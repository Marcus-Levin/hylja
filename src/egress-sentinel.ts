/**
 * #19 independent egress sentinel: the last check on the exact serialized outbound bytes. It is
 * deliberately NOT the detector stack run twice. It matches known originals and canaries (held only as
 * keyed fingerprints), applies its own small set of high-risk patterns, inspects bounded canonical views
 * (#6 decoded views plus its own escape decoding, iterated to a fixpoint), and asserts the destination.
 * Anything it cannot inspect, any embedded opaque binary, any error, any exhausted budget and any outage
 * is BLOCK. It never returns originals or matched text; on ALLOW it returns a private copy of the bytes.
 */
import { createHmac } from 'node:crypto';
import { brotliDecompressSync, gunzipSync, inflateRawSync, inflateSync } from 'node:zlib';
import { normalizeInput } from './normalization.js';

export const SENTINEL_VERSION = 'hylja.egress-sentinel.v1' as const;
export const MAX_MESSAGE_BYTES = 1 << 20;
const MAX_ENTRIES = 4096, MIN_ORIGINAL = 4, MAX_ORIGINAL = 1024, GRAM = 8, MAX_TOKENS = 16;
/** Canonical-view budget: escape/decoding rounds and total text inspected per message. */
const MAX_ROUNDS = 4, MAX_VIEW_UNITS = 8 << 20, MAX_VIEWS = 512;
/** HMAC verifications per message; prefilters make real matches rare, so exceeding this is itself suspicious. */
const MAX_VERIFICATIONS = 20_000;
/** Prefilter probes per message (length buckets and short windows); exceeding it blocks as SENTINEL_BUDGET. */
const MAX_PROBES = 8_000_000;
/** Base64/hex runs at least this long must decode to text; otherwise they are opaque embedded binary. */
const OPAQUE_RUN = 128;

export interface SentinelScope { tenantRef: string; projectRef: string }
export interface Destination { id: string; profileDigest: string }
export interface KnownEntry {
  /** A planted synthetic original, a known protected original, or a canary/honeytoken. */
  kind: 'ORIGINAL' | 'CANARY';
  value: string;
  /** Privacy-safe label reported on a match (never the value). */
  ref: string;
}
export interface SentinelFinding {
  kind: 'KNOWN_ORIGINAL' | 'CANARY' | 'PATTERN';
  /** Entry ref or pattern rule id. */
  rule: string;
  /** Canonical view path where it was found, e.g. `ROOT`, `ROOT>ESCAPES>BASE64`. */
  view: string;
}
export interface SentinelResult {
  decision: 'ALLOW' | 'BLOCK';
  reasons: readonly string[];
  findings: readonly SentinelFinding[];
  /** On ALLOW: a private copy of exactly the checked bytes, to send instead of the caller's buffer. */
  release?: Uint8Array;
  /** Sanitized record for a regression case: codes and refs only, never bytes or values. */
  regression?: Readonly<{ version: string; reasons: readonly string[]; rules: readonly string[]; views: readonly string[] }>;
}
export interface EgressCheck {
  bytes: Uint8Array;
  scope: SentinelScope;
  /** Destination the adapter is about to send to, observed at the send point. */
  destination: Destination;
  /** Destination and profile the policy decision authorized. */
  authorized: Destination;
  /**
   * Known originals for this tenant/project. Required: pass `null` explicitly for egress that has no known
   * originals to protect; omitting it blocks, so a forgotten handle never silently weakens the check.
   */
  known: KnownOriginalsHandle | null;
}

/* ---------- Folding for matching ---------- */

// Common Cyrillic/Greek homoglyphs of Latin letters (lower case, after case folding).
const CONFUSABLES: Readonly<Record<string, string>> = Object.freeze({
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'і': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't',
  'у': 'y', 'х': 'x', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v',
  'ı': 'i', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'օ': 'o', 'ս': 'u', 'ց': 'g', 'հ': 'h', 'ո': 'n',
});
/**
 * Matching fold for both registered values and payloads: NFKD, marks stripped (`Órla`, `Zoë` -> `orla`,
 * `zoe`), NFKC, lower case with `ß` -> `ss`, default-ignorables removed, homoglyphs mapped to Latin.
 */
function fold(text: string): string {
  const base = text.normalize('NFKD').replace(/\p{M}/gu, '').normalize('NFKC').toLowerCase().replace(/ß/gu, 'ss')
    .replace(/\p{Default_Ignorable_Code_Point}/gu, '');
  let out = '';
  for (const char of base) out += CONFUSABLES[char] ?? char;
  return out;
}
const TOKEN = /[\p{L}\p{N}]+/gu;
function tokens(folded: string): string[] {
  return folded.match(TOKEN) ?? [];
}
/** Separator-free form with leading zeros removed from every digit run (`gateway07` == `gateway7`, `010` == `10`). */
function stripZeros(text: string): string {
  return text.replace(/(?<!\d)0+(?=\d)/gu, '');
}
function compact(folded: string): string {
  // Strip per token, before joining, so `192.000.002.010` compacts like `192.0.2.10`.
  return tokens(folded).map(stripZeros).join('');
}

/* ---------- Known originals (keyed fingerprints only) ---------- */

declare const knownBrand: unique symbol;
export interface KnownOriginalsHandle { readonly [knownBrand]: true }
interface LongEntry { length: number; suffix: number; mac: string; entry: number }
interface Known {
  scope: SentinelScope;
  key: Uint8Array;
  base: number;
  /** Prefix gram hash -> length -> suffix gram hash -> entries: three independent keyed checks before any HMAC. */
  grams: Map<number, Map<number, Map<number, LongEntry[]>>>;
  /**
   * Short values (under GRAM compact characters): keyed hash of the compact form -> entries. They match a window
   * of whole consecutive tokens whose compact form is equal, so `Or la`, `o r l a` and `10.0.0.1 x` are found
   * but `orla` inside `colorlab` is not.
   */
  shorts: Map<number, { mac: string; entry: number }[]>;
  entries: { kind: KnownEntry['kind']; ref: string }[];
}
const registry = new WeakMap<object, Known>();
function mac(known: Known, text: string): string {
  return createHmac('sha256', known.key).update(`${SENTINEL_VERSION}\u0000${text}`).digest('hex');
}
/** Rolling polynomial hash mod 2^32 with a secret random odd base (a prefilter; matches are HMAC-verified). */
function gramHash(text: string, from: number, base: number): number {
  let hash = 0;
  for (let index = from; index < from + GRAM; index++) hash = (Math.imul(hash, base) + text.charCodeAt(index)) >>> 0;
  return hash;
}
function tokenHash(token: string, base: number): number {
  let hash = base;
  for (let index = 0; index < token.length; index++) hash = Math.imul(hash ^ token.charCodeAt(index), 0x01000193) >>> 0;
  return hash;
}
function label(value: unknown, limit = 256): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
function nested<K, V>(map: Map<K, V>, key: K, make: () => V): V {
  let value = map.get(key);
  if (value === undefined) map.set(key, value = make());
  return value;
}

/**
 * Trusted configuration: register planted/known originals and canaries for one tenant and project. The
 * handle keeps keyed fingerprints and keyed prefilter hashes, not the values. `key` is a dedicated
 * sentinel key of at least 32 bytes; errors never include a value.
 */
export function createKnownOriginals(scope: SentinelScope, key: Uint8Array, entries: readonly KnownEntry[]): KnownOriginalsHandle {
  const invalid = (): never => { throw new TypeError('Invalid known-originals configuration'); };
  try {
    if (!scope || !label(scope.tenantRef) || !label(scope.projectRef) || !(key instanceof Uint8Array) || !(key.byteLength >= 32) ||
      !Array.isArray(entries) || entries.length > MAX_ENTRIES) invalid();
    const random = new Uint32Array(1);
    globalThis.crypto.getRandomValues(random);
    const known: Known = { scope: Object.freeze({ tenantRef: scope.tenantRef, projectRef: scope.projectRef }),
      key: Uint8Array.from(key), base: (random[0]! | 1) >>> 0, grams: new Map(), shorts: new Map(), entries: [] };
    for (const entry of entries as unknown[]) {
      const { kind, value, ref } = (entry ?? {}) as Record<string, unknown>;
      if ((kind !== 'ORIGINAL' && kind !== 'CANARY') || typeof value !== 'string' || !label(ref, 128)) invalid();
      const folded = fold(value as string);
      const packed = compact(folded);
      if (packed.length < MIN_ORIGINAL || packed.length > MAX_ORIGINAL) invalid();
      known.entries.push({ kind: kind as KnownEntry['kind'], ref: ref as string });
      const index = known.entries.length - 1;
      if (packed.length >= GRAM) {
        // Long values match on separator-stripped text, so splitting with punctuation does not evade them.
        const byLength = nested(known.grams, gramHash(packed, 0, known.base), () => new Map<number, Map<number, LongEntry[]>>());
        const bySuffix = nested(byLength, packed.length, () => new Map<number, LongEntry[]>());
        const suffix = gramHash(packed, packed.length - GRAM, known.base);
        nested(bySuffix, suffix, () => [] as LongEntry[]).push({ length: packed.length, suffix, mac: mac(known, packed), entry: index });
      } else {
        if (tokens(folded).length > MAX_TOKENS) invalid();
        nested(known.shorts, tokenHash(packed, known.base), () => [] as { mac: string; entry: number }[])
          .push({ mac: mac(known, packed), entry: index });
      }
    }
    const handle = Object.freeze(Object.create(null)) as KnownOriginalsHandle;
    registry.set(handle, known);
    return handle;
  } catch { return invalid(); }
}
class BudgetExceeded extends Error {}
function matchKnown(known: Known, text: string, budget: { verifications: number; probes: number }): Set<number> {
  const hits = new Set<number>();
  const verify = (candidate: string, expected: string): boolean => {
    if (++budget.verifications > MAX_VERIFICATIONS) throw new BudgetExceeded();
    return mac(known, candidate) === expected;
  };
  const probe = (): void => { if (++budget.probes > MAX_PROBES) throw new BudgetExceeded(); };
  const folded = fold(text);
  if (known.grams.size) {
    const packed = compact(folded);
    if (packed.length >= GRAM) {
      // One rolling pass computes every window hash; candidates need prefix, length and suffix to agree.
      const windows = new Uint32Array(packed.length - GRAM + 1);
      let power = 1;
      for (let index = 1; index < GRAM; index++) power = Math.imul(power, known.base) >>> 0;
      let hash = gramHash(packed, 0, known.base);
      for (let start = 0; start < windows.length; start++) {
        if (start > 0) {
          hash = (hash - Math.imul(packed.charCodeAt(start - 1), power)) >>> 0;
          hash = (Math.imul(hash, known.base) + packed.charCodeAt(start + GRAM - 1)) >>> 0;
        }
        windows[start] = hash;
      }
      for (let start = 0; start < windows.length; start++) {
        const byLength = known.grams.get(windows[start]!);
        if (!byLength) continue;
        for (const [length, bySuffix] of byLength) {
          probe();
          const end = start + length - GRAM;
          if (end >= windows.length) continue;
          const candidates = bySuffix.get(windows[end]!);
          if (!candidates) continue;
          for (const candidate of candidates) {
            if (!hits.has(candidate.entry) && verify(packed.slice(start, start + length), candidate.mac)) hits.add(candidate.entry);
          }
        }
      }
    }
  }
  if (known.shorts.size) {
    const list = tokens(folded);
    for (let index = 0; index < list.length; index++) {
      let joined = '';
      // Windows of whole tokens up to 24 raw characters (room for leading zeros) and MAX_TOKENS tokens.
      for (let next = index; next < list.length && next - index < MAX_TOKENS; next++) {
        joined += stripZeros(list[next]!);
        if (joined.length > 24) break;
        const packed = joined;
        if (packed.length >= GRAM) break;
        probe();
        const candidates = known.shorts.get(tokenHash(packed, known.base));
        if (!candidates) continue;
        for (const candidate of candidates) {
          if (!hits.has(candidate.entry) && verify(packed, candidate.mac)) hits.add(candidate.entry);
        }
      }
    }
  }
  return hits;
}

/* ---------- Independent high-risk patterns (separate from the #8 detector implementation) ---------- */

const PATTERNS: readonly { rule: string; pattern: { test(text: string): boolean } }[] = [
  { rule: 'pattern.private-key-block', pattern: /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----|---- BEGIN SSH2 [A-Z ]{0,20}PRIVATE KEY ----|PuTTY-User-Key-File-\d/u },
  { rule: 'pattern.cloud-access-key', pattern: /(?<![0-9A-Z])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])/u },
  { rule: 'pattern.source-control-token', pattern: /gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}/u },
  { rule: 'pattern.chat-token', pattern: /xox[abposr]-[A-Za-z0-9-]{10,}/u },
  { rule: 'pattern.payment-key', pattern: /(?:sk|rk)_live_[A-Za-z0-9]{16,}/u },
  { rule: 'pattern.google-api-key', pattern: /AIza[0-9A-Za-z_-]{35}/u },
  { rule: 'pattern.llm-api-key', pattern: /(?<![A-Za-z0-9])sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}/u },
  { rule: 'pattern.npm-token', pattern: /npm_[A-Za-z0-9]{36}/u },
  { rule: 'pattern.jwt', pattern: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\./u },
  { rule: 'pattern.authorization-credential', pattern: /authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}/iu },
  // Found from each `://`, looking back at most 32 characters for the scheme, so long letter runs stay linear.
  // A placeholder password (`${password}`, `{{password}}`, `$DB_PASS`, `%s`, `<password>`) is not a value.
  { rule: 'pattern.url-password', pattern: { test: urlPassword } },
];
// A literal value after a credential-like key. References (`${X}`, `{{x}}`, `<...>`, masks), type names,
// booleans and identifier/member expressions (`process.env.SECRET`, `config.password`) are not values.
const URL_PLACEHOLDER = /^(?:\$\{[^}]*\}|\{\{[^}]*\}\}|\$[A-Za-z_][A-Za-z0-9_]*|%s|<[\w -]{1,40}>)$/u;
function urlPassword(text: string): boolean {
  for (let at = text.indexOf('://'); at >= 0; at = text.indexOf('://', at + 3)) {
    if (!/[a-z][a-z0-9+.-]{1,31}$/iu.test(text.slice(Math.max(0, at - 32), at))) continue;
    // The user name may be empty (`redis://:password@host`); a whole placeholder is not a password.
    const credential = /^[^\s:/@"']{0,256}:([^\s/@"']{3,256})@/u.exec(text.slice(at + 3, at + 3 + 520));
    if (credential && !URL_PLACEHOLDER.test(credential[1]!)) return true;
  }
  return false;
}
// A bare identifier that repeats the key (`{ password: password }`, `apiKey: apiKey`) is a shorthand, not a value;
// other bare words are flagged, since unquoted passwords look the same as identifiers.
const CREDENTIAL_ASSIGNMENT = /(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*(?:(["'`])([^"'`\r\n]{4,})\2|([^\s"'`,;)]{4,}))/giu;
const REFERENCE = /^(?:\$\{[^}]*\}|\{\{[^}]*\}\}|<[\w -]{1,40}>|\*{3,}|\[hylja:protected:[A-Z0-9_]+\])$/u;
const NOT_A_VALUE = /^(?:[$<*{[]|(?:string|number|boolean|bigint|object|any|unknown|undefined|null|none|true|false|nil|str|int|bool|bytes)$|[A-Za-z_$][\w$]*(?:(?:\.|\?\.)[A-Za-z_$][\w$]*|\[[^\]]*\])+$)/iu;
function credentialAssignment(text: string): boolean {
  for (const match of text.matchAll(CREDENTIAL_ASSIGNMENT)) {
    // Only a whole quoted branch label (`? 'SECRET' : 'INTERNAL'`) is a ternary separator. A credential
    // assignment *inside* a quoted branch (`? 'password: value' : ...`) still contains a value.
    const prefix = text.slice(Math.max(0, match.index - 8), match.index);
    const branchQuote = /\?\s*(["'`])$/u.exec(prefix)?.[1];
    if (branchQuote && text[match.index + match[1]!.length] === branchQuote) continue;
    // A quoted string is a literal unless it is a whole reference or mask; only unquoted values can be
    // identifiers, member expressions, type names or booleans.
    // Unquoted: brackets inside the value belong to it; only trailing ones (`false}`) close a surrounding structure.
    const unquoted = match[4]?.replace(/[}\]]+$/u, '');
    // `PWD=/srv/app` is the working directory, not a password.
    if (/^pwd$/iu.test(match[1]!) && /^[/~]/u.test(match[4] ?? match[3] ?? '')) continue;
    const sameName = unquoted !== undefined && unquoted.replace(/[_-]/gu, '').toLowerCase() === match[1]!.replace(/[_-]/gu, '').toLowerCase();
    if (match[4] !== undefined ? unquoted!.length >= 4 && !NOT_A_VALUE.test(unquoted!) && !sameName : !REFERENCE.test(match[3]!)) return true;
  }
  return false;
}
const ENCODED_RUN = /(?<![A-Za-z0-9+/_-])(?:[A-Za-z0-9+/_-]{16,65536}={0,2})(?![A-Za-z0-9+/=_-])/gu;
// #6 intentionally requires longer runs. With a registered short original, 6–15-character Base64/hex
// alphabet runs (plus optional padding) still need a bounded matching pass.
const SHORT_ENCODED_RUN = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{6,15}={0,2}(?![A-Za-z0-9+/=_-])/gu;
const MAX_SHORT_RUNS = 8192;
/**
 * Decoded binary that is not text and not a recognized digest, UUID or public key is opaque once a message holds
 * more than this many bytes in total, however it is chunked or interleaved. Random tokens and session ids count:
 * in protected egress they are credentials themselves (decision 009), and encrypted or unknown formats cannot be
 * inspected (decision 007). Decompression still runs first so a planted original yields a precise reason.
 */
const OPAQUE_BYTES = 32;
/** Total decompressed output per message across all attempts and rounds; exceeding it blocks (bomb or flood). */
const MAX_INFLATE_TOTAL = 4 << 20;
// Container and compression formats the sentinel does not decode: opaque at any length.
const OPAQUE_SIGNATURES: readonly number[][] = [[0x50, 0x4b, 0x03, 0x04], [0x42, 0x5a, 0x68], [0xfd, 0x37, 0x7a, 0x58, 0x5a],
  [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], [0x28, 0xb5, 0x2f, 0xfd]];
/** 64-bit values and span ids, object ids, MD5/trace ids, SHA-1/256/384/512 hex digests are ordinary text, not payloads. */
const DIGEST_HEX = /^(?:[0-9A-Fa-f]{16}|[0-9A-Fa-f]{24}|[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{96}|[0-9A-Fa-f]{128})$/u;
/** Base64 digests and public keys identified by their context: SRI values and SSH public-key fields. */
function isIdentifierRun(run: string): boolean {
  return DIGEST_HEX.test(run) || /^sha(?:1|256|384|512)-[A-Za-z0-9+/]+={0,2}$/u.test(run) ||
    /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/u.test(run);
}
const DIGEST_CONTEXT = /(?:sha(1|224|256|384|512)[-:]|(h1:)|(content-md5:\s*)|(etag:\s*"?))$/iu;
const SSH_ED25519_CONTEXT = /(?:^|\s)ssh-ed25519\s$/u;
const SSH_ED25519_HEADER = Uint8Array.from([0, 0, 0, 11, ...[...'ssh-ed25519'].map((char) => char.charCodeAt(0)), 0, 0, 0, 32]);
// Public certificate and key blocks are not secrets: their base64 lines are exempt from the opaque count, but are
// still decoded and decompressed. The END label must match, the body must be base64 lines only and start like a
// DER sequence (`M…`). Line breaks may be real or JSON-escaped (`\n`), as in a model request body.
const PUBLIC_PEM = /-----BEGIN (CERTIFICATE|TRUSTED CERTIFICATE|PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST|X509 CRL)-----(?:\r?\n|(?:\\r)?\\n)(?=[ \t]*M)(?:[ \t]*[A-Za-z0-9+/]{1,76}={0,2}[ \t]*(?:\r?\n|(?:\\r)?\\n)){1,1024}[ \t]*-----END \1-----/gu;
/** A PEM block whose body is one DER SEQUENCE whose length header matches the body exactly. */
function derShaped(block: string): boolean {
  const body = block.replace(/-----[A-Z0-9 ]+-----/gu, '').replace(/\\[rn]|\s/gu, '');
  const der = decodeRun(body);
  if (!der || der[0] !== 0x30 || der.length < 2) return false;
  const first = der[1]!;
  if (first < 0x80) return der.length === 2 + first;
  const size = first & 0x7f;
  if (size < 1 || size > 3 || der.length < 2 + size) return false;
  let length = 0;
  for (let index = 0; index < size; index++) length = length * 256 + der[2 + index]!;
  return der.length === 2 + size + length;
}
/** The Base64 alphabet itself, or a stretch of it (a constant in code, not a payload). */
const B64_ALPHABET = { test: (value: string): boolean => value.length >= 16 && 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_'.includes(value) };
/** Exact digest lengths: hex MD5/SHA-1/224/256/384/512, and base64 MD5/SHA-1/256/384/512 with or without padding. */
function isDigest(value: string): boolean {
  if (/^[0-9A-Fa-f]+$/u.test(value)) return [16, 24, 32, 40, 56, 64, 96, 128].includes(value.length);
  return [22, 24, 27, 28, 43, 44, 64, 86, 88].includes(value.length);
}
function isContextDigest(context: RegExpExecArray, value: string, decodedLength: number): boolean {
  const size = context[1] ? ({ '1': 20, '224': 28, '256': 32, '384': 48, '512': 64 } as Record<string, number>)[context[1]!]
    : context[2] ? 32 : 16; // go.sum h1 is SHA-256; Content-MD5 and the supported ETag form are MD5.
  if (decodedLength !== size) return false;
  if (/^[0-9A-Fa-f]+$/u.test(value)) return value.length === size * 2;
  const bare = value.replace(/=+$/u, '');
  return /^[A-Za-z0-9+/_-]+={0,2}$/u.test(value) && bare.length === Math.ceil(size * 8 / 6) &&
    (value.length === bare.length || value.length === Math.ceil(size / 3) * 4);
}
function isSshEd25519PublicKey(before: string, value: string, bytes: Uint8Array): boolean {
  // A 51-byte SSH ed25519 wire key is exactly 68 unpadded standard-Base64 characters. Hex and Base64url
  // strings with the same decoded bytes are not valid SSH public-key fields.
  return SSH_ED25519_CONTEXT.test(before) && /^[A-Za-z0-9+/]{68}$/u.test(value) &&
    bytes.length === SSH_ED25519_HEADER.length + 32 &&
    SSH_ED25519_HEADER.every((byte, index) => bytes[index] === byte);
}
/**
 * camelCase/PascalCase/snake identifiers and path-like names made of words and short digit groups
 * (`convertUtf8ToBase64String`, `com/Marcus-Levin/hylja/pull/56`). Random Base64 does not split into words.
 * A path segment may be a whole numeric id up to int64 width (`actions/runs/36169013008`). At least one letter
 * outside a-f is required.
 */
function isIdentifier(value: string): boolean {
  // Hex split into short groups (`a3f9-01bc-…`) has no word in it and is data, not a name.
  // Repeated Base64 slash bytes are data even when an ordinary-looking advisory or other id follows them.
  if (value.length > 256 || /[+=]|\/{8,}/u.test(value) || !/[g-zG-Z]/u.test(value)) return false;
  const segments = value.split(/[_/.-]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])/u).filter(Boolean);
  // Names have few, long segments; random Base64 that happens to split into word-like pieces has many short ones.
  // Advisory ids (`GHSA-jfh8-c2jp-5v3q`, `CVE-2026-12345`) and short `-_.`-separated groups (`Q1_2026_Report_v3_Final.pdf`)
  // are names too. `/` does not count as a separator here: random Base64 contains it.
  const advisory = /(?:^|\/)(?:GHSA(?:-[0-9a-z]{4}){3}|CVE-\d{4}-\d{4,7})$/iu.exec(value);
  if (advisory) {
    // An advisory at the end of a path exempts only ordinary path components. The prior whole-run exemption
    // also hid a high-entropy Base64url token placed before `/GHSA-…`.
    const prefix = value.slice(0, advisory.index);
    // One leading slash is a path root; two may be a URL authority. Interior or extra slashes are
    // encoded data, not empty path words. Dropping them hid long Base64 slash runs before an advisory.
    const leading = prefix.startsWith('//') ? 2 : prefix.startsWith('/') ? 1 : 0;
    const path = prefix.slice(leading);
    if ((prefix.length > 0 && path.length === 0) || path.startsWith('/') || path.endsWith('/') || path.includes('//')) return false;
    const parts = path ? path.split('/') : [];
    // Each component must be an ordinary short path word or group of words. A generic alphanumeric
    // component can be a Base32 payload: two 32-character chunks before a real GHSA id previously passed.
    const words = /^(?:[A-Z]?[a-z]{2,16}(?:[A-Z][a-z]{2,16})*)(?:[._-](?:[A-Z]?[a-z]{2,16}(?:[A-Z][a-z]{2,16})*))*$/u;
    return parts.length <= 8 && parts.every((part) => part.length <= 32 &&
      (words.test(part) || /^\d{1,4}$/u.test(part)));
  }
  const groups = value.split(/[-_.]/u).filter(Boolean);
  const shortGroups = groups.length >= 3 && groups.every((group) => group.length <= 12);
  if (!shortGroups && value.replace(/[_/.-]/gu, '').length < segments.length * 3) return false;
  return segments.length >= 2 && segments.every((segment) =>
    /^[A-Z]?[a-z]{2,}$/u.test(segment) || /^[A-Z][a-z]$/u.test(segment) || /^[A-Z]{1,5}$/u.test(segment) || /^\d{1,4}$/u.test(segment) || /^[a-z]$/u.test(segment) ||
    /^\d{5,20}$/u.test(segment) && new RegExp(`(?:^|[/._-])${segment}(?:$|[/._-])`, 'u').test(value));
}
// Separators between pairs: whitespace, `,;:|.&`, quotes, brackets, JSON escapes and YAML `- ` list markers, so
// JSON/YAML arrays of pairs (`["4f","72",…]`) and padded columns decode too.
const HEX_PAIRS = /(?<![0-9A-Fa-f])(?:0[xX]|\\x)?[0-9A-Fa-f]{2}(?:(?:[ \t\r\n,;:|.&"'[\]]|\\[nrt"\\]|-(?=[ \t0-9A-Fa-f])){1,24}(?:0[xX]|\\x)?[0-9A-Fa-f]{2}(?![0-9A-Fa-f])){7,4096}/gu;
/**
 * Hex dump lines (`od`, `xxd`, `xxd -g1`, `hexdump -C` with offsets): an offset, byte pairs or two-byte groups, then an optional ASCII column after `  |`
 * or two or more spaces. The offset and ASCII column are dropped, so hex-looking text in the ASCII column (`|.Ee.`)
 * cannot corrupt the bytes. Consecutive dump lines (real or JSON-escaped line breaks) form one decode-only run.
 */
// Lines with an offset column; the line may carry a prefix (a JSON body's first line: `"content":"00000000  78 9c …`).
// Dumps without offsets (`od -An`) are plain byte-pair runs.
const DUMP_OFFSET = /(?:^|[^0-9A-Fa-f])[0-9A-Fa-f]{4,8}:?[ \t]+/u;
function dumpLineHex(line: string): string | null {
  const ascii = line.indexOf('  |');
  const body = ascii >= 0 ? line.slice(0, ascii) : line;
  const offset = DUMP_OFFSET.exec(body);
  if (!offset) return null;
  const field = body.slice(offset.index + offset[0].length);
  // hexdump -C puts two spaces between halves but marks its ASCII column with `|`. xxd pads with two or
  // more spaces before an unmarked ASCII column. Split the latter only after the offset has been removed.
  const hexField = ascii >= 0 ? field : field.split(/[ \t]{2,}/u, 1)[0]!;
  const groups = hexField.trim().split(/[ \t]+/u);
  const width = groups[0]?.length;
  if ((width !== 2 && width !== 4) || groups.length > 32 || groups.some((group, index) =>
    !/^[0-9A-Fa-f]+$/u.test(group) || group.length !== width && !(width === 4 && index === groups.length - 1 && group.length === 2))) return null;
  return groups.join('');
}
function* dumpRuns(text: string): Generator<EncodedRun> {
  let block: { start: number; end: number; hex: string[]; lines: number } | null = null;
  const flush = function* (): Generator<EncodedRun> {
    if (block && block.lines >= 2 && block.hex.join('').length >= 32) {
      yield { start: block.start, end: block.end, value: block.hex.join(''), prefixed: false, countable: false, separated: true };
    }
    block = null;
  };
  const breaks = /\r?\n|\\r\\n|\\n/gu;
  let start = 0;
  for (let found = breaks.exec(text); ; found = breaks.exec(text)) {
    const end = found ? found.index : text.length;
    if (end - start <= 400) {
      const pairs = dumpLineHex(text.slice(start, end));
      if (pairs !== null) {
        block ??= { start, end, hex: [], lines: 0 };
        block.hex.push(pairs);
        block.end = end;
        block.lines++;
      } else yield* flush();
    } else yield* flush();
    if (!found) break;
    start = found.index + found[0].length;
  }
  yield* flush();
}
const SEPARATED_HEX = /^[0-9A-Fa-f]{2,}(?:[-_/][0-9A-Fa-f]{2,})+$/u;
const UUID = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/u;
interface EncodedRun { start: number; end: number; value: string; prefixed: boolean; countable: boolean; separated?: boolean; joined?: boolean; escaped?: boolean }
// Chunks of any length: a fixed-width split ends in a short remainder (`…Ghs2 M=`), and short words between chunks
// are dropped by the word-free variant.
const CHUNK = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{1,1024}={0,2}(?![A-Za-z0-9+/=_-])/gu;
/** A chunk that is clearly encoded data: letters with digits, long hex, or padding. */
function chunkLike(token: string): boolean {
  return /\d/u.test(token) && /[A-Za-z]/u.test(token) || /^[0-9A-Fa-f]{8,}$/u.test(token) || /=$/u.test(token);
}
/**
 * Also possibly encoded: `+`/`/`, a lower-to-upper case switch (digit-free Base64 chunks) or short hex groups
 * (hex of text is mostly digits: `6f6e 7461 6374`).
 */
function chunkLikeLoose(token: string): boolean {
  return chunkLike(token) || /[+/]/u.test(token) || /[a-z][A-Z]/u.test(token) || /^[0-9A-Fa-f]{4,}$/u.test(token);
}
/**
 * Encoded runs: every run of 16+ alphabet characters (a `shaNNN-`/`shaNNN:`/`h1:` prefix stripped), plus
 * sequences of short chunk-like tokens separated only by whitespace, commas, quotes, brackets or `:;|.&`, joined
 * into one run so that chunking below 16 characters cannot hide compressed data. A joined sequence counts toward
 * OPAQUE_BYTES only when it is separated by whitespace, commas, quotes or brackets and three quarters of its
 * tokens are clearly encoded; other sequences (digit-free Base64 chunks, but also JSON ids, IPv6 addresses and
 * regex classes) are decoded and decompressed, never counted.
 */
function* encodedRuns(text: string): Generator<EncodedRun> {
  for (const run of text.matchAll(ENCODED_RUN)) {
    // A digest prefix, `0x` before hex (`0x0000A1B2C3D4E5F6`), or the letter of a JSON escape before the run
    // (`\nQUJD…`) is not part of the value.
    const prefix = /^(?:sha(?:1|224|256|384|512)-|h1:)/iu.exec(run[0]) ?? /^0[xX](?=[0-9A-Fa-f]+$)/u.exec(run[0]) ??
      (text[run.index - 1] === '\\' ? /^[nrt](?=.{16})/u.exec(run[0]) : null);
    let value = prefix ? run[0].slice(prefix[0].length) : run[0];
    // Hex in dash-separated groups (`a3f9-01bc-…`) is hex data; a UUID keeps its shape and exemption.
    const separated = SEPARATED_HEX.test(value) && !UUID.test(value);
    // Hex split into equal groups (`a3f9-01bc-…`) is a dump and counts; mixed groups (trace parents) are decoded only.
    const groups = separated ? value.split(/[-_/]/u) : [];
    // MAC-48/EUI-64 (`00-1A-2B-3C-4D-5E`) are addresses, not dumps.
    const mac = (groups.length === 6 || groups.length === 8) && groups.every((group) => group.length === 2);
    const uniform = !mac && groups.length >= 4 && /[A-Fa-f]/u.test(value) && groups.slice(0, -1).every((group) => group.length === groups[0]!.length) && groups.at(-1)!.length <= groups[0]!.length;
    if (separated) value = groups.join('');
    yield { start: run.index + (prefix?.[0].length ?? 0), end: run.index + run[0].length, value, prefixed: prefix !== null && /^(?:sha|h1)/iu.test(prefix[0]),
      countable: !separated || uniform, separated };
  }
  yield* dumpRuns(text);
  // Byte pairs (`63:6f:6e:…`, hexdump `63 6f 6e …`, C arrays `0x63, 0x6f, …`), eight or more: decoded, not counted
  // (fingerprints, MACs).
  for (const run of text.matchAll(HEX_PAIRS)) {
    const value = run[0].replace(/0[xX](?=[0-9A-Fa-f]{2})|\\x|\\n/gu, '').replace(/[^0-9A-Fa-f]/gu, '');
    yield { start: run.index, end: run.index + run[0].length, value, prefixed: false, countable: false, separated: true };
  }
  yield* escapedByteRuns(text);
  yield* chunkSequences(text, /^(?:[\s,"'[\]]|\\[nrt]){1,64}$/u, false);
  yield* chunkSequences(text, /^(?:[\s,"'[\]:;|.&]|\\[nrt]){1,64}$/u, true);
}
/**
 * Joined chunk sequences. The strict pass (whitespace, commas, quotes, brackets) may count; the weak pass also
 * joins across `:;|.&` (hex dumps, pipe-separated fields) and yields only sequences that used one of those. Both
 * also yield the sequence without its word tokens (`data 1f8b… 0800…`, keys or notes between chunks), decode-only.
 * A sequence counts only in the strict pass, when all its chunks are short (4–15), it is not all hex or decimal
 * (hash lists, ids, timestamps) and three quarters of its chunks are clearly encoded.
 */
function* chunkSequences(text: string, separator: RegExp, weakPass: boolean): Generator<EncodedRun> {
  let sequence: RegExpMatchArray[] = [];
  let weak = false;
  const emit = function* (tokens: RegExpMatchArray[], mayCount: boolean): Generator<EncodedRun> {
    if (tokens.length < 2 || tokens.filter((token) => chunkLikeLoose(token[0])).length < tokens.length * 0.5) return;
    const value = tokens.map((token) => token[0].replace(/=+$/u, '').replace(/^0[xX](?=[0-9A-Fa-f]+$)/u, '')).join('');
    if (value.length < 16) return;
    const last = tokens[tokens.length - 1]!;
    // Mostly hex tokens are a hex list (fingerprints, hashes, ids), decoded but not counted.
    const hexTokens = tokens.filter((token) => /^(?:0[xX])?[0-9A-Fa-f]+$/u.test(token[0])).length;
    // Mostly dash/underscore ids (`D01-DEV-001`, `span_42_ok`) are an id list; random Base64url rarely splits so.
    const idTokens = tokens.filter((token) => /^[A-Za-z0-9]{1,8}(?:[-_][A-Za-z0-9]{1,8}){1,5}$/u.test(token[0])).length;
    const countable = mayCount && tokens.every((token) => token[0].length <= 17) && hexTokens < tokens.length * 0.75 &&
      idTokens < tokens.length * 0.75 &&
      tokens.filter((token) => chunkLike(token[0])).length >= tokens.length * 0.75;
    yield { start: tokens[0]!.index!, end: last.index! + last[0].length, value, prefixed: false, separated: true, countable, joined: true };
  };
  const flush = function* (): Generator<EncodedRun> {
    if (!weakPass || weak) {
      // A sequence with words between chunks is judged without them (`blob 3F2A9C1B …` is hex, not Base64).
      // The last token stays even when short: it is usually the remainder of a fixed-width split.
      const words = sequence.filter((token, index) => chunkLikeLoose(token[0]) || index === sequence.length - 1 && index > 0);
      yield* emit(sequence, !weakPass && words.length === sequence.length);
      if (words.length !== sequence.length) yield* emit(words, !weakPass);
      // Decode-only variants for a prefix that misaligns the chunks (`sha256 <digest> H4sI AAAA …`): the stretches
      // between long tokens (runs of their own), and the words-free sequence without its first one to three tokens.
      // Very long sequences are dumps, read by byte-pair runs and the inner stream scan instead.
      const variants: RegExpMatchArray[][] = [];
      let stretch: RegExpMatchArray[] = [];
      for (const token of words.length <= 4096 ? words : []) {
        if (token[0].length > 17) { if (stretch.length) variants.push(stretch); stretch = []; } else stretch.push(token);
      }
      if (stretch.length && stretch.length !== words.length) variants.push(stretch);
      for (let drop = 1; drop <= 3 && words.length - drop >= 2 && words.length <= 4096; drop++) variants.push(words.slice(drop));
      for (const variant of variants) yield* emit(variant, false);
    }
    sequence = [];
    weak = false;
  };
  for (const match of text.matchAll(CHUNK)) {
    // After a JSON escape (`\nABCD`), the escape letter belongs to the separator, not the chunk.
    let token: RegExpMatchArray = match;
    if (text[match.index - 1] === '\\' && /^[nrt]./u.test(match[0])) {
      token = Object.assign([match[0].slice(1)], { index: match.index + 1 }) as unknown as RegExpMatchArray;
    }
    const previous = sequence[sequence.length - 1];
    const gap = previous ? text.slice(previous.index! + previous[0].length, token.index) : '';
    if (previous && !separator.test(gap)) yield* flush();
    else if (/[:;|.&]/u.test(gap)) weak = true;
    sequence.push(token);
  }
  yield* flush();
}

/** Read a byte-valued escape without interpreting it as a Unicode replacement character. */
function escapedByteAt(text: string, at: number, allowQuotedPrintable = true): { byte: number; end: number } | null {
  const lead = text[at];
  const hex = (from: number, length: number): number | null => {
    const digits = text.slice(from, from + length);
    return digits.length === length && /^[0-9A-Fa-f]+$/u.test(digits) ? parseInt(digits, 16) : null;
  };
  if (lead === '%' || lead === '=' && allowQuotedPrintable) {
    if (lead === '%' && text[at + 1] === 'u') {
      const value = hex(at + 2, 4);
      return value !== null && value <= 255 ? { byte: value, end: at + 6 } : null;
    }
    const value = hex(at + 1, 2);
    return value !== null ? { byte: value, end: at + 3 } : null;
  }
  if (lead === '\\') {
    if (text[at + 1] === 'x') {
      const value = hex(at + 2, 2);
      return value !== null ? { byte: value, end: at + 4 } : null;
    }
    if (text[at + 1] === 'u' || text[at + 1] === 'U') {
      const length = text[at + 1] === 'u' ? 4 : 8;
      const value = hex(at + 2, length);
      return value !== null && value <= 255 ? { byte: value, end: at + 2 + length } : null;
    }
    const control = text.charCodeAt(at + 2);
    if (text[at + 1] === '^' && control >= 64 && control <= 95) {
      return { byte: control ^ 64, end: at + 3 };
    }
    const octal = /^[0-7]{1,3}/u.exec(text.slice(at + 1, at + 4))?.[0];
    if (octal) {
      const value = parseInt(octal, 8);
      return value <= 255 ? { byte: value, end: at + 1 + octal.length } : null;
    }
  }
  if (lead === '&' && text[at + 1] === '#') {
    const entity = /^&#(?:[xX]([0-9A-Fa-f]{1,2})|(\d{1,3}));?/u.exec(text.slice(at, at + 10));
    if (entity) {
      const value = entity[1] ? parseInt(entity[1], 16) : Number(entity[2]);
      if (value <= 255) return { byte: value, end: at + entity[0].length };
    }
  }
  return null;
}

function escapedRun(start: number, end: number, bytes: number[], byteSyntax: boolean): EncodedRun {
  return { start, end, value: bytes.map((byte) => byte.toString(16).padStart(2, '0')).join(''),
    // Unicode escapes for ordinary accented prose are ambiguous Latin-1, so inspect them without opaque counting
    // unless control bytes or explicitly byte-oriented syntax make the representation binary.
    prefixed: false, countable: byteSyntax || bytes.some((byte) => byte < 32 || byte === 127), separated: true, escaped: true };
}

/** Direct escape runs plus mixed byte string literals, including Latin-1 JSON and Python/JS strings. */
function* escapedByteRuns(text: string): Generator<EncodedRun> {
  for (let at = 0; at < text.length;) {
    const first = escapedByteAt(text, at);
    if (!first) { at++; continue; }
    const start = at;
    const bytes: number[] = [];
    let byteSyntax = false;
    for (let token: { byte: number; end: number } | null = first; token; token = escapedByteAt(text, at)) {
      bytes.push(token.byte);
      if (text[at] === '%' || text[at] === '=' || text[at] === '\\' && !/[uU]/u.test(text[at + 1]!)) byteSyntax = true;
      at = token.end;
    }
    if (bytes.length >= 4) yield escapedRun(start, at, bytes, byteSyntax);
  }
  const quoted = (start: number, prefixed: boolean): { run: EncodedRun | null; end: number } => {
    const quote = text[start]!;
    const bytes: number[] = [];
    let escaped = 0, byteSyntax = prefixed, latin1High = false, valid = true, closed = false;
    let at = start + 1;
    for (; at < text.length; at++) {
      const char = text[at]!;
      if (char === quote) { closed = true; break; }
      // A lone `=EC` in a log assignment is not quoted-printable. Only contiguous QP runs are read above.
      const token = escapedByteAt(text, at, false);
      if (token) {
        bytes.push(token.byte);
        escaped++;
        if (char === '%' || char === '\\' && !/[uU]/u.test(text[at + 1]!)) byteSyntax = true;
        at = token.end - 1;
        continue;
      }
      if (char === '\\') {
        const simple: Readonly<Record<string, number>> = { '0': 0, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, '\\': 92, '"': 34, "'": 39 };
        const value = simple[text[at + 1]!];
        if (value !== undefined) { bytes.push(value); at++; continue; }
        valid = false;
        break;
      }
      const code = text.charCodeAt(at);
      if (code > 255) { valid = false; break; }
      if (code >= 128) latin1High = true;
      bytes.push(code);
    }
    return { run: valid && closed && bytes.length >= 4 && (escaped >= 2 || latin1High)
      ? escapedRun(start + 1, at, bytes, byteSyntax) : null, end: at };
  };
  for (let at = 0; at < text.length; at++) {
    if (text[at] !== '"' && text[at] !== "'") continue;
    const result = quoted(at, text[at - 1] === 'b');
    if (result.run) yield result.run;
    at = result.end;
  }
  // The outer JSON string can contain a Python byte literal. Scan its `b'…'` span independently after the
  // JSON escape round; otherwise the outer quote absorbs the literal and a short raw-deflate stream is missed.
  for (const match of text.matchAll(/\bb(?=["'])/gu)) {
    const result = quoted(match.index + 1, true);
    if (result.run) yield result.run;
  }
}
/**
 * Decompress binary as gzip or zlib (signature in the first 16 bytes), brotli or raw deflate, tolerating a
 * truncated stream, within the per-message output budget. `consumed` is how many input bytes the stream used, so
 * bytes after the end of a stream are not presumed decompressed. gzip/zlib decodes are `signed`; brotli and raw
 * deflate (which can succeed by accident on ordinary text) are tentative match-only views. Returns 'BUDGET'
 * when the message's decompression budget is exhausted.
 */
const SYNC_FLUSH = 2;
interface Inflated { out: Uint8Array; signed: boolean; consumed: number }
type Engine = (buffer: Uint8Array, options: { maxOutputLength: number; finishFlush: number; info: true }) => { buffer: Uint8Array; engine: { bytesWritten: number } };
function inflate(bytes: Uint8Array, budget: { inflated: number }): Inflated | null | 'BUDGET' {
  const attempt = (engine: Engine, input: Uint8Array, start: number, signed: boolean, trailer = 0): Inflated | null | 'BUDGET' => {
    const remaining = MAX_INFLATE_TOTAL - budget.inflated;
    if (remaining <= 0) return 'BUDGET';
    try {
      const { buffer: out, engine: state } = engine(input, { maxOutputLength: remaining, finishFlush: SYNC_FLUSH, info: true });
      budget.inflated += out.length;
      const consumed = Math.min(bytes.length, start + (state.bytesWritten || input.length) + trailer);
      // A gzip/zlib stream that decoded is a stream even when its output is tiny or empty, so a chain continues.
      if (signed) return consumed > start ? { out, signed, consumed } : null;
      if (out.length < 4) return null;
      return { out, signed, consumed };
    } catch (error) {
      return (error as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE' ? 'BUDGET' : null;
    }
  };
  for (let offset = 0; offset < Math.min(16, bytes.length - 1); offset++) {
    const view = bytes.subarray(offset);
    const gzip = view[0] === 0x1f && view[1] === 0x8b && view[2] === 8;
    const zlib = view[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(view[1]!);
    if (!gzip && !zlib) continue;
    if (zlib) {
      const result = attempt(inflateSync as unknown as Engine, view, offset, true);
      if (result) return result;
      continue;
    }
    const whole = attempt(gunzipSync as unknown as Engine, view, offset, true);
    if (whole === 'BUDGET') return whole;
    if (whole) return whole;
    // gunzip rejects bytes after the stream; read the member's deflate body directly instead.
    const body = gzipBody(view);
    if (body >= 0) {
      // The member's 8-byte CRC/size trailer follows its deflate body.
      const result = attempt(inflateRawSync as unknown as Engine, view.subarray(body), offset + body, true, 8);
      if (result) return result;
    }
  }
  const brotli = attempt(brotliDecompressSync as unknown as Engine, bytes, 0, false);
  if (brotli) return brotli;
  return attempt(inflateRawSync as unknown as Engine, bytes, 0, false);
}
/** Offset of the deflate body after a gzip member header (RFC 1952), or -1. */
function gzipBody(view: Uint8Array): number {
  const flags = view[3] ?? 0;
  let at = 10;
  if (flags & 4) at += 2 + ((view[at] ?? 0) | ((view[at + 1] ?? 0) << 8));
  for (const flag of [8, 16]) if (flags & flag) { while (at < view.length && view[at] !== 0) at++; at++; }
  if (flags & 2) at += 2;
  return at < view.length ? at : -1;
}
const MAX_INFLATE_DEPTH = 4;
// `consumed`: input accounted for. After a real stream that is all of it: any remainder was decoded along the chain,
// matched as text or counted as opaque.
interface Expanded { opaque: number; consumed: number; keep: boolean }
/**
 * Decompress `bytes` and any compressed layers inside, to MAX_INFLATE_DEPTH. Text layers go to `sink.texts` (views
 * that are inspected and counted like any other), binary layers to `sink.printables`. Returns null when nothing
 * decompresses, 'CONTAINER' for a container signature inside, 'BUDGET', or the opaque bytes it found: binary
 * gzip/zlib output and bytes after a stream's end. `keep` marks tentative brotli/raw deflate output: the input's
 * own count then stands, and nested results are matching evidence only.
 */
/**
 * Views from decompression: `texts` are inspected and counted, `uncertain` texts (found under output that may be
 * accidental) are decoded further but never counted, `printables` and `junk` are matched only.
 */
interface Sink { texts: string[]; uncertain: string[]; printables: string[]; junk: string[] }
const MAX_STREAM_CHAIN = 256;
/**
 * Overlap queries against a set of spans in O(log n): spans sorted by start, with the running maximum end. Some span
 * overlaps [a, b) exactly when the largest end among spans starting before b exceeds a.
 */
function spanIndex(sorted: readonly (readonly [number, number])[]): (span: readonly [number, number]) => boolean {
  const spans = [...sorted].sort((x, y) => x[0] - y[0]);
  const maxEnd: number[] = [];
  for (const [index, span] of spans.entries()) maxEnd.push(Math.max(span[1], index ? maxEnd[index - 1]! : -1));
  return ([a, b]) => {
    let low = 0, high = spans.length;
    while (low < high) { const mid = (low + high) >> 1; if (spans[mid]![0] < b) low = mid + 1; else high = mid; }
    return low > 0 && maxEnd[low - 1]! > a;
  };
}
/** A gzip or zlib signature in the first 16 bytes, where `inflate` looks for one. */
function startsStream(bytes: Uint8Array): boolean {
  for (let offset = 0; offset < Math.min(16, bytes.length - 1); offset++) {
    if (bytes[offset] === 0x1f && bytes[offset + 1] === 0x8b || bytes[offset] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(bytes[offset + 1]!)) return true;
  }
  return false;
}
function expand(bytes: Uint8Array, budget: { inflated: number }, sink: Sink, depth = 0, chain = 0): Expanded | null | 'CONTAINER' | 'BUDGET' {
  const inflated = inflate(bytes, budget);
  if (inflated === 'BUDGET' || inflated === null) return inflated;
  const { out, signed, consumed } = inflated;
  const decoded = out;
  // Every layer is matched: as text when it is text, and as printable bytes and UTF-16 otherwise.
  const matchBinary = (): void => { sink.printables.push(printable(decoded), utf16Printable(out)); };
  // Brotli/raw deflate has no reliable signature. Even plausible printable output from ordinary decimal text
  // is only tentative: inspect it and its nested layers, but never use it to lower or raise opaque authority.
  if (!signed) {
    sink.junk.push(printable(decoded), utf16Printable(out));
    if (isText(decoded)) sink.uncertain.push(utf8Lenient.decode(out));
    if (depth + 1 < MAX_INFLATE_DEPTH) {
      const inner: Sink = { texts: [], uncertain: [], printables: [], junk: [] };
      for (const part of consumed < bytes.length ? [out, bytes.subarray(consumed)] : [out]) {
        const result = expand(part, budget, inner, depth + 1);
        // Only a successfully decoded signed gzip/zlib layer can return CONTAINER. Preserve that restrictive
        // finding even when the layer was reached through tentative raw deflate or brotli output.
        if (result === 'CONTAINER' || result === 'BUDGET') return result;
      }
      sink.uncertain.push(...inner.texts, ...inner.uncertain);
      sink.junk.push(...inner.printables, ...inner.junk);
    }
    return { opaque: 0, consumed, keep: true };
  }
  if (OPAQUE_SIGNATURES.some((signature) => signature.every((byte, index) => out[index] === byte))) return 'CONTAINER';
  // Bytes after the stream's end: another stream (followed along the chain, not nested), text, or opaque bytes.
  let trailing = 0;
  if (consumed < bytes.length) {
    const tail = bytes.subarray(consumed);
    const next = chain + 1 < MAX_STREAM_CHAIN ? expand(tail, budget, sink, depth, chain + 1) : null;
    if (next === 'CONTAINER' || next === 'BUDGET') return next;
    if (next && !next.keep) trailing = next.opaque;
    else if (isText(tail)) sink.texts.push(utf8Lenient.decode(tail));
    else { trailing = tail.length; sink.printables.push(printable(tail), utf16Printable(tail)); }
  }
  if (isText(decoded)) { sink.texts.push(utf8Lenient.decode(out)); return { opaque: trailing, consumed: bytes.length, keep: false }; }
  matchBinary();
  const nested = depth + 1 < MAX_INFLATE_DEPTH ? expand(out, budget, sink, depth + 1) : null;
  if (nested === 'CONTAINER' || nested === 'BUDGET') return nested;
  if (nested && !nested.keep) return { opaque: nested.opaque + trailing, consumed: bytes.length, keep: false };
  return { opaque: out.length + trailing, consumed: bytes.length, keep: false };
}
/** UTF-16LE reading of binary, printable characters only, so UTF-16 text inside a binary layer is matched. */
function utf16Printable(bytes: Uint8Array): string {
  let text = '';
  for (let index = 0; index + 1 < bytes.length; index += 2) {
    const code = bytes[index]! | (bytes[index + 1]! << 8);
    text += code >= 0x20 && code !== 0x7f && (code < 0xd800 || code > 0xdfff) && code !== 0xfffd ? String.fromCharCode(code) : ' ';
  }
  return text;
}
const utf8Lenient = new TextDecoder('utf-8', { fatal: false });
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
/**
 * The sentinel's own decode of a short encoded run into printable bytes (others become spaces). Known-value
 * matching ignores separators, so a value scattered between binary bytes (`\0orla\3Synthe\7tica`) is found.
 */
function decodeRun(run: string): number[] | null {
  const bytes: number[] = [];
  if (/^(?:[0-9A-Fa-f]{2})+$/u.test(run)) {
    for (let index = 0; index < run.length; index += 2) bytes.push(parseInt(run.slice(index, index + 2), 16));
  } else {
    let buffer = 0, bits = 0;
    for (const char of run.replace(/=+$/u, '').replace(/-/gu, '+').replace(/_/gu, '/')) {
      const value = B64.indexOf(char);
      if (value < 0) return null;
      buffer = ((buffer << 6) | value) & 0xffffff;
      bits += 6;
      if (bits >= 8) { bits -= 8; bytes.push((buffer >> bits) & 0xff); }
    }
  }
  return bytes;
}
function isText(bytes: ArrayLike<number>): boolean {
  try { return !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(utf8.decode(bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes))); } catch { return false; }
}
const latin1 = new TextDecoder('latin1');
function printable(bytes: ArrayLike<number>): string {
  return latin1.decode(Uint8Array.from(bytes, (byte) => byte >= 0x20 && byte < 0x7f ? byte : 0x20));
}

/* ---------- Canonical views ---------- */

const NAMED_ENTITIES: Readonly<Record<string, string>> = Object.freeze({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', bsol: '\\', percnt: '%' });
/**
 * One round of the sentinel's own escape decoding: JSON/JS `\uXXXX`, `\u{...}`, `\xNN`, octal `\NNN`,
 * simple backslash escapes, HTML entities (hex in either case, decimal, named; `;` optional), `%uXXXX` and
 * quoted-printable. Returns null when nothing changes. Rounds repeat to a fixpoint (bounded).
 */
function unescapeOnce(text: string): string | null {
  const out = text
    .replace(/&#[xX]([0-9A-Fa-f]{1,6});?|&#(\d{1,7});?|&([a-zA-Z]{2,8});/gu, (all, hex, dec, name) => {
      const point = hex ? parseInt(hex, 16) : dec ? Number(dec) : -1;
      if (point >= 0) return point <= 0x10ffff ? String.fromCodePoint(point) : all;
      return NAMED_ENTITIES[(name as string).toLowerCase()] ?? all;
    })
    .replace(/\\U([0-9A-Fa-f]{8})|\\u\{([0-9A-Fa-f]{1,6})\}|\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})|\\([0-9A-Fa-f]{1,6}) |\\((?=[0-9A-Fa-f]{0,5}[A-Fa-f])[0-9A-Fa-f]{1,6})|\\([0-7]{1,3})|\\([\\/"'bfnrt])/gu,
      // CSS escapes (hex with a letter, or followed by a space) take precedence over octal.
      (all, u8, cp, u4, x2, cssSpaced, cssHex, octal, simple) => {
        const wide = u8 ?? cp ?? cssSpaced ?? cssHex;
        if (wide) { const point = parseInt(wide, 16); return point <= 0x10ffff ? String.fromCodePoint(point) : all; }
        if (u4) return String.fromCharCode(parseInt(u4, 16));
        if (x2) return String.fromCharCode(parseInt(x2, 16));
        if (octal) { const value = parseInt(octal, 8); return value <= 255 ? String.fromCharCode(value) : all; }
        return ({ b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' } as Record<string, string>)[simple!] ?? simple!;
      })
    .replace(/%u([0-9A-Fa-f]{4})/gu, (_all, u4) => String.fromCharCode(parseInt(u4, 16)))
    // Quoted-printable only where it is unambiguous: runs of two or more `=XX` escapes (a lone `key=44` is text).
    .replace(/(?:=[0-9A-F]{2}){2,}/gu, (run) => run.replace(/=([0-9A-F]{2})/gu, (_all, hex) => String.fromCharCode(parseInt(hex, 16))));
  const softBreaks = /(?:=[0-9A-F]{2}){2,}/u.test(text) ? out.replace(/=\r?\n/gu, '') : out;
  return softBreaks === text ? null : softBreaks;
}

interface View { name: string; text: string; derived?: boolean; matchOnly?: boolean }
const INVALID_BYTE_OCTAL = /\\[4-7][0-7]{2}/u;
/**
 * All canonical views: each text is decoded by #6 (Base64/percent/hex) and by the escape round, and every
 * resulting view is processed again, to MAX_ROUNDS. Returns a block reason when anything is uninspectable.
 */
function canonicalViews(root: string): { views: View[]; opaque: boolean } | { reason: string } {
  const views: View[] = [];
  const budget = { inflated: 0 };
  const countedValues = new Set<string>();
  const countedBytes: string[] = [];
  let opaqueTotal = 0;
  let queue: View[] = [{ name: 'ROOT', text: root }];
  let units = 0;
  for (let round = 0; queue.length && round <= MAX_ROUNDS; round++) {
    const next: View[] = [];
    for (const view of queue) {
      if (views.length >= MAX_VIEWS || (units += view.text.length) > MAX_VIEW_UNITS) return { reason: 'SENTINEL_BUDGET' };
      views.push(view);
      if (INVALID_BYTE_OCTAL.test(view.text)) return { reason: 'UNINSPECTED_CONTENT' };
      if (round === MAX_ROUNDS || view.matchOnly) continue;
      const normalized = normalizeInput(view.text);
      // Content the sentinel cannot fully inspect, or embedded binary it cannot read, is never presumed clean.
      if (normalized.status !== 'COMPLETE') return { reason: 'UNINSPECTED_CONTENT' };
      // Opacity is judged on decoded bytes, so chunking or wrapping cannot hide binary: a wrapped/joined #6 view
      // of binary, any run decoding to compressed data, or any non-text decode of OPAQUE_BYTES or more blocks.
      const textSpans = normalized.views.filter((child) => child.parent === 0 && child.form === 'TEXT').flatMap((child) => child.occurrences);
      for (const child of normalized.views.slice(1)) {
        // A decode of a recognized digest/UUID (a hex trace id read as base64) is noise, not a payload layer.
        const fromIdentifier = child.parent === 0 && child.occurrences.every((o) => isIdentifierRun(view.text.slice(o.start, o.end)));
        next.push({ name: `${view.name}>${child.encoding}`, text: child.text,
          derived: view.derived === true || child.form === 'STRINGS' || fromIdentifier });
      }
      // Other encoded runs that are not text. Container signatures are opaque at once. Everything else is tried
      // for decompression (the concatenation first, then up to 256 runs, until one covers the whole message);
      // decompressed and printable bytes become matching views. Any remaining binary that is not a recognized
      // digest, UUID or public key counts toward OPAQUE_BYTES, whatever its chunking.
      const printables: string[] = [];
      const joinedTexts: string[] = [];
      const binary: Uint8Array[] = [];
      let countable = 0;
      const spans: [number, number][] = [];
      const chunkJoin: boolean[] = [];
      const runCounts: number[] = [];
      const runIdentified: boolean[] = [];
      const publicBlocks = [...view.text.matchAll(PUBLIC_PEM)].filter((block) => derShaped(block[0]))
        .map((block) => ({ start: block.index, end: block.index + block[0].length }));
      for (const run of encodedRuns(view.text)) {
        if (textSpans.some((span) => span.start <= run.start && run.end <= span.end)) continue;
        const decoded = decodeRun(run.value);
        if (!decoded) continue;
        // Text from joined chunks or separated hex is a layer #6 did not see: inspect it like any decoded view.
        if (isText(decoded)) { if (run.separated) joinedTexts.push(utf8Lenient.decode(Uint8Array.from(decoded))); continue; }
        const bytes = Uint8Array.from(decoded);
        // Not counted: exact-length digests (with or without a `shaNNN-`/`h1:` prefix), SSH key blobs, UUIDs,
        // identifiers (`http2ServerSessionOptions`), runs that do not look encoded (lower-case paths, snake_case
        // ids), and anything inside views derived from decompression or printable bytes.
        // All-decimal runs (nanosecond timestamps, snowflake ids, float digits) are numbers, not hex.
        // Mixed case with a digit, `+`, or frequent case switches (digit-free random Base64); camelCase names are
        // exempted by the identifier check.
        const mixedCase = /[A-Z]/u.test(run.value) && /[a-z]/u.test(run.value);
        // A long run of `/` is Base64 alphabet data; treating it as plain path punctuation can hide opaque bytes.
        const encodedShape = run.escaped === true || /^[0-9A-Fa-f]+$/u.test(run.value) && /[A-Fa-f]/u.test(run.value) ||
          /={1,2}$/u.test(run.value) || /\/{8,}/u.test(run.value) ||
          mixedCase && (/\d|\+/u.test(run.value) || (run.value.match(/[a-z][A-Z]/gu)?.length ?? 0) * 6 >= run.value.length);
        const before = view.text.slice(Math.max(0, run.start - 32), run.start);
        // A digest is one unbroken run; joined chunks or separated hex of digest length are not exempt.
        const digestContext = DIGEST_CONTEXT.exec(before);
        const digest = run.separated !== true && (digestContext ? isContextDigest(digestContext, run.value, bytes.length) :
          DIGEST_HEX.test(run.value) && isDigest(run.value));
        const identified = digest || publicBlocks.some((block) => block.start <= run.start && run.end <= block.end) ||
          B64_ALPHABET.test(run.value) || isSshEd25519PublicKey(before, run.value, bytes) || UUID.test(run.value);
        const recognized = identified || !encodedShape || !run.countable || view.derived === true || isIdentifier(run.value);
        // A container signature is opaque at once, unless the run is a digest or id that happens to start with one.
        if (!identified && OPAQUE_SIGNATURES.some((signature) => signature.every((byte, index) => bytes[index] === byte))) return { reason: 'OPAQUE_EMBEDDED' };
        binary.push(bytes);
        spans.push([run.start, run.end]);
        chunkJoin.push(run.joined === true);
        // Each distinct run counts once per message. An escape view repeats its parent's runs, sometimes with one
        // more or one fewer leading character (`\nQUJD…` becomes a newline and `QUJD…`).
        // A run whose bytes are part of an already counted run (the same token split by an escape) counts once too.
        const byteKey = String.fromCharCode(...bytes.subarray(0, 4096));
        const seen = countedValues.has(run.value) || countedValues.has(run.value.slice(1)) ||
          bytes.length >= 8 && countedBytes.some((counted) => counted.includes(byteKey));
        const counted = recognized || seen ? 0 : bytes.length;
        if (counted) { countedValues.add(run.value); countedValues.add(run.value.slice(1)); countedBytes.push(byteKey); }
        runCounts.push(counted);
        runIdentified.push(identified);
        countable += counted;
        const text = printable(decoded);
        if (text.trim()) printables.push(text);
      }
      if (printables.length) next.push({ name: `${view.name}>BINARY_PRINTABLE`, text: printables.join('\n'), derived: true });
      if (joinedTexts.length) next.push({ name: `${view.name}>JOINED`, text: joinedTexts.join('\n'), derived: view.derived === true });
      if (binary.length) {
        // The concatenation takes whole runs and byte-pair runs first, then chunk joins that overlap none of them, in
        // text order and without overlaps, so one stream is not chained to copies of itself (a chunk join and its
        // word-free variant, or a join across a hex dump's offset column).
        const bySpan = (a: number, b: number): number => spans[a]![0] - spans[b]![0] || spans[b]![1] - spans[a]![1];
        const whole = binary.map((_, index) => index).filter((index) => !chunkJoin[index]).sort(bySpan);
        const wholeOverlaps = spanIndex(whole.map((index) => spans[index]!));
        const taken: number[] = [];
        let reach = -1;
        for (const index of whole) if (spans[index]![0] >= reach) { taken.push(index); reach = spans[index]![1]; }
        const takenOverlaps = spanIndex(taken.map((index) => spans[index]!));
        reach = -1;
        for (const index of binary.map((_, i) => i).filter((i) => chunkJoin[i]).sort(bySpan)) {
          if (taken.length >= 4096 || spans[index]![0] < reach || takenOverlaps(spans[index]!)) continue;
          taken.push(index);
          reach = spans[index]![1];
        }
        taken.sort((a, b) => spans[a]![0] - spans[b]![0]);
        const offsets: number[] = binary.map(() => -1);
        let offset = 0;
        for (const index of taken) { offsets[index] = offset; offset += binary[index]!.length; }
        const joined = new Uint8Array(offset);
        for (const [index, start] of offsets.entries()) if (start >= 0) joined.set(binary[index]!, start);
        const sink: Sink = { texts: [], uncertain: [], printables: [], junk: [] };
        const covered = new Set<number>();
        // A chunk join that overlaps a whole or byte-pair run may be misaligned (across padding or words); a pure one
        // is the only reading of its chunks.
        const misalignable = binary.map((_, index) => chunkJoin[index] === true && wholeOverlaps(spans[index]!));
        // Candidates: the whole concatenation, the concatenation from each later run that starts with a gzip/zlib
        // signature (a dump after unrelated hex ids), then single runs.
        const starts = taken.filter((index, position) => position > 0 && startsStream(binary[index]!)).slice(0, 256);
        const candidates: { bytes: Uint8Array; base: number; single: number }[] = binary.length > 1
          ? [{ bytes: joined, base: 0, single: -1 }, ...starts.map((index) => ({ bytes: joined.subarray(offsets[index]!), base: offsets[index]!, single: -1 })),
            ...binary.slice(0, 256).map((bytes, index) => ({ bytes, base: 0, single: index }))]
          : [{ bytes: binary[0]!, base: 0, single: 0 }];
        for (const { bytes: candidate, base, single } of candidates) {
          if (single >= 0 && covered.has(single)) continue;
          if (single < 0 && base > 0 && taken.every((index) => offsets[index]! < base || covered.has(index))) continue;
          const result = expand(candidate, budget, sink);
          if (result === 'BUDGET') return { reason: 'SENTINEL_BUDGET' };
          if (result === 'CONTAINER') return { reason: 'OPAQUE_EMBEDDED' };
          if (result === null || result.keep) continue;
          // Runs the stream consumed are decompressed, not opaque: their count is replaced by what the stream held
          // (binary gzip/zlib output, bytes after its end). Streams in recognized digests count nothing.
          const runs = single >= 0 ? [single] : offsets.flatMap((start, index) =>
            start >= base && start + binary[index]!.length <= base + result.consumed ? [index] : []);
          if (!runs.length) continue;
          for (const index of runs) { covered.add(index); countable -= runCounts[index]!; runCounts[index] = 0; }
          // A join that may be misaligned must not add stream remainders; digests that look like streams add nothing.
          if (!view.derived && !runs.every((index) => runIdentified[index] || misalignable[index])) countable += result.opaque;
          if (covered.size === binary.length) break;
        }
        // A stream deeper inside a run (a dump after other byte pairs in one long run) is decoded for matching only;
        // the run's own count stands.
        // At most 256 decoded streams per run and 8192 attempts per view, skipping bytes a decoded stream covered.
        // Failed attempts are cheap, so decoy signatures cannot use up the stream budget.
        let attempts = 0;
        for (const [index, bytes] of binary.entries()) {
          if (covered.has(index) || attempts >= 8192) continue;
          for (let at = 16, streams = 0; at + 2 < bytes.length && streams < 256 && attempts < 8192; at++) {
            if (!(bytes[at] === 0x1f && bytes[at + 1] === 0x8b && bytes[at + 2] === 8 || bytes[at] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(bytes[at + 1]!))) continue;
            attempts++;
            const result = expand(bytes.subarray(at), budget, sink);
            if (result === 'BUDGET') return { reason: 'SENTINEL_BUDGET' };
            if (result === 'CONTAINER') return { reason: 'OPAQUE_EMBEDDED' };
            if (result && !result.keep) { streams++; at += result.consumed - 1; }
          }
        }
        if (sink.texts.length) next.push({ name: `${view.name}>INFLATED`, text: sink.texts.join('\n'), derived: view.derived === true });
        // Binary layers are matched but not decoded further: signed binary output already counts as opaque in full.
        if (sink.printables.length) next.push({ name: `${view.name}>INFLATED_BINARY`, text: sink.printables.join('\n'), derived: true, matchOnly: true });
        if (sink.uncertain.length) next.push({ name: `${view.name}>INFLATED_UNCERTAIN_TEXT`, text: sink.uncertain.join('\n'), derived: true });
        if (sink.junk.length) next.push({ name: `${view.name}>INFLATED_UNCERTAIN`, text: sink.junk.join('\n'), derived: true, matchOnly: true });
      }
      // One opaque total per message, across all views and rounds (distinct runs are counted once).
      // Once the message is opaque it blocks whatever else it holds: stop decoding and match what is decoded so far.
      if ((opaqueTotal += countable) > OPAQUE_BYTES) return { views: [...views, ...next], opaque: true };
      const unescaped = unescapeOnce(view.text);
      if (unescaped !== null) next.push({ name: `${view.name}>ESCAPES`, text: unescaped, derived: view.derived === true });
    }
    queue = next;
    if (round === MAX_ROUNDS && queue.length) return { reason: 'SENTINEL_BUDGET' };
  }
  return { views, opaque: false };
}

/* ---------- Check ---------- */

const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
function blocked(reasons: Iterable<string>, findings: SentinelFinding[] = []): SentinelResult {
  const sortedReasons = Object.freeze([...new Set(reasons)].sort());
  return Object.freeze({
    decision: 'BLOCK', reasons: sortedReasons, findings: Object.freeze(findings.map((finding) => Object.freeze(finding))),
    regression: Object.freeze({ version: SENTINEL_VERSION, reasons: sortedReasons,
      rules: Object.freeze([...new Set(findings.map((finding) => finding.rule))].sort()),
      views: Object.freeze([...new Set(findings.map((finding) => finding.view))].sort()) }),
  });
}
/** Restrictive outage behaviour: when the sentinel cannot run, high-risk egress is blocked. */
export function sentinelUnavailable(): SentinelResult {
  return blocked(['SENTINEL_UNAVAILABLE']);
}
/** Read a destination once into primitives, so getters cannot answer differently on a second read. */
function snapshot(value: unknown): { id: string; profileDigest: string } | null {
  if (!value || typeof value !== 'object') return null;
  const { id, profileDigest } = value as Record<string, unknown>;
  return label(id) && label(profileDigest) ? { id, profileDigest } : null;
}
/** Match short encodings only when this scope has short originals. They add no opaque-byte count. */
function shortKnownMatches(known: Known, views: readonly View[], budget: { verifications: number; probes: number }):
  Map<number, string> | { reason: string } {
  const hits = new Map<number, string>();
  const seen = new Set<string>();
  const inflateBudget = { inflated: 0 };
  for (const view of views) {
    for (const run of view.text.matchAll(SHORT_ENCODED_RUN)) {
      if (seen.has(run[0])) continue;
      if (seen.size >= MAX_SHORT_RUNS) return { reason: 'SENTINEL_BUDGET' };
      seen.add(run[0]);
      const value = /^0[xX](?=[0-9A-Fa-f]{8,14}$)/u.test(run[0]) ? run[0].slice(2) : run[0];
      const decoded = decodeRun(value);
      if (!decoded || decoded.length < MIN_ORIGINAL) continue;
      const bytes = Uint8Array.from(decoded);
      const texts = [utf8Lenient.decode(bytes), printable(bytes), utf16Printable(bytes)];
      const sink: Sink = { texts: [], uncertain: [], printables: [], junk: [] };
      const expanded = expand(bytes, inflateBudget, sink);
      if (expanded === 'BUDGET') return { reason: 'SENTINEL_BUDGET' };
      if (expanded === 'CONTAINER') return { reason: 'OPAQUE_EMBEDDED' };
      texts.push(...sink.texts, ...sink.uncertain, ...sink.printables, ...sink.junk);
      for (const text of texts) {
        for (const index of matchKnown(known, text, budget)) {
          if (!hits.has(index)) hits.set(index, `${view.name}>SHORT_ENCODED`);
        }
      }
    }
  }
  return hits;
}

/**
 * Check the exact bytes an adapter is about to send. ALLOW only when the bytes are valid UTF-8, fully
 * inspectable, sent to the authorized destination/profile, and contain no known original, canary or
 * high-risk pattern in any canonical view. The caller must then send `release`, not its own buffer.
 */
export function checkEgress(check: EgressCheck): SentinelResult {
  try {
    const { bytes: input, scope, destination, authorized, known: handle } = check;
    if (!(input instanceof Uint8Array) || !scope || typeof scope !== 'object') return blocked(['INVALID_CHECK']);
    // Copy the underlying bytes (not via an overridable iterator): every later step and `release` use this
    // snapshot. Callers must send `release`, never their own buffer.
    const bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength).slice();
    if (bytes.byteLength > MAX_MESSAGE_BYTES) return blocked(['MESSAGE_TOO_LARGE']);
    const observed = snapshot(destination), allowed = snapshot(authorized);
    if (!observed || !allowed || observed.id !== allowed.id || observed.profileDigest !== allowed.profileDigest) {
      return blocked(['DESTINATION_MISMATCH']);
    }
    let known: Known | undefined;
    if (handle === undefined) return blocked(['KNOWN_ORIGINALS_REQUIRED']);
    if (handle !== null) {
      known = typeof handle === 'object' ? registry.get(handle) : undefined;
      if (!known) return blocked(['KNOWN_ORIGINALS_INVALID']);
      const { tenantRef, projectRef } = scope as unknown as Record<string, unknown>;
      if (known.scope.tenantRef !== tenantRef || known.scope.projectRef !== projectRef) return blocked(['KNOWN_ORIGINALS_SCOPE_MISMATCH']);
    }
    let root: string;
    try { root = utf8.decode(bytes); } catch { return blocked(['OPAQUE_CONTENT']); }
    const canonical = canonicalViews(root);
    if ('reason' in canonical) return blocked([canonical.reason]);
    const findings: SentinelFinding[] = [];
    const seen = new Set<string>();
    const budget = { verifications: 0, probes: 0 };
    for (const view of canonical.views) {
      if (known) {
        for (const index of matchKnown(known, view.text, budget)) {
          const entry = known.entries[index]!;
          const key = `${entry.ref}|${view.name}`;
          if (!seen.has(key)) { seen.add(key); findings.push({ kind: entry.kind === 'CANARY' ? 'CANARY' : 'KNOWN_ORIGINAL', rule: entry.ref, view: view.name }); }
        }
      }
      // Case-preserving compatibility view (full-width, zero-width removed) for the case-sensitive patterns.
      const compatible = view.text.normalize('NFKC').replace(/\p{Default_Ignorable_Code_Point}/gu, '');
      for (const { rule, pattern } of PATTERNS) {
        const key = `${rule}|${view.name}`;
        if (!seen.has(key) && (pattern.test(view.text) || pattern.test(compatible))) { seen.add(key); findings.push({ kind: 'PATTERN', rule, view: view.name }); }
      }
      const assignmentKey = `pattern.credential-assignment|${view.name}`;
      if (!seen.has(assignmentKey) && (credentialAssignment(view.text) || credentialAssignment(compatible))) {
        seen.add(assignmentKey);
        findings.push({ kind: 'PATTERN', rule: 'pattern.credential-assignment', view: view.name });
      }
    }
    if (known?.shorts.size) {
      const short = shortKnownMatches(known, canonical.views, budget);
      if ('reason' in short) return blocked([short.reason], findings);
      for (const [index, view] of short) {
        const entry = known.entries[index]!;
        const key = `${entry.ref}|${view}`;
        if (!seen.has(key)) { seen.add(key); findings.push({ kind: entry.kind === 'CANARY' ? 'CANARY' : 'KNOWN_ORIGINAL', rule: entry.ref, view }); }
      }
    }
    if (findings.length || canonical.opaque) {
      const reasons = findings.map((finding) => finding.kind === 'CANARY' ? 'CANARY_DETECTED' :
        finding.kind === 'KNOWN_ORIGINAL' ? 'KNOWN_ORIGINAL_DETECTED' : 'HIGH_RISK_PATTERN');
      // Findings in decoded views give the precise reason; opaque binary blocks even without one.
      return blocked(canonical.opaque ? [...reasons, 'OPAQUE_EMBEDDED'] : reasons, findings);
    }
    return Object.freeze({ decision: 'ALLOW', reasons: Object.freeze([]), findings: Object.freeze([]), release: bytes });
  } catch (error) {
    // An exhausted budget or an internal failure is restrictive, never a pass.
    return blocked([error instanceof BudgetExceeded ? 'SENTINEL_BUDGET' : 'SENTINEL_ERROR']);
  }
}

/* ---------- Streaming: hold the complete message, check once, then release or block ---------- */

export interface StreamGate {
  /** Buffer a chunk. Nothing is released before `end()`; exceeding the size limit blocks the whole stream. */
  push(chunk: Uint8Array): { accepted: boolean };
  /** Check the assembled message; returns the bytes to release only on ALLOW. */
  end(): { result: SentinelResult; release?: Uint8Array };
}
export function createStreamGate(check: Omit<EgressCheck, 'bytes'>, maxBytes = MAX_MESSAGE_BYTES): StreamGate {
  const chunks: Uint8Array[] = [];
  let size = 0, failed = false, ended = false;
  return Object.freeze({
    push(chunk: Uint8Array) {
      try {
        if (ended || failed || !(chunk instanceof Uint8Array)) { failed = true; return { accepted: false }; }
        // Copy first and size from the copy, so a lying `length` cannot misstate the buffer.
        const copy = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength).slice();
        size += copy.byteLength;
        if (size > maxBytes) { failed = true; chunks.length = 0; return { accepted: false }; }
        chunks.push(copy);
        return { accepted: true };
      } catch { failed = true; chunks.length = 0; return { accepted: false }; }
    },
    end() {
      try {
        if (ended) return { result: blocked(['STREAM_ALREADY_ENDED']) };
        ended = true;
        if (failed) return { result: blocked(['STREAM_REJECTED']) };
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        chunks.length = 0;
        const result = checkEgress({ ...check, bytes });
        return result.decision === 'ALLOW' ? { result, release: result.release! } : { result };
      } catch { return { result: blocked(['SENTINEL_ERROR']) }; }
    },
  });
}
