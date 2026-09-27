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

const PATTERNS: readonly { rule: string; pattern: RegExp }[] = [
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
  { rule: 'pattern.url-password', pattern: /[a-z][a-z0-9+.-]{1,31}:\/\/[^\s:/@"']{1,256}:[^\s/@"']{3,256}@/iu },
];
// A literal value after a credential-like key. References (`${X}`, `{{x}}`, `<...>`, masks), type names,
// booleans and identifier/member expressions (`process.env.SECRET`, `config.password`) are not values.
const CREDENTIAL_ASSIGNMENT = /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*(?:(["'])([^"'\r\n]{4,})\1|([^\s"',;)]{4,}))/giu;
const REFERENCE = /^(?:\$\{[^}]*\}|\{\{[^}]*\}\}|<[\w -]{1,40}>|\*{3,}|\[hylja:protected:[A-Z0-9_]+\])$/u;
const NOT_A_VALUE = /^(?:[$<*{[]|(?:string|number|boolean|bigint|object|any|unknown|undefined|null|none|true|false|nil|str|int|bool|bytes)$|[A-Za-z_$][\w$]*(?:(?:\.|\?\.)[A-Za-z_$][\w$]*|\[[^\]]*\])+$)/iu;
function credentialAssignment(text: string): boolean {
  for (const match of text.matchAll(CREDENTIAL_ASSIGNMENT)) {
    // A quoted string is a literal unless it is a whole reference or mask; only unquoted values can be
    // identifiers, member expressions, type names or booleans.
    // Unquoted: brackets inside the value belong to it; only trailing ones (`false}`) close a surrounding structure.
    const unquoted = match[3]?.replace(/[}\]]+$/u, '');
    if (match[2] !== undefined ? !REFERENCE.test(match[2]) : unquoted!.length >= 4 && !NOT_A_VALUE.test(unquoted!)) return true;
  }
  return false;
}
const ENCODED_RUN = /(?<![A-Za-z0-9+/_-])(?:[A-Za-z0-9+/_-]{16,65536}={0,2})(?![A-Za-z0-9+/=_-])/gu;
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
/** MD5/trace-id, SHA-1/256/384/512 hex digests are ordinary text, not payloads. */
const DIGEST_HEX = /^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}|[0-9A-Fa-f]{96}|[0-9A-Fa-f]{128})$/u;
/** Base64 digests and public keys identified by their context: SRI values and SSH public-key fields. */
function isIdentifierRun(run: string): boolean {
  return DIGEST_HEX.test(run) || /^sha(?:1|256|384|512)-[A-Za-z0-9+/]+={0,2}$/u.test(run) ||
    /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/u.test(run);
}
const DIGEST_CONTEXT = /(?:sha(?:1|224|256|384|512)[-:]|h1:|content-md5:\s*|etag:\s*"?)$/iu;
const SSH_KEY_CONTEXT = /(?:ssh-(?:ed25519|rsa|dss)\s|ecdsa-sha2-nistp\d{3}\s|sk-ssh-ed25519@openssh\.com\s)$/iu;
// Public certificate and key blocks are not secrets and are exempt from the opaque count.
const PUBLIC_PEM = /-----BEGIN (?:CERTIFICATE|TRUSTED CERTIFICATE|PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE REQUEST|NEW CERTIFICATE REQUEST|X509 CRL)-----[\s\S]{0,65536}?-----END [A-Z0-9 ]{1,40}-----/gu;
/** Exact digest lengths: hex MD5/SHA-1/224/256/384/512, and base64 MD5/SHA-1/256/384/512 with or without padding. */
function isDigest(value: string): boolean {
  if (/^[0-9A-Fa-f]+$/u.test(value)) return [32, 40, 56, 64, 96, 128].includes(value.length);
  return [22, 24, 27, 28, 43, 44, 64, 86, 88].includes(value.length);
}
/**
 * camelCase/PascalCase/snake identifiers and path-like names made of words and short digit groups
 * (`convertUtf8ToBase64String`, `com/Marcus-Levin/hylja/pull/56`). Random Base64 does not split into words.
 * A path segment may be a whole numeric id up to int64 width (`actions/runs/36169013008`).
 */
function isIdentifier(value: string): boolean {
  if (/[+=]/u.test(value)) return false;
  const segments = value.split(/[_/.-]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])/u).filter(Boolean);
  return segments.length >= 2 && segments.every((segment) =>
    /^[A-Z]?[a-z]{2,}$/u.test(segment) || /^[A-Z]{1,5}$/u.test(segment) || /^\d{1,4}$/u.test(segment) || /^[a-z]$/u.test(segment) ||
    /^\d{5,20}$/u.test(segment) && new RegExp(`(?:^|[/._-])${segment}(?:$|[/._-])`, 'u').test(value));
}
interface EncodedRun { start: number; end: number; value: string; prefixed: boolean; countable: boolean }
const CHUNK = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{4,15}={0,2}(?![A-Za-z0-9+/=_-])/gu;
/** A chunk that is clearly encoded data: letters with digits, long hex, or padding. */
function chunkLike(token: string): boolean {
  return /\d/u.test(token) && /[A-Za-z]/u.test(token) || /^[0-9A-Fa-f]{8,}$/u.test(token) || /=$/u.test(token);
}
/** Also possibly encoded: `+`/`/` or a lower-to-upper case switch, which digit-free Base64 chunks usually show. */
function chunkLikeLoose(token: string): boolean {
  return chunkLike(token) || /[+/]/u.test(token) || /[a-z][A-Z]/u.test(token);
}
/**
 * Encoded runs: every run of 16+ alphabet characters (a `shaNNN-`/`shaNNN:`/`h1:` prefix stripped), plus
 * sequences of short chunk-like tokens separated only by whitespace, commas, quotes or brackets, joined into
 * one run so that chunking below 16 characters cannot hide compressed data. A joined sequence counts toward
 * OPAQUE_BYTES only when three quarters of its tokens are clearly encoded; looser sequences (digit-free Base64
 * chunks, but also JSON ids and regex classes) are decoded and decompressed, never counted.
 */
function* encodedRuns(text: string): Generator<EncodedRun> {
  for (const run of text.matchAll(ENCODED_RUN)) {
    const prefix = /^(?:sha(?:1|224|256|384|512)-|h1:)/iu.exec(run[0]);
    yield { start: run.index + (prefix?.[0].length ?? 0), end: run.index + run[0].length,
      value: prefix ? run[0].slice(prefix[0].length) : run[0], prefixed: prefix !== null, countable: true };
  }
  let sequence: RegExpMatchArray[] = [];
  const flush = function* (): Generator<EncodedRun> {
    if (sequence.length >= 2 && sequence.filter((token) => chunkLikeLoose(token[0])).length >= sequence.length * 0.5) {
      const value = sequence.map((token) => token[0].replace(/=+$/u, '')).join('');
      if (value.length >= 16) {
        const last = sequence[sequence.length - 1]!;
        yield { start: sequence[0]!.index!, end: last.index! + last[0].length, value, prefixed: false,
          countable: sequence.filter((token) => chunkLike(token[0])).length >= sequence.length * 0.75 };
      }
    }
    sequence = [];
  };
  for (const token of text.matchAll(CHUNK)) {
    const previous = sequence[sequence.length - 1];
    if (previous && !/^[\s,"'[\]]{1,4}$/u.test(text.slice(previous.index! + previous[0].length, token.index))) yield* flush();
    sequence.push(token);
  }
  yield* flush();
}
/**
 * Decompress binary as gzip or zlib (signature in the first 16 bytes), brotli or raw deflate, tolerating a
 * truncated stream, within the per-message output budget. A successful gzip/zlib/brotli decode is always kept;
 * raw deflate (which can succeed by accident on random bytes) is kept when its output is mostly printable once
 * control characters are ignored. Returns 'BUDGET' when the message's decompression budget is exhausted.
 */
const SYNC_FLUSH = 2;
function inflate(bytes: Uint8Array, budget: { inflated: number }): Uint8Array | null | 'BUDGET' {
  const attempt = (run: (options: { maxOutputLength: number; finishFlush: number }) => Uint8Array, strict: boolean): Uint8Array | null | 'BUDGET' => {
    const remaining = MAX_INFLATE_TOTAL - budget.inflated;
    if (remaining <= 0) return 'BUDGET';
    try {
      const out = run({ maxOutputLength: remaining, finishFlush: SYNC_FLUSH });
      budget.inflated += out.length;
      if (out.length < 4) return null;
      if (!strict) return out;
      const text = new TextDecoder('utf-8', { fatal: false }).decode(out).replace(/[\u0000-\u001f\u007f\ufffd]/gu, '');
      return text.length >= 8 && (text.match(/[\p{L}\p{N}\p{P}\p{S}\s]/gu) ?? []).length >= text.length * 0.9 ? out : null;
    } catch (error) {
      return (error as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE' ? 'BUDGET' : null;
    }
  };
  for (let offset = 0; offset < Math.min(16, bytes.length - 1); offset++) {
    const view = bytes.subarray(offset);
    const gzip = view[0] === 0x1f && view[1] === 0x8b;
    const zlib = view[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(view[1]!);
    if (!gzip && !zlib) continue;
    const result = attempt((options) => (gzip ? gunzipSync : inflateSync)(view, options), false);
    if (result) return result;
  }
  const brotli = attempt((options) => brotliDecompressSync(bytes, options), true);
  if (brotli) return brotli;
  return attempt((options) => inflateRawSync(bytes, options), true);
}
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
function isText(bytes: number[]): boolean {
  try { return !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(utf8.decode(Uint8Array.from(bytes))); } catch { return false; }
}
function printable(bytes: number[]): string {
  return bytes.map((byte) => byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ' ').join('');
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

interface View { name: string; text: string; derived?: boolean }
/**
 * All canonical views: each text is decoded by #6 (Base64/percent/hex) and by the escape round, and every
 * resulting view is processed again, to MAX_ROUNDS. Returns a block reason when anything is uninspectable.
 */
function canonicalViews(root: string): { views: View[]; opaque: boolean } | { reason: string } {
  const views: View[] = [];
  const budget = { inflated: 0 };
  const countedValues = new Set<string>();
  let pendingOpaque = false;
  let queue: View[] = [{ name: 'ROOT', text: root }];
  let units = 0;
  for (let round = 0; queue.length && round <= MAX_ROUNDS; round++) {
    const next: View[] = [];
    for (const view of queue) {
      if (views.length >= MAX_VIEWS || (units += view.text.length) > MAX_VIEW_UNITS) return { reason: 'SENTINEL_BUDGET' };
      views.push(view);
      if (round === MAX_ROUNDS) continue;
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
      const binary: Uint8Array[] = [];
      let binaryTotal = 0, countable = 0;
      const runCounts: number[] = [];
      const publicBlocks = [...view.text.matchAll(PUBLIC_PEM)].map((block) => ({ start: block.index, end: block.index + block[0].length }));
      for (const run of encodedRuns(view.text)) {
        if (textSpans.some((span) => span.start <= run.start && run.end <= span.end)) continue;
        if (publicBlocks.some((block) => block.start <= run.start && run.end <= block.end)) continue;
        const decoded = decodeRun(run.value);
        if (!decoded || isText(decoded)) continue;
        const bytes = Uint8Array.from(decoded);
        if (OPAQUE_SIGNATURES.some((signature) => signature.every((byte, index) => bytes[index] === byte))) return { reason: 'OPAQUE_EMBEDDED' };
        // Not counted: exact-length digests (with or without a `shaNNN-`/`h1:` prefix), SSH key blobs, UUIDs,
        // identifiers (`http2ServerSessionOptions`), runs that do not look encoded (lower-case paths, snake_case
        // ids), and anything inside views derived from decompression or printable bytes.
        const encodedShape = /^[0-9A-Fa-f]+$/u.test(run.value) || /=$/u.test(run.value) ||
          /[A-Z]/u.test(run.value) && /[a-z]/u.test(run.value) && /\d/u.test(run.value);
        const before = view.text.slice(Math.max(0, run.start - 32), run.start);
        const recognized = isDigest(run.value) && (run.prefixed || DIGEST_HEX.test(run.value) || DIGEST_CONTEXT.test(before) || /=$/u.test(run.value)) ||
          SSH_KEY_CONTEXT.test(before) && run.value.length <= 800 ||
          /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/u.test(run.value) ||
          isIdentifier(run.value) || !encodedShape || !run.countable || view.derived === true;
        binary.push(bytes);
        binaryTotal += bytes.length;
        // Each distinct run counts once per message (an escape view repeats the runs of its parent).
        const counted = recognized || countedValues.has(run.value) ? 0 : bytes.length;
        if (counted) countedValues.add(run.value);
        runCounts.push(counted);
        countable += counted;
        const text = printable(decoded);
        if (text.trim()) printables.push(text);
      }
      if (printables.length) next.push({ name: `${view.name}>BINARY_PRINTABLE`, text: printables.join('\n'), derived: true });
      if (binary.length) {
        const joined = new Uint8Array(binaryTotal);
        let offset = 0;
        for (const part of binary) { joined.set(part, offset); offset += part.length; }
        const inflated: string[] = [];
        for (const candidate of binary.length > 1 ? [joined, ...binary.slice(0, 256)] : binary) {
          const result = inflate(candidate, budget);
          if (result === 'BUDGET') return { reason: 'SENTINEL_BUDGET' };
          if (!result) continue;
          inflated.push(printable([...result]));
          // Decompressed bytes are inspected, not opaque. Once the whole concatenation decodes, stop.
          if (candidate === joined) { countable = 0; break; }
          const index = binary.indexOf(candidate);
          if (index >= 0) { countable -= runCounts[index]!; runCounts[index] = 0; }
        }
        if (inflated.length) next.push({ name: `${view.name}>INFLATED`, text: inflated.join('\n'), derived: true });
        if (countable > OPAQUE_BYTES) pendingOpaque = true;
      }
      const unescaped = unescapeOnce(view.text);
      if (unescaped !== null) next.push({ name: `${view.name}>ESCAPES`, text: unescaped, derived: view.derived === true });
    }
    queue = next;
    if (round === MAX_ROUNDS && queue.length) return { reason: 'SENTINEL_BUDGET' };
  }
  return { views, opaque: pendingOpaque };
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
