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
/** The shortest literal the single-line credential pattern accepts, and the floor a block-scalar body must clear. */
const MIN_ASSIGNED_VALUE = 4;
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
  return blockScalarCredential(text);
}
/**
 * A YAML block scalar (`password: |`, `secret: >-2`) is a credential-shaped assignment whose value is on the
 * following indented lines, so the single-line pattern above cannot see it. A block scalar body is always a
 * literal, exactly like a quoted value: it is a value unless it is a whole reference or mask, a key-echo
 * shorthand, or a `PWD` path. The indicator itself (`|`, `>`) is never a value and never exempts the body.
 *
 * The header is found anywhere a key may appear, like the single-line pattern, so a YAML document carried inside
 * a JSON string is read once the escape round has produced its line breaks. Each header is read forward from its
 * own end, so a line is visited once per header and the work stays linear in the text. A line that is not more
 * indented than the header's own line ends the block and starts a new mapping entry. The per-block line and byte
 * bounds are this module's other per-field bounds: a longer block is read up to the bound and reading resumes at
 * the next line, so a bound can never hide a later key.
 */
const BLOCK_SCALAR_ASSIGNMENT = /(?<![A-Za-z0-9_-])(?:"|')?(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)(?:"|')?[ \t]*:[ \t]*[|>](?:[+-][1-9]?|[1-9][+-]?)?[ \t]*(?:#[^\r\n]*)?\r?(?=\n|$)/giu;
const MAX_BLOCK_LINES = 64;
const MAX_BLOCK_BYTES = 4096;
const LEADING_SPACE = /^[ \t]*/u;
const BLOCK_COMMENT = /^[ \t]*#/u;
function blockScalarCredential(text: string): boolean {
  for (const match of text.matchAll(BLOCK_SCALAR_ASSIGNMENT)) {
    const indent = LEADING_SPACE.exec(text.slice(text.lastIndexOf('\n', match.index) + 1, match.index))![0].length;
    let at = match.index + match[0].length;
    if (text[at] === '\n') at += 1;
    else if (text[at] === '\r' && text[at + 1] === '\n') at += 2;
    const body: string[] = [];
    let bytes = 0;
    while (at < text.length && body.length < MAX_BLOCK_LINES && bytes < MAX_BLOCK_BYTES) {
      let end = text.indexOf('\n', at);
      if (end < 0) end = text.length;
      const line = text.slice(at, end);
      bytes += line.length + 1;
      at = end + 1;
      // A blank line belongs to the block only after the block has started.
      if (line.trim() === '') { if (body.length) body.push(''); continue; }
      const width = LEADING_SPACE.exec(line)![0].length;
      if (width <= indent) break;
      const content = line.slice(width).trim();
      // A comment line inside the block is a comment, and a document marker ends the document.
      if (!BLOCK_COMMENT.test(line) && content !== '---' && content !== '...') body.push(content);
    }
    const value = body.join('\n').trim();
    if (value.length < MIN_ASSIGNED_VALUE) continue;
    if (/^pwd$/iu.test(match[1]!) && /^[/~]/u.test(value)) continue;
    if (REFERENCE.test(value)) continue;
    if (value.replace(/[_-]/gu, '').toLowerCase() === match[1]!.replace(/[_-]/gu, '').toLowerCase()) continue;
    return true;
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
/**
 * Bounds on the interior read of a run the opaque count does not count (a run shorter than `OPAQUE_BYTES` that is
 * not a recognized digest, id or public key, a run whose exact byte length is a digest length, and a run inside a
 * DER-shaped public PEM body). Brotli and raw deflate carry no signature to scan for, so every starting offset of
 * such a run is tried, and the read is split into two ceilings because the two kinds are not the same claim.
 *
 * `MAX_INTERIOR_BYTES` bounds the runs **nothing declared**: their exemption is a coincidence of length, so they are
 * read in full or the message is uninspectable (`SENTINEL_BUDGET`). Without that refusal a bounded read that ran out
 * released whatever it never reached, and adding harmless lines *before* a hidden payload disabled detection of it,
 * which is a bypass rather than a completeness gap.
 *
 * `MAX_OPTIONAL_WINDOWS` bounds every **other** exempt run: a short run that is not a recognized digest, id or
 * public key, a declared reconstruction, a digest the message named under an algorithm context (`sha256-`, `h1:`,
 * `Content-MD5:`, `ETag:`), and a run inside a DER-shaped public PEM body. Those keep the exemptions this module
 * has always published; they are read when the window ceiling allows, and exhausting it is never a reason to
 * refuse, because refusing them would refuse ordinary `go.sum` and certificate traffic, which is what the
 * exemption is for.
 *
 * `MAX_INTERIOR_OUTPUT` bounds one speculative decode and `MAX_INTERIOR_TEXT` bounds what those decodes may add to
 * the message's views. Every window is charged whether it decoded, decoded nothing or failed; a window is the unit
 * of work and tries `INTERIOR_SWEEP + 1` starting offsets against both signature-less formats.
 */
const MAX_INTERIOR_BYTES = 32 << 10;
const MAX_OPTIONAL_WINDOWS = 64;
/**
 * Starting offsets after the first that one interior window sweeps. The width is a measured trade, not a guess:
 * each offset costs one brotli and one raw-deflate attempt (fewer for deflate, whose reserved block-type bit rules
 * three of every four offsets out), and each attempt holds up to `DECODE_CHUNK` bytes of native memory until the
 * runtime can run again, so a wider window buys coverage with a higher high-water mark for a synchronous batch. The
 * ceiling that
 * decides coverage is `MAX_INTERIOR_BYTES`; this only decides how many attempts reach it.
 */
const INTERIOR_SWEEP = 15;
/** Shorter runs cannot hold a deflate or brotli stream that decodes to a value, so they are never read inside. */
const MIN_INTERIOR_RUN = 16;
const MAX_INTERIOR_OUTPUT = 1 << 10;
const MAX_INTERIOR_TEXT = 1 << 16;
/**
 * Total decompressed output the interior read itself may produce. It is separate from the message's own 4 MiB
 * because these decodes are speculative and a long list of compressible digests decodes by chance at many offsets;
 * sharing one ceiling refused messages this module has always read and released for finding nothing. Measured on
 * this host, reading the module's own 900-line digest-list control produces about 12 MiB of it.
 */
const MAX_INTERIOR_INFLATED = 16 << 20;
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
/** Allow a URL's initial `//`, but no additional empty slash-delimited component. */
function repeatedPathSlashes(value: string): boolean {
  const leading = value.startsWith('//') ? 2 : value.startsWith('/') ? 1 : 0;
  const rest = value.slice(leading);
  return rest.startsWith('/') || rest.includes('//');
}
/**
 * camelCase/PascalCase/snake identifiers and path-like names made of words and short digit groups
 * (`convertUtf8ToBase64String`, `com/Marcus-Levin/hylja/pull/56`). Random Base64 does not split into words.
 * A path segment may be a whole numeric id up to int64 width (`actions/runs/36169013008`). At least one letter
 * outside a-f is required.
 */
function isIdentifier(value: string): boolean {
  // Hex split into short groups (`a3f9-01bc-…`) has no word in it and is data, not a name.
  // Interior or extra leading Base64 slash bytes are data even when an ordinary-looking id follows them.
  if (value.length > 256 || /[+=]/u.test(value) || repeatedPathSlashes(value) || !/[g-zG-Z]/u.test(value)) return false;
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
 * One dump row, as its structure rather than as a string: the cells it spells, the width they are written at, how
 * many of them are cells at all, how many there are before its ASCII column, the byte offset it declares, and
 * whether its ASCII column carries the explicit `|` marker. The offset column is what makes the row width knowable
 * without trusting the column separator, which matters because a sender chooses both the whitespace inside the hex
 * field and the content of the column; the marker is what makes the column itself unambiguous.
 */
interface DumpRow { cells: string[]; width: number; count: number; gap: number; offset: number; marked: boolean }
// Lines with an offset column; the line may carry a prefix (a JSON body's first line: `"content":"00000000  78 9c …`).
// Dumps without offsets (`od -An`) are plain byte-pair runs.
const DUMP_OFFSET = /(?:^|[^0-9A-Fa-f])([0-9A-Fa-f]{4,8}):?[ \t]+/u;
/**
 * Cells examined in one dump row, counting the ASCII column. This is a parsing bound on one line the caller has
 * already capped at 400 characters, not a work, view, depth or output budget, and it guards no reconstruction: the
 * reconstruction is bounded by the row width the row's own offsets declare, and the line by that 400-character
 * ceiling. What it decides is only whether a line is read as a dump row at all, and that is not a neutral choice,
 * because a rejected row falls back to the byte-pair reader, which reads the column's pairs as data and interleaves
 * them into the reconstruction. Measured: with this bound at 32 -- below a 32-byte `xxd -c 32` row plus its column,
 * or any `xxd -g1` row whose column spells more than 16 cells -- a dump carrying an unmarked column of
 * two-character hex cells, or of either cell width written as word-like groups, released a planted original and
 * canary with `release` bytes even with the offset-derived row width in place. 64 covers every standard dump row up
 * to `xxd -c 64` plus its column; a row wider than that is still reconstructed by the byte-pair reader and blocks,
 * which is measured rather than assumed.
 */
const MAX_DUMP_CELLS = 64;
function dumpLineRow(line: string): DumpRow | null {
  const ascii = line.indexOf('  |');
  const body = ascii >= 0 ? line.slice(0, ascii) : line;
  const offset = DUMP_OFFSET.exec(body);
  if (!offset) return null;
  const tail = body.slice(offset.index + offset[0].length);
  const cells = tail.trim().split(/[ \t]+/u);
  const width = cells[0]?.length;
  if (cells.length > MAX_DUMP_CELLS || (width !== 2 && width !== 4)) return null;
  // The cells the row spells before anything that is not a cell: every cell is hex of the row's own width, except
  // a default `xxd` row's final odd byte, which is one cell shorter.
  const shortCell = width === 4 ? cells.length - 1 : -1;
  let count = 0;
  while (count < cells.length &&
    (cells[count]!.length === width || (count === shortCell && cells[count]!.length === 2))) count++;
  if (!count) return null;
  // Cells before the ASCII column: every cell up to the first run of two or more spaces. Only an unmarked column
  // can be mistaken for cells, so only an unmarked row has one.
  const gap = ascii < 0 ? /[ \t]{2,}/u.exec(tail) : null;
  return { cells, width, count, offset: parseInt(offset[1]!, 16), marked: ascii >= 0,
    gap: gap ? tail.slice(0, gap.index).trim().split(/[ \t]+/u).length : count };
}
/**
 * One **explicitly marked** dump row, as its own reading: the row declares its bytes with an ASCII-column marker
 * (`  |…|`), so the column is unambiguously not data and the cells between the offset and the marker are exactly
 * the row's bytes. That is a stronger declaration than the multi-row readings need — they take a row's width from
 * its own offsets — and it is what makes a single row readable without guessing.
 *
 * The grammar is deliberately narrow and it is the whole of what this reading claims:
 *
 * - one offset-prefixed row, and only one: a block of two or more rows keeps exactly the readings it always had,
 *   which already span sixteen bytes and read whole rows whatever separator a sender put inside the field;
 * - at most one standard sixteen-byte row, so a wider row is left to the byte-pair and dump readers above rather
 *   than given a second reading here;
 * - **every** token before the marker a cell of the row's own width: `count` stops at the first one that is not,
 *   which is what the multi-row readings want (a row may spell its column too) and is not enough here. A field
 *   with prose or any other non-cell after its cells is malformed, and a reading taken from the cell prefix alone
 *   would invent a stream out of part of a field the sender never finished writing. `xxd`'s final odd byte in a
 *   four-character row is a cell and is kept;
 * - every cell hex, so a row of word-like groups (`dead beef cafe food`) is not bytes and is not read as Base64
 *   either;
 * - the offset column and the ASCII column are excluded, both by construction (`cells` is the text between them).
 *
 * A row this rejects is left exactly as base left it: the byte-pair and multi-row readers still see their own
 * reading of the same text, so nothing stops being inspected and this reading only declines to invent one.
 *
 * It is **decode-only**, exactly like every other dump reading: the row adds no opaque bytes of its own, so an
 * ordinary one-row dump of a digest, an id or a short piece of compressed prose gains no opaque authority from
 * its shape, while a compressed note in that row is inflated and matched like any other. What it decodes can still
 * block as it always does (a container signature, opaque output, an exhausted budget).
 */
const MIN_SHORT_DUMP_BYTES = 4;
const MAX_SHORT_DUMP_BYTES = 16;
function shortDumpValue(row: DumpRow): string | null {
  if (!row.marked || row.count !== row.cells.length) return null;
  const value = row.cells.join('');
  if (value.length < MIN_SHORT_DUMP_BYTES * 2 || value.length > MAX_SHORT_DUMP_BYTES * 2) return null;
  return /^(?:[0-9A-Fa-f]{2})+$/u.test(value) ? value : null;
}
/**
 * The cell count a block's rows agree on, from their own offsets. A short final row has no successor to compare
 * against, and a row that spells more cells than the agreed width is not a full row, so it falls back to the cells
 * before its column; that fallback is safe because a doubled separator inside a full row leaves the row's own
 * offsets and cell count untouched, and the row cut at the gap is read as well. `xxd`, `hexdump -C` and `od` all advance the offset
 * by one row, so the difference between two consecutive offsets is that row's byte count. This is the whole answer to
 * "where does the hex field end": a doubled space or tab *inside* the field adds no cell, so the row's own offsets
 * are unchanged by it and the complete reading still spans the field; while an unmarked ASCII column adds cells, and
 * cells past the row's declared width are the column, not bytes. Reading past them interleaves the column into the
 * reconstruction, destroys the stream it carries and released the payload outright. A block whose offsets do not
 * advance uniformly (a partial or hand-written listing) has no agreed width, and is read as before.
 */
function dumpRowWidth(rows: readonly DumpRow[]): number | null {
  let width: number | null = null;
  for (let index = 0; index + 1 < rows.length; index++) {
    const bytes = rows[index + 1]!.offset - rows[index]!.offset;
    const cells = rows[index]!.width === 2 ? bytes : bytes / 2;
    if (!(cells >= 1 && cells <= 32) || !Number.isInteger(cells)) return null;
    if (width === null) width = cells;
    else if (width !== cells) return null;
  }
  return width;
}
function* dumpRuns(text: string): Generator<EncodedRun> {
  // One block per reading, kept side by side so a complete reading is never displaced by a shorter one.
  let block: { start: number; end: number; rows: DumpRow[]; hex: string[][]; lines: number } | null = null;
  const flush = function* (): Generator<EncodedRun> {
    if (block) {
      const width = dumpRowWidth(block.rows);
      // One explicitly marked row, read on its own. The readings below need two rows and sixteen bytes of hex and
      // the byte-pair reader needs eight pairs, so a single row of a short stream was read by nothing at all; this
      // adds that reading and displaces none.
      if (block.rows.length === 1) {
        const value = shortDumpValue(block.rows[0]!);
        if (value !== null) yield { start: block.start, end: block.end, value, prefixed: false, countable: false, separated: true };
      }
      for (const [index, hex] of block.hex.entries()) {
        if (block.lines < 2 || hex.join('').length < 32) continue;
        // Reading 0 is the whole row, bounded by the width the offsets declare so a hex-looking unmarked ASCII column
        // is never read as bytes. Reading 1 is the row cut at the first multi-space run, which is what a doubled
        // separator inside the hex field must not be allowed to truncate.
        // A row that spells no more cells than the agreed width holds exactly those cells — its own hex field,
        // whatever separator a sender put inside it. A row that spells more spells its column too, and there the
        // cells before the column are the field. Either way the column's cells are left out.
        const value = index === 0 && width !== null ? block.rows.map((row) =>
          row.cells.slice(0, row.count > width ? row.gap : row.count).join('')).join('') : hex.join('');
        if (value.length >= 32) yield { start: block.start, end: block.end, value, prefixed: false, countable: false, separated: true };
      }
    }
    block = null;
  };
  const breaks = /\r?\n|\\r\\n|\\n/gu;
  let start = 0;
  for (let found = breaks.exec(text); ; found = breaks.exec(text)) {
    const end = found ? found.index : text.length;
    if (end - start <= 400) {
      const row = dumpLineRow(text.slice(start, end));
      if (row) {
        block ??= { start, end, rows: [], hex: [], lines: 0 };
        block.lines++;
        block.rows.push(row);
        for (const [index, upTo] of [row.count, row.gap].entries()) {
          const hex = row.cells.slice(0, upTo).join('');
          if (hex && hex !== block.hex[index]?.at(-1)) (block.hex[index] ??= []).push(hex);
        }
        block.end = end;
      } else yield* flush();
    } else yield* flush();
    if (!found) break;
    start = found.index + found[0].length;
  }
  yield* flush();
}
const SEPARATED_HEX = /^[0-9A-Fa-f]{2,}(?:[-_/][0-9A-Fa-f]{2,})+$/u;
const UUID = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/u;
interface EncodedRun { start: number; end: number; value: string; prefixed: boolean; countable: boolean; separated?: boolean; joined?: boolean; escaped?: boolean; declared?: boolean; escapedSeries?: boolean }
// Chunks of any length: a fixed-width split ends in a short remainder (`…Ghs2 M=`), and short words between chunks
// are dropped by the word-free variant.
const CHUNK = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{1,1024}={0,2}(?![A-Za-z0-9+/=_-])/gu;
/** A chunk that is clearly encoded data: letters with digits, long hex, or padding. */
function chunkLike(token: string): boolean {
  return /\d/u.test(token) && /[A-Za-z]/u.test(token) || /^[0-9A-Fa-f]{8,}$/u.test(token) || /=$/u.test(token);
}
/** A short hex group of a chunked hex value (`6f6e`, `7461`): data, but never a whole digest. */
const HEX_GROUP = /^[0-9A-Fa-f]{4,}$/u;
/**
 * Also possibly encoded: `+`/`/`, a lower-to-upper case switch (digit-free Base64 chunks) or short hex groups
 * (hex of text is mostly digits: `6f6e 7461 6374`).
 */
function chunkLikeLoose(token: string): boolean {
  return chunkLike(token) || /[+/]/u.test(token) || /[a-z][A-Z]/u.test(token) || /^[0-9A-Fa-f]{4,}$/u.test(token);
}
/* ---------- Declared reconstructions (labelled chunks, declared separators, decimal byte arrays) ---------- */

/**
 * Reconstructions that the representation itself declares: chunks labelled with a key (`part1: …`, `p1=…`,
 * arrays of labelled JSON objects), chunks joined by a declared separator (` + `, ` / `, ` > ` and their
 * percent-escaped forms), and decimal byte arrays including Node `Buffer` JSON (`{"type":"Buffer","data":[…]}`).
 *
 * They are **decode-only**, like the hex byte-pair lists above: the joined bytes are read as text when they are
 * text, decompressed, container-checked and matched, but they add no opaque bytes, so no ordinary engineering
 * numeric array or labelled configuration list gains opaque authority from its shape. Compressed opaque data
 * still blocks, because a decoded stream's own opaque output is counted, and so does a container signature.
 * Unknown *uncompressed* binary inside these forms can still pass. That is a declared limit, not a completeness
 * claim (the #19 known-limits list, frozen in the retired `docs/plan.md` at commit f838fc2, and the prose above).
 *
 * Work is bounded per message and shared by every view and round: each distinct joined value is read once, and a
 * message demanding more reconstructions than the budget allows is uninspectable rather than clean, because
 * stopping early would let a sender hide a payload behind padding.
 *
 * **Escape-valued declared series, and exactly what is admitted.** A field whose value is a list of byte escapes
 * (`%XX`, `\xXX`, `\uXXXX`, octal, `\^X`, `&#xXX;`, `&#NN;`, `=XX`) and whose label names the series is joined with
 * the other members of that series: `part1: \x1f`, `face1: \x1f`. A label drawn from the hex alphabet is admitted
 * on the same evidence the chunk reader beside it demands (`completeHexSeries`): its own numbers must declare one
 * complete run under one name (rank 0 or 1, consecutive, no repeat). For that candidate the field must also be
 * **whole** -- the escapes it spells and nothing else -- which includes the contiguous ones (`\x50\x51` is two bytes
 * of one field, as it is one run to the direct reader), and every member of the run must be one this reader read in
 * full. Three things make a field or a member not-whole, and each withholds the run rather than shortening it:
 * an unsupported suffix after its last escape (`face1: \x50oops`, `face1: \x50\xGG`), anything but the closing
 * quote after a **quoted** value (`"\x50\noops"`, `"\x50 cafe1: ordinary"` -- inside a string a line break, a
 * label or a word is still inside the value, and end of input does not close a quote the sender opened), and a
 * member of the same name whose value is not an escape list at all (`face1: ordinary`), whether that rank is
 * missing from the run, duplicated inside it (`FACE01` and `face1` are one rank written twice) or one past its end.
 * That membership test spans the **numeric** ranks the run covers, never the order the text is in, so reversing the
 * lines cannot move it.
 *
 * The ordinary-label reading is a separate alternative of its own and is not narrowed here: it collects what it
 * always collected from each field, a bounded prefix up to the first contiguous run of escapes, and it is charged and
 * yielded beside the whole-cell reading rather than instead of it. Both readings exist for one field; whether the
 * shorter one should remain is a separate decision this change does not make.
 *
 * A veto reaches the **bounded group the member belongs to and nothing else**. Groups are the ones this module
 * already builds (`labelledGap`, `MAX_DECLARED_FIELDS`), so a field on the other side of a break the group rule
 * rejects, or of a gap wider than it allows, belongs to another declaration: the run beside it is read on its own.
 * A rank far outside a run is likewise another declaration and never a veto. A veto that reached further released
 * nothing it was meant to find.
 *
 * The ordinary-label reading keeps its own, older prefix behaviour unchanged, because that is the prior path's
 * decision and not this reading's.
 *
 * What is therefore a published limit rather than a claim:
 *
 * - a hex-labelled run whose numbering has a gap, a repeat, or no first member; a hex name carrying no numbers;
 *   one field. These are the shapes a dump offset column (`face:`, `d10:`, `00000010:`) already has.
 * - a payload spread across two label names, or across two spellings of one series (one member written as a plain
 *   hexadecimal chunk). The series reader joins one series and never a subset of it, so leaving a member out ends
 *   the declaration rather than shifting it.
 * - a value that continues into a labelled assignment with nothing but whitespace after it: `face1: \x41 face2:
 *   \x42` and `face1: \x41 face2: \x42 oops` are the same text to this reader, and it resolves them as the
 *   declaration rather than as an unfinished value.
 * - a JSON **string** wrapper is not a discriminator for any of this: the escape round turns the escapes into
 *   literal bytes and the quoted-string reader refuses the body, in every revision, with or without this reading.
 *   The tests pin only that this reading adds no finding and releases nothing there.
 * - the hex byte-pair list and the chunk join above, which stay decode-only and are never counted opaque. Only a
 *   compressed stream, a container signature, the opaque byte count or a matched original can refuse them.
 */
const MAX_DECLARED_RUNS = 16384;
const MAX_DECLARED_UNITS = 8 << 20;
/**
 * Characters every declared join costs, counted whether or not the joined value is a new reconstruction: a join
 * that is dropped as a duplicate or as too short still spent the work. It is a ceiling on how far the readers may
 * fan out rather than a threshold tuned to observed traffic: no message within the 1 MiB input limit was found to
 * reach it (the measured maximum is recorded in the retired `docs/plan.md` at commit f838fc2), and exceeding it is
 * uninspectable, never clean.
 */
const MAX_DECLARED_WORK = 8 << 20;
const MAX_DECLARED_VALUE = 1 << 16;
/** Group bounds: a wider group is split and read in parts, and a truncated part still inflates its own head. */
const MAX_DECLARED_FIELDS = 512;
const MAX_DECLARED_CHUNKS = 256;
const MIN_DECLARED_UNITS = 16;
const MIN_DECLARED_VALUES = 2;
/** Filler between two labelled fields (whitespace, punctuation, list markers, prose) is never data itself. */
const MAX_DECLARED_GAP = 256;
/** Per-message reconstruction work: distinct joined values already read, how many, and their total length. */
interface DeclaredBudget { seen: Set<string>; runs: number; units: number; work: number }
interface DeclaredEntry {
  label: string;
  value: string;
  /** A label drawn from the hex alphabet (`face:`, `deadbeef1:`) is a value the sender wrote before a colon
   * (a dump offset column) rather than a key, so it joins no reading until its own numbers make it a declared
   * series: see `completeHexSeries`. */
  hexLabel: boolean;
}
/** One candidate reading of a group: its values in reading order, and how many of them it requires. */
interface DeclaredReading {
  entries: readonly DeclaredEntry[];
  minimum: number;
  /** Values the encoded-data evidence is judged on, when the join itself differs (`/` glued into a chunk). */
  evidence?: readonly DeclaredEntry[];
  /**
   * Values decoded from byte escapes rather than written as chunks. Their encoded-ness evidence is the escape
   * spelling itself — every value is a list of supported byte escapes, which is stronger than the shape test
   * `declaredRuns` applies to a chunk — and the decoded bytes are not hex text any sender wrote, so the shape
   * test is skipped rather than misapplied to them.
   */
  escaped?: boolean;
}
/** Strip a chunk's own padding and hex `0x` prefix, as the chunk join does before concatenating. */
function declaredValue(token: string): string {
  return token.replace(/=+$/u, '').replace(/^0[xX](?=[0-9A-Fa-f]+$)/u, '');
}
/**
 * Charge one reconstructed value to the per-message budget, or return false when it is too short, too long or
 * was already read for this message. Exceeding the budget is uninspectable, not clean.
 */
function charge(value: string, budget: DeclaredBudget): boolean {
  // Every join is charged, including one this budget will drop as too short, too long or already read: the
  // characters were copied either way, and an uncharged join is work nobody can bound.
  budget.work += value.length;
  if (budget.work > MAX_DECLARED_WORK || budget.runs > MAX_DECLARED_RUNS || budget.units > MAX_DECLARED_UNITS) throw new BudgetExceeded();
  if (value.length < MIN_DECLARED_UNITS || value.length > MAX_DECLARED_VALUE || budget.seen.has(value)) return false;
  budget.seen.add(value);
  budget.runs++;
  budget.units += value.length;
  return true;
}
/** A declared numeric label: one name followed by a number (`part1`, `p2`, `part-3`, `chunk_07`). */
const NUMERIC_LABEL = /^(.*?)(\d{1,4})$/u;
/** Labels that are one numbered series (`part1`, `part2`, …) in another order than the text carries them. */
function numericOrder(entries: readonly DeclaredEntry[]): DeclaredEntry[] | null {
  const ranks: number[] = [];
  let base: string | null = null;
  for (const entry of entries) {
    const label = NUMERIC_LABEL.exec(entry.label);
    if (label === null) return null;
    const name = label[1]!.toLowerCase();
    if (base === null) base = name;
    else if (name !== base) return null;
    ranks.push(Number(label[2]!));
  }
  if (base === null) return null;
  const order: number[] = entries.map((_, index) => index);
  order.sort((left, right) => ranks[left]! - ranks[right]!);
  const sorted = order.map((index) => entries[index]!);
  return sorted.some((entry, index) => entry !== entries[index]) ? sorted : null;
}
/**
 * The joined runs of one group, one per candidate reading. Evidence is judged **per value**, as for a plain
 * chunk sequence: at least half of them must look encoded and at least one must look clearly encoded, so a
 * labelled list of ordinary words, a numeric list and a sentence of prose are not reconstructed at all.
 */
function* declaredRuns(start: number, end: number, readings: readonly DeclaredReading[],
  budget: DeclaredBudget): Generator<EncodedRun> {
  for (const reading of readings) {
    const entries = reading.entries;
    if (entries.length < reading.minimum) continue;
    const evidence = reading.evidence ?? entries;
    // A reading of byte escapes is judged by its spelling, not by the shape of the bytes it spells.
    if (reading.escaped !== true) {
      if (evidence.filter((entry) => chunkLikeLoose(entry.value)).length < evidence.length * 0.5) continue;
      if (!evidence.some((entry) => chunkLike(entry.value) || HEX_GROUP.test(entry.value))) continue;
    }
    const value = entries.map((entry) => declaredValue(entry.value)).join('');
    if (!charge(value, budget)) continue;
    yield { start, end, value, prefixed: false, countable: false, separated: true, joined: true, declared: true,
      escapedSeries: reading.escaped === true };
  }
}
/**
 * A labelled field: `part1: <chunk>`, `p1=<chunk>`, `"part1":"<chunk>"` (a JSON closing quote may sit between
 * the label and the colon) and `part: 1`. The label is bounded and word-initial; the value is one bounded
 * chunk, quoted or bare.
 */
const LABELLED_FIELD = /(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_-]{0,23})"?[ \t]{0,4}[:=][ \t]{0,4}(?:"([A-Za-z0-9+/_-]{1,1024}={0,2})"|'([A-Za-z0-9+/_-]{1,1024}={0,2})'|([A-Za-z0-9+/_-]{1,1024}={0,2}))(?![A-Za-z0-9+/_=-])/gu;
/**
 * Between two labelled fields: whitespace, JSON punctuation, list markers and prose. A gap may be long, since a
 * document may introduce each part in words, but it is never a run of 16+ alphabet characters: that is data, so
 * it ends the group instead of joining across it.
 */
function labelledGap(gap: string): boolean {
  return gap.length <= MAX_DECLARED_GAP && !/[A-Za-z0-9+/_-]{16,}/u.test(gap);
}
/**
 * One declared label series of a group: the fields that share a label name, whether the name carries a number
 * (`part1 … partN`, `p1=…`) or not (`data`, `value`, `note` — the keys an array of labelled objects uses).
 * A label repeated inside one group keeps every occurrence, so the series partition the group's fields by name.
 *
 * This is a per-name reading, never a search over subsets: a group of n labelled fields yields at most n/2 series,
 * and each series reading costs its own size, so the work stays linear in the group.
 */
interface DeclaredSeries { numeric: boolean; entries: DeclaredEntry[] }
function labelledSeries(entries: readonly DeclaredEntry[]): DeclaredSeries[] {
  const series = new Map<string, DeclaredEntry[]>();
  for (const entry of entries) {
    const numbered = NUMERIC_LABEL.exec(entry.label);
    const name = (numbered ? numbered[1]! : entry.label).toLowerCase();
    const found = series.get(name);
    if (found) found.push(entry);
    else series.set(name, [entry]);
  }
  // Largest first, so the metadata beside the dominant series is well defined and stable for equal sizes.
  return [...series.values()]
    .map((members) => ({ numeric: members.every((entry) => NUMERIC_LABEL.test(entry.label)), entries: members }))
    .sort((left, right) => right.entries.length - left.entries.length);
}
/** The rank part of a declared numeric label, which is its label number and nothing else. */
function labelRank(entry: DeclaredEntry): string {
  return NUMERIC_LABEL.exec(entry.label)?.[2] ?? entry.label;
}
/**
 * The hex-labelled fields of a group that declare one coherent numbered series under one label name
 * (`face1 … faceN`, `dead1 … deadN`, or the same counted from 0): every member carries a number, the numbers are
 * distinct, and together they cover a complete run with no gap. A dump offset column is one value written before
 * a colon (`face: 1f8b0800`, `d0: 0000…`) and never repeats into that shape, so a series is a declaration the
 * sender made, exactly like `part1 … partN`, and dropping every hex-alphabet label instead made the same payload
 * readable or not depending on which letters the sender happened to pick.
 *
 * The test is over each name's own members, once per field, so it stays linear in the group and is not a search
 * over subsets. A hex-labelled field that fails it joins no reading at all, so a dump offset column still reads
 * as it always did.
 */
function completeHexSeries(entries: readonly DeclaredEntry[]): DeclaredEntry[][] {
  const byName = new Map<string, DeclaredEntry[]>();
  for (const entry of entries) {
    if (!entry.hexLabel) continue;
    const name = NUMERIC_LABEL.exec(entry.label)?.[1]?.toLowerCase();
    if (name === undefined) continue;
    const members = byName.get(name);
    if (members) members.push(entry);
    else byName.set(name, [entry]);
  }
  const complete: DeclaredEntry[][] = [];
  for (const members of byName.values()) {
    if (members.length < MIN_DECLARED_VALUES) continue;
    // Every member here carries a number (the grouping above), so this is its rank and nothing else.
    const ranks = members.map((entry) => Number(labelRank(entry))).sort((left, right) => left - right);
    const start = ranks[0]!;
    if (start !== 0 && start !== 1) continue;
    // A repeated or skipped rank leaves a gap, so the series is not the complete one it claims to be.
    if (ranks.some((rank, index) => rank !== start + index)) continue;
    complete.push(members);
  }
  return complete;
}
/**
 * One reading of a numbered series whose label numbers repeat: a record with a duplicate key reads first-wins or
 * last-wins, and the sentinel does not know which parser produced the text, so it reads both. The series keeps its
 * text order, so a duplicate key does not move a payload part.
 */
function duplicateKeyReadings(members: readonly DeclaredEntry[]): DeclaredEntry[][] {
  const first = new Map<string, number>(), last = new Map<string, number>();
  members.forEach((entry, index) => {
    const rank = labelRank(entry);
    if (!first.has(rank)) first.set(rank, index);
    last.set(rank, index);
  });
  return [members.filter((_, index) => first.get(labelRank(members[index]!)) === index),
    members.filter((_, index) => last.get(labelRank(members[index]!)) === index)];
}
/**
 * Readings of one labelled group: every field value in text order, only the clearly-encoded values, the values
 * that are not bare decimal numbers, and each of those in ascending numeric-label order. A JSON array of
 * objects carries its order indexes beside the payload (`{"part":1,"data":"…"}`), and a chunk of a short split
 * is not always chunk-like on its own, so the numeric values must be droppable without dropping the chunks.
 *
 * One declared label series per reading as well, read on its own in text and numeric order. Unrelated metadata
 * written between the members of a series (`part1: …`, `trace: 1a2b3c4d`, `part2: …`) is not part of that
 * declaration, and joining it into the value leaves every reading junk, so the series is read without it; the
 * metadata beside the dominant series is then read as its own group, so no field is dropped from inspection.
 * Every earlier reading of the group is kept, so nothing that used to be read stops being read.
 */
function labelledReadings(entries: readonly DeclaredEntry[]): DeclaredReading[] {
  // Fields whose label comes from the hex alphabet carry no declaration of their own (`face: 1f8b…` is a value
  // before a colon, as in a dump offset), so they are in no reading of the group below: a hex dump keeps reading
  // as it did, and an unrelated hex-looking field beside labelled parts does not join or split them.
  const fields = entries.filter((entry) => !entry.hexLabel);
  const sets: DeclaredEntry[][] = [fields as DeclaredEntry[]];
  const encoded = fields.filter((entry) => chunkLikeLoose(entry.value));
  const payload = fields.filter((entry) => !DECIMAL_VALUE.test(entry.value));
  if (encoded.length !== fields.length) sets.push(encoded);
  if (payload.length !== fields.length && payload.length !== encoded.length) sets.push(payload);
  const readings: DeclaredReading[] = [];
  for (const set of sets) {
    readings.push({ entries: set, minimum: MIN_DECLARED_VALUES });
    const numbered = numericOrder(set);
    if (numbered) readings.push({ entries: numbered, minimum: MIN_DECLARED_VALUES });
  }
  // A series whose values are all bare decimals is an order index (`{"part":1,"data":"…"}`, `- part: 1`), which
  // the readings above already handle by dropping the numbers; reading the numbers alone would only spend budget.
  const series = labelledSeries(fields)
    .filter((candidate) => candidate.entries.length >= MIN_DECLARED_VALUES &&
      !candidate.entries.every((entry) => DECIMAL_VALUE.test(entry.value)));
  for (const candidate of series) {
    readings.push({ entries: candidate.entries, minimum: MIN_DECLARED_VALUES });
    const numbered = numericOrder(candidate.entries);
    if (numbered) readings.push({ entries: numbered, minimum: MIN_DECLARED_VALUES });
    if (candidate.numeric && candidate.entries.length !== new Set(candidate.entries.map(labelRank)).size) {
      readings.push(...duplicateKeyReadings(candidate.entries)
        .map((reading): DeclaredReading => ({ entries: reading, minimum: MIN_DECLARED_VALUES })));
    }
  }
  // A hex-labelled field is read when its own numbers declare one complete series, in text order and in
  // numeric-label order. These readings are additional: every reading above is exactly the one it was, so no
  // field that used to be read stops being read and no other view is displaced.
  for (const members of completeHexSeries(entries)) {
    readings.push({ entries: members, minimum: MIN_DECLARED_VALUES });
    const numbered = numericOrder(members);
    if (numbered) readings.push({ entries: numbered, minimum: MIN_DECLARED_VALUES });
  }
  if (series.length) {
    const declared = new Set(series[0]!.entries);
    const metadata = fields.filter((entry) => !declared.has(entry));
    if (metadata.length >= MIN_DECLARED_VALUES) readings.push({ entries: metadata, minimum: MIN_DECLARED_VALUES });
  }
  return readings;
}
const DECIMAL_VALUE = /^\d{1,16}$/u;
function* labelledChunkRuns(text: string, budget: DeclaredBudget): Generator<EncodedRun> {
  if (!HAS_LABEL.test(text)) return;
  let group: DeclaredEntry[] = [];
  let start = 0, end = 0;
  let previous: { at: number; length: number } | null = null;
  const flush = function* (): Generator<EncodedRun> {
    if (group.length) yield* declaredRuns(start, end, labelledReadings(group), budget);
    group = [];
    previous = null;
  };
  for (const field of text.matchAll(LABELLED_FIELD)) {
    const at = field.index!;
    const gap = previous ? text.slice(previous.at + previous.length, at) : '';
    if (previous && (!labelledGap(gap) || group.length >= MAX_DECLARED_FIELDS)) yield* flush();
    if (group.length === 0) start = at;
    const value = field[2] ?? field[3] ?? field[4];
    // A word that is all hex (`face:`) is a value, not a label: it joins no reading unless it declares a
    // numbered series of its own, and it does not end the group, so an unrelated hex-looking field between
    // labelled parts cannot split the declaration in two.
    if (value !== undefined) group.push({ label: field[1]!, value, hexLabel: !/[g-zG-Z]/u.test(field[1]!) });
    end = at + field[0].length;
    previous = { at, length: field[0].length };
  }
  yield* flush();
}
/**
 * The label half of a labelled field, without its value: `part1:`, `"part2":`, `p3=`, up to the first character of
 * the value. It is the label grammar `LABELLED_FIELD` already uses — the same bounded label, the optional quoted
 * key, the same `[ \t]{0,4}` spacing around the separator, and the optional opening quote of a JSON string value
 * (`"part1":"\x1f"`) — so a field this reader skips for want of an escape is exactly a field the chunk reader owns,
 * and the two never both claim one field.
 *
 * The label may not start inside a backslash escape. In a JSON body the line break between two fields is the two
 * characters `\n`, and a label scan that started at its `n` read `npart2` for every field after the first: one series
 * of 159 fields whose join was the payload minus its own first byte, which decoded to nothing and was released while
 * the same payload in every other spelling was refused. The escape is therefore consumed **before** the label here,
 * and the label may not follow a backslash at all — a measured hole, not a hypothetical one, and the opposite of
 * the direction this whole reader exists for.
 */
const LABELLED_HEAD = /(?<![A-Za-z0-9_\\])(?:\\[nrtbfunx0-7])?([A-Za-z][A-Za-z0-9_-]{0,23})"?[ \t]{0,4}[:=][ \t]{0,4}"?/gu;
/**
 * One reading per declared label series of a group of escape-valued fields, in text order and in numeric-label
 * order. A series is the same declaration the chunk reader reads — the fields that share a label name, numbered
 * (`part1 … partN`) or not (`data`, `value`, the keys an array of labelled objects uses) — so this adds a reading
 * and never removes one. It is a per-name reading, not a search over subsets: a group of n fields yields at most
 * n/2 series and each costs its own size. A group whose fields are *not* one series is still read, one name at a
 * time; a payload spread across two declared names is not, which is the limit the chunk reader already publishes.
 *
 * A hex-alphabet label (`face1: \x1f`, `dead: 1f8b0800`) is not a declaration on its own, because a dump offset
 * column is written the same way and carries numbers too. The exclusion from the name series above is therefore
 * replaced, not widened, by the same rule the chunk reader beside it uses: a hex-labelled field joins an escape
 * series when — and only when — `completeHexSeries` says its own numbers declare one complete run (rank 0 or 1,
 * consecutive, no repeat) under one label name. Before this rule a zlib stream spelled `face1: \xHH`, `face2: …`
 * joined no reading at all and a registered original and canary were released with their bytes, while the
 * ordinary-label and byte-pair spellings of the same bytes were refused. A dump offset column, a hex name with
 * no numbers, one field, a gap in the numbering and two names alternating are all still not one declaration, and
 * a part written as a plain hexadecimal chunk still leaves the escape run incomplete rather than joining it: the
 * series reader joins one series and never a subset of it, which is the limit every declared form already
 * These readings are **added** to the name series above, so no field that used to be read stops being read, and
 * they are charged through the same per-message budget.
 *
 * A member of a hex-labelled run that this reader could not reconstruct whole — a field with an unsupported
 * suffix after its last escape, or a field of that name and rank whose value is not an escape list at all — is
 * still a member the sender wrote, so the run over that name is not complete and no reading is offered for it.
 * `incomplete` carries those identities from the collector below. The rule is confined to this candidate: the
 * name-series readings above keep exactly the prefix behaviour they have always had, because changing that is
 * the prior path's own decision and not this reading's.
 */
function escapeReadings(prefix: readonly DeclaredEntry[], whole: readonly DeclaredEntry[],
  incomplete: readonly HexMember[]): DeclaredReading[] {
  const readings: DeclaredReading[] = [];
  // The ordinary-name series, over the escapes each field held before this change: a declared alternative of its
  // own, charged like every other reconstruction, and left exactly as it was.
  for (const candidate of labelledSeries(prefix.filter((entry) => !entry.hexLabel))) {
    if (candidate.entries.length < MIN_DECLARED_VALUES) continue;
    readings.push({ entries: candidate.entries, minimum: MIN_DECLARED_VALUES, escaped: true });
    const numbered = numericOrder(candidate.entries);
    if (numbered) readings.push({ entries: numbered, minimum: MIN_DECLARED_VALUES, escaped: true });
  }
  // The hex-labelled candidate, over whole fields. `completeHexSeries` returns its members in the order the sender
  // wrote them, so the span below is computed from the **numeric ranks** of all of them and never from the first one
  // in text order: reversing the lines used to move the span from 1..N to N..2N, which both vetoed an unrelated rank
  // that was nothing to do with the run and read past a member at rank 1 that the run was missing.
  for (const members of completeHexSeries(whole)) {
    const first = hexMember(members[0]!.label);
    let lowest = Number.POSITIVE_INFINITY, highest = Number.NEGATIVE_INFINITY;
    for (const entry of members) {
      const rank = hexMember(entry.label);
      if (rank !== null) { lowest = Math.min(lowest, rank.rank); highest = Math.max(highest, rank.rank); }
    }
    // Full membership, over that span: a member of the same name this reader could not reconstruct, at a rank inside
    // or beside it, is one the sender wrote -- the member the run is missing, or a second spelling of one it has. A
    // rank far outside is another declaration and is never a veto, so an unrelated field cannot hide a payload.
    if (first !== null && incomplete.some((entry) => entry.name === first.name
      && entry.rank >= lowest - 1 && entry.rank <= highest + 1)) continue;
    readings.push({ entries: members, minimum: MIN_DECLARED_VALUES, escaped: true });
    const numbered = numericOrder(members);
    if (numbered) readings.push({ entries: numbered, minimum: MIN_DECLARED_VALUES, escaped: true });
  }
  return readings;
}
/**
 * Escapes written as the values of one declared label series — `part1: \x1f`, `part2: \x8b`, … — rebuilt as the
 * one byte string that series spells. Before this reading each of those escapes was a one-byte run below the
 * floor, so a compressed note, a canary or a blob written this way was read as ordinary text and released.
 *
 * It is a **declared series** reading and nothing wider. The fields are grouped exactly as `labelledChunkRuns`
 * groups them (the same gap rule, the same `MAX_DECLARED_FIELDS`), every field of the series must be an escape
 * list, and the join is charged through the same per-message `DeclaredBudget`, so a message demanding more
 * reconstructions than the budget allows is uninspectable in the same way and never quietly clean. Like every
 * declared reconstruction it is decode-only: it adds no opaque bytes of its own, so ordinary labelled
 * configuration cannot be blocked by the shape of its values. It reads nothing inside a quoted string (that is
 * `quoted()`, untouched), and it joins nothing that is not one series — no word skipping, no subset search.
 */
function* labelledEscapeRuns(text: string, budget: DeclaredBudget): Generator<EncodedRun> {
  if (!HAS_LABEL.test(text)) return;
  /**
   * The two readings this collector produces from the same fields, side by side and never instead of each other:
   * `prefix` is the escapes a field holds before a contiguous run of them, which is what this reader has always
   * collected and what the ordinary-name series is built from, and `whole` is every escape the field holds, which is
   * what the hex-labelled candidate needs so that a field is reconstructed whole or not at all. Each is charged and
   * yielded as its own reading.
   */
  let prefix: DeclaredEntry[] = [], whole: DeclaredEntry[] = [];
  /**
   * Hex-labelled numbered members near this group that were not reconstructed whole, each with where it was
   * written and whether the text that reaches it continues the group. A member on the other side of a break the
   * group rule rejects, or of a gap it does not allow, belongs to a different declaration and is dropped with it:
   * a veto that reached past its own group suppressed valid series beside it and released what it was meant to
   * find. Cleared with the group.
   */
  const incomplete: (HexMember & { at: number; length: number; joins: boolean })[] = [];
  let start = 0, end = 0;
  let previous: { at: number; end: number } | null = null;
  const flush = function* (): Generator<EncodedRun> {
    if (whole.length) {
      // A member ahead of this group vetoes it only when the text between them would have continued one.
      const blocked = incomplete.filter((entry) => entry.joins
        || entry.at < start && labelledGap(text.slice(entry.at + entry.length, start)));
      yield* declaredRuns(start, end, escapeReadings(prefix, whole, blocked), budget);
    }
    prefix = [];
    whole = [];
    incomplete.length = 0;
    previous = null;
  };
  for (const head of text.matchAll(LABELLED_HEAD)) {
    const at = head.index!;
    const label = head[1]!;
    const member = hexMember(label);
    const hexLabel = !/[g-zG-Z]/u.test(label);
    const quote = head[0].endsWith('"') ? '"' : head[0].endsWith("'") ? "'" : '';
    const valueAt = at + head[0].length;
    const prefixPieces = escapeListPieces(text, valueAt, false);
    const wholePieces = escapeListPieces(text, valueAt, true);
    // Not an escape-valued field, so it belongs to no reading here: `LABELLED_FIELD` may still read it as a chunk.
    // For a hex-labelled numbered name it is also a member of that declaration, and one this reader cannot
    // reconstruct must not be counted among the ones it did.
    if (!prefixPieces.length) {
      if (member !== null) {
        incomplete.push({ ...member, at, length: head[0].length,
          joins: previous !== null && labelledGap(text.slice(previous.end, at)) });
      }
      continue;
    }
    const gap = previous ? text.slice(previous.end, at) : '';
    if (previous && (!labelledGap(gap) || whole.length + wholePieces.length > MAX_DECLARED_FIELDS)) yield* flush();
    if (whole.length === 0) start = at;
    const entries = (pieces: readonly { bytes: number[] }[]) =>
      pieces.map((piece) => ({ label, value: hexBytes(piece.bytes), hexLabel }));
    prefix.push(...entries(prefixPieces));
    whole.push(...entries(wholePieces));
    end = wholePieces.at(-1)!.end;
    previous = { at, end };
    // A field the sender did not finish is still collected for the name-series reading, which has always read the
    // escapes it can see; only the hex-labelled candidate above needs the whole field, so only it is withheld.
    // It is inside the group by construction, so it always vetoes it.
    if (member !== null && !wholeEscapeField(text, end, quote)) {
      incomplete.push({ ...member, at, length: head[0].length, joins: true });
    }
  }
  yield* flush();
}
/** Declared separators between encoded chunks: `+` concatenation, `/` grouping, `>` pipeline output. */
const MIN_JOIN_CHUNKS = 3;
const MIN_JOIN_CHUNK = 2;
const MAX_JOIN_CHUNK = 1024;
/** Base64url characters, plus the separator characters that can be glued inside a chunk (`+`, `/`, `>`). */
function joinChunkChar(code: number): boolean {
  return (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a) ||
    code === 0x2d || code === 0x5f || code === 0x2b || code === 0x2f || code === 0x3e;
}
/** A chunk needs Base64url characters of its own: a lone `+`, `/` or `>` is separator punctuation. */
function joinChunkCore(code: number): boolean {
  return joinChunkChar(code) && code !== 0x2b && code !== 0x2f && code !== 0x3e;
}
/**
 * The same two sets as a table, for scanning a whole message: bit 1 is a Base64url character, bit 2 is one of its
 * own. Every join this reader reconstructs needs a separator or its percent-escaped spelling somewhere, so a
 * message without one has nothing for it to read and is skipped in a single scan.
 */
const JOIN_CHAR = ((): Uint8Array => {
  const table = new Uint8Array(128);
  for (let code = 0; code < 128; code++) table[code] = joinChunkChar(code) ? (joinChunkCore(code) ? 3 : 1) : 0;
  return table;
})();
const HAS_JOIN_SEPARATOR = /[/+>]|%2[BbFf]|%3[Ee]/u;
const HAS_LABEL = /[:=]/u;
const GLUED_SEPARATOR = /[/+>]/u;
/**
 * Whitespace-padded single separator between two chunks: ` + `, ` / `, ` > `, their asymmetric and line-broken
 * forms, and the percent-escaped spelling of the same separator (`%2B`, `%2f`, `%3e`).
 */
const DECLARED_GAP = /^[ \t\r\n]{0,8}([/+>]|%2[BbFf]|%3[Ee])[ \t\r\n]{0,8}$/u;
const PERCENT_ESCAPE = /^%[0-9A-Fa-f]{2}/u;
/**
 * Chunks joined by declared separators, scanned once. A chunk is a run of Base64url characters that may carry a
 * glued separator character, so several readings of one group are decoded: the text as written, the text with
 * every separator character removed, and the text with a separator character glued to the same side of every
 * chunk removed (`X +Y` and `X+ Y`). Evidence is judged on the chunks as written, so a hex join split by `/`
 * (`1f8b/0800/…`) is read as hex and a Base64 join as Base64. `/` and `>` are ordinary punctuation, so a group
 * using them needs three or more chunks; `+` alone is an explicit concatenation operator and two are enough.
 */
function* separatorChunkRuns(text: string, budget: DeclaredBudget): Generator<EncodedRun> {
  if (!HAS_JOIN_SEPARATOR.test(text)) return;
  let group: { start: number; end: number }[] = [];
  let plus = true;
  let previousEnd = 0;
  /** One reading: the joined value, judged against the chunks exactly as they were written. */
  const reading = (value: string, evidence: readonly DeclaredEntry[]): DeclaredReading =>
    ({ entries: [{ label: '', value, hexLabel: false }], minimum: 1, evidence });
  /**
   * The same chunks with one separator character removed from a consistent edge of the chunks it was written
   * against (`X +Y`, `X+ Y`). Both the interior boundaries and the outer edges are offered, since the first or
   * last chunk may or may not have been written with the same glue.
   */
  const glued = (chunks: readonly string[], side: 'leading' | 'trailing'): string[] => {
    const edge = (value: string): string => (side === 'leading' ? value[0] ?? '' : value[value.length - 1] ?? '');
    const interior = side === 'leading' ? chunks.slice(1) : chunks.slice(0, -1);
    if (chunks.length < 2 || !interior.every((value) => GLUED_SEPARATOR.test(edge(value)))) return [];
    const separator = edge(interior[0]!);
    const trim = (value: string): string => (side === 'leading' ? value.slice(1) : value.slice(0, -1));
    const values = [chunks.map((value, index) => {
      const interiorEdge = side === 'leading' ? index > 0 : index < chunks.length - 1;
      return interiorEdge ? trim(value) : value;
    }).join('')];
    // The uniform spelling: the outer chunks were glued the same way as the interior boundaries.
    const outer = edge(side === 'leading' ? chunks[0]! : chunks[chunks.length - 1]!);
    if (outer === separator) values.push(chunks.map((value) => (edge(value) === separator ? trim(value) : value)).join(''));
    return values;
  };
  const flush = function* (): Generator<EncodedRun> {
    if (!group.length) { group = []; plus = true; return; }
    const chunks = group.map(({ start, end }) => text.slice(start, end));
    const asWritten: DeclaredEntry[] = chunks.map((value) => ({ label: '', value, hexLabel: false }));
    const start = group[0]!.start, end = group[group.length - 1]!.end;
    const joined = chunks.join('');
    // `>` is in no encoding alphabet, so dropping it is exact. `+` and `/` are Base64 characters: dropping
    // every one of them is a guess that only wins when the sender used them as the separator rather than data.
    const readings = [reading(joined, asWritten), reading(joined.replace(/>/gu, ''), asWritten),
      reading(joined.replace(/[/+>]/gu, ''), asWritten)];
    for (const side of ['leading', 'trailing'] as const) {
      for (const value of glued(chunks, side)) readings.push(reading(value, asWritten));
    }
    if (chunks.length >= (plus ? MIN_DECLARED_VALUES : MIN_JOIN_CHUNKS)) yield* declaredRuns(start, end, readings, budget);
    // Too few chunks for a declared join, but they may still be one written without spaces around the separator.
    else yield* declaredRuns(start, end, readings.slice(1), budget);
    group = [];
    plus = true;
  };
  let at = 0;
  while (at < text.length) {
    // A percent escape is separator spelling, not a chunk: its two hex digits must not become one.
    if (text[at] === '%' && PERCENT_ESCAPE.test(text.slice(at, at + 3))) { at += 3; continue; }
    const start = at;
    let core = 0;
    while (at < text.length && (JOIN_CHAR[text.charCodeAt(at)] ?? 0) !== 0) {
      if ((JOIN_CHAR[text.charCodeAt(at)] ?? 0) === 3) core++;
      at++;
    }
    if (at === start) { at++; continue; }
    if (core < MIN_JOIN_CHUNK) {
      // A lone `+`, `/` or `>` is separator punctuation, not a chunk: leave the gap open so a later chunk can
      // still be read as joined to the previous one.
      continue;
    }
    if (at - start > MAX_JOIN_CHUNK) {
      // A run wider than the chunk bound is not one; the whole-run reader already has it on its own.
      yield* flush();
      previousEnd = at;
      continue;
    }
    if (group.length) {
      const gapText = text.slice(previousEnd, start);
      const separator = DECLARED_GAP.exec(gapText)?.[1];
      // A separator written against the chunk it touches (`X +Y`, `X+ Y`) has whitespace-only around it and the
      // separator character itself at the edge of a chunk; the glued readings above join it correctly.
      const against = /^[ \t\r\n]{1,8}$/u.test(gapText) ? GLUED_SEPARATOR.test(text[start] ?? '') ?
        text[start]! : GLUED_SEPARATOR.test(text[at - 1] ?? '') ? text[at - 1]! : '' : '';
      // Anything else is ordinary text between two chunks.
      if (separator === undefined && !against) yield* flush();
      else if (!/^(?:[+/])$/u.test(separator ?? against)) plus = false;
    }
    group.push({ start, end: at });
    previousEnd = at;
    if (group.length >= MAX_DECLARED_CHUNKS) yield* flush();
  }
  yield* flush();
}
/**
 * Decimal byte arrays and Node `Buffer` JSON: `[63, 111, 110]`, `["63","111"]` and `{"type":"Buffer","data":[…]}`.
 * Eight or more decimal bytes below 256 inside one bracket, with or without a trailing comma, read as bytes for
 * matching, decompression and the container check only. A value above 255, a non-integer or any other content
 * ends the array, so timestamps, versions, port lists and float vectors are not reinterpreted as bytes.
 */
const MIN_DECIMAL_ARRAY = 8;
/** As many bytes as one reconstructed value can hold, so a byte array is never read past its own value cap. */
const MAX_DECIMAL_ARRAY = MAX_DECLARED_VALUE >> 1;
const SPACE = /[ \t\r\n]/u;
/** Whitespace and at most one quote: numbers in a byte array may be written as strings. */
function decimalSpace(text: string, at: number): number {
  while (SPACE.test(text[at] ?? '')) at++;
  if (text[at] === '"' || text[at] === "'") { at++; while (SPACE.test(text[at] ?? '')) at++; }
  return at;
}
function* decimalByteRuns(text: string, budget: DeclaredBudget): Generator<EncodedRun> {
  if (!text.includes('[')) return;
  for (let at = 0; at < text.length; at++) {
    if (text[at] !== '[') continue;
    let cursor = decimalSpace(text, at + 1), closed = false;
    const bytes: number[] = [];
    for (; cursor < text.length && bytes.length < MAX_DECIMAL_ARRAY;) {
      const start = cursor;
      while (cursor - start < 3 && (text[cursor] ?? '') >= '0' && (text[cursor] ?? '') <= '9') cursor++;
      if (cursor === start) break;
      const value = Number(text.slice(start, cursor));
      if (value > 255) break;
      bytes.push(value);
      cursor = decimalSpace(text, cursor);
      // A trailing comma before the bracket is valid in the array literals this form comes from.
      if (text[cursor] === ',') { cursor = decimalSpace(text, cursor + 1); if (text[cursor] !== ']') continue; }
      closed = text[cursor] === ']';
      break;
    }
    if (!closed || bytes.length < MIN_DECIMAL_ARRAY) continue;
    const value = bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('');
    if (!charge(value, budget)) continue;
    yield { start: at, end: cursor + 1, value, prefixed: false, countable: false, separated: true, joined: true, declared: true };
  }
}
/**
 * Encoded runs: every run of 16+ alphabet characters (a `shaNNN-`/`shaNNN:`/`h1:` prefix stripped), plus
 * sequences of short chunk-like tokens separated only by whitespace, commas, quotes, brackets or `:;|.&`, joined
 * into one run so that chunking below 16 characters cannot hide compressed data. A joined sequence counts toward
 * OPAQUE_BYTES only when it is separated by whitespace, commas, quotes or brackets and three quarters of its
 * tokens are clearly encoded; other sequences (digit-free Base64 chunks, but also JSON ids, IPv6 addresses and
 * regex classes) are decoded and decompressed, never counted.
 */
function* encodedRuns(text: string, budget: DeclaredBudget): Generator<EncodedRun> {
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
  // Representations that declare their own reconstruction, decode-only and budgeted per message.
  yield* labelledChunkRuns(text, budget);
  yield* labelledEscapeRuns(text, budget);
  yield* separatorChunkRuns(text, budget);
  yield* decimalByteRuns(text, budget);
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

/**
 * A separator character between two byte escapes, and nothing else: whitespace, `,;:|.&`, quotes and brackets,
 * or the two-character JSON spelling of a line break (`\n`, `\r`, `\t`). `-` is deliberately not one, because a
 * hyphen between two escapes is as likely to be a word.
 */
const ESCAPE_SEPARATOR = /^[ \t\r\n,;:|.&"'[\]]$/u;
const ESCAPE_JSON_SEPARATOR = /\\[nrt]/u;
/**
 * How wide one separator run between two byte escapes may be, in characters of the text. Formatting is not one
 * character wide: a list is separated by `, `, ` : `, a tab and a space, a CRLF pair or its JSON spelling `\r\n`,
 * and a JSON array of escapes by `","` or by `,\n  "`. The run is bounded and drawn from the class above rather
 * than open, so it stays a statement about the *formatting* between escapes and never becomes a way to skip words:
 * every character in it is a separator-class character or a JSON line-break spelling, `-` is still not one, and
 * the run ends at the first character that is neither. A wider gap is ordinary text and ends the run, which is a
 * declared limit (the #19 known-limits list, frozen in the retired `docs/plan.md` at commit f838fc2) rather than a
 * completeness claim.
 */
const MAX_ESCAPE_SEPARATOR = 8;
/**
 * The end of the separator run between two byte escapes in ordinary text, or -1 when the run ends at `at`. The run
 * is skipped only when it is bounded by the class above and is immediately followed by another escape, so `=41 =42`
 * and `=41,  =42` are one two-byte run while `=41 and =42` and a nine-character gap stay two one-byte runs below
 * the floor.
 *
 * This is a rule about the **text between** escapes, so it applies where the text is text and nowhere else. Inside
 * a quoted string every literal character is a byte of that string (`b'\x1f\x8b \x08'` holds a space), so the
 * quoted readers below never call this: dropping such a character corrupts the bytes they reconstruct, and a
 * corrupted stream that decodes to nothing lands under `OPAQUE_BYTES` and would be released. Ordinary text has the
 * same trade and fails the same way: a payload whose own bytes spell separator-class characters, written literally
 * between its escapes, reconstructs to bytes that are not a stream and are counted opaque rather than released.
 */
function escapeSeparatorEnd(text: string, at: number): number {
  const limit = Math.min(text.length, at + MAX_ESCAPE_SEPARATOR);
  let end = at;
  while (end < limit) {
    // A character that opens an escape belongs to that escape, not to the run: `&` is both a separator-class
    // character and the lead of `&#xNN;`, so a greedy scan would eat the next entity's lead and then fail.
    if (escapedByteAt(text, end) !== null) break;
    if (end + 2 <= limit) {
      const json = ESCAPE_JSON_SEPARATOR.exec(text.slice(end, end + 2))?.[0];
      if (json !== undefined) { end += 2; continue; }
    }
    if (ESCAPE_SEPARATOR.test(text[end]!)) { end += 1; continue; }
    break;
  }
  if (end === at || escapedByteAt(text, end) === null) return -1;
  return end;
}

/**
 * Bytes one escape run reconstructs before the escapes after it are read as the next run. The bound is below #6's
 * own longest-run ceiling (`MAX_RUN` in src/normalization.ts) on purpose: a run this reader builds is inspected
 * again as a view, and a decoded text run longer than that ceiling would be a view #6 refuses, so this module
 * would refuse a message it could otherwise read. The split drops no byte — the separator after the bound is
 * absorbed into the run's own span, so the next run is adjacent to it and the two concatenate back into the same
 * bytes — and the message-size and view budgets still bound the total. It bounds the direct reader only; a quoted
 * string is read whole, as it always was.
 */
const MAX_ESCAPED_RUN = 32 << 10;
/** The hex spelling of reconstructed bytes, the one form every reader hands to `decodeRun`. */
function hexBytes(bytes: readonly number[]): string {
  return bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('');
}
function escapedRun(start: number, end: number, bytes: number[], byteSyntax: boolean): EncodedRun {
  return { start, end, value: hexBytes(bytes),
    // Unicode escapes for ordinary accented prose are ambiguous Latin-1, so inspect them without opaque counting
    // unless control bytes or explicitly byte-oriented syntax make the representation binary.
    prefixed: false, countable: byteSyntax || bytes.some((byte) => byte < 32 || byte === 127), separated: true, escaped: true };
}

/**
 * Escape runs in ordinary text. `separated` decides whether a bounded separator run between two escapes is
 * skipped: the contiguous reading this reader has always had, or the separated reading added to it. Both are read from the
 * same text, so a sender cannot lose the contiguous reading by formatting the list, and a character that is a byte
 * of the payload rather than formatting is still read by the contiguous one. A separated run that skipped no
 * separator at all is byte-for-byte the contiguous run and is not yielded twice.
 *
 * A run ends at the first character that is not an escape (and, when separated, at a separator that is not between
 * two escapes), or at `MAX_ESCAPED_RUN`, which never drops a byte: the next run starts at the next escape, adjacent
 * to this one, so consecutive runs concatenate back into the same bytes.
 */
function* textEscapeRuns(text: string, separated: boolean): Generator<EncodedRun> {
  for (let at = 0; at < text.length;) {
    const first = escapedByteAt(text, at);
    if (!first) { at++; continue; }
    const start = at;
    const bytes: number[] = [];
    let byteSyntax = false, skipped = false;
    for (let token: { byte: number; end: number } | null = first; token; token = escapedByteAt(text, at)) {
      bytes.push(token.byte);
      if (text[at] === '%' || text[at] === '=' || text[at] === '\\' && !/[uU]/u.test(text[at + 1]!)) byteSyntax = true;
      at = token.end;
      if (separated) {
        const skip = escapeSeparatorEnd(text, at);
        if (skip >= 0) { at = skip; skipped = true; }
      }
      if (bytes.length >= MAX_ESCAPED_RUN) break;
    }
    // The contiguous reading is always yielded; a separated one only when it actually skipped a separator.
    if (bytes.length >= 4 && (!separated || skipped)) yield escapedRun(start, at, bytes, byteSyntax);
  }
}

/**
 * One escape list written as the value of a labelled field: the escape at `at`, then every further escape that
 * follows a bounded separator run, up to `MAX_ESCAPED_RUN` bytes. It calls the same `escapedByteAt`, the same
 * separator rule and the same bound as the direct reader above, so an escape family or a separator spelling that
 * reads in one reader reads in the other and no spelling can appear in only one of them. A list of one escape is a
 * list: a declared series whose every field carries a single escape is one byte stream, not a sequence of
 * one-byte runs below the floor.
 */
function escapeListAt(text: string, at: number, contiguous: boolean): { bytes: number[]; end: number } | null {
  const first = escapedByteAt(text, at);
  if (first === null) return null;
  const bytes = [first.byte];
  let end = first.end;
  while (bytes.length < MAX_ESCAPED_RUN) {
    // `contiguous` is the whole-field candidate's rule, not this helper's: for it a contiguous escape belongs to
    // the same value as the one before it, because the direct reader treats `\x50\x51` as one run and a field the
    // reader half-reads is a stream the sender never wrote. It is tried *before* the separator rule below, never
    // instead of it. The ordinary-name reading keeps that rule on its own, because the prefix it collects is a
    // declared alternative of its own and narrowing it is a separate decision this change does not make.
    if (contiguous) {
      const next = escapedByteAt(text, end);
      if (next !== null) { bytes.push(next.byte); end = next.end; continue; }
    }
    const skip = escapeSeparatorEnd(text, end);
    if (skip < 0) break;
    const next = escapedByteAt(text, skip);
    if (next === null) break;
    bytes.push(next.byte);
    end = next.end;
  }
  return { bytes, end };
}
/** The label grammar `LABELLED_HEAD` uses, anchored so it can only match at one position. */
const LABELLED_HEAD_AT = new RegExp(LABELLED_HEAD.source, 'uy');
/**
 * What a field's own formatting may add after its last escape: the between-escape separator class, plus the
 * structural closers a JSON body writes around a value and the brackets a line of text may be wrapped in. This is
 * a rule about the text *after* a value, so it decides where the field's value ends and never contributes a byte
 * of it. A letter or a digit is not one, which is the whole point: `face1: \x50oops` carries a suffix, not padding.
 */
const FIELD_TAIL = /^[ \t\r\n,;:|.&"'[\]{}())\]]$/u;
/**
 * Whether the escape list ending at `end` is the **whole** value of its field. `escapeListAt` stops at the first
 * character it does not support, so on its own it cannot tell a finished value from one the sender began and
 * abandoned: `face1: \x50oops` and `face1: \x50\xGG` both read as one byte, and `labelledGap` then accepts the
 * dropped suffix as the prose between two fields. A reconstruction taken from such a prefix invents a stream out
 * of part of a field the sender never finished writing, which at `32811da` refused the ZIP signature the sender
 * wrote only one byte of.
 *
 * A field is whole when the next character is another escape (the contiguous escapes the direct reader owns, and
 * which this reader has always collected exactly as far as the list rule reached), or when everything between the
 * last escape and what follows is a bounded separator run and that run ends the text, ends the line, or is followed
 * by the next label. A suffix *inside* the field's own line is what this cannot see apart from a value, and it
 * resolves that in favour of the declaration.
 */
function wholeEscapeField(text: string, end: number, quote: string): boolean {
  // Inside a quoted value only the closing quote ends it, and end of input is not one: a field the sender opened and
  // never closed is not a field. A line break, a label or a word written between two escapes of a JSON string or a
  // byte literal is still inside the value, so treating it as formatting after the value dropped it and
  // reconstructed a stream the sender never wrote.
  if (quote !== '') {
    let at = end;
    while (at < text.length && /[ \t\r\n]/u.test(text[at]!)) at++;
    return text[at] === quote;
  }
  if (end >= text.length) return true;
  // The next escape continues the same value across a separator run the list rule has not reached.
  if (escapedByteAt(text, end) !== null) return true;
  const limit = Math.min(text.length, end + MAX_ESCAPE_SEPARATOR);
  let after = end, line = false;
  while (after < limit) {
    // A character that opens an escape belongs to a value, not to formatting: the value simply continues.
    if (escapedByteAt(text, after) !== null) break;
    const json = after + 2 <= limit ? ESCAPE_JSON_SEPARATOR.exec(text.slice(after, after + 2))?.[0] : undefined;
    if (json !== undefined) { line = line || json === '\\n' || json === '\\r'; after += 2; continue; }
    const char = text[after]!;
    if (!FIELD_TAIL.test(char)) break;
    if (char === '\n' || char === '\r') line = true;
    after += 1;
  }
  // The text ends here, or the field's own line does: whatever follows is another field or another sentence.
  if (after === text.length || line) return true;
  if (after === end) return false;
  LABELLED_HEAD_AT.lastIndex = after;
  return LABELLED_HEAD_AT.test(text);
}
/** One member of a hex-labelled numbered series: the name it shares, and the rank as a number. */
interface HexMember { name: string; rank: number }
/**
 * The member a hex-alphabet label declares, or null when it declares none. A hex label is a value the sender
 * wrote before a colon unless its own numbers declare a complete run, so the name and the rank together are what
 * two members of one declaration share. The rank is compared **as a number**: `face1` and `FACE01` are one member
 * written twice, exactly as `completeHexSeries` already treats them, and a string comparison hid the duplicate.
 */
function hexMember(label: string): HexMember | null {
  if (/[g-zG-Z]/u.test(label)) return null;
  const rank = NUMERIC_LABEL.exec(label);
  return rank === null ? null : { name: rank[1]!.toLowerCase(), rank: Number(rank[2]!) };
}
/**
 * Every escape list one labelled field holds, as one or more pieces of at most `MAX_ESCAPED_RUN` bytes. A field
 * longer than that bound is split exactly as the direct reader splits a long run, and the split drops no byte:
 * every piece carries the field's own label, so the declared series concatenates them back into the bytes the
 * field spells. Without the split a payload straddling the bound would be truncated to its first piece, decode
 * nothing, and — like every declared reconstruction — carry no opaque bytes of its own.
 */
function escapeListPieces(text: string, at: number, contiguous: boolean): { bytes: number[]; end: number }[] {
  const pieces: { bytes: number[]; end: number }[] = [];
  let cursor = at;
  for (;;) {
    const piece = escapeListAt(text, cursor, contiguous);
    if (piece === null) return pieces;
    pieces.push(piece);
    if (piece.bytes.length < MAX_ESCAPED_RUN) return pieces;
    const skip = escapeSeparatorEnd(text, piece.end);
    cursor = skip < 0 ? piece.end : skip;
  }
}

/**
 * Direct escape runs plus mixed byte string literals, including Latin-1 JSON and Python/JS strings.
 *
 * In ordinary text a run is a list of escapes the same way a hex dump is a list of byte pairs: a **bounded
 * separator run** may sit between two escapes, so an escape list the sender formatted (`=1F =8B =08 …`,
 * `%1f, %8b; …`, `\u001f,  \u008b …`, `&#x1f;&#x8b; …` as a JSON array, one escape per line) is read as the bytes
 * it spells rather than as the formatting around it. Ordinary text is read twice for that reason, in this order:
 * the contiguous reading this reader has always had, then the separated one, which is **added** to it and never
 * instead of it — so neither a sender who formats the list nor a sender whose separator characters are bytes of
 * the payload loses a reading. A gap wider than `MAX_ESCAPE_SEPARATOR`, or one holding any other character, still
 * ends a run; that limit is a declared limit of this module, pinned in the sentinel tests rather than claimed closed.
 *
 * Inside a quoted string the escapes are read by `quoted()` below, which is unchanged: there every literal
 * character is a byte of the string, so the separator rule is not applied and no byte is dropped. Both readings
 * reach the same run list, so a formatted escape list is read even when it sits inside a JSON string or a byte
 * literal, and a byte of the string itself is never mistaken for formatting.
 *
 * The four-byte floor, the supported escape families, the bounded separator run and `MAX_ESCAPED_RUN` are the
 * whole of the direct reader's grammar, and the work all of it does is bounded by the message limit and the
 * per-view budget it runs inside. Escapes spread across the fields of a **declared label series** are the separate
 * reading `labelledEscapeRuns` adds below; they are not joined here, because the text between them is a label
 * rather than formatting and skipping words is not something this reader does.
 */
function* escapedByteRuns(text: string): Generator<EncodedRun> {
  yield* textEscapeRuns(text, false);
  yield* textEscapeRuns(text, true);
  /**
   * A quoted string read as bytes: escapes, simple backslash escapes and Latin-1 characters, in the order they are
   * written. Every literal character is a byte of the string, including a character that sits between two escapes
   * and belongs to this module's separator class, so no reading here drops one: this is the reader's original
   * behaviour and the one the direct reader's separated reading is added to, never a replacement for.
   */
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
/**
 * Output chunk every decode attempt asks Node's zlib for. A synchronous zlib call allocates one output buffer per
 * call at Node's default `chunkSize` of 16 KiB, and a call that *fails* keeps that buffer until the runtime can run
 * again: measured on this host, a synchronous batch of 24,000 failed calls raises `arrayBuffers` by 16,148 bytes per
 * call at the default, by 4,037 at 4,096 and by 1,049 at 1,024, independent of `windowBits`. That is the high-water
 * mark of one synchronous batch, not a per-process retention: after two event-loop turns and a forced GC,
 * `arrayBuffers` and `external` return to within 0.1 MiB of their baseline, while RSS does not come back. So this
 * constant bounds how much a wrong-offset or decoy-signature scan can hold *while it runs*; it costs nothing
 * measurable on successful decodes (median of five, 1 MiB gunzip: 1.92 ms at 1 KiB against 1.49 ms at the default).
 */
const DECODE_CHUNK = 1024;
interface Inflated { out: Uint8Array; signed: boolean; consumed: number }
type Engine = (buffer: Uint8Array, options: { maxOutputLength: number; finishFlush: number; info: true; chunkSize: number }) => { buffer: Uint8Array; engine: { bytesWritten: number } };
/**
 * `sweep` is how many starting offsets after the first a raw-deflate attempt may try. A signed stream carries a
 * signature, so those sixteen attempts are already bounded; an unsigned one does not, so the interior read asks
 * for a bounded number of starting offsets per call rather than one, and steps its window on by the same amount,
 * so every offset is tried once. A sweep is matching evidence only: it never lowers or raises the opaque authority
 * of what it decodes.
 */
/**
 * `budget.total` is the message-wide decompression ceiling for the reads that share it. The interior read charges
 * its own, because its decodes are speculative: a long list of compressible digests decodes by chance at many
 * offsets, and charging those against the message's own 4 MiB would refuse messages the module has always inspected
 * and released for reading nothing. Both ceilings fail closed when they are reached.
 */
interface DecodeBudget { inflated: number; total: number }
function inflate(bytes: Uint8Array, budget: DecodeBudget, cap = budget.total, sweep = 0): Inflated | null | 'BUDGET' {
  const attempt = (engine: Engine, input: Uint8Array, start: number, signed: boolean, trailer = 0): Inflated | null | 'BUDGET' => {
    const remaining = budget.total - budget.inflated;
    if (remaining <= 0) return 'BUDGET';
    // A per-attempt cap (`cap`) bounds one speculative decode; running out of *that* is a failed attempt, while
    // running out of the message budget still fails closed.
    const limit = Math.min(remaining, cap);
    try {
      const { buffer: out, engine: state } = engine(input, { maxOutputLength: limit, finishFlush: SYNC_FLUSH, info: true, chunkSize: DECODE_CHUNK });
      budget.inflated += out.length;
      const consumed = Math.min(bytes.length, start + (state.bytesWritten || input.length) + trailer);
      // A gzip/zlib stream that decoded is a stream even when its output is tiny or empty, so a chain continues.
      if (signed) return consumed > start ? { out, signed, consumed } : null;
      if (out.length < 4) return null;
      return { out, signed, consumed };
    } catch (error) {
      return (error as { code?: string }).code === 'ERR_BUFFER_TOO_LARGE' && limit >= remaining ? 'BUDGET' : null;
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
  if (!sweep) {
    const brotli = attempt(brotliDecompressSync as unknown as Engine, bytes, 0, false);
    return brotli ?? attempt(inflateRawSync as unknown as Engine, bytes, 0, false);
  }
  // A sweep reads several starting offsets for the formats whose header cannot be scanned for. RFC 1951 reserves
  // one block type, so three of every four offsets cannot start a deflate stream and are not tried; brotli has no
  // such bit, so its own decoder is asked at each offset. A speculative interior read adds text and nothing else,
  // so a binary decode from a wrong offset is not evidence and must not displace the real stream behind it; among
  // the text decodes, the longest wins.
  let best: Inflated | null = null;
  for (let offset = 0; offset < Math.min(sweep + 1, bytes.length - 1); offset++) {
    for (const engine of [brotliDecompressSync, inflateRawSync]) {
      if (engine === inflateRawSync && ((bytes[offset]! >> 1) & 3) === 3) continue;
      const result = attempt(engine as unknown as Engine, bytes.subarray(offset), offset, false);
      if (result === 'BUDGET') return 'BUDGET';
      if (result && isText(result.out) && (!best || result.out.length > best.out.length)) best = result;
    }
  }
  return best;
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
/**
 * `speculative` marks a read whose printable and junk layers are discarded (an interior offset scan), so only the
 * text a decode produces is built: garbage that is dropped must not cost a string.
 */
function expand(bytes: Uint8Array, budget: DecodeBudget, sink: Sink, depth = 0, chain = 0,
  cap = budget.total, speculative = false, sweep = 0): Expanded | null | 'CONTAINER' | 'BUDGET' {
  const inflated = inflate(bytes, budget, cap, sweep);
  if (inflated === 'BUDGET' || inflated === null) return inflated;
  const { out, signed, consumed } = inflated;
  const decoded = out;
  // Every layer is matched: as text when it is text, and as printable bytes and UTF-16 otherwise.
  const matchBinary = (): void => { if (!speculative) sink.printables.push(printable(decoded), utf16Printable(out)); };
  // Brotli/raw deflate has no reliable signature. Even plausible printable output from ordinary decimal text
  // is only tentative: inspect it and its nested layers, but never use it to lower or raise opaque authority.
  if (!signed) {
    if (!speculative) sink.junk.push(printable(decoded), utf16Printable(out));
    if (isText(decoded)) sink.uncertain.push(utf8Lenient.decode(out));
    // A speculative read does not recurse: its sweep already tries every starting offset of the whole run, so a
    // layer inside this output is reached by the next window rather than by a second pass over the same bytes.
    if (!speculative && depth + 1 < MAX_INFLATE_DEPTH) {
      const inner: Sink = { texts: [], uncertain: [], printables: [], junk: [] };
      for (const part of consumed < bytes.length ? [out, bytes.subarray(consumed)] : [out]) {
        const result = expand(part, budget, inner, depth + 1, 0, cap);
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
    // A speculative read does not follow the chain: its sweep already tries every starting offset of the run, so a
    // stream after this one's end is read by the next window rather than by a second pass over the same bytes.
    const next = chain + 1 < MAX_STREAM_CHAIN && !speculative ? expand(tail, budget, sink, depth, chain + 1, cap, speculative) : null;
    if (next === 'CONTAINER' || next === 'BUDGET') return next;
    if (next && !next.keep) trailing = next.opaque;
    else if (isText(tail)) sink.texts.push(utf8Lenient.decode(tail));
    else { trailing = tail.length; if (!speculative) sink.printables.push(printable(tail), utf16Printable(tail)); }
  }
  if (isText(decoded)) { sink.texts.push(utf8Lenient.decode(out)); return { opaque: trailing, consumed: bytes.length, keep: false }; }
  matchBinary();
  const nested = depth + 1 < MAX_INFLATE_DEPTH ? expand(out, budget, sink, depth + 1, 0, cap) : null;
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

/**
 * One canonical view. `derived` means the text was produced by decoding the message itself, so **nothing inside it
 * counts toward the opaque total**: it is a switch over the whole view, at both gates that matter (`recognized` and
 * the decompression output counted for the view). That is too coarse for a text this module *reconstructed* from a
 * declared escape series: the series' own text is a decode, so re-reading it as an encoded run must not make the
 * sender's own text opaque — but everything that text **encodes** (a Base64 or hex payload, a signed stream, a
 * container signature) is new data and must count exactly as it does in every other declared form. `ownText` is the
 * narrow form of that exemption: the exact strings this view was built from, and only a run whose whole value is one
 * of them is exempt from the byte count.
 */
interface View { name: string; text: string; derived?: boolean; matchOnly?: boolean; ownText?: ReadonlySet<string> }
const INVALID_BYTE_OCTAL = /\\[4-7][0-7]{2}/u;
/**
 * All canonical views: each text is decoded by #6 (Base64/percent/hex) and by the escape round, and every
 * resulting view is processed again, to MAX_ROUNDS. Returns a block reason when anything is uninspectable.
 */
function canonicalViews(root: string): { views: View[]; opaque: boolean } | { reason: string } {
  const views: View[] = [];
  const budget: DecodeBudget = { inflated: 0, total: MAX_INFLATE_TOTAL };
  // The interior read's own decompression ceiling, charged across every window and every round.
  const interiorBudget: DecodeBudget = { inflated: 0, total: MAX_INTERIOR_INFLATED };
  /** Declared reconstructions are budgeted per message, across every view and round. */
  const declaredBudget: DeclaredBudget = { seen: new Set<string>(), runs: 0, units: 0, work: 0 };
  const countedValues = new Set<string>();
  const countedBytes: string[] = [];
  let opaqueTotal = 0;
  let interiorWindows = 0;
  let interiorBytes = 0;
  let interiorText = 0;
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
      /**
       * The text a **declared escape series** spells. It is inspected as its own view, carrying `ownText` rather
       * than `derived`: the series' own text is a decode (below), while a Base64 or hex payload *inside* that text,
       * and any decompression under it, raise the opaque total exactly as they do in a non-derived view. Appending
       * it to the shared joined text instead was measured as a second, narrower problem in the other direction: a
       * series spelling only hex letters (`=41 =42 …` -> `ABAB…`) was re-read there as an encoded run of its own and
       * refused for the sender's own text.
       */
      const escapedTexts: string[] = [];
      const binary: Uint8Array[] = [];
      let countable = 0;
      const spans: [number, number][] = [];
      const chunkJoin: boolean[] = [];
      const declaredRun: boolean[] = [];
      const runCounts: number[] = [];
      const runIdentified: boolean[] = [];
      const runPublicBlock: boolean[] = [];
      const runDeclared: boolean[] = [];
      const runDigest: boolean[] = [];
      const runValue: string[] = [];
      const publicBlocks = [...view.text.matchAll(PUBLIC_PEM)].filter((block) => derShaped(block[0]))
        .map((block) => ({ start: block.index, end: block.index + block[0].length }));
      for (const run of encodedRuns(view.text, declaredBudget)) {
        if (textSpans.some((span) => span.start <= run.start && run.end <= span.end)) continue;
        const decoded = decodeRun(run.value);
        if (!decoded) continue;
        // Text from joined chunks or separated hex is a layer #6 did not see: inspect it like any decoded view.
        if (isText(decoded)) {
          if (run.separated && run.escapedSeries === true) escapedTexts.push(utf8Lenient.decode(Uint8Array.from(decoded)));
          else if (run.separated) joinedTexts.push(utf8Lenient.decode(Uint8Array.from(decoded)));
          continue;
        }
        const bytes = Uint8Array.from(decoded);
        // Not counted: exact-length digests (with or without a `shaNNN-`/`h1:` prefix), SSH key blobs, UUIDs,
        // identifiers (`http2ServerSessionOptions`), runs that do not look encoded (lower-case paths, snake_case
        // ids), and anything inside views derived from decompression or printable bytes.
        // All-decimal runs (nanosecond timestamps, snowflake ids, float digits) are numbers, not hex.
        // Mixed case with a digit, `+`, or frequent case switches (digit-free random Base64); camelCase names are
        // exempted by the identifier check.
        const mixedCase = /[A-Z]/u.test(run.value) && /[a-z]/u.test(run.value);
        // Repeated `/` is Base64 alphabet data; treating it as plain path punctuation can hide opaque bytes.
        const encodedShape = run.escaped === true || /^[0-9A-Fa-f]+$/u.test(run.value) && /[A-Fa-f]/u.test(run.value) ||
          /={1,2}$/u.test(run.value) || /\/{2,}/u.test(run.value) ||
          mixedCase && (/\d|\+/u.test(run.value) || (run.value.match(/[a-z][A-Z]/gu)?.length ?? 0) * 6 >= run.value.length);
        const before = view.text.slice(Math.max(0, run.start - 32), run.start);
        // A digest is one unbroken run; joined chunks or separated hex of digest length are not exempt.
        const digestContext = DIGEST_CONTEXT.exec(before);
        const digest = run.separated !== true && (digestContext ? isContextDigest(digestContext, run.value, bytes.length) :
          DIGEST_HEX.test(run.value) && isDigest(run.value));
        const identified = digest || publicBlocks.some((block) => block.start <= run.start && run.end <= block.end) ||
          B64_ALPHABET.test(run.value) || isSshEd25519PublicKey(before, run.value, bytes) || UUID.test(run.value);
        const recognized = identified || !encodedShape || !run.countable || view.derived === true || isIdentifier(run.value);
        // This view's own text, decoded from a declared escape series: re-reading it as an encoded run is a decode of
        // a decode, so its byte count is not new data. Only the exact strings the view was built from are exempt —
        // a run *inside* one of them, and anything a decompression of it produces, still counts, which is what
        // `derived` would have waived.
        const ownShape = view.ownText?.has(run.value) === true;
        // A container signature is opaque at once, unless the run is a digest or id that happens to start with one.
        if (!identified && OPAQUE_SIGNATURES.some((signature) => signature.every((byte, index) => bytes[index] === byte))) return { reason: 'OPAQUE_EMBEDDED' };
        binary.push(bytes);
        spans.push([run.start, run.end]);
        chunkJoin.push(run.joined === true);
        declaredRun.push(run.declared === true);
        // Each distinct run counts once per message. An escape view repeats its parent's runs, sometimes with one
        // more or one fewer leading character (`\nQUJD…` becomes a newline and `QUJD…`).
        // A run whose bytes are part of an already counted run (the same token split by an escape) counts once too.
        const byteKey = String.fromCharCode(...bytes.subarray(0, 4096));
        const seen = countedValues.has(run.value) || countedValues.has(run.value.slice(1)) ||
          bytes.length >= 8 && countedBytes.some((counted) => counted.includes(byteKey));
        const counted = recognized || seen || ownShape ? 0 : bytes.length;
        if (counted) { countedValues.add(run.value); countedValues.add(run.value.slice(1)); countedBytes.push(byteKey); }
        runCounts.push(counted);
        runIdentified.push(identified);
        // A DER-shaped public PEM body is exempt from the opaque count by its shape, so a stream inside one is
        // never found by counting; the interior read below is the only thing that can find it.
        runPublicBlock.push(publicBlocks.some((block) => block.start <= run.start && run.end <= block.end));
        // What the message itself declares about this run: a digest under a named algorithm, or a certificate body
        // whose DER length header matches. Everything else the opaque count ignores, it ignores by coincidence.
        runDeclared.push(digestContext !== null ||
          publicBlocks.some((block) => block.start <= run.start && run.end <= block.end));
        runDigest.push(digest);
        runValue.push(run.value);
        countable += counted;
        const text = printable(decoded);
        if (text.trim()) printables.push(text);
      }
      if (printables.length) next.push({ name: `${view.name}>BINARY_PRINTABLE`, text: printables.join('\n'), derived: true });
      if (joinedTexts.length) next.push({ name: `${view.name}>JOINED`, text: joinedTexts.join('\n'), derived: view.derived === true });
      if (escapedTexts.length) next.push({ name: `${view.name}>DECLARED_ESCAPES`, text: escapedTexts.join('\n'),
        ownText: new Set(escapedTexts) });
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
        // A declared reconstruction is one complete value, so it is appended after the chunk joins it overlaps:
        // a labelled or joined group must never take the concatenation slot of a chunk sequence that still needs
        // another run to complete its stream.
        const byJoin = (a: number, b: number): number => Number(declaredRun[a]) - Number(declaredRun[b]) || bySpan(a, b);
        for (const index of binary.map((_, i) => i).filter((i) => chunkJoin[i]).sort(byJoin)) {
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
        // A run the opaque count does not count contributes nothing to that count, so a stream inside it is only
        // ever found here: a run shorter than OPAQUE_BYTES that is not a recognized digest, id or public key, a run
        // whose exact byte length is a digest length, and a run inside a DER-shaped public PEM body. Brotli and raw
        // deflate carry no signature to scan for, so every starting offset of such a run is tried. Must-read runs
        // are read first and in full; declared ones after them, within their own window budget.
        // Distinct values only: a list repeats its entries, and reading the same bytes again is work nobody can
        // bill for twice. A run's bytes are its encoded value, so this cannot merge two different reads.
        const seenRuns = new Set<string>();
        const exempt = binary.map((_, index) => index).filter((index) => !covered.has(index) &&
          binary[index]!.length >= MIN_INTERIOR_RUN &&
          (runPublicBlock[index]! || binary[index]!.length < OPAQUE_BYTES || runDigest[index]!) &&
          !seenRuns.has(runValue[index]!) && seenRuns.add(runValue[index]!));
        // Only the shape coincidence obliges this module: a run whose exact byte length is a digest length that
        // nothing declared. The other exempt runs are decode-only by design (declared reconstructions, chunk joins,
        // byte-pair lists) or positively identified, and their residual is a published limit, not a hidden payload.
        const mustRead = exempt.filter((index) => runDigest[index]! && !runDeclared[index]! && !runPublicBlock[index]!);
        /**
         * One run's starting offsets, as bounded matching evidence: the text these attempts decode goes only to the
         * uncertain layers, which are matched but never counted, because a wrong-offset decode is garbage and
         * garbage must not become evidence of its own. `obliged` selects which ceiling applies; an `EXHAUSTED`
         * result is a refusal for a run the opaque count excuses on a length coincidence and a stop for the rest.
         */
        const readInterior = (index: number, obliged: boolean): 'EXHAUSTED' | 'BUDGET' | 'CONTAINER' | null => {
          const bytes = binary[index]!;
          if (obliged) {
            if (interiorBytes + bytes.length > MAX_INTERIOR_BYTES) return 'EXHAUSTED';
            interiorBytes += bytes.length;
          } else if (interiorWindows >= MAX_OPTIONAL_WINDOWS) return 'EXHAUSTED';
          for (let at = 1; at + 1 < bytes.length && (obliged || interiorWindows < MAX_OPTIONAL_WINDOWS); at += INTERIOR_SWEEP + 1) {
            interiorWindows++;
            const interior: Sink = { texts: [], uncertain: [], printables: [], junk: [] };
            // Speculative: no layer below it is followed and no chain is continued, so one window costs one signed
            // scan and one sweep of the two formats that have no signature.
            const result = expand(bytes.subarray(at), interiorBudget, interior, MAX_INFLATE_DEPTH - 1, 0, MAX_INTERIOR_OUTPUT,
              true, INTERIOR_SWEEP);
            if (result === 'BUDGET') return 'BUDGET';
            if (result === 'CONTAINER') return 'CONTAINER';
            if (!result) continue;
            for (const text of [...interior.texts, ...interior.uncertain]) {
              if (interiorText >= MAX_INTERIOR_TEXT) break;
              sink.uncertain.push(text.slice(0, MAX_INTERIOR_TEXT - interiorText));
              interiorText += text.length;
            }
          }
          return null;
        };
        for (const index of mustRead) {
          const status = readInterior(index, true);
          if (status === 'BUDGET') return { reason: 'SENTINEL_BUDGET' };
          if (status === 'CONTAINER') return { reason: 'OPAQUE_EMBEDDED' };
          // Content the opaque count ignores and nothing declared, which this read cannot afford: uninspectable.
          if (status === 'EXHAUSTED') return { reason: 'SENTINEL_BUDGET' };
        }
        // Every other exempt run — a short run, a declared reconstruction, a digest the message named, a public
        // certificate body — is read when the window ceiling allows and is never a reason to refuse.
        for (const index of exempt) if (!mustRead.includes(index)) {
          const status = readInterior(index, false);
          if (status === 'BUDGET') return { reason: 'SENTINEL_BUDGET' };
          if (status === 'CONTAINER') return { reason: 'OPAQUE_EMBEDDED' };
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
  const inflateBudget: DecodeBudget = { inflated: 0, total: MAX_INFLATE_TOTAL };
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
