/**
 * #19 independent egress sentinel: the last check on the exact serialized outbound bytes. It is
 * deliberately NOT the detector stack run twice. It matches known originals and canaries (held only as
 * keyed fingerprints), applies its own small set of high-risk patterns, inspects bounded canonical views
 * (#6 decoded views plus its own escape decoding, iterated to a fixpoint), and asserts the destination.
 * Anything it cannot inspect, any embedded opaque binary, any error, any exhausted budget and any outage
 * is BLOCK. It never returns originals or matched text; on ALLOW it returns a private copy of the bytes.
 */
import { createHmac } from 'node:crypto';
import { normalizeInput } from './normalization.js';

export const SENTINEL_VERSION = 'hylja.egress-sentinel.v1' as const;
export const MAX_MESSAGE_BYTES = 1 << 20;
const MAX_ENTRIES = 4096, MIN_ORIGINAL = 4, MAX_ORIGINAL = 1024, GRAM = 8, MAX_TOKENS = 16;
/** Canonical-view budget: escape/decoding rounds and total text inspected per message. */
const MAX_ROUNDS = 4, MAX_VIEW_UNITS = 8 << 20, MAX_VIEWS = 512;
/** HMAC verifications per message; prefilters make real matches rare, so exceeding this is itself suspicious. */
const MAX_VERIFICATIONS = 20_000;
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
  'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
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
/** Tokens with numeric leading zeros removed (`192.000.002.010` == `192.0.2.10`), and runs of single-character
 * tokens also joined (`o r l a` -> `orla`), so separators cannot split a short value. */
function tokens(folded: string): string[] {
  const raw = (folded.match(TOKEN) ?? []).map((token) => /^\d+$/u.test(token) ? token.replace(/^0+(?=\d)/u, '') : token);
  const out: string[] = [];
  for (let index = 0; index < raw.length;) {
    if (raw[index]!.length === 1) {
      let end = index;
      while (end < raw.length && raw[end]!.length === 1) end++;
      if (end - index > 1) { out.push(raw.slice(index, end).join('')); index = end; continue; }
    }
    out.push(raw[index]!);
    index++;
  }
  return out;
}
function compact(folded: string): string {
  return tokens(folded).join('');
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
  /** Short values: first-token hash -> token count -> last-token hash -> entries. */
  firstTokens: Map<number, Map<number, Map<number, { mac: string; entry: number }[]>>>;
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
      key: Uint8Array.from(key), base: (random[0]! | 1) >>> 0, grams: new Map(), firstTokens: new Map(), entries: [] };
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
        // Short values match whole token sequences only, so `orla` does not fire inside `colorlab`.
        const list = tokens(folded);
        if (!list.length || list.length > MAX_TOKENS) invalid();
        const byCount = nested(known.firstTokens, tokenHash(list[0]!, known.base), () => new Map<number, Map<number, { mac: string; entry: number }[]>>());
        const byLast = nested(byCount, list.length, () => new Map<number, { mac: string; entry: number }[]>());
        nested(byLast, tokenHash(list[list.length - 1]!, known.base), () => [] as { mac: string; entry: number }[])
          .push({ mac: mac(known, list.join('\u0001')), entry: index });
      }
    }
    const handle = Object.freeze(Object.create(null)) as KnownOriginalsHandle;
    registry.set(handle, known);
    return handle;
  } catch { return invalid(); }
}
class BudgetExceeded extends Error {}
function matchKnown(known: Known, text: string, budget: { verifications: number }): Set<number> {
  const hits = new Set<number>();
  const verify = (candidate: string, expected: string): boolean => {
    if (++budget.verifications > MAX_VERIFICATIONS) throw new BudgetExceeded();
    return mac(known, candidate) === expected;
  };
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
  if (known.firstTokens.size) {
    const list = tokens(folded);
    const hashes = list.map((token) => tokenHash(token, known.base));
    for (let index = 0; index < list.length; index++) {
      const byCount = known.firstTokens.get(hashes[index]!);
      if (!byCount) continue;
      for (const [count, byLast] of byCount) {
        if (index + count > list.length) continue;
        const candidates = byLast.get(hashes[index + count - 1]!);
        if (!candidates) continue;
        for (const candidate of candidates) {
          if (!hits.has(candidate.entry) && verify(list.slice(index, index + count).join('\u0001'), candidate.mac)) hits.add(candidate.entry);
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
  // A literal value after a credential-like key; references (`${X}`, `{{x}}`, `<...>`, masks, placeholders) are not values.
  { rule: 'pattern.credential-assignment', pattern: /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["']?(?![$<*{[]|null\b|none\b)[^\s"',;]{4,}/iu },
];
const TEXT_ENCODED_RUN = /[A-Za-z0-9+/_-]{128,}={0,2}|(?:[0-9A-Fa-f]{2}){64,}/gu;
const SHORT_ENCODED_RUN = /(?<![A-Za-z0-9+/_-])(?:[A-Za-z0-9+/_-]{16,127}={0,2}|(?:[0-9A-Fa-f]{2}){8,63})(?![A-Za-z0-9+/=_-])/gu;
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
/**
 * The sentinel's own decode of a short encoded run into printable bytes (others become spaces). Known-value
 * matching ignores separators, so a value scattered between binary bytes (`\0orla\3Synthe\7tica`) is found.
 */
function printableBytes(run: string): string | null {
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
    .replace(/\\u\{([0-9A-Fa-f]{1,6})\}|\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})|\\([0-7]{1,3})|\\([\\/"'bfnrt])/gu,
      (all, cp, u4, x2, octal, simple) => {
        if (cp) { const point = parseInt(cp, 16); return point <= 0x10ffff ? String.fromCodePoint(point) : all; }
        if (u4) return String.fromCharCode(parseInt(u4, 16));
        if (x2) return String.fromCharCode(parseInt(x2, 16));
        if (octal) { const value = parseInt(octal, 8); return value <= 255 ? String.fromCharCode(value) : all; }
        return ({ b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' } as Record<string, string>)[simple] ?? simple;
      })
    .replace(/%u([0-9A-Fa-f]{4})/gu, (_all, u4) => String.fromCharCode(parseInt(u4, 16)))
    .replace(/=\r?\n/gu, '')
    .replace(/=([0-9A-F]{2})/gu, (_all, hex) => String.fromCharCode(parseInt(hex, 16)));
  return out === text ? null : out;
}
interface View { name: string; text: string }
/**
 * All canonical views: each text is decoded by #6 (Base64/percent/hex) and by the escape round, and every
 * resulting view is processed again, to MAX_ROUNDS. Returns a block reason when anything is uninspectable.
 */
function canonicalViews(root: string): { views: View[] } | { reason: string } {
  const views: View[] = [];
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
      if (normalized.views.some((child) => child.form === 'STRINGS')) return { reason: 'OPAQUE_EMBEDDED' };
      const textSpans = normalized.views.filter((child) => child.parent === 0).flatMap((child) => child.occurrences);
      for (const run of view.text.matchAll(TEXT_ENCODED_RUN)) {
        const end = run.index + run[0].length;
        if (!textSpans.some((span) => span.start <= run.index && end <= span.end)) return { reason: 'OPAQUE_EMBEDDED' };
      }
      for (const child of normalized.views.slice(1)) next.push({ name: `${view.name}>${child.encoding}`, text: child.text });
      // Short encoded runs that are not text still get a printable-bytes view for known-value matching.
      for (const run of view.text.matchAll(SHORT_ENCODED_RUN)) {
        const end = run.index + run[0].length;
        if (textSpans.some((span) => span.start <= run.index && end <= span.end)) continue;
        const printable = printableBytes(run[0]);
        if (printable && printable.trim()) views.push({ name: `${view.name}>BINARY_PRINTABLE`, text: printable });
      }
      const unescaped = unescapeOnce(view.text);
      if (unescaped !== null) next.push({ name: `${view.name}>ESCAPES`, text: unescaped });
    }
    queue = next;
    if (round === MAX_ROUNDS && queue.length) return { reason: 'SENTINEL_BUDGET' };
  }
  return { views };
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
    // Copy first: every later step and the released bytes use this private snapshot.
    const bytes = Uint8Array.from(input);
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
    const budget = { verifications: 0 };
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
    }
    if (findings.length) {
      const reasons = findings.map((finding) => finding.kind === 'CANARY' ? 'CANARY_DETECTED' :
        finding.kind === 'KNOWN_ORIGINAL' ? 'KNOWN_ORIGINAL_DETECTED' : 'HIGH_RISK_PATTERN');
      return blocked(reasons, findings);
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
        const copy = Uint8Array.from(chunk);
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
