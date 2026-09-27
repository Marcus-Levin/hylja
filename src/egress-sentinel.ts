/**
 * #19 independent egress sentinel: the last check on the exact serialized outbound bytes. It is
 * deliberately NOT the detector stack run twice. It matches known originals and canaries (held only as
 * keyed fingerprints), applies its own small set of high-risk patterns, inspects bounded canonical views
 * (#6 decoded views plus its own escape decoding), and asserts the destination. Anything it cannot inspect,
 * any error and any outage is BLOCK. It never returns payload bytes, originals or matched text.
 */
import { createHmac } from 'node:crypto';
import { normalizeInput } from './normalization.js';

export const SENTINEL_VERSION = 'hylja.egress-sentinel.v1' as const;
export const MAX_MESSAGE_BYTES = 1 << 20;
const MAX_ENTRIES = 4096, MIN_ORIGINAL = 4, MAX_ORIGINAL = 1024, GRAM = 8, MAX_TOKENS = 16;

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
  /** Canonical view path where it was found, e.g. `ROOT`, `BASE64`, `ROOT>ESCAPES`. */
  view: string;
}
export interface SentinelResult {
  decision: 'ALLOW' | 'BLOCK';
  reasons: readonly string[];
  findings: readonly SentinelFinding[];
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
  known?: KnownOriginalsHandle;
}

/* ---------- Folding for matching ---------- */

/** NFKC, lower case, default-ignorables removed: `ＯＲＬＡ`, `orla` and `or<ZWSP>la` compare equal. */
function fold(text: string): string {
  return text.normalize('NFKC').toLowerCase().replace(/\p{Default_Ignorable_Code_Point}/gu, '');
}
const ALNUM = /[\p{L}\p{N}]/u;
function compact(folded: string): string {
  let out = '';
  for (const char of folded) if (ALNUM.test(char)) out += char;
  return out;
}
const TOKEN = /[\p{L}\p{N}]+/gu;

/* ---------- Known originals (keyed fingerprints only) ---------- */

declare const knownBrand: unique symbol;
export interface KnownOriginalsHandle { readonly [knownBrand]: true }
interface Known {
  scope: SentinelScope;
  key: Uint8Array;
  base: number;
  /** Keyed rolling hash of the first GRAM compact characters -> entries with that prefix. */
  grams: Map<number, { length: number; mac: string; entry: number }[]>;
  /** Short originals: keyed hash of the first token -> token-sequence fingerprints. */
  firstTokens: Map<number, { count: number; mac: string; entry: number }[]>;
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
  for (let index = 0; index < token.length; index++) hash = (Math.imul(hash ^ token.charCodeAt(index), 0x01000193) >>> 0);
  return hash;
}
function label(value: unknown, limit = 256): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

/**
 * Trusted configuration: register planted/known originals and canaries for one tenant and project. The
 * handle keeps keyed fingerprints and a keyed rolling-hash prefilter, not the values. `key` is a dedicated
 * sentinel key of at least 32 bytes; errors never include a value.
 */
export function createKnownOriginals(scope: SentinelScope, key: Uint8Array, entries: readonly KnownEntry[]): KnownOriginalsHandle {
  const invalid = (): never => { throw new TypeError('Invalid known-originals configuration'); };
  try {
    if (!scope || !label(scope.tenantRef) || !label(scope.projectRef) || !(key instanceof Uint8Array) || !(key.length >= 32) ||
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
        // Long values match on separator-stripped text, so `O-r-l-a S y n` style splitting does not evade them.
        const hash = gramHash(packed, 0, known.base);
        const list = known.grams.get(hash) ?? [];
        list.push({ length: packed.length, mac: mac(known, packed), entry: index });
        known.grams.set(hash, list);
      } else {
        // Short values match whole token sequences only, so `orla` does not fire inside `colorlab`.
        const tokens = folded.match(TOKEN) ?? [];
        if (!tokens.length || tokens.length > MAX_TOKENS) invalid();
        const hash = tokenHash(tokens[0]!, known.base);
        const list = known.firstTokens.get(hash) ?? [];
        list.push({ count: tokens.length, mac: mac(known, tokens.join('\u0001')), entry: index });
        known.firstTokens.set(hash, list);
      }
    }
    const handle = Object.freeze(Object.create(null)) as KnownOriginalsHandle;
    registry.set(handle, known);
    return handle;
  } catch { return invalid(); }
}
function matchKnown(known: Known, text: string): Set<number> {
  const hits = new Set<number>();
  const folded = fold(text);
  if (known.grams.size) {
    const packed = compact(folded);
    if (packed.length >= GRAM) {
      // Rolling window: remove the leading character's contribution, then add the next one.
      let power = 1;
      for (let index = 1; index < GRAM; index++) power = Math.imul(power, known.base) >>> 0;
      let hash = gramHash(packed, 0, known.base);
      for (let start = 0; start + GRAM <= packed.length; start++) {
        if (start > 0) {
          hash = (hash - Math.imul(packed.charCodeAt(start - 1), power)) >>> 0;
          hash = (Math.imul(hash, known.base) + packed.charCodeAt(start + GRAM - 1)) >>> 0;
        }
        const candidates = known.grams.get(hash);
        if (!candidates) continue;
        for (const candidate of candidates) {
          if (!hits.has(candidate.entry) && start + candidate.length <= packed.length &&
            mac(known, packed.slice(start, start + candidate.length)) === candidate.mac) hits.add(candidate.entry);
        }
      }
    }
  }
  if (known.firstTokens.size) {
    const tokens = folded.match(TOKEN) ?? [];
    for (let index = 0; index < tokens.length; index++) {
      const candidates = known.firstTokens.get(tokenHash(tokens[index]!, known.base));
      if (!candidates) continue;
      for (const candidate of candidates) {
        if (!hits.has(candidate.entry) && index + candidate.count <= tokens.length &&
          mac(known, tokens.slice(index, index + candidate.count).join('\u0001')) === candidate.mac) hits.add(candidate.entry);
      }
    }
  }
  return hits;
}

/* ---------- Independent high-risk patterns (separate from the #8 detector implementation) ---------- */

const PATTERNS: readonly { rule: string; pattern: RegExp }[] = [
  { rule: 'pattern.private-key-block', pattern: /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----|---- BEGIN SSH2 [A-Z ]{0,20}PRIVATE KEY ----|PuTTY-User-Key-File-\d/u },
  { rule: 'pattern.cloud-access-key', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/u },
  { rule: 'pattern.source-control-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bglpat-[A-Za-z0-9_-]{20,}/u },
  { rule: 'pattern.chat-token', pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}/u },
  { rule: 'pattern.payment-key', pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}/u },
  { rule: 'pattern.google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}/u },
  { rule: 'pattern.jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\./u },
  { rule: 'pattern.authorization-credential', pattern: /\bauthorization\s*[:=]\s*["']?(?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}/iu },
];

/* ---------- Canonical views ---------- */

const NAMED_ENTITIES: Readonly<Record<string, string>> = Object.freeze({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' });
/** The sentinel's own escape decoding: JSON/JS `\uXXXX`, `\xNN`, simple backslash escapes and HTML entities. */
function unescapeView(text: string): string | null {
  if (!/\\[ux"'\\/bfnrt]|&#?\w{1,8};/u.test(text)) return null;
  return text
    .replace(/\\u\{([0-9A-Fa-f]{1,6})\}|\\u([0-9A-Fa-f]{4})|\\x([0-9A-Fa-f]{2})|\\([\\/"'bfnrt])/gu, (_all, cp, u4, x2, simple) => {
      if (cp) { const point = parseInt(cp, 16); return point <= 0x10ffff ? String.fromCodePoint(point) : _all; }
      if (u4) return String.fromCharCode(parseInt(u4, 16));
      if (x2) return String.fromCharCode(parseInt(x2, 16));
      return ({ b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' } as Record<string, string>)[simple] ?? simple;
    })
    .replace(/&#x([0-9A-Fa-f]{1,6});|&#(\d{1,7});|&(\w{1,8});/gu, (all, hex, dec, name) => {
      const point = hex ? parseInt(hex, 16) : dec ? Number(dec) : -1;
      if (point >= 0) return point <= 0x10ffff ? String.fromCodePoint(point) : all;
      return NAMED_ENTITIES[name as string] ?? all;
    });
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
function sameDestination(a: unknown, b: unknown): boolean {
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  const x = a as Record<string, unknown>, y = b as Record<string, unknown>;
  return label(x.id) && label(x.profileDigest) && x.id === y.id && x.profileDigest === y.profileDigest;
}

/**
 * Check the exact bytes an adapter is about to send. ALLOW only when the bytes are valid UTF-8, fully
 * inspectable within the #6 budget, sent to the authorized destination/profile, and contain no known
 * original, canary or high-risk pattern in any canonical view. Everything else is BLOCK.
 */
export function checkEgress(check: EgressCheck): SentinelResult {
  try {
    const { bytes, scope, destination, authorized, known: handle } = check;
    if (!(bytes instanceof Uint8Array) || !scope || typeof scope !== 'object') return blocked(['INVALID_CHECK']);
    if (bytes.length > MAX_MESSAGE_BYTES) return blocked(['MESSAGE_TOO_LARGE']);
    if (!sameDestination(destination, authorized)) return blocked(['DESTINATION_MISMATCH']);
    let known: Known | undefined;
    if (handle !== undefined) {
      known = handle && typeof handle === 'object' ? registry.get(handle) : undefined;
      if (!known) return blocked(['KNOWN_ORIGINALS_INVALID']);
      if (known.scope.tenantRef !== scope.tenantRef || known.scope.projectRef !== scope.projectRef) return blocked(['KNOWN_ORIGINALS_SCOPE_MISMATCH']);
    }
    let root: string;
    try { root = utf8.decode(bytes); } catch { return blocked(['OPAQUE_CONTENT']); }
    const normalized = normalizeInput(root);
    // Content the sentinel cannot fully inspect is never presumed clean.
    if (normalized.status !== 'COMPLETE') return blocked(['UNINSPECTED_CONTENT', ...normalized.reasons.map((r) => `NORMALIZATION_${r}`)]);
    const views: { name: string; text: string }[] = [];
    for (const view of normalized.views) {
      const path: string[] = [];
      for (let at: typeof view | undefined = view; at; at = at.parent === null ? undefined : normalized.views[at.parent]) path.unshift(at.encoding);
      const name = path.join('>');
      views.push({ name, text: view.text });
      const unescaped = unescapeView(view.text);
      if (unescaped !== null) {
        views.push({ name: `${name}>ESCAPES`, text: unescaped });
        // Escapes can hide an encoding, and an encoding can hide escapes: decode the unescaped text once more.
        const nested = normalizeInput(unescaped);
        if (nested.status !== 'COMPLETE') return blocked(['UNINSPECTED_CONTENT']);
        nested.views.slice(1).forEach((inner) => views.push({ name: `${name}>ESCAPES>${inner.encoding}`, text: inner.text }));
      }
    }
    const findings: SentinelFinding[] = [];
    const seen = new Set<string>();
    for (const view of views) {
      if (known) {
        for (const index of matchKnown(known, view.text)) {
          const entry = known.entries[index]!;
          const key = `${entry.ref}|${view.name}`;
          if (!seen.has(key)) { seen.add(key); findings.push({ kind: entry.kind === 'CANARY' ? 'CANARY' : 'KNOWN_ORIGINAL', rule: entry.ref, view: view.name }); }
        }
      }
      const folded = fold(view.text);
      for (const { rule, pattern } of PATTERNS) {
        const key = `${rule}|${view.name}`;
        if (!seen.has(key) && (pattern.test(view.text) || pattern.test(folded))) { seen.add(key); findings.push({ kind: 'PATTERN', rule, view: view.name }); }
      }
    }
    if (findings.length) {
      const reasons = findings.map((finding) => finding.kind === 'CANARY' ? 'CANARY_DETECTED' :
        finding.kind === 'KNOWN_ORIGINAL' ? 'KNOWN_ORIGINAL_DETECTED' : 'HIGH_RISK_PATTERN');
      return blocked(reasons, findings);
    }
    return Object.freeze({ decision: 'ALLOW', reasons: Object.freeze([]), findings: Object.freeze([]) });
  } catch {
    // An internal failure is an outage: restrictive, never a pass.
    return blocked(['SENTINEL_ERROR']);
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
  let size = 0, overflow = false, ended = false;
  return Object.freeze({
    push(chunk: Uint8Array) {
      if (ended || overflow || !(chunk instanceof Uint8Array)) { overflow = true; return { accepted: false }; }
      size += chunk.length;
      if (size > maxBytes) { overflow = true; chunks.length = 0; return { accepted: false }; }
      chunks.push(Uint8Array.from(chunk));
      return { accepted: true };
    },
    end() {
      if (ended) return { result: blocked(['STREAM_ALREADY_ENDED']) };
      ended = true;
      if (overflow) return { result: blocked(['STREAM_OVERFLOW']) };
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      chunks.length = 0;
      const result = checkEgress({ ...check, bytes });
      return result.decision === 'ALLOW' ? { result, release: bytes } : { result };
    },
  });
}
