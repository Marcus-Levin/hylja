/**
 * #6 bounded normalization. Pure and NON-ENFORCING: it never mutates or drops the input. It returns the
 * original text as the root view, bounded decoded views of Base64/percent/hex runs with provenance, a
 * content-type *hint*, and an explicit record of everything it did not inspect. Anything uninspected makes
 * the result PARTIAL, which policy must treat as opaque, never as clean.
 */

export const ENCODINGS = ['ROOT', 'BASE64', 'BASE64URL', 'PERCENT', 'HEX'] as const;
export type Encoding = (typeof ENCODINGS)[number];
export const CONTENT_TYPES = ['JSON', 'XML', 'DOTENV', 'INI', 'URL', 'LOG', 'TEXT', 'BINARY_LIKE'] as const;
export type ContentType = (typeof CONTENT_TYPES)[number];

export interface NormalizationBudget {
  /** Maximum input size in UTF-16 code units (strings) or bytes (byte input). */
  maxInputUnits: number;
  /** Maximum decoding depth below the root view. */
  maxDepth: number;
  /** Maximum total decoded code units across all views. */
  maxDecodedUnits: number;
  /** Maximum number of decoded views. */
  maxViews: number;
}
export const DEFAULT_BUDGET: Readonly<NormalizationBudget> = Object.freeze({
  maxInputUnits: 1 << 20, maxDepth: 3, maxDecodedUnits: 1 << 20, maxViews: 256,
});
const HARD_LIMITS: Readonly<NormalizationBudget> = Object.freeze({
  maxInputUnits: 16 << 20, maxDepth: 8, maxDecodedUnits: 16 << 20, maxViews: 4096,
});
/** Longest single encoded run considered for decoding; longer runs are recorded as uninspected. */
const MAX_RUN = 1 << 16;

export interface NormalizedView {
  id: number;
  /** Parent view id; null for the root. */
  parent: number | null;
  encoding: Encoding;
  depth: number;
  /** UTF-16 span of the encoded run inside the parent view's text; the whole run maps to the decoded view. */
  parentStart: number;
  parentEnd: number;
  text: string;
}
export interface UninspectedSpan {
  viewId: number;
  start: number;
  end: number;
  reason: 'DEPTH_LIMIT' | 'EXPANSION_LIMIT' | 'VIEW_LIMIT' | 'RUN_TOO_LONG';
}
export interface NormalizationResult {
  /** COMPLETE: every candidate run was decoded or proved non-text. PARTIAL: see `uninspected`. */
  status: 'COMPLETE' | 'PARTIAL' | 'FAILURE';
  reasons: readonly string[];
  contentType: ContentType | 'UNKNOWN';
  views: readonly NormalizedView[];
  uninspected: readonly UninspectedSpan[];
  /** Encoded-looking runs that decoded to non-text bytes; the original run stays in its parent view. */
  binaryDecodes: number;
}

function failure(reason: string): NormalizationResult {
  return Object.freeze({ status: 'FAILURE', reasons: Object.freeze([reason]), contentType: 'UNKNOWN',
    views: Object.freeze([]), uninspected: Object.freeze([]), binaryDecodes: 0 });
}
function budgetFrom(raw: unknown): NormalizationBudget | null {
  if (raw === undefined) return { ...DEFAULT_BUDGET };
  if (raw === null || typeof raw !== 'object') return null;
  const result = { ...DEFAULT_BUDGET };
  try {
    for (const key of Object.keys(raw)) {
      if (!(key in DEFAULT_BUDGET)) return null;
      const value: unknown = (raw as Record<string, unknown>)[key];
      const name = key as keyof NormalizationBudget;
      if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > HARD_LIMITS[name]) return null;
      result[name] = value;
    }
  } catch { return null; }
  return result;
}

/* ---------- Decoders (fatal: invalid bytes are never replaced) ---------- */

const utf8 = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
/** Text a detector can read: valid UTF-8 with no controls other than tab/newline/carriage return. */
function asText(bytes: Uint8Array): string | null {
  let text: string;
  try { text = utf8.decode(bytes); } catch { return null; }
  return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(text) || !text.length ? null : text;
}
function decodeBase64(run: string, url: boolean): Uint8Array | null {
  const standard = url ? run.replace(/-/gu, '+').replace(/_/gu, '/') : run;
  const padded = standard.padEnd(Math.ceil(standard.length / 4) * 4, '=');
  if (padded.length % 4 !== 0 || /=[^=]/u.test(padded) || /={3,}$/u.test(padded)) return null;
  const bytes: number[] = [];
  let buffer = 0, bits = 0;
  for (const char of padded) {
    if (char === '=') break;
    const value = BASE64_ALPHABET.indexOf(char);
    if (value < 0) return null;
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) { bits -= 8; bytes.push((buffer >> bits) & 0xff); }
  }
  return Uint8Array.from(bytes);
}
function decodeHex(run: string): Uint8Array {
  const bytes = new Uint8Array(run.length / 2);
  for (let index = 0; index < bytes.length; index++) bytes[index] = parseInt(run.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}
function decodePercent(run: string): Uint8Array {
  const bytes: number[] = [];
  for (let index = 0; index < run.length;) {
    if (run[index] === '%' && /^[0-9A-Fa-f]{2}$/u.test(run.slice(index + 1, index + 3))) {
      bytes.push(parseInt(run.slice(index + 1, index + 3), 16));
      index += 3;
    } else {
      // Non-escaped characters pass through as their UTF-8 bytes.
      const point = run.codePointAt(index)!;
      const char = String.fromCodePoint(point);
      for (const byte of encoder.encode(char)) bytes.push(byte);
      index += char.length;
    }
  }
  return Uint8Array.from(bytes);
}

// Bounded run patterns; lookarounds make each run maximal so one run is considered once.
const BASE64_RUN = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])/gu;
const BASE64URL_RUN = /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[_-])[A-Za-z0-9_-]{16,}={0,2}(?![A-Za-z0-9_=-])/gu;
const HEX_RUN = /(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])/gu;
// Percent runs: whole whitespace/quote-delimited tokens that contain an escape (linear: no backtracking).
const TOKEN_RUN = /[^\s"'<>`]+/gu;
const PERCENT_ESCAPE = /%[0-9A-Fa-f]{2}/u;

interface Run { start: number; end: number; encoding: Exclude<Encoding, 'ROOT'> }
function runs(text: string): Run[] {
  const found: Run[] = [];
  for (const match of text.matchAll(TOKEN_RUN)) {
    if (PERCENT_ESCAPE.test(match[0])) found.push({ start: match.index, end: match.index + match[0].length, encoding: 'PERCENT' });
  }
  for (const [pattern, encoding] of [[HEX_RUN, 'HEX'], [BASE64_RUN, 'BASE64'], [BASE64URL_RUN, 'BASE64URL']] as const) {
    for (const match of text.matchAll(pattern)) {
      found.push({ start: match.index, end: match.index + match[0].length, encoding });
    }
  }
  return found.sort((a, b) => a.start - b.start || a.end - b.end);
}
function decodeRun(text: string, encoding: Run['encoding']): Uint8Array | null {
  switch (encoding) {
    case 'HEX': return decodeHex(text);
    case 'PERCENT': return decodePercent(text);
    case 'BASE64': return decodeBase64(text, false);
    case 'BASE64URL': return decodeBase64(text, true);
  }
}

/* ---------- Content-type hint (parsers verify; this never authorizes anything) ---------- */

export function sniffContentType(text: string): ContentType {
  const sample = text.slice(0, 1 << 16);
  const trimmed = sample.trim();
  if (!trimmed) return 'TEXT';
  const controls = (sample.match(/[\u0000-\u0008\u000e-\u001f]/gu) ?? []).length;
  if (controls > sample.length / 100) return 'BINARY_LIKE';
  if (/^[{[]/u.test(trimmed) && /[}\]]$/u.test(text.trim())) {
    if (text.length <= 1 << 20) {
      try { JSON.parse(text); return 'JSON'; } catch { /* fall through */ }
    }
  }
  if (/^<(?:\?xml|[A-Za-z_][\w.-]*[\s>/])/u.test(trimmed)) return 'XML';
  const lines = sample.split(/\r?\n/u).filter((line) => line.trim() && !/^\s*[#;]/u.test(line));
  if (/^[a-z][a-z0-9+.-]*:\/\/\S+$/iu.test(trimmed)) return 'URL';
  const assignments = lines.filter((line) => /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=/u.test(line)).length;
  const sections = lines.filter((line) => /^\s*\[[^\]\n]+\]\s*$/u.test(line)).length;
  const keyValues = lines.filter((line) => /^\s*[^=\s][^=]*=/u.test(line)).length;
  if (sections && sections + keyValues >= lines.length * 0.8) return 'INI';
  if (lines.length && assignments >= lines.length * 0.8) return 'DOTENV';
  const stamped = lines.filter((line) => /^\s*\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/u.test(line)).length;
  if (lines.length && stamped >= lines.length * 0.5) return 'LOG';
  return 'TEXT';
}

/* ---------- Normalization ---------- */

/**
 * Build bounded decoded views. String input is used as-is (lone surrogates are a FAILURE); byte input
 * must be valid UTF-8 or the result is FAILURE with no text. A FAILURE or PARTIAL result is never clean:
 * the caller keeps the original and policy treats it conservatively.
 */
export function normalizeInput(input: unknown, budget?: unknown): NormalizationResult {
  const limits = budgetFrom(budget);
  if (!limits) return failure('INVALID_BUDGET');
  let root: string;
  if (typeof input === 'string') {
    if (input.length > limits.maxInputUnits) return failure('INPUT_TOO_LARGE');
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(input)) return failure('INVALID_TEXT');
    root = input;
  } else if (input instanceof Uint8Array) {
    if (input.length > limits.maxInputUnits) return failure('INPUT_TOO_LARGE');
    try { root = utf8.decode(input); } catch { return failure('INVALID_UTF8'); }
  } else return failure('INVALID_INPUT');

  const views: NormalizedView[] = [Object.freeze({ id: 0, parent: null, encoding: 'ROOT', depth: 0,
    parentStart: 0, parentEnd: root.length, text: root })];
  const uninspected: UninspectedSpan[] = [];
  const reasons = new Set<string>();
  let decodedUnits = 0;
  let binaryDecodes = 0;
  for (let cursor = 0; cursor < views.length; cursor++) {
    const view = views[cursor]!;
    const seen = new Set<string>();
    for (const run of runs(view.text)) {
      const key = `${run.start}:${run.end}`;
      const record = (reason: UninspectedSpan['reason']): void => {
        uninspected.push(Object.freeze({ viewId: view.id, start: run.start, end: run.end, reason }));
        reasons.add(reason);
      };
      if (run.end - run.start > MAX_RUN) { if (!seen.has(key)) record('RUN_TOO_LONG'); seen.add(key); continue; }
      const bytes = decodeRun(view.text.slice(run.start, run.end), run.encoding);
      const text = bytes && asText(bytes);
      if (!text || text === view.text.slice(run.start, run.end)) {
        if (bytes && !text) binaryDecodes++;
        continue;
      }
      // The same span may be valid under several encodings (e.g. hex digits are also Base64); keep each text view.
      if (view.depth + 1 > limits.maxDepth) { record('DEPTH_LIMIT'); continue; }
      if (views.length >= limits.maxViews + 1) { record('VIEW_LIMIT'); continue; }
      if (decodedUnits + text.length > limits.maxDecodedUnits) { record('EXPANSION_LIMIT'); continue; }
      decodedUnits += text.length;
      views.push(Object.freeze({ id: views.length, parent: view.id, encoding: run.encoding, depth: view.depth + 1,
        parentStart: run.start, parentEnd: run.end, text }));
    }
  }
  return Object.freeze({
    status: uninspected.length ? 'PARTIAL' : 'COMPLETE', reasons: Object.freeze([...reasons].sort()),
    contentType: sniffContentType(root), views: Object.freeze(views), uninspected: Object.freeze(uninspected),
    binaryDecodes,
  });
}

/* ---------- Detection fold: compatibility-normalized text with an offset map ---------- */

export interface DetectionFold {
  text: string;
  /** For each folded code unit, the start and end of its source cluster in the input. */
  origin: readonly number[];
  originEnd: readonly number[];
}
const DASHES = /[‐-―−﹘﹣－]/gu;
/**
 * NFKC per grapheme-ish cluster (a base plus its marks), with default-ignorable characters (zero-width,
 * bidi controls, variation selectors, soft hyphen) removed and Unicode dashes mapped to `-`. Detectors
 * match on `text` and map spans back with `origin`/`originEnd`, so the input is never rewritten.
 */
export function foldForDetection(input: string): DetectionFold {
  if (typeof input !== 'string') throw new TypeError('Invalid fold input');
  let text = '';
  const origin: number[] = [];
  const originEnd: number[] = [];
  for (const match of input.matchAll(/\P{M}\p{M}*|\p{M}+/gsu)) {
    const piece = match[0].normalize('NFKC').replace(/\p{Default_Ignorable_Code_Point}/gu, '').replace(DASHES, '-');
    for (let unit = 0; unit < piece.length; unit++) {
      origin.push(match.index);
      originEnd.push(match.index + match[0].length);
    }
    text += piece;
  }
  return Object.freeze({ text, origin: Object.freeze(origin), originEnd: Object.freeze(originEnd) });
}
/** Map a folded span back to the smallest covering input span. */
export function mapFoldedSpan(fold: DetectionFold, start: number, end: number): { start: number; end: number } {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end <= start || end > fold.text.length) {
    throw new RangeError('Invalid folded span');
  }
  return { start: fold.origin[start]!, end: fold.originEnd[end - 1]! };
}
