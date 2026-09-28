/**
 * #6 bounded normalization. Pure and NON-ENFORCING: it never mutates or drops the input. It returns the
 * original text as the root view, bounded decoded views of Base64/percent/hex runs with provenance, a
 * content-type *hint*, and an explicit record of everything it did not inspect. Anything uninspected makes
 * the result PARTIAL, which policy must treat as opaque, never as clean.
 *
 * Scope limits (not decoded here, owned by #7 parsers or #8 detectors): JSON/JS `\uXXXX`/`\xNN` escapes,
 * colon-separated hex, HTML entities, `+`-as-space form encoding, quoted-printable, compression and archives.
 * Minimum candidate lengths: Base64 12 characters, hex 16 digits (8 bytes). Residual limits: printable runs
 * shorter than 8 characters inside binary, line-wrapped Base64 with lines under 16 characters, UTF-32.
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
  /** Maximum total encoded code units fed to decoders, including runs that decode to nothing useful. */
  maxDecodeWork: number;
}
export const DEFAULT_BUDGET: Readonly<NormalizationBudget> = Object.freeze({
  maxInputUnits: 1 << 20, maxDepth: 3, maxDecodedUnits: 1 << 20, maxViews: 256, maxDecodeWork: 8 << 20,
});
const HARD_LIMITS: Readonly<NormalizationBudget> = Object.freeze({
  maxInputUnits: 16 << 20, maxDepth: 8, maxDecodedUnits: 16 << 20, maxViews: 4096, maxDecodeWork: 128 << 20,
});
/** Longest single encoded run considered for decoding; longer runs are recorded as uninspected. */
const MAX_RUN = 1 << 16;
/** Disjoint parent spans recorded on one view for identical decoded text before a new view is created. */
const MAX_OCCURRENCES = 1024;
/** Work units charged per attempted decode on top of its length (decoding and text checks have fixed costs). */
const DECODE_OVERHEAD = 64;
/** Uninspected spans kept before collapsing into one truncation reason. */
const MAX_UNINSPECTED = 1024;
/** Printable runs shorter than this inside binary decodes are noise, not text. */
const MIN_STRING = 8;

export interface NormalizedView {
  id: number;
  /** Parent view id; null for the root. */
  parent: number | null;
  encoding: Encoding;
  /** TEXT: the decode is text. STRINGS: printable runs extracted from a binary decode, joined by newlines. */
  form: 'TEXT' | 'STRINGS';
  depth: number;
  /** UTF-16 span of the (first) encoded run inside the parent view's text; the whole run maps to the view. */
  parentStart: number;
  parentEnd: number;
  /** Every disjoint parent span whose run decoded to this same text, including the first. */
  occurrences: readonly { start: number; end: number }[];
  text: string;
}
export interface UninspectedSpan {
  viewId: number;
  start: number;
  end: number;
  reason: 'DEPTH_LIMIT' | 'EXPANSION_LIMIT' | 'VIEW_LIMIT' | 'RUN_TOO_LONG' | 'WORK_LIMIT';
}
export interface NormalizationResult {
  /**
   * COMPLETE: no budget was exceeded, and every candidate run (at the minimum lengths above) was decoded to
   * a TEXT or STRINGS view or held no printable run. COMPLETE is not "clean": out-of-scope encodings remain
   * only in their parent view, where detectors still scan them. PARTIAL: see `uninspected`/`reasons`.
   */
  status: 'COMPLETE' | 'PARTIAL' | 'FAILURE';
  reasons: readonly string[];
  contentType: ContentType | 'UNKNOWN';
  views: readonly NormalizedView[];
  uninspected: readonly UninspectedSpan[];
  /** Encoded-looking runs that decoded to bytes without any printable run; the run stays in its parent. */
  binaryDecodes: number;
}

type MutableView = Omit<NormalizedView, 'occurrences'> & { occurrences: { start: number; end: number }[] };
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
      if (!Object.hasOwn(DEFAULT_BUDGET, key)) return null;
      const value: unknown = (raw as Record<string, unknown>)[key];
      const name = key as keyof NormalizationBudget;
      if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > HARD_LIMITS[name]) return null;
      result[name] = value;
    }
  } catch { return null; }
  return result;
}

/* ---------- Decoders (strict: invalid bytes are never silently replaced in TEXT views) ---------- */

const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const lenient = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true });
const utf16 = new TextDecoder('utf-16le', { fatal: false, ignoreBOM: true });
const utf16be = new TextDecoder('utf-16be', { fatal: false, ignoreBOM: true });
const ASCII_RUN = /[\u0020-\u007e\t]{8,}/gu;
const encoder = new TextEncoder();
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;
const NOT_PRINTABLE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f�]+/u;
const BASE64_VALUES = new Int16Array(128).fill(-1);
'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.split('').forEach((char, index) => {
  BASE64_VALUES[char.charCodeAt(0)] = index;
});

/** Strict text: UTF-8, or UTF-16LE when every other byte is mostly zero, with no controls. */
function textOf(bytes: Uint8Array): string | null {
  if (!bytes.length) return null;
  try {
    const text = utf8.decode(bytes);
    if (!CONTROL.test(text)) return text;
  } catch { /* not strict UTF-8 */ }
  if (bytes.length >= 2 * MIN_STRING && bytes.length % 2 === 0) {
    let zeros = 0;
    for (let index = 1; index < bytes.length; index += 2) if (bytes[index] === 0) zeros++;
    if (zeros >= bytes.length / 2 * 0.8) {
      const text = utf16.decode(bytes);
      if (!CONTROL.test(text) && !text.includes('\ufffd')) return text;
    }
  }
  return null;
}
/** Printable runs (>= MIN_STRING) from lenient UTF-8, plus ASCII runs from UTF-16LE/BE at both parities. */
function stringsOf(bytes: Uint8Array): string[] {
  const strings = lenient.decode(bytes).split(NOT_PRINTABLE).filter((piece) => piece.length >= MIN_STRING);
  if (bytes.length >= 2 * MIN_STRING) {
    for (const decoder of [utf16, utf16be]) {
      for (const offset of [0, 1]) {
        const view = bytes.subarray(offset, offset + ((bytes.length - offset) & ~1));
        for (const match of decoder.decode(view).matchAll(ASCII_RUN)) strings.push(match[0]);
      }
    }
  }
  return strings;
}
function decodeBase64(run: string, url: boolean, skip = 0): Uint8Array | null {
  const body = run.replace(/[\r\n \t]/gu, '').replace(/=+$/u, '').slice(skip);
  const usable = body.length - (body.length % 4 === 1 ? 1 : 0);
  const bytes = new Uint8Array(Math.floor(usable * 3 / 4));
  let buffer = 0, bits = 0, out = 0;
  for (let index = 0; index < usable; index++) {
    let code = body.charCodeAt(index);
    if (url) code = code === 45 ? 43 : code === 95 ? 47 : code;
    const value = code < 128 ? BASE64_VALUES[code]! : -1;
    if (value < 0) return null;
    buffer = ((buffer << 6) | value) & 0xffffff;
    bits += 6;
    if (bits >= 8) { bits -= 8; bytes[out++] = (buffer >> bits) & 0xff; }
  }
  return bytes.subarray(0, out);
}
function decodeHex(run: string): Uint8Array {
  const bytes = new Uint8Array(run.length >> 1);
  for (let index = 0; index < bytes.length; index++) bytes[index] = parseInt(run.substr(index * 2, 2), 16);
  return bytes;
}
function hexValue(code: number): number {
  return code >= 48 && code <= 57 ? code - 48 : code >= 65 && code <= 70 ? code - 55 : code >= 97 && code <= 102 ? code - 87 : -1;
}
function decodePercent(run: string): Uint8Array {
  const bytes: number[] = [];
  for (let index = 0; index < run.length;) {
    const code = run.charCodeAt(index);
    if (code === 37 && index + 2 < run.length) {
      const high = hexValue(run.charCodeAt(index + 1)), low = hexValue(run.charCodeAt(index + 2));
      if (high >= 0 && low >= 0) { bytes.push(high * 16 + low); index += 3; continue; }
    }
    if (code < 128) { bytes.push(code); index++; continue; }
    const char = String.fromCodePoint(run.codePointAt(index)!);
    for (const byte of encoder.encode(char)) bytes.push(byte);
    index += char.length;
  }
  return Uint8Array.from(bytes);
}

/* ---------- Candidate runs ---------- */

// A Base64 run may end at its padding even when another run follows (concatenated segments).
// Quantifiers are bounded (MAX_RUN + 1) so regex backtracking cannot exhaust the stack; longer runs are
// found by a linear scan and recorded as RUN_TOO_LONG.
const BASE64_RUN = /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,65537}(?:={1,2}|(?![A-Za-z0-9+/=]))/gu;
// Line-wrapped (MIME/PEM-style) Base64: two or more full lines joined into one logical run.
const BASE64_WRAPPED = /(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{16,4096}\r?\n[ \t]*){1,4096}[A-Za-z0-9+/]{4,4096}={0,2}(?![A-Za-z0-9+/=])/gu;
const BASE64URL_RUN = /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]{0,65537}[_-])[A-Za-z0-9_-]{12,65537}={0,2}(?![A-Za-z0-9_=-])/gu;
const HEX_RUN = /(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,65537}(?![0-9A-Fa-f])/gu;
// Percent runs: whole whitespace/quote-delimited tokens that contain an escape (linear: no backtracking).
const TOKEN_RUN = /[^\s"'<>`]{1,65537}/gu;
const PERCENT_ESCAPE = /%[0-9A-Fa-f]{2}/u;

interface Run { start: number; end: number; encoding: Exclude<Encoding, 'ROOT'>; decodes: (() => Uint8Array | null)[] }
interface Readable { text: string; form: NormalizedView['form'] }
/**
 * Decode a run. When the first (aligned) decode is text, that is the view. Otherwise the view is the
 * de-duplicated union of text and printable strings from *every* alternative decode, so a marker at one
 * alignment is never discarded in favour of a longer benign string at another.
 */
function best(decodes: readonly (() => Uint8Array | null)[]): { bytes: Uint8Array | null; found: Readable | null } {
  const first = decodes[0]!();
  const text = first && textOf(first);
  if (text) return { bytes: first, found: { text, form: 'TEXT' } };
  const pieces = new Set<string>();
  let bytes = first;
  decodes.forEach((decode, index) => {
    const decoded = index === 0 ? first : decode();
    if (!decoded) return;
    bytes ??= decoded;
    const whole = index === 0 ? null : textOf(decoded);
    if (whole) pieces.add(whole);
    else for (const piece of stringsOf(decoded)) pieces.add(piece);
  });
  return { bytes, found: pieces.size ? { text: [...pieces].join('\n'), form: 'STRINGS' } : null };
}
/** Candidate runs, produced lazily so a budget stop does not first materialize every run of a view. */
function* runs(text: string): Generator<Run> {
  for (const match of text.matchAll(TOKEN_RUN)) {
    if (PERCENT_ESCAPE.test(match[0])) {
      const value = match[0];
      yield { start: match.index, end: match.index + value.length, encoding: 'PERCENT', decodes: [() => decodePercent(value)] };
    }
  }
  for (const match of text.matchAll(HEX_RUN)) {
    const value = match[0], start = match.index, end = start + value.length;
    if (value.length % 2 === 0) yield { start, end, encoding: 'HEX', decodes: [() => decodeHex(value)] };
    else {
      // Odd length: a stray nibble at either end; the second parity only runs when the first is not text.
      yield { start, end, encoding: 'HEX', decodes: [() => decodeHex(value.slice(1)), () => decodeHex(value.slice(0, -1))] };
    }
  }
  // A prefix glued to Base64 (`token<b64>`, a URL path) misaligns it; decoding at offsets 0-3 realigns
  // any prefix length, and the prefix garbage falls out of STRINGS extraction.
  for (const [pattern, url] of [[BASE64_RUN, false], [BASE64_WRAPPED, false], [BASE64URL_RUN, true]] as const) {
    for (const match of text.matchAll(pattern)) {
      const value = match[0];
      yield { start: match.index, end: match.index + value.length, encoding: url ? 'BASE64URL' : 'BASE64',
        decodes: [0, 1, 2, 3].map((skip) => () => decodeBase64(value, url, skip)) };
    }
  }
}

/* ---------- Content-type hint (parsers verify; this never authorizes or skips anything) ---------- */

/** A hint only. Only JSON is verified by parsing. `BINARY_LIKE` never means "skip text detection". */
export function sniffContentType(text: string): ContentType {
  const sample = text.slice(0, 1 << 16);
  const trimmed = sample.trim();
  if (!trimmed) return 'TEXT';
  // ESC is common in ANSI-coloured logs and is not counted as binary.
  const controls = (sample.match(/[\u0000-\u0008\u000e-\u001a\u001c-\u001f]/gu) ?? []).length;
  if (controls > sample.length / 100) return 'BINARY_LIKE';
  if (/^[{[]/u.test(trimmed) && /[}\]]$/u.test(text.trim()) && text.length <= 1 << 20) {
    try { JSON.parse(text); return 'JSON'; } catch { /* fall through */ }
  }
  if (/^<(?:\?xml|[A-Za-z_][\w.-]*[\s>/])/u.test(trimmed) && /<\/[A-Za-z_]|\/>/u.test(sample)) return 'XML';
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
 * must be valid UTF-8 (a BOM is kept) or the result is FAILURE with no text. FAILURE or PARTIAL is never
 * clean: the caller keeps the original and policy treats it conservatively.
 */
export function normalizeInput(input: unknown, budget?: unknown): NormalizationResult {
  // Contract: FAILURE or PARTIAL, never a throw (e.g. an engine stack limit on a pathological input).
  try { return normalizeUnchecked(input, budget); } catch { return failure('INTERNAL_ERROR'); }
}
function normalizeUnchecked(input: unknown, budget?: unknown): NormalizationResult {
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

  const views: MutableView[] = [{ id: 0, parent: null, encoding: 'ROOT', form: 'TEXT', depth: 0,
    parentStart: 0, parentEnd: root.length, occurrences: [{ start: 0, end: root.length }], text: root }];
  const uninspected: UninspectedSpan[] = [];
  const reasons = new Set<string>();
  let decodedUnits = 0, work = 0, binaryDecodes = 0;
  let exhausted: UninspectedSpan['reason'] | null = null;
  const record = (span: UninspectedSpan): void => {
    reasons.add(span.reason);
    if (uninspected.length < MAX_UNINSPECTED) uninspected.push(Object.freeze(span));
    else reasons.add('UNINSPECTED_TRUNCATED');
  };
  for (let cursor = 0; cursor < views.length; cursor++) {
    const view = views[cursor]!;
    if (exhausted) {
      // A global budget ran out: every not-yet-scanned view is wholly uninspected.
      record({ viewId: view.id, start: 0, end: view.text.length, reason: exhausted });
      continue;
    }
    // Runs longer than MAX_RUN never match the bounded patterns: find them linearly and record them.
    let runStart = -1;
    for (let index = 0; index <= view.text.length; index++) {
      const code = index < view.text.length ? view.text.charCodeAt(index) : 32;
      const encoded = code === 37 || code === 43 || code === 45 || (code >= 47 && code <= 57) || code === 61 ||
        (code >= 65 && code <= 90) || code === 95 || (code >= 97 && code <= 122);
      if (encoded && runStart < 0) runStart = index;
      else if (!encoded && runStart >= 0) {
        if (index - runStart > MAX_RUN) record({ viewId: view.id, start: runStart, end: index, reason: 'RUN_TOO_LONG' });
        runStart = -1;
      }
    }
    // Decoded text already produced from this view, with its disjoint parent spans.
    const produced = new Map<string, MutableView>();
    for (const run of runs(view.text)) {
      if (run.end - run.start > MAX_RUN) { record({ viewId: view.id, start: run.start, end: run.end, reason: 'RUN_TOO_LONG' }); continue; }
      // Charge every possible decode plus a fixed per-decode overhead, so many short runs are budgeted too.
      const cost = (run.end - run.start + DECODE_OVERHEAD) * run.decodes.length;
      if (work + cost > limits.maxDecodeWork) exhausted = 'WORK_LIMIT';
      else {
        work += cost;
        const { bytes, found } = best(run.decodes);
        if (!found) { if (bytes) binaryDecodes++; continue; }
        if (found.text === view.text.slice(run.start, run.end)) continue;
        const existing = produced.get(found.text);
        if (existing) {
          // Overlapping duplicates (odd-hex parities, alternative encodings of one span) add nothing; a
          // disjoint copy is another occurrence that transformation must also cover.
          // Runs within one pattern pass arrive in order, so recent occurrences suffice for the overlap test.
          if (existing.occurrences.slice(-4).some((o) => o.start < run.end && run.start < o.end)) continue;
          if (existing.occurrences.length < MAX_OCCURRENCES) { existing.occurrences.push({ start: run.start, end: run.end }); continue; }
        }
        if (view.depth + 1 > limits.maxDepth) {
          record({ viewId: view.id, start: run.start, end: run.end, reason: 'DEPTH_LIMIT' });
          continue;
        }
        if (views.length >= limits.maxViews + 1) exhausted = 'VIEW_LIMIT';
        else if (decodedUnits + found.text.length > limits.maxDecodedUnits) exhausted = 'EXPANSION_LIMIT';
        else {
          decodedUnits += found.text.length;
          const created: MutableView = { id: views.length, parent: view.id, encoding: run.encoding, form: found.form,
            depth: view.depth + 1, parentStart: run.start, parentEnd: run.end,
            occurrences: [{ start: run.start, end: run.end }], text: found.text };
          views.push(created);
          produced.set(found.text, created);
          continue;
        }
      }
      // Runs are produced lazily and out of position order, so the whole view is marked uninspected.
      record({ viewId: view.id, start: 0, end: view.text.length, reason: exhausted });
      break;
    }
  }
  return Object.freeze({
    status: uninspected.length || reasons.size ? 'PARTIAL' : 'COMPLETE', reasons: Object.freeze([...reasons].sort()),
    contentType: sniffContentType(root),
    views: Object.freeze(views.map((view) => Object.freeze({ ...view,
      occurrences: Object.freeze(view.occurrences.map((o) => Object.freeze(o))) }))),
    uninspected: Object.freeze(uninspected),
    binaryDecodes,
  });
}

/* ---------- Detection fold: compatibility-normalized text with an offset map ---------- */

export interface DetectionFold {
  text: string;
  /** For each folded code unit, the start and end of its source cluster in the input. */
  origin: Uint32Array;
  originEnd: Uint32Array;
}
const DASHES = /[‐-―−﹘﹣－]/gu;
const IGNORABLE = /\p{Default_Ignorable_Code_Point}/u;
const MARK = /\p{M}/u;
const MAX_FOLD_CLUSTER_UNITS = 4096;
const FOLD_TEXT_CHUNK_UNITS = 1 << 16;
/**
 * Visit clusters after deleting default-ignorable code points. A pathological combining-mark run is
 * explicitly rejected before it becomes a giant normalization argument or an offset-map allocation.
 */
function foldClusters(input: string, visit: (cluster: string, start: number, end: number) => void): void {
  let cluster = '', start = 0, end = 0;
  for (let index = 0; index < input.length;) {
    const char = String.fromCodePoint(input.codePointAt(index)!);
    if (!IGNORABLE.test(char)) {
      if (cluster && !MARK.test(char)) { visit(cluster, start, end); cluster = ''; }
      if (!cluster) start = index;
      if (cluster.length + char.length > MAX_FOLD_CLUSTER_UNITS) throw new RangeError('Fold cluster too large');
      cluster += char;
      end = index + char.length;
    }
    index += char.length;
  }
  if (cluster) visit(cluster, start, end);
}
/**
 * NFKC per cluster (a base plus its marks) after removing default-ignorable characters (zero-width, bidi
 * controls, variation selectors, soft hyphen), with Unicode dashes mapped to `-`. Removing ignorables first
 * lets a mark rejoin its base (`o<SHY>́` -> `ó`). Detectors match on `text` and map spans back with
 * `origin`/`originEnd`; the input is never rewritten. `maxUnits` (default 1 MiB, at most 16 MiB) bounds
 * both input and folded output. An overlong cluster or expansion throws before output maps are allocated.
 */
export function foldForDetection(input: string, maxUnits: number = DEFAULT_BUDGET.maxInputUnits): DetectionFold {
  if (typeof input !== 'string') throw new TypeError('Invalid fold input');
  if (!Number.isSafeInteger(maxUnits) || maxUnits < 0 || maxUnits > HARD_LIMITS.maxInputUnits) throw new RangeError('Invalid fold limit');
  if (input.length > maxUnits) throw new RangeError('Fold input too large');
  const normalizedPiece = (cluster: string): string => cluster.normalize('NFKC').replace(DASHES, '-');
  let outputUnits = 0;
  foldClusters(input, (cluster) => {
    const pieceUnits = normalizedPiece(cluster).length;
    if (pieceUnits > maxUnits - outputUnits) throw new RangeError('Fold output too large');
    outputUnits += pieceUnits;
  });
  const origin = new Uint32Array(outputUnits), originEnd = new Uint32Array(outputUnits);
  const chunks: string[] = [];
  let chunk = '', offset = 0;
  foldClusters(input, (cluster, start, end) => {
    const piece = normalizedPiece(cluster);
    origin.fill(start, offset, offset + piece.length);
    originEnd.fill(end, offset, offset + piece.length);
    offset += piece.length;
    chunk += piece;
    if (chunk.length >= FOLD_TEXT_CHUNK_UNITS) { chunks.push(chunk); chunk = ''; }
  });
  if (chunk) chunks.push(chunk);
  return Object.freeze({ text: chunks.join(''), origin, originEnd });
}
/** Map a folded span back to the smallest covering input span. */
export function mapFoldedSpan(fold: DetectionFold, start: number, end: number): { start: number; end: number } {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end <= start || end > fold.text.length) {
    throw new RangeError('Invalid folded span');
  }
  return { start: fold.origin[start]!, end: fold.originEnd[end - 1]! };
}
