/**
 * #7 bounded structured parsers. Pure and NON-ENFORCING. They extract fields with key paths, source
 * spans and decoded values so detectors can use structural meaning (a `password` key, a URL userinfo).
 * A parse never replaces scanning the whole text: a malformed, unsupported or budget-limited input yields
 * an explicit FAILURE/PARTIAL/UNSUPPORTED state with opaque ranges, never a success-shaped partial parse.
 * Results hold raw values in memory for detectors; they must never be logged or reported.
 */

export const FORMATS = ['JSON', 'DOTENV', 'INI', 'URL', 'CONNECTION_STRING', 'LOG', 'YAML', 'TOML', 'XML'] as const;
export type Format = (typeof FORMATS)[number];
const SUPPORTED: readonly Format[] = ['JSON', 'DOTENV', 'INI', 'URL', 'CONNECTION_STRING', 'LOG'];

export interface ParseBudget { maxInputUnits: number; maxDepth: number; maxFields: number }
export const DEFAULT_PARSE_BUDGET: Readonly<ParseBudget> = Object.freeze({ maxInputUnits: 1 << 20, maxDepth: 64, maxFields: 4096 });

/** How a value is written in the source; rewriting must re-encode for the same context. */
export type ValueSyntax = 'JSON_STRING' | 'JSON_LITERAL' | 'BARE' | 'SINGLE_QUOTED' | 'DOUBLE_QUOTED' | 'BRACED' |
  'PERCENT_ENCODED' | 'DOUBLED_DOUBLE_QUOTED' | 'DOUBLED_SINGLE_QUOTED';
export interface ParsedField {
  /** Key path, e.g. ['db', 'password'], ['query', 'token'], ['userinfo', 'password']; array indexes as strings. */
  path: readonly string[];
  keyStart?: number;
  keyEnd?: number;
  /** UTF-16 span of the value's source text, excluding surrounding quotes. */
  valueStart: number;
  valueEnd: number;
  /** Decoded value (escapes resolved). Differs from the source slice when `syntax` involves escaping. */
  value: string;
  syntax: ValueSyntax;
  /** The key names a credential-like field; its value is a high-risk candidate regardless of shape. */
  highRisk: boolean;
}
export interface OpaqueRange { start: number; end: number; reason: string }
export interface ParseResult {
  /**
   * COMPLETE: every byte is structure, a field or a listed comment. PARTIAL: some ranges are opaque.
   * UNSUPPORTED: no parser for the format. FAILURE: the input as a whole is malformed or over budget.
   * LOG results are field extraction only (`coverage: FIELDS_ONLY`); free text still needs detectors.
   */
  status: 'COMPLETE' | 'PARTIAL' | 'UNSUPPORTED' | 'FAILURE';
  format: Format;
  coverage: 'FULL' | 'FIELDS_ONLY';
  reasons: readonly string[];
  fields: readonly ParsedField[];
  opaque: readonly OpaqueRange[];
  /**
   * Comment text (full-line and inline) in dotenv/INI sources. Comments are not fields, but they are never
   * dropped: detectors must scan them, and rewriting refuses sources with comments unless told to remove them.
   */
  comments: readonly OpaqueRange[];
}

/* ---------- Credential-like keys ---------- */

const RISKY = ['password', 'passwd', 'passphrase', 'pwd', 'secret', 'token', 'apikey', 'accesskey', 'privatekey',
  'credential', 'authorization', 'cookie', 'sessionid', 'signature', 'bearer', 'connectionstring', 'sas', 'jwt'];
const RISKY_EXACT = ['auth', 'pass', 'sid', 'sig', 'key', 'pw', 'otp', 'dsn'];
const RISKY_SUFFIX = ['pass', 'pw', 'key', 'sessid', 'auth', 'dsn'];
/**
 * Normalizes `API_KEY`, `apiKey`, `x-api-key`, `Client Secret` and similar before matching. Keys with
 * non-ASCII letters are treated as credential-like: homoglyphs (`pаssword`) must not hide a password.
 * Over-matching (`max_tokens`, `monkey`) only over-protects.
 */
export function isCredentialKey(key: string): boolean {
  if (/[^\u0000-\u007f]/u.test(key)) return true;
  const compact = key.toLowerCase().replace(/[^a-z0-9]/gu, '');
  if (!compact) return false;
  if (RISKY_EXACT.includes(compact) || RISKY_SUFFIX.some((suffix) => compact.endsWith(suffix))) return true;
  return RISKY.some((word) => compact.includes(word));
}

/* ---------- Shared helpers ---------- */

class Budget extends Error { constructor(readonly reason: string) { super(reason); } }
class Malformed extends Error { constructor(readonly reason: string, readonly at: number) { super(reason); } }
function budgetFrom(raw: unknown): ParseBudget | null {
  if (raw === undefined) return { ...DEFAULT_PARSE_BUDGET };
  if (raw === null || typeof raw !== 'object') return null;
  const result = { ...DEFAULT_PARSE_BUDGET };
  try {
    for (const key of Object.keys(raw)) {
      if (!(key in DEFAULT_PARSE_BUDGET)) return null;
      const value: unknown = (raw as Record<string, unknown>)[key];
      // Depth stays well below the JS stack limit; fields are capped so per-field path copies stay bounded.
      const cap = key === 'maxDepth' ? 128 : key === 'maxFields' ? 65536 : 16 << 20;
      if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > cap) return null;
      result[key as keyof ParseBudget] = value;
    }
  } catch { return null; }
  return result;
}
function result(format: Format, status: ParseResult['status'], fields: ParsedField[], opaque: OpaqueRange[],
  reasons: Iterable<string>, coverage: ParseResult['coverage'] = 'FULL', comments: OpaqueRange[] = []): ParseResult {
  return Object.freeze({ status, format, coverage, reasons: Object.freeze([...new Set(reasons)].sort()),
    fields: Object.freeze(fields.map((field) => Object.freeze({ ...field, path: Object.freeze([...field.path]) }))),
    opaque: Object.freeze(opaque.map((range) => Object.freeze(range))),
    comments: Object.freeze(comments.map((range) => Object.freeze(range))) });
}
function whole(format: Format, text: string, status: 'FAILURE' | 'UNSUPPORTED', reason: string): ParseResult {
  return result(format, status, [], text.length ? [{ start: 0, end: text.length, reason }] : [], [reason]);
}
/** Total path segments across all fields, bounding memory for deep-and-wide inputs. */
const MAX_PATH_ELEMENTS = 1 << 20;
interface Collector { fields: ParsedField[]; max: number; pathElements: number; comments: OpaqueRange[] }
function push(into: Collector, field: ParsedField): void {
  into.pathElements += field.path.length;
  if (into.fields.length >= into.max || into.pathElements > MAX_PATH_ELEMENTS) throw new Budget('FIELD_LIMIT');
  into.fields.push(field);
}
function lines(text: string): { start: number; end: number; line: string }[] {
  const out: { start: number; end: number; line: string }[] = [];
  for (const match of text.matchAll(/[^\r\n]*(?:\r\n|\r|\n|$)/gu)) {
    if (!match[0].length && match.index >= text.length) break;
    const line = match[0].replace(/(?:\r\n|\r|\n)$/u, '');
    out.push({ start: match.index, end: match.index + line.length, line });
  }
  return out;
}

/* ---------- JSON: recursive descent with spans ---------- */

function parseJson(text: string, budget: ParseBudget, into: Collector, reasons: Set<string>): void {
  let at = 0;
  const ws = (): void => { while (at < text.length && ' \t\n\r'.includes(text[at]!)) at++; };
  const string = (): { value: string; start: number; end: number; escaped: boolean } => {
    if (text[at] !== '"') throw new Malformed('EXPECTED_STRING', at);
    const start = ++at;
    let value = '', escaped = false;
    for (;;) {
      if (at >= text.length) throw new Malformed('UNTERMINATED_STRING', start);
      const char = text[at]!;
      if (char === '"') break;
      if (char < ' ') throw new Malformed('CONTROL_IN_STRING', at);
      if (char !== '\\') { value += char; at++; continue; }
      escaped = true;
      const next = text[at + 1];
      const simple: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
      if (next !== undefined && next in simple) { value += simple[next]; at += 2; continue; }
      if (next !== 'u' || !/^[0-9A-Fa-f]{4}$/u.test(text.slice(at + 2, at + 6))) throw new Malformed('BAD_ESCAPE', at);
      value += String.fromCharCode(parseInt(text.slice(at + 2, at + 6), 16));
      at += 6;
    }
    const end = at++;
    return { value, start, end, escaped };
  };
  const value = (path: string[], depth: number, key?: { start: number; end: number }): void => {
    if (depth > budget.maxDepth) throw new Budget('DEPTH_LIMIT');
    ws();
    const char = text[at];
    const keyed = key ? { keyStart: key.start, keyEnd: key.end } : {};
    // A credential-like ancestor makes every nested value high risk (`{"password":["x"]}`).
    const risky = path.some((segment) => isCredentialKey(segment));
    if (char === '{') {
      at++; ws();
      const seen = new Set<string>();
      if (text[at] === '}') { at++; return; }
      const first = into.fields.length;
      const close = (): void => {
        // `{"name":"DB_PASSWORD","value":"x"}` (Kubernetes env, docker inspect): the sibling names the value.
        const children = into.fields.slice(first).filter((field) => field.path.length === path.length + 1);
        const named = children.some((field) => /^(?:name|key)$/iu.test(field.path[path.length]!) &&
          field.syntax === 'JSON_STRING' && isCredentialKey(field.value));
        if (named) {
          for (const field of into.fields.slice(first)) {
            if (/^value$/iu.test(field.path[path.length] ?? '')) field.highRisk = true;
          }
        }
        at++;
      };
      for (;;) {
        ws();
        const name = string();
        if (seen.has(name.value)) reasons.add('DUPLICATE_KEY');
        seen.add(name.value);
        ws();
        if (text[at] !== ':') throw new Malformed('EXPECTED_COLON', at);
        at++;
        value([...path, name.value], depth + 1, { start: name.start, end: name.end });
        ws();
        if (text[at] === ',') { at++; continue; }
        if (text[at] === '}') { close(); return; }
        throw new Malformed('EXPECTED_OBJECT_END', at);
      }
    }
    if (char === '[') {
      at++; ws();
      if (text[at] === ']') { at++; return; }
      for (let index = 0; ; index++) {
        value([...path, String(index)], depth + 1);
        ws();
        if (text[at] === ',') { at++; continue; }
        if (text[at] === ']') { at++; return; }
        throw new Malformed('EXPECTED_ARRAY_END', at);
      }
    }
    if (char === '"') {
      const parsed = string();
      push(into, { path, ...keyed, valueStart: parsed.start, valueEnd: parsed.end, value: parsed.value,
        syntax: 'JSON_STRING', highRisk: risky });
      return;
    }
    const literal = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/u.exec(text.slice(at, at + 400));
    if (!literal) throw new Malformed('UNEXPECTED_TOKEN', at);
    push(into, { path, ...keyed, valueStart: at, valueEnd: at + literal[0].length, value: literal[0],
      syntax: 'JSON_LITERAL', highRisk: risky });
    at += literal[0].length;
  };
  value([], 0);
  ws();
  if (at !== text.length) throw new Malformed('TRAILING_CONTENT', at);
}

/* ---------- Line formats: dotenv / shell assignments and INI ---------- */

interface Quoted { value: string; start: number; end: number; syntax: ValueSyntax; commentStart?: number }
/** Parse a value starting at `at` in `line` (offset `base`); returns null if a quote is unterminated. */
function lineValue(line: string, at: number, base: number, comments: string): Quoted | null {
  const quote = line[at];
  if (quote === '"' || quote === "'") {
    let value = '', index = at + 1;
    for (; index < line.length && line[index] !== quote; index++) {
      if (quote === '"' && line[index] === '\\' && index + 1 < line.length) {
        const next = line[++index]!;
        value += next === 'n' ? '\n' : next === 't' ? '\t' : next;
      } else value += line[index];
    }
    if (index >= line.length) return null;
    const rest = line.slice(index + 1);
    const marker = new RegExp(`^\\s+[${comments}]`, 'u').exec(rest);
    if (rest.trim() && !marker) return null;
    return { value, start: base + at + 1, end: base + index, syntax: quote === '"' ? 'DOUBLE_QUOTED' : 'SINGLE_QUOTED',
      ...(marker ? { commentStart: base + index + 1 + marker[0].length - 1 } : {}) };
  }
  let end = line.length;
  const comment = new RegExp(`\\s[${comments}]`, 'u').exec(line.slice(at));
  if (comment) end = at + comment.index;
  const commentStart = comment ? base + at + comment.index + 1 : undefined;
  while (end > at && /\s/u.test(line[end - 1]!)) end--;
  return { value: line.slice(at, end), start: base + at, end: base + end, syntax: 'BARE',
    ...(commentStart !== undefined ? { commentStart } : {}) };
}
function parseDotenv(text: string, into: Collector, opaque: OpaqueRange[]): void {
  for (const { start, line } of lines(text)) {
    if (!line.trim()) continue;
    const full = /^\s*#/u.exec(line);
    if (full) { into.comments.push({ start: start + full[0].length - 1, end: start + line.length, reason: 'COMMENT' }); continue; }
    const match = /^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)/u.exec(line);
    const parsed = match && lineValue(line, match[0].length, start, '#');
    if (!match || !parsed) { opaque.push({ start, end: start + line.length, reason: 'UNRECOGNIZED_LINE' }); continue; }
    const keyStart = start + match[1]!.length;
    push(into, { path: [match[2]!], keyStart, keyEnd: keyStart + match[2]!.length, valueStart: parsed.start,
      valueEnd: parsed.end, value: parsed.value, syntax: parsed.syntax, highRisk: isCredentialKey(match[2]!) });
    if (parsed.commentStart !== undefined) into.comments.push({ start: parsed.commentStart, end: start + line.length, reason: 'COMMENT' });
  }
}
function parseIni(text: string, into: Collector, opaque: OpaqueRange[]): void {
  let section: string[] = [];
  for (const { start, line } of lines(text)) {
    if (!line.trim()) continue;
    const full = /^\s*[#;]/u.exec(line);
    if (full) { into.comments.push({ start: start + full[0].length - 1, end: start + line.length, reason: 'COMMENT' }); continue; }
    const trimmed = line.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']') && trimmed.length > 2 && !/[\]\r\n]/u.test(trimmed.slice(1, -1))) {
      section = trimmed.slice(1, -1).trim().split('.');
      continue;
    }
    // Linear key scan: the first `=` or `:` separates key and value (no backtracking regex).
    const indent = line.length - line.trimStart().length;
    let separator = -1;
    for (let index = indent; index < line.length; index++) if (line[index] === '=' || line[index] === ':') { separator = index; break; }
    const key = separator > indent ? line.slice(indent, separator).trimEnd() : '';
    let valueAt = separator + 1;
    while (valueAt < line.length && (line[valueAt] === ' ' || line[valueAt] === '\t')) valueAt++;
    const parsed = key ? lineValue(line, valueAt, start, '#;') : null;
    if (!key || !parsed) { opaque.push({ start, end: start + line.length, reason: 'UNRECOGNIZED_LINE' }); continue; }
    const path = [...section, key];
    push(into, { path, keyStart: start + indent, keyEnd: start + indent + key.length, valueStart: parsed.start,
      valueEnd: parsed.end, value: parsed.value, syntax: parsed.syntax, highRisk: path.some((segment) => isCredentialKey(segment)) });
    if (parsed.commentStart !== undefined) into.comments.push({ start: parsed.commentStart, end: start + line.length, reason: 'COMMENT' });
  }
}

/* ---------- URLs and connection strings ---------- */

const utf8 = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();
/** Strict percent-decoding: malformed escapes or invalid UTF-8 are errors, never replaced. */
function percentDecode(text: string, plusIsSpace: boolean): string {
  const bytes: number[] = [];
  for (let index = 0; index < text.length;) {
    if (text[index] === '%') {
      if (!/^[0-9A-Fa-f]{2}$/u.test(text.slice(index + 1, index + 3))) throw new Malformed('BAD_PERCENT', index);
      bytes.push(parseInt(text.slice(index + 1, index + 3), 16));
      index += 3;
    } else {
      const char = String.fromCodePoint(text.codePointAt(index)!);
      for (const byte of encoder.encode(plusIsSpace && char === '+' ? ' ' : char)) bytes.push(byte);
      index += char.length;
    }
  }
  try { return utf8.decode(Uint8Array.from(bytes)); } catch { throw new Malformed('BAD_PERCENT_UTF8', 0); }
}
// A compound scheme such as `jdbc:postgresql://` is accepted as one scheme.
const URL_SHAPE = /^([A-Za-z][A-Za-z0-9+.-]*(?::[A-Za-z][A-Za-z0-9+.-]*)?):\/\/(?:([^/?#@\s]*)@)?(\[[0-9A-Fa-f:.]+\]|[^/?#:@\s]*)(?::(\d{1,5}))?(\/[^?#\s]*)?(?:\?([^#\s]*))?(?:#(\S*))?$/u;
function parseUrl(text: string, into: Collector, base = 0): void {
  const match = URL_SHAPE.exec(text);
  if (!match || match[4] !== undefined && Number(match[4]) > 65535) throw new Malformed('NOT_A_URL', base);
  const field = (path: string[], raw: string | undefined, offset: number, plus = false, risky = false): void => {
    if (raw === undefined || raw === '') return;
    // URL components are always rewritten percent-encoded, whatever the original spelling.
    push(into, { path, valueStart: base + offset, valueEnd: base + offset + raw.length, value: percentDecode(raw, plus),
      syntax: 'PERCENT_ENCODED', highRisk: risky });
  };
  let offset = match[1]!.length + 3;
  field(['scheme'], match[1], 0);
  if (match[2] !== undefined) {
    const colon = match[2].indexOf(':');
    const user = colon < 0 ? match[2] : match[2].slice(0, colon);
    // Without a password, the username often *is* the token (`https://<token>@host`).
    field(['userinfo', 'username'], user, offset, false, colon < 0);
    if (colon >= 0) field(['userinfo', 'password'], match[2].slice(colon + 1), offset + colon + 1, false, true);
    offset += match[2].length + 1;
  }
  field(['host'], match[3], offset);
  offset += match[3]!.length;
  if (match[4] !== undefined) { field(['port'], match[4], offset + 1); offset += match[4].length + 1; }
  field(['path'], match[5], offset);
  offset += match[5]?.length ?? 0;
  if (match[6] !== undefined) {
    pairs(['query'], match[6], base + offset + 1, into);
    offset += match[6].length + 1;
  }
  // OAuth implicit-flow fragments carry `access_token=...`: parse key=value fragments like a query.
  if (match[7] !== undefined && match[7].includes('=')) pairs(['fragment'], match[7], base + offset + 1, into);
  else field(['fragment'], match[7], offset + 1);
}
/** `&`- or `;`-separated pairs; a parameter without `=` is still a field (key ''), never dropped. */
function pairs(prefix: string[], raw: string, start: number, into: Collector): void {
  let cursor = start;
  for (const pair of raw.split(/[&;]/u)) {
    const eq = pair.indexOf('=');
    const key = eq < 0 ? '' : percentDecode(pair.slice(0, eq), true);
    const valueStart = eq < 0 ? cursor : cursor + eq + 1;
    if (pair.length) {
      push(into, { path: [...prefix, key], ...(eq >= 0 ? { keyStart: cursor, keyEnd: cursor + eq } : {}), valueStart,
        valueEnd: cursor + pair.length, value: percentDecode(pair.slice(eq + 1), true), syntax: 'PERCENT_ENCODED',
        highRisk: eq < 0 || isCredentialKey(key) });
    }
    cursor += pair.length + 1;
  }
}
function parseConnectionString(text: string, into: Collector): void {
  if (/^[A-Za-z][A-Za-z0-9+.-]*(?::[A-Za-z][A-Za-z0-9+.-]*)?:\/\//u.test(text.trim())) {
    const lead = text.length - text.trimStart().length;
    parseUrl(text.trim(), into, lead);
    return;
  }
  let at = 0;
  while (at < text.length) {
    while (at < text.length && /[\s;]/u.test(text[at]!)) at++;
    if (at >= text.length) break;
    const eq = text.indexOf('=', at);
    if (eq < 0) throw new Malformed('EXPECTED_EQUALS', at);
    const rawKey = text.slice(at, eq);
    const key = rawKey.trim();
    if (!key || /[;\r\n]/u.test(key)) throw new Malformed('BAD_KEY', at);
    const keyStart = at + rawKey.indexOf(key);
    let valueAt = eq + 1;
    while (valueAt < text.length && text[valueAt] === ' ') valueAt++;
    const open = text[valueAt];
    let value: string, start: number, end: number, syntax: ValueSyntax;
    if (open === '"' || open === "'" || open === '{') {
      const close = open === '{' ? '}' : open;
      let index = valueAt + 1;
      value = '';
      for (;; index++) {
        if (index >= text.length) throw new Malformed('UNTERMINATED_VALUE', valueAt);
        if (text[index] === close) {
          // A doubled quote or brace is an escaped literal.
          if (text[index + 1] === close) { value += close; index++; continue; }
          break;
        }
        value += text[index];
      }
      start = valueAt + 1; end = index; at = index + 1;
      syntax = open === '{' ? 'BRACED' : open === '"' ? 'DOUBLED_DOUBLE_QUOTED' : 'DOUBLED_SINGLE_QUOTED';
      if (at < text.length && !/[\s;]/u.test(text[at]!)) throw new Malformed('TRAILING_AFTER_QUOTE', at);
    } else {
      const semi = text.indexOf(';', valueAt);
      end = semi < 0 ? text.length : semi;
      while (end > valueAt && /\s/u.test(text[end - 1]!)) end--;
      start = valueAt; value = text.slice(start, end); syntax = 'BARE';
      at = semi < 0 ? text.length : semi + 1;
    }
    push(into, { path: [key], keyStart, keyEnd: keyStart + key.length, valueStart: start, valueEnd: end, value, syntax,
      highRisk: isCredentialKey(key) });
  }
}

/* ---------- Logs: header lines and key=value tokens (field extraction only) ---------- */

// Linear: the value runs to end of line and trailing whitespace is trimmed in code, not by backtracking.
const HEADER_LINE = /^(\s*)([A-Za-z][A-Za-z0-9-]{0,63})(:[ \t]*)(\S[^\r\n]*)$/u;
const QUOTE_OPEN = /(?<![\w.-])[A-Za-z_][\w.-]{0,63}=(["'])/gu;
const KV_TOKEN = /(?<![\w.-])([A-Za-z_][\w.-]{0,63})=("(?:[^"\\\r\n]|\\.){0,4096}"|'[^'\r\n]{0,4096}'|[^\s"',;]{1,4096})/gu;
function parseLog(text: string, into: Collector, opaque: OpaqueRange[]): void {
  lines(text).forEach(({ start, line }, lineNo) => {
    const header = HEADER_LINE.exec(line);
    // A timestamp-like `12:34` is not a header; header names start with a letter.
    if (header && !/^\d/u.test(header[4]!)) {
      const keyStart = start + header[1]!.length;
      const valueStart = keyStart + header[2]!.length + header[3]!.length;
      const value = header[4]!.trimEnd();
      push(into, { path: [String(lineNo), header[2]!], keyStart, keyEnd: keyStart + header[2]!.length, valueStart,
        valueEnd: valueStart + value.length, value, syntax: 'BARE', highRisk: isCredentialKey(header[2]!) });
    }
    // A value cut by a length cap or an unterminated quote would give a partial span: mark the line opaque.
    const quotedStarts = new Set<number>();
    let overflow = false;
    for (const match of line.matchAll(KV_TOKEN)) {
      const raw = match[2]!;
      if (raw[0] === '"' || raw[0] === "'") quotedStarts.add(match.index + match[1]!.length + 1);
      else if (raw.length === 4096 && /[^\s"',;]/u.test(line[match.index + match[0].length] ?? ' ')) overflow = true;
    }
    for (const open of line.matchAll(QUOTE_OPEN)) {
      if (!quotedStarts.has(open.index + open[0].length - 1)) overflow = true;
    }
    if (overflow) opaque.push({ start, end: start + line.length, reason: 'VALUE_OVERFLOW' });
    for (const match of line.matchAll(KV_TOKEN)) {
      const raw = match[2]!;
      const quoted = raw[0] === '"' || raw[0] === "'";
      const valueStart = start + match.index + match[1]!.length + 1 + (quoted ? 1 : 0);
      const inner = quoted ? raw.slice(1, -1) : raw;
      push(into, { path: [String(lineNo), match[1]!], keyStart: start + match.index,
        keyEnd: start + match.index + match[1]!.length, valueStart, valueEnd: valueStart + inner.length,
        value: raw[0] === '"' ? inner.replace(/\\(.)/gu, '$1') : inner,
        syntax: raw[0] === '"' ? 'DOUBLE_QUOTED' : raw[0] === "'" ? 'SINGLE_QUOTED' : 'BARE',
        highRisk: isCredentialKey(match[1]!) });
    }
  });
}

/* ---------- Entry point ---------- */

/**
 * Parse `text` as `format` (the caller chooses; #6's content-type sniff is only a hint). YAML, TOML and
 * XML are UNSUPPORTED here and must be treated as opaque by policy.
 */
export function parseStructured(text: unknown, format: unknown, budget?: unknown): ParseResult {
  if (!(FORMATS as readonly unknown[]).includes(format)) return whole('JSON', '', 'FAILURE', 'INVALID_FORMAT');
  const kind = format as Format;
  if (typeof text !== 'string') return whole(kind, '', 'FAILURE', 'INVALID_INPUT');
  const limits = budgetFrom(budget);
  if (!limits) return whole(kind, text, 'FAILURE', 'INVALID_BUDGET');
  if (text.length > limits.maxInputUnits) return whole(kind, text, 'FAILURE', 'INPUT_TOO_LARGE');
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(text)) {
    return whole(kind, text, 'FAILURE', 'INVALID_TEXT');
  }
  if (!SUPPORTED.includes(kind)) return whole(kind, text, 'UNSUPPORTED', 'UNSUPPORTED_FORMAT');
  const into: Collector = { fields: [], max: limits.maxFields, pathElements: 0, comments: [] };
  const opaque: OpaqueRange[] = [];
  const reasons = new Set<string>();
  try {
    switch (kind) {
      case 'JSON': parseJson(text, limits, into, reasons); break;
      case 'DOTENV': parseDotenv(text, into, opaque); break;
      case 'INI': parseIni(text, into, opaque); break;
      case 'URL': parseUrl(text.trim(), into, text.length - text.trimStart().length); break;
      case 'CONNECTION_STRING': parseConnectionString(text, into); break;
      case 'LOG': parseLog(text, into, opaque); break;
    }
  } catch (error) {
    // No success-shaped partial parse: the whole input becomes opaque.
    if (error instanceof Budget || error instanceof Malformed) return whole(kind, text, 'FAILURE', error.reason);
    return whole(kind, text, 'FAILURE', 'PARSER_ERROR');
  }
  if (opaque.length) reasons.add('OPAQUE_RANGES');
  if (into.comments.length) reasons.add('COMMENTS');
  return result(kind, opaque.length ? 'PARTIAL' : 'COMPLETE', into.fields, opaque, reasons,
    kind === 'LOG' ? 'FIELDS_ONLY' : 'FULL', into.comments);
}

/* ---------- Round-trip rewriting (keys and syntax preserved, or FAILURE) ---------- */

function encodeFor(syntax: ValueSyntax, replacement: string): string | null {
  switch (syntax) {
    case 'JSON_STRING': return JSON.stringify(replacement).slice(1, -1);
    case 'JSON_LITERAL': return null; // A number/boolean/null cannot take arbitrary text without changing type.
    case 'DOUBLE_QUOTED': return /\r/u.test(replacement) ? null : replacement.replace(/[\\"]/gu, '\\$&').replace(/\n/gu, '\\n');
    case 'DOUBLED_DOUBLE_QUOTED': return replacement.replace(/"/gu, '""');
    case 'DOUBLED_SINGLE_QUOTED': return replacement.replace(/'/gu, "''");
    case 'SINGLE_QUOTED': return replacement.includes("'") || /[\r\n]/u.test(replacement) ? null : replacement;
    case 'BRACED': return replacement.replace(/\}/gu, '}}');
    case 'PERCENT_ENCODED': try { return encodeURIComponent(replacement); } catch { return null; }
    case 'BARE': return /^[A-Za-z0-9._~:@\-[\]<>]*$/u.test(replacement) ? replacement : null;
  }
}
export interface RewriteEdit { field: ParsedField; replacement: string }
export interface RewriteOptions {
  /** REFUSE (default): sources with comments fail. REMOVE: comment text is deleted (markers kept). */
  comments?: 'REFUSE' | 'REMOVE';
}
/**
 * Replace field values, re-encoding each replacement for the syntax the parser found at that span, then
 * re-parse and require identical key paths, the replacements at edited fields and unchanged values
 * everywhere else. Any mismatch is a FAILURE: callers must not fall back to emitting the original text.
 */
export function rewriteFieldValues(text: string, format: Format, edits: readonly RewriteEdit[], options: RewriteOptions = {}):
  { status: 'OK'; text: string } | { status: 'FAILURE'; reason: string } {
  const before = parseStructured(text, format);
  if (before.status !== 'COMPLETE' || before.coverage !== 'FULL') return { status: 'FAILURE', reason: 'SOURCE_NOT_COMPLETE' };
  if (before.comments.length && options.comments !== 'REMOVE') return { status: 'FAILURE', reason: 'SOURCE_HAS_COMMENTS' };
  const byStart = new Map(before.fields.map((field, index) => [`${field.valueStart}:${field.valueEnd}`, index]));
  const replacements = new Map<number, string>();
  for (const edit of edits) {
    const index = byStart.get(`${edit.field?.valueStart}:${edit.field?.valueEnd}`);
    if (index === undefined || typeof edit.replacement !== 'string' || replacements.has(index)) {
      return { status: 'FAILURE', reason: 'INVALID_EDIT' };
    }
    replacements.set(index, edit.replacement);
  }
  // Splice right to left: field values, then removed comment text, never overlapping.
  const splices: { start: number; end: number; text: string }[] = [];
  for (const [index, replacement] of replacements) {
    const field = before.fields[index]!;
    const encoded = encodeFor(field.syntax, replacement);
    if (encoded === null) return { status: 'FAILURE', reason: 'UNENCODABLE_REPLACEMENT' };
    splices.push({ start: field.valueStart, end: field.valueEnd, text: encoded });
  }
  for (const comment of before.comments) splices.push({ start: comment.start + 1, end: comment.end, text: '' });
  splices.sort((a, b) => b.start - a.start);
  let output = text;
  for (const splice of splices) output = output.slice(0, splice.start) + splice.text + output.slice(splice.end);
  const after = parseStructured(output, format);
  if (after.status !== 'COMPLETE' || after.fields.length !== before.fields.length) return { status: 'FAILURE', reason: 'ROUND_TRIP_MISMATCH' };
  for (let index = 0; index < before.fields.length; index++) {
    const expected = replacements.get(index) ?? before.fields[index]!.value;
    if (JSON.stringify(after.fields[index]!.path) !== JSON.stringify(before.fields[index]!.path) ||
      after.fields[index]!.value !== expected) return { status: 'FAILURE', reason: 'ROUND_TRIP_MISMATCH' };
  }
  return { status: 'OK', text: output };
}
