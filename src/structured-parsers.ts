/**
 * #7 bounded structured parsers. Pure and NON-ENFORCING. They extract fields with key paths, source
 * spans and decoded values so detectors can use structural meaning (a `password` key, a URL userinfo).
 * A parse never replaces scanning the whole text: a malformed, unsupported or budget-limited input yields
 * an explicit FAILURE/PARTIAL/UNSUPPORTED state with opaque ranges, never a success-shaped partial parse.
 * Results hold raw values in memory for detectors; they must never be logged or reported.
 *
 * Resource budgets are explicit and independent: input units, nesting depth, field/comment/path counts, and
 * one cooperative wall-clock time budget read from a host-owned monotonic clock. Time exhaustion
 * (`TIME_BUDGET_EXPIRED`) and an unusable clock (`CLOCK_UNAVAILABLE`) are whole-input `FAILURE`s with the
 * original text opaque, exactly like a depth or field overflow: no field, span, coverage or reason survives.
 */

export const FORMATS = ['JSON', 'DOTENV', 'INI', 'URL', 'CONNECTION_STRING', 'LOG', 'YAML', 'TOML', 'XML'] as const;
export type Format = (typeof FORMATS)[number];
const SUPPORTED: readonly Format[] = ['JSON', 'DOTENV', 'INI', 'URL', 'CONNECTION_STRING', 'LOG', 'YAML', 'TOML', 'XML'];

export interface ParseBudget { maxInputUnits: number; maxDepth: number; maxFields: number; maxTimeMs: number }
export const DEFAULT_PARSE_BUDGET: Readonly<ParseBudget> =
  Object.freeze({ maxInputUnits: 1 << 20, maxDepth: 64, maxFields: 4096, maxTimeMs: 2000 });
/** Largest accepted time budget. Longer parsing is off the request path, so the parser refuses the claim. */
export const MAX_PARSE_TIME_MS = 60_000;

/** How a value is written in the source; rewriting must re-encode for the same context. */
export type ValueSyntax = 'JSON_STRING' | 'JSON_LITERAL' | 'BARE' | 'SINGLE_QUOTED' | 'DOUBLE_QUOTED' | 'BRACED' |
  'PERCENT_ENCODED' | 'DOUBLED_DOUBLE_QUOTED' | 'DOUBLED_SINGLE_QUOTED' | 'YAML_PLAIN' | 'YAML_PRIMITIVE' |
  'YAML_SINGLE_QUOTED' | 'YAML_DOUBLE_QUOTED' | 'TOML_PRIMITIVE' | 'TOML_BASIC' | 'TOML_LITERAL' |
  'XML_TEXT' | 'XML_DOUBLE_QUOTED' | 'XML_SINGLE_QUOTED';
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
/* ---------- Cooperative time budget ---------- */

/**
 * Host-owned monotonic millisecond reading. The parser owns no clock of its own: a payload cannot supply,
 * disable, rewind or forge this, and a serialized caller assertion that time remains is not a clock.
 * The unit is **milliseconds**, by contract with the host; a host that reports seconds makes every elapsed
 * span read as ~0 and silently disables the budget, which no in-process check can tell apart from a fast
 * parse, so the unit is a trusted-host obligation rather than something this module validates.
 */
export type MonotonicClock = () => number;
export interface ParseHost {
  /** Required: a host without a usable function here is refused, never defaulted. Called bound to its host. */
  readonly now: MonotonicClock;
}
/** Boundary events charged between two samples of the host clock; bounds clock-read cost, not work. */
const CLOCK_POLL_STEPS = 64;
/** Monotonic where the host offers it. A non-monotonic fallback still fails closed, see `Deadline`. */
const defaultClock: MonotonicClock = () => (typeof performance === 'object' ? performance.now() : Date.now());
/**
 * The one definition of a usable host, shared with the #6 composition seam so the two cannot drift.
 * Shape only: a reading is still validated on every sample, and a hostile trap that throws fails closed.
 */
export function isParseHost(host: unknown): boolean {
  if (host === null || typeof host !== 'object') return false;
  try { return typeof (host as { now?: unknown }).now === 'function'; } catch { return false; }
}
/**
 * Snapshot the host clock exactly once per parse and keep the call bound to its own host, so a method-style
 * `now() { return this.t }` reads its own state instead of resolving `this` to the deadline. A value that
 * changes what it returns later can only change readings, never the budget or the enforcement of it.
 */
function clockFrom(host: unknown): MonotonicClock {
  if (host === undefined) return defaultClock;
  let candidate: unknown;
  try { candidate = (host as { now?: unknown }).now; } catch { throw new Budget('CLOCK_UNAVAILABLE'); }
  if (typeof candidate !== 'function') throw new Budget('CLOCK_UNAVAILABLE');
  const owner = host;
  return () => (candidate as MonotonicClock).call(owner);
}
/**
 * Cooperative deadline over one parse. The clock is sampled at most once per `CLOCK_POLL_STEPS` charged
 * boundary steps and once more before any success-shaped result is returned, so a parse that finishes after
 * its budget reports the budget, never a `COMPLETE`/`PARTIAL` result. The cost is honest and bounded: one
 * charged primitive (a single string/scalar/regex run, a URL regex match, a whole-input character scan or
 * one percent-decode slice, each already bounded by the size budget or a fixed slice) is never interrupted,
 * and nothing here preempts a hostile `Proxy` trap, a blocking regexp or arbitrary same-process code that
 * never returns to a check point. A host that returns a frozen or otherwise dishonest reading cannot be
 * told apart from a slow host: successive readings are all this can compare, and a frozen clock simply never
 * expires, nor can a clock reporting another unit. That is why the clock is a trusted host capability and
 * never budget or payload data — the same property any in-process deadline has.
 */
class Deadline {
  private readonly start: number;
  private last: number;
  private pending = CLOCK_POLL_STEPS;
  constructor(private readonly clock: MonotonicClock, private readonly limitMs: number) {
    this.last = Number.NEGATIVE_INFINITY;
    this.start = this.read();
  }
  private read(): number {
    let value: unknown;
    try { value = this.clock(); } catch { throw new Budget('CLOCK_UNAVAILABLE'); }
    if (typeof value !== 'number' || !Number.isFinite(value)) throw new Budget('CLOCK_UNAVAILABLE');
    // A clock that moves backwards cannot report elapsed time, and reading that as "not expired" would make
    // a parser failure less restrictive, so an unreliable clock is a closed failure instead.
    if (value < this.last) throw new Budget('CLOCK_UNAVAILABLE');
    this.last = value;
    return value;
  }
  /** Charge one bounded primitive step at a scan/recursion boundary. */
  step(): void {
    if (--this.pending > 0) return;
    this.pending = CLOCK_POLL_STEPS;
    this.check();
  }
  /** Sample now. Throws `TIME_BUDGET_EXPIRED` or `CLOCK_UNAVAILABLE`, both whole-input failures. */
  check(): void {
    if (this.read() - this.start >= this.limitMs) throw new Budget('TIME_BUDGET_EXPIRED');
  }
}
class Malformed extends Error { constructor(readonly reason: string, readonly at: number) { super(reason); } }
class Unsupported extends Error { constructor(readonly reason: string) { super(reason); } }
function budgetFrom(raw: unknown): ParseBudget | null {
  if (raw === undefined) return { ...DEFAULT_PARSE_BUDGET };
  if (raw === null || typeof raw !== 'object') return null;
  const result = { ...DEFAULT_PARSE_BUDGET };
  try {
    for (const key of Object.keys(raw)) {
      if (!(key in DEFAULT_PARSE_BUDGET)) return null;
      const value: unknown = (raw as Record<string, unknown>)[key];
      // Depth stays well below the JS stack limit; fields are capped so per-field path copies stay bounded.
      // The time cap is a request-path budget, not an off-request one. A budget never carries a clock.
      const cap = key === 'maxDepth' ? 128 : key === 'maxFields' ? 65536 : key === 'maxTimeMs' ? MAX_PARSE_TIME_MS : 16 << 20;
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
/** JSON values of any kind (containers included) per parse. */
const MAX_NODES = 1 << 20;
interface Collector { fields: ParsedField[]; max: number; pathElements: number; comments: OpaqueRange[] }
function push(into: Collector, field: ParsedField): void {
  into.pathElements += field.path.length;
  if (into.fields.length >= into.max || into.pathElements > MAX_PATH_ELEMENTS) throw new Budget('FIELD_LIMIT');
  into.fields.push(field);
}
function pushComment(into: Collector, range: OpaqueRange): void {
  if (into.comments.length >= into.max) throw new Budget('COMMENT_LIMIT');
  into.comments.push(range);
}
function lines(text: string, deadline: Deadline): { start: number; end: number; line: string }[] {
  const out: { start: number; end: number; line: string }[] = [];
  for (const match of text.matchAll(/[^\r\n]*(?:\r\n|\r|\n|$)/gu)) {
    deadline.step();
    if (!match[0].length && match.index >= text.length) break;
    const line = match[0].replace(/(?:\r\n|\r|\n)$/u, '');
    out.push({ start: match.index, end: match.index + line.length, line });
  }
  return out;
}
/** Stream lines for formats with no need to materialize every line before the field budget is checked. */
function* boundedLines(text: string, deadline: Deadline): Generator<{ start: number; line: string }> {
  let start = 0;
  while (start < text.length) {
    deadline.step();
    let end = start;
    while (end < text.length && text[end] !== '\n' && text[end] !== '\r') end++;
    yield { start, line: text.slice(start, end) };
    start = end + (text[end] === '\r' && text[end + 1] === '\n' ? 2 : end < text.length ? 1 : 0);
  }
}

/* ---------- JSON: recursive descent with spans ---------- */

function parseJson(text: string, budget: ParseBudget, into: Collector, reasons: Set<string>, deadline: Deadline): void {
  let at = 0;
  const ws = (): void => { while (at < text.length && ' \t\n\r'.includes(text[at]!)) at++; };
  const string = (): { value: string; start: number; end: number; escaped: boolean } => {
    deadline.step();
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
  // One shared key stack: leaves copy it once; containers never copy (linear in input, not depth x values).
  const stack: string[] = [];
  let nodes = 0;
  const value = (depth: number, risky: boolean, key?: { start: number; end: number }): void => {
    deadline.step();
    if (depth > budget.maxDepth) throw new Budget('DEPTH_LIMIT');
    // Every value, including empty containers, counts against the node budget.
    if (++nodes > MAX_NODES) throw new Budget('FIELD_LIMIT');
    ws();
    const char = text[at];
    const keyed = key ? { keyStart: key.start, keyEnd: key.end } : {};
    if (char === '{') {
      at++; ws();
      const seen = new Set<string>();
      if (text[at] === '}') { at++; return; }
      const first = into.fields.length, level = stack.length;
      const close = (): void => {
        // `{"name":"DB_PASSWORD","value":"x"}` (Kubernetes env, docker inspect): the sibling names the value.
        let named = false;
        for (let index = first; index < into.fields.length && !named; index++) {
          const field = into.fields[index]!;
          named = field.path.length === level + 1 && /^(?:name|key)$/iu.test(field.path[level]!) &&
            field.syntax === 'JSON_STRING' && isCredentialKey(field.value);
        }
        if (named) {
          for (let index = first; index < into.fields.length; index++) {
            if (/^value$/iu.test(into.fields[index]!.path[level] ?? '')) into.fields[index]!.highRisk = true;
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
        stack.push(name.value);
        // A credential-like ancestor makes every nested value high risk (`{"password":["x"]}`).
        value(depth + 1, risky || isCredentialKey(name.value), { start: name.start, end: name.end });
        stack.pop();
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
        stack.push(String(index));
        value(depth + 1, risky);
        stack.pop();
        ws();
        if (text[at] === ',') { at++; continue; }
        if (text[at] === ']') { at++; return; }
        throw new Malformed('EXPECTED_ARRAY_END', at);
      }
    }
    if (char === '"') {
      const parsed = string();
      push(into, { path: stack.slice(), ...keyed, valueStart: parsed.start, valueEnd: parsed.end, value: parsed.value,
        syntax: 'JSON_STRING', highRisk: risky });
      return;
    }
    const literal = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/u.exec(text.slice(at, at + 400));
    if (!literal) throw new Malformed('UNEXPECTED_TOKEN', at);
    push(into, { path: stack.slice(), ...keyed, valueStart: at, valueEnd: at + literal[0].length, value: literal[0],
      syntax: 'JSON_LITERAL', highRisk: risky });
    at += literal[0].length;
  };
  value(0, false);
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
function parseDotenv(text: string, into: Collector, opaque: OpaqueRange[], deadline: Deadline): void {
  for (const { start, line } of lines(text, deadline)) {
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
function parseIni(text: string, into: Collector, opaque: OpaqueRange[], deadline: Deadline): void {
  let section: string[] = [];
  for (const { start, line } of lines(text, deadline)) {
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
/** Literal units decoded per charged budget step: the most one decode can do without being observed. */
const DECODE_SLICE = 8192;
/** The only digits a percent escape may use. A map, so no inherited property name can pass as a digit. */
const HEX = new Map([['0', 0], ['1', 1], ['2', 2], ['3', 3], ['4', 4], ['5', 5], ['6', 6], ['7', 7], ['8', 8],
  ['9', 9], ['a', 10], ['b', 11], ['c', 12], ['d', 13], ['e', 14], ['f', 15], ['A', 10], ['B', 11], ['C', 12],
  ['D', 13], ['E', 14], ['F', 15]]);
/** A UTF-16 high surrogate. A slice must never end between one of these and its low surrogate. */
function isHighSurrogate(code: number): boolean { return code >= 0xd800 && code <= 0xdbff; }
/**
 * Strict percent-decoding: malformed escapes or invalid UTF-8 are errors, never replaced.
 *
 * A literal run is UTF-8 encoded in bounded slices rather than one code point at a time, and a slice never
 * ends between a low surrogate and its high surrogate: `TextEncoder` replaces each *unpaired* surrogate
 * with U+FFFD, so a cut there would silently turn one character into two while the parse still reported
 * `COMPLETE` with no reason. A boundary that would land on a high surrogate is moved back one unit and the
 * pair is encoded whole by the next slice, so the byte stream is the concatenation of the encoding of each
 * of its code points, and the first bad escape is still reported at its own offset before anything is
 * decoded. The parser's own entry guard already refuses input containing an unpaired surrogate
 * (`INVALID_TEXT`), so a well-formed pair is the only case a slice can split in practice. It matters for
 * the budget: charging each slice means a long component is observed while it is decoded instead of only
 * after it, and encoding a slice instead of a character removes the per-character allocation that made one
 * megabyte of URL text cost more than the whole default time budget.
 */
function percentDecode(text: string, plusIsSpace: boolean, deadline: Deadline): string {
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let pending: number[] = [];
  const flush = (): void => {
    if (pending.length) { chunks.push(Uint8Array.from(pending)); bytes += pending.length; pending = []; }
  };
  const literal = (run: string): void => {
    flush();
    let at = 0;
    while (at < run.length) {
      // A slice always ends at least one unit past its start, so the loop always advances.
      let end = at + DECODE_SLICE < run.length ? at + DECODE_SLICE : run.length;
      if (end < run.length && isHighSurrogate(run.charCodeAt(end - 1))) end -= 1;
      const part = run.slice(at, end);
      const chunk = encoder.encode(plusIsSpace && part.includes('+') ? part.replace(/\+/gu, ' ') : part);
      chunks.push(chunk);
      bytes += chunk.length;
      at = end;
      deadline.step();
    }
  };
  let at = 0;
  for (;;) {
    const escape = text.indexOf('%', at);
    if (escape < 0) { if (at < text.length) literal(text.slice(at)); break; }
    if (escape > at) literal(text.slice(at, escape));
    const high = HEX.get(text[escape + 1] ?? '');
    const low = HEX.get(text[escape + 2] ?? '');
    if (high === undefined || low === undefined) throw new Malformed('BAD_PERCENT', escape);
    pending.push((high << 4) | low);
    at = escape + 3;
    // Escapes are charged too, so a component cannot buy uninterruptible work by spelling `%41` instead
    // of `a`. Consecutive escapes are batched into one chunk, so the charge does not cost an allocation.
    if (pending.length >= DECODE_SLICE) flush();
    deadline.step();
  }
  flush();
  let out: Uint8Array;
  if (chunks.length === 1) out = chunks[0]!;
  else {
    out = new Uint8Array(bytes);
    let written = 0;
    for (const chunk of chunks) { out.set(chunk, written); written += chunk.length; }
  }
  try { return utf8.decode(out); } catch { throw new Malformed('BAD_PERCENT_UTF8', 0); }
}
// A compound scheme such as `jdbc:postgresql://` is accepted as one scheme.
const URL_SHAPE = /^([A-Za-z][A-Za-z0-9+.-]*(?::[A-Za-z][A-Za-z0-9+.-]*)?):\/\/(?:([^/?#@\s]*)@)?(\[[0-9A-Fa-f:.]+\]|[^/?#:@\s;=]*)(?::(\d{1,5}))?(;[^/?#\s]*)?(\/[^?#\s]*)?(?:\?([^#\s]*))?(?:#(\S*))?$/u;
function parseUrl(text: string, into: Collector, deadline: Deadline, base = 0): void {
  // A URL is one bounded regex over one bounded input: a single primitive, charged once.
  deadline.step();
  const match = URL_SHAPE.exec(text);
  if (!match || match[4] !== undefined && Number(match[4]) > 65535) throw new Malformed('NOT_A_URL', base);
  const field = (path: string[], raw: string | undefined, offset: number, plus = false, risky = false): void => {
    if (raw === undefined || raw === '') return;
    deadline.step();
    // URL components are always rewritten percent-encoded, whatever the original spelling.
    push(into, { path, valueStart: base + offset, valueEnd: base + offset + raw.length, value: percentDecode(raw, plus, deadline),
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
  // `;key=value` parameters after the authority (SQL Server JDBC) are fields, never part of the host.
  if (match[5] !== undefined) { pairs(['params'], match[5].slice(1), base + offset + 1, into, deadline); offset += match[5].length; }
  field(['path'], match[6], offset);
  offset += match[6]?.length ?? 0;
  if (match[7] !== undefined) {
    pairs(['query'], match[7], base + offset + 1, into, deadline);
    offset += match[7].length + 1;
  }
  // OAuth implicit-flow fragments carry `access_token=...`: parse key=value fragments like a query.
  if (match[8] !== undefined && match[8].includes('=')) pairs(['fragment'], match[8], base + offset + 1, into, deadline);
  else field(['fragment'], match[8], offset + 1);
}
/** `&`- or `;`-separated pairs; a parameter without `=` is still a field (key ''), never dropped. */
function pairs(prefix: string[], raw: string, start: number, into: Collector, deadline: Deadline): void {
  let cursor = start;
  for (const pair of raw.split(/[&;]/u)) {
    deadline.step();
    const eq = pair.indexOf('=');
    const key = eq < 0 ? '' : percentDecode(pair.slice(0, eq), true, deadline);
    const valueStart = eq < 0 ? cursor : cursor + eq + 1;
    if (pair.length) {
      push(into, { path: [...prefix, key], ...(eq >= 0 ? { keyStart: cursor, keyEnd: cursor + eq } : {}), valueStart,
        valueEnd: cursor + pair.length, value: percentDecode(pair.slice(eq + 1), true, deadline), syntax: 'PERCENT_ENCODED',
        highRisk: eq < 0 || isCredentialKey(key) });
    }
    cursor += pair.length + 1;
  }
}
function parseConnectionString(text: string, into: Collector, deadline: Deadline): void {
  if (/^[A-Za-z][A-Za-z0-9+.-]*(?::[A-Za-z][A-Za-z0-9+.-]*)?:\/\//u.test(text.trim())) {
    const lead = text.length - text.trimStart().length;
    parseUrl(text.trim(), into, deadline, lead);
    return;
  }
  let at = 0;
  while (at < text.length) {
    deadline.step();
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
function parseLog(text: string, into: Collector, opaque: OpaqueRange[], deadline: Deadline): void {
  lines(text, deadline).forEach(({ start, line }, lineNo) => {
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

/* ---------- Conservative YAML and TOML subsets ---------- */

interface Scalar { value: string; start: number; end: number; syntax: ValueSyntax; commentStart?: number }
const INVALID_UNICODE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u;
function commentAt(line: string, from: number): number {
  for (let at = from; at < line.length; at++) if (line[at] === '#' && (at === from || /[ \t]/u.test(line[at - 1]!))) return at;
  return -1;
}
function quoteScalar(line: string, at: number, base: number, dialect: 'YAML' | 'TOML'): Scalar {
  const quote = line[at]!;
  let cursor = at + 1, value = '';
  while (cursor < line.length) {
    const char = line[cursor]!;
    if (char === quote) {
      if (dialect === 'YAML' && quote === "'" && line[cursor + 1] === "'") { value += "'"; cursor += 2; continue; }
      break;
    }
    if (char === '\\' && quote === '"') {
      const next = line[cursor + 1];
      if (next === undefined) throw new Malformed('UNTERMINATED_QUOTE', base + cursor);
      const simple: Record<string, string> = { '"': '"', '\\': '\\', b: '\b', t: '\t', n: '\n', f: '\f', r: '\r' };
      if (next in simple) { value += simple[next]; cursor += 2; continue; }
      if (next === 'u' && /^[0-9A-Fa-f]{4}$/u.test(line.slice(cursor + 2, cursor + 6))) {
        value += String.fromCharCode(parseInt(line.slice(cursor + 2, cursor + 6), 16)); cursor += 6; continue;
      }
      // Valid YAML/TOML have more escapes; the bounded subset declines them as a whole.
      throw new Unsupported('UNSUPPORTED_ESCAPE');
    }
    if ((char < ' ' && char !== '\t') || char === '\u007f') throw new Malformed('INVALID_SCALAR', base + cursor);
    value += char;
    cursor++;
  }
  if (cursor >= line.length) throw new Malformed('UNTERMINATED_QUOTE', base + at);
  if (/[\u0000-\u0007\u000b\u000e-\u001f\u007f]/u.test(value)) throw new Malformed('INVALID_SCALAR', base + at);
  if (INVALID_UNICODE.test(value)) throw new Malformed('INVALID_SCALAR', base + at);
  const rest = line.slice(cursor + 1);
  if (rest.trim() && !/^[ \t]+#/u.test(rest)) throw new Unsupported('UNSUPPORTED_SCALAR');
  const marker = rest.indexOf('#');
  return { value, start: base + at + 1, end: base + cursor,
    syntax: dialect === 'YAML' ? quote === "'" ? 'YAML_SINGLE_QUOTED' : 'YAML_DOUBLE_QUOTED' :
      quote === "'" ? 'TOML_LITERAL' : 'TOML_BASIC',
    ...(marker >= 0 ? { commentStart: base + cursor + 1 + marker } : {}) };
}
function yamlScalar(line: string, at: number, base: number): Scalar {
  if (line[at] === '"' || line[at] === "'") return quoteScalar(line, at, base, 'YAML');
  const marker = commentAt(line, at);
  let end = marker >= 0 ? marker : line.length;
  while (end > at && /[ \t]/u.test(line[end - 1]!)) end--;
  const value = line.slice(at, end);
  // Flow syntax, tags, aliases, block scalars and implicit complex keys need a full YAML parser.
  if (!/^[A-Za-z0-9_.\/+~-][A-Za-z0-9._~@/+:-]*$/u.test(value) || /:[ \t]/u.test(value)) {
    throw new Unsupported('UNSUPPORTED_YAML_SCALAR');
  }
  const primitive = yamlPrimitive(value);
  return { value, start: base + at, end: base + end, syntax: primitive ? 'YAML_PRIMITIVE' : 'YAML_PLAIN',
    ...(marker >= 0 ? { commentStart: base + marker } : {}) };
}
function yamlPrimitive(value: string): boolean {
  // YAML 1.1/1.2 implicit scalar rules differ. Refuse rewrites of all numeric-looking forms.
  return /^(?:true|false|null|~|yes|no|on|off|[-+]?(?:\d|\.inf|\.nan))/iu.test(value);
}
const NAME_OR_KEY = /^@?(?:name|key)$/iu;
const VALUE_KEY = /^@?value$/iu;
function markNamedValues(fields: ParsedField[], deadline: Deadline): void {
  const riskyParents = new Set<string>();
  for (const field of fields) {
    deadline.step();
    if (NAME_OR_KEY.test(field.path.at(-1) ?? '') && isCredentialKey(field.value)) {
      riskyParents.add(JSON.stringify(field.path.slice(0, -1)));
    }
  }
  for (const field of fields) {
    deadline.step();
    if (VALUE_KEY.test(field.path.at(-1) ?? '') && riskyParents.has(JSON.stringify(field.path.slice(0, -1)))) {
      field.highRisk = true;
    }
  }
}
function parseYaml(text: string, budget: ParseBudget, into: Collector, deadline: Deadline): void {
  type Frame = { indent: number; path: string[]; kind: 'MAP' | 'SEQ'; seen: Set<string>; next: number };
  const frames: Frame[] = [{ indent: 0, path: [], kind: 'MAP', seen: new Set(), next: 0 }];
  let pending: { indent: number; path: string[] } | undefined;
  let documentSeen = false;
  for (const { start, line } of boundedLines(text, deadline)) {
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    if (line.slice(0, indent).includes('\t')) throw new Unsupported('UNSUPPORTED_YAML_INDENT');
    const body = line.slice(indent);
    if (body.startsWith('#')) { pushComment(into, { start: start + indent, end: start + line.length, reason: 'COMMENT' }); continue; }
    if (body === '---' && !documentSeen && !pending) { documentSeen = true; continue; }
    documentSeen = true;
    if (body === '---' || body === '...' || body.startsWith('%')) throw new Unsupported('UNSUPPORTED_YAML_DOCUMENT');
    if (pending) {
      if (indent <= pending.indent) throw new Unsupported('UNSUPPORTED_EMPTY_CONTAINER');
      frames.push({ indent, path: pending.path, kind: /^-(?:[ \t]|$)/u.test(body) ? 'SEQ' : 'MAP', seen: new Set(), next: 0 });
      pending = undefined;
      if (frames.length > budget.maxDepth) throw new Budget('DEPTH_LIMIT');
    } else {
      while (frames.length > 1 && indent < frames[frames.length - 1]!.indent) frames.pop();
      if (indent !== frames[frames.length - 1]!.indent) throw new Unsupported('UNSUPPORTED_YAML_INDENT');
    }
    const frame = frames[frames.length - 1]!;
    if (frame.kind === 'SEQ') {
      if (!/^-[ \t]+\S/u.test(body)) throw new Unsupported('UNSUPPORTED_YAML_SEQUENCE');
      const valueAt = indent + 1 + (/^[ \t]*/u.exec(body.slice(1))?.[0].length ?? 0);
      const scalar = yamlScalar(line, valueAt, start);
      push(into, { path: [...frame.path, String(frame.next++)], valueStart: scalar.start, valueEnd: scalar.end,
        value: scalar.value, syntax: scalar.syntax, highRisk: frame.path.some(isCredentialKey) });
      if (scalar.commentStart !== undefined) pushComment(into, { start: scalar.commentStart, end: start + line.length, reason: 'COMMENT' });
      continue;
    }
    const match = /^([A-Za-z_][A-Za-z0-9_.-]*):(?=[ \t]|$)/u.exec(body);
    if (!match) throw new Unsupported('UNSUPPORTED_YAML_MAPPING');
    const key = match[1]!;
    if (frame.seen.has(key)) throw new Malformed('DUPLICATE_KEY', start + indent);
    frame.seen.add(key);
    const path = [...frame.path, key];
    const restAt = indent + match[0].length;
    let valueAt = restAt;
    while (valueAt < line.length && /[ \t]/u.test(line[valueAt]!)) valueAt++;
    if (valueAt === line.length || line[valueAt] === '#') {
      if (line[valueAt] === '#') pushComment(into, { start: start + valueAt, end: start + line.length, reason: 'COMMENT' });
      pending = { indent, path };
      continue;
    }
    const scalar = yamlScalar(line, valueAt, start);
    push(into, { path, keyStart: start + indent, keyEnd: start + indent + key.length,
      valueStart: scalar.start, valueEnd: scalar.end, value: scalar.value, syntax: scalar.syntax,
      highRisk: path.some(isCredentialKey) });
    if (scalar.commentStart !== undefined) pushComment(into, { start: scalar.commentStart, end: start + line.length, reason: 'COMMENT' });
  }
  if (pending) throw new Unsupported('UNSUPPORTED_EMPTY_CONTAINER');
  markNamedValues(into.fields, deadline);
}

function tomlScalar(line: string, at: number, base: number): Scalar {
  if (line[at] === '"' || line[at] === "'") return quoteScalar(line, at, base, 'TOML');
  const marker = commentAt(line, at);
  let end = marker >= 0 ? marker : line.length;
  while (end > at && /[ \t]/u.test(line[end - 1]!)) end--;
  const value = line.slice(at, end);
  const primitive = /^(?:true|false|[-+]?(?:0|[1-9](?:_?\d)*)(?:\.(?:\d(?:_?\d)*))?(?:[eE][-+]?\d(?:_?\d)*)?)$/u.test(value);
  if (!primitive) throw new Unsupported('UNSUPPORTED_TOML_VALUE');
  return { value, start: base + at, end: base + end, syntax: 'TOML_PRIMITIVE',
    ...(marker >= 0 ? { commentStart: base + marker } : {}) };
}
function parseToml(text: string, budget: ParseBudget, into: Collector, deadline: Deadline): void {
  let section: string[] = [];
  const tables = new Set<string>(), leaves = new Set<string>(), nodes = new Set<string>();
  // JSON path IDs repeat section text; cap their total expansion as well as their element count.
  const maxPathUnits = 8 << 20;
  const maxPathWorkUnits = 32 << 20;
  let storedPathUnits = 0, storedPathElements = 0, pathWorkUnits = 0;
  const pathId = (parts: readonly string[]): string => {
    deadline.step();
    const id = JSON.stringify(parts);
    pathWorkUnits += id.length;
    if (pathWorkUnits > maxPathWorkUnits) throw new Budget('PATH_LIMIT');
    return id;
  };
  const storePath = (set: Set<string>, id: string, elements: number): void => {
    if (set.has(id)) return;
    storedPathUnits += id.length;
    storedPathElements += elements;
    if (storedPathUnits > maxPathUnits || storedPathElements > MAX_PATH_ELEMENTS) throw new Budget('PATH_LIMIT');
    set.add(id);
  };
  for (const { start, line } of boundedLines(text, deadline)) {
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    if (line.slice(0, indent).includes('\t')) throw new Unsupported('UNSUPPORTED_TOML_INDENT');
    const body = line.slice(indent);
    if (body.startsWith('#')) { pushComment(into, { start: start + indent, end: start + line.length, reason: 'COMMENT' }); continue; }
    if (body.startsWith('[')) {
      const table = /^\[([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)\](?:[ \t]+(#.*))?$/u.exec(body);
      if (!table) throw new Unsupported('UNSUPPORTED_TOML_TABLE');
      section = table[1]!.split('.');
      if (section.length > budget.maxDepth) throw new Budget('DEPTH_LIMIT');
      const id = pathId(section);
      if (tables.has(id) || leaves.has(id) || nodes.has(id)) throw new Malformed('DUPLICATE_TABLE', start + indent);
      if (tables.size >= into.max) throw new Budget('FIELD_LIMIT');
      storePath(tables, id, section.length);
      storePath(nodes, id, section.length);
      for (let count = 1; count < section.length; count++) {
        const prefix = pathId(section.slice(0, count));
        if (leaves.has(prefix)) throw new Malformed('KEY_TABLE_COLLISION', start + indent);
        storePath(nodes, prefix, count);
      }
      if (table[2]) pushComment(into, { start: start + indent + body.indexOf('#'), end: start + line.length, reason: 'COMMENT' });
      continue;
    }
    const match = /^([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)[ \t]*=[ \t]*/u.exec(body);
    if (!match) throw new Unsupported('UNSUPPORTED_TOML_KEY');
    const key = match[1]!;
    const path = [...section, ...key.split('.')];
    if (path.length > budget.maxDepth) throw new Budget('DEPTH_LIMIT');
    const id = pathId(path);
    if (leaves.has(id) || nodes.has(id)) throw new Malformed('DUPLICATE_KEY', start + indent);
    // Section prefixes were checked and stored at the table declaration. Avoid rebuilding them per field.
    for (let count = section.length + 1; count < path.length; count++) {
      const prefix = pathId(path.slice(0, count));
      if (leaves.has(prefix)) throw new Malformed('KEY_TABLE_COLLISION', start + indent);
      storePath(nodes, prefix, count);
    }
    const valueAt = indent + match[0].length;
    if (valueAt >= line.length || line[valueAt] === '#') throw new Unsupported('UNSUPPORTED_TOML_VALUE');
    const scalar = tomlScalar(line, valueAt, start);
    push(into, { path, keyStart: start + indent, keyEnd: start + indent + key.length,
      valueStart: scalar.start, valueEnd: scalar.end, value: scalar.value, syntax: scalar.syntax,
      highRisk: path.some(isCredentialKey) });
    storePath(leaves, id, path.length);
    if (scalar.commentStart !== undefined) pushComment(into, { start: scalar.commentStart, end: start + line.length, reason: 'COMMENT' });
  }
  markNamedValues(into.fields, deadline);
}

/* ---------- XML without DTD, external entities, namespaces or mixed content ---------- */

const XML_NAME = /[A-Za-z_][A-Za-z0-9_.-]*/gy;
const XML_ENTITIES: Readonly<Record<string, string>> = Object.freeze({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" });
function xmlValidChar(code: number): boolean {
  return code === 9 || code === 10 || code === 13 || code >= 0x20 && code <= 0xd7ff ||
    code >= 0xe000 && code <= 0xfffd || code >= 0x10000 && code <= 0x10ffff;
}
function xmlValidText(value: string): boolean {
  if (INVALID_UNICODE.test(value)) return false;
  for (const char of value) if (!xmlValidChar(char.codePointAt(0)!)) return false;
  return true;
}
function xmlName(text: string, at: number): { name: string; end: number } {
  XML_NAME.lastIndex = at;
  const found = XML_NAME.exec(text);
  if (!found) throw new Malformed('EXPECTED_XML_NAME', at);
  return { name: found[0], end: XML_NAME.lastIndex };
}
function xmlWhitespace(char: string | undefined): boolean { return char === ' ' || char === '\t' || char === '\n' || char === '\r'; }
function xmlScalar(raw: string, at: number, deadline: Deadline): string {
  deadline.step();
  let value = '';
  for (let cursor = 0; cursor < raw.length;) {
    if (raw[cursor] !== '&') { value += raw[cursor++]; continue; }
    const semi = raw.indexOf(';', cursor + 1);
    if (semi < 0 || semi - cursor > 12) throw new Malformed('BAD_XML_ENTITY', at + cursor);
    const entity = raw.slice(cursor + 1, semi);
    if (Object.hasOwn(XML_ENTITIES, entity)) value += XML_ENTITIES[entity];
    else {
      const hex = /^#x([0-9A-Fa-f]+)$/u.exec(entity);
      const decimal = /^#([0-9]+)$/u.exec(entity);
      if (!hex && !decimal) throw new Malformed('BAD_XML_ENTITY', at + cursor);
      const code = Number.parseInt((hex ?? decimal)![1]!, hex ? 16 : 10);
      if (!xmlValidChar(code)) {
        throw new Malformed('BAD_XML_ENTITY', at + cursor);
      }
      value += String.fromCodePoint(code);
    }
    cursor = semi + 1;
  }
  return value;
}
function parseXml(text: string, budget: ParseBudget, into: Collector, deadline: Deadline): void {
  // One whole-input character-validity sweep is a single bounded primitive, charged once.
  deadline.step();
  if (!xmlValidText(text)) throw new Malformed('INVALID_XML_CHAR', 0);
  let at = 0, nodes = 0, nodePathElements = 0;
  const ws = (): void => { while (xmlWhitespace(text[at])) at++; };
  const comment = (): void => {
    deadline.step();
    const end = text.indexOf('-->', at + 4);
    if (end < 0 || text[end - 1] === '-' || text.slice(at + 4, end).includes('--')) {
      throw new Malformed('BAD_XML_COMMENT', at);
    }
    pushComment(into, { start: at, end: end + 3, reason: 'COMMENT' });
    at = end + 3;
  };
  ws();
  if (text.startsWith('<?xml', at)) {
    const end = text.indexOf('?>', at + 5);
    if (end < 0) throw new Malformed('BAD_XML_DECLARATION', at);
    const declaration = text.slice(at, end + 2);
    if (!/^<\?xml[ \t]+version=(?:'1\.0'|"1\.0")(?:[ \t]+encoding=(?:'UTF-8'|"UTF-8"))?(?:[ \t]+standalone=(?:'yes'|"yes"|'no'|"no"))?[ \t]*\?>$/u.test(declaration)) {
      throw new Unsupported('UNSUPPORTED_XML_DECLARATION');
    }
    at = end + 2;
  }
  const element = (parent: string[], inheritedRisk: boolean, depth: number): void => {
    deadline.step();
    if (depth > budget.maxDepth) throw new Budget('DEPTH_LIMIT');
    if (++nodes > MAX_NODES) throw new Budget('FIELD_LIMIT');
    if (text[at] !== '<' || text[at + 1] === '!' || text[at + 1] === '?') throw new Unsupported('UNSUPPORTED_XML_MARKUP');
    at++;
    const opening = xmlName(text, at);
    const path = [...parent, opening.name];
    nodePathElements += path.length;
    if (nodePathElements > MAX_PATH_ELEMENTS) throw new Budget('FIELD_LIMIT');
    const risky = inheritedRisk || isCredentialKey(opening.name);
    const keyStart = at;
    at = opening.end;
    const firstAttr = into.fields.length;
    const attrNames = new Set<string>();
    let selfClosing = false;
    for (;;) {
      const before = at;
      ws();
      if (text.startsWith('/>', at)) { at += 2; selfClosing = true; break; }
      if (text[at] === '>') { at++; break; }
      if (before === at) throw new Malformed('BAD_XML_ATTRIBUTE', at);
      const attrStart = at;
      const attr = xmlName(text, at);
      if (attr.name === 'xmlns') throw new Unsupported('UNSUPPORTED_XML_NAMESPACE');
      if (attrNames.has(attr.name)) throw new Malformed('DUPLICATE_ATTRIBUTE', attrStart);
      attrNames.add(attr.name);
      at = attr.end;
      ws();
      if (text[at] !== '=') throw new Malformed('BAD_XML_ATTRIBUTE', at);
      at++; ws();
      const quote = text[at];
      if (quote !== '"' && quote !== "'") throw new Malformed('BAD_XML_ATTRIBUTE', at);
      const valueStart = ++at;
      const valueEnd = text.indexOf(quote, at);
      if (valueEnd < 0 || text.slice(at, valueEnd).includes('<')) throw new Malformed('BAD_XML_ATTRIBUTE', at);
      const raw = text.slice(at, valueEnd);
      if (/[\r\n\t]/u.test(raw)) throw new Unsupported('UNSUPPORTED_XML_WHITESPACE');
      push(into, { path: [...path, `@${attr.name}`], keyStart: attrStart, keyEnd: attr.end,
        valueStart, valueEnd, value: xmlScalar(raw, valueStart, deadline),
        syntax: quote === '"' ? 'XML_DOUBLE_QUOTED' : 'XML_SINGLE_QUOTED',
        highRisk: risky || isCredentialKey(attr.name) });
      at = valueEnd + 1;
    }
    // XML `name`/`key` and `value` attributes carry the same risk as JSON name/value siblings.
    const nameAttr = into.fields.slice(firstAttr).find((field) => NAME_OR_KEY.test(field.path.at(-1) ?? '') &&
      isCredentialKey(field.value));
    if (nameAttr) for (let index = firstAttr; index < into.fields.length; index++) {
      if (VALUE_KEY.test(into.fields[index]!.path.at(-1) ?? '')) into.fields[index]!.highRisk = true;
    }
    if (selfClosing) return;
    const firstChild = into.fields.length;
    let contentStart = at, children = 0, hasComment = false;
    for (;;) {
      const next = text.indexOf('<', at);
      if (next < 0) throw new Malformed('UNCLOSED_XML_ELEMENT', at);
      const raw = text.slice(contentStart, next);
      if (text.startsWith('</', next)) {
        at = next + 2;
        const closing = xmlName(text, at);
        if (closing.name !== opening.name) throw new Malformed('MISMATCHED_XML_TAG', at);
        at = closing.end;
        ws();
        if (text[at] !== '>') throw new Malformed('BAD_XML_CLOSE', at);
        at++;
        if (children || hasComment) {
          if (raw.trim()) throw new Unsupported('UNSUPPORTED_XML_MIXED_CONTENT');
          let named = false;
          for (let index = firstChild; index < into.fields.length && !named; index++) {
            const field = into.fields[index]!;
            named = field.path.length === path.length + 1 && NAME_OR_KEY.test(field.path.at(-1) ?? '') &&
              isCredentialKey(field.value);
          }
          if (named) for (let index = firstChild; index < into.fields.length; index++) {
            const field = into.fields[index]!;
            if (field.path.length === path.length + 1 && VALUE_KEY.test(field.path.at(-1) ?? '')) field.highRisk = true;
          }
        } else {
          if (raw.includes('\r') || raw.includes(']]>')) throw new Unsupported('UNSUPPORTED_XML_TEXT');
          push(into, { path, keyStart, keyEnd: opening.end, valueStart: contentStart, valueEnd: next,
            value: xmlScalar(raw, contentStart, deadline), syntax: 'XML_TEXT', highRisk: risky });
        }
        return;
      }
      if (raw.trim()) throw new Unsupported('UNSUPPORTED_XML_MIXED_CONTENT');
      at = next;
      if (text.startsWith('<!--', at)) { comment(); hasComment = true; }
      else if (text.startsWith('<!', at) || text.startsWith('<?', at)) throw new Unsupported('UNSUPPORTED_XML_MARKUP');
      else { element(path, risky, depth + 1); children++; }
      contentStart = at;
    }
  };
  while (true) { ws(); if (text.startsWith('<!--', at)) comment(); else break; }
  element([], false, 1);
  while (true) { ws(); if (text.startsWith('<!--', at)) comment(); else break; }
  if (at !== text.length) throw new Malformed('TRAILING_XML_CONTENT', at);
}

/* ---------- Entry point ---------- */

/**
 * Parse `text` as `format` (the caller chooses; #6's content-type sniff is only a hint).
 * YAML, TOML and XML accept conservative subsets; other constructs are wholly opaque UNSUPPORTED.
 *
 * `budget` is validated data only and can never carry a clock: a serialized caller assertion that time
 * remains is not a trusted clock and authorizes nothing. `host` is the host-owned capability that supplies
 * the monotonic reading the `maxTimeMs` budget is measured against, read once per parse. A parse that runs
 * out of time, or whose clock is unusable, returns a whole-input `FAILURE` with no field, span or coverage.
 */
export function parseStructured(text: unknown, format: unknown, budget?: unknown, host?: unknown): ParseResult {
  if (!(FORMATS as readonly unknown[]).includes(format)) {
    return whole('JSON', typeof text === 'string' ? text : '', 'FAILURE', 'INVALID_FORMAT');
  }
  const kind = format as Format;
  if (typeof text !== 'string') return whole(kind, '', 'FAILURE', 'INVALID_INPUT');
  const limits = budgetFrom(budget);
  if (!limits) return whole(kind, text, 'FAILURE', 'INVALID_BUDGET');
  let deadline: Deadline;
  try { deadline = new Deadline(clockFrom(host), limits.maxTimeMs); }
  catch { return whole(kind, text, 'FAILURE', 'CLOCK_UNAVAILABLE'); }
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
      case 'JSON': parseJson(text, limits, into, reasons, deadline); break;
      case 'DOTENV': parseDotenv(text, into, opaque, deadline); break;
      case 'INI': parseIni(text, into, opaque, deadline); break;
      case 'URL': parseUrl(text.trim(), into, deadline, text.length - text.trimStart().length); break;
      case 'CONNECTION_STRING': parseConnectionString(text, into, deadline); break;
      case 'LOG': parseLog(text, into, opaque, deadline); break;
      case 'YAML': parseYaml(text, limits, into, deadline); break;
      case 'TOML': parseToml(text, limits, into, deadline); break;
      case 'XML': parseXml(text, limits, into, deadline); break;
    }
    // A success-shaped result is only ever returned after one more sample of the host clock, so a parse
    // that finished past its budget reports the budget instead of COMPLETE or PARTIAL coverage.
    deadline.check();
  } catch (error) {
    // No success-shaped partial parse: the whole input becomes opaque.
    if (error instanceof Budget || error instanceof Malformed) return whole(kind, text, 'FAILURE', error.reason);
    if (error instanceof Unsupported) return whole(kind, text, 'UNSUPPORTED', error.reason);
    return whole(kind, text, 'FAILURE', 'PARSER_ERROR');
  }
  if (opaque.length) reasons.add('OPAQUE_RANGES');
  if (into.comments.length) reasons.add('COMMENTS');
  return result(kind, opaque.length ? 'PARTIAL' : 'COMPLETE', into.fields, opaque, reasons,
    kind === 'LOG' ? 'FIELDS_ONLY' : 'FULL', into.comments);
}

/* ---------- Round-trip rewriting (keys and syntax preserved, or FAILURE) ---------- */

function encodeFor(syntax: ValueSyntax, replacement: string): string | null {
  if (INVALID_UNICODE.test(replacement)) return null;
  if (syntax.startsWith('XML_') && !xmlValidText(replacement)) return null;
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
    case 'YAML_PLAIN': return /^[A-Za-z0-9_.\/+~-][A-Za-z0-9._~@/+:-]*$/u.test(replacement) &&
      !yamlPrimitive(replacement) ? replacement : null;
    case 'YAML_PRIMITIVE':
    case 'TOML_PRIMITIVE': return null;
    case 'YAML_SINGLE_QUOTED': return /[\r\n]/u.test(replacement) ? null : replacement.replace(/'/gu, "''");
    case 'YAML_DOUBLE_QUOTED':
    case 'TOML_BASIC': return JSON.stringify(replacement).slice(1, -1);
    case 'TOML_LITERAL': return /['\r\n]/u.test(replacement) ? null : replacement;
    case 'XML_TEXT': return replacement.replace(/&/gu, '&amp;').replace(/</gu, '&lt;').replace(/>/gu, '&gt;')
      .replace(/\r/gu, '&#13;');
    case 'XML_DOUBLE_QUOTED': return replacement.replace(/&/gu, '&amp;').replace(/</gu, '&lt;')
      .replace(/"/gu, '&quot;').replace(/\t/gu, '&#9;').replace(/\n/gu, '&#10;').replace(/\r/gu, '&#13;');
    case 'XML_SINGLE_QUOTED': return replacement.replace(/&/gu, '&amp;').replace(/</gu, '&lt;')
      .replace(/'/gu, '&apos;').replace(/\t/gu, '&#9;').replace(/\n/gu, '&#10;').replace(/\r/gu, '&#13;');
  }
}
export interface RewriteEdit { field: ParsedField; replacement: string }
export interface RewriteOptions {
  /** REFUSE (default): sources with comments fail. REMOVE: comment text is deleted (markers kept). */
  comments?: 'REFUSE' | 'REMOVE';
  /** Validated exactly like a parse budget; applies to the source parse and the round-trip re-parse. */
  budget?: unknown;
  /** Host-owned monotonic clock, read once per parse. Never taken from the payload or from `budget`. */
  host?: unknown;
}
/** A time-expired or clock-less parse is reported as itself, never as a source-completeness problem. */
function rewriteFailure(parsed: ParseResult, fallback: string): string {
  for (const reason of parsed.reasons) if (reason === 'TIME_BUDGET_EXPIRED' || reason === 'CLOCK_UNAVAILABLE') {
    return reason;
  }
  return fallback;
}
/**
 * Replace field values, re-encoding each replacement for the syntax the parser found at that span, then
 * re-parse and require identical key paths, the replacements at edited fields and unchanged values
 * everywhere else. Any mismatch is a FAILURE: callers must not fall back to emitting the original text.
 * A source or round-trip parse that runs out of its time budget, or loses its clock, is a FAILURE too, and
 * the failure result carries no text at all.
 *
 * Caller arguments are read once inside a sanitization boundary, and a finite synchronous throw from one is
 * a FAILURE: `REWRITE_ERROR` carries no text, no exception detail, no original and no partial rewrite, so a
 * rewrite either completes every edit or emits nothing. A throwing or answer-changing getter, a value that
 * is not an edit, and an iterator that throws after yielding one all take that path. Nothing here preempts a
 * getter or callback that never returns: like the parse budget, this bounds what the parser charges, not
 * arbitrary same-process code.
 */
export function rewriteFieldValues(text: string, format: Format, edits: readonly RewriteEdit[], options: RewriteOptions = {}):
  { status: 'OK'; text: string } | { status: 'FAILURE'; reason: string } {
  try {
    // Snapshot the options both parses share, once. A getter that throws, or that answers differently later,
    // cannot swap the budget or the clock halfway through the rewrite.
    const { budget, host } = options;
    const before = parseStructured(text, format, budget, host);
    if (before.status !== 'COMPLETE' || before.coverage !== 'FULL') {
      return { status: 'FAILURE', reason: rewriteFailure(before, 'SOURCE_NOT_COMPLETE') };
    }
    if (before.reasons.includes('DUPLICATE_KEY')) return { status: 'FAILURE', reason: 'SOURCE_AMBIGUOUS' };
    if (before.comments.length && options.comments !== 'REMOVE') return { status: 'FAILURE', reason: 'SOURCE_HAS_COMMENTS' };
    const byStart = new Map(before.fields.map((field, index) => [`${field.valueStart}:${field.valueEnd}`, index]));
    const replacements = new Map<number, string>();
    for (const edit of edits) {
      // One read of each caller value per edit: a span read twice, or a replacement read once for its type
      // and again for its value, lets a getter that answers differently the second time move or swap an edit
      // that has already been decided.
      const field = edit.field;
      const index = byStart.get(`${field?.valueStart}:${field?.valueEnd}`);
      if (index === undefined || replacements.has(index)) return { status: 'FAILURE', reason: 'INVALID_EDIT' };
      const replacement = edit.replacement;
      if (typeof replacement !== 'string') return { status: 'FAILURE', reason: 'INVALID_EDIT' };
      replacements.set(index, replacement);
    }
    // Splice right to left: field values, then removed comment text, never overlapping.
    const splices: { start: number; end: number; text: string }[] = [];
    for (const [index, replacement] of replacements) {
      const field = before.fields[index]!;
      const encoded = encodeFor(field.syntax, replacement);
      if (encoded === null) return { status: 'FAILURE', reason: 'UNENCODABLE_REPLACEMENT' };
      splices.push({ start: field.valueStart, end: field.valueEnd, text: encoded });
    }
    for (const comment of before.comments) splices.push({ start: format === 'XML' ? comment.start : comment.start + 1,
      end: comment.end, text: '' });
    splices.sort((a, b) => b.start - a.start);
    let output = text;
    for (const splice of splices) output = output.slice(0, splice.start) + splice.text + output.slice(splice.end);
    const after = parseStructured(output, format, budget, host);
    if (after.status !== 'COMPLETE') return { status: 'FAILURE', reason: rewriteFailure(after, 'ROUND_TRIP_MISMATCH') };
    if (after.fields.length !== before.fields.length) return { status: 'FAILURE', reason: 'ROUND_TRIP_MISMATCH' };
    for (let index = 0; index < before.fields.length; index++) {
      const expected = replacements.get(index) ?? before.fields[index]!.value;
      if (JSON.stringify(after.fields[index]!.path) !== JSON.stringify(before.fields[index]!.path) ||
        after.fields[index]!.value !== expected) return { status: 'FAILURE', reason: 'ROUND_TRIP_MISMATCH' };
    }
    return { status: 'OK', text: output };
  } catch {
    // A finite synchronous caller-side throw is a rewrite failure, never a crash and never a partial rewrite:
    // nothing spliced or emitted leaves this branch, and the reason names no exception, cause or value.
    return { status: 'FAILURE', reason: 'REWRITE_ERROR' };
  }
}
