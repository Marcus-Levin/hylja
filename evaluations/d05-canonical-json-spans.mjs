// Evaluator-private public D05 source -> #5 canonical JSON byte spans.
// SYNTHETIC-ONLY, NON-ENFORCING, unscored development contract. No oracle import.
export const D05_CANONICAL_JSON_SPAN_VERSION = 'd05-canonical-json-v1';

const MAX_RAW_BYTES = 131_072;
const MAX_DEPTH = 16;
const MAX_TOKENS = 2_048;
const MAX_FIELD_BYTES = 65_536;
const D05_ID = 'D05-DEV-001';
const D05_PATH = '/fixtures/2/input/value';
const STRING_KEYS = ['customer', 'endpointUrl', 'os', 'outputPath', 'project', 'protocol'];
const NUMBER_KEYS = ['port', 'timeoutMs'];
const VALUE_KEYS = [...STRING_KEYS, ...NUMBER_KEYS].sort();
const OCCURRENCE_KEYS = ['customer', 'project', 'endpointUrl', 'outputPath'];
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function invalid() { throw new TypeError('Invalid public D05 span projection input'); }
function safe(action) { try { return action(); } catch { return invalid(); } }
function record(value, required, optional = []) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.length < required.length || keys.length > required.length + optional.length) invalid();
  const result = Object.create(null);
  for (const key of keys) {
    if (typeof key !== 'string' || !required.includes(key) && !optional.includes(key)) invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
    result[key] = descriptor.value;
  }
  if (required.some((key) => !Object.hasOwn(result, key))) invalid();
  return result;
}
function ownValue(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid();
  return descriptor.value;
}

// Parse the ENTIRE raw fixture before any JS JSON.parse. Every object checks unique *decoded*
// keys, including aliases made with \u escapes, at every depth. The parser also rejects
// malformed JSON, invalid escapes, lone surrogate pairs, depth/token/byte overflows.
// Raw token text is kept only in this ephemeral evaluator-private snapshot.
function parseRawFixture(bytes) {
  if (Object.getPrototypeOf(bytes) !== Uint8Array.prototype ||
    bytes.length < 1 || bytes.length > MAX_RAW_BYTES) invalid();
  const text = decoder.decode(bytes);
  if (text.charCodeAt(0) === 0xfeff) invalid();
  let cursor = 0;
  let nodes = 0;
  function whitespace() { while (/[\x20\x09\x0a\x0d]/u.test(text[cursor] ?? '')) cursor++; }
  function string() {
    if (text[cursor++] !== '"') invalid();
    const begin = cursor - 1;
    let decoded = '';
    let escaped = false;
    while (cursor < text.length) {
      const char = text[cursor++];
      if (char === '"') return { value: decoded, raw: text.slice(begin, cursor), escaped };
      if (char === '\\') {
        escaped = true;
        const escape = text[cursor++];
        const literals = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
        if (Object.hasOwn(literals, escape)) { decoded += literals[escape]; continue; }
        if (escape !== 'u') invalid();
        function hex() {
          const four = text.slice(cursor, cursor + 4);
          if (!/^[0-9a-fA-F]{4}$/u.test(four)) invalid();
          cursor += 4;
          return Number.parseInt(four, 16);
        }
        const point = hex();
        if (point >= 0xdc00 && point <= 0xdfff) invalid();
        if (point >= 0xd800 && point <= 0xdbff) {
          if (text.slice(cursor, cursor + 2) !== '\\u') invalid();
          cursor += 2;
          const low = hex();
          if (low < 0xdc00 || low > 0xdfff) invalid();
          decoded += String.fromCodePoint(0x10000 + (point - 0xd800) * 1024 + low - 0xdc00);
        } else decoded += String.fromCharCode(point);
      } else {
        const point = char.charCodeAt(0);
        if (point < 0x20 || point >= 0xd800 && point <= 0xdfff) {
          // UTF-8 decoder already refuses raw surrogates; a valid astral pair is two JS
          // code units, so handle it explicitly rather than losing code-point identity.
          if (point >= 0xd800 && point <= 0xdbff) {
            const low = text.charCodeAt(cursor);
            if (!(low >= 0xdc00 && low <= 0xdfff)) invalid();
            decoded += char + text[cursor++];
            continue;
          }
          invalid();
        }
        decoded += char;
      }
    }
    return invalid();
  }
  function value(depth) {
    if (++nodes > MAX_TOKENS || depth > MAX_DEPTH) invalid();
    whitespace();
    const char = text[cursor];
    if (char === '"') return { kind: 'string', ...string() };
    if (char === '{') {
      cursor++;
      const entries = new Map();
      whitespace();
      if (text[cursor] === '}') { cursor++; return { kind: 'object', entries }; }
      while (true) {
        whitespace();
        const key = string();
        if (entries.has(key.value)) invalid(); // MUST precede any lossy parse or object assignment.
        whitespace();
        if (text[cursor++] !== ':') invalid();
        const entry = value(depth + 1);
        entries.set(key.value, { key, entry });
        whitespace();
        const separator = text[cursor++];
        if (separator === '}') return { kind: 'object', entries };
        if (separator !== ',') invalid();
      }
    }
    if (char === '[') {
      cursor++;
      const elements = [];
      whitespace();
      if (text[cursor] === ']') { cursor++; return { kind: 'array', elements }; }
      while (true) {
        elements.push(value(depth + 1));
        whitespace();
        const separator = text[cursor++];
        if (separator === ']') return { kind: 'array', elements };
        if (separator !== ',') invalid();
      }
    }
    if (char === 't' && text.slice(cursor, cursor + 4) === 'true') {
      cursor += 4; return { kind: 'boolean', value: true };
    }
    if (char === 'f' && text.slice(cursor, cursor + 5) === 'false') {
      cursor += 5; return { kind: 'boolean', value: false };
    }
    if (char === 'n' && text.slice(cursor, cursor + 4) === 'null') {
      cursor += 4; return { kind: 'null', value: null };
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(text.slice(cursor));
    if (!number) invalid();
    cursor += number[0].length;
    const parsed = Number(number[0]);
    if (!Number.isFinite(parsed)) invalid();
    return { kind: 'number', raw: number[0], value: parsed };
  }
  const root = value(0);
  whitespace();
  if (cursor !== text.length || root.kind !== 'object') invalid();
  return root;
}
function at(object, key, kind) {
  if (object?.kind !== 'object') invalid();
  const entry = object.entries.get(key)?.entry;
  if (!entry || kind && entry.kind !== kind) invalid();
  return entry;
}
function d05Snapshot(raw) {
  const fixtures = at(raw, 'fixtures', 'array').elements;
  if (fixtures.length !== 3) invalid();
  // Only one bound D05 at exactly index 2; an id elsewhere is ambiguous, not provenance.
  if (fixtures.filter((item) => item?.kind === 'object' &&
    item.entries.get('fixtureId')?.entry.value === D05_ID).length !== 1) invalid();
  const fixture = fixtures[2];
  if (at(fixture, 'fixtureId', 'string').value !== D05_ID ||
    at(fixture, 'familyId', 'string').value !== 'D05' ||
    at(fixture, 'partition', 'string').value !== 'development') invalid();
  const input = at(fixture, 'input', 'object');
  if (input.entries.size !== 2 || at(input, 'format', 'string').value !== 'json-object') invalid();
  const object = at(input, 'value', 'object');
  if (object.entries.size !== VALUE_KEYS.length ||
    VALUE_KEYS.some((key) => !object.entries.has(key))) invalid();
  const leaves = new Map();
  for (const key of VALUE_KEYS) {
    const { key: rawKey, entry } = object.entries.get(key);
    // No escaped/Unicode/ambiguous D05 keys, leaves, nested objects or arrays in v1.
    if (rawKey.escaped || rawKey.raw !== `"${key}"`) invalid();
    if (STRING_KEYS.includes(key)) {
      if (entry.kind !== 'string' || entry.escaped || entry.value.length > 4096 ||
        !/^[\x20-\x21\x23-\x5b\x5d-\x7e]+$/u.test(entry.value) ||
        entry.raw !== `"${entry.value}"`) invalid();
    } else if (entry.kind !== 'number' || !Number.isSafeInteger(entry.value) ||
      entry.value < 0 || entry.value > 1_000_000 || entry.raw !== String(entry.value)) invalid();
    leaves.set(key, entry.value);
  }
  return leaves;
}
function canonicalField(leaves) {
  // Independent pinned reconstruction of the landed adapter's
  // JSON.stringify(jsonCanonical(snapshot)): lexicographically sorted keys, no spaces.
  // Walk its ACTUAL emitted bytes to anchor each string leaf to a key/token boundary;
  // never use global value.indexOf or candidate output to infer positions.
  const canonical = JSON.stringify(Object.fromEntries(VALUE_KEYS.map((key) => [key, leaves.get(key)])));
  const bytes = encoder.encode(canonical);
  if (!bytes.length || bytes.length > MAX_FIELD_BYTES) invalid();
  const positions = new Map();
  let cursor = 0;
  function take(char) { if (bytes[cursor++] !== char.charCodeAt(0)) invalid(); }
  function ascii(value) { for (const character of value) take(character); }
  take('{');
  for (let index = 0; index < VALUE_KEYS.length; index++) {
    const key = VALUE_KEYS[index];
    if (index) take(',');
    take('"'); ascii(key); take('"'); take(':');
    const value = leaves.get(key);
    if (typeof value === 'string') {
      take('"');
      const boundaries = [cursor];
      // Each accepted D05 code point is one ASCII byte, but store a genuine per-point
      // boundary table: offsets remain attached to the actual serialized lexeme.
      for (const point of value) { ascii(point); boundaries.push(cursor); }
      take('"');
      positions.set(key, Object.freeze({ decoded: value, boundaries: Object.freeze(boundaries) }));
    } else ascii(String(value));
  }
  take('}');
  if (cursor !== bytes.length) invalid();
  return { canonical, bytes, positions };
}
function hostBounds(url) {
  // This bounded public D05 URL subset excludes userinfo, percent-encoding, fragments,
  // escaped/non-ASCII forms and alternate/ambiguous authorities. The HOST is not a full URL.
  const match = /^https:\/\/((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+invalid)(?::([1-9][0-9]{0,4}))?(?:\/[a-zA-Z0-9/._-]*)?$/u.exec(url);
  if (!match || match[2] !== undefined && Number(match[2]) > 65535) invalid();
  return { start: 'https://'.length, end: 'https://'.length + match[1].length };
}

/**
 * Requires the caller-supplied bounded full raw public fixture UTF-8 bytes plus a
 * separate landed adapter projection. Verifies internal raw-source self-consistency,
 * NOT file authenticity: an external custodian/pinned file digest is still required
 * for scored provenance. Parsed objects/fragments cannot prove duplicate-key absence.
 * Never return a scored eligibility flag.
 */
export function createPublicD05SpanProjector(options) {
  return safe(() => {
    const args = record(options, ['rawFixtureUtf8', 'projection', 'fixtureId', 'sourceValuePath']);
    if (args.fixtureId !== D05_ID || args.sourceValuePath !== D05_PATH) invalid();
    const raw = parseRawFixture(args.rawFixtureUtf8);
    const leaves = d05Snapshot(raw);
    const endpointHost = hostBounds(leaves.get('endpointUrl')); // Reject ambiguous syntax even with zero occurrences.
    const { canonical, bytes, positions } = canonicalField(leaves);
    const projection = args.projection;
    if (projection === null || typeof projection !== 'object' || !Object.isFrozen(projection)) invalid();
    const developmentCase = ownValue(projection, 'developmentCase');
    if (developmentCase === null || typeof developmentCase !== 'object' ||
      !Object.isFrozen(developmentCase) || ownValue(developmentCase, 'id') !== D05_ID ||
      ownValue(developmentCase, 'familyId') !== 'D05' ||
      ownValue(developmentCase, 'partition') !== 'development') invalid();
    const fields = ownValue(developmentCase, 'fields');
    if (!Array.isArray(fields) || !Object.isFrozen(fields) || fields.length !== 1 ||
      !Object.isFrozen(fields[0]) || ownValue(fields[0], 'ref') !== 'field-0') invalid();
    const field = ownValue(fields[0], 'content');
    if (typeof field !== 'string' || field !== canonical ||
      !encoder.encode(field).every((byte, index) => byte === bytes[index])) invalid();
    return Object.freeze({ version: D05_CANONICAL_JSON_SPAN_VERSION,
      projectSourceOccurrence(source) {
        return safe(() => {
          const occurrence = record(source,
            ['fixtureId', 'path', 'sourceSpan', 'normalizedSpan', 'sourceOriginalText']);
          if (occurrence.fixtureId !== D05_ID || typeof occurrence.path !== 'string' ||
            !OCCURRENCE_KEYS.some((key) => occurrence.path === `${D05_PATH}/${key}`)) invalid();
          const key = occurrence.path.slice(D05_PATH.length + 1);
          const leaf = positions.get(key);
          if (!leaf) invalid();
          const startEnd = record(occurrence.sourceSpan, ['start', 'end']);
          const normalized = record(occurrence.normalizedSpan, ['start', 'end']);
          const { start, end } = startEnd;
          if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) ||
            start < 0 || end <= start || end >= leaf.boundaries.length ||
            normalized.start !== start || normalized.end !== end) invalid();
          if (key === 'endpointUrl' &&
            (start !== endpointHost.start || end !== endpointHost.end)) invalid();
          const decoded = Array.from(leaf.decoded).slice(start, end).join('');
          if (occurrence.sourceOriginalText !== decoded) invalid();
          const byteStart = leaf.boundaries[start];
          const byteEnd = leaf.boundaries[end];
          // This string is the exact raw serialized JSON lexeme slice, not the source
          // path/key, normalized claim, candidate spelling or full unprotected URL.
          const value = decoder.decode(bytes.subarray(byteStart, byteEnd));
          if (value !== decoded) invalid();
          return Object.freeze({ fieldRef: 'field-0', start: byteStart, end: byteEnd, value });
        });
      },
    });
  });
}
