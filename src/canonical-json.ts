/**
 * Bounded canonical JSON for release evidence and conformance suites.
 *
 * The form is the RFC 8785 (JCS) style: no insignificant whitespace, object members sorted by
 * UTF-16 code unit, minimal string escaping, and integers only. JCS itself is not reproduced:
 * ECMAScript number formatting (Section 7.1.12.1 of ECMA-262) is deliberately out of scope, so a
 * non-integer, `-0` or out-of-range number is refused instead of being formatted. Parsing is
 * `JSON.parse` plus an exact re-serialization comparison, which is what rejects duplicate keys,
 * ignored duplicate escapes, alternative number spellings and non-canonical whitespace: a document
 * that survives is byte-identical to its own canonical form, so the digest and the signature over
 * it cannot be made to mean two different documents.
 */
import { createHash } from 'node:crypto';

export const CANONICAL_JSON_VERSION = 'hylja.canonical-json.v1' as const;
/** Bounds applied to the value graph before any byte is produced. */
export const MAX_CANONICAL_DEPTH = 24;
export const MAX_CANONICAL_MEMBERS = 4096;
export const MAX_CANONICAL_STRING = 4096;

export type CanonicalFailureCode =
  | 'NOT_AN_OBJECT' | 'NOT_CANONICALIZABLE' | 'NOT_AN_INTEGER' | 'NOT_UNICODE' | 'STRING_TOO_LONG'
  | 'DEPTH_EXCEEDED' | 'MEMBER_EXCEEDED' | 'NOT_UTF8' | 'NOT_JSON' | 'NOT_CANONICAL' | 'TOO_LARGE';

export class CanonicalJsonFailure extends Error {
  constructor(readonly code: CanonicalFailureCode) {
    // The code is a fixed vocabulary item; the offending value, path and message never appear.
    super(`canonical JSON rejected (${code})`);
    this.name = 'CanonicalJsonFailure';
  }
}

const ESCAPES: Readonly<Record<string, string>> = Object.freeze({
  '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t',
});
const decoder = new TextDecoder('utf-8', { fatal: true });

function isPlainObject(value: object): boolean {
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}
function encodeString(value: string, out: string[]): void {
  if (value.length > MAX_CANONICAL_STRING) throw new CanonicalJsonFailure('STRING_TOO_LONG');
  // Lone surrogates are not Unicode scalar values (RFC 8785 requires I-JSON compatible strings).
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = index + 1 < value.length ? value.charCodeAt(index + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) throw new CanonicalJsonFailure('NOT_UNICODE');
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new CanonicalJsonFailure('NOT_UNICODE');
    }
  }
  out.push('"');
  for (const character of value) {
    const escape = ESCAPES[character];
    if (escape !== undefined) { out.push(escape); continue; }
    const unit = character.codePointAt(0) as number;
    if (unit < 0x20) { out.push(`\\u${unit.toString(16).padStart(4, '0')}`); continue; }
    out.push(character);
  }
  out.push('"');
}
function write(value: unknown, out: string[], depth: number, state: { members: number }): void {
  if (depth > MAX_CANONICAL_DEPTH) throw new CanonicalJsonFailure('DEPTH_EXCEEDED');
  if (value === null) { out.push('null'); return; }
  switch (typeof value) {
    case 'boolean': out.push(value ? 'true' : 'false'); return;
    case 'number': {
      if (!Number.isInteger(value) || Object.is(value, -0) || !Number.isSafeInteger(value)) {
        throw new CanonicalJsonFailure('NOT_AN_INTEGER');
      }
      out.push(String(value));
      return;
    }
    case 'string': encodeString(value, out); return;
    case 'object': break;
    default: throw new CanonicalJsonFailure('NOT_CANONICALIZABLE');
  }
  if (Array.isArray(value)) {
    out.push('[');
    for (let index = 0; index < value.length; index += 1) {
      state.members += 1;
      if (state.members > MAX_CANONICAL_MEMBERS) throw new CanonicalJsonFailure('MEMBER_EXCEEDED');
      if (index > 0) out.push(',');
      write((value as unknown[])[index], out, depth + 1, state);
    }
    out.push(']');
    return;
  }
  if (!isPlainObject(value as object)) throw new CanonicalJsonFailure('NOT_AN_OBJECT');
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  out.push('{');
  let written = 0;
  for (const key of keys) {
    state.members += 1;
    if (state.members > MAX_CANONICAL_MEMBERS) throw new CanonicalJsonFailure('MEMBER_EXCEEDED');
    // Read each member once through a data descriptor: no caller getter runs during signing.
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor || !('value' in descriptor)) throw new CanonicalJsonFailure('NOT_CANONICALIZABLE');
    if (written > 0) out.push(',');
    encodeString(key, out);
    out.push(':');
    write(descriptor.value, out, depth + 1, state);
    written += 1;
  }
  out.push('}');
}

/**
 * Serialize a bounded JSON value to its canonical UTF-8 bytes. Throws `CanonicalJsonFailure` with a
 * fixed code for anything outside the supported subset; never returns partial bytes.
 */
export function canonicalJson(value: unknown): Uint8Array {
  const out: string[] = [];
  write(value, out, 0, { members: 0 });
  return new TextEncoder().encode(out.join(''));
}

/**
 * Parse bytes that must already be in canonical form. Rejects non-UTF-8, malformed JSON, duplicate
 * or non-canonical encodings and anything above `maxBytes`, without echoing the content.
 */
export function parseCanonicalJson(bytes: Uint8Array, maxBytes: number): unknown {
  if (!(bytes instanceof Uint8Array) || bytes.length > maxBytes) throw new CanonicalJsonFailure('TOO_LARGE');
  let text: string;
  try {
    text = decoder.decode(bytes);
  } catch { throw new CanonicalJsonFailure('NOT_UTF8'); }
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { throw new CanonicalJsonFailure('NOT_JSON'); }
  let canonical: Uint8Array;
  try { canonical = canonicalJson(parsed); } catch (error) {
    if (error instanceof CanonicalJsonFailure) throw error;
    throw new CanonicalJsonFailure('NOT_CANONICALIZABLE');
  }
  let encoded: string;
  try { encoded = new TextDecoder('utf-8', { fatal: true }).decode(canonical); } catch {
    throw new CanonicalJsonFailure('NOT_CANONICAL');
  }
  if (encoded !== text) throw new CanonicalJsonFailure('NOT_CANONICAL');
  return parsed;
}

/** SHA-256 over exact bytes, lowercase hex. Not an authorization token and not a signature. */
export function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}
