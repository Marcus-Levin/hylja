import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  CANONICAL_JSON_VERSION, CanonicalJsonFailure, MAX_CANONICAL_DEPTH, MAX_CANONICAL_MEMBERS,
  MAX_CANONICAL_STRING, canonicalJson, parseCanonicalJson, sha256Hex,
} from '../dist/canonical-json.js';
import { decodeBase64Strict, isLowerHex } from '../dist/byte-encoding.js';

const encode = (value) => new TextEncoder().encode(value);
const parse = (text) => parseCanonicalJson(encode(text), 1 << 20);
const code = (text) => {
  try { parse(text); return null; } catch (error) {
    assert.ok(error instanceof CanonicalJsonFailure, 'a rejection must be a CanonicalJsonFailure');
    return error.code;
  }
};
const canonicalCode = (value) => {
  try { canonicalJson(value); return null; } catch (error) {
    assert.ok(error instanceof CanonicalJsonFailure);
    return error.code;
  }
};

test('canonical JSON is deterministic, sorted and minimally escaped', () => {
  assert.equal(CANONICAL_JSON_VERSION, 'hylja.canonical-json.v1');
  assert.equal(new TextDecoder().decode(canonicalJson({ b: 1, a: 2 })), '{"a":2,"b":1}');
  assert.equal(new TextDecoder().decode(canonicalJson({ 'ä': 'ö', A: 'z' })), '{"A":"z","ä":"ö"}');
  // Sorting is by UTF-16 code unit, so an astral key sorts after every BMP key, as JCS requires.
  assert.equal(new TextDecoder().decode(canonicalJson({ '\u{10000}': 1, '￿': 2 })), '{"\u{10000}":1,"￿":2}');
  assert.equal(new TextDecoder().decode(canonicalJson(['a', null, true, -1])), '["a",null,true,-1]');
  assert.equal(new TextDecoder().decode(canonicalJson('a"b\\c\nd\tef')), '"a\\"b\\\\c\\nd\\te\\u0001f"');
  assert.equal(new TextDecoder().decode(canonicalJson({})), '{}');
  assert.deepEqual(Buffer.from(canonicalJson({ a: [1, { b: 2 }] })), Buffer.from('{"a":[1,{"b":2}]}'));
});

test('non-integer, non-finite and non-scalar values are refused', () => {
  assert.equal(canonicalCode(1.5), 'NOT_AN_INTEGER');
  assert.equal(canonicalCode(-0), 'NOT_AN_INTEGER');
  assert.equal(canonicalCode(Number.NaN), 'NOT_AN_INTEGER');
  assert.equal(canonicalCode(Number.POSITIVE_INFINITY), 'NOT_AN_INTEGER');
  assert.equal(canonicalCode(Number.MAX_SAFE_INTEGER + 2), 'NOT_AN_INTEGER');
  assert.equal(canonicalCode(undefined), 'NOT_CANONICALIZABLE');
  assert.equal(canonicalCode(() => 1), 'NOT_CANONICALIZABLE');
  assert.equal(canonicalCode(new Date(0)), 'NOT_AN_OBJECT');
  assert.equal(canonicalCode(new Map()), 'NOT_AN_OBJECT');
  assert.equal(canonicalCode(new Set()), 'NOT_AN_OBJECT');
  assert.equal(canonicalCode('a'.repeat(MAX_CANONICAL_STRING + 1)), 'STRING_TOO_LONG');
  assert.equal(canonicalCode('\ud800'), 'NOT_UNICODE');
  assert.equal(canonicalCode('\udc00x'), 'NOT_UNICODE');
});

test('depth, member count and accessor members are bounded', () => {
  let deep = 0;
  for (let index = 0; index <= MAX_CANONICAL_DEPTH; index += 1) deep = { deep };
  assert.equal(canonicalCode(deep), 'DEPTH_EXCEEDED');
  const wide = {};
  for (let index = 0; index <= MAX_CANONICAL_MEMBERS; index += 1) wide[`k${index}`] = index;
  assert.equal(canonicalCode(wide), 'MEMBER_EXCEEDED');
  // A getter member is never invoked by the serializer: it is refused, not called.
  let called = false;
  const withAccessor = { safe: 1 };
  Object.defineProperty(withAccessor, 'trap', { enumerable: true, get() { called = true; return 2; } });
  assert.equal(canonicalCode(withAccessor), 'NOT_CANONICALIZABLE');
  assert.equal(called, false);
});

test('parsing requires the exact canonical byte form', () => {
  assert.deepEqual(parse('{"a":1}'), { a: 1 });
  assert.equal(code('{"a": 1}'), 'NOT_CANONICAL');
  assert.equal(code('{"a":1}\n'), 'NOT_CANONICAL');
  assert.equal(code('{ "a" : 1 }'), 'NOT_CANONICAL');
  assert.equal(code('{"a":1,"a":2}'), 'NOT_CANONICAL');
  assert.equal(code('{"a":1,"b":2,"a":3}'), 'NOT_CANONICAL');
  assert.equal(code('{"\\u0061":1}'), 'NOT_CANONICAL');
  // JSON.parse cannot see the original number spelling, so these are caught by the byte comparison.
  assert.equal(code('{"a":1.0}'), 'NOT_CANONICAL');
  assert.equal(code('{"a":1e2}'), 'NOT_CANONICAL');
  assert.equal(code('{"a":1.5}'), 'NOT_AN_INTEGER');
  assert.equal(code('{"a":"\\u0041"}'), 'NOT_CANONICAL');
  assert.equal(code('{"a":01}'), 'NOT_JSON');
  assert.equal(code(''), 'NOT_JSON');
  // A top-level array is canonical JSON, but not a document this gate accepts as an object.
  assert.deepEqual(parse('[]'), []);
  // Invalid UTF-8 bytes are refused as such, never repaired with a replacement character, and a
  // lone continuation byte inside a string is not silently decoded either.
  assert.throws(() => parseCanonicalJson(Uint8Array.of(0x7b, 0xff, 0x7d), 16), (error) => error.code === 'NOT_UTF8');
  // WTF-8 bytes that encode a lone surrogate are refused, not decoded into U+FFFD.
  assert.throws(() => parseCanonicalJson(Uint8Array.of(0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xed, 0xa0, 0x80, 0x22, 0x7d), 16),
    (error) => error.code === 'NOT_UTF8');
  assert.throws(() => parseCanonicalJson(encode('{"a":1}'), 2), (error) => error.code === 'TOO_LARGE');
  assert.throws(() => parseCanonicalJson('not bytes', 16), (error) => error.code === 'TOO_LARGE');
});

test('a canonical round trip is stable for a realistic evidence-shaped document', () => {
  const document = {
    adapters: [{ adapterId: 'synthetic-adapter-a', evidenceSha256: 'a'.repeat(64) }],
    artifact: { bytes: 220, name: 'synthetic.tgz', sha256: 'b'.repeat(64) },
    format: 'hylja-release-evidence/v1',
    release: { commit: 'c'.repeat(40), profileId: 'synthetic-profile', scopeRef: 'synthetic-scope', version: '0.1.0' },
  };
  const bytes = canonicalJson(document);
  const once = parseCanonicalJson(bytes, 1 << 20);
  assert.deepEqual(Buffer.from(canonicalJson(once)), Buffer.from(bytes));
  assert.equal(sha256Hex(bytes), sha256Hex(canonicalJson(once)));
  assert.match(sha256Hex(bytes), /^[0-9a-f]{64}$/);
});

test('base64 decoding is canonical, bounded and exact', () => {
  assert.deepEqual(Buffer.from(decodeBase64Strict('AAAA', 8)), Buffer.from([0, 0, 0]));
  assert.deepEqual(Buffer.from(decodeBase64Strict('QUJD', 8)), Buffer.from([0x41, 0x42, 0x43]));
  assert.deepEqual(Buffer.from(decodeBase64Strict('QUI=', 8)), Buffer.from([0x41, 0x42]));
  assert.deepEqual(Buffer.from(decodeBase64Strict('QQ==', 8)), Buffer.from([0x41]));
  assert.equal(decodeBase64Strict('QQ=', 8), null, 'wrong length');
  assert.equal(decodeBase64Strict('QQ', 8), null);
  assert.equal(decodeBase64Strict('Q Q==', 8), null, 'whitespace is not base64');
  assert.equal(decodeBase64Strict('QUJ$', 8), null, 'the URL-safe alphabet is not base64');
  assert.equal(decodeBase64Strict('QQ==', 0), null, 'oversize result');
  assert.equal(decodeBase64Strict('', 8), null);
  assert.equal(decodeBase64Strict('QR==', 8), null, 'non-canonical trailing bits');
  assert.equal(decodeBase64Strict('QUJDRA==', 3), null, 'more than the bound');
  assert.deepEqual(Buffer.from(decodeBase64Strict('QUJDRA==', 4)), Buffer.from([0x41, 0x42, 0x43, 0x44]));
  assert.equal(isLowerHex('0a'.repeat(32), 64), true);
  assert.equal(isLowerHex('0A'.repeat(32), 64), false, 'uppercase is not the canonical digest form');
  assert.equal(isLowerHex('0a'.repeat(31), 64), false);
  assert.equal(isLowerHex('0g'.repeat(32), 64), false);
});
