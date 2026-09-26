import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  normalizeInput, sniffContentType, foldForDetection, mapFoldedSpan, DEFAULT_BUDGET,
} from '../dist/normalization.js';

// Synthetic only; the marker is obviously fake and non-routable.
const MARKER = 'synthetic-protected-marker.invalid';
const b64 = (text) => Buffer.from(text, 'utf8').toString('base64');
const b64url = (text) => Buffer.from(text, 'utf8').toString('base64url');
const hex = (text) => Buffer.from(text, 'utf8').toString('hex');
const pct = (text) => encodeURIComponent(text);
const texts = (result) => result.views.map((view) => view.text);
const reachable = (result, marker = MARKER) => result.views.some((view) => view.text.includes(marker));

function prng(seed) {
  let state = seed >>> 0;
  return () => { state = (state + 0x6d2b79f5) >>> 0; let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

test('the root view is the unmodified input and plain text is COMPLETE', () => {
  const input = 'Plain text with Café and port 443.';
  const result = normalizeInput(input);
  assert.equal(result.status, 'COMPLETE');
  assert.equal(result.views.length, 1);
  assert.equal(result.views[0].text, input);
  assert.deepEqual(result.uninspected, []);
});

test('each supported encoding yields a decoded view with provenance', () => {
  for (const [encode, encoding] of [[b64, 'BASE64'], [b64url, 'BASE64URL'], [hex, 'HEX'], [pct, 'PERCENT']]) {
    const encoded = encode(`value ${MARKER} ?/>~ ??>>`);
    const input = `key=${encoded} tail`;
    const result = normalizeInput(input);
    // Base64url without `-`/`_` is indistinguishable from standard Base64.
    const expected = encoding === 'BASE64URL' && !/[-_]/u.test(encoded) ? 'BASE64' : encoding;
    const view = result.views.find((v) => v.text.includes(MARKER) && v.encoding === expected);
    assert.ok(view, encoding);
    assert.equal(view.parent, 0);
    assert.equal(view.depth, 1);
    // Percent runs are whole whitespace-delimited tokens, so the span may include the key.
    assert.ok(input.slice(view.parentStart, view.parentEnd).includes(encoded), encoding);
  }
});

test('nested Base64 -> percent -> Base64 is decoded to depth 3 with a provenance chain', () => {
  const inner = b64(`token ${MARKER}`);
  const input = `payload ${b64(`x=${pct(`t=${inner}`)}`)} end`;
  const result = normalizeInput(input);
  assert.equal(result.status, 'COMPLETE');
  const leaf = result.views.find((v) => v.text.includes(MARKER));
  const chain = [];
  for (let view = leaf; view; view = view.parent === null ? undefined : result.views[view.parent]) chain.push(view.encoding);
  assert.deepEqual(chain, ['BASE64', 'PERCENT', 'BASE64', 'ROOT']);
});

test('#6 negative: a marker beyond the depth budget is uninspected, PARTIAL and never clean', () => {
  let encoded = `${MARKER}`;
  for (let layer = 0; layer < 5; layer++) encoded = b64(`layer${layer}:${encoded}`);
  const input = `data ${encoded}`;
  const result = normalizeInput(input, { maxDepth: 3 });
  assert.equal(result.status, 'PARTIAL');
  assert.ok(result.reasons.includes('DEPTH_LIMIT'));
  assert.ok(!reachable(result));
  // The original bytes are retained: the root view still holds the full encoded payload.
  assert.equal(result.views[0].text, input);
  const span = result.uninspected[0];
  assert.equal(span.reason, 'DEPTH_LIMIT');
  assert.ok(result.views[span.viewId].text.slice(span.start, span.end).length > 0);
  // With a larger budget the same marker is reached.
  assert.ok(reachable(normalizeInput(input, { maxDepth: 6 })));
});

test('expansion, view and run-length budgets stop decoding explicitly', () => {
  const many = Array.from({ length: 40 }, (_, i) => b64(`synthetic chunk ${i} ${'x'.repeat(40)}`)).join(' ');
  const expansion = normalizeInput(many, { maxDecodedUnits: 200 });
  assert.equal(expansion.status, 'PARTIAL');
  assert.ok(expansion.reasons.includes('EXPANSION_LIMIT'));
  const views = normalizeInput(many, { maxViews: 5 });
  assert.equal(views.views.length, 6);
  assert.ok(views.reasons.includes('VIEW_LIMIT'));
  const long = normalizeInput(`blob ${b64('y'.repeat(60_000))}`);
  assert.equal(long.status, 'PARTIAL');
  assert.ok(long.reasons.includes('RUN_TOO_LONG'));
});

test('binary-looking decodes do not create views and do not drop the original run', () => {
  const input = 'sha 3f2a1b9c0d4e5f60718293a4b5c6d7e8 and internationalization';
  const result = normalizeInput(input);
  assert.equal(result.status, 'COMPLETE');
  assert.equal(result.views.length, 1);
  assert.ok(result.binaryDecodes >= 1);
  assert.equal(result.views[0].text, input);
});

test('byte input: valid UTF-8 decodes; invalid bytes FAIL with no text rather than replacement', () => {
  assert.equal(normalizeInput(new TextEncoder().encode('ok text')).views[0].text, 'ok text');
  const invalid = normalizeInput(Uint8Array.from([0x6f, 0x6b, 0xff, 0xfe]));
  assert.equal(invalid.status, 'FAILURE');
  assert.deepEqual(invalid.reasons, ['INVALID_UTF8']);
  assert.deepEqual(invalid.views, []);
});

test('malformed input and budgets fail closed', () => {
  for (const [input, budget, reason] of [
    [42, undefined, 'INVALID_INPUT'], ['bad \uD800', undefined, 'INVALID_TEXT'],
    ['x'.repeat(DEFAULT_BUDGET.maxInputUnits + 1), undefined, 'INPUT_TOO_LARGE'],
    ['x', { maxDepth: -1 }, 'INVALID_BUDGET'], ['x', { maxDepth: 99 }, 'INVALID_BUDGET'],
    ['x', { unknown: 1 }, 'INVALID_BUDGET'], ['x', null, 'INVALID_BUDGET'], ['x', { maxViews: 1.5 }, 'INVALID_BUDGET'],
  ]) {
    const result = normalizeInput(input, budget);
    assert.equal(result.status, 'FAILURE', reason);
    assert.deepEqual(result.reasons, [reason]);
  }
});

test('property: every planted encoded marker is either reached or covered by an uninspected span', () => {
  const random = prng(0x0606);
  const encoders = [b64, b64url, hex, pct];
  for (let run = 0; run < 300; run++) {
    let value = `${MARKER}-${run}`;
    const layers = 1 + Math.floor(random() * 5);
    for (let layer = 0; layer < layers; layer++) value = encoders[Math.floor(random() * 4)](`k${layer}=${value}`);
    const input = `prefix ${value} suffix`;
    const budget = { maxDepth: 1 + Math.floor(random() * 4) };
    const result = normalizeInput(input, budget);
    const found = reachable(result, `${MARKER}-${run}`);
    if (!found) {
      assert.equal(result.status, 'PARTIAL', `${layers} layers, depth ${budget.maxDepth}`);
      assert.ok(result.uninspected.length > 0);
    }
  }
});

test('adversarial inputs finish within a bounded-work budget', () => {
  const nested = (() => { let v = MARKER; for (let i = 0; i < 12; i++) v = b64(v); return v; })();
  for (const input of ['A'.repeat(1 << 20), '%41'.repeat(300_000), 'ab'.repeat(500_000), `${'x_'.repeat(400_000)}`,
    Array.from({ length: 30_000 }, (_, i) => b64(`chunk-${i}-synthetic`)).join(' ').slice(0, 1 << 20), nested]) {
    const started = process.hrtime.bigint();
    const result = normalizeInput(input);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(['COMPLETE', 'PARTIAL'].includes(result.status));
    const decoded = result.views.slice(1).reduce((total, view) => total + view.text.length, 0);
    assert.ok(decoded <= DEFAULT_BUDGET.maxDecodedUnits && result.views.length <= DEFAULT_BUDGET.maxViews + 1);
    // Catches super-linear work; not a performance SLA.
    assert.ok(elapsedMs < 5000, `${elapsedMs}ms`);
  }
});

test('content-type sniffing is a hint for parsers', () => {
  for (const [text, type] of [
    ['{"server":"api.example.com","port":443}', 'JSON'], ['[1,2]', 'JSON'], ['{not json', 'TEXT'],
    ['<?xml version="1.0"?><a/>', 'XML'], ['<config enabled="true"/>', 'XML'],
    ['API_URL=https://api.example.com\nexport DEBUG=1\n# comment', 'DOTENV'],
    ['[server]\nhost = db.example.invalid\nport = 5432', 'INI'],
    ['https://api.example.com/v1/ping?x=1', 'URL'],
    ['2026-09-26T10:00:00Z INFO start\n2026-09-26 10:00:01 WARN retry', 'LOG'],
    ['just a sentence', 'TEXT'], ['', 'TEXT'], ['\u0000\u0001\u0002binary', 'BINARY_LIKE'],
  ]) assert.equal(sniffContentType(text), type, text);
  assert.equal(normalizeInput('{"a":1}').contentType, 'JSON');
});

test('detection fold removes invisible characters and maps compatibility forms with exact offsets', () => {
  const input = 'ＡＢ​１２３−４ Café o­k ️x';
  const fold = foldForDetection(input);
  assert.equal(fold.text, 'AB123-4 Café ok x');
  const digits = fold.text.indexOf('123');
  assert.deepEqual(mapFoldedSpan(fold, digits, digits + 3), { start: 3, end: 6 });
  const cafe = fold.text.indexOf('Café');
  const span = mapFoldedSpan(fold, cafe, cafe + 4);
  assert.equal(input.slice(span.start, span.end), 'Café');
  assert.throws(() => mapFoldedSpan(fold, 3, 3), RangeError);
  assert.throws(() => foldForDetection(7), TypeError);
});
