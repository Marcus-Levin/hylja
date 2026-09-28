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
  // Several decode paths may reach the marker; the full provenance chain must be one of them.
  const chains = result.views.filter((v) => v.text.includes(MARKER)).map((leaf) => {
    const chain = [];
    for (let view = leaf; view; view = view.parent === null ? undefined : result.views[view.parent]) chain.push(view.encoding);
    return chain.join('>');
  });
  assert.ok(chains.includes('BASE64>PERCENT>BASE64>ROOT'), chains.join(' | '));
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

test('detection fold bounds compatibility expansion before allocating origin maps', () => {
  const phrase = '\uFDFA'; // One source unit expands to 18 units under NFKC.
  const fold = foldForDetection(phrase.repeat(4));
  assert.equal(fold.text.length, 72);
  assert.equal(fold.origin.length, fold.text.length);
  assert.deepEqual(mapFoldedSpan(fold, 54, 72), { start: 3, end: 4 });
  assert.throws(() => foldForDetection(phrase.repeat(1 << 20)), RangeError);
  assert.throws(() => foldForDetection(`x${'\u0301'.repeat(4096)}`), RangeError);
});

test('review regressions: binary-wrapped text is reached as TEXT or STRINGS, never hidden under COMPLETE', () => {
  const bytes = (...parts) => Buffer.concat(parts.map((p) => typeof p === 'string' ? Buffer.from(p, 'utf8') : Buffer.from(p)));
  const cases = [
    bytes([0], MARKER), bytes(MARKER, [0]), bytes('\x1b[1m', MARKER), bytes([0xff], MARKER), Buffer.from(MARKER, 'utf16le'),
  ].map((raw) => `v=${raw.toString('base64')}`);
  cases.push(`id=ff${hex(MARKER)}`, `id=cafe${hex(MARKER)}`, `q=%ff%00${[...Buffer.from(MARKER)].map((b) => `%${b.toString(16)}`).join('')}`,
    `name=%E9${pct(MARKER)}`);
  for (const input of cases) {
    const result = normalizeInput(input);
    assert.ok(reachable(result) || result.status === 'PARTIAL', input);
    assert.ok(reachable(result), input);
  }
});

test('review regressions: misaligned, odd, concatenated, wrapped and short encodings are decoded', () => {
  const wrapped = b64(`line one ${MARKER} ${'é'.repeat(40)} end`).match(/.{1,76}/gu).join('\r\n');
  for (const input of [
    `GET /files/${b64(MARKER)} HTTP/1.1`, `https://api.example.com/v1/token/${b64(MARKER)}`, `a+${b64(MARKER)}`,
    `${b64(`${MARKER}ab`)}A`, `id=a${hex(MARKER)}`, `${b64(`${MARKER}a`)}${b64('z')}`, `-----\n${wrapped}\n-----`,
  ]) assert.ok(reachable(normalizeInput(input)), input);
  // Short Basic credentials (12+ characters) are decoded for detectors.
  const basic = normalizeInput(`Authorization: Basic ${b64('user:pass')}`);
  assert.ok(basic.views.some((v) => v.text === 'user:pass'));
});

test('review regressions: uninspected spans are capped and budgets collapse to one span', () => {
  const many = Array.from({ length: 100_000 }, (_, i) => `%41${i}`).join(' ');
  const result = normalizeInput(many, { maxViews: 2 });
  assert.equal(result.status, 'PARTIAL');
  assert.ok(result.uninspected.length <= 1024);
  assert.ok(result.reasons.includes('VIEW_LIMIT'));
  const work = normalizeInput(`${b64(MARKER)} ${b64(MARKER + 'x')}`, { maxDecodeWork: 10 });
  assert.equal(work.status, 'PARTIAL');
  assert.deepEqual(work.reasons, ['WORK_LIMIT']);
  assert.equal(work.uninspected[0].end, work.views[0].text.length);
});

test('review regressions: budget keys, BOM, fold ordering and size, sniff hints', () => {
  for (const budget of [{ constructor: 5 }, { toString: 3 }, { hasOwnProperty: 1 }]) {
    assert.deepEqual(normalizeInput('x', budget).reasons, ['INVALID_BUDGET']);
  }
  assert.equal(normalizeInput(Uint8Array.from([0xef, 0xbb, 0xbf, 0x61])).views[0].text, '﻿a');
  const fold = foldForDetection('o­́k');
  assert.equal(fold.text, 'ók');
  assert.deepEqual(mapFoldedSpan(fold, 0, 1), { start: 0, end: 3 });
  assert.throws(() => foldForDetection('x'.repeat(DEFAULT_BUDGET.maxInputUnits + 1)), RangeError);
  assert.equal(sniffContentType('<b>hi'), 'TEXT');
  assert.equal(sniffContentType('\x1b[32mINFO\x1b[0m started\n\x1b[31mERROR\x1b[0m failed'), 'TEXT');
});

test('property: a random single-byte binary prefix never hides a planted marker under COMPLETE', () => {
  const random = prng(0x6060);
  for (let run = 0; run < 300; run++) {
    const marker = `${MARKER}-${run}`;
    const raw = Buffer.concat([Buffer.from([Math.floor(random() * 256)]), Buffer.from(marker)]);
    const encoded = [raw.toString('base64'), raw.toString('base64url'), raw.toString('hex'),
      [...raw].map((b) => `%${b.toString(16).padStart(2, '0')}`).join('')][Math.floor(random() * 4)];
    const result = normalizeInput(`x=${encoded} y`);
    assert.ok(reachable(result, marker) || result.status === 'PARTIAL', encoded);
  }
});


test('rereview: disjoint identical copies are all recorded as occurrences', () => {
  const encoded = b64('synthetic-user:synthetic-pass.invalid');
  const input = `Authorization: Basic ${encoded}\nX-Forwarded-Auth: Basic ${encoded}\nx=${hex('synthetic-user:synthetic-pass.invalid')}`;
  const result = normalizeInput(input);
  const views = result.views.filter((v) => v.text === 'synthetic-user:synthetic-pass.invalid');
  const spans = views.flatMap((v) => v.occurrences.map((o) => input.slice(o.start, o.end)));
  assert.equal(spans.filter((s) => s === encoded).length, 2);
  assert.ok(spans.some((s) => s.startsWith(hex('synthetic'))));
});

test('rereview: UTF-16 variants and Base64 glued to letters are reached', () => {
  const le = Buffer.from(MARKER, 'utf16le');
  const be = Buffer.from(MARKER, 'utf16le').swap16();
  for (const raw of [Buffer.concat([le, Buffer.from([0x41])]), Buffer.concat([Buffer.from([1, 0]), le]),
    Buffer.concat([Buffer.from([0x00, 0xd8]), le]), be]) {
    assert.ok(reachable(normalizeInput(`v=${raw.toString('base64')}`)), raw.toString('hex').slice(0, 12));
  }
  for (const prefix of ['token', 'abc', 'x', 'ab']) assert.ok(reachable(normalizeInput(`${prefix}${b64(MARKER)}`)), prefix);
});

test('rereview: ordinary binary attachments stay COMPLETE and produce at most one view per run', () => {
  const random = prng(0x6161);
  const blob = () => Buffer.from(Array.from({ length: 48_000 }, () => Math.floor(random() * 256))).toString('base64');
  const payload = JSON.stringify({ files: Array.from({ length: 7 }, (_, i) => ({ name: `f${i}.bin`, data: blob() })) });
  const result = normalizeInput(payload);
  assert.equal(result.status, 'COMPLETE');
  // One direct view per blob at most; noise strings may themselves nest, which is bounded by the budgets.
  assert.ok(result.views.filter((v) => v.parent === 0).length <= 7);
  assert.deepEqual(result.uninspected, []);
});

test('rereview: fold accepts an explicit limit up to the hard input limit', () => {
  assert.equal(foldForDetection('x'.repeat(DEFAULT_BUDGET.maxInputUnits + 1), 2 << 20).text.length, DEFAULT_BUDGET.maxInputUnits + 1);
  assert.throws(() => foldForDetection('x', 1 << 30), RangeError);
});


test('second rereview: a marker at one alignment survives a longer benign string at another', () => {
  for (const sep of ['x', 'xy', 'xyz']) {
    const first = Buffer.concat([Buffer.from([0]), Buffer.from(`${MARKER}!`)]).toString('base64');
    const input = `v=${first}${sep}${b64('a benign printable sentence that is long enough to win')}`;
    assert.ok(reachable(normalizeInput(input)), sep);
  }
});

test('second rereview: a multi-megabyte run is RUN_TOO_LONG, never a throw', () => {
  for (const input of ['A'.repeat(8 << 20), 'ab'.repeat(4 << 20), `${'/AAAAAAAAAAAAAAA'.repeat(1 << 19)}`]) {
    const result = normalizeInput(input, { maxInputUnits: 16 << 20 });
    assert.ok(['PARTIAL', 'FAILURE'].includes(result.status));
    if (result.status === 'PARTIAL') assert.ok(result.reasons.includes('RUN_TOO_LONG'));
  }
});

test('second rereview: many short encoded tokens stay within a bounded-work budget', () => {
  for (const input of [`${'%01' + 'a'.repeat(17) + '_ '}`.repeat(45_000), '0'.repeat(17).concat(' ').repeat(55_000),
    'AAAAAAAAAAAA '.repeat(80_000), '%41 '.repeat(260_000)]) {
    const started = process.hrtime.bigint();
    const result = normalizeInput(input.slice(0, 1 << 20));
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(['COMPLETE', 'PARTIAL'].includes(result.status));
    assert.ok(elapsedMs < 5000, `${elapsedMs}ms`);
  }
});
