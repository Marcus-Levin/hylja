/**
 * #7 explicit parser time/deadline budget: deterministic fake-clock regressions.
 *
 * Synthetic only. Every value below is invented and non-routable (`.invalid` hosts, `SYNTHETIC-*` markers),
 * and every clock is injected, so no case waits for a real wall-clock expiration, spins a busy loop or
 * simulates CPU stress. The cases assert contract behavior, not latency: there is no timing threshold here.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  parseStructured, rewriteFieldValues, isParseHost, DEFAULT_PARSE_BUDGET, MAX_PARSE_TIME_MS, FORMATS,
} from '../dist/structured-parsers.js';
import { detectNormalizedCandidates } from '../dist/normalized-detection.js';
import { checkEgress, createKnownOriginals } from '../dist/egress-sentinel.js';
import { composeClassification } from '../dist/classification.js';
import { decidePolicy, digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE } from '../dist/policy.js';

const scope = Object.freeze({ tenantRef: 'tenant-a.invalid', projectRef: 'project-a.invalid' });
const whole = (result) => result.opaque.map((range) => [range.start, range.end]);
/** A clock that reads `0` at the start sample and 5000 ms at every later one: past any legal budget. */
function stepping(step = 5000) {
  const clock = { reads: 0, now: () => { clock.reads += 1; return (clock.reads - 1) * step; } };
  return clock;
}
/** A clock that never moves, so a parse with a working clock is never mistaken for an expired one. */
const frozen = () => ({ now: () => 0 });

/* ---------- Ordinary synthetic documents, one per supported format ---------- */

const SMALL = {
  JSON: '{"host":"h.example.invalid","password":"SYNTHETIC-pw","list":[{"token":"SYNTHETIC-tok"},7]}',
  DOTENV: 'HOST=h.example.invalid\nPASSWORD="SYNTHETIC-pw"\nMODE=safe',
  INI: '[db]\nhost=h.example.invalid\npassword: SYNTHETIC-pw',
  URL: 'https://svc:SYNTHETIC-pw@h.example.invalid:8443/app?token=SYNTHETIC-tok#frag',
  CONNECTION_STRING: 'Server=h.example.invalid;Password="SYNTHETIC-pw";Pwd={SYNTHETIC-tok}',
  LOG: '2026-01-01T00:00:00Z INFO user=SYNTHETIC-user token="SYNTHETIC-tok" status=200',
  YAML: '---\nhost: h.example.invalid\npassword: "SYNTHETIC-pw"\nitems:\n  - one\n  - \'two\'',
  TOML: '[db]\nhost = "h.example.invalid"\npassword = "SYNTHETIC-pw"',
  XML: '<config host="h.example.invalid"><password>SYNTHETIC-pw</password></config>',
};
/** Documents with enough bounded scan steps that a real parse samples the clock repeatedly. */
const WIDE = {
  JSON: `{${Array.from({ length: 1000 }, (_, i) => `"k${i}":"v${i}"`).join(',')}}`,
  DOTENV: Array.from({ length: 1000 }, (_, i) => `K${i}=v${i}`).join('\n'),
  INI: `[s]\n${Array.from({ length: 1000 }, (_, i) => `k${i}=v${i}`).join('\n')}`,
  URL: `https://h.example.invalid/?${Array.from({ length: 1000 }, (_, i) => `a${i}=v${i}`).join('&')}`,
  CONNECTION_STRING: Array.from({ length: 1000 }, (_, i) => `K${i}=v${i}`).join(';') + ';',
  LOG: Array.from({ length: 1000 }, (_, i) => `line${i} user=SYNTHETIC-u${i}`).join('\n'),
  YAML: Array.from({ length: 1000 }, (_, i) => `k${i}: v${i}`).join('\n'),
  TOML: Array.from({ length: 1000 }, (_, i) => `k${i} = "v${i}"`).join('\n'),
  XML: `<r>${Array.from({ length: 500 }, (_, i) => `<i><v>x${i}</v></i>`).join('')}</r>`,
};
const shapes = (result) => JSON.stringify({
  status: result.status, coverage: result.coverage, reasons: result.reasons,
  fields: result.fields, opaque: result.opaque, comments: result.comments,
});

test('the time budget is a validated, separate limit that never carries a clock', () => {
  // The pre-existing caps are unchanged; only a bounded time budget is added.
  assert.deepEqual({ ...DEFAULT_PARSE_BUDGET }, { maxInputUnits: 1 << 20, maxDepth: 64, maxFields: 4096, maxTimeMs: 2000 });
  assert.ok(Number.isSafeInteger(DEFAULT_PARSE_BUDGET.maxTimeMs) && DEFAULT_PARSE_BUDGET.maxTimeMs >= 1);
  assert.ok(DEFAULT_PARSE_BUDGET.maxTimeMs <= MAX_PARSE_TIME_MS);
  const text = SMALL.JSON;
  // A serialized caller assertion about a clock, or about how much time remains, is not a trusted clock.
  for (const budget of [{ clock: () => 0 }, { now: () => 0 }, { elapsedMs: 0 }, { remainingMs: 0 },
    { maxTimeMs: 5, clock: frozen.now }, { maxTimeMs: 0 }, { maxTimeMs: -1 }, { maxTimeMs: 1.5 },
    { maxTimeMs: Number.NaN }, { maxTimeMs: MAX_PARSE_TIME_MS + 1 }, { maxTimeMs: '5' }]) {
    assert.deepEqual(parseStructured(text, 'JSON', budget).reasons, ['INVALID_BUDGET'], JSON.stringify(Object.keys(budget)));
  }
  // A prototype-inherited key is ignored rather than raising or lowering an enforced limit.
  const inherited = Object.create({ maxTimeMs: 1 });
  assert.equal(parseStructured(text, 'JSON', inherited).status, 'COMPLETE');
  // The ceiling itself is accepted, and is a caller claim about time only, never about authority.
  assert.equal(parseStructured(text, 'JSON', { maxTimeMs: MAX_PARSE_TIME_MS }).status, 'COMPLETE');
});

test('every supported format fails wholly opaque when its time budget is exhausted', () => {
  for (const format of FORMATS) {
    for (const [label, text] of [['small', SMALL[format]], ['wide', WIDE[format]]]) {
      // Positive control: the same document parses completely with a clock that never moves.
      const control = parseStructured(text, format, undefined, { now: frozen().now });
      assert.equal(control.status, 'COMPLETE', `${format} ${label} control`);
      assert.ok(control.fields.length > 0, `${format} ${label} control fields`);
      const clock = stepping();
      const expired = parseStructured(text, format, undefined, { now: clock.now });
      assert.equal(expired.status, 'FAILURE', `${format} ${label}`);
      assert.deepEqual(expired.reasons, ['TIME_BUDGET_EXPIRED'], `${format} ${label}`);
      // No success-shaped partial parse: no field, no span, no coverage claim, the whole input opaque.
      assert.deepEqual(expired.fields, [], `${format} ${label}`);
      assert.deepEqual(expired.opaque, [{ start: 0, end: text.length, reason: 'TIME_BUDGET_EXPIRED' }], `${format} ${label}`);
      assert.equal(expired.coverage, 'FULL');
      assert.equal(clock.reads, 2, `${format} ${label} samples`);
    }
  }
});

test('expiry is observed at a bounded scan boundary, not only after a whole document is read', () => {
  for (const format of FORMATS) {
    const text = WIDE[format];
    // With a clock frozen at zero the same document is fully parsed, so there is real work to interrupt.
    const control = parseStructured(text, format, undefined, { now: frozen().now });
    assert.equal(control.status, 'COMPLETE', format);
    assert.ok(control.fields.length >= 500, `${format} control fields`);
    // The clock is sampled at the start and then once per poll interval, so a parse that dies at the first
    // poll after the start has charged at most one poll interval of steps, not the whole document.
    const clock = stepping();
    const expired = parseStructured(text, format, undefined, { now: clock.now });
    assert.deepEqual([expired.status, expired.reasons, clock.reads], ['FAILURE', ['TIME_BUDGET_EXPIRED'], 2], format);
  }
  // A short document charges fewer steps than one poll interval; the final sample before any
  // success-shaped result still reports the budget rather than COMPLETE/PARTIAL coverage.
  const late = () => { const clock = { reads: 0, now: () => { clock.reads += 1; return clock.reads === 1 ? 0 : 5000; } }; return clock; };
  const shortClock = late();
  const short = parseStructured(SMALL.DOTENV, 'DOTENV', undefined, { now: shortClock.now });
  assert.deepEqual([short.status, short.reasons, shortClock.reads], ['FAILURE', ['TIME_BUDGET_EXPIRED'], 2]);
  assert.deepEqual(short.fields, []);
  assert.deepEqual(whole(short), [[0, SMALL.DOTENV.length]]);
  for (const format of FORMATS) {
    // Every format has a boundary short enough to be missed by the poll interval, so the final sample
    // is what stops a late finish from being reported as coverage.
    const boundaryClock = late();
    const boundary = parseStructured(SMALL[format], format, undefined, { now: boundaryClock.now });
    assert.deepEqual([boundary.status, boundary.reasons], ['FAILURE', ['TIME_BUDGET_EXPIRED']], format);
    assert.deepEqual(boundaryClock.reads, 2, `${format} samples without a poll`);
  }
});

test('a parse that finishes after its budget still reports the budget, never coverage', () => {
  // Expiry is only detectable at a sample, so the result must be re-checked after the scan, not only during it.
  for (const [format, text] of Object.entries(SMALL)) {
    const before = parseStructured(text, format, undefined, { now: frozen().now });
    const clock = stepping();
    const after = parseStructured(text, format, undefined, { now: clock.now });
    assert.equal(after.status, 'FAILURE', format);
    assert.deepEqual(after.reasons, ['TIME_BUDGET_EXPIRED'], format);
    assert.deepEqual(after.fields, [], format);
    assert.deepEqual(whole(after), [[0, text.length]], format);
    assert.ok(clock.reads >= 2 && clock.reads <= 3, `${format} samples ${clock.reads}`);
    // The injected clock changes no parse decision: the same document parses completely with it.
    assert.equal(before.status, 'COMPLETE', format);
    assert.ok(before.fields.length > 0, format);
  }
  // Same input, same result shape, whether the clock is the host default or an injected frozen one.
  for (const format of FORMATS) {
    assert.equal(shapes(parseStructured(SMALL[format], format)), shapes(parseStructured(SMALL[format], format, undefined, { now: frozen().now })), format);
  }
});

test('an unusable clock is a closed failure, never an unbounded parse', () => {
  const text = WIDE.INI;
  const cases = [
    ['non-finite NaN', () => Number.NaN], ['non-finite Infinity', () => Number.POSITIVE_INFINITY],
    ['non-finite -Infinity', () => Number.NEGATIVE_INFINITY], ['non-number', () => '5'],
    ['throwing', () => { throw new Error('synthetic clock failure'); }],
    ['throwing after the start sample', (() => { let n = 0; return () => { if (++n > 1) throw new Error('synthetic clock failure'); return 0; }; })()],
    ['rollback', (() => { let n = 0; return () => (n++ === 0 ? 500 : 500 - 100 * n); })()],
  ];
  for (const [label, now] of cases) {
    for (const document of [SMALL.INI, text]) {
      const result = parseStructured(document, 'INI', undefined, { now });
      assert.equal(result.status, 'FAILURE', label);
      assert.deepEqual(result.reasons, ['CLOCK_UNAVAILABLE'], label);
      assert.deepEqual(result.fields, [], label);
      assert.deepEqual(whole(result), [[0, document.length]], label);
    }
  }
  // A clock that starts negative but never goes backwards is usable: only the span between samples matters.
  let n = 0;
  const negative = parseStructured(SMALL.INI, 'INI', undefined, { now: () => -1e6 + (n += 5) });
  assert.equal(negative.status, 'COMPLETE');
  assert.deepEqual(negative.reasons, []);
});

test('a host that is not a usable clock is refused, and its clock is read once per parse', () => {
  const text = SMALL.JSON;
  for (const host of [null, 7, 'clock', true, {}, { now: 1 }, { now: null }, Object.freeze({}),
    { get now() { throw new Error('synthetic accessor failure'); } },
    new Proxy({}, { get() { throw new Error('synthetic trap failure'); } })]) {
    const result = parseStructured(text, 'JSON', undefined, host);
    assert.equal(result.status, 'FAILURE');
    assert.deepEqual(result.reasons, ['CLOCK_UNAVAILABLE']);
    assert.deepEqual(whole(result), [[0, text.length]]);
  }
  let gets = 0;
  const varying = new Proxy({ now: () => 0 }, { get(target, property) { if (property === 'now') gets += 1; return Reflect.get(target, property); } });
  assert.equal(parseStructured(text, 'JSON', undefined, varying).status, 'COMPLETE');
  assert.equal(gets, 1, 'the host clock is read exactly once per parse');
  // A time-varying clock can only change readings, never the budget or the enforcement of it.
  let turn = 0;
  const switching = { now: () => (turn++ % 2 ? Number.NaN : 0) };
  const switched = parseStructured(SMALL.DOTENV, 'DOTENV', undefined, switching);
  assert.equal(switched.status, 'FAILURE');
  assert.deepEqual(switched.reasons, ['CLOCK_UNAVAILABLE']);
  assert.deepEqual(switched.fields, []);
  // A method-style host clock reads its own state: the snapshot is called bound to the host that owns it,
  // so `this` is the host rather than the deadline. Unbound it would read `undefined` and fail closed.
  const method = { t: 0, now() { return this.t; } };
  assert.equal(parseStructured(SMALL.INI, 'INI', undefined, method).status, 'COMPLETE');
  const ticking = { t: 0, now() { this.t += 1000; return this.t; } };
  assert.deepEqual(parseStructured(SMALL.INI, 'INI', { maxTimeMs: 1 }, ticking).reasons, ['TIME_BUDGET_EXPIRED']);
  // Documented unit hazard, pinned rather than left implicit: a host that reports SECONDS makes every
  // elapsed span read as ~0, so the budget never fires. No in-process check can tell that from a fast
  // parse, which is why the millisecond unit is a trusted-host obligation stated in the contract.
  const seconds = { now: () => Date.now() / 1000 };
  assert.equal(isParseHost(seconds), true, 'the shape is accepted; the unit is the host obligation');
  assert.equal(parseStructured(WIDE.INI, 'INI', { maxTimeMs: 1 }, seconds).status, 'COMPLETE');
  const milliseconds = { now: () => Date.now() };
  assert.equal(isParseHost(milliseconds), true);
});

test('percent-decoding is byte-identical to the strict per-code-point algorithm it replaced', () => {
  // Characterization copy of the previous implementation, kept here as the oracle: one code point at a
  // time, per-code-point UTF-8 encoding, `+` handling and a whole-buffer strict decode. The parser now
  // encodes bounded literal slices instead; the byte stream it must produce is unchanged.
  const reference = (text, plusIsSpace) => {
    const bytes = [];
    for (let index = 0; index < text.length;) {
      if (text[index] === '%') {
        if (!/^[0-9A-Fa-f]{2}$/u.test(text.slice(index + 1, index + 3))) return { error: 'BAD_PERCENT', at: index };
        bytes.push(parseInt(text.slice(index + 1, index + 3), 16));
        index += 3;
      } else {
        const char = String.fromCodePoint(text.codePointAt(index));
        for (const byte of new TextEncoder().encode(plusIsSpace && char === '+' ? ' ' : char)) bytes.push(byte);
        index += char.length;
      }
    }
    try { return { value: new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes)) }; }
    catch { return { error: 'BAD_PERCENT_UTF8', at: 0 }; }
  };
  // The query slot decodes with `+` as space, the userinfo slot without: both decoder modes are compared.
  const slots = [
    { plusIsSpace: true, probe: (raw) => parseStructured(`https://h.example.invalid/?x=${raw}`, 'URL', undefined, frozen()) },
    { plusIsSpace: false, probe: (raw) => parseStructured(`https://u:${raw}@h.example.invalid/`, 'URL', undefined, frozen()) },
  ];
  const path = (result, name) => result.fields.find((field) => field.path.join('.') === name)?.value ?? '';
  // Exact comparison with a report small enough to read: megabyte-scale shapes are compared whole, but a
  // failure prints only lengths and the code points that differ, never the payload-sized value.
  const same = (actual, expected, note) => {
    if (actual === expected) return;
    const tail = (value) => [...value.slice(-4)].map((char) => 'U+' + char.codePointAt(0).toString(16).toUpperCase());
    assert.fail(`${note}: length ${actual.length} vs ${expected.length}, tail ${JSON.stringify(tail(actual))} vs ${JSON.stringify(tail(expected))}`);
  };
  const compare = (raw, slot) => {
    const parsed = slot.probe(raw);
    if (parsed.reasons.includes('NOT_A_URL')) return 'grammar';
    const want = reference(raw, slot.plusIsSpace);
    if (want.error) {
      assert.ok(parsed.reasons.includes(want.error), `${JSON.stringify(raw)} wanted ${want.error} got ${parsed.reasons.join('|')}`);
      assert.deepEqual(parsed.fields, [], `${JSON.stringify(raw)} keeps no field on a decode error`);
      return 'checked';
    }
    assert.equal(parsed.status, 'COMPLETE', `length ${raw.length}`);
    same(path(parsed, slot.plusIsSpace ? 'query.x' : 'userinfo.password'), want.value, `length ${raw.length}`);
    return 'checked';
  };
  // Fixed shapes: empty, plain, `+`, every escape boundary, invalid UTF-8, NUL, overlong, astral, and
  // runs that straddle the internal decode slice from both sides. The slice-straddling cases use an
  // ESCAPED pair, because the slice boundary is measured in input units and each escape adds three.
  const slice = 8192;
  const at = (offset, tail) => 'a'.repeat(offset) + tail;
  const fixed = ['', 'a', 'a%20b', '%41%42', '%', '%z', '%4', 'a%', 'a%zz', 'a%4', 'a%41', 'A%2fB', 'a%2Fb',
    '%2f%2F', '%00', '%FF', '%C0%80', '%C3%28', '%C3%A9', '%E2%9C%93', '%F0%9F%98%80', 'p%40ss', 'a+b', '+a+b',
    at(slice - 1, 'a'), at(slice, 'a'), at(slice + 1, 'a'), at(2 * slice, 'a'), at(2 * slice + 1, 'a'),
    at(slice - 2, '%41'), at(slice - 1, '%41'), at(slice, '%41'), at(slice - 1, '%F0%9F%98%80'),
    at(slice - 2, '%F0%9F%98%80'), at(slice - 1, '😀'), at(slice, '😀'), at(2 * slice - 1, '😀'),
    `${'a'.repeat(slice - 1)}%C3%28`, '%41'.repeat(3000), 'a%41'.repeat(2000), 'a+'.repeat(5000),
    '+'.repeat(9000), 'é'.repeat(5000), '😀'.repeat(3000), '%E2%9C%93'.repeat(2000),
    '\u{10437}'.repeat(2000), '\u{10FFFF}'.repeat(2000)];
  let checked = 0;
  for (const raw of fixed) for (const slot of slots) if (compare(raw, slot) === 'checked') checked++;
  assert.ok(checked >= fixed.length * slots.length, `compared ${checked} fixed shapes`);
  // Every offset across a whole decode-slice period, with an astral character at that offset. Slicing is
  // by UTF-16 index, so a pair whose high surrogate lands on a slice boundary is what a naive slice breaks:
  // the encoder replaces an unpaired surrogate with U+FFFD, which silently turns one character into two
  // while the parse still reports COMPLETE with no reason. Sweeping the whole period closes the class
  // rather than the single offset.
  //
  // The oracle for this sweep is a SINGLE encode of the whole literal run, never a slice: the claim under
  // test is that slicing reproduces it. It is anchored to the strict per-code-point oracle below on a sample
  // of offsets, so the cheap oracle cannot itself be subtly wrong and quietly green-light a regression.
  const wholeRun = (run, plusIsSpace) => {
    try {
      return { value: new TextDecoder('utf-8', { fatal: true })
        .decode(new TextEncoder().encode(plusIsSpace ? run.replace(/\+/gu, ' ') : run)) };
    } catch { return { error: 'BAD_PERCENT_UTF8' }; }
  };
  let swept = 0, anchored = 0;
  const compareSlice = (raw, slot) => {
    const parsed = slot.probe(raw);
    const want = wholeRun(raw, slot.plusIsSpace);
    swept++;
    assert.equal(parsed.status, 'COMPLETE', `length ${raw.length}`);
    same(path(parsed, slot.plusIsSpace ? 'query.x' : 'userinfo.password'), want.value,
      `astral at run offset ${raw.length - 2} must decode as one character, not two replacements`);
    return parsed;
  };
  for (const astral of ['\u{1F600}', '\u{10437}', '\u{10FFFF}']) {
    for (let offset = 0; offset <= slice + 2; offset++) {
      for (const slot of slots) {
        const raw = at(offset, astral);
        compareSlice(raw, slot);
        if (offset % 683 === 0 || offset === slice - 1 || offset === slice) {
          anchored++;
          same(wholeRun(raw, slot.plusIsSpace).value, reference(raw, slot.plusIsSpace).value,
            `the whole-run oracle agrees with the strict oracle at offset ${offset}`);
        }
      }
    }
  }
  // The second slice period, where a deferred pair meets the end of the run.
  for (const astral of ['\u{1F600}', '\u{10FFFF}']) {
    for (let offset = 2 * slice - 3; offset <= 2 * slice + 1; offset++) {
      for (const slot of slots) compareSlice(at(offset, astral), slot);
    }
  }
  assert.ok(swept > 2 * (slice + 3) * slots.length, `swept ${swept} slice-boundary offsets`);
  assert.ok(anchored >= 30, `anchored the sweep oracle on ${anchored} offsets`);
  // A generated sweep over the characters that decide a decode: escape markers, hex digits (both cases),
  // non-hex neighbours, `+`, an astral plane character and inherited object property names. Each slot uses
  // the alphabet its own URL position admits, so a shape the grammar splits is never compared as a decode.
  let state = 0x9e3779b9;
  const random = () => { state = (Math.imul(state ^ (state >>> 15), 1 | state) + 0x6d2b79f5) >>> 0; return state / 4294967296; };
  const shared = ['%', '2', 'a', 'F', 'g', '+', '=', 'z', '0', 'C3', 'A9', 'F0', '9F', '98', '80', 'é', '\u{1F600}',
    'constructor', 'toString', '-', '.', '_', '~', '!'];
  const alphabets = [[...shared], [...shared, '&', ';']].map((alphabet) => alphabet);
  alphabets[0] = shared.filter((char) => char !== ';' && char !== '&');
  for (let run = 0; run < 1500; run++) {
    const length = 1 + Math.floor(random() * 14);
    for (const [index, alphabet] of alphabets.entries()) {
      let raw = '';
      for (let at = 0; at < length; at++) raw += alphabet[Math.floor(random() * alphabet.length)];
      if (compare(raw, slots[index]) === 'checked') checked++;
    }
  }
  assert.ok(checked > fixed.length * slots.length + 2000, `compared ${checked} shapes against the strict oracle`);
});

test('a long URL component is charged while it is decoded, so the budget can stop it', () => {
  const cap = DEFAULT_PARSE_BUDGET.maxInputUnits;
  const head = 'https://h.example.invalid/';
  const huge = head + 'abcd/'.repeat(Math.floor((cap - head.length) / 5));
  assert.ok(huge.length <= cap && huge.length > cap - 16, `one component filling the default cap: ${huge.length}`);
  // A clock that is already a whole budget past its start by the third sample: the decode is charged in
  // bounded slices, so the budget is observed *during* the component instead of only after it.
  const midDecode = (() => { let samples = 0; return () => (samples++) * 1000; })();
  const stopped = parseStructured(huge, 'URL', undefined, { now: midDecode });
  assert.equal(stopped.status, 'FAILURE');
  assert.deepEqual(stopped.reasons, ['TIME_BUDGET_EXPIRED']);
  assert.deepEqual(stopped.fields, [], 'no field survives a budget stopped mid-decode');
  assert.deepEqual(whole(stopped), [[0, huge.length]], 'the original whole input stays opaque');
  assert.equal(JSON.stringify(stopped).includes('abcd/'), false, 'no payload text is reported');
  // The same clock does not stop a small URL, so the case measures the component length, not the clock.
  assert.equal(parseStructured(SMALL.URL, 'URL', undefined, { now: (() => { let n = 0; return () => (n++) * 1000; })() }).status,
    'COMPLETE');
  // Utility control: with a clock that never moves, a megabyte of URL text at the default budget still
  // parses completely, with the same fields, spans and syntax the decoder has always produced.
  const complete = parseStructured(huge, 'URL', undefined, { now: frozen().now });
  assert.equal(complete.status, 'COMPLETE');
  assert.deepEqual(complete.reasons, []);
  assert.deepEqual(complete.opaque, []);
  assert.deepEqual(complete.fields.map((field) => field.path.join('.')), ['scheme', 'host', 'path']);
  assert.equal(complete.fields[2].syntax, 'PERCENT_ENCODED');
  // The path component keeps its leading `/` in its span, and that span addresses exactly the source.
  assert.equal(complete.fields[2].valueStart, head.length - 1);
  assert.equal(huge.slice(complete.fields[2].valueStart, complete.fields[2].valueEnd), huge.slice(head.length - 1));
  assert.equal(complete.fields[2].value, huge.slice(head.length - 1), 'a percent-free component decodes to itself');
  // A component that is almost entirely escapes is charged per escape, so a payload cannot buy
  // uninterruptible decode work by writing `%41` instead of `a`.
  const escaped = `https://h.example.invalid/?x=${'%61'.repeat(Math.floor((cap - head.length - 3) / 3))}`;
  const escapedClock = (() => { let samples = 0; return () => (samples++) * 1000; })();
  const escapesStopped = parseStructured(escaped, 'URL', undefined, { now: escapedClock });
  assert.equal(escapesStopped.status, 'FAILURE');
  assert.deepEqual(escapesStopped.reasons, ['TIME_BUDGET_EXPIRED']);
  assert.deepEqual(escapesStopped.fields, []);
  const escapesComplete = parseStructured(escaped, 'URL', undefined, { now: frozen().now });
  assert.equal(escapesComplete.status, 'COMPLETE');
  assert.equal(escapesComplete.fields.find((field) => field.path.join('.') === 'query.x').value.length,
    Math.floor((cap - head.length - 3) / 3), 'the escaped component still decodes to every byte it spelled');
});

test('an expired budget never masks the existing refusals or changes accepted behavior', () => {
  const generous = { maxTimeMs: MAX_PARSE_TIME_MS };
  // Oversize and invalid input are still refused by their own codes, with the whole input opaque.
  const oversize = 'x'.repeat(DEFAULT_PARSE_BUDGET.maxInputUnits + 1);
  for (const format of FORMATS) {
    assert.deepEqual(parseStructured(oversize, format, generous, { now: frozen().now }).reasons, ['INPUT_TOO_LARGE'], format);
  }
  assert.deepEqual(parseStructured('"\uD800"', 'JSON', generous, { now: frozen().now }).reasons, ['INVALID_TEXT']);
  assert.deepEqual(parseStructured(7, 'JSON', generous, { now: frozen().now }).reasons, ['INVALID_INPUT']);
  // Malformed, duplicate, over-deep and unsupported documents keep exactly their established codes.
  for (const [text, format, status, reason] of [
    ['{"a":', 'JSON', 'FAILURE', 'UNEXPECTED_TOKEN'],
    ['{"a":1} trailing', 'JSON', 'FAILURE', 'TRAILING_CONTENT'],
    [`${'['.repeat(100)}1${']'.repeat(100)}`, 'JSON', 'FAILURE', 'DEPTH_LIMIT'],
    ['https://h.example.invalid/%zz', 'URL', 'FAILURE', 'BAD_PERCENT'],
    ['Server=h.example.invalid;Password="open', 'CONNECTION_STRING', 'FAILURE', 'UNTERMINATED_VALUE'],
    ['<a>x</b>', 'XML', 'FAILURE', 'MISMATCHED_XML_TAG'],
    ['password: |\n  x\n', 'YAML', 'UNSUPPORTED', 'UNSUPPORTED_YAML_SCALAR'],
    ['a = {b = 1}\n', 'TOML', 'UNSUPPORTED', 'UNSUPPORTED_TOML_VALUE'],
  ]) {
    const result = parseStructured(text, format, generous, { now: frozen().now });
    assert.deepEqual([result.status, result.reasons], [status, [reason]], `${format} ${text.slice(0, 20)}`);
    assert.deepEqual(whole(result), [[0, text.length]]);
  }
  const duplicate = parseStructured('{"token":"SYNTHETIC-a","token":"SYNTHETIC-b"}', 'JSON', generous, { now: frozen().now });
  assert.deepEqual([duplicate.status, duplicate.reasons], ['COMPLETE', ['DUPLICATE_KEY']]);
  assert.deepEqual(duplicate.fields.map((field) => field.value), ['SYNTHETIC-a', 'SYNTHETIC-b']);
  // Spans, key paths, syntax tags, credential flags and unterminated-line opacity are untouched.
  const source = 'API_TOKEN="SYNTHETIC-tok" # note\nnot an assignment\n';
  const dotenvParsed = parseStructured(source, 'DOTENV', generous, { now: frozen().now });
  assert.equal(dotenvParsed.status, 'PARTIAL');
  assert.equal(dotenvParsed.fields[0].highRisk, true);
  assert.equal(dotenvParsed.fields[0].syntax, 'DOUBLE_QUOTED');
  assert.equal(source.slice(dotenvParsed.fields[0].valueStart, dotenvParsed.fields[0].valueEnd), 'SYNTHETIC-tok');
  assert.equal(source.slice(dotenvParsed.opaque[0].start, dotenvParsed.opaque[0].end), 'not an assignment');
  assert.deepEqual(dotenvParsed.opaque[0].reason, 'UNRECOGNIZED_LINE');
});

test('a rewrite whose parse runs out of time refuses and emits no text at all', () => {
  const source = SMALL.JSON;
  const field = parseStructured(source, 'JSON', undefined, { now: frozen().now }).fields[0];
  // The source parse is exhausted: no output, and not a "source is not complete" excuse.
  for (const step of [stepping(5000).now, () => { throw new Error('synthetic clock failure'); }]) {
    const out = rewriteFieldValues(source, 'JSON', [{ field, replacement: 'masked' }], { host: { now: step } });
    assert.equal(out.status, 'FAILURE');
    assert.equal(Object.hasOwn(out, 'text'), false, 'a refused rewrite carries no text');
    assert.equal(JSON.stringify(out).includes('masked'), false);
  }
  // The round-trip re-parse is bounded too: a clock that survives the source parse and expires on the
  // second one still produces no rewritten text.
  let probe = 0;
  parseStructured(source, 'JSON', undefined, { now: () => { probe += 1; return 0; } });
  let live = 0;
  const roundTrip = rewriteFieldValues(source, 'JSON', [{ field, replacement: 'masked' }], {
    host: { now: () => { live += 1; return live <= probe ? 0 : (live - probe) * 5000; } },
  });
  assert.equal(roundTrip.status, 'FAILURE');
  assert.equal(roundTrip.reason, 'TIME_BUDGET_EXPIRED');
  assert.equal(Object.hasOwn(roundTrip, 'text'), false);
  // Positive control: the same rewrite with a clock that never moves keeps keys, syntax and the edit.
  const ok = rewriteFieldValues(source, 'JSON', [{ field, replacement: 'masked' }], { host: { now: frozen().now } });
  assert.equal(ok.status, 'OK');
  assert.deepEqual(parseStructured(ok.text, 'JSON', undefined, { now: frozen().now }).fields.map((item) => item.path.join('.')),
    parseStructured(source, 'JSON', undefined, { now: frozen().now }).fields.map((item) => item.path.join('.')));
  assert.equal(parseStructured(ok.text, 'JSON', undefined, { now: frozen().now }).fields[0].value, 'masked');
});

test('a time-expired parse composes as an opaque state and the whole text is still scanned', () => {
  const input = '{"password":"SYNTHETIC-planted.invalid","host":"h.example.invalid"}';
  const run = (host) => detectNormalizedCandidates({ input, inputRef: 'synthetic-time-budget.invalid', scope, formats: ['JSON'], host });
  const control = run(undefined);
  assert.equal(control.status, 'COMPLETE');
  // The planted value is reachable with a working clock, so the case is not vacuous.
  assert.ok(control.candidates.some((item) => item.source === 'SECRET' && item.evidence.claim.semanticType === 'CREDENTIAL_OR_SECRET'));
  const expired = run({ now: stepping().now });
  assert.equal(expired.status, 'PARTIAL', 'a parse failure is an inspection gap, never "nothing there"');
  assert.ok(expired.reasons.includes('PARSER_JSON_FAILURE'));
  assert.ok(expired.reasons.includes('PARSER_JSON_TIME_BUDGET_EXPIRED'), expired.reasons.join(','));
  const opaque = expired.uninspected.filter((item) => String(item.reason).startsWith('PARSER_JSON_'));
  assert.ok(opaque.length >= 1);
  assert.deepEqual([opaque[0].viewSpan.start, opaque[0].viewSpan.end], [0, input.length]);
  // Parsed fields are gone, but the view text is still scanned independently of any parse, so the
  // credential is still found: a bounded parse can never hide a value from detection.
  assert.equal(expired.candidates.some((item) => item.source === 'SECRET'), true);
  assert.ok(expired.candidates.some((item) => input.slice(item.original.span.start, item.original.span.end) === 'SYNTHETIC-planted.invalid'));
  assert.equal(JSON.stringify(expired).includes('SYNTHETIC-planted.invalid'), false, 'no value is reported in metadata');
  // A host that is not a usable clock is refused before any parse runs, including one whose accessor throws.
  for (const host of [null, 7, { now: 'x' }, { get now() { throw new Error('synthetic accessor failure'); } },
    new Proxy({}, { get() { throw new Error('synthetic trap failure'); } })]) {
    const refused = detectNormalizedCandidates({ input, inputRef: 'synthetic-time-budget.invalid', scope, host });
    assert.equal(refused.status, 'FAILURE');
    assert.deepEqual(refused.reasons, ['INVALID_HOST']);
    assert.deepEqual(refused.candidates, []);
  }
});

test('the opaque parse state is denied at the policy and final-byte boundaries', () => {
  // A parse that produced no fields leaves the unit unresolved; unresolved evidence is denied, and a
  // candidate naming a SECRET sensitivity is denied too. No treatment releases these bytes.
  const subject = { principalId: 'principal-a.invalid', workloadId: 'workload-a.invalid' };
  const context = { tenantId: 'tenant-a.invalid', projectId: 'project-a.invalid', sessionId: 'session-a.invalid',
    purpose: 'diagnostic-a.invalid' };
  const source = { kind: 'tool.result', ref: 'tool-source-a.invalid', trustZone: 'LOCAL' };
  const destination = { kind: 'model', ref: 'model.example.invalid', trustZone: 'EXTERNAL', profileId: 'enterprise.invalid' };
  const trusted = { ...source, trust: 'TRUSTED' };
  const bundleWith = (decision) => ({
    ...KNOWN_POLICY_BUNDLE,
    profiles: [{ id: 'enterprise.invalid', sink: destination, exposure: 'EXTERNAL',
      permittedTreatments: ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE'],
      maxCleartextSensitivity: 'INTERNAL' }],
    rules: [{ id: 'enterprise-secret.invalid', profileId: 'enterprise.invalid', semanticType: 'CREDENTIAL_OR_SECRET',
      sensitivities: ['SECRET'], sourceTrust: ['TRUSTED'], operations: ['SEND'], decision }],
  });
  const scenario = (classification, policy) => {
    const boundary = { interactionRef: 'interaction-a.invalid', candidateRef: 'unit-a.invalid',
      classificationDigest: digestClassification(classification),
      authenticated: { subject, context }, observed: { source: trusted, destination },
      policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(policy) } };
    return { request: { version: 1, interactionRef: boundary.interactionRef, candidateRef: boundary.candidateRef,
      subject, context, source, destination, classification, operation: 'SEND', policy: KNOWN_POLICY_BUNDLE }, boundary };
  };
  const evaluate = (classification, policy) => decidePolicy(...Object.values(scenario(classification, policy)), policy);
  const unresolved = composeClassification({ detectorEvidence: [] },
    { interactionRef: 'interaction-a.invalid', sourceRef: source.ref, trust: 'TRUSTED' });
  assert.equal(unresolved.status, 'UNRESOLVED');
  const denied = evaluate(unresolved, bundleWith('REMOVE'));
  assert.equal(denied.state, 'DENIED');
  assert.equal(denied.reason, 'UNRESOLVED_CLASSIFICATION');
  // A resolved SECRET claim for the same unit is a treatment decision, never a plaintext release: an
  // external profile may only select REMOVE here, and a rule that would keep the secret cleartext denies.
  const resolved = composeClassification({ detectorEvidence: [{ version: 1, id: 'detector-a.invalid', status: 'FOUND',
    provenance: { inputRef: 'field-a.invalid', producerId: 'detector-a.invalid', producerVersion: 'pack-1' },
    claim: { semanticType: 'CREDENTIAL_OR_SECRET', sensitivity: 'SECRET' } }] },
    { interactionRef: 'interaction-a.invalid', sourceRef: source.ref, trust: 'TRUSTED' });
  assert.equal(evaluate(resolved, bundleWith('KEEP')).state, 'DENIED');
  assert.equal(evaluate(resolved, bundleWith('KEEP')).reason, 'UNSAFE_TREATMENT');
  const removed = evaluate(resolved, bundleWith('REMOVE'));
  assert.equal(removed.state, 'SELECTED');
  assert.equal(removed.treatment, 'REMOVE');
  assert.equal(Object.hasOwn(removed, 'payload'), false, 'a decision never carries bytes');
  // Controlled final-byte attempt on the exact outbound bytes of a document whose parse just expired.
  const planted = 'SYNTHETIC-planted.invalid';
  const document = `{"password":"${planted}","host":"h.example.invalid"}`;
  const timedOut = parseStructured(document, 'JSON', undefined, { now: stepping().now });
  assert.deepEqual(timedOut.reasons, ['TIME_BUDGET_EXPIRED']);
  const key = new Uint8Array(32).fill(11);
  const known = createKnownOriginals(scope, key, [{ kind: 'ORIGINAL', value: planted, ref: 'planted.value.1' }]);
  const target = Object.freeze({ id: 'model-gateway.invalid', profileDigest: 'sha256-profile-synthetic' });
  const bytes = new TextEncoder().encode(document);
  const blocked = checkEgress({ bytes, scope, destination: target, authorized: target, known });
  assert.equal(blocked.decision, 'BLOCK');
  // Both the independent credential-assignment pattern and the registered known original report it.
  assert.ok(blocked.reasons.includes('KNOWN_ORIGINAL_DETECTED'), blocked.reasons.join(','));
  assert.ok(blocked.reasons.includes('HIGH_RISK_PATTERN'), blocked.reasons.join(','));
  assert.equal(blocked.release, undefined, 'no bytes are handed back for a payload whose parse failed');
  assert.equal(JSON.stringify(blocked.findings).includes(planted), false, 'no value is reported');
  // Positive control: the same document without the planted value is allowed, so the block is not blanket denial.
  const clean = checkEgress({ bytes: new TextEncoder().encode('{"host":"h.example.invalid","mode":"safe"}'), scope,
    destination: target, authorized: target, known });
  assert.equal(clean.decision, 'ALLOW');
  assert.deepEqual([...clean.release], [...new TextEncoder().encode('{"host":"h.example.invalid","mode":"safe"}')]);
});

test('the clock is sampled per bounded step, so a big document costs bounded clock reads', () => {
  // Sampling is amortized on purpose: a 1 MiB document must not turn into a million clock reads, and the
  // absence of a per-character clock read is what keeps the budget itself cheap.
  for (const [format, text] of Object.entries(WIDE)) {
    const clock = { reads: 0, now: () => { clock.reads += 1; return 0; } };
    const result = parseStructured(text, format, undefined, { now: clock.now });
    assert.equal(result.status, 'COMPLETE', format);
    assert.ok(result.fields.length >= 500, format);
    // 500+ fields means thousands of charged steps; a clock read per step would need at least one read per
    // field, so bounding reads well below one per eight fields is what shows the sampling is amortized.
    assert.ok(clock.reads >= 2, `${format} ${clock.reads}`);
    assert.ok(clock.reads < result.fields.length, `${format} ${clock.reads} reads for ${result.fields.length} fields`);
    assert.ok(clock.reads <= Math.ceil(result.fields.length / 8) + 4, `${format} ${clock.reads}`);
  }
});
