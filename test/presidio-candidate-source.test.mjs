import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DEFAULT_SUBTYPES, SEMANTIC_CLASSES } from '../dist/classification.js';
import { composeClassification } from '../dist/classification.js';
import { normalizeInput, foldForDetection } from '../dist/normalization.js';
import { parseStructured, DEFAULT_PARSE_BUDGET } from '../dist/structured-parsers.js';
import { placeExternalSpan } from '../dist/normalized-detection.js';
import {
  PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES, PRESIDIO_ENTITY_MAPPING, PRESIDIO_LABEL_VOCABULARY_VERSION,
  PRESIDIO_MAPPING_VERSION, PRESIDIO_MAX_ANALYSIS_UNITS, PRESIDIO_MAX_FIELD_PLACEMENTS,
  PRESIDIO_MAX_RESULTS, PRESIDIO_OFFSET_UNIT, PRESIDIO_PINNED_RECOGNIZER_IDS, PRESIDIO_PRODUCER_ID,
  codePointIndex, codePointSpanToUtf16, completePresidioAnalysis, preparePresidioAnalysis,
} from '../dist/presidio-candidate-source.js';

const SCOPE = Object.freeze({
  requestId: 'req-synthetic-0001', inputRef: 'n6-aaaaaaaaaaaaaaaa-v0-raw',
  tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01',
  expectedProducerVersion: '2_2_364', expectedLanguage: 'en', expectedNerAvailable: true,
});
/**
 * The planted value every disclosure case below carries, and the *entire analysed text*: an
 * identifier-grammar-legal token, so it passes every shape check the reply protocol applies and any
 * appearance of it in a record is an untrusted string reaching a shared result.
 */
const PLANTED = 'SYNTHETICNONLIVETOKENNOTVALID';
/** The configuration this trial actually pinned: an explicit no-NLP engine, so no NER. */
const NO_NER_SCOPE = Object.freeze({ ...SCOPE, expectedNerAvailable: false });
const OTHER_SCOPE = Object.freeze({ ...SCOPE, tenantRef: 'tenant-synthetic-02' });
const decoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();

function planFor(text, target = { kind: 'VIEW', viewId: 0, representation: 'RAW', source: 'STRING' }, scope = SCOPE) {
  const normalized = normalizeInput(text);
  const prepared = preparePresidioAnalysis(normalized, { ...target, unit: { start: 0, end: 1 } }, scope);
  assert.equal(prepared.ok, true, 'analysis is preparable');
  return { normalized, plan: prepared.plan };
}
/** Build a worker reply that echoes the real binding, so only the field under test varies. */
function replyFor(plan, mutate = {}) {
  const body = {
    version: 1, protocol: 'hylja.presidio.worker', requestId: plan.binding.requestId,
    inputRef: plan.binding.inputRef, tenantRef: plan.binding.tenantRef,
    projectRef: plan.binding.projectRef, representation: plan.binding.representation,
    textDigest: plan.binding.textDigest, offsetUnit: PRESIDIO_OFFSET_UNIT, status: 'OK', results: [],
    filtering: { scoreThreshold: 0, deduplicate: true, allowListCount: 0, allowListMatch: 'NONE',
      context: 'UNAVAILABLE_NO_NLP', decisionProcess: 'NOT_REQUESTED' },
    // By construction the agreeing reply: the plan's pinned identity, echoed. A test that wants a
    // disagreement mutates exactly one of these three fields.
    runtime: { version: plan.expectedProducerVersion, language: plan.expectedLanguage,
      nerAvailable: plan.expectedNerAvailable }, unsupported: [],
  };
  return JSON.stringify({ ...body, ...mutate }) + '\n';
}
function email(start, end, extra = {}) {
  return { entityType: 'EMAIL_ADDRESS', start, end, score: 0.85, ...extra };
}
const only = (reasons) => (result) => assert.deepEqual(result.reasons, reasons);
const noCandidates = (result) => assert.deepEqual(result.candidates, []);

// ---- span translation: the whole point of the adapter -------------------------------------

test('a non-BMP prefix shifts the JS offset but never the code-point span Presidio reported', () => {
  // 🛰️ is two code points (U+1F6F0 U+FE0F) and three UTF-16 units; 🧑‍🚀 is five and nine.
  const text = '🛰️ 🧑‍🚀 contact persona.demo@example.invalid tail';
  const { plan } = planFor(text);
  const body = JSON.parse(decoder.decode(encoder.encode(replyFor(plan))));
  const start = [...text].findIndex((symbol) => symbol === 'p');
  body.results = [email(start, start + 'persona.demo@example.invalid'.length)];
  const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
  assert.equal(result.status, 'COMPLETE');
  assert.equal(result.candidates.length, 1);
  const [candidate] = result.candidates;
  assert.equal(candidate.original.kind, 'ORIGINAL_EXACT');
  assert.equal(text.slice(candidate.original.span.start, candidate.original.span.end),
    'persona.demo@example.invalid');
  assert.ok(candidate.original.span.start > start,
    'a code-point index is not a UTF-16 index on non-BMP text');
  // The naive UTF-16 reading of the same numbers would land somewhere else entirely.
  assert.notEqual(text.slice(start, start + 'persona.demo@example.invalid'.length),
    'persona.demo@example.invalid');
});

test('a non-BMP character inside the match is covered whole, never cut at a surrogate boundary', () => {
  const value = '🧑‍🚀-persona@example.invalid';
  const text = `prefix ${value} suffix`;
  const { plan } = planFor(text);
  const body = JSON.parse(decoder.decode(encoder.encode(replyFor(plan))));
  const start = [...text].findIndex((symbol) => symbol === '🧑');
  body.results = [email(start, start + [...value].length)];
  const [candidate] = completePresidioAnalysis(plan, JSON.stringify(body) + '\n').candidates;
  assert.equal(text.slice(candidate.original.span.start, candidate.original.span.end), value);
  const units = text.slice(candidate.original.span.start, candidate.original.span.end);
  assert.equal(text.slice(candidate.original.span.start, candidate.original.span.end), value);
  // The invariant is about the boundaries: neither may fall between the halves of a pair.
  const before = text.charCodeAt(candidate.original.span.start);
  const after = text.charCodeAt(candidate.original.span.end - 1);
  assert.ok(!(before >= 0xdc00 && before <= 0xdfff), 'span start may not be a low surrogate');
  assert.ok(!(after >= 0xd800 && after <= 0xdbff), 'span end may not be a high surrogate');
  assert.equal(units.length, candidate.original.span.end - candidate.original.span.start);
});

test('generated astral, combining and invisible text converts without ever splitting a pair', () => {
  const pieces = ['a', '🛰️', '🧑‍🚀', 'é', '', 'ﬀ', 'Ａ', '🌍'];
  for (let seed = 0; seed < 200; seed++) {
    let text = '';
    for (let index = 0; index < 8; index++) text += pieces[(seed * 7 + index * 3) % pieces.length];
    text += ' demo@example.invalid';
    const map = codePointIndex(text);
    assert.equal(map.unpaired, false);
    const points = [...text].length;
    for (let start = 0; start < points; start += 3) {
      const end = Math.min(points, start + 11);
      if (end <= start) continue;
      const span = codePointSpanToUtf16(map, start, end);
      assert.equal(span.ok, true);
      // The converted span is the same text, and both ends are code-point boundaries.
      assert.equal([...text.slice(span.start, span.end)].join(''), [...text].slice(start, end).join(''));
      assert.equal(map.offsets[map.offsets.indexOf(span.start)] === span.start, true);
    }
  }
});

test('compatibility folding is analysed as its own spelling and only ever claims a covering span', () => {
  const text = 'ＦＵＬＬＷＩＤＴＨ Ｄｅｍｏ demo@example.invalid';
  const { normalized, plan } = planFor(text, { kind: 'VIEW', viewId: 0, representation: 'FOLDED', source: 'STRING' });
  assert.equal(plan.binding.representation, 'FOLDED');
  assert.equal(plan.text, foldForDetection(text).text);
  assert.equal(plan.text.includes('FULLWIDTH'), true);
  const folded = [...plan.text];
  const start = folded.findIndex((symbol) => symbol === 'd');
  const body = JSON.parse(replyFor(plan));
  body.results = [email(start, start + 'demo@example.invalid'.length)];
  const [candidate] = completePresidioAnalysis(plan, JSON.stringify(body) + '\n').candidates;
  assert.equal(candidate.view.representation, 'FOLDED');
  assert.equal(candidate.original.kind, 'ORIGINAL_COVER');
  // A folded span covers the whole cluster it came from, which may be wider than the folded match.
  assert.ok(candidate.original.span.end - candidate.original.span.start >=
    'demo@example.invalid'.length);
  assert.ok(text.slice(candidate.original.span.start, candidate.original.span.end)
    .endsWith('demo@example.invalid'));
  assert.equal(normalized.views.length, 1);
});

test('text an escaped field decoded hides claims the field cover, never an invented raw offset', () => {
  const text = '{"a":"one@x.invalid","b":"one@x.invalid","c":"esc\\u0061ped@x.invalid"}';
  const parsed = parseStructured(text, 'JSON', { ...DEFAULT_PARSE_BUDGET, maxInputUnits: text.length });
  assert.equal(parsed.status, 'COMPLETE');
  const normalized = normalizeInput(text);
  const target = (index) => ({ kind: 'FIELD', viewId: 0, format: 'JSON', fieldIndex: index, source: 'STRING' });
  const spans = [];
  for (const index of [0, 1, 2]) {
    const prepared = preparePresidioAnalysis(normalized, { ...target(index), unit: { start: 0, end: 1 } }, SCOPE);
    assert.equal(prepared.ok, true);
    const value = prepared.plan.text;
    const body = JSON.parse(replyFor(prepared.plan));
    body.results = [email(0, value.length)];
    const [candidate] = completePresidioAnalysis(prepared.plan, JSON.stringify(body) + '\n').candidates;
    spans.push([text.slice(candidate.original.span.start, candidate.original.span.end),
      candidate.field.verbatim, candidate.original.kind]);
  }
  // Two repeated identical values keep two distinct original ranges, not one deduplicated range.
  assert.deepEqual(spans[0], ['one@x.invalid', true, 'ORIGINAL_EXACT']);
  assert.deepEqual(spans[1], ['one@x.invalid', true, 'ORIGINAL_EXACT']);
  // The escaped value is a different spelling in the source, so only its whole field is claimed.
  assert.deepEqual(spans[2], ['esc\\u0061ped@x.invalid', false, 'ORIGINAL_COVER']);
  const first = placeExternalSpan(normalized, { ...target(0), unit: { start: 0, end: 3 } });
  const second = placeExternalSpan(normalized, { ...target(1), unit: { start: 0, end: 3 } });
  assert.notDeepEqual(first.original.span, second.original.span);
});

test('a decoded view keeps every encoded-run envelope rather than a raw inner offset', () => {
  const inner = 'demo@example.invalid';
  const encoded = Buffer.from(inner, 'utf8').toString('base64');
  const text = `note: ${encoded} end`;
  const normalized = normalizeInput(text);
  assert.equal(normalized.views.length, 2);
  const prepared = preparePresidioAnalysis(normalized,
    { kind: 'VIEW', viewId: 1, representation: 'RAW', source: 'STRING', unit: { start: 0, end: 1 } }, SCOPE);
  assert.equal(prepared.ok, true);
  const body = JSON.parse(replyFor(prepared.plan));
  body.results = [email(0, inner.length)];
  const [candidate] = completePresidioAnalysis(prepared.plan, JSON.stringify(body) + '\n').candidates;
  assert.equal(candidate.original.kind, 'ENCODED_RUNS');
  assert.equal(candidate.original.spans.length, 1);
  assert.equal(text.slice(candidate.original.spans[0].start, candidate.original.spans[0].end), encoded);
});

// ---- binding: a reply is only evidence about the request it answers -----------------------

test('a reply bound to another input, request, tenant, project, representation or text is refused', () => {
  const text = 'contact demo@example.invalid';
  const { plan } = planFor(text);
  for (const mutate of [
    { requestId: 'req-synthetic-0002' }, { inputRef: 'n6-bbbbbbbbbbbbbbbb-v1-folded' },
    { tenantRef: 'tenant-synthetic-99' }, { projectRef: 'project-synthetic-99' },
    { representation: 'FOLDED' },
    { textDigest: 'f'.repeat(64) },
  ]) {
    const result = completePresidioAnalysis(plan, replyFor(plan, mutate));
    assert.equal(result.status, 'FAILURE', JSON.stringify(mutate));
    only(['REPLY_BINDING_MISMATCH'])(result);
    noCandidates(result);
  }
  // A second tenant's request is a different plan, so its reply cannot land on this one either.
  const foreign = planFor(text, undefined, OTHER_SCOPE).plan;
  assert.notEqual(foreign.binding.tenantRef, plan.binding.tenantRef);
  const crossed = completePresidioAnalysis(plan, replyFor(foreign));
  only(['REPLY_BINDING_MISMATCH'])(crossed);
});

test('the analysed text is derived from #6, never from the caller, and is digest-bound', () => {
  const text = 'contact demo@example.invalid';
  const normalized = normalizeInput(text);
  const prepared = preparePresidioAnalysis(normalized,
    { kind: 'VIEW', viewId: 0, representation: 'RAW', source: 'STRING', unit: { start: 0, end: 1 } }, SCOPE);
  assert.equal(prepared.ok, true);
  const request = JSON.parse(prepared.plan.line);
  assert.equal(request.text, text);
  assert.equal(request.textDigest, prepared.plan.binding.textDigest);
  assert.equal(request.offsetUnit, PRESIDIO_OFFSET_UNIT);
  for (const key of ['tenantRef', 'projectRef', 'inputRef']) {
    assert.equal(request[key], SCOPE[key]);
    assert.ok(!request[key].includes('@') && !request[key].includes('demo'), 'no value rides in a scope ref');
  }
  assert.equal(JSON.stringify(request).includes('sensitivity'), false);
  assert.equal(JSON.stringify(request).includes('trust'), false);
});

test('an unpaired surrogate is refused rather than analysed as different characters', () => {
  const lone = `a\ud800b demo@example.invalid`;
  assert.equal(codePointIndex(lone).unpaired, true);
  const prepared = preparePresidioAnalysis(normalizeInput(lone),
    { kind: 'VIEW', viewId: 0, representation: 'RAW', source: 'STRING', unit: { start: 0, end: 1 } }, SCOPE);
  assert.equal(prepared.ok, false);
  assert.equal(prepared.reason, 'INVALID_ANALYSIS_REQUEST');
  assert.equal(codePointSpanToUtf16(codePointIndex(lone), 0, 1).reason, 'SPAN_TEXT_UNPAIRED_SURROGATE');
});

test('an unsupported offset unit, malformed frame, or extra field yields no candidate', () => {
  const { plan } = planFor('contact demo@example.invalid');
  const body = JSON.parse(replyFor(plan));
  body.results = [email(0, 5)];
  const cases = [
    [JSON.stringify({ ...body, offsetUnit: 'UTF16' }) + '\n', ['REPLY_OFFSET_UNIT_UNSUPPORTED']],
    [JSON.stringify({ ...body, offsetUnit: undefined }) + '\n', ['INVALID_WORKER_REPLY']],
    [JSON.stringify({ ...body, extra: 'x' }) + '\n', ['INVALID_WORKER_REPLY']],
    ['{"partial": true}\n', ['INVALID_WORKER_REPLY']],
    ['not json at all\n', ['INVALID_WORKER_REPLY']],
    [JSON.stringify(body), ['INVALID_WORKER_REPLY']],
    [JSON.stringify(body) + '\nextra\n', ['INVALID_WORKER_REPLY']],
    ['', ['INVALID_WORKER_REPLY']],
  ];
  for (const [raw, reasons] of cases) {
    const result = completePresidioAnalysis(plan, raw);
    assert.equal(result.status, 'FAILURE', raw.slice(0, 40));
    only(reasons)(result);
    noCandidates(result);
  }
});

test('malformed, fractional, reversed, out-of-range and non-integer spans are never findings', () => {
  const { plan } = planFor('contact demo@example.invalid');
  for (const [item, reason] of [
    [{ entityType: 'EMAIL_ADDRESS', start: 1.5, end: 4, score: 0.5 }, 'SPAN_NOT_INTEGER'],
    [{ entityType: 'EMAIL_ADDRESS', start: '0', end: 4, score: 0.5 }, 'SPAN_NOT_INTEGER'],
    [{ entityType: 'EMAIL_ADDRESS', start: Number.NaN, end: 4, score: 0.5 }, 'SPAN_NOT_INTEGER'],
    [{ entityType: 'EMAIL_ADDRESS', start: Number.POSITIVE_INFINITY, end: 4, score: 0.5 }, 'SPAN_NOT_INTEGER'],
    [{ entityType: 'EMAIL_ADDRESS', start: 4, end: 1, score: 0.5 }, 'SPAN_REVERSED'],
    [{ entityType: 'EMAIL_ADDRESS', start: 3, end: 3, score: 0.5 }, 'SPAN_REVERSED'],
    [{ entityType: 'EMAIL_ADDRESS', start: -1, end: 4, score: 0.5 }, 'SPAN_OUT_OF_RANGE'],
    [{ entityType: 'EMAIL_ADDRESS', start: 0, end: 10_000, score: 0.5 }, 'SPAN_OUT_OF_RANGE'],
  ]) {
    const body = JSON.parse(replyFor(plan));
    body.results = [item];
    const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
    assert.equal(result.status, 'FAILURE', JSON.stringify(item));
    only([reason])(result);
    noCandidates(result);
    // A structurally valid sibling result still survives; the bad one is dropped, never trusted.
    body.results = [item, email(8, 28)];
    const partial = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
    assert.equal(partial.status, 'PARTIAL');
    only([reason])(partial);
    assert.equal(partial.candidates.length, 1);
  }
});

test('a score outside [0,1] is detector evidence Hylja will not carry', () => {
  const { plan } = planFor('contact demo@example.invalid');
  for (const score of [-0.1, 1.1, Number.NaN, '0.9']) {
    const body = JSON.parse(replyFor(plan));
    body.results = [email(8, 28, { score })];
    const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
    only(['SCORE_OUT_OF_RANGE'])(result);
    noCandidates(result);
  }
});

test('no worker-chosen entity-type label reaches a result, on any status or reply shape', () => {
  // The analysed text *is* the planted token, so any appearance of it below is a worker string that
  // reached the result. The reply puts the same token in an unmapped result's type and in its
  // declaration: two agreeing strings from one untrusted worker are not corroboration, and an unknown
  // entity type is examined before its span and score, so even a malformed result produces it.
  const { plan } = planFor(PLANTED);
  const unmapped = (extra = {}) => ({ entityType: PLANTED, start: 0, end: PLANTED.length, score: 0.5, ...extra });
  for (const [name, mutate, expected] of [
    ['unmapped result, valid span, OK', (body) => {
      body.results = [unmapped()]; body.unsupported = [{ entityType: PLANTED, count: 3 }];
    }, 1],
    ['unmapped result, malformed span, OK', (body) => {
      body.results = [unmapped({ start: -999, score: null })];
      body.unsupported = [{ entityType: PLANTED, count: 1 }];
    }, 1],
    ['unmapped result, worker PARTIAL', (body) => {
      body.status = 'PARTIAL'; body.results = [unmapped()]; body.unsupported = [{ entityType: PLANTED, count: 1 }];
    }, 1],
    ['unmapped result beside a real finding', (body) => {
      body.results = [unmapped(), email(0, PLANTED.length)];
      body.unsupported = [{ entityType: PLANTED, count: 1 }];
    }, 1],
    ['worker FAILURE with the declaration', (body) => {
      body.status = 'FAILURE'; body.unsupported = [{ entityType: PLANTED, count: 4 }];
    }, 0],
  ]) {
    const body = JSON.parse(replyFor(plan));
    mutate(body);
    const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
    assert.equal(JSON.stringify(result).includes(PLANTED), false, `${name} leaked the planted label`);
    if (name === 'unmapped result beside a real finding') {
      assert.equal(result.status, 'PARTIAL');
      assert.equal(result.candidates.length, 1, 'a supported sibling finding still survives');
    }
    // The loss is counted, never named: the dropped labels, their results, and nothing reversible.
    if (body.status === 'FAILURE') {
      assert.deepEqual(result.unsupported, [], name);
      assert.equal(result.declaredUnsupportedTypes, 1, name);
      continue;
    }
    assert.deepEqual(result.unsupported, [{ entityType: null, count: expected }], name);
    assert.equal(result.unpinnedUnsupportedTypes, 1, name);
    assert.ok(result.reasons.includes('UNSUPPORTED_ENTITY_TYPE'), name);
  }
  // A canonical pinned-release type this repository vouches for keeps its name: coverage stays
  // legible without a worker's free text becoming the label.
  const canonical = JSON.parse(replyFor(plan));
  canonical.results = [{ entityType: 'US_SSN', start: 0, end: 3, score: 0.9 },
    { entityType: 'LOCATION', start: 0, end: 3, score: 0.9 }];
  canonical.unsupported = [{ entityType: 'US_SSN', count: 1 }, { entityType: 'LOCATION', count: 1 }];
  const named = completePresidioAnalysis(plan, JSON.stringify(canonical) + '\n');
  assert.deepEqual(named.unsupported, [{ entityType: 'LOCATION', count: 1 }, { entityType: 'US_SSN', count: 1 }]);
  assert.equal(named.unpinnedUnsupportedTypes, 0);
  assert.equal(JSON.stringify(named).includes(PLANTED), false);
  // A declared type with no finding behind it was already a bare count, and stays one whether or not
  // its label is pinned: a declaration is a claim, never evidence.
  const declaredOnly = JSON.parse(replyFor(plan));
  declaredOnly.results = [email(0, PLANTED.length)];
  declaredOnly.unsupported = [{ entityType: PLANTED, count: 3 }];
  const result = completePresidioAnalysis(plan, JSON.stringify(declaredOnly) + '\n');
  assert.deepEqual(result.unsupported, []);
  assert.equal(result.declaredUnsupportedTypes, 1);
  assert.equal(result.unpinnedUnsupportedTypes, 0);
  assert.equal(JSON.stringify(result).includes(PLANTED), false,
    'a worker-declared label with no finding behind it never reaches a record');
  // Over-cap declarations are still named as a limit, and no label survives that either.
  const many = JSON.parse(replyFor(plan));
  many.results = [email(0, PLANTED.length)];
  many.unsupported = Array.from({ length: 70 }, (_, index) => ({ entityType: `${PLANTED}${index}`, count: 1 }));
  const capped = completePresidioAnalysis(plan, JSON.stringify(many) + '\n');
  assert.deepEqual(capped.reasons, ['UNSUPPORTED_REPORT_LIMIT']);
  assert.deepEqual(capped.unsupported, []);
  assert.equal(JSON.stringify(capped).includes(PLANTED), false);
  // A repeated declared type is a malformed reply, not last-wins.
  const repeated = JSON.parse(replyFor(plan));
  repeated.results = [unmapped()];
  repeated.unsupported = [{ entityType: PLANTED, count: 3 }, { entityType: PLANTED, count: 7 }];
  const duplicated = completePresidioAnalysis(plan, JSON.stringify(repeated) + '\n');
  assert.deepEqual(duplicated.reasons, ['INVALID_WORKER_REPLY']);
  assert.equal(JSON.stringify(duplicated).includes(PLANTED), false);
});

test('a supported-type seam carries a pinned recognizer id and never a worker-chosen label', () => {
  const { plan } = planFor(PLANTED);
  // Supported type, valid span, and BOTH seam identifiers set to the exact analysed plaintext. The
  // candidate is real and stays usable; the labels are worker-chosen free text, and being
  // grammar-legal and repeated twice is not authentication of either.
  const body = JSON.parse(replyFor(plan));
  body.results = [{ entityType: 'EMAIL_ADDRESS', start: 0, end: PLANTED.length, score: 0.5,
    seam: { patternName: PLANTED, recognizerId: PLANTED, enhancedByContext: false } }];
  const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
  assert.equal(result.status, 'COMPLETE');
  assert.equal(result.candidates.length, 1, 'only the label is withheld, never the span');
  assert.equal(JSON.stringify(result).includes(PLANTED), false);
  assert.deepEqual(result.candidates[0].producer.seam, { reported: true, recognizerIdUnpinned: true,
    patternNameReported: true, enhancedByContext: false });
  // A committed recognizer class name is a constant this repository vouches for, so it survives and
  // stays useful for rule-versus-context attribution.
  const pinned = JSON.parse(replyFor(plan));
  pinned.results = [{ entityType: 'IP_ADDRESS', start: 0, end: PLANTED.length, score: 0.5,
    seam: { patternName: 'IPv4', recognizerId: 'IpRecognizer', enhancedByContext: true } }];
  const pinnedResult = completePresidioAnalysis(plan, JSON.stringify(pinned) + '\n');
  assert.deepEqual(pinnedResult.candidates[0].producer.seam, { reported: true, recognizerId: 'IpRecognizer',
    recognizerIdUnpinned: false, patternNameReported: true, enhancedByContext: true });
  assert.equal(pinnedResult.candidates[0].producer.entityType, 'IP_ADDRESS');
  assert.equal(JSON.stringify(pinnedResult).includes('IpRecognizer'), true, 'the pinned name is reportable');
  // Booleans and closed codes from the seam stay observable; only free text is withheld.
  const bare = JSON.parse(replyFor(plan));
  bare.results = [email(0, PLANTED.length, { seam: { enhancedByContext: false } })];
  assert.deepEqual(completePresidioAnalysis(plan, JSON.stringify(bare) + '\n').candidates[0].producer.seam,
    { reported: true, recognizerIdUnpinned: false, patternNameReported: false, enhancedByContext: false });
});

test('every string this API returns is a committed constant, a closed code or a trusted pin', () => {
  // The sweep plants a grammar-legal token into every untrusted string slot a reply offers, then walks
  // the *returned object* (not its serialization) and holds each surviving string to that list. This
  // is the one place a new reportable field has to be justified, so it fails on any unvouched string.
  // The analysed text is deliberately *not* a planted token here, so the digest check below is about
  // worker-supplied values only. `provenance.textDigest` is the trusted adapter's own binding digest
  // of this text, equal to the digest the worker had to echo; the bridge's printed record omits it.
  const { plan } = planFor('contact demo@example.invalid');
  const safe = new Set([
    'COMPLETE', 'PARTIAL', 'FAILURE', 'FOUND', 'OK', 'UNREPORTED', 'UNBOUND', 'NONE',
    ...['CONTACT', 'INFRASTRUCTURE', 'SECRET'], ...['RAW', 'FOLDED'], ...['EXACT', 'COVER'],
    ...['TEXT', 'STRINGS'], // #6's own view forms, which placement derives and never the worker.
    ...['ORIGINAL_EXACT', 'ORIGINAL_COVER', 'ENCODED_RUNS', 'UTF8_TEXT', 'UTF8_ENCODED_RUNS'],
    ...['NONE', 'EXACT', 'REGEX'], ...['UNAVAILABLE_NO_NLP', 'DISABLED', 'TEXT_DERIVED',
      'EXPLICIT_CONTEXT_ONLY'], ...['NOT_REQUESTED', 'REQUESTED'],
    ...['UPSTREAM_SCORE_THRESHOLD', 'UPSTREAM_ALLOW_LIST', 'UPSTREAM_CONTEXT_ENHANCEMENT',
      'UPSTREAM_DUPLICATE_SUPPRESSION', 'NO_NER', 'NO_TEXT_CONTEXT', 'POST_FILTER_REPLY_ONLY',
      'UNSUPPORTED_ENTITY_TYPES'],
    ...['INVALID_ANALYSIS_REQUEST', 'INVALID_WORKER_REPLY', 'REPLY_BINDING_MISMATCH',
      'REPLY_OFFSET_UNIT_UNSUPPORTED', 'REPLY_RESULT_LIMIT', 'UNSUPPORTED_REPORT_LIMIT',
      'PRODUCER_VERSION_MISMATCH', 'REPLY_LANGUAGE_MISMATCH', 'NER_CAPABILITY_MISMATCH',
      'SPAN_NOT_INTEGER', 'SPAN_OUT_OF_RANGE', 'SPAN_REVERSED', 'SPAN_TEXT_UNPAIRED_SURROGATE',
      'UNSUPPORTED_ENTITY_TYPE', 'SCORE_OUT_OF_RANGE', 'WORKER_REPORTED_FAILURE', 'NO_NER_CAPABILITY'],
    ...SEMANTIC_CLASSES, ...Object.values(DEFAULT_SUBTYPES).flat(),
    ...Object.keys(PRESIDIO_ENTITY_MAPPING), ...PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES,
    ...PRESIDIO_PINNED_RECOGNIZER_IDS,
    PRESIDIO_PRODUCER_ID, PRESIDIO_MAPPING_VERSION, PRESIDIO_LABEL_VOCABULARY_VERSION,
    PRESIDIO_OFFSET_UNIT, SCOPE.expectedProducerVersion, SCOPE.expectedLanguage, SCOPE.inputRef,
  ]);
  const shapes = [/^[0-9a-f]{64}$/u, /^presidio-[0-9a-f]{32}-\d+$/u, /^PRESIDIO:[A-Z_]+$/u];
  assert.equal(planFor('contact demo@example.invalid').plan.binding.textDigest,
    createHash('sha256').update('contact demo@example.invalid').digest('hex'),
    'the carried digest is the trusted binding digest, not one of anything a reply supplied');
  const stringsIn = (value, into = []) => {
    if (typeof value === 'string') into.push(value);
    else if (Array.isArray(value)) for (const item of value) stringsIn(item, into);
    else if (value !== null && typeof value === 'object') {
      for (const item of Object.values(value)) stringsIn(item, into);
    }
    return into;
  };
  const mutations = [
    ['result entityType', (body, planted) => { body.results = [{ entityType: planted, start: 0, end: 4, score: 0.5 }]; }],
    ['result entityType, malformed', (body, planted) => { body.results = [{ entityType: planted, start: -1, end: 4, score: null }]; }],
    ['declared type', (body, planted) => { body.unsupported = [{ entityType: planted, count: 2 }]; }],
    ['seam patternName', (body, planted) => { body.results = [email(0, 4, { seam: { patternName: planted } })]; }],
    ['seam recognizerId', (body, planted) => { body.results = [email(0, 4, { seam: { recognizerId: planted } })]; }],
    ['runtime version', (body, planted) => { body.runtime.version = planted; body.results = [email(0, 4)]; }],
    ['runtime language', (body, planted) => { body.runtime.language = planted; body.results = [email(0, 4)]; }],
    ['echoed requestId', (body, planted) => { body.requestId = planted; body.results = [email(0, 4)]; }],
    ['echoed inputRef', (body, planted) => { body.inputRef = planted; body.results = [email(0, 4)]; }],
    ['echoed tenantRef', (body, planted) => { body.tenantRef = planted; body.results = [email(0, 4)]; }],
    ['echoed projectRef', (body, planted) => { body.projectRef = planted; body.results = [email(0, 4)]; }],
    ['status', (body, planted) => { body.status = planted; body.results = [email(0, 4)]; }],
    ['supported result, clean reply', (body) => { body.results = [email(8, 28)]; }],
  ];
  for (const planted of [PLANTED, `${PLANTED}X`, PLANTED.slice(0, 12), `Z${PLANTED}`]) {
    for (const [name, mutate] of mutations) {
      const body = JSON.parse(replyFor(plan));
      mutate(body, planted);
      const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
      assert.ok(['COMPLETE', 'PARTIAL', 'FAILURE'].includes(result.status), `${name}: ${result.status}`);
      assert.equal(JSON.stringify(result).includes(planted), false, `${name} leaked ${planted}`);
      for (const value of stringsIn(result)) {
        assert.ok(safe.has(value) || shapes.some((shape) => shape.test(value)),
          `unvouched string survived: ${JSON.stringify(value)} (from ${name})`);
      }
      // A digest of the planted value is not an acceptable substitute either.
      assert.equal(JSON.stringify(result).includes(
        createHash('sha256').update(planted).digest('hex')), false, `${name} leaked a digest`);
    }
  }
  // The label vocabulary is a versioned pin of its own, so a record says which one produced its names.
  const record = completePresidioAnalysis(plan, replyFor(plan));
  assert.equal(record.provenance.labelVocabularyVersion, PRESIDIO_LABEL_VOCABULARY_VERSION);
});

test('the pinned label vocabulary is finite, committed and kept in step with the manifest', () => {
  const manifest = JSON.parse(readFileSync(new URL('../evaluations/presidio-worker/manifest.json',
    import.meta.url), 'utf8'));
  // The recognizer names the adapter is willing to report are exactly the ones the pinned manifest
  // enables. Both are committed data records; a recognizer added to one without the other is a
  // reviewed change, not a label the adapter invents at run time.
  assert.deepEqual([...PRESIDIO_PINNED_RECOGNIZER_IDS].sort(),
    [...manifest.configuration.recognizers].sort());
  // Every pinned entity type is a real pinned-release type that the accepted v1 mapping refuses.
  assert.ok(PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES.length > 0);
  assert.equal(new Set(PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES).size,
    PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES.length, 'no duplicates in the pinned vocabulary');
  for (const entity of PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES) {
    assert.equal(Object.hasOwn(PRESIDIO_ENTITY_MAPPING, entity), false,
      `${entity} is mapped, so it is not an unsupported type`);
  }
  assert.equal(Object.isFrozen(PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES), true);
  assert.equal(Object.isFrozen(PRESIDIO_PINNED_RECOGNIZER_IDS), true);
});

test('an unmapped entity type stays explicit and never becomes the nearest accepted class', () => {
  const { plan } = planFor('contact demo@example.invalid');
  const body = JSON.parse(replyFor(plan));
  body.results = [{ entityType: 'US_SSN', start: 8, end: 28, score: 0.9 },
    { entityType: 'LOCATION', start: 0, end: 7, score: 0.9 }, email(8, 28)];
  body.unsupported = [{ entityType: 'US_SSN', count: 1 }, { entityType: 'LOCATION', count: 1 }];
  const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
  assert.equal(result.status, 'PARTIAL');
  assert.deepEqual(result.reasons, ['UNSUPPORTED_ENTITY_TYPE']);
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].evidence.claim.semanticType, 'PERSON');
  assert.deepEqual(result.unsupported.map((item) => item.entityType), ['LOCATION', 'US_SSN']);
  assert.ok(result.limitations.includes('UNSUPPORTED_ENTITY_TYPES'));
  // A type whose *mapped* subtype is not in the accepted v1 registry is refused, not widened.
  for (const [entity, expected] of Object.entries(PRESIDIO_ENTITY_MAPPING)) {
    assert.ok(SEMANTIC_CLASSES.includes(expected.semanticType), entity);
    if (expected.subtype) {
      const subtypes = prepareAndClassify(plan, entity);
      assert.equal(subtypes, expected.subtype);
    }
  }
});

function prepareAndClassify(plan, entity) {
  const body = JSON.parse(replyFor(plan));
  body.results = [email(8, 28)];
  body.results[0].entityType = entity;
  const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
  return result.candidates[0]?.evidence.claim.subtype;
}

test('a detector result carries no sensitivity, trust, reversibility, scope or confidence', () => {
  const { plan } = planFor('contact demo@example.invalid');
  const body = JSON.parse(replyFor(plan));
  body.results = [email(8, 28)];
  const [candidate] = completePresidioAnalysis(plan, JSON.stringify(body) + '\n').candidates;
  assert.deepEqual(Object.keys(candidate.evidence.claim).sort(), ['semanticType', 'subtype']);
  assert.equal(candidate.evidence.claim.sensitivity, undefined);
  assert.equal(candidate.evidence.claim.confidence, undefined);
  assert.equal(candidate.evidence.claim.reversible, undefined);
  assert.equal(candidate.evidence.claim.scope, undefined);
  assert.equal(candidate.producer.score, 0.85, 'the score is kept as detector evidence');
  assert.equal(JSON.stringify(candidate.evidence.claim).includes('0.85'), false);
  // Composed through the accepted v1 composer, the result is UNRESOLVED until trusted configuration
  // supplies a sensitivity: a Presidio score cannot resolve a classification on its own.
  const composed = composeClassification({ detectorEvidence: [candidate.evidence] },
    { interactionRef: 'interaction-synthetic-1', sourceRef: 'source-synthetic-1', trust: 'UNTRUSTED' });
  assert.equal(composed.status, 'UNRESOLVED');
  assert.ok(composed.reasons.includes('MISSING_SENSITIVITY'));
  assert.equal(composed.sensitivity, 'UNKNOWN');
  assert.equal(composed.trust, 'UNTRUSTED', 'trust comes from the integration, never from the worker');
  assert.equal(composed.reversible, false);
  assert.equal(composed.scope, 'request');
  assert.equal(composed.sensitivity, 'UNKNOWN');
});

test('producer/version provenance is preserved verbatim and stays privacy-safe', () => {
  const { plan } = planFor('contact demo@example.invalid');
  const body = JSON.parse(replyFor(plan));
  body.results = [email(8, 28, { seam: { patternName: 'email', recognizerId: 'EmailRecognizer',
    enhancedByContext: false } })];
  const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
  const [candidate] = result.candidates;
  assert.equal(candidate.evidence.provenance.producerId, PRESIDIO_PRODUCER_ID);
  assert.equal(candidate.evidence.provenance.producerVersion, '2_2_364');
  assert.equal(candidate.evidence.provenance.inputRef, SCOPE.inputRef);
  assert.equal(candidate.evidence.provenance.questionSetVersion, undefined);
  assert.equal(candidate.producer.mappingVersion, PRESIDIO_MAPPING_VERSION);
  assert.equal(candidate.producer.entityType, 'EMAIL_ADDRESS');
  // The configured recognizer's class name is a committed constant and is carried; the pattern name is
  // detector-internal free text, so only the fact that one was reported survives.
  assert.deepEqual(candidate.producer.seam, { reported: true, recognizerId: 'EmailRecognizer',
    recognizerIdUnpinned: false, patternNameReported: true, enhancedByContext: false });
  assert.equal(result.provenance.nerAvailable, true);
  assert.equal(result.provenance.language, 'en');
  assert.equal(result.provenance.textDigest, plan.binding.textDigest);
  // A seam field is still held to an identifier grammar, so a malformed seam is a malformed reply.
  for (const seam of [{ patternName: 'persona.demo@example.invalid' }, { recognizerId: 'a/b' },
    { patternName: 'x'.repeat(65) }, { enhancedByContext: 'yes' }, { unknown: 1 }, {}]) {
    const mutated = JSON.parse(replyFor(plan));
    mutated.results = [email(8, 28, { seam })];
    const refused = completePresidioAnalysis(plan, JSON.stringify(mutated) + '\n');
    assert.ok(['INVALID_WORKER_REPLY'].includes(refused.reasons[0]) || refused.candidates.length === 0,
      JSON.stringify(seam));
  }
});

test('upstream filtering provenance is recorded and its evidence loss is stated, not reconstructed', () => {
  const { plan } = planFor('contact demo@example.invalid');
  const body = JSON.parse(replyFor(plan));
  body.results = [email(8, 28)];
  body.filtering = { scoreThreshold: 0.4, deduplicate: true, allowListCount: 2, allowListMatch: 'EXACT',
    context: 'TEXT_DERIVED', decisionProcess: 'REQUESTED' };
  const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
  assert.deepEqual(result.filtering, { scoreThreshold: 0.4, deduplicate: true, allowListCount: 2,
    allowListMatch: 'EXACT', context: 'TEXT_DERIVED', decisionProcess: 'REQUESTED' });
  for (const code of ['UPSTREAM_SCORE_THRESHOLD', 'UPSTREAM_ALLOW_LIST', 'UPSTREAM_CONTEXT_ENHANCEMENT',
    'UPSTREAM_DUPLICATE_SUPPRESSION', 'POST_FILTER_REPLY_ONLY']) {
    assert.ok(result.limitations.includes(code), code);
  }
  // The reply is the analyzer's post-filter output; nothing here invents pre-filter evidence.
  assert.equal(result.candidates[0].producer.filtering.allowListCount, 2);
  assert.equal(JSON.stringify(result).includes('"allowed"'), false);
  // A malformed filtering block is a malformed reply, not a default.
  for (const filtering of [{ scoreThreshold: 0.4 }, { scoreThreshold: 2, deduplicate: true,
    allowListCount: 0, allowListMatch: 'NONE', context: 'DISABLED', decisionProcess: 'REQUESTED' },
  { scoreThreshold: 0, deduplicate: 'yes', allowListCount: 0, allowListMatch: 'NONE', context: 'DISABLED',
    decisionProcess: 'REQUESTED' },
  { scoreThreshold: 0, deduplicate: true, allowListCount: 0, allowListMatch: 'ALLOW_ALL', context: 'DISABLED',
    decisionProcess: 'REQUESTED' }]) {
    const mutated = JSON.parse(replyFor(plan));
    mutated.results = [email(8, 28)];
    mutated.filtering = filtering;
    const refused = completePresidioAnalysis(plan, JSON.stringify(mutated) + '\n');
    only(['INVALID_WORKER_REPLY'])(refused);
    noCandidates(refused);
  }
});

test('a run without a NER engine, a worker failure and a partial reply are never clean success', () => {
  const { plan } = planFor('contact demo@example.invalid');
  // The run whose PIN says there is no NER engine, which is the configuration this trial shipped.
  const { plan: noNerPlan } = planFor('contact demo@example.invalid', undefined, NO_NER_SCOPE);
  const noNer = JSON.parse(replyFor(noNerPlan));
  noNer.results = [];
  const noNerResult = completePresidioAnalysis(noNerPlan, JSON.stringify(noNer) + '\n');
  assert.equal(noNerResult.status, 'PARTIAL', 'an empty reply with no NER capability is never a clean pass');
  assert.deepEqual(noNerResult.reasons, ['NO_NER_CAPABILITY']);
  assert.ok(noNerResult.limitations.includes('NO_NER'));
  assert.ok(noNerResult.limitations.includes('NO_TEXT_CONTEXT'));
  assert.equal(noNerResult.provenance.nerAvailable, false);

  const failed = JSON.parse(replyFor(plan));
  failed.status = 'FAILURE';
  failed.results = [email(8, 28)];
  const failedResult = completePresidioAnalysis(plan, JSON.stringify(failed) + '\n');
  assert.equal(failedResult.status, 'FAILURE');
  assert.deepEqual(failedResult.reasons, ['WORKER_REPORTED_FAILURE']);
  noCandidates(failedResult);

  const partial = JSON.parse(replyFor(plan));
  partial.status = 'PARTIAL';
  partial.results = [email(8, 28)];
  const partialResult = completePresidioAnalysis(plan, JSON.stringify(partial) + '\n');
  assert.equal(partialResult.status, 'PARTIAL');
  assert.equal(partialResult.candidates.length, 1);
});

test('candidate overflow and duplicate suppression are bounded and never silently truncated', () => {
  const text = `${'a'.repeat(64)}@x.invalid `.repeat(200);
  const { plan } = planFor(text);
  const over = JSON.parse(replyFor(plan));
  over.results = Array.from({ length: PRESIDIO_MAX_RESULTS + 1 }, (_, index) => email(index * 6, index * 6 + 5));
  const refused = completePresidioAnalysis(plan, JSON.stringify(over) + '\n');
  only(['REPLY_RESULT_LIMIT'])(refused);
  noCandidates(refused);

  const exact = JSON.parse(replyFor(plan));
  const points = [...text];
  exact.results = Array.from({ length: PRESIDIO_MAX_RESULTS }, (_, index) => {
    const start = points.findIndex((symbol, at) => symbol === 'a' && points[at - 1] === ' ');
    return email(start, start + 10);
  });
  const accepted = completePresidioAnalysis(plan, JSON.stringify(exact) + '\n');
  assert.equal(accepted.candidates.length, 1, 'identical spans are one occurrence, not 256');
  // A generated sweep of hostile reply mutations never produces an unparseable result.
  for (let seed = 0; seed < 64; seed++) {
    const mutated = JSON.parse(replyFor(plan));
    mutated.results = [{ entityType: 'EMAIL_ADDRESS', start: (seed % 7) - 2, end: seed * 13,
      score: (seed % 11) / 10 }];
    const result = completePresidioAnalysis(plan, JSON.stringify(mutated) + '\n');
    assert.ok(['COMPLETE', 'PARTIAL', 'FAILURE'].includes(result.status));
    for (const candidate of result.candidates) {
      assert.ok(candidate.original.span.start < candidate.original.span.end);
    }
  }
});

test('byte input is labelled decoded-text offsets, never byte offsets', () => {
  const bytes = Buffer.from('contact demo@example.invalid', 'utf8');
  const normalized = normalizeInput(bytes);
  const prepared = preparePresidioAnalysis(normalized,
    { kind: 'VIEW', viewId: 0, representation: 'RAW', source: 'BYTES', unit: { start: 0, end: 1 } }, SCOPE);
  assert.equal(prepared.ok, true);
  const body = JSON.parse(replyFor(prepared.plan));
  body.results = [email(8, 28)];
  const [candidate] = completePresidioAnalysis(prepared.plan, JSON.stringify(body) + '\n').candidates;
  assert.equal(candidate.original.kind, 'UTF8_TEXT');
  assert.equal(candidate.original.coverage, 'EXACT');
});

test('a repeated #7 field parse is charged, so an untrusted result count cannot multiply the work', () => {
  const fields = Array.from({ length: 64 }, (_, index) =>
    `"k${index}":"${'v'.repeat(40)}${index}@x.invalid"`).join(',');
  const text = `{${fields}}`;
  const normalized = normalizeInput(text);
  const target = (index) => ({ kind: 'FIELD', viewId: 0, format: 'JSON', fieldIndex: index, source: 'STRING' });
  const placements = [];
  for (let index = 0; index < 64; index++) {
    const prepared = preparePresidioAnalysis(normalized, { ...target(index), unit: { start: 0, end: 1 } }, SCOPE);
    assert.equal(prepared.ok, true);
    const value = prepared.plan.text;
    const body = JSON.parse(replyFor(prepared.plan));
    body.results = [email(0, value.length)];
    placements.push(completePresidioAnalysis(prepared.plan, JSON.stringify(body) + '\n'));
  }
  // Each placement is one analysis, so each is charged once; the cap bounds a *single* reply that
  // claims many results against one field.
  assert.ok(placements.every((result) => result.candidates.length === 1));
  const prepared = preparePresidioAnalysis(normalized, { ...target(0), unit: { start: 0, end: 1 } }, SCOPE);
  const many = JSON.parse(replyFor(prepared.plan));
  many.results = Array.from({ length: PRESIDIO_MAX_FIELD_PLACEMENTS + 4 }, (_, index) => email(index, index + 1));
  const capped = completePresidioAnalysis(prepared.plan, JSON.stringify(many) + '\n');
  assert.deepEqual(capped.reasons, ['REPLY_RESULT_LIMIT']);
  assert.equal(capped.candidates.length, PRESIDIO_MAX_FIELD_PLACEMENTS);
});

test('every malformed reply field is refused by the strict schema, not by a silent default', () => {
  const { plan } = planFor('contact demo@example.invalid');
  const mutations = {
    'runtime version grammar': (body) => { body.runtime.version = 'presidio/analyzer'; },
    'runtime language grammar': (body) => { body.runtime.language = 'en;rm -rf /'; },
    'runtime not an object': (body) => { body.runtime = '2_2_364'; },
    'runtime extra key': (body) => { body.runtime.nerModel = 'en_core_web_lg'; },
    'text digest not hex': (body) => { body.textDigest = 'not-a-digest'; },
    'text digest wrong length': (body) => { body.textDigest = 'a'.repeat(63); },
    'echoed ref not a string': (body) => { body.tenantRef = 7; },
    'status not a fixed code': (body) => { body.status = 'OKAY'; },
    'representation not fixed': (body) => { body.representation = 'SIDEWAYS'; },
    'version not the protocol version': (body) => { body.version = 2; },
    'protocol not this protocol': (body) => { body.protocol = 'other/1'; },
    'results not an array': (body) => { body.results = { 0: email(8, 28) }; },
    'result missing a field': (body) => { body.results = [{ entityType: 'EMAIL_ADDRESS', start: 8, score: 0.5 }]; },
    'result with an extra field': (body) => { body.results = [email(8, 28, { textMatch: 'demo@example.invalid' })]; },
    'result entity type not a token': (body) => {
      body.results = [{ entityType: 'persona.demo@example.invalid', start: 8, end: 28, score: 0.5 }];
    },
    'unsupported entry malformed': (body) => { body.unsupported = [{ entityType: 'US_SSN' }]; },
    'unsupported count out of range': (body) => { body.unsupported = [{ entityType: 'US_SSN', count: 0 }]; },
    'seam not an object': (body) => { body.results = [email(8, 28, { seam: 'Email (Medium)' })]; },
    'seam empty object': (body) => { body.results = [email(8, 28, { seam: {} })]; },
    'seam pattern name not a token': (body) => { body.results = [email(8, 28, { seam: { patternName: 'a b' } })]; },
    'seam recognizer id not a token': (body) => { body.results = [email(8, 28, { seam: { recognizerId: 'a.b' } })]; },
    'seam enhanced flag not boolean': (body) => { body.results = [email(8, 28, { seam: { enhancedByContext: 1 } })]; },
    'seam unknown key': (body) => { body.results = [email(8, 28, { seam: { textMatch: 'x' } })]; },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const body = JSON.parse(replyFor(plan));
    body.results = [email(8, 28)];
    mutate(body);
    const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
    assert.notEqual(result.status, 'COMPLETE', name);
    assert.deepEqual(result.candidates, [], name);
  }
});

test('a lone low surrogate and every unplaced-result fallback are named, never dropped quietly', () => {
  // A lone *trailing* low surrogate: the code-point walk reaches it without a preceding high unit.
  const trailing = `demo@example.invalid\udc00`;
  assert.equal(codePointIndex(trailing).unpaired, true);
  const { plan } = planFor('contact demo@example.invalid');
  // An in-range span the target cannot place is `INVALID_ANALYSIS_REQUEST`, not a silent skip. The
  // FOLDED mapping can return a span wider than the fold origin array only if a result sits past the
  // end, which the range check already refuses; forcing it here needs a hand-built plan.
  // A well-formed reply with no results and an NER-capable PIN is a genuine zero-findings answer, and
  // it is the *only* zero-findings answer the adapter will give.
  const placed = completePresidioAnalysis(plan, replyFor(plan, { results: [] }));
  assert.equal(placed.status, 'COMPLETE');
  assert.equal(placed.candidates.length, 0);
});

test('the NER capability is a trusted pin, so a worker cannot claim away its own coverage limits', () => {
  // The direction that would over-claim: the pin says there is no NER engine, the worker says there is.
  // Left unchecked this turned a degraded run into `COMPLETE` and erased `NO_NER`/`NO_TEXT_CONTEXT`.
  const { plan: noNerPlan } = planFor('contact demo@example.invalid', undefined, NO_NER_SCOPE);
  const overclaiming = JSON.parse(replyFor(noNerPlan));
  overclaiming.runtime.nerAvailable = true;
  overclaiming.results = [email(8, 28)];
  const refused = completePresidioAnalysis(noNerPlan, JSON.stringify(overclaiming) + '\n');
  assert.equal(refused.status, 'FAILURE');
  assert.deepEqual(refused.reasons, ['NER_CAPABILITY_MISMATCH']);
  assert.deepEqual(refused.candidates, []);
  assert.equal(refused.provenance.nerAvailable, false, 'the pinned value is what a record carries');
  assert.equal(JSON.stringify(refused).includes('NO_TEXT_CONTEXT'), false,
    'a refused run reports no limitations at all, so nothing is over- or under-claimed');
  // The other direction is refused too: a pin with NER and a worker without it is a misconfiguration.
  const { plan } = planFor('contact demo@example.invalid');
  const underclaiming = JSON.parse(replyFor(plan));
  underclaiming.runtime.nerAvailable = false;
  const alsoRefused = completePresidioAnalysis(plan, JSON.stringify(underclaiming) + '\n');
  assert.deepEqual(alsoRefused.reasons, ['NER_CAPABILITY_MISMATCH']);
  assert.deepEqual(alsoRefused.candidates, []);
  // An unusable runtime under the no-NER pin names the failure and the capability limit together.
  const broken = JSON.parse(replyFor(noNerPlan));
  broken.status = 'FAILURE';
  const brokenResult = completePresidioAnalysis(noNerPlan, JSON.stringify(broken) + '\n');
  assert.equal(brokenResult.status, 'FAILURE');
  assert.deepEqual(brokenResult.reasons, ['NO_NER_CAPABILITY', 'WORKER_REPORTED_FAILURE']);
  assert.ok(brokenResult.limitations.includes('NO_NER'));
});

test('an unmapped entity type counts toward the per-analysis result bound', () => {
  const { plan } = planFor('contact demo@example.invalid');
  const body = JSON.parse(replyFor(plan));
  body.results = Array.from({ length: PRESIDIO_MAX_RESULTS }, (_, index) => ({
    entityType: 'LOCATION', start: index % 20, end: (index % 20) + 1, score: 0.5,
  }));
  const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
  // Unmapped results are named but do not consume candidate slots, so all 256 are accounted for.
  assert.deepEqual(result.reasons, ['UNSUPPORTED_ENTITY_TYPE']);
  assert.equal(result.candidates.length, 0);
  assert.equal(result.unsupported.length, 1);
  assert.equal(result.unsupported[0].count, PRESIDIO_MAX_RESULTS);
});

test('a result whose span the target cannot place is reported, not silently discarded', () => {
  const text = '{"a":"demo@example.invalid"}';
  const normalized = normalizeInput(text);
  const prepared = preparePresidioAnalysis(normalized,
    { kind: 'FIELD', viewId: 0, format: 'JSON', fieldIndex: 0, unit: { start: 0, end: 1 }, source: 'STRING' },
    SCOPE);
  assert.equal(prepared.ok, true);
  const body = JSON.parse(replyFor(prepared.plan));
  // A JSON field target against a view whose own field index moved: the span is in range for the
  // analysed text but no longer lands on the placement #6 can derive.
  body.results = [email(0, 5)];
  const plan2 = { ...prepared.plan, target: { kind: 'FIELD', viewId: 0, format: 'JSON', fieldIndex: 9,
    unit: { start: 0, end: 1 }, source: 'STRING' } };
  const result = completePresidioAnalysis(plan2, JSON.stringify(body) + '\n');
  assert.deepEqual(result.reasons, ['INVALID_ANALYSIS_REQUEST']);
  assert.equal(result.status, 'FAILURE');
  assert.deepEqual(result.candidates, []);
});

test('the analysis size, wire-size and hostile-input refusals are each reachable and named', () => {
  const target = { kind: 'VIEW', viewId: 0, representation: 'RAW', source: 'STRING' };
  // A view the caller raised the #6 budget for, but this adapter still caps.
  const oversized = normalizeInput('a'.repeat(PRESIDIO_MAX_ANALYSIS_UNITS + 16),
    { maxInputUnits: 4 << 20 });
  assert.ok(['COMPLETE', 'PARTIAL'].includes(oversized.status));
  assert.equal(preparePresidioAnalysis(oversized, { ...target, unit: { start: 0, end: 1 } }, SCOPE).reason,
    'INVALID_ANALYSIS_REQUEST');
  // An escaped-text expansion that would put the request line over the wire ceiling.
  const expanded = normalizeInput('\u0001'.repeat(400_000));
  assert.equal(preparePresidioAnalysis(expanded, { ...target, unit: { start: 0, end: 1 } }, SCOPE).reason,
    'INVALID_ANALYSIS_REQUEST');
  // A hostile #6 result: the property read throws, and the adapter reports a fixed reason.
  const hostile = new Proxy(normalizeInput('contact demo@example.invalid'),
    { get() { throw new Error('synthetic-planted-getter.invalid'); } });
  const refused = preparePresidioAnalysis(hostile, { ...target, unit: { start: 0, end: 1 } }, SCOPE);
  assert.deepEqual(refused, { ok: false, reason: 'INVALID_ANALYSIS_REQUEST' });
  assert.equal(JSON.stringify(refused).includes('synthetic-planted-getter'), false);
});

test('every admitted mapping row names a class and subtype the accepted v1 registry knows', () => {
  const admitted = Object.entries(PRESIDIO_ENTITY_MAPPING);
  assert.deepEqual(admitted.map(([entity]) => entity).sort(),
    ['EMAIL_ADDRESS', 'IP_ADDRESS', 'MAC_ADDRESS', 'PERSON', 'PHONE_NUMBER', 'URL']);
  for (const [entity, mapping] of admitted) {
    assert.ok(Object.hasOwn(DEFAULT_SUBTYPES, mapping.semanticType), entity);
    if (mapping.subtype !== undefined) {
      assert.ok(DEFAULT_SUBTYPES[mapping.semanticType].includes(mapping.subtype), entity);
    }
    assert.ok(['CONTACT', 'INFRASTRUCTURE', 'SECRET'].includes(mapping.source), entity);
  }
  // A type v1 does not accept has no row at all, so it can only ever be an explicit unsupported type.
  for (const entity of ['US_SSN', 'LOCATION', 'DATE_TIME', 'CREDIT_CARD', 'CRYPTO', 'IBAN_CODE',
    'MEDICAL_LICENSE', 'NRP', 'US_DRIVER_LICENSE', 'PERSON_NAME']) {
    assert.equal(Object.hasOwn(PRESIDIO_ENTITY_MAPPING, entity), false, entity);
  }
});

test('an over-long unsupported-type report is named, and a declared count cannot be inflated', () => {
  const { plan } = planFor('contact demo@example.invalid');
  // A worker declaring seventy distinct unsupported types exceeds the named bound; the excess is named
  // as `UNSUPPORTED_REPORT_LIMIT` instead of being dropped by a cap that says nothing.
  const many = JSON.parse(replyFor(plan));
  many.unsupported = Array.from({ length: 70 }, (_, index) => ({ entityType: `TYPE${index}`, count: 1 }));
  const capped = completePresidioAnalysis(plan, JSON.stringify(many) + '\n');
  assert.deepEqual(capped.reasons, ['UNSUPPORTED_REPORT_LIMIT']);
  assert.equal(capped.unsupported.length, 0);
  assert.ok(capped.limitations.includes('UNSUPPORTED_ENTITY_TYPES'));
  // A worker that both returns three US_SSN results and declares five of them must not read as eight.
  const doubled = JSON.parse(replyFor(plan));
  doubled.results = Array.from({ length: 3 }, (_, index) => ({ entityType: 'US_SSN', start: index,
    end: index + 1, score: 0.5 }));
  doubled.unsupported = [{ entityType: 'US_SSN', count: 5 }];
  const counted = completePresidioAnalysis(plan, JSON.stringify(doubled) + '\n');
  assert.deepEqual(counted.reasons, ['UNSUPPORTED_ENTITY_TYPE']);
  assert.deepEqual(counted.unsupported, [{ entityType: 'US_SSN', count: 5 }]);
  assert.equal(counted.candidates.length, 0);
});

test('the reply boundary is a decoded string, so a hostile object never reaches a getter at all', () => {
  const { plan } = planFor('contact demo@example.invalid');
  let reads = 0;
  const hostile = new Proxy({}, { get() { reads++; throw new Error('synthetic-planted-trap.invalid'); },
    ownKeys(target) { reads++; return Reflect.ownKeys(target); },
    getOwnPropertyDescriptor() { reads++; throw new Error('synthetic-planted-trap.invalid'); } });
  // The transport hands `completePresidioAnalysis` decoded bytes. Anything that is not such a string is
  // refused by shape before it is parsed, so no trap on a caller-supplied object can ever run here.
  const result = completePresidioAnalysis(plan, hostile);
  assert.deepEqual(result.reasons, ['INVALID_WORKER_REPLY']);
  assert.deepEqual(result.candidates, []);
  assert.equal(reads, 0, 'no trap on the supplied value was invoked');
  assert.equal(JSON.stringify(result).includes('synthetic-planted-trap'), false);
});

test('the plan freezes a copy of the target, so a reused object cannot move a finding', () => {
  const text = '{"a":"person.alpha@example.invalid","b":"other.person@example.invalid"}';
  const normalized = normalizeInput(text);
  // The caller reuses ONE mutable target object across fields, exactly as an async fan-out or a loop
  // over a shared template would. Preparing with index 0 fixes what the worker is shown.
  const shared = { kind: 'FIELD', viewId: 0, format: 'JSON', fieldIndex: 0, unit: { start: 0, end: 1 },
    source: 'STRING' };
  const prepared = preparePresidioAnalysis(normalized, shared, SCOPE);
  assert.equal(prepared.ok, true);
  assert.equal(prepared.plan.text, 'person.alpha@example.invalid');
  shared.fieldIndex = 1; // A caller bug, a stale template, or anything else holding the same object.
  assert.equal(shared.fieldIndex, 1, 'the caller object really did change');
  assert.equal(prepared.plan.target.fieldIndex, 0, 'the plan holds its own frozen copy');
  assert.equal(Object.isFrozen(prepared.plan.target), true);
  assert.equal(prepared.plan.text, 'person.alpha@example.invalid', 'the analysed text did not move');
  const body = JSON.parse(replyFor(prepared.plan));
  body.results = [email(0, 'person.alpha@example.invalid'.length)];
  const result = completePresidioAnalysis(prepared.plan, JSON.stringify(body) + '\n');
  assert.equal(result.status, 'COMPLETE');
  const [candidate] = result.candidates;
  assert.equal(text.slice(candidate.original.span.start, candidate.original.span.end),
    'person.alpha@example.invalid', 'the finding is credited to the field the worker actually saw');
  assert.equal(candidate.original.kind, 'ORIGINAL_EXACT');
  assert.notEqual(text.slice(candidate.original.span.start, candidate.original.span.end),
    'other.person@example.invalid');
});

test('a candidate id is bound to the request input reference, never to the analysed text', () => {
  const text = 'contact demo@example.invalid';
  const idsFor = (scope) => {
    const { plan } = planFor(text, undefined, scope);
    const body = JSON.parse(replyFor(plan));
    body.results = [email(8, 28)];
    return completePresidioAnalysis(plan, JSON.stringify(body) + '\n').candidates[0].evidence.id;
  };
  const base = idsFor(SCOPE);
  assert.equal(base, idsFor(SCOPE), 'the same request gives the same id');
  // The same analysed text under a different input reference must not give the same id: that is what
  // stops "these two messages share this content here" being read off an evidence id.
  for (const scope of [{ ...SCOPE, inputRef: 'n6-bbbbbbbbbbbbbbbb-v0-raw' }, OTHER_SCOPE]) {
    assert.notEqual(idsFor(scope), base, `ids must not be comparable across ${scope.inputRef}`);
  }
  // Two different texts under one request also differ, but the id reveals nothing about either: it is
  // a digest of the opaque reference, not of the content.
  const { plan } = planFor('contact other@example.invalid');
  const other = JSON.parse(replyFor(plan));
  other.results = [email(8, 29)];
  const otherId = completePresidioAnalysis(plan, JSON.stringify(other) + '\n').candidates[0].evidence.id;
  assert.equal(otherId, base, 'one request reference yields one id prefix regardless of content');
  for (const planted of ['demo@example.invalid', text]) {
    assert.equal(base.includes(planted), false);
  }
  assert.match(base, /^presidio-[0-9a-f]{32}-1$/);
});

test('a worker-supplied analyzer version or language can never reach a provenance record', () => {
  const { plan } = planFor('contact demo@example.invalid');
  const planted = 'DEMONONLIVETOKENNOTVALID'.repeat(2);
  for (const [mutate, reason] of [
    [(body) => { body.runtime.version = planted; }, 'PRODUCER_VERSION_MISMATCH'],
    [(body) => { body.runtime.version = 'presidio-analyzer'; }, 'PRODUCER_VERSION_MISMATCH'],
    [(body) => { body.runtime.language = 'DE'; }, 'REPLY_LANGUAGE_MISMATCH'],
    [(body) => { body.runtime.language = 'DEUTSCH'; }, 'REPLY_LANGUAGE_MISMATCH'],
  ]) {
    const body = JSON.parse(replyFor(plan));
    body.results = [email(8, 28)];
    mutate(body);
    const result = completePresidioAnalysis(plan, JSON.stringify(body) + '\n');
    assert.equal(result.status, 'FAILURE', JSON.stringify(body.runtime));
    assert.deepEqual(result.reasons, [reason]);
    assert.deepEqual(result.candidates, []);
    // Not even the refusal record echoes the token: provenance reports the pinned value only.
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes(planted), false);
    assert.equal(serialized.includes('DEUTSCH'), false);
    // A refused reply never reports the worker's own runtime identity back at all.
    assert.equal(result.provenance.producerVersion, 'UNREPORTED');
    assert.equal(result.provenance.language, 'UNREPORTED');
  }
  // The agreed values are what a result carries, for the evidence record as well as the run record.
  const agreed = JSON.parse(replyFor(plan));
  agreed.results = [email(8, 28)];
  const result = completePresidioAnalysis(plan, JSON.stringify(agreed) + '\n');
  assert.equal(result.provenance.producerVersion, plan.expectedProducerVersion);
  assert.equal(result.provenance.language, plan.expectedLanguage);
  assert.equal(result.candidates[0].evidence.provenance.producerVersion, plan.expectedProducerVersion);
});

test('an out-of-surface target is refused before any text is read', () => {
  const normalized = normalizeInput('contact demo@example.invalid');
  for (const target of [
    { kind: 'VIEW', viewId: 9, representation: 'RAW', source: 'STRING' },
    { kind: 'VIEW', viewId: 0, representation: 'SIDEWAYS', source: 'STRING' },
    { kind: 'FIELD', viewId: 0, format: 'AVRO', fieldIndex: 0, source: 'STRING' },
    { kind: 'FIELD', viewId: 0, format: 'JSON', fieldIndex: 99, source: 'STRING' },
    { kind: 'OTHER', viewId: 0, source: 'STRING' },
  ]) {
    const prepared = preparePresidioAnalysis(normalized, { ...target, unit: { start: 0, end: 1 } }, SCOPE);
    assert.equal(prepared.ok, false, JSON.stringify(target));
    assert.equal(prepared.reason, 'INVALID_ANALYSIS_REQUEST');
  }
  for (const scope of [undefined, null, { ...SCOPE, tenantRef: '' }, { ...SCOPE, requestId: 'x'.repeat(300) },
    { ...SCOPE, requestId: 'line\nbreak' }]) {
    const prepared = preparePresidioAnalysis(normalized,
      { kind: 'VIEW', viewId: 0, representation: 'RAW', source: 'STRING', unit: { start: 0, end: 1 } }, scope);
    assert.equal(prepared.ok, false, JSON.stringify(scope));
  }
});
