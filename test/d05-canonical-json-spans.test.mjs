import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createDevelopmentEvaluation, createInMemorySinkCapture } from '../dist/evaluation.js';
import { projectPublicDevelopmentFixture } from '../evaluations/public-development-adapter.mjs';
import { createPublicD05SpanProjector, D05_CANONICAL_JSON_SPAN_VERSION } from
  '../evaluations/d05-canonical-json-spans.mjs';

// Never open/import the separately held independent DEV oracle. Every span below is test-authored.
const originalRaw = readFileSync(new URL(
  '../docs/research/issue-39-public-development-fixtures-p0.1.json', import.meta.url), 'utf8');
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const sink = { id: 'CAPTURE-DEMO-MODEL', profileId: 'EVAL-LOCAL-D05-SPANS' };
const fixtureId = 'D05-DEV-001';
const valuePath = '/fixtures/2/input/value';
const generic = (error) => error instanceof TypeError &&
  error.message === 'Invalid public D05 span projection input';

function inputs(raw = originalRaw) {
  const source = JSON.parse(raw).fixtures[2];
  const fixture = { fixtureId: source.fixtureId, familyId: source.familyId,
    partition: source.partition, input: source.input, taskControl: { prompt: source.taskControl.prompt } };
  return { fixture, projection: projectPublicDevelopmentFixture(fixture, sink) };
}
function projector(raw = originalRaw, overrides = {}) {
  const { fixture, projection } = inputs();
  return { fixture, projection, span: createPublicD05SpanProjector({
    rawFixtureUtf8: encoder.encode(raw), projection, fixtureId, sourceValuePath: valuePath,
    ...overrides,
  }) };
}
function occurrence(key, text, start = 0, end = [...text].length) {
  return { fixtureId, path: `${valuePath}/${key}`, sourceSpan: { start, end },
    normalizedSpan: { start, end }, sourceOriginalText: [...text].slice(start, end).join('') };
}
function anchoredByteSpan(value, key, start, end) {
  // Independently derive expected bytes by key/token order, NEVER searching field values.
  const keys = Object.keys(value).sort();
  const before = keys.slice(0, keys.indexOf(key)).map((item) =>
    `${JSON.stringify(item)}:${JSON.stringify(value[item])}`).join(',');
  const prefix = `{${before}${before ? ',' : ''}${JSON.stringify(key)}:"`;
  return { start: encoder.encode(prefix).length + start,
    end: encoder.encode(prefix).length + end };
}
function replace(source, before, after) {
  assert.equal(source.split(before).length, 2, 'one synthetic source anchor');
  return source.replace(before, after);
}
function rejectsRaw(raw, options) {
  assert.throws(() => projector(raw, options), generic);
}
function rejectsRawEvenWithMatchingParsedProjection(raw) {
  const { projection } = inputs(raw); // Test control: a lossy JS parse cannot establish raw provenance.
  assert.throws(() => createPublicD05SpanProjector({ rawFixtureUtf8: encoder.encode(raw),
    projection, fixtureId, sourceValuePath: valuePath }), generic);
}

test('D05 public raw fixture binds one id/pointer; canonical field and four exact #5 UTF-8 byte slices', () => {
  const { fixture, projection, span } = projector();
  assert.equal(span.version, D05_CANONICAL_JSON_SPAN_VERSION);
  assert.equal(span.version, 'd05-canonical-json-v1');
  const field = projection.developmentCase.fields[0].content;
  const value = fixture.input.value;
  assert.ok(field === JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a], [b]) =>
    a.localeCompare(b)))));
  const controls = [
    ['customer', value.customer, 0, value.customer.length],
    ['project', value.project, 0, value.project.length],
    ['endpointUrl', value.endpointUrl, 8, 28], // URL HOST only; neither scheme, port nor route.
    ['outputPath', value.outputPath, 0, value.outputPath.length],
  ];
  const evalOnly = createDevelopmentEvaluation();
  evalOnly.registerCase(projection.developmentCase);
  const projected = controls.map(([key, text, start, end], index) => {
    const entry = span.projectSourceOccurrence(occurrence(key, text, start, end));
    const expected = anchoredByteSpan(value, key, start, end);
    assert.ok(entry.fieldRef === 'field-0' && entry.start === expected.start &&
      entry.end === expected.end && entry.value === text.slice(start, end));
    assert.ok(decoder.decode(encoder.encode(field).subarray(entry.start, entry.end)) === entry.value);
    return { id: `test-authored-${index}`, ...entry,
      semanticType: { customer: 'CUSTOMER_OR_PARTNER', project: 'PROJECT_OR_CONTRACT',
        endpointUrl: 'HOST_OR_SERVICE', outputPath: 'FILE_OR_RESOURCE_PATH' }[key],
      sensitivity: 'CONFIDENTIAL', trust: 'UNTRUSTED', critical: false,
      expectedBySink: [{ sinkId: sink.id, treatment: 'MASK' }] };
  });
  evalOnly.registerOracle({ version: 1, caseId: fixtureId, occurrences: projected });
  evalOnly.registerCandidateEvents(fixtureId, []);
  const ordinaryReport = evalOnly.report(fixtureId, createInMemorySinkCapture());
  assert.equal(ordinaryReport.candidates.planted, 4);
  assert.ok(controls.every(([, text, start, end]) =>
    !JSON.stringify(ordinaryReport).includes(text.slice(start, end))));
  evalOnly.clear();
});

test('path/key identity resolves repeated identical leaves; source object key order does not affect offsets', () => {
  let raw = replace(originalRaw, '"Customer Demo-West"', '"shared-demo.invalid"');
  raw = replace(raw, '"PROJECT-DEMO-05",\n          "protocol"', '"shared-demo.invalid",\n          "protocol"');
  raw = replace(raw, '"customer": "shared-demo.invalid",\n          "project": "shared-demo.invalid",',
    '"project": "shared-demo.invalid",\n          "customer": "shared-demo.invalid",');
  const { fixture, projection } = inputs(raw);
  const span = createPublicD05SpanProjector({ rawFixtureUtf8: encoder.encode(raw), projection,
    fixtureId, sourceValuePath: valuePath });
  const first = span.projectSourceOccurrence(occurrence('customer', fixture.input.value.customer));
  const second = span.projectSourceOccurrence(occurrence('project', fixture.input.value.project));
  assert.ok(first.value === second.value && first.start !== second.start);
  for (const [key, result] of [['customer', first], ['project', second]]) {
    const expected = anchoredByteSpan(fixture.input.value, key, 0, result.value.length);
    assert.ok(result.fieldRef === 'field-0' && result.start === expected.start &&
      result.end === expected.end && result.value === 'shared-demo.invalid');
  }
});

test('D05 URL occurrence is HOST substring only; route, scheme, port, numeric controls and utility strings reject', () => {
  const { span, fixture } = projector();
  const url = fixture.input.value.endpointUrl;
  assert.ok(span.projectSourceOccurrence(occurrence('endpointUrl', url, 8, 28)).value ===
    'service.demo.invalid');
  for (const entry of [occurrence('endpointUrl', url),
    occurrence('endpointUrl', url, 29, 33), occurrence('endpointUrl', url, 33, 41),
    occurrence('endpointUrl', url, 0, 8), occurrence('protocol', 'https'),
    occurrence('os', 'linux'), occurrence('port', '9443'), occurrence('timeoutMs', '2500')]) {
    assert.throws(() => span.projectSourceOccurrence(entry), generic);
  }
});

test('whole-leaf D05 customer, project and outputPath reject even truthful partial source spans', () => {
  const { span, fixture } = projector();
  for (const key of ['customer', 'project', 'outputPath']) {
    const text = fixture.input.value[key];
    for (const [start, end] of [[0, text.length - 1], [1, text.length], [1, text.length - 1]]) {
      // Exact decoded substring and identity normalized span do not make a partial
      // occurrence eligible as one of the four fixed public D05 planted controls.
      assert.throws(() => span.projectSourceOccurrence(occurrence(key, text, start, end)), generic);
    }
    assert.ok(span.projectSourceOccurrence(occurrence(key, text)).value === text);
  }
});

test('ambiguous URL authorities and unsupported D05 lexical forms reject with matching parsed projection', () => {
  const currentUrl = '"endpointUrl": "https://service.demo.invalid:9443/v1/ping"';
  for (const changedUrl of [
    'https://user@service.demo.invalid:9443/v1/ping',
    'https://service..demo.invalid:9443/v1/ping',
    'https://service.demo.invalid:9443//other.invalid',
    'https://service.demo.invalid:9443/v1//ping',
    'https://service.demo.invalid:99999/v1/ping',
    'https://%73ervice.demo.invalid:9443/v1/ping',
    'https://[2001:db8::1]:9443/v1/ping',
  ]) {
    rejectsRawEvenWithMatchingParsedProjection(replace(originalRaw, currentUrl,
      `"endpointUrl": "${changedUrl}"`));
  }
  for (const changed of ['"Customer \\nDemo-West"', '"Customer \\\"Demo-West"',
    '"Customer \\\\ Demo-West"', '""']) {
    rejectsRawEvenWithMatchingParsedProjection(replace(originalRaw, '"Customer Demo-West"', changed));
  }
});

test('wrong fixture/path, absent or nonstring leaf, offsets and independent decoded truth fail closed', () => {
  const { span, fixture } = projector();
  const good = occurrence('customer', fixture.input.value.customer);
  for (const changed of [
    { ...good, fixtureId: 'D05-DEV-OTHER' },
    { ...good, path: '/fixtures/1/input/value/customer' },
    { ...good, path: '/fixtures/2/input/value/missing' },
    { ...good, path: '/fixtures/2/input/value/port' },
    { ...good, sourceOriginalText: 'synthetic-misinformation.invalid' },
    { ...good, normalizedSpan: { start: 1, end: good.sourceSpan.end } },
    { ...good, sourceSpan: { start: -1, end: 1 } },
    { ...good, sourceSpan: { start: 0, end: 0 }, sourceOriginalText: '' },
    { ...good, sourceSpan: { start: 0, end: 999 } },
    { ...good, sourceSpan: { start: 0.5, end: 5 } },
    { ...good, sourceSpan: { start: 0, end: 5.5 } },
    { ...good, normalizedSpan: undefined },
    { ...good, sourceOriginalText: 'Customer Demo-We' },
  ]) assert.throws(() => span.projectSourceOccurrence(changed), generic);
});

test('raw provenance required, exactly one D05 fixture at supplied index, no parsed-object substitute', () => {
  const { projection } = inputs();
  for (const bad of [undefined, null, originalRaw, JSON.parse(originalRaw), new Uint8Array(0)]) {
    assert.throws(() => createPublicD05SpanProjector({ rawFixtureUtf8: bad,
      fixtureId, sourceValuePath: valuePath, projection }), generic);
  }
  for (const extra of [{ fixtureId: 'D05-DEV-OTHER' },
    { sourceValuePath: '/fixtures/0/input/value' },
    { sourceValuePath: '/input/value' }]) rejectsRaw(originalRaw, extra);
  rejectsRaw(replace(originalRaw, '"fixtureId": "D01-DEV-001"',
    '"fixtureId": "D05-DEV-001"'));
  rejectsRaw(replace(originalRaw, '"fixtureId": "D05-DEV-001"',
    '"fixtureId": "D05-DEV-OTHER"'));
});

test('decoded duplicate object keys, including escaped aliases, reject before any parsed collapse', () => {
  for (const raw of [
    replace(originalRaw, '"customer": "Customer Demo-West",',
      '"customer": "Different", "customer": "Customer Demo-West",'),
    replace(originalRaw, '"customer": "Customer Demo-West",',
      '"\\u0063ustomer": "Different", "customer": "Customer Demo-West",'),
    replace(originalRaw, '"draftId":', '"\\u0064raftId": "alias", "draftId":'),
  ]) rejectsRaw(raw);
});

test('malformed/invalid UTF-8, excessive source bytes/depth and lone surrogates reject generically', () => {
  for (const raw of [originalRaw.slice(0, -3), originalRaw + ' trailing',
    originalRaw + ' '.repeat(131_073),
    replace(originalRaw, '"timeoutMs": 2500\n        }', '"timeoutMs": 2500, "deep": ' + '['.repeat(40) +
      '0' + ']'.repeat(40) + '\n        }'),
    replace(originalRaw, '"Customer Demo-West"', '"\\uD800"'),
    replace(originalRaw, '"Customer Demo-West"', '"\\uDC00"'),
  ]) rejectsRaw(raw);
  assert.throws(() => projector(originalRaw, { rawFixtureUtf8: Uint8Array.of(0xc3, 0x28) }), generic);
});

test('unsupported D05 escaping, non-ASCII, nested/array, integer-like keys and ambiguous numbers fail closed', () => {
  for (const raw of [
    replace(originalRaw, '"Customer Demo-West"', '"Customer \\u0044emo-West"'),
    replace(originalRaw, '"customer": "Customer Demo-West",',
      '"\\u0063ustomer": "Customer Demo-West",'),
    replace(originalRaw, '"Customer Demo-West"', '"Customer Démo-West"'),
    replace(originalRaw, '"Customer Demo-West"', '"Customer \\u00e9-West"'),
    replace(originalRaw, '"Customer Demo-West"', '["Customer Demo-West"]'),
    replace(originalRaw, '"Customer Demo-West"', '{"inside":"Customer Demo-West"}'),
    replace(originalRaw, '"customer": "Customer Demo-West",',
      '"customer": "Customer Demo-West", "1": "other",'),
    replace(originalRaw, '"timeoutMs": 2500\n        }', '"timeoutMs": 2.5e3\n        }'),
  ]) rejectsRawEvenWithMatchingParsedProjection(raw);
});

test('snapshot survives source and raw-byte mutation; serializer drift and candidate misinformation cannot move truth', () => {
  const raw = encoder.encode(originalRaw);
  const { fixture, projection } = inputs();
  const span = createPublicD05SpanProjector({ rawFixtureUtf8: raw, fixtureId,
    sourceValuePath: valuePath, projection });
  const occurrenceBefore = span.projectSourceOccurrence(occurrence('customer', fixture.input.value.customer));
  raw.fill(0);
  fixture.input.value.customer = 'candidate-claimed-value.invalid';
  const fakeEvent = { fieldId: 'f0', startByte: 0, endByte: 1, label: 'safe' };
  assert.equal(fakeEvent.label, 'safe'); // Candidate assertions are not source evidence.
  const after = span.projectSourceOccurrence(occurrence('customer', 'Customer Demo-West'));
  assert.ok(after.fieldRef === occurrenceBefore.fieldRef && after.start === occurrenceBefore.start &&
    after.end === occurrenceBefore.end && after.value === occurrenceBefore.value);
  assert.throws(() => span.projectSourceOccurrence(occurrence('customer',
    'candidate-claimed-value.invalid')), generic);
  const altered = inputs().fixture;
  altered.input.value.customer = 'candidate-claimed-value.invalid';
  const drift = projectPublicDevelopmentFixture(altered, sink);
  assert.throws(() => createPublicD05SpanProjector({ rawFixtureUtf8: encoder.encode(originalRaw),
    fixtureId, sourceValuePath: valuePath, projection: drift }), generic);
  const spoofed = { ...projection, developmentCase: { ...projection.developmentCase,
    fields: [{ ref: 'field-0', content: projection.developmentCase.fields[0].content + ' ' }] } };
  assert.throws(() => createPublicD05SpanProjector({ rawFixtureUtf8: encoder.encode(originalRaw),
    fixtureId, sourceValuePath: valuePath, projection: spoofed }), generic);
});
