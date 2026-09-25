import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DEVELOPMENT_FAMILY_IDS, HELD_OUT_FAMILY_IDS } from '../dist/evaluation-partitions.js';
import { createDevelopmentEvaluation, createInMemorySinkCapture } from '../dist/evaluation.js';

const bytes = (value) => new TextEncoder().encode(value);
const planted = 'synthetic-secret-escape-01.invalid';
const content = `diagnose port 443; sample ${planted}; keep port 443`;
const start = bytes(content.slice(0, content.indexOf(planted))).length;
const sink = { id: 'sink-remote', surface: 'model.input', profileId: 'profile-external' };
const secondSink = { id: 'sink-judge', surface: 'model.input', profileId: 'profile-judge' };
function developmentCase(overrides = {}) {
  return {
    version: 1, id: 'synthetic-config-01', familyId: 'D05', partition: 'development',
    fields: [{ ref: 'body', content }], sinks: [sink, secondSink],
    task: { id: 'diagnose-config', prompt: 'Which port must the client use?' }, ...overrides,
  };
}
function oracle(overrides = {}) {
  return {
    version: 1, caseId: 'synthetic-config-01',
    occurrences: [{ id: 'plant-01', fieldRef: 'body', start, end: start + bytes(planted).length,
      value: planted, semanticType: 'CREDENTIAL_OR_SECRET', subtype: 'API_KEY', sensitivity: 'SECRET',
      trust: 'UNTRUSTED', critical: true,
      expectedBySink: [{ sinkId: 'sink-remote', treatment: 'BLOCK' },
        { sinkId: 'sink-judge', treatment: 'BLOCK' }] }],
    taskExpected: 'port 443', ...overrides,
  };
}
function initialized() {
  const evals = createDevelopmentEvaluation();
  evals.registerCase(developmentCase());
  evals.registerOracle(oracle());
  return { evals, capture: createInMemorySinkCapture() };
}
const findRow = (report, claim, sinkId) => report.observed.find((row) => row.claim === claim && row.sinkId === sinkId);
const findUntested = (report, claim, sinkId) => report.untested.find((row) => row.claim === claim && row.sinkId === sinkId);

test('public family IDs are disjoint, and development registration never accepts blind families', () => {
  assert.deepEqual(DEVELOPMENT_FAMILY_IDS, Array.from({ length: 12 }, (_, index) => `D${String(index + 1).padStart(2, '0')}`));
  assert.deepEqual(HELD_OUT_FAMILY_IDS, ['H01', 'H02', 'H03', 'H04']);
  assert.equal(DEVELOPMENT_FAMILY_IDS.some((id) => HELD_OUT_FAMILY_IDS.includes(id)), false);
  const evals = createDevelopmentEvaluation();
  assert.throws(() => evals.registerCase(developmentCase({ familyId: 'H01' })), TypeError);
  assert.throws(() => evals.registerCase(developmentCase({ familyId: 'D99' })), TypeError);
  assert.throws(() => evals.registerCase(developmentCase({ partition: 'held-out' })), TypeError);
  evals.registerCase(developmentCase());
  assert.throws(() => evals.registerCase(developmentCase()), TypeError);
});

test('independent oracle validates source byte offsets and exact planted UTF-8 before candidate events', () => {
  const evals = createDevelopmentEvaluation();
  evals.registerCase(developmentCase());
  assert.throws(() => evals.registerCandidateEvents('synthetic-config-01', []), TypeError);
  for (const bad of [
    { caseId: 'other-case' },
    { occurrences: [{ ...oracle().occurrences[0], start: 0 }] },
    { occurrences: [{ ...oracle().occurrences[0], value: 'synthetic-incorrect.invalid' }] },
    { occurrences: [{ ...oracle().occurrences[0], expectedBySink: [{ sinkId: 'missing', treatment: 'BLOCK' }] }] },
  ]) assert.throws(() => evals.registerOracle(oracle(bad)), TypeError);
  evals.registerOracle(oracle());
  assert.throws(() => evals.registerOracle(oracle()), TypeError);
  assert.throws(() => evals.registerCandidateEvents('synthetic-config-01', [{
    fieldRef: 'missing', start: 0, end: 3, semanticType: 'PERSON',
  }]), TypeError);
});

test('case, oracle, candidate and capture sizes and field schemas are bounded without value echo', () => {
  const evals = createDevelopmentEvaluation();
  const attempts = [
    () => evals.registerCase(developmentCase({ id: 'raw planted: synthetic-secret-escape-01.invalid' })),
    () => evals.registerCase(developmentCase({ fields: [{ ref: 'body', content: 'x'.repeat(65_537) }] })),
    () => evals.registerCase({ ...developmentCase(), hostile: 'CONTROL' }),
  ];
  for (const attempt of attempts) assert.throws(attempt, (error) => error instanceof TypeError && !error.message.includes(planted));
  evals.registerCase(developmentCase());
  evals.registerOracle(oracle());
  assert.throws(() => evals.registerCandidateEvents('synthetic-config-01', Array.from({ length: 257 },
    () => ({ fieldRef: 'body', start, end: start + 1, semanticType: 'PERSON' }))), TypeError);
  const capture = createInMemorySinkCapture();
  assert.throws(() => capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-remote',
    body: bytes('x'.repeat(1_048_577)), metadata: bytes('') }), TypeError);
  assert.throws(() => capture.capture({ caseId: planted, sinkId: 'sink-remote', body: bytes('ok'), metadata: bytes('') }),
    (error) => error instanceof TypeError && !error.message.includes(planted));
});

test('post-serialization sink retains copies of exact body AND metadata bytes, with disposable lifetime', () => {
  const capture = createInMemorySinkCapture();
  const body = bytes('serialized body');
  const metadata = bytes(`header:${planted}`);
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-remote', body, metadata });
  body.fill(0); metadata.fill(0);
  const first = capture.forCase('synthetic-config-01');
  assert.equal(new TextDecoder().decode(first[0].body), 'serialized body');
  assert.equal(new TextDecoder().decode(first[0].metadata), `header:${planted}`);
  first[0].metadata.fill(0);
  assert.equal(new TextDecoder().decode(capture.forCase('synthetic-config-01')[0].metadata), `header:${planted}`);
  capture.clear();
  assert.deepEqual(capture.forCase('synthetic-config-01'), []);
});

test('missing capture is explicitly untested, not a zero-leak pass', () => {
  const { evals, capture } = initialized();
  const report = evals.report('synthetic-config-01', capture);
  assert.equal(report.privacy.secretPlanted, 1);
  assert.equal(report.privacy.testedSinkPairs, 0);
  assert.equal(findRow(report, 'secret-plaintext-escape', 'sink-remote'), undefined);
  assert.equal(findUntested(report, 'secret-plaintext-escape', 'sink-remote').provenance, 'untested');
  assert.equal('outcome' in findUntested(report, 'secret-plaintext-escape', 'sink-remote'), false);
  assert.equal(findUntested(report, 'secret-plaintext-escape', 'sink-judge').reason, 'no-capture');
});

test('actual plaintext in serialized metadata fails containment despite zero candidate events', () => {
  const { evals, capture } = initialized();
  evals.registerCandidateEvents('synthetic-config-01', []);
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-remote',
    body: bytes('diagnose port 443'), metadata: bytes(`x-fixture: ${planted}`) });
  const report = evals.report('synthetic-config-01', capture);
  assert.equal(report.candidates.misses, 1);
  assert.equal(report.candidates.recall, 0);
  assert.equal(report.privacy.criticalPlaintextEscapes, 1);
  assert.equal(report.privacy.testedSinkPairs, 1);
  assert.deepEqual(findRow(report, 'secret-plaintext-escape', 'sink-remote'), {
    claim: 'secret-plaintext-escape', sinkId: 'sink-remote', provenance: 'independently-executed', outcome: 'fail',
  });
  assert.equal(findUntested(report, 'secret-plaintext-escape', 'sink-judge').reason, 'no-capture');
});

test('body capture grades each disallowed sink independently, no candidate/sentinel pass substitution', () => {
  const { evals, capture } = initialized();
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-remote', body: bytes(planted), metadata: bytes('') });
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-judge', body: bytes('synthetic masked'), metadata: bytes('') });
  const report = evals.report('synthetic-config-01', capture);
  assert.equal(report.privacy.criticalPlaintextEscapes, 1);
  assert.equal(findRow(report, 'secret-plaintext-escape', 'sink-remote').outcome, 'fail');
  assert.equal(findRow(report, 'secret-plaintext-escape', 'sink-judge').outcome, 'pass');
  assert.equal(findUntested(report, 'candidate-detection').reason, 'no-candidate-events');
});

test('candidate exact-byte/class matches count separately from FP, subtype confusion and egress', () => {
  const { evals, capture } = initialized();
  evals.registerCandidateEvents('synthetic-config-01', [
    { fieldRef: 'body', start, end: start + bytes(planted).length,
      semanticType: 'CREDENTIAL_OR_SECRET', subtype: 'API_KEY' },
    { fieldRef: 'body', start: 0, end: 8, semanticType: 'PERSON', subtype: 'NAME' },
  ]);
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-remote', body: bytes(planted), metadata: bytes('') });
  const report = evals.report('synthetic-config-01', capture);
  assert.deepEqual(report.candidates, { planted: 1, matched: 1, misses: 0, falsePositives: 1, recall: 1, precision: 0.5 });
  assert.equal(findRow(report, 'candidate-detection').outcome, 'observed-only');
  assert.equal(findRow(report, 'secret-plaintext-escape', 'sink-remote').outcome, 'fail');
});

test('independent downstream task control uses an injected rubric; correctness never offsets privacy', () => {
  const { evals, capture } = initialized();
  const grader = (expected, actual) => expected === actual;
  assert.equal(findUntested(evals.report('synthetic-config-01', capture, grader), 'task-correctness').reason, 'no-task-result');
  evals.recordTaskResult('synthetic-config-01', 'port 443');
  assert.equal(findUntested(evals.report('synthetic-config-01', capture), 'task-correctness').reason, 'no-grader');
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-remote', body: bytes(planted), metadata: bytes('') });
  const correct = evals.report('synthetic-config-01', capture, grader);
  assert.equal(correct.utility.taskCorrect, true);
  assert.equal(findRow(correct, 'task-correctness').outcome, 'pass');
  assert.equal(findRow(correct, 'secret-plaintext-escape', 'sink-remote').outcome, 'fail');
  assert.equal(JSON.stringify(correct).includes(planted), false);
  const throwing = evals.report('synthetic-config-01', capture, () => { throw Error(planted); });
  assert.equal(findUntested(throwing, 'task-correctness').reason, 'grader-error');
  assert.equal(JSON.stringify(throwing).includes(planted), false);
});

test('ordinary report is allowlisted counters/IDs/axes, not payload, oracle, task, metadata or labels', () => {
  const { evals, capture } = initialized();
  evals.registerCandidateEvents('synthetic-config-01', []);
  evals.recordTaskResult('synthetic-config-01', planted);
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-remote', body: bytes('mask'), metadata: bytes(planted) });
  const report = evals.report('synthetic-config-01', capture, () => false);
  const encoded = JSON.stringify(report);
  assert.equal(encoded.includes(planted), false);
  assert.equal(encoded.includes('Which port'), false);
  assert.equal(encoded.includes('API_KEY'), false);
  assert.equal(report.version, 1);
  assert.equal(report.partition, 'development');
  assert.equal(report.privacy.criticalPlaintextEscapes, 1);
  assert.ok(report.observed.length >= 3, 'reports must carry independently measured findings');
  assert.equal(report.observed.every((item) => item.provenance === 'independently-executed' && 'outcome' in item), true);
  assert.equal(report.untested.every((item) => item.provenance === 'untested' && !('outcome' in item)), true);
});

test('capture for an undeclared sink is rejected instead of silently making a known sink pass', () => {
  const { evals, capture } = initialized();
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'other-sink', body: bytes(planted), metadata: bytes('') });
  assert.throws(() => evals.report('synthetic-config-01', capture), TypeError);
});
