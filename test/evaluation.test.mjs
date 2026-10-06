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
    context: { tenantId: 'tenant-a.invalid', projectId: 'project-a.invalid',
      sessionId: 'session-a.invalid', principalId: 'principal-a.invalid',
      purpose: 'synthetic-diagnostic', provenanceRef: 'issuer-a.invalid' },
    task: { id: 'diagnose-config', prompt: 'Which port must the client use?', requiredSinkId: sink.id }, ...overrides,
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
const publicSinkRef = (sinkId) => sinkId === 'sink-remote' ? 'sink-1' : sinkId === 'sink-judge' ? 'sink-2' : sinkId;
const findRow = (report, claim, sinkId) => report.observed.find((row) => row.claim === claim && row.sinkId === publicSinkRef(sinkId));
const findUntested = (report, claim, sinkId) => report.untested.find((row) => row.claim === claim && row.sinkId === publicSinkRef(sinkId));

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

test('CREDENTIAL_OR_SECRET oracle cannot label a planted credential below SECRET or allow KEEP', () => {
  for (const sensitivity of ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED']) {
    for (const treatment of ['KEEP', 'BLOCK']) {
      const evals = createDevelopmentEvaluation();
      evals.registerCase(developmentCase());
      const contradictory = { ...oracle().occurrences[0], sensitivity,
        expectedBySink: [{ sinkId: 'sink-remote', treatment }, { sinkId: 'sink-judge', treatment }] };
      assert.throws(() => evals.registerOracle(oracle({ occurrences: [contradictory] })),
        (error) => error instanceof TypeError && !error.message.includes(planted),
        `${sensitivity}/${treatment} must not erase a credential from SECRET escape controls`);
    }
  }
  const legitimateNoncredential = createDevelopmentEvaluation();
  legitimateNoncredential.registerCase(developmentCase());
  legitimateNoncredential.registerOracle(oracle({ occurrences: [{ ...oracle().occurrences[0],
    semanticType: 'PERSON', subtype: 'NAME', sensitivity: 'PUBLIC', critical: false,
    expectedBySink: [{ sinkId: 'sink-remote', treatment: 'KEEP' },
      { sinkId: 'sink-judge', treatment: 'KEEP' }] }] }));
  const capture = createInMemorySinkCapture();
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-remote', body: bytes(planted), metadata: bytes('') });
  const report = legitimateNoncredential.report('synthetic-config-01', capture);
  assert.equal(report.privacy.secretPlanted, 0);
  assert.equal(findUntested(report, 'secret-plaintext-escape', 'sink-remote').reason, 'no-secret-control');
});

test('plant cannot coincide with allowlisted IDs emitted by an ordinary report', () => {
  const value = 'synthetic-ambiguous-plant';
  const caseId = value;
  const evals = createDevelopmentEvaluation();
  evals.registerCase(developmentCase({ id: caseId, fields: [{ ref: 'body', content: value }] }));
  const item = oracle().occurrences[0];
  const againstId = oracle({ caseId, occurrences: [{ ...item, value, start: 0, end: bytes(value).length }] });
  assert.throws(() => evals.registerOracle(againstId),
    (error) => error instanceof TypeError && !error.message.includes(value));
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
  assert.equal(Object.isFrozen(capture), true);
  assert.throws(() => { capture.forCase = () => []; }, TypeError);
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
    claim: 'secret-plaintext-escape', sinkId: 'sink-1', provenance: 'independently-executed', outcome: 'fail',
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
  assert.equal(findUntested(evals.report('synthetic-config-01', capture), 'task-correctness').reason, 'no-capture');
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-remote', body: bytes(planted), metadata: bytes('') });
  assert.equal(findUntested(evals.report('synthetic-config-01', capture), 'task-correctness').reason, 'no-grader');
  const correct = evals.report('synthetic-config-01', capture, grader);
  assert.equal(correct.utility.taskCorrect, true);
  assert.equal(findRow(correct, 'task-correctness').outcome, 'pass');
  assert.equal(findRow(correct, 'secret-plaintext-escape', 'sink-remote').outcome, 'fail');
  assert.equal(JSON.stringify(correct).includes(planted), false);
  const throwing = evals.report('synthetic-config-01', capture, () => { throw Error(planted); });
  assert.equal(findUntested(throwing, 'task-correctness').reason, 'grader-error');
  assert.equal(JSON.stringify(throwing).includes(planted), false);
});

test('a task answer without any controlled sink capture cannot become a solved task', async () => {
  let graderCalls = 0;
  const grader = () => { graderCalls++; return true; };
  const direct = initialized();
  direct.evals.recordTaskResult('synthetic-config-01', 'port 443');
  const directReport = direct.evals.report('synthetic-config-01', direct.capture, grader);
  assert.equal(directReport.utility.taskCorrect, null);
  assert.equal(findRow(directReport, 'task-correctness'), undefined);
  assert.equal(findUntested(directReport, 'task-correctness').reason, 'no-capture');
  assert.equal(findUntested(directReport, 'secret-plaintext-escape', 'sink-remote').reason,
    'no-capture');
  assert.equal(graderCalls, 0);

  const callback = initialized();
  await callback.evals.runCandidate('synthetic-config-01', async () => ({
    events: [], taskResult: 'port 443',
  }), callback.capture);
  const callbackReport = callback.evals.report('synthetic-config-01', callback.capture, grader);
  assert.equal(callbackReport.utility.taskCorrect, null);
  assert.equal(findRow(callbackReport, 'task-correctness'), undefined);
  assert.equal(findUntested(callbackReport, 'task-correctness').reason, 'no-capture');
  assert.equal(findUntested(callbackReport, 'secret-plaintext-escape', 'sink-remote').outcome,
    undefined);
  assert.equal(graderCalls, 0);
});

test('ordinary report mints opaque case/sink refs instead of echoing a protected value prefix', () => {
  const protectedPrefix = 'synthetic-private-key-abcdef123456';
  const value = `${protectedPrefix}.invalid`;
  const caseId = `${protectedPrefix}-case`;
  const sinkId = `${protectedPrefix}-sink`;
  const source = `diagnose ${value}`;
  const evals = createDevelopmentEvaluation();
  evals.registerCase(developmentCase({ id: caseId, fields: [{ ref: 'body', content: source }],
    sinks: [{ ...sink, id: sinkId }, secondSink],
    task: { id: 'task-control', prompt: value, requiredSinkId: sinkId } }));
  evals.registerOracle(oracle({ caseId, occurrences: [{ ...oracle().occurrences[0], value,
    start: bytes('diagnose ').length, end: bytes(source).length,
    expectedBySink: [{ sinkId, treatment: 'BLOCK' }, { sinkId: 'sink-judge', treatment: 'BLOCK' }] }] }));
  const capture = createInMemorySinkCapture();
  capture.capture({ caseId, sinkId, body: bytes('masked synthetic data'), metadata: bytes('local-only') });
  evals.recordTaskResult(caseId, value);
  const report = evals.report(caseId, capture, () => { throw Error(value); });
  assert.equal(findUntested(report, 'task-correctness').reason, 'grader-error');
  assert.equal(JSON.stringify(report).includes(protectedPrefix), false);
  assert.equal(report.privacy.secretPlanted, 1);
  assert.equal(report.caseId, 'case-1');
  assert.equal(findRow(report, 'secret-plaintext-escape', 'sink-1').outcome, 'pass');
  assert.equal(report.observed.some((row) => row.sinkId === 'sink-1'), true);
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

test('evaluator-origin latency/compute/model cost have units, bounds and untested state', () => {
  const { evals, capture } = initialized();
  const absent = evals.report('synthetic-config-01', capture);
  assert.deepEqual(absent.operations, { latencyMs: null, computeMs: null, modelApiCostMicrounits: null });
  assert.equal(findUntested(absent, 'operational-measurement').reason, 'no-operational-observation');
  for (const invalid of [{ latencyMs: -1, computeMs: 1, modelApiCostMicrounits: 0 },
    { latencyMs: Number.NaN, computeMs: 1, modelApiCostMicrounits: 0 },
    { latencyMs: 1, computeMs: 1, modelApiCostMicrounits: 0, rawTrace: planted }]) {
    assert.throws(() => evals.recordOperationalMeasurement('synthetic-config-01', invalid), TypeError);
  }
  evals.recordOperationalMeasurement('synthetic-config-01', {
    latencyMs: 12.5, computeMs: 2.25, modelApiCostMicrounits: 0,
  });
  const result = evals.report('synthetic-config-01', capture);
  assert.deepEqual(result.operations, { latencyMs: 12.5, computeMs: 2.25, modelApiCostMicrounits: 0 });
  assert.equal(findRow(result, 'operational-measurement').outcome, 'observed-only');
  assert.throws(() => evals.recordOperationalMeasurement('synthetic-config-01', {
    latencyMs: 10, computeMs: 3, modelApiCostMicrounits: 0,
  }), TypeError);
  assert.equal(JSON.stringify(result).includes(planted), false);
});

test('candidate callback receives only frozen development data; evaluator exclusively captures and grades', async () => {
  const { evals, capture } = initialized();
  await evals.runCandidate('synthetic-config-01', async (view, send) => {
    assert.equal(view.version, 1);
    assert.equal(view.familyId, 'D05');
    assert.equal(view.fields[0].content, content);
    assert.equal(view.context.tenantId, 'tenant-a.invalid');
    assert.equal(view.context.provenanceRef, 'issuer-a.invalid');
    assert.equal(Object.isFrozen(view.context), true);
    assert.equal(view.task.prompt, 'Which port must the client use?');
    assert.equal(Object.hasOwn(view, 'oracle'), false);
    assert.equal(Object.hasOwn(view.task, 'expected'), false);
    assert.equal(Object.isFrozen(view), true);
    assert.equal(Object.isFrozen(view.fields[0]), true);
    assert.throws(() => { view.fields[0].content = 'tampered'; }, TypeError);
    assert.throws(() => send('unknown-sink', { body: bytes('x'), metadata: bytes('') }), TypeError);
    send('sink-remote', { body: bytes('masked output'), metadata: bytes(planted) });
    return { events: [{ fieldRef: 'body', start, end: start + bytes(planted).length,
      semanticType: 'CREDENTIAL_OR_SECRET', subtype: 'API_KEY' }], taskResult: 'port 443' };
  }, capture);
  const report = evals.report('synthetic-config-01', capture, (expected, actual) => expected === actual);
  assert.equal(report.candidates.matched, 1);
  assert.equal(report.utility.taskCorrect, true);
  assert.equal(report.privacy.criticalPlaintextEscapes, 1);
  assert.equal(JSON.stringify(report).includes(planted), false);
  assert.equal(findUntested(report, 'secret-plaintext-escape', 'sink-judge').reason, 'no-capture');
});

test('candidate callback cannot smuggle oracle labels or self-grade via extra fields', async () => {
  const { evals, capture } = initialized();
  await assert.rejects(evals.runCandidate('synthetic-config-01', async () => ({
    events: [], result: 'pass', oracle: planted,
  }), capture), (error) => error instanceof TypeError && !error.message.includes(planted));
  const result = evals.report('synthetic-config-01', capture);
  assert.equal(findUntested(result, 'candidate-detection').reason, 'no-candidate-events');
  assert.equal(findUntested(result, 'task-correctness').reason, 'no-task-result');
});

test('required task sink: another declared capture never invokes the grader', () => {
  const { evals, capture } = initialized();
  evals.recordTaskResult('synthetic-config-01', 'port 443');
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'sink-judge',
    body: bytes('synthetic masked'), metadata: bytes('') });
  let calls = 0;
  const report = evals.report('synthetic-config-01', capture, () => { calls++; return true; });
  assert.equal(calls, 0);
  assert.equal(report.utility.taskCorrect, null);
  assert.equal(report.observed.some((row) => row.claim === 'task-correctness'), false);
  assert.equal(findUntested(report, 'task-correctness').reason, 'no-capture');
  capture.capture({ caseId: 'synthetic-config-01', sinkId: sink.id,
    body: bytes('synthetic masked'), metadata: bytes('') });
  const bound = evals.report('synthetic-config-01', capture, () => { calls++; return true; });
  assert.equal(calls, 1);
  assert.equal(bound.utility.taskCorrect, true);
});

test('capture for an undeclared sink is rejected instead of silently making a known sink pass', () => {
  const { evals, capture } = initialized();
  capture.capture({ caseId: 'synthetic-config-01', sinkId: 'other-sink', body: bytes(planted), metadata: bytes('') });
  assert.throws(() => evals.report('synthetic-config-01', capture), TypeError);
});

function taskFixture(task, sinks = [sink, secondSink]) {
  const evals = createDevelopmentEvaluation();
  const record = developmentCase({ task, sinks });
  evals.registerCase(record);
  evals.registerOracle(oracle({ occurrences: [] }));
  return { evals, record, capture: createInMemorySinkCapture() };
}
function localCapture(capture, sinkId, caseId = 'synthetic-config-01') {
  capture.capture({ caseId, sinkId, body: bytes('synthetic masked'), metadata: bytes('') });
}
const fixedEvaluationError = (error) => error instanceof TypeError &&
  error.message === 'Invalid synthetic evaluation input';

test('unbound single-sink legacy task stays untested with task prerequisite precedence', () => {
  const task = { id: 'task-control', prompt: planted };
  const { evals, capture } = taskFixture(task, [sink]);
  localCapture(capture, sink.id);
  assert.equal(findUntested(evals.report('synthetic-config-01', capture), 'task-correctness').reason, 'no-task-result');
  evals.recordTaskResult('synthetic-config-01', planted);
  let calls = 0;
  const report = evals.report('synthetic-config-01', capture, () => { calls++; return true; });
  assert.equal(calls, 0);
  assert.equal(report.utility.taskCorrect, null);
  assert.equal(findUntested(report, 'task-correctness').reason, 'no-task-sink-binding');
  assert.equal(findRow(report, 'task-correctness') === undefined, true);
  assert.equal(JSON.stringify(report).includes(planted), false);
  const noControl = createDevelopmentEvaluation();
  noControl.registerCase(developmentCase({ task }));
  noControl.registerOracle({ version: 1, caseId: 'synthetic-config-01', occurrences: [] });
  noControl.recordTaskResult('synthetic-config-01', planted);
  assert.equal(findUntested(noControl.report('synthetic-config-01', capture), 'task-correctness').reason, 'no-task-control');
});

test('present binding validates closed own descriptors without reading hostile accessors', () => {
  let calls = 0;
  const base = { id: 'task-control', prompt: planted };
  const getter = { ...base, get requiredSinkId() { calls++; throw Error(planted); } };
  const bad = [undefined, null, '', 1, {}, 'foreign-sink', 'x'.repeat(65), planted];
  for (const task of [getter, Object.assign(Object.create({ requiredSinkId: sink.id }), base),
    { ...base, requiredSinkId: sink.id, extra: planted },
    ...bad.map((requiredSinkId) => ({ ...base, requiredSinkId }))]) {
    assert.throws(() => createDevelopmentEvaluation().registerCase(developmentCase({ task })), fixedEvaluationError);
  }
  assert.equal(calls, 0);
  Object.defineProperty(Object.prototype, 'requiredSinkId', { configurable: true,
    get() { calls++; throw Error(planted); } });
  try {
    const { evals, capture } = taskFixture(base);
    evals.recordTaskResult('synthetic-config-01', planted);
    localCapture(capture, sink.id);
    const report = evals.report('synthetic-config-01', capture, () => { calls++; return true; });
    assert.equal(findUntested(report, 'task-correctness').reason, 'no-task-sink-binding');
    assert.equal(report.utility.taskCorrect, null);
  } finally { delete Object.prototype.requiredSinkId; }
  assert.equal(calls, 0);
});

test('binding snapshot and frozen private handoff gate callback grading at B only', async () => {
  for (const includeRequired of [false, true]) {
    const task = { id: 'task-control', prompt: planted, requiredSinkId: secondSink.id };
    const { evals, capture } = taskFixture(task);
    task.requiredSinkId = sink.id;
    await evals.runCandidate('synthetic-config-01', (view, send) => {
      assert.equal(Object.keys(view.task).sort().join(',') === 'id,prompt', true);
      assert.equal(Object.isFrozen(view.task), true);
      assert.equal(Object.hasOwn(view.task, 'requiredSinkId'), false);
      send(sink.id, { body: bytes('synthetic masked'), metadata: bytes('') });
      if (includeRequired) send(secondSink.id, { body: bytes('synthetic masked'), metadata: bytes('') });
      return { events: [], taskResult: planted };
    }, capture);
    let calls = 0;
    const report = evals.report('synthetic-config-01', capture, () => { calls++; return true; });
    assert.equal(calls, includeRequired ? 1 : 0);
    assert.equal(report.utility.taskCorrect, includeRequired ? true : null);
    assert.equal(JSON.stringify(report).includes(planted), false);
  }
});

test('candidate binding overrides reject without choosing evaluator task destination', async () => {
  for (const extra of [{ requiredSinkId: sink.id }, { task: { requiredSinkId: sink.id } }]) {
    const { evals, capture } = taskFixture({ id: 'task-control', prompt: planted,
      requiredSinkId: secondSink.id });
    await assert.rejects(evals.runCandidate('synthetic-config-01', (_view, send) => {
      send(sink.id, { body: bytes('synthetic masked'), metadata: bytes('') });
      return { events: [], taskResult: planted, ...extra };
    }, capture), fixedEvaluationError);
    let calls = 0;
    const report = evals.report('synthetic-config-01', capture, () => { calls++; return true; });
    assert.equal(calls, 0);
    assert.equal(report.utility.taskCorrect, null);
    assert.equal(findUntested(report, 'task-correctness').reason, 'no-task-result');
  }
});

test('bound grader false, throwing and non-boolean preserve distinct utility outcomes', () => {
  for (const outcome of [false, true, 'nonboolean', 'throw']) {
    const { evals, capture } = taskFixture({ id: 'task-control', prompt: planted, requiredSinkId: secondSink.id });
    evals.recordTaskResult('synthetic-config-01', planted);
    localCapture(capture, secondSink.id);
    let calls = 0;
    const report = evals.report('synthetic-config-01', capture, () => {
      calls++;
      if (outcome === 'throw') throw Error(planted);
      return outcome === 'nonboolean' ? planted : outcome;
    });
    assert.equal(calls, 1);
    assert.equal(report.utility.taskCorrect, typeof outcome === 'boolean' ? outcome : null);
    assert.equal(findRow(report, 'task-correctness')?.outcome,
      typeof outcome === 'boolean' ? (outcome ? 'pass' : 'fail') : undefined);
    if (typeof outcome !== 'boolean') assert.equal(findUntested(report, 'task-correctness').reason, 'grader-error');
    assert.equal(JSON.stringify(report).includes(planted), false);
  }
});

test('generated required-sink subsets and order through eight sinks never borrow another case capture', () => {
  let vectors = 0;
  for (let size = 1; size <= 8; size++) {
    const sinks = Array.from({ length: size }, (_, index) => ({ ...sink, id: `synthetic-sink-${index}` }));
    for (const required of sinks) for (const reverse of [false, true]) {
      for (let subset = 0; subset < 2 ** size; subset++) {
        const { evals, capture } = taskFixture({ id: 'task-control', prompt: planted,
          requiredSinkId: required.id }, reverse ? [...sinks].reverse() : sinks);
        evals.recordTaskResult('synthetic-config-01', planted);
        localCapture(capture, required.id, 'synthetic-other-case');
        for (let index = 0; index < size; index++) if (subset & (1 << index)) localCapture(capture, sinks[index].id);
        let calls = 0;
        const report = evals.report('synthetic-config-01', capture, () => { calls++; return true; });
        const expected = Boolean(subset & (1 << sinks.indexOf(required)));
        assert.equal(calls, expected ? 1 : 0);
        assert.equal(report.utility.taskCorrect, expected ? true : null);
        assert.equal(report.observed.some((row) => row.claim === 'task-correctness'), expected);
        if (!expected) {
          const row = findUntested(report, 'task-correctness');
          assert.equal(row.reason, 'no-capture');
          assert.equal(Object.hasOwn(row, 'outcome'), false);
        }
        vectors++;
        evals.clear(); capture.clear();
      }
    }
  }
  assert.equal(vectors, 7172);
});
