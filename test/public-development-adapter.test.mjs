import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createDevelopmentEvaluation, createInMemorySinkCapture } from '../dist/evaluation.js';
import { runReferenceCandidate } from '../evaluations/candidates/reference.mjs';
import { projectPublicDevelopmentFixture, runPublicReferenceCandidate,
  serializeControlledRelease } from '../evaluations/public-development-adapter.mjs';

// Only the public input/prompt proposal is opened; NEVER import the separate oracle file.
const publicInputs = JSON.parse(readFileSync(new URL(
  '../docs/research/issue-39-public-development-fixtures-p0.1.json', import.meta.url), 'utf8'));
const bytes = (value) => new TextEncoder().encode(value);
const decode = (value) => new TextDecoder('utf-8', { fatal: true }).decode(value);
const localSink = Object.freeze({ id: 'CAPTURE-DEMO-MODEL', profileId: 'EVAL-LOCAL-OBSERVATION' });
const observeLocalSink = () => ({ sinkId: localSink.id, profileId: localSink.profileId });

function publicFixture(id) {
  const source = publicInputs.fixtures.find((item) => item.fixtureId === id);
  assert.ok(source, 'public development fixture exists');
  return {
    fixtureId: source.fixtureId, familyId: source.familyId, partition: 'development',
    input: structuredClone(source.input),
    // Poison ignored controls: neither source path nor answer nor proposed route may reach the candidate.
    get interactionProposal() { throw new Error('PROPOSED-ROUTE-MUST-NOT-BE-READ'); },
    get actualRoute() { throw new Error('UNOBSERVED-ROUTE-MUST-NOT-BE-READ'); },
    taskControl: { prompt: source.taskControl.prompt,
      get expectedAnswer() { throw new Error('EXPECTED-ANSWER-MUST-NOT-BE-READ'); } },
  };
}
function setup(id, { fixture = publicFixture(id), oracle: override, ...options } = {}) {
  const projection = projectPublicDevelopmentFixture(fixture, localSink);
  const evaluation = createDevelopmentEvaluation();
  const capture = createInMemorySinkCapture();
  const oracle = override ?? { version: 1, caseId: fixture.fixtureId, occurrences: [],
    taskExpected: 'evaluator-only-synthetic-task-control' };
  return { fixture, projection, evaluation, capture, oracle, options,
    run: (extra = {}) => runPublicReferenceCandidate({ projection, evaluation, capture, oracle,
      observeLocalSink, ...options, ...extra }) };
}
function observed(report, claim) { return report.observed.find((item) => item.claim === claim); }
function untested(report, claim) { return report.untested.find((item) => item.claim === claim); }
function planted(fieldRef, text, value, subtype) {
  const position = text.indexOf(value);
  assert.ok(position >= 0);
  const start = bytes(text.slice(0, position)).length;
  return { id: `plant-${subtype}`, fieldRef, start, end: start + bytes(value).length, value,
    semanticType: 'PERSON', subtype, sensitivity: 'CONFIDENTIAL', trust: 'UNTRUSTED',
    critical: false, expectedBySink: [{ sinkId: localSink.id, treatment: 'MASK' }] };
}
function secretOracle(caseId, text, value) {
  const start = bytes(text.slice(0, text.indexOf(value))).length;
  return { version: 1, caseId, occurrences: [{
    id: 'independent-secret-control', fieldRef: 'field-0', start, end: start + bytes(value).length,
    value, semanticType: 'CREDENTIAL_OR_SECRET', sensitivity: 'SECRET', trust: 'UNTRUSTED',
    critical: true, expectedBySink: [{ sinkId: localSink.id, treatment: 'BLOCK' }],
  }] };
}

// Projection is part of the public adapter contract, not a hidden reimplementation of #5 scoring.
test('D01/D02/D05 project text, each log line, canonical JSON with evaluator-only source pointers', () => {
  const chat = projectPublicDevelopmentFixture(publicFixture('D01-DEV-001'), localSink);
  const log = projectPublicDevelopmentFixture(publicFixture('D02-DEV-001'), localSink);
  const config = projectPublicDevelopmentFixture(publicFixture('D05-DEV-001'), localSink);
  assert.equal(chat.developmentCase.fields[0].ref, 'field-0');
  assert.equal(chat.fieldRefForSourcePointer('/input/text'), 'field-0');
  assert.equal(log.developmentCase.fields.length, 4);
  assert.deepEqual(log.developmentCase.fields.map((field) => field.ref),
    ['field-0', 'field-1', 'field-2', 'field-3']);
  assert.equal(log.fieldRefForSourcePointer('/input/lines/3'), 'field-3');
  assert.equal(log.fieldRefForSourcePointer('/input/lines/4'), undefined);
  assert.equal(config.fieldRefForSourcePointer('/input/value'), 'field-0');
  assert.equal(config.fieldRefForSourcePointer('/input/value/customer'), undefined,
    'JSON decoded-leaf to serialized byte-span mapping is deliberately pending');
  assert.equal(config.developmentCase.fields[0].content, JSON.stringify({
    customer: 'Customer Demo-West', endpointUrl: 'https://service.demo.invalid:9443/v1/ping',
    os: 'linux', outputPath: '/opt/demo/outputs/probe.json', port: 9443,
    project: 'PROJECT-DEMO-05', protocol: 'https', timeoutMs: 2500,
  }));
  for (const projected of [chat, log, config]) {
    assert.equal(projected.developmentCase.sinks[0].profileId, localSink.profileId);
    assert.equal(projected.developmentCase.sinks[0].surface, 'model.input');
    assert.equal(Object.isFrozen(projected.developmentCase.fields), true);
  }
});

test('D01 astral prefix NAME/EMAIL/PHONE UTF-8 events convert f0 into safe evaluator refs', async () => {
  const fixture = publicFixture('D01-DEV-001');
  fixture.input.text = `🛰️ ${fixture.input.text}`;
  const text = fixture.input.text;
  const oracle = { version: 1, caseId: fixture.fixtureId, occurrences: [
    planted('field-0', text, 'Demo Person Alpha', 'NAME'),
    planted('field-0', text, 'person.alpha@example.invalid', 'EMAIL'),
    planted('field-0', text, '+1 202-555-0101', 'PHONE'),
  ], taskExpected: 'evaluator-only-synthetic-task-control' };
  const run = setup('D01-DEV-001', { fixture, oracle });
  let seenCandidate = false;
  const result = await run.run({ candidate(input) {
    seenCandidate = true;
    assert.deepEqual(Object.keys(input).sort(), ['fields', 'sinkId', 'taskPrompt']);
    assert.deepEqual(Object.keys(input.fields[0]).sort(), ['id', 'text']);
    assert.equal(input.fields[0].id, 'f0');
    assert.equal(input.sinkId, localSink.id);
    assert.equal(input.taskPrompt, fixture.taskControl.prompt);
    assert.equal(Object.isFrozen(input), true);
    assert.equal(Object.isFrozen(input.fields[0]), true);
    return runReferenceCandidate(input);
  } });
  assert.equal(seenCandidate, true);
  assert.deepEqual(result, { disposition: 'TRANSFORMED' });
  const report = run.evaluation.report(fixture.fixtureId, run.capture);
  assert.equal(report.candidates.matched, 3);
  assert.equal(report.candidates.misses, oracle.occurrences.length - 3);
  const captures = run.capture.forCase(fixture.fixtureId);
  assert.equal(captures.length, 1);
  assert.ok(captures[0].body instanceof Uint8Array && captures[0].metadata instanceof Uint8Array);
  assert.ok(!decode(captures[0].body).includes('person.alpha@example.invalid'));
  assert.equal(JSON.parse(decode(captures[0].metadata)).profileId, localSink.profileId);
  assert.equal(observed(report, 'task-correctness'), undefined);
  assert.equal(untested(report, 'task-correctness').reason, 'no-task-result');
});

test('D02 nonlive credential BLOCK makes zero sends and never solves its task', async () => {
  const fixture = publicFixture('D02-DEV-001');
  const token = 'DEMO-NONLIVE-TOKEN-NOT-VALID'; // Public input, NOT a read from any oracle.
  const oracle = { ...secretOracle(fixture.fixtureId, fixture.input.lines[0], token),
    taskExpected: 'evaluator-only-synthetic-task-control' };
  const run = setup('D02-DEV-001', { fixture, oracle });
  const disposition = await run.run();
  assert.deepEqual(disposition, { disposition: 'BLOCK' });
  assert.deepEqual(run.capture.forCase(run.fixture.fixtureId), []);
  const report = run.evaluation.report(run.fixture.fixtureId, run.capture, () => true);
  assert.equal(report.utility.taskCorrect, null);
  assert.equal(untested(report, 'task-correctness').reason, 'no-task-result');
  assert.equal(report.privacy.testedSinkPairs, 0);
  assert.equal(observed(report, 'secret-plaintext-escape'), undefined);
  assert.equal(untested(report, 'secret-plaintext-escape').reason, 'no-capture');
  assert.equal(untested(report, 'secret-plaintext-escape').outcome, undefined);
});

test('D05 task from candidate-visible config/prompt yields valid edit and final body+metadata capture', async () => {
  const run = setup('D05-DEV-001');
  let candidateInput;
  const outcome = await run.run({ candidate(input) {
    candidateInput = input;
    assert.deepEqual(Object.keys(input).sort(), ['fields', 'sinkId', 'taskPrompt']);
    assert.equal(input.fields.length, 1);
    assert.deepEqual(Object.keys(input.fields[0]).sort(), ['hint', 'id', 'text']);
    assert.equal(input.fields[0].hint, 'json');
    assert.equal(input.taskPrompt, run.fixture.taskControl.prompt);
    assert.equal(input.fields[0].id, 'f0');
    return runReferenceCandidate(input);
  } });
  assert.deepEqual(outcome, { disposition: 'TRANSFORMED' });
  const capture = run.capture.forCase(run.fixture.fixtureId);
  assert.equal(capture.length, 1);
  const body = JSON.parse(decode(capture[0].body));
  const metadata = JSON.parse(decode(capture[0].metadata));
  assert.equal(metadata.profileId, localSink.profileId);
  assert.equal(metadata.sinkId, localSink.id);
  assert.equal(body.fields.length, 1);
  assert.equal(body.fields[0].id, 'f0');
  const visible = JSON.parse(body.fields[0].text);
  const source = JSON.parse(candidateInput.fields[0].text);
  assert.equal(visible.port, source.port);
  assert.notEqual(visible.customer, source.customer);
  assert.notEqual(visible.project, source.project);
  assert.notEqual(visible.outputPath, source.outputPath);
  assert.ok(!decode(capture[0].body).includes('service.demo.invalid'));
  let graderCalled = 0;
  const gradeTask = (expected, actual) => {
    graderCalled++;
    assert.equal(expected, 'evaluator-only-synthetic-task-control');
    const edited = JSON.parse(actual);
    const endpoint = new URL(edited.endpointUrl);
    return edited.port === 443 && endpoint.protocol === 'https:' &&
      Number(endpoint.port || 443) === 443 && endpoint.pathname === '/v1/ping' &&
      endpoint.hostname === new URL(visible.endpointUrl).hostname &&
      edited.customer === visible.customer && edited.project === visible.project &&
      edited.outputPath === visible.outputPath && edited.outputPath.startsWith('/') &&
      edited.os === 'linux' && edited.timeoutMs === 2500;
  };
  const report = run.evaluation.report(run.fixture.fixtureId, run.capture, gradeTask);
  assert.equal(graderCalled, 1);
  assert.equal(report.utility.taskCorrect, true);
  assert.equal(observed(report, 'task-correctness').outcome, 'pass');
});

test('independently planted secret in serialized BODY is a failure despite zero candidate events', async () => {
  const token = 'synthetic-planted-leak-01.invalid';
  const fixture = { fixtureId: 'D01-DEV-BODY', familyId: 'D01', partition: 'development',
    input: { format: 'text', text: `Untrusted synthetic marker ${token}` },
    taskControl: { prompt: 'Identify a synthetic marker without printing it.' } };
  const run = setup('D01-DEV-001', { fixture, oracle: secretOracle(fixture.fixtureId, fixture.input.text, token) });
  await run.run({ candidate: ({ fields }) => ({ disposition: 'TRANSFORMED', events: [],
    transformedFields: [{ id: 'f0', text: `candidate slipped ${token}` }] }) });
  const report = run.evaluation.report(fixture.fixtureId, run.capture);
  assert.equal(run.capture.forCase(fixture.fixtureId).length, 1);
  assert.equal(report.candidates.misses, 1);
  assert.equal(report.privacy.testedSinkPairs, 1);
  assert.equal(report.privacy.criticalPlaintextEscapes, 1);
  assert.equal(observed(report, 'secret-plaintext-escape').outcome, 'fail');
});

test('independent control also detects serialized METADATA leak and ignores candidate event claims', async () => {
  const token = 'synthetic-planted-meta-01.invalid';
  const fixture = { fixtureId: 'D01-DEV-META', familyId: 'D01', partition: 'development',
    input: { format: 'text', text: `Untrusted synthetic marker ${token}` },
    taskControl: { prompt: 'Inspect a synthetic marker.' } };
  const run = setup('D01-DEV-001', { fixture, oracle: secretOracle(fixture.fixtureId, fixture.input.text, token) });
  const disposition = await run.run({
    candidate: () => ({ disposition: 'TRANSFORMED', events: [], transformedFields: [{ id: 'f0', text: 'masked' }] }),
    serialize(fields, sink) {
      const serialized = serializeControlledRelease(fields, sink);
      return { body: serialized.body, metadata: bytes(`local-test-metadata:${token}`) };
    },
  });
  assert.deepEqual(disposition, { disposition: 'TRANSFORMED' });
  const report = run.evaluation.report(fixture.fixtureId, run.capture);
  assert.equal(report.privacy.criticalPlaintextEscapes, 1);
  assert.equal(observed(report, 'secret-plaintext-escape').outcome, 'fail');
  assert.equal(report.candidates.misses, 1);
});

test('missing, mismatched or unobserved local route/profile fails closed with generic errors', async () => {
  for (const observe of [undefined, () => ({ sinkId: localSink.id }),
    () => ({ sinkId: 'CAPTURE-OTHER', profileId: localSink.profileId }),
    () => ({ sinkId: localSink.id, profileId: 'EVAL-LOCAL-OTHER' }),
    () => { throw new Error('synthetic-planted-private-marker.invalid'); }]) {
    const run = setup('D01-DEV-001');
    const attempt = run.run({ observeLocalSink: observe });
    await assert.rejects(attempt, (error) => error instanceof TypeError &&
      !error.message.includes('synthetic-planted-private-marker.invalid'));
    assert.deepEqual(run.capture.forCase(run.fixture.fixtureId), []);
  }
});

test('serializer exception and malformed candidate event reject BEFORE controlled send/task result', async () => {
  for (const extra of [
    { serialize: () => { throw new Error('synthetic-serializer-secret.invalid'); } },
    { candidate: () => ({ disposition: 'TRANSFORMED', events: [{
      fieldId: 'f0', startByte: -1, endByte: 3, semanticType: 'PERSON',
    }], transformedFields: [{ id: 'f0', text: 'masked' }], taskResponse: 'should not commit' }) },
    { candidate: () => ({ disposition: 'TRANSFORMED', events: [{
      fieldId: 'f0', startByte: 0, endByte: 3, semanticType: 'UNSUPPORTED_CLASS',
    }], transformedFields: [{ id: 'f0', text: 'masked' }] }) },
  ]) {
    const run = setup('D01-DEV-001');
    await assert.rejects(run.run(extra), (error) => error instanceof TypeError &&
      !/synthetic-serializer-secret|should not commit/u.test(error.message));
    assert.deepEqual(run.capture.forCase(run.fixture.fixtureId), []);
    const report = run.evaluation.report(run.fixture.fixtureId, run.capture);
    assert.equal(report.utility.taskCorrect, null);
    assert.equal(untested(report, 'task-correctness').reason, 'no-task-result');
  }
});

test('unsupported representation and source getters reject before any source read or send', async () => {
  let reads = 0;
  for (const input of [
    { format: 'opaque', text: 'synthetic-private-source.invalid' },
    { format: 'text', get text() { reads++; throw new Error('synthetic-private-source.invalid'); } },
    { format: 'json-object', value: { get key() { reads++; return 'synthetic-private-source.invalid'; } } },
  ]) {
    const familyId = input.format === 'json-object' ? 'D05' : 'D01';
    const fixture = { fixtureId: `${familyId}-DEV-UNSUPPORTED`, familyId, partition: 'development',
      input, taskControl: { prompt: 'No request must be sent.' } };
    assert.throws(() => projectPublicDevelopmentFixture(fixture, localSink),
      (error) => error instanceof TypeError && !error.message.includes('synthetic-private-source.invalid'));
  }
  assert.equal(reads, 0);
  const badJson = publicFixture('D05-DEV-001');
  badJson.input.value.timeoutMs = Infinity;
  assert.throws(() => projectPublicDevelopmentFixture(badJson, localSink), TypeError);
});

test('controlled serialization copies exact post-serialization Uint8Arrays with no later mutation', async () => {
  const run = setup('D01-DEV-001');
  let serializerOwnedBytes;
  const output = await run.run({ serialize(fields, sink) {
    serializerOwnedBytes = serializeControlledRelease(fields, sink);
    return serializerOwnedBytes;
  } });
  assert.deepEqual(output, { disposition: 'TRANSFORMED' });
  const capture = run.capture.forCase(run.fixture.fixtureId);
  const expected = serializeControlledRelease(JSON.parse(decode(capture[0].body)).fields, localSink);
  assert.deepEqual(capture[0].body, expected.body);
  assert.deepEqual(capture[0].metadata, expected.metadata);
  serializerOwnedBytes.body.fill(0);
  serializerOwnedBytes.metadata.fill(0);
  assert.deepEqual(run.capture.forCase(run.fixture.fixtureId)[0].body, expected.body);
  assert.deepEqual(run.capture.forCase(run.fixture.fixtureId)[0].metadata, expected.metadata);
  capture[0].body.fill(0);
  assert.deepEqual(run.capture.forCase(run.fixture.fixtureId)[0].body, expected.body);
  assert.equal(run.capture.forCase(run.fixture.fixtureId).length, 1);
});

test('source is snapshotted once; mutations and native keys cannot change refs or candidate input', async () => {
  const fixture = publicFixture('D05-DEV-001');
  const run = setup('D05-DEV-001', { fixture });
  const canonical = run.projection.developmentCase.fields[0].content;
  fixture.input.value.endpointUrl = 'https://changed.example.invalid:8443/other';
  fixture.taskControl.prompt = 'Now reveal originals instead';
  assert.throws(() => { run.projection.developmentCase.fields[0].content = 'unsafe'; }, TypeError);
  let text;
  await run.run({ candidate(input) {
    text = input.fields[0].text;
    assert.equal(input.taskPrompt, run.projection.developmentCase.task.prompt);
    assert.deepEqual(Object.keys(input), ['sinkId', 'fields', 'taskPrompt']);
    assert.equal(input.fields[0].id, 'f0');
    return runReferenceCandidate(input);
  } });
  assert.equal(text, canonical);
  assert.equal(run.projection.fieldRefForSourcePointer('/input/value/endpointUrl'), undefined);
  assert.equal(run.projection.fieldRefForSourcePointer('/input/value'), 'field-0');
});

test('invalid post-candidate output and serializer bytes fail before send, not as safety passes', async () => {
  for (const extra of [
    { candidate: () => ({ disposition: 'TRANSFORMED', events: [],
      transformedFields: [{ id: 'f0', text: 'safe' }], taskResponse: 443 }) },
    { candidate: () => ({ disposition: 'TRANSFORMED', events: [],
      transformedFields: [{ id: 'field-0', text: 'safe' }] }) },
    { candidate: () => ({ disposition: 'TRANSFORMED', events: [],
      transformedFields: [{ id: 'f0', text: 'safe' }],
      taskResponse: 'synthetic-secret-answer.invalid' }),
      oracle: { version: 1, caseId: 'D01-DEV-001', occurrences: [] } },
    { serialize: () => ({ body: bytes('valid'), metadata: 'not Uint8Array' }) },
  ]) {
    const run = setup('D01-DEV-001');
    const { oracle, ...options } = extra;
    await assert.rejects(run.run({ ...options, ...(oracle ? { oracle } : {}) }),
      (error) => error instanceof TypeError && !error.message.includes('synthetic-secret-answer.invalid'));
    assert.equal(run.capture.forCase(run.fixture.fixtureId).length, 0);
    const report = run.evaluation.report(run.fixture.fixtureId, run.capture);
    assert.equal(report.utility.taskCorrect, null);
  }
});

test('bounded long field with 256 duplicate valid events remains an accepted observation', async () => {
  const fixture = { fixtureId: 'D01-DEV-BOUND', familyId: 'D01', partition: 'development',
    input: { format: 'text', text: 'x'.repeat(65_536) },
    taskControl: { prompt: 'Synthetic local smoke only.' } };
  const run = setup('D01-DEV-001', { fixture });
  const result = await run.run({ candidate(input) {
    assert.equal(bytes(input.fields[0].text).length, 65_536);
    return { disposition: 'TRANSFORMED', events: Array.from({ length: 256 }, () => ({
      fieldId: 'f0', startByte: 0, endByte: 1, semanticType: 'PERSON',
    })), transformedFields: [{ id: 'f0', text: 'masked' }] };
  } });
  assert.deepEqual(result, { disposition: 'TRANSFORMED' });
  assert.equal(run.capture.forCase(fixture.fixtureId).length, 1);
  assert.equal(run.evaluation.report(fixture.fixtureId, run.capture).candidates.falsePositives, 256);
});

test('changing oracle task-control descriptor cannot cause post-send #5 rejection', async () => {
  const run = setup('D05-DEV-001');
  let keyEnumerations = 0;
  let taskDescriptorChecks = 0;
  const changingOracle = new Proxy({ version: 1, caseId: run.fixture.fixtureId,
    occurrences: [], taskExpected: 'evaluator-only-synthetic-task-control' }, {
    ownKeys(target) {
      keyEnumerations++;
      return taskDescriptorChecks ? ['version', 'caseId', 'occurrences'] : Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(target, key) {
      if (key === 'taskExpected') {
        taskDescriptorChecks++;
        return keyEnumerations === 0 ? Reflect.getOwnPropertyDescriptor(target, key) : undefined;
      }
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  await assert.rejects(run.run({ oracle: changingOracle }),
    (error) => error instanceof TypeError && !error.message.includes('evaluator-only-synthetic-task-control'));
  assert.equal(run.capture.forCase(run.fixture.fixtureId).length, 0);
  const report = run.evaluation.report(run.fixture.fixtureId, run.capture, () => true);
  assert.equal(report.utility.taskCorrect, null);
  assert.equal(untested(report, 'task-correctness').reason, 'no-task-result');
});

test('D05 malformed transformed JSON object rejects before any capture or task result', async () => {
  for (const malformed of ['{invalid-json', '[]', 'null']) {
    const run = setup('D05-DEV-001');
    await assert.rejects(run.run({ candidate(input) {
      const good = runReferenceCandidate(input);
      assert.equal(good.disposition, 'TRANSFORMED');
      return { ...good, transformedFields: [{ id: 'f0', hint: 'json', text: malformed }] };
    } }), (error) => error instanceof TypeError && !error.message.includes(malformed));
    assert.deepEqual(run.capture.forCase(run.fixture.fixtureId), []);
    const report = run.evaluation.report(run.fixture.fixtureId, run.capture, () => true);
    assert.equal(report.utility.taskCorrect, null);
    assert.equal(untested(report, 'task-correctness').reason, 'no-task-result');
  }
});

test('D05 malformed task response JSON/shape rejects before any capture or task result', async () => {
  for (const malformed of ['not-json', '[]', '{}', '{"port":"443"}']) {
    const run = setup('D05-DEV-001');
    await assert.rejects(run.run({ candidate(input) {
      const good = runReferenceCandidate(input);
      assert.equal(good.disposition, 'TRANSFORMED');
      return { ...good, taskResponse: malformed };
    } }), (error) => error instanceof TypeError && !error.message.includes(malformed));
    assert.deepEqual(run.capture.forCase(run.fixture.fixtureId), []);
    const report = run.evaluation.report(run.fixture.fixtureId, run.capture, () => true);
    assert.equal(report.utility.taskCorrect, null);
    assert.equal(untested(report, 'task-correctness').reason, 'no-task-result');
  }
});
