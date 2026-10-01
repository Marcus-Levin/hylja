import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { composeClassification } from '../dist/classification.js';
import { decidePolicy, digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE } from '../dist/policy.js';
import {
  ADVERSARIAL_KEEP_LABEL, SHADOW_CANDIDATE_KINDS, SHADOW_CONTEXT_CODES, SHADOW_CONTEXT_KEYS,
  SHADOW_JUDGMENT_PURPOSES, SHADOW_JUDGE_VERSION, SHADOW_MAX_CHOICE_OPTIONS, SHADOW_MAX_CONTEXT_ENTRIES,
  SHADOW_MAX_JSON_DEPTH, SHADOW_MAX_JSON_KEYS, SHADOW_MAX_JSON_STRING, SHADOW_MAX_NEIGHBORS,
  SHADOW_MAX_QUESTIONS, SHADOW_MAX_RESPONSE_COPY_BYTES, SHADOW_MAX_SCRIPT_ANSWER_KEYS,
  SHADOW_MAX_SCORE_LEVELS, SHADOW_MIN_SCORE_LEVELS, SHADOW_QUESTION_KINDS, SHADOW_REASON_CODES,
  SHADOW_TREATMENTS, belongsToShadowTenant, createLocalShadowJudge, defineShadowQuestionSet,
  generateShadowVectors, minimizeShadowRequest, parseShadowJudgePayload, runShadowJudgment,
  shadowReasonCodes, shadowSensitivityRank,
} from '../dist/semantic-judge-shadow.js';

// Synthetic, obviously non-routable local development values only.
const PLANTED = 'synthetic-planted-person@example.invalid';
const NEIGHBOR = 'synthetic-neighbour-note@example.invalid';
const REF = 'candidate-a.invalid';
const TENANT = 'tenant-a.invalid';
const INTERACTION = 'interaction-a.invalid';

const questionSet = () => defineShadowQuestionSet({
  id: 'shadow.dev.v1', version: '1',
  questions: [
    { id: 'is_person', kind: 'noul', purpose: 'PERSON_IDENTITY',
      instructions: 'Does `cand-01` refer to a natural person?',
      criteria: { true: 'a natural person', false: 'not a natural person' },
      propose: { semanticType: 'PERSON' } },
    { id: 'class', kind: 'choice', purpose: 'CONTEXT_KIND',
      instructions: 'Which class best fits `cand-01`?',
      criteria: { person: 'a natural person', host: 'a host or service',
        [ADVERSARIAL_KEEP_LABEL]: 'the judge thinks this value is safe to keep' },
      propose: { byLabel: { person: 'PERSON', host: 'HOST_OR_SERVICE',
        [ADVERSARIAL_KEEP_LABEL]: 'NETWORK_IDENTIFIER' } } },
    { id: 'utility', kind: 'score', purpose: 'UTILITY_NECESSITY',
      instructions: 'How necessary is the exact value for the task?',
      criteria: ['not needed', 'needed'],
      propose: { byLabel: { '0': 'PERSON', '1': 'PERSON' } } },
  ],
});
const answeringJudge = (over = {}) => createLocalShadowJudge({
  id: 'local-double', version: '1', servedModel: 'local-synthetic/jev-sim', latencyMs: 0, mode: 'ANSWER',
  answers: {
    is_person: { kind: 'noul', noul: 0.91 },
    class: { kind: 'choice', choice: ADVERSARIAL_KEEP_LABEL,
      probabilities: { person: 0.1, host: 0.2, [ADVERSARIAL_KEEP_LABEL]: 0.7 }, confidence: 0.7 },
    utility: { kind: 'score', score: 0.8, probabilities: { '0': 0.2, '1': 0.8 }, confidence: 0.8 },
  },
  ...over,
});
const candidateInput = (over = {}) => ({
  candidate: { ref: REF, kind: 'PERSON_REFERENCE', raw: PLANTED },
  neighbors: [{ kind: 'CONTACT_REFERENCE', raw: NEIGHBOR }, { kind: 'PERSON_REFERENCE', raw: PLANTED }],
  context: [{ key: 'surface', code: 'log-line' }, { key: 'fieldKind', code: 'name' }],
  ...over,
});
const inProcess = (over = {}) => ({ execution: 'IN_PROCESS', deadlineMs: 1000, ...over });
const reasonSet = (record) => new Set(record.reasons);
const run = async (set, judge, input, options, tenantRef = TENANT) => {
  const result = runShadowJudgment(set, judge, INTERACTION, tenantRef, input, options);
  const record = await result.record;
  return { record, settlement: await result.settlement };
};

/* ----------------------------------------------------------------- versioned question sets */

test('the shipped seam is versioned and its vocabularies are closed and credential-free', () => {
  assert.equal(SHADOW_JUDGE_VERSION, 'hylja.semantic-judge-shadow.v1');
  assert.deepEqual([...SHADOW_QUESTION_KINDS], ['noul', 'choice', 'score']);
  assert.ok(SHADOW_MAX_CHOICE_OPTIONS === 255 && SHADOW_MIN_SCORE_LEVELS === 2 &&
    SHADOW_MAX_SCORE_LEVELS === 10, 'documented System One limits are pinned');
  assert.ok(SHADOW_MAX_QUESTIONS >= 1 && SHADOW_MAX_NEIGHBORS >= 1 && SHADOW_MAX_CONTEXT_ENTRIES >= 1);
  assert.deepEqual(SHADOW_CONTEXT_KEYS, Object.keys(SHADOW_CONTEXT_CODES).sort());
  assert.equal(SHADOW_CANDIDATE_KINDS.some((kind) => /CREDENTIAL|SECRET|PASSWORD|TOKEN_VALUE/u.test(kind)),
    false, 'no credential kind is representable as judge input');
  assert.deepEqual([...SHADOW_TREATMENTS],
    ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE', 'BLOCK', 'REQUIRE_REVIEW']);
  for (const purpose of SHADOW_JUDGMENT_PURPOSES) assert.match(purpose, /^[A-Z_]+$/u);
  assert.equal(new Set(SHADOW_REASON_CODES).size, SHADOW_REASON_CODES.length, 'reason codes are unique');
  for (const code of SHADOW_REASON_CODES) assert.match(code, /^[A-Z_]+$/u, code);
});

test('question sets are versioned configuration: structural limits and duplicate ids are refused', () => {
  const questions = Array.from({ length: SHADOW_MAX_QUESTIONS }, (_value, index) => ({
    id: `q_${index}`, kind: 'noul', purpose: 'CONTEXT_KIND', instructions: 'Is `cand-01` present?',
  }));
  assert.equal(defineShadowQuestionSet({ id: 'q.v1', version: '1', questions }).questions.length,
    SHADOW_MAX_QUESTIONS);
  assert.throws(() => defineShadowQuestionSet({ id: 'q.v1', version: '1',
    questions: [...questions.slice(0, 4), { ...questions[0] }] }),
  (error) => error.message === 'DUPLICATE_QUESTION_ID');
  assert.throws(() => defineShadowQuestionSet({ id: 'q.v1', version: '1',
    questions: [...questions, { id: `q_${SHADOW_MAX_QUESTIONS}`, kind: 'noul', purpose: 'CONTEXT_KIND',
      instructions: 'x' }] }), (error) => error.message === 'TOO_MANY_QUESTIONS');
  // Question ids travel as request metadata, so a value-shaped id is refused outright.
  assert.throws(() => defineShadowQuestionSet({ id: 'q.v1', version: '1',
    questions: [{ id: PLANTED, kind: 'noul', purpose: 'CONTEXT_KIND', instructions: 'x' }] }),
  (error) => error.message === 'QUESTION_ID_REVEALS_VALUE');
  assert.throws(() => defineShadowQuestionSet({ id: 'q.v1', version: '1', questions: [{ id: 'a', kind: 'vote',
    purpose: 'CONTEXT_KIND', instructions: 'x' }] }), (error) => error.message === 'INVALID_REQUEST');
  assert.throws(() => defineShadowQuestionSet({ id: 'q.v1', version: '1', questions: [{ id: 'a', kind: 'choice',
    purpose: 'CONTEXT_KIND', instructions: 'x', criteria: { only_one: 'single option' } }] }),
  (error) => error.message === 'INVALID_REQUEST', 'a Choice needs at least two documented options');
  assert.throws(() => defineShadowQuestionSet({ id: 'q.v1', version: '1', questions: [{ id: 'a', kind: 'score',
    purpose: 'CONTEXT_KIND', instructions: 'x', criteria: ['only one level'] }] }),
  (error) => error.message === 'SCORE_LEVELS_INVALID');
  // A proposal may name a semantic class only: sensitivity, reversibility and scope are excluded.
  assert.throws(() => defineShadowQuestionSet({ id: 'q.v1', version: '1', questions: [{ id: 'a', kind: 'noul',
    purpose: 'CONTEXT_KIND', instructions: 'x', propose: { semanticType: 'PERSON', sensitivity: 'PUBLIC' } }] }),
  (error) => error.message === 'UNEXPECTED_FIELD');
  assert.equal(questionSet().questions[1].criteria[ADVERSARIAL_KEEP_LABEL].length > 0, true);
});

/* -------------------------------------------------------------------- request minimization */

test('a minimized request is exactly the placeholder view: no raw candidate, neighbour or value', () => {
  const request = minimizeShadowRequest(INTERACTION, TENANT, questionSet(), answeringJudge(),
    candidateInput());
  assert.deepEqual(JSON.parse(JSON.stringify(request)), {
    version: 1, interactionRef: INTERACTION, tenantRef: TENANT,
    questionSet: { id: 'shadow.dev.v1', version: '1' },
    judge: { id: 'local-double', version: '1', transport: 'IN_PROCESS' },
    model: { requested: 'local-synthetic' },
    state: {
      candidate: { placeholder: 'cand-01', kind: 'PERSON_REFERENCE' },
      neighbors: [{ placeholder: 'nbr-01', kind: 'CONTACT_REFERENCE' },
        { placeholder: 'nbr-02', kind: 'PERSON_REFERENCE' }],
      context: [{ key: 'surface', code: 'log-line' }, { key: 'fieldKind', code: 'name' }],
    },
    questions: [
      { id: 'is_person', kind: 'noul', purpose: 'PERSON_IDENTITY',
        instructions: 'Does `cand-01` refer to a natural person?',
        criteria: { true: 'a natural person', false: 'not a natural person' } },
      { id: 'class', kind: 'choice', purpose: 'CONTEXT_KIND',
        instructions: 'Which class best fits `cand-01`?',
        criteria: { person: 'a natural person', host: 'a host or service',
          [ADVERSARIAL_KEEP_LABEL]: 'the judge thinks this value is safe to keep' } },
      { id: 'utility', kind: 'score', purpose: 'UTILITY_NECESSITY',
        instructions: 'How necessary is the exact value for the task?',
        criteria: ['not needed', 'needed'] },
    ],
  });
  const serialized = JSON.stringify(request);
  for (const planted of [PLANTED, NEIGHBOR, 'raw', '@example.invalid']) {
    assert.equal(serialized.includes(planted), false, `minimized request must omit ${planted}`);
  }
  // Minimization is content independent: different raw text, same placeholder view, same digest input.
  const other = minimizeShadowRequest(INTERACTION, TENANT, questionSet(), answeringJudge(),
    candidateInput({ candidate: { ref: REF, kind: 'PERSON_REFERENCE', raw: 'completely different' } }));
  assert.equal(JSON.stringify(other), serialized);
});

test('minimization accepts only issued configuration, bounded approved context and opaque refs', () => {
  const set = questionSet();
  const judge = answeringJudge();
  // A caller cannot substitute its own look-alike question set or judge object.
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, { ...set }, judge, candidateInput()),
    (error) => error.message === 'INVALID_REQUEST');
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, set, { ...judge }, candidateInput()),
    (error) => error.message === 'INVALID_REQUEST');
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, set, judge,
    candidateInput({ candidate: { ref: REF, kind: 'CREDENTIAL_OR_SECRET', raw: PLANTED } })),
  (error) => error.message === 'INVALID_REQUEST', 'a credential is not representable judge input');
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, set, judge,
    candidateInput({ context: [{ key: 'planted_value', code: PLANTED }] })),
  (error) => error.message === 'UNAPPROVED_CONTEXT');
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, set, judge,
    candidateInput({ context: [{ key: 'surface', code: 'internal-logfile' }] })),
  (error) => error.message === 'UNAUTHORIZED_CONTEXT_CODE');
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, set, judge,
    candidateInput({ context: [{ key: 'surface', code: 'log-line' }, { key: 'surface', code: 'unknown' }] })),
  (error) => error.message === 'INVALID_CONTEXT');
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, set, judge, candidateInput({
    neighbors: Array.from({ length: SHADOW_MAX_NEIGHBORS + 1 }, () => ({ kind: 'PERSON_REFERENCE', raw: PLANTED })) })),
  (error) => error.message === 'TOO_MANY_NEIGHBORS');
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, set, judge, candidateInput({
    context: Array.from({ length: SHADOW_MAX_CONTEXT_ENTRIES + 1 }, (_value, index) =>
      ({ key: `fieldKind`, code: 'unknown', extra: index })) })),
  (error) => error.message === 'TOO_MANY_CONTEXT_ENTRIES');
  // A value-shaped, over-long or accessor-backed candidate field is refused, never read as text.
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, set, judge,
    candidateInput({ candidate: { ref: REF, kind: 'PERSON_REFERENCE' } })),
  (error) => error.message === 'INVALID_REQUEST');
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, set, judge,
    candidateInput({ candidate: { ref: ' candidate-a.invalid', kind: 'PERSON_REFERENCE', raw: PLANTED } })),
  (error) => error.message === 'INVALID_REQUEST');
  assert.throws(() => minimizeShadowRequest(INTERACTION, TENANT, set, judge, candidateInput({
    candidate: { ref: REF, kind: 'PERSON_REFERENCE', raw: 'x'.repeat(4097) } })),
  (error) => error.message === 'INVALID_REQUEST');
});

/* --------------------------------------------------------------- answered shadow judgment */

test('an answered local judgment is evidence only: no treatment, no release, no raw value', async () => {
  const { record } = await run(questionSet(), answeringJudge(), candidateInput(), inProcess());
  assert.equal(record.version, 1);
  assert.equal(record.outcome, 'ANSWERED');
  assert.deepEqual([...record.reasons], []);
  assert.equal(record.interactionRef, INTERACTION);
  assert.equal(record.tenantRef, TENANT);
  assert.equal(record.candidateRef, REF);
  assert.deepEqual(record.questionSet, { id: 'shadow.dev.v1', version: '1' });
  assert.deepEqual(record.judge, { id: 'local-double', version: '1', transport: 'IN_PROCESS' });
  assert.deepEqual(record.model, { requested: 'local-synthetic', served: 'local-synthetic/jev-sim' });
  assert.equal(record.authority, 'NONE');
  assert.deepEqual(record.advisory, { suggestedTreatment: 'NONE', effect: 'IGNORED_NO_AUTHORITY' });
  assert.deepEqual(record.deterministicFloor, { sensitivity: 'UNKNOWN', source: 'NONE' });
  assert.equal(Object.isFrozen(record), true);
  assert.equal(record.request.bytes > 0 && /^[0-9a-f]{64}$/u.test(record.request.digest), true);
  assert.equal(Number.isInteger(record.metadata.latencyMs) && record.metadata.latencyMs >= 0, true);
  assert.equal(record.metadata.deadlineMs, 1000);
  assert.deepEqual(record.metadata.usage, 'NONE');

  // Request metadata is versioned shadow metadata: served model, latency, probabilities, confidence.
  assert.deepEqual(record.answers.map((item) => item.questionId), ['is_person', 'class', 'utility']);
  const noul = record.answers[0];
  assert.deepEqual(noul.measure, { kind: 'noul', noul: 0.91 });
  const choice = record.answers[1];
  assert.equal(choice.measure.choice, ADVERSARIAL_KEEP_LABEL);
  assert.equal(choice.measure.selectionIsProviderClaimed, true);
  assert.equal(choice.measure.confidence, 0.7);
  assert.deepEqual({ ...choice.measure.probabilities },
    { person: 0.1, host: 0.2, [ADVERSARIAL_KEEP_LABEL]: 0.7 });
  const score = record.answers[2];
  assert.equal(score.measure.levelIsLocallyDerived, true, 'a discrete level is derived locally, not interpolated');
  assert.equal(score.measure.level, 1);

  // Semantic evidence only: a claim, never a sensitivity, subtype, scope, reversibility or trust.
  assert.equal(record.evidence.length, 3);
  for (const item of record.evidence) {
    assert.equal(item.status, 'FOUND');
    assert.equal(Object.hasOwn(item, 'source'), false, 'the composer channel names the source');
    assert.deepEqual(Object.keys(item.claim).sort(), ['confidence', 'semanticType']);
    assert.equal(item.provenance.questionSetVersion, 'shadow.dev.v1@1');
    assert.equal(item.provenance.modelId, 'local-synthetic/jev-sim');
    assert.equal(item.provenance.inputRef, REF);
  }
  const serialized = JSON.stringify(record);
  for (const planted of [PLANTED, NEIGHBOR, '@example.invalid']) {
    assert.equal(serialized.includes(planted), false, `record must omit ${planted}`);
  }
  for (const treatment of SHADOW_TREATMENTS) {
    assert.equal(serialized.includes(`"${treatment}"`), false, `a record must never name ${treatment}`);
  }
});

test('the request digest is stable, content independent and bound to question set and context', async () => {
  const first = await run(questionSet(), answeringJudge(), candidateInput(), inProcess());
  const second = await run(questionSet(), answeringJudge(), candidateInput({
    candidate: { ref: REF, kind: 'PERSON_REFERENCE', raw: 'a different synthetic raw value' } }),
  inProcess());
  const changedContext = await run(questionSet(), answeringJudge(),
    candidateInput({ context: [{ key: 'surface', code: 'config-file' }] }), inProcess());
  assert.equal(first.record.request.digest, second.record.request.digest,
    'the digest covers the minimized view, never the raw value');
  assert.notEqual(first.record.request.digest, changedContext.record.request.digest);
  assert.equal(first.record.request.digest,
    (await run(questionSet(), answeringJudge(), candidateInput(), inProcess({ deadlineMs: 2000 }))).record
      .request.digest, 'the minimized request does not depend on the caller deadline');
  const otherSet = defineShadowQuestionSet({
    id: 'shadow.dev.v1', version: '2',
    questions: [{ id: 'is_person', kind: 'noul', purpose: 'PERSON_IDENTITY', instructions: 'x?',
      propose: { semanticType: 'PERSON' } }],
  });
  const other = await run(otherSet, answeringJudge(), candidateInput(), inProcess());
  assert.notEqual(other.record.request.digest, first.record.request.digest,
    'a versioned question set change is a different request');
  assert.equal(other.record.outcome, 'ANSWERED', 'every question that still exists was answered');
  assert.equal(reasonSet(other.record).has('UNKNOWN_ANSWER'), true,
    'an answer for a removed question stays an explicit reason');
});

/* -------------------------------------------------------------- authority and failure modes */

test('a refused local judge is an explicit refusal, never a cancellation or an answer', async () => {
  const refusing = createLocalShadowJudge({
    id: 'local-double', version: '1', servedModel: 'local-synthetic/jev-sim', latencyMs: 0,
    mode: 'REFUSE',
  });
  const { record, settlement } = await run(questionSet(), refusing, candidateInput(), inProcess());
  assert.equal(record.outcome, 'REFUSED');
  assert.equal(reasonSet(record).has('ADAPTER_REFUSED'), true);
  assert.equal(reasonSet(record).has('CANCELLED'), false);
  assert.equal(record.answers.length, 0);
  assert.equal(record.evidence.length, 0);
  assert.equal(record.model.served, 'NONE');
  assert.equal(settlement.late, false);
});

test('external execution is refused before any request exists, whatever the caller claims', async () => {
  for (const attempt of ['EXTERNAL', 'IN_PROCESS_REMOTE', 'local']) {
    const record = (await run(questionSet(), answeringJudge(), candidateInput(),
      { execution: attempt, deadlineMs: 50 })).record;
    assert.equal(record.outcome, 'REFUSED', attempt);
    const reasons = reasonSet(record);
    for (const code of ['UNSUPPORTED_EXECUTION', 'MISSING_DESTINATION_POLICY', 'MISSING_ROUTE_BINDING',
      'MISSING_BYTE_VERIFICATION']) assert.equal(reasons.has(code), true, `${attempt}: ${code}`);
    assert.equal(record.request.bytes, 0, 'no request was built');
    assert.equal(record.evidence.length, 0);
  }
  // Caller flags are not an authorization primitive: unknown option keys are refused outright.
  for (const flag of [{ safe: true }, { synthetic: true }, { trusted: true }, { destinationPolicy: {} },
    { routeBinding: {} }, { byteVerified: true }, { authorization: 'granted' }]) {
    const record = (await run(questionSet(), answeringJudge(), candidateInput(),
      inProcess(flag))).record;
    assert.equal(record.outcome, 'REFUSED', JSON.stringify(Object.keys(flag)));
    assert.equal(reasonSet(record).has('UNEXPECTED_FIELD'), true,
      'an unknown option key is refused, not ignored');
  }
  for (const deadline of [0, -1, 1.5, 30_001]) {
    const record = (await run(questionSet(), answeringJudge(), candidateInput(), inProcess({ deadlineMs: deadline })))
      .record;
    assert.equal(record.outcome, 'REFUSED', String(deadline));
    assert.equal(reasonSet(record).has('INVALID_REQUEST'), true);
  }
});

test('a hosted served-model claim cannot be made by a local double', () => {
  for (const servedModel of ['jev-1.13.0', 'jev-latest', 'local-synthetic', 'synthetic']) {
    assert.throws(() => createLocalShadowJudge({ id: 'd', version: '1', servedModel, latencyMs: 0,
      mode: 'ANSWER' }), (error) => error.message === 'MODEL_ID_NOT_LOCAL', servedModel);
  }
  assert.equal(createLocalShadowJudge({ id: 'd', version: '1', servedModel: 'local-synthetic/ok',
    latencyMs: 0, mode: 'ANSWER' }).servedModel, 'local-synthetic/ok');
});

test('timeout, cancellation and a late result stay explicit, conservative and out of the record', async () => {
  const slow = answeringJudge({ latencyMs: 300 });
  const timed = await run(questionSet(), slow, candidateInput(), inProcess({ deadlineMs: 5 }));
  assert.equal(timed.record.outcome, 'TIMEOUT');
  assert.deepEqual([...timed.record.reasons], ['TIMED_OUT']);
  assert.equal(timed.record.answers.length, 0);
  assert.equal(timed.record.evidence.length, 0);
  assert.equal(timed.record.model.served, 'NONE', 'a late answer is never merged into the final record');
  assert.equal(timed.settlement.late, true, 'the late settlement is observable');
  assert.equal(Number.isInteger(timed.record.metadata.latencyMs), true);

  const preAborted = AbortSignal.abort();
  for (let attempt = 0; attempt < 4; attempt++) {
    const cancelled = await run(questionSet(), answeringJudge(), candidateInput(), inProcess({ signal: preAborted }));
    assert.equal(cancelled.record.outcome, 'CANCELLED', `attempt ${attempt}`);
    assert.deepEqual([...cancelled.record.reasons], ['CANCELLED']);
    assert.equal(cancelled.record.evidence.length, 0);
  }
  for (let attempt = 0; attempt < 4; attempt++) {
    const controller = new AbortController();
    const pending = runShadowJudgment(questionSet(), answeringJudge({ latencyMs: 200 }), INTERACTION, TENANT,
      candidateInput(), inProcess({ signal: controller.signal }));
    controller.abort();
    const record = await pending.record;
    assert.equal(record.outcome, 'CANCELLED', `mid-flight attempt ${attempt}`);
    assert.deepEqual([...record.reasons], ['CANCELLED']);
    assert.equal(record.answers.length, 0);
    assert.equal((await pending.settlement).late, false, 'cancelled work is stopped, not late');
  }
  const badSignal = await run(questionSet(), answeringJudge(), candidateInput(), inProcess({ signal: { aborted: 'no' } }));
  assert.equal(badSignal.record.outcome, 'REFUSED');
  assert.equal(reasonSet(badSignal.record).has('INVALID_REQUEST'), true);
});

test('an oversized, malformed or non-local response is refused without partial trust', async () => {
  const oversized = answeringJudge({ responsePadBytes: 40_000 });
  const big = await run(questionSet(), oversized, candidateInput(), inProcess());
  assert.equal(big.record.outcome, 'REFUSED');
  assert.equal(reasonSet(big.record).has('RESPONSE_TOO_LARGE'), true);
  assert.equal(big.record.answers.length, 0, 'an oversized response is not parsed into answers');
  assert.equal(big.record.evidence.length, 0);

  const noulAnswer = { kind: 'noul', noul: 0.5 };
  const choiceAnswer = (choice, probabilities, confidence) => ({ kind: 'choice', choice,
    probabilities, confidence });
  const cases = [
    { answers: { is_person: { kind: 'score', score: 1, probabilities: { '0': 1 }, confidence: 0.9 } },
      invalid: [['is_person', 'TYPE_MISMATCH']] },
    { answers: { is_person: noulAnswer, class: {} }, invalid: [['class', 'MALFORMED_RESPONSE']] },
    { answers: { is_person: { kind: 'noul' } }, invalid: [['is_person', 'MALFORMED_RESPONSE']] },
    { answers: { is_person: { kind: 'noul', noul: 1.4 } }, invalid: [['is_person', 'NOUL_OUT_OF_RANGE']] },
    { answers: { is_person: { ...noulAnswer, treatment: 'KEEP' } },
      invalid: [['is_person', 'UNEXPECTED_FIELD']] },
    { answers: { is_person: { ...noulAnswer, sensitivity: 'PUBLIC' } },
      invalid: [['is_person', 'UNEXPECTED_FIELD']] },
    { answers: { is_person: { ...noulAnswer, trust: 'CONTROL' } },
      invalid: [['is_person', 'UNEXPECTED_FIELD']] },
    { answers: { is_person: choiceAnswer('person', { person: 0.2, host: 0.8 }, 0.5) },
      invalid: [['is_person', 'TYPE_MISMATCH']] },
    { answers: { is_person: noulAnswer,
      class: choiceAnswer('person', { person: 0.2, host: 0.2, [ADVERSARIAL_KEEP_LABEL]: 0.6 }, 0.2) },
      invalid: [['class', 'SELECTED_NOT_MOST_PROBABLE']] },
    { answers: { is_person: noulAnswer, class: choiceAnswer('person', { person: 0.5 }, 0.2) },
      invalid: [['class', 'PROBABILITIES_MISMATCH']] },
    { answers: { is_person: noulAnswer,
      class: choiceAnswer('person', { person: 0.2, host: 0.8, [ADVERSARIAL_KEEP_LABEL]: 1.4 }, 0.2) },
      invalid: [['class', 'PROBABILITY_OUT_OF_RANGE']] },
    { answers: { is_person: noulAnswer,
      class: choiceAnswer('not_an_option', { person: 0.2, host: 0.8, [ADVERSARIAL_KEEP_LABEL]: 0 }, 0.2) },
      invalid: [['class', 'UNKNOWN_CHOICE_LABEL']] },
    { answers: { is_person: noulAnswer,
      class: choiceAnswer('person', { person: 0.5, host: 0.5, [ADVERSARIAL_KEEP_LABEL]: 0 }, 1.4) },
      invalid: [['class', 'CONFIDENCE_OUT_OF_RANGE']] },
    { answers: { is_person: noulAnswer,
      utility: { kind: 'score', score: 0.5, probabilities: { '0': 0.5 }, confidence: 0.5 } },
      invalid: [['utility', 'PROBABILITIES_MISMATCH']] },
    { answers: { is_person: noulAnswer, utility: { kind: 'score', score: 0.5,
      probabilities: { '0': 0.5, '1': 0.5 }, confidence: 0.5, level: 1 } },
      invalid: [['utility', 'UNEXPECTED_FIELD']] },
  ];
  for (const { answers, invalid } of cases) {
    const { record } = await run(questionSet(), answeringJudge({ answers }), candidateInput(), inProcess());
    assert.equal(record.outcome, 'PARTIAL', JSON.stringify(answers));
    assert.equal(reasonSet(record).has('INCOMPLETE_ANSWERS'), true);
    for (const [questionId, code] of invalid) {
      const item = record.answers.find((answer) => answer.questionId === questionId);
      assert.equal(item.status, 'INVALID', `${questionId}: ${JSON.stringify(answers)}`);
      assert.equal(item.reason, code);
      assert.equal(item.proposal.semanticType, 'NONE', 'a rejected answer proposes nothing');
      assert.equal(reasonSet(record).has(code), true, code);
    }
    // Whatever the provider claimed, only a well-formed judgment may propose a class.
    for (const item of record.evidence) {
      assert.deepEqual(Object.keys(item.claim).sort(), ['confidence', 'semanticType']);
      assert.equal(item.claim.confidence >= 0 && item.claim.confidence <= 1, true);
    }
  }
  // An answer for a question that does not exist is an explicit reason, not a silently dropped value.
  const unknown = await run(questionSet(), answeringJudge({ answers: { is_person: noulAnswer,
    not_a_question: { kind: 'noul', noul: 0.99 } } }), candidateInput(), inProcess());
  assert.equal(reasonSet(unknown.record).has('UNKNOWN_ANSWER'), true);
  assert.equal(unknown.record.answers.some((item) => item.questionId === 'not_a_question'), false);

  // A value that is not JSON data never reaches a record at all: a local script is refused where the
  // data is, and the parser keeps the same closed reason for a body supplied by an adapter.
  assert.throws(() => answeringJudge({ answers: { utility: { kind: 'score', score: Number.NaN,
    probabilities: { '0': 0.5, '1': 0.5 }, confidence: 0.5 } } }),
  (error) => error.message === 'INVALID_REQUEST', 'a non-finite score is not script data');
  const nonFinite = parseShadowJudgePayload({ servedModel: 'local-synthetic/jev-sim',
    answers: { is_person: { kind: 'noul', noul: 0.5 }, utility: { kind: 'score', score: Number.NaN,
      probabilities: { '0': 0.5, '1': 0.5 }, confidence: 0.5 } } }, questionSet());
  assert.equal(nonFinite.invalid.utility, 'SCORE_NOT_FINITE');
  assert.equal(nonFinite.problems.includes('SCORE_NOT_FINITE'), true);

  // A missing answer is MISSING, and a hosted served-model label is refused as non-local.
  const partial = await run(questionSet(), answeringJudge({ answers: { is_person: { kind: 'noul', noul: 0.5 } } }),
    candidateInput(), inProcess());
  assert.equal(partial.record.answers[1].status, 'MISSING');
  assert.equal(partial.record.answers[1].reason, 'MISSING_ANSWER');
  assert.equal(partial.record.evidence.length, 1);
});

test('an abstaining judgment proposes nothing and is recorded as an abstention', async () => {
  const abstaining = answeringJudge({ answers: {
    is_person: { kind: 'noul', noul: 0.05 },
    class: { kind: 'choice', choice: 'host', probabilities: { person: 0.1, host: 0.9 }, confidence: 0.9 },
    utility: { kind: 'score', score: 0, probabilities: { '0': 1, '1': 0 }, confidence: 1 },
  } });
  const set = defineShadowQuestionSet({
    id: 'shadow.dev.v1', version: '1',
    questions: [{ id: 'class', kind: 'choice', purpose: 'CONTEXT_KIND', instructions: 'Which class?',
      criteria: { person: 'a natural person', host: 'a host or service' },
      propose: { byLabel: { person: 'PERSON', host: 'NONE' } } }],
  });
  const { record } = await run(set, abstaining, candidateInput(), inProcess());
  assert.equal(record.outcome, 'ABSTAINED');
  assert.equal(reasonSet(record).has('ABSTAINED'), true);
  assert.equal(record.answers[0].status, 'ABSTAINED');
  assert.equal(record.answers[0].proposal.semanticType, 'NONE');
  assert.equal(record.evidence.length, 0, 'an abstention proposes no semantic class');
});

/* ------------------------------------------- credential floor and adversarial KEEP behavior */

test('a shadow KEEP suggestion cannot resolve, downgrade or release a deterministic credential', async () => {
  const { record } = await run(questionSet(), answeringJudge(), candidateInput(),
    inProcess({ deterministicFloor: 'SECRET' }));
  assert.equal(record.deterministicFloor.sensitivity, 'SECRET', 'the echoed floor is recorded');
  assert.equal(record.deterministicFloor.source, 'INTEGRATION');
  assert.equal(record.advisory.suggestedTreatment, 'NONE');
  // Shadow evidence alone can never resolve a v1 classification: no detector evidence, no sensitivity.
  const shadowOnly = composeClassification({ semanticJudgments: record.evidence },
    { interactionRef: INTERACTION, sourceRef: REF, trust: 'TRUSTED' });
  assert.equal(shadowOnly.status, 'UNRESOLVED');
  assert.ok(shadowOnly.reasons.includes('MISSING_DETECTOR_EVIDENCE'));
  assert.ok(shadowOnly.reasons.includes('MISSING_SENSITIVITY'));
  assert.equal(shadowOnly.sensitivity, 'UNKNOWN');

  // With deterministic credential evidence present, the floor is SECRET and the shadow claim cannot
  // clear it: a conflicting semantic type stays UNRESOLVED and policy denies the external sink.
  const credential = { version: 1, id: 'detector-a.invalid', status: 'FOUND',
    provenance: { inputRef: REF, producerId: 'detector-a.invalid', producerVersion: 'pack-1' },
    claim: { semanticType: 'CREDENTIAL_OR_SECRET', sensitivity: 'SECRET' } };
  const composed = composeClassification({ detectorEvidence: [credential],
    semanticJudgments: record.evidence },
  { interactionRef: INTERACTION, sourceRef: REF, trust: 'TRUSTED' });
  assert.equal(composed.sensitivity, 'SECRET', 'the deterministic credential floor survives');
  assert.equal(composed.status, 'UNRESOLVED', 'a conflicting shadow claim never resolves the unit');
  assert.ok(composed.reasons.includes('CONFLICTING_SEMANTIC_TYPE'));

  const profile = { id: 'external.invalid', sink: { kind: 'model', ref: 'external.example.invalid',
    trustZone: 'EXTERNAL', profileId: 'external.invalid' }, exposure: 'EXTERNAL',
  permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'PUBLIC' };
  const policy = { ...KNOWN_POLICY_BUNDLE, profiles: [profile], rules: [
    { id: 'external-public.invalid', profileId: 'external.invalid', semanticType: 'CREDENTIAL_OR_SECRET',
      sensitivities: ['PUBLIC'], sourceTrust: ['CONTROL', 'TRUSTED'], operations: ['SEND'],
      decision: 'KEEP' },
  ] };
  const boundary = { interactionRef: INTERACTION, candidateRef: REF,
    classificationDigest: digestClassification(composed),
    authenticated: { subject: { principalId: 'principal-a.invalid', workloadId: 'workload-a.invalid' },
      context: { tenantId: TENANT, projectId: 'project-a.invalid', sessionId: 'session-a.invalid',
        purpose: 'diagnostic-a.invalid' } },
    observed: { source: { kind: 'user.message', ref: REF, trustZone: 'TRUSTED' },
      destination: profile.sink },
    policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(policy) } };
  const request = { version: 1, interactionRef: INTERACTION, candidateRef: REF,
    subject: structuredClone(boundary.authenticated.subject),
    context: structuredClone(boundary.authenticated.context),
    source: { kind: 'user.message', ref: REF, trustZone: 'TRUSTED' },
    destination: structuredClone(profile.sink), classification: composed, operation: 'SEND',
    policy: structuredClone(KNOWN_POLICY_BUNDLE), semanticRecommendation: 'KEEP' };
  const decision = decidePolicy(request, boundary, policy);
  assert.equal(decision.state, 'DENIED');
  assert.equal(decision.treatment, 'BLOCK');
  assert.equal(Object.hasOwn(decision, 'payload'), false);
});

test('sensitivity ordering keeps the deterministic floor above any semantic-only view', () => {
  assert.equal(shadowSensitivityRank('UNKNOWN'), -1);
  const ranks = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'SECRET'].map(shadowSensitivityRank);
  assert.deepEqual(ranks, [0, 1, 2, 3, 4]);
  assert.ok(shadowSensitivityRank('SECRET') > shadowSensitivityRank('UNKNOWN'));
});

/* ------------------------------------------------------------ tenant scoping and diagnostics */

test('records are tenant scoped for replay, refusals are closed codes and diagnostics echo nothing', async () => {
  const { record } = await run(questionSet(), answeringJudge(), candidateInput(), inProcess());
  assert.equal(belongsToShadowTenant(record, TENANT), true);
  assert.equal(belongsToShadowTenant(record, 'tenant-b.invalid'), false);
  assert.equal(belongsToShadowTenant(structuredClone({ ...record, tenantRef: TENANT }), 'tenant-b.invalid'), false);
  assert.equal(belongsToShadowTenant(null, TENANT), false);
  assert.deepEqual([...shadowReasonCodes(record)], []);
  assert.deepEqual([...shadowReasonCodes({ reasons: ['TIMED_OUT', 'TIMED_OUT', 'ABSTAINED'] })],
    ['ABSTAINED', 'TIMED_OUT']);
  assert.deepEqual([...shadowReasonCodes(null)], []);
  const refused = await run(questionSet(), answeringJudge(), candidateInput(), { execution: 'EXTERNAL' });
  for (const code of refused.record.reasons) assert.ok(SHADOW_REASON_CODES.includes(code), code);
  // Exported configuration functions throw closed codes, never data-bearing messages.
  for (const attempt of [
    () => defineShadowQuestionSet({ id: 'q.v1', version: '1', questions: 'nope' }),
    () => createLocalShadowJudge({ id: 'd', version: '1', servedModel: 'local-synthetic/x', latencyMs: 0,
      mode: 'ANSWER', issuedByCaller: true }),
    () => minimizeShadowRequest(INTERACTION, TENANT, questionSet(), answeringJudge(),
      { candidate: { ref: REF, kind: 'PERSON_REFERENCE', raw: PLANTED, extra: 'x' } }),
  ]) {
    assert.throws(attempt, (error) => SHADOW_REASON_CODES.includes(error.message) &&
      !error.message.includes(PLANTED) && !error.message.includes('@'));
  }
});

test('seeded tenant, ref and bounds variations all settle conservatively and stay tenant bound', async () => {
  const vectors = generateShadowVectors(20_260_101, 64);
  assert.equal(vectors.length, 64);
  const tenants = new Set();
  for (const vector of vectors) {
    assert.match(vector.tenantRef, /\.invalid$/u);
    assert.match(vector.candidateRef, /\.invalid$/u);
    tenants.add(vector.tenantRef);
    const input = { candidate: { ref: vector.candidateRef, kind: vector.candidateKind,
      raw: `synthetic-raw-${vector.id}` },
      neighbors: Array.from({ length: vector.neighborCount }, () => ({ kind: 'PERSON_REFERENCE',
        raw: 'synthetic-neighbour.invalid' })),
      context: vector.contextCount === 0 ? [] : [{ key: 'surface', code: 'unknown' }] };
    const { record, settlement } = await run(questionSet(), answeringJudge(), input,
      inProcess({ deadlineMs: vector.deadlineMs }), vector.tenantRef);
    assert.equal(record.tenantRef, vector.tenantRef, vector.id);
    assert.equal(belongsToShadowTenant(record, vector.tenantRef), true, vector.id);
    assert.equal(record.outcome === 'TIMEOUT' || record.outcome === 'ANSWERED', true, `${vector.id} ${record.outcome}`);
    assert.equal(record.authority, 'NONE');
    assert.equal(settlement.late, record.outcome === 'TIMEOUT');
  }
  assert.ok(tenants.size > 4, 'generated variation really varies tenants');
  const [first] = vectors;
  const { record } = await run(questionSet(), answeringJudge(), { candidate: { ref: first.candidateRef,
    kind: first.candidateKind, raw: 'synthetic-raw' } }, inProcess(), first.tenantRef);
  for (const other of vectors) if (other.tenantRef !== first.tenantRef) {
    assert.equal(belongsToShadowTenant(record, other.tenantRef), false, 'cross-tenant replay is refused');
  }
  assert.throws(() => generateShadowVectors(0, 1), TypeError);
  assert.throws(() => generateShadowVectors(1, 1_000), TypeError);
  // Deterministic: the same seed reproduces the same bounded variations.
  assert.deepEqual(generateShadowVectors(20_260_101, 8), generateShadowVectors(20_260_101, 8));
});

test('forged configuration and hostile diagnostics stay refusals, never exceptions', async () => {
  const set = questionSet();
  const judge = answeringJudge();
  // A look-alike question set or judge object never runs, and a request this seam will not build
  // (here: a credential kind) is an explicit refusal with its own closed reason.
  for (const forged of [{ set: { ...set }, judge }, { set, judge: { ...judge } }]) {
    const record = await runShadowJudgment(forged.set, forged.judge, INTERACTION, TENANT, candidateInput(),
      inProcess()).record;
    assert.equal(record.outcome, 'REFUSED');
    assert.deepEqual([...record.reasons], ['INVALID_REQUEST']);
    assert.equal(record.tenantRef, 'unbound', 'a refused run carries no interaction identity');
  }
  const unbuildable = await runShadowJudgment(set, judge, INTERACTION, TENANT,
    candidateInput({ candidate: { ref: REF, kind: 'CREDENTIAL_OR_SECRET', raw: PLANTED } }),
    inProcess()).record;
  assert.equal(unbuildable.outcome, 'REFUSED');
  assert.deepEqual([...unbuildable.reasons], ['INVALID_REQUEST']);
  assert.equal(unbuildable.request.bytes, 0);

  // Record inspection never throws, whatever it is handed, and never echoes what it read.
  const hostile = new Proxy(Object.freeze({ version: 1, tenantRef: TENANT }), {
    getOwnPropertyDescriptor() { throw new Error(`leak ${PLANTED}`); },
  });
  assert.equal(belongsToShadowTenant(hostile, TENANT), false);
  assert.equal(belongsToShadowTenant({ version: 1, tenantRef: TENANT }, 'tenant\u0000bad.invalid'), false);
  assert.deepEqual([...shadowReasonCodes(hostile)], []);
  assert.deepEqual([...shadowReasonCodes({ reasons: ['PLANTED', 'not-a-closed-code'] })], []);
  assert.deepEqual([...shadowReasonCodes({ reasons: Array.from({ length: 200 }, () => 'TIMED_OUT') })], []);
  assert.deepEqual([...shadowReasonCodes({ reasons: 'TIMED_OUT' })], []);
});

/* ------------------------------------------------- conservative records for hostile scripts */

const surplusAnswers = (total) => {
  const answers = { is_person: { kind: 'noul', noul: 0.5 } };
  for (let index = 1; index < total; index += 1) answers[`surplus_${index}`] = { kind: 'noul', noul: 0.5 };
  return answers;
};

test('the record promise always resolves, so awaiting settlement alone can never kill the process', async () => {
  // The script bound can no longer outrun the parser bound: a module-issued judge cannot produce a
  // payload the seam then refuses to interpret, so a surplus key is an explicit reason, not a
  // rejection. This is the shape that used to reject with MALFORMED_RESPONSE.
  const within = await run(questionSet(), answeringJudge({
    answers: surplusAnswers(SHADOW_MAX_SCRIPT_ANSWER_KEYS) }), candidateInput(), inProcess());
  assert.equal(within.record.outcome, 'PARTIAL');
  assert.equal(reasonSet(within.record).has('UNKNOWN_ANSWER'), true, 'a surplus answer is a closed reason');
  assert.equal(reasonSet(within.record).has('INCOMPLETE_ANSWERS'), true);
  assert.equal(within.record.answers.length, 3, 'every question of the set still gets an answer record');
  assert.equal(within.record.evidence.length, 1, 'the answered question still proposes its class');
  assert.equal(within.settlement.late, false);
  // A script wider than the documented answer bound is refused at creation, where it is data.
  for (const total of [SHADOW_MAX_SCRIPT_ANSWER_KEYS + 1, 41, 64]) {
    assert.throws(() => answeringJudge({ answers: surplusAnswers(total) }),
      (error) => error.message === 'INVALID_REQUEST', String(total));
  }
  // Excess keys plus the documented padding key used to be the exact rejecting shape.
  const padded = await run(questionSet(), answeringJudge({
    answers: surplusAnswers(SHADOW_MAX_SCRIPT_ANSWER_KEYS), responsePadBytes: 1 }),
  candidateInput(), inProcess());
  assert.equal(padded.record.outcome, 'PARTIAL');
  assert.equal(reasonSet(padded.record).has('UNKNOWN_ANSWER'), true);

  // The documented way to observe late work is `await run.settlement`. If `record` could reject,
  // nothing would attach a handler and Node's default `--unhandled-rejections=throw` exits the
  // process. A child process is the only honest way to observe that default, so every script shape
  // the seam accepts -- and the shapes it must refuse -- is run there with settlement-only usage.
  const seam = new URL('../dist/semantic-judge-shadow.js', import.meta.url).href;
  const script = `
    import { createLocalShadowJudge, defineShadowQuestionSet, runShadowJudgment } from ${JSON.stringify(seam)};
    const set = defineShadowQuestionSet({ id: 'shadow.dev.v1', version: '1', questions: [
      { id: 'is_person', kind: 'noul', purpose: 'PERSON_IDENTITY', instructions: 'Is it a person?',
        propose: { semanticType: 'PERSON' } }]});
    const input = { candidate: { ref: 'candidate-a.invalid', kind: 'PERSON_REFERENCE',
      raw: 'synthetic.invalid' } };
    const base = { id: 'd', version: '1', servedModel: 'local-synthetic/x', latencyMs: 0 };
    const surplus = { is_person: { kind: 'noul', noul: 0.5 } };
    for (let index = 0; index < 40; index += 1) surplus['q_' + index] = { kind: 'noul', noul: 0.5 };
    const outcomes = [];
    for (const script of [
      { ...base, mode: 'ANSWER', answers: { is_person: { kind: 'noul', noul: 0.5 } } },
      { ...base, mode: 'ANSWER', answers: { is_person: { kind: 'noul', noul: 0.5 } },
        responsePadBytes: 40000 },
      { ...base, mode: 'REFUSE' },
      { ...base, mode: 'ANSWER', answers: surplus },
      { ...base, mode: 'ANSWER', answers: { is_person: { kind: 'noul', noul: 0.5 },
        hostile: { get boom() { throw new Error('caller code ran'); } } } },
    ]) {
      let judge = null;
      try { judge = createLocalShadowJudge(script); } catch (error) { outcomes.push('REFUSED:' + error.message); continue; }
      const run = runShadowJudgment(set, judge, 'interaction-a.invalid', 'tenant-a.invalid', input,
        { execution: 'IN_PROCESS', deadlineMs: 500 });
      const settlement = await run.settlement;
      await new Promise((resolve) => { setTimeout(resolve, 25); });
      outcomes.push(JSON.stringify(settlement) + '|' + (await run.record).outcome);
    }
    process.stdout.write(outcomes.join(';'));
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(child.status, 0, `settlement-only usage must exit cleanly: ${child.stderr}`);
  const outcomes = child.stdout.split(';');
  assert.equal(outcomes.length, 5, child.stdout);
  assert.deepEqual(outcomes, [
    '{"late":false}|ANSWERED',
    '{"late":false}|REFUSED',
    '{"late":false}|REFUSED',
    'REFUSED:INVALID_REQUEST',
    'REFUSED:INVALID_REQUEST',
  ]);
});

test('a local script is copied bounded JSON data, never executed caller behavior', async () => {
  let invocations = 0;
  const executed = () => { invocations += 1; throw new Error(`caller code ran ${PLANTED}`); };
  const cycle = { kind: 'noul', noul: 0.5 };
  cycle.self = cycle;
  const deep = { kind: 'noul', noul: 0.5, nested: 0 };
  let cursor = deep;
  for (let index = 0; index < SHADOW_MAX_JSON_DEPTH + 2; index += 1) { cursor.nested = {}; cursor = cursor.nested; }
  const sparse = ['present', , 'also-present'];
  const inherited = Object.assign(Object.create({ inheritedGetter: executed }), { kind: 'noul', noul: 0.5 });
  const hostile = {
    accessor: { kind: 'noul', get noul() { return executed(); } },
    toJSON: { kind: 'noul', noul: 0.5, toJSON() { return executed(); } },
    functionValue: { kind: 'noul', noul: () => executed() },
    symbolValue: { kind: 'noul', noul: 0.5, extra: Symbol('synthetic') },
    bigint: { kind: 'noul', noul: 1n },
    nonFinite: { kind: 'noul', noul: Number.NaN },
    infinite: { kind: 'noul', noul: Number.POSITIVE_INFINITY },
    undefinedValue: { kind: 'noul', noul: 0.5, extra: undefined },
    cycle: { is_person: cycle },
    sparse: { is_person: sparse },
    inherited,
    tooDeep: { is_person: deep },
    tooManyKeys: { is_person: Object.fromEntries(Array.from({ length: SHADOW_MAX_JSON_KEYS + 1 },
      (_value, index) => [`k${index}`, index])) },
    tooLong: { is_person: { kind: 'noul', noul: 0.5, note: 'x'.repeat(SHADOW_MAX_JSON_STRING + 1) } },
    bytes: { is_person: { kind: 'noul', noul: 0.5, note: 'y'.repeat(SHADOW_MAX_RESPONSE_COPY_BYTES) } },
  };
  for (const [name, answers] of Object.entries(hostile)) {
    invocations = 0;
    assert.throws(() => answeringJudge({ answers }),
      (error) => error.message === 'INVALID_REQUEST', name);
    assert.equal(invocations, 0, `${name}: a refused value must not execute caller code`);
  }
  // A throwing Proxy is contained as a closed code; no caller message reaches the caller.
  const trap = new Proxy({ kind: 'noul', noul: 0.5 }, { ownKeys() { throw new Error(`x ${PLANTED}`); } });
  assert.throws(() => answeringJudge({ answers: { is_person: trap } }),
    (error) => error.message === 'INVALID_REQUEST' && !error.message.includes(PLANTED));
  // What is issued is inert data: a deep copy, so later caller mutation cannot reach a judgment.
  const answers = { is_person: { kind: 'noul', noul: 0.91 } };
  const judge = answeringJudge({ answers });
  answers.is_person.noul = 0.01;
  answers.is_person.extra = PLANTED;
  const { record } = await run(questionSet(), judge, candidateInput(), inProcess());
  assert.equal(record.answers[0].measure.noul, 0.91, 'the judge holds a snapshot copy, not the caller object');
  assert.equal(JSON.stringify(record).includes(PLANTED), false);
  assert.equal(Object.isFrozen(judge.answers.is_person), true, 'copied script data is frozen');
  // Bounds stay closed and ordered, so no cap can silently outgrow another.
  assert.ok(SHADOW_MAX_SCRIPT_ANSWER_KEYS <= SHADOW_MAX_QUESTIONS, 'a script cannot answer more than the parser bound');
  assert.ok(SHADOW_MAX_RESPONSE_COPY_BYTES > 32 * 1024, 'copy ceiling stays above the response refusal limit');
  assert.ok(SHADOW_MAX_JSON_DEPTH >= 2 && SHADOW_MAX_JSON_KEYS >= 8 && SHADOW_MAX_JSON_STRING >= 1024);
});

test('a time-varying or hostile caller object is read once and never throws out of the run', async () => {
  // The candidate answers differently on each read. The seam must use the single validated
  // snapshot, not a second independent read of a value that can change underneath it.
  let reads = 0;
  const varying = new Proxy({ ref: REF, kind: 'PERSON_REFERENCE', raw: PLANTED }, {
    getOwnPropertyDescriptor(target, property) {
      if (property === 'ref') {
        reads += 1;
        return { value: reads === 1 ? REF : `changed-${reads} ref`, enumerable: true,
          configurable: true, writable: true };
      }
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
  const { record: single } = await run(questionSet(), answeringJudge(), { candidate: varying }, inProcess());
  assert.equal(reads, 1, 'the candidate ref is read exactly once, through the validated snapshot');
  assert.equal(single.outcome, 'ANSWERED');
  assert.equal(single.candidateRef, REF, 'attribution uses the validated snapshot value');
  // Neighbours and context come from the same validated snapshot, never from a later read of the
  // caller object: a `get` trap must never be able to swap them for a different, unvalidated view.
  let inputReads = 0;
  const snapshotInput = new Proxy({
    candidate: { ref: REF, kind: 'PERSON_REFERENCE', raw: PLANTED },
    neighbors: [{ kind: 'CONTACT_REFERENCE', raw: 'first synthetic neighbour' }],
    context: [{ key: 'surface', code: 'log-line' }],
  }, {
    get(target, property, receiver) {
      if (property === 'neighbors' || property === 'context') {
        inputReads += 1;
        return property === 'neighbors' ? [{ kind: 'CONTACT_REFERENCE', raw: 'second synthetic neighbour' }]
          : [{ key: 'surface', code: 'config-file' }];
      }
      return Reflect.get(target, property, receiver);
    },
  });
  const snapshot = await run(questionSet(), answeringJudge(), snapshotInput, inProcess());
  assert.equal(snapshot.record.outcome, 'ANSWERED');
  assert.equal(inputReads, 0, 'neighbours and context are read only through the validated snapshot');
  assert.equal(snapshot.record.request.digest, (await run(questionSet(), answeringJudge(),
    candidateInput({ neighbors: [{ kind: 'CONTACT_REFERENCE', raw: 'first synthetic neighbour' }],
      context: [{ key: 'surface', code: 'log-line' }] }), inProcess())).record.request.digest,
  'the request is built from the snapshot values, not from a later read');
  assert.notEqual(snapshot.record.request.digest, (await run(questionSet(), answeringJudge(),
    candidateInput({ neighbors: [{ kind: 'CONTACT_REFERENCE', raw: 'second synthetic neighbour' }],
      context: [{ key: 'surface', code: 'config-file' }] }), inProcess())).record.request.digest);
  let neighborReads = 0;
  const neighbors = [new Proxy({ kind: 'PERSON_REFERENCE', raw: PLANTED }, {
    getOwnPropertyDescriptor(target, property) {
      if (property === 'raw') {
        neighborReads += 1;
        return { value: neighborReads === 1 ? PLANTED : 'other synthetic neighbour', enumerable: true,
          configurable: true, writable: true };
      }
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  })];
  const withNeighbors = await run(questionSet(), answeringJudge(), candidateInput({ neighbors }),
    inProcess());
  assert.equal(withNeighbors.record.outcome, 'ANSWERED');
  assert.equal(neighborReads, 1, 'a neighbouring raw value is read once and dropped');
  assert.equal(JSON.stringify(withNeighbors.record).includes(PLANTED), false);

  // A hostile object at any input position resolves a conservative record with a fixed unbound
  // placeholder identity, never a synchronous throw and never the caller's own message.
  const hostileAt = (trap) => new Proxy({ ref: REF, kind: 'PERSON_REFERENCE', raw: PLANTED },
    { [trap]() { throw new Error(`planted ${PLANTED}`); } });
  for (const trap of ['ownKeys', 'getOwnPropertyDescriptor', 'getPrototypeOf']) {
    const { record } = await run(questionSet(), answeringJudge(), { candidate: hostileAt(trap) },
      inProcess());
    assert.equal(record.outcome, 'REFUSED', trap);
    assert.deepEqual([...record.reasons], ['INVALID_REQUEST'], trap);
    assert.equal(record.candidateRef, 'unbound');
    assert.equal(record.interactionRef, 'unbound');
    assert.equal(JSON.stringify(record).includes(PLANTED), false, trap);
  }
  // A throwing `get` trap proves the opposite point: no caller object is read through [[Get]] at
  // all, so an accessor-shaped property can never run code even when it is enumerable data.
  const viaGet = await run(questionSet(), answeringJudge(), { candidate: hostileAt('get') }, inProcess());
  assert.equal(viaGet.record.outcome, 'ANSWERED', 'no [[Get]] read reaches a caller object');
  assert.equal(viaGet.record.candidateRef, REF);
  const hostileInput = { candidate: { ref: REF, kind: 'PERSON_REFERENCE', raw: PLANTED } };
  for (const [key, value] of [['neighbors', hostileAt('ownKeys')], ['context', hostileAt('ownKeys')]]) {
    const { record } = await run(questionSet(), answeringJudge(),
      { ...hostileInput, [key]: [value] }, inProcess());
    assert.equal(record.outcome, 'REFUSED', key);
    assert.deepEqual([...record.reasons], ['INVALID_REQUEST'], key);
  }
  const hostileOptions = new Proxy({ execution: 'IN_PROCESS', deadlineMs: 1000 },
    { ownKeys() { throw new Error(`planted ${PLANTED}`); } });
  const refusedOptions = await run(questionSet(), answeringJudge(), candidateInput(), hostileOptions);
  assert.equal(refusedOptions.record.outcome, 'REFUSED');
  assert.deepEqual([...refusedOptions.record.reasons], ['INVALID_REQUEST']);
  // A signal-shaped object with no abort API is refused explicitly, not by a thrown TypeError.
  const fakeSignal = await run(questionSet(), answeringJudge(), candidateInput(),
    inProcess({ signal: { aborted: false } }));
  assert.equal(fakeSignal.record.outcome, 'REFUSED');
  assert.deepEqual([...fakeSignal.record.reasons], ['INVALID_REQUEST']);
  const throwingSignal = await run(questionSet(), answeringJudge(), candidateInput(),
    inProcess({ signal: { aborted: false, addEventListener() { throw new Error(PLANTED); } } }));
  assert.equal(throwingSignal.record.outcome, 'REFUSED');
  assert.deepEqual([...throwingSignal.record.reasons], ['INVALID_REQUEST']);
});

test('a provider payload is judged as a response, and a labelled question cannot carry a bare claim', () => {
  const set = questionSet();
  // A malformed served model is a response defect, not a caller-request defect.
  assert.throws(() => parseShadowJudgePayload({ servedModel: 42, answers: {} }, set),
    (error) => error.message === 'MALFORMED_RESPONSE');
  assert.throws(() => parseShadowJudgePayload({ servedModel: 'local\nsynthetic', answers: {} }, set),
    (error) => error.message === 'MALFORMED_RESPONSE');
  assert.throws(() => parseShadowJudgePayload({ servedModel: 'local-synthetic/x', answers: {} },
    { ...set }), (error) => error.message === 'INVALID_REQUEST', 'a forged set is still a request defect');
  // `semanticType` alone would be silently ignored on a labelled question, which abstains forever;
  // a proposal is therefore either a single class (noul) or a complete label mapping.
  for (const kind of ['choice', 'score']) {
    const spec = kind === 'choice'
      ? { criteria: { person: 'a natural person', host: 'a host or service' } }
      : { criteria: ['not needed', 'needed'] };
    assert.throws(() => defineShadowQuestionSet({ id: 'shadow.dev.v1', version: '1',
      questions: [{ id: 'q_one', kind, purpose: 'CONTEXT_KIND', instructions: 'Which class?',
        ...spec, propose: { semanticType: 'PERSON' } }] }),
    (error) => error.message === 'INVALID_REQUEST', kind);
    assert.throws(() => defineShadowQuestionSet({ id: 'shadow.dev.v1', version: '1',
      questions: [{ id: 'q_one', kind, purpose: 'CONTEXT_KIND', instructions: 'Which class?',
        ...spec, propose: { semanticType: 'PERSON', byLabel: spec.criteria instanceof Array
          ? { '0': 'PERSON', '1': 'PERSON' } : { person: 'PERSON', host: 'HOST_OR_SERVICE' } } }] }),
    (error) => error.message === 'INVALID_REQUEST', kind);
  }
  // A Noul keeps its single-class proposal.
  assert.equal(defineShadowQuestionSet({ id: 'shadow.dev.v1', version: '1',
    questions: [{ id: 'is_person', kind: 'noul', purpose: 'PERSON_IDENTITY', instructions: 'x?',
      propose: { semanticType: 'PERSON' } }] }).questions[0].propose.semanticType, 'PERSON');
  // Trusted configuration is still read as data: a getter-backed label mapping is refused without
  // invoking it, and an unmapped label never silently becomes a class.
  let invoked = 0;
  assert.throws(() => defineShadowQuestionSet({ id: 'shadow.dev.v1', version: '1', questions: [
    { id: 'class', kind: 'choice', purpose: 'CONTEXT_KIND', instructions: 'Which class?',
      criteria: { person: 'a natural person', host: 'a host or service' },
      propose: { byLabel: { get person() { invoked += 1; return 'PERSON'; } } } }] }),
  (error) => error.message === 'INVALID_REQUEST');
  assert.equal(invoked, 0);
  assert.throws(() => defineShadowQuestionSet({ id: 'shadow.dev.v1', version: '1', questions: [
    { id: 'class', kind: 'choice', purpose: 'CONTEXT_KIND', instructions: 'Which class?',
      criteria: { person: 'a natural person', host: 'a host or service' },
      propose: { byLabel: { person: 'PERSON', other: 'PERSON' } } }] }),
  (error) => error.message === 'UNKNOWN_CHOICE_LABEL');
});

test('byte counting is exact UTF-8 JSON, and non-JSON answer values stay closed codes', async () => {
  // Multi-byte text, an astral character and a lone surrogate: the size check must measure the real
  // serialized length, and nothing may crash or silently drop a character on the way.
  const astral = 'a\u{1d4b0}b';
  const lone = 'c\ud800d';
  const answers = {
    is_person: { kind: 'noul', noul: 0.91, note: `${astral}${lone}\u00e9\u4e2d\u0001\u000a` },
    class: { kind: 'choice', choice: 'person', probabilities: { person: 1 }, confidence: 0.5 },
    utility: { kind: 'score', score: 0.5, probabilities: { '0': 1 }, confidence: 0.5 },
  };
  const judge = answeringJudge({ answers });
  const request = minimizeShadowRequest(INTERACTION, TENANT, questionSet(), judge,
    candidateInput({ candidate: { ref: `${REF}${lone}`, kind: 'PERSON_REFERENCE', raw: PLANTED } }));
  const { record } = await run(questionSet(), judge, candidateInput({
    candidate: { ref: `${REF}${lone}`, kind: 'PERSON_REFERENCE', raw: PLANTED } }), inProcess());
  assert.equal(record.request.bytes, Buffer.byteLength(JSON.stringify(request), 'utf8'),
    'the recorded request size is the exact UTF-8 JSON length of the request that was built');
  assert.equal(record.metadata.responseBytes, Buffer.byteLength(JSON.stringify(
    { servedModel: 'local-synthetic/jev-sim', answers }), 'utf8'),
  'the measured response size is the exact UTF-8 JSON length of the payload that was refused');
  assert.equal(reasonSet(record).has('UNEXPECTED_FIELD'), true, 'an unknown answer field is still refused');
  assert.equal(JSON.stringify(record).includes(PLANTED), false);

  // `null` and booleans are JSON data, so they are measured and then rejected as an answer value,
  // rather than refused as script configuration.
  for (const [value, code] of [[null, 'NOUL_OUT_OF_RANGE'], [true, 'NOUL_OUT_OF_RANGE'],
    ['0.5', 'NOUL_OUT_OF_RANGE']]) {
    const item = (await run(questionSet(), answeringJudge({ answers: { is_person: { kind: 'noul', noul: value } } }),
      candidateInput(), inProcess())).record.answers[0];
    assert.equal(item.status, 'INVALID', String(value));
    assert.equal(item.reason, code, String(value));
  }
  // A deep-but-bounded structure is still measured and refused per answer, not truncated.
  const nested = { kind: 'score', score: 0.5, confidence: 0.5, probabilities: { '0': 0.5, '1': 0.5 } };
  nested.extra = { list: [1, 2, 3], flag: false };
  const bounded = (await run(questionSet(), answeringJudge({ answers: { utility: nested } }),
    candidateInput(), inProcess())).record;
  assert.equal(bounded.answers[2].status, 'INVALID');
  assert.equal(bounded.answers[2].reason, 'UNEXPECTED_FIELD');
  assert.ok(bounded.metadata.responseBytes > 0);
});

test('the shipped modules cannot reach a network, a credential or an arbitrary evaluator', () => {
  for (const file of ['semantic-judge-shadow.js', 'typesafe-system-one-adapter.js']) {
    const source = readFileSync(new URL(`../dist/${file}`, import.meta.url), 'utf8');
    const forbidden = [/node:(?:http|https|net|tls|dgram|dns|cluster|child_process|worker_threads)\b/u,
      /\bfetch\s*\(/u, /XMLHttpRequest/u, /WebSocket/u, /navigator\./u, /process\.env/u, /\beval\s*\(/u,
      /new Function/u, /\brequire\s*\(/u, /\bimport\s*\(/u, /Buffer\./u];
    for (const pattern of forbidden) assert.doesNotMatch(source, pattern, `${file}: ${pattern}`);
    const imports = [...source.matchAll(/from ['"]([^'"]+)['"]/gu)].map((match) => match[1]);
    for (const specifier of imports) {
      assert.match(specifier, /^(?:\.\/[a-z-]+\.js|node:crypto)$/u, `${file}: ${specifier}`);
    }
  }
});