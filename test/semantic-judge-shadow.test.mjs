import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { composeClassification } from '../dist/classification.js';
import { decidePolicy, digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE } from '../dist/policy.js';
import {
  ADVERSARIAL_KEEP_LABEL, SHADOW_CANDIDATE_KINDS, SHADOW_CONTEXT_CODES, SHADOW_CONTEXT_KEYS,
  SHADOW_JUDGMENT_PURPOSES, SHADOW_JUDGE_VERSION, SHADOW_MAX_CHOICE_OPTIONS, SHADOW_MAX_CONTEXT_ENTRIES,
  SHADOW_MAX_NEIGHBORS, SHADOW_MAX_QUESTIONS, SHADOW_MAX_SCORE_LEVELS, SHADOW_MIN_SCORE_LEVELS,
  SHADOW_QUESTION_KINDS, SHADOW_REASON_CODES, SHADOW_TREATMENTS, belongsToShadowTenant,
  createLocalShadowJudge, defineShadowQuestionSet, generateShadowVectors, minimizeShadowRequest,
  runShadowJudgment, shadowReasonCodes, shadowSensitivityRank,
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
    { answers: { is_person: noulAnswer, utility: { kind: 'score', score: Number.NaN,
      probabilities: { '0': 0.5, '1': 0.5 }, confidence: 0.5 } },
      invalid: [['utility', 'SCORE_NOT_FINITE']] },
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