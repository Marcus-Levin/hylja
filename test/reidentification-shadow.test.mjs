import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  REIDENTIFICATION_SHADOW_VERSION, REID_ADVISORY_MIN_CELL_SITES, REID_MAX_ADVISORY_RECOMMENDATIONS,
  REID_MAX_EVALUATED_CASES, REID_MAX_GENERATED_VECTORS, REID_MAX_QUASI_IDENTIFIERS, REID_MAX_RECORDS,
  REID_CORPUS_ID, REID_CORPUS_VERSION, REID_COMBINED_BASES, REID_DERIVED_FACT_KINDS, REID_DIMENSIONS,
  REID_DIMENSION_NEIGHBOR_KINDS, REID_FAMILY_IDS, REID_GENERALIZATION_ACTIONS, REID_JUDGE_FLAGS,
  REID_LABELS, REID_LOCAL_FLAGS, REID_QUESTION_SET_ID, REID_QUESTION_SET_VERSION,
  REID_RECOMMENDATION_RATIONALES, REID_RISK_LABEL, REID_RISK_QUESTION_ID, REID_ROLES, REID_SAFE_LABEL,
  REID_UTILITY_QUESTION_ID, createReidentificationCorpus, defineReidentificationQuestionSet,
  generateReidentificationVectors, isIssuedReidentificationQuestionSet, isReidentificationCorpus,
  reidentificationCells, runReidentificationShadow,
} from '../dist/reidentification-shadow.js';
import {
  SHADOW_JUDGMENT_PURPOSES, SHADOW_OUTCOMES, SHADOW_QUESTION_KINDS, createLocalShadowJudge,
  defineShadowQuestionSet, isIssuedShadowQuestionSet,
} from '../dist/semantic-judge-shadow.js';

// Every value below is synthetic. The corpus holds no site, geography, date, process or project
// name at all -- only abstract opaque handles -- so there is nothing realistic to copy and nothing
// routable. A test may not make a fixture more realistic than this.
const TENANT = 'tenant-reid-a.invalid';
const OPTIONS = { execution: 'IN_PROCESS', deadlineMs: 2000, tenantRef: TENANT };
const corpus = () => createReidentificationCorpus();
const questionSet = () => defineReidentificationQuestionSet();
const BASE_SCRIPT = { id: 'local-double', version: '1', servedModel: 'local-synthetic/jev-sim',
  latencyMs: 0, mode: 'ANSWER' };
const RISK_ANSWER = { kind: 'choice', choice: 'reidentifiable',
  probabilities: { reidentifiable: 0.72, not_reidentifiable: 0.28 }, confidence: 0.72 };
const SAFE_ANSWER = { kind: 'choice', choice: 'not_reidentifiable',
  probabilities: { reidentifiable: 0.28, not_reidentifiable: 0.72 }, confidence: 0.72 };
const UTILITY_ANSWER = { kind: 'score', score: 0.5, probabilities: { '0': 0.5, '1': 0.5 },
  confidence: 0.5 };
const answers = (risk) => ({ ri_risk: risk ? RISK_ANSWER : SAFE_ANSWER, ri_utility: UTILITY_ANSWER });
const localJudge = (over = {}) => createLocalShadowJudge({ ...BASE_SCRIPT, answers: answers(true),
  ...over });
const run = (judge, over = {}) => runReidentificationShadow(corpus(), questionSet(), judge,
  { ...OPTIONS, ...over });
const row = (report, caseId) => report.rows.find((item) => item.caseId === caseId);
const sum = (counts) => counts.trueFlag + counts.falseFlag + counts.miss + counts.correctSafe +
  counts.abstained;
const handlesOf = (value, recordId) => value.records.find((item) => item.id === recordId)
  .quasiIdentifiers.map((item) => item.handle);
const shippedRowIds = ['reid-case-01', 'reid-case-13', 'reid-case-17', 'reid-case-31'];
const specRecord = (over = {}) => ({ id: 'reid-spec-a', role: 'EVALUATED_CASE',
  familyId: 'REIDENTIFIABLE_RARE_COMBINATION', siteRef: 'site-00000000ffff.invalid',
  directNameReplaced: true, label: 'REIDENTIFIABLE',
  quasiIdentifiers: [{ ref: 'qi-00000000ffff.invalid', dimension: 'GEOGRAPHY',
    handle: 'qh-000000000000ffff.invalid' }], ...over });
const spec = (records, over = {}) => ({ version: 1, id: 'spec-development', corpusVersion: '1',
  records, ...over });
/** Every JSON string a corpus may contain, as a closed allowlist. */
const CORPUS_STRING = [/^reid-[a-z0-9-]{1,64}$/u, /^qh-[0-9a-f]{16}\.invalid$/u,
  /^qi-[0-9a-f]{12}\.invalid$/u, /^site-[0-9a-f]{12}\.invalid$/u, /^[A-Z][A-Z_]{1,63}$/u,
  /^synthetic-reidentification-development$/u, /^spec-development$/u, /^generated-[0-9]+-development$/u,
  /^inverted-labels-development$/u, /^cap-development$/u, /^[0-9]+$/u];
function corpusStrings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((item) => corpusStrings(item, out));
  else if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value)) corpusStrings(item, out);
  }
  return out;
}
const allKeys = (value, out = []) => {
  if (Array.isArray(value)) value.forEach((item) => allKeys(item, out));
  else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) { out.push(key); allKeys(item, out); }
  }
  return out;
};

/* ------------------------------------------------------------------ versioned, bounded surface */

test('the shipped seam is versioned and every vocabulary it exposes is closed', () => {
  assert.equal(REIDENTIFICATION_SHADOW_VERSION, 'hylja.reidentification-shadow.v1');
  assert.deepEqual([...REID_DIMENSIONS], ['GEOGRAPHY', 'DATE', 'PROCESS', 'PROJECT', 'ORG_UNIT',
    'ROLE', 'DEVICE_CLASS', 'CUSTOMER_TYPE']);
  assert.deepEqual([...REID_LABELS], ['REIDENTIFIABLE', 'NOT_REIDENTIFIABLE']);
  assert.deepEqual([...REID_ROLES], ['EVALUATED_CASE', 'POPULATION_BACKGROUND']);
  assert.deepEqual([...REID_LOCAL_FLAGS], ['RISK', 'COMMON']);
  assert.deepEqual([...REID_JUDGE_FLAGS], ['RISK', 'SAFE', 'ABSTAIN']);
  assert.equal(new Set(REID_FAMILY_IDS).size, REID_FAMILY_IDS.length);
  assert.equal(new Set(REID_GENERALIZATION_ACTIONS).size, REID_GENERALIZATION_ACTIONS.length);
  assert.equal(new Set(REID_RECOMMENDATION_RATIONALES).size, REID_RECOMMENDATION_RATIONALES.length);
  assert.equal(new Set(REID_DERIVED_FACT_KINDS).size, REID_DERIVED_FACT_KINDS.length);
  assert.deepEqual([...REID_COMBINED_BASES], ['LOCAL_UNIQUE_COMBINATION', 'JUDGE_RISK',
    'JUDGE_ABSTENTION_ESCALATION', 'NO_FLAG']);
  for (const name of [...REID_DIMENSIONS, ...REID_LABELS, ...REID_ROLES, ...REID_LOCAL_FLAGS,
    ...REID_JUDGE_FLAGS, ...REID_COMBINED_BASES, ...REID_GENERALIZATION_ACTIONS]) {
    assert.match(name, /^[A-Z_]+$/u, name);
  }
  // Every dimension has one judge presentation, and no presentation is a credential or secret kind.
  assert.deepEqual(Object.keys(REID_DIMENSION_NEIGHBOR_KINDS).sort(), [...REID_DIMENSIONS].sort());
  for (const kind of Object.values(REID_DIMENSION_NEIGHBOR_KINDS)) {
    assert.match(kind, /^[A-Z_]+$/u);
    assert.equal(/CREDENTIAL|SECRET|PASSWORD/u.test(kind), false, kind);
  }
});

test('bounds stay ordered, so no cap can silently outgrow the seam it feeds', () => {
  // A record's quasi-identifiers must fit the reviewed #11 neighbour ceiling.
  assert.equal(REID_MAX_QUASI_IDENTIFIERS, 8);
  assert.ok(REID_MAX_RECORDS >= REID_MAX_EVALUATED_CASES, 'evaluated cases are a subset of records');
  assert.ok(REID_MAX_ADVISORY_RECOMMENDATIONS <= REID_MAX_QUASI_IDENTIFIERS,
    'a case cannot recommend more dimensions than it has');
  assert.ok(REID_ADVISORY_MIN_CELL_SITES >= 2,
    'an advisory target below two sites is not a re-identification claim');
  assert.ok(REID_MAX_GENERATED_VECTORS >= 16);
  assert.ok(REID_MAX_RECORDS <= 128 && REID_MAX_EVALUATED_CASES <= 64);
});

test('the re-identification question set is bounded, versioned and issued by the #11 seam', () => {
  const set = questionSet();
  assert.equal(isIssuedShadowQuestionSet(set), true);
  assert.equal(set.id, REID_QUESTION_SET_ID);
  assert.equal(set.version, REID_QUESTION_SET_VERSION);
  assert.equal(set.questions.length, 2);
  for (const question of set.questions) {
    assert.match(question.id, /^[a-z][a-z0-9_]*$/u);
    assert.ok(SHADOW_QUESTION_KINDS.includes(question.kind));
    assert.ok(SHADOW_JUDGMENT_PURPOSES.includes(question.purpose));
    // Question text is bounded configuration and never carries a treatment or an authority claim.
    assert.equal(/treatment|sensitivity|authorization|release/iu.test(question.instructions), false);
  }
  const risk = set.questions.find((question) => question.id === REID_RISK_QUESTION_ID);
  assert.equal(risk.kind, 'choice');
  assert.equal(risk.purpose, 'REIDENTIFICATION_RISK');
  assert.deepEqual(Object.keys(risk.criteria).sort(), [REID_RISK_LABEL, REID_SAFE_LABEL].sort());
  // Every option maps to a class: an unmapped label would abstain forever.
  assert.deepEqual(Object.keys(risk.propose.byLabel).sort(),
    [REID_RISK_LABEL, REID_SAFE_LABEL].sort());
  assert.equal(set.questions.find((question) => question.id === REID_UTILITY_QUESTION_ID).purpose,
    'UTILITY_NECESSITY');
  // The text describes placeholders, because placeholders are all the judge can ever see.
  assert.match(risk.instructions, /cand-01/u);
  assert.deepEqual(questionSet(), set, 'the set is stable and reproducible');
});

/* ------------------------------------------- the issue's negative case: unique rare combination */

test('a rare geography/date/process/project combination that uniquely identifies a fictional site ' +
  'after its direct name is replaced is flagged as re-identification risk', async () => {
  const value = corpus();
  const report = await run(localJudge());
  const acceptance = row(report, 'reid-case-01');
  assert.ok(acceptance, 'the acceptance case is present in the development corpus');
  // The site's direct name is not in the corpus at all: every record states the precondition.
  assert.equal(value.records.every((entry) => entry.directNameReplaced === true), true);
  for (const dimension of ['GEOGRAPHY', 'DATE', 'PROCESS', 'PROJECT']) {
    assert.ok(acceptance.dimensions.includes(dimension), dimension);
    // Rarity is a property of the COMBINATION: each of its handles occurs in other records too.
    const handle = handlesOf(value, 'reid-case-01')[acceptance.dimensions.indexOf(dimension)];
    const sharers = value.records.filter((entry) => entry.quasiIdentifiers
      .some((item) => item.handle === handle)).length;
    assert.ok(sharers > 1, `${dimension} handle is shared with only ${sharers} record(s)`);
  }
  assert.equal(acceptance.label, 'REIDENTIFIABLE');
  assert.equal(acceptance.familyId, 'REIDENTIFIABLE_RARE_COMBINATION');
  assert.equal(acceptance.local.flag, 'RISK');
  assert.equal(acceptance.local.equivalenceSiteCount, 1);
  assert.equal(acceptance.combined.flag, 'RISK');
  assert.equal(report.counts.combined.miss, 0,
    'no re-identifiable case is left unflagged in the shipped corpus');
  assert.equal(report.counts.localModel.trueFlag,
    report.rows.filter((item) => item.label === 'REIDENTIFIABLE').length);
  // The flag is evidence, never authority, and generalization is never applied.
  assert.equal(report.authority, 'NONE');
  assert.deepEqual({ ...report.advisory },
    { applied: false, effect: 'IGNORED_NO_AUTHORITY', requiresDeterministicPolicy: true });
  assert.equal(acceptance.advisory.applied, false);
  assert.ok(acceptance.advisory.recommendations.length > 0);
  for (const item of acceptance.advisory.recommendations) {
    assert.equal(item.implemented, false);
    assert.equal(item.requiresDeterministicPolicy, true);
    assert.ok(REID_DIMENSIONS.includes(item.dimension));
    assert.ok(REID_GENERALIZATION_ACTIONS.includes(item.action));
    assert.ok(REID_RECOMMENDATION_RATIONALES.includes(item.rationale));
    assert.ok(item.derivedFacts.some((fact) => fact.kind === 'EQUIVALENCE_SITE_COUNT'));
    assert.ok(item.derivedFacts.some((fact) => fact.kind === 'ADVISORY_MIN_CELL_SITES' &&
      fact.value === REID_ADVISORY_MIN_CELL_SITES));
  }
});

test('a false-safe judgment is counted as a miss, never as a pass and never as a safe verdict',
  async () => {
    const report = await run(localJudge({ answers: answers(false) }));
    const reidentifiable = report.rows.filter((item) => item.label === 'REIDENTIFIABLE');
    assert.equal(report.counts.shadowJudge.miss, reidentifiable.length);
    assert.equal(report.counts.shadowJudge.trueFlag, 0);
    assert.equal(report.counts.shadowJudge.falseFlag, 0);
    assert.equal(report.counts.shadowJudge.abstained, 0);
    for (const item of reidentifiable) {
      assert.equal(item.judge.flag, 'SAFE');
      assert.equal(item.combined.flag, 'RISK', 'the deterministic signal still flags the case');
      assert.equal(item.advisory.applied, false, 'a safe judgment must not generalize anything');
    }
    assert.equal(report.rows.filter((item) => item.label === 'REIDENTIFIABLE')
      .every((item) => item.combined.basis === 'LOCAL_UNIQUE_COMBINATION'), true);
    assert.equal(sum(report.counts.combined), report.rows.length);
    // Nothing in the corpus changed: a run is measurement, never a transformation.
    assert.deepEqual(corpus(), corpus());
  });

test('every re-identifiable case stays flagged under every judge behaviour, including outages',
  async () => {
    const judges = {
      flagsRisk: localJudge(),
      falseSafe: localJudge({ answers: answers(false) }),
      refuses: localJudge({ mode: 'REFUSE' }),
      partial: localJudge({ answers: { ri_risk: RISK_ANSWER } }),
      malformed: localJudge({ answers: { ri_risk: { ...RISK_ANSWER, treatment: 'GENERALIZE' },
        ri_utility: UTILITY_ANSWER } }),
    };
    for (const [name, judge] of Object.entries(judges)) {
      const report = await run(judge);
      assert.equal(sum(report.counts.localModel), report.rows.length, name);
      assert.equal(sum(report.counts.shadowJudge), report.rows.length, name);
      assert.equal(sum(report.counts.combined), report.rows.length, name);
      assert.equal(report.counts.combined.miss, 0, `${name}: no re-identifiable case is unflagged`);
      assert.equal(report.rows.filter((item) => item.label === 'REIDENTIFIABLE')
        .every((item) => item.combined.flag === 'RISK'), true, name);
      assert.equal(report.authority, 'NONE', name);
    }
  });

/* ------------------------------------------------- counting: true, false, miss, abstention */

test('the report counts true flags, false flags, misses and abstentions separately', async () => {
  const risk = await run(localJudge());
  const safe = await run(localJudge({ answers: answers(false) }));
  const out = await run(localJudge({ mode: 'REFUSE' }));
  const reidentifiable = risk.rows.filter((item) => item.label === 'REIDENTIFIABLE').length;
  const common = risk.rows.length - reidentifiable;

  assert.deepEqual(risk.counts.localModel,
    { cases: risk.rows.length, trueFlag: reidentifiable, falseFlag: 0, miss: 0,
      correctSafe: common, abstained: 0 });
  assert.deepEqual(risk.counts.shadowJudge,
    { cases: risk.rows.length, trueFlag: reidentifiable, falseFlag: common, miss: 0,
      correctSafe: 0, abstained: 0 });
  assert.deepEqual(safe.counts.shadowJudge,
    { cases: safe.rows.length, trueFlag: 0, falseFlag: 0, miss: reidentifiable,
      correctSafe: common, abstained: 0 });
  assert.deepEqual(out.counts.shadowJudge,
    { cases: out.rows.length, trueFlag: 0, falseFlag: 0, miss: 0, correctSafe: 0,
      abstained: out.rows.length });
  // An outage abstains. It is never a safe verdict and never reduces protection: the combination
  // escalates it, and the report says how many flags that escalation produced.
  assert.equal(out.judgeOutcomes.REFUSED, out.rows.length);
  assert.equal(out.escalatedByAbstention, common);
  assert.equal(out.rows.every((item) => item.combined.flag === 'RISK'), true);
  for (const report of [risk, safe, out]) {
    assert.equal(report.counts.localModel.abstained, 0, 'the deterministic signal never abstains');
    assert.deepEqual(Object.keys(report.judgeOutcomes).sort(), [...SHADOW_OUTCOMES].sort());
    assert.equal(Object.values(report.judgeOutcomes).reduce((total, value) => total + value, 0),
      report.rows.length, 'every observed outcome is attributed to exactly one row');
  }
});

test('an abstention escalates and is reported as such rather than hidden', async () => {
  const report = await run(localJudge({ mode: 'REFUSE' }));
  const escalated = report.rows.filter((item) =>
    item.combined.basis === 'JUDGE_ABSTENTION_ESCALATION');
  assert.equal(escalated.length, report.escalatedByAbstention);
  for (const item of escalated) {
    assert.equal(item.judge.flag, 'ABSTAIN');
    assert.equal(item.local.flag, 'COMMON');
    assert.equal(item.label, 'NOT_REIDENTIFIABLE', 'an escalated flag is an over-flag, and says so');
    assert.deepEqual([...item.judge.reasonCodes], ['ADAPTER_REFUSED']);
  }
  const local = report.rows.filter((item) => item.combined.basis === 'LOCAL_UNIQUE_COMBINATION');
  assert.equal(local.length, report.counts.localModel.trueFlag);
  assert.equal(report.rows.some((item) => item.combined.basis === 'JUDGE_RISK'), false);
  assert.equal(report.rows.some((item) => item.combined.basis === 'NO_FLAG'), false);
});

test('#11 timeout, partial and malformed outcomes are reused, never re-implemented', async () => {
  // The deadline only stops waiting, so a slower local double produces a TIMEOUT record with an
  // observable late settlement and no answer at all.
  const late = await run(localJudge({ latencyMs: 60 }), { deadlineMs: 5 });
  assert.equal(late.judgeOutcomes.TIMEOUT, late.rows.length);
  assert.equal(late.rows.every((item) => item.judge.flag === 'ABSTAIN' && item.judge.late === true),
    true);
  for (const item of late.rows) assert.deepEqual([...item.judge.reasonCodes], ['TIMED_OUT']);
  assert.equal(late.counts.shadowJudge.abstained, late.rows.length);
  // A judge answering only the risk question yields a PARTIAL record, and that answer is usable.
  const partial = await run(localJudge({ answers: { ri_risk: RISK_ANSWER } }));
  assert.equal(partial.judgeOutcomes.PARTIAL, partial.rows.length);
  assert.equal(partial.counts.shadowJudge.abstained, 0);
  assert.equal(partial.counts.shadowJudge.trueFlag,
    partial.rows.filter((item) => item.label === 'REIDENTIFIABLE').length);
  assert.equal(partial.rows.every((item) => item.judge.flag === 'RISK'), true);
  // The mirror image: a judge that never answers the risk question abstains on every row, and the
  // run still reports an attributable outcome rather than an empty-looking success.
  const unanswered = await run(localJudge({ answers: { ri_utility: UTILITY_ANSWER } }));
  assert.equal(unanswered.counts.shadowJudge.abstained, unanswered.rows.length);
  assert.equal(unanswered.counts.shadowJudge.miss, 0);
  assert.equal(unanswered.rows.every((item) => item.judge.flag === 'ABSTAIN'), true);
  assert.equal(unanswered.rows.every((item) => item.judge.reasonCodes.includes('MISSING_ANSWER')),
    true);
  assert.equal(unanswered.rows.every((item) => item.combined.flag === 'RISK'), true);
  // A malformed answer becomes a closed reason on the record and an abstention on the row.
  const malformed = await run(localJudge({ answers: { ri_risk: { ...RISK_ANSWER, sensitivity: 'PUBLIC' },
    ri_utility: UTILITY_ANSWER } }));
  assert.equal(malformed.judgeOutcomes.PARTIAL, malformed.rows.length);
  assert.equal(malformed.rows.every((item) => item.judge.flag === 'ABSTAIN'), true);
  assert.equal(malformed.rows.every((item) => item.judge.reasonCodes.includes('UNEXPECTED_FIELD')),
    true);
  assert.equal(malformed.rows.every((item) => item.combined.flag === 'RISK'), true);
  // An oversized response is refused before parsing, and is likewise an abstention.
  const oversized = await run(localJudge({ answers: answers(true), responsePadBytes: 40_000 }));
  assert.equal(oversized.judgeOutcomes.REFUSED, oversized.rows.length);
  assert.equal(oversized.rows.every((item) => item.judge.reasonCodes.includes('RESPONSE_TOO_LARGE')),
    true);
  // A forged judge object is refused by #11: every row abstains and the pass is still reportable.
  const forged = await run({ ...BASE_SCRIPT, answers: answers(true) });
  assert.equal(forged.rows.every((item) => item.judge.flag === 'ABSTAIN'), true);
  assert.equal(forged.judgeOutcomes.REFUSED, forged.rows.length);
  // A judge whose identity cannot even be read falls back to fixed placeholders, never a message.
  const hostile = await run(new Proxy(BASE_SCRIPT, { getOwnPropertyDescriptor() {
    throw new Error('caller code ran'); } }));
  assert.deepEqual({ ...hostile.judge }, { id: 'unbound', version: 'unbound', servedModel: 'NONE' });
  assert.equal(hostile.rows.every((item) => item.judge.flag === 'ABSTAIN'), true);
  assert.equal(hostile.rows.every((item) => item.combined.flag === 'RISK'), true);
});

/* ------------------------------------------------------------------- the local quasi-identifier model */

test('the local model counts distinct SITES in a combination cell, not records', () => {
  const value = corpus();
  const cells = reidentificationCells(value);
  const byId = new Map(cells.map((cell) => [cell.recordId, cell]));
  // Two records of the SAME site: two matching records, one site, still re-identifying.
  assert.deepEqual({ ...byId.get('reid-case-17') },
    { recordId: 'reid-case-17', recordCount: 2, siteCount: 1, flag: 'RISK' });
  // A common combination shared by four evaluated sites plus one background record.
  assert.deepEqual({ ...byId.get('reid-case-13') },
    { recordId: 'reid-case-13', recordCount: 5, siteCount: 5, flag: 'COMMON' });
  // One common geography, process or date value alone is not identifying.
  for (const caseId of ['reid-case-22', 'reid-case-25', 'reid-case-28']) {
    assert.equal(byId.get(caseId).siteCount, 3, caseId);
    assert.equal(byId.get(caseId).flag, 'COMMON', caseId);
  }
  // Rare-looking but shared by exactly two sites: rare is not the same as re-identifying.
  assert.deepEqual({ ...byId.get('reid-case-31') },
    { recordId: 'reid-case-31', recordCount: 2, siteCount: 2, flag: 'COMMON' });
  // A wide combination shared by three sites.
  assert.equal(byId.get('reid-case-19').siteCount, 3);
  assert.equal(byId.get('reid-case-19').flag, 'COMMON');
  // The cell table exposes counts only: no handle and no combination key.
  const serialized = JSON.stringify(cells);
  for (const entry of value.records) {
    for (const item of entry.quasiIdentifiers) {
      assert.equal(serialized.includes(item.handle), false, 'a cell must not carry a handle');
    }
  }
  // Cells cover every record, including the background population.
  assert.equal(cells.length, value.records.length);
});

test('the shipped corpus is structural only and covers every quasi-identifier dimension', () => {
  const value = corpus();
  assert.equal(value.id, REID_CORPUS_ID);
  assert.equal(value.corpusVersion, REID_CORPUS_VERSION);
  assert.equal(value.records.length, 39);
  assert.equal(value.records.filter((entry) => entry.role === 'POPULATION_BACKGROUND').length, 6);
  assert.equal(value.records.filter((entry) => entry.role === 'EVALUATED_CASE').length, 33);
  const dimensions = new Set(value.records.flatMap((entry) =>
    entry.quasiIdentifiers.map((item) => item.dimension)));
  assert.deepEqual([...dimensions].sort(), [...REID_DIMENSIONS].sort());
  for (const family of REID_FAMILY_IDS) {
    assert.ok(value.records.some((entry) => entry.familyId === family), family);
  }
  // A label exists on every evaluated case and on no background record.
  assert.equal(value.records.filter((entry) => entry.role === 'EVALUATED_CASE')
    .every((entry) => REID_LABELS.includes(entry.label)), true);
  assert.equal(value.records.filter((entry) => entry.role === 'POPULATION_BACKGROUND')
    .every((entry) => entry.label === undefined), true);
  // Every string in the corpus matches a closed allowlist, so no geography, date, process, project
  // or site name can hide in a field this module later reports on.
  for (const text of corpusStrings(value)) {
    assert.ok(CORPUS_STRING.some((pattern) => pattern.test(text)),
      `corpus string outside the allowlist: ${JSON.stringify(text)}`);
  }
  for (const entry of value.records) {
    assert.equal(entry.quasiIdentifiers.length >= 1 &&
      entry.quasiIdentifiers.length <= REID_MAX_QUASI_IDENTIFIERS, true);
    for (const item of entry.quasiIdentifiers) {
      assert.match(item.handle, /^qh-[0-9a-f]{16}\.invalid$/u);
      assert.match(item.ref, /^qi-[0-9a-f]{12}\.invalid$/u);
    }
  }
});

test('labels are planted independently and are compared, never recomputed', async () => {
  // A corpus whose labels contradict its structure must be counted in both directions. That is
  // only possible when the report compares against the planted label instead of deriving it.
  const records = corpus().records.filter((entry) => entry.role === 'EVALUATED_CASE')
    .map((entry) => ({ ...entry, label: entry.label === 'REIDENTIFIABLE' ? 'NOT_REIDENTIFIABLE'
      : 'REIDENTIFIABLE' }));
  const inverted = createReidentificationCorpus(spec(records, { id: 'inverted-labels-development' }));
  const report = await runReidentificationShadow(inverted, questionSet(), localJudge(), OPTIONS);
  const flagged = reidentificationCells(inverted).filter((cell) => cell.flag === 'RISK').length;
  assert.equal(report.counts.localModel.falseFlag, flagged,
    'a flagged case labelled safe is a false flag');
  assert.equal(report.counts.localModel.miss, report.rows.length - flagged,
    'a re-identifiable case the model did not flag is a miss');
  assert.equal(report.counts.localModel.trueFlag, 0);
  assert.equal(sum(report.counts.localModel), report.rows.length);
  // The local verdict itself is unchanged: only the comparison moved.
  assert.equal(row(report, 'reid-case-01').label, 'NOT_REIDENTIFIABLE');
  assert.equal(row(report, 'reid-case-01').local.flag, 'RISK');
  assert.equal(row(report, 'reid-case-01').advisory.recommendations.length > 0, true);
});

/* --------------------------------------------------- minimization, privacy and no lexical proof */

test('no handle, quasi-identifier reference or site reference reaches a request or a report', async () => {
  const value = corpus();
  const report = await run(localJudge());
  const serialized = JSON.stringify(report);
  for (const entry of value.records) {
    assert.equal(serialized.includes(entry.siteRef), false, `${entry.id} site ref`);
    for (const item of entry.quasiIdentifiers) {
      assert.equal(serialized.includes(item.handle), false, `${entry.id} handle`);
      assert.equal(serialized.includes(item.ref), false, `${entry.id} quasi-identifier ref`);
    }
  }
  // Content independence, measured rather than asserted: replacing every handle with a different
  // handle, while keeping ids, dimensions, site refs and labels, leaves every request digest
  // unchanged. That is the testable form of "no raw value is sent".
  const mapping = new Map();
  for (const handle of new Set(value.records.flatMap((entry) =>
    entry.quasiIdentifiers.map((item) => item.handle)))) {
    mapping.set(handle, `qh-${(0xa000000000000000n + BigInt(mapping.size)).toString(16)}.invalid`);
  }
  const swapped = createReidentificationCorpus(spec(value.records.map((entry) => ({
    ...entry, quasiIdentifiers: entry.quasiIdentifiers.map((item) => ({
      ...item, handle: mapping.get(item.handle) })) })), { id: REID_CORPUS_ID }));
  const swappedReport = await runReidentificationShadow(swapped, questionSet(), localJudge(),
    OPTIONS);
  assert.deepEqual(swappedReport.rows.map((item) => item.judge.requestDigest),
    report.rows.map((item) => item.judge.requestDigest));
  // The dimension structure is still visible to the report; the values are not.
  assert.deepEqual(swappedReport.rows.map((item) => item.dimensions),
    report.rows.map((item) => item.dimensions));
});

test('this seam cannot produce a lexical match, because no name exists anywhere in it', () => {
  // The corpus stores no text field at all, so "the site name was still present" is not an
  // available failure mode here. The strongest structural statement is an allowlist over the
  // corpus and an allowlist over the report's own keys.
  const value = corpus();
  for (const entry of value.records) {
    assert.deepEqual(Object.keys(entry).sort(), ['directNameReplaced', 'familyId', 'id', 'label',
      'quasiIdentifiers', 'role', 'siteRef'].filter((key) => entry[key] !== undefined));
    assert.deepEqual(Object.keys(entry.quasiIdentifiers[0]).sort(), ['dimension', 'handle', 'ref']);
  }
  assert.equal(corpusStrings(value).some((text) => text.includes('@')), false);
  assert.equal(corpusStrings(value).some((text) => /[A-Z][a-z]/u.test(text)), false);
});

/* ------------------------------------------------------------ configuration is authority-free */

test('a caller flag is not an authorization primitive and cannot reach the judge', async () => {
  const judge = localJudge();
  for (const [name, options] of [
    ['synthetic', { ...OPTIONS, synthetic: true }],
    ['trusted', { ...OPTIONS, trusted: true }],
    ['safe', { ...OPTIONS, safe: true }],
    ['destinationPolicy', { ...OPTIONS, destinationPolicy: 'external' }],
    ['authorization', { ...OPTIONS, authorization: 'granted' }],
    ['external', { ...OPTIONS, execution: 'EXTERNAL' }],
    ['unknownExecution', { ...OPTIONS, execution: 'HOSTED_JEV' }],
    ['missingDeadline', { execution: 'IN_PROCESS', tenantRef: TENANT }],
    ['zeroDeadline', { ...OPTIONS, deadlineMs: 0 }],
    ['hugeDeadline', { ...OPTIONS, deadlineMs: 30_001 }],
    ['fractionalDeadline', { ...OPTIONS, deadlineMs: 12.5 }],
    ['badTenant', { ...OPTIONS, tenantRef: ` ${TENANT}` }],
    ['controlTenant', { ...OPTIONS, tenantRef: `tenant${String.fromCharCode(9)}a.invalid` }],
    ['longTenant', { ...OPTIONS, tenantRef: `t${'x'.repeat(256)}` }],
    ['notAnObject', 'IN_PROCESS'],
  ]) {
    await assert.rejects(() => runReidentificationShadow(corpus(), questionSet(), judge, options),
      (error) => error.message === 'Invalid reidentification shadow input' &&
        !error.message.includes(TENANT), name);
  }
  // No option shape can make the runner reach anything but the local in-process #11 seam.
  assert.equal(JSON.stringify(await run(judge)), JSON.stringify(await run(judge)));
});

test('a forged corpus, question set or judge identity is refused before anything runs', async () => {
  const judge = localJudge();
  const value = corpus();
  assert.equal(isReidentificationCorpus(value), true);
  assert.equal(isReidentificationCorpus({ ...value }), false);
  assert.equal(isReidentificationCorpus(JSON.parse(JSON.stringify(value))), false);
  assert.equal(isReidentificationCorpus(null), false);
  assert.equal(isReidentificationCorpus('corpus'), false);
  await assert.rejects(() => runReidentificationShadow({ ...value }, questionSet(), judge, OPTIONS),
    (error) => error.message === 'Invalid reidentification shadow input');
  await assert.rejects(() => runReidentificationShadow(value, { ...questionSet() }, judge, OPTIONS),
    (error) => error.message === 'Invalid reidentification shadow input');
  // A question set without the re-identification question cannot be scored.
  const withoutRisk = defineShadowQuestionSet({ id: REID_QUESTION_SET_ID,
    version: REID_QUESTION_SET_VERSION, questions: [
      { id: REID_UTILITY_QUESTION_ID, kind: 'score', purpose: 'UTILITY_NECESSITY',
        instructions: 'Is exact precision required?', criteria: ['coarsen first', 'required'],
        propose: { byLabel: { '0': 'ENGINEERING_IDENTIFIER', '1': 'ENGINEERING_IDENTIFIER' } } }] });
  await assert.rejects(() => runReidentificationShadow(value, withoutRisk, judge, OPTIONS),
    (error) => error.message === 'Invalid reidentification shadow input');
  assert.throws(() => reidentificationCells({ ...value }),
    (error) => error.message === 'Invalid reidentification shadow input');
  assert.throws(() => reidentificationCells(null),
    (error) => error.message === 'Invalid reidentification shadow input');
});

test('a hostile corpus spec is refused as data, without running caller code or echoing it', () => {
  let invocations = 0;
  const executed = () => { invocations += 1; throw new Error('caller code ran'); };
  const good = specRecord();
  const hostile = [
    ['accessorField', [specRecord({ siteRef: { get value() { return executed(); } } })]],
    ['accessorHandle', [specRecord({ quasiIdentifiers: [{ ref: 'qi-00000000ffff.invalid',
      dimension: 'GEOGRAPHY', get handle() { return executed(); } }] })]],
    ['throwingProxy', [new Proxy(good, { ownKeys() { throw new Error('planted value'); } })]],
    ['recordToJSON', [specRecord({ toJSON() { return executed(); } })]],
    ['quasiIdentifierToJSON', [specRecord({ quasiIdentifiers: [{ ref: 'qi-00000000ffff.invalid',
      dimension: 'GEOGRAPHY', handle: 'qh-000000000000ffff.invalid',
      toJSON() { return executed(); } }] })]],
    ['corpusToJSON', Object.assign(spec([good]), { toJSON() { return executed(); } })],
    ['prototypeToJSON', [Object.assign(Object.create({ toJSON() { return executed(); } }), good)]],
    ['functionValue', [specRecord({ familyId: () => executed() })]],
    ['unknownDimension', [specRecord({ quasiIdentifiers: [{ ref: 'qi-00000000ffff.invalid',
      dimension: 'SITE_NAME', handle: 'qh-000000000000ffff.invalid' }] })]],
    ['repeatedDimension', [specRecord({ quasiIdentifiers: [good.quasiIdentifiers[0],
      { ...good.quasiIdentifiers[0], ref: 'qi-00000000fffe.invalid' }] })]],
    ['rawLookingHandle', [specRecord({ quasiIdentifiers: [{ ref: 'qi-00000000ffff.invalid',
      dimension: 'GEOGRAPHY', handle: 'synthetic-plant-north' }] })]],
    ['emailHandle', [specRecord({ quasiIdentifiers: [{ ref: 'qi-00000000ffff.invalid',
      dimension: 'GEOGRAPHY', handle: 'someone@example.invalid' }] })]],
    ['routableHandle', [specRecord({ quasiIdentifiers: [{ ref: 'qi-00000000ffff.invalid',
      dimension: 'GEOGRAPHY', handle: 'qh-10.0.0.1' }] })]],
    ['rawSiteRef', [specRecord({ siteRef: 'synthetic-plant-north' })]],
    ['missingLabel', [specRecord({ label: undefined })]],
    ['labelOmitted', [{ id: good.id, role: good.role, familyId: good.familyId,
      siteRef: good.siteRef, directNameReplaced: true, quasiIdentifiers: good.quasiIdentifiers }]],
    ['labelOnBackground', [specRecord({ role: 'POPULATION_BACKGROUND' })]],
    ['inventedLabel', [specRecord({ label: 'MAYBE' })]],
    ['nameNotReplaced', [specRecord({ directNameReplaced: false })]],
    ['nameReplacedMissing', [specRecord({ directNameReplaced: undefined })]],
    ['duplicateId', [good, specRecord({ siteRef: 'site-00000000fffe.invalid' })]],
    ['noQuasiIdentifiers', [specRecord({ quasiIdentifiers: [] })]],
    ['widenedRecord', [specRecord({ siteName: 'synthetic-plant-north' })]],
    ['overBoundList', [specRecord({ quasiIdentifiers: Array.from({ length: 9 },
      (_value, index) => ({ ref: `qi-${String(index).padStart(12, '0')}.invalid`,
        dimension: REID_DIMENSIONS[index % REID_DIMENSIONS.length],
        handle: `qh-${String(index + 1).padStart(16, '0')}.invalid` })) })]],
    ['sparseArray', [Object.assign([good], { 1: good })]],
    ['arraySubclass', [spec]],
    ['badVersion', spec([good], { version: 2 })],
    ['missingVersion', { id: 'spec-development', corpusVersion: '1', records: [good] }],
    ['badCorpusId', spec([good], { id: 'Synthetic Development' })],
    ['badCorpusVersion', spec([good], { corpusVersion: 'v 1' })],
    ['emptyRecords', spec([])],
    ['backgroundOnly', spec([specRecord({ role: 'POPULATION_BACKGROUND', label: undefined })])],
    ['notAnObject', 'corpus'],
  ];
  for (const [name, value] of hostile) {
    invocations = 0;
    assert.throws(() => createReidentificationCorpus(value),
      (error) => error.message === 'Invalid reidentification shadow input' &&
        !error.message.includes('caller code ran'), name);
    assert.equal(invocations, 0, `${name}: a refused spec must not run caller code`);
  }
  // The record caps: 128 records in total, 64 of them evaluated cases.
  const capped = (count, role, start) => Array.from({ length: count }, (_value, offset) => {
    const index = start + offset;
    const base = { id: `reid-cap-${role === 'EVALUATED_CASE' ? 'case' : 'pop'}-${index}`, role,
      familyId: role === 'EVALUATED_CASE' ? 'REIDENTIFIABLE_RARE_COMBINATION'
        : 'POPULATION_BACKGROUND',
      siteRef: `site-${String(index).padStart(12, '0')}.invalid`, directNameReplaced: true,
      quasiIdentifiers: [{ ref: `qi-${String(index).padStart(12, '0')}.invalid`,
        dimension: role === 'EVALUATED_CASE' ? 'GEOGRAPHY' : 'DATE',
        handle: `qh-${String(index + 1).padStart(16, '0')}.invalid` }] };
    // A background record must not even carry a label key, which is a different refusal.
    return role === 'EVALUATED_CASE' ? { ...base, label: 'REIDENTIFIABLE' } : base;
  });
  assert.throws(() => createReidentificationCorpus(
    spec(capped(REID_MAX_RECORDS + 1, 'EVALUATED_CASE', 0))),
  (error) => error.message === 'Invalid reidentification shadow input');
  assert.throws(() => createReidentificationCorpus(
    spec(capped(REID_MAX_EVALUATED_CASES + 1, 'EVALUATED_CASE', 0))),
  (error) => error.message === 'Invalid reidentification shadow input');
  const atLimit = createReidentificationCorpus(spec([
    ...capped(REID_MAX_EVALUATED_CASES, 'EVALUATED_CASE', 0),
    ...capped(REID_MAX_RECORDS - REID_MAX_EVALUATED_CASES, 'POPULATION_BACKGROUND', 500),
  ]));
  assert.equal(atLimit.records.length, REID_MAX_RECORDS);
  assert.equal(atLimit.records.filter((entry) => entry.role === 'EVALUATED_CASE').length,
    REID_MAX_EVALUATED_CASES);
});

/* ---------------------------------------------- generated isolation and bounded-work properties */

test('the local flag equals its own definition on generated corpora, and counts always balance',
  async () => {
    const judge = localJudge();
    let labels = 0;
    let commonCases = 0;
    for (let seed = 1; seed <= 16; seed += 1) {
      const records = generateReidentificationVectors(seed, 24).map((item) => ({
        ...item, familyId: item.role === 'EVALUATED_CASE' ? 'NOT_REIDENTIFIABLE_SHARED_COMBINATION'
          : 'POPULATION_BACKGROUND' }));
      const cases = records.filter((entry) => entry.role === 'EVALUATED_CASE');
      if (cases.length < 2) continue;
      const value = createReidentificationCorpus(spec(records,
        { id: `generated-${seed}-development` }));
      const cells = new Map(reidentificationCells(value).map((cell) => [cell.recordId, cell]));
      // A generated label is planted REIDENTIFIABLE exactly when the record's combination is the
      // only one for its site. This tests the implementation against its own definition; it is not
      // an independent oracle and says nothing about corpus quality.
      for (const entry of cases) {
        assert.equal(entry.label, cells.get(entry.id).siteCount === 1 ? 'REIDENTIFIABLE'
          : 'NOT_REIDENTIFIABLE', `seed ${seed} ${entry.id}`);
        labels += 1;
      }
      const report = await runReidentificationShadow(value, questionSet(), judge, OPTIONS);
      assert.equal(sum(report.counts.localModel), report.rows.length, `seed ${seed}`);
      assert.equal(sum(report.counts.shadowJudge), report.rows.length, `seed ${seed}`);
      assert.equal(sum(report.counts.combined), report.rows.length, `seed ${seed}`);
      assert.equal(report.counts.localModel.miss, 0, `seed ${seed}`);
      assert.equal(report.counts.localModel.falseFlag, 0, `seed ${seed}`);
      commonCases += report.counts.localModel.correctSafe;
      for (const item of report.rows) {
        const cell = cells.get(item.caseId);
        assert.equal(item.local.flag, cell.siteCount === 1 ? 'RISK' : 'COMMON', `seed ${seed}`);
        assert.equal(item.local.equivalenceSiteCount, cell.siteCount, `seed ${seed}`);
        assert.equal(item.local.equivalenceRecordCount, cell.recordCount, `seed ${seed}`);
        // No relaxation is reachable: RISK, or any unknown judge verdict, keeps the case flagged.
        if (item.local.flag === 'RISK' || item.judge.flag !== 'SAFE') {
          assert.equal(item.combined.flag, 'RISK', `seed ${seed} ${item.caseId}`);
        }
        assert.ok(item.quasiIdentifierCount <= REID_MAX_QUASI_IDENTIFIERS, `seed ${seed}`);
      }
      const serialized = JSON.stringify(report);
      for (const entry of value.records) {
        for (const item of entry.quasiIdentifiers) {
          assert.equal(serialized.includes(item.handle), false, `seed ${seed}`);
        }
      }
    }
    assert.ok(labels > 40, `generated property coverage: ${labels} labels`);
    assert.ok(commonCases > 40, `generated common-cell coverage: ${commonCases} cases`);
    assert.throws(() => generateReidentificationVectors(0, 1), TypeError);
    assert.throws(() => generateReidentificationVectors(1, REID_MAX_GENERATED_VECTORS + 1), TypeError);
    assert.throws(() => generateReidentificationVectors(2 ** 33, 1), TypeError);
    assert.equal(generateReidentificationVectors(7, 0).length, 0);
    assert.deepEqual(generateReidentificationVectors(7, 4), generateReidentificationVectors(7, 4),
      'a seed is reproducible');
    assert.notDeepEqual(generateReidentificationVectors(7, 4), generateReidentificationVectors(8, 4));
  });

test('a case is isolated: unrelated population records never change its verdict', async () => {
  const value = corpus();
  const baseline = new Map(reidentificationCells(value).map((cell) => [cell.recordId, cell]));
  const extra = Array.from({ length: 8 }, (_unused, index) => ({
    id: `reid-extra-${index}`, role: 'POPULATION_BACKGROUND', familyId: 'POPULATION_BACKGROUND',
    siteRef: `site-${String(index).padStart(12, '0')}.invalid`, directNameReplaced: true,
    quasiIdentifiers: [{ ref: `qi-${String(900000 + index).padStart(12, '0')}.invalid`,
      dimension: 'CUSTOMER_TYPE',
      handle: `qh-${String(index * 7 + 1).padStart(16, '0')}.invalid` }],
  }));
  const widened = createReidentificationCorpus(spec([...value.records, ...extra],
    { id: REID_CORPUS_ID }));
  const grown = new Map(reidentificationCells(widened).map((cell) => [cell.recordId, cell]));
  for (const cell of baseline.values()) {
    assert.deepEqual(grown.get(cell.recordId), cell,
      `${cell.recordId} must not depend on unrelated population records`);
  }
  const report = await runReidentificationShadow(widened, questionSet(), localJudge(), OPTIONS);
  assert.equal(report.rows.length, 33);
  assert.equal(report.corpus.records, 47);
  assert.equal(report.counts.localModel.miss, 0);
});

test('a corpus at the documented caps stays inside a generous bounded-work budget', async () => {
  const evaluated = Array.from({ length: REID_MAX_EVALUATED_CASES }, (_unused, index) => ({
    id: `reid-cap-${index}`, role: 'EVALUATED_CASE',
    familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    siteRef: `site-${String(index).padStart(12, '0')}.invalid`, directNameReplaced: true,
    label: 'REIDENTIFIABLE',
    quasiIdentifiers: REID_DIMENSIONS.slice(0, REID_MAX_QUASI_IDENTIFIERS).map((dimension, slot) => ({
      ref: `qi-${String(index * 8 + slot).padStart(12, '0')}.invalid`, dimension,
      handle: `qh-${String((index % 60) * 8 + slot + 1).padStart(16, '0')}.invalid` })) }));
  const background = Array.from({ length: REID_MAX_RECORDS - REID_MAX_EVALUATED_CASES },
    (_unused, index) => ({
      id: `reid-cap-pop-${index}`, role: 'POPULATION_BACKGROUND',
      familyId: 'POPULATION_BACKGROUND',
      siteRef: `site-${String(500 + index).padStart(12, '0')}.invalid`, directNameReplaced: true,
      quasiIdentifiers: [{ ref: `qi-${String(500 + index).padStart(12, '0')}.invalid`,
        dimension: 'ORG_UNIT', handle: `qh-${String(500 + index).padStart(16, '0')}.invalid` }] }));
  const value = createReidentificationCorpus(spec([...evaluated, ...background],
    { id: 'cap-development' }));
  const started = process.hrtime.bigint();
  const report = await runReidentificationShadow(value, questionSet(), localJudge(), OPTIONS);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  // A bounded-work sanity check on a development workstation, not a service latency claim. The
  // budget sits far above the measured cost so host contention cannot masquerade as a regression,
  // and it is not tuned against an observed measurement.
  assert.equal(report.rows.length, REID_MAX_EVALUATED_CASES);
  assert.equal(report.corpus.records, REID_MAX_RECORDS);
  assert.equal(sum(report.counts.combined), REID_MAX_EVALUATED_CASES);
  assert.ok(elapsedMs < 20_000, `bounded work took ${Math.round(elapsedMs)} ms`);
});

/* ---------------------------------------------------------------------- tenant scoping and shape */

test('a report is tenant scoped and its evidence cannot be replayed under another tenant', async () => {
  const report = await run(localJudge());
  const other = await runReidentificationShadow(corpus(), questionSet(), localJudge(),
    { ...OPTIONS, tenantRef: 'tenant-reid-b.invalid' });
  assert.equal(report.tenantRef, TENANT);
  assert.equal(other.tenantRef, 'tenant-reid-b.invalid');
  assert.equal(other.corpus.id, report.corpus.id, 'the corpus is shared; the binding is the tenant');
  // The tenant is part of the minimized request, so no digest from one tenant's run can be matched
  // against another tenant's run: a cross-tenant comparison of this evidence is not expressible.
  const mine = new Set(report.rows.map((item) => item.judge.requestDigest));
  const theirs = new Set(other.rows.map((item) => item.judge.requestDigest));
  assert.equal([...mine].some((digest) => theirs.has(digest)), false);
  assert.equal(mine.size, report.rows.length, 'each case is its own request');
});

test('the report shape is fixed: versioned, authority-free and free of treatment vocabulary',
  async () => {
    const report = await run(localJudge());
    assert.deepEqual(Object.keys(report).sort(), ['advisory', 'authority', 'corpus', 'counts',
      'escalatedByAbstention', 'judge', 'judgeOutcomes', 'questionSet', 'rows', 'tenantRef',
      'version']);
    assert.equal(report.version, 1);
    assert.equal(report.authority, 'NONE');
    assert.deepEqual(Object.keys(report.counts).sort(), ['combined', 'localModel', 'shadowJudge']);
    assert.deepEqual(Object.keys(report.counts.localModel).sort(),
      ['abstained', 'cases', 'correctSafe', 'falseFlag', 'miss', 'trueFlag']);
    assert.deepEqual(Object.keys(report.judgeOutcomes).sort(), [...SHADOW_OUTCOMES].sort());
    assert.deepEqual(Object.keys(report.advisory).sort(),
      ['applied', 'effect', 'requiresDeterministicPolicy']);
    assert.deepEqual({ ...report.corpus }, { id: REID_CORPUS_ID, corpusVersion: REID_CORPUS_VERSION,
      records: 39, evaluatedCases: 33 });
    assert.deepEqual({ ...report.questionSet },
      { id: REID_QUESTION_SET_ID, version: REID_QUESTION_SET_VERSION });
    assert.deepEqual({ ...report.judge }, { id: BASE_SCRIPT.id, version: BASE_SCRIPT.version,
      servedModel: BASE_SCRIPT.servedModel });
    // No object anywhere in the report names a treatment, an authorization or a sensitivity.
    const FORBIDDEN_KEY = /^(?:treatment|authorization|release|sensitivity|trust|scope|reversibility|permission|override)$/u;
    for (const key of allKeys(report)) {
      assert.equal(FORBIDDEN_KEY.test(key), false, `report key must not be ${key}`);
    }
    for (const item of report.rows) {
      assert.deepEqual(Object.keys(item).sort(), ['advisory', 'caseId', 'combined', 'dimensions',
        'familyId', 'judge', 'label', 'local', 'quasiIdentifierCount']);
      assert.deepEqual(Object.keys(item.local).sort(),
        ['equivalenceRecordCount', 'equivalenceSiteCount', 'flag']);
      assert.deepEqual(Object.keys(item.judge).sort(),
        ['flag', 'late', 'outcome', 'reasonCodes', 'requestDigest']);
      assert.deepEqual(Object.keys(item.combined).sort(), ['basis', 'flag']);
      assert.deepEqual(Object.keys(item.advisory).sort(), ['applied', 'effect', 'recommendations']);
      assert.match(item.judge.requestDigest, /^[0-9a-f]{64}$/u);
      assert.match(item.judge.outcome, /^[A-Z]+$/u);
      for (const code of item.judge.reasonCodes) assert.match(code, /^[A-Z_]+$/u, code);
      for (const item2 of item.advisory.recommendations) {
        assert.equal(item2.implemented, false);
        assert.equal(item2.requiresDeterministicPolicy, true);
        assert.deepEqual(Object.keys(item2).sort(), ['action', 'derivedFacts', 'dimension',
          'implemented', 'rationale', 'requiresDeterministicPolicy']);
        assert.ok(item.advisory.recommendations.length <= REID_MAX_ADVISORY_RECOMMENDATIONS);
      }
    }
    // Advisory recommendations appear for flagged combinations only.
    for (const item of report.rows) {
      assert.equal(item.local.flag === 'RISK', item.advisory.recommendations.length > 0,
        `${item.caseId}`);
    }
    assert.deepEqual(shippedRowIds.every((caseId) => report.rows.some((item) =>
      item.caseId === caseId)), true);
  });

/* ------------------------------------------------------------------------------- shipped module */

test('the shipped module cannot reach a network, a credential or an arbitrary evaluator', () => {
  const source = readFileSync(new URL('../dist/reidentification-shadow.js', import.meta.url),
    'utf8');
  const forbidden = [/node:(?:http|https|net|tls|dgram|dns|cluster|child_process|worker_threads)\b/u,
    /\bfetch\s*\(/u, /XMLHttpRequest/u, /WebSocket/u, /navigator\./u, /process\.env/u, /\beval\s*\(/u,
    /new Function/u, /\brequire\s*\(/u, /\bimport\s*\(/u, /Buffer\./u];
  for (const pattern of forbidden) assert.doesNotMatch(source, pattern, String(pattern));
  const imports = [...source.matchAll(/from ['"]([^'"]+)['"]/gu)].map((match) => match[1]);
  assert.deepEqual([...new Set(imports)], ['./semantic-judge-shadow.js']);
});

/* ------------------------------------------------- regressions for the independent review findings */

/**
 * Review finding F1: the shipped corpus stated that every handle of every case is shared, while three
 * handles occurred in exactly one record. The corpus now satisfies the claim and the claim is measured
 * over the WHOLE corpus rather than over the four dimensions of the acceptance case.
 */
test('every handle in the shipped corpus is shared, so no case rests on a single value', () => {
  const value = corpus();
  const sharing = new Map();
  for (const entry of value.records) {
    for (const item of entry.quasiIdentifiers) {
      const holders = sharing.get(item.handle) ?? [];
      holders.push(`${entry.id}:${item.dimension}`);
      sharing.set(item.handle, holders);
    }
  }
  const singletons = [...sharing].filter(([, holders]) => holders.length < 2)
    .map(([handle, holders]) => `${handle} ${JSON.stringify(holders)}`);
  assert.deepEqual(singletons, [],
    'a single shared value must not be able to identify a case on its own');
  assert.ok(sharing.size >= REID_DIMENSIONS.length, 'the corpus exercises a handle pool per dimension');
  // The dimensions that used to be singletons are the ones this assertion is about.
  for (const dimension of ['CUSTOMER_TYPE', 'DEVICE_CLASS', 'ROLE']) {
    const records = value.records.filter((entry) => entry.quasiIdentifiers
      .some((item) => item.dimension === dimension));
    assert.ok(records.length >= 2, `${dimension} must appear in more than one record`);
  }
});

/**
 * Review finding F3: the combination key was handle-only, so two records carrying the same handles
 * under different dimensions were merged and a unique (dimension, handle) fact was reported COMMON.
 * A cell is defined over (dimension, handle) pairs.
 */
test('an equivalence cell is keyed on (dimension, handle), never on a bare handle', async () => {
  const handles = (n) => `qh-${String(n).padStart(16, '0')}.invalid`;
  const record = (id, site, pairs) => ({ id, role: 'EVALUATED_CASE',
    familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    siteRef: `site-${String(site).padStart(12, '0')}.invalid`, directNameReplaced: true,
    label: 'REIDENTIFIABLE',
    quasiIdentifiers: pairs.map(([dimension, handle], slot) => ({
      ref: `qi-${String(slot + 1).padStart(12, '0')}.invalid`, dimension, handle: handles(handle) })) });
  // db-a and db-b carry the SAME handle multiset with the dimensions swapped. A handle-only key merges
  // them and under-claims; a dimension-aware key keeps both unique.
  const value = createReidentificationCorpus(spec([
    record('reid-dim-a', 1, [['GEOGRAPHY', 1], ['DATE', 2]]),
    record('reid-dim-b', 2, [['GEOGRAPHY', 2], ['DATE', 1]]),
    record('reid-dim-c', 3, [['GEOGRAPHY', 3], ['DATE', 4]]),
  ], { id: 'dimension-blind-development' }));
  const cells = new Map(reidentificationCells(value).map((cell) => [cell.recordId, cell]));
  assert.equal(cells.get('reid-dim-a').flag, 'RISK');
  assert.equal(cells.get('reid-dim-b').flag, 'RISK');
  assert.equal(cells.get('reid-dim-a').siteCount, 1);
  // A genuine shared (dimension, handle) combination is still one cell.
  const shared = createReidentificationCorpus(spec([
    record('reid-shared-a', 1, [['GEOGRAPHY', 5], ['DATE', 6]]),
    record('reid-shared-b', 2, [['GEOGRAPHY', 5], ['DATE', 6]]),
  ], { id: 'dimension-shared-development' }));
  const sharedCells = new Map(reidentificationCells(shared).map((cell) => [cell.recordId, cell]));
  assert.equal(sharedCells.get('reid-shared-a').siteCount, 2);
  assert.equal(sharedCells.get('reid-shared-a').flag, 'COMMON');
  // The report agrees with the cell table on the dimension-aware corpus.
  const report = await runReidentificationShadow(value, questionSet(), localJudge(), OPTIONS);
  assert.equal(report.counts.localModel.miss, 0);
  assert.equal(report.counts.localModel.falseFlag, 0);
  for (const item of report.rows) {
    assert.equal(item.local.flag, cells.get(item.caseId).flag, item.caseId);
  }
});

/**
 * Review finding F4: a caller-issued question set carrying the same id and version but different
 * question text was accepted and reported under the shipped question-set metadata. Only the set this
 * module issues may be scored.
 */
test('only the issued question set may be scored: id and version are not enough', async () => {
  const substituted = defineShadowQuestionSet({ id: REID_QUESTION_SET_ID,
    version: REID_QUESTION_SET_VERSION, questions: [
      { id: REID_RISK_QUESTION_ID, kind: 'choice', purpose: 'REIDENTIFICATION_RISK',
        instructions: 'A different question entirely, with no placeholder in it.',
        criteria: { [REID_RISK_LABEL]: 'different risk meaning',
          [REID_SAFE_LABEL]: 'different safe meaning' },
        propose: { byLabel: { [REID_RISK_LABEL]: 'CUSTOMER_OR_PARTNER',
          [REID_SAFE_LABEL]: 'ENGINEERING_IDENTIFIER' } } },
      { id: REID_UTILITY_QUESTION_ID, kind: 'score', purpose: 'UTILITY_NECESSITY',
        instructions: 'A different utility question.',
        criteria: ['different low', 'different high'],
        propose: { byLabel: { '0': 'ENGINEERING_IDENTIFIER', '1': 'ENGINEERING_IDENTIFIER' } } }] });
  assert.equal(substituted.id, REID_QUESTION_SET_ID);
  assert.equal(substituted.version, REID_QUESTION_SET_VERSION);
  await assert.rejects(() => runReidentificationShadow(corpus(), substituted, localJudge(), OPTIONS),
    (error) => error.message === 'Invalid reidentification shadow input');
  assert.equal(isIssuedReidentificationQuestionSet(questionSet()), true);
  assert.equal(isIssuedReidentificationQuestionSet({ ...questionSet() }), false);
  assert.equal(isIssuedReidentificationQuestionSet(substituted), false);
  assert.equal(isIssuedReidentificationQuestionSet(null), false);
});

/**
 * Review finding F5: the recommendation rationale claimed combination rarity while the ordering used
 * population cardinality, and a dimension whose single value every record shares was recommended --
 * generalizing a universal value cannot change an equivalence cell.
 */
test('a recommendation never names a dimension whose only value every record already shares',
  async () => {
    const report = await run(localJudge());
    const cardinality = new Map();
    const seen = new Map();
    for (const entry of corpus().records) {
      for (const item of entry.quasiIdentifiers) {
        const handles = seen.get(item.dimension) ?? new Set();
        handles.add(item.handle);
        seen.set(item.dimension, handles);
      }
    }
    for (const [dimension, handles] of seen) cardinality.set(dimension, handles.size);
    assert.equal(cardinality.get('CUSTOMER_TYPE'), 1);
    assert.equal(cardinality.get('DEVICE_CLASS'), 1);
    for (const item of report.rows) {
      for (const recommendation of item.advisory.recommendations) {
        const fact = recommendation.derivedFacts.find((entry) =>
          entry.kind === 'DISTINCT_HANDLE_COUNT_IN_DIMENSION');
        assert.ok(fact.value >= 2,
          `${item.caseId}/${recommendation.dimension}: a universal value cannot be generalized`);
        assert.equal(recommendation.rationale,
          recommendation === item.advisory.recommendations[0]
            ? 'LOWEST_POPULATION_CARDINALITY_DIMENSION' : 'OTHER_DIMENSION_IN_UNIQUE_COMBINATION');
      }
      assert.deepEqual([...new Set(REID_RECOMMENDATION_RATIONALES)].sort(),
        ['LOWEST_POPULATION_CARDINALITY_DIMENSION', 'OTHER_DIMENSION_IN_UNIQUE_COMBINATION']);
    }
    // The two cases that used to be told to generalize a universal dimension.
    for (const caseId of ['reid-case-10', 'reid-case-33']) {
      const recommended = row(report, caseId).advisory.recommendations.map((item) => item.dimension);
      assert.equal(recommended.includes('CUSTOMER_TYPE'), false, caseId);
      assert.equal(recommended.includes('DEVICE_CLASS'), false, caseId);
      assert.ok(recommended.length > 0, caseId);
    }
  });

/**
 * Review finding F6: the tenant reference accepted any bounded string while the other three reference
 * types were pattern-locked, so an email-shaped or path-shaped value could reach the report and the
 * judge request.
 */
test('the tenant reference is a bounded opaque token, like every other reference here', async () => {
  for (const [name, tenantRef] of [
    ['email', 'synthetic-planted-person@example.invalid'],
    ['path', '../../etc/synthetic'],
    ['uppercase', 'Tenant-A.invalid'],
    ['scheme', 'https://synthetic.invalid'],
    ['tooLong', `t${'x'.repeat(128)}`],
  ]) {
    await assert.rejects(() => runReidentificationShadow(corpus(), questionSet(), localJudge(),
      { ...OPTIONS, tenantRef }), (error) =>
      error.message === 'Invalid reidentification shadow input' &&
      !error.message.includes(tenantRef), name);
  }
  const report = await run(localJudge());
  assert.equal(report.tenantRef, TENANT);
  assert.equal(report.rows.length > 0, true);
});
