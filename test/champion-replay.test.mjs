import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  REPLAY_ANNOTATION_STATES, REPLAY_CASE_STATUSES, REPLAY_MARKER_PREFIX, REPLAY_MAX_CASES,
  REPLAY_MAX_CASE_BYTES, REPLAY_MAX_DEADLINE_MS, REPLAY_MAX_DISAGREEMENTS, REPLAY_MAX_EMISSION_BYTES,
  REPLAY_PRIVACY_OUTCOMES, REPLAY_PROMOTION_GATES, REPLAY_REASON_CODES, REPLAY_ROLES,
  REPLAY_RUN_STATUSES, REPLAY_RUN_KEY_BYTES, REPLAY_UTILITY_OUTCOMES, REPLAY_VERSION,
  generateSyntheticReplayCorpus, replayMarkerFor, runChampionReplay,
} from '../dist/champion-replay.js';

// Synthetic, obviously non-routable local development values only.
const SCOPE = { tenantId: 'tenant-a.invalid', projectId: 'project-a.invalid' };
const MARKER = /SYNTHETIC-MARKER-[0-9a-f]{16}/u;
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sha = (value) => createHash('sha256').update(String(value)).digest('hex');
const runKey = (fill) => new Uint8Array(REPLAY_RUN_KEY_BYTES).fill(fill);
const bundle = (id, version, seed) => ({ id, version, digest: sha(`${id}/${version}/${seed}`) });
const trusted = (overrides = {}) => ({
  version: 1, scope: SCOPE, runId: 'replay-dev-run-1', runKey: runKey(7),
  pins: { champion: bundle('hylja.detectors', '1', 'champion'), challenger: bundle('hylja.detectors', '2', 'challenger') },
  ...overrides,
});
const corpus = (count = 6, seed = 11, scope = SCOPE) =>
  generateSyntheticReplayCorpus({ version: 1, scope, count, seed });
const ordinal = (caseRef) => Number(caseRef.slice('case-'.length));
const expectedAnswer = (view) => `REPLAY-ANSWER-${ordinal(view.caseRef)}-${view.family}`;

/**
 * A strict deterministic evaluator: withholds the planted marker, answers the task expectation.
 * Its own observation state is kept out of the evaluator object, because the substrate refuses any
 * property an evaluator does not need (`bundle`, `evaluate`) and never runs a caller accessor.
 */
const evaluatorStates = new WeakMap();
const stateOf = (evaluator) => evaluatorStates.get(evaluator);
function strictEvaluator(reference, options = {}) {
  const state = { calls: [], inFlight: 0, peak: 0, seen: null };
  const evaluator = {
    bundle: options.bundle ?? reference,
    evaluate(view) {
      state.calls.push(view.caseRef);
      state.inFlight += 1;
      state.peak = Math.max(state.peak, state.inFlight);
      state.seen ??= view;
      const finish = () => { state.inFlight -= 1; };
      const result = {
        version: 1,
        claim: options.claim ?? (MARKER.test(view.text) ? 'MARKER_WITHHELD' : 'NO_MARKER_PRESENT'),
        emission: options.leak ? view.text : view.text.replace(MARKER, '[REDACTED-SYNTHETIC]'),
        ...(options.omitAnswer ? {} : { taskAnswer: options.taskAnswer ?? expectedAnswer(view) }),
      };
      if (options.delayMs !== undefined) {
        return new Promise((resolveResult, rejectResult) => {
          setTimeout(() => {
            finish();
            if (options.reject) { rejectResult(new Error(`late failure ${view.text}`)); return; }
            resolveResult(result);
          }, options.delayMs).unref?.();
        });
      }
      finish();
      if (options.throws) throw new Error(`evaluator failure ${view.text}`);
      return Object.hasOwn(options, 'result') ? options.result : result;
    },
  };
  evaluatorStates.set(evaluator, state);
  return evaluator;
}
const spec = (cases, champion, challenger, extra = {}) => ({
  trusted: trusted(), cases, champion, challenger, ...extra,
});
const recordsFor = (report, role) => report.records.filter((record) => record.role === role);
const plantedCount = (cases) => cases.filter((entry) => entry.marker.expectation === 'DENY').length;
const serialized = (report) => JSON.stringify(report);

test('a deterministic development replay compares both sides per case and grants nothing', async () => {
  const cases = corpus();
  const champion = strictEvaluator(trusted().pins.champion);
  const challenger = strictEvaluator(trusted().pins.challenger);
  const report = await runChampionReplay(spec(cases, champion, challenger));

  assert.equal(REPLAY_VERSION, 'hylja.replay-shadow.v1');
  assert.equal(report.version, 1);
  assert.equal(report.status, 'COMPLETE');
  assert.deepEqual(report.reasons, []);
  assert.equal(report.run.cases, cases.length);
  assert.equal(report.run.annotations.authority, 'NONE');
  assert.equal(report.records.length, cases.length * 2);

  for (const role of REPLAY_ROLES) {
    const side = report.sides[role];
    assert.equal(side.role, role);
    assert.equal(side.pinState, 'PINNED');
    assert.deepEqual(side.bundle, role === 'CHAMPION' ? trusted().pins.champion : trusted().pins.challenger);
    assert.deepEqual(side.cases, { total: cases.length, measured: cases.length, unknown: 0, rejected: 0 });
    assert.deepEqual(side.privacy, {
      withheld: plantedCount(cases), emitted: 0, notApplicable: cases.length - plantedCount(cases), unknown: 0,
    });
    assert.deepEqual(side.utility, { match: cases.length, mismatch: 0, unknown: 0 });
    assert.equal(side.errors, 0);
    assert.ok(side.latencyMs.total >= 0 && side.latencyMs.max >= 0);
    assert.deepEqual(side.cost, { state: 'UNMEASURED', reason: 'OFFLINE_NO_COST_SIGNAL' });
    assert.equal(side.review.recommendation, 'NO_FINDING_IN_THIS_SUBSET');
    assert.equal(side.review.authority, 'NONE');
    assert.deepEqual(side.review.reasons, []);
  }
  assert.deepEqual(report.disagreements, []);
  assert.deepEqual(report.shadow, {
    mode: 'OFFLINE_DEVELOPMENT', execution: 'IN_PROCESS', hostedTransport: 'NONE',
    candidateExecution: 'NONE', authority: 'NONE',
  });
  assert.deepEqual(report.promotion, { state: 'UNAVAILABLE', authority: 'NONE', gates: REPLAY_PROMOTION_GATES });
  assert.deepEqual(report.productionEligibility, { state: 'UNAVAILABLE', authority: 'NONE' });

  // Fixed order: every case in ordinal order, champion record before challenger record.
  assert.deepEqual(report.records.map((record) => `${record.caseRef}/${record.role}`),
    cases.flatMap((_, index) => [`case-${index + 1}/CHAMPION`, `case-${index + 1}/CHALLENGER`]));
  const first = report.records[0];
  assert.equal(first.caseRef, 'case-1');
  assert.equal(first.status, 'MEASURED');
  assert.equal(first.privacy, 'MARKER_WITHHELD');
  assert.equal(first.privacyClaim, 'MARKER_WITHHELD');
  assert.equal(first.utility, 'MATCH');
  assert.deepEqual(first.reasons, []);
  assert.equal(typeof first.digest, 'string');
  assert.equal(first.digest.length, 64);
  assert.match(first.caseRef, /^case-\d+$/u);
  assert.match(first.casePseudonym, /^[0-9a-f]{32}$/u);
  assert.match(first.runRef, /^[0-9a-f]{32}$/u);
  assert.match(first.scopePseudonym.tenant, /^[0-9a-f]{32}$/u);
  // The report binds references only: no case key, case text, marker, tenant label or expectation.
  const text = serialized(report);
  for (const entry of cases) {
    assert.ok(!text.includes(entry.caseKey), entry.caseKey);
    assert.ok(!text.includes(entry.text), entry.caseRef);
    assert.ok(!text.includes(entry.task.expectedAnswer), entry.caseRef);
    const marker = MARKER.exec(entry.text);
    if (marker) assert.ok(!text.includes(marker[0]), marker[0]);
  }
  for (const label of [SCOPE.tenantId, SCOPE.projectId, 'replay-dev-run-1']) {
    assert.ok(!text.includes(label), label);
  }
});

test('a permissive challenger that releases the planted marker is an explicit finding, never an adoption', async () => {
  const cases = corpus();
  const champion = strictEvaluator(trusted().pins.champion);
  const challenger = strictEvaluator(trusted().pins.challenger, { leak: true, claim: 'MARKER_WITHHELD' });
  const report = await runChampionReplay(spec(cases, champion, challenger));

  assert.equal(report.status, 'COMPLETE');
  assert.deepEqual(report.sides.CHAMPION.privacy, {
    withheld: plantedCount(cases), emitted: 0, notApplicable: cases.length - plantedCount(cases), unknown: 0,
  });
  assert.deepEqual(report.sides.CHALLENGER.privacy, {
    withheld: 0, emitted: plantedCount(cases), notApplicable: cases.length - plantedCount(cases), unknown: 0,
  });
  assert.equal(report.sides.CHALLENGER.review.recommendation, 'HUMAN_REVIEW_RECOMMENDED');
  assert.ok(report.sides.CHALLENGER.review.reasons.includes('MARKER_EMITTED_OBSERVED'));
  assert.ok(report.sides.CHALLENGER.review.reasons.includes('EVALUATOR_CLAIM_MISMATCH'));
  assert.equal(report.sides.CHAMPION.review.recommendation, 'NO_FINDING_IN_THIS_SUBSET');

  for (const record of recordsFor(report, 'CHALLENGER')) {
    if (record.privacy === 'MARKER_EMITTED') {
      assert.ok(record.reasons.includes('MARKER_EMITTED_OBSERVED'));
      assert.ok(record.reasons.includes('EVALUATOR_CLAIM_MISMATCH'));
    }
  }
  assert.equal(report.disagreements.length, plantedCount(cases));
  for (const disagreement of report.disagreements) {
    assert.deepEqual(Object.keys(disagreement).sort(), ['caseRef', 'challenger', 'champion', 'field']);
    assert.equal(disagreement.field, 'PRIVACY');
    assert.equal(disagreement.champion, 'MARKER_WITHHELD');
    assert.equal(disagreement.challenger, 'MARKER_EMITTED');
  }

  // The finding is not a decision: nothing in the report can replace, promote or release the champion.
  assert.deepEqual(report.promotion, { state: 'UNAVAILABLE', authority: 'NONE', gates: REPLAY_PROMOTION_GATES });
  assert.equal(report.productionEligibility.state, 'UNAVAILABLE');
  assert.equal(report.shadow.authority, 'NONE');
  assert.equal(report.shadow.hostedTransport, 'NONE');
  assert.equal(report.sides.CHAMPION.bundle.digest, trusted().pins.champion.digest);
  // The leaked marker itself is never echoed into any record.
  const text = serialized(report);
  const marker = MARKER.exec(cases[0].text);
  assert.ok(marker);
  assert.ok(!text.includes(marker[0]));
});

test('a stale or substituted bundle reference rejects every case for that side with no fallback', async () => {
  const cases = corpus(3, 5);

  const versionPin = strictEvaluator({ ...trusted().pins.challenger, version: '2.0.0-unpinned' });
  const versionReport = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion), versionPin));
  assert.equal(versionReport.sides.CHALLENGER.pinState, 'MISMATCHED');
  assert.deepEqual(versionReport.sides.CHALLENGER.cases, { total: 3, measured: 0, unknown: 0, rejected: 3 });
  // Every case lands in exactly one privacy and one utility bucket: an unmeasured case is unknown.
  assert.deepEqual(versionReport.sides.CHALLENGER.privacy, { withheld: 0, emitted: 0, notApplicable: 0, unknown: 3 });
  assert.deepEqual(versionReport.sides.CHALLENGER.utility, { match: 0, mismatch: 0, unknown: 3 });
  assert.deepEqual(stateOf(versionPin).calls, [], 'a rejected side is never executed as a fallback');
  assert.ok(versionReport.sides.CHALLENGER.review.reasons.includes('BUNDLE_PIN_MISMATCH'));
  assert.equal(versionReport.sides.CHAMPION.cases.measured, 3);
  assert.equal(versionReport.status, 'PARTIAL');
  for (const record of recordsFor(versionReport, 'CHALLENGER')) {
    assert.equal(record.status, 'REJECTED');
    assert.equal(record.privacy, 'UNKNOWN');
    assert.equal(record.utility, 'UNKNOWN');
    assert.deepEqual(record.reasons, ['BUNDLE_PIN_MISMATCH']);
  }

  const contentPin = strictEvaluator({ ...trusted().pins.challenger, digest: sha('substituted-content') });
  const contentReport = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion), contentPin));
  assert.equal(contentReport.sides.CHALLENGER.pinState, 'MISMATCHED');
  assert.deepEqual(stateOf(contentPin).calls, []);
  assert.ok(contentReport.sides.CHALLENGER.review.reasons.includes('BUNDLE_CONTENT_PIN_MISMATCH'));
  for (const record of recordsFor(contentReport, 'CHALLENGER')) {
    assert.deepEqual(record.reasons, ['BUNDLE_CONTENT_PIN_MISMATCH']);
  }

  const championPin = strictEvaluator({ ...trusted().pins.champion, digest: sha('substituted-champion') });
  const championReport = await runChampionReplay(spec(cases, championPin, strictEvaluator(trusted().pins.challenger)));
  assert.equal(championReport.sides.CHAMPION.pinState, 'MISMATCHED');
  assert.equal(championReport.sides.CHAMPION.cases.rejected, 3);
  // A rejected champion is not silently replaced by the challenger either.
  assert.deepEqual(recordsFor(championReport, 'CHAMPION').map((record) => record.status),
    ['REJECTED', 'REJECTED', 'REJECTED']);
  assert.equal(championReport.sides.CHALLENGER.cases.measured, 3);
});

test('malformed, unknown, missing and hostile evaluator output stays an explicit unknown result', async () => {
  const cases = corpus(2, 3);
  const attempts = [
    { name: 'authorization flag', options: { result: { version: 1, claim: 'MARKER_WITHHELD', emission: '', authorization: 'granted' } } },
    { name: 'promote flag', options: { result: { version: 1, claim: 'MARKER_WITHHELD', emission: '', promote: true } } },
    { name: 'wrong version', options: { result: { version: 2, claim: 'MARKER_WITHHELD', emission: '' } } },
    { name: 'unknown claim', options: { result: { version: 1, claim: 'CERTAINLY_FINE', emission: '' } } },
    { name: 'missing emission', options: { result: { version: 1, claim: 'MARKER_WITHHELD' } } },
    { name: 'non-string emission', options: { result: { version: 1, claim: 'MARKER_WITHHELD', emission: 42 } } },
    { name: 'missing result', options: { result: undefined } },
    { name: 'array result', options: { result: [] } },
    { name: 'oversized emission', options: { result: { version: 1, claim: 'MARKER_WITHHELD', emission: 'x'.repeat(REPLAY_MAX_EMISSION_BYTES + 1) } } },
    { name: 'oversized task answer', options: { result: { version: 1, claim: 'MARKER_WITHHELD', emission: '', taskAnswer: 'x'.repeat(600) } } },
    { name: 'throwing evaluator', options: { throws: true } },
    { name: 'rejected promise', options: { delayMs: 0, reject: true } },
  ];
  for (const attempt of attempts) {
    const champion = strictEvaluator(trusted().pins.champion);
    const challenger = strictEvaluator(trusted().pins.challenger, attempt.options);
    const report = await runChampionReplay(spec(cases, champion, challenger));
    const side = report.sides.CHALLENGER;
    assert.equal(side.cases.measured, 0, attempt.name);
    assert.equal(side.cases.unknown + side.cases.rejected, cases.length, attempt.name);
    assert.equal(side.privacy.withheld, 0, attempt.name);
    assert.equal(side.utility.match, 0, attempt.name);
    assert.equal(side.review.recommendation, 'HUMAN_REVIEW_RECOMMENDED', attempt.name);
    assert.notEqual(report.status, 'COMPLETE', attempt.name);
    for (const record of recordsFor(report, 'CHALLENGER')) {
      assert.ok(REPLAY_CASE_STATUSES.includes(record.status), attempt.name);
      assert.notEqual(record.status, 'MEASURED', attempt.name);
      assert.equal(record.privacy, 'UNKNOWN', attempt.name);
      assert.equal(record.utility, 'UNKNOWN', attempt.name);
      assert.ok(record.reasons.length > 0, attempt.name);
      for (const reason of record.reasons) assert.ok(REPLAY_REASON_CODES.includes(reason), `${attempt.name}:${reason}`);
    }
    // A refused side never changes what the champion measured.
    assert.equal(report.sides.CHAMPION.cases.measured, cases.length, attempt.name);
    // No exception text, planted value or marker reaches the report.
    const text = serialized(report);
    assert.ok(!text.includes('evaluator failure'), attempt.name);
    assert.ok(!text.includes('late failure'), attempt.name);
    assert.ok(!text.includes('granted'), attempt.name);
    assert.ok(!text.includes(MARKER.exec(cases[0].text)[0]), attempt.name);
    assert.deepEqual(report.promotion.gates, REPLAY_PROMOTION_GATES);
  }

  const hostile = strictEvaluator(trusted().pins.challenger, { result: new Proxy({ version: 1 }, {
    ownKeys() { throw new Error(`planted ${cases[0].text}`); },
  }) });
  const hostileReport = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion), hostile));
  assert.equal(hostileReport.sides.CHALLENGER.cases.measured, 0);
  assert.ok(!serialized(hostileReport).includes('planted'));
});

test('a deadline, a cancellation and a late failure are explicit outcomes and never an unhandled rejection', async () => {
  const cases = corpus(2, 8);

  const slow = strictEvaluator(trusted().pins.challenger, { delayMs: 200, reject: true });
  const timed = await runChampionReplay(
    spec(cases, strictEvaluator(trusted().pins.champion), slow), { deadlineMs: 5 });
  assert.ok(timed.sides.CHAMPION.cases.measured, 2);
  assert.equal(timed.sides.CHALLENGER.cases.measured, 0);
  for (const record of recordsFor(timed, 'CHALLENGER')) {
    assert.equal(record.status, 'UNKNOWN');
    assert.deepEqual(record.reasons, ['DEADLINE_EXCEEDED']);
    assert.ok(record.elapsedMs >= 0 && record.elapsedMs <= REPLAY_MAX_DEADLINE_MS, `${record.elapsedMs}`);
  }
  assert.ok(timed.sides.CHALLENGER.review.reasons.includes('DEADLINE_EXCEEDED'));
  assert.ok(timed.sides.CHALLENGER.review.reasons.includes('CASE_UNKNOWN'));
  assert.ok(!timed.sides.CHALLENGER.review.reasons.includes('EVALUATOR_ERROR'),
    'a deadline is not attributed to the evaluator');

  const controller = new AbortController();
  controller.abort();
  const never = strictEvaluator(trusted().pins.challenger);
  const cancelled = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion), never),
    { signal: controller.signal });
  assert.deepEqual(stateOf(never).calls, []);
  assert.equal(cancelled.sides.CHALLENGER.cases.measured, 0);
  assert.equal(cancelled.sides.CHAMPION.cases.measured, 0);
  for (const record of cancelled.records) {
    assert.equal(record.status, 'UNKNOWN');
    assert.deepEqual(record.reasons, ['CANCELLED']);
  }
  assert.ok(cancelled.reasons.includes('CANCELLED'));
  for (const role of REPLAY_ROLES) {
    assert.ok(!cancelled.sides[role].review.reasons.includes('EVALUATOR_ERROR'), role);
    assert.ok(cancelled.sides[role].review.reasons.includes('CASE_UNKNOWN'), role);
  }

  const midFlight = new AbortController();
  const slowChampion = strictEvaluator(trusted().pins.champion, { delayMs: 500 });
  const slowCancel = strictEvaluator(trusted().pins.challenger, { delayMs: 500 });
  const running = runChampionReplay(spec(cases, slowChampion, slowCancel),
    { deadlineMs: 1000, signal: midFlight.signal });
  setTimeout(() => midFlight.abort(), 20).unref?.();
  const midReport = await running;
  assert.equal(midReport.sides.CHAMPION.cases.measured, 0);
  assert.equal(midReport.sides.CHALLENGER.cases.measured, 0);
  assert.ok(midReport.sides.CHALLENGER.review.reasons.includes('CANCELLED'));

  // A settlement-only child process: late rejections after the deadline must not exit non-zero.
  const script = `
    import { runChampionReplay, generateSyntheticReplayCorpus } from '${root}/dist/champion-replay.js';
    const cases = generateSyntheticReplayCorpus({ version: 1,
      scope: { tenantId: 'tenant-a.invalid' }, count: 2, seed: 4 });
    const bundle = { id: 'hylja.detectors', version: '1', digest: '${'a'.repeat(64)}' };
    const late = { bundle, evaluate: () => new Promise((_, reject) =>
      setTimeout(() => reject(new Error('late boom')), 60)) };
    const strict = { bundle, evaluate: (view) => ({ version: 1, claim: 'MARKER_WITHHELD', emission: view.text }) };
    const report = await runChampionReplay({ trusted: { version: 1,
      scope: { tenantId: 'tenant-a.invalid' }, runId: 'r', runKey: new Uint8Array(32).fill(3),
      pins: { champion: bundle, challenger: bundle } },
      cases, champion: strict, challenger: late }, { deadlineMs: 5 });
    process.stdout.write(report.status + ':' + report.sides.CHALLENGER.cases.unknown);
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(child.status, 0, `a late rejection must not become an unhandled rejection: ${child.stderr}`);
  assert.equal(child.stdout, 'PARTIAL:2');
});

test('a foreign tenant or project scope is rejected before any evaluator runs', async () => {
  const champion = strictEvaluator(trusted().pins.champion);
  const challenger = strictEvaluator(trusted().pins.challenger);
  const foreign = corpus(4, 2, { tenantId: 'tenant-b.invalid', projectId: 'project-a.invalid' });
  const report = await runChampionReplay(spec(foreign, champion, challenger));

  assert.deepEqual(stateOf(champion).calls, []);
  assert.deepEqual(stateOf(challenger).calls, []);
  for (const side of REPLAY_ROLES) {
    assert.deepEqual(report.sides[side].cases, { total: 4, measured: 0, unknown: 0, rejected: 4 });
    assert.equal(report.sides[side].review.recommendation, 'HUMAN_REVIEW_RECOMMENDED');
    assert.ok(report.sides[side].review.reasons.includes('FOREIGN_TENANT_SCOPE'));
  }
  for (const record of report.records) {
    assert.equal(record.status, 'REJECTED');
    assert.equal(record.privacy, 'UNKNOWN');
    assert.equal(record.utility, 'UNKNOWN');
    assert.deepEqual(record.reasons, ['FOREIGN_TENANT_SCOPE']);
  }
  assert.deepEqual(report.disagreements, []);
  assert.equal(report.status, 'PARTIAL');

  const wrongProject = corpus(1, 2, { tenantId: SCOPE.tenantId, projectId: 'project-z.invalid' });
  const projectReport = await runChampionReplay(spec(wrongProject, champion, challenger));
  assert.equal(projectReport.sides.CHAMPION.cases.rejected, 1);
  assert.ok(projectReport.sides.CHAMPION.review.reasons.includes('FOREIGN_TENANT_SCOPE'));

  // A scope label is compared exactly: an omitted project is not the trusted scope.
  const unscoped = corpus(2, 2, { tenantId: SCOPE.tenantId });
  const unscopedReport = await runChampionReplay(spec(unscoped, champion, challenger));
  assert.equal(unscopedReport.sides.CHAMPION.cases.rejected, 2);
  const exactReport = await runChampionReplay(spec(corpus(2, 2, SCOPE), champion, challenger));
  assert.equal(exactReport.sides.CHAMPION.cases.measured, 2);
  assert.equal(exactReport.sides.CHAMPION.cases.rejected, 0);
});

test('records are safe references: keyed pseudonyms never correlate across tenants or runs', async () => {
  const cases = corpus(3, 21);
  const first = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)));
  const again = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)));
  const otherKey = await runChampionReplay(spec(cases,
    strictEvaluator(trusted().pins.champion), strictEvaluator(trusted().pins.challenger),
    { trusted: trusted({ runKey: runKey(8) }) }));

  // Same inputs and same run key: identical except for harness-measured wall clock.
  // Identical inputs and key: identical report apart from the harness-measured wall clock.
  const strip = (report) => JSON.parse(JSON.stringify(report, (key, value) => {
    if (key === 'elapsedMs' || key === 'digest') return 0;
    if (key === 'latencyMs') return { total: 0, max: 0 };
    return value;
  }));
  assert.deepEqual(strip(first), strip(again));

  // A different run key changes every pseudonym and digest, so no global digest can be joined.
  assert.notEqual(first.run.runRef, otherKey.run.runRef);
  assert.notEqual(first.records[0].digest, otherKey.records[0].digest);
  assert.notEqual(first.records[0].casePseudonym, otherKey.records[0].casePseudonym);
  assert.notEqual(first.run.corpusRef, otherKey.run.corpusRef);

  // The same synthetic cases replayed under a different trusted tenant scope.
  const otherTenant = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger),
    { trusted: trusted({ scope: { tenantId: 'tenant-z.invalid', projectId: 'project-a.invalid' } }) }));
  assert.notEqual(first.run.runRef, otherTenant.run.runRef);
  assert.notEqual(first.run.scopePseudonym.tenant, otherTenant.run.scopePseudonym.tenant);
  assert.notEqual(first.run.corpusRef, otherTenant.run.corpusRef);
  for (let index = 0; index < first.records.length; index += 1) {
    assert.notEqual(first.records[index].digest, otherTenant.records[index].digest, `record ${index}`);
    assert.notEqual(first.records[index].casePseudonym, otherTenant.records[index].casePseudonym, `record ${index}`);
  }
  // The tenant label itself is absent from both reports.
  assert.ok(!serialized(otherTenant).includes('tenant-z.invalid'));
});

test('bounded work: corpus size, duplicate keys, blind families and hostile case objects are refused', async () => {
  const champion = strictEvaluator(trusted().pins.champion);
  const challenger = strictEvaluator(trusted().pins.challenger);

  const tooMany = corpus(REPLAY_MAX_CASES);
  assert.equal(tooMany.length, REPLAY_MAX_CASES);
  const overflow = Array.from({ length: REPLAY_MAX_CASES + 1 }, (unused, index) => tooMany[index % REPLAY_MAX_CASES.length]);
  const overflowReport = await runChampionReplay(spec(overflow, champion, challenger));
  assert.equal(overflowReport.status, 'INVALID');
  assert.ok(overflowReport.reasons.includes('CASE_COUNT_EXCEEDED'));
  assert.deepEqual(stateOf(champion).calls, []);
  assert.deepEqual(overflowReport.records, []);
  assert.deepEqual(overflowReport.promotion.gates, REPLAY_PROMOTION_GATES);

  const cases = corpus(3, 13);
  const duplicated = [cases[0], cases[0], { ...cases[1], caseKey: cases[0].caseKey }, cases[2]];
  const duplicateReport = await runChampionReplay(spec(duplicated, champion, challenger));
  assert.deepEqual(duplicateReport.records.slice(0, 2).map((record) => record.status), ['MEASURED', 'MEASURED']);
  for (const record of duplicateReport.records.slice(2, 4)) {
    assert.equal(record.status, 'REJECTED');
    assert.deepEqual(record.reasons, ['CASE_KEY_DUPLICATE']);
  }
  assert.ok(duplicateReport.sides.CHAMPION.review.reasons.includes('CASE_REJECTED'));

  const oversized = [{ ...cases[0], text: 'x'.repeat(REPLAY_MAX_CASE_BYTES + 1) }, ...cases.slice(1)];
  const oversizedReport = await runChampionReplay(spec(oversized, champion, challenger));
  assert.deepEqual(oversizedReport.records.slice(0, 2).map((record) => record.status), ['REJECTED', 'REJECTED']);
  assert.ok(oversizedReport.records[0].reasons.includes('CASE_TEXT_TOO_LARGE'));

  const unplanted = [{ ...cases[0], text: 'no marker in this synthetic sentence' }, ...cases.slice(1)];
  const unplantedReport = await runChampionReplay(spec(unplanted, champion, challenger));
  assert.ok(unplantedReport.records[0].reasons.includes('CASE_MARKER_EXPECTATION_MISMATCH'));
  assert.equal(unplantedReport.records[0].privacy, 'UNKNOWN');

  const blind = [{ ...cases[0], family: 'H01' }, ...cases.slice(1)];
  const blindReport = await runChampionReplay(spec(blind, champion, challenger));
  assert.ok(blindReport.records[0].reasons.includes('CASE_FAMILY_NOT_DEVELOPMENT'));

  let enumerations = 0;
  const changing = new Proxy({ ...cases[0] }, {
    ownKeys(target) { enumerations += 1; return Reflect.ownKeys(target); },
    getOwnPropertyDescriptor() { throw new Error(`planted ${cases[1].text}`); },
  });
  const hostile = [changing, ...cases.slice(1)];
  const hostileReport = await runChampionReplay(spec(hostile, champion, challenger));
  assert.equal(hostileReport.records[0].status, 'REJECTED');
  assert.deepEqual(hostileReport.records[0].reasons, ['CASE_SPEC_INVALID']);
  assert.ok(enumerations <= 4, `a hostile case must not drive unbounded reflection: ${enumerations}`);
  assert.ok(!serialized(hostileReport).includes('planted'));

  const accessor = [{ ...cases[0], get text() { throw new Error('accessor'); } }, ...cases.slice(1)];
  const accessorReport = await runChampionReplay(spec(accessor, champion, challenger));
  assert.equal(accessorReport.records[0].status, 'REJECTED');
  assert.ok(!serialized(accessorReport).includes('accessor'));

  for (const invalid of [null, 'cases', 7, { first: cases[0] }]) {
    const invalidReport = await runChampionReplay({ ...spec(cases, champion, challenger), cases: invalid });
    assert.equal(invalidReport.status, 'INVALID');
    assert.ok(invalidReport.reasons.includes('INVALID_SPEC'), JSON.stringify(invalid));
    assert.deepEqual(invalidReport.records, []);
  }
  const empty = await runChampionReplay({ ...spec(cases, champion, challenger), cases: [] });
  assert.equal(empty.status, 'INVALID');
  assert.deepEqual(empty.reasons, ['CASE_COUNT_EXCEEDED']);
});

test('generated development corpora are deterministic, obviously synthetic and bounded', () => {
  const first = corpus(12, 77);
  const second = corpus(12, 77);
  assert.deepEqual(first, second);
  assert.notDeepEqual(first, corpus(12, 78));
  assert.equal(first.length, 12);

  const routable = /(?:@(?!example\.invalid)[a-z0-9.-]+\.(?:com|net|org|io|se)\b)|(?:\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})/iu;
  for (const entry of first) {
    assert.equal(entry.version, 1);
    assert.deepEqual(entry.scope, SCOPE);
    assert.match(entry.family, /^D(?:0[1-9]|1[0-2])$/u);
    assert.ok(entry.text.length > 0 && entry.text.length <= REPLAY_MAX_CASE_BYTES);
    assert.ok(!routable.test(entry.text), entry.text);
    assert.ok(entry.text.includes('example.invalid'), entry.text);
    const marker = MARKER.exec(entry.text);
    if (entry.marker.expectation === 'DENY') {
      assert.ok(marker, `a DENY case must plant a marker: ${entry.text}`);
      assert.equal(marker[0], replayMarkerFor(entry.caseKey));
      assert.ok(entry.text.startsWith(REPLAY_MARKER_PREFIX) || entry.text.includes(REPLAY_MARKER_PREFIX));
    } else {
      assert.equal(marker, null, entry.text);
    }
    assert.match(entry.task.expectedAnswer, /^REPLAY-ANSWER-\d+-D\d{2}$/u);
  }
  // Both a marker case and a marker-free control case exist in every generated corpus.
  assert.ok(first.some((entry) => entry.marker.expectation === 'DENY'));
  assert.ok(first.some((entry) => entry.marker.expectation === 'NONE'));
  // Markers are derived from the case key, so two corpora with the same key share the marker.
  assert.equal(replayMarkerFor('dev-1-1'), replayMarkerFor('dev-1-1'));
  assert.notEqual(replayMarkerFor('dev-1-1'), replayMarkerFor('dev-1-2'));
  assert.match(replayMarkerFor('anything'), /^SYNTHETIC-MARKER-[0-9a-f]{16}$/u);

  for (const bad of [undefined, null, { version: 2, scope: SCOPE, count: 3, seed: 1 },
    { version: 1, scope: SCOPE, count: 0, seed: 1 }, { version: 1, scope: SCOPE, count: 3, seed: -1 },
    { version: 1, scope: {}, count: 3, seed: 1 }, { version: 1, scope: SCOPE, count: REPLAY_MAX_CASES + 1, seed: 1 },
    { version: 1, scope: SCOPE, count: 3, seed: 1, extra: true }]) {
    assert.throws(() => generateSyntheticReplayCorpus(bad), (error) => {
      assert.equal(error.name, 'ReplayInputError');
      assert.ok(REPLAY_REASON_CODES.includes(error.code));
      assert.ok(!error.message.includes('extra'));
      return true;
    }, JSON.stringify(bad ?? null));
  }
});

test('optional annotation evidence is advisory, and conflict, unknown and invalid labels stay explicit', async () => {
  const cases = corpus(3, 31);
  const caseKey = cases[0].caseKey;
  const annotations = [
    { version: 1, caseKey, verdict: 'AGREED', source: 'MANUAL' },
    { version: 1, caseKey: cases[1].caseKey, verdict: 'DISAGREED', source: 'PROPOSED' },
    { version: 1, caseKey: cases[2].caseKey, verdict: 'UNRESOLVED', source: 'PROPOSED' },
  ];
  const report = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger), { annotations }));

  assert.deepEqual(report.run.annotations, {
    provided: 3, agreed: 1, disagreed: 1, unresolved: 1, conflicting: 0, rejected: 0, authority: 'NONE',
  });
  assert.deepEqual(recordsFor(report, 'CHAMPION').map((record) => record.annotation),
    ['AGREED', 'DISAGREED', 'UNRESOLVED']);
  // An annotation never changes a measured outcome.
  assert.equal(report.sides.CHAMPION.cases.measured, 3);
  assert.equal(report.sides.CHAMPION.utility.mismatch, 0);
  assert.ok(report.sides.CHAMPION.review.reasons.includes('ANNOTATION_DISAGREEMENT'));
  assert.ok(report.sides.CHAMPION.review.reasons.includes('ANNOTATION_CONFLICT') === false);
  assert.deepEqual(report.promotion.gates, REPLAY_PROMOTION_GATES);
  assert.equal(report.productionEligibility.state, 'UNAVAILABLE');

  const conflicting = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger), { annotations: [
      { version: 1, caseKey, verdict: 'AGREED', source: 'MANUAL' },
      { version: 1, caseKey, verdict: 'DISAGREED', source: 'PROPOSED' },
    ] }));
  assert.equal(conflicting.run.annotations.conflicting, 1);
  assert.equal(conflicting.run.annotations.agreed, 0);
  assert.equal(conflicting.run.annotations.disagreed, 0);
  assert.ok(REPLAY_ANNOTATION_STATES.includes(conflicting.records[0].annotation));
  assert.equal(conflicting.records[0].annotation, 'CONFLICT');
  assert.ok(conflicting.records[0].reasons.includes('ANNOTATION_CONFLICT'));
  assert.equal(conflicting.sides.CHAMPION.cases.measured, 3);
  assert.ok(conflicting.sides.CHAMPION.review.reasons.includes('ANNOTATION_CONFLICT'));

  const hostile = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger), { annotations: [
      { version: 1, caseKey, verdict: 'CERTAIN', source: 'MANUAL' },
      { version: 1, caseKey: cases[1].caseKey, verdict: 'AGREED', source: 'ADJUDICATOR', note: 'trusted' },
      { version: 1, caseKey: 'dev-unknown-99', verdict: 'AGREED', source: 'MANUAL' },
      { version: 1, caseKey: cases[2].caseKey, verdict: 'AGREED', source: 'MANUAL', authority: 'APPROVED' },
    ] }));
  assert.equal(hostile.run.annotations.provided, 4);
  assert.equal(hostile.run.annotations.rejected, 4);
  assert.equal(hostile.run.annotations.agreed, 0);
  assert.deepEqual(hostile.records.slice(0, 6).map((record) => record.annotation),
    ['INVALID', 'INVALID', 'INVALID', 'INVALID', 'INVALID', 'INVALID']);
  assert.equal(hostile.sides.CHAMPION.cases.measured, 3);
  assert.deepEqual(hostile.promotion.gates, REPLAY_PROMOTION_GATES);
  assert.ok(!serialized(hostile).includes('ADJUDICATOR'));
});

test('fixture expectations are labels: no expectation, flag or annotation can produce a pass or an authority', async () => {
  const cases = corpus(3, 44).map((entry) => ({ ...entry, task: { ...entry.task, expectedAnswer: 'UNREACHABLE-ANSWER' } }));
  const report = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)));

  assert.deepEqual(report.sides.CHAMPION.utility, { match: 0, mismatch: 3, unknown: 0 });
  assert.equal(report.sides.CHAMPION.review.recommendation, 'HUMAN_REVIEW_RECOMMENDED');
  assert.ok(report.sides.CHAMPION.review.reasons.includes('UTILITY_MISMATCH_OBSERVED'));
  // Mismatched expectations are an observation, not a failed run and not a promotion input.
  assert.equal(report.status, 'COMPLETE');
  assert.deepEqual(report.promotion, { state: 'UNAVAILABLE', authority: 'NONE', gates: REPLAY_PROMOTION_GATES });

  const unauthorized = [
    { ...spec(cases, strictEvaluator(trusted().pins.champion), strictEvaluator(trusted().pins.challenger)), promote: true },
    { ...spec(cases, strictEvaluator(trusted().pins.champion), strictEvaluator(trusted().pins.challenger)), authorization: 'granted' },
    { trusted: { ...trusted(), pins: { ...trusted().pins, challenger: { ...trusted().pins.challenger, promoted: true } } },
      cases, champion: strictEvaluator(trusted().pins.champion), challenger: strictEvaluator(trusted().pins.challenger) },
  ];
  for (const attempt of unauthorized) {
    const attemptReport = await runChampionReplay(attempt);
    assert.equal(attemptReport.status, 'INVALID');
    assert.ok(attemptReport.reasons.includes('INVALID_SPEC'));
    assert.deepEqual(attemptReport.records, []);
    assert.deepEqual(attemptReport.promotion, { state: 'UNAVAILABLE', authority: 'NONE', gates: REPLAY_PROMOTION_GATES });
  }
  for (const options of [{ deadlineMs: 5, promote: true }, { execution: 'EXTERNAL' }, { signal: {} }, { deadlineMs: 0 },
    { deadlineMs: REPLAY_MAX_DEADLINE_MS + 1 }, { deadlineMs: 1.5 }, 'deadline', []]) {
    const optionReport = await runChampionReplay(
      spec(cases, strictEvaluator(trusted().pins.champion), strictEvaluator(trusted().pins.challenger)), options);
    assert.equal(optionReport.status, 'INVALID', JSON.stringify(options ?? null));
    assert.ok(optionReport.reasons.includes('INVALID_OPTIONS'), JSON.stringify(options ?? null));
    assert.deepEqual(optionReport.records, []);
  }
  // A better-than-champion challenger changes nothing about the external gates.
  const perfect = strictEvaluator(trusted().pins.challenger, { claim: 'MARKER_WITHHELD' });
  const perfectReport = await runChampionReplay(spec(corpus(3, 44), strictEvaluator(trusted().pins.champion), perfect));
  assert.deepEqual(perfectReport.promotion, { state: 'UNAVAILABLE', authority: 'NONE', gates: REPLAY_PROMOTION_GATES });
  assert.equal(perfectReport.productionEligibility.state, 'UNAVAILABLE');
});

test('the compiled module runs no candidate package, hosted transport or dynamic evaluation', async () => {
  const source = readFileSync(resolve(root, 'dist/champion-replay.js'), 'utf8');
  const specifiers = [...source.matchAll(/(?:from|import)\s*'([^']+)'/gu)].map((match) => match[1]);
  assert.deepEqual([...new Set(specifiers)].sort(), ['./canonical-json.js', './evaluation-partitions.js', 'node:crypto']);
  for (const forbidden of ['child_process', 'node:fs', 'node:http', 'node:net', 'node:worker_threads', 'node:vm',
    'eval(', 'new Function(', 'WebSocket', 'fetch(']) {
    assert.ok(!source.includes(forbidden), `compiled module must not reference ${forbidden}`);
  }

  const script = `
    const tripped = (name) => () => { process.stderr.write(name); process.exit(91); };
    globalThis.fetch = tripped('fetch');
    globalThis.WebSocket = tripped('WebSocket');
    const { runChampionReplay, generateSyntheticReplayCorpus } = await import('${root}/dist/champion-replay.js');
    const cases = generateSyntheticReplayCorpus({ version: 1, scope: { tenantId: 'tenant-a.invalid' },
      count: 3, seed: 6 });
    const bundle = { id: 'hylja.detectors', version: '1', digest: 'a'.repeat(64) };
    const permissive = (view) => ({ version: 1, claim: 'MARKER_WITHHELD', emission: view.text });
    const evaluator = { bundle, evaluate: permissive };
    const report = await runChampionReplay({ trusted: { version: 1,
      scope: { tenantId: 'tenant-a.invalid' }, runId: 'r', runKey: new Uint8Array(32).fill(1),
      pins: { champion: bundle, challenger: bundle } },
      cases, champion: evaluator, challenger: evaluator });
    process.stdout.write([report.status, report.sides.CHAMPION.privacy.emitted, report.promotion.state].join('|'));
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(child.status, 0, `a replay must not reach a transport: ${child.stderr}`);
  assert.equal(child.stdout, 'COMPLETE|2|UNAVAILABLE');
});

test('a bounded generated sweep stays explicit, complete and free of case content', async () => {
  const seenMarkers = new Set();
  for (let seed = 1; seed <= 32; seed += 1) {
    const cases = corpus(6, seed);
    const champion = strictEvaluator(trusted().pins.champion);
    const challenger = strictEvaluator(trusted().pins.challenger);
    const report = await runChampionReplay(spec(cases, champion, challenger));
    assert.deepEqual(Object.keys(report).sort(), ['disagreements', 'productionEligibility', 'promotion',
      'reasons', 'records', 'run', 'shadow', 'sides', 'status', 'version']);
    assert.ok(REPLAY_RUN_STATUSES.includes(report.status));
    assert.ok(REPLAY_PRIVACY_OUTCOMES.includes(report.sides.CHAMPION.privacy.withheld === 0 ? 'UNKNOWN' : 'MARKER_WITHHELD'));
    assert.equal(report.sides.CHAMPION.cases.measured, 6);
    assert.equal(report.sides.CHALLENGER.cases.measured, 6);
    assert.equal(report.sides.CHAMPION.privacy.withheld, plantedCount(cases));
    assert.equal(report.sides.CHAMPION.privacy.emitted, 0);
    assert.equal(report.sides.CHAMPION.utility.mismatch, 0);
    assert.equal(report.records.length, 12);
    for (const record of report.records) {
      assert.deepEqual(Object.keys(record).sort(), ['annotation', 'bundle', 'casePseudonym', 'caseRef', 'digest',
        'elapsedMs', 'privacy', 'privacyClaim', 'reasons', 'role', 'runRef', 'scopePseudonym', 'status',
        'utility', 'version']);
      assert.ok(REPLAY_UTILITY_OUTCOMES.includes(record.utility));
      assert.ok(REPLAY_ANNOTATION_STATES.includes(record.annotation));
      assert.ok(record.elapsedMs >= 0 && Number.isSafeInteger(record.elapsedMs));
    }
    const text = serialized(report);
    for (const entry of cases) {
      assert.ok(!text.includes(entry.caseKey));
      const marker = MARKER.exec(entry.text);
      if (marker) { seenMarkers.add(marker[0]); assert.ok(!text.includes(marker[0])); }
    }
  }
  assert.ok(seenMarkers.size >= 32, 'the sweep must exercise distinct planted markers');
});

test('both sides run sequentially in a fixed order under one bounded budget', async () => {
  const cases = corpus(4, 19);
  const champion = strictEvaluator(trusted().pins.champion);
  const challenger = strictEvaluator(trusted().pins.challenger);
  const report = await runChampionReplay(spec(cases, champion, challenger));
  assert.equal(report.status, 'COMPLETE');
  assert.deepEqual(stateOf(champion).calls, ['case-1', 'case-2', 'case-3', 'case-4']);
  assert.deepEqual(stateOf(challenger).calls, ['case-1', 'case-2', 'case-3', 'case-4']);
  assert.equal(stateOf(champion).peak, 1, 'no parallel evaluation harness');
  assert.equal(stateOf(challenger).peak, 1);
  // The evaluator view carries no expectation, no pins, no trust context and no other side.
  const view = stateOf(champion).seen;
  assert.deepEqual(Object.keys(view).sort(), ['caseRef', 'family', 'task', 'text']);
  assert.deepEqual(Object.keys(view.task), ['prompt']);
  assert.equal(view.caseRef, 'case-1');
  assert.ok(Object.isFrozen(view));
  const viewText = JSON.stringify(view);
  for (const label of [SCOPE.tenantId, 'replay-dev-run-1', trusted().pins.champion.digest,
    cases[0].task.expectedAnswer, cases[0].caseKey]) {
    assert.ok(!viewText.includes(label), label);
  }
  const disagreements = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger, { taskAnswer: 'wrong' })));
  assert.equal(disagreements.disagreements.length, 4);
  assert.ok(disagreements.disagreements.length <= REPLAY_MAX_DISAGREEMENTS);
  for (const entry of disagreements.disagreements) {
    assert.equal(entry.field, 'UTILITY');
    assert.equal(entry.champion, 'MATCH');
    assert.equal(entry.challenger, 'MISMATCH');
  }
});

test('an evaluator cannot mutate the harness, its own reported result or the champion record', async () => {
  const cases = corpus(2, 55);
  const attempts = [
    {
      // A strict-mode write to the frozen view throws and is caught here, so the harness-owned
      // case reference and text are intact and the case still measures as an ordinary denial.
      name: 'writes to the frozen view', expected: 'MARKER_WITHHELD',
      evaluate: (view) => {
        try { view.text = 'rewritten'; view.caseRef = 'case-99'; view.task.prompt = 'rewritten'; } catch { /* strict */ }
        return { version: 1, claim: 'MARKER_WITHHELD', emission: view.text.replace(MARKER, '[R]') };
      },
    },
    {
      name: 'returns the view as its own emission', expected: 'UNKNOWN',
      evaluate: (view) => ({ version: 1, claim: 'MARKER_WITHHELD', emission: view }),
    },
    {
      // An empty emission is a legitimate total denial, not a malformed result.
      name: 'extends the shared prototype', expected: 'MARKER_WITHHELD',
      evaluate: (view) => {
        Object.prototype.hyljaReplayMarker = 'injected';
        return { version: 1, claim: 'MARKER_WITHHELD', emission: '' };
      },
      after: () => { delete Object.prototype.hyljaReplayMarker; },
    },
    {
      name: 'mutates a shared prototype member', expected: 'MARKER_EMITTED',
      evaluate: (view) => {
        Object.prototype.hyljaReplayMarker = 'injected';
        return { version: 1, claim: 'MARKER_WITHHELD', emission: view.text };
      },
      after: () => { delete Object.prototype.hyljaReplayMarker; },
    },
  ];
  for (const attempt of attempts) {
    const challenger = { bundle: trusted().pins.challenger, evaluate: attempt.evaluate };
    const champion = strictEvaluator(trusted().pins.champion);
    const report = await runChampionReplay(spec(cases, champion, challenger));
    attempt.after?.();
    for (const record of recordsFor(report, 'CHALLENGER')) {
      assert.ok(REPLAY_CASE_STATUSES.includes(record.status), attempt.name);
      assert.equal(record.role, 'CHALLENGER');
      assert.match(record.caseRef, /^case-[12]$/u, attempt.name);
      assert.equal(record.privacy, attempt.expected, attempt.name);
    }
    // The champion's own observations are computed from its own evaluator and stay untouched.
    assert.deepEqual(report.sides.CHAMPION.privacy, {
      withheld: plantedCount(cases), emitted: 0, notApplicable: cases.length - plantedCount(cases), unknown: 0,
    });
    for (const record of recordsFor(report, 'CHAMPION')) {
      assert.equal(record.role, 'CHAMPION');
      assert.equal(record.status, 'MEASURED');
    }
    assert.deepEqual(report.promotion.gates, REPLAY_PROMOTION_GATES);
  }

  // A result object mutated after the fact cannot change a record that was already measured.
  const mutable = { version: 1, claim: 'MARKER_WITHHELD', emission: '', taskAnswer: 'REPLAY-ANSWER-1-D' + '01' };
  const fixed = { bundle: trusted().pins.challenger, evaluate: () => mutable };
  const before = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion), fixed));
  mutable.claim = 'MARKER_RELEASED';
  mutable.emission = cases[0].text;
  mutable.taskAnswer = 'rewritten';
  const after = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    { bundle: trusted().pins.challenger, evaluate: () => ({ ...mutable }) }));
  // The first run already measured the object as handed over, so the later mutation cannot reach it.
  assert.equal(before.sides.CHALLENGER.privacy.emitted, 0);
  assert.equal(before.sides.CHALLENGER.privacy.withheld, plantedCount(cases));
  // A fresh run over the mutated emission observes exactly the case whose marker it contains.
  assert.equal(after.sides.CHALLENGER.privacy.emitted, 1);
  assert.notEqual(before.records[1].digest, after.records[1].digest);
  assert.equal(before.records[1].privacy, 'MARKER_WITHHELD');
  assert.equal(after.records[1].privacy, 'MARKER_EMITTED');
});

test('Unicode handling and long disagreement lists stay bounded and explicit', async () => {
  const cases = corpus(2, 63);
  const marker = replayMarkerFor(cases[0].caseKey);

  // An astral-plane character is valid UTF-8 and must not break marker verification.
  const astral = [{ ...cases[0], text: `contact ${marker} \u{1F600} plant-synthetic.example.invalid` }, cases[1]];
  const astralReport = await runChampionReplay(spec(astral, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)));
  assert.equal(astralReport.sides.CHAMPION.cases.measured, 2);
  assert.equal(astralReport.sides.CHAMPION.privacy.emitted, 0);

  // A lone surrogate is not a Unicode scalar value: refused in case text and in an emission.
  const lone = [{ ...cases[0], text: `contact ${marker} \uD800 plant-synthetic.example.invalid` }, cases[1]];
  const loneReport = await runChampionReplay(spec(lone, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)));
  assert.deepEqual(loneReport.records.slice(0, 2).map((record) => record.status), ['REJECTED', 'REJECTED']);
  assert.deepEqual(loneReport.records[0].reasons, ['CASE_TEXT_INVALID']);
  const badEmission = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger, { result: { version: 1, claim: 'MARKER_WITHHELD', emission: '\uDFFF' } })));
  assert.equal(badEmission.sides.CHALLENGER.cases.measured, 0);
  assert.ok(badEmission.records.some((entry) => entry.role === 'CHALLENGER'
    && entry.reasons.includes('EVALUATOR_RESULT_MALFORMED')));

  // An empty expectation label is a malformed case, not a utility mismatch.
  const emptyExpectation = [{ ...cases[0], task: { prompt: cases[0].task.prompt, expectedAnswer: '' } }, cases[1]];
  const emptyReport = await runChampionReplay(spec(emptyExpectation, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)));
  assert.deepEqual(emptyReport.records[0].reasons, ['CASE_SPEC_INVALID']);

  // The disagreement list is bounded and says so instead of growing without limit.
  const many = corpus(40, 71);
  const truncated = await runChampionReplay(spec(many, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger, { leak: true, taskAnswer: 'wrong-answer' })));
  assert.equal(truncated.disagreements.length, REPLAY_MAX_DISAGREEMENTS);
  assert.deepEqual(truncated.reasons, ['DISAGREEMENTS_TRUNCATED']);
  assert.equal(truncated.records.length, many.length * 2);
});

// The supervisor review of 44a71aa found that the containment decision went through a mutable
// process-wide intrinsic that an evaluated function can reassign between the two sides, and that a
// throwing listener escaped `discard` before the promise settled. Both are pinned here.
test('a poisoned shared intrinsic cannot falsify the privacy observation', async () => {
  const cases = corpus(9, 3);
  const original = String.prototype.includes;
  const release = (reference) => ({
    bundle: reference,
    evaluate(view) {
      // One assignment rewires the predicate the harness uses to judge this very emission.
      String.prototype.includes = () => false;
      return { version: 1, claim: 'MARKER_WITHHELD', emission: view.text };
    },
  });
  let report;
  try {
    report = await runChampionReplay(spec(cases, release(trusted().pins.champion), release(trusted().pins.challenger)));
  } finally {
    String.prototype.includes = original;
  }
  const released = plantedCount(cases);
  assert.ok(released > 0);
  let measured = 0;
  for (const record of report.records) {
    assert.equal(record.status, 'MEASURED', record.caseRef);
    if (record.privacy === 'MARKER_EMITTED') {
      measured += 1;
      assert.ok(record.reasons.includes('MARKER_EMITTED_OBSERVED'), record.caseRef);
    } else {
      assert.equal(record.privacy, 'NOT_APPLICABLE', record.caseRef);
    }
    // `includes` is no longer part of the observation path, so nothing here is silently wrong.
    assert.ok(!record.reasons.includes('HARNESS_INTRINSIC_TAMPERED'), record.caseRef);
  }
  assert.equal(measured, released * 2);
  assert.equal(report.sides.CHAMPION.privacy.emitted, released);
  assert.equal(report.sides.CHALLENGER.privacy.emitted, released);
  assert.equal(report.sides.CHAMPION.privacy.withheld, 0);
  assert.deepEqual(report.disagreements, []);
  for (const role of REPLAY_ROLES) {
    assert.equal(report.sides[role].privacy.emitted, released, role);
  }

  // Replacing an intrinsic the observation *does* depend on keeps the observation true and is
  // reported explicitly, so a run in a mutated environment is never presented as clean.
  const observed = String.prototype.charCodeAt;
  let tamperedReport;
  try {
    tamperedReport = await runChampionReplay(spec(cases, {
      bundle: trusted().pins.champion,
      evaluate(view) {
        String.prototype.charCodeAt = () => 0;
        return { version: 1, claim: 'MARKER_WITHHELD', emission: view.text };
      },
    }, {
      bundle: trusted().pins.challenger,
      evaluate(view) {
        String.prototype.charCodeAt = () => 0;
        return { version: 1, claim: 'MARKER_WITHHELD', emission: view.text };
      },
    }));
  } finally {
    String.prototype.charCodeAt = observed;
  }
  for (const record of tamperedReport.records) {
    assert.ok(record.reasons.includes('HARNESS_INTRINSIC_TAMPERED'), record.caseRef);
    if (record.privacy === 'MARKER_EMITTED') {
      assert.ok(record.reasons.includes('MARKER_EMITTED_OBSERVED'), record.caseRef);
    } else {
      assert.equal(record.privacy, 'NOT_APPLICABLE', record.caseRef);
    }
    assert.notEqual(record.privacy, 'MARKER_WITHHELD', record.caseRef);
  }
  assert.equal(tamperedReport.sides.CHAMPION.privacy.emitted, released);
  assert.equal(tamperedReport.sides.CHALLENGER.privacy.emitted, released);
  assert.ok(tamperedReport.reasons.includes('HARNESS_INTRINSIC_TAMPERED'));
  for (const role of REPLAY_ROLES) {
    assert.equal(tamperedReport.sides[role].review.recommendation, 'HUMAN_REVIEW_RECOMMENDED', role);
    assert.ok(tamperedReport.sides[role].review.reasons.includes('HARNESS_INTRINSIC_TAMPERED'), role);
  }

  // Cross-side: a challenger that poisons during its own case cannot silence the champion's later
  // releases, and the privacy disagreement between the two sides survives.
  const cross = corpus(4, 5);
  let poisoned = false;
  let crossReport;
  try {
    crossReport = await runChampionReplay(spec(cross,
      strictEvaluator(trusted().pins.champion, { leak: true, claim: 'MARKER_WITHHELD' }),
      { bundle: trusted().pins.challenger, evaluate(view) {
        if (!poisoned) { poisoned = true; String.prototype.includes = () => false; }
        return { version: 1, claim: 'MARKER_WITHHELD', emission: view.text,
          taskAnswer: expectedAnswer(view) };
      } }));
  } finally {
    String.prototype.includes = original;
  }
  assert.equal(crossReport.sides.CHAMPION.privacy.emitted, plantedCount(cross));
  assert.equal(crossReport.sides.CHALLENGER.privacy.emitted, plantedCount(cross));
  // Both sides answer and release identically, so a cross-side poison can neither create nor hide a
  // privacy disagreement.
  assert.deepEqual(crossReport.disagreements, []);
  for (const record of recordsFor(crossReport, 'CHAMPION')) {
    assert.notEqual(record.privacy, 'MARKER_WITHHELD', record.caseRef);
  }

  // Once the intrinsics are restored the harness is clean again: the flag is not sticky state.
  const restored = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)));
  assert.equal(restored.sides.CHAMPION.review.recommendation, 'NO_FINDING_IN_THIS_SUBSET');
  assert.ok(!serialized(restored).includes('HARNESS_INTRINSIC_TAMPERED'));
});

test('planting verification uses the same untamperable predicate as the observation', async () => {
  const cases = corpus(6, 3);
  const original = String.prototype.includes;
  let poisonedReport;
  try {
    String.prototype.includes = () => false;
    poisonedReport = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
      strictEvaluator(trusted().pins.challenger)));
  } finally {
    String.prototype.includes = original;
  }
  // A poisoned prototype predicate must not reject legitimately planted development cases.
  assert.equal(poisonedReport.sides.CHAMPION.cases.rejected, 0);
  assert.equal(poisonedReport.sides.CHAMPION.cases.measured, cases.length);
  assert.equal(poisonedReport.sides.CHAMPION.privacy.withheld, plantedCount(cases));

  // The harness still refuses a DENY case whose marker is not really there.
  const unplanted = [{ ...cases[0], text: 'this synthetic sentence contains no planted marker' },
    ...cases.slice(1)];
  const unplantedReport = await runChampionReplay(spec(unplanted, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)));
  assert.equal(unplantedReport.records[0].status, 'REJECTED');
  assert.deepEqual(unplantedReport.records[0].reasons, ['CASE_MARKER_EXPECTATION_MISMATCH']);
  // ... and a NONE case that really contains its derived marker is a fixture defect, not a licence
  // to skip the privacy observation.
  const control = cases.find((entry) => entry.marker.expectation === 'NONE');
  assert.ok(control);
  const relabelled = [{ ...control, text: `note ${replayMarkerFor(control.caseKey)} plant-synthetic.example.invalid` },
    ...cases.filter((entry) => entry !== control)];
  const relabelledReport = await runChampionReplay(spec(relabelled, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)));
  assert.equal(relabelledReport.records[0].status, 'REJECTED');
  assert.deepEqual(relabelledReport.records[0].reasons, ['CASE_MARKER_EXPECTATION_MISMATCH']);
  const leaking = await runChampionReplay(spec(relabelled, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger, { leak: true, claim: 'MARKER_WITHHELD' })));
  assert.equal(leaking.sides.CHALLENGER.cases.rejected, 1);
  assert.equal(leaking.records[1].status, 'REJECTED');
  assert.equal(leaking.records[1].privacy, 'UNKNOWN');
  assert.equal(leaking.sides.CHALLENGER.privacy.unknown, 1);
});

test('a hostile cancellation signal resolves explicitly and never escapes the run', async () => {
  const cases = corpus(3, 9);
  const slow = (reference) => ({
    bundle: reference,
    evaluate: (view) => new Promise((resolve) => {
      setTimeout(() => resolve({ version: 1, claim: 'MARKER_WITHHELD', emission: view.text }), 200).unref?.();
    }),
  });
  const attempts = [
    {
      name: 'a throwing removeEventListener',
      signal: { aborted: false, addEventListener() {}, removeEventListener() { throw new Error(`planted ${cases[0].text}`); } },
    },
    {
      name: 'a throwing addEventListener',
      signal: { aborted: false, addEventListener() { throw new Error('planted-add'); }, removeEventListener() {} },
    },
  ];
  for (const attempt of attempts) {
    const raced = await Promise.race([
      runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion), slow(trusted().pins.challenger)),
        { signal: attempt.signal, deadlineMs: 20 }),
      new Promise((resolve) => { setTimeout(() => resolve('UNSETTLED'), 2000).unref?.(); }),
    ]);
    assert.notEqual(raced, 'UNSETTLED', `${attempt.name} must still settle`);
    assert.notEqual(raced.status, 'INVALID', `${attempt.name} is not an invalid request`);
    assert.equal(raced.sides.CHAMPION.cases.measured, cases.length, attempt.name);
    assert.equal(raced.sides.CHALLENGER.cases.unknown, cases.length, attempt.name);
    for (const record of recordsFor(raced, 'CHALLENGER')) {
      assert.deepEqual(record.reasons, ['DEADLINE_EXCEEDED'], attempt.name);
    }
    assert.ok(!serialized(raced).includes('planted'), attempt.name);
  }

  // A signal that passes validation and then throws when it is interrogated is treated as aborted:
  // the direction that refuses to measure, never the one that records a clean result.
  let reads = 0;
  const flipping = {
    get aborted() {
      reads += 1;
      if (reads === 1) return false;
      throw new Error(`planted ${cases[2].text}`);
    },
    addEventListener() {},
    removeEventListener() {},
  };
  const flipReport = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)), { signal: flipping });
  assert.notEqual(flipReport.status, 'INVALID');
  assert.equal(flipReport.sides.CHAMPION.cases.measured, 0);
  for (const record of flipReport.records) {
    assert.equal(record.status, 'UNKNOWN', record.caseRef);
    assert.deepEqual(record.reasons, ['CANCELLED'], record.caseRef);
  }
  assert.ok(!serialized(flipReport).includes('planted'));

  // A signal-shaped object that throws while being interrogated is a refused option, not a run.
  const throwing = { get aborted() { throw new Error(`planted ${cases[1].text}`); },
    addEventListener() {}, removeEventListener() {} };
  const refused = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)), { signal: throwing });
  assert.equal(refused.status, 'INVALID');
  assert.deepEqual(refused.reasons, ['INVALID_OPTIONS']);
  assert.deepEqual(refused.records, []);
  assert.ok(!serialized(refused).includes('planted'));

  // A settlement-only child process: a hostile signal must not hang it or leave an unhandled
  // rejection behind, and it must exit 0.
  const script = `
    process.on('unhandledRejection', () => { process.stdout.write('UNHANDLED'); });
    const { runChampionReplay, generateSyntheticReplayCorpus } = await import('${root}/dist/champion-replay.js');
    const bundle = { id: 'hylja.detectors', version: '1', digest: '${'b'.repeat(64)}' };
    const cases = generateSyntheticReplayCorpus({ version: 1,
      scope: { tenantId: 'tenant-a.invalid' }, count: 2, seed: 9 });
    const slow = { bundle, evaluate: (view) => new Promise((resolve) => {
      setTimeout(() => resolve({ version: 1, claim: 'MARKER_WITHHELD', emission: view.text }), 400); }) };
    const raced = await Promise.race([
      runChampionReplay({ trusted: { version: 1, scope: { tenantId: 'tenant-a.invalid' }, runId: 'r',
        runKey: new Uint8Array(32).fill(2), pins: { champion: bundle, challenger: bundle } },
      cases, champion: slow, challenger: slow },
      { deadlineMs: 20, signal: { aborted: false, addEventListener() {},
        removeEventListener() { throw new Error('boom-remove'); } } }),
      new Promise((resolve) => setTimeout(() => resolve('UNSETTLED'), 2000))]);
    process.stdout.write(raced === 'UNSETTLED' ? 'UNSETTLED'
      : raced.status + ':' + raced.sides.CHALLENGER.cases.unknown);
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' });
  assert.equal(child.status, 0, `a hostile signal must not exit the process: ${child.stderr}`);
  assert.equal(child.stdout, 'PARTIAL:2');
});

test('case and evidence bindings are verified rather than labelled', async () => {
  const cases = corpus(3, 91);
  const champion = strictEvaluator(trusted().pins.champion);
  const challenger = strictEvaluator(trusted().pins.challenger);

  // The first occurrence of a case key reserves it whatever its own validity turns out to be.
  const unplantedFirst = [{ ...cases[0], text: 'this synthetic sentence contains no planted marker' }, cases[0]];
  const duplicateReport = await runChampionReplay(spec(unplantedFirst, champion, challenger));
  // Records are one per case and side, so the second case is records[2] and records[3].
  assert.deepEqual(duplicateReport.records.slice(0, 4).map((record) => record.status),
    ['REJECTED', 'REJECTED', 'REJECTED', 'REJECTED']);
  assert.deepEqual(duplicateReport.records[0].reasons, ['CASE_MARKER_EXPECTATION_MISMATCH']);
  assert.deepEqual(duplicateReport.records[2].reasons, ['CASE_KEY_DUPLICATE']);

  // Annotation evidence with no usable case key never attaches to a case that has none.
  const unattached = await runChampionReplay(spec([unplantedFirst[0]], champion, challenger, {
    annotations: [
      { version: 1, caseKey: '', verdict: 'DISAGREED', source: 'PROPOSED' },
      { version: 1, caseKey: 'dev-not-a-case', verdict: 'UNRESOLVED', source: 'MANUAL' },
    ],
  }));
  assert.equal(unattached.run.annotations.provided, 2);
  assert.equal(unattached.run.annotations.rejected, 2);
  assert.equal(unattached.run.annotations.disagreed, 0);
  assert.equal(unattached.run.annotations.unresolved, 0);
  for (const record of unattached.records) {
    assert.equal(record.annotation, 'NONE', record.caseRef);
    assert.ok(!record.reasons.some((reason) => reason.startsWith('ANNOTATION_')), record.caseRef);
  }

  // A resolvable label is attached to its own case only.
  const resolved = await runChampionReplay(spec(cases, champion, challenger, {
    annotations: [
      { version: 1, caseKey: cases[0].caseKey, verdict: 'UNRESOLVED', source: 'MANUAL' },
      { version: 1, caseKey: cases[1].caseKey, verdict: 'DISAGREED', source: 'PROPOSED' },
    ],
  }));
  assert.deepEqual(recordsFor(resolved, 'CHAMPION').map((record) => record.annotation),
    ['UNRESOLVED', 'DISAGREED', 'NONE']);
  assert.ok(recordsFor(resolved, 'CHAMPION')[0].reasons.includes('ANNOTATION_UNRESOLVED'));
  assert.equal(resolved.run.annotations.unresolved, 1);
  assert.equal(resolved.run.annotations.disagreed, 1);
  assert.equal(resolved.sides.CHAMPION.cases.measured, 3);
});

test('every report shape is valid and the report cannot be edited in place', async () => {
  const cases = corpus(3, 95);
  const measured = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)));
  const invalid = await runChampionReplay({ ...spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger)), promote: true });
  assert.equal(measured.status, 'COMPLETE');
  assert.equal(invalid.status, 'INVALID');

  for (const report of [measured, invalid]) {
    // A strict consumer needs no special case for the invalid report: every reference is shaped.
    assert.match(report.run.runRef, /^[0-9a-f]{32}$/u);
    assert.match(report.run.corpusRef, /^[0-9a-f]{32}$/u);
    assert.match(report.run.scopePseudonym.tenant, /^[0-9a-f]{32}$/u);
    for (const role of REPLAY_ROLES) {
      const side = report.sides[role];
      assert.ok(side.bundle.id.length > 0, role);
      assert.ok(side.bundle.version.length > 0, role);
      assert.match(side.bundle.digest, /^[0-9a-f]{64}$/u, role);
    }
    for (const record of report.records) {
      assert.match(record.digest, /^[0-9a-f]{64}$/u);
      assert.match(record.bundle.digest, /^[0-9a-f]{64}$/u);
      assert.match(record.casePseudonym, /^[0-9a-f]{32}$/u);
      assert.match(record.runRef, /^[0-9a-f]{32}$/u);
    }
    assert.ok(Object.isFrozen(report), 'a report is immutable');
    assert.ok(Object.isFrozen(report.records));
    assert.ok(Object.isFrozen(report.disagreements));
    assert.ok(Object.isFrozen(report.run));
    for (const role of REPLAY_ROLES) {
      assert.ok(Object.isFrozen(report.sides[role]), role);
      assert.ok(Object.isFrozen(report.sides[role].privacy), role);
      assert.ok(Object.isFrozen(report.sides[role].review), role);
      assert.ok(Object.isFrozen(report.sides[role].bundle), role);
    }
    for (const record of report.records) {
      assert.ok(Object.isFrozen(record), record.caseRef);
      assert.ok(Object.isFrozen(record.reasons), record.caseRef);
      assert.ok(Object.isFrozen(record.bundle), record.caseRef);
      assert.ok(Object.isFrozen(record.scopePseudonym), record.caseRef);
    }
  }
  assert.throws(() => { measured.status = 'INVALID'; }, TypeError);
  assert.throws(() => { measured.records[0].privacy = 'MARKER_WITHHELD'; }, TypeError);
  assert.throws(() => { measured.sides.CHAMPION.privacy.emitted = 0; }, TypeError);
  assert.equal(measured.sides.CHAMPION.privacy.emitted, 0);
});

test('the deadline bounds waiting for an async answer and latency is measured, not clamped', async () => {
  const cases = corpus(1, 97);
  let spins = 0;
  const spin = (reference) => ({
    bundle: reference,
    evaluate(view) {
      // Synchronous work: no deadline can interrupt it, so the recorded latency is the truth.
      let ticks = 0;
      const until = Date.now() + 40;
      while (Date.now() < until) ticks += 1;
      spins += ticks;
      return { version: 1, claim: /SYNTHETIC-MARKER-[0-9a-f]{16}/u.test(view.text) ? 'MARKER_WITHHELD' : 'NO_MARKER_PRESENT',
        emission: view.text.replace(/SYNTHETIC-MARKER-[0-9a-f]{16}/u, '[REDACTED-SYNTHETIC]') };
    },
  });
  const report = await runChampionReplay(spec(cases, spin(trusted().pins.champion), spin(trusted().pins.challenger)),
    { deadlineMs: 1 });
  assert.ok(spins > 0);
  for (const record of report.records) {
    assert.equal(record.status, 'MEASURED', record.caseRef);
    assert.deepEqual(record.reasons, []);
    // The measurement is the harness's own elapsed time, not a clamp to the 1 ms deadline.
    assert.ok(record.elapsedMs > 1, `${record.caseRef}: ${record.elapsedMs}`);
  }
  for (const role of REPLAY_ROLES) assert.equal(report.sides[role].errors, 0, role);
  assert.equal(report.status, 'COMPLETE');
});

// The supervisor review of d37c142 found that the report freeze silently truncated at the documented
// maximum corpus size, and that two prototype methods the module calls (`Array.prototype.includes`
// and `RegExp.prototype.test`) were neither captured nor observed: poisoning either one turned a
// refusal into a silent acceptance. Both are pinned here at documented-size inputs.
test('the report freeze covers every record at the documented maximum corpus size', async () => {
  const cases = corpus(REPLAY_MAX_CASES, 5);
  assert.equal(cases.length, REPLAY_MAX_CASES);
  const report = await runChampionReplay(spec(cases, strictEvaluator(trusted().pins.champion),
    strictEvaluator(trusted().pins.challenger, { leak: true, claim: 'MARKER_WITHHELD' })));
  assert.equal(report.records.length, REPLAY_MAX_CASES * 2);
  for (const [index, record] of report.records.entries()) {
    assert.ok(Object.isFrozen(record), `record ${index}`);
    assert.ok(Object.isFrozen(record.reasons), `record ${index} reasons`);
    assert.ok(Object.isFrozen(record.bundle), `record ${index} bundle`);
    assert.ok(Object.isFrozen(record.scopePseudonym), `record ${index} scope`);
  }
  for (const key of ['records', 'disagreements', 'reasons', 'run', 'shadow', 'promotion',
    'productionEligibility', 'sides']) {
    assert.ok(Object.isFrozen(report[key]), key);
  }
  for (const role of REPLAY_ROLES) {
    for (const key of ['cases', 'privacy', 'utility', 'latencyMs', 'cost', 'review', 'bundle']) {
      assert.ok(Object.isFrozen(report.sides[role][key]), `${role}.${key}`);
    }
  }
  assert.ok(Object.isFrozen(report.run.scopePseudonym));
  // No record of a maximum-size report is editable, and no run reason can be appended.
  assert.throws(() => { report.records[REPLAY_MAX_CASES * 2 - 1].privacy = 'MARKER_WITHHELD'; }, TypeError);
  assert.throws(() => { report.records[0].status = 'COMPLETE'; }, TypeError);
  assert.throws(() => report.reasons.push('DISAGREEMENTS_TRUNCATED'), TypeError);
  assert.throws(() => { report.sides.CHALLENGER.review.recommendation = 'NO_FINDING_IN_THIS_SUBSET'; }, TypeError);
  assert.equal(report.sides.CHALLENGER.privacy.emitted, plantedCount(cases));
});

test('a poisoned lookup or pattern intrinsic cannot turn a refusal into a silent acceptance', async () => {
  const cases = corpus(4, 15);
  const strict = strictEvaluator(trusted().pins.champion);
  const permissive = strictEvaluator(trusted().pins.challenger);

  // Unknown keys are refusals, not defaults: an authorization or promote flag on a result or spec
  // is rejected whether or not the shared membership check is intact.
  const flaggedResult = { bundle: trusted().pins.challenger, evaluate: (view) => ({
    version: 1, claim: 'MARKER_WITHHELD', emission: view.text, authorization: 'granted', promote: true }) };
  const flaggedSpec = { ...spec(cases, strict, strictEvaluator(trusted().pins.challenger)),
    promote: true, authorization: 'granted' };
  const cleanResult = await runChampionReplay(spec(cases, strict, flaggedResult));
  assert.equal(cleanResult.sides.CHALLENGER.cases.measured, 0);
  assert.ok(cleanResult.records.some((entry) => entry.role === 'CHALLENGER'
    && entry.reasons.includes('EVALUATOR_RESULT_MALFORMED')));
  const cleanSpec = await runChampionReplay(flaggedSpec);
  assert.equal(cleanSpec.status, 'INVALID');
  assert.deepEqual(cleanSpec.reasons, ['INVALID_SPEC']);

  // The opaque-token and digest shapes are refusals too.
  const malformedBundle = { id: 'not a valid token', version: 'v1', digest: 'nope' };
  const cleanBundle = await runChampionReplay(spec(cases,
    { bundle: malformedBundle, evaluate: permissive.evaluate }, permissive));
  assert.equal(cleanBundle.status, 'INVALID');
  assert.deepEqual(cleanBundle.reasons, ['BUNDLE_REFERENCE_INVALID']);

  // A membership check that always matches must not admit an unknown result key or spec key.
  {
    const original = Array.prototype.includes;
    let resultReport;
    let specReport;
    try {
      Array.prototype.includes = () => true;
      resultReport = await runChampionReplay(spec(cases, strict, flaggedResult));
      specReport = await runChampionReplay(flaggedSpec);
    } finally {
      Array.prototype.includes = original;
    }
    assert.equal(resultReport.sides.CHALLENGER.cases.measured, 0);
    assert.ok(resultReport.records.some((entry) => entry.role === 'CHALLENGER'
      && entry.reasons.includes('EVALUATOR_RESULT_MALFORMED')));
    assert.equal(specReport.status, 'INVALID');
    assert.ok(specReport.reasons.includes('INVALID_SPEC'));
    assert.ok(specReport.reasons.includes('HARNESS_INTRINSIC_TAMPERED'));
    assert.ok(!specReport.reasons.includes('RUN_BUDGET_EXCEEDED'));
    assert.ok(!resultReport.reasons.includes('RUN_BUDGET_EXCEEDED'));
  }

  // A pattern test that always matches must not admit an opaque token or a malformed digest, and
  // no non-token text may reach a record's bundle reference.
  {
    const original = RegExp.prototype.test;
    let bundleReport;
    let measuredReport;
    try {
      RegExp.prototype.test = () => true;
      bundleReport = await runChampionReplay(spec(cases,
        { bundle: malformedBundle, evaluate: permissive.evaluate }, permissive));
      measuredReport = await runChampionReplay(spec(cases, strict, permissive));
    } finally {
      RegExp.prototype.test = original;
    }
    // The shape checks no longer call a pattern implementation at all, so replacing one is inert:
    // the refusal holds and nothing is reported as tampered, because nothing this module uses changed.
    assert.equal(bundleReport.status, 'INVALID');
    assert.ok(bundleReport.reasons.includes('BUNDLE_REFERENCE_INVALID'));
    assert.ok(!bundleReport.reasons.includes('HARNESS_INTRINSIC_TAMPERED'));
    assert.deepEqual(bundleReport.records, []);
    // A valid run in the same environment still measures every case and fabricates nothing.
    assert.equal(measuredReport.sides.CHAMPION.cases.measured, cases.length);
    assert.equal(measuredReport.sides.CHALLENGER.cases.measured, cases.length);
    assert.ok(!measuredReport.reasons.includes('HARNESS_INTRINSIC_TAMPERED'));
    assert.ok(!measuredReport.reasons.includes('RUN_BUDGET_EXCEEDED'));
    assert.ok(!serialized(measuredReport).includes('not a valid token'));
  }

  // A run-level reason is a claim about this run only: it cannot be pushed after the fact either.
  const clean = await runChampionReplay(spec(cases, strict, permissive));
  assert.deepEqual(clean.reasons, []);
  assert.throws(() => clean.reasons.push('EVALUATOR_ERROR'), TypeError);

  // An intrinsic this module does still call, poisoned before the run, is reported on the run itself:
  // a short run cannot end with an empty reason list in an environment it never verified.
  const pristineUnits = String.prototype.charCodeAt;
  String.prototype.charCodeAt = () => 0;
  let preRun;
  try {
    preRun = await runChampionReplay(spec(corpus(1, 15), strict, permissive));
  } finally {
    String.prototype.charCodeAt = pristineUnits;
  }
  assert.ok(preRun.reasons.includes('HARNESS_INTRINSIC_TAMPERED'));
  assert.ok(preRun.records.every((entry) => entry.reasons.includes('HARNESS_INTRINSIC_TAMPERED')));
});

// The supervisor review of f899551 found that Promise.resolve was called live and so was outside the
// captured set: replacing it handed `bounded` a non-thenable value, its executor threw before the
// deadline timer was cleared, and the surviving timer callback threw an uncaught exception in the
// caller's process about a second after the report had already returned. It also found one more live
// call site (the corpus reference) and a dropped string coercion in the marker helper.
test('a replaced promise constructor leaves no armed timer and no uncaught exception behind', async () => {
  // A replaced Array.prototype.map must not forge the corpus reference either, and the tampering is
  // reported. This runs in process: no timer is involved.
  const cases = corpus(3, 5);
  const champion = strictEvaluator(trusted().pins.champion);
  const challenger = strictEvaluator(trusted().pins.challenger);
  const clean = await runChampionReplay(spec(cases, champion, challenger));
  assert.deepEqual(clean.reasons, []);
  const nativeMap = Array.prototype.map;
  let mapped;
  try {
    Array.prototype.map = () => ['forged'];
    mapped = await runChampionReplay(spec(cases,
      strictEvaluator(trusted().pins.champion), strictEvaluator(trusted().pins.challenger)));
  } finally {
    Array.prototype.map = nativeMap;
  }
  assert.equal(mapped.run.corpusRef, clean.run.corpusRef, 'the corpus reference cannot be forged');
  assert.ok(mapped.reasons.includes('HARNESS_INTRINSIC_TAMPERED'));
  assert.equal(mapped.status, 'COMPLETE');
  assert.equal(mapped.sides.CHAMPION.cases.measured, cases.length);

  // The marker helper coerces its argument rather than throwing a TypeError from node:crypto.
  assert.equal(replayMarkerFor(12345), replayMarkerFor('12345'));

  // The promise-constructor case runs in a child process: the failure mode is an uncaught exception
  // in the host process, so it can only be asserted where such an exception is visible as an exit
  // code. The child waits past the armed deadline before reporting.
  const script = `
    import { runChampionReplay, generateSyntheticReplayCorpus } from '${root}/dist/champion-replay.js';
    const bundle = { id: 'hylja.detectors', version: '1', digest: '${'c'.repeat(64)}' };
    const cases = generateSyntheticReplayCorpus({ version: 1,
      scope: { tenantId: 'tenant-a.invalid' }, count: 2, seed: 4 });
    const strict = { bundle, evaluate: (view) => ({ version: 1,
      claim: /SYNTHETIC-MARKER-[0-9a-f]{16}/u.test(view.text) ? 'MARKER_WITHHELD' : 'NO_MARKER_PRESENT',
      emission: view.text.replace(/SYNTHETIC-MARKER-[0-9a-f]{16}/u, '[REDACTED]') }) };
    Promise.resolve = (value) => value;
    const report = await runChampionReplay({ trusted: { version: 1, scope: { tenantId: 'tenant-a.invalid' },
      runId: 'r', runKey: new Uint8Array(32).fill(9), pins: { champion: bundle, challenger: bundle } },
      cases, champion: strict, challenger: strict }, { deadlineMs: 50 });
    process.stdout.write('report:' + report.status + ':' + report.sides.CHAMPION.cases.measured + ':'
      + JSON.stringify(report.reasons) + ':' +
      JSON.stringify(report.records.map((entry) => entry.reasons)) + '\\n');
    await new Promise((resolve) => setTimeout(resolve, 400));
    process.stdout.write('SURVIVED');
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 20000 });
  assert.equal(child.status, 0, `a replaced promise constructor must not end the process: ${child.stderr}`);
  const [reportLine, tail] = child.stdout.split('\n');
  assert.equal(tail, 'SURVIVED', 'no uncaught exception may follow the returned report');
  const [, status, measured, reasons, recordReasons] = /report:([^:]*):([^:]*):(.*):(.*)/.exec(reportLine) ?? [];
  // The constructor this module uses is the captured one, so replacing the global changes no
  // measured outcome; the tampering is still reported on the run and on every record.
  assert.equal(status, 'COMPLETE', reportLine);
  assert.equal(measured, '2', reportLine); // two cases on the champion side of a two-case corpus
  assert.ok(reasons.includes('HARNESS_INTRINSIC_TAMPERED'), reportLine);
  assert.ok(recordReasons.includes('HARNESS_INTRINSIC_TAMPERED'), reportLine);
  assert.ok(!child.stderr.includes('is not a function'), child.stderr);
});

// The supervisor review of 8a846e5 found that the "mutated before load" limit I documented was
// stated in the permissive direction: a prototype mutated before this module is imported is invisible
// to identity comparison, and an always-true Array.prototype.includes silently emptied every reason
// list and rejected every case as a duplicate with its code dropped, while an always-true
// RegExp.prototype.test silently accepted a malformed bundle reference into the report. Each of those
// needs its own process, because the poison has to be in place before the module is imported, so they
// run as children that report through JSON.stringify so the poisoned prototype cannot lie to them.
const preloadChild = (poison, body) => {
  // The authoring helper and the comparison both refuse in an untrusted realm, so the child reports
  // whichever refusal happened instead of letting the exception end the process.
  const script = `
    ${poison}
    const mod = await import('${root}/dist/champion-replay.js');
    const scope = { tenantId: 'tenant-a.invalid', projectId: 'project-a.invalid' };
    const digest = '${'e'.repeat(64)}';
    const pins = { champion: { id: 'h', version: '1', digest }, challenger: { id: 'h', version: '2', digest } };
    const strict = (bundle) => ({ bundle, evaluate: (view) => ({ version: 1,
      claim: /SYNTHETIC-MARKER-[0-9a-f]{16}/u.test(view.text) ? 'MARKER_WITHHELD' : 'NO_MARKER_PRESENT',
      emission: view.text.replace(/SYNTHETIC-MARKER-[0-9a-f]{16}/u, '[REDACTED]'),
      taskAnswer: 'REPLAY-ANSWER-' + view.caseRef.slice(5) + '-' + view.family }) });
    try {
      const cases = mod.generateSyntheticReplayCorpus({ version: 1, scope, count: 2, seed: 4 });
      ${body}
    } catch (error) {
      const refused = await mod.runChampionReplay(null);
      process.stdout.write(JSON.stringify({ authoringRefusal: String(error && error.code),
        status: refused.status, reasons: refused.reasons, records: [],
        championReview: refused.sides.CHAMPION.review.reasons }));
    }
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script],
    { encoding: 'utf8', timeout: 20000 });
  return { child, output: (child.stdout || '').trim() };
};

const cleanPreloadBody = `
  const report = await mod.runChampionReplay({ trusted: { version: 1, scope, runId: 'r',
    runKey: new Uint8Array(32).fill(3), pins }, cases,
    champion: strict(pins.champion), challenger: strict(pins.challenger) });
  process.stdout.write(JSON.stringify({ status: report.status, reasons: report.reasons,
    records: report.records.map((entry) => ({ status: entry.status, privacy: entry.privacy,
      reasons: entry.reasons })),
    championReview: report.sides.CHAMPION.review.reasons }));
`;

const bundlePreloadBody = `
  const malformed = { id: 'not a valid token', version: 'v1', digest: 'nope' };
  const report = await mod.runChampionReplay({ trusted: { version: 1, scope, runId: 'r',
    runKey: new Uint8Array(32).fill(3), pins }, cases,
    champion: strict(malformed), challenger: strict(pins.challenger) });
  process.stdout.write(JSON.stringify({ status: report.status, reasons: report.reasons,
    pinState: report.sides.CHAMPION.pinState,
    recordBundle: report.records.length ? report.records[0].bundle : null }));
`;

test('a realm whose primitives fail the load-time self-test is refused explicitly', () => {
  // An untruthful membership check must never empty a reason list or reject every case as a
  // duplicate: a realm that cannot answer a known answer gets an explicit refusal instead.
  const attempts = [
    { name: 'Array.prototype.includes', poison: 'Array.prototype.includes = () => true;' },
    { name: 'Array.prototype.push', poison: 'Array.prototype.push = () => 0;' },
    { name: 'String.prototype.charCodeAt', poison: 'String.prototype.charCodeAt = () => 0;' },
    { name: 'Array.prototype.sort', poison: 'Array.prototype.sort = () => {};' },
  ];
  for (const attempt of attempts) {
    const { child, output } = preloadChild(attempt.poison, cleanPreloadBody);
    assert.equal(child.status, 0, `${attempt.name}: ${child.stderr}`);
    const parsed = JSON.parse(output);
    // An explicit refusal, from the authoring helper or from the comparison, and never a report.
    // Both entry points refuse: the authoring helper by its typed error, the comparison by an
    // explicit INVALID report carrying the same code.
    assert.equal(parsed.authoringRefusal, 'HARNESS_REALM_UNTRUSTED', `${attempt.name}: ${output}`);
    assert.equal(parsed.status, 'INVALID', `${attempt.name}: ${output}`);
    assert.deepEqual(parsed.reasons, ['HARNESS_REALM_UNTRUSTED'], `${attempt.name}: ${output}`);
    assert.deepEqual(parsed.records, [], attempt.name);
    assert.ok(parsed.reasons.every((code) => code === 'HARNESS_REALM_UNTRUSTED'), attempt.name);
    assert.ok(!parsed.championReview || parsed.championReview.length === 0, attempt.name);
  }

  // The opaque-token and digest shapes no longer depend on a mutable pattern implementation, so an
  // always-true RegExp.prototype.test cannot admit a malformed bundle reference into a report.
  const pattern = preloadChild('RegExp.prototype.test = () => true;', bundlePreloadBody);
  assert.equal(pattern.child.status, 0, pattern.child.stderr);
  const parsedPattern = JSON.parse(pattern.output);
  // Either an untrusted-realm refusal, or the refusal of the malformed bundle with no trace of the
  // non-token label: never an acceptance.
  assert.ok(parsedPattern.authoringRefusal === 'HARNESS_REALM_UNTRUSTED' ||
    parsedPattern.status === 'INVALID', pattern.output);
  if (parsedPattern.status === 'INVALID') {
    assert.ok(parsedPattern.reasons.includes('BUNDLE_REFERENCE_INVALID'), pattern.output);
  }
  assert.equal(parsedPattern.recordBundle, null, pattern.output);
  assert.ok(!pattern.output.includes('not a valid token'), pattern.output);

  // Control: an unmodified realm still measures, still refuses a malformed bundle, and keeps its
  // reason vocabulary intact.
  const control = preloadChild('', cleanPreloadBody);
  assert.equal(control.child.status, 0, control.child.stderr);
  const parsedControl = JSON.parse(control.output);
  assert.equal(parsedControl.authoringRefusal, undefined, control.output);
  assert.equal(parsedControl.status, 'COMPLETE', control.output);
  assert.deepEqual(parsedControl.reasons, []);
  assert.ok(parsedControl.records.every((entry) => entry.status === 'MEASURED'));
  const controlBundle = preloadChild('', bundlePreloadBody);
  assert.equal(JSON.parse(controlBundle.output).status, 'INVALID', controlBundle.output);
  assert.ok(JSON.parse(controlBundle.output).reasons.includes('BUNDLE_REFERENCE_INVALID'));
});
