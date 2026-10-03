// Deterministic evidence for the #40 matched public-development comparison. Every group drives the
// same bridge the real run uses, with the generated stdlib-only fake worker instead of the screened
// stack, so the arm wiring, the control planting, the per-control breakdown, the union property, the
// unmatched-event classification, the pre-execution screen verification, the failure paths and the
// record's privacy properties are all exercised without installing, importing or executing any
// third-party candidate.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  MATCHED_ARMS, MATCHED_COMPARISON_VERSION, MATCHED_PRIVACY_FILTER_ARM, assertNoSilentControlDrop,
  assertOwnerAgreement, classifyUnmatched, combineArms, loadOracleNegatives, plantDevelopmentControl,
  runMatchedDevelopmentComparison, runNativeArm, scoreArm, verifySelectedRuntime,
} from '../evaluations/matched-development-comparison.mjs';
import { generateContactCandidates } from '../dist/contact-candidates.js';
import { readFileSync } from 'node:fs';

const VERIFIER = new URL('../evaluations/presidio-worker/verify_selected_runtime.py', import.meta.url).pathname;
const WORKER = new URL('../test/fixtures/presidio-fake-worker/fake_worker.py', import.meta.url).pathname;
const SCRIPT = new URL('../evaluations/matched-development-comparison.mjs', import.meta.url).pathname;
const PYTHON = process.env.HYLJA_TEST_PYTHON ?? 'python3';
const skip = spawnSync(PYTHON, ['-c', 'import sys'], { timeout: 20_000 }).status === 0
  ? false : 'no usable python3 interpreter for the matched comparison test';
let workspace;
process.on('exit', () => { if (workspace) rmSync(workspace, { recursive: true, force: true }); });

/** One file plays both roles, exactly as in the real run: the pin the bridge reads and the worker's control. */
function manifest(overrides = {}) {
  if (!workspace) workspace = mkdtempSync(join(tmpdir(), 'hylja-matched-comparison-'));
  const path = join(workspace, `manifest-${Math.random().toString(16).slice(2)}.json`);
  writeFileSync(path, JSON.stringify({ protocol: 'hylja.presidio.worker', version: 1,
    runtimeVersion: 'fake0', language: 'en',
    configuration: { language: 'en', nlpEngine: { nerAvailable: false },
      filtering: { requestScoreThreshold: null, deduplicate: true, decisionProcess: false,
        context: 'UNAVAILABLE_NO_NLP' } },
    artifacts: [{ name: 'presidio_analyzer', version: 'fake0' }], ...overrides }), 'utf8');
  return path;
}
const command = () => ({ pythonPath: PYTHON, workerScript: WORKER, startupTimeoutMs: 30_000,
  executionTimeoutMs: 30_000, cwd: workspace ?? tmpdir() });
const scope = { tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01',
  expectedProducerVersion: 'fake0', expectedLanguage: 'en', expectedNerAvailable: false };
const compare = (control = {}, extra = {}) => runMatchedDevelopmentComparison({ command: command(),
  caseIds: ['D01-DEV-001', 'D02-DEV-001'], manifest: manifest(control), workdir: workspace, scope,
  ...extra });

const PLANTED = ['Demo Person Alpha', 'person.alpha@example.invalid', '+1 202-555-0101',
  'person.beta@example.invalid', 'Demo Person Beta', 'Customer Demo-North', 'PROJECT-DEMO-01',
  '192.0.2.17', 'diag-node.example.invalid', '8443', 'https://diag-node.example.invalid:443/health',
  'DEMO-NONLIVE-TOKEN-NOT-VALID', 'demo.operator', 'TRACE-DEMO-02', 'service.demo.invalid',
  'Customer Demo-West', 'primary on-call', 'approved internal channel', 'ProxyDial.demo'];
function assertNoPlantedValue(record, label) {
  const serialized = JSON.stringify(record);
  for (const planted of PLANTED) {
    assert.equal(serialized.includes(planted), false, `${label} must not carry ${planted}`);
  }
}
const armOf = (record, caseId, arm) => record.cases.find((item) => item.caseId === caseId).arms[arm];
const controlOf = (entry, controlRef) => entry.controls.find((item) => item.controlRef === controlRef);
const sum = (values) => values.reduce((total, value) => total + value, 0);

/** A complete, passing executed-subset check set plus the pin check, for the synthetic shims. */
function executedChecks(overrides = {}) {
  const base = { PINNED_DIGESTS_PRESENT: { pinnedRecords: 2, digestsPresent: 2 },
    SELECTED_ARTIFACTS_NAME_AND_SCREEN_VERIFIED: { selected: 2, selectedWithScreenRecord: 2, excludedRecords: 0 },
    RUNTIME_FILE_PROVENANCE: { files: 2, byteVerified: 2, foreign: 0, missing: 0, nonRegular: 0 },
    RUNTIME_DISTRIBUTION_SET: { installed: 2, selected: 2 },
    RUNTIME_STARTUP_HOOKS: { pthFiles: 0, bytecodeFiles: 0 },
    DECLARED_EXECUTED_SUBSET: { declared: 2, verified: 2 } };
  return Object.entries({ ...base, ...overrides }).map(([check, detail]) =>
    ({ check, ok: true, code: null, detail }));
}
/** The pin check: ok only when nothing was excluded, and it carries the reason when something was. */
function pinCheck(resolved, reason = 'PINNED_RECORD_NAME_OR_VERSION_DOES_NOT_MATCH_THE_ARTIFACT') {
  return { check: 'PINNED_RECORDS_ALL_RESOLVED', ok: resolved, code: resolved ? null : reason,
    detail: { pinnedRecords: 2, excluded: resolved ? 0 : 1 } };
}

test('all three arms run over the same cases and controls, and the record carries no value', { skip },
  async () => {
    const record = await compare({ mode: 'scan' });
    assert.equal(record.kind, 'matched-development-comparison');
    assert.equal(record.comparisonVersion, MATCHED_COMPARISON_VERSION);
    assert.equal(record.scored, false);
    assert.equal(record.enforcing, false);
    // Nothing is sent, so no arm may claim an escape, a task result or a release.
    assert.equal(record.sentBytes, 0);
    assert.equal(record.capturedReleases, 0);
    assert.equal(record.semanticJudgeAndSentinel, 'ABSENT_NO_RECALL_CREDIT');
    assert.deepEqual(record.privacyFilterArm, MATCHED_PRIVACY_FILTER_ARM);
    assert.deepEqual([...MATCHED_ARMS], ['NATIVE', 'PRESIDIO', 'COMBINED']);
    assert.equal(record.cases.length, 2);
    // Every control the run declared is one the independent oracle also plants, plus the two
    // comparison-declared engineering ones: 13 oracle occurrences and 2 comparisons, and the
    // identity block names only the controls for the cases that ran.
    assert.equal(record.identity.declaredControlsForRun.length, 15);
    assert.deepEqual(record.identity.declaredControlsForRun
      .filter((item) => item.declaration === 'ORACLE_DRAFT_OCCURRENCE').length, 7);
    assert.deepEqual(record.identity.declaredControlsForRun
      .filter((item) => item.declaration === 'MATCHED_TRIAL_CONTROL').length, 5);
    assert.deepEqual(record.identity.declaredControlsForRun
      .filter((item) => item.declaration === 'COMPARISON_CONTROL').length, 3);
    for (const entry of record.cases) {
      assert.deepEqual(entry.droppedControls, [], 'a declared control must never vanish silently');
      assert.equal(entry.controlsPlanted, entry.arms.NATIVE.controls.length);
      for (const arm of MATCHED_ARMS) {
        const result = armOf(record, entry.caseId, arm);
        assert.equal(result.controls.length, entry.controlsPlanted);
        assert.ok(result.untested.includes('task-correctness/no-task-control'));
        // D01 has no SECRET control, so that claim is untested for a different named reason; either
        // way no arm may report an observed escape.
        assert.ok(result.untested.some((item) => item.startsWith('secret-plaintext-escape/')));
        assert.equal(result.observed.some((item) => item.startsWith('secret-plaintext-escape/')), false);
        assert.equal(result.observed.some((item) => item.startsWith('task-correctness/')), false);
        assert.equal(result.privacy.criticalPlaintextEscapes, 0);
        // #5 mints its own report ordinals; the comparison names the public fixture id separately so
        // a reviewer can find the inputs, and neither carries a planted value.
        assert.equal(result.caseId.startsWith('case-'), true);
      }
    }
    assertNoPlantedValue(record, 'the matched comparison record');
  });

test('the per-control breakdown is the evaluation owner\'s own count, never a second score', { skip },
  async () => {
    const record = await compare({ mode: 'scan' });
    for (const entry of record.cases) {
      for (const arm of MATCHED_ARMS) {
        const result = armOf(record, entry.caseId, arm);
        const matched = result.controls.filter((item) => item.outcome === 'MATCHED').length;
        assert.equal(matched, result.candidates.matched, 'per-control matched must equal #5 matched');
        assert.equal(result.candidates.misses, result.candidates.planted - matched);
        // The subtype view partitions the same controls: nothing double-counted, nothing dropped.
        assert.equal(sum(Object.values(result.bySubtype).map((item) => item.planted)),
          result.candidates.planted);
        assert.equal(sum(Object.values(result.bySubtype).map((item) => item.matched)), matched);
        for (const [label, group] of Object.entries(result.bySubtype)) {
          assert.equal(group.planted - group.matched, group.missed);
          // A key is `CLASS` or `CLASS/SUBTYPE`; a control with no accepted v1 subtype must not
          // borrow one to make the row look uniform.
          assert.match(label, /^[A-Z][A-Z0-9_]*(\/[A-Z][A-Z0-9_]*)?$/);
        }
      }
    }
    // #37's three subtypes are reported separately for every arm, never merged into one PERSON row.
    for (const arm of MATCHED_ARMS) {
      const subtypes = Object.keys(armOf(record, 'D01-DEV-001', arm).bySubtype);
      for (const required of ['PERSON/NAME', 'PERSON/EMAIL', 'PERSON/PHONE']) {
        assert.ok(subtypes.includes(required), `${arm} must report ${required} separately`);
      }
      // Both NAME occurrences the independent oracle plants are accounted for, not just the first.
      assert.equal(armOf(record, 'D01-DEV-001', arm).bySubtype['PERSON/NAME'].planted, 2);
    }
  });

test('a control no arm generated stays a miss in every arm, with no retroactive credit', { skip },
  async () => {
    // The fake worker finds EMAIL_ADDRESS spans, so the arm emits real findings, and NAME is still
    // a miss. A semantic judge or a sentinel catch cannot become candidate recall here.
    const record = await compare({ mode: 'scan', entityType: 'EMAIL_ADDRESS',
      pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}' });
    const native = armOf(record, 'D01-DEV-001', 'NATIVE');
    assert.equal(controlOf(native, 'control-2').outcome, 'MATCHED');
    assert.equal(controlOf(native, 'control-3').outcome, 'MATCHED');
    for (const arm of MATCHED_ARMS) {
      const entry = armOf(record, 'D01-DEV-001', arm);
      for (const control of entry.controls.filter((item) => item.subtype === 'NAME')) {
        assert.equal(control.outcome, 'NO_CANDIDATE_AT_SPAN', 'NAME is unconfigured, not recovered');
        assert.equal(control.sameSpanLabels.length, 0);
      }
      assert.equal(entry.bySubtype['PERSON/NAME'].matched, 0);
      assert.equal(entry.candidates.misses, entry.candidates.planted - entry.candidates.matched);
    }
    assert.ok(record.limitations.native.includes('NATIVE_NAME_SOURCE_UNCONFIGURED'));
  });

test('missing candidate generation is never reported as a span-level near miss', () => {
  // The distinction #40's critical-miss list depends on: a same-label event on the same field at a
  // *different* value is not a candidate for this control, and reading it as one is how a missing
  // generation turns into an apparent near miss.
  const occurrences = [{ id: 'control-x', fieldRef: 'field-1', start: 10, end: 14,
    semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT' }];
  const elsewhere = scoreArm(occurrences, [{ fieldRef: 'field-1', start: 2, end: 5,
    semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT' }]);
  assert.equal(elsewhere.outcomes.get('control-x').outcome, 'NO_CANDIDATE_AT_SPAN');
  assert.equal(elsewhere.outcomes.get('control-x').sameLabelElsewhere, 1);
  assert.equal(elsewhere.outcomes.get('control-x').sameSpanLabels.length, 0);
  assert.equal(elsewhere.matched, 0);
  // An event that really does cover the control's span under a different label is reported as the
  // label disagreement it is.
  const covered = scoreArm(occurrences, [{ fieldRef: 'field-1', start: 10, end: 14,
    semanticType: 'NETWORK_IDENTIFIER', subtype: 'URL' }]);
  assert.equal(covered.outcomes.get('control-x').outcome, 'SPAN_COVERED_LABEL_DIFFERS');
  assert.deepEqual([...covered.outcomes.get('control-x').sameSpanLabels], ['NETWORK_IDENTIFIER/URL']);
  assert.equal(covered.unmatchedClasses[0].category, 'PLANTED_OCCURRENCE_LABEL_DIFFERS');
});

test('the native arm is configured by omission only, and #6 does not surface the NAME gap', () => {
  // Characterization of existing behavior, not a defect claim and not a change: #37 records
  // `NO_NAME_DICTIONARY` on its own channel, and the unconfigured run is still COMPLETE, so a
  // consumer of #6 alone cannot tell "no names present" from "no name source configured".
  const contact = generateContactCandidates({ text: 'Demo Person Alpha', inputRef: 'probe',
    scope: { tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01' } });
  assert.equal(contact.status, 'COMPLETE');
  assert.deepEqual(contact.reasons, ['NO_NAME_DICTIONARY']);
  assert.equal(contact.candidates.length, 0);
  const native = runNativeArm([{ ref: 'field-0',
    content: 'Demo Person Alpha and person.alpha@example.invalid' }], scope, 'probe');
  assert.deepEqual(native.reasons, []);
  assert.equal(native.events.filter((event) => event.subtype === 'NAME').length, 0);
  assert.equal(native.events.filter((event) => event.subtype === 'EMAIL').length, 1);
});

test('the combined arm is a union: it adds findings and never removes a native one', { skip },
  async () => {
    const record = await compare({ mode: 'scan', entityType: 'EMAIL_ADDRESS' });
    for (const entry of record.cases) {
      const native = armOf(record, entry.caseId, 'NATIVE');
      const combined = armOf(record, entry.caseId, 'COMBINED');
      const overlap = record.overlap[entry.caseId];
      // The record's own overlap accounting states the union property: every distinct native event
      // survives, exactly once, and only identical duplicates are folded away.
      assert.ok(combined.events >= overlap.nativeEvents, 'the union cannot lose a distinct finding');
      assert.equal(overlap.identicalToBothArms + overlap.nativeOnly, overlap.nativeEvents);
      assert.equal(overlap.combinedEvents,
        overlap.identicalToBothArms + overlap.nativeOnly + overlap.presidioOnly);
      // The two ways an event disappears are named separately, because they are different facts.
      assert.equal(overlap.intraArmDuplicatesNative, overlap.nativeEmitted - overlap.nativeEvents);
      assert.equal(overlap.intraArmDuplicatesPresidio, overlap.presidioEmitted - overlap.presidioEvents);
      assert.equal(overlap.totalEmittedEventsFoldedAway,
        overlap.intraArmDuplicatesNative + overlap.intraArmDuplicatesPresidio + overlap.identicalToBothArms);
      // A control the native arm matched stays matched in the union: combining may add a finding,
      // never remove one. A control the native arm *missed* stays a miss unless the other source
      // generated it too - which is why this asserts the native match is preserved, not that every
      // control improved.
      for (const control of native.controls) {
        if (control.outcome !== 'MATCHED') continue;
        assert.equal(controlOf(combined, control.controlRef).outcome, 'MATCHED',
          `combining removed a native finding for ${control.controlRef}`);
      }
    }
    // Pure-function property of the union itself, without any worker at all.
    const left = [{ fieldRef: 'field-0', start: 0, end: 4, semanticType: 'PERSON', subtype: 'NAME' }];
    const right = [{ fieldRef: 'field-0', start: 0, end: 4, semanticType: 'PERSON', subtype: 'NAME' },
      { fieldRef: 'field-0', start: 4, end: 9, semanticType: 'NETWORK_IDENTIFIER', subtype: 'IP' }];
    const union = combineArms(left, right);
    assert.equal(union.events.length, 2);
    assert.equal(union.overlap.identicalToBothArms, 1);
    assert.equal(union.overlap.presidioOnly, 1);
    // Two native rules matching one occurrence collapse to one event, and the loss is named as an
    // intra-arm duplicate rather than as a cross-arm fold.
    const duplicated = combineArms([...left, { ...left[0] }], []);
    assert.equal(duplicated.overlap.nativeEmitted, 2);
    assert.equal(duplicated.overlap.nativeEvents, 1);
    assert.equal(duplicated.overlap.intraArmDuplicatesNative, 1);
    assert.equal(duplicated.overlap.identicalToBothArms, 0);
  });

test('an upstream allow list is recorded as a limitation and cannot suppress native SECRET', { skip },
  async () => {
    // The pinned real configuration has an empty allow list, so this drives the adapter's
    // allow-list branch with the fake worker instead. It proves the composition side only: an
    // upstream configured allow list is named as a limitation, and the native SECRET control is
    // still matched in the combined arm. The real upstream-suppression path stays unexercised.
    const record = await compare({ mode: 'scan', entityType: 'EMAIL_ADDRESS',
      filtering: { allowListCount: 2, allowListMatch: 'EXACT' } });
    assert.ok(record.limitations.presidio.includes('UPSTREAM_ALLOW_LIST'));
    const combined = armOf(record, 'D02-DEV-001', 'COMBINED');
    assert.equal(controlOf(combined, 'control-8').outcome, 'MATCHED',
      'native SECRET protection survives an upstream allow list');
    assert.equal(combined.bySubtype['CREDENTIAL_OR_SECRET/ACCESS_TOKEN'].matched, 1);
  });

test('an unmatched event is classified, and only an oracle-contradicted one is an established error',
  { skip }, async () => {
    const record = await compare({ mode: 'scan', entityType: 'EMAIL_ADDRESS' });
    const categories = new Set(['DUPLICATE_OF_PLANTED_OCCURRENCE', 'PLANTED_OCCURRENCE_LABEL_DIFFERS',
      'ORACLE_DECLARED_NEGATIVE_CONTRADICTED', 'UNRESOLVED']);
    for (const entry of record.cases) {
      for (const arm of MATCHED_ARMS) {
        const result = armOf(record, entry.caseId, arm);
        // The owner's arithmetic and the classification must partition the same events.
        assert.equal(sum(Object.values(result.unmatchedByCategory)),
          result.candidates.falsePositives);
        for (const key of Object.keys(result.unmatchedByCategory)) {
          assert.ok(categories.has(key), `${key} must be a declared category`);
        }
        for (const key of Object.keys(result.unmatchedByCategoryAndLabel)) {
          const [category] = key.split(':');
          assert.ok(categories.has(category));
          assert.match(key.slice(category.length + 1), /^[A-Z][A-Z0-9_]*(\/[A-Z][A-Z0-9_]*)?$/);
        }
      }
    }
    // The classification itself, driven directly on the four cases.
    const planted = [{ fieldRef: 'field-0', start: 10, end: 14, semanticType: 'PERSON', subtype: 'NAME' }];
    const negatives = [{ negativeId: 'N-synthetic-0001', caseId: 'D01-DEV-001', fieldRef: 'field-0',
      start: 40, end: 60, notAClasses: ['PERSON'] },
      { negativeId: 'N-synthetic-0002', caseId: 'D01-DEV-001', fieldRef: 'field-0',
        start: 70, end: 80, notAClasses: ['NETWORK_IDENTIFIER'] }];
    const events = [
      { fieldRef: 'field-0', start: 10, end: 14, semanticType: 'PERSON', subtype: 'NAME' },
      { fieldRef: 'field-0', start: 10, end: 14, semanticType: 'PERSON', subtype: 'EMAIL' },
      { fieldRef: 'field-0', start: 10, end: 14, semanticType: 'PERSON', subtype: 'NAME' },
      { fieldRef: 'field-0', start: 42, end: 48, semanticType: 'PERSON', subtype: 'NAME' },
      { fieldRef: 'field-0', start: 72, end: 78, semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT' },
      { fieldRef: 'field-0', start: 90, end: 95, semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT' }];
    const scored = scoreArm(planted, events, negatives);
    assert.equal(scored.matched, 1);
    assert.equal(scored.falsePositives, 5);
    const byCategory = Object.fromEntries(classifyUnmatched(scored.unmatched, planted, negatives)
      .map((item) => [`${item.category}:${item.semanticType}`, item]));
    assert.equal(byCategory['PLANTED_OCCURRENCE_LABEL_DIFFERS:PERSON'].subtype, 'EMAIL');
    assert.equal(byCategory['DUPLICATE_OF_PLANTED_OCCURRENCE:PERSON'].start, 10);
    // A candidate overlapping a declared negative of its own class contradicts it, and says so.
    assert.equal(byCategory['ORACLE_DECLARED_NEGATIVE_CONTRADICTED:PERSON'].oracleNegativeId,
      'N-synthetic-0001');
    assert.equal(byCategory['ORACLE_DECLARED_NEGATIVE_CONTRADICTED:PERSON'].spanRelation,
      'OVERLAPS_DECLARED_NEGATIVE');
    // The same value shape on a negative whose `notA` does not name its class stays resolved as an
    // established contradiction of its own negative, which is a different negative.
    assert.equal(byCategory['ORACLE_DECLARED_NEGATIVE_CONTRADICTED:NETWORK_IDENTIFIER']
      .oracleNegativeId, 'N-synthetic-0002');
    // A candidate on neither a planted span nor a declared negative stays unresolved, and unresolved
    // is never silently promoted to an established error.
    const onlyUnresolved = classifyUnmatched([{ fieldRef: 'field-0', start: 90, end: 95,
      semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT' }], planted, negatives);
    assert.equal(onlyUnresolved[0].category, 'UNRESOLVED');
    assert.equal(onlyUnresolved[0].oracleNegativeId, undefined);
  });

test('the independent oracle draft supplies the occurrences and the negatives this run uses',
  { skip }, () => {
    const fixtures = JSON.parse(readFileSync(
      new URL('../docs/research/issue-39-public-development-fixtures-p0.1.json', import.meta.url),
      'utf8'));
    const oracle = JSON.parse(readFileSync(
      new URL('../docs/research/issue-39-public-development-oracle-p0.1.json', import.meta.url),
      'utf8'));
    assert.equal(oracle.releaseAuthority, false, 'the draft carries no scoring authority');
    const negatives = loadOracleNegatives(fixtures, oracle, ['D01-DEV-001', 'D02-DEV-001']);
    assert.ok(negatives.length >= 8);
    for (const negative of negatives) {
      assert.match(negative.fieldRef, /^field-\d+$/);
      assert.ok(Number.isSafeInteger(negative.start) && Number.isSafeInteger(negative.end));
      assert.ok(negative.start < negative.end);
      // Only accepted v1 classes survive, and no negative text is carried.
      for (const entry of negative.notAClasses) {
        assert.match(entry, /^[A-Z][A-Z0-9_]*$/);
      }
    }
    assert.equal(negatives.some((item) => item.fieldRef === 'field-2'), true,
      'the log stack-frame negative must be reachable');
    assertNoPlantedValue(negatives, 'the loaded negatives');
    // A D05-only negative is filtered out: the run declares which cases it analysed.
    assert.equal(negatives.some((item) => item.caseId === 'D05-DEV-001'), false);
    assert.equal(loadOracleNegatives(fixtures, oracle, ['D05-DEV-001'])
      .every((item) => item.caseId === 'D05-DEV-001'), true);
    assert.deepEqual(loadOracleNegatives(fixtures, { unplantedNegatives: 'not-a-list' }, ['D01-DEV-001']),
      []);
  });

test('an oracle-declared control whose span disagrees with the computed one is a named drop', () => {
  // The oracle-derived part of the control set is bound to the oracle's own spans, so a control
  // cannot drift away from the independent source it claims to extend.
  const fields = [{ ref: 'field-0', content: `${'x'.repeat(44)}Demo Person Alpha` }];
  const dropped = [];
  const control = { controlRef: 'control-1', caseId: 'D01-DEV-001', fieldRef: 'field-0',
    value: 'Demo Person Alpha', semanticType: 'PERSON', subtype: 'NAME', group: 'CONTACT',
    declaration: 'MATCHED_TRIAL_CONTROL', oracleDraftLabel: 'PERSON.NAME' };
  assert.equal(plantDevelopmentControl(control, fields, dropped).start, 44);
  assert.deepEqual(dropped, []);
  // `control-1` is declared by the oracle at [44, 61), so a text where it lands elsewhere is refused
  // by planting rather than silently scored at a different span.
  const moved = plantDevelopmentControl(control, [{ ref: 'field-0', content: 'Demo Person Alpha' }],
    dropped);
  assert.equal(moved, null);
  assert.deepEqual(dropped.map((item) => item.reason), ['CONTROL_SPAN_DISAGREES_WITH_DECLARED_ORACLE_SPAN']);
});

test('a failing third-party worker is a named bounded failure with no disclosure, not a clean zero',
  { skip }, async () => {
    for (const mode of ['crash', 'raise']) {
      const record = await compare({ mode, stderrText: 'synthetic-planted-stderr.invalid',
        planted: 'synthetic-planted-trace.invalid' });
      for (const entry of record.cases) {
        const presidio = armOf(record, entry.caseId, 'PRESIDIO');
        assert.equal(presidio.events, 0);
        for (const control of presidio.controls) {
          assert.equal(control.outcome, 'NO_CANDIDATE_AT_SPAN',
            'an unavailable detector is never a silent pass');
        }
        // A crashed worker never removes a native finding, and the union collapses onto it.
        assert.deepEqual(armOf(record, entry.caseId, 'COMBINED').controls.map((item) => item.outcome),
          armOf(record, entry.caseId, 'NATIVE').controls.map((item) => item.outcome));
      }
      const failure = record.presidioArm[0];
      assert.equal(failure.status, 'FAILURE');
      assert.ok(failure.transportFailures.length > 0);
      for (const item of failure.transportFailures) {
        assert.ok(['WORKER_CRASHED', 'WORKER_SPAWN_FAILED', 'WORKER_REPLY_MISSING',
          'WORKER_REPLY_INCOMPLETE', 'WORKER_OUTPUT_LIMIT', 'WORKER_STDERR_LIMIT',
          'WORKER_STARTUP_TIMEOUT', 'WORKER_EXECUTION_TIMEOUT'].includes(item.reason));
      }
      // stderr, an exception and a traceback carrying planted values reach no channel.
      assertNoPlantedValue(record, `the ${mode} comparison record`);
      assert.equal(JSON.stringify(record).includes('Traceback'), false);
    }
  });

test('an unknown case fails before any worker process starts, and arguments never echo', { skip },
  async () => {
    await assert.rejects(runMatchedDevelopmentComparison({ command: command(),
      caseIds: ['D09-DEV-999'], manifest: manifest(), workdir: workspace, scope }), TypeError);
    for (const bad of [['--python'], ['--nonsense', 'x'], ['--case']]) {
      const refused = spawnSync(process.execPath, [SCRIPT, ...bad], { encoding: 'utf8', timeout: 60_000 });
      assert.notEqual(refused.status, 0);
      assert.equal(refused.stdout.includes('matched-development-comparison'), false);
      assert.equal(/synthetic-planted/.test(refused.stderr), false);
    }
  });

test('an unplantable control is a named drop, and a silent one is a refused run', () => {
  const control = { controlRef: 'control-x', caseId: 'D01-DEV-001', fieldRef: 'field-0',
    value: 'synthetic-absent.invalid', semanticType: 'HOST_OR_SERVICE', subtype: null, group: 'ENGINEERING',
    declaration: 'COMPARISON_CONTROL', oracleDraftLabel: null };
  const fields = [{ ref: 'field-0', content: 'synthetic-plant.invalid and synthetic-plant.invalid' }];
  const absent = [];
  assert.equal(plantDevelopmentControl(control, fields, absent), null);
  assert.deepEqual(absent.map((item) => item.reason), ['CONTROL_ABSENT']);
  const ambiguous = [];
  assert.equal(plantDevelopmentControl({ ...control, value: 'synthetic-plant.invalid' }, fields, ambiguous), null);
  assert.deepEqual(ambiguous.map((item) => item.reason), ['CONTROL_AMBIGUOUS']);
  const noField = [];
  assert.equal(plantDevelopmentControl({ ...control, fieldRef: 'field-9' }, fields, noField), null);
  assert.deepEqual(noField.map((item) => item.reason), ['FIELD_ABSENT']);
  assert.equal(JSON.stringify(absent).includes('synthetic-absent.invalid'), false);
  const planted = plantDevelopmentControl({ ...control, value: 'synthetic-plant.invalid',
    semanticType: 'NETWORK_IDENTIFIER', subtype: 'IP' },
    [{ ref: 'field-0', content: 'see synthetic-plant.invalid here' }], []);
  assert.equal(planted.id, 'control-x');
  assert.equal(planted.start, 4);
  assert.equal(planted.end, 4 + 'synthetic-plant.invalid'.length);
  assert.doesNotThrow(() => assertNoSilentControlDrop(1, [{ reason: 'CONTROL_ABSENT' }], 2));
  assert.throws(() => assertNoSilentControlDrop(1, [], 2), TypeError);
  assert.throws(() => assertNoSilentControlDrop(2, [{ reason: 'CONTROL_ABSENT' }], 2), TypeError);
});

test('a breakdown that disagrees with the evaluation owner is refused, never printed', () => {
  const occurrences = [{ id: 'control-a', fieldRef: 'field-0', start: 0, end: 4,
    semanticType: 'PERSON', subtype: 'NAME' }];
  const events = [{ fieldRef: 'field-0', start: 0, end: 4, semanticType: 'PERSON', subtype: 'NAME' }];
  const scored = scoreArm(occurrences, events);
  const honest = { planted: 1, matched: 1, falsePositives: 0 };
  assert.doesNotThrow(() => assertOwnerAgreement(honest, scored, 1));
  for (const tampered of [{ ...honest, matched: 2 }, { ...honest, falsePositives: 1 },
    { ...honest, planted: 2 }]) {
    assert.throws(() => assertOwnerAgreement(tampered, scored, 1), TypeError);
  }
});

test('a run with no execution-environment evidence says so instead of implying a pass', { skip },
  async () => {
    const record = await compare({ mode: 'scan' });
    assert.equal(record.executionEnvironment.status, 'NOT_PERFORMED');
    assert.match(record.executionEnvironment.code, /^[A-Z_]+$/);
    assert.ok(record.limits.includes(
      'EXECUTION_ENVIRONMENT_NOT_VERIFIED_NO_THIRD_PARTY_EXECUTION_EVIDENCE_ACCEPTED'));
    assert.equal(record.limits.includes(
      'EXECUTION_ENVIRONMENT_VERIFIES_THE_EXECUTED_SUBSET_ONLY_NOT_EVERY_PINNED_RECORD'), false);
    // Every part of the verification shape is required: supplying one input is never a pass.
    for (const partial of [{ scriptPath: VERIFIER }, { scriptPath: VERIFIER, manifestPath: 'x' },
      { scriptPath: VERIFIER, manifestPath: 'x', wheelDirectory: 'y' }]) {
      assert.equal(verifySelectedRuntime(partial).status, 'NOT_PERFORMED');
    }
  });

test('the screen verifier refuses a manifest record whose name does not match its artifact', { skip },
  () => {
    // Synthetic wheels and a synthetic manifest, one of whose records names the wrong package: the
    // exact shape of the defect that a digest-complete screen still passes.
    const root = mkdtempSync(join(tmpdir(), 'hylja-runtime-verify-'));
    const wheels = join(root, 'wheels');
    const site = join(root, 'site');
    mkdirSync(wheels); mkdirSync(site);
    const build = (name, version) => {
      const importName = name.replace(/-/g, '_');
      const dist = `${importName}-${version}.dist-info`;
      const path = join(wheels, `${name}-${version}-py3-none-any.whl`);
      const members = [
        { name: `${importName}/__init__.py`, body: `# ${name} ${version}\n` },
        { name: `${dist}/METADATA`, body: `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\n` }];
      // A minimal stored (uncompressed) zip, written with the standard library only.
      spawnSync(PYTHON, ['-c', [
        'import json,sys,zipfile',
        'members=json.loads(sys.argv[1])',
        'with zipfile.ZipFile(sys.argv[2],"w",zipfile.ZIP_STORED) as z:',
        '    [z.writestr(m["name"], m["body"]) for m in members]',
      ].join('\n'), JSON.stringify(members), path], { stdio: 'pipe' });
      return { path, members };
    };
    const alpha = build('synthetic-alpha', '1.0');
    build('synthetic-beta', '2.0');
    const digestOf = (target) => spawnSync(PYTHON, ['-c',
      'import hashlib,sys\nprint(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())', target],
    { encoding: 'utf8' }).stdout.trim();
    const screenOf = (name, version, digest) => [{ package_name: name, version, outcome: 'OK',
      yanked: false, advisories: [], observed_sha256: digest }];
    const records = [
      { name: 'synthetic-alpha', version: '1.0', sha256: digestOf(alpha.path) },
      // Same bytes, different declared identity: what the pinned set contained.
      { name: 'synthetic-gamma', version: '9.9', sha256: digestOf(alpha.path) }];
    const manifestPath = join(root, 'manifest.json');
    const screenPath = join(root, 'screen.json');
    writeFileSync(manifestPath, JSON.stringify({ artifacts: records }));
    writeFileSync(screenPath, JSON.stringify([
      ...screenOf('synthetic-alpha', '1.0', records[0].sha256),
      ...screenOf('synthetic-gamma', '9.9', records[1].sha256)]));
    // Install only the selected artifact: exactly what the corrected run's runtime contains.
    mkdirSync(join(site, 'synthetic_alpha'), { recursive: true });
    mkdirSync(join(site, 'synthetic_alpha-1.0.dist-info'), { recursive: true });
    for (const member of alpha.members) {
      writeFileSync(join(site, member.name), member.body);
    }
    const hookPath = join(site, 'synthetic_hook.pth');
    const verify = (overrides = {}) => verifySelectedRuntime({ pythonPath: PYTHON, scriptPath: VERIFIER,
      manifestPath, wheelDirectory: wheels, screenPath, sitePackagesPath: site, ...overrides });
    // The name mismatch is caught, excluded and disclosed, and the executed subset still verifies.
    const withMismatch = verify();
    assert.equal(withMismatch.status, 'VERIFIED_WITH_EXCLUSIONS');
    assert.equal(withMismatch.selectedArtifacts, 1);
    assert.equal(withMismatch.excludedArtifactRecords, 1);
    assert.deepEqual([...withMismatch.excludedReasons],
      ['PINNED_RECORD_NAME_OR_VERSION_DOES_NOT_MATCH_THE_ARTIFACT']);
    const pinCheck = withMismatch.checks.find((item) => item.check === 'PINNED_RECORDS_ALL_RESOLVED');
    assert.equal(pinCheck.ok, false, 'the pin check stays a visible non-ok, not a hidden one');
    // A runtime that carries a startup hook is refused outright, whatever the pin says: an `import `
    // line in a .pth is executed by `site` at interpreter startup.
    writeFileSync(hookPath, 'import os\n');
    const withHook = verify();
    assert.equal(withHook.status, 'MISMATCH');
    const hooks = withHook.checks.find((item) => item.check === 'RUNTIME_STARTUP_HOOKS');
    assert.equal(hooks.ok, false);
    assert.equal(hooks.code, 'RUNTIME_HAS_PTH_STARTUP_HOOK');
    assert.equal(hooks.detail.pthFiles, 1);
    rmSync(hookPath);
    // A distribution that is not in the selected set is refused as well.
    mkdirSync(join(site, 'synthetic_beta-2.0.dist-info'), { recursive: true });
    writeFileSync(join(site, 'synthetic_beta-2.0.dist-info', 'METADATA'), 'Name: synthetic-beta\n');
    const foreign = verify();
    assert.equal(foreign.status, 'MISMATCH');
    const distributions = foreign.checks.find((item) => item.check === 'RUNTIME_DISTRIBUTION_SET');
    assert.equal(distributions.ok, false);
    // An unreadable input is `NOT_PERFORMED`, never a silent pass, and nothing is carried.
    const refused = verify({ screenPath: join(root, 'absent.json') });
    assert.equal(refused.status, 'NOT_PERFORMED');
    assert.deepEqual([...refused.checks], []);
    // The verifier's own output carries no path and no file name.
    const serialized = JSON.stringify(verify());
    assert.equal(serialized.includes(root), false);
    assert.equal(serialized.includes('.whl'), false);
    rmSync(root, { recursive: true, force: true });
  });

test('the verifier output is re-derived from a closed vocabulary before it reaches a record', { skip },
  async () => {
    // The helper's stdout is untrusted content: a reply that carries a free string, an unknown check
    // name or an off-vocabulary code is discarded rather than printed.
    const root = mkdtempSync(join(tmpdir(), 'hylja-runtime-shape-'));
    const fake = join(root, 'fake_verifier.py');
    const good = { protocol: 'hylja.presidio.runtime-verification', version: 1,
      status: 'VERIFIED', selectedArtifacts: 2, excludedArtifactRecords: [],
      screen: { records: 2 }, runtime: { distributions: 2, files: 3, pthFiles: 0 },
      checks: [...executedChecks(), pinCheck(false)] };
    // `reply` is not part of the function's options, so a shim script is driven with a fixed
    // argument instead: the helper is invoked with the four verification inputs and its stdout is
    // what is shape-checked.
    for (const bad of [{ ...good, protocol: 'other' }, { ...good, version: 2 },
      { ...good, status: 'MAYBE' },
      { ...good, checks: [{ check: 'ARBITRARY', ok: true, code: null, detail: {} }] },
      { ...good, checks: [{ check: 'NAME_IDENTITY', ok: true, code: 'PLANTED_VALUE',
        detail: {} }] },
      { ...good, excludedArtifactRecords: [{ reason: 'PLANTED_VALUE' }] }]) {
      writeFileSync(fake, `import json,sys\nsys.stdout.write(json.loads(${JSON.stringify(
        `${JSON.stringify(bad)}\n`)}) + "\\n")\n`);
      const result = verifySelectedRuntime({ pythonPath: PYTHON, scriptPath: fake, manifestPath: 'a',
        wheelDirectory: 'b', screenPath: 'c', sitePackagesPath: 'd' });
      assert.equal(result.status, 'NOT_PERFORMED', 'an off-vocabulary verification reply is refused');
      assert.deepEqual([...result.checks], []);
    }
    rmSync(root, { recursive: true, force: true });
  });

test('the verifier process is bounded and every unusable reply is a named refusal', { skip }, () => {
  // The helper's stdout crosses an untrusted boundary, so its failure paths matter as much as the
  // happy one: a helper that crashes, says nothing, says too much or answers with an off-vocabulary
  // field must produce a fixed code and carry nothing into a record.
  const root = mkdtempSync(join(tmpdir(), 'hylja-verifier-refusal-'));
  const script = join(root, 'shim.py');
  const run = (body) => {
    writeFileSync(script, body);
    return verifySelectedRuntime({ pythonPath: PYTHON, scriptPath: script, manifestPath: 'a',
      wheelDirectory: 'b', screenPath: 'c', sitePackagesPath: 'd' });
  };
  // The payload travels as a JSON *string* literal that the shim parses, so Python never has to read
  // JSON's bare `true`/`false`/`null` and every refusal below is the bridge's verdict, not a crash.
  // The payload travels as a JSON *string* literal that the shim parses, so Python never has to read
  // JSON's bare `true`/`false`/`null`; `writes` emits exactly the text given, newlines included.
  const writes = (value) => `import json,sys\nsys.stdout.write(json.loads(${JSON.stringify(
    JSON.stringify(value))}))\n`;
  const crashed = run('import sys\nsys.stderr.write("synthetic-planted-trace.invalid")\nsys.exit(3)\n');
  assert.equal(crashed.status, 'NOT_PERFORMED');
  assert.equal(crashed.reason, 'VERIFICATION_PROCESS_DID_NOT_SUCCEED');
  assert.deepEqual([...crashed.checks], []);
  assert.equal(JSON.stringify(crashed).includes('synthetic-planted-trace.invalid'), false,
    'a helper traceback on stderr is never materialised');
  for (const body of ['pass\n', writes('{not json\n'), writes('{"protocol":"hylja.presidio.runtime-verification"}\n{"a":1}\n')]) {
    const refused = run(body);
    assert.equal(refused.status, 'NOT_PERFORMED');
    assert.equal(refused.reason, 'VERIFICATION_OUTPUT_SHAPE_REJECTED');
  }
  // A helper refusal is carried as its own fixed code, never as a pass.
  const refused = run(writes(`${JSON.stringify({ protocol: 'hylja.presidio.runtime-verification',
    version: 1, status: 'MISMATCH', checks: [], reason: 'MANIFEST_OR_SCREEN_UNREADABLE' })}\n`));
  assert.equal(refused.status, 'NOT_PERFORMED');
  assert.equal(refused.reason, 'MANIFEST_OR_SCREEN_UNREADABLE');
  // A detail value that is not a count, an off-vocabulary excluded reason, and an unknown code are
  // all refusals rather than values that could reach a record.
  const good = { protocol: 'hylja.presidio.runtime-verification', version: 1, status: 'VERIFIED',
    selectedArtifacts: 1, excludedArtifactRecords: [], screen: { records: 1 },
    runtime: { distributions: 1, files: 1, pthFiles: 0 },
    checks: [...executedChecks(), pinCheck(false)] };
  for (const bad of [
    { ...good, checks: [{ check: 'NAME_IDENTITY', ok: true, code: null, detail: { selected: 'one' } }] },
    { ...good, checks: [{ check: 'NAME_IDENTITY', ok: true, code: null, detail: { selected: -1 } }] },
    { ...good, excludedArtifactRecords: [{ reason: 'PLANTED_VALUE' }] },
    { ...good, checks: [{ check: 'NAME_IDENTITY', ok: true, code: 'UNLISTED_CODE', detail: {} }] },
    { ...good, runtime: { distributions: 'two', files: 1, pthFiles: 0 } },
    { ...good, checks: [{ check: 'NAME_IDENTITY', ok: true, code: null, detail: [] }] },
    { ...good, checks: [{ check: 'NAME_IDENTITY', ok: true, code: null, detail: 5 }] },
    { ...good, selectedArtifacts: -1 }]) {
    assert.equal(run(writes(`${JSON.stringify(bad)}\n`)).status, 'NOT_PERFORMED');
  }
  // An interpreter that cannot be spawned at all is a named refusal, never an exception. `spawnSync`
  // reports it through `error`/`status`, so the module's own `catch` stays a defensive net that
  // configuration validation already excludes - the same convention the worker transport documents.
  const noInterpreter = verifySelectedRuntime({ pythonPath: join(root, 'absent-python'),
    scriptPath: 'x', manifestPath: 'a', wheelDirectory: 'b', screenPath: 'c', sitePackagesPath: 'd' });
  assert.equal(noInterpreter.status, 'NOT_PERFORMED');
  assert.equal(noInterpreter.reason, 'VERIFICATION_PROCESS_DID_NOT_SUCCEED');
  rmSync(root, { recursive: true, force: true });
});

test('a run with a verified environment says which subset was verified and what was excluded',
  { skip }, async () => {
    // The successful branch of the environment claim, driven by a shim verifier: a record that
    // reports `VERIFIED` must also report the executed subset size and every excluded record's
    // reason, so it can never read as "the whole pin was conformant".
    const root = mkdtempSync(join(tmpdir(), 'hylja-verifier-claim-'));
    const shim = join(root, 'shim.py');
    const verified = { protocol: 'hylja.presidio.runtime-verification', version: 1,
      status: 'VERIFIED_WITH_EXCLUSIONS', selectedArtifacts: 50,
      excludedArtifactRecords: [{ name: 'synthetic', version: '1', reason: 'ARTIFACT_UNREADABLE' }],
      screen: { records: 51 }, runtime: { distributions: 50, files: 4609, pthFiles: 0 },
      checks: [...executedChecks(), pinCheck(true)] };
    writeFileSync(shim, `import json,sys\nsys.stdout.write(json.dumps(json.loads(${JSON.stringify(
      JSON.stringify(verified))})) + "\\n")\n`);
    const record = await compare({ mode: 'scan' }, { verificationScript: shim,
      verificationPython: PYTHON, verificationManifest: 'm', wheelDirectory: 'w',
      screenReport: 's', sitePackages: 'p' });
    assert.equal(record.executionEnvironment.status, 'VERIFIED_WITH_EXCLUSIONS');
    assert.equal(record.executionEnvironment.selectedArtifacts, 50);
    assert.equal(record.executionEnvironment.excludedArtifactRecords, 1);
    assert.deepEqual([...record.executionEnvironment.excludedReasons], ['ARTIFACT_UNREADABLE']);
    assert.equal(record.executionEnvironment.runtimeStartupHookFiles, 0);
    assert.match(record.executionEnvironment.note, /executed subset only/);
    assert.equal(record.limits.includes(
      'EXECUTION_ENVIRONMENT_VERIFIES_THE_EXECUTED_SUBSET_ONLY_NOT_EVERY_PINNED_RECORD'), true);
    assert.equal(record.limits.includes(
      'EXECUTION_ENVIRONMENT_NOT_VERIFIED_NO_THIRD_PARTY_EXECUTION_EVIDENCE_ACCEPTED'), false);
    rmSync(root, { recursive: true, force: true });
  });

test('a verifier reply cannot declare a verified environment its own checks contradict', { skip },
  () => {
    // The helper's `status` is a claim about the whole verification, so it is derived from the checks the
    // bridge accepted rather than copied. Every declared status is tried against the SAME failing
    // check set: a runtime carrying one startup hook with `RUNTIME_STARTUP_HOOKS` not ok must never be
    // recorded as verified, whichever string the helper declares.
    const root = mkdtempSync(join(tmpdir(), 'hylja-verifier-status-'));
    const shim = join(root, 'shim.py');
    // The full executed check set with exactly one check - the startup-hook one - turned to not-ok.
    const all = executedChecks({ RUNTIME_STARTUP_HOOKS: { pthFiles: 1, bytecodeFiles: 0 } });
    const failing = [...all.slice(0, 4), { ...all[4], ok: false, code: 'RUNTIME_HAS_PTH_STARTUP_HOOK' },
      all[5]];
    const reply = (value) => `import json,sys\nsys.stdout.write(json.dumps(json.loads(${JSON.stringify(
      JSON.stringify(value))})) + "\\n")\n`;
    const base = { protocol: 'hylja.presidio.runtime-verification', version: 1, selectedArtifacts: 2,
      excludedArtifactRecords: [], screen: { records: 2 },
      runtime: { distributions: 2, files: 2, pthFiles: 1 } };
    for (const status of ['VERIFIED', 'VERIFIED_WITH_EXCLUSIONS', 'MISMATCH']) {
      writeFileSync(shim, reply({ ...base, status, checks: [...failing, pinCheck(true)] }));
      const result = verifySelectedRuntime({ pythonPath: PYTHON, scriptPath: shim, manifestPath: 'a',
        wheelDirectory: 'b', screenPath: 'c', sitePackagesPath: 'd' });
      // Only the status the checks support is accepted; the other two are refused outright.
      if (status === 'MISMATCH') {
        assert.equal(result.status, 'MISMATCH');
        const hooks = result.checks.find((item) => item.check === 'RUNTIME_STARTUP_HOOKS');
        assert.equal(hooks.ok, false);
        assert.equal(hooks.code, 'RUNTIME_HAS_PTH_STARTUP_HOOK');
      } else {
        assert.equal(result.status, 'NOT_PERFORMED', `declared ${status} must not be recorded`);
        assert.equal(result.reason, 'VERIFICATION_STATUS_DISAGREES_WITH_ACCEPTED_CHECKS');
        assert.deepEqual([...result.checks], []);
      }
    }
    // The mirror case: a reply that declares MISMATCH while every executed check passed is also refused,
    // so neither direction is believed.
    writeFileSync(shim, reply({ ...base, status: 'MISMATCH', checks: [...executedChecks(), pinCheck(true)] }));
    const overRefused = verifySelectedRuntime({ pythonPath: PYTHON, scriptPath: shim, manifestPath: 'a',
      wheelDirectory: 'b', screenPath: 'c', sitePackagesPath: 'd' });
    assert.equal(overRefused.status, 'NOT_PERFORMED');
    assert.equal(overRefused.reason, 'VERIFICATION_STATUS_DISAGREES_WITH_ACCEPTED_CHECKS');
    // An incomplete check set is refused rather than judged on the checks that happen to be present.
    writeFileSync(shim, reply({ ...base, status: 'VERIFIED',
      checks: [executedChecks()[0], pinCheck(true)] }));
    const incomplete = verifySelectedRuntime({ pythonPath: PYTHON, scriptPath: shim, manifestPath: 'a',
      wheelDirectory: 'b', screenPath: 'c', sitePackagesPath: 'd' });
    assert.equal(incomplete.status, 'NOT_PERFORMED');
    assert.equal(incomplete.reason, 'VERIFICATION_CHECK_SET_INCOMPLETE');
    // `ok` and `code` may never disagree in the accepted reply, in either direction, and neither may a
    // code outside the vocabulary or a detail that is not an object of counts.
    for (const inconsistent of [
      { ...executedChecks()[0], code: 'DIGEST_NOT_CACHED' },
      { ...executedChecks()[0], ok: false, code: null },
      { ...executedChecks()[0], code: 'PLANTED_VALUE' },
      { ...executedChecks()[0], detail: [] },
      { ...executedChecks()[0], detail: 5 }]) {
      writeFileSync(shim, reply({ ...base, status: 'MISMATCH',
        checks: [inconsistent, ...executedChecks().slice(1), pinCheck(true)] }));
      assert.equal(verifySelectedRuntime({ pythonPath: PYTHON, scriptPath: shim, manifestPath: 'a',
        wheelDirectory: 'b', screenPath: 'c', sitePackagesPath: 'd' }).status, 'NOT_PERFORMED',
      `an inconsistent check (${JSON.stringify(inconsistent).slice(0, 60)}) must be refused`);
    }
    rmSync(root, { recursive: true, force: true });
  });

test('a verified environment carries its own checks, including the deliberately failing pin check',
  { skip }, async () => {
    const root = mkdtempSync(join(tmpdir(), 'hylja-verifier-claim-checks-'));
    const shim = join(root, 'shim.py');
    const reply = { protocol: 'hylja.presidio.runtime-verification', version: 1,
      status: 'VERIFIED_WITH_EXCLUSIONS', selectedArtifacts: 50,
      excludedArtifactRecords: [{ name: 'synthetic', version: '1',
        reason: 'PINNED_RECORD_NAME_OR_VERSION_DOES_NOT_MATCH_THE_ARTIFACT' }],
      screen: { records: 51 }, runtime: { distributions: 50, files: 4609, pthFiles: 0 },
      checks: [...executedChecks({ PINNED_DIGESTS_PRESENT: { pinnedRecords: 51, digestsPresent: 51 },
        SELECTED_ARTIFACTS_NAME_AND_SCREEN_VERIFIED: { selected: 50, selectedWithScreenRecord: 50,
          excludedRecords: 1 },
        RUNTIME_FILE_PROVENANCE: { files: 4609, byteVerified: 4609, foreign: 0, missing: 0, nonRegular: 0 },
        RUNTIME_DISTRIBUTION_SET: { installed: 50, selected: 50 },
        DECLARED_EXECUTED_SUBSET: { declared: 50, verified: 50 } }),
      pinCheck(false)] };
    writeFileSync(shim, `import json,sys\nsys.stdout.write(json.dumps(json.loads(${JSON.stringify(
      JSON.stringify(reply))})) + "\\n")\n`);
    const record = await compare({ mode: 'scan' }, { verificationScript: shim, verificationPython: PYTHON,
      verificationManifest: 'm', wheelDirectory: 'w', screenReport: 's', sitePackages: 'p' });
    const claim = record.executionEnvironment;
    assert.equal(claim.status, 'VERIFIED_WITH_EXCLUSIONS');
    assert.equal(claim.selectedArtifacts, 50);
    assert.deepEqual([...claim.excludedReasons],
      ['PINNED_RECORD_NAME_OR_VERSION_DOES_NOT_MATCH_THE_ARTIFACT']);
    // Every accepted check is carried, with its own ok and code, so a reader never sees a green status
    // with no way to see which check produced it - or that the pin check is deliberately not ok.
    assert.equal(claim.checks.length, 7);
    const pin = claim.checks.find((item) => item.check === 'PINNED_RECORDS_ALL_RESOLVED');
    assert.equal(pin.ok, false);
    assert.equal(pin.code, 'PINNED_RECORD_NAME_OR_VERSION_DOES_NOT_MATCH_THE_ARTIFACT');
    const executed = claim.checks.filter((item) => item.check !== 'PINNED_RECORDS_ALL_RESOLVED');
    assert.equal(executed.length, 6);
    for (const item of executed) {
      assert.equal(item.ok, true, `${item.check} must be ok in a verified claim`);
      assert.equal(item.code, null, `${item.check} must not carry a code while ok`);
    }
    assert.match(claim.note, /DERIVED from the checks/);
    assert.match(claim.note, /executed subset only/);
    rmSync(root, { recursive: true, force: true });
  });

test('the committed verifier reports its own refusal causes, and refuses a symlinked runtime entry',
  { skip }, () => {
    // Driven through the COMMITTED helper with real missing inputs, not a hand-written shim: a refusal
    // must name its cause, and the bridge must carry that code through instead of collapsing five
    // distinct causes into one shape rejection.
    const root = mkdtempSync(join(tmpdir(), 'hylja-verifier-refusals-'));
    const wheels = join(root, 'wheels');
    const site = join(root, 'site');
    mkdirSync(wheels); mkdirSync(site);
    // `withDistInfo: false` builds an artifact that cannot identify itself, which is a pin defect the
    // verifier must report by its own cause rather than refuse to answer about.
    const build = (name, version, { withDistInfo = true } = {}) => {
      const importName = name.replace(/-/g, '_');
      const dist = `${importName}-${version}.dist-info`;
      const path = join(wheels, `${name}-${version}-py3-none-any.whl`);
      const members = [{ name: `${importName}/__init__.py`, body: `# ${name} ${version}\n` }];
      if (withDistInfo) members.push({ name: `${dist}/METADATA`,
        body: `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\n` });
      spawnSync(PYTHON, ['-c', ['import json,sys,zipfile', 'members=json.loads(sys.argv[1])',
        'with zipfile.ZipFile(sys.argv[2],"w",zipfile.ZIP_STORED) as z:',
        '    [z.writestr(m["name"], m["body"]) for m in members]'].join('\n'),
      JSON.stringify(members), path], { stdio: 'pipe' });
      return { path, members };
    };
    const alpha = build('synthetic-alpha', '1.0');
    const digestOf = (target) => spawnSync(PYTHON, ['-c',
      'import hashlib,sys\nprint(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())', target],
    { encoding: 'utf8' }).stdout.trim();
    const manifestPath = join(root, 'manifest.json');
    const screenPath = join(root, 'screen.json');
    writeFileSync(manifestPath, JSON.stringify({ artifacts: [
      { name: 'synthetic-alpha', version: '1.0', sha256: digestOf(alpha.path) }] }));
    writeFileSync(screenPath, JSON.stringify([{ package_name: 'synthetic-alpha', version: '1.0',
      outcome: 'OK', yanked: false, advisories: [], observed_sha256: digestOf(alpha.path) }]));
    mkdirSync(join(site, 'synthetic_alpha'), { recursive: true });
    mkdirSync(join(site, 'synthetic_alpha-1.0.dist-info'), { recursive: true });
    for (const member of alpha.members) writeFileSync(join(site, member.name), member.body);
    const verify = (overrides = {}) => verifySelectedRuntime({ pythonPath: PYTHON, scriptPath: VERIFIER,
      manifestPath, wheelDirectory: wheels, screenPath, sitePackagesPath: site, ...overrides });
    const clean = verify();
    assert.equal(clean.status, 'VERIFIED');
    assert.equal(clean.selectedArtifacts, 1);
    // Five distinct causes, five distinct codes, each carried through the bridge rather than collapsed.
    for (const [overrides, expected] of [
      [{ screenPath: join(root, 'absent.json') }, 'MANIFEST_OR_SCREEN_UNREADABLE'],
      [{ manifestPath: join(root, 'absent.json') }, 'MANIFEST_OR_SCREEN_UNREADABLE'],
      [{ sitePackagesPath: join(root, 'absent-dir') }, 'RUNTIME_SITE_PACKAGES_NOT_A_DIRECTORY'],
      [{ wheelDirectory: join(root, 'absent-dir') }, 'WHEEL_DIRECTORY_UNREADABLE'],
      [{ manifestPath: (() => {
        const path = join(root, 'empty-manifest.json');
        writeFileSync(path, JSON.stringify({ artifacts: [] }));
        return path;
      })() }, 'MANIFEST_ARTIFACT_RECORDS']]) {
      const refused = verify(overrides);
      assert.equal(refused.status, 'NOT_PERFORMED');
      assert.equal(refused.reason, expected, 'a refusal must carry its own cause');
      assert.deepEqual([...refused.checks], []);
    }
    // Every non-regular entry is refused rather than skipped: Python imports through a symlink, and a
    // FIFO or device is not something a file-provenance check can establish anything about. All three
    // shapes are driven here because each one is a different branch of the same decision.
    const outsideDir = join(root, 'outside_package');
    mkdirSync(outsideDir);
    writeFileSync(join(outsideDir, 'planted_module.py'), '# outside the verified runtime\n');
    const fifo = join(site, 'synthetic_alpha', 'planted.fifo');
    const fifoCase = () => {
      const result = spawnSync(PYTHON, ['-c', 'import os,sys\nos.mkfifo(sys.argv[1])\n', fifo],
        { stdio: 'pipe' });
      assert.equal(result.status, 0, result.stderr.toString());
    };
    const cases = [
      ['symlinked file', () => symlinkSync(join(outsideDir, 'planted_module.py'),
        join(site, 'synthetic_alpha', 'planted_module.py'))],
      ['symlinked directory', () => symlinkSync(outsideDir, join(site, 'synthetic_alpha', 'planted_pkg'))],
      ['fifo', () => fifoCase()],
    ];
    for (const [label, plant] of cases) {
      plant();
      const linked = verify();
      assert.equal(linked.status, 'MISMATCH', `${label} must not verify`);
      const provenance = linked.checks.find((item) => item.check === 'RUNTIME_FILE_PROVENANCE');
      assert.equal(provenance.ok, false, `${label}: provenance must fail`);
      assert.equal(provenance.code, 'NON_REGULAR_RUNTIME_ENTRY', `${label}: must name the cause`);
      assert.equal(provenance.detail.nonRegular, 1, `${label}: must be counted`);
      assertNoPlantedValue(linked, `the ${label} verification record`);
      {
        rmSync(join(site, 'synthetic_alpha', 'planted_module.py'), { force: true });
        rmSync(join(site, 'synthetic_alpha', 'planted_pkg'), { force: true });
        rmSync(fifo, { force: true });
      }
    }
    // A regular file the verifier cannot read is a runtime defect with its own cause, not a protocol
    // error: `ok: false` must always name why, or the cause is lost and a reader is sent to look at the
    // wrong thing.
    const blocked = join(site, 'synthetic_alpha', 'blocked.py');
    writeFileSync(blocked, '# unreadable by the verifier\n');
    chmodSync(blocked, 0o000);
    try {
      const unreadable = verify();
      assert.equal(unreadable.status, 'MISMATCH', 'an unreadable entry must not verify');
      const provenance = unreadable.checks.find((item) => item.check === 'RUNTIME_FILE_PROVENANCE');
      assert.equal(provenance.ok, false);
      assert.equal(provenance.code, 'RUNTIME_ENTRY_UNREADABLE');
      assertNoPlantedValue(unreadable, 'the unreadable-entry verification record');
    } finally { chmodSync(blocked, 0o600); }
    // A pin record naming an artifact that cannot identify itself is reported by its own cause rather
    // than collapsing the whole reply into a shape rejection.
    build('synthetic-gamma', '3.0', { withDistInfo: false });
    const selfIdentifiable = join(root, 'wheels', 'synthetic-gamma-3.0-py3-none-any.whl');
    const oddPin = join(root, 'manifest-odd.json');
    writeFileSync(oddPin, JSON.stringify({ artifacts: [
      { name: 'synthetic-gamma', version: '3.0', sha256: digestOf(selfIdentifiable) }] }));
    const oddScreen = join(root, 'screen-odd.json');
    writeFileSync(oddScreen, JSON.stringify([{ package_name: 'synthetic-gamma', version: '3.0',
      outcome: 'OK', yanked: false, advisories: [], observed_sha256: digestOf(selfIdentifiable) }]));
    const odd = verifySelectedRuntime({ pythonPath: PYTHON, scriptPath: VERIFIER, manifestPath: oddPin,
      wheelDirectory: wheels, screenPath: oddScreen, sitePackagesPath: site });
    assert.equal(odd.status, 'MISMATCH');
    assert.deepEqual([...odd.excludedReasons], ['ARTIFACT_OWNS_NO_SINGLE_TOP_LEVEL_DIST_INFO']);
    const pin = odd.checks.find((item) => item.check === 'PINNED_RECORDS_ALL_RESOLVED');
    assert.equal(pin.ok, false);
    assert.equal(pin.code, 'ARTIFACT_OWNS_NO_SINGLE_TOP_LEVEL_DIST_INFO');
    assert.equal(odd.selectedArtifacts, 0);
    rmSync(root, { recursive: true, force: true });
  });

test('the documented command line runs the same bridge and prints only the privacy-safe record',
  { skip }, () => {
    const args = ['--python', PYTHON, '--worker', WORKER, '--manifest', manifest({ mode: 'scan' }),
      '--workdir', workspace ?? tmpdir(), '--tenant', 'tenant-synthetic-01',
      '--project', 'project-synthetic-01', '--case', 'D01-DEV-001'];
    const result = spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', timeout: 180_000 });
    assert.equal(result.status, 0, result.stderr);
    const record = JSON.parse(result.stdout);
    assert.equal(record.kind, 'matched-development-comparison');
    assert.equal(record.scored, false);
    assert.equal(record.cases.length, 1);
    assert.equal(record.cases[0].familyId, 'D01');
    assert.deepEqual(record.privacyFilterArm, MATCHED_PRIVACY_FILTER_ARM);
    // `--case` restricts the run, and the identity block then names only that case's controls.
    assert.equal(record.identity.declaredControlsForRun.length, 7);
    assert.equal(record.identity.declaredControlsForRun.every((item) => item.caseId === 'D01-DEV-001'),
      true);
    assert.equal(record.cases[0].controlsPlanted, 7);
    for (const planted of PLANTED) {
      assert.equal(result.stdout.includes(planted), false, `printed record must not carry ${planted}`);
    }
  });