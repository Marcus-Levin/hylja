import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { runPresidioDevelopmentTrial } from '../evaluations/presidio-development-trial.mjs';
import { completePresidioAnalysis, preparePresidioAnalysis } from '../dist/presidio-candidate-source.js';
import { normalizeInput } from '../dist/normalization.js';

const SCOPE_REFS = { requestId: 'req-synthetic-0001', inputRef: 'n6-aaaaaaaaaaaaaaaa-v0-raw',
  tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01',
  expectedProducerVersion: 'fake0', expectedLanguage: 'en', expectedNerAvailable: false };
function planFor() {
  const prepared = preparePresidioAnalysis(normalizeInput('contact demo@example.invalid'),
    { kind: 'VIEW', viewId: 0, representation: 'RAW', source: 'STRING', unit: { start: 0, end: 1 } },
    SCOPE_REFS);
  assert.equal(prepared.ok, true);
  return prepared.plan;
}
function replyFor(plan, mutate = {}) {
  const { binding } = plan;
  return JSON.stringify({ version: 1, protocol: 'hylja.presidio.worker', requestId: binding.requestId,
    inputRef: binding.inputRef, tenantRef: binding.tenantRef, projectRef: binding.projectRef,
    representation: binding.representation, textDigest: binding.textDigest, offsetUnit: 'CODE_POINT',
    status: 'OK', results: [],
    filtering: { scoreThreshold: 0, deduplicate: true, allowListCount: 0, allowListMatch: 'NONE',
      context: 'UNAVAILABLE_NO_NLP', decisionProcess: 'NOT_REQUESTED' },
    runtime: { version: plan.expectedProducerVersion, language: plan.expectedLanguage,
      nerAvailable: plan.expectedNerAvailable }, unsupported: [], ...mutate }) + '\n';
}

// The #5 bridge itself is exercised with the generated fake worker, so the deterministic suite
// proves the wiring, the byte-span conversion and the report's privacy properties without any
// screened third-party stack. The real pinned stack is run separately through the same code path.
const WORKER = new URL('../test/fixtures/presidio-fake-worker/fake_worker.py', import.meta.url).pathname;
const PYTHON = process.env.HYLJA_TEST_PYTHON ?? 'python3';
const skip = spawnSync(PYTHON, ['-c', 'import sys'], { timeout: 20_000 }).status === 0
  ? false : 'no usable python3 interpreter for the evaluation bridge test';
let workspace;
/**
 * One file plays both roles here: the fake worker reads its control from it and the CLI reads the pin
 * from it, exactly as the real trial reads `manifest.json` while the real worker reads the installed
 * package metadata. `runtimeVersion`/`language` are what the worker reports, so a disagreement in a
 * test is always a deliberate edit rather than an accident of construction.
 */
function manifest(overrides) {
  if (!workspace) workspace = mkdtempSync(join(tmpdir(), 'hylja-presidio-trial-'));
  const path = join(workspace, `manifest-${Math.random().toString(16).slice(2)}.json`);
  writeFileSync(path, JSON.stringify({ protocol: 'hylja.presidio.worker', version: 1,
    runtimeVersion: 'fake0', language: 'en',
    configuration: { language: 'en', nlpEngine: { nerAvailable: false },
      filtering: { requestScoreThreshold: null, deduplicate: true,
        decisionProcess: false, context: 'UNAVAILABLE_NO_NLP' } },
    artifacts: [{ name: 'presidio_analyzer', version: 'fake0' }], ...overrides }), 'utf8');
  return path;
}
const command = () => ({ pythonPath: PYTHON, workerScript: WORKER, startupTimeoutMs: 30_000,
  executionTimeoutMs: 30_000, cwd: workspace ?? tmpdir() });
const scope = { tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01',
  expectedProducerVersion: 'fake0', expectedLanguage: 'en', expectedNerAvailable: false };
process.on('exit', () => { if (workspace) rmSync(workspace, { recursive: true, force: true }); });

test('the trial reports privacy-safe records and no capture for the public development cases',
  { skip }, async () => {
    const trial = await runPresidioDevelopmentTrial({
      command: command(), caseIds: ['D01-DEV-001', 'D02-DEV-001'],
      manifest: manifest({ mode: 'scan' }), workdir: workspace, scope,
    });
    assert.equal(trial.scored, false);
    assert.equal(trial.enforcing, false);
    assert.equal(trial.mappingVersion, 'presidio-entity-map/1');
    assert.equal(trial.cases.length, 2);
    for (const entry of trial.cases) {
      assert.equal(entry.caseId, 'case-1', 'report refs are evaluator-minted ordinals');
      assert.equal(entry.transportFailures.length, 0);
      // Nothing was sent, so the escape and task claims stay untested rather than passing.
      assert.ok(entry.report.untested.includes('task-correctness/no-task-control'));
      assert.equal(entry.report.observed.includes('secret-plaintext-escape'), false);
      assert.ok(entry.provenance.producerId === 'presidio-analyzer');
      // The fake worker has no NER, so no run may read as a clean complete analysis.
      assert.equal(entry.adapterStatus, 'PARTIAL');
      assert.deepEqual(entry.reasons, ['NO_NER_CAPABILITY']);
      assert.ok(entry.limitations.includes('NO_NER'));
    }
    // The record itself carries codes, counts and ordinal refs only.
    const serialized = JSON.stringify(trial);
    for (const planted of ['person.alpha@example.invalid', '+1 202-555-0101', 'Demo Person Alpha',
      'diag-node.example.invalid', '192.0.2.17', 'DEMO-NONLIVE-TOKEN-NOT-VALID',
      'service.demo.invalid', 'Customer Demo-West']) {
      assert.equal(serialized.includes(planted), false, `trial record must not carry ${planted}`);
    }
  });

test('a transport failure is an explicit per-field failure, never a zero-findings pass', { skip }, async () => {
  const trial = await runPresidioDevelopmentTrial({
    command: command(), caseIds: ['D01-DEV-001'], manifest: manifest({ mode: 'crash', exitCode: 5 }),
    workdir: workspace, scope,
  });
  const [entry] = trial.cases;
  assert.equal(entry.adapterStatus, 'FAILURE');
  assert.equal(entry.transportFailures.length, 1);
  assert.equal(entry.transportFailures[0].reason, 'WORKER_CRASHED');
  assert.equal(entry.emittedEvents, 0);
  assert.equal(entry.provenance, null);
  assert.equal(entry.report.candidates.matched, 0);
  assert.equal(entry.report.candidates.misses, 3);
  // A miss is still a miss: an unavailable detector is not silently counted as a clean result.
  assert.ok(entry.report.untested.includes('task-correctness/no-task-control'));
});

test('an unmapped entity type from the worker stays explicit in the evaluation record', { skip }, async () => {
  const trial = await runPresidioDevelopmentTrial({
    command: command(), caseIds: ['D01-DEV-001'],
    manifest: manifest({ mode: 'scan', entityType: 'US_SSN' }),
    workdir: workspace, scope,
  });
  const [entry] = trial.cases;
  assert.deepEqual(entry.unsupportedEntityTypes, ['US_SSN']);
  assert.ok(entry.reasons.includes('UNSUPPORTED_ENTITY_TYPE'));
  assert.ok(entry.limitations.includes('UNSUPPORTED_ENTITY_TYPES'));
  assert.equal(entry.emittedEvents, 0, 'an unmapped type becomes no Hylja candidate at all');
});

test('the delivered bridge refuses a worker that claims the NER capability its pin denies',
  { skip }, async () => {
    // End-to-end form of the adapter-level pin regression: the manifest pins a no-NLP engine, the
    // generated worker is told to claim NER anyway, and nothing about the rest of the run changes.
    const trial = await runPresidioDevelopmentTrial({
      command: command(), caseIds: ['D01-DEV-001'], manifest: manifest({ mode: 'scan', nerAvailable: true }),
      workdir: workspace, scope,
    });
    const [entry] = trial.cases;
    assert.equal(entry.adapterStatus, 'FAILURE');
    assert.deepEqual(entry.reasons, ['NER_CAPABILITY_MISMATCH']);
    assert.equal(entry.emittedEvents, 0);
    // A refused frame records no identity at all: `UNREPORTED` version/language and the conservative
    // `nerAvailable: false` default, never the worker's claim.
    assert.deepEqual(entry.provenance, { producerId: 'presidio-analyzer', producerVersion: 'UNREPORTED',
      mappingVersion: 'presidio-entity-map/1', labelVocabularyVersion: 'presidio-label-vocabulary/1',
      language: 'UNREPORTED', nerAvailable: false });
    assert.deepEqual(entry.fields.map((field) => field.emitted), [0]);
    assert.equal(entry.report.candidates.misses, 3, 'every control is a miss, not a silent pass');
    // Nothing in the printed record reports a capability the pin denies: no `NO_NER`/
    // `NO_TEXT_CONTEXT` limitation for a run that produced nothing, and the conservative
    // `nerAvailable: false` default rather than the worker's claim.
    assert.deepEqual(entry.limitations, []);
    assert.equal(entry.provenance.nerAvailable, false);
    assert.equal(JSON.stringify(trial).includes('NO_TEXT_CONTEXT'), false);
  });

test('a planted entity-type or seam label cannot reach the shared trial record on ANY reply status',
  { skip }, async () => {
    const planted = 'DEMONONLIVETOKENNOTVALID'.repeat(2);
    // Declared with no finding behind it: counted, never named.
    const declaredOnly = await runPresidioDevelopmentTrial({
      command: command(), caseIds: ['D01-DEV-001'],
      manifest: manifest({ mode: 'scan', entityType: 'US_SSN',
        unsupported: [{ entityType: planted, count: 4 }] }),
      workdir: workspace, scope,
    });
    const [entry] = declaredOnly.cases;
    assert.equal(entry.declaredUnsupportedTypes, 1);
    // Only the type the adapter actually refused appears; the planted declaration is a bare count.
    assert.deepEqual(entry.unsupportedEntityTypes, ['US_SSN']);
    assert.equal(JSON.stringify(declaredOnly).includes(planted), false);
    // A canonical pinned-release type the adapter actually refused keeps its name.
    const corroborated = await runPresidioDevelopmentTrial({
      command: command(), caseIds: ['D01-DEV-001'],
      manifest: manifest({ mode: 'scan', entityType: 'US_SSN' }),
      workdir: workspace, scope,
    });
    assert.deepEqual(corroborated.cases[0].unsupportedEntityTypes, ['US_SSN']);
    assert.equal(JSON.stringify(corroborated).includes(planted), false);
    // The worker-chosen *type* case: the planted token is BOTH the result's entity type and its
    // declaration. Two agreeing strings from one untrusted worker are not corroboration, and a
    // grammar-legal identifier is not an authenticated identity, so the printed record keeps counts.
    const workerChosen = await runPresidioDevelopmentTrial({
      command: command(), caseIds: ['D01-DEV-001'],
      manifest: manifest({ mode: 'scan', entityType: planted, pattern: '\\S+',
        unsupported: [{ entityType: planted, count: 4 }] }),
      workdir: workspace, scope,
    });
    const [chosen] = workerChosen.cases;
    assert.deepEqual(chosen.unsupportedEntityTypes, [], 'an unvouched label is never named');
    assert.ok(chosen.unpinnedUnsupportedLabels > 0, 'the dropped label is counted');
    assert.ok(chosen.unpinnedUnsupportedResults > 0, 'so is the evidence it covered');
    assert.ok(chosen.reasons.includes('UNSUPPORTED_ENTITY_TYPE'));
    assert.equal(chosen.emittedEvents, 0, 'an unvouched type produces no Hylja candidate at all');
    assert.equal(JSON.stringify(workerChosen).includes(planted), false);
    // The worker-chosen *seam* case: a supported type, so real candidates are emitted, with both seam
    // identifiers set to the planted token. Only the labels are withheld, never the span.
    const seamLabels = await runPresidioDevelopmentTrial({
      command: command(), caseIds: ['D01-DEV-001'],
      manifest: manifest({ mode: 'scan', entityType: 'EMAIL_ADDRESS',
        seam: { patternName: planted, recognizerId: planted, enhancedByContext: false } }),
      workdir: workspace, scope,
    });
    assert.ok(seamLabels.cases[0].emittedEvents > 0, 'a supported type still yields real candidates');
    assert.equal(JSON.stringify(seamLabels).includes(planted), false);
    // The pinned recognizer id is reportable in a result's producer evidence (the adapter regression
    // covers that); this bridge never prints seam evidence at all, so neither the pinned name nor a
    // pattern name may appear in the record.
    const pinned = await runPresidioDevelopmentTrial({
      command: command(), caseIds: ['D01-DEV-001'],
      manifest: manifest({ mode: 'scan', entityType: 'EMAIL_ADDRESS',
        seam: { patternName: 'IPv4', recognizerId: 'EmailRecognizer', enhancedByContext: false } }),
      workdir: workspace, scope,
    });
    assert.ok(pinned.cases[0].emittedEvents > 0, 'a supported type still yields real candidates');
    assert.equal(JSON.stringify(pinned).includes('IPv4'), false, 'a pattern name is never carried');
    assert.equal(JSON.stringify(pinned).includes(planted), false);
    // A worker `FAILURE` is an ordinary diagnostic path (unusable manifest, import error) and is the
    // one most likely to carry a pasted type name, so it must drop the label too.
    const failed = await runPresidioDevelopmentTrial({
      command: command(), caseIds: ['D01-DEV-001'],
      manifest: manifest({ mode: 'crash', exitCode: 6 }),
      workdir: workspace, scope,
    });
    assert.equal(JSON.stringify(failed).includes(planted), false);
    // And the adapter-level branch, driven directly with a `FAILURE` frame that declares the token.
    const plan = planFor();
    const frame = JSON.parse(replyFor(plan, { status: 'FAILURE', results: [] }));
    frame.unsupported = [{ entityType: planted, count: 4 }];
    const refusal = completePresidioAnalysis(plan, JSON.stringify(frame) + '\n');
    assert.equal(refusal.status, 'FAILURE');
    assert.ok(refusal.reasons.includes('WORKER_REPORTED_FAILURE'));
    assert.deepEqual(refusal.unsupported, [], 'a refused runtime reports no declared type name');
    assert.equal(refusal.declaredUnsupportedTypes, 1);
    assert.equal(JSON.stringify(refusal).includes(planted), false);
  });

test('an unknown case or missing argument fails before any worker process starts', { skip }, async () => {
  await assert.rejects(runPresidioDevelopmentTrial({
    command: command(), caseIds: ['D09-DEV-999'], manifest: manifest({}), workdir: workspace, scope,
  }), TypeError);
});

test('the documented command line runs the same bridge and prints only the privacy-safe record',
  { skip }, async () => {
    const script = new URL('../evaluations/presidio-development-trial.mjs', import.meta.url).pathname;
    const args = ['--python', PYTHON, '--worker', WORKER, '--manifest', manifest({ mode: 'scan' }),
      '--workdir', workspace ?? tmpdir(), '--tenant', 'tenant-synthetic-01',
      '--project', 'project-synthetic-01', '--case', 'D01-DEV-001'];
    const result = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', timeout: 120_000 });
    assert.equal(result.status, 0, result.stderr);
    const record = JSON.parse(result.stdout);
    assert.equal(record.kind, 'presidio-development-trial');
    assert.equal(record.scored, false);
    assert.equal(record.cases.length, 1);
    assert.equal(record.cases[0].familyId, 'D01');
    assert.equal(record.cases[0].transportFailures.length, 0);
    for (const planted of ['person.alpha@example.invalid', '+1 202-555-0101', 'Demo Person Alpha']) {
      assert.equal(result.stdout.includes(planted), false);
    }
    // A wrong or missing argument is refused without echoing a value or a path.
    for (const bad of [['--python'], ['--nonsense', 'x'], ['--case']]) {
      const refused = spawnSync(process.execPath, [script, ...bad], { encoding: 'utf8', timeout: 60_000 });
      assert.notEqual(refused.status, 0);
      assert.equal(refused.stdout.includes('presidio-development-trial'), false);
      assert.equal(/synthetic-planted/.test(refused.stderr), false);
    }
  });
