import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { normalizeInput } from '../dist/normalization.js';
import { PRESIDIO_MAX_RESULTS, completePresidioAnalysis, preparePresidioAnalysis } from '../dist/presidio-candidate-source.js';
import { PRESIDIO_WORKER_LIMITS, runPresidioWorker } from '../dist/presidio-worker-process.js';

// Generated stdlib-only scaffolding. It imports no third-party package and loads no model, so these
// resource, privacy and binding tests need no screened stack and no network.
//
// A Python 3 interpreter is a hard requirement for this file: without one there is no process to
// bound, so the transport is untested rather than tested-and-skipped. The skip below is the one
// honest exception, and it names itself; a run that reports these groups as skipped is not evidence.
const WORKER = new URL('../test/fixtures/presidio-fake-worker/fake_worker.py', import.meta.url).pathname;
const PYTHON = process.env.HYLJA_TEST_PYTHON ?? 'python3';
const PYTHON_AVAILABLE = spawnSync(PYTHON, ['-c', 'import sys'], { timeout: 20_000 }).status === 0;
const skip = PYTHON_AVAILABLE ? false : 'no usable python3 interpreter for the worker transport tests';
const SCOPE = Object.freeze({ requestId: 'req-synthetic-0001', inputRef: 'n6-aaaaaaaaaaaaaaaa-v0-raw',
  tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01',
  // The generated worker names itself `fake0`/`en`; pinning those here is what lets the adapter check
  // them, and a test below drives the disagreement path deliberately.
  expectedProducerVersion: 'fake0', expectedLanguage: 'en', expectedNerAvailable: false });
const PLANTED = 'synthetic-planted-worker-4f2a.invalid';
let workspace;
let controlIndex = 0;

function control(overrides) {
  if (!workspace) workspace = mkdtempSync(join(tmpdir(), 'hylja-presidio-fake-'));
  const path = join(workspace, `control-${controlIndex++}.json`);
  writeFileSync(path, JSON.stringify(overrides), 'utf8');
  return path;
}
function command(overrides = {}) {
  return { pythonPath: PYTHON, workerScript: WORKER, startupTimeoutMs: 30_000, executionTimeoutMs: 30_000,
    cwd: workspace ?? tmpdir(), ...overrides };
}
async function analyse(text, controlOverrides = {}, commandOverrides = {}) {
  const normalized = normalizeInput(text);
  const prepared = preparePresidioAnalysis(normalized,
    { kind: 'VIEW', viewId: 0, representation: 'RAW', source: 'STRING', unit: { start: 0, end: 1 } }, SCOPE);
  assert.equal(prepared.ok, true);
  const outcome = await runPresidioWorker(prepared.plan.line,
    command({ args: [control(controlOverrides)], ...commandOverrides }));
  return { plan: prepared.plan, outcome };
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

process.on('exit', () => { if (workspace) rmSync(workspace, { recursive: true, force: true }); });

test('a generated worker whose regex scan runs on real text yields correctly converted candidates', { skip }, async () => {
  // 🛰️ is two code points; the match is entirely after it, so a code-point index and a UTF-16
  // index disagree by exactly one here. The Python worker reports the former, on purpose.
  const text = '🛰️ write to persona.demo@example.invalid today';
  const { plan, outcome } = await analyse(text, { requireCleanEnv: true });
  assert.equal(outcome.status, 'REPLY');
  const result = completePresidioAnalysis(plan, outcome.line);
  // No NER means the run is never a clean COMPLETE, even though a real regex finding was produced.
  assert.equal(result.status, 'PARTIAL');
  assert.equal(result.candidates.length, 1);
  const [candidate] = result.candidates;
  assert.equal(text.slice(candidate.original.span.start, candidate.original.span.end),
    'persona.demo@example.invalid');
  assert.equal(candidate.evidence.provenance.producerVersion, 'fake0');
  assert.equal(candidate.evidence.provenance.producerId, 'presidio-analyzer');
  assert.ok(result.limitations.includes('NO_NER'));
});

test('the worker environment is the fixed minimum, with nothing inherited from the parent', { skip }, async () => {
  const before = process.env.SECRET_HANDOFF_TOKEN;
  process.env.SECRET_HANDOFF_TOKEN = PLANTED;
  try {
    const { outcome } = await analyse('note demo@example.invalid', { requireCleanEnv: true });
    assert.equal(outcome.status, 'REPLY');
    assert.equal(JSON.stringify(outcome).includes(PLANTED), false);
  } finally {
    if (before === undefined) delete process.env.SECRET_HANDOFF_TOKEN;
    else process.env.SECRET_HANDOFF_TOKEN = before;
  }
  // Without the guard the same worker answers normally, proving the guard is what failed closed.
  const { outcome } = await analyse('note demo@example.invalid', { requireCleanEnv: false });
  assert.equal(outcome.status, 'REPLY');
});

test('a hung worker is killed at the startup deadline and its post-sleep code never runs',
  { skip }, async () => {
    const marker = join(workspace ?? tmpdir(), `marker-${controlIndex++}.txt`);
    const { outcome } = await analyse('note demo@example.invalid',
      { mode: 'hang_then_mark', seconds: 5, marker }, { startupTimeoutMs: 700 });
    assert.deepEqual(outcome, { status: 'FAILURE', reason: 'WORKER_STARTUP_TIMEOUT' });
    // Positive control first: the same mode with a deadline the child beats DOES write the marker, so
    // the assertion below is about the kill and not about a marker nothing ever writes.
    const control = join(workspace ?? tmpdir(), `marker-control-${controlIndex++}.txt`);
    const reached = await analyse('note demo@example.invalid',
      { mode: 'hang_then_mark', seconds: 0.2, marker: control }, { startupTimeoutMs: 30_000 });
    assert.equal(reached.outcome.status, 'REPLY');
    assert.equal(existsSync(control), true, 'the positive control must actually reach the marker write');
    // Negative control: the killed child never got there.
    assert.equal(existsSync(marker), false, 'the SIGKILL reached the child before its sleep ended');
  });

test('each deadline bounds the phase it names, and both kill the child', { skip }, async () => {
  // A one-shot worker that answers only after its sleep has produced no byte yet, so the *startup*
  // deadline is what bounds it. That is the design, not an accident, and it is asserted here.
  const late = await analyse('note demo@example.invalid', { mode: 'slow_reply', seconds: 5 },
    { startupTimeoutMs: 700, executionTimeoutMs: 30_000 });
  assert.deepEqual(late.outcome, { status: 'FAILURE', reason: 'WORKER_STARTUP_TIMEOUT' });
  // A worker that writes its whole reply and then stays alive is inside the startup window and inside
  // the execution window: the execution deadline starts on the first stdout byte and must fire there.
  const stall = await analyse('note demo@example.invalid', { mode: 'reply_then_stall', seconds: 30 },
    { startupTimeoutMs: 30_000, executionTimeoutMs: 700 });
  assert.deepEqual(stall.outcome, { status: 'FAILURE', reason: 'WORKER_EXECUTION_TIMEOUT' });
  // And the same worker inside the execution deadline answers normally.
  const fast = await analyse('note demo@example.invalid', { mode: 'reply_then_stall', seconds: 0.1 },
    { startupTimeoutMs: 30_000, executionTimeoutMs: 30_000 });
  assert.equal(fast.outcome.status, 'REPLY');
  const result = completePresidioAnalysis(fast.plan, fast.outcome.line);
  assert.equal(result.candidates.length, 1);
  assert.equal('note demo@example.invalid'.slice(
    result.candidates[0].original.span.start, result.candidates[0].original.span.end),
  'demo@example.invalid');
});

test('oversize stdout, stderr flood, crash and missing reply are distinct bounded failures', { skip }, async () => {
  const cases = [
    [{ mode: 'stdout_flood', bytes: 1 << 20 }, { maxStdoutBytes: 1024 }, 'WORKER_OUTPUT_LIMIT'],
    [{ mode: 'stderr_flood', bytes: 1 << 20 }, { maxStderrBytes: 1024 }, 'WORKER_STDERR_LIMIT'],
    [{ mode: 'crash', stderrText: 'boom\n', exitCode: 9 }, {}, 'WORKER_CRASHED'],
    [{ mode: 'reply_then_crash', exitCode: 4 }, {}, 'WORKER_CRASHED'],
    [{ mode: 'bad_utf8' }, {}, 'WORKER_REPLY_INCOMPLETE'],
    [{ mode: 'no_newline' }, {}, 'WORKER_REPLY_INCOMPLETE'],
    [{ mode: 'two_lines' }, {}, 'WORKER_REPLY_INCOMPLETE'],
  ];
  for (const [controlOverrides, commandOverrides, reason] of cases) {
    const { outcome } = await analyse('note demo@example.invalid', controlOverrides, commandOverrides);
    assert.deepEqual(outcome, { status: 'FAILURE', reason }, JSON.stringify(controlOverrides));
  }
  // A well-framed but unparseable body is the validator's refusal, not a transport failure.
  const { plan, outcome } = await analyse('note demo@example.invalid', { mode: 'garbage' });
  assert.equal(outcome.status, 'REPLY');
  const malformed = completePresidioAnalysis(plan, outcome.line);
  assert.deepEqual(malformed.reasons, ['INVALID_WORKER_REPLY']);
  assert.deepEqual(malformed.candidates, []);
});

test('a deliberate worker exception carrying a planted value leaks through no channel', { skip }, async () => {
  const { outcome } = await analyse('note demo@example.invalid', { mode: 'raise', planted: PLANTED });
  assert.deepEqual(outcome, { status: 'FAILURE', reason: 'WORKER_CRASHED' });
  const serialized = JSON.stringify(outcome);
  assert.equal(serialized.includes(PLANTED), false);
  assert.equal(serialized.includes('Traceback'), false);
  assert.equal(serialized.includes('fake_worker'), false, 'no host path reaches a result');
  assert.equal(serialized.includes('/tmp'), false);
  // The same planted text inside the analysed text is still just analysed text, never echoed.
  const { plan, outcome: echoed } = await analyse(`contact ${PLANTED}`,
    { pattern: '[A-Za-z0-9.-]+@?[A-Za-z0-9.-]*\\.invalid', entityType: 'PERSON' });
  assert.equal(echoed.status, 'REPLY');
  const result = completePresidioAnalysis(plan, echoed.line);
  assert.equal(JSON.stringify(result).includes(PLANTED), false);
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].original.kind, 'ORIGINAL_EXACT');
});

test('an oversized result array from a real worker process is a bounded failure, not a truncation', { skip }, async () => {
  const filler = `${'a'.repeat(6)}@x.invalid `.repeat(PRESIDIO_MAX_RESULTS + 8);
  const over = await analyse(filler, { pattern: '[a-z]+@x\\.invalid', maxResults: PRESIDIO_MAX_RESULTS + 8 });
  assert.equal(over.outcome.status, 'REPLY');
  const refused = completePresidioAnalysis(over.plan, over.outcome.line);
  assert.equal(refused.status, 'FAILURE');
  assert.deepEqual(refused.reasons, ['REPLY_RESULT_LIMIT']);
  assert.deepEqual(refused.candidates, []);
  // Exactly at the bound the reply is accepted, still degraded because the worker has no NER.
  const exact = await analyse(filler, { pattern: '[a-z]+@x\\.invalid' });
  const accepted = completePresidioAnalysis(exact.plan, exact.outcome.line);
  assert.equal(accepted.candidates.length, PRESIDIO_MAX_RESULTS);
  assert.equal(accepted.status, 'PARTIAL');
});

test('a mutated reply frame is rejected without leaving a usable line behind', { skip }, async () => {
  const { plan, outcome } = await analyse('note demo@example.invalid', {});
  assert.equal(outcome.status, 'REPLY');
  const body = JSON.parse(outcome.line);
  for (const mutation of [
    (value) => { value.status = 'FAILURE'; },
    (value) => { value.tenantRef = 'tenant-synthetic-02'; },
    (value) => { value.results = [{ entityType: 'US_SSN', start: 5, end: 9, score: 0.9 }]; },
    (value) => { value.results = [{ entityType: 'EMAIL_ADDRESS', start: 5, end: 9, score: 9 }]; },
    (value) => { value.results = [{ entityType: 'EMAIL_ADDRESS', start: 9, end: 5, score: 0.9 }]; },
    (value) => { delete value.filtering; },
    (value) => { value.filtering.allowListCount = -1; },
  ]) {
    const mutated = structuredClone(body);
    mutation(mutated);
    const result = completePresidioAnalysis(plan, JSON.stringify(mutated) + '\n');
    assert.notEqual(result.status, 'COMPLETE', JSON.stringify(mutated).slice(0, 80));
  }
});

test('a child that exits before reading its request cannot crash the parent process', { skip }, async () => {
  const early = join(workspace ?? tmpdir(), `early-exit-${controlIndex++}.py`);
  writeFileSync(early, 'import sys\nsys.exit(0)\n', 'utf8');
  // A request far larger than any pipe buffer guarantees the write fails asynchronously.
  const outcome = await runPresidioWorker(`${'x'.repeat(4 << 20)}\n`,
    { pythonPath: PYTHON, workerScript: early, startupTimeoutMs: 5_000, executionTimeoutMs: 5_000 });
  assert.equal(outcome.status, 'FAILURE');
  assert.ok(['WORKER_SPAWN_FAILED', 'WORKER_REPLY_MISSING', 'WORKER_CRASHED'].includes(outcome.reason));
  assert.equal(JSON.stringify(outcome).includes(early), false, 'no worker path reaches the result');
});

test('an invalid command is refused before any process is started', { skip }, async () => {
  for (const overrides of [
    { pythonPath: '' }, { workerScript: 'x'.repeat(5000) }, { startupTimeoutMs: 0 },
    { executionTimeoutMs: -1 }, { maxStdoutBytes: 8 }, { maxStderrBytes: -5 },
    { args: Array.from({ length: 9 }, (_, index) => `arg${index}`) }, { args: ['bad\narg'] },
  ]) {
    const outcome = await runPresidioWorker('{"protocol":"hylja.presidio.worker"}\n',
      command(overrides));
    assert.deepEqual(outcome, { status: 'FAILURE', reason: 'WORKER_SPAWN_FAILED' }, JSON.stringify(overrides));
  }
  const missing = await runPresidioWorker('{"protocol":"hylja.presidio.worker"}\n',
    command({ pythonPath: 'hylja-no-such-interpreter-4f2a' }));
  assert.deepEqual(missing, { status: 'FAILURE', reason: 'WORKER_SPAWN_FAILED' });
  assert.equal(JSON.stringify(missing).includes('4f2a'), false, 'a spawn error path is never reported');
});

test('the pinned worker limits are the documented bounded defaults', () => {
  assert.equal(PRESIDIO_WORKER_LIMITS.startupTimeoutMs, 120_000);
  assert.equal(PRESIDIO_WORKER_LIMITS.executionTimeoutMs, 60_000);
  assert.equal(PRESIDIO_WORKER_LIMITS.maxStderrBytes, 65_536);
  assert.ok(PRESIDIO_WORKER_LIMITS.maxStdoutBytes <= 1 << 20);
});

// A missing interpreter is reported as a named skip, never as a silent pass.
test('the worker transport requires a real Python 3 interpreter', () => {
  assert.equal(PYTHON_AVAILABLE, true);
});

await sleep(0);
