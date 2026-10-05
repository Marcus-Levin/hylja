// #250 focused tests for the test-only subprocess helper the demo evidence runs on.
//
// What this proves, by running real children: the helper reports what actually happened, and a failure
// to RUN never escapes as a raw exception or as a checkout path in diagnostics. A synchronous spawn
// exception, an asynchronous `error` from the spawn itself and a child whose required pipes are missing
// all settle ONCE with the same fixed restrictive outcome: no exit code, no signal, no captured text
// and the fixed `transportFailure` flag. An ordinary non-zero exit is NOT a transport failure - the exit
// code, the signal and the captured streams survive, which is what lets the confidentiality evidence
// read a real failing TAP report. A stall inside the bound is reported as a stall and stops only the
// child this helper owns. A child that really runs is the control for all of it.
//
// The descriptor-exhaustion case runs one real child under a lowered descriptor limit, so the failure is
// a genuine native `EMFILE` and not a simulated one; it is skipped, with a fixed reason, where that
// limit cannot be lowered.
//
// Nothing here calls a provider, uses a credential or reaches the network, and every value involved is
// this repository's own invented material.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import {
  BOUND_MS, MAX_CAPTURE_BYTES, REPO_ROOT, TEST_TIMEOUT_MS, runNode, runNodeFixture, runNodeTest,
} from './support/run-node-subprocess.mjs';

const FIXTURE = fileURLToPath(new URL('./support/run-node-subprocess-fixture.mjs', import.meta.url));
const FAILING_CONTROL = fileURLToPath(
  new URL('./support/run-node-subprocess-failing-control.test.mjs', import.meta.url),
);
/** A fixed message declared here, not captured: the control's own deliberately failing assertion text. */
const CONTROL_MESSAGE = 'this control fails on purpose';
/** Short enough to keep the suite quick, long enough that a healthy child never reaches it. */
const SHORT_BOUND_MS = 1_500;
/** Long enough that a loaded host has started the fixture and its descendant before the stall fires. */
const TREE_BOUND_MS = 3_000;

/** The pid a fixture published, or `null` while nothing complete has been published. */
function publishedPid(file) {
  try {
    const text = readFileSync(file, 'utf8').trim();
    return /^[0-9]+$/.test(text) ? Number(text) : null;
  } catch {
    return null;
  }
}

/**
 * Whether the process is really still RUNNING, observed from the OS: a signal-0 probe, then (where the OS
 * exposes it) the process state, because an exited process that has not been reaped yet still answers a
 * signal-0 probe and is a zombie, not a running descendant. A process this check cannot read is running.
 */
function isRunning(pid) {
  try {
    process.kill(pid, 0);
  } catch (error) {
    return error.code === 'EPERM';
  }
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    return stat.slice(stat.lastIndexOf(')') + 2, stat.lastIndexOf(')') + 3) !== 'Z';
  } catch {
    return true;
  }
}

/** Stop a process this test started, whatever the helper did, so a failing run leaves nothing behind. */
function reap(pid) {
  if (pid === null) return;
  try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ }
}

const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

test('a child that really runs reports its own exit code and both captured streams', { timeout: TEST_TIMEOUT_MS },
  async () => {
    const run = await runNode(FIXTURE, []);
    assert.equal(run.transportFailure, false, 'a working child is not a transport failure');
    assert.equal(run.stalled, false, 'the working run finished inside the default bound');
    assert.equal(run.code, 0, 'the working run exited zero');
    assert.equal(run.signal, null, 'the working run exited on its own');
    assert.equal(run.stdout.includes('a working run'), true, 'its stdout was captured');
    assert.equal(run.stderr, '', 'it printed nothing on stderr');
  });

test('an ordinary non-zero exit keeps its code and its output, and is not a transport failure', { timeout: TEST_TIMEOUT_MS },
  async () => {
    const run = await runNode(FIXTURE, ['failing']);
    assert.equal(run.transportFailure, false, 'a failing test is not a transport failure');
    assert.equal(run.stalled, false, 'the failing run finished inside the default bound');
    assert.equal(run.code, 1, 'the failing run reported its own exit code');
    assert.equal(run.signal, null, 'the failing run exited on its own, not on a signal');
    assert.equal(run.stderr.includes('an ordinary failing run'), true, 'its stderr was captured');
    assert.equal(run.stdout, '', 'it printed nothing on stdout');
  });

test('a failing `node --test` run keeps its TAP and its non-zero exit', { timeout: TEST_TIMEOUT_MS }, async () => {
  const run = await runNodeTest(FAILING_CONTROL);
  assert.equal(run.transportFailure, false, 'a failing test run is not a transport failure');
  assert.equal(run.stalled, false, 'the failing test run finished inside the default bound');
  assert.equal(run.code, 1, 'the test runner really reported a failing run');
  assert.equal(run.signal, null, 'the test runner exited on its own');
  const tap = `${run.stdout}${run.stderr}`;
  assert.equal(tap.includes('not ok 1'), true, 'the real TAP report of the failing test was captured');
  assert.equal(tap.includes('# fail 1'), true, 'the real failure count was captured');
  assert.equal(tap.includes(CONTROL_MESSAGE), true,
    'the report is the runner own serialization of the control real failure, not a substitute');
  // Deliberately NOT asserted: that the report contains no checkout path. The real test runner prints
  // its own file URLs in every failing assertion's stack, so path absence would be a false invariant
  // that hides the property that matters: the fixed transport outcome above carries no captured text at
  // all, and the demo E2E shows that a run whose captured stream really carries planted material still
  // reports none of it.
});

test('a synchronous spawn exception settles once with the fixed restrictive outcome', { timeout: TEST_TIMEOUT_MS },
  async () => {
    const run = await runNodeFixture({ entry: FIXTURE, args: [], spawnOptions: { stdio: ['ignore', 'pipe', 'not-a-stream'] } });
    assert.equal(run.transportFailure, true, 'a spawn that throws is a transport failure');
    assert.equal(run.code, null, 'no exit code is invented for a child that never ran');
    assert.equal(run.signal, null, 'no signal is invented for a child that never ran');
    assert.equal(run.stalled, false, 'a spawn that threw is not a stall');
    assert.equal(run.stdout, '', 'nothing is captured when the child never ran');
    assert.equal(run.stderr, '', 'no native error text and no checkout path is reported');
  });

test('an asynchronous spawn error settles once with the fixed restrictive outcome', { timeout: TEST_TIMEOUT_MS },
  async () => {
    const run = await runNodeFixture({ entry: FIXTURE, args: [], spawnOptions: { cwd: '/nonexistent-run-node-subprocess-probe' } });
    assert.equal(run.transportFailure, true, 'a spawn that reports an error is a transport failure');
    assert.equal(run.code, null, 'no exit code is invented');
    assert.equal(run.signal, null, 'no signal is invented');
    assert.equal(run.stdout, '', 'nothing is captured');
    assert.equal(run.stderr, '', 'no native error text and no checkout path is reported');
  });

test('a child whose required pipes are missing settles once with the fixed restrictive outcome', { timeout: TEST_TIMEOUT_MS },
  async () => {
    const run = await runNodeFixture({ entry: FIXTURE, args: [], spawnOptions: { stdio: 'ignore' } });
    assert.equal(run.transportFailure, true, 'a run whose output cannot be captured is a transport failure');
    assert.equal(run.code, null, 'no exit code is reported for a run that was not observed');
    assert.equal(run.signal, null, 'no signal is reported');
    assert.equal(run.stdout, '', 'nothing is captured');
    assert.equal(run.stderr, '', 'nothing is reported');
  });

test('a stall inside the bound is reported as a stall, and only the owned child is stopped', { timeout: TEST_TIMEOUT_MS },
  async () => {
    const run = await runNodeFixture({ entry: FIXTURE, args: ['stall'], boundMs: SHORT_BOUND_MS });
    assert.equal(run.stalled, true, 'the stalled run is reported as a stall');
    assert.equal(run.code, null, 'a stopped child reported no exit code of its own');
    assert.equal(typeof run.signal, 'string', 'the stop really was a signal');
    assert.equal(run.stdout, '', 'a stopped run captured nothing');
    assert.equal(run.stderr, '', 'a stopped run reported nothing');
  });

test('a stalled run takes down its whole process tree before it returns', { timeout: TEST_TIMEOUT_MS }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'hylja-run-node-'));
  const file = join(directory, 'descendant.pid');
  let pid = null;
  let aliveWhileRunning = false;
  let watcher = null;
  try {
    const run = await runNodeFixture({
      entry: FIXTURE, args: ['descendant', file], boundMs: TREE_BOUND_MS,
      inspect: () => {
        // Observed, not assumed: the first time the descendant is published it must really be running.
        watcher = setInterval(() => {
          const seen = publishedPid(file);
          if (seen === null) return;
          clearInterval(watcher);
          aliveWhileRunning = isRunning(seen);
        }, 5);
      },
    });
    pid = publishedPid(file);
    const aliveAtReturn = pid !== null && isRunning(pid);
    assert.equal(run.stalled, true, 'the run stalled inside its short bound');
    assert.equal(pid !== null, true, 'the fixture really spawned a descendant');
    assert.equal(aliveWhileRunning, true, 'the descendant was really running before the stop, so the probe is not vacuous');
    assert.equal(aliveAtReturn, false, 'no descendant is still running once the helper has returned');
  } finally {
    clearInterval(watcher);
    reap(pid);
    rmSync(directory, { recursive: true, force: true });
  }
});

test('a run that exits normally leaves no running descendant behind either', { timeout: TEST_TIMEOUT_MS }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'hylja-run-node-'));
  const file = join(directory, 'orphan.pid');
  let pid = null;
  try {
    const run = await runNodeFixture({ entry: FIXTURE, args: ['orphan', file] });
    pid = publishedPid(file);
    const aliveAtReturn = pid !== null && isRunning(pid);
    assert.equal(run.transportFailure, false, 'a normal exit is not a transport failure');
    assert.equal(run.code, 0, 'the run reported its own exit code');
    assert.equal(run.stalled, false, 'the run did not stall');
    assert.equal(pid !== null, true, 'the fixture really spawned a descendant');
    assert.equal(aliveAtReturn, false, 'the descendant it left running is stopped before the helper returns');
  } finally {
    reap(pid);
    rmSync(directory, { recursive: true, force: true });
  }
});

test('a failed run stops retaining output at once, even while a process out of its reach keeps writing',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const directory = mkdtempSync(join(tmpdir(), 'hylja-run-node-'));
    const file = join(directory, 'stray.pid');
    const seen = { failed: false, arrivedAfterFailure: 0, retained: () => -1 };
    let pid = null;
    let watcher = null;
    try {
      const run = await runNodeFixture({
        entry: FIXTURE, args: ['stray', file], boundMs: 30_000,
        inspect: ({ child, retainedChunks }) => {
          seen.retained = retainedChunks;
          // A listener of this test's own, so the data that really keeps arriving is counted separately.
          child.stderr.on('data', () => { if (seen.failed) seen.arrivedAfterFailure += 1; });
          // Once the stray writer exists, the run really fails: a genuine error on the owned stdout pipe.
          watcher = setInterval(() => {
            if (publishedPid(file) === null) return;
            clearInterval(watcher);
            seen.failed = true;
            child.stdout.destroy(new Error('fixture pipe error'));
          }, 5);
        },
      });
      pid = publishedPid(file);
      const retainedAtReturn = seen.retained();
      await sleep(150);
      const retainedLater = seen.retained();
      assert.equal(run.transportFailure, true, 'a run that lost a pipe is a transport failure');
      assert.equal(seen.arrivedAfterFailure > 0, true,
        'output really kept arriving after the failure, so the retention check below is not vacuous');
      assert.equal(retainedAtReturn, 0, 'no chunk is retained when the helper returns');
      assert.equal(retainedLater, 0, 'no chunk is retained afterwards either');
    } finally {
      clearInterval(watcher);
      reap(pid);
      rmSync(directory, { recursive: true, force: true });
    }
  });

test('output beyond the retention bound fails the run closed and keeps nothing', { timeout: TEST_TIMEOUT_MS },
  async () => {
    let retained = () => -1;
    const run = await runNodeFixture({
      entry: FIXTURE, args: ['flood'], inspect: (probe) => { retained = probe.retainedChunks; },
    });
    assert.equal(run.transportFailure, true, 'a stream larger than the bound is a transport failure, not a capture');
    assert.equal(run.stdout === '' && run.stderr === '', true, 'nothing the overflowing run produced is returned');
    assert.equal(retained(), 0, 'nothing is retained after the overflow');
    assert.equal(MAX_CAPTURE_BYTES > 0 && MAX_CAPTURE_BYTES < 5 * 1024 * 1024, true, 'the bound is positive and below the flood');
  });

test('a real descriptor exhaustion is contained as a fixed transport failure', { timeout: TEST_TIMEOUT_MS },
  async (t) => {
    // One real child under a lowered descriptor limit, so the failure is a genuine native `EMFILE` and
    // not a simulated one. Skipped, with a fixed reason, where the limit cannot be lowered.
    const probe = spawn('/bin/sh', ['-c', 'ulimit -n 32 2>/dev/null || exit 9; exec "$0" "$1" descriptors',
      process.execPath, FIXTURE], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks = [];
    probe.stdout.on('data', (chunk) => { chunks.push(chunk); });
    probe.stderr.on('data', () => {});
    const done = new Promise((resolve) => { probe.on('close', (code) => { resolve(code); }); });
    const code = await done;
    if (code === 9) {
      t.skip('this host cannot lower the descriptor limit, so no native EMFILE was produced');
      return;
    }
    assert.equal(code, 0, 'the bounded descriptor fixture itself finished normally');
    const printed = Buffer.concat(chunks).toString('utf8');
    assert.equal(printed.includes('descriptor limit reached: yes'), true,
      'the bounded child really hit the native EMFILE');
    assert.equal(printed.includes('helper reported a transport failure: yes'), true,
      'the helper contained it as a fixed transport failure instead of letting it escape');
    assert.equal(printed.includes('helper reported an exit code: no'), true,
      'no exit code was invented for the child that never ran');
    assert.equal(printed.includes('helper captured any stream text: no'), true,
      'no error text and no checkout path reached the caller');
    assert.equal(printed.includes(REPO_ROOT), false, 'the bounded child reported no checkout path');
  });

test('the default bound is a real deadline, not a policy that stops valid work', () => {
  assert.equal(typeof BOUND_MS === 'number' && BOUND_MS > 0, true, 'the default bound is a positive number');
  assert.equal(typeof TEST_TIMEOUT_MS === 'number' && TEST_TIMEOUT_MS > BOUND_MS, true,
    'the test timeout outlasts the bound, so a bound expiry is observable rather than hidden');
});
