// #250 focused test: the demo's worker liveness is OBSERVED from the operating system, not counted.
//
// The demonstration's cleanup report says how many fixed-worker children are still live after cleanup.
// A handle counter cannot say that: it reports what this process still holds, not whether a recorded
// child process still exists. This test spawns one REAL fixed worker through the installed observation,
// reads its liveness while it runs, stops it, and reads it again once the operating system no longer
// knows the process. It also confirms a process that is not a fixed worker is never recorded.
//
// Nothing here calls a provider, uses a credential or reaches the network, and no byte of any worker
// reply is read or printed.
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import {
  installWorkerObservation, workerObservation, workersStillRunning,
} from '../scripts/lib/synthetic-conversation-worker-observation.mjs';

const WORKER = fileURLToPath(new URL('../dist/egress-sentinel-process-worker.js', import.meta.url));
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

test('a really running fixed worker is counted as live, and not once the OS no longer has it', async () => {
  installWorkerObservation();
  const before = workerObservation().spawned;
  // The one argument shape the accepted runner uses: the node executable and exactly one worker module.
  // Its stdin stays open, so the real worker waits for a request that never comes and keeps running.
  const worker = childProcess.spawn(process.execPath, [WORKER], { stdio: ['pipe', 'pipe', 'pipe'] });
  const closed = new Promise((resolve) => { worker.on('close', () => { resolve(true); }); });
  try {
    await sleep(200);
    const recorded = workerObservation().spawned - before;
    const whileRunning = workersStillRunning();
    assert.equal(recorded, 1, 'the real fixed worker was recorded');
    assert.equal(whileRunning, 1, 'the worker that is really running is reported as live');
    worker.kill('SIGKILL');
    await closed;
    let afterClose = workersStillRunning();
    for (let attempt = 0; attempt < 100 && afterClose !== 0; attempt += 1) {
      await sleep(10);
      afterClose = workersStillRunning();
    }
    assert.equal(afterClose, 0, 'once the OS no longer has the worker it is no longer reported');
  } finally {
    try { worker.kill('SIGKILL'); } catch { /* already gone */ }
  }
});

test('a process that is not a fixed worker is never recorded', async () => {
  installWorkerObservation();
  const before = workerObservation().spawned;
  const other = childProcess.spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
  await new Promise((resolve) => { other.on('close', () => { resolve(true); }); });
  assert.equal(workerObservation().spawned, before, 'no other spawn is observed');
});
