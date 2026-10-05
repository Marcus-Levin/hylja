// #250 confidentiality probe for the demo evidence. Run by the demo E2E suite under `node --test`.
//
// What this proves, by running rather than by reading source: a real subprocess whose ACTUAL output
// carries the planted original, the planted secret and the fixed refusal text can be put into a real
// assertion path - including a comparison that really FAILS - and neither the passing assertions nor the
// failing one report any of it. The suite that spawns this probe captures the TAP output the real test
// runner produced and asserts, from the outside, that no planted value is in it.
//
// Non-vacuity matters here. A confidentiality check that never sees protected material proves nothing, so
// this probe first asserts that the fixture subprocess really printed both planted values, and then
// deliberately fails one comparison over that same captured stream and inspects the failure report.
//
// What it is NOT: not a secret detector, not an enforcement boundary, not a held-out or scored result.
// Every value involved is this repository's own invented, non-routable synthetic material.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { MASKED, PLANTED_ORIGINAL, PLANTED_SECRET }
  from '../../scripts/lib/synthetic-conversation-fixture.mjs';
import { runNode, TEST_TIMEOUT_MS } from './run-node-subprocess.mjs';

const FAULT_DRIVER = fileURLToPath(new URL('./synthetic-conversation-demo-fault-driver.mjs', import.meta.url));
/** A fixed, safe, static expected string: nothing planted and nothing captured goes into it. */
const NOT_WHAT_THIS_RUN_PRINTS = 'hylja synthetic conversation demo fault driver: argument refused\n'
  + 'expected: terminate-second-worker | leak-planted-diagnostics\n';

test('a subprocess output carrying planted material enters the assertion path and reports none of it',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const run = await runNode(FAULT_DRIVER, ['leak-planted-diagnostics']);
    // The fixture really printed the planted values, so every comparison below is over output that
    // genuinely carries protected material rather than over output that happens to be clean.
    assert.equal(run.stdout.includes(PLANTED_ORIGINAL) || run.stderr.includes(PLANTED_ORIGINAL), true,
      'the fixture subprocess really printed the planted original');
    assert.equal(run.stderr.includes(PLANTED_SECRET), true,
      'the fixture subprocess really printed the planted secret');
    assert.equal(run.stderr.includes(NOT_WHAT_THIS_RUN_PRINTS), false,
      'the captured stream is not the static expected refusal text, so the comparison below is a real failure');
    // A deliberately FAILING comparison over the captured stream. Its report is caught here instead of
    // being reported, so this probe can inspect what a failing assertion would actually have said.
    let report = '';
    try {
      assert.equal(run.stderr === NOT_WHAT_THIS_RUN_PRINTS, true,
        'a deliberately failing comparison over a captured stream carrying planted material');
    } catch (error) {
      report = error instanceof Error ? error.message : String(error);
    }
    assert.equal(report.length > 0, true, 'that comparison really failed, so the report below is a real one');
    assert.equal(report.includes(PLANTED_ORIGINAL), false,
      'the failing report carries no planted original');
    assert.equal(report.includes(PLANTED_SECRET), false,
      'the failing report carries no planted secret');
    assert.equal(report.includes(MASKED), false,
      'the failing report carries no mask literal');
    assert.equal(report.includes(run.stderr), false,
      'the failing report does not carry the captured stream itself');
    // What the fixture run really did, all of it a boolean or a fixed count.
    assert.equal(run.stalled, false, 'the faulted invocation finished inside its bound');
    assert.equal(run.signal, null, 'the faulted run exited on its own, with no signal');
    assert.equal(run.code, 1, 'a terminated fixed worker makes the demonstration decline itself');
    assert.equal(run.stdout.includes(MASKED), false,
      'the faulted run printed the generic mask literal in no stream');
  });