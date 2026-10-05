// #250 confidentiality probe for the demo evidence. Run by the demo E2E suite under `node --test`.
//
// What this proves, by running rather than by reading source: a real subprocess whose ACTUAL output
// carries the planted original, the planted secret and the fixed refusal text can be put into a real
// assertion path - including a comparison that really FAILS - and neither the passing assertions nor the
// failing one report any of it.
//
// THIS FILE FAILS ON PURPOSE, AND THAT IS ITS OUTPUT. The designated comparison below is the last
// statement of the only test here and is deliberately left UNCAUGHT, so the real test runner really
// serializes a real failure: this run exits non-zero and prints a real `not ok` entry with its real
// failure count. `test/synthetic-conversation-demo.e2e.test.mjs` spawns this file, captures that TAP and
// asserts from the outside that the report carries none of the planted values. Catching the failure here
// and inspecting the message instead would have observed no runner at all.
//
// Non-vacuity comes first: this probe asserts, through booleans only, that the fixture subprocess really
// printed both planted values and that the designated comparison really is a failing one. Only then does
// the failure happen, so the report below is about output that genuinely carries protected material.
//
// The unsafe counterpart - the same comparison with the captured stream itself as the expected operand,
// which really does leak it - is `synthetic-conversation-demo-unsafe-negative-control.test.mjs`. It is
// run by the same suite, and its leaking TAP is captured there and only ever reduced to booleans, so the
// leak this probe avoids is demonstrated rather than assumed.
//
// Every value involved is this repository's own invented, non-routable synthetic material. This is not a
// secret detector, not an enforcement boundary, and not a held-out, scored or promotion result.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { MASKED, PLANTED_ORIGINAL, PLANTED_SECRET }
  from '../../scripts/lib/synthetic-conversation-fixture.mjs';
import { runNode, TEST_TIMEOUT_MS } from './run-node-subprocess.mjs';

const FAULT_DRIVER = fileURLToPath(new URL('./synthetic-conversation-demo-fault-driver.mjs', import.meta.url));
/**
 * A fixed, safe, static expected string: nothing planted and nothing captured goes into it. The captured
 * stream is compared with it behind a BOOLEAN, so neither operand can ever reach a report.
 */
const NOT_WHAT_THIS_RUN_PRINTS = 'hylja synthetic conversation demo fault driver: argument refused\n'
  + 'expected: terminate-second-worker | leak-planted-diagnostics\n';
/** The fixed message of the designated failing assertion. Declared here, and matched by the suite. */
export const DESIGNATED_FAILURE_MESSAGE =
  'this probe ends on a deliberately failing boolean comparison over a captured stream';

test('a subprocess output carrying planted material enters the assertion path and reports none of it',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const run = await runNode(FAULT_DRIVER, ['leak-planted-diagnostics']);
    // The fixture really printed the planted values, so every comparison below is over output that
    // genuinely carries protected material rather than over output that happens to be clean. Each of
    // these is a boolean, so a failure reports the boolean and nothing else.
    assert.equal(run.stdout.includes(PLANTED_ORIGINAL) || run.stderr.includes(PLANTED_ORIGINAL), true,
      'the fixture subprocess really printed the planted original');
    assert.equal(run.stderr.includes(PLANTED_SECRET), true,
      'the fixture subprocess really printed the planted secret');
    assert.equal(run.stderr === NOT_WHAT_THIS_RUN_PRINTS, false,
      'the designated comparison is a real failing one: the captured stream is not this static text');
    // What the fixture run really did, all of it a boolean or a fixed count, before the failure below.
    assert.equal(run.stalled, false, 'the faulted invocation finished inside its bound');
    assert.equal(run.signal, null, 'the faulted run exited on its own, with no signal');
    assert.equal(run.code, 1, 'a terminated fixed worker makes the demonstration decline itself');
    assert.equal(run.stdout.includes(MASKED), false,
      'the faulted run printed the generic mask literal in no stream');
    // The DESIGNATED FAILURE, deliberately uncaught and deliberately last. Both operands are booleans
    // and the message is fixed, so what the runner serializes below is that boolean pair and this
    // message - not one byte of the captured stream.
    assert.equal(run.stderr === NOT_WHAT_THIS_RUN_PRINTS, true, DESIGNATED_FAILURE_MESSAGE);
  });