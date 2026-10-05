// #250 UNSAFE negative control for the confidentiality evidence. Run by the demo E2E suite.
//
// This file exists to make the safe comparison in `synthetic-conversation-demo-confidentiality-probe.test.mjs`
// non-vacuous by showing the unsafe one really leaks. It does exactly the one thing the probe refuses to
// do: it puts the CAPTURED STREAM ITSELF into an assertion as the expected operand of a comparison that
// really fails. The real test runner therefore serializes the whole captured stream - planted original,
// planted secret and all - into its report, and this process exits non-zero with a real `not ok` entry.
//
// Its leaking TAP is captured PRIVATELY by `test/synthetic-conversation-demo.e2e.test.mjs`: it is held in
// that process's memory and only ever reduced to BOOLEANS. Nothing compares it to another string, puts it
// in an assertion message, prints it or writes it anywhere. That is the only safe way to keep a leak on
// record, and it is why this control is test-only code under `test/support/`, which the suite glob never
// collects.
//
// The captured values are this repository's own invented, non-routable synthetic literals, printed by
// `test/support/synthetic-conversation-demo-fault-driver.mjs` for exactly this purpose.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { runNode, TEST_TIMEOUT_MS } from './run-node-subprocess.mjs';

const FAULT_DRIVER = fileURLToPath(new URL('./synthetic-conversation-demo-fault-driver.mjs', import.meta.url));
/** The same fixed static text the safe probe compares against - behind a boolean there, an operand here. */
const NOT_WHAT_THIS_RUN_PRINTS = 'hylja synthetic conversation demo fault driver: argument refused\n'
  + 'expected: terminate-second-worker | leak-planted-diagnostics\n';

test('this control leaks the captured stream into the report on purpose', { timeout: TEST_TIMEOUT_MS },
  async () => {
    const run = await runNode(FAULT_DRIVER, ['leak-planted-diagnostics']);
    // UNSAFE, ON PURPOSE: `run.stderr` is the EXPECTED operand, so this failing comparison reports the
    // captured stream - the planted original and the planted secret - in this file's own TAP output.
    assert.equal(run.stderr, NOT_WHAT_THIS_RUN_PRINTS, 'this control really leaks what it captured');
  });