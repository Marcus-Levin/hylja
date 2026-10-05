#!/usr/bin/env node
/**
 * TEST-ONLY fixture for `test/run-node-subprocess.test.mjs`. Not a suite member and not an entry point
 * for any product command.
 *
 * Four fixed modes, so the subprocess helper can be exercised against a real child on every path that
 * matters - a working run, an ordinary non-zero exit, a stall inside the helper's bound, and descriptor
 * exhaustion in a process whose descriptor limit was lowered by its parent. Everything this file prints
 * is a fixed label or a boolean; nothing it prints is ever compared as a string by the suite, and no
 * planted or protected value exists here at all.
 *
 *   (no argument)  a working run: one fixed stdout line, exit 0
 *   --fail         an ordinary failing run: one fixed stderr line, exit 1, no signal
 *   --sleep        a stall: sleeps well past any bound the suite uses, until it is stopped
 *   --descriptors  reports whether this process really hit EMFILE, then really runs one child
 *
 * Any other argument is refused with one fixed line and exits 2, like every other fixture here.
 */
import { closeSync, openSync } from 'node:fs';
import { runNode } from './run-node-subprocess.mjs';

const MODES = Object.freeze({
  WORKING: 'working',
  FAILING: 'failing',
  STALL: 'stall',
  DESCRIPTORS: 'descriptors',
});
const KNOWN = new Set(Object.values(MODES));
const REFUSED = 'run-node-subprocess fixture: argument refused\n';

const mode = process.argv.length === 2 && KNOWN.has(process.argv[2]) ? process.argv[2] : MODES.WORKING;

if (process.argv.length > 2 && !KNOWN.has(mode)) {
  process.stderr.write(REFUSED);
  process.exitCode = 2;
} else if (mode === MODES.FAILING) {
  process.stderr.write('run-node-subprocess fixture: an ordinary failing run\n');
  process.exitCode = 1;
} else if (mode === MODES.STALL) {
  // Ten seconds: far longer than the bound the suite gives this run, short enough that a leaked handle
  // cannot outlive the suite by much even if the bound were removed.
  setTimeout(() => { process.exitCode = 0; }, 10_000);
} else if (mode === MODES.DESCRIPTORS) {
  // Open descriptors until the OS refuses, so the next real spawn really fails the way a busy process
  // fails. Only the fixed label below leaves this process.
  let exhausted = false;
  const opened = [];
  try {
    for (;;) opened.push(openSync('/dev/null', 'r'));
  } catch (error) { exhausted = error.code === 'EMFILE'; }
  for (const fd of opened) { try { closeSync(fd); } catch { /* the OS already refused more */ } }
  const run = await runNode(process.execPath, ['-e', '']);
  process.stdout.write(`descriptor limit reached: ${exhausted ? 'yes' : 'no'}\n`);
  process.stdout.write(`helper reported a transport failure: ${run.transportFailure ? 'yes' : 'no'}\n`);
  process.stdout.write(`helper reported an exit code: ${run.code === null ? 'no' : 'yes'}\n`);
  process.stdout.write(`helper captured any stream text: ${run.stdout === '' && run.stderr === '' ? 'no' : 'yes'}\n`);
  process.stdout.write(`helper reported a signal: ${typeof run.signal === 'string' ? 'yes' : 'no'}\n`);
} else {
  process.stdout.write('run-node-subprocess fixture: a working run\n');
}
