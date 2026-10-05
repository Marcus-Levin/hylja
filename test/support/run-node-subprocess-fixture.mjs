#!/usr/bin/env node
/**
 * TEST-ONLY fixture for `test/run-node-subprocess.test.mjs`. Not a suite member and not an entry point
 * for any product command.
 *
 * Fixed modes, so the subprocess helper can be exercised against a real child on every path that
 * matters - a working run, an ordinary non-zero exit, a stall inside the helper's bound, and descriptor
 * exhaustion in a process whose descriptor limit was lowered by its parent. Everything this file prints
 * is a fixed label or a boolean; nothing it prints is ever compared as a string by the suite, and no
 * planted or protected value exists here at all.
 *
 *   (no argument)  a working run: one fixed stdout line, exit 0
 *   failing        an ordinary failing run: one fixed stderr line, exit 1, no signal
 *   stall          a stall: holds itself well past any bound the suite uses, until it is stopped
 *   descriptors    reports whether this process really hit EMFILE, then really runs one child
 *   descendant F   spawns one real idle grandchild in this process group, publishes its pid to file F, stalls
 *   orphan F       spawns one real idle grandchild in this process group, publishes its pid to F, exits 0 at once
 *   stray F        spawns one real chattering grandchild in its OWN session, publishes its pid to F, stalls
 *   flood          writes more stdout than the helper may retain, then exits normally
 *
 * Exactly one of those words (plus the one file argument where shown), or none at all. Anything else is
 * refused below.
 *
 * Any other argument is refused with one fixed line and exits 2, like every other fixture here.
 */
import { spawn } from 'node:child_process';
import { closeSync, openSync, renameSync, writeFileSync } from 'node:fs';
import { runNode } from './run-node-subprocess.mjs';

const MODES = Object.freeze({
  WORKING: 'working',
  FAILING: 'failing',
  STALL: 'stall',
  DESCRIPTORS: 'descriptors',
  DESCENDANT: 'descendant',
  STRAY: 'stray',
  ORPHAN: 'orphan',
  FLOOD: 'flood',
});
const KNOWN = new Set(Object.values(MODES));
const REFUSED = 'run-node-subprocess fixture: argument refused\n';

/** The arguments after the entry point: exactly one fixed mode word, or none. */
const requested = process.argv.slice(2);
/** `descendant` and `stray` take exactly one more argument: where to publish the descendant's pid. */
const TAKES_PID_FILE = new Set([MODES.DESCENDANT, MODES.STRAY, MODES.ORPHAN]);
const refused = requested.length === 0 ? false
  : !KNOWN.has(requested[0]) || requested.length !== (TAKES_PID_FILE.has(requested[0]) ? 2 : 1);
const mode = refused ? null : requested[0] ?? MODES.WORKING;

/** Publish a pid atomically, so a reader never sees a half-written file. */
function publishPid(file, pid) {
  const temporary = `${file}.part`;
  writeFileSync(temporary, `${pid}\n`);
  renameSync(temporary, file);
}

/**
 * One real descendant that does nothing observable until it is stopped, and bounds itself: the timer
 * below is the only thing keeping it alive, so it exits on its own after ten seconds even if every stop
 * and every teardown failed. A fixture that could outlive an interrupted suite would break the rule
 * stated for the stall mode.
 */
const IDLE_DESCENDANT = 'setTimeout(() => {}, 10000)';
/** One real descendant that writes to the stderr it inherited every 10 ms for 1.5 s, then exits. */
const CHATTER_DESCENDANT = "const t = setInterval(() => process.stderr.write('x'.repeat(64) + '\\n'), 10);"
  + ' setTimeout(() => clearInterval(t), 1500)';

if (refused) {
  process.stderr.write(REFUSED);
  process.exitCode = 2;
} else if (mode === MODES.FAILING) {
  process.stderr.write('run-node-subprocess fixture: an ordinary failing run\n');
  process.exitCode = 1;
} else if (mode === MODES.STALL) {
  // Ten seconds: far longer than the bound the suite gives this run, short enough that a leaked handle
  // cannot outlive the suite by much even if the bound were removed. It prints nothing, so a stopped
  // run has captured nothing to report.
  setTimeout(() => { process.exitCode = 0; }, 10_000);
} else if (mode === MODES.DESCENDANT) {
  // A real grandchild in the SAME process group, with no stdio of its own, and a parent that stalls
  // until it is stopped: what the helper has to take down is the whole tree, not only this process.
  const grandchild = spawn(process.execPath, ['-e', IDLE_DESCENDANT], { stdio: 'ignore' });
  publishPid(requested[1], grandchild.pid);
  setTimeout(() => { process.exitCode = 0; }, 10_000);
} else if (mode === MODES.ORPHAN) {
  // The same idle grandchild, but this process exits NORMALLY at once and leaves it running: a run that
  // ends well must not leave a descendant behind either.
  const grandchild = spawn(process.execPath, ['-e', IDLE_DESCENDANT], { stdio: 'ignore' });
  publishPid(requested[1], grandchild.pid);
  grandchild.unref();
} else if (mode === MODES.STRAY) {
  // A real grandchild that is OUT OF REACH of a process-group stop (its own session), and that keeps
  // writing to the stderr pipe it inherited after its parent is gone. It stops on its own after 1.5 s.
  const stray = spawn(process.execPath, ['-e', CHATTER_DESCENDANT], { detached: true, stdio: ['ignore', 'ignore', 'inherit'] });
  publishPid(requested[1], stray.pid);
  setTimeout(() => { process.exitCode = 0; }, 10_000);
} else if (mode === MODES.FLOOD) {
  // More output than any invocation of this helper is allowed to retain, then a normal exit.
  process.stdout.write(Buffer.alloc(5 * 1024 * 1024, 0x61));
} else if (mode === MODES.DESCRIPTORS) {
  // Open descriptors until the OS refuses, and KEEP THEM OPEN across the run below: a descriptor this
  // process gives back is one the next spawn can use again, so closing them first would make the spawn
  // succeed and prove nothing. They are this process's own, and are closed once the run has settled.
  let exhausted = false;
  const opened = [];
  try {
    for (;;) opened.push(openSync('/dev/null', 'r'));
  } catch (error) { exhausted = error.code === 'EMFILE'; }
  let run;
  try {
    run = await runNode(process.execPath, ['-e', '']);
  } finally {
    for (const fd of opened) { try { closeSync(fd); } catch { /* the OS already refused more */ } }
    opened.length = 0;
  }
  // Only the fixed labels below leave this process, each of them a boolean about what really happened.
  process.stdout.write(`descriptor limit reached: ${exhausted ? 'yes' : 'no'}\n`);
  process.stdout.write(`helper reported a transport failure: ${run.transportFailure ? 'yes' : 'no'}\n`);
  process.stdout.write(`helper reported an exit code: ${run.code === null ? 'no' : 'yes'}\n`);
  process.stdout.write(`helper captured any stream text: ${run.stdout === '' && run.stderr === '' ? 'no' : 'yes'}\n`);
  process.stdout.write(`helper reported a signal: ${typeof run.signal === 'string' ? 'yes' : 'no'}\n`);
} else {
  process.stdout.write('run-node-subprocess fixture: a working run\n');
}
