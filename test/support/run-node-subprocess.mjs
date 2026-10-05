/**
 * Test-only subprocess helper for the #250 demo evidence. Not a suite member and not an entry point.
 *
 * It runs one Node entry point in a real child process with the same executable, working directory and
 * stdio discipline the operator uses, and it returns what actually happened: the exit code, the signal,
 * whether the invocation finished inside its bound, and the two captured streams.
 *
 * The captured streams are returned as opaque strings and are only ever to be compared through BOOLEANS.
 * Nothing here puts them into an assertion message, an error, a diagnostic or a log, because a captured
 * stream can carry planted material and a failing assertion prints its actual operand. A caller that
 * compares one of these strings directly to another string reintroduces exactly that leak; comparing
 * `stream === expected` and asserting the resulting boolean does not.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
/** Bound every invocation, so a stalled peer or child fails the suite loudly instead of hanging it. */
export const BOUND_MS = 60_000;
/** The bound is a deadline, not a kill policy for valid work: only a stalled owned child is stopped. */
export const TEST_TIMEOUT_MS = 180_000;

/**
 * Run one entry point in a real child process and resolve once it is gone. The child's own stdout and
 * stderr are collected in memory and handed back untouched; they are never decoded into a report.
 */
export function runNode(entry, args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [entry, ...args], {
      cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    let stalled = false;
    child.stdout.on('data', (chunk) => { stdout.push(chunk); });
    child.stderr.on('data', (chunk) => { stderr.push(chunk); });
    const timer = setTimeout(() => { stalled = true; child.kill('SIGKILL'); }, BOUND_MS);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        code,
        signal,
        stalled,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });
  });
}

/**
 * Run one entry point under the real test runner and resolve with its TAP output. Used to observe what
 * the runner actually reports for assertions over protected material, rather than inferring it from the
 * shape of the source.
 *
 * `NODE_TEST_CONTEXT` is dropped from this one child so it runs as a fresh top-level `node --test` run.
 * The runner marks its own children with that variable, and a grandchild that inherits it refuses to run
 * ("node:test run() is being called recursively within a test file") and reports nothing at all, which
 * would make the observation below vacuous. Nothing else in the environment is changed.
 */
export function runNodeTest(entry) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', entry], {
      cwd: REPO_ROOT, env, stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    let stalled = false;
    child.stdout.on('data', (chunk) => { stdout.push(chunk); });
    child.stderr.on('data', (chunk) => { stderr.push(chunk); });
    const timer = setTimeout(() => { stalled = true; child.kill('SIGKILL'); }, BOUND_MS);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        code,
        signal,
        stalled,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });
  });
}