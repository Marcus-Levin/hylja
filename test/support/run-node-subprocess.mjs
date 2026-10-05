/**
 * Test-only subprocess helper for the #250 demo evidence. Not a suite member and not an entry point.
 *
 * It runs one Node entry point in a real child process with the same executable, working directory and
 * stdio discipline the operator uses, and it returns what actually happened: the exit code, the signal,
 * whether the invocation finished inside its bound, whether the RUN ITSELF failed, and the two captured
 * streams. There is ONE private lifecycle helper behind all of it, so every entry point is spawned,
 * bounded, stopped and settled the same way.
 *
 * A failure to RUN is never an exception and never a diagnostic. A synchronous spawn exception, an
 * asynchronous `error` from the spawn itself, a child whose required pipes are missing and an error on
 * one of those pipes all settle exactly once with the same fixed restrictive outcome: no exit code, no
 * signal, no captured text, and `transportFailure` set. Nothing from the failure - no native message, no
 * code, no stack, no checkout path - reaches the caller, and only the one child this helper spawned is
 * ever signalled, with a bounded stop whose unconfirmed outcome is still the fixed failure. The child
 * itself is contained before its streams are inspected, because a spawn that fails after the child
 * object exists reports an asynchronous `error` on it and never reports `close`.
 *
 * An ordinary NON-ZERO exit is not a transport failure. The exit code, the signal and both captured
 * streams survive it, which is what lets the confidentiality evidence read a real failing TAP report
 * from a real `node --test` run instead of inferring one.
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
/** Placeholder for the red checkpoint: the current helper has no retention bound. */
export const MAX_CAPTURE_BYTES = 4 * 1024 * 1024;
/** The bound is a deadline, not a kill policy for valid work: only a stalled owned child is stopped. */
export const TEST_TIMEOUT_MS = 180_000;
/**
 * How long an owned child may take to actually go away after it has been stopped. A stop this helper
 * cannot confirm within it settles as the fixed failure anyway: an unconfirmed stop is never success.
 */
const CLEANUP_BOUND_MS = 5_000;

/** The one fixed restrictive outcome. Fixed, non-echoing, and carrying nothing from the failure. */
const FIXED_FAILURE = Object.freeze({
  code: null, signal: null, stalled: false, transportFailure: true, stdout: '', stderr: '',
});

/**
 * The one lifecycle helper: spawn one owned child, collect its two streams inside a bound, stop only
 * that child, and settle exactly once. `spawnOptions` is passed to the native spawn unchanged, so a
 * fixture can hand the native call a genuinely bad option and observe the real failure it raises.
 */
function runOwnedChild(execPath, execArgs, spawnOptions, boundMs, inspect = null) {
  return new Promise((resolve) => {
    const stdout = [];
    const stderr = [];
    /** Every timer this invocation owns. None of them outlives the outcome they exist for. */
    const owned = new Set();
    let child = null;
    let settled = false;
    let failing = false;
    let stalled = false;

    const clearOwnedTimers = () => { for (const timer of owned) clearTimeout(timer); owned.clear(); };

    const own = (fn, ms) => { const timer = setTimeout(fn, ms); owned.add(timer); return timer; };

    const settle = (outcome) => {
      if (settled) return;
      settled = true;
      clearOwnedTimers();
      resolve(outcome);
    };

    /** Bounded stop of the ONE child this invocation spawned. No other process is ever signalled. */
    const stopOwnedChild = () => {
      if (child === null || typeof child.kill !== 'function') return;
      try { child.kill('SIGKILL'); } catch { /* already gone: its own `close` still decides */ }
    };

    /**
     * The run itself failed. Stop the owned child, keep nothing the failure produced, and settle with the
     * one fixed outcome - immediately if the child really closes, and at the cleanup bound if it does
     * not, so an unconfirmed stop can never leave this promise pending or read as success.
     */
    const failTheRun = () => {
      if (settled || failing) return;
      failing = true;
      clearOwnedTimers();
      stdout.length = 0;
      stderr.length = 0;
      stopOwnedChild();
      own(() => settle(FIXED_FAILURE), CLEANUP_BOUND_MS);
    };

    /**
     * The child is really gone. A run that already failed reports the fixed outcome whatever this close
     * says; an observed close is the only thing that may report an exit code or captured text at all.
     */
    const onClose = (code, signal) => {
      if (failing) { settle(FIXED_FAILURE); return; }
      if (settled) return;
      settle({
        code,
        signal,
        stalled,
        transportFailure: false,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    };

    let spawned;
    try {
      spawned = spawn(execPath, execArgs, spawnOptions);
    } catch {
      // A synchronous spawn exception: the native call refused the arguments and no child exists, so
      // there is nothing to stop and nothing to capture. The fixed outcome is the whole report.
      settle(FIXED_FAILURE);
      return;
    }
    child = spawned;

    // The child itself is contained BEFORE anything else is looked at. A spawn that fails after the
    // child object exists - a descriptor-exhaustion `EMFILE`, for one - reports it as an asynchronous
    // `error` on that object and never emits `close`, so a listener attached after a missing-pipe
    // refusal would leave that event unobserved and crash the caller with a native message and a path.
    child.on('error', failTheRun);
    child.on('close', onClose);

    // The two streams are how the outcome is observed, so a child without them cannot be observed.
    if (child.stdout === null || child.stdout === undefined || child.stderr === null || child.stderr === undefined) {
      failTheRun();
      return;
    }
    child.stdout.on('data', (chunk) => { stdout.push(chunk); });
    child.stderr.on('data', (chunk) => { stderr.push(chunk); });
    child.stdout.on('error', failTheRun);
    child.stderr.on('error', failTheRun);
    // TEST-ONLY seam: a fixture may look at the real child and at how many chunks are retained right now.
    if (typeof inspect === 'function') {
      try { inspect({ child, retainedChunks: () => stdout.length + stderr.length }); } catch { /* a probe never decides the run */ }
    }
    // The bound is a deadline on this invocation. It stops only the owned child, and whether the child
    // really goes away is decided by its own `close`, with this bound as the fallback.
    own(() => {
      stalled = true;
      stopOwnedChild();
      own(() => settle({
        code: null, signal: null, stalled: true, transportFailure: false,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      }), CLEANUP_BOUND_MS);
    }, boundMs);
  });
}

/** The stdio discipline every invocation of this helper uses, so both streams are observable. */
const ownChildOptions = Object.freeze({ cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });

/**
 * Run one entry point in a real child process and resolve once it is gone. The child's own stdout and
 * stderr are collected in memory and handed back untouched; they are never decoded into a report.
 */
export function runNode(entry, args) {
  return runOwnedChild(process.execPath, [entry, ...args], { ...ownChildOptions }, BOUND_MS);
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
  return runOwnedChild(process.execPath, ['--test', '--test-reporter=tap', entry],
    { ...ownChildOptions, env }, BOUND_MS);
}

/**
 * TEST-ONLY: the same one private lifecycle helper, with the native spawn options and the bound a fixture
 * needs in order to reach a real failure - a spawn the native call refuses synchronously, a spawn that
 * reports an error asynchronously, or a child whose required pipes are missing. `entry` means exactly
 * what it means in `runNode`: the script this repository's own node runs, with `args` after it. Passing
 * `null` runs the executable with no script at all, which only ever reaches a spawn failure that
 * happens before a child could run. There is no simulation here: the options are handed to the native
 * spawn unchanged and whatever the OS does is what is observed.
 * Reachable from test files under `test/` only; no product or operator command imports this module.
 */
export function runNodeFixture({ entry = null, args = [], spawnOptions = {}, boundMs = BOUND_MS, inspect = null } = {}) {
  const execArgs = entry === null ? [...args] : [entry, ...args];
  return runOwnedChild(process.execPath, execArgs, { ...ownChildOptions, ...spawnOptions }, boundMs, inspect);
}
