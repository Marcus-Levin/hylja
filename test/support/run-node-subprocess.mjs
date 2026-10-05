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
 * code, no stack, no checkout path - reaches the caller. The child is contained before its streams are
 * inspected, because a spawn that fails after the child object exists reports an asynchronous `error` on
 * it and never reports `close`.
 *
 * Stopping is of the child's whole PROCESS GROUP: the child leads its own group, a stop signals the group,
 * and the helper does not return until the OS reports the group empty. If the group is still not empty
 * when the bounded wait expires, the outcome is the fixed failure (or the reported stall), never the
 * child's own exit code and never success. That covers a run that fails, a run that stalls and a run that
 * exits normally but leaves a descendant behind. A descendant that moves into a new process group or a
 * new session leaves the group and is out of reach; that is the one thing this does not claim.
 *
 * Interruption is covered as well, within limits. The helper tracks the groups it owns while they are live;
 * if THIS process exits, or receives SIGINT or SIGTERM, they are killed synchronously before it goes, and
 * for a signal its default behaviour is then re-raised (unless another listener of the test's own is
 * installed, which then decides). Because the children are detached from the runner's group, a terminal
 * Ctrl-C no longer reaches them directly - this hook is what stands in for it. SIGKILL of this process,
 * SIGHUP and a crash of the node runtime cannot run a hook, so those leave the groups running until the
 * fixtures' own self-bounds (ten seconds) or the operator stop them.
 *
 * Retention is bounded and closable: each stream keeps at most `MAX_CAPTURE_BYTES`, a stream that crosses
 * it fails the run closed, and a failed or settled run keeps no chunk that an open pipe delivers later.
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
/**
 * The most one stream of one invocation may retain. The demo prints a few kilobytes and a TAP report is of
 * the same order, so this is far above any legitimate run; a stream that crosses it fails the run closed.
 */
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
 * Process groups this process owns right now, by group id, and the hooks that kill them when this process
 * is interrupted. The hooks are installed while at least one group is live and removed when none is, so an
 * idle process keeps the default behaviour of every signal.
 */
const ownedGroups = new Set();
let hooked = false;
const SIGNALS = Object.freeze(['SIGINT', 'SIGTERM']);

function killOwnedGroups() {
  for (const group of ownedGroups) {
    try { process.kill(-group, 'SIGKILL'); } catch { /* already gone */ }
  }
  ownedGroups.clear();
}

const onExitHook = () => { killOwnedGroups(); };
const signalHooks = new Map(SIGNALS.map((signal) => [signal, () => {
  killOwnedGroups();
  unhook();
  // Restore the default: with no listener left the re-raised signal ends this process as it would have.
  // A listener that belongs to someone else is left to decide.
  if (process.listenerCount(signal) === 0) process.kill(process.pid, signal);
}]));

function hook() {
  if (hooked) return;
  hooked = true;
  process.on('exit', onExitHook);
  for (const [signal, handler] of signalHooks) process.on(signal, handler);
}

function unhook() {
  if (!hooked) return;
  hooked = false;
  process.off('exit', onExitHook);
  for (const [signal, handler] of signalHooks) process.off(signal, handler);
}

function trackGroup(group) { ownedGroups.add(group); hook(); }
function untrackGroup(group) { ownedGroups.delete(group); if (ownedGroups.size === 0) unhook(); }

/**
 * One stream's retained chunks, bounded and closable. It retains at most `limit` bytes; the chunk that would
 * cross the bound closes the collector, drops everything it held and reports the overflow, and from then on
 * nothing is ever retained again. `stop()` does the same on demand, so a failed or settled run keeps no
 * chunk that a still-open pipe delivers afterwards.
 */
function createCollector(limit, onOverflow) {
  const chunks = [];
  let bytes = 0;
  let open = true;
  return {
    push(chunk) {
      if (!open) return;
      bytes += chunk.byteLength;
      if (bytes > limit) {
        this.stop();
        onOverflow();
        return;
      }
      chunks.push(chunk);
    },
    stop() { open = false; chunks.length = 0; bytes = 0; },
    text() { return Buffer.concat(chunks).toString('utf8'); },
    retained() { return chunks.length; },
  };
}

/**
 * The one lifecycle helper: spawn one owned child, collect its two streams inside a bound, stop the
 * child's whole process group, and settle exactly once. `spawnOptions` is passed to the native spawn
 * unchanged, so a fixture can hand the native call a genuinely bad option and observe the real failure it
 * raises.
 *
 * The child is spawned as the leader of its OWN process group (`detached`, where the OS has such a thing),
 * so a stop reaches every descendant it started - the demo's fixed workers are its grandchildren - and
 * the helper does not return until the group is observed empty or the cleanup bound expires. That is
 * checked against the OS (a signal-0 probe of the group), not inferred from a counter. Limits, stated
 * rather than implied: a descendant that leaves the group on purpose (a new process group or a new
 * session) is out of reach, and a terminated descendant that nothing has reaped yet still counts as a group member until the bound.
 */
function runOwnedChild(execPath, execArgs, spawnOptions, boundMs, inspect = null, seams = {}) {
  return new Promise((resolve) => {
    let child = null;
    let settled = false;
    let failing = false;
    let stalled = false;
    /** Whether the cleanup bound is already armed, so it is armed once whichever path gets there first. */
    let bounded = false;
    /** The deadline timer. A child that is already gone can no longer stall. */
    let deadline = null;
    /** Every timer this invocation owns. None of them outlives the outcome they exist for. */
    const owned = new Set();
    const clearOwnedTimers = () => { for (const timer of owned) clearTimeout(timer); owned.clear(); };
    const own = (fn, ms) => { const timer = setTimeout(fn, ms); owned.add(timer); return timer; };
    const groupLeader = spawnOptions.detached === true && process.platform !== 'win32';

    // Overflow is a failure to RUN, not a truncated capture: it fails the run closed.
    const stdout = createCollector(MAX_CAPTURE_BYTES, () => failTheRun());
    const stderr = createCollector(MAX_CAPTURE_BYTES, () => failTheRun());

    /** Every outcome funnels through here once. Collection ends with it: nothing is retained afterwards. */
    const settle = (code, signal) => {
      if (settled) return;
      settled = true;
      clearOwnedTimers();
      const outcome = failing ? FIXED_FAILURE : {
        code, signal, stalled, transportFailure: false, stdout: stdout.text(), stderr: stderr.text(),
      };
      stdout.stop();
      stderr.stop();
      // A group the OS reports empty is no longer owned. One that is not stays tracked for the exit hook.
      if (groupLeader && Number.isInteger(child?.pid) && !osGroupExists()) untrackGroup(child.pid);
      resolve(outcome);
    };

    /** Whether any member of the owned child's process group still exists, from the OS. */
    const osGroupExists = () => {
      if (!groupLeader || child === null || !Number.isInteger(child.pid)) return false;
      try { process.kill(-child.pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; }
    };
    /** The same, unless a test supplies its own probe through the fixture seam. */
    const groupExists = () => (typeof seams.groupProbe === 'function' ? seams.groupProbe() === true : osGroupExists());

    /** SIGKILL the owned child, and its whole group when it leads one. No other process is signalled. */
    const killOwned = () => {
      if (child === null) return;
      if (groupLeader && Number.isInteger(child.pid)) {
        try { process.kill(-child.pid, 'SIGKILL'); return; } catch { /* no such group: fall through */ }
      }
      if (typeof child.kill === 'function') {
        try { child.kill('SIGKILL'); } catch { /* already gone: its own `close` still decides */ }
      }
    };

    const armCleanupBound = (fn) => {
      if (bounded) return;
      bounded = true;
      own(fn, Number.isSafeInteger(seams.cleanupBoundMs) ? seams.cleanupBoundMs : CLEANUP_BOUND_MS);
    };

    /** Stop what this invocation owns, with the cleanup bound as the fallback if nothing confirms it. */
    const stopOwned = () => {
      killOwned();
      armCleanupBound(() => settle(null, null));
    };

    /**
     * The run itself failed. Stop collecting and keep nothing, stop the owned tree, and settle with the one
     * fixed outcome - once the child and its group are really gone, and at the cleanup bound if they are
     * not, so an unconfirmed stop can never leave this promise pending or read as success.
     */
    const failTheRun = () => {
      if (settled || failing) return;
      failing = true;
      stdout.stop();
      stderr.stop();
      clearOwnedTimers();
      bounded = false;
      stopOwned();
    };

    /**
     * The child itself is really gone. Whatever else of its group is still standing is stopped and awaited
     * before anything is reported, so a normal exit, a stall and a failure all return with no running
     * descendant. A run that already failed reports the fixed outcome whatever this close says.
     */
    const onClose = (code, signal) => {
      if (settled) return;
      if (deadline !== null) { clearTimeout(deadline); owned.delete(deadline); }
      if (!groupExists()) { settle(code, signal); return; }
      killOwned();
      // A group the OS still reports after the bounded wait is an unconfirmed stop: the fixed failure,
      // never the child's own exit code, which would read as success for a run that left a member behind.
      armCleanupBound(() => { failing = true; settle(code, signal); });
      const poll = () => {
        if (settled) return;
        if (!groupExists()) { settle(code, signal); return; }
        own(poll, 10);
      };
      poll();
    };

    let spawned;
    try {
      spawned = spawn(execPath, execArgs, spawnOptions);
    } catch {
      // A synchronous spawn exception: the native call refused the arguments and no child exists, so
      // there is nothing to stop and nothing to capture. The fixed outcome is the whole report.
      failing = true;
      settle(null, null);
      return;
    }
    child = spawned;
    if (groupLeader && Number.isInteger(child.pid)) trackGroup(child.pid);

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
      try {
        inspect({ child, retainedChunks: () => stdout.retained() + stderr.retained() });
      } catch { /* a probe never decides the run */ }
    }
    // The bound is a deadline on this invocation. It stops the owned child and its group, and whether
    // they really go away is decided by the child's own `close` and the group probe, with the cleanup
    // bound as the fallback.
    deadline = own(() => {
      stalled = true;
      stopOwned();
    }, boundMs);
  });
}

/** The stdio discipline every invocation of this helper uses, so both streams are observable. */
const ownChildOptions = Object.freeze({
  cwd: REPO_ROOT,
  stdio: ['ignore', 'pipe', 'pipe'],
  // The child leads its own process group, so a stop reaches its descendants too.
  detached: process.platform !== 'win32',
});

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
export function runNodeFixture({
  entry = null, args = [], spawnOptions = {}, boundMs = BOUND_MS, inspect = null,
  cleanupBoundMs = null, groupProbe = null,
} = {}) {
  const execArgs = entry === null ? [...args] : [entry, ...args];
  const seams = {
    ...(cleanupBoundMs === null ? {} : { cleanupBoundMs }),
    ...(groupProbe === null ? {} : { groupProbe }),
  };
  return runOwnedChild(process.execPath, execArgs, { ...ownChildOptions, ...spawnOptions }, boundMs, inspect, seams);
}
