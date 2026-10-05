import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { test } from 'node:test';

import { createKnownOriginals } from '../dist/egress-sentinel.js';
import {
  EGRESS_SENTINEL_PROCESS_WORKER,
  createSentinelProcessRunner,
} from '../dist/egress-sentinel-process.js';
import {
  EGRESS_SENTINEL_PROCESS_LIMITS,
  classifyReplyFraming,
  decodeRequestFrame,
  decodeResponseFrame,
  encodeRequestFrame,
  encodeResponseFrame,
  isSentinelBlockReason,
  snapshotSentinelRequest,
} from '../dist/egress-sentinel-process-protocol.js';

/**
 * #147 optional egress sentinel process wrapper.
 *
 * Every planted value below is obviously synthetic and non-routable (`.invalid`, `tenant-synthetic-*`).
 * Nothing here calls a provider, uses a credential, reaches the network or reads private data, and no
 * fixture is written into the repository: the synthetic children are stdlib-only scripts written into a
 * throwaway temporary directory at run time.
 *
 * Two child shapes are exercised. The REAL child is this repository's own fixed compiled worker, used
 * for every sentinel-behaviour assertion. The SYNTHETIC children are generated stdlib-only scripts
 * installed into a private temporary COPY of `dist/`, where the fixed worker file is replaced. That is
 * how stall, trickled output, crash, malformed, duplicate, oversize, diagnostic-overflow and
 * unconfirmed-cleanup behaviour gets a real process without a configurable product worker path: the
 * runner still resolves its worker from `import.meta.url` and there is no option that could move it.
 */

const SCOPE = Object.freeze({ tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01' });
const OTHER_SCOPE = Object.freeze({ tenantRef: 'tenant-synthetic-02', projectRef: 'project-synthetic-01' });
const DESTINATION = Object.freeze({ id: 'DEST-SYNTHETIC-LOCAL', profileDigest: 'sha256:0f1e2d3c4b5a6978' });
const OTHER_DESTINATION = Object.freeze({ id: 'DEST-SYNTHETIC-OTHER', profileDigest: 'sha256:0f1e2d3c4b5a6978' });
const KEY = Uint8Array.from(Array.from({ length: 32 }, (unused, index) => (index * 7 + 3) & 0xff));
const PLANTED_ORIGINAL = 'orla.vance@synthetic-planted.invalid';
const PLANTED_CANARY = 'synthetic-canary-7f3a.invalid';
const PLANTED_SECRET = 'sk-synthetic-0000000000000000000000';
const NEVER = Symbol('never-settled');
/** Bounded capture for the instrumented child's public TAP counts; never the whole stream. */
const COVERAGE_TAP_CAPTURE_BYTES = 64_000;

const DIST = fileURLToPath(new URL('../dist/', import.meta.url));

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const text = (value) => new TextEncoder().encode(value);

/**
 * Fail loudly instead of hanging when a parent that should settle never does.
 *
 * The timer is owned here and cleared in `finally` on every path, including rejection: a losing
 * `setTimeout` keeps the event loop armed for its full deadline after the race is already decided,
 * which delays process exit for as long as the longest bound in the suite. No `unref`: the deadline
 * must still be able to fire.
 */
async function bounded(promise, ms, label) {
  let timer;
  try {
    const outcome = await Promise.race([
      promise,
      new Promise((resolve) => { timer = setTimeout(() => resolve(NEVER), ms); }),
    ]);
    assert.notEqual(outcome, NEVER, `${label} did not settle within ${ms}ms`);
    return outcome;
  } finally {
    clearTimeout(timer);
  }
}

/* ------------------------------------------------------------------------------------------- *
 * The harness helper's own timer ownership, observed in a real child process.
 * ------------------------------------------------------------------------------------------- */

/** Fixed labels the control child writes, in order. No other child output is read. */
const CONTROL_LABELS = ['CONTROL-SUCCESS', 'CONTROL-REJECTION', 'CONTROL-TIMEOUT'];
/** Minimal child environment: this control needs no inherited variable, secret or coverage path. */
const CONTROL_ENV = Object.freeze({ LANG: 'C', LC_ALL: 'C' });
/** Finite parent watchdog: a helper whose losing deadline timer stays armed trips this. */
const CONTROL_WATCHDOG_MS = 1_500;
const CONTROL_CAPTURE_BYTES = 4_096;

/**
 * The helper under control, run by its own source text: nothing here re-implements it, so whatever
 * `bounded` does is what the child does. Its only free names are supplied from this module too -
 * `assert`, the `NEVER` marker and `delay` - while `Promise`, `Symbol`, `setTimeout` and
 * `clearTimeout` are the standard runtime. A helper revision that no longer calls `delay` simply
 * ignores the argument, so the same control runs against both.
 */
const CONTROL_DRIVER = [
  "import assert from 'node:assert/strict';",
  "const NEVER = Symbol('never-settled');",
  'const delay = new Function(\'return (\' + __DELAY__ + \');\')();',
  'const bounded = new Function(\'assert\', \'NEVER\', \'delay\', \'return (\' + __BOUNDED__ + \');\')(',
  '  assert, NEVER, delay);',
  "const settled = await bounded(Promise.resolve('synthetic-settled'), 30_000, 'control immediate success');",
  "assert.equal(settled, 'synthetic-settled');",
  "process.stdout.write('CONTROL-SUCCESS\\n');",
  'await assert.rejects(bounded(Promise.reject(new Error(\'synthetic control rejection\')), 30_000,',
  "  'control immediate rejection'), /synthetic control rejection/);",
  "process.stdout.write('CONTROL-REJECTION\\n');",
  // A promise that never settles must still produce the fixed timeout message, not a hang.
  "await assert.rejects(bounded(new Promise(() => {}), 200, 'control never settles'),",
  "  (error) => error.message === 'control never settles did not settle within 200ms');",
  "process.stdout.write('CONTROL-TIMEOUT\\n');",
  '',
].join('\n')
  .replace('__DELAY__', () => JSON.stringify(delay.toString()))
  .replace('__BOUNDED__', () => JSON.stringify(bounded.toString()));

test('the bounded helper owns its deadline timer: a child that settles at once still exits promptly', async () => {
  const started = Date.now();
  const child = spawn(process.execPath, ['--input-type=module', '--eval', CONTROL_DRIVER], {
    stdio: ['ignore', 'pipe', 'ignore'], env: { ...CONTROL_ENV },
  });
  child.stdout.setEncoding('utf8');
  let out = '';
  child.stdout.on('data', (chunk) => { if (out.length < CONTROL_CAPTURE_BYTES) out += chunk; });

  let watchdogFired = false;
  // The only process this test may signal is the synthetic control child it just spawned.
  const watchdog = setTimeout(() => {
    watchdogFired = true;
    try { child.kill('SIGKILL'); } catch { /* already closed */ }
  }, CONTROL_WATCHDOG_MS);
  try {
    const code = await new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('close', (exitCode) => resolve(exitCode));
    });
    const elapsed = Date.now() - started;

    // The load-bearing observation: the labels alone prove nothing, because a helper whose losing
    // deadline timer keeps the event loop armed still writes every label and then hangs.
    assert.equal(watchdogFired, false,
      `the control child outlived the ${CONTROL_WATCHDOG_MS}ms watchdog: a losing deadline timer is still armed`);
    assert.equal(code, 0, 'the control child did not exit 0');
    for (const label of CONTROL_LABELS) {
      assert.ok(out.includes(label), `the control child never reached ${label}`);
    }
    assert.ok(elapsed < CONTROL_WATCHDOG_MS, `the control child exited late at ${elapsed}ms`);
  } finally {
    clearTimeout(watchdog);
  }
});

/** `key` is a parameter so a mutation test can submit the exact buffer it then mutates. */
function registration(scope, entries, key = KEY) {
  return { scope, key, entries };
}

function request(overrides = {}) {
  return {
    bytes: text('{"status":"synthetic-ok"}'),
    scope: SCOPE,
    destination: DESTINATION,
    authorized: DESTINATION,
    known: null,
    ...overrides,
  };
}

/**
 * Liveness of one real child, observed directly with signal 0. A value that is not a real pid is refused
 * rather than passed on: pid 0 addresses this test process's own group and would report alive for
 * anything, which would make a stop observation vacuous.
 */
function alive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch { return false; }
}

/* ------------------------------------------------------------------------------------------- *
 * Real child: the fixed compiled worker, through the public runner.
 * ------------------------------------------------------------------------------------------- */

test('the fixed worker path is the compiled sibling of the runner module, not a selectable option', () => {
  assert.equal(EGRESS_SENTINEL_PROCESS_WORKER, fileURLToPath(new URL('../dist/egress-sentinel-process-worker.js', import.meta.url)));
  assert.ok(EGRESS_SENTINEL_PROCESS_WORKER.length > 0);
});

test('real child: a benign message is allowed and the release is a private copy of the parent snapshot', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const source = text('{"status":"synthetic-ok","note":"nothing protected here"}');
  const outcome = await bounded(runner.check(request({ bytes: source })), 10_000, 'benign check');

  assert.equal(outcome.status, 'ALLOW');
  assert.deepEqual(Buffer.from(outcome.release), Buffer.from(source));
  assert.equal(runner.state, 'IDLE');

  // The caller mutates its own buffer afterwards; the returned copy and any later check are unaffected.
  source.fill(0x41);
  const second = await bounded(runner.check(request()), 10_000, 'post-mutation check');
  assert.equal(second.status, 'ALLOW');
  assert.equal(Buffer.from(second.release).toString('utf8'), '{"status":"synthetic-ok"}');
});

test('real child: a planted ORIGINAL blocks with the registered ref and never returns release bytes', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const outcome = await bounded(runner.check(request({
    bytes: text(`{"email":"${PLANTED_ORIGINAL}"}`),
    known: registration(SCOPE, [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }]),
  })), 10_000, 'planted original check');

  assert.equal(outcome.status, 'BLOCK');
  assert.equal(outcome.code, 'SENTINEL_BLOCK');
  assert.deepEqual(outcome.reasonCodes, ['KNOWN_ORIGINAL_DETECTED']);
  assert.deepEqual(outcome.rules, ['ref-original-email']);
  assert.equal('release' in outcome, false);
});

test('real child: a planted CANARY blocks as a canary, not as an ordinary known original', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const outcome = await bounded(runner.check(request({
    bytes: text(`token ${PLANTED_CANARY} end`),
    known: registration(SCOPE, [{ kind: 'CANARY', value: PLANTED_CANARY, ref: 'ref-canary-token' }]),
  })), 10_000, 'planted canary check');

  assert.equal(outcome.code, 'SENTINEL_BLOCK');
  assert.deepEqual(outcome.reasonCodes, ['CANARY_DETECTED']);
  assert.deepEqual(outcome.rules, ['ref-canary-token']);
});

test('real child: a planted SECRET credential assignment blocks as a high-risk pattern', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const outcome = await bounded(runner.check(request({
    bytes: text(`{"note":"api_key = ${PLANTED_SECRET}"}`),
  })), 10_000, 'planted secret check');

  assert.equal(outcome.code, 'SENTINEL_BLOCK');
  assert.ok(outcome.reasonCodes.includes('HIGH_RISK_PATTERN'));
  assert.deepEqual(outcome.rules, []);
});

test('real child: an observed destination that differs from the authorized one blocks', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const mismatched = await bounded(runner.check(request({
    destination: OTHER_DESTINATION,
  })), 10_000, 'destination id mismatch check');
  assert.equal(mismatched.code, 'SENTINEL_BLOCK');
  assert.deepEqual(mismatched.reasonCodes, ['DESTINATION_MISMATCH']);

  const profileMismatch = await bounded(runner.check(request({
    destination: { id: DESTINATION.id, profileDigest: 'sha256:ffffffffffffffff' },
  })), 10_00, 'destination profile mismatch check');
  assert.deepEqual(profileMismatch.reasonCodes, ['DESTINATION_MISMATCH']);
});

test('the child runs with a replaced minimal environment and a fixed single-element argv', async () => {
  const fake = await fakeRunner({ mode: 'report', reportFile: 'fake-report.json' }, { deadlineMs: 10_000 });
  const outcome = await bounded(fake.runner.check(request()), 10_000, 'environment report check');
  // The synthetic child reports and exits without a reply, which is itself a restrictive outcome.
  assert.equal(outcome.status, 'BLOCK');
  const report = JSON.parse(readFileSync(join(fake.installation, 'fake-report.json'), 'utf8'));
  // Nothing from this process is inherited; the only addition the runtime itself may make to a spawn
  // is NODE_V8_COVERAGE, and only when this very process is instrumented for coverage.
  const expectedKeys = ['LANG', 'LC_ALL', 'NODE_NO_WARNINGS', 'PATH'];
  if (process.env.NODE_V8_COVERAGE !== undefined) expectedKeys.push('NODE_V8_COVERAGE');
  expectedKeys.sort();
  assert.deepEqual(Object.keys(report.env).sort(), expectedKeys);
  assert.equal(report.env.NODE_OPTIONS, undefined);
  assert.equal(report.env.HOME, undefined);
  assert.equal(report.argv.length, 1);
  assert.ok(report.argv[0].endsWith('/egress-sentinel-process-worker.js'));
  assert.equal(report.execPath, process.execPath);
});

test('under an instrumented test child a healthy fixed-worker check still returns ALLOW', async () => {
  // CI runs this suite with coverage. The stdlib spawn then writes NODE_V8_COVERAGE into the
  // environment object it was handed, so an environment the runner cannot write to throws before the
  // child exists and the check reports SPAWN_FAILED. Coverage is only real when the test runner is
  // active, so the driver registers one node:test case and is invoked with `--test` AND
  // `--experimental-test-coverage`: instrumentation must not change the verdict.
  const directory = mkdtempSync(join(tmpdir(), 'sentinel-coverage-'));
  const driver = join(directory, 'driver.test.mjs');
  const runnerUrl = pathToFileURL(join(DIST, 'egress-sentinel-process.js')).href;
  writeFileSync(driver, [
    "import assert from 'node:assert/strict';",
    "import { test } from 'node:test';",
    `import { createSentinelProcessRunner } from ${JSON.stringify(runnerUrl)};`,
    "test('an instrumented check of the fixed worker returns ALLOW', async () => {",
    '  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });',
    '  const outcome = await runner.check({',
    "    bytes: new TextEncoder().encode('{\"status\":\"synthetic-ok\"}'),",
    "    scope: { tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01' },",
    "    destination: { id: 'DEST-SYNTHETIC-LOCAL', profileDigest: 'sha256:0f1e2d3c4b5a6978' },",
    "    authorized: { id: 'DEST-SYNTHETIC-LOCAL', profileDigest: 'sha256:0f1e2d3c4b5a6978' },",
    '    known: null,',
    '  });',
    "  assert.equal(outcome.status, 'ALLOW');",
    '});',
    '',
  ].join('\n'));
  try {
    // `NODE_TEST_CONTEXT` is what makes a nested `node --test` report through the run IPC channel
    // instead of stdout; a driver started with it inherits a context that never reports, so its exit
    // code and TAP cannot be read. Everything else is inherited so the driver really runs instrumented.
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    delete env.NODE_TEST_WORKER_ID;
    // The reporter is pinned rather than inherited: Node's default test reporter changed between the
    // pinned Node versions, and the two counts below are asserted against this run's TAP output.
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', '--experimental-test-coverage', driver], {
      stdio: ['ignore', 'pipe', 'ignore'], env,
    });
    let out = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { if (out.length < COVERAGE_TAP_CAPTURE_BYTES) out += chunk; });
    // Finite wall-clock bound owned here: the timer is always cleared and, when it fires, the child is
    // killed so the awaited value can only come from a kill-confirmed close.
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* already closed */ } }, 30_000);
    let code;
    try {
      code = await new Promise((resolve, reject) => {
        child.on('error', reject);
        child.on('close', (exitCode) => resolve(exitCode));
      });
    } finally {
      clearTimeout(timer);
    }
    assert.equal(code, 0, `instrumented driver exited ${code}: ${out.slice(0, 2_000)}`);
    // Bounded public TAP counts only: no JSON parse of the whole stream.
    assert.match(out, /^# fail 0$/m);
    assert.match(out, /^# pass 1$/m);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('a second concurrent check is refused rather than queued, pooled or run in thread', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const first = runner.check(request());
  const second = await bounded(runner.check(request()), 1_000, 'concurrent second check');
  assert.equal(second.status, 'BLOCK');
  assert.equal(second.code, 'RUNNER_BUSY');
  assert.equal(runner.state, 'BUSY');
  const settled = await bounded(first, 10_000, 'first check');
  assert.equal(settled.status, 'ALLOW');
  assert.equal(runner.state, 'IDLE');
});

/* ------------------------------------------------------------------------------------------- *
 * Refusals before spawn: nothing here may reach a child process or invoke a refused accessor.
 * ------------------------------------------------------------------------------------------- */

test('an omitted known field is refused, never silently read as null', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const outcome = await bounded(runner.check({
    bytes: text('x'), scope: SCOPE, destination: DESTINATION, authorized: DESTINATION,
  }), 1_000, 'omitted known check');
  assert.equal(outcome.code, 'INVALID_REQUEST');
  assert.equal(runner.state, 'IDLE');
});

test('a process-local KnownOriginalsHandle is refused, never serialized as {} or as null', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const handle = createKnownOriginals(SCOPE, KEY, [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }]);
  const asHandle = await bounded(runner.check(request({ known: handle })), 1_000, 'handle check');
  assert.equal(asHandle.code, 'INVALID_REQUEST');
  const asUnknown = await bounded(runner.check(request({ known: undefined })), 1_000, 'undefined known check');
  assert.equal(asUnknown.code, 'INVALID_REQUEST');
  const asString = await bounded(runner.check(request({ known: 'null' })), 1_000, 'string known check');
  assert.equal(asString.code, 'INVALID_REQUEST');
});

test('a registration whose own scope does not match the check scope is refused before spawn', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const outcome = await bounded(runner.check(request({
    known: registration(OTHER_SCOPE, [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }]),
  })), 1_000, 'scope mismatch check');
  assert.equal(outcome.code, 'INVALID_REQUEST');
  assert.equal(runner.state, 'IDLE');
});

test('an unsupported cancellation or worker hook is refused and its value is never invoked', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const controller = new AbortController();
  const unsupported = [
    { signal: controller.signal },
    { onCancel: () => undefined },
    { worker: '/tmp/anything.mjs' },
    { timeoutMs: 1 },
    { shell: true },
  ];
  for (const extra of unsupported) {
    const outcome = await bounded(runner.check({ ...request(), ...extra }), 1_000, `unsupported option ${Object.keys(extra)[0]}`);
    assert.equal(outcome.code, 'INVALID_REQUEST', `option ${Object.keys(extra)[0]} was not refused`);
  }
  let touched = false;
  const throwing = { ...request(), get signal() { touched = true; throw new Error('accessor must not run'); } };
  const outcome = await bounded(runner.check(throwing), 1_000, 'throwing accessor check');
  assert.equal(outcome.code, 'INVALID_REQUEST');
  assert.equal(touched, false, 'a refused option accessor must never be invoked');
});

test('an oversize message, a short key and an unbounded request are refused before spawn', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const oversize = await bounded(runner.check(request({
    bytes: new Uint8Array(EGRESS_SENTINEL_PROCESS_LIMITS.maxPayloadBytes + 1),
  })), 1_000, 'oversize check');
  assert.equal(oversize.code, 'INVALID_REQUEST');

  const shortKey = await bounded(runner.check(request({
    known: { scope: SCOPE, key: Uint8Array.from([1, 2, 3]), entries: [] },
  })), 1_000, 'short key check');
  assert.equal(shortKey.code, 'INVALID_REQUEST');

  const duplicateRefs = await bounded(runner.check(request({
    known: registration(SCOPE, [
      { kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-dup' },
      { kind: 'CANARY', value: PLANTED_CANARY, ref: 'ref-dup' },
    ]),
  })), 1_000, 'duplicate ref check');
  assert.equal(duplicateRefs.code, 'INVALID_REQUEST');
});

test('an out-of-range deadline makes every check restrictive instead of running unbounded', async () => {
  for (const deadlineMs of [0, 1, -1, 1e9, Number.NaN, '5000', null]) {
    const runner = createSentinelProcessRunner({ deadlineMs });
    const outcome = await bounded(runner.check(request()), 1_000, `deadline ${String(deadlineMs)}`);
    assert.equal(outcome.code, 'INVALID_REQUEST');
  }
});

test('a caller-mutated input cannot change the private image that is checked and released', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const scope = { tenantRef: SCOPE.tenantRef, projectRef: SCOPE.projectRef };
  const destination = { id: DESTINATION.id, profileDigest: DESTINATION.profileDigest };
  const authorized = { id: DESTINATION.id, profileDigest: DESTINATION.profileDigest };
  const key = Uint8Array.from(KEY);
  const bytes = text(`{"email":"${PLANTED_ORIGINAL}"}`);
  const pending = runner.check({ bytes, scope, destination, authorized, known: registration(scope, [
    { kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' },
  ], key) });
  // Every caller-owned object is mutated the instant the check is in flight.
  bytes.fill(0x41);
  scope.tenantRef = 'tenant-synthetic-mutated';
  destination.id = 'DEST-SYNTHETIC-MUTATED';
  authorized.profileDigest = 'sha256:deadbeefdeadbeef';
  key.fill(0);

  const outcome = await bounded(pending, 10_000, 'mutated input check');
  assert.equal(outcome.code, 'SENTINEL_BLOCK');
  assert.deepEqual(outcome.reasonCodes, ['KNOWN_ORIGINAL_DETECTED']);
  assert.deepEqual(outcome.rules, ['ref-original-email']);
});

/* ------------------------------------------------------------------------------------------- *
 * Real synthetic children: lifecycle, cancellation, termination and framing failures.
 * ------------------------------------------------------------------------------------------- */

/** Generated stdlib-only child. It never imports the sentinel, a policy module or any package. */
const FAKE_WORKER = String.raw`
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const control = JSON.parse(readFileSync(HERE + 'fake-control.json', 'utf8'));

function field(tag, bytes) {
  const header = Buffer.alloc(5);
  header[0] = tag;
  header.writeUInt32BE(bytes.length, 1);
  return Buffer.concat([header, bytes]);
}
function u32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value, 0);
  return bytes;
}
function frame(kind, parts) {
  const body = Buffer.concat(parts);
  const head = Buffer.alloc(9);
  Buffer.from('HSPP', 'ascii').copy(head, 0);
  head[4] = kind;
  head.writeUInt32BE(body.length, 5);
  return Buffer.concat([head, body, Buffer.from('\n', 'ascii')]);
}
function fields(request) {
  const out = new Map();
  let at = 9;
  const end = 9 + request.readUInt32BE(5);
  while (at < end) {
    const tag = request[at];
    const length = request.readUInt32BE(at + 1);
    out.set(tag, Buffer.from(request.subarray(at + 5, at + 5 + length)));
    at += 5 + length;
  }
  return out;
}
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

/**
 * Readiness is written to a private staged name inside this child's OWN installation directory and then
 * renamed onto the final ready name. A rename within one directory is atomic, so the final name never
 * exists with an empty or partial payload: it appears only once the whole publication is on disk. The
 * in-place write this replaces exposed the final name between create/truncate and write, so a parent
 * could see the name and read an incomplete file - the fixture race, not a runner defect.
 */
function stage(relative, payload) {
  const staged = HERE + relative + '.staged-' + process.pid;
  writeFileSync(staged, JSON.stringify(payload));
  return staged;
}
function publish(relative, payload) {
  renameSync(stage(relative, payload), HERE + relative);
}
/** A structurally valid reply that echoes the real request binding unless a field is overridden. */
function reply(request, override = {}) {
  const f = fields(request);
  const echo = (tag) => f.get(tag).toString('utf8');
  const reasons = override.reasons ?? [];
  const rules = override.rules ?? [];
  return frame(2, [
    field(30, Buffer.from(override.requestId ?? echo(1), 'utf8')),
    field(31, Buffer.from(override.tenantRef ?? echo(2), 'utf8')),
    field(32, Buffer.from(override.projectRef ?? echo(3), 'utf8')),
    field(33, Buffer.from(override.observedId ?? echo(4), 'utf8')),
    field(34, Buffer.from(override.observedProfile ?? echo(5), 'utf8')),
    field(35, Buffer.from(override.authorizedId ?? echo(6), 'utf8')),
    field(36, Buffer.from(override.authorizedProfile ?? echo(7), 'utf8')),
    field(37, Buffer.from(override.payloadDigest ?? sha256(f.get(8)), 'utf8')),
    field(38, Buffer.from([override.decision ?? 1])),
    field(39, u32(reasons.length)),
    ...reasons.map((reason) => field(40, Buffer.from(reason, 'utf8'))),
    ...rules.map((rule) => field(50, Buffer.from(rule, 'utf8'))),
  ]);
}

const collected = [];
process.stdin.on('data', (chunk) => collected.push(chunk));
process.stdin.on('end', () => {
  const request = Buffer.concat(collected);
  if (control.reportFile) {
    writeFileSync(HERE + control.reportFile, JSON.stringify({
      env: process.env, argv: process.argv.slice(1), execPath: process.execPath,
    }));
  }
  // Readiness is published only where a control asked for it, and always as a COMPLETE payload renamed
  // onto the final name. The stall-unpublished control is the deliberate negative: it writes the complete
  // staged file and never renames it, so no final name ever appears.
  if (control.pidFile && control.mode === 'stall') publish(control.pidFile, { pid: process.pid });
  if (control.pidFile && control.mode === 'stall-unpublished') stage(control.pidFile, { pid: process.pid });
  switch (control.mode) {
    case 'report':
      process.exit(0);
      return;
    case 'stall':
    case 'stall-unpublished':
      // Both hold open exactly like a stalled child, so readiness is decided by what was published and
      // never by this process exiting.
      setInterval(() => {}, 1000);
      return;
    case 'trickle':
      setInterval(() => { process.stdout.write('x'); }, control.intervalMs ?? 50);
      return;
    case 'late-reply':
      setInterval(() => {}, 1000);
      setTimeout(() => process.stdout.write(reply(request, control.override ?? {})), control.delayMs ?? 900);
      return;
    case 'crash':
      process.exit(control.code ?? 7);
      return;
    case 'flush-then-crash':
      process.stdout.write(Buffer.from(control.stdoutBase64, 'base64'));
      process.exit(control.code ?? 0);
      return;
    case 'duplicate-reply':
      process.stdout.write(reply(request, control.override ?? {}));
      process.stdout.write(reply(request, control.override ?? {}));
      process.exitCode = 0;
      return;
    case 'stderr-flood':
      process.stderr.write(Buffer.alloc(control.bytes ?? 200000, 0x79));
      setInterval(() => {}, 1000);
      return;
    case 'leak-diagnostics':
      // A hostile synthetic child that writes the planted protected marker on BOTH of its ordinary
      // diagnostic channels. The wrapper must withhold both from anything it can reach.
      process.stdout.write('STDOUT-LEAK ' + control.marker + '\n');
      process.stderr.write('STDERR-LEAK ' + control.marker + '\n');
      setInterval(() => {}, 1000);
      return;
    case 'grandchild': {
      const held = spawn(process.execPath, ['-e', 'setTimeout(() => {}, ' + (control.grandchildMs ?? 900) + ')'],
        { stdio: ['ignore', 'inherit', 'inherit'] });
      // This readiness is only complete once the held child exists: both pids are published together,
      // never a premature name that carries only this process.
      publish(control.pidFile, { pid: process.pid, held: held.pid });
      setInterval(() => {}, 1000);
      return;
    }
    case 'raw-stdout':
      process.stdout.write(Buffer.from(control.stdoutBase64, 'base64'));
      process.exitCode = 0;
      return;
    case 'reply':
      process.stdout.write(reply(request, control.override ?? {}));
      process.exitCode = 0;
      return;
    default:
      process.exit(9);
  }
});
`;

const installations = [];
test.after(() => {
  for (const directory of installations) {
    try { rmSync(directory, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/**
 * Install a private copy of `dist/` in a throwaway directory with the fixed worker file replaced by a
 * generated stdlib-only script. The runner under test still resolves its worker from `import.meta.url`,
 * so this proves the lifecycle without adding a product option that could move the worker.
 */
async function fakeRunner(control, config) {
  const installation = mkdtempSync(join(tmpdir(), 'hylja-egress-fake-'));
  installations.push(installation);
  cpSync(DIST, installation, { recursive: true });
  writeFileSync(join(installation, 'fake-control.json'), JSON.stringify(control));
  writeFileSync(join(installation, 'egress-sentinel-process-worker.js'), FAKE_WORKER, 'utf8');
  const module = await import(pathToFileURL(join(installation, 'egress-sentinel-process.js')).href);
  return { runner: module.createSentinelProcessRunner(config), installation };
}

/** Finite handshake bounds for readiness observation, unchanged from the previous fixed budget. */
const READINESS_POLL_MS = 20;
const READINESS_POLLS = 100;

/**
 * Readiness is the FINAL ready name existing, never a parse that retries a malformed publication.
 * The child renames a complete staged file onto that name, so its existence IS completed publication
 * and one read is the whole observation. This never catches, retries or sleeps on a partial file.
 */
function readPublication(directory, name) {
  const path = join(directory, name);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Wait for a completed publication within a finite number of polls, or `null` if it never lands. */
async function awaitPublication(directory, name, polls = READINESS_POLLS) {
  for (let attempt = 0; attempt < polls; attempt++) {
    const published = readPublication(directory, name);
    if (published !== null) return published;
    await delay(READINESS_POLL_MS);
  }
  return null;
}

/** Poll a bounded number of times and report whether the final ready name ever appeared. */
async function publicationAppeared(directory, name, polls) {
  for (let attempt = 0; attempt < polls; attempt++) {
    if (readPublication(directory, name) !== null) return true;
    await delay(READINESS_POLL_MS);
  }
  return false;
}

/** What one staged-name observation reports: appearance, exact-basename shape, and that child's pid. */
const STAGED_ABSENT = Object.freeze({ appeared: false, wellFormed: false, pid: 0 });
const STAGED_UNUSABLE = Object.freeze({ appeared: true, wellFormed: false, pid: 0 });

/**
 * The child names its private staged file `<ready name>.staged-<its own process.pid>`, so the NAME
 * carries that child's identity while the payload may still be mid-write. This reads directory entries
 * only - it never opens or parses the staged file - and it never treats staging as readiness. A name that
 * is not exactly the expected basename, or more than one such name, yields no pid at all, so a malformed
 * or foreign entry can never be read as a live child.
 */
function stagedObservation(directory, name) {
  const prefix = name + '.staged-';
  const staged = readdirSync(directory).filter((entry) => entry.startsWith(prefix));
  if (staged.length === 0) return STAGED_ABSENT;
  if (staged.length !== 1) return STAGED_UNUSABLE;
  const suffix = /^\d+$/.exec(staged[0].slice(prefix.length));
  if (suffix === null) return STAGED_UNUSABLE;
  const pid = Number(suffix[0]);
  return { appeared: true, wellFormed: pid > 0, pid };
}

/** Wait for the child's private staged name within the fixed poll budget, or report that it never came. */
async function awaitStagedName(directory, name, polls = READINESS_POLLS) {
  let observation = stagedObservation(directory, name);
  for (let attempt = 0; attempt < polls && !observation.appeared; attempt++) {
    await delay(READINESS_POLL_MS);
    observation = stagedObservation(directory, name);
  }
  return observation;
}

test('the readiness boundary itself: a partially written ready name is not a publication, a renamed one is', () => {
  const directory = mkdtempSync(join(tmpdir(), 'hylja-egress-readiness-'));
  installations.push(directory);
  const ready = join(directory, 'fake-pid.json');

  // The publication this fixture used to make: the ready name exists from its creation onwards, so its
  // existence is not completed publication and a parent can read a file with no content in it.
  writeFileSync(ready, '');
  assert.equal(existsSync(ready), true);
  assert.equal(readFileSync(ready, 'utf8').length > 0, false);

  // The publication now in use: the complete payload exists only under a private staged name, and the
  // ready name appears with that whole payload or not at all.
  rmSync(ready);
  const staged = join(directory, 'fake-pid.json.staged-synthetic');
  writeFileSync(staged, JSON.stringify({ pid: process.pid }));
  assert.equal(existsSync(ready), false, 'a staged write published the ready name');
  // The exact basename shape is what would carry a child pid. A suffix that is not digits is a malformed
  // staged name: it is observed, and it yields no pid, so nothing can be read as a live child from it.
  const malformed = stagedObservation(directory, 'fake-pid.json');
  assert.equal(malformed.appeared, true, 'the private staged write was not observed at all');
  assert.equal(malformed.wellFormed, false, 'a non-numeric staged suffix was read as a child pid');
  assert.equal(malformed.pid, 0, 'a malformed staged name still yielded a pid');

  renameSync(staged, ready);
  assert.equal(existsSync(ready), true);
  assert.equal(typeof JSON.parse(readFileSync(ready, 'utf8')).pid, 'number');
  // The rename consumed exactly the staged name, so nothing staged is left behind to be re-observed.
  assert.equal(stagedObservation(directory, 'fake-pid.json').appeared, false,
    'the staged name outlived the rename onto the ready name');
});

test('a stalled child is terminated at the absolute deadline, with no in-thread fallback and no release', async () => {
  const { runner } = await fakeRunner({ mode: 'stall' }, { deadlineMs: 500, cleanupGraceMs: 2_000 });
  const started = Date.now();
  const outcome = await bounded(runner.check(request()), 5_000, 'stalled check');
  const elapsed = Date.now() - started;

  assert.equal(outcome.status, 'BLOCK');
  assert.equal(outcome.code, 'DEADLINE_EXCEEDED');
  assert.equal('release' in outcome, false);
  assert.ok(elapsed >= 450, `deadline fired early at ${elapsed}ms`);
  assert.ok(elapsed < 4_000, `deadline did not bound the stall (${elapsed}ms)`);
  assert.equal(runner.state, 'IDLE', 'a confirmed stop must leave the runner usable');
});

test('trickled output never resets the absolute deadline', async () => {
  const { runner } = await fakeRunner({ mode: 'trickle', intervalMs: 25 }, { deadlineMs: 600, cleanupGraceMs: 2_000 });
  const started = Date.now();
  const outcome = await bounded(runner.check(request()), 5_000, 'trickled check');
  const elapsed = Date.now() - started;

  assert.equal(outcome.code, 'DEADLINE_EXCEEDED');
  assert.ok(elapsed >= 550, `the deadline was reset by output (${elapsed}ms)`);
  assert.ok(elapsed < 4_000, `trickled output exceeded the deadline (${elapsed}ms)`);
});

test('runner-owned cancel() is observed promptly and really terminates the child', async () => {
  const { runner, installation } = await fakeRunner({ mode: 'stall', pidFile: 'fake-pid.json' }, {
    deadlineMs: 30_000, cleanupGraceMs: 2_000,
  });
  const started = Date.now();
  const pending = runner.check(request());
  assert.equal(runner.state, 'BUSY');

  // The final name appears only after a complete staged file is renamed onto it, so this one read is
  // a real child's real pid rather than a name that was visible while its file was still empty.
  const published = await awaitPublication(installation, 'fake-pid.json');
  assert.ok(published !== null, 'the synthetic child never published a complete readiness');
  const pid = published.pid;
  assert.equal(typeof pid, 'number', 'the published readiness carried no pid');
  assert.equal(alive(pid), true, 'the published pid is not a live child process');

  runner.cancel();
  const outcome = await bounded(pending, 5_000, 'cancelled check');
  const elapsed = Date.now() - started;

  assert.equal(outcome.status, 'BLOCK');
  assert.equal(outcome.code, 'CANCELLED');
  assert.equal('release' in outcome, false);
  assert.ok(elapsed < 10_000, `cancellation was not prompt (${elapsed}ms)`);
  assert.equal(alive(pid), false, 'the cancelled child was still alive after close');
  assert.equal(runner.state, 'IDLE');
});

test('a staged readiness write is never observed as ready, and the check stays pending until it is', async () => {
  // Deterministic negative control for the removed race. The child writes its COMPLETE payload to a
  // private staged name and never renames it, so the final name can never appear; the observation must
  // report not-ready instead of counting a temporary write as readiness.
  const { runner, installation } = await fakeRunner({ mode: 'stall-unpublished', pidFile: 'fake-pid.json' }, {
    deadlineMs: 30_000, cleanupGraceMs: 2_000,
  });
  // The installation is fresh and owned by this test, so any staged name seen below belongs to the child
  // this check spawns and cannot be a leftover from an earlier run.
  assert.equal(stagedObservation(installation, 'fake-pid.json').appeared, false,
    'the owned installation already held a staged readiness name before this check started');
  const pending = runner.check(request());
  let settled = false;
  pending.then(() => { settled = true; }, () => { settled = true; });

  const staged = await awaitStagedName(installation, 'fake-pid.json');
  assert.equal(staged.appeared, true,
    'the control never wrote its private staged file, so it proved nothing');
  // Only the exact basename shape carries this child's identity. Reading the pid out of the staged
  // payload instead would parse a file that may still be being written.
  assert.equal(staged.wellFormed, true,
    'the staged name did not have the exact basename shape that carries the child pid');
  assert.equal(staged.pid === process.pid, false,
    'the staged name identified this test process instead of the spawned child');

  assert.equal(await publicationAppeared(installation, 'fake-pid.json', 30), false,
    'a staged temporary write was observed as a completed publication');
  assert.equal(settled, false, 'the check settled while its readiness was never published');

  // The child is still a real running process: cancelling it is what ends the check, not its exit.
  assert.equal(alive(staged.pid), true, 'the staged name did not identify a live child process');
  runner.cancel();
  const outcome = await bounded(pending, 5_000, 'staged readiness cancel');
  assert.equal(outcome.status, 'BLOCK');
  assert.equal(outcome.code, 'CANCELLED');
  assert.equal('release' in outcome, false);
  // The stop is observed on that same child rather than inferred from the outcome code: a pid that was
  // never a real child, or that belonged to this test process, would still read as alive here.
  assert.equal(alive(staged.pid), false, 'the cancelled child was still alive after close');
  assert.equal(runner.state, 'IDLE');
});

test('a complete publication is a live child on the noncancelled stalled path, and the deadline stops it', async () => {
  // The same observation without a cancel: readiness must be a real running child, and the run must end
  // at the absolute deadline with a confirmed stop and a still usable runner.
  const { runner, installation } = await fakeRunner({ mode: 'stall', pidFile: 'fake-pid.json' }, {
    deadlineMs: 2_000, cleanupGraceMs: 2_000,
  });
  const started = Date.now();
  const pending = runner.check(request());
  const published = await awaitPublication(installation, 'fake-pid.json');
  assert.ok(published !== null, 'the stalled child never published a complete readiness');
  const pid = published.pid;
  assert.equal(typeof pid, 'number', 'the published readiness carried no pid');
  assert.equal(alive(pid), true, 'the published pid is not a live child process');

  const outcome = await bounded(pending, 5_000, 'stalled deadline check');
  const elapsed = Date.now() - started;

  assert.equal(outcome.status, 'BLOCK');
  assert.equal(outcome.code, 'DEADLINE_EXCEEDED');
  assert.equal('release' in outcome, false);
  assert.ok(elapsed >= 1_950, `deadline fired early at ${elapsed}ms`);
  assert.ok(elapsed < 4_000, `deadline did not bound the stall (${elapsed}ms)`);
  assert.equal(alive(pid), false, 'the stopped child was still alive after close');
  assert.equal(runner.state, 'IDLE', 'a confirmed stop must leave the runner usable');
});

test('a late reply never overrides a deadline that already fired', async () => {
  const { runner } = await fakeRunner({ mode: 'late-reply', delayMs: 700 }, { deadlineMs: 300, cleanupGraceMs: 2_000 });
  const outcome = await bounded(runner.check(request()), 5_000, 'late reply check');
  assert.equal(outcome.code, 'DEADLINE_EXCEEDED');
  assert.equal('release' in outcome, false);
});

test('an uncertain cleanup quarantines the runner instead of reporting a confirmed stop', async () => {
  const { runner, installation } = await fakeRunner({ mode: 'grandchild', grandchildMs: 900, pidFile: 'fake-pid.json' }, {
    deadlineMs: 250, cleanupGraceMs: 120,
  });
  const outcome = await bounded(runner.check(request()), 5_000, 'unconfirmed cleanup check');
  assert.equal(outcome.status, 'BLOCK');
  assert.equal(outcome.code, 'CLEANUP_UNCONFIRMED');
  assert.equal(runner.state, 'QUARANTINED');

  const after = await bounded(runner.check(request()), 2_000, 'post-quarantine check');
  assert.equal(after.code, 'RUNNER_QUARANTINED');
  // The grandchild readiness is published as one complete payload that already carries the held pid, so
  // this read is never a name that appeared before its content did.
  const published = await awaitPublication(installation, 'fake-pid.json');
  assert.ok(published !== null, 'the quarantined child never published a complete readiness');
  assert.equal(typeof published.held, 'number');
  // Let the held grandchild exit so this test leaves no live process behind.
  for (let attempt = 0; attempt < 150 && alive(published.held); attempt++) await delay(20);
  assert.equal(alive(published.held), false, 'the held grandchild outlived the test');
});

test('a crashing child, a missing reply and a truncated reply are each distinct restrictive codes', async () => {
  const crash = await fakeRunner({ mode: 'crash', code: 7 }, { deadlineMs: 5_000 });
  assert.equal((await bounded(crash.runner.check(request()), 5_000, 'crash check')).code, 'CHILD_CRASHED');

  const silent = await fakeRunner({ mode: 'report' }, { deadlineMs: 5_000 });
  assert.equal((await bounded(silent.runner.check(request()), 5_000, 'missing reply check')).code, 'REPLY_MISSING');

  const truncated = await fakeRunner({ mode: 'raw-stdout', stdoutBase64: Buffer.from('HSPP').toString('base64') }, {
    deadlineMs: 5_000,
  });
  assert.equal((await bounded(truncated.runner.check(request()), 5_000, 'truncated reply check')).code, 'REPLY_MALFORMED');
});

test('a duplicated reply, a garbage reply and an oversized reply are each restrictive', async () => {
  const duplicate = await fakeRunner({ mode: 'duplicate-reply' }, { deadlineMs: 5_000 });
  assert.equal((await bounded(duplicate.runner.check(request()), 5_000, 'duplicate reply check')).code, 'REPLY_DUPLICATE');

  const garbage = await fakeRunner({
    mode: 'raw-stdout',
    stdoutBase64: Buffer.from(`not a frame at all ${PLANTED_ORIGINAL}\n`, 'utf8').toString('base64'),
  }, { deadlineMs: 5_000 });
  const garbageOutcome = await bounded(garbage.runner.check(request()), 5_000, 'garbage reply check');
  assert.equal(garbageOutcome.code, 'REPLY_MALFORMED');
  assert.equal(JSON.stringify(garbageOutcome).includes(PLANTED_ORIGINAL), false,
    'a value echoed by a child must never reach an ordinary result');

  const oversized = await fakeRunner({
    mode: 'raw-stdout',
    stdoutBase64: Buffer.alloc(EGRESS_SENTINEL_PROCESS_LIMITS.maxStdoutBytes + 4096, 0x41).toString('base64'),
  }, { deadlineMs: 5_000 });
  assert.equal((await bounded(oversized.runner.check(request()), 5_000, 'oversize reply check')).code, 'REPLY_TOO_LARGE');
});

test('a diagnostic flood is counted, dropped and restrictive, and never surfaces its bytes', async () => {
  const { runner } = await fakeRunner({ mode: 'stderr-flood', bytes: 200_000 }, { deadlineMs: 5_000, cleanupGraceMs: 2_000 });
  const outcome = await bounded(runner.check(request()), 5_000, 'stderr flood check');
  assert.equal(outcome.status, 'BLOCK');
  assert.equal(outcome.code, 'DIAGNOSTIC_OVERFLOW');
  assert.deepEqual(outcome.reasonCodes, []);
  assert.equal(JSON.stringify(outcome).includes(PLANTED_ORIGINAL), false);
});

test('a reply whose binding differs from the request the parent sent cannot authorize a release', async () => {
  for (const override of [
    { tenantRef: OTHER_SCOPE.tenantRef },
    { projectRef: 'project-synthetic-99' },
    { observedProfile: 'sha256:ffffffffffffffff' },
    { payloadDigest: 'f'.repeat(64) },
    { requestId: 'r0000000000000000' },
  ]) {
    const { runner } = await fakeRunner({ mode: 'reply', override }, { deadlineMs: 5_000 });
    const outcome = await bounded(runner.check(request()), 5_000, `binding mismatch ${Object.keys(override)[0]}`);
    assert.equal(outcome.status, 'BLOCK');
    assert.equal(outcome.code, 'REPLY_BINDING_MISMATCH', `binding mismatch ${Object.keys(override)[0]} was accepted`);
    assert.equal('release' in outcome, false);
  }
});

test('an ALLOW frame with a reason, a BLOCK frame without one, or a free-text ref is malformed', async () => {
  const inconsistentAllow = await fakeRunner({ mode: 'reply', override: { reasons: ['HIGH_RISK_PATTERN'] } }, { deadlineMs: 5_000 });
  assert.equal((await bounded(inconsistentAllow.runner.check(request()), 5_000, 'allow with reason')).code, 'REPLY_MALFORMED');

  const emptyBlock = await fakeRunner({ mode: 'reply', override: { decision: 2 } }, { deadlineMs: 5_000 });
  assert.equal((await bounded(emptyBlock.runner.check(request()), 5_000, 'empty block')).code, 'REPLY_MALFORMED');

  const foreignRef = await fakeRunner({
    mode: 'reply',
    override: { decision: 2, reasons: ['HIGH_RISK_PATTERN'], rules: [PLANTED_ORIGINAL] },
  }, { deadlineMs: 5_000 });
  const outcome = await bounded(foreignRef.runner.check(request()), 5_000, 'foreign ref');
  assert.equal(outcome.code, 'REPLY_MALFORMED');
  assert.equal(JSON.stringify(outcome).includes(PLANTED_ORIGINAL), false,
    'a child-selected string must never reach an ordinary result');
});

test('a genuine BLOCK reply carrying only registered refs and fixed codes reaches the caller unchanged', async () => {
  const { runner } = await fakeRunner({
    mode: 'reply',
    override: { decision: 2, reasons: ['KNOWN_ORIGINAL_DETECTED'], rules: ['ref-original-email'] },
  }, { deadlineMs: 5_000 });
  const outcome = await bounded(runner.check(request({
    known: registration(SCOPE, [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }]),
  })), 5_000, 'registered ref reply');
  assert.equal(outcome.status, 'BLOCK');
  assert.equal(outcome.code, 'SENTINEL_BLOCK');
  assert.deepEqual(outcome.reasonCodes, ['KNOWN_ORIGINAL_DETECTED']);
  assert.deepEqual(outcome.rules, ['ref-original-email']);
});

/* ------------------------------------------------------------------------------------------- *
 * Pure protocol assertions over the same functions the runner calls.
 * ------------------------------------------------------------------------------------------- */

test('the reason vocabulary is exactly the fixed sentinel code set', () => {
  assert.equal(isSentinelBlockReason('KNOWN_ORIGINAL_DETECTED'), true);
  assert.equal(isSentinelBlockReason('SENTINEL_UNAVAILABLE'), false);
  assert.equal(isSentinelBlockReason(PLANTED_ORIGINAL), false);
  assert.equal(isSentinelBlockReason('high_risk_pattern'), false);
  assert.equal(isSentinelBlockReason(''), false);
});

test('a snapshot is a private copy: mutating the submitted key, entries and bytes changes nothing', () => {
  const key = Uint8Array.from(KEY);
  const bytes = text('{"a":1}');
  const entries = [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }];
  const snap = snapshotSentinelRequest(request({ bytes, known: registration(SCOPE, entries, key) }), 'r0000000000000001');
  assert.equal(snap.ok, true);

  key.fill(9);
  bytes.fill(9);
  entries[0].value = 'mutated';
  entries.push({ kind: 'CANARY', value: 'x', ref: 'ref-extra' });

  assert.deepEqual(Buffer.from(snap.value.known.key), Buffer.from(KEY));
  assert.equal(snap.value.known.entries.length, 1);
  assert.equal(snap.value.known.entries[0].value, PLANTED_ORIGINAL);
  assert.equal(Buffer.from(snap.value.payload).toString('utf8'), '{"a":1}');
  assert.deepEqual([...snap.value.registeredRefs], ['ref-original-email']);
});

test('a request frame round-trips the exact bytes and a truncated or altered one is refused', () => {
  const snap = snapshotSentinelRequest(request({
    known: registration(SCOPE, [{ kind: 'CANARY', value: PLANTED_CANARY, ref: 'ref-canary-token' }]),
  }), 'r0000000000000002');
  assert.equal(snap.ok, true);
  const frame = encodeRequestFrame(snap.value);
  assert.ok(frame instanceof Uint8Array);

  const rebuilt = decodeRequestFrame(frame);
  assert.equal(rebuilt.ok, true);
  assert.equal(Buffer.from(rebuilt.ok ? rebuilt.value.payload : new Uint8Array(0)).toString('utf8'),
    Buffer.from(snap.value.payload).toString('utf8'));
  assert.equal(rebuilt.ok && rebuilt.value.payloadDigest, snap.value.payloadDigest);
  assert.deepEqual(rebuilt.ok ? [...rebuilt.value.registeredRefs] : [], ['ref-canary-token']);
  assert.equal(rebuilt.ok && rebuilt.value.known.entries[0].value, PLANTED_CANARY);

  // A raw key or payload may legitimately contain a newline byte, so only the declared length and the
  // trailing newline distinguish a truncated request frame.
  assert.equal(decodeRequestFrame(frame.subarray(0, frame.byteLength - 1)).ok, false);
  const extended = new Uint8Array(frame.byteLength + 1);
  extended.set(frame, 0);
  assert.equal(decodeRequestFrame(extended).ok, false);
});

test('reply framing follows the declared length, not a newline scan', () => {
  const reply = encodeResponseFrame({
    requestId: 'r0000000000000001', tenantRef: 'tenant-001', projectRef: 'project-001',
    observedId: 'DEST-SYNTHETIC-LOCAL', observedProfileDigest: 'sha256:0f1e2d3c4b5a6978',
    authorizedId: 'DEST-SYNTHETIC-LOCAL', authorizedProfileDigest: 'sha256:0f1e2d3c4b5a6978',
    payloadDigest: 'a'.repeat(64),
    response: { decision: 'ALLOW', reasonCodes: [], rules: [] },
  });
  // `tenant-001` is exactly ten bytes, so its big-endian length field ends in byte 0x0a. Inside a
  // length-delimited frame that byte is ordinary binary data, not a second reply delimiter.
  assert.equal(classifyReplyFraming(reply), 'OK');
  assert.equal(classifyReplyFraming(reply.subarray(0, reply.byteLength - 1)), 'REPLY_MALFORMED');
  assert.equal(classifyReplyFraming(Buffer.concat([reply, reply])), 'REPLY_DUPLICATE');
  assert.equal(classifyReplyFraming(new Uint8Array(0)), 'REPLY_MALFORMED');
  assert.equal(classifyReplyFraming(new TextEncoder().encode('not a frame at all\n')), 'REPLY_MALFORMED');
  const trailing = new Uint8Array(reply.byteLength + 4);
  trailing.set(reply, 0);
  trailing.set(text('junk'), reply.byteLength);
  assert.equal(classifyReplyFraming(trailing), 'REPLY_MALFORMED');
});

/* ------------------------------------------------------------------------------------------- *
 * Boundary correction (2026-10-04): descriptor-only snapshots, busy-before-inspection admission,
 * an exact runner configuration, length-delimited binary frames, original values as CONTENT rather
 * than identifiers, and an independent capture of the caller's own diagnostic channels.
 * ------------------------------------------------------------------------------------------- */

test('a caller accessor is refused without being invoked, and a planted throw never escapes check', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 5_000 });
  let invoked = 0;
  const hostileBytes = request();
  Object.defineProperty(hostileBytes, 'bytes', {
    enumerable: true,
    get() { invoked += 1; throw new Error(`planted ${PLANTED_ORIGINAL}`); },
  });
  const thrown = await bounded(runner.check(hostileBytes), 1_000, 'throwing bytes accessor');
  assert.equal(thrown.code, 'INVALID_REQUEST');
  assert.equal(invoked, 0, 'a refused accessor must never be invoked');

  const hostileScope = request({
    scope: { get tenantRef() { invoked += 1; throw new Error(PLANTED_ORIGINAL); }, projectRef: 'project-001' },
  });
  assert.equal((await bounded(runner.check(hostileScope), 1_000, 'throwing scope accessor')).code, 'INVALID_REQUEST');
  assert.equal(invoked, 0, 'a refused nested accessor must never be invoked');
  assert.equal(runner.state, 'IDLE');
});

test('a caller-overridden typed-array method cannot break or steer the private copy', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 5_000 });
  const bytes = text(`{"email":"${PLANTED_ORIGINAL}"}`);
  for (const name of ['slice', 'set', 'subarray']) {
    Object.defineProperty(bytes, name, { enumerable: false, value() { throw new Error(`planted ${name}`); } });
  }
  const outcome = await bounded(runner.check(request({
    bytes,
    known: registration(SCOPE, [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }]),
  })), 5_000, 'overridden typed array check');

  assert.equal(outcome.code, 'SENTINEL_BLOCK');
  assert.deepEqual(outcome.reasonCodes, ['KNOWN_ORIGINAL_DETECTED']);
  assert.deepEqual(outcome.rules, ['ref-original-email']);
  assert.equal(runner.state, 'IDLE');
});

test('a shadowed payload or key byteLength, set or iterator is never invoked and the snapshot stays exact', () => {
  let invoked = 0;
  const payload = text(`{"email":"${PLANTED_ORIGINAL}"}`);
  const key = Uint8Array.from(KEY);
  for (const target of [payload, key]) {
    Object.defineProperty(target, 'byteLength', { configurable: true, get() { invoked += 1; return 32; } });
    Object.defineProperty(target, 'set', { configurable: true, value() { invoked += 1; throw new Error('planted set'); } });
    Object.defineProperty(target, Symbol.iterator, {
      configurable: true,
      value() { invoked += 1; throw new Error('planted iterator'); },
    });
  }
  const entries = [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }];
  const shadowed = snapshotSentinelRequest(
    request({ bytes: payload, known: registration(SCOPE, entries, key) }), 'r-shadow-getters',
  );

  assert.equal(invoked, 0, 'a shadowed payload or key property must never be invoked');
  assert.equal(shadowed.ok, true, 'a genuine byte array stays admissible');

  // The positive control is the same request with no shadow at all: byte identity, the digest and the
  // private key copy must be indistinguishable, so ignoring the shadow changed no effect.
  const clean = snapshotSentinelRequest(
    request({ bytes: text(`{"email":"${PLANTED_ORIGINAL}"}`), known: registration(SCOPE, entries) }), 'r-shadow-getters',
  );
  assert.equal(clean.ok, true);
  assert.deepEqual(Buffer.from(shadowed.value.payload), Buffer.from(clean.value.payload));
  assert.equal(shadowed.value.payloadDigest, clean.value.payloadDigest);
  assert.deepEqual(Buffer.from(shadowed.value.known.key), Buffer.from(clean.value.known.key));
  assert.notEqual(shadowed.value.payload, payload, 'the payload must still be a private copy');
  assert.notEqual(shadowed.value.known.key, key, 'the key must still be a private copy');
});

test('a Proxy over bytes, and any non-byte view, is refused without one reflection trap', () => {
  let traps = 0;
  const count = (apply) => (target, property, receiver) => {
    traps += 1;
    return apply(target, property, receiver);
  };
  const proxiedBytes = new Proxy(text(`{"email":"${PLANTED_ORIGINAL}"}`), {
    get: count((target, property, receiver) => Reflect.get(target, property, receiver)),
    getOwnPropertyDescriptor: count((target, property) => Reflect.getOwnPropertyDescriptor(target, property)),
    has: count((target, property) => Reflect.has(target, property)),
    ownKeys: count((target) => Reflect.ownKeys(target)),
    getPrototypeOf: count((target) => Reflect.getPrototypeOf(target)),
  });
  const entries = [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }];

  const asPayload = snapshotSentinelRequest(request({ bytes: proxiedBytes }), 'r-proxy-bytes');
  assert.equal(asPayload.ok, false);
  assert.equal(asPayload.code, 'INVALID_REQUEST');
  const afterPayload = traps;

  const asKey = snapshotSentinelRequest(
    request({ known: registration(SCOPE, entries, proxiedBytes) }), 'r-proxy-key',
  );
  assert.equal(asKey.code, 'INVALID_REQUEST');
  assert.equal(traps, afterPayload, `a refused registration key dispatched ${traps - afterPayload} trap(s)`);
  assert.equal(afterPayload, 0, `a refused payload dispatched ${afterPayload} reflection trap(s)`);

  // A narrow typed array shares the typed-array brand but is not byte identity.
  assert.equal(snapshotSentinelRequest(request({ bytes: new Int8Array([1, 2, 3]) }), 'r-int8').code, 'INVALID_REQUEST');
});

test('a species-producing brand check is gone: a constructor or Symbol.species getter is never invoked', () => {
  // `TypedArray.prototype.slice` and `subarray` are SPECIES producers: validating with either reads
  // caller-owned `constructor[Symbol.species]` and can construct a replacement array from user code.
  // That dispatch runs before any restriction exists, and catching its exception cannot retract what
  // it already disclosed. Admission must read internal slots only.
  let invoked = 0;
  const plant = (label) => () => { invoked += 1; throw new Error(`planted ${label} ${PLANTED_ORIGINAL}`); };
  const payload = text(`{"email":"${PLANTED_ORIGINAL}"}`);
  const key = Uint8Array.from(KEY);
  for (const target of [payload, key]) {
    const speciesConstructor = Object.create(Uint8Array);
    Object.defineProperty(speciesConstructor, Symbol.species, {
      configurable: true,
      get() { invoked += 1; throw new Error(`planted species ${PLANTED_ORIGINAL}`); },
    });
    Object.defineProperty(target, 'constructor', {
      configurable: true,
      get() { invoked += 1; return speciesConstructor; },
    });
    Object.defineProperty(target, Symbol.species, {
      configurable: true,
      get() { invoked += 1; throw new Error(`planted own species ${PLANTED_ORIGINAL}`); },
    });
  }
  const entries = [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }];
  const snapshot = snapshotSentinelRequest(
    request({ bytes: payload, known: registration(SCOPE, entries, key) }), 'r-species',
  );

  assert.equal(invoked, 0, `admission dispatched ${invoked} caller getter(s)`);
  assert.equal(snapshot.ok, true, 'a genuine byte array stays admissible under a species trap');
  const clean = snapshotSentinelRequest(
    request({ bytes: text(`{"email":"${PLANTED_ORIGINAL}"}`), known: registration(SCOPE, entries) }), 'r-species',
  );
  assert.deepEqual(Buffer.from(snapshot.value.payload), Buffer.from(clean.value.payload));
  assert.equal(snapshot.value.payloadDigest, clean.value.payloadDigest);
  assert.deepEqual(Buffer.from(snapshot.value.known.key), Buffer.from(clean.value.known.key));
  assert.notEqual(snapshot.value.payload, payload, 'the payload must still be a private copy');
  assert.notEqual(snapshot.value.known.key, key, 'the key must still be a private copy');
  assert.doesNotMatch(
    JSON.stringify(snapshot.value), /planted (species|own species|constructor)/,
    'no planted diagnostic from a getter may surface in the snapshot',
  );
});

test('a re-prototyped non-byte view is refused on its native element kind, not its prototype identity', () => {
  // Prototype identity is mutable caller state and proves nothing about the internal element kind.
  // A genuine `Int8Array` wearing `Uint8Array.prototype` must still be refused; a real `Buffer`, whose
  // intrinsic kind is `Uint8Array`, must still be admitted.
  const entries = [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }];
  const disguised = new Int8Array([1, 2, 3]);
  Object.setPrototypeOf(disguised, Uint8Array.prototype);
  assert.equal(Object.getPrototypeOf(disguised) === Uint8Array.prototype, true);
  assert.equal(snapshotSentinelRequest(request({ bytes: disguised }), 'r-reprototype').code, 'INVALID_REQUEST');
  assert.equal(
    snapshotSentinelRequest(request({ known: registration(SCOPE, entries, disguised) }), 'r-reprototype-key').code,
    'INVALID_REQUEST',
  );

  const fromBuffer = Buffer.from(`{"email":"${PLANTED_ORIGINAL}"}`);
  const admitted = snapshotSentinelRequest(
    request({ bytes: fromBuffer, known: registration(SCOPE, entries, Buffer.from(KEY)) }), 'r-buffer-kind',
  );
  assert.equal(admitted.ok, true, 'a Buffer is a genuine Uint8Array and stays admissible');
  assert.deepEqual(Buffer.from(admitted.value.payload), Buffer.from(`{"email":"${PLANTED_ORIGINAL}"}`));
});

test('a genuine Uint8Array subclass is admitted exactly like a Buffer, and its own getters are never invoked', () => {
  // Subclassing changes the prototype chain, not the internal element kind. Admission reads internal
  // slots only, so an ordinary `class SyntheticBytes extends Uint8Array {}` instance IS byte identity
  // here and must not be refused for what it is; what must never happen is reading any of its getters.
  let invoked = 0;
  const plant = (label) => () => { invoked += 1; throw new Error(`planted ${label}`); };
  class SyntheticBytes extends Uint8Array {}
  const payload = SyntheticBytes.from(text(`{"email":"${PLANTED_ORIGINAL}"}`));
  const key = SyntheticBytes.from(KEY);
  for (const target of [payload, key]) {
    Object.defineProperty(target, 'constructor', { configurable: true, get: plant('constructor') });
    Object.defineProperty(target, Symbol.species, { configurable: true, get: plant('species') });
    Object.defineProperty(target, Symbol.iterator, { configurable: true, get: plant('iterator') });
    Object.defineProperty(target, Symbol.toStringTag, { configurable: true, get: plant('tag') });
    Object.defineProperty(target, 'length', { configurable: true, get: plant('length') });
  }
  const entries = [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }];
  const snapshot = snapshotSentinelRequest(
    request({ bytes: payload, known: registration(SCOPE, entries, key) }), 'r-subclass-kind',
  );

  assert.equal(invoked, 0, `admission dispatched ${invoked} caller getter(s)`);
  assert.equal(snapshot.ok, true, 'a genuine Uint8Array subclass is byte identity, exactly like a Buffer');

  // The independent control is the same request built from plain arrays: byte identity, the digest, the
  // private key copy and the entry copies must be indistinguishable, so admitting the subclass changed
  // no effect, and the caller buffers must still be copied rather than retained.
  const clean = snapshotSentinelRequest(
    request({ bytes: text(`{"email":"${PLANTED_ORIGINAL}"}`), known: registration(SCOPE, entries) }), 'r-subclass-kind',
  );
  assert.equal(clean.ok, true);
  assert.deepEqual(Buffer.from(snapshot.value.payload), Buffer.from(`{"email":"${PLANTED_ORIGINAL}"}`));
  assert.deepEqual(Buffer.from(snapshot.value.payload), Buffer.from(clean.value.payload));
  assert.equal(snapshot.value.payloadDigest, clean.value.payloadDigest);
  assert.deepEqual(Buffer.from(snapshot.value.known.key), Buffer.from(KEY));
  assert.deepEqual(Buffer.from(snapshot.value.known.key), Buffer.from(clean.value.known.key));
  assert.deepEqual(snapshot.value.known.entries, clean.value.known.entries);
  assert.notEqual(snapshot.value.payload, payload, 'the payload must be a private copy, not the caller subclass');
  assert.notEqual(snapshot.value.known.key, key, 'the key must be a private copy, not the caller subclass');
  assert.notEqual(
    Object.getPrototypeOf(snapshot.value.payload), SyntheticBytes.prototype,
    'the private copy is an ordinary byte array, not the caller subclass',
  );
});

test('admission is busy before any caller inspection, so a reentrant check cannot start a second child', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 5_000 });
  let reentrant = null;
  // A `Proxy` trap is caller-observable code that runs during the snapshot: it is the one reentry
  // surface left once every value is read from a descriptor instead of an ordinary property read.
  const hostile = new Proxy(request(), {
    getOwnPropertyDescriptor(target, property) {
      if (property !== 'bytes') return Reflect.getOwnPropertyDescriptor(target, property);
      reentrant = runner.check(request());
      return { configurable: true, enumerable: true, get() { throw new Error('planted'); } };
    },
  });
  const outcome = await bounded(runner.check(hostile), 2_000, 'reentrant check');
  assert.equal(outcome.code, 'INVALID_REQUEST');
  const inner = await bounded(reentrant, 2_000, 'reentrant inner check');
  assert.equal(inner.code, 'RUNNER_BUSY');
  assert.equal(runner.state, 'IDLE', 'an invalid pre-spawn snapshot must release admission safely');
});

test('an unsupported runner configuration is refused before spawn without reading an accessor', async () => {
  let invoked = 0;
  const withSignal = {
    deadlineMs: 5_000,
    signal: { get aborted() { invoked += 1; return false; } },
  };
  const signalRunner = createSentinelProcessRunner(withSignal);
  assert.equal((await bounded(signalRunner.check(request()), 1_000, 'runner signal config')).code, 'INVALID_REQUEST');
  assert.equal(signalRunner.state, 'IDLE');

  for (const extra of [{ worker: '/tmp/anything.mjs' }, { options: {} }, { cleanupGraceMs: 10, shell: true }]) {
    const runner = createSentinelProcessRunner({ deadlineMs: 5_000, ...extra });
    assert.equal((await bounded(runner.check(request()), 1_000, `runner config ${Object.keys(extra)[0]}`)).code,
      'INVALID_REQUEST', `unsupported runner option ${Object.keys(extra)[0]} was accepted`);
  }

  const accessorConfig = { deadlineMs: 5_000 };
  Object.defineProperty(accessorConfig, 'cleanupGraceMs', {
    enumerable: true,
    get() { invoked += 1; return 250; },
  });
  const accessorRunner = createSentinelProcessRunner(accessorConfig);
  assert.equal((await bounded(accessorRunner.check(request()), 1_000, 'accessor runner config')).code, 'INVALID_REQUEST');
  assert.equal(invoked, 0, 'a refused configuration accessor must never be invoked');
});

test('a supported runner configuration with only cleanupGraceMs still runs', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 5_000, cleanupGraceMs: 250 });
  const outcome = await bounded(runner.check(request()), 5_000, 'supported config check');
  assert.equal(outcome.status, 'ALLOW');
});

test('real child: a ten-byte tenant label is a healthy reply, not a duplicate', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const source = text('{"status":"synthetic-ok","note":"nothing protected here"}');
  const scope = Object.freeze({ tenantRef: 'tenant-001', projectRef: 'project-001' });
  const outcome = await bounded(runner.check(request({ scope, bytes: source })), 10_000, 'ten byte tenant check');

  assert.equal(outcome.status, 'ALLOW');
  assert.deepEqual(Buffer.from(outcome.release), Buffer.from(source));
});

test('a known original that spans several lines is content: it round-trips and still restricts', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  const multiline = 'first synthetic line\n  indented second line\nthird synthetic line';
  const detect = await bounded(runner.check(request({
    bytes: text(`note follows\n${multiline}\nend note`),
    known: registration(SCOPE, [{ kind: 'ORIGINAL', value: multiline, ref: 'ref-multiline-original' }]),
  })), 10_000, 'multiline original check');
  assert.equal(detect.code, 'SENTINEL_BLOCK');
  assert.ok(detect.reasonCodes.includes('KNOWN_ORIGINAL_DETECTED'), JSON.stringify(detect.reasonCodes));
  assert.ok(detect.rules.includes('ref-multiline-original'), JSON.stringify(detect.rules));

  // The positive control: the same multiline registration against a payload that does not contain it
  // must stay a normal, non-refused check. Newlines in scope and destination labels stay refused.
  const clean = await bounded(runner.check(request({
    scope: { tenantRef: SCOPE.tenantRef, projectRef: SCOPE.projectRef },
    known: registration(SCOPE, [{ kind: 'ORIGINAL', value: multiline, ref: 'ref-multiline-original' }]),
  })), 10_000, 'multiline registration positive control');
  assert.equal(clean.status, 'ALLOW');

  const labelled = await bounded(runner.check(request({
    scope: { tenantRef: 'tenant-synthetic-01\ninjected', projectRef: SCOPE.projectRef },
  })), 1_000, 'newline scope label check');
  assert.equal(labelled.code, 'INVALID_REQUEST');
});

/* ---- Independent diagnostic-channel capture ---- */

const DRIVER = String.raw`
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const control = JSON.parse(readFileSync(HERE + 'driver-control.json', 'utf8'));
const wrapper = await import(pathToFileURL(HERE + 'egress-sentinel-process.js').href);
const scope = { tenantRef: 'tenant-synthetic-01', projectRef: 'project-synthetic-01' };
const destination = { id: 'DEST-SYNTHETIC-LOCAL', profileDigest: 'sha256:0f1e2d3c4b5a6978' };
const key = Uint8Array.from(Array.from({ length: 32 }, (unused, index) => (index * 7 + 3) & 0xff));
const bytes = new TextEncoder().encode('synthetic payload for ' + control.marker);
// A shadowed byteLength is an ordinary own accessor on an otherwise genuine byte array: if admission
// or copying reads it as a property, caller code runs and can disclose through stderr right there.
if (control.shadowGetter) {
  for (const target of [bytes, key]) {
    const disclose = (label) => { process.stderr.write('SHADOW-GETTER ' + label + ' ' + control.marker + '\n'); };
    Object.defineProperty(target, 'byteLength', { configurable: true, get() { disclose('byteLength'); return 32; } });
    Object.defineProperty(target, 'set', { configurable: true, value() { disclose('set'); } });
    Object.defineProperty(target, Symbol.iterator, { configurable: true, value() { disclose('iterator'); return [][Symbol.iterator](); } });
  }
}
const outcome = await wrapper.createSentinelProcessRunner({ deadlineMs: 400 }).check({
  bytes,
  scope, destination, authorized: destination,
  known: { scope, key, entries: [{ kind: 'ORIGINAL', value: control.marker, ref: 'ref-original-email' }] },
});
if (control.leak) {
  process.stdout.write('DRIVER-STDOUT ' + control.marker + '\n');
  process.stderr.write('DRIVER-STDERR ' + control.marker + '\n');
}
process.stdout.write('OUTCOME ' + outcome.status + ' ' + (outcome.code ?? 'none') + '\n');
`;

/** Run a command and capture BOTH of its ordinary diagnostic channels to completion. */
function captureChannels(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString('utf8'); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
    child.on('error', reject);
    child.on('close', () => resolve({ stdout, stderr }));
  });
}

async function runDiagnosticDriver(control) {
  const { installation } = await fakeRunner(
    { mode: 'leak-diagnostics', marker: PLANTED_ORIGINAL }, { deadlineMs: 400 },
  );
  writeFileSync(join(installation, 'driver-control.json'), JSON.stringify({ ...control, marker: PLANTED_ORIGINAL }));
  writeFileSync(join(installation, 'driver.mjs'), DRIVER, 'utf8');
  return captureChannels(process.execPath, [join(installation, 'driver.mjs')]);
}

test('a hostile child stdout and stderr are withheld: an independent capture sees no planted marker', async () => {
  const captured = await bounded(runDiagnosticDriver({ leak: false }), 20_000, 'withholding driver');

  assert.match(captured.stdout, /OUTCOME BLOCK SENTINEL_BLOCK|DEADLINE_EXCEEDED/, 'the driver must still reach a real outcome');
  assert.equal(captured.stdout.includes(PLANTED_ORIGINAL), false, `child stdout leaked: ${captured.stdout}`);
  assert.equal(captured.stderr.includes(PLANTED_ORIGINAL), false, `child stderr leaked: ${captured.stderr}`);
  assert.equal(captured.stderr.includes('STDOUT-LEAK'), false);
});

test('the same capture detects a deliberate leak, so the withholding result is not a blind capture', async () => {
  const captured = await bounded(runDiagnosticDriver({ leak: true }), 20_000, 'leaking control');

  assert.match(captured.stdout, /OUTCOME BLOCK SENTINEL_BLOCK|DEADLINE_EXCEEDED/);
  assert.ok(captured.stdout.includes(PLANTED_ORIGINAL), 'the capture missed a known stdout disclosure');
  assert.ok(captured.stderr.includes(PLANTED_ORIGINAL), 'the capture missed a known stderr disclosure');
});

test('a shadowed payload or key getter cannot disclose through the caller diagnostic channels', async () => {
  const captured = await bounded(runDiagnosticDriver({ leak: false, shadowGetter: true }), 20_000, 'shadow-getter driver');

  assert.match(captured.stdout, /OUTCOME BLOCK SENTINEL_BLOCK|DEADLINE_EXCEEDED/, 'the driver must still reach a real outcome');
  assert.equal(captured.stderr.includes('SHADOW-GETTER'), false, `a shadow getter ran: ${captured.stderr}`);
  assert.equal(captured.stderr.includes(PLANTED_ORIGINAL), false, `getter disclosure: ${captured.stderr}`);
  assert.equal(captured.stdout.includes(PLANTED_ORIGINAL), false, `stdout disclosure: ${captured.stdout}`);
});

test('the pure reply decoder refuses a binding difference, a foreign ref and an inconsistent decision', () => {
  const snap = snapshotSentinelRequest(request({
    known: registration(SCOPE, [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'ref-original-email' }]),
  }), 'r0000000000000003');
  assert.equal(snap.ok, true);
  const base = {
    requestId: snap.value.requestId,
    tenantRef: snap.value.scope.tenantRef,
    projectRef: snap.value.scope.projectRef,
    observedId: snap.value.observed.id,
    observedProfileDigest: snap.value.observed.profileDigest,
    authorizedId: snap.value.authorized.id,
    authorizedProfileDigest: snap.value.authorized.profileDigest,
    payloadDigest: snap.value.payloadDigest,
  };
  const encode = (response) => encodeResponseFrame({ ...base, response });

  const allow = decodeResponseFrame(encode({ decision: 'ALLOW', reasonCodes: [], rules: [] }), snap.value);
  assert.equal(allow.ok, true);
  assert.equal(allow.ok && allow.value.decision, 'ALLOW');

  for (const [response, code] of [
    [{ decision: 'ALLOW', reasonCodes: ['HIGH_RISK_PATTERN'], rules: [] }, 'REPLY_MALFORMED'],
    [{ decision: 'BLOCK', reasonCodes: [], rules: [] }, 'REPLY_MALFORMED'],
    [{ decision: 'BLOCK', reasonCodes: [PLANTED_ORIGINAL], rules: [] }, 'REPLY_MALFORMED'],
    [{ decision: 'BLOCK', reasonCodes: ['HIGH_RISK_PATTERN'], rules: ['ref-not-registered'] }, 'REPLY_MALFORMED'],
    [{ decision: 'BLOCK', reasonCodes: ['KNOWN_ORIGINAL_DETECTED'], rules: ['ref-original-email'] }, null],
  ]) {
    const decoded = decodeResponseFrame(encode(response), snap.value);
    assert.equal(decoded.ok, code === null, `unexpected result for ${JSON.stringify(response)}`);
    if (code !== null) assert.equal(decoded.code, code);
  }

  const foreign = decodeResponseFrame(encodeResponseFrame({
    ...base, tenantRef: OTHER_SCOPE.tenantRef, response: { decision: 'ALLOW', reasonCodes: [], rules: [] },
  }), snap.value);
  assert.equal(foreign.ok, false);
  assert.equal(foreign.ok === false && foreign.code, 'REPLY_BINDING_MISMATCH');
});

/* ------------------------------------------------------------------------------------------- *
 * Deterministic adversarial scope cases.
 * ------------------------------------------------------------------------------------------- */

test('across generated tenant/project pairs, only the matching registration is accepted and it still binds', async () => {
  const runner = createSentinelProcessRunner({ deadlineMs: 10_000 });
  let state = 0x13579bdf;
  const nextInt = (limit) => { state = (Math.imul(state, 1103515245) + 12345) >>> 0; return (state >>> 8) % limit; };

  for (let index = 0; index < 12; index++) {
    const scope = Object.freeze({
      tenantRef: `tenant-synthetic-${nextInt(9999)}`,
      projectRef: `project-synthetic-${nextInt(9999)}`,
    });
    const foreignScope = Object.freeze({
      tenantRef: `${scope.tenantRef}x`,
      projectRef: scope.projectRef,
    });
    const ref = `ref-scope-${index}`;

    const foreign = await bounded(runner.check(request({
      scope, known: registration(foreignScope, [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref }]),
    })), 2_000, `foreign scope ${index}`);
    assert.equal(foreign.code, 'INVALID_REQUEST');

    const matching = await bounded(runner.check(request({
      scope,
      bytes: text(`{"email":"${PLANTED_ORIGINAL}"}`),
      known: registration(scope, [{ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref }]),
    })), 10_000, `matching scope ${index}`);
    assert.equal(matching.status, 'BLOCK');
    assert.equal(matching.code, 'SENTINEL_BLOCK');
    assert.deepEqual(matching.reasonCodes, ['KNOWN_ORIGINAL_DETECTED']);
    assert.deepEqual(matching.rules, [ref]);

    const clean = await bounded(runner.check(request({ scope })), 10_000, `clean scope ${index}`);
    assert.equal(clean.status, 'ALLOW');
  }
});

test('a runner with no deadline configured refuses every check rather than running unbounded', async () => {
  const runner = createSentinelProcessRunner({});
  const outcome = await bounded(runner.check(request()), 1_000, 'missing deadline check');
  assert.equal(outcome.code, 'INVALID_REQUEST');
  assert.equal(runner.state, 'IDLE');
});