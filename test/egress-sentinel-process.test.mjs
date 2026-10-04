import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

const DIST = fileURLToPath(new URL('../dist/', import.meta.url));

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const text = (value) => new TextEncoder().encode(value);

/** Fail loudly instead of hanging when a parent that should settle never does. */
async function bounded(promise, ms, label) {
  const outcome = await Promise.race([promise, delay(ms).then(() => NEVER)]);
  assert.notEqual(outcome, NEVER, `${label} did not settle within ${ms}ms`);
  return outcome;
}

function registration(scope, entries) {
  return { scope, key: KEY, entries };
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

function alive(pid) {
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
  assert.deepEqual(Object.keys(report.env).sort(), ['LANG', 'LC_ALL', 'NODE_NO_WARNINGS', 'PATH']);
  assert.equal(report.env.NODE_OPTIONS, undefined);
  assert.equal(report.env.HOME, undefined);
  assert.equal(report.argv.length, 1);
  assert.ok(report.argv[0].endsWith('/egress-sentinel-process-worker.js'));
  assert.equal(report.execPath, process.execPath);
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
  ]) });
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
import { readFileSync, writeFileSync } from 'node:fs';
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
  if (control.pidFile) {
    writeFileSync(HERE + control.pidFile, JSON.stringify({ pid: process.pid }));
  }
  switch (control.mode) {
    case 'report':
      process.exit(0);
      return;
    case 'stall':
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
    case 'stderr-flood':
      process.stderr.write(Buffer.alloc(control.bytes ?? 200000, 0x79));
      setInterval(() => {}, 1000);
      return;
    case 'grandchild': {
      const held = spawn(process.execPath, ['-e', 'setTimeout(() => {}, ' + (control.grandchildMs ?? 900) + ')'],
        { stdio: ['ignore', 'inherit', 'inherit'] });
      writeFileSync(HERE + control.pidFile, JSON.stringify({ pid: process.pid, held: held.pid }));
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

  let pid = null;
  for (let attempt = 0; attempt < 100 && pid === null; attempt++) {
    await delay(20);
    const path = join(installation, 'fake-pid.json');
    if (existsSync(path)) pid = JSON.parse(readFileSync(path, 'utf8')).pid;
  }
  assert.equal(typeof pid, 'number', 'the synthetic child never started');

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
  const report = JSON.parse(readFileSync(join(installation, 'fake-pid.json'), 'utf8'));
  assert.equal(typeof report.held, 'number');
  // Let the held grandchild exit so this test leaves no live process behind.
  for (let attempt = 0; attempt < 150 && alive(report.held); attempt++) await delay(20);
  assert.equal(alive(report.held), false, 'the held grandchild outlived the test');
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
  const duplicate = await fakeRunner({
    mode: 'raw-stdout',
    stdoutBase64: Buffer.concat([
      Buffer.from('HSPP\nHSPP\n', 'ascii'),
    ]).toString('base64'),
  }, { deadlineMs: 5_000 });
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
  const snap = snapshotSentinelRequest(request({ bytes, known: registration(SCOPE, entries) }), 'r0000000000000001');
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

test('reply framing distinguishes a truncated reply from a duplicated one', () => {
  const single = new TextEncoder().encode('one-frame\n');
  assert.equal(classifyReplyFraming(single), 'OK');
  assert.equal(classifyReplyFraming(single.subarray(0, single.byteLength - 1)), 'REPLY_MALFORMED');
  assert.equal(classifyReplyFraming(new TextEncoder().encode('one-frame\ntwo-frame\n')), 'REPLY_DUPLICATE');
  assert.equal(classifyReplyFraming(new Uint8Array(0)), 'REPLY_MALFORMED');
  assert.equal(classifyReplyFraming(new TextEncoder().encode('one-frame\ntrailing-bytes')), 'REPLY_MALFORMED');
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