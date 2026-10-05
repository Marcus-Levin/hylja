// #250: the operator-visible synthetic conversation demo, driven as a real subprocess.
//
// What this proves, precisely: the operator command runs the real application-level local conversation
// owner - `createOpenAiLocalConversation` - over a real standard HTTP loopback peer and the real fixture
// host, and prints a fixed summary derived from the real owner result and the real peer, release,
// detector and fixed-worker counters. The default invocation really classifies one synthetic masked
// request with the real detector and the real policy engine, sends it to the peer once and releases one
// guarded reply, with both real children really returning `ALLOW`. The two declared negatives really hold
// at their declared counts: the blocked reply reaches the peer once, the second real child really runs,
// really exits cleanly and really blocks that reply over the registered known original, and nothing is
// released; the unsupported request reaches the peer not at all and starts no worker. A malformed
// invocation is refused before any effect and echoes nothing.
//
// The fourth case is the one that keeps the two refusals honest. The accepted receiver collapses a
// genuine block, a crashed child, a malformed reply and a missing reply into one `SENTINEL_BLOCKED`, so a
// demonstration that trusted that code alone would print "success" for a worker that died. The
// test-only fault driver terminates the SECOND real child and leaves the first alone: the run then
// reports the same owner refusal code, one observed zero exit instead of two, one signal close, one
// `ALLOW` and no `BLOCK`, and the demonstration declines itself with exit 1. The working blocked case is
// asserted in the same test as the control, at its observed counts, so the fault case is not a run that
// fails for an unrelated reason.
//
// Assertions are booleans, counts and fixed labels. Every comparison of captured stdout or stderr is
// turned into a boolean BEFORE it reaches `assert`, so a failing report can never carry a captured byte,
// a planted value or a native error into the TAP output. Planted material and the mask literal are
// declared here independently of the script, and the confidentiality claim itself is observed rather
// than asserted about: the suite spawns a real `node --test` run whose subprocess really printed the
// planted values and whose designated comparison really fails uncaught, then checks that the failing TAP
// that run reported contains none of them. The unsafe counterpart, which really does leak, runs alongside
// so that safe comparison is not vacuous.
//
// What this is NOT. This is not a gateway, a provider client, an authentication implementation, a
// restoration path, a streaming design or a held-out, scored or promotion result. The identity, clock,
// policy bundle, profile digest, known-original registration and the static PUBLIC model/metadata
// records are TRUSTED FIXTURES this demo declares; nothing here authenticates a principal, a tenant, a
// workload or a control plane, and no detector absence is read as clearance. Every value is invented and
// non-routable (`*.invalid`, loopback, a made-up token literal).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  MASKED, PLANTED_ORIGINAL, PLANTED_SECRET,
} from '../scripts/lib/synthetic-conversation-fixture.mjs';
import {
  REPO_ROOT, runNode, runNodeTest, TEST_TIMEOUT_MS,
} from './support/run-node-subprocess.mjs';

const DEMO = fileURLToPath(new URL('../scripts/synthetic-conversation-demo.mjs', import.meta.url));
/** TEST-ONLY. The fixture driver can arm a worker fault; the operator command cannot reach it. */
const FAULT_DRIVER = fileURLToPath(
  new URL('./support/synthetic-conversation-demo-fault-driver.mjs', import.meta.url),
);
/** The test-only probe that really runs assertions over output carrying the planted values, and fails. */
const CONFIDENTIALITY_PROBE = fileURLToPath(
  new URL('./support/synthetic-conversation-demo-confidentiality-probe.test.mjs', import.meta.url),
);
/**
 * The unsafe counterpart: the same comparison with the captured stream as a string operand, which really
 * does report it. Its leaking TAP is captured in this process and only ever reduced to booleans.
 */
const UNSAFE_NEGATIVE_CONTROL = fileURLToPath(
  new URL('./support/synthetic-conversation-demo-unsafe-negative-control.test.mjs', import.meta.url),
);
/** The probe's own test name, declared here so the failing entry can be matched by NAME, not by count. */
const PROBE_TEST_NAME =
  'a subprocess output carrying planted material enters the assertion path and reports none of it';
/** The probe's designated failing message, declared here and identical to the probe's own constant. */
const PROBE_DESIGNATED_MESSAGE =
  'this probe ends on a deliberately failing boolean comparison over a captured stream';

/** Run the real operator entry point in a real child process. */
const runDemo = (args) => runNode(DEMO, args);

/** The declared counters of each case, as the summary must report them. Nothing here is inferred. */
const ROWS = Object.freeze({
  default: {
    result: 'COMPLETED', code: 'none', connections: 1, requests: 1, releases: 1, mask: 'yes',
    runs: 2, findings: 1,
    workers: { spawned: 2, exitedZero: 2, closedBySignal: 0, frames: 2, allow: 2, block: 0, named: 0 },
  },
  'blocked-reply': {
    result: 'REFUSED', code: 'SENTINEL_BLOCKED', connections: 1, requests: 1, releases: 0, mask: 'yes',
    runs: 2, findings: 1,
    workers: { spawned: 2, exitedZero: 2, closedBySignal: 0, frames: 2, allow: 1, block: 1, named: 1 },
  },
  'unsupported-request': {
    result: 'REFUSED', code: 'UNSUPPORTED_TOOLS', connections: 0, requests: 0, releases: 0, mask: 'no',
    runs: 0, findings: 0,
    workers: { spawned: 0, exitedZero: 0, closedBySignal: 0, frames: 0, allow: 0, block: 0, named: 0 },
  },
  /** The blocked-reply case with its SECOND real child terminated: the first one still really allows. */
  faulted: {
    result: 'REFUSED', code: 'SENTINEL_BLOCKED', connections: 1, requests: 1, releases: 0, mask: 'yes',
    runs: 2, findings: 1,
    workers: { spawned: 2, exitedZero: 1, closedBySignal: 1, frames: 1, allow: 1, block: 0, named: 0 },
  },
  /**
   * The blocked-reply case with its SECOND real child's reply replaced by a frame the protocol must
   * refuse: an unknown reason code, a foreign binding, or one ref over the rule bound. The child really
   * runs and really exits cleanly - it only answered differently - so the request-side `ALLOW` is
   * unaffected and the demonstration still has to decline itself.
   */
  unfavourableReply: {
    result: 'REFUSED', code: 'SENTINEL_BLOCKED', connections: 1, requests: 1, releases: 0, mask: 'yes',
    runs: 2, findings: 1,
    workers: { spawned: 2, exitedZero: 2, closedBySignal: 0, frames: 1, allow: 1, block: 0, named: 0 },
  },
});

/** The fixed labels the demo prints about what it is and is not. */
const LABELS = Object.freeze([
  'synthetic loopback only: no provider, no credential, no real host, no network beyond 127.0.0.1',
  'trusted fixture identity, clock and policy inputs; nothing here authenticates a principal, workload, tenant or control plane',
  'the model and metadata PUBLIC records are trusted fixture labels, not an inference from detector absence',
  'irreversible whole-message MASK of accepted decision 011; proposed decision 010 is not wired in',
  'no production authentication, no streaming, no restoration and no held-out utility, scoring or release claim',
]);

/** The exact summary one case must print: a fixed shape, never a captured copy of the real output. */
function summaryOf(name, row) {
  return [
    'hylja synthetic conversation demo',
    `case: ${name}`,
    'transport: standard HTTP peer on 127.0.0.1, OS-assigned ephemeral port (synthetic loopback)',
    `owner result: ${row.result}`,
    `owner refusal code: ${row.code}`,
    `peer connections: ${row.connections}`,
    `peer requests: ${row.requests}`,
    'peer observed the planted original: no',
    'peer observed the planted secret: no',
    `peer observed the generic mask literal: ${row.mask}`,
    `application releases: ${row.releases}`,
    'application release carried the planted original: no',
    `real detector runs: ${row.runs}`,
    `real detector findings: ${row.findings}`,
    `real fixed-worker children spawned: ${row.workers.spawned}`,
    `real fixed-worker children that exited with code zero: ${row.workers.exitedZero}`,
    `real fixed-worker children closed by a signal: ${row.workers.closedBySignal}`,
    'real fixed-worker children that never reported close: 0',
    `real fixed-worker replies read as exactly one complete decision frame: ${row.workers.frames}`,
    `real fixed-worker ALLOW decisions: ${row.workers.allow}`,
    `real fixed-worker BLOCK decisions: ${row.workers.block}`,
    `real fixed-worker blocks naming the registered known original: ${row.workers.named}`,
    'fixed-worker children still live after cleanup: 0',
    'peer sockets open after cleanup: 0',
    'owner state after the exchange: IDLE',
    'labels:',
    ...LABELS.map((label) => `- ${label}`),
  ].join('\n');
}

/** The exact refusal text a malformed invocation gets, declared here rather than captured. */
const REFUSAL_STDERR = 'hylja synthetic conversation demo: argument refused\n'
  + 'expected: no arguments, or --case default | --case blocked-reply'
  + ' | --case unsupported-request\n';
/** The exact line a demonstration that missed its own declared behaviour prints. */
const DECLINED_STDERR = 'hylja synthetic conversation demo: the case did not match its declared behaviour\n';

/**
 * Nothing planted may appear anywhere in what the operator sees, in either stream. Each check is a
 * boolean over the whole captured output, so a failing report says only that a value was present.
 */
const assertNoPlantedMaterial = (run, what) => {
  const printed = `${run.stdout}${run.stderr}`;
  assert.equal(printed.includes(PLANTED_ORIGINAL), false,
    `${what}: no planted original printed`);
  assert.equal(printed.includes(PLANTED_SECRET), false,
    `${what}: no planted secret printed`);
  assert.equal(printed.includes(MASKED), false,
    `${what}: no mask literal printed`);
};

test('the default operator command masks one synthetic request and releases one guarded reply',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const run = await runDemo([]);
    assert.equal(run.stalled, false, 'the invocation finished inside its bound');
    assert.equal(run.signal, null, 'the demo exited on its own, with no signal and no orphan left behind');
    assert.equal(run.code, 0, 'a completed demonstration exits zero');
    assert.equal(run.stderr === '', true, 'the completed case prints nothing on stderr');
    assert.equal(run.stdout === `${summaryOf('default', ROWS.default)}\n`, true,
      'the printed summary is exactly the declared fixed shape and counters');
    assertNoPlantedMaterial(run, 'the default case');
  });

test('a blocked reply reaches the peer once, really blocks on the registered original, and releases nothing',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const run = await runDemo(['--case', 'blocked-reply']);
    assert.equal(run.stalled, false, 'the invocation finished inside its bound');
    assert.equal(run.signal, null, 'the demo exited on its own, with no signal and no orphan left behind');
    assert.equal(run.code, 0, 'an expected refusal is a successful demonstration');
    assert.equal(run.stderr === '', true, 'the expected refusal prints nothing on stderr');
    assert.equal(run.stdout === `${summaryOf('blocked-reply', ROWS['blocked-reply'])}\n`, true,
      'one upstream request, zero releases and the real blocked reply are reported exactly');
    assertNoPlantedMaterial(run, 'the blocked reply case');
  });

test('an unsupported request reaches no payload request at all, starts no worker and releases nothing',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const run = await runDemo(['--case', 'unsupported-request']);
    assert.equal(run.stalled, false, 'the invocation finished inside its bound');
    assert.equal(run.signal, null, 'the demo exited on its own, with no signal and no orphan left behind');
    assert.equal(run.code, 0, 'an expected refusal is a successful demonstration');
    assert.equal(run.stderr === '', true, 'the expected refusal prints nothing on stderr');
    assert.equal(run.stdout === `${summaryOf('unsupported-request', ROWS['unsupported-request'])}\n`, true,
      'the strict codec refusal is reported with zero peer requests, zero workers and zero releases');
    assertNoPlantedMaterial(run, 'the unsupported request case');
  });

test('a malformed invocation is refused before any effect and never echoes its argument',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    // Every shape carries the planted values as the rejected argument, so a refusal that echoed its
    // input would print them and fail here.
    const refused = [
      ['--case'],
      ['--case', PLANTED_ORIGINAL],
      ['--case', PLANTED_SECRET],
      ['--unknown-flag'],
      ['--case', 'blocked-reply', 'extra'],
      [MASKED],
    ];
    for (const args of refused) {
      const run = await runDemo(args);
      assert.equal(run.stalled, false, 'the refusal finished inside its bound');
      assert.equal(run.signal, null, 'a refused invocation exits on its own');
      assert.equal(run.code, 2, 'a malformed argument exits non-zero');
      assert.equal(run.stdout === '', true, 'a refused invocation printed no summary: it had no effect to report');
      assert.equal(run.stderr === REFUSAL_STDERR, true, 'the refusal is the fixed text, with no argument echoed');
      assertNoPlantedMaterial(run, 'a refused invocation');
    }
  });

test('a terminated fixed worker fails the blocked case even though the owner reports the same refusal code',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    // The working control, at its observed counts: two real children, both clean exits, one ALLOW and
    // one BLOCK naming the registered known original.
    const control = await runDemo(['--case', 'blocked-reply']);
    assert.equal(control.code, 0, 'the working blocked case is the control and exits zero');
    assert.equal(control.stdout === `${summaryOf('blocked-reply', ROWS['blocked-reply'])}\n`, true,
      'the control really ran both fixed children to a declared decision');
    // The fault: the SECOND real child is terminated and the first is left alone.
    const faulted = await runNode(FAULT_DRIVER, ['terminate-second-worker']);
    assert.equal(faulted.stalled, false, 'the faulted invocation finished inside its bound');
    assert.equal(faulted.signal, null, 'the faulted run exited on its own, with no signal');
    assert.equal(faulted.code, 1, 'a fixed worker that did not really run makes the demonstration exit non-zero');
    assert.equal(faulted.stderr === DECLINED_STDERR, true,
      'the faulted run reports one fixed line and nothing else');
    assert.equal(faulted.stdout === `${summaryOf('blocked-reply', ROWS.faulted)}\n`, true,
      'the faulted run reports the same owner refusal code with its own real worker counters');
    // What makes the fault non-vacuous, stated directly: the kill really landed on one child only, and
    // the first child still really returned ALLOW.
    assert.equal(faulted.stdout.includes('real fixed-worker children closed by a signal: 1'), true,
      'the terminated child really closed on a signal');
    assert.equal(faulted.stdout.includes('real fixed-worker children that exited with code zero: 1'), true,
      'exactly one child really exited cleanly, so the fault reached one worker and not both');
    assert.equal(faulted.stdout.includes('real fixed-worker ALLOW decisions: 1'), true,
      'the first request-side child was preserved and really allowed the masked request');
    assert.equal(faulted.stdout.includes('real fixed-worker BLOCK decisions: 0'), true,
      'no real BLOCK decision was observed, so the refusal code alone is never treated as a block');
    assertNoPlantedMaterial(faulted, 'the faulted run');
  });

test('a reply the protocol must refuse never passes as the genuine known-original block', { timeout: TEST_TIMEOUT_MS },
  async () => {
    // The genuine control, in the same test and at its observed counts: the second real child really
    // runs, really exits cleanly and really blocks that reply over the registered known original.
    const control = await runDemo(['--case', 'blocked-reply']);
    assert.equal(control.code, 0, 'the genuine blocked reply is the control and exits zero');
    assert.equal(control.stdout === `${summaryOf('blocked-reply', ROWS['blocked-reply'])}\n`, true,
      'the control really observed one BLOCK naming the registered known original');
    // Each fault keeps both real children and both clean exits, and changes only what the second one
    // answered. None of them may be counted as the declared block.
    const faults = [
      'corrupt-reply-unknown-reason',
      'corrupt-reply-foreign-binding',
      'corrupt-reply-too-many-rules',
    ];
    for (const fault of faults) {
      const run = await runNode(FAULT_DRIVER, [fault]);
      assert.equal(run.stalled, false, 'the faulted invocation finished inside its bound');
      assert.equal(run.signal, null, 'the faulted run exited on its own, with no signal');
      assert.equal(run.code, 1, 'a reply the protocol must refuse makes the demonstration decline itself');
      assert.equal(run.stderr === DECLINED_STDERR, true, 'the faulted run reports one fixed line and nothing else');
      assert.equal(run.stdout === `${summaryOf('blocked-reply', ROWS.unfavourableReply)}\n`, true,
        'both real children ran and exited cleanly, and the unfavourable reply is counted as no decision');
      assert.equal(run.stdout.includes('real fixed-worker BLOCK decisions: 0'), true,
        'an unfavourable reply is never counted as a block');
      assert.equal(run.stdout.includes('real fixed-worker blocks naming the registered known original: 0'), true,
        'an unfavourable reply is never counted as the declared known-original block');
      assertNoPlantedMaterial(run, 'the faulted run');
    }
  });

test('a real failing TAP run over output carrying the planted values reports none of them',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    // Observed, not asserted about. The probe really runs under the real test runner, its subprocess
    // really printed the planted values, and its designated comparison really fails UNCAUGHT - so the run
    // really exits non-zero and the report really carries a named `not ok` entry and a failure count.
    const probe = await runNodeTest(CONFIDENTIALITY_PROBE);
    assert.equal(probe.transportFailure, false,
      'a legitimate completed failing test run is preserved, not turned into a transport failure');
    assert.equal(probe.stalled, false, 'the confidentiality probe finished inside its bound');
    assert.equal(probe.signal, null, 'the probe exited on its own, with no signal');
    assert.equal(probe.code, 1, 'the designated comparison really failed, so the runner reported a non-zero exit');
    const tap = `${probe.stdout}${probe.stderr}`;
    assert.equal(tap.includes(`not ok 1 - ${PROBE_TEST_NAME}`), true,
      'the real TAP report carries the named failing entry for the probe test');
    assert.equal(tap.includes('# fail 1'), true, 'the real failure count was reported');
    assert.equal(tap.includes(PROBE_DESIGNATED_MESSAGE), true,
      'the failure the runner reported is the designated one, not some other failure');
    // The confidentiality claim, over that real failing report: booleans only, so this test's own
    // assertions can never report a captured byte either.
    assert.equal(tap.includes(PLANTED_ORIGINAL), false,
      'the observed failing TAP output carries no planted original');
    assert.equal(tap.includes(PLANTED_SECRET), false,
      'the observed failing TAP output carries no planted secret');
    assert.equal(tap.includes(MASKED), false,
      'the observed failing TAP output carries no mask literal');

    // The unsafe counterpart, so the three checks above are not vacuous. Its TAP is captured here, in
    // this process's memory, and is ONLY ever reduced to booleans: it is never compared to another
    // string, never put in an assertion message, printed, logged or written anywhere.
    const unsafe = await runNodeTest(UNSAFE_NEGATIVE_CONTROL);
    assert.equal(unsafe.transportFailure, false, 'the unsafe control ran, and finished on its own');
    assert.equal(unsafe.code, 1, 'the unsafe comparison really failed too');
    const leaked = `${unsafe.stdout}${unsafe.stderr}`;
    assert.equal(leaked.includes(PLANTED_ORIGINAL), true,
      'the unsafe string operand really reported the planted original, so the safe check above is not vacuous');
    assert.equal(leaked.includes(PLANTED_SECRET), true,
      'the unsafe string operand really reported the planted secret too');
    assert.equal(leaked.includes(MASKED), false,
      'the mask literal is in no captured stream at all, so neither run could have reported it');
  });

/**
 * One real operator run whose OUTPUT PIPE IS REALLY BROKEN: the reader end of stdout is closed in this
 * process right after the spawn, which is long before the demo (it starts a peer and two real children
 * first) writes its summary, so the demo's own write really meets a pipe nobody reads and the OS really
 * reports `EPIPE`. Stderr stays readable, so what the operator would be shown is observable. Nothing is
 * simulated; only booleans and one exit code leave this function, never a captured byte.
 */
function runDemoWithBrokenStdout() {
  return new Promise((resolve) => {
    const chunks = [];
    let settled = false;
    const done = (outcome) => { if (!settled) { settled = true; clearTimeout(timer); resolve(outcome); } };
    const child = spawn(process.execPath, [DEMO], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      done({ code: null, signal: null, stalled: true, fixedDecline: false, nativeText: false });
    }, 60_000);
    child.on('error', () => { done({ code: null, signal: null, stalled: false, fixedDecline: false, nativeText: false }); });
    child.stderr.on('data', (chunk) => { chunks.push(chunk); });
    child.stdout.destroy();
    child.on('close', (code, signal) => {
      const text = Buffer.concat(chunks).toString('utf8');
      chunks.length = 0;
      done({
        code,
        signal,
        stalled: false,
        fixedDecline: text === DECLINED_STDERR,
        nativeText: text.includes('EPIPE') || text.includes('write ') || text.includes('    at ')
          || text.includes('node:internal') || text.includes(REPO_ROOT) || text.includes('Error'),
      });
    });
  });
}

test('a really broken output pipe yields the one fixed decline and no native error, code, stack or path',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const outcome = await runDemoWithBrokenStdout();
    assert.equal(outcome.stalled, false, 'the run finished inside its bound');
    assert.equal(outcome.signal, null, 'the run exited on its own, with no signal');
    assert.equal(outcome.nativeText, false, 'no native error text, error code, stack frame or path was printed');
    assert.equal(outcome.fixedDecline, true, 'stderr carries exactly the one fixed decline line and nothing else');
    assert.equal(outcome.code, 1, 'a demonstration that could not report itself exits non-zero');
  });
