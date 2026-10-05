// #250: the operator-visible synthetic conversation demo, driven as a real subprocess.
//
// What this proves, precisely: the operator command runs the real application-level local conversation
// owner - `createOpenAiLocalConversation` - over a real standard HTTP loopback peer and the real
// fixture host, and prints a fixed summary derived from the real owner result and the real peer,
// release, detector and child counters. The default invocation really classifies one synthetic masked
// request with the real detector and the real policy engine, sends it to the peer once and releases one
// guarded reply; the two declared negatives really hold at their declared counts, the blocked reply
// reaching the peer once and releasing nothing, and the unsupported request reaching the peer not at
// all. A malformed invocation is refused before any effect and echoes nothing.
//
// What it is NOT. This is not a gateway, a provider client, an authentication implementation, a
// restoration path, a streaming design or a held-out, scored or promotion result. The identity, clock,
// policy bundle, profile digest, known-original registration and the static PUBLIC model/metadata
// records are TRUSTED FIXTURES this demo declares; nothing here authenticates a principal, a tenant,
// a workload or a control plane, and no detector absence is read as clearance. Every value is invented
// and non-routable (`*.invalid`, loopback, a made-up token literal).
//
// Assertions are counts, booleans and fixed labels. Planted material and the mask literal are declared
// here independently of the script and are only ever asserted ABSENT, so a failing assertion prints no
// body, no key, no reply and no planted value into the TAP output.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  MASKED, PLANTED_ORIGINAL, PLANTED_SECRET,
} from '../scripts/lib/synthetic-conversation-fixture.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DEMO = fileURLToPath(new URL('../scripts/synthetic-conversation-demo.mjs', import.meta.url));
/** Bound every invocation, so a stalled peer or child fails this suite loudly instead of hanging it. */
const BOUND_MS = 60_000;
/** The bound is a deadline, not a kill policy for valid work: nothing here is killed unless it stalls. */
const TEST_TIMEOUT_MS = 180_000;

/**
 * Run the real operator entry point in a real child process and report what actually happened. The
 * child's own stdout and stderr are returned for exact comparison and are never interpolated into an
 * assertion message, so no planted value and no native error can reach the TAP output.
 */
function runDemo(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [DEMO, ...args], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [];
    const stderr = [];
    let stalled = false;
    child.stdout.on('data', (chunk) => { stdout.push(chunk); });
    child.stderr.on('data', (chunk) => { stderr.push(chunk); });
    const timer = setTimeout(() => { stalled = true; child.kill('SIGKILL'); }, BOUND_MS);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        code, signal, stalled,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });
  });
}

/** The declared counters of each case, as the summary must report them. Nothing here is inferred. */
const ROWS = Object.freeze({
  default: {
    result: 'COMPLETED', code: 'none', connections: 1, requests: 1, releases: 1, mask: 'yes',
    runs: 2, findings: 1,
  },
  'blocked-reply': {
    result: 'REFUSED', code: 'SENTINEL_BLOCKED', connections: 1, requests: 1, releases: 0, mask: 'yes',
    runs: 2, findings: 1,
  },
  'unsupported-request': {
    result: 'REFUSED', code: 'UNSUPPORTED_TOOLS', connections: 0, requests: 0, releases: 0, mask: 'no',
    runs: 0, findings: 0,
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

/** Nothing planted may appear anywhere in what the operator sees, in either stream. */
const assertNoPlantedMaterial = (run) => {
  const printed = `${run.stdout}${run.stderr}`;
  for (const value of [PLANTED_ORIGINAL, PLANTED_SECRET, MASKED]) {
    assert.equal(printed.includes(value), false, 'no planted original, planted secret or mask literal printed');
  }
};

test('the default operator command masks one synthetic request and releases one guarded reply',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const run = await runDemo([]);
    assert.equal(run.stalled, false, 'the invocation finished inside its bound');
    assert.equal(run.signal, null, 'the demo exited on its own, with no signal and no orphan left behind');
    assert.equal(run.code, 0, 'a completed demonstration exits zero');
    assert.equal(run.stderr, '', 'the completed case prints nothing on stderr');
    assert.equal(run.stdout, `${summaryOf('default', ROWS.default)}\n`,
      'the printed summary is exactly the declared fixed shape and counters');
    assertNoPlantedMaterial(run);
  });

test('a blocked reply reaches the peer once and releases nothing, and still exits zero',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const run = await runDemo(['--case', 'blocked-reply']);
    assert.equal(run.stalled, false, 'the invocation finished inside its bound');
    assert.equal(run.signal, null, 'the demo exited on its own, with no signal and no orphan left behind');
    assert.equal(run.code, 0, 'an expected refusal is a successful demonstration');
    assert.equal(run.stderr, '', 'the expected refusal prints nothing on stderr');
    assert.equal(run.stdout, `${summaryOf('blocked-reply', ROWS['blocked-reply'])}\n`,
      'one upstream request, zero releases and a real blocked reply are reported exactly');
    assertNoPlantedMaterial(run);
  });

test('an unsupported request reaches no payload request at all and releases nothing',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const run = await runDemo(['--case', 'unsupported-request']);
    assert.equal(run.stalled, false, 'the invocation finished inside its bound');
    assert.equal(run.signal, null, 'the demo exited on its own, with no signal and no orphan left behind');
    assert.equal(run.code, 0, 'an expected refusal is a successful demonstration');
    assert.equal(run.stderr, '', 'the expected refusal prints nothing on stderr');
    assert.equal(run.stdout, `${summaryOf('unsupported-request', ROWS['unsupported-request'])}\n`,
      'the strict codec refusal is reported with zero peer requests and zero releases');
    assertNoPlantedMaterial(run);
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
      assert.equal(run.stdout, '', 'a refused invocation printed no summary: it had no effect to report');
      assert.equal(run.stderr, REFUSAL_STDERR, 'the refusal is the fixed text, with no argument echoed');
      assertNoPlantedMaterial(run);
    }
  });