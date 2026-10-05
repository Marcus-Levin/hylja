/**
 * The three declared synthetic conversation cases and the fixed summary they report (#250).
 *
 * This module is fixture and demonstration code, never a runtime owner: it starts the loopback peer,
 * calls the REAL application-level local conversation owner
 * ([openai-local-conversation.ts](../../src/openai-local-conversation.ts)), reads the REAL counters back
 * and decides only what to PRINT and whether the run matched its own declared row. It composes nothing
 * new - no transport, no coordinator, no policy authority - and it changes no owner result.
 *
 * Why it is a module and not the entry script. The operator entry point
 * ([synthetic-conversation-demo.mjs](../synthetic-conversation-demo.mjs)) owns argument matching and the
 * process exit code; the test-only fault driver
 * ([test/support/synthetic-conversation-demo-fault-driver.mjs](../../test/support/synthetic-conversation-demo-fault-driver.mjs))
 * runs the very same cases through this module with a fixture fault armed. One implementation, one fixed
 * summary, one fixed refusal text, so a faulted run is comparable to an operator run byte for byte.
 *
 * It must be imported DYNAMICALLY, after `installWorkerObservation()`. ESM links a whole module graph
 * before any body in it runs, and a builtin named import is a value snapshot taken at that link step: a
 * capture installed after this graph was linked could never see the accepted runner's `spawn`. The import
 * below therefore refuses to run at all when the capture is missing, rather than reporting a fixed zero
 * for children that really ran.
 *
 * What is printed is a fixed human-readable summary of the real owner result, the real peer, release and
 * detector counters, and the real worker counters. No original value, key, model traffic, caller argument,
 * signal name, native exception text or child reply text is ever printed: arguments are matched against a
 * fixed vocabulary and refused without echo before any peer, owner or child exists, and an unexpected
 * failure prints one fixed line and nothing else.
 *
 * Cleanup runs on every outcome, including a refusal, a thrown failure and a stalled bound: the owner is
 * cancelled, every peer socket is destroyed, the server is closed and the retained request bytes are
 * dropped. The fixed-worker children are WAITED for, not killed: this module sends no signal to any
 * process and has no blanket kill. What it does is measure, inside one bounded wait, whether each worker
 * process it recorded still exists according to the operating system (plus the child-process handles this
 * process still holds), and report what is still standing when the bound expires exactly as it is. The
 * case then fails its declared behaviour. Terminating a stalled worker is the accepted runner's own
 * deadline, not this module's.
 */
import http from 'node:http';
import { DEMO_ARGUMENT_REFUSED, DEMO_DECLINED } from './synthetic-conversation-demo-text.mjs';
import {
  noteRegisteredOriginal, workerObservation, workerObservationInstalled, workersStillRunning,
} from './synthetic-conversation-worker-observation.mjs';
import { createOpenAiLocalConversation } from '../../dist/openai-local-conversation.js';
import {
  createDemoHost, DEMO_LEAKY_REPLY, DEMO_REPLY, DEMO_REQUEST, DEMO_UNSUPPORTED_REQUEST,
  MASKED, PLANTED_ORIGINAL, PLANTED_ORIGINAL_REF, PLANTED_SECRET,
} from './synthetic-conversation-fixture.mjs';

/**
 * Why this module reports real worker counters at all. The accepted receiver reports `SENTINEL_BLOCKED`
 * for a genuine block over a registered original, for a crashed child, for a malformed reply and for a
 * missing reply alike. That collapse is the correct runtime contract and is untouched here, but it means
 * an exit code and a refusal code alone cannot tell a real block from a dead worker. So the real children
 * are observed directly, and a case only holds when they really ran, really exited cleanly and really
 * returned the declared decision:
 * [synthetic-conversation-worker-observation.mjs](./synthetic-conversation-worker-observation.mjs).
 */

/**
 * The capture must already be in place: linking this graph bound the accepted runner's `spawn` by value,
 * so a capture installed after this import could not observe a single child. Importing this module
 * without it fails loudly instead of reporting zero workers for a run that really spawned two.
 */
if (!workerObservationInstalled()) throw new Error('the fixed-worker observation must be installed before import');

/** The ref both fixed children were asked to check under, so a `BLOCK` naming a rule is comparable to it. */
noteRegisteredOriginal(PLANTED_ORIGINAL_REF);

/** Host-owned sentinel deadline and the owner's exchange deadline: one fixed value for every case. */
const DEADLINE_MS = 10_000;
/** Bound the cleanup itself, so a stalled socket cannot hang the demonstration. */
const CLEANUP_BOUND_MS = 5_000;

/** The only three accepted cases. The default case is the one that runs with no arguments at all. */
export const DEMO_CASES = Object.freeze({
  DEFAULT: 'default',
  BLOCKED_REPLY: 'blocked-reply',
  UNSUPPORTED_REQUEST: 'unsupported-request',
});
const KNOWN = new Set(Object.values(DEMO_CASES));

/** What each case declares it will actually do. A case that deviates from its own row exits non-zero. */
const EXPECTED = Object.freeze({
  [DEMO_CASES.DEFAULT]: Object.freeze({
    status: 'COMPLETED', code: null, connections: 1, requests: 1, releases: 1, detectorRuns: 2,
    findings: 1, maskSeen: true,
    workers: Object.freeze({ spawned: 2, exitedZero: 2, closedBySignal: 0, completeFrames: 2, allow: 2, block: 0, namedKnownOriginal: 0 }),
  }),
  [DEMO_CASES.BLOCKED_REPLY]: Object.freeze({
    status: 'REFUSED', code: 'SENTINEL_BLOCKED', connections: 1, requests: 1, releases: 0,
    detectorRuns: 2, findings: 1, maskSeen: true,
    workers: Object.freeze({ spawned: 2, exitedZero: 2, closedBySignal: 0, completeFrames: 2, allow: 1, block: 1, namedKnownOriginal: 1 }),
  }),
  [DEMO_CASES.UNSUPPORTED_REQUEST]: Object.freeze({
    status: 'REFUSED', code: 'UNSUPPORTED_TOOLS', connections: 0, requests: 0, releases: 0,
    detectorRuns: 0, findings: 0, maskSeen: false,
    workers: Object.freeze({ spawned: 0, exitedZero: 0, closedBySignal: 0, completeFrames: 0, allow: 0, block: 0, namedKnownOriginal: 0 }),
  }),
});

/**
 * The fixed operator lines are declared in [synthetic-conversation-demo-text.mjs](./synthetic-conversation-demo-text.mjs),
 * which imports nothing, so the entry point can print them even when this module cannot load. They are
 * re-exported here so every entry point prints the same bytes.
 */
export { DEMO_ARGUMENT_REFUSED, DEMO_DECLINED };

/**
 * Match the caller's arguments against the fixed vocabulary. Anything else - an unknown flag, a missing
 * or repeated value, an unknown case name, a positional argument or an `=` spelling - is refused as `null`
 * here, BEFORE any peer, owner, detector, policy decision or child can exist. The rejected text is never
 * returned, stored or printed, so this refusal cannot echo it.
 */
export function resolveDemoCase(argv) {
  if (argv.length === 0) return DEMO_CASES.DEFAULT;
  if (argv.length !== 2 || argv[0] !== '--case') return null;
  return KNOWN.has(argv[1]) ? argv[1] : null;
}

/** One loopback HTTP peer that counts what it really received and answers in the one supported profile. */
function startPeer(reply) {
  const counters = { connections: 0, requests: 0, sawOriginal: false, sawSecret: false, sawMask: false };
  const sockets = new Set();
  const bodies = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('error', () => {});
    res.on('error', () => {});
    req.on('data', (chunk) => { chunks.push(chunk); });
    req.on('end', () => {
      counters.requests += 1;
      const body = Buffer.concat(chunks);
      bodies.push(body);
      // Boolean comparisons over planted material only. The values themselves are never printed.
      if (body.includes(Buffer.from(PLANTED_ORIGINAL, 'utf8'))) counters.sawOriginal = true;
      if (body.includes(Buffer.from(PLANTED_SECRET, 'utf8'))) counters.sawSecret = true;
      if (body.includes(Buffer.from(MASKED, 'utf8'))) counters.sawMask = true;
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(reply, 'utf8'),
        Connection: 'close',
      });
      res.end(reply);
    });
  });
  server.on('connection', (socket) => {
    counters.connections += 1;
    sockets.add(socket);
    socket.on('close', () => { sockets.delete(socket); });
    socket.on('error', () => {});
  });
  return { server, counters, sockets, bodies };
}

/** Bound one cleanup step, so a stalled socket fails the run instead of hanging it. */
function bounded(promise, label) {
  let timer;
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => { reject(new Error(label)); }, CLEANUP_BOUND_MS);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

/**
 * Fixed-worker children still standing: the larger of the child-process handles this process holds and
 * the recorded worker processes the operating system still reports as existing. The second is real
 * liveness of the very processes that were spawned; the first catches a handle with no recorded process.
 */
const liveChildren = () => Math.max(
  process.getActiveResourcesInfo().filter((kind) => kind === 'ProcessWrap').length,
  workersStillRunning(),
);

/** One bounded poll, so a stalled socket or a lingering handle fails the run instead of hanging it. */
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

/**
 * Drain what the case left behind and measure it. Every fixed-worker child has already been observed
 * `close` by its own runner before the exchange settled, so only the handle that close releases
 * asynchronously is left; a peer socket is retired by its own `close` event. Both are polled to zero
 * inside one bound, the children by real process liveness, and whatever is still standing when the
 * bound expires is reported as it really is rather than rounded to zero.
 */
async function drain(peer) {
  const deadline = Date.now() + CLEANUP_BOUND_MS;
  let openSockets = peer.sockets.size;
  let children = liveChildren();
  while ((openSockets > 0 || children > 0) && Date.now() < deadline) {
    await sleep(5);
    openSockets = peer.sockets.size;
    children = liveChildren();
  }
  return { openSockets, children };
}

/** Fixed labels. What this run is, and what it is not, stated once and never derived from a count. */
const LABELS = Object.freeze([
  'synthetic loopback only: no provider, no credential, no real host, no network beyond 127.0.0.1',
  'trusted fixture identity, clock and policy inputs; nothing here authenticates a principal, workload, tenant or control plane',
  'the model and metadata PUBLIC records are trusted fixture labels, not an inference from detector absence',
  'irreversible whole-message MASK of accepted decision 011; proposed decision 010 is not wired in',
  'no production authentication, no streaming, no restoration and no held-out utility, scoring or release claim',
]);

const yesNo = (value) => (value ? 'yes' : 'no');

/** Run one declared case and return only the counters this summary is allowed to report. */
export async function runDemoCase(name) {
  const releases = [];
  const runs = [];
  const peer = startPeer(name === DEMO_CASES.BLOCKED_REPLY ? DEMO_LEAKY_REPLY : DEMO_REPLY);
  let conversation = null;
  let result = null;
  let exchangeState = 'UNAVAILABLE';
  let drained = { openSockets: -1, children: -1 };
  let failed = false;
  try {
    await bounded(new Promise((resolve, reject) => {
      peer.server.once('error', reject);
      peer.server.listen(0, '127.0.0.1', resolve);
    }), 'peer listen');
    const address = peer.server.address();
    if (address === null || typeof address !== 'object' || address.address !== '127.0.0.1') {
      throw new Error('peer address');
    }
    conversation = createOpenAiLocalConversation(createDemoHost({
      port: address.port, timeoutMs: DEADLINE_MS, releases, runs,
    }));
    // The call shape is exactly `{ body }`. The route, the destination, the treatment and the sink
    // cannot travel in it, and no caller input reaches this module at all.
    const body = name === DEMO_CASES.UNSUPPORTED_REQUEST ? DEMO_UNSUPPORTED_REQUEST : DEMO_REQUEST;
    result = await bounded(conversation.exchange({ body }), 'exchange');
    // Read before the unconditional cancel below, so the reported state is the state the exchange
    // actually left behind: a refusal is not a latch.
    exchangeState = conversation.state;
  } catch {
    // A native error, a transport error and a planted value all land here identically and identically
    // unprinted: the fixed line below is the whole report of an unexpected failure.
    failed = true;
  } finally {
    // Unconditional cleanup on every outcome, including a refusal and a thrown failure: cancel the
    // owner, destroy every peer socket, close the server, then drain the children.
    conversation?.cancel();
    for (const socket of peer.sockets) { try { socket.destroy(); } catch { /* already closed */ } }
    peer.server.closeAllConnections?.();
    // The peer held real request bytes only to compare them against the planted values; none of it
    // outlives this block.
    peer.bodies.length = 0;
    // Sockets and children are drained after the peer is closed, so a live handle is the only thing
    // left to report on. A bound that expires with handles still live leaves the real number in the
    // summary, and the case then fails its declared behaviour.
    drained = await drain(peer);
    try {
      await bounded(new Promise((resolve) => { peer.server.close(() => resolve()); }), 'peer close');
    } catch { failed = true; }
  }
  return {
    failed,
    result,
    ownerState: exchangeState,
    counters: peer.counters,
    releases: releases.length,
    releaseCarriedOriginal: releases.some((reply) => reply.includes(PLANTED_ORIGINAL)),
    detectorRuns: runs.length,
    findings: runs.reduce((total, run) => total + run.findings, 0),
    detectorStatuses: runs.map((run) => run.status),
    workers: workerObservation(),
    children: drained.children,
    openSockets: drained.openSockets,
  };
}

/** The fixed summary. Every value is a declared comparison or a measured counter; nothing is inferred. */
export function summarizeDemoCase(name, seen) {
  const { result, workers } = seen;
  const status = result === null ? 'NONE' : result.status;
  const code = result !== null && result.status === 'REFUSED' ? result.code : 'none';
  return [
    'hylja synthetic conversation demo',
    `case: ${name}`,
    'transport: standard HTTP peer on 127.0.0.1, OS-assigned ephemeral port (synthetic loopback)',
    `owner result: ${status}`,
    `owner refusal code: ${code}`,
    `peer connections: ${seen.counters.connections}`,
    `peer requests: ${seen.counters.requests}`,
    `peer observed the planted original: ${yesNo(seen.counters.sawOriginal)}`,
    `peer observed the planted secret: ${yesNo(seen.counters.sawSecret)}`,
    `peer observed the generic mask literal: ${yesNo(seen.counters.sawMask)}`,
    `application releases: ${seen.releases}`,
    `application release carried the planted original: ${yesNo(seen.releaseCarriedOriginal)}`,
    `real detector runs: ${seen.detectorRuns}`,
    `real detector findings: ${seen.findings}`,
    `real fixed-worker children spawned: ${workers.spawned}`,
    `real fixed-worker children that exited with code zero: ${workers.exitedZero}`,
    `real fixed-worker children closed by a signal: ${workers.closedBySignal}`,
    `real fixed-worker children that never reported close: ${workers.neverReportedClose}`,
    `real fixed-worker replies read as exactly one complete decision frame: ${workers.completeFrames}`,
    `real fixed-worker ALLOW decisions: ${workers.allow}`,
    `real fixed-worker BLOCK decisions: ${workers.block}`,
    `real fixed-worker blocks naming the registered known original: ${workers.namedKnownOriginal}`,
    `fixed-worker children still live after cleanup: ${seen.children}`,
    `peer sockets open after cleanup: ${seen.openSockets}`,
    `owner state after the exchange: ${seen.ownerState}`,
    'labels:',
    ...LABELS.map((label) => `- ${label}`),
  ];
}

/**
 * The declared case against what really happened. Zero writes are never inferred from zero releases, and
 * an owner refusal code is never taken as evidence on its own: the real children must have really run,
 * really exited cleanly and really returned the declared decision, so a crashed, killed, malformed or
 * silent worker cannot pass as a successful demonstration.
 */
export function demoCaseHolds(name, seen) {
  const expected = EXPECTED[name];
  const { result, workers } = seen;
  if (expected === undefined || seen.failed || result === null) return false;
  if (result.status !== expected.status) return false;
  if (expected.code !== null && (result.status !== 'REFUSED' || result.code !== expected.code)) return false;
  if (seen.counters.connections !== expected.connections
    || seen.counters.requests !== expected.requests
    || seen.releases !== expected.releases
    || seen.detectorRuns !== expected.detectorRuns
    || seen.findings !== expected.findings
    // Every real detector run must have really completed; a degraded run is a failure, never a note.
    || seen.detectorStatuses.some((status) => status !== 'COMPLETE')
    || seen.counters.sawMask !== expected.maskSeen
    || seen.counters.sawOriginal !== false
    || seen.counters.sawSecret !== false
    || seen.releaseCarriedOriginal !== false
    || seen.children !== 0
    || seen.openSockets !== 0) return false;
  // The real worker protocol, observed on the real children. Every spawned child must have reported
  // `close` by an observed zero exit, every frame counted must be one complete decision frame, and the
  // decisions must be the ones this case declares. A block counts as the declared block only when it
  // also carried the known-original reason code and named the ref this fixture registered.
  return workers.spawned === expected.workers.spawned
    && workers.exitedZero === expected.workers.exitedZero
    && workers.closedBySignal === expected.workers.closedBySignal
    && workers.neverReportedClose === 0
    && workers.completeFrames === expected.workers.completeFrames
    && workers.allow === expected.workers.allow
    && workers.block === expected.workers.block
    && workers.namedKnownOriginal === expected.workers.namedKnownOriginal;
}