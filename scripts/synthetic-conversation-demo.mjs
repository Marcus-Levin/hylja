#!/usr/bin/env node
/**
 * #250 provider-free synthetic conversation demonstration.
 *
 *   npm run build && node scripts/synthetic-conversation-demo.mjs
 *   node scripts/synthetic-conversation-demo.mjs --case blocked-reply
 *   node scripts/synthetic-conversation-demo.mjs --case unsupported-request
 *
 * One command runs the REAL application-level local conversation owner -
 * `createOpenAiLocalConversation` from [`src/openai-local-conversation.ts`](../src/openai-local-conversation.ts)
 * - over a REAL standard HTTP peer bound to `127.0.0.1` on an OS-assigned ephemeral port. Nothing is
 * stubbed: `detectSecrets` runs over the sender's own private original request image, the accepted
 * policy engine selects the irreversible whole-message `MASK` of accepted decision 011, both fixed
 * egress-sentinel worker children really run, and the reply leaves the receiver's own guarded release
 * point. This is a demonstration, not a new transport, coordinator or policy authority: no provider,
 * no credential, no network beyond loopback, and no new production surface.
 *
 * Three cases, all over the same working fixture:
 *
 * - `default`: one synthetic request whose planted secret is really detected and really masked, one
 *   request at the peer and one guarded release.
 * - `blocked-reply`: the same request, and a reply that carries the REGISTERED synthetic original. The
 *   request reaches the peer once; the real child blocks the reply, so nothing is released.
 * - `unsupported-request`: a request outside the strict complete-text subset. The strict codec refuses
 *   it, so no payload request reaches the peer at all and nothing is released.
 *
 * Both refusals are SUCCESSFUL demonstrations: this script exits 0 when the case behaved exactly as
 * declared above and non-zero otherwise, so a wrong refusal, a leaked original or a missed release is
 * a failure rather than a note.
 *
 * What is printed is a fixed human-readable summary derived from the real owner result and the real
 * peer, release and detector counters, plus fixed labels naming what this run is. No original value,
 * no key, no model traffic, no caller argument and no native exception text is ever printed: arguments
 * are matched against a fixed vocabulary and refused without echo before any peer, owner or child
 * exists, and an unexpected failure prints one fixed line and nothing else.
 *
 * Cleanup is unconditional: the owner is cancelled, every peer socket is destroyed, the server is
 * closed, the retained request bytes are dropped and the fixed-worker child handles are drained
 * inside one bounded wait. Every fixture value is obviously synthetic and non-routable (`*.invalid`,
 * loopback, a made-up token literal). This run demonstrates a completed MVP over fixtures. It is not
 * a gateway, it authenticates nobody, it restores nothing, it streams nothing and it is not a
 * held-out or scored result.
 */
import http from 'node:http';
import { createOpenAiLocalConversation } from '../dist/openai-local-conversation.js';
import {
  createDemoHost, DEMO_LEAKY_REPLY, DEMO_REPLY, DEMO_REQUEST, DEMO_UNSUPPORTED_REQUEST,
  MASKED, PLANTED_ORIGINAL, PLANTED_SECRET,
} from './lib/synthetic-conversation-fixture.mjs';

/** Host-owned sentinel deadline and the owner's exchange deadline: one fixed value for every case. */
const DEADLINE_MS = 10_000;
/** Bound the cleanup itself, so a stalled socket cannot hang the demonstration. */
const CLEANUP_BOUND_MS = 5_000;

/** The only three accepted cases. The default case is the one that runs with no arguments at all. */
const CASES = Object.freeze({
  DEFAULT: 'default',
  BLOCKED_REPLY: 'blocked-reply',
  UNSUPPORTED_REQUEST: 'unsupported-request',
});
const KNOWN = new Set(Object.values(CASES));

/** What each case declares it will actually do. A case that deviates from its own row exits non-zero. */
const EXPECTED = Object.freeze({
  [CASES.DEFAULT]: Object.freeze({
    status: 'COMPLETED', code: null, connections: 1, requests: 1, releases: 1, detectorRuns: 2,
    findings: 1, maskSeen: true,
  }),
  [CASES.BLOCKED_REPLY]: Object.freeze({
    status: 'REFUSED', code: 'SENTINEL_BLOCKED', connections: 1, requests: 1, releases: 0,
    detectorRuns: 2, findings: 1, maskSeen: true,
  }),
  [CASES.UNSUPPORTED_REQUEST]: Object.freeze({
    status: 'REFUSED', code: 'UNSUPPORTED_TOOLS', connections: 0, requests: 0, releases: 0,
    detectorRuns: 0, findings: 0, maskSeen: false,
  }),
});

/**
 * Match the caller's arguments against the fixed vocabulary. Anything else - an unknown flag, a
 * missing or repeated value, an unknown case name, a positional argument or an `=` spelling - is
 * refused as `null` here, BEFORE any peer, owner, detector, policy decision or child can exist. The
 * rejected text is never returned, stored or printed, so this refusal cannot echo it.
 */
function caseOf(argv) {
  if (argv.length === 0) return CASES.DEFAULT;
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

/** Fixed-worker child processes this process still holds a live handle to. */
const liveChildren = () => process.getActiveResourcesInfo().filter((kind) => kind === 'ProcessWrap').length;

/** One bounded poll, so a stalled socket or a lingering handle fails the run instead of hanging it. */
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

/**
 * Drain what the case left behind and measure it. Every fixed-worker child has already been observed
 * `close` by its own runner before the exchange settled, so only the handle that close releases
 * asynchronously is left; a peer socket is retired by its own `close` event. Both are polled to zero
 * inside one bound, and whatever is still standing when the bound expires is reported as it really is
 * rather than rounded to zero.
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
async function run(name) {
  const releases = [];
  const runs = [];
  const peer = startPeer(name === CASES.BLOCKED_REPLY ? DEMO_LEAKY_REPLY : DEMO_REPLY);
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
    // cannot travel in it, and no caller input reaches this script at all.
    const body = name === CASES.UNSUPPORTED_REQUEST ? DEMO_UNSUPPORTED_REQUEST : DEMO_REQUEST;
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
    children: drained.children,
    openSockets: drained.openSockets,
  };
}

/** The fixed summary. Every value is a declared comparison or a measured counter; nothing is inferred. */
function summary(name, seen) {
  const { result } = seen;
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
    `fixed-worker children still live after cleanup: ${seen.children}`,
    `peer sockets open after cleanup: ${seen.openSockets}`,
    `owner state after the exchange: ${seen.ownerState}`,
    'labels:',
    ...LABELS.map((label) => `- ${label}`),
  ];
}

/** The declared case against what really happened. Zero writes are never inferred from zero releases. */
function holds(name, seen) {
  const expected = EXPECTED[name];
  const { result } = seen;
  if (seen.failed || result === null) return false;
  if (result.status !== expected.status) return false;
  if (expected.code !== null && (result.status !== 'REFUSED' || result.code !== expected.code)) return false;
  return seen.counters.connections === expected.connections
    && seen.counters.requests === expected.requests
    && seen.releases === expected.releases
    && seen.detectorRuns === expected.detectorRuns
    && seen.findings === expected.findings
    // Every real detector run must have really completed; a degraded run is a failure, never a note.
    && seen.detectorStatuses.every((status) => status === 'COMPLETE')
    && seen.counters.sawMask === expected.maskSeen
    && seen.counters.sawOriginal === false
    && seen.counters.sawSecret === false
    && seen.releaseCarriedOriginal === false
    && seen.children === 0
    && seen.openSockets === 0;
}

/* ---------- The operator entry point ---------- */

const name = caseOf(process.argv.slice(2));
if (name === null) {
  // Refused before any effect: no peer, no socket, no owner, no detector, no policy decision, no
  // child, and no echo of what was actually passed.
  process.stderr.write('hylja synthetic conversation demo: argument refused\n');
  process.stderr.write('expected: no arguments, or --case default | --case blocked-reply | --case unsupported-request\n');
  process.exitCode = 2;
} else {
  const seen = await run(name);
  process.stdout.write(`${summary(name, seen).join('\n')}\n`);
  if (!holds(name, seen)) {
    // The case did not behave as declared. One fixed line: no native error, no planted value.
    process.stderr.write('hylja synthetic conversation demo: the case did not match its declared behaviour\n');
    process.exitCode = 1;
  }
}