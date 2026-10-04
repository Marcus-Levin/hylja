// #190: the shipped strict text-only codec (`translateOpenAiTextRequest`), the shipped deterministic
// policy seam (`decidePolicy`) and the shipped optional local egress sentinel process runner
// (`createSentinelProcessRunner` with its FIXED compiled worker) are wired, in this file only, to a real
// loopback TCP sink bound to an OS-assigned ephemeral port.
//
// What this proves, precisely: for these narrow, obviously synthetic fixtures, a byte leaves this test
// only when the codec translated a complete text request AND the real policy decision was SELECTED with
// KEEP AND the real child process returned ALLOW over the exact serialized image, metadata included.
// Every other outcome - a sentinel block over a planted original, a planted canary, an observed
// destination or profile the decision did not authorize, a runner-owned cancel, an unusable runner
// configuration or a refused request - is zero bytes and zero connections at the sink.
//
// What it is NOT: a production gateway, a product adapter, an authentication proof (the trusted
// boundary, the policy bundle pin, the sentinel key and the known-original registration are test
// fixtures, not authenticated identities), an OS sandbox or an RSS cap, a scoring or enforcement
// result. No in-process fallback exists on any path here: a check that did not run in the real child
// simply withholds the release. No network beyond 127.0.0.1 on an ephemeral port, no provider traffic,
// no credentials, no real customer, infrastructure or held-out data.
//
// Every fixture value is invented and non-routable (`*.invalid`, loopback, a made-up name and host).
// Assertions carry fixed counts, codes and booleans only: a failing assertion must never print a buffer
// or a planted value into the TAP output.
import assert from 'node:assert/strict';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { composeClassification, TRUST_LEVELS } from '../dist/classification.js';
import {
  decidePolicy, digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE,
} from '../dist/policy.js';
import { createSentinelProcessRunner } from '../dist/egress-sentinel-process.js';
import { OPENAI_TEXT_REQUEST_ENDPOINT, translateOpenAiTextRequest } from '../dist/openai-text-request.js';

/** Host-owned runner deadline: a check either answers inside it or is stopped at it. Never extended. */
const DEADLINE_MS = 10_000;
/** Bound every await in this file, so a stalled child or socket fails loudly instead of hanging. */
const BOUND_MS = 20_000;
const TEST_TIMEOUT_MS = 60_000;

/* ---------- Planted synthetic originals and the registration fixture ---------- */

const SCOPE = Object.freeze({ tenantRef: 'tenant-fixture.invalid', projectRef: 'project-fixture.invalid' });
// A dedicated, obviously synthetic sentinel key for this test only. It is not a credential.
const KEY = Uint8Array.from({ length: 32 }, (unused, index) => (index * 7 + 3) & 0xff);
const PLANTED_ORIGINAL = 'verity.synthanon@synthetic-planted.invalid';
const PLANTED_CANARY = 'synthetic-canary-4f21.invalid';
// The ONLY accepted way to protect originals across the process boundary: an explicit registration with
// its own scope and a dedicated key. A process-local `KnownOriginalsHandle` is refused by the module.
const registration = (entries) => ({ scope: SCOPE, key: KEY, entries });
const BENIGN_ENTRIES = Object.freeze([
  Object.freeze({ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'planted.person.1' }),
  Object.freeze({ kind: 'CANARY', value: PLANTED_CANARY, ref: 'planted.canary.1' }),
]);

/* ---------- Trusted test fixture bindings (not authenticated identities) ---------- */

const SUBJECT = Object.freeze({ principalId: 'principal-fixture.invalid', workloadId: 'workload-fixture.invalid' });
const CONTEXT = Object.freeze({
  tenantId: SCOPE.tenantRef, projectId: SCOPE.projectRef,
  sessionId: 'session-fixture.invalid', purpose: 'fixture-egress.invalid',
});
const SOURCE = Object.freeze({ kind: 'tool.result', ref: 'tool-source-fixture.invalid', trustZone: 'LOCAL' });
const SOURCE_TRUST = 'TRUSTED';
const SINK = Object.freeze({
  kind: 'model', ref: 'model-sink.example.invalid', trustZone: 'EXTERNAL', profileId: 'fixture-sink.invalid',
});
const PROFILE = Object.freeze({
  id: 'fixture-sink.invalid', sink: SINK, exposure: 'EXTERNAL',
  permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'INTERNAL',
});
const BUNDLE = Object.freeze({
  ...KNOWN_POLICY_BUNDLE,
  profiles: [PROFILE],
  rules: [{
    id: 'fixture-keep.invalid', profileId: PROFILE.id, semanticType: 'PERSON', sensitivities: ['PUBLIC'],
    sourceTrust: [...TRUST_LEVELS], operations: ['SEND'], decision: 'KEEP',
  }],
});

/** One trusted-boundary scenario supplied by this test; the modules still re-check every binding. */
function scenario() {
  const classification = composeClassification({
    detectorEvidence: [{
      version: 1, id: 'detector-fixture.invalid', status: 'FOUND',
      provenance: {
        inputRef: 'field-fixture.invalid', producerId: 'detector-fixture.invalid',
        producerVersion: 'pack-fixture-1',
      },
      claim: { semanticType: 'PERSON', sensitivity: 'PUBLIC' },
    }],
  }, { interactionRef: 'interaction-fixture.invalid', sourceRef: SOURCE.ref, trust: SOURCE_TRUST });
  return {
    request: {
      version: 1, interactionRef: 'interaction-fixture.invalid', candidateRef: 'unit-fixture-1.invalid',
      subject: SUBJECT, context: CONTEXT, source: SOURCE, destination: SINK, classification,
      operation: 'SEND', policy: KNOWN_POLICY_BUNDLE,
    },
    boundary: {
      interactionRef: 'interaction-fixture.invalid', candidateRef: 'unit-fixture-1.invalid',
      classificationDigest: digestClassification(classification),
      authenticated: { subject: SUBJECT, context: CONTEXT },
      observed: { source: { ...SOURCE, trust: SOURCE_TRUST }, destination: SINK },
      policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) },
    },
  };
}

/* ---------- The accepted request and the independently declared expected wire image ---------- */

const MODEL = 'fixture-model-openai-e2e';
const SAFE_SYSTEM_TEXT = 'You are a synthetic fixture assistant.';
// The literal protocol and port the downstream utility fixture needs in order to answer correctly. If a
// gate redacted or rewrote either literal, the downstream answer would change; nothing here transforms.
const SAFE_USER_TEXT = 'Diagnose why the synthetic fixture gateway fails on https and port 443.';
const requestBody = (messages, extra = {}) => JSON.stringify({ model: MODEL, messages, ...extra });
const SAFE_REQUEST_BODY = requestBody([
  { role: 'system', content: SAFE_SYSTEM_TEXT },
  { role: 'user', content: SAFE_USER_TEXT },
]);
const LEAKY_REQUEST_BODY = requestBody([
  { role: 'user', content: `Escalate to ${PLANTED_ORIGINAL} before the window opens.` },
]);
const BASE_HEADERS = Object.freeze([
  Object.freeze(['Host', '127.0.0.1']),
  Object.freeze(['X-Hylja-Fixture', 'openai-process-sendpoint-e2e']),
  Object.freeze(['Content-Type', 'application/json; charset=utf-8']),
]);

/**
 * Serialize the TRANSLATED draft back into the native text-only image, in native field and message
 * order, plus the metadata headers. This is test-local serialization, not a transformation: no
 * treatment is selected, applied or emulated, so the checked image is exactly the sent image.
 */
function serializeDraft(draft, extraHeaders = []) {
  const messages = draft.payload.messages.map((message) =>
    `{"role":${JSON.stringify(message.role)},"content":${JSON.stringify(message.content)}}`);
  const body = `{"model":${JSON.stringify(draft.metadata.model)},"messages":[${messages.join(',')}]}`;
  const head = [
    `POST ${OPENAI_TEXT_REQUEST_ENDPOINT} HTTP/1.1`,
    ...BASE_HEADERS.map(([name, value]) => `${name}: ${value}`),
    ...extraHeaders.map(([name, value]) => `${name}: ${value}`),
    `Content-Length: ${Buffer.byteLength(body, 'utf8')}`,
    '', '',
  ].join('\r\n');
  return `${head}${body}`;
}

// Independently declared expected wire bytes for the accepted safe fixture: a reviewer can read this
// literal and compare it with what the sink received without running any part of this pipeline.
const EXPECTED_CONTENT_LENGTH = 218;
const EXPECTED_WIRE = [
  'POST /v1/chat/completions HTTP/1.1',
  'Host: 127.0.0.1',
  'X-Hylja-Fixture: openai-process-sendpoint-e2e',
  'Content-Type: application/json; charset=utf-8',
  `Content-Length: ${EXPECTED_CONTENT_LENGTH}`,
  '',
  '{"model":"fixture-model-openai-e2e","messages":['
    + '{"role":"system","content":"You are a synthetic fixture assistant."},'
    + '{"role":"user","content":"Diagnose why the synthetic fixture gateway fails on https and port 443."}'
    + ']}',
].join('\r\n');
const EXPECTED_WIRE_BYTES = Buffer.from(EXPECTED_WIRE, 'utf8');

/* ---------- The downstream synthetic utility fixture ---------- */

// A deterministic, local, non-model "downstream utility": it answers only if BOTH the literal protocol
// and the literal port survived the whole pipeline into the received bytes. It never calls anything.
function downstreamUtilityAnswer(receivedBodyText) {
  if (!receivedBodyText.includes('https')) return 'protocol-lost';
  const port = receivedBodyText.match(/\b(443)\b/u);
  return port ? `port ${port[1]}` : 'port-lost';
}

/* ---------- A real loopback sink on an OS-assigned ephemeral port ---------- */

/** Every await in this file is bounded, and every timer this file creates is cleared on both paths. */
function bounded(promise, label) {
  let timer;
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`deadline exceeded: ${label}`)), BOUND_MS);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

async function startSink() {
  const open = new Set();
  const captures = [];
  let connections = 0;
  let receivedBytes = 0;

  const server = net.createServer((socket) => {
    connections += 1;
    open.add(socket);
    socket.on('close', () => open.delete(socket));
    socket.on('error', () => {});
    let received = Buffer.alloc(0);
    let complete = false;
    socket.on('data', (chunk) => {
      receivedBytes += chunk.byteLength;
      if (complete) return;
      received = received.byteLength === 0 ? Buffer.from(chunk) : Buffer.concat([received, chunk]);
      const split = received.indexOf('\r\n\r\n');
      if (split < 0) return;
      const lengthLine = received.subarray(0, split).toString('latin1').split('\r\n')
        .find((line) => line.toLowerCase().startsWith('content-length:'));
      const length = lengthLine === undefined ? NaN : Number(lengthLine.slice('content-length:'.length).trim());
      // The complete message is known only once the declared body has fully arrived: no sleeps, no
      // guesses, and an undeclared length counts as a protocol failure instead of a captured request.
      if (!Number.isSafeInteger(length)) { complete = true; return; }
      if (received.byteLength - (split + 4) < length) return;
      complete = true;
      captures.push(Buffer.from(received.subarray(0, split + 4 + length)));
      socket.end('HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
    });
  });

  await bounded(new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  }), 'sink listen');
  const address = server.address();
  assert.equal(typeof address, 'object');
  const port = address.port;

  return {
    port,
    get connections() { return connections; },
    get receivedBytes() { return receivedBytes; },
    get captures() { return captures; },
    async send(bytes) {
      const socket = net.connect(port, '127.0.0.1');
      open.add(socket);
      socket.on('error', () => {});
      await bounded(new Promise((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      }), 'loopback connect');
      const answered = [];
      // Reading the response is also what puts the client socket in flowing mode, so the exchange is
      // observed here rather than inferred from the write.
      socket.on('data', (chunk) => answered.push(chunk));
      socket.write(bytes);
      await bounded(new Promise((resolve) => socket.once('close', resolve)), 'loopback response');
      open.delete(socket);
      assert.equal(Buffer.concat(answered).toString('latin1').startsWith('HTTP/1.1 204'), true,
        'the sink answered the request it received');
      return captures.length;
    },
    async close() {
      for (const socket of open) socket.destroy();
      await bounded(new Promise((resolve) => server.close(() => resolve())), 'sink shutdown');
    },
  };
}

/* ---------- The test-local send point under test ---------- */

// The destination/profile this send point observes, and the one the policy decision authorized. The
// profile digest is computed here from the trusted fixture profile, not by the sentinel.
const AUTHORIZED = Object.freeze({
  id: SINK.ref,
  profileDigest: createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex'),
});
// The same destination id bound to a different profile: only the sentinel can refuse this, because the
// observed destination id is unchanged.
const OTHER_PROFILE_DIGEST = createHash('sha256')
  .update(JSON.stringify({ ...PROFILE, maxCleartextSensitivity: 'RESTRICTED' })).digest('hex');
assert.notEqual(OTHER_PROFILE_DIGEST, AUTHORIZED.profileDigest, 'the second profile really differs');
const OTHER_DESTINATION = Object.freeze({ id: 'other-sink.example.invalid', profileDigest: AUTHORIZED.profileDigest });

/**
 * The whole test-only send point. Nothing here is production code: it exists to show what a future
 * gateway must require, and it implements no treatment at all.
 */
function createSendPoint(sink, runnerConfig = { deadlineMs: DEADLINE_MS }) {
  const runner = createSentinelProcessRunner(runnerConfig);
  return {
    runner,
    /**
     * Codec, then the real policy decision, then the exact serialized image - metadata included -
     * checked in the real fixed child process. Nothing is written to a socket here: only a real ALLOW
     * produces a release, and only that private copy may be sent.
     */
    async prepare({ body = SAFE_REQUEST_BODY, endpoint = OPENAI_TEXT_REQUEST_ENDPOINT,
      extraHeaders = [], known = registration(BENIGN_ENTRIES), requestOverrides = {} } = {}) {
      const translated = translateOpenAiTextRequest({ endpoint, body });
      if (translated.status === 'REFUSED') return { stage: 'codec', translated };
      const { request, boundary } = scenario();
      const decision = decidePolicy(request, boundary, BUNDLE);
      const callerBytes = Buffer.from(serializeDraft(translated.draft, extraHeaders), 'utf8');
      if (decision.state !== 'SELECTED' || decision.treatment !== 'KEEP') {
        return { stage: 'policy', translated, decision, callerBytes };
      }
      const outcome = await runner.check({
        bytes: callerBytes, scope: SCOPE, destination: AUTHORIZED, authorized: AUTHORIZED, known,
        ...requestOverrides,
      });
      // Every outcome other than a real ALLOW withholds the release: there is no in-thread fallback.
      if (outcome.status !== 'ALLOW') return { stage: 'sentinel', translated, decision, callerBytes, outcome };
      return { stage: 'ready', translated, decision, callerBytes, outcome, release: outcome.release };
    },
    /** Sends only the runner's private ALLOW copy. Anything else is zero bytes and zero connections. */
    async send(prepared) {
      if (prepared?.stage !== 'ready' || !(prepared.release instanceof Uint8Array)) return { requests: 0 };
      await sink.send(prepared.release);
      return { requests: 1 };
    },
  };
}

async function harness(t) {
  const sink = await startSink();
  t.after(() => sink.close());
  return { sink, point: createSendPoint(sink) };
}

/** The whole withholding invariant in one helper: no request, no connection, no byte, no capture. */
const assertNothingSent = (sink, requests) => {
  assert.equal(requests, 0, 'no request was sent');
  assert.equal(sink.connections, 0, 'the sink accepted no connection');
  assert.equal(sink.receivedBytes, 0, 'the sink received zero bytes');
  assert.equal(sink.captures.length, 0);
};

/* ---------- The accepted safe path ---------- */

test('an accepted complete text request is ALLOWed by the real child process and reaches the loopback sink as exactly the declared bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    // The independently declared oracle and the serializer must agree before anything is sent.
    assert.equal(Buffer.byteLength(SAFE_REQUEST_BODY, 'utf8'), EXPECTED_CONTENT_LENGTH);

    const prepared = await point.prepare({ body: SAFE_REQUEST_BODY });
    assert.equal(prepared.stage, 'ready');
    assert.equal(prepared.translated.status, 'TRANSLATED');
    assert.equal(prepared.translated.draft.stream.mode, 'complete');
    assert.equal(prepared.decision.state, 'SELECTED');
    assert.equal(prepared.decision.treatment, 'KEEP');
    // The image the child was asked to check and the image this test independently declared are the
    // same bytes, metadata included. Compared by value: a failing diff would print the whole image.
    assert.equal(prepared.callerBytes.equals(EXPECTED_WIRE_BYTES), true, 'the checked image is the declared image');
    assert.equal(prepared.outcome.status, 'ALLOW');
    assert.equal(point.runner.state, 'IDLE');

    assert.equal((await point.send(prepared)).requests, 1);
    assert.equal(sink.connections, 1);
    assert.equal(sink.receivedBytes, EXPECTED_WIRE_BYTES.byteLength);
    assert.equal(sink.captures.length, 1);
    assert.equal(sink.captures[0].equals(EXPECTED_WIRE_BYTES), true, 'the sink received the declared image');
  });

test('the downstream synthetic utility fixture still sees literal https and port 443 in the received bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    assert.equal((await point.send(await point.prepare({ body: SAFE_REQUEST_BODY }))).requests, 1);
    const received = sink.captures[0].toString('utf8');
    const receivedBody = received.slice(received.indexOf('\r\n\r\n') + 4);
    // Literal protocol and port survive codec, policy and the child process: nothing was rewritten.
    assert.equal(receivedBody.includes('https'), true, 'the literal protocol is still in the received body');
    assert.equal(receivedBody.includes('443'), true, 'the literal port is still in the received body');
    assert.equal(downstreamUtilityAnswer(receivedBody), 'port 443');
  });

test('an explicit stream:false request produces the same checked and sent image',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    // `stream: false` is codec metadata; it does not change the serialized native image.
    const body = requestBody([
      { role: 'system', content: SAFE_SYSTEM_TEXT },
      { role: 'user', content: SAFE_USER_TEXT },
    ], { stream: false });
    const prepared = await point.prepare({ body });
    assert.equal(prepared.stage, 'ready');
    assert.equal((await point.send(prepared)).requests, 1);
    assert.equal(sink.captures[0].equals(EXPECTED_WIRE_BYTES), true, 'the sink received the declared image');
  });

test('mutating the caller buffer after the real check cannot change the released or received copy',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const prepared = await point.prepare({ body: SAFE_REQUEST_BODY });
    assert.equal(prepared.outcome.status, 'ALLOW');
    assert.equal(prepared.release === prepared.callerBytes, false, 'the runner returns its own copy');

    // Rewrite the caller's serialized body with a planted original after the check, before any send.
    // The head stays intact so the sink can still parse the request: the received bytes, not the parse,
    // are what must not change.
    const bodyStart = prepared.callerBytes.indexOf('\r\n\r\n') + 4;
    prepared.callerBytes.fill(0x41, bodyStart);
    prepared.callerBytes.write(PLANTED_ORIGINAL, bodyStart, 'utf8');
    assert.equal(prepared.callerBytes.includes(PLANTED_ORIGINAL), true);
    assert.equal(Buffer.from(prepared.release).includes(PLANTED_ORIGINAL), false,
      'the checked and released copy never carried the later mutation');
    assert.equal(prepared.callerBytes.equals(prepared.release), false,
      'the caller buffer and the private copy differ');

    assert.equal((await point.send(prepared)).requests, 1);
    assert.equal(sink.receivedBytes, EXPECTED_WIRE_BYTES.byteLength);
    assert.equal(sink.captures[0].includes(PLANTED_ORIGINAL), false, 'no planted value reached the sink');
    assert.equal(sink.captures[0].equals(EXPECTED_WIRE_BYTES), true, 'the sink received the declared image');
  });

/* ---------- The real child process refuses, and the sink sees nothing ---------- */

test('a planted original in the checked image is refused by the child process with its registered ref',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const prepared = await point.prepare({ body: LEAKY_REQUEST_BODY });
    assert.equal(prepared.stage, 'sentinel');
    assert.equal(prepared.decision.treatment, 'KEEP', 'the real policy decision selected KEEP before the check');
    assert.equal(prepared.outcome.status, 'BLOCK');
    assert.equal(prepared.outcome.code, 'SENTINEL_BLOCK');
    assert.deepEqual(prepared.outcome.reasonCodes, ['KNOWN_ORIGINAL_DETECTED']);
    assert.deepEqual(prepared.outcome.rules, ['planted.person.1']);
    assert.equal('release' in prepared.outcome, false);
    assertNothingSent(sink, (await point.send(prepared)).requests);
  });

test('a planted canary reintroduced in the metadata is refused by the child process over the whole image',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    // The body stays exactly the accepted safe request, so only the metadata header differs: the child
    // is asked about the whole serialized image, not about a body it could have been handed alone.
    const prepared = await point.prepare({ extraHeaders: [['X-Hylja-Note', PLANTED_CANARY]] });
    assert.equal(prepared.stage, 'sentinel');
    assert.equal(prepared.outcome.code, 'SENTINEL_BLOCK');
    assert.deepEqual(prepared.outcome.reasonCodes, ['CANARY_DETECTED']);
    assert.deepEqual(prepared.outcome.rules, ['planted.canary.1']);
    assertNothingSent(sink, (await point.send(prepared)).requests);
  });

test('an observed destination or profile the policy decision did not authorize is refused, not corrected',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    for (const [name, requestOverrides] of [
      ['destination', { destination: OTHER_DESTINATION }],
      ['profile', { destination: { id: AUTHORIZED.id, profileDigest: OTHER_PROFILE_DIGEST } }],
    ]) {
      const prepared = await point.prepare({ requestOverrides });
      assert.equal(prepared.stage, 'sentinel', name);
      assert.equal(prepared.outcome.code, 'SENTINEL_BLOCK', name);
      assert.deepEqual(prepared.outcome.reasonCodes, ['DESTINATION_MISMATCH'], name);
      assert.equal('release' in prepared.outcome, false, name);
      assertNothingSent(sink, (await point.send(prepared)).requests);
    }
  });

test('runner-owned cancel refuses a genuinely active check and leaves the runner clean and idle',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const { request, boundary } = scenario();
    assert.equal(decidePolicy(request, boundary, BUNDLE).treatment, 'KEEP');

    // Start a real check and cancel it in the same synchronous turn, so the cancel is certainly
    // observed before the fixed child can answer. No configurable worker, no mock checker, no clock.
    const translated = translateOpenAiTextRequest({ endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY });
    assert.equal(translated.status, 'TRANSLATED');
    const pending = point.runner.check({
      bytes: Buffer.from(serializeDraft(translated.draft), 'utf8'),
      scope: SCOPE, destination: AUTHORIZED, authorized: AUTHORIZED, known: registration(BENIGN_ENTRIES),
    });
    assert.equal(point.runner.state, 'BUSY', 'the check was genuinely active');
    point.runner.cancel();
    const outcome = await bounded(pending, 'cancelled check');

    assert.equal(outcome.status, 'BLOCK');
    assert.equal(outcome.code, 'CANCELLED');
    assert.equal('release' in outcome, false);
    assert.equal(point.runner.state, 'IDLE', 'a cancelled check leaves the runner clean, not quarantined');
    assertNothingSent(sink, (await point.send({ stage: 'sentinel', outcome })).requests);
    // Cancelling an idle runner is a no-op, not a state change and not a quarantine.
    point.runner.cancel();
    assert.equal(point.runner.state, 'IDLE');

    // The cancelled runner is clean, not quarantined: the next real check runs a real child again and
    // releases the same declared image. An idle state that could never check again would prove nothing.
    const afterwards = await point.prepare({ body: SAFE_REQUEST_BODY });
    assert.equal(afterwards.outcome.status, 'ALLOW');
    assert.equal((await point.send(afterwards)).requests, 1);
    assert.equal(sink.connections, 1);
    assert.equal(sink.captures[0].equals(EXPECTED_WIRE_BYTES), true, 'the sink received the declared image');
  });

test('a restrictive runner configuration or a refused request withholds everything and contacts nothing',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const sink = await startSink();
    t.after(() => sink.close());

    // Configurations the runner refuses before any child can exist: an unsupported own key, and a
    // deadline below the module's own floor. Neither is silently ignored, and neither throws.
    for (const [name, runnerConfig] of [
      ['unsupported own key', { deadlineMs: DEADLINE_MS, signal: null }],
      ['deadline below the floor', { deadlineMs: 1 }],
    ]) {
      const point = createSendPoint(sink, runnerConfig);
      const prepared = await point.prepare({ body: SAFE_REQUEST_BODY });
      assert.equal(prepared.stage, 'sentinel', name);
      assert.equal(prepared.outcome.status, 'BLOCK', name);
      assert.equal(prepared.outcome.code, 'INVALID_REQUEST', name);
      assert.deepEqual(prepared.outcome.reasonCodes, [], name);
      assert.equal(point.runner.state, 'IDLE', name);
      assertNothingSent(sink, (await point.send(prepared)).requests);
    }

    // A usable runner handed a request it must refuse: an omitted registration is never read as "no
    // originals to protect", so a forgotten handle cannot weaken the check into a decorative one.
    const point = createSendPoint(sink);
    for (const [name, requestOverrides] of [
      ['omitted registration', { known: undefined }],
      ['foreign registration scope', {
        known: { scope: { tenantRef: 'tenant-other.invalid', projectRef: SCOPE.projectRef }, key: KEY, entries: [] },
      }],
    ]) {
      const prepared = await point.prepare({ requestOverrides });
      assert.equal(prepared.stage, 'sentinel', name);
      assert.equal(prepared.outcome.code, 'INVALID_REQUEST', name);
      assert.equal(point.runner.state, 'IDLE', name);
      assertNothingSent(sink, (await point.send(prepared)).requests);
    }
  });
