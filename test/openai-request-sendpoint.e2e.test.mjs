// #174 / E2 of docs/development/proposals/2026-10-04/e2e-critical-path.md: the shipped strict text-only
// codec (`translateOpenAiTextRequest`), the shipped deterministic policy seam (`decidePolicy`) and the
// shipped independent sentinel (`checkEgress`, `sentinelUnavailable`) are wired, in this file only, to a
// real loopback TCP sink bound to an OS-assigned ephemeral port that records the exact bytes it receives.
//
// What this proves, precisely: for these narrow, obviously synthetic fixtures, a byte leaves the test
// only when the codec translated the request AND the real policy decision was SELECTED with KEEP AND the
// independent sentinel returned ALLOW over the exact serialized image. Every other outcome - codec
// refusal, DENIED, HELD, a SELECTED treatment other than KEEP, a trusted-boundary mismatch, a missing
// boundary, a known original the upstream evidence missed, a sentinel outage or failure - reaches the
// sink as zero bytes and zero connections.
//
// What it is NOT: a production gateway, a product adapter, an authentication proof (the trusted boundary,
// the policy bundle pin and the sentinel key are test fixtures, not authenticated identities), a
// transformation engine, a scoring or enforcement result, or a held-out result. There is no source
// transformer here: the send point applies no treatment at all, so a selected treatment other than KEEP
// simply withholds the release. No network beyond 127.0.0.1 on an ephemeral port; no provider traffic, no
// credentials, no real customer, infrastructure or held-out data.
//
// Every fixture value is invented and non-routable (`*.invalid`, loopback, a made-up name and host).
import assert from 'node:assert/strict';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { composeClassification, TRUST_LEVELS } from '../dist/classification.js';
import {
  decidePolicy, digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE,
} from '../dist/policy.js';
import { checkEgress, createKnownOriginals, sentinelUnavailable } from '../dist/egress-sentinel.js';
import { OPENAI_TEXT_REQUEST_ENDPOINT, translateOpenAiTextRequest } from '../dist/openai-text-request.js';
import { detectSecrets } from '../dist/secret-detectors.js';

const DEADLINE_MS = 5_000;
const TEST_TIMEOUT_MS = 30_000;

/* ---------- Planted synthetic originals and sentinel bindings ---------- */

const SCOPE = Object.freeze({ tenantRef: 'tenant-fixture.invalid', projectRef: 'project-fixture.invalid' });
const OTHER_SCOPE = Object.freeze({ tenantRef: 'tenant-other.invalid', projectRef: 'project-other.invalid' });
// A dedicated, obviously synthetic sentinel key for this test only. It is not a credential.
const SENTINEL_KEY = new Uint8Array(32).fill(11);
const PLANTED_PERSON = 'Verity Synthanon';
const PLANTED_HOST = 'gw-plc-42.tenant-fixture.invalid';
const known = createKnownOriginals(SCOPE, SENTINEL_KEY, [
  { kind: 'ORIGINAL', value: PLANTED_PERSON, ref: 'planted.person.1' },
  { kind: 'ORIGINAL', value: PLANTED_HOST, ref: 'planted.host.1' },
]);
// A handle bound to a different tenant and project: using it in this scope is cross-tenant handle misuse.
const foreignKnown = createKnownOriginals(OTHER_SCOPE, SENTINEL_KEY, [
  { kind: 'ORIGINAL', value: PLANTED_PERSON, ref: 'planted.person.1' },
]);

/* ---------- Trusted test fixture bindings (not authenticated identities) ---------- */

const SUBJECT = { principalId: 'principal-fixture.invalid', workloadId: 'workload-fixture.invalid' };
const CONTEXT = {
  tenantId: SCOPE.tenantRef, projectId: SCOPE.projectRef,
  sessionId: 'session-fixture.invalid', purpose: 'fixture-egress.invalid',
};
const SOURCE = { kind: 'tool.result', ref: 'tool-source-fixture.invalid', trustZone: 'LOCAL' };
const SOURCE_TRUST = 'TRUSTED';
const SINK = {
  kind: 'model', ref: 'model-sink.example.invalid', trustZone: 'EXTERNAL', profileId: 'fixture-sink.invalid',
};
const PROFILE = {
  id: 'fixture-sink.invalid', sink: SINK, exposure: 'EXTERNAL',
  permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'INTERNAL',
};
function rule(id, sensitivities, decision, reviewTreatments) {
  return {
    id: `${id}.invalid`, profileId: PROFILE.id, semanticType: 'PERSON', sensitivities,
    sourceTrust: [...TRUST_LEVELS], operations: ['SEND'], decision,
    ...(reviewTreatments ? { reviewTreatments } : {}),
  };
}
const BUNDLE = Object.freeze({
  ...KNOWN_POLICY_BUNDLE,
  profiles: [PROFILE],
  rules: [
    rule('fixture-keep', ['PUBLIC'], 'KEEP'),
    rule('fixture-mask', ['INTERNAL'], 'MASK'),
    rule('fixture-review', ['CONFIDENTIAL'], 'REQUIRE_REVIEW', ['REMOVE']),
    rule('fixture-block', ['RESTRICTED', 'SECRET'], 'BLOCK'),
  ],
});

function classificationFor(sensitivity) {
  return composeClassification({
    detectorEvidence: [{
      version: 1, id: 'detector-fixture.invalid', status: 'FOUND',
      provenance: {
        inputRef: 'field-fixture.invalid', producerId: 'detector-fixture.invalid',
        producerVersion: 'pack-fixture-1',
      },
      claim: { semanticType: 'PERSON', sensitivity },
    }],
  }, { interactionRef: 'interaction-fixture.invalid', sourceRef: SOURCE.ref, trust: SOURCE_TRUST });
}

// One trusted-boundary scenario supplied by this test, exactly as a trusted integration would. The
// module under test still re-checks every binding, digest and pinned bundle identity itself.
function scenario(sensitivity) {
  const evidence = classificationFor(sensitivity);
  return {
    request: {
      version: 1, interactionRef: 'interaction-fixture.invalid', candidateRef: 'unit-fixture-1.invalid',
      subject: SUBJECT, context: CONTEXT, source: SOURCE, destination: SINK, classification: evidence,
      operation: 'SEND', policy: KNOWN_POLICY_BUNDLE,
    },
    boundary: {
      interactionRef: 'interaction-fixture.invalid', candidateRef: 'unit-fixture-1.invalid',
      classificationDigest: digestClassification(evidence),
      authenticated: { subject: SUBJECT, context: CONTEXT },
      observed: { source: { ...SOURCE, trust: SOURCE_TRUST }, destination: SINK },
      policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) },
    },
  };
}

/* ---------- The accepted request and the independently declared expected wire image ---------- */

const SAFE_SYSTEM_TEXT = 'You are a synthetic fixture assistant.';
// The literal protocol and port a downstream utility fixture needs in order to answer correctly. If a
// gate redacted or rewrote either literal, the downstream answer would change; nothing here transforms.
const SAFE_USER_TEXT = 'Diagnose why the synthetic fixture gateway fails on https and port 443.';
const SAFE_REQUEST_BODY = JSON.stringify({
  model: 'fixture-model-openai-e2e',
  messages: [
    { role: 'system', content: SAFE_SYSTEM_TEXT },
    { role: 'user', content: SAFE_USER_TEXT },
  ],
});
const BASE_HEADERS = Object.freeze([
  Object.freeze(['Host', '127.0.0.1']),
  Object.freeze(['X-Hylja-Fixture', 'openai-request-sendpoint-e2e']),
  Object.freeze(['Content-Type', 'application/json; charset=utf-8']),
]);
// Serialize the TRANSLATED draft back into the native text-only image, in native field and message order.
// This is test-local serialization, not a transformation: no treatment is selected, applied or emulated.
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
const EXPECTED_SAFE_WIRE = [
  'POST /v1/chat/completions HTTP/1.1',
  'Host: 127.0.0.1',
  'X-Hylja-Fixture: openai-request-sendpoint-e2e',
  'Content-Type: application/json; charset=utf-8',
  `Content-Length: ${EXPECTED_CONTENT_LENGTH}`,
  '',
  '{"model":"fixture-model-openai-e2e","messages":['
    + '{"role":"system","content":"You are a synthetic fixture assistant."},'
    + '{"role":"user","content":"Diagnose why the synthetic fixture gateway fails on https and port 443."}'
    + ']}',
].join('\r\n');

/* ---------- The downstream synthetic utility fixture ---------- */

// A deterministic, local, non-model "downstream utility": it answers only if BOTH the literal protocol
// and the literal port survived the whole pipeline into the received bytes. It never calls anything.
function downstreamUtilityAnswer(receivedBodyText) {
  if (!receivedBodyText.includes('https')) return 'protocol-lost';
  const port = receivedBodyText.match(/\b(443)\b/u);
  return port ? `port ${port[1]}` : 'port-lost';
}
const EXPECTED_UTILITY_ANSWER = 'port 443';

/* ---------- A real loopback sink on an OS-assigned ephemeral port ---------- */

function deadline(promise, label) {
  let timer;
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`deadline exceeded: ${label}`)), DEADLINE_MS);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

async function startSink() {
  const serverSockets = new Set();
  const clientSockets = new Set();
  const captures = [];
  const protocolFailures = [];
  let connections = 0;
  let receivedBytes = 0;

  const server = net.createServer((socket) => {
    connections += 1;
    serverSockets.add(socket);
    socket.on('close', () => serverSockets.delete(socket));
    socket.on('error', () => {});
    let received = Buffer.alloc(0);
    let complete = false;
    socket.on('data', (chunk) => {
      receivedBytes += chunk.byteLength;
      if (complete) return;
      received = received.byteLength === 0 ? Buffer.from(chunk) : Buffer.concat([received, chunk]);
      const split = received.indexOf('\r\n\r\n');
      if (split < 0) return;
      const lines = received.subarray(0, split).toString('latin1').split('\r\n');
      const lengthLine = lines.find((line) => line.toLowerCase().startsWith('content-length:'));
      if (lengthLine === undefined) {
        complete = true;
        protocolFailures.push('missing-content-length');
        return;
      }
      const length = Number(lengthLine.slice('content-length:'.length).trim());
      if (!Number.isSafeInteger(length)) {
        complete = true;
        protocolFailures.push('malformed-content-length');
        return;
      }
      // The complete message is known only once the declared body has fully arrived: no sleeps, no guesses.
      if (received.byteLength - (split + 4) < length) return;
      complete = true;
      captures.push(Buffer.from(received.subarray(0, split + 4 + length)));
      socket.end('HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
    });
  });

  await deadline(new Promise((resolve, reject) => {
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
    captures,
    async send(bytes) {
      assert.deepEqual(protocolFailures, [], 'the sink parsed every request it received');
      const socket = net.connect(port, '127.0.0.1');
      clientSockets.add(socket);
      socket.on('error', () => {});
      await deadline(new Promise((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      }), 'loopback connect');
      const answered = [];
      // Reading the response is also what puts the client socket in flowing mode, so the whole loopback
      // exchange is observed here rather than inferred from the write.
      socket.on('data', (chunk) => answered.push(chunk));
      socket.write(bytes);
      await deadline(new Promise((resolve) => socket.once('close', resolve)), 'loopback response');
      clientSockets.delete(socket);
      assert.deepEqual(protocolFailures, [], 'the sink parsed every request it received');
      assert.equal(Buffer.concat(answered).toString('latin1').startsWith('HTTP/1.1 204'), true,
        'the sink answered the request it received');
      return captures.length;
    },
    async close() {
      for (const socket of clientSockets) socket.destroy();
      for (const socket of serverSockets) socket.destroy();
      await deadline(new Promise((resolve) => server.close(() => resolve())), 'sink shutdown');
    },
  };
}

/* ---------- The test-local send point under test ---------- */

// The destination/profile this send point observes, and the one policy authorized. The profile digest is
// computed here from the trusted fixture profile, not by the sentinel.
const AUTHORIZED = Object.freeze({
  id: SINK.ref,
  profileDigest: createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex'),
});
// The same destination bound to a different profile: the send point observes a profile the policy
// decision never authorized, so only the sentinel can refuse this.
const OTHER_PROFILE_DIGEST = createHash('sha256')
  .update(JSON.stringify({ ...PROFILE, maxCleartextSensitivity: 'RESTRICTED' })).digest('hex');
assert.notEqual(OTHER_PROFILE_DIGEST, AUTHORIZED.profileDigest, 'the second profile really differs');

const selectedKeep = (decision) => decision?.state === 'SELECTED' && decision?.treatment === 'KEEP';

/**
 * The whole test-only send point. Nothing here is production code: it exists to show what a future
 * gateway must require, and it deliberately implements no treatment at all.
 */
function createSendPoint(sink) {
  return {
    /**
     * Codec, then policy, then the exact final-byte check. Nothing is written to the socket here: the
     * caller receives the caller's own buffer plus, on ALLOW, the sentinel's private copy, and decides
     * when to send. Every refusal path returns no release at all.
     */
    prepare({ endpoint = OPENAI_TEXT_REQUEST_ENDPOINT, body, sensitivity = 'PUBLIC', extraHeaders = [],
      boundaryOverride, boundaryMissing = false, checkOverrides, outcome } = {}) {
      const translated = translateOpenAiTextRequest({ endpoint, body });
      if (translated.status === 'REFUSED') {
        return { stage: 'codec', translated, callerBytes: undefined, result: null, release: undefined };
      }
      const { request, boundary } = scenario(sensitivity);
      const trustedBoundary = boundaryMissing ? undefined
        : (typeof boundaryOverride === 'function' ? boundaryOverride(boundary) : boundaryOverride) ?? boundary;
      const decision = decidePolicy(request, trustedBoundary, BUNDLE);
      // No transformer: the translated draft is serialized as-is. A selected treatment other than KEEP
      // cannot be applied here at all, so it withholds the release instead of silently sending.
      const callerBytes = Buffer.from(serializeDraft(translated.draft, extraHeaders), 'utf8');
      if (!selectedKeep(decision)) {
        return { stage: 'policy', translated, decision, callerBytes, result: null, release: undefined };
      }
      const result = outcome ?? checkEgress({
        bytes: callerBytes, scope: SCOPE, destination: AUTHORIZED, authorized: AUTHORIZED, known,
        ...checkOverrides,
      });
      if (result.decision !== 'ALLOW' || !(result.release instanceof Uint8Array)) {
        return { stage: 'sentinel', translated, decision, callerBytes, result, release: undefined };
      }
      return { stage: 'ready', translated, decision, callerBytes, result, release: result.release };
    },
    /**
     * The send point. It requires SELECTED/KEEP from the real decision and ALLOW from the sentinel, and
     * sends only the sentinel's private copy. Any other combination is zero bytes and zero connections.
     */
    async send(prepared) {
      const releasable = selectedKeep(prepared?.decision) && prepared?.result?.decision === 'ALLOW'
        && prepared.release instanceof Uint8Array;
      if (!releasable) return { requests: 0 };
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
const assertNothingSent = (sink, requests) => {
  assert.equal(requests, 0, 'no request was sent');
  assert.equal(sink.connections, 0, 'the sink accepted no connection');
  assert.equal(sink.receivedBytes, 0, 'the sink received zero bytes');
  assert.deepEqual(sink.captures, []);
};

/* ---------- The accepted safe path ---------- */

test('an accepted complete text request reaches the loopback sink as exactly the declared bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    // The independent oracle and the serializer must agree before anything is sent.
    assert.equal(Buffer.byteLength(SAFE_REQUEST_BODY, 'utf8'), EXPECTED_CONTENT_LENGTH);

    const prepared = point.prepare({ body: SAFE_REQUEST_BODY });
    assert.equal(prepared.stage, 'ready');
    assert.equal(prepared.translated.status, 'TRANSLATED');
    assert.equal(prepared.translated.draft.stream.mode, 'complete');
    assert.equal(prepared.decision.state, 'SELECTED');
    assert.equal(prepared.decision.treatment, 'KEEP');
    assert.equal(prepared.callerBytes.toString('utf8'), EXPECTED_SAFE_WIRE);
    assert.equal(prepared.result.decision, 'ALLOW');
    assert.deepEqual(prepared.result.reasons, []);

    assert.equal((await point.send(prepared)).requests, 1);
    assert.equal(sink.connections, 1);
    assert.equal(sink.receivedBytes, Buffer.byteLength(EXPECTED_SAFE_WIRE, 'utf8'));
    assert.equal(sink.captures.length, 1);
    assert.deepEqual(sink.captures[0], Buffer.from(EXPECTED_SAFE_WIRE, 'utf8'));
  });

test('the downstream synthetic utility fixture still sees literal https and port 443 in the received bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    assert.equal((await point.send(point.prepare({ body: SAFE_REQUEST_BODY }))).requests, 1);
    const received = sink.captures[0].toString('utf8');
    const receivedBody = received.slice(received.indexOf('\r\n\r\n') + 4);
    // Literal protocol and port survive the whole pipeline: nothing redacted, rewrote or narrowed them.
    assert.equal(receivedBody.includes('https'), true, 'the literal protocol is still in the received body');
    assert.equal(receivedBody.includes('443'), true, 'the literal port is still in the received body');
    assert.equal(downstreamUtilityAnswer(receivedBody), EXPECTED_UTILITY_ANSWER);
  });

test('an explicit stream:false request is still one complete message and sends the same declared bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const body = JSON.stringify({
      model: 'fixture-model-openai-e2e',
      messages: [
        { role: 'system', content: SAFE_SYSTEM_TEXT },
        { role: 'user', content: SAFE_USER_TEXT },
      ],
      stream: false,
    });
    const prepared = point.prepare({ body });
    assert.equal(prepared.stage, 'ready');
    assert.equal((await point.send(prepared)).requests, 1);
    // `stream: false` is codec metadata; it does not change the serialized native image.
    assert.deepEqual(sink.captures[0], Buffer.from(EXPECTED_SAFE_WIRE, 'utf8'));
  });

test('mutating the caller buffer after the final-byte check cannot change the received ALLOW copy',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const prepared = point.prepare({ body: SAFE_REQUEST_BODY });
    assert.equal(prepared.result.decision, 'ALLOW');
    assert.notEqual(prepared.release, prepared.callerBytes, 'the sentinel returns its own copy');

    // Rewrite the caller's serialized body with a planted original after the check, before any send.
    // The head is left intact so the sink can still parse the request: the received bytes, not the parse,
    // are what must not change.
    const bodyStart = prepared.callerBytes.indexOf('\r\n\r\n') + 4;
    prepared.callerBytes.fill(0x41, bodyStart);
    prepared.callerBytes.write(PLANTED_PERSON, bodyStart, 'utf8');
    assert.equal(prepared.callerBytes.subarray(0, bodyStart).includes(PLANTED_PERSON), false);
    // Compared by value, not by structure: a failing deep-equal diff would print buffer contents, and
    // this buffer now holds a planted original by construction.
    assert.notEqual(prepared.callerBytes.equals(prepared.release), true,
      'the caller buffer and the private copy differ');

    assert.equal((await point.send(prepared)).requests, 1);
    assert.equal(sink.receivedBytes, Buffer.byteLength(EXPECTED_SAFE_WIRE, 'utf8'));
    assert.equal(sink.captures[0].includes(PLANTED_PERSON), false);
    assert.deepEqual(sink.captures[0], Buffer.from(EXPECTED_SAFE_WIRE, 'utf8'));
  });

/* ---------- Strict codec refusals ---------- */

test('a stream, tool, unknown-field or wrong-endpoint request is refused by name and makes no contact',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const cases = [
      ['stream', '{"model":"fixture-model-openai-e2e","stream":true,'
        + `"messages":[{"role":"user","content":${JSON.stringify(SAFE_USER_TEXT)}}]}`, 'STREAMING_NOT_SUPPORTED'],
      ['tools', '{"model":"fixture-model-openai-e2e","tools":[],'
        + `"messages":[{"role":"user","content":${JSON.stringify(SAFE_USER_TEXT)}}]}`, 'UNSUPPORTED_TOOLS'],
      ['unknown-field', '{"model":"fixture-model-openai-e2e","temperature":0,'
        + `"messages":[{"role":"user","content":${JSON.stringify(SAFE_USER_TEXT)}}]}`, 'UNEXPECTED_FIELD'],
      ['role', '{"model":"fixture-model-openai-e2e","messages":[{"role":"tool","content":"x"}]}',
        'UNSUPPORTED_ROLE'],
      ['duplicate-key', '{"model":"a","model":"b","messages":[{"role":"user","content":"x"}]}',
        'AMBIGUOUS_BODY'],
    ];
    for (const [name, body, reason] of cases) {
      const prepared = point.prepare({ body });
      assert.equal(prepared.stage, 'codec', name);
      assert.equal(prepared.translated.status, 'REFUSED', name);
      assert.equal(prepared.translated.reason, reason, name);
      assert.equal(prepared.release, undefined, name);
      assertNothingSent(sink, (await point.send(prepared)).requests);
    }

    for (const endpoint of ['/v1/responses', '/v1/chat/completions/', 'https://api.example.invalid/v1/chat/completions']) {
      const prepared = point.prepare({ endpoint, body: SAFE_REQUEST_BODY });
      assert.equal(prepared.translated.reason, 'ENDPOINT_NOT_SUPPORTED', endpoint);
      assertNothingSent(sink, (await point.send(prepared)).requests);
    }
  });

/* ---------- The real policy seam ---------- */

test('a real DENIED or HELD decision reaches the sink as zero bytes', { timeout: TEST_TIMEOUT_MS }, async (t) => {
  const { sink, point } = await harness(t);
  const denied = point.prepare({ body: SAFE_REQUEST_BODY, sensitivity: 'RESTRICTED' });
  assert.equal(denied.decision.state, 'DENIED');
  assert.equal(denied.decision.treatment, 'BLOCK');
  assert.equal(denied.decision.reason, 'RULE_BLOCK');
  const held = point.prepare({ body: SAFE_REQUEST_BODY, sensitivity: 'CONFIDENTIAL' });
  assert.equal(held.decision.state, 'HELD');
  assert.equal(held.decision.treatment, 'REQUIRE_REVIEW');
  assert.equal(held.decision.reason, 'RULE_REVIEW');

  for (const prepared of [denied, held]) {
    assert.equal(prepared.stage, 'policy');
    assert.equal(prepared.result, null);
    assert.equal(prepared.release, undefined);
    assertNothingSent(sink, (await point.send(prepared)).requests);
  }
});

test('a SELECTED treatment other than KEEP withholds the release: this seam transforms nothing',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const prepared = point.prepare({ body: SAFE_REQUEST_BODY, sensitivity: 'INTERNAL' });
    assert.equal(prepared.decision.state, 'SELECTED');
    assert.equal(prepared.decision.treatment, 'MASK');
    assert.equal(prepared.stage, 'policy');
    assert.equal(prepared.release, undefined);
    assertNothingSent(sink, (await point.send(prepared)).requests);
  });

test('a mismatched trusted destination or tenant, or a missing boundary, denies and makes no contact',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const cases = [
      // The send point's authenticated destination is not the one the request asked for.
      ['destination', (boundary) => ({
        ...boundary, observed: { ...boundary.observed, destination: { ...SINK, ref: 'other-sink.example.invalid' } },
      }), 'CONTEXT_MISMATCH'],
      // The authenticated tenant is not the one the request claimed.
      ['tenant', (boundary) => ({
        ...boundary,
        authenticated: { subject: SUBJECT, context: { ...CONTEXT, tenantId: 'tenant-other.invalid' } },
      }), 'CONTEXT_MISMATCH'],
      // The classification does not match the independently pinned digest.
      ['digest', (boundary) => ({ ...boundary, classificationDigest: '0'.repeat(64) }), 'CLASSIFICATION_MISMATCH'],
      // The pinned bundle digest is not the one this bundle hashes to.
      ['bundle', (boundary) => ({ ...boundary, policy: { ...KNOWN_POLICY_BUNDLE, digest: 'a'.repeat(64) } }),
        'BUNDLE_MISMATCH'],
      // No authenticated boundary at all: nothing is authorized.
      ['missing', 'missing', 'INVALID_CONTEXT'],
    ];
    for (const [name, boundaryOverride, reason] of cases) {
      const prepared = point.prepare({
        body: SAFE_REQUEST_BODY,
        boundaryMissing: boundaryOverride === 'missing',
        ...(boundaryOverride !== 'missing' ? { boundaryOverride } : {}),
      });
      assert.equal(prepared.decision.state, 'DENIED', name);
      assert.equal(prepared.decision.reason, reason, name);
      assert.equal(prepared.stage, 'policy', name);
      assertNothingSent(sink, (await point.send(prepared)).requests);
    }
  });

/* ---------- A planted original the primary evidence misses ---------- */

test('a planted original the primary evidence misses is caught independently in the received-image bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const leaky = JSON.stringify({
      model: 'fixture-model-openai-e2e',
      messages: [{ role: 'user', content: `Escalate to ${PLANTED_PERSON} on ${PLANTED_HOST} before the window.` }],
    });

    // PRIMARY-EVIDENCE MISS: the upstream detector stack genuinely does not know these values. This is a
    // deliberate upstream miss and is NOT counted as candidate-recall success anywhere.
    assert.deepEqual(detectSecrets({ text: leaky, inputRef: 'fixture-wire' }).candidates, []);

    // SENTINEL CATCH: the independent check over the exact bytes that would go on the wire still finds
    // both planted originals. The two outcomes are named separately on purpose.
    const prepared = point.prepare({ body: leaky });
    assert.equal(prepared.stage, 'sentinel');
    assert.equal(prepared.decision.treatment, 'KEEP', 'policy selected KEEP before the sentinel ran');
    assert.equal(prepared.result.decision, 'BLOCK');
    assert.deepEqual(prepared.result.reasons, ['KNOWN_ORIGINAL_DETECTED']);
    assert.deepEqual(prepared.result.findings.map((finding) => finding.rule).sort(),
      ['planted.host.1', 'planted.person.1']);
    assert.equal(prepared.release, undefined);
    assertNothingSent(sink, (await point.send(prepared)).requests);
  });

test('a planted original reintroduced into the serialized metadata is caught and sends zero bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    for (const [name, extraHeaders] of [
      ['metadata', [['X-Hylja-Note', PLANTED_PERSON]]],
      ['encoded-metadata', [['X-Hylja-Note', Buffer.from(`note: ${PLANTED_PERSON}`, 'utf8').toString('base64')]]],
    ]) {
      // The body itself stays exactly the accepted safe request, so the only difference is metadata.
      const prepared = point.prepare({ body: SAFE_REQUEST_BODY, extraHeaders });
      assert.equal(prepared.stage, 'sentinel', name);
      assert.ok(prepared.result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), name);
      assert.equal(prepared.release, undefined, name);
      assertNothingSent(sink, (await point.send(prepared)).requests);
    }
  });

/* ---------- Sentinel failure, unavailability and destination disagreement ---------- */

test('a sentinel outage, an unusable check and a destination the decision did not authorize send zero bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const outage = sentinelUnavailable();
    assert.deepEqual(outage.reasons, ['SENTINEL_UNAVAILABLE']);
    const cases = [
      // A required final-byte check that cannot run is restrictive, never a pass.
      ['outage', { outcome: outage }, 'SENTINEL_UNAVAILABLE'],
      // The check is handed something it cannot inspect at all.
      ['invalid-check', { checkOverrides: { bytes: 'not-bytes' } }, 'INVALID_CHECK'],
      // The send point observes the authorized destination bound to a profile digest policy never
      // authorized: the destination id is unchanged, so only the profile can refuse this.
      ['profile', {
        checkOverrides: { destination: { id: AUTHORIZED.id, profileDigest: OTHER_PROFILE_DIGEST } },
      }, 'DESTINATION_MISMATCH'],
      // Another tenant and project's known-originals handle used in this scope.
      ['cross-tenant', { checkOverrides: { known: foreignKnown } }, 'KNOWN_ORIGINALS_SCOPE_MISMATCH'],
    ];
    for (const [name, options, reason] of cases) {
      const prepared = point.prepare({ body: SAFE_REQUEST_BODY, ...options });
      assert.equal(prepared.stage, 'sentinel', name);
      assert.equal(prepared.result.decision, 'BLOCK', name);
      assert.deepEqual(prepared.result.reasons, [reason], name);
      assert.equal(prepared.release, undefined, name);
      assertNothingSent(sink, (await point.send(prepared)).requests);
    }
  });

test('no refusal, decision, sentinel finding or regression record contains a planted original',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, point } = await harness(t);
    const leaky = JSON.stringify({
      model: 'fixture-model-openai-e2e',
      messages: [{ role: 'user', content: `Escalate to ${PLANTED_PERSON} on ${PLANTED_HOST}.` }],
    });
    const caught = point.prepare({ body: leaky });
    const refused = point.prepare({ body: '{"model":"m","stream":true,"messages":[{"role":"user","content":"x"}]}' });
    const held = point.prepare({ body: SAFE_REQUEST_BODY, sensitivity: 'CONFIDENTIAL' });
    const evidence = JSON.stringify({
      decisions: [caught.decision, refused.translated, held.decision],
      results: [caught.result, sentinelUnavailable()],
      regressions: [caught.result.regression],
      send: await point.send(caught),
    });
    for (const [label, planted] of [
      ['planted person', PLANTED_PERSON],
      ['planted person, case-folded', PLANTED_PERSON.toLowerCase()],
      ['planted host', PLANTED_HOST],
      ['planted person, first six bytes', PLANTED_PERSON.slice(0, 6)],
    ]) {
      // Fixed privacy-safe labels: the assertion message must never carry a planted original, or a leak
      // would be echoed into the TAP output and invert the invariant this test exists to prove.
      assert.equal(evidence.includes(planted), false, label);
    }
    assertNothingSent(sink, JSON.parse(evidence).send.requests);
  });