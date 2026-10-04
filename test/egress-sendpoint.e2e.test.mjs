// #154 / E2 of docs/development/proposals/2026-10-04/e2e-critical-path.md: the shipped deterministic
// policy seam (`decidePolicy`) and the shipped independent sentinel (`checkEgress`,
// `createStreamGate`, `sentinelUnavailable`) run over one serialized synthetic fixture release, and a
// real loopback TCP sink bound to an OS-assigned ephemeral port records the exact bytes it receives.
//
// What this proves, precisely: for this narrow public synthetic fixture, with trusted test-supplied
// policy/sentinel bindings, a release happens only on SELECTED KEEP plus sentinel ALLOW, and what the
// sink receives is the sentinel's private ALLOW copy of the exact post-serialization wire image.
//
// What it is NOT: a product adapter, a gateway, an authentication proof (the trusted boundary and the
// sentinel key are test fixtures, not authenticated identities), a transformation engine, a production
// send point, or a held-out result. No network beyond 127.0.0.1 on an ephemeral port; no provider
// traffic, no credentials, no real customer or infrastructure data.
//
// Every fixture value is invented and non-routable (`*.invalid`, `example.invalid`, loopback).
import assert from 'node:assert/strict';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { composeClassification, TRUST_LEVELS } from '../dist/classification.js';
import {
  decidePolicy, digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE,
} from '../dist/policy.js';
import {
  checkEgress, createKnownOriginals, createStreamGate, sentinelUnavailable,
} from '../dist/egress-sentinel.js';
import { detectSecrets } from '../dist/secret-detectors.js';

const DEADLINE_MS = 5_000;
const TEST_TIMEOUT_MS = 30_000;

/* ---------- Planted synthetic originals and sentinel bindings ---------- */

const SCOPE_A = Object.freeze({ tenantRef: 'tenant-fixture.invalid', projectRef: 'project-fixture.invalid' });
const SCOPE_B = Object.freeze({ tenantRef: 'tenant-other.invalid', projectRef: 'project-other.invalid' });
// A dedicated, obviously synthetic sentinel key for this test only. It is not a credential.
const SENTINEL_KEY = new Uint8Array(32).fill(7);
const PLANTED_PERSON = 'Verity Synthanon';
const PLANTED_HOST = 'gw-plc-42.tenant-fixture.invalid';
const known = createKnownOriginals(SCOPE_A, SENTINEL_KEY, [
  { kind: 'ORIGINAL', value: PLANTED_PERSON, ref: 'planted.person.1' },
  { kind: 'ORIGINAL', value: PLANTED_HOST, ref: 'planted.host.1' },
]);
// A handle for another tenant: using it in this tenant's check is cross-tenant handle misuse.
const foreignKnown = createKnownOriginals(SCOPE_B, SENTINEL_KEY, [
  { kind: 'ORIGINAL', value: PLANTED_PERSON, ref: 'planted.person.1' },
]);

/* ---------- Trusted test fixture bindings (not authenticated identities) ---------- */

const SUBJECT = { principalId: 'principal-fixture.invalid', workloadId: 'workload-fixture.invalid' };
const CONTEXT = {
  tenantId: 'tenant-fixture.invalid', projectId: 'project-fixture.invalid',
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
    rule('fixture-keep', ['PUBLIC', 'INTERNAL'], 'KEEP'),
    rule('fixture-review', ['CONFIDENTIAL'], 'REQUIRE_REVIEW', ['REMOVE']),
    rule('fixture-block', ['RESTRICTED', 'SECRET'], 'BLOCK'),
  ],
});

function classification(sensitivity) {
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

// One trusted-boundary scenario. The boundary, the bundle pin and the classification digest are supplied
// by this test, exactly as a trusted integration would; the module under test still checks every binding.
function scenario(sensitivity) {
  const evidence = classification(sensitivity);
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
const decide = (sensitivity) => {
  const { request, boundary } = scenario(sensitivity);
  return decidePolicy(request, boundary, BUNDLE);
};

/* ---------- Explicit serialization: ordered body fields and ordered metadata ---------- */

const BASE_HEADERS = Object.freeze([
  Object.freeze(['Host', 'model-sink.example.invalid']),
  Object.freeze(['X-Hylja-Fixture', 'egress-sendpoint-e2e']),
  Object.freeze(['Content-Type', 'application/json; charset=utf-8']),
]);
function serializeMessage(content) {
  return `{"role":"user","content":${JSON.stringify(content)}}`;
}
function serializeBody(content) {
  return `{"model":"fixture-model-e2e","messages":[${serializeMessage(content)}]}`;
}
function serializeWire(content, extraHeaders = []) {
  const body = serializeBody(content);
  const head = [
    'POST /v1/messages HTTP/1.1',
    ...BASE_HEADERS.map(([name, value]) => `${name}: ${value}`),
    ...extraHeaders.map(([name, value]) => `${name}: ${value}`),
    `Content-Length: ${Buffer.byteLength(body, 'utf8')}`,
    '', '',
  ].join('\r\n');
  return `${head}${body}`;
}

const SAFE_MESSAGE = 'Rotate the synthetic fixture deployment in the next window.';
// Independently declared expected wire bytes for the safe fixture: a reviewer can read this literal and
// compare it with what the sink received without running any part of the pipeline.
const EXPECTED_CONTENT_LENGTH = 130;
const EXPECTED_SAFE_WIRE = [
  'POST /v1/messages HTTP/1.1',
  'Host: model-sink.example.invalid',
  'X-Hylja-Fixture: egress-sendpoint-e2e',
  'Content-Type: application/json; charset=utf-8',
  `Content-Length: ${EXPECTED_CONTENT_LENGTH}`,
  '',
  '{"model":"fixture-model-e2e","messages":[{"role":"user","content":'
    + `"${SAFE_MESSAGE}"}]}`,
].join('\r\n');

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
      // The complete message is only known once the declared body has fully arrived: no sleeps, no guesses.
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
      // A response reader is also what puts the client socket in flowing mode; the response bytes are
      // collected here so the loopback exchange is observed rather than inferred.
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

/* ---------- The test-local release adapter under test ---------- */

// The destination/profile the send point observes and the policy decision authorized. The profile digest
// is computed here from the trusted fixture profile, not by the sentinel.
const AUTHORIZED = Object.freeze({
  id: SINK.ref,
  profileDigest: createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex'),
});

// A planted original wrapped in more encoding layers than the sentinel's bounded decode rounds reach:
// opaque, uninspectable content is never presumed clean.
function nestedEncoding() {
  let nested = PLANTED_PERSON;
  for (let layer = 0; layer < 6; layer++) {
    nested = Buffer.from(`layer:${nested}`, 'utf8').toString('base64');
  }
  return nested;
}

function createAdapter(sink) {
  const check = (bytes, overrides) => checkEgress({
    bytes, scope: SCOPE_A, destination: AUTHORIZED, authorized: AUTHORIZED, known, ...overrides,
  });
  return {
    /**
     * The send point: refuse unless policy selected KEEP, then run the required final-byte check over the
     * exact bytes about to go on the wire. Returns the caller's own buffer alongside the private copy.
     */
    prepare(wire, decision, { overrides, result } = {}) {
      const callerBytes = typeof wire === 'string' ? Buffer.from(wire, 'utf8') : wire;
      if (decision.state !== 'SELECTED' || decision.treatment !== 'KEEP') {
        return { callerBytes, refused: 'policy', result: null, release: undefined };
      }
      const outcome = result ?? check(callerBytes, overrides);
      return { callerBytes, refused: undefined, result: outcome, release: outcome.release };
    },
    /** Sends only the sentinel's ALLOW copy; every other outcome reaches the sink as zero bytes. */
    async send(prepared) {
      if (prepared.refused !== undefined || prepared.result?.decision !== 'ALLOW') return { requests: 0 };
      await sink.send(prepared.release);
      return { requests: 1 };
    },
    stream(overrides) {
      return createStreamGate({
        scope: SCOPE_A, destination: AUTHORIZED, authorized: AUTHORIZED, known, ...overrides,
      });
    },
  };
}

async function harness(t) {
  const sink = await startSink();
  t.after(() => sink.close());
  return { sink, adapter: createAdapter(sink) };
}
const assertNothingSent = (sink, requests) => {
  assert.equal(requests, 0, 'no request was sent');
  assert.equal(sink.connections, 0, 'the sink accepted no connection');
  assert.equal(sink.receivedBytes, 0, 'the sink received zero bytes');
  assert.deepEqual(sink.captures, []);
};

/* ---------- The safe release path ---------- */

test('a safe fixture passes the real policy and sentinel, and the sink receives exactly the declared wire bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, adapter } = await harness(t);
    const decision = decide('PUBLIC');
    assert.equal(decision.state, 'SELECTED');
    assert.equal(decision.treatment, 'KEEP');

    // The independently declared oracle and the serializer must agree before anything is sent.
    assert.equal(Buffer.byteLength(serializeBody(SAFE_MESSAGE), 'utf8'), EXPECTED_CONTENT_LENGTH);
    assert.equal(serializeWire(SAFE_MESSAGE), EXPECTED_SAFE_WIRE);

    const prepared = adapter.prepare(EXPECTED_SAFE_WIRE, decision);
    assert.equal(prepared.result.decision, 'ALLOW');
    assert.deepEqual(prepared.result.reasons, []);
    const sent = await adapter.send(prepared);
    assert.equal(sent.requests, 1);
    assert.equal(sink.connections, 1);
    assert.equal(sink.receivedBytes, Buffer.byteLength(EXPECTED_SAFE_WIRE, 'utf8'));
    assert.equal(sink.captures.length, 1);
    assert.deepEqual(sink.captures[0], Buffer.from(EXPECTED_SAFE_WIRE, 'utf8'));
  });

test('mutating the caller buffer after the check cannot change the received ALLOW copy',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, adapter } = await harness(t);
    const prepared = adapter.prepare(EXPECTED_SAFE_WIRE, decide('PUBLIC'));
    assert.equal(prepared.result.decision, 'ALLOW');
    assert.notEqual(prepared.release, prepared.callerBytes, 'the sentinel returns its own copy');

    // Rewrite the caller's serialized body with a planted original after the check, before any send.
    // The head is left intact so the sink can still parse the request: the received bytes, not the parse,
    // are what must not change.
    const bodyStart = prepared.callerBytes.indexOf('\r\n\r\n') + 4;
    prepared.callerBytes.fill(0x41, bodyStart);
    prepared.callerBytes.write(PLANTED_PERSON, bodyStart, 'utf8');
    assert.equal(prepared.callerBytes.subarray(0, bodyStart).includes(PLANTED_PERSON), false);
    assert.notDeepEqual(prepared.callerBytes, prepared.release);

    assert.equal((await adapter.send(prepared)).requests, 1);
    assert.equal(sink.receivedBytes, Buffer.byteLength(EXPECTED_SAFE_WIRE, 'utf8'));
    assert.equal(sink.captures[0].includes(PLANTED_PERSON), false);
    assert.deepEqual(sink.captures[0], Buffer.from(EXPECTED_SAFE_WIRE, 'utf8'));
  });

/* ---------- A planted original that upstream misses ---------- */

test('a planted original the upstream detector stack misses is caught independently before any byte is sent',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, adapter } = await harness(t);
    const leaky = serializeWire(`Escalate to ${PLANTED_PERSON} on ${PLANTED_HOST} before the window.`);

    // The primary detector stack genuinely does not know these values. This is a deliberate upstream
    // miss and is NOT counted as candidate-recall success anywhere.
    assert.deepEqual(detectSecrets({ text: leaky, inputRef: 'fixture-wire' }).candidates, []);

    const prepared = adapter.prepare(leaky, decide('PUBLIC'));
    assert.equal(prepared.result.decision, 'BLOCK');
    assert.deepEqual(prepared.result.reasons, ['KNOWN_ORIGINAL_DETECTED']);
    assert.deepEqual(prepared.result.findings.map((finding) => finding.rule).sort(),
      ['planted.host.1', 'planted.person.1']);
    assertNothingSent(sink, (await adapter.send(prepared)).requests);
  });

test('reintroduction during body or metadata serialization, and an encoded variant, produce zero received bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, adapter } = await harness(t);
    const encoded = Buffer.from(`note: ${PLANTED_PERSON}`, 'utf8').toString('base64');
    const cases = [
      // A later composition step reintroduces the planted original into the serialized body.
      ['body', serializeWire(`${SAFE_MESSAGE} Escalate to ${PLANTED_PERSON}.`), []],
      // ...into the serialized metadata.
      ['metadata', serializeWire(SAFE_MESSAGE, [['X-Hylja-Note', PLANTED_PERSON]]), []],
      // ...into metadata in an encoded form the raw bytes never spell out.
      ['encoded', serializeWire(SAFE_MESSAGE, [['X-Hylja-Note', encoded]]), []],
    ];
    for (const [name, wire] of cases) {
      const prepared = adapter.prepare(wire, decide('PUBLIC'));
      assert.equal(prepared.result.decision, 'BLOCK', name);
      assert.ok(prepared.result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), name);
      assert.equal(prepared.release, undefined, name);
      assertNothingSent(sink, (await adapter.send(prepared)).requests);
    }
  });

/* ---------- Every other restrictive outcome ---------- */

test('policy DENIED and HELD results reach the sink as zero bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, adapter } = await harness(t);
    const denied = decide('RESTRICTED');
    assert.equal(denied.state, 'DENIED');
    assert.equal(denied.treatment, 'BLOCK');
    const held = decide('CONFIDENTIAL');
    assert.equal(held.state, 'HELD');
    assert.equal(held.treatment, 'REQUIRE_REVIEW');
    assert.equal(typeof held.decisionRef, 'string');

    for (const decision of [denied, held]) {
      const prepared = adapter.prepare(EXPECTED_SAFE_WIRE, decision);
      assert.equal(prepared.refused, 'policy');
      assert.equal(prepared.result, null);
      assert.equal(prepared.release, undefined);
      assertNothingSent(sink, (await adapter.send(prepared)).requests);
    }
  });

test('outage, opaque bytes, destination/profile mismatch and cross-tenant handle misuse produce zero received bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, adapter } = await harness(t);
    const decision = decide('PUBLIC');
    const outage = sentinelUnavailable();
    assert.deepEqual(outage.reasons, ['SENTINEL_UNAVAILABLE']);

    const cases = [
      // A required final-byte check that cannot run is restrictive, never a pass.
      ['outage', EXPECTED_SAFE_WIRE, { result: outage }, 'SENTINEL_UNAVAILABLE'],
      // Bytes the sentinel cannot decode as UTF-8 text.
      ['opaque-text', Uint8Array.from([0x7b, 0xff, 0xfe, 0x7d]), {}, 'OPAQUE_CONTENT'],
      // Content the sentinel cannot inspect through its bounded decode rounds.
      ['uninspected', serializeWire(`x=${nestedEncoding()}`), {}, 'UNINSPECTED_CONTENT'],
      // The send point observes a different destination/profile than policy authorized.
      ['destination', EXPECTED_SAFE_WIRE, {
        overrides: { destination: { id: 'other-sink.example.invalid', profileDigest: AUTHORIZED.profileDigest } },
      }, 'DESTINATION_MISMATCH'],
      // Another tenant's known-originals handle used in this tenant's check.
      ['cross-tenant', EXPECTED_SAFE_WIRE, { overrides: { known: foreignKnown } },
        'KNOWN_ORIGINALS_SCOPE_MISMATCH'],
    ];
    for (const [name, wire, options, reason] of cases) {
      const prepared = adapter.prepare(wire, decision, options);
      assert.equal(prepared.result.decision, 'BLOCK', name);
      assert.deepEqual(prepared.result.reasons, [reason], name);
      assert.equal(prepared.release, undefined, name);
      assertNothingSent(sink, (await adapter.send(prepared)).requests);
    }
  });

test('no decision, error or regression evidence contains a planted original',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, adapter } = await harness(t);
    const decisions = [decide('PUBLIC'), decide('INTERNAL'), decide('CONFIDENTIAL'), decide('RESTRICTED')];
    const leaky = adapter.prepare(serializeWire(`Escalate to ${PLANTED_PERSON}.`), decisions[0]).result;
    const opaque = adapter.prepare(
      serializeWire(`x=${nestedEncoding()}`), decisions[0],
    ).result;
    const mismatch = adapter.prepare(EXPECTED_SAFE_WIRE, decisions[0], {
      overrides: { destination: { id: 'other-sink.example.invalid', profileDigest: AUTHORIZED.profileDigest } },
    }).result;

    let thrown;
    try {
      // A rejected configuration error must not echo the value that caused it.
      createKnownOriginals(SCOPE_A, SENTINEL_KEY, [
        { kind: 'ORIGINAL', value: PLANTED_PERSON.slice(0, 3), ref: 'planted.person.too-short' },
      ]);
    } catch (error) { thrown = error; }
    assert.ok(thrown instanceof TypeError);

    const evidence = JSON.stringify({
      decisions,
      results: [leaky, opaque, mismatch, sentinelUnavailable()],
      regressions: [leaky.regression, opaque.regression, mismatch.regression],
      error: { name: thrown.name, message: thrown.message },
    });
    for (const planted of [PLANTED_PERSON, PLANTED_PERSON.toLowerCase(), PLANTED_HOST,
      PLANTED_PERSON.slice(0, 6)]) {
      assert.equal(evidence.includes(planted), false, planted);
    }
    assertNothingSent(sink, (await adapter.send({ result: leaky })).requests);
  });

/* ---------- Streaming through the real gate ---------- */

test('streaming releases nothing before completion and a split planted secret produces zero received bytes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, adapter } = await harness(t);
    const decision = decide('PUBLIC');
    const gate = adapter.stream();
    const safeBytes = Buffer.from(EXPECTED_SAFE_WIRE, 'utf8');
    for (let at = 0; at < safeBytes.byteLength; at += 17) {
      assert.deepEqual(gate.push(safeBytes.subarray(at, at + 17)), { accepted: true });
      assert.equal(sink.connections, 0, 'no chunk reaches the sink before completion');
      assert.equal(sink.receivedBytes, 0);
    }
    const completed = gate.end();
    assert.equal(completed.result.decision, 'ALLOW');
    assert.equal(completed.release instanceof Uint8Array, true);
    assert.equal((await adapter.send({
      callerBytes: safeBytes, result: completed.result, release: completed.release,
    })).requests, 1);
    assert.deepEqual(sink.captures[0], Buffer.from(EXPECTED_SAFE_WIRE, 'utf8'));

    // The planted secret is split across chunk boundaries, so no single chunk spells it out.
    const leaky = adapter.stream();
    const leakyBytes = Buffer.from(serializeWire(`Escalate to ${PLANTED_PERSON} now.`), 'utf8');
    for (let at = 0; at < leakyBytes.byteLength; at += 3) {
      assert.deepEqual(leaky.push(leakyBytes.subarray(at, at + 3)), { accepted: true });
      assert.equal(sink.receivedBytes, Buffer.byteLength(EXPECTED_SAFE_WIRE, 'utf8'),
        'the completed stream is still the only thing the sink has');
    }
    const blocked = leaky.end();
    assert.equal(blocked.result.decision, 'BLOCK');
    assert.deepEqual(blocked.result.reasons, ['KNOWN_ORIGINAL_DETECTED']);
    assert.equal(blocked.release, undefined);
    assert.equal((await adapter.send({ callerBytes: leakyBytes, result: blocked.result })).requests, 0);
    // Cumulative counters: a chunk released early would have added connections and bytes here.
    assert.equal(sink.connections, 1);
    assert.equal(sink.receivedBytes, Buffer.byteLength(EXPECTED_SAFE_WIRE, 'utf8'));
    assert.equal(sink.captures.length, 1);
  });

test('a completed safe stream sends only its approved complete-message copy',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, adapter } = await harness(t);
    const gate = adapter.stream();
    const chunks = [
      Buffer.from(EXPECTED_SAFE_WIRE.slice(0, 60), 'utf8'),
      Buffer.from(EXPECTED_SAFE_WIRE.slice(60, 120), 'utf8'),
      Buffer.from(EXPECTED_SAFE_WIRE.slice(120), 'utf8'),
    ];
    const callerBytes = Buffer.concat(chunks);
    for (const chunk of chunks) assert.deepEqual(gate.push(chunk), { accepted: true });
    // Rewrite the caller's chunk buffers after they were pushed.
    for (const chunk of chunks) chunk.fill(0x41);
    Buffer.from(PLANTED_HOST, 'utf8').copy(chunks[2], 0);
    callerBytes.write(PLANTED_HOST, 120, 'utf8');

    const { result, release } = gate.end();
    assert.equal(result.decision, 'ALLOW');
    assert.equal((await adapter.send({ callerBytes, result, release })).requests, 1);
    assert.equal(sink.connections, 1);
    assert.equal(sink.receivedBytes, Buffer.byteLength(EXPECTED_SAFE_WIRE, 'utf8'));
    assert.equal(sink.captures[0].includes(PLANTED_HOST), false);
    assert.deepEqual(sink.captures[0], Buffer.from(EXPECTED_SAFE_WIRE, 'utf8'));
  });
