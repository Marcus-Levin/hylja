// #201 and #218: the complete-text OpenAI request sender under test.
//
// What this proves, precisely: `createOpenAiTextSender` owns translation, the exact private serialized
// ORIGINAL request image (allowlisted fixed metadata and the model included), snapshot-bound whole-image
// classification evidence over that original, the real deterministic SEND policy decision per unit, the
// private per-unit plan, the rebuilt final image when real policy selected MASK for a message unit, the
// real FIXED-WORKER child process sentinel over exactly those final bytes, and exactly one trusted
// transport dispatch. Nothing is ever handed back to a caller that could be replayed: there is no
// READY/prepared handle and no `sendPrepared`.
//
// What it is NOT: an authentication proof (the host boundary, the policy pin, the sentinel key and
// the known-original registration are obvious synthetic fixtures), an OS sandbox or an RSS cap, a
// scoring or enforcement result, a listener, a credential store or a provider client. The transport is
// trusted and this unit cannot prove an arbitrary injected transport honors its contract; the loopback
// sink below is owned by this test file only.
//
// Every value is invented and non-routable (`*.invalid`, loopback, a made-up person and host).
// Assertions carry fixed counts, codes and booleans only: a failing assertion must never print a
// buffer, an exception message or a planted value into the TAP output.
import assert from 'node:assert/strict';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { composeClassification, TRUST_LEVELS } from '../dist/classification.js';
import {
  decidePolicy, digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE,
} from '../dist/policy.js';
import { createOpenAiTextSender, OPENAI_TEXT_SENDER_REFUSALS } from '../dist/openai-text-sender.js';
import { OPENAI_TEXT_REQUEST_ENDPOINT } from '../dist/openai-text-request.js';

/** Host-owned sentinel deadline. A check either answers inside it or is stopped at it. */
const DEADLINE_MS = 10_000;
/** Bound every await this file creates, so a stalled child or socket fails loudly instead of hanging. */
const BOUND_MS = 20_000;
const TEST_TIMEOUT_MS = 60_000;

/* ---------- Planted synthetic originals and the registration fixture ---------- */

const SCOPE = Object.freeze({ tenantRef: 'tenant-keep.invalid', projectRef: 'project-keep.invalid' });
// A dedicated, obviously synthetic sentinel key for this test only. It is not a credential.
const KEY = Uint8Array.from({ length: 32 }, (unused, index) => (index * 11 + 5) & 0xff);
const PLANTED_ORIGINAL = 'avery.synthanon@synthetic-planted.invalid';
const PLANTED_CANARY = 'synthetic-canary-8c17.invalid';
const registration = (entries) => ({ scope: SCOPE, key: KEY, entries });
const BENIGN_ENTRIES = Object.freeze([
  Object.freeze({ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'planted.person.1' }),
  Object.freeze({ kind: 'CANARY', value: PLANTED_CANARY, ref: 'planted.canary.1' }),
]);

/* ---------- Trusted test fixture bindings (not authenticated identities) ---------- */

const SUBJECT = Object.freeze({ principalId: 'principal-keep.invalid', workloadId: 'workload-keep.invalid' });
const CONTEXT = Object.freeze({
  tenantId: SCOPE.tenantRef, projectId: SCOPE.projectRef,
  sessionId: 'session-keep.invalid', purpose: 'fixture-send.invalid',
});
const SOURCE = Object.freeze({ kind: 'tool.result', ref: 'tool-source-keep.invalid', trustZone: 'LOCAL' });
const SOURCE_TRUST = 'TRUSTED';
const SINK = Object.freeze({
  kind: 'model', ref: 'model-sink.example.invalid', trustZone: 'EXTERNAL', profileId: 'keep-sink.invalid',
});
const PROFILE = Object.freeze({
  id: 'keep-sink.invalid', sink: SINK, exposure: 'EXTERNAL',
  permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'INTERNAL',
});
const BUNDLE = Object.freeze({
  ...KNOWN_POLICY_BUNDLE,
  profiles: [PROFILE],
  rules: [{
    id: 'keep-rule.invalid', profileId: PROFILE.id, semanticType: 'PERSON', sensitivities: ['PUBLIC'],
    sourceTrust: [...TRUST_LEVELS], operations: ['SEND'], decision: 'KEEP',
  }],
});
/** The same profile id bound to a different treatment rule, so a non-KEEP decision is real policy. */
const MASK_BUNDLE = Object.freeze({
  ...KNOWN_POLICY_BUNDLE,
  profiles: [PROFILE],
  rules: [{ ...BUNDLE.rules[0], decision: 'MASK' }],
});
const REVIEW_BUNDLE = Object.freeze({
  ...KNOWN_POLICY_BUNDLE,
  profiles: [PROFILE],
  rules: [{ ...BUNDLE.rules[0], decision: 'REQUIRE_REVIEW', reviewTreatments: ['MASK'] }],
});

/** Proof freshness, not authenticity: `createInteractionEnvelope` checks the interval, not the signer. */
function proof(ref) {
  const now = Date.now();
  return Object.freeze({
    ref, issuedAt: new Date(now - 30_000).toISOString(), expiresAt: new Date(now + 120_000).toISOString(),
  });
}
const BOUNDARY = Object.freeze({
  authenticated: {
    subject: SUBJECT, context: CONTEXT,
    identityProof: proof('identity-keep.invalid'), requestProof: proof('request-keep.invalid'),
  },
  observed: {
    source: SOURCE, destination: SINK,
    sourceProof: proof('source-keep.invalid'), routeProof: proof('route-keep.invalid'),
  },
});

/* ---------- The accepted request and the independently declared expected wire image ---------- */

const MODEL = 'fixture-model-keep-sender';
const SAFE_SYSTEM_TEXT = 'You are a synthetic fixture assistant.';
// Literal protocol and port, plus astral and combining Unicode: if any stage rewrote, folded or dropped
// one of these, the independently declared image below would not match what the sink received.
const SAFE_USER_TEXT = 'Diagnose café \u{1F600} https port 443 now.';
const requestBody = (messages, extra = {}) => JSON.stringify({ model: MODEL, messages, ...extra });
const SAFE_REQUEST_BODY = requestBody([
  { role: 'system', content: SAFE_SYSTEM_TEXT },
  { role: 'user', content: SAFE_USER_TEXT },
]);
const LEAKY_REQUEST_BODY = requestBody([
  { role: 'user', content: `Escalate to ${PLANTED_ORIGINAL} before the window opens.` },
]);
const CANARY_REQUEST_BODY = requestBody([{ role: 'user', content: 'ping' }], { model: PLANTED_CANARY });

/** The image the sender owns, declared here as a literal a reviewer can read without running anything. */
const EXPECTED_BODY = '{"model":"fixture-model-keep-sender","messages":['
  + '{"role":"system","content":"You are a synthetic fixture assistant."},'
  + '{"role":"user","content":"Diagnose café \u{1F600} https port 443 now."}]}';
const EXPECTED_BODY_BYTES = Buffer.byteLength(EXPECTED_BODY, 'utf8');

/* ---------- The trusted inspection fixture: whole-image, snapshot-bound, per unit ---------- */

function classificationFor(binding) {
  return composeClassification({
    detectorEvidence: [{
      version: 1, id: 'detector-keep.invalid', status: 'FOUND',
      provenance: {
        inputRef: 'field-keep.invalid', producerId: 'detector-keep.invalid', producerVersion: 'pack-keep-1',
      },
      claim: { semanticType: 'PERSON', sensitivity: 'PUBLIC' },
    }],
  }, { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust: SOURCE_TRUST });
}

/** One finding per unit the sender declared, bound to the sender's own image digest and interaction. */
function inspectWholeImage(_image, binding) {
  return {
    version: 1,
    interactionRef: binding.interactionRef,
    imageDigest: binding.imageDigest,
    coverage: 'COMPLETE',
    remainder: 'NONE',
    units: binding.units.map((unit) => ({
      unitRef: unit.unitRef,
      classificationDigest: digestClassification(classificationFor(binding)),
      classification: classificationFor(binding),
    })),
  };
}

/* ---------- A real loopback sink on an OS-assigned ephemeral port ---------- */

function bounded(promise, label) {
  let timer;
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`deadline exceeded: ${label}`)), BOUND_MS);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

async function startSink(order = []) {
  const open = new Set();
  const captures = [];
  let connections = 0;
  let receivedBytes = 0;
  let writes = 0;
  let prepared = null;
  const dispose = () => {
    const owned = prepared;
    prepared = null;
    if (owned !== null) { try { owned.socket.destroy(); } catch { /* already closed */ } }
  };

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

  return {
    get connections() { return connections; },
    get receivedBytes() { return receivedBytes; },
    get captures() { return captures; },
    /** Fixed labels of the real effects on this sink, in the order they actually happened. */
    get order() { return order; },
    get writes() { return writes; },
    /**
     * Readiness: open the one real connection, confirm it, install the reply, error and close
     * listeners and capture the socket's own write and end. It sends no byte.
     */
    async waitUntilReady() {
      dispose();
      const socket = net.connect(address.port, '127.0.0.1');
      open.add(socket);
      socket.on('error', () => {});
      // Reading the response is also what puts the socket in flowing mode, so the listener belongs
      // here, in readiness, before any byte exists on it.
      const answered = [];
      socket.on('data', (chunk) => answered.push(chunk));
      await bounded(new Promise((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      }), 'loopback connect');
      const writeMethod = socket.write;
      const endMethod = socket.end;
      prepared = {
        socket, answered,
        write: (bytes) => { writes += 1; order.push('write'); writeMethod.call(socket, bytes); },
        end: () => { endMethod.call(socket); },
      };
    },
    async write(bytes) {
      const owned = prepared;
      prepared = null;
      if (owned === null) throw new Error('the sink transport was never prepared');
      // Synchronous, before this function's first `await`: the effect happens in the caller's own turn.
      owned.write(bytes);
      owned.end();
      await bounded(new Promise((resolve) => owned.socket.once('close', resolve)), 'loopback response');
      open.delete(owned.socket);
      assert.equal(Buffer.concat(owned.answered).toString('latin1').startsWith('HTTP/1.1 204'), true,
        'the sink answered the request it received');
    },
    /** A socket prepared and never dispatched is destroyed here, from the send `finally`. */
    dispose,
    async close() {
      dispose();
      for (const socket of open) socket.destroy();
      await bounded(new Promise((resolve) => server.close(() => resolve())), 'sink shutdown');
    },
  };
}

/* ---------- The trusted host under test ---------- */

const PROFILE_DIGEST = createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex');
const OTHER_PROFILE_DIGEST = createHash('sha256')
  .update(JSON.stringify({ ...PROFILE, maxCleartextSensitivity: 'RESTRICTED' })).digest('hex');

/**
 * The whole trusted host, with only the members the sender surface declares. The transport writes to
 * the real loopback sink; every other member is an obviously synthetic fixture, not an identity.
 */
function createHost(sink, options = {}) {
  const dispatch = [];
  const observations = [];
  let calls = 0;
  const bundle = options.policyBundle ?? BUNDLE;
  const commit = options.commit ?? { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(bundle) };
  for (const entry of options.observations ?? [{ destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST }, commit }]) {
    observations.push(entry);
  }

  const host = {
    boundary: options.boundary ?? BOUNDARY,
    sourceTrust: SOURCE_TRUST,
    policyBundle: bundle,
    scope: options.scope ?? SCOPE,
    known: options.known === undefined ? registration(BENIGN_ENTRIES) : options.known,
    sentinel: options.sentinel ?? { deadlineMs: DEADLINE_MS },
    inspectOriginal: options.inspect ?? inspectWholeImage,
    sendPoint: {
      // Queued observations: the first call is the one the check is made against, the second is what
      // the send point reports immediately before dispatch, and later calls clamp to the last entry.
      observe: () => observations[Math.min(calls++, observations.length - 1)],
      // Readiness owns the sink's real connection: it opens it, confirms it, installs the reply
      // listener and sends nothing. Only a genuinely connectionless capture (no sink at all) has
      // nothing to prepare, and only there is a no-op the whole shape of this seam.
      waitUntilReady: options.waitUntilReady ?? (async () => {
        if (sink !== null) await sink.waitUntilReady();
      }),
      sendExact: async (image) => {
        dispatch.push(Buffer.from(image));
        if (sink !== null) await sink.write(image);
      },
    },
  };
  for (const [key, value] of Object.entries(options.host ?? {})) host[key] = value;
  return { host, dispatch };
}

async function harness(t, options = {}) {
  const sink = options.sink === null ? null : await startSink();
  if (sink !== null) t.after(() => sink.close());
  const { host, dispatch } = createHost(sink, options);
  // `options.create` selects the sender factory. It exists so the instrumentation section below can
  // drive a FRESH sender module instance; every other test keeps the one imported at the top.
  const create = options.create ?? createOpenAiTextSender;
  const owner = create(host);
  return {
    sink, host, dispatch,
    sender: {
      // The outer send `finally` this harness owns: whatever the sender decided, a socket prepared
      // and never dispatched is destroyed here rather than left to `t.after`.
      send: (input) => owner.send(input).finally(() => { if (sink !== null) sink.dispose(); }),
      cancel: () => { owner.cancel(); },
      get state() { return owner.state; },
    },
  };
}

/** The whole withholding invariant in one helper: no dispatch, no connection, no byte, no capture. */
const assertNothingSent = (sink, dispatch) => {
  assert.equal(dispatch.length, 0, 'the transport was invoked zero times');
  if (sink === null) return;
  assert.equal(sink.connections, 0, 'the sink accepted no connection');
  assert.equal(sink.receivedBytes, 0, 'the sink received zero bytes');
  assert.equal(sink.captures.length, 0);
};

/**
 * The same invariant for a send whose READINESS already ran: readiness owns the connection and sends
 * nothing, so what a withheld dispatch must leave behind is no byte, no capture and no native write -
 * never "no connection", which is only true of a refusal taken before readiness.
 */
const assertNoByteSent = (sink, dispatch) => {
  assert.equal(dispatch.length, 0, 'the transport was invoked zero times');
  if (sink === null) return;
  assert.equal(sink.receivedBytes, 0, 'the sink received zero bytes');
  assert.equal(sink.captures.length, 0, 'no complete request reached the sink');
  assert.equal(sink.writes, 0, 'the native write never happened');
  assert.equal(sink.order.includes('write'), false, 'no write label was recorded at all');
};

/* ---------- The API surface ---------- */

test('the sender exposes send, cancel and state, and no prepared or replayable send handle',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sender } = await harness(t);
    assert.deepEqual(Object.keys(sender).sort(), ['cancel', 'send', 'state']);
    assert.equal(sender.state, 'IDLE');
    for (const name of ['prepare', 'sendPrepared', 'sendExact', 'dispatch', 'release', 'bytes', 'ready']) {
      assert.equal(name in sender, false, `${name} is not part of the sender surface`);
    }
    assert.equal(typeof sender.send, 'function');
    assert.equal(typeof sender.cancel, 'function');
    // The published refusal vocabulary is a closed, fixed list of codes.
    assert.equal(OPENAI_TEXT_SENDER_REFUSALS.includes('SENTINEL_BLOCKED'), true);
    assert.equal(OPENAI_TEXT_SENDER_REFUSALS.includes('SENDER_BUSY'), true);
  });

/* ---------- The accepted path ---------- */

test('an accepted, fully covered text request is sent exactly once as the independently declared image',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, sender, dispatch } = await harness(t);
    assert.equal(sender.state, 'IDLE');

    const result = await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'accepted send');
    assert.deepEqual(result, { status: 'SENT' });
    assert.equal(sender.state, 'IDLE');

    assert.equal(dispatch.length, 1, 'exactly one trusted transport dispatch');
    assert.equal(sink.connections, 1);
    assert.equal(sink.captures.length, 1);
    const received = sink.captures[0];
    // Byte-for-byte, compared as a boolean: a failing diff must not print the image into TAP output.
    assert.equal(received.equals(expectedImage()), true, 'the sink received the declared image');
    // Literal protocol, literal port, astral and combining Unicode and message order all survive.
    const body = received.subarray(received.indexOf('\r\n\r\n') + 4).toString('utf8');
    assert.equal(body, EXPECTED_BODY);
    assert.equal(body.includes('https'), true);
    assert.equal(body.includes('443'), true);
    assert.equal(body.indexOf('role":"system') < body.indexOf('role":"user'), true);
    // The fixed, allowlisted metadata is part of the checked image and was not rewritten.
    const head = received.subarray(0, received.indexOf('\r\n\r\n') + 2).toString('latin1');
    assert.equal(head.startsWith(`POST ${OPENAI_TEXT_REQUEST_ENDPOINT} HTTP/1.1\r\n`), true);
    assert.equal(head.includes(`Host: ${SINK.ref}\r\n`), true);
    assert.equal(head.includes('Content-Type: application/json; charset=utf-8\r\n'), true);
    assert.equal(head.includes(`Content-Length: ${EXPECTED_BODY_BYTES}\r\n`), true);
    // Nothing about the sent request escapes as a replayable handle: the result is a bare status.
    assert.deepEqual(Object.keys(result), ['status']);
  });

/** The declared image, built here from literals only - never from the sender's own serializer. */
function expectedImage() {
  const head = [
    `POST ${OPENAI_TEXT_REQUEST_ENDPOINT} HTTP/1.1`,
    `Host: ${SINK.ref}`,
    'Content-Type: application/json; charset=utf-8',
    `Content-Length: ${EXPECTED_BODY_BYTES}`,
    '', '',
  ].join('\r\n');
  return Buffer.from(`${head}${EXPECTED_BODY}`, 'utf8');
}

test('an explicit stream:false request produces the same complete, non-streamed image',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, sender } = await harness(t);
    const body = requestBody([
      { role: 'system', content: SAFE_SYSTEM_TEXT },
      { role: 'user', content: SAFE_USER_TEXT },
    ], { stream: false });
    assert.deepEqual(await bounded(sender.send({ endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body }), 'stream false send'),
      { status: 'SENT' });
    assert.equal(sink.captures[0].equals(expectedImage()), true);
  });

test('a later caller mutation and any mutation of the inspection copy change no released byte',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    let dispatched = 0;
    const { sink, sender } = await harness(t, {
      inspect: (image, binding) => {
        // The callback is handed its OWN copy: scribbling on it cannot reach the bytes the sender
        // sends. Rewriting the caller's own input object during the async inspection proves the image
        // was already snapshotted before any await.
        image.fill(0x41);
        input.endpoint = '/v1/responses';
        input.body = requestBody([{ role: 'user', content: PLANTED_ORIGINAL }]);
        dispatched += 1;
        return inspectWholeImage(image, binding);
      },
    });
    const input = { endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY };
    assert.deepEqual(await bounded(sender.send(input), 'mutating inspection'), { status: 'SENT' });
    assert.equal(dispatched, 1);
    assert.equal(sink.captures[0].equals(expectedImage()), true, 'the released image is the declared image');
    assert.equal(sink.captures[0].includes(PLANTED_ORIGINAL), false, 'no planted value reached the sink');
  });

/* ---------- Malformed, unsupported and streaming input ---------- */

test('malformed, unsupported, oversized and streaming input refuses without a dispatch',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, sender, dispatch } = await harness(t);
    const cases = [
      ['malformed json', { endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: '{"model":"m","messages":[' }, 'MALFORMED_JSON'],
      ['unsupported endpoint', { endpoint: '/v1/responses', body: SAFE_REQUEST_BODY }, 'ENDPOINT_NOT_SUPPORTED'],
      ['already parsed body', { endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: { model: 'm', messages: [] } }, 'BODY_NOT_TEXT'],
      ['streaming', { endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: requestBody([{ role: 'user', content: 'hi' }], { stream: true }) }, 'STREAMING_NOT_SUPPORTED'],
      ['tools', { endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: 'hi' }], tools: [] }) }, 'UNSUPPORTED_TOOLS'],
      ['no messages', { endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: requestBody([]) }, 'NO_MESSAGES'],
      ['too many messages', { endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: requestBody(Array.from({ length: 65 }, () => ({ role: 'user', content: 'hi' }))) }, 'TOO_MANY_MESSAGES'],
      ['duplicate key', { endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: '{"model":"a","model":"b","messages":[]}' }, 'AMBIGUOUS_BODY'],
      // A caller cannot smuggle authority, a destination, a profile or a policy through the payload.
      ['extra own key', { endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY, profileId: 'attacker.invalid' }, 'INVALID_ARGUMENTS'],
      ['not an object', 'not-an-object', 'INVALID_ARGUMENTS'],
    ];
    for (const [name, input, code] of cases) {
      assert.deepEqual(await bounded(sender.send(input), name), { status: 'REFUSED', code }, name);
    }
    assertNothingSent(sink, dispatch);
    assert.equal(sender.state, 'IDLE');
  });

/* ---------- Policy: only a real SELECTED KEEP releases ---------- */

test('a non-KEEP treatment, a held review and a foreign or stale boundary all refuse without a dispatch',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const sink = await startSink();
    t.after(() => sink.close());

    for (const [name, options, code] of [
      // METADATA and MODEL units are never masked, so a MASK decision over the first unit still refuses.
      ['METADATA unit selected MASK', { policyBundle: MASK_BUNDLE }, 'POLICY_NOT_KEEP'],
      ['REQUIRE_REVIEW', { policyBundle: REVIEW_BUNDLE }, 'POLICY_HELD'],
      ['stale policy pin', { commit: { ...KNOWN_POLICY_BUNDLE, digest: OTHER_PROFILE_DIGEST } }, 'POLICY_DENIED'],
      ['foreign boundary destination', {
        boundary: {
          ...BOUNDARY,
          observed: {
            ...BOUNDARY.observed,
            destination: { ...SINK, profileId: 'foreign-sink.invalid' },
            routeProof: proof('route-foreign.invalid'),
          },
        },
      }, 'POLICY_DENIED'],
      ['foreign tenant scope', { scope: { tenantRef: 'tenant-other.invalid', projectRef: SCOPE.projectRef } }, 'SCOPE_REFUSED'],
    ]) {
      const point = await harness(t, { ...options, sink });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
      }), name), { status: 'REFUSED', code }, name);
      assertNothingSent(sink, point.dispatch);
      assert.equal(point.sender.state, 'IDLE', name);
    }
  });

/* ---------- The snapshot-bound inspection handoff ---------- */

test('empty, absent, partial or unclassified-inspection results never authorize',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const sink = await startSink();
    t.after(() => sink.close());

    const whole = (_image, binding) => inspectWholeImage(_image, binding);
    const cases = [
      ['empty findings', (_image, binding) => ({ ...whole(_image, binding), units: [] })],
      ['missing one unit', (_image, binding) => {
        const result = whole(_image, binding);
        return { ...result, units: result.units.slice(0, -1) };
      }],
      ['duplicate unit', (_image, binding) => {
        const result = whole(_image, binding);
        return { ...result, units: [...result.units, result.units[0]] };
      }],
      ['unknown extra unit', (_image, binding) => {
        const result = whole(_image, binding);
        return { ...result, units: [...result.units, { ...result.units[0], unitRef: 'invented-unit' }] };
      }],
      ['remainder not cleared', (_image, binding) => ({ ...whole(_image, binding), remainder: 'UNKNOWN' })],
      ['caller image digest', (_image, binding) => ({ ...whole(_image, binding), imageDigest: '0'.repeat(64) })],
      ['caller interaction', (_image, binding) => ({ ...whole(_image, binding), interactionRef: 'invented-interaction.invalid' })],
      ['substituted classification', (_image, binding) => {
        // A pinned digest that does not match the record handed back is a substitution, not evidence.
        const result = whole(_image, binding);
        return { ...result, units: result.units.map((unit) => ({ ...unit, classificationDigest: '1'.repeat(64) })) };
      }],
      ['unresolved remainder', (_image, binding) => {
        const result = whole(_image, binding);
        return {
          ...result,
          units: result.units.map((unit) => ({
            unitRef: unit.unitRef,
            classificationDigest: digestClassification(unit.classification),
            classification: {
              ...unit.classification, status: 'UNRESOLVED',
              semanticType: 'UNKNOWN', sensitivity: 'UNKNOWN', reasons: ['synthetic.unresolved'],
              evidence: [],
            },
          })),
        };
      }],
      ['detector absence is not clearance', (_image, binding) => {
        // A model-only PUBLIC judgment with no detector evidence stays unresolved.
        const result = whole(_image, binding);
        const semanticOnly = composeClassification({
          semanticJudgments: [{
            version: 1, id: 'judge-keep.invalid', status: 'FOUND',
            provenance: {
              inputRef: 'field-keep.invalid', producerId: 'judge-keep.invalid', producerVersion: 'judge-keep-1',
              questionSetVersion: 'q-keep-1', modelId: 'model-judge.invalid',
            },
            claim: { semanticType: 'PERSON', sensitivity: 'PUBLIC' },
          }],
        }, { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust: SOURCE_TRUST });
        return {
          ...result,
          units: result.units.map((unit) => ({
            unitRef: unit.unitRef,
            classificationDigest: digestClassification(semanticOnly),
            classification: semanticOnly,
          })),
        };
      }],
      ['inspection throws', () => { throw new Error(`inspection failed: ${PLANTED_ORIGINAL}`); }],
      ['inspection returns nothing', () => undefined],
      ['unknown own key', (_image, binding) => ({ ...whole(_image, binding), clearance: 'PUBLIC' })],
    ];

    for (const [name, inspect] of cases) {
      const point = await harness(t, { inspect, sink });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
      }), name), { status: 'REFUSED', code: 'INSPECTION_REFUSED' }, name);
      assertNothingSent(sink, point.dispatch);
    }
  });

test('every unit of the whole image is inspected, metadata and model included',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    let seen = null;
    const { sender, dispatch } = await harness(t, {
      sink: null,
      inspect: (image, binding) => {
        seen = binding;
        return inspectWholeImage(image, binding);
      },
    });
    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'coverage'), { status: 'SENT' });
    assert.equal(seen.version, 1);
    assert.equal(/^[0-9a-f]{64}$/u.test(seen.imageDigest), true, 'the binding carries the sender image digest');
    // METADATA (the fixed header block), MODEL, then one unit per message in wire order.
    assert.deepEqual(seen.units.map((unit) => unit.kind), ['METADATA', 'MODEL', 'MESSAGE', 'MESSAGE']);
    assert.equal(new Set(seen.units.map((unit) => unit.unitRef)).size, seen.units.length,
      'each unit carries its own distinct opaque reference');
    for (const unit of seen.units) assert.equal(/^[0-9a-f]{64}$/u.test(unit.digest), true);
    assert.equal(dispatch.length, 1);
  });

/* ---------- The real sentinel child and the transport ---------- */

test('a planted original in the model or a message is refused by the real child process',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    for (const [name, body] of [
      ['planted original', LEAKY_REQUEST_BODY],
      ['planted canary in the model', CANARY_REQUEST_BODY],
    ]) {
      const { sink, sender, dispatch } = await harness(t);
      assert.deepEqual(await bounded(sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body,
      }), name), { status: 'REFUSED', code: 'SENTINEL_BLOCKED' }, name);
      assertNothingSent(sink, dispatch);
      assert.equal(sender.state, 'IDLE', name);
    }
  });

test('a sentinel failure and an unusable runner configuration invoke the transport zero times',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const sink = await startSink();
    t.after(() => sink.close());
    for (const [name, options] of [
      ['deadline below the module floor', { sentinel: { deadlineMs: 1 } }],
      ['unsupported runner key', { sentinel: { deadlineMs: DEADLINE_MS, signal: null } }],
      ['foreign known-original scope', {
        known: { scope: { tenantRef: 'tenant-other.invalid', projectRef: SCOPE.projectRef }, key: KEY, entries: [] },
      }],
    ]) {
      const point = await harness(t, { ...options, sink });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
      }), name), { status: 'REFUSED', code: 'SENTINEL_BLOCKED' }, name);
      assertNothingSent(sink, point.dispatch);
      assert.equal(point.sender.state, 'IDLE', name);
    }
  });

test('a route or profile that changes before dispatch refuses with no await in between',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const sink = await startSink();
    t.after(() => sink.close());
    const commit = { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) };
    for (const [name, second, code] of [
      ['route changed', { destination: { id: 'other-sink.example.invalid', profileDigest: PROFILE_DIGEST }, commit }, 'ROUTE_CHANGED'],
      ['profile changed', { destination: { id: SINK.ref, profileDigest: OTHER_PROFILE_DIGEST }, commit }, 'ROUTE_CHANGED'],
      ['policy commit changed', {
        destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST },
        commit: { ...KNOWN_POLICY_BUNDLE, digest: OTHER_PROFILE_DIGEST },
      }, 'POLICY_STALE'],
    ]) {
      // Observation 0 is what the check is made against; observation 1 is what the send point reports
      // immediately before dispatch, in the same synchronous turn as the dispatch.
      const point = await harness(t, {
        sink, observations: [{ destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST }, commit }, second],
      });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
      }), name), { status: 'REFUSED', code }, name);
      assertNothingSent(sink, point.dispatch);
    }
  });

test('a cancellation raised inside the last host observation withholds the dispatch',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const commit = { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) };
    const observation = Object.freeze({ destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST }, commit });

    // Positive control: the same host and the same queued second observation, cancelling nothing. One
    // real fixed-worker check, one real loopback capture, exactly the independently declared image.
    const safe = await harness(t, { observations: [observation, observation] });
    assert.deepEqual(await bounded(safe.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'final observation without a cancel'), { status: 'SENT' });
    assert.equal(safe.dispatch.length, 1);
    assert.equal(safe.sink.captures.length, 1);
    assert.equal(safe.sink.captures[0].equals(expectedImage()), true);
    assert.equal(safe.sender.state, 'IDLE');

    // The send point cancels from inside the last observation it returns. Sticky cancellation is read
    // again AFTER that callback, so the transport is still never invoked and nothing reaches the sink.
    const sink = await startSink();
    t.after(() => sink.close());
    const { host, dispatch } = createHost(sink, { observations: [observation, observation] });
    const transport = host.sendPoint;
    const owner = { sender: null };
    let calls = 0;
    host.sendPoint = Object.freeze({
      waitUntilReady: transport.waitUntilReady,
      observe: () => {
        calls += 1;
        if (calls === 2) owner.sender.cancel();
        return observation;
      },
      sendExact: transport.sendExact,
    });
    const sender = createOpenAiTextSender(host);
    owner.sender = sender;
    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'cancelled inside the final observation'), { status: 'REFUSED', code: 'CANCELLED' });
    assert.equal(calls, 2, 'the refusal came after the final observation, not before it');
    assert.equal(sender.state, 'CANCELLED');
    assertNoByteSent(sink, dispatch);
    // Readiness ran and opened the connection, so the cancellation is not explained by never having
    // prepared a transport: a connection existed and still no byte ever crossed it.
    assert.equal(sink.connections, 1, 'readiness opened the one connection this transport owns');
  });

test('the migrated real transport writes in its first synchronous turn, never after a queued cancel',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const commit = { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) };
    const observation = Object.freeze({ destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST }, commit });
    const send = (sender) => sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    });

    /* Case 1: a cancellation queued from the LAST observation. Readiness has already opened the one
       real connection, so the counters below cannot be explained by never having prepared one - and
       the fixed-label order shows the native write never followed the cancellation. */
    {
      const sink = await startSink();
      t.after(() => sink.close());
      const { host, dispatch } = createHost(sink, { observations: [observation, observation] });
      const accepted = host.sendPoint;
      const owner = { sender: null };
      let calls = 0;
      host.sendPoint = Object.freeze({
        waitUntilReady: accepted.waitUntilReady,
        observe: () => {
          calls += 1;
          if (calls === 2) { sink.order.push('cancel'); owner.sender.cancel(); }
          return observation;
        },
        sendExact: accepted.sendExact,
      });
      const sender = createOpenAiTextSender(host);
      owner.sender = sender;
      assert.deepEqual(await bounded(send(sender), 'cancel queued from the last observation'),
        { status: 'REFUSED', code: 'CANCELLED' });
      assert.equal(calls, 2, 'the refusal came after the final observation');
      assert.deepEqual(sink.order, ['cancel'], 'no native write was ever dispatched after the cancellation');
      assert.equal(sink.connections, 1, 'readiness opened exactly one real connection');
      assertNoByteSent(sink, dispatch);
    }

    /* Case 2: the same transport with nothing queued. One connected native write, one exact request
       off that connection, and the write label is the first and only effect label. */
    {
      const point = await harness(t);
      const sink = point.sink;
      assert.deepEqual(await bounded(send(point.sender), 'live control'), { status: 'SENT' });
      assert.deepEqual(sink.order, ['write'], 'the live control performed exactly one native write');
      assert.equal(sink.connections, 1, 'exactly one real connection');
      assert.equal(sink.captures.length, 1, 'and exactly one complete request off it');
      assert.equal(sink.captures[0].equals(expectedImage()), true, 'the declared image, byte for byte');
    }

    /* Case 3: a cancellation queued DURING readiness, after the real child ALLOWed. Readiness
       connects but sends nothing, so zero writes, zero requests and zero connections. */
    {
      const owner = { sender: null };
      let order = null;
      const point = await harness(t, {
        waitUntilReady: async () => {
          point.sink.order.push('cancel');
          order = point.sink.order;
          owner.sender.cancel();
        },
      });
      owner.sender = point.sender;
      const sink = point.sink;
      assert.deepEqual(await bounded(send(point.sender), 'cancel during readiness'),
        { status: 'REFUSED', code: 'CANCELLED' });
      assert.deepEqual(order, ['cancel'], 'readiness dispatched no native write');
      assert.equal(sink.connections, 0, 'and opened no connection at all');
      assertNoByteSent(sink, point.dispatch);
      assert.equal(point.sender.state, 'CANCELLED');
    }

    /* Case 4: the ordering claim itself, with no sender in the way. The write happens inside the
       call, so a cancel queued in the SAME turn by the caller lands strictly after it. This is the
       observation a "no deferred write" claim needs: a real effect, then the queued callback. */
    {
      const sink = await startSink();
      t.after(() => sink.close());
      await bounded(sink.waitUntilReady(), 'direct readiness');
      const pending = sink.write(Buffer.from(expectedImage(), 'utf8'));
      sink.order.push('cancel');
      await bounded(pending, 'direct exchange');
      assert.deepEqual(sink.order, ['write', 'cancel'], 'the native write precedes a cancel queued after it');
      assert.equal(sink.captures.length, 1, 'the exact request really crossed the wire');
    }
  });

test('an accepted transport is captured, so a send-point Proxy get trap cannot run at dispatch',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const sink = await startSink();
    t.after(() => sink.close());
    const { host, dispatch } = createHost(sink);
    const owner = { sender: null };
    let methodReads = 0;
    // A supported Proxy send point: exactly the two declared own data properties, so it is accepted
    // like any other host. Its `get` trap cancels the sender the first time the transport method is
    // read back off it. Reading that method at the dispatch point is a host callback after the last
    // guard, so the accepted function must be captured during validation and invoked from there.
    host.sendPoint = new Proxy(host.sendPoint, {
      get(object, key, receiver) {
        if (key === 'sendExact') {
          methodReads += 1;
          if (owner.sender !== null) owner.sender.cancel();
        }
        return Reflect.get(object, key, receiver);
      },
    });
    const sender = createOpenAiTextSender(host);
    owner.sender = sender;
    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'proxy send point'), { status: 'SENT' });
    assert.equal(methodReads, 0, 'the accepted transport method was never looked up again');
    assert.equal(sender.state, 'IDLE', 'no host callback cancelled this sender after the guards');
    assert.equal(dispatch.length, 1, 'exactly one trusted transport dispatch');
    assert.equal(sink.connections, 1);
    assert.equal(sink.captures.length, 1);
    assert.equal(sink.captures[0].equals(expectedImage()), true, 'the sink received the declared image');
  });

test('a captured transport keeps its own receiver and is not retargeted by a later method swap',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const commit = { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) };
    const observation = Object.freeze({ destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST }, commit });
    let observations = 0;
    let receiverPreserved = true;
    let released = null;
    // Exactly the two declared own data properties. Every host state these methods use lives in this
    // closure, so the only way `this` can be wrong is a lost receiver.
    const sendPoint = {
      observe() { if (this !== sendPoint) receiverPreserved = false; observations += 1; return observation; },
      async waitUntilReady() { if (this !== sendPoint) receiverPreserved = false; },
      async sendExact(image) { if (this !== sendPoint) receiverPreserved = false; released = Buffer.from(image); },
    };
    const point = await harness(t, { sink: null, host: { sendPoint } });
    // A host that replaces its own transport method after construction does not retarget this sender.
    let swapped = 0;
    sendPoint.sendExact = async () => { swapped += 1; };
    assert.deepEqual(await bounded(point.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'captured transport'), { status: 'SENT' });
    assert.equal(receiverPreserved, true, 'each captured method ran on the send point it was accepted on');
    assert.equal(observations, 2, 'the route is still observed fresh for the check and at the dispatch');
    assert.equal(swapped, 0, 'the replacement installed after construction was never invoked');
    assert.equal(released.equals(expectedImage()), true, 'the captured transport sent the declared image');
    assert.equal(point.dispatch.length, 0, 'the replaced method is not what dispatched');
    assert.equal(point.sender.state, 'IDLE');
  });

test('readiness is awaited only after the real child ALLOWs, and every guard is re-read after it',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const commit = { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) };
    const observation = Object.freeze({ destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST }, commit });
    const otherRoute = Object.freeze({
      destination: { id: 'other-sink.invalid', profileDigest: PROFILE_DIGEST }, commit,
    });
    const otherCommit = Object.freeze({
      destination: observation.destination,
      commit: { ...commit, version: 'policy-draft/9999' },
    });

    /* Readiness never runs on an upstream refusal: an unresolved inspection and a real child block
       both withhold before any transport is prepared. */
    for (const [name, options, body] of [
      ['unresolved inspection', { inspect: () => null }, SAFE_REQUEST_BODY],
      ['real child block', { known: registration([PLANTED_ORIGINAL]) }, LEAKY_REQUEST_BODY],
    ]) {
      let ready = 0;
      const point = await harness(t, {
        ...options, waitUntilReady: async () => { ready += 1; },
      });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body,
      }), name), { status: 'REFUSED', code: name === 'real child block' ? 'SENTINEL_BLOCKED' : 'INSPECTION_REFUSED' },
      name);
      assert.equal(ready, 0, `${name}: readiness was never reached`);
      assertNothingSent(point.sink, point.dispatch);
    }

    /* What readiness may invalidate: a route, a commit, cancellation, or readiness itself failing.
       Every one withholds the dispatch, and the real sink saw no byte. */
    const owner = { sender: null };
    for (const [name, observations, ready, code] of [
      ['route changed while ready', [observation, otherRoute], async () => {}, 'ROUTE_CHANGED'],
      ['commit changed while ready', [observation, otherCommit], async () => {}, 'POLICY_STALE'],
      ['cancelled while ready', [observation, observation], function readyCancel() {
        owner.sender.cancel();
      }, 'CANCELLED'],
      ['readiness refused', [observation, observation], async () => {
        throw new Error(`not ready: ${PLANTED_ORIGINAL}`);
      }, 'DISPATCH_FAILED'],
    ]) {
      const sink = await startSink();
      t.after(() => sink.close());
      let prepared = 0;
      const point = await harness(t, {
        sink, observations, waitUntilReady: async () => { prepared += 1; await ready(); },
      });
      owner.sender = point.sender;
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
      }), name), { status: 'REFUSED', code }, name);
      assert.equal(prepared, 1, `${name}: readiness ran exactly once, after the child ALLOWed`);
      assertNothingSent(sink, point.dispatch);
      assert.equal(sink.captures.length, 0, `${name}: not one byte reached the real sink`);
      assert.equal(point.sender.state, name === 'cancelled while ready' ? 'CANCELLED' : 'IDLE', name);
    }

    /* The positive control on the same harness shape: readiness that resolves changes nothing else. */
    const control = await harness(t, { observations: [observation, observation] });
    assert.deepEqual(await bounded(control.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'ready control'), { status: 'SENT' });
    assert.equal(control.dispatch.length, 1);
    assert.equal(control.sink.captures[0].equals(expectedImage()), true);
  });

test('boundary evidence that expires during a finite inspection never authorizes a dispatch',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // One proof window, and the real elapsed time this fixture spends inside the trusted inspection
    // under it. Nothing here is stubbed: the envelope, the sender and the expiry check all read the
    // same real `Date.now()`, and time only ever moves forward, so this cannot flake the other way.
    const PROOF_WINDOW_MS = 200;
    const INSPECTION_MS = 600;
    const spinTo = (deadline) => {
      for (let now = Date.now(); now < deadline; now = Date.now()) { /* finite real inspection */ }
    };

    for (const [name, windowMs, result] of [
      ['expired before the dispatch', PROOF_WINDOW_MS, { status: 'REFUSED', code: 'INTERACTION_REFUSED' }],
      ['still current at the dispatch', 60_000, { status: 'SENT' }],
    ]) {
      // Initially VALID evidence in both cases: issued now, expiring `windowMs` from now.
      const issuedAt = Date.now();
      const fresh = (ref) => Object.freeze({
        ref,
        issuedAt: new Date(issuedAt).toISOString(),
        expiresAt: new Date(issuedAt + windowMs).toISOString(),
      });
      const boundary = Object.freeze({
        authenticated: {
          ...BOUNDARY.authenticated,
          identityProof: fresh('identity-window.invalid'), requestProof: fresh('request-window.invalid'),
        },
        observed: {
          ...BOUNDARY.observed,
          sourceProof: fresh('source-window.invalid'), routeProof: fresh('route-window.invalid'),
        },
      });
      const point = await harness(t, {
        boundary,
        inspect: (image, binding) => {
          spinTo(issuedAt + INSPECTION_MS);
          return inspectWholeImage(image, binding);
        },
      });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
      }), name), result, name);
      if (result.status === 'SENT') {
        // The identical finite inspection with current evidence still reaches the real transport.
        assert.equal(point.dispatch.length, 1, name);
        assert.equal(point.sink.captures.length, 1, name);
        assert.equal(point.sink.captures[0].equals(expectedImage()), true, name);
        assert.equal(point.sender.state, 'IDLE', name);
      } else {
        // The real fixed-worker child ALLOWed these bytes and readiness opened the connection; only
        // the dispatch-time freshness re-read withheld them, so nothing was dispatched, written or
        // captured.
        assertNoByteSent(point.sink, point.dispatch);
        assert.equal(point.sender.state, 'IDLE', name);
      }
    }
  });

test('a dispatch failure is a fixed code and never leaks the transport exception',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sender, dispatch } = await harness(t, {
      sink: null,
      host: { sendPoint: {
        waitUntilReady: async () => {},
        observe: () => ({
          destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST },
          commit: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) },
        }),
        sendExact: async () => { dispatch.push(Buffer.alloc(0)); throw new Error(`connect failed: ${PLANTED_ORIGINAL}`); },
      } },
    });
    const result = await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'dispatch failure');
    assert.deepEqual(result, { status: 'REFUSED', code: 'DISPATCH_FAILED' });
    assert.equal(JSON.stringify(result).includes(PLANTED_ORIGINAL), false, 'no planted value in the result');
    assert.equal(sender.state, 'IDLE');
  });

test('a hostile route label cannot inject a header into the image',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sender, dispatch } = await harness(t, {
      sink: null,
      observations: [{
        destination: { id: `evil.invalid\r\nX-Injected: 1`, profileDigest: PROFILE_DIGEST },
        commit: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) },
      }],
    });
    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'hostile route label'), { status: 'REFUSED', code: 'ROUTE_REFUSED' });
    assert.equal(dispatch.length, 0);
  });

test('a destination label with an ordinary space refuses at the route boundary and sends nothing',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // An ordinary space is legal in a string and illegal in this label: the label is interpolated into
    // the image's `Host` header, so it is refused where the route is read, before any image exists.
    // The committed profile, the policy bundle and the authenticated boundary all carry this same
    // spaced label, so on a sender that failed to refuse it the whole path would run and the spaced
    // label would reach the transport. That is what this test refuses to allow.
    const spacedSink = Object.freeze({ ...SINK, ref: 'model sink.example.invalid' });
    const spacedProfile = Object.freeze({ ...PROFILE, sink: spacedSink });
    const spacedBundle = Object.freeze({
      ...KNOWN_POLICY_BUNDLE, profiles: [spacedProfile], rules: [BUNDLE.rules[0]],
    });
    const observation = Object.freeze({
      destination: {
        id: spacedSink.ref,
        profileDigest: createHash('sha256').update(JSON.stringify(spacedProfile)).digest('hex'),
      },
      commit: Object.freeze({ ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(spacedBundle) }),
    });
    const boundary = Object.freeze({
      ...BOUNDARY,
      observed: { ...BOUNDARY.observed, destination: spacedSink, routeProof: proof('route-spaced.invalid') },
    });
    const point = await harness(t, {
      boundary, policyBundle: spacedBundle, observations: [observation, observation],
    });
    assert.deepEqual(await bounded(point.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'spaced destination label'), { status: 'REFUSED', code: 'ROUTE_REFUSED' });
    assertNothingSent(point.sink, point.dispatch);
    assert.equal(point.sender.state, 'IDLE');

    // Positive control: the space-free fixture label is still accepted on the same path - one real
    // fixed-worker check, one dispatch, and the independently declared image at the sink.
    const safe = await harness(t);
    assert.deepEqual(await bounded(safe.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'space-free destination label'), { status: 'SENT' });
    assert.equal(safe.dispatch.length, 1);
    assert.equal(safe.sink.captures.length, 1);
    assert.equal(safe.sink.captures[0].equals(expectedImage()), true);
    assert.equal(safe.sender.state, 'IDLE');
  });

test('boundary evidence that cannot be bound refuses with INTERACTION_REFUSED and no effect',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // Independently bound evidence, not sender-owned: each boundary below is structurally an accepted
    // host member and fails only where the envelope binds it to this interaction. Nothing here is
    // stubbed, so these are the real bindings the real envelope refuses.
    for (const [name, boundary] of [
      ['expired route proof', {
        ...BOUNDARY,
        observed: {
          ...BOUNDARY.observed,
          routeProof: {
            ref: 'route-expired.invalid',
            issuedAt: new Date(Date.now() - 600_000).toISOString(),
            expiresAt: new Date(Date.now() - 300_000).toISOString(),
          },
        },
      }],
      ['identity proof with an extra own key', {
        ...BOUNDARY,
        authenticated: {
          ...BOUNDARY.authenticated,
          identityProof: { ...proof('identity-unknown-key.invalid'), signature: 'synthetic-not-a-proof' },
        },
      }],
    ]) {
      const point = await harness(t, { boundary });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
      }), name), { status: 'REFUSED', code: 'INTERACTION_REFUSED' }, name);
      assertNothingSent(point.sink, point.dispatch);
      assert.equal(point.sender.state, 'IDLE', name);
    }
  });

/* ---------- The captured scope and registration the child is asked to check under ---------- */

test('a host that rewrites its own scope, registration scope, key or entries cannot retarget the check',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // LEAKY_REQUEST_BODY carries the planted original and the fixture classifies the whole image PUBLIC
    // with detector evidence, so real policy selects KEEP for every unit and the send really reaches the
    // real child. Only the sentinel's own known-original registration can withhold it from there.
    const foreign = { tenantRef: 'tenant-foreign-keep.invalid', projectRef: 'project-foreign-keep.invalid' };

    /** One mutable, host-owned scope and registration per control. Nothing here is frozen. */
    const aliasHost = () => {
      const scope = { tenantRef: SCOPE.tenantRef, projectRef: SCOPE.projectRef };
      const key = KEY.slice();
      const known = {
        scope: { tenantRef: SCOPE.tenantRef, projectRef: SCOPE.projectRef }, key, entries: [],
      };
      for (const entry of BENIGN_ENTRIES) known.entries.push({ ...entry });
      return { scope, key, known };
    };

    for (const [name, rewrite] of [
      // Everything the child would be asked to run under moved to a foreign tenant: a different scope, a
      // matching registration scope, different key bytes and a registration that no longer holds A.
      ['every scope, key and entry alias rewritten to a foreign tenant', (alias) => {
        alias.scope.tenantRef = foreign.tenantRef;
        alias.scope.projectRef = foreign.projectRef;
        alias.known.scope.tenantRef = foreign.tenantRef;
        alias.known.scope.projectRef = foreign.projectRef;
        alias.key.fill(0x2a);
        alias.known.entries = [];
      }],
      // Only the key array rewritten IN PLACE: the same Uint8Array the host handed over, different
      // bytes. This one is not a bypass on its own - the child fingerprints the registration entries and
      // the payload under the same key of one request frame - so what it shows is that the captured key
      // bytes are what the child is handed and that the outcome stays one fixed restrictive refusal.
      ['the key array rewritten in place', (alias) => { alias.key.fill(0x00); }],
      // Only the entry list replaced, with an equal-shaped list that no longer holds A's original.
      ['the entry list replaced without the planted original', (alias) => {
        alias.known.entries = [{ kind: 'CANARY', value: PLANTED_CANARY, ref: 'planted.canary.2' }];
      }],
    ]) {
      const alias = aliasHost();
      // A finite inspection that rewrites the host's own members after they were handed over. The
      // sender still checks under the scope and registration it captured privately.
      const point = await harness(t, {
        inspect: (image, binding) => { rewrite(alias); return inspectWholeImage(image, binding); },
        host: { scope: alias.scope, known: alias.known },
      });
      const result = await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: LEAKY_REQUEST_BODY,
      }), name);
      assert.deepEqual(result, { status: 'REFUSED', code: 'SENTINEL_BLOCKED' }, name);
      assertNothingSent(point.sink, point.dispatch);
      assert.equal(point.sender.state, 'IDLE', name);
    }

    // An unknown own key on the registration is still one fixed restrictive refusal and no effect.
    const unknown = aliasHost();
    unknown.known.clearance = 'PUBLIC';
    const unusable = await harness(t, { host: { scope: unknown.scope, known: unknown.known } });
    assert.deepEqual(await bounded(unusable.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: LEAKY_REQUEST_BODY,
    }), 'unknown registration key'), { status: 'REFUSED', code: 'SENTINEL_BLOCKED' });
    assertNothingSent(unusable.sink, unusable.dispatch);
    assert.equal(unusable.sender.state, 'IDLE');

    // Positive control on the same mechanism: a benign rewrite that keeps the captured tenant A values
    // sends normally. Capturing a private copy is not a rule that revokes on any host-side mutation, and
    // no such automatic revocation rule is invented here.
    const benign = aliasHost();
    const benignPoint = await harness(t, {
      inspect: (image, binding) => {
        benign.scope.tenantRef = SCOPE.tenantRef;
        benign.scope.projectRef = SCOPE.projectRef;
        benign.known.scope = { tenantRef: SCOPE.tenantRef, projectRef: SCOPE.projectRef };
        benign.known.key = KEY.slice();
        benign.known.entries = BENIGN_ENTRIES.map((entry) => ({ ...entry }));
        return inspectWholeImage(image, binding);
      },
      host: { scope: benign.scope, known: benign.known },
    });
    assert.deepEqual(await bounded(benignPoint.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'benign host rewrite'), { status: 'SENT' });
    assert.equal(benignPoint.dispatch.length, 1);
    assert.equal(benignPoint.sink.captures.length, 1);
    assert.equal(benignPoint.sink.captures[0].equals(expectedImage()), true,
      'a benign host rewrite still sends the declared image');
    assert.equal(benignPoint.sender.state, 'IDLE');
  });

/* ---------- Cancellation, contention and an unusable host ---------- */

test('cancelling a genuinely active send invokes the transport zero times and disables the sender',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, sender, dispatch } = await harness(t);
    // The sentinel child is spawned inside the synchronous prelude of `send`, so the cancel below is
    // observed on a genuinely active check rather than after it finished.
    const pending = sender.send({ endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY });
    sender.cancel();
    assert.equal(sender.state, 'CANCELLED');
    assert.deepEqual(await bounded(pending, 'cancelled send'), { status: 'REFUSED', code: 'CANCELLED' });
    assertNothingSent(sink, dispatch);

    // A cancelled sender stays cancelled: it can neither dispatch again nor be raced into a second
    // effect by a later call.
    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'after cancel'), { status: 'REFUSED', code: 'CANCELLED' });
    assertNothingSent(sink, dispatch);
  });

test('a second send while one is in flight is refused rather than queued or duplicated',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, sender, dispatch } = await harness(t);
    const first = sender.send({ endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY });
    const second = sender.send({ endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY });
    assert.deepEqual(await bounded(second, 'busy send'), { status: 'REFUSED', code: 'SENDER_BUSY' });
    assert.deepEqual(await bounded(first, 'first send'), { status: 'SENT' });
    assert.equal(dispatch.length, 1, 'exactly one dispatch, never two');
    assert.equal(sink.captures.length, 1);
    assert.equal(sender.state, 'IDLE');
  });

test('an unusable trusted host yields a permanently restrictive sender, never a throw',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { host } = await harness(t);
    for (const [name, unusable] of [
      ['not an object', 'nope'],
      ['missing send point', { ...host, sendPoint: undefined }],
      ['unknown own key', { ...host, trustedTransport: null }],
      ['send point is not callable', { ...host, sendPoint: { ...host.sendPoint, sendExact: 'nope' } }],
      ['send point cannot become ready', { ...host, sendPoint: { ...host.sendPoint, waitUntilReady: 'nope' } }],
      ['source trust is not a trust level', { ...host, sourceTrust: 'CONTROLLED' }],
      ['inspection is not a function', { ...host, inspectOriginal: {} }],
      ['accessor instead of a data property', Object.defineProperty({ ...host }, 'scope', {
        enumerable: true, get: () => SCOPE,
      })],
    ]) {
      const sender = createOpenAiTextSender(unusable);
      assert.equal(sender.state, 'FAILED', name);
      assert.deepEqual(await bounded(sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
      }), name), { status: 'REFUSED', code: 'HOST_INVALID' }, name);
      // Cancelling an unusable sender is a no-op, not a crash and not a state change.
      sender.cancel();
      assert.equal(sender.state, 'FAILED', name);
    }
  });

test('a revoked Proxy anywhere in the trusted host is contained as an unusable sender',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { host, dispatch } = createHost(null);
    // A revoked Proxy throws from every trap, including the array check the structural reader starts
    // with. That is contained by the structural refusal, not by an exception escaping construction.
    const revokedHost = Proxy.revocable(host, {});
    revokedHost.revoke();
    const revokedSendPoint = Proxy.revocable(host.sendPoint, {});
    revokedSendPoint.revoke();

    for (const [name, unusable] of [
      ['revoked host', revokedHost.proxy],
      ['revoked send point', { ...host, sendPoint: revokedSendPoint.proxy }],
    ]) {
      let sender = null;
      let threw = false;
      try { sender = createOpenAiTextSender(unusable); } catch { threw = true; }
      assert.equal(threw, false, `${name}: construction never throws`);
      assert.equal(sender.state, 'FAILED', name);
      assert.deepEqual(await bounded(sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
      }), name), { status: 'REFUSED', code: 'HOST_INVALID' }, name);
      sender.cancel();
      assert.equal(sender.state, 'FAILED', name);
      assert.equal(dispatch.length, 0, `${name}: the transport was never invoked`);
    }
  });
/* ---------- Policy-selected whole-message irreversible MASK (#218) ---------- */

/**
 * The generic irreversible literal. It is written here as an independently declared literal a
 * reviewer can read without running anything, and it is compared byte-for-byte: this file never
 * imports the sender's own constant.
 */
const MASKED = '[hylja:masked]';
/** Not a registered original, so two identical units can be shown to be treated independently. */
const DUPLICATE_LINE = 'shared synthetic line token-2f81.invalid';

const ruleFor = (semanticType, decision) => ({
  id: `text-rule-${semanticType.toLowerCase()}.invalid`, profileId: PROFILE.id, semanticType,
  sensitivities: ['PUBLIC'], sourceTrust: [...TRUST_LEVELS], operations: ['SEND'], decision,
});
/** One real policy rule per semantic type, so real policy selects a different treatment per unit. */
function bundleFor(byType, permittedTreatments) {
  return Object.freeze({
    ...KNOWN_POLICY_BUNDLE,
    profiles: [Object.freeze({ ...PROFILE, permittedTreatments })],
    rules: Object.freeze(Object.entries(byType).map(([type, decision]) => ruleFor(type, decision))),
  });
}
/** The two semantic types this section classifies by: kept units and selected-MASK units. */
const KEEP_TYPE = 'APPLICATION_OR_ENVIRONMENT';
const MASK_TYPE = 'PERSON';

function classificationOfType(binding, semanticType) {
  return composeClassification({
    detectorEvidence: [{
      version: 1, id: 'detector-text.invalid', status: 'FOUND',
      provenance: {
        inputRef: 'field-text.invalid', producerId: 'detector-text.invalid', producerVersion: 'pack-text-1',
      },
      claim: { semanticType, sensitivity: 'PUBLIC' },
    }],
  }, { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust: SOURCE_TRUST });
}

/**
 * Classify by unit kind (and by message index), so the real Policy Engine selects a real treatment
 * for each unit independently. Nothing here supplies a treatment, a literal or a replacement: the
 * classification is fixture evidence and the treatment is whatever real policy decides over it.
 */
function inspectByKind(kindTypes) {
  return (image, binding) => {
    let message = 0;
    const units = binding.units.map((unit) => {
      const semanticType = unit.kind === 'MESSAGE'
        ? (kindTypes.message?.[message++] ?? KEEP_TYPE)
        : kindTypes[unit.kind.toLowerCase()];
      const classification = classificationOfType(binding, semanticType);
      return { unitRef: unit.unitRef, classificationDigest: digestClassification(classification), classification };
    });
    return {
      version: 1, interactionRef: binding.interactionRef, imageDigest: binding.imageDigest,
      coverage: 'COMPLETE', remainder: 'NONE', units,
    };
  };
}

/** The final image a reviewer can read: the same framing, only Content-Length recomputed. */
function maskedImage(body) {
  const bytes = Buffer.byteLength(body, 'utf8');
  const head = [
    `POST ${OPENAI_TEXT_REQUEST_ENDPOINT} HTTP/1.1`,
    `Host: ${SINK.ref}`,
    'Content-Type: application/json; charset=utf-8',
    `Content-Length: ${bytes}`,
    '', '',
  ].join('\r\n');
  return Buffer.from(`${head}${body}`, 'utf8');
}

test('a policy-selected MASK sends the declared mixed image with only the selected message replaced',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, sender, dispatch } = await harness(t, {
      policyBundle: bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']),
      inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [KEEP_TYPE, MASK_TYPE] }),
    });
    const leaky = `Escalate to ${PLANTED_ORIGINAL} before the window opens.`;
    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT,
      body: requestBody([
        { role: 'system', content: SAFE_SYSTEM_TEXT },
        { role: 'user', content: leaky },
      ]),
    }), 'mixed keep and mask'), { status: 'SENT' });

    assert.equal(dispatch.length, 1, 'exactly one trusted transport dispatch');
    assert.equal(sink.captures.length, 1);
    // Declared here as a literal, so a wrong literal, a wrong role, a wrong order or a wrong
    // Content-Length all fail the comparison instead of agreeing with a buggy serializer.
    const expectedBody = '{"model":"fixture-model-keep-sender","messages":['
      + '{"role":"system","content":"You are a synthetic fixture assistant."},'
      + `{"role":"user","content":${JSON.stringify(MASKED)}}]}`;
    const received = sink.captures[0];
    assert.equal(received.equals(maskedImage(expectedBody)), true, 'the sink received the declared masked image');
    assert.equal(received.includes(PLANTED_ORIGINAL), false, 'the masked original never reached the sink');
    assert.equal(received.includes(MASKED), true, 'the generic literal is present exactly as declared');
    const body = received.subarray(received.indexOf('\r\n\r\n') + 4).toString('utf8');
    assert.equal(body, expectedBody, 'the body is the declared final body');
    const head = received.subarray(0, received.indexOf('\r\n\r\n') + 2).toString('latin1');
    // Only Content-Length is recomputed; every other header field is byte-identical.
    assert.equal(head.includes(`Content-Length: ${Buffer.byteLength(expectedBody, 'utf8')}\r\n`), true,
      'Content-Length is the UTF-8 byte length of the final body');
    assert.equal(head.includes(`Host: ${SINK.ref}\r\n`), true);
    assert.equal(head.includes('Content-Type: application/json; charset=utf-8\r\n'), true);
    assert.equal(body.indexOf('role":"system') < body.indexOf('role":"user'), true, 'message order survives');
    assert.equal(sender.state, 'IDLE');
  });

test('every selected message is masked, KEEP units keep their bytes, and Unicode length is exact',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sink, sender, dispatch } = await harness(t, {
      policyBundle: bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']),
      inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE, KEEP_TYPE, MASK_TYPE] }),
    });
    // Astral, combining and CJK text in a KEEP unit, and a planted original in each masked unit.
    const kept = 'Diagnose café \u{1F600} 诊断 https port 443 now.';
    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT,
      body: requestBody([
        { role: 'user', content: `first ${PLANTED_ORIGINAL}` },
        { role: 'assistant', content: kept },
        { role: 'user', content: `third ${PLANTED_CANARY}` },
      ]),
    }), 'mask, keep, mask'), { status: 'SENT' });
    assert.equal(dispatch.length, 1);
    const expectedBody = '{"model":"fixture-model-keep-sender","messages":['
      + `{"role":"user","content":${JSON.stringify(MASKED)}},`
      + `{"role":"assistant","content":${JSON.stringify(kept)}},`
      + `{"role":"user","content":${JSON.stringify(MASKED)}}]}`;
    const received = sink.captures[0];
    assert.equal(received.equals(maskedImage(expectedBody)), true, 'the sink received the declared image');
    // The declared expectation is checked against real UTF-8 byte length, not a JS string length.
    assert.equal(received.subarray(received.indexOf('\r\n\r\n') + 4).byteLength,
      Buffer.byteLength(expectedBody, 'utf8'));
    assert.equal(received.includes(Buffer.from(kept, 'utf8')), true, 'the KEEP unit kept its exact bytes');
    assert.equal(received.includes(PLANTED_ORIGINAL), false);
    assert.equal(received.includes(PLANTED_CANARY), false);
    assert.equal(sender.state, 'IDLE');
  });

test('duplicate identical occurrences are separate units, never one global replacement',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // Both messages carry byte-identical text. The trusted inspection classifies them differently,
    // so real policy selects KEEP for the first and MASK for the second: only that one unit may
    // change, which is exactly what a global replace of matching text could not do.
    const bundle = bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']);
    const inspect = inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [KEEP_TYPE, MASK_TYPE] });
    const body = requestBody([
      { role: 'user', content: DUPLICATE_LINE },
      { role: 'user', content: DUPLICATE_LINE },
    ]);
    const { sink, sender } = await harness(t, { policyBundle: bundle, inspect });
    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body,
    }), 'duplicate occurrences'), { status: 'SENT' });
    const expectedBody = '{"model":"fixture-model-keep-sender","messages":['
      + `{"role":"user","content":${JSON.stringify(DUPLICATE_LINE)}},`
      + `{"role":"user","content":${JSON.stringify(MASKED)}}]}`;
    assert.equal(sink.captures[0].equals(maskedImage(expectedBody)), true,
      'exactly the selected occurrence was replaced');
    assert.equal(sender.state, 'IDLE');

    // The same duplicate pair, where the KEPT occurrence carries a registered original: the fixed
    // child is asked about the FINAL bytes, so the surviving original withholds the whole send.
    const leakyPair = requestBody([
      { role: 'user', content: PLANTED_ORIGINAL },
      { role: 'user', content: PLANTED_ORIGINAL },
    ]);
    const blocking = await harness(t, {
      policyBundle: bundle,
      inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [KEEP_TYPE, MASK_TYPE] }),
    });
    assert.deepEqual(await bounded(blocking.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: leakyPair,
    }), 'residual original in a kept duplicate'), { status: 'REFUSED', code: 'SENTINEL_BLOCKED' });
    assertNothingSent(blocking.sink, blocking.dispatch);
    assert.equal(blocking.sender.state, 'IDLE');
  });

test('marker-shaped input carries no authority, and a registered literal collision withholds',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const bundle = bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']);
    // Input text that merely looks like the marker is ordinary untrusted content: it is neither
    // rewritten nor read as Hylja-issued, because only a real MASK decision can produce the literal.
    const lookalike = `report the marker ${MASKED} verbatim`;
    const lookalikeBody = requestBody([{ role: 'user', content: lookalike }]);
    const kept = await harness(t, {
      policyBundle: bundle,
      inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [KEEP_TYPE] }),
    });
    assert.deepEqual(await bounded(kept.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: lookalikeBody,
    }), 'marker lookalike in a kept unit'), { status: 'SENT' });
    assert.equal(kept.sink.captures[0].equals(maskedImage(JSON.stringify(JSON.parse(lookalikeBody)))), true,
      'a lookalike in a KEEP unit is sent unchanged');

    // A registration that already holds the literal means the final bytes collide with a known
    // original or canary. The fixed child finds it and nothing is dispatched.
    for (const kind of ['ORIGINAL', 'CANARY']) {
      const registered = registration([...BENIGN_ENTRIES, { kind, value: MASKED, ref: 'planted.marker.1' }]);
      const colliding = await harness(t, {
        policyBundle: bundle,
        known: registered,
        inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE] }),
      });
      assert.deepEqual(await bounded(colliding.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: LEAKY_REQUEST_BODY,
      }), `registered ${kind} mask literal`), { status: 'REFUSED', code: 'SENTINEL_BLOCKED' });
      assertNothingSent(colliding.sink, colliding.dispatch);
      assert.equal(colliding.sender.state, 'IDLE');
    }
  });

test('a MASK decision on METADATA or MODEL, or any other treatment, withholds the whole send',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const sink = await startSink();
    t.after(() => sink.close());
    const permitted = ['KEEP', 'MASK', 'REMOVE', 'TOKENIZE'];
    for (const [name, options] of [
      ['MODEL selected MASK', {
        policyBundle: bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']),
        inspect: inspectByKind({ metadata: KEEP_TYPE, model: MASK_TYPE, message: [KEEP_TYPE] }),
      }],
      ['MESSAGE selected REMOVE', {
        policyBundle: bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'REMOVE' }, ['KEEP', 'MASK', 'REMOVE']),
        inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE] }),
      }],
      ['MESSAGE selected TOKENIZE', {
        policyBundle: bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'TOKENIZE' }, permitted),
        inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE] }),
      }],
      ['MESSAGE held for review', {
        policyBundle: Object.freeze({
          ...KNOWN_POLICY_BUNDLE,
          profiles: [Object.freeze({ ...PROFILE, permittedTreatments: ['KEEP', 'MASK', 'REMOVE'] })],
          rules: [ruleFor(KEEP_TYPE, 'KEEP'),
            Object.freeze({ ...ruleFor(MASK_TYPE, 'REQUIRE_REVIEW'), reviewTreatments: ['MASK'] })],
        }),
        inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE] }),
      }],
    ]) {
      const point = await harness(t, { ...options, sink });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: LEAKY_REQUEST_BODY,
      }), name), { status: 'REFUSED', code: name.includes('held') ? 'POLICY_HELD' : 'POLICY_NOT_KEEP' }, name);
      assertNothingSent(sink, point.dispatch);
      assert.equal(point.sender.state, 'IDLE', name);
    }
  });

/* ---------- The receiver the inspection callback runs on, and owned-copy lifetime ---------- */

test('the inspection callback runs on the accepted data-property snapshot receiver',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const bundle = bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']);
    const observation = Object.freeze({
      destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST },
      commit: Object.freeze({ ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(bundle) }),
    });
    let receiverPreserved = true;
    let swapped = 0;
    let released = null;
    // Declared as real methods on their own objects, so a lost receiver is observable from inside.
    const sendPoint = {
      observe() { if (this !== sendPoint) receiverPreserved = false; return observation; },
      async waitUntilReady() { if (this !== sendPoint) receiverPreserved = false; },
      async sendExact(image) {
        if (this !== sendPoint) receiverPreserved = false;
        released = Buffer.from(image);
      },
    };
    // The accepted callback must see the receiver it was validated on: the host's own accepted data
    // properties, carrying the ORIGINAL members and not the wrappers this sender installed over them.
    const classify = inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE] });
    const accepted = function inspectOriginal(image, binding) {
      if (this.inspectOriginal !== accepted) receiverPreserved = false;
      if (this.sendPoint !== sendPoint) receiverPreserved = false;
      if (this.sendPoint.observe !== sendPoint.observe) receiverPreserved = false;
      return classify(image, binding);
    };
    const point = await harness(t, {
      policyBundle: bundle, sink: null, inspect: accepted, observations: [observation, observation],
      host: { sendPoint },
    });
    // A host that replaces its own inspection method after construction does not retarget this sender.
    point.host.inspectOriginal = () => { swapped += 1; return undefined; };
    const leaky = `Escalate to ${PLANTED_ORIGINAL} before the window opens.`;
    assert.deepEqual(await bounded(point.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT,
      body: requestBody([{ role: 'user', content: leaky }]),
    }), 'snapshot receiver'), { status: 'SENT' });
    assert.equal(receiverPreserved, true, 'the callback ran on the accepted snapshot, not on a wrapper');
    assert.equal(swapped, 0, 'the replacement installed after construction was never invoked');
    // Normal new control: the same path still releases exactly the declared masked image.
    const expectedBody = '{"model":"fixture-model-keep-sender","messages":['
      + `{"role":"user","content":${JSON.stringify(MASKED)}}]}`;
    assert.equal(released.equals(maskedImage(expectedBody)), true, 'the transport received the masked image');
    assert.equal(released.includes(PLANTED_ORIGINAL), false);
    assert.equal(point.sender.state, 'IDLE');
  });

test('a byte copy this send hands the inspector is zeroed when the send ends',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const bundle = bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']);
    const leaky = `Escalate to ${PLANTED_ORIGINAL} before the window opens.`;
    // The inspector RETAINS the copy it is handed instead of scribbling on it, so a zero byte
    // afterwards can only have come from the sender's own end-of-send cleanup. Only a count of zero
    // bytes is ever asserted; no byte of the copy and no planted value can reach the TAP output.
    for (const [name, expected] of [['masked send', 'SENT'], ['inspection refusal', 'INSPECTION_REFUSED']]) {
      let retained = null;
      const classify = inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE] });
      const inspect = (image, binding) => {
        retained = image;
        return expected === 'SENT' ? classify(image, binding) : { ...classify(image, binding), remainder: 'UNKNOWN' };
      };
      const point = await harness(t, { policyBundle: bundle, inspect });
      const result = await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT,
        body: requestBody([{ role: 'user', content: leaky }]),
      }), name);
      assert.deepEqual(result, expected === 'SENT'
        ? { status: 'SENT' } : { status: 'REFUSED', code: expected }, name);
      assert.equal(retained !== null && retained.length > 0, true, `${name}: a real copy was handed over`);
      assert.equal(retained.reduce((zero, byte) => zero + (byte === 0 ? 1 : 0), 0), retained.length,
        `${name}: every byte of the sender's own inspection copy is zero once the send ended`);
    }
  });

test('a masked rebuild that outgrows the strict codec byte bound withholds the whole send',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // The original body sits inside the codec's own 65_536-byte bound, and the fixed mask literal is
    // 14 bytes longer than the empty message unit it replaces, so the rebuilt body crosses that bound
    // and the strict re-parse refuses it. This is the real derivation refusal: no child is spawned.
    const TARGET_BYTES = 65_534;
    const skeleton = requestBody([{ role: 'user', content: '' }, { role: 'user', content: '' }]);
    const body = requestBody([
      { role: 'user', content: '' },
      { role: 'user', content: 'x'.repeat(TARGET_BYTES - Buffer.byteLength(skeleton, 'utf8')) },
    ]);
    assert.equal(Buffer.byteLength(body, 'utf8'), TARGET_BYTES, 'the fixture body is inside the codec bound');
    const point = await harness(t, {
      policyBundle: bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']),
      inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE] }),
    });
    assert.deepEqual(await bounded(point.sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body,
    }), 'rebuild over the codec byte bound'), { status: 'REFUSED', code: 'SENDER_FAILED' });
    assertNothingSent(point.sink, point.dispatch);
    assert.equal(point.sender.state, 'IDLE');
  });

/* ---------- Sender-owned encode allocations (#231): the buffers a length alone would leak ---------- */

/**
 * The native constructor, captured once at module load. Every restoration assertion below compares
 * against this one and not against whatever happens to be installed when it runs.
 */
const NATIVE_TEXT_ENCODER = globalThis.TextEncoder;
/** An obviously synthetic fault label. It is swallowed by the sender's own catch and reaches no assertion. */
const ENCODER_FAULT = 'synthetic-encode-fault.invalid';

/**
 * The number of NON-ZERO bytes across every captured buffer. A count only: a failing assertion prints
 * a number, so no byte of a buffer, no image and no planted value can reach the TAP output. This is a
 * statement about the buffers this sender allocated, and about nothing else - it claims no erasure of
 * the runtime's memory, of a heap dump, or of any other process's copies.
 */
const unclearedBytes = (buffers) => buffers.reduce(
  (total, buffer) => total + buffer.reduce((count, byte) => count + (byte === 0 ? 0 : 1), 0), 0);

/** One distinct module URL per probe, so every probe re-evaluates the sender rather than reusing a cache hit. */
let probeSerial = 0;

/**
 * Install a global `TextEncoder` subclass for the duration of one callback and restore the native
 * constructor in a `finally`. No production hook, injection point or dependency is involved: the
 * sender builds its one module-scope encoder at import time, so a constructor installed around a
 * fresh import is the only way to observe the buffers that encoder owns.
 *
 * Attribution is the entire point of this instrument, so it is deliberately narrow:
 *
 * - Only encoders CONSTRUCTED while that fresh import is being evaluated are tracked. The sender
 *   holds exactly one module-scope encoder. Every other `new TextEncoder()` reachable from a send
 *   belongs either to a module that was already cached at this module's own import, or to a
 *   per-call `utf8Bytes` helper in the codec or the envelope - and those bytes are never attributed
 *   here, so a passing count says nothing about a buffer this sender does not own.
 * - The fresh import re-evaluates the sender and nothing else; the test below proves that by
 *   comparing one dependency export by identity.
 * - `encode` delegates to the native method, so the bytes are the native bytes and only the returned
 *   buffer is retained by this test. `encodeInto` writes into a caller-owned array and allocates
 *   nothing, so it is deliberately left alone.
 *
 * `failEncodeAt(n)` makes the n-th TRACKED - that is, sender-owned - encode throw a synthetic
 * allocation failure. That is how the "failed after a body encode, before the image was completed"
 * window is entered deterministically, at the sender's own allocation point, without changing a line
 * of production code. The fault is gated on the same ownership set as the counter, so an armed fault
 * can never land on an encoder this sender does not own while the probe is installed globally.
 */
async function withEncoderProbe(run) {
  const native = globalThis.TextEncoder;
  const owned = new WeakSet();
  const constructed = [];
  const allocations = [];
  let importing = false;
  let faultAt = 0;
  class ProbedTextEncoder extends native {
    constructor(...args) {
      super(...args);
      if (importing) { owned.add(this); constructed.push(this); }
    }
    encode(input = '') {
      // The fault is injected into SENDER-OWNED encodes only, and only OWNED encodes are counted, so
      // an encoder constructed after the import - untracked, belonging to no part of this sender - can
      // neither trip the fault nor move it. Without the ownership gate on the fault condition itself
      // the counter, which is shared by every encoder while the probe is installed globally, would make
      // the fault land on an unrelated encoder's encode instead.
      if (!owned.has(this)) return super.encode(input);
      if (faultAt > 0 && allocations.length + 1 === faultAt) throw new TypeError(ENCODER_FAULT);
      const bytes = super.encode(input);
      allocations.push(bytes);
      return bytes;
    }
  }
  globalThis.TextEncoder = ProbedTextEncoder;
  try {
    importing = true;
    probeSerial += 1;
    const fresh = await import(`../dist/openai-text-sender.js?encoder-probe=${probeSerial}`);
    importing = false;
    return await run({
      create: fresh.createOpenAiTextSender, probed: ProbedTextEncoder, native, constructed, allocations,
      failEncodeAt: (n) => { faultAt = n; },
    });
  } finally {
    importing = false;
    globalThis.TextEncoder = native;
  }
}

/** The one masked image the probe tests assert against, declared here as a literal, as everywhere else. */
const PROBE_MASKED_BODY = '{"model":"fixture-model-keep-sender","messages":['
  + `{"role":"user","content":${JSON.stringify(MASKED)}}]}`;

test('the encoder probe attributes only this sender module and restores the native constructor',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // Astral, combining and CJK text, so the byte-identity claim below is over real UTF-8 encoding.
    const sample = 'café \u{1F600} 诊断';
    const nativeBytes = Buffer.from(new TextEncoder().encode(sample));

    await withEncoderProbe(async (probe) => {
      assert.notEqual(probe.create, createOpenAiTextSender, 'a fresh sender module instance was imported');
      // The probe is a pass-through: it encodes exactly what the native constructor encodes.
      assert.equal(Buffer.from(new probe.probed().encode(sample)).equals(nativeBytes), true,
        'instrumentation does not change a single encoded byte');
      // The fresh import re-evaluated the sender and nothing else. Without this, an allocation made
      // inside a re-evaluated dependency could be attributed to the sender.
      const shared = await import('../dist/policy.js');
      assert.equal(shared.decidePolicy, decidePolicy, 'the sender dependencies were already cached');
      assert.equal(probe.constructed.length, 1,
        'the sender built exactly its own module-scope encoder under the probe');
      assert.equal(probe.allocations.length, 0, 'no send has run yet, so nothing was allocated');
    });

    // Restored by the probe's `finally`, and checked from outside it rather than from inside.
    assert.equal(globalThis.TextEncoder, NATIVE_TEXT_ENCODER, 'the native constructor is back in place');
    assert.equal(Buffer.from(new TextEncoder().encode(sample)).equals(nativeBytes), true);
    // The sender every other test in this file uses is unaffected by the probe having run at all.
    const { sender, dispatch } = await harness(t);
    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'post-probe send'), { status: 'SENT' });
    assert.equal(dispatch.length, 1);
  });

test('every sender-owned encode allocation is zeroed after a successful masked send',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const leaky = `Escalate to ${PLANTED_ORIGINAL} before the window opens.`;
    await withEncoderProbe(async (probe) => {
      const point = await harness(t, {
        create: probe.create,
        policyBundle: bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']),
        inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE] }),
      });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT,
        body: requestBody([{ role: 'user', content: leaky }]),
      }), 'masked send'), { status: 'SENT' });

      // The real effect happened: one trusted dispatch and one loopback capture of the declared image.
      assert.equal(point.dispatch.length, 1, 'exactly one trusted transport dispatch');
      assert.equal(point.sink.connections, 1);
      assert.equal(point.sink.captures.length, 1);
      assert.equal(point.sink.captures[0].equals(maskedImage(PROBE_MASKED_BODY)), true,
        'the sink received the declared masked image');
      assert.equal(point.sink.captures[0].includes(PLANTED_ORIGINAL), false, 'no planted value reached the sink');

      // Attribution is not vacuous: this send really allocated the sender its own encode buffers -
      // the ORIGINAL and FINAL head and body encodes plus a buffer behind every unit digest.
      assert.equal(probe.allocations.length >= 6, true,
        'the send allocated several sender-owned encode buffers');
      assert.equal(unclearedBytes(probe.allocations), 0,
        'every sender-owned encode allocation is zero once the send ended');
      assert.equal(point.sender.state, 'IDLE');
    });
  });

test('every sender-owned encode allocation is zeroed after a restrictive refusal',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    await withEncoderProbe(async (probe) => {
      // A planted original in a KEEP unit reaches the real fixed child, which finds it in the FINAL
      // bytes and withholds the whole send. This is the latest restrictive refusal on the path, so
      // by the time it returns both images have been framed and every unit digest encoded.
      const point = await harness(t, { create: probe.create });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: LEAKY_REQUEST_BODY,
      }), 'sentinel refusal'), { status: 'REFUSED', code: 'SENTINEL_BLOCKED' });
      assertNothingSent(point.sink, point.dispatch);

      assert.equal(probe.allocations.length >= 6, true,
        'the refused send allocated several sender-owned encode buffers');
      assert.equal(unclearedBytes(probe.allocations), 0,
        'a refusal clears every sender-owned encode allocation, not only the accepted path');
      assert.equal(point.sender.state, 'IDLE');
    });
  });

test('a sender-owned body encode is zeroed when a later encode fails before the image completes',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    await withEncoderProbe(async (probe) => {
      // The synthetic fault is raised at the sender's SECOND own encode. The first is the body buffer
      // the framed image is built from and the head encode is the step that follows it, so this enters
      // exactly the window where an already-allocated body buffer can still escape its own cleanup.
      probe.failEncodeAt(2);
      const point = await harness(t, {
        create: probe.create,
        policyBundle: bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']),
        inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE] }),
      });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: LEAKY_REQUEST_BODY,
      }), 'encode fault'), { status: 'REFUSED', code: 'SENDER_FAILED' });
      assertNothingSent(point.sink, point.dispatch);

      // One buffer, and it is the body encode the fault interrupted: not the faulted call itself,
      // which allocated nothing because it threw.
      assert.equal(probe.allocations.length, 1, 'the fault landed after exactly one sender-owned encode');
      assert.equal(unclearedBytes(probe.allocations), 0,
        'the body encode buffer is zero after the head encode failed');
      assert.equal(point.sender.state, 'IDLE');
    });
  });

test('an armed encode fault reaches only the sender: an untracked encoder encodes natively',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // Astral, combining and CJK text, so the byte-identity claim below is over real UTF-8 encoding.
    const sample = 'café \u{1F600} 诊断';
    const nativeBytes = Buffer.from(new TextEncoder().encode(sample));

    await withEncoderProbe(async (probe) => {
      // The synthetic fault stays armed at the sender's SECOND own encode across everything below.
      probe.failEncodeAt(2);

      // Armed, with no tracked allocation yet: an encoder constructed AFTER the import is not the
      // sender's module-scope encoder, so a sender-only fault has nothing to say about it.
      const early = new probe.probed();
      assert.equal(probe.constructed.length, 1, 'the post-import encoder was not attributed to the sender');
      assert.equal(Buffer.from(early.encode(sample)).equals(nativeBytes), true,
        'an untracked encoder encodes natively while the fault is armed');
      assert.equal(probe.allocations.length, 0, 'an untracked encoder allocation is not counted');

      // The real sender, under that same armed fault, still faults at its own second encode, and the
      // buffer it had already allocated is wiped rather than left behind by the thrown allocation.
      const point = await harness(t, {
        create: probe.create,
        policyBundle: bundleFor({ [KEEP_TYPE]: 'KEEP', [MASK_TYPE]: 'MASK' }, ['KEEP', 'MASK', 'REMOVE']),
        inspect: inspectByKind({ metadata: KEEP_TYPE, model: KEEP_TYPE, message: [MASK_TYPE] }),
      });
      assert.deepEqual(await bounded(point.sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: LEAKY_REQUEST_BODY,
      }), 'armed encode fault'), { status: 'REFUSED', code: 'SENDER_FAILED' });
      assertNothingSent(point.sink, point.dispatch);
      assert.equal(probe.allocations.length, 1, 'the armed fault landed after exactly one sender-owned encode');
      assert.equal(unclearedBytes(probe.allocations), 0, 'the owned buffer is zero after the armed fault');
      assert.equal(point.sender.state, 'IDLE');

      // The counter now sits exactly where an ungated injection would trip: one owned allocation is
      // recorded, so the next encode of ANY encoder built while the probe is installed would throw
      // under a fault condition that never asked about ownership.
      const late = new probe.probed();
      assert.equal(probe.constructed.length, 1, 'the post-fault encoder was not attributed to the sender');
      assert.equal(Buffer.from(late.encode(sample)).equals(nativeBytes), true,
        'an untracked encoder encodes natively after the armed fault has landed');
      assert.equal(probe.allocations.length, 1, 'an untracked encode after the fault is still uncounted');
      assert.equal(unclearedBytes(probe.allocations), 0, 'the sender-owned buffer is still zero');
    });

    // Restored by the probe's `finally`, and checked from outside it rather than from inside.
    assert.equal(globalThis.TextEncoder, NATIVE_TEXT_ENCODER, 'the native constructor is back in place');
    assert.equal(Buffer.from(new TextEncoder().encode(sample)).equals(nativeBytes), true);
  });
