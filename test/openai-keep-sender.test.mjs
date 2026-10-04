// #201: the KEEP-only complete-text OpenAI request sender under test.
//
// What this proves, precisely: `createOpenAiKeepSender` owns translation, the exact private serialized
// request image (allowlisted fixed metadata and the model included), snapshot-bound whole-image
// classification evidence, the real deterministic SEND policy decision, the real FIXED-WORKER child
// process sentinel, and exactly one trusted transport dispatch. Nothing is ever handed back to a
// caller that could be replayed: there is no READY/prepared handle and no `sendPrepared`.
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
  digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE,
} from '../dist/policy.js';
import { createOpenAiKeepSender, OPENAI_KEEP_SENDER_REFUSALS } from '../dist/openai-keep-sender.js';
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
    async write(bytes) {
      const socket = net.connect(address.port, '127.0.0.1');
      open.add(socket);
      socket.on('error', () => {});
      await bounded(new Promise((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
      }), 'loopback connect');
      // Reading the response is also what puts the socket in flowing mode, so the exchange is
      // observed here rather than inferred from the write.
      const answered = [];
      socket.on('data', (chunk) => answered.push(chunk));
      socket.write(bytes);
      await bounded(new Promise((resolve) => socket.once('close', resolve)), 'loopback response');
      open.delete(socket);
      assert.equal(Buffer.concat(answered).toString('latin1').startsWith('HTTP/1.1 204'), true,
        'the sink answered the request it received');
    },
    async close() {
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
    inspect: options.inspect ?? inspectWholeImage,
    sendPoint: {
      // Queued observations: the first call is the one the check is made against, the second is what
      // the send point reports immediately before dispatch, and later calls clamp to the last entry.
      observe: () => observations[Math.min(calls++, observations.length - 1)],
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
  return { sink, host, dispatch, sender: createOpenAiKeepSender(host) };
}

/** The whole withholding invariant in one helper: no dispatch, no connection, no byte, no capture. */
const assertNothingSent = (sink, dispatch) => {
  assert.equal(dispatch.length, 0, 'the transport was invoked zero times');
  if (sink === null) return;
  assert.equal(sink.connections, 0, 'the sink accepted no connection');
  assert.equal(sink.receivedBytes, 0, 'the sink received zero bytes');
  assert.equal(sink.captures.length, 0);
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
    assert.equal(OPENAI_KEEP_SENDER_REFUSALS.includes('SENTINEL_BLOCKED'), true);
    assert.equal(OPENAI_KEEP_SENDER_REFUSALS.includes('SENDER_BUSY'), true);
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
      ['MASK treatment', { policyBundle: MASK_BUNDLE }, 'POLICY_NOT_KEEP'],
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
      observe: () => {
        calls += 1;
        if (calls === 2) owner.sender.cancel();
        return observation;
      },
      sendExact: transport.sendExact,
    });
    const sender = createOpenAiKeepSender(host);
    owner.sender = sender;
    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'cancelled inside the final observation'), { status: 'REFUSED', code: 'CANCELLED' });
    assert.equal(calls, 2, 'the refusal came after the final observation, not before it');
    assert.equal(sender.state, 'CANCELLED');
    assertNothingSent(sink, dispatch);
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
    const sender = createOpenAiKeepSender(host);
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
        // The real fixed-worker child ALLOWed these bytes; only the dispatch-time freshness re-read
        // withheld them, so nothing was dispatched, connected or captured.
        assertNothingSent(point.sink, point.dispatch);
        assert.equal(point.sender.state, 'IDLE', name);
      }
    }
  });

test('a dispatch failure is a fixed code and never leaks the transport exception',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const { sender, dispatch } = await harness(t, {
      sink: null,
      host: { sendPoint: { observe: () => ({
        destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST },
        commit: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) },
      }), sendExact: async () => { dispatch.push(Buffer.alloc(0)); throw new Error(`connect failed: ${PLANTED_ORIGINAL}`); } } },
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
      ['source trust is not a trust level', { ...host, sourceTrust: 'CONTROLLED' }],
      ['inspect is not a function', { ...host, inspect: {} }],
      ['accessor instead of a data property', Object.defineProperty({ ...host }, 'scope', {
        enumerable: true, get: () => SCOPE,
      })],
    ]) {
      const sender = createOpenAiKeepSender(unusable);
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
      try { sender = createOpenAiKeepSender(unusable); } catch { threw = true; }
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