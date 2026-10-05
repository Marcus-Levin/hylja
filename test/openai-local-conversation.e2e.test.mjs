// #236: one bounded runtime conversation owner over its own numeric loopback transport.
//
// What this proves, precisely: `createOpenAiLocalConversation` composes the accepted-v1 text sender and
// the accepted-v1 KEEP-only receiver into one application-facing owner that owns the loopback socket
// itself. A request whose text carries a locally planted, obviously synthetic secret is classified by
// the REAL `detectSecrets` over the sender's own private ORIGINAL image, composed by the accepted-v1
// `composeClassification` and decided by the REAL Policy Engine, which selects the narrow whole-message
// irreversible MASK of accepted decision 011. The sender's rebuilt final bytes reach one real peer
// exactly once, the complete reply comes back off that socket, and only the receiver's own guarded
// release reaches the application sink.
//
// It also proves the withholding side on the same sinks: an unresolved upstream inspection and an
// upstream sentinel block open zero sockets at all; a registered original in the reply, a truncated
// reply, an oversize reply, an unsupported framing profile, a timeout and a cancellation each leave the
// application with zero releases and every socket closed. Every refusal group is followed by a genuine
// positive control on the same sink, so the counters above are real.
//
// What it is NOT. It is not a gateway, a listener, a provider client, a broker, a vault, an
// authentication proof, a restoration path, a streaming design, a scored or held-out result, or a claim
// about any production send point. The boundary, the policy pin, the sentinel key, the known-original
// registration and the per-unit records for units the real detector stack does not cover are obviously
// synthetic TRUSTED FIXTURES supplied by this file: nothing here authenticates a principal, tenant
// membership, workload, profile or control plane, and no detector absence is ever read as PUBLIC
// clearance. The masked literal is the narrow accepted decision 011 whole-message mask and nothing more.
// No model traffic, no credential, no network beyond loopback, and no real provider is ever contacted.
// This run proves a bounded local seam composes over fixtures; it proves no enforcement boundary.
//
// Every value is invented and non-routable (`*.invalid`, loopback, a made-up token literal that is
// documentation-shaped and not live). Assertions over planted material are booleans, counts, fixed
// codes and independently declared literals only: a failing assertion never prints a body, a buffer,
// an exception message or a planted value into the TAP output.
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { composeClassification, TRUST_LEVELS } from '../dist/classification.js';
import { digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE } from '../dist/policy.js';
import { detectSecrets } from '../dist/secret-detectors.js';
import {
  createOpenAiLocalConversation, OPENAI_LOCAL_CONVERSATION_REFUSALS,
} from '../dist/openai-local-conversation.js';
import { OPENAI_TEXT_SENDER_REFUSALS } from '../dist/openai-text-sender.js';
import { OPENAI_KEEP_RECEIVER_REFUSALS } from '../dist/openai-keep-receiver.js';
import { OPENAI_TEXT_REQUEST_REFUSALS } from '../dist/openai-text-request.js';
import { OPENAI_TEXT_RESPONSE_REFUSALS } from '../dist/openai-text-response.js';

/** Host-owned sentinel deadline for the real fixed-worker children. */
const DEADLINE_MS = 10_000;
/** Bound every await this file creates, so a stalled child or socket fails loudly instead of hanging. */
const BOUND_MS = 20_000;
const TEST_TIMEOUT_MS = 60_000;
/** The fixed head bound the owner refuses past; the flood peer sends more than this before a terminator. */
const HEAD_BOUND = 4_096;
/** A short exchange deadline, so the timeout case is bounded rather than slow. */
const SHORT_TIMEOUT_MS = 250;

/* ---------- Planted synthetic originals and the registration fixture ---------- */

const SCOPE = Object.freeze({
  tenantRef: 'tenant-owner.invalid', projectRef: 'project-owner.invalid',
});
// A dedicated, obviously synthetic sentinel key for this test only. It is not a credential.
const KEY = Uint8Array.from({ length: 32 }, (unused, index) => (index * 29 + 7) & 0xff);
/** Registered as a known original for BOTH real children, on the request and the reply side. */
const PLANTED_ORIGINAL = 'avery.synthanon@synthetic-planted.invalid';
/**
 * Obviously synthetic and not a live token: a made-up literal in one documented vendor shape, which is
 * exactly what the real format rule is written to recognise.
 */
const PLANTED_SECRET = `ghp_${'SYNTHETIC1'.repeat(4)}`;
const registration = () => ({
  scope: SCOPE, key: KEY, entries: Object.freeze([
    Object.freeze({ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'planted.person.1' }),
  ]),
});

/* ---------- Trusted test fixture bindings (fixtures, not authenticated identities) ---------- */

const SUBJECT = Object.freeze({
  principalId: 'principal-owner.invalid', workloadId: 'workload-owner.invalid',
});
const CONTEXT = Object.freeze({
  tenantId: SCOPE.tenantRef, projectId: SCOPE.projectRef,
  sessionId: 'session-owner.invalid', purpose: 'fixture-owner.invalid',
});
const SOURCE = Object.freeze({
  kind: 'tool.result', ref: 'tool-source-owner.invalid', trustZone: 'LOCAL',
});
const SOURCE_TRUST = 'TRUSTED';
const HOST_LABEL = 'model-sink-owner.example.invalid';
const SINK = Object.freeze({
  kind: 'model', ref: HOST_LABEL, trustZone: 'EXTERNAL', profileId: 'owner-sink.invalid',
});
const PROFILE = Object.freeze({
  id: 'owner-sink.invalid', sink: SINK, exposure: 'EXTERNAL',
  permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'INTERNAL',
});
/**
 * Two real rules so the REAL Policy Engine, not this file, picks a treatment per unit: the units the
 * detector stack finds nothing in get the trusted fixture claim below (PERSON/PUBLIC) and KEEP, and the
 * unit the REAL detector finds a secret in is classified CREDENTIAL_OR_SECRET/SECRET and MASKed.
 */
const BUNDLE = Object.freeze({
  ...KNOWN_POLICY_BUNDLE,
  profiles: [PROFILE],
  rules: [
    {
      id: 'owner-fixture-keep.invalid', profileId: PROFILE.id, semanticType: 'PERSON',
      sensitivities: ['PUBLIC'], sourceTrust: [...TRUST_LEVELS], operations: ['SEND'], decision: 'KEEP',
    },
    {
      id: 'owner-secret-mask.invalid', profileId: PROFILE.id, semanticType: 'CREDENTIAL_OR_SECRET',
      sensitivities: ['SECRET'], sourceTrust: [...TRUST_LEVELS], operations: ['SEND'], decision: 'MASK',
    },
  ],
});

/** Proof freshness, not authenticity: the envelope checks the interval, never the signer. */
function proof(ref) {
  const now = Date.now();
  return Object.freeze({
    ref, issuedAt: new Date(now - 30_000).toISOString(), expiresAt: new Date(now + 120_000).toISOString(),
  });
}
const BOUNDARY = Object.freeze({
  authenticated: {
    subject: SUBJECT, context: CONTEXT,
    identityProof: proof('identity-owner.invalid'), requestProof: proof('request-owner.invalid'),
  },
  observed: {
    source: SOURCE, destination: SINK,
    sourceProof: proof('source-owner.invalid'), routeProof: proof('route-owner.invalid'),
  },
});
const PROFILE_DIGEST = createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex');
const OBSERVATION = Object.freeze({
  destination: Object.freeze({ id: SINK.ref, profileDigest: PROFILE_DIGEST }),
  commit: Object.freeze({ ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) }),
});

/* ---------- The conversation, and the masked request declared here as a literal ---------- */

const MODEL = 'fixture-model-owner';
const SYSTEM_TEXT = 'You are a synthetic fixture assistant.';
const SECRET_TEXT = `Rotate the synthetic fixture for ${PLANTED_ORIGINAL} using ${PLANTED_SECRET} tonight.`;
const WINDOW_TEXT = 'Reply with the rotation window only.';
const MESSAGES = Object.freeze([
  Object.freeze({ role: 'system', content: SYSTEM_TEXT }),
  Object.freeze({ role: 'user', content: SECRET_TEXT }),
  Object.freeze({ role: 'user', content: WINDOW_TEXT }),
]);
/** The generic irreversible literal of accepted decision 011, declared here, never imported. */
const MASKED = '[hylja:masked]';
/**
 * The exact final request image a reviewer can read without running anything: the same fixed framing as
 * any accepted send, with only the selected message content replaced and `Content-Length` recomputed.
 */
const EXPECTED_MASKED_BODY = '{"model":"fixture-model-owner","messages":['
  + '{"role":"system","content":"You are a synthetic fixture assistant."},'
  + '{"role":"user","content":"[hylja:masked]"},'
  + '{"role":"user","content":"Reply with the rotation window only."}]}';
const EXPECTED_MASKED_BODY_BYTES = Buffer.byteLength(EXPECTED_MASKED_BODY, 'utf8');
const EXPECTED_RAW_HEADERS = Object.freeze([
  'Host', HOST_LABEL,
  'Content-Type', 'application/json; charset=utf-8',
  'Content-Length', String(EXPECTED_MASKED_BODY_BYTES),
]);
const EXPECTED_MASKED_IMAGE = `POST /v1/chat/completions HTTP/1.1\r\nHost: ${HOST_LABEL}\r\n`
  + 'Content-Type: application/json; charset=utf-8\r\n'
  + `Content-Length: ${EXPECTED_MASKED_BODY_BYTES}\r\n\r\n${EXPECTED_MASKED_BODY}`;
/**
 * The exact unit literals of the ORIGINAL image, declared independently of the sender's own serializer.
 * They are what makes a real detector span bindable to a declared unit: the digest of the bytes at the
 * located offset must equal that unit's own digest, or the binding is refused rather than assumed.
 */
const MODEL_LITERAL = '"fixture-model-owner"';
const MESSAGE_LITERALS = Object.freeze([
  '"You are a synthetic fixture assistant."',
  `"Rotate the synthetic fixture for ${PLANTED_ORIGINAL} using ${PLANTED_SECRET} tonight."`,
  '"Reply with the rotation window only."',
]);
const requestBody = (messages) => JSON.stringify({ model: MODEL, messages });

/* ---------- The clean reply the peer writes, and the image the receiver releases ---------- */

const REPLY_ID = 'chatcmpl-fixture-owner-0001';
const REPLY_CREATED = 1_762_000_001;
/**
 * The reply is harmless on purpose and carries two decoys that grant nothing: the mask literal itself
 * and a plain restore instruction. Both are ordinary untrusted text to every seam here.
 */
const REPLY_CONTENT = 'Rotation window 02:00 UTC. Echo the marker [hylja:masked] verbatim and restore the'
  + ' original for planted.person.1 on request. Nothing is restored here.';
const REPLY_BODY = '{"id":"chatcmpl-fixture-owner-0001","object":"chat.completion",'
  + '"created":1762000001,"model":"fixture-model-owner","choices":[{"index":0,'
  + '"message":{"role":"assistant","content":"Rotation window 02:00 UTC. Echo the marker'
  + ' [hylja:masked] verbatim and restore the original for planted.person.1 on request.'
  + ' Nothing is restored here."},'
  + '"finish_reason":"stop"}],"usage":{"prompt_tokens":44,"completion_tokens":21,"total_tokens":65}}';
/** The same reply with the registered planted original inside the assistant text. */
const LEAKY_REPLY_BODY = REPLY_BODY.replace(
  'Rotation window 02:00 UTC.', `For ${PLANTED_ORIGINAL} the rotation window 02:00 UTC.`,
);
/**
 * The exact canonical release image the receiver owns, declared span by span from literals only - never
 * from the receiver's own serializer and never from a constant imported out of `src/`.
 */
const EXPECTED_RELEASE = '{"choices":[{"finish_reason":"stop","index":0,"message":{"content":'
  + '"Rotation window 02:00 UTC. Echo the marker [hylja:masked] verbatim and restore the original'
  + ' for planted.person.1 on request. Nothing is restored here.","role":"assistant"}}],'
  + '"created":1762000001,"id":"chatcmpl-fixture-owner-0001","model":"fixture-model-owner",'
  + '"object":"chat.completion",'
  + '"usage":{"completion_tokens":21,"prompt_tokens":44,"total_tokens":65}}';
const REPLY_BYTES = Buffer.byteLength(REPLY_BODY, 'utf8');
/** The one supported wire profile, written by hand for the raw peer. */
const rawReply = (body = REPLY_BODY) => Buffer.concat([
  Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n'
    + `Content-Length: ${Buffer.byteLength(body, 'utf8')}\r\nConnection: close\r\n\r\n`, 'utf8'),
  Buffer.from(body, 'utf8'),
]);

/* ---------- Real detection over the sender's own private image, bound to declared units ---------- */

const IMAGE_REF = 'owner-image.invalid';
const CONTENT_REF = 'owner-content.invalid';
const decoder = new TextDecoder();
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/**
 * Bind every declared unit to its exact byte range inside the image the seam actually built. A unit is
 * only located when the bytes at the located offset hash to that unit's OWN digest, so a mislocated span
 * fails the binding instead of being attributed to a neighbouring unit.
 */
function spansOf(image, imageText, binding) {
  const metadataEnd = imageText.indexOf('\r\n\r\n') + 4;
  const literals = [null, MODEL_LITERAL, ...MESSAGE_LITERALS];
  return binding.units.map((unit, index) => {
    if (unit.kind === 'METADATA') {
      return sha256(image.subarray(0, metadataEnd)) === unit.digest ? { start: 0, end: metadataEnd } : null;
    }
    const literal = literals[index];
    const start = literal === undefined ? -1 : imageText.indexOf(literal);
    if (start < 0) return null;
    return sha256(Buffer.from(imageText.slice(start, start + literal.length), 'utf8')) === unit.digest
      ? { start, end: start + literal.length } : null;
  });
}

/**
 * The classification every unit the REAL detector stack covers nothing in gets. This is a TRUSTED
 * FIXTURE record, declared here, that exists so completeness can be expressed: it is never derived from
 * an empty candidate set, and the test asserts the real detector status separately so an absence stays
 * an absence rather than becoming PUBLIC clearance.
 */
function fixtureClaim(binding, trust) {
  return composeClassification({
    detectorEvidence: [{
      version: 1, id: 'detector-owner-fixture.invalid', status: 'FOUND',
      provenance: {
        inputRef: 'owner-fixture-field.invalid', producerId: 'detector-owner-fixture.invalid',
        producerVersion: 'fixture-pack-1',
      },
      claim: { semanticType: 'PERSON', sensitivity: 'PUBLIC' },
    }],
  }, { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust });
}
/** Provider source trust is fixed by the receiver itself and is not a host or caller input. */
const PROVIDER_TRUST = 'UNTRUSTED';

/**
 * The request-side whole-image inspection: the REAL detector runs over the sender's own private ORIGINAL
 * image bytes, and a unit is classified from that run only when a real candidate span provably lies
 * inside it. `suppress` withholds the real run's candidates from the classification, so the planted
 * secret survives into the final bytes the real child is asked about.
 */
function requestInspect(runs, suppress = false) {
  return (image, binding) => {
    const imageText = decoder.decode(image);
    const detected = detectSecrets({ text: imageText, inputRef: IMAGE_REF });
    const spans = spansOf(image, imageText, binding);
    const units = binding.units.map((unit, index) => {
      const span = spans[index];
      const covered = suppress || detected.status !== 'COMPLETE' || span === null
        ? []
        : detected.candidates.filter((candidate) => candidate.start >= span.start && candidate.end <= span.end);
      const classification = covered.length > 0
        ? composeClassification({ detectorEvidence: covered.map((candidate) => candidate.evidence) },
          { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust: SOURCE_TRUST })
        : fixtureClaim(binding, SOURCE_TRUST);
      return { unitRef: unit.unitRef, classificationDigest: digestClassification(classification), classification };
    });
    runs.push({
      status: detected.status, candidates: detected.candidates.length,
      resolvedSpans: spans.filter((entry) => entry !== null).length, declaredUnits: binding.units.length,
    });
    return {
      version: 1, interactionRef: binding.interactionRef, imageDigest: binding.imageDigest,
      coverage: 'COMPLETE', remainder: 'NONE', units,
    };
  };
}

/**
 * The receiver's own whole-image inspection: the REAL detector runs over the inbound image, its result
 * is recorded, and the per-unit record stays a declared fixture. There is no per-unit real secret
 * evidence on a clean reply, and none is invented from its absence.
 */
function replyInspect(runs) {
  return (image, binding) => {
    const detected = detectSecrets({ text: decoder.decode(image), inputRef: CONTENT_REF });
    const units = binding.units.map((unit) => {
      const classification = fixtureClaim(binding, PROVIDER_TRUST);
      return { unitRef: unit.unitRef, classificationDigest: digestClassification(classification), classification };
    });
    runs.push({ status: detected.status, candidates: detected.candidates.length, units: binding.units.length });
    return {
      version: 1, interactionRef: binding.interactionRef, imageDigest: binding.imageDigest,
      coverage: 'COMPLETE', remainder: 'NONE', units,
    };
  };
}

/**
 * The published refusal vocabulary of the owner and of both owners it composes, whose own codes pass
 * through unchanged. Every code this file asserts must come from one of them.
 */
const VOCABULARY = new Set([
  ...OPENAI_LOCAL_CONVERSATION_REFUSALS, ...OPENAI_TEXT_SENDER_REFUSALS, ...OPENAI_KEEP_RECEIVER_REFUSALS,
  ...OPENAI_TEXT_REQUEST_REFUSALS, ...OPENAI_TEXT_RESPONSE_REFUSALS,
]);

const assertRefusal = (result, code) => {
  assert.equal(VOCABULARY.has(result.code), true, 'the refusal code is in the published vocabulary');
  assert.deepEqual(result, { status: 'REFUSED', code });
};

/* ---------- Bound every await, so a stalled child or socket fails loudly ---------- */

function bounded(promise, label) {
  let timer;
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`deadline exceeded: ${label}`)), BOUND_MS);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

/* ---------- Two real peers on an OS-assigned ephemeral 127.0.0.1 port ---------- */

/** A standard loopback HTTP peer: the masked image is parsed by a real HTTP parser, not by this file. */
async function startHttpPeer(t) {
  const state = {
    connections: 0, requests: 0, bodyBytes: 0, wireBytes: 0, bodies: [], open: new Set(), sockets: [],
  };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('error', () => {});
    res.on('error', () => {});
    req.on('data', (chunk) => { state.bodyBytes += chunk.byteLength; chunks.push(chunk); });
    req.on('end', () => {
      state.requests += 1;
      state.wireBytes += req.socket.bytesRead;
      state.bodies.push({
        method: req.method, url: req.url, rawHeaders: Array.from(req.rawHeaders),
        contentType: req.headers['content-type'], contentLength: req.headers['content-length'],
        transferEncoding: req.headers['transfer-encoding'], body: Buffer.concat(chunks),
      });
      const answer = state.next === undefined ? REPLY_BODY : state.next;
      state.next = undefined;
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(answer, 'utf8'),
        Connection: 'close',
      });
      res.end(answer);
    });
  });
  await closeable(t, server, state, (socket) => state.open.add(socket), (socket) => state.open.delete(socket));
  return state;
}

/**
 * A raw loopback peer that answers with exact bytes this file writes itself, so the reply framing under
 * test is the framing that reaches the owner. `respond(socket, request)` is called once per complete
 * request, and the request bytes are retained for the exactness assertion.
 */
async function startRawPeer(t, respond) {
  const state = { connections: 0, requests: 0, images: [], open: new Set(), sockets: [] };
  const server = net.createServer({ allowHalfOpen: true }, (socket) => {
    const chunks = [];
    socket.on('error', () => {});
    socket.on('data', (chunk) => {
      chunks.push(chunk);
      const total = completeRequest(Buffer.concat(chunks));
      if (total === null) return;
      state.requests += 1;
      state.images.push(Buffer.concat(chunks).subarray(0, total));
      respond(socket);
    });
  });
  await closeable(t, server, state);
  return state;
}

/** Shared listen/close plumbing for both peer kinds, so neither leaks a socket into the next case. */
async function closeable(t, server, state) {
  server.on('connection', (socket) => {
    state.connections += 1;
    state.open.add(socket);
    const retire = () => state.open.delete(socket);
    socket.on('close', retire);
    socket.on('end', retire);
    socket.on('error', () => {});
    state.sockets.push(socket);
  });
  t.after(async () => {
    for (const socket of state.sockets) socket.destroy();
    server.closeAllConnections?.();
    await bounded(new Promise((resolve) => server.close(() => resolve())), 'peer shutdown');
  });
  await bounded(new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  }), 'peer listen');
  const address = server.address();
  assert.equal(typeof address === 'object' && address !== null && address.address === '127.0.0.1', true,
    'the peer is bound to loopback on an OS-assigned ephemeral port');
  state.port = address.port;
}

/**
 * The end offset of one complete request in the bytes this peer has read, parsed here with no help from
 * an HTTP client library: the head terminator plus the declared `Content-Length`.
 */
function completeRequest(buffer) {
  const head = buffer.toString('latin1').indexOf('\r\n\r\n');
  if (head < 0) return null;
  const length = /content-length: *([0-9]+)/iu.exec(buffer.toString('latin1').slice(0, head));
  if (length === null) return null;
  const total = head + 4 + Number.parseInt(length[1], 10);
  return buffer.length < total ? null : total;
}

/* ---------- The trusted host the conversation owner composes from ---------- */

/**
 * One owner over one peer. `suppress` withholds the real detector's candidates so the planted secret
 * survives into the final bytes, which is what the real fixed-worker child blocks on.
 */
function createConversation(state, { runs = [], inbound = [], releases = [], suppress = false,
  timeoutMs = DEADLINE_MS, port = state.port, create = createOpenAiLocalConversation } = {}) {
  const conversation = create({
    port,
    timeoutMs,
    observe: () => OBSERVATION,
    onReply: async (reply) => { releases.push(reply); },
    sender: {
      boundary: BOUNDARY, sourceTrust: SOURCE_TRUST, policyBundle: BUNDLE, scope: SCOPE,
      known: registration(), sentinel: { deadlineMs: DEADLINE_MS },
      inspectOriginal: requestInspect(runs, suppress),
    },
    receiver: {
      boundary: BOUNDARY, policyBundle: BUNDLE, scope: SCOPE, known: registration(),
      sentinel: { deadlineMs: DEADLINE_MS }, inspect: replyInspect(inbound),
    },
  });
  return { conversation, releases };
}

/** The accepted request this owner always frames, declared once for every case in this file. */
const acceptedRequest = () => ({ body: requestBody(MESSAGES) });

/** The whole withholding invariant on the peer side: no connection, no request and no byte. */
const assertNothingReachedPeer = (state) => {
  assert.equal(state.connections, 0, 'the peer accepted no connection');
  assert.equal(state.requests, 0, 'the peer parsed no request');
  assert.equal(state.open.size, 0, 'the peer holds no open socket');
};

/**
 * Wait until the peer reports no live socket, so a closure assertion is never a race. A socket is
 * retired when the peer observes either a full close or the owner's own FIN: what is under test is that
 * the owner closes its side of every socket it opened.
 */
async function closed(state, label) {
  await waitFor(() => state.open.size === 0, `${label}: the owner closed its socket`);
  assert.equal(state.open.size, 0, `${label}: the owner closed every socket it opened`);
}

/**
 * Spin the real clock forward on one thread. Nothing here is stubbed: the owner, the sender and the
 * envelope all read the same real `Date.now()`, and time only moves forward, so a finite cost of this
 * kind can expire a deadline but can never manufacture one.
 */
function spinTo(milliseconds) {
  const deadline = Date.now() + milliseconds;
  while (Date.now() < deadline) { /* the real elapsed time the observation under test costs */ }
}

/** Poll one bounded condition instead of sleeping a fixed guess. */
async function waitFor(condition, label) {
  const deadline = Date.now() + BOUND_MS;
  while (!condition() && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(condition(), true, label);
}

/** The same invariant on the application side: no release invocation at all. */
const assertNothingReleased = (releases) => {
  assert.equal(releases.length, 0, 'the application sink was invoked zero times');
};

/* ---------- The accepted conversation over one real loopback peer ---------- */

test('one bounded conversation: real detection, real policy MASK, real children, one guarded reply',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const state = await startHttpPeer(t);
    const runs = [];
    const inbound = [];
    const releases = [];
    const { conversation } = createConversation(state, { runs, inbound, releases });

    assert.deepEqual(await bounded(conversation.exchange(acceptedRequest()), 'accepted exchange'),
      { status: 'COMPLETED' });
    assert.equal(conversation.state, 'IDLE');

    /* The REAL detector ran over the sender's own private ORIGINAL image and every unit bound. */
    assert.equal(runs.length, 1, 'the real detector ran exactly once, over the original image');
    assert.equal(runs[0].status, 'COMPLETE');
    assert.equal(runs[0].candidates, 1, 'exactly one real local finding, the planted synthetic secret');
    assert.equal(runs[0].resolvedSpans, runs[0].declaredUnits,
      'every declared unit located and digest-bound inside the image');

    /* Exactly one connection, exactly one parsed request, and it is the declared masked image. */
    assert.equal(state.connections, 1, 'exactly one loopback connection');
    assert.equal(state.requests, 1, 'exactly one parsed request');
    assert.equal(state.wireBytes, Buffer.byteLength(EXPECTED_MASKED_IMAGE, 'utf8'),
      'exactly the declared masked image crossed the socket');
    const record = state.bodies[0];
    assert.equal(record.method, 'POST');
    assert.equal(record.url, '/v1/chat/completions', 'the route bound at construction is the one framed');
    assert.equal(record.contentType, 'application/json; charset=utf-8');
    assert.equal(record.transferEncoding, undefined, 'no chunked framing was used');
    assert.equal(record.contentLength, String(EXPECTED_MASKED_BODY_BYTES));
    assert.deepEqual(record.rawHeaders, EXPECTED_RAW_HEADERS,
      'the standard loopback parser saw exactly the three declared headers, in order');
    assert.equal(record.body.equals(Buffer.from(EXPECTED_MASKED_BODY, 'utf8')), true,
      'the body is the independently declared masked body');
    assert.equal(record.body.includes(PLANTED_SECRET), false, 'the planted secret never reached the peer');
    assert.equal(record.body.includes(PLANTED_ORIGINAL), false, 'no registered original reached the peer');
    assert.equal(record.body.includes(MASKED), true, 'the generic decision 011 literal is what is there');
    assert.equal(record.body.includes(SYSTEM_TEXT), true, 'the KEEP units kept their exact bytes');

    /* The receiver ran its own half: its own codec, its own real child, its own release point. */
    assert.equal(inbound.length, 1, 'the real detector ran once over the inbound image');
    assert.equal(inbound[0].status, 'COMPLETE');
    assert.equal(inbound[0].units, 3, 'all three declared units of the inbound image were inspected');

    /* Exactly one application release, and it is the independently declared canonical image. */
    assert.equal(releases.length, 1, 'exactly one application release');
    assert.equal(releases[0], EXPECTED_RELEASE, 'the released text is the declared canonical image');
    assert.equal(releases[0].includes(PLANTED_ORIGINAL), false, 'no original is present in the release');
    assert.equal(releases[0].includes(PLANTED_SECRET), false);
    const released = JSON.parse(releases[0]).choices[0].message.content;
    assert.equal(released, REPLY_CONTENT, 'the released text is byte-identical to the reply content');
    assert.equal(released.includes(MASKED), true, 'the mask literal stays literal text');
    await closed(state, 'accepted conversation');
  });

/* ---------- Every upstream refusal opens no socket at all, on its own fresh peer ---------- */

test('an unresolved inspection and an upstream sentinel block reach no socket, on the same sink',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    /* An UNRESOLVED composition over the planted secret: no detector evidence, so no clearance, so no
       policy decision and no socket. The inspection callback itself is what refuses. */
    {
      const state = await startHttpPeer(t);
      const releases = [];
      const { conversation } = createConversation(state, { releases });
      const owner = createOpenAiLocalConversation({
        port: state.port, timeoutMs: DEADLINE_MS, observe: () => OBSERVATION,
        onReply: async (reply) => { releases.push(reply); },
        sender: {
          boundary: BOUNDARY, sourceTrust: SOURCE_TRUST, policyBundle: BUNDLE, scope: SCOPE,
          known: registration(), sentinel: { deadlineMs: DEADLINE_MS },
          inspectOriginal: (image, binding) => ({
            version: 1, interactionRef: binding.interactionRef, imageDigest: binding.imageDigest,
            coverage: 'COMPLETE', remainder: 'NONE',
            units: binding.units.map((unit) => ({
              unitRef: unit.unitRef,
              classificationDigest: '0'.repeat(64),
              classification: composeClassification({ detectorEvidence: [] },
                { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust: SOURCE_TRUST }),
            })),
          }),
        },
        receiver: {
          boundary: BOUNDARY, policyBundle: BUNDLE, scope: SCOPE, known: registration(),
          sentinel: { deadlineMs: DEADLINE_MS },
          inspect: () => { throw new Error('the receiver half must never run'); },
        },
      });
      assert.equal(conversation.state, 'IDLE', 'the composed owner is idle before its own call');
      assertRefusal(await bounded(owner.exchange(acceptedRequest()), 'unresolved inspection'),
        'INSPECTION_REFUSED');
      assertNothingReachedPeer(state);
      assertNothingReleased(releases);

      /* The ACTUAL positive exchange on this same peer and this same sink: the counters above were
         real, so a peer that never answers can never explain them. */
      assert.deepEqual(await bounded(conversation.exchange(acceptedRequest()), 'same-peer control'),
        { status: 'COMPLETED' });
      assert.equal(state.connections, 1, 'the control opened exactly one connection');
      assert.equal(state.requests, 1, 'and delivered exactly one request');
      assert.equal(releases.length, 1, 'and exactly one guarded release');
      assert.equal(releases[0] === EXPECTED_RELEASE, true,
        'the released text is the declared canonical image');
      await closed(state, 'same-peer control');
    }

    /* The planted secret survives into the final bytes: real policy then selects KEEP over the fixture
       claim and the REAL fixed-worker child blocks. Zero sockets, zero releases. */
    {
      const state = await startHttpPeer(t);
      const runs = [];
      const releases = [];
      const { conversation } = createConversation(state, { runs, releases, suppress: true });
      assertRefusal(await bounded(conversation.exchange(acceptedRequest()), 'upstream sentinel block'),
        'SENTINEL_BLOCKED');
      assert.equal(runs[0].candidates, 1, 'the real detector still found the planted secret');
      assertNothingReachedPeer(state);
      assertNothingReleased(releases);

      /* The positive control on this same peer: the counters above were real. */
      const control = [];
      const positive = createConversation(state, { releases: control });
      assert.deepEqual(await bounded(positive.conversation.exchange(acceptedRequest()), 'control'),
        { status: 'COMPLETED' });
      assert.equal(state.connections, 1, 'the positive control opened exactly one connection');
      assert.equal(state.requests, 1);
      assert.equal(control.length, 1, 'and it delivered exactly one guarded reply');
    }
  });

/* ---------- A reply carrying a registered original releases nothing; the control releases one ---------- */

test('a reply carrying a registered original releases zero application bytes; the control releases one',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const state = await startHttpPeer(t);
    state.next = LEAKY_REPLY_BODY;
    const inbound = [];
    const releases = [];
    const { conversation } = createConversation(state, { inbound, releases });

    /* Policy selected KEEP over every unit, so only the real child stands between this reply and the
       application. The connection happened; the release did not. */
    assertRefusal(await bounded(conversation.exchange(acceptedRequest()), 'registered original'),
      'SENTINEL_BLOCKED');
    assert.equal(state.connections, 1, 'the request did reach the peer exactly once');
    assert.equal(state.requests, 1);
    assertNothingReleased(releases);
    await closed(state, 'registered original');

    /* The positive control on the same peer and the same owner instance: one release, declared bytes. */
    assert.deepEqual(await bounded(conversation.exchange(acceptedRequest()), 'positive control'),
      { status: 'COMPLETED' });
    assert.equal(state.connections, 2, 'the control opened exactly one more connection');
    assert.equal(releases.length, 1, 'exactly one application release across both exchanges');
    assert.equal(releases[0], EXPECTED_RELEASE);
    assert.equal(inbound.length, 2, 'the real detector ran for both accepted translations');
  });

/* ---------- Framing outside the supported profile, truncation and oversize, on one raw peer ---------- */

test('an unsupported, truncated or oversize reply releases nothing; the controls on the same peer release',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const head = (extra) => Buffer.from(
      `HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n${extra}\r\n`, 'utf8');

    /* Each case gets its own raw peer whose FIRST request is answered with the framing under test; a
       later request on that same peer is answered normally, so every refusal is followed by a genuine
       positive control on the same sink and cannot be confused with a peer that never answers. */
    const once = (behaviour) => {
      let used = false;
      return (socket) => {
        if (used) { socket.end(rawReply()); return; }
        used = true;
        behaviour(socket);
      };
    };
    const cases = [
      {
        name: 'chunked', code: 'RESPONSE_REFUSED',
        respond: once((socket) => socket.end(head('Transfer-Encoding: chunked\r\n\r\n1\r\n{\r\n0\r\n\r\n'))),
      },
      {
        name: 'non-200', code: 'RESPONSE_REFUSED',
        respond: once((socket) => socket.end(Buffer.from(
          'HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: http://elsewhere.invalid/\r\n\r\n', 'utf8'))),
      },
      {
        name: 'declared over the bound', code: 'RESPONSE_REFUSED',
        respond: once((socket) => socket.end(head(`Content-Length: ${'9'.repeat(9)}\r\n\r\n`))),
      },
      {
        name: 'duplicate length', code: 'RESPONSE_REFUSED',
        respond: once((socket) => socket.end(head(
          `Content-Length: ${REPLY_BYTES}\r\nContent-Length: ${REPLY_BYTES}\r\n\r\n`))),
      },
      {
        name: 'truncated', code: 'RESPONSE_TRUNCATED',
        respond: once((socket) => { socket.write(rawReply().subarray(0, 40)); socket.destroy(); }),
      },
      {
        name: 'head flood', code: 'RESPONSE_TOO_LARGE',
        respond: once((socket) => { socket.write(Buffer.alloc(HEAD_BOUND * 2, 0x41)); }),
      },
    ];

    for (const entry of cases) {
      const state = await startRawPeer(t, entry.respond);
      const releases = [];
      const { conversation } = createConversation(state, { releases });
      assertRefusal(await bounded(conversation.exchange(acceptedRequest()), entry.name), entry.code);
      assert.equal(state.connections, 1, `${entry.name}: exactly one connection reached the peer`);
      assert.equal(state.requests, 1, `${entry.name}: the peer read exactly one complete request`);
      assert.equal(state.images[0].toString('utf8') === EXPECTED_MASKED_IMAGE, true,
        `${entry.name}: the peer received exactly the declared masked image`);
      assertNothingReleased(releases);
      await closed(state, entry.name);

      /* The positive control on this same peer: the counters above were real and the peer does answer. */
      const control = [];
      const positive = createConversation(state, { releases: control });
      assert.deepEqual(await bounded(positive.conversation.exchange(acceptedRequest()), `${entry.name} control`),
        { status: 'COMPLETED' }, entry.name);
      assert.equal(control.length, 1, `${entry.name}: the control delivered exactly one guarded reply`);
      assert.equal(control[0], EXPECTED_RELEASE, `${entry.name}: and it is the declared canonical image`);
      assert.equal(state.connections, 2, `${entry.name}: the control opened exactly one more connection`);
    }
  });

/* ---------- The reply profile: labeling, head bound and surplus, over one raw peer each ---------- */

test('the head bound, the reply labeling and the surplus profile are decided on the reply alone',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    /* A body that is far larger than the head bound, but a small head. It must be accepted identically
       however the peer happened to segment it, because the bound is on the header block, never on the
       bytes coalesced with it. */
    const BIG_BODY_BYTES = 4_199;
    const BIG_REPLY_BODY = REPLY_BODY.replace(
      'Rotation window 02:00 UTC.', `Rotation window 02:00 UTC.${'x'.repeat(BIG_BODY_BYTES - REPLY_BYTES)}`);
    assert.equal(Buffer.byteLength(BIG_REPLY_BODY, 'utf8') === BIG_BODY_BYTES, true,
      'the declared body is larger than the header bound');
    const bigHead = Buffer.from(
      'HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n'
      + `Content-Length: ${BIG_BODY_BYTES}\r\nConnection: close\r\n\r\n`, 'utf8');
    const bigBody = Buffer.from(BIG_REPLY_BODY, 'utf8');
    const segmentations = [
      {
        name: 'coalesced', respond: (socket) => { socket.end(Buffer.concat([bigHead, bigBody])); },
      },
      {
        // The terminator itself is split across two writes, so the head is never whole in one chunk.
        name: 'segmented', respond: (socket) => {
          socket.write(bigHead.subarray(0, bigHead.byteLength - 2));
          socket.write(bigHead.subarray(bigHead.byteLength - 2));
          socket.end(bigBody);
        },
      },
    ];

    for (const entry of segmentations) {
      const state = await startRawPeer(t, (socket) => { entry.respond(socket); });
      const releases = [];
      const { conversation } = createConversation(state, { releases });
      assert.deepEqual(await bounded(conversation.exchange(acceptedRequest()), entry.name),
        { status: 'COMPLETED' }, entry.name);
      assert.equal(state.connections, 1, `${entry.name}: exactly one connection`);
      assert.equal(state.requests, 1, `${entry.name}: exactly one request`);
      assert.equal(releases.length, 1, `${entry.name}: exactly one guarded release`);
      assert.equal(state.images[0].toString('utf8') === EXPECTED_MASKED_IMAGE, true,
        `${entry.name}: the peer received exactly the declared masked image`);
      await closed(state, entry.name);
    }

    /* The same reply delivered as genuinely SEPARATE received chunks, paced by what the owner's own
       client socket really observed rather than by two adjacent writes. The head minus its final LF is
       sent first; nothing else crosses the wire until the owner's real `data` handler has been handed
       that incomplete head. The terminator therefore spans two received chunks, which is the case the
       adjacent-write version above never produced on a loopback socket. */
    {
      const state = await startRawPeer(t, (socket) => {
        socket.write(bigHead.subarray(0, bigHead.byteLength - 1));
        state.tail = () => { socket.end(Buffer.concat([bigHead.subarray(bigHead.byteLength - 1), bigBody])); };
      });
      const releases = [];
      let observeFirst = () => {};
      const firstChunk = new Promise((resolve) => { observeFirst = resolve; });
      await withOwnerProbe(state.port, async (probe) => {
        probe.afterData((index, chunk) => { if (index === 1) observeFirst(chunk); });
        const { conversation } = createConversation(state, { releases, create: probe.create });
        const pending = bounded(conversation.exchange(acceptedRequest()), 'segmented reply');
        const head = await bounded(firstChunk, 'the owner received the incomplete head');
        assert.equal(head.seen.byteLength, bigHead.byteLength - 1,
          'the first chunk the owner received really was the head minus its final LF');
        assert.equal(head.seen.toString('latin1').includes('\r\n\r\n'), false,
          'the head terminator did NOT arrive whole: it spans the two chunks');
        state.tail();
        assert.deepEqual(await pending, { status: 'COMPLETED' }, 'segmented reply completed');
        assert.equal(probe.chunks.length >= 2, true,
          'the owner received the reply as more than one separate chunk');
        assert.equal(probe.chunks[1].seen.toString('latin1').startsWith('\n'), true,
          'the second received chunk starts with the LF the first one was missing');
        assert.equal(releases.length, 1, 'exactly one guarded release from the segmented reply');
        assert.equal(releases.length, 1, 'the segmented reply released exactly one guarded image');
      });
      await closed(state, 'segmented reply');
    }

    /* Labeling outside the one supported profile is refused, and a balanced quoted charset is not. */
    const labelled = [
      { name: 'unmatched charset quote', header: 'Content-Type: application/json; charset="utf-8\r\n', code: 'RESPONSE_REFUSED' },
      { name: 'mislabelled gzip', header: 'Content-Type: application/json; charset=utf-8\r\nContent-Encoding: gzip\r\n', code: 'RESPONSE_REFUSED' },
      { name: 'identity content encoding', header: 'Content-Type: application/json; charset=utf-8\r\nContent-Encoding: identity\r\n', code: 'RESPONSE_REFUSED' },
    ];
    for (const entry of labelled) {
      const state = await startRawPeer(t, (socket) => { socket.end(Buffer.from(
        `HTTP/1.1 200 OK\r\n${entry.header}Content-Length: ${REPLY_BYTES}\r\n\r\n${REPLY_BODY}`, 'utf8')); });
      const releases = [];
      const { conversation } = createConversation(state, { releases });
      assertRefusal(await bounded(conversation.exchange(acceptedRequest()), entry.name), entry.code);
      assert.equal(state.requests, 1, `${entry.name}: the peer read exactly one request`);
      assertNothingReleased(releases);
      await closed(state, entry.name);
    }

    /* A balanced quoted charset, and a first reply that carries surplus after the declared length, are
       both inside the one supported profile: the surplus is ignored and the socket is closed. */
    const accepted = [
      {
        name: 'quoted utf-8 charset',
        bytes: () => Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/json; charset="utf-8"\r\n`
          + `Content-Length: ${REPLY_BYTES}\r\n\r\n${REPLY_BODY}`, 'utf8'),
      },
      {
        name: 'surplus after the declared length',
        bytes: () => Buffer.concat([rawReply(), Buffer.from('{"surplus":true}', 'utf8')]),
      },
    ];
    for (const entry of accepted) {
      const state = await startRawPeer(t, (socket) => { socket.end(entry.bytes()); });
      const releases = [];
      const { conversation } = createConversation(state, { releases });
      assert.deepEqual(await bounded(conversation.exchange(acceptedRequest()), entry.name),
        { status: 'COMPLETED' }, entry.name);
      assert.equal(releases.length, 1, `${entry.name}: exactly one guarded release`);
      assert.equal(releases[0] === EXPECTED_RELEASE, true,
        `${entry.name}: the release is the declared canonical image, surplus ignored`);
      await closed(state, entry.name);
    }
  });

test('the accepted host methods run on the host receiver they were validated on',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const state = await startHttpPeer(t);
    const releases = [];
    let receiverPreserved = true;
    const observation = OBSERVATION;
    // Declared as real methods on their own object, so a lost `this` is observable from inside.
    const host = {
      port: state.port,
      timeoutMs: DEADLINE_MS,
      observe() {
        if (this !== host) receiverPreserved = false;
        this.observations = (this.observations ?? 0) + 1;
        return observation;
      },
      async onReply(reply) {
        if (this !== host) receiverPreserved = false;
        this.sink = (this.sink ?? []).concat([reply]);
        releases.push(reply);
      },
      sender: {
        boundary: BOUNDARY, sourceTrust: SOURCE_TRUST, policyBundle: BUNDLE, scope: SCOPE,
        known: registration(), sentinel: { deadlineMs: DEADLINE_MS }, inspectOriginal: requestInspect([]),
      },
      receiver: {
        boundary: BOUNDARY, policyBundle: BUNDLE, scope: SCOPE, known: registration(),
        sentinel: { deadlineMs: DEADLINE_MS }, inspect: replyInspect([]),
      },
    };
    const conversation = createOpenAiLocalConversation(host);
    assert.deepEqual(await bounded(conversation.exchange(acceptedRequest()), 'host receiver'),
      { status: 'COMPLETED' });
    assert.equal(receiverPreserved, true,
      'every accepted host method ran on the host object it was validated on');
    assert.equal(state.connections, 1);
    assert.equal(state.requests, 1);
    assert.equal(releases.length, 1);
    assert.equal(releases[0] === EXPECTED_RELEASE, true);
    await closed(state, 'host receiver');
  });

/* ---------- A test-only pass-through probe over the owner's REAL client socket ---------- */

/**
 * One probe, no production hook and no injection point, following #231's fresh-import codec pattern.
 * It exists because two claims are only observable from outside the owner: that a segmented reply
 * really arrives as more than one received chunk, and that every buffer the exchange allocates is
 * zeroed when it ends.
 *
 * Attribution is the whole point, so it is deliberately narrow and every gate says why:
 *
 * - The owner is re-imported under a fresh URL, so the module-scope `TextDecoder` it builds is the
 *   ONLY decoder tracked here. Its dependencies are not re-evaluated (a query string on the entry does
 *   not propagate), so no other decoder can be counted and no other module is re-instrumented.
 * - Only the OWNER's client socket is observed. A socket is the owner's when it is connected TO this
 *   peer's port FROM another port, which is exactly the owner connecting and never the peer accepting;
 *   the peer's own sockets are excluded by construction, not by provenance.
 * - The client's real `data` listener is WRAPPED, not replaced: the owner's handler receives the same
 *   chunk object through the same call, and this test only looks at it. Native `Uint8Array`
 *   construction and `slice` are counted ONLY while that wrapped handler runs, which is precisely the
 *   window in which the owner allocates its received chunks, its head/body joins and its body slice. A
 *   `subarray` view allocates through that same species constructor, so one is counted too; it shares
 *   the storage of a buffer the owner already wipes and can never outlive it.
 * - Everything is restored in the probe's `finally`. Nothing here is a claim about the heap, about any
 *   other process's copies, or about a buffer this module did not allocate.
 */
let ownerProbeSerial = 0;

async function withOwnerProbe(peerPort, run) {
  const nativeDecoder = globalThis.TextDecoder;
  const nativeBytes = globalThis.Uint8Array;
  const nativeOn = net.Socket.prototype.on;
  const ownedDecoders = new WeakSet();
  const chunks = [];
  const allocations = [];
  let decodes = 0;
  let dispatching = false;
  let importing = false;
  let after = () => {};

  class ProbedTextDecoder extends nativeDecoder {
    constructor(...args) {
      super(...args);
      if (importing) ownedDecoders.add(this);
    }
    decode(input, options) {
      if (ownedDecoders.has(this)) decodes += 1;
      return super.decode(input, options);
    }
  }
  class ProbedUint8Array extends nativeBytes {
    constructor(...args) {
      super(...args);
      if (dispatching) allocations.push(this);
    }
  }
  net.Socket.prototype.on = function probedOn(event, listener) {
    if (event !== 'data' || typeof listener !== 'function' || this.remotePort !== peerPort
      || this.localPort === peerPort) return nativeOn.call(this, event, listener);
    const socket = this;
    return nativeOn.call(this, event, (chunk) => {
      // `seen` is a copy taken BEFORE the owner's handler can wipe the live buffer, and `live` is the
      // object the owner itself enrolled and is expected to zero. Both are needed and neither is a
      // claim about anything this owner did not allocate and receive.
      chunks.push({ live: chunk, seen: Buffer.from(chunk) });
      dispatching = true;
      try { Reflect.apply(listener, socket, [chunk]); } finally { dispatching = false; }
      after(chunks.length, chunks[chunks.length - 1]);
    });
  };
  globalThis.TextDecoder = ProbedTextDecoder;
  globalThis.Uint8Array = ProbedUint8Array;
  try {
    importing = true;
    ownerProbeSerial += 1;
    const fresh = await import(`../dist/openai-local-conversation.js?owner-probe=${ownerProbeSerial}`);
    importing = false;
    return await run({
      create: fresh.createOpenAiLocalConversation, probed: ProbedTextDecoder,
      chunks, allocations,
      get decodes() { return decodes; },
      afterData: (handler) => { after = handler; },
    });
  } finally {
    importing = false;
    globalThis.TextDecoder = nativeDecoder;
    globalThis.Uint8Array = nativeBytes;
    net.Socket.prototype.on = nativeOn;
  }
}

/** Nonzero bytes still standing in the buffers this probe observed: zero is the whole claim. */
const unclearedBytes = (buffers) => buffers.reduce(
  (total, buffer) => total + buffer.reduce((count, byte) => count + (byte === 0 ? 0 : 1), 0), 0);

/* ---------- Bounded cleanup, observed from outside the owner over its REAL allocations ---------- */

/**
 * Nonzero bytes standing, at one instant, in every buffer the probe attributes to this owner: the
 * received chunks it enrolled and the buffers it allocated inside its own `data` handler. Zero-length
 * buffers are excluded on purpose - they can never hold a byte, so counting one would make a residual
 * total look measured where nothing was there. The probe's own `seen` copies are host copies and are
 * deliberately NOT in this set: this is a claim about what the owner allocated, never about a copy
 * this test made or about any buffer another process holds.
 */
const ownedResidual = (probe) => unclearedBytes([
  ...probe.chunks.map((entry) => entry.live),
  ...probe.allocations.filter((buffer) => buffer.byteLength > 0),
]);

/**
 * One instant of that same observation, taken inside the wrapped handler's synchronous aftermath: after
 * the owner's own handler returned and before any promise continuation of the exchange has run. It is
 * the only window in which the reply body copy is still observable before its own decode, and it splits
 * the owner's allocations into the ones its `done()` already wiped and the one it had not.
 */
const observationOf = (probe) => ({
  chunk: unclearedBytes(probe.chunks.map((entry) => entry.live)),
  wiped: unclearedBytes(probe.allocations.slice(0, -1)),
  newest: unclearedBytes(probe.allocations.slice(-1)),
  sizes: probe.allocations.map((buffer) => buffer.byteLength),
  decodes: probe.decodes,
});

/** Collect one observation per received data event, on the probe's own restoration-safe hook. */
const observeEveryChunk = (probe, onEvent) => {
  const events = [];
  probe.afterData(() => {
    events.push(observationOf(probe));
    if (onEvent !== undefined) onEvent(events.length);
  });
  return events;
};

/** The one supported reply head, written by hand, so the peer paces a head it can split itself. */
const replyHead = (bodyBytes) => Buffer.from(
  'HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n'
  + `Content-Length: ${bodyBytes}\r\nConnection: close\r\n\r\n`, 'utf8');

/**
 * One raw peer that paces its own reply. The head minus its final LF is written first, and nothing else
 * crosses the wire until the owner's real `data` handler has been handed that incomplete head: the
 * terminator therefore spans two received chunks, and the first data event is observed while every
 * buffer the owner allocated is still standing. `tail()` then delivers the final LF with whatever body
 * bytes the case needs; a case that never calls it is a genuine incomplete reply.
 */
async function pacedPeer(t, body = Buffer.from(REPLY_BODY, 'utf8')) {
  const head = replyHead(body.byteLength);
  const state = await startRawPeer(t, (socket) => {
    socket.write(head.subarray(0, head.byteLength - 1));
    state.tail = (extra = body) => {
      socket.end(Buffer.concat([head.subarray(head.byteLength - 1), extra]));
    };
  });
  state.head = head;
  state.tail = () => { throw new Error('this case never delivers the final LF'); };
  state.bodyBytes = body.byteLength;
  return state;
}

/**
 * Non-vacuity, shared by all four cases below: at the FIRST received chunk the enrolled chunk and the
 * head join the owner allocated over it really did hold bytes. Without this, every later "zero residual"
 * assertion would also hold on an owner that had never allocated anything at all.
 */
const assertAllocatedNotVacuous = (label, first) => {
  assert.equal(first.chunk > 0, true, `${label}: the received chunk really carried bytes`);
  assert.equal(first.newest > 0, true, `${label}: the head join over it really carried bytes`);
};

/* ---------- A timeout and a cancellation leave the application empty and the peer closed ---------- */

test('a silent peer times out and a cancelled exchange releases nothing; both controls release one',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    /* A peer that reads the complete request and never answers. */
    const state = await startRawPeer(t, () => {});
    const releases = [];
    const { conversation } = createConversation(state, { releases, timeoutMs: SHORT_TIMEOUT_MS });
    assertRefusal(await bounded(conversation.exchange(acceptedRequest()), 'timeout'), 'RESPONSE_TIMEOUT');
    assert.equal(state.requests, 1, 'the request itself did reach the peer exactly once');
    assertNothingReleased(releases);
    await closed(state, 'timeout');
    assert.equal(conversation.state, 'IDLE', 'a refusal is not a latch');

    /* The positive control on the same silent peer is not possible - it never answers - so the control
       runs on a peer that does, proving the owner still works after a timed-out exchange. */
    const answering = await startRawPeer(t, (socket) => { socket.end(rawReply()); });
    const control = [];
    const positive = createConversation(answering, { releases: control, timeoutMs: SHORT_TIMEOUT_MS });
    assert.deepEqual(await bounded(positive.conversation.exchange(acceptedRequest()), 'timeout control'),
      { status: 'COMPLETED' });
    assert.equal(control.length, 1);
    assert.equal(control[0], EXPECTED_RELEASE);

    /* Cancellation raised while the peer holds an open, unanswered connection. */
    let observed;
    const arrived = new Promise((resolve) => { observed = resolve; });
    const silent = await startRawPeer(t, () => observed());
    const cancelledReleases = [];
    const owner = createConversation(silent, { releases: cancelledReleases, timeoutMs: DEADLINE_MS });
    const pending = owner.conversation.exchange(acceptedRequest());
    await bounded(arrived, 'cancel: the peer read the request');
    assert.equal(owner.conversation.state, 'BUSY', 'the exchange is in flight');
    /* A second call while one is in flight is refused, never queued and never duplicated. */
    assertRefusal(await bounded(owner.conversation.exchange(acceptedRequest()), 'second call'),
      'CONVERSATION_BUSY');
    assert.equal(silent.requests, 1, 'the refused second call dispatched nothing');
    owner.conversation.cancel();
    assertRefusal(await bounded(pending, 'cancelled exchange'), 'CANCELLED');
    assert.equal(owner.conversation.state, 'CANCELLED', 'cancellation is sticky and owned');
    assertNothingReleased(cancelledReleases);
    await closed(silent, 'cancellation');
    assertRefusal(await bounded(owner.conversation.exchange(acceptedRequest()), 'after cancel'),
      'CANCELLED');
    assert.equal(silent.requests, 1, 'a cancelled owner dispatches nothing further');
  });

/* ---------- One absolute deadline: readiness, final observation and the whole reply share it ------- */

test('an exchange deadline that expires before the write delivers no request at all',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // The one absolute connection-and-reply deadline starts when readiness opens the connection and
    // is never reset. The trusted final observation below costs real, finite time INSIDE that budget:
    // a 150 ms observation against a 50 ms deadline. Readiness itself completes inside its own 50 ms,
    // so the deadline is not spent there - it is spent by the observation that runs after it.
    const BUDGET_MS = 50;
    const OBSERVATION_MS = 150;
    const state = await startRawPeer(t, (socket) => { socket.end(rawReply()); });
    const releases = [];
    const { conversation } = createConversation(state, { releases, timeoutMs: BUDGET_MS });
    // Both observations are finite and both cost the same real time, so this is not a stub: the
    // SECOND one is the dispatch-point observation the sender makes after readiness.
    const owner = createOpenAiLocalConversation({
      port: state.port, timeoutMs: BUDGET_MS,
      observe: () => { spinTo(OBSERVATION_MS); return OBSERVATION; },
      onReply: async (reply) => { releases.push(reply); },
      sender: {
        boundary: BOUNDARY, sourceTrust: SOURCE_TRUST, policyBundle: BUNDLE, scope: SCOPE,
        known: registration(), sentinel: { deadlineMs: DEADLINE_MS },
        inspectOriginal: requestInspect([]),
      },
      receiver: {
        boundary: BOUNDARY, policyBundle: BUNDLE, scope: SCOPE, known: registration(),
        sentinel: { deadlineMs: DEADLINE_MS }, inspect: replyInspect([]),
      },
    });
    assertRefusal(await bounded(owner.exchange(acceptedRequest()), 'expired prepared deadline'),
      'RESPONSE_TIMEOUT');
    assert.equal(state.connections, 1, 'readiness opened exactly one connection');
    assert.equal(state.requests, 0, 'an expired prepared deadline delivers no request');
    assertNothingReleased(releases);
    await closed(state, 'expired prepared deadline');

    /* The live control on the same peer and the same shape with a budget the real observation fits
       inside: the counters above are therefore real, not a peer that never accepted anything. */
    assert.deepEqual(await bounded(conversation.exchange(acceptedRequest()), 'live control'),
      { status: 'COMPLETED' });
    assert.equal(state.requests, 1, 'the live control delivered exactly one exact request');
    assert.equal(releases.length, 1, 'and exactly one guarded release');
    assert.equal(releases[0] === EXPECTED_RELEASE, true);
    await closed(state, 'live control');
  });

/* ---------- An unusable host or endpoint can never dispatch ---------- */

test('an unusable host or an unusable loopback endpoint can never dispatch',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const state = await startHttpPeer(t);
    const releases = [];

    /* A structurally valid host whose endpoint is not one plain numeric port is refused at
       construction, before any owner, socket or composed effect can exist. */
    const base = (over) => ({
      port: state.port, timeoutMs: DEADLINE_MS, observe: () => OBSERVATION,
      onReply: async (reply) => { releases.push(reply); },
      sender: {
        boundary: BOUNDARY, sourceTrust: SOURCE_TRUST, policyBundle: BUNDLE, scope: SCOPE,
        known: registration(), sentinel: { deadlineMs: DEADLINE_MS }, inspectOriginal: requestInspect([]),
      },
      receiver: {
        boundary: BOUNDARY, policyBundle: BUNDLE, scope: SCOPE, known: registration(),
        sentinel: { deadlineMs: DEADLINE_MS }, inspect: replyInspect([]),
      },
      ...over,
    });
    for (const port of [0, -1, 70_000, 1.5, '8080', null, undefined, Number.NaN, { port: state.port }]) {
      const refused = createOpenAiLocalConversation(base({ port }));
      assert.equal(refused.state, 'FAILED', `port ${typeof port}`);
      assertRefusal(await bounded(refused.exchange(acceptedRequest()), `port ${typeof port}`),
        'ENDPOINT_REFUSED');
    }
    /* An out-of-range exchange deadline is a host-shape refusal, not a silently clamped one. */
    for (const timeoutMs of [0, -5, 1.5, '10', null, undefined, Number.NaN, 120_001]) {
      const refused = createOpenAiLocalConversation(base({ timeoutMs }));
      assert.equal(refused.state, 'FAILED', `timeout ${typeof timeoutMs}`);
      assertRefusal(await bounded(refused.exchange(acceptedRequest()), `timeout ${typeof timeoutMs}`),
        'HOST_INVALID');
    }

    /* An extra own key, a missing member and a non-function member are all the one fixed host refusal. */
    const { onReply: unused, ...missing } = base({});
    const hosts = [undefined, null, 'host', base({ extra: 1 }), missing, base({ observe: 'observe' })];
    for (const host of hosts) {
      const refused = createOpenAiLocalConversation(host);
      assert.equal(refused.state, 'FAILED', `host ${typeof host}`);
      assertRefusal(await bounded(refused.exchange(acceptedRequest()), `host ${typeof host}`), 'HOST_INVALID');
    }
    assertNothingReachedPeer(state);
    assertNothingReleased(releases);

    /* A caller cannot travel an endpoint, a route or anything else: the call shape is exactly `body`. */
    const released = [];
    const owner = createConversation(state, { releases: released });
    assertRefusal(await bounded(owner.conversation.exchange({ endpoint: '/v1/chat/completions',
      body: requestBody(MESSAGES) }), 'extra caller key'), 'INVALID_ARGUMENTS');
    assert.equal(state.connections, 0, 'a refused call shape opens no socket');

    assert.deepEqual(await bounded(owner.conversation.exchange(acceptedRequest()), 'accepted shape'),
      { status: 'COMPLETED' });
    assert.equal(released.length, 1);
  });
/* ---------- What the exchange allocates is zeroed when it ends, on all four real endings --------- */

/**
 * The shared shape of the four cleanup cases below. Each one is a real exchange over a real loopback
 * peer with a real reply, differs only in how it ENDS, and is observed through the same pass-through
 * probe. Every claim is a count of bytes or a fixed code: a failing assertion prints no reply, no
 * request, no chunk and no planted value.
 */
async function cleanupCase(t, label, act) {
  const releases = [];
  return withOwnerProbe(act.state.port, async (probe) => {
    const events = observeEveryChunk(probe);
    const { conversation } = createConversation(act.state, {
      releases, timeoutMs: act.timeoutMs, create: probe.create,
    });
    const result = await bounded(act.run(conversation, events), label);
    await closed(act.state, label);
    return { result, releases, events, probe, conversation };
  });
}

test('a completed exchange leaves no nonzero byte in anything it allocated', { timeout: TEST_TIMEOUT_MS },
  async (t) => {
    const state = await pacedPeer(t);
    const { result, releases, events, probe } = await cleanupCase(t, 'success', {
      state,
      run: async (conversation, events) => {
        const pending = conversation.exchange(acceptedRequest());
        await bounded(waitFor(() => events.length >= 1, 'the owner received the incomplete head'),
          'the owner received the incomplete head');
        state.tail();
        return pending;
      },
    });
    assert.deepEqual(result, { status: 'COMPLETED' });
    assert.equal(releases.length, 1, 'the exchange really did release a guarded reply');

    /* Non-vacuous: the owner allocated, and what it allocated really held bytes. */
    assert.equal(events.length >= 2, true, 'the paced reply arrived as separate received chunks');
    assertAllocatedNotVacuous('success', events[0]);
    const final = events[events.length - 1];
    assert.equal(final.wiped, 0,
      'every received chunk and every head join was already zeroed when the data handler returned');
    assert.equal(final.newest, state.bodyBytes,
      'the reply body copy really held exactly its declared bytes, still standing at that instant');
    assert.equal(final.decodes, 0, 'the body had not been decoded at that instant either');

    /* The claim: once the exchange has settled, nothing it allocated holds a byte. */
    assert.equal(ownedResidual(probe), 0, 'no allocated buffer holds a nonzero byte after the exchange');
    /* Exactly two decodes on this owner's own decoder: the received reply body, and the canonical
       release image the receiver hands this owner's release point. Neither is a buffer allocated here. */
    assert.equal(probe.decodes, 2, 'the reply body and the release image were each decoded exactly once');
    assert.equal(probe.chunks.filter((entry) => entry.live.byteLength > 0).length >= 1, true,
      'at least one real received chunk was observed');
  });

test('a complete reply whose body is not decodable leaves no nonzero byte in anything it allocated',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    /* A complete, correctly framed, correctly labelled reply whose one declared body byte is not
       decodable UTF-8. The whole body therefore arrives, the owner's own strict decode fails, and the
       owner refuses - the one ending where a body copy exists and no application byte is ever released. */
    const UNDECODABLE = Buffer.from([0xff]);
    const state = await pacedPeer(t, UNDECODABLE);
    const { result, releases, events, probe } = await cleanupCase(t, 'undecodable body', {
      state,
      run: async (conversation, events) => {
        const pending = conversation.exchange(acceptedRequest());
        await bounded(waitFor(() => events.length >= 1, 'the owner received the incomplete head'),
          'the owner received the incomplete head');
        state.tail();
        return pending;
      },
    });
    assertRefusal(result, 'RESPONSE_REFUSED');
    assert.equal(releases.length, 0, 'an undecodable body releases nothing to the application');
    assertAllocatedNotVacuous('undecodable body', events[0]);
    const final = events[events.length - 1];
    assert.equal(final.wiped, 0, 'the received chunk and the head joins were zeroed in the same handler');
    assert.equal(final.newest, 1, 'the one declared body byte really was standing at that instant');
    assert.equal(ownedResidual(probe), 0,
      'a refused decode still leaves no allocated buffer holding a nonzero byte');
    assert.equal(probe.decodes, 1, 'the strict decode really was attempted exactly once');
  });

test('a reply that stops short of its declared body leaves no nonzero byte in anything it allocated',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    /* The declared body never arrives. The owner legitimately never allocates a completed body copy,
       so this case proves the weaker, honest claim: what it DID allocate is wiped, and it never
       decoded a body that does not exist. */
    const PARTIAL = 16;
    const head = replyHead(REPLY_BYTES);
    const state = await startRawPeer(t, (socket) => {
      socket.write(Buffer.concat([head, Buffer.alloc(PARTIAL, 0x41)]));
    });
    const { result, releases, events, probe } = await cleanupCase(t, 'partial reply', {
      state, timeoutMs: SHORT_TIMEOUT_MS, run: (conversation) => conversation.exchange(acceptedRequest()),
    });
    assertRefusal(result, 'RESPONSE_TIMEOUT');
    assert.equal(releases.length, 0, 'an incomplete reply releases nothing to the application');
    assertAllocatedNotVacuous('partial reply', events[0]);
    assert.equal(events[events.length - 1].newest > 0, true,
      'the partial head join really was still standing when its data handler returned');
    assert.equal(probe.decodes, 0, 'no body was decoded, because no complete body ever arrived');
    assert.equal(probe.allocations.some((buffer) => buffer.byteLength === REPLY_BYTES), false,
      'no body copy of the declared length was ever allocated');
    const whole = head.byteLength + REPLY_BYTES;
    assert.equal(Math.max(...probe.allocations.map((buffer) => buffer.byteLength)) < whole, true,
      'every buffer allocated was strictly smaller than a complete framed reply');
    assert.equal(ownedResidual(probe), 0, 'a timed-out exchange leaves no allocated buffer holding a byte');
  });

test('a cancel queued at body creation, before the decode, releases nothing and leaves no nonzero byte',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    /* Cancellation raised from inside the owner's own `data` handler aftermath: the reply body copy
       exists and is still standing, the exchange's promise continuations have not run yet, and the
       owner's next real step would be the decode. The cancellation therefore lands exactly there. */
    const state = await pacedPeer(t);
    const releases = [];
    let cancelledAt = null;
    let owner = null;
    const { settled, events, probe } = await withOwnerProbe(state.port, async (probeHost) => {
      const eventsHere = observeEveryChunk(probeHost, () => {
        const newest = probeHost.allocations[probeHost.allocations.length - 1];
        // The one event at which the owner created the declared-length body copy, and no other.
        if (cancelledAt === null && newest !== undefined && newest.byteLength === state.bodyBytes) {
          cancelledAt = eventsHere.length;
          owner.cancel();
        }
      });
      owner = createConversation(state, {
        releases, timeoutMs: DEADLINE_MS, create: probeHost.create,
      }).conversation;
      const pending = bounded(owner.exchange(acceptedRequest()), 'cancel at body creation');
      // The tail is delivered only after the owner has really received the incomplete head, so the body
      // copy this cancellation targets is created by the LAST data event and by no other.
      await bounded(waitFor(() => eventsHere.length >= 1, 'the owner received the incomplete head'),
        'the owner received the incomplete head');
      state.tail();
      const settledResult = await pending;
      assert.equal(cancelledAt !== null, true,
        'the owner really did create the declared-length body copy before the exchange settled');
      await closed(state, 'cancel at body creation');
      return { settled: settledResult, events: eventsHere, probe: probeHost };
    });

    assertRefusal(settled, 'CANCELLED');
    assert.equal(releases.length, 0, 'a cancelled exchange releases nothing to the application');
    assertAllocatedNotVacuous('cancel at body creation', events[0]);
    const atCancel = events[cancelledAt - 1];
    assert.equal(atCancel.newest, state.bodyBytes,
      'the body copy really existed and really was standing when the cancellation was queued');
    assert.equal(atCancel.decodes, 0, 'and it had not been decoded at that instant');
    assert.equal(ownedResidual(probe), 0,
      'the abandoned body copy is wiped by the exchange cleanup on this outcome too');
    assert.equal(probe.decodes, 0, 'the body was never decoded at all after the queued cancellation');
  });
