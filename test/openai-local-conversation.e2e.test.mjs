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
  timeoutMs = DEADLINE_MS, port = state.port } = {}) {
  const conversation = createOpenAiLocalConversation({
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
      assert.equal(state.images[0].toString('utf8'), EXPECTED_MASKED_IMAGE,
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