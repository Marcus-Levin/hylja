// #209: an actual HTTP framing round trip over the shipped text sender and the shipped response codec.
//
// What this proves, precisely: one complete, text-only, KEEP-only request produced by the real
// `createOpenAiTextSender` (which itself runs the real fixed-worker sentinel child over the exact bytes)
// is written by the trusted test transport as raw socket bytes to a real `node:http` server on an
// OS-assigned ephemeral 127.0.0.1 port. The server parses one POST with exact framing - the method, the
// path, the exact three-header set, the declared Host label, the UTF-8 Content-Type and the UTF-8
// Content-Length - and its body is compared against a canonical request body declared here as a literal,
// independently of any serializer in `src/`. The server then writes a complete synthetic response, the
// test captures the COMPLETE response bytes off the socket, and the real strict
// `translateOpenAiTextResponse` codec decodes them into the expected synthetic answer.
//
// What it is NOT: a gateway, a listener seam, a provider client, a credential path, an authentication
// proof, a release, a restoration of anything, an inbound protection claim, a scored or held-out result.
// The trusted boundary, the policy pin, the sentinel key, the known-original registration and the
// whole-image classification below are obviously synthetic FIXTURES supplied by this file: nothing here
// authenticates a principal, tenant, workload, profile digest or control plane, and the FOUND detector
// record the inspection fixture supplies is fixture data, not a real detector run. Detector absence
// authorizes nothing anywhere in this repository, so no "no finding means PUBLIC, therefore safe"
// inference is made or needed here. The reply is TRANSLATED and compared inside this test frame and
// nothing else: it is never handed to a caller, a model, a sink or any release surface, so this file
// claims no inbound protection, no cloaking and no original restoration. The trusted transport is this
// file's own raw socket, so what "exact bytes on the wire" means here is measured, not assumed.
//
// Every value is invented and non-routable (`*.invalid`, `example.invalid`, loopback, made-up names).
// Assertions over planted material are counts, booleans and fixed codes only: a failing assertion never
// prints a body, a buffer, an exception message or a planted value into the TAP output.
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { composeClassification, TRUST_LEVELS } from '../dist/classification.js';
import {
  digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE,
} from '../dist/policy.js';
import { createOpenAiTextSender } from '../dist/openai-text-sender.js';
import { OPENAI_TEXT_REQUEST_ENDPOINT } from '../dist/openai-text-request.js';
import { OPENAI_TEXT_RESPONSE_ENDPOINT, translateOpenAiTextResponse } from '../dist/openai-text-response.js';

/** Host-owned sentinel deadline. A check either answers inside it or is stopped at it. */
const DEADLINE_MS = 10_000;
/** Bound every await this file creates, so a stalled child or socket fails loudly instead of hanging. */
const BOUND_MS = 20_000;
const TEST_TIMEOUT_MS = 60_000;

/* ---------- Planted synthetic originals and the registration fixture ---------- */

const SCOPE = Object.freeze({ tenantRef: 'tenant-http-roundtrip.invalid', projectRef: 'project-http.invalid' });
// A dedicated, obviously synthetic sentinel key for this test only. It is not a credential.
const KEY = Uint8Array.from({ length: 32 }, (unused, index) => (index * 13 + 7) & 0xff);
const PLANTED_ORIGINAL = 'avery.synthanon@synthetic-planted.invalid';
const PLANTED_CANARY = 'synthetic-canary-4f02.invalid';
const BENIGN_ENTRIES = Object.freeze([
  Object.freeze({ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'planted.person.1' }),
  Object.freeze({ kind: 'CANARY', value: PLANTED_CANARY, ref: 'planted.canary.1' }),
]);

/* ---------- Trusted test fixture bindings (fixtures, not authenticated identities) ---------- */

const SUBJECT = Object.freeze({ principalId: 'principal-http.invalid', workloadId: 'workload-http.invalid' });
const CONTEXT = Object.freeze({
  tenantId: SCOPE.tenantRef, projectId: SCOPE.projectRef,
  sessionId: 'session-http.invalid', purpose: 'fixture-http-roundtrip.invalid',
});
const SOURCE = Object.freeze({ kind: 'tool.result', ref: 'tool-source-http.invalid', trustZone: 'LOCAL' });
const SOURCE_TRUST = 'TRUSTED';
const HOST_LABEL = 'model-sink-http.example.invalid';
const SINK = Object.freeze({
  kind: 'model', ref: HOST_LABEL, trustZone: 'EXTERNAL', profileId: 'http-sink.invalid',
});
const PROFILE = Object.freeze({
  id: 'http-sink.invalid', sink: SINK, exposure: 'EXTERNAL',
  permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'INTERNAL',
});
const BUNDLE = Object.freeze({
  ...KNOWN_POLICY_BUNDLE,
  profiles: [PROFILE],
  rules: [{
    id: 'http-rule.invalid', profileId: PROFILE.id, semanticType: 'PERSON', sensitivities: ['PUBLIC'],
    sourceTrust: [...TRUST_LEVELS], operations: ['SEND'], decision: 'KEEP',
  }],
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
    identityProof: proof('identity-http.invalid'), requestProof: proof('request-http.invalid'),
  },
  observed: {
    source: SOURCE, destination: SINK,
    sourceProof: proof('source-http.invalid'), routeProof: proof('route-http.invalid'),
  },
});
const COMMIT = Object.freeze({ ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) });
const OBSERVATION = Object.freeze({
  destination: Object.freeze({
    id: SINK.ref, profileDigest: createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex'),
  }),
  commit: COMMIT,
});

/* ---------- The accepted request and the independently declared canonical body ---------- */

const MODEL = 'fixture-model-http-roundtrip';
/**
 * Four messages over three roles. The text deliberately carries JSON escapes (a real newline, a real
 * tab, a quote, a backslash), a combining mark in decomposed form, an astral character and CJK, so a
 * stage that folded, dropped, re-escaped or normalized any of them fails the literal below. Every
 * non-ASCII code point is written as an explicit `\\uXXXX` escape here and in that literal, so the
 * exact code points are reviewable and no editor can silently fold a decomposed sequence into its
 * precomposed form.
 */
const MESSAGES = Object.freeze([
  Object.freeze({ role: 'system', content: 'You are a synthetic fixture assistant.' }),
  Object.freeze({ role: 'user', content: 'Escape me: \n "quoted" \t and a backslash \\ here.' }),
  Object.freeze({ role: 'assistant', content: 'Acknowledged: caf\u00e9 \u{1F600} and \u5408\u6210.' }),
  Object.freeze({ role: 'user', content: 'Compare precomposed \u00e9 with decomposed cafe\u0301 over port 443.' }),
]);
const requestBody = (messages, extra = {}) => JSON.stringify({ model: MODEL, messages, ...extra });
const SAFE_REQUEST_BODY = requestBody(MESSAGES);
const LEAKY_REQUEST_BODY = requestBody([
  { role: 'user', content: `Escalate to ${PLANTED_ORIGINAL} before the window opens.` },
]);
const CANARY_REQUEST_BODY = requestBody([{ role: 'user', content: 'ping' }], { model: PLANTED_CANARY });

/**
 * The canonical request body, declared here as a readable literal. It is never built by a serializer
 * from `src/`: each `\\` below is the single backslash character the JSON wire form requires, and the
 * astral character is written raw in UTF-8 because that is how JSON escapes it.
 */
const EXPECTED_BODY = '{"model":"fixture-model-http-roundtrip","messages":['
  + '{"role":"system","content":"You are a synthetic fixture assistant."},'
  + '{"role":"user","content":"Escape me: \\n \\"quoted\\" \\t and a backslash \\\\ here."},'
  + '{"role":"assistant","content":"Acknowledged: caf\u00e9 \u{1F600} and \u5408\u6210."},'
  + '{"role":"user","content":"Compare precomposed \u00e9 with decomposed cafe\u0301 over port 443."}]}';
const EXPECTED_BODY_BYTES = Buffer.byteLength(EXPECTED_BODY, 'utf8');
/** The framing the server below demands, written as literals on the server side of the boundary. */
const EXPECTED_RAW_HEADERS = Object.freeze([
  'Host', HOST_LABEL,
  'Content-Type', 'application/json; charset=utf-8',
  'Content-Length', String(EXPECTED_BODY_BYTES),
]);
const EXPECTED_REQUEST_LINE = 'POST /v1/chat/completions HTTP/1.1';
const EXPECTED_IMAGE_BYTES = Buffer.byteLength(`${EXPECTED_REQUEST_LINE}\r\nHost: ${HOST_LABEL}\r\n`
  + `Content-Type: application/json; charset=utf-8\r\nContent-Length: ${EXPECTED_BODY_BYTES}\r\n\r\n`
  + EXPECTED_BODY, 'utf8');

/* ---------- The complete synthetic reply the server writes on the wire ---------- */

const RESPONSE_ID = 'chatcmpl-fixture-http-0001';
const RESPONSE_CREATED = 1_700_000_000;
const RESPONSE_ANSWER = 'Round trip complete: caf\u00e9 \u{1F600}, decomposed cafe\u0301, and port 443.';
/**
 * Declared as wire literals: the astral character appears ESCAPED here (as a surrogate pair, which is
 * how JSON carries it) while the combining mark and the accented letter appear as raw UTF-8.
 */
const RESPONSE_BODY = `{"id":"${RESPONSE_ID}","object":"chat.completion","created":${RESPONSE_CREATED},`
  + `"model":"${MODEL}","choices":[{"index":0,"message":{"role":"assistant",`
  + '"content":"Round trip complete: caf\u00e9 \\ud83d\\ude00, decomposed cafe\u0301, and port 443."},'
  + '"finish_reason":"stop"}],"usage":{"prompt_tokens":31,"completion_tokens":19,"total_tokens":50}}';
/** A control reply in a shape the strict codec must refuse by name, never narrow. */
const STREAMING_RESPONSE_BODY = `{"id":"${RESPONSE_ID}","object":"chat.completion.chunk","created":${RESPONSE_CREATED},`
  + `"model":"${MODEL}","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`;

/* ---------- The whole-image inspection fixture: explicit FOUND detector evidence ---------- */

function classificationFor(binding) {
  return composeClassification({
    detectorEvidence: [{
      version: 1, id: 'detector-http.invalid', status: 'FOUND',
      provenance: {
        inputRef: 'field-http.invalid', producerId: 'detector-http.invalid', producerVersion: 'pack-http-1',
      },
      claim: { semanticType: 'PERSON', sensitivity: 'PUBLIC' },
    }],
  }, { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust: SOURCE_TRUST });
}

/**
 * One finding per declared unit, bound to the sender's own image digest and interaction. The record
 * above is FIXTURE data handed in by this file: it is not the output of a real detector run over the
 * image, which is exactly why nothing in this file may read its absence as clearance.
 */
function inspectWholeImage(_image, binding) {
  const classification = classificationFor(binding);
  const classificationDigest = digestClassification(classification);
  return {
    version: 1,
    interactionRef: binding.interactionRef,
    imageDigest: binding.imageDigest,
    coverage: 'COMPLETE',
    remainder: 'NONE',
    units: binding.units.map((unit) => ({
      unitRef: unit.unitRef, classificationDigest, classification,
    })),
  };
}

/* ---------- Bound every await, so a stalled child or socket fails loudly ---------- */

function bounded(promise, label) {
  let timer;
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`deadline exceeded: ${label}`)), BOUND_MS);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

/* ---------- A real node:http server on an ephemeral 127.0.0.1 port ---------- */

/**
 * `answer` selects the complete response the server writes; the streaming variant exists only as a
 * control for the strict codec. The server records everything it actually received and never inspects
 * or approves it: recording a request is not deciding anything.
 */
async function startServer(t, answer = RESPONSE_BODY) {
  const state = {
    connections: 0,
    bodyBytes: 0,
    wireBytes: 0,
    requests: [],
    responses: [],
    sockets: new Set(),
    port: 0,
  };

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('error', () => {});
    res.on('error', () => {});
    req.on('data', (chunk) => {
      state.bodyBytes += chunk.byteLength;
      chunks.push(chunk);
    });
    req.on('end', () => {
      // The header block reaches the parser and the body reaches this stream, so the wire total is
      // read from the socket itself rather than inferred from either.
      const wireBytes = req.socket.bytesRead;
      state.wireBytes += wireBytes;
      state.requests.push({
        method: req.method,
        url: req.url,
        rawHeaders: Array.from(req.rawHeaders),
        host: req.headers.host,
        contentType: req.headers['content-type'],
        contentLength: req.headers['content-length'],
        transferEncoding: req.headers['transfer-encoding'],
        body: Buffer.concat(chunks),
        wireBytes,
      });
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(answer, 'utf8'),
        Connection: 'close',
      });
      res.end(answer);
    });
  });
  server.on('connection', (socket) => {
    state.connections += 1;
    state.sockets.add(socket);
    socket.on('close', () => state.sockets.delete(socket));
    socket.on('error', () => {});
  });

  // Drain every socket and the listener whether or not the test body threw, so an assertion failure
  // still leaves no handle, timer or connection behind. Registered before the listen, so a failed
  // setup cannot strand a bound listener either.
  t.after(async () => {
    for (const socket of state.sockets) socket.destroy();
    state.sockets.clear();
    server.closeAllConnections?.();
    await bounded(new Promise((resolve) => server.close(() => resolve())), 'server shutdown');
  });

  await bounded(new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  }), 'server listen');
  const address = server.address();
  assert.equal(typeof address === 'object' && address !== null && address.address === '127.0.0.1', true,
    'the listener is bound to loopback on an OS-assigned ephemeral port');

  state.port = address.port;
  return state;
}

/** Independent, literal-only framing verdict. No constant from `src/` is used on this side. */
function framingExact(record) {
  return record.method === 'POST'
    && record.url === '/v1/chat/completions'
    && record.host === HOST_LABEL
    && record.contentType === 'application/json; charset=utf-8'
    && record.transferEncoding === undefined
    && record.contentLength === String(EXPECTED_BODY_BYTES)
    && JSON.stringify(record.rawHeaders) === JSON.stringify(EXPECTED_RAW_HEADERS)
    && record.body.equals(Buffer.from(EXPECTED_BODY, 'utf8'));
}

/** Split the COMPLETE captured reply on its own framing, with no help from the client library. */
function splitResponse(bytes) {
  const head = bytes.toString('latin1');
  const split = head.indexOf('\r\n\r\n');
  if (split < 0) return null;
  const lines = head.slice(0, split).split('\r\n');
  const headerOf = (name) => {
    const line = lines.find((candidate) => candidate.toLowerCase().startsWith(`${name}:`));
    return line === undefined ? null : line.slice(name.length + 1).trim();
  };
  return {
    statusLine: lines[0],
    contentType: headerOf('content-type'),
    contentLength: headerOf('content-length'),
    body: bytes.subarray(split + 4),
  };
}

/* ---------- The trusted raw-socket transport owned by this test file ---------- */

/**
 * Writes the exact bytes the sender hands it onto one real loopback socket and captures the COMPLETE
 * reply off that same socket. A rejected promise here becomes `DISPATCH_FAILED` in the sender, so the
 * socket is a real effect boundary and not a recording of an in-memory call.
 */
function rawSocketTransport(state) {
  return async (image) => {
    const socket = net.connect(state.port, '127.0.0.1');
    state.sockets.add(socket);
    socket.on('error', () => {});
    const received = [];
    socket.on('data', (chunk) => received.push(chunk));
    await bounded(new Promise((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    }), 'loopback connect');
    socket.write(Buffer.from(image));
    await bounded(new Promise((resolve) => socket.once('close', resolve)), 'exchange close');
    state.sockets.delete(socket);
    state.responses.push(Buffer.concat(received));
  };
}

function createSender(state) {
  const host = {
    boundary: BOUNDARY,
    sourceTrust: SOURCE_TRUST,
    policyBundle: BUNDLE,
    scope: SCOPE,
    known: { scope: SCOPE, key: KEY, entries: BENIGN_ENTRIES },
    sentinel: { deadlineMs: DEADLINE_MS },
    inspectOriginal: inspectWholeImage,
    sendPoint: {
      observe: () => OBSERVATION,
      sendExact: rawSocketTransport(state),
    },
  };
  return createOpenAiTextSender(host);
}

/** The whole withholding invariant: no connection, no parsed request and no byte reached the server. */
const assertNothingReachedServer = (state) => {
  assert.equal(state.connections, 0, 'the server accepted no connection');
  assert.equal(state.requests.length, 0, 'the server parsed no request');
  assert.equal(state.bodyBytes, 0, 'the server received zero body bytes');
  assert.equal(state.wireBytes, 0, 'the server read zero bytes off the wire');
  assert.equal(state.responses.length, 0, 'no reply was produced');
};

/* ---------- The accepted round trip ---------- */

test('an accepted request crosses one real HTTP exchange and the complete reply decodes to the expected text',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // The declared expectation is canonical JSON, so a mismatch against the sender's serialization
    // cannot be an artifact of a sloppy fixture literal declared above.
    assert.equal(JSON.stringify(JSON.parse(EXPECTED_BODY)) === EXPECTED_BODY, true,
      'the declared canonical body is in canonical JSON form');

    const state = await startServer(t);
    const sender = createSender(state);
    assert.equal(sender.state, 'IDLE');

    assert.deepEqual(await bounded(sender.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'accepted send'), { status: 'SENT' });
    assert.equal(sender.state, 'IDLE');

    /* Exactly one connection and exactly one parsed request reached the server. */
    assert.equal(state.connections, 1, 'exactly one connection');
    assert.equal(state.requests.length, 1, 'exactly one parsed request');
    assert.equal(state.wireBytes, EXPECTED_IMAGE_BYTES, 'exactly the declared image crossed the socket');
    assert.equal(state.bodyBytes, EXPECTED_BODY_BYTES, 'and exactly the declared body reached the parser');

    /* The framing is exact: method, path, the three declared headers and nothing else. */
    const [request] = state.requests;
    assert.equal(request.method, 'POST');
    assert.equal(request.url, '/v1/chat/completions');
    assert.equal(request.host, HOST_LABEL, 'the declared Host label was on the wire');
    assert.equal(request.contentType, 'application/json; charset=utf-8', 'the exact content type');
    assert.equal(request.transferEncoding, undefined, 'no chunked framing was used');
    assert.equal(request.contentLength, String(EXPECTED_BODY_BYTES), 'the UTF-8 byte length was declared');
    assert.equal(JSON.stringify(request.rawHeaders), JSON.stringify(EXPECTED_RAW_HEADERS),
      'the header block is exactly the three declared headers, in order');
    assert.equal(request.body.equals(Buffer.from(EXPECTED_BODY, 'utf8')), true,
      'the body is the independently declared canonical body');
    // Every role, the JSON escapes, the combining mark and the astral character survived the trip.
    assert.equal(request.body.byteLength, EXPECTED_BODY_BYTES);
    let cursor = 0;
    let ordered = true;
    for (const needle of ['role":"system', 'role":"user', 'role":"assistant', 'role":"user']) {
      const index = request.body.indexOf(Buffer.from(needle, 'utf8'), cursor);
      if (index < 0) { ordered = false; break; }
      cursor = index + 1;
    }
    assert.equal(ordered, true, 'every message kept its place in the declared order');
    assert.equal(framingExact(request), true, 'the framing verdict holds for the accepted request');

    /* The COMPLETE reply bytes came off the socket and were decoded by the real strict codec. */
    assert.equal(state.responses.length, 1, 'exactly one captured reply');
    const reply = splitResponse(state.responses[0]);
    assert.equal(reply === null, false, 'the captured reply is framed');
    assert.equal(reply.statusLine, 'HTTP/1.1 200 OK');
    assert.equal(reply.contentType, 'application/json; charset=utf-8');
    assert.equal(reply.contentLength, String(Buffer.byteLength(RESPONSE_BODY, 'utf8')),
      'the complete body was delivered');
    assert.equal(reply.body.byteLength, Buffer.byteLength(RESPONSE_BODY, 'utf8'));

    const result = translateOpenAiTextResponse({
      endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body: reply.body.toString('utf8'),
    });
    assert.equal(result.status, 'TRANSLATED', 'the strict codec accepted the complete reply');
    if (result.status !== 'TRANSLATED') return;
    // Translation only: the decoded draft is compared inside this frame and released to nothing. There
    // is no inspection, classification, policy or authorization of it anywhere in this file, so no
    // inbound protection or restoration claim follows from decoding it here.
    assert.equal(result.draft.operation, 'model.output');
    assert.equal(result.draft.stream.mode, 'complete');
    assert.equal(result.draft.payload.messages.length, 1);
    assert.equal(result.draft.payload.messages[0].role, 'assistant');
    assert.equal(result.draft.payload.messages[0].content === RESPONSE_ANSWER, true,
      'the decoded answer is the expected synthetic text, astral and combining marks included');
    assert.equal(result.draft.metadata.model, MODEL);
    assert.equal(result.draft.metadata.provider, 'openai');
    assert.equal(result.protocol.id, RESPONSE_ID);
    assert.equal(result.protocol.created, RESPONSE_CREATED);
    assert.equal(result.protocol.finish_reason, 'stop');
    assert.deepEqual(result.protocol.usage, { prompt_tokens: 31, completion_tokens: 19, total_tokens: 50 });
  });

/* ---------- Zero effect on refusal, with the positive control on the same server ---------- */

test('an unsupported request, a planted original, a planted canary and a sticky cancellation reach nothing',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    // One server for every case, so the counters that stay at zero below are the same counters the
    // positive control at the end moves to exactly one. A zero is a measurement here, not an absence
    // of observation.
    const state = await startServer(t);

    /* An unsupported request never reaches a socket at all: the codec refuses it first. */
    for (const [name, input, code] of [
      ['unsupported endpoint', { endpoint: '/v1/responses', body: SAFE_REQUEST_BODY }, 'ENDPOINT_NOT_SUPPORTED'],
      ['streaming request', {
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT,
        body: requestBody([{ role: 'user', content: 'hi' }], { stream: true }),
      }, 'STREAMING_NOT_SUPPORTED'],
      ['already parsed body', {
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: { model: MODEL, messages: [] },
      }, 'BODY_NOT_TEXT'],
    ]) {
      const sender = createSender(state);
      assert.deepEqual(await bounded(sender.send(input), name), { status: 'REFUSED', code }, name);
      assert.equal(sender.state, 'IDLE', name);
      assertNothingReachedServer(state);
    }

    /* A planted known original and a planted canary get all the way through translation, policy and
       the whole-image inspection fixture, and are stopped by the REAL fixed-worker sentinel child over
       the exact bytes. No value is inspected here: only the counters and the fixed code are asserted. */
    for (const [name, body] of [
      ['planted original', LEAKY_REQUEST_BODY],
      ['planted canary in the model', CANARY_REQUEST_BODY],
    ]) {
      const sender = createSender(state);
      assert.deepEqual(await bounded(sender.send({
        endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body,
      }), name), { status: 'REFUSED', code: 'SENTINEL_BLOCKED' }, name);
      assert.equal(sender.state, 'IDLE', name);
      assertNothingReachedServer(state);
    }

    /* Cancellation is sticky: the in-flight send and every later one are refused, and neither can
       reach the transport. The cancel lands while the sentinel child check is genuinely running. */
    const cancelled = createSender(state);
    const pending = cancelled.send({ endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY });
    cancelled.cancel();
    assert.equal(cancelled.state, 'CANCELLED');
    assert.deepEqual(await bounded(pending, 'cancelled send'), { status: 'REFUSED', code: 'CANCELLED' });
    assertNothingReachedServer(state);
    assert.deepEqual(await bounded(cancelled.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'send after cancel'), { status: 'REFUSED', code: 'CANCELLED' });
    assertNothingReachedServer(state);

    /* The positive control, on this same server: the counters above were real, and one accepted send
       moves them to exactly one connection, one parsed request and exactly the declared byte count. */
    const control = createSender(state);
    assert.deepEqual(await bounded(control.send({
      endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: SAFE_REQUEST_BODY,
    }), 'positive control'), { status: 'SENT' });
    assert.equal(state.connections, 1, 'the positive control opened exactly one connection');
    assert.equal(state.requests.length, 1, 'the positive control parsed exactly one request');
    assert.equal(state.wireBytes, EXPECTED_IMAGE_BYTES, 'and the declared byte count crossed the socket');
    assert.equal(state.bodyBytes, EXPECTED_BODY_BYTES);
    assert.equal(framingExact(state.requests[0]), true, 'and that request was the declared frame');
    assert.equal(state.responses.length, 1);
  });

/* ---------- The round-trip checks discriminate: controls that must NOT be accepted ---------- */

test('the framing and codec checks bite: a control one header or one character off is not the accepted frame',
  { timeout: TEST_TIMEOUT_MS }, async (t) => {
    const state = await startServer(t);
    const transport = rawSocketTransport(state);

    /* Control 1: correct body and correct Content-Length, but the content type is not the exact
       declared one. The server still parses the request, and the exact framing verdict rejects it. */
    const wrongType = `${EXPECTED_REQUEST_LINE}\r\nHost: ${HOST_LABEL}\r\n`
      + `Content-Type: application/json\r\nContent-Length: ${EXPECTED_BODY_BYTES}\r\n\r\n${EXPECTED_BODY}`;
    await bounded(transport(Buffer.from(wrongType, 'utf8')), 'control 1 exchange');
    assert.equal(state.requests.length, 1, 'the control request really was parsed off the wire');
    assert.equal(state.connections, 1);
    const wrongTypeRecord = state.requests[0];
    assert.equal(wrongTypeRecord.contentType === 'application/json; charset=utf-8', false);
    assert.equal(framingExact(wrongTypeRecord), false, 'a wrong content type is not the declared frame');
    assert.equal(wrongTypeRecord.body.equals(Buffer.from(EXPECTED_BODY, 'utf8')), true,
      'the body itself was still the declared body, so the header is what failed');

    /* Control 2: every declared header exact, but one astral character of the body differs. Same byte
       length, so the declared Content-Length is still right and framing alone cannot catch it. */
    const mutatedBody = EXPECTED_BODY.replace('\u{1F600}', '\u{1F601}');
    assert.equal(Buffer.byteLength(mutatedBody, 'utf8') === EXPECTED_BODY_BYTES, true,
      'the mutated body keeps the declared byte length');
    const wrongByte = `${EXPECTED_REQUEST_LINE}\r\nHost: ${HOST_LABEL}\r\n`
      + `Content-Type: application/json; charset=utf-8\r\nContent-Length: ${EXPECTED_BODY_BYTES}\r\n\r\n${mutatedBody}`;
    await bounded(transport(Buffer.from(wrongByte, 'utf8')), 'control 2 exchange');
    assert.equal(state.requests.length, 2);
    const wrongByteRecord = state.requests[1];
    assert.equal(wrongByteRecord.contentLength, String(EXPECTED_BODY_BYTES));
    assert.equal(wrongByteRecord.body.equals(Buffer.from(EXPECTED_BODY, 'utf8')), false,
      'one changed character fails the canonical body comparison');
    assert.equal(framingExact(wrongByteRecord), false);

    /* Control 3: a complete reply in a shape the strict codec must refuse by name, delivered as real
       socket bytes. The codec refuses it; nothing narrows, drops or forwards it. */
    const streaming = await startServer(t, STREAMING_RESPONSE_BODY);
    await bounded(rawSocketTransport(streaming)(Buffer.from(wrongType, 'utf8')), 'control 3 exchange');
    assert.equal(streaming.responses.length, 1);
    const streamingReply = splitResponse(streaming.responses[0]);
    assert.equal(streamingReply === null, false, 'the control reply is framed');
    assert.deepEqual(translateOpenAiTextResponse({
      endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body: streamingReply.body.toString('utf8'),
    }), { status: 'REFUSED', reason: 'STREAMING_NOT_SUPPORTED' });
  });
