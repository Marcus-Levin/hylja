// #212: the KEEP-only complete OpenAI-compatible response receiver under test.
//
// What this proves, precisely: `createOpenAiKeepReceiver` owns the strict inbound codec, the exact
// private canonical body image of one complete response, the snapshot-bound per-unit classification
// evidence over every variable field of that image, the real deterministic SEND policy decision for
// every unit, the real FIXED-WORKER child process egress sentinel over those exact bytes, and exactly
// one trusted release of the sentinel's own private ALLOW copy. Nothing is ever handed back to a
// caller that could be replayed: there is no READY/prepared handle and no `releasePrepared`.
//
// What it is NOT: a listener, a gateway, a provider client, an authentication proof (the host
// boundary, the policy pin, the sentinel key and the known-original registration are obviously
// synthetic fixtures), a transport, a scoring or enforcement result, a credential store or a
// restoration path. The release point is trusted and this unit cannot prove an arbitrary injected
// release point honors its contract; the capture below is an in-memory recorder owned by this file.
//
// Every value is invented and non-routable (`*.invalid`, documentation literals). Assertions carry
// fixed counts, codes and booleans only: a failing assertion must never print a buffer, an exception
// message or a planted value into the TAP output.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { composeClassification } from '../dist/classification.js';
import { digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE } from '../dist/policy.js';
import { createOpenAiKeepReceiver, OPENAI_KEEP_RECEIVER_REFUSALS } from '../dist/openai-keep-receiver.js';
import { OPENAI_TEXT_RESPONSE_ENDPOINT } from '../dist/openai-text-response.js';

/** Host-owned sentinel deadline. A check either answers inside it or is stopped at it. */
const DEADLINE_MS = 10_000;
/** Bound every await this file creates, so a stalled child fails loudly instead of hanging. */
const BOUND_MS = 20_000;
const TEST_TIMEOUT_MS = 60_000;

/* ---------- Planted synthetic originals and the registration fixture ---------- */

const SCOPE = Object.freeze({ tenantRef: 'tenant-keep-receiver.invalid', projectRef: 'project-keep-receiver.invalid' });
// A dedicated, obviously synthetic sentinel key for this test only. It is not a credential.
const KEY = Uint8Array.from({ length: 32 }, (unused, index) => (index * 7 + 13) & 0xff);
const PLANTED_ORIGINAL = 'avery.synthanon@synthetic-planted.invalid';
const PLANTED_CANARY = 'synthetic-canary-b41d.invalid';
const registration = (entries) => ({ scope: SCOPE, key: KEY, entries });
const BENIGN_ENTRIES = Object.freeze([
  Object.freeze({ kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: 'planted.person.1' }),
  Object.freeze({ kind: 'CANARY', value: PLANTED_CANARY, ref: 'planted.canary.1' }),
]);

/* ---------- Trusted test fixture bindings (not authenticated identities) ---------- */

const SUBJECT = Object.freeze({ principalId: 'principal-keep-receiver.invalid', workloadId: 'workload-keep-receiver.invalid' });
const CONTEXT = Object.freeze({
  tenantId: SCOPE.tenantRef, projectId: SCOPE.projectRef,
  sessionId: 'session-keep-receiver.invalid', purpose: 'fixture-receive.invalid',
});
/** Protected model output is untrusted text at its own source, and the module fixes that itself. */
const SOURCE = Object.freeze({ kind: 'model.response', ref: 'model-response-keep.invalid', trustZone: 'LOCAL' });
const PROVIDER_TRUST = 'UNTRUSTED';
const SINK = Object.freeze({
  kind: 'model', ref: 'model-context-keep.invalid', trustZone: 'LOCAL', profileId: 'keep-receiver-sink.invalid',
});
const PROFILE = Object.freeze({
  id: 'keep-receiver-sink.invalid', sink: SINK, exposure: 'LOCAL',
  permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'INTERNAL',
});
const TRUST_LEVELS = ['CONTROL', 'TRUSTED', 'VERIFIED_EXTERNAL', 'UNTRUSTED', 'HOSTILE'];
const KEEP_RULE = Object.freeze({
  id: 'keep-receiver-rule.invalid', profileId: PROFILE.id, semanticType: 'PERSON', sensitivities: ['PUBLIC'],
  sourceTrust: TRUST_LEVELS, operations: ['SEND'], decision: 'KEEP',
});
const BUNDLE = Object.freeze({ ...KNOWN_POLICY_BUNDLE, profiles: [PROFILE], rules: [KEEP_RULE] });
/** The same profile bound to a non-KEEP treatment, so a withholding outcome is real policy. */
const MASK_BUNDLE = Object.freeze({ ...KNOWN_POLICY_BUNDLE, profiles: [PROFILE], rules: [{ ...KEEP_RULE, decision: 'MASK' }] });
const REVIEW_BUNDLE = Object.freeze({
  ...KNOWN_POLICY_BUNDLE, profiles: [PROFILE],
  rules: [{ ...KEEP_RULE, decision: 'REQUIRE_REVIEW', reviewTreatments: ['MASK'] }],
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
    identityProof: proof('identity-keep-receiver.invalid'), requestProof: proof('request-keep-receiver.invalid'),
  },
  observed: {
    source: SOURCE, destination: SINK,
    sourceProof: proof('source-keep-receiver.invalid'), routeProof: proof('route-keep-receiver.invalid'),
  },
});

/* ---------- The accepted response and the independently declared canonical image ---------- */

const SAFE_ID = 'chatcmpl-keep-receiver-1';
const SAFE_MODEL = 'fixture-model-keep-receiver';
// Astral, combining and punctuation characters: if any stage rewrote, folded or dropped one of them,
// the declared image below would not match what the capture recorded.
const SAFE_CONTENT = 'Café \u{1F600} — synthetic rotation opens at 02:00 UTC; no action is required.';
const SAFE_FINISH = 'stop';

const completion = (fields = {}) => JSON.stringify({
  id: fields.id ?? SAFE_ID,
  object: fields.object ?? 'chat.completion',
  created: 1_760_000_000,
  model: fields.model ?? SAFE_MODEL,
  choices: [{
    index: 0,
    message: { role: 'assistant', content: fields.content ?? SAFE_CONTENT },
    finish_reason: fields.finishReason ?? SAFE_FINISH,
    ...(fields.toolCalls ? { tool_calls: [] } : {}),
  }],
  ...(fields.usage === false ? {} : {
    usage: fields.usage ?? { prompt_tokens: 41, completion_tokens: 17, total_tokens: 58 },
  }),
  ...(fields.unknown ? { system_fingerprint: 'fp_fixture_keep_receiver' } : {}),
});

/**
 * The image the receiver owns, declared field by field from literals only - never from the
 * receiver's own serializer. It is the canonical (JCS-order) body of the complete response, and the
 * three slices below are exactly the byte ranges the receiver declares as inspectable units.
 */
const EXPECTED_PREFIX = '{"choices":[{"finish_reason":"stop","index":0,"message":{"content":';
const EXPECTED_CONTENT_LITERAL = '"Café \u{1F600} — synthetic rotation opens at 02:00 UTC; no action is required."';
const EXPECTED_SUFFIX = ',"role":"assistant"}}],"created":1760000000,'
  + '"id":"chatcmpl-keep-receiver-1","model":"fixture-model-keep-receiver",'
  + '"object":"chat.completion",'
  + '"usage":{"completion_tokens":17,"prompt_tokens":41,"total_tokens":58}}';
const EXPECTED_IMAGE = EXPECTED_PREFIX + EXPECTED_CONTENT_LITERAL + EXPECTED_SUFFIX;
const EXPECTED_IMAGE_BYTES = Buffer.byteLength(EXPECTED_IMAGE, 'utf8');

/** The declared image as bytes, and the three declared unit slices as bytes. */
const expectedImage = () => Buffer.from(EXPECTED_IMAGE, 'utf8');
const expectedUnits = () => [
  { kind: 'PROTOCOL', digest: sha256(EXPECTED_PREFIX) },
  { kind: 'MESSAGE', digest: sha256(EXPECTED_CONTENT_LITERAL) },
  { kind: 'PROTOCOL', digest: sha256(EXPECTED_SUFFIX) },
];
function sha256(text) { return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex'); }

/* ---------- The trusted inspection fixture: snapshot-bound, one finding per declared unit ---------- */

function classificationFor(binding, trust = PROVIDER_TRUST) {
  return composeClassification({
    detectorEvidence: [{
      version: 1, id: 'detector-keep-receiver.invalid', status: 'FOUND',
      provenance: {
        inputRef: 'field-keep-receiver.invalid', producerId: 'detector-keep-receiver.invalid',
        producerVersion: 'pack-keep-receiver-1',
      },
      claim: { semanticType: 'PERSON', sensitivity: 'PUBLIC' },
    }],
  }, { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust });
}

function inspectWholeImage(_image, binding) {
  return {
    version: 1,
    interactionRef: binding.interactionRef,
    imageDigest: binding.imageDigest,
    coverage: 'COMPLETE',
    remainder: 'NONE',
    units: binding.units.map((unit) => {
      const classification = classificationFor(binding);
      return { unitRef: unit.unitRef, classificationDigest: digestClassification(classification), classification };
    }),
  };
}

/* ---------- The trusted host under test, with an in-memory release capture ---------- */

const PROFILE_DIGEST = createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex');
const OTHER_PROFILE_DIGEST = createHash('sha256')
  .update(JSON.stringify({ ...PROFILE, maxCleartextSensitivity: 'RESTRICTED' })).digest('hex');
const COMMIT = Object.freeze({ ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) });
const OBSERVATION = Object.freeze({
  destination: Object.freeze({ id: SINK.ref, profileDigest: PROFILE_DIGEST }), commit: COMMIT,
});

function createHost(options = {}) {
  const captured = [];
  const observations = [];
  let calls = 0;
  const bundle = options.policyBundle ?? BUNDLE;
  const commit = options.commit ?? { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(bundle) };
  for (const entry of options.observations ?? [
    { destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST }, commit },
  ]) observations.push(entry);

  const host = {
    boundary: options.boundary ?? BOUNDARY,
    policyBundle: bundle,
    scope: options.scope ?? SCOPE,
    known: options.known === undefined ? registration(BENIGN_ENTRIES) : options.known,
    sentinel: options.sentinel ?? { deadlineMs: DEADLINE_MS },
    inspect: options.inspect ?? inspectWholeImage,
    releasePoint: {
      // Queued observations: the first call is the one the check is made against, the second is what
      // the release point reports immediately before the release, and later calls clamp to the last.
      observe: () => observations[Math.min(calls++, observations.length - 1)],
      releaseExact: async (image) => { captured.push(Buffer.from(image)); },
    },
  };
  for (const [key, value] of Object.entries(options.host ?? {})) host[key] = value;
  return { host, captured };
}

function harness(options = {}) {
  const { host, captured } = createHost(options);
  return { captured, host, receiver: createOpenAiKeepReceiver(host) };
}

const receive = (receiver, body, label) => bounded(
  receiver.receive({ endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body }), label ?? 'receive',
);

function bounded(promise, label) {
  let timer;
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`deadline exceeded: ${label}`)), BOUND_MS);
  });
  return Promise.race([promise, expiry]).finally(() => clearTimeout(timer));
}

/** The whole withholding invariant in one helper: no release invocation and no captured byte. */
const assertNothingReleased = (captured) => {
  assert.equal(captured.length, 0, 'the release point was invoked zero times');
};

/* ---------- The API surface ---------- */

test('the receiver exposes receive, cancel and state, and no prepared or replayable release handle',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const { receiver } = harness();
    assert.deepEqual(Object.keys(receiver).sort(), ['cancel', 'receive', 'state']);
    assert.equal(receiver.state, 'IDLE');
    for (const name of ['prepare', 'releasePrepared', 'releaseExact', 'inspect', 'image', 'bytes', 'ready']) {
      assert.equal(name in receiver, false, `${name} is not part of the receiver surface`);
    }
    assert.equal(typeof receiver.receive, 'function');
    assert.equal(typeof receiver.cancel, 'function');
    // The published refusal vocabulary is a closed, fixed list of codes.
    assert.equal(OPENAI_KEEP_RECEIVER_REFUSALS.includes('SENTINEL_BLOCKED'), true);
    assert.equal(OPENAI_KEEP_RECEIVER_REFUSALS.includes('RECEIVER_BUSY'), true);
    assert.equal(OPENAI_KEEP_RECEIVER_REFUSALS.includes('CANCELLED'), true);
  });

/* ---------- The accepted path ---------- */

test('an accepted complete response is released exactly once as the independently declared canonical image',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const { receiver, captured } = harness();
    const result = await receive(receiver, completion());

    assert.deepEqual(result, { status: 'RELEASED' });
    assert.equal(receiver.state, 'IDLE');
    assert.deepEqual(Object.keys(result), ['status'], 'the result carries no bytes and no handle');

    assert.equal(captured.length, 1, 'exactly one trusted release');
    const released = captured[0];
    // Byte-for-byte, compared as a boolean: a failing diff must not print the image into TAP output.
    assert.equal(released.equals(expectedImage()), true, 'the capture recorded the declared image');
    assert.equal(released.byteLength, EXPECTED_IMAGE_BYTES);
    // Literal troubleshooting facts, asserted independently of anything the receiver computed.
    const image = released.toString('utf8');
    assert.equal(image.startsWith(EXPECTED_PREFIX), true);
    assert.equal(image.endsWith(EXPECTED_SUFFIX), true);
    assert.equal(image.includes('chatcmpl-keep-receiver-1'), true);
    assert.equal(image.includes('fixture-model-keep-receiver'), true);
    assert.equal(image.includes('chat.completion'), true);
    assert.equal(image.includes('"total_tokens":58'), true);
    assert.equal(image.includes('é'), true, 'a combining character survived');
    assert.equal(image.includes('\u{1F600}'), true, 'an astral character survived');
    // The released image parses back to exactly the accepted response, in canonical key order.
    const parsed = JSON.parse(image);
    assert.equal(parsed.object, 'chat.completion');
    assert.equal(parsed.id, SAFE_ID);
    assert.equal(parsed.model, SAFE_MODEL);
    assert.equal(parsed.created, 1_760_000_000);
    assert.equal(parsed.choices.length, 1);
    assert.equal(parsed.choices[0].index, 0);
    assert.equal(parsed.choices[0].finish_reason, SAFE_FINISH);
    assert.equal(parsed.choices[0].message.role, 'assistant');
    assert.equal(parsed.choices[0].message.content, SAFE_CONTENT);
    assert.deepEqual(parsed.usage, { completion_tokens: 17, prompt_tokens: 41, total_tokens: 58 });
  });

test('every variable field of the image is covered by its own snapshot-bound unit and finding',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const bindings = [];
    const { receiver, captured } = harness({
      inspect: (image, binding) => {
        bindings.push({ binding, image: Buffer.from(image) });
        return inspectWholeImage(image, binding);
      },
    });
    assert.deepEqual(await receive(receiver, completion()), { status: 'RELEASED' });

    assert.equal(bindings.length, 1);
    const { binding, image } = bindings[0];
    assert.equal(binding.version, 1);
    assert.equal(/^[0-9a-f]{64}$/u.test(binding.imageDigest), true, 'the binding carries the image digest');
    // The binding pins the receiver's own private snapshot: an independent digest of what it holds.
    assert.equal(binding.imageDigest, createHash('sha256').update(image).digest('hex'));
    assert.equal(image.equals(expectedImage()), true, 'the inspected copy is the declared image');

    // Three declared units, in wire order, each pinned to the exact bytes it names.
    assert.equal(binding.units.length, 3);
    assert.deepEqual(binding.units.map((unit) => unit.kind), ['PROTOCOL', 'MESSAGE', 'PROTOCOL']);
    assert.equal(new Set(binding.units.map((unit) => unit.unitRef)).size, binding.units.length,
      'each unit carries its own distinct opaque reference');
    const declared = expectedUnits();
    binding.units.forEach((unit, index) => {
      assert.equal(unit.kind, declared[index].kind);
      assert.equal(unit.digest, declared[index].digest,
        `unit ${index} is pinned to its declared byte range of the declared image`);
    });
    // The three declared ranges are contiguous and cover the whole image: no byte sits outside a unit.
    assert.equal(binding.units[0].digest, sha256(EXPECTED_PREFIX));
    assert.equal(binding.units[1].digest, sha256(EXPECTED_CONTENT_LITERAL));
    assert.equal(binding.units[2].digest, sha256(EXPECTED_SUFFIX));
    assert.equal(captured.length, 1);
    assert.equal(captured[0].byteLength, EXPECTED_IMAGE_BYTES);
  });

test('a later caller mutation and any mutation of the inspection copy change no released byte',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const input = { endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body: completion() };
    const { receiver, captured } = harness({
      inspect: (image, binding) => {
        // The callback is handed its OWN copy: scribbling on it cannot reach the released bytes.
        // Rewriting the caller's own input during the inspection proves the image was already
        // snapshotted before any await.
        image.fill(0x41);
        input.endpoint = '/v1/responses';
        input.body = completion({ content: PLANTED_ORIGINAL });
        return inspectWholeImage(image, binding);
      },
    });
    assert.deepEqual(await bounded(receiver.receive(input), 'mutating inspection'), { status: 'RELEASED' });
    assert.equal(captured.length, 1);
    assert.equal(captured[0].equals(expectedImage()), true, 'the released image is the declared image');
    assert.equal(captured[0].includes(PLANTED_ORIGINAL), false, 'no planted value reached the release point');
  });

/* ---------- The real fixed-worker sentinel over the exact private image ---------- */

test('a planted original or canary in the content, the model or the id releases zero bytes',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    for (const [name, fields] of [
      ['planted original in the assistant content', { content: `Escalate to ${PLANTED_ORIGINAL} before the window.` }],
      ['planted canary in the model metadata', { model: PLANTED_CANARY }],
      ['planted original in the protocol id', { id: PLANTED_ORIGINAL }],
      ['planted canary in the assistant content', { content: `The window token is ${PLANTED_CANARY}.` }],
    ]) {
      const { receiver, captured } = harness();
      const result = await receive(receiver, completion(fields), name);
      assert.deepEqual(result, { status: 'REFUSED', code: 'SENTINEL_BLOCKED' }, name);
      assertNothingReleased(captured);
      assert.equal(receiver.state, 'IDLE', name);
      assert.equal(JSON.stringify(result).includes(PLANTED_ORIGINAL), false, name);
      assert.equal(JSON.stringify(result).includes(PLANTED_CANARY), false, name);
    }

    // Positive control on the same chain: an answer the registration genuinely misses is released.
    const control = harness();
    assert.deepEqual(await receive(control.receiver, completion(), 'control'), { status: 'RELEASED' });
    assert.equal(control.captured[0].equals(expectedImage()), true);
  });

test('a sentinel failure and an unusable runner configuration release zero bytes',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    for (const [name, options] of [
      ['deadline below the module floor', { sentinel: { deadlineMs: 1 } }],
      ['unsupported runner key', { sentinel: { deadlineMs: DEADLINE_MS, signal: null } }],
      ['foreign known-original scope', {
        known: { scope: { tenantRef: 'tenant-other.invalid', projectRef: SCOPE.projectRef }, key: KEY, entries: [] },
      }],
      ['no known originals to check under', { known: null }],
    ]) {
      const { receiver, captured } = harness(options);
      const expected = name === 'no known originals to check under' ? 'RELEASED' : 'SENTINEL_BLOCKED';
      const result = await receive(receiver, completion(), name);
      if (expected === 'RELEASED') {
        // An explicit null registration is an accepted statement that this egress has none to
        // protect; it is not a weakening of any check the child would otherwise have run.
        assert.deepEqual(result, { status: 'RELEASED' }, name);
        assert.equal(captured.length, 1, name);
      } else {
        assert.deepEqual(result, { status: 'REFUSED', code: 'SENTINEL_BLOCKED' }, name);
        assertNothingReleased(captured);
        assert.equal(receiver.state, 'IDLE', name);
      }
    }
  });

/* ---------- The captured scope and registration the child is asked to check under ---------- */

test('a host that rewrites its own scope, registration scope, key or entries cannot retarget the check',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    // The planted original is in the assistant content and the fixture classifies the whole image PUBLIC
    // with detector evidence, so real policy selects KEEP for every unit and the receive really reaches
    // the real child. Only the sentinel's own known-original registration can withhold it from there.
    const body = completion({ content: `Escalate to ${PLANTED_ORIGINAL} before the window.` });
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
      const { host, captured } = createHost({
        // A finite inspection that rewrites the host's own members after they were handed over. The
        // receiver still checks under the scope and registration it captured privately.
        inspect: (image, binding) => { rewrite(alias); return inspectWholeImage(image, binding); },
        host: { scope: alias.scope, known: alias.known },
      });
      const receiver = createOpenAiKeepReceiver(host);
      const result = await receive(receiver, body, name);
      assert.deepEqual(result, { status: 'REFUSED', code: 'SENTINEL_BLOCKED' }, name);
      assertNothingReleased(captured);
      assert.equal(receiver.state, 'IDLE', name);
      assert.equal(JSON.stringify(result).includes(PLANTED_ORIGINAL), false, name);
    }

    // An unknown own key on the registration is still one fixed restrictive refusal and no effect.
    const unknown = aliasHost();
    unknown.known.clearance = 'PUBLIC';
    const unusable = createHost({ host: { scope: unknown.scope, known: unknown.known } });
    const unusableReceiver = createOpenAiKeepReceiver(unusable.host);
    const unusableResult = await receive(unusableReceiver, body, 'unknown registration key');
    assert.deepEqual(unusableResult, { status: 'REFUSED', code: 'SENTINEL_BLOCKED' });
    assertNothingReleased(unusable.captured);
    assert.equal(unusableReceiver.state, 'IDLE');

    // Positive control on the same mechanism: a benign rewrite that keeps the captured tenant A values
    // releases normally. Capturing a private copy is not a rule that revokes on any host-side mutation,
    // and no such automatic revocation rule is invented here.
    const benign = aliasHost();
    const benignHost = createHost({
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
    const benignReceiver = createOpenAiKeepReceiver(benignHost.host);
    assert.deepEqual(await receive(benignReceiver, completion(), 'benign host rewrite'), { status: 'RELEASED' });
    assert.equal(benignHost.captured.length, 1);
    assert.equal(benignHost.captured[0].equals(expectedImage()), true,
      'a benign host rewrite still releases the declared image');
    assert.equal(benignReceiver.state, 'IDLE');
  });

/* ---------- Unsupported, ambiguous, opaque, multi-choice and streaming output ---------- */

test('unsupported, duplicate, opaque, multi-choice and streaming output refuses before any release',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const multiChoice = JSON.stringify({
      id: SAFE_ID, object: 'chat.completion', created: 1_760_000_000, model: SAFE_MODEL,
      choices: [
        { index: 0, message: { role: 'assistant', content: SAFE_CONTENT }, finish_reason: 'stop' },
        { index: 1, message: { role: 'assistant', content: PLANTED_ORIGINAL }, finish_reason: 'stop' },
      ],
    });
    const cases = [
      ['tools', completion({ toolCalls: true }), 'UNSUPPORTED_TOOLS'],
      ['streaming object', completion({ object: 'chat.completion.chunk' }), 'STREAMING_NOT_SUPPORTED'],
      ['unknown top-level field', completion({ unknown: true }), 'UNEXPECTED_FIELD'],
      ['malformed text', '{"id":"chatcmpl-keep-receiver-1","object":"chat.completion",', 'MALFORMED_JSON'],
      ['duplicate key', `{"id":"a","id":"b","object":"chat.completion","created":1,"model":"m","choices":[]}`, 'AMBIGUOUS_BODY'],
      ['opaque multimodal content', JSON.stringify({
        id: SAFE_ID, object: 'chat.completion', created: 1_760_000_000, model: SAFE_MODEL,
        choices: [{
          index: 0, message: { role: 'assistant', content: [{ type: 'text', text: SAFE_CONTENT }] },
          finish_reason: 'stop',
        }],
      }), 'UNSUPPORTED_CONTENT'],
      ['opaque null content', JSON.stringify({
        id: SAFE_ID, object: 'chat.completion', created: 1_760_000_000, model: SAFE_MODEL,
        choices: [{ index: 0, message: { role: 'assistant', content: null }, finish_reason: 'stop' }],
      }), 'UNSUPPORTED_CONTENT'],
      ['no choices', JSON.stringify({
        id: SAFE_ID, object: 'chat.completion', created: 1_760_000_000, model: SAFE_MODEL, choices: [],
      }), 'NO_CHOICES'],
      ['multiple choices', multiChoice, 'MULTIPLE_CHOICES'],
      ['unsupported role', JSON.stringify({
        id: SAFE_ID, object: 'chat.completion', created: 1_760_000_000, model: SAFE_MODEL,
        choices: [{ index: 0, message: { role: 'system', content: SAFE_CONTENT }, finish_reason: 'stop' }],
      }), 'UNSUPPORTED_ROLE'],
      ['unsupported finish reason', completion({ finishReason: 'tool_calls' }), 'UNSUPPORTED_FINISH_REASON'],
      ['bad usage', completion({ usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 3 } }), 'INVALID_USAGE'],
      // A caller cannot smuggle authority, a destination, a profile or a policy through the payload.
      ['extra own key', { endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body: completion(), trust: 'TRUSTED' }, 'INVALID_ARGUMENTS'],
      ['unsupported endpoint', { endpoint: '/v1/responses', body: completion() }, 'ENDPOINT_NOT_SUPPORTED'],
      ['already parsed body', { endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body: { id: SAFE_ID } }, 'BODY_NOT_TEXT'],
    ];
    for (const [name, input, code] of cases) {
      const { receiver, captured } = harness();
      const result = await bounded(
        receiver.receive(typeof input === 'string'
          ? { endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body: input } : input),
        name,
      );
      assert.deepEqual(result, { status: 'REFUSED', code }, name);
      assertNothingReleased(captured);
      assert.equal(receiver.state, 'IDLE', name);
      assert.equal(JSON.stringify(result).includes(PLANTED_ORIGINAL), false, name);
    }
  });

/* ---------- The snapshot-bound inspection handoff ---------- */

test('missing, partial, foreign, substituted or detector-free evidence never authorizes',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const whole = (_image, binding) => inspectWholeImage(_image, binding);
    const semanticOnly = (binding) => composeClassification({
      semanticJudgments: [{
        version: 1, id: 'judge-keep-receiver.invalid', status: 'FOUND',
        provenance: {
          inputRef: 'field-keep-receiver.invalid', producerId: 'judge-keep-receiver.invalid',
          producerVersion: 'judge-keep-receiver-1', questionSetVersion: 'q-keep-receiver-1',
          modelId: 'model-judge.invalid',
        },
        claim: { semanticType: 'PERSON', sensitivity: 'PUBLIC' },
      }],
    }, { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust: PROVIDER_TRUST });

    const cases = [
      ['no findings at all', () => undefined],
      ['empty finding list', (_image, binding) => ({ ...whole(_image, binding), units: [] })],
      ['a missing unit', (_image, binding) => {
        const result = whole(_image, binding);
        return { ...result, units: result.units.slice(0, 2) };
      }],
      ['a duplicated unit', (_image, binding) => {
        const result = whole(_image, binding);
        return { ...result, units: [...result.units, result.units[0]] };
      }],
      ['an invented unit', (_image, binding) => {
        const result = whole(_image, binding);
        return { ...result, units: [...result.units, { ...result.units[0], unitRef: 'invented-unit' }] };
      }],
      ['a foreign image digest', (_image, binding) => ({ ...whole(_image, binding), imageDigest: '0'.repeat(64) })],
      ['a foreign interaction', (_image, binding) => ({ ...whole(_image, binding), interactionRef: 'invented.invalid' })],
      ['a remainder that is not cleared', (_image, binding) => ({ ...whole(_image, binding), remainder: 'UNKNOWN' })],
      ['a coverage that is not complete', (_image, binding) => ({ ...whole(_image, binding), coverage: 'PARTIAL' })],
      ['an unknown own key', (_image, binding) => ({ ...whole(_image, binding), clearance: 'PUBLIC' })],
      ['a substituted classification', (_image, binding) => {
        const result = whole(_image, binding);
        return { ...result, units: result.units.map((unit) => ({ ...unit, classificationDigest: '1'.repeat(64) })) };
      }],
      ['an unresolved record', (_image, binding) => {
        const result = whole(_image, binding);
        return {
          ...result,
          units: result.units.map((unit) => ({
            unitRef: unit.unitRef,
            classificationDigest: digestClassification({
              ...unit.classification, status: 'UNRESOLVED', semanticType: 'UNKNOWN',
              sensitivity: 'UNKNOWN', reasons: ['synthetic.unresolved'], evidence: [],
            }),
            classification: {
              ...unit.classification, status: 'UNRESOLVED', semanticType: 'UNKNOWN',
              sensitivity: 'UNKNOWN', reasons: ['synthetic.unresolved'], evidence: [],
            },
          })),
        };
      }],
      ['a semantic-only clearance with no detector', (_image, binding) => {
        // A model-only PUBLIC judgment is not evidence: absence of a detector finding is never
        // clearance, and this receiver never turns an absent finding into a PUBLIC assumption.
        const result = whole(_image, binding);
        const record = semanticOnly(binding);
        return {
          ...result,
          units: result.units.map((unit) => ({
            unitRef: unit.unitRef, classificationDigest: digestClassification(record), classification: record,
          })),
        };
      }],
      ['a classification that is not an object', (_image, binding) => {
        const result = whole(_image, binding);
        return { ...result, units: result.units.map((unit) => ({ ...unit, classification: 'PUBLIC' })) };
      }],
      ['an inspection that throws', () => { throw new Error(`inspection failed: ${PLANTED_ORIGINAL}`); }],
    ];

    for (const [name, inspect] of cases) {
      const { receiver, captured } = harness({ inspect });
      const result = await receive(receiver, completion(), name);
      assert.deepEqual(result, { status: 'REFUSED', code: 'INSPECTION_REFUSED' }, name);
      assertNothingReleased(captured);
      assert.equal(receiver.state, 'IDLE', name);
    }
  });

/* ---------- Policy: only a real per-unit SELECTED KEEP releases ---------- */

test('a non-KEEP treatment, a held review, a foreign context and a stale policy pin all withhold',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    for (const [name, options, code] of [
      ['MASK treatment', { policyBundle: MASK_BUNDLE }, 'POLICY_NOT_KEEP'],
      ['REQUIRE_REVIEW', { policyBundle: REVIEW_BUNDLE }, 'POLICY_HELD'],
      ['stale policy pin', { commit: { ...KNOWN_POLICY_BUNDLE, digest: OTHER_PROFILE_DIGEST } }, 'POLICY_DENIED'],
      ['foreign tenant scope', { scope: { tenantRef: 'tenant-other.invalid', projectRef: SCOPE.projectRef } }, 'SCOPE_REFUSED'],
      ['a classification that elevated its own trust', {
        inspect: (_image, binding) => {
          const result = inspectWholeImage(_image, binding);
          return {
            ...result,
            units: result.units.map((unit) => {
              const record = classificationFor(binding, 'TRUSTED');
              return { unitRef: unit.unitRef, classificationDigest: digestClassification(record), classification: record };
            }),
          };
        },
      }, 'POLICY_DENIED'],
      ['a foreign boundary destination', {
        boundary: {
          ...BOUNDARY,
          observed: {
            ...BOUNDARY.observed,
            destination: { ...SINK, profileId: 'foreign-sink.invalid' },
            routeProof: proof('route-foreign-keep-receiver.invalid'),
          },
        },
      }, 'POLICY_DENIED'],
    ]) {
      const { receiver, captured } = harness(options);
      const result = await receive(receiver, completion(), name);
      assert.deepEqual(result, { status: 'REFUSED', code }, name);
      assertNothingReleased(captured);
      assert.equal(receiver.state, 'IDLE', name);
    }

    // A length that exceeds the fixed canonical serializer bound is refused, not truncated.
    const { receiver, captured } = harness();
    const long = await receive(receiver, completion({ content: 'x'.repeat(4_200) }), 'over-bound content');
    assert.deepEqual(long, { status: 'REFUSED', code: 'IMAGE_REFUSED' });
    assertNothingReleased(captured);
  });

/* ---------- The dispatch-point re-reads ---------- */

test('a route, profile or policy commit that changes before the release refuses with no await between',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    for (const [name, second, code] of [
      ['route changed', { destination: { id: 'other-context.invalid', profileDigest: PROFILE_DIGEST }, commit: COMMIT }, 'ROUTE_CHANGED'],
      ['profile changed', { destination: { id: SINK.ref, profileDigest: OTHER_PROFILE_DIGEST }, commit: COMMIT }, 'ROUTE_CHANGED'],
      ['policy commit changed', {
        destination: { id: SINK.ref, profileDigest: PROFILE_DIGEST },
        commit: { ...KNOWN_POLICY_BUNDLE, digest: OTHER_PROFILE_DIGEST },
      }, 'POLICY_STALE'],
      ['an unusable route at the release point', { destination: null, commit: COMMIT }, 'ROUTE_REFUSED'],
    ]) {
      // Observation 0 is what the check is made against; observation 1 is what the release point
      // reports immediately before the release, in the same synchronous turn as the release.
      const { receiver, captured } = harness({ observations: [OBSERVATION, second] });
      const result = await receive(receiver, completion(), name);
      assert.deepEqual(result, { status: 'REFUSED', code }, name);
      assertNothingReleased(captured);
      assert.equal(receiver.state, 'IDLE', name);
    }

    // A hostile observed label is refused at the route boundary, before any image exists.
    const { receiver, captured } = harness({
      observations: [{ destination: { id: `evil.invalid`, profileDigest: PROFILE_DIGEST }, commit: COMMIT }],
    });
    assert.deepEqual(await receive(receiver, completion(), 'hostile route label'),
      { status: 'REFUSED', code: 'ROUTE_REFUSED' });
    assertNothingReleased(captured);
  });

test('boundary evidence that expires during a finite inspection never authorizes a release',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    // One proof window, and the real elapsed time this fixture spends inside the trusted inspection
    // under it. Nothing is stubbed: the envelope, the receiver and the freshness re-read all read the
    // same real `Date.now()`, and time only moves forward, so this cannot flake the other way.
    const PROOF_WINDOW_MS = 200;
    const INSPECTION_MS = 600;
    const spinTo = (deadline) => {
      for (let now = Date.now(); now < deadline; now = Date.now()) { /* finite real inspection */ }
    };

    for (const [name, windowMs, expected] of [
      ['expired before the release', PROOF_WINDOW_MS, 'INTERACTION_REFUSED'],
      ['still current at the release', 60_000, 'RELEASED'],
    ]) {
      const issuedAt = Date.now();
      const fresh = (ref) => Object.freeze({
        ref, issuedAt: new Date(issuedAt).toISOString(),
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
      const { receiver, captured } = harness({
        boundary,
        inspect: (image, binding) => {
          spinTo(issuedAt + INSPECTION_MS);
          return inspectWholeImage(image, binding);
        },
      });
      const result = await receive(receiver, completion(), name);
      if (expected === 'RELEASED') {
        assert.deepEqual(result, { status: 'RELEASED' }, name);
        assert.equal(captured.length, 1, name);
        assert.equal(captured[0].equals(expectedImage()), true, name);
      } else {
        assert.deepEqual(result, { status: 'REFUSED', code: expected }, name);
        assertNothingReleased(captured);
      }
      assert.equal(receiver.state, 'IDLE', name);
    }
  });

test('boundary evidence that cannot be bound refuses with INTERACTION_REFUSED and no release',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    // Independently bound evidence, not receiver-owned: each boundary below is structurally an
    // accepted host member and fails only where the envelope binds it to this interaction.
    for (const [name, boundary] of [
      ['an expired route proof', {
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
      ['an identity proof with an extra own key', {
        ...BOUNDARY,
        authenticated: {
          ...BOUNDARY.authenticated,
          identityProof: { ...proof('identity-unknown-key.invalid'), signature: 'synthetic-not-a-proof' },
        },
      }],
    ]) {
      const { receiver, captured } = harness({ boundary });
      assert.deepEqual(await receive(receiver, completion(), name),
        { status: 'REFUSED', code: 'INTERACTION_REFUSED' }, name);
      assertNothingReleased(captured);
      assert.equal(receiver.state, 'IDLE', name);
    }
  });

/* ---------- Cancellation, contention and an unusable host ---------- */

test('cancellation inside the trusted inspection withholds the release and disables the receiver',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const owner = { receiver: null };
    let ran = 0;
    const { host, captured } = createHost({
      inspect: (image, binding) => {
        ran += 1;
        // A cancellation raised inside the trusted inspection is read again at the release point, so
        // the release point is never invoked even though the sentinel check already ran.
        owner.receiver.cancel();
        return inspectWholeImage(image, binding);
      },
    });
    const receiver = createOpenAiKeepReceiver(host);
    owner.receiver = receiver;
    assert.deepEqual(await receive(receiver, completion(), 'cancelled inside the inspection'),
      { status: 'REFUSED', code: 'CANCELLED' });
    assert.equal(ran, 1, 'the inspection really ran');
    assertNothingReleased(captured);
    assert.equal(receiver.state, 'CANCELLED');

    // A cancelled receiver stays cancelled: it can neither release again nor be raced into a second
    // effect by a later call.
    assert.deepEqual(await receive(receiver, completion(), 'after cancel'),
      { status: 'REFUSED', code: 'CANCELLED' });
    assertNothingReleased(captured);
  });

test('cancellation inside the final observation withholds the release', { timeout: TEST_TIMEOUT_MS }, async () => {
  // Positive control: the same host and the same queued second observation, cancelling nothing. One
  // real fixed-worker check and exactly the independently declared image at the capture.
  const safe = harness({ observations: [OBSERVATION, OBSERVATION] });
  assert.deepEqual(await receive(safe.receiver, completion(), 'final observation without a cancel'),
    { status: 'RELEASED' });
  assert.equal(safe.captured.length, 1);
  assert.equal(safe.captured[0].equals(expectedImage()), true);
  assert.equal(safe.receiver.state, 'IDLE');

  // The release point cancels from inside the last observation it returns. Sticky cancellation is
  // read again AFTER that callback, so the release point is still never invoked.
  const { host, captured } = createHost({ observations: [OBSERVATION, OBSERVATION] });
  const owner = { receiver: null };
  let calls = 0;
  host.releasePoint = Object.freeze({
    observe: () => {
      calls += 1;
      if (calls === 2) owner.receiver.cancel();
      return OBSERVATION;
    },
    releaseExact: host.releasePoint.releaseExact,
  });
  const receiver = createOpenAiKeepReceiver(host);
  owner.receiver = receiver;
  assert.deepEqual(await receive(receiver, completion(), 'cancelled inside the final observation'),
    { status: 'REFUSED', code: 'CANCELLED' });
  assert.equal(calls, 2, 'the refusal came after the final observation, not before it');
  assertNothingReleased(captured);
  assert.equal(receiver.state, 'CANCELLED');
});

test('a second receive while one is in flight is refused rather than queued or duplicated',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const { receiver, captured } = harness();
    const first = receiver.receive({ endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body: completion() });
    const second = receiver.receive({ endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body: completion() });
    assert.deepEqual(await bounded(second, 'busy receive'), { status: 'REFUSED', code: 'RECEIVER_BUSY' });
    assert.deepEqual(await bounded(first, 'first receive'), { status: 'RELEASED' });
    assert.equal(captured.length, 1, 'exactly one release, never two');
    assert.equal(receiver.state, 'IDLE');
  });

test('an unusable trusted host yields a permanently restrictive receiver, never a throw',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const { host } = createHost();
    for (const [name, unusable] of [
      ['not an object', 'nope'],
      ['missing release point', { ...host, releasePoint: undefined }],
      ['unknown own key', { ...host, trustedTransport: null }],
      ['release point is not callable', { ...host, releasePoint: { ...host.releasePoint, releaseExact: 'nope' } }],
      ['inspect is not a function', { ...host, inspect: {} }],
      ['a source trust the module does not take', { ...host, sourceTrust: 'TRUSTED' }],
      ['an accessor instead of a data property', Object.defineProperty({ ...host }, 'scope', {
        enumerable: true, get: () => SCOPE,
      })],
    ]) {
      const receiver = createOpenAiKeepReceiver(unusable);
      assert.equal(receiver.state, 'FAILED', name);
      assert.deepEqual(await receive(receiver, completion(), name), { status: 'REFUSED', code: 'HOST_INVALID' }, name);
      receiver.cancel();
      assert.equal(receiver.state, 'FAILED', name);
    }
  });

test('a revoked Proxy anywhere in the trusted host is contained as an unusable receiver',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const { host, captured } = createHost();
    const revokedHost = Proxy.revocable(host, {});
    revokedHost.revoke();
    const revokedPoint = Proxy.revocable(host.releasePoint, {});
    revokedPoint.revoke();

    for (const [name, unusable] of [
      ['revoked host', revokedHost.proxy],
      ['revoked release point', { ...host, releasePoint: revokedPoint.proxy }],
    ]) {
      let receiver = null;
      let threw = false;
      try { receiver = createOpenAiKeepReceiver(unusable); } catch { threw = true; }
      assert.equal(threw, false, `${name}: construction never throws`);
      assert.equal(receiver.state, 'FAILED', name);
      assert.deepEqual(await receive(receiver, completion(), name), { status: 'REFUSED', code: 'HOST_INVALID' }, name);
      receiver.cancel();
      assert.equal(receiver.state, 'FAILED', name);
    }
    assertNothingReleased(captured);
  });

/* ---------- The captured release point ---------- */

test('an accepted release point is captured, so a Proxy get trap cannot run at the release',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    const { host, captured } = createHost();
    const owner = { receiver: null };
    let methodReads = 0;
    // A supported Proxy release point: exactly the two declared own data properties, so it is
    // accepted like any other host. Its `get` trap cancels the receiver the first time the release
    // method is read back off it. Reading that method at the release point would be a host callback
    // after the last guard, so the accepted function must be captured during validation.
    host.releasePoint = new Proxy(host.releasePoint, {
      get(object, key, receiver_) {
        if (key === 'releaseExact') {
          methodReads += 1;
          if (owner.receiver !== null) owner.receiver.cancel();
        }
        return Reflect.get(object, key, receiver_);
      },
    });
    const receiver = createOpenAiKeepReceiver(host);
    owner.receiver = receiver;
    assert.deepEqual(await receive(receiver, completion(), 'proxy release point'), { status: 'RELEASED' });
    assert.equal(methodReads, 0, 'the accepted release method was never looked up again');
    assert.equal(receiver.state, 'IDLE', 'no host callback cancelled this receiver after the guards');
    assert.equal(captured.length, 1, 'exactly one trusted release');
    assert.equal(captured[0].equals(expectedImage()), true, 'the capture recorded the declared image');
  });

test('a captured release point keeps its own receiver and is not retargeted by a later swap',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    let observations = 0;
    let receiverPreserved = true;
    const released = [];
    // Exactly the two declared own data properties. Every host state these methods use lives in this
    // closure, so the only way `this` can be wrong is a lost receiver.
    const releasePoint = {
      observe() {
        if (this !== releasePoint) receiverPreserved = false;
        observations += 1;
        return OBSERVATION;
      },
      async releaseExact(image) {
        if (this !== releasePoint) receiverPreserved = false;
        released.push(Buffer.from(image));
      },
    };
    const { receiver } = harness({ host: { releasePoint } });
    // A host that replaces its own release method after construction does not retarget this receiver.
    let swapped = 0;
    releasePoint.releaseExact = async () => { swapped += 1; };
    assert.deepEqual(await receive(receiver, completion(), 'captured release point'), { status: 'RELEASED' });
    assert.equal(receiverPreserved, true, 'each captured method ran on the release point it was accepted on');
    assert.equal(observations, 2, 'the route is still observed fresh for the check and at the release');
    assert.equal(swapped, 0, 'the replacement installed after construction was never invoked');
    assert.equal(released.length, 1);
    assert.equal(released[0].equals(expectedImage()), true, 'the captured release point got the declared image');
    assert.equal(receiver.state, 'IDLE');
  });

/* ---------- No restoration authority anywhere in the chain ---------- */

test('token-shaped provider text stays literal, and a failing release leaks nothing',
  { timeout: TEST_TIMEOUT_MS }, async () => {
    // Each token is invented: a placeholder form this repository has no encoder for, a forged
    // reference to a registration entry that exists here, and a bare opaque token.
    const tokens = [
      '[hylja:protected:HOST_1]',
      '[hylja:protected:planted.person.1]',
      '[hylja:protected:UNKNOWN_CLASS_7]',
      'hylja_prot_7f3c91aa2b',
    ];
    const content = `The protected values are ${tokens.join(', ')}; keep them scoped to this turn.`;
    const { receiver, captured } = harness();
    assert.deepEqual(await receive(receiver, completion({ content }), 'token-shaped text'), { status: 'RELEASED' });
    assert.equal(captured.length, 1);

    // Nothing was substituted and no original came back: the released content is byte-identical to
    // the accepted assistant text. This is absence of restoration authority in this chain, not a
    // claim about any broker: no broker, vault, mapping store or uncloak path is configured, called or
    // imported here, and none of those are implemented in this repository.
    const released = JSON.parse(captured[0].toString('utf8')).choices[0].message.content;
    assert.equal(released, content);
    for (const token of tokens) assert.equal(released.includes(token), true, token);
    assert.equal(captured[0].includes(PLANTED_ORIGINAL), false);
    assert.equal(captured[0].includes(PLANTED_CANARY), false);
    assert.equal(captured[0].includes('undefined'), false);

    // A release point that fails reports one fixed code and never leaks the exception.
    const failing = createHost({ host: { releasePoint: {
      observe: () => OBSERVATION,
      releaseExact: async () => { throw new Error(`release failed: ${PLANTED_ORIGINAL}`); },
    } } });
    const failingReceiver = createOpenAiKeepReceiver(failing.host);
    const result = await receive(failingReceiver, completion(), 'release failure');
    assert.deepEqual(result, { status: 'REFUSED', code: 'RELEASE_FAILED' });
    assert.equal(JSON.stringify(result).includes(PLANTED_ORIGINAL), false, 'no planted value in the result');
    assert.equal(failingReceiver.state, 'IDLE');
  });