// #175 / complete OpenAI-compatible response inspection, end to end over accepted v1 exports only.
//
// What this proves, precisely: one complete, non-streamed, text-only native response travels through the
// real chain `translateOpenAiTextResponse` -> real `detectSecrets` -> real `composeClassification` ->
// real `decidePolicy`, and the *independently checked* final serialized representation is what the
// controlled in-memory model-context capture receives. The capture records the sentinel's own private
// ALLOW copy, never the pipeline's buffer, so a release is observed rather than asserted.
//
// What it is NOT: a product adapter, a gateway, a broker, an authenticated caller, a live transport, a
// streaming path, a transformation engine, a release proof or a held-out result. The trusted boundary,
// policy bundle pin and sentinel key are test fixtures, not authenticated identities. Nothing here
// cloaks, uncloaks, resolves or substitutes an original: token-shaped model text carries no restoration
// authority. No network at all: the capture is a recording in this process, not a socket.
//
// Every fixture value is invented and obviously synthetic and non-routable (`*.invalid`, documentation
// names). The planted credential-shaped string is a made-up literal, not a live token.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { OPENAI_TEXT_RESPONSE_ENDPOINT, translateOpenAiTextResponse } from '../dist/openai-text-response.js';
import { composeClassification, TRUST_LEVELS } from '../dist/classification.js';
import { decidePolicy, digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE } from '../dist/policy.js';
import { checkEgress, createKnownOriginals, sentinelUnavailable } from '../dist/egress-sentinel.js';
import { detectSecrets } from '../dist/secret-detectors.js';

const TEST_TIMEOUT_MS = 30_000;

/* ---------- Planted synthetic originals and the independent sentinel binding ---------- */

const SCOPE = Object.freeze({ tenantRef: 'tenant-inspection.invalid', projectRef: 'project-inspection.invalid' });
// A dedicated, obviously synthetic sentinel key for this test only. It is not a credential.
const SENTINEL_KEY = new Uint8Array(32).fill(11);
const PLANTED_HOST = 'gw-plc-77.tenant-inspection.invalid';
const PLANTED_PERSON = 'Verity Synthanon';
const known = createKnownOriginals(SCOPE, SENTINEL_KEY, [
  { kind: 'ORIGINAL', value: PLANTED_HOST, ref: 'planted.host.1' },
  { kind: 'ORIGINAL', value: PLANTED_PERSON, ref: 'planted.person.1' },
]);

/* ---------- Trusted test fixture bindings (not authenticated identities) ---------- */

const INTERACTION_REF = 'interaction-inspection-e2e.invalid';
const CANDIDATE_REF = 'candidate-inspection-1.invalid';
const CONTENT_REF = 'assistant-content-inspection.invalid';
const SUBJECT = { principalId: 'principal-inspection.invalid', workloadId: 'workload-inspection.invalid' };
const CONTEXT = {
  tenantId: 'tenant-inspection.invalid', projectId: 'project-inspection.invalid',
  sessionId: 'session-inspection.invalid', purpose: 'fixture-response-inspection.invalid',
};
// Protected model output is untrusted text at its own source, and nothing the response says raises this.
const SOURCE = { kind: 'model.response', ref: 'model-response-inspection.invalid', trustZone: 'LOCAL' };
const SOURCE_TRUST = 'UNTRUSTED';
const SINK = {
  kind: 'model', ref: 'model-context-fixture.invalid', trustZone: 'LOCAL', profileId: 'fixture-model-context.invalid',
};
const PROFILE = {
  id: 'fixture-model-context.invalid', sink: SINK, exposure: 'LOCAL',
  permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'INTERNAL',
};
function rule(id, semanticType, sensitivities, decision, reviewTreatments) {
  return {
    id: `${id}.invalid`, profileId: PROFILE.id, semanticType, sensitivities,
    sourceTrust: [...TRUST_LEVELS], operations: ['SEND'], decision,
    ...(reviewTreatments ? { reviewTreatments } : {}),
  };
}
const BUNDLE = Object.freeze({
  ...KNOWN_POLICY_BUNDLE,
  profiles: [PROFILE],
  rules: [
    rule('fixture-person-clear', 'PERSON', ['PUBLIC'], 'KEEP'),
    rule('fixture-person-review', 'PERSON', ['INTERNAL'], 'REQUIRE_REVIEW', ['REMOVE']),
    rule('fixture-secret-block', 'CREDENTIAL_OR_SECRET', ['SECRET'], 'BLOCK'),
  ],
});
const AUTHORIZED = Object.freeze({
  id: SINK.ref, profileDigest: createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex'),
});

const TRUST_CONTEXT = Object.freeze({
  interactionRef: INTERACTION_REF, sourceRef: SOURCE.ref, trust: SOURCE_TRUST,
});

/**
 * The trusted fixture claim used when the real detector stack finds nothing. It is a fixture binding, not
 * a claim derived from the wire: this repository ships no person or host detector, so a benign complete
 * response carries no FOUND evidence of its own and the composer would leave it UNRESOLVED. Every case
 * where the wire itself produces the classification (the planted credential) uses real detector evidence
 * and no fixture claim.
 */
const benignCache = new Map();
function benign(sensitivity) {
  if (benignCache.has(sensitivity)) return benignCache.get(sensitivity);
  const composed = composeClassification({
    detectorEvidence: [{
      version: 1, id: 'detector-fixture-inspection.invalid', status: 'FOUND',
      provenance: {
        inputRef: 'fixture-field-inspection.invalid', producerId: 'detector-fixture-inspection.invalid',
        producerVersion: 'fixture-pack-1',
      },
      claim: { semanticType: 'PERSON', sensitivity },
    }],
  }, TRUST_CONTEXT);
  benignCache.set(sensitivity, composed);
  return composed;
}

function bindings(classification, mutateBoundary) {
  const boundary = {
    interactionRef: INTERACTION_REF, candidateRef: CANDIDATE_REF,
    classificationDigest: digestClassification(classification),
    authenticated: { subject: SUBJECT, context: CONTEXT },
    observed: { source: { ...SOURCE, trust: SOURCE_TRUST }, destination: SINK },
    policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) },
  };
  return {
    request: {
      version: 1, interactionRef: INTERACTION_REF, candidateRef: CANDIDATE_REF,
      subject: SUBJECT, context: CONTEXT, source: SOURCE, destination: SINK, classification,
      operation: 'SEND', policy: KNOWN_POLICY_BUNDLE,
    },
    boundary: mutateBoundary ? mutateBoundary(boundary) : boundary,
  };
}

/* ---------- Explicit serialization: ordered fields, declared independently of the serializer ---------- */

const USER_TURN = 'Status of the synthetic fixture rotation?';
function serializeModelContext(assistantText) {
  return JSON.stringify({
    model: 'fixture-model-inspection-e2e',
    messages: [
      { role: 'user', content: USER_TURN },
      { role: 'assistant', content: assistantText },
    ],
  });
}

const SAFE_ANSWER = 'The synthetic rotation window opens at 02:00 UTC; no action is required tonight.';
// The expected captured image is written out literally, field by field, so a reviewer can compare it with
// what the capture recorded without running the pipeline.
const EXPECTED_SAFE_CAPTURE = '{"model":"fixture-model-inspection-e2e","messages":['
  + '{"role":"user","content":"Status of the synthetic fixture rotation?"},'
  + '{"role":"assistant","content":"The synthetic rotation window opens at 02:00 UTC; no action is required tonight."}'
  + ']}';
const EXPECTED_SAFE_CAPTURE_BYTES = 237;

/** One complete, non-streamed, text-only native response body, in native wire text. */
function completion(fields = {}) {
  return JSON.stringify({
    id: 'chatcmpl-fixture-inspection-e2e',
    object: fields.object ?? 'chat.completion',
    created: 1_760_000_000,
    model: 'fixture-model-inspection-e2e',
    choices: [{
      index: 0,
      message: { role: 'assistant', content: fields.content ?? SAFE_ANSWER },
      finish_reason: 'stop',
      ...(fields.toolCalls ? { tool_calls: [] } : {}),
    }],
    usage: { prompt_tokens: 41, completion_tokens: 17, total_tokens: 58 },
    ...(fields.unknown ? { system_fingerprint: 'fp_fixture_inspection' } : {}),
  });
}

// Obviously synthetic, not a live token: a made-up literal in a documentation-only vendor shape.
const PLANTED_SECRET = `ghp_${'SYNTHETIC0'.repeat(4)}`;

/* ---------- The complete-response inspection chain and its controlled capture ---------- */

/**
 * The chain under test. A release needs four independent things, in order: an accepted complete
 * translation, a SELECTED/KEEP policy decision from `decidePolicy`, and an ALLOW from `checkEgress` over
 * the exact serialized bytes. Everything else captures nothing. There is no chunk path here and no
 * restoration step: nothing in it can turn model text back into an original.
 */
function inspectModelContext(wire, options = {}) {
  const translated = translateOpenAiTextResponse({ endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body: wire });
  const empty = { translated, detected: null, classification: null, decision: null, sentinel: null, captured: [] };
  if (translated.status !== 'TRANSLATED') return empty;
  const content = translated.draft.payload.messages[0].content;
  const detected = detectSecrets({ text: content, inputRef: CONTENT_REF });
  const classification = detected.candidates.length
    ? composeClassification({ detectorEvidence: detected.candidates.map((item) => item.evidence) }, TRUST_CONTEXT)
    : benign(options.benignSensitivity ?? 'PUBLIC');
  const { request, boundary } = bindings(classification, options.mutateBoundary);
  const decision = decidePolicy(request, boundary, BUNDLE);
  if (decision.state !== 'SELECTED' || decision.treatment !== 'KEEP') {
    return { translated, detected, classification, decision, sentinel: null, captured: [] };
  }
  // The final serialized representation is built only after policy selected, and is what the sentinel
  // reads: the decision is never taken on the un-serialized draft.
  const bytes = Buffer.from(serializeModelContext(content), 'utf8');
  const sentinel = options.sentinel ?? checkEgress({
    bytes, scope: SCOPE, destination: AUTHORIZED, authorized: AUTHORIZED, known,
    ...options.sentinelOverrides,
  });
  const captured = sentinel.decision === 'ALLOW' && sentinel.release instanceof Uint8Array
    ? [Buffer.from(sentinel.release).toString('utf8')] : [];
  return { translated, detected, classification, decision, sentinel, captured };
}

/* ---------- The safe complete response ---------- */

test('a safe complete response is inspected and captured as the declared literal bytes',
  { timeout: TEST_TIMEOUT_MS }, () => {
    const result = inspectModelContext(completion());

    // Literal troubleshooting facts, asserted independently of anything the pipeline computed.
    assert.equal(result.translated.status, 'TRANSLATED');
    assert.deepEqual(result.translated.protocol, {
      id: 'chatcmpl-fixture-inspection-e2e',
      created: 1_760_000_000,
      finish_reason: 'stop',
      usage: { prompt_tokens: 41, completion_tokens: 17, total_tokens: 58 },
    });
    assert.equal(result.translated.draft.operation, 'model.output');
    assert.equal(result.translated.draft.stream.mode, 'complete');
    assert.deepEqual(result.translated.draft.metadata,
      { adapter: 'hylja.openai-text-response', provider: 'openai', model: 'fixture-model-inspection-e2e' });
    assert.deepEqual(result.translated.draft.payload,
      { messages: [{ role: 'assistant', content: SAFE_ANSWER }] });
    assert.equal(result.detected.status, 'COMPLETE');
    assert.deepEqual(result.detected.candidates, []);
    assert.equal(result.classification.sensitivity, 'PUBLIC');
    assert.equal(result.decision.state, 'SELECTED');
    assert.equal(result.decision.treatment, 'KEEP');
    assert.equal(result.decision.reason, 'RULE_SELECTED');
    assert.equal(result.sentinel.decision, 'ALLOW');
    assert.deepEqual(result.sentinel.reasons, []);
    assert.deepEqual(result.sentinel.findings, []);

    assert.equal(result.captured.length, 1, 'the capture recorded exactly one image');
    assert.equal(result.captured[0], EXPECTED_SAFE_CAPTURE);
    assert.equal(Buffer.byteLength(result.captured[0], 'utf8'), EXPECTED_SAFE_CAPTURE_BYTES);
    assert.deepEqual(JSON.parse(result.captured[0]).messages,
      [{ role: 'user', content: USER_TURN }, { role: 'assistant', content: SAFE_ANSWER }]);
  });

/* ---------- A planted synthetic credential the real detector finds ---------- */

test('a planted synthetic secret in the response is denied by accepted-v1 policy and captures zero bytes',
  { timeout: TEST_TIMEOUT_MS }, () => {
    const result = inspectModelContext(completion({
      content: `Restart the fixture with ${PLANTED_SECRET} before the window.`,
    }));

    // The real detector stack, not a fixture claim, produces this classification.
    assert.equal(result.detected.status, 'COMPLETE');
    assert.equal(result.detected.candidates.length, 1);
    assert.equal(result.detected.candidates[0].rule, 'format.github-token');
    assert.equal(result.detected.candidates[0].subtype, 'ACCESS_TOKEN');
    assert.equal(result.classification.status, 'RESOLVED');
    assert.equal(result.classification.semanticType, 'CREDENTIAL_OR_SECRET');
    assert.equal(result.classification.subtype, 'ACCESS_TOKEN');
    assert.equal(result.classification.sensitivity, 'SECRET');
    assert.equal(result.classification.reversible, false);
    assert.deepEqual(result.decision,
      { version: 1, state: 'DENIED', treatment: 'BLOCK', reason: 'RULE_BLOCK' });
    // Denied at policy: the final bytes are never even serialized for the sentinel.
    assert.equal(result.sentinel, null);
    assert.deepEqual(result.captured, [], 'zero captured bytes');

    // The planted value never reappears in any observable the pipeline produced.
    const observable = JSON.stringify({
      protocol: result.translated.protocol, detected: result.detected,
      classification: result.classification, decision: result.decision,
    });
    assert.equal(observable.includes(PLANTED_SECRET), false);
  });

/* ---------- A protected original the primary evidence deliberately misses ---------- */

test('a protected original that candidate detection misses is caught at the final-byte check',
  { timeout: TEST_TIMEOUT_MS }, () => {
    const leaky = `Escalate to ${PLANTED_PERSON} on ${PLANTED_HOST} before the window.`;
    const result = inspectModelContext(completion({ content: leaky }));

    // The candidate miss and the sentinel outcome are distinguished, not conflated.
    assert.equal(result.detected.status, 'COMPLETE');
    assert.deepEqual(result.detected.candidates, [], 'the primary detector stack genuinely finds nothing');
    assert.equal(result.classification.status, 'RESOLVED');
    assert.equal(result.decision.state, 'SELECTED', 'policy allowed it: only the sentinel still stands');
    assert.equal(result.sentinel.decision, 'BLOCK');
    assert.deepEqual(result.sentinel.reasons, ['KNOWN_ORIGINAL_DETECTED']);
    assert.deepEqual(result.sentinel.findings.map((finding) => finding.rule).sort(),
      ['planted.host.1', 'planted.person.1']);
    assert.equal(result.captured.length, 0, 'zero captured bytes');

    // A positive control on the same chain: an answer the detector also misses is captured normally, so
    // the BLOCK above is the sentinel's finding and not a chain that refuses everything.
    assert.deepEqual(inspectModelContext(completion()).captured, [EXPECTED_SAFE_CAPTURE]);

    // The same original, encoded into the response text, is still caught at the final-byte check.
    const encoded = `Continue with ${Buffer.from(PLANTED_HOST, 'utf8').toString('base64')} and proceed.`;
    const encodedResult = inspectModelContext(completion({ content: encoded }));
    assert.deepEqual(encodedResult.detected.candidates, []);
    assert.equal(encodedResult.decision.state, 'SELECTED');
    assert.equal(encodedResult.sentinel.decision, 'BLOCK');
    assert.deepEqual(encodedResult.captured, []);
  });

/* ---------- Unsupported responses refuse before anything is captured ---------- */

test('tool calls, streaming, malformed text and unknown fields refuse before the capture',
  { timeout: TEST_TIMEOUT_MS }, () => {
    const cases = [
      ['tool-calls', completion({ toolCalls: true }), 'UNSUPPORTED_TOOLS'],
      ['streaming', completion({ object: 'chat.completion.chunk' }), 'STREAMING_NOT_SUPPORTED'],
      ['unknown-field', completion({ unknown: true }), 'UNEXPECTED_FIELD'],
      ['malformed', '{"id":"chatcmpl-fixture-inspection-e2e","object":"chat.completion",', 'MALFORMED_JSON'],
    ];
    for (const [name, wire, reason] of cases) {
      const result = inspectModelContext(wire);
      assert.equal(result.translated.status, 'REFUSED', name);
      assert.equal(result.translated.reason, reason, name);
      assert.equal(result.detected, null, name);
      assert.equal(result.classification, null, name);
      assert.equal(result.decision, null, name);
      assert.equal(result.sentinel, null, name);
      assert.deepEqual(result.captured, [], name);
    }
  });

/* ---------- Every other restrictive outcome ---------- */

test('missing or mismatched trusted context, HELD, and an unavailable sentinel capture zero bytes',
  { timeout: TEST_TIMEOUT_MS }, () => {
    const outage = sentinelUnavailable();
    assert.deepEqual(outage.reasons, ['SENTINEL_UNAVAILABLE']);
    const zeroDigest = '0'.repeat(64);
    const cases = [
      ['missing-boundary', {
        mutateBoundary: (boundary) => ({ ...boundary, authenticated: undefined }),
      }, null, 'INVALID_CONTEXT'],
      ['context-mismatch', {
        mutateBoundary: (boundary) => ({
          ...boundary,
          authenticated: {
            subject: SUBJECT,
            context: { ...CONTEXT, sessionId: 'session-other.invalid' },
          },
        }),
      }, null, 'CONTEXT_MISMATCH'],
      ['digest-mismatch', {
        mutateBoundary: (boundary) => ({ ...boundary, classificationDigest: zeroDigest }),
      }, null, 'CLASSIFICATION_MISMATCH'],
      ['held-for-review', { benignSensitivity: 'INTERNAL' }, null, null],
      ['sentinel-unavailable', {}, outage, null],
    ];
    for (const [name, options, sentinel, reason] of cases) {
      const result = inspectModelContext(completion(), sentinel ? { ...options, sentinel } : options);
      assert.equal(result.detected.status, 'COMPLETE', name);
      if (reason !== null) {
        assert.deepEqual(result.decision,
          { version: 1, state: 'DENIED', treatment: 'BLOCK', reason }, name);
        assert.equal(result.sentinel, null, name);
      } else if (sentinel) {
        assert.equal(result.decision.state, 'SELECTED', name);
        assert.equal(result.sentinel.decision, 'BLOCK', name);
        assert.deepEqual(result.sentinel.reasons, ['SENTINEL_UNAVAILABLE'], name);
      } else {
        assert.equal(result.decision.state, 'HELD', name);
        assert.equal(result.decision.treatment, 'REQUIRE_REVIEW', name);
        assert.equal(result.decision.reason, 'RULE_REVIEW', name);
        assert.equal(typeof result.decision.decisionRef, 'string', name);
        assert.equal(result.sentinel, null, name);
      }
      assert.deepEqual(result.captured, [], name);
    }
  });

/* ---------- Token-shaped model text carries no restoration authority ---------- */

test('unknown, forged and scoped token-shaped model text stays literal and resolves no original',
  { timeout: TEST_TIMEOUT_MS }, () => {
    // Each token is invented: a placeholder form this repository has no encoder for, a forged reference to
    // a sentinel entry that exists here, and a bare opaque token.
    const tokens = [
      '[hylja:protected:HOST_1]',
      '[hylja:protected:planted.host.1]',
      '[hylja:protected:UNKNOWN_CLASS_7]',
      'hylja_prot_7f3c91aa2b',
    ];
    const content = `The protected values are ${tokens.join(', ')}; keep them scoped to this turn.`;
    const result = inspectModelContext(completion({ content }));

    assert.deepEqual(result.detected.candidates, [], 'a token reference is not a credential');
    assert.equal(result.decision.state, 'SELECTED');
    assert.equal(result.sentinel.decision, 'ALLOW');
    assert.equal(result.captured.length, 1);

    // Nothing was substituted, and no original came back: the captured assistant turn is byte-identical
    // to the translated content. This is absence of restoration authority in this chain, not a claim
    // about any broker: no broker is configured, called or imported here.
    const capturedTurn = JSON.parse(result.captured[0]).messages[1].content;
    assert.equal(capturedTurn, content);
    for (const token of tokens) assert.equal(capturedTurn.includes(token), true, token);
    assert.equal(result.captured[0].includes(PLANTED_HOST), false);
    assert.equal(result.captured[0].includes(PLANTED_PERSON), false);
    assert.equal(result.captured[0].includes('undefined'), false);
  });