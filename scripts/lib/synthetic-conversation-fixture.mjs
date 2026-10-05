/**
 * Synthetic fixture host for the bounded local conversation owner (#250).
 *
 * This module is a fixture, not an authority. It declares the trusted inputs a real integration host
 * would supply and nothing else: the already authenticated `PolicyBoundary`, the pinned policy bundle
 * and its committed digest, the observed destination profile, the known-original registration handed
 * to the two fixed-worker sentinel children, and the proof intervals those boundaries carry. Nothing
 * here authenticates a principal, a tenant membership, a workload, a session or a control plane, and
 * the static PUBLIC claim used for the units the real detector stack covers nothing in is a declared
 * fixture label: it is never derived from an empty candidate set, so no detector absence is ever read
 * as clearance.
 *
 * The real seams still do all the work: `detectSecrets` runs over the sender's own private ORIGINAL
 * request image and over the receiver's own inbound image, `composeClassification` composes those
 * real findings, and the real Policy Engine selects the treatment. Only the boundary, the clock, the
 * policy bundle, the profile digest and the registration are declared here.
 *
 * Every value is invented, obviously synthetic and non-routable: `*.invalid` labels, a loopback
 * destination and a made-up vendor-shaped token literal that is documentation-shaped and not live.
 */
import { createHash } from 'node:crypto';
import { composeClassification, TRUST_LEVELS } from '../../dist/classification.js';
import { digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE } from '../../dist/policy.js';
import { detectSecrets } from '../../dist/secret-detectors.js';

/* ---------- Planted synthetic material and the generic mask literal ---------- */

/** Registered as a known original for both real children, on the request and the reply side. */
export const PLANTED_ORIGINAL = 'avery.synthanon@synthetic-planted.invalid';
/**
 * The privacy-safe label this fixture registered that original under. It is the only label a fixed child
 * may report back, and it is what the worker observation compares a reported rule against, so a `BLOCK`
 * naming a rule can be shown to name THIS registration rather than something the child chose.
 */
export const PLANTED_ORIGINAL_REF = 'planted.person.demo';
/** Obviously synthetic and not a live token: one documented vendor shape, exactly what the rule sees. */
export const PLANTED_SECRET = `ghp_${'SYNTHETIC1'.repeat(4)}`;
/** The generic irreversible literal of accepted decision 011, declared here and never imported. */
export const MASKED = '[hylja:masked]';

const SCOPE = Object.freeze({
  tenantRef: 'tenant-demo.invalid', projectRef: 'project-demo.invalid',
});
/** A dedicated synthetic sentinel key for these fixtures only. It is not a credential. */
const KEY = Uint8Array.from({ length: 32 }, (unused, index) => (index * 29 + 7) & 0xff);

const registration = () => ({
  scope: SCOPE, key: KEY,
  entries: Object.freeze([Object.freeze({
    kind: 'ORIGINAL', value: PLANTED_ORIGINAL, ref: PLANTED_ORIGINAL_REF,
  })]),
});

/* ---------- Trusted fixture bindings: fixtures, not authenticated identities ---------- */

const SUBJECT = Object.freeze({
  principalId: 'principal-demo.invalid', workloadId: 'workload-demo.invalid',
});
const CONTEXT = Object.freeze({
  tenantId: SCOPE.tenantRef, projectId: SCOPE.projectRef,
  sessionId: 'session-demo.invalid', purpose: 'fixture-demo.invalid',
});
const SOURCE = Object.freeze({
  kind: 'tool.result', ref: 'tool-source-demo.invalid', trustZone: 'LOCAL',
});
export const SOURCE_TRUST = 'TRUSTED';
/** Provider source trust is fixed by the receiver itself and is not a host or caller input. */
const PROVIDER_TRUST = 'UNTRUSTED';
const SINK_LABEL = 'model-sink-demo.example.invalid';
const SINK = Object.freeze({
  kind: 'model', ref: SINK_LABEL, trustZone: 'EXTERNAL', profileId: 'demo-sink.invalid',
});
const PROFILE = Object.freeze({
  id: 'demo-sink.invalid', sink: SINK, exposure: 'EXTERNAL',
  permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'INTERNAL',
});

/**
 * Two real rules, so the real Policy Engine - not this file - picks a treatment per unit: a unit the
 * detector stack finds nothing in takes the declared fixture claim (PERSON/PUBLIC) and KEEP, and the
 * unit the real detector finds a secret in is classified CREDENTIAL_OR_SECRET/SECRET and MASKed.
 */
const BUNDLE = Object.freeze({
  ...KNOWN_POLICY_BUNDLE,
  profiles: [PROFILE],
  rules: [
    {
      id: 'demo-fixture-keep.invalid', profileId: PROFILE.id, semanticType: 'PERSON',
      sensitivities: ['PUBLIC'], sourceTrust: [...TRUST_LEVELS], operations: ['SEND'], decision: 'KEEP',
    },
    {
      id: 'demo-secret-mask.invalid', profileId: PROFILE.id, semanticType: 'CREDENTIAL_OR_SECRET',
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
    identityProof: proof('identity-demo.invalid'), requestProof: proof('request-demo.invalid'),
  },
  observed: {
    source: SOURCE, destination: SINK,
    sourceProof: proof('source-demo.invalid'), routeProof: proof('route-demo.invalid'),
  },
});

const PROFILE_DIGEST = createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex');
const OBSERVATION = Object.freeze({
  destination: Object.freeze({ id: SINK.ref, profileDigest: PROFILE_DIGEST }),
  commit: Object.freeze({ ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(BUNDLE) }),
});

/* ---------- The one synthetic conversation these fixtures describe ---------- */

const MODEL = 'fixture-model-demo';
const SYSTEM_TEXT = 'You are a synthetic fixture assistant.';
const SECRET_TEXT = `Rotate the synthetic fixture for ${PLANTED_ORIGINAL} using ${PLANTED_SECRET} tonight.`;
const WINDOW_TEXT = 'Reply with the rotation window only.';
const MESSAGES = Object.freeze([
  Object.freeze({ role: 'system', content: SYSTEM_TEXT }),
  Object.freeze({ role: 'user', content: SECRET_TEXT }),
  Object.freeze({ role: 'user', content: WINDOW_TEXT }),
]);

/** The accepted complete text request: one secret-bearing message the real detector will find. */
export const DEMO_REQUEST = JSON.stringify({ model: MODEL, messages: MESSAGES });
/**
 * A request outside the strict complete-text subset: it carries a `tools` member, so the strict codec
 * refuses it by name before any image, classification, policy decision, child or socket can exist.
 */
export const DEMO_UNSUPPORTED_REQUEST = JSON.stringify({
  model: MODEL, messages: MESSAGES, tools: [],
});
/** The exact ORIGINAL unit literals, declared independently of the sender's own serializer. */
const MODEL_LITERAL = '"fixture-model-demo"';
const MESSAGE_LITERALS = Object.freeze([
  '"You are a synthetic fixture assistant."',
  `"Rotate the synthetic fixture for ${PLANTED_ORIGINAL} using ${PLANTED_SECRET} tonight."`,
  '"Reply with the rotation window only."',
]);

const REPLY_ID = 'chatcmpl-fixture-demo-0001';
const REPLY_CREATED = 1_762_000_101;
const REPLY_CONTENT = 'Rotation window 02:00 UTC. Nothing is restored and no original is returned.';
const REPLY_BODY = `{"id":"${REPLY_ID}","object":"chat.completion","created":${REPLY_CREATED},`
  + `"model":"${MODEL}","choices":[{"index":0,"message":{"role":"assistant",`
  + `"content":"${REPLY_CONTENT}"},"finish_reason":"stop"}],`
  + '"usage":{"prompt_tokens":40,"completion_tokens":18,"total_tokens":58}}';
/** The same reply with the registered planted original inside the assistant text. */
export const DEMO_REPLY = REPLY_BODY;
export const DEMO_LEAKY_REPLY = REPLY_BODY.replace(
  'Rotation window 02:00 UTC.', `For ${PLANTED_ORIGINAL} the rotation window 02:00 UTC.`,
);

/* ---------- Real detection over the seams' own private images ---------- */

const REQUEST_IMAGE_REF = 'demo-request-image.invalid';
const REPLY_IMAGE_REF = 'demo-reply-image.invalid';
const decoder = new TextDecoder();
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/**
 * Bind every declared unit of the request image to its exact byte range. A unit is located only when
 * the bytes at the located offset hash to that unit's OWN digest, so a mislocated span fails the
 * binding instead of being attributed to a neighbouring unit.
 */
function requestSpans(image, imageText, binding) {
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

/** The declared TRUSTED FIXTURE claim for a unit the real detector covers nothing in. */
function fixtureClaim(binding, trust) {
  return composeClassification({
    detectorEvidence: [{
      version: 1, id: 'detector-demo-fixture.invalid', status: 'FOUND',
      provenance: {
        inputRef: 'demo-fixture-field.invalid', producerId: 'detector-demo-fixture.invalid',
        producerVersion: 'fixture-pack-1',
      },
      claim: { semanticType: 'PERSON', sensitivity: 'PUBLIC' },
    }],
  }, { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust });
}

/** The request-side whole-image inspection: the real detector runs over the sender's ORIGINAL image. */
function inspectOriginal(runs) {
  return (image, binding) => {
    const imageText = decoder.decode(image);
    const detected = detectSecrets({ text: imageText, inputRef: REQUEST_IMAGE_REF });
    const spans = requestSpans(image, imageText, binding);
    const units = binding.units.map((unit, index) => {
      const span = spans[index];
      const covered = detected.status !== 'COMPLETE' || span === null
        ? []
        : detected.candidates.filter((candidate) => candidate.start >= span.start && candidate.end <= span.end);
      const classification = covered.length > 0
        ? composeClassification({ detectorEvidence: covered.map((candidate) => candidate.evidence) },
          { interactionRef: binding.interactionRef, sourceRef: SOURCE.ref, trust: SOURCE_TRUST })
        : fixtureClaim(binding, SOURCE_TRUST);
      return { unitRef: unit.unitRef, classificationDigest: digestClassification(classification),
        classification };
    });
    runs.push({ side: 'request', status: detected.status, findings: detected.candidates.length });
    return {
      version: 1, interactionRef: binding.interactionRef, imageDigest: binding.imageDigest,
      coverage: 'COMPLETE', remainder: 'NONE', units,
    };
  };
}

/**
 * The receiver-side whole-image inspection: the real detector runs over the inbound image and is
 * recorded, while each per-unit record stays a declared fixture. No per-unit secret evidence is
 * invented from the absence of a finding.
 */
function inspectReply(runs) {
  return (image, binding) => {
    const detected = detectSecrets({ text: decoder.decode(image), inputRef: REPLY_IMAGE_REF });
    const units = binding.units.map((unit) => {
      const classification = fixtureClaim(binding, PROVIDER_TRUST);
      return { unitRef: unit.unitRef, classificationDigest: digestClassification(classification),
        classification };
    });
    runs.push({ side: 'reply', status: detected.status, findings: detected.candidates.length });
    return {
      version: 1, interactionRef: binding.interactionRef, imageDigest: binding.imageDigest,
      coverage: 'COMPLETE', remainder: 'NONE', units,
    };
  };
}

/**
 * The exact trusted host `createOpenAiLocalConversation` takes: six own data properties, where
 * `sender` and `receiver` are the two accepted owner hosts without their `sendPoint` and
 * `releasePoint`, because this owner supplies both. Every counter the demo reports is filled here:
 * `releases` counts the guarded application sink calls and `runs` records each real detector run.
 */
export function createDemoHost({ port, timeoutMs, releases, runs }) {
  return {
    port,
    timeoutMs,
    observe: () => OBSERVATION,
    onReply: async (reply) => { releases.push(reply); },
    sender: {
      boundary: BOUNDARY, sourceTrust: SOURCE_TRUST, policyBundle: BUNDLE, scope: SCOPE,
      known: registration(), sentinel: { deadlineMs: timeoutMs },
      inspectOriginal: inspectOriginal(runs),
    },
    receiver: {
      boundary: BOUNDARY, policyBundle: BUNDLE, scope: SCOPE, known: registration(),
      sentinel: { deadlineMs: timeoutMs }, inspect: inspectReply(runs),
    },
  };
}