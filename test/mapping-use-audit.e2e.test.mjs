// #197 / synthetic integration test: audited USE of a scoped encrypted mapping, resolved by a
// trusted local resource lookup and never handed back to the caller.
//
// Five already-shipped seams are joined over one explicitly ephemeral in-process scenario:
//
//   deriveScopedEntityReference -> createMappingMetadataRegistry -> authorizeMappingOperation
//     -> decidePolicy -> appendAuditEvent + gateHighRiskEffect -> openMappingPayload
//
// What this proves, precisely: a mapping that exists only as AEAD ciphertext is opened **only** after
// a fresh registry `current` read, an actual `AUTHORIZED` USE decision from the real authorization
// seam on an explicit purpose-bound grant, an actual `SELECTED`/`KEEP` decision from the real Policy
// Engine for `USE`, a real `appendAuditEvent` whose own result `gateHighRiskEffect` reports as
// permitted, and a **second** registry currency read after the audit and before the effect. The
// recovered identifier is spent on a synthetic trusted local resource backend whose success depends
// on it, and only a fixed non-secret outcome - a code, a boolean, a byte count - leaves this file.
// Nothing here reports USED without a real opener call and a real backend lookup.
//
// What it is NOT: not a production broker, vault, store, KMS/HSM, audit service or model. It
// authenticates nobody: the workload identity, destination, classification, policy bundle, audit
// bundle, grants, DEK, HMAC key, audit keys, the resource backend and the clock are literal
// explicitly trusted test fixtures. There is no real authentication, no durable audit, no key
// management, no network effect and no production broker. Comparative custody and scoring, decision
// 010, and the parent slice's acceptance remain out of scope and unexercised here.
//
// Mapping ciphertext-only: the registry and the scenario hold ciphertext and non-secret metadata
// only. The one cleartext instance is the synthetic resource backend, which is **separately
// provisioned out of band** with the handle its own resource owns - a trusted resource system
// legitimately knows the identifier of its own record - and which compares the recovered bytes
// inside its own closure, so no identifier is ever returned, logged, asserted or captured as an
// audit field.
//
// Every value here is invented, obviously synthetic and non-routable: `.invalid` names, fixed byte
// fills as DEK, HMAC and audit key material, one fixed epoch instant and one planted marker string.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  sealMappingPayload, openMappingPayload, MAPPING_AEAD_LIMITS, MAPPING_AEAD_FINDINGS,
} from '../dist/mapping-aead.js';
import { deriveScopedEntityReference } from '../dist/scoped-entity-reference.js';
import { createMappingMetadataRegistry } from '../dist/mapping-metadata-registry.js';
import { authorizeMappingOperation } from '../dist/mapping-authorization.js';
import { decidePolicy, digestPolicyBundle, digestClassification, KNOWN_POLICY_BUNDLE }
  from '../dist/policy.js';
import { composeClassification } from '../dist/classification.js';
import {
  appendAuditEvent, createAuditCheckpoint, createInMemoryAuditLedger, gateHighRiskEffect,
  readAuditEvents, serializeAuditEntry, verifyAuditStream, AUDIT_SCHEMA_VERSION,
} from '../dist/audit-ledger.js';

/* ---------- Independent literals and explicitly trusted synthetic fixtures ---------- */

// The planted original, written here and never recomputed from the implementation. Obviously
// synthetic, non-routable, not a person, host, customer or credential.
const SYNTHETIC_ORIGINAL = 'synthetic-use-original-fixture.invalid';
const SYNTHETIC_ORIGINAL_BYTES = new TextEncoder().encode(SYNTHETIC_ORIGINAL);
// A second, independently provisioned handle this resource does NOT own, for the fault control.
const FOREIGN_HANDLE = 'synthetic-use-foreign-handle.invalid';
const MARKER = 'synthetic-use-original';
const KEY_VERSION = '1.0';
const CLASS = 'PERSON';
const SENSITIVITY = 'CONFIDENTIAL';
const TRUST = 'TRUSTED';
const T0 = 1_700_000_000_000;
const TTL_MS = 3_600_000;
const CAPACITY = 8;
const OCCURRED_AT = new Date(T0).toISOString();

const WORKLOAD = Object.freeze({
  principalId: 'principal-use-fixture.invalid', workloadId: 'workload-use-fixture.invalid',
});
const PURPOSE = 'support-review-use-fixture.invalid';
const DESTINATION = Object.freeze({
  kind: 'tool.result', ref: 'resource-lookup-use-fixture.invalid', trustZone: 'LOCAL',
  profileId: 'profile-use-fixture.invalid',
});
const SOURCE = Object.freeze({
  kind: 'tool.result', ref: 'source-record-use-fixture.invalid', trustZone: 'LOCAL',
});
const INTERACTION_REF = 'interaction-use-fixture.invalid';
const CANDIDATE_REF = 'candidate-use-fixture.invalid';
const ENTITY_A = 'entity-use-fixture';
const CONTEXT_A = Object.freeze({ ...Object.freeze({
  tenantId: 'tenant-use-alpha.invalid', projectId: 'project-use-alpha.invalid',
  sessionId: 'session-use-alpha.invalid',
}), purpose: PURPOSE });
const SCOPE_A = Object.freeze({ tenantId: CONTEXT_A.tenantId, projectId: CONTEXT_A.projectId,
  sessionId: CONTEXT_A.sessionId });
const SCOPE_B = Object.freeze({
  tenantId: 'tenant-use-beta.invalid', projectId: 'project-use-beta.invalid',
  sessionId: 'session-use-beta.invalid',
});
const OTHER_SUBJECT = Object.freeze({
  principalId: 'principal-other-use-fixture.invalid', workloadId: 'workload-other-use-fixture.invalid',
});

/** Byte equality decided here and returned as one boolean, so a failure prints true/false only. */
function bytesEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) return false;
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/** Fixed synthetic key material for one role. Never a real key, never persisted, never sent. */
function keyBytes(fill) { return new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(fill); }

/* ---------- Counters: the real opener and the real resource effect ---------- */

/**
 * Every real call to the shipped `openMappingPayload` and to the synthetic resource backend's
 * lookup. A refused path is shown to make neither call, rather than to have opened a plaintext or
 * spent a resource and then reported a refusal.
 */
let openCalls = 0;
let effectCalls = 0;
function resetCalls() { openCalls = 0; effectCalls = 0; }

/* ---------- The synthetic trusted resource backend ---------- */

/**
 * The synthetic trusted local resource backend: a lookup over the handle its own resource owns,
 * provisioned **out of band** with that handle. This is the honest boundary of the scenario - a real
 * resource system legitimately knows the identifier of its own record - and it is a literal test
 * fixture, not a shipped store, index or service.
 *
 * The recovered bytes are compared here, inside this closure, and only a fixed non-secret outcome
 * leaves: a status code, a boolean, a byte count. No identifier, string or buffer is ever returned,
 * so neither the caller nor any audit event can see it.
 */
function createResourceBackend({ handle = SYNTHETIC_ORIGINAL } = {}) {
  const provisioned = new TextEncoder().encode(handle);
  return Object.freeze({
    lookup(identifierBytes) {
      effectCalls += 1;
      const matched = bytesEqual(identifierBytes, provisioned);
      return Object.freeze({
        status: matched ? 'RESOURCE_MATCHED' : 'RESOURCE_NOT_FOUND',
        found: matched, matched, identifierBytes: identifierBytes.byteLength,
      });
    },
  });
}

/* ---------- One ephemeral mapping scenario ---------- */

/**
 * One ephemeral mapping scenario. Its metadata lives in the shipped registry, never in this object;
 * the object holds the sealed record, host key material and the entity id the AEAD AAD needs. No
 * original value and no plaintext is retained here: the plaintext is passed in only to be sealed.
 */
function makeMapping({ scope = SCOPE_A, keyFill = 0x11, hmacFill = 0x44 } = {}) {
  const hmacKey = keyBytes(hmacFill);
  const derived = deriveScopedEntityReference({
    scope: 'SESSION', tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId,
    entityId: ENTITY_A, semanticType: CLASS, keyVersion: KEY_VERSION, key: hmacKey,
  });
  assert.equal(derived.state, 'DERIVED');
  return {
    registry: createMappingMetadataRegistry({ capacity: CAPACITY }),
    scope: Object.freeze({ ...scope }),
    mappingRef: derived.token,
    key: keyBytes(keyFill),
    hmacKey,
    entityId: ENTITY_A,
    expiresAt: T0 + TTL_MS,
    envelope: undefined,
  };
}

/** Creates through the registry, activates through the registry, and seals at the current revision. */
function activeMapping(options = {}) {
  const mapping = makeMapping(options);
  const inserted = mapping.registry.insert(
    { version: 1, mappingRef: mapping.mappingRef, scope: { ...mapping.scope },
      expiresAt: mapping.expiresAt }, { now: T0 });
  assert.equal(inserted.state, 'INSERTED');
  assert.equal(inserted.metadata.revision, 1);
  const activated = applyCommand(mapping, { expectedRevision: 1, action: 'ACTIVATE', now: T0 + 1_500 });
  assert.equal(activated.state, 'CHANGED');
  assert.equal(activated.metadata.state, 'ACTIVE');
  assert.equal(activated.metadata.revision, 2);
  const sealed = sealUnder(mapping, activated.metadata.revision);
  assert.equal(sealed.status, 'SEALED');
  return mapping;
}

/**
 * Controlled synthetic host setup: seals the scenario's value under one explicit revision with a
 * fresh nonce drawn from the shipped primitive. This is **not** a lifecycle rotation, rewrap, key
 * rotation or store, and it persists nothing.
 */
function sealUnder(mapping, revision) {
  const sealed = sealMappingPayload({
    scope: aadScope(mapping, revision), plaintext: SYNTHETIC_ORIGINAL_BYTES, key: mapping.key });
  if (sealed.status === 'SEALED') mapping.envelope = sealed.envelope;
  return sealed;
}

/** Every metadata read in this file goes through the registry's own fresh `current` read. */
function readCurrent(mapping, now, { mappingRef = mapping.mappingRef, scope = mapping.scope } = {}) {
  return mapping.registry.current({ version: 1, mappingRef, scope: { ...scope } }, { now });
}
/** One real lifecycle command against the registry's own current record. */
function applyCommand(mapping, { expectedRevision, action, now }) {
  return mapping.registry.transition({ version: 1, mappingRef: mapping.mappingRef,
    scope: { ...mapping.scope }, expectedRevision, action }, { now });
}
/** The trusted metadata projection of one registry record, for the authorization seam. */
function metadataOf(record) {
  return { version: 1, mappingRef: record.mappingRef, scope: { ...record.scope },
    lifecycle: record.state, semanticType: CLASS, sensitivity: SENSITIVITY,
    revision: record.revision, expiresAt: record.expiresAt };
}
/** One explicit, purpose-bound, finite grant, pinned to the revision of the record it was read from. */
function grantFor(mapping, record, operation = 'USE', overrides = {}) {
  return { version: 1, mappingRef: mapping.mappingRef, revision: record.revision,
    principal: { ...WORKLOAD }, context: { ...mapping.scope, purpose: PURPOSE },
    destination: { ...DESTINATION }, operation, expiresAt: record.expiresAt - 1, ...overrides };
}
/** The expected AEAD scope for one explicit revision; the revision always comes from a read. */
function aadScope(mapping, revision) {
  return { tenantId: mapping.scope.tenantId, projectId: mapping.scope.projectId,
    entityId: mapping.entityId, classification: CLASS, mappingRevision: String(revision),
    keyVersion: KEY_VERSION };
}
function cloneEnvelope(envelope) {
  return { version: envelope.version, nonce: Uint8Array.from(envelope.nonce),
    ciphertext: Uint8Array.from(envelope.ciphertext), tag: Uint8Array.from(envelope.tag) };
}

/* ---------- The real Policy Engine seam for USE ---------- */

const RELEASE_TREATMENTS = ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE'];
const EVIDENCE = composeClassification({ detectorEvidence: [{
  version: 1, id: 'detector-use-fixture.invalid', status: 'FOUND',
  provenance: { inputRef: 'field-use-fixture.invalid', producerId: 'detector-use-fixture.invalid',
    producerVersion: 'pack-1' },
  claim: { semanticType: CLASS, sensitivity: SENSITIVITY },
}] }, { interactionRef: INTERACTION_REF, sourceRef: SOURCE.ref, trust: TRUST });

/**
 * One explicitly trusted synthetic policy bundle. Exactly one rule can match the pinned USE request,
 * because the real seam refuses an ambiguous rule set, so `decision` here selects the control
 * (`KEEP`), the fault (`BLOCK`) or the review hold (`REQUIRE_REVIEW`) and nothing else changes.
 */
function policyBundle(decision = 'KEEP') {
  const rule = { id: `rule-use-${decision.toLowerCase()}.invalid`, profileId: DESTINATION.profileId,
    semanticType: CLASS, sensitivities: [SENSITIVITY], sourceTrust: [TRUST], operations: ['USE'],
    decision, ...(decision === 'REQUIRE_REVIEW' ? { reviewTreatments: ['GENERALIZE'] } : {}) };
  return { ...KNOWN_POLICY_BUNDLE,
    profiles: [{ id: DESTINATION.profileId, sink: { ...DESTINATION }, exposure: 'LOCAL',
      permittedTreatments: RELEASE_TREATMENTS, maxCleartextSensitivity: 'RESTRICTED' }],
    rules: [rule] };
}

/** One real `decidePolicy` call over the pinned bundle; the boundary digest is the bundle's content. */
function decideUse(bundle) {
  const boundary = {
    interactionRef: INTERACTION_REF, candidateRef: CANDIDATE_REF,
    classificationDigest: digestClassification(EVIDENCE),
    authenticated: { subject: { ...WORKLOAD }, context: { ...CONTEXT_A } },
    observed: { source: { ...SOURCE, trust: TRUST }, destination: { ...DESTINATION } },
    policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(bundle) },
  };
  const request = { version: 1, interactionRef: INTERACTION_REF, candidateRef: CANDIDATE_REF,
    subject: { ...WORKLOAD }, context: { ...CONTEXT_A }, source: { ...SOURCE },
    destination: { ...DESTINATION }, classification: EVIDENCE, operation: 'USE',
    policy: { ...KNOWN_POLICY_BUNDLE } };
  return decidePolicy(request, boundary, bundle);
}

/* ---------- The real audit seam, with scope-bound fixture keys ---------- */

/**
 * The explicitly trusted audit context: one in-memory stream per tenant/project scope and one pair of
 * literal scope-bound fixture keys. Nothing authenticates a caller here; this is the trusted handoff
 * the core documents, and the keys are ephemeral test literals that never leave this process.
 */
function makeAudit(scope = SCOPE_A) {
  const ledgerScope = { tenantId: scope.tenantId, projectId: scope.projectId };
  const trusted = { version: AUDIT_SCHEMA_VERSION, scope: ledgerScope,
    actor: { principalId: WORKLOAD.principalId, workloadId: WORKLOAD.workloadId },
    integrationId: 'integration-use-fixture.invalid', actorBinding: 'AUTHENTICATED_UPSTREAM',
    pseudonymKey: keyBytes(0x33), chainKey: keyBytes(0x77) };
  return { ledger: createInMemoryAuditLedger(ledgerScope), trusted, ledgerScope };
}
/** The bundle identity recorded with every event: the real policy bundle's own content digest. */
function auditBundle(bundle) {
  return { policy: { id: KNOWN_POLICY_BUNDLE.id, version: KNOWN_POLICY_BUNDLE.version,
      digest: digestPolicyBundle(bundle) },
    components: [{ id: 'NORMALIZATION', version: '1' }, { id: 'DETECTOR', version: '1' },
      { id: 'CLASSIFICATION_POLICY', version: '1' }, { id: 'AUTHORIZATION_POLICY', version: '1' }] };
}
const CLASSIFICATION_REF = Object.freeze({ semanticType: CLASS, sensitivity: SENSITIVITY });

/**
 * One privacy-safe draft: an operation, an outcome, a fixed reason code, a timestamp and opaque
 * references the ledger pseudonymizes. Never an original, a key, a byte buffer or free-text reason.
 * Each kind's optional field set differs, so `classification` is attached only to the kinds whose
 * shipped schema accepts it.
 */
function auditDraft(kind, operation, outcome, reason, mapping, bundle, extra = {}) {
  const base = { version: AUDIT_SCHEMA_VERSION, kind, operation, outcome, reason,
    occurredAt: OCCURRED_AT, bundle: auditBundle(bundle),
    correlationRef: `correlation-${mapping.mappingRef}` };
  if (kind === 'AUTHORIZATION_ATTEMPT') {
    return { ...base, entityRef: mapping.mappingRef, classification: CLASSIFICATION_REF, ...extra };
  }
  return { ...base, candidateRef: CANDIDATE_REF, ...extra };
}

/* ---------- Fixed, non-secret outcomes ---------- */

/** A withheld outcome: fixed strings, numbers and booleans only; no field a buffer could enter. */
function withheld(code) {
  return { outcome: 'WITHHELD', code, opened: false, matched: false, resource: 'NOT_CALLED',
    bytes: 0 };
}
/** Reads one AEAD result into fixed fields, so no assertion receives a byte buffer or a plaintext. */
function projectOpen(value) {
  const projection = { version: 0, status: 'UNREADABLE', finding: 'UNREADABLE',
    findingIsKnown: false, hasPlaintext: false, plaintextIsBuffer: false, plaintextBytes: 0 };
  try {
    if (value?.version === 1) projection.version = 1;
    if (value?.status === 'OPENED' || value?.status === 'REFUSED') projection.status = value.status;
    if (MAPPING_AEAD_FINDINGS.includes(value?.finding)) {
      projection.finding = value.finding;
      projection.findingIsKnown = true;
    }
    projection.hasPlaintext = 'plaintext' in value;
    if (value?.plaintext instanceof Uint8Array) {
      projection.plaintextIsBuffer = true;
      projection.plaintextBytes = value.plaintext.byteLength;
    }
  } catch { /* A hostile result stays UNREADABLE; nothing read from it is echoed anywhere. */ }
  return projection;
}

/**
 * The counted effect tail: the one real call into the shipped opener at an explicit revision, then
 * the one real resource lookup. Success is decided by the backend's own match, never by the open
 * call, and every returned field is a fixed code, boolean or count.
 */
function performEffect(mapping, revision, backend) {
  openCalls += 1;
  const opened = openMappingPayload({ scope: aadScope(mapping, revision),
    envelope: cloneEnvelope(mapping.envelope), key: mapping.key });
  const projection = projectOpen(opened);
  if (projection.status !== 'OPENED') return withheld(projection.finding);
  const looked = backend.lookup(opened.plaintext);
  const bytes = projection.plaintextBytes;
  // Best-effort hygiene in JavaScript, not a zeroization guarantee: the buffer this process still
  // holds is overwritten here, so the recovered bytes do not outlive the inspection.
  opened.plaintext.fill(0);
  if (!looked.matched) {
    return { outcome: 'WITHHELD', code: 'RESOURCE_NOT_FOUND', opened: true, matched: false,
      resource: looked.status, bytes };
  }
  return { outcome: 'USED', code: 'RESOURCE_MATCHED', opened: true, matched: true,
    resource: looked.status, bytes };
}

/* ---------- The trusted USE path: audit before effect, currency before and after ---------- */

/**
 * The USE path this file exists to pin. Seven gates stand between a scenario and a resource effect,
 * in this fixed order:
 *
 *   1. a fresh registry `current` read, before anything else is decided;
 *   2. an actual `AUTHORIZED` decision from the real authorization seam for exactly this operation;
 *   3. an actual `SELECTED` + `KEEP` decision from the real Policy Engine for `USE`;
 *   4. real `appendAuditEvent` calls for the authorization attempt and the policy decision, each one
 *      gated by `gateHighRiskEffect` on the result `appendAuditEvent` itself returned;
 *   5. a second fresh registry currency read, AFTER the audit and BEFORE any effect;
 *   6. the real `openMappingPayload` call at that confirmed revision;
 *   7. the real resource backend lookup, whose success depends on the recovered identifier.
 *
 * Withhold at any gate and no opener call and no backend lookup is made at all.
 *
 * The fault-injection options exist so one test can present each broken precondition against this
 * same real path: `ledgerAccepting: false` makes the real append unavailable, `evidence` replaces
 * the append result the gate is handed, `afterAudit` runs an actual registry command at exactly the
 * point between the audit and the second currency read, and `recheckCurrency: false` removes that
 * second read - the one check the deliberately incomplete host below is forbidden to make.
 */
function useMapping(mapping, options = {}) {
  const now = options.now ?? T0 + 60_000;
  const audit = options.audit ?? makeAudit();
  const bundle = options.bundle ?? policyBundle('KEEP');
  const backend = options.backend ?? createResourceBackend();
  const operation = options.operation ?? 'USE';

  // Gate 1: fresh registry currency, before anything else is decided.
  const fresh = readCurrent(mapping, now, { mappingRef: options.mappingRef, scope: options.scope });
  if (fresh.state !== 'FOUND') return withheld(fresh.reason);
  const metadata = metadataOf(fresh.metadata);

  // Gate 2: the real purpose-bound authorization seam, for exactly the requested operation.
  // An explicitly supplied `grant` is used verbatim, including an explicit `undefined`, which is a
  // host that issued nothing at all and must be refused rather than defaulted.
  const context = { ...(options.scope ?? mapping.scope), purpose: PURPOSE };
  const subject = options.subject ?? WORKLOAD;
  const grant = Object.hasOwn(options, 'grant') ? options.grant
    : grantFor(mapping, fresh.metadata, operation);
  const decision = authorizeMappingOperation(
    { version: 1, mappingRef: mapping.mappingRef, subject: { ...subject }, context: { ...context },
      destination: { ...DESTINATION }, operation },
    { authenticated: { subject: { ...subject }, context: { ...context } },
      observed: { destination: { ...DESTINATION } } },
    metadata, grant, { now });
  if (decision.state !== 'AUTHORIZED') {
    appendAuditEvent(audit.ledger, auditDraft('AUTHORIZATION_ATTEMPT', operation, 'DENIED',
      'RESOLUTION_DENIED', mapping, bundle), audit.trusted);
    return withheld(decision.reason);
  }

  // Gate 3: the real Policy Engine, for USE, over the pinned bundle.
  const policy = decideUse(bundle);
  if (policy.state !== 'SELECTED' || policy.treatment !== 'KEEP') {
    appendAuditEvent(audit.ledger, auditDraft('POLICY_DECISION', 'USE', 'DENIED', 'POLICY_DENIED',
      mapping, bundle, { decision: { state: policy.state, treatment: policy.treatment,
        digest: policy.decisionRef ?? '0'.repeat(64) } }), audit.trusted);
    return withheld(policy.state === 'HELD' ? 'POLICY_HELD' : 'POLICY_DENIED');
  }

  // Gate 4: real audit appends, each gated by the real gate on the result append returned. The
  // events recorded here are ALLOWED decisions only: nothing in this file claims an effect ran.
  const attempt = appendAuditEvent(audit.ledger,
    auditDraft('AUTHORIZATION_ATTEMPT', operation, 'ALLOWED', 'RESOLUTION_AUTHORIZED', mapping, bundle),
    audit.trusted);
  const attemptGate = gateHighRiskEffect(Object.hasOwn(options, 'evidence') ? options.evidence : attempt);
  if (!attemptGate.permitted) return withheld(attemptGate.finding);
  const policyEvent = appendAuditEvent(audit.ledger,
    auditDraft('POLICY_DECISION', 'USE', 'ALLOWED', 'POLICY_ALLOWED', mapping, bundle,
      { decision: { state: policy.state, treatment: policy.treatment, digest: policy.decisionRef } }),
    audit.trusted);
  const policyGate = gateHighRiskEffect(policyEvent);
  if (!policyGate.permitted) return withheld(policyGate.finding);

  // The fault-injection point: a real registry command injected at exactly this stage.
  if (typeof options.afterAudit === 'function') options.afterAudit(mapping);

  // Gate 5: registry currency is rechecked AFTER the authorization and the audit and BEFORE any
  // effect, so a revocation that lands in that window cannot be spent on a cached ACTIVE snapshot.
  if (options.recheckCurrency === false) return performEffect(mapping, metadata.revision, backend);
  const confirm = readCurrent(mapping, now, { mappingRef: options.mappingRef, scope: options.scope });
  if (confirm.state !== 'FOUND') return withheld(confirm.reason);
  if (confirm.metadata.revision !== metadata.revision || confirm.metadata.state !== 'ACTIVE') {
    return withheld('SNAPSHOT_SUPERSEDED');
  }
  return performEffect(mapping, confirm.metadata.revision, backend);
}

/**
 * The deliberately INCOMPLETE host this file forbids: the same real steps with only the post-audit
 * currency read removed, so it spends the snapshot it read before the audit. It is kept in-test so
 * the revocation refusal it contrasts with is provably non-vacuous.
 */
function createIncompleteHost(mapping) {
  return Object.freeze({
    use(options = {}) {
      return useMapping(mapping, { ...options, recheckCurrency: false });
    },
  });
}

/* ---------- 1. The accepted USE effect: audited, current, and identifier-dependent ---------- */

test('an audited USE opens a real resource lookup and returns only a fixed non-secret outcome', () => {
  const mapping = activeMapping();
  const audit = makeAudit();
  const bundle = policyBundle('KEEP');
  resetCalls();
  assert.equal(mapping.registry.size, 1);

  // The registry really holds the live record the path is about to read.
  const fresh = readCurrent(mapping, T0 + 60_000);
  assert.equal(fresh.state, 'FOUND');
  assert.equal(fresh.metadata.state, 'ACTIVE');
  assert.equal(fresh.metadata.revision, 2);

  const used = useMapping(mapping, { audit, bundle, now: T0 + 60_000 });
  assert.equal(used.outcome, 'USED');
  assert.equal(used.code, 'RESOURCE_MATCHED');
  assert.equal(used.opened, true);
  assert.equal(used.matched, true);
  assert.equal(used.resource, 'RESOURCE_MATCHED');
  assert.equal(used.bytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  // Independent literal success: the backend matched the identifier it was provisioned with, and
  // exactly one real opener call and one real effect call happened.
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);
  assert.equal(Object.keys(used).sort().join(','), 'bytes,code,matched,opened,outcome,resource');

  // The actual shipped audit chain, verified with the scope-bound fixture keys and read back as
  // privacy-safe entries: two appended decisions and no event claiming an effect ran.
  assert.equal(audit.ledger.entries.length, 2);
  const anchor = createAuditCheckpoint(audit.ledger, audit.trusted);
  const verified = verifyAuditStream(audit.ledger, audit.trusted, [anchor]);
  assert.equal(verified.status, 'VERIFIED');
  assert.equal(verified.finding, 'VERIFIED_TO_ANCHOR');
  assert.equal(verified.entriesChecked, 2);
  assert.equal(verified.anchorsChecked, 1);
  assert.equal(verified.anchoredThrough, 2);
  assert.equal(verified.unanchoredEntries, 0);
  const unanchored = verifyAuditStream(audit.ledger, audit.trusted, []);
  assert.equal(unanchored.status, 'UNANCHORED');
  assert.equal(unanchored.finding, 'NO_ANCHOR');

  const read = readAuditEvents(audit.ledger,
    { version: 1, scope: audit.ledgerScope, principalId: WORKLOAD.principalId }, {});
  assert.equal(read.status, 'OK');
  assert.equal(read.matched, 2);
  assert.equal(read.entries.length, 2);
  assert.deepEqual(read.entries.map((item) => [item.event.kind, item.event.operation,
    item.event.outcome, item.event.reason]),
  [['AUTHORIZATION_ATTEMPT', 'USE', 'ALLOWED', 'RESOLUTION_AUTHORIZED'],
    ['POLICY_DECISION', 'USE', 'ALLOWED', 'POLICY_ALLOWED']]);
  // Correct stage: an ALLOWED decision is not an APPLIED effect, and no event here records an
  // execution this file did not perform.
  assert.equal(read.entries.some((item) => item.event.outcome === 'APPLIED'), false);
  assert.equal(read.entries.every((item) => item.event.operation === 'USE'), true);
  assert.equal(read.entries.every((item) => item.event.scope.tenantId === SCOPE_A.tenantId), true);

  // The recorded evidence carries pseudonyms and codes, never the planted original, the mapping
  // reference or the resource outcome.
  const image = read.entries.map((item) => serializeAuditEntry(item)).join('\n');
  assert.equal(image.includes(MARKER), false);
  assert.equal(image.includes(SYNTHETIC_ORIGINAL), false);
  assert.equal(image.includes(mapping.mappingRef), false);
  assert.equal(image.includes('RESOURCE_MATCHED'), false);
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);
});

/* ---------- 2. A USE grant never authorizes DISPLAY or EXPORT ---------- */

test('a USE grant is spent as DISPLAY or EXPORT by nothing, while USE itself still works', () => {
  const mapping = activeMapping();
  const audit = makeAudit();
  resetCalls();
  const fresh = readCurrent(mapping, T0 + 60_000);
  const useGrant = grantFor(mapping, fresh.metadata, 'USE');
  const displayGrant = grantFor(mapping, fresh.metadata, 'DISPLAY');

  // Positive control first: the USE grant on the USE path is the one that works.
  const control = useMapping(mapping, { audit, grant: useGrant, now: T0 + 60_000 });
  assert.equal(control.outcome, 'USED');
  assert.equal(control.matched, true);
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);

  // A USE grant handed to any other operation authorizes nothing: no opener call, no effect call.
  for (const operation of ['DISPLAY', 'EXPORT']) {
    const escalated = useMapping(mapping, { audit, grant: useGrant, operation, now: T0 + 61_000 });
    assert.equal(escalated.outcome, 'WITHHELD', operation);
    assert.equal(escalated.code, 'OPERATION_NOT_GRANTED', operation);
    assert.equal(escalated.opened, false, operation);
    assert.equal(escalated.resource, 'NOT_CALLED', operation);
    assert.equal(openCalls, 1, operation);
    assert.equal(effectCalls, 1, operation);
  }

  // And the other direction: a DISPLAY grant cannot be spent as a USE.
  const asUse = useMapping(mapping, { audit, grant: displayGrant, now: T0 + 61_000 });
  assert.equal(asUse.outcome, 'WITHHELD');
  assert.equal(asUse.code, 'OPERATION_NOT_GRANTED');
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);

  // Every refusal was evidenced privately: two ALLOWED decisions, then one denial per attempt,
  // and no event ever claiming an effect.
  assert.equal(audit.ledger.entries.length, 5);
  assert.deepEqual(audit.ledger.entries.map((item) => [item.event.operation, item.event.outcome]),
    [['USE', 'ALLOWED'], ['USE', 'ALLOWED'], ['DISPLAY', 'DENIED'], ['EXPORT', 'DENIED'],
      ['USE', 'DENIED']]);
  assert.equal(audit.ledger.entries[2].event.reason, 'RESOLUTION_DENIED');
  assert.equal(verifyAuditStream(audit.ledger, audit.trusted,
    [createAuditCheckpoint(audit.ledger, audit.trusted)]).status, 'VERIFIED');
});

/* ---------- 3. Missing, foreign, stale and misbound grants withhold ---------- */

test('a missing, foreign, stale, misbound or expired grant withholds before any open or effect', () => {
  const mapping = activeMapping();
  const audit = makeAudit();
  resetCalls();
  const fresh = readCurrent(mapping, T0 + 60_000);
  assert.equal(fresh.state, 'FOUND');

  // Positive control on the very same record, so every refusal below is non-vacuous.
  const control = useMapping(mapping, { audit, now: T0 + 60_000 });
  assert.equal(control.outcome, 'USED');
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);

  const cases = [
    ['no grant at all', undefined, 'NO_GRANT'],
    ['a grant for another mapping reference', grantFor(mapping, fresh.metadata, 'USE',
      { mappingRef: 'map-synthetic-use-foreign.invalid' }), 'GRANT_MISMATCH'],
    ['a grant pinned to a superseded revision', grantFor(mapping, fresh.metadata, 'USE',
      { revision: 1 }), 'STALE_REVISION'],
    ['a grant issued to another workload', grantFor(mapping, fresh.metadata, 'USE',
      { principal: { ...OTHER_SUBJECT } }), 'SCOPE_MISMATCH'],
    ['a grant bound to another purpose', grantFor(mapping, fresh.metadata, 'USE',
      { context: { ...mapping.scope, purpose: 'other-purpose-use-fixture.invalid' } }), 'GRANT_MISMATCH'],
    ['a grant bound to another destination', grantFor(mapping, fresh.metadata, 'USE',
      { destination: { ...DESTINATION, ref: 'other-sink-use-fixture.invalid' } }), 'GRANT_MISMATCH'],
    ['a grant that has already expired', grantFor(mapping, fresh.metadata, 'USE',
      { expiresAt: T0 + 30_000 }), 'GRANT_EXPIRED'],
  ];
  for (const [name, grant, expected] of cases) {
    const attempt = useMapping(mapping, { audit, grant, now: T0 + 90_000 });
    assert.equal(attempt.outcome, 'WITHHELD', name);
    assert.equal(attempt.code, expected, name);
    assert.equal(attempt.opened, false, name);
    assert.equal(attempt.matched, false, name);
    assert.equal(attempt.resource, 'NOT_CALLED', name);
    assert.equal(attempt.bytes, 0, name);
    assert.equal(openCalls, 1, name);
    assert.equal(effectCalls, 1, name);
  }

  // Wrong tenant: a foreign scope is the registry's own unknown-mapping answer, and neither it nor
  // a foreign workload reaches this record.
  const foreign = useMapping(mapping, { audit, scope: SCOPE_B, now: T0 + 90_000 });
  assert.equal(foreign.outcome, 'WITHHELD');
  assert.equal(foreign.code, 'UNKNOWN_MAPPING');
  assert.equal(readCurrent(mapping, T0 + 90_000, { scope: SCOPE_B }).reason, 'UNKNOWN_MAPPING');
  const foreignSubject = useMapping(mapping, { audit, subject: OTHER_SUBJECT, now: T0 + 90_000 });
  assert.equal(foreignSubject.outcome, 'WITHHELD');
  assert.equal(foreignSubject.code, 'SCOPE_MISMATCH');
  assert.equal(foreignSubject.opened, false);
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);
});

/* ---------- 4. Revoked and expired registry records withhold before any effect ---------- */

test('a revoked or expired registry record withholds before any opener call or resource effect', () => {
  const mapping = activeMapping();
  const audit = makeAudit();
  resetCalls();
  const control = useMapping(mapping, { audit, now: T0 + 60_000 });
  assert.equal(control.outcome, 'USED');
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);

  // The registry's own record moves, through its own transition, at its own expected revision.
  const revoked = applyCommand(mapping, { expectedRevision: 2, action: 'REVOKE', now: T0 + 90_000 });
  assert.equal(revoked.state, 'CHANGED');
  assert.equal(revoked.metadata.state, 'REVOKED');
  assert.equal(revoked.metadata.revision, 3);
  const afterRevocation = useMapping(mapping, { audit, now: T0 + 90_000 });
  assert.equal(afterRevocation.outcome, 'WITHHELD');
  assert.equal(afterRevocation.code, 'NOT_LIVE');
  assert.equal(afterRevocation.opened, false);
  assert.equal(afterRevocation.resource, 'NOT_CALLED');
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);

  // The registry's own record for the tombstone, read back through a real idempotent command, is
  // refused by the authorization seam itself and not only by the registry's read.
  const tombstone = applyCommand(mapping, { expectedRevision: 3, action: 'REVOKE', now: T0 + 90_000 });
  assert.equal(tombstone.state, 'UNCHANGED');
  assert.equal(authorizeMappingOperation(
    { version: 1, mappingRef: mapping.mappingRef, subject: { ...WORKLOAD },
      context: { ...CONTEXT_A }, destination: { ...DESTINATION }, operation: 'USE' },
    { authenticated: { subject: { ...WORKLOAD }, context: { ...CONTEXT_A } },
      observed: { destination: { ...DESTINATION } } },
    metadataOf(tombstone.metadata), grantFor(mapping, tombstone.metadata, 'USE'),
    { now: T0 + 90_000 }).reason, 'MAPPING_REVOKED');

  // Expiry: the first observation at or after `expiresAt` refuses the record, and no opener runs.
  const expiring = activeMapping();
  const expiringAudit = makeAudit();
  const beforeExpiry = useMapping(expiring, { audit: expiringAudit, now: T0 + 60_000 });
  assert.equal(beforeExpiry.outcome, 'USED');
  assert.equal(openCalls, 2);
  assert.equal(effectCalls, 2);
  const afterExpiry = useMapping(expiring, { audit: expiringAudit, now: expiring.expiresAt });
  assert.equal(afterExpiry.outcome, 'WITHHELD');
  assert.equal(afterExpiry.code, 'NOT_LIVE');
  assert.equal(afterExpiry.opened, false);
  assert.equal(openCalls, 2);
  assert.equal(effectCalls, 2);
});

/* ---------- 5. A real BLOCK or HELD policy decision withholds before audit, open and effect --- */

test('an actual BLOCK or HELD policy decision withholds before any opener call or effect', () => {
  const mapping = activeMapping();
  resetCalls();

  // Positive control: the same pinned request over the control bundle is SELECTED and spends the
  // effect exactly once.
  const control = useMapping(mapping, { audit: makeAudit(), bundle: policyBundle('KEEP'),
    now: T0 + 60_000 });
  assert.equal(control.outcome, 'USED');
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);

  for (const [decision, expected] of [['BLOCK', 'POLICY_DENIED'], ['REQUIRE_REVIEW', 'POLICY_HELD']]) {
    const audit = makeAudit();
    const refused = useMapping(mapping, { audit, bundle: policyBundle(decision), now: T0 + 61_000 });
    assert.equal(refused.outcome, 'WITHHELD', decision);
    assert.equal(refused.code, expected, decision);
    assert.equal(refused.opened, false, decision);
    assert.equal(refused.matched, false, decision);
    assert.equal(refused.resource, 'NOT_CALLED', decision);
    assert.equal(openCalls, 1, decision);
    assert.equal(effectCalls, 1, decision);
    // The refusal is evidenced at the right stage: one denial event, no ALLOWED event anywhere in
    // this ledger, and no event claiming an execution that did not happen.
    assert.equal(audit.ledger.entries.length, 1, decision);
    assert.equal(audit.ledger.entries[0].event.operation, 'USE', decision);
    assert.equal(audit.ledger.entries[0].event.outcome, 'DENIED', decision);
    assert.equal(audit.ledger.entries[0].event.reason, 'POLICY_DENIED', decision);
    assert.equal(audit.ledger.entries.some((item) => item.event.outcome === 'ALLOWED'), false, decision);
    assert.equal(audit.ledger.entries.some((item) => item.event.outcome === 'APPLIED'), false, decision);
    assert.equal(verifyAuditStream(audit.ledger, audit.trusted,
      [createAuditCheckpoint(audit.ledger, audit.trusted)]).status, 'VERIFIED', decision);
  }
});

/* ---------- 6. Audit evidence that is not accepted withholds before open and effect ---------- */

test('unaccepted or malformed audit evidence withholds before any opener call or effect', () => {
  const mapping = activeMapping();
  resetCalls();

  // A real sink that cannot commit: the shipped append answers AUDIT_UNAVAILABLE and the shipped
  // gate turns that into EVIDENCE_UNAVAILABLE, which is never `permitted`.
  const unavailable = makeAudit();
  unavailable.ledger.accepting = false;
  const outage = useMapping(mapping, { audit: unavailable, now: T0 + 60_000 });
  assert.equal(outage.outcome, 'WITHHELD');
  assert.equal(outage.code, 'EVIDENCE_UNAVAILABLE');
  assert.equal(outage.opened, false);
  assert.equal(outage.resource, 'NOT_CALLED');
  assert.equal(openCalls, 0);
  assert.equal(effectCalls, 0);
  assert.equal(unavailable.ledger.entries.length, 0);

  // Malformed evidence handed to the real gate: a RECORDED claim with no receipt is invalid, and so
  // is a value that is not an append result at all.
  for (const evidence of [{ version: 1, status: 'RECORDED', finding: 'RECORDED' }, {}, null]) {
    const audit = makeAudit();
    const malformed = useMapping(mapping, { audit, evidence, now: T0 + 60_000 });
    assert.equal(malformed.outcome, 'WITHHELD');
    assert.equal(malformed.code, 'EVIDENCE_INVALID');
    assert.equal(malformed.opened, false);
    assert.equal(malformed.resource, 'NOT_CALLED');
    assert.equal(openCalls, 0);
    assert.equal(effectCalls, 0);
  }

  // Positive control on the identical scenario: with an accepting sink the same path opens once and
  // performs the effect once, so the refusals above are about the evidence and nothing else.
  const audit = makeAudit();
  const control = useMapping(mapping, { audit, now: T0 + 60_000 });
  assert.equal(control.outcome, 'USED');
  assert.equal(control.matched, true);
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);
  const appended = appendAuditEvent(audit.ledger,
    auditDraft('AUTHORIZATION_ATTEMPT', 'USE', 'DENIED', 'RESOLUTION_DENIED', mapping,
      policyBundle('KEEP')), audit.trusted);
  assert.equal(appended.status, 'RECORDED');
  assert.equal(gateHighRiskEffect(appended).finding, 'EVIDENCE_RECORDED');
});

/* ---------- 7. Currency is rechecked after the audit, so a revocation there cannot be spent ---- */

test('a revocation injected between the audit and the effect is refused, and the incomplete host spends it', () => {
  const mapping = activeMapping();
  const audit = makeAudit();
  resetCalls();

  // The real path: a genuine REVOKE lands exactly after the audit is recorded and before the second
  // currency read. The pre-audit snapshot is still coherent and the ciphertext is untouched.
  const injected = useMapping(mapping, {
    audit, now: T0 + 60_000,
    afterAudit(target) {
      const revoked = applyCommand(target, { expectedRevision: 2, action: 'REVOKE', now: T0 + 60_000 });
      assert.equal(revoked.state, 'CHANGED');
      assert.equal(revoked.metadata.state, 'REVOKED');
    },
  });
  assert.equal(injected.outcome, 'WITHHELD');
  assert.equal(injected.code, 'NOT_LIVE');
  assert.equal(injected.opened, false);
  assert.equal(injected.matched, false);
  assert.equal(injected.resource, 'NOT_CALLED');
  assert.equal(injected.bytes, 0);
  assert.equal(openCalls, 0);
  assert.equal(effectCalls, 0);

  // The audit trail exists and is honest about what happened: two ALLOWED decisions, verified to an
  // anchor, and no event claiming that an effect ran.
  assert.equal(audit.ledger.entries.length, 2);
  assert.equal(audit.ledger.entries.every((item) => item.event.outcome === 'ALLOWED'), true);
  assert.equal(audit.ledger.entries.some((item) => item.event.outcome === 'APPLIED'), false);
  assert.equal(verifyAuditStream(audit.ledger, audit.trusted,
    [createAuditCheckpoint(audit.ledger, audit.trusted)]).status, 'VERIFIED');

  // The positive fault control: the deliberately incomplete host, which reads the registry once and
  // never rechecks, opens the revoked mapping and still performs the effect at the same instant.
  // That is the fault this file forbids, kept in-test so the refusal above is loadbearing.
  const second = activeMapping();
  const secondAudit = makeAudit();
  const incomplete = createIncompleteHost(second);
  const leaked = incomplete.use({
    audit: secondAudit, now: T0 + 60_000,
    afterAudit(target) {
      const revoked = applyCommand(target, { expectedRevision: 2, action: 'REVOKE', now: T0 + 60_000 });
      assert.equal(revoked.state, 'CHANGED');
    },
  });
  assert.equal(readCurrent(second, T0 + 60_000).state, 'ABSENT');
  assert.equal(leaked.outcome, 'USED');
  assert.equal(leaked.matched, true);
  assert.equal(leaked.bytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);
});

/* ---------- 8. Resource success depends on the recovered identifier ---------- */

test('the resource lookup succeeds only for the identifier its own record was provisioned with', () => {
  const mapping = activeMapping();
  const audit = makeAudit();
  resetCalls();

  // A backend provisioned with a handle this resource does not own: the opener really runs and the
  // ciphertext really decrypts, yet the effect does not succeed. Success is not the open call.
  const wrong = createResourceBackend({ handle: FOREIGN_HANDLE });
  const miss = useMapping(mapping, { audit, backend: wrong, now: T0 + 60_000 });
  assert.equal(miss.outcome, 'WITHHELD');
  assert.equal(miss.code, 'RESOURCE_NOT_FOUND');
  assert.equal(miss.opened, true);
  assert.equal(miss.matched, false);
  assert.equal(miss.resource, 'RESOURCE_NOT_FOUND');
  assert.equal(miss.bytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);

  // The correctly provisioned backend, on the same ciphertext, succeeds.
  const hit = useMapping(mapping, { audit, now: T0 + 60_000 });
  assert.equal(hit.outcome, 'USED');
  assert.equal(hit.matched, true);
  assert.equal(openCalls, 2);
  assert.equal(effectCalls, 2);

  // A mapping whose ciphertext still belongs to a superseded revision is refused by the AEAD
  // itself, so no resource lookup is ever attempted with bytes that did not authenticate.
  const rotated = makeMapping();
  const inserted = rotated.registry.insert(
    { version: 1, mappingRef: rotated.mappingRef, scope: { ...rotated.scope },
      expiresAt: rotated.expiresAt }, { now: T0 });
  assert.equal(inserted.metadata.revision, 1);
  sealUnder(rotated, inserted.metadata.revision);
  const activated = applyCommand(rotated, { expectedRevision: 1, action: 'ACTIVATE', now: T0 + 1_500 });
  assert.equal(activated.metadata.revision, 2);
  const stale = useMapping(rotated, { audit: makeAudit(), now: T0 + 60_000 });
  assert.equal(stale.outcome, 'WITHHELD');
  assert.equal(stale.code, 'AUTHENTICATION_FAILED');
  assert.equal(stale.opened, false);
  assert.equal(stale.resource, 'NOT_CALLED');
  assert.equal(openCalls, 3);
  assert.equal(effectCalls, 2);
});

/* ---------- 9. Cross-tenant audit isolation and ciphertext-only scenario state -------------- */

test('the audit stream is scope-isolated and the scenario holds ciphertext plus non-secret metadata', () => {
  const mapping = activeMapping();
  const audit = makeAudit();
  const foreign = makeAudit(SCOPE_B);
  resetCalls();
  const used = useMapping(mapping, { audit, now: T0 + 60_000 });
  assert.equal(used.outcome, 'USED');
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);

  // Another tenant's authority reads nothing from this stream, and this tenant's own entry digests
  // do not verify under a foreign trusted context.
  const crossTenant = readAuditEvents(audit.ledger,
    { version: 1, scope: foreign.ledgerScope, principalId: WORKLOAD.principalId }, {});
  assert.equal(crossTenant.status, 'RESTRICTED');
  assert.equal(crossTenant.finding, 'SCOPE_MISMATCH');
  assert.equal(crossTenant.matched, 0);
  assert.equal('entries' in crossTenant, false);
  assert.equal(verifyAuditStream(audit.ledger, foreign.trusted,
    [createAuditCheckpoint(audit.ledger, audit.trusted)]).status, 'UNAVAILABLE');
  assert.equal(foreign.ledger.entries.length, 0);
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);

  // The registry and the scenario hold ciphertext plus non-secret metadata, never the original.
  const fresh = readCurrent(mapping, T0 + 60_000);
  assert.equal(Object.keys(fresh.metadata).sort().join(','),
    'createdAt,expiresAt,mappingRef,revision,scope,state,version');
  assert.equal('plaintext' in mapping, false);
  assert.equal('original' in mapping, false);
  assert.equal('ciphertext' in mapping, false);
  assert.equal(Object.keys(mapping.envelope).sort().join(','), 'ciphertext,nonce,tag,version');
  const image = JSON.stringify({ version: mapping.envelope.version,
    nonce: [...mapping.envelope.nonce], ciphertext: [...mapping.envelope.ciphertext],
    tag: [...mapping.envelope.tag], mappingRef: mapping.mappingRef,
    tenantId: mapping.scope.tenantId, revision: fresh.metadata.revision });
  assert.equal(image.includes(MARKER), false);
  assert.equal(image.includes(SYNTHETIC_ORIGINAL), false);
  assert.equal(openCalls, 1);
  assert.equal(effectCalls, 1);
});