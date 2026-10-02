// #28 bounded OFFLINE policy governance substrate: behaviour tests over synthetic, non-routable
// `.invalid` / `example.invalid` data only. No provider, no network, no customer data.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SENSITIVITIES, SEMANTIC_CLASSES, TRUST_LEVELS } from '../dist/classification.js';
import {
  KNOWN_POLICY_BUNDLE, decidePolicy, digestClassification, digestPolicyBundle,
} from '../dist/policy.js';
import { createInMemoryAuditLedger, readAuditEvents } from '../dist/audit-ledger.js';
import { composeClassification } from '../dist/classification.js';
import {
  GOVERNANCE_LIMITS, GOVERNANCE_MAX_EXCEPTION_TTL_MS, GOVERNANCE_PROMOTION_GATES,
  GOVERNANCE_ZERO_DIGEST, PolicyGovernanceError, activatePolicyConfiguration,
  createPolicyConfiguration, createPolicyException, createPolicyRegistry,
  digestPolicyConfiguration, digestPolicyException, evaluatePolicyException, registerPolicyException,
  revokePolicyException, simulatePolicyConfiguration,
} from '../dist/policy-governance.js';

const copy = (value) => structuredClone(value);
const ZERO64 = GOVERNANCE_ZERO_DIGEST;
const ISO = (value) => new Date(value).toISOString();
const T0 = Date.parse('2026-10-01T00:00:00.000Z');

// Obviously synthetic, non-routable identities. No real principal, tenant, project or sink.
const scopeA = { tenantId: 'tenant-a.invalid', projectId: 'project-a.invalid' };
const scopeB = { tenantId: 'tenant-b.invalid', projectId: 'project-b.invalid' };
const subjectA = { principalId: 'principal-a.invalid', workloadId: 'workload-a.invalid' };
const approverA = { principalId: 'approver-a.invalid', workloadId: 'workload-approver-a.invalid' };

// Obviously synthetic planted originals. They must never appear in any output, refusal or record.
const PLANTED = [
  'planted-original-person-a1',
  'planted-original-customer-c3',
  'planted-original-secret-d4',
];
const PLANTED_MAIL = 'planted.original@planted.invalid';

const sinks = {
  local: { kind: 'local.tool', ref: 'tool-local.example.invalid', trustZone: 'LOCAL',
    profileId: 'local.invalid' },
  allowed: { kind: 'model', ref: 'https://allowed.example.invalid/v1', trustZone: 'EXTERNAL',
    profileId: 'allowed.invalid' },
  exfil: { kind: 'web', ref: 'https://exfil.example.invalid/collect', trustZone: 'EXTERNAL',
    profileId: 'exfil.invalid' },
};
const release = ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE'];
const profiles = [
  { id: 'local.invalid', sink: sinks.local, exposure: 'LOCAL', permittedTreatments: release,
    maxCleartextSensitivity: 'SECRET' },
  { id: 'allowed.invalid', sink: sinks.allowed, exposure: 'EXTERNAL', permittedTreatments: release,
    maxCleartextSensitivity: 'INTERNAL' },
  { id: 'exfil.invalid', sink: sinks.exfil, exposure: 'EXTERNAL',
    permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'PUBLIC' },
];
function rule(id, profileId, semanticType, values, operations, decision, reviewTreatments) {
  return { id: `${id}.invalid`, profileId, semanticType, sensitivities: values,
    sourceTrust: [...TRUST_LEVELS], operations, decision,
    ...(reviewTreatments ? { reviewTreatments } : {}) };
}
/** Baseline: the external allowed sink holds CONFIDENTIAL/RESTRICTED for review; exfil allows nothing. */
function baselineBundle() {
  const rules = [];
  for (const semanticType of SEMANTIC_CLASSES) {
    rules.push(rule(`local-use-${semanticType}`, 'local.invalid', semanticType, SENSITIVITIES, ['USE'],
      'KEEP'));
    rules.push(rule(`allowed-public-${semanticType}`, 'allowed.invalid', semanticType, ['PUBLIC'], ['SEND'],
      'KEEP'));
    rules.push(rule(`allowed-internal-${semanticType}`, 'allowed.invalid', semanticType, ['INTERNAL'],
      ['SEND'], 'TOKENIZE'));
    rules.push(rule(`allowed-review-${semanticType}`, 'allowed.invalid', semanticType,
      ['CONFIDENTIAL', 'RESTRICTED'], ['SEND'], 'REQUIRE_REVIEW', ['GENERALIZE', 'REMOVE']));
    rules.push(rule(`exfil-public-${semanticType}`, 'exfil.invalid', semanticType, ['PUBLIC'], ['SEND'],
      'KEEP'));
  }
  rules.push(rule('allowed-credential-remove', 'allowed.invalid', 'CREDENTIAL_OR_SECRET', ['SECRET'],
    ['SEND'], 'REMOVE'));
  return { ...KNOWN_POLICY_BUNDLE, profiles: copy(profiles), rules };
}
/**
 * Candidate: releases the held CONFIDENTIAL SEND immediately, and raises the exfil sink's
 * cleartext ceiling together with a rule, so the exfil sink becomes a newly exposed destination.
 */
function relaxedBundle() {
  const base = baselineBundle();
  const rules = base.rules.filter((item) => item.id !== 'allowed-review-PERSON.invalid');
  rules.push(rule('allowed-review-person-candidate', 'allowed.invalid', 'PERSON', ['CONFIDENTIAL'],
    ['SEND'], 'SYNTHETIC'));
  rules.push(rule('exfil-confidential-candidate', 'exfil.invalid', 'PERSON', ['CONFIDENTIAL'], ['SEND'],
    'KEEP'));
  const exposed = copy(profiles);
  exposed[2].maxCleartextSensitivity = 'RESTRICTED';
  return { ...base, profiles: exposed, rules };
}

const trustedContextFor = (scope = scopeA) => ({
  version: 1,
  scope: copy(scope),
  actor: copy(approverA),
  integrationId: 'integration-a.invalid',
  actorBinding: 'AUTHENTICATED_UPSTREAM',
  pseudonymKey: Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) % 251),
  chainKey: Uint8Array.from({ length: 32 }, (_, i) => (i * 5 + 11) % 251),
});
function auditHook(scope = scopeA, overrides = {}) {
  return {
    version: 1,
    scope: copy(scope),
    ledger: overrides.ledger ?? createInMemoryAuditLedger(scope),
    trusted: overrides.trusted ?? trustedContextFor(scope),
    components: [
      { id: 'CLASSIFICATION_POLICY', version: '1' },
      { id: 'AUTHORIZATION_POLICY', version: '1' },
    ],
    correlationRef: overrides.correlationRef ?? 'governance-run-a.invalid',
    occurredAt: overrides.occurredAt ?? ISO(T0),
  };
}

function configuration(bundle = baselineBundle(), overrides = {}) {
  return createPolicyConfiguration({
    version: 1,
    configVersion: 1,
    revision: overrides.revision ?? 2,
    createdAt: overrides.createdAt ?? ISO(T0),
    purpose: overrides.purpose ?? 'policy-activation-a.invalid',
    bundle: copy(bundle),
    ...(overrides.pinnedDigest ? { pinnedDigest: overrides.pinnedDigest } : {}),
  });
}
function exception(overrides = {}) {
  return createPolicyException({
    version: 1,
    id: overrides.id ?? 'exception-a.invalid',
    scope: copy(overrides.scope ?? scopeA),
    subject: copy(overrides.subject ?? subjectA),
    purpose: overrides.purpose ?? 'support-review-a.invalid',
    semanticType: overrides.semanticType ?? 'PERSON',
    sensitivity: overrides.sensitivity ?? 'CONFIDENTIAL',
    destination: copy(overrides.destination ?? { profileId: 'allowed.invalid',
      sinkRef: sinks.allowed.ref }),
    operation: overrides.operation ?? 'SEND',
    treatment: overrides.treatment ?? 'GENERALIZE',
    configRevision: overrides.configRevision ?? 2,
    issuedAt: overrides.issuedAt ?? ISO(T0),
    expiresAt: overrides.expiresAt ?? ISO(T0 + 3_600_000),
  });
}
/**
 * A configuration-activation approval. `configDigest` is the content commitment of the
 * **currently active** configuration, or the zero digest when the registry has never activated
 * one: an approval minted against a configuration that has since been replaced cannot act.
 */
function configApproval(candidate, activeConfig, overrides = {}) {
  const { binding, ...rest } = overrides;
  return {
    version: 1,
    authority: 'TRUSTED_INTEGRATION',
    approvalRef: 'approval-a.invalid',
    scope: copy(scopeA),
    approver: copy(approverA),
    purpose: candidate.purpose,
    operation: 'DEPLOY',
    revision: candidate.revision,
    configDigest: activeConfig ? digestPolicyConfiguration(activeConfig) : GOVERNANCE_ZERO_DIGEST,
    targetDigest: digestPolicyConfiguration(candidate),
    validFrom: ISO(T0 - 60_000),
    validUntil: ISO(T0 + 900_000),
    ...rest,
    ...(binding ? { binding: copy(binding) } : {}),
  };
}
function exceptionApproval(ref, activeConfig, overrides = {}) {
  const { binding, ...rest } = overrides;
  return {
    version: 1,
    authority: 'TRUSTED_INTEGRATION',
    approvalRef: 'approval-exception-a.invalid',
    scope: copy(scopeA),
    approver: copy(approverA),
    purpose: ref.purpose,
    operation: 'UPDATE',
    revision: ref.configRevision,
    configDigest: activeConfig ? digestPolicyConfiguration(activeConfig) : GOVERNANCE_ZERO_DIGEST,
    targetDigest: ref.digest,
    validFrom: ISO(T0 - 60_000),
    validUntil: ISO(T0 + 900_000),
    ...rest,
    ...('binding' in overrides ? { binding: copy(binding) } : { binding: exceptionBinding(ref) }),
  };
}
function exceptionBinding(ref) {
  return {
    subject: copy(ref.subject),
    semanticType: ref.semanticType,
    sensitivity: ref.sensitivity,
    destination: copy(ref.destination),
    operation: ref.operation,
  };
}
/** A registry with `configuration` already activated at revision 2 through the real path. */
function activeRegistry(bundle = baselineBundle(), scope = scopeA) {
  const registry = createPolicyRegistry(scope);
  const configurationRef = configuration(bundle);
  const hook = auditHook(scope);
  const outcome = activatePolicyConfiguration(registry, configurationRef,
    configApproval(configurationRef, null, { scope: copy(scope) }), hook, ISO(T0));
  assert.equal(outcome.state, 'APPLIED', JSON.stringify(outcome));
  return { registry, configuration: configurationRef, hook };
}

/** Candidate that ADDS a destination profile the baseline does not declare at all. */
function addedSinkBundle() {
  const base = baselineBundle();
  const moved = copy(profiles);
  moved.push({ id: 'third.invalid', sink: { kind: 'web',
    ref: 'https://third-party.example.invalid/collect', trustZone: 'EXTERNAL',
    profileId: 'third.invalid' }, exposure: 'EXTERNAL',
    permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'RESTRICTED' });
  const rules = base.rules.filter((item) => item.profileId !== 'third.invalid');
  rules.push(rule('third-person-candidate', 'third.invalid', 'PERSON', ['CONFIDENTIAL'], ['SEND'],
    'KEEP'));
  return { ...base, profiles: moved, rules };
}
/** Candidate that REBINDS an existing profile to a different exact sink reference. */
function reboundSinkBundle() {
  const base = baselineBundle();
  const moved = copy(profiles);
  moved[1].sink.ref = 'https://exfil-moved.example.invalid/v1';
  return { ...base, profiles: moved };
}

function probe(profileId, semanticType, sensitivity, operation, overrides = {}) {
  return { version: 1, profileId, semanticType, sensitivity, operation,
    sourceTrust: overrides.sourceTrust ?? 'TRUSTED', ...(overrides.probeId
      ? { probeId: overrides.probeId } : {}) };
}
/** Bounded read of one #20 stream's length and chain head, for unchanged-after-denial assertions. */
function chainHead(ledger) {
  const entries = ledger.entries;
  const length = Object.getOwnPropertyDescriptor(entries, 'length').value;
  if (length === 0) return { entries: 0, head: null };
  const last = Object.getOwnPropertyDescriptor(entries, String(length - 1));
  return { entries: length, head: last.value.entryDigest };
}
function sinkRefFor(profileId) {
  return { 'local.invalid': sinks.local.ref, 'allowed.invalid': sinks.allowed.ref,
    'exfil.invalid': sinks.exfil.ref }[profileId];
}
function classificationFor(semanticType, sensitivity, trust) {
  return composeClassification({ detectorEvidence: [{
    version: 1, id: 'detector-governance.invalid', status: 'FOUND',
    provenance: { inputRef: 'unit-a.invalid', producerId: 'detector-a.invalid',
      producerVersion: 'pack-1' },
    claim: { semanticType, sensitivity },
  }] }, { interactionRef: 'interaction-governance.invalid',
    sourceRef: 'tool-source-governance.invalid', trust });
}
/** The same decision the simulation runs, assembled independently in the test. */
function independentDecision(bundle, p, absentDestination) {
  const profile = bundle.profiles.find((item) => item.id === p.profileId);
  if (!profile && !absentDestination) return null;
  const destination = profile ? profile.sink : absentDestination;
  const classification = classificationFor(p.semanticType, p.sensitivity, p.sourceTrust);
  const subject = { principalId: 'principal-a.invalid' };
  const context = { tenantId: scopeA.tenantId, projectId: scopeA.projectId,
    sessionId: 'session-governance.invalid', purpose: 'support-review-a.invalid' };
  const source = { kind: 'tool.result', ref: 'tool-source-governance.invalid', trustZone: 'LOCAL' };
  const boundary = {
    interactionRef: 'interaction-governance.invalid', candidateRef: 'unit-governance.invalid',
    classificationDigest: digestClassification(classification),
    authenticated: { subject: copy(subject), context: copy(context) },
    observed: { source: { ...copy(source), trust: p.sourceTrust }, destination: copy(destination) },
    policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(bundle) },
  };
  const request = {
    version: 1, interactionRef: boundary.interactionRef, candidateRef: boundary.candidateRef,
    subject: copy(subject), context: copy(context), source: copy(source),
    destination: copy(destination), classification, operation: p.operation,
    policy: copy(KNOWN_POLICY_BUNDLE),
  };
  return decidePolicy(request, boundary, bundle);
}

test('governance configuration refuses an unsupported policy id/version and a forged pin', () => {
  const bundle = baselineBundle();
  const spec = (overrides = {}) => ({ version: 1, configVersion: 1, revision: 2,
    createdAt: ISO(T0), purpose: 'policy-activation-a.invalid', bundle: copy(bundle), ...overrides });
  for (const mutation of [{ id: 'other.control-plane' }, { version: '2' }]) {
    assert.throws(() => createPolicyConfiguration(spec({
      bundle: { ...bundle, ...mutation } })), (error) => error instanceof PolicyGovernanceError &&
      error.code === 'CONFIGURATION_POLICY_VERSION_UNSUPPORTED');
  }
  assert.throws(() => createPolicyConfiguration(spec({ configVersion: 2 })),
    (error) => error instanceof PolicyGovernanceError &&
      error.code === 'CONFIGURATION_VERSION_UNSUPPORTED');
  const digest = digestPolicyConfiguration(configuration(bundle));
  assert.throws(() => createPolicyConfiguration(spec({ pinnedDigest: ZERO64 })), (error) =>
    error instanceof PolicyGovernanceError && error.code === 'CONFIGURATION_CONTENT_CHANGED');
  // The same configuration accepts its own recomputed digest: the pin is congruence, not a secret.
  assert.doesNotThrow(() => createPolicyConfiguration(spec({ pinnedDigest: digest })));
  assert.throws(() => configuration(baselineBundle(), { pinnedDigest: `${'a'.repeat(64)}` }),
    (error) => error instanceof PolicyGovernanceError);
});

test('governance configuration revision and content pin are distinct from the policy schema version', () => {
  const first = configuration(baselineBundle(), { revision: 2 });
  const second = configuration(baselineBundle(), { revision: 3 });
  assert.equal(first.bundleDigest, second.bundleDigest, 'content pin is independent of revision');
  assert.notEqual(digestPolicyConfiguration(first), digestPolicyConfiguration(second));
  assert.equal(first.policy.id, KNOWN_POLICY_BUNDLE.id);
  assert.equal(first.policy.version, KNOWN_POLICY_BUNDLE.version);
  const third = configuration(relaxedBundle(), { revision: 2 });
  assert.notEqual(third.bundleDigest, first.bundleDigest, 'content pin tracks the bundle content');
});

test('activation requires an exact approval and records through the #20 ledger', () => {
  const registry = createPolicyRegistry(scopeA);
  const configurationRef = configuration(baselineBundle());
  const hook = auditHook(scopeA);
  const outcome = activatePolicyConfiguration(registry, configurationRef,
    configApproval(configurationRef, null), hook, ISO(T0));
  assert.equal(outcome.state, 'APPLIED');
  assert.equal(outcome.reason, 'CONFIGURATION_ACTIVATED');
  assert.equal(outcome.revision, 2);
  assert.equal(outcome.authority, 'NONE');
  assert.equal(outcome.effect, 'SYNTHETIC_REGISTRY_ONLY');
  assert.deepEqual(outcome.promotion.gates, GOVERNANCE_PROMOTION_GATES);
  assert.equal(outcome.audit.status, 'RECORDED');
  assert.equal(registry.config.revision, 2);
  assert.equal(registry.config.bundleDigest, digestPolicyBundle(baselineBundle()));
  const read = readAuditEvents(hook.ledger,
    { version: 1, scope: copy(scopeA), principalId: 'principal-a.invalid' }, {});
  assert.equal(read.status, 'OK');
  assert.equal(read.entries.length, 1);
  const entry = read.entries[0].event;
  assert.equal(entry.kind, 'POLICY_OPERATION');
  assert.equal(entry.operation, 'DEPLOY');
  assert.equal(entry.outcome, 'APPLIED');
  assert.equal(entry.bundle.policy.digest, digestPolicyBundle(baselineBundle()));
});

test('missing, forged, substituted, stale and future-dated approvals deny and leave the registry unchanged', () => {
  const cases = [
    ['missing', null, 'APPROVAL_MISSING'],
    ['forged authority', { authority: 'SELF_ASSERTED' }, 'INVALID_APPROVAL'],
    ['forged digest', { targetDigest: 'f'.repeat(64) }, 'APPROVAL_MISMATCH'],
    ['forged revision', { revision: 99 }, 'APPROVAL_MISMATCH'],
    ['forged version', { version: 2 }, 'INVALID_APPROVAL'],
    ['foreign tenant', { scope: copy(scopeB) }, 'APPROVAL_MISMATCH'],
    ['changed purpose', { purpose: 'other-purpose-a.invalid' }, 'APPROVAL_MISMATCH'],
    ['changed operation', { operation: 'UPDATE' }, 'APPROVAL_MISMATCH'],
    ['planted free text purpose', { purpose: PLANTED_MAIL }, 'INVALID_APPROVAL'],
    ['expired window', { validFrom: ISO(T0 - 1800_000), validUntil: ISO(T0 - 1) },
      'APPROVAL_EXPIRED'],
    ['future window', { validFrom: ISO(T0 + 3600_000), validUntil: ISO(T0 + 4500_000) },
      'APPROVAL_NOT_YET_VALID'],
    ['oversized window', { validFrom: ISO(T0 - 60_000), validUntil: ISO(T0 + 86_400_001) },
      'APPROVAL_TTL_EXCEEDED'],
  ];
  for (const [label, overrides, expected] of cases) {
    const registry = createPolicyRegistry(scopeA);
    const configurationRef = configuration(baselineBundle());
    const forged = overrides === null ? undefined
      : configApproval(configurationRef, null, overrides ?? {});
    const outcome = activatePolicyConfiguration(registry, configurationRef, forged, auditHook(scopeA),
      ISO(T0));
    assert.equal(outcome.state, 'DENIED', label);
    assert.equal(outcome.reason, expected, label);
    assert.equal(registry.config, null, `${label} must not promote`);
  }
});

test('an approval bound to another exact configuration digest cannot activate this one', () => {
  const registry = createPolicyRegistry(scopeA);
  const candidate = configuration(relaxedBundle());
  const other = configuration(baselineBundle());
  // A genuine approval for the baseline snapshot, replayed against the relaxed candidate.
  const outcome = activatePolicyConfiguration(registry, candidate,
    configApproval(other, null), auditHook(scopeA), ISO(T0));
  assert.equal(outcome.state, 'DENIED');
  assert.equal(outcome.reason, 'APPROVAL_MISMATCH');
  assert.equal(registry.config, null);
});

test('stale and replayed revisions deny: only a strictly newer revision activates', () => {
  const { registry } = activeRegistry(baselineBundle());
  assert.equal(registry.config.revision, 2);
  const replay = configuration(baselineBundle(), { revision: 2 });
  const first = activatePolicyConfiguration(registry, replay,
    configApproval(replay, registry.config), auditHook(scopeA), ISO(T0 + 1000));
  assert.equal(first.state, 'DENIED');
  assert.equal(first.reason, 'CONFIGURATION_ALREADY_ACTIVE');
  const older = configuration(baselineBundle(), { revision: 1 });
  const second = activatePolicyConfiguration(registry, older,
    configApproval(older, registry.config), auditHook(scopeA), ISO(T0 + 1000));
  assert.equal(second.state, 'DENIED');
  assert.equal(second.reason, 'CONFIGURATION_STALE');
  assert.equal(registry.config.revision, 2);
});

test('policy content altered after approval is refused at activation and at evaluation', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const candidate = configuration(relaxedBundle(), { revision: 3 });
  // The approval is genuine for revision 3; the *stored* bundle is mutated afterwards.
  candidate.bundle.rules.push({
    id: 'injected-wildcard.invalid', profileId: 'exfil.invalid', semanticType: 'PERSON',
    sensitivities: SENSITIVITIES, sourceTrust: TRUST_LEVELS, operations: ['SEND', 'USE', 'DISPLAY',
      'EXPORT'], decision: 'KEEP',
  });
  const outcome = activatePolicyConfiguration(registry, candidate,
    configApproval(candidate, configurationRef), auditHook(scopeA), ISO(T0 + 1000));
  assert.equal(outcome.state, 'DENIED');
  assert.equal(outcome.reason, 'CONFIGURATION_CONTENT_CHANGED');
  assert.equal(registry.config.revision, 2, 'the active revision must not move');
});

test('audit unavailability or scope mismatch leaves a high-risk activation unchanged', () => {
  for (const [label, hook, expected] of [
    ['sealed ledger', auditHook(scopeA, { ledger: (() => {
      const ledger = createInMemoryAuditLedger(scopeA);
      ledger.accepting = false;
      return ledger;
    })() }), 'AUDIT_UNAVAILABLE'],
    ['foreign audit scope', auditHook(scopeB), 'AUDIT_SCOPE_MISMATCH'],
    ['unusable keys', auditHook(scopeA, { trusted: { ...trustedContextFor(scopeA),
      chainKey: new Uint8Array(32) } }), 'AUDIT_EVIDENCE_INVALID'],
  ]) {
    const registry = createPolicyRegistry(scopeA);
    const configurationRef = configuration(baselineBundle());
    const outcome = activatePolicyConfiguration(registry, configurationRef,
      configApproval(configurationRef, null), hook, ISO(T0));
    assert.equal(outcome.state, 'DENIED', label);
    assert.equal(outcome.reason, expected, label);
    assert.equal(registry.config, null, `${label} must leave the registry unchanged`);
  }
});

test('a hook that self-declares tenant A but carries tenant B writes nothing anywhere', () => {
  const configurationRef = configuration(baselineBundle());
  const mixedHook = () => auditHook(scopeA, { ledger: createInMemoryAuditLedger(scopeB),
    trusted: trustedContextFor(scopeB) });
  // Activation: the registry must not change AND tenant B's chain must not advance.
  const registry = createPolicyRegistry(scopeA);
  const mixed = mixedHook();
  const before = chainHead(mixed.ledger);
  const outcome = activatePolicyConfiguration(registry, configurationRef,
    configApproval(configurationRef, null), mixed, ISO(T0));
  assert.equal(outcome.state, 'DENIED');
  assert.equal(outcome.reason, 'AUDIT_SCOPE_MISMATCH');
  assert.equal(outcome.audit.status, 'NOT_ATTEMPTED', 'no append was even attempted');
  assert.equal(registry.config, null, 'a foreign-scope audit must not activate anything');
  assert.deepEqual(chainHead(mixed.ledger), before,
    'no event may be committed into the foreign chain, and its head must not advance');
  assert.equal(readAuditEvents(mixed.ledger,
    { version: 1, scope: copy(scopeB), principalId: 'principal-a.invalid' }, {}).matched, 0);
  // Exception registration: same invariant.
  const { registry: live } = activeRegistry(baselineBundle());
  const ref = exception();
  const registrationHook = mixedHook();
  const registrationBefore = chainHead(registrationHook.ledger);
  const registered = registerPolicyException(live, ref, exceptionApproval(ref, configurationRef),
    registrationHook, ISO(T0));
  assert.equal(registered.state, 'DENIED');
  assert.equal(registered.reason, 'AUDIT_SCOPE_MISMATCH');
  assert.equal(live.exceptions.length, 0);
  assert.deepEqual(chainHead(registrationHook.ledger), registrationBefore);
  // Revocation of a genuinely registered exception: it must stay live and tenant B untouched.
  const { registry: revoking, configuration: activeRef } = activeRegistry(baselineBundle());
  const liveRef = exception();
  assert.equal(registerPolicyException(revoking, liveRef, exceptionApproval(liveRef, activeRef),
    auditHook(scopeA), ISO(T0)).state, 'APPLIED');
  const revocationHook = mixedHook();
  const revocationBefore = chainHead(revocationHook.ledger);
  const revoked = revokePolicyException(revoking, liveRef.id,
    exceptionApproval(liveRef, activeRef), revocationHook, ISO(T0));
  assert.equal(revoked.state, 'DENIED');
  assert.equal(revoked.reason, 'AUDIT_SCOPE_MISMATCH');
  assert.equal(revoking.exceptions[0].revokedAt, null, 'a live exception must stay live');
  assert.deepEqual(chainHead(revocationHook.ledger), revocationBefore);
});

test('the ledger and trusted scopes are read before any append, never trusted from the hook', () => {
  const configurationRef = configuration(baselineBundle());
  // The hook declares tenant A and carries something that is not an #20 ledger at all: the refusal
  // happens before an append, so nothing is attempted anywhere.
  const registry = createPolicyRegistry(scopeA);
  const foreign = { version: 1, scope: copy(scopeA), entries: [] };
  const outcome = activatePolicyConfiguration(registry, configurationRef,
    configApproval(configurationRef, null),
    auditHook(scopeA, { ledger: foreign, trusted: trustedContextFor(scopeA) }), ISO(T0));
  assert.equal(outcome.state, 'DENIED');
  assert.equal(outcome.reason, 'INVALID_AUDIT_HOOK');
  assert.equal(outcome.audit.status, 'NOT_ATTEMPTED');
  assert.equal(registry.config, null);
  // A ledger scoped to another tenant is refused on its own scope, not on the hook's declaration.
  const mismatched = auditHook(scopeA, { ledger: createInMemoryAuditLedger(
    { tenantId: scopeA.tenantId }), trusted: trustedContextFor({ tenantId: scopeA.tenantId }) });
  const second = activatePolicyConfiguration(createPolicyRegistry(scopeA), configurationRef,
    configApproval(configurationRef, null), mismatched, ISO(T0));
  assert.equal(second.state, 'DENIED');
  assert.equal(second.reason, 'AUDIT_SCOPE_MISMATCH');
  assert.deepEqual(chainHead(mismatched.ledger), { entries: 0, head: null },
    'a stream carrying no project is not this registry\'s stream, and stays empty');
  // A trusted context scoped to another tenant is refused before the append as well.
  const mixedTrusted = auditHook(scopeA, { trusted: trustedContextFor(scopeB) });
  const third = activatePolicyConfiguration(createPolicyRegistry(scopeA), configurationRef,
    configApproval(configurationRef, null), mixedTrusted, ISO(T0));
  assert.equal(third.state, 'DENIED');
  assert.equal(third.reason, 'AUDIT_SCOPE_MISMATCH');
  assert.deepEqual(chainHead(mixedTrusted.ledger), { entries: 0, head: null });
});

test('a narrow exception applies inside its exact tuple and stops applying at expiry', () => {
  const { registry, configuration: configurationRef, hook } = activeRegistry(baselineBundle());
  const ref = exception({ expiresAt: ISO(T0 + 3_600_000) });
  const registered = registerPolicyException(registry, ref, exceptionApproval(ref, configurationRef),
    hook, ISO(T0));
  assert.equal(registered.state, 'APPLIED');
  assert.equal(registered.reason, 'EXCEPTION_REGISTERED');
  const binding = {
    scope: copy(scopeA), subject: copy(subjectA), purpose: 'support-review-a.invalid',
    semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
    destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
  };
  const live = evaluatePolicyException(registry, ref.id, binding, ISO(T0 + 1_800_000));
  assert.equal(live.state, 'APPLICABLE');
  assert.equal(live.reason, 'EXCEPTION_APPLICABLE');
  assert.equal(live.authority, 'NONE');
  assert.equal(live.grantsTreatment, false, 'an exception never grants a treatment');
  assert.equal(live.requiresPolicyDecision, true);
  assert.equal(live.expiresAt, ref.expiresAt);
  // The exact expiry instant is the first instant at which it does not apply.
  for (const at of [ref.expiresAt, ISO(T0 + 3_600_001), ISO(T0 + 86_400_000)]) {
    const expired = evaluatePolicyException(registry, ref.id, binding, at);
    assert.equal(expired.state, 'DENIED', at);
    assert.equal(expired.reason, 'EXCEPTION_EXPIRED', at);
  }
  const read = readAuditEvents(hook.ledger,
    { version: 1, scope: copy(scopeA), principalId: 'principal-a.invalid' }, {});
  assert.equal(read.entries.length, 2, 'the exception registration is audited too');
});

test('a replayed binding outside the exact tuple denies with a fixed code', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const ref = exception();
  registerPolicyException(registry, ref,
    exceptionApproval(ref, configurationRef),
    auditHook(scopeA), ISO(T0));
  const base = {
    scope: copy(scopeA), subject: copy(subjectA), purpose: 'support-review-a.invalid',
    semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
    destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
  };
  const mutations = [
    ['tenant', { ...base, scope: copy(scopeB) }, 'EXCEPTION_SCOPE_MISMATCH'],
    ['project', { ...base, scope: { tenantId: scopeA.tenantId, projectId: 'project-b.invalid' } },
      'EXCEPTION_SCOPE_MISMATCH'],
    ['subject', { ...base, subject: { principalId: 'principal-b.invalid' } },
      'EXCEPTION_BINDING_MISMATCH'],
    ['purpose', { ...base, purpose: 'other-purpose-a.invalid' }, 'EXCEPTION_BINDING_MISMATCH'],
    ['class', { ...base, semanticType: 'CUSTOMER_OR_PARTNER' }, 'EXCEPTION_BINDING_MISMATCH'],
    ['sensitivity', { ...base, sensitivity: 'RESTRICTED' }, 'EXCEPTION_BINDING_MISMATCH'],
    ['destination profile', { ...base, destination: { profileId: 'exfil.invalid',
      sinkRef: sinks.exfil.ref } }, 'EXCEPTION_BINDING_MISMATCH'],
    ['destination ref', { ...base, destination: { profileId: 'allowed.invalid',
      sinkRef: sinks.exfil.ref } }, 'EXCEPTION_BINDING_MISMATCH'],
    ['operation', { ...base, operation: 'EXPORT' }, 'EXCEPTION_BINDING_MISMATCH'],
  ];
  for (const [label, binding, expected] of mutations) {
    const outcome = evaluatePolicyException(registry, ref.id, binding, ISO(T0 + 1000));
    assert.equal(outcome.state, 'DENIED', label);
    assert.equal(outcome.reason, expected, label);
    assert.equal(outcome.authority, 'NONE', label);
  }
  assert.equal(evaluatePolicyException(registry, 'exception-missing.invalid', base, ISO(T0)).reason,
    'EXCEPTION_UNKNOWN');
});

test('the exception capacity bound is enforced before any further registration', () => {
  const registry = createPolicyRegistry(scopeA, { maxExceptions: 2 });
  const configurationRef = configuration(baselineBundle());
  const hook = auditHook(scopeA);
  assert.equal(activatePolicyConfiguration(registry, configurationRef,
    configApproval(configurationRef, null), hook, ISO(T0)).state, 'APPLIED');
  for (const index of [0, 1]) {
    const ref = exception({ id: `exception-cap-${index}.invalid` });
    assert.equal(registerPolicyException(registry, ref, exceptionApproval(ref, configurationRef),
      hook, ISO(T0)).reason, 'EXCEPTION_REGISTERED', `exception ${index}`);
  }
  const overflow = exception({ id: 'exception-cap-overflow.invalid' });
  const outcome = registerPolicyException(registry, overflow,
    exceptionApproval(overflow, configurationRef), hook, ISO(T0));
  assert.equal(outcome.state, 'DENIED');
  assert.equal(outcome.reason, 'EXCEPTION_CAPACITY');
  assert.equal(registry.exceptions.length, 2, 'the cap holds and nothing is evicted');
  // The asymmetry is deliberate and is the safe direction: capacity gates *widening* authority, so a
  // full registry can still revoke. Refusing a revocation because the registry is full would strand
  // a live exception, which is the fail-open direction.
  const revocation = revokePolicyException(registry, 'exception-cap-0.invalid',
    exceptionApproval(exception({ id: 'exception-cap-0.invalid' }), configurationRef), hook,
    ISO(T0));
  assert.equal(revocation.state, 'APPLIED');
  assert.equal(revocation.reason, 'EXCEPTION_REVOCATION_RECORDED');
  assert.equal(registry.exceptions.length, 2, 'a revocation narrows and is never evicted');
});

test('revocation stops an exception immediately and never widens it', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const ref = exception();
  registerPolicyException(registry, ref,
    exceptionApproval(ref, configurationRef),
    auditHook(scopeA), ISO(T0));
  const binding = {
    scope: copy(scopeA), subject: copy(subjectA), purpose: 'support-review-a.invalid',
    semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
    destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
  };
  assert.equal(evaluatePolicyException(registry, ref.id, binding, ISO(T0)).state, 'APPLICABLE');
  const outcome = revokePolicyException(registry, ref.id,
    exceptionApproval(ref, configurationRef),
    auditHook(scopeA), ISO(T0 + 1000));
  assert.equal(outcome.state, 'APPLIED');
  assert.equal(outcome.reason, 'EXCEPTION_REVOCATION_RECORDED');
  const after = evaluatePolicyException(registry, ref.id, binding, ISO(T0 + 2000));
  assert.equal(after.state, 'DENIED');
  assert.equal(after.reason, 'EXCEPTION_REVOKED');
  // A replay of the same registration after revocation is refused; it cannot be resurrected.
  const replay = registerPolicyException(registry, ref,
    exceptionApproval(ref, configurationRef),
    auditHook(scopeA), ISO(T0 + 3000));
  assert.equal(replay.state, 'DENIED');
  assert.equal(evaluatePolicyException(registry, ref.id, binding, ISO(T0 + 4000)).reason,
    'EXCEPTION_REVOKED');
});

test('exception registration refuses an exception minted for another tenant or project', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  for (const [label, foreign] of [
    ['foreign tenant', scopeB],
    ['foreign project', { tenantId: scopeA.tenantId, projectId: 'project-b.invalid' }],
  ]) {
    const ref = exception({ id: `exception-${label.replace(/\s/g, '-')}.invalid`, scope: foreign });
    const outcome = registerPolicyException(registry, ref,
      exceptionApproval(ref, configurationRef, { scope: copy(foreign) }), auditHook(scopeA),
      ISO(T0));
    assert.equal(outcome.state, 'DENIED', label);
    assert.equal(outcome.reason, 'EXCEPTION_SCOPE_MISMATCH', label);
    assert.equal(registry.exceptions.length, 0, label);
  }
});

test('exception registration refuses unbound, cross-tenant, unlimited and unsafe exceptions', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const cases = [
    ['no approval binding', { binding: undefined }, 'INVALID_APPROVAL'],
    ['foreign binding subject', { binding: (ref) => exceptionBinding({ ...ref,
      subject: { principalId: 'principal-b.invalid' } }) }, 'APPROVAL_MISMATCH'],
    ['foreign binding destination', { binding: (ref) => exceptionBinding({ ...ref,
      destination: { profileId: 'exfil.invalid', sinkRef: sinks.exfil.ref } }) }, 'APPROVAL_MISMATCH'],
    ['foreign binding operation', { binding: (ref) => exceptionBinding({ ...ref,
      operation: 'EXPORT' }) }, 'APPROVAL_MISMATCH'],
    ['approval for another exception', { binding: (ref) => exceptionBinding({ ...ref,
      semanticType: 'CUSTOMER_OR_PARTNER' }) }, 'APPROVAL_MISMATCH'],
  ];
  for (const [label, options, expected] of cases) {
    const ref = exception();
    if (options.binding === undefined) {
      const approval = exceptionApproval(ref, configurationRef);
      delete approval.binding;
      const outcome = registerPolicyException(registry, ref, approval, auditHook(scopeA), ISO(T0));
      assert.equal(outcome.state, 'DENIED', label);
      assert.equal(outcome.reason, expected, label);
    } else {
      const forged = options.binding({ ...ref, subject: subjectA });
      const approval = exceptionApproval(ref, configurationRef, { binding: forged });
      const outcome = registerPolicyException(registry, ref, approval, auditHook(scopeA), ISO(T0));
      assert.equal(outcome.state, 'DENIED', label);
      assert.equal(outcome.reason, expected, label);
    }
  }
  // A "temporary" exception that never expires, or that outlives the hard ceiling, is refused.
  assert.throws(() => createPolicyException({
    version: 1, id: 'exception-forever.invalid', scope: copy(scopeA), subject: copy(subjectA),
    purpose: 'support-review-a.invalid', semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
    destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
    treatment: 'GENERALIZE', configRevision: 2, issuedAt: ISO(T0),
    expiresAt: ISO(T0 + GOVERNANCE_MAX_EXCEPTION_TTL_MS + 1),
  }), (error) => error instanceof PolicyGovernanceError && error.code === 'EXCEPTION_TTL_EXCEEDED');
  assert.throws(() => createPolicyException({
    version: 1, id: 'exception-inverted.invalid', scope: copy(scopeA), subject: copy(subjectA),
    purpose: 'support-review-a.invalid', semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
    destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
    treatment: 'GENERALIZE', configRevision: 2, issuedAt: ISO(T0 + 1000), expiresAt: ISO(T0),
  }), (error) => error instanceof PolicyGovernanceError && error.code === 'EXCEPTION_WINDOW_INVALID');
  // A secret or credential exception may only ever select an irreversible treatment.
  for (const semanticType of ['CREDENTIAL_OR_SECRET']) {
    assert.throws(() => createPolicyException({
      version: 1, id: 'exception-secret.invalid', scope: copy(scopeA), subject: copy(subjectA),
      purpose: 'support-review-a.invalid', semanticType, sensitivity: 'SECRET',
      destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
      treatment: 'KEEP', configRevision: 2, issuedAt: ISO(T0), expiresAt: ISO(T0 + 1000),
    }), (error) => error instanceof PolicyGovernanceError &&
      error.code === 'EXCEPTION_ABOVE_TREATMENT_CEILING');
  }
  // A global bypass is not expressible: tenant and project are both required, never optional.
  for (const scope of [{ tenantId: 'tenant-a.invalid' }, { projectId: 'project-a.invalid' }, {}]) {
    assert.throws(() => createPolicyException({
      version: 1, id: 'exception-global.invalid', scope, subject: copy(subjectA),
      purpose: 'support-review-a.invalid', semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
      destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
      treatment: 'GENERALIZE', configRevision: 2, issuedAt: ISO(T0), expiresAt: ISO(T0 + 1000),
    }), (error) => error instanceof PolicyGovernanceError);
  }
  assert.throws(() => createPolicyException({
    version: 1, id: 'exception-wildcard.invalid', scope: copy(scopeA), subject: copy(subjectA),
    purpose: '*', semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
    destination: { profileId: '*', sinkRef: '*' }, operation: 'SEND', treatment: 'KEEP',
    configRevision: 2, issuedAt: ISO(T0), expiresAt: ISO(T0 + 1000),
  }), (error) => error instanceof PolicyGovernanceError);
});

test('activating a newer revision supersedes a live exception automatically', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const ref = exception({ expiresAt: ISO(T0 + 3_600_000) });
  assert.equal(registerPolicyException(registry, ref, exceptionApproval(ref, configurationRef),
    auditHook(scopeA), ISO(T0)).state, 'APPLIED');
  const binding = {
    scope: copy(scopeA), subject: copy(subjectA), purpose: 'support-review-a.invalid',
    semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
    destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
  };
  assert.equal(evaluatePolicyException(registry, ref.id, binding, ISO(T0)).state, 'APPLICABLE');
  const next = configuration(baselineBundle(), { revision: 3 });
  assert.equal(activatePolicyConfiguration(registry, next,
    configApproval(next, configurationRef), auditHook(scopeA), ISO(T0 + 1000)).state, 'APPLIED');
  // The exception was bound to revision 2 and nobody approved it against revision 3.
  const superseded = evaluatePolicyException(registry, ref.id, binding, ISO(T0 + 2000));
  assert.equal(superseded.state, 'DENIED');
  assert.equal(superseded.reason, 'EXCEPTION_CONFIG_SUPERSEDED');
  // A revision-3 exception can still be registered and applied.
  const fresh = exception({ id: 'exception-r3.invalid', configRevision: 3 });
  assert.equal(registerPolicyException(registry, fresh, exceptionApproval(fresh, next),
    auditHook(scopeA), ISO(T0 + 3000)).state, 'APPLIED');
  assert.equal(evaluatePolicyException(registry, fresh.id, binding, ISO(T0 + 4000)).state,
    'APPLICABLE');
});

test('an exception never changes a policy decision and cannot lift a #4 hard floor', () => {
  // The #4 floor that matters most here: an unresolved classification stays denied for exactly the
  // tuple the exception covers, whatever the exception says.
  const unresolved = composeClassification({ detectorEvidence: [{
    version: 1, id: 'detector-governance.invalid', status: 'ABSTAIN',
    provenance: { inputRef: 'unit-a.invalid', producerId: 'detector-a.invalid',
      producerVersion: 'pack-1' },
  }] }, { interactionRef: 'interaction-governance.invalid',
    sourceRef: 'tool-source-governance.invalid', trust: 'TRUSTED' });
  assert.equal(unresolved.status, 'UNRESOLVED');
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const ref = exception({ expiresAt: ISO(T0 + 3_600_000) });
  registerPolicyException(registry, ref,
    exceptionApproval(ref, configurationRef),
    auditHook(scopeA), ISO(T0));
  const binding = {
    scope: copy(scopeA), subject: copy(subjectA), purpose: 'support-review-a.invalid',
    semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
    destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
  };
  assert.equal(evaluatePolicyException(registry, ref.id, binding, ISO(T0)).state, 'APPLICABLE');
  // The #4 seam is unchanged by any exception: it still holds, and the sink floors still stand.
  const held = independentDecision(baselineBundle(),
    probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND'));
  assert.equal(held.state, 'HELD');
  assert.equal(held.treatment, 'REQUIRE_REVIEW');
  assert.equal(independentDecision(baselineBundle(),
    probe('exfil.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND')).state, 'DENIED');
  assert.equal(independentDecision(baselineBundle(),
    probe('exfil.invalid', 'CREDENTIAL_OR_SECRET', 'SECRET', 'SEND')).state, 'DENIED');
  assert.equal(independentDecision(baselineBundle(),
    probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'EXPORT')).state, 'DENIED');
  // The same tuple, decided by the real seam with unresolved evidence: still denied.
  const destination = { ...sinks.allowed };
  const boundary = {
    interactionRef: 'interaction-governance.invalid', candidateRef: 'unit-governance.invalid',
    classificationDigest: digestClassification(unresolved),
    authenticated: { subject: { principalId: 'principal-a.invalid' }, context: copy({
      tenantId: scopeA.tenantId, projectId: scopeA.projectId, sessionId: 'session-governance.invalid',
      purpose: 'support-review-a.invalid' }) },
    observed: { source: { kind: 'tool.result', ref: 'tool-source-governance.invalid', trustZone: 'LOCAL',
      trust: 'TRUSTED' }, destination },
    policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(baselineBundle()) },
  };
  const decision = decidePolicy({ version: 1, interactionRef: boundary.interactionRef,
    candidateRef: boundary.candidateRef, subject: copy(boundary.authenticated.subject),
    context: copy(boundary.authenticated.context),
    source: { kind: 'tool.result', ref: 'tool-source-governance.invalid', trustZone: 'LOCAL' },
    destination: copy(destination), classification: unresolved, operation: 'SEND',
    policy: copy(KNOWN_POLICY_BUNDLE) }, boundary, baselineBundle());
  assert.equal(decision.state, 'DENIED');
  assert.equal(decision.reason, 'UNRESOLVED_CLASSIFICATION');
  // And the simulation reports the same floor rather than a release.
  const report = simulatePolicyConfiguration(registry, configuration(baselineBundle(), { revision: 3 }),
    [probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'held' })]);
  assert.equal(report.findings[0].baseline.state, 'HELD');
  assert.equal(report.newlyExposed.count, 0);
});

test('simulation reports newly exposed classes, sinks and operations before activation', () => {
  const { registry } = activeRegistry(baselineBundle());
  const candidate = configuration(relaxedBundle(), { revision: 3 });
  const probes = [
    probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'held-to-released' }),
    probe('exfil.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'denied-to-released' }),
    probe('allowed.invalid', 'CUSTOMER_OR_PARTNER', 'CONFIDENTIAL', 'SEND',
      { probeId: 'unchanged-hold' }),
    probe('exfil.invalid', 'CUSTOMER_OR_PARTNER', 'CONFIDENTIAL', 'SEND',
      { probeId: 'unchanged-deny' }),
  ];
  const report = simulatePolicyConfiguration(registry, candidate, probes);
  assert.equal(report.status, 'COMPARED');
  assert.equal(report.finding, 'SIMULATION_COMPARED');
  assert.equal(report.authority, 'NONE');
  assert.deepEqual(report.activation, { state: 'UNAVAILABLE', effect: 'IGNORED_NO_AUTHORITY' });
  assert.deepEqual(report.promotion.gates, GOVERNANCE_PROMOTION_GATES);
  assert.equal(report.probes.evaluated, 4);
  assert.equal(report.newlyExposed.count, 2);
  assert.deepEqual([...report.newlyExposed.classes], ['PERSON']);
  assert.deepEqual([...report.newlyExposed.sinks],
    ['https://allowed.example.invalid/v1', 'https://exfil.example.invalid/collect']);
  assert.deepEqual([...report.newlyExposed.profiles], ['allowed.invalid', 'exfil.invalid']);
  assert.deepEqual([...report.newlyExposed.operations], ['SEND']);
  const ids = report.findings.filter((item) => item.kind === 'NEW_EXPOSURE')
    .map((item) => item.probeId);
  assert.deepEqual(ids.sort(), ['denied-to-released', 'held-to-released']);
  for (const finding of report.findings) {
    assert.equal(finding.reason, ['NEW_EXPOSURE', 'SINK_REBOUND'].includes(finding.kind)
      ? 'NEWLY_EXPOSED_SINK_OR_CLASS' : finding.kind === 'NARROWED'
      ? 'NARROWED_DESTINATION_OR_TREATMENT' : finding.kind === 'UNAVAILABLE'
      ? 'PROFILE_UNAVAILABLE' : 'COMPARED');
    assert.equal(typeof finding.baselineSink === 'string' || finding.baselineSink === null, true);
    assert.equal(typeof finding.candidateSink === 'string' || finding.candidateSink === null, true);
    assert.equal(Object.hasOwn(finding, 'purpose'), false, 'a finding never carries a purpose');
  }
  const project = (decision) => ({ state: decision.state, treatment: decision.treatment,
    reason: decision.reason });
  for (const finding of report.findings) {
    if (finding.kind !== 'NEW_EXPOSURE') continue;
    // The reported transition is the transition the real #4 seam produced, not a guess.
    const p = probes.find((item) => item.probeId === finding.probeId);
    assert.deepEqual(finding.baseline, project(independentDecision(baselineBundle(), p)));
    assert.deepEqual(finding.candidate, project(independentDecision(relaxedBundle(), p)));
  }
  for (const finding of report.findings) {
    if (finding.kind !== 'UNCHANGED') continue;
    const p = probes.find((item) => item.probeId === finding.probeId);
    assert.deepEqual(finding.baseline, project(independentDecision(baselineBundle(), p)));
    assert.deepEqual(finding.candidate, project(independentDecision(relaxedBundle(), p)));
  }
});

test('a candidate that adds a destination reports the newly exposed sink by reference', () => {
  const { registry } = activeRegistry(baselineBundle());
  const candidate = configuration(addedSinkBundle(), { revision: 3 });
  const report = simulatePolicyConfiguration(registry, candidate, [
    probe('third.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'added-sink' }),
    probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'unchanged' }),
  ]);
  assert.equal(report.status, 'COMPARED');
  const added = report.findings.find((item) => item.probeId === 'added-sink');
  assert.equal(added.kind, 'NEW_EXPOSURE');
  // The report names the destination, and both sides are real #4 outcomes.
  assert.equal(added.candidateSink, 'https://third-party.example.invalid/collect');
  assert.equal(added.baselineSink, null);
  assert.equal(added.baseline.state, 'DENIED');
  assert.equal(added.baseline.reason, 'PROFILE_MISMATCH');
  assert.equal(added.candidate.state, 'SELECTED');
  assert.equal(added.candidate.treatment, 'KEEP');
  assert.equal(report.findings.find((item) => item.probeId === 'unchanged').kind, 'UNCHANGED');
  assert.equal(report.newlyExposed.count, 1);
  assert.deepEqual([...report.newlyExposed.sinks],
    ['https://third-party.example.invalid/collect']);
  assert.deepEqual([...report.newlyExposed.profiles], ['third.invalid']);
  assert.deepEqual([...report.newlyExposed.classes], ['PERSON']);
  assert.deepEqual([...report.newlyExposed.operations], ['SEND']);
  // And the transition is re-derivable from the real seam on both sides.
  const p = probe('third.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'x' });
  const underCandidate = independentDecision(addedSinkBundle(), p);
  assert.equal(underCandidate.state, 'SELECTED');
  assert.equal(underCandidate.treatment, 'KEEP');
  const underBaseline = independentDecision(baselineBundle(), p,
    { ...addedSinkBundle().profiles.find((item) => item.id === 'third.invalid').sink });
  assert.equal(underBaseline.state, 'DENIED');
  assert.equal(underBaseline.reason, 'PROFILE_MISMATCH');
});

test('a candidate that rebinds a profile sink reports the new destination even unchanged', () => {
  const { registry } = activeRegistry(baselineBundle());
  const candidate = configuration(reboundSinkBundle(), { revision: 3 });
  const report = simulatePolicyConfiguration(registry, candidate, [
    probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'moved-hold' }),
    probe('allowed.invalid', 'PERSON', 'PUBLIC', 'SEND', { probeId: 'moved-keep' }),
  ]);
  assert.equal(report.status, 'COMPARED');
  for (const finding of report.findings) {
    assert.equal(finding.kind, 'SINK_REBOUND', finding.probeId);
    assert.equal(finding.reason, 'NEWLY_EXPOSED_SINK_OR_CLASS');
    assert.equal(finding.baselineSink, 'https://allowed.example.invalid/v1');
    assert.equal(finding.candidateSink, 'https://exfil-moved.example.invalid/v1');
    // The decision level itself is unchanged on both sides: the destination is the exposure.
    assert.equal(finding.baseline.state, finding.candidate.state);
  }
  assert.equal(report.newlyExposed.count, 2);
  assert.deepEqual([...report.newlyExposed.sinks], ['https://exfil-moved.example.invalid/v1']);
  assert.deepEqual([...report.newlyExposed.profiles], ['allowed.invalid']);
});

test('a candidate that removes a destination narrows and is not reported as a new exposure', () => {
  const { registry } = activeRegistry(baselineBundle());
  const base = baselineBundle();
  const trimmed = { ...base, profiles: base.profiles.filter((item) => item.id !== 'exfil.invalid'),
    rules: base.rules.filter((item) => item.profileId !== 'exfil.invalid') };
  const candidate = configuration(trimmed, { revision: 3 });
  const report = simulatePolicyConfiguration(registry, candidate,
    [probe('exfil.invalid', 'PERSON', 'PUBLIC', 'SEND', { probeId: 'removed' })]);
  const finding = report.findings[0];
  assert.equal(finding.kind, 'NARROWED');
  assert.equal(finding.reason, 'NARROWED_DESTINATION_OR_TREATMENT');
  assert.equal(finding.baselineSink, 'https://exfil.example.invalid/collect');
  assert.equal(finding.candidateSink, null);
  assert.equal(finding.baseline.state, 'SELECTED');
  assert.equal(finding.candidate.state, 'DENIED');
  assert.equal(finding.candidate.reason, 'PROFILE_MISMATCH');
  assert.equal(report.newlyExposed.count, 0);
  assert.deepEqual([...report.newlyExposed.sinks], []);
});

test('a rebind to a strictly narrower destination is labelled narrowed, not a new exposure', () => {
  const { registry } = activeRegistry(baselineBundle());
  const base = baselineBundle();
  const localMoved = copy(profiles);
  localMoved[1].sink = { kind: 'local.tool', ref: 'https://local-moved.example.invalid/v1',
    trustZone: 'LOCAL', profileId: 'allowed.invalid' };
  const rules = base.rules.filter((item) => item.id.startsWith('allowed-')).map((item) =>
    ({ ...item, decision: item.decision === 'KEEP' ? 'KEEP' : item.decision }));
  const narrowed = { ...base, profiles: localMoved.map((item) => item.id === 'allowed.invalid'
    ? { ...item, exposure: 'LOCAL' } : item), rules };
  const candidate = configuration(narrowed, { revision: 3 });
  const report = simulatePolicyConfiguration(registry, candidate,
    [probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'moved-local' })]);
  const finding = report.findings[0];
  assert.equal(finding.kind, 'NARROWED');
  assert.equal(finding.baselineSink, 'https://allowed.example.invalid/v1');
  assert.equal(finding.candidateSink, 'https://local-moved.example.invalid/v1');
  assert.equal(report.newlyExposed.count, 0,
    'a narrowing rebind is not counted as a newly exposed sink');
  assert.deepEqual([...report.newlyExposed.sinks], []);
});

test('simulation output cannot activate a configuration or an exception', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const candidate = configuration(relaxedBundle(), { revision: 3 });
  const report = simulatePolicyConfiguration(registry, candidate,
    [probe('exfil.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'probe-1' })]);
  assert.throws(() => activatePolicyConfiguration(registry, report,
    configApproval(candidate, configurationRef), auditHook(scopeA), ISO(T0)),
  (error) => error instanceof PolicyGovernanceError && error.code === 'INVALID_CONFIGURATION');
  assert.throws(() => registerPolicyException(registry, report,
    exceptionApproval(candidate, configurationRef), auditHook(scopeA), ISO(T0)),
  (error) => error instanceof PolicyGovernanceError && error.code === 'INVALID_EXCEPTION');
  // Even a report-shaped object that merely looks like an approval is a fixed-code denial.
  const reportApproval = activatePolicyConfiguration(registry, candidate,
    { ...report, version: 1 }, auditHook(scopeA), ISO(T0));
  assert.equal(reportApproval.state, 'DENIED');
  assert.equal(reportApproval.reason, 'INVALID_APPROVAL');
  assert.equal(registry.config.revision, 2);
  assert.equal(registry.exceptions.length, 0);
});

test('a profile neither bundle declares is reported per probe, not as a release', () => {
  const { registry } = activeRegistry(baselineBundle());
  const candidate = configuration(relaxedBundle(), { revision: 3 });
  const report = simulatePolicyConfiguration(registry, candidate,
    [probe('absent.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'probe-1' })]);
  assert.equal(report.status, 'COMPARED');
  assert.equal(report.probes.unavailable, 1);
  assert.equal(report.probes.evaluated, 1);
  assert.equal(report.findings[0].kind, 'UNAVAILABLE');
  assert.equal(report.findings[0].reason, 'PROFILE_UNAVAILABLE');
  assert.equal(report.findings[0].baseline, null);
  assert.equal(report.findings[0].candidate, null);
  assert.equal(report.newlyExposed.count, 0);
});

test('simulation without an active baseline reports unavailable instead of comparing', () => {
  const registry = createPolicyRegistry(scopeA);
  const candidate = configuration(baselineBundle());
  const report = simulatePolicyConfiguration(registry, candidate,
    [probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'probe-1' })]);
  assert.equal(report.status, 'UNAVAILABLE');
  assert.equal(report.finding, 'SIMULATION_UNAVAILABLE');
  assert.equal(report.baseline.revision, null);
  assert.equal(report.probes.evaluated, 0);
});

test('hostile, oversize, duplicate and unknown-shaped governance input is refused with fixed codes', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const ref = exception();
  registerPolicyException(registry, ref,
    exceptionApproval(ref, configurationRef),
    auditHook(scopeA), ISO(T0));
  const binding = {
    scope: copy(scopeA), subject: copy(subjectA), purpose: 'support-review-a.invalid',
    semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
    destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
  };
  // Hostile getters are never invoked: an ownKeys/getOwnPropertyDescriptor trap that throws.
  const hostile = { ...binding };
  Object.defineProperty(hostile, 'purpose', { enumerable: true, get() { throw new Error('boom'); } });
  assert.equal(evaluatePolicyException(registry, ref.id, hostile, ISO(T0)).reason, 'INVALID_BINDING');
  const proxied = new Proxy({ ...binding }, {
    ownKeys() { throw new Error('boom'); },
  });
  assert.equal(evaluatePolicyException(registry, ref.id, proxied, ISO(T0)).reason, 'INVALID_BINDING');
  // Unknown properties are a refusal, never a default.
  assert.equal(evaluatePolicyException(registry, ref.id, { ...binding, extra: 'x' }, ISO(T0)).reason,
    'INVALID_BINDING');
  // A time-varying container cannot grow the inspected key set, and is enumerated exactly once.
  let enumerations = 0;
  const shifting = new Proxy({ ...binding }, {
    ownKeys() {
      enumerations += 1;
      return enumerations === 1
        ? Array.from({ length: 4000 }, (_, index) => `pad-${index}`)
        : ['scope', 'subject', 'purpose', 'semanticType', 'sensitivity', 'destination', 'operation'];
    },
  });
  assert.equal(evaluatePolicyException(registry, ref.id, shifting, ISO(T0)).reason, 'INVALID_BINDING');
  assert.equal(enumerations, 1, 'an untrusted container is enumerated exactly once');
  // Imaginary and malformed clocks are refused with a fixed code.
  for (const now of ['2026-02-31T00:00:00.000Z', '2026-13-01T00:00:00.000Z', 'yesterday', '', 1]) {
    assert.equal(evaluatePolicyException(registry, ref.id, binding, now).reason, 'INVALID_CLOCK');
  }
  // Over-cap probe sets are refused before any comparison work runs.
  const many = Array.from({ length: GOVERNANCE_LIMITS.probes + 1 }, (_, index) =>
    probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: `probe-${index}` }));
  assert.throws(() => simulatePolicyConfiguration(registry, configurationRef, many),
    (error) => error instanceof PolicyGovernanceError && error.code === 'INVALID_PROBES');
  // A duplicated probe is ambiguous and is refused rather than silently counted once.
  assert.throws(() => simulatePolicyConfiguration(registry, configurationRef,
    [probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'same' }),
      probe('allowed.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'same' })]),
  (error) => error instanceof PolicyGovernanceError && error.code === 'INVALID_PROBES');
  // A registry this module did not issue is refused, and an unavailable one changes nothing.
  assert.equal(evaluatePolicyException({ ...registry, exceptions: [] }, ref.id, binding, ISO(T0))
    .reason, 'INVALID_REGISTRY');
  const sealed = activeRegistry(baselineBundle()).registry;
  sealed.accepting = false;
  assert.equal(evaluatePolicyException(sealed, 'exception-a.invalid', binding, ISO(T0)).reason,
    'REGISTRY_UNAVAILABLE');
  const sealedConfiguration = configuration(relaxedBundle(), { revision: 9 });
  const outcome = activatePolicyConfiguration(sealed, sealedConfiguration,
    configApproval(sealedConfiguration, sealed.config), auditHook(scopeA), ISO(T0));
  assert.equal(outcome.state, 'DENIED');
  assert.equal(outcome.reason, 'REGISTRY_UNAVAILABLE');
  assert.equal(sealed.config.revision, 2);
});

test('planted protected values never reach governance outputs, refusals or audit records', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const plantedId = 'exception-planted-a.invalid';
  const ref = exception({ id: plantedId, purpose: PLANTED[1] });
  const hook = auditHook(scopeA, { correlationRef: `correlation-${PLANTED[2]}.invalid` });
  const registration = registerPolicyException(registry, ref,
    exceptionApproval(ref, configurationRef), hook, ISO(T0));
  assert.equal(registration.state, 'APPLIED');
  const binding = {
    scope: copy(scopeA), subject: copy(subjectA), purpose: PLANTED[1], semanticType: 'PERSON',
    sensitivity: 'CONFIDENTIAL',
    destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND',
  };
  const evaluation = evaluatePolicyException(registry, plantedId, binding, ISO(T0));
  assert.equal(evaluation.state, 'APPLICABLE');
  const denial = evaluatePolicyException(registry, plantedId,
    { ...binding, operation: 'EXPORT' }, ISO(T0));
  const report = simulatePolicyConfiguration(registry, configuration(relaxedBundle(), { revision: 3 }),
    [probe('exfil.invalid', 'PERSON', 'CONFIDENTIAL', 'SEND', { probeId: 'probe-1' })]);
  let refusal = '';
  assert.throws(() => createPolicyException({ version: 1, id: `bad-${PLANTED[0]}.invalid`,
    scope: copy(scopeA), subject: copy(subjectA), purpose: PLANTED_MAIL, semanticType: 'PERSON',
    sensitivity: 'CONFIDENTIAL', destination: { profileId: 'allowed.invalid', sinkRef: PLANTED_MAIL },
    operation: 'SEND', treatment: 'GENERALIZE', configRevision: 2, issuedAt: ISO(T0),
    expiresAt: ISO(T0 + 1000) }), (error) => {
      refusal = `${error.message} ${error.code}`;
      return true;
    });
  assert.equal(refusal.includes('policy governance'), true);
  assert.equal(registerPolicyException(registry, exception(),
    exceptionApproval(ref, configurationRef, { purpose: PLANTED_MAIL }), hook, ISO(T0)).reason,
  'INVALID_APPROVAL');
  const read = readAuditEvents(hook.ledger,
    { version: 1, scope: copy(scopeA), principalId: 'principal-a.invalid' }, {});
  assert.equal(read.entries.length, 1);
  // Every surface this module produces: outcomes, an evaluation, a denial, a simulation report, a
  // typed refusal and the whole #20 read result. The registry itself stores the caller's own
  // bounded administrative tokens, exactly as #20 stores verbatim identity tokens: minting a
  // privacy-safe purpose is the trusted integration's obligation, and this module never emits one.
  const surfaces = JSON.stringify([registration, evaluation, denial, report, refusal, read]) +
    digestPolicyException(ref) + digestPolicyConfiguration(configurationRef);
  for (const planted of [...PLANTED, PLANTED_MAIL]) {
    assert.equal(surfaces.includes(planted), false, `planted value leaked: ${planted}`);
  }
});

test('generated tenant vectors keep every governance surface isolated per tenant', () => {
  let checked = 0;
  for (let index = 0; index < 24; index += 1) {
    const tenant = `tenant-${index}.invalid`;
    const project = `project-${index}.invalid`;
    const scope = { tenantId: tenant, projectId: project };
    const subject = { principalId: `principal-${index}.invalid` };
    const { registry, configuration: configurationRef } = activeRegistry(baselineBundle(), scope);
    const ref = exception({ id: `exception-${index}.invalid`, scope, subject,
      configRevision: configurationRef.revision });
    const binding = exceptionBinding(ref);
    const request = { scope: copy(scope), subject: copy(subject), purpose: ref.purpose,
      semanticType: ref.semanticType, sensitivity: ref.sensitivity, destination: copy(ref.destination),
      operation: ref.operation };
    const registered = registerPolicyException(registry, ref,
      exceptionApproval(ref, configurationRef, { scope: copy(scope) }),
      auditHook(scope), ISO(T0));
    assert.equal(registered.state, 'APPLIED', tenant);
    assert.equal(evaluatePolicyException(registry, ref.id, request, ISO(T0)).state, 'APPLICABLE');
    for (let other = 0; other < 24; other += 1) {
      if (other === index) continue;
      const foreign = {
        ...copy(request),
        scope: { tenantId: `tenant-${other}.invalid`, projectId: `project-${other}.invalid` },
      };
      const outcome = evaluatePolicyException(registry, ref.id, foreign, ISO(T0));
      assert.equal(outcome.state, 'DENIED', `${tenant} vs tenant-${other}`);
      assert.equal(outcome.reason, 'EXCEPTION_SCOPE_MISMATCH');
      // No foreign configuration or exception is ever reachable through this registry either.
      const foreignRegistry = createPolicyRegistry(foreign.scope);
      assert.equal(foreignRegistry.exceptions.length, 0);
      assert.equal(evaluatePolicyException(foreignRegistry, ref.id, request, ISO(T0)).reason,
        'EXCEPTION_UNKNOWN');
      checked += 1;
    }
  }
  assert.equal(checked, 24 * 23);
});

test('generated decision-floor vectors keep every #4 floor through the governance substrate', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const ref = exception({ semanticType: 'CREDENTIAL_OR_SECRET', sensitivity: 'SECRET',
    treatment: 'REMOVE', expiresAt: ISO(T0 + 3_600_000) });
  assert.equal(registerPolicyException(registry, ref,
    exceptionApproval(ref, configurationRef),
    auditHook(scopeA), ISO(T0)).state, 'APPLIED');
  assert.equal(evaluatePolicyException(registry, ref.id, { scope: copy(scopeA),
    subject: copy(subjectA), purpose: 'support-review-a.invalid',
    semanticType: 'CREDENTIAL_OR_SECRET', sensitivity: 'SECRET',
    destination: { profileId: 'allowed.invalid', sinkRef: sinks.allowed.ref }, operation: 'SEND' },
  ISO(T0)).state, 'APPLICABLE');
  let checked = 0;
  for (const semanticType of SEMANTIC_CLASSES) {
    const sensitivity = semanticType === 'CREDENTIAL_OR_SECRET' ? 'SECRET' : 'CONFIDENTIAL';
    for (const operation of ['SEND', 'USE', 'DISPLAY', 'EXPORT']) {
      for (const profileId of ['local.invalid', 'allowed.invalid', 'exfil.invalid']) {
        const before = independentDecision(baselineBundle(),
          probe(profileId, semanticType, sensitivity, operation));
        const after = independentDecision(baselineBundle(),
          probe(profileId, semanticType, sensitivity, operation));
        assert.deepEqual(after, before, `${semanticType}/${profileId}/${operation}`);
        // Nothing here may clear a decision, and the exfil sink never permits release.
        if (before.state !== 'DENIED') assert.notEqual(before.treatment, 'BLOCK');
        if (profileId === 'exfil.invalid' && sensitivity !== 'PUBLIC') {
          assert.equal(before.state, 'DENIED', `${semanticType}/${operation}`);
        }
        checked += 1;
      }
    }
  }
  assert.equal(checked, SEMANTIC_CLASSES.length * 4 * 3);
});

test('generated floor vectors are measured with a live exception in the registry', () => {
  const { registry, configuration: configurationRef } = activeRegistry(baselineBundle());
  const ref = exception({ expiresAt: ISO(T0 + 3_600_000) });
  assert.equal(registerPolicyException(registry, ref, exceptionApproval(ref, configurationRef),
    auditHook(scopeA), ISO(T0)).state, 'APPLIED');
  const covered = {
    scope: copy(scopeA), subject: copy(subjectA), purpose: ref.purpose,
    semanticType: ref.semanticType, sensitivity: ref.sensitivity,
    destination: copy(ref.destination), operation: ref.operation,
  };
  let applicable = 0;
  let checked = 0;
  for (const semanticType of SEMANTIC_CLASSES) {
    const sensitivity = semanticType === 'CREDENTIAL_OR_SECRET' ? 'SECRET' : 'CONFIDENTIAL';
    for (const operation of ['SEND', 'USE', 'DISPLAY', 'EXPORT']) {
      for (const profileId of ['local.invalid', 'allowed.invalid', 'exfil.invalid']) {
        const p = probe(profileId, semanticType, sensitivity, operation);
        const decision = independentDecision(baselineBundle(), p);
        // The floor is measured on the same registry that holds a live exception: the exception is
        // APPLICABLE only for its own tuple and never changes this decision.
        const evaluated = evaluatePolicyException(registry, ref.id, {
          ...covered, semanticType, sensitivity, operation,
          destination: { profileId, sinkRef: sinkRefFor(profileId) },
        }, ISO(T0 + 1000));
        const matchesTuple = semanticType === ref.semanticType &&
          sensitivity === ref.sensitivity && operation === ref.operation &&
          profileId === ref.destination.profileId;
        assert.equal(evaluated.state, matchesTuple ? 'APPLICABLE' : 'DENIED',
          `${semanticType}/${profileId}/${operation}`);
        if (matchesTuple) applicable += 1;
        else assert.equal(evaluated.reason, 'EXCEPTION_BINDING_MISMATCH');
        if (decision.state !== 'DENIED') assert.notEqual(decision.treatment, 'BLOCK');
        if (profileId === 'exfil.invalid' && sensitivity !== 'PUBLIC') {
          assert.equal(decision.state, 'DENIED', `${semanticType}/${operation}`);
        }
        checked += 1;
      }
    }
  }
  assert.equal(checked, SEMANTIC_CLASSES.length * 4 * 3);
  assert.equal(applicable, 1, 'exactly one generated vector is the exception\'s own tuple');
});

test('governance work stays bounded at the declared caps', () => {
  const started = Date.now();
  const { registry } = activeRegistry(baselineBundle());
  const candidate = configuration(relaxedBundle(), { revision: 3 });
  const probes = Array.from({ length: GOVERNANCE_LIMITS.probes }, (_, index) => {
    const semanticType = SEMANTIC_CLASSES[index % SEMANTIC_CLASSES.length];
    return probe(['local.invalid', 'allowed.invalid', 'exfil.invalid'][index % 3], semanticType,
      semanticType === 'CREDENTIAL_OR_SECRET' ? 'SECRET' : 'CONFIDENTIAL', 'SEND',
      { probeId: `probe-${index}` });
  });
  const report = simulatePolicyConfiguration(registry, candidate, probes);
  assert.equal(report.probes.evaluated, GOVERNANCE_LIMITS.probes);
  assert.ok(report.findings.length <= GOVERNANCE_LIMITS.findings);
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 15_000, `bounded simulation took ${elapsed} ms`);
});