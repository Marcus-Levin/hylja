// #238 behavioral tests for the one bound audited revocation owner.
//
// What is real here: `createBoundMappingRevocation`, the shipped registry and its compare-and-set,
// the shipped lifecycle reducer behind it, the shipped audit append and its gate, the shipped bound
// `USE` executor, the shipped purpose-bound authorization seam, the shipped Policy Engine and the
// shipped AEAD sealer/opener. What is a fixture: the administrator identity, the workload identity,
// the scope, the administrative decision, the policy bundle and its pinned digest, the audit keys,
// the clock and the private synchronous resource. Nothing authenticates anybody here, and nothing
// here proves the host's decision came from a real authorization service.
//
// Every value is invented, obviously synthetic and non-routable: `.invalid` names and fixed byte
// fills as DEK, HMAC and audit key material. The backend is provisioned out of band with the handle
// its own resource owns, so no identifier ever leaves it as a value: the executor sees one primitive
// boolean and this file asserts codes, counters, registry state and audit evidence.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createBoundMappingRevocation, MAPPING_REVOCATION_CODES }
  from '../dist/mapping-revocation.js';
import { createBoundMappingUse } from '../dist/mapping-use.js';
import { createMappingMetadataRegistry } from '../dist/mapping-metadata-registry.js';
import { digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE } from '../dist/policy.js';
import { composeClassification } from '../dist/classification.js';
import { createInMemoryAuditLedger, verifyAuditStream, AUDIT_SCHEMA_VERSION }
  from '../dist/audit-ledger.js';
import { deriveScopedEntityReference } from '../dist/scoped-entity-reference.js';
import { sealMappingPayload, MAPPING_AEAD_LIMITS } from '../dist/mapping-aead.js';

/* ---------- Fixed synthetic literals ---------- */

const ORIGINAL = 'synthetic-revocation-original.invalid';
const ORIGINAL_BYTES = new TextEncoder().encode(ORIGINAL);
const KEY_VERSION = '1.0';
const CLASS = 'PERSON';
const SENSITIVITY = 'CONFIDENTIAL';
const TRUST = 'TRUSTED';
const T0 = 1_700_000_000_000;
const TTL_MS = 3_600_000;
const CAPACITY = 8;
const NOW = T0 + 60_000;
const ADMIN_PURPOSE = 'mapping-administration-fixture.invalid';
const USE_PURPOSE = 'bound-use-fixture.invalid';
const ENTITY_ID = 'entity-revocation-fixture';
const INTERACTION_REF = 'interaction-revocation-fixture.invalid';
const CANDIDATE_REF = 'candidate-revocation-fixture.invalid';
const SOURCE = Object.freeze({ kind: 'tool.result', ref: 'source-revocation-fixture.invalid',
  trustZone: 'LOCAL' });
const DESTINATION = Object.freeze({ kind: 'tool.result', ref: 'sink-revocation-fixture.invalid',
  trustZone: 'LOCAL', profileId: 'profile-revocation-fixture.invalid' });
const SCOPE = Object.freeze({ tenantId: 'tenant-revocation-alpha.invalid',
  projectId: 'project-revocation-alpha.invalid', sessionId: 'session-revocation-alpha.invalid' });
const FOREIGN_SCOPE = Object.freeze({ tenantId: 'tenant-revocation-beta.invalid',
  projectId: 'project-revocation-beta.invalid', sessionId: 'session-revocation-beta.invalid' });

/** The authenticated `USE` workload: a different principal from the administrator. */
const WORKLOAD = Object.freeze({ principalId: 'principal-revocation-workload.invalid',
  workloadId: 'workload-revocation-workload.invalid' });
/** The authenticated administrator whose decision authorizes revocation, and nothing else. */
const ADMIN = Object.freeze({ principalId: 'principal-revocation-admin.invalid',
  workloadId: 'workload-revocation-admin.invalid' });

function keyBytes(fill) { return new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(fill); }
const COMPONENTS = Object.freeze([{ id: 'CLASSIFICATION_POLICY', version: '1' },
  { id: 'AUTHORIZATION_POLICY', version: '1' }]);

/* ---------- One ephemeral mapping, real registry, real AEAD ---------- */

function buildScenario({ scope = SCOPE } = {}) {
  const derived = deriveScopedEntityReference({ scope: 'SESSION', tenantId: scope.tenantId,
    projectId: scope.projectId, sessionId: scope.sessionId, entityId: ENTITY_ID,
    semanticType: CLASS, keyVersion: KEY_VERSION, key: keyBytes(0x44) });
  assert.equal(derived.state, 'DERIVED');
  const registry = createMappingMetadataRegistry({ capacity: CAPACITY });
  const mappingRef = derived.token;
  const expiresAt = T0 + TTL_MS;
  const inserted = registry.insert({ version: 1, mappingRef, scope: { ...scope }, expiresAt },
    { now: T0 });
  assert.equal(inserted.state, 'INSERTED');
  const activated = registry.transition({ version: 1, mappingRef, scope: { ...scope },
    expectedRevision: 1, action: 'ACTIVATE' }, { now: T0 + 1_500 });
  assert.equal(activated.state, 'CHANGED');
  assert.equal(activated.metadata.revision, 2);
  const sealed = sealMappingPayload({ scope: aadScope(scope, 2), plaintext: ORIGINAL_BYTES,
    key: keyBytes(0x11) });
  assert.equal(sealed.status, 'SEALED');
  return { registry, mappingRef, scope: Object.freeze({ ...scope }), expiresAt,
    envelope: sealed.envelope, revision: 2 };
}
function aadScope(scope, revision) {
  return { tenantId: scope.tenantId, projectId: scope.projectId, entityId: ENTITY_ID,
    classification: CLASS, mappingRevision: String(revision), keyVersion: KEY_VERSION };
}

const EVIDENCE = composeClassification({ detectorEvidence: [{
  version: 1, id: 'detector-revocation-fixture.invalid', status: 'FOUND',
  provenance: { inputRef: 'field-revocation-fixture.invalid',
    producerId: 'detector-revocation-fixture.invalid', producerVersion: 'pack-1' },
  claim: { semanticType: CLASS, sensitivity: SENSITIVITY } },
] }, { interactionRef: INTERACTION_REF, sourceRef: SOURCE.ref, trust: TRUST });

function policyBundle() {
  return { ...KNOWN_POLICY_BUNDLE,
    profiles: [{ id: DESTINATION.profileId, sink: { ...DESTINATION }, exposure: 'LOCAL',
      permittedTreatments: ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE'],
      maxCleartextSensitivity: 'RESTRICTED' }],
    rules: [{ id: 'rule-revocation-keep.invalid', profileId: DESTINATION.profileId,
      semanticType: CLASS, sensitivities: [SENSITIVITY], sourceTrust: [TRUST], operations: ['USE'],
      decision: 'KEEP' }] };
}

/* ---------- The private synchronous `USE` resource ---------- */

/** Returns one primitive boolean and nothing else, over a handle provisioned out of band. */
function createBackend() {
  const provisioned = new TextEncoder().encode(ORIGINAL);
  const state = { calls: 0 };
  return { state, lookup(identifier) {
    state.calls += 1;
    if (identifier.byteLength !== provisioned.byteLength) return false;
    for (let index = 0; index < provisioned.byteLength; index += 1) {
      if (identifier[index] !== provisioned[index]) return false;
    }
    return true;
  } };
}

/**
 * A delegating view of the real registry, so a test can count or fault the seam calls this owner
 * actually made. The owner binds the view's own `current` and `transition` at construction, exactly
 * as it binds the real registry object's, so the view is the object it must call through.
 */
function countingRegistry(registry, { afterCurrent, wrapTransition } = {}) {
  const counters = { current: 0, transition: 0 };
  const view = { version: 1,
    current: (...args) => {
      counters.current += 1;
      const answer = registry.current(...args);
      if (typeof afterCurrent === 'function') afterCurrent(counters.current, answer);
      return answer;
    },
    transition: (...args) => {
      counters.transition += 1;
      return typeof wrapTransition === 'function' ? wrapTransition(...args) : registry.transition(...args);
    } };
  return { view, counters };
}

/** The racing mutation a queued callback performs: the same transition this owner just applied. */
function competitor(built) {
  return built.scenario.registry.transition({ version: 1, mappingRef: built.scenario.mappingRef,
    scope: { ...built.scenario.scope }, expectedRevision: built.scenario.revision, action: 'REVOKE' },
  { now: NOW });
}

/* ---------- The two trusted hosts ---------- */

/** The `USE` host over the real registry, audit substrate, policy and AEAD material. */
function createUseHost({ scenario, backend, ledger, auditContext, record }) {
  const counters = { authority: 0, material: 0 };
  const bundle = policyBundle();
  const state = { now: NOW };
  return { counters, state, host: {
    version: 1,
    mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope },
    entityId: ENTITY_ID,
    registry: scenario.registry,
    audit: { ledger, context: auditContext, components: COMPONENTS },
    policy: { version: 1, interactionRef: INTERACTION_REF, candidateRef: CANDIDATE_REF,
      source: { ...SOURCE, trust: TRUST }, classification: EVIDENCE,
      classificationDigest: digestClassification(EVIDENCE),
      policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(bundle) }, bundle },
    backend,
    authority: () => {
      counters.authority += 1;
      return { version: 1, subject: { ...WORKLOAD },
        context: { ...scenario.scope, purpose: USE_PURPOSE }, destination: { ...DESTINATION },
        grant: { version: 1, mappingRef: scenario.mappingRef, revision: record.revision,
          principal: { ...WORKLOAD }, context: { ...scenario.scope, purpose: USE_PURPOSE },
          destination: { ...DESTINATION }, operation: 'USE', expiresAt: scenario.expiresAt - 1 },
        keyVersion: KEY_VERSION, now: state.now };
    },
    material: () => {
      counters.material += 1;
      return { version: 1, envelope: { ...scenario.envelope }, key: keyBytes(0x11),
        mappingRevision: String(record.revision), keyVersion: KEY_VERSION };
    },
  } };
}

/**
 * The revocation host. `decision` is the closed administrative answer the owner must validate, and
 * `hooks.onAuthority(n)` runs at exactly the observation points so a test can change the world
 * between two of them. `state` holds what the next observation reports.
 */
function createRevocationHost({ scenario, ledger, auditContext, overrides = {}, hooks = {} }) {
  const bundle = policyBundle();
  const state = {
    subject: { ...ADMIN }, scope: { ...scenario.scope }, purpose: ADMIN_PURPOSE,
    decision: 'ALLOW', role: 'MAPPING_ADMIN', mappingRef: scenario.mappingRef,
    revision: scenario.revision, expiresAt: scenario.expiresAt - 1, now: NOW, ...overrides,
  };
  const counters = { authority: 0 };
  const fixture = { state, counters, scenario, ledger, auditContext };
  const host = {
    version: 1,
    mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope },
    adminPurpose: ADMIN_PURPOSE,
    interactionRef: INTERACTION_REF,
    registry: scenario.registry,
    audit: { ledger, context: auditContext, components: COMPONENTS },
    policy: { id: KNOWN_POLICY_BUNDLE.id, version: KNOWN_POLICY_BUNDLE.version,
      digest: digestPolicyBundle(bundle) },
    authority: () => {
      counters.authority += 1;
      if (typeof hooks.onAuthority === 'function') hooks.onAuthority(counters.authority, fixture);
      // `authorityScope` overrides the decision's own scope only; the context it carries stays at
      // the bound scope. That separation is what makes a foreign or absent decision scope
      // observable at all: a host cannot hide a foreign scope behind a matching context.
      const answer = { version: 1, subject: { ...state.subject },
        context: { ...state.scope, purpose: state.purpose }, decision: state.decision,
        role: state.role, mappingRef: state.mappingRef,
        scope: Object.hasOwn(state, 'authorityScope') ? state.authorityScope : { ...state.scope },
        revision: state.revision, expiresAt: state.expiresAt, now: state.now };
      return Object.hasOwn(state, 'extra') ? { ...answer, ...state.extra } : answer;
    },
  };
  fixture.host = host;
  return fixture;
}

function adminContext(scope = SCOPE, fill = 0x22) {
  return { version: AUDIT_SCHEMA_VERSION,
    scope: { tenantId: scope.tenantId, projectId: scope.projectId },
    actor: { principalId: ADMIN.principalId, workloadId: ADMIN.workloadId },
    integrationId: 'integration-revocation-fixture.invalid',
    actorBinding: 'AUTHENTICATED_UPSTREAM', pseudonymKey: keyBytes(fill), chainKey: keyBytes(fill + 1) };
}
function workloadContext(scope = SCOPE) {
  const context = adminContext(scope);
  return { ...context, actor: { principalId: WORKLOAD.principalId, workloadId: WORKLOAD.workloadId } };
}

/** The accepted path, with the real `USE` executed around it, so the ordering is observable. */
function fullScenario(options = {}) {
  const scope = options.scope ?? SCOPE;
  const scenario = buildScenario({ scope });
  const ledger = options.ledger ?? createInMemoryAuditLedger(
    { tenantId: scope.tenantId, projectId: scope.projectId },
    options.ledgerOptions);
  const record = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
    scope: { ...scope } }, { now: NOW });
  assert.equal(record.state, 'FOUND');
  const backend = createBackend();
  const useHost = createUseHost({ scenario, backend, ledger, auditContext: workloadContext(scope),
    record: record.metadata });
  const revocation = createRevocationHost({ scenario, ledger, auditContext: adminContext(scope),
    overrides: options.overrides, hooks: options.hooks });
  return { scope, scenario, ledger, backend, use: useHost, revocation,
    execute: createBoundMappingUse(useHost.host), owner: undefined,
    materialCalls: () => useHost.counters.material };
}

/** Only the registry's own read says whether a revocation actually landed. */
function lifecycleOf(scenario, now = NOW) {
  const observed = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope } }, { now });
  return observed.state === 'FOUND'
    ? { state: observed.metadata.state, revision: observed.metadata.revision }
    : { state: 'ABSENT', revision: undefined, finding: observed.reason };
}
function fixedShape(result) {
  assert.equal(result.version, 1);
  assert.equal(MAPPING_REVOCATION_CODES.includes(result.code), true);
  assert.deepEqual(Object.keys(result).sort(), ['code', 'version']);
}
function revokeEvidence(ledger) {
  return ledger.entries.map((entry) => entry.event).filter((event) => event.kind === 'MAPPING_LIFECYCLE');
}

/* ---------- 1. Accepted path: a live mapping is really used, then really revoked ---------- */

test('an ACTIVE mapping completes a bound use, then an authorized revocation records real evidence',
  async () => {
    const built = fullScenario();
    built.owner = createBoundMappingRevocation(built.revocation.host);
    assert.equal(lifecycleOf(built.scenario).state, 'ACTIVE');

    // The positive is genuinely dependent: the real USE executor opens the real AEAD envelope and
    // the backend answers from its own out-of-band provisioned handle.
    const used = await built.execute.use();
    assert.equal(used.code, 'USED');
    assert.equal(built.backend.state.calls, 1);
    assert.equal(built.materialCalls(), 1);

    const revoked = await built.owner.revoke();
    fixedShape(revoked);
    assert.equal(revoked.code, 'REVOKED');

    // The registry's own record is the only claim of a mutation, and it is a terminal tombstone.
    assert.deepEqual(lifecycleOf(built.scenario), { state: 'ABSENT', revision: undefined,
      finding: 'NOT_LIVE' });
    assert.equal(built.scenario.registry.size, 1);

    // The lifecycle evidence is real, ordered, and pseudonymized: two `REVOKE` events, intent first.
    const evidence = revokeEvidence(built.ledger);
    assert.deepEqual(evidence.map((event) => [event.operation, event.outcome, event.reason]), [
      ['REVOKE', 'ALLOWED', 'RESOLUTION_AUTHORIZED'],
      ['REVOKE', 'APPLIED', 'ADMIN_APPLIED'],
    ]);
    for (const event of evidence) {
      assert.equal(event.actor.principalId, ADMIN.principalId);
      assert.equal(event.actor.workloadId, ADMIN.workloadId);
      assert.equal(event.entityRef.startsWith('ent_'), true);
      assert.equal(event.correlationRef.startsWith('cor_'), true);
    }
    // No raw reference or plaintext ever reaches the recorded bytes.
    const serialized = JSON.stringify(built.ledger.entries);
    assert.equal(serialized.includes(built.scenario.mappingRef), false);
    assert.equal(serialized.includes(ORIGINAL), false);
    // The chain is internally consistent; it is anchored nowhere, which the verification says.
    const verified = verifyAuditStream(built.ledger, built.revocation.auditContext, []);
    assert.equal(verified.status, 'UNANCHORED');
    assert.equal(verified.finding, 'NO_ANCHOR');
  });

test('the same USE withholds before any material or backend access after a real revocation',
  async () => {
    const built = fullScenario();
    const owner = createBoundMappingRevocation(built.revocation.host);
    assert.equal((await owner.revoke()).code, 'REVOKED');

    const before = { material: built.materialCalls(), calls: built.backend.state.calls };
    assert.deepEqual(before, { material: 0, calls: 0 });

    const withheld = await built.execute.use();
    assert.equal(withheld.code, 'WITHHELD');
    // Zero material load and zero backend calls: the refusal came from the registry's own record
    // before the sealed record was loaded, which is the strongest observable form of "before".
    assert.equal(built.materialCalls(), before.material);
    assert.equal(built.backend.state.calls, before.calls);
    assert.equal(lifecycleOf(built.scenario).state, 'ABSENT');
  });

/* ---------- 2. Retry, idempotency and concurrency follow the registry ---------- */

test('a retry after a real revocation is refused with zero mutation and never revives the record',
  async () => {
    const built = fullScenario();
    const owner = createBoundMappingRevocation(built.revocation.host);
    assert.equal((await owner.revoke()).code, 'REVOKED');
    const evidence = revokeEvidence(built.ledger).length;

    const retry = await owner.revoke();
    fixedShape(retry);
    assert.equal(retry.code, 'WITHHELD');
    // The tombstone is unchanged and no further evidence is written: there is no rollback path here.
    assert.deepEqual(lifecycleOf(built.scenario), { state: 'ABSENT', revision: undefined,
      finding: 'NOT_LIVE' });
    assert.equal(revokeEvidence(built.ledger).length, evidence);
  });

test('two owners pinned at one revision: exactly one applies, the loser cannot mutate', async () => {
  const built = fullScenario();
  const first = createBoundMappingRevocation(built.revocation.host);
  const secondHost = createRevocationHost({ scenario: built.scenario, ledger: built.ledger,
    auditContext: built.revocation.auditContext });
  const second = createBoundMappingRevocation(secondHost.host);

  const results = await Promise.all([first.revoke(), second.revoke()]);
  const codes = results.map((result) => result.code).sort();
  assert.deepEqual(codes, ['REVOKED', 'WITHHELD']);
  assert.equal(built.scenario.registry.size, 1);
  assert.deepEqual(lifecycleOf(built.scenario), { state: 'ABSENT', revision: undefined,
    finding: 'NOT_LIVE' });
});

test('a decision pinned at a stale revision refuses with zero mutation', async () => {
  const built = fullScenario();
  const owner = createBoundMappingRevocation(built.revocation.host);
  built.revocation.state.revision = built.scenario.revision - 1;

  assert.equal((await owner.revoke()).code, 'WITHHELD');
  assert.equal(lifecycleOf(built.scenario).state, 'ACTIVE');
  assert.equal(built.scenario.registry.current({ version: 1, mappingRef: built.scenario.mappingRef,
    scope: { ...built.scenario.scope } }, { now: NOW }).metadata.revision, built.scenario.revision);
  assert.equal(revokeEvidence(built.ledger).length, 0);
});

test('a revision that moved between two observations refuses with zero mutation', async () => {
  const built = fullScenario({ hooks: { onAuthority: (n) => {
    // The registry moves under the pinned decision between the first observation and a recheck.
    if (n === 2) {
      built.scenario.registry.transition({ version: 1, mappingRef: built.scenario.mappingRef,
        scope: { ...built.scenario.scope }, expectedRevision: built.scenario.revision,
        action: 'REVOKE' }, { now: NOW });
    }
  } } });
  const owner = createBoundMappingRevocation(built.revocation.host);

  assert.equal((await owner.revoke()).code, 'WITHHELD');
  assert.equal(lifecycleOf(built.scenario).state, 'ABSENT');
  // The intent evidence was recorded before the mutation and the applied result never was.
  const evidence = revokeEvidence(built.ledger);
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].reason, 'RESOLUTION_AUTHORIZED');
});

/* ---------- 3. Administrative authorization, and never a USE grant ---------- */

test('a decision naming another scope or another reference refuses with zero mutation', async () => {
  for (const override of [{ scope: FOREIGN_SCOPE }, { mappingRef: 'other-reference.invalid' }]) {
    const built = fullScenario();
    const owner = createBoundMappingRevocation(built.revocation.host);
    Object.assign(built.revocation.state, override);
    assert.equal((await owner.revoke()).code, 'WITHHELD');
    assert.equal(lifecycleOf(built.scenario).state, 'ACTIVE');
    assert.equal(revokeEvidence(built.ledger).length, 0);
  }
});

test('no administrative decision, a denial, an expired decision or a foreign role refuses', async () => {
  for (const override of [{ decision: 'DENY' }, { expiresAt: NOW }, { role: 'USE_WORKLOAD' },
    { purpose: USE_PURPOSE }]) {
    const built = fullScenario();
    const owner = createBoundMappingRevocation(built.revocation.host);
    Object.assign(built.revocation.state, override);
    assert.equal((await owner.revoke()).code, 'WITHHELD');
    assert.equal(lifecycleOf(built.scenario).state, 'ACTIVE');
    assert.equal(revokeEvidence(built.ledger).length, 0);
  }
});

test('a real USE grant carried alongside an administrative decision is refused with zero mutation',
  async () => {
    const built = fullScenario();
    // The accepted authority shape is closed: a grant has no key to sit in, so a decision that
    // brings one is not a decision this owner may act on at all.
    built.revocation.state.extra = { grant: { version: 1, mappingRef: built.scenario.mappingRef,
      revision: built.scenario.revision, principal: { ...WORKLOAD },
      context: { ...built.scenario.scope, purpose: USE_PURPOSE }, destination: { ...DESTINATION },
      operation: 'USE', expiresAt: built.scenario.expiresAt - 1 } };
    const owner = createBoundMappingRevocation(built.revocation.host);

    assert.equal((await owner.revoke()).code, 'WITHHELD');
    assert.equal(lifecycleOf(built.scenario).state, 'ACTIVE');
    // The grant alone authorizes nothing here: with the same grant the bound `USE` still succeeds.
    assert.equal((await built.execute.use()).code, 'USED');
    assert.equal(revokeEvidence(built.ledger).length, 0);
  });

test('an administrator whose audit actor is not recorded authorizes nothing', async () => {
  const built = fullScenario();
  // The ledger attributes from its trusted context, so a decision whose subject is not the
  // recorded actor is refused before any mutation or evidence.
  const mismatched = { ...built.revocation.auditContext, actor: { ...WORKLOAD } };
  const host = { ...built.revocation.host, audit: { ...built.revocation.host.audit,
    context: mismatched } };
  const owner = createBoundMappingRevocation(host);

  assert.equal((await owner.revoke()).code, 'WITHHELD');
  assert.equal(lifecycleOf(built.scenario).state, 'ACTIVE');
  assert.equal(revokeEvidence(built.ledger).length, 0);
});

test('an audit ledger or context outside the bound scope authorizes nothing', async () => {
  const built = fullScenario();
  const foreignLedger = createInMemoryAuditLedger(
    { tenantId: FOREIGN_SCOPE.tenantId, projectId: FOREIGN_SCOPE.projectId });
  const { view, counters } = countingRegistry(built.scenario.registry);
  // Genuine A authority, the real A registry and a real B stream with a matching B context: only the
  // audit destination is foreign, and every one of those values is honest on its own terms.
  const owner = createBoundMappingRevocation({ ...built.revocation.host, registry: view,
    audit: { ledger: foreignLedger, context: adminContext(FOREIGN_SCOPE), components: COMPONENTS } });

  assert.equal((await owner.revoke()).code, 'WITHHELD');
  // The refusal costs nothing: no host callback, no registry seam call, and no event in either
  // stream - A's revocation is never written into B's ledger, and B's ledger stays empty.
  assert.equal(built.revocation.counters.authority, 0);
  assert.deepEqual(counters, { current: 0, transition: 0 });
  assert.deepEqual(lifecycleOf(built.scenario), { state: 'ACTIVE', revision: built.scenario.revision });
  assert.equal(foreignLedger.entries.length, 0);
  assert.equal(revokeEvidence(built.ledger).length, 0);

  // The positive control over the same authority, the same registry and the matching A stream.
  assert.equal((await createBoundMappingRevocation(built.revocation.host).revoke()).code, 'REVOKED');
  assert.deepEqual(lifecycleOf(built.scenario), { state: 'ABSENT', revision: undefined,
    finding: 'NOT_LIVE' });
});

test('a trusted context whose scope moves off the bound scope refuses before the mutation', async () => {
  const built = fullScenario({ hooks: { onAuthority: (n, fixture) => {
    // The trusted context is host-owned and mutable, and the scope the append is handed is an owned
    // snapshot taken at capture, so this move cannot rewrite the intent already recorded. The guard
    // re-reads the live context inside the final continuation and refuses before anything it would
    // misattribute is written.
    if (n === 2) fixture.auditContext.scope.tenantId = 'tenant-revocation-gamma.invalid';
  } } });
  const owner = createBoundMappingRevocation(built.revocation.host);

  assert.equal((await owner.revoke()).code, 'WITHHELD');
  assert.deepEqual(lifecycleOf(built.scenario), { state: 'ACTIVE', revision: built.scenario.revision });
  const evidence = revokeEvidence(built.ledger);
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].reason, 'RESOLUTION_AUTHORIZED');
  // The intent that was already committed stays in the stream it belongs to.
  assert.equal(evidence[0].scope.tenantId, SCOPE.tenantId);
  assert.equal(evidence[0].scope.projectId, SCOPE.projectId);
});

test('a decision whose own scope is foreign or absent refuses with zero mutation', async () => {
  for (const authorityScope of [{ ...FOREIGN_SCOPE }, null, 'not-a-scope.invalid']) {
    const built = fullScenario();
    const { view, counters } = countingRegistry(built.scenario.registry);
    const owner = createBoundMappingRevocation({ ...built.revocation.host, registry: view });
    // The decision's own scope moves; the context it carries stays bound to A, so a host cannot
    // answer for B while pointing at A's context.
    built.revocation.state.authorityScope = authorityScope;

    assert.equal((await owner.revoke()).code, 'WITHHELD');
    assert.equal(counters.transition, 0);
    assert.deepEqual(lifecycleOf(built.scenario), { state: 'ACTIVE', revision: built.scenario.revision });
    assert.equal(revokeEvidence(built.ledger).length, 0);
  }
});

/* ---------- 4. Audit outages on both sides of the mutation ---------- */

test('an audit outage before the mutation withholds and leaves the mapping ACTIVE', async () => {
  const built = fullScenario();
  const owner = createBoundMappingRevocation(built.revocation.host);
  built.ledger.accepting = false;

  const withheld = await owner.revoke();
  fixedShape(withheld);
  assert.equal(withheld.code, 'WITHHELD');
  // The registry's own record is the proof that nothing was revoked.
  assert.deepEqual(lifecycleOf(built.scenario), { state: 'ACTIVE', revision: built.scenario.revision });
  assert.equal(revokeEvidence(built.ledger).length, 0);
});

test('a fault recording the applied result stays revoked and never reports audited success',
  async () => {
    // One slot: the authorized intent commits, the applied result cannot, so the sink fails only
    // after the registry already applied the transition.
    const built = fullScenario({ ledgerOptions: { maxEntries: 1 } });
    const owner = createBoundMappingRevocation(built.revocation.host);

    const result = await owner.revoke();
    fixedShape(result);
    assert.equal(result.code, 'UNRECORDED');
    assert.equal(result.code === 'REVOKED', false);
    assert.deepEqual(lifecycleOf(built.scenario), { state: 'ABSENT', revision: undefined,
      finding: 'NOT_LIVE' });
    const evidence = revokeEvidence(built.ledger);
    assert.equal(evidence.length, 1);
    assert.equal(evidence[0].reason, 'RESOLUTION_AUTHORIZED');

    // Nothing was revived: the same `USE` still withholds before any material access.
    const withheld = await built.execute.use();
    assert.equal(withheld.code, 'WITHHELD');
    assert.equal(built.materialCalls(), 0);
    assert.equal(built.backend.state.calls, 0);
  });

/* ---------- 5. What the registry actually answered ---------- */

test('a mutation that applied and then failed is UNRECORDED and never claims WITHHELD', async () => {
  for (const fault of ['throw', 'malformed-scope', 'throwing-getter']) {
    const built = fullScenario();
    const registry = built.scenario.registry;
    const { view, counters } = countingRegistry(registry, { wrapTransition: (request, clock) => {
      // The real transition is applied first, so the record really is terminal when the fault lands.
      // Once the mutation has been attempted, uncertainty is the only honest answer: a `WITHHELD`
      // here would claim zero mutation for a record the registry already moved.
      const applied = registry.transition(request, clock);
      if (fault === 'throw') throw new Error('synthetic post-mutation fault');
      if (fault === 'malformed-scope') {
        return { version: 1, state: 'CHANGED', metadata: { ...applied.metadata, scope: null } };
      }
      const metadata = { ...applied.metadata };
      Object.defineProperty(metadata, 'scope', { enumerable: true,
        get() { throw new Error('synthetic scope fault'); } });
      return { version: 1, state: 'CHANGED', metadata };
    } });
    const owner = createBoundMappingRevocation({ ...built.revocation.host, registry: view });

    const result = await owner.revoke();
    fixedShape(result);
    assert.equal(result.code, 'UNRECORDED');
    assert.equal(result.code === 'WITHHELD', false);
    assert.equal(counters.transition, 1);
    // The registry's own record is terminal: the mapping really was revoked and nothing revives it.
    assert.deepEqual(lifecycleOf(built.scenario), { state: 'ABSENT', revision: undefined,
      finding: 'NOT_LIVE' });
    // Intent only: an application this owner cannot confirm is never recorded as a success.
    const evidence = revokeEvidence(built.ledger);
    assert.equal(evidence.length, 1);
    assert.equal(evidence[0].reason, 'RESOLUTION_AUTHORIZED');
    assert.equal(evidence.some((event) => event.outcome === 'APPLIED'), false);
  }
});

test('an unconfirmed registry answer is UNRECORDED and records no applied evidence', async () => {
  const built = fullScenario();
  const registry = built.scenario.registry;
  const { view, counters } = countingRegistry(registry, { wrapTransition: (request, clock) => {
    // The record the registry really holds is reported back as an unchanged application: the seam
    // claims nothing was applied and nothing was, so uncertainty is still the honest answer.
    const live = registry.current({ version: 1, mappingRef: request.mappingRef,
      scope: request.scope }, clock);
    return { version: 1, state: 'UNCHANGED', metadata: live.metadata };
  } });
  const owner = createBoundMappingRevocation({ ...built.revocation.host, registry: view });

  const result = await owner.revoke();
  fixedShape(result);
  assert.equal(result.code, 'UNRECORDED');
  assert.equal(counters.transition, 1);
  assert.deepEqual(lifecycleOf(built.scenario), { state: 'ACTIVE', revision: built.scenario.revision });
  const evidence = revokeEvidence(built.ledger);
  assert.deepEqual(evidence.map((event) => event.outcome), ['ALLOWED']);
  assert.equal(evidence[0].reason, 'RESOLUTION_AUTHORIZED');
});

test('a genuine registry refusal is WITHHELD with intent-only evidence and no applied event',
  async () => {
    const built = fullScenario();
    const registry = built.scenario.registry;
    const answers = [];
    const { view, counters } = countingRegistry(registry, { wrapTransition: (request, clock) => {
      // A competitor applies the same transition through the same registry first, so this owner's
      // compare-and-set is answered by the shipped registry with its own refusal, not a planted one.
      answers.push(registry.transition(request, clock), registry.transition(request, clock));
      return answers[1];
    } });
    const owner = createBoundMappingRevocation({ ...built.revocation.host, registry: view });

    const result = await owner.revoke();
    fixedShape(result);
    assert.equal(result.code, 'WITHHELD');
    assert.equal(counters.transition, 1);
    // Both answers are the shipped registry's own, and the second confirms it applied nothing.
    assert.equal(answers[0].state, 'CHANGED');
    assert.equal(answers[1].state, 'REFUSED');
    assert.equal(answers[1].reason, 'STALE_REVISION');
    // The tombstone is the competitor's; this owner recorded its intent and no applied success.
    assert.deepEqual(lifecycleOf(built.scenario), { state: 'ABSENT', revision: undefined,
      finding: 'NOT_LIVE' });
    const evidence = revokeEvidence(built.ledger);
    assert.deepEqual(evidence.map((event) => event.outcome), ['ALLOWED']);
    assert.equal(evidence[0].reason, 'RESOLUTION_AUTHORIZED');
  });

/* ---------- 6. Captured methods, receivers and the sealed segment ---------- */

test('a transition method replaced after construction is never invoked', async () => {
  const built = fullScenario();
  const registry = built.scenario.registry;
  // The shipped registry object is frozen, so the host hands a delegating view of it. That view is
  // exactly the object whose methods the owner binds, so a `transition` installed on it after
  // construction has replaced a property the owner no longer reads.
  const view = { version: 1, current: (...args) => registry.current(...args),
    transition: (...args) => registry.transition(...args) };
  let replacements = 0;
  const owner = createBoundMappingRevocation({ ...built.revocation.host, registry: view });
  Object.defineProperty(view, 'transition', { value: () => { replacements += 1;
    return { version: 1, state: 'REFUSED', reason: 'INVALID_TRANSITION' }; }, configurable: true });

  assert.equal((await owner.revoke()).code, 'REVOKED');
  assert.equal(replacements, 0);
  // The registry's own record is the only claim of a mutation, and it is the real terminal one.
  assert.deepEqual(lifecycleOf(built.scenario), { state: 'ABSENT', revision: undefined,
    finding: 'NOT_LIVE' });
});

test('an authority method that depends on its receiver is called with the host', async () => {
  const built = fullScenario();
  const base = built.revocation.host;
  const answer = base.authority;
  const host = { ...base };
  // The owner must invoke the captured method with the host it was constructed against.
  host.authority = function () {
    if (this !== host || this.mappingRef !== built.scenario.mappingRef ||
      this.adminPurpose !== ADMIN_PURPOSE) throw new Error('synthetic receiver fault');
    return answer.call(this);
  };
  const owner = createBoundMappingRevocation(host);
  assert.equal((await owner.revoke()).code, 'REVOKED');
});

test('an authority callback that throws or answers with a boolean refuses with zero mutation',
  async () => {
    for (const answer of [() => { throw new Error('synthetic authority fault'); },
      () => true, () => { const b = {}; b.allowed = true; return b; }]) {
      const built = fullScenario();
      const owner = createBoundMappingRevocation({ ...built.revocation.host, authority: answer });
      assert.equal((await owner.revoke()).code, 'WITHHELD');
      assert.equal(lifecycleOf(built.scenario).state, 'ACTIVE');
      assert.equal(revokeEvidence(built.ledger).length, 0);
    }
  });

test('a denial or an expiry queued at the last guard refuses before the mutation', async () => {
  for (const queued of [(state) => { state.decision = 'DENY'; },
    (state) => { state.expiresAt = state.now; }]) {
    const built = fullScenario({ hooks: { onAuthority: (n, fixture) => {
      // Queued on the final observation: the answer this owner acts on is normalized and fully
      // guarded in the continuation that reads it, so a decision revoked or expired while that
      // answer was pending still withholds - the authority cannot be stale at the mutation.
      if (n === 2) queued(fixture.state);
    } } });
    const owner = createBoundMappingRevocation(built.revocation.host);

    assert.equal((await owner.revoke()).code, 'WITHHELD');
    // Exactly two observations: the initial one and the last awaited answer.
    assert.equal(built.revocation.counters.authority, 2);
    assert.deepEqual(lifecycleOf(built.scenario), { state: 'ACTIVE', revision: built.scenario.revision });
    const evidence = revokeEvidence(built.ledger);
    assert.equal(evidence.length, 1);
    assert.equal(evidence[0].reason, 'RESOLUTION_AUTHORIZED');
  }
});

test('a revocation queued by a host callback is observed before the mutation and never claimed',
  async () => {
    const raced = { queued: 0, answer: undefined };
    const built = fullScenario({ hooks: { onAuthority: (n) => {
      // Queued by the last authority answer: the awaited answer resumes only after the microtask
      // queue drains, so this racing mutation has already moved the record by the time the final
      // guards run - and the owner's own compare-and-set is never reached.
      if (n === 2) {
        raced.queued += 1;
        queueMicrotask(() => { raced.answer = competitor(built); });
      }
    } } });
    const owner = createBoundMappingRevocation(built.revocation.host);

    const result = await owner.revoke();
    fixedShape(result);
    assert.equal(result.code, 'WITHHELD');
    // The trigger really fired, on the final observation and exactly once, and its real transition
    // really applied.
    assert.equal(raced.queued, 1);
    assert.equal(built.revocation.counters.authority, 2);
    assert.equal(raced.answer.state, 'CHANGED');
    assert.deepEqual(lifecycleOf(built.scenario), { state: 'ABSENT', revision: undefined,
      finding: 'NOT_LIVE' });
    // The tombstone is the competitor's: this owner recorded its intent and no applied success.
    const evidence = revokeEvidence(built.ledger);
    assert.deepEqual(evidence.map((event) => event.outcome), ['ALLOWED']);
    assert.equal(evidence.some((event) => event.outcome === 'APPLIED'), false);
  });

test('a revocation queued at the last registry read cannot land between that read and the mutation',
  async () => {
    const built = fullScenario();
    const raced = { queued: 0, answer: undefined };
    const { view, counters } = countingRegistry(built.scenario.registry, { afterCurrent: (n) => {
      // Queued by the last registry read of the whole call: the final guard and the compare-and-set
      // share one continuation, so this racing mutation is queued behind the entire effect rather
      // than inside it.
      if (n === 2) {
        raced.queued += 1;
        queueMicrotask(() => { raced.answer = competitor(built); });
      }
    } });
    const owner = createBoundMappingRevocation({ ...built.revocation.host, registry: view });

    assert.equal((await owner.revoke()).code, 'REVOKED');
    assert.deepEqual(counters, { current: 2, transition: 1 });
    assert.equal(raced.queued, 1);
    assert.deepEqual(lifecycleOf(built.scenario), { state: 'ABSENT', revision: undefined,
      finding: 'NOT_LIVE' });
    assert.equal(raced.answer.state, 'REFUSED');
    assert.equal(raced.answer.state === 'CHANGED', false);
  });

test('an overlapping call is refused immediately, before any host call', async () => {
  const built = fullScenario();
  const owner = createBoundMappingRevocation(built.revocation.host);
  const held = owner.revoke();
  const overlapping = await owner.revoke();
  assert.equal(overlapping.code, 'WITHHELD');
  assert.equal((await held).code, 'REVOKED');
});

/* ---------- 7. Construction, privacy and the module's own silence ---------- */

test('an unusable host is refused at construction with one fixed TypeError', () => {
  const built = fullScenario();
  const planted = 'planted-revocation-host-value.invalid';
  for (const host of [undefined, { ...built.revocation.host, version: 2 },
    { ...built.revocation.host, registry: null },
    { ...built.revocation.host, adminPurpose: ` ${planted} ` },
    { ...built.revocation.host, authority: 'not-a-function' }]) {
    assert.throws(() => createBoundMappingRevocation(host), (error) => {
      assert.ok(error instanceof TypeError);
      assert.equal(error.message.includes(planted), false);
      return true;
    });
  }
  assert.equal(lifecycleOf(built.scenario).state, 'ACTIVE');
});

test('the owner resolves nothing, logs nothing and carries no plaintext or key claim', () => {
  for (const path of ['src/mapping-revocation.ts', 'dist/mapping-revocation.js']) {
    const source = readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
    assert.equal(/\bconsole\s*\./u.test(source), false);
    // No mapping-value resolution, no persistence and no key handling reached this module.
    for (const forbidden of ['openMappingPayload', 'sealMappingPayload', 'createCipher',
      'writeFile', 'randomUUID', 'createHash']) {
      assert.equal(source.includes(forbidden), false, `${path} must not reference ${forbidden}`);
    }
    assert.equal(source.includes(ORIGINAL), false, `${path} must not reference a planted original`);
  }
});