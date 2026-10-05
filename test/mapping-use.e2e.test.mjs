// #211 behavioral tests for the one bound runtime USE executor.
//
// What is real here: `createBoundMappingUse`, the shipped registry, the shipped purpose-bound
// authorization seam, the shipped Policy Engine, the shipped audit append and its gate, the shipped
// AEAD opener, and the lifecycle reducer behind the registry. What is a fixture: the workload
// identity, the scope, the grant, the destination, the policy bundle and its pinned digests, the
// audit keys, the clock and the private synchronous resource. Nothing authenticates anybody here.
//
// Every value is invented, obviously synthetic and non-routable: `.invalid` names, fixed byte fills
// as DEK, HMAC and audit key material, one epoch instant, and a planted original that is never used
// as an assertion operand. The backend is provisioned out of band with the handle its own resource
// owns and compares the recovered bytes inside its own closure, so no identifier ever leaves it as a
// value: the executor sees one primitive boolean and this file asserts codes, counters and booleans.
//
// What is deliberately NOT claimed: this file cannot count calls the executor makes into
// `openMappingPayload`, because that call is internal to the shipped module. The observable counters
// are the host's own authority callback, its material callback, its backend and the audit ledger. A
// `USED` or a `NOT_FOUND` proves the opener ran, because the only route to the backend is a recovered
// identifier; a `WITHHELD` proves only that the backend was not spent, which is what is asserted.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createBoundMappingUse, MAPPING_USE_CODES } from '../dist/mapping-use.js';
import { createMappingMetadataRegistry } from '../dist/mapping-metadata-registry.js';
import { digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE }
  from '../dist/policy.js';
import { composeClassification } from '../dist/classification.js';
import { appendAuditEvent, createInMemoryAuditLedger, verifyAuditStream, AUDIT_SCHEMA_VERSION }
  from '../dist/audit-ledger.js';
import { deriveScopedEntityReference } from '../dist/scoped-entity-reference.js';
import { sealMappingPayload, MAPPING_AEAD_LIMITS } from '../dist/mapping-aead.js';

/* ---------- Fixed synthetic literals ---------- */

const ORIGINAL = 'synthetic-bound-use-original.invalid';
const ORIGINAL_BYTES = new TextEncoder().encode(ORIGINAL);
const FOREIGN_HANDLE = 'synthetic-bound-use-foreign.invalid';
const KEY_VERSION = '1.0';
const ROTATED_KEY_VERSION = '2.0';
const CLASS = 'PERSON';
const SENSITIVITY = 'CONFIDENTIAL';
const TRUST = 'TRUSTED';
const T0 = 1_700_000_000_000;
const TTL_MS = 3_600_000;
const CAPACITY = 8;
const USE_NOW = T0 + 60_000;
const OCCURRED_AT = new Date(USE_NOW).toISOString();

const WORKLOAD = Object.freeze({
  principalId: 'principal-bound-use-fixture.invalid', workloadId: 'workload-bound-use-fixture.invalid' });
const OTHER_WORKLOAD = Object.freeze({
  principalId: 'principal-other-bound-use.invalid', workloadId: 'workload-other-bound-use.invalid' });
const PURPOSE = 'bound-use-fixture.invalid';
const ENTITY_ID = 'entity-bound-use-fixture';
const INTERACTION_REF = 'interaction-bound-use-fixture.invalid';
const CANDIDATE_REF = 'candidate-bound-use-fixture.invalid';
const SOURCE = Object.freeze({ kind: 'tool.result', ref: 'source-bound-use-fixture.invalid',
  trustZone: 'LOCAL' });
const DESTINATION = Object.freeze({ kind: 'tool.result', ref: 'sink-bound-use-fixture.invalid',
  trustZone: 'LOCAL', profileId: 'profile-bound-use-fixture.invalid' });
const OTHER_DESTINATION = Object.freeze({ ...DESTINATION, ref: 'other-sink-bound-use.invalid' });
const SCOPE = Object.freeze({ tenantId: 'tenant-bound-use-alpha.invalid',
  projectId: 'project-bound-use-alpha.invalid', sessionId: 'session-bound-use-alpha.invalid' });
const FOREIGN_SCOPE = Object.freeze({ tenantId: 'tenant-bound-use-beta.invalid',
  projectId: 'project-bound-use-beta.invalid', sessionId: 'session-bound-use-beta.invalid' });

function keyBytes(fill) { return new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(fill); }

/* ---------- One ephemeral mapping, real registry, real AEAD ---------- */

/**
 * Builds the mapping, its real registry record and its real sealed envelope. The plaintext exists
 * only to be sealed; nothing here retains it, and the scenario holds ciphertext plus non-secret
 * metadata.
 */
function buildScenario({ scope = SCOPE, keyFill = 0x11 } = {}) {
  const hmacKey = keyBytes(0x44);
  const derived = deriveScopedEntityReference({ scope: 'SESSION', tenantId: scope.tenantId,
    projectId: scope.projectId, sessionId: scope.sessionId, entityId: ENTITY_ID,
    semanticType: CLASS, keyVersion: KEY_VERSION, key: hmacKey });
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
  const seal = (revision) => sealMappingPayload({ scope: aadScope(scope, revision),
    plaintext: ORIGINAL_BYTES, key: keyBytes(keyFill) });
  const sealed = seal(2);
  assert.equal(sealed.status, 'SEALED');
  return { registry, mappingRef, scope: Object.freeze({ ...scope }), expiresAt,
    envelope: sealed.envelope, seal };
}
function aadScope(scope, revision) {
  return { tenantId: scope.tenantId, projectId: scope.projectId, entityId: ENTITY_ID,
    classification: CLASS, mappingRevision: String(revision), keyVersion: KEY_VERSION };
}

/* ---------- The pinned policy handoff ---------- */

const EVIDENCE = composeClassification({ detectorEvidence: [{
  version: 1, id: 'detector-bound-use-fixture.invalid', status: 'FOUND',
  provenance: { inputRef: 'field-bound-use-fixture.invalid',
    producerId: 'detector-bound-use-fixture.invalid', producerVersion: 'pack-1' },
  claim: { semanticType: CLASS, sensitivity: SENSITIVITY } },
] }, { interactionRef: INTERACTION_REF, sourceRef: SOURCE.ref, trust: TRUST });

// The same detector finding with one declared subtype more, composed by the same v1 API. It is a
// structurally valid record that is congruent with its own evidence and that the same bundle selects
// KEEP for, so the only thing that separates it from `EVIDENCE` is the content digest an independent
// pin commits to. A record whose top-level field disagrees with its own evidence would be a different
// and easier thing to refuse.
const EVIDENCE_WITH_SUBTYPE = composeClassification({ detectorEvidence: [{
  version: 1, id: 'detector-bound-use-fixture.invalid', status: 'FOUND',
  provenance: { inputRef: 'field-bound-use-fixture.invalid',
    producerId: 'detector-bound-use-fixture.invalid', producerVersion: 'pack-1' },
  claim: { semanticType: CLASS, subtype: 'NAME', sensitivity: SENSITIVITY } },
] }, { interactionRef: INTERACTION_REF, sourceRef: SOURCE.ref, trust: TRUST });
assert.notEqual(digestClassification(EVIDENCE_WITH_SUBTYPE), digestClassification(EVIDENCE));

const RELEASE_TREATMENTS = ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE'];
function policyBundle(decision = 'KEEP') {
  const rule = { id: `rule-bound-use-${decision.toLowerCase()}.invalid`,
    profileId: DESTINATION.profileId, semanticType: CLASS, sensitivities: [SENSITIVITY],
    sourceTrust: [TRUST], operations: ['USE'], decision,
    ...(decision === 'REQUIRE_REVIEW' ? { reviewTreatments: ['GENERALIZE'] } : {}) };
  return { ...KNOWN_POLICY_BUNDLE,
    profiles: [{ id: DESTINATION.profileId, sink: { ...DESTINATION }, exposure: 'LOCAL',
      permittedTreatments: RELEASE_TREATMENTS, maxCleartextSensitivity: 'RESTRICTED' }],
    rules: [rule] };
}

/* ---------- The private synchronous resource ---------- */

/**
 * The synthetic trusted local resource: a lookup over the handle its own record owns, provisioned out
 * of band. It returns one primitive boolean and nothing else. `retained` deliberately keeps the
 * buffer reference so this file can prove the executor's `finally` overwrote the bytes it owns; the
 * assertion reads only a boolean over those bytes, never the bytes themselves. `bound` makes the
 * method depend on its own receiver, and `applyFault` wraps it in a callable proxy whose invocation
 * trap throws, so a caller that resolved a mutable property of the function instead of invoking it
 * would be observed rather than trusted.
 */
function createBackend({ handle = ORIGINAL, behaviour = 'match', bound = false,
  applyFault = false, probe = undefined } = {}) {
  const provisioned = new TextEncoder().encode(handle);
  const state = { calls: 0, retained: undefined, probed: undefined };
  const backend = {
    state,
    lookup(identifier) {
      if (bound && this !== backend) throw new Error('synthetic receiver fault');
      state.calls += 1;
      state.retained = identifier;
      // The optional probe reads the world at the moment the resource is really called, so a test can
      // observe the state the effect was actually spent against instead of inferring it.
      if (typeof probe === 'function') state.probed = probe();
      if (behaviour === 'throw') throw new Error('synthetic resource fault');
      if (behaviour === 'non-boolean') return { matched: true };
      let matched = identifier.byteLength === provisioned.byteLength;
      for (let index = 0; index < provisioned.byteLength && matched; index += 1) {
        matched = identifier[index] === provisioned[index];
      }
      return matched;
    },
  };
  if (applyFault) {
    const trapped = new Proxy(backend.lookup, { apply() {
      throw new Error('synthetic invocation fault');
    } });
    return Object.freeze({ ...backend, lookup: trapped });
  }
  return backend;
}
/**
 * A byte source that throws on one index read, so a copy of it is interrupted part-way through. The
 * typed-array accessors are forwarded with the **target** as their receiver: a `Proxy` is not itself a
 * typed array, so forwarding `byteLength` with the `Proxy` would throw before a single byte was read
 * and this case would prove an early refusal instead of an interrupted copy. `source.reads` counts
 * the index reads that reached the trap, which is how the fault index itself is asserted.
 */
function interruptedBytes(bytes, faultAt = 5) {
  const source = { reads: 0, faultAt, reached: false, bytes: undefined };
  source.bytes = new Proxy(bytes, { get(target, property) {
    if (typeof property === 'string' && /^(?:0|[1-9][0-9]*)$/u.test(property)) source.reads += 1;
    if (property === String(faultAt)) { source.reached = true; throw new Error('synthetic byte fault'); }
    return Reflect.get(target, property, target);
  } });
  return source;
}
function cleared(buffer) {
  if (buffer === undefined) return false;
  for (let index = 0; index < buffer.byteLength; index += 1) if (buffer[index] !== 0) return false;
  return true;
}

/* ---------- One host, assembled from the real seams ---------- */

/**
 * Assembles the trusted host. `state` holds the values the host will report on each authority
 * observation, so a test can change the world between two observations and see whether the executor
 * notices. `hooks.onMaterial` and `hooks.onAuthority(n)` run at exactly those points.
 */
function createHost(options = {}) {
  const scenario = options.scenario ?? buildScenario();
  const bundle = options.bundle ?? policyBundle('KEEP');
  const classification = options.classification ?? EVIDENCE;
  const backend = options.backend ?? createBackend();
  const ledger = options.ledger ?? createInMemoryAuditLedger(
    { tenantId: scenario.scope.tenantId, projectId: scenario.scope.projectId });
  const auditContext = options.auditContext ?? { version: AUDIT_SCHEMA_VERSION,
    scope: { tenantId: scenario.scope.tenantId, projectId: scenario.scope.projectId },
    actor: { principalId: WORKLOAD.principalId, workloadId: WORKLOAD.workloadId },
    integrationId: 'integration-bound-use-fixture.invalid',
    actorBinding: 'AUTHENTICATED_UPSTREAM', pseudonymKey: keyBytes(0x33), chainKey: keyBytes(0x77) };
  const revision = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope } }, { now: USE_NOW });
  assert.equal(revision.state, 'FOUND');
  const record = revision.metadata;
  const state = { subject: WORKLOAD, context: { ...scenario.scope, purpose: PURPOSE },
    destination: DESTINATION, grant: Object.hasOwn(options, 'grant') ? options.grant
      : makeGrant(scenario, record, 'USE'),
    keyVersion: KEY_VERSION, now: USE_NOW };
  const interrupted = options.interruptedCiphertext
    ? interruptedBytes(scenario.envelope.ciphertext) : undefined;
  const counters = { authority: 0, material: 0 };
  const hooks = options.hooks ?? {};
  const order = [];
  const fixture = { host: undefined, state, counters, scenario, backend, ledger, auditContext,
    bundle, hooks, order, interrupted, source: scenario.envelope.ciphertext };
  const report = () => ({ version: 1, subject: { ...state.subject }, context: { ...state.context },
    destination: { ...state.destination },
    grant: state.grant === undefined ? undefined : { ...state.grant },
    keyVersion: state.keyVersion, now: state.now });
  const host = {
    version: 1,
    mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope },
    entityId: ENTITY_ID,
    registry: scenario.registry,
    audit: { ledger, context: auditContext,
      components: [{ id: 'CLASSIFICATION_POLICY', version: '1' },
        { id: 'AUTHORIZATION_POLICY', version: '1' }] },
    policy: { version: 1, interactionRef: INTERACTION_REF, candidateRef: CANDIDATE_REF,
      source: { ...SOURCE, trust: TRUST }, classification,
      classificationDigest: options.classificationDigest ?? digestClassification(classification),
      policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(bundle) }, bundle },
    backend,
    authority: options.authority ?? (() => {
      counters.authority += 1;
      if (typeof hooks.onAuthority === 'function') hooks.onAuthority(counters.authority, fixture);
      return report();
    }),
    material() {
      counters.material += 1;
      order.push('material');
      if (typeof hooks.onMaterial === 'function') hooks.onMaterial(fixture);
      const ciphertext = interrupted === undefined
        ? scenario.envelope.ciphertext : interrupted.bytes;
      return { version: 1, envelope: { ...scenario.envelope, ciphertext },
        key: keyBytes(options.keyFill ?? 0x11),
        mappingRevision: options.materialRevision ?? String(record.revision),
        keyVersion: options.materialKeyVersion ?? state.keyVersion };
    },
  };
  if (options.asyncAuthority) {
    // A host callback documented as possibly asynchronous answers with a promise. The executor must
    // await it before it is read, and every observation must settle inside the one `use()` call.
    host.authority = async () => {
      counters.authority += 1;
      order.push('authority:start');
      await new Promise((resolve) => { setTimeout(resolve, 1); });
      if (typeof hooks.onAuthority === 'function') hooks.onAuthority(counters.authority, fixture);
      order.push('authority:settled');
      if (options.asyncAuthority === 'reject') throw new Error('synthetic authority fault');
      return report();
    };
  }
  if (options.receiverDependent) {
    // Both callbacks read their own receiver's bound configuration, the way a real host method does.
    const owner = host;
    const answer = host.authority;
    const supply = host.material;
    host.authority = function () {
      if (this !== owner || this.scope.tenantId !== SCOPE.tenantId || this.entityId !== ENTITY_ID) {
        throw new Error('synthetic receiver fault');
      }
      return answer.call(this);
    };
    host.material = function () {
      if (this !== owner || this.scope.sessionId !== SCOPE.sessionId || this.entityId !== ENTITY_ID) {
        throw new Error('synthetic receiver fault');
      }
      return supply.call(this);
    };
  }
  fixture.host = host;
  return fixture;
}
function makeGrant(scenario, record, operation, overrides = {}) {
  return { version: 1, mappingRef: scenario.mappingRef, revision: record.revision,
    principal: { ...WORKLOAD }, context: { ...scenario.scope, purpose: PURPOSE },
    destination: { ...DESTINATION }, operation, expiresAt: scenario.expiresAt - 1, ...overrides };
}

/** A WITHHELD/FAILED/USED run must show exactly what the host was asked for, and nothing else. */
function assertFixedShape(result) {
  assert.equal(result.version, 1);
  assert.equal(MAPPING_USE_CODES.includes(result.code), true);
  assert.deepEqual(Object.keys(result).sort(), ['code', 'version']);
}

/* ---------- 1. The accepted path: an independent private lookup decides USED ---------- */

test('an audited use spends the recovered identifier on its own private resource', async () => {
  const backend = createBackend();
  const built = createHost({ backend });
  const executor = createBoundMappingUse(built.host);
  assert.equal(built.scenario.registry.size, 1);

  const used = await executor.use();
  assertFixedShape(used);
  assert.equal(used.code, 'USED');
  // The positive is genuinely dependent: one material load, one backend call, and the backend
  // matched the handle it was provisioned with out of band.
  assert.equal(built.counters.material, 1);
  assert.equal(backend.state.calls, 1);
  assert.equal(built.counters.authority, 4);
  assert.equal(built.ledger.entries.length, 2);
  assert.equal(built.ledger.entries.every((entry) => entry.event.operation === 'USE'), true);
  assert.equal(built.ledger.entries.every((entry) => entry.event.outcome === 'ALLOWED'), true);
  assert.equal(built.ledger.entries.some((entry) => entry.event.outcome === 'APPLIED'), false);
  assert.equal(verifyAuditStream(built.ledger, built.auditContext, []).status, 'UNANCHORED');
  // The recovered bytes do not outlive the call: the backend kept only the reference.
  assert.equal(cleared(backend.state.retained), true);
  // A second, sequential use is a fresh observation, not a cached snapshot.
  assert.equal((await executor.use()).code, 'USED');
  assert.equal(built.counters.material, 2);
  assert.equal(backend.state.calls, 2);
  assert.equal(built.counters.authority, 8);
});

test('a backend provisioned with another handle genuinely misses and reports NOT_FOUND', async () => {
  const wrong = createBackend({ handle: FOREIGN_HANDLE });
  const built = createHost({ backend: wrong });
  const result = await createBoundMappingUse(built.host).use();
  assertFixedShape(result);
  assert.equal(result.code, 'NOT_FOUND');
  // The opener really ran and the resource really was consulted: success is never the open call.
  assert.equal(built.counters.material, 1);
  assert.equal(wrong.state.calls, 1);
  assert.equal(cleared(wrong.state.retained), true);
  assert.equal(built.ledger.entries.length, 2);
});

/* ---------- 2. A real BLOCK or HELD policy decision withholds before any material ---------- */

test('an actual BLOCK or HELD policy decision withholds before the material load', async () => {
  for (const decision of ['BLOCK', 'REQUIRE_REVIEW']) {
    const bundle = policyBundle(decision);
    const backend = createBackend();
    const built = createHost({ bundle, backend });
    const control = await createBoundMappingUse(createHost({}).host).use();
    assert.equal(control.code, 'USED', decision);
    const refused = await createBoundMappingUse(built.host).use();
    assertFixedShape(refused);
    assert.equal(refused.code, 'WITHHELD', decision);
    assert.equal(built.counters.material, 0, decision);
    assert.equal(backend.state.calls, 0, decision);
    assert.equal(built.ledger.entries.length, 0, decision);
    assert.equal(cleared(backend.state.retained), false, decision);
  }
});

/* ---------- 3. Refused authorization, scope and lifecycle ---------- */

test('a missing, misbound, stale or expired grant withholds before the material load', async () => {
  const scenario = buildScenario();
  const record = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope } }, { now: USE_NOW });
  const cases = [
    ['no grant at all', undefined, 1],
    ['a grant for another operation', makeGrant(scenario, record.metadata, 'DISPLAY'), 0],
    ['a grant pinned to a superseded revision', makeGrant(scenario, record.metadata, 'USE',
      { revision: 1 }), 0],
    ['a grant issued to another workload', makeGrant(scenario, record.metadata, 'USE',
      { principal: { ...OTHER_WORKLOAD } }), 0],
    ['a grant bound to another destination', makeGrant(scenario, record.metadata, 'USE',
      { destination: { ...OTHER_DESTINATION } }), 0],
    ['a grant bound to another purpose', makeGrant(scenario, record.metadata, 'USE',
      { context: { ...scenario.scope, purpose: 'other-bound-use.invalid' } }), 0],
    ['a grant that has already expired', makeGrant(scenario, record.metadata, 'USE',
      { expiresAt: T0 + 30_000 }), 1],
  ];
  assert.equal((await createBoundMappingUse(createHost({}).host).use()).code, 'USED');
  for (const [name, grant, recorded] of cases) {
    const backend = createBackend();
    const built = createHost({ scenario, grant, backend });
    const refused = await createBoundMappingUse(built.host).use();
    assert.equal(refused.code, 'WITHHELD', name);
    assert.equal(built.counters.material, 0, name);
    assert.equal(backend.state.calls, 0, name);
    // A missing grant and an expired grant are refusals attributable to the established, in-scope,
    // authenticated actor, so each leaves one privacy-safe DENIED record. Every other refusal in
    // this list is the actor's own misbound authority or a refusal of a reference this call never
    // proved it held, so it leaves the ledger untouched and stays the host's obligation.
    assert.equal(built.ledger.entries.length, recorded, name);
    if (recorded === 1) {
      assert.equal(built.ledger.entries[0].event.kind, 'AUTHORIZATION_ATTEMPT', name);
      assert.equal(built.ledger.entries[0].event.outcome, 'DENIED', name);
      assert.equal(built.ledger.entries[0].event.reason, 'RESOLUTION_DENIED', name);
    }
  }
});

test('a foreign scope and a non-active lifecycle record withhold before the material load', async () => {
  // The scope is bound at construction, so a foreign observation never reaches the registry, the
  // grant or the resource at all.
  const foreignBackend = createBackend();
  const foreign = createHost({ backend: foreignBackend, authority: () => ({ version: 1,
    subject: { ...WORKLOAD }, context: { ...FOREIGN_SCOPE, purpose: PURPOSE },
    destination: { ...DESTINATION }, keyVersion: KEY_VERSION, now: USE_NOW,
    grant: makeGrant(foreignScopeScenario(), { revision: 2 }, 'USE') }) });
  const refusedScope = await createBoundMappingUse(foreign.host).use();
  assert.equal(refusedScope.code, 'WITHHELD');
  assert.equal(foreign.counters.material, 0);
  assert.equal(foreignBackend.state.calls, 0);
  assert.equal(foreign.ledger.entries.length, 0);

  const revokedBackend = createBackend();
  const revoked = createHost({ backend: revokedBackend });
  const transition = revoked.scenario.registry.transition({ version: 1,
    mappingRef: revoked.scenario.mappingRef, scope: { ...revoked.scenario.scope },
    expectedRevision: 2, action: 'REVOKE' }, { now: USE_NOW });
  assert.equal(transition.state, 'CHANGED');
  assert.equal((await createBoundMappingUse(revoked.host).use()).code, 'WITHHELD');
  assert.equal(revoked.counters.material, 0);
  assert.equal(revokedBackend.state.calls, 0);

  const expiredBackend = createBackend();
  const expired = createHost({ backend: expiredBackend });
  expired.state.now = expired.scenario.expiresAt;
  assert.equal((await createBoundMappingUse(expired.host).use()).code, 'WITHHELD');
  assert.equal(expired.counters.material, 0);
  assert.equal(expiredBackend.state.calls, 0);
});
function foreignScopeScenario() {
  return { mappingRef: buildScenario().mappingRef, scope: SCOPE };
}

/* ---------- 4. Refused audit evidence ---------- */

test('audit evidence that the real append will not record withholds before the resource', async () => {
  // A sink that cannot commit: the shipped append answers RESTRICTED and the shipped gate withholds.
  const closed = createHost();
  closed.ledger.accepting = false;
  const outage = await createBoundMappingUse(closed.host).use();
  assert.equal(outage.code, 'WITHHELD');
  assert.equal(closed.counters.material, 1);
  assert.equal(closed.host.backend.state.calls, 0);
  assert.equal(closed.ledger.entries.length, 0);

  // A trusted context whose scope does not match the stream: a real SCOPE_MISMATCH from the real
  // append, gated by the real gate, never a fabricated RECORDED result.
  const misScoped = createHost({ auditContext: { version: AUDIT_SCHEMA_VERSION,
    scope: { tenantId: FOREIGN_SCOPE.tenantId, projectId: FOREIGN_SCOPE.projectId },
    actor: { principalId: WORKLOAD.principalId, workloadId: WORKLOAD.workloadId },
    integrationId: 'integration-bound-use-fixture.invalid', actorBinding: 'AUTHENTICATED_UPSTREAM',
    pseudonymKey: keyBytes(0x33), chainKey: keyBytes(0x77) } });
  const mismatched = await createBoundMappingUse(misScoped.host).use();
  assert.equal(mismatched.code, 'WITHHELD');
  assert.equal(misScoped.host.backend.state.calls, 0);
  assert.equal(misScoped.ledger.entries.length, 0);

  // The audit actor must be this authenticated subject; the ledger takes the actor from its trusted
  // context and never from a draft, so another actor is refused before anything is written.
  const otherActor = createHost({ auditContext: { version: AUDIT_SCHEMA_VERSION,
    scope: { tenantId: SCOPE.tenantId, projectId: SCOPE.projectId },
    actor: { principalId: OTHER_WORKLOAD.principalId, workloadId: OTHER_WORKLOAD.workloadId },
    integrationId: 'integration-bound-use-fixture.invalid', actorBinding: 'AUTHENTICATED_UPSTREAM',
    pseudonymKey: keyBytes(0x33), chainKey: keyBytes(0x77) } });
  const wrongActor = await createBoundMappingUse(otherActor.host).use();
  assert.equal(wrongActor.code, 'WITHHELD');
  assert.equal(otherActor.counters.material, 0);
  assert.equal(otherActor.host.backend.state.calls, 0);
  assert.equal(otherActor.ledger.entries.length, 0);

  // Positive control on the identical scenario: the same path with an accepting, congruent substrate
  // records both decisions and spends the resource exactly once.
  assert.equal((await createBoundMappingUse(createHost({}).host).use()).code, 'USED');
});

/* ---------- 5. The world changes during the material callback ---------- */

test('a revocation or a route change during the material callback withholds before the resource', async () => {
  const revoked = createHost({ hooks: { onMaterial(fixture) {
    const applied = fixture.host.registry.transition({ version: 1, mappingRef: fixture.host.mappingRef,
      scope: { ...fixture.host.scope }, expectedRevision: 2, action: 'REVOKE' }, { now: USE_NOW });
    assert.equal(applied.state, 'CHANGED');
  } } });
  const afterRevocation = await createBoundMappingUse(revoked.host).use();
  assert.equal(afterRevocation.code, 'WITHHELD');
  assert.equal(revoked.counters.material, 1);
  assert.equal(revoked.backend.state.calls, 0);
  assert.equal(revoked.ledger.entries.length, 0);

  const rerouted = createHost({ hooks: { onMaterial(fixture) {
    fixture.state.destination = OTHER_DESTINATION;
  } } });
  const afterRouteChange = await createBoundMappingUse(rerouted.host).use();
  assert.equal(afterRouteChange.code, 'WITHHELD');
  assert.equal(rerouted.counters.material, 1);
  assert.equal(rerouted.backend.state.calls, 0);
  assert.equal(rerouted.ledger.entries.length, 0);
});

/* ---------- 6. The world changes between the audit and the effect ---------- */

test('a revocation landing after the authorization audit is refused and nothing is spent', async () => {
  const built = createHost({ hooks: { onAuthority(count, fixture) {
    // The fourth observation is the final recheck: both decisions are already recorded, and the
    // effect is the very next thing that would happen.
    if (count === 4) {
      const applied = fixture.host.registry.transition({ version: 1,
        mappingRef: fixture.host.mappingRef, scope: { ...fixture.host.scope },
        expectedRevision: 2, action: 'REVOKE' }, { now: USE_NOW });
      assert.equal(applied.state, 'CHANGED');
    }
  } } });
  const result = await createBoundMappingUse(built.host).use();
  assert.equal(result.code, 'WITHHELD');
  assert.equal(built.backend.state.calls, 0);
  // The trail is honest about what happened: two recorded decisions, no recorded effect.
  assert.equal(built.ledger.entries.length, 2);
  assert.equal(built.ledger.entries[0].event.kind, 'AUTHORIZATION_ATTEMPT');
  assert.equal(built.ledger.entries[0].event.outcome, 'ALLOWED');
  assert.equal(built.ledger.entries[1].event.kind, 'POLICY_DECISION');
  assert.equal(built.ledger.entries.some((entry) => entry.event.outcome === 'APPLIED'), false);
});

test('a grant revoked between the audit and the effect is refused and nothing is spent', async () => {
  const built = createHost({ hooks: { onAuthority(count, fixture) {
    if (count === 4) {
      const record = fixture.host.registry.current({ version: 1, mappingRef: fixture.host.mappingRef,
        scope: { ...fixture.host.scope } }, { now: USE_NOW });
      fixture.state.grant = makeGrant(fixture.scenario, record.metadata, 'USE',
        { principal: { ...OTHER_WORKLOAD } });
    }
  } } });
  const result = await createBoundMappingUse(built.host).use();
  assert.equal(result.code, 'WITHHELD');
  assert.equal(built.backend.state.calls, 0);
  assert.equal(built.ledger.entries.length, 2);
});

/* ---------- 7. A stale key, a stale revision and a moved clock ---------- */

test('a rotated key, a stale revision and a moving clock each withhold before the resource', async () => {
  const staleKey = createHost({ materialKeyVersion: ROTATED_KEY_VERSION });
  const keyRefused = await createBoundMappingUse(staleKey.host).use();
  assert.equal(keyRefused.code, 'WITHHELD');
  assert.equal(staleKey.counters.material, 1);
  assert.equal(staleKey.backend.state.calls, 0);

  const rotatedMidFlight = createHost({ hooks: { onAuthority(count, fixture) {
    if (count === 2) fixture.state.keyVersion = ROTATED_KEY_VERSION;
  } } });
  const rotated = await createBoundMappingUse(rotatedMidFlight.host).use();
  assert.equal(rotated.code, 'WITHHELD');
  assert.equal(rotatedMidFlight.backend.state.calls, 0);

  const staleRevision = createHost({ materialRevision: '1' });
  const revisionRefused = await createBoundMappingUse(staleRevision.host).use();
  assert.equal(revisionRefused.code, 'WITHHELD');
  assert.equal(staleRevision.backend.state.calls, 0);

  const expiring = createHost({ hooks: { onAuthority(count, fixture) {
    if (count === 2) fixture.state.now = fixture.scenario.expiresAt;
  } } });
  const expired = await createBoundMappingUse(expiring.host).use();
  assert.equal(expired.code, 'WITHHELD');
  assert.equal(expiring.backend.state.calls, 0);

  const rolling = createHost({ hooks: { onAuthority(count, fixture) {
    if (count === 2) fixture.state.now = USE_NOW - 1;
  } } });
  const rolled = await createBoundMappingUse(rolling.host).use();
  assert.equal(rolled.code, 'WITHHELD');
  assert.equal(rolling.backend.state.calls, 0);
});

/* ---------- 8. Retargeting a method after capture cannot change what runs ---------- */

test('a method re-targeted after capture, and a host callback replaced after construction, are ignored', async () => {
  let originalCalls = 0;
  let retargetCalls = 0;
  const provisioned = new TextEncoder().encode(ORIGINAL);
  const matches = (identifier) => {
    let same = identifier.byteLength === provisioned.byteLength;
    for (let index = 0; index < provisioned.byteLength && same; index += 1) {
      same = identifier[index] === provisioned[index];
    }
    return same;
  };
  const original = (identifier) => { originalCalls += 1; return matches(identifier); };
  const retarget = () => { retargetCalls += 1; return true; };
  let reads = 0;
  const target = {
    get lookup() { reads += 1; return reads === 1 ? original : retarget; } };
  const built = createHost({ backend: target, hooks: { onMaterial(fixture) {
    // Re-pointing the method, and even the whole authority callback, once the call is in flight.
    fixture.host.backend = { lookup: retarget };
    fixture.host.authority = () => { throw new Error('synthetic host retarget'); };
  } } });
  const result = await createBoundMappingUse(built.host).use();
  assert.equal(result.code, 'USED');
  assert.equal(originalCalls, 1);
  assert.equal(retargetCalls, 0);
  assert.equal(reads, 1);

  // Contrast: a method re-targeted *before* the call is observed, so the capture is per use and the
  // assertion above is not vacuous.
  const replacement = createBackend();
  const swapped = createHost({ backend: replacement });
  assert.equal((await createBoundMappingUse(swapped.host).use()).code, 'USED');
  assert.equal(replacement.state.calls, 1);
});

test('the backend method bound at construction is the one spent, not a replacement installed after it',
  async () => {
    // The promise is a construction-time binding, so the replacement is installed on the same backend
    // object between construction and `use()`. A capture that re-read the property inside `use()`
    // would spend the recovered bytes on the replacement.
    const backend = createBackend();
    const built = createHost({ backend });
    const executor = createBoundMappingUse(built.host);
    let replacementCalls = 0;
    backend.lookup = (identifier) => { replacementCalls += 1; return true; };

    const result = await executor.use();
    assertFixedShape(result);
    assert.equal(result.code, 'USED');
    assert.equal(backend.state.calls, 1);
    assert.equal(replacementCalls, 0);
    assert.equal(cleared(backend.state.retained), true);
    assert.equal(built.ledger.entries.length, 2);
    assert.equal(built.counters.material, 1);

    // Non-vacuous contrast: the identical replacement, installed before its own construction, is what
    // a bound executor spends, so the assertions above are about the moment of binding and not about
    // a replacement that could never have run.
    const fresh = createBackend();
    const freshHost = createHost({ backend: fresh });
    fresh.lookup = (identifier) => { replacementCalls += 1; return true; };
    assert.equal((await createBoundMappingUse(freshHost.host).use()).code, 'USED');
    assert.equal(replacementCalls, 1);
    assert.equal(fresh.state.calls, 0);
  });

/* ---------- 9. Reentry and overlap are refused ---------- */

test('an overlapping use is refused before any host call, and one resource call is spent', async () => {
  // The same executor asked twice while the first call is unfinished: the second is refused
  // synchronously, before it captures a callback or reads a single host value.
  const race = createHost();
  const bounded = createBoundMappingUse(race.host);
  const first = bounded.use();
  const second = bounded.use();
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.code, 'USED');
  assertFixedShape(b);
  assert.equal(b.code, 'WITHHELD');
  assert.equal(race.counters.material, 1);
  assert.equal(race.backend.state.calls, 1);
  assert.equal(race.ledger.entries.length, 2);
  assert.equal(race.counters.authority, 4);
});

/* ---------- 10. A faulty resource is FAILED, and the bytes are still cleared ---------- */

test('a throwing resource reports FAILED, a non-boolean one withholds, and both clear the bytes', async () => {
  const throwing = createBackend({ behaviour: 'throw' });
  const thrown = await createBoundMappingUse(createHost({ backend: throwing }).host).use();
  assertFixedShape(thrown);
  assert.equal(thrown.code, 'FAILED');
  assert.equal(throwing.state.calls, 1);
  assert.equal(cleared(throwing.state.retained), true);

  // A backend that answers with anything but a primitive boolean never buys a USE claim.
  const nonBoolean = createBackend({ behaviour: 'non-boolean' });
  const malformed = await createBoundMappingUse(createHost({ backend: nonBoolean }).host).use();
  assert.equal(malformed.code, 'WITHHELD');
  assert.equal(nonBoolean.state.calls, 1);
  assert.equal(cleared(nonBoolean.state.retained), true);
});

/* ---------- 11. An unusable host is refused at construction, with no value echoed ---------- */

test('an unusable host throws one fixed TypeError at construction', async () => {
  const built = createHost();
  for (const broken of [null, 'bound-use.invalid', 42, {}, { ...built.host, registry: {} },
    { ...built.host, authority: 'nope' }, { ...built.host, material: 'nope' },
    { ...built.host, backend: {} }, { ...built.host, backend: { lookup: 'nope' } },
    { ...built.host, entityId: 'not a token' }, { ...built.host, scope: { ...SCOPE, tenantId: '' } }]) {
    assert.throws(() => createBoundMappingUse(broken), (error) => {
      assert.equal(error instanceof TypeError, true);
      assert.equal(error.message, 'Invalid mapping use host');
      return true;
    });
  }
  // A backend with no callable `lookup` is refused here, at construction, where its method is bound:
  // an executor that captured a missing method per call would have deferred that refusal into a
  // `use()` this file could no longer describe as a construction failure.
  const noMethod = createHost({ backend: {} });
  assert.throws(() => createBoundMappingUse(noMethod.host), TypeError);
  assert.equal(noMethod.counters.authority, 0);
  assert.equal(noMethod.counters.material, 0);
});

/* ---------- 12. The audit record is privacy-safe and the ledger is the real one ---------- */

test('the recorded evidence carries pseudonyms and codes, never the recovered identifier', async () => {
  const built = createHost();
  const result = await createBoundMappingUse(built.host).use();
  assert.equal(result.code, 'USED');
  const image = JSON.stringify(built.ledger.entries);
  assert.equal(image.includes(ORIGINAL), false);
  assert.equal(image.includes(built.scenario.mappingRef), false);
  assert.equal(image.includes(FOREIGN_HANDLE), false);
  assert.equal(built.ledger.entries[1].event.kind, 'POLICY_DECISION');
  assert.equal(built.ledger.entries[1].event.decision.treatment, 'KEEP');
  // The append is the real one: a hand-built equivalent draft still names the same fixed codes.
  const manual = appendAuditEvent(built.ledger, { version: AUDIT_SCHEMA_VERSION,
    kind: 'AUTHORIZATION_ATTEMPT', operation: 'USE', outcome: 'DENIED',
    reason: 'RESOLUTION_DENIED', occurredAt: OCCURRED_AT,
    bundle: { policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(built.bundle) },
      components: [{ id: 'AUTHORIZATION_POLICY', version: '1' }] },
    correlationRef: built.scenario.mappingRef, entityRef: built.scenario.mappingRef },
    built.auditContext);
  assert.equal(manual.status, 'RECORDED');
  assert.equal(built.ledger.entries.length, 3);
});

/* ---------- 13. The recorded identity is owned, not read live from the host ---------- */

test('an audit actor swapped during the material callback withholds before anything is recorded',
  async () => {
    // Positive control on the identical scenario: the congruent actor records both decisions.
    const control = createHost();
    assert.equal((await createBoundMappingUse(control.host).use()).code, 'USED');
    assert.equal(control.ledger.entries.length, 2);

    // The material callback re-points the trusted context's actor at another workload. The recorded
    // decisions belong to this executor's reference, so an identity that changes in flight is a
    // refusal, not a decision recorded under somebody else.
    const swapped = createHost({ hooks: { onMaterial(fixture) {
      fixture.auditContext.actor = { principalId: OTHER_WORKLOAD.principalId,
        workloadId: OTHER_WORKLOAD.workloadId };
    } } });
    const afterSwap = await createBoundMappingUse(swapped.host).use();
    assertFixedShape(afterSwap);
    assert.equal(afterSwap.code, 'WITHHELD');
    assert.equal(swapped.counters.material, 1);
    assert.equal(swapped.backend.state.calls, 0);
    // Nothing was written under either identity: the append is never handed the drifted actor.
    assert.equal(swapped.ledger.entries.length, 0);
    assert.equal(cleared(swapped.backend.state.retained), false);

    // The same swap after the first decision is recorded: the one entry that exists was written from
    // the captured identity, the second is never written, and the resource is never spent.
    const late = createHost({ hooks: { onAuthority(count, fixture) {
      if (count === 3) {
        fixture.auditContext.actor = { principalId: OTHER_WORKLOAD.principalId,
          workloadId: OTHER_WORKLOAD.workloadId };
      }
    } } });
    const afterLateSwap = await createBoundMappingUse(late.host).use();
    assert.equal(afterLateSwap.code, 'WITHHELD');
    assert.equal(late.backend.state.calls, 0);
    assert.equal(late.ledger.entries.length, 1);
    assert.equal(late.ledger.entries[0].event.kind, 'AUTHORIZATION_ATTEMPT');
  });

/* ---------- 14. The sealed effect segment consults nothing of the host's ---------- */

test('the effect segment resolves no mutable function property and re-reads no classification',
  async () => {
    // A captured backend method whose own `call` property is trapped. An effect segment that
    // resolved `.call` would run the trap and never touch the resource; invoking the captured
    // function on its captured receiver cannot reach the trap at all.
    const provisioned = new TextEncoder().encode(ORIGINAL);
    let realCalls = 0;
    let trappedCalls = 0;
    const genuine = function (identifier) {
      realCalls += 1;
      let same = identifier.byteLength === provisioned.byteLength;
      for (let index = 0; index < provisioned.byteLength && same; index += 1) {
        same = identifier[index] === provisioned[index];
      }
      return same;
    };
    const trap = () => { trappedCalls += 1; return true; };
    const backend = { lookup: new Proxy(genuine, { get(target, property, receiver) {
      if (property === 'call' || property === 'apply') { trappedCalls += 1; return trap; }
      return Reflect.get(target, property, receiver);
    } }) };
    const built = createHost({ backend });
    const result = await createBoundMappingUse(built.host).use();
    // Ordering first: the backend saw the recovered bytes at all, so the segment ran, and it ran
    // without resolving `call` or `apply` on the captured function.
    assert.equal(trappedCalls, 0);
    assert.equal(result.code, 'USED');
    assert.equal(realCalls, 1);

    // Two hosts whose only difference is that one reached the effect and the other was refused at
    // its final policy decision. Reaching the effect reads nothing further from the host's own
    // classification object, so the two read it exactly as often - one read apart would mean the
    // sealed segment consulted it.
    const counting = () => {
      const counter = { reads: 0 };
      const classification = new Proxy(EVIDENCE, { get(target, property, receiver) {
        if (property === 'semanticType') counter.reads += 1;
        return Reflect.get(target, property, receiver);
      } });
      return { counter, classification };
    };
    const served = counting();
    const servedHost = createHost({ classification: served.classification });
    const servedResult = await createBoundMappingUse(servedHost.host).use();
    assert.equal(servedResult.code, 'USED');
    const refused = counting();
    const refusedHost = createHost({ classification: refused.classification,
      hooks: { onAuthority(count, fixture) {
        if (count === 4) fixture.bundle.rules[0].decision = 'BLOCK';
      } } });
    const refusedResult = await createBoundMappingUse(refusedHost.host).use();
    assert.equal(refusedResult.code, 'WITHHELD');
    assert.equal(refusedHost.backend.state.calls, 0);
    // Like for like: both runs made every observation and recorded both decisions, and the only
    // difference is the effect segment one of them entered.
    assert.equal(servedHost.counters.authority, refusedHost.counters.authority);
    assert.equal(servedHost.ledger.entries.length, refusedHost.ledger.entries.length);
    assert.equal(served.counter.reads > 0, true);
    assert.equal(served.counter.reads, refused.counter.reads);

    // A classification that drifts after the material load is refused before the resource, while the
    // registry record is still ACTIVE: nothing is withdrawn, the pinned digest simply no longer
    // describes what the policy engine was handed, so this is digest congruence and not lifecycle.
    // The drifted record is a real composed v1 record carrying its own consistent detector evidence,
    // so this case cannot be passing because the record became structurally invalid.
    const drifted = { ...EVIDENCE };
    const driftedHost = createHost({ classification: drifted,
      hooks: { onMaterial() { Object.assign(drifted, EVIDENCE_WITH_SUBTYPE); } } });
    const afterDrift = await createBoundMappingUse(driftedHost.host).use();
    assert.equal(afterDrift.code, 'WITHHELD');
    assert.equal(driftedHost.backend.state.calls, 0);
    assert.equal(driftedHost.counters.material, 1);
    assert.equal(driftedHost.ledger.entries.length, 0);
    // What the engine was finally handed is exactly the record the positive control accepts.
    assert.equal(digestClassification(drifted), digestClassification(EVIDENCE_WITH_SUBTYPE));
    const stillActive = driftedHost.scenario.registry.current({ version: 1,
      mappingRef: driftedHost.scenario.mappingRef, scope: { ...driftedHost.scenario.scope } },
      { now: USE_NOW });
    assert.equal(stillActive.metadata.state, 'ACTIVE');

    // The same changed record, pinned from the start against the original digest and nothing else
    // different: also WITHHELD, and refused at the first policy selection, before any material is
    // loaded. The only variable left is the pin.
    const stalePin = createHost({ classification: EVIDENCE_WITH_SUBTYPE,
      classificationDigest: digestClassification(EVIDENCE) });
    const afterStalePin = await createBoundMappingUse(stalePin.host).use();
    assert.equal(afterStalePin.code, 'WITHHELD');
    assert.equal(stalePin.counters.material, 0);
    assert.equal(stalePin.backend.state.calls, 0);
    assert.equal(stalePin.ledger.entries.length, 0);

    // Positive control on that exact record with its matching pin: a real SELECTED/KEEP decision and
    // a real spend. The refusal above is therefore attributable to the pinned digest and to nothing
    // else - not to the changed record, not to the bundle and not to the lifecycle.
    const matchedPin = createHost({ classification: EVIDENCE_WITH_SUBTYPE,
      classificationDigest: digestClassification(EVIDENCE_WITH_SUBTYPE) });
    const afterMatchedPin = await createBoundMappingUse(matchedPin.host).use();
    assertFixedShape(afterMatchedPin);
    assert.equal(afterMatchedPin.code, 'USED');
    assert.equal(matchedPin.backend.state.calls, 1);
    assert.equal(matchedPin.ledger.entries.length, 2);
    assert.equal(matchedPin.ledger.entries[1].event.decision.treatment, 'KEEP');
    assert.equal(cleared(matchedPin.backend.state.retained), true);
  });

test('the final observation swaps in a reflection-faulting actor and withholds before any effect',
  async () => {
    // Control on the identical timing: the fourth observation replaces the live audit actor with a
    // congruent plain object, and the run still spends. Only the reflection fault below changes, so
    // the refusal afterwards cannot be attributed to the rewrite itself or to that observation.
    const congruent = createHost({ hooks: { onAuthority(count, fixture) {
      if (count === 4) fixture.auditContext.actor = { principalId: WORKLOAD.principalId,
        workloadId: WORKLOAD.workloadId };
    } } });
    const congruentResult = await createBoundMappingUse(congruent.host).use();
    assertFixedShape(congruentResult);
    assert.equal(congruent.counters.authority, 4);
    assert.equal(congruentResult.code, 'USED');
    assert.equal(congruent.backend.state.calls, 1);
    assert.equal(congruent.ledger.entries.length, 2);
    assert.equal(cleared(congruent.backend.state.retained), true);

    // The same replacement with an actor whose own key enumeration throws. The final guard re-reads
    // the live actor inside the sealed segment, so this reflection fault is raised after the last
    // awaited answer and after the material load. It is a guard, so it is one `WITHHELD` like any
    // other refusal: `FAILED` is reserved for an effect that was really invoked and threw.
    const trapped = createHost({ hooks: { onAuthority(count, fixture) {
      if (count === 4) fixture.auditContext.actor = new Proxy(
        { principalId: WORKLOAD.principalId, workloadId: WORKLOAD.workloadId },
        { ownKeys() { throw new Error('synthetic actor reflection fault'); } });
    } } });
    const result = await createBoundMappingUse(trapped.host).use();
    assertFixedShape(result);
    assert.equal(trapped.counters.authority, 4);
    assert.equal(result.code, 'WITHHELD');
    // Zero opener and backend effects. The backend is the only route past the opener this file can
    // observe, and it is never called, so no recovered identifier was ever handed to the resource.
    assert.equal(trapped.backend.state.calls, 0);
    assert.equal(cleared(trapped.backend.state.retained), false);
    // The run reached the final observation, so both decisions were already recorded from the
    // captured identity; the faulting actor is never handed to the append.
    assert.equal(trapped.counters.material, 1);
    assert.equal(trapped.ledger.entries.length, 2);
    assert.equal(trapped.ledger.entries[0].event.kind, 'AUTHORIZATION_ATTEMPT');
    assert.equal(trapped.ledger.entries[1].event.kind, 'POLICY_DECISION');
  });

test('an effect is spent only while the registry record is still ACTIVE at the backend', async () => {
  // The actual gap control, and the cheap way to see it. The live audit actor is the last host-owned
  // read before the fresh registry read, so a host that queues one finite revocation from it queues
  // that revocation inside the sealed segment itself. The resource probes the shipped registry at
  // the instant it is really called, so a spend against stale state is observed, not inferred.
  const control = { armed: false, queued: false, revoke: () => {} };
  const auditContext = { version: AUDIT_SCHEMA_VERSION,
    scope: { tenantId: SCOPE.tenantId, projectId: SCOPE.projectId },
    integrationId: 'integration-bound-use-fixture.invalid',
    actorBinding: 'AUTHENTICATED_UPSTREAM', pseudonymKey: keyBytes(0x33), chainKey: keyBytes(0x77) };
  Object.defineProperty(auditContext, 'actor', { enumerable: true, configurable: true, get() {
    if (control.armed && !control.queued) {
      control.queued = true;
      queueMicrotask(() => { control.revoke(); });
    }
    return { principalId: WORKLOAD.principalId, workloadId: WORKLOAD.workloadId };
  } });
  let built;
  const backend = createBackend({ probe() {
    const found = built.scenario.registry.current({ version: 1,
      mappingRef: built.scenario.mappingRef, scope: { ...built.scenario.scope } }, { now: USE_NOW });
    return found.state === 'FOUND' ? found.metadata.state : found.state;
  } });
  built = createHost({ backend, auditContext, hooks: { onAuthority(count, fixture) {
    // The fourth observation is the last answer this call awaits: the final guard and the effect are
    // what happens next, in the continuation that reads it.
    if (count >= 4) control.armed = true;
    control.revoke = () => {
      const applied = fixture.host.registry.transition({ version: 1,
        mappingRef: fixture.host.mappingRef, scope: { ...fixture.host.scope },
        expectedRevision: 2, action: 'REVOKE' }, { now: USE_NOW });
      assert.equal(applied.state, 'CHANGED');
    };
  } } });
  const result = await createBoundMappingUse(built.host).use();
  assertFixedShape(result);
  assert.equal(built.counters.authority, 4);
  assert.equal(result.code, 'USED');
  assert.equal(backend.state.calls, 1);
  // The only spend this case allows is one made against a record the registry still calls ACTIVE.
  assert.equal(backend.state.probed, 'ACTIVE');
  assert.equal(cleared(backend.state.retained), true);
  // The queued revocation really was finite and really landed; it landed after the sealed effect was
  // already complete, and a revocation that lands then is not expected to cancel it retroactively.
  assert.equal(control.queued, true);
  await new Promise((resolve) => { setImmediate(resolve); });
  const afterwards = built.scenario.registry.current({ version: 1,
    mappingRef: built.scenario.mappingRef, scope: { ...built.scenario.scope } }, { now: USE_NOW });
  // A revoked record is no longer live, so the shipped registry stops reporting it as the current
  // one at all: the queued revocation really landed, just not inside the effect.
  assert.equal(afterwards.state, 'ABSENT');
  assert.equal(afterwards.reason, 'NOT_LIVE');
});

/* ---------- 15. Host callbacks keep their own receiver and may answer asynchronously ---------- */

test('a host method runs on its own receiver, and a promised answer is awaited before it is read',
  async () => {
    // Both host callbacks read their own receiver's bound scope and entity id, so an invocation that
    // drops the receiver cannot answer at all.
    const bound = createHost({ receiverDependent: true, backend: createBackend({ bound: true }) });
    const boundResult = await createBoundMappingUse(bound.host).use();
    assertFixedShape(boundResult);
    assert.equal(boundResult.code, 'USED');
    assert.equal(bound.counters.authority, 4);
    assert.equal(bound.counters.material, 1);
    assert.equal(bound.backend.state.calls, 1);
    assert.equal(bound.ledger.entries.length, 2);

    // A host that answers each observation with a promise settles every one of them inside the call,
    // before the material is loaded and long before any byte is spent.
    const promised = createHost({ asyncAuthority: 'resolve' });
    const promisedResult = await createBoundMappingUse(promised.host).use();
    assertFixedShape(promisedResult);
    assert.equal(promisedResult.code, 'USED');
    assert.equal(promised.counters.authority, 4);
    assert.equal(promised.counters.material, 1);
    assert.equal(promised.backend.state.calls, 1);
    assert.equal(promised.ledger.entries.length, 2);
    assert.deepEqual(promised.order.slice(0, 2), ['authority:start', 'authority:settled']);
    assert.equal(promised.order.length, 9);
    assert.equal(promised.order.indexOf('material') > 1, true);
    assert.equal(promised.order.lastIndexOf('authority:settled') > promised.order.indexOf('material'),
      true);

    // A rejected promise is one refusal like any other: no material, no record, no effect, and
    // nothing of it survives the call that awaited it.
    const refused = createHost({ asyncAuthority: 'reject' });
    const refusedResult = await createBoundMappingUse(refused.host).use();
    assert.equal(refusedResult.code, 'WITHHELD');
    assert.equal(refused.counters.material, 0);
    assert.equal(refused.backend.state.calls, 0);
    assert.equal(refused.ledger.entries.length, 0);
  });

/* ---------- 16. Exceptional paths before the effect are refusals, not reached effects ---------- */

test('a byte source that throws mid-copy, and a host fault before the effect, both withhold',
  async () => {
    const torn = createHost({ interruptedCiphertext: true });
    const tornResult = await createBoundMappingUse(torn.host).use();
    assertFixedShape(tornResult);
    // An index read that throws part-way through a copy never reaches the resource and is never
    // reported as a reached effect: the interruption is a refusal, and the copied bytes it left
    // behind are this module's own to overwrite.
    assert.equal(tornResult.code, 'WITHHELD');
    assert.equal(torn.counters.material, 1);
    assert.equal(torn.backend.state.calls, 0);
    assert.equal(torn.ledger.entries.length, 0);
    assert.equal(cleared(torn.backend.state.retained), false);
    // The copy really was interrupted: the fault index was reached, not refused before allocation.
    assert.equal(torn.interrupted.reached, true);
    assert.equal(torn.interrupted.reads, torn.interrupted.faultAt + 1);
    // The host's own buffers belong to the host: this module overwrites only what it copied.
    assert.notEqual(torn.source[0], 0);

    const faulting = createHost({ authority: () => { throw new Error('synthetic host fault'); } });
    const faulted = await createBoundMappingUse(faulting.host).use();
    assert.equal(faulted.code, 'WITHHELD');
    assert.equal(faulting.counters.material, 0);
    assert.equal(faulting.backend.state.calls, 0);
    assert.equal(faulting.ledger.entries.length, 0);
  });

test('an invocation that faults inside the reached effect segment is FAILED and clears the bytes',
  async () => {
    const trapped = createBackend({ applyFault: true });
    const result = await createBoundMappingUse(createHost({ backend: trapped }).host).use();
    assertFixedShape(result);
    assert.equal(result.code, 'FAILED');
    assert.equal(trapped.state.calls, 0);
  });

/* ---------- 17. An attributable refusal leaves evidence; every other one leaves none ---------- */

/**
 * The fixed evidence of a refusal this file asserts, read the way an auditor reads it: the two fixed
 * codes, the established actor, the bound scope, the pinned bundle identity and the instant. Nothing
 * else is in there - no reference, no identifier, no original and no exception text.
 */
function assertAttributableDenial(built, event, reason) {
  assert.equal(event.kind, 'AUTHORIZATION_ATTEMPT');
  assert.equal(event.operation, 'USE');
  assert.equal(event.outcome, 'DENIED');
  assert.equal(event.reason, reason);
  assert.equal(event.occurredAt, OCCURRED_AT);
  assert.deepEqual(event.actor, { integrationId: built.auditContext.integrationId,
    actorBinding: 'AUTHENTICATED_UPSTREAM', principalId: WORKLOAD.principalId,
    workloadId: WORKLOAD.workloadId });
  assert.deepEqual(event.scope, { tenantId: SCOPE.tenantId, projectId: SCOPE.projectId });
  assert.equal(event.classification.semanticType, CLASS);
  assert.equal(event.classification.sensitivity, SENSITIVITY);
  const image = JSON.stringify(built.ledger.entries);
  assert.equal(image.includes(ORIGINAL), false);
  assert.equal(image.includes(FOREIGN_HANDLE), false);
  assert.equal(image.includes(built.scenario.mappingRef), false);
  assert.equal(image.includes(OTHER_WORKLOAD.principalId), false);
  assert.equal(verifyAuditStream(built.ledger, built.auditContext, []).status, 'UNANCHORED');
}

test('a missing or expired grant and a revoked mapping each record one attributable DENIED decision',
  async () => {
    // The accepted path is the control for every assertion below: the same host, the same actor and
    // the same ledger still record exactly two ALLOWED decisions, spend the private resource once and
    // never record a denial.
    const control = createHost();
    const accepted = await createBoundMappingUse(control.host).use();
    assert.equal(accepted.code, 'USED');
    assert.equal(control.ledger.entries.length, 2);
    assert.equal(control.ledger.entries.every((entry) => entry.event.outcome === 'ALLOWED'), true);
    assert.equal(control.ledger.entries.some((entry) => entry.event.outcome === 'DENIED'), false);

    const scenario = buildScenario();
    const record = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
      scope: { ...scenario.scope } }, { now: USE_NOW }).metadata;
    // Both refusals are answered by the real purpose-bound seam under an authenticated, in-scope
    // actor, so both are attributable and both are recorded before anything is loaded or spent.
    const grantCases = [
      ['no grant at all', undefined],
      ['a grant that has already expired', makeGrant(scenario, record, 'USE',
        { expiresAt: T0 + 30_000 })],
    ];
    for (const [name, grant] of grantCases) {
      const backend = createBackend();
      const built = createHost({ scenario, grant, backend });
      const refused = await createBoundMappingUse(built.host).use();
      assertFixedShape(refused);
      assert.equal(refused.code, 'WITHHELD', name);
      // The evidence costs no sealed read and spends no identifier: this refusal is recorded with the
      // material untouched and the private resource never called.
      assert.equal(built.counters.material, 0, name);
      assert.equal(backend.state.calls, 0, name);
      assert.equal(cleared(backend.state.retained), false, name);
      assert.equal(built.ledger.entries.length, 1, name);
      assertAttributableDenial(built, built.ledger.entries[0].event, 'RESOLUTION_DENIED');
      // Sequential reuse is not cached evidence: a second refused call records its own decision.
      assert.equal((await createBoundMappingUse(built.host).use()).code, 'WITHHELD', name);
      assert.equal(built.ledger.entries.length, 2, name);
      assert.equal(built.ledger.entries[1].event.reason, 'RESOLUTION_DENIED', name);
      assert.equal(built.backend.state.calls, 0, name);
    }

    // A revoked mapping is refused by the real registry, which stops reporting the record as current,
    // and the refusal is recorded under the same established actor with the lifecycle class.
    const revokedScenario = buildScenario();
    const revokedBackend = createBackend();
    const revoked = createHost({ scenario: revokedScenario, backend: revokedBackend });
    const revokedRecord = revokedScenario.registry.current({ version: 1,
      mappingRef: revokedScenario.mappingRef, scope: { ...revokedScenario.scope } },
      { now: USE_NOW }).metadata;
    const applied = revokedScenario.registry.transition({ version: 1,
      mappingRef: revokedScenario.mappingRef, scope: { ...revokedScenario.scope },
      expectedRevision: revokedRecord.revision, action: 'REVOKE' }, { now: USE_NOW });
    assert.equal(applied.state, 'CHANGED');
    const afterRevocation = await createBoundMappingUse(revoked.host).use();
    assertFixedShape(afterRevocation);
    assert.equal(afterRevocation.code, 'WITHHELD');
    assert.equal(revoked.counters.material, 0);
    assert.equal(revokedBackend.state.calls, 0);
    assert.equal(cleared(revokedBackend.state.retained), false);
    assert.equal(revoked.ledger.entries.length, 1);
    assertAttributableDenial(revoked, revoked.ledger.entries[0].event, 'LIFECYCLE_DENIED');
    // The recorded class is the lifecycle gate, and it names no lifecycle value the registry answer
    // did not: the record is not live, which is exactly what the real registry reported.
    assert.equal(applied.metadata.state, 'REVOKED');
  });

test('a foreign scope, a foreign audit actor and a ledger that cannot commit record nothing', async () => {
  const scenario = buildScenario();
  const record = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope } }, { now: USE_NOW }).metadata;
  const expired = makeGrant(scenario, record, 'USE', { expiresAt: T0 + 30_000 });

  // A foreign scope is refused before anything is known about the actor, so nothing is written for a
  // tenant this call was never bound to: the record would be foreign-tenant evidence.
  const foreignBackend = createBackend();
  const foreign = createHost({ scenario, grant: expired, backend: foreignBackend,
    authority: () => ({ version: 1, subject: { ...WORKLOAD },
      context: { ...FOREIGN_SCOPE, purpose: PURPOSE }, destination: { ...DESTINATION },
      keyVersion: KEY_VERSION, now: USE_NOW, grant: { ...expired } }) });
  const refusedScope = await createBoundMappingUse(foreign.host).use();
  assert.equal(refusedScope.code, 'WITHHELD');
  assert.equal(foreign.counters.material, 0);
  assert.equal(foreignBackend.state.calls, 0);
  assert.equal(foreign.ledger.entries.length, 0);
  assert.equal(JSON.stringify(foreign.ledger.entries).includes(FOREIGN_SCOPE.tenantId), false);

  // A trusted context whose actor is somebody else is refused before the registry and the grant are
  // read, so an attributable-looking refusal can never be filed under a substituted identity.
  const foreignActor = createHost({ scenario, grant: expired, auditContext: { version: AUDIT_SCHEMA_VERSION,
    scope: { tenantId: SCOPE.tenantId, projectId: SCOPE.projectId },
    actor: { principalId: OTHER_WORKLOAD.principalId, workloadId: OTHER_WORKLOAD.workloadId },
    integrationId: 'integration-bound-use-fixture.invalid', actorBinding: 'AUTHENTICATED_UPSTREAM',
    pseudonymKey: keyBytes(0x33), chainKey: keyBytes(0x77) } });
  const refusedActor = await createBoundMappingUse(foreignActor.host).use();
  assert.equal(refusedActor.code, 'WITHHELD');
  assert.equal(foreignActor.counters.material, 0);
  assert.equal(foreignActor.backend.state.calls, 0);
  assert.equal(foreignActor.ledger.entries.length, 0);

  // A ledger that cannot commit is an audit outage, not an exception: the refusal is still
  // `WITHHELD`, the code is unchanged, and no material or resource call follows the failed append.
  const outage = createHost({ scenario, grant: expired });
  outage.ledger.accepting = false;
  const duringOutage = await createBoundMappingUse(outage.host).use();
  assertFixedShape(duringOutage);
  assert.equal(duringOutage.code, 'WITHHELD');
  assert.equal(outage.ledger.entries.length, 0);
  assert.equal(outage.counters.material, 0);
  assert.equal(outage.backend.state.calls, 0);

  // The same refusal against the same scenario with a committing substrate records its evidence, so
  // the outage above is what withheld the record and not a scenario that never records one.
  const control = createHost({ scenario, grant: expired });
  assert.equal((await createBoundMappingUse(control.host).use()).code, 'WITHHELD');
  assert.equal(control.ledger.entries.length, 1);
  assert.equal(control.ledger.entries[0].event.reason, 'RESOLUTION_DENIED');
});

test('an accepted run records no denial, and a real BLOCK records none either', async () => {
  // The success path is unchanged by refusal evidence: two ALLOWED records, one private effect, no
  // DENIED entry anywhere in the stream.
  const accepted = createHost();
  assert.equal((await createBoundMappingUse(accepted.host).use()).code, 'USED');
  assert.equal(accepted.ledger.entries.length, 2);
  assert.equal(accepted.ledger.entries.every((entry) => entry.event.outcome === 'ALLOWED'), true);
  assert.equal(accepted.backend.state.calls, 1);
  assert.equal(cleared(accepted.backend.state.retained), true);

  // A policy `BLOCK` is refused before the registry and the grant are read, so it records nothing: the
  // evidence this executor owns describes the authorization and lifecycle gate, not the Policy Engine.
  const blocked = createHost({ bundle: policyBundle('BLOCK') });
  assert.equal((await createBoundMappingUse(blocked.host).use()).code, 'WITHHELD');
  assert.equal(blocked.ledger.entries.length, 0);
  assert.equal(blocked.counters.material, 0);
  assert.equal(blocked.backend.state.calls, 0);
});