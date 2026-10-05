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
function buildScenario({ scope = SCOPE, keyFill = 0x11, activate = true } = {}) {
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
  // `activate: false` leaves the real record at `CREATED`: the shipped registry still calls that
  // live and reports it as the current record, so it is the one genuine in-bound `FOUND` answer
  // whose metadata is not `ACTIVE`.
  let revision = 1;
  if (activate) {
    const activated = registry.transition({ version: 1, mappingRef, scope: { ...scope },
      expectedRevision: 1, action: 'ACTIVATE' }, { now: T0 + 1_500 });
    assert.equal(activated.state, 'CHANGED');
    assert.equal(activated.metadata.revision, 2);
    revision = 2;
  }
  const seal = (at) => sealMappingPayload({ scope: aadScope(scope, at),
    plaintext: ORIGINAL_BYTES, key: keyBytes(keyFill) });
  const sealed = seal(revision);
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
/**
 * Whole-buffer survival as one boolean: equal length and every index equal. The answer is a boolean
 * and never a byte, so no planted value is ever an assertion operand here, and a run that overwrote
 * exactly one byte cannot pass a length-only check.
 */
function unchanged(before, after) {
  if (before.byteLength !== after.byteLength) return false;
  for (let index = 0; index < before.byteLength; index += 1) {
    if (before[index] !== after[index]) return false;
  }
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
    registry: options.registry ?? scenario.registry,
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

test('the authorization reads an owned grant snapshot, never the host object behind it', async () => {
  // The host hands over a shallow copy whose nested grant records it still shares, and then edits
  // one of those shared records from inside a synchronous registry callback - after this call has
  // already normalized the answer and before the authorization reads it. The decision must be taken
  // on the snapshot this executor owns, so the run still spends; a reader that carried the host's
  // nested records by reference would see the foreign purpose and refuse.
  const FOREIGN_PURPOSE = 'other-bound-use.invalid';
  const built = createHost({ hooks: { onAuthority(count, fixture) {
    // The next observation is genuine again, so the only difference under test is the mid-call edit.
    if (count === 2) fixture.state.grant.context.purpose = PURPOSE;
  } } });
  const real = built.scenario.registry;
  let edited = false;
  built.host.registry = Object.freeze({ version: 1, current(request, clock) {
    if (!edited) {
      edited = true;
      built.state.grant.context.purpose = FOREIGN_PURPOSE;
    }
    return real.current(request, clock);
  } });
  assert.equal((await createBoundMappingUse(createHost({}).host).use()).code, 'USED');
  const result = await createBoundMappingUse(built.host).use();
  assertFixedShape(result);
  assert.equal(result.code, 'USED');
  assert.equal(edited, true);
  assert.equal(built.backend.state.calls, 1);
  assert.equal(built.counters.material, 1);
  assert.equal(built.ledger.entries.length, 2);
  assert.equal(built.ledger.entries.every((entry) => entry.event.outcome === 'ALLOWED'), true);

  // The control: the same edit, made before the answer is built, is a genuine misbound authority and
  // withholds with no effect and no evidence. Without an owned snapshot the run above would be here.
  const bound = createHost({ hooks: { onAuthority(count, fixture) {
    fixture.state.grant.context.purpose = FOREIGN_PURPOSE;
  } } });
  const refused = await createBoundMappingUse(bound.host).use();
  assert.equal(refused.code, 'WITHHELD');
  assert.equal(bound.counters.material, 0);
  assert.equal(bound.backend.state.calls, 0);
  assert.equal(bound.ledger.entries.length, 0);
  assert.equal(cleared(bound.backend.state.retained), false);
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
    // The host's own ciphertext is the host's to choose and this path never opens it: the copy is
    // interrupted before the AEAD seam is reached at all. Its first byte is therefore fixed to zero
    // here, deterministically, so the survival assertion below can never rest on a random byte that
    // AES-GCM happened not to leave as zero - a valid ciphertext that begins with one is a normal
    // outcome, and sampling one byte is not a proof that the host's buffer came back untouched.
    const torn = createHost({ interruptedCiphertext: true });
    torn.source[0] = 0;
    const before = Uint8Array.from(torn.source);
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
    // The host's own buffers belong to the host: this module overwrites only what it copied, so the
    // whole source comes back byte-identical - asserted as one boolean over the length and every
    // index, never as a dump and never as one sampled byte.
    assert.equal(unchanged(before, torn.source), true);
    // Non-vacuity of that comparison: the same buffer with one non-leading byte changed is not
    // unchanged, so the assertion above is about this executor's overwrite and not about a helper
    // that answers `true` for anything at all.
    assert.equal(before.byteLength > 1, true);
    const altered = Uint8Array.from(before);
    altered[1] = (altered[1] + 1) & 0xff;
    assert.equal(unchanged(before, altered), false);

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

/* ---------- 18. Every append is bound to this call's own stream ---------- */

/**
 * A genuine tenant-B substrate: the shipped ledger over the foreign tenant/project, and a trusted
 * context over that same foreign scope with this call's actor and its own keys. Nothing here mocks
 * the append - `appendAuditEvent` really records into this stream, which is precisely why the
 * executor has to refuse to hand it a decision it did not establish inside tenant B.
 */
function foreignSubstrate() {
  return { ledger: createInMemoryAuditLedger({ tenantId: FOREIGN_SCOPE.tenantId,
    projectId: FOREIGN_SCOPE.projectId }),
    auditContext: { version: AUDIT_SCHEMA_VERSION,
      scope: { tenantId: FOREIGN_SCOPE.tenantId, projectId: FOREIGN_SCOPE.projectId },
      actor: { principalId: WORKLOAD.principalId, workloadId: WORKLOAD.workloadId },
      integrationId: 'integration-bound-use-fixture.invalid',
      actorBinding: 'AUTHENTICATED_UPSTREAM', pseudonymKey: keyBytes(0x33), chainKey: keyBytes(0x77) } };
}

test('an audit substrate outside the bound scope records neither decision on either path', async () => {
  // The accepted path is the control: the same host with its own stream records exactly two ALLOWED
  // decisions, loads the material once and spends the private resource once.
  const control = createHost();
  assert.equal((await createBoundMappingUse(control.host).use()).code, 'USED');
  assert.equal(control.ledger.entries.length, 2);
  assert.equal(control.counters.material, 1);
  assert.equal(control.backend.state.calls, 1);

  // The genuine tenant-A host - tenant-A registry, authority, scope and actor - with tenant B's
  // genuine ledger and a matching tenant-B context. Every earlier guard passes, so both appends
  // would really commit and the pseudonyms in them would be tenant B's.
  const cases = [
    ['the ALLOWED path', {}],
    ['the DENIED path', { grant: undefined }]];
  for (const [name, grantOptions] of cases) {
    const backend = createBackend();
    const substrate = foreignSubstrate();
    const built = createHost({ backend, ...grantOptions, ...substrate });
    const refused = await createBoundMappingUse(built.host).use();
    assertFixedShape(refused);
    assert.equal(refused.code, 'WITHHELD', name);
    // Zero entries, zero material and zero backend calls: the mismatch is caught before the guarded
    // effect exists, and not one decision of this call lands in another tenant's stream.
    assert.equal(built.ledger.entries.length, 0, name);
    assert.equal(built.counters.material, 0, name);
    assert.equal(backend.state.calls, 0, name);
    assert.equal(cleared(backend.state.retained), false, name);
    assert.equal(JSON.stringify(built.ledger.entries).includes(FOREIGN_SCOPE.tenantId), false, name);
  }

  // The foreign stream is genuinely usable, so the zero entries above are this executor's congruence
  // refusal and not a ledger that could not have committed one.
  const probe = foreignSubstrate();
  const recorded = appendAuditEvent(probe.ledger, { version: AUDIT_SCHEMA_VERSION,
    kind: 'AUTHORIZATION_ATTEMPT', operation: 'USE', outcome: 'DENIED',
    reason: 'RESOLUTION_DENIED', occurredAt: OCCURRED_AT,
    bundle: { policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(control.bundle) },
      components: [{ id: 'AUTHORIZATION_POLICY', version: '1' }] },
    correlationRef: control.scenario.mappingRef, entityRef: control.scenario.mappingRef },
    probe.auditContext);
  assert.equal(recorded.status, 'RECORDED');
  assert.deepEqual(probe.ledger.entries[0].event.scope,
    { tenantId: FOREIGN_SCOPE.tenantId, projectId: FOREIGN_SCOPE.projectId });
});

/* ---------- 19. Lifecycle evidence needs a validated record in the bound scope ---------- */

/**
 * The shipped registry, its real scope query and its real lifecycle reducer, answering with a
 * different record than the one it holds. The read is not mocked - only the metadata the host hands
 * back is replaced, which is what an unauthenticated host is free to do.
 */
function rewrittenRegistry(scenario, rewrite) {
  const real = scenario.registry;
  const seen = { last: undefined };
  return { registry: { version: 1, current(request, clock) {
    const answer = real.current(request, clock);
    seen.last = answer.state === 'FOUND' ? rewrite(answer.metadata) : undefined;
    if (answer.state !== 'FOUND') return answer;
    return Object.freeze({ version: 1, state: 'FOUND', metadata: seen.last });
  } }, seen };
}

test('a record that is not a validated record of this bound reference records no lifecycle denial',
  async () => {
    const scenario = buildScenario();
    const record = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
      scope: { ...scenario.scope } }, { now: USE_NOW }).metadata;

    // The control on the identical host: the real record, the real substrate, two ALLOWED decisions.
    const control = createHost({ scenario });
    assert.equal((await createBoundMappingUse(control.host).use()).code, 'USED');
    assert.equal(control.ledger.entries.length, 2);

    const cases = [
      ['no metadata at all', () => null],
      ['an empty metadata record', () => ({})],
      ['a record whose own state names no lifecycle', () => ({ ...record, state: 'unknown' })],
      ['a record in another scope that is still ACTIVE',
        () => ({ ...record, scope: { ...FOREIGN_SCOPE } })],
      ['a record in another scope that is not ACTIVE', () => ({ ...record, state: 'REVOKED',
        scope: { ...FOREIGN_SCOPE } })]];
    for (const [name, rewrite] of cases) {
      const backend = createBackend();
      const tampered = rewrittenRegistry(scenario, rewrite);
      const built = createHost({ scenario, backend, registry: tampered.registry });
      const refused = await createBoundMappingUse(built.host).use();
      assertFixedShape(refused);
      assert.equal(refused.code, 'WITHHELD', name);
      // Non-vacuity: the shipped registry really reported `FOUND` and really handed over a record
      // that is not the bound `ACTIVE` one it holds, so every case is a real answer this call
      // declined to attribute rather than a read that never got that far.
      assert.equal(tampered.seen.last !== undefined, true, name);
      assert.notDeepEqual(tampered.seen.last, record, name);
      // An unreadable, foreign or malformed record is not evidence about a lifecycle: nothing is
      // recorded, no sealed read happens and the resource is never reached.
      assert.equal(built.ledger.entries.length, 0, name);
      assert.equal(JSON.stringify(built.ledger.entries).includes('LIFECYCLE_DENIED'), false, name);
      assert.equal(built.counters.material, 0, name);
      assert.equal(backend.state.calls, 0, name);
    }

    // A real record in the bound scope that the real registry still calls current, and that is
    // simply not `ACTIVE`: the lifecycle class is real here and is still recorded.
    const unactivated = buildScenario({ activate: false });
    const unactivatedBackend = createBackend();
    const notActive = createHost({ scenario: unactivated, backend: unactivatedBackend });
    const found = unactivated.registry.current({ version: 1, mappingRef: unactivated.mappingRef,
      scope: { ...unactivated.scope } }, { now: USE_NOW });
    assert.equal(found.state, 'FOUND');
    assert.equal(found.metadata.state, 'CREATED');
    assert.equal((await createBoundMappingUse(notActive.host).use()).code, 'WITHHELD');
    assert.equal(notActive.ledger.entries.length, 1);
    assertAttributableDenial(notActive, notActive.ledger.entries[0].event, 'LIFECYCLE_DENIED');
    assert.equal(notActive.counters.material, 0);
    assert.equal(unactivatedBackend.state.calls, 0);

    // The revoked bound record is the other real lifecycle denial, and it is unaffected.
    const revoked = buildScenario();
    const revokedBackend = createBackend();
    const revokedHost = createHost({ scenario: revoked, backend: revokedBackend });
    const applied = revoked.registry.transition({ version: 1, mappingRef: revoked.mappingRef,
      scope: { ...revoked.scope }, expectedRevision: 2, action: 'REVOKE' }, { now: USE_NOW });
    assert.equal(applied.state, 'CHANGED');
    assert.equal((await createBoundMappingUse(revokedHost.host).use()).code, 'WITHHELD');
    assert.equal(revokedHost.ledger.entries.length, 1);
    assertAttributableDenial(revokedHost, revokedHost.ledger.entries[0].event, 'LIFECYCLE_DENIED');
    assert.equal(revokedHost.counters.material, 0);
    assert.equal(revokedBackend.state.calls, 0);
  });
/* ---------- 20. Lifecycle evidence needs a complete, validated registry answer ---------- */

/**
 * A registry that answers with exactly the value one case planted. The shipped registry still holds
 * the real record and is still what the fixture's grant, revision and sealed material were built
 * from, so nothing here weakens the world the executor is reasoning about: only the answer the host
 * hands back is replaced, which is what an unauthenticated host is free to do. `seen.calls` is the
 * non-vacuity evidence that a case really reached the read it claims to be about.
 */
function answeredRegistry(answer) {
  const seen = { calls: 0, answered: undefined };
  return { registry: { version: 1, current(request, clock) {
    seen.calls += 1;
    seen.answered = typeof answer === 'function' ? answer(request, clock, seen.calls) : answer;
    return seen.answered;
  } }, seen };
}

/** The real `FOUND` answer over the real record, before a case plants something else in its place. */
function foundAnswer(scenario) {
  const found = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope } }, { now: USE_NOW });
  assert.equal(found.state, 'FOUND');
  return found;
}

/** One planted answer, and the fixed outcome every row of the matrix owes. */
async function assertPlantedRefusal(scenario, answer, entries, name) {
  const backend = createBackend();
  const planted = answeredRegistry(answer);
  const built = createHost({ scenario, backend, registry: planted.registry });
  const refused = await createBoundMappingUse(built.host).use();
  assertFixedShape(refused);
  assert.equal(refused.code, 'WITHHELD', name);
  // Non-vacuity: the read really happened, so every row is an answer this call declined to attribute
  // rather than a refusal that happened before the registry was ever consulted.
  assert.equal(planted.seen.calls >= 1, true, name);
  assert.equal(built.counters.material, 0, name);
  assert.equal(backend.state.calls, 0, name);
  assert.equal(cleared(backend.state.retained), false, name);
  assert.equal(built.ledger.entries.length, entries, name);
  if (entries === 1) assertAttributableDenial(built, built.ledger.entries[0].event,
    'LIFECYCLE_DENIED');
}

test('a FOUND record relabelled and stripped of its own mandatory fields records no denial', async () => {
  const scenario = buildScenario();
  const record = foundAnswer(scenario).metadata;
  const planted = { version: 1, state: 'FOUND',
    metadata: { mappingRef: record.mappingRef, scope: { ...record.scope }, state: 'CREATED',
      revision: record.revision, expiresAt: record.expiresAt } };
  // The planted value is what a host that relabels a real record as `CREATED` while dropping the
  // fields the lifecycle schema makes mandatory actually hands back. Its state names a lifecycle and
  // nothing else about it is malformed, which is exactly why the shape has to be settled first.
  assert.equal(Object.hasOwn(planted.metadata, 'version'), false);
  assert.equal(Object.hasOwn(planted.metadata, 'createdAt'), false);
  await assertPlantedRefusal(scenario, planted, 0, 'stripped record');

  // The same relabelling with every mandatory field present is a different case, and the shipped
  // registry really produces it: that one is an attributable lifecycle denial (see below).
  const complete = await answeredRegistry({ version: 1, state: 'FOUND',
    metadata: { version: 1, mappingRef: record.mappingRef, scope: { ...record.scope },
      state: 'CREATED', revision: record.revision, createdAt: record.createdAt,
      expiresAt: record.expiresAt } });
  assert.equal(complete.seen.calls, 0);
});

test('an answer state the registry never returns cannot carry NOT_LIVE evidence', async () => {
  const scenario = buildScenario();
  const record = foundAnswer(scenario).metadata;
  // A discriminator outside the registry's own three branches, carrying the reason that would
  // otherwise name a lifecycle. The reason is only ever evidence about a branch the registry owns.
  await assertPlantedRefusal(scenario, { version: 1, state: 'unknown', reason: 'NOT_LIVE' }, 0,
    'state outside the registry branches');
  // The same reason on the `REFUSED` branch: the shipped registry reports `NOT_LIVE` as `ABSENT`,
  // so a refusal that claims it never proved it held this record.
  await assertPlantedRefusal(scenario, { version: 1, state: 'REFUSED', reason: 'NOT_LIVE' }, 0,
    'NOT_LIVE on the REFUSED branch');
  // The genuine reasons of the other two branches name no lifecycle, so they record nothing either.
  await assertPlantedRefusal(scenario, { version: 1, state: 'ABSENT', reason: 'UNKNOWN_MAPPING' }, 0,
    'an unknown reference');
  await assertPlantedRefusal(scenario, { version: 1, state: 'REFUSED', reason: 'INVALID_REQUEST' }, 0,
    'a refused read');
  // A reason outside the registry's own vocabulary is a malformed answer, not a lifecycle fact.
  await assertPlantedRefusal(scenario, { version: 1, state: 'ABSENT', reason: 'NOT_LIVE_AT_ALL' }, 0,
    'a reason outside the vocabulary');
  // The genuine lifecycle answer this file's other cases depend on, planted directly so the row
  // above cannot pass merely because the executor refuses `ABSENT` altogether.
  await assertPlantedRefusal(scenario, { version: 1, state: 'ABSENT', reason: 'NOT_LIVE' }, 1,
    'the genuine NOT_LIVE answer');
  assert.equal(record.state, 'ACTIVE');
});

test('every mandatory envelope key is required before any lifecycle class is attached', async () => {
  const scenario = buildScenario();
  const record = foundAnswer(scenario).metadata;
  const envelopeCases = [
    ['no answer at all', null],
    ['an answer that is not an object', 'FOUND'],
    ['an answer that is an array', []],
    ['an empty answer', {}],
    ['no discriminator', { version: 1 }],
    ['a wrong version', { version: 2, state: 'ABSENT', reason: 'NOT_LIVE' }],
    ['no version', { state: 'ABSENT', reason: 'NOT_LIVE' }],
    ['a state outside the vocabulary', { version: 1, state: 'NOT_FOUND', reason: 'NOT_LIVE' }],
    ['a branch with no reason', { version: 1, state: 'ABSENT' }],
    ['a reason branch carrying a record', { version: 1, state: 'ABSENT', reason: 'NOT_LIVE',
      metadata: { ...record } }],
    ['a record branch carrying a reason', { version: 1, state: 'FOUND', metadata: { ...record },
      reason: 'NOT_LIVE' }],
    ['a record branch carrying no record', { version: 1, state: 'FOUND' }],
    ['an unknown key on a record branch', { version: 1, state: 'FOUND', metadata: { ...record },
      note: 'x' }],
    ['an unknown key on a reason branch', { version: 1, state: 'ABSENT', reason: 'NOT_LIVE',
      note: 'x' }],
    ['an inherited prototype', Object.assign(Object.create({ state: 'ABSENT', reason: 'NOT_LIVE' }),
      { version: 1 })]];
  for (const [name, answer] of envelopeCases) {
    await assertPlantedRefusal(scenario, answer, 0, `envelope: ${name}`);
  }
});

test('every mandatory record and scope field is required before any lifecycle class is attached',
  async () => {
    const scenario = buildScenario();
    const record = foundAnswer(scenario).metadata;
    const without = (key) => { const copy = { ...record }; delete copy[key]; return copy; };
    const scopeWithout = (key) => { const copy = { ...record.scope }; delete copy[key]; return copy; };
    const rows = [
      ['no version', without('version')],
      ['no mappingRef', without('mappingRef')],
      ['no scope', without('scope')],
      ['no state', without('state')],
      ['no revision', without('revision')],
      ['no createdAt', without('createdAt')],
      ['no expiresAt', without('expiresAt')],
      ['an unknown record key', { ...record, note: 'x' }],
      ['a wrong record version', { ...record, version: 2 }],
      ['an empty mappingRef', { ...record, mappingRef: '' }],
      ['a mappingRef with a control character', { ...record, mappingRef: 'xSy\u0000y' }],
      ['a mappingRef of another reference', { ...record,
        mappingRef: buildScenario({ scope: FOREIGN_SCOPE }).mappingRef }],
      ['a scope that is not an object', { ...record, scope: 'tenant-bound-use-alpha.invalid' }],
      ['a scope with no tenantId', { ...record, scope: scopeWithout('tenantId') }],
      ['a scope with no projectId', { ...record, scope: scopeWithout('projectId') }],
      ['a scope with no sessionId', { ...record, scope: scopeWithout('sessionId') }],
      ['a scope with an unknown key', { ...record, scope: { ...record.scope, note: 'x' } }],
      ['an empty tenantId', { ...record, scope: { ...record.scope, tenantId: '' } }],
      ['a scope padded with whitespace', { ...record,
        scope: { ...record.scope, sessionId: ' session-bound-use-alpha.invalid ' } }],
      ['another tenant', { ...record, scope: { ...FOREIGN_SCOPE } }],
      ['another session in this tenant', { ...record, scope: { ...scenario.scope,
        sessionId: FOREIGN_SCOPE.sessionId } }],
      ['a state outside the lifecycle vocabulary', { ...record, state: 'unknown' }],
      ['a state that is not a string', { ...record, state: 7 }],
      ['a revision below one', { ...record, revision: 0 }],
      ['a fractional revision', { ...record, revision: 2.5 }],
      ['a revision carried as text', { ...record, revision: '2' }],
      ['a negative createdAt', { ...record, createdAt: -1 }],
      ['a fractional createdAt', { ...record, createdAt: T0 + 0.5 }],
      ['a negative expiresAt', { ...record, expiresAt: -1 }],
      ['a createdAt that is not a number', { ...record, createdAt: String(T0) }],
      ['a record on an inherited prototype', Object.assign(Object.create({ state: 'REVOKED' }),
        { ...record })]];
    for (const [name, metadata] of rows) {
      await assertPlantedRefusal(scenario, { version: 1, state: 'FOUND', metadata }, 0, `record: ${name}`);
    }
  });

test('a coherent record whose own window is closed, or not yet open, names what it can', async () => {
  const scenario = buildScenario();
  const record = foundAnswer(scenario).metadata;
  const incoherent = [
    ['createdAt equal to expiresAt', { ...record, createdAt: record.expiresAt }],
    ['createdAt after expiresAt', { ...record, createdAt: record.expiresAt + 1 }],
    ['both at the epoch', { ...record, createdAt: 0, expiresAt: 0 }]];
  for (const [name, metadata] of incoherent) {
    await assertPlantedRefusal(scenario, { version: 1, state: 'FOUND', metadata }, 0, `window: ${name}`);
  }

  // A clock earlier than the record's own creation instant is not a lifecycle this call can name:
  // the shipped registry cannot report one, so the answer is refused as unreadable and recorded
  // nowhere, while the record itself is complete and matches this bound reference and scope.
  await assertPlantedRefusal(scenario, { version: 1, state: 'FOUND',
    metadata: { ...record, createdAt: USE_NOW + 1 } }, 0, 'window: created in the future');

  // A complete record of this bound reference and scope whose expiry has passed at the observed
  // instant is no longer live, whatever state the answer claims: that is the lifecycle fact the
  // class exists for, so it is recorded.
  await assertPlantedRefusal(scenario, { version: 1, state: 'FOUND',
    metadata: { ...record, expiresAt: USE_NOW } }, 1, 'window: expired at the observed instant');
});

test('a getter or a trapping registry answer is a refusal with no evidence at all', async () => {
  const scenario = buildScenario();
  const record = foundAnswer(scenario).metadata;
  const trappedKeys = { ownKeys() { throw new Error('synthetic answer reflection fault'); } };
  const trappedDescriptor = { getOwnPropertyDescriptor() {
    throw new Error('synthetic answer descriptor fault'); } };
  const getterRecord = { ...record };
  Object.defineProperty(getterRecord, 'revision', { enumerable: true,
    get() { throw new Error('synthetic record accessor fault'); } });
  const hiddenRecord = Object.defineProperty({ ...record }, 'revision',
    { enumerable: false, value: record.revision, configurable: true });
  const getterEnvelope = { version: 1 };
  Object.defineProperty(getterEnvelope, 'state', { enumerable: true,
    get() { throw new Error('synthetic envelope accessor fault'); } });
  const rows = [
    ['an accessor on the discriminator', getterEnvelope],
    ['an accessor on the record', { version: 1, state: 'FOUND', metadata: getterRecord }],
    ['a hidden record field', { version: 1, state: 'FOUND', metadata: hiddenRecord }],
    ['an envelope whose own keys trap', new Proxy({ version: 1, state: 'ABSENT', reason: 'NOT_LIVE' },
      trappedKeys)],
    ['a record whose own keys trap', { version: 1, state: 'FOUND',
      metadata: new Proxy({ ...record }, trappedKeys) }],
    ['a record whose descriptors trap', { version: 1, state: 'FOUND',
      metadata: new Proxy({ ...record }, trappedDescriptor) }]];
  for (const [name, answer] of rows) {
    await assertPlantedRefusal(scenario, answer, 0, `trap: ${name}`);
  }
});

test('the genuine lifecycle states still record their own evidence and the effect still spends',
  async () => {
    // The accepted path is the control for everything below: the same host, actor and ledger record
    // exactly two ALLOWED decisions, load the material once and spend the private resource once.
    const control = createHost();
    assert.equal((await createBoundMappingUse(control.host).use()).code, 'USED');
    assert.equal(control.ledger.entries.length, 2);
    assert.equal(control.ledger.entries.every((entry) => entry.event.outcome === 'ALLOWED'), true);
    assert.equal(control.counters.material, 1);
    assert.equal(control.backend.state.calls, 1);

    // A genuine in-bound record the shipped registry still calls current, and that is simply not
    // `ACTIVE`: complete, matched and attributable, so the lifecycle class is recorded once.
    const unactivated = buildScenario({ activate: false });
    const unactivatedBackend = createBackend();
    const notActive = createHost({ scenario: unactivated, backend: unactivatedBackend });
    const current = unactivated.registry.current({ version: 1, mappingRef: unactivated.mappingRef,
      scope: { ...unactivated.scope } }, { now: USE_NOW });
    assert.equal(current.state, 'FOUND');
    assert.equal(current.metadata.state, 'CREATED');
    assert.equal((await createBoundMappingUse(notActive.host).use()).code, 'WITHHELD');
    assert.equal(notActive.ledger.entries.length, 1);
    assertAttributableDenial(notActive, notActive.ledger.entries[0].event, 'LIFECYCLE_DENIED');
    assert.equal(notActive.counters.material, 0);
    assert.equal(unactivatedBackend.state.calls, 0);

    // A genuine revoked record, revoked through the shipped reducer: the registry stops reporting it
    // as current and answers `ABSENT` / `NOT_LIVE`, which is the branch that names the lifecycle.
    const revoked = buildScenario();
    const revokedBackend = createBackend();
    const revokedHost = createHost({ scenario: revoked, backend: revokedBackend });
    const applied = revoked.registry.transition({ version: 1, mappingRef: revoked.mappingRef,
      scope: { ...revoked.scope }, expectedRevision: 2, action: 'REVOKE' }, { now: USE_NOW });
    assert.equal(applied.state, 'CHANGED');
    const afterRevocation = revoked.registry.current({ version: 1, mappingRef: revoked.mappingRef,
      scope: { ...revoked.scope } }, { now: USE_NOW });
    assert.equal(afterRevocation.state, 'ABSENT');
    assert.equal(afterRevocation.reason, 'NOT_LIVE');
    assert.equal((await createBoundMappingUse(revokedHost.host).use()).code, 'WITHHELD');
    assert.equal(revokedHost.ledger.entries.length, 1);
    assertAttributableDenial(revokedHost, revokedHost.ledger.entries[0].event, 'LIFECYCLE_DENIED');
    assert.equal(revokedHost.counters.material, 0);
    assert.equal(revokedBackend.state.calls, 0);
  });

/* ---------- 21. Authority and grant shape: nothing malformed is ever attributed ---------- */

/** Deletes a planted member instead of carrying it as an absent value, which is a different answer. */
const OMIT = Symbol('omit');
const TRAPPED_KEYS = { ownKeys() { throw new Error('synthetic grant reflection fault'); } };
const TRAPPED_DESCRIPTOR = { getOwnPropertyDescriptor() {
  throw new Error('synthetic grant descriptor fault'); } };

/**
 * Re-points a host's authority at exactly the planted observation. Without `whole` the answer is the
 * host's own accepted one with the named members replaced, and each replacement is handed over
 * untouched: a hostile value is never spread, cloned or normalized by this fixture on its way in.
 * With `whole` the answer is the planted object itself, so an observation this file wants to hand
 * over exactly as built is not rebuilt first.
 */
function plant(built, overrides, whole) {
  built.host.authority = () => {
    if (whole !== undefined) return whole;
    const answer = { version: 1, subject: { ...WORKLOAD }, context: { ...SCOPE, purpose: PURPOSE },
      destination: { ...DESTINATION }, keyVersion: KEY_VERSION, now: USE_NOW,
      grant: { ...built.state.grant } };
    for (const key of Object.keys(overrides)) {
      if (overrides[key] === OMIT) delete answer[key];
      else answer[key] = overrides[key];
    }
    return answer;
  };
  return built;
}

/** One fresh ledger per host, over this scenario's own stream, so no row inherits another's entries. */
function freshLedger() {
  return createInMemoryAuditLedger({ tenantId: SCOPE.tenantId, projectId: SCOPE.projectId });
}

/**
 * A revoked record, revoked by the shipped reducer: the host is assembled while its own registry read
 * is still genuine, and the revocation is applied afterwards, so the answer this world reports is the
 * shipped registry's own `ABSENT` / `NOT_LIVE` and not a fixture's.
 */
function revokedWorld() {
  const scenario = buildScenario();
  const built = createHost({ backend: createBackend(), ledger: freshLedger(), scenario });
  const record = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope } }, { now: USE_NOW }).metadata;
  const applied = scenario.registry.transition({ version: 1, mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope }, expectedRevision: record.revision, action: 'REVOKE' },
    { now: USE_NOW });
  assert.equal(applied.state, 'CHANGED');
  const gone = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
    scope: { ...scenario.scope } }, { now: USE_NOW });
  assert.equal(gone.state, 'ABSENT');
  assert.equal(gone.reason, 'NOT_LIVE');
  return built;
}

/**
 * The three real lifecycle worlds every planted row below is measured in, each rebuilt per row: a
 * complete `ACTIVE` record, the genuine `CREATED` record the shipped registry still reports as
 * current, and a genuine revoked record the registry no longer reports at all. The lifecycle guard is
 * the only one that can leave evidence, so a malformed authority answer is provably unattributable
 * only if it is unattributable in the two worlds where a real lifecycle class would otherwise land.
 */
const WORLDS = [
  ['ACTIVE', () => createHost({ backend: createBackend(), ledger: freshLedger() })],
  ['CREATED', () => createHost({ backend: createBackend(), ledger: freshLedger(),
    scenario: buildScenario({ activate: false }) })],
  ['REVOKED', revokedWorld]];

/**
 * One planted observation: a fixed `WITHHELD` and exactly the evidence the row owes - nothing for a
 * malformed value, one attributable decision with its own class for a genuine refusal, and in both
 * cases no sealed read, no private effect and no recovered bytes at all.
 */
async function assertPlanted(built, entries, reason, name) {
  const refused = await createBoundMappingUse(built.host).use();
  assertFixedShape(refused);
  assert.equal(refused.code, 'WITHHELD', name);
  assert.equal(built.counters.material, 0, name);
  assert.equal(built.backend.state.calls, 0, name);
  assert.equal(cleared(built.backend.state.retained), false, name);
  assert.equal(built.ledger.entries.length, entries, name);
  assert.equal(JSON.stringify(built.ledger.entries).includes('DENIED'), entries === 1, name);
  if (entries === 1) assertAttributableDenial(built, built.ledger.entries[0].event, reason);
  return built;
}

/** Walks one table of planted observations against every real lifecycle world. */
async function eachWorld(rows) {
  for (const [worldName, world] of WORLDS) {
    for (const [name, overrides, whole] of rows) {
      await assertPlanted(plant(world(), overrides, whole), 0, undefined, `${worldName}: ${name}`);
    }
  }
}

test('the genuine outcomes in every real lifecycle world are unchanged', async () => {
  // `ACTIVE` is the control for every refusal below: the accepted path still spends its own private
  // resource once and still records exactly the two `ALLOWED` decisions and no denial at all.
  const accepted = WORLDS[0][1]();
  const acceptedResult = await createBoundMappingUse(accepted.host).use();
  assertFixedShape(acceptedResult);
  assert.equal(acceptedResult.code, 'USED');
  assert.equal(accepted.counters.authority, 4);
  assert.equal(accepted.counters.material, 1);
  assert.equal(accepted.backend.state.calls, 1);
  assert.equal(accepted.ledger.entries.length, 2);
  assert.equal(accepted.ledger.entries.every((entry) => entry.event.outcome === 'ALLOWED'), true);
  assert.equal(accepted.ledger.entries.some((entry) => entry.event.outcome === 'DENIED'), false);

  // The refusals the authorization seam itself names, on a live `ACTIVE` record: a grant carried as
  // absent and a grant carried as the absent value are both its `NO_GRANT` row, and a grant whose own
  // expiry has passed is its `GRANT_EXPIRED` row. A grant for either other operation is the actor's
  // own misbound authority, so it stays `OPERATION_NOT_GRANTED` and records nothing.
  const template = { ...WORLDS[0][1]().state.grant };
  await assertPlanted(plant(WORLDS[0][1](), { grant: OMIT }), 1, 'RESOLUTION_DENIED', 'ACTIVE: absent');
  await assertPlanted(plant(WORLDS[0][1](), { grant: undefined }), 1, 'RESOLUTION_DENIED',
    'ACTIVE: the absent value');
  await assertPlanted(plant(WORLDS[0][1](), { grant: { ...template, expiresAt: T0 + 30_000 } }), 1,
    'RESOLUTION_DENIED', 'ACTIVE: expired');
  for (const operation of ['DISPLAY', 'EXPORT']) {
    await assertPlanted(plant(WORLDS[0][1](), { grant: { ...template, operation } }), 0, undefined,
      `ACTIVE: a grant for ${operation}`);
  }

  // The two lifecycle worlds still record their own class, and it still wins over every grant row -
  // including an absent or an expired one, because the lifecycle guard runs before the seam.
  for (const [worldName, world] of [[WORLDS[1][0], WORLDS[1][1]], [WORLDS[2][0], WORLDS[2][1]]]) {
    const grant = { ...world().state.grant };
    await assertPlanted(plant(world(), {}), 1, 'LIFECYCLE_DENIED', `${worldName}: a valid grant`);
    await assertPlanted(plant(world(), { grant: OMIT }), 1, 'LIFECYCLE_DENIED',
      `${worldName}: an absent grant`);
    await assertPlanted(plant(world(), { grant: undefined }), 1, 'LIFECYCLE_DENIED',
      `${worldName}: the absent value`);
    await assertPlanted(plant(world(), { grant: { ...grant, expiresAt: T0 + 30_000 } }), 1,
      'LIFECYCLE_DENIED', `${worldName}: an expired grant`);
  }
});

test('a grant outside the authorization schema is attributed in no real lifecycle world', async () => {
  const valid = { ...WORLDS[0][1]().state.grant };
  const principal = { ...valid.principal };
  const context = { ...valid.context };
  const destination = { ...valid.destination };
  const without = (record, key) => { const copy = { ...record }; delete copy[key]; return copy; };
  const long = (length) => 'x'.repeat(length);
  const accessorGrant = () => { const copy = { ...valid };
    Object.defineProperty(copy, 'expiresAt', { enumerable: true, configurable: true,
      get() { throw new Error('synthetic grant accessor fault'); } });
    return copy; };
  await eachWorld([
    // The grant answer itself: exactly the fields its own private parser reads, none of them optional.
    ['a grant that is not an object', { grant: 'grant-bound-use.invalid' }],
    ['a grant that is an array', { grant: [] }],
    ['a wrong grant version', { grant: { ...valid, version: 2 } }],
    ['no grant version', { grant: without(valid, 'version') }],
    ['no mappingRef', { grant: without(valid, 'mappingRef') }],
    ['no revision', { grant: without(valid, 'revision') }],
    ['no principal', { grant: without(valid, 'principal') }],
    ['no context', { grant: without(valid, 'context') }],
    ['no destination', { grant: without(valid, 'destination') }],
    ['no operation', { grant: without(valid, 'operation') }],
    ['no expiresAt', { grant: without(valid, 'expiresAt') }],
    ['an unknown grant key', { grant: { ...valid, note: 'x' } }],
    ['an empty mappingRef', { grant: { ...valid, mappingRef: '' } }],
    ['a padded mappingRef', { grant: { ...valid, mappingRef: ' grant.invalid ' } }],
    ['a mappingRef with a control character', { grant: { ...valid, mappingRef: 'grant\u0000.invalid' } }],
    ['a mappingRef over its own limit', { grant: { ...valid, mappingRef: long(257) } }],
    ['a revision below one', { grant: { ...valid, revision: 0 } }],
    ['a negative revision', { grant: { ...valid, revision: -1 } }],
    ['a fractional revision', { grant: { ...valid, revision: 2.5 } }],
    ['a revision carried as text', { grant: { ...valid, revision: '2' } }],
    ['an unsafe revision', { grant: { ...valid, revision: Number.MAX_SAFE_INTEGER + 1 } }],
    ['a revision that is not a number', { grant: { ...valid, revision: null } }],
    ['an operation outside the vocabulary', { grant: { ...valid, operation: 'DELETE' } }],
    ['an operation that is not a string', { grant: { ...valid, operation: 7 } }],
    ['an operation that is not this case', { grant: { ...valid, operation: 'use' } }],
    ['an expiry at zero', { grant: { ...valid, expiresAt: 0 } }],
    ['a negative expiry', { grant: { ...valid, expiresAt: -1 } }],
    ['a fractional expiry', { grant: { ...valid, expiresAt: T0 + 0.5 } }],
    ['an expiry carried as text', { grant: { ...valid, expiresAt: String(T0) } }],
    ['an unsafe expiry', { grant: { ...valid, expiresAt: Number.MAX_SAFE_INTEGER + 1 } }],
    ['an expiry that is not a number', { grant: { ...valid, expiresAt: undefined } }],
    // The nested principal, context and destination are read the same way, one bounded own-key
    // snapshot each, and their string limits are the authorization strings' own limits.
    ['a principal that is not an object', { grant: { ...valid, principal: 'workload.invalid' } }],
    ['a principal with no principalId', { grant: { ...valid,
      principal: without(principal, 'principalId') } }],
    ['a principal with no workloadId', { grant: { ...valid,
      principal: without(principal, 'workloadId') } }],
    ['a principal with an unknown key', { grant: { ...valid,
      principal: { ...principal, note: 'x' } } }],
    ['an empty principalId', { grant: { ...valid, principal: { ...principal, principalId: '' } } }],
    ['a padded principalId', { grant: { ...valid,
      principal: { ...principal, principalId: ' principal.invalid ' } } }],
    ['a principalId with a control character', { grant: { ...valid,
      principal: { ...principal, principalId: 'p\u0000q' } } }],
    ['an oversized principalId', { grant: { ...valid,
      principal: { ...principal, principalId: long(257) } } }],
    ['an oversized workloadId', { grant: { ...valid,
      principal: { ...principal, workloadId: long(257) } } }],
    ['a principal on an inherited prototype', { grant: { ...valid,
      principal: Object.assign(Object.create({ workloadId: 'workload.invalid' }), principal) } }],
    ['a context that is not an object', { grant: { ...valid, context: 'tenant.invalid' } }],
    ['a context with no tenantId', { grant: { ...valid, context: without(context, 'tenantId') } }],
    ['a context with no sessionId', { grant: { ...valid, context: without(context, 'sessionId') } }],
    ['a context with no purpose', { grant: { ...valid, context: without(context, 'purpose') } }],
    ['a context with an unknown key', { grant: { ...valid, context: { ...context, note: 'x' } } }],
    ['an empty tenantId', { grant: { ...valid, context: { ...context, tenantId: '' } } }],
    ['an oversized tenantId', { grant: { ...valid, context: { ...context, tenantId: long(257) } } }],
    ['an oversized purpose', { grant: { ...valid, context: { ...context, purpose: long(257) } } }],
    ['an oversized projectId', { grant: { ...valid, context: { ...context, projectId: long(257) } } }],
    ['a context on an inherited prototype', { grant: { ...valid,
      context: Object.assign(Object.create({ purpose: PURPOSE }), context) } }],
    ['a destination that is not an object', { grant: { ...valid, destination: 'sink.invalid' } }],
    ['a destination with no kind', { grant: { ...valid,
      destination: without(destination, 'kind') } }],
    ['a destination with no ref', { grant: { ...valid,
      destination: without(destination, 'ref') } }],
    ['a destination with no trustZone', { grant: { ...valid,
      destination: without(destination, 'trustZone') } }],
    ['a destination with no profileId', { grant: { ...valid,
      destination: without(destination, 'profileId') } }],
    ['a destination with an unknown key', { grant: { ...valid,
      destination: { ...destination, note: 'x' } } }],
    ['an empty kind', { grant: { ...valid, destination: { ...destination, kind: '' } } }],
    ['an oversized kind', { grant: { ...valid, destination: { ...destination, kind: long(257) } } }],
    ['an oversized ref', { grant: { ...valid, destination: { ...destination, ref: long(2049) } } }],
    ['an oversized trustZone', { grant: { ...valid, destination: { ...destination,
      trustZone: long(257) } } }],
    ['an oversized profileId', { grant: { ...valid, destination: { ...destination,
      profileId: long(257) } } }],
    // Hostile shapes: a symbol, a hidden field, an accessor, a trapped reflection, a prototype.
    ['a symbol key', { grant: { ...valid, [Symbol('note')]: 'x' } }],
    ['a hidden field', { grant: Object.defineProperty({ ...valid }, 'revision',
      { enumerable: false, value: valid.revision, configurable: true }) }],
    ['an accessor', { grant: accessorGrant() }],
    ['an ownKeys trap', { grant: new Proxy({ ...valid }, TRAPPED_KEYS) }],
    ['a descriptor trap', { grant: new Proxy({ ...valid }, TRAPPED_DESCRIPTOR) }],
    ['an inherited prototype', { grant: Object.assign(Object.create({ operation: 'USE' }), valid) }]]);
});

test('an authority answer outside its own schema is attributed in no real lifecycle world', async () => {
  const observation = { version: 1, subject: { ...WORKLOAD }, context: { ...SCOPE, purpose: PURPOSE },
    destination: { ...DESTINATION }, keyVersion: KEY_VERSION, now: USE_NOW };
  const without = (key) => { const copy = { ...observation }; delete copy[key]; return copy; };
  const long = (length) => 'x'.repeat(length);
  const accessorAnswer = () => { const copy = { ...observation };
    Object.defineProperty(copy, 'now', { enumerable: true, configurable: true,
      get() { throw new Error('synthetic answer accessor fault'); } });
    return copy; };
  await eachWorld([
    // Only `grant` is optional on this answer; everything else is settled before anything reads it,
    // and none of it may name a lifecycle when it is not this module's own schema.
    ['no answer at all', undefined, null],
    ['an answer that is not an object', undefined, 'bound-use.invalid'],
    ['an answer that is an array', undefined, []],
    ['an empty answer', undefined, {}],
    ['a wrong answer version', undefined, { ...observation, version: 2 }],
    ['no answer version', undefined, without('version')],
    ['no subject', undefined, without('subject')],
    ['a subject that is not an object', undefined, { ...observation, subject: 'workload.invalid' }],
    ['a subject with no workloadId', undefined, { ...observation,
      subject: { principalId: WORKLOAD.principalId } }],
    ['an oversized subject principalId', undefined, { ...observation,
      subject: { ...WORKLOAD, principalId: long(257) } }],
    ['no context', undefined, without('context')],
    ['a context with no purpose', undefined, { ...observation, context: { ...SCOPE } }],
    ['an oversized context purpose', undefined, { ...observation,
      context: { ...SCOPE, purpose: long(257) } }],
    ['no destination', undefined, without('destination')],
    ['a destination with no profileId', undefined, { ...observation, destination: {
      kind: DESTINATION.kind, ref: DESTINATION.ref, trustZone: DESTINATION.trustZone } }],
    ['an oversized destination ref', undefined, { ...observation,
      destination: { ...DESTINATION, ref: long(2049) } }],
    ['an unknown answer key', undefined, { ...observation, note: 'x' }],
    ['a keyVersion over its own limit', undefined, { ...observation, keyVersion: long(49) }],
    ['a keyVersion that is not its own shape', undefined, { ...observation, keyVersion: 'v1' }],
    ['a padded keyVersion', undefined, { ...observation, keyVersion: ' 1.0' }],
    ['a keyVersion carried as a number', undefined, { ...observation, keyVersion: 1 }],
    ['no now', undefined, without('now')],
    ['a now at zero', undefined, { ...observation, now: 0 }],
    ['a negative now', undefined, { ...observation, now: -1 }],
    ['a fractional now', undefined, { ...observation, now: USE_NOW + 0.5 }],
    ['a now carried as text', undefined, { ...observation, now: String(USE_NOW) }],
    ['an unsafe now', undefined, { ...observation, now: Number.MAX_SAFE_INTEGER + 1 }],
    ['a symbol key', undefined, { ...observation, [Symbol('note')]: 'x' }],
    ['a hidden field', undefined, Object.defineProperty({ ...observation }, 'now',
      { enumerable: false, value: USE_NOW, configurable: true })],
    ['an accessor', undefined, accessorAnswer()],
    ['an ownKeys trap', undefined, new Proxy({ ...observation }, TRAPPED_KEYS)],
    ['a descriptor trap', undefined, new Proxy({ ...observation }, TRAPPED_DESCRIPTOR)],
    ['an inherited prototype', undefined,
      Object.assign(Object.create({ now: USE_NOW }), observation)]]);
});
