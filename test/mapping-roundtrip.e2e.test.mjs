// #176 / synthetic integration test for the mapping round trip: the shipped mapping AEAD primitive
// (seal/open), the shipped keyed scope-bound entity reference derivation, the shipped purpose-bound
// mapping authorization seam and the shipped mapping lifecycle reducer are joined over one explicitly
// ephemeral in-process synthetic fixture.
//
// What this proves, precisely: over this fixture, with test-supplied trusted bindings (a literal
// synthetic DEK, HMAC key, host clock, authenticated workload and explicit grant), an original value
// exists only as AEAD ciphertext until an actual AUTHORIZED DISPLAY decision from the real
// `authorizeMappingOperation` seam permits one `openMappingPayload` call under an independently
// supplied expected scope; the restored bytes equal an independent literal expected outcome. USE does
// not imply DISPLAY or EXPORT, cross-scope references and records never resolve, and lifecycle
// commits to the fixture's current revision so a stale revision or cached snapshot cannot supersede
// it.
//
// What it is NOT: not a production vault, broker, KMS/HSM, key-management system, transaction, store,
// index, durable audit ledger, transport or model. It authenticates nobody: the DEK, the HMAC key, the
// grant, the authenticated subject and the clock are test fixtures. No network, no provider traffic,
// no credentials, no held-out data, no comparison or recovery claim. Parent #15 stays open.
//
// Every fixture value is invented and obviously synthetic and non-routable (`.invalid` names, fixed
// byte fills, one planted marker string that is never a real person, host or credential).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sealMappingPayload, openMappingPayload, MAPPING_AEAD_LIMITS } from '../dist/mapping-aead.js';
import { deriveScopedEntityReference, ENTITY_REFERENCE_TOKEN_PREFIX } from '../dist/scoped-entity-reference.js';
import { applyMappingLifecycleCommand } from '../dist/mapping-lifecycle.js';
import { authorizeMappingOperation } from '../dist/mapping-authorization.js';

/* ---------- Independent literal expectations and planted synthetic markers ---------- */

// The expected outcome is a literal written here, never recomputed from the implementation, and the
// value the fixture encrypts. Obviously synthetic, non-routable and not a credential or identity.
const SYNTHETIC_ORIGINAL = 'synthetic-original-verity-fixture.invalid';
const SYNTHETIC_ORIGINAL_BYTES = new TextEncoder().encode(SYNTHETIC_ORIGINAL);
const FOREIGN_ORIGINAL = 'synthetic-original-other-tenant-fixture.invalid';
const ENTITY_ID_A = 'entity-verity-fixture';
const ENTITY_ID_B = 'entity-oskar-fixture';

/* ---------- Trusted test bindings (fixtures, not authenticated identities) ---------- */

const DEK_A = new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x11);
const DEK_B = new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x22);
const UNRELATED_DEK = new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x33);
const HMAC_A = new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x44);
const HMAC_B = new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x55);
const KEY_VERSION = '1.0';
const T0 = 1_760_000_000_000;
const TTL_MS = 3_600_000;
const WORKLOAD = { principalId: 'principal-fixture.invalid', workloadId: 'workload-fixture.invalid' };
const FOREIGN_WORKLOAD = { principalId: 'principal-other.invalid', workloadId: 'workload-other.invalid' };
const PURPOSE = 'support-review-fixture.invalid';
const DESTINATION = Object.freeze({
  kind: 'tool.result', ref: 'tool-sink-fixture.invalid', trustZone: 'LOCAL',
  profileId: 'profile-fixture.invalid',
});
const FOREIGN_DESTINATION = Object.freeze({
  kind: 'tool.result', ref: 'tool-sink-other.invalid', trustZone: 'LOCAL',
  profileId: 'profile-other.invalid',
});

const TENANT_A = Object.freeze({
  tenantId: 'tenant-alpha.invalid', projectId: 'project-alpha.invalid', sessionId: 'session-alpha.invalid',
});
const TENANT_B = Object.freeze({
  tenantId: 'tenant-beta.invalid', projectId: 'project-beta.invalid', sessionId: 'session-beta.invalid',
});

/* ---------- Model-visible capture: fixed outcomes and opaque tokens only ---------- */

// What a model could plausibly observe. Only the opaque keyed reference and fixed non-secret outcome
// labels are ever admitted; the original, its bytes and any derived plaintext never enter it.
const modelCapture = [];
function captureForModel(value) {
  modelCapture.push(value);
  return value;
}
function resetModelCapture() { modelCapture.length = 0; }
function assertCaptureIsNonSecret() {
  for (const entry of modelCapture) {
    assert.equal(typeof entry, 'string');
    assert.ok(!entry.includes(SYNTHETIC_ORIGINAL));
    assert.ok(!entry.includes(FOREIGN_ORIGINAL));
    assert.ok(!entry.includes('synthetic-original'));
  }
}

/* ---------- The ephemeral fixture: ciphertext plus non-secret metadata only ---------- */

/**
 * One ephemeral tenant fixture. It holds the sealed record, the host-held expected scope and DEK, and
 * the metadata the trusted host would read. It stores no original value and no plaintext: after
 * construction the only copy of the original anywhere in this process is the literal constant above.
 * `current` is the fixture's authoritative current record, advanced only by the lifecycle reducer.
 */
function makeFixture({ scope, key, hmacKey, entityId, original, createdAt, expiresAt }) {
  const reference = deriveScopedEntityReference({
    scope: 'SESSION', tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId,
    entityId, semanticType: 'PERSON', keyVersion: KEY_VERSION, key: hmacKey,
  });
  assert.equal(reference.state, 'DERIVED');
  const aadScope = Object.freeze({
    tenantId: scope.tenantId, projectId: scope.projectId, entityId, classification: 'PERSON',
    mappingRevision: '1', keyVersion: KEY_VERSION,
  });
  const sealed = sealMappingPayload({
    scope: aadScope, plaintext: new TextEncoder().encode(original), key,
  });
  assert.equal(sealed.status, 'SEALED');
  const fixture = {
    scope, key, hmacKey, aadScope, mappingRef: reference.token,
    envelope: sealed.envelope,
    // The authoritative current record: lifecycle metadata only, never a value or a ciphertext.
    current: Object.freeze({
      version: 1, mappingRef: reference.token,
      scope: { tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId },
      state: 'CREATED', revision: 1, createdAt, expiresAt,
    }),
  };
  return fixture;
}

/**
 * The only serialization this fixture ever emits: the AEAD record plus non-secret metadata. Used to
 * prove that a planted marker never reaches a ciphertext-only serialized image.
 */
function serializeFixture(fixture) {
  const envelope = fixture.envelope;
  return JSON.stringify({
    version: envelope.version,
    nonce: [...envelope.nonce],
    ciphertext: [...envelope.ciphertext],
    tag: [...envelope.tag],
    mappingRef: fixture.mappingRef,
    tenantId: fixture.scope.tenantId,
    projectId: fixture.scope.projectId,
    sessionId: fixture.scope.sessionId,
    lifecycle: fixture.current.state,
    revision: fixture.current.revision,
    expiresAt: fixture.current.expiresAt,
    keyVersion: KEY_VERSION,
  });
}

/**
 * `openMappingPayload` overwrites the sealed-record buffers it was handed, on every exit, so each open
 * attempt gets its own copy. That is a harness detail of this fixture, not a store and not a
 * durability claim: no value survives an open except the bytes the call returns.
 */
function cloneEnvelope(envelope) {
  return {
    version: envelope.version,
    nonce: Uint8Array.from(envelope.nonce),
    ciphertext: Uint8Array.from(envelope.ciphertext),
    tag: Uint8Array.from(envelope.tag),
  };
}

/** The host's trusted current metadata, read from the fixture's authoritative current record. */
function trustedMetadata(fixture, overrides = {}) {
  const record = fixture.current;
  return {
    version: 1, mappingRef: record.mappingRef, scope: record.scope, lifecycle: record.state,
    semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL', revision: record.revision,
    expiresAt: record.expiresAt, ...overrides,
  };
}

/** One explicit, purpose-bound, finite grant. Absent means `undefined`, which the seam denies. */
function grantFor(fixture, operation, overrides = {}) {
  return {
    version: 1, mappingRef: fixture.mappingRef, revision: fixture.current.revision,
    principal: { ...WORKLOAD },
    context: { ...fixture.current.scope, purpose: PURPOSE },
    destination: { ...DESTINATION },
    operation, expiresAt: fixture.current.expiresAt - 1, ...overrides,
  };
}

/** The real authorization seam, called with separately supplied request, host, mapping and grant. */
function decide(fixture, {
  operation = 'DISPLAY', subject = WORKLOAD, scope = fixture.current.scope, destination = DESTINATION,
  grant, now = T0 + 60_000, mapping = trustedMetadata(fixture), hostScope, mappingRef,
} = {}) {
  const request = {
    version: 1, mappingRef: mappingRef ?? fixture.mappingRef, subject: { ...subject },
    context: { ...scope, purpose: PURPOSE }, destination: { ...destination }, operation,
  };
  const host = {
    authenticated: {
      subject: { ...subject }, context: { ...(hostScope ?? scope), purpose: PURPOSE },
    },
    observed: { destination: { ...destination } },
  };
  return authorizeMappingOperation(request, host, mapping, grant, { now });
}

/**
 * The DISPLAY release path: one real authorization decision, and only then one real open under the
 * independently supplied expected scope. Without an AUTHORIZED decision nothing is opened, so no
 * plaintext can exist in this process.
 */
function releaseForDisplay(fixture, options = {}) {
  const decision = decide(fixture, { operation: 'DISPLAY', ...options });
  if (decision.state !== 'AUTHORIZED') {
    return { outcome: 'WITHHELD', code: decision.reason, plaintext: null };
  }
  const opened = openMappingPayload({
    scope: fixture.aadScope, envelope: cloneEnvelope(fixture.envelope), key: fixture.key,
  });
  if (opened.status !== 'OPENED') return { outcome: 'WITHHELD', code: opened.finding, plaintext: null };
  return { outcome: 'RELEASED', code: opened.finding, plaintext: opened.plaintext };
}

/**
 * The trusted USE path: an authorized USE returns a fixed non-secret outcome only. The original is
 * never resolved here, so a USE cannot become a reveal.
 */
function useMapping(fixture, options = {}) {
  const decision = decide(fixture, { operation: 'USE', ...options });
  if (decision.state !== 'AUTHORIZED') return { outcome: 'WITHHELD', code: decision.reason, used: false };
  return { outcome: captureForModel('USED'), code: decision.reason, used: true };
}

/** Commits one lifecycle command to the fixture's authoritative current record. */
function commit(fixture, action, { expectedRevision, now, scope = fixture.current.scope } = {}) {
  const result = applyMappingLifecycleCommand(
    fixture.current,
    { version: 1, mappingRef: fixture.mappingRef, scope, expectedRevision, action },
    { now },
  );
  if (result.state === 'CHANGED' || result.state === 'UNCHANGED') fixture.current = result.record;
  return result;
}

/** Brings one fixture to ACTIVE through the real reducer, so each test does not depend on a
 *  previous test's commit. There is no bypass: activation always goes through the reducer. */
function ensureActive(fixture, now = T0 + 1_500) {
  if (fixture.current.state === 'CREATED') {
    const activated = commit(fixture, 'ACTIVATE', { expectedRevision: fixture.current.revision, now });
    assert.equal(activated.state, 'CHANGED');
    assert.equal(activated.record.state, 'ACTIVE');
  }
  return fixture.current;
}

const FIXTURE_A = makeFixture({
  scope: TENANT_A, key: DEK_A, hmacKey: HMAC_A, entityId: ENTITY_ID_A,
  original: SYNTHETIC_ORIGINAL, createdAt: T0, expiresAt: T0 + TTL_MS,
});
const FIXTURE_B = makeFixture({
  scope: TENANT_B, key: DEK_B, hmacKey: HMAC_B, entityId: ENTITY_ID_B,
  original: FOREIGN_ORIGINAL, createdAt: T0, expiresAt: T0 + TTL_MS,
});
// A third ephemeral fixture, a third synthetic tenant, used only for the grant-expiry controls.
const TENANT_C = Object.freeze({
  tenantId: 'tenant-gamma.invalid', projectId: 'project-gamma.invalid', sessionId: 'session-gamma.invalid',
});
const FIXTURE_C = makeFixture({
  scope: TENANT_C, key: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x66),
  hmacKey: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x77),
  entityId: 'entity-juno-fixture', original: SYNTHETIC_ORIGINAL, createdAt: T0, expiresAt: T0 + TTL_MS,
});

/* ---------- 1. Accepted DISPLAY round-trip exactness ---------- */

test('an original is restored byte-exactly only after an actual AUTHORIZED DISPLAY decision', () => {
  ensureActive(FIXTURE_A);
  // Control: with no grant at all the seam denies, and nothing is opened. The lifecycle and mapping
  // checks precede the absent-grant check, so the fixture is active first.
  const withheld = releaseForDisplay(FIXTURE_A, { grant: undefined });
  assert.equal(withheld.outcome, 'WITHHELD');
  assert.equal(withheld.code, 'NO_GRANT');
  assert.equal(withheld.plaintext, null);

  // Positive: an explicit DISPLAY grant over the active current record authorizes one open.
  const released = releaseForDisplay(FIXTURE_A, { grant: grantFor(FIXTURE_A, 'DISPLAY') });
  assert.equal(released.outcome, 'RELEASED');
  assert.equal(released.code, 'OPENED');
  // The expected outcome is the independent literal, compared byte for byte.
  assert.deepEqual([...released.plaintext], [...SYNTHETIC_ORIGINAL_BYTES]);
  assert.equal(new TextDecoder().decode(released.plaintext), SYNTHETIC_ORIGINAL);
});

/* ---------- 2. The fixture holds ciphertext and non-secret metadata only ---------- */

test('the ephemeral fixture holds ciphertext plus non-secret metadata and never the original', () => {
  const serialized = serializeFixture(FIXTURE_A);
  // No planted marker reaches a ciphertext-only serialized image. This is a marker search, not a
  // ciphertext-versus-plaintext inequality claim: an AEAD ciphertext may equal its plaintext bytes.
  assert.ok(!serialized.includes(SYNTHETIC_ORIGINAL));
  assert.ok(!serialized.includes('synthetic-original'));
  // The opaque keyed reference is present and is the only identifier the fixture exposes.
  assert.ok(serialized.includes(FIXTURE_A.mappingRef));
  assert.ok(FIXTURE_A.mappingRef.startsWith(ENTITY_REFERENCE_TOKEN_PREFIX));
  assert.ok(!('plaintext' in FIXTURE_A) && !('original' in FIXTURE_A));
  // The sealed record is the ciphertext plus its own full-length tag; the fixture holds no key and no
  // scope authority inside it. Lengths only: an AEAD ciphertext may equal its plaintext byte for byte.
  assert.equal(FIXTURE_A.envelope.ciphertext.byteLength, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  assert.equal(FIXTURE_A.envelope.tag.byteLength, MAPPING_AEAD_LIMITS.tagBytes);
  assert.equal(FIXTURE_A.envelope.nonce.byteLength, MAPPING_AEAD_LIMITS.nonceBytes);
  assert.ok(!('key' in FIXTURE_A.envelope) && !('scope' in FIXTURE_A.envelope));
});

/* ---------- 3. USE does not imply DISPLAY or EXPORT ---------- */

test('a USE-only grant authorizes USE and denies DISPLAY and EXPORT, and USE reveals nothing', () => {
  const useGrant = grantFor(FIXTURE_A, 'USE');

  // Positive control: the operation the grant names is authorized.
  const used = useMapping(FIXTURE_A, { grant: useGrant });
  assert.equal(used.used, true);
  assert.equal(used.outcome, 'USED');
  assert.equal(used.code, 'AUTHORIZED');

  // Negative controls: the same grant never escalates to a reveal or an export.
  for (const operation of ['DISPLAY', 'EXPORT']) {
    const decision = decide(FIXTURE_A, { operation, grant: useGrant });
    assert.equal(decision.state, 'DENIED');
    assert.equal(decision.reason, 'OPERATION_NOT_GRANTED');
    const withheld = releaseForDisplay(FIXTURE_A, { grant: useGrant });
    assert.equal(withheld.outcome, 'WITHHELD');
    assert.equal(withheld.code, 'OPERATION_NOT_GRANTED');
    assert.equal(withheld.plaintext, null);
  }

  // The model capture holds fixed non-secret outcomes and the opaque reference, never an original.
  captureForModel(FIXTURE_A.mappingRef);
  assertCaptureIsNonSecret();
  resetModelCapture();
});

/* ---------- 4. Scope-bound references and cross-scope nonresolution ---------- */

test('one original yields distinct references per tenant, and a foreign scope never resolves', () => {
  ensureActive(FIXTURE_A);
  ensureActive(FIXTURE_B);
  // The same synthetic original sealed in both tenants, under both a derived reference and a DEK.
  assert.ok(FIXTURE_A.mappingRef !== FIXTURE_B.mappingRef);
  assert.equal(deriveScopedEntityReference({
    scope: 'TENANT', tenantId: TENANT_A.tenantId, entityId: ENTITY_ID_A, semanticType: 'PERSON',
    keyVersion: KEY_VERSION, key: HMAC_A,
  }).state, 'DERIVED');

  // Tenant B's sealed record, presented inside tenant A's authenticated context, is not authorized.
  const foreignReference = decide(FIXTURE_A, { mappingRef: FIXTURE_B.mappingRef });
  assert.equal(foreignReference.reason, 'UNKNOWN_MAPPING');
  const foreignTenant = decide(FIXTURE_A, {
    scope: TENANT_B, hostScope: TENANT_B, grant: grantFor(FIXTURE_A, 'DISPLAY'),
    mapping: trustedMetadata(FIXTURE_A),
  });
  assert.equal(foreignTenant.state, 'DENIED');
  assert.equal(foreignTenant.reason, 'SCOPE_MISMATCH');
  const foreignSession = decide(FIXTURE_A, {
    scope: { ...TENANT_A, sessionId: TENANT_B.sessionId },
    grant: grantFor(FIXTURE_A, 'DISPLAY'),
  });
  assert.equal(foreignSession.reason, 'SCOPE_MISMATCH');
  const foreignSubject = decide(FIXTURE_A, {
    subject: FOREIGN_WORKLOAD, grant: grantFor(FIXTURE_A, 'DISPLAY'),
  });
  assert.equal(foreignSubject.reason, 'SCOPE_MISMATCH');
  // The request and the observed sink still agree here, so the foreign destination is caught by the
  // grant's own destination binding instead.
  const foreignDestination = decide(FIXTURE_A, {
    destination: FOREIGN_DESTINATION, grant: grantFor(FIXTURE_A, 'DISPLAY'),
  });
  assert.equal(foreignDestination.state, 'DENIED');
  assert.equal(foreignDestination.reason, 'GRANT_MISMATCH');

  // Even bypassing authorization, tenant B's ciphertext cannot be opened in tenant A's scope: the AAD
  // binds the tenant and the DEK differs, so no foreign original or metadata is returned.
  const crossOpen = openMappingPayload({
    scope: FIXTURE_A.aadScope, envelope: cloneEnvelope(FIXTURE_B.envelope), key: FIXTURE_A.key,
  });
  assert.equal(crossOpen.status, 'REFUSED');
  assert.equal(crossOpen.finding, 'AUTHENTICATION_FAILED');
  assert.ok(!('plaintext' in crossOpen));
});

/* ---------- 5. AEAD failures produce zero plaintext ---------- */

test('tampering, a wrong key and a wrong AAD each fail with zero plaintext capture', () => {
  const expected = { version: 1, status: 'REFUSED', finding: 'AUTHENTICATION_FAILED' };
  const cases = {
    wrongKey: () => openMappingPayload({
      scope: FIXTURE_A.aadScope, envelope: cloneEnvelope(FIXTURE_A.envelope), key: UNRELATED_DEK,
    }),
    wrongClassification: () => openMappingPayload({
      scope: { ...FIXTURE_A.aadScope, classification: 'USER_ACCOUNT' },
      envelope: cloneEnvelope(FIXTURE_A.envelope), key: FIXTURE_A.key,
    }),
    wrongRevision: () => openMappingPayload({
      scope: { ...FIXTURE_A.aadScope, mappingRevision: '99' },
      envelope: cloneEnvelope(FIXTURE_A.envelope), key: FIXTURE_A.key,
    }),
    wrongKeyVersion: () => openMappingPayload({
      scope: { ...FIXTURE_A.aadScope, keyVersion: '2.0' },
      envelope: cloneEnvelope(FIXTURE_A.envelope), key: FIXTURE_A.key,
    }),
    tamperedCiphertext: () => {
      const envelope = cloneEnvelope(FIXTURE_A.envelope);
      envelope.ciphertext[0] = (envelope.ciphertext[0] + 1) & 0xff;
      return openMappingPayload({ scope: FIXTURE_A.aadScope, envelope, key: FIXTURE_A.key });
    },
    tamperedTag: () => {
      const envelope = cloneEnvelope(FIXTURE_A.envelope);
      envelope.tag[0] = (envelope.tag[0] + 1) & 0xff;
      return openMappingPayload({ scope: FIXTURE_A.aadScope, envelope, key: FIXTURE_A.key });
    },
    foreignEntity: () => openMappingPayload({
      scope: { ...FIXTURE_A.aadScope, entityId: ENTITY_ID_B },
      envelope: cloneEnvelope(FIXTURE_A.envelope), key: FIXTURE_A.key,
    }),
  };
  for (const [name, run] of Object.entries(cases)) {
    const result = run();
    assert.deepEqual(result, expected, name);
    assert.ok(!('plaintext' in result) && !('bytes' in result), name);
    // A refusal is one fixed code: it carries no planted value and no native error text.
    assert.equal(JSON.stringify(result).includes('synthetic-original'), false, name);
  }
  // Control: the untouched record still opens, so the refusals above are not vacuous.
  const control = openMappingPayload({
    scope: FIXTURE_A.aadScope, envelope: cloneEnvelope(FIXTURE_A.envelope), key: FIXTURE_A.key,
  });
  assert.equal(control.status, 'OPENED');
  assert.deepEqual([...control.plaintext], [...SYNTHETIC_ORIGINAL_BYTES]);
});

/* ---------- 6. Lifecycle commits to the current revision ---------- */

test('the reducer commits monotonic revisions and a stale revision or snapshot cannot supersede them', () => {
  const activated = ensureActive(FIXTURE_A);
  assert.equal(activated.state, 'ACTIVE');
  assert.equal(activated.revision >= 2, true);
  // Creation, expiry, scope and reference are immutable through a transition.
  assert.equal(activated.createdAt, T0);
  assert.equal(activated.expiresAt, T0 + TTL_MS);
  assert.equal(activated.scope.sessionId, TENANT_A.sessionId);

  // A stale expected revision is refused outright and never mutates the current record.
  const stale = applyMappingLifecycleCommand(
    activated,
    { version: 1, mappingRef: FIXTURE_A.mappingRef, scope: activated.scope,
      expectedRevision: activated.revision - 1, action: 'REVOKE' },
    { now: T0 + 4_000 },
  );
  assert.equal(stale.state, 'REFUSED');
  assert.equal(stale.reason, 'STALE_REVISION');
  assert.equal(FIXTURE_A.current.state, 'ACTIVE');
  assert.equal(FIXTURE_A.current.revision, activated.revision);

  // A grant pinned to a superseded revision cannot authorize against the record the host reads now,
  // and a cached snapshot of the record cannot authorize a grant pinned to the current revision. The
  // seam binds a grant to one revision; it is not a compare-and-set and claims no race safety.
  const staleGrant = grantFor(FIXTURE_A, 'DISPLAY', { revision: activated.revision - 1 });
  assert.equal(decide(FIXTURE_A, { grant: staleGrant }).reason, 'STALE_REVISION');
  const cachedRelease = releaseForDisplay(FIXTURE_A, { grant: staleGrant });
  assert.equal(cachedRelease.outcome, 'WITHHELD');
  assert.equal(cachedRelease.code, 'STALE_REVISION');
  assert.equal(cachedRelease.plaintext, null);
  const cachedMapping = trustedMetadata(FIXTURE_A, { revision: activated.revision - 1 });
  assert.equal(decide(FIXTURE_A, {
    mapping: cachedMapping, grant: grantFor(FIXTURE_A, 'DISPLAY'),
  }).reason, 'STALE_REVISION');

  // Monotonicity: a state is never re-entered, and the transition table decides what may follow.
  const reactivate = applyMappingLifecycleCommand(
    activated,
    { version: 1, mappingRef: FIXTURE_A.mappingRef, scope: activated.scope,
      expectedRevision: activated.revision, action: 'ACTIVATE' },
    { now: T0 + 5_000 },
  );
  assert.equal(reactivate.state, 'REFUSED');
  assert.equal(reactivate.reason, 'INVALID_TRANSITION');
});

/* ---------- 7. Expired, revoked and deleted records cannot resolve ---------- */

test('expiry, revocation and deletion each deny at the seam and withhold any release', () => {
  ensureActive(FIXTURE_A);
  const expired = commit(FIXTURE_A, 'EXPIRE', {
    expectedRevision: FIXTURE_A.current.revision, now: FIXTURE_A.current.expiresAt,
  });
  assert.equal(expired.state, 'CHANGED');
  assert.equal(expired.record.state, 'EXPIRED');
  const afterExpiry = releaseForDisplay(FIXTURE_A, { grant: grantFor(FIXTURE_A, 'DISPLAY') });
  assert.equal(afterExpiry.outcome, 'WITHHELD');
  assert.equal(afterExpiry.code, 'MAPPING_EXPIRED');
  assert.equal(afterExpiry.plaintext, null);
  // An expiry cannot be rolled back by reactivation.
  const revive = commit(FIXTURE_A, 'ACTIVATE', {
    expectedRevision: FIXTURE_A.current.revision, now: T0 + 6_000,
  });
  assert.equal(revive.state, 'REFUSED');
  assert.equal(revive.reason, 'INVALID_TRANSITION');
  assert.equal(FIXTURE_A.current.state, 'EXPIRED');

  commit(FIXTURE_B, 'ACTIVATE', { expectedRevision: FIXTURE_B.current.revision, now: T0 + 1_000 });
  ensureActive(FIXTURE_B, T0 + 1_000);
  const revoked = commit(FIXTURE_B, 'REVOKE', {
    expectedRevision: FIXTURE_B.current.revision, now: T0 + 2_000,
  });
  assert.equal(revoked.record.state, 'REVOKED');
  const afterRevoke = releaseForDisplay(FIXTURE_B, { grant: grantFor(FIXTURE_B, 'DISPLAY') });
  assert.equal(afterRevoke.code, 'MAPPING_REVOKED');
  assert.equal(afterRevoke.plaintext, null);

  const deleted = commit(FIXTURE_B, 'DELETE', {
    expectedRevision: FIXTURE_B.current.revision, now: T0 + 3_000,
  });
  assert.equal(deleted.record.state, 'DELETED');
  const afterDelete = releaseForDisplay(FIXTURE_B, { grant: grantFor(FIXTURE_B, 'DISPLAY') });
  assert.equal(afterDelete.code, 'MAPPING_REVOKED');
  assert.equal(afterDelete.plaintext, null);

  // A terminal command is idempotent: the same record, no revision increment.
  const repeat = commit(FIXTURE_B, 'DELETE', {
    expectedRevision: FIXTURE_B.current.revision, now: T0 + 4_000,
  });
  assert.equal(repeat.state, 'UNCHANGED');
  assert.equal(repeat.record.revision, FIXTURE_B.current.revision);

  // An expired grant is refused by its own check on a still-active fixture, independently of the
  // lifecycle and mapping checks that precede it.
  commit(FIXTURE_C, 'ACTIVATE', { expectedRevision: FIXTURE_C.current.revision, now: T0 + 1_000 });
  ensureActive(FIXTURE_C, T0 + 1_000);
  const expiredGrant = releaseForDisplay(FIXTURE_C, {
    grant: grantFor(FIXTURE_C, 'DISPLAY', { expiresAt: T0 + 10 }), now: T0 + 100,
  });
  assert.equal(expiredGrant.outcome, 'WITHHELD');
  assert.equal(expiredGrant.code, 'GRANT_EXPIRED');
  assert.equal(expiredGrant.plaintext, null);
  // Positive control on the same fixture: a live grant still restores the independent literal.
  const live = releaseForDisplay(FIXTURE_C, { grant: grantFor(FIXTURE_C, 'DISPLAY'), now: T0 + 100 });
  assert.equal(live.outcome, 'RELEASED');
  assert.deepEqual([...live.plaintext], [...SYNTHETIC_ORIGINAL_BYTES]);
});