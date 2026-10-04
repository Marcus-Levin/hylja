// #176 / synthetic integration test for the mapping round trip: the shipped mapping AEAD primitive
// (seal/open), the shipped keyed scope-bound entity reference derivation, the shipped purpose-bound
// mapping authorization seam and the shipped mapping lifecycle reducer are joined over one explicitly
// ephemeral in-process synthetic fixture.
//
// One revision authority. `fixture.current` is the only record of lifecycle, revision, scope and
// expiry in this file. It supplies the AEAD's expected AAD revision as well as the authorization
// metadata and the grant revision, so there is no second, frozen copy of the revision anywhere. A
// revision embedded in an envelope is never read back as authority: the expected scope is always
// recomputed from the current record, so a valid old envelope cannot authenticate itself as current.
//
// Privacy-safe assertions. No assertion in this file ever receives a crypto result object, a byte
// buffer, or a plaintext-versus-null operand. Every crypto result is read through `projectOpen`,
// which returns fixed enum strings, numbers and internally computed booleans only, and byte equality
// is decided inside `bytesEqual` and asserted as one boolean. The release path passes the restored
// bytes to a test-local inspector and returns only `outcome`, `code`, `released`, `matched` and
// `bytes`, so a synthetic original can reach neither ordinary evidence nor model capture.
//
// What this proves, precisely: over this fixture, with test-supplied trusted bindings (a literal
// synthetic DEK, HMAC key, host clock, authenticated workload and explicit grant), an original value
// exists only as AEAD ciphertext until the trusted host reads the fixture's authoritative current
// record, the operation is pinned to DISPLAY, and an actual AUTHORIZED DISPLAY decision from the real
// `authorizeMappingOperation` seam permits one `openMappingPayload` call under an expected scope
// recomputed from that current record; the restored bytes equal an independent literal expected
// outcome. USE does not imply DISPLAY or EXPORT, cross-scope references and records never resolve, an
// old but internally valid envelope refuses under a newer current revision while the matched current
// envelope releases, and lifecycle commits to the fixture's current revision so a stale revision or a
// cached snapshot cannot supersede it.
//
// What it is NOT: not a production vault, broker, KMS/HSM, key-management system, transaction, store,
// index, durable audit ledger, transport or model. It authenticates nobody: the DEK, the HMAC key,
// the grant, the authenticated subject, the clock and the current record are test fixtures. Re-sealing
// under a new current revision is controlled synthetic host setup, not a lifecycle rotation, rewrap or
// storage operation. No network, no provider traffic, no credentials, no held-out data, no comparison
// or recovery claim. Parent #15 stays open.
//
// Every fixture value is invented and obviously synthetic and non-routable (`.invalid` names, fixed
// byte fills, one planted marker string that is never a real person, host or credential).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  sealMappingPayload, openMappingPayload, MAPPING_AEAD_LIMITS, MAPPING_AEAD_FINDINGS,
} from '../dist/mapping-aead.js';
import { deriveScopedEntityReference, ENTITY_REFERENCE_TOKEN_PREFIX } from '../dist/scoped-entity-reference.js';
import { applyMappingLifecycleCommand } from '../dist/mapping-lifecycle.js';
import { authorizeMappingOperation } from '../dist/mapping-authorization.js';

/* ---------- Independent literal expectations and planted synthetic markers ---------- */

// The expected outcome is a literal written here, never recomputed from the implementation, and the
// value the fixture encrypts. Obviously synthetic, non-routable and not a credential or identity.
const SYNTHETIC_ORIGINAL = 'synthetic-original-verity-fixture.invalid';
const SYNTHETIC_ORIGINAL_BYTES = new TextEncoder().encode(SYNTHETIC_ORIGINAL);
const FOREIGN_ORIGINAL = 'synthetic-original-other-tenant-fixture.invalid';
const FOREIGN_ORIGINAL_BYTES = new TextEncoder().encode(FOREIGN_ORIGINAL);
const ENTITY_ID_A = 'entity-verity-fixture';
const ENTITY_ID_B = 'entity-oskar-fixture';

/**
 * Byte equality decided here and returned as one boolean, so every caller asserts a boolean and a
 * failure prints `true`/`false`. Asserting a plaintext buffer directly would put the synthetic
 * original's bytes into ordinary test output, which this file never does.
 */
function bytesEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) return false;
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/**
 * The trusted test-local inspector. It sees the restored bytes inside the release path and returns
 * only one boolean. The original never leaves this callback: it is not returned, not recorded and
 * never becomes an assertion operand, and the caller receives `matched` alone.
 */
const RESTORED_EXACTLY = (plaintext) => bytesEqual(plaintext, SYNTHETIC_ORIGINAL_BYTES);

/* ---------- Privacy-safe projections: fixed enum strings, numbers and booleans only ---------- */

/**
 * Reads one crypto result into fixed fields. No property of the returned object is a byte buffer or
 * a caller value, so a failure on any assertion built from it prints codes and numbers only. Every
 * reading is guarded: a hostile or unreadable result degrades to `UNREADABLE` and never escapes.
 */
function projectOpen(value) {
  const projection = {
    version: 0, status: 'UNREADABLE', finding: 'UNREADABLE', findingIsKnown: false,
    hasPlaintext: false, hasBytes: false, plaintextIsBuffer: false, plaintextBytes: 0,
    plaintextIsEmpty: true,
  };
  try {
    projection.hasPlaintext = 'plaintext' in value;
    projection.hasBytes = 'bytes' in value;
    if (value?.version === 1) projection.version = 1;
    if (value?.status === 'OPENED' || value?.status === 'REFUSED') projection.status = value.status;
    if (typeof value?.finding === 'string' && MAPPING_AEAD_FINDINGS.includes(value.finding)) {
      projection.finding = value.finding;
      projection.findingIsKnown = true;
    }
    const plaintext = value?.plaintext;
    if (plaintext instanceof Uint8Array) {
      projection.plaintextIsBuffer = true;
      projection.plaintextBytes = plaintext.byteLength;
      projection.plaintextIsEmpty = plaintext.byteLength === 0;
    }
  } catch {
    // A hostile result stays UNREADABLE. Nothing read from it is echoed anywhere.
  }
  return projection;
}

/**
 * Whether a value graph holds a byte buffer or the planted marker string. Returned as one boolean and
 * used only as an assertion operand. Anything unreadable, symbol-keyed, accessor-backed or deeper
 * than the bound counts as unsafe, so this check fails closed rather than passing on a value it could
 * not examine.
 *
 * `allowAccessors` is set only for one call: a caught assertion error carries a runtime-installed
 * lazily-formatted `stack` accessor, and invoking an accessor in order to inspect it would run code to
 * look for plaintext. That walk therefore skips accessors without reading them, and the operands that
 * actually reach the assertion - `actual` and `expected` - are checked separately, unskipped.
 */
function graphCarriesPlaintext(value, depth = 0, allowAccessors = false) {
  if (value instanceof Uint8Array) return true;
  if (typeof value === 'string') return value.includes('synthetic-original');
  if (value === null || typeof value !== 'object') return false;
  if (depth >= 3) return true;
  try {
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') return true;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor) return true;
      if (!('value' in descriptor)) {
        if (!allowAccessors) return true;
        continue;
      }
      if (graphCarriesPlaintext(descriptor.value, depth + 1)) return true;
    }
  } catch {
    return true;
  }
  return false;
}

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
// A second tenant scope that deliberately shares A's original, entity id, DEK and HMAC key. Only the
// scope differs, so any reference or ciphertext difference below is attributable to scope alone.
const TENANT_A2 = Object.freeze({
  tenantId: 'tenant-alpha-alt.invalid', projectId: 'project-alpha-alt.invalid',
  sessionId: 'session-alpha-alt.invalid',
});
const TENANT_B = Object.freeze({
  tenantId: 'tenant-beta.invalid', projectId: 'project-beta.invalid', sessionId: 'session-beta.invalid',
});
const TENANT_C = Object.freeze({
  tenantId: 'tenant-gamma.invalid', projectId: 'project-gamma.invalid', sessionId: 'session-gamma.invalid',
});
const TENANT_D = Object.freeze({
  tenantId: 'tenant-delta.invalid', projectId: 'project-delta.invalid', sessionId: 'session-delta.invalid',
});
const TENANT_E = Object.freeze({
  tenantId: 'tenant-echo.invalid', projectId: 'project-echo.invalid', sessionId: 'session-echo.invalid',
});
// A sixth, reserved for the old-envelope-against-current-revision case so no other test's commits
// can influence it.
const TENANT_F = Object.freeze({
  tenantId: 'tenant-foxtrot.invalid', projectId: 'project-foxtrot.invalid',
  sessionId: 'session-foxtrot.invalid',
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
  assert.equal(modelCapture.length > 0, true);
  for (const entry of modelCapture) {
    assert.equal(typeof entry, 'string');
    assert.equal(entry.includes(SYNTHETIC_ORIGINAL), false);
    assert.equal(entry.includes(FOREIGN_ORIGINAL), false);
    assert.equal(entry.includes('synthetic-original'), false);
  }
}

/* ---------- The ephemeral fixture: ciphertext plus non-secret metadata only ---------- */

/**
 * One ephemeral tenant fixture. It holds the sealed record, the host-held key material and the
 * metadata the trusted host would read. It stores no original value and no plaintext: the plaintext is
 * passed in from the module-level literal for the moment it is sealed and is never retained on the
 * fixture, so the only value this object can ever release is what `openMappingPayload` decrypts from
 * the ciphertext it stores.
 * `current` is the fixture's single authority: lifecycle, revision, scope and expiry all come from
 * this record, and the AEAD's expected revision is recomputed from it on every open.
 */
function makeFixture({ scope, key, hmacKey, entityId, plaintext, createdAt, expiresAt }) {
  const reference = deriveScopedEntityReference({
    scope: 'SESSION', tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId,
    entityId, semanticType: 'PERSON', keyVersion: KEY_VERSION, key: hmacKey,
  });
  assert.equal(reference.state, 'DERIVED');
  const fixture = {
    scope, key, hmacKey, entityId, mappingRef: reference.token,
    current: Object.freeze({
      version: 1, mappingRef: reference.token,
      scope: { tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId },
      state: 'CREATED', revision: 1, createdAt, expiresAt,
    }),
    // The revision the stored envelope was sealed under. It is a fact about the ciphertext, never an
    // input to any decision: nothing reads it back as the expected revision.
    sealedRevision: 0,
    envelope: undefined,
  };
  resealUnderCurrentRevision(fixture, plaintext);
  return fixture;
}

/**
 * The expected AEAD scope, recomputed from the fixture's authoritative current record on every call.
 * This is the only place an AAD revision comes from, and it is never cached, frozen at seal time or
 * copied out of an envelope.
 */
function expectedScope(fixture) {
  return {
    tenantId: fixture.scope.tenantId, projectId: fixture.scope.projectId, entityId: fixture.entityId,
    classification: 'PERSON', mappingRevision: String(fixture.current.revision), keyVersion: KEY_VERSION,
  };
}

/**
 * Seals the fixture's current value under the revision that is now authoritative, drawing a fresh
 * synthetic nonce from the shipped primitive on every call. This is controlled synthetic host setup
 * for a test that needs the stored ciphertext to match the current record; it is **not** a lifecycle
 * rotation, a rewrap, a key rotation or a store. The reducer rotates nothing, the same DEK is reused
 * deliberately so only the revision differs, and the nonce is never reused to re-seal.
 */
function resealUnderCurrentRevision(fixture, plaintext) {
  const previousNonce = fixture.envelope?.nonce;
  const sealed = sealMappingPayload({
    scope: expectedScope(fixture), plaintext, key: fixture.key,
  });
  assert.equal(sealed.status, 'SEALED');
  fixture.envelope = sealed.envelope;
  fixture.sealedRevision = fixture.current.revision;
  if (previousNonce !== undefined) {
    assert.equal(bytesEqual(sealed.envelope.nonce, previousNonce), false);
  }
  return sealed.envelope;
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
    sealedRevision: fixture.sealedRevision,
    expiresAt: fixture.current.expiresAt,
    keyVersion: KEY_VERSION,
  });
}

/**
 * Each open attempt gets its own copy of the sealed record so repeated attempts over one fixture do not
 * share buffers. The accepted AEAD contract is explicit that `openMappingPayload` never overwrites a
 * buffer the caller supplied and never overwrites the plaintext it returns: it clears only the owned
 * snapshots it took of the key and the envelope, and that hygiene is best effort in JavaScript, not a
 * zeroization guarantee for copies inside native crypto, garbage-collected buffers or swapped pages.
 * Cloning here is therefore harness convenience for reuse of the fixture, not a retention or
 * durability claim.
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

/**
 * Whether one mapping snapshot is still the fixture's authoritative current record. The trusted host
 * reads the current record; it never adopts a cached snapshot. A snapshot that disagrees on the
 * reference, lifecycle, revision, expiry or any scope part is superseded, and the host refuses it
 * before any decision and long before any open. This is the trusted host's own duty, not store
 * semantics: there is no row lock, transaction or compare-and-set anywhere in this fixture.
 */
function snapshotIsCurrent(fixture, mapping) {
  const record = fixture.current;
  return mapping !== null && typeof mapping === 'object'
    && mapping.mappingRef === fixture.mappingRef
    && mapping.mappingRef === record.mappingRef
    && mapping.lifecycle === record.state
    && mapping.revision === record.revision
    && mapping.expiresAt === record.expiresAt
    && mapping.scope?.tenantId === record.scope.tenantId
    && mapping.scope?.projectId === record.scope.projectId
    && mapping.scope?.sessionId === record.scope.sessionId;
}

/** One explicit, purpose-bound, finite grant, pinned to the same current revision as everything else. */
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
  operation, subject = WORKLOAD, scope = fixture.current.scope, destination = DESTINATION,
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

/** One withheld outcome. Fixed strings and booleans only; there is no field a buffer could enter. */
function withheldOutcome(code) {
  return { outcome: captureForModel('WITHHELD'), code, released: false, matched: false, bytes: 0 };
}

/**
 * The DISPLAY release path. Three independent gates stand between a fixture and a plaintext, in this
 * order: the snapshot presented must still be the fixture's current record, the operation is pinned
 * to DISPLAY *after* caller options are applied so no option can substitute USE or EXPORT for it, and
 * only an actual AUTHORIZED decision from the real seam permits one real open under the expected scope
 * recomputed from that current record. Withhold at any gate and no `openMappingPayload` call is made
 * at all, so no plaintext can exist in this process on that path.
 *
 * On the release path the restored bytes go to `inspect`, a trusted test-local callback that returns
 * one boolean, and are then overwritten here. Nothing else can see them: the returned record carries
 * only `outcome`, `code`, `released`, `matched` and `bytes`.
 */
function releaseForDisplay(fixture, options = {}, inspect = RESTORED_EXACTLY) {
  const mapping = options.mapping ?? trustedMetadata(fixture);
  if (!snapshotIsCurrent(fixture, mapping)) return withheldOutcome('SNAPSHOT_SUPERSEDED');
  // The operation is pinned last and is never taken from options: this path is DISPLAY by construction.
  const decision = decide(fixture, { ...options, mapping, operation: 'DISPLAY' });
  if (decision.state !== 'AUTHORIZED') return withheldOutcome(decision.reason);
  const opened = openMappingPayload({
    scope: expectedScope(fixture), envelope: cloneEnvelope(fixture.envelope), key: fixture.key,
  });
  const projection = projectOpen(opened);
  if (projection.status !== 'OPENED') return withheldOutcome(projection.finding);
  const matched = inspect(opened.plaintext) === true;
  const bytes = projection.plaintextBytes;
  // Best-effort hygiene in JavaScript, not a zeroization guarantee: the buffer this process still holds
  // is overwritten here so the restored bytes do not outlive the inspection.
  opened.plaintext.fill(0);
  return { outcome: captureForModel('RELEASED'), code: projection.finding, released: true, matched,
    bytes };
}

/**
 * The trusted USE path: the operation is pinned to USE after caller options are applied, an authorized
 * USE returns a fixed non-secret outcome only, and the original is never resolved here, so a USE can
 * never become a reveal and a DISPLAY grant cannot be spent as a USE.
 */
function useMapping(fixture, options = {}) {
  const decision = decide(fixture, { ...options, operation: 'USE' });
  if (decision.state !== 'AUTHORIZED') {
    return { outcome: captureForModel('WITHHELD'), code: decision.reason, used: false };
  }
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

/**
 * Brings one fixture to ACTIVE through the real reducer, so each test does not depend on a previous
 * test's commit, and then re-seals the fixture's value under the now-current revision so its stored
 * ciphertext is the one the current record describes. There is no lifecycle bypass: activation always
 * goes through the reducer. Tests that must exercise a stale ciphertext call `commit` directly
 * instead, deliberately skipping the re-seal.
 */
function ensureActive(fixture, plaintext, now = T0 + 1_500) {
  if (fixture.current.state === 'CREATED') {
    const activated = commit(fixture, 'ACTIVATE', { expectedRevision: fixture.current.revision, now });
    assert.equal(activated.state, 'CHANGED');
    assert.equal(activated.record.state, 'ACTIVE');
  }
  resealUnderCurrentRevision(fixture, plaintext);
  return fixture.current;
}

const FIXTURE_A = makeFixture({
  scope: TENANT_A, key: DEK_A, hmacKey: HMAC_A, entityId: ENTITY_ID_A,
  plaintext: SYNTHETIC_ORIGINAL_BYTES, createdAt: T0, expiresAt: T0 + TTL_MS,
});
// Same synthetic original, same entity id, same DEK, same HMAC key as A; a different tenant scope.
const FIXTURE_A2 = makeFixture({
  scope: TENANT_A2, key: DEK_A, hmacKey: HMAC_A, entityId: ENTITY_ID_A,
  plaintext: SYNTHETIC_ORIGINAL_BYTES, createdAt: T0, expiresAt: T0 + TTL_MS,
});
const FIXTURE_B = makeFixture({
  scope: TENANT_B, key: DEK_B, hmacKey: HMAC_B, entityId: ENTITY_ID_B,
  plaintext: FOREIGN_ORIGINAL_BYTES, createdAt: T0, expiresAt: T0 + TTL_MS,
});
// A third ephemeral fixture, a third synthetic tenant, used only for the grant-expiry controls.
const FIXTURE_C = makeFixture({
  scope: TENANT_C, key: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x66),
  hmacKey: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x77),
  entityId: 'entity-juno-fixture', plaintext: SYNTHETIC_ORIGINAL_BYTES, createdAt: T0,
  expiresAt: T0 + TTL_MS,
});
// A fourth and fifth, each dedicated to one authority control so no test depends on another's commits.
const FIXTURE_D = makeFixture({
  scope: TENANT_D, key: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x88),
  hmacKey: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0x99),
  entityId: 'entity-delta-fixture', plaintext: SYNTHETIC_ORIGINAL_BYTES, createdAt: T0,
  expiresAt: T0 + TTL_MS,
});
const FIXTURE_E = makeFixture({
  scope: TENANT_E, key: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0xaa),
  hmacKey: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0xbb),
  entityId: 'entity-echo-fixture', plaintext: SYNTHETIC_ORIGINAL_BYTES, createdAt: T0,
  expiresAt: T0 + TTL_MS,
});

/* ---------- 1. Accepted DISPLAY round-trip exactness ---------- */

test('an original is restored byte-exactly only after an actual AUTHORIZED DISPLAY decision', () => {
  ensureActive(FIXTURE_A, SYNTHETIC_ORIGINAL_BYTES);
  resetModelCapture();
  // Control: with no grant at all the seam denies, and nothing is opened. The lifecycle and mapping
  // checks precede the absent-grant check, so the fixture is active first.
  const withheld = releaseForDisplay(FIXTURE_A, { grant: undefined });
  assert.equal(withheld.outcome, 'WITHHELD');
  assert.equal(withheld.code, 'NO_GRANT');
  assert.equal(withheld.released, false);
  assert.equal(withheld.matched, false);
  assert.equal(withheld.bytes, 0);

  // Positive: an explicit DISPLAY grant over the active current record authorizes one open.
  const released = releaseForDisplay(FIXTURE_A, { grant: grantFor(FIXTURE_A, 'DISPLAY') });
  assert.equal(released.outcome, 'RELEASED');
  assert.equal(released.code, 'OPENED');
  assert.equal(released.released, true);
  // The oracle is the independent literal's own encoding, decided inside the release path and asserted
  // here as one boolean, so a failure prints `true`/`false` and never a byte of the synthetic original.
  assert.equal(released.matched, true);
  assert.equal(released.bytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  assertCaptureIsNonSecret();
});

/* ---------- 2. The fixture holds ciphertext and non-secret metadata only ---------- */

test('the ephemeral fixture holds ciphertext plus non-secret metadata and never the original', () => {
  const serialized = serializeFixture(FIXTURE_A);
  // No planted marker reaches a ciphertext-only serialized image. This is a marker search, not a
  // ciphertext-versus-plaintext inequality claim: an AEAD ciphertext may equal its plaintext bytes.
  assert.equal(serialized.includes(SYNTHETIC_ORIGINAL), false);
  assert.equal(serialized.includes('synthetic-original'), false);
  // The opaque keyed reference is present and is the only identifier the fixture exposes.
  assert.equal(serialized.includes(FIXTURE_A.mappingRef), true);
  assert.equal(FIXTURE_A.mappingRef.startsWith(ENTITY_REFERENCE_TOKEN_PREFIX), true);
  assert.equal('plaintext' in FIXTURE_A, false);
  assert.equal('original' in FIXTURE_A, false);
  // The sealed record is the ciphertext plus its own full-length tag; the fixture holds no key and no
  // scope authority inside it. Lengths only: an AEAD ciphertext may equal its plaintext byte for byte.
  assert.equal(FIXTURE_A.envelope.ciphertext.byteLength, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  assert.equal(FIXTURE_A.envelope.tag.byteLength, MAPPING_AEAD_LIMITS.tagBytes);
  assert.equal(FIXTURE_A.envelope.nonce.byteLength, MAPPING_AEAD_LIMITS.nonceBytes);
  assert.equal('key' in FIXTURE_A.envelope, false);
  assert.equal('scope' in FIXTURE_A.envelope, false);
  // The stored ciphertext is sealed under the current revision: one authority, no frozen AAD copy.
  assert.equal(FIXTURE_A.sealedRevision, FIXTURE_A.current.revision);
  assert.equal(serialized.includes(`"sealedRevision":${FIXTURE_A.current.revision}`), true);
});

/* ---------- 3. USE does not imply DISPLAY or EXPORT ---------- */

test('a USE-only grant authorizes USE and denies DISPLAY and EXPORT, and USE reveals nothing', () => {
  resetModelCapture();
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
    assert.equal(withheld.released, false);
  }

  // The model capture holds fixed non-secret outcomes and the opaque reference, never an original.
  captureForModel(FIXTURE_A.mappingRef);
  assertCaptureIsNonSecret();
  resetModelCapture();
});

/* ---------- 4. Neither operation can be substituted for the other ---------- */

test('the operation is pinned per path: a USE grant is not a DISPLAY, and a DISPLAY is not a USE', () => {
  ensureActive(FIXTURE_D, SYNTHETIC_ORIGINAL_BYTES);
  resetModelCapture();
  const useGrant = grantFor(FIXTURE_D, 'USE');
  const displayGrant = grantFor(FIXTURE_D, 'DISPLAY');

  // A caller cannot substitute its own operation onto the DISPLAY release path: the path pins DISPLAY
  // after caller options are applied, so the USE-only grant is judged as a DISPLAY request and denied.
  for (const requested of ['USE', 'EXPORT']) {
    const override = releaseForDisplay(FIXTURE_D, { grant: useGrant, operation: requested });
    assert.equal(override.outcome, 'WITHHELD');
    assert.equal(override.code, 'OPERATION_NOT_GRANTED');
    assert.equal(override.released, false);
  }
  // The same substitution in the other direction: a DISPLAY grant cannot be spent as a USE.
  const usedAsDisplay = useMapping(FIXTURE_D, { grant: displayGrant, operation: 'DISPLAY' });
  assert.equal(usedAsDisplay.used, false);
  assert.equal(usedAsDisplay.code, 'OPERATION_NOT_GRANTED');

  // Positive controls on the same fixture, both against the pinned paths: the USE grant authorizes
  // USE, and the DISPLAY grant authorizes exactly one DISPLAY release. Without these the refusals above
  // could be vacuous.
  const used = useMapping(FIXTURE_D, { grant: useGrant });
  assert.equal(used.used, true);
  assert.equal(used.code, 'AUTHORIZED');
  const released = releaseForDisplay(FIXTURE_D, { grant: displayGrant });
  assert.equal(released.outcome, 'RELEASED');
  assert.equal(released.matched, true);
  assertCaptureIsNonSecret();
  resetModelCapture();
});

/* ---------- 5. Scope-bound references and cross-scope nonresolution ---------- */

test('one original yields distinct references per tenant, and a foreign scope never resolves', () => {
  ensureActive(FIXTURE_A, SYNTHETIC_ORIGINAL_BYTES);
  ensureActive(FIXTURE_B, FOREIGN_ORIGINAL_BYTES);
  // The same synthetic original sealed in both tenants, under both a derived reference and a DEK.
  assert.equal(FIXTURE_A.mappingRef !== FIXTURE_B.mappingRef, true);
  assert.equal(deriveScopedEntityReference({
    scope: 'TENANT', tenantId: TENANT_A.tenantId, entityId: ENTITY_ID_A, semanticType: 'PERSON',
    keyVersion: KEY_VERSION, key: HMAC_A,
  }).state, 'DERIVED');

  // Tenant B's sealed record, presented inside tenant A's authenticated context, is not authorized.
  const foreignReference = decide(FIXTURE_A, { operation: 'DISPLAY', mappingRef: FIXTURE_B.mappingRef });
  assert.equal(foreignReference.reason, 'UNKNOWN_MAPPING');
  const foreignTenant = decide(FIXTURE_A, {
    operation: 'DISPLAY', scope: TENANT_B, hostScope: TENANT_B, grant: grantFor(FIXTURE_A, 'DISPLAY'),
    mapping: trustedMetadata(FIXTURE_A),
  });
  assert.equal(foreignTenant.state, 'DENIED');
  assert.equal(foreignTenant.reason, 'SCOPE_MISMATCH');
  const foreignSession = decide(FIXTURE_A, {
    operation: 'DISPLAY', scope: { ...TENANT_A, sessionId: TENANT_B.sessionId },
    grant: grantFor(FIXTURE_A, 'DISPLAY'),
  });
  assert.equal(foreignSession.reason, 'SCOPE_MISMATCH');
  const foreignSubject = decide(FIXTURE_A, {
    operation: 'DISPLAY', subject: FOREIGN_WORKLOAD, grant: grantFor(FIXTURE_A, 'DISPLAY'),
  });
  assert.equal(foreignSubject.reason, 'SCOPE_MISMATCH');
  // The request and the observed sink still agree here, so the foreign destination is caught by the
  // grant's own destination binding instead.
  const foreignDestination = decide(FIXTURE_A, {
    operation: 'DISPLAY', destination: FOREIGN_DESTINATION, grant: grantFor(FIXTURE_A, 'DISPLAY'),
  });
  assert.equal(foreignDestination.state, 'DENIED');
  assert.equal(foreignDestination.reason, 'GRANT_MISMATCH');

  // Even bypassing authorization, tenant B's ciphertext cannot be opened in tenant A's scope: the AAD
  // binds the tenant and the DEK differs, so no foreign original or metadata is returned.
  const crossOpen = projectOpen(openMappingPayload({
    scope: expectedScope(FIXTURE_A), envelope: cloneEnvelope(FIXTURE_B.envelope), key: FIXTURE_A.key,
  }));
  assert.equal(crossOpen.status, 'REFUSED');
  assert.equal(crossOpen.finding, 'AUTHENTICATION_FAILED');
  assert.equal(crossOpen.hasPlaintext, false);
  assert.equal(crossOpen.hasBytes, false);
  assert.equal(crossOpen.plaintextIsBuffer, false);
});

/* ---------- 6. The controlled same-original, same-entity, same-key scope contrast ---------- */

test('the same original, entity and key under one other tenant scope still yield a distinct reference', () => {
  // A and A2 hold the identical synthetic original, entity id, DEK, HMAC key and key version. Only the
  // tenant, project and session differ, so a difference below is attributable to scope alone and not
  // to a different value, a different entity or a different key.
  assert.equal(FIXTURE_A2.scope.tenantId !== FIXTURE_A.scope.tenantId, true);
  assert.equal(FIXTURE_A2.mappingRef !== FIXTURE_A.mappingRef, true);
  assert.equal(FIXTURE_A2.mappingRef.startsWith(ENTITY_REFERENCE_TOKEN_PREFIX), true);

  // The same contrast at the narrower TENANT derivation scope, with the same entity and HMAC key.
  const tenantScoped = [TENANT_A, TENANT_A2].map((scope) => deriveScopedEntityReference({
    scope: 'TENANT', tenantId: scope.tenantId, entityId: ENTITY_ID_A, semanticType: 'PERSON',
    keyVersion: KEY_VERSION, key: HMAC_A,
  }));
  assert.equal(tenantScoped[0].state, 'DERIVED');
  assert.equal(tenantScoped[1].state, 'DERIVED');
  assert.equal(tenantScoped[0].token === tenantScoped[1].token, false);

  // Identical plaintext bytes and an identical key, but the AAD binds the tenant: the ciphertexts are
  // not interchangeable, and neither opens in the other's scope.
  const crossOpen = projectOpen(openMappingPayload({
    scope: expectedScope(FIXTURE_A), envelope: cloneEnvelope(FIXTURE_A2.envelope), key: FIXTURE_A.key,
  }));
  assert.equal(crossOpen.status, 'REFUSED');
  assert.equal(crossOpen.finding, 'AUTHENTICATION_FAILED');
  assert.equal(crossOpen.hasPlaintext, false);
  assert.equal(crossOpen.hasBytes, false);

  // Controls: each record still opens under its own current scope and restores the same independent
  // literal, asserted through the release path so no byte reaches the output.
  for (const fixture of [FIXTURE_A, FIXTURE_A2]) {
    ensureActive(fixture, SYNTHETIC_ORIGINAL_BYTES);
    const opened = releaseForDisplay(fixture, { grant: grantFor(fixture, 'DISPLAY') });
    assert.equal(opened.outcome, 'RELEASED');
    assert.equal(opened.matched, true);
  }
  // And a foreign reference is still denied at the seam in the other tenant's scope.
  const foreign = decide(FIXTURE_A2, {
    operation: 'DISPLAY', mappingRef: FIXTURE_A.mappingRef, grant: grantFor(FIXTURE_A2, 'DISPLAY'),
  });
  assert.equal(foreign.state, 'DENIED');
  assert.equal(foreign.reason, 'UNKNOWN_MAPPING');
});

/* ---------- 7. AEAD failures produce zero plaintext, through the projection only ---------- */

test('tampering, a wrong key and a wrong AAD each fail with zero plaintext capture', () => {
  const cases = {
    wrongKey: () => openMappingPayload({
      scope: expectedScope(FIXTURE_A), envelope: cloneEnvelope(FIXTURE_A.envelope), key: UNRELATED_DEK,
    }),
    wrongClassification: () => openMappingPayload({
      scope: { ...expectedScope(FIXTURE_A), classification: 'USER_ACCOUNT' },
      envelope: cloneEnvelope(FIXTURE_A.envelope), key: FIXTURE_A.key,
    }),
    wrongRevision: () => openMappingPayload({
      scope: { ...expectedScope(FIXTURE_A), mappingRevision: '99' },
      envelope: cloneEnvelope(FIXTURE_A.envelope), key: FIXTURE_A.key,
    }),
    wrongKeyVersion: () => openMappingPayload({
      scope: { ...expectedScope(FIXTURE_A), keyVersion: '2.0' },
      envelope: cloneEnvelope(FIXTURE_A.envelope), key: FIXTURE_A.key,
    }),
    tamperedCiphertext: () => {
      const envelope = cloneEnvelope(FIXTURE_A.envelope);
      envelope.ciphertext[0] = (envelope.ciphertext[0] + 1) & 0xff;
      return openMappingPayload({ scope: expectedScope(FIXTURE_A), envelope, key: FIXTURE_A.key });
    },
    tamperedTag: () => {
      const envelope = cloneEnvelope(FIXTURE_A.envelope);
      envelope.tag[0] = (envelope.tag[0] + 1) & 0xff;
      return openMappingPayload({ scope: expectedScope(FIXTURE_A), envelope, key: FIXTURE_A.key });
    },
    foreignEntity: () => openMappingPayload({
      scope: { ...expectedScope(FIXTURE_A), entityId: ENTITY_ID_B },
      envelope: cloneEnvelope(FIXTURE_A.envelope), key: FIXTURE_A.key,
    }),
  };
  for (const [name, run] of Object.entries(cases)) {
    // Every crypto assertion reads the projection, never the result object itself, so a regression
    // that returned OPENED here would still print only fixed codes and booleans.
    const projection = projectOpen(run());
    assert.equal(projection.version, 1, name);
    assert.equal(projection.status, 'REFUSED', name);
    assert.equal(projection.finding, 'AUTHENTICATION_FAILED', name);
    assert.equal(projection.findingIsKnown, true, name);
    assert.equal(projection.hasPlaintext, false, name);
    assert.equal(projection.hasBytes, false, name);
    assert.equal(projection.plaintextIsBuffer, false, name);
    assert.equal(projection.plaintextIsEmpty, true, name);
    // A refusal is one fixed code: it carries no planted value and no native error text.
    assert.equal(graphCarriesPlaintext(projection), false, name);
  }
  // Control: the untouched record still opens, so the refusals above are not vacuous.
  const control = projectOpen(openMappingPayload({
    scope: expectedScope(FIXTURE_A), envelope: cloneEnvelope(FIXTURE_A.envelope), key: FIXTURE_A.key,
  }));
  assert.equal(control.status, 'OPENED');
  assert.equal(control.hasPlaintext, true);
  assert.equal(control.plaintextIsBuffer, true);
  assert.equal(control.plaintextBytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);
});

/* ---------- 8. The diagnostic path cannot print an opened result's plaintext ---------- */

test('a planted OPENED result cannot carry plaintext into a caught assertion', () => {
  // An intentionally OPENED result whose `plaintext` field really is a byte buffer, standing in for the
  // regression this projection exists to contain: a refusal path that starts returning plaintext.
  const planted = {
    version: 1, status: 'OPENED', finding: 'OPENED',
    plaintext: SYNTHETIC_ORIGINAL_BYTES, bytes: SYNTHETIC_ORIGINAL_BYTES.byteLength,
  };
  const projection = projectOpen(planted);
  assert.equal(projection.status, 'OPENED');
  assert.equal(projection.finding, 'OPENED');
  assert.equal(projection.hasPlaintext, true);
  assert.equal(projection.hasBytes, true);
  assert.equal(projection.plaintextIsBuffer, true);
  assert.equal(projection.plaintextBytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  // The projection is itself safe to assert on: no buffer, no planted marker anywhere in its graph.
  assert.equal(graphCarriesPlaintext(projection), false);

  // The failing assertion below therefore receives only two fixed codes as operands.
  let caught;
  try {
    assert.equal(projection.status, 'REFUSED');
  } catch (error) {
    caught = error;
  }
  assert.equal(caught !== undefined, true);
  assert.equal(typeof caught.actual, 'string');
  assert.equal(typeof caught.expected, 'string');
  assert.equal(caught.actual, 'OPENED');
  assert.equal(caught.expected, 'REFUSED');
  // And the caught error's own actual/expected graph carries neither a buffer nor the marker. This is
  // the check the projection exists to satisfy, so it is asserted, not assumed.
  assert.equal(graphCarriesPlaintext(caught, 0, true), false);
  assert.equal(graphCarriesPlaintext(caught.actual), false);
  assert.equal(graphCarriesPlaintext(caught.expected), false);

  // The negative control for that check: it really does fire on a graph that holds the bytes, so the
  // assertions above are not vacuously true.
  assert.equal(graphCarriesPlaintext({ nested: { deeper: SYNTHETIC_ORIGINAL_BYTES } }), true);
  assert.equal(graphCarriesPlaintext({ nested: SYNTHETIC_ORIGINAL }), true);
  assert.equal(graphCarriesPlaintext({ version: 1, status: 'REFUSED' }), false);
});

/* ---------- 9. One current revision authority, and an old envelope refuses under it ---------- */

test('an old valid envelope refuses under the current revision while the current envelope releases', () => {
  resetModelCapture();
  // Built at the creation revision 1, so its stored ciphertext is sealed under revision 1.
  const fixture = makeFixture({
    scope: TENANT_F, key: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0xcc),
    hmacKey: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(0xdd),
    entityId: 'entity-foxtrot-fixture', plaintext: SYNTHETIC_ORIGINAL_BYTES,
    createdAt: T0, expiresAt: T0 + TTL_MS,
  });
  assert.equal(fixture.current.revision, 1);
  assert.equal(fixture.sealedRevision, 1);

  // The current record moves to revision 2 through the real reducer. Nothing re-seals the fixture, so
  // its untouched ciphertext is now a coherent *old* record that still authenticates under revision 1.
  const activated = commit(fixture, 'ACTIVATE', { expectedRevision: 1, now: T0 + 1_500 });
  assert.equal(activated.state, 'CHANGED');
  assert.equal(activated.record.state, 'ACTIVE');
  assert.equal(fixture.current.revision, 2);
  assert.equal(fixture.sealedRevision, 1);

  // Current metadata, a current grant and a genuinely authorized DISPLAY: the only thing that can
  // refuse now is the stale ciphertext under the current expected revision.
  const decision = decide(fixture, { operation: 'DISPLAY', grant: grantFor(fixture, 'DISPLAY') });
  assert.equal(decision.state, 'AUTHORIZED');
  const stale = releaseForDisplay(fixture, { grant: grantFor(fixture, 'DISPLAY') });
  assert.equal(stale.outcome, 'WITHHELD');
  assert.equal(stale.code, 'AUTHENTICATION_FAILED');
  assert.equal(stale.released, false);
  assert.equal(stale.matched, false);
  assert.equal(stale.bytes, 0);

  // The expected AAD revision is the current record's, never the envelope's and never a frozen copy:
  // the ciphertext's own revision is a fact about it, not an authority over it.
  assert.equal(expectedScope(fixture).mappingRevision, '2');
  assert.equal(fixture.sealedRevision, 1);

  // Matched control: after the controlled host re-seal, the current envelope releases byte-exactly.
  const resealed = resealUnderCurrentRevision(fixture, SYNTHETIC_ORIGINAL_BYTES);
  assert.equal(fixture.sealedRevision, 2);
  assert.equal(resealed.nonce.byteLength, MAPPING_AEAD_LIMITS.nonceBytes);
  const current = releaseForDisplay(fixture, { grant: grantFor(fixture, 'DISPLAY') });
  assert.equal(current.outcome, 'RELEASED');
  assert.equal(current.released, true);
  assert.equal(current.matched, true);
  assert.equal(current.bytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  assertCaptureIsNonSecret();
});

/* ---------- 10. Lifecycle commits to the current revision ---------- */

test('the reducer commits monotonic revisions and a stale revision or snapshot cannot supersede them', () => {
  // One activation from a record created at revision 1 commits the literal revision 2. The oracle is
  // the literal, not a comparison against whatever the reducer happened to return.
  const activated = ensureActive(FIXTURE_A, SYNTHETIC_ORIGINAL_BYTES);
  assert.equal(activated.state, 'ACTIVE');
  assert.equal(activated.revision, 2);
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
  assert.equal(decide(FIXTURE_A, { operation: 'DISPLAY', grant: staleGrant }).reason, 'STALE_REVISION');
  const cachedRelease = releaseForDisplay(FIXTURE_A, { grant: staleGrant });
  assert.equal(cachedRelease.outcome, 'WITHHELD');
  assert.equal(cachedRelease.code, 'STALE_REVISION');
  assert.equal(cachedRelease.released, false);
  const cachedMapping = trustedMetadata(FIXTURE_A, { revision: activated.revision - 1 });
  assert.equal(decide(FIXTURE_A, {
    operation: 'DISPLAY', mapping: cachedMapping, grant: grantFor(FIXTURE_A, 'DISPLAY'),
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

/* ---------- 11. A coherent cached snapshot, grant and ciphertext cannot supersede the current record ---------- */

test('a cached ACTIVE snapshot with its own grant and the old ciphertext releases nothing after revocation', () => {
  ensureActive(FIXTURE_E, SYNTHETIC_ORIGINAL_BYTES);
  resetModelCapture();

  // The stale triple is captured while the record is genuinely ACTIVE at the literal revision 2.
  const activeRevision = FIXTURE_E.current.revision;
  assert.equal(activeRevision, 2);
  const cachedSnapshot = trustedMetadata(FIXTURE_E);
  assert.equal(cachedSnapshot.lifecycle, 'ACTIVE');
  assert.equal(cachedSnapshot.revision, 2);
  // A grant that is coherent with that snapshot: same reference, same revision, same scope, same
  // destination, and unexpired at the decision instant. Nothing about it is mismatched.
  const cachedGrant = {
    version: 1, mappingRef: FIXTURE_E.mappingRef, revision: cachedSnapshot.revision,
    principal: { ...WORKLOAD }, context: { ...cachedSnapshot.scope, purpose: PURPOSE },
    destination: { ...DESTINATION }, operation: 'DISPLAY', expiresAt: T0 + 120_000,
  };

  // Positive control before the revocation: the same fixture releases once under the live record.
  const before = releaseForDisplay(FIXTURE_E, { grant: grantFor(FIXTURE_E, 'DISPLAY') });
  assert.equal(before.outcome, 'RELEASED');
  assert.equal(before.matched, true);

  // The authoritative current record moves: activation, then revocation, each through the reducer.
  const revoked = commit(FIXTURE_E, 'REVOKE', { expectedRevision: activeRevision, now: T0 + 2_000 });
  assert.equal(revoked.state, 'CHANGED');
  assert.equal(revoked.record.state, 'REVOKED');
  assert.equal(revoked.record.revision, 3);

  // The whole coherent stale triple is now presented together: the cached ACTIVE snapshot, the grant
  // that matches it, and the fixture's own untouched ciphertext, whose AAD still authenticates.
  const stale = releaseForDisplay(FIXTURE_E, { mapping: cachedSnapshot, grant: cachedGrant });
  assert.equal(stale.outcome, 'WITHHELD');
  assert.equal(stale.code, 'SNAPSHOT_SUPERSEDED');
  assert.equal(stale.released, false);

  // Attribution, stated honestly: the pure seam alone trusts the snapshot the host hands it, so it
  // does authorize this stale triple. What refuses it is the fixture's own current-record authority
  // check, which is the trusted store's or broker's duty in a real host and is not implemented here.
  assert.equal(decide(FIXTURE_E, {
    operation: 'DISPLAY', mapping: cachedSnapshot, grant: cachedGrant,
  }).state, 'AUTHORIZED');

  // With the live current record the same ciphertext and a current grant deny at the seam, so the
  // refusal above is about stale authority and not about the ciphertext being unopenable.
  const afterCurrent = decide(FIXTURE_E, {
    operation: 'DISPLAY', grant: grantFor(FIXTURE_E, 'DISPLAY'),
  });
  assert.equal(afterCurrent.state, 'DENIED');
  assert.equal(afterCurrent.reason, 'MAPPING_REVOKED');
  const currentRelease = releaseForDisplay(FIXTURE_E, { grant: grantFor(FIXTURE_E, 'DISPLAY') });
  assert.equal(currentRelease.outcome, 'WITHHELD');
  assert.equal(currentRelease.code, 'MAPPING_REVOKED');
  assert.equal(currentRelease.released, false);

  // Zero plaintext capture across every attempt on this path: the capture holds outcome labels only.
  assertCaptureIsNonSecret();
  resetModelCapture();
});

/* ---------- 12. Expired, revoked and deleted records cannot resolve ---------- */

test('expiry, revocation and deletion each deny at the seam and withhold any release', () => {
  resetModelCapture();
  ensureActive(FIXTURE_A, SYNTHETIC_ORIGINAL_BYTES);
  assert.equal(FIXTURE_A.current.revision, 2);
  const expired = commit(FIXTURE_A, 'EXPIRE', {
    expectedRevision: FIXTURE_A.current.revision, now: FIXTURE_A.current.expiresAt,
  });
  assert.equal(expired.state, 'CHANGED');
  assert.equal(expired.record.state, 'EXPIRED');
  assert.equal(expired.record.revision, 3);
  const afterExpiry = releaseForDisplay(FIXTURE_A, { grant: grantFor(FIXTURE_A, 'DISPLAY') });
  assert.equal(afterExpiry.outcome, 'WITHHELD');
  assert.equal(afterExpiry.code, 'MAPPING_EXPIRED');
  assert.equal(afterExpiry.released, false);
  // An expiry cannot be rolled back by reactivation.
  const revive = commit(FIXTURE_A, 'ACTIVATE', {
    expectedRevision: FIXTURE_A.current.revision, now: T0 + 6_000,
  });
  assert.equal(revive.state, 'REFUSED');
  assert.equal(revive.reason, 'INVALID_TRANSITION');
  assert.equal(FIXTURE_A.current.state, 'EXPIRED');
  assert.equal(FIXTURE_A.current.revision, 3);

  ensureActive(FIXTURE_B, FOREIGN_ORIGINAL_BYTES);
  assert.equal(FIXTURE_B.current.revision, 2);
  const revoked = commit(FIXTURE_B, 'REVOKE', {
    expectedRevision: FIXTURE_B.current.revision, now: T0 + 2_000,
  });
  assert.equal(revoked.state, 'CHANGED');
  assert.equal(revoked.record.state, 'REVOKED');
  assert.equal(revoked.record.revision, 3);
  const afterRevoke = releaseForDisplay(FIXTURE_B, { grant: grantFor(FIXTURE_B, 'DISPLAY') });
  assert.equal(afterRevoke.code, 'MAPPING_REVOKED');
  assert.equal(afterRevoke.released, false);

  const deleted = commit(FIXTURE_B, 'DELETE', {
    expectedRevision: FIXTURE_B.current.revision, now: T0 + 3_000,
  });
  assert.equal(deleted.state, 'CHANGED');
  assert.equal(deleted.record.state, 'DELETED');
  assert.equal(deleted.record.revision, 4);
  const afterDelete = releaseForDisplay(FIXTURE_B, { grant: grantFor(FIXTURE_B, 'DISPLAY') });
  assert.equal(afterDelete.code, 'MAPPING_REVOKED');
  assert.equal(afterDelete.released, false);

  // A terminal command is idempotent. The state before the repeat command is captured independently, so
  // the assertion is not comparing the result against a value the commit itself just assigned.
  const beforeRepeat = { state: FIXTURE_B.current.state, revision: FIXTURE_B.current.revision };
  assert.equal(beforeRepeat.state, 'DELETED');
  assert.equal(beforeRepeat.revision, 4);
  const repeat = commit(FIXTURE_B, 'DELETE', {
    expectedRevision: FIXTURE_B.current.revision, now: T0 + 4_000,
  });
  assert.equal(repeat.state, 'UNCHANGED');
  assert.equal(repeat.record.state, beforeRepeat.state);
  assert.equal(repeat.record.revision, beforeRepeat.revision);
  assert.equal(repeat.record.revision, 4);
  assert.equal(FIXTURE_B.current.state, 'DELETED');
  assert.equal(FIXTURE_B.current.revision, 4);

  // An expired grant is refused by its own check on a still-active fixture, independently of the
  // lifecycle and mapping checks that precede it.
  ensureActive(FIXTURE_C, SYNTHETIC_ORIGINAL_BYTES);
  assert.equal(FIXTURE_C.current.revision, 2);
  const expiredGrant = releaseForDisplay(FIXTURE_C, {
    grant: grantFor(FIXTURE_C, 'DISPLAY', { expiresAt: T0 + 10 }), now: T0 + 100,
  });
  assert.equal(expiredGrant.outcome, 'WITHHELD');
  assert.equal(expiredGrant.code, 'GRANT_EXPIRED');
  assert.equal(expiredGrant.released, false);
  // Positive control on the same fixture: a live grant still restores the independent literal.
  const live = releaseForDisplay(FIXTURE_C, { grant: grantFor(FIXTURE_C, 'DISPLAY'), now: T0 + 100 });
  assert.equal(live.outcome, 'RELEASED');
  assert.equal(live.matched, true);
  assertCaptureIsNonSecret();
});