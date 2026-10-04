// #188 / synthetic integration test: the registry-backed synthetic encrypted mapping round trip.
//
// Four already-shipped seams are joined over one explicitly ephemeral in-process scenario, with the
// shipped `createMappingMetadataRegistry` as the **actual** owner of the current metadata record:
//
//   deriveScopedEntityReference  ->  createMappingMetadataRegistry  ->  authorizeMappingOperation  ->  seal/open
//
// What this proves, precisely: an original value exists only as AEAD ciphertext until a trusted host
// reads the registry's own current record *now*, the operation is pinned to DISPLAY *after* caller
// options are applied, and an actual AUTHORIZED decision from the real authorization seam permits one
// real `openMappingPayload` call whose expected AAD revision is that same fresh record's revision.
// Nothing in the test owns a current record: a fixture-owned `Map` would be the very thing the
// registry contract forbids, so the registry holds it and the test only reads it.
//
// What it is NOT: not a production vault, broker, KMS/HSM, key-management system, store, index,
// transport, audit ledger or model. It authenticates nobody - the DEK, the HMAC key, the grant, the
// authenticated workload and the clock are literal test fixtures. It proves nothing about a real
// store's durability, transactional isolation or authentication, and no claim is made about parent
// #15, #17 or #18, which stay open. No network, no provider traffic, no credentials, no held-out data.
//
// Privacy-safe assertions: no assertion ever receives a crypto result, a byte buffer or a plaintext
// operand. AEAD results are read through `projectOpen` (fixed enum strings, numbers and booleans),
// byte equality is decided by `bytesEqual` and asserted as one boolean, and the restored bytes reach
// exactly one trusted test-local inspector that returns that boolean.
//
// Every value here is invented, obviously synthetic and non-routable: `.invalid` names, fixed byte
// fills as DEK and HMAC material, one fixed epoch instant and one planted marker string. The DEK, the
// HMAC key, the grants, the clock and every ciphertext are explicitly ephemeral: they exist only for
// this process and are never persisted, serialized into a snapshot or sent anywhere.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  sealMappingPayload, openMappingPayload, MAPPING_AEAD_LIMITS, MAPPING_AEAD_FINDINGS,
} from '../dist/mapping-aead.js';
import { deriveScopedEntityReference, ENTITY_REFERENCE_TOKEN_PREFIX } from '../dist/scoped-entity-reference.js';
import { createMappingMetadataRegistry } from '../dist/mapping-metadata-registry.js';
import { authorizeMappingOperation } from '../dist/mapping-authorization.js';

/* ---------- Independent literals and synthetic fixtures ---------- */

// The expected restored value, written here and never recomputed from the implementation. Obviously
// synthetic, non-routable, not a person, host or credential.
const SYNTHETIC_ORIGINAL = 'synthetic-registry-original-fixture.invalid';
const SYNTHETIC_ORIGINAL_BYTES = new TextEncoder().encode(SYNTHETIC_ORIGINAL);
const MARKER = 'synthetic-registry-original';
const KEY_VERSION = '1.0';
const CLASS = 'PERSON';
const T0 = 1_700_000_000_000;
const TTL_MS = 3_600_000;
const CAPACITY = 8;

const WORKLOAD = Object.freeze({
  principalId: 'principal-registry-fixture.invalid', workloadId: 'workload-registry-fixture.invalid',
});
const PURPOSE = 'support-review-fixture.invalid';
const DESTINATION = Object.freeze({
  kind: 'tool.result', ref: 'tool-sink-registry-fixture.invalid', trustZone: 'LOCAL',
  profileId: 'profile-registry-fixture.invalid',
});
const UNKNOWN_REF = 'map-synthetic-registry-unknown.invalid';

const TENANT_A = Object.freeze({
  tenantId: 'tenant-registry-alpha.invalid', projectId: 'project-registry-alpha.invalid',
  sessionId: 'session-registry-alpha.invalid',
});
// A second tenant scope that deliberately shares A's original, entity id, DEK, HMAC key and key
// version, so every difference observed between the two is attributable to the tenant scope alone.
const TENANT_A2 = Object.freeze({
  tenantId: 'tenant-registry-alpha-alt.invalid', projectId: 'project-registry-alpha-alt.invalid',
  sessionId: 'session-registry-alpha-alt.invalid',
});
const TENANT_B = Object.freeze({
  tenantId: 'tenant-registry-beta.invalid', projectId: 'project-registry-beta.invalid',
  sessionId: 'session-registry-beta.invalid',
});
const ENTITY_A = 'entity-registry-verity-fixture';

/** Byte equality decided here and returned as one boolean, so a failure prints true/false. */
function bytesEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) return false;
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/**
 * The one trusted test-local inspector. The restored bytes are compared here, inside the release path,
 * and only the resulting boolean leaves this callback, so the original is never an assertion operand.
 */
const RESTORED_EXACTLY = (plaintext) => bytesEqual(plaintext, SYNTHETIC_ORIGINAL_BYTES);

/**
 * Reads one AEAD result into fixed fields. No property of the returned object is a byte buffer or a
 * caller value, so any assertion built from it prints codes, numbers and booleans only. An unreadable
 * or hostile result degrades to `UNREADABLE` and never escapes.
 */
function projectOpen(value) {
  const projection = {
    version: 0, status: 'UNREADABLE', finding: 'UNREADABLE', findingIsKnown: false, hasPlaintext: false,
    plaintextIsBuffer: false, plaintextBytes: 0,
  };
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
  } catch {
    // A hostile result stays UNREADABLE; nothing read from it is echoed anywhere.
  }
  return projection;
}

/**
 * Counts every real call to the shipped `openMappingPayload`, so a refused path can be shown to make
 * no opener call at all rather than to have inspected and rejected a plaintext.
 */
let openCalls = 0;
function resetOpenCalls() { openCalls = 0; }

/* ---------- The ephemeral scenario: ciphertext plus non-secret metadata only ---------- */

/**
 * One ephemeral mapping scenario. Its metadata lives in the shipped registry, never in this object;
 * what the object holds is the sealed record, the host-held key material and the entity id the AEAD
 * AAD needs. No original value and no plaintext is ever retained here: the plaintext is passed in
 * from the module-level literal only for the moment it is sealed.
 */
function makeMapping({ scope = TENANT_A, keyFill = 0x11, hmacFill = 0x44, entityId = ENTITY_A } = {}) {
  const hmacKey = new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(hmacFill);
  const derived = deriveScopedEntityReference({
    scope: 'SESSION', tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId,
    entityId, semanticType: CLASS, keyVersion: KEY_VERSION, key: hmacKey,
  });
  assert.equal(derived.state, 'DERIVED');
  return {
    registry: createMappingMetadataRegistry({ capacity: CAPACITY }),
    scope: Object.freeze({ ...scope }),
    mappingRef: derived.token,
    key: new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(keyFill),
    hmacKey,
    entityId,
    expiresAt: T0 + TTL_MS,
    envelope: undefined,
    // A fact about the stored ciphertext, never an input to any decision: nothing reads it back as
    // the expected revision.
    sealedRevision: 0,
  };
}

/** The registry's own three operations. Every metadata read in this file goes through `readCurrent`. */
function insertRequest(mapping, now = T0) {
  return mapping.registry.insert(
    { version: 1, mappingRef: mapping.mappingRef, scope: { ...mapping.scope }, expiresAt: mapping.expiresAt },
    { now },
  );
}
function lookupRequest(mapping, { mappingRef = mapping.mappingRef, scope = mapping.scope } = {}) {
  return { version: 1, mappingRef, scope: { ...scope } };
}
/** The fresh current-record read. Returns the registry's own result record, never a cached copy. */
function readCurrent(mapping, now, options = {}) {
  return mapping.registry.current(lookupRequest(mapping, options), { now });
}
/** One real lifecycle command against the registry's own current record. */
function applyCommand(mapping, { expectedRevision, action, now, scope = mapping.scope, mappingRef }) {
  return mapping.registry.transition(
    { version: 1, mappingRef: mappingRef ?? mapping.mappingRef, scope: { ...scope }, expectedRevision, action },
    { now },
  );
}
/** The trusted metadata projection of one registry record, for the authorization seam. */
function metadataOf(record) {
  return {
    version: 1, mappingRef: record.mappingRef, scope: { ...record.scope }, lifecycle: record.state,
    semanticType: CLASS, sensitivity: 'CONFIDENTIAL', revision: record.revision, expiresAt: record.expiresAt,
  };
}
/** One explicit, purpose-bound, finite grant, pinned to the revision of the record it was read from. */
function grantFor(mapping, record, operation, overrides = {}) {
  return {
    version: 1, mappingRef: mapping.mappingRef, revision: record.revision,
    principal: { ...WORKLOAD }, context: { ...mapping.scope, purpose: PURPOSE },
    destination: { ...DESTINATION }, operation, expiresAt: record.expiresAt - 1, ...overrides,
  };
}
/** The expected AEAD scope for one explicit revision. The revision argument always comes from a read. */
function aadScope(mapping, revision) {
  return {
    tenantId: mapping.scope.tenantId, projectId: mapping.scope.projectId, entityId: mapping.entityId,
    classification: CLASS, mappingRevision: String(revision), keyVersion: KEY_VERSION,
  };
}
/** Each open attempt gets its own copy of the sealed record; the primitive never overwrites inputs. */
function cloneEnvelope(envelope) {
  return {
    version: envelope.version, nonce: Uint8Array.from(envelope.nonce),
    ciphertext: Uint8Array.from(envelope.ciphertext), tag: Uint8Array.from(envelope.tag),
  };
}
/** The one counted call into the shipped opener. */
function realOpen(mapping, revision, envelope = mapping.envelope, key = mapping.key) {
  openCalls += 1;
  return openMappingPayload({ scope: aadScope(mapping, revision), envelope: cloneEnvelope(envelope), key });
}
/**
 * Seals the scenario's value under one explicit revision, drawing a fresh nonce from the shipped
 * primitive on every call. This is controlled synthetic host setup for a test whose stored ciphertext
 * must match the current record: it is **not** a lifecycle rotation, rewrap, key rotation or store,
 * and it persists nothing.
 */
function sealUnder(mapping, revision, plaintext = SYNTHETIC_ORIGINAL_BYTES) {
  const previous = mapping.envelope?.nonce;
  const sealed = sealMappingPayload({ scope: aadScope(mapping, revision), plaintext, key: mapping.key });
  assert.equal(sealed.status, 'SEALED');
  mapping.envelope = sealed.envelope;
  mapping.sealedRevision = revision;
  if (previous !== undefined) assert.equal(bytesEqual(sealed.envelope.nonce, previous), false);
  return sealed.envelope;
}
/** Creates through the registry, activates through the registry, and seals at the current revision. */
function activeMapping(options = {}) {
  const mapping = makeMapping(options);
  const inserted = insertRequest(mapping);
  assert.equal(inserted.state, 'INSERTED');
  assert.equal(inserted.metadata.state, 'CREATED');
  assert.equal(inserted.metadata.revision, 1);
  const activated = applyCommand(mapping, { expectedRevision: 1, action: 'ACTIVATE', now: T0 + 1_500 });
  assert.equal(activated.state, 'CHANGED');
  assert.equal(activated.metadata.state, 'ACTIVE');
  assert.equal(activated.metadata.revision, 2);
  sealUnder(mapping, activated.metadata.revision, options.plaintext);
  return mapping;
}

/** A withheld outcome. Fixed strings and booleans only; no field a buffer could enter. */
function withheld(code) { return { outcome: 'WITHHELD', code, released: false, matched: false, bytes: 0 }; }

/** The real authorization seam, called with separately supplied request, host, mapping and grant. */
function decide(mapping, {
  operation, subject = WORKLOAD, scope = mapping.scope, hostScope, destination = DESTINATION,
  metadata, grant, now, mappingRef,
}) {
  const request = {
    version: 1, mappingRef: mappingRef ?? mapping.mappingRef, subject: { ...subject },
    context: { ...scope, purpose: PURPOSE }, destination: { ...destination }, operation,
  };
  const host = {
    authenticated: {
      subject: { ...subject }, context: { ...(hostScope ?? scope), purpose: PURPOSE },
    },
    observed: { destination: { ...destination } },
  };
  return authorizeMappingOperation(request, host, metadata, grant, { now });
}

/**
 * The authorization-and-open tail shared by the correct host and the deliberately incomplete one, so
 * the only difference between them is where the metadata comes from. A denied decision and a refused
 * open both return before any plaintext exists in this process.
 */
function openAndRelease(mapping, { operation, metadata, grant, now }) {
  const decision = decide(mapping, { operation, metadata, grant, now });
  if (decision.state !== 'AUTHORIZED') return withheld(decision.reason);
  const opened = realOpen(mapping, metadata.revision);
  const projection = projectOpen(opened);
  if (projection.status !== 'OPENED') return withheld(projection.finding);
  const matched = RESTORED_EXACTLY(opened.plaintext);
  const bytes = projection.plaintextBytes;
  // Best-effort hygiene in JavaScript, not a zeroization guarantee: the buffer this process still
  // holds is overwritten here so the restored bytes do not outlive the inspection.
  opened.plaintext.fill(0);
  return { outcome: 'RELEASED', code: projection.finding, released: true, matched, bytes };
}

/**
 * Whether one snapshot is still what the registry currently holds. The trusted host reads the current
 * record and never adopts a cache; a snapshot that disagrees on reference, lifecycle, revision,
 * expiry or any scope part is superseded and is refused before any decision and long before any open.
 */
function snapshotIsCurrent(fresh, snapshot) {
  if (fresh.state !== 'FOUND' || snapshot === undefined) return false;
  const record = fresh.metadata;
  return snapshot.mappingRef === record.mappingRef && snapshot.lifecycle === record.state
    && snapshot.revision === record.revision && snapshot.expiresAt === record.expiresAt
    && snapshot.scope.tenantId === record.scope.tenantId
    && snapshot.scope.projectId === record.scope.projectId
    && snapshot.scope.sessionId === record.scope.sessionId;
}

/**
 * The DISPLAY release path. Three gates stand between a scenario and a plaintext, in this order: a
 * fresh registry `current` read, the operation pinned to DISPLAY *after* caller options are applied,
 * and an actual AUTHORIZED decision from the real seam. Withhold at any gate and no opener call is
 * made at all.
 *
 * `options.snapshot` exists only so one test can present a deliberately cached record; the fresh read
 * still happens first, and the cached record is compared against what the registry holds now.
 */
function releaseForDisplay(mapping, options = {}) {
  const now = options.now ?? T0 + 60_000;
  const fresh = readCurrent(mapping, now, { mappingRef: options.mappingRef, scope: options.scope });
  const snapshot = options.snapshot ?? (fresh.state === 'FOUND' ? metadataOf(fresh.metadata) : undefined);
  if (snapshot === undefined) return withheld(fresh.reason);
  if (!snapshotIsCurrent(fresh, snapshot)) return withheld('SNAPSHOT_SUPERSEDED');
  return openAndRelease(mapping, { operation: 'DISPLAY', metadata: snapshot, grant: options.grant, now });
}

/** The trusted USE path: a fresh record, the operation pinned to USE, and no resolution at all. */
function useMapping(mapping, options = {}) {
  const now = options.now ?? T0 + 60_000;
  const fresh = readCurrent(mapping, now, { scope: options.scope });
  if (fresh.state !== 'FOUND') return { outcome: 'WITHHELD', code: fresh.reason, used: false };
  const decision = decide(mapping, {
    operation: 'USE', metadata: metadataOf(fresh.metadata), grant: options.grant, now,
    subject: options.subject, scope: options.scope, hostScope: options.hostScope,
  });
  if (decision.state !== 'AUTHORIZED') return { outcome: 'WITHHELD', code: decision.reason, used: false };
  return { outcome: 'USED', code: decision.reason, used: true };
}

/**
 * The deliberately INCOMPLETE cached-record host this file forbids, kept so the revocation refusal is
 * provably non-vacuous. It primes one cache from the registry while the record is active and then
 * answers every later resolution from that cache, with no fresh registry read - which is exactly the
 * design that releases a revoked mapping.
 */
function createIncompleteCachedHost(mapping) {
  let cached;
  return Object.freeze({
    prime(now) {
      const fresh = readCurrent(mapping, now);
      cached = fresh.state === 'FOUND' ? metadataOf(fresh.metadata) : undefined;
      return cached !== undefined;
    },
    snapshot() { return cached; },
    release(now, operation = 'DISPLAY') {
      if (cached === undefined) return withheld('UNKNOWN_MAPPING');
      return openAndRelease(mapping, { operation, metadata: cached,
        grant: grantFor(mapping, cached, operation), now });
    },
  });
}

/* ---------- 1. DISPLAY round-trip exactness over a fresh registry record ---------- */

test('the original is restored byte-exactly only after an actual AUTHORIZED DISPLAY on a fresh registry record', () => {
  const mapping = activeMapping();
  resetOpenCalls();
  assert.equal(mapping.registry.size, 1);

  // Control: no grant at all denies at the real seam, and no opener call is made.
  const noGrant = releaseForDisplay(mapping);
  assert.equal(noGrant.outcome, 'WITHHELD');
  assert.equal(noGrant.code, 'NO_GRANT');
  assert.equal(noGrant.released, false);
  assert.equal(noGrant.matched, false);
  assert.equal(noGrant.bytes, 0);
  assert.equal(openCalls, 0);

  // Positive: an explicit DISPLAY grant over the record the registry holds now authorizes one open.
  const fresh = readCurrent(mapping, T0 + 60_000);
  assert.equal(fresh.state, 'FOUND');
  assert.equal(fresh.metadata.state, 'ACTIVE');
  assert.equal(fresh.metadata.revision, 2);
  const released = releaseForDisplay(mapping, {
    grant: grantFor(mapping, fresh.metadata, 'DISPLAY'), now: T0 + 60_000,
  });
  assert.equal(released.outcome, 'RELEASED');
  assert.equal(released.code, 'OPENED');
  assert.equal(released.released, true);
  assert.equal(released.matched, true);
  assert.equal(released.bytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  assert.equal(openCalls, 1);
});

/* ---------- 2. USE does not imply DISPLAY or EXPORT, and the path pins its operation ---------- */

test('a USE grant never becomes DISPLAY or EXPORT, and the DISPLAY path pins its own operation', () => {
  const mapping = activeMapping();
  resetOpenCalls();
  const fresh = readCurrent(mapping, T0 + 60_000);
  assert.equal(fresh.state, 'FOUND');
  const useGrant = grantFor(mapping, fresh.metadata, 'USE');
  const displayGrant = grantFor(mapping, fresh.metadata, 'DISPLAY');
  const exportGrant = grantFor(mapping, fresh.metadata, 'EXPORT');

  // Positive control: the operation the grant names is authorized, and nothing is resolved.
  const used = useMapping(mapping, { grant: useGrant, now: T0 + 60_000 });
  assert.equal(used.outcome, 'USED');
  assert.equal(used.code, 'AUTHORIZED');
  assert.equal(used.used, true);
  assert.equal(openCalls, 0);

  // Negative: the same USE grant never escalates to a reveal or an export.
  for (const operation of ['DISPLAY', 'EXPORT']) {
    const escalated = decide(mapping, { operation, metadata: metadataOf(fresh.metadata), grant: useGrant,
      now: T0 + 60_000 });
    assert.equal(escalated.state, 'DENIED');
    assert.equal(escalated.reason, 'OPERATION_NOT_GRANTED');
  }
  const withheldDisplay = releaseForDisplay(mapping, { grant: useGrant, now: T0 + 60_000 });
  assert.equal(withheldDisplay.code, 'OPERATION_NOT_GRANTED');
  assert.equal(withheldDisplay.released, false);
  assert.equal(openCalls, 0);
  // The other direction: a DISPLAY grant cannot be spent as a USE.
  const usedAsDisplay = useMapping(mapping, { grant: displayGrant, now: T0 + 60_000 });
  assert.equal(usedAsDisplay.used, false);
  assert.equal(usedAsDisplay.code, 'OPERATION_NOT_GRANTED');

  // Operation pinning: an EXPORT grant handed to the DISPLAY path is refused even when the caller
  // also names EXPORT, because the path decides its operation after caller options are applied.
  const pinned = releaseForDisplay(mapping, { grant: exportGrant, operation: 'EXPORT', now: T0 + 60_000 });
  assert.equal(pinned.code, 'OPERATION_NOT_GRANTED');
  assert.equal(pinned.released, false);
  assert.equal(openCalls, 0);

  // Positive control on the same record, so the refusals above are not vacuous.
  const released = releaseForDisplay(mapping, { grant: displayGrant, now: T0 + 60_000 });
  assert.equal(released.outcome, 'RELEASED');
  assert.equal(released.matched, true);
  assert.equal(openCalls, 1);
});

/* ---------- 3. Two real commands at one revision: one applies, the loser cannot overwrite ---------- */

test('of two real commands pinned to one revision exactly one applies, and the loser cannot overwrite the record', () => {
  const mapping = makeMapping();
  resetOpenCalls();
  const inserted = insertRequest(mapping);
  assert.equal(inserted.state, 'INSERTED');
  assert.equal(inserted.metadata.revision, 1);

  // Two real transition commands, both pinned to the literal revision 1, both at the same instant.
  const winner = applyCommand(mapping, { expectedRevision: 1, action: 'ACTIVATE', now: T0 + 1_500 });
  assert.equal(winner.state, 'CHANGED');
  assert.equal(winner.metadata.state, 'ACTIVE');
  assert.equal(winner.metadata.revision, 2);
  const loser = applyCommand(mapping, { expectedRevision: 1, action: 'REVOKE', now: T0 + 1_500 });
  assert.equal(loser.state, 'REFUSED');
  assert.equal(loser.reason, 'STALE_REVISION');

  // The fresh read shows the winner's record and not the loser's intent: creation, expiry, scope and
  // reference are carried through untouched.
  const fresh = readCurrent(mapping, T0 + 2_000);
  assert.equal(fresh.state, 'FOUND');
  assert.equal(fresh.metadata.state, 'ACTIVE');
  assert.equal(fresh.metadata.revision, 2);
  assert.equal(fresh.metadata.createdAt, T0);
  assert.equal(fresh.metadata.expiresAt, T0 + TTL_MS);
  assert.equal(fresh.metadata.mappingRef, mapping.mappingRef);
  assert.equal(fresh.metadata.scope.tenantId, TENANT_A.tenantId);
  assert.equal(fresh.metadata.scope.projectId, TENANT_A.projectId);
  assert.equal(fresh.metadata.scope.sessionId, TENANT_A.sessionId);
  assert.equal(mapping.registry.size, 1);

  // The record is live and releasable, so the refusal above was about the pinned revision alone.
  sealUnder(mapping, 2);
  const released = releaseForDisplay(mapping, {
    grant: grantFor(mapping, fresh.metadata, 'DISPLAY'), now: T0 + 60_000,
  });
  assert.equal(released.outcome, 'RELEASED');
  assert.equal(released.matched, true);
  assert.equal(openCalls, 1);
});

/* ---------- 4. A real registry revocation denies a coherent cached triple before opening ---------- */

test('a cached ACTIVE snapshot with its own grant releases nothing after a real registry revocation', () => {
  const mapping = activeMapping();
  resetOpenCalls();

  // The stale triple is captured while the record is genuinely ACTIVE at the literal revision 2.
  const active = readCurrent(mapping, T0 + 60_000);
  assert.equal(active.state, 'FOUND');
  assert.equal(active.metadata.revision, 2);
  const cachedSnapshot = metadataOf(active.metadata);
  assert.equal(cachedSnapshot.lifecycle, 'ACTIVE');
  const cachedGrant = grantFor(mapping, cachedSnapshot, 'DISPLAY', { expiresAt: T0 + 120_000 });

  // Positive control before the revocation: the same record releases once.
  const before = releaseForDisplay(mapping, {
    grant: grantFor(mapping, active.metadata, 'DISPLAY'), now: T0 + 60_000,
  });
  assert.equal(before.outcome, 'RELEASED');
  assert.equal(before.matched, true);
  assert.equal(openCalls, 1);

  // The registry's own record moves, through its own transition, at the literal expected revision 2.
  const revoked = applyCommand(mapping, { expectedRevision: 2, action: 'REVOKE', now: T0 + 90_000 });
  assert.equal(revoked.state, 'CHANGED');
  assert.equal(revoked.metadata.state, 'REVOKED');
  assert.equal(revoked.metadata.revision, 3);

  // The whole coherent stale triple - cached ACTIVE snapshot, its own unexpired grant, and the
  // untouched ciphertext whose AAD still authenticates - is now presented together.
  const stale = releaseForDisplay(mapping, {
    snapshot: cachedSnapshot, grant: cachedGrant, now: T0 + 90_000,
  });
  assert.equal(stale.outcome, 'WITHHELD');
  assert.equal(stale.code, 'SNAPSHOT_SUPERSEDED');
  assert.equal(stale.released, false);
  assert.equal(openCalls, 1);

  // With the fresh read alone the registry itself refuses first: a revoked entry is not live.
  const afterRevocation = releaseForDisplay(mapping, { now: T0 + 90_000 });
  assert.equal(afterRevocation.code, 'NOT_LIVE');
  assert.equal(afterRevocation.released, false);
  assert.equal(readCurrent(mapping, T0 + 90_000).reason, 'NOT_LIVE');
  assert.equal(openCalls, 1);

  // Attribution, stated honestly: the pure authorization seam trusts the snapshot the host hands it,
  // so on its own it does authorize this stale triple. What refuses it here is the trusted host's
  // fresh registry read, which is the store or broker duty this scenario supplies in place of a
  // shipped compare-and-set over a cache.
  assert.equal(decide(mapping, {
    operation: 'DISPLAY', metadata: cachedSnapshot, grant: cachedGrant, now: T0 + 90_000,
  }).state, 'AUTHORIZED');
  // And with the registry's own record for the revoked entry - read back through a real idempotent
  // terminal command, because `current` never returns a tombstone - the seam itself denies it.
  const revokedRecord = applyCommand(mapping, {
    expectedRevision: 3, action: 'REVOKE', now: T0 + 90_000,
  });
  assert.equal(revokedRecord.state, 'UNCHANGED');
  assert.equal(revokedRecord.metadata.state, 'REVOKED');
  assert.equal(revokedRecord.metadata.revision, 3);
  assert.equal(decide(mapping, {
    operation: 'DISPLAY', metadata: metadataOf(revokedRecord.metadata),
    grant: grantFor(mapping, revokedRecord.metadata, 'DISPLAY'), now: T0 + 90_000,
  }).reason, 'MAPPING_REVOKED');
});

/* ---------- 5. Positive fault control: the incomplete cached host does release after revocation ---------- */

test('the incomplete cached-record host this forbids still releases after the same revocation', () => {
  const mapping = activeMapping();
  resetOpenCalls();
  const incomplete = createIncompleteCachedHost(mapping);
  assert.equal(incomplete.prime(T0 + 60_000), true);
  assert.equal(incomplete.snapshot().revision, 2);

  const revoked = applyCommand(mapping, { expectedRevision: 2, action: 'REVOKE', now: T0 + 90_000 });
  assert.equal(revoked.state, 'CHANGED');
  assert.equal(revoked.metadata.state, 'REVOKED');

  // The fault control fires: without a fresh registry read the revoked mapping is still released, so
  // the correct path's refusal above is a property of the fresh read and not of the ciphertext.
  const leaked = incomplete.release(T0 + 90_000);
  assert.equal(leaked.outcome, 'RELEASED');
  assert.equal(leaked.released, true);
  assert.equal(leaked.matched, true);
  assert.equal(leaked.bytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  assert.equal(openCalls, 1);

  // The correct host, on the same revoked record at the same instant, withholds and makes no call.
  const withheldRelease = releaseForDisplay(mapping, { now: T0 + 90_000 });
  assert.equal(withheldRelease.code, 'NOT_LIVE');
  assert.equal(withheldRelease.released, false);
  assert.equal(openCalls, 1);
});

/* ---------- 6. The registry's own expiry and clock rollback deny ---------- */

test('the registry expiries the record at its own expiry and refuses a clock that moves backwards', () => {
  const mapping = activeMapping();
  resetOpenCalls();

  // Positive control before the expiry instant, so the later refusals are not vacuous.
  const active = readCurrent(mapping, T0 + 60_000);
  assert.equal(active.state, 'FOUND');
  assert.equal(active.metadata.state, 'ACTIVE');
  const live = releaseForDisplay(mapping, {
    grant: grantFor(mapping, active.metadata, 'DISPLAY'), now: T0 + 60_000,
  });
  assert.equal(live.outcome, 'RELEASED');
  assert.equal(live.matched, true);
  assert.equal(openCalls, 1);

  // At the expiry instant the registry's own observation latches the expiry and drives EXPIRE, so the
  // read refuses the record as no longer live and no opener call is made.
  const expired = readCurrent(mapping, mapping.expiresAt);
  assert.equal(expired.state, 'ABSENT');
  assert.equal(expired.reason, 'NOT_LIVE');
  const afterExpiry = releaseForDisplay(mapping, { now: mapping.expiresAt });
  assert.equal(afterExpiry.code, 'NOT_LIVE');
  assert.equal(afterExpiry.released, false);
  assert.equal(openCalls, 1);

  // The latched state and its revision, read back through a real registry operation: an idempotent
  // terminal EXPIRE returns the same record with no new increment.
  const latched = applyCommand(mapping, {
    expectedRevision: 3, action: 'EXPIRE', now: mapping.expiresAt + 1,
  });
  assert.equal(latched.state, 'UNCHANGED');
  assert.equal(latched.metadata.state, 'EXPIRED');
  assert.equal(latched.metadata.revision, 3);
  // Expiry cannot be undone: activation of the tombstone is refused.
  const revive = applyCommand(mapping, {
    expectedRevision: 3, action: 'ACTIVATE', now: mapping.expiresAt + 1,
  });
  assert.equal(revive.state, 'REFUSED');
  assert.equal(revive.reason, 'INVALID_TRANSITION');

  // A clock that moves backwards after that observation is refused outright, on the read and on the
  // release path, and neither attempt opens anything.
  const rollback = readCurrent(mapping, T0 + 100);
  assert.equal(rollback.state, 'REFUSED');
  assert.equal(rollback.reason, 'CLOCK_ROLLBACK');
  const afterRollback = releaseForDisplay(mapping, { now: T0 + 100 });
  assert.equal(afterRollback.code, 'CLOCK_ROLLBACK');
  assert.equal(afterRollback.released, false);
  assert.equal(openCalls, 1);
});

/* ---------- 7. Unknown reference and foreign scope refuse before any open ---------- */

test('an unknown reference and a foreign scope refuse at the registry before any authorization or open', () => {
  const mapping = activeMapping();
  resetOpenCalls();
  const active = readCurrent(mapping, T0 + 60_000);
  assert.equal(active.state, 'FOUND');
  const released = releaseForDisplay(mapping, {
    grant: grantFor(mapping, active.metadata, 'DISPLAY'), now: T0 + 60_000,
  });
  assert.equal(released.outcome, 'RELEASED');
  assert.equal(released.matched, true);
  assert.equal(openCalls, 1);

  // A reference this registry never held: the registry answers, and no decision or open follows.
  const unknown = releaseForDisplay(mapping, { mappingRef: UNKNOWN_REF, now: T0 + 61_000 });
  assert.equal(unknown.code, 'UNKNOWN_MAPPING');
  assert.equal(unknown.released, false);
  assert.equal(readCurrent(mapping, T0 + 61_000, { mappingRef: UNKNOWN_REF }).reason, 'UNKNOWN_MAPPING');

  // A foreign scope in the same registry is the same answer, so neither discloses the other.
  const foreign = releaseForDisplay(mapping, { scope: TENANT_B, now: T0 + 61_000 });
  assert.equal(foreign.code, 'UNKNOWN_MAPPING');
  assert.equal(foreign.released, false);
  const foreignUse = useMapping(mapping, { scope: TENANT_B, now: T0 + 61_000 });
  assert.equal(foreignUse.used, false);
  assert.equal(foreignUse.code, 'UNKNOWN_MAPPING');
  assert.equal(openCalls, 1);

  // Attribution: when the current record is supplied with a coherent foreign-scope host context, the
  // authorization seam itself refuses the scope swap.
  const fresh = readCurrent(mapping, T0 + 61_000);
  assert.equal(fresh.state, 'FOUND');
  assert.equal(decide(mapping, {
    operation: 'DISPLAY', scope: TENANT_B, hostScope: TENANT_B, metadata: metadataOf(fresh.metadata),
    grant: grantFor(mapping, fresh.metadata, 'DISPLAY'), now: T0 + 61_000,
  }).reason, 'SCOPE_MISMATCH');
});

/* ---------- 8. Controlled same-original, same-entity, same-key tenant contrast ---------- */

test('the same original, entity and key under one other tenant scope stay distinct and never open each other', () => {
  // A and A2 share the synthetic original, the entity id, the DEK, the HMAC key and the key version.
  // Only the tenant, project and session differ, so any difference below is attributable to scope.
  const alpha = activeMapping();
  const alphaAlt = activeMapping({ scope: TENANT_A2 });
  resetOpenCalls();
  assert.equal(alphaAlt.scope.tenantId !== alpha.scope.tenantId, true);
  assert.equal(alphaAlt.mappingRef !== alpha.mappingRef, true);
  assert.equal(alpha.mappingRef.startsWith(ENTITY_REFERENCE_TOKEN_PREFIX), true);
  assert.equal(alphaAlt.mappingRef.startsWith(ENTITY_REFERENCE_TOKEN_PREFIX), true);

  // Both records are at the same literal current revision and the same sealed revision before the
  // cross-tenant open, so revision cannot explain its refusal.
  assert.equal(alpha.sealedRevision, 2);
  assert.equal(alphaAlt.sealedRevision, 2);
  assert.equal(readCurrent(alpha, T0 + 60_000).metadata.revision, 2);
  assert.equal(readCurrent(alphaAlt, T0 + 60_000).metadata.revision, 2);

  // Identical plaintext bytes and an identical key, but the AAD binds the tenant.
  const crossOpen = projectOpen(realOpen(alpha, 2, alphaAlt.envelope, alpha.key));
  assert.equal(crossOpen.status, 'REFUSED');
  assert.equal(crossOpen.finding, 'AUTHENTICATION_FAILED');
  assert.equal(crossOpen.findingIsKnown, true);
  assert.equal(crossOpen.hasPlaintext, false);
  assert.equal(crossOpen.plaintextIsBuffer, false);
  assert.equal(openCalls, 1);

  // Controls: each record still opens under its own current scope and restores the same literal.
  for (const mapping of [alpha, alphaAlt]) {
    const fresh = readCurrent(mapping, T0 + 60_000);
    assert.equal(fresh.state, 'FOUND');
    const control = releaseForDisplay(mapping, {
      grant: grantFor(mapping, fresh.metadata, 'DISPLAY'), now: T0 + 60_000,
    });
    assert.equal(control.outcome, 'RELEASED');
    assert.equal(control.matched, true);
  }
  assert.equal(openCalls, 3);
});

/* ---------- 9. One revision authority: an old envelope refuses under the current revision ---------- */

test('an old envelope opens under its own old revision but refuses under the current one until a matched re-seal', () => {
  const mapping = makeMapping();
  resetOpenCalls();
  const inserted = insertRequest(mapping);
  assert.equal(inserted.metadata.revision, 1);
  // Sealed at the creation revision, so the stored ciphertext is a coherent record at revision 1.
  sealUnder(mapping, inserted.metadata.revision);
  assert.equal(mapping.sealedRevision, 1);

  // Cryptographic fact, isolated: that old envelope still authenticates under its own old AAD.
  const oldAad = projectOpen(realOpen(mapping, 1));
  assert.equal(oldAad.status, 'OPENED');
  assert.equal(oldAad.finding, 'OPENED');
  assert.equal(oldAad.hasPlaintext, true);
  assert.equal(oldAad.plaintextIsBuffer, true);
  assert.equal(oldAad.plaintextBytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);

  // The registry's record moves to the literal revision 2 through its own transition. Nothing
  // re-seals, so the stored ciphertext is now an old record.
  const activated = applyCommand(mapping, { expectedRevision: 1, action: 'ACTIVATE', now: T0 + 1_500 });
  assert.equal(activated.metadata.state, 'ACTIVE');
  assert.equal(activated.metadata.revision, 2);
  assert.equal(mapping.sealedRevision, 1);
  const fresh = readCurrent(mapping, T0 + 60_000);
  assert.equal(fresh.metadata.revision, 2);

  // Current metadata, a current DISPLAY grant, an actual AUTHORIZED decision - and still no release,
  // because the expected AAD revision is the fresh record's, not the envelope's.
  const decision = decide(mapping, {
    operation: 'DISPLAY', metadata: metadataOf(fresh.metadata),
    grant: grantFor(mapping, fresh.metadata, 'DISPLAY'), now: T0 + 60_000,
  });
  assert.equal(decision.state, 'AUTHORIZED');
  const stale = releaseForDisplay(mapping, {
    grant: grantFor(mapping, fresh.metadata, 'DISPLAY'), now: T0 + 60_000,
  });
  assert.equal(stale.outcome, 'WITHHELD');
  assert.equal(stale.code, 'AUTHENTICATION_FAILED');
  assert.equal(stale.released, false);
  assert.equal(stale.bytes, 0);
  assert.equal(aadScope(mapping, fresh.metadata.revision).mappingRevision, '2');
  assert.equal(mapping.sealedRevision, 1);
  assert.equal(openCalls, 2);

  // Matched control: the controlled host re-seal draws a fresh nonce from the shipped primitive, and
  // the current envelope then releases the literal.
  const resealed = sealUnder(mapping, fresh.metadata.revision);
  assert.equal(resealed.nonce.byteLength, MAPPING_AEAD_LIMITS.nonceBytes);
  assert.equal(resealed.tag.byteLength, MAPPING_AEAD_LIMITS.tagBytes);
  assert.equal(mapping.sealedRevision, 2);
  const current = releaseForDisplay(mapping, {
    grant: grantFor(mapping, fresh.metadata, 'DISPLAY'), now: T0 + 60_000,
  });
  assert.equal(current.outcome, 'RELEASED');
  assert.equal(current.released, true);
  assert.equal(current.matched, true);
  assert.equal(current.bytes, SYNTHETIC_ORIGINAL_BYTES.byteLength);
  assert.equal(openCalls, 3);
});

/* ---------- 10. The registry and the scenario hold ciphertext and non-secret metadata only ---------- */

test('the registry record and the scenario hold ciphertext plus non-secret metadata and never the original', () => {
  const mapping = activeMapping();
  resetOpenCalls();
  const fresh = readCurrent(mapping, T0 + 60_000);
  assert.equal(fresh.state, 'FOUND');

  // The registry returns metadata under one fixed key set: no original, ciphertext, key or alias.
  assert.equal(Object.keys(fresh.metadata).sort().join(','),
    'createdAt,expiresAt,mappingRef,revision,scope,state,version');
  assert.equal(fresh.metadata.scope.tenantId, TENANT_A.tenantId);
  assert.equal('plaintext' in fresh.metadata, false);
  assert.equal('original' in fresh.metadata, false);
  assert.equal('ciphertext' in fresh.metadata, false);

  // The scenario object holds the sealed record and host key material only, never a plaintext buffer.
  assert.equal('plaintext' in mapping, false);
  assert.equal('original' in mapping, false);
  assert.equal('ciphertext' in mapping, false);
  assert.equal('key' in mapping.envelope, false);
  assert.equal('scope' in mapping.envelope, false);
  assert.equal(Object.keys(mapping.envelope).sort().join(','), 'ciphertext,nonce,tag,version');

  // The only image this scenario serializes is ciphertext plus non-secret metadata, and it never
  // carries the planted marker. This is a marker search, not a ciphertext-versus-plaintext claim.
  const image = JSON.stringify({
    version: mapping.envelope.version, nonce: [...mapping.envelope.nonce],
    ciphertext: [...mapping.envelope.ciphertext], tag: [...mapping.envelope.tag],
    mappingRef: mapping.mappingRef, tenantId: mapping.scope.tenantId,
    projectId: mapping.scope.projectId, sessionId: mapping.scope.sessionId,
    state: fresh.metadata.state, revision: fresh.metadata.revision, keyVersion: KEY_VERSION,
  });
  assert.equal(image.includes(MARKER), false);
  assert.equal(image.includes(SYNTHETIC_ORIGINAL), false);
  assert.equal(image.includes(mapping.mappingRef), true);
  assert.equal(mapping.envelope.nonce.byteLength, MAPPING_AEAD_LIMITS.nonceBytes);
  assert.equal(mapping.envelope.tag.byteLength, MAPPING_AEAD_LIMITS.tagBytes);
  assert.equal(mapping.sealedRevision, fresh.metadata.revision);
  assert.equal(openCalls, 0);
});