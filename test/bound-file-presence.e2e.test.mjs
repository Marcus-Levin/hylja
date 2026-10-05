// #245 behavioral tests for one construction-bound, read-only file-presence effect.
//
// What is real here: `createBoundFilePresence`, the shipped bound USE executor behind it, the
// shipped registry, the shipped purpose-bound authorization seam, the shipped Policy Engine, the
// shipped audit append and its gate, the shipped AEAD opener, and Node's own `openSync`/`fstatSync`/
// `closeSync`/`lstatSync`/`realpathSync` against real temporary files. What is a fixture: the
// workload identity, the scope, the grant, the destination, the policy bundle and its pinned
// digests, the audit keys, the clock and the temporary directory tree.
//
// Every value is invented, obviously synthetic and non-routable: `.invalid` names, fixed byte fills
// as DEK, HMAC and audit key material, one epoch instant, and `mkdtemp` paths under the OS temp
// directory. The private identifier is planted inside this file's own closure and is never an
// assertion operand: the file asserts codes, counters, booleans and whole-buffer comparisons only.
//
// Native effect counters. The test wraps the real `node:fs` exports **before** it dynamically
// imports the shipped module, so the numbers below are counts of the actual native calls that
// reached Node - every wrapper delegates to the original implementation and no assertion depends on
// a self-reported counter inside the module. Setup metadata operations (`lstatSync`, `realpathSync`,
// run once per construction) are counted separately from the per-call effect triple
// (`openSync`, `fstatSync`, `closeSync`), and every zero-open case ships a same-target control that
// proves the instrument registers the **complete** triple - one open, one fstat, one close - at that
// exact target, not merely an open.
//
// What is deliberately NOT claimed: this file cannot observe the recovered identifier, the contents
// of any target, or any heap state. It observes codes, real native call counts and file identity.
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createMappingMetadataRegistry } from '../dist/mapping-metadata-registry.js';
import { digestClassification, digestPolicyBundle, KNOWN_POLICY_BUNDLE } from '../dist/policy.js';
import { composeClassification } from '../dist/classification.js';
import { createInMemoryAuditLedger, AUDIT_SCHEMA_VERSION } from '../dist/audit-ledger.js';
import { deriveScopedEntityReference } from '../dist/scoped-entity-reference.js';
import { sealMappingPayload, MAPPING_AEAD_LIMITS } from '../dist/mapping-aead.js';
import { MAPPING_USE_CODES } from '../dist/mapping-use.js';

/* ---------- The native effect instrument, installed before the module under test ---------- */

// `node:fs` is deliberately reached through `createRequire` and never through a static import: the
// ESM facade of a built-in snapshots its exports when it is first imported, so a static import would
// be evaluated before the wrappers below are installed and every count in this file would be zero.
const require = createRequire(import.meta.url);
const cjs = require('node:fs');
const NATIVE = { lstatSync: cjs.lstatSync, realpathSync: cjs.realpathSync, openSync: cjs.openSync,
  fstatSync: cjs.fstatSync, closeSync: cjs.closeSync };
const seen = { opens: 0, stats: 0, closes: 0, lstats: 0, realpaths: 0, openPath: undefined };
cjs.openSync = (...args) => { seen.opens += 1; seen.openPath = args[0]; return NATIVE.openSync(...args); };
cjs.fstatSync = (...args) => { seen.stats += 1; return NATIVE.fstatSync(...args); };
cjs.closeSync = (...args) => { seen.closes += 1; return NATIVE.closeSync(...args); };
cjs.lstatSync = (...args) => { seen.lstats += 1; return NATIVE.lstatSync(...args); };
cjs.realpathSync = (...args) => { seen.realpaths += 1; return REALPATH_FALLBACK(...args); };
/** `realpathSync` is delegated with its own receiver so the wrapper stays a drop-in. */
function REALPATH_FALLBACK(...args) { return NATIVE.realpathSync(...args); }

// Loaded after the instrument is installed, so the shipped module captures these very wrappers.
const { createBoundFilePresence } = await import('../dist/bound-file-presence.js');

const mark = () => ({ ...seen });
/** Counts of the real native calls made since one `mark`. Only numbers cross an assertion. */
function since(point) {
  return { opens: seen.opens - point.opens, stats: seen.stats - point.stats,
    closes: seen.closes - point.closes, lstats: seen.lstats - point.lstats,
    realpaths: seen.realpaths - point.realpaths };
}
function sameBytes(left, right) {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) if (left[index] !== right[index]) {
    return false;
  }
  return true;
}
function openDescriptors() {
  try { return cjs.readdirSync('/proc/self/fd').length; } catch { return -1; }
}
/**
 * One boolean: two observed filesystem identities really name different files. Both operands are
 * observed with the instrumented `lstatSync` **outside** every effect window, so this comparison can
 * never spend an effect counter and no device or inode number is ever an assertion operand.
 */
function distinctIdentity(left, right) {
  return left.dev !== right.dev || left.ino !== right.ino;
}

/* ---------- Fixed synthetic literals ---------- */

const ORIGINAL = 'synthetic-bound-presence-original.invalid';
const ORIGINAL_BYTES = new TextEncoder().encode(ORIGINAL);
/**
 * A second private identifier of exactly the same length, differing in one byte. It is the
 * provisioned identifier of a target that must be refused, and it is never an assertion operand.
 */
const OTHER_BYTES = new TextEncoder().encode(ORIGINAL.replace('original', 'originaL'));
const KEY_VERSION = '1.0';
const CLASS = 'PERSON';
const SENSITIVITY = 'CONFIDENTIAL';
const TRUST = 'TRUSTED';
const T0 = 1_700_000_000_000;
const TTL_MS = 3_600_000;
const USE_NOW = T0 + 60_000;
const WORKLOAD = Object.freeze({ principalId: 'principal-bound-presence.invalid',
  workloadId: 'workload-bound-presence.invalid' });
const PURPOSE = 'bound-presence-fixture.invalid';
const ENTITY_ID = 'entity-bound-presence-fixture';
const INTERACTION_REF = 'interaction-bound-presence.invalid';
const CANDIDATE_REF = 'candidate-bound-presence.invalid';
const SOURCE = Object.freeze({ kind: 'tool.result', ref: 'source-bound-presence.invalid',
  trustZone: 'LOCAL' });
const DESTINATION = Object.freeze({ kind: 'tool.result', ref: 'sink-bound-presence.invalid',
  trustZone: 'LOCAL', profileId: 'profile-bound-presence.invalid' });
const SCOPE = Object.freeze({ tenantId: 'tenant-bound-presence-alpha.invalid',
  projectId: 'project-bound-presence-alpha.invalid',
  sessionId: 'session-bound-presence-alpha.invalid' });
const PRESENT_LEAF = 'present.txt';
const ABSENT_LEAF = 'absent.txt';
const MIRROR_LEAF = 'mirrored.txt';
const DIRECTORY_LEAF = 'nested';
const LINK_LEAF = 'linked.txt';
const SUBSTITUTED_LEAF = 'substituted.txt';
/**
 * Where the bound inode is **renamed** instead of unlinked. Keeping it alive at a second owned path
 * inside the same fixture directory is what makes a substitution deterministic: an unlink/recreate
 * pair can hand the just-freed inode straight back to the replacement, and the case would then pass
 * only by luck. Both names are owned fixture paths and both are removed in a `finally`.
 */
const RETAINED_LEAF = 'substituted-bound.txt';

const keyBytes = (fill) => new Uint8Array(MAPPING_AEAD_LIMITS.keyBytes).fill(fill);

/* ---------- One real temporary tree, created once and removed at the end ---------- */

const BASE = cjs.mkdtempSync(join(tmpdir(), 'synthetic-bound-presence-'));
const TRUSTED = join(BASE, 'trusted');
const MIRROR = join(BASE, 'mirror');
cjs.mkdirSync(TRUSTED);
cjs.mkdirSync(MIRROR);
cjs.mkdirSync(join(TRUSTED, DIRECTORY_LEAF));
const PRESENT_PATH = join(TRUSTED, PRESENT_LEAF);
const ABSENT_PATH = join(TRUSTED, ABSENT_LEAF);
const MIRROR_PATH = join(MIRROR, MIRROR_LEAF);
const LINK_PATH = join(TRUSTED, LINK_LEAF);
const ROOT_LINK = join(BASE, 'root-link');
cjs.writeFileSync(PRESENT_PATH, 'synthetic presence fixture body\n');
cjs.writeFileSync(MIRROR_PATH, 'synthetic mirror fixture body\n');
cjs.symlinkSync(PRESENT_PATH, LINK_PATH);
cjs.symlinkSync(TRUSTED, ROOT_LINK);
const PRESENT_BODY = cjs.readFileSync(PRESENT_PATH);
const MIRROR_BODY = cjs.readFileSync(MIRROR_PATH);
after(() => { cjs.rmSync(BASE, { recursive: true, force: true }); });

function target(overrides = {}) {
  return { version: 1, identifier: ORIGINAL_BYTES, root: TRUSTED, leaf: PRESENT_LEAF, ...overrides };
}

/* ---------- One mapping, real registry, real AEAD, real host ---------- */

const EVIDENCE = composeClassification({ detectorEvidence: [{
  version: 1, id: 'detector-bound-presence.invalid', status: 'FOUND',
  provenance: { inputRef: 'field-bound-presence.invalid',
    producerId: 'detector-bound-presence.invalid', producerVersion: 'pack-1' },
  claim: { semanticType: CLASS, sensitivity: SENSITIVITY },
}] }, { interactionRef: INTERACTION_REF, sourceRef: SOURCE.ref, trust: TRUST });

function policyBundle(decision = 'KEEP') {
  const rule = { id: `rule-bound-presence-${decision.toLowerCase()}.invalid`,
    profileId: DESTINATION.profileId, semanticType: CLASS, sensitivities: [SENSITIVITY],
    sourceTrust: [TRUST], operations: ['USE'], decision };
  return { ...KNOWN_POLICY_BUNDLE,
    profiles: [{ id: DESTINATION.profileId, sink: { ...DESTINATION }, exposure: 'LOCAL',
      permittedTreatments: ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE'],
      maxCleartextSensitivity: 'RESTRICTED' }],
    rules: [rule] };
}

function buildScenario({ activate = true } = {}) {
  const derived = deriveScopedEntityReference({ scope: 'SESSION', tenantId: SCOPE.tenantId,
    projectId: SCOPE.projectId, sessionId: SCOPE.sessionId, entityId: ENTITY_ID,
    semanticType: CLASS, keyVersion: KEY_VERSION, key: keyBytes(0x44) });
  assert.equal(derived.state, 'DERIVED');
  const registry = createMappingMetadataRegistry({ capacity: 8 });
  const expiresAt = T0 + TTL_MS;
  const inserted = registry.insert({ version: 1, mappingRef: derived.token,
    scope: { ...SCOPE }, expiresAt }, { now: T0 });
  assert.equal(inserted.state, 'INSERTED');
  let revision = 1;
  if (activate) {
    const activated = registry.transition({ version: 1, mappingRef: derived.token,
      scope: { ...SCOPE }, expectedRevision: 1, action: 'ACTIVATE' }, { now: T0 + 1_500 });
    assert.equal(activated.state, 'CHANGED');
    revision = activated.metadata.revision;
  }
  const sealed = sealMappingPayload({ scope: aadScope(revision), plaintext: ORIGINAL_BYTES,
    key: keyBytes(0x11) });
  assert.equal(sealed.status, 'SEALED');
  return { registry, mappingRef: derived.token, scope: SCOPE, expiresAt, envelope: sealed.envelope,
    revision };
}
function aadScope(revision) {
  return { tenantId: SCOPE.tenantId, projectId: SCOPE.projectId, entityId: ENTITY_ID,
    classification: CLASS, mappingRevision: String(revision), keyVersion: KEY_VERSION };
}

function createHost(scenario, options = {}) {
  const bundle = options.bundle ?? policyBundle('KEEP');
  const ledger = options.ledger ?? createInMemoryAuditLedger(
    { tenantId: SCOPE.tenantId, projectId: SCOPE.projectId });
  const auditContext = { version: AUDIT_SCHEMA_VERSION,
    scope: { tenantId: SCOPE.tenantId, projectId: SCOPE.projectId },
    actor: { principalId: WORKLOAD.principalId, workloadId: WORKLOAD.workloadId },
    integrationId: 'integration-bound-presence.invalid',
    actorBinding: 'AUTHENTICATED_UPSTREAM', pseudonymKey: keyBytes(0x33), chainKey: keyBytes(0x77) };
  const current = scenario.registry.current({ version: 1, mappingRef: scenario.mappingRef,
    scope: { ...SCOPE } }, { now: USE_NOW });
  assert.equal(current.state, 'FOUND');
  const state = { grant: Object.hasOwn(options, 'grant') ? options.grant : makeGrant(scenario, 'USE') };
  const counters = { authority: 0, material: 0 };
  const hooks = options.hooks ?? {};
  const report = () => ({ version: 1, subject: { ...WORKLOAD },
    context: { ...SCOPE, purpose: PURPOSE }, destination: { ...DESTINATION },
    grant: state.grant === undefined ? undefined : { ...state.grant },
    keyVersion: KEY_VERSION, now: USE_NOW });
  const host = {
    version: 1,
    mappingRef: scenario.mappingRef,
    scope: { ...SCOPE },
    entityId: ENTITY_ID,
    registry: scenario.registry,
    audit: { ledger, context: auditContext,
      components: [{ id: 'CLASSIFICATION_POLICY', version: '1' },
        { id: 'AUTHORIZATION_POLICY', version: '1' }] },
    policy: { version: 1, interactionRef: INTERACTION_REF, candidateRef: CANDIDATE_REF,
      source: { ...SOURCE, trust: TRUST }, classification: EVIDENCE,
      classificationDigest: digestClassification(EVIDENCE),
      policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(bundle) }, bundle },
    // Written as `function` expressions on purpose: `this` inside them is the receiver the shipped
    // executor actually applies them with, which is what the private-backend probe below inspects.
    authority: options.authority ?? function authority() {
      counters.authority += 1;
      if (typeof hooks.onAuthority === 'function') hooks.onAuthority(counters.authority);
      if (typeof options.onReceiver === 'function') options.onReceiver('authority', this);
      return report();
    },
    material: options.material ?? function material() {
      counters.material += 1;
      if (typeof options.onReceiver === 'function') options.onReceiver('material', this);
      return { version: 1, envelope: { ...scenario.envelope }, key: keyBytes(0x11),
        mappingRevision: String(scenario.revision), keyVersion: KEY_VERSION };
    },
  };
  return { host, counters, ledger, state };
}
/**
 * The injected values really are the host's own, so a denial case can never pass by silently
 * dropping what it planted: the pinned bundle and its digest, the ledger, and the exact grant object
 * the case claims to be exercising.
 */
function assertInjected(built, expected) {
  if (expected.bundle !== undefined) {
    assert.equal(built.host.policy.bundle, expected.bundle);
    assert.equal(built.host.policy.policy.digest, digestPolicyBundle(expected.bundle));
  }
  if (expected.grant !== undefined) assert.equal(built.state.grant, expected.grant);
  assert.equal(built.host.audit.ledger, built.ledger);
}
function makeGrant(scenario, operation, overrides = {}) {
  return { version: 1, mappingRef: scenario.mappingRef, revision: scenario.revision,
    principal: { ...WORKLOAD }, context: { ...SCOPE, purpose: PURPOSE },
    destination: { ...DESTINATION }, operation, expiresAt: scenario.expiresAt - 1, ...overrides };
}
function assertFixedShape(result) {
  assert.equal(result.version, 1);
  assert.equal(MAPPING_USE_CODES.includes(result.code), true);
  assert.deepEqual(Object.keys(result).sort(), ['code', 'version']);
}

/* ---------- 1. The accepted path: a genuine temporary file yields USED ---------- */

test('an authorized use of a genuine temporary file yields USED from one real open', async () => {
  const scenario = buildScenario();
  const built = createHost(scenario);
  const before = mark();
  const created = createBoundFilePresence(built.host, target());
  const construction = since(before);
  // Construction is trusted setup metadata: the root is checked, canonicalized, re-checked as a
  // real directory, and the bound leaf is observed once. None of it is a per-call effect.
  assert.equal(construction.lstats, 3);
  assert.equal(construction.realpaths, 1);
  assert.equal(construction.opens, 0);
  assert.deepEqual(Object.keys(created).sort(), ['dispose', 'handle']);
  assert.deepEqual(Object.keys(created.handle).sort(), ['use']);
  assert.equal(typeof created.dispose, 'function');

  const beforeUse = mark();
  const descriptors = openDescriptors();
  const used = await created.handle.use();
  const effect = since(beforeUse);

  assertFixedShape(used);
  assert.equal(used.code, 'USED');
  // The effect is exactly one real open, one real fstat on the descriptor and one real close.
  assert.equal(effect.opens, 1);
  assert.equal(effect.stats, 1);
  assert.equal(effect.closes, 1);
  assert.equal(effect.lstats, 0);
  assert.equal(effect.realpaths, 0);
  assert.equal(effect.opens === 1 && seen.openPath === PRESENT_PATH, true);
  assert.equal(built.counters.authority, 4);
  assert.equal(built.counters.material, 1);
  assert.equal(built.ledger.entries.length, 2);
  assert.equal(built.ledger.entries.every((entry) => entry.event.outcome === 'ALLOWED'), true);
  // A presence check reads no content and writes nothing: the descriptor is closed and the file is
  // byte-for-byte what it was.
  assert.equal(descriptors === openDescriptors() || descriptors === -1, true);
  assert.equal(sameBytes(cjs.readFileSync(PRESENT_PATH), PRESENT_BODY), true);
  created.dispose();
});

/* ---------- 2. The genuine negative: an absent target is NOT_FOUND ---------- */

test('a genuine absent target yields NOT_FOUND from one real open that returns ENOENT', async () => {
  const scenario = buildScenario();
  const built = createHost(scenario);
  const created = createBoundFilePresence(built.host, target({ leaf: ABSENT_LEAF }));
  const beforeUse = mark();
  const result = await created.handle.use();
  const effect = since(beforeUse);

  assertFixedShape(result);
  assert.equal(result.code, 'NOT_FOUND');
  assert.equal(effect.opens, 1);
  assert.equal(effect.stats, 0);
  assert.equal(effect.closes, 0);
  assert.equal(effect.opens === 1 && seen.openPath === ABSENT_PATH, true);
  created.dispose();
});

/* ---------- 3. Refusals cost zero native effects, against a same-target control ---------- */

/**
 * One denial and its mandatory paired control. The control is not optional and is not a shared
 * fixture: each denial gets its own freshly built scenario whose `use()` must return `USED` and
 * spend one real open, one real fstat and one real close. A zero-open count on the denial therefore
 * cannot be a broken instrument, a dead target or a silently dropped input - the same instrument,
 * the same process and the same construction path register the effect for the control.
 */
async function assertZeroOpenDenied(name, denial, control) {
  assert.equal(typeof denial, 'function', name);
  assert.equal(typeof control, 'function', name);
  const denied = mark();
  const result = await denial();
  const refused = since(denied);
  assertFixedShape(result);
  assert.equal(result.code, 'WITHHELD', name);
  assert.deepEqual(refused, { opens: 0, stats: 0, closes: 0, lstats: 0, realpaths: 0 }, name);
  const controlMark = mark();
  const spent = await control();
  assert.equal(spent.code, 'USED', name);
  assert.deepEqual(since(controlMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 },
    name);
}
/** A genuinely working same-target control: fresh host, fresh scenario, the real present file. */
function sameTargetControl() {
  const built = createHost(buildScenario());
  const created = createBoundFilePresence(built.host, target());
  return async () => {
    const result = await created.handle.use();
    created.dispose();
    return result;
  };
}

test('a revoked mapping, a blocked policy, a foreign grant and a malformed grant open nothing',
  async () => {
    const revokedScenario = buildScenario();
    const revokedHost = createHost(revokedScenario);
    assertInjected(revokedHost, {});
    const revoked = revokedScenario.registry.transition({ version: 1,
      mappingRef: revokedScenario.mappingRef, scope: { ...SCOPE }, expectedRevision: 2,
      action: 'REVOKE' }, { now: USE_NOW });
    assert.equal(revoked.state, 'CHANGED');
    const revokedPresence = createBoundFilePresence(revokedHost.host, target());
    await assertZeroOpenDenied('revoked', () => revokedPresence.handle.use(),
      sameTargetControl());
    assert.equal(revokedHost.counters.material, 0);
    revokedPresence.dispose();

    const blockedBundle = policyBundle('BLOCK');
    const blockedScenario = buildScenario();
    const blockedHost = createHost(blockedScenario, { bundle: blockedBundle });
    // The planted bundle is the host's own bundle, under its own pinned digest.
    assertInjected(blockedHost, { bundle: blockedBundle });
    assert.equal(blockedHost.host.policy.bundle.rules[0].decision, 'BLOCK');
    const blocked = createBoundFilePresence(blockedHost.host, target());
    await assertZeroOpenDenied('blocked policy', () => blocked.handle.use(), sameTargetControl());
    // The real Policy Engine really ran over the injected bundle before it refused.
    assert.equal(blockedHost.counters.authority, 1);
    assert.equal(blockedHost.counters.material, 0);
    assert.equal(blockedHost.ledger.entries.length, 0);
    blocked.dispose();

    // A **foreign** USE grant: the operation is the right one, but the principal and the tenant scope
    // the grant itself names are not this mapping's. This is a scope/principal denial, not a
    // "USE was requested as DISPLAY" denial.
    const foreignScenario = buildScenario();
    const foreignGrant = makeGrant(foreignScenario, 'USE', {
      principal: { principalId: 'principal-bound-presence-foreign.invalid',
        workloadId: 'workload-bound-presence-foreign.invalid' },
      context: { ...SCOPE, tenantId: 'tenant-bound-presence-foreign.invalid', purpose: PURPOSE },
    });
    const foreignHost = createHost(foreignScenario, { grant: foreignGrant });
    assertInjected(foreignHost, { grant: foreignGrant });
    assert.equal(foreignHost.state.grant.operation, 'USE');
    assert.equal(foreignHost.state.grant.principal.principalId, 'principal-bound-presence-foreign.invalid');
    assert.equal(foreignHost.state.grant.context.tenantId, 'tenant-bound-presence-foreign.invalid');
    const foreign = createBoundFilePresence(foreignHost.host, target());
    await assertZeroOpenDenied('foreign USE grant', () => foreign.handle.use(),
      sameTargetControl());
    assert.equal(foreignHost.counters.material, 0);
    // A foreign misbinding is not an attributable refusal, so it records nothing.
    assert.equal(foreignHost.ledger.entries.length, 0);
    foreign.dispose();

    // `USE` never implies `DISPLAY`: a correct principal, scope and revision on the wrong operation.
    const displayScenario = buildScenario();
    const displayGrant = makeGrant(displayScenario, 'DISPLAY');
    const displayHost = createHost(displayScenario, { grant: displayGrant });
    assertInjected(displayHost, { grant: displayGrant });
    const display = createBoundFilePresence(displayHost.host, target());
    await assertZeroOpenDenied('DISPLAY grant', () => display.handle.use(), sameTargetControl());
    assert.equal(displayHost.counters.material, 0);
    assert.equal(displayHost.ledger.entries.length, 0);
    display.dispose();

    const malformedScenario = buildScenario();
    const malformedGrant = makeGrant(malformedScenario, 'USE',
      { principal: { principalId: WORKLOAD.principalId } });
    const malformedHost = createHost(malformedScenario, { grant: malformedGrant });
    assertInjected(malformedHost, { grant: malformedGrant });
    const malformed = createBoundFilePresence(malformedHost.host, target());
    await assertZeroOpenDenied('malformed grant', () => malformed.handle.use(),
      sameTargetControl());
    assert.equal(malformedHost.counters.material, 0);
    assert.equal(malformedHost.ledger.entries.length, 0);
    malformed.dispose();

    const unusableScenario = buildScenario();
    const unusableHost = createHost(unusableScenario);
    assertInjected(unusableHost, {});
    const unusable = createBoundFilePresence({ ...unusableHost.host, registry: undefined },
      target());
    await assertZeroOpenDenied('unusable host', () => unusable.handle.use(), sameTargetControl());
    assert.equal(unusableHost.counters.authority, 0);
    assert.equal(unusableHost.counters.material, 0);
    unusable.dispose();
  });

test('an expired grant is refused, recorded once, and still opens nothing', async () => {
  const scenario = buildScenario();
  const built = createHost(scenario, { grant: makeGrant(scenario, 'USE', { expiresAt: T0 + 30_000 }) });
  const created = createBoundFilePresence(built.host, target());
  const before = mark();
  const result = await created.handle.use();

  assertFixedShape(result);
  assert.equal(result.code, 'WITHHELD');
  assert.deepEqual(since(before), { opens: 0, stats: 0, closes: 0, lstats: 0, realpaths: 0 });
  // The real authorization seam named this refusal, so the shipped executor recorded it once and the
  // sealed bytes never existed.
  assert.equal(built.ledger.entries.length, 1);
  assert.equal(built.ledger.entries[0].event.outcome, 'DENIED');
  assert.equal(built.ledger.entries[0].event.reason, 'RESOLUTION_DENIED');
  assert.equal(built.counters.material, 0);

  // Same-target control: the instrument does register a real open here.
  const controlHost = createHost(buildScenario());
  const control = createBoundFilePresence(controlHost.host, target());
  const controlMark = mark();
  assert.equal((await control.handle.use()).code, 'USED');
  assert.deepEqual(since(controlMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 });
  control.dispose();
  created.dispose();
});

/* ---------- 8. A recovered identifier that is not the private one is not an absence ---------- */

test('a recovered identifier that differs from the private one refuses before any native effect',
  async () => {
    const scenario = buildScenario();
    const built = createHost(scenario);
    // The very same genuine file, the very same sealed material, but the target record was
    // provisioned with a different private identifier of the same length.
    assert.equal(OTHER_BYTES.byteLength, ORIGINAL_BYTES.byteLength);
    const created = createBoundFilePresence(built.host, target({ identifier: OTHER_BYTES }));
    const before = mark();
    const descriptors = openDescriptors();
    const result = await created.handle.use();
    const refused = since(before);

    assertFixedShape(result);
    // The comparison happens before the first native function, so a mismatch is a reached effect that
    // could not be completed - never an `ENOENT`, and never the `NOT_FOUND` of an absent target.
    assert.equal(result.code, 'FAILED');
    assert.deepEqual(refused, { opens: 0, stats: 0, closes: 0, lstats: 0, realpaths: 0 });
    assert.equal(descriptors === openDescriptors() || descriptors === -1, true);
    // The material really was loaded and decrypted: the comparison is over recovered bytes, not a
    // refusal that skipped the effect's own inputs.
    assert.equal(built.counters.material, 1);
    assert.equal(built.ledger.entries.length, 2);
    created.dispose();

    // Same-target control with the matching identifier: this exact target really does open.
    const controlHost = createHost(buildScenario());
    const control = createBoundFilePresence(controlHost.host, target());
    const controlMark = mark();
    assert.equal((await control.handle.use()).code, 'USED');
    assert.deepEqual(since(controlMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 });
    assert.equal(seen.openPath === PRESENT_PATH, true);
    control.dispose();
  });

/* ---------- 9. The private backend never escapes into a host callback's receiver ---------- */

test('a blocked call never exposes the private backend through a host callback receiver',
  async () => {
    // A genuine core call that is refused: BLOCK over the pinned bundle, real executor, real policy.
    const refusedReceivers = [];
    const blockedBundle = policyBundle('BLOCK');
    const blockedHost = createHost(buildScenario(), { bundle: blockedBundle,
      onReceiver: (which, receiver) => refusedReceivers.push([which, receiver]) });
    assertInjected(blockedHost, { bundle: blockedBundle });
    const blocked = createBoundFilePresence(blockedHost.host, target());
    const before = mark();
    const result = await blocked.handle.use();
    const refused = since(before);

    assertFixedShape(result);
    assert.equal(result.code, 'WITHHELD');
    // Genuine `WITHHELD`: no effect and no audit entry at all on this path.
    assert.deepEqual(refused, { opens: 0, stats: 0, closes: 0, lstats: 0, realpaths: 0 });
    assert.equal(blockedHost.ledger.entries.length, 0);
    assert.equal(blockedHost.counters.authority, 1);
    blocked.dispose();

    // The callback ran, and the object it was handed as its receiver is the caller's own host object
    // - never the copy this module decorated with the private backend.
    const authorities = refusedReceivers.filter(([which]) => which === 'authority');
    assert.equal(authorities.length, 1);
    const receivers = new Set(refusedReceivers.map(([, receiver]) => receiver));
    assert.equal(receivers.size, 1);
    for (const receiver of receivers) {
      assert.equal(receiver === blockedHost.host, true);
      assert.equal(Object.hasOwn(receiver, 'backend'), false);
      assert.equal(receiver.backend, undefined);
      assert.equal(typeof receiver.backend?.lookup, 'undefined');
    }
    // Nothing usable escaped: the object in the callback's hands is the caller's own host, which
    // carries no backend and can spend no effect on its own.
    assert.equal(Object.hasOwn(blockedHost.host, 'backend'), false);
    assert.equal(blockedHost.host.backend, undefined);

    // Positive receiver check on the accepted path, where the material callback really is invoked:
    // its receiver is that same caller-owned object, and the effect is spent exactly once.
    const acceptedReceivers = [];
    const acceptedHost = createHost(buildScenario(),
      { onReceiver: (which, receiver) => acceptedReceivers.push([which, receiver]) });
    const accepted = createBoundFilePresence(acceptedHost.host, target());
    const acceptedMark = mark();
    assert.equal((await accepted.handle.use()).code, 'USED');
    assert.deepEqual(since(acceptedMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 });
    const materials = acceptedReceivers.filter(([which]) => which === 'material');
    assert.equal(materials.length, 1);
    assert.equal(acceptedHost.counters.material, 1);
    assert.equal(materials[0][1] === acceptedHost.host, true);
    assert.equal(Object.hasOwn(materials[0][1], 'backend'), false);
    assert.equal(acceptedReceivers.every(([, receiver]) => receiver === acceptedHost.host), true);
    accepted.dispose();
  });

/* ---------- 4. The closed target record: shape refusals touch no native function at all ---------- */

test('a malformed, traversing or multi-component target record yields a restrictive handle', async () => {
  const cases = {
    'wrong version': target({ version: 2 }),
    'unknown key': target({ extra: true }),
    'empty leaf': target({ leaf: '' }),
    'dot leaf': target({ leaf: '.' }),
    'dot dot leaf': target({ leaf: '..' }),
    'traversal leaf': target({ leaf: `../${MIRROR}/${MIRROR_LEAF}` }),
    'absolute leaf': target({ leaf: '/etc/hostname' }),
    'multi component leaf': target({ leaf: `${MIRROR}/${MIRROR_LEAF}` }),
    'nul in leaf': target({ leaf: 'present\u0000.txt' }),
    'relative root': target({ root: 'mirror' }),
    'traversal root': target({ root: `${TRUSTED}/../mirror` }),
    'identifier not bytes': target({ identifier: 'synthetic-not-bytes.invalid' }),
    'identifier too large': target({ identifier: new Uint8Array(65_537) }),
    'identifier empty': target({ identifier: new Uint8Array(0) }),
    'inherited prototype': Object.assign(Object.create({ inherited: true }), target()),
  };
  for (const [name, value] of Object.entries(cases)) {
    const built = createHost(buildScenario());
    const before = mark();
    const created = createBoundFilePresence(built.host, value);
    const refused = since(before);
    const result = await created.handle.use();

    assertFixedShape(result);
    assert.equal(result.code, 'WITHHELD', name);
    // Shape is decided before any native call: not one metadata stat, not one open.
    assert.deepEqual(refused, { opens: 0, stats: 0, closes: 0, lstats: 0, realpaths: 0 }, name);
    assert.equal(built.counters.authority, 0, name);
    assert.equal(built.counters.material, 0, name);
    assert.equal(built.ledger.entries.length, 0, name);
    created.dispose();
    assert.equal((await created.handle.use()).code, 'WITHHELD', name);

    // Same-target control for this exact case: the instrument is live in this loop, and a genuine
    // bound file at the very same target spends the effect, so the zero above cannot be a counter
    // that stopped counting. The control is constructed before the window opens, so its trusted
    // setup metadata is not counted as an effect.
    const control = sameTargetControl();
    const controlMark = mark();
    assert.equal((await control()).code, 'USED', name);
    assert.deepEqual(since(controlMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 },
      name);
  }
});

test('a symbolic-link root is refused at construction and never opened', async () => {
  const built = createHost(buildScenario());
  const before = mark();
  const created = createBoundFilePresence(built.host, target({ root: ROOT_LINK }));
  const refused = since(before);
  const result = await created.handle.use();

  assert.equal(result.code, 'WITHHELD');
  // The one native call is the trusted setup stat of the root itself; the canonicalization that
  // would have resolved the link never ran.
  assert.deepEqual(refused, { opens: 0, stats: 0, closes: 0, lstats: 1, realpaths: 0 });
  assert.equal(built.counters.material, 0);

  // Same-target control: the trusted real root really does open, and spends the whole effect triple.
  const controlHost = createHost(buildScenario());
  const control = createBoundFilePresence(controlHost.host, target());
  const controlMark = mark();
  assert.equal((await control.handle.use()).code, 'USED');
  assert.deepEqual(since(controlMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 },
    'linked-root control');
  control.dispose();
  created.dispose();
});

/* ---------- 5. Targets that are not the bound regular file ---------- */

test('a symlink target, a directory and a substituted inode all refuse without leaking a descriptor',
  async () => {
    const symlinkScenario = buildScenario();
    const symlinkHost = createHost(symlinkScenario);
    const symlink = createBoundFilePresence(symlinkHost.host, target({ leaf: LINK_LEAF }));
    const symlinkMark = mark();
    const descriptors = openDescriptors();
    // `O_NOFOLLOW` makes the kernel refuse the link inside the open itself, so **no descriptor is ever
    // created**: the `finally` that owns the close has nothing to close and spends nothing. The trace
    // is therefore one open, no fstat and no close - not the full triple.
    assert.equal((await symlink.handle.use()).code, 'FAILED');
    assert.deepEqual(since(symlinkMark), { opens: 1, stats: 0, closes: 0, lstats: 0, realpaths: 0 },
      'symlink leaf');
    assert.equal(descriptors === openDescriptors() || descriptors === -1, true);
    symlink.dispose();

    const directoryScenario = buildScenario();
    const directoryHost = createHost(directoryScenario);
    const directory = createBoundFilePresence(directoryHost.host,
      target({ leaf: DIRECTORY_LEAF }));
    const directoryMark = mark();
    // The real open and the real fstat both ran, the descriptor was a directory, and it was closed.
    assert.equal((await directory.handle.use()).code, 'FAILED');
    assert.deepEqual(since(directoryMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 },
      'directory leaf');
    assert.equal(descriptors === openDescriptors() || descriptors === -1, true);
    directory.dispose();

    // Substitution: the construction-bound identity is this inode, so a different file that appears at
    // the same name is refused rather than reported. The bound inode is **renamed**, not unlinked, so
    // it stays alive at a second owned path: unlink-and-recreate can hand the just-freed inode
    // straight back to the replacement, and the case would then pass only by luck.
    const substituteName = join(TRUSTED, SUBSTITUTED_LEAF);
    const retainedName = join(TRUSTED, RETAINED_LEAF);
    const substituteHost = createHost(buildScenario());
    cjs.writeFileSync(substituteName, 'synthetic substitution body one\n');
    const boundObservation = cjs.lstatSync(substituteName);
    const substitute = createBoundFilePresence(substituteHost.host,
      target({ leaf: SUBSTITUTED_LEAF }));
    cjs.renameSync(substituteName, retainedName);
    cjs.writeFileSync(substituteName, 'synthetic substitution body two\n');
    const replacementObservation = cjs.lstatSync(substituteName);
    const substituteMark = mark();
    try {
      // The precondition, asserted before the effect as two booleans: both paths are regular files,
      // and the replacement really is a different file. Every observation above is real filesystem
      // metadata taken outside this window, so none of it can be a self-reported module value.
      assert.equal(boundObservation.isFile() && replacementObservation.isFile(), true,
        'substitution operands');
      assert.equal(distinctIdentity(boundObservation, replacementObservation), true,
        'substitution identities differ');
      // The open and the fstat both ran on the replacement and the descriptor was closed again.
      assert.equal((await substitute.handle.use()).code, 'FAILED');
      assert.deepEqual(since(substituteMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 },
        'substitution leaf');
      assert.equal(descriptors === openDescriptors() || descriptors === -1, true);
    } finally {
      substitute.dispose();
      // Both names are owned fixture paths inside this test's own ephemeral tree, and both go.
      cjs.rmSync(substituteName, { force: true });
      cjs.rmSync(retainedName, { force: true });
    }

    // Same-target control: a genuine bound file at its bound identity spends the whole effect triple.
    const controlHost = createHost(buildScenario());
    const control = createBoundFilePresence(controlHost.host, target());
    const controlMark = mark();
    assert.equal((await control.handle.use()).code, 'USED');
    assert.deepEqual(since(controlMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 },
      'nonregular control');
    assert.equal(seen.openPath === PRESENT_PATH, true);
    control.dispose();
  });

/* ---------- 6. The binding is immutable: caller mutation and later replacement cannot retarget --- */

test('caller mutation and a replaced native function cannot retarget an existing handle', async () => {
  const scenario = buildScenario();
  const record = target();
  const built = createHost(scenario);
  const created = createBoundFilePresence(built.host, record);

  // The caller owns its own record and its own byte buffer. Both are mutated after construction.
  record.root = MIRROR;
  record.leaf = MIRROR_LEAF;
  record.identifier.fill(0x5a);
  built.host.authority = () => { throw new Error('synthetic replacement authority'); };
  built.host.material = () => { throw new Error('synthetic replacement material'); };
  const nativeOpen = cjs.openSync;
  const nativeStat = cjs.fstatSync;
  const nativeClose = cjs.closeSync;
  cjs.openSync = () => { throw new Error('synthetic replacement open'); };
  cjs.fstatSync = () => { throw new Error('synthetic replacement fstat'); };
  cjs.closeSync = () => { throw new Error('synthetic replacement close'); };

  const before = mark();
  let result;
  try {
    result = await created.handle.use();
  } finally {
    cjs.openSync = nativeOpen;
    cjs.fstatSync = nativeStat;
    cjs.closeSync = nativeClose;
  }

  // The captured host callbacks and the captured native functions are the ones that ran, and they
  // spent the effect on the construction-bound target, not on the record the caller edited.
  assert.equal(result.code, 'USED');
  assert.equal(since(before).opens, 1);
  assert.equal(seen.openPath === PRESENT_PATH, true);
  assert.equal(seen.opens, before.opens + 1);
  // The record the caller edited after construction names a file that was never opened. This read is
  // last, because Node's own `readFileSync` performs a real `openSync` of its own.
  assert.equal(sameBytes(cjs.readFileSync(MIRROR_PATH), MIRROR_BODY), true);
  created.dispose();
});

/* ---------- 7. Disposal blocks later calls and refuses an in-flight effect ---------- */

test('disposal blocks later calls and clears the owned configuration it created', async () => {
  const callerBytes = new Uint8Array(ORIGINAL_BYTES);
  const built = createHost(buildScenario());
  const created = createBoundFilePresence(built.host, target({ identifier: callerBytes }));

  const beforeDispose = mark();
  // The paired same-target control for every zero-count below, in this same test and at this same
  // target: the genuine present file really opens, fstats and closes before anything is disposed.
  assert.equal((await created.handle.use()).code, 'USED');
  assert.deepEqual(since(beforeDispose), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 },
    'disposal control');

  created.dispose();
  // A second disposal is safe, and every later call is refused before any native function is reached.
  created.dispose();
  const afterDispose = mark();
  assert.equal((await created.handle.use()).code, 'WITHHELD');
  assert.equal((await created.handle.use()).code, 'WITHHELD');
  assert.deepEqual(since(afterDispose), { opens: 0, stats: 0, closes: 0, lstats: 0, realpaths: 0 });

  // The caller keeps its own buffer: this module copied the identifier and owns the copy it clears.
  assert.equal(sameBytes(callerBytes, ORIGINAL_BYTES), true);
});

test('disposal from inside a host callback refuses the in-flight call before any native effect',
  async () => {
    const built = createHost(buildScenario(), {
      hooks: { onAuthority: (count) => { if (count === 3) created.dispose(); } },
    });
    let created;
    created = createBoundFilePresence(built.host, target());
    const before = mark();
    const result = await created.handle.use();

    // The private effect was reached and refused: no open, no fstat, no close, and no descriptor.
    assertFixedShape(result);
    assert.equal(result.code, 'FAILED');
    assert.deepEqual(since(before), { opens: 0, stats: 0, closes: 0, lstats: 0, realpaths: 0 });

    // Control: the identical hook sequence without the disposal spends the whole effect triple.
    const controlHost = createHost(buildScenario(), { hooks: { onAuthority: () => {} } });
    const control = createBoundFilePresence(controlHost.host, target());
    const controlMark = mark();
    assert.equal((await control.handle.use()).code, 'USED');
    assert.deepEqual(since(controlMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 },
      'in-callback disposal control');
    control.dispose();
  });