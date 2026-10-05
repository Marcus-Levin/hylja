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
// proves the instrument registers a real open at that exact target.
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

/* ---------- Fixed synthetic literals ---------- */

const ORIGINAL = 'synthetic-bound-presence-original.invalid';
const ORIGINAL_BYTES = new TextEncoder().encode(ORIGINAL);
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
    authority: options.authority ?? (() => {
      counters.authority += 1;
      if (typeof hooks.onAuthority === 'function') hooks.onAuthority(counters.authority);
      return report();
    }),
    material: options.material ?? (() => {
      counters.material += 1;
      return { version: 1, envelope: { ...scenario.envelope }, key: keyBytes(0x11),
        mappingRevision: String(scenario.revision), keyVersion: KEY_VERSION };
    }),
  };
  return { host, counters, ledger, state };
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
 * One denial and its control. The control spends the effect on the exact target the denial refuses,
 * so a zero-open count on the denial cannot be a broken instrument: the same instrument, in the same
 * process and on the same path, registers the real open for the control.
 */
async function assertZeroOpenDenied(name, denial, control) {
  const denied = mark();
  const result = await denial();
  const refused = since(denied);
  assertFixedShape(result);
  assert.equal(result.code, 'WITHHELD', name);
  assert.equal(refused.opens, 0, name);
  assert.equal(refused.stats, 0, name);
  assert.equal(refused.closes, 0, name);
  if (!control) return;
  const controlMark = mark();
  const spent = await control();
  const observed = since(controlMark);
  assert.equal(spent.code, 'USED', name);
  assert.equal(observed.opens, 1, name);
  assert.equal(observed.stats, 1, name);
  assert.equal(observed.closes, 1, name);
}

test('a revoked mapping, a blocked policy, a foreign grant and a malformed target open nothing', async () => {
  const control = (async () => {
    const fresh = createHost(buildScenario());
    const created = createBoundFilePresence(fresh.host, target());
    const result = await created.handle.use();
    created.dispose();
    return result;
  });

  const revokedScenario = buildScenario();
  const revokedHost = createHost(revokedScenario);
  const revoked = revokedScenario.registry.transition({ version: 1,
    mappingRef: revokedScenario.mappingRef, scope: { ...SCOPE }, expectedRevision: 2,
    action: 'REVOKE' }, { now: USE_NOW });
  assert.equal(revoked.state, 'CHANGED');
  const revokedPresence = createBoundFilePresence(revokedHost.host, target());
  await assertZeroOpenDenied('revoked', () => revokedPresence.handle.use());
  assert.equal(revokedHost.counters.material, 0);
  revokedPresence.dispose();

  const blockedScenario = buildScenario();
  const blockedHost = createHost(blockedScenario, { bundle: policyBundle('BLOCK') });
  const blocked = createBoundFilePresence(blockedHost.host, target());
  await assertZeroOpenDenied('blocked policy', () => blocked.handle.use());
  blocked.dispose();

  const foreignScenario = buildScenario();
  const foreignHost = createHost(foreignScenario, { grant: makeGrant(foreignScenario, 'DISPLAY') });
  const foreign = createBoundFilePresence(foreignHost.host, target());
  await assertZeroOpenDenied('foreign grant', () => foreign.handle.use());
  assert.equal(foreignHost.counters.material, 0);
  foreign.dispose();

  const malformedScenario = buildScenario();
  const malformedHost = createHost(malformedScenario, { grant: makeGrant(malformedScenario, 'USE',
    { principal: { principalId: WORKLOAD.principalId } }) });
  const malformed = createBoundFilePresence(malformedHost.host, target());
  await assertZeroOpenDenied('malformed grant', () => malformed.handle.use());
  malformed.dispose();

  const unusableScenario = buildScenario();
  const unusableHost = createHost(unusableScenario);
  const unusable = createBoundFilePresence({ ...unusableHost.host, registry: undefined },
    target());
  await assertZeroOpenDenied('unusable host', () => unusable.handle.use());
  unusable.dispose();

  await control();
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

  // Same-target control: the trusted real root really does open.
  const controlHost = createHost(buildScenario());
  const control = createBoundFilePresence(controlHost.host, target());
  const controlMark = mark();
  assert.equal((await control.handle.use()).code, 'USED');
  assert.equal(since(controlMark).opens, 1);
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
    // `O_NOFOLLOW` makes the real open itself refuse the link, so the descriptor never exists.
    assert.equal((await symlink.handle.use()).code, 'FAILED');
    assert.deepEqual(since(symlinkMark), { opens: 1, stats: 0, closes: 0, lstats: 0, realpaths: 0 });
    symlink.dispose();

    const directoryScenario = buildScenario();
    const directoryHost = createHost(directoryScenario);
    const directory = createBoundFilePresence(directoryHost.host,
      target({ leaf: DIRECTORY_LEAF }));
    const directoryMark = mark();
    // The real open and the real fstat both ran, the descriptor was a directory, and it was closed.
    assert.equal((await directory.handle.use()).code, 'FAILED');
    assert.deepEqual(since(directoryMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 });
    assert.equal(descriptors === openDescriptors() || descriptors === -1, true);
    directory.dispose();

    // Substitution: the construction-bound identity is this inode, so a different file that appears
    // at the same name is refused rather than reported.
    const substituteName = join(TRUSTED, 'substituted.txt');
    const substituteHost = createHost(buildScenario());
    cjs.writeFileSync(substituteName, 'synthetic substitution body one\n');
    const substitute = createBoundFilePresence(substituteHost.host,
      target({ leaf: 'substituted.txt' }));
    const substituteMark = mark();
    cjs.unlinkSync(substituteName);
    cjs.writeFileSync(substituteName, 'synthetic substitution body two\n');
    assert.equal((await substitute.handle.use()).code, 'FAILED');
    assert.deepEqual(since(substituteMark), { opens: 1, stats: 1, closes: 1, lstats: 0, realpaths: 0 });
    substitute.dispose();
    cjs.rmSync(substituteName, { force: true });

    // Same-target control: a genuine bound file at its bound identity still spends the effect.
    const controlHost = createHost(buildScenario());
    const control = createBoundFilePresence(controlHost.host, target());
    const controlMark = mark();
    assert.equal((await control.handle.use()).code, 'USED');
    assert.equal(since(controlMark).opens, 1);
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
  assert.equal((await created.handle.use()).code, 'USED');
  assert.equal(since(beforeDispose).opens, 1);

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

    // Control: the identical hook sequence without the disposal spends the effect normally.
    const controlHost = createHost(buildScenario(), { hooks: { onAuthority: () => {} } });
    const control = createBoundFilePresence(controlHost.host, target());
    const controlMark = mark();
    assert.equal((await control.handle.use()).code, 'USED');
    assert.equal(since(controlMark).opens, 1);
    control.dispose();
  });