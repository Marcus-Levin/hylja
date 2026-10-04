// Behavior tests for the bounded ephemeral mapping metadata registry (issue #180).
// Synthetic, non-routable `.invalid` identifiers only. No network, no credentials, no keys, no plaintext.
//
// These assertions test the registry's own behaviour: what it creates, what it returns, which fixed
// code it refuses with, and that two callers pinned to one expected revision cannot both apply. They
// do not prove that a vault, a database, a broker, a scheduler or a KMS applies a lifecycle effect,
// and they do not prove any caller was authenticated or authorized.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MAPPING_LIFECYCLE_ACTIONS, MAPPING_LIFECYCLE_STATES } from '../dist/mapping-lifecycle.js';
import {
  MAPPING_METADATA_REASONS, createMappingMetadataRegistry,
} from '../dist/mapping-metadata-registry.js';

const NOW = 1_800_000_000_000;
const HOUR = 3_600_000;
const REF = 'map-synthetic-registry.invalid';
const OTHER_REF = 'map-synthetic-registry-other.invalid';
const TENANT_A = 'tenant-synthetic-a.invalid';
const TENANT_B = 'tenant-synthetic-b.invalid';
const PROJECT_A = 'project-synthetic-a.invalid';
const PROJECT_B = 'project-synthetic-b.invalid';
const SESSION_A = 'session-synthetic-a.invalid';
const SESSION_B = 'session-synthetic-b.invalid';
const SCOPE_A = { tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A };
const SCOPE_B = { tenantId: TENANT_B, projectId: PROJECT_B, sessionId: SESSION_B };

const clock = (now = NOW) => ({ now });
const insertRequest = (over = {}) => ({ version: 1, mappingRef: REF, scope: { ...SCOPE_A },
  expiresAt: NOW + HOUR, ...over });
const lookup = (over = {}) => ({ version: 1, mappingRef: REF, scope: { ...SCOPE_A }, ...over });
const command = (over = {}) => ({ version: 1, mappingRef: REF, scope: { ...SCOPE_A },
  expectedRevision: 1, action: 'ACTIVATE', ...over });
const refused = (reason) => ({ version: 1, state: 'REFUSED', reason });
const absent = (reason) => ({ version: 1, state: 'ABSENT', reason });

/** One registry holding one mapping, at `CREATED` revision 1, created at `NOW`. */
function seeded(capacity = 8, over = {}) {
  const registry = createMappingMetadataRegistry({ capacity });
  const inserted = registry.insert(insertRequest(over), clock());
  assert.equal(inserted.state, 'INSERTED', 'the fixture must insert');
  return { registry, inserted: inserted.metadata };
}
/** Runs `body` and reports only whether it escaped as a throw. Planted values never reach a message. */
function escapes(body) {
  try { body(); return false; } catch { return true; }
}

/**
 * The test-local INCOMPLETE registry this issue forbids, kept so the reason it is forbidden is
 * replayable rather than asserted. It keeps a current record like the real one, but a transition may
 * be validated against a CALLER-CACHED copy and its read and write are separated by an `await` the
 * way any storage seam separates them, so two racing callers read the same revision and both apply.
 */
function createIncompleteRegistry({ capacity }) {
  const root = new Map();
  let size = 0;
  const bucket = (scope) => {
    let byProject = root.get(scope.tenantId);
    if (byProject === undefined) { byProject = new Map(); root.set(scope.tenantId, byProject); }
    let bySession = byProject.get(scope.projectId);
    if (bySession === undefined) { bySession = new Map(); byProject.set(scope.projectId, bySession); }
    let byRef = bySession.get(scope.sessionId);
    if (byRef === undefined) { byRef = new Map(); bySession.set(scope.sessionId, byRef); }
    return byRef;
  };
  const insert = (request, at) => {
    const byRef = bucket(request.scope);
    if (byRef.has(request.mappingRef) || size >= capacity) {
      return { version: 1, state: 'REFUSED', reason: 'DUPLICATE_MAPPING' };
    }
    const entry = { version: 1, mappingRef: request.mappingRef, scope: { ...request.scope },
      state: 'CREATED', revision: 1, createdAt: at.now, expiresAt: request.expiresAt };
    byRef.set(request.mappingRef, entry);
    size += 1;
    return { version: 1, state: 'INSERTED', metadata: { ...entry, scope: { ...entry.scope } } };
  };
  const current = (request) => {
    const entry = bucket(request.scope).get(request.mappingRef);
    if (entry === undefined) return { version: 1, state: 'ABSENT', reason: 'UNKNOWN_MAPPING' };
    return { version: 1, state: 'FOUND', metadata: { ...entry, scope: { ...entry.scope } } };
  };
  const transition = async (request, at) => {
    const entry = bucket(request.scope).get(request.mappingRef);
    await Promise.resolve();
    const cached = request.record ?? entry;
    if (cached === undefined) return { version: 1, state: 'REFUSED', reason: 'UNKNOWN_MAPPING' };
    const proposed = await applyLifecycle(cached, request, at);
    if (proposed.state === 'REFUSED') return proposed;
    entry.state = proposed.record.state;
    entry.revision = proposed.record.revision;
    return { version: 1, state: proposed.state, metadata: { ...entry, scope: { ...entry.scope } } };
  };
  return Object.freeze({ version: 1, capacity, insert, current, transition });
}
// The incomplete registry still uses the one transition table; only its compare-and-set is wrong.
async function applyLifecycle(cached, request, at) {
  const { applyMappingLifecycleCommand } = await import('../dist/mapping-lifecycle.js');
  return applyMappingLifecycleCommand({ ...cached }, {
    version: 1, mappingRef: cached.mappingRef, scope: { ...cached.scope },
    expectedRevision: request.expectedRevision, action: request.action,
  }, at);
}

test('the registry declares its own bounded capacity and an empty start', () => {
  const registry = createMappingMetadataRegistry({ capacity: 3 });
  assert.equal(registry.version, 1);
  assert.equal(registry.capacity, 3);
  assert.equal(registry.size, 0);
  assert.equal(Object.isFrozen(registry), true);
  registry.insert(insertRequest(), clock());
  assert.equal(registry.size, 1);
  // The three operations are the whole surface: there is no remove, scan, enumerate or resolve.
  assert.deepEqual(Object.keys(registry).sort(), ['capacity', 'current', 'insert', 'size', 'transition',
    'version']);
});

test('unusable options throw a fixed TypeError and never echo the supplied value', () => {
  for (const options of [undefined, null, 'capacity 3', {}, { capacity: 0 }, { capacity: -1 },
    { capacity: 1.5 }, { capacity: '3' }, { capacity: Number.NaN }, { capacity: 1e12 },
    { capacity: 3, trusted: true }, [3]]) {
    const error = escapes(() => createMappingMetadataRegistry(options));
    assert.equal(error, true, `options ${JSON.stringify(options)}`);
    try { createMappingMetadataRegistry(options); assert.fail('must throw'); } catch (thrown) {
      assert.equal(thrown.constructor.name, 'TypeError');
      assert.equal(thrown.message, 'invalid mapping metadata registry options');
    }
  }
});

test('creation is CREATED at revision 1 with immutable identity, scope and expiry', () => {
  const { inserted } = seeded();
  assert.deepEqual(inserted, { version: 1, mappingRef: REF, scope: { ...SCOPE_A }, state: 'CREATED',
    revision: 1, createdAt: NOW, expiresAt: NOW + HOUR });
  assert.deepEqual(Object.keys(inserted).sort(),
    ['createdAt', 'expiresAt', 'mappingRef', 'revision', 'scope', 'state', 'version']);
  // Creation has no field for a state or a revision: a caller cannot pre-activate or pre-increment one.
  for (const forbidden of [{ state: 'ACTIVE' }, { state: 'ACTIVE', revision: 9 }, { revision: 1 },
    { revision: 41 }, { lifecycle: 'ACTIVE' }, { record: {} }, { now: NOW }]) {
    assert.deepEqual(createMappingMetadataRegistry({ capacity: 2 }).insert(insertRequest(forbidden),
      clock()), refused('INVALID_REQUEST'), `insert with ${Object.keys(forbidden).join(',')}`);
  }
  // The same reference in the same scope is already held, at revision 1 or terminal.
  const { registry } = seeded();
  assert.deepEqual(registry.insert(insertRequest(), clock()), refused('DUPLICATE_MAPPING'));
  registry.transition(command({ action: 'DELETE' }), clock());
  assert.deepEqual(registry.insert(insertRequest(), clock()), refused('DUPLICATE_MAPPING'));
  assert.deepEqual(registry.current(lookup(), clock()), absent('NOT_LIVE'));
});

test('the exact positive path creates, activates and reads back through the reducer', () => {
  const { registry, inserted } = seeded();
  assert.deepEqual(registry.current(lookup(), clock()),
    { version: 1, state: 'FOUND', metadata: inserted });
  const activated = registry.transition(command({ expectedRevision: 1 }), clock());
  assert.deepEqual(activated, { version: 1, state: 'CHANGED', metadata: { ...inserted, state: 'ACTIVE',
    revision: 2 } });
  assert.deepEqual(registry.current(lookup(), clock()), { version: 1, state: 'FOUND',
    metadata: { ...inserted, state: 'ACTIVE', revision: 2 } });
  // Every state the reducer can reach is reached here, each one revision at a time.
  const revived = createMappingMetadataRegistry({ capacity: 4 });
  revived.insert(insertRequest(), clock());
  const steps = [['ACTIVATE', 'ACTIVE', 2], ['REVOKE', 'REVOKED', 3], ['DELETE', 'DELETED', 4]];
  for (const [action, state, revision] of steps) {
    const result = revived.transition(command({ expectedRevision: revision - 1, action }), clock());
    assert.equal(result.state, 'CHANGED', `${action} applies`);
    assert.equal(result.metadata.state, state, action);
    assert.equal(result.metadata.revision, revision, action);
  }
  // A repeated terminal command is unchanged and consumes no revision.
  const repeat = revived.transition(command({ expectedRevision: 4, action: 'DELETE' }), clock());
  assert.equal(repeat.state, 'UNCHANGED');
  assert.equal(repeat.metadata.revision, 4);
});

test('of two racing commands pinned to one expected revision, exactly one applies', async () => {
  const { registry } = seeded();
  // The caller caches the record it read, then races two commands against that one revision.
  const cached = registry.current(lookup(), clock()).metadata;
  assert.equal(cached.revision, 1);
  // The real registry accepts no record at all: both callers name the same revision and nothing else.
  const race = (subject) => Promise.all([
    subject.transition(command({ expectedRevision: 1 }), clock()),
    subject.transition(command({ expectedRevision: 1, action: 'REVOKE' }), clock()),
  ]);
  const results = await race(registry);
  const applied = results.filter((result) => result.state === 'CHANGED');
  const losers = results.filter((result) => result.state === 'REFUSED');
  assert.equal(applied.length, 1,
    `exactly one competing update may apply, ${applied.length} applied: ${JSON.stringify(results)}`);
  assert.equal(losers.length, 1, `the losing command refuses: ${JSON.stringify(results)}`);
  assert.equal(losers[0].reason, 'STALE_REVISION');
  // The loser cannot overwrite the record the winner wrote.
  const final = registry.current(lookup(), clock());
  assert.equal(final.metadata.revision, applied[0].metadata.revision);
  assert.equal(final.metadata.state, applied[0].metadata.state);
  assert.deepEqual(cached.revision, 1, 'the caller cache is never written back into the registry');
});

test('the incomplete cached-record design this forbids lets both racing commands apply', async () => {
  const incomplete = createIncompleteRegistry({ capacity: 4 });
  incomplete.insert(insertRequest(), clock());
  const cached = incomplete.current(lookup()).metadata;
  const results = await Promise.all([
    incomplete.transition({ ...command({ expectedRevision: 1 }), record: cached }, clock()),
    incomplete.transition({ ...command({ expectedRevision: 1, action: 'REVOKE' }), record: cached },
      clock()),
  ]);
  // This is the red checkpoint replayed against the real implementation: the naive design applies two
  // updates at one revision, which is exactly the property the registry above refuses to violate.
  assert.equal(results.filter((result) => result.state === 'CHANGED').length, 2);
});

test('a stale expected revision refuses and cannot overwrite the final record', () => {
  const { registry } = seeded();
  const first = registry.transition(command({ expectedRevision: 1 }), clock());
  assert.equal(first.metadata.state, 'ACTIVE');
  for (const action of MAPPING_LIFECYCLE_ACTIONS) {
    const stale = registry.transition(command({ expectedRevision: 1, action }), clock());
    assert.equal(stale.state, 'REFUSED', action);
    assert.equal(stale.reason, 'STALE_REVISION', action);
  }
  assert.deepEqual(registry.current(lookup(), clock()).metadata, first.metadata);
  // A revision the registry never held is stale too, and so is one beyond its public ceiling.
  for (const expectedRevision of [3, 4, 41, Number.MAX_SAFE_INTEGER]) {
    const result = registry.transition(command({ expectedRevision }), clock());
    assert.equal(result.state, 'REFUSED', `expectedRevision ${expectedRevision}`);
    assert.equal(result.reason, 'STALE_REVISION', `expectedRevision ${expectedRevision}`);
  }
  assert.deepEqual(registry.current(lookup(), clock()).metadata, first.metadata);
});

test('a terminal entry is a tombstone: it refuses transitions and is never revived', () => {
  for (const [setup, terminal] of [['REVOKE', 'REVOKED'], ['DELETE', 'DELETED']]) {
    const { registry } = seeded();
    assert.equal(registry.transition(command({ expectedRevision: 1, action: setup }), clock())
      .metadata.state, terminal);
    const entry = registry.current(lookup(), clock());
    assert.equal(entry.state, 'ABSENT');
    assert.equal(entry.reason, 'NOT_LIVE');
    // Repeating the terminal command is idempotent: same record, no new revision.
    assert.equal(registry.transition(command({ expectedRevision: 2, action: setup }), clock()).state,
      'UNCHANGED');
    // `DELETED` is the only state a terminal entry can still reach, and only from a revocable one.
    const deleted = registry.transition(command({ expectedRevision: 2, action: 'DELETE' }), clock());
    assert.equal(deleted.state, setup === 'DELETE' ? 'UNCHANGED' : 'CHANGED', terminal);
    const terminalRevision = 2 + (setup === 'DELETE' ? 0 : 1);
    assert.equal(deleted.metadata.revision, terminalRevision, terminal);
    for (const action of ['ACTIVATE', 'EXPIRE']) {
      const revived = registry.transition(command({ expectedRevision: terminalRevision, action }),
        clock());
      assert.deepEqual(revived, refused('INVALID_TRANSITION'), `${terminal} + ${action}`);
    }
    // Terminal states of the lifecycle vocabulary are exactly the ones that are never live.
    assert.ok(MAPPING_LIFECYCLE_STATES.includes(terminal));
    assert.ok(MAPPING_LIFECYCLE_STATES.includes(deleted.metadata.state));
    assert.deepEqual(registry.current(lookup(), clock()), absent('NOT_LIVE'));
  }
});

test('expiry is restrictive at every observation and a rollback cannot undo it', () => {
  const { registry, inserted } = seeded(8, { expiresAt: NOW + 1000 });
  // The last live instant is one before the expiry instant; the expiry instant itself is expired.
  assert.equal(registry.transition(command({ expectedRevision: 1 }), clock(NOW + 999)).state, 'CHANGED');
  assert.equal(registry.current(lookup(), clock(NOW + 1000)).state, 'ABSENT');
  assert.equal(registry.current(lookup(), clock(NOW + 1000)).reason, 'NOT_LIVE');
  // Observing the expiry latched it: ACTIVE at revision 2 became EXPIRED at revision 3, and nothing
  // moves it back. `expectedRevision: 2` is stale only because the observation consumed a revision.
  assert.deepEqual(registry.transition(command({ expectedRevision: 2, action: 'REVOKE' }),
    clock(NOW + 1001)), refused('STALE_REVISION'));
  assert.deepEqual(registry.transition(command({ expectedRevision: 3, action: 'ACTIVATE' }),
    clock(NOW + 1001)), refused('INVALID_TRANSITION'));
  assert.deepEqual(registry.transition(command({ expectedRevision: 3, action: 'REVOKE' }),
    clock(NOW + 1001)), refused('INVALID_TRANSITION'));
  // A clock that moves backwards is refused outright, whatever it would otherwise have shown.
  for (const now of [NOW, NOW + 999, NOW - 1, inserted.createdAt - 1]) {
    assert.deepEqual(registry.current(lookup(), clock(now)), refused('CLOCK_ROLLBACK'), `now ${now}`);
    assert.deepEqual(registry.transition(command({ expectedRevision: 3 }), clock(now)),
      refused('CLOCK_ROLLBACK'), `now ${now}`);
  }
  // Expiry is observed on every operation, so an insert-then-never-touched record is caught too.
  const untouched = createMappingMetadataRegistry({ capacity: 4 });
  untouched.insert(insertRequest({ expiresAt: NOW + 10 }), clock());
  assert.equal(untouched.current(lookup(), clock(NOW + 9)).state, 'FOUND');
  assert.equal(untouched.current(lookup(), clock(NOW + 10)).reason, 'NOT_LIVE');
  // An expiry observed before a stale command consumes a revision, so that command refuses.
  const raced = seeded(8, { expiresAt: NOW + 5 });
  const atExpiry = raced.registry.transition(command({ expectedRevision: 1 }), clock(NOW + 5));
  assert.deepEqual(atExpiry, refused('STALE_REVISION'));
  assert.deepEqual(raced.registry.transition(command({ expectedRevision: 2 }), clock(NOW + 5)),
    refused('INVALID_TRANSITION'));
});

test('a full registry refuses new inserts and never evicts a tombstone', () => {
  const registry = createMappingMetadataRegistry({ capacity: 2 });
  registry.insert(insertRequest({ mappingRef: REF, scope: { ...SCOPE_A } }), clock());
  const second = insertRequest({ mappingRef: OTHER_REF, scope: { ...SCOPE_A } });
  assert.equal(registry.insert(second, clock()).state, 'INSERTED');
  assert.equal(registry.size, 2);
  assert.deepEqual(registry.insert(insertRequest({ mappingRef: 'map-synthetic-third.invalid',
    scope: { ...SCOPE_A } }), clock()), refused('REGISTRY_FULL'));
  assert.equal(registry.size, 2, 'a refused insert changes nothing');
  // Terminaling an entry does not free a slot: the tombstone is what prevents a revival.
  assert.equal(registry.transition(command({ expectedRevision: 1, action: 'REVOKE' }), clock()).state,
    'CHANGED');
  assert.equal(registry.size, 2);
  assert.deepEqual(registry.insert(insertRequest({ mappingRef: 'map-synthetic-third.invalid',
    scope: { ...SCOPE_A } }), clock()), refused('REGISTRY_FULL'));
  assert.deepEqual(registry.current(lookup(), clock()), absent('NOT_LIVE'));
  // A reference the registry already holds is named even when the registry is full.
  assert.deepEqual(registry.insert(insertRequest(), clock()), refused('DUPLICATE_MAPPING'));
  assert.equal(registry.current(lookup({ mappingRef: OTHER_REF }), clock()).state, 'FOUND');
});

test('equal references in two scopes stay isolated in one registry', () => {
  const registry = createMappingMetadataRegistry({ capacity: 4 });
  registry.insert(insertRequest({ scope: { ...SCOPE_A } }), clock());
  registry.insert(insertRequest({ scope: { ...SCOPE_B } }), clock());
  assert.equal(registry.size, 2, 'one reference in each scope is two entries');
  // One differing part is already a foreign scope: only the whole three-part scope matches.
  for (const over of [{ tenantId: TENANT_B }, { projectId: PROJECT_B }, { sessionId: SESSION_B }]) {
    const other = { ...SCOPE_A, ...over };
    assert.deepEqual(registry.current(lookup({ scope: other }), clock()), absent('UNKNOWN_MAPPING'),
      `scope ${other.tenantId}/${other.projectId}/${other.sessionId}`);
    assert.deepEqual(registry.transition(command({ scope: other, expectedRevision: 1 }), clock()),
      refused('UNKNOWN_MAPPING'));
  }
  assert.deepEqual(registry.current(lookup({ scope: { ...SCOPE_A } }), clock()).metadata.scope,
    { ...SCOPE_A });
  const active = registry.transition(command({ scope: { ...SCOPE_A } }), clock());
  assert.equal(active.metadata.state, 'ACTIVE');
  assert.equal(active.metadata.revision, 2);
  // The other scope's record is untouched by this scope's transition.
  assert.deepEqual(registry.current(lookup({ scope: { ...SCOPE_B } }), clock()),
    { version: 1, state: 'FOUND', metadata: { ...insertRequest({ scope: { ...SCOPE_B } }) && {},
      version: 1, mappingRef: REF, scope: { ...SCOPE_B }, state: 'CREATED', revision: 1,
      createdAt: NOW, expiresAt: NOW + HOUR } });
  // A revision this scope never held is stale for it, however current it is in the other scope.
  assert.deepEqual(registry.transition(command({ scope: { ...SCOPE_B }, expectedRevision: 2,
    action: 'REVOKE' }), clock()), refused('STALE_REVISION'));
  assert.deepEqual(registry.current(lookup({ scope: { ...SCOPE_A } }), clock()).metadata,
    { ...active.metadata });
  // A foreign scope and an unknown reference are the same answer, so neither discloses the other.
  for (const request of [lookup({ scope: { ...SCOPE_B } }), lookup({ mappingRef: OTHER_REF })]) {
    const foreign = createMappingMetadataRegistry({ capacity: 4 });
    assert.deepEqual(foreign.current(request, clock()), absent('UNKNOWN_MAPPING'));
  }
});

test('delimiter-shaped identifiers cannot collide into one another', () => {
  // Each pair below shares one `|`-joined key under a naive flat map, and is a different structural
  // path here: tenant, project, session and reference are four levels, not one string.
  const pairs = [
    [{ tenantId: 'tsynthetic.invalid', projectId: 'psynthetic.invalid',
      sessionId: 'ssynthetic.invalid|x' }, 'y.invalid'],
    [{ tenantId: 'tsynthetic.invalid', projectId: 'psynthetic.invalid', sessionId: 'ssynthetic.invalid' },
      'x|y.invalid'],
    [{ tenantId: 'tsynthetic.invalid|x', projectId: 'psynthetic.invalid', sessionId: 'ssynthetic.invalid' },
      'y.invalid'],
    [{ tenantId: 'tsynthetic.invalid', projectId: 'psynthetic.invalid|x', sessionId: 'ssynthetic.invalid' },
      'y.invalid'],
  ];
  const registry = createMappingMetadataRegistry({ capacity: 8 });
  for (const [scope, mappingRef] of pairs) registry.insert(insertRequest({ scope, mappingRef }), clock());
  assert.equal(registry.size, pairs.length, 'each path is its own entry');
  for (const [scope, mappingRef] of pairs) {
    const found = registry.current(lookup({ scope, mappingRef }), clock());
    assert.equal(found.state, 'FOUND', `${scope.tenantId}|${scope.projectId}`);
    assert.deepEqual(found.metadata.scope, scope);
    assert.equal(found.metadata.revision, 1, 'no path was advanced by another');
  }
});

test('generated scope and revision permutations stay isolated', () => {
  /** A deterministic xorshift32 generator: its low bits are usable, unlike a plain LCG's. */
  function generate(seed, length) {
    let x = (seed >>> 0) || 1;
    const next = () => {
      x ^= x << 13; x >>>= 0;
      x ^= x >>> 17;
      x ^= x << 5; x >>>= 0;
      return x;
    };
    const steps = [];
    for (let index = 0; index < length; index += 1) steps.push(next());
    return steps;
  }
  const tenants = [TENANT_A, TENANT_B, 'tenant-synthetic-a.invalid|project-synthetic-b.invalid'];
  const projects = [PROJECT_A, PROJECT_B, 'project-synthetic-a.invalid|session-synthetic-b.invalid'];
  const sessions = [SESSION_A, SESSION_B, 'session-synthetic-a.invalid|map-synthetic.invalid'];
  const scopes = [];
  for (const tenantId of tenants) {
    for (const projectId of projects) {
      for (const sessionId of sessions) scopes.push({ tenantId, projectId, sessionId });
    }
  }
  const registry = createMappingMetadataRegistry({ capacity: scopes.length });
  for (const scope of scopes) registry.insert(insertRequest({ scope }), clock());
  assert.equal(registry.size, scopes.length);
  for (const [seed, values] of [[1, generate(1, 64)], [65537, generate(65537, 64)]]) {
    for (const [index, value] of values.entries()) {
      const scope = scopes[(value >>> 0) % scopes.length];
      const action = MAPPING_LIFECYCLE_ACTIONS[(value >>> 8) % MAPPING_LIFECYCLE_ACTIONS.length];
      const expectedRevision = (value >>> 16) % 3 + 1;
      const result = registry.transition(command({ scope, expectedRevision, action }), clock());
      const found = registry.current(lookup({ scope }), clock());
      // Whatever this scope did, no other scope moved: each path owns its own current record.
      if (result.state === 'CHANGED') {
        assert.equal(result.metadata.revision, expectedRevision + 1, `seed ${seed} one step`);
        if (MAPPING_LIFECYCLE_STATES.slice(2).includes(result.metadata.state)) {
          assert.deepEqual(found, absent('NOT_LIVE'), `seed ${seed} terminal ${result.metadata.state}`);
        } else {
          assert.equal(found.state, 'FOUND', `seed ${seed} scope ${index}`);
          assert.equal(found.metadata.revision, result.metadata.revision, `seed ${seed} committed`);
          assert.equal(found.metadata.state, result.metadata.state, `seed ${seed} committed state`);
        }
      } else if (result.state === 'UNCHANGED') {
        assert.deepEqual(found, absent('NOT_LIVE'), `seed ${seed} a terminal repeat`);
      } else {
        assert.equal(result.state, 'REFUSED', `seed ${seed}`);
        assert.ok(MAPPING_METADATA_REASONS.includes(result.reason), `seed ${seed}`);
        assert.notEqual(result.reason, 'INVALID_REQUEST', `seed ${seed} a well-formed command`);
        assert.notEqual(result.reason, 'INVALID_CLOCK', `seed ${seed} a well-formed clock`);
      }
    }
    // Every scope is still readable in its own right, and every revision it reports is its own.
    const revisions = new Set();
    for (const scope of scopes) {
      const found = registry.current(lookup({ scope }), clock());
      if (found.state === 'FOUND') assert.deepEqual(found.metadata.scope, scope);
      else assert.deepEqual(found, absent('NOT_LIVE'), `seed ${seed} terminal scope`);
      if (found.state === 'FOUND') revisions.add(found.metadata.revision);
    }
    assert.ok(revisions.size > 1, `seed ${seed} must not collapse every scope onto one revision`);
  }
});

test('unknown and foreign requests return no metadata at all', () => {
  const { registry } = seeded();
  for (const request of [lookup({ mappingRef: OTHER_REF }), lookup({ scope: { ...SCOPE_B } }),
    lookup({ scope: { ...SCOPE_A, tenantId: 'tenant-synthetic-unknown.invalid' } })]) {
    assert.deepEqual(registry.current(request, clock()), absent('UNKNOWN_MAPPING'));
    assert.deepEqual(registry.transition(command({ mappingRef: request.mappingRef,
      scope: request.scope }), clock()), refused('UNKNOWN_MAPPING'));
  }
  assert.deepEqual(registry.current(lookup(), clock()).metadata.scope, { ...SCOPE_A });
});

test('malformed requests, scopes and clocks refuse with a fixed code and never throw', () => {
  const { registry } = seeded(4);
  const hostileRequests = [
    ['null request', () => null], ['string request', () => 'insert'],
    ['array request', () => []], ['missing version', () => ({ ...insertRequest(), version: undefined })],
    ['wrong version', () => insertRequest({ version: 2 })],
    ['unknown key', () => insertRequest({ approved: true })],
    ['original value', () => insertRequest({ original: 'planted-original.invalid' })],
    ['ciphertext', () => insertRequest({ ciphertext: 'planted-cipher.invalid' })],
    ['key', () => insertRequest({ key: 'planted-key.invalid' })],
    ['keyVersion', () => insertRequest({ keyVersion: 3 })],
    ['dek', () => insertRequest({ dek: 'planted-dek.invalid' })],
    ['blind index', () => insertRequest({ blindIndex: 'planted-index.invalid' })],
    ['plaintext', () => insertRequest({ plaintext: 'planted-plain.invalid' })],
    ['state at insert', () => insertRequest({ state: 'ACTIVE' })],
    ['revision at insert', () => insertRequest({ revision: 41 })],
    ['empty reference', () => insertRequest({ mappingRef: '' })],
    ['padded reference', () => insertRequest({ mappingRef: ` ${REF}` })],
    ['control character reference', () => insertRequest({ mappingRef: 'mapref' })],
    ['oversized reference', () => insertRequest({ mappingRef: 'm'.repeat(4096) })],
    ['numeric reference', () => insertRequest({ mappingRef: 7 })],
    ['fractional expiry', () => insertRequest({ expiresAt: NOW + 0.5 })],
    ['string expiry', () => insertRequest({ expiresAt: `${NOW + HOUR}` })],
    ['negative expiry', () => insertRequest({ expiresAt: -1 })],
    ['missing scope session', () => insertRequest({ scope: { tenantId: TENANT_A,
      projectId: PROJECT_A } })],
    ['extra scope key', () => insertRequest({ scope: { ...SCOPE_A, purpose: 'use' } })],
    ['empty tenant', () => insertRequest({ scope: { ...SCOPE_A, tenantId: '' } })],
    ['padded tenant', () => insertRequest({ scope: { ...SCOPE_A, tenantId: ` ${TENANT_A}` } })],
    ['numeric session', () => insertRequest({ scope: { ...SCOPE_A, sessionId: 3 } })],
    ['inherited scope', () => insertRequest({ scope: Object.assign(Object.create({ tenantId: TENANT_A }),
      { projectId: PROJECT_A, sessionId: SESSION_A }) })],
    ['unknown transition action', () => command({ action: 'PUBLISH' })],
    ['negative expectedRevision', () => command({ expectedRevision: -1 })],
    ['fractional expectedRevision', () => command({ expectedRevision: 0.5 })],
    ['string expectedRevision', () => command({ expectedRevision: '0' })],
    ['clock in the command', () => command({ now: NOW })],
    ['expiry in the command', () => command({ expiresAt: NOW + HOUR })],
  ];
  for (const [label, make] of hostileRequests) {
    const request = make();
    for (const result of [registry.insert(request, clock()), registry.current(request, clock()),
      registry.transition(request, clock())]) {
      assert.deepEqual(result, refused('INVALID_REQUEST'), label);
      assert.equal(escapes(() => registry.insert(request, clock())), false, label);
      assert.equal(escapes(() => registry.current(request, clock())), false, label);
      assert.equal(escapes(() => registry.transition(request, clock())), false, label);
      // A refusal is a fixed code: it never carries the planted value back to the caller.
      assert.ok(!JSON.stringify(result).includes('planted'), label);
    }
  }
  // The registry is unchanged by every one of them.
  assert.equal(registry.size, 1);
  assert.equal(registry.current(lookup(), clock()).state, 'FOUND');
  // A field its own operation requires is asserted against that operation: the same shape without it
  // is a well-formed lookup, so it is refused as a request and never as a missing record.
  assert.deepEqual(registry.insert({ version: 1, mappingRef: REF, scope: { ...SCOPE_A } }, clock()),
    refused('INVALID_REQUEST'), 'insert without an expiry');
  assert.deepEqual(registry.transition({ version: 1, mappingRef: REF, scope: { ...SCOPE_A },
    action: 'ACTIVATE' }, clock()), refused('INVALID_REQUEST'), 'transition without a revision');
  for (const [label, request] of [['restore', { ...command(), action: 'RESTORE' }],
    ['extend', { ...command(), action: 'EXTEND' }]]) {
    assert.deepEqual(registry.transition(request, clock()), refused('INVALID_REQUEST'), label);
  }
});

test('a throwing accessor, proxy or hostile thrown value refuses without leaking detail', () => {
  const planted = new Error('planted-internal-detail.invalid');
  const throwingValue = new Proxy({}, { get() { throw planted; } });
  const withGetter = (value, key) => Object.defineProperty({ ...value }, key,
    { enumerable: true, get() { throw planted; } });
  const hostile = [
    ['insert mappingRef getter', (request) => withGetter(request, 'mappingRef'), () => clock()],
    ['insert scope getter', (request) => withGetter(request, 'scope'), () => clock()],
    ['insert expiry getter', (request) => withGetter(request, 'expiresAt'), () => clock()],
    ['insert scope ownKeys proxy', () => new Proxy(insertRequest(), { ownKeys() { throw planted; } }),
      () => clock()],
    ['insert scope descriptor proxy', () => new Proxy(insertRequest(),
      { getOwnPropertyDescriptor() { throw planted; } }), () => clock()],
    ['insert proxy throwing value', () => new Proxy(insertRequest(),
      { ownKeys() { throw throwingValue; } }), () => clock()],
    ['lookup proxy', () => new Proxy(lookup(), { ownKeys() { throw planted; } }), () => clock()],
    ['transition proxy', () => new Proxy(command(), { ownKeys() { throw planted; } }), () => clock()],
    ['clock getter', () => clock(), () => withGetter({ now: NOW }, 'now')],
    ['clock ownKeys proxy', () => clock(),
      () => new Proxy({ now: NOW }, { ownKeys() { throw planted; } })],
  ];
  const registry = createMappingMetadataRegistry({ capacity: 4 });
  registry.insert(insertRequest(), clock());
  for (const [label, makeRequest, makeClock] of hostile) {
    for (const call of [registry.insert, registry.current, registry.transition]) {
      const result = call.call(registry, makeRequest(), makeClock());
      assert.equal(result.state, 'REFUSED', label);
      assert.ok(MAPPING_METADATA_REASONS.includes(result.reason), label);
      assert.equal(escapes(() => call.call(registry, makeRequest(), makeClock())), false, label);
      const rendered = JSON.stringify(result);
      assert.ok(!rendered.includes('planted'), `${label} must not echo the planted value`);
      assert.ok(!rendered.includes(' at '), `${label} must not echo a stack`);
      assert.ok(!rendered.includes('Error'), `${label} must not echo an exception`);
    }
  }
  assert.equal(registry.size, 1, 'a hostile request never reaches the map');
});

test('a malformed host clock refuses with its own code and nothing is logged', () => {
  const { registry } = seeded();
  const clocks = [undefined, null, {}, [], 'now', { now: 'NOW' }, { now: Number.NaN },
    { now: Number.POSITIVE_INFINITY }, { now: -1 }, { now: NOW + 0.5 }, { now: NOW, source: 'request' },
    { now: NOW, trusted: true }];
  for (const value of clocks) {
    for (const [label, call] of [['insert', registry.insert], ['current', registry.current],
      ['transition', registry.transition]]) {
      const request = label === 'insert' ? insertRequest() : label === 'current' ? lookup()
        : command({ expectedRevision: 1 });
      assert.deepEqual(call.call(registry, request, value), refused('INVALID_CLOCK'), `${label} clock`);
      assert.equal(escapes(() => call.call(registry, request, value)), false, `${label} clock`);
    }
  }
  // Nothing this registry does writes to a console, including while refusing hostile input.
  const written = [];
  const original = { log: console.log, warn: console.warn, error: console.error,
    info: console.info, debug: console.debug, trace: console.trace };
  try {
    for (const [name, sink] of Object.entries(original)) console[name] = (...args) => written.push(args);
    const hostileRegistry = createMappingMetadataRegistry({ capacity: 2 });
    for (const [label, request] of [['bad insert', insertRequest({ original: 'planted.invalid' })],
      ['bad lookup', lookup({ ciphertext: 'planted.invalid' })],
      ['bad command', command({ key: 'planted.invalid' })]]) {
      hostileRegistry.insert(request, clock());
      hostileRegistry.current(request, clock());
      hostileRegistry.transition(request, clock());
      assert.ok(written.length === 0, `${label} must not log`);
    }
  } finally {
    for (const [name, sink] of Object.entries(original)) console[name] = sink;
  }
  assert.deepEqual(written, []);
});

test('a caller cannot decide a compare-and-set with a cached record', () => {
  const { registry } = seeded();
  const cached = registry.current(lookup(), clock()).metadata;
  // A supplied record, revision or expiry has no field in any request: it is an unknown key.
  for (const extra of [{ record: cached }, { current: cached }, { revision: 1 },
    { expiresAt: NOW + HOUR }, { state: 'ACTIVE' }, { lifecycle: 'ACTIVE' }]) {
    assert.deepEqual(registry.current(lookup(extra), clock()), refused('INVALID_REQUEST'),
      `current with ${Object.keys(extra).join(',')}`);
    assert.deepEqual(registry.transition(command(extra), clock()), refused('INVALID_REQUEST'),
      `transition with ${Object.keys(extra).join(',')}`);
  }
  // What a lookup returns is the registry's own current record, not what the caller still holds.
  assert.equal(registry.transition(command({ expectedRevision: 1 }), clock()).metadata.revision, 2);
  assert.equal(cached.revision, 1, 'the caller cache is never adopted or rewritten');
  assert.equal(registry.current(lookup(), clock()).metadata.revision, 2);
  assert.deepEqual(registry.current(lookup(), clock()).metadata.state, 'ACTIVE');
});

test('caller mutation cannot alter a stored record, its scope or a returned copy', () => {
  const registry = createMappingMetadataRegistry({ capacity: 4 });
  const supplied = { ...SCOPE_A };
  const request = insertRequest({ scope: supplied });
  assert.equal(registry.insert(request, clock()).state, 'INSERTED');
  assert.equal(registry.current(lookup(), clock()).state, 'FOUND');
  // Mutating the caller's own objects after the call changes nothing that is stored: the mutated
  // request now names a foreign scope, and the stored record is still the one that was inserted.
  supplied.tenantId = TENANT_B;
  supplied.projectId = PROJECT_B;
  assert.deepEqual(registry.insert(request, clock()), { version: 1, state: 'INSERTED',
    metadata: { version: 1, mappingRef: REF, scope: { tenantId: TENANT_B, projectId: PROJECT_B,
      sessionId: SESSION_A }, state: 'CREATED', revision: 1, createdAt: NOW, expiresAt: NOW + HOUR } },
    'the mutated request was read once, as it was');
  assert.equal(registry.size, 2, 'the mutated scope is its own entry');
  assert.deepEqual(registry.current(lookup(), clock()).metadata.scope, { ...SCOPE_A });
  assert.deepEqual(registry.current(lookup(), clock()).metadata.revision, 1);
  for (const found of [registry.current(lookup(), clock()), registry.transition(
    command({ expectedRevision: 1 }), clock())]) {
    const metadata = found.metadata;
    assert.equal(Object.isFrozen(found), true);
    assert.equal(Object.isFrozen(metadata), true);
    assert.equal(Object.isFrozen(metadata.scope), true);
    assert.equal(escapes(() => { metadata.revision = 41; }), true, 'a returned record is frozen');
    assert.equal(escapes(() => { metadata.scope.tenantId = TENANT_B; }), true);
    assert.equal(escapes(() => { metadata.state = 'REVOKED'; }), true);
  }
  // Each read hands back a fresh copy, so no two results share one mutable record.
  const first = registry.current(lookup(), clock()).metadata;
  const second = registry.current(lookup(), clock()).metadata;
  assert.deepEqual(first, second);
  assert.notEqual(first, second);
  assert.notEqual(first.scope, second.scope);
  // The stored record survived all of it: it is a tombstone now, still holding exactly its own scope.
  assert.equal(registry.transition(command({ expectedRevision: 2, action: 'REVOKE' }), clock()).state,
    'CHANGED');
  assert.deepEqual(registry.current(lookup(), clock()), absent('NOT_LIVE'));
  assert.deepEqual(registry.current(lookup({ scope: { tenantId: TENANT_B, projectId: PROJECT_B,
    sessionId: SESSION_A } }), clock()).metadata.revision, 1, 'the mutated-scope entry is untouched');
  assert.equal(registry.size, 2);
});

test('results carry metadata only: a fixed envelope, no originals, keys or exceptions', () => {
  const registry = createMappingMetadataRegistry({ capacity: 4 });
  const rendered = JSON.stringify([
    registry.insert(insertRequest(), clock()), registry.current(lookup(), clock()),
    registry.transition(command({ expectedRevision: 1 }), clock()),
    registry.current(lookup({ scope: { ...SCOPE_B } }), clock()),
    registry.insert(insertRequest({ original: 'planted-original.invalid' }), clock()),
  ]);
  const fresh = createMappingMetadataRegistry({ capacity: 4 });
  assert.deepEqual(Object.keys(fresh.insert(insertRequest(), clock())).sort(),
    ['metadata', 'state', 'version']);
  assert.deepEqual(Object.keys(fresh.current(lookup({ mappingRef: OTHER_REF }), clock())).sort(),
    ['reason', 'state', 'version']);
  assert.deepEqual(Object.keys(fresh.transition(command({ expectedRevision: 9 }), clock())).sort(),
    ['reason', 'state', 'version']);
  for (const planted of ['original', 'cipher', 'dek', 'plaintext', 'password', 'apiKey', 'planted']) {
    assert.ok(!rendered.includes(planted), `the result must not carry ${planted}`);
  }
});

test('every refusal code this registry can return is one of its fixed codes', () => {
  const { registry } = seeded(2);
  const seen = new Set();
  const note = (result) => {
    assert.ok(['INSERTED', 'CHANGED', 'UNCHANGED', 'FOUND', 'ABSENT', 'REFUSED'].includes(result.state),
      `unexpected state ${String(result.state)}`);
    if (result.state === 'REFUSED' || result.state === 'ABSENT') {
      assert.ok(MAPPING_METADATA_REASONS.includes(result.reason),
        `unexpected refusal code ${String(result.reason)}`);
      seen.add(result.reason);
    } else {
      assert.equal('reason' in result, false, 'a record is never a refusal');
    }
    return result;
  };
  // A held reference is named as a duplicate before its window is examined, so `INVALID_EXPIRY` is
  // read from an empty registry rather than from one that already holds the reference.
  note(createMappingMetadataRegistry({ capacity: 2 }).insert(insertRequest({ expiresAt: NOW }),
    clock()));
  note(registry.insert(insertRequest(), clock()));
  note(registry.insert(insertRequest(), clock()));
  note(registry.insert(insertRequest({ mappingRef: OTHER_REF }), clock()));
  note(registry.insert(insertRequest({ mappingRef: 'map-synthetic-third.invalid' }), clock()));
  note(registry.insert(insertRequest({ mappingRef: REF }), { now: 'later' }));
  note(registry.current(lookup({ mappingRef: OTHER_REF }), clock()));
  note(registry.current(lookup({ scope: { ...SCOPE_B } }), clock()));
  note(registry.transition(command({ expectedRevision: 7 }), clock()));
  note(registry.transition(command({ expectedRevision: 1 }), clock()));
  note(registry.transition(command({ expectedRevision: 2 }), clock(NOW - 1)));
  note(registry.current(lookup(), clock(NOW + HOUR)));
  note(registry.transition(command({ expectedRevision: 2, action: 'REVOKE' }),
    clock(NOW + HOUR)));
  note(registry.transition(command({ expectedRevision: 3 }), clock(NOW + HOUR)));
  note(registry.insert(insertRequest({ original: 'planted.invalid' }), clock()));
  // Every code declared here is one this registry can actually produce, and `INVALID_CLOCK` is the one
  // produced by the malformed host clock above. `REVISION_OVERFLOW` is the reducer's arithmetic
  // ceiling, two^53 changes away and unreachable from any bounded run, so it is asserted absent.
  assert.deepEqual([...seen].sort(), ['CLOCK_ROLLBACK', 'DUPLICATE_MAPPING', 'INVALID_CLOCK',
    'INVALID_EXPIRY', 'INVALID_REQUEST', 'INVALID_TRANSITION', 'NOT_LIVE', 'REGISTRY_FULL',
    'STALE_REVISION', 'UNKNOWN_MAPPING']);
  assert.equal(seen.has('REVISION_OVERFLOW'), false, 'the reducer ceiling was never reached');
});
