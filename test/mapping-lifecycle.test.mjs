// Behavior tests for the pure mapping lifecycle reducer (issue #169).
// Synthetic, non-routable `.invalid` identifiers only. No network, no credentials, no keys, no plaintext.
//
// These assertions test the function's own choices: what next record a command proposes, which fixed
// code a proposal is refused with, and that inputs are never mutated. They do not prove that a vault,
// a scheduler, a broker or any durable store performs a lifecycle effect.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  MAPPING_LIFECYCLE_ACTIONS, MAPPING_LIFECYCLE_REASONS, MAPPING_LIFECYCLE_STATES,
  applyMappingLifecycleCommand,
} from '../dist/mapping-lifecycle.js';
import { authorizeMappingOperation } from '../dist/mapping-authorization.js';

const NOW = 1_800_000_000_000;
const HOUR = 3_600_000;
const CREATED_AT = NOW - HOUR;
const EXPIRES_AT = NOW + HOUR;
const REF = 'map-synthetic-lifecycle.invalid';
const OTHER_REF = 'map-synthetic-other.invalid';
const TENANT_A = 'tenant-synthetic-a.invalid';
const TENANT_B = 'tenant-synthetic-b.invalid';
const PROJECT_A = 'project-synthetic-a.invalid';
const PROJECT_B = 'project-synthetic-b.invalid';
const SESSION_A = 'session-synthetic-a.invalid';
const SESSION_B = 'session-synthetic-b.invalid';
const PRINCIPAL_A = 'principal-synthetic-a.invalid';
const WORKLOAD_A = 'workload-synthetic-a.invalid';
const PURPOSE = 'purpose-synthetic-use.invalid';
const SINK = {
  kind: 'local.tool', ref: 'sink-local-synthetic.invalid',
  trustZone: 'LOCAL', profileId: 'profile-local-synthetic.invalid',
};

/** One structurally intact current record, one command and one host clock; cases change one field. */
function current(over = {}) {
  return {
    version: 1, mappingRef: REF,
    scope: { tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A },
    state: 'CREATED', revision: 3, createdAt: CREATED_AT, expiresAt: EXPIRES_AT, ...over,
  };
}
function command(over = {}) {
  return {
    version: 1, mappingRef: REF,
    scope: { tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A },
    expectedRevision: 3, action: 'ACTIVATE', ...over,
  };
}
const at = (now) => ({ now });
const nextRecord = (over = {}) => current(over);
const changed = (over) => ({ version: 1, state: 'CHANGED', record: nextRecord(over) });
const unchanged = (over) => ({ version: 1, state: 'UNCHANGED', record: nextRecord(over) });
const refused = (reason) => ({ version: 1, state: 'REFUSED', reason });

function apply(over = {}, commandOver = {}, now = NOW) {
  return applyMappingLifecycleCommand(current(over), command(commandOver), at(now));
}
/**
 * Runs `body` and reports only whether it escaped as a throw. The planted values inside the hostile
 * fixtures below are never handed to an assertion message, so they cannot be printed by a failure.
 */
function escapes(body) {
  try { body(); return false; } catch { return true; }
}

test('the fixed vocabulary is exactly the five lifecycle states and four actions', () => {
  assert.deepEqual(MAPPING_LIFECYCLE_STATES, ['CREATED', 'ACTIVE', 'EXPIRED', 'REVOKED', 'DELETED']);
  assert.deepEqual(MAPPING_LIFECYCLE_ACTIONS, ['ACTIVATE', 'EXPIRE', 'REVOKE', 'DELETE']);
  // QUARANTINED exists in the security model but is not a state this reducer can hold or propose.
  assert.ok(!MAPPING_LIFECYCLE_STATES.includes('QUARANTINED'));
  assert.ok(!MAPPING_LIFECYCLE_STATES.includes('RESTORED'));
  assert.ok(!MAPPING_LIFECYCLE_ACTIONS.includes('EXTEND'));
});

// The literal matrix: every (state, action) pair at a clock strictly before expiry.
const BEFORE_EXPIRY = {
  'CREATED|ACTIVATE': changed({ state: 'ACTIVE', revision: 4 }),
  'CREATED|EXPIRE': refused('NOT_EXPIRED'),
  'CREATED|REVOKE': changed({ state: 'REVOKED', revision: 4 }),
  'CREATED|DELETE': changed({ state: 'DELETED', revision: 4 }),
  'ACTIVE|ACTIVATE': refused('INVALID_TRANSITION'),
  'ACTIVE|EXPIRE': refused('NOT_EXPIRED'),
  'ACTIVE|REVOKE': changed({ state: 'REVOKED', revision: 4 }),
  'ACTIVE|DELETE': changed({ state: 'DELETED', revision: 4 }),
  'EXPIRED|ACTIVATE': refused('INVALID_TRANSITION'),
  'EXPIRED|EXPIRE': unchanged({ state: 'EXPIRED' }),
  'EXPIRED|REVOKE': refused('INVALID_TRANSITION'),
  'EXPIRED|DELETE': changed({ state: 'DELETED', revision: 4 }),
  'REVOKED|ACTIVATE': refused('INVALID_TRANSITION'),
  'REVOKED|EXPIRE': refused('INVALID_TRANSITION'),
  'REVOKED|REVOKE': unchanged({ state: 'REVOKED' }),
  'REVOKED|DELETE': changed({ state: 'DELETED', revision: 4 }),
  'DELETED|ACTIVATE': refused('INVALID_TRANSITION'),
  'DELETED|EXPIRE': refused('INVALID_TRANSITION'),
  'DELETED|REVOKE': refused('INVALID_TRANSITION'),
  'DELETED|DELETE': unchanged({ state: 'DELETED' }),
};
// The same matrix at exactly the expiry instant: expiry applies, activation does not.
const AT_EXPIRY = {
  ...BEFORE_EXPIRY,
  'CREATED|ACTIVATE': refused('EXPIRY_REACHED'),
  'CREATED|EXPIRE': changed({ state: 'EXPIRED', revision: 4 }),
  'ACTIVE|ACTIVATE': refused('INVALID_TRANSITION'),
  'ACTIVE|EXPIRE': changed({ state: 'EXPIRED', revision: 4 }),
};

test('every state and action pair returns its literal outcome before expiry', () => {
  assert.equal(Object.keys(BEFORE_EXPIRY).length, MAPPING_LIFECYCLE_STATES.length * MAPPING_LIFECYCLE_ACTIONS.length);
  for (const state of MAPPING_LIFECYCLE_STATES) {
    for (const action of MAPPING_LIFECYCLE_ACTIONS) {
      const result = apply({ state }, { action });
      assert.deepEqual(result, BEFORE_EXPIRY[`${state}|${action}`], `${state} + ${action}`);
    }
  }
});

test('every state and action pair returns its literal outcome at exactly the expiry instant', () => {
  for (const state of MAPPING_LIFECYCLE_STATES) {
    for (const action of MAPPING_LIFECYCLE_ACTIONS) {
      const result = apply({ state }, { action }, EXPIRES_AT);
      assert.deepEqual(result, AT_EXPIRY[`${state}|${action}`], `${state} + ${action} at expiry`);
    }
  }
});

test('expiry is inclusive: the last usable instant activates, the expiry instant expires', () => {
  assert.deepEqual(apply({}, {}, EXPIRES_AT - 1), changed({ state: 'ACTIVE', revision: 4 }));
  assert.deepEqual(apply({}, {}, EXPIRES_AT), refused('EXPIRY_REACHED'));
  assert.deepEqual(apply({}, {}, EXPIRES_AT + 1), refused('EXPIRY_REACHED'));
  assert.deepEqual(apply({}, { action: 'EXPIRE' }, EXPIRES_AT - 1), refused('NOT_EXPIRED'));
  assert.deepEqual(apply({}, { action: 'EXPIRE' }, EXPIRES_AT), changed({ state: 'EXPIRED', revision: 4 }));
  assert.deepEqual(apply({}, { action: 'EXPIRE' }, EXPIRES_AT + 1), changed({ state: 'EXPIRED', revision: 4 }));
});

test('no state is ever reachable from EXPIRED, REVOKED or DELETED except a later DELETE', () => {
  for (const state of ['EXPIRED', 'REVOKED', 'DELETED']) {
    for (const action of MAPPING_LIFECYCLE_ACTIONS) {
      const result = apply({ state }, { action });
      if (result.state === 'CHANGED') {
        assert.equal(result.record.state, 'DELETED', `${state} + ${action} may only reach DELETED`);
      } else if (result.state === 'UNCHANGED') {
        // The only "nothing happens" outcome here is this record repeating its own terminal command.
        assert.equal(result.record.state, state, `${state} + ${action} repeats its own state`);
      } else {
        assert.equal(result.reason, 'INVALID_TRANSITION', `${state} + ${action}`);
      }
    }
  }
});

test('every effective change increments the revision exactly once', () => {
  const changes = [['CREATED', 'ACTIVATE', 'ACTIVE'], ['CREATED', 'REVOKE', 'REVOKED'],
    ['CREATED', 'DELETE', 'DELETED'], ['ACTIVE', 'REVOKE', 'REVOKED'], ['ACTIVE', 'DELETE', 'DELETED'],
    ['EXPIRED', 'DELETE', 'DELETED'], ['REVOKED', 'DELETE', 'DELETED']];
  for (const [state, action, target] of changes) {
    assert.deepEqual(apply({ state, revision: 41 }, { action, expectedRevision: 41 }),
      changed({ state: target, revision: 42 }), `${state} + ${action}`);
  }
  assert.deepEqual(apply({ state: 'CREATED', revision: 41 }, { action: 'EXPIRE', expectedRevision: 41 },
    EXPIRES_AT), changed({ state: 'EXPIRED', revision: 42 }));
  // An unchanged record never bumps the revision, whatever its current value.
  for (const [state, action] of [['EXPIRED', 'EXPIRE'], ['REVOKED', 'REVOKE'], ['DELETED', 'DELETE']]) {
    assert.deepEqual(apply({ state, revision: 41 }, { action, expectedRevision: 41 }),
      unchanged({ state, revision: 41 }), `${state} + ${action}`);
  }
  // A refused proposal leaves the revision where it was; nothing here consumes a revision.
  assert.deepEqual(apply({ revision: 41 }, { expectedRevision: 41 }, EXPIRES_AT),
    refused('EXPIRY_REACHED'));
  assert.deepEqual(apply({ revision: 41 }, { expectedRevision: 40 }), refused('STALE_REVISION'));
});

test('a revision that cannot increment is refused instead of wrapping', () => {
  const max = Number.MAX_SAFE_INTEGER;
  for (const [state, action] of [['CREATED', 'ACTIVATE'], ['ACTIVE', 'REVOKE'], ['REVOKED', 'DELETE']]) {
    assert.deepEqual(apply({ state, revision: max }, { action, expectedRevision: max }),
      refused('REVISION_OVERFLOW'), `${state} + ${action} at the maximum revision`);
  }
  // A record already in the requested terminal state needs no increment and is still UNCHANGED.
  assert.deepEqual(apply({ state: 'REVOKED', revision: max }, { action: 'REVOKE', expectedRevision: max }),
    unchanged({ state: 'REVOKED', revision: max }));
  // One below the maximum still advances exactly one step.
  assert.deepEqual(apply({ state: 'CREATED', revision: max - 1 },
    { action: 'ACTIVATE', expectedRevision: max - 1 }),
    changed({ state: 'ACTIVE', revision: max }));
});

test('only the exact mapping reference, scope and revision may transition the record', () => {
  assert.deepEqual(apply({}, { mappingRef: OTHER_REF }), refused('UNKNOWN_MAPPING'));
  assert.deepEqual(apply({}, { scope: { ...command().scope, tenantId: TENANT_B } }),
    refused('SCOPE_MISMATCH'));
  assert.deepEqual(apply({}, { scope: { ...command().scope, projectId: PROJECT_B } }),
    refused('SCOPE_MISMATCH'));
  assert.deepEqual(apply({}, { scope: { ...command().scope, sessionId: SESSION_B } }),
    refused('SCOPE_MISMATCH'));
  assert.deepEqual(apply({}, { expectedRevision: 2 }), refused('STALE_REVISION'));
  assert.deepEqual(apply({}, { expectedRevision: 4 }), refused('STALE_REVISION'));
  // A stale proposal refuses on the revision, not on the transition it would have made.
  assert.deepEqual(apply({ state: 'DELETED' }, { action: 'ACTIVATE', expectedRevision: 2 }),
    refused('STALE_REVISION'));
  // A record that drifted in a different tenant cannot be moved by its own tenant's command.
  assert.deepEqual(apply({ scope: { ...current().scope, tenantId: TENANT_B } }, {}),
    refused('SCOPE_MISMATCH'));
  // The documented order: reference, then scope, then revision, then the transition itself.
  assert.deepEqual(apply({}, { mappingRef: OTHER_REF, scope: { ...command().scope, tenantId: TENANT_B },
    expectedRevision: 1 }), refused('UNKNOWN_MAPPING'));
  assert.deepEqual(apply({ state: 'DELETED' }, { scope: { ...command().scope, tenantId: TENANT_B },
    expectedRevision: 1 }), refused('SCOPE_MISMATCH'));
  assert.deepEqual(apply({ state: 'DELETED' }, { action: 'ACTIVATE' }), refused('INVALID_TRANSITION'));
});

test('expiry, creation and scope survive every command unchanged', () => {
  const actions = ['ACTIVATE', 'EXPIRE', 'REVOKE', 'DELETE'];
  for (const state of MAPPING_LIFECYCLE_STATES) {
    for (const action of actions) {
      const result = apply({ state }, { action });
      if (result.state === 'REFUSED') continue;
      assert.deepEqual(result.record.scope, current().scope, `${state} + ${action} scope`);
      assert.equal(result.record.mappingRef, REF, `${state} + ${action} reference`);
      assert.equal(result.record.createdAt, CREATED_AT, `${state} + ${action} createdAt`);
      assert.equal(result.record.expiresAt, EXPIRES_AT, `${state} + ${action} expiresAt`);
    }
  }
  // No command extends the expiry, however late the clock is.
  const late = apply({ state: 'CREATED' }, { action: 'ACTIVATE' }, EXPIRES_AT + 86_400_000);
  assert.deepEqual(late, refused('EXPIRY_REACHED'));
  assert.deepEqual(apply({ state: 'CREATED' }, { action: 'EXPIRE' }, EXPIRES_AT + 86_400_000),
    changed({ state: 'EXPIRED', revision: 4 }));
  // Re-sending the same expiry inside a command cannot rewrite it either.
  assert.deepEqual(apply({}, { expiresAt: EXPIRES_AT + 86_400_000 }), refused('INVALID_COMMAND'));
});

test('repeated terminal commands are idempotent and a stale repeat still refuses', () => {
  const revoked = apply({ state: 'CREATED' }, { action: 'REVOKE' }).record;
  const repeat = (record, action, expectedRevision) => applyMappingLifecycleCommand(
    record, { version: 1, mappingRef: record.mappingRef, scope: { ...record.scope },
      expectedRevision, action }, at(NOW));
  assert.deepEqual(repeat(revoked, 'REVOKE', 4), { version: 1, state: 'UNCHANGED', record: revoked });
  assert.deepEqual(repeat(revoked, 'REVOKE', 3), refused('STALE_REVISION'));
  assert.deepEqual(repeat(revoked, 'DELETE', 4), changed({ state: 'DELETED', revision: 5 }));
  const deleted = repeat(revoked, 'DELETE', 4).record;
  assert.deepEqual(repeat(deleted, 'DELETE', 5), { version: 1, state: 'UNCHANGED', record: deleted });
  assert.deepEqual(repeat(deleted, 'DELETE', 4), refused('STALE_REVISION'));
  const expired = apply({ state: 'CREATED' }, { action: 'EXPIRE' }, EXPIRES_AT).record;
  assert.deepEqual(repeat(expired, 'EXPIRE', 4), { version: 1, state: 'UNCHANGED', record: expired });
  // An ACTIVE record is not touched by its own ACTIVATE command: there is no reactivation.
  const active = apply({}, {}).record;
  assert.deepEqual(repeat(active, 'ACTIVATE', 4), refused('INVALID_TRANSITION'));
});

test('generated command sequences stay monotonic and never revive a terminal record', () => {
  /**
   * A deterministic xorshift32 generator: its low bits are usable, unlike a plain LCG's. It produces
   * proposals only. The host, not this sequence, would decide which commands are ever issued.
   */
  function generate(seed, length) {
    let x = (seed >>> 0) || 1;
    const next = () => {
      x ^= x << 13; x >>>= 0;
      x ^= x >>> 17;
      x ^= x << 5; x >>>= 0;
      return x;
    };
    const steps = [];
    for (let index = 0; index < length; index += 1) {
      const action = MAPPING_LIFECYCLE_ACTIONS[next() % MAPPING_LIFECYCLE_ACTIONS.length];
      // Clocks from the current instant to six hours later straddle the expiry instant.
      steps.push({ action, now: NOW + (next() % 7) * HOUR });
    }
    return steps;
  }
  const terminal = ['EXPIRED', 'REVOKED', 'DELETED'];
  for (const seed of [1, 7, 169, 65537, 4294967295]) {
    let record = current();
    let previousRevision = record.revision;
    let reachedTerminal = false;
    for (const step of generate(seed, 200)) {
      const result = applyMappingLifecycleCommand(record, {
        version: 1, mappingRef: record.mappingRef, scope: { ...record.scope },
        expectedRevision: record.revision, action: step.action,
      }, at(step.now));
      assert.ok(['CHANGED', 'UNCHANGED', 'REFUSED'].includes(result.state), `seed ${seed}`);
      if (result.state === 'REFUSED') {
        assert.ok(MAPPING_LIFECYCLE_REASONS.includes(result.reason), `seed ${seed}`);
        continue;
      }
      if (result.state === 'UNCHANGED') {
        assert.deepEqual(result.record, record, `seed ${seed} unchanged repeats the current record`);
        assert.equal(result.record.revision, previousRevision, `seed ${seed} no revision bump`);
        continue;
      }
      assert.equal(result.record.revision, previousRevision + 1, `seed ${seed} one revision per change`);
      assert.equal(result.record.expiresAt, EXPIRES_AT, `seed ${seed} immutable expiry`);
      assert.equal(result.record.createdAt, CREATED_AT, `seed ${seed} immutable creation`);
      assert.deepEqual(result.record.scope, current().scope, `seed ${seed} immutable scope`);
      previousRevision = result.record.revision;
      record = result.record;
      if (terminal.includes(record.state)) reachedTerminal = true;
      // Once terminal, always terminal: no generated action revives or rolls a record back.
      if (reachedTerminal) {
        assert.ok(terminal.includes(record.state), `seed ${seed} never leaves a terminal state`);
      }
    }
    assert.ok(reachedTerminal, `seed ${seed} must reach a terminal state`);
  }
});

test('a terminal record is never revived by any later action at any later clock', () => {
  const clocks = [CREATED_AT, NOW, EXPIRES_AT - 1, EXPIRES_AT, EXPIRES_AT + HOUR, EXPIRES_AT + 86_400_000];
  for (const state of ['EXPIRED', 'REVOKED']) {
    for (const action of MAPPING_LIFECYCLE_ACTIONS) {
      for (const now of clocks) {
        const result = apply({ state }, { action }, now);
        if (result.state === 'CHANGED') {
          assert.equal(result.record.state, 'DELETED', `${state} + ${action} at ${now}`);
        } else if (result.state === 'UNCHANGED') {
          assert.equal(result.record.state, state);
        } else {
          assert.equal(result.reason, 'INVALID_TRANSITION', `${state} + ${action} at ${now}`);
        }
      }
    }
  }
});

test('the result carries metadata only: a fixed envelope, no originals, keys or exception text', () => {
  const changedResult = apply({}, {});
  assert.deepEqual(Object.keys(changedResult).sort(), ['record', 'state', 'version']);
  assert.deepEqual(Object.keys(changedResult.record).sort(),
    ['createdAt', 'expiresAt', 'mappingRef', 'revision', 'scope', 'state', 'version']);
  assert.deepEqual(Object.keys(changedResult.record.scope).sort(),
    ['projectId', 'sessionId', 'tenantId']);
  assert.deepEqual(Object.keys(apply({ state: 'DELETED' }, { action: 'ACTIVATE' })).sort(),
    ['reason', 'state', 'version']);
  const rendered = JSON.stringify([changedResult, apply({ state: 'DELETED' }, { action: 'ACTIVATE' })]);
  for (const planted of ['original', 'cipher', 'dek', 'plaintext', 'password', 'apiKey']) {
    assert.ok(!rendered.includes(planted), `the result must not carry ${planted}`);
  }
});

test('inputs are never mutated and outputs are fresh frozen records that do not alias them', () => {
  const record = current();
  const cmd = command();
  const clock = at(NOW);
  const before = [structuredClone(record), structuredClone(cmd), structuredClone(clock)];
  for (const [over, commandOver] of [[{}, {}], [{ state: 'EXPIRED' }, { action: 'EXPIRE' }],
    [{ state: 'DELETED' }, { action: 'DELETE' }], [{ state: 'DELETED' }, { action: 'ACTIVATE' }]]) {
    const result = applyMappingLifecycleCommand(current(over), command(commandOver), clock);
    if (result.state === 'REFUSED') continue;
    assert.equal(Object.isFrozen(result), true);
    assert.equal(Object.isFrozen(result.record), true);
    assert.equal(Object.isFrozen(result.record.scope), true);
    assert.notEqual(result.record, record, 'the record is copied, never returned as-is');
    assert.notEqual(result.record.scope, record.scope, 'the scope is copied too');
    assert.equal(escapes(() => { result.record.state = 'REVOKED'; }), true, 'a returned record is frozen');
    assert.equal(escapes(() => { result.record.scope.tenantId = TENANT_B; }), true);
    assert.equal(escapes(() => { result.state = 'REFUSED'; }), true);
  }
  // The very objects above came back unchanged, and the supplied clock was not rewritten either.
  assert.deepEqual(record, before[0]);
  assert.deepEqual(cmd, before[1]);
  assert.deepEqual(clock, before[2]);
  // A frozen input is accepted on the same terms as a mutable one.
  const frozenRecord = current();
  Object.freeze(frozenRecord.scope);
  Object.freeze(frozenRecord);
  assert.deepEqual(applyMappingLifecycleCommand(frozenRecord, cmd, clock),
    changed({ state: 'ACTIVE', revision: 4 }));
  assert.equal(Object.isFrozen(frozenRecord), true, 'the input record is not frozen by this seam');
  // The same inputs give the same proposal every time.
  assert.deepEqual(applyMappingLifecycleCommand(record, cmd, clock),
    applyMappingLifecycleCommand(record, cmd, clock));
});

test('malformed current records are refused with a fixed code and never throw', () => {
  const cases = [
    ['null record', () => null, 'INVALID_RECORD'],
    ['string record', () => 'expire it', 'INVALID_RECORD'],
    ['array record', () => [], 'INVALID_RECORD'],
    ['inherited prototype', () => Object.assign(Object.create({ approved: true }), current()), 'INVALID_RECORD'],
    ['null prototype with extra inherited key', () => Object.assign(Object.create({ approved: true }),
      { ...current(), approved: true }), 'INVALID_RECORD'],
    ['wrong version', () => current({ version: 2 }), 'INVALID_RECORD'],
    ['missing version', () => { const r = current(); delete r.version; return r; }, 'INVALID_RECORD'],
    ['unknown key', () => ({ ...current(), approved: true }), 'INVALID_RECORD'],
    ['trusted claim', () => ({ ...current(), trusted: true }), 'INVALID_RECORD'],
    ['empty reference', () => current({ mappingRef: '' }), 'INVALID_RECORD'],
    ['padded reference', () => current({ mappingRef: ` ${REF}` }), 'INVALID_RECORD'],
    ['control character reference', () => current({ mappingRef: `map${String.fromCharCode(1)}ok` }),
      'INVALID_RECORD'],
    ['oversized reference', () => current({ mappingRef: 'm'.repeat(4096) }), 'INVALID_RECORD'],
    ['numeric reference', () => current({ mappingRef: 7 }), 'INVALID_RECORD'],
    ['unknown state', () => current({ state: 'PENDING' }), 'INVALID_RECORD'],
    ['QUARANTINED state', () => current({ state: 'QUARANTINED' }), 'INVALID_RECORD'],
    ['missing scope session', () => { const r = current(); delete r.scope.sessionId; return r; },
      'INVALID_RECORD'],
    ['extra scope key', () => current({ scope: { ...current().scope, purpose: PURPOSE } }), 'INVALID_RECORD'],
    ['empty tenant', () => current({ scope: { ...current().scope, tenantId: '' } }), 'INVALID_RECORD'],
    ['zero revision', () => current({ revision: 0 }), 'INVALID_RECORD'],
    ['fractional revision', () => current({ revision: 1.5 }), 'INVALID_RECORD'],
    ['NaN revision', () => current({ revision: Number.NaN }), 'INVALID_RECORD'],
    ['string revision', () => current({ revision: '3' }), 'INVALID_RECORD'],
    ['infinite revision', () => current({ revision: Number.POSITIVE_INFINITY }), 'INVALID_RECORD'],
    ['missing createdAt', () => { const r = current(); delete r.createdAt; return r; }, 'INVALID_RECORD'],
    ['negative createdAt', () => current({ createdAt: -1 }), 'INVALID_RECORD'],
    ['missing expiry', () => { const r = current(); delete r.expiresAt; return r; }, 'INVALID_RECORD'],
    ['fractional expiry', () => current({ expiresAt: EXPIRES_AT + 0.5 }), 'INVALID_RECORD'],
    ['expiry equal to creation', () => current({ expiresAt: CREATED_AT }), 'INVALID_RECORD'],
    ['expiry before creation', () => current({ expiresAt: CREATED_AT - 1 }), 'INVALID_RECORD'],
  ];
  for (const [label, make, reason] of cases) {
    const result = applyMappingLifecycleCommand(make(), command(), at(NOW));
    assert.deepEqual(result, refused(reason), label);
    assert.equal(escapes(() => applyMappingLifecycleCommand(make(), command(), at(NOW))), false, label);
  }
});

test('malformed commands are refused with a fixed code and never throw', () => {
  const cases = [
    ['null command', () => null, 'INVALID_COMMAND'],
    ['string command', () => 'expire it', 'INVALID_COMMAND'],
    ['array command', () => [], 'INVALID_COMMAND'],
    ['undefined command', () => undefined, 'INVALID_COMMAND'],
    ['inherited prototype', () => Object.assign(Object.create({ approved: true }), command()),
      'INVALID_COMMAND'],
    ['wrong version', () => command({ version: 2 }), 'INVALID_COMMAND'],
    ['unknown action', () => command({ action: 'PUBLISH' }), 'INVALID_COMMAND'],
    ['RESTORE action', () => command({ action: 'RESTORE' }), 'INVALID_COMMAND'],
    ['EXTEND action', () => command({ action: 'EXTEND' }), 'INVALID_COMMAND'],
    ['numeric action', () => command({ action: 1 }), 'INVALID_COMMAND'],
    ['missing action', () => { const c = command(); delete c.action; return c; }, 'INVALID_COMMAND'],
    ['missing expectedRevision', () => { const c = command(); delete c.expectedRevision; return c; },
      'INVALID_COMMAND'],
    ['zero expectedRevision', () => command({ expectedRevision: 0 }), 'INVALID_COMMAND'],
    ['fractional expectedRevision', () => command({ expectedRevision: 2.5 }), 'INVALID_COMMAND'],
    ['unknown key', () => command({ approved: true }), 'INVALID_COMMAND'],
    ['expiresAt in command', () => command({ expiresAt: EXPIRES_AT + 1 }), 'INVALID_COMMAND'],
    ['now in command', () => command({ now: NOW }), 'INVALID_COMMAND'],
    ['empty reference', () => command({ mappingRef: '' }), 'INVALID_COMMAND'],
    ['missing scope project', () => { const c = command(); delete c.scope.projectId; return c; },
      'INVALID_COMMAND'],
  ];
  for (const [label, make, reason] of cases) {
    const result = applyMappingLifecycleCommand(current(), make(), at(NOW));
    assert.deepEqual(result, refused(reason), label);
    assert.equal(escapes(() => applyMappingLifecycleCommand(current(), make(), at(NOW))), false, label);
  }
});

test('the host clock is supplied separately, validated and never taken from the record', () => {
  const cases = [
    ['undefined clock', undefined, 'INVALID_CLOCK'],
    ['null clock', null, 'INVALID_CLOCK'],
    ['empty clock', {}, 'INVALID_CLOCK'],
    ['string now', { now: 'NOW' }, 'INVALID_CLOCK'],
    ['NaN now', { now: Number.NaN }, 'INVALID_CLOCK'],
    ['infinite now', { now: Number.POSITIVE_INFINITY }, 'INVALID_CLOCK'],
    ['negative now', { now: -1 }, 'INVALID_CLOCK'],
    ['fractional now', { now: NOW + 0.5 }, 'INVALID_CLOCK'],
    ['clock before creation', { now: CREATED_AT - 1 }, 'INVALID_CLOCK'],
    ['unknown clock key', { now: NOW, source: 'request' }, 'INVALID_CLOCK'],
    ['array clock', [], 'INVALID_CLOCK'],
  ];
  for (const [label, value, reason] of cases) {
    const result = applyMappingLifecycleCommand(current(), command(), value);
    assert.deepEqual(result, refused(reason), label);
    assert.equal(escapes(() => applyMappingLifecycleCommand(current(), command(), value)), false, label);
  }
  // The creation instant itself is a valid clock; it is never required to be strictly later.
  assert.deepEqual(applyMappingLifecycleCommand(current(), command(), at(CREATED_AT)),
    changed({ state: 'ACTIVE', revision: 4 }));
});

test('a throwing accessor, proxy or hostile thrown value refuses without leaking detail', () => {
  const planted = new Error('planted-internal-detail.invalid');
  const hostileProxy = new Proxy({ ...current() }, { ownKeys() { throw planted; } });
  const thrownValue = new Proxy({}, { get() { throw planted; } });
  const cases = [
    ['record getter', () => Object.defineProperty({ ...current() }, 'state',
      { enumerable: true, get() { throw planted; } })],
    ['record revision getter', () => Object.defineProperty({ ...current() }, 'revision',
      { enumerable: true, get() { throw planted; } })],
    ['record scope getter', () => Object.defineProperty({ ...current() }, 'scope',
      { enumerable: true, get() { throw planted; } })],
    ['record proxy ownKeys', () => hostileProxy],
    ['record proxy descriptor', () => new Proxy({ ...current() },
      { getOwnPropertyDescriptor() { throw planted; } })],
    ['record proxy throwing error value', () => new Proxy({ ...current() },
      { ownKeys() { throw thrownValue; } })],
    ['command getter', () => Object.defineProperty({ ...command() }, 'action',
      { enumerable: true, get() { throw planted; } })],
    ['command proxy ownKeys', () => new Proxy({ ...command() }, { ownKeys() { throw planted; } })],
    ['clock getter', () => Object.defineProperty({ ...at(NOW) }, 'now',
      { enumerable: true, get() { throw planted; } })],
    ['clock proxy ownKeys', () => new Proxy({ ...at(NOW) }, { ownKeys() { throw thrownValue; } })],
  ];
  for (const [label, make] of cases) {
    assert.equal(escapes(() => applyMappingLifecycleCommand(make(), command(), at(NOW))), false, label);
    assert.equal(escapes(() => applyMappingLifecycleCommand(current(), make(), at(NOW))), false, label);
    assert.equal(escapes(() => applyMappingLifecycleCommand(current(), command(), make())), false, label);
  }
  // Every hostile input lands on a fixed code, and no result carries the planted detail.
  for (const [label, make] of cases) {
    for (const result of [applyMappingLifecycleCommand(make(), command(), at(NOW)),
      applyMappingLifecycleCommand(current(), make(), at(NOW)),
      applyMappingLifecycleCommand(current(), command(), make())]) {
      assert.equal(result.state, 'REFUSED', label);
      assert.ok(MAPPING_LIFECYCLE_REASONS.includes(result.reason), label);
      const rendered = JSON.stringify(result);
      assert.ok(!rendered.includes('planted'), `${label} must not echo the planted value`);
      assert.ok(!rendered.includes(' at '), `${label} must not echo a stack`);
    }
  }
});

test('a null-prototype record and command are judged on their own data', () => {
  const neutral = (value) => Object.assign(Object.create(null), structuredClone(value));
  assert.deepEqual(applyMappingLifecycleCommand(neutral(current()), neutral(command()), neutral(at(NOW))),
    changed({ state: 'ACTIVE', revision: 4 }));
  // A record with a symbol key or a non-Object prototype is malformed, however complete its data looks.
  const symbolKeyed = current();
  symbolKeyed[Symbol('approved')] = true;
  assert.deepEqual(applyMappingLifecycleCommand(symbolKeyed, command(), at(NOW)),
    refused('INVALID_RECORD'));
  assert.deepEqual(applyMappingLifecycleCommand(Object.create({ state: 'DELETED' }), command(), at(NOW)),
    refused('INVALID_RECORD'));
  assert.deepEqual(applyMappingLifecycleCommand(current(), Object.create(command()), at(NOW)),
    refused('INVALID_COMMAND'));
});

test('every refusal code this reducer can return is one of its fixed codes', () => {
  const seen = new Set();
  const record = (result) => {
    assert.ok(['CHANGED', 'UNCHANGED', 'REFUSED'].includes(result.state));
    if (result.state === 'REFUSED') {
      assert.ok(MAPPING_LIFECYCLE_REASONS.includes(result.reason),
        `unexpected refusal code ${String(result.reason)}`);
      seen.add(result.reason);
    } else {
      assert.ok(!('reason' in result), 'a proposed record is never a refusal');
    }
    return result;
  };
  record(apply({}, {}));
  record(apply({ state: 'EXPIRED' }, { action: 'EXPIRE' }));
  record(apply({ state: 'CREATED' }, { action: 'EXPIRE' }));
  record(apply({ state: 'CREATED' }, { action: 'ACTIVATE' }, EXPIRES_AT));
  record(apply({ state: 'DELETED' }, { action: 'ACTIVATE' }));
  record(apply({}, { mappingRef: OTHER_REF }));
  record(apply({}, { scope: { ...command().scope, tenantId: TENANT_B } }));
  record(apply({}, { expectedRevision: 2 }));
  record(apply({ revision: Number.MAX_SAFE_INTEGER }, { expectedRevision: Number.MAX_SAFE_INTEGER }));
  record(applyMappingLifecycleCommand(current({ state: 'PENDING' }), command(), at(NOW)));
  record(applyMappingLifecycleCommand(current(), command({ action: 'RESTORE' }), at(NOW)));
  record(applyMappingLifecycleCommand(current(), command(), at(CREATED_AT - 1)));
  assert.deepEqual([...seen].sort(), ['EXPIRY_REACHED', 'INVALID_CLOCK', 'INVALID_COMMAND',
    'INVALID_RECORD', 'INVALID_TRANSITION', 'NOT_EXPIRED', 'REVISION_OVERFLOW', 'SCOPE_MISMATCH',
    'STALE_REVISION', 'UNKNOWN_MAPPING']);
  assert.equal(seen.size, MAPPING_LIFECYCLE_REASONS.length);
});

// --- Local adaptation to the existing authorization seam -------------------------------
// The reducer and `authorizeMappingOperation` are separate seams with separate metadata shapes. These
// tests project a proposed next record onto that seam's record locally, in the test only. Nothing here
// integrates the two modules, and nothing here shows that a caller can authorize a lifecycle change.

function authorizedParts(record, operation, now = NOW) {
  const context = { tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A, purpose: PURPOSE };
  const subject = { principalId: PRINCIPAL_A, workloadId: WORKLOAD_A };
  return {
    request: { version: 1, mappingRef: REF, subject: { ...subject }, context: { ...context },
      destination: { ...SINK }, operation },
    host: { authenticated: { subject: { ...subject }, context: { ...context } },
      observed: { destination: { ...SINK } } },
    // Test-local projection: lifecycle metadata as the authorization seam names it.
    mapping: { version: 1, mappingRef: record.mappingRef, scope: { ...record.scope },
      lifecycle: record.state, semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
      revision: record.revision, expiresAt: record.expiresAt },
    grant: { version: 1, mappingRef: REF, revision: record.revision, principal: { ...subject },
      context: { ...context }, destination: { ...SINK }, operation, expiresAt: now + HOUR },
    clock: { now },
  };
}
function authorizationFor(record, operation, now = NOW) {
  const parts = authorizedParts(record, operation, now);
  return authorizeMappingOperation(parts.request, parts.host, parts.mapping, parts.grant, parts.clock);
}

test('the ACTIVE record this reducer proposes is still an authorizable mapping before expiry', () => {
  const active = apply({}, {}).record;
  assert.equal(active.state, 'ACTIVE');
  for (const operation of ['USE', 'DISPLAY', 'EXPORT']) {
    assert.deepEqual(authorizationFor(active, operation),
      { version: 1, state: 'AUTHORIZED', reason: 'AUTHORIZED' }, operation);
  }
  assert.equal(authorizationFor(active, 'USE', EXPIRES_AT).reason, 'MAPPING_EXPIRED');
});

test('the EXPIRED, REVOKED and DELETED records this reducer proposes authorize nothing', () => {
  const expired = apply({ state: 'CREATED' }, { action: 'EXPIRE' }, EXPIRES_AT).record;
  const revoked = apply({ state: 'ACTIVE' }, { action: 'REVOKE' }).record;
  const deleted = apply({ state: 'REVOKED' }, { action: 'DELETE' }).record;
  for (const [label, record, reason] of [['EXPIRED', expired, 'MAPPING_EXPIRED'],
    ['REVOKED', revoked, 'MAPPING_REVOKED'], ['DELETED', deleted, 'MAPPING_REVOKED']]) {
    for (const operation of ['USE', 'DISPLAY', 'EXPORT']) {
      assert.deepEqual(authorizationFor(record, operation),
        { version: 1, state: 'DENIED', reason }, `${label} ${operation}`);
    }
  }
  // A terminal record that keeps its own revision is still denied; the grant pins that revision.
  assert.deepEqual(authorizationFor(revoked, 'USE').reason, 'MAPPING_REVOKED');
});

test('the reducer never carries a key, an original or a resolution capability', () => {
  const active = apply({}, {}).record;
  assert.deepEqual(Object.keys(active).sort(),
    ['createdAt', 'expiresAt', 'mappingRef', 'revision', 'scope', 'state', 'version']);
  assert.ok(!('original' in active));
  assert.ok(!('keyVersion' in active));
  assert.ok(!('ciphertext' in active));
  // The proposed record is metadata; the authorization seam still has to grant anything using it.
  assert.equal(authorizationFor(active, 'DISPLAY').state, 'AUTHORIZED');
  const noGrant = authorizedParts(active, 'USE');
  assert.deepEqual(authorizeMappingOperation(noGrant.request, noGrant.host, noGrant.mapping,
    undefined, noGrant.clock).reason, 'NO_GRANT');
});
