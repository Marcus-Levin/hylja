// Behavior tests for the pure broker authorization seam (issue #163).
// Synthetic, non-routable `.invalid` identifiers only. No network, no credentials, no plaintext.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  MAPPING_AUTHORIZATION_OPERATIONS, MAPPING_AUTHORIZATION_REASONS,
  authorizeMappingOperation, normalizeMappingGrant,
} from '../dist/mapping-authorization.js';

const NOW = 1_800_000_000_000;
const REF = 'map-synthetic-a.invalid';
const FORGED = 'map-synthetic-forged.invalid';
const TENANT_A = 'tenant-synthetic-a.invalid';
const TENANT_B = 'tenant-synthetic-b.invalid';
const PROJECT_A = 'project-synthetic-a.invalid';
const PROJECT_B = 'project-synthetic-b.invalid';
const SESSION_A = 'session-synthetic-a.invalid';
const SESSION_B = 'session-synthetic-b.invalid';
const PRINCIPAL_A = 'principal-synthetic-a.invalid';
const PRINCIPAL_B = 'principal-synthetic-b.invalid';
const WORKLOAD_A = 'workload-synthetic-a.invalid';
const WORKLOAD_B = 'workload-synthetic-b.invalid';
const PURPOSE = 'purpose-synthetic-use.invalid';
const OTHER_PURPOSE = 'purpose-synthetic-export.invalid';
const LOCAL_SINK = {
  kind: 'local.tool', ref: 'sink-local-synthetic.invalid',
  trustZone: 'LOCAL', profileId: 'profile-local-synthetic.invalid',
};
const WEB_SINK = {
  kind: 'web', ref: 'sink-web-synthetic.invalid',
  trustZone: 'EXTERNAL', profileId: 'profile-web-synthetic.invalid',
};
const OTHER_PROFILE = {
  ...LOCAL_SINK, ref: 'sink-local-other.invalid', profileId: 'profile-local-other.invalid',
};
const ALL = {
  request: { version: 1, mappingRef: REF, subject: { principalId: PRINCIPAL_A, workloadId: WORKLOAD_A },
    context: { tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A, purpose: PURPOSE },
    destination: { ...LOCAL_SINK }, operation: 'USE' },
  host: { authenticated: { subject: { principalId: PRINCIPAL_A, workloadId: WORKLOAD_A },
    context: { tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A, purpose: PURPOSE } },
    observed: { destination: { ...LOCAL_SINK } } },
  mapping: { version: 1, mappingRef: REF,
    scope: { tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A },
    lifecycle: 'ACTIVE', semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL',
    revision: 4, expiresAt: NOW + 3_600_000 },
  grant: { version: 1, mappingRef: REF, revision: 4,
    principal: { principalId: PRINCIPAL_A, workloadId: WORKLOAD_A },
    context: { tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A, purpose: PURPOSE },
    destination: { ...LOCAL_SINK }, operation: 'USE', expiresAt: NOW + 900_000 },
  clock: { now: NOW },
};
/** A structurally intact set of inputs; every case below changes only the field under test. */
function parts() { return structuredClone(ALL); }
function set(target, path, value) {
  const keys = path.split('.');
  const last = keys.pop();
  const owner = keys.reduce((node, key) => node[key], target);
  owner[last] = value;
  return target;
}
const swap = (path, value) => (p) => set(p, path, value);
function decide(mutate) {
  const p = parts();
  if (mutate) mutate(p);
  return authorizeMappingOperation(p.request, p.host, p.mapping, p.grant, p.clock);
}
const authorized = { version: 1, state: 'AUTHORIZED', reason: 'AUTHORIZED' };
const denied = (reason) => ({ version: 1, state: 'DENIED', reason });

test('a matching trusted context and explicit USE grant authorizes USE', () => {
  assert.deepEqual(decide(), authorized);
});

test('a single explicit grant authorizes only its own operation', () => {
  for (const granted of MAPPING_AUTHORIZATION_OPERATIONS) {
    for (const requested of MAPPING_AUTHORIZATION_OPERATIONS) {
      assert.deepEqual(
        decide((p) => { p.grant.operation = granted; p.request.operation = requested; }),
        granted === requested ? authorized : denied('OPERATION_NOT_GRANTED'),
        `grant ${granted} must not authorize a ${requested} request`,
      );
    }
  }
});

test('each of DISPLAY and EXPORT needs its own separate explicit grant', () => {
  for (const granted of ['DISPLAY', 'EXPORT']) {
    assert.deepEqual(decide((p) => { p.grant.operation = granted; p.request.operation = granted; }),
      authorized);
    assert.deepEqual(decide((p) => { p.grant.operation = 'USE'; p.request.operation = granted; }),
      denied('OPERATION_NOT_GRANTED'));
    assert.deepEqual(decide((p) => { p.grant.operation = 'EXPORT'; p.request.operation = 'USE'; }),
      denied('OPERATION_NOT_GRANTED'));
  }
});

test('the decision carries only the fixed outcome, never metadata, grants or identifiers', () => {
  const decision = decide();
  assert.deepEqual(Object.keys(decision).sort(), ['reason', 'state', 'version']);
  const rendered = JSON.stringify(decision);
  for (const planted of [REF, TENANT_A, PROJECT_A, SESSION_A, PRINCIPAL_A, WORKLOAD_A, PURPOSE,
    LOCAL_SINK.ref, LOCAL_SINK.profileId, 'watermark', 'token', 'secret']) {
    assert.ok(!rendered.includes(planted), `decision must not echo ${planted}`);
  }
});

test('no grant at all denies even when everything else matches', () => {
  assert.deepEqual(decide((p) => { p.grant = undefined; }), denied('NO_GRANT'));
  assert.deepEqual(decide((p) => { p.grant = undefined; p.request.operation = 'EXPORT'; }),
    denied('NO_GRANT'));
});

test('an unknown or forged mapping reference never authorizes', () => {
  assert.deepEqual(decide(swap('request.mappingRef', FORGED)), denied('UNKNOWN_MAPPING'));
  assert.deepEqual(decide(swap('request.mappingRef', '')), denied('INVALID_REQUEST'));
  assert.deepEqual(decide(swap('request.mappingRef', '*')), denied('UNKNOWN_MAPPING'));
  assert.deepEqual(decide(swap('mapping.mappingRef', FORGED)), denied('UNKNOWN_MAPPING'));
  assert.deepEqual(decide(swap('grant.mappingRef', FORGED)), denied('GRANT_MISMATCH'));
});

test('missing trusted identity or workload denies', () => {
  assert.deepEqual(decide(swap('host.authenticated.subject.principalId', undefined)),
    denied('INVALID_CONTEXT'));
  assert.deepEqual(decide(swap('host.authenticated.subject', { workloadId: WORKLOAD_A })),
    denied('INVALID_CONTEXT'));
  assert.deepEqual(decide(swap('host.authenticated.subject.workloadId', undefined)),
    denied('INVALID_CONTEXT'));
  assert.deepEqual(decide((p) => { delete p.host.authenticated.subject.workloadId; }),
    denied('INVALID_CONTEXT'));
  // A principal-only request and host never reach the workload-bound grant to be compared.
  assert.deepEqual(decide((p) => {
    delete p.host.authenticated.subject.workloadId;
    delete p.request.subject.workloadId;
  }), denied('INVALID_REQUEST'));
  assert.deepEqual(decide(swap('host.authenticated.subject.workloadId', WORKLOAD_B)),
    denied('CONTEXT_MISMATCH'));
  assert.deepEqual(decide(swap('request.subject.principalId', PRINCIPAL_B)),
    denied('CONTEXT_MISMATCH'));
  // A request cannot inherit or omit the workload the host authenticated.
  assert.deepEqual(decide((p) => { delete p.request.subject.workloadId; }),
    denied('INVALID_REQUEST'));
  assert.deepEqual(decide((p) => { p.request.subject = { principalId: PRINCIPAL_A }; }),
    denied('INVALID_REQUEST'));
});

test('every supported operation requires a nonempty workload identity in all three records', () => {
  for (const operation of MAPPING_AUTHORIZATION_OPERATIONS) {
    const forOperation = (p) => { p.request.operation = operation; p.grant.operation = operation; };
    // All three records coherently principal-only is malformed, not an authorized human path.
    assert.deepEqual(decide((p) => {
      forOperation(p);
      delete p.request.subject.workloadId;
      delete p.host.authenticated.subject.workloadId;
      delete p.grant.principal.workloadId;
    }), denied('INVALID_REQUEST'), `coherent principal-only ${operation}`);
    // A coherent principal-only request and host cannot be rescued by a workload-bound grant.
    assert.deepEqual(decide((p) => {
      forOperation(p);
      delete p.request.subject.workloadId;
      delete p.host.authenticated.subject.workloadId;
    }), denied('INVALID_REQUEST'), `principal-only request and host, ${operation}`);
    // A request workload the host did not authenticate is not a workload identity either.
    assert.deepEqual(decide((p) => {
      forOperation(p);
      delete p.host.authenticated.subject.workloadId;
      delete p.grant.principal.workloadId;
    }), denied('INVALID_CONTEXT'), `principal-only host identity, ${operation}`);
    // A grant whose principal is principal-only is malformed trusted context.
    assert.deepEqual(decide((p) => {
      forOperation(p);
      delete p.grant.principal.workloadId;
    }), denied('INVALID_CONTEXT'), `principal-only grant principal, ${operation}`);
    // Blank is not an identity: empty and whitespace-only workload values all deny.
    assert.deepEqual(decide((p) => { forOperation(p); p.request.subject.workloadId = ''; }),
      denied('INVALID_REQUEST'));
    assert.deepEqual(decide((p) => { forOperation(p); p.request.subject.workloadId = '   '; }),
      denied('INVALID_REQUEST'));
    assert.deepEqual(decide((p) => { forOperation(p); p.host.authenticated.subject.workloadId = ''; }),
      denied('INVALID_CONTEXT'));
    assert.deepEqual(decide((p) => { forOperation(p); p.grant.principal.workloadId = '   '; }),
      denied('INVALID_CONTEXT'));
    assert.deepEqual(decide((p) => { forOperation(p); p.grant.principal.workloadId = 7; }),
      denied('INVALID_CONTEXT'));
    // The same operation with a complete workload identity on all three records still authorizes.
    assert.deepEqual(decide(forOperation), authorized, `workload-bound ${operation}`);
  }
});

test('only ACTIVE current mappings authorize', () => {
  const byLifecycle = { CREATED: 'MAPPING_NOT_ACTIVE', QUARANTINED: 'MAPPING_NOT_ACTIVE',
    EXPIRED: 'MAPPING_EXPIRED', REVOKED: 'MAPPING_REVOKED', DELETED: 'MAPPING_REVOKED' };
  for (const [lifecycle, reason] of Object.entries(byLifecycle)) {
    assert.deepEqual(decide(swap('mapping.lifecycle', lifecycle)), denied(reason));
  }
  assert.deepEqual(decide(swap('mapping.lifecycle', 'unknown-lifecycle.invalid')),
    denied('INVALID_CONTEXT'));
});

test('an expired mapping or grant denies at and after its expiry', () => {
  assert.deepEqual(decide(swap('mapping.expiresAt', NOW)), denied('MAPPING_EXPIRED'));
  assert.deepEqual(decide(swap('mapping.expiresAt', NOW - 1)), denied('MAPPING_EXPIRED'));
  assert.deepEqual(decide(swap('mapping.expiresAt', NOW + 1)), authorized);
  assert.deepEqual(decide(swap('grant.expiresAt', NOW)), denied('GRANT_EXPIRED'));
  assert.deepEqual(decide(swap('grant.expiresAt', NOW - 1)), denied('GRANT_EXPIRED'));
  assert.deepEqual(decide(swap('grant.expiresAt', NOW + 1)), authorized);
  assert.deepEqual(decide((p) => { p.clock = { now: ALL.grant.expiresAt + 1 }; }),
    denied('GRANT_EXPIRED'));
  assert.deepEqual(decide(swap('clock.now', Number.NaN)), denied('INVALID_CONTEXT'));
  assert.deepEqual(decide(swap('clock.now', Number.POSITIVE_INFINITY)), denied('INVALID_CONTEXT'));
});

test('a grant must pin the current monotonic revision', () => {
  assert.deepEqual(decide(swap('grant.revision', 3)), denied('STALE_REVISION'));
  assert.deepEqual(decide(swap('grant.revision', 5)), denied('STALE_REVISION'));
  assert.deepEqual(decide(swap('mapping.revision', 5)), denied('STALE_REVISION'));
  assert.deepEqual(decide(swap('mapping.revision', 0)), denied('INVALID_CONTEXT'));
  assert.deepEqual(decide(swap('mapping.revision', 1.5)), denied('INVALID_CONTEXT'));
});

test('a credential or SECRET mapping is never authorizable at this seam', () => {
  assert.deepEqual(decide(swap('mapping.semanticType', 'CREDENTIAL_OR_SECRET')),
    denied('NON_REVERSIBLE_MAPPING'));
  assert.deepEqual(decide(swap('mapping.sensitivity', 'SECRET')),
    denied('NON_REVERSIBLE_MAPPING'));
  assert.deepEqual(decide(swap('mapping.sensitivity', 'PUBLIC')), authorized);
  for (const granted of MAPPING_AUTHORIZATION_OPERATIONS) {
    assert.deepEqual(decide((p) => { p.mapping.semanticType = 'CREDENTIAL_OR_SECRET'; p.grant.operation = granted; }),
      denied('NON_REVERSIBLE_MAPPING'), `${granted} must not authorize a credential mapping`);
  }
});

test('the host clock is trusted and never taken from the request', () => {
  // A request that carries its own clock is refused as malformed, whatever it claims.
  assert.deepEqual(decide((p) => { p.request.now = NOW + 3_600_000; }), denied('INVALID_REQUEST'));
  assert.deepEqual(decide((p) => { p.request.timestamp = 'whenever'; }), denied('INVALID_REQUEST'));
  // Time moves only through the host clock argument.
  assert.deepEqual(decide((p) => { p.clock = { now: ALL.grant.expiresAt }; }),
    denied('GRANT_EXPIRED'));
  assert.deepEqual(decide((p) => { p.clock = { now: ALL.grant.expiresAt - 1 }; }), authorized);
  assert.deepEqual(decide((p) => { p.clock = { now: ALL.mapping.expiresAt }; }),
    denied('MAPPING_EXPIRED'));
});

test('one-field swaps across request, host, mapping and grant each deny with a fixed reason', () => {
  const swaps = [
    ['request.mappingRef', FORGED, 'UNKNOWN_MAPPING'],
    ['request.subject.principalId', PRINCIPAL_B, 'CONTEXT_MISMATCH'],
    ['request.subject.workloadId', WORKLOAD_B, 'CONTEXT_MISMATCH'],
    ['request.context.tenantId', TENANT_B, 'CONTEXT_MISMATCH'],
    ['request.context.projectId', PROJECT_B, 'CONTEXT_MISMATCH'],
    ['request.context.sessionId', SESSION_B, 'CONTEXT_MISMATCH'],
    ['request.context.purpose', OTHER_PURPOSE, 'CONTEXT_MISMATCH'],
    ['request.destination.ref', OTHER_PROFILE.ref, 'CONTEXT_MISMATCH'],
    ['request.destination.profileId', OTHER_PROFILE.profileId, 'CONTEXT_MISMATCH'],
    ['request.destination.kind', WEB_SINK.kind, 'CONTEXT_MISMATCH'],
    ['request.destination.trustZone', WEB_SINK.trustZone, 'CONTEXT_MISMATCH'],
    ['request.operation', 'DISPLAY', 'OPERATION_NOT_GRANTED'],
    ['host.authenticated.subject.principalId', PRINCIPAL_B, 'CONTEXT_MISMATCH'],
    ['host.authenticated.subject.workloadId', WORKLOAD_B, 'CONTEXT_MISMATCH'],
    ['host.authenticated.context.tenantId', TENANT_B, 'CONTEXT_MISMATCH'],
    ['host.authenticated.context.projectId', PROJECT_B, 'CONTEXT_MISMATCH'],
    ['host.authenticated.context.sessionId', SESSION_B, 'CONTEXT_MISMATCH'],
    ['host.authenticated.context.purpose', OTHER_PURPOSE, 'CONTEXT_MISMATCH'],
    ['host.observed.destination.ref', OTHER_PROFILE.ref, 'CONTEXT_MISMATCH'],
    ['host.observed.destination.profileId', OTHER_PROFILE.profileId, 'CONTEXT_MISMATCH'],
    ['mapping.mappingRef', FORGED, 'UNKNOWN_MAPPING'],
    ['mapping.scope.tenantId', TENANT_B, 'SCOPE_MISMATCH'],
    ['mapping.scope.projectId', PROJECT_B, 'SCOPE_MISMATCH'],
    ['mapping.scope.sessionId', SESSION_B, 'SCOPE_MISMATCH'],
    ['mapping.lifecycle', 'REVOKED', 'MAPPING_REVOKED'],
    ['mapping.semanticType', 'CREDENTIAL_OR_SECRET', 'NON_REVERSIBLE_MAPPING'],
    ['mapping.sensitivity', 'SECRET', 'NON_REVERSIBLE_MAPPING'],
    ['mapping.revision', 5, 'STALE_REVISION'],
    ['mapping.expiresAt', NOW - 1, 'MAPPING_EXPIRED'],
    ['grant.mappingRef', FORGED, 'GRANT_MISMATCH'],
    ['grant.principal.principalId', PRINCIPAL_B, 'SCOPE_MISMATCH'],
    ['grant.principal.workloadId', WORKLOAD_B, 'SCOPE_MISMATCH'],
    ['grant.context.tenantId', TENANT_B, 'SCOPE_MISMATCH'],
    ['grant.context.projectId', PROJECT_B, 'SCOPE_MISMATCH'],
    ['grant.context.sessionId', SESSION_B, 'SCOPE_MISMATCH'],
    ['grant.context.purpose', OTHER_PURPOSE, 'GRANT_MISMATCH'],
    ['grant.destination.ref', OTHER_PROFILE.ref, 'GRANT_MISMATCH'],
    ['grant.destination.profileId', OTHER_PROFILE.profileId, 'GRANT_MISMATCH'],
    ['grant.operation', 'EXPORT', 'OPERATION_NOT_GRANTED'],
    ['grant.revision', 3, 'STALE_REVISION'],
    ['grant.expiresAt', NOW - 1, 'GRANT_EXPIRED'],
  ];
  assert.equal(new Set(swaps.map(([path]) => path)).size, swaps.length);
  for (const [path, value, reason] of swaps) {
    assert.deepEqual(decide(swap(path, value)), denied(reason), `swap of ${path}`);
  }
});

test('a tenant-A mapping never authorizes a tenant-B caller, with or without an exception', () => {
  const tenants = [[TENANT_A, PROJECT_A, SESSION_A, PRINCIPAL_A, WORKLOAD_A],
    [TENANT_B, PROJECT_B, SESSION_B, PRINCIPAL_B, WORKLOAD_B]];
  for (const granted of MAPPING_AUTHORIZATION_OPERATIONS) {
    for (const [tenantId, projectId, sessionId, principalId, workloadId] of tenants) {
      for (const requested of MAPPING_AUTHORIZATION_OPERATIONS) {
        const decision = decide((p) => {
          p.grant.operation = granted;
          p.request.operation = requested;
          p.request.subject = { principalId, workloadId };
          p.request.context = { tenantId, projectId, sessionId, purpose: PURPOSE };
          p.host.authenticated.subject = { principalId, workloadId };
          p.host.authenticated.context = { tenantId, projectId, sessionId, purpose: PURPOSE };
        });
        if (tenantId === TENANT_A) {
          // Inside the issuing scope the only remaining question is the operation itself.
          assert.deepEqual(decision,
            granted === requested ? authorized : denied('OPERATION_NOT_GRANTED'));
        } else {
          // Outside it, no operation, grant or tenant-A scope field helps.
          assert.equal(decision.state, 'DENIED');
          assert.equal(decision.reason, 'SCOPE_MISMATCH', `tenant ${tenantId} ${granted}/${requested}`);
        }
      }
    }
  }
  // A coherent tenant-B caller holding its own tenant-B grant still cannot use the tenant-A mapping.
  const asTenantB = (p) => {
    p.request.subject = { principalId: PRINCIPAL_B, workloadId: WORKLOAD_B };
    p.request.context = { tenantId: TENANT_B, projectId: PROJECT_B, sessionId: SESSION_B, purpose: PURPOSE };
    p.host.authenticated.subject = { principalId: PRINCIPAL_B, workloadId: WORKLOAD_B };
    p.host.authenticated.context = { tenantId: TENANT_B, projectId: PROJECT_B, sessionId: SESSION_B, purpose: PURPOSE };
    p.grant.principal = { principalId: PRINCIPAL_B, workloadId: WORKLOAD_B };
    p.grant.context = { tenantId: TENANT_B, projectId: PROJECT_B, sessionId: SESSION_B, purpose: PURPOSE };
  };
  assert.deepEqual(decide(asTenantB), denied('SCOPE_MISMATCH'));
  // A tenant-A grant presented to a tenant-B caller is refused the same way.
  assert.deepEqual(decide((p) => {
    p.request.subject = { principalId: PRINCIPAL_B, workloadId: WORKLOAD_B };
    p.request.context = { tenantId: TENANT_B, projectId: PROJECT_B, sessionId: SESSION_B, purpose: PURPOSE };
    p.host.authenticated.subject = { principalId: PRINCIPAL_B, workloadId: WORKLOAD_B };
    p.host.authenticated.context = { tenantId: TENANT_B, projectId: PROJECT_B, sessionId: SESSION_B, purpose: PURPOSE };
  }), denied('SCOPE_MISMATCH'));
});

test('a purpose-bound grant is not a general-purpose release', () => {
  assert.deepEqual(decide(swap('grant.context.purpose', OTHER_PURPOSE)), denied('GRANT_MISMATCH'));
  assert.deepEqual(decide((p) => { p.grant.context = { ...p.grant.context, purpose: '*' }; }),
    denied('GRANT_MISMATCH'));
  assert.deepEqual(decide((p) => { p.grant.context = { ...p.grant.context, purpose: '' }; }),
    denied('INVALID_CONTEXT'));
});

test('combined-invalid records report the first failure in the documented order', () => {
  // A grant's own shape is validated before congruence and lifecycle, so a REVOKED mapping with a
  // null grant is malformed trusted context, not a lifecycle verdict about the mapping.
  assert.deepEqual(decide((p) => { p.mapping.lifecycle = 'REVOKED'; p.grant = null; }),
    denied('INVALID_CONTEXT'));
  assert.deepEqual(decide((p) => { p.mapping.lifecycle = 'REVOKED'; p.grant = 'approved'; }),
    denied('INVALID_CONTEXT'));
  assert.deepEqual(decide((p) => { p.mapping.lifecycle = 'REVOKED'; delete p.grant.expiresAt; }),
    denied('INVALID_CONTEXT'));
  assert.deepEqual(decide((p) => { p.mapping.scope.tenantId = TENANT_B; p.grant = null; }),
    denied('INVALID_CONTEXT'));
  assert.deepEqual(decide((p) => {
    p.request.subject.principalId = PRINCIPAL_B; p.grant = null;
  }), denied('INVALID_CONTEXT'));
  // A well-formed grant leaves congruence (row 3) ahead of every later mapping and grant check.
  assert.deepEqual(decide((p) => {
    p.request.subject.principalId = PRINCIPAL_B; p.grant.operation = 'EXPORT';
  }), denied('CONTEXT_MISMATCH'));
  assert.deepEqual(decide((p) => {
    p.request.subject.principalId = PRINCIPAL_B; p.mapping.lifecycle = 'REVOKED';
    p.grant.revision = 3;
  }), denied('CONTEXT_MISMATCH'));
  // A well-formed grant leaves the lifecycle verdict as the first failure.
  assert.deepEqual(decide((p) => { p.mapping.lifecycle = 'REVOKED'; }), denied('MAPPING_REVOKED'));
  // A malformed request outranks every malformed trusted input, and a malformed host outranks the grant.
  assert.deepEqual(decide((p) => { p.request.mappingRef = ''; p.grant = null; }),
    denied('INVALID_REQUEST'));
  assert.deepEqual(decide((p) => { p.host = {}; p.grant = null; }), denied('INVALID_CONTEXT'));
  assert.deepEqual(decide((p) => { p.clock = {}; p.grant = null; }), denied('INVALID_CONTEXT'));
  // An absent grant is not malformed, so it keeps its own check, which still sits after the mapping
  // checks and ahead of every grant-content check that needs a grant at all.
  assert.deepEqual(decide((p) => { p.grant = undefined; }), denied('NO_GRANT'));
  assert.deepEqual(decide((p) => { p.mapping.lifecycle = 'REVOKED'; p.grant = undefined; }),
    denied('MAPPING_REVOKED'));
  assert.deepEqual(decide((p) => { p.mapping.scope.tenantId = TENANT_B; p.grant = undefined; }),
    denied('SCOPE_MISMATCH'));
  assert.deepEqual(decide((p) => { p.mapping.revision = 5; p.grant = undefined; }),
    denied('NO_GRANT'));
  assert.deepEqual(decide((p) => { p.mapping.revision = 5; }), denied('STALE_REVISION'));
  // A malformed mapping outranks a well-formed but wrong grant.
  assert.deepEqual(decide((p) => { p.mapping.semanticType = 'ROBOT'; p.grant.operation = 'EXPORT'; }),
    denied('INVALID_CONTEXT'));
});

test('malformed untrusted request shapes deny with a fixed reason and never throw', () => {
  // Every field-level case mutates an otherwise complete and valid request, so the named validator is
  // the one that rejects it; only the cases about the request as a whole replace it wholesale.
  const malformed = [
    ['null request', (p) => { p.request = null; }, 'INVALID_REQUEST'],
    ['string request', (p) => { p.request = 'grant me'; }, 'INVALID_REQUEST'],
    ['array request', (p) => { p.request = []; }, 'INVALID_REQUEST'],
    ['inherited prototype', (p) => { p.request = Object.assign(Object.create({ approved: true }),
      structuredClone(ALL.request)); }, 'INVALID_REQUEST'],
    ['wrong version', (p) => { p.request.version = 2; }, 'INVALID_REQUEST'],
    ['missing version', (p) => { delete p.request.version; }, 'INVALID_REQUEST'],
    ['missing operation', (p) => { delete p.request.operation; }, 'INVALID_REQUEST'],
    ['unknown operation', (p) => { p.request.operation = 'REVEAL'; }, 'INVALID_REQUEST'],
    ['numeric operation', (p) => { p.request.operation = 1; }, 'INVALID_REQUEST'],
    ['extra field', (p) => { p.request.approved = true; }, 'INVALID_REQUEST'],
    ['control character in ref', (p) => { p.request.mappingRef = `map${String.fromCharCode(1)}ok`; },
      'INVALID_REQUEST'],
    ['oversized ref', (p) => { p.request.mappingRef = 'm'.repeat(4096); }, 'INVALID_REQUEST'],
    ['padded ref', (p) => { p.request.mappingRef = ` ${ALL.request.mappingRef}`; },
      'INVALID_REQUEST'],
    ['numeric subject', (p) => { p.request.subject = 42; }, 'INVALID_REQUEST'],
    ['numeric principal', (p) => { p.request.subject.principalId = 7; }, 'INVALID_REQUEST'],
    ['nested destination extras', (p) => { p.request.destination = { ...LOCAL_SINK, profile: 'x' }; },
      'INVALID_REQUEST'],
    ['nested context extras', (p) => { p.request.context = { ...ALL.request.context, role: 'owner' }; },
      'INVALID_REQUEST'],
    ['oversized destination ref', (p) => { p.request.destination.ref = 'm'.repeat(4096); },
      'INVALID_REQUEST'],
    ['missing destination profile', (p) => { delete p.request.destination.profileId; },
      'INVALID_REQUEST'],
  ];
  for (const [label, mutate, reason] of malformed) {
    const decision = decide(mutate);
    assert.deepEqual(decision, denied(reason), label);
    assert.ok(MAPPING_AUTHORIZATION_REASONS.includes(decision.reason), label);
  }
});

test('malformed trusted inputs deny with a fixed reason and never throw', () => {
  const cases = [
    ['host undefined', (p) => { p.host = undefined; }, 'INVALID_CONTEXT'],
    ['host empty', (p) => { p.host = {}; }, 'INVALID_CONTEXT'],
    ['host trust claim', (p) => { p.host.authenticated.trusted = true; }, 'INVALID_CONTEXT'],
    ['mapping undefined', (p) => { p.mapping = undefined; }, 'INVALID_CONTEXT'],
    ['mapping empty', (p) => { p.mapping = {}; }, 'INVALID_CONTEXT'],
    ['mapping unknown lifecycle', (p) => { p.mapping.lifecycle = 'PENDING'; }, 'INVALID_CONTEXT'],
    ['mapping unknown semantic type', (p) => { p.mapping.semanticType = 'ROBOT'; }, 'INVALID_CONTEXT'],
    ['mapping unknown sensitivity', (p) => { p.mapping.sensitivity = 'TOP_SECRET'; }, 'INVALID_CONTEXT'],
    ['mapping missing expiry', (p) => { delete p.mapping.expiresAt; }, 'INVALID_CONTEXT'],
    ['mapping fractional expiry', (p) => { p.mapping.expiresAt = NOW + 0.5; }, 'INVALID_CONTEXT'],
    ['clock undefined', (p) => { p.clock = undefined; }, 'INVALID_CONTEXT'],
    ['clock empty', (p) => { p.clock = {}; }, 'INVALID_CONTEXT'],
    ['clock from request shape', (p) => { p.clock = { now: 'NOW' }; }, 'INVALID_CONTEXT'],
    ['grant null', (p) => { p.grant = null; }, 'INVALID_CONTEXT'],
    ['grant string', (p) => { p.grant = 'approved'; }, 'INVALID_CONTEXT'],
    ['grant missing expiry', (p) => { delete p.grant.expiresAt; }, 'INVALID_CONTEXT'],
    ['grant infinite expiry', (p) => { p.grant.expiresAt = Number.POSITIVE_INFINITY; },
      'INVALID_CONTEXT'],
    ['grant missing revision', (p) => { delete p.grant.revision; }, 'INVALID_CONTEXT'],
    ['grant missing operation', (p) => { delete p.grant.operation; }, 'INVALID_CONTEXT'],
    ['grant unknown operation', (p) => { p.grant.operation = 'PUBLISH'; }, 'INVALID_CONTEXT'],
  ];
  for (const [label, mutate, reason] of cases) {
    const decision = decide(mutate);
    assert.deepEqual(decision, denied(reason), label);
    assert.ok(MAPPING_AUTHORIZATION_REASONS.includes(decision.reason), label);
  }
});

test('a throwing accessor or proxy denies without leaking exception detail', () => {
  const boom = new Error('planted-internal-detail.invalid');
  const hostile = [
    ['request getter', (p) => { p.request = Object.defineProperty({ ...ALL.request }, 'mappingRef',
      { enumerable: true, get() { throw boom; } }); }],
    ['request proxy ownKeys', (p) => { p.request = new Proxy({ ...ALL.request }, {
      ownKeys() { throw boom; } }); }],
    ['mapping getter', (p) => { p.mapping = Object.defineProperty({ ...ALL.mapping }, 'revision',
      { enumerable: true, get() { throw boom; } }); }],
    ['grant proxy ownKeys', (p) => { p.grant = new Proxy({ ...ALL.grant }, {
      ownKeys() { throw boom; } }); }],
    ['clock proxy ownKeys', (p) => { p.clock = new Proxy({ ...ALL.clock }, {
      ownKeys() { throw boom; } }); }],
    ['host getter', (p) => { p.host = Object.defineProperty({ ...ALL.host }, 'authenticated',
      { enumerable: true, get() { throw boom; } }); }],
  ];
  for (const [label, mutate] of hostile) {
    const decision = decide(mutate);
    assert.equal(decision.state, 'DENIED', label);
    assert.ok(MAPPING_AUTHORIZATION_REASONS.includes(decision.reason), label);
    assert.ok(!JSON.stringify(decision).includes('planted-internal-detail.invalid'), label);
    assert.ok(!JSON.stringify(decision).includes('at '), label);
  }
});

test('a null-prototype record is judged on its own data, never on its prototype', () => {
  const neutral = (value) => Object.assign(Object.create(null), structuredClone(value));
  assert.deepEqual(authorizeMappingOperation(neutral(ALL.request), neutral(ALL.host),
    neutral(ALL.mapping), neutral(ALL.grant), neutral(ALL.clock)), authorized);
  assert.deepEqual(decide((p) => { p.grant = Object.create({ operation: 'EXPORT' }); }),
    denied('INVALID_CONTEXT'));
});

test('the shared grant normalizer returns an owned copy that later caller mutation cannot reach', () => {
  const p = parts();
  const normalized = normalizeMappingGrant(p.grant);
  // A complete, valid grant round-trips into a structurally identical record that is not the source:
  // every nested record is a new object of this module's own making, not an alias into the caller's.
  assert.deepEqual(normalized, ALL.grant);
  assert.notEqual(normalized, p.grant);
  assert.notEqual(normalized.principal, p.grant.principal);
  assert.notEqual(normalized.context, p.grant.context);
  assert.notEqual(normalized.destination, p.grant.destination);
  // The copy is settled: a caller that edits every one of its own records afterwards leaves the
  // snapshot exactly as it was normalized, so a later check reads the value it validated.
  p.grant.principal.principalId = PRINCIPAL_B;
  p.grant.principal.workloadId = WORKLOAD_B;
  p.grant.context.purpose = OTHER_PURPOSE;
  p.grant.destination.ref = FORGED;
  p.grant.destination.profileId = OTHER_PROFILE.profileId;
  p.grant.operation = 'EXPORT';
  p.grant.expiresAt = NOW;
  assert.deepEqual(normalized, ALL.grant);
  // It is the record the seam itself would have built, so it authorizes exactly as the source does.
  assert.deepEqual(authorizeMappingOperation(p.request, p.host, p.mapping, normalized, p.clock),
    authorized);
  // Normalizing the normalized copy again is stable, and the copy's own shape is not an alias.
  const again = normalizeMappingGrant(normalized);
  assert.deepEqual(again, normalized);
  assert.notEqual(again, normalized);
});

test('the shared grant normalizer refuses every shape outside the one grant schema', () => {
  const boom = new Error('planted-normalizer-detail.invalid');
  const grant = ALL.grant;
  const without = (key) => { const copy = { ...grant }; delete copy[key]; return copy; };
  const nested = (key, value) => ({ ...grant, [key]: value });
  const refused = [
    ['absent', undefined],
    ['null', null],
    ['text', 'approved'],
    ['a number', 7],
    ['an array', []],
    ['an empty record', {}],
    ['a wrong version', { ...grant, version: 2 }],
    ['no mappingRef', without('mappingRef')],
    ['no revision', without('revision')],
    ['a revision below one', { ...grant, revision: 0 }],
    ['a fractional revision', { ...grant, revision: 4.5 }],
    ['no principal', without('principal')],
    ['a principal with no workloadId', nested('principal', { principalId: PRINCIPAL_A })],
    ['an extra principal key', nested('principal', { ...grant.principal, note: 'x' })],
    ['no context', without('context')],
    ['a context with no purpose', nested('context',
      { tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A })],
    ['an oversized tenantId', nested('context', { ...grant.context, tenantId: 't'.repeat(257) })],
    ['no destination', without('destination')],
    ['a destination with no profileId', nested('destination',
      { kind: LOCAL_SINK.kind, ref: LOCAL_SINK.ref, trustZone: LOCAL_SINK.trustZone })],
    ['an oversized destination ref', nested('destination',
      { ...grant.destination, ref: 'r'.repeat(2049) })],
    ['no operation', without('operation')],
    ['an operation outside the vocabulary', { ...grant, operation: 'PUBLISH' }],
    ['no expiry', without('expiresAt')],
    ['an expiry at zero', { ...grant, expiresAt: 0 }],
    ['an unsafe expiry', { ...grant, expiresAt: Number.MAX_SAFE_INTEGER + 1 }],
    ['an unknown key', { ...grant, approved: true }],
    ['an oversized mappingRef', { ...grant, mappingRef: 'm'.repeat(257) }],
    ['a padded mappingRef', { ...grant, mappingRef: ` ${grant.mappingRef}` }],
    ['a symbol key', { ...grant, [Symbol('note')]: 'x' }],
    ['a hidden field', Object.defineProperty({ ...grant }, 'revision',
      { enumerable: false, value: 4, configurable: true })],
    ['an accessor', Object.defineProperty({ ...grant }, 'expiresAt',
      { enumerable: true, get() { throw boom; } })],
    ['an ownKeys trap', new Proxy({ ...grant }, { ownKeys() { throw boom; } })],
    ['a descriptor trap', new Proxy({ ...grant }, {
      getOwnPropertyDescriptor() { throw boom; } })],
    ['a getPrototypeOf trap', new Proxy({ ...grant }, { getPrototypeOf() { throw boom; } })],
    ['an inherited prototype', Object.assign(Object.create({ operation: 'USE' }), grant)],
    ['too many keys', { ...grant, a: 1, b: 2, c: 3, d: 4, e: 5, f: 6, g: 7, h: 8, i: 9, j: 10,
      k: 11, l: 12, m: 13, n: 14, o: 15, p: 16, q: 17, r: 18, s: 19, t: 20, u: 21, v: 22,
      w: 23, x: 24, y: 25, z: 26 }],
  ];
  for (const [label, value] of refused) {
    // Every one of these, including the four that raise while the value is being reflected on,
    // answers with the absent marker and never lets an exception - or its text - reach the caller.
    let answer;
    assert.doesNotThrow(() => { answer = normalizeMappingGrant(value); }, label);
    assert.equal(answer, null, label);
  }
  // A refused shape is refused as itself, not as an absent grant: the seam still names it malformed.
  const p = parts();
  assert.deepEqual(authorizeMappingOperation(p.request, p.host, p.mapping,
    { ...grant, note: 'x' }, p.clock), denied('INVALID_CONTEXT'));
});

test('the seam is pure: inputs are not mutated and the same inputs give the same decision', () => {
  const p = parts();
  const before = structuredClone(p);
  const first = authorizeMappingOperation(p.request, p.host, p.mapping, p.grant, p.clock);
  const second = authorizeMappingOperation(p.request, p.host, p.mapping, p.grant, p.clock);
  assert.deepEqual(first, authorized);
  assert.deepEqual(second, first);
  assert.deepEqual(p, before);
  const frozen = Object.freeze(structuredClone(ALL));
  assert.deepEqual(authorizeMappingOperation(frozen.request, frozen.host, frozen.mapping,
    frozen.grant, frozen.clock), authorized);
});

test('every reason this seam can return is one of its fixed codes', () => {
  const seen = new Set();
  const record = (mutate) => {
    const decision = decide(mutate);
    assert.ok(MAPPING_AUTHORIZATION_REASONS.includes(decision.reason),
      `unexpected reason ${decision.reason}`);
    seen.add(decision.reason);
    return decision;
  };
  record();
  record(swap('request.mappingRef', FORGED));
  record(swap('mapping.lifecycle', 'REVOKED'));
  record(swap('mapping.lifecycle', 'CREATED'));
  record(swap('mapping.expiresAt', NOW - 1));
  record(swap('mapping.semanticType', 'CREDENTIAL_OR_SECRET'));
  record(swap('mapping.scope.tenantId', TENANT_B));
  record((p) => { p.grant = undefined; });
  record(swap('grant.mappingRef', FORGED));
  record(swap('grant.revision', 3));
  record(swap('grant.context.purpose', OTHER_PURPOSE));
  record(swap('grant.destination.ref', OTHER_PROFILE.ref));
  record(swap('grant.operation', 'EXPORT'));
  record(swap('grant.expiresAt', NOW - 1));
  record(swap('request.context.tenantId', TENANT_B));
  record(swap('request.mappingRef', ''));
  record(swap('host', undefined));
  assert.deepEqual([...seen].sort(), ['AUTHORIZED', 'CONTEXT_MISMATCH', 'GRANT_EXPIRED', 'GRANT_MISMATCH',
    'INVALID_CONTEXT', 'INVALID_REQUEST', 'MAPPING_EXPIRED', 'MAPPING_NOT_ACTIVE', 'MAPPING_REVOKED',
    'NON_REVERSIBLE_MAPPING', 'NO_GRANT', 'OPERATION_NOT_GRANTED', 'SCOPE_MISMATCH', 'STALE_REVISION',
    'UNKNOWN_MAPPING']);
  assert.equal(seen.size, MAPPING_AUTHORIZATION_REASONS.length);
});