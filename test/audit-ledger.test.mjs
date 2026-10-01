import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  appendAuditEvent, createAuditCheckpoint, createInMemoryAuditLedger, digestAuditBundle,
  exportAuditEvents, gateHighRiskEffect, readAuditEvents, serializeAuditCheckpoint,
  serializeAuditEntry, verifyAuditStream,
  AUDIT_APPEND_FINDINGS, AUDIT_BUNDLE_COMPONENTS, AUDIT_KINDS, AUDIT_KIND_OPERATIONS,
  AUDIT_OPERATIONS, AUDIT_OUTCOMES, AUDIT_REASON_CODES, AUDIT_SCHEMA_VERSION,
} from '../dist/audit-ledger.js';
import { SENSITIVITIES, SEMANTIC_CLASSES } from '../dist/classification.js';
import { KNOWN_POLICY_BUNDLE, digestPolicyBundle } from '../dist/policy.js';

const HEX64 = 'a'.repeat(64);
const ZERO64 = '0'.repeat(64);
// Obviously synthetic, non-routable planted originals. Never real data.
const PLANTED = [
  'planted-original-person-a1',
  'planted-original-person-b2',
  'planted-original-customer-c3',
  'planted-original-secret-d4',
  'planted-original-internal-e5',
  'planted-original-project-f6',
];
const PLANTED_MAIL = 'planted.original@planted.invalid';
const PLANTED_URL = 'https://planted.invalid/internal/planted-original';

function key(seed) {
  return Uint8Array.from({ length: 32 }, (_, i) => (seed + i) % 251);
}
function context(overrides = {}) {
  return {
    version: 1,
    scope: { tenantId: 'tenant-a.invalid', projectId: 'project-a.invalid' },
    actor: { principalId: 'principal-a.invalid', workloadId: 'workload-a.invalid' },
    integrationId: 'integration-a.invalid',
    actorBinding: 'AUTHENTICATED_UPSTREAM',
    pseudonymKey: key(1),
    chainKey: key(2),
    ...overrides,
  };
}
function bundle() {
  return {
    policy: { id: KNOWN_POLICY_BUNDLE.id, version: KNOWN_POLICY_BUNDLE.version,
      digest: digestPolicyBundle({ ...KNOWN_POLICY_BUNDLE, profiles: [], rules: [] }) },
    components: [
      { id: 'NORMALIZATION', version: '1' }, { id: 'PARSER', version: '1' },
      { id: 'DETECTOR', version: '1' }, { id: 'SEMANTIC_PROVIDER', version: 'jev-1' },
      { id: 'CLASSIFICATION_POLICY', version: '1' },
    ],
  };
}
function draft(overrides = {}) {
  // Per-kind required fields are added by the factory so one draft never mixes two schemas.
  const kind = overrides.kind ?? 'CLOAK';
  const references = ['CLOAK', 'AUTHORIZATION_ATTEMPT', 'MAPPING_LIFECYCLE'].includes(kind)
    ? { entityRef: 'entity-a1' } : {};
  return {
    version: AUDIT_SCHEMA_VERSION, kind, operation: 'CLOAK', outcome: 'APPLIED', reason: 'APPLIED',
    occurredAt: '2026-09-20T10:11:12.130Z', bundle: bundle(), correlationRef: 'correlation-a1',
    ...references,
    ...overrides,
  };
}
function scenario(overrides = {}, contextOverrides = {}) {
  const trusted = context(contextOverrides);
  const ledger = createInMemoryAuditLedger(trusted.scope);
  return { trusted, ledger, value: draft(overrides) };
}
function appendOnce(overrides = {}, contextOverrides = {}) {
  const { trusted, ledger, value } = scenario(overrides, contextOverrides);
  return { ledger, trusted, result: appendAuditEvent(ledger, value, trusted) };
}
function assertRestricted(result, finding, message = '') {
  assert.equal(result.status, 'RESTRICTED', `${message} ${JSON.stringify(result)}`);
  assert.equal(result.finding, finding, `${message} ${JSON.stringify(result)}`);
  assert.equal(result.receipt, undefined);
  return true;
}

test('schema constants are closed sets and the kind/operation table is complete', () => {
  assert.deepEqual([...AUDIT_KINDS], ['CLOAK', 'POLICY_DECISION', 'AUTHORIZATION_ATTEMPT',
    'MAPPING_LIFECYCLE', 'KEY_OPERATION', 'POLICY_OPERATION']);
  for (const kind of AUDIT_KINDS) {
    assert.ok(AUDIT_KIND_OPERATIONS[kind].length > 0, kind);
    for (const operation of AUDIT_KIND_OPERATIONS[kind]) assert.ok(AUDIT_OPERATIONS.includes(operation));
  }
  assert.deepEqual([...AUDIT_OUTCOMES], ['ALLOWED', 'DENIED', 'APPLIED']);
  assert.equal(new Set(AUDIT_REASON_CODES).size, AUDIT_REASON_CODES.length);
  for (const component of AUDIT_BUNDLE_COMPONENTS) assert.match(component, /^[A-Z_]+$/);
  assert.ok(AUDIT_APPEND_FINDINGS.includes('AUDIT_UNAVAILABLE'));
});

test('a synthetic cloak event is recorded as a pseudonymized, attributable record', () => {
  const { ledger, trusted, result } = appendOnce();
  assert.equal(result.status, 'RECORDED', JSON.stringify(result));
  assert.equal(ledger.entries.length, 1);
  const entry = ledger.entries[0];
  assert.equal(entry.version, 1);
  assert.equal(entry.sequence, 1);
  assert.equal(entry.prevDigest, ZERO64);
  assert.match(entry.entryDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual(entry.event.scope, { tenantId: 'tenant-a.invalid', projectId: 'project-a.invalid' });
  assert.deepEqual(entry.event.actor, { integrationId: 'integration-a.invalid',
    actorBinding: 'AUTHENTICATED_UPSTREAM', principalId: 'principal-a.invalid',
    workloadId: 'workload-a.invalid' });
  // Caller-supplied opaque references are replaced by scoped keyed pseudonyms.
  assert.match(entry.event.entityRef, /^ent_[a-f0-9]{32}$/);
  assert.match(entry.event.correlationRef, /^cor_[a-f0-9]{32}$/);
  assert.notEqual(entry.event.entityRef, 'entity-a1');
  assert.equal(result.receipt.sequence, 1);
  assert.equal(result.receipt.correlationRef, entry.event.correlationRef);
  assert.deepEqual(result.receipt.scope, entry.event.scope);
  assert.ok(Object.isFrozen(entry));
  assert.ok(Object.isFrozen(entry.event));
  assert.ok(Object.isFrozen(trusted) === false, 'the supplied context is not captured by the ledger');
});

test('exact serialization excludes every planted protected original', () => {
  const { ledger, trusted, result } = appendOnce({
    entityRef: PLANTED[0], correlationRef: PLANTED[1], interactionRef: PLANTED[2],
    classification: { semanticType: 'PERSON', sensitivity: 'CONFIDENTIAL' },
  });
  assert.equal(result.status, 'RECORDED', JSON.stringify(result));
  const keyOperation = appendOnce({ kind: 'KEY_OPERATION', operation: 'ROTATE', outcome: 'APPLIED',
    reason: 'ADMIN_APPLIED', keyVersion: '7', correlationRef: PLANTED[3] });
  assert.equal(keyOperation.result.status, 'RECORDED', JSON.stringify(keyOperation.result));
  const wire = [
    serializeAuditEntry(ledger.entries[0]),
    JSON.stringify(result), JSON.stringify(ledger.entries[0]),
    serializeAuditCheckpoint(createAuditCheckpoint(ledger, trusted)),
    JSON.stringify(createAuditCheckpoint(ledger, trusted)),
    serializeAuditEntry(keyOperation.ledger.entries[0]),
  ].join('\n');
  for (const planted of PLANTED) assert.ok(!wire.includes(planted), `planted original leaked: ${planted}`);
  assert.ok(!wire.includes(PLANTED_MAIL) && !wire.includes(PLANTED_URL));
});

test('a caller cannot assert actor, tenant, project or key material through the draft', () => {
  for (const forged of [
    { actor: { principalId: 'attacker.invalid' } },
    { scope: { tenantId: 'tenant-b.invalid' } },
    { tenantId: 'tenant-b.invalid' },
    { projectId: 'project-b.invalid' },
    { chainKey: Uint8Array.from([1, 2, 3]) },
    { pseudonymKey: Uint8Array.from([1, 2, 3]) },
    { integrationId: 'attacker.invalid' },
    { payload: 'raw-plaintext' },
    { metadata: { note: 'arbitrary' } },
    { error: 'boom' },
    { value: PLANTED[0] },
  ]) {
    const { ledger, trusted } = scenario();
    assertRestricted(appendAuditEvent(ledger, { ...draft(), ...forged }, trusted), 'INVALID_DRAFT');
    assert.equal(ledger.entries.length, 0);
  }
});

test('an identity-shaped or content-shaped planted original cannot be stored in identity fields', () => {
  const mailContext = () => context({ actor: { principalId: PLANTED_MAIL } });
  const ledgerA = createInMemoryAuditLedger(mailContext().scope);
  assertRestricted(appendAuditEvent(ledgerA, draft(), mailContext()), 'INVALID_CONTEXT');
  assert.equal(ledgerA.entries.length, 0);

  const urlBundle = scenario();
  assertRestricted(appendAuditEvent(urlBundle.ledger, draft({ bundle: { ...bundle(),
    policy: { id: PLANTED_URL, version: '1', digest: HEX64 } } }), urlBundle.trusted), 'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(urlBundle.ledger, draft({ bundle: { ...bundle(),
    components: [{ id: 'DETECTOR', version: PLANTED_MAIL }] } }), urlBundle.trusted), 'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(urlBundle.ledger, draft({ kind: 'KEY_OPERATION', operation: 'ROTATE',
    outcome: 'APPLIED', reason: 'ADMIN_APPLIED', keyVersion: PLANTED_URL }), urlBundle.trusted), 'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(urlBundle.ledger, draft({ interactionId: PLANTED_MAIL }), urlBundle.trusted),
    'INVALID_DRAFT');
  assert.equal(urlBundle.ledger.entries.length, 0);
});

test('policy decision events record the exact bundle identity, state, treatment and decision digest', () => {
  const { ledger, trusted, result } = appendOnce({
    kind: 'POLICY_DECISION', operation: 'SEND', outcome: 'DENIED', reason: 'POLICY_DENIED',
    correlationRef: 'correlation-a1', interactionRef: 'interaction-a1', candidateRef: 'candidate-a1',
    decision: { state: 'DENIED', treatment: 'BLOCK', digest: HEX64 },
  });
  assert.equal(result.status, 'RECORDED', JSON.stringify(result));
  const event = ledger.entries[0].event;
  assert.equal(event.decision.state, 'DENIED');
  assert.equal(event.decision.treatment, 'BLOCK');
  assert.equal(event.decision.digest, HEX64);
  // The exact pinned bundle identity is recorded, not recomputed from the draft.
  assert.equal(event.bundle.policy.digest, bundle().policy.digest);
  assert.equal(event.bundle.policy.id, 'hylja.foundation');
  assert.match(event.candidateRef, /^cnd_[a-f0-9]{32}$/);
  assert.equal(event.entityRef, undefined);
  // A policy decision without its committed digest, or with a non-digest value, is not recordable.
  const missing = scenario();
  assertRestricted(appendAuditEvent(missing.ledger, draft({ kind: 'POLICY_DECISION', operation: 'SEND',
    outcome: 'DENIED', reason: 'POLICY_DENIED', decision: { state: 'DENIED', treatment: 'BLOCK' } }),
    missing.trusted), 'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(missing.ledger, draft({ kind: 'POLICY_DECISION', operation: 'SEND',
    outcome: 'DENIED', reason: 'POLICY_DENIED', decision: { state: 'DENIED', treatment: 'BLOCK',
      digest: PLANTED[0] } }), missing.trusted), 'INVALID_DRAFT');
  assert.equal(missing.ledger.entries.length, 0);
});

test('administrative key and policy operations are attributable to the authenticated actor', () => {
  const admin = context({ actor: { principalId: 'admin-a.invalid', workloadId: 'workload-admin-a.invalid' },
    integrationId: 'control-plane-a.invalid' });
  const ledger = createInMemoryAuditLedger(admin.scope);
  for (const [value, expected] of [
    [draft({ kind: 'KEY_OPERATION', operation: 'ROTATE', outcome: 'APPLIED', reason: 'ADMIN_APPLIED',
      keyVersion: '7' }), 'KEY_OPERATION'],
    [draft({ kind: 'KEY_OPERATION', operation: 'DESTROY', outcome: 'APPLIED', reason: 'ADMIN_APPLIED',
      keyVersion: '7' }), 'KEY_OPERATION'],
    [draft({ kind: 'KEY_OPERATION', operation: 'ROTATE', outcome: 'DENIED', reason: 'ADMIN_DENIED',
      keyVersion: '7' }), 'KEY_OPERATION'],
    [draft({ kind: 'POLICY_OPERATION', operation: 'DEPLOY', outcome: 'APPLIED', reason: 'ADMIN_APPLIED' }),
      'POLICY_OPERATION'],
    [draft({ kind: 'POLICY_OPERATION', operation: 'UPDATE', outcome: 'DENIED', reason: 'ADMIN_DENIED' }),
      'POLICY_OPERATION'],
  ]) {
    assert.equal(appendAuditEvent(ledger, value, admin).status, 'RECORDED', expected);
  }
  const events = ledger.entries.map((entry) => entry.event);
  assert.deepEqual(events.map((e) => e.kind), ['KEY_OPERATION', 'KEY_OPERATION', 'KEY_OPERATION',
    'POLICY_OPERATION', 'POLICY_OPERATION']);
  for (const event of events) {
    assert.equal(event.actor.principalId, 'admin-a.invalid');
    assert.equal(event.actor.workloadId, 'workload-admin-a.invalid');
    assert.equal(event.actor.integrationId, 'control-plane-a.invalid');
    assert.equal(event.actor.actorBinding, 'AUTHENTICATED_UPSTREAM');
  }
  assert.equal(events[0].keyVersion, '7');
  // An unauthenticated workload cannot be attributed to a fabricated actor binding.
  const forged = context({ actorBinding: 'SELF_ASSERTED' });
  assertRestricted(appendAuditEvent(ledger, draft({ kind: 'KEY_OPERATION', operation: 'ROTATE',
    outcome: 'APPLIED', reason: 'ADMIN_APPLIED', keyVersion: '8' }), forged), 'INVALID_CONTEXT');
  assert.equal(ledger.entries.length, 5);
});

test('future #17 and #18 producer event schemas are reserved without a broker or vault', () => {
  const reserved = [
    [draft({ kind: 'AUTHORIZATION_ATTEMPT', operation: 'USE', outcome: 'ALLOWED',
      reason: 'RESOLUTION_AUTHORIZED', entityRef: 'mapping-a1' }), 'USE'],
    [draft({ kind: 'AUTHORIZATION_ATTEMPT', operation: 'DISPLAY', outcome: 'DENIED',
      reason: 'RESOLUTION_DENIED', entityRef: 'mapping-a1' }), 'DISPLAY'],
    [draft({ kind: 'AUTHORIZATION_ATTEMPT', operation: 'EXPORT', outcome: 'DENIED',
      reason: 'RESOLUTION_DENIED', entityRef: 'mapping-a1' }), 'EXPORT'],
    [draft({ kind: 'MAPPING_LIFECYCLE', operation: 'CREATE', outcome: 'APPLIED', reason: 'APPLIED',
      entityRef: 'mapping-a1' }), 'CREATE'],
    [draft({ kind: 'MAPPING_LIFECYCLE', operation: 'DELETE', outcome: 'DENIED',
      reason: 'LIFECYCLE_DENIED', entityRef: 'mapping-a1' }), 'DELETE'],
  ];
  const ledger = createInMemoryAuditLedger(context().scope);
  const trusted = context();
  for (const [value, operation] of reserved) {
    assert.equal(appendAuditEvent(ledger, value, trusted).status, 'RECORDED', operation);
  }
  const events = ledger.entries.map((entry) => entry.event);
  assert.deepEqual(events.map((e) => e.operation), ['USE', 'DISPLAY', 'EXPORT', 'CREATE', 'DELETE']);
  // No reserved schema carries a grant, capability, token or reveal field of any kind.
  for (const entry of ledger.entries) {
    assert.deepEqual(Object.keys(entry.event).filter((key) => /grant|permit|capab|token|reveal/iu
      .test(key)), []);
  }
  // Reserved schemas are strict: an operation outside the kind table is rejected.
  assertRestricted(appendAuditEvent(ledger, draft({ kind: 'AUTHORIZATION_ATTEMPT', operation: 'CLOAK',
    outcome: 'ALLOWED', reason: 'RESOLUTION_AUTHORIZED', entityRef: 'mapping-a1' }), trusted), 'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(ledger, draft({ kind: 'MAPPING_LIFECYCLE', operation: 'EXPORT',
    outcome: 'ALLOWED', reason: 'RESOLUTION_AUTHORIZED', entityRef: 'mapping-a1' }), trusted), 'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(ledger, draft({ kind: 'CLOAK', operation: 'EXPORT', outcome: 'APPLIED',
    reason: 'APPLIED', entityRef: 'mapping-a1' }), trusted), 'INVALID_DRAFT');
});

test('outcome and reason must agree, and unlisted fields or reasons are rejected', () => {
  const ledger = createInMemoryAuditLedger(context().scope);
  const trusted = context();
  for (const [outcome, reason] of [['DENIED', 'APPLIED'], ['APPLIED', 'POLICY_ALLOWED'],
    ['ALLOWED', 'ADMIN_APPLIED'], ['DENIED', 'RESOLUTION_AUTHORIZED']]) {
    assertRestricted(appendAuditEvent(ledger, draft({ outcome, reason }), trusted), 'INVALID_DRAFT', reason);
  }
  assertRestricted(appendAuditEvent(ledger, draft({ reason: 'exploded in caller code' }), trusted),
    'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(ledger, draft({ kind: 'NOT_A_KIND', operation: 'CLOAK' }), trusted),
    'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(ledger, draft({ operation: 'LEAK' }), trusted), 'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(ledger, draft({ classification: { semanticType: 'PERSON',
    sensitivity: 'TOP_SECRET' } }), trusted), 'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(ledger, draft({ classification: { semanticType: 'NOT_A_CLASS',
    sensitivity: 'RESTRICTED' } }), trusted), 'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(ledger, draft({ occurredAt: '2026-09-20 10:11:12Z' }), trusted),
    'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(ledger, draft({ occurredAt: 'not-a-time' }), trusted), 'INVALID_DRAFT');
  assert.equal(ledger.entries.length, 0);
});

test('generated tenant and project variations keep entity and correlation identifiers scoped', () => {
  const seen = new Map();
  for (let i = 0; i < 64; i += 1) {
    const scope = { tenantId: `tenant-${i}.invalid`, projectId: `project-${i}.invalid` };
    const trusted = context({ scope, actor: { principalId: `principal-${i}.invalid` },
      pseudonymKey: key(i), chainKey: key(64 - i) });
    const ledger = createInMemoryAuditLedger(scope);
    // The same raw references in every stream must never collide across tenants/projects.
    const value = draft({ entityRef: 'entity-shared', correlationRef: 'correlation-shared',
      interactionRef: 'interaction-shared' });
    assert.equal(appendAuditEvent(ledger, value, trusted).status, 'RECORDED', JSON.stringify(scope));
    assert.equal(appendAuditEvent(ledger, draft({ kind: 'KEY_OPERATION', operation: 'ROTATE',
      outcome: 'APPLIED', reason: 'ADMIN_APPLIED', keyVersion: String(i),
      correlationRef: 'correlation-shared' }), trusted).status, 'RECORDED');
    for (const entry of ledger.entries) {
      const keyName = `${entry.event.scope.tenantId}/${entry.event.scope.projectId ?? ''}/`
        + `${entry.event.entityRef ?? ''}/${entry.event.correlationRef}`;
      assert.equal(seen.has(keyName), false, keyName);
      seen.set(keyName, true);
      assert.match(entry.event.correlationRef, /^cor_[a-f0-9]{32}$/);
      assert.deepEqual(entry.event.scope, scope);
      assert.equal(entry.event.actor.principalId, `principal-${i}.invalid`);
    }
  }
  assert.equal(seen.size, 64 * 2);
});

test('the ledger retains no key material and exposes no field beyond its declared scope', () => {
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope);
  assert.deepEqual(Object.keys(ledger).sort(), ['accepting', 'entries', 'maxEntries', 'scope', 'version']);
  assert.equal(appendAuditEvent(ledger, draft(), trusted).status, 'RECORDED');
  const wire = JSON.stringify(ledger);
  for (const supplied of [trusted.pseudonymKey, trusted.chainKey]) {
    for (const byte of supplied) {
      assert.ok(!wire.includes(String.fromCharCode(byte)), 'a raw key byte must not survive in the ledger');
    }
  }
  // The chain is recomputed from the supplied key; it is never stored anywhere in the ledger.
  assert.ok(!Object.keys(ledger.entries[0]).includes('chainKey'));
  assert.ok(!Object.keys(ledger.entries[0].event).includes('pseudonymKey'));
});

test('append refuses a context or ledger from another tenant scope', () => {
  const tenantA = appendOnce();
  assert.equal(tenantA.result.status, 'RECORDED');
  const foreignLedger = createInMemoryAuditLedger({ tenantId: 'tenant-b.invalid',
    projectId: 'project-b.invalid' });
  assertRestricted(appendAuditEvent(foreignLedger, draft(), tenantA.trusted), 'SCOPE_MISMATCH');
  assert.equal(foreignLedger.entries.length, 0);
  const foreignContext = context({ scope: { tenantId: 'tenant-b.invalid', projectId: 'project-b.invalid' } });
  assertRestricted(appendAuditEvent(tenantA.ledger, draft(), foreignContext), 'SCOPE_MISMATCH');
  assert.equal(tenantA.ledger.entries.length, 1);
  // A missing project is not the same stream as a project-scoped one.
  assertRestricted(appendAuditEvent(tenantA.ledger, draft(), context({ scope: { tenantId: 'tenant-a.invalid' } })),
    'SCOPE_MISMATCH');
});

test('hostile objects, proxies, accessors and oversized input are rejected without recording', () => {
  const hostile = [
    null, undefined, 42, 'text', [], new Date(0), new Map(), new Set(),
    Object.create({ inherited: 'a1' }), { get version() { throw new Error('planted getter'); } },
    new Proxy({ version: 1 }, { get() { throw new Error('planted proxy get'); } }),
    new Proxy({ version: 1 }, { ownKeys() { throw new Error('planted proxy keys'); } }),
    new Proxy({ version: 1 }, { getOwnPropertyDescriptor() { throw new Error('planted proxy descriptor'); } }),
    (() => { const o = { ...draft() }; Object.defineProperty(o, 'entityRef',
      { enumerable: true, get() { throw new Error('planted accessor'); } }); return o; })(),
    Object.fromEntries(Array.from({ length: 4096 }, (_, i) => [`extra-${i}`, 'a1'])),
    draft({ entityRef: 'e'.repeat(4096) }),
    draft({ correlationRef: 'c'.repeat(4096) }),
  ];
  for (const value of hostile) {
    const { ledger, trusted } = scenario();
    const result = appendAuditEvent(ledger, value, trusted);
    assertRestricted(result, 'INVALID_DRAFT');
    assert.equal(ledger.entries.length, 0);
    for (const planted of [...PLANTED, 'planted getter', 'planted proxy get', 'planted accessor']) {
      assert.ok(!JSON.stringify(result).includes(planted));
    }
  }
  for (const bad of [context({ pseudonymKey: new Uint8Array(4) }), context({ chainKey: 'not-bytes' }),
    context({ chainKey: new Uint8Array(0) }), context({ actorBinding: undefined }),
    context({ integrationId: PLANTED_MAIL }), context({ actor: { principalId: 'x'.repeat(1024) } })]) {
    const { ledger } = scenario();
    const result = appendAuditEvent(ledger, draft(), bad);
    assert.equal(result.status, 'RESTRICTED', JSON.stringify(bad && Object.keys(bad)));
    assert.ok(['INVALID_CONTEXT', 'KEY_UNAVAILABLE'].includes(result.finding), result.finding);
    assert.equal(ledger.entries.length, 0);
  }
});

test('a modified entry is detected against a retained checkpoint', () => {
  const { ledger, trusted } = scenario();
  for (let i = 1; i <= 3; i += 1) {
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), trusted).status,
      'RECORDED');
  }
  const anchor = createAuditCheckpoint(ledger, trusted);
  const forged = { ...ledger, entries: ledger.entries.slice() };
  forged.entries[1] = { ...forged.entries[1],
    event: { ...forged.entries[1].event, outcome: 'ALLOWED', reason: 'POLICY_ALLOWED' } };
  const result = verifyAuditStream(forged, trusted, [anchor]);
  assert.equal(result.status, 'TAMPERED', JSON.stringify(result));
  assert.ok(['CHAIN_BROKEN', 'CHECKPOINT_DIGEST_MISMATCH'].includes(result.finding), result.finding);
  // Unmodified stream verifies to the anchor.
  const clean = verifyAuditStream(ledger, trusted, [anchor]);
  assert.equal(clean.status, 'VERIFIED', JSON.stringify(clean));
  assert.equal(clean.anchoredThrough, 3);
  assert.equal(clean.unanchoredEntries, 0);
});

test('a key-holder rewriting the chain is still detected by the independent checkpoint', () => {
  // A second, legitimately chained stream in the same scope whose first entry differs.
  const trusted = context();
  const honest = createInMemoryAuditLedger(trusted.scope);
  const rewritten = createInMemoryAuditLedger(trusted.scope);
  for (const [ledger, reason] of [[honest, 'APPLIED'], [rewritten, 'POLICY_DENIED']]) {
    assert.equal(appendAuditEvent(ledger, draft({ outcome: reason === 'APPLIED' ? 'APPLIED' : 'DENIED',
      reason }), trusted).status, 'RECORDED');
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: 'correlation-2' }), trusted).status,
      'RECORDED');
  }
  const anchor = createAuditCheckpoint(honest, trusted);
  const substituted = { ...honest, entries: rewritten.entries.slice() };
  const result = verifyAuditStream(substituted, trusted, [anchor]);
  assert.equal(result.status, 'TAMPERED', JSON.stringify(result));
  assert.equal(result.finding, 'CHECKPOINT_DIGEST_MISMATCH');
});

test('deleted, reordered and tail-truncated streams are detected against a retained checkpoint', () => {
  const build = () => {
    const trusted = context();
    const ledger = createInMemoryAuditLedger(trusted.scope);
    for (let i = 1; i <= 4; i += 1) {
      assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), trusted).status,
        'RECORDED');
    }
    return { trusted, ledger, anchor: createAuditCheckpoint(ledger, trusted) };
  };
  const deleted = build();
  const missing = { ...deleted.ledger, entries: deleted.ledger.entries.filter((e) => e.sequence !== 2) };
  assert.equal(verifyAuditStream(missing, deleted.trusted,
    [createAuditCheckpoint(deleted.ledger, deleted.trusted, 2)]).finding, 'ENTRY_MISSING');

  const reordered = build();
  const swapped = { ...reordered.ledger, entries: reordered.ledger.entries.slice() };
  [swapped.entries[1], swapped.entries[2]] = [swapped.entries[2], swapped.entries[1]];
  const reorderResult = verifyAuditStream(swapped, reordered.trusted, [reordered.anchor]);
  assert.equal(reorderResult.status, 'TAMPERED', JSON.stringify(reorderResult));
  assert.equal(reorderResult.finding, 'CHAIN_BROKEN');

  const truncated = build();
  const shortened = { ...truncated.ledger, entries: truncated.ledger.entries.slice(0, 2) };
  const tailResult = verifyAuditStream(shortened, truncated.trusted, [truncated.anchor]);
  assert.equal(tailResult.status, 'TAMPERED', JSON.stringify(tailResult));
  assert.equal(tailResult.finding, 'TAIL_TRUNCATED');
  const emptied = { ...truncated.ledger, entries: [] };
  assert.equal(verifyAuditStream(emptied, truncated.trusted, [truncated.anchor]).finding, 'TAIL_TRUNCATED');
});

test('cross-tenant substitution and a wrong-scope checkpoint are reported as scope mismatch', () => {
  const tenantA = context();
  const tenantB = context({ scope: { tenantId: 'tenant-b.invalid', projectId: 'project-b.invalid' },
    actor: { principalId: 'principal-b.invalid' }, pseudonymKey: key(9), chainKey: key(10) });
  const ledgerA = createInMemoryAuditLedger(tenantA.scope);
  const ledgerB = createInMemoryAuditLedger(tenantB.scope);
  assert.equal(appendAuditEvent(ledgerA, draft(), tenantA).status, 'RECORDED');
  assert.equal(appendAuditEvent(ledgerB, draft({ entityRef: 'entity-b1' }), tenantB).status, 'RECORDED');
  const anchorA = createAuditCheckpoint(ledgerA, tenantA);
  const anchorB = createAuditCheckpoint(ledgerB, tenantB);

  const spliced = { ...ledgerB, entries: [ledgerA.entries[0], ...ledgerB.entries] };
  assert.equal(verifyAuditStream(spliced, tenantB, [anchorB]).finding, 'SCOPE_MISMATCH');
  // Relabelling the substituted entry also breaks its authenticated digest.
  const relabelled = { ...ledgerB, entries: ledgerA.entries.map((e) => ({ ...e,
    event: { ...e.event, scope: tenantB.scope } })) };
  assert.equal(verifyAuditStream(relabelled, tenantB, [anchorB]).finding, 'CHECKPOINT_DIGEST_MISMATCH');
  // Re-keying the substitution needs the chain key; the chain then looks clean, and only the
  // tenant's own independently retained anchor disagrees.
  const rekeyed = createInMemoryAuditLedger(tenantB.scope);
  assert.equal(appendAuditEvent(rekeyed, draft({ entityRef: 'entity-a1' }), tenantB).status, 'RECORDED');
  assert.equal(verifyAuditStream(rekeyed, tenantB, []).status, 'UNANCHORED');
  assert.equal(verifyAuditStream(rekeyed, tenantB, [anchorB]).finding, 'CHECKPOINT_DIGEST_MISMATCH');
  assert.equal(verifyAuditStream(rekeyed, tenantB, [createAuditCheckpoint(rekeyed, tenantB)]).status,
    'VERIFIED');
  // A checkpoint retained for another tenant is never evidence for this stream.
  assert.equal(verifyAuditStream(ledgerB, tenantB, [anchorA]).finding, 'SCOPE_MISMATCH');
  assert.equal(verifyAuditStream(ledgerB, tenantB, [anchorB]).status, 'VERIFIED');
});

test('a recomputed unauthenticated chain is never reported as verified without an anchor', () => {
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope);
  for (let i = 1; i <= 3; i += 1) {
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), trusted).status,
      'RECORDED');
  }
  // Internal chain integrity alone is explicitly not tamper evidence.
  const unanchored = verifyAuditStream(ledger, trusted, []);
  assert.equal(unanchored.status, 'UNANCHORED', JSON.stringify(unanchored));
  assert.equal(unanchored.finding, 'NO_ANCHOR');
  assert.equal(unanchored.anchoredThrough, 0);
  assert.equal(unanchored.anchorsChecked, 0);
  assert.equal(unanchored.entriesChecked, 3);
  assert.equal(unanchored.unanchoredEntries, 3);

  // A complete rewritten stream that a key holder could recompute stays UNANCHORED without a pin.
  const rewritten = createInMemoryAuditLedger(trusted.scope);
  for (let i = 1; i <= 3; i += 1) {
    assert.equal(appendAuditEvent(rewritten, draft({ outcome: 'DENIED', reason: 'POLICY_DENIED',
      correlationRef: `correlation-${i}` }), trusted).status, 'RECORDED');
  }
  const swapped = { ...ledger, entries: rewritten.entries.slice() };
  assert.equal(verifyAuditStream(swapped, trusted, []).status, 'UNANCHORED');
  assert.equal(verifyAuditStream(swapped, trusted, [createAuditCheckpoint(ledger, trusted)]).status, 'TAMPERED');
});

test('entries newer than the newest retained checkpoint are reported as unanchored', () => {
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope);
  for (let i = 1; i <= 2; i += 1) {
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), trusted).status,
      'RECORDED');
  }
  const early = createAuditCheckpoint(ledger, trusted);
  for (let i = 3; i <= 5; i += 1) {
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), trusted).status,
      'RECORDED');
  }
  const result = verifyAuditStream(ledger, trusted, [early]);
  assert.equal(result.status, 'VERIFIED', JSON.stringify(result));
  assert.equal(result.anchoredThrough, 2);
  assert.equal(result.unanchoredEntries, 3);
  assert.equal(result.entriesChecked, 5);
  const pinned = verifyAuditStream(ledger, trusted, [early, createAuditCheckpoint(ledger, trusted)]);
  assert.equal(pinned.status, 'VERIFIED', JSON.stringify(pinned));
  assert.equal(pinned.anchoredThrough, 5);
  assert.equal(pinned.unanchoredEntries, 0);
});

test('a changed checkpoint and malformed anchors are rejected', () => {
  const { ledger, trusted } = scenario();
  assert.equal(appendAuditEvent(ledger, draft(), trusted).status, 'RECORDED');
  const anchor = createAuditCheckpoint(ledger, trusted);
  assert.equal(verifyAuditStream(ledger, trusted, [{ ...anchor, entryDigest: 'b'.repeat(64) }]).finding,
    'CHECKPOINT_DIGEST_MISMATCH');
  assert.equal(verifyAuditStream(ledger, trusted, [{ ...anchor, sequence: 9 }]).finding, 'TAIL_TRUNCATED');
  for (const bad of [null, undefined, 'x', {}, [{ ...anchor, digest: 'x' }],
    [{ ...anchor, entryDigest: 'not-a-digest' }], [{ ...anchor, sequence: 0 }],
    [anchor, anchor], [anchor, { ...anchor, sequence: 1, entryDigest: 'c'.repeat(64) }],
    Array.from({ length: 129 }, () => anchor)]) {
    const result = verifyAuditStream(ledger, trusted, bad);
    assert.equal(result.status, 'UNAVAILABLE', JSON.stringify(result));
    assert.equal(result.finding, 'ANCHOR_INVALID');
  }
  // Verification without a usable key cannot claim tamper evidence.
  assert.equal(verifyAuditStream(ledger, context({ chainKey: new Uint8Array(3) }), [anchor]).finding,
    'KEY_UNAVAILABLE');
  assert.equal(verifyAuditStream(ledger, context({ scope: { tenantId: 'tenant-b.invalid' } }), [anchor]).finding,
    'INVALID_CONTEXT');
  assert.equal(verifyAuditStream(ledger, trusted, [anchor]).entriesChecked, 1);
});

test('append unavailability yields a restrictive gate for dependent high-risk effects', () => {
  const { ledger, trusted } = scenario();
  ledger.accepting = false;
  const blocked = appendAuditEvent(ledger, draft(), trusted);
  assertRestricted(blocked, 'AUDIT_UNAVAILABLE');
  assert.equal(ledger.entries.length, 0);
  const gate = gateHighRiskEffect(blocked);
  assert.equal(gate.permitted, false, 'an unrecorded effect must not be permitted');
  assert.equal(gate.finding, 'EVIDENCE_UNAVAILABLE');
  ledger.accepting = true;
  const recorded = appendAuditEvent(ledger, draft(), trusted);
  assert.equal(gateHighRiskEffect(recorded).permitted, true);
  assert.equal(gateHighRiskEffect(recorded).finding, 'EVIDENCE_RECORDED');
  // An invalid event never satisfies the audit precondition either.
  assertRestricted(appendAuditEvent(ledger, draft({ kind: 'NOPE' }), trusted), 'INVALID_DRAFT');
  const invalidGate = gateHighRiskEffect(appendAuditEvent(ledger, draft({ kind: 'NOPE' }), trusted));
  assert.equal(invalidGate.permitted, false);
  assert.equal(invalidGate.finding, 'EVIDENCE_INVALID');
  for (const bad of [null, undefined, {}, { status: 'RECORDED' }, { status: 'ALLOWED', finding: 'RECORDED' },
    { status: 'RECORDED', finding: 'RECORDED', receipt: 'x' }]) {
    assert.equal(gateHighRiskEffect(bad).permitted, false, JSON.stringify(bad));
  }
});

test('a rejected append is atomic and never advances or corrupts the chain', () => {
  const { ledger, trusted } = scenario();
  assert.equal(appendAuditEvent(ledger, draft(), trusted).status, 'RECORDED');
  const before = serializeAuditEntry(ledger.entries[0]);
  const failures = [draft({ kind: 'NOPE' }), draft({ reason: 'caller text' }),
    draft({ entityRef: 'e'.repeat(8192) }),
    (() => { const o = draft(); Object.defineProperty(o, 'bundle', { enumerable: true,
      get() { throw new Error('planted bundle accessor'); } }); return o; })(),
    new Proxy(draft(), { getOwnPropertyDescriptor() { throw new Error('planted descriptor'); } })];
  for (const value of failures) appendAuditEvent(ledger, value, trusted);
  assert.equal(ledger.entries.length, 1);
  assert.equal(serializeAuditEntry(ledger.entries[0]), before);
  // The chain still continues cleanly after the rejected appends.
  assert.equal(appendAuditEvent(ledger, draft({ correlationRef: 'correlation-2' }), trusted).status, 'RECORDED');
  assert.equal(ledger.entries[1].prevDigest, ledger.entries[0].entryDigest);
  assert.equal(verifyAuditStream(ledger, trusted, [createAuditCheckpoint(ledger, trusted)]).status, 'VERIFIED');
});

test('a full ledger refuses further appends atomically', () => {
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope, { maxEntries: 2 });
  assert.equal(appendAuditEvent(ledger, draft(), trusted).status, 'RECORDED');
  assert.equal(appendAuditEvent(ledger, draft({ correlationRef: 'correlation-2' }), trusted).status, 'RECORDED');
  assertRestricted(appendAuditEvent(ledger, draft({ correlationRef: 'correlation-3' }), trusted),
    'EVENT_CAPACITY');
  assert.equal(ledger.entries.length, 2);
  const anchor = createAuditCheckpoint(ledger, trusted);
  assert.equal(verifyAuditStream(ledger, trusted, [anchor]).status, 'VERIFIED');
});

test('appending under a changed chain key extends the chain and verification then reports it', () => {
  // The ledger deliberately retains no key, so it cannot tell that a key changed: the append is
  // recorded rather than refused, and the retained checkpoint is what exposes the fork.
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope);
  assert.equal(appendAuditEvent(ledger, draft(), trusted).status, 'RECORDED');
  const anchor = createAuditCheckpoint(ledger, trusted);
  assert.equal(appendAuditEvent(ledger, draft({ correlationRef: 'correlation-2' }),
    context({ chainKey: key(77) })).status, 'RECORDED');
  const result = verifyAuditStream(ledger, trusted, [anchor]);
  assert.equal(result.status, 'TAMPERED', JSON.stringify(result));
  assert.equal(result.finding, 'CHAIN_BROKEN');
  // Verification under the same wrong key also fails: the first entry cannot be re-derived.
  assert.equal(verifyAuditStream(ledger, context({ chainKey: key(77) }), [anchor]).status, 'TAMPERED');
});

test('a stream that cannot commit is a typed restrictive failure and never a thrown error', () => {
  const sealed = createInMemoryAuditLedger(context().scope);
  Object.freeze(sealed.entries);
  let thrown = null;
  try { appendAuditEvent(sealed, draft(), context()); } catch (error) { thrown = error; }
  assert.equal(thrown, null, 'an uncommittable audit sink must not throw at the caller');
  assertRestricted(appendAuditEvent(sealed, draft(), context()), 'AUDIT_UNAVAILABLE');
  assert.equal(sealed.entries.length, 0);

  const grown = createInMemoryAuditLedger(context().scope);
  const trusted = context();
  assert.equal(appendAuditEvent(grown, draft(), trusted).status, 'RECORDED');
  Object.preventExtensions(grown.entries);
  const blocked = appendAuditEvent(grown, draft(), trusted);
  assertRestricted(blocked, 'AUDIT_UNAVAILABLE');
  assert.equal(grown.entries.length, 1);
  // A sink that cannot commit the evidence never satisfies the dependent effect precondition.
  assert.equal(gateHighRiskEffect(blocked).permitted, false);
  assert.equal(gateHighRiskEffect(blocked).finding, 'EVIDENCE_UNAVAILABLE');
});

test('a degenerate all-zero key is refused, while other entropy quality stays a KMS obligation', () => {
  // An all-zero HMAC key is publicly derivable, so a chain "verified" under it would authenticate
  // nothing. That single degenerate case is refused. Distribution, generation, custody, rotation
  // and destruction remain key-management obligations this module does not take over.
  const zero = new Uint8Array(32);
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope);
  for (const bad of [context({ chainKey: zero }), context({ pseudonymKey: zero }),
    context({ chainKey: new Uint8Array(128) }), context({ pseudonymKey: new Uint8Array(3) })]) {
    const result = appendAuditEvent(ledger, draft(), bad);
    assertRestricted(result, 'KEY_UNAVAILABLE', JSON.stringify(Object.keys(bad)));
    assert.equal(gateHighRiskEffect(result).permitted, false);
  }
  assert.equal(ledger.entries.length, 0);
  // Verification cannot claim tamper evidence under a key it refuses, and no anchor is minted.
  assert.equal(verifyAuditStream(ledger, trusted, []).status, 'UNANCHORED');
  assert.equal(verifyAuditStream(ledger, context({ chainKey: zero }), []).finding, 'KEY_UNAVAILABLE');
  assert.throws(() => createAuditCheckpoint(ledger, context({ chainKey: zero })), /Invalid audit ledger/);
  // Positive control: a non-degenerate key with a zero byte is ordinary, not rejected.
  assert.equal(appendAuditEvent(ledger, draft(), context({ chainKey: key(0), pseudonymKey: key(0) }))
    .status, 'RECORDED');
  assert.equal(verifyAuditStream(ledger, context({ chainKey: key(0) }),
    [createAuditCheckpoint(ledger, context({ chainKey: key(0) }))]).status, 'VERIFIED');
});

test('occurredAt is the caller-supplied instant: recorded verbatim, never independently verified', () => {
  // Stated limit: there is no injected clock. A shape-valid backdated or forward-dated instant is
  // recorded exactly as supplied, and altering it afterwards is tamper evidence, not a silent fix.
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope);
  const backdated = '2001-01-01T00:00:00.000Z';
  const recorded = appendAuditEvent(ledger, draft({ occurredAt: backdated }), trusted);
  assert.equal(recorded.status, 'RECORDED', JSON.stringify(recorded));
  assert.equal(ledger.entries[0].event.occurredAt, backdated);
  assert.equal(recorded.receipt.occurredAt, backdated);
  const anchor = createAuditCheckpoint(ledger, trusted);
  assert.equal(verifyAuditStream(ledger, trusted, [anchor]).status, 'VERIFIED');
  // Altering the instant afterwards is tamper evidence, not a silent correction: the digest is
  // bound to the event, so an un-rekeyed edit breaks the chain and a rekeyed one breaks the anchor.
  const edited = { ...ledger, entries: [{ ...ledger.entries[0],
    event: { ...ledger.entries[0].event, occurredAt: '2026-09-20T10:11:12.130Z' } }] };
  assert.equal(verifyAuditStream(edited, trusted, [anchor]).finding, 'CHAIN_BROKEN');
  // Shape and parse acceptance are the whole clock check: a rolled-over calendar date is recorded
  // exactly as supplied, and an instant that is not parseable is not stored at all.
  const rolled = appendAuditEvent(ledger, draft({ occurredAt: '2001-02-30T00:00:00.000Z' }), trusted);
  assert.equal(rolled.status, 'RECORDED', JSON.stringify(rolled));
  assert.equal(ledger.entries[1].event.occurredAt, '2001-02-30T00:00:00.000Z');
  assertRestricted(appendAuditEvent(ledger, draft({ occurredAt: '2026-13-45T99:99:99.999Z' }), trusted),
    'INVALID_DRAFT');
  assert.equal(ledger.entries.length, 2);
});

test('a sink that accepts the write and discards it is an outage, never a recorded receipt', () => {
  // The write into a caller-supplied container is a dynamic call: it can succeed and store nothing.
  // A receipt is therefore only issued once the commit is *confirmed* by a bounded descriptor
  // read-back, so no dependent high-risk effect can be permitted over evidence that was lost.
  const trusted = context();
  const value = draft();
  const outliving = (result) => {
    assertRestricted(result, 'AUDIT_UNAVAILABLE');
    assert.equal(gateHighRiskEffect(result).permitted, false);
    assert.equal(gateHighRiskEffect(result).finding, 'EVIDENCE_UNAVAILABLE');
  };

  // An own no-op `push`: the call returns normally and nothing is stored anywhere.
  const ownNoopPush = createInMemoryAuditLedger(trusted.scope);
  Object.defineProperty(ownNoopPush.entries, 'push',
    { value: () => 0, writable: true, configurable: true });
  outliving(appendAuditEvent(ownNoopPush, value, trusted));
  assert.equal(ownNoopPush.entries.length, 0, 'nothing may be reported recorded when nothing was stored');

  // A Proxy whose traps report success without writing: two appends, still no evidence.
  const sink = createInMemoryAuditLedger(trusted.scope);
  const silent = new Proxy(sink.entries, { set: () => true, defineProperty: () => true });
  const discarding = { ...sink, entries: silent };
  for (const sequence of [1, 2]) {
    outliving(appendAuditEvent(discarding, draft({ correlationRef: `correlation-${sequence}` }), trusted));
  }
  assert.equal(sink.entries.length, 0);

  // A sink that stores something other than the record it was handed is equally unverifiable.
  const donor = createInMemoryAuditLedger(trusted.scope);
  assert.equal(appendAuditEvent(donor, value, trusted).status, 'RECORDED');
  const impostor = createInMemoryAuditLedger(trusted.scope);
  const swapping = new Proxy(impostor.entries, {
    defineProperty(target, key, descriptor) {
      Object.defineProperty(target, key, key === 'length' ? descriptor
        : { ...descriptor, value: donor.entries[0] });
      return true;
    },
  });
  outliving(appendAuditEvent({ ...impostor, entries: swapping }, value, trusted));

  // A descriptor read-back that throws is an outage, never an unverified receipt.
  const exploding = createInMemoryAuditLedger(trusted.scope);
  const unreadable = new Proxy(exploding.entries, {
    getOwnPropertyDescriptor(target, key) {
      if (key === 'length') return Reflect.getOwnPropertyDescriptor(target, key);
      throw new Error('planted commit acknowledgement');
    },
  });
  outliving(appendAuditEvent({ ...exploding, entries: unreadable }, value, trusted));
  for (const result of [appendAuditEvent({ ...exploding, entries: unreadable }, value, trusted),
    appendAuditEvent({ ...sink, entries: new Proxy(sink.entries, {
      get() { throw new Error('planted sink trap'); } }) }, value, trusted)]) {
    assertRestricted(result, 'AUDIT_UNAVAILABLE');
    assert.ok(!JSON.stringify(result).includes('planted'));
  }

  // A decorated container is never left looking like a healthy empty stream either.
  const decorated = verifyAuditStream(ownNoopPush, trusted, []);
  assert.equal(decorated.status, 'UNAVAILABLE', JSON.stringify(decorated));
  assert.equal(decorated.finding, 'INVALID_LEDGER', 'a sink that hides its own shape is not empty evidence');
  assert.equal(decorated.entriesChecked, 0);

  // Positive control: an honest sink is confirmed, recorded, and verifiable against a checkpoint.
  const honest = createInMemoryAuditLedger(trusted.scope);
  const recorded = appendAuditEvent(honest, value, trusted);
  assert.equal(recorded.status, 'RECORDED', JSON.stringify(recorded));
  assert.equal(honest.entries.length, 1);
  assert.equal(honest.entries[0].entryDigest, recorded.receipt.entryDigest);
  assert.equal(gateHighRiskEffect(recorded).permitted, true);
  assert.equal(verifyAuditStream(honest, trusted, [createAuditCheckpoint(honest, trusted)]).status,
    'VERIFIED');
});

test('generated hostile sinks never yield a receipt over evidence that was not committed', () => {
  const trusted = context();
  const impostor = Object.freeze({ version: 1, sequence: 1, prevDigest: ZERO64,
    entryDigest: HEX64, event: Object.freeze({ kind: 'CLOAK' }) });
  const shapes = [
    (entries) => new Proxy(entries, { set: () => true, defineProperty: () => true }),
    (entries) => new Proxy(entries, { set: () => true }),
    (entries) => new Proxy(entries, { defineProperty: () => true }),
    (entries) => new Proxy(entries, { get: (target, key) => (
      key === 'length' ? 0 : Reflect.get(target, key)) }),
    (entries) => { Object.defineProperty(entries, 'push',
      { value: () => 0, writable: true, configurable: true }); return entries; },
    (entries) => { Object.defineProperty(entries, 'push',
      { value: function push() { return 0; }, writable: true, configurable: true }); return entries; },
    (entries) => new Proxy(entries, { defineProperty: (target, key, descriptor) => {
      Object.defineProperty(target, key, key === 'length' ? descriptor
        : { ...descriptor, value: impostor });
      return true;
    } }),
    (entries) => new Proxy(entries, { getOwnPropertyDescriptor: (target, key) => {
      if (key === 'length') return Reflect.getOwnPropertyDescriptor(target, key);
      throw new Error('planted commit acknowledgement');
    } }),
    (entries) => new Proxy(entries, { get() { throw new Error('planted sink trap'); } }),
  ];
  for (const [index, shape] of shapes.entries()) {
    const ledger = createInMemoryAuditLedger(trusted.scope);
    const wrapped = shape(ledger.entries);
    const stream = { ...ledger, entries: wrapped };
    for (const sequence of [1, 2]) {
      const result = appendAuditEvent(stream, draft({ correlationRef: `correlation-${sequence}` }), trusted);
      assert.ok(result.status === 'RECORDED' || result.status === 'RESTRICTED', index);
      if (result.status === 'RECORDED') {
        // A receipt is only ever issued over a record that is actually readable in this array.
        const stored = Object.getOwnPropertyDescriptor(wrapped, String(result.receipt.sequence - 1));
        assert.ok(stored && stored.value === ledger.entries[result.receipt.sequence - 1],
          `shape ${index}: a receipt over evidence that cannot be read back`);
        assert.equal(ledger.entries.length, result.receipt.sequence, `shape ${index}`);
        continue;
      }
      // Every other outcome is restrictive: an uncommittable/unverifiable commit, or a container
      // that is no longer readable as a stream. Neither ever satisfies the effect precondition.
      assert.ok(['AUDIT_UNAVAILABLE', 'INVALID_LEDGER'].includes(result.finding),
        `shape ${index}: ${JSON.stringify(result)}`);
      assert.equal(result.receipt, undefined, `shape ${index}`);
      assert.equal(gateHighRiskEffect(result).permitted, false, `shape ${index}`);
      assert.equal(gateHighRiskEffect(result).finding, result.finding === 'AUDIT_UNAVAILABLE'
        ? 'EVIDENCE_UNAVAILABLE' : 'EVIDENCE_INVALID', `shape ${index}`);
      assert.ok(!JSON.stringify(result).includes('planted'), `shape ${index}`);
    }
    // Whatever the sink did, the module never hands out a receipt it cannot read back.
    const verified = verifyAuditStream(stream, trusted, []);
    assert.ok(['VERIFIED', 'UNANCHORED', 'TAMPERED'].includes(verified.status) ||
      verified.finding === 'INVALID_LEDGER' || verified.finding === 'CHAIN_BROKEN', `shape ${index}`);
    if (verified.status === 'VERIFIED' || verified.status === 'UNANCHORED') {
      assert.equal(verified.entriesChecked, ledger.entries.length, `shape ${index}`);
    }
  }
});

test('a container that lies about both the write and the read-back is a stated in-language limit', () => {
  // Honest boundary: confirmation reads the record back through the *same* container it was written
  // into. A container that accepts the record, stores nothing and reports it back is not
  // distinguishable, in language, from one that committed it. That is why the substrate is an
  // in-memory array with no durability claim, and why an integrating storage adapter's own durable
  // commit acknowledgment is a trust obligation this module cannot discharge - exactly like the
  // effect gate's inability to bind a receipt to an entry.
  const trusted = context();
  const phantom = [];
  const claimed = [];
  const entries = new Proxy(phantom, {
    set(target, key, value) {
      if (key === 'length') claimed.length = Number(value); else claimed[Number(key)] = value;
      return true;
    },
    getOwnPropertyDescriptor(target, key) {
      if (key === 'length') return { value: claimed.length, writable: true, enumerable: false,
        configurable: false };
      if (Number(key) < claimed.length) return { value: claimed[Number(key)], writable: true,
        enumerable: true, configurable: true };
      return undefined;
    },
  });
  const ledger = createInMemoryAuditLedger(trusted.scope);
  const result = appendAuditEvent({ ...ledger, entries }, draft(), trusted);
  assert.equal(phantom.length, 0, 'the real array holds nothing');
  assert.equal(claimed.length, 1, 'the container claims one committed record');
  // Stated limit: the receipt reflects what the container reported, not external durability.
  assert.equal(result.status, 'RECORDED', JSON.stringify(result));
  assert.equal(verifyAuditStream({ ...ledger, entries }, trusted, []).finding, 'INVALID_LEDGER');
  // Nothing about this weakens the ordinary substrate: an honest ledger is still appendable.
  assert.equal(appendAuditEvent(ledger, draft(), trusted).status, 'RECORDED');
});

test('an unreadable ledger is reported as INVALID_LEDGER, not as a caller or authority failure', () => {
  const trusted = context();
  const good = createInMemoryAuditLedger(trusted.scope);
  assert.equal(appendAuditEvent(good, draft(), trusted).status, 'RECORDED');
  const authority = { version: 1, scope: trusted.scope, principalId: 'auditor-a.invalid' };
  const unreadable = [
    { ...good, entries: 'not-an-array' },
    { ...good, entries: new Map() },
    { ...good, entries: [null] },
    { ...good, entries: {} },
    { ...good, maxEntries: 0 },
    { ...good, accepting: 'yes' },
    { ...good, version: 2 },
    { ...good, extra: 'unlisted' },
    new Proxy(good, { ownKeys() { throw new Error('planted ledger keys'); } }),
    new Proxy(good, { getOwnPropertyDescriptor() { throw new Error('planted ledger descriptor'); } }),
    null, undefined, 42, 'stream', [],
  ];
  for (const ledger of unreadable) {
    const label = typeof ledger;
    assertRestricted(appendAuditEvent(ledger, draft(), trusted), 'INVALID_LEDGER', label);
    const verified = verifyAuditStream(ledger, trusted, []);
    assert.equal(verified.status, 'UNAVAILABLE', label);
    assert.equal(verified.finding, 'INVALID_LEDGER', label);
    for (const read of [readAuditEvents(ledger, authority, {}),
      exportAuditEvents(ledger, { ...authority, exportAuthorized: true }, {})]) {
      assert.equal(read.status, 'RESTRICTED', label);
      assert.equal(read.finding, 'INVALID_LEDGER', label);
      assert.equal(read.entries, undefined);
      assert.equal(read.matched, 0);
    }
    assert.ok(!JSON.stringify([appendAuditEvent(ledger, draft(), trusted), verified]).includes('planted'));
  }
  // The unreadable ledger is intact: no forged finding is ever recorded as an event.
  assert.equal(good.entries.length, 1);
});

test('read and export results are independent frozen copies that cannot reach back into the ledger', () => {
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope);
  for (let i = 1; i <= 3; i += 1) {
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), trusted).status,
      'RECORDED');
  }
  const authority = { version: 1, scope: trusted.scope, principalId: 'auditor-a.invalid' };
  const first = readAuditEvents(ledger, authority, {});
  const second = readAuditEvents(ledger, authority, {});
  const exported = exportAuditEvents(ledger, { ...authority, exportAuthorized: true }, {});
  for (const result of [first, second, exported]) {
    assert.equal(result.status, 'OK', JSON.stringify(result));
    const entry = result.entries[0];
    for (const part of [entry, entry.event, entry.event.scope, entry.event.actor, entry.event.bundle,
      entry.event.bundle.policy, ...entry.event.bundle.components]) {
      assert.ok(Object.isFrozen(part), 'every delivered part must be frozen');
    }
  }
  // No delivered copy is a live alias into the ledger or into another reader's result.
  assert.notEqual(first.entries[0].event, second.entries[0].event);
  assert.notEqual(first.entries[0].event, ledger.entries[0].event);
  assert.notEqual(exported.entries[0].event, first.entries[0].event);
  // A delivered copy is byte-identical to the stored evidence, so isolation costs no fidelity.
  for (const entry of [first.entries[0], exported.entries[2]]) {
    assert.equal(serializeAuditEntry(entry), serializeAuditEntry(ledger.entries[entry.sequence - 1]));
  }
  const before = JSON.stringify(ledger);
  try { first.entries[0].event.outcome = 'DENIED'; } catch { /* frozen: the write is refused */ }
  assert.equal(JSON.stringify(ledger), before, 'a read result must not be a mutation channel');
  assert.equal(ledger.entries[0].event.outcome, 'APPLIED');
});

test('append cost stays linear in one event instead of re-validating the whole stream', () => {
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope, { maxEntries: 2000 });
  const started = performance.now();
  for (let i = 1; i <= 2000; i += 1) {
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), trusted).status,
      'RECORDED');
  }
  const elapsed = performance.now() - started;
  // Bounded-work regression, not a latency SLA: re-validating the stream per append is quadratic.
  assert.ok(elapsed < 8000, `2000 appends took ${elapsed.toFixed(0)} ms; append must not rescan the stream`);
  assert.equal(ledger.entries.length, 2000);
  assert.equal(verifyAuditStream(ledger, trusted, [createAuditCheckpoint(ledger, trusted)]).status,
    'VERIFIED');
});

test('corruption away from the append head is caught at verification, not at append', () => {
  // Stated limit: the append path validates only the entry it extends, so a stream already corrupt
  // further back still accepts an append. Whole-stream validation is a verification/read concern.
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope);
  for (let i = 1; i <= 3; i += 1) {
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), trusted).status,
      'RECORDED');
  }
  const anchor = createAuditCheckpoint(ledger, trusted);
  const corrupted = { ...ledger, entries: ledger.entries.slice() };
  corrupted.entries[0] = { ...corrupted.entries[0], entryDigest: 'd'.repeat(64) };
  assert.equal(appendAuditEvent(corrupted, draft({ correlationRef: 'correlation-4' }), trusted).status,
    'RECORDED');
  const result = verifyAuditStream(corrupted, trusted, [anchor]);
  assert.equal(result.status, 'TAMPERED', JSON.stringify(result));
  assert.equal(result.finding, 'CHAIN_BROKEN');
});

test('the effect gate is a structural precondition and never carries a grant of its own', () => {
  // Stated limit: the gate is a pure structural check on the value handed to it. It cannot bind a
  // receipt to a committed entry, so an integrating effect must pass the result it received
  // directly from appendAuditEvent and must never reconstruct or replay one.
  const forged = { version: 1, status: 'RECORDED', finding: 'RECORDED',
    receipt: { version: 1, scope: context().scope, sequence: 1, entryDigest: HEX64,
      correlationRef: `cor_${'0'.repeat(32)}`, occurredAt: '2026-09-20T10:11:12.130Z' } };
  const gate = gateHighRiskEffect(forged);
  assert.equal(gate.permitted, true, 'a fabricated result is accepted; prevention is a call-site obligation');
  assert.deepEqual(Object.keys(gate).sort(), ['finding', 'permitted', 'version']);
  assert.ok(!Object.keys(gate).some((key) => /grant|permit(?!ted)|resolve|reveal|token|capab/iu
    .test(key)), 'a gate result must not carry a permission or capability');
  // Malformed or unrecognised input is never permissive, in either direction.
  for (const bad of [{ version: 1, status: 'RECORDED', finding: 'AUDIT_UNAVAILABLE' },
    { version: 1, status: 'RESTRICTED', finding: 'RECORDED' }, { version: 1, status: 'RECORDED' },
    { version: 1, status: 'RECORDED', finding: 'RECORDED', receipt: null }]) {
    assert.equal(gateHighRiskEffect(bad).permitted, false, JSON.stringify(bad));
  }
});

test('ledger construction and checkpoint serialization reject bad input with a fixed message', () => {
  for (const bad of [null, undefined, 42, 'tenant', [], {}, { tenantId: PLANTED_MAIL },
    { tenantId: 'tenant-a.invalid', projectId: PLANTED_URL }, { tenantId: 'tenant-a.invalid', extra: 1 }]) {
    assert.throws(() => createInMemoryAuditLedger(bad), (error) => {
      assert.ok(error instanceof TypeError);
      assert.equal(error.message, 'Invalid audit ledger scope');
      return true;
    });
  }
  for (const bad of [{}, { maxEntries: 0 }, { maxEntries: '4' }, { maxEntries: 1, extra: 1 }, null]) {
    assert.throws(() => createInMemoryAuditLedger(context().scope, bad), /Invalid audit ledger scope/);
  }
  assert.equal(createInMemoryAuditLedger(context().scope).maxEntries, 4096);
  const { ledger, trusted } = scenario();
  assert.equal(appendAuditEvent(ledger, draft(), trusted).status, 'RECORDED');
  const anchor = createAuditCheckpoint(ledger, trusted);
  for (const bad of [null, undefined, 42, 'anchor', {}, { ...anchor, digest: 'x' },
    { ...anchor, entryDigest: HEX64.toUpperCase() }, { ...anchor, scope: { tenantId: PLANTED_MAIL } }]) {
    assert.throws(() => serializeAuditCheckpoint(bad), (error) => {
      assert.ok(error instanceof TypeError);
      assert.equal(error.message, 'Invalid audit checkpoint');
      return true;
    });
  }
});

test('a lying stream length can neither bypass the capacity bound nor hide a chain fork', () => {
  // The append path takes exactly one `length` read. A hostile container that reports a length it
  // does not have is rejected at the bound, and its commit can never be confirmed, so it is a
  // typed audit outage rather than a receipt over evidence the container never kept.
  const inflating = (entries, reported) => new Proxy(entries, {
    getOwnPropertyDescriptor(target, key) {
      if (key === 'length') {
        return { value: reported, writable: true, enumerable: false, configurable: false };
      }
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  const trusted = context();
  const honest = createInMemoryAuditLedger(trusted.scope, { maxEntries: 4 });
  assert.equal(appendAuditEvent(honest, draft(), trusted).status, 'RECORDED');
  const overstated = { ...honest, entries: inflating(honest.entries, 99) };
  assertRestricted(appendAuditEvent(overstated, draft({ correlationRef: 'correlation-2' }), trusted),
    'INVALID_LEDGER');
  assert.equal(honest.entries.length, 1);

  const hidden = createInMemoryAuditLedger(trusted.scope);
  const liar = { ...hidden, entries: inflating(hidden.entries, 0) };
  for (let i = 1; i <= 3; i += 1) {
    const result = appendAuditEvent(liar, draft({ correlationRef: `correlation-${i}` }), trusted);
    assertRestricted(result, 'AUDIT_UNAVAILABLE', `append ${i}: ${JSON.stringify(result)}`);
    assert.equal(gateHighRiskEffect(result).permitted, false);
  }
  // The stream is not silently presented as healthy, empty evidence either.
  const forked = verifyAuditStream(liar, trusted, []);
  assert.equal(forked.status, 'UNAVAILABLE', JSON.stringify(forked));
  assert.equal(forked.finding, 'INVALID_LEDGER');
  assert.ok(!JSON.stringify([forked, appendAuditEvent(liar, draft(), trusted)]).includes('planted'));
});

test('read access is scope-isolated, bounded and never returns another tenant stream', () => {
  const tenantA = context();
  const ledger = createInMemoryAuditLedger(tenantA.scope);
  for (let i = 1; i <= 5; i += 1) {
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), tenantA).status,
      'RECORDED');
  }
  assert.equal(appendAuditEvent(ledger, draft({ kind: 'KEY_OPERATION', operation: 'ROTATE', outcome: 'APPLIED',
    reason: 'ADMIN_APPLIED', keyVersion: '1', correlationRef: 'correlation-6' }), tenantA).status,
    'RECORDED');
  const authority = { version: 1, scope: tenantA.scope, principalId: 'auditor-a.invalid' };
  const all = readAuditEvents(ledger, authority, {});
  assert.equal(all.status, 'OK', JSON.stringify(all));
  assert.equal(all.entries.length, 6);
  assert.equal(all.matched, 6);
  assert.equal(all.truncated, false);
  for (const planted of PLANTED) assert.ok(!JSON.stringify(all).includes(planted));
  const bounded = readAuditEvents(ledger, authority, { limit: 2 });
  assert.equal(bounded.entries.length, 2);
  assert.equal(bounded.matched, 6);
  assert.equal(bounded.truncated, true);
  const ranged = readAuditEvents(ledger, authority, { fromSequence: 2, toSequence: 3 });
  assert.deepEqual(ranged.entries.map((e) => e.sequence), [2, 3]);
  const filtered = readAuditEvents(ledger, authority, { kinds: ['KEY_OPERATION'] });
  assert.equal(filtered.entries.length, 1);
  assert.equal(filtered.entries[0].event.kind, 'KEY_OPERATION');
  for (const foreign of [context({ scope: { tenantId: 'tenant-b.invalid', projectId: 'project-b.invalid' } }),
    context({ scope: { tenantId: 'tenant-a.invalid' } }),
    { version: 1, scope: tenantA.scope }, { version: 1, scope: tenantA.scope, principalId: PLANTED_MAIL },
    null, 'auditor']) {
    const denied = readAuditEvents(ledger, foreign, {});
    assert.equal(denied.status, 'RESTRICTED', JSON.stringify(foreign));
    assert.ok(['SCOPE_MISMATCH', 'INVALID_AUTHORITY'].includes(denied.finding), denied.finding);
    assert.equal(denied.entries, undefined);
    assert.equal(denied.matched, 0);
  }
  for (const bad of [null, 42, { limit: 0 }, { limit: 1.5 }, { limit: 100000 }, { fromSequence: 0 },
    { toSequence: -1 }, { kinds: [] }, { kinds: ['NOPE'] }, { kinds: 'CLOAK' }, { kinds: ['CLOAK', 'CLOAK'] }]) {
    assertRestricted(readAuditEvents(ledger, authority, bad), 'INVALID_QUERY', JSON.stringify(bad));
  }
});

test('export requires an explicit, scope-matched export authority and stays bounded', () => {
  const tenantA = context();
  const ledger = createInMemoryAuditLedger(tenantA.scope);
  for (let i = 1; i <= 3; i += 1) {
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), tenantA).status,
      'RECORDED');
  }
  const readOnly = { version: 1, scope: tenantA.scope, principalId: 'auditor-a.invalid' };
  assertRestricted(exportAuditEvents(ledger, readOnly, {}), 'EXPORT_NOT_AUTHORIZED');
  assertRestricted(exportAuditEvents(ledger, { ...readOnly, exportAuthorized: 'yes' }, {}), 'INVALID_AUTHORITY');
  const exporter = { ...readOnly, exportAuthorized: true };
  const exported = exportAuditEvents(ledger, exporter, {});
  assert.equal(exported.status, 'OK', JSON.stringify(exported));
  assert.equal(exported.entries.length, 3);
  for (const planted of PLANTED) assert.ok(!JSON.stringify(exported).includes(planted));
  assert.equal(exportAuditEvents(ledger, exporter, { limit: 1 }).truncated, true);
  assertRestricted(exportAuditEvents(ledger, { ...exporter,
    scope: { tenantId: 'tenant-b.invalid' } }, {}), 'SCOPE_MISMATCH');
  // Reading never implies exporting, and a read authority must not carry export authority.
  assert.equal(readAuditEvents(ledger, readOnly, {}).status, 'OK');
  assertRestricted(readAuditEvents(ledger, exporter, {}), 'INVALID_AUTHORITY');
  assertRestricted(exportAuditEvents(ledger, readOnly, {}), 'EXPORT_NOT_AUTHORIZED');
});

test('a relabelled ledger returns no foreign event or foreign metadata on read or export', () => {
  // Scope isolation is per entry, not merely per declared label: relabelling the outer ledger while
  // the entries still belong to another tenant must not hand that stream (or any of its metadata)
  // to the relabelled tenant, on any path, under any query.
  const tenantA = context();
  const scopeB = { tenantId: 'tenant-b.invalid', projectId: 'project-b.invalid' };
  const tenantB = context({ scope: scopeB, actor: { principalId: 'principal-b.invalid' },
    integrationId: 'integration-b.invalid', pseudonymKey: key(41), chainKey: key(42) });
  const streamA = createInMemoryAuditLedger(tenantA.scope);
  for (let i = 1; i <= 3; i += 1) {
    assert.equal(appendAuditEvent(streamA, draft({ correlationRef: `correlation-a-${i}` }),
      tenantA).status, 'RECORDED');
  }
  const relabelled = { ...streamA, scope: scopeB };
  const readB = { version: 1, scope: scopeB, principalId: 'auditor-b.invalid' };
  const exportB = { ...readB, exportAuthorized: true };
  const attempts = [
    readAuditEvents(relabelled, readB, {}),
    exportAuditEvents(relabelled, exportB, {}),
    // A query that selects none of the foreign entries is still refused: the check is stream-wide.
    readAuditEvents(relabelled, readB, { fromSequence: 99 }),
    readAuditEvents(relabelled, readB, { kinds: ['CLOAK'], limit: 1 }),
    exportAuditEvents(relabelled, exportB, { kinds: ['KEY_OPERATION'] }),
  ];
  for (const result of attempts) {
    assert.equal(result.status, 'RESTRICTED', JSON.stringify(result));
    assert.equal(result.finding, 'SCOPE_MISMATCH');
    assert.equal(result.entries, undefined);
    assert.equal(result.matched, 0);
    assert.equal(result.truncated, false);
    const wire = JSON.stringify(result);
    assert.ok(!wire.includes('tenant-a.invalid') && !wire.includes('principal-a.invalid'), wire);
    assert.ok(!wire.includes('workload-a.invalid') && !wire.includes('integration-a.invalid'), wire);
    for (const entry of streamA.entries) {
      assert.ok(!wire.includes(entry.event.correlationRef), 'foreign correlation pseudonym disclosed');
      assert.ok(!wire.includes(entry.event.entityRef), 'foreign entity pseudonym disclosed');
      assert.ok(!wire.includes(entry.entryDigest), 'foreign chain digest disclosed');
    }
  }
  // Verification already called this structure tampered; read and export now agree with it.
  const verified = verifyAuditStream(relabelled, tenantB, []);
  assert.equal(verified.status, 'TAMPERED', JSON.stringify(verified));
  assert.equal(verified.finding, 'SCOPE_MISMATCH');

  // A single substituted entry poisons the whole read: nothing in scope is delivered either.
  const donorB = createInMemoryAuditLedger(scopeB);
  assert.equal(appendAuditEvent(donorB, draft({ correlationRef: 'correlation-b-1' }), tenantB).status,
    'RECORDED');
  const mixed = { ...streamA, entries: [...streamA.entries.slice(0, 2), donorB.entries[0]] };
  const readA = { version: 1, scope: tenantA.scope, principalId: 'auditor-a.invalid' };
  for (const result of [readAuditEvents(mixed, readA, {}),
    readAuditEvents(mixed, readA, { toSequence: 1 }),
    exportAuditEvents(mixed, { ...readA, exportAuthorized: true }, {})]) {
    assert.equal(result.status, 'RESTRICTED', JSON.stringify(result));
    assert.equal(result.finding, 'SCOPE_MISMATCH');
    assert.equal(result.entries, undefined);
    assert.equal(result.matched, 0);
    assert.ok(!JSON.stringify(result).includes('correlation-b-1'));
  }
  // Tenant A's own stream is untouched and still fully readable under A's authority.
  assert.equal(readAuditEvents(streamA, readA, {}).status, 'OK');
  assert.equal(readAuditEvents(streamA, readA, {}).entries.length, 3);
});

test('generated tenant substitutions never return the foreign stream they are labelled with', () => {
  for (let i = 0; i < 32; i += 1) {
    const scopeA = { tenantId: `tenant-a${i}.invalid`, projectId: `project-a${i}.invalid` };
    const scopeB = { tenantId: `tenant-b${i}.invalid`, projectId: `project-b${i}.invalid` };
    const a = context({ scope: scopeA, actor: { principalId: `principal-a${i}.invalid` },
      pseudonymKey: key(100 + i), chainKey: key(200 + i) });
    const b = context({ scope: scopeB, actor: { principalId: `principal-b${i}.invalid` },
      pseudonymKey: key(300 + i), chainKey: key(400 + i) });
    const streamA = createInMemoryAuditLedger(scopeA);
    for (const sequence of [1, 2]) {
      assert.equal(appendAuditEvent(streamA, draft({ correlationRef: `correlation-a${i}-${sequence}` }),
        a).status, 'RECORDED', JSON.stringify(scopeA));
    }
    const relabelled = { ...streamA, scope: scopeB };
    const readB = { version: 1, scope: scopeB, principalId: `auditor-b${i}.invalid` };
    const foreign = [readAuditEvents(relabelled, readB, {}),
      exportAuditEvents(relabelled, { ...readB, exportAuthorized: true }, {})];
    for (const result of foreign) {
      assert.equal(result.status, 'RESTRICTED', `pair ${i}: ${JSON.stringify(result)}`);
      assert.equal(result.finding, 'SCOPE_MISMATCH', `pair ${i}`);
      assert.equal(result.entries, undefined, `pair ${i}`);
      assert.equal(result.matched, 0, `pair ${i}`);
      const wire = JSON.stringify(result);
      for (const entry of streamA.entries) {
        assert.ok(!wire.includes(entry.event.correlationRef), `pair ${i}`);
        assert.ok(!wire.includes(entry.event.entityRef), `pair ${i}`);
      }
      assert.ok(!wire.includes(scopeA.tenantId), `pair ${i}`);
    }
    assert.equal(verifyAuditStream(relabelled, b, []).finding, 'SCOPE_MISMATCH', `pair ${i}`);
    assert.equal(readAuditEvents(streamA, { version: 1, scope: scopeA, principalId: `auditor-a${i}.invalid` },
      {}).entries.length, 2, `pair ${i}`);
  }
});

test('an over-long entries array is refused before its key set is enumerated', () => {
  // A bound that is only applied after materialising the whole key set is not a bound. The length
  // descriptor is O(1), so an over-long container is refused without proportional own-key work.
  let enumerations = 0;
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope);
  assert.equal(appendAuditEvent(ledger, draft(), trusted).status, 'RECORDED');
  const overlength = new Proxy(ledger.entries, {
    getOwnPropertyDescriptor(target, key) {
      if (key === 'length') {
        return { value: 1_000_000, writable: true, enumerable: false, configurable: false };
      }
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
    ownKeys(target) { enumerations += 1; return Reflect.ownKeys(target); },
  });
  const stream = { ...ledger, entries: overlength };
  const authority = { version: 1, scope: trusted.scope, principalId: 'auditor-a.invalid' };
  const verified = verifyAuditStream(stream, trusted, []);
  assert.equal(verified.status, 'UNAVAILABLE', JSON.stringify(verified));
  assert.equal(verified.finding, 'INVALID_LEDGER');
  for (const read of [readAuditEvents(stream, authority, {}),
    exportAuditEvents(stream, { ...authority, exportAuthorized: true }, {})]) {
    assertRestricted(read, 'INVALID_LEDGER');
    assert.equal(read.entries, undefined);
    assert.equal(read.matched, 0);
  }
  assertRestricted(appendAuditEvent(stream, draft({ correlationRef: 'correlation-2' }), trusted),
    'INVALID_LEDGER');
  assert.equal(enumerations, 0, 'the length bound must be decided without enumerating the key set');
  assert.equal(ledger.entries.length, 1, 'a refused append never touches the stream');
});

test('checkpoints serialize deterministically and expose no opaque reference material', () => {
  const { ledger, trusted } = scenario();
  for (let i = 1; i <= 2; i += 1) {
    assert.equal(appendAuditEvent(ledger, draft({ correlationRef: `correlation-${i}` }), trusted).status,
      'RECORDED');
  }
  const anchor = createAuditCheckpoint(ledger, trusted, 1);
  assert.equal(anchor.sequence, 1);
  assert.equal(anchor.entryDigest, ledger.entries[0].entryDigest);
  assert.equal(serializeAuditCheckpoint(anchor), serializeAuditCheckpoint({ ...anchor }));
  assert.deepEqual(JSON.parse(serializeAuditCheckpoint(anchor)), anchor);
  assert.equal(serializeAuditEntry(ledger.entries[1]), serializeAuditEntry(ledger.entries[1]));
  assert.ok(!serializeAuditEntry(ledger.entries[1]).includes('entity-a1'));
  assert.throws(() => createAuditCheckpoint(createInMemoryAuditLedger(trusted.scope), trusted),
    /Invalid audit ledger/);
  assert.throws(() => createAuditCheckpoint(ledger, trusted, 99), /Invalid audit ledger/);
  for (const bad of [null, undefined, {}, { version: 2 }, { ...ledger, entries: 'x' },
    { ...ledger, maxEntries: 0 }, { ...ledger, scope: { tenantId: PLANTED_MAIL } }]) {
    assert.throws(() => createAuditCheckpoint(bad, trusted), /Invalid audit/);
    assert.throws(() => serializeAuditEntry(bad), /Invalid audit entry/);
  }
  for (const bad of [null, undefined, {}, { version: 1 }, { version: 1, policy: { id: 'a', version: '1' },
    components: [] }, { ...bundle(), policy: { ...bundle().policy, digest: 'not-a-digest' } }]) {
    assert.throws(() => digestAuditBundle(bad), /Invalid audit bundle/);
  }
  assert.equal(digestAuditBundle(bundle()), digestAuditBundle({ ...bundle(),
    components: [...bundle().components].reverse() }));
  const reversioned = bundle();
  reversioned.components = reversioned.components.map((component) => component.id === 'DETECTOR'
    ? { id: 'DETECTOR', version: '2' } : component);
  assert.notEqual(digestAuditBundle(bundle()), digestAuditBundle(reversioned));
  assert.throws(() => digestAuditBundle({ ...bundle(),
    components: [...bundle().components, { id: 'DETECTOR', version: '1' }] }), /Invalid audit bundle/);
});

test('every recorded event carries an exact bundle version set and vocabulary-compatible fields', () => {
  const trusted = context();
  const ledger = createInMemoryAuditLedger(trusted.scope);
  for (const semanticType of SEMANTIC_CLASSES) {
    for (const sensitivity of SENSITIVITIES) {
      const value = draft({ classification: { semanticType, sensitivity } });
      const result = appendAuditEvent(ledger, value, trusted);
      assert.equal(result.status, 'RECORDED', `${semanticType}/${sensitivity}`);
      const event = ledger.entries.at(-1).event;
      assert.equal(event.classification.semanticType, semanticType);
      assert.equal(event.classification.sensitivity, sensitivity);
      assert.deepEqual([...event.bundle.components].map((c) => c.id).sort(),
        [...bundle().components].map((c) => c.id).sort());
      assert.equal(event.bundle.policy.id, 'hylja.foundation');
      assert.equal(event.bundle.policy.version, '1');
    }
  }
  // Duplicate or unknown bundle components are not exact version records.
  assertRestricted(appendAuditEvent(ledger, draft({ bundle: { ...bundle(),
    components: [{ id: 'DETECTOR', version: '1' }, { id: 'DETECTOR', version: '1' }] } }), trusted),
    'INVALID_DRAFT');
  assertRestricted(appendAuditEvent(ledger, draft({ bundle: { ...bundle(),
    components: Array.from({ length: 33 }, (_, i) => ({ id: 'DETECTOR', version: String(i) })) } }), trusted),
    'INVALID_DRAFT');
});

test('the audit module never logs, echoes caller text or references future broker or vault producers', () => {
  const sources = ['../src/audit-ledger.ts', './audit-ledger.test.mjs', '../dist/audit-ledger.js']
    .map((path) => readFileSync(new URL(path, import.meta.url), 'utf8'));
  for (const text of sources) {
    assert.doesNotMatch(text, /console\.|process\.stdout|process\.stderr/);
    assert.doesNotMatch(text, /from '\.\/(vault|broker|authorization)/);
  }
});