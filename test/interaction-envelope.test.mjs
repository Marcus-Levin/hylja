import assert from 'node:assert/strict';
import { test } from 'node:test';
import { performance } from 'node:perf_hooks';
import {
  INTERACTION_OPERATIONS,
  createInteractionEnvelope,
  parseInteractionEnvelope,
  serializeInteractionEnvelope,
} from '../dist/interaction-envelope.js';

const operations = [
  'model.input', 'model.output', 'tool.call', 'tool.result',
  'mcp.list', 'mcp.resource', 'mcp.prompt', 'mcp.call', 'mcp.result',
  'file.list', 'file.read', 'file.search', 'file.write', 'file.diff',
  'shell.command', 'shell.stdout', 'shell.stderr',
  'skill.load', 'skill.resource', 'skill.execute',
  'memory.read', 'memory.write', 'web.request', 'web.response',
  'agent.handoff', 'agent.result',
];

// Stable throughout this test process: changing one field never incidentally changes proof timestamps.
const issuedForSuite = new Date(Date.now() - 1_000).toISOString();
const expiresForSuite = new Date(Date.now() + 4 * 60_000).toISOString();
// Every value is synthetic; only the separately supplied adapter/broker context is trusted.
function boundary({ principalId = 'principal-a.invalid', workloadId = 'workload-a.invalid',
  tenantId = 'tenant-a.invalid', projectId = 'project-a.invalid',
  sessionId = 'session-a.invalid', purpose = 'synthetic-evaluation',
  sourceZone = 'untrusted-input', sourceRef = 'source-a.example.invalid',
  destinationRef = 'https://sink-a.example.invalid/actual',
  destinationZone = 'external', profileId = 'profile-a.invalid',
  issuedAt = issuedForSuite, expiresAt = expiresForSuite } = {}) {
  return {
    authenticated: {
      subject: { principalId, workloadId },
      context: { tenantId, projectId, sessionId, purpose },
      identityProof: { ref: 'synthetic-proof:identity-a', issuedAt, expiresAt },
      requestProof: { ref: 'synthetic-proof:request-a', issuedAt, expiresAt },
    },
    observed: {
      source: { kind: 'tool-result', ref: sourceRef, trustZone: sourceZone },
      destination: { kind: 'model-api', ref: destinationRef, trustZone: destinationZone, profileId },
      sourceProof: { ref: 'synthetic-proof:source-a', issuedAt, expiresAt },
      routeProof: { ref: 'synthetic-proof:actual-route-a', issuedAt, expiresAt },
    },
  };
}

function draft(operation = 'model.input') {
  return {
    operation,
    payload: { text: 'synthetic task', nested: [null, true, 3] },
    representation: { mediaType: 'application/json', encodings: ['utf-8'] },
    metadata: {
      adapter: 'synthetic-gateway', provider: 'provider-a.invalid',
      model: 'model-a.invalid', correlationId: 'trace-a.invalid',
    },
  };
}

function alter(envelope, mutate) {
  const value = JSON.parse(serializeInteractionEnvelope(envelope));
  mutate(value);
  return JSON.stringify(value);
}

test('all 26 initial operation families round-trip as versioned normalized interactions', () => {
  assert.deepEqual(INTERACTION_OPERATIONS, operations);
  const trusted = boundary();
  for (const operation of operations) {
    const original = createInteractionEnvelope(draft(operation), trusted);
    const json = serializeInteractionEnvelope(original);
    const parsed = parseInteractionEnvelope(json, trusted);
    assert.deepEqual(parsed, original, operation);
    assert.equal(parsed.operation, operation);
    assert.equal(parsed.version, 1);
    assert.match(parsed.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    assert.equal(parsed.metadata.provider, 'provider-a.invalid');
    assert.equal(parsed.metadata.model, 'model-a.invalid');
    assert.equal(parsed.metadata.correlationId, 'trace-a.invalid');
    assert.equal('provider' in parsed, false);
    assert.equal('model' in parsed, false);
    assert.equal('correlationId' in parsed.context, false);
    assert.equal(parsed.destination.ref, trusted.observed.destination.ref);
    assert.equal(parsed.destination.profileId, trusted.observed.destination.profileId);
    assert.equal(parsed.provenance.length, 4);
  }
});

test('malformed, unknown, unversioned and extra policy fields fail before interpretation', () => {
  const trusted = boundary();
  const valid = createInteractionEnvelope(draft(), trusted);
  for (const bad of [
    '{', 'null', '[]', '"not an interaction"', '{}',
    alter(valid, (v) => { delete v.version; }),
    alter(valid, (v) => { v.version = 2; }),
    alter(valid, (v) => { v.operation = 'model.unsupported'; }),
    alter(valid, (v) => { v.destination.policy = 'allow'; }),
    alter(valid, (v) => { v.subject.isAdmin = true; }),
    alter(valid, (v) => { v.metadata.policy = 'CONTROL'; }),
    alter(valid, (v) => { v.occurredAt = 'not a timestamp'; }),
  ]) assert.throws(() => parseInteractionEnvelope(bad, trusted));
  assert.throws(() => createInteractionEnvelope({ ...draft(), destination: trusted.observed.destination }, trusted));
  assert.throws(() => createInteractionEnvelope({ ...draft(), provider: 'provider-a.invalid' }, trusted));
  assert.throws(() => createInteractionEnvelope({ ...draft(), payload: undefined }, trusted));
  assert.throws(() => createInteractionEnvelope({ ...draft(), payload: Number.NaN }, trusted));
});

test('malformed wire, extra keys and hostile objects never echo synthetic planted values in errors', () => {
  const planted = 'planted-private-synthetic-value.invalid';
  const trusted = boundary();
  const valid = createInteractionEnvelope(draft(), trusted);
  const malformed = `{"p":${planted}}`;
  const unexpected = alter(valid, (v) => { v[planted] = 'CONTROL'; });
  const nestedUnexpected = alter(valid, (v) => { v.context[planted] = 'CONTROL'; });
  const hostile = new Proxy(draft(), { ownKeys() { throw Error(`proxy ${planted}`); } });
  for (const attempt of [
    () => parseInteractionEnvelope(malformed, trusted),
    () => parseInteractionEnvelope(unexpected, trusted),
    () => parseInteractionEnvelope(nestedUnexpected, trusted),
    () => createInteractionEnvelope(hostile, trusted),
  ]) {
    let caught;
    try { attempt(); } catch (error) { caught = error; }
    assert.ok(caught instanceof Error, 'invalid input must be rejected');
    assert.equal(caught.message.includes(planted), false, 'no planted value in an error');
  }
});

test('a forged instance of a previously observed failure cannot echo planted data', () => {
  const planted = 'private-planted-synthetic.invalid';
  let sample;
  try { serializeInteractionEnvelope({}); } catch (error) { sample = error; }
  assert.ok(sample instanceof Error);
  const forged = new sample.constructor(planted);
  const input = new Proxy(draft(), { ownKeys() { throw forged; } });
  let result;
  try { createInteractionEnvelope(input, boundary()); } catch (error) { result = error; }
  assert.ok(result instanceof Error);
  assert.equal(result.message.includes(planted), false);
});

test('time-varying adapter objects cannot become bound unsupported operations or invalid streams', () => {
  const trusted = boundary();
  let operationReads = 0;
  const changingOperation = new Proxy(draft(), {
    get(target, property, receiver) {
      if (property === 'operation') return ++operationReads === 1 ? 'model.input' : 'forged.unsupported';
      return Reflect.get(target, property, receiver);
    },
  });
  const operation = createInteractionEnvelope(changingOperation, trusted);
  assert.equal(operation.operation, 'model.input');
  assert.deepEqual(parseInteractionEnvelope(serializeInteractionEnvelope(operation), trusted), operation);

  let finalReads = 0;
  const changingStream = new Proxy({ mode: 'stream', id: 'stream-a.invalid', sequence: 0,
    final: false, cancelled: false, inspection: 'unverified' }, {
    get(target, property, receiver) {
      if (property === 'final') return ++finalReads === 1 ? false : 'CONTROL';
      return Reflect.get(target, property, receiver);
    },
  });
  const fragment = createInteractionEnvelope({ ...draft('model.output'), stream: changingStream }, trusted);
  assert.equal(fragment.stream.final, false);
  assert.deepEqual(parseInteractionEnvelope(serializeInteractionEnvelope(fragment), trusted), fragment);
});

test('capped adapter keys are never enumerated a second time for descriptors', () => {
  const trusted = boundary();
  const input = draft();
  const realKeys = Reflect.ownKeys(input);
  const oversizedKeys = [...realKeys, ...Array.from({ length: 80_000 }, (_, i) => `synthetic-field-${i}`)];
  let enumerations = 0;
  let descriptorVisits = 0;
  const changingKeys = new Proxy(input, {
    ownKeys() { return ++enumerations === 1 ? realKeys : oversizedKeys; },
    getOwnPropertyDescriptor(target, key) {
      descriptorVisits++;
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  const bound = createInteractionEnvelope(changingKeys, trusted);
  assert.equal(enumerations, 1, 'the capped key list must be the only enumeration');
  assert.equal(descriptorVisits, realKeys.length, 'only captured keys may be inspected');
  assert.deepEqual(parseInteractionEnvelope(serializeInteractionEnvelope(bound), trusted), bound);

  let invalidDescriptorVisits = 0;
  const oversizedFirst = new Proxy(input, {
    ownKeys() { return oversizedKeys; },
    getOwnPropertyDescriptor(target, key) {
      invalidDescriptorVisits++;
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
  assert.throws(() => createInteractionEnvelope(oversizedFirst, trusted), TypeError);
  assert.equal(invalidDescriptorVisits, 0, 'an over-cap object must be rejected before descriptors');
});

test('authenticated identity/request and observed source/actual route come only from independent trusted context', () => {
  const trusted = boundary();
  const valid = createInteractionEnvelope(draft(), trusted);
  assert.deepEqual(valid.subject, trusted.authenticated.subject);
  assert.deepEqual(valid.context, trusted.authenticated.context);
  assert.deepEqual(valid.source, trusted.observed.source);
  assert.deepEqual(valid.destination, trusted.observed.destination);
  assert.deepEqual(valid.provenance.map(({ kind, authority }) => [kind, authority]), [
    ['identity', 'authenticated'], ['request', 'authenticated'],
    ['source', 'adapter-observed'], ['route', 'adapter-observed'],
  ]);
  assert.equal(Object.isFrozen(valid), true);
  assert.equal(Object.isFrozen(valid.payload.nested), true);
  assert.throws(() => { valid.destination.profileId = 'forged-profile.invalid'; }, TypeError);
  assert.throws(() => { valid.payload.nested.push('late change'); }, TypeError);
  assert.throws(() => serializeInteractionEnvelope({ ...valid }), TypeError);
});

test('absent, unauthenticated, stale, or malformed trusted evidence cannot be promoted by wire provenance', () => {
  const trusted = boundary();
  const valid = createInteractionEnvelope(draft(), trusted);
  const serialized = serializeInteractionEnvelope(valid);
  for (const path of ['authenticated', 'observed']) {
    const missing = structuredClone(trusted);
    delete missing[path];
    assert.throws(() => parseInteractionEnvelope(serialized, missing));
  }
  for (const proof of ['identityProof', 'requestProof', 'sourceProof', 'routeProof']) {
    const missing = structuredClone(trusted);
    delete missing[proof === 'identityProof' || proof === 'requestProof' ? 'authenticated' : 'observed'][proof];
    assert.throws(() => parseInteractionEnvelope(serialized, missing), proof);
  }
  for (const stale of [
    boundary({ issuedAt: '2000-01-01T00:00:00.000Z', expiresAt: '2000-01-01T00:01:00.000Z' }),
    boundary({ issuedAt: '2000-01-01T00:00:00.000Z', expiresAt: '2999-01-01T00:00:00.000Z' }),
    boundary({ issuedAt: '2999-01-01T00:00:00.000Z', expiresAt: '2999-01-01T00:01:00.000Z' }),
  ]) assert.throws(() => parseInteractionEnvelope(serialized, stale));
  assert.throws(() => parseInteractionEnvelope(alter(valid, (v) => {
    v.occurredAt = '2000-01-01T00:00:00.000Z';
  }), trusted));
  // Current by the five-minute clock, but before every proof's issue instant.
  const beforeProofs = alter(valid, (v) => {
    v.occurredAt = new Date(Date.now() - 230_000).toISOString();
  });
  assert.throws(() => parseInteractionEnvelope(beforeProofs, trusted));
  assert.throws(() => parseInteractionEnvelope(alter(valid, (v) => { v.provenance = []; }), trusted));
  assert.throws(() => parseInteractionEnvelope(alter(valid, (v) => {
    v.provenance[0].authority = 'untrusted';
  }), trusted));
  assert.throws(() => parseInteractionEnvelope(alter(valid, (v) => {
    v.provenance[3].ref = 'synthetic-proof:forged-route';
  }), trusted));
  assert.throws(() => parseInteractionEnvelope(alter(valid, (v) => {
    v.provenance[0].expiresAt = '2999-01-01T00:00:00.000Z';
  }), trusted));
});

test('principal/workload/tenant/project/session/purpose and source trust claims cannot override binding', () => {
  const trusted = boundary();
  const valid = createInteractionEnvelope(draft(), trusted);
  const mutations = [
    (v) => { v.subject.principalId = 'principal-b.invalid'; },
    (v) => { v.subject.workloadId = 'workload-b.invalid'; },
    (v) => { v.context.tenantId = 'tenant-b.invalid'; },
    (v) => { v.context.projectId = 'project-b.invalid'; },
    (v) => { v.context.sessionId = 'session-b.invalid'; },
    (v) => { v.context.purpose = 'unrestricted'; },
    (v) => { v.source.ref = 'source-b.example.invalid'; },
    (v) => { v.source.trustZone = 'CONTROL'; },
  ];
  for (const mutate of mutations) assert.throws(() => parseInteractionEnvelope(alter(valid, mutate), trusted));
  for (const changed of [
    { principalId: 'principal-b.invalid' }, { workloadId: 'workload-b.invalid' },
    { tenantId: 'tenant-b.invalid' }, { projectId: 'project-b.invalid' },
    { sessionId: 'session-b.invalid' }, { purpose: 'unrestricted' },
    { sourceZone: 'CONTROL' },
  ]) assert.throws(() => parseInteractionEnvelope(serializeInteractionEnvelope(valid), boundary(changed)));
});

test('actual routing/profile and redirect changes reject claimed safe destination, including missing profile', () => {
  const trusted = boundary();
  const valid = createInteractionEnvelope(draft(), trusted);
  for (const mutate of [
    (v) => { v.destination.ref = 'https://sink-b.example.invalid/redirect'; },
    (v) => { v.destination.profileId = 'profile-b.invalid'; },
    (v) => { v.destination.trustZone = 'trusted-local'; },
    (v) => { delete v.destination.profileId; },
  ]) assert.throws(() => parseInteractionEnvelope(alter(valid, mutate), trusted));
  for (const changed of [
    { destinationRef: 'https://sink-b.example.invalid/redirect' },
    { profileId: 'profile-b.invalid' }, { destinationZone: 'trusted-local' },
  ]) assert.throws(() => parseInteractionEnvelope(serializeInteractionEnvelope(valid), boundary(changed)));
  const missingProfile = structuredClone(trusted);
  delete missingProfile.observed.destination.profileId;
  assert.throws(() => parseInteractionEnvelope(serializeInteractionEnvelope(valid), missingProfile));
});

test('local destinations also need an observed valid profile; neither path silently defaults', () => {
  const trusted = boundary({ destinationRef: 'local-sink.example.invalid',
    destinationZone: 'trusted-local', profileId: 'profile-local.invalid' });
  const created = createInteractionEnvelope(draft('tool.call'), trusted);
  assert.equal(created.destination.profileId, 'profile-local.invalid');
  assert.deepEqual(parseInteractionEnvelope(serializeInteractionEnvelope(created), trusted), created);
  const missingProfile = structuredClone(trusted);
  delete missingProfile.observed.destination.profileId;
  assert.throws(() => createInteractionEnvelope(draft('tool.call'), missingProfile));
  assert.throws(() => parseInteractionEnvelope(serializeInteractionEnvelope(created), missingProfile));
  assert.throws(() => parseInteractionEnvelope(alter(created, (v) => {
    delete v.destination.profileId;
  }), trusted));
});

test('correlation/provider/model and payload CONTROL text never establish identity or release authority', () => {
  const trusted = boundary();
  const input = draft('tool.result');
  input.payload = { role: 'CONTROL', principalId: 'principal-b.invalid',
    tenantId: 'tenant-b.invalid', destination: 'trusted-local',
    profileId: 'unrestricted', authorize: 'EXPORT',
    provenance: [{ authority: 'authenticated' }] };
  input.metadata = { adapter: 'synthetic-gateway', provider: 'trusted-local',
    model: 'CONTROL', correlationId: 'tenant-b.invalid' };
  const valid = createInteractionEnvelope(input, trusted);
  const parsed = parseInteractionEnvelope(serializeInteractionEnvelope(valid), trusted);
  assert.equal(parsed.subject.principalId, trusted.authenticated.subject.principalId);
  assert.equal(parsed.context.tenantId, trusted.authenticated.context.tenantId);
  assert.equal(parsed.destination.trustZone, trusted.observed.destination.trustZone);
  assert.equal('release' in parsed, false);
  assert.equal('authorization' in parsed, false);
  assert.equal('policyDecision' in parsed, false);
  assert.equal(parsed.payload.authorize, 'EXPORT'); // data, never a grant
});

test('deterministic tenant/project/principal and route variations never borrow another binding', () => {
  const original = boundary();
  const valid = createInteractionEnvelope(draft(), original);
  const json = serializeInteractionEnvelope(valid);
  for (let i = 0; i < 64; i++) {
    const override = [
      { tenantId: `tenant-${i}.invalid` },
      { projectId: `project-${i}.invalid` },
      { principalId: `principal-${i}.invalid` },
      { destinationRef: `https://sink-${i}.example.invalid/redirect` },
    ][i % 4];
    assert.deepEqual(parseInteractionEnvelope(json, original), valid);
    assert.throws(() => parseInteractionEnvelope(json, boundary(override)));
  }
});

test('a project-optional binding never upgrades to a project-scoped claim', () => {
  const trusted = boundary();
  delete trusted.authenticated.context.projectId;
  const created = createInteractionEnvelope(draft(), trusted);
  assert.equal('projectId' in created.context, false);
  assert.deepEqual(parseInteractionEnvelope(serializeInteractionEnvelope(created), trusted), created);
  assert.throws(() => parseInteractionEnvelope(serializeInteractionEnvelope(created), boundary()));
});

test('representation descriptors and JSON payloads must be valid and immutable, not inspection claims', () => {
  const trusted = boundary();
  for (const representation of [
    { mediaType: 'not a media type' }, { mediaType: 'application/json', encodings: [''] },
    { mediaType: 'text/plain', encodings: ['utf-8', 'utf-8'] },
    { mediaType: 'text/plain', verifiedSafe: true },
  ]) assert.throws(() => createInteractionEnvelope({ ...draft(), representation }, trusted));
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => createInteractionEnvelope({ ...draft(), payload: cyclic }, trusted));
  const getter = {};
  Object.defineProperty(getter, 'secret', { enumerable: true, get() { throw Error('getter executed'); } });
  assert.throws(() => createInteractionEnvelope({ ...draft(), payload: getter }, trusted), TypeError);
});

test('wire limits count UTF-8 bytes and reject repeated acyclic branching input', () => {
  const trusted = boundary();
  const valid = createInteractionEnvelope(draft(), trusted);
  // Fewer than one million JS code units, but over one million UTF-8 bytes.
  const unicode = '☃'.repeat(350_000);
  assert.throws(() => createInteractionEnvelope({ ...draft(), payload: unicode }, trusted));
  assert.throws(() => parseInteractionEnvelope(alter(valid, (v) => { v.payload = unicode; }), trusted));
  let shared = { value: 'synthetic' };
  for (let i = 0; i < 18; i++) shared = { left: shared, right: shared };
  assert.throws(() => createInteractionEnvelope({ ...draft(), payload: shared }, trusted));
});

test('near-limit JSON fields round-trip while oversized key maps reject promptly', () => {
  const trusted = boundary();
  const fields = (count) => Object.fromEntries(Array.from({ length: count }, (_, i) => [`k${i.toString(36)}`, i % 2]));
  const nearLimit = createInteractionEnvelope({ ...draft(), payload: fields(9_800) }, trusted);
  assert.deepEqual(parseInteractionEnvelope(serializeInteractionEnvelope(nearLimit), trusted), nearLimit);

  // Compact synthetic JSON stays under the byte limit but exceeds the object-key cap.
  const valid = createInteractionEnvelope(draft(), trusted);
  const oversizedWire = alter(valid, (v) => { v.payload = fields(80_000); });
  assert.ok(Buffer.byteLength(oversizedWire, 'utf8') < 1_048_576);
  const started = performance.now();
  assert.throws(() => parseInteractionEnvelope(oversizedWire, trusted));
  assert.ok(performance.now() - started < 4_000, 'oversized key maps must not require quadratic validation');
});

test('stream fragments require contiguous order, stable trust context, and only unverified inspection state', () => {
  const trusted = boundary();
  const fragment = (sequence, extra = {}) => ({
    ...draft('model.output'), payload: `synthetic fragment ${sequence}`,
    stream: { mode: 'stream', id: 'stream-a.invalid', sequence, final: false,
      cancelled: false, inspection: 'unverified', ...extra },
  });
  const first = createInteractionEnvelope(fragment(0), trusted);
  const second = createInteractionEnvelope(fragment(1), trusted, first);
  const final = createInteractionEnvelope(fragment(2, { final: true }), trusted, second);
  assert.deepEqual(parseInteractionEnvelope(serializeInteractionEnvelope(second), trusted, first), second);
  assert.throws(() => createInteractionEnvelope(fragment(1), trusted));
  assert.throws(() => createInteractionEnvelope(fragment(2), trusted, first));
  assert.throws(() => createInteractionEnvelope(fragment(0), trusted, first));
  assert.throws(() => createInteractionEnvelope(fragment(3), trusted, final));
  assert.throws(() => createInteractionEnvelope(fragment(0, { inspection: 'released' }), trusted));
  assert.throws(() => createInteractionEnvelope(fragment(0, { final: true, cancelled: true }), trusted));
  assert.throws(() => createInteractionEnvelope(fragment(1, { id: 'stream-b.invalid' }), trusted, first));
  for (const changed of [
    { tenantId: 'tenant-b.invalid' }, { projectId: 'project-b.invalid' },
    { principalId: 'principal-b.invalid' }, { sourceZone: 'CONTROL' },
    { destinationRef: 'https://sink-b.example.invalid/redirect' },
    { profileId: 'profile-b.invalid' },
  ]) assert.throws(() => createInteractionEnvelope(fragment(1), boundary(changed), first));
  const cancelled = createInteractionEnvelope(fragment(1, { cancelled: true }), trusted, first);
  assert.throws(() => createInteractionEnvelope(fragment(2), trusted, cancelled));
  assert.throws(() => parseInteractionEnvelope(alter(second, (v) => {
    v.stream.sequence = 7;
  }), trusted, first));
});
