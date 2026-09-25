import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  REFERENCE_KINDS, SYNTHETIC_SCOPE_REFERENCES, generateSyntheticScopeVectors,
  runSyntheticScopeContract,
} from '../dist/synthetic-scope-contract.js';

// Minimal scoped synthetic double: no encryption, persistent records, keys, network or broker.
const fixtures = new Map(SYNTHETIC_SCOPE_REFERENCES.map((item) => [item.ref, item]));
const sameScope = (item, request) => !!item && Object.keys(item).every((key) => item[key] === request[key]);
const scopedDouble = {
  canResolve: async (request) => sameScope(fixtures.get(request.ref), request),
  authorize: async (request) => request.action === 'USE' && sameScope(fixtures.get(request.ref), request),
};
const permissiveDouble = { canResolve: () => true, authorize: () => true };

test('runner tests real A/B candidate/entity/token/ciphertext/cache/synthetic identity scope and authorization', async () => {
  assert.deepEqual(REFERENCE_KINDS, ['candidate', 'entity', 'token', 'ciphertext', 'cache', 'synthetic-identity']);
  assert.equal(SYNTHETIC_SCOPE_REFERENCES.length, 12);
  const result = await runSyntheticScopeContract(scopedDouble);
  assert.ok(result.length >= 100, 'run the contract, not a vacuous placeholder');
  assert.ok(result.some((item) => item.expected === 'allow' && item.boundary === 'resolution'));
  assert.ok(result.some((item) => item.expected === 'deny' && item.boundary === 'authorization'));
  assert.equal(result.every((item) => item.outcome === 'pass'), true);
  for (const kind of REFERENCE_KINDS) {
    assert.ok(result.some((item) => item.id.includes(kind) && item.id.includes('cross-tenant')));
    assert.ok(result.some((item) => item.id.includes(kind) && item.id.includes('wrong-project')));
    assert.ok(result.some((item) => item.id.includes(kind) && item.id.includes('wrong-session')));
    assert.ok(result.some((item) => item.id.includes(kind) && item.id.includes('forged-provenance')));
  }
});

test('the same contract fails conspicuously on an intentionally PERMISSIVE implementation', async () => {
  const findings = await runSyntheticScopeContract(permissiveDouble);
  const failures = findings.filter((item) => item.outcome === 'fail');
  assert.ok(failures.length > 60, `permissive implementation must fail many denial checks: ${failures.length}`);
  assert.ok(failures.some((item) => item.boundary === 'resolution' && item.id.includes('cross-tenant')));
  assert.ok(failures.some((item) => item.boundary === 'authorization' && item.id.includes('forged-provenance')));
  assert.ok(failures.some((item) => item.id.includes('cross-tenant-exception')));
  assert.ok(failures.some((item) => item.id.includes('display-not-use')));
  assert.ok(failures.some((item) => item.id.includes('export-not-display')));
  assert.equal(JSON.stringify(findings).includes('synthetic-token-a.invalid'), false, 'only opaque test IDs in findings');
});

test('errors or non-boolean results cannot masquerade as denied authorization', async () => {
  const findings = await runSyntheticScopeContract({
    canResolve: () => { throw Error('synthetic-private-plant.invalid'); },
    authorize: async () => undefined,
  });
  assert.ok(findings.length >= 100, 'errors must not short-circuit contract execution');
  assert.equal(findings.every((item) => item.outcome === 'fail'), true);
  assert.equal(JSON.stringify(findings).includes('synthetic-private-plant.invalid'), false);
});

test('throwing boundary accessors and Proxy traps never echo planted values through contract errors', async () => {
  const planted = 'synthetic-private-plant.invalid';
  for (const boundary of [
    { get canResolve() { throw Error(planted); }, authorize: () => false },
    new Proxy({ canResolve: () => false, authorize: () => false }, {
      get(target, key) { if (key === 'authorize') throw Error(planted); return Reflect.get(target, key); },
    }),
  ]) {
    let findings;
    try { findings = await runSyntheticScopeContract(boundary); } catch (error) {
      assert.ok(error instanceof TypeError);
      assert.equal(error.message.includes(planted), false);
    }
    if (findings) {
      assert.ok(findings.length >= 100);
      assert.ok(findings.some((item) => item.outcome === 'fail'));
      assert.equal(JSON.stringify(findings).includes(planted), false);
    }
  }
});

test('boundary methods are snapshotted once before running vectors, not re-read by malicious getters', async () => {
  let resolutionReads = 0;
  let authorizationReads = 0;
  const boundary = {
    get canResolve() { resolutionReads++; return scopedDouble.canResolve; },
    get authorize() { authorizationReads++; return scopedDouble.authorize; },
  };
  const findings = await runSyntheticScopeContract(boundary);
  assert.equal(findings.every((item) => item.outcome === 'pass'), true);
  assert.equal(resolutionReads, 1);
  assert.equal(authorizationReads, 1);
});

test('deterministic generator varies wrong scopes, provenance and tenant, including exception claims', () => {
  const a = generateSyntheticScopeVectors(SYNTHETIC_SCOPE_REFERENCES, 789, 128);
  const b = generateSyntheticScopeVectors(SYNTHETIC_SCOPE_REFERENCES, 789, 128);
  const c = generateSyntheticScopeVectors(SYNTHETIC_SCOPE_REFERENCES, 790, 128);
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, c);
  assert.equal(a.length, 128);
  assert.equal(a.every((vector) => !vector.expectedResolution && !vector.expectedAuthorization), true);
  assert.ok(a.some((item) => item.id.includes('cross-tenant')));
  assert.ok(a.some((item) => item.id.includes('wrong-session')));
  assert.ok(a.some((item) => item.id.includes('forged-provenance')));
  assert.ok(a.some((item) => item.attempt.exception?.crossTenant));
  for (const count of [-1, 257, 1.5]) assert.throws(() => generateSyntheticScopeVectors(
    SYNTHETIC_SCOPE_REFERENCES, 1, count), TypeError);
  assert.throws(() => generateSyntheticScopeVectors(SYNTHETIC_SCOPE_REFERENCES, 0, 8), TypeError);
});

test('scope references snapshot bounded array descriptors before any Proxy length/map/index traps', () => {
  const values = [...SYNTHETIC_SCOPE_REFERENCES];
  let lengthReads = 0;
  let visited = 0;
  const planted = 'synthetic-private-plant.invalid';
  const changingLength = new Proxy(values, {
    get(target, key) {
      if (key === 'length') return ++lengthReads < 3 ? target.length : 100_000;
      if (typeof key === 'string' && /^(0|[1-9][0-9]*)$/u.test(key)) {
        if (++visited > 64) throw Error(planted);
        return target[Number(key) % target.length];
      }
      return Reflect.get(target, key);
    },
    has(target, key) { return typeof key === 'string' && /^(0|[1-9][0-9]*)$/u.test(key) || Reflect.has(target, key); },
  });
  let vectors;
  try { vectors = generateSyntheticScopeVectors(changingLength, 789, 12); } catch (error) {
    assert.ok(error instanceof TypeError);
    assert.equal(error.message.includes(planted), false);
  }
  assert.ok(visited <= 32, `bounded fixture must not visit ${visited} proxy indices`);
  assert.ok(lengthReads <= 1, `bounded fixture must not re-read changing length ${lengthReads} times`);
  if (vectors) assert.equal(vectors.length, 12);
  const withAccessor = [...values];
  Object.defineProperty(withAccessor, '0', { get() { throw Error(planted); }, enumerable: true });
  assert.throws(() => generateSyntheticScopeVectors(withAccessor, 789, 12),
    (error) => error instanceof TypeError && !error.message.includes(planted));
  let mapCalled = 0;
  const withOverride = [...values];
  withOverride.map = () => { mapCalled++; throw Error(planted); };
  assert.throws(() => generateSyntheticScopeVectors(withOverride, 789, 12), TypeError);
  assert.equal(mapCalled, 0);
});

test('custom synthetic fixture IDs cannot collide with generated wrong-scope attempts', async () => {
  const references = SYNTHETIC_SCOPE_REFERENCES.map((item, index) => ({
    ...item, ...(index === 0 ? { projectId: 'project-other-1024.invalid',
      ref: 'unknown-1024.invalid' } : {}),
  }));
  const issued = new Map(references.map((item) => [item.ref, item]));
  const double = {
    canResolve: (attempt) => sameScope(issued.get(attempt.ref), attempt),
    authorize: (attempt) => attempt.action === 'USE' && sameScope(issued.get(attempt.ref), attempt),
  };
  const findings = await runSyntheticScopeContract(double, references);
  assert.ok(findings.length >= 100);
  assert.equal(findings.every((item) => item.outcome === 'pass'), true);
});

test('a single all-true or all-false result is not sufficient: positives and negatives are both checked', async () => {
  const denied = await runSyntheticScopeContract({ canResolve: () => false, authorize: () => false });
  assert.ok(denied.some((item) => item.expected === 'allow' && item.outcome === 'fail'));
  const permitted = await runSyntheticScopeContract(permissiveDouble);
  assert.ok(permitted.some((item) => item.expected === 'deny' && item.outcome === 'fail'));
});
