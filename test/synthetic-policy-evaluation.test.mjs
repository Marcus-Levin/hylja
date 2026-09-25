import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decidePolicy } from '../dist/policy.js';
import { createInMemorySinkCapture } from '../dist/evaluation.js';
import { SYNTHETIC_SCOPE_REFERENCES, runSyntheticScopeContract } from '../dist/synthetic-scope-contract.js';
import {
  REAL_SYNTHETIC_POLICY_ADAPTER, makeSyntheticPolicyFixture, runSyntheticPolicyInvariants,
} from '../dist/synthetic-policy-evaluation.js';

const get = (rows, id) => rows.find((row) => row.id === id);

test('real #4 decision adapter exercises A/B positive, held, denied, route, bundle and composer cases', async () => {
  const rows = await runSyntheticPolicyInvariants(REAL_SYNTHETIC_POLICY_ADAPTER);
  assert.ok(rows.length >= 40, `real adapter must execute the full contract, not an empty matrix: ${rows.length}`);
  assert.equal(rows.every((row) => row.outcome === 'pass'), true);
  for (const [id, state] of [
    ['a-public', 'SELECTED'], ['b-public', 'SELECTED'],
    ['a-confidential', 'SELECTED'], ['b-confidential', 'SELECTED'],
    ['a-credential', 'SELECTED'], ['b-credential', 'SELECTED'],
    ['a-restricted', 'HELD'], ['b-restricted', 'HELD'],
    ['a-unresolved', 'DENIED'], ['b-unresolved', 'DENIED'],
    ['a-explicit-block', 'DENIED'], ['b-explicit-block', 'DENIED'],
    ['a-wrong-tenant', 'DENIED'], ['b-wrong-tenant', 'DENIED'],
    ['a-missing-profile', 'DENIED'], ['b-missing-profile', 'DENIED'],
    ['a-route-mismatch', 'DENIED'], ['b-route-mismatch', 'DENIED'],
    ['a-bundle-swap', 'DENIED'], ['b-bundle-swap', 'DENIED'],
    ['a-classification-swap', 'DENIED'], ['b-classification-swap', 'DENIED'],
    ['a-review-own-candidate', 'SELECTED'], ['b-review-own-candidate', 'SELECTED'],
    ['a-review-other-candidate', 'HELD'], ['b-review-other-candidate', 'HELD'],
    ['a-review-other-tenant', 'HELD'], ['b-review-other-tenant', 'HELD'],
    ['a-review-stale-route', 'DENIED'], ['b-review-stale-route', 'DENIED'],
  ]) assert.equal(get(rows, id)?.expected, state, `${id}: state must be independently specified`);
  assert.equal(JSON.stringify(rows).includes('tenant-a.invalid'), false, 'findings only contain safe test IDs');
});

test('the same policy invariant contract rejects an intentionally PERMISSIVE synthetic double', async () => {
  const permissive = {
    decide: () => ({ version: 1, state: 'SELECTED', treatment: 'KEEP',
      reason: 'synthetic-permissive', decisionRef: '0'.repeat(64) }),
    reviewed: () => ({ version: 1, state: 'SELECTED', treatment: 'KEEP',
      reason: 'synthetic-permissive', decisionRef: '0'.repeat(64) }),
  };
  const rows = await runSyntheticPolicyInvariants(permissive);
  assert.ok(rows.length >= 40);
  const failures = rows.filter((row) => row.outcome === 'fail');
  assert.ok(failures.length > 20, `permissive double must fail many policy and review checks: ${failures.length}`);
  assert.equal(get(rows, 'a-public').outcome, 'pass', 'negative suite retains a positive control');
  for (const name of ['a-wrong-tenant', 'b-route-mismatch', 'a-bundle-swap',
    'a-classification-swap', 'a-review-other-candidate', 'b-review-other-tenant']) {
    assert.equal(get(rows, name).outcome, 'fail', `${name} must expose permissiveness`);
  }
});

test('throwing synthetic policy adapters cannot fake denial or echo planted values', async () => {
  const planted = 'synthetic-private-plant.invalid';
  const rows = await runSyntheticPolicyInvariants({
    decide() { throw Error(planted); },
    reviewed() { throw Error(planted); },
  });
  assert.ok(rows.length >= 40);
  assert.equal(rows.every((row) => row.outcome === 'fail'), true);
  assert.equal(JSON.stringify(rows).includes(planted), false);
});

test('selected local USE policy treatment is not DISPLAY/EXPORT authorization or a byte send', async () => {
  const { request, boundary, bundle } = makeSyntheticPolicyFixture('a', 'local-use');
  const selected = decidePolicy(request, boundary, bundle);
  assert.equal(selected.state, 'SELECTED');
  assert.equal(selected.treatment, 'KEEP');
  for (const key of ['authorized', 'allow', 'canResolve', 'grant', 'payload', 'plaintext', 'bytes', 'effect']) {
    assert.equal(Object.hasOwn(selected, key), false, `${key} cannot be a policy capability`);
  }
  const issued = new Map(SYNTHETIC_SCOPE_REFERENCES.map((item) => [item.ref, item]));
  const scoped = {
    canResolve: (attempt) => {
      const stored = issued.get(attempt.ref);
      return !!stored && Object.keys(stored).every((key) => stored[key] === attempt[key]);
    },
    authorize(attempt) { return attempt.action === 'USE' && this.canResolve(attempt); },
  };
  const contract = await runSyntheticScopeContract(scoped);
  assert.ok(contract.length >= 100);
  assert.equal(contract.every((row) => row.outcome === 'pass'), true);
  const token = SYNTHETIC_SCOPE_REFERENCES.find((item) => item.kind === 'token' && item.tenantId === 'tenant-a.invalid');
  assert.equal(scoped.authorize({ ...token, action: 'USE' }), true);
  assert.equal(scoped.authorize({ ...token, action: 'DISPLAY' }), false);
  assert.equal(scoped.authorize({ ...token, action: 'EXPORT' }), false);
  assert.equal(scoped.authorize({ ...token, tenantId: 'tenant-b.invalid', action: 'USE' }), false);
  assert.equal(createInMemorySinkCapture().forCase('synthetic-no-send').length, 0);
});
