import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createCandidateConfig, detectConfigured } from '../dist/configured-candidates.js';

// Synthetic-only scope labels and an invented dictionary term. This tests a pure handle seam,
// not authentication, atomic snapshots, array safety or a protected-egress boundary.
const A = Object.freeze({ tenantRef: 'synthetic-tenant-a.invalid', projectRef: 'synthetic-project-a.invalid' });
const B = Object.freeze({ tenantRef: 'synthetic-tenant-b.invalid', projectRef: 'synthetic-project-b.invalid' });
const term = 'Synthetic Snapshot Organisation';
const config = { terms: [{ term, semanticType: 'CUSTOMER_OR_PARTNER', sensitivity: 'CONFIDENTIAL' }] };
const fields = ['tenantRef', 'projectRef'];

function changingScope(mode, field, read) {
  const counts = { tenantRef: 0, projectRef: 0 };
  const access = (key) => {
    counts[key]++;
    return key === field ? read(counts[key]) : A[key];
  };
  const scope = mode === 'getter' ? Object.defineProperties({}, {
    tenantRef: { enumerable: true, get: () => access('tenantRef') },
    projectRef: { enumerable: true, get: () => access('projectRef') },
  }) : new Proxy({ ...A }, {
    get(target, key, receiver) {
      return fields.includes(key) ? access(key) : Reflect.get(target, key, receiver);
    },
  });
  return { scope, counts };
}

function construct(scope) {
  try { return { handle: createCandidateConfig(scope, config) }; }
  catch (error) { return { error }; }
}

function assertBound(handle) {
  const run = (scope) => detectConfigured({ text: term, inputRef: 'synthetic-snapshot-input.invalid', scope, config: handle });
  const same = run({ ...A });
  assert.equal(same.status === 'COMPLETE', true, 'the captured scope must retain a usable trusted handle');
  assert.equal(same.reasons.length, 0);
  assert.equal(same.candidates.length, 1);
  assert.equal(same.candidates[0].basis === 'DICTIONARY', true);
  assert.equal(same.candidates[0].sensitivity === 'CONFIDENTIAL', true);
  for (const field of fields) {
    const foreign = run({ ...A, [field]: B[field] });
    assert.equal(foreign.status === 'PARTIAL', true, 'each foreign scope must be refused by trusted handle lookup');
    assert.equal(foreign.reasons.length, 1);
    assert.equal(foreign.reasons[0] === 'CONFIG_SCOPE_MISMATCH', true);
    assert.equal(foreign.candidates.length, 0);
  }
}

function assertSafeError(error, hostile) {
  assert.equal(error instanceof TypeError, true);
  assert.equal(error === hostile, false, 'the boundary must mint a fresh fixed error');
  assert.equal(error.message === 'Invalid candidate configuration', true);
  assert.equal(Object.hasOwn(error, 'cause'), false);
  assert.equal(Object.hasOwn(error, 'planted'), false);
  assert.equal(String(error.stack).includes('synthetic-hostile-marker.invalid'), false);
}

for (const mode of ['getter', 'proxy']) {
  for (const field of fields) {
    test(`${mode} ${field}: finite A-to-B reads cannot retarget the handle`, () => {
      const { scope, counts } = changingScope(mode, field, (count) => count === 1 ? A[field] : B[field]);
      const result = construct(scope);
      assert.equal(Object.hasOwn(result, 'handle'), true);
      assertBound(result.handle);
      assert.equal(counts.tenantRef, 1);
      assert.equal(counts.projectRef, 1);
    });

    test(`${mode} ${field}: a valid first label is bound without reading a later malformed label`, () => {
      for (const later of [undefined, null, '', 42]) {
        const { scope, counts } = changingScope(mode, field, (count) => count === 1 ? A[field] : later);
        const result = construct(scope);
        assert.equal(Object.hasOwn(result, 'handle'), true);
        assertBound(result.handle);
        assert.equal(counts.tenantRef, 1);
        assert.equal(counts.projectRef, 1);
      }
    });

    test(`${mode} ${field}: a finite second-read throw is never reached`, () => {
      const { scope, counts } = changingScope(mode, field, (count) => {
        if (count === 1) return A[field];
        throw new Error('synthetic-hostile-marker.invalid');
      });
      const result = construct(scope);
      assert.equal(Object.hasOwn(result, 'handle'), true, 'accepted primitive scope labels must not be reread');
      assertBound(result.handle);
      assert.equal(counts.tenantRef, 1);
      assert.equal(counts.projectRef, 1);
    });

    test(`${mode} ${field}: malformed first labels refuse despite later valid labels`, () => {
      for (const first of [undefined, null, '', ' synthetic.invalid', 'synthetic.invalid\n', 'x'.repeat(257), 42, {}]) {
        const { scope, counts } = changingScope(mode, field, (count) => count === 1 ? first : A[field]);
        const firstAttempt = construct(scope);
        assert.equal(Object.hasOwn(firstAttempt, 'error'), true);
        assertSafeError(firstAttempt.error);
        assert.equal(counts[field], 1);
      }
    });

    test(`${mode} ${field}: finite hostile throws become fresh non-echoing errors`, () => {
      let hostileReads = 0;
      const hostile = Object.defineProperties({}, Object.fromEntries(
        ['message', 'stack', 'cause', 'planted'].map((key) => [key, { get() { hostileReads++; return 'synthetic-hostile-marker.invalid'; } }]),
      ));
      const { scope, counts } = changingScope(mode, field, () => { throw hostile; });
      const first = construct(scope);
      const second = construct(scope);
      assert.equal(Object.hasOwn(first, 'error'), true);
      assert.equal(Object.hasOwn(second, 'error'), true);
      assertSafeError(first.error, hostile);
      assertSafeError(second.error, hostile);
      assert.equal(first.error === second.error, false);
      assert.equal(counts[field], 2);
      assert.equal(hostileReads, 0);
    });
  }
}

test('ordinary, null-prototype, inherited and stable Proxy scopes retain compatibility', () => {
  for (const scope of [{ ...A }, Object.assign(Object.create(null), A), Object.create(A), new Proxy({ ...A }, {})]) {
    const result = construct(scope);
    assert.equal(Object.hasOwn(result, 'handle'), true);
    assertBound(result.handle);
  }
});

test('later caller mutation cannot retarget a stored handle', () => {
  const scope = { ...A };
  const result = construct(scope);
  assert.equal(Object.hasOwn(result, 'handle'), true);
  Object.assign(scope, B);
  assertBound(result.handle);
});
