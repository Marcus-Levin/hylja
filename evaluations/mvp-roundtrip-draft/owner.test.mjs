// Public synthetic draft evidence only: no accepted policy, authentication or effects.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createDraftOwner } from './owner.mjs';
import { transformDraft } from './transform.mjs';

const encode = (value) => JSON.stringify(value);
const original = 'SYNTHETIC-ASSET-A1';
const context = { version: 1, scope: 'SYNTHETIC-SCOPE-A', session: 'SYNTHETIC-SESSION-A', context: 'SYNTHETIC-CONTEXT-A' };
const config = { version: 1, purpose: 'SYNTHETIC-LOG-SUMMARY', operation: 'DISPLAY', destination: 'SYNTHETIC-DISPLAY-A', adminDestination: 'SYNTHETIC-ADMIN-A', createdAt: 10, expiresAt: 100, revision: 1 };
const request = { ...context, purpose: config.purpose, operation: config.operation, destination: config.destination, revision: 1 };
const admin = { ...context, administrativePurpose: 'SYNTHETIC-OWNER-LIFECYCLE', operation: 'REVOKE', destination: config.adminDestination, revision: 1 };
function reference(c = context, value = original) {
  const result = transformDraft(encode(c), encode({ version: 1, task: 'SUMMARIZE_FAILURES', asset: value }),
    encode({ version: 1, events: [{ asset: value, tick: 0, level: 'INFO', code: 'START' }] }));
  assert.equal(result.status === 'TRANSFORMED', true, 'qualified unchanged S1 dependency');
  return result.references[0];
}
function owned(cfg = config, c = context, value = original) {
  const result = createDraftOwner(encode(cfg), encode(c), value);
  assert.equal(result.status === 'OWNED', true, 'valid one-pair fixture must create a draft owner');
  return result.owner;
}
function refused(result) {
  assert.equal(encode(result) === '{"status":"REFUSED","reason":"OWNER_REFUSED"}', true, 'fixed atomic non-echoing refusal');
  assert.equal(Object.isFrozen(result), true);
}
function displayed(result, value = original) {
  assert.equal(result.status === 'DISPLAYED' && result.value === value, true, 'exact one-marker restoration');
  assert.equal(Object.keys(result).sort().join(',') === 'status,value', true);
  assert.equal(Object.isFrozen(result), true);
}

test('valid independent fixture DISPLAY restores exactly the one S1 original', () => {
  const owner = owned();
  displayed(owner.displayOne(reference(), encode(request), 10));
  displayed(owner.displayOne(reference(), encode(request), 99));
});

test('frozen bound handle has only two methods and no original or bulk lookup surface', () => {
  const result = createDraftOwner(encode(config), encode(context), original);
  assert.equal(result.status === 'OWNED', true);
  assert.equal(Object.isFrozen(result) && Object.isFrozen(result.owner), true);
  assert.equal(Object.keys(result).sort().join(',') === 'owner,status', true);
  assert.equal(Object.keys(result.owner).sort().join(',') === 'displayOne,revoke', true);
  assert.equal(encode(result).includes(original), false);
  const display = result.owner.displayOne;
  displayed(display.call({ value: 'SYNTHETIC-ASSET-B2' }, reference(), encode(request), 10));
  refused(display([reference()], encode(request), 10));
  refused(display([reference(), reference(context, 'SYNTHETIC-ASSET-B2')], encode(request), 10));
});

test('constructor rejects malformed, noncanonical, nonprimitive and oversized inputs without coercion', () => {
  let touched = false;
  const hostile = { toString() { touched = true; throw new Error('synthetic sentinel'); } };
  for (const bad of [undefined, null, 0, hostile, '', '{', '[]', 'null', '\u00e9', '\ud800', 'x'.repeat(513)]) {
    refused(createDraftOwner(bad, encode(context), original));
    refused(createDraftOwner(encode(config), bad, original));
  }
  for (const bad of [null, undefined, hostile, 1, '', 'SYNTHETIC-ASSET-', 'SYNTHETIC-ASSET-a', 'SYNTHETIC-ASSET-' + 'A'.repeat(65),
    original + '\n', 'prefix' + original, 'ordinary.example.invalid', reference()]) {
    refused(createDraftOwner(encode(config), encode(context), bad));
  }
  assert.equal(touched, false);
  for (const value of [config, context]) for (const bad of [' ' + encode(value), encode(value) + '\n', encode(value) + '{}',
    encode(value).replace('SYNTHETIC', '\\u0053YNTHETIC'), encode(value).replace('"version":1', '"version":2,"version":1'),
    encode(value).replace('"version":1', '"version":1e0')]) {
    if (value === config) refused(createDraftOwner(bad, encode(context), original));
    else refused(createDraftOwner(encode(config), bad, original));
  }
});

test('constructor closed schema, destination, clock and version boundaries', () => {
  for (const bad of [{ ...config, extra: original }, { ...config, purpose: 'OTHER' }, { ...config, operation: 'USE' },
    { ...config, destination: 'SYNTHETIC-DISPLAY-' }, { ...config, adminDestination: 'SYNTHETIC-DISPLAY-A' },
    { ...config, destination: { value: config.destination } }, { ...config, revision: 2 }, { ...config, version: '1' },
    { ...config, createdAt: -1 }, { ...config, createdAt: 0.5 }, { ...config, expiresAt: 1000001 },
    { ...config, expiresAt: config.createdAt }, { ...config, expiresAt: 0 }, { ...config, createdAt: undefined }]) {
    refused(createDraftOwner(encode(bad), encode(context), original));
  }
  for (const bad of [{ ...context, extra: original }, { ...context, scope: 'SYNTHETIC-SCOPE-' },
    { ...context, session: { value: context.session } }, { ...context, context: undefined }, { ...context, version: 2 }]) {
    refused(createDraftOwner(encode(config), encode(bad), original));
  }
  const c = { ...context, scope: 'SYNTHETIC-SCOPE-' + 'Z'.repeat(32) };
  const cfg = { ...config, destination: 'SYNTHETIC-DISPLAY-' + 'Z'.repeat(32), createdAt: 0, expiresAt: 1000000 };
  const value = 'SYNTHETIC-ASSET-' + 'Z'.repeat(64);
  displayed(owned(cfg, c, value).displayOne(reference(c, value), encode({ ...request, ...c, destination: cfg.destination }), 999999), value);
  const reordered = Object.fromEntries(Object.entries(config).reverse());
  displayed(owned(reordered).displayOne(reference(), encode(Object.fromEntries(Object.entries(request).reverse())), 10));
});

test('unknown, foreign, forged and prefix references never restore another original', () => {
  const owner = owned();
  for (const candidate of ['', 'DRAFT-REF-' + '0'.repeat(64), reference().slice(0, -1), reference() + 'x', reference().toUpperCase(),
    reference(context, 'SYNTHETIC-ASSET-B2'), reference({ ...context, scope: 'SYNTHETIC-SCOPE-B' }),
    reference({ ...context, session: 'SYNTHETIC-SESSION-B' }), reference({ ...context, context: 'SYNTHETIC-CONTEXT-B' }), original]) {
    refused(owner.displayOne(candidate, encode(request), 10));
  }
  displayed(owner.displayOne(reference(), encode(request), 10));
});

test('each independent request authority component refuses mismatches and response-shaped grants', () => {
  const owner = owned();
  for (const bad of [{ ...request, purpose: 'OTHER' }, { ...request, operation: 'USE' }, { ...request, operation: 'EXPORT' },
    { ...request, destination: 'SYNTHETIC-DISPLAY-B' }, { ...request, scope: 'SYNTHETIC-SCOPE-B' },
    { ...request, session: 'SYNTHETIC-SESSION-B' }, { ...request, context: 'SYNTHETIC-CONTEXT-B' },
    { ...request, revision: 0 }, { ...request, revision: 2 }, { ...request, revision: '1' }, { ...request, version: 2 },
    { ...request, extra: original }, { ...request, purpose: { value: request.purpose } }, { ...request, context: undefined },
    { version: 1, summary: 'FAILURES_FOUND', reference: reference(), errorCount: 1 },
    { ...request, grant: 'DISPLAY' }]) refused(owner.displayOne(reference(), encode(bad), 10));
  for (const bad of ['{', '[]', 'null', '', 'x'.repeat(513), encode(request) + ' ',
    encode(request).replace('"revision":1', '"revision":0,"revision":1'), encode(request).replace('SYNTHETIC', '\\u0053YNTHETIC'),
    encode(request).replace('"revision":1', '"revision":1e0'), encode(request).replace('"revision":1', '"revision":-0')]) {
    refused(owner.displayOne(reference(), bad, 10));
  }
  displayed(owner.displayOne(reference(), encode(request), 10));
});

test('hostile caller objects are never inspected as candidate, request, clock or admin authority', () => {
  let touched = false;
  const hostile = new Proxy({}, { get() { touched = true; throw new Error('synthetic sentinel'); }, ownKeys() { touched = true; throw new Error('synthetic sentinel'); } });
  const owner = owned();
  refused(owner.displayOne(hostile, encode(request), 10));
  refused(owner.displayOne(reference(), hostile, 10));
  refused(owner.revoke(hostile, 10));
  refused(owner.displayOne(reference(), encode(request), hostile));
  refused(owner.displayOne(reference(), encode(request), 10));
  assert.equal(touched, false);
});

test('expiry equality latches even for denied input; rollback and admin replay cannot resurrect', () => {
  const owner = owned();
  displayed(owner.displayOne(reference(), encode(request), 99));
  refused(owner.displayOne('unknown', '{', 100));
  for (const now of [99, 100, 101, 10]) {
    refused(owner.displayOne(reference(), encode(request), now));
    refused(owner.revoke(encode(admin), now));
  }
});

test('invalid clocks and rollback have restrictive terminal results without implicit deadlines', () => {
  for (const now of [undefined, null, '10', NaN, Infinity, -1, 0.1, 1000001, 9, -0]) {
    const owner = owned();
    refused(owner.displayOne(reference(), encode(request), now));
    refused(owner.displayOne(reference(), encode(request), 10));
    refused(owner.revoke(encode(admin), 10));
  }
  const owner = owned();
  refused(owner.displayOne('unknown', encode(request), 50));
  refused(owner.displayOne(reference(), encode(request), 49));
  refused(owner.displayOne(reference(), encode(request), 50));
  const revokedByInvalidClock = owned();
  refused(revokedByInvalidClock.revoke(encode(admin), NaN));
  refused(revokedByInvalidClock.displayOne(reference(), encode(request), 10));
});

test('separate closed admin request revokes monotonically with current revision and idempotency', () => {
  const owner = owned();
  for (const bad of [request, { ...admin, operation: 'DISPLAY' }, { ...admin, operation: 'USE' },
    { ...admin, administrativePurpose: config.purpose }, { ...admin, destination: config.destination },
    { ...admin, scope: 'SYNTHETIC-SCOPE-B' }, { ...admin, session: 'SYNTHETIC-SESSION-B' },
    { ...admin, context: 'SYNTHETIC-CONTEXT-B' }, { ...admin, revision: 2 }, { ...admin, extra: original },
    { ...admin, revision: undefined }, { ...admin, operation: { value: 'REVOKE' } }]) {
    refused(owner.revoke(encode(bad), 10));
  }
  for (const bad of ['{', 'x'.repeat(513), ' ' + encode(admin), encode(admin).replace('"revision":1', '"revision":0,"revision":1'),
    encode(admin).replace('SYNTHETIC', '\\u0053YNTHETIC')]) refused(owner.revoke(bad, 10));
  displayed(owner.displayOne(reference(), encode(request), 10));
  const result = owner.revoke(encode(admin), 20);
  assert.equal(encode(result) === '{"status":"REVOKED","revision":2}' && Object.isFrozen(result), true);
  refused(owner.revoke(encode(admin), 20));
  assert.equal(owner.revoke(encode({ ...admin, revision: 2 }), 20).status === 'REVOKED', true);
  refused(owner.displayOne(reference(), encode({ ...request, revision: 2 }), 20));
  refused(owner.revoke(encode({ ...admin, revision: 2 }), 19));
  assert.equal(owner.revoke(encode({ ...admin, revision: 2 }), 100).status === 'REVOKED', true);
  refused(owner.displayOne(reference(), encode(request), 100));
});

test('1000 bounded generated identities and lifecycle sequences keep scope and terminal isolation', () => {
  for (let i = 0; i < 1000; i += 1) {
    const suffix = i.toString(36).toUpperCase();
    const value = 'SYNTHETIC-ASSET-' + suffix;
    const c = { ...context, context: 'SYNTHETIC-CONTEXT-' + suffix };
    const r = { ...request, ...c };
    const a = { ...admin, ...c };
    const token = reference(c, value);
    const owner = owned(config, c, value);
    displayed(owner.displayOne(token, encode(r), 10), value);
    displayed(owned(config, c, value).displayOne(token, encode(r), 10), value);
    for (const [key, replacement] of [['scope', 'SYNTHETIC-SCOPE-ZZ'], ['session', 'SYNTHETIC-SESSION-ZZ'], ['context', 'SYNTHETIC-CONTEXT-ZZ' + suffix]]) {
      const foreign = { ...c, [key]: replacement };
      refused(owner.displayOne(reference(foreign, value), encode(r), 10));
      refused(owner.displayOne(token, encode({ ...r, [key]: replacement }), 10));
    }
    refused(owner.displayOne(reference(c, value + 'Z'), encode(r), 10));
    if (i % 3 === 0) {
      assert.equal(owner.revoke(encode(a), 20).status === 'REVOKED', true);
      refused(owner.revoke(encode(a), 20));
    } else if (i % 3 === 1) refused(owner.displayOne(token, encode(r), 100));
    else {
      refused(owner.displayOne('unknown', encode(r), 20));
      refused(owner.displayOne(token, encode(r), 19));
    }
    for (const now of [10, 20, 99, 100, 101]) refused(owner.displayOne(token, encode(r), now));
  }
});
