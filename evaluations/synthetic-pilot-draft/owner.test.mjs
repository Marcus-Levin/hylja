// PROPOSED / ISOLATED / PUBLIC_DRAFT_ONLY: public pure component evidence only.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from './owner.mjs';
import { derivePilotReference } from './transform.mjs';

const { createPilotOwner } = api;
const encode = (value) => JSON.stringify(value);
const original = 'SYNTHETIC-ASSET-A1';
const context = { version: 1, scope: 'SYNTHETIC-SCOPE-A', session: 'SYNTHETIC-SESSION-A', context: 'SYNTHETIC-CONTEXT-A' };
const config = { version: 1, displayPurpose: 'SYNTHETIC-PILOT-RESULT', displayDestination: 'SYNTHETIC-DISPLAY-A', adminPurpose: 'SYNTHETIC-OWNER-LIFECYCLE', adminDestination: 'SYNTHETIC-ADMIN-A', createdAt: 10, expiresAt: 100, revision: 1 };
const requestFor = (c = context, cfg = config, rev = 1, admin = false) => ({
  version: 1, scope: c.scope, session: c.session, context: c.context,
  purpose: admin ? cfg.adminPurpose : cfg.displayPurpose, operation: admin ? 'REVOKE' : 'DISPLAY',
  destination: admin ? cfg.adminDestination : cfg.displayDestination, revision: rev,
});
const request = requestFor();
const admin = requestFor(context, config, 1, true);
function reference(c = context, value = original) {
  const result = derivePilotReference(encode(c), value);
  assert.equal(result.status === 'DERIVED', true, 'reviewed P1 derivation prerequisite');
  return result.reference;
}
function owned(cfg = config, c = context, value = original) {
  const result = createPilotOwner(encode(cfg), encode(c), value);
  assert.equal(result.status === 'OWNED', true, 'new positive one-reference owner behavior');
  return result;
}
function refused(result) {
  assert.equal(encode(result) === '{"status":"REFUSED","reason":"PILOT_OWNER_REFUSED"}', true, 'fixed atomic non-echoing refusal');
  assert.equal(Object.isFrozen(result), true);
}
function displayed(result, value = original) {
  assert.equal(encode(result) === encode({ status: 'DISPLAYED', mode: 'PUBLIC_DRAFT_ONLY', original: value, revision: 1 }), true, 'exact one-marker display');
  assert.equal(Object.isFrozen(result), true);
}
function revoked(result) {
  assert.equal(encode(result) === '{"status":"REVOKED","mode":"PUBLIC_DRAFT_ONLY","revision":2}', true, 'exact revision2 acknowledgment');
  assert.equal(Object.isFrozen(result), true);
}
const variants = (text) => ['', '{', 'null', '[]', '1', '"synthetic"', '\u00e9', '\ud800',
  ' ' + text, text + '\n', text + '{}', text.replace('SYNTHETIC', '\\u0053YNTHETIC'),
  text.replace('"version"', '"\\u0076ersion"'), text.replace('"version":1', '"version":2,"version":1'),
  text.replace('"version":1', '"version":1e0'), text.replace('"version":1', '"version":1.0'),
  encode(Object.fromEntries(Object.entries(JSON.parse(text)).reverse()))];
const nonstrings = [undefined, null, true, 0, 1n, Symbol('synthetic'), [], {}, () => {}, new String('synthetic')];

test('new factory and repeated independent DISPLAY return exact frozen shapes', () => {
  const owner = owned();
  displayed(owner.displayOne(reference(), encode(request), 10));
  displayed(owner.displayOne(reference(), encode(request), 10));
  displayed(owner.displayOne(reference(), encode(request), 99));
});

test('only factory export, frozen bound handle with no reference/map/original/accessor/bulk surface', () => {
  assert.equal(Object.keys(api).join(',') === 'createPilotOwner', true);
  const owner = owned();
  assert.equal(Object.keys(owner).join(',') === 'status,mode,displayOne,revoke', true);
  assert.equal(owner.mode === 'PUBLIC_DRAFT_ONLY' && Object.isFrozen(owner), true);
  assert.equal(encode(owner).includes(original), false);
  assert.equal(Object.values(Object.getOwnPropertyDescriptors(owner)).every((d) => Object.hasOwn(d, 'value')), true);
  let rejected = 0;
  try { owner.displayOne = () => {}; } catch { rejected += 1; }
  try { owner.original = original; } catch { rejected += 1; }
  assert.equal(rejected, 2);
  const display = owner.displayOne;
  displayed(display.call({ original: 'SYNTHETIC-ASSET-B2' }, reference(), encode(request), 10));
  refused(display([reference()], encode(request), 10));
  refused(display([reference(), reference(context, 'SYNTHETIC-ASSET-B2')], encode(request), 10));
  displayed(display(reference(), encode(request), 10));
});

test('factory primitive positions and hostile wrappers/proxies/getters/hooks are never touched', () => {
  let touched = 0;
  const hostile = new Proxy({}, { get() { touched += 1; throw new Error('synthetic sentinel'); }, ownKeys() { touched += 1; throw new Error('synthetic sentinel'); }, getOwnPropertyDescriptor() { touched += 1; throw new Error('synthetic sentinel'); } });
  const hooks = { get version() { touched += 1; throw new Error('synthetic sentinel'); }, toString() { touched += 1; throw new Error('synthetic sentinel'); }, toJSON() { touched += 1; throw new Error('synthetic sentinel'); }, [Symbol.toPrimitive]() { touched += 1; throw new Error('synthetic sentinel'); } };
  for (const bad of [...nonstrings, hostile, hooks]) for (const index of [0, 1, 2]) {
    const args = [encode(config), encode(context), original]; args[index] = bad;
    refused(createPilotOwner(...args));
  }
  assert.equal(touched, 0);
});

test('factory config canonical order/closed schema and whole destinations refuse atomic invalid units', () => {
  for (const bad of variants(encode(config))) refused(createPilotOwner(bad, encode(context), original));
  for (const key of Object.keys(config)) {
    const missing = { ...config }; delete missing[key];
    refused(createPilotOwner(encode(missing), encode(context), original));
    for (const bad of [null, [], {}, true, 'unknown.synthetic.invalid']) refused(createPilotOwner(encode({ ...config, [key]: bad }), encode(context), original));
  }
  for (const change of [{ extra: original }, { version: 2 }, { revision: 2 }, { displayPurpose: config.adminPurpose }, { adminPurpose: config.displayPurpose }]) refused(createPilotOwner(encode({ ...config, ...change }), encode(context), original));
  for (const key of ['displayDestination', 'adminDestination']) {
    const prefix = config[key].slice(0, -1);
    for (const value of [prefix, prefix + 'a', prefix + 'A'.repeat(33), config[key] + '\n', 'prefix' + config[key], prefix + '\u0391', config[key] + 'suffix.invalid']) refused(createPilotOwner(encode({ ...config, [key]: value }), encode(context), original));
  }
});

test('P1 exact context/original validation remains sole derivation authority, context key reorder admitted', () => {
  const ordered = encode(context);
  for (const bad of variants(ordered).slice(0, -1)) refused(createPilotOwner(encode(config), bad, original));
  for (const key of Object.keys(context)) {
    const missing = { ...context }; delete missing[key];
    refused(createPilotOwner(encode(config), encode(missing), original));
    for (const bad of [null, {}, [], true, 'unknown.synthetic.invalid']) refused(createPilotOwner(encode(config), encode({ ...context, [key]: bad }), original));
  }
  refused(createPilotOwner(encode(config), encode({ ...context, extra: original }), original));
  for (const bad of ['', 'SYNTHETIC-ASSET-', 'SYNTHETIC-ASSET-a', 'SYNTHETIC-ASSET-A_', 'SYNTHETIC-ASSET-' + 'Z'.repeat(65), original + '\n', original + 'suffix.invalid', 'prefix' + original, 'ordinary.example.invalid', 'SYNTHETIC-ASSET-\u0391', reference()]) refused(createPilotOwner(encode(config), ordered, bad));
  const reordered = Object.fromEntries(Object.entries(context).reverse());
  displayed(owned(config, reordered).displayOne(reference(), encode(request), 10));
});

test('maximal valid schemas below caps; raw exact/over caps are malformed refusal not valid cap exercise', () => {
  const c = { version: 1, scope: 'SYNTHETIC-SCOPE-' + 'Z'.repeat(32), session: 'SYNTHETIC-SESSION-' + 'Z'.repeat(32), context: 'SYNTHETIC-CONTEXT-' + 'Z'.repeat(32) };
  const cfg = { ...config, displayDestination: 'SYNTHETIC-DISPLAY-' + 'Z'.repeat(32), adminDestination: 'SYNTHETIC-ADMIN-' + 'Z'.repeat(32), createdAt: 999999, expiresAt: 1000000 };
  const value = 'SYNTHETIC-ASSET-' + 'Z'.repeat(64);
  const r = requestFor(c, cfg); const a = requestFor(c, cfg, 1, true);
  assert.equal(encode(cfg).length < 1024 && encode(c).length < 512 && encode(r).length < 1024 && encode(a).length < 1024, true);
  const owner = owned(cfg, c, value);
  displayed(owner.displayOne(reference(c, value), encode(r), 999999), value);
  revoked(owner.revoke(encode(a), 1000000));
  for (const n of [1024, 1025]) {
    refused(createPilotOwner('x'.repeat(n), encode(context), original));
    refused(owned().displayOne(reference(), 'x'.repeat(n), 10));
    refused(owned().revoke('x'.repeat(n), 10));
  }
  for (const n of [512, 513]) refused(createPilotOwner(encode(config), 'x'.repeat(n), original));
});

test('config clock interval limits equality and canonical number checks', () => {
  for (const key of ['createdAt', 'expiresAt']) for (const bad of [-1, 0.5, 1000001, null, '10']) refused(createPilotOwner(encode({ ...config, [key]: bad }), encode(context), original));
  for (const cfg of [{ ...config, createdAt: 100, expiresAt: 100 }, { ...config, expiresAt: 9 }, { ...config, createdAt: 1000000, expiresAt: 1000000 }]) refused(createPilotOwner(encode(cfg), encode(context), original));
  refused(createPilotOwner(encode(config).replace('"createdAt":10', '"createdAt":-0'), encode(context), original));
  const cfg = { ...config, createdAt: 0, expiresAt: 1 };
  displayed(owned(cfg).displayOne(reference(), encode(request), -0));
  refused(owned(cfg).displayOne(reference(), encode(request), 1));
});

test('unknown foreign legacy truncated uppercase bulk and request-as-reference forms refuse', () => {
  const owner = owned();
  for (const bad of [...nonstrings, '', original, 'DRAFT-REF-' + 'a'.repeat(64), 'DRAFT-PILOT-REF-' + '0'.repeat(64), reference().slice(0, -1), reference() + '\n', reference() + 'x', reference().toUpperCase(), reference(context, 'SYNTHETIC-ASSET-B2'), encode(request), { reference: reference(), grant: 'DISPLAY' }]) refused(owner.displayOne(bad, encode(request), 10));
  for (const key of ['scope', 'session', 'context']) refused(owner.displayOne(reference({ ...context, [key]: context[key] + 'B' }), encode(request), 10));
  displayed(owner.displayOne(reference(), encode(request), 10));
});

test('every DISPLAY component independently binds; USE EXPORT REVOKE and provider grants do not display', () => {
  const owner = owned();
  for (const key of Object.keys(request)) {
    const missing = { ...request }; delete missing[key]; refused(owner.displayOne(reference(), encode(missing), 10));
    for (const bad of [null, [], {}, true, 'unknown.synthetic.invalid']) refused(owner.displayOne(reference(), encode({ ...request, [key]: bad }), 10));
  }
  for (const change of [{ scope: context.scope + 'B' }, { session: context.session + 'B' }, { context: context.context + 'B' }, { purpose: config.adminPurpose }, { operation: 'USE' }, { operation: 'EXPORT' }, { operation: 'REVOKE' }, { destination: config.displayDestination + 'B' }, { version: 2 }, { revision: 0 }, { revision: 2 }, { grant: 'DISPLAY' }, { reference: reference() }]) refused(owner.displayOne(reference(), encode({ ...request, ...change }), 10));
  refused(owner.displayOne(reference(), encode(admin), 10));
  refused(owner.displayOne(reference(), encode({ version: 1, reference: reference(), result: original, purpose: config.displayPurpose }), 10));
  displayed(owner.displayOne(reference(), encode(request), 10));
});

test('DISPLAY/admin primitive canonical closed order and duplicate revision checks', () => {
  const owner = owned();
  for (const bad of [...nonstrings, ...variants(encode(request)), encode(request).replace('"revision":1', '"revision":2,"revision":1'), encode(request).replace('"revision":1', '"revision":1e0')]) refused(owner.displayOne(reference(), bad, 10));
  for (const bad of [...nonstrings, ...variants(encode(admin)), encode(admin).replace('"revision":1', '"revision":2,"revision":1'), encode(admin).replace('"revision":1', '"revision":-0')]) refused(owner.revoke(bad, 10));
  displayed(owner.displayOne(reference(), encode(request), 10));
  revoked(owner.revoke(encode(admin), 10));
});

test('method hostile inputs including clocks never invoke getters/coercions/hooks', () => {
  let touched = 0;
  const bad = new Proxy({}, { get() { touched += 1; throw new Error('synthetic sentinel'); }, ownKeys() { touched += 1; throw new Error('synthetic sentinel'); } });
  const owner = owned();
  refused(owner.displayOne(bad, encode(request), 10));
  refused(owner.displayOne(reference(), bad, 10));
  refused(owner.revoke(bad, 10));
  displayed(owner.displayOne(reference(), encode(request), 10));
  refused(owner.displayOne(reference(), encode(request), bad));
  refused(owner.revoke(encode(admin), bad));
  refused(owner.displayOne(reference(), encode(request), 10));
  revoked(owner.revoke(encode(admin), 10));
  assert.equal(touched, 0);
});

test('separate admin binds all members; malformed foreign and stale revoke cannot advance revision', () => {
  const owner = owned();
  for (const key of Object.keys(admin)) {
    const missing = { ...admin }; delete missing[key]; refused(owner.revoke(encode(missing), 10));
    for (const bad of [null, [], {}, true, 'unknown.synthetic.invalid']) refused(owner.revoke(encode({ ...admin, [key]: bad }), 10));
  }
  for (const change of [{ scope: context.scope + 'B' }, { session: context.session + 'B' }, { context: context.context + 'B' }, { purpose: config.displayPurpose }, { operation: 'DISPLAY' }, { operation: 'USE' }, { operation: 'EXPORT' }, { destination: config.adminDestination + 'B' }, { revision: 2 }, { version: 2 }, { extra: original }]) refused(owner.revoke(encode({ ...admin, ...change }), 10));
  refused(owner.revoke(encode(request), 10));
  displayed(owner.displayOne(reference(), encode(request), 10));
  revoked(owner.revoke(encode(admin), 20));
  refused(owner.revoke(encode(admin), 20));
  refused(owner.displayOne(reference(), encode({ ...request, revision: 2 }), 20));
  revoked(owner.revoke(encode({ ...admin, revision: 2 }), 20));
  revoked(owner.revoke(encode({ ...admin, revision: 2 }), 100));
});

test('expiry is sticky even on denied display/admin; proper current admin acknowledges closure', () => {
  for (const viaAdmin of [false, true]) {
    const owner = owned();
    displayed(owner.displayOne(reference(), encode(request), 99));
    refused(viaAdmin ? owner.revoke('{', 100) : owner.displayOne('unknown', '{', 100));
    refused(owner.displayOne(reference(), encode(request), 100));
    refused(owner.revoke(encode({ ...admin, revision: 2 }), 100));
    revoked(owner.revoke(encode(admin), 100));
    refused(owner.revoke(encode(admin), 100));
    revoked(owner.revoke(encode({ ...admin, revision: 2 }), 1000000));
    refused(owner.displayOne(reference(), encode(request), 1000000));
  }
});

test('invalid and rollback observations permanently close before candidate/request inspection', () => {
  for (const now of [...nonstrings, NaN, Infinity, -Infinity, -1, 0.1, 1000001, Number.MAX_SAFE_INTEGER, 9, -0]) for (const viaAdmin of [false, true]) {
    const owner = owned();
    refused(viaAdmin ? owner.revoke(encode(admin), now) : owner.displayOne(reference(), encode(request), now));
    refused(owner.displayOne(reference(), encode(request), 10));
    revoked(owner.revoke(encode(admin), 10));
    refused(owner.displayOne(reference(), encode(request), 10));
  }
});

test('denied calls advance high-water; equal valid time allowed but rollback latches without changing revision', () => {
  for (const viaAdmin of [false, true]) {
    const owner = owned();
    refused(viaAdmin ? owner.revoke('{', 50) : owner.displayOne('unknown', '{', 50));
    displayed(owner.displayOne(reference(), encode(request), 50));
    refused(owner.revoke(encode(admin), 49));
    refused(owner.displayOne(reference(), encode(request), 50));
    revoked(owner.revoke(encode(admin), 50));
    refused(owner.revoke(encode({ ...admin, revision: 2 }), 49));
    revoked(owner.revoke(encode({ ...admin, revision: 2 }), 50));
  }
});

test('independent A/B owners neither share state nor resolve foreign fixture scope', () => {
  const c = { ...context, scope: 'SYNTHETIC-SCOPE-B' };
  const value = 'SYNTHETIC-ASSET-B2';
  const a = owned(); const b = owned(config, c, value);
  refused(a.displayOne(reference(c, value), encode(request), 10));
  refused(b.displayOne(reference(), encode(requestFor(c)), 10));
  revoked(a.revoke(encode(admin), 20));
  displayed(b.displayOne(reference(c, value), encode(requestFor(c)), 10), value);
  displayed(owned().displayOne(reference(), encode(request), 10));
  refused(a.displayOne(reference(), encode(request), 20));
});

test('1000 generated public identity/lifecycle cases with independent tuple dimensions and owners', () => {
  for (let i = 0; i < 1000; i += 1) {
    const suffix = i.toString(36).toUpperCase();
    const c = { version: 1, scope: 'SYNTHETIC-SCOPE-' + suffix, session: 'SYNTHETIC-SESSION-' + (i * 7).toString(36).toUpperCase(), context: 'SYNTHETIC-CONTEXT-' + (i * 13).toString(36).toUpperCase() };
    const value = 'SYNTHETIC-ASSET-' + suffix;
    const cfg = { ...config, displayDestination: 'SYNTHETIC-DISPLAY-' + suffix, adminDestination: 'SYNTHETIC-ADMIN-' + suffix, createdAt: i, expiresAt: i + 100 };
    const owner = owned(cfg, c, value); const independent = owned(cfg, c, value);
    const ref = reference(c, value); const r = requestFor(c, cfg); const a = requestFor(c, cfg, 1, true);
    displayed(owner.displayOne(ref, encode(r), i), value);
    for (const key of ['scope', 'session', 'context']) {
      const foreign = { ...c, [key]: c[key] + 'Q' };
      refused(owner.displayOne(reference(foreign, value), encode(r), i));
      refused(owner.displayOne(ref, encode({ ...r, [key]: foreign[key] }), i));
    }
    refused(owner.displayOne(reference(c, value + 'Z'), encode(r), i));
    if (i % 4 === 0) revoked(owner.revoke(encode(a), i + 10));
    else if (i % 4 === 1) refused(owner.displayOne('unknown', '{', i + 100));
    else if (i % 4 === 2) refused(owner.revoke(encode(a), NaN));
    else {
      refused(owner.revoke('{', i + 10));
      refused(owner.displayOne(ref, encode(r), i + 9));
    }
    const now = i % 4 === 1 ? i + 100 : i + 10;
    refused(owner.displayOne(ref, encode(r), now));
    const current = i % 4 === 0 ? 2 : 1;
    revoked(owner.revoke(encode({ ...a, revision: current }), now));
    refused(owner.revoke(encode(a), now));
    revoked(owner.revoke(encode({ ...a, revision: 2 }), now));
    refused(owner.displayOne(ref, encode({ ...r, revision: 2 }), now));
    displayed(independent.displayOne(ref, encode(r), i), value);
  }
});
