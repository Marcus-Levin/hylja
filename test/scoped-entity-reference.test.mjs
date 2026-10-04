// Behavior tests for the keyed, scope-bound entity reference derivation (issue #168).
// Synthetic, non-routable `.invalid` identifiers only. No network, no credentials, no originals.
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { test } from 'node:test';
import { SEMANTIC_CLASSES } from '../dist/classification.js';
import {
  ENTITY_REFERENCE_KEY_BYTES, ENTITY_REFERENCE_MAX_ID_UNITS, ENTITY_REFERENCE_REFUSALS,
  ENTITY_REFERENCE_SCOPE_KINDS, ENTITY_REFERENCE_TOKEN_PREFIX,
  deriveScopedEntityReference,
} from '../dist/scoped-entity-reference.js';

const SCOPE_ID_NAMES = ['tenantId', 'projectId', 'sessionId', 'requestId'];

const TENANT_A = 'tenant-synthetic-a.invalid';
const TENANT_B = 'tenant-synthetic-b.invalid';
const PROJECT_A = 'project-synthetic-a.invalid';
const PROJECT_B = 'project-synthetic-b.invalid';
const SESSION_A = 'session-synthetic-a.invalid';
const SESSION_B = 'session-synthetic-b.invalid';
const REQUEST_A = 'request-synthetic-a.invalid';
const REQUEST_B = 'request-synthetic-b.invalid';
const ENTITY_A = 'entity-synthetic-a.invalid';
const ENTITY_B = 'entity-synthetic-b.invalid';
const KEY_VERSION_A = 'kv-synthetic-1.invalid';
const KEY_VERSION_B = 'kv-synthetic-2.invalid';
// Deterministic synthetic key bytes. Obviously not a real key and never committed as one.
const KEY_A = Uint8Array.from({ length: 32 }, (_, index) => (index * 7 + 3) & 0xff);
const KEY_B = Uint8Array.from({ length: 32 }, (_, index) => (index * 11 + 5) & 0xff);

const ALWAYS = {
  entityId: ENTITY_A, semanticType: 'PERSON', keyVersion: KEY_VERSION_A,
  key: Uint8Array.from(KEY_A),
};
function keyCopy(source = KEY_A) { return Uint8Array.from(source); }
/** A genuine view whose own `length` data property lies about the real element count. */
function shadowedLength(bytes, length) {
  const view = new Uint8Array(bytes);
  Object.defineProperty(view, 'length', { value: length, configurable: true });
  return view;
}
/** A view (or a view of the wrong element width) that lies about both its brand and its length. */
function spoofedBrand(view, length) {
  Object.defineProperty(view, 'length', { value: length, configurable: true });
  Object.defineProperty(view, Symbol.toStringTag, { value: 'Uint8Array', configurable: true });
  return view;
}
function request(overrides = {}) {
  return Object.assign({ scope: 'REQUEST', tenantId: TENANT_A, projectId: PROJECT_A,
    sessionId: SESSION_A, requestId: REQUEST_A, key: keyCopy() }, ALWAYS, overrides);
}
function narrow(fields) { return Object.assign({ key: keyCopy() }, ALWAYS, fields); }
function derivedToken(result) {
  assert.equal(result.state, 'DERIVED', `expected DERIVED, got ${String(result.reason)}`);
  return result.token;
}
const refused = (reason) => ({ version: 1, state: 'REFUSED', reason });
/**
 * Call the seam and report an escape as a boolean instead of letting it fail the test with the planted
 * value, so no exception detail from the module's internals is ever printed by this suite.
 */
function deriveSafely(value) {
  try {
    return { result: deriveScopedEntityReference(value), escaped: false };
  } catch {
    return { result: undefined, escaped: true };
  }
}

test('the same complete input and key derive the same reference every time', () => {
  const first = deriveScopedEntityReference(request());
  const second = deriveScopedEntityReference(request());
  assert.deepEqual(first, second);
  assert.deepEqual(first, { version: 1, state: 'DERIVED', token: first.token, scope: 'REQUEST' });
  assert.equal(typeof first.token, 'string');
  // Property order of an equal input is not part of the derivation.
  const reordered = { keyVersion: KEY_VERSION_A, semanticType: 'PERSON', entityId: ENTITY_A,
    key: keyCopy(), requestId: REQUEST_A, sessionId: SESSION_A, projectId: PROJECT_A,
    tenantId: TENANT_A, scope: 'REQUEST' };
  assert.equal(deriveScopedEntityReference(reordered).token, first.token);
});

test('a derived reference is one fixed-prefix full 256-bit hex token and no scope ID or key bytes', () => {
  const result = deriveScopedEntityReference(request());
  const token = derivedToken(result);
  assert.ok(token.startsWith(ENTITY_REFERENCE_TOKEN_PREFIX));
  assert.match(token, /^her1:[0-9a-f]{64}$/u);
  assert.equal(token.length, ENTITY_REFERENCE_TOKEN_PREFIX.length + 64);
  assert.deepEqual(Object.keys(result).sort(), ['scope', 'state', 'token', 'version']);
  const json = JSON.stringify(result);
  for (const id of [TENANT_A, PROJECT_A, SESSION_A, REQUEST_A, ENTITY_A, KEY_VERSION_A, KEY_VERSION_B]) {
    assert.ok(!json.includes(id), 'the record must not carry a scope, entity or key-version identifier');
  }
  assert.ok(!json.includes(Buffer.from(KEY_A).toString('hex')));
  assert.ok(!json.includes(Buffer.from(KEY_A).toString('base64')));
});

test('no arbitrary caller text is echoed: a keyVersion chosen to be sensitive still derives silently', () => {
  const keyHex = Buffer.from(KEY_A).toString('hex');
  // Each value below is inside the 128-unit bound and the closed alphabet, so the call is accepted.
  // An accepted call must not hand any of it back: bounds and an alphabet are not non-sensitivity.
  for (const [label, value] of [['tenant id', TENANT_A], ['project id', PROJECT_A],
    ['session id', SESSION_A], ['request id', REQUEST_A], ['entity id', ENTITY_A],
    ['key hex', keyHex]]) {
    const result = deriveScopedEntityReference(request({ keyVersion: value }));
    assert.equal(result.state, 'DERIVED', `${label} is a valid keyVersion, so the call must derive`);
    assert.equal(Object.hasOwn(result, 'keyVersion'), false, `${label} must not be echoed as a field`);
    assert.ok(!JSON.stringify(result).includes(value), `${label} must not appear in the record`);
    // It is still bound into the derivation: another keyVersion is another reference.
    assert.notEqual(result.token, derivedToken(deriveScopedEntityReference(request())));
  }
  // A keyVersion that carries key bytes cannot be smuggled out through the DERIVED record either.
  const hexResult = deriveScopedEntityReference(request({ keyVersion: keyHex }));
  assert.deepEqual(Object.keys(hexResult).sort(), ['scope', 'state', 'token', 'version']);
  assert.equal(hexResult.token.length, ENTITY_REFERENCE_TOKEN_PREFIX.length + 64);
});

test('the digest is HMAC-SHA256 over the documented versioned framed serialization', () => {
  // An independent recomputation of the contract's own framing, not a copy of the module's code.
  const frame = (value) => `${value.length}:${value}`;
  const message = ['hylja.scoped-entity-reference.v1', 'REQUEST', TENANT_A, PROJECT_A, SESSION_A,
    REQUEST_A, ENTITY_A, 'PERSON', KEY_VERSION_A].map(frame).join('|');
  const expected = `${ENTITY_REFERENCE_TOKEN_PREFIX}${createHmac('sha256', KEY_A).update(message).digest('hex')}`;
  assert.equal(derivedToken(deriveScopedEntityReference(request())), expected);
  // The unkeyed digest of the same message is not the reference: the derivation is keyed.
  assert.notEqual(derivedToken(deriveScopedEntityReference(request())),
    `her1:${createHmac('sha256', Buffer.alloc(32)).update(message).digest('hex')}`);
});

test('changing key, scope id, kind, entity, class or key version yields a different reference', () => {
  const base = derivedToken(deriveScopedEntityReference(request()));
  const variants = {
    key: request({ key: keyCopy(KEY_B) }),
    tenantId: request({ tenantId: TENANT_B }),
    projectId: request({ projectId: PROJECT_B }),
    sessionId: request({ sessionId: SESSION_B }),
    requestId: request({ requestId: REQUEST_B }),
    // A narrower kind is a different tuple: it drops the request id the base carries.
    kind: narrow({ scope: 'SESSION', tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A }),
    entityId: request({ entityId: ENTITY_B }),
    semanticType: request({ semanticType: 'ENGINEERING_IDENTIFIER' }),
    keyVersion: request({ keyVersion: KEY_VERSION_B }),
  };
  const tokens = [base];
  for (const [field, value] of Object.entries(variants)) {
    const token = derivedToken(deriveScopedEntityReference(value));
    assert.notEqual(token, base, `${field} must change the reference`);
    tokens.push(token);
  }
  assert.equal(new Set(tokens).size, tokens.length, 'every variant is distinct from every other');
});

test('each scope kind derives with exactly its own identifiers and refuses any other', () => {
  const ids = { tenantId: TENANT_A, projectId: PROJECT_A, sessionId: SESSION_A, requestId: REQUEST_A };
  const cases = [
    ['TENANT', ['tenantId'], true],
    ['TENANT', [], false],
    ['TENANT', ['tenantId', 'projectId'], false],
    ['TENANT', ['tenantId', 'sessionId'], false],
    ['TENANT', ['tenantId', 'projectId', 'sessionId', 'requestId'], false],
    ['PROJECT', ['tenantId', 'projectId'], true],
    ['PROJECT', ['tenantId'], false],
    ['PROJECT', ['tenantId', 'projectId', 'sessionId'], false],
    ['PROJECT', ['tenantId', 'projectId', 'requestId'], false],
    ['SESSION', ['tenantId', 'projectId', 'sessionId'], true],
    ['SESSION', ['tenantId', 'projectId'], false],
    ['SESSION', ['tenantId', 'sessionId'], false],
    ['SESSION', ['tenantId', 'projectId', 'sessionId', 'requestId'], false],
    ['REQUEST', ['tenantId', 'projectId', 'sessionId', 'requestId'], true],
    ['REQUEST', ['tenantId', 'projectId', 'sessionId'], false],
    ['REQUEST', ['tenantId'], false],
  ];
  for (const [scope, present, ok] of cases) {
    const fields = narrow({ scope });
    for (const name of present) fields[name] = ids[name];
    const result = deriveScopedEntityReference(fields);
    if (ok) derivedToken(result);
    else assert.deepEqual(result, refused('SCOPE_FIELDS_INVALID'),
      `${scope} with [${present.join(',')}] must refuse`);
  }
});

test('delimiter-like identifiers cannot alias distinct tuples', () => {
  // Flattened without framing, both tuples read as the same text.
  const left = narrow({ scope: 'PROJECT', tenantId: 'tenant-synthetic-ab', projectId: 'c',
    entityId: 'de' });
  const right = narrow({ scope: 'PROJECT', tenantId: 'tenant-synthetic-a', projectId: 'bc',
    entityId: 'de' });
  assert.notEqual(derivedToken(deriveScopedEntityReference(left)),
    derivedToken(deriveScopedEntityReference(right)));
  // The scope kind is bound too: the same characters under a different kind are another reference.
  const kindSwap = narrow({ scope: 'TENANT', tenantId: 'tenant-synthetic-abc', entityId: 'de' });
  const projectSwap = narrow({ scope: 'PROJECT', tenantId: 'tenant-synthetic-a', projectId: 'bc',
    entityId: 'de' });
  assert.notEqual(derivedToken(deriveScopedEntityReference(kindSwap)),
    derivedToken(deriveScopedEntityReference(projectSwap)));
});

test('a host-selected broader scope is a different reference, not a wider permission', () => {
  const atTenant = deriveScopedEntityReference(narrow({ scope: 'TENANT', tenantId: TENANT_A }));
  const atRequest = deriveScopedEntityReference(request());
  assert.equal(atTenant.scope, 'TENANT');
  assert.equal(atRequest.scope, 'REQUEST');
  assert.notEqual(atTenant.token, atRequest.token);
  // A derived reference carries no authorization decision of its own.
  for (const record of [atTenant, atRequest]) {
    for (const name of ['authorized', 'permission', 'grants', 'mapping', 'original', 'alias']) {
      assert.equal(Object.hasOwn(record, name), false);
    }
  }
});

test('credentials are refused and only accepted-v1 classes derive', () => {
  assert.deepEqual(deriveScopedEntityReference(request({ semanticType: 'CREDENTIAL_OR_SECRET' })),
    refused('CREDENTIAL_REFUSED'));
  for (const candidate of ['ROBOT', 'UNKNOWN', 'NAME', 'person', 'PSEUDONYM', '', 'PERSON ']) {
    assert.deepEqual(deriveScopedEntityReference(request({ semanticType: candidate })),
      refused('INVALID_REQUEST'));
  }
  const derived = SEMANTIC_CLASSES.filter((name) => name !== 'CREDENTIAL_OR_SECRET');
  assert.ok(derived.length > 1);
  for (const name of derived) {
    assert.equal(deriveScopedEntityReference(request({ semanticType: name })).state, 'DERIVED');
  }
});

test('every identifier is bounded nonempty ASCII from the closed safe alphabet', () => {
  const atLimit = 'a'.repeat(ENTITY_REFERENCE_MAX_ID_UNITS);
  for (const field of ['entityId', 'tenantId', 'projectId', 'sessionId', 'requestId', 'keyVersion']) {
    assert.equal(deriveScopedEntityReference(request({ [field]: atLimit })).state, 'DERIVED');
    assert.equal(deriveScopedEntityReference(request({ [field]: `${atLimit}a` })).state, 'REFUSED');
  }
  const malformed = ['', ' ', 'tenant é.invalid', 'tab\ttid', 'nl\nid', 'cr\rtid', 'nul id',
    ' leading', 'trailing ', 'two words', 'a/b', 'a:b', 'a|b', 'a,b', 'a+b', 'a=b', 'a?b', 'a#b',
    'a"b', "a'b", 'a\\b', 'a%b', 'a(b', 'a[b', 'a{b', 'a;b', 'ünïcode'];
  for (const value of malformed) {
    assert.deepEqual(deriveScopedEntityReference(request({ entityId: value })),
      refused('INVALID_REQUEST'));
    assert.deepEqual(deriveScopedEntityReference(request({ keyVersion: value })),
      refused('INVALID_REQUEST'));
    for (const field of ['tenantId', 'projectId', 'sessionId', 'requestId']) {
      assert.deepEqual(deriveScopedEntityReference(request({ [field]: value })),
        refused('INVALID_REQUEST'), 'a present but invalid scope id is malformed input');
    }
  }
  for (const value of [42, null, undefined, [], {}, true]) {
    assert.deepEqual(deriveScopedEntityReference(request({ entityId: value })),
      refused('INVALID_REQUEST'));
  }
});

test('the host key must be a 32-byte byte view, and the caller key is never modified', () => {
  const key = keyCopy();
  const before = Uint8Array.from(key);
  assert.equal(deriveScopedEntityReference(request({ key })).state, 'DERIVED');
  assert.deepEqual(Array.from(key), Array.from(before), 'the owned copy is cleared, never the caller key');
  assert.equal(key.length, ENTITY_REFERENCE_KEY_BYTES);
  const wrong = [
    ['empty', new Uint8Array(0)], ['short', new Uint8Array(ENTITY_REFERENCE_KEY_BYTES - 1)],
    ['long', new Uint8Array(ENTITY_REFERENCE_KEY_BYTES + 1)],
    ['clamped', new Uint8ClampedArray(ENTITY_REFERENCE_KEY_BYTES)],
    ['data view', new DataView(new ArrayBuffer(ENTITY_REFERENCE_KEY_BYTES))],
    ['array buffer', new ArrayBuffer(ENTITY_REFERENCE_KEY_BYTES)],
    ['plain array', new Array(ENTITY_REFERENCE_KEY_BYTES).fill(1)],
    ['16-bit view', new Uint16Array(ENTITY_REFERENCE_KEY_BYTES / 2)],
    ['string', 'x'.repeat(ENTITY_REFERENCE_KEY_BYTES)], ['number', ENTITY_REFERENCE_KEY_BYTES],
    ['null', null], ['undefined', undefined], ['plain object', { length: ENTITY_REFERENCE_KEY_BYTES }],
  ];
  for (const [label, key] of wrong) {
    assert.deepEqual(deriveScopedEntityReference(request({ key })), refused('INVALID_REQUEST'), label);
  }
  // A real view can lie about its own length, and a non-byte view can lie about its brand. Neither is
  // a 32-byte Uint8Array, so neither may derive.
  const spoofed = [
    ['33 bytes claiming length 32', shadowedLength(ENTITY_REFERENCE_KEY_BYTES + 1, ENTITY_REFERENCE_KEY_BYTES)],
    ['31 bytes claiming length 32', shadowedLength(ENTITY_REFERENCE_KEY_BYTES - 1, ENTITY_REFERENCE_KEY_BYTES)],
    ['33 bytes claiming length 0', shadowedLength(ENTITY_REFERENCE_KEY_BYTES + 1, 0)],
    ['16-bit view with a spoofed tag', spoofedBrand(new Uint16Array(ENTITY_REFERENCE_KEY_BYTES),
      ENTITY_REFERENCE_KEY_BYTES)],
    ['16-bit view with a spoofed tag and length', spoofedBrand(new Uint16Array(1),
      ENTITY_REFERENCE_KEY_BYTES)],
    ['byte view with a spoofed tag and length', spoofedBrand(new Uint8Array(1),
      ENTITY_REFERENCE_KEY_BYTES)],
  ];
  for (const [label, key] of spoofed) {
    assert.deepEqual(deriveScopedEntityReference(request({ key })), refused('INVALID_REQUEST'), label);
  }
  // The mirror case: a view that is really 32 bytes and lies upward is still read for its real bytes,
  // so it derives exactly what the honest 32-byte key derives. The lie is ignored, not obeyed.
  const lying = spoofedBrand(Uint8Array.from(KEY_A), ENTITY_REFERENCE_KEY_BYTES + 1);
  assert.deepEqual(deriveScopedEntityReference(request({ key: lying })),
    deriveScopedEntityReference(request()));
});

test('the key copy this module allocates is owned by it and cleared on success and on refusal', () => {
  // The caller key is never the buffer that gets cleared, on any path out of the function.
  const cases = [
    ['accepted', keyCopy()],
    ['wrong size', new Uint8Array(4)],
    ['shadowed length', shadowedLength(ENTITY_REFERENCE_KEY_BYTES + 1, ENTITY_REFERENCE_KEY_BYTES)],
    ['spoofed brand', spoofedBrand(new Uint16Array(ENTITY_REFERENCE_KEY_BYTES),
      ENTITY_REFERENCE_KEY_BYTES)],
    ['shadowed brand and length', spoofedBrand(new Uint8Array(1), ENTITY_REFERENCE_KEY_BYTES)],
  ];
  for (const [label, key] of cases) {
    const before = Uint8Array.from(key);
    const { result, escaped } = deriveSafely(request({ key }));
    assert.equal(escaped, false, `${label}: the seam must not throw at the caller`);
    assert.deepEqual(Array.from(key), Array.from(before), `${label}: the caller key must be untouched`);
    for (const field of Object.values(result)) {
      assert.ok(typeof field === 'string' || typeof field === 'number',
        `${label}: no key view or buffer may survive in the record`);
    }
  }
  // A proxied key is refused, and the caller's own bytes behind it survive that refusal untouched.
  const target = keyCopy();
  const targetBefore = Array.from(target);
  assert.deepEqual(deriveScopedEntityReference(request({ key: new Proxy(target, {}) })),
    refused('INVALID_REQUEST'));
  assert.deepEqual(Array.from(target), targetBefore, 'a refused proxied key leaves the caller key untouched');
  // The derivation reads one snapshot: a key changed after the call cannot rewrite an earlier token.
  const live = keyCopy();
  const first = derivedToken(deriveScopedEntityReference(request({ key: live })));
  live.fill(0);
  assert.deepEqual(Array.from(live), new Array(ENTITY_REFERENCE_KEY_BYTES).fill(0));
  assert.notEqual(first, derivedToken(deriveScopedEntityReference(request({ key: live }))));
});

test('a key length that is not a primitive safe integer refuses without allocating or leaking', () => {
  const hostile = [
    ['huge length', { length: 2 ** 40, byteLength: 2 ** 40 }],
    ['fractional length', { length: ENTITY_REFERENCE_KEY_BYTES + 0.5 }],
    ['string length', { length: `${ENTITY_REFERENCE_KEY_BYTES}` }],
    ['no length', {}],
    ['throwing length', { get length() { throw new Error('planted-internal-detail.invalid'); } }],
    ['view with throwing length', new Proxy(new Uint8Array(ENTITY_REFERENCE_KEY_BYTES),
      { get: (target, property) => { if (property === 'length') throw new Error('planted-internal-detail.invalid');
        return Reflect.get(target, property); } })],
    ['view with throwing index', new Proxy(new Uint8Array(ENTITY_REFERENCE_KEY_BYTES),
      { get: (target, property) => { if (property === '0') throw new Error('planted-internal-detail.invalid');
        return Reflect.get(target, property); } })],
  ];
  for (const [label, key] of hostile) {
    const result = deriveScopedEntityReference(request({ key }));
    assert.deepEqual(result, refused('INVALID_REQUEST'), label);
    assert.ok(!JSON.stringify(result).includes('planted-internal-detail.invalid'), label);
  }
});

test('malformed, proxy and accessor requests refuse with a fixed code and never throw', () => {
  const boom = new Error('planted-internal-detail.invalid');
  const noScope = request(); delete noScope.scope;
  const hostile = [
    ['null', null], ['undefined', undefined], ['string', 'derive this'], ['number', 7],
    ['array', [request()]], ['inherited prototype', Object.assign(Object.create({ scope: 'TENANT' }),
      request())],
    ['unknown field', { ...request(), prompt: 'name: synthetic-person.invalid' }],
    ['original field', { ...request(), original: 'synthetic-original.invalid' }],
    ['alias field', { ...request(), alias: 'synthetic-alias.invalid' }],
    ['audit field', { ...request(), audit: true }],
    ['missing scope', noScope],
    ['symbol key', Object.assign(request(), { [Symbol('synthetic')]: 'x' })],
    ['non-enumerable field', Object.defineProperty(request(), 'entityId',
      { value: ENTITY_A, enumerable: false, writable: true, configurable: true })],
    ['entity getter', Object.defineProperty(request(), 'entityId',
      { enumerable: true, get() { throw boom; } })],
    ['prototype throwing', new Proxy(request(), { getPrototypeOf() { throw boom; } })],
    ['ownKeys throwing', new Proxy(request(), { ownKeys() { throw boom; } })],
    ['descriptor throwing', new Proxy(request(), { getOwnPropertyDescriptor() { throw boom; } })],
    ['extra reported key', new Proxy(request(), { ownKeys: (target) => [...Reflect.ownKeys(target), 'prompt'],
      getOwnPropertyDescriptor: (target, property) => Reflect.getOwnPropertyDescriptor(target, property) })],
    ['unknown kind', request({ scope: 'GLOBAL' })], ['lowercase kind', request({ scope: 'tenant' })],
    ['numeric kind', request({ scope: 1 })],
  ];
  for (const [label, value] of hostile) {
    const { result, escaped } = deriveSafely(value);
    assert.equal(escaped, false, `${label}: the seam must not throw at the caller`);
    assert.equal(result.state, 'REFUSED', label);
    assert.ok(ENTITY_REFERENCE_REFUSALS.includes(result.reason), label);
    assert.ok(!JSON.stringify(result).includes('planted-internal-detail.invalid'), label);
    assert.ok(!JSON.stringify(result).includes('synthetic-'), label);
  }
});

test('a hostile throw that is itself a Proxy is refused internally and never escapes', () => {
  const boom = new Error('planted-internal-detail.invalid');
  // Reflecting over a caught value can throw again: `instanceof`, a prototype walk and an own-key
  // read all run caller code. The refusal must therefore never look at what was thrown.
  const poisoned = new Proxy({}, { getPrototypeOf() { throw boom; } });
  const nested = new Proxy({}, { ownKeys() { throw boom; } });
  const hostile = [
    ['descriptor trap throws a poisoned proxy', new Proxy(request(), {
      getOwnPropertyDescriptor() { throw poisoned; } })],
    ['ownKeys trap throws a poisoned proxy', new Proxy(request(), { ownKeys() { throw poisoned; } })],
    ['get trap throws a poisoned proxy', new Proxy(request(), { get() { throw poisoned; } })],
    ['ownKeys trap throws a differently poisoned proxy', new Proxy(request(), {
      ownKeys() { throw nested; } })],
    ['key proxy throws a poisoned value on index', request({ key: new Proxy(keyCopy(), {
      get: (target, property) => {
        if (property === '0') throw poisoned;
        return Reflect.get(target, property);
      } }) })],
  ];
  for (const [label, value] of hostile) {
    const { result, escaped } = deriveSafely(value);
    assert.equal(escaped, false, `${label}: the seam must not throw at the caller`);
    assert.equal(result.state, 'REFUSED', label);
    assert.ok(ENTITY_REFERENCE_REFUSALS.includes(result.reason), label);
    assert.ok(!JSON.stringify(result).includes('planted-internal-detail.invalid'), label);
    assert.ok(!JSON.stringify(result).includes('synthetic-'), label);
  }
});

test('every proxied request or key refuses, transparent or throwing, and never throws back out', () => {
  const boom = new Error('planted-internal-detail.invalid');
  const poisoned = new Proxy({}, { getPrototypeOf() { throw boom; } });
  const proxied = [
    ['transparent request proxy', new Proxy(request(), {})],
    ['fully forwarding request proxy', new Proxy(request(), {
      get: (target, property, receiver) => Reflect.get(target, property, receiver),
      getPrototypeOf: (target) => Reflect.getPrototypeOf(target),
      ownKeys: (target) => Reflect.ownKeys(target),
      getOwnPropertyDescriptor: (target, property) => Reflect.getOwnPropertyDescriptor(target, property),
    })],
    ['get trap throws', new Proxy(request(), { get() { throw boom; } })],
    ['prototype trap throws', new Proxy(request(), { getPrototypeOf() { throw boom; } })],
    ['ownKeys trap throws', new Proxy(request(), { ownKeys() { throw boom; } })],
    ['descriptor trap throws', new Proxy(request(), { getOwnPropertyDescriptor() { throw boom; } })],
    ['ownKeys trap throws a primitive', new Proxy(request(), { ownKeys() { throw 42; } })],
    ['descriptor trap throws null', new Proxy(request(), { getOwnPropertyDescriptor() { throw null; } })],
  ];
  for (const [label, value] of proxied) {
    const { result, escaped } = deriveSafely(value);
    assert.equal(escaped, false, `${label}: the seam must not throw at the caller`);
    assert.deepEqual(result, refused('INVALID_REQUEST'), label);
    assert.ok(!JSON.stringify(result).includes('planted-internal-detail.invalid'), label);
    assert.ok(!JSON.stringify(result).includes('synthetic-'), label);
  }
  // A proxy around a perfectly valid view is not a key, however transparent its traps are.
  const keys = [
    ['transparent key proxy', new Proxy(keyCopy(), {})],
    ['forwarding key proxy', new Proxy(keyCopy(), {
      get: (target, property, receiver) => Reflect.get(target, property, receiver) })],
    ['key proxy throwing on index', new Proxy(keyCopy(), {
      get: (target, property) => {
        if (property === '0') throw poisoned;
        return Reflect.get(target, property);
      } })],
    ['key proxy throwing on length', new Proxy(keyCopy(), {
      get: (target, property) => {
        if (property === 'length') throw poisoned;
        return Reflect.get(target, property);
      } })],
  ];
  for (const [label, key] of keys) {
    const { result, escaped } = deriveSafely(request({ key }));
    assert.equal(escaped, false, `${label}: the seam must not throw at the caller`);
    assert.deepEqual(result, refused('INVALID_REQUEST'), label);
    assert.ok(!JSON.stringify(result).includes('planted-internal-detail.invalid'), label);
  }
});

test('the derived record is frozen, holds no alias to the input and mutates nothing', () => {
  const value = request();
  const before = structuredClone(value);
  const result = deriveScopedEntityReference(value);
  derivedToken(result);
  assert.ok(Object.isFrozen(result));
  assert.throws(() => { result.token = `${ENTITY_REFERENCE_TOKEN_PREFIX}${'0'.repeat(64)}`; }, TypeError);
  assert.throws(() => { result.state = 'REFUSED'; }, TypeError);
  assert.throws(() => { result.scope = 'TENANT'; }, TypeError);
  for (const [name, field] of Object.entries(result)) {
    assert.ok(typeof field === 'string' || typeof field === 'number',
      `${name} must be a primitive, never a reference into the caller's object`);
  }
  assert.deepEqual(value, before, 'the caller input is never mutated');
  const frozenInput = Object.freeze(request());
  assert.equal(Object.isFrozen(frozenInput), true);
  assert.equal(deriveScopedEntityReference(frozenInput).state, 'DERIVED');
});

test('every outcome this seam can return is one of its fixed codes', () => {
  const seen = new Set();
  const record = (value) => {
    const result = deriveScopedEntityReference(value);
    assert.ok(ENTITY_REFERENCE_SCOPE_KINDS.includes(result.scope) || result.state === 'REFUSED');
    if (result.state === 'REFUSED') {
      assert.ok(ENTITY_REFERENCE_REFUSALS.includes(result.reason), 'a fixed refusal code');
      seen.add(result.reason);
    }
    return result;
  };
  record(request());
  record(request({ entityId: 'not a safe id' }));
  record(request({ key: new Uint8Array(4) }));
  record(narrow({ scope: 'REQUEST', tenantId: TENANT_A }));
  record(request({ semanticType: 'CREDENTIAL_OR_SECRET' }));
  assert.deepEqual([...seen].sort(), ['CREDENTIAL_REFUSED', 'INVALID_REQUEST', 'SCOPE_FIELDS_INVALID']);
  assert.equal(seen.size, ENTITY_REFERENCE_REFUSALS.length);
});

test('a generated synthetic matrix keeps every complete tuple and every one-field change distinct', () => {
  // Deterministic generator: index-driven synthetic identifiers, keys, classes and versions, no randomness.
  // The distinctness below is *observed over exactly these cases*. It is not a claim that HMAC cannot
  // collide; collision handling against an entity registry stays a later obligation of #14.
  const classes = SEMANTIC_CLASSES.filter((name) => name !== 'CREDENTIAL_OR_SECRET');
  const requiredFor = {
    TENANT: ['tenantId'], PROJECT: ['tenantId', 'projectId'],
    SESSION: ['tenantId', 'projectId', 'sessionId'],
    REQUEST: ['tenantId', 'projectId', 'sessionId', 'requestId'],
  };
  const synthetic = (name, index) => `${name}-synthetic-${index}.invalid`;
  const syntheticKey = (index) => Uint8Array.from({ length: 32 }, (_, position) => (index * 31 + position) & 0xff);
  const tuple = (scope, index) => {
    const fields = {
      scope, entityId: synthetic('entity', index), semanticType: classes[index % classes.length],
      keyVersion: synthetic('kv', index), key: syntheticKey(index),
    };
    for (const name of requiredFor[scope]) fields[name] = synthetic(name, index);
    return narrow(fields);
  };
  const bases = [];
  const tokens = new Set();
  const observations = { observed: 0 };
  for (let index = 0; index < 8; index += 1) {
    for (const scope of ENTITY_REFERENCE_SCOPE_KINDS) {
      const base = tuple(scope, index);
      bases.push({ scope, index, base, token: derivedToken(deriveScopedEntityReference(base)) });
      tokens.add(derivedToken(deriveScopedEntityReference(base)));
      const mutated = new Set();
      const alternatives = {
        key: syntheticKey(index + 100),
        tenantId: synthetic('tenant', `alt${index}`),
        projectId: synthetic('project', `alt${index}`),
        sessionId: synthetic('session', `alt${index}`),
        requestId: synthetic('request', `alt${index}`),
        entityId: synthetic('entity', `alt${index}`),
        semanticType: classes[(index + 1) % classes.length],
        keyVersion: synthetic('kv', `alt${index}`),
      };
      for (const [field, value] of Object.entries(alternatives)) {
        // Only an *absent* scope identifier is skipped, because a narrower kind binds none of them.
        // Every other dimension - key, entity, class, key version and each required scope id - is a
        // mutation this matrix must make, for every kind and every index.
        if (SCOPE_ID_NAMES.includes(field) && !requiredFor[scope].includes(field)) continue;
        mutated.add(field);
        const variant = Object.assign({}, base, { [field]: value });
        const token = derivedToken(deriveScopedEntityReference(variant));
        observations.observed += 1;
        assert.notEqual(token, derivedToken(deriveScopedEntityReference(base)),
          `${field} must change the reference at ${scope}/${index}`);
      }
      for (const dimension of ['key', 'entityId', 'semanticType', 'keyVersion', ...requiredFor[scope]]) {
        assert.ok(mutated.has(dimension), `${scope}/${index} must mutate ${dimension}`);
      }
      // The kind is bound too: the same identifiers and key under each other kind are other references.
      const fullIds = {
        tenantId: synthetic('tenant', index), projectId: synthetic('project', index),
        sessionId: synthetic('session', index), requestId: synthetic('request', index),
      };
      const baseToken = derivedToken(deriveScopedEntityReference(base));
      for (const other of ENTITY_REFERENCE_SCOPE_KINDS) {
        if (other === scope) continue;
        // The kind is bound too: the same entity, class, key version and key under another kind,
        // with that kind's own identifiers, is another reference. Kinds are cumulative, so a wider
        // kind adds an identifier rather than reusing a narrower tuple.
        const swapped = narrow({
          scope: other, entityId: base.entityId, semanticType: base.semanticType,
          keyVersion: base.keyVersion, key: base.key,
          ...Object.fromEntries(requiredFor[other].map((name) => [name, fullIds[name]])),
        });
        assert.notEqual(derivedToken(deriveScopedEntityReference(swapped)), baseToken,
          `the scope kind must change the reference at ${index}`);
      }
    }
  }
  assert.equal(bases.length, 32);
  assert.equal(tokens.size, bases.length,
    'every complete tuple in this generated matrix derives a distinct reference');
  assert.ok(observations.observed > 0 && observations.observed < 100000,
    `distinctness is a bounded observation over ${observations.observed} synthetic comparisons`);
});
