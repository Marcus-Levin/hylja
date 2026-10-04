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

test('the same complete input and key derive the same reference every time', () => {
  const first = deriveScopedEntityReference(request());
  const second = deriveScopedEntityReference(request());
  assert.deepEqual(first, second);
  assert.deepEqual(first, { version: 1, state: 'DERIVED', token: first.token,
    scope: 'REQUEST', keyVersion: KEY_VERSION_A });
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
  assert.deepEqual(Object.keys(result).sort(), ['keyVersion', 'scope', 'state', 'token', 'version']);
  const json = JSON.stringify(result);
  for (const id of [TENANT_A, PROJECT_A, SESSION_A, REQUEST_A, ENTITY_A]) {
    assert.ok(!json.includes(id), 'the record must not carry a scope or entity identifier');
  }
  assert.ok(!json.includes(Buffer.from(KEY_A).toString('hex')));
  assert.ok(!json.includes(Buffer.from(KEY_A).toString('base64')));
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
    const result = deriveScopedEntityReference(value);
    assert.equal(result.state, 'REFUSED', label);
    assert.ok(ENTITY_REFERENCE_REFUSALS.includes(result.reason), label);
    assert.ok(!JSON.stringify(result).includes('planted-internal-detail.invalid'), label);
    assert.ok(!JSON.stringify(result).includes('synthetic-'), label);
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
  for (let index = 0; index < 8; index += 1) {
    for (const scope of ENTITY_REFERENCE_SCOPE_KINDS) {
      const base = tuple(scope, index);
      bases.push({ scope, index, base, token: derivedToken(deriveScopedEntityReference(base)) });
      tokens.add(derivedToken(deriveScopedEntityReference(base)));
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
        if (!requiredFor[scope].includes(field)) continue;
        const variant = Object.assign({}, base, { [field]: value });
        const token = derivedToken(deriveScopedEntityReference(variant));
        assert.notEqual(token, derivedToken(deriveScopedEntityReference(base)),
          `${field} must change the reference at ${scope}/${index}`);
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
  assert.equal(tokens.size, bases.length, 'every complete tuple derives a pairwise-distinct reference');
});
