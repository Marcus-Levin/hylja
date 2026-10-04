// #162 bounded scope-bound mapping AEAD primitive.
//
// Every case here is synthetic. Byte payloads are generated per run with Node's cryptographic RNG,
// identifiers are obviously non-routable `.invalid` names, and no real customer, employee,
// credential or production value appears in this file. No case reaches the network, a provider, a
// KMS/HSM or any vault store: the DEK below is a local host-supplied test key, and no case claims
// that it proves managed-key handling, key wrapping or envelope-key lifecycle.
//
// Failure assertions compare fixed status codes, byte lengths and digests. They never print a
// planted payload byte, and no assertion message carries one. Owned transient key and plaintext
// buffers are filled with zeroes once a case is finished with them; that is best-effort hygiene in
// JavaScript, not a zeroization guarantee. Copies held inside native crypto, garbage-collected
// buffers and swapped pages are outside anything this file can prove.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import {
  sealMappingPayload, openMappingPayload,
  MAPPING_AEAD_FINDINGS, MAPPING_AEAD_LIMITS, MAPPING_AEAD_REFUSALS, MAPPING_AEAD_VERSION,
} from '../dist/mapping-aead.js';
import { SEMANTIC_CLASSES } from '../dist/classification.js';

/** Deterministic synthetic host keys. `seed` is a fixture constant, never key material. */
function key(seed) {
  return Uint8Array.from({ length: 32 }, (_, index) => (seed * 31 + index * 7) % 251);
}
function scope(overrides = {}) {
  return {
    tenantId: 'tenant-a.invalid',
    projectId: 'project-a.invalid',
    entityId: 'entity-a1',
    classification: 'PERSON',
    mappingRevision: '7',
    keyVersion: '1',
    ...overrides,
  };
}
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const plaintextOf = (bytes) => `synthetic-payload-${bytes.length}b`;

function assertSealed(result, plaintext) {
  assert.equal(result.status, 'SEALED');
  assert.equal(result.finding, 'SEALED');
  assert.deepEqual(Reflect.ownKeys(result).sort(), ['envelope', 'finding', 'status', 'version']);
  assert.equal(result.version, MAPPING_AEAD_VERSION);
  const envelope = result.envelope;
  assert.deepEqual(Reflect.ownKeys(envelope).sort(), ['ciphertext', 'nonce', 'tag', 'version']);
  assert.equal(envelope.version, MAPPING_AEAD_VERSION);
  assert.equal(envelope.nonce.byteLength, MAPPING_AEAD_LIMITS.nonceBytes);
  assert.equal(envelope.tag.byteLength, MAPPING_AEAD_LIMITS.tagBytes);
  assert.equal(envelope.ciphertext.byteLength, plaintext.byteLength);
  // The caller's payload is not reachable through the sealed record in any shape. This is an
  // identity check on where the bytes are stored, not a statistical claim about their values: a
  // valid AES-256-GCM ciphertext can equal the plaintext byte for byte (a one-byte payload in
  // particular), so no ciphertext-vs-plaintext digest inequality is asserted anywhere in this file.
  // No assertion below ever receives a raw payload byte, so a regression cannot print protected
  // bytes into TAP.
  assert.equal(envelope.ciphertext === plaintext, false);
  return envelope;
}

/** A refusal is a fixed, closed, text-free record: no native error, no cause, no partial plaintext. */
function assertRefused(result, finding) {
  assert.equal(result.status, 'REFUSED');
  assert.equal(result.finding, finding);
  assert.ok(MAPPING_AEAD_REFUSALS.includes(result.finding));
  assert.deepEqual(Reflect.ownKeys(result).sort(), ['finding', 'status', 'version']);
  assert.equal(result.version, MAPPING_AEAD_VERSION);
  assert.equal(Object.hasOwn(result, 'plaintext'), false);
  assert.equal(Object.hasOwn(result, 'envelope'), false);
  assert.equal(JSON.stringify(result).includes('Error'), false);
}

/** Calls through a hostile argument and reports a throw instead of leaking it as an assertion error.
 *  Every hostile case below goes through here, so a value the boundary was supposed to contain -
 *  including the deliberately planted error text inside a hostile thrown Proxy - is reduced to the
 *  safe boolean `threw` and never printed into TAP. */
function attempt(run, request) {
  try {
    return { threw: false, result: run(request) };
  } catch {
    return { threw: true, result: undefined };
  }
}

/** A byte source that reports `length` in place of its `byteLength`. */
function declaring(source, length) {
  return new Proxy(source, {
    get(target, property, receiver) {
      if (property === 'byteLength') return length;
      return Reflect.get(target, property, receiver);
    },
  });
}

test('the module publishes a closed finding vocabulary and fixed bounds', () => {
  assert.equal(MAPPING_AEAD_VERSION, 1);
  assert.equal(MAPPING_AEAD_LIMITS.plaintextBytes, 65536);
  assert.equal(MAPPING_AEAD_LIMITS.ciphertextBytes, 65536);
  assert.equal(MAPPING_AEAD_LIMITS.keyBytes, 32);
  assert.equal(MAPPING_AEAD_LIMITS.nonceBytes, 12);
  assert.equal(MAPPING_AEAD_LIMITS.tagBytes, 16);
  assert.equal(MAPPING_AEAD_LIMITS.identifierChars, 128);
  assert.ok(MAPPING_AEAD_FINDINGS.includes('SEALED'));
  assert.ok(MAPPING_AEAD_FINDINGS.includes('OPENED'));
  assert.equal(new Set(MAPPING_AEAD_FINDINGS).size, MAPPING_AEAD_FINDINGS.length);
  assert.ok(MAPPING_AEAD_REFUSALS.includes('AUTHENTICATION_FAILED'));
  assert.equal(MAPPING_AEAD_REFUSALS.includes('SEALED'), false);
  assert.equal(MAPPING_AEAD_REFUSALS.includes('OPENED'), false);
  assert.deepEqual(MAPPING_AEAD_REFUSALS.slice().sort(), MAPPING_AEAD_FINDINGS
    .filter((finding) => finding !== 'SEALED' && finding !== 'OPENED').slice().sort());
});

test('positive synthetic bytes roundtrip exactly through seal and open', () => {
  for (const size of [1, 2, 15, 16, 17, 4096, MAPPING_AEAD_LIMITS.plaintextBytes]) {
    const plaintext = randomBytes(size);
    const expected = digest(plaintext);
    const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(3) });
    const envelope = assertSealed(sealed, plaintext);
    const opened = openMappingPayload({ scope: scope(), key: key(3), envelope });
    assert.equal(opened.status, 'OPENED');
    assert.equal(opened.finding, 'OPENED');
    assert.deepEqual(Reflect.ownKeys(opened).sort(), ['bytes', 'finding', 'plaintext', 'status', 'version']);
    assert.equal(opened.bytes, size);
    assert.equal(digest(opened.plaintext), expected, `roundtrip must be byte-exact at ${size} bytes`);
    plaintext.fill(0);
    opened.plaintext.fill(0);
  }
});

test('accepted v1 classes other than CREDENTIAL_OR_SECRET seal and open', () => {
  for (const classification of SEMANTIC_CLASSES.filter((item) => item !== 'CREDENTIAL_OR_SECRET')) {
    const plaintext = randomBytes(24);
    const sealed = sealMappingPayload({ scope: scope({ classification }), plaintext, key: key(5) });
    assertSealed(sealed, plaintext);
    const opened = openMappingPayload({ scope: scope({ classification }), key: key(5),
      envelope: sealed.envelope });
    assert.equal(opened.status, 'OPENED');
    assert.equal(digest(opened.plaintext), digest(plaintext));
    opened.plaintext.fill(0);
    plaintext.fill(0);
  }
});

test('repeated writes of one payload use fresh, distinct nonces and ciphertexts', () => {
  const plaintext = randomBytes(96);
  const expected = digest(plaintext);
  const nonces = new Set();
  const ciphertexts = new Set();
  const tags = new Set();
  for (let round = 0; round < 64; round += 1) {
    const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(7) });
    const envelope = assertSealed(sealed, plaintext);
    nonces.add(digest(envelope.nonce));
    ciphertexts.add(digest(envelope.ciphertext));
    tags.add(digest(envelope.tag));
    const opened = openMappingPayload({ scope: scope(), key: key(7), envelope });
    assert.equal(digest(opened.plaintext), expected);
    opened.plaintext.fill(0);
  }
  assert.equal(nonces.size, 64, 'every nonce must be fresh');
  assert.equal(ciphertexts.size, 64, 'ciphertext must never repeat for one payload and key');
  assert.equal(tags.size, 64, 'tags must never repeat for one payload and key');
  plaintext.fill(0);
});

test('every sealed scope component is bound: changing one fails authentication', () => {
  const swaps = [
    ['tenantId', 'tenant-b.invalid'],
    ['projectId', 'project-b.invalid'],
    ['entityId', 'entity-b2'],
    ['classification', 'USER_ACCOUNT'],
    ['mappingRevision', '8'],
    ['keyVersion', '2'],
  ];
  const plaintext = randomBytes(64);
  const expected = digest(plaintext);
  for (const [field, value] of swaps) {
    const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(9) });
    assertSealed(sealed, plaintext);
    // The attacker supplies the matching scope metadata instead of the sealed one.
    const opened = attempt(openMappingPayload,
      { scope: scope({ [field]: value }), key: key(9), envelope: sealed.envelope });
    assert.equal(opened.threw, false, `${field} swap must not throw`);
    assertRefused(opened.result, 'AUTHENTICATION_FAILED');
    // Attaching the same field to the sealed record cannot help either: the record has exactly four
    // fields, so any injected scope metadata is a malformed record, never authority.
    const attached = attempt(openMappingPayload,
      { scope: scope({ [field]: value }), key: key(9), envelope: { ...sealed.envelope, [field]: value } });
    assert.equal(attached.threw, false, `${field} in the sealed record must not throw`);
    assertRefused(attached.result, 'INVALID_ENVELOPE');
    // And the untouched record still opens under its own scope.
    const intact = openMappingPayload({ scope: scope(), key: key(9), envelope: sealed.envelope });
    assert.equal(intact.status, 'OPENED');
    assert.equal(digest(intact.plaintext), expected);
    intact.plaintext.fill(0);
  }
  assert.equal(expected.length, 64);
  plaintext.fill(0);
});

test('independent tenant A and tenant B keys never resolve each other ciphertext', () => {
  const plaintext = randomBytes(40);
  const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(11) });
  assertSealed(sealed, plaintext);
  const tenantB = scope({ tenantId: 'tenant-b.invalid', projectId: 'project-b.invalid', entityId: 'entity-b1' });
  for (let round = 0; round < 16; round += 1) {
    const opened = attempt(openMappingPayload,
      { scope: tenantB, key: randomBytes(32), envelope: sealed.envelope });
    assert.equal(opened.threw, false);
    assertRefused(opened.result, 'AUTHENTICATION_FAILED');
  }
  // An intra-tenant project swap is refused for the tenant's own key as well.
  for (const projectId of ['project-b.invalid', 'project-c.invalid']) {
    const opened = attempt(openMappingPayload,
      { scope: { ...scope(), projectId }, key: key(11), envelope: sealed.envelope });
    assertRefused(opened.result, 'AUTHENTICATION_FAILED');
  }
  plaintext.fill(0);
});

test('revision and key-version swaps are refused in both directions', () => {
  const plaintext = randomBytes(32);
  const cases = [
    [scope(), scope({ mappingRevision: '8' })],
    [scope({ mappingRevision: '8' }), scope()],
    [scope(), scope({ keyVersion: '2' })],
    [scope({ keyVersion: '2' }), scope()],
    [scope({ keyVersion: '1' }), scope({ keyVersion: '1.1' })],
  ];
  for (const [sealing, opening] of cases) {
    const sealed = sealMappingPayload({ scope: sealing, plaintext, key: key(13) });
    assertSealed(sealed, plaintext);
    const opened = attempt(openMappingPayload, { scope: opening, key: key(13), envelope: sealed.envelope });
    assert.equal(opened.threw, false);
    assertRefused(opened.result, 'AUTHENTICATION_FAILED');
  }
  plaintext.fill(0);
});

test('a different key of the right size is refused, and every wrong key size is a fixed refusal', () => {
  const plaintext = randomBytes(56);
  const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(17) });
  assertSealed(sealed, plaintext);
  const wrongKey = attempt(openMappingPayload, { scope: scope(), key: key(19), envelope: sealed.envelope });
  assert.equal(wrongKey.threw, false);
  assertRefused(wrongKey.result, 'AUTHENTICATION_FAILED');
  for (const bad of [randomBytes(16), randomBytes(31), randomBytes(33), randomBytes(64), new Uint8Array(32),
    'string-key', 32, null, undefined, {}, [1, 2, 3]]) {
    const refused = attempt(openMappingPayload, { scope: scope(), key: bad, envelope: sealed.envelope });
    assert.equal(refused.threw, false);
    assertRefused(refused.result, 'INVALID_KEY');
    const sealedToo = attempt(sealMappingPayload, { scope: scope(), plaintext, key: bad });
    assert.equal(sealedToo.threw, false);
    assertRefused(sealedToo.result, 'INVALID_KEY');
  }
  plaintext.fill(0);
});

test('a modified nonce, tag or ciphertext byte yields only a fixed failure', () => {
  const plaintext = randomBytes(72);
  const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(23) });
  assertSealed(sealed, plaintext);
  const expected = digest(plaintext);
  const positions = [0, 1, 5, 11];
  for (const field of ['nonce', 'tag', 'ciphertext']) {
    for (const position of positions) {
      if (position >= sealed.envelope[field].byteLength) continue;
      const mutated = new Uint8Array(sealed.envelope[field]);
      mutated[position] ^= 0x01;
      const opened = attempt(openMappingPayload,
        { scope: scope(), key: key(23), envelope: { ...sealed.envelope, [field]: mutated } });
      assert.equal(opened.threw, false, `${field}[${position}] mutation must not throw`);
      assertRefused(opened.result, 'AUTHENTICATION_FAILED');
    }
  }
  // Truncation and extension of the ciphertext body are refused as a malformed record.
  for (const body of [sealed.envelope.ciphertext.subarray(0, 71), new Uint8Array(73)]) {
    const opened = attempt(openMappingPayload,
      { scope: scope(), key: key(23), envelope: { ...sealed.envelope, ciphertext: body } });
    assert.equal(opened.threw, false);
    assertRefused(opened.result, 'AUTHENTICATION_FAILED');
  }
  // A completely replaced ciphertext body of a valid length is also refused.
  const opened = attempt(openMappingPayload,
    { scope: scope(), key: key(23), envelope: { ...sealed.envelope, ciphertext: randomBytes(72) } });
  assertRefused(opened.result, 'AUTHENTICATION_FAILED');
  assert.equal(digest(plaintext), expected);
  plaintext.fill(0);
});

test('a refused open returns no partial plaintext and no native error or cause', () => {
  const plaintext = randomBytes(48);
  const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(29) });
  const attempts = [
    { scope: scope({ tenantId: 'tenant-b.invalid' }), key: key(29), envelope: sealed.envelope },
    { scope: scope(), key: key(31), envelope: sealed.envelope },
    { scope: scope(), key: key(29), envelope: { ...sealed.envelope, tag: randomBytes(16) } },
    { scope: scope(), key: key(29), envelope: { ...sealed.envelope, nonce: randomBytes(12) } },
    { scope: scope(), key: key(29), envelope: { ...sealed.envelope, ciphertext: randomBytes(48) } },
  ];
  for (const request of attempts) {
    const opened = attempt(openMappingPayload, request);
    assert.equal(opened.threw, false);
    assertRefused(opened.result, 'AUTHENTICATION_FAILED');
    const serialized = JSON.stringify(opened.result);
    assert.equal(serialized.length, JSON.stringify({ version: MAPPING_AEAD_VERSION, status: 'REFUSED',
      finding: 'AUTHENTICATION_FAILED' }).length);
    for (const forbidden of ['plaintext', 'bytes', 'cause', 'error', 'message', 'stack', 'errno']) {
      assert.equal(serialized.includes(forbidden), false);
    }
  }
  plaintext.fill(0);
});

test('credential and secret mappings are refused on both directions', () => {
  const plaintext = randomBytes(32);
  const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(37) });
  assertSealed(sealed, plaintext);
  const refused = attempt(sealMappingPayload,
    { scope: scope({ classification: 'CREDENTIAL_OR_SECRET' }), plaintext, key: key(37) });
  assert.equal(refused.threw, false);
  assertRefused(refused.result, 'SECRET_NOT_REVERSIBLE');
  // Even a genuinely sealed envelope cannot be opened under a secret scope label.
  const opened = attempt(openMappingPayload,
    { scope: scope({ classification: 'CREDENTIAL_OR_SECRET' }), key: key(37), envelope: sealed.envelope });
  assert.equal(opened.threw, false);
  assertRefused(opened.result, 'SECRET_NOT_REVERSIBLE');
  plaintext.fill(0);
});

test('a draft or unknown classification label is refused, never silently mapped', () => {
  for (const classification of ['EMAIL', 'SECRET', 'password', 'CREDENTIAL', '', 'UNKNOWN',
    'PERSON ', 'person', 42, null, ['PERSON'], { semanticType: 'PERSON' }]) {
    const refused = attempt(sealMappingPayload,
      { scope: scope({ classification }), plaintext: randomBytes(8), key: key(41) });
    assert.equal(refused.threw, false);
    assertRefused(refused.result, 'INVALID_CONTEXT');
  }
});

test('empty payloads are refused consistently in both directions', () => {
  const refused = attempt(sealMappingPayload, { scope: scope(), plaintext: new Uint8Array(0), key: key(43) });
  assert.equal(refused.threw, false);
  assertRefused(refused.result, 'INVALID_PAYLOAD');
  const sealed = sealMappingPayload({ scope: scope(), plaintext: randomBytes(8), key: key(43) });
  assertSealed(sealed, new Uint8Array(8));
  const empty = attempt(openMappingPayload,
    { scope: scope(), key: key(43), envelope: { ...sealed.envelope, ciphertext: new Uint8Array(0) } });
  assert.equal(empty.threw, false);
  assertRefused(empty.result, 'INVALID_ENVELOPE');
});

test('payload and envelope sizes are bounded at the documented maximum', () => {
  const atLimit = randomBytes(MAPPING_AEAD_LIMITS.plaintextBytes);
  const sealed = sealMappingPayload({ scope: scope(), plaintext: atLimit, key: key(47) });
  const envelope = assertSealed(sealed, atLimit);
  const opened = openMappingPayload({ scope: scope(), key: key(47), envelope });
  assert.equal(opened.status, 'OPENED');
  assert.equal(opened.bytes, MAPPING_AEAD_LIMITS.plaintextBytes);
  assert.equal(digest(opened.plaintext), digest(atLimit));
  opened.plaintext.fill(0);
  atLimit.fill(0);
  const overLimit = randomBytes(MAPPING_AEAD_LIMITS.plaintextBytes + 1);
  const refused = attempt(sealMappingPayload, { scope: scope(), plaintext: overLimit, key: key(47) });
  assert.equal(refused.threw, false);
  assertRefused(refused.result, 'PAYLOAD_TOO_LARGE');
  overLimit.fill(0);
  const large = attempt(openMappingPayload, { scope: scope(), key: key(47),
    envelope: { ...envelope, ciphertext: randomBytes(MAPPING_AEAD_LIMITS.ciphertextBytes + 1) } });
  assert.equal(large.threw, false);
  assertRefused(large.result, 'INVALID_ENVELOPE');
});

test('mutable caller buffers are copied: no alias to a key or plaintext survives the call', () => {
  const plaintext = randomBytes(48);
  const expected = digest(plaintext);
  const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(53) });
  const envelope = assertSealed(sealed, plaintext);
  // The key never appears in the sealed record, in any field.
  const flat = Buffer.concat([Buffer.from(envelope.nonce), Buffer.from(envelope.ciphertext),
    Buffer.from(envelope.tag)]);
  assert.equal(flat.includes(Buffer.from(key(53))), false);
  const keyDigest = digest(key(53));
  assert.notEqual(digest(envelope.nonce), keyDigest);
  assert.notEqual(digest(envelope.tag), keyDigest);
  // The caller wipes its own plaintext afterwards: the sealed record is self-contained.
  plaintext.fill(0);
  const opened = openMappingPayload({ scope: scope(), key: key(53), envelope });
  assert.equal(opened.status, 'OPENED');
  assert.equal(digest(opened.plaintext), expected);
  // The returned plaintext is an independent copy, not a view over the stored ciphertext.
  assert.equal(opened.plaintext === envelope.ciphertext, false);
  assert.equal(opened.plaintext.constructor.name, 'Uint8Array');
  opened.plaintext.fill(0);
  envelope.ciphertext.fill(0);
  const again = openMappingPayload({ scope: scope(), key: key(53),
    envelope: { ...envelope, ciphertext: sealMappingPayload({ scope: scope(), plaintext: randomBytes(48),
      key: key(53) }).envelope.ciphertext } });
  assert.equal(again.status, 'REFUSED');
  // A Buffer key and payload are accepted and never aliased either.
  const bufferKey = Buffer.from(key(59));
  const bufferPlaintext = Buffer.from(randomBytes(24));
  const bufferExpected = digest(bufferPlaintext);
  const bufferSealed = sealMappingPayload({ scope: scope(), plaintext: bufferPlaintext, key: bufferKey });
  assertSealed(bufferSealed, bufferPlaintext);
  assert.equal(bufferSealed.envelope.ciphertext.constructor.name, 'Uint8Array');
  bufferPlaintext.fill(0);
  bufferKey.fill(0);
  const bufferOpened = openMappingPayload({ scope: scope(), key: Buffer.from(key(59)),
    envelope: bufferSealed.envelope });
  assert.equal(digest(bufferOpened.plaintext), bufferExpected);
  bufferOpened.plaintext.fill(0);
});

test('a hostile byte source that changes between reads is snapshotted once', () => {
  let reads = 0;
  const drifting = new Proxy(new Uint8Array(4), {
    get(target, property, receiver) {
      if (property === 'byteLength') return 4;
      if (typeof property === 'string' && /^\d+$/u.test(property)) {
        reads += 1;
        return reads <= 4 ? 0x41 : 0x00;
      }
      return Reflect.get(target, property, receiver);
    },
  });
  const sealed = sealMappingPayload({ scope: scope(), plaintext: drifting, key: key(61) });
  const opened = openMappingPayload({ scope: scope(), key: key(61), envelope: sealed.envelope });
  assert.equal(opened.status, 'OPENED');
  assert.equal(digest(opened.plaintext), digest(Uint8Array.from([0x41, 0x41, 0x41, 0x41])));
  opened.plaintext.fill(0);
});

test('a hostile byte source that yields a non-byte is refused rather than coerced', () => {
  const lying = new Proxy(new Uint8Array(2), {
    get(target, property, receiver) {
      if (property === 'byteLength') return 2;
      if (typeof property === 'string' && /^\d+$/u.test(property)) return 'not-a-byte';
      return Reflect.get(target, property, receiver);
    },
  });
  const refused = attempt(sealMappingPayload, { scope: scope(), plaintext: lying, key: key(67) });
  assert.equal(refused.threw, false);
  assertRefused(refused.result, 'INVALID_PAYLOAD');
});

test('malformed scope records are refused without echoing a planted value', () => {
  const scopes = [
    null, undefined, 'tenant-a.invalid', 7, [], Object.create({ tenantId: 'planted.invalid' }),
    { ...scope(), tenantId: undefined }, { ...scope(), extra: 'field' },
    { ...scope(), tenantId: '' }, { ...scope(), tenantId: ' tenant-a.invalid' },
    { ...scope(), tenantId: 'tenant-a.invalid ' }, { ...scope(), tenantId: 'a'.repeat(129) },
    { ...scope(), tenantId: 'tenant\u0000a.invalid' }, { ...scope(), tenantId: 'planted original' },
    { ...scope(), projectId: 'https://planted.invalid/x' },
    { ...scope(), entityId: 'planted original@person.invalid' },
    { ...scope(), mappingRevision: 'v7' }, { ...scope(), mappingRevision: '-1' },
    { ...scope(), mappingRevision: 7 }, { ...scope(), mappingRevision: '7.0' },
    { ...scope(), keyVersion: 'key-v1' }, { ...scope(), keyVersion: '1.' },
    { ...scope(), keyVersion: '' }, { ...scope(), keyVersion: '1'.repeat(13) },
  ];
  for (const planted of scopes) {
    const refused = attempt(sealMappingPayload,
      { scope: planted, plaintext: randomBytes(8), key: key(71) });
    assert.equal(refused.threw, false, 'a malformed scope must not throw');
    assertRefused(refused.result, 'INVALID_CONTEXT');
    const sealed = sealMappingPayload({ scope: scope(), plaintext: randomBytes(8), key: key(71) });
    const opened = attempt(openMappingPayload, { scope: planted, key: key(71), envelope: sealed.envelope });
    assert.equal(opened.threw, false, 'a malformed expected scope must not throw');
    assertRefused(opened.result, 'INVALID_CONTEXT');
  }
});

test('malformed request records are refused without throwing', () => {
  // The request record itself is structurally wrong: one fixed code, and no partial work.
  for (const planted of [
    null, undefined, 'request', 7, [], Object.create({ scope: scope() }),
    { scope: scope() }, { scope: scope(), plaintext: randomBytes(8) }, { plaintext: randomBytes(8), key: key(73) },
    { scope: scope(), plaintext: randomBytes(8), key: key(73), extra: 1 },
    { scope: scope(), key: key(73) }, { scope: scope(), envelope: { version: 1, nonce: new Uint8Array(12),
      ciphertext: new Uint8Array(8), tag: new Uint8Array(16) } },
  ]) {
    const refused = attempt(sealMappingPayload, planted);
    assert.equal(refused.threw, false);
    assertRefused(refused.result, 'INVALID_INPUT');
  }
  // A wrong payload type is refused as a payload, not as the request record.
  for (const planted of [
    { scope: scope(), plaintext: 'bytes', key: key(73) }, { scope: scope(), plaintext: [1, 2, 3], key: key(73) },
    { scope: scope(), plaintext: new ArrayBuffer(8), key: key(73) },
    { scope: scope(), plaintext: new DataView(new ArrayBuffer(8)), key: key(73) },
  ]) {
    const refused = attempt(sealMappingPayload, planted);
    assert.equal(refused.threw, false);
    assertRefused(refused.result, 'INVALID_PAYLOAD');
  }
  const sealed = sealMappingPayload({ scope: scope(), plaintext: randomBytes(8), key: key(73) });
  assertSealed(sealed, new Uint8Array(8));
  const openRecords = [
    null, undefined, 'request', 7, [], Object.create({ scope: scope() }),
    { scope: scope(), key: key(73) }, { key: key(73), envelope: sealed.envelope },
    { scope: scope(), key: key(73), envelope: sealed.envelope, extra: 1 },
  ];
  for (const planted of openRecords) {
    const refused = attempt(openMappingPayload, planted);
    assert.equal(refused.threw, false);
    assertRefused(refused.result, 'INVALID_INPUT');
  }
  const openEnvelopes = [
    { scope: scope(), key: key(73), envelope: null }, { scope: scope(), key: key(73), envelope: [] },
    { scope: scope(), key: key(73), envelope: 'envelope' },
    { scope: scope(), key: key(73), envelope: { ...sealed.envelope, version: 2 } },
    { scope: scope(), key: key(73), envelope: { ...sealed.envelope, version: '1' } },
    { scope: scope(), key: key(73), envelope: { ...sealed.envelope, nonce: randomBytes(11) } },
    { scope: scope(), key: key(73), envelope: { ...sealed.envelope, nonce: randomBytes(13) } },
    { scope: scope(), key: key(73), envelope: { ...sealed.envelope, nonce: 'nonce' } },
    { scope: scope(), key: key(73), envelope: { ...sealed.envelope, tag: randomBytes(15) } },
    { scope: scope(), key: key(73), envelope: { ...sealed.envelope, tag: randomBytes(17) } },
    { scope: scope(), key: key(73), envelope: { ...sealed.envelope, tag: 'tag' } },
    { scope: scope(), key: key(73), envelope: { ...sealed.envelope, ciphertext: 'body' } },
    { scope: scope(), key: key(73), envelope: { ...sealed.envelope, extra: new Uint8Array(1) } },
    { scope: scope(), key: key(73), envelope: { nonce: sealed.envelope.nonce,
      ciphertext: sealed.envelope.ciphertext, tag: sealed.envelope.tag } },
    { scope: scope(), key: key(73), envelope: Object.create(sealed.envelope) },
  ];
  for (const planted of openEnvelopes) {
    const refused = attempt(openMappingPayload, planted);
    assert.equal(refused.threw, false);
    assertRefused(refused.result, 'INVALID_ENVELOPE');
  }
});

test('an accessor property is refused: only own data descriptors are read', () => {
  let touched = 0;
  const accessorScope = scope();
  Object.defineProperty(accessorScope, 'tenantId', { enumerable: true, get() { touched += 1; return 'planted.invalid'; } });
  const refused = attempt(sealMappingPayload, { scope: accessorScope, plaintext: randomBytes(8), key: key(79) });
  assert.equal(refused.threw, false);
  assertRefused(refused.result, 'INVALID_CONTEXT');
  assert.equal(touched, 0, 'an accessor must never be invoked');
  let requestTouched = 0;
  const accessorRequest = { scope: scope(), key: key(79), get plaintext() { requestTouched += 1; return new Uint8Array(4); } };
  const refusedRequest = attempt(sealMappingPayload, accessorRequest);
  assert.equal(refusedRequest.threw, false);
  assertRefused(refusedRequest.result, 'INVALID_INPUT');
  assert.equal(requestTouched, 0, 'an accessor must never be invoked');
});

test('a throwing proxy for the request object is a fixed refusal, not an escaped error', () => {
  const hostile = new Proxy({ scope: scope(), plaintext: randomBytes(8), key: key(83) }, {
    ownKeys() { throw new Error('planted-proxy-detail'); },
  });
  const refused = attempt(sealMappingPayload, hostile);
  assert.equal(refused.threw, false);
  assertRefused(refused.result, 'INVALID_INPUT');
  const hostileKey = new Proxy({}, { get() { throw new Error('planted-key-detail'); } });
  const refusedKey = attempt(sealMappingPayload, { scope: scope(), plaintext: randomBytes(8), key: hostileKey });
  assert.equal(refusedKey.threw, false);
  assertRefused(refusedKey.result, 'INVALID_KEY');
});

test('the sealed record authenticates under an identical, independently built scope', () => {
  const plaintext = randomBytes(64);
  const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(89) });
  // Same field values, different object identity and key order: the AAD serialization is canonical.
  const reordered = Object.fromEntries(Object.entries(scope()).reverse());
  const opened = openMappingPayload({ scope: reordered, key: key(89), envelope: sealed.envelope });
  assert.equal(opened.status, 'OPENED');
  assert.equal(digest(opened.plaintext), digest(plaintext));
  // A frozen sealed record and a frozen expected scope are ordinary values, not refusals.
  const frozen = Object.freeze({ ...scope() });
  const alsoOpened = openMappingPayload({ scope: frozen, key: Uint8Array.from(key(89)),
    envelope: Object.freeze(sealed.envelope) });
  assert.equal(alsoOpened.status, 'OPENED');
  assert.equal(digest(alsoOpened.plaintext), digest(plaintext));
  plaintext.fill(0);
  opened.plaintext.fill(0);
  alsoOpened.plaintext.fill(0);
});

test('generated synthetic cases roundtrip and any single-byte corruption fails', () => {
  for (let round = 0; round < 24; round += 1) {
    const size = 1 + Math.floor(randomBytes(1)[0] % 512);
    const plaintext = randomBytes(size);
    const expected = digest(plaintext);
    const sealScope = scope({
      tenantId: `tenant-${round % 3}.invalid`,
      projectId: `project-${round % 2}.invalid`,
      entityId: `entity-${round}-${size}`,
      classification: SEMANTIC_CLASSES[round % SEMANTIC_CLASSES.length] === 'CREDENTIAL_OR_SECRET'
        ? 'PERSON' : SEMANTIC_CLASSES[round % SEMANTIC_CLASSES.length],
      mappingRevision: String(round + 1),
      keyVersion: `${round + 1}.${round % 3}`,
    });
    const sealKey = randomBytes(32);
    const sealed = sealMappingPayload({ scope: sealScope, plaintext, key: sealKey });
    const envelope = assertSealed(sealed, plaintext);
    const opened = openMappingPayload({ scope: sealScope, key: sealKey, envelope });
    assert.equal(opened.status, 'OPENED');
    assert.equal(digest(opened.plaintext), expected);
    const corrupted = new Uint8Array(envelope.ciphertext);
    corrupted[randomBytes(1)[0] % size] ^= 0xff;
    const refused = attempt(openMappingPayload, { scope: sealScope, key: sealKey,
      envelope: { ...envelope, ciphertext: corrupted } });
    assert.equal(refused.threw, false);
    assertRefused(refused.result, 'AUTHENTICATION_FAILED');
    const foreignKey = attempt(openMappingPayload, { scope: sealScope, key: randomBytes(32), envelope });
    assertRefused(foreignKey.result, 'AUTHENTICATION_FAILED');
    plaintext.fill(0);
    sealKey.fill(0);
    opened.plaintext.fill(0);
  }
});

test('the same request yields the same refusal every time', () => {
  const plaintext = randomBytes(16);
  const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(97) });
  const request = { scope: scope({ tenantId: 'tenant-b.invalid' }), key: key(97), envelope: sealed.envelope };
  const serialized = new Set();
  for (let round = 0; round < 5; round += 1) {
    const opened = attempt(openMappingPayload, request);
    assert.equal(opened.threw, false);
    assertRefused(opened.result, 'AUTHENTICATION_FAILED');
    serialized.add(JSON.stringify(opened.result));
  }
  assert.equal(serialized.size, 1, 'a refusal must be byte-identical across repeats');
  plaintext.fill(0);
});

test('a declared byte length is a primitive safe integer before anything is allocated', () => {
  // A byte source that claims an oversized length through an object is the reviewed bypass: an
  // object compares false against the cap and still allocates. Every claim below must be refused as
  // a malformed byte source, with no allocation and no seal.
  const oversizedClaims = [
    { length: MAPPING_AEAD_LIMITS.plaintextBytes + 1, valueOf: () => 0 },
    { length: MAPPING_AEAD_LIMITS.ciphertextBytes + 1, valueOf: () => 0 },
    { length: Number.MAX_SAFE_INTEGER, valueOf: () => 0 },
    { length: MAPPING_AEAD_LIMITS.plaintextBytes + 1, toString: () => '0' },
  ];
  const malformedClaims = [undefined, null, '8', 8n, -1, -0.5, 1.5, Number.NaN,
    Number.POSITIVE_INFINITY, true, {}, [], () => 8, Symbol.iterator];
  for (const claim of [...oversizedClaims, ...malformedClaims]) {
    const refused = attempt(sealMappingPayload,
      { scope: scope(), plaintext: declaring(new Uint8Array(4), claim), key: key(101) });
    assert.equal(refused.threw, false, 'a declared length must never throw');
    assertRefused(refused.result, 'INVALID_PAYLOAD');
    const refusedKey = attempt(sealMappingPayload,
      { scope: scope(), plaintext: randomBytes(8), key: declaring(key(101), claim) });
    assert.equal(refusedKey.threw, false, 'a declared key length must never throw');
    assertRefused(refusedKey.result, 'INVALID_KEY');
  }
  // The sealed record's own byte fields obey the same rule, and a hostile claim there is a
  // malformed record rather than an un-authenticated body.
  const sealed = sealMappingPayload({ scope: scope(), plaintext: randomBytes(8), key: key(101) });
  assertSealed(sealed, new Uint8Array(8));
  for (const field of ['nonce', 'ciphertext', 'tag']) {
    for (const claim of [...oversizedClaims, ...malformedClaims]) {
      const forged = { ...sealed.envelope, [field]: declaring(sealed.envelope[field], claim) };
      const opened = attempt(openMappingPayload, { scope: scope(), key: key(101), envelope: forged });
      assert.equal(opened.threw, false, `a declared ${field} length must never throw`);
      assertRefused(opened.result, 'INVALID_ENVELOPE');
    }
  }
  // A source that declares its true length is untouched by the rule, and a genuine oversized
  // primitive number is still `PAYLOAD_TOO_LARGE` rather than a malformed source.
  const honest = sealMappingPayload({ scope: scope(), plaintext: declaring(new Uint8Array(16), 16),
    key: key(101) });
  assertSealed(honest, new Uint8Array(16));
  const oversized = attempt(sealMappingPayload,
    { scope: scope(), plaintext: randomBytes(MAPPING_AEAD_LIMITS.plaintextBytes + 1), key: key(101) });
  assert.equal(oversized.threw, false);
  assertRefused(oversized.result, 'PAYLOAD_TOO_LARGE');
});

test('a hostile thrown Proxy is one fixed refusal, never an error this boundary throws', () => {
  const planted = 'planted-thrown-proxy-detail';
  // `hostile` throws a plain error carrying obviously synthetic planted text; the returned value is
  // then itself a Proxy whose prototype read throws again. Every case below is asserted through
  // `attempt`, so that planted text can never reach TAP even while the boundary is still wrong.
  const hostile = () => new Proxy({}, { getPrototypeOf() { throw new Error(planted); } });
  // First, the case the review reported: a byte source whose length read throws a hostile value.
  // Reflective identification of that value is what let a caller-controlled error escape, so this
  // is the assertion that carries the reviewed defect.
  const throwingLength = () => new Proxy(new Uint8Array(4), {
    get(target, property, receiver) {
      if (property === 'byteLength') throw hostile();
      return Reflect.get(target, property, receiver);
    },
  });
  // The count makes the reachability of the index trap observable. Without it a proxy whose
  // `byteLength` accessor throws first would produce the same fixed refusal, and this case would
  // pass for the wrong reason instead of exercising the hostile index read.
  const elementTraps = { count: 0 };
  const throwingElement = () => new Proxy(new Uint8Array(4), {
    get(target, property) {
      if (typeof property === 'string' && /^\d+$/u.test(property)) {
        elementTraps.count += 1;
        throw hostile();
      }
      // Forwarded with the real target as the receiver on purpose: a typed-array accessor such as
      // `byteLength` validates its receiver, so passing the Proxy rejects it natively before any
      // index read and the index trap above would never run. With the target as receiver the
      // declared length succeeds and the hostile index read is what the boundary has to contain.
      return Reflect.get(target, property, target);
    },
  });
  const refusedPayload = attempt(sealMappingPayload,
    { scope: scope(), plaintext: throwingLength(), key: key(103) });
  assert.equal(refusedPayload.threw, false, 'a throwing byteLength must not throw out of the boundary');
  assertRefused(refusedPayload.result, 'INVALID_PAYLOAD');
  const refusedElement = attempt(sealMappingPayload,
    { scope: scope(), plaintext: throwingElement(), key: key(103) });
  assert.equal(refusedElement.threw, false, 'a throwing element read must not throw out of the boundary');
  assertRefused(refusedElement.result, 'INVALID_PAYLOAD');
  assert.ok(elementTraps.count > 0, 'the hostile index trap must be the trap that was reached');
  assert.equal(JSON.stringify(refusedElement.result).includes(planted), false);
  const refusedKey = attempt(sealMappingPayload,
    { scope: scope(), plaintext: randomBytes(8), key: throwingLength() });
  assert.equal(refusedKey.threw, false, 'a throwing key length must not throw out of the boundary');
  assertRefused(refusedKey.result, 'INVALID_KEY');
  const hostileKey = attempt(sealMappingPayload,
    { scope: scope(), plaintext: randomBytes(8), key: declaring(key(103), hostile()) });
  assert.equal(hostileKey.threw, false, 'a hostile key length must not throw out of the boundary');
  assertRefused(hostileKey.result, 'INVALID_KEY');
  // The same rule inside a sealed record: a hostile read is a malformed record, not an escape.
  const sealed = sealMappingPayload({ scope: scope(), plaintext: randomBytes(8), key: key(103) });
  assertSealed(sealed, new Uint8Array(8));
  for (const field of ['nonce', 'ciphertext', 'tag']) {
    for (const [label, build] of [['length', throwingLength], ['element', throwingElement]]) {
      const opened = attempt(openMappingPayload, { scope: scope(), key: key(103),
        envelope: { ...sealed.envelope, [field]: build() } });
      assert.equal(opened.threw, false, `a throwing ${field} ${label} must not throw out of the boundary`);
      assertRefused(opened.result, 'INVALID_ENVELOPE');
      assert.equal(JSON.stringify(opened.result).includes(planted), false);
    }
  }
  // Then the request record's own reflective traps, whose hostile values used to escape the inner
  // reader and surface as an unrelated fallback code at the outer boundary.
  for (const name of ['ownKeys', 'getPrototypeOf', 'getOwnPropertyDescriptor']) {
    const refused = attempt(sealMappingPayload, new Proxy(
      { scope: scope(), plaintext: randomBytes(8), key: key(103) }, { [name]: () => { throw hostile(); } }));
    assert.equal(refused.threw, false, `a hostile ${name} trap must not throw out of the boundary`);
    assertRefused(refused.result, 'INVALID_INPUT');
    assert.equal(JSON.stringify(refused.result).includes(planted), false);
  }
  // A hostile value in a position that is checked structurally never reaches a trap at all.
  for (const planted_scope of [
    { ...scope(), tenantId: hostile() }, { ...scope(), classification: hostile() },
    { ...scope(), mappingRevision: hostile() },
  ]) {
    const refused = attempt(sealMappingPayload,
      { scope: planted_scope, plaintext: randomBytes(8), key: key(103) });
    assert.equal(refused.threw, false, 'a hostile scope field must not throw out of the boundary');
    assertRefused(refused.result, 'INVALID_CONTEXT');
    const opened = attempt(openMappingPayload,
      { scope: planted_scope, key: key(103), envelope: sealed.envelope });
    assert.equal(opened.threw, false, 'a hostile expected scope field must not throw out of the boundary');
    assertRefused(opened.result, 'INVALID_CONTEXT');
  }
});

test('clearing owned transient buffers never wipes a returned or caller-supplied buffer', () => {
  const plaintext = randomBytes(48);
  const expected = digest(plaintext);
  const sealed = sealMappingPayload({ scope: scope(), plaintext, key: key(107) });
  const envelope = assertSealed(sealed, plaintext);
  const record = {
    nonce: digest(envelope.nonce), ciphertext: digest(envelope.ciphertext), tag: digest(envelope.tag),
  };
  // A refused open leaves every caller buffer byte-for-byte intact.
  for (const request of [
    { scope: scope({ tenantId: 'tenant-b.invalid' }), key: key(107), envelope: sealed.envelope },
    { scope: scope(), key: key(109), envelope: sealed.envelope },
    { scope: scope(), key: key(107), envelope: { ...envelope, tag: randomBytes(16) } },
    { scope: scope(), key: key(107), envelope: { ...envelope, ciphertext: randomBytes(48) } },
  ]) {
    const refused = attempt(openMappingPayload, request);
    assert.equal(refused.threw, false);
    assertRefused(refused.result, 'AUTHENTICATION_FAILED');
    assert.equal(digest(envelope.nonce), record.nonce, 'a refusal must not touch the caller record');
    assert.equal(digest(envelope.ciphertext), record.ciphertext, 'a refusal must not touch the caller record');
    assert.equal(digest(envelope.tag), record.tag, 'a refusal must not touch the caller record');
  }
  // A successful open hands back a buffer no later open and no internal copy shares: wiping it
  // leaves a second open of the same record intact and still byte-exact.
  const first = openMappingPayload({ scope: scope(), key: key(107), envelope });
  assert.equal(first.status, 'OPENED');
  first.plaintext.fill(0);
  const second = openMappingPayload({ scope: scope(), key: key(107), envelope });
  assert.equal(second.status, 'OPENED');
  assert.equal(digest(second.plaintext), expected, 'a returned buffer must not alias a later open');
  second.plaintext.fill(0);
  // The caller's own payload and key survive both directions untouched.
  assert.equal(digest(plaintext), expected, 'a seal must not touch the caller payload');
  const callerPayload = randomBytes(24);
  const callerDigest = digest(callerPayload);
  const refused = attempt(sealMappingPayload, { scope: scope({ classification: 'CREDENTIAL_OR_SECRET' }),
    plaintext: callerPayload, key: key(107) });
  assert.equal(refused.threw, false);
  assertRefused(refused.result, 'SECRET_NOT_REVERSIBLE');
  assert.equal(digest(callerPayload), callerDigest, 'a refusal must not touch the caller payload');
  callerPayload.fill(0);
  plaintext.fill(0);
});

test('the module exposes only the primitive surface', async () => {
  const module = await import('../dist/mapping-aead.js');
  const names = Object.keys(module).sort();
  assert.deepEqual(names, ['MAPPING_AEAD_FINDINGS', 'MAPPING_AEAD_LIMITS', 'MAPPING_AEAD_REFUSALS',
    'MAPPING_AEAD_VERSION', 'openMappingPayload', 'sealMappingPayload']);
  // No key-management, broker, storage or policy surface exists in this module.
  for (const forbidden of ['unwrapKey', 'wrapKey', 'generateKey', 'resolve', 'authorize', 'lookup',
    'store', 'encryptDeterministic', 'blindIndex']) {
    assert.equal(names.includes(forbidden), false);
  }
});
