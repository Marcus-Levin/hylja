import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  checkEgress, createKnownOriginals, createStreamGate, sentinelUnavailable, MAX_MESSAGE_BYTES,
} from '../dist/egress-sentinel.js';
import { detectSecrets } from '../dist/secret-detectors.js';

// Synthetic only. Planted originals and canaries are invented; token shapes are assembled at runtime.
const scopeA = Object.freeze({ tenantRef: 'tenant-a.invalid', projectRef: 'project-a.invalid' });
const scopeB = Object.freeze({ tenantRef: 'tenant-b.invalid', projectRef: 'project-b.invalid' });
const key = new Uint8Array(32).fill(9);
const destination = Object.freeze({ id: 'model-gateway.invalid', profileDigest: 'sha256-profile-synthetic' });
const PLANTED = 'Orla Synthetica';
const HOST = 'plc-gateway-07.tenant-a.invalid';
const CANARY = 'canary-7f3a-synthetic-honeytoken';
const known = createKnownOriginals(scopeA, key, [
  { kind: 'ORIGINAL', value: PLANTED, ref: 'planted.person.1' },
  { kind: 'ORIGINAL', value: HOST, ref: 'planted.host.1' },
  { kind: 'ORIGINAL', value: 'Orla', ref: 'planted.alias.1' },
  { kind: 'CANARY', value: CANARY, ref: 'canary.1' },
]);
const enc = (text) => new TextEncoder().encode(text);
const check = (text, more = {}) => checkEgress({ bytes: typeof text === 'string' ? enc(text) : text, scope: scopeA, destination,
  authorized: destination, known, ...more });
const b64 = (text) => Buffer.from(text, 'utf8').toString('base64');

test('a clean payload to the authorized destination is allowed', () => {
  const result = check(JSON.stringify({ model: 'synthetic', messages: [{ role: 'user', content: 'Why does HTTPS on 443 fail for HOST_12?' }] }));
  assert.deepEqual([result.decision, result.reasons, result.findings], ['ALLOW', [], []]);
});

test('a planted original deliberately missed upstream is blocked before send', () => {
  const payload = JSON.stringify({ messages: [{ role: 'user', content: `Escalate to ${PLANTED} about ${HOST}` }] });
  // The primary detector stack does not know these values: the upstream miss is real.
  assert.deepEqual(detectSecrets({ text: payload, inputRef: 'x' }).candidates, []);
  const result = check(payload);
  assert.equal(result.decision, 'BLOCK');
  assert.deepEqual(result.reasons, ['KNOWN_ORIGINAL_DETECTED']);
  assert.deepEqual(result.findings.map((f) => f.rule).sort(), ['planted.alias.1', 'planted.host.1', 'planted.person.1']);
});

test('encoded, escaped, case-folded and separator-split variants of an original are blocked', () => {
  const variants = [
    `{"c":"${PLANTED.toUpperCase()}"}`, `{"c":"${[...PLANTED].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')}"}`,
    `<p>${[...HOST].map((c) => `&#${c.charCodeAt(0)};`).join('')}</p>`, `data=${b64(`note: ${HOST}`)}`, `q=${encodeURIComponent(HOST)}`,
    `x=${Buffer.from(HOST).toString('hex')}`, 'ｏｒｌａ　ｓｙｎｔｈｅｔｉｃａ', 'plc-gateway-07 . tenant-a . invalid',
    'p​l​c-gateway-07.tenant-a.invalid', `{"c":"${b64(`\\u004frla Synthetica`)}"}`,
  ];
  for (const payload of variants) assert.equal(check(payload).decision, 'BLOCK', payload);
});

test('short originals match whole tokens only (no false block inside longer words)', () => {
  assert.equal(check('the colorlab reported orlando values').decision, 'ALLOW');
  assert.equal(check('ask orla today').decision, 'BLOCK');
});

test('canaries are reported as canaries', () => {
  const result = check(`log line ${CANARY}`);
  assert.equal(result.decision, 'BLOCK');
  assert.deepEqual(result.reasons, ['CANARY_DETECTED']);
  assert.equal(result.findings[0].kind, 'CANARY');
});

test('independent high-risk patterns block without any known originals', () => {
  const github = ['gh', 'p_', 'Synthetic0'.repeat(4)].join('');
  const aws = ['AK', 'IA', 'SYNTHETIC0000000'].join('');
  for (const payload of [`token ${github}`, `id ${aws}`, ['-----BEGIN ', 'PRIVATE KEY-----'].join(''),
    'Authorization: Bearer synthetic-bearer-value', `k=${b64(`key ${aws}`)}`]) {
    const result = checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
    assert.equal(result.decision, 'BLOCK', payload);
    assert.ok(result.reasons.includes('HIGH_RISK_PATTERN'));
  }
});

test('opaque, uninspectable and oversized content is blocked, never presumed clean', () => {
  assert.deepEqual(check(Uint8Array.from([0x7b, 0xff, 0xfe, 0x7d])).reasons, ['OPAQUE_CONTENT']);
  let nested = PLANTED;
  for (let i = 0; i < 6; i++) nested = b64(`layer:${nested}`);
  assert.ok(check(`x=${nested}`).reasons.includes('UNINSPECTED_CONTENT'));
  assert.deepEqual(check(new Uint8Array(MAX_MESSAGE_BYTES + 1)).reasons, ['MESSAGE_TOO_LARGE']);
});

test('destination or profile mismatch blocks even a clean payload', () => {
  for (const authorized of [{ ...destination, id: 'other.invalid' }, { ...destination, profileDigest: 'sha256-other' }, null, { id: '' }]) {
    assert.deepEqual(check('clean text', { authorized }).reasons, ['DESTINATION_MISMATCH']);
  }
});

test('known originals are tenant-scoped; forged or foreign handles block', () => {
  assert.deepEqual(check('clean text', { scope: scopeB }).reasons, ['KNOWN_ORIGINALS_SCOPE_MISMATCH']);
  assert.deepEqual(check('clean text', { known: { values: [PLANTED] } }).reasons, ['KNOWN_ORIGINALS_INVALID']);
});

test('outage and internal errors are restrictive', () => {
  assert.deepEqual(sentinelUnavailable().decision, 'BLOCK');
  const hostile = { get bytes() { throw new Error('synthetic'); } };
  assert.deepEqual(checkEgress(hostile).reasons, ['SENTINEL_ERROR']);
  assert.deepEqual(checkEgress(null).reasons, ['SENTINEL_ERROR']);
});

test('streaming: a value split across chunks is caught and nothing is released before the check', () => {
  const payload = enc(`data: {"delta":"escalate to ${PLANTED} now"}\n\n`);
  const gate = createStreamGate({ scope: scopeA, destination, authorized: destination, known });
  for (let offset = 0; offset < payload.length; offset += 3) assert.deepEqual(gate.push(payload.subarray(offset, offset + 3)), { accepted: true });
  const { result, release } = gate.end();
  assert.equal(result.decision, 'BLOCK');
  assert.equal(release, undefined);
  const clean = createStreamGate({ scope: scopeA, destination, authorized: destination, known });
  clean.push(enc('hello '));
  clean.push(enc('world'));
  const ok = clean.end();
  assert.equal(ok.result.decision, 'ALLOW');
  assert.equal(new TextDecoder().decode(ok.release), 'hello world');
  assert.deepEqual(ok.result.findings, []);
  const small = createStreamGate({ scope: scopeA, destination, authorized: destination, known: null }, 4);
  small.push(enc('12345'));
  assert.deepEqual(small.end().result.reasons, ['STREAM_REJECTED']);
  assert.deepEqual(small.end().result.reasons, ['STREAM_ALREADY_ENDED']);
});

test('results, regression records and errors never contain payload bytes or originals', () => {
  const result = check(`{"c":"${PLANTED} ${HOST} ${CANARY}"}`);
  const serialized = JSON.stringify(result);
  for (const value of ['Orla', 'orla', 'plc-gateway', CANARY]) assert.ok(!serialized.includes(value), value);
  assert.deepEqual(Object.keys(result.regression).sort(), ['reasons', 'rules', 'version', 'views']);
  assert.throws(() => createKnownOriginals(scopeA, key, [{ kind: 'ORIGINAL', value: 'ab', ref: 'short.1' }]),
    (error) => error.message === 'Invalid known-originals configuration' && !String(error.stack).includes('ab"'));
  assert.throws(() => createKnownOriginals(scopeA, new Uint8Array(8), []), TypeError);
  // The handle exposes nothing.
  assert.deepEqual(Object.getOwnPropertyNames(known), []);
});

test('review: shared-prefix entries and adversarial payloads stay within a bounded-work budget', () => {
  const many = createKnownOriginals(scopeA, key, [
    ...Array.from({ length: 2000 }, (_, i) => ({ kind: 'ORIGINAL', value: `synthetic-original-${i}-value`, ref: `o.${i}` })),
    ...Array.from({ length: 1000 }, (_, i) => ({ kind: 'ORIGINAL', value: `plc-gateway-${i}.tenant-a.invalid`, ref: `h.${i}` })),
    ...Array.from({ length: 500 }, (_, i) => ({ kind: 'ORIGINAL', value: `jo ${i + 100}`, ref: `s.${i}` })),
  ]);
  for (const text of ['synthetic original '.repeat(55_000), 'plc gatew '.repeat(100_000), 'jo x '.repeat(200_000), 'orla '.repeat(200_000),
    '\\u0041 '.repeat(140_000), 'synthetic original 1 value '.repeat(38_000)]) {
    const started = process.hrtime.bigint();
    const result = checkEgress({ bytes: enc(text.slice(0, MAX_MESSAGE_BYTES)), scope: scopeA, destination, authorized: destination, known: many });
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(['ALLOW', 'BLOCK'].includes(result.decision));
    assert.ok(!result.reasons.includes('UNINSPECTED_CONTENT'), 'timing input must reach matching');
    assert.ok(elapsedMs < 5000, `${text.slice(0, 12)} ${elapsedMs}ms`);
  }
  // A real planted value among many shared-prefix entries is still found.
  assert.equal(checkEgress({ bytes: enc('note plc-gateway-777.tenant-a.invalid'), scope: scopeA, destination, authorized: destination, known: many }).decision, 'BLOCK');
});

test('review: multi-layer escapes, entity variants, octal, %u, quoted-printable, marks and homoglyphs are all blocked', () => {
  const u = (text) => [...text].map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  const variants = [
    `{"c":"${u(PLANTED).replace(/\\/gu, '\\\\')}"}`, `{"c":"${u(b64(`note ${PLANTED}`))}"}`,
    [...PLANTED].map((c) => `&#92;u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
    [...PLANTED].map((c) => `&#X${c.charCodeAt(0).toString(16).toUpperCase()};`).join(''), [...PLANTED].map((c) => `&#${c.charCodeAt(0)} `).join(''),
    [...PLANTED].map((c) => `\\${c.charCodeAt(0).toString(8)}`).join(''), [...PLANTED].map((c) => `%u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join(''),
    [...PLANTED].map((c) => `=${c.charCodeAt(0).toString(16).toUpperCase()}`).join(''), 'Órla Synthetica', 'orlá today',
    'Оrla Synthetica', 'o r l a', 'o.r.l.a',
  ];
  for (const payload of variants) assert.equal(check(payload).decision, 'BLOCK', payload);
  const accented = createKnownOriginals(scopeA, key, [{ kind: 'ORIGINAL', value: 'Zoë Examplé', ref: 'acc.1' }, { kind: 'ORIGINAL', value: '192.0.2.10', ref: 'ip.1' }]);
  for (const payload of ['Zoe Example', 'ZOË EXAMPLÉ', 'host 192.000.002.010']) {
    assert.equal(checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: accented }).decision, 'BLOCK', payload);
  }
});

test('review: case-sensitive patterns survive zero-width and full-width tricks; new pattern families', () => {
  const aws = ['AK', 'IA', 'SYNTHETIC0000000'].join('');
  const payloads = [`${aws.slice(0, 2)}​${aws.slice(2)}`, [...aws].map((c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0)).join(''),
    `id=${aws}_x`, ['-----BEGIN ', 'PRIVATE KEY-----'].join('').replace(/[A-Z]/gu, (c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0)),
    `key ${['sk', '-proj-', 'Synthetic0'.repeat(3)].join('')}`, `npmrc ${['np', 'm_', 'Synthetic0'.repeat(4).slice(0, 36)].join('')}`,
    'postgres://svc:synthetic-pass@db.example.invalid/app', 'password=synthetic-literal-value',
    '{"headers":{"Authorization":"Bearer synthetic-bearer-value"}}'];
  for (const payload of payloads) {
    assert.equal(checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null }).decision, 'BLOCK', payload);
  }
  for (const payload of ['password: ${DB_PASSWORD}', '{"max_tokens": 4096}', 'token: <redacted>']) {
    assert.equal(checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null }).decision, 'ALLOW', payload);
  }
});

test('review: embedded opaque binary is blocked; ordinary hashes are not', () => {
  const binary = Buffer.concat([Buffer.from([0x1f, 0x8b, 8, 0]), Buffer.alloc(200, 7)]).toString('base64');
  assert.deepEqual(check(`{"att":"${binary}"}`).reasons, ['OPAQUE_EMBEDDED']);
  const scattered = Buffer.from('\u0000\u0001orla\u0003Synthe\u0007tica').toString('base64');
  assert.equal(check(`x=${scattered}`).decision, 'BLOCK');
  assert.equal(check('commit 3f2a1b9c0d4e5f60718293a4b5c6d7e8a9b0c1d2 ok').decision, 'ALLOW');
});

test('review: missing known-originals handle, lying destinations and hostile streams fail closed; release is a private copy', () => {
  assert.deepEqual(checkEgress({ bytes: enc('clean'), scope: scopeA, destination, authorized: destination }).reasons, ['KNOWN_ORIGINALS_REQUIRED']);
  let reads = 0;
  const lying = { get id() { return reads++ === 0 ? 'evil.invalid' : destination.id; }, profileDigest: destination.profileDigest };
  assert.equal(check('clean', { destination: lying }).decision, 'BLOCK');
  const bytes = enc('clean text');
  const result = check(bytes);
  assert.equal(result.decision, 'ALLOW');
  bytes.fill(0);
  assert.equal(new TextDecoder().decode(result.release), 'clean text');
  class Liar extends Uint8Array { get length() { return 1e9; } }
  const gate = createStreamGate({ scope: scopeA, destination, authorized: destination, known });
  gate.push(new Liar(4));
  assert.ok(['ALLOW', 'BLOCK'].includes(gate.end().result.decision));
  const throwing = createStreamGate({ get scope() { throw new Error('synthetic'); }, destination, authorized: destination, known });
  throwing.push(enc('x'));
  assert.equal(throwing.end().result.decision, 'BLOCK');
});

test('second review: ordinary prose, code, ids and digests are allowed', () => {
  const uuid = '123e4567-e89b-12d3-a456-426614174000';
  for (const payload of ['Consider all combinations of inputs.', `ids ${Array.from({ length: 600 }, () => uuid).join(',')}`,
    `sha512 ${'ab'.repeat(64)}`, `https://docs.example.invalid/${'section-name_part/'.repeat(10)}`, `id ${'snake_case_identifier_'.repeat(8)}`,
    'call alphaBetaGammaDeltaHandler now', 'interface Login { password: string; secret: boolean }', '{"secret": false}',
    'const secret = process.env.SECRET_VALUE', 'password = config.db.password']) {
    const result = checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
    assert.equal(result.decision, 'ALLOW', `${payload.slice(0, 50)} ${result.reasons}`);
  }
});

test('second review: zero padding inside tokens, split short values and escape families are blocked', () => {
  for (const payload of ['reach plc-gateway07.tenant-a.invalid', 'plcgateway07tenantainvalid', 'ask Or la today']) {
    assert.equal(check(payload).decision, 'BLOCK', payload);
  }
  const shorts = createKnownOriginals(scopeA, key, [{ kind: 'ORIGINAL', value: 'Orla K', ref: 's.1' }, { kind: 'ORIGINAL', value: 'A Tan', ref: 's.2' },
    { kind: 'ORIGINAL', value: '10.0.0.1', ref: 's.3' }]);
  for (const payload of ['contact Orla K J today', 'Orla K. a lot', 'met B A Tan', 'ping 10.0.0.1 x', '\\4F rla K', 'x \\U0000004Frla K', 'օrla K']) {
    assert.equal(checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: shorts }).decision, 'BLOCK', payload);
  }
});

test('second review: many distinct lengths in one prefix bucket hit the probe budget, not unbounded work', () => {
  const entries = Array.from({ length: 1000 }, (_, i) => ({ kind: 'ORIGINAL', value: `plcgatew${'q'.repeat(i + 1)}z`, ref: `l.${i}` }));
  const lengths = createKnownOriginals(scopeA, key, entries);
  const started = process.hrtime.bigint();
  const result = checkEgress({ bytes: enc('plcgatew '.repeat(116_000).slice(0, MAX_MESSAGE_BYTES)), scope: scopeA, destination, authorized: destination, known: lengths });
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000);
  assert.ok(['ALLOW', 'BLOCK'].includes(result.decision));
});

test('second review: the checked copy ignores an overridden iterator', () => {
  const aws = ['AK', 'IA', 'SYNTHETIC0000000'].join('');
  class Sneaky extends Uint8Array { *[Symbol.iterator]() { yield 104; yield 105; } }
  const sneaky = new Sneaky(enc(`key ${aws}`));
  const result = checkEgress({ bytes: sneaky, scope: scopeA, destination, authorized: destination, known: null });
  assert.equal(result.decision, 'BLOCK');
});

test('third review: compressed or opaque binary is blocked however it is chunked or wrapped', async () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const secret = `contact ${PLANTED} re ${CANARY}`;
  const gz = zlib.gzipSync(Buffer.from(secret));
  const big = zlib.gzipSync(Buffer.from(`${secret} ${'padding text '.repeat(40)}${Math.random()}`.repeat(3)));
  const b64 = big.toString('base64');
  for (const payload of [`{"att":"${gz.toString('base64')}"}`, `raw ${zlib.deflateRawSync(Buffer.from(secret)).toString('base64')}`,
    `hex ${gz.toString('hex')}`, b64.match(/.{1,76}/gu).join('\r\n'), b64.match(/.{1,100}/gu).join(' '),
    JSON.stringify(b64.match(/.{1,120}/gu)), big.toString('hex').match(/.{1,128}/gu).join('\n')]) {
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK', payload.slice(0, 40));
  }
});

test('third review: quoted dotted passwords are literals; bracket characters do not hide a value; many UUIDs and digests are fine', () => {
  for (const payload of ['{"password": "Synthetic.Passw0rd"}', "DB_PASSWORD='Synth.Pass9'", 'password=Syn}theticPass']) {
    assert.equal(checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null }).decision, 'BLOCK', payload);
  }
  const uuid = '123e4567-e89b-12d3-a456-426614174000';
  const sha = 'a'.repeat(63) + 'b';
  for (const payload of [JSON.stringify(Array.from({ length: 900 }, () => uuid)), Array.from({ length: 900 }, () => sha).join('\n'),
    `integrity="sha256-${Buffer.alloc(32, 7).toString('base64')}"`]) {
    const result = checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
    assert.equal(result.decision, 'ALLOW', `${payload.slice(0, 40)} ${result.reasons}`);
  }
});
