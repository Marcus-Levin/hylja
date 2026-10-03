import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
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
let syntheticCounter = 0;
const syntheticBytes = (length) => {
  const blocks = Array.from({ length: Math.ceil(length / 32) }, () =>
    createHash('sha256').update(`hylja-sentinel-synthetic-${syntheticCounter++}`).digest());
  return Buffer.concat(blocks, length);
};
const syntheticFraction = () => syntheticBytes(6).readUIntBE(0, 6) / 2 ** 48;
const syntheticUUID = () => {
  const hex = syntheticBytes(16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};
const sshEd25519Public = () => Buffer.concat([
  Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), syntheticBytes(32),
]).toString('base64');

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
  const binary = Buffer.concat([Buffer.from([0x1f, 0x8b, 8, 0]), syntheticBytes(2048)]).toString('base64');
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
  const big = zlib.gzipSync(Buffer.from(`${secret} ${'padding text '.repeat(40)}${syntheticFraction()}`.repeat(3)));
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

test('fourth review: chunked or prefixed compressed payloads are inflated and matched; bombs and large opaque binary block', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const secret = `contact ${PLANTED} re ${CANARY} ${syntheticBytes(16).toString('hex')} `.repeat(4);
  const raw = zlib.deflateRawSync(Buffer.from(secret));
  const chunks = (buffer, size) => Array.from({ length: Math.ceil(buffer.length / size) }, (_, i) => buffer.subarray(i * size, (i + 1) * size));
  const prefixed = Buffer.concat([Buffer.from([0]), zlib.gzipSync(Buffer.from(secret))]);
  for (const payload of [chunks(raw, 30).map((c) => c.toString('base64')).join(' '), chunks(raw, 47).map((c) => c.toString('hex')).join(' '),
    chunks(prefixed, 40).map((c) => c.toString('hex')).join('\n')]) {
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK', payload.slice(0, 40));
    assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED') || result.reasons.includes('CANARY_DETECTED'), result.reasons.join());
  }
  const bomb = zlib.gzipSync(Buffer.alloc(8 << 20, 65)).toString('base64');
  assert.equal(check(`x ${bomb}`).decision, 'BLOCK');
  assert.equal(check(`blob ${syntheticBytes(2048).toString('base64')}`).decision, 'BLOCK');
});

test('fourth review: digests, SRI values, SSH keys, session ids, UUIDs and trace ids are ordinary text', () => {
  const hex = (n) => syntheticBytes(n).toString('hex');
  const b64 = (n) => syntheticBytes(n).toString('base64');
  for (let run = 0; run < 40; run++) {
    for (const payload of [`digest ${hex(32)} ok`, `digest ${hex(64)} ok`, `sha384 ${hex(48)}`, Array.from({ length: 5 }, () => hex(20)).join('\n'),
      `image@sha256:${hex(32)}`, `<script integrity="sha384-${b64(48)}"></script>`, `"integrity": "sha512-${b64(64)}"`,
      `ssh-ed25519 ${sshEd25519Public()} user@host.invalid`,
      JSON.stringify(Array.from({ length: 300 }, () => syntheticUUID())), Array.from({ length: 200 }, () => `trace=${hex(16)}`).join('\n')]) {
      const result = checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
      assert.equal(result.decision, 'ALLOW', `${payload.slice(0, 40)} ${result.reasons}`);
    }
  }
});


test('fifth review: decoy-interleaved, brotli and container payloads block; random session tokens are credentials; inflate is budgeted', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const secret = `contact ${PLANTED} re ${CANARY} `;
  const raw = zlib.deflateRawSync(Buffer.from(secret));
  const decoyed = Array.from({ length: Math.ceil(raw.length / 32) }, (_, i) =>
    `${raw.subarray(i * 32, (i + 1) * 32).toString('base64')} ${syntheticBytes(20).toString('base64')}`).join(' ');
  const padded = zlib.gzipSync(Buffer.concat([Buffer.from(secret), Buffer.alloc(10)])).toString('base64');
  const controls = zlib.deflateRawSync(Buffer.from([...secret].map((c) => `${c}\u0001`).join(''))).toString('base64');
  for (const payload of [decoyed, zlib.brotliCompressSync(Buffer.from(secret)).toString('base64'), padded, controls,
    `x ${Buffer.concat([Buffer.from([0x28, 0xb5, 0x2f, 0xfd]), syntheticBytes(8)]).toString('base64')}`]) {
    assert.equal(check(payload).decision, 'BLOCK', payload.slice(0, 40));
  }
  const token = checkEgress({ bytes: enc(`session=${syntheticBytes(48).toString('base64url')}`), scope: scopeA, destination, authorized: destination, known: null });
  assert.equal(token.decision, 'BLOCK');
  const flood = Array.from({ length: 300 }, () => zlib.deflateRawSync(Buffer.alloc((1 << 20) - 100, 97)).toString('base64')).join(' ');
  const started = process.hrtime.bigint();
  const heavy = check(flood.slice(0, MAX_MESSAGE_BYTES));
  assert.equal(heavy.decision, 'BLOCK');
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000);
});

test('sixth review: data chunked under 16 characters is joined, decompressed and counted; digest prefixes are bounded', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const secret = `contact ${PLANTED} re ${CANARY} ${syntheticBytes(8).toString('hex')}`;
  const gz = zlib.gzipSync(Buffer.from(secret));
  const split = (text, n, sep) => text.match(new RegExp(`.{1,${n}}`, 'gu')).join(sep);
  for (const payload of [split(gz.toString('base64'), 15, ' '), split(gz.toString('base64'), 12, ' '), split(gz.toString('hex'), 15, ' '),
    split(zlib.brotliCompressSync(Buffer.from(secret)).toString('base64'), 14, '\n'), `sha512-${gz.toString('base64')}`]) {
    assert.equal(check(payload).decision, 'BLOCK', payload.slice(0, 30));
  }
  for (const payload of [split(syntheticBytes(4096).toString('base64'), 15, ' '), `integrity sha512-${syntheticBytes(3072).toString('base64')}`,
    `sha256:${syntheticBytes(3072).toString('base64')}`]) {
    assert.equal(checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null }).decision, 'BLOCK', payload.slice(0, 30));
  }
});

test('sixth review: chunked gzip without digits in some chunks is still joined and inflated', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const split = (text, n, sep) => text.match(new RegExp(`.{1,${n}}`, 'gu')).join(sep);
  for (let run = 0; run < 300; run++) {
    const gz = zlib.gzipSync(Buffer.from(`contact ${PLANTED} re ${CANARY} ${syntheticBytes(8).toString('hex')}`)).toString('base64');
    for (const width of [15, 12, 8]) assert.equal(check(split(gz, width, ' ')).decision, 'BLOCK', split(gz, width, ' '));
  }
});

test('sixth review: ordinary code, go.sum, Content-MD5 and public certificates are allowed', () => {
  const der = Buffer.concat([Buffer.from([0x30, 0x82, 0x02, 0x54]), syntheticBytes(596)]);
  const cert = ['-----BEGIN CERTIFICATE-----', ...der.toString('base64').match(/.{1,64}/gu), '-----END CERTIFICATE-----'].join('\n');
  for (let run = 0; run < 20; run++) {
    for (const payload of ['const http2ServerSessionOptions = convertUtf8ToBase64String(input);',
      'const id = await getEc2InstanceIdentity(ec2InstanceMetadataV2, s3BucketNameForUploads);',
      'CI: https://github.com/example-org/example-repo/actions/runs/36169013008 and /runs/36134297661/job/108599394046',
      Array.from({ length: 520 }, (_, i) => `synthRecordHandler${i}Value`).join(' '),
      Array.from({ length: 4 }, (_, i) => `example.invalid/mod${i} v1.0.${i} h1:${syntheticBytes(32).toString('base64')}`).join('\n'),
      Array.from({ length: 3 }, () => `Content-MD5: ${syntheticBytes(16).toString('base64')}`).join('\n'), cert]) {
      const result = checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
      assert.equal(result.decision, 'ALLOW', `${payload.slice(0, 40)} ${result.reasons}`);
    }
  }
});

test('seventh review: nested and gzip-wrapped binary, PEM-wrapped compression and per-view splitting all block', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const b64 = (bytes) => Buffer.from(bytes).toString('base64');
  const secret = Buffer.from(`note: ${PLANTED} end`);
  const pem = (label, body, end = label) => [`-----BEGIN ${label}-----`, ...b64(body).match(/.{1,64}/gu), `-----END ${end}-----`].join('\n');
  const hexGz = zlib.gzipSync(secret).toString('hex');
  const known = [b64(zlib.gzipSync(zlib.gzipSync(secret))), b64(zlib.gzipSync(zlib.deflateSync(secret))),
    pem('CERTIFICATE', zlib.gzipSync(secret)), pem('PUBLIC KEY', zlib.deflateSync(secret)),
    `-----BEGIN CERTIFICATE-----\nsome prose\nblob=${b64(zlib.gzipSync(secret))}\n-----END NOTE-----`,
    hexGz.match(/.{1,4}/gu).join('-'), hexGz.match(/.{1,12}/gu).join(':'), hexGz.match(/.{1,12}/gu).join('|')];
  for (const payload of known) assert.equal(check(JSON.stringify({ messages: [{ role: 'user', content: payload }] })).decision, 'BLOCK', payload.slice(0, 40));
  const random = (n) => syntheticBytes(n);
  const escaped = (text) => [...text].map((char) => `\\u00${char.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');
  let layered = b64(random(32));
  for (let i = 0; i < 20; i++) layered = b64(Buffer.from(`layer ${i} x=${b64(random(32))} ${layered.length > 4000 ? '' : layered}`));
  const opaque = [b64(zlib.gzipSync(random(1000))), b64(zlib.deflateSync(random(1000))),
    b64(zlib.gzipSync(Buffer.concat([Buffer.from([0x50, 0x4b, 3, 4]), random(500)]))),
    `${b64(random(31))} and ${escaped(b64(random(31)))}`, layered,
    Array.from({ length: 16 }, () => b64(random(64))).join(' '), Array.from({ length: 40 }, () => b64(random(16))).join(' '),
    random(64).toString('hex').match(/.{1,4}/gu).join('-'), random(64).toString('hex').match(/.{1,4}/gu).join('_')];
  for (const payload of opaque) {
    assert.equal(checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null }).decision, 'BLOCK', payload.slice(0, 40));
  }
  for (const payload of ["const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';",
    'fe80:0000:0000:0000:0202:b3ff:fe1e:8329 and 2001:0db8:85a3:0000:0000:8a2e:0370:7334 and 2001:0db8:0000:0042:0000:8a2e:0370:733a',
    '{"model":"synthetic","messages":[{"role":"user","content":"Why does HTTPS on 443 fail?"}]}']) {
    assert.equal(checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null }).decision, 'ALLOW', payload.slice(0, 40));
  }
});

test('eighth review: chunked plain encodings, trailing garbage and unsigned layers are inspected; id lists are ordinary', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const b64 = (bytes) => Buffer.from(bytes).toString('base64');
  const hex = (bytes) => Buffer.from(bytes).toString('hex');
  const groups = (text, n, sep) => text.match(new RegExp(`.{1,${n}}`, 'gu')).join(sep);
  const wrap = (content) => JSON.stringify({ model: 'synthetic', messages: [{ role: 'user', content }] });
  const secret = Buffer.from(`contact ${PLANTED} re ${CANARY}`);
  for (const payload of [groups(b64(secret), 8, ' '), groups(hex(secret), 4, ','), groups(hex(secret), 20, '\n'),
    groups(hex(secret), 4, '-'), groups(hex(secret), 4, '_'), groups(hex(secret), 2, ':'), groups(hex(secret), 4, '.'),
    `data ${groups(hex(zlib.gzipSync(secret)), 8, ' ')}`,
    groups(b64(zlib.gzipSync(secret)), 8, ' ').split(' ').map((chunk, i) => i % 4 === 0 ? `x ${chunk}` : chunk).join(' ')]) {
    assert.equal(check(wrap(payload)).decision, 'BLOCK', payload.slice(0, 40));
    assert.equal(check(payload).decision, 'BLOCK', payload.slice(0, 40));
  }
  const random = (n) => syntheticBytes(n);
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  for (const payload of [b64(Buffer.concat([zlib.deflateSync('build log: all tests passed'), random(4000)])),
    b64(Buffer.concat([zlib.brotliCompressSync(Buffer.from('build log: all tests passed')), random(4000)])),
    `a ${b64(zlib.deflateSync('build log: all tests passed'))} b ${b64(random(4000))}`,
    b64(zlib.brotliCompressSync(random(1000))), b64(zlib.deflateRawSync(random(1000))), b64(zlib.gzipSync(zlib.deflateRawSync(random(1000)))),
    b64(zlib.gzipSync(b64(random(1000)))), b64(zlib.brotliCompressSync(Buffer.from(hex(random(500)))))]) {
    assert.equal(unknown(wrap(payload)).decision, 'BLOCK', payload.slice(0, 40));
  }
  const hx = (n) => hex(random(n));
  const der = Buffer.concat([Buffer.from([0x30, 0x82, 0x02, 0x54]), random(596)]);
  const pem = ['-----BEGIN CERTIFICATE-----', ...b64(der).match(/.{1,64}/gu), '-----END CERTIFICATE-----'].join('\n');
  for (let run = 0; run < 20; run++) {
    for (const payload of [`{"timestamps":[${Array.from({ length: 12 }, (_, i) => 1695826432 + i * 17).join(',')}]}`,
      `timestamps: ${Array.from({ length: 12 }, (_, i) => 1695826432 + i * 17).join('|')}`,
      `squashed ${Array.from({ length: 12 }, () => hx(4).slice(0, 7)).join(' ')}`, JSON.stringify(Array.from({ length: 8 }, () => hx(6))),
      Array.from({ length: 2 }, () => `GET /api 200 traceparent=00-${hx(16)}-${hx(8)}-01`).join('\n'),
      Array.from({ length: 3 }, () => hx(20).toUpperCase().match(/.{4}/gu).join(' ')).join('\n'), `ids ${hx(12)} ${hx(12)} ${hx(12)}`,
      `commit ${hx(20)} and integrity sha256-${b64(random(32))}`, pem, `id\n${b64(random(24))}`]) {
      assert.equal(unknown(wrap(payload)).decision, 'ALLOW', payload.slice(0, 40));
    }
  }
  // Recognized digests that happen to hold a zlib header are not decompressed into an opaque count.
  for (const payload of ['commit b41f7f5f4f78175418789c8ae4c4000bc80566f4', 'digest d288ae4aa79c302c06789c73b5885b2537850011778e6d40e40c56fcf6d5bbf9 ok',
    '"integrity": "sha256-0oiuSqecMCwGeJxztYhbJTeFABF3jm1A5AxW/PbVu/k="']) {
    assert.equal(unknown(wrap(payload)).decision, 'ALLOW', payload);
  }
});

test('ninth review: stream remainders, uncertain layers, dumps and indented chunks are inspected; ordinary logs pass', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const b64 = (bytes) => Buffer.from(bytes).toString('base64');
  const hex = (bytes) => Buffer.from(bytes).toString('hex');
  const wrap = (content) => JSON.stringify({ model: 'synthetic', messages: [{ role: 'user', content }] });
  const random = (n) => syntheticBytes(n);
  const T = Buffer.from(`note ${PLANTED} ${CANARY}`);
  const benign = zlib.gzipSync(Buffer.from('build log ok, all good'));
  const colon = (bytes) => hex(bytes).match(/../gu).join(':');
  for (const payload of [`attachment ${b64(Buffer.concat([benign, Buffer.alloc(8), zlib.brotliCompressSync(T)]))}`,
    colon(Buffer.concat([benign, zlib.brotliCompressSync(T)])), colon(Buffer.concat([zlib.deflateSync('ok'), zlib.gzipSync(T)])),
    colon(zlib.deflateRawSync(Buffer.concat([random(16), T, random(16)]))),
    hex(T).match(/../gu).join(' '), hex(T).match(/../gu).map((pair) => `0x${pair}`).join(', '),
    b64(T).match(/.{1,8}/gu).join('     '), JSON.stringify(b64(zlib.gzipSync(T)).match(/.{1,8}/gu), null, 2),
    b64(T).match(/.{1,8}/gu).map((chunk) => `      ${chunk}`).join('\n')]) {
    assert.equal(check(wrap(payload)).decision, 'BLOCK', payload.slice(0, 40));
  }
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  for (const payload of [`attachment ${b64(Buffer.concat([benign, Buffer.alloc(8), random(2000)]))}`, colon(Buffer.concat([benign, random(4000)]))]) {
    assert.equal(unknown(wrap(payload)).decision, 'BLOCK', payload.slice(0, 40));
  }
  const hx = (n) => hex(random(n));
  for (let run = 0; run < 20; run++) {
    for (const payload of [Array.from({ length: 6 }, () => `{"ts":${1695826432123456789n + BigInt(run)}}`).join('\n'),
      Array.from({ length: 5 }, () => String(syntheticFraction())).join(' '), Array.from({ length: 6 }, () => `RAX=${hx(8).toUpperCase()}`).join(' '),
      Array.from({ length: 6 }, () => `at 0x${hx(8).toUpperCase()}`).join('\n'), Array.from({ length: 6 }, () => hx(6).toUpperCase().match(/../gu).join('-')).join('\n'),
      `blob ${Array.from({ length: 20 }, () => hx(4).toUpperCase()).join(' ')}`, Array.from({ length: 3 }, () => hx(16).toUpperCase()).join('\n'),
      `pub rsa4096\n      ${hx(20).toUpperCase().match(/.{4}/gu).join(' ')}\nsub\n      ${hx(20).toUpperCase().match(/.{4}/gu).join(' ')}`]) {
      assert.equal(unknown(wrap(payload)).decision, 'ALLOW', payload.slice(0, 40));
    }
  }
  // A PEM body must be one DER SEQUENCE of exactly its stated length.
  const pem = (der) => ['-----BEGIN CERTIFICATE-----', ...b64(der).match(/.{1,64}/gu), '-----END CERTIFICATE-----'].join('\n');
  assert.equal(unknown(pem(Buffer.concat([Buffer.from([0x30, 0x82, 0x10, 0x00]), random(4000)]))).decision, 'BLOCK');
  assert.equal(unknown(wrap(pem(Buffer.concat([Buffer.from([0x30, 0x82, 0x02, 0x54]), random(596)])))).decision, 'ALLOW');
});

test('tenth review: uncertain streams keep their tails and layers, wide byte pairs and dumps decode, compressed blobs are ordinary', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const hex = (bytes) => Buffer.from(bytes).toString('hex');
  const b64 = (bytes) => Buffer.from(bytes).toString('base64');
  const wrap = (content) => JSON.stringify({ model: 'synthetic', messages: [{ role: 'user', content }] });
  const T = Buffer.from(`note ${PLANTED} ${CANARY}`);
  const H = Buffer.from('harmless text here');
  const pairs = (bytes, sep) => hex(bytes).match(/../gu).join(sep);
  const br = (bytes) => zlib.brotliCompressSync(bytes);
  const raw = (bytes) => zlib.deflateRawSync(bytes);
  for (const bytes of [Buffer.concat([br(H), zlib.gzipSync(T)]), Buffer.concat([raw(H), br(T)]), br(br(T)), raw(zlib.gzipSync(T)), raw(raw(T))]) {
    for (const sep of [' ', ':']) assert.equal(check(wrap(pairs(bytes, sep))).decision, 'BLOCK', pairs(bytes, sep).slice(0, 30));
  }
  for (const payload of [pairs(T, '    '), pairs(zlib.gzipSync(T), ',    '),
    hex(zlib.gzipSync(T)).match(/.{1,32}/gu).map((line, i) => `${(i * 16).toString(16).padStart(8, '0')}: ${line.match(/../gu).join(' ')}`).join('\n')]) {
    assert.equal(check(wrap(payload)).decision, 'BLOCK', payload.slice(0, 30));
  }
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  const blob = (n) => zlib.deflateSync(`config section ${n}: enabled=true, retries=3`);
  for (const payload of [`${b64(blob(1))}\n${b64(blob(2))}`, `${hex(blob(1))}\n${hex(blob(2))}`, `${b64(zlib.gzipSync('first log line'))} then ${b64(zlib.gzipSync('second log line'))}`,
    '{ password: password }', 'new Client({ apiKey: apiKey })']) {
    assert.equal(unknown(wrap(payload)).decision, 'ALLOW', payload.slice(0, 40));
  }
});

test('eleventh review: dumps after unrelated ids, pair arrays, text under uncertain layers, and ordinary blobs and paths', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const hex = (bytes) => Buffer.from(bytes).toString('hex');
  const b64 = (bytes) => Buffer.from(bytes).toString('base64');
  const wrap = (content) => JSON.stringify({ model: 'synthetic', messages: [{ role: 'user', content }] });
  const T = Buffer.from(`note ${PLANTED} ${CANARY} and some more text`);
  const gz = zlib.gzipSync(T);
  const od = hex(gz).match(/.{1,32}/gu).map((line) => ` ${line.match(/../gu).join(' ')}`).join('\n');
  const pairs = (bytes, sep) => hex(bytes).match(/../gu).join(sep);
  for (const payload of [`commit ${hex(syntheticBytes(20))}\n${od}`, `${syntheticUUID()}\n${od}`,
    Array.from({ length: 300 }, () => `fp ${pairs(syntheticBytes(16), ':')}`).join('\n') + `\n${pairs(gz, ' ')}`,
    `sha256 ${hex(syntheticBytes(32))}\n${b64(gz).match(/.{1,12}/gu).join(' ')}`,
    JSON.stringify(hex(T).match(/../gu)), JSON.stringify(hex(gz).match(/../gu), null, 2), hex(T).match(/../gu).map((pair) => `- ${pair}`).join('\n'),
    pairs(T, '; '), pairs(T, ',\n    '),
    pairs(Buffer.concat([zlib.deflateRawSync(Buffer.from('harmless text here')), zlib.gzipSync(b64(T))]), ' '),
    pairs(zlib.brotliCompressSync(zlib.brotliCompressSync(b64(T))), ' ')]) {
    assert.equal(check(wrap(payload)).decision, 'BLOCK', payload.slice(0, 40));
  }
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  assert.equal(unknown(wrap(b64(Buffer.concat([zlib.gzipSync('harmless log line'), syntheticBytes(600)])).match(/.{1,12}/gu).join(' '))).decision, 'BLOCK');
  assert.equal(check('const password = `Synthetic-Passw0rd-1`;').decision, 'BLOCK');
  assert.equal(check('db=1postgres://admin:Synthetic-pass@db.invalid/x').decision, 'BLOCK');
  for (const payload of [Array.from({ length: 6 }, (_, i) => `2026-09-27T10:00:0${i}Z INFO event payload=${b64(zlib.deflateSync(JSON.stringify({ event: 'login', n: i })))}`).join('\n'),
    'PWD=/srv/app\nHOME=/home/app', 'const url = `postgres://${user}:${password}@${host}/db`;', 'postgres://{{user}}:{{password}}@db.invalid',
    'postgres://$DB_USER:$DB_PASS@db.invalid']) {
    assert.equal(unknown(wrap(payload)).decision, 'ALLOW', payload.slice(0, 40));
  }
});

test('twelfth review: dump ASCII columns, empty streams in a chain, advisory ids, URL placeholders and conditionals', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const hex = (bytes) => Buffer.from(bytes).toString('hex');
  const wrap = (content) => JSON.stringify({ model: 'synthetic', messages: [{ role: 'user', content }] });
  const T = Buffer.from(`note ${PLANTED} ${CANARY} and some more text`);
  const printableColumn = (bytes) => [...bytes].map((byte) => byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.').join('');
  const hexdump = (bytes) => Array.from({ length: Math.ceil(bytes.length / 16) }, (_, row) => {
    const line = bytes.subarray(row * 16, row * 16 + 16);
    const pairs = [...line].map((byte) => byte.toString(16).padStart(2, '0'));
    return `${(row * 16).toString(16).padStart(8, '0')}  ${pairs.slice(0, 8).join(' ')}  ${pairs.slice(8).join(' ')}`.padEnd(60) + `|${printableColumn(line)}|`;
  }).join('\n');
  const xxd = (bytes) => Array.from({ length: Math.ceil(bytes.length / 16) }, (_, row) => {
    const line = bytes.subarray(row * 16, row * 16 + 16);
    return `${(row * 16).toString(16).padStart(8, '0')}: ${[...line].map((byte) => byte.toString(16).padStart(2, '0')).join(' ')}`.padEnd(59) + printableColumn(line);
  }).join('\n');
  const words = Array.from({ length: 300 }, (_, i) => `word${i % 17}`).join(' ');
  for (const body of [zlib.deflateSync(Buffer.from(`${words} ${T} ${words}`)), zlib.gzipSync(Buffer.from(`${words} ${T} ${words}`)),
    Buffer.concat([Buffer.from('x'.repeat(15)), zlib.deflateSync(T)])]) {
    for (const dump of [hexdump(body), xxd(body)]) {
      assert.equal(check(dump).decision, 'BLOCK', dump.slice(0, 40));
      assert.equal(check(wrap(dump)).decision, 'BLOCK', dump.slice(0, 40));
    }
  }
  const z0 = zlib.deflateSync(Buffer.alloc(0));
  const pairs = (bytes) => hex(bytes).match(/../gu).join(' ');
  const decoy = Buffer.concat([Buffer.alloc(16), Buffer.from('7801'.repeat(300), 'hex')]);
  assert.equal(check(wrap(`${pairs(decoy)}\n\n${pairs(Buffer.concat([z0, z0, zlib.deflateSync(T)]))}`)).decision, 'BLOCK');
  for (const payload of ['postgres://admin:$ynthetic-pass@db.invalid/x', 'postgres://admin:{Synthetic-pass}@db.invalid/x', 'redis://:Synthetic-pass@cache.invalid:6379']) {
    assert.equal(check(payload).decision, 'BLOCK', payload);
  }
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  for (const payload of ['Bump deps for GHSA-c2qf-rxjj-qqgw, GHSA-72xf-g2v4-qvf3 and GHSA-j8xg-fqg3-53r7',
    'see https://github.com/advisories/GHSA-c2qf-rxjj-qqgw https://github.com/advisories/GHSA-72xf-g2v4-qvf3 https://github.com/advisories/GHSA-j8xg-fqg3-53r7',
    'files: Q1_2026_Report_v3_Final.pdf Q2_2026_Report_v1_Draft.pdf Q3_2026_Report_v2_Final.pdf', "const label = kind === 'credential' ? 'SECRET' : 'INTERNAL';",
    'postgres://admin:<password>@db.invalid/x']) {
    assert.equal(unknown(wrap(payload)).decision, 'ALLOW', payload.slice(0, 40));
  }
});

test('issue 88: compressed originals under byte escapes are inflated before release', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const gzip = zlib.gzipSync(Buffer.from(`synthetic note for ${PLANTED} and ${CANARY}`));
  const hex = (byte) => byte.toString(16).padStart(2, '0');
  const forms = [
    [...gzip].map((byte) => `%${hex(byte)}`).join(''),
    [...gzip].map((byte) => `\\x${hex(byte)}`).join(''),
    [...gzip].map((byte, index) => index === 0 ? '\\^_' : `\\x${hex(byte)}`).join(''),
    [...gzip].map((byte) => `\\u00${hex(byte)}`).join(''),
    [...gzip].map((byte) => `\\${byte.toString(8).padStart(3, '0')}`).join(''),
    [...gzip].map((byte) => `&#x${hex(byte)};`).join(''),
    [...gzip].map((byte) => `=${hex(byte).toUpperCase()}`).join(''),
    `b'${[...gzip].map((byte) => byte >= 32 && byte < 127 && byte !== 39 && byte !== 92 ? String.fromCharCode(byte) : `\\x${hex(byte)}`).join('')}'`,
  ];
  for (const body of forms) {
    const result = check(JSON.stringify({ content: body }));
    assert.equal(result.decision, 'BLOCK', body.slice(0, 24));
    assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), `${body.slice(0, 24)}: ${result.reasons}`);
    assert.equal(result.release, undefined);
  }
  const latin1Json = check(JSON.stringify({ content: String.fromCharCode(...gzip) }));
  assert.ok(latin1Json.reasons.includes('KNOWN_ORIGINAL_DETECTED'), latin1Json.reasons.join(','));
});

test('issue 88: default two-byte-group xxd rows rebuild a compressed planted leak', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const compressed = zlib.gzipSync(Buffer.from(`note ${PLANTED} ${CANARY} synthetic text`));
  const dump = Array.from({ length: Math.ceil(compressed.length / 16) }, (_, row) => {
    const line = compressed.subarray(row * 16, row * 16 + 16);
    const pairs = [...line].map((byte) => byte.toString(16).padStart(2, '0'));
    const groups = pairs.join('').match(/.{1,4}/gu).join(' ');
    const ascii = [...line].map((byte) => byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '.').join('');
    return `${(row * 16).toString(16).padStart(8, '0')}: ${groups.padEnd(39)}  ${ascii}`;
  }).join('\n');
  for (const payload of [dump, JSON.stringify({ content: dump })]) {
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK');
    assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), result.reasons.join(','));
  }
});

test('issue 88: escaped opaque bytes block, while ordinary log assignments still pass', () => {
  const opaque = Buffer.concat(Array.from({ length: 3 }, (_, index) =>
    createHash('sha256').update(`synthetic-opaque-${index}`).digest()));
  const escaped = [...opaque].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
  assert.ok(check(JSON.stringify({ content: escaped })).reasons.includes('OPAQUE_EMBEDDED'));
  for (const log of ['GET /api 200 traceparent=00-f569e0751199', 'RAX=EC37B814521BE4FD RAX=073592AFDF35F68']) {
    assert.equal(check(JSON.stringify({ content: log })).decision, 'ALLOW');
  }
  assert.equal(check(`{"content":"${'\\u00e9'.repeat(40)}"}`).decision, 'ALLOW');
  assert.equal(check(JSON.stringify({ content: 'café '.repeat(40) })).decision, 'ALLOW');
  assert.deepEqual(check('b"\\400\\377 synthetic"').reasons, ['UNINSPECTED_CONTENT']);
  assert.deepEqual(check('b"\\777 synthetic"').reasons, ['UNINSPECTED_CONTENT']);
});

/**
 * Reproduced on base `e2b5714`: a byte-escape **list** whose escapes are separated by one character was never
 * assembled into bytes. `escapedByteAt` reads the supported families (`%XX`, `\xXX`, `\uXXXX`/`\UXXXXXXXX`, octal,
 * `\^X`, `&#xXX;`, `&#NN;`, `=XX`), but the two readers that consume it required the escapes to be *contiguous*:
 * the first separator ended the run and every remaining escape was a run of its own, below the four-byte floor.
 * So `=1F =8B =08 …` (quoted-printable with separators), `%1f %8b …`, `\u001f \u008b …`, `\037\213 …` and
 * `&#x1f; &#x8b; …` were read as text: a gzip note carrying a planted original and a canary was ALLOWed with
 * `release` bytes, and 96 bytes of opaque binary under the same spelling were never counted. The fix accepts
 * exactly one separator character between two escapes and drops it from the reconstruction; what a longer or
 * multi-character split does is pinned in the declared-limit group below, not claimed closed here.
 */
const ESCAPED_NOTE = `contact ${PLANTED} re ${CANARY} and a little more synthetic padding text to compress`;
/** Locally seeded synthetic bytes: the shared counter above belongs to the groups that already consume it. */
const escapedOpaqueBytes = (length) => Buffer.concat(Array.from({ length: Math.ceil(length / 32) },
  (_, index) => createHash('sha256').update(`issue-88-escaped-opaque-${index}`).digest()), length).subarray(0, length);
const escapeFamilies = () => ({
  percent: (byte) => `%${byte.toString(16).padStart(2, '0')}`,
  hex: (byte) => `\\x${byte.toString(16).padStart(2, '0')}`,
  unicode: (byte) => `\\u00${byte.toString(16).padStart(2, '0')}`,
  octal: (byte) => `\\${byte.toString(8).padStart(3, '0')}`,
  htmlHex: (byte) => `&#x${byte.toString(16).padStart(2, '0')};`,
  htmlDecimal: (byte) => `&#${byte};`,
  quotedPrintable: (byte) => `=${byte.toString(16).toUpperCase().padStart(2, '0')}`,
  quotedPrintableLower: (byte) => `=${byte.toString(16).padStart(2, '0')}`,
});
/** One separator character, in every spelling this fix accepts: literal punctuation and a JSON line break. */
const ESCAPE_SEPARATORS = [' ', '\t', '\r', '\n', ',', ';', ':', '|', '&', '.', '\\n'];
/**
 * The containers a dressed body is checked in. A backslash cannot appear unescaped inside a JSON body, so a body
 * carrying the JSON-escaped line-break separator is reachable only as a raw message and is checked there alone;
 * a literal newline in a JSON body is the same wire text as that escaped spelling in a raw one.
 */
const escapeContainers = (body) => [body, ...(body.includes('\\') ? [] : [JSON.stringify({ content: body }),
  JSON.stringify({ model: 'synthetic', messages: [{ role: 'user', content: body }] })])];

test('issue 88: byte escapes separated by one character are rebuilt, inflated and matched', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const note = Buffer.from(ESCAPED_NOTE);
  let dressings = 0;
  for (const compress of [zlib.gzipSync, zlib.deflateSync, zlib.deflateRawSync, zlib.brotliCompressSync]) {
    const stream = compress(note);
    for (const [family, spell] of Object.entries(escapeFamilies())) {
      for (const separator of ESCAPE_SEPARATORS) {
        const body = [...stream].map(spell).join(separator);
        assert.ok(body.length <= MAX_MESSAGE_BYTES, `${family}/${JSON.stringify(separator)}`);
        for (const payload of escapeContainers(body)) {
          blocksWithOriginal(payload, true);
          dressings++;
        }
      }
    }
  }
  assert.ok(dressings >= 260, `${dressings} generated dressings`);
  // The same escapes with nothing compressed: the note is spelled out in the bytes themselves, so it is found as
  // the text those bytes decode to rather than through decompression. Both routes are the same reconstruction, so
  // one separator of each kind is enough here; every family is covered.
  for (const [family, spell] of Object.entries(escapeFamilies())) {
    for (const separator of [' ', ',', '\t', '\\n']) {
      const body = [...note].map(spell).join(separator);
      for (const payload of escapeContainers(body)) blocksWithOriginal(payload, true);
    }
  }
});

test('issue 88: separated escape bytes are counted opaque, with no known original registered', () => {
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  // 96 bytes of synthetic binary: above the opaque threshold on its own, and holding no planted value, so only the
  // byte count can refuse it. No `release` bytes on any spelling.
  const opaque = escapedOpaqueBytes(96);
  for (const [family, spell] of Object.entries(escapeFamilies())) {
    for (const separator of ESCAPE_SEPARATORS) {
      const body = [...opaque].map(spell).join(separator);
      for (const payload of escapeContainers(body)) {
        const result = unknown(payload);
        assert.ok(result.reasons.includes('OPAQUE_EMBEDDED'), `${family}/${JSON.stringify(separator)}: ${result.reasons.join()}`);
        assert.equal(result.release, undefined, `${family}/${JSON.stringify(separator)}`);
      }
    }
  }
  // The same bytes one escape at a time stay below the floor and stay ordinary text: a separator that is not
  // between two escapes is not data.
  assert.equal(unknown([...opaque.slice(0, 3)].map((byte) => `=${byte.toString(16).toUpperCase()}`).join(' ')).decision, 'ALLOW');
  assert.equal(unknown('RAX=EC37B814521BE4FD RAX=073592AFDF35F68 note').decision, 'ALLOW');
  // Ordinary text that happens to spell separated escapes stays allowed: a hex escape list is ASCII text, and the
  // opaque count is a byte count, not a shape.
  for (const payload of ['key =41 =42 =43 =44 done', 'note a=41 b=42 c=43 and =44 end', '&#160; &#160; &#160; spacing',
    '&#65; &#66; &#67; &#68; letters', 'flags =00 =01 =02 =03 =04 =05 =06 =07 set', 'width=20 height=30 color=#ff0000 pad=8',
    'budget=100 &amp; cost=200 &amp; total=300', 'GET /api 200 traceparent=00-f569e0751199']) {
    assert.equal(unknown(payload).decision, 'ALLOW', `${payload.slice(0, 40)} ${unknown(payload).reasons.join()}`);
    assert.equal(unknown(JSON.stringify({ content: payload })).decision, 'ALLOW', `json ${payload.slice(0, 40)}`);
  }
});

test('issue 88: every separated-escape dressing of one planted note is blocked, generated deterministically', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  // A fixed-seed generator: which dressing a round gets is not asserted, only that every dressing of the same
  // planted note reaches the planted original and the canary through the public interface.
  let seed = 0x1f2e3d4c;
  const next = () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) >>> 8) / 2 ** 24;
  const pick = (list) => list[Math.floor(next() * list.length) % list.length];
  const families = Object.values(escapeFamilies());
  const separators = [...ESCAPE_SEPARATORS, ' ', '\t'];
  const compressors = [zlib.gzipSync, zlib.deflateSync, zlib.deflateRawSync, zlib.brotliCompressSync];
  let dressings = 0;
  for (let round = 0; round < 160; round++) {
    const spell = pick(families), separator = pick(separators), compress = pick(compressors);
    const stream = compress(Buffer.from(ESCAPED_NOTE));
    const body = [...stream].map(spell).join(separator);
    for (const payload of escapeContainers(body)) {
      blocksWithOriginal(payload, true);
      dressings++;
    }
  }
  assert.ok(dressings >= 300, `${dressings} generated dressings`);
  // Findings and the regression record carry codes and refs only: no planted byte reaches a result.
  const body = [...zlib.gzipSync(Buffer.from(ESCAPED_NOTE))].map(escapeFamilies().quotedPrintable).join(' ');
  const serialized = JSON.stringify(check(body));
  for (const value of ['Orla', 'orla', 'Synthetica', CANARY, 'contact']) assert.ok(!serialized.includes(value), value);
  assert.deepEqual(Object.keys(check(body).regression).sort(), ['reasons', 'rules', 'version', 'views']);
});

test('issue 88: separated-escape reconstruction is bounded and fails closed rather than releasing what it skipped', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  // One escape list per view: the escape readers run once per view and per round, so the work is bounded by the
  // message-size and view-budget limits the module already publishes. A dense 1 MiB list decides, and a list
  // carrying a planted note behind padding is still read rather than released.
  const dense = `${Array.from({ length: 200_000 }, () => '=3D').join(' ')}`.slice(0, MAX_MESSAGE_BYTES);
  const started = process.hrtime.bigint();
  const denseResult = check(dense);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(['ALLOW', 'BLOCK'].includes(denseResult.decision));
  assert.ok(elapsedMs < 5000, `${elapsedMs.toFixed(0)}ms`);
  // Padding that is not a byte escape never ends a run: the planted note behind ordinary lines is still read rather
  // than released.
  const padding = 'ordinary log line about the synthetic build\n'.repeat(200);
  const body = [...zlib.gzipSync(Buffer.from(ESCAPED_NOTE))].map(escapeFamilies().quotedPrintable).join(' ');
  blocksWithOriginal(`${padding}${body}\n${padding}`, true);
  blocksWithOriginal(JSON.stringify({ content: `${padding}${body}` }), true);
  // A payload larger than one run is read in consecutive runs whose spans touch, so a note behind the bound is
  // still found. Where a signed stream itself starts inside one run and continues in the next, the interior scan
  // reads each run on its own and the truncated half decodes nothing: the bytes are then refused by the opaque
  // count instead of by the precise finding. That is a declared limit, pinned here so it cannot become a release.
  const spell = escapeFamilies().quotedPrintable;
  for (const pad of [32_760, 32_768, 40_000]) {
    const straddled = Buffer.concat([Buffer.alloc(pad, 0x3d), Buffer.from(`note ${PLANTED} re ${CANARY}`)]);
    blocksWithOriginal([...straddled].map(spell).join(' '), true);
    const stream = Buffer.concat([Buffer.alloc(pad, 0x3d), zlib.gzipSync(Buffer.from(ESCAPED_NOTE))]);
    const payload = [...stream].map(spell).join(' ');
    assert.ok(payload.length <= MAX_MESSAGE_BYTES, `${pad}`);
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK', `${pad}`);
    assert.ok(result.reasons.length > 0, `${pad}`);
    assert.equal(result.release, undefined, `${pad}`);
  }
});

/* ---------- Issue #126: a wider escape separator, and escapes across one declared label series ---------- */

/**
 * Issue #126, RED on the assigned base `7514bbc` and reproduced from the public interface with synthetic data
 * only, not taken from the issue summary. Two adjacent shapes of #124's escape reader were not read:
 *
 * (i) **a gap wider than one character between two escapes.** `escapeSeparatorEnd` accepted a single
 * separator-class character (or the two-character JSON spelling of one line break), so `=41, =42`, `%1f  %8b`,
 * `\u001f\t \u008b` and a CRLF line-broken list all ended the run: every remaining escape was a one-byte run below
 * the four-byte floor. Measured on that base over four compressors x eight escape families x the containers
 * below, a gzip/zlib/raw-deflate/brotli note carrying a planted original and a canary was returned `ALLOW`
 * **with `release` bytes** for the quoted-printable (either case), octal and `\u00NN` spellings, and no family
 * reported the precise known-original finding. The `\x`-prefixed spelling was already blocked by the byte-pair
 * reader, which rebuilds it at any single-character separator and publishes its own limit above that.
 *
 * (ii) **escapes distributed across one declared label series.** `part1: \x1f`, `part2: \x8b`, ... Each escape was
 * a one-byte run below the floor and the labelled-field reader takes chunk values only (`[A-Za-z0-9+/_-]`), so the
 * same compressed note, its opaque bytes and its `{"part":N,"data":"…"}` spelling were read as ordinary text.
 * Measured on that base: every one of those payloads returned `ALLOW` with `release` bytes.
 *
 * The fix is two readings, both added to the ones that existed: a **bounded separator run** between escapes in
 * ordinary text (`MAX_ESCAPE_SEPARATOR`, every character a separator-class character or a JSON line-break
 * spelling, and the run ends at the first character that opens the next escape), and one reading per **declared
 * label series** whose every value is an escape list. `quoted()` is untouched — inside a quoted string every
 * literal character is still a byte — and no threshold, opaque count, budget or other reader moved.
 */
const MULTI_ESCAPE_SEPARATORS = ['  ', ', ', ': ', '\r\n', ' , ', '\t ', ',  '];

test('issue 126: escapes separated by more than one character are rebuilt, inflated and matched', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const note = Buffer.from(ESCAPED_NOTE);
  let dressings = 0;
  for (const compress of [zlib.gzipSync, zlib.deflateSync, zlib.deflateRawSync, zlib.brotliCompressSync]) {
    const stream = compress(note);
    for (const [family, spell] of Object.entries(escapeFamilies())) {
      for (const separator of MULTI_ESCAPE_SEPARATORS) {
        const body = [...stream].map(spell).join(separator);
        assert.ok(body.length <= MAX_MESSAGE_BYTES, `${family}/${JSON.stringify(separator)}`);
        for (const payload of escapeContainers(body)) {
          blocksWithOriginal(payload, true);
          dressings++;
        }
      }
    }
  }
  assert.ok(dressings >= 300, `${dressings} generated dressings`);
  // The same escapes with nothing compressed: the note is spelled out in the bytes themselves, so it is found as
  // the text those bytes decode to rather than through decompression. Both routes are the same reconstruction.
  for (const separator of ['  ', ', ', '\t ', ',  ']) {
    const body = [...note].map(escapeFamilies().quotedPrintable).join(separator);
    for (const payload of escapeContainers(body)) blocksWithOriginal(payload, true);
  }
  // A JSON array of escapes: the separator between two entries is `","` or `",\n  "`, which is the widest
  // formatting any list of these carries.
  const spell = escapeFamilies().percent;
  const stream = zlib.gzipSync(note);
  for (const wrap of [(list) => JSON.stringify(list), (list) => JSON.stringify(list, null, 2),
    (list) => JSON.stringify({ parts: list }), (list) => JSON.stringify({ payload: `parts=${list.join(' ')}` })]) {
    blocksWithOriginal(wrap([...stream].map(spell)), true);
  }
  // Findings and the regression record carry codes and refs only: no planted byte reaches a result.
  const serialized = JSON.stringify(check([...stream].map(escapeFamilies().quotedPrintable).join(', ')));
  for (const value of ['Orla', 'orla', 'Synthetica', CANARY, 'contact']) assert.ok(!serialized.includes(value), value);
  assert.deepEqual(Object.keys(check([...stream].map(escapeFamilies().quotedPrintable).join(', ')).regression).sort(),
    ['reasons', 'rules', 'version', 'views']);
});

/** One declared label series whose every value is an escape list, in the shapes a sender actually writes. */
const labelledEscapeSeries = (bytes, spell, perField) => {
  const fields = [];
  for (let at = 0; at < bytes.length; at += perField) {
    fields.push([...bytes.subarray(at, at + perField)].map(spell).join(' '));
  }
  return {
    lines: fields.map((value, index) => `part${index + 1}: ${value}`).join('\n'),
    json: JSON.stringify({ content: fields.map((value, index) => `part${index + 1}: ${value}`).join('\n') }),
    query: fields.map((value, index) => `part${index + 1}=${value}`).join('&'),
    arrayOfObjects: JSON.stringify(fields.map((value, index) => ({ part: index + 1, data: value }))),
    commajoin: fields.map((value, index) => `"part${index + 1}":"${value}"`).join(',\n'),
    nonNumbered: fields.map((value) => `data: ${value}`).join('\n'),
    reversed: fields.map((value, index) => `part${fields.length - index}: ${value}`).join('\n'),
    interleaved: fields.map((value, index) => index === 1 ? `trace: 1a2b3c4d\npart2: ${value}` : `part${index + 1}: ${value}`).join('\n'),
  };
};

test('issue 126: escapes spread across one declared label series are rebuilt, inflated and matched', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const note = Buffer.from(ESCAPED_NOTE);
  let dressings = 0;
  for (const compress of [zlib.gzipSync, zlib.deflateSync, zlib.deflateRawSync, zlib.brotliCompressSync]) {
    const stream = compress(note);
    for (const [family, spell] of Object.entries(escapeFamilies())) {
      for (const perField of [1, 2]) {
        for (const [shape, payload] of Object.entries(labelledEscapeSeries(stream, spell, perField))) {
          // Every shape below was `ALLOW` with `release` bytes at the base. The `json` container is the one
          // exception to the *precise* claim: for the entity and percent families the base already refused that
          // shape opaquely, because the JSON escape round turns those escapes into the bytes themselves, so what
          // this slice claims there is that nothing is released rather than which finding is reported.
          if (shape === 'json' && ['percent', 'htmlHex', 'htmlDecimal'].includes(family)) blocksLeak(payload);
          else blocksWithOriginal(payload, true);
          dressings++;
        }
      }
    }
  }
  assert.ok(dressings >= 200, `${dressings} generated declared-series dressings`);
  // Several bytes per field, and the same series under a JSON body that escapes its own line breaks: all one
  // declared series, all read the same way.
  const spell = escapeFamilies().quotedPrintable;
  for (const perField of [1, 2, 3, 4]) {
    const fields = [];
    for (let at = 0; at < note.length; at += perField) {
      fields.push([...zlib.gzipSync(note).subarray(at, at + perField)].map(spell).join(' '));
    }
    blocksWithOriginal(fields.map((value, index) => `part${index + 1}: ${value}`).join('\n'), true);
    blocksWithOriginal(fields.map((value, index) => `part${index + 1}: ${value}`).join('\n\n'), true);
    blocksWithOriginal(fields.map((value, index) => `p${index + 1} = ${value}`).join(', '), true);
    blocksWithOriginal(JSON.stringify({ content: fields.map((value, index) => `part${index + 1}: ${value}`).join('\n') }), true);
    blocksWithOriginal(fields.map((value, index) => `part${index + 1}: ${value}`).join('\n').toUpperCase().replace(/PART/g, 'PART'), true);
  }
});

test('issue 126: separated escapes and declared label series are refused as opaque with no known original', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  const opaque = escapedOpaqueBytes(96);
  // Uncompressed opaque bytes above the opaque threshold, in the widened separator spellings: only the byte count
  // can refuse these, and no `release` bytes may come back on any spelling.
  for (const [family, spell] of Object.entries(escapeFamilies())) {
    for (const separator of MULTI_ESCAPE_SEPARATORS) {
      const body = [...opaque].map(spell).join(separator);
      for (const payload of escapeContainers(body)) {
        const result = unknown(payload);
        assert.ok(result.reasons.includes('OPAQUE_EMBEDDED'), `${family}/${JSON.stringify(separator)}: ${result.reasons.join()}`);
        assert.equal(result.release, undefined, `${family}/${JSON.stringify(separator)}`);
      }
    }
  }
  // The same bytes compressed: a signed stream's own output is counted, so a declared label series of them is
  // refused opaquely rather than released.
  for (const compress of [zlib.gzipSync, zlib.deflateSync]) {
    for (const [family, spell] of Object.entries(escapeFamilies())) {
      const stream = compress(opaque);
      for (const [shape, payload] of Object.entries(labelledEscapeSeries(stream, spell, 1))) {
        const result = unknown(payload);
        assert.ok(result.reasons.includes('OPAQUE_EMBEDDED'), `${compress === zlib.gzipSync ? 'gzip' : 'zlib'}/${family}/${shape}: ${result.reasons.join()}`);
        assert.equal(result.release, undefined, `${family}/${shape}`);
      }
    }
  }
  // And the published tentative-output limit, pinned in this spelling too: brotli and raw deflate carry no
  // signature and their output cannot raise the opaque count, so opaque bytes inside them stay uninspectable
  // rather than clean — nothing is released with a precise claim, and this is a declared limit.
  for (const compress of [zlib.deflateRawSync, zlib.brotliCompressSync]) {
    const stream = compress(opaque);
    const result = unknown(labelledEscapeSeries(stream, escapeFamilies().quotedPrintable, 1).lines);
    assert.ok(!result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), result.reasons.join());
    assert.ok(!result.reasons.includes('CANARY_DETECTED'), result.reasons.join());
  }
});

/**
 * One declared label series carrying `perField` escapes of a **text** value (not a byte buffer): the series
 * spelling of a string the sender encoded as text, which is the shape a nested payload takes when the payload is
 * itself Base64 or hex.
 */
const labelledEscapeText = (text, spell, perField) => {
  const fields = [];
  for (let at = 0; at < text.length; at += perField) {
    fields.push([...text.slice(at, at + perField)].map((char) => spell(char.charCodeAt(0))).join(' '));
  }
  return fields.map((value, index) => `part${index + 1}: ${value}`).join('\n');
};

/**
 * Independent review of `0724426`, blocking finding, reproduced here: the text a declared escape series spells was
 * routed into a view marked `derived: true`, and in this module `derived` is the switch that turns off opaque-byte
 * accounting for a **whole view** — both for the runs inside it and for what a decompression inside it produces. So
 * an unknown embedded opaque payload written as text inside a declared escape series was released with `release`
 * bytes while the identical bytes were refused in every other spelling. This group is the direction that must
 * hold: a declared reconstruction's own spelling exempts nothing about what the reconstruction **encodes**, exactly
 * as the frozen #19 known-limits list records for every other declared form ("compressed opaque data inside them
 * still blocks").
 */
test('issue 126 review: a declared escape series waives no opaque byte count', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  const opaque = escapedOpaqueBytes(96);
  const qp = (byte) => `=${byte.toString(16).toUpperCase().padStart(2, '0')}`;
  // Four nested payloads, each spelled as text: a signed stream of opaque bytes, the same as hex, the same as a
  // second signed layer, and a container signature. Each is checked against its own ordinary spellings first, so the
  // series spelling is compared to the reference rather than to a magic constant.
  const texts = {
    base64: zlib.gzipSync(opaque).toString('base64'),
    hex: zlib.gzipSync(opaque).toString('hex'),
    nested: zlib.gzipSync(zlib.gzipSync(opaque)).toString('base64'),
    container: Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), opaque]).toString('hex'),
  };
  for (const [label, text] of Object.entries(texts)) {
    for (const reference of [`x=${text}`, [...text].map((char) => qp(char.charCodeAt(0))).join(' ')]) {
      const result = unknown(reference);
      assert.ok(result.reasons.includes('OPAQUE_EMBEDDED'), `${label}/reference: ${result.reasons.join()}`);
      assert.equal(result.release, undefined, `${label}/reference`);
    }
    for (const perField of [1, 2, 3, 4, 5, 8]) {
      const result = unknown(labelledEscapeText(text, qp, perField));
      assert.equal(result.decision, 'BLOCK', `${label}/${perField}: ${result.reasons.join()}`);
      assert.ok(result.reasons.includes('OPAQUE_EMBEDDED'), `${label}/${perField}: ${result.reasons.join()}`);
      assert.equal(result.release, undefined, `${label}/${perField}`);
    }
    for (const [family, spell] of Object.entries(escapeFamilies())) {
      for (const perField of [1, 3]) {
        for (const payload of [labelledEscapeText(text, (byte) => spell(byte), perField),
          JSON.stringify({ content: labelledEscapeText(text, (byte) => spell(byte), perField) })]) {
          const result = unknown(payload);
          assert.equal(result.decision, 'BLOCK', `${label}/${family}/${perField}: ${result.reasons.join()}`);
          assert.ok(result.reasons.includes('OPAQUE_EMBEDDED'), `${label}/${family}/${perField}: ${result.reasons.join()}`);
          assert.equal(result.release, undefined, `${label}/${family}/${perField}`);
        }
      }
    }
  }
  // The own-shape exemption that keeps ordinary text ordinary is unchanged by this, and it stays a property of the
  // series' own text rather than of its contents: a series spelling text that is itself all hex letters decodes to
  // no data the sender wrote. Its one ordinary separated-list spelling is refused by the pre-existing chunk reader,
  // at the base as at this head; the asymmetry between the two spellings is what this reading added and what this
  // assertion pins, so neither half can be swapped for the other by a later change.
  assert.equal(unknown(Array.from({ length: 60 }, (_, index) => `part${index + 1}: =41 =42`).join('\n')).decision, 'ALLOW');
  assert.ok(unknown(Array.from({ length: 60 }, () => '=41 =42').join(' ')).reasons.includes('OPAQUE_EMBEDDED'));
  // Prose spelled in escapes across a declared series is ordinary text and stays ordinary, and a planted value in
  // that spelling is still found: the exemption is over the text's shape, not over its contents.
  assert.equal(unknown(labelledEscapeText('ordinary build log about the synthetic service, nothing protected here',
    qp, 4)).decision, 'ALLOW');
  blocksWithOriginal(labelledEscapeText(ESCAPED_NOTE, qp, 1), true);
  blocksWithOriginal(labelledEscapeText(ESCAPED_NOTE, qp, 2), true);
});

test('issue 126: ordinary escaped text, labels and configuration stay allowed', () => {
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  // Accented prose as escapes, entity runs in prose and in a query string, escaped digits, and ordinary text that
  // merely contains separator-class punctuation. A declared series adds no opaque bytes of its own, so labelled
  // configuration written in escapes keeps its shape: only a stream inside it is read.
  for (const payload of [
    '\\u00e9'.repeat(40), '&#160; &#160; &#160; spacing', '&#8212; &#8217; &euro; &nbsp; in prose',
    'entities &#8212; &#8217; &euro; &nbsp; in prose', 'width = 41% height = 42px top = 0 left = 0',
    'time=12:30:45 date=2026-10-02 pid=1234 tid=0x4f2a cpu=3.5% mem=12%',
    'query: ?a=1&b=22&c=333 filter[status]=200 limit=50 offset=1000', 'budget = 100 &amp; cost = 200 &amp; total = 300',
    'RAX=EC37B814521BE4FD  RAX=073592AFDF35F68 note', 'key =41 , =42 ; =43 , =44 done',
    'x =41, y =42, z =43, w =44', 'step 1: =41\nstep 2: =42\nstep 3: =43\n',
    'part1: \\n\\npart2: \\t\\tpart3: \\r\\rpart4: \\n\\n', 'part1: alpha\npart2: gamma\npart3: delta\n',
    'matrix = [1, 0, 0, 0, 1, 0, 0, 0, 1]', 'step one / step two / step three', 'alpha + beta > gamma / delta',
  ]) {
    assert.equal(unknown(payload).decision, 'ALLOW', `${payload.slice(0, 44)} ${unknown(payload).reasons.join()}`);
    assert.equal(unknown(JSON.stringify({ content: payload })).decision, 'ALLOW', `json ${payload.slice(0, 44)}`);
  }
  // A declared series adds no opaque bytes of its own, in raw text: a series of accents, and one of control-byte
  // escapes below the reconstruction floor, keep their shape however many fields they carry.
  for (const payload of [Array.from({ length: 24 }, (_, index) => `part${index + 1}: \\u00e9`).join('\n'),
    Array.from({ length: 12 }, (_, index) => `part${index + 1}: \\x20 \\x09 \\x0a`).join('\n')]) {
    assert.equal(unknown(payload).decision, 'ALLOW', `${payload.slice(0, 44)} ${unknown(payload).reasons.join()}`);
  }
  // A compressed blob of ordinary text inside a declared escape series is read, and read as ordinary.
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const ordinary = zlib.gzipSync(Buffer.from('ordinary build log about the synthetic service, nothing protected'));
  assert.equal(unknown(labelledEscapeSeries(ordinary, escapeFamilies().quotedPrintable, 1).lines).decision,
    'ALLOW', 'ordinary compressed text');
});

test('issue 126: reconstruction stays inside the run bound, and a wider gap is refused rather than released', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const spell = escapeFamilies().quotedPrintable;
  const stream = zlib.gzipSync(Buffer.from(ESCAPED_NOTE));
  // A declared field holding more than `MAX_ESCAPED_RUN` escapes is split at that bound, and the split drops no
  // byte: the pieces carry the field's own label and the series concatenates them back. A payload straddling that
  // bound is not reported by name here, for the reason #124 already published for the direct reader — the run is
  // far above the opaque threshold, so it is refused by the byte count rather than by its contents. What is
  // pinned is the direction that matters: a refusal with a reason, and no released bytes.
  for (const pad of [4_000, 32_760, 40_000]) {
    const payload = `part1: ${[...Buffer.concat([Buffer.alloc(pad, 0x3d), stream])].map(spell).join(' ')}`;
    assert.ok(payload.length <= MAX_MESSAGE_BYTES, `${pad}`);
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK', `${pad}`);
    assert.ok(result.reasons.length > 0, `${pad}`);
    assert.equal(result.release, undefined, `${pad}`);
  }
  // A payload whose pieces are each under the bound is read precisely, however many fields carry it.
  const halves = Math.floor(stream.length / 2);
  blocksWithOriginal([
    [...stream.subarray(0, halves)].map(spell).join(' '), [...stream.subarray(halves)].map(spell).join(' '),
    [...zlib.brotliCompressSync(Buffer.from(ESCAPED_NOTE))].map(spell).join(' '),
  ].map((value, index) => `part${index + 1}: ${value}`).join('\n'), true);
  // The separator bound itself: eight separator-class characters between two escapes is still formatting. The
  // gap beyond it, and a gap holding any other character, are pinned as declared limits in the next group.
  for (const separator of [' '.repeat(8), ','.repeat(8), `${','.repeat(7)} `]) {
    blocksWithOriginal([...stream].map(escapeFamilies().quotedPrintable).join(separator), true);
  }
  // A declared series split across two names is the other limit the series reading publishes: it joins one series
  // and never a subset of names, so the alternative to choosing a subset is not reconstructing it at all.
  const fields = labelledEscapeSeries(stream, spell, 1);
  const twoNames = fields.lines.split('\n').map((line, index) => line.replace('part', index % 2 ? 'part' : 'chunk')).join('\n');
  assert.ok(!check(twoNames).reasons.includes('KNOWN_ORIGINAL_DETECTED'), twoNames.slice(0, 40));
  // A dense 1 MiB escaped list with the wider separator decides inside a work bound rather than uninspectably.
  const dense = Array.from({ length: 200_000 }, (_, index) => spell(index % 256)).join(', ').slice(0, MAX_MESSAGE_BYTES);
  const started = process.hrtime.bigint();
  const denseResult = check(dense);
  const denseMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(['ALLOW', 'BLOCK'].includes(denseResult.decision), denseResult.reasons.join());
  assert.ok(denseMs < 5000, `${denseMs.toFixed(0)}ms`);
  // The same demand written as a declared label series, which is charged like every other reconstruction: a
  // message demanding more of them than the budget allows is uninspectable rather than quietly clean.
  const series = Array.from({ length: 60_000 }, (_, index) => `part${index + 1}: ${spell(index % 256)}`).join('\n')
    .slice(0, MAX_MESSAGE_BYTES);
  const seriesAt = process.hrtime.bigint();
  const seriesResult = check(series);
  const seriesMs = Number(process.hrtime.bigint() - seriesAt) / 1e6;
  assert.ok(['ALLOW', 'BLOCK'].includes(seriesResult.decision), seriesResult.reasons.join());
  assert.equal(seriesResult.release, undefined);
  assert.ok(seriesMs < 5000, `${seriesMs.toFixed(0)}ms`);
});

test('issue 88: the escape separator bound is a bounded run, and the rest is measured, not claimed closed', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const stream = zlib.gzipSync(Buffer.from(ESCAPED_NOTE));
  // Superseded by #126 in one place only: a gap of two or more separator-class characters between two escapes used
  // to end this reader's run, so each remaining escape was a one-byte run below the floor and the note was
  // released with `release` bytes. It is read now, by the groups above and by the boundary cases in this one; what
  // remains is pinned here and is a declared limit, not a completeness claim.
  //
  // A gap holding a character outside the class, or wider than `MAX_ESCAPE_SEPARATOR`, still ends the run: this
  // reader skips formatting between escapes and never skips words. The `\x`-prefixed spelling keeps the
  // byte-pair reader's own, already-published coverage wherever that reader's separator class reaches (a single
  // `-`, a run of whitespace), unchanged by this reader either way.
  const bytePair = new Set(['- ', ' '.repeat(9)]);
  for (const separator of ['- ', ' -> ', ' and ', ' '.repeat(9), '/ / /']) {
    for (const [family, spell] of Object.entries(escapeFamilies())) {
      const body = [...stream].map(spell).join(separator);
      assert.ok(body.length <= MAX_MESSAGE_BYTES, `${family}/${JSON.stringify(separator)}`);
      const result = check(body);
      if (family === 'hex' && bytePair.has(separator)) assert.equal(result.decision, 'BLOCK', `hex/${JSON.stringify(separator)}`);
      else assert.ok(!result.reasons.includes('KNOWN_ORIGINAL_DETECTED'),
        `${family}/${JSON.stringify(separator)}: ${result.reasons.join()}`);
    }
  }
  // An escape run shorter than four bytes is not one, and stays ordinary text.
  assert.equal(check('=41 =42 =43 end', { known: null }).decision, 'ALLOW');
  assert.equal(check('&#65 &#66 &#67 end', { known: null }).decision, 'ALLOW');
  // A single separator character is still read in every spelling, exactly as #124 left it, and the `\x`-prefixed
  // spelling is rebuilt by the byte-pair reader at a single separator whatever this reader does with it.
  for (const separator of ESCAPE_SEPARATORS) {
    for (const [family, spell] of Object.entries(escapeFamilies())) blocksWithOriginal([...stream].map(spell).join(separator), true);
  }
  for (const separator of [', ', '. ', ': ', '  ', '\r\n', ' , ', ' \u0020 ']) {
    assert.equal(check([...stream].map(escapeFamilies().hex).join(separator)).decision, 'BLOCK',
      `hex/${JSON.stringify(separator)}`);
  }
});

/**
 * Independent review of `c091789`, blocking finding, reproduced here: the one-character separator rule had been
 * applied inside the quoted-string reader as well. Inside `b'…'` or a JSON string every literal character is a byte
 * of that string, so a compressed payload whose own bytes include a separator-class character — written literally
 * between two escapes — lost that byte. Base reconstructed the stream and blocked with the precise reason;
 * `c091789` inflated nothing, the corrupted bytes stayed under `OPAQUE_BYTES`, and `checkEgress` returned `ALLOW`
 * **with `release` bytes**. That is a fail-open regression, not a completeness gap, and it is pinned below in
 * decision, reason and released bytes over a generated corpus whose two builds are compared case by case.
 *
 * The second half of the same finding is the mirror image: a reading this module already had must not be *replaced*
 * by the new one. Ordinary text is therefore read twice — the contiguous reading first, the separated one added to
 * it — so a sender who formats an escape list, and a sender whose separator character is a byte of the payload,
 * both keep every reading they had. The quoted reading is unchanged and is the only reading inside a string.
 */
const ESCAPE_LITERAL_NOTES = [
  `note for ${PLANTED} re ${CANARY}`,
  `contact ${PLANTED} about ${CANARY} | a,b; c:d. e&f [g] h (i) and more synthetic padding text here`,
  `'0&:''c;:b  ";9--&${PLANTED}'0&:''c;:b  ";9--&`,
];
/** Separator-class byte values that are literal inside both quoted shapes; `"`, `'` and `\` would close the quoting. */
const ESCAPE_LITERAL_BYTES = [0x20, 0x09, 0x0a, 0x0d, 0x2c, 0x3a, 0x3b, 0x26, 0x2e, 0x5b, 0x5d, 0x7c];
const escapeLiteralCases = (compressors) => {
  const families = escapeFamilies();
  const cases = [];
  compressors.forEach((compress, compressor) => {
    ESCAPE_LITERAL_NOTES.forEach((note, noteIndex) => {
      const stream = compress(Buffer.from(note));
      for (const [family, spell] of Object.entries(families)) {
        const planted = [];
        for (let at = 1; at < stream.length - 1; at++) if (ESCAPE_LITERAL_BYTES.includes(stream[at])) planted.push(at);
        // First, middle and last interior occurrence: bounded, deterministic, and spread over the stream.
        for (const at of [planted[0], planted[Math.floor(planted.length / 2)], planted.at(-1)]
          .filter((value, index, all) => value !== undefined && all.indexOf(value) === index)) {
          const char = String.fromCharCode(stream[at]);
          const body = [...stream].map((byte, index) => (index === at ? char : spell(byte))).join('');
          for (const [shape, wrap] of Object.entries({
            json: (value) => JSON.stringify({ content: value }), py: (value) => `b'${value}'`, raw: (value) => value,
          })) cases.push({ shape, label: `${compressor}/${noteIndex}/${family}/0x${stream[at].toString(16)}@${at}`, payload: wrap(body) });
        }
      }
    });
  });
  return cases;
};

test('issue 88 review: a literal separator character between two escapes inside a quoted string is data', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const compressors = [zlib.gzipSync, zlib.deflateSync, zlib.deflateRawSync, zlib.brotliCompressSync];
  // 360 generated cases: four compressors, three notes, six families, up to three planted positions, three shapes.
  const cases = escapeLiteralCases(compressors);
  assert.ok(cases.length >= 300, `${cases.length} generated literal-separator cases`);
  const per = {};
  for (const { shape, label, payload } of cases) {
    const result = check(payload);
    // Fail closed with a reason and nothing released, whatever the character between the escapes was.
    assert.equal(result.decision, 'BLOCK', label);
    assert.ok(result.reasons.length > 0, label);
    assert.equal(result.release, undefined, label);
    per[shape] ??= { total: 0, precise: 0 };
    per[shape].total++;
    if (result.reasons.includes('KNOWN_ORIGINAL_DETECTED')) per[shape].precise++;
  }
  // Blocking opaquely is not enough: the corpus has to keep the precise known-original finding base reports. Measured
  // on base `e2b5714` over this same corpus: json 109/120, python 109/120, unquoted 54/120; at `c091789` the two
  // quoted shapes fell to 42/120 and the corpus held six releases with `release` bytes. The floors sit below what
  // base reports and far above what the reviewed head reported, so a reading that stops being read fails here.
  assert.ok(per.json.precise >= 100, `json precise ${per.json.precise}/${per.json.total}`);
  assert.ok(per.py.precise >= 100, `python precise ${per.py.precise}/${per.py.total}`);
  assert.ok(per.raw.precise >= 50, `unquoted precise ${per.raw.precise}/${per.raw.total}`);
  // The reviewer's own mechanism, spelled out: a gzip note whose bytes include a tab, the tab written literally
  // between two percent escapes inside a JSON string and inside a Python byte literal. Base blocks with both
  // findings; `c091789` returned ALLOW with 306 and 295 released bytes.
  const stream = zlib.gzipSync(Buffer.from(`contact ${PLANTED} about ${CANARY} and some more synthetic padding text`));
  const at = stream.indexOf(0x09, 1);
  assert.ok(at > 0, `the note must contain a tab byte at ${at}`);
  const planted = [...stream].map((byte, index) => (index === at ? '\t' : `%${byte.toString(16).padStart(2, '0')}`)).join('');
  for (const payload of [JSON.stringify({ content: planted }), `b'${planted}'`]) {
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK', payload.slice(0, 40));
    assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), payload.slice(0, 40));
    assert.ok(result.reasons.includes('CANARY_DETECTED'), payload.slice(0, 40));
    assert.equal(result.release, undefined, payload.slice(0, 40));
  }
  // Controls: the same byte written as its own escape is ordinary formatting between escapes and blocks precisely,
  // and the unquoted formatted list — the capability this reader gained — is unchanged by any of the above.
  const spelled = [...stream].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join(' ');
  for (const payload of [spelled, `{"content":"${spelled}"}`, `b'${spelled}'`]) {
    const result = check(payload);
    assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), `${payload.slice(0, 40)}: ${result.reasons.join()}`);
    assert.equal(result.release, undefined, payload.slice(0, 40));
  }
});

test('issue 88 review: ordinary text with escape-shaped tokens and quoted literals is unchanged', () => {
  // No new false positives: the separated reading is added beside the contiguous one, and inside a quoted string
  // nothing changed at all. Ordinary prose, log lines, configuration and quoted literals that happen to spell
  // `=NN`, `%NN`, `#NN`, `0xNN`, `&#NN;` or `\xNN` tokens stay allowed in raw text and inside JSON strings.
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  for (const payload of [
    'RAX=EC37B814521BE4FD RAX=073592AFDF35F68', 'GET /api 200 traceparent=00-f569e0751199 - 42ms',
    'colour: #ff8800; margin: 0 auto; content: "a=1 b=2 c=3" padding: 4px',
    'query: ?a=1&b=22&c=333 filter[status]=200 limit=50 offset=1000', 'width = 41% height = 42px top = 0 left = 0',
    'time=12:30:45 date=2026-10-02 pid=1234 tid=0x4f2a cpu=3.5% mem=12%', 'mask: 0xFF 0x00 0x7F 0x80 flags=0x1 shift=0x10',
    'matrix [1, 0, 0, 0, 1, 0, 0, 0, 1]', "note =41 =42 =43 =44 done", 'entities &#8212; &#8217; &euro; &nbsp; in prose',
    'x=1 y=2 z=3 w=4 v=5 u=6 t=7 s=8 r=9 q=10', 'chmod 644 file.txt; umask 022; ulimit -n 1024',
    'b\'\\x41\\x42 plain bytes\'', 'b"\\x4f\\x72\\x6c\\x61 ordinary"', 'value = "=41 =42 =43 =44" and =22 trailing',
  ]) {
    assert.equal(unknown(payload).decision, 'ALLOW', `raw ${payload.slice(0, 44)} ${unknown(payload).reasons.join()}`);
    assert.equal(unknown(JSON.stringify({ content: payload })).decision, 'ALLOW', `json ${payload.slice(0, 44)}`);
  }
  // And the pinned positives around it: a formatted escape list still blocks with both findings, in every shape.
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const spell = escapeFamilies().percent;
  for (const compress of [zlib.gzipSync, zlib.brotliCompressSync]) {
    const stream = compress(Buffer.from(ESCAPED_NOTE));
    for (const payload of [[...stream].map(spell).join(' '), JSON.stringify({ content: [...stream].map(spell).join(' ') }),
      `b'${[...stream].map((byte) => (byte >= 32 && byte < 127 && byte !== 39 && byte !== 92
        ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, '0')}`)).join('')}'`]) {
      blocksWithOriginal(payload, true);
    }
  }
});

test('independent review: a short final default xxd row retains every byte of a planted zlib stream', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const bytes = zlib.deflateSync('Orla Synthetica ABCDEFG');
  assert.equal(bytes.length, 31);
  const dump = Array.from({ length: Math.ceil(bytes.length / 16) }, (_, row) => {
    const line = bytes.subarray(row * 16, row * 16 + 16);
    const groups = Buffer.from(line).toString('hex').match(/.{1,4}/gu).join(' ');
    const ascii = [...line].map((byte) => byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '.').join('');
    return `${(row * 16).toString(16).padStart(8, '0')}: ${groups.padEnd(39)}  ${ascii}`;
  }).join('\n');
  for (const payload of [dump, JSON.stringify({ content: dump })]) {
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK');
    assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), result.reasons.join(','));
  }
});

test('independent review: JSON-wrapped Python byte literals expose short raw deflate', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const bytes = zlib.deflateRawSync(PLANTED);
  assert.equal(bytes.length, 17);
  const literal = `b'${[...bytes].map((byte) => byte >= 32 && byte < 127 && byte !== 39 && byte !== 92
    ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, '0')}`).join('')}'`;
  const result = check(JSON.stringify({ content: literal }));
  assert.equal(result.decision, 'BLOCK');
  assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), result.reasons.join(','));
});

test('independent review: ternary label exemption does not hide a credential inside a branch', () => {
  const unknown = (text) => check(text, { known: null });
  const result = unknown("kind ? 'password: Synthetic-passw0rd' : 'other'");
  assert.equal(result.decision, 'BLOCK');
  assert.ok(result.reasons.includes('HIGH_RISK_PATTERN'));
  assert.equal(unknown("const label = kind === 'credential' ? 'SECRET' : 'INTERNAL';").decision, 'ALLOW');
});

test('independent review: only complete advisory identifiers receive the identifier exemption', () => {
  const unknown = (text) => check(text, { known: null });
  const suffix = createHash('sha256').update('synthetic-advisory-suffix').digest('base64url');
  const prefix = createHash('sha256').update('synthetic-advisory-prefix').digest('base64url');
  // Lowercase Base32 prefixes of SHA-256('synthetic-prefix-a/b'), truncated to 32 characters.
  const base32A = 'vgoo2zy4d7k2i5s4oe4sk32ted5fxioy';
  const base32B = 'orghtfbubbnd3he4osguykve42a74i47';
  assert.equal(unknown(`GHSA-c2qf-rxjj-qqgw${suffix}`).decision, 'BLOCK');
  assert.equal(unknown(`${prefix}/GHSA-c2qf-rxjj-qqgw`).decision, 'BLOCK');
  assert.equal(unknown(`${base32A}/${base32B}/GHSA-c2qf-rxjj-qqgw`).decision, 'BLOCK');
  assert.equal(unknown(`${base32A}/${base32B}/GHSX-c2qf-rxjj-qqgw`).decision, 'BLOCK');
  assert.equal(unknown(`${base32A}/${base32B}/CVE-2026-12345`).decision, 'BLOCK');
  assert.equal(unknown(`${base32A}/${base32B}/CVX-2026-12345`).decision, 'BLOCK');
  for (const identifier of ['GHSA-c2qf-rxjj-qqgw', 'CVE-2026-12345', 'GHSX-c2qf-rxjj-qqgw', 'CVX-2026-12345', 'docs/security']) {
    for (const count of [64, 128]) {
      assert.equal(unknown(`${'/'.repeat(count)}${identifier}`).decision, 'BLOCK', `${count} ${identifier}`);
    }
    for (const slash of ['%2F', '%2f', '\\u002f']) {
      assert.equal(unknown(`${slash.repeat(64)}${identifier}`).decision, 'BLOCK', `${slash} ${identifier}`);
    }
  }
  assert.equal(unknown(`${'/'.repeat(7)}docs${'/'.repeat(7)}readme${'/'.repeat(7)}CVX-2026-12345`).decision, 'BLOCK');
  for (const width of [2, 3, 4, 5, 6, 7]) {
    const prefix = ['docs', 'readme', 'security', 'guides', 'notes', 'issues', 'archive'].join('/'.repeat(width));
    for (const suffix of ['CVX-2026-12345', 'GHSX-c2qf-rxjj-qqgw', 'docs/security']) {
      assert.equal(unknown(`${prefix}${'/'.repeat(width)}${suffix}`).decision, 'BLOCK', `${width} ${suffix}`);
    }
  }
  assert.equal(unknown('GHSA-c2qf-rxjj-qqgw').decision, 'ALLOW');
  assert.equal(unknown('advisories/GHSA-c2qf-rxjj-qqgw').decision, 'ALLOW');
  assert.equal(unknown('/advisories/GHSA-c2qf-rxjj-qqgw').decision, 'ALLOW');
  assert.equal(unknown('docs/security/advisories/GHSA-c2qf-rxjj-qqgw').decision, 'ALLOW');
  assert.equal(unknown('https://github.com/advisories/GHSA-c2qf-rxjj-qqgw').decision, 'ALLOW');
  assert.equal(unknown('Engineering/Security/advisories/GHSA-c2qf-rxjj-qqgw').decision, 'ALLOW');
  assert.equal(unknown('https://github.com/SomeOrg/Security/advisories/GHSA-c2qf-rxjj-qqgw').decision, 'ALLOW');
  assert.equal(unknown('Engineering/Security/advisories/CVE-2026-12345').decision, 'ALLOW');
  assert.equal(unknown('/Engineering/Security/advisories/CVE-2026-12345').decision, 'ALLOW');
  assert.equal(unknown('https://github.com/my_org/my_repo/security/GHSA-c2qf-rxjj-qqgw').decision, 'ALLOW');
  assert.equal(unknown('https://github.com/my_org/my_repo/security/GHSX-c2qf-rxjj-qqgw').decision, 'ALLOW');
  assert.equal(unknown('/Engineering/Security/issues/CVX-2026-12345').decision, 'ALLOW');
  assert.equal(unknown('docs/security').decision, 'ALLOW');
  assert.equal(unknown('//github/advisories/GHSA-c2qf-rxjj-qqgw').decision, 'ALLOW');
  assert.equal(unknown('docs/security/readme/CVX-2026-12345').decision, 'ALLOW');
});

test('independent review: digest and SSH exemptions validate length and wire structure', () => {
  const unknown = (text) => check(text, { known: null });
  const blob = Buffer.concat([
    createHash('sha256').update('synthetic-a').digest(), createHash('sha256').update('synthetic-b').digest(),
  ]).toString('base64');
  assert.equal(unknown(blob).decision, 'BLOCK');
  assert.equal(unknown(`sha256-${blob}`).decision, 'BLOCK');
  assert.equal(unknown(`Content-MD5: ${blob}`).decision, 'BLOCK');
  assert.equal(unknown(`ssh-ed25519 ${blob} user@host.invalid`).decision, 'BLOCK');
  const publicWire = Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), syntheticBytes(32)]);
  assert.equal(unknown(`xssh-ed25519 ${publicWire.toString('base64')} user@host.invalid`).decision, 'BLOCK');
  assert.equal(unknown(`ssh-ed25519 ${publicWire.toString('hex')} user@host.invalid`).decision, 'BLOCK');
  assert.equal(unknown(`sha256-${syntheticBytes(32).toString('base64')}`).decision, 'ALLOW');
  assert.equal(unknown(`ssh-ed25519 ${sshEd25519Public()} user@host.invalid`).decision, 'ALLOW');
});

test('independent review: short registered originals are matched under short encodings', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const raw = (value) => zlib.deflateRawSync(value).toString('base64');
  const pem = (value) => `-----BEGIN CERTIFICATE-----\n${Buffer.concat([Buffer.from([0x30, 0x04]), Buffer.from(value)]).toString('base64')}\n-----END CERTIFICATE-----`;
  for (const payload of ['T3JsYQ==', '4f726c61', '0x4f726c61', JSON.stringify({ content: 'T3JsYQ==' }),
    raw('Orla'), zlib.deflateRawSync('Orla').toString('base64url'), pem('Orla')]) {
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK', payload);
    assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), `${payload}: ${result.reasons}`);
  }
  for (const payload of ['T3JsZQ==', '42656c61', '0x42656c61', JSON.stringify({ content: 'T3JsZQ==' }), raw('Bela'), pem('Bela')]) {
    assert.equal(check(payload).decision, 'ALLOW', payload);
  }
});

test('independent review: ordinary decimals cannot gain opaque authority from tentative raw deflate', () => {
  const unknown = (text) => check(text, { known: null });
  for (const payload of ['0.7231478778415019', JSON.stringify({ content: '0.7231478778415019' })]) {
    assert.equal(unknown(payload).decision, 'ALLOW', payload);
  }
});

/* ---------- Issue #19 residual encoded views: labelled chunks, declared separators, byte arrays ---------- */

const SECRET_NOTE = `contact ${PLANTED} re ${CANARY} ${syntheticBytes(16).toString('hex')} `;
const splitEvery = (text, width) => text.match(new RegExp(`.{1,${width}}`, 'gu'));
/**
 * Every assertion here is a public-interface decision and reason code, never a planted value. A truncated
 * prefix carries the planted original but not the canary, so `complete` marks the payloads that hold it all.
 */
const blocksWithOriginal = (payload, complete = true) => {
  const result = check(payload);
  assert.equal(result.decision, 'BLOCK', payload.slice(0, 40));
  assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), `${payload.slice(0, 40)}: ${result.reasons.join()}`);
  if (complete) assert.ok(result.reasons.includes('CANARY_DETECTED'), `${payload.slice(0, 40)}: ${result.reasons.join()}`);
  assert.equal(result.release, undefined);
  return result;
};
/**
 * A dress that leaves one Base64 run (`A+B`, or a JSON-escaped separator whose letters fuse with the next chunk)
 * is already refused as opaque binary by the plain encoded-run reader: a block, without the precise reason.
 */
const blocksLeak = (payload) => {
  const result = check(payload);
  assert.equal(result.decision, 'BLOCK', payload.slice(0, 40));
  assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED') || result.reasons.includes('OPAQUE_EMBEDDED'),
    `${payload.slice(0, 40)}: ${result.reasons.join()}`);
  assert.equal(result.release, undefined);
  return result;
};

test('residual encoded views: labelled chunks are rebuilt, inflated and matched', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const note = Buffer.from(SECRET_NOTE);
  const compressed = zlib.gzipSync(note);
  for (const width of [7, 8, 11, 16, 24, 40]) {
    const text = splitEvery(note.toString('base64'), width);
    const gzip = splitEvery(compressed.toString('base64'), width);
    const labelled = (chunks, label, opener, closer) => chunks.map((chunk, index) =>
      `${opener}${label}${index + 1}${closer}${chunk}`).join('\n');
    for (const payload of [
      labelled(text, 'part', '', ': '),
      labelled(text, 'p', '', '='),
      labelled(text, 'chunk_', '', ': '),
      labelled(text, 'PART', '', ': '),
      labelled(gzip, 'part', '', ': '),
      labelled(gzip, 'p', '', '='),
      text.map((chunk, index) => `part${index + 1}: ${chunk}`).join('&'),
      text.map((chunk, index) => `\tpart${index + 1}\t=\t${chunk}`).join(',\n'),
      text.map((chunk, index) => `"part${index + 1}":"${chunk}"`).join(','),
      JSON.stringify(Object.fromEntries(text.map((chunk, index) => [`part${index + 1}`, chunk]))),
      JSON.stringify(text.map((chunk, index) => ({ part: index + 1, data: chunk }))),
      JSON.stringify(text.map((chunk, index) => ({ index: index + 1, note: 'ignored', data: chunk })), null, 2),
      JSON.stringify({ parts: text.map((chunk, index) => ({ id: index + 1, value: chunk })) }, null, 2),
      `payload ${text.map((chunk, index) => `part${index + 1}: ${chunk}`).join(' note ')}`,
    ]) blocksWithOriginal(payload);
    // Declared separators: an explicit concatenation join of the same compressed note. Hex chunks keep an
    // even width, since an odd-width split shifts every following nibble and cannot be rebuilt at all.
    const hex = splitEvery(compressed.toString('hex'), width + (width % 2));
    for (const payload of [hex.join(' + '), hex.join('/'), hex.join(' > '), gzip.join(' + '), gzip.join(' / '),
      gzip.join(' > '), `data ${hex.join(' + ')} trailing`]) blocksWithOriginal(payload);
  }
});

test('residual encoded views: label order, decoys and mixed syntax are reconstructed', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const note = Buffer.from(SECRET_NOTE);
  const chunks = splitEvery(zlib.gzipSync(note).toString('base64'), 8);
  assert.ok(chunks.length > 10, 'needs enough chunks for a lexicographic mis-order');
  const reversed = chunks.map((chunk, index) => `part${chunks.length - index}: ${chunk}`).join('\n');
  const lexical = [...chunks.keys()].sort((a, b) => `p${a + 1}` < `p${b + 1}` ? -1 : 1)
    .map((index) => `p${index + 1}: ${chunks[index]}`).join('\n');
  const singleDigit = chunks.slice(0, 9).map((chunk, index) => `p${index + 1}: ${chunk}`).join('\n');
  for (const [payload, complete] of [[reversed, true], [lexical, true], [singleDigit, false],
    [chunks.map((chunk, index) => `part${index + 1}: ${chunk}`).join('\n'), true],
    [chunks.map((chunk, index) => `part${index + 1}: ${chunk}`).join(' decoy '), true],
    [chunks.map((chunk, index) => `{"part":${index + 1},"data":"${chunk}"}`).join(',\n'), true]]) {
    blocksWithOriginal(payload, complete);
  }
  // The same bytes as a decimal byte array and as Node `Buffer` JSON.
  for (const bytes of [zlib.gzipSync(note), [...note], zlib.deflateSync(note)]) {
    blocksWithOriginal(`[${[...bytes].join(', ')}]`);
    blocksWithOriginal(`{"type":"Buffer","data":[${[...bytes].join(',')}]}`);
    blocksWithOriginal(JSON.stringify({ messages: [{ content: `[${[...bytes].map((b) => `0x${b.toString(16).padStart(2, '0')}`).join(', ')}]` }] }));
  }
  blocksWithOriginal(JSON.stringify({ content: `{"type":"Buffer","data":[${[...zlib.gzipSync(note)].join(',')}]}` }));
  // Labelled hex with per-field `0x` prefixes, and the same list nested in an escaped JSON string.
  const hexChunks = splitEvery(zlib.gzipSync(note).toString('hex'), 8);
  blocksWithOriginal(hexChunks.map((chunk, index) => `part${index + 1}: 0x${chunk}`).join('\n'));
  blocksWithOriginal(JSON.stringify({ content: JSON.stringify({ parts: hexChunks.map((chunk, index) => ({ part: index + 1, data: chunk })) }) }));
  blocksWithOriginal(JSON.stringify({ content: `[${[...zlib.gzipSync(note)].map(String).join('\\u002c')}]`.replaceAll('\\u002c', ',') }));
});

test('residual encoded views: an interleaved ordinary field no longer defeats a declared label series', () => {
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const note = Buffer.from(SECRET_NOTE);
  const chunks = splitEvery(zlib.gzipSync(note).toString('base64'), 8);
  const parts = chunks.map((chunk, index) => `part${index + 1}: ${chunk}`);
  const withField = (field, at) => [...parts.slice(0, at), field, ...parts.slice(at)].join('\n');
  // A field the group never declared as part of the payload (`trace: 1a2b3c4d`, `note: Zz9Qa1b2`,
  // `region: 4f2a91b7`) is what an honest trace between labelled parts looks like. It carries no bytes of its own
  // payload, so the declared series stays readable on its own, before, in the middle and after it.
  for (const [label, value] of [['trace', '1a2b3c4d'], ['note', 'Zz9Qa1b2'], ['region', '4f2a91b7'],
    ['x', syntheticBytes(8).toString('hex')], ['region_code', 'c3d4e5f6']]) {
    for (const at of [0, 1, Math.floor(parts.length / 2), parts.length - 1, parts.length]) {
      blocksWithOriginal(withField(`${label}: ${value}`, at));
      blocksWithOriginal(withField(`${label}=${value}`, at));
      blocksWithOriginal(withField(`"${label}":"${value}"`, at));
    }
  }
  // Several such fields at once, and a field on a line of its own between two parts.
  for (const at of [0, 2, parts.length - 1, parts.length]) blocksWithOriginal([...parts.slice(0, at),
    'trace: 1a2b3c4d', 'region: 4f2a91b7', ...parts.slice(at)].join('\n'));
  blocksWithOriginal(parts.join(' the next part follows here. '));
  // A field whose own label is entirely hex (`face: 1a2b3c4d`, a dump offset column) joins no reading, and it must
  // not split the labelled declaration either: the series either side of it is still one declared sequence.
  for (const label of ['d0', 'cafe', 'deadbeef', 'bad', 'f00d', 'abc123', 'eff']) {
    for (const at of [1, Math.floor(parts.length / 2)]) blocksWithOriginal(
      [...parts.slice(0, at), `${label}: 1a2b3c4d`, ...parts.slice(at)].join('\n'));
  }
  // JSON bodies, YAML lists, query strings, list markers and an escaped inner body.
  const object = Object.fromEntries(parts.map((line) => [line.slice(0, line.indexOf(':')), line.slice(line.indexOf(': ') + 2)]));
  blocksWithOriginal(JSON.stringify({ trace: '1a2b3c4d', ...object }));
  blocksWithOriginal(JSON.stringify({ ...object, trace: '1a2b3c4d' }));
  blocksWithOriginal(JSON.stringify({ parts: [{ trace: '1a2b3c4d' },
    ...chunks.map((chunk, index) => ({ part: index + 1, data: chunk }))] }));
  blocksWithOriginal(JSON.stringify({ content: [...parts.slice(0, 2), 'trace: 1a2b3c4d', ...parts.slice(2)].join('\n') }));
  blocksWithOriginal(chunks.flatMap((chunk, index) => index === 1 ? ['  trace: 1a2b3c4d', `  part${index + 1}: ${chunk}`]
    : [`  part${index + 1}: ${chunk}`]).join('\n'));
  blocksWithOriginal(parts.map((line) => line.replace(': ', '=')).join('&').replace('part2=', 'trace=1a2b3c4d&part2='));
  blocksWithOriginal(parts.map((line, index) => index === 1 ? `- trace: 1a2b3c4d\n- ${line}` : `- ${line}`).join('\n'));
  // Hex chunks, so the series reading is not a Base64 reading.
  const hex = splitEvery(zlib.gzipSync(note).toString('hex'), 16);
  for (const at of [0, 1, hex.length]) blocksWithOriginal([...hex.slice(0, at).map((value, index) => `part${index + 1}: ${value}`),
    'trace: 1a2b3c4d', ...hex.slice(at).map((value, index) => `part${index + at + 1}: ${value}`)].join('\n'));
  // Compressed opaque bytes behind an interleaved field stay opaque, not merely an allowed message.
  const opaqueChunks = splitEvery(zlib.gzipSync(syntheticBytes(200)).toString('base64'), 8);
  for (const at of [0, 2]) {
    const payload = [...opaqueChunks.slice(0, at).map((chunk, index) => `part${index + 1}: ${chunk}`), 'trace: 1a2b3c4d',
      ...opaqueChunks.slice(at).map((chunk, index) => `part${index + at + 1}: ${chunk}`)].join('\n');
    const result = unknown(payload);
    assert.equal(result.decision, 'BLOCK', payload.slice(0, 40));
    assert.ok(result.reasons.includes('OPAQUE_EMBEDDED'), result.reasons.join());
    assert.equal(result.release, undefined);
  }
});

test('residual encoded views: duplicate, ambiguous and unrelated labels each keep their own reading', () => {
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const chunks = splitEvery(zlib.gzipSync(Buffer.from(SECRET_NOTE)).toString('base64'), 8);
  const series = (label, values = chunks) => values.map((chunk, index) => `${label}${index + 1}: ${chunk}`);
  // A repeated field is read once as written.
  blocksWithOriginal(series('part').flatMap((line, index) => index % 4 === 0 ? [line, line] : [line]).join('\n'));
  // A duplicate label number carrying a different value is read the way a record with a duplicate key would be:
  // first occurrence and last occurrence, so neither reading depends on where the duplicate sits.
  for (const at of [1, Math.floor(series('part').length / 2)]) {
    const lines = series('part');
    const duplicate = lines[at].slice(0, lines[at].indexOf(':'));
    lines.splice(at, 0, `${duplicate}: 1a2b3c4d`);
    blocksWithOriginal(lines.join('\n'));
  }
  // Two declared series in one message: each is readable on its own, in either order, beside or interleaved.
  const first = series('part'), second = series('chunk');
  for (const payload of [[...first, ...second], [...second, ...first], first.flatMap((line, index) => [line, second[index]]),
    [...first, 'region: 4f2a91b7', ...second]]) blocksWithOriginal(payload.join('\n'));
  // Unrelated metadata carrying the payload beside a numbered decoy series is its own reading, and reading the
  // metadata never displaces reading the series beside it.
  const decoy = Array.from({ length: chunks.length }, (_, index) => `part${index + 1}: ${syntheticBytes(4).toString('hex')}`);
  for (const payload of [[...decoy, ...series('note')], [...series('note'), ...decoy], [...decoy, 'note: 4f2a91b7', ...series('note')]]) {
    blocksWithOriginal(payload.join('\n'));
  }
  blocksWithOriginal([...decoy, ...series('note'), ...series('other')].join('\n'));
  // Zero-padded, dashed and case-varied spellings of the same declared name are one series.
  for (const spell of [(index) => `part${String(index + 1).padStart(3, '0')}`, (index) => `part-${index + 1}`,
    (index) => `${index % 2 ? 'PART' : 'part'}${index + 1}`]) {
    const lines = chunks.map((chunk, index) => `${spell(index)}: ${chunk}`);
    lines.splice(1, 0, 'trace: 1a2b3c4d');
    blocksWithOriginal(lines.join('\n'));
  }
  // A numbered label whose values are plain numbers is an index list, not a payload, and stays allowed.
  for (const payload of [Array.from({ length: 40 }, (_, index) => `ts${index + 1}: ${1695826432 + index}`).join('\n'),
    Array.from({ length: 24 }, (_, index) => `part${index + 1}: ${(index + 1) * 8}`).join('\n'),
    '{"part1":1,"part2":2,"part3":3,"part4":4,"part5":5,"part6":6,"part7":7,"part8":8}']) {
    assert.equal(unknown(payload).decision, 'ALLOW', `${payload.slice(0, 40)} ${unknown(payload).reasons.join()}`);
  }
  // Ordinary labelled values that merely look encoded keep their shape: a declared series adds no opaque bytes.
  // (A series of *random* Base64 chunks is opaque before this change, through the plain chunk-sequence reader; a
  // hex series and a word series are the controls for the declared readings themselves.)
  for (const payload of [Array.from({ length: 40 }, (_, index) => `part${index + 1}: ${syntheticBytes(4).toString('hex')}`).join('\n'),
    `${Array.from({ length: 40 }, (_, index) => `part${index + 1}: ${syntheticBytes(4).toString('hex')}`).join('\n')}trace: 1a2b3c4d\n`,
    Array.from({ length: 12 }, (_, index) => `part${index + 1}: alpha${index}`).join('\ntrace: 1a2b3c4d\n'),
    // Hex-labelled values, and a dump offset column, are ordinary engineering text: no opaque authority.
    Array.from({ length: 40 }, (_, index) => `face${index}: ${syntheticBytes(4).toString('hex')}`).join('\n'),
    Array.from({ length: 8 }, (_, index) => `deadbeef${index}: ${syntheticBytes(16).toString('hex')}`).join('\n'),
    Array.from({ length: 40 }, (_, index) => `bad${index}: worker-${index}`).join('\n'),
    Array.from({ length: 8 }, (_, index) => `part${index + 1}: alpha${index}`).join('\ndeadbeef: 1f8b0800\n')]) {
    assert.equal(unknown(payload).decision, 'ALLOW', `${payload.slice(0, 40)} ${unknown(payload).reasons.join()}`);
  }
});

test('residual encoded views: a hex-alphabet label name declares its own numbered series', () => {
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const compressed = zlib.gzipSync(Buffer.from(SECRET_NOTE));
  // A label drawn from the hex alphabet is normally a value the sender wrote before a colon (`face: 1f8b0800`, a
  // dump offset), not a key. It is still a key when its own numbers declare one complete series under one name,
  // so the same payload is read whichever letters the sender picked, instead of depending on the label alphabet.
  const names = ['bad', 'dead', 'face', 'add', 'faded', 'cafe', 'beef', 'cab', 'deed', 'decade', 'facade'];
  for (const width of [6, 8]) {
    const chunks = splitEvery(compressed.toString('base64'), width);
    assert.ok(chunks.length >= 10, 'needs a long enough series to be worth labelling');
    // The same bytes under an ordinary label name, and with no labels at all, already blocked: what reaches the
    // hex-named shape is the declared series reading, not some other reader seeing the same payload.
    blocksWithOriginal(chunks.map((chunk, index) => `part${index + 1}: ${chunk}`).join('\n'));
    blocksWithOriginal(chunks.join('\n'));
    for (const name of names) {
      blocksWithOriginal(chunks.map((chunk, index) => `${name}${index + 1}: ${chunk}`).join('\n'));
      // Counted from zero, which is the same complete series.
      blocksWithOriginal(chunks.map((chunk, index) => `${name}${index}: ${chunk}`).join('\n'));
      // Hex chunks under a hex-labelled name are read as hex, not as Base64.
      blocksWithOriginal(splitEvery(compressed.toString('hex'), width + (width % 2))
        .map((chunk, index) => `${name}${index + 1}: ${chunk}`).join('\n'));
    }
  }
  const chunks = splitEvery(compressed.toString('base64'), 8);
  const parts = chunks.map((chunk, index) => `face${index + 1}: ${chunk}`);
  const at = (field, position) => [...parts.slice(0, position), field, ...parts.slice(position)].join('\n');
  // An unrelated field between the parts is what an honest trace looks like, and a dump offset column written
  // between them neither joins the series nor splits it in two.
  for (const field of ['trace: 1a2b3c4d', 'deadbeef: 1f8b0800', 'note: Zz9Qa1b2']) {
    for (const position of [0, 1, Math.floor(parts.length / 2), parts.length]) blocksWithOriginal(at(field, position));
  }
  // Syntaxes and label orders the same series is written in.
  blocksWithOriginal(parts.join('\n') + '\nregion: 4f2a91b7\n');
  blocksWithOriginal(parts.join(' the next part follows here. '));
  blocksWithOriginal(parts.join(',\n'));
  blocksWithOriginal(parts.map((line) => line.replace(': ', '=')).join('&'));
  blocksWithOriginal(parts.map((line) => `- ${line}`).join('\n'));
  blocksWithOriginal(parts.map((line) => `  ${line}`).join('\n'));
  blocksWithOriginal(JSON.stringify(Object.fromEntries(parts.map((line) =>
    [line.slice(0, line.indexOf(':')), line.slice(line.indexOf(': ') + 2)]))));
  blocksWithOriginal(JSON.stringify({ trace: '1a2b3c4d', ...Object.fromEntries(parts.map((line) =>
    [line.slice(0, line.indexOf(':')), line.slice(line.indexOf(': ') + 2)])) }));
  blocksWithOriginal(JSON.stringify({ content: parts.join('\n') }));
  blocksWithOriginal(chunks.map((chunk, index) => `${index % 2 ? 'FACE' : 'face'}${index + 1}: ${chunk}`).join('\n'));
  blocksWithOriginal(parts.map((line, index) => `face${String(index + 1).padStart(3, '0')}: ${chunks[index]}`).join('\n'));
  blocksWithOriginal(chunks.map((chunk, index) => `face${chunks.length - index}: ${chunk}`).join('\n'));
  blocksWithOriginal([...chunks.keys()].sort((a, b) => `face${a + 1}` < `face${b + 1}` ? -1 : 1)
    .map((index) => `face${index + 1}: ${chunks[index]}`).join('\n'));
  // Two complete series under two hex names in one message are each read on their own.
  blocksWithOriginal(chunks.flatMap((chunk, index) => [`face${index + 1}: ${chunk}`, `cafe${index + 1}: ${chunk}`]).join('\n'));
  blocksWithOriginal([...chunks.map((chunk, index) => `face${index + 1}: ${chunk}`), ...chunks.map((chunk, index) => `beef${index + 1}: ${chunk}`)].join('\n'));

  // Ordinary hex-labelled text is not a declaration: a hex dump offset column, hex values, word values and
  // decimals keep their shape, and none of them gains opaque authority from being read.
  for (const payload of [
    Array.from({ length: 40 }, (_, index) => `face${index}: ${syntheticBytes(4).toString('hex')}`).join('\n'),
    Array.from({ length: 8 }, (_, index) => `deadbeef${index}: ${syntheticBytes(16).toString('hex')}`).join('\n'),
    Array.from({ length: 40 }, (_, index) => `bad${index}: worker-${index}`).join('\n'),
    Array.from({ length: 8 }, (_, index) => `fade${index + 1}: ${1695826432 + index}`).join('\n'),
    '00000000  1f8b 0800 0000 0000 0003 4b4c 4a06  |.....K.LJ.|',
    '00000000: 1f8b 0800 0000 0000 0003 4b4c 4a06 4a06 4b4c',
    ['face: 1f8b0800', 'd10: 00000000', 'd20: 4b4c4a06', 'd30: 00000000'].join('\n'),
    `${Array.from({ length: 8 }, (_, index) => `part${index + 1}: alpha${index}`).join('\n')}\ndeadbeef: 1f8b0800`,
  ]) assert.equal(unknown(payload).decision, 'ALLOW', `${payload.slice(0, 44)} ${unknown(payload).reasons.join()}`);

  // Measured limits, not guarantees: a hex-labelled group whose numbers are not one complete series is not read,
  // because a dump offset column (`face:`, `d10:`) carries numbers too and only a complete run tells them apart.
  // With the planted originals registered these release the note at this width; they did before this correction.
  const ranked = (ranks) => ranks.map((rank, index) => `face${rank}: ${chunks[index]}`).join('\n');
  const every = (count) => Array.from({ length: count }, (_, index) => index + 1);
  for (const payload of [
    ranked([...every(9), 11, 12, 13, 14]),                                      // a gap in the numbering
    ranked([1, 1, ...every(3)]),                                                 // a repeated label number
    ranked(every(chunks.length).slice(1)),                                      // no first part
    chunks.map((chunk) => `face: ${chunk}`).join('\n'),                          // a hex name with no numbers
    `face1: ${chunks[0]}`,                                                       // one field is not a series
    chunks.map((chunk, index) => `${index % 2 ? `face${index + 1}` : `part${index + 1}`}: ${chunk}`).join('\n'),
    chunks.map((chunk, index) => `${index % 2 ? `face${String(index + 1).padStart(3, '0')}` : `part${index + 1}`}: ${chunk}`).join('\n'),
  ]) assert.equal(check(payload).decision, 'ALLOW', `${payload.slice(0, 44)} ${check(payload).reasons.join()}`);

  // The same group's **escape** spelling is stricter than the chunk spelling above, and the gap is pinned rather
  // than implied: a hex-labelled series of byte escapes is excluded from the series reading outright, because a
  // dump offset column (`face:`, `d10:`) carries numbers too and only a complete run tells the two apart. With the
  // planted originals registered this releases the note at one escape per field, exactly as the base did, and the
  // chunk spelling of the same bytes still blocks one line above. Closing it would mean teaching the escape series
  // reader the complete-hex-series rule, which is a coverage decision and not this slice's claim.
  const escapedHexSeries = (perField) => {
    const fields = [];
    for (let at = 0; at < compressed.length; at += perField) {
      fields.push([...compressed.subarray(at, at + perField)]
        .map((byte) => `\\x${byte.toString(16).padStart(2, '0')}`).join(' '));
    }
    return fields.map((value, index) => `face${index + 1}: ${value}`).join('\n');
  };
  assert.equal(check(escapedHexSeries(1)).decision, 'ALLOW', 'published gap: a hex-labelled escape series');
  assert.equal(check(escapedHexSeries(4)).decision, 'BLOCK', 'the direct reader fires at four escapes per field');
  blocksWithOriginal(chunks.map((chunk, index) => `part${index + 1}: ${chunk}`).join('\n'), true);
});

test('residual encoded views: byte arrays that spell a container stay opaque', () => {
  for (const payload of [`[80, 75, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]`,
    `{"type":"Buffer","data":[66, 90, 104, 57, 0, 1, 2, 3, 4, 5, 6, 7]}`,
    JSON.stringify({ content: `[${[0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0].join(',')}]` })]) {
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK', payload.slice(0, 40));
    assert.ok(result.reasons.includes('OPAQUE_EMBEDDED'), `${payload.slice(0, 40)}: ${result.reasons.join()}`);
  }
});

test('residual encoded views: ordinary engineering numbers, ids and labelled text are allowed', () => {
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  const digest = createHash('sha256').update('synthetic-buffer-digest').digest();
  const palette = Array.from({ length: 32 }, (_, index) => index * 8);
  const matrix = Array.from({ length: 64 }, (_, index) => (index * 37) % 256);
  for (const payload of [
    '[1, 2, 3]', '[255, 128, 0]', `rgb = [${palette.join(', ')}]`, `matrix = [${matrix.join(',')}]`,
    `versions = [1, 0, 0, 0, 0, 0, 0, 0]`, `ports = [80, 443, 8080, 5432]`,
    `{"timestamps":[1695826432,1695826433,1695826434,1695826435,1695826436,1695826437,1695826438,1695826439]}`,
    `{"offsets":[0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5, 9.5, 10.5, 11.5]}`,
    `{"type":"Buffer","data":[${[...digest].join(',')}]}`,
    `sensor: ${syntheticBytes(8).toString('hex')}\nreading: ${syntheticBytes(8).toString('hex')}\nregion: cafe1234`,
    'sensor: a1b2c3d4\nreading: b2c3d4e5\nregion: c3d4e5f6',
    'budget: 1200\nretries: 3\nwindow_ms: 45000\nshard_id: 0007',
    'alpha + beta > gamma / delta', 'if (count > 5 && retries > 3) reset()', '+86 138 0000 0000',
    '1 + 1 = 2', 'size + count < limit', 'path/to/resource', 'docs/security/advisories/GHSA-c2qf-rxjj-qqgw',
    'part1: alpha beta\npart2: gamma delta\npart3: epsilon zeta',
    '{"part1":"alpha","part2":"beta","part3":"gamma"}',
    'chunk1: readme\nchunk2: build\nchunk3: deploy',
  ]) assert.equal(unknown(payload).decision, 'ALLOW', `${payload.slice(0, 44)} ${unknown(payload).reasons.join()}`);
});

test('residual encoded views: reconstruction work is bounded and fails closed on demand', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const chunk = splitEvery(zlib.gzipSync(Buffer.from(SECRET_NOTE)).toString('base64'), 8)[0];
  const dense = () => Array.from({ length: 40_000 }, (_, index) => `part${index}: ${chunk}${index.toString(16)}`).join(' ')
    .slice(0, MAX_MESSAGE_BYTES);
  const decimals = () => Array.from({ length: 60_000 }, (_, index) => `[${Array.from({ length: 12 },
    (_, byte) => (index * 31 + byte * 7) % 256).join(',')}]`).join(' ').slice(0, MAX_MESSAGE_BYTES);
  const unterminated = () => `${'['}${'1,2,3,4,5,6,7,8,9,'.repeat(20_000)}`;
  for (const build of [dense, decimals, unterminated]) {
    const started = process.hrtime.bigint();
    const result = check(build());
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(['ALLOW', 'BLOCK'].includes(result.decision));
    assert.ok(elapsedMs < 5000, `${elapsedMs}ms`);
  }
  // A message demanding more distinct reconstructions than the declared budget allows is uninspectable, never
  // presumed clean: stopping early would let a sender hide one payload behind padding. Every value below is
  // distinct, so nothing is deduplicated away before the budget is reached.
  // A filler with a 16-character word ends a labelled group, the way unrelated prose in a document does.
  const sectionBreak = '\n-- incompatibility --\n';
  // Values that no other reader treats as an encoded run of its own, so only the declared reconstructions see them.
  const value = (index) => `Zz${index.toString(36).padStart(4, '0')}Kq9Tp`;
  const byteRun = (index) => [index & 255, (index >> 8) & 255, (index * 7) & 255, (index * 13) & 255,
    (index * 29) & 255, (index * 31) & 255, (index * 37) & 255, (index * 53) & 255];
  const overloads = [
    Array.from({ length: 17_000 }, (_, index) => `p1: ${value(index)}\np2: ${value(index)}b`).join(sectionBreak),
    Array.from({ length: 17_000 }, (_, index) => `${value(index)} + ${value(index)}b`).join(' '),
    Array.from({ length: 17_000 }, (_, index) => `[${byteRun(index).join(',')}]`).join(' '),
  ];
  for (const payload of overloads) {
    assert.ok(payload.length <= MAX_MESSAGE_BYTES, `${payload.length}`);
    const started = process.hrtime.bigint();
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK', payload.slice(0, 32));
    // Whichever bound trips first is the outcome: the reconstruction budget, or the view budget the decoded
    // results feed. Both are uninspectable outcomes, never a pass.
    assert.ok(['SENTINEL_BUDGET', 'UNINSPECTED_CONTENT'].includes(result.reasons[0]), result.reasons.join());
    assert.equal(result.findings.length, 0);
    assert.equal(result.release, undefined);
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 20_000);
  }
  // Moderate demand from ordinary content stays inside the same budget: it is reconstructed, not refused.
  const moderate = Array.from({ length: 2_000 }, (_, index) => `part${index}: ${syntheticBytes(4).toString('hex')}`)
    .join(sectionBreak);
  const started = process.hrtime.bigint();
  const result = check(moderate);
  assert.ok(['ALLOW', 'BLOCK'].includes(result.decision));
  assert.ok(!result.reasons.includes('SENTINEL_BUDGET'), result.reasons.join());
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000);
});

test('residual encoded views: declared series readings are charged like every other reconstruction', () => {
  // Every declared series reading, its duplicate-key readings and the metadata beside it go through the same
  // per-message charge as the all-values reading, so a message demanding more distinct reconstructions than the
  // budget allows is uninspectable rather than clean. Stopping early would let a sender hide one payload behind
  // padding, and an uncharged reading would be a reading nobody accounts for.
  const sectionBreak = '\n-- incompatibility --\n';
  // Values no other reader treats as an encoded run of its own, so only the declared readings see them.
  const value = (index) => `Zz${index.toString(36).padStart(4, '0')}Kq`;
  // A group of the widest shape this reader accepts (512 fields) written as 256 distinct declared names, each with
  // its two label numbers reversed, so every declared name is read both as written and in numeric order: this
  // message is refused because the series readings alone exceed the budget, not because of any other reader.
  const overload = Array.from({ length: 32 }, (_, group) => Array.from({ length: 256 }, (_, index) =>
    `p${index}q1: ${value(group * 512 + index * 2)}\np${index}q0: ${value(group * 512 + index * 2 + 1)}`).join('\n')).join(sectionBreak);
  for (const payload of [overload,
    Array.from({ length: 17_000 }, (_, index) => `p1: ${value(index)}\np2: ${value(index)}b`).join(sectionBreak)]) {
    assert.ok(payload.length <= MAX_MESSAGE_BYTES, `${payload.length}`);
    const started = process.hrtime.bigint();
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK', payload.slice(0, 32));
    assert.ok(['SENTINEL_BUDGET', 'UNINSPECTED_CONTENT'].includes(result.reasons[0]), result.reasons.join());
    assert.equal(result.findings.length, 0);
    assert.equal(result.release, undefined);
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 20_000);
  }
  // Demand that stays inside the budget is reconstructed rather than refused: a message that was read in full has
  // no reason to block, so refusing it would report a limit as a verdict.
  const withinBudget = Array.from({ length: 8 }, (_, group) => Array.from({ length: 64 }, (_, index) =>
    `p${index}q1: ${value(group * 128 + index * 2)}\np${index}q0: ${value(group * 128 + index * 2 + 1)}`).join('\n')).join(sectionBreak);
  const started = process.hrtime.bigint();
  const within = check(withinBudget);
  assert.ok(!within.reasons.includes('SENTINEL_BUDGET'), within.reasons.join());
  assert.ok(!within.reasons.includes('UNINSPECTED_CONTENT'), within.reasons.join());
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000);
  // Ordinary labelled content with many distinct names stays inside the same budget and stays allowed.
  const document = Array.from({ length: 400 }, (_, index) => [
    `## Section ${index}`, '', `The synthetic deployment writes part${index + 1}: region ${syntheticBytes(2).toString('hex')}.`,
    `Worker ${index} reports status ${syntheticBytes(2).toString('hex')}.`, '',
  ].join('\n')).join('\n');
  const ordinary = check(document);
  assert.ok(!ordinary.reasons.includes('SENTINEL_BUDGET'), ordinary.reasons.join());
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000);
});

test('residual encoded views: results stay privacy-safe and the checked bytes are unchanged', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const compressed = zlib.gzipSync(Buffer.from(SECRET_NOTE));
  const payload = `part1: ${splitEvery(compressed.toString('base64'), 8).join('\npart2: ')}`;
  const bytes = enc(payload);
  const result = check(bytes);
  assert.equal(result.decision, 'BLOCK');
  const serialized = JSON.stringify(result);
  for (const value of ['Orla', 'orla', 'plc-gateway', CANARY, 'Synthetica']) assert.ok(!serialized.includes(value), value);
  assert.deepEqual(Object.keys(result.regression).sort(), ['reasons', 'rules', 'version', 'views']);
  bytes.fill(0);
  assert.equal(result.release, undefined);
});

test('independent rereview: a signed container inside tentative raw deflate remains opaque', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const inner = zlib.gzipSync(Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.from('Orla')]));
  const outer = zlib.deflateRawSync(inner);
  assert.equal(inner.length, 28);
  assert.equal(outer.length, 25);
  assert.deepEqual(check(inner.toString('base64')).reasons, ['OPAQUE_EMBEDDED']);
  for (const payload of [outer.toString('base64'), JSON.stringify({ content: outer.toString('base64') })]) {
    assert.deepEqual(check(payload).reasons, ['OPAQUE_EMBEDDED']);
  }
  assert.equal(check('0.7231478778415019', { known: null }).decision, 'ALLOW');
});

test('residual encoded views: generated labelled, joined, decimal and escaped dresses all block', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const note = Buffer.from(SECRET_NOTE);
  const compressed = zlib.gzipSync(note);
  // A fixed-seed generator: which payload is dressed is not asserted, only that every dressing of the same
  // planted note reaches the planted original and the canary through the public interface.
  let seed = 0x9e3779b9;
  const next = () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) >>> 8) / 2 ** 24;
  const pick = (list) => list[Math.floor(next() * list.length) % list.length];
  const labels = ['part', 'p', 'chunk', 'segment', 'piece', 'blk_'];
  const gaps = ['\n', ', ', ' & ', ' ', '; ', ',\n  ', '\t', '\n\n', ',', ' &'];
  const quotes = ['', '', '"', "'"];
  const seps = [' + ', ' / ', ' > ', ' +', '+ ', ' %2B ', ' \\u002b ', '\n+\n', '\t/\t', ' >'];
  const encodings = ['base64', 'hex', 'decimal'];
  let dresses = 0;
  for (let round = 0; round < 96; round++) {
    const encoding = pick(encodings);
    const width = 3 + Math.floor(next() * 30);
    if (encoding === 'decimal') {
      const spaced = pick([',', ', ', ',\n  ']);
      blocksWithOriginal(`[${[...compressed].join(spaced)}]`);
      blocksWithOriginal(`{"type":"Buffer","data":[${[...compressed].join(',')}]}`);
      blocksWithOriginal(JSON.stringify({ content: `{"type":"Buffer","data":[${[...compressed].join(',')}]}` }));
      dresses += 3;
      continue;
    }
    const chunks = splitEvery(compressed.toString(encoding), encoding === 'hex' ? width + (width % 2) : width);
    if (chunks.length < 2) continue;
    const label = pick(labels);
    const gap = pick(gaps);
    const quote = pick(quotes);
    const dressed = chunks.map((chunk, index) => `${label}${index + 1}: ${quote}${chunk}${quote}`);
    blocksWithOriginal(dressed.join(gap));
    blocksWithOriginal(JSON.stringify(Object.fromEntries(dressed.map((line, index) =>
      [`${label}${index + 1}`, chunks[index]]))));
    blocksWithOriginal(JSON.stringify(chunks.map((chunk, index) => ({ part: index + 1, data: chunk }))));
    blocksLeak(chunks.join(pick(seps)));
    dresses += 4;
  }
  assert.ok(dresses >= 200, `only ${dresses} generated payloads`);
});

test('residual encoded views: adversarial spellings of each declared form block', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const compressed = zlib.gzipSync(Buffer.from(SECRET_NOTE));
  const chunks = splitEvery(compressed.toString('base64'), 8);
  const hexChunks = splitEvery(compressed.toString('hex'), 16);
  for (const payload of [
    // Separators written against their chunks, on a line of their own, percent- or JSON-escaped.
    ...[' + ', ' / ', ' > ', '>', ' +', '+ ', ' %2B ', ' %2f ', ' %3E ', ' \\u002b ', '\n+\n', '\t/\t']
      .map((separator) => chunks.join(separator)),
    ...[' + ', ' %2B '].map((separator) => hexChunks.join(separator)),
    // Labels in lists, in prose and with dashes, zero padding, single quotes and query strings.
    chunks.map((chunk, index) => `- part${index + 1}: ${chunk}`).join('\n'),
    chunks.map((chunk, index) => `1. part${index + 1}: ${chunk}`).join('\n'),
    chunks.map((chunk, index) => `## part${index + 1}: ${chunk}`).join('\n'),
    chunks.map((chunk, index) => `part-${index + 1}: ${chunk}`).join('\n'),
    chunks.map((chunk, index) => `part${String(index + 1).padStart(3, '0')}: '${chunk}'`).join('\n'),
    chunks.map((chunk, index) => `part${index + 1}=${chunk}`).join('&'),
    chunks.map((chunk, index) => `part${index + 1}: ${chunk}`).join('\nThe next part follows here.\n'),
    chunks.map((chunk, index) => `- part: ${index + 1}\n  data: ${chunk}`).join('\n'),
    `chunks: [${chunks.map((chunk) => `"${chunk}"`).join(', ')}]`,
    // JSON bodies: arrays of labelled objects, nested bodies and an escaped inner body.
    JSON.stringify({ parts: chunks.map((chunk, index) => ({ id: index + 1, value: chunk })) }, null, 2),
    JSON.stringify({ content: JSON.stringify({ parts: chunks.map((chunk, index) => ({ part: index + 1, data: chunk })) }) }),
    // Decimal bytes with a trailing comma, over several lines, and inside an escaped body.
    `[\n${[...compressed].map((byte) => `  ${byte},`).join('\n')}\n]`,
    JSON.stringify({ content: `["${[...compressed].join('\\u002c')}]`.replaceAll('\\u002c', ',') }),
  ]) blocksWithOriginal(payload);
  for (const separator of ['+', '/']) blocksLeak(chunks.join(separator));
  // Two independent declared reconstructions in one message, and a labelled payload beside a byte-pair stream:
  // reading one never stops the other, and neither displaces a neighbouring reconstruction.
  const pairs = splitEvery(zlib.gzipSync(Buffer.from(SECRET_NOTE)).toString('hex'), 2);
  const half = Math.floor(pairs.length / 2);
  const labelled = chunks.map((chunk, index) => `part${index + 1}: ${chunk}`).join('\n');
  for (const payload of [labelled, labelled.split('\n').map((line, index) => `copy${index + 1}: ${line.split(' ')[1]}`).join('\n'),
    `${labelled}\n${pairs.slice(0, half).join(' ')}\n${pairs.slice(half).join(' ')}`]) blocksWithOriginal(payload);
});

test('residual encoded views: ordinary configuration, prose and engineering numbers stay allowed', () => {
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  // Ordinary text with the punctuation these forms use, and labelled configuration that merely looks structured.
  for (const payload of ['alpha + beta > gamma / delta', '1 / 2 / 4 / 8 / 16 / 32 / 64',
    'read/write/exec flags', 'input / output / error', 'step one / step two / step three',
    'a1b2c3d4 / b2c3d4e5 / c3d4e5f6', 'x = 1 / y = 2', '10.0.0.1 / 10.0.0.2 / 10.0.0.3',
    'part1: alpha\npart2: beta\npart3: gamma', '{"part1":"alpha","part2":"beta","part3":"gamma"}',
    'chunk1: readme\nchunk2: build\nchunk3: deploy', '- item: one\n- item: two\n- item: three',
    'sensor: a1b2c3d4\nreading: b2c3d4e5\nregion: c3d4e5f6',
    'digest: 3f2a1b9c0d4e5f60718293a4b5c6d7e8a9b0c1d2\nchecksum: a1b2c3d4e5f60718',
    'ports = [80, 443, 8080, 5432, 3000, 9090, 5672, 15672]',
    `rgb = [${Array.from({ length: 32 }, (_, index) => index * 8).join(', ')}]`,
    `matrix = [${Array.from({ length: 64 }, (_, index) => (index * 37) % 256).join(',')}]`,
    `{"timestamps":[1695826432,1695826433,1695826434,1695826435,1695826436,1695826437,1695826438,1695826439]}`,
    `{"offsets":[0.5, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5, 9.5, 10.5, 11.5]}`,
    `{"type":"Buffer","data":[${[...createHash('sha256').update('synthetic-buffer-digest').digest()].join(',')}]}`,
    '[1, 2, 3]', '[255, 128, 0]', `versions = [1, 0, 0, 0, 0, 0, 0, 0]`,
    '[[1,2,3],[4,5,6,7,8,9,10,11,12]]', '[80, 443, 8080, 5432, 3000, 9090, 5672, 15672]',
    'budget: 1200\nretries: 3\nwindow_ms: 45000\nshard_id: 0007',
    'docs/security/advisories/GHSA-c2qf-rxjj-qqgw', 'https://github.com/example-org/example-repo/actions/runs/36169013008']) {
    assert.equal(unknown(payload).decision, 'ALLOW', `${payload.slice(0, 40)} ${unknown(payload).reasons.join()}`);
  }
  // Generated ordinary content: labelled fields, short hex ids and prose, the way a real report or log reads.
  const document = Array.from({ length: 400 }, (_, index) => [
    `## Section ${index}`, '', `The synthetic deployment writes part${index + 1}: region ${syntheticBytes(2).toString('hex')}.`,
    '', `Service gateway-worker-${index} serves ${index} requests per minute with retries set to ${index % 5}.`, '',
  ].join('\n')).join('\n');
  const started = process.hrtime.bigint();
  const result = unknown(document);
  assert.equal(result.decision, 'ALLOW', result.reasons.join());
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000);
  // A compressed blob dressed in each declared form is still opaque, even with no known originals registered.
  const opaque = zlib.gzipSync(syntheticBytes(200));
  for (const payload of [splitEvery(opaque.toString('base64'), 8).map((chunk, index) => `part${index + 1}: ${chunk}`).join('\n'),
    splitEvery(opaque.toString('base64'), 8).join(' + '), `[${[...opaque].join(',')}]`]) {
    assert.equal(unknown(payload).decision, 'BLOCK', payload.slice(0, 40));
  }
});

test('residual encoded views: declared recognition limits are explicit, not completeness claims', () => {
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  // Unknown uncompressed binary inside a declared form passes: these forms add no opaque bytes of their own,
  // so ordinary numeric arrays and labelled configuration cannot be blocked by their shape alone.
  const opaque = syntheticBytes(200);
  assert.equal(unknown(splitEvery(opaque.toString('base64'), 8).map((chunk, index) => `part${index + 1}: ${chunk}`).join('\n')).decision, 'ALLOW');
  assert.equal(unknown(splitEvery(opaque.toString('hex'), 16).join(' + ')).decision, 'ALLOW');
  assert.equal(unknown(`[${[...opaque].join(',')}]`).decision, 'ALLOW');
  // The same bytes compressed, or a container signature, are still refused, and a known original still matches.
  assert.ok(unknown(splitEvery(zlib.gzipSync(opaque).toString('base64'), 8).join(' + ')).reasons.includes('OPAQUE_EMBEDDED'));
  const zip = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), opaque]);
  assert.ok(unknown(splitEvery(zip.toString('hex'), 16).map((chunk, index) => `part${index + 1}: ${chunk}`).join('\n'))
    .reasons.includes('OPAQUE_EMBEDDED'));
  const note = Buffer.from(SECRET_NOTE);
  for (const payload of [splitEvery(note.toString('base64'), 8).map((chunk, index) => `part${index + 1}: ${chunk}`).join('\n'),
    `[${[...note].join(',')}]`]) blocksWithOriginal(payload);
});

/* ---------- Issue #88 residual R2: a credential-shaped block scalar, and a stream behind other bytes ---------- */

/**
 * Every case in these groups is a public-interface decision and reason code over generated, obviously synthetic
 * values. The credential cases register **no** known original, so a block blocks on its own shape: a sentinel that
 * needed the registry would fail all of them.
 */
const credentialOnly = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
const blocksAsCredential = (payload, at) => {
  const result = credentialOnly(payload);
  assert.equal(result.decision, 'BLOCK', at ?? payload.slice(0, 60));
  assert.ok(result.reasons.includes('HIGH_RISK_PATTERN'), `${payload.slice(0, 60)}: ${result.reasons.join()}`);
  assert.ok(result.findings.some((finding) => finding.rule === 'pattern.credential-assignment'),
    `${payload.slice(0, 60)}: ${result.findings.map((finding) => finding.rule).join()}`);
  assert.equal(result.release, undefined);
  return result;
};

test('issue 88 R2: a credential-shaped block scalar blocks with no known original registered', () => {
  const bodies = ['synthetic-block-scalar-value', 'correct synthetic horse battery staple'];
  for (const body of bodies) {
    for (const indicator of ['|', '|-', '|+', '>2', '|4', '|-2', '>4-']) {
      // Literal, folded, chomping and explicit-indentation spellings, in and out of a document, CRLF, and with a
      // comment after the header. The credential-shaped assignment is read from the block, not from the indicator.
      blocksAsCredential(`password: ${indicator}\n  ${body}\n`);
      blocksAsCredential(`password: ${indicator}\r\n  ${body}\r\n`);
      blocksAsCredential(`password: ${indicator} # synthetic note\n  ${body}\n`);
      blocksAsCredential(`  api_key: ${indicator}\n    ${body}\n`);
      blocksAsCredential(`'secret': ${indicator}\n  ${body}\n`);
      blocksAsCredential(`"auth_token": ${indicator}\n  ${body}\n`);
      blocksAsCredential(JSON.stringify({ config: `password: ${indicator}\n  ${body}\n` }));
      blocksAsCredential(`database:\n  password: ${indicator}\n    ${body}\n  port: 5432\n`);
      blocksAsCredential(`items:\n  - name: synthetic-one\n    secret: ${indicator}\n      ${body}\n`);
    }
  }
  // A multi-line literal and a folded paragraph are one value; the same literal on a single line already blocks.
  blocksAsCredential('password: |\n  first synthetic line\n  second synthetic line\n  third synthetic line\n');
  blocksAsCredential('password: >\n  first synthetic line\n  second synthetic line\n');
  // The value may sit under the key with a blank line and deeper indentation, and the block may end at a sibling key.
  blocksAsCredential('password: |\n\n      synthetic-block-scalar-value\nreplicas: 3\n');
  // Nesting an encoded assignment inside the literal is a literal, and is still a credential-shaped assignment.
  blocksAsCredential('password: |\n  Authorization: Bearer synthetic-bearer-value\n');
});

test('issue 88 R2: block-scalar credential controls, placeholders and ordinary YAML stay allowed', () => {
  for (const payload of [
    // Whole-value placeholders and masks are references, exactly as in the single-line forms.
    'password: |\n  <your-password-here>\n', 'api_key: >\n  ${API_KEY}\n', 'secret: |-\n  {{ secret }}\n',
    'password: |\n  ***\n', 'password: |\n  ${password}\n',
    'password: "<your-password-here>"\n',
    // A type name, a key-echo shorthand and a `PWD` path are the same non-values they are on one line.
    'password: |\n  password\n', 'pwd: |\n  /srv/synthetic/app\n', 'pwd: >\n  ~/synthetic\n',
    // An empty or comment-only block carries no value; a scalar under a key that is not credential-like is ordinary.
    'password: |\n', 'password: | # note\n  # only a comment\nreplicas: 3\n', 'password: |\n  \nnext: value\n',
    'description: |\n  A long synthetic description of the service\n', 'notes: >\n  a folded note\n',
    // Pipes and angle brackets that are prose, tables, regexes or shell, not block-scalar headers after a key.
    '| password | value |\n| --- | --- |\n', 'the flag is | and the arrow is >\n', 'cat <<EOF\nhello\nEOF\n',
    'password: |0\n  out-of-range indentation indicator\n', 'secret: |\tvalue on the same line\n',
    // Indentation indicator 0 is not a header at all, and `password` inside a longer key is a different key.
    'user_password_hint: |\n  not this key\n', 'myapikey: |\n  not this key either\n',
    // A Kubernetes reference and a JSON body are ordinary configuration.
    'env:\n  - name: PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: synthetic-secret\n',
    JSON.stringify({ password: '${PASSWORD}', api_key: '<api-key>', secret: null, replicas: 3 }),
  ]) assert.equal(credentialOnly(payload).decision, 'ALLOW', `${payload.slice(0, 40)}: ${credentialOnly(payload).reasons.join()}`);
  // The single-line forms this rule mirrors are unchanged: still blocking, still allowed, same reasons.
  assert.equal(credentialOnly('password: |\n  x\n').decision, 'ALLOW');
  blocksAsCredential('password: synthetic-plain-value\n');
  // A bare `$NAME` body is flagged, which is exactly what the quoted form it mirrors already does. A multi-line
  // body is one value, so two placeholders on two lines are not one whole reference either.
  assert.equal(credentialOnly('password: "$ACCESS_TOKEN"\n').decision, 'BLOCK');
  blocksAsCredential('access_token: |\n  $ACCESS_TOKEN\n');
  blocksAsCredential('password: |\n  ${API_KEY}\n  ${DB_PASSWORD}\n');
  // A block body is a literal, exactly like the quoted form, so a body that reads as a type name is still a value
  // while the *unquoted* plain scalar `password: string` stays a type name. That difference is deliberate.
  blocksAsCredential('password: |\n  string\n');
  assert.equal(credentialOnly('password: string\n').decision, 'ALLOW');
  assert.equal(credentialOnly('password: "string"\n').decision, 'BLOCK', 'the quoted form this body mirrors');
  assert.equal(credentialOnly('secret: required\n').decision, 'BLOCK', 'a bare identifier value on one line is unchanged');
});

test('issue 88 R2: block-scalar reading is bounded, linear and fails closed like every other bound', () => {
  // One credential block far larger than the per-block bound is still read, and stays within a work bound.
  const huge = `password: |\n${'  synthetic line of configuration text\n'.repeat(4000)}`;
  const started = process.hrtime.bigint();
  blocksAsCredential(huge);
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000);
  // Many credential blocks in one message: read every one of them, linearly, without exceeding the work bound.
  const many = Array.from({ length: 2000 }, (_, index) =>
    `service-${index}:\n  password: |\n    synthetic-block-scalar-value-${index}\n`).join('\n');
  const flood = process.hrtime.bigint();
  const flooded = credentialOnly(many);
  assert.equal(flooded.decision, 'BLOCK');
  assert.ok(flooded.reasons.includes('HIGH_RISK_PATTERN'), flooded.reasons.join());
  assert.ok(Number(process.hrtime.bigint() - flood) / 1e6 < 5000);
  // Blocks nested inside other blocks are content, not mapping keys: a single pass reads the outer one and stops.
  assert.equal(credentialOnly('password: |\n  password: |\n    inner-synthetic-value\n').decision, 'BLOCK');
  // The declared-reconstruction budget still fails closed above its own bound, unchanged by this rule: a cheap
  // 17,000-part distinct join is refused, and a 1,024-part one is reconstructed and inspected instead.
  const join = (count) => Array.from({ length: count }, (_, index) => `part${index}: ${(index + 1).toString(36)}abcdefgh`).join(' + ');
  const overBudget = credentialOnly(join(17000));
  assert.equal(overBudget.decision, 'BLOCK');
  assert.deepEqual(overBudget.reasons, ['SENTINEL_BUDGET']);
  assert.equal(overBudget.release, undefined);
  assert.deepEqual(overBudget.findings, []);
  assert.deepEqual(credentialOnly(join(1024)).reasons, []);
});

test('issue 88 R2: a compressed stream behind other bytes is found inside a run the opaque count does not count', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const blocksWith = (payload, at) => {
    const result = check(payload);
    assert.equal(result.decision, 'BLOCK', `${at ?? payload.slice(0, 40)}: ${result.reasons.join()}`);
    assert.ok(result.reasons.includes('KNOWN_ORIGINAL_DETECTED'), `${at ?? payload.slice(0, 40)}: ${result.reasons.join()}`);
    assert.equal(result.release, undefined);
  };
  const short = Buffer.from(PLANTED);
  const full = Buffer.from(SECRET_NOTE);
  for (const compress of [zlib.deflateRawSync, zlib.brotliCompressSync]) {
    // A run shorter than the opaque threshold, carrying only the planted original: Base64 and hex, whole and
    // chunked, and inside a JSON string. A prefix byte puts the stream where the run's own start is not.
    const shortStream = compress(short);
    for (const prefix of ['x', 'ok', 'note:', 'junkjunk']) {
      const body = Buffer.concat([Buffer.from(prefix), shortStream]);
      for (const payload of [body.toString('base64'), body.toString('hex'), splitEvery(body.toString('base64'), 8).join(' '),
        splitEvery(body.toString('hex'), 16).join('\n'), JSON.stringify({ attachment: body.toString('base64') }),
        JSON.stringify({ attachment: body.toString('hex') })]) blocksWith(payload, `${prefix}/${payload.slice(0, 20)}`);
    }
    // The same stream inside a DER-shaped public PEM body, which the opaque count exempts by its shape alone.
    const der = Buffer.concat([Buffer.from([0x30, shortStream.length + 2]), shortStream]);
    blocksWith(`-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/(.{40})/gu, '$1\n')}\n-----END CERTIFICATE-----\n`);
    // A run whose exact byte length is a digest length, so the opaque count exempts it, hiding the full note.
    const fullStream = compress(full);
    for (const size of [16, 20, 32, 48, 64]) {
      const pad = size - fullStream.length;
      if (pad < 1) continue;
      blocksWithOriginal(Buffer.concat([syntheticBytes(pad), fullStream]).toString('hex'));
    }
  }
});

test('issue 88 R2: digests, ids, public keys and ordinary text keep their exemptions with the interior read', () => {
  // Every shape the interior read must not disturb, at volume, with a work bound.
  const digests = Array.from({ length: 2000 }, (_, index) =>
    `sha256-${createHash('sha256').update(`synthetic-digest-${index}`).digest('base64')}`).join('\n');
  const hexDigests = Array.from({ length: 1000 }, (_, index) =>
    createHash('sha256').update(`synthetic-hex-digest-${index}`).digest('hex')).join('\n');
  const ids = Array.from({ length: 2000 }, () => syntheticUUID()).join('\n');
  const keys = Array.from({ length: 200 }, () => `ssh-ed25519 ${sshEd25519Public()}`).join('\n');
  const der = Buffer.concat([Buffer.from([0x30, 0x82, 0x02, 0x54]), syntheticBytes(596)]);
  const certificates = ['-----BEGIN CERTIFICATE-----', ...der.toString('base64').match(/.{1,64}/gu), '-----END CERTIFICATE-----'].join('\n');
  const goSum = Array.from({ length: 200 }, (_, index) =>
    `example.invalid/module${index} v1.0.${index} h1:${syntheticBytes(32).toString('base64')}`).join('\n');
  const source = Array.from({ length: 300 }, (_, index) =>
    `const synthRecordHandler${index}Value = convertUtf8ToBase64String(input${index});`).join('\n');
  for (const payload of [digests, hexDigests, ids, keys, certificates, goSum, source]) {
    const started = process.hrtime.bigint();
    const result = credentialOnly(payload);
    assert.equal(result.decision, 'ALLOW', `${payload.slice(0, 40)}: ${result.reasons.join()}`);
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000, payload.slice(0, 40));
  }
  // Ordinary compressed text still inflates to its own text and stays allowed, and a container still blocks.
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  for (const payload of ['build log ok, all good', 'attachment ok', 'contact the synthetic team about the build']) {
    const compressed = zlib.gzipSync(Buffer.from(payload));
    for (const prefix of ['', 'x', 'note:', 'junkjunk', 'attachment:']) {
      // Correctly aligned bytes: a character glued to the front of Base64 text shifts the encoding by six bits,
      // which is a different (and opaque) case, so the prefix belongs inside the encoded bytes here.
      const dressed = Buffer.concat([Buffer.from(prefix), compressed]).toString('base64');
      assert.equal(credentialOnly(dressed).decision, 'ALLOW', `${dressed.slice(0, 40)}: ${credentialOnly(dressed).reasons.join()}`);
    }
  }
  const zip = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), syntheticBytes(64)]);
  assert.equal(credentialOnly(splitEvery(zip.toString('hex'), 16).map((chunk, index) => `part${index + 1}: ${chunk}`).join('\n')).decision, 'BLOCK');
  // A pre-existing catch is not weakened: a value glued to a single-line assignment is still refused.
  blocksAsCredential('const re = /password: |hunter2/;\n');
});

test('issue 88 R2: the remaining declared limits are measured and pinned, not claimed closed', () => {
  const unknown = (payload) => checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination, known: null });
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  // 1. Uncompressed random data in ordinary-looking shapes is not counted opaque. A fingerprint list, a hex list
  //    and a `:;|.&`-joined byte list are indistinguishable from data this module must let through, so they pass.
  const random = syntheticBytes(400);
  for (const payload of [splitEvery(random.toString('hex'), 2).join('\n'),
    splitEvery(random.toString('hex'), 2).join(':;|.&'), splitEvery(random.toString('base64'), 4).join(' '),
    splitEvery(random.toString('base64'), 6).join(', ')]) {
    assert.equal(unknown(payload).decision, 'ALLOW', payload.slice(0, 40));
  }
  // 2. The same bytes under a signed gzip block, however the hex is chunked and separated.
  for (const payload of [splitEvery(zlib.gzipSync(random).toString('base64'), 4).join(' '),
    splitEvery(zlib.gzipSync(random).toString('hex'), 2).join(':;|.&')]) {
    assert.ok(unknown(payload).reasons.includes('OPAQUE_EMBEDDED'), payload.slice(0, 40));
  }
  //    A tentative (unsigned) stream in the same shape is matched but cannot raise the opaque count, so the run
  //    itself still passes: this is the declared tentative-output limit, not a new finding.
  // 3. Binary that is exactly a digest length in hex is exempt from the opaque count by its shape alone.
  for (const size of [8, 12, 16, 20, 28, 32, 48, 64]) assert.equal(unknown(syntheticBytes(size).toString('hex')).decision, 'ALLOW', `${size}`);
  // 4. A credential assignment whose value is a bare identifier is flagged on purpose, and a `PWD` path is not.
  assert.equal(unknown('secret: required\n').decision, 'BLOCK');
  assert.equal(unknown('Password: pass\n').decision, 'BLOCK');
  assert.equal(unknown('pwd: /srv/synthetic/app\n').decision, 'ALLOW');
  // 5. A list of short digit-heavy camelCase names counts as opaque binary: the price of the identifier exemption.
  //    Measured here: three names are allowed and four block, while eleven lowercase camelCase names are allowed.
  const camel = ['UTF8ToUTF16LE', 'UTF16LEToUTF8', 'UTF8ToUTF32LE', 'UTF32LEToUTF8', 'UTF8ToUTF16BE', 'UTF16BEToUTF8',
    'UTF8ToUTF32BE', 'UTF32BEToUTF8', 'UTF8ToUTF32', 'UTF32ToUTF8', 'UTF8ToUTF16', 'UTF16ToUTF8', 'UTF16LEToUTF32LE',
    'UTF32LEToUTF16LE', 'UTF16BEToUTF32BE', 'UTF32BEToUTF16BE', 'UTF8ToUTF16LE', 'UTF16LEToUTF8', 'UTF8ToUTF32LE',
    'UTF32LEToUTF8'];
  assert.equal(unknown(camel.slice(0, 3).join(', ')).decision, 'ALLOW');
  assert.ok(unknown(camel.join(', ')).reasons.includes('OPAQUE_EMBEDDED'));
  assert.equal(unknown(Array.from({ length: 11 }, (_, index) => `convertUtf8ToBase64String${index}`).join(', ')).decision, 'ALLOW');
  // 6. A single short default-`xxd` row is not rebuilt, and a truncated prefix of a longer stream is released.
  const gz = zlib.gzipSync(Buffer.from(SECRET_NOTE));
  const row = (bytes) => {
    const hex = Buffer.from(bytes).toString('hex');
    return `00000000: ${splitEvery(hex, 4).join(' ')}  |${[...bytes].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('')}|`;
  };
  assert.equal(unknown(row(gz.subarray(0, 16))).decision, 'ALLOW');
  assert.equal(unknown(row(gz.subarray(0, 16)) + '\n' + row(gz.subarray(16, 32))).decision, 'ALLOW');
  const dump = Array.from({ length: Math.ceil(gz.length / 16) }, (_, index) => row(gz.subarray(index * 16, index * 16 + 16))).join('\n');
  blocksWithOriginal(dump);
  // 7. A legitimate list of concatenated hex digests exhausts #6's decode budget, which the sentinel refuses.
  //    This is #6's bound, measured here: 1,000 lines are allowed and 1,100 are uninspectable.
  const digestList = (count) => Array.from({ length: count }, (_, index) =>
    createHash('sha256').update(`synthetic-list-${index}`).digest('hex')).join('\n');
  assert.equal(unknown(digestList(1000)).decision, 'ALLOW');
  assert.deepEqual(unknown(digestList(1100)).reasons, ['UNINSPECTED_CONTENT']);
});

/**
 * Core-audit blocker B1, red at the reviewed head: one extra space or tab inside a dump row's hex field made
 * `dumpLineHex` split at it, so the reconstructed bytes were truncated to the first group. The truncated reading
 * still spanned the whole block, so it displaced the complete one, the gzip stream never inflated, and a message
 * carrying a planted original and a canary was ALLOWed with `release` bytes. Every probe here is in-process and
 * every value is synthetic.
 */
const dumpRows = (bytes, { group = 1, marker = false, midGap = false, at = -1, sep = ' ', column = null } = {}) => {
  const printable = (line) => column ? column(line)
    : [...line].map((byte) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.')).join('');
  const rows = [];
  for (let index = 0; index < bytes.length; index += 16) {
    const line = bytes.subarray(index, index + 16);
    let cells = [...line].map((byte) => byte.toString(16).padStart(2, '0'));
    if (group === 2) cells = cells.join('').match(/.{1,4}/gu);
    // `hexdump -C` splits each row into two halves with two spaces between them.
    if (midGap) cells = [cells.slice(0, cells.length / 2).join(' '), cells.slice(cells.length / 2).join(' ')];
    if (index === at) cells = [cells[0] + sep, ...cells.slice(1)];
    rows.push(`${(index >>> 0).toString(16).padStart(8, '0')}:  ${cells.join(' ')}  ` +
      `${marker ? '|' : ''}${printable(line)}${marker ? '|' : ''}`);
  }
  return `synthetic hex dump\n${rows.join('\n')}\nend\n`;
};

test('core audit B1: one extra separator or a missing ASCII marker inside a dump row never releases a block', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const payload = zlib.gzipSync(Buffer.from(SECRET_NOTE + 'synthetic padding text '.repeat(6)));
  // `xxd -g1` byte pairs, default `xxd` two-byte groups and `hexdump -C`'s two halves, each with an unmarked
  // ASCII column, plus the marked spelling. Whitespace inside the hex field is sender-controlled: one extra
  // space or tab at any row must not change the outcome.
  for (const shape of [{ group: 1 }, { group: 1, marker: true }, { group: 2 }, { group: 2, marker: true },
    { group: 1, midGap: true }, { group: 1, midGap: true, marker: true }]) {
    const label = JSON.stringify(shape);
    blocksWithOriginal(dumpRows(payload, shape), true);
    for (const at of [0, 16, 32, 48]) blocksWithOriginal(dumpRows(payload, { ...shape, at }), true);
    blocksWithOriginal(dumpRows(payload, { ...shape, at: 0, sep: '\t' }), true);
    // The same dump inside a JSON body, where the line breaks are escapes and the first row carries a prefix.
    const body = JSON.stringify({ model: 'synthetic', messages: [{ role: 'user', content: dumpRows(payload, shape) }] });
    blocksWithOriginal(body, true);
    blocksWithOriginal(JSON.stringify({ model: 'synthetic', messages: [{ role: 'user', content: dumpRows(payload, { ...shape, at: 16 }) }] }), true);
  }
  // A `|`-marked row keeps its ASCII column out of the bytes; an unmarked one reads the row, never the column.
  assert.equal(credentialOnly(dumpRows(Buffer.from('ordinary prose about the synthetic build'), { column: () => 'deadbeef cafe f00d 0000' })).decision, 'ALLOW');
  assert.equal(credentialOnly(dumpRows(zlib.gzipSync(Buffer.from('ordinary build log, nothing secret')), { column: () => 'deadbeef cafe f00d 0000' })).decision, 'ALLOW');
  assert.equal(credentialOnly(dumpRows(zlib.gzipSync(Buffer.from('ordinary build log, nothing secret')), { midGap: true, column: () => 'deadbeef cafe f00d 0000' })).decision, 'ALLOW');
  // A planted value written literally in the ASCII column is plain text and is still caught, not read as bytes.
  const withLiteral = dumpRows(zlib.gzipSync(Buffer.from('ordinary build log')), { column: () => PLANTED });
  assert.ok(check(withLiteral).reasons.includes('KNOWN_ORIGINAL_DETECTED'), withLiteral);
  // Ordinary text with offsets and words is not a dump at all.
  for (const ordinary of ['2024-01-02: build step 3 of 9 finished in 4211ms\n2024-01-02: build step 4 of 9 finished',
    'deadbeef cafe f00d 0000 1111 2222 3333 4444\n5555 6666 7777 8888 9999 aaaa bbbb cccc',
    'a line, another line, ordinary log output with 1024 rows and 4096 columns']) {
    assert.equal(credentialOnly(ordinary).decision, 'ALLOW', ordinary.slice(0, 40));
  }
});

test('core audit: the interior read covers every exempt run it can afford, and its work stays bounded', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  // A run whose exact byte length is a digest length is exempt from the opaque count by its shape alone, so a
  // compressed note inside one is found only by the interior read. One window now reads sixteen starting offsets
  // instead of one, and the budget is spent across every such run in the message instead of being skipped whole.
  for (const compress of [zlib.deflateRawSync, zlib.brotliCompressSync]) {
    // A note short enough that its compressed form still fits a 64-byte run, which is the longest run whose hex
    // length is also a digest length, so the opaque count exempts it by shape alone.
    const stream = compress(Buffer.from(`${PLANTED} ${CANARY}`));
    assert.ok(stream.length < 64, `${stream.length}`);
    const hidden = Buffer.concat([syntheticBytes(64 - stream.length), stream]).toString('hex');
    assert.equal(hidden.length, 128);
    // Decoys of the same exempt shape, then the hidden run last: one beyond the old run gate, and eight beyond it.
    for (const decoys of [0, 1, 3]) {
      const payload = [...Array.from({ length: decoys }, () => syntheticBytes(64).toString('hex')), hidden].join('\n');
      const started = process.hrtime.bigint();
      blocksWithOriginal(payload, true);
      assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000, `${decoys} decoys`);
    }
    // The same run written in Base64, whole and inside a JSON body, and the raw bytes as one hex run. A signed stream
    // is found by the signature scan that reads every run; an unsigned one inside a Base64 run is not exempt from
    // the opaque count by shape, so it is the hex digest-length spelling above that needs the interior read.
    const gz = zlib.gzipSync(Buffer.from(`${PLANTED} ${CANARY}`));
    const signed = Buffer.concat([syntheticBytes(64 - gz.length), gz]);
    assert.ok(gz.length < 64, `${gz.length}`);
    blocksWithOriginal(JSON.stringify({ attachment: signed.toString('base64') }), true);
    blocksWithOriginal(signed.toString('hex'), true);
    blocksWithOriginal(`sha256=${signed.toString('hex')}`, true);
  }
  // The ceiling is explicit rather than silent: the read spends its windows in span order across every exempt
  // run, so a message whose exempt runs need more starting offsets than the budget holds has a declared gap and
  // no claim of completeness (the frozen #19 known-limits list, measured at 1,024 starting offsets per message).
  // Nothing here claims such a message is clean, and the controls below stay allowed.
  const many = Array.from({ length: 400 }, () => syntheticBytes(64).toString('hex')).join('\n');
  const started = process.hrtime.bigint();
  assert.equal(credentialOnly(many).decision, 'ALLOW');
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000);
  const goSum = Array.from({ length: 300 }, (_, index) =>
    `example.invalid/module${index} v1.0.${index} h1:${syntheticBytes(32).toString('base64')}`).join('\n');
  const certificates = ['-----BEGIN CERTIFICATE-----', ...Buffer.concat([Buffer.from([0x30, 0x82, 0x02, 0x54]),
    syntheticBytes(596)]).toString('base64').match(/.{1,64}/gu), '-----END CERTIFICATE-----'].join('\n');
  for (const payload of [goSum, certificates]) {
    const at = process.hrtime.bigint();
    assert.equal(credentialOnly(payload).decision, 'ALLOW', payload.slice(0, 40));
    assert.ok(Number(process.hrtime.bigint() - at) / 1e6 < 5000, payload.slice(0, 40));
  }
});

/**
 * Independent review blocking finding B2 at `e2ad93b`: the interior read spent its ceiling in text order and then
 * skipped every later exempt run, so a handful of ordinary digest lines *before* a hidden payload turned BLOCK into
 * a clean ALLOW with `release` bytes. The trigger was a few lines, the effect was non-monotonic, and nothing
 * distinguished "read and clean" from "never read".
 *
 * Every value below is invented and the decoys are fixed digests, so the results are deterministic rather than
 * seeded: the test must fail or pass identically on every run.
 */
const deterministicHex = (seed, algorithm = 'sha256') => createHash(algorithm).update(seed).digest('hex');

test('core audit B2: exhausting the interior read refuses the message instead of releasing what it never read', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  // Short enough that its compressed form still fits a 64-byte run, the longest run whose hex length is also a
  // digest length, so the opaque count excuses it on a length coincidence and nothing declares what it is.
  const note = Buffer.from(`${PLANTED} ${CANARY}`);
  const hiddenRun = (stream) => Buffer.concat([syntheticBytes(64 - stream.length), stream]).toString('hex');
  // Decoys of the shape the opaque count excuses on a length coincidence, then the hidden run last: one beyond the
  // old run gate, far beyond its window ceiling, and past the byte ceiling that now refuses instead of releasing.
  for (const compress of [zlib.deflateRawSync, zlib.brotliCompressSync]) {
    const carried = compress(note);
    const hidden = hiddenRun(carried);
    assert.equal(hidden.length, 128);
    for (const decoys of [0, 1, 4, 8, 32]) {
      for (const [label, algorithm] of [['sha256', 'sha256'], ['sha512', 'sha512']]) {
        const payload = [...Array.from({ length: decoys }, (_, index) => deterministicHex(`decoy-${label}-${index}`, algorithm)), hidden].join('\n');
        blocksWithOriginal(payload, true);
      }
    }
    // Decoy-heavy beyond any read this module can afford is refused, never released: a reason, no `release` bytes.
    for (const decoys of [200, 600]) {
      const payload = [...Array.from({ length: decoys }, (_, index) => deterministicHex(`heavy-${index}`)), hidden].join('\n');
      const refused = check(payload);
      assert.equal(refused.decision, 'BLOCK', `${decoys} decoys`);
      assert.ok(refused.reasons.length > 0, `${decoys} decoys`);
      assert.equal(refused.release, undefined, `${decoys} decoys`);
    }
    // A declared context is not a licence to starve the read: `go.sum`-shaped decoys leave the hidden run first.
    for (const decoys of [0, 8, 200]) {
      const lines = Array.from({ length: decoys }, (_, index) =>
        `example.invalid/module${index} v1.0.${index} h1:${Buffer.from(syntheticBytes(32)).toString('base64')}`);
      blocksWithOriginal([...lines, hidden].join('\n'), true);
    }
    // Past the byte ceiling with no payload in it, the message is uninspectable, not clean, and releases nothing.
    const over = Array.from({ length: 1400 }, (_, index) => deterministicHex(`over-${index}`)).join('\n');
    const exhausted = credentialOnly(over);
    assert.equal(exhausted.decision, 'BLOCK');
    assert.ok(['SENTINEL_BUDGET', 'UNINSPECTED_CONTENT'].includes(exhausted.reasons.join()), exhausted.reasons.join());
    assert.equal(exhausted.release, undefined);
    assert.deepEqual(exhausted.findings, []);
  }
  // The exemptions the module publishes for ordinary traffic are unchanged by the refusal, with their work bounds.
  const certificate = ['-----BEGIN CERTIFICATE-----', ...Buffer.concat([Buffer.from([0x30, 0x82, 0x02, 0x54]),
    syntheticBytes(596)]).toString('base64').match(/.{1,64}/gu), '-----END CERTIFICATE-----'].join('\n');
  for (const [label, payload] of [
    ['1000 bare hex digests', Array.from({ length: 1000 }, (_, index) => deterministicHex(`synthetic-hex-digest-${index}`)).join('\n')],
    ['2000 sha256- digests', Array.from({ length: 2000 }, (_, index) => `sha256-${Buffer.from(syntheticBytes(32)).toString('base64')}`).join('\n')],
    ['300 go.sum lines', Array.from({ length: 300 }, (_, index) =>
      `example.invalid/module${index} v1.0.${index} h1:${Buffer.from(syntheticBytes(32)).toString('base64')}`).join('\n')],
    ['200 trace ids', Array.from({ length: 200 }, () => `trace=${deterministicHex(`trace-${syntheticCounter++}`).slice(0, 32)}`).join('\n')],
    ['certificate', certificate],
  ]) {
    const started = process.hrtime.bigint();
    const result = credentialOnly(payload);
    assert.equal(result.decision, 'ALLOW', `${label}: ${result.reasons.join()}`);
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000, `${label} exceeded its work bound`);
  }
});

test("core audit: every decode attempt sizes its own codec window, bounding a synchronous scan's high-water mark", () => {
  // Node's synchronous zlib helper allocates an output buffer per call at its default 16 KiB chunk size, and a call
  // that decodes nothing holds that buffer until the runtime can run again. Measured on this host: a synchronous
  // batch of 24,000 failed calls grows `arrayBuffers` by about 16 KiB per call at that default and about 1 KiB at a
  // 1 KiB chunk, and after two event-loop turns and a forced GC `arrayBuffers` and `external` return to within
  // 0.1 MiB of their baseline while RSS does not. So this is the high-water mark of one synchronous batch: a work
  // bound, not a retention claim and not a lifetime claim, and deliberately not a test of process-lifetime memory.
  // Every decode attempt in the module names its own chunk, so a decoy-signature or wrong-offset scan's high-water
  // mark is its chunk times its attempts rather than Node's default: about 20 MiB without that, about 1 MiB with it.
  const pieces = [];
  let index = 0;
  while (pieces.join('').length < 60000) pieces.push(deterministicHex(`piece-${index++}`).slice(0, 6), '1f8b08', deterministicHex(`x${index}`).slice(0, 10));
  const payload = pieces.join('');
  const before = process.memoryUsage();
  const started = process.hrtime.bigint();
  const result = credentialOnly(payload);
  const highWater = process.memoryUsage().arrayBuffers - before.arrayBuffers;
  assert.equal(result.decision, 'BLOCK');
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000);
  assert.ok(highWater < 8 * 1024 * 1024, `synchronous high-water mark ${Math.round(highWater / 1048576)} MiB`);
});

test('core audit: a speculative interior window reads every offset of its run without following a chain', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  // Two unsigned streams in one digest-shaped run, so the second is only reachable by a window that reads on past
  // the first: a read that stopped at its own stream's end, or continued a chain instead of sweeping, would miss it.
  const stream = zlib.brotliCompressSync(Buffer.from(PLANTED));
  const second = zlib.deflateRawSync(Buffer.from(CANARY));
  const body = Buffer.concat([syntheticBytes(2), stream, syntheticBytes(2), second]);
  assert.ok(body.length < 64, `${body.length}`);
  const padded = Buffer.concat([syntheticBytes(64 - body.length), body]);
  assert.equal(padded.length, 64);
  const both = blocksWithOriginal(padded.toString('hex'), false);
  assert.ok(both.reasons.includes('CANARY_DETECTED'), both.reasons.join());
  // One stream alone in the same shape, so the second is not found by any other route.
  const single = Buffer.concat([syntheticBytes(64 - stream.length), stream]);
  blocksWithOriginal(single.toString('hex'), false);
});

test('core audit: an unmarked ASCII column is never read as cells, at any column width', () => {
  const zlib = globalThis.process.getBuiltinModule('node:zlib');
  const printable = (line) => [...line].map((byte) => (byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '.')).join('');
  const dump = (bytes, column, marker) => `synthetic dump\n${Array.from({ length: Math.ceil(bytes.length / 16) }, (_, row) => {
    const line = bytes.subarray(row * 16, row * 16 + 16);
    const cells = [...line].map((byte) => byte.toString(16).padStart(2, '0')).join(' ');
    return `${(row * 16 >>> 0).toString(16).padStart(8, '0')}:  ${cells}  ${marker ? '|' : ''}${typeof column === 'function' ? column(line) : column}${marker ? '|' : ''}`;
  }).join('\n')}\nend\n`;
  // A dump row carries its own offset, so the row width is knowable without trusting where the column separator is:
  // consecutive offsets say how many bytes the row holds. That is what separates the hex field from an unmarked
  // ASCII column, which is the point here -- a doubled space or tab *inside* the field adds no cell and leaves the
  // row's offsets untouched, so the complete reading still spans the field, while the column's cells never are read.
  // Without it, an unmarked column whose cells are hex of the row's own width was absorbed, the interleaving
  // destroyed the stream it carried, and a planted original and canary were released with `release` bytes.
  const columns = {
    'four-character hex cells': 'deadbeef cafe f00d 0000 1111 2222 3333 4444 5555 6666 7777 8888 9999 aaaa bbbb cccc',
    'two-character hex cells': 'dead beef cafe f00d 0000 1111 2222 3333 4444 5555 6666 7777 8888 9999 aaaa bbbb cccc dddd eeee ffff 0001',
    'four-character words': 'dead beef cafe food 1111 2222 3333 4444 5555 6666 7777 8888 9999 aaaa bbbb cccc dddd',
    'two-character words': 'de ad be ef ca fe f0 0d 00 00 11 11 22 22 33 33 44 44 55 55 66 66 77 77 88 88 99 99 aa aa bb bb cc cc',
    'dots': '................................',
  };
  const long = zlib.gzipSync(Buffer.from(`contact ${PLANTED} re ${CANARY} and some more synthetic padding text to move the row count`));
  assert.equal(long.length, 108, `${long.length}`);
  const ordinary = zlib.gzipSync(Buffer.from(`ordinary build log about the synthetic service.${'x'.repeat(8)}`));
  assert.equal(ordinary.length, 69, `${ordinary.length}`);
  const short = zlib.gzipSync(Buffer.from(`note for ${PLANTED} ${CANARY}`));
  // Every column width, marked and unmarked, on ordinary and planted payloads: the column is dropped either way.
  for (const [name, column] of Object.entries(columns)) {
    for (const marker of [false, true]) {
      blocksWithOriginal(dump(long, column, marker), true);
      blocksWithOriginal(dump(short, column, marker), true);
      assert.equal(credentialOnly(dump(ordinary, column, marker)).decision, 'ALLOW', `${name}/${marker}`);
    }
  }
  for (const marker of [false, true]) {
    blocksWithOriginal(dump(long, printable, marker), true);
    assert.equal(credentialOnly(dump(ordinary, printable, marker)).decision, 'ALLOW', `printable/${marker}`);
  }
  // A planted value written literally in the column is plain text and is still caught, marked or unmarked.
  const literal = zlib.gzipSync(Buffer.from('ordinary build log'));
  const withLiteral = dump(literal, PLANTED, false);
  assert.ok(check(withLiteral).reasons.includes('KNOWN_ORIGINAL_DETECTED'), withLiteral);
  // A row the dump reader declines to parse is not a release path: the row's own byte pairs are still reconstructed
  // by the byte-pair reader. Rows of 64, 80 and 128 cells all exceed the dump reader's parsing bound or the
  // 400-character line ceiling, and all three still block precisely.
  for (const perRow of [64, 80, 128]) {
    const wide = Array.from({ length: Math.ceil(long.length / perRow) }, (_, row) => {
      const line = long.subarray(row * perRow, (row + 1) * perRow);
      const column = [...line].map((byte) => (byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '.')).join('').replace(/(.{4})/gu, '$1 ');
      return `${(row * perRow >>> 0).toString(16).padStart(8, '0')}:  ${[...line].map((byte) => byte.toString(16).padStart(2, '0')).join(' ')}  ${column}`;
    }).join('\n');
    blocksWithOriginal(`synthetic dump\n${wide}\nend\n`, true);
  }
  // Ordinary text with offsets and words is not a dump, whatever its column looks like.
  assert.equal(credentialOnly('2024-01-02: build step 3 of 9 finished in 4211ms\n2024-01-02: build step 4 of 9 finished').decision, 'ALLOW');
});
