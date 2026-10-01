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
