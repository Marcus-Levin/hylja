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
    const result = checkEgress({ bytes: enc(payload), scope: scopeA, destination, authorized: destination });
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
  const small = createStreamGate({ scope: scopeA, destination, authorized: destination }, 4);
  small.push(enc('12345'));
  assert.deepEqual(small.end().result.reasons, ['STREAM_OVERFLOW']);
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

test('the sentinel check stays within a bounded-work budget at the size limit', () => {
  const many = createKnownOriginals(scopeA, key, Array.from({ length: 2000 }, (_, i) => ({ kind: 'ORIGINAL', value: `synthetic-original-${i}-value`, ref: `o.${i}` })));
  for (const text of ['synthetic-original-'.repeat(50_000), 'a'.repeat(MAX_MESSAGE_BYTES - 16), 'orla '.repeat(200_000), '\\u0041'.repeat(170_000)]) {
    const started = process.hrtime.bigint();
    const result = checkEgress({ bytes: enc(text.slice(0, MAX_MESSAGE_BYTES)), scope: scopeA, destination, authorized: destination, known: many });
    assert.ok(['ALLOW', 'BLOCK'].includes(result.decision));
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 5000);
  }
});
