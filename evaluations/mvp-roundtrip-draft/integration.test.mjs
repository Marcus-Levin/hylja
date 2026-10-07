// PROPOSED / PUBLIC_DRAFT_ONLY: physical fixed-file and injected synthetic cases.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runFixedDraft, runInjectedDraft } from './integration.mjs';

const asset = 'SYNTHETIC-ASSET-A1';
const encode = JSON.stringify;
const event = { asset, tick: 1, level: 'ERROR', code: 'FAILURE' };
const log = (events) => encode({ version: 1, events });
const text = (bytes) => String.fromCharCode(...bytes);
function success(result, count) {
  assert.equal(result.status === 'DISPLAYED', true, 'complete proposed synthetic round trip required');
  assert.equal(result.mode === 'PUBLIC_DRAFT_ONLY', true);
  assert.equal(result.errorCount, count);
  assert.equal(result.answer === `Synthetic log summary for ${asset}: ${count} ERROR events.`, true, 'exact displayed answer');
  assert.equal(Object.isFrozen(result) && Object.isFrozen(result.trace), true);
  assert.equal(Object.isFrozen(result.trace.consumedBytes) && Object.isFrozen(result.trace.returnedBytes), true);
  const outbound = text(result.trace.consumedBytes);
  const reply = text(result.trace.returnedBytes);
  assert.equal(outbound.includes(asset), false, 'whole actual responder input excludes original');
  assert.equal(reply.includes(asset), false, 'actual responder output excludes original');
  assert.equal(result.trace.consumedBytes.every((b) => b >= 32 && b <= 126), true);
  assert.equal(result.trace.returnedBytes.every((b) => b >= 32 && b <= 126), true);
  const image = JSON.parse(outbound);
  const response = JSON.parse(reply);
  assert.equal(encode(image) === outbound && encode(response) === reply, true);
  assert.equal(image.message.task === 'SUMMARIZE_FAILURES', true);
  assert.equal(image.log.events.every((entry) => entry.asset === image.message.asset), true);
  assert.equal(response.reference === image.message.asset, true);
  assert.equal(response.errorCount, count);
  assert.equal(response.summary === (count === 0 ? 'NO_FAILURES' : 'FAILURES_FOUND'), true);
  assert.equal(encode(Object.keys(response)) === '["version","summary","reference","errorCount"]', true);
  assert.equal(JSON.parse(result.trace.displayRequestJson).purpose === 'SYNTHETIC-LOG-SUMMARY', true);
  assert.equal(result.trace.displayNow, 20);
  assert.equal(reply.length <= 1024 && outbound.length <= 32768 && result.answer.length <= 256, true);
  return image;
}
function refusal(result) {
  assert.equal(encode(result) === '{"status":"REFUSED","reason":"INTEGRATION_REFUSED"}', true, 'atomic fixed refusal with no trace/answer');
  assert.equal(Object.isFrozen(result), true);
}

test('physical fixed regular attachment reaches exact responder bytes and one restored answer', () => {
  const result = runFixedDraft();
  const image = success(result, 2);
  const attachment = JSON.parse(text(result.trace.attachmentBytes));
  assert.equal(result.trace.attachmentKind === 'FIXED_FILE', true);
  assert.equal(attachment.events.length, 4);
  assert.equal(image.log.events.length, 4);
  for (let i = 0; i < 4; i += 1) {
    for (const key of ['tick', 'level', 'code']) assert.equal(image.log.events[i][key] === attachment.events[i][key], true, 'order and fidelity');
  }
  const repeat = runFixedDraft();
  success(repeat, 2);
  assert.equal(encode(repeat.trace) === encode(result.trace), true, 'deterministic owned captures');
});

test('injected no-failure log proves zero-count utility without claiming physical IO', () => {
  const result = runInjectedDraft(log([{ ...event, level: 'INFO', code: 'START' }, { ...event, level: 'INFO', code: 'FAILURE' }]));
  success(result, 0);
  assert.equal(result.trace.attachmentKind === 'INJECTED_TEXT', true);
});

test('count follows ERROR level rather than code and preserves unsorted duplicate ticks', () => {
  const events = [{ ...event, tick: 1000000, code: 'START' }, { ...event, tick: 0, level: 'INFO' }, { ...event, tick: 0, code: 'STOP' }];
  const image = success(runInjectedDraft(log(events)), 2);
  for (let i = 0; i < events.length; i += 1) {
    for (const key of ['tick', 'level', 'code']) assert.equal(image.log.events[i][key] === events[i][key], true);
  }
});

test('finite independent request and lifecycle scenarios withhold entire answer', () => {
  for (const scenario of ['WRONG_PURPOSE', 'WRONG_DESTINATION', 'USE', 'EXPORT', 'FOREIGN_SCOPE', 'FOREIGN_SESSION', 'FOREIGN_CONTEXT', 'STALE_REVISION', 'EXPIRED', 'REVOKED', 'ROLLBACK']) {
    refusal(runInjectedDraft(log([event]), scenario));
  }
});

test('untrusted response cannot supply authority, foreign reference or inconsistent count', () => {
  for (const scenario of ['FOREIGN_REFERENCE', 'UNKNOWN_REFERENCE', 'MALFORMED_RESPONSE', 'COUNT_DISAGREEMENT', 'SUMMARY_DISAGREEMENT', 'AUTHORITY_SMUGGLING', 'OVERSIZE_RESPONSE', 'DUPLICATE_RESPONSE', 'ESCAPED_RESPONSE', 'NON_ASCII_RESPONSE', 'WRONG_RESPONSE_TYPE', 'NEGATIVE_COUNT', 'OVER_COUNT', 'TRAILING_RESPONSE', 'MALFORMED_REFERENCE']) {
    refusal(runInjectedDraft(log([event]), scenario));
  }
});

test('injected invalid attachment text refuses atomically, not an OS failure claim', () => {
  for (const bad of ['', '{', '[]', 'null', 'x'.repeat(16385), log([]), log(Array.from({ length: 129 }, () => event)),
    log([event]) + '\n', log([event]) + '{}', log([event]).replace('SYNTHETIC', '\\u0053YNTHETIC'),
    log([event]).replace('"tick":1', '"tick":0,"tick":1'), log([event]).replace('"tick":1', '"tick":1e0'),
    log([event]).replace('"tick":1', '"tick":-0'), log([{ ...event, extra: asset }]),
    log([{ ...event, asset: 'ordinary.example.invalid' }]), log([{ ...event, asset: 'SYNTHETIC-ASSET-B2' }]),
    log([event, { ...event, code: 'UNKNOWN' }]), log([event]).replace('A1', '\u00e9'), '\ud800']) {
    refusal(runInjectedDraft(bad));
  }
});

test('primitive-only input and finite scenario admission do not inspect caller objects', () => {
  let touched = false;
  const hostile = new Proxy({}, { get() { touched = true; throw new Error('synthetic sentinel'); }, ownKeys() { touched = true; throw new Error('synthetic sentinel'); } });
  for (const value of [hostile, null, undefined, 1]) refusal(runInjectedDraft(value));
  for (const value of [hostile, null, 1, 'OTHER', 'VALID '.repeat(1000)]) {
    refusal(runInjectedDraft(log([event]), value));
    refusal(runFixedDraft(value));
  }
  assert.equal(touched, false);
});

test('exact 128-event limit and 129-event refusal do not truncate', () => {
  const events = Array.from({ length: 128 }, (_, tick) => ({ ...event, tick }));
  const image = success(runInjectedDraft(log(events)), 128);
  assert.equal(image.log.events.length, 128);
  refusal(runInjectedDraft(log([...events, event])));
});

test('bounded deterministic 129 count/order cases exercise exact byte path', () => {
  for (let count = 0; count <= 128; count += 1) {
    const events = Array.from({ length: Math.max(1, count) }, (_, tick) => ({ ...event, tick, level: count === 0 ? 'INFO' : 'ERROR', code: tick % 2 === 0 ? 'START' : 'STOP' }));
    const image = success(runInjectedDraft(log(events)), count);
    assert.equal(image.log.events.length, events.length);
    assert.equal(text(runInjectedDraft(log(events)).trace.consumedBytes) === encode(image), true);
  }
});
