// Public synthetic development evidence ONLY; no accepted classification/policy/effects/scoring.
import test from 'node:test';
import assert from 'node:assert/strict';
import { transformDraft } from './transform.mjs';

const asset = 'SYNTHETIC-ASSET-A1';
const context = { version: 1, scope: 'SYNTHETIC-SCOPE-A', session: 'SYNTHETIC-SESSION-A', context: 'SYNTHETIC-CONTEXT-A' };
const message = { version: 1, task: 'SUMMARIZE_FAILURES', asset };
const event = { asset, tick: 1, level: 'ERROR', code: 'FAILURE' };
const log = { version: 1, events: [event, { ...event, tick: 2 }] };
const encode = (value) => JSON.stringify(value);
const run = (c = context, m = message, l = log) => transformDraft(encode(c), encode(m), encode(l));
const transformed = (result) => {
  assert.equal(result.status === 'TRANSFORMED', true, 'valid synthetic input must transform');
  return JSON.parse(result.cloakedJson);
};
const refused = (result) => {
  // Only booleans enter diagnostic operands; raw input/result never prints on failure.
  assert.equal(encode(result) === '{"status":"REFUSED","reason":"TRANSFORM_REFUSED"}', true, 'atomic fixed refusal');
};

test('valid message and log transform atomically with no original ID in any result field', () => {
  const result = run();
  const cloak = transformed(result);
  assert.equal(encode(result).includes(asset), false, 'no original in result');
  assert.equal(cloak.mode === 'PUBLIC_DRAFT_ONLY', true);
  assert.equal(cloak.message.asset === cloak.log.events[0].asset, true);
  assert.equal(cloak.log.events[0].asset === cloak.log.events[1].asset, true);
  assert.equal(/^DRAFT-REF-[a-f0-9]{64}$/u.test(cloak.message.asset), true);
  assert.equal(result.references.length, 1);
  assert.equal(result.references[0] === cloak.message.asset, true);
  assert.equal(cloak.message.task === message.task, true);
  assert.equal(cloak.log.events[1].tick, 2);
});

test('repeated calls and reordered records preserve scoped asset reference', () => {
  const first = run();
  const second = run({ context: context.context, session: context.session, scope: context.scope, version: 1 },
    { asset, task: message.task, version: 1 }, { events: [{ code: 'FAILURE', level: 'ERROR', tick: 1, asset }], version: 1 });
  transformed(first);
  transformed(second);
  assert.equal(first.references[0] === second.references[0], true);
  assert.equal(run().cloakedJson === first.cloakedJson, true);
});

test('every scope, session and context component separates references', () => {
  const first = run();
  transformed(first);
  for (const [key, value] of [['scope', 'SYNTHETIC-SCOPE-B'], ['session', 'SYNTHETIC-SESSION-B'], ['context', 'SYNTHETIC-CONTEXT-B']]) {
    const changed = run({ ...context, [key]: value });
    transformed(changed);
    assert.equal(first.references[0] === changed.references[0], false, 'scope component must bind reference');
  }
});

test('distinct whole-value assets do not alias or depend on occurrence order', () => {
  const other = 'SYNTHETIC-ASSET-B2';
  const first = run(context, message, { version: 1, events: [event, { ...event, asset: other }] });
  const second = run(context, message, { version: 1, events: [{ ...event, asset: other }, event] });
  const a = transformed(first);
  const b = transformed(second);
  assert.equal(first.references.length, 2);
  assert.equal(a.log.events[0].asset === a.log.events[1].asset, false);
  assert.equal(a.log.events[0].asset === b.log.events[1].asset, true);
  assert.equal(a.log.events[1].asset === b.log.events[0].asset, true);
  assert.equal(encode(first).includes(other), false);
});

test('malformed, non-primitive, non-ASCII and non-compact JSON refuses without conversion', () => {
  let converted = false;
  const object = { toString() { converted = true; throw new Error('synthetic refusal sentinel'); } };
  for (const bad of [undefined, null, 1, object, '{', '', '[]', 'null', ' ' + encode(context), encode(context) + '\n', '\u00e9', '\ud800']) {
    refused(transformDraft(bad, encode(message), encode(log)));
  }
  assert.equal(converted, false);
  for (const index of [1, 2]) {
    const inputs = [encode(context), encode(message), encode(log)];
    inputs[index] = '{';
    refused(transformDraft(...inputs));
  }
});

test('unknown, missing, nested and wrong-type fields refuse in each closed schema', () => {
  for (const bad of [{ ...context, extra: asset }, { ...context, version: 2 }, { ...context, scope: { asset } },
    { ...context, scope: 'ordinary.invalid' }, { ...context, session: 'SYNTHETIC-SESSION-' },
    { ...context, context: 'SYNTHETIC-CONTEXT-' + 'A'.repeat(33) }, { ...context, scope: undefined }]) refused(run(bad));
  for (const bad of [{ ...message, extra: asset }, { ...message, task: 'DISPLAY' }, { version: 1, asset },
    { ...message, asset: { asset } }, { ...message, version: '1' }]) refused(run(context, bad));
  for (const bad of [{ ...log, extra: asset }, { ...log, events: {} }, { ...log, events: [] }, { events: log.events },
    { ...log, version: 2 }]) refused(run(context, message, bad));
  for (const bad of [{ ...event, extra: asset }, { ...event, level: 'DEBUG' }, { ...event, code: 'OTHER' },
    { ...event, tick: -1 }, { ...event, tick: 0.1 }, { ...event, tick: 1000001 }, { ...event, asset: null }, null, []]) {
    refused(run(context, message, { version: 1, events: [event, bad] }));
  }
});

test('asset grammar is whole-value and permits only explicitly synthetic uppercase ASCII', () => {
  for (const bad of ['', 'SYNTHETIC-ASSET-', 'SYNTHETIC-ASSET-a', 'SYNTHETIC-ASSET-A_',
    'SYNTHETIC-ASSET-' + 'A'.repeat(65), 'prefix ' + asset, asset + ' suffix', asset + '\n',
    'ordinary.example.invalid', 'DRAFT-REF-' + 'a'.repeat(64), 'SYNTHETIC-ASSET-\u0391']) {
    refused(run(context, { ...message, asset: bad }));
    refused(run(context, message, { version: 1, events: [{ ...event, asset: bad }] }));
  }
  transformed(run(context, { ...message, asset: 'SYNTHETIC-ASSET-' + 'Z'.repeat(64) }));
});

test('duplicate keys, escaped alternatives and discarded unknown fields cannot hide unchecked text', () => {
  const c = encode(context);
  const m = encode(message);
  const l = encode(log);
  refused(transformDraft(c.replace('"version":1', '"version":2,"version":1'), m, l));
  refused(transformDraft(c, m.replace('"asset":', '"asset":"ordinary.invalid","asset":'), l));
  refused(transformDraft(c, m, l.replace('"tick":1', '"tick":-1,"tick":1')));
  refused(transformDraft(c, m.replace('SYNTHETIC', '\\u0053YNTHETIC'), l));
  refused(transformDraft(c, m, l.replace('"tick":1', '"tick":1e0')));
  refused(transformDraft(c, m, l.replace('"tick":1', '"tick":-0')));
  refused(transformDraft(c, m, l.replace('"events":', '"__proto__":{"asset":"ordinary.invalid"},"events":')));
});

test('late invalid event refuses the entire unit with no prefix or references', () => {
  refused(run(context, message, { version: 1, events: [...Array.from({ length: 127 }, () => event), { ...event, code: asset }] }));
  refused(transformDraft(encode(context), encode(message), encode(log) + 'unchecked'));
});

test('primitive byte caps refuse before parsing and event count has an exact boundary', () => {
  const inputs = [encode(context), encode(message), encode(log)];
  for (const [index, limit] of [[0, 512], [1, 512], [2, 16384]]) {
    const changed = [...inputs];
    changed[index] = 'x'.repeat(limit + 1);
    refused(transformDraft(...changed));
  }
  const admitted = run(context, message, { version: 1, events: Array.from({ length: 128 }, () => event) });
  transformed(admitted);
  assert.equal(admitted.cloakedJson.length <= 32768, true);
  refused(run(context, message, { version: 1, events: Array.from({ length: 129 }, () => event) }));
});

test('log byte limit accepts exact compact ASCII boundary and refuses one byte more', () => {
  const events = Array.from({ length: 128 }, (_, tick) => ({ ...event, tick, asset: 'SYNTHETIC-ASSET-' + 'A'.repeat(64) }));
  // Start maximal, shorten only known synthetic suffixes until exactly at the fixed byte cap.
  let excess = encode({ version: 1, events }).length - 16384;
  assert.equal(excess > 0, true);
  for (const entry of events) {
    const removed = Math.min(63, excess);
    entry.asset = entry.asset.slice(0, entry.asset.length - removed);
    excess -= removed;
    if (excess === 0) break;
  }
  const exact = encode({ version: 1, events });
  assert.equal(exact.length, 16384);
  transformed(transformDraft(encode(context), encode(message), exact));
  events[0].asset += 'B';
  const over = encode({ version: 1, events });
  assert.equal(over.length, 16385);
  refused(transformDraft(encode(context), encode(message), over));
});

test('results contain only immutable cloak and opaque references, never a lookup/mapping surface', () => {
  const result = run();
  transformed(result);
  assert.equal(Object.keys(result).sort().join(',') === 'cloakedJson,references,status', true);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.references), true);
});

test('bounded deterministic property cases preserve schema/equality and separate 1000 contexts', () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i += 1) {
    const id = 'SYNTHETIC-ASSET-' + i.toString(36).toUpperCase();
    const c = { ...context, context: 'SYNTHETIC-CONTEXT-' + i.toString(36).toUpperCase() };
    const m = { ...message, asset: id };
    const l = { version: 1, events: [{ ...event, asset: id, tick: i }, { ...event, asset: id, tick: i + 1 }] };
    const result = run(c, m, l);
    const cloak = transformed(result);
    assert.equal(encode(result).includes(id), false);
    assert.equal(cloak.message.asset === cloak.log.events[0].asset, true);
    assert.equal(cloak.log.events[0].asset === cloak.log.events[1].asset, true);
    assert.equal(cloak.log.events[0].tick, i);
    assert.equal(cloak.log.events[1].tick, i + 1);
    assert.equal(cloak.log.events[0].code === 'FAILURE', true);
    assert.equal(cloak.log.events[0].level === 'ERROR', true);
    assert.equal(result.cloakedJson === run(c, m, l).cloakedJson, true);
    assert.equal(seen.has(result.references[0]), false);
    seen.add(result.references[0]);
    const changed = run({ ...c, session: 'SYNTHETIC-SESSION-B' }, m, l);
    transformed(changed);
    assert.equal(changed.references[0] === result.references[0], false);
  }
  assert.equal(seen.size, 1000);
});

test('all admitted enums, tick extremes, scope suffix extremes and absence of file effects', () => {
  const c = { version: 1, scope: 'SYNTHETIC-SCOPE-' + 'Z'.repeat(32), session: 'SYNTHETIC-SESSION-0', context: 'SYNTHETIC-CONTEXT-0' };
  for (const level of ['INFO', 'ERROR']) for (const code of ['START', 'STOP', 'FAILURE']) for (const tick of [0, 1000000]) {
    const cloak = transformed(run(c, message, { version: 1, events: [{ ...event, level, code, tick }] }));
    assert.equal(cloak.log.events[0].level === level, true);
    assert.equal(cloak.log.events[0].code === code, true);
    assert.equal(cloak.log.events[0].tick === tick, true);
  }
  // No attachment path, file bytes, responder, policy or authorization argument is supported.
  refused(run(context, { ...message, attachmentPath: 'synthetic.example.invalid' }));
});
