// PROPOSED / PUBLIC_DRAFT_ONLY: pure public synthetic component evidence only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as api from './transform.mjs';

const { transformPilot, derivePilotReference } = api;
const encode = (value) => JSON.stringify(value);
const context = { version: 1, scope: 'SYNTHETIC-SCOPE-A', session: 'SYNTHETIC-SESSION-A', context: 'SYNTHETIC-CONTEXT-A' };
const asset = 'SYNTHETIC-ASSET-A1';
const other = 'SYNTHETIC-ASSET-B2';
const message = { version: 1, task: 'ERROR_COUNTS', assets: [asset, other] };
const event = { asset, tick: 1, level: 'ERROR', code: 'FAILURE' };
const log = { version: 1, events: [event, { ...event, asset: other, tick: 0, level: 'INFO' }, { ...event, tick: 1, code: 'STOP' }] };
const run = (c = context, m = message, l = log) => transformPilot(encode(c), encode(m), encode(l));
function refused(result) {
  assert.equal(encode(result) === '{"status":"REFUSED","reason":"PILOT_TRANSFORM_REFUSED"}', true, 'fixed atomic refusal');
  assert.equal(Object.isFrozen(result), true, 'frozen refusal');
}
function derived(c = context, a = asset) {
  const result = derivePilotReference(encode(c), a);
  assert.equal(result.status === 'DERIVED', true, 'valid public derivation');
  assert.equal(Object.keys(result).join(',') === 'status,mode,reference', true);
  assert.equal(result.mode === 'PUBLIC_DRAFT_ONLY' && /^DRAFT-PILOT-REF-[a-f0-9]{64}$/u.test(result.reference), true);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(encode(result).includes(a), false, 'no original in derivation');
  return result.reference;
}
function transformed(result) {
  assert.equal(result.status === 'TRANSFORMED', true, 'valid new multi-asset behavior');
  assert.equal(Object.keys(result).join(',') === 'status,mode,cloakedJson,references', true);
  assert.equal(result.mode === 'PUBLIC_DRAFT_ONLY', true);
  assert.equal(Object.isFrozen(result) && Object.isFrozen(result.references), true);
  assert.equal(result.cloakedJson.length <= 32768 && /^[\x20-\x7e]+$/u.test(result.cloakedJson), true);
  const image = JSON.parse(result.cloakedJson);
  assert.equal(encode(image) === result.cloakedJson, true);
  assert.equal(Object.keys(image).join(',') === 'version,mode,message,log', true);
  assert.equal(image.version === 1 && image.mode === 'PUBLIC_DRAFT_ONLY', true);
  assert.equal(Object.keys(image.message).join(',') === 'version,task,assets', true);
  assert.equal(Object.keys(image.log).join(',') === 'version,events', true);
  return image;
}
function fidelity(c, m, l) {
  const result = run(c, m, l);
  const image = transformed(result);
  assert.equal(image.message.version === 1 && image.log.version === 1 && image.message.task === m.task, true);
  assert.equal(result.references.length === m.assets.length, true);
  assert.equal(encode(image.message.assets) === encode(result.references), true);
  assert.equal(new Set(result.references).size === m.assets.length, true);
  for (const [index, value] of m.assets.entries()) {
    assert.equal(result.references[index] === derived(c, value), true, 'cross-API stable equality');
    assert.equal(encode(result).includes(value), false, 'no original anywhere in result');
  }
  for (const label of [c.scope, c.session, c.context]) assert.equal(encode(result).includes(label), false);
  assert.equal(image.log.events.length === l.events.length, true);
  for (const [index, original] of l.events.entries()) {
    const cloaked = image.log.events[index];
    assert.equal(Object.keys(cloaked).join(',') === 'asset,tick,level,code', true);
    assert.equal(cloaked.asset === result.references[m.assets.indexOf(original.asset)], true);
    assert.equal(cloaked.tick === original.tick && cloaked.level === original.level && cloaked.code === original.code, true);
  }
  return result;
}

test('valid repeated/distinct assets cloak every slot with declared ordering and exact fidelity', () => {
  fidelity(context, message, log);
  fidelity(context, { ...message, task: 'FIRST_ERRORS', assets: [other, asset] }, log);
  assert.equal(run().cloakedJson === run().cloakedJson, true, 'deterministic repeat');
});

test('exact public framed domain identity and independent context/asset separation', () => {
  const components = ['hylja.public-synthetic-pilot-draft.reference.v1', context.scope, context.session, context.context, asset];
  const framed = components.map((value) => String(value.length) + ':' + value).join('');
  const expected = 'DRAFT-PILOT-REF-' + createHash('sha256').update(framed).digest('hex');
  assert.equal(derived() === expected, true, 'independent frame oracle');
  for (const key of ['scope', 'session', 'context']) {
    const changed = { ...context, [key]: context[key] + 'B' };
    assert.equal(derived(changed) === derived(), false, 'each component binds');
  }
  assert.equal(derived(context, other) === derived(), false);
  const a = { ...context, scope: 'SYNTHETIC-SCOPE-AB', session: 'SYNTHETIC-SESSION-C' };
  const b = { ...context, scope: 'SYNTHETIC-SCOPE-A', session: 'SYNTHETIC-SESSION-BC' };
  assert.equal(derived(a) === derived(b), false, 'structurally different tuples');
  const reordered = Object.fromEntries(Object.entries(context).reverse());
  assert.equal(derived(reordered) === derived(), true);
  const reorderedLog = { events: log.events.map((e) => ({ code: e.code, level: e.level, tick: e.tick, asset: e.asset })), version: 1 };
  assert.equal(run(reordered, { assets: message.assets, task: message.task, version: 1 }, reorderedLog).cloakedJson === run().cloakedJson, true);
});

test('1/8/9 distinct declared assets and 1/128/129 event boundaries', () => {
  for (const count of [1, 8]) {
    const assets = Array.from({ length: count }, (_, i) => 'SYNTHETIC-ASSET-' + i);
    const m = { ...message, assets };
    for (const n of [count, 128]) fidelity(context, m, { version: 1, events: Array.from({ length: n }, (_, i) => ({ ...event, asset: assets[i % count] })) });
  }
  const assets = Array.from({ length: 9 }, (_, i) => 'SYNTHETIC-ASSET-' + i);
  refused(run(context, { ...message, assets }, { version: 1, events: assets.map((a) => ({ ...event, asset: a })) }));
  refused(run(context, { ...message, assets: [asset] }, { version: 1, events: Array.from({ length: 129 }, () => event) }));
  refused(run(context, { ...message, assets: [] }));
  refused(run(context, { ...message, assets: [asset] }, { version: 1, events: [] }));
});

test('duplicate declarations and mismatched declared/log sets refuse whole unit', () => {
  refused(run(context, { ...message, assets: [asset, asset] }, { version: 1, events: [event] }));
  refused(run(context, message, { version: 1, events: [event] }));
  refused(run(context, { ...message, assets: [asset] }, log));
  refused(run(context, message, { version: 1, events: [...log.events, { ...event, asset: 'SYNTHETIC-ASSET-C' }] }));
});

test('all caller positions refuse nonprimitive/hostile values without inspecting or coercing them', () => {
  let touched = false;
  const hostile = new Proxy({}, { get() { touched = true; throw new Error('synthetic sentinel'); }, ownKeys() { touched = true; throw new Error('synthetic sentinel'); } });
  for (const bad of [undefined, null, true, 1, 1n, Symbol('synthetic'), [], {}, hostile, () => {}, new String(asset)]) {
    for (const index of [0, 1, 2]) {
      const args = [encode(context), encode(message), encode(log)];
      args[index] = bad;
      refused(transformPilot(...args));
    }
    refused(derivePilotReference(bad, asset));
    refused(derivePilotReference(encode(context), bad));
  }
  assert.equal(touched, false);
});

test('every closed member rejects omission, unknown, nested, wrong primitive, and version changes', () => {
  const samples = [context, message, log, event];
  const apply = (index, value) => index === 0 ? run(value) : index === 1 ? run(context, value) : index === 2 ? run(context, message, value) : run(context, message, { version: 1, events: [...log.events, value] });
  for (const [index, sample] of samples.entries()) {
    refused(apply(index, { ...sample, extra: asset }));
    for (const key of Object.keys(sample)) {
      const missing = { ...sample };
      delete missing[key];
      refused(apply(index, missing));
      for (const bad of [null, {}, [], true, 'unknown.synthetic.invalid']) refused(apply(index, { ...sample, [key]: bad }));
    }
    for (const bad of [null, [], 1, 'synthetic']) refused(apply(index, bad));
  }
  for (const version of [0, 2, '1']) {
    refused(run({ ...context, version }));
    refused(run(context, { ...message, version }));
    refused(run(context, message, { ...log, version }));
  }
  for (const bad of ['SUMMARIZE_FAILURES', 'DISPLAY', 'USE', 'EXPORT']) refused(run(context, { ...message, task: bad }));
});

test('whole public asset/context grammar max and over, substring, Unicode, and reference-shaped inputs', () => {
  const maxAsset = 'SYNTHETIC-ASSET-' + 'Z'.repeat(64);
  const c = { version: 1, scope: 'SYNTHETIC-SCOPE-' + 'Z'.repeat(32), session: 'SYNTHETIC-SESSION-' + 'Z'.repeat(32), context: 'SYNTHETIC-CONTEXT-' + 'Z'.repeat(32) };
  fidelity(c, { ...message, assets: [maxAsset] }, { version: 1, events: [{ ...event, asset: maxAsset }] });
  for (const bad of ['', 'SYNTHETIC-ASSET-', 'SYNTHETIC-ASSET-a', 'SYNTHETIC-ASSET-A_', 'SYNTHETIC-ASSET-' + 'Z'.repeat(65), 'prefix' + asset, asset + 'suffix.invalid', asset + '\n', 'SYNTHETIC-ASSET-\u0391', 'ordinary.example.invalid', 'DRAFT-PILOT-REF-' + 'a'.repeat(64)]) {
    refused(derivePilotReference(encode(context), bad));
    refused(run(context, { ...message, assets: [bad] }, { version: 1, events: [{ ...event, asset: bad }] }));
    refused(run(context, message, { version: 1, events: [...log.events, { ...event, asset: bad }] }));
  }
  for (const key of ['scope', 'session', 'context']) {
    const prefix = context[key].slice(0, -1);
    for (const bad of [prefix, prefix + 'A'.repeat(33), 'prefix' + context[key], context[key] + '\n', prefix + '\u0391', prefix + 'a']) {
      const changed = { ...context, [key]: bad };
      refused(run(changed));
      refused(derivePilotReference(encode(changed), asset));
    }
  }
});

test('all tick/enum combinations and stable input order including unsorted and tied ticks', () => {
  const events = [];
  for (const level of ['INFO', 'ERROR']) for (const code of ['START', 'STOP', 'FAILURE']) for (const tick of [1000000, 0, 5, 5]) events.push({ asset, tick, level, code });
  fidelity(context, { ...message, task: 'FIRST_ERRORS', assets: [asset] }, { version: 1, events });
  for (const tick of [-1, 0.1, 1000001, '1', null]) refused(run(context, message, { ...log, events: [...log.events, { ...event, tick }] }));
  for (const level of ['error', 'DEBUG', 1]) refused(run(context, message, { ...log, events: [...log.events, { ...event, level }] }));
  for (const code of ['OTHER', 'failure', 1]) refused(run(context, message, { ...log, events: [...log.events, { ...event, code }] }));
});

test('all JSON positions reject duplicates, escapes, noncanonical numbers, whitespace and trailing material', () => {
  const inputs = [encode(context), encode(message), encode(log)];
  for (const [index, text] of inputs.entries()) {
    const variants = ['', '{', 'null', '[]', '\u00e9', '\ud800', ' ' + text, text + '\n', text + '{}', text.replace('"version":1', '"version":2,"version":1'), text.replace('"version":1', '"version":1e0'), text.replace('"version":1', '"version":1.0'), text.replace('SYNTHETIC', '\\u0053YNTHETIC'), text.replace('"version"', '"\\u0076ersion"')];
    for (const bad of variants) {
      const args = [...inputs]; args[index] = bad;
      refused(transformPilot(...args));
      if (index === 0) refused(derivePilotReference(bad, asset));
    }
  }
  for (const bad of [inputs[2].replace('"tick":1', '"tick":-1,"tick":1'), inputs[2].replace('"tick":1', '"tick":-0'), inputs[2].replace('"tick":1', '"tick":1e0'), inputs[2].replace('"events":', '"__proto__":{"asset":"synthetic.invalid"},"events":'), inputs[2].replace('"asset":', '"asset":"synthetic.invalid","asset":')]) refused(transformPilot(inputs[0], inputs[1], bad));
  refused(transformPilot(inputs[0], inputs[1].replace('"assets":', '"assets":[],"assets":'), inputs[2]));
});

test('late invalid 128th event is atomic without image/reference/prefix/echo', () => {
  const events = Array.from({ length: 127 }, (_, i) => ({ ...event, asset: i % 2 ? asset : other }));
  refused(run(context, message, { version: 1, events: [...events, { ...event, code: asset }] }));
  refused(run(context, message, { version: 1, events: [...events, { ...event, extra: asset }] }));
});

test('unreachable canonical context/message caps: raw exact/over refuse; maximal schemas admitted', () => {
  const inputs = [encode(context), encode(message), encode(log)];
  for (const [index, limit] of [[0, 512], [1, 1024], [2, 16384]]) for (const n of [limit, limit + 1]) {
    const args = [...inputs]; args[index] = 'x'.repeat(n); refused(transformPilot(...args));
    if (index === 0) refused(derivePilotReference(args[0], asset));
  }
  const c = { version: 1, scope: 'SYNTHETIC-SCOPE-' + 'Z'.repeat(32), session: 'SYNTHETIC-SESSION-' + 'Z'.repeat(32), context: 'SYNTHETIC-CONTEXT-' + 'Z'.repeat(32) };
  const assets = Array.from({ length: 8 }, (_, i) => 'SYNTHETIC-ASSET-' + 'Z'.repeat(63) + i);
  const m = { version: 1, task: 'ERROR_COUNTS', assets };
  assert.equal(encode(c).length < 256 && encode(m).length < 800, true, 'canonical maxima below raw caps');
  fidelity(c, m, { version: 1, events: assets.map((a) => ({ ...event, asset: a })) });
});

function logBoundary() {
  for (let size = 1; size <= 64; size += 1) {
    const assets = Array.from({ length: 8 }, (_, i) => 'SYNTHETIC-ASSET-' + 'Z'.repeat(size - 1) + i);
    const events = Array.from({ length: 128 }, (_, i) => ({ asset: assets[i % 8], tick: 0, level: 'ERROR', code: 'FAILURE' }));
    const l = { version: 1, events };
    const base = encode(l).length;
    if (base > 16384 || base + 6 * 128 < 16385) continue;
    let remaining = 16384 - base;
    for (const entry of events) {
      const added = Math.min(6, remaining);
      if (added > 0) entry.tick = 10 ** added;
      remaining -= added;
    }
    assert.equal(remaining === 0 && encode(l).length === 16384, true);
    const over = { version: 1, events: events.map((e) => ({ ...e })) };
    const next = over.events.find((e) => e.tick < 1000000);
    assert.equal(next !== undefined, true);
    next.tick = next.tick === 0 ? 10 : next.tick * 10;
    assert.equal(encode(over).length === 16385, true);
    return { assets, l, over };
  }
  assert.equal(false, true, 'reachable log boundary fixture');
}

test('canonical schema-valid exact16384 log admits and valid one-byte-over differs solely in cap', () => {
  const { assets, l, over } = logBoundary();
  fidelity(context, { ...message, assets }, l);
  refused(run(context, { ...message, assets }, over));
  assert.equal(over.events.every((e) => Number.isInteger(e.tick) && e.tick <= 1000000), true);
  assert.equal(new Set(over.events.map((e) => e.asset)).size === assets.length, true);
});

test('maximum-shaped reachable cloak and sound conservative bound do not reach output32768', () => {
  const assets = Array.from({ length: 8 }, (_, i) => 'SYNTHETIC-ASSET-' + i);
  const events = Array.from({ length: 128 }, (_, i) => ({ asset: assets[i % 8], tick: 1000000, level: 'ERROR', code: 'FAILURE' }));
  const result = fidelity(context, { ...message, assets }, { version: 1, events });
  const maximumEventBytes = encode({ asset: 'DRAFT-PILOT-REF-' + 'a'.repeat(64), tick: 1000000, level: 'ERROR', code: 'FAILURE' }).length;
  assert.equal(maximumEventBytes <= 141, true);
  assert.equal(128 * (maximumEventBytes + 1) + 8 * 82 + 512 < 22000, true, 'conservative fixed framing bound');
  assert.equal(result.cloakedJson.length < 22000 && result.cloakedJson.length < 32768, true, 'over-cap canonical output unreachable');
});

test('only two exports; frozen success/reference arrays reject mutation without changed behavior', () => {
  assert.equal(Object.keys(api).sort().join(',') === 'derivePilotReference,transformPilot', true);
  const result = fidelity(context, message, log);
  let denied = 0;
  try { result.cloakedJson = asset; } catch { denied += 1; }
  try { result.references[0] = asset; } catch { denied += 1; }
  try { result.references.push(asset); } catch { denied += 1; }
  assert.equal(denied === 3, true);
  assert.equal(result.cloakedJson === run().cloakedJson, true);
});

test('1000 generated multi-asset cases independently vary each context dimension and both tasks', () => {
  for (let i = 0; i < 1000; i += 1) {
    const suffix = i.toString(36).toUpperCase();
    const c = { version: 1, scope: 'SYNTHETIC-SCOPE-' + suffix, session: 'SYNTHETIC-SESSION-' + (i * 7).toString(36).toUpperCase(), context: 'SYNTHETIC-CONTEXT-' + (i * 13).toString(36).toUpperCase() };
    const count = 2 + i % 7;
    const assets = Array.from({ length: count }, (_, j) => 'SYNTHETIC-ASSET-' + suffix + 'X' + j);
    if (i % 2) assets.reverse();
    const m = { version: 1, task: i % 2 ? 'FIRST_ERRORS' : 'ERROR_COUNTS', assets };
    const n = count + i % (129 - count);
    const events = Array.from({ length: n }, (_, j) => ({ asset: assets[j % count], tick: j % 3 ? (i * 31 + j) % 1000001 : 0, level: j % count === 0 ? 'INFO' : j % 2 ? 'ERROR' : 'INFO', code: ['START', 'STOP', 'FAILURE'][j % 3] }));
    const result = fidelity(c, m, { version: 1, events });
    assert.equal(result.cloakedJson === run(c, m, { version: 1, events }).cloakedJson, true);
    for (const key of ['scope', 'session', 'context']) {
      const changed = { ...c, [key]: c[key] + 'Q' };
      const different = transformed(run(changed, m, { version: 1, events }));
      assert.equal(different.message.assets.every((r, j) => r !== result.references[j]), true, 'independent component separation');
    }
    const changedTask = run(c, { ...m, task: m.task === 'ERROR_COUNTS' ? 'FIRST_ERRORS' : 'ERROR_COUNTS' }, { version: 1, events });
    transformed(changedTask);
    assert.equal(encode(changedTask.references) === encode(result.references), true, 'task is data, not reference authority');
  }
});
