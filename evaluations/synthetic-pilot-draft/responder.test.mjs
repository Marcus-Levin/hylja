// PROPOSED / PUBLIC_DRAFT_ONLY: deterministic responder, never native-model evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from './responder.mjs';
import { transformPilot } from './transform.mjs';
const { respondPilot } = api;
const enc = JSON.stringify;
const context = { version: 1, scope: 'SYNTHETIC-SCOPE-A', session: 'SYNTHETIC-SESSION-A', context: 'SYNTHETIC-CONTEXT-A' };
const assets = ['SYNTHETIC-ASSET-A', 'SYNTHETIC-ASSET-B'];
const events = [
  { asset: assets[0], tick: 9, level: 'ERROR', code: 'STOP' },
  { asset: assets[1], tick: 2, level: 'INFO', code: 'FAILURE' },
  { asset: assets[0], tick: 2, level: 'ERROR', code: 'START' },
  { asset: assets[0], tick: 2, level: 'ERROR', code: 'FAILURE' },
];
function cloak(task = 'ERROR_COUNTS', entries = events, aa = assets) {
  const r = transformPilot(enc(context), enc({ version: 1, task, assets: aa }), enc({ version: 1, events: entries }));
  assert.equal(r.status === 'TRANSFORMED', true, 'reviewed P1 prerequisite'); return r;
}
function refused(r) {
  assert.equal(enc(r) === '{"status":"REFUSED","reason":"PILOT_RESPONDER_REFUSED"}' && Object.isFrozen(r), true);
}
function answered(task, expected, entries = events, aa = assets) {
  const transformed = cloak(task, entries, aa);
  const r = respondPilot(transformed.cloakedJson);
  assert.equal(r.status === 'RESPONDED', true, 'new offline two-task behavior');
  assert.equal(Object.keys(r).join(',') === 'status,mode,replyJson' && r.mode === 'PUBLIC_DRAFT_ONLY' && Object.isFrozen(r), true);
  const truth = { version: 1, task, results: transformed.references.map((reference, i) => task === 'ERROR_COUNTS' ? { reference, errorCount: expected[i] } : { reference, firstError: expected[i] }) };
  assert.equal(r.replyJson === enc(truth), true, 'independent known semantics');
  assert.equal(r.replyJson.includes('SYNTHETIC-ASSET-'), false);
}
test('counts level regardless of code; first min tick/stable tie/null; closed frozen exports', () => {
  assert.equal(Object.keys(api).join(',') === 'respondPilot', true);
  answered('ERROR_COUNTS', [3, 0]); answered('FIRST_ERRORS', [{ tick: 2, code: 'START' }, null]);
  answered('FIRST_ERRORS', [{ tick: 0, code: 'START' }], [{ asset: assets[0], tick: 1000000, level: 'ERROR', code: 'STOP' }, { asset: assets[0], tick: 0, level: 'ERROR', code: 'START' }], [assets[0]]);
  answered('ERROR_COUNTS', [128], Array.from({ length: 128 }, (_, tick) => ({ asset: assets[0], tick, level: 'ERROR', code: tick%2 ? 'START' : 'STOP' })), [assets[0]]);
});
test('hostile primitive-only callers never execute hooks', () => {
  let touched = 0;
  const hostile = new Proxy({}, { get() { touched++; throw new Error('synthetic'); }, ownKeys() { touched++; throw new Error('synthetic'); } });
  for (const bad of [hostile, undefined, null, 0, true, 1n, Symbol('synthetic'), [], {}, () => {}, new String('synthetic')]) refused(respondPilot(bad));
  assert.equal(touched, 0);
});
test('entire canonical closed cloak, member/reference sets, caps and late event validation', () => {
  const raw = cloak().cloakedJson; const image = JSON.parse(raw);
  for (const bad of ['', '{', 'null', '[]', '1', ' '+raw, raw+'\n', raw+'{}', raw.replace('"version":1', '"version":2,"version":1'), raw.replace('DRAFT', '\\u0044RAFT'), raw.replace('"tick":9', '"tick":9e0'), 'x'.repeat(32768), 'x'.repeat(32769)]) refused(respondPilot(bad));
  for (const key of Object.keys(image)) { const bad = { ...image }; delete bad[key]; refused(respondPilot(enc(bad))); }
  for (const bad of [
    { ...image, purpose: 'DISPLAY' }, { ...image, mode: 'OTHER' }, { mode: image.mode, version: 1, message: image.message, log: image.log },
    { ...image, message: { ...image.message, assets: [image.message.assets[0], image.message.assets[0]] } },
    { ...image, message: { ...image.message, task: 'SUMMARIZE_FAILURES' } },
    { ...image, message: { ...image.message, grant: 'DISPLAY' } },
    { ...image, log: { version: 1, events: [] } },
    { ...image, log: { version: 1, events: image.log.events.filter((e) => e.asset === image.message.assets[0]) } },
  ]) refused(respondPilot(enc(bad)));
  for (const change of [{ asset: 'SYNTHETIC-ASSET-A' }, { asset: 'DRAFT-REF-'+'a'.repeat(64) }, { asset: 'DRAFT-PILOT-REF-'+'0'.repeat(64) }, { tick: -1 }, { tick: 1000001 }, { code: 'BOOT' }, { level: 'WARN' }, { now: 20 }]) refused(respondPilot(enc({ ...image, log: { version: 1, events: [...image.log.events, { ...image.log.events[0], ...change }] } })));
  refused(respondPilot(enc({ ...image, log: { version: 1, events: Array.from({ length: 129 }, () => image.log.events[0]) } })));
});
