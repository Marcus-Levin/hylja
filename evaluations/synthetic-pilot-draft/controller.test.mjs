// PROPOSED / PUBLIC_DRAFT_ONLY: public fixture predicates, not authorization.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from './controller.mjs';
import { transformPilot, derivePilotReference } from './transform.mjs';
const { preparePilot, completePilot } = api;
const enc = JSON.stringify;
const context = { version: 1, scope: 'SYNTHETIC-SCOPE-A', session: 'SYNTHETIC-SESSION-A', context: 'SYNTHETIC-CONTEXT-A' };
const assets = ['SYNTHETIC-ASSET-A', 'SYNTHETIC-ASSET-B'];
const input = { version: 1, context, message: { version: 1, task: 'ERROR_COUNTS', assets }, log: { version: 1, events: [
  { asset: assets[0], tick: 9, level: 'ERROR', code: 'START' },
  { asset: assets[1], tick: 2, level: 'INFO', code: 'FAILURE' },
  { asset: assets[0], tick: 9, level: 'ERROR', code: 'STOP' },
] } };
function controlsFor(unit) {
  return unit.message.assets.map((asset, i) => {
    const cfg = { version: 1, displayPurpose: 'SYNTHETIC-PILOT-RESULT', displayDestination: 'SYNTHETIC-DISPLAY-' + i, adminPurpose: 'SYNTHETIC-OWNER-LIFECYCLE', adminDestination: 'SYNTHETIC-ADMIN-' + i, createdAt: 10, expiresAt: 100, revision: 1 };
    const display = { ...unit.context, purpose: cfg.displayPurpose, operation: 'DISPLAY', destination: cfg.displayDestination, revision: 1 };
    return { asset, configJson: enc(cfg), displayJson: enc(display), now: 20, revokeJson: null };
  });
}
function replyFor(unit, values) {
  const transformed = transformPilot(enc(unit.context), enc(unit.message), enc(unit.log));
  assert.equal(transformed.status === 'TRANSFORMED', true, 'reviewed input prerequisite');
  return { version: 1, task: unit.message.task, results: transformed.references.map((reference, i) =>
    unit.message.task === 'ERROR_COUNTS' ? { reference, errorCount: values[i] } : { reference, firstError: values[i] }) };
}
function refused(result) {
  assert.equal(enc(result) === '{"status":"REFUSED","reason":"PILOT_CONTROLLER_REFUSED"}', true, 'whole-unit fixed refusal');
  assert.equal(Object.isFrozen(result), true);
}
function displayed(unit, reply, controls = controlsFor(unit)) {
  const result = completePilot(enc(unit), enc(reply), enc(controls));
  assert.equal(result.status === 'DISPLAYED', true, 'new whole-answer restoration behavior');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.keys(result).join(',') === 'status,mode,answerJson' && result.mode === 'PUBLIC_DRAFT_ONLY', true);
  const expected = { version: 1, mode: 'PUBLIC_DRAFT_ONLY', task: unit.message.task, results: reply.results.map((record, i) =>
    unit.message.task === 'ERROR_COUNTS' ? { asset: unit.message.assets[i], errorCount: record.errorCount } : { asset: unit.message.assets[i], firstError: record.firstError }) };
  assert.equal(result.answerJson === enc(expected), true, 'exact ordered unchanged reply semantics');
  return result;
}
const runBad = (unit = input, reply = replyFor(input, [2, 0]), controls = controlsFor(input)) => refused(completePilot(enc(unit), enc(reply), enc(controls)));
const variants = (text) => {
  const escaped = text.replace('"version"', '"\\u0076ersion"');
  assert.equal(escaped !== text, true, 'escape negative must change the admitted version key');
  return ['', '{', 'null', '[]', '1', ' ' + text, text + '\n', text + '{}', escaped, text.replace('"version":1', '"version":2,"version":1'), text.replace('"version":1', '"version":1e0')];
};

test('prepare returns exactly the reviewed frozen transform; complete preserves both task answers', () => {
  assert.equal(Object.keys(api).sort().join(',') === 'completePilot,preparePilot', true);
  const prepared = preparePilot(enc(input));
  const expected = transformPilot(enc(context), enc(input.message), enc(input.log));
  assert.equal(prepared.status === 'TRANSFORMED', true, 'new prepare behavior');
  assert.equal(enc(prepared) === enc(expected), true);
  assert.equal(Object.isFrozen(prepared) && Object.isFrozen(prepared.references), true);
  assert.equal(enc(prepared).includes('SYNTHETIC-ASSET-') || enc(prepared).includes('SYNTHETIC-CONTEXT-'), false);
  displayed(input, replyFor(input, [2, 0]));
  const first = { ...input, message: { ...input.message, task: 'FIRST_ERRORS' } };
  displayed(first, replyFor(first, [{ tick: 9, code: 'START' }, null]));
  displayed(input, replyFor(input, [128, 128])); // Semantically wrong but schema/fixture-authorized: never repaired.
});

test('primitive positions and hostile hooks are never touched', () => {
  let touched = 0;
  const hostile = new Proxy({}, { get() { touched += 1; throw new Error('synthetic sentinel'); }, ownKeys() { touched += 1; throw new Error('synthetic sentinel'); } });
  const bads = [undefined, null, true, 0, 1n, Symbol('synthetic'), [], {}, () => {}, new String(enc(input)), hostile];
  const args = [enc(input), enc(replyFor(input, [2, 0])), enc(controlsFor(input))];
  for (const bad of bads) {
    refused(preparePilot(bad));
    for (const i of [0, 1, 2]) { const altered = [...args]; altered[i] = bad; refused(completePilot(...altered)); }
  }
  assert.equal(touched, 0);
});

test('canonical closed input and reviewed late-invalid upstream units refuse', () => {
  for (const bad of variants(enc(input))) refused(preparePilot(bad));
  const units = [{ ...input, extra: assets[0] }, { ...input, version: 2 }, { context, version: 1, message: input.message, log: input.log },
    { ...input, message: { ...input.message, assets: [assets[0], assets[0]] } },
    { ...input, log: { version: 1, events: [...input.log.events, { ...input.log.events[0], code: 'BOOT' }] } }];
  for (const bad of units) { refused(preparePilot(enc(bad))); runBad(bad); }
  for (const key of Object.keys(input)) { const bad = { ...input }; delete bad[key]; refused(preparePilot(enc(bad))); }
  for (const n of [32768, 32769]) { refused(preparePilot('x'.repeat(n))); refused(completePilot('x'.repeat(n), '{}', '[]')); }
});

test('complete reply sequence must exactly match, including last B; no partial answer', () => {
  const good = replyFor(input, [2, 0]);
  const foreign = derivePilotReference(enc({ ...context, context: 'SYNTHETIC-CONTEXT-B' }), assets[1]).reference;
  for (const reference of [foreign, good.results[0].reference, 'DRAFT-REF-' + 'a'.repeat(64), 'DRAFT-PILOT-REF-' + '0'.repeat(64), assets[1], null]) {
    runBad(input, { ...good, results: [good.results[0], { ...good.results[1], reference }] });
  }
  for (const results of [[], [good.results[0]], [...good.results, good.results[0]], [...good.results].reverse()]) runBad(input, { ...good, results });
  for (const task of ['FIRST_ERRORS', 'DISPLAY', 'ERROR_COUNT']) runBad(input, { ...good, task });
  for (const errorCount of [-1, 129, 0.1, '2', null, {}]) runBad(input, { ...good, results: [good.results[0], { ...good.results[1], errorCount }] });
  const first = { ...input, message: { ...input.message, task: 'FIRST_ERRORS' } };
  const r = replyFor(first, [{ tick: 0, code: 'START' }, { tick: 1000000, code: 'FAILURE' }]);
  displayed(first, r);
  for (const value of [{ tick: -1, code: 'START' }, { tick: 1000001, code: 'START' }, { tick: 0.1, code: 'STOP' }, { tick: 1, code: 'READY' }, { tick: 1, code: 'STOP', grant: 'DISPLAY' }, {}, [], 0]) runBad(first, { ...r, results: [r.results[0], { ...r.results[1], firstError: value }] }, controlsFor(first));
});

test('every provider metadata position/schema member/canonical variant refuses', () => {
  const good = replyFor(input, [2, 0]);
  for (const key of ['scope', 'session', 'context', 'purpose', 'operation', 'destination', 'revision', 'grant', 'clock', 'now', '__proto__']) {
    runBad(input, { ...good, [key]: 'SYNTHETIC-ASSET-INJECTED' });
    runBad(input, { ...good, results: [good.results[0], { ...good.results[1], [key]: 'SYNTHETIC-ASSET-INJECTED' }] });
  }
  for (const key of Object.keys(good)) { const r = { ...good }; delete r[key]; runBad(input, r); }
  for (const key of Object.keys(good.results[1])) { const b = { ...good.results[1] }; delete b[key]; runBad(input, { ...good, results: [good.results[0], b] }); }
  for (const bad of [...variants(enc(good)), enc({ task: good.task, version: 1, results: good.results }), enc(good).replace('"errorCount":2', '"errorCount":-0'), 'x'.repeat(8192), 'x'.repeat(8193)]) refused(completePilot(enc(input), bad, enc(controlsFor(input))));
});

test('late per-reference independent DISPLAY denial never releases A prefix or trace', () => {
  const good = replyFor(input, [2, 0]);
  for (const change of [{ purpose: 'OTHER' }, { operation: 'USE' }, { operation: 'EXPORT' }, { revision: 2 }, { destination: 'SYNTHETIC-DISPLAY-FOREIGN' }, { scope: 'SYNTHETIC-SCOPE-B' }, { session: 'SYNTHETIC-SESSION-B' }, { context: 'SYNTHETIC-CONTEXT-B' }]) {
    const controls = controlsFor(input); controls[1].displayJson = enc({ ...JSON.parse(controls[1].displayJson), ...change }); runBad(input, good, controls);
  }
  for (const now of [9, 100, 1000001, '20', null, 20.1]) { const controls = controlsFor(input); controls[1].now = now; runBad(input, good, controls); }
  const revoked = controlsFor(input);
  const cfg = JSON.parse(revoked[1].configJson);
  revoked[1].revokeJson = enc({ ...context, purpose: cfg.adminPurpose, operation: 'REVOKE', destination: cfg.adminDestination, revision: 1 });
  runBad(input, good, revoked);
  revoked[1].revokeJson = revoked[1].displayJson; runBad(input, good, revoked);
  displayed(input, good); // Fresh reconstruction does not inherit global revocation.
});

test('complete controls order/shape/config/revoke and raw caps refuse whole unit', () => {
  const good = replyFor(input, [2, 0]);
  const controls = controlsFor(input);
  for (const list of [[], [controls[0]], [...controls, controls[0]], [...controls].reverse(), [controls[0], { ...controls[1], asset: assets[0] }]]) runBad(input, good, list);
  for (const key of Object.keys(controls[1])) {
    const missing = { ...controls[1] }; delete missing[key]; runBad(input, good, [controls[0], missing]);
  }
  for (const change of [{ extra: assets[1] }, { configJson: '{}' }, { configJson: '' }, { displayJson: '{}' }, { revokeJson: '{}' }, { configJson: 'x'.repeat(1025) }, { displayJson: 'x'.repeat(1025) }, { revokeJson: 'x'.repeat(1025) }]) runBad(input, good, [controls[0], { ...controls[1], ...change }]);
  const wrong = controlsFor(input); wrong[1].configJson = enc({ ...JSON.parse(wrong[1].configJson), displayPurpose: 'OTHER' }); runBad(input, good, wrong);
  for (const bad of [' '+enc(controls), enc(controls)+'\n', enc(controls)+'{}', enc(controls).replace('"now":20', '"now":1,"now":20'), 'x'.repeat(8192), 'x'.repeat(8193)]) refused(completePilot(enc(input), enc(good), bad));
});

test('1000 independently expected multi-reference cases across both tasks and tuple dimensions', () => {
  for (let i = 0; i < 1000; i += 1) {
    const suffix = i.toString(36).toUpperCase();
    const c = { version: 1, scope: 'SYNTHETIC-SCOPE-' + suffix, session: 'SYNTHETIC-SESSION-' + (i*7).toString(36).toUpperCase(), context: 'SYNTHETIC-CONTEXT-' + (i*13).toString(36).toUpperCase() };
    const aa = Array.from({ length: 2+i%7 }, (_, j) => 'SYNTHETIC-ASSET-' + suffix + 'X' + j);
    if (i%2) aa.reverse();
    const task = i%2 ? 'FIRST_ERRORS' : 'ERROR_COUNTS';
    const events = aa.flatMap((asset, j) => j%3 === 0 ? [{ asset, tick: 7, level: 'INFO', code: 'FAILURE' }] : [
      { asset, tick: 9, level: 'ERROR', code: 'STOP' }, { asset, tick: 2, level: 'ERROR', code: 'START' }, { asset, tick: 2, level: 'ERROR', code: 'FAILURE' },
    ]);
    const unit = { version: 1, context: c, message: { version: 1, task, assets: aa }, log: { version: 1, events } };
    const truth = aa.map((_, j) => task === 'ERROR_COUNTS' ? (j%3 === 0 ? 0 : 3) : (j%3 === 0 ? null : { tick: 2, code: 'START' }));
    const reply = replyFor(unit, truth); displayed(unit, reply);
    const cc = controlsFor(unit); cc[cc.length-1].displayJson = enc({ ...JSON.parse(cc[cc.length-1].displayJson), operation: 'USE' }); runBad(unit, reply, cc);
    const foreign = derivePilotReference(enc({ ...c, context: c.context+'Q' }), aa[aa.length-1]).reference;
    const rr = { ...reply, results: reply.results.map((r, j) => j === aa.length-1 ? { ...r, reference: foreign } : r) }; runBad(unit, rr, controlsFor(unit));
  }
});
