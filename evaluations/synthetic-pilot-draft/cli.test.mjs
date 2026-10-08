// PROPOSED / PUBLIC_DRAFT_ONLY. Real public stdin/stdout children, not model traffic.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { pilotCases } from './cases.mjs';
import { preparePilot } from './controller.mjs';
import { respondPilot } from './responder.mjs';
const enc = JSON.stringify;
const refusal = '{"status":"REFUSED","reason":"PILOT_CONTROLLER_REFUSED"}\n';
const truth = [[0], [2], [2], [0,1], [0,1,0,1,0,1,0,1], [1,0], [null], [{ tick: 2, code: 'FAILURE' }], [{ tick: 5, code: 'START' }], [null,{ tick: 2, code: 'STOP' }], [{ tick: 0, code: 'START' }], [null]];
function run(args, packet) {
  return spawnSync(process.execPath, ['evaluations/synthetic-pilot-draft/cli.mjs', ...args], {
    input: packet, encoding: 'utf8', stdio: 'pipe', shell: false, timeout: 2000, maxBuffer: 131072,
    env: { PATH: '/home/marcus/.local/state/hylja-delivery/issue269-recovery.sD2tQ8/toolchain/bin:/usr/bin:/bin', LC_ALL: 'C', OPENSSL_CONF: '' },
  });
}
function checked(result, status, expected) {
  assert.equal(result.error === undefined && result.signal === null, true, 'fixed child fully returned');
  assert.equal(result.status, status);
  assert.equal(result.stderr === '', true, 'no raw diagnostics');
  assert.equal(result.stdout === expected, true, 'exact entire actual stdout bytes');
}
function replyFor(c) {
  const transformed = preparePilot(c.inputJson);
  assert.equal(transformed.status === 'TRANSFORMED', true, 'reviewed pure preparation');
  const offline = respondPilot(transformed.cloakedJson);
  assert.equal(offline.status === 'RESPONDED', true, 'explicit offline response');
  return offline.replyJson;
}
function expectedAnswer(c, values) {
  const input = JSON.parse(c.inputJson);
  return enc({ version: 1, mode: 'PUBLIC_DRAFT_ONLY', task: input.message.task, results: input.message.assets.map((asset, i) =>
    input.message.task === 'ERROR_COUNTS' ? { asset, errorCount: values[i] } : { asset, firstError: values[i] }) }) + '\n';
}
test('frozen public12case corpus; actual variable cloak/demo/display paths with independent truth', () => {
  assert.equal(pilotCases.length, 12);
  assert.equal(Object.isFrozen(pilotCases) && pilotCases.every(Object.isFrozen), true);
  for (const [i, c] of pilotCases.entries()) {
    assert.equal(Object.keys(c).join(',') === 'id,inputJson,controlsJson' && c.id === 'C'+String(i+1).padStart(2,'0'), true);
    const original = JSON.parse(c.inputJson);
    const prepared = preparePilot(c.inputJson);
    assert.equal(prepared.status === 'TRANSFORMED', true);
    const cloak = run(['cloak'], enc({ version: 1, inputJson: c.inputJson }));
    checked(cloak, 0, prepared.cloakedJson+'\n');
    assert.equal(original.message.assets.every((asset) => !cloak.stdout.includes(asset)), true, 'no originals in actual request');
    assert.equal(!cloak.stdout.includes(original.context.scope) && !cloak.stdout.includes('configJson'), true);
    const want = expectedAnswer(c, truth[i]);
    checked(run(['demo'], enc({ version: 1, inputJson: c.inputJson, controlsJson: c.controlsJson })), 0, want);
    checked(run(['display'], enc({ version: 1, inputJson: c.inputJson, replyJson: replyFor(c), controlsJson: c.controlsJson })+'\n'), 0, want);
  }
  assert.equal(JSON.parse(pilotCases[4].inputJson).message.assets.length, 8);
});
test('actual max128event variable input reaches both tasks with exact equality/order and null result', () => {
  const c = pilotCases[3]; const input = JSON.parse(c.inputJson); const [a,b] = input.message.assets;
  input.log.events = Array.from({ length: 128 }, (_, i) => ({ asset: i%2 ? b : a, tick: i%2 ? 7 : 1000000-i, level: i%2 ? 'INFO' : 'ERROR', code: i%3 ? 'STOP' : 'FAILURE' }));
  let sample = { ...c, inputJson: enc(input) };
  checked(run(['demo'], enc({ version: 1, inputJson: sample.inputJson, controlsJson: sample.controlsJson })), 0, expectedAnswer(sample,[64,0]));
  input.message.task = 'FIRST_ERRORS'; sample = { ...sample, inputJson: enc(input) };
  checked(run(['demo'], enc({ version: 1, inputJson: sample.inputJson, controlsJson: sample.controlsJson })), 0, expectedAnswer(sample,[{ tick: 999874, code: 'FAILURE' },null]));
});
test('actual mixed late B authorization refusals never print eligible A prefix', () => {
  const c = pilotCases[3]; const goodReply = replyFor(c);
  const controls = JSON.parse(c.controlsJson);
  const failures = [
    ...['scope','session','context'].map((key) => ({ [key]: JSON.parse(controls[1].displayJson)[key]+'Z' })),
    { revision: 2 }, { purpose: 'OTHER' }, { destination: 'SYNTHETIC-DISPLAY-FOREIGN' }, { operation: 'USE' }, { operation: 'EXPORT' },
  ];
  for (const change of failures) {
    const cc = JSON.parse(c.controlsJson); cc[1].displayJson = enc({ ...JSON.parse(cc[1].displayJson), ...change });
    checked(run(['display'], enc({ version: 1, inputJson: c.inputJson, replyJson: goodReply, controlsJson: enc(cc) })), 2, refusal);
  }
  for (const now of [9,100]) { const cc = JSON.parse(c.controlsJson); cc[1].now = now; checked(run(['demo'], enc({ version: 1, inputJson: c.inputJson, controlsJson: enc(cc) })), 2, refusal); }
  const cc = JSON.parse(c.controlsJson); const context = JSON.parse(c.inputJson).context; const cfg = JSON.parse(cc[1].configJson);
  cc[1].revokeJson = enc({ ...context, purpose: cfg.adminPurpose, operation: 'REVOKE', destination: cfg.adminDestination, revision: 1 });
  checked(run(['display'], enc({ version: 1, inputJson: c.inputJson, replyJson: goodReply, controlsJson: enc(cc) })), 2, refusal);
});
test('actual late reply corruption/provider authority refuses entire stdout', () => {
  const c = pilotCases[3]; const good = JSON.parse(replyFor(c));
  for (const change of [{ reference: good.results[0].reference }, { reference: 'DRAFT-PILOT-REF-'+'0'.repeat(64) }, { errorCount: -1 }, { errorCount: 129 }, { errorCount: '1' }, { purpose: 'DISPLAY' }, { now: 20 }]) {
    const replyJson = enc({ ...good, results: [good.results[0], { ...good.results[1], ...change }] });
    checked(run(['display'], enc({ version: 1, inputJson: c.inputJson, replyJson, controlsJson: c.controlsJson })), 2, refusal);
  }
  for (const reply of [{ ...good, grant: 'DISPLAY' }, { ...good, results: [...good.results].reverse() }, { ...good, results: [good.results[0]] }]) checked(run(['display'], enc({ version: 1, inputJson: c.inputJson, replyJson: enc(reply), controlsJson: c.controlsJson })), 2, refusal);
});
test('fixed argv/closed packet/canonical byte/LF/raw size refusals', () => {
  const c = pilotCases[0]; const valid = enc({ version: 1, inputJson: c.inputJson });
  for (const args of [[], ['other'], ['cloak','extra'], ['--help']]) checked(run(args, ''), 2, refusal);
  for (const raw of ['', '{', 'null', '[]', valid+'\n\n', ' '+valid, valid+'{}', valid.replace('"version":1','"version":2,"version":1'), enc({ inputJson: c.inputJson, version: 1 }), enc({ version: 1, inputJson: c.inputJson, path: 'synthetic.invalid' }), enc({ version: 1, inputJson: '\u00e9' }), 'x'.repeat(65536), 'x'.repeat(65537), 'x'.repeat(65538)]) checked(run(['cloak'],raw), 2, refusal);
  checked(run(['cloak'],valid+'\n'), 0, preparePilot(c.inputJson).cloakedJson+'\n');
  checked(run(['display'],enc({ version: 1, inputJson: c.inputJson, replyJson: replyFor(c), controlsJson: '[]' })), 2, refusal);
});
