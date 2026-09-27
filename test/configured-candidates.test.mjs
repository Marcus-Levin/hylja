import assert from 'node:assert/strict';
import { test } from 'node:test';
import { composeClassification } from '../dist/classification.js';
import { createCandidateConfig, detectConfigured, MAX_TEXT_UNITS } from '../dist/configured-candidates.js';

// Synthetic only: invented organisations, .invalid project names and made-up engineering identifiers.
const A = Object.freeze({ tenantRef: 'tenant-a.invalid', projectRef: 'project-a.invalid' });
const B = Object.freeze({ tenantRef: 'tenant-b.invalid', projectRef: 'project-b.invalid' });
const configA = createCandidateConfig(A, {
  terms: [
    { term: 'Northwind Synthetic AB', semanticType: 'CUSTOMER_OR_PARTNER', sensitivity: 'CONFIDENTIAL' },
    { term: 'project-a.invalid', semanticType: 'PROJECT_OR_CONTRACT', sensitivity: 'CONFIDENTIAL' },
    { term: 'Contract SYN-0001', semanticType: 'PROJECT_OR_CONTRACT' },
    { term: 'Pricing Sheet Synthetic', semanticType: 'BUSINESS_CONFIDENTIAL' },
  ],
  patterns: [
    { template: '{A:3}-{9:4}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG', sensitivity: 'INTERNAL' },
    { template: 'DWG-{9:6}-{X:1-2}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'DRAWING_NUMBER' },
    { template: 'PN{9:5}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'PART_NUMBER' },
    { template: 'IT-{X:8}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ITEM_ID' },
    { template: 'DOC-{9:4}-{A}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'DOCUMENT_ID' },
    { template: '=S{9:2}.{A:3}.{9:3}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'FUNCTIONAL_LOCATION' },
    { template: 'N{9}:{9:1-3}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'PLC_TAG' },
    { template: 'SYN.{A:2}{9:3}.PV', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'SCADA_TAG' },
  ],
  fieldHints: [{ path: 'asset.tag', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG' },
    { path: 'items.*.customer', semanticType: 'CUSTOMER_OR_PARTNER' }],
});
const run = (text, more = {}) => detectConfigured({ text, inputRef: 'field-a.invalid', scope: A, config: configA, ...more });
const rows = (text, result) => result.candidates.map((c) => [c.semanticType, c.subtype ?? '', c.basis, text.slice(c.start, c.end)]);

test('synthetic industrial fixtures exercise every initial engineering subtype and the business classes', () => {
  const text = 'Pump PMP-0042 per DWG-123456-A2 part PN12345 item IT-AB12CD34 doc DOC-0007-C at =S01.PMP.001 plc N7:12 '
    + 'historian SYN.FT101.PV for Northwind Synthetic AB on project-a.invalid under Contract SYN-0001 see Pricing Sheet Synthetic';
  const result = run(text);
  assert.equal(result.status, 'COMPLETE');
  const got = rows(text, result);
  for (const [type, subtype, value] of [
    ['ENGINEERING_IDENTIFIER', 'ASSET_TAG', 'PMP-0042'], ['ENGINEERING_IDENTIFIER', 'DRAWING_NUMBER', 'DWG-123456-A2'],
    ['ENGINEERING_IDENTIFIER', 'PART_NUMBER', 'PN12345'], ['ENGINEERING_IDENTIFIER', 'ITEM_ID', 'IT-AB12CD34'],
    ['ENGINEERING_IDENTIFIER', 'DOCUMENT_ID', 'DOC-0007-C'], ['ENGINEERING_IDENTIFIER', 'FUNCTIONAL_LOCATION', '=S01.PMP.001'],
    ['ENGINEERING_IDENTIFIER', 'PLC_TAG', 'N7:12'], ['ENGINEERING_IDENTIFIER', 'SCADA_TAG', 'SYN.FT101.PV'],
    ['CUSTOMER_OR_PARTNER', '', 'Northwind Synthetic AB'], ['PROJECT_OR_CONTRACT', '', 'project-a.invalid'],
    ['PROJECT_OR_CONTRACT', '', 'Contract SYN-0001'], ['BUSINESS_CONFIDENTIAL', '', 'Pricing Sheet Synthetic'],
  ]) assert.ok(got.some(([t, s, , v]) => t === type && s === subtype && v === value), `${subtype || type} ${value}`);
});

test('dictionary terms match case-, whitespace- and normalization-insensitively with exact spans', () => {
  for (const text of ['northwind  synthetic ab', 'NORTHWIND\nSynthetic\tAB', 'Northwind Synthetic AB.']) {
    const [candidate] = run(text).candidates;
    assert.equal(candidate.basis, 'DICTIONARY');
    assert.ok(/northwind/iu.test(text.slice(candidate.start, candidate.end)) && /ab$/iu.test(text.slice(candidate.start, candidate.end)));
  }
  assert.deepEqual(rows('Northwind Synthetic ABC', run('Northwind Synthetic ABC')), []);
});

test('#10 negative: tenant A terms, patterns and forged hints never match or leak in tenant B', () => {
  const text = 'project-a.invalid and Northwind Synthetic AB with PMP-0042; part_number: SYN-P-1';
  const forgedHint = { fieldHints: [{ path: 'asset.tag', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG' }] };
  for (const [config, reason] of [[configA, 'CONFIG_SCOPE_MISMATCH'], [forgedHint, 'INVALID_CONFIG'],
    [createCandidateConfig({ tenantRef: A.tenantRef, projectRef: 'project-z.invalid' }, { terms: [{ term: 'project-a.invalid', semanticType: 'PROJECT_OR_CONTRACT' }] }), 'CONFIG_SCOPE_MISMATCH']]) {
    const result = detectConfigured({ text, inputRef: 'field-b.invalid', scope: B, config, fieldPath: ['asset', 'tag'] });
    assert.equal(result.status, 'PARTIAL');
    assert.deepEqual(result.reasons, [reason]);
    // Only the independent generic rule remains, clearly labelled as such.
    assert.ok(result.candidates.every((c) => c.basis === 'CONTEXT' && c.rule === 'context.engineering-key'));
    assert.deepEqual(result.candidates.map((c) => text.slice(c.start, c.end)), ['SYN-P-1']);
    const serialized = JSON.stringify(result);
    for (const term of ['project-a', 'Northwind', 'PMP-0042']) assert.ok(!serialized.includes(term), term);
  }
});

test('field hints apply only to the trusted key path, with * matching one segment', () => {
  assert.deepEqual(run('  anything-synthetic  ', { fieldPath: ['asset', 'tag'] }).candidates.map((c) => [c.rule, c.subtype]),
    [['field-hint.0', 'ASSET_TAG']]);
  assert.equal(run('Synthetic Org', { fieldPath: ['items', '3', 'customer'] }).candidates[0].semanticType, 'CUSTOMER_OR_PARTNER');
  assert.deepEqual(run('anything', { fieldPath: ['asset', 'name'] }).candidates, []);
  assert.deepEqual(run('anything', { fieldPath: ['items', 'customer'] }).candidates, []);
});

test('results and configuration errors never contain configured text', () => {
  const result = run('Northwind Synthetic AB PMP-0042');
  assert.ok(!JSON.stringify(result).includes('Northwind') && !JSON.stringify(result).includes('PMP'));
  for (const config of [{ terms: [{ term: 'Secret Customer Synthetic', semanticType: 'PERSON' }] },
    { patterns: [{ template: 'Secret{9', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG' }] },
    { terms: [{ term: 'Secret Customer Synthetic', semanticType: 'ENGINEERING_IDENTIFIER' }] }]) {
    assert.throws(() => createCandidateConfig(A, config), (error) => error instanceof TypeError &&
      error.message === 'Invalid candidate configuration' && !String(error.stack).includes('Secret'));
  }
});

test('templates reject ambiguous or unconstrained forms', () => {
  for (const template of ['{9:1-5}{9:1-5}', '{A:1-9}{X:2}', 'PLAIN-LITERAL', '{9:0}', '{9:40}', '{9:5-2}', '{Z}', '{9', 'x'.repeat(65)]) {
    assert.throws(() => createCandidateConfig(A, { patterns: [{ template, semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG' }] }),
      TypeError, template);
  }
  // A literal between variable-length placeholders is allowed.
  assert.ok(createCandidateConfig(A, { patterns: [{ template: '{9:1-5}-{9:1-5}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ITEM_ID' }] }));
});

test('configured sensitivity lets v1 composition resolve; generic candidates stay unresolved', () => {
  const context = { interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' };
  const [configured] = run('Northwind Synthetic AB').candidates;
  const resolved = composeClassification({ detectorEvidence: [configured.evidence] }, context);
  assert.deepEqual([resolved.status, resolved.semanticType, resolved.sensitivity], ['RESOLVED', 'CUSTOMER_OR_PARTNER', 'CONFIDENTIAL']);
  const [generic] = run('part_number: SYN-P-1').candidates;
  assert.equal(composeClassification({ detectorEvidence: [generic.evidence] }, context).status, 'UNRESOLVED');
  const all = run('Northwind Synthetic AB PMP-0042 part_number: SYN-P-1', { fieldPath: undefined }).candidates;
  const composed = composeClassification({ detectorEvidence: all.map((c) => c.evidence) }, context);
  assert.ok(!composed.reasons.includes('INVALID_EVIDENCE') && !composed.reasons.includes('DUPLICATE_EVIDENCE_ID'));
});

test('failures and missing configuration are explicit', () => {
  assert.deepEqual(detectConfigured({ text: 'x', inputRef: 'x', scope: A }).reasons, ['NO_CONFIG']);
  for (const [request, reason] of [[{ text: 1, inputRef: 'x', scope: A }, 'INVALID_REQUEST'],
    [{ text: 'x', inputRef: 'x', scope: null }, 'INVALID_REQUEST'], [{ text: 'x', inputRef: 'x', scope: A, fieldPath: 'a.b' }, 'INVALID_FIELD_PATH'],
    [{ text: 'x'.repeat(MAX_TEXT_UNITS + 1), inputRef: 'x', scope: A }, 'INPUT_TOO_LARGE'], [{ text: '\uDC00', inputRef: 'x', scope: A }, 'INVALID_TEXT'],
    [{ text: 'PMP-0042 '.repeat(300), inputRef: 'x', scope: A, config: configA }, 'TOO_MANY_CANDIDATES']]) {
    const result = detectConfigured(request);
    assert.deepEqual([result.status, result.reasons], ['FAILURE', [reason]], reason);
  }
});

test('large dictionaries and adversarial inputs stay within a bounded-work budget', () => {
  const terms = Array.from({ length: 10_000 }, (_, i) => ({ term: `Synthetic Customer ${i.toString(36)} AB`, semanticType: 'CUSTOMER_OR_PARTNER' }));
  const big = createCandidateConfig(A, { terms, patterns: [{ template: '{A:3}-{9:4}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG' }] });
  for (const text of ['Synthetic Customer '.repeat(55_000), 'AAA-'.repeat(260_000), 'part_number='.repeat(85_000), 'lorem ipsum '.repeat(87_000)]) {
    const started = process.hrtime.bigint();
    const result = detectConfigured({ text: text.slice(0, MAX_TEXT_UNITS), inputRef: 'x', scope: A, config: big });
    assert.ok(['COMPLETE', 'FAILURE'].includes(result.status));
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 3000);
  }
});

test('review: templates whose literals overlap a preceding variable class are rejected; accepted ones stay linear', () => {
  for (const template of ['{9:1-32}1{9:1-32}', '{X:1-8}A{9:2}', '{A:1-4}B', '{a:1-9}x']) {
    assert.throws(() => createCandidateConfig(A, { patterns: [{ template, semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ITEM_ID' }] }),
      TypeError, template);
  }
  const deterministic = createCandidateConfig(A, { patterns: [{ template: '{9:1-32}-{9:1-32}-{9:1-32}-{9:4}-{9:4}-{9:4}-{9:4}',
    semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ITEM_ID' }] });
  const started = process.hrtime.bigint();
  detectConfigured({ text: `${'1-'.repeat(60)}x `.repeat(8000), inputRef: 'x', scope: A, config: deterministic });
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 3000);
});

test('review: pattern spans expand over the whole identifier token, never covering it in part', () => {
  // A different token (`ÅPMP-0042`, `XPMP-0042`) is not a match: patterns start at identifier starts.
  for (const text of ['ÅPMP-0042 x', 'XPMP-0042 x', 'ABCD-12345']) assert.deepEqual(rows(text, run(text)).filter(([, , b]) => b === 'PATTERN'), [], text);
  for (const [text, value] of [['PMP-0042Ä x', 'PMP-0042Ä'], ['PMP-0042́ x', 'PMP-0042́'],
    ['part PN12345.01 x', 'PN12345.01'], ['SYN.FT101.PV.X ok', 'SYN.FT101.PV.X'], ['tag PMP-0042.', 'PMP-0042'],
    ['floc=S01.PMP.001 x', '=S01.PMP.001']]) {
    assert.ok(rows(text, run(text)).some(([, , basis, v]) => basis === 'PATTERN' && v === value), `${text} -> ${value}`);
  }
});

test('review: the generic engineering-key rule reads quoted, full-line, dotted and Swedish keys without prose hits', () => {
  for (const [text, value] of [['plc_tag: %I0.1', '%I0.1'], ['plc_address=%MW100', '%MW100'], ['opc_node: ns=2;s=Line1.Pump.Speed', 'ns=2;s=Line1.Pump.Speed'],
    ['scada_tag: "Line 1 Pump Speed"', 'Line 1 Pump Speed'], ['part_number: ABC+123', 'ABC+123'], ['drawing_no: DWG 1234 A', 'DWG 1234 A'],
    [`part_number: P${'9'.repeat(200)}`, `P${'9'.repeat(200)}`], ['meta.part_number: X-1', 'X-1'], ['artikelnummer: SYN-4711', 'SYN-4711'],
    ['ritningsnummer = R-1002', 'R-1002'], ['funktionsplats: =A1.B2', '=A1.B2']]) {
    const found = run(text, { config: undefined }).candidates.map((c) => text.slice(c.start, c.end));
    assert.ok(found.includes(value), `${text} -> ${JSON.stringify(found)}`);
  }
  for (const text of ['Part: Introduction', 'material: steel', 'article: news']) assert.deepEqual(run(text, { config: undefined }).candidates, [], text);
});

test('review: dictionary folding handles dotted I, sharp s, compatibility forms and invisible characters', () => {
  const config = createCandidateConfig(A, { terms: [{ term: 'İstanbul Synthetic', semanticType: 'CUSTOMER_OR_PARTNER' },
    { term: 'Straße Synthetic', semanticType: 'CUSTOMER_OR_PARTNER' }, { term: 'Northwind Synthetic AB', semanticType: 'CUSTOMER_OR_PARTNER' }] });
  for (const text of ['ISTANBUL SYNTHETIC', 'istanbul synthetic', 'STRASSE SYNTHETIC', 'North​wind Synthetic AB', 'Ｎｏｒｔｈｗｉｎｄ Synthetic AB']) {
    assert.equal(detectConfigured({ text, inputRef: 'x', scope: A, config }).candidates.length, 1, text);
  }
});

test('review: requests read own properties only; bad field paths fail with their own reason', () => {
  Object.prototype.config = configA;
  try {
    assert.deepEqual(detectConfigured({ text: 'Northwind Synthetic AB', inputRef: 'x', scope: A }).candidates, []);
  } finally { delete Object.prototype.config; }
  const revoked = Proxy.revocable([], {});
  revoked.revoke();
  assert.deepEqual(detectConfigured({ text: 'x', inputRef: 'x', scope: A, fieldPath: revoked.proxy }).reasons, ['INVALID_REQUEST']);
  assert.deepEqual(detectConfigured({ text: 'x', inputRef: 'x', scope: A, fieldPath: [1] }).reasons, ['INVALID_FIELD_PATH']);
  assert.equal(detectConfigured({ text: 'x', inputRef: 'x', scope: A, fieldPath: Array.from({ length: 100 }, () => 'a') }).status, 'COMPLETE');
});


test('second review: 64 realistic patterns over adversarial 1 MiB text stay within a bounded-work budget', () => {
  assert.throws(() => createCandidateConfig(A, { patterns: [{ template: '{X:1-32}-{X:1-32}-{X:1-32}-{X:1-32}-{9}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ITEM_ID' }] }), TypeError);
  for (const template of ['{X:32}{X:32}{9}', '{X:1-32}-{X:1-32}-{X:1-32}-{9}', '{X:1-32}-{9:4}']) {
    const config = createCandidateConfig(A, { patterns: Array.from({ length: 64 }, () => ({ template, semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ITEM_ID' })) });
    for (const text of ['A'.repeat(1 << 20), `${'A'.repeat(32)}-`.repeat(31_000)]) {
      const started = process.hrtime.bigint();
      detectConfigured({ text: text.slice(0, MAX_TEXT_UNITS), inputRef: 'x', scope: A, config });
      const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
      assert.ok(elapsedMs < 3000, `${template} ${elapsedMs}ms`);
    }
  }
});

test('second review: expansion stays inside the identifier; keys, URLs and paths are not swallowed', () => {
  for (const [text, value] of [['asset_tag:PMP-0042', 'PMP-0042'], ['https://portal.example.invalid/api/v2/PMP-0042/details', 'PMP-0042'],
    ['C:/data/PMP-0042.csv', 'PMP-0042.csv'], ['x.PMP-0042 y', 'PMP-0042']]) {
    assert.deepEqual(rows(text, run(text)).filter(([, , b]) => b === 'PATTERN').map(([, , , v]) => v), [value], text);
  }
});

test('second review: line-leading generic values stop at comments and the next key; invisible separators do not hide terms', () => {
  const text = 'part_number=PN-1 plc_tag=N7:1';
  assert.deepEqual(run(text, { config: undefined }).candidates.map((c) => [c.subtype, text.slice(c.start, c.end)]),
    [['PART_NUMBER', 'PN-1'], ['PLC_TAG', 'N7:1']]);
  const comment = '- part_number: PN-7 # see drawing_no: D-9';
  assert.deepEqual(run(comment, { config: undefined }).candidates.map((c) => comment.slice(c.start, c.end)), ['PN-7', 'D-9']);
  for (const variant of ['Northwind\u200bSynthetic AB', 'Northwind Synthetic\u2060AB', 'North\u200bwind Synthetic AB']) {
    assert.equal(run(variant).candidates.filter((c) => c.basis === 'DICTIONARY').length, 1, JSON.stringify(variant));
  }
});
