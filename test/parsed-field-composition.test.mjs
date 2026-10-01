import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { createNameDictionary } from '../dist/contact-candidates.js';
import { detectNormalizedCandidates } from '../dist/normalized-detection.js';

// Synthetic only: `.invalid` hosts, documentation hosts and obviously fake values.
const scope = Object.freeze({ tenantRef: 'tenant-a', projectRef: 'project-a' });
const run = (input, rest = {}) => detectNormalizedCandidates({ input, inputRef: 'synthetic-field-case', scope, ...rest });
const b64 = (value) => Buffer.from(value, 'utf8').toString('base64');
const fieldCandidates = (result, source) => result.candidates.filter((item) => item.field && (!source || item.source === source));
const secretFields = (result) => fieldCandidates(result, 'SECRET').filter((item) => item.subtype === 'PASSWORD');
const keyHints = (result, source) => fieldCandidates(result, source).filter((item) => item.rule === 'context.field-key');
const reasonSet = (result) => new Set(result.reasons);
const opaqueReasons = (result) => result.uninspected.map((item) => item.reason);
const spans = (list) => list.map((item) => `${item.original.span.start}-${item.original.span.end}`);
const covers = (result, length) => result.uninspected.some((item) => item.viewSpan.start === 0 && item.viewSpan.end === length);

test('a verbatim credential field keeps an exact original span and its trusted key hint', () => {
  const input = '{"apiKey":"synthetic-key.invalid","region":"eu"}';
  const result = run(input);
  assert.equal(result.status, 'COMPLETE');
  const hinted = keyHints(result, 'SECRET');
  assert.equal(hinted.length, 1);
  const [candidate] = hinted;
  assert.equal(candidate.subtype, 'API_KEY');
  assert.equal(candidate.field.verbatim, true);
  assert.equal(candidate.field.format, 'JSON');
  assert.equal(candidate.field.hintDepth, 0);
  assert.equal(candidate.field.highRisk, true);
  assert.equal(input.slice(candidate.original.span.start, candidate.original.span.end), 'synthetic-key.invalid');
  assert.equal(candidate.original.kind, 'ORIGINAL_EXACT');
  assert.equal(candidate.field.span.start, candidate.view.span.start);
  assert.equal(candidate.evidence.provenance.producerId, 'hylja.secret-detectors');
  assert.equal(candidate.field.hintSource, 'PATH');
  // The innocuous sibling is neither hinted nor reported as uninspected anywhere.
  assert.deepEqual([...new Set(fieldCandidates(result).map((item) => item.field.hintSource))], ['PATH']);
  assert.deepEqual(opaqueReasons(result), []);
});

test('a name/key sibling supplies the trusted key hint when no key segment is credential-like', () => {
  for (const [input, rest] of [
    ['{"name":"DB_PASSWORD","value":"synthetic-pass.invalid"}', {}],
    ['{"NAME":"DB_PASSWORD","VALUE":"synthetic-pass.invalid"}', {}],
    ['name: DB_PASSWORD\nvalue: synthetic-pass.invalid\n', { formats: ['YAML'] }],
    ['<entry><name>DB_PASSWORD</name><value>synthetic-pass.invalid</value></entry>', {}],
  ]) {
    const result = run(input, rest);
    const hinted = secretFields(result).filter((item) => item.rule === 'context.field-key');
    assert.equal(hinted.length, 1, input);
    const [candidate] = hinted;
    assert.equal(candidate.subtype, 'PASSWORD');
    assert.equal(candidate.field.hintSource, 'NAME_SIBLING');
    assert.equal(candidate.field.hintDepth, -1);
    assert.equal(candidate.field.highRisk, true);
    assert.equal(input.slice(candidate.original.span.start, candidate.original.span.end), 'synthetic-pass.invalid');
  }
  // A sibling that does not name a credential never becomes a hint.
  const plain = run('{"name":"DB_USER","value":"synthetic-value.invalid"}');
  assert.deepEqual(secretFields(plain), []);
  assert.deepEqual(fieldCandidates(plain).map((item) => item.field.hintSource), []);
});

test('an escaped field value is scanned as a covering span and never as an exact one', () => {
  const input = '{"password":"syn\\u0074hetic-pass.invalid"}';
  const result = run(input);
  assert.equal(result.status, 'COMPLETE');
  const hinted = secretFields(result).filter((item) => item.rule === 'context.field-key');
  assert.equal(hinted.length, 1);
  const [candidate] = hinted;
  assert.equal(candidate.field.verbatim, false);
  assert.equal(candidate.original.kind, 'ORIGINAL_COVER');
  assert.equal(input.slice(candidate.original.span.start, candidate.original.span.end), 'syn\\u0074hetic-pass.invalid');
  assert.equal(candidate.original.span.start, candidate.field.span.start);
  assert.equal(candidate.original.span.end, candidate.field.span.end);
  assert.equal(candidate.field.valueSpan.start, 0);
  assert.equal(candidate.field.valueSpan.end, 'synthetic-pass.invalid'.length);
  assert.equal(JSON.stringify(result).includes('synthetic-pass.invalid'), false);
  for (const item of fieldCandidates(result)) {
    if (!item.field.verbatim) assert.notEqual(item.original.kind, 'ORIGINAL_EXACT');
  }
});

test('key names are never emitted as metadata, only a privacy-safe path digest', () => {
  const input = '{"customer_synthetic@example.com":{"apiKey":"synthetic-key.invalid"}}';
  const hinted = keyHints(run(input), 'SECRET');
  assert.equal(hinted.length, 1);
  assert.match(hinted[0].field.pathRef, /^[0-9a-f]{16}$/u);
  assert.equal(hinted[0].field.hintDepth, 1);
  assert.equal(JSON.stringify(input && run(input)).includes('customer_synthetic@example.com'), false);
  const other = keyHints(run('{"tenant":{"apiKey":"synthetic-key.invalid"}}'), 'SECRET');
  assert.notEqual(other[0].field.pathRef, hinted[0].field.pathRef);
});

test('an inherited credential ancestor still hints the nested field value', () => {
  const result = run('{"credentials":{"note":"synthetic-pass.invalid"}}');
  const hinted = secretFields(result).filter((item) => item.rule === 'context.field-key');
  assert.equal(hinted.length, 1);
  assert.equal(hinted[0].field.hintDepth, 0);
  assert.equal(hinted[0].field.highRisk, true);
  assert.equal(result.status, 'COMPLETE');
});

test('a key that only describes a credential produces no field candidate', () => {
  const result = run('{"password_policy":"rotate-90-days"}');
  assert.equal(result.status, 'COMPLETE');
  assert.deepEqual(fieldCandidates(result), []);
  assert.equal(result.candidates.some((item) => item.source === 'SECRET'), false);
});

test('malformed structured input stays PARTIAL with a whole-input opaque location', () => {
  const input = '{"password":"syn\\u0074hetic-pass.invalid"';
  const result = run(input, { formats: ['JSON'] });
  assert.equal(result.status, 'PARTIAL');
  assert.ok(reasonSet(result).has('PARSER_JSON_FAILURE'));
  const opaque = result.uninspected.filter((item) => String(item.reason).startsWith('PARSER_JSON_'));
  assert.ok(opaque.length >= 1);
  assert.equal(opaque[0].viewSpan.start, 0);
  assert.equal(opaque[0].viewSpan.end, input.length);
  assert.equal(opaque[0].original.kind, 'ORIGINAL_EXACT');
  assert.equal(fieldCandidates(result).length, 0);
  assert.equal(JSON.stringify(result).includes('synthetic-pass.invalid'), false);
});

test('unsupported XML markup keeps the parser state and the candidates text scanning did find', () => {
  const input = '<root><password><![CDATA[synthetic-pass.invalid]]></password></root>';
  const result = run(input);
  assert.equal(result.status, 'PARTIAL');
  assert.ok(reasonSet(result).has('PARSER_XML_UNSUPPORTED'));
  assert.ok(opaqueReasons(result).some((reason) => String(reason).startsWith('PARSER_XML_')));
  assert.equal(covers(result, input.length), true);
  assert.equal(result.candidates.some((item) => item.source === 'SECRET' && item.subtype === 'PASSWORD'), true);
  assert.equal(fieldCandidates(result).length, 0);
});

test('an opaque dotenv line is reported at its own range while parsed fields are still scanned', () => {
  const input = ['API_TOKEN="synthetic-token.invalid"', 'DB_HOST=db.example.invalid', 'DEBUG=1', 'REGION=eu',
    'not an assignment'].join('\n');
  const result = run(input);
  assert.equal(result.status, 'PARTIAL');
  const opaque = result.uninspected.find((item) => item.reason === 'PARSER_DOTENV_UNRECOGNIZED_LINE');
  assert.ok(opaque);
  assert.equal(input.slice(opaque.viewSpan.start, opaque.viewSpan.end), 'not an assignment');
  const hinted = keyHints(result, 'SECRET');
  assert.equal(hinted.length, 1);
  assert.equal(hinted[0].subtype, 'ACCESS_TOKEN');
  assert.equal(hinted[0].field.highRisk, true);
});

test('repeated identical credential fields each keep their own evidence and span', () => {
  const input = '{"a":{"password":"synthetic-pass.invalid"},"b":{"password":"synthetic-pass.invalid"}}';
  const result = run(input);
  const hinted = secretFields(result).filter((item) => item.rule === 'context.field-key');
  assert.equal(hinted.length, 2);
  assert.equal(new Set(spans(hinted)).size, 2);
  assert.equal(new Set(hinted.map((item) => item.evidence.id)).size, 2);
  assert.equal(new Set(hinted.map((item) => item.evidence.provenance.inputRef)).size, 2);
  assert.equal(new Set(hinted.map((item) => item.field.pathRef)).size, 2);
  assert.equal(hinted.every((item) => input.slice(item.original.span.start, item.original.span.end) === 'synthetic-pass.invalid'), true);
});

test('overlapping credential and format evidence inside one field is both retained', () => {
  const jwt = ['eyJ' + 'A'.repeat(20), 'eyJ' + 'B'.repeat(20), 'C'.repeat(20)].join('.');
  const input = JSON.stringify({ token: `rotated ${jwt} today` });
  const result = run(input);
  assert.equal(result.status, 'COMPLETE');
  const secrets = fieldCandidates(result, 'SECRET');
  const rules = new Set(secrets.map((item) => item.rule));
  assert.ok(rules.has('context.field-key'));
  assert.ok(rules.has('format.jwt'));
  const [format] = secrets.filter((item) => item.rule === 'format.jwt');
  const hint = secrets.find((item) => item.rule === 'context.field-key');
  // The structural credential candidate covers the format match instead of replacing it.
  assert.ok(format.field.valueSpan.start > hint.field.valueSpan.start);
  assert.ok(format.field.valueSpan.end < hint.field.valueSpan.end);
});

test('parsed fields of a decoded view keep only the encoded envelope as original location', () => {
  const document = '{"password":"syn\\u0074hetic-pass.invalid"}';
  const encoded = b64(document);
  const input = `payload=${encoded}`;
  const result = run(input);
  assert.equal(result.status, 'COMPLETE');
  const hinted = secretFields(result).filter((item) => item.rule === 'context.field-key');
  assert.equal(hinted.length, 1);
  assert.deepEqual([...hinted[0].view.encodingPath], ['BASE64']);
  assert.equal(hinted[0].original.kind, 'ENCODED_RUNS');
  assert.deepEqual(hinted[0].original.spans.map((span) => input.slice(span.start, span.end)), [encoded]);
  assert.equal(hinted[0].field.verbatim, false);
  assert.equal(JSON.stringify(result).includes(document), false);
});

test('byte input reports UTF-8 text coverage, exactly only where the field is verbatim', () => {
  const exact = run(new TextEncoder().encode('{"apiKey":"synthetic-key.invalid"}'));
  const exactHint = keyHints(exact, 'SECRET')[0];
  assert.equal(exactHint.original.kind, 'UTF8_TEXT');
  assert.equal(exactHint.original.coverage, 'EXACT');
  assert.equal(exactHint.field.verbatim, true);

  const cover = run(new TextEncoder().encode('{"password":"syn\\u0074hetic-pass.invalid"}'));
  const coverHint = secretFields(cover).filter((item) => item.rule === 'context.field-key')[0];
  assert.equal(coverHint.original.kind, 'UTF8_TEXT');
  assert.equal(coverHint.original.coverage, 'COVER');
  assert.equal(coverHint.field.verbatim, false);
});

test('trusted format hints reach the fields that content sniffing cannot see', () => {
  const yaml = 'database:\n  password: synthetic-pass.invalid\n';
  const yamlResult = run(yaml, { formats: ['YAML'] });
  assert.equal(yamlResult.status, 'COMPLETE');
  const yamlHint = secretFields(yamlResult).filter((item) => item.rule === 'context.field-key')[0];
  assert.equal(yamlHint.field.format, 'YAML');
  assert.equal(yamlHint.field.hintDepth, 1);
  assert.equal(yaml.slice(yamlHint.original.span.start, yamlHint.original.span.end), 'synthetic-pass.invalid');

  const toml = '[db]\npassword = "syn\\u0074hetic-pass.invalid"\n';
  const tomlResult = run(toml, { formats: ['TOML'] });
  assert.equal(tomlResult.status, 'COMPLETE');
  const tomlHint = secretFields(tomlResult).filter((item) => item.rule === 'context.field-key')[0];
  assert.equal(tomlHint.field.format, 'TOML');
  assert.equal(tomlHint.field.verbatim, false);
  assert.equal(tomlHint.original.kind, 'ORIGINAL_COVER');

  const connection = 'Server=db.example.invalid;Password=synthetic-pass.invalid;Uid=synthetic-user';
  const connectionResult = run(connection, { formats: ['CONNECTION_STRING'] });
  const connectionHint = secretFields(connectionResult).filter((item) => item.rule === 'context.field-key')[0];
  assert.equal(connectionHint.field.format, 'CONNECTION_STRING');
  assert.equal(connectionHint.field.verbatim, true);
  assert.equal(connectionResult.status, 'COMPLETE');

  const url = 'postgres://svc:synthetic%2Dpass%40invalid@db.example.invalid:5432/app';
  const urlResult = run(url, { formats: ['URL'] });
  const userinfo = secretFields(urlResult).filter((item) => item.rule === 'context.field-key')[0];
  assert.equal(userinfo.field.hintDepth, 1);
  assert.equal(userinfo.field.verbatim, false);
  assert.equal(userinfo.original.kind, 'ORIGINAL_COVER');
  // Percent-decoding also produced a decoded view that no longer parses as one URL: that gap stays visible.
  assert.equal(urlResult.status, 'PARTIAL');
  assert.ok([...reasonSet(urlResult)].some((reason) => reason.startsWith('PARSER_URL_')));
});

test('a requested format that does not hold is conservative and an invalid hint fails closed', () => {
  const input = '{"password":"synthetic-pass.invalid"}';
  const mismatched = run(input, { formats: ['YAML'] });
  assert.equal(mismatched.status, 'PARTIAL');
  assert.ok(reasonSet(mismatched).has('PARSER_YAML_UNSUPPORTED'));
  assert.equal(covers(mismatched, input.length), true);

  for (const formats of [['NOPE'], [], ['JSON', 'JSON', 'JSON', 'JSON'], 'JSON', [7], [null]]) {
    const invalid = run(input, { formats });
    assert.equal(invalid.status, 'FAILURE', JSON.stringify(formats));
    assert.deepEqual(invalid.reasons, ['INVALID_FORMATS']);
    assert.deepEqual(invalid.candidates, []);
  }
});

test('two requested formats over the same text do not duplicate identical evidence', () => {
  const input = '{"password":"synthetic-pass.invalid"}';
  const single = run(input, { formats: ['JSON'] });
  const both = run(input, { formats: ['JSON', 'INI'] });
  assert.equal(single.status, 'COMPLETE');
  assert.ok(reasonSet(both).has('PARSER_INI_PARTIAL'));
  assert.equal(both.candidates.length, single.candidates.length);
});

test('configured name evidence stays tenant and project scoped at view and field level', () => {
  const names = createNameDictionary(scope, ['Synthetic Visitor']);
  // The escaped field only yields a name candidate when the parsed value is scanned, so this proves the
  // field-level #37 pass runs with the request's own scope rather than a wider one.
  const input = '{"owner":"Synthetic Visitor","note":"Synthetic\\u0020Visitor"}';
  const matched = run(input, { names });
  const names0 = matched.candidates.filter((item) => item.source === 'CONTACT' && item.subtype === 'NAME');
  assert.equal(names0.filter((item) => item.field).length, 1);
  assert.equal(names0.filter((item) => !item.field).length, 1);
  const [attributed] = names0.filter((item) => item.field);
  assert.equal(attributed.field.format, 'JSON');
  assert.equal(attributed.field.verbatim, false);
  assert.equal(attributed.original.kind, 'ORIGINAL_COVER');
  assert.equal(matched.status, 'COMPLETE');

  for (const wrong of [{ tenantRef: 'tenant-b', projectRef: 'project-a' }, { tenantRef: 'tenant-a', projectRef: 'project-b' }]) {
    const crossed = run(input, { names, scope: wrong });
    assert.equal(crossed.status, 'PARTIAL');
    assert.ok(reasonSet(crossed).has('CONTACT_NAME_DICTIONARY_SCOPE_MISMATCH'));
    assert.equal(crossed.candidates.some((item) => item.subtype === 'NAME'), false);
  }
  const forged = run(input, { names: {} });
  assert.equal(forged.status, 'PARTIAL');
  assert.ok(reasonSet(forged).has('CONTACT_INVALID_NAME_DICTIONARY'));
  assert.equal(forged.candidates.some((item) => item.subtype === 'NAME'), false);
});

test('the field-scan budget stays PARTIAL instead of reporting a partial scan as complete', () => {
  const input = JSON.stringify(Object.fromEntries(Array.from({ length: 1100 },
    (_, index) => [`k${index}`, { token: `synthetic-t${index}.invalid` }])));
  const result = run(input);
  assert.equal(result.status, 'PARTIAL');
  assert.ok(reasonSet(result).has('PARSED_FIELD_SCAN_LIMIT'));
  assert.ok(opaqueReasons(result).includes('PARSED_FIELD_SCAN_LIMIT'));
  assert.ok(reasonSet(result).has('SECRET_CANDIDATE_LIMIT'));
  assert.ok(fieldCandidates(result).length <= 256);
  const limit = result.uninspected.find((item) => item.reason === 'PARSED_FIELD_SCAN_LIMIT');
  // Everything from the first unscanned field onwards stays opaque rather than silently uninspected.
  assert.equal(limit.viewSpan.end, input.length);
  assert.ok(input.slice(limit.viewSpan.start, limit.viewSpan.end).includes('synthetic-t1024.invalid'));
  assert.equal(input.slice(0, limit.viewSpan.start).includes('synthetic-t1023.invalid'), true);
});

test('a parser budget failure stays visible instead of looking like a document without fields', () => {
  const input = `${'['.repeat(100)}1${']'.repeat(100)}`;
  const result = run(input, { formats: ['JSON'] });
  assert.equal(result.status, 'PARTIAL');
  assert.ok(reasonSet(result).has('PARSER_JSON_FAILURE'));
  assert.ok(opaqueReasons(result).includes('PARSER_JSON_DEPTH_LIMIT'));
  assert.equal(fieldCandidates(result).length, 0);
});

test('property: escaped, re-escaped and non-ASCII field spellings keep honest span provenance', () => {
  const spellings = [
    (value) => JSON.stringify(value),
    (value) => JSON.stringify(value).replace(/a/gu, '\\u0061'),
    (value) => JSON.stringify(value).replace(/s/gu, '\\u0073'),
    (value) => `"${value.replace(/\\/gu, '\\\\\\\\').replace(/"/gu, '\\"')}"`,
    (value) => JSON.stringify(`${value}\\tail`),
    (value) => JSON.stringify(`é${value}́`),
  ];
  for (let index = 0; index < 60; index++) {
    const value = `synthetic-pass-${index}.invalid`;
    const input = `{"password":${spellings[index % spellings.length](value)}}`;
    assert.ok(JSON.parse(input).password.includes('synthetic-pass-'), input);
    const result = run(input);
    assert.equal(result.status, 'COMPLETE', `${index} ${input}`);
    const hinted = secretFields(result).filter((item) => item.rule === 'context.field-key');
    assert.equal(hinted.length, 1, `${index} ${input}`);
    const [candidate] = hinted;
    assert.equal(candidate.field.format, 'JSON');
    if (candidate.field.verbatim) {
      assert.equal(input.slice(candidate.original.span.start, candidate.original.span.end),
        JSON.parse(input).password);
    } else assert.notEqual(candidate.original.kind, 'ORIGINAL_EXACT');
    assert.equal(JSON.stringify(result).includes(value), false, `${index}`);
  }
});

test('property: tenant scope variations keep configured name evidence inside its own scope', () => {
  const scopes = [
    { tenantRef: 'tenant-a', projectRef: 'project-a' }, { tenantRef: 'tenant-a', projectRef: 'project-b' },
    { tenantRef: 'tenant-b', projectRef: 'project-a' }, { tenantRef: 'tenant-b', projectRef: 'project-b' },
  ];
  const names = createNameDictionary(scopes[0], ['Synthetic Visitor']);
  const isOwn = (candidate) => candidate.tenantRef === 'tenant-a' && candidate.projectRef === 'project-a';
  for (let index = 0; index < 40; index++) {
    const own = scopes[index % scopes.length];
    const other = scopes[(index + 1) % scopes.length];
    const input = `{"owner":"Synthetic Visitor","password":"syn\\u0074hetic-pass-${index}.invalid"}`;
    // A rotated scope is sometimes the dictionary's own scope; that one must still match.
    const crossed = run(input, { names, scope: other });
    assert.equal(crossed.candidates.some((item) => item.subtype === 'NAME'), isOwn(other), String(index));
    if (isOwn(other)) assert.equal(reasonSet(crossed).has('CONTACT_NAME_DICTIONARY_SCOPE_MISMATCH'), false);
    else assert.ok(reasonSet(crossed).has('CONTACT_NAME_DICTIONARY_SCOPE_MISMATCH'));
    const matched = run(input, { names, scope: own });
    assert.equal(matched.candidates.some((item) => item.subtype === 'NAME'), isOwn(own), String(index));
    if (!isOwn(own)) assert.ok(reasonSet(matched).has('CONTACT_NAME_DICTIONARY_SCOPE_MISMATCH'));
    assert.equal(JSON.stringify(matched).includes('Synthetic Visitor'), false);
  }
});

test('field path digests are bound to one request and never reveal a key name', () => {
  const input = '{"tenant":{"apiKey":"synthetic-key.invalid"},"tenant":{"apiKey":"synthetic-key.invalid"}}';
  const first = detectNormalizedCandidates({ input, inputRef: 'synthetic-ref-a', scope });
  const second = detectNormalizedCandidates({ input, inputRef: 'synthetic-ref-b', scope });
  const refsOf = (result) => fieldCandidates(result, 'SECRET').map((item) => item.field.pathRef);
  assert.equal(refsOf(first).length, 2);
  assert.equal(new Set(refsOf(first)).size, 1);
  assert.equal(new Set(refsOf(second)).size, 1);
  // Two requests over the same document produce unrelated digests, so structure cannot be correlated.
  assert.equal(refsOf(first)[0] === refsOf(second)[0], false);
  assert.equal(JSON.stringify(first).includes('tenant'), false);
});

test('a lying formats proxy cannot grow the format list or change it between reads', () => {
  const input = '{"password":"synthetic-pass.invalid"}';
  const invariantBreaker = new Proxy(['JSON'], {
    getOwnPropertyDescriptor: () => ({ value: 3, writable: true, enumerable: false, configurable: true }),
  });
  const broken = run(input, { formats: invariantBreaker });
  assert.equal(broken.status, 'FAILURE');
  assert.deepEqual(broken.reasons, ['INVALID_FORMATS']);

  let reads = 0;
  const real = ['JSON'];
  const hostile = new Proxy(real, {
    get(target, property, receiver) {
      if (property === Symbol.iterator) return function* iterator() { yield 'JSON'; yield 'YAML'; yield 'XML'; };
      return Reflect.get(target, property, receiver);
    },
    getOwnPropertyDescriptor(target, property) {
      const described = Reflect.getOwnPropertyDescriptor(target, property);
      if (property !== '0' || !described) return described;
      reads += 1;
      return { ...described, value: reads === 1 ? 'JSON' : 'YAML' };
    },
  });
  const result = run(input, { formats: hostile });
  // Each index is read once from its descriptor and validated there; the lying iterator is never consulted.
  assert.equal(reads, 1);
  assert.equal(result.status, 'COMPLETE');
  assert.deepEqual([...reasonSet(result)].filter((reason) => reason.startsWith('PARSER_')), []);
  assert.equal(keyHints(result, 'SECRET').length, 1);
});

test('an empty field value is skipped and a field with no recognizable key keeps no hint', () => {
  const empty = run('{"password":"","token":"","region":"eu"}');
  assert.equal(empty.status, 'COMPLETE');
  assert.deepEqual(fieldCandidates(empty), []);
  assert.equal(empty.candidates.some((item) => item.source === 'SECRET'), false);

  // #7 flags a non-ASCII key as credential-like, but #8 has no subtype for it: the field is still scanned
  // and reported with no hint rather than being given an invented credential key.
  const jwt = ['eyJ' + 'A'.repeat(20), 'eyJ' + 'B'.repeat(20), 'C'.repeat(20)].join('.');
  const input = `{"пароль":"prefix\\u0020${jwt}"}`;
  const result = run(input);
  assert.equal(result.status, 'COMPLETE');
  const secrets = fieldCandidates(result, 'SECRET');
  assert.deepEqual([...new Set(secrets.map((item) => item.field.hintSource))], ['NONE']);
  assert.equal(secrets.some((item) => item.rule === 'context.field-key'), false);
  assert.equal(secrets[0].field.highRisk, true);
  assert.equal(secrets[0].field.verbatim, false);
  assert.equal(secrets[0].original.kind, 'ORIGINAL_COVER');
});

test('no result carries an effect and no failure path echoes planted content', () => {
  const planted = 'syn\\u0074hetic-pass.invalid';
  const hostile = {
    input: `{"password":"${planted}"`,
    inputRef: 'synthetic-throwing-case',
    get scope() { throw new Error(`threw ${planted}`); },
  };
  const thrown = detectNormalizedCandidates(hostile);
  assert.equal(thrown.status, 'FAILURE');
  assert.deepEqual(thrown.reasons, ['INVALID_REQUEST']);
  assert.equal(JSON.stringify(thrown).includes('threw'), false);

  for (const [input, rest] of [
    [`{"password":"${planted}"`, { formats: ['JSON'] }],
    [`payload=${b64(`{"password":"${planted}"`)}`, {}],
    [`{"password":"${planted}"}`, { formats: ['YAML'] }],
  ]) {
    const result = run(input, rest);
    assert.equal(JSON.stringify(result).includes(planted), false);
    assert.doesNotMatch(JSON.stringify(result), /allow|release|clean|permit|deny|blocked|decision|effect/iu);
    assert.deepEqual(Object.keys(result).sort(), ['candidates', 'contentType', 'reasons', 'status', 'uninspected']);
  }
});

test('a request that throws while being read never reaches a result value', () => {
  const planted = 'syn\\u0074hetic-pass.invalid';
  const request = Object.defineProperty({ inputRef: 'synthetic-getter-case', scope, formats: ['JSON'] }, 'input', {
    enumerable: true,
    get() { throw new Error(`boom ${planted}`); },
  });
  const result = detectNormalizedCandidates(request);
  assert.equal(result.status, 'FAILURE');
  assert.deepEqual(result.reasons, ['INVALID_REQUEST']);
  assert.equal(JSON.stringify(result).includes('boom'), false);
});

test('field-only log coverage stays COMPLETE because the whole view text was still scanned', () => {
  const input = '2026-01-01T00:00:00Z INFO password=synthetic-pass.invalid';
  const result = run(input, { formats: ['LOG'] });
  assert.equal(result.status, 'COMPLETE');
  assert.deepEqual(opaqueReasons(result), []);
  assert.equal(keyHints(result, 'SECRET').length, 1);
});

test('text without structure produces no field candidates and no parser state', () => {
  const result = run('just a sentence with synthetic@example.com and build.tenant-a.invalid:443');
  assert.equal(result.status, 'COMPLETE');
  assert.deepEqual(fieldCandidates(result), []);
  assert.deepEqual(opaqueReasons(result), []);
  assert.equal(result.candidates.some((item) => item.source === 'CONTACT' && item.subtype === 'EMAIL'), true);
});

test('a view above the detector unit cap stays opaque instead of being parsed', () => {
  const input = `{"password":"${'a'.repeat(1 << 20)}"}`;
  const result = run(input, { budget: { maxInputUnits: 2 << 20 } });
  assert.equal(result.status, 'PARTIAL');
  assert.ok(reasonSet(result).has('VIEW_TOO_LARGE'));
  assert.equal(fieldCandidates(result).length, 0);
});

test('a large parsed input stays bounded, capped and explicitly opaque', () => {
  const input = Array.from({ length: 4000 },
    (_, index) => `2026-01-01T00:00:00Z INFO password=synthetic-pass-${index}.invalid`).join('\n');
  const result = run(input, { formats: ['LOG'] });
  assert.equal(result.status, 'PARTIAL');
  assert.ok(reasonSet(result).has('PARSED_FIELD_SCAN_LIMIT'));
  assert.ok(reasonSet(result).has('SECRET_CANDIDATE_LIMIT'));
  assert.equal(keyHints(result, 'SECRET').length, 256);
  assert.ok(result.candidates.length <= 3 * 256);
  assert.ok(result.uninspected.length <= 1024);
});

test('field composition stays bounded in time and memory on a large structured input', () => {
  const script = `
    import { detectNormalizedCandidates } from './dist/normalized-detection.js';
    const line = '2026-01-01T00:00:00Z INFO password=synthetic-pass.invalid';
    const result = detectNormalizedCandidates({
      input: Array.from({ length: 4000 }, () => line).join('\\n'), inputRef: 'synthetic-bounded-fields',
      scope: { tenantRef: 'tenant-a', projectRef: 'project-a' }, formats: ['LOG'],
    });
    process.stdout.write(JSON.stringify({ status: result.status, candidates: result.candidates.length,
      fields: result.candidates.filter((item) => item.field).length, opaque: result.uninspected.length }));
  `;
  const child = spawnSync(process.execPath, ['--max-old-space-size=256', '--input-type=module', '-e', script],
    { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 });
  assert.equal(child.status, 0, `child exit ${child.status}, signal ${child.signal}`);
  const result = JSON.parse(child.stdout);
  assert.equal(result.status, 'PARTIAL');
  assert.ok(result.fields <= 256);
  assert.ok(result.opaque > 0);
});