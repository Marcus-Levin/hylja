import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  parseStructured, rewriteFieldValues, isCredentialKey, DEFAULT_PARSE_BUDGET,
} from '../dist/structured-parsers.js';

// Synthetic only: .invalid/example hosts and obviously fake values.
const view = (text, result) => result.fields.map((f) => [f.path.join('.'), f.value, f.highRisk]);
const sourceOf = (text, field) => text.slice(field.valueStart, field.valueEnd);
const fake = 'synthetic-value.invalid';

test('JSON: key paths, decoded values, exact source spans and credential keys', () => {
  const text = '{"server":"plc-gateway.example.invalid","port":443,"apiKey":"syn\\u0074hetic","list":[true,{"client_secret":"x"}]}';
  const result = parseStructured(text, 'JSON');
  assert.equal(result.status, 'COMPLETE');
  assert.deepEqual(view(text, result), [
    ['server', 'plc-gateway.example.invalid', false], ['port', '443', false], ['apiKey', 'synthetic', true],
    ['list.0', 'true', false], ['list.1.client_secret', 'x', true],
  ]);
  const key = result.fields[2];
  assert.equal(sourceOf(text, key), 'syn\\u0074hetic');
  assert.equal(text.slice(key.keyStart, key.keyEnd), 'apiKey');
});

test('JSON: malformed input is a whole-input FAILURE, never a partial success', () => {
  for (const text of ['{"a":', '{"a":1,}', '{"a" 1}', '[1 2]', '{"a":"\u0001"}', '{"a":"\\x"}', '{"a":1} trailing', '']) {
    const result = parseStructured(text, 'JSON');
    assert.equal(result.status, 'FAILURE', text);
    assert.deepEqual(result.fields, []);
    if (text) assert.deepEqual(result.opaque.map((r) => [r.start, r.end]), [[0, text.length]]);
  }
});

test('JSON: duplicate keys surface every value; depth and field budgets fail closed', () => {
  const dup = parseStructured('{"token":"a","token":"b"}', 'JSON');
  assert.deepEqual(dup.fields.map((f) => f.value), ['a', 'b']);
  assert.ok(dup.reasons.includes('DUPLICATE_KEY'));
  const deep = parseStructured(`${'['.repeat(100)}1${']'.repeat(100)}`, 'JSON');
  assert.deepEqual([deep.status, deep.reasons], ['FAILURE', ['DEPTH_LIMIT']]);
  const wide = parseStructured(JSON.stringify(Array.from({ length: 50 }, (_, i) => i)), 'JSON', { maxFields: 10 });
  assert.deepEqual([wide.status, wide.reasons], ['FAILURE', ['FIELD_LIMIT']]);
  const veryDeep = parseStructured(`${'['.repeat(100_000)}${']'.repeat(100_000)}`, 'JSON');
  assert.equal(veryDeep.status, 'FAILURE');
});

test('dotenv/shell: export, quoting, comments; unrecognized lines stay opaque (PARTIAL)', () => {
  const text = '# config\nexport API_TOKEN="syn\\"thetic" # note\nDEBUG=1\nPASSWORD=\'a b\'\nnot an assignment\nURL=https://api.example.com/x#frag';
  const result = parseStructured(text, 'DOTENV');
  assert.equal(result.status, 'PARTIAL');
  assert.deepEqual(view(text, result), [
    ['API_TOKEN', 'syn"thetic', true], ['DEBUG', '1', false], ['PASSWORD', 'a b', true],
    ['URL', 'https://api.example.com/x#frag', false],
  ]);
  const [opaque] = result.opaque;
  assert.equal(text.slice(opaque.start, opaque.end), 'not an assignment');
  // An unterminated quote hides nothing: the line is opaque.
  const open = parseStructured('SECRET="unterminated', 'DOTENV');
  assert.equal(open.status, 'PARTIAL');
  assert.deepEqual(open.fields, []);
});

test('INI: sections become path prefixes; both = and : separators', () => {
  const text = '[database.primary]\nhost = db.example.invalid\npassword: synthetic ; comment\n[app]\nname=demo';
  const result = parseStructured(text, 'INI');
  assert.equal(result.status, 'COMPLETE');
  assert.deepEqual(view(text, result), [
    ['database.primary.host', 'db.example.invalid', false], ['database.primary.password', 'synthetic', true],
    ['app.name', 'demo', false],
  ]);
});

test('URL: userinfo password, host, port, path, query and fragment with percent-decoding', () => {
  const text = 'postgres://svc:p%40ss@db.example.invalid:5432/app?sslmode=require&access_token=a+b#frag';
  const result = parseStructured(text, 'URL');
  assert.equal(result.status, 'COMPLETE');
  assert.deepEqual(view(text, result), [
    ['scheme', 'postgres', false], ['userinfo.username', 'svc', false], ['userinfo.password', 'p@ss', true],
    ['host', 'db.example.invalid', false], ['port', '5432', false], ['path', '/app', false],
    ['query.sslmode', 'require', false], ['query.access_token', 'a b', true], ['fragment', 'frag', false],
  ]);
  const password = result.fields.find((f) => f.path.join('.') === 'userinfo.password');
  assert.equal(sourceOf(text, password), 'p%40ss');
  for (const bad of ['not a url', 'https://h.example/%zz', 'https://h.example/%ff', 'https://h.example:99999999/']) {
    assert.equal(parseStructured(bad, 'URL').status, 'FAILURE', bad);
  }
});

test('connection strings: key=value with quoted, doubled-quote and braced values; URI form', () => {
  const text = 'Server=db.example.invalid;Database=app;User Id=svc;Password="a;b""c";Pwd={x}}y};';
  const result = parseStructured(text, 'CONNECTION_STRING');
  assert.equal(result.status, 'COMPLETE');
  assert.deepEqual(view(text, result), [
    ['Server', 'db.example.invalid', false], ['Database', 'app', false], ['User Id', 'svc', false],
    ['Password', 'a;b"c', true], ['Pwd', 'x}y', true],
  ]);
  const uri = parseStructured('  mongodb://u:synthetic@db.example.invalid/app', 'CONNECTION_STRING');
  const password = uri.fields.find((f) => f.path.join('.') === 'userinfo.password');
  assert.equal(sourceOf('  mongodb://u:synthetic@db.example.invalid/app', password), 'synthetic');
  for (const bad of ['Password="open', 'novalue', '=x', 'A="b"c']) {
    assert.equal(parseStructured(bad, 'CONNECTION_STRING').status, 'FAILURE', bad);
  }
});

test('logs: header lines and key=value tokens are fields-only coverage', () => {
  const text = '2026-09-26T10:00:00Z INFO user=synthetic-user token="t k" status=200\nAuthorization: Bearer synthetic.invalid\nCookie: sid=synthetic';
  const result = parseStructured(text, 'LOG');
  assert.equal(result.status, 'COMPLETE');
  assert.equal(result.coverage, 'FIELDS_ONLY');
  assert.deepEqual(view(text, result), [
    ['0.user', 'synthetic-user', false], ['0.token', 't k', true], ['0.status', '200', false],
    ['1.Authorization', 'Bearer synthetic.invalid', true], ['2.Cookie', 'sid=synthetic', true],
    ['2.sid', 'synthetic', true],
  ]);
});

test('YAML, TOML and XML are UNSUPPORTED and wholly opaque; bad input fails closed', () => {
  for (const format of ['YAML', 'TOML', 'XML']) {
    const result = parseStructured('password: synthetic', format);
    assert.equal(result.status, 'UNSUPPORTED');
    assert.deepEqual(result.opaque.map((r) => [r.start, r.end]), [[0, 19]]);
  }
  for (const [text, format, budget, reason] of [
    ['x', 'CSV', undefined, 'INVALID_FORMAT'], [7, 'JSON', undefined, 'INVALID_INPUT'],
    ['x'.repeat(DEFAULT_PARSE_BUDGET.maxInputUnits + 1), 'JSON', undefined, 'INPUT_TOO_LARGE'],
    ['"\uD800"', 'JSON', undefined, 'INVALID_TEXT'], ['1', 'JSON', { maxDepth: 1e6 }, 'INVALID_BUDGET'],
    ['1', 'JSON', { other: 1 }, 'INVALID_BUDGET'],
  ]) assert.deepEqual(parseStructured(text, format, budget).reasons, [reason], reason);
});

test('credential key recognition normalizes case and separators without catching near-misses', () => {
  for (const key of ['password', 'DB_PASSWORD', 'apiKey', 'x-api-key', 'Client Secret', 'access_token', 'AUTH',
    'Authorization', 'set-cookie', 'privateKey', 'SAS', 'pwd', 'passphrase', 'basicAuth']) assert.ok(isCredentialKey(key), key);
  for (const key of ['author', 'authority', 'host', 'port', 'passenger', 'user']) {
    assert.ok(!isCredentialKey(key), key);
  }
});

test('round-trip: rewriting values preserves keys and syntax for every supported full format', () => {
  const cases = [
    ['{"password":"old","n":1}', 'JSON', 'password'], ['API_TOKEN="old"\nX=1', 'DOTENV', 'API_TOKEN'],
    ["SECRET='old'", 'DOTENV', 'SECRET'], ['[s]\npassword = old', 'INI', 's.password'],
    ['https://u:old@h.example.invalid/p?token=old', 'URL', 'userinfo.password'],
    ['Server=h.example.invalid;Password="old";', 'CONNECTION_STRING', 'Password'],
    ['Pwd={old};', 'CONNECTION_STRING', 'Pwd'],
  ];
  for (const [text, format, path] of cases) {
    const field = parseStructured(text, format).fields.find((f) => f.path.join('.') === path);
    for (const replacement of ['[hylja:protected:PASSWORD]', 'with "quotes", {braces}; and\\slashes']) {
      const out = rewriteFieldValues(text, format, [{ field, replacement }]);
      if (out.status === 'FAILURE') {
        // Contexts that cannot hold the replacement refuse rather than emit the original.
        assert.equal(out.reason, 'UNENCODABLE_REPLACEMENT', `${format} ${replacement}`);
        continue;
      }
      const reparsed = parseStructured(out.text, format);
      assert.equal(reparsed.status, 'COMPLETE');
      assert.deepEqual(reparsed.fields.map((f) => f.path.join('.')), parseStructured(text, format).fields.map((f) => f.path.join('.')));
      assert.equal(reparsed.fields.find((f) => f.path.join('.') === path).value, replacement);
      assert.ok(!out.text.includes('old') || path !== 'userinfo.password' || out.text.includes('token=old'));
    }
  }
});

test('round-trip refuses unsafe edits instead of passing the original through', () => {
  const text = '{"n":1,"s":"a"}';
  const parsed = parseStructured(text, 'JSON');
  assert.deepEqual(rewriteFieldValues(text, 'JSON', [{ field: parsed.fields[0], replacement: 'x' }]),
    { status: 'FAILURE', reason: 'UNENCODABLE_REPLACEMENT' });
  assert.deepEqual(rewriteFieldValues(text, 'JSON', [{ field: { ...parsed.fields[1], valueStart: 0 }, replacement: 'x' }]),
    { status: 'FAILURE', reason: 'INVALID_EDIT' });
  assert.deepEqual(rewriteFieldValues('{"a":', 'JSON', []), { status: 'FAILURE', reason: 'SOURCE_NOT_COMPLETE' });
  assert.deepEqual(rewriteFieldValues('a=b', 'LOG', []), { status: 'FAILURE', reason: 'SOURCE_NOT_COMPLETE' });
});

test('hidden credentials in unparsed ranges are never reported as inspected', () => {
  const text = `GOOD=1\n${fake} password ${fake}\nOTHER=2`;
  const result = parseStructured(text, 'DOTENV');
  assert.equal(result.status, 'PARTIAL');
  assert.ok(result.opaque.some((range) => text.slice(range.start, range.end).includes('password')));
});

test('adversarial inputs stay within a bounded-work budget', () => {
  for (const [text, format] of [
    ['{"a":'.repeat(50_000), 'JSON'], [`"${'\\u0041'.repeat(150_000)}"`, 'JSON'], ['a=' + 'b'.repeat(1 << 19), 'LOG'],
    ['x=1 '.repeat(200_000), 'LOG'], ['A=1\n'.repeat(200_000), 'DOTENV'], ['k="'.repeat(200_000), 'CONNECTION_STRING'],
    [`https://h.example/?${'a=1&'.repeat(200_000)}`, 'URL'], ['Authorization: ' + 'x'.repeat(1 << 19), 'LOG'],
  ]) {
    const started = process.hrtime.bigint();
    const result = parseStructured(text, format);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(['COMPLETE', 'PARTIAL', 'FAILURE'].includes(result.status));
    assert.ok(result.fields.length <= DEFAULT_PARSE_BUDGET.maxFields);
    // Catches super-linear work; not a performance SLA.
    assert.ok(elapsedMs < 5000, `${format} ${elapsedMs}ms`);
  }
});
