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
    'Authorization', 'set-cookie', 'privateKey', 'SAS', 'pwd', 'passphrase', 'basicAuth', 'key', 'sig', 'DB_PASS',
    'SMTP_PASS', 'db_pw', 'PHPSESSID', 'dsn', 'ssh_key', 'encryption_key', 'otp', 'p\u0430ssword']) assert.ok(isCredentialKey(key), key);
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
      // The original value is gone from the edited field's source span.
      const after = parseStructured(out.text, format).fields.find((f) => f.path.join('.') === path);
      assert.ok(!out.text.slice(after.valueStart, after.valueEnd).includes('old'));
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


function prng(seed) {
  let state = seed >>> 0;
  return () => { state = (state + 0x6d2b79f5) >>> 0; let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

test('review regressions: comments are listed, and rewriting refuses or removes them', () => {
  const text = '# PASSWORD=synthetic-old\nA=1 # token=synthetic-old\nPASSWORD=synthetic-old # was synthetic-old';
  const result = parseStructured(text, 'DOTENV');
  assert.equal(result.status, 'COMPLETE');
  assert.ok(result.reasons.includes('COMMENTS'));
  assert.deepEqual(result.comments.map((c) => text.slice(c.start, c.end)),
    ['# PASSWORD=synthetic-old', '# token=synthetic-old', '# was synthetic-old']);
  const field = result.fields.find((f) => f.path[0] === 'PASSWORD');
  assert.deepEqual(rewriteFieldValues(text, 'DOTENV', [{ field, replacement: 'X' }]),
    { status: 'FAILURE', reason: 'SOURCE_HAS_COMMENTS' });
  const removed = rewriteFieldValues(text, 'DOTENV', [{ field, replacement: 'X' }], { comments: 'REMOVE' });
  assert.equal(removed.status, 'OK');
  assert.ok(!removed.text.includes('synthetic-old'));
  const ini = parseStructured('[s]\n; old password\npassword = synthetic-old #1', 'INI');
  assert.equal(ini.comments.length, 2);
  assert.equal(ini.fields[0].value, 'synthetic-old');
});

test('review regressions: credential ancestors, name/value siblings and URL forms are high risk', () => {
  const risky = (text, format) => parseStructured(text, format).fields.filter((f) => f.highRisk).map((f) => f.path.join('.'));
  assert.deepEqual(risky('{"password":["synthetic"],"token":{"value":"synthetic"}}', 'JSON'), ['password.0', 'token.value']);
  assert.deepEqual(risky('[secrets]\ndb = synthetic', 'INI'), ['secrets.db']);
  assert.deepEqual(risky('{"env":[{"name":"DB_PASSWORD","value":"synthetic"},{"name":"MODE","value":"x"}]}', 'JSON'),
    ['env.0.value']);
  assert.deepEqual(risky('https://h.example.invalid/?syntheticbare&a=1;token=synthetic', 'URL'), ['query.', 'query.token']);
  assert.deepEqual(risky('https://h.example.invalid/cb#access_token=synthetic&x=1', 'URL'), ['fragment.access_token']);
  assert.deepEqual(risky('https://synthetic-token@h.example.invalid/', 'URL'), ['userinfo.username']);
  const jdbc = parseStructured('jdbc:postgresql://h.example.invalid/db?user=u&password=synthetic', 'CONNECTION_STRING');
  assert.equal(jdbc.status, 'COMPLETE');
  assert.deepEqual(jdbc.fields.filter((f) => f.highRisk).map((f) => f.path.join('.')), ['query.password']);
});

test('review regressions: over-long or unterminated log values mark the line opaque', () => {
  for (const text of [`token=${'x'.repeat(5000)}`, `password="${'y'.repeat(5000)}"`, 'password="unterminated', "k='open"]) {
    const result = parseStructured(text, 'LOG');
    assert.equal(result.status, 'PARTIAL', text.slice(0, 20));
    assert.ok(result.reasons.includes('OPAQUE_RANGES'));
  }
  const header = parseStructured('Authorization: Bearer synthetic   ', 'LOG').fields[0];
  assert.equal(header.value, 'Bearer synthetic');
});

test('review regressions: budget caps bound memory; rewrites never throw', () => {
  assert.deepEqual(parseStructured('1', 'JSON', { maxDepth: 129 }).reasons, ['INVALID_BUDGET']);
  assert.deepEqual(parseStructured('1', 'JSON', { maxFields: 65537 }).reasons, ['INVALID_BUDGET']);
  const deepWide = `${'['.repeat(120)}${'1,'.repeat(20_000)}1${']'.repeat(120)}`;
  assert.equal(parseStructured(deepWide, 'JSON', { maxDepth: 128, maxFields: 65536 }).status, 'FAILURE');
  const url = 'https://u:old@h.example.invalid/';
  const field = parseStructured(url, 'URL').fields.find((f) => f.path.join('.') === 'userinfo.password');
  assert.deepEqual(rewriteFieldValues(url, 'URL', [{ field, replacement: '\uD800' }]),
    { status: 'FAILURE', reason: 'UNENCODABLE_REPLACEMENT' });
  // Caller-supplied syntax is ignored: the parser's own syntax for that span is used.
  const json = '{"a":"old"}';
  const jf = parseStructured(json, 'JSON').fields[0];
  const out = rewriteFieldValues(json, 'JSON', [{ field: { ...jf, syntax: 'BARE' }, replacement: 'q"x' }]);
  assert.deepEqual(parseStructured(out.text, 'JSON').fields[0].value, 'q"x');
});

test('review regressions: long whitespace runs parse in linear time', () => {
  for (const [text, format] of [[`A: x${' '.repeat(1 << 19)}y`, 'LOG'], [`a${' '.repeat(1 << 19)}`, 'INI'],
    [`[s${' '.repeat(1 << 19)}`, 'INI'], [`A=${' '.repeat(1 << 19)}#c`, 'DOTENV'], [`a:${' '.repeat(1 << 19)}b`, 'INI']]) {
    const started = process.hrtime.bigint();
    parseStructured(text, format);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(elapsedMs < 2000, `${format} ${elapsedMs}ms`);
  }
});

test('property: rewriting random fields preserves every key and unedited value and removes the edited originals', () => {
  const random = prng(0x0707);
  const alphabet = ['a', 'Z', '0', ' ', '"', "'", '\\', ';', '#', '}', '{', '=', '&', '%', '\n', 'é', ':', '/'];
  const pick = (list) => list[Math.floor(random() * list.length)];
  const word = (n) => Array.from({ length: n }, () => pick(alphabet)).join('');
  for (let run = 0; run < 300; run++) {
    const obj = { host: 'h.example.invalid', password: `old-${run}`, nested: { token: `old2-${run}`, list: ['x', `old3-${run}`] } };
    const cases = [
      [JSON.stringify(obj), 'JSON'],
      [`HOST=h.example.invalid\nPASSWORD="old-${run}"\nTOKEN='old2-${run}'`, 'DOTENV'],
      [`Server=h.example.invalid;Password="old-${run}";Pwd={old2-${run}}`, 'CONNECTION_STRING'],
      [`https://u:old-${run}@h.example.invalid/p?token=old2-${run}#f`, 'URL'],
    ];
    const [text, format] = pick(cases);
    const parsed = parseStructured(text, format);
    const targets = parsed.fields.filter((f) => f.value.startsWith('old'));
    const edits = targets.map((field) => ({ field, replacement: word(1 + Math.floor(random() * 12)) }));
    const out = rewriteFieldValues(text, format, edits);
    if (out.status === 'FAILURE') { assert.ok(['UNENCODABLE_REPLACEMENT', 'ROUND_TRIP_MISMATCH'].includes(out.reason)); continue; }
    const after = parseStructured(out.text, format);
    assert.deepEqual(after.fields.map((f) => f.path.join('.')), parsed.fields.map((f) => f.path.join('.')));
    parsed.fields.forEach((field, index) => {
      const edit = edits.find((e) => e.field === field);
      assert.equal(after.fields[index].value, edit ? edit.replacement : field.value);
    });
    for (const field of targets) assert.ok(!out.text.includes(field.value), `${format} ${out.text}`);
  }
});

test('rereview: JSON containers and long ancestor keys stay linear; containers count against the node budget', () => {
  const key = 'x'.repeat(300);
  const nested = `${`{"${key}":`.repeat(63)}[${'[],'.repeat(330_000)}[]]${'}'.repeat(63)}`;
  for (const text of [`[${'['.repeat(63)}${'{},'.repeat(340_000)}{}${']'.repeat(64)}`, nested]) {
    const started = process.hrtime.bigint();
    assert.equal(parseStructured(text, 'JSON').status, 'COMPLETE');
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 2000);
  }
  assert.deepEqual(parseStructured(`[${'[],'.repeat(349_000)}[]]`, 'JSON').status, 'COMPLETE');
});

test('rereview: ;key=value after a URL authority is parsed, never hidden in the host', () => {
  for (const [text, format] of [['jdbc:sqlserver://h.example.invalid;user=u;password=synthetic', 'URL'],
    ['jdbc:sqlserver://h.example.invalid:1433;user=u;password=synthetic', 'CONNECTION_STRING'],
    ['https://h.example.invalid;token=synthetic/x', 'URL']]) {
    const result = parseStructured(text, format);
    assert.equal(result.status, 'COMPLETE');
    assert.equal(result.fields.find((f) => f.path[0] === 'host').value, 'h.example.invalid');
    assert.ok(result.fields.some((f) => f.highRisk && f.value === 'synthetic'), text);
  }
  assert.equal(parseStructured('https://h=x.example.invalid/', 'URL').status, 'FAILURE');
});
