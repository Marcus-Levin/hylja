import assert from 'node:assert/strict';
import { test } from 'node:test';
import { composeClassification } from '../dist/classification.js';
import { detectSecrets, subtypeForKey, MAX_TEXT_UNITS, SECRET_PRODUCER } from '../dist/secret-detectors.js';

// Synthetic only. Token-shaped values are assembled at runtime from obviously fake parts so no
// realistic credential literal is committed; none is valid for any service.
const fill = (n, seed = 'Synthetic0') => seed.repeat(Math.ceil(n / seed.length)).slice(0, n);
const T = {
  github: ['gh', 'p_', fill(36)].join(''),
  githubPat: ['github', '_pat_', fill(40, 'Synth_0')].join(''),
  gitlab: ['gl', 'pat-', fill(20, 'Synth-0')].join(''),
  slack: ['xo', 'xb-', fill(24, 'Synth0-')].join(''),
  slackApp: ['xapp-', '1-', 'A', '0123456789-', '1234567890123-', fill(32, 'Synth0-')].join(''),
  huggingface: ['hf', '_', fill(34)].join(''),
  shopify: ['shpat', '_', fill(32, '0f1e2d')].join(''),
  sendgrid: ['SG', '.', fill(22, 'Syn-th_0'), '.', fill(43, 'Syn-th_0')].join(''),
  stripe: ['sk', '_test_', fill(24)].join(''),
  google: ['AI', 'za', fill(35, 'Synth_-0')].join(''),
  aws: ['AK', 'IA', 'SYNTHETIC0000000'].join(''),
  skKey: ['sk', '-', fill(32, 'synthetic-')].join(''),
  npm: ['np', 'm_', fill(36)].join(''),
  jwt: ['ey', 'JhbGciOiJub25lIn0', '.', 'ey', 'JzdWIiOiJzeW50aGV0aWMifQ', '.', 'c3ludGhldGlj'].join(''),
  webhook: ['https://hooks.slack.com/services/', 'TSYNTH00/', 'BSYNTH00/', fill(24)].join(''),
};
const pem = ['-----BEGIN ', 'OPENSSH PRIVATE KEY-----\nc3ludGhldGljLWtleS1tYXRlcmlhbA==\n-----END ', 'OPENSSH PRIVATE KEY-----'].join('');
const run = (text, more = {}) => detectSecrets({ text, inputRef: 'field-a.invalid', ...more });
const spans = (text, result) => result.candidates.map((c) => [c.subtype, c.rule, text.slice(c.start, c.end)]);
const values = (text, result) => result.candidates.map((c) => text.slice(c.start, c.end));

test('format rules find each synthetic credential with its exact span and subtype', () => {
  for (const [value, subtype, rule] of [
    [T.github, 'ACCESS_TOKEN', 'format.github-token'], [T.githubPat, 'ACCESS_TOKEN', 'format.github-fine-grained-pat'],
    [T.gitlab, 'ACCESS_TOKEN', 'format.gitlab-pat'], [T.slack, 'ACCESS_TOKEN', 'format.slack-token'], [T.slackApp, 'ACCESS_TOKEN', 'format.slack-app-token'],
    [T.huggingface, 'ACCESS_TOKEN', 'format.huggingface-token'], [T.shopify, 'ACCESS_TOKEN', 'format.shopify-admin-token'],
    [T.sendgrid, 'API_KEY', 'format.sendgrid-api-key'],
    [T.stripe, 'API_KEY', 'format.stripe-key'], [T.google, 'API_KEY', 'format.google-api-key'],
    [T.aws, 'API_KEY', 'format.aws-access-key-id'], [T.skKey, 'API_KEY', 'format.sk-prefixed-api-key'],
    [T.npm, 'ACCESS_TOKEN', 'format.npm-token'], [T.jwt, 'ACCESS_TOKEN', 'format.jwt'],
    [T.webhook, 'API_KEY', 'format.slack-webhook'], [pem, 'PRIVATE_KEY', 'format.pem-private-key'],
  ]) {
    const text = `before ${value} after`;
    assert.deepEqual(spans(text, run(text)).filter(([, r]) => r === rule), [[subtype, rule, value]], rule);
  }
});

test('an unterminated private key block is still covered to the end of the text', () => {
  const text = `x\n${pem.slice(0, pem.indexOf('-----END'))}`;
  const [candidate] = run(text).candidates;
  assert.equal(candidate.subtype, 'PRIVATE_KEY');
  assert.equal(candidate.end, text.length);
});

test('context rules: headers, URL userinfo and credential-like key assignments', () => {
  const text = [
    `Authorization: Bearer ${T.jwt}`, 'Authorization: Basic dXNlcjpzeW50aGV0aWM=', 'Cookie: sid=synthetic; theme=dark',
    'Set-Cookie: session=synthetic-session; Path=/; HttpOnly', 'X-Api-Key: synthetic-header-key',
    'url=postgres://svc:synthetic-pass@db.example.invalid/app', 'DB_PASSWORD="syn thetic"', "client_secret: 'synthetic'",
    '{"apiKey": "synthetic-json-key", "refresh_token": "synthetic-refresh"}', 'AccountKey=synthetic-account-key;',
  ].join('\n');
  const found = spans(text, run(text));
  // Context rules may over-cover (to end of line); they must never stop inside the value.
  const has = (subtype, value) => assert.ok(found.some(([s, , v]) => s === subtype && v.includes(value)), `${subtype} ${value}`);
  has('ACCESS_TOKEN', T.jwt);
  has('PASSWORD', 'dXNlcjpzeW50aGV0aWM=');
  has('COOKIE', 'sid=synthetic; theme=dark');
  has('COOKIE', 'session=synthetic-session');
  has('API_KEY', 'synthetic-header-key');
  has('PASSWORD', 'synthetic-pass');
  has('PASSWORD', 'syn thetic');
  has('API_KEY', 'synthetic');
  has('API_KEY', 'synthetic-json-key');
  has('REFRESH_TOKEN', 'synthetic-refresh');
  has('CONNECTION_SECRET', 'synthetic-account-key');
  // The same span found by a format rule keeps the stronger FORMAT basis.
  const jwt = run(text).candidates.filter((c) => text.slice(c.start, c.end) === T.jwt);
  assert.ok(jwt.every((c) => c.basis === 'FORMAT'));
});

test('references, masks and non-credential keys are not candidates', () => {
  for (const text of ['password: ${DB_PASSWORD}', 'secret={{ vault.db }}', 'token=$TOKEN', 'pwd=%PWD%',
    'password: [hylja:protected:PASSWORD]', 'password=********', 'api_key: <redacted>', 'token: null',
    'author=synthetic', 'port=443', 'passenger=synthetic', 'Authorization: Bearer', 'tokenizer: bpe',
    '-----BEGIN CERTIFICATE-----\nc3ludGhldGlj\n-----END CERTIFICATE-----']) {
    assert.deepEqual(spans(text, run(text)), [], text);
  }
});

test('trusted field keys make the whole value a candidate', () => {
  const result = run('  opaque-synthetic-value  ', { fieldKey: 'DB_PASSWORD' });
  assert.deepEqual(spans('  opaque-synthetic-value  ', result), [['PASSWORD', 'context.field-key', 'opaque-synthetic-value']]);
  assert.equal(result.candidates[0].basis, 'FIELD_KEY');
  assert.deepEqual(run('value', { fieldKey: 'hostname' }).candidates, []);
  assert.deepEqual(run('${X}', { fieldKey: 'password' }).candidates, []);
});

test('key subtype mapping', () => {
  for (const [key, subtype] of [['DB_PASSWORD', 'PASSWORD'], ['pwd', 'PASSWORD'], ['apiKey', 'API_KEY'],
    ['x-api-key', 'API_KEY'], ['Client Secret', 'API_KEY'], ['aws_secret_access_key', 'API_KEY'],
    ['access_token', 'ACCESS_TOKEN'], ['refreshToken', 'REFRESH_TOKEN'], ['private_key', 'PRIVATE_KEY'],
    ['Cookie', 'COOKIE'], ['sessionId', 'COOKIE'], ['connectionString', 'CONNECTION_SECRET'], ['host', null],
    ['author', null], ['', null]]) assert.equal(subtypeForKey(key), subtype, key);
});

test('results never contain secret values; fingerprints are keyed and tenant-separated', () => {
  const text = `token=${T.github} password="synthetic-password-value"`;
  const plain = JSON.stringify(run(text));
  for (const value of [T.github, 'synthetic-password-value']) assert.ok(!plain.includes(value));
  assert.ok(!plain.includes('fingerprint'), 'no fingerprint without a key');
  const keyA = new Uint8Array(32).fill(1), keyB = new Uint8Array(32).fill(2);
  const a1 = run(text, { fingerprintKey: keyA }), a2 = run(text, { fingerprintKey: keyA }), b = run(text, { fingerprintKey: keyB });
  assert.equal(a1.candidates[0].fingerprint, a2.candidates[0].fingerprint);
  assert.notEqual(a1.candidates[0].fingerprint, b.candidates[0].fingerprint);
  assert.match(a1.candidates[0].fingerprint, /^[0-9a-f]{32}$/);
  assert.ok(!JSON.stringify(a1).includes(T.github));
  assert.deepEqual(run(text, { fingerprintKey: new Uint8Array(16) }).reasons, ['INVALID_FINGERPRINT_KEY']);
});

test('evidence is SECRET, non-reversible v1 detector evidence that composes to SECRET', () => {
  const result = run(`token=${T.github}`);
  const [candidate] = result.candidates;
  assert.equal(candidate.evidence.provenance.producerId, SECRET_PRODUCER.id);
  const composed = composeClassification({ detectorEvidence: result.candidates.map((c) => c.evidence) },
    { interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
  assert.equal(composed.status, 'RESOLVED');
  assert.equal(composed.semanticType, 'CREDENTIAL_OR_SECRET');
  assert.equal(composed.sensitivity, 'SECRET');
  assert.equal(composed.reversible, false);
  // A semantic PUBLIC judgment cannot lower it.
  const judged = composeClassification({ detectorEvidence: [candidate.evidence], semanticJudgments: [{ version: 1,
    id: 'judge.invalid', status: 'FOUND', provenance: { inputRef: 'field-a.invalid', producerId: 'judge.invalid',
      producerVersion: '1', questionSetVersion: 'q1', modelId: 'model.invalid' },
    claim: { semanticType: 'CREDENTIAL_OR_SECRET', sensitivity: 'PUBLIC' } }] },
  { interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
  assert.equal(judged.sensitivity, 'SECRET');
  assert.equal(judged.reversible, false);
});

test('failures are explicit and report nothing', () => {
  for (const [request, reason] of [
    [{ text: 1, inputRef: 'x' }, 'INVALID_REQUEST'], [{ text: 'a', inputRef: '' }, 'INVALID_REQUEST'],
    [{ text: 'a', inputRef: 'x', fieldKey: 3 }, 'INVALID_REQUEST'],
    [{ text: 'x'.repeat(MAX_TEXT_UNITS + 1), inputRef: 'x' }, 'INPUT_TOO_LARGE'],
    [{ text: '\uDC00', inputRef: 'x' }, 'INVALID_TEXT'],
    [{ text: Array.from({ length: 300 }, (_, i) => `password=synthetic${i}`).join('\n'), inputRef: 'x' }, 'TOO_MANY_CANDIDATES'],
  ]) {
    const result = detectSecrets(request);
    assert.equal(result.status, 'FAILURE', reason);
    assert.deepEqual(result.reasons, [reason]);
    assert.deepEqual(result.candidates, []);
  }
});

test('adversarial inputs stay within a bounded-work budget', () => {
  for (const text of ['-----BEGIN PRIVATE KEY-----'.repeat(30_000), 'eyJ'.repeat(300_000), 'eyJaaaaa.'.repeat(100_000),
    'password='.repeat(100_000), `Authorization: ${'x'.repeat(1 << 19)}`, 'a://b:'.repeat(150_000), '"k":"'.repeat(200_000),
    `gh${'p_'.repeat(400_000)}`]) {
    const started = process.hrtime.bigint();
    const result = run(text.slice(0, MAX_TEXT_UNITS));
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(['COMPLETE', 'FAILURE'].includes(result.status));
    // Catches super-linear matching; not a performance SLA.
    assert.ok(elapsedMs < 5000, `${elapsedMs}ms`);
  }
});

test('synthetic golden set: per-subtype detector recall and precision (not egress evidence)', (t) => {
  const golden = [
    [`export GITHUB_TOKEN=${T.github}`, [['ACCESS_TOKEN', T.github]]],
    [`curl -H "Authorization: Bearer ${T.jwt}" https://api.example.com`, [['ACCESS_TOKEN', T.jwt]]],
    ['DATABASE_URL=postgres://svc:synthetic-pass@db.example.invalid:5432/app', [['PASSWORD', 'synthetic-pass']]],
    [`{"server":"api.example.com","port":443,"apiKey":"${T.stripe}"}`, [['API_KEY', T.stripe]]],
    [`${pem}`, [['PRIVATE_KEY', pem]]],
    ['GET /health 200 port=8443 trace=4bf92f3577b34da6a3ce929d0e0e4736', []],
    ['build sha 3f2a1b9c0d4e5f60718293a4b5c6d7e8 version 1.2.3', []],
  ];
  const stats = {};
  for (const [text, expected] of golden) {
    const got = spans(text, run(text)).map(([s, , v]) => `${s}|${v}`);
    const want = expected.map(([s, v]) => `${s}|${v}`);
    for (const item of new Set([...got, ...want])) {
      const subtype = item.split('|')[0];
      stats[subtype] ??= { tp: 0, fp: 0, fn: 0 };
      if (got.includes(item) && want.includes(item)) stats[subtype].tp++;
      else if (got.includes(item)) stats[subtype].fp++;
      else stats[subtype].fn++;
    }
  }
  for (const [subtype, { tp, fp, fn }] of Object.entries(stats)) {
    t.diagnostic(`${subtype}: recall ${tp}/${tp + fn}, precision ${tp}/${tp + fp}`);
    assert.equal(fn, 0, `${subtype} false negatives`);
  }
  // Key-assignment context overlaps the format match for the same value; no other false positives.
  for (const [subtype, { fp }] of Object.entries(stats)) assert.equal(fp, 0, `${subtype} false positives`);
  assert.deepEqual(values('trace=4bf92f3577b34da6a3ce929d0e0e4736', run('trace=4bf92f3577b34da6a3ce929d0e0e4736')), []);
});

const covers = (text, value) => run(text).candidates.some((c) => text.slice(c.start, c.end).includes(value));

test('review regressions: nested assignments, reference prefixes and CLI/space-separated forms', () => {
  for (const [text, value] of [
    ['{"environment":"DB_PASSWORD=synthpass1"}', 'synthpass1'], ['command: DB_PASSWORD=synthpass1 ./run', 'synthpass1'],
    ['msg=password=synthpass1', 'synthpass1'], ['env:PGPASSWORD=synthpass1', 'synthpass1'],
    ['$env:API_KEY = "synthps"', 'synthps'], ['password=${X}synthrest', '${X}synthrest'],
    ['password={{ x }}realsecret', 'realsecret'], ['password=$SynthPass1', '$SynthPass1'],
    ['password=<realsecret>', '<realsecret>'], ['--password=synthpass1', 'synthpass1'], ['--api-key synthkey1', 'synthkey1'],
    ['curl -u svc:synthpass1 https://h.example.invalid', 'synthpass1'], ['ENV DB_PASSWORD synthpass1', 'synthpass1'],
    ['machine h.example.invalid login u password synthpass1', 'synthpass1'], ['password := synthpass1', 'synthpass1'],
    ['"password" => "synthpass1"', 'synthpass1'], ['<password>synthpass1</password>', 'synthpass1'],
    ['db:\n  password: |\n    synth-block-line\n  host: h.example.invalid', 'synth-block-line'],
    ['password=Basic', 'Basic'], ['DB_PASS=synthpass1', 'synthpass1'], ['credentials: synthpass1', 'synthpass1'],
  ]) assert.ok(covers(text, value), text);
});

test('review regressions: quoted, unterminated and multi-word values are covered in full', () => {
  for (const [text, value] of [
    ['Authorization: Bearer "synthquoted000"', 'synthquoted000'], ["Authorization: Bearer syn'thbearer000", "syn'thbearer000"],
    ['Cookie: sid="synthcookie"; x=1', '"synthcookie"'], ['Authorization: Digest username="u", response="synthresp"', 'synthresp'],
    ['password="synthtruncated', 'synthtruncated'], [`password="${'z'.repeat(5000)}`, 'z'.repeat(5000)],
    ['password=synth;pass', 'synth;pass'], ['db.password=my synth pass phrase', 'my synth pass phrase'],
    ['password: my synth pass phrase', 'my synth pass phrase'], ["password='syn\\'thpass'", "syn\\'thpass"],
    [`password=${'q'.repeat(6000)}`, 'q'.repeat(6000)], ['postgres://svc:p@ss@db.example.invalid/app', 'p@ss'],
    ['postgres://svc:p#s/s@db.example.invalid/app', 'p#s/s'],
  ]) assert.ok(covers(text, value), text.slice(0, 60));
});

test('review regressions: usage counters, working directories and certificates are not secrets', () => {
  for (const text of ['{"input_tokens":12,"output_tokens":34,"max_tokens":4096}', 'PWD=/home/synthetic/app',
    'jwt_algorithm: RS256', 'cert_pem: public-certificate-reference']) {
    assert.deepEqual(run(text).candidates, [], text);
  }
});

test('review regressions: format tokens next to _ or -, long JWT payloads, JWE, SSH2 and PuTTY keys', () => {
  for (const [text, value] of [[`X_${T.github}`, T.github], [`${T.github}-suffix`, T.github], [`${T.github}_`, T.github],
    [`${T.jwt.split('.')[0]}.eyJ${'a'.repeat(9000)}.sig`, `eyJ${'a'.repeat(9000)}`],
    ['eyJhbGciOiJkaXIifQ..c3ludGg.c3ludGhldGlj.dGFn', 'eyJhbGciOiJkaXIifQ..c3ludGg.c3ludGhldGlj.dGFn'],
    ['---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nc3ludGg=\n---- END SSH2 ENCRYPTED PRIVATE KEY ----', 'c3ludGg='],
    ['PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\nc3ludGg=\nPrivate-MAC: 00ff', 'c3ludGg=']]) {
    assert.ok(covers(text, value), text.slice(0, 40));
  }
});

test('fingerprints are domain-separated and a hostile key object fails closed', () => {
  const key = new Uint8Array(32).fill(7);
  const [candidate] = run(`token=${T.github}`, { fingerprintKey: key }).candidates;
  const { createHmac } = await_import_crypto();
  assert.notEqual(candidate.fingerprint, createHmac('sha256', key).update(T.github).digest('hex').slice(0, 32));
  const hostile = new Proxy(new Uint8Array(32), { get: () => { throw new Error('synthetic'); } });
  assert.equal(run('x', { fingerprintKey: hostile }).status, 'FAILURE');
});
function await_import_crypto() { return globalThis.process.getBuiltinModule('node:crypto'); }

test('second review: repeated headers on one line stay linear; sigil keys, multi-line quotes and mid-value quotes', () => {
  for (const text of [' Set-Cookie: a'.repeat(80_000), `${' Cookie:x'.repeat(50_000)}${' '.repeat(500_000)}`,
    `${' Set-Cookie: a'.repeat(30_000)}${'b'.repeat(500_000)}`, `${' Authorization: x'.repeat(40_000)}${'\t'.repeat(300_000)}`,
    `${' name:'.repeat(20_000)}${' '.repeat(600_000)}`]) {
    const started = process.hrtime.bigint();
    run(text.slice(0, MAX_TEXT_UNITS));
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 3000);
  }
  for (const [text, value] of [['$password = "synthphp";', 'synthphp'], ["my $db_pass = 'synthperl';", 'synthperl'],
    ['$Password = "synthps"', 'synthps'], ['password="line1\nline2"', 'line1\nline2'], ['x=1 password=synth"pass', 'synth"pass'],
    ['https://synthetictokenvalue0000@h.example.invalid/', 'synthetictokenvalue0000'],
    ['<password><![CDATA[synthcdata]]></password>', 'synthcdata'], ['<add key="DbPassword" value="synthattr"/>', 'synthattr'],
    ['env:\n  - name: DB_PASSWORD\n    value: synthk8s', 'synthk8s']]) assert.ok(covers(text, value), text);
});

test('second review: prose, ports and bare quotes are not candidates', () => {
  for (const text of ['Password reset email sent', 'Token expired at 12:00', 'https://example.invalid:8443/users/@me',
    'password="']) {
    assert.deepEqual(run(text).candidates.map((c) => text.slice(c.start, c.end)), [], text);
  }
});

test('third review: CDATA is linear, later keys survive a stray quote, short numeric URL passwords, multi-line .netrc', () => {
  const started = process.hrtime.bigint();
  run('<a><![CDATA['.repeat(90_000));
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 3000);
  for (const [text, value] of [['password: "abc\napi_key: "synthsecretvalue"', 'synthsecretvalue'],
    ['password="a\nsecret="synthsec3"', 'synthsec3'], ['redis://:12345@cache.example.invalid', '12345'],
    ['https://svc:1234@h.example.invalid/x', '1234'], ['machine h.example.invalid\n  login svc\n  password synthnetrc', 'synthnetrc'],
    ['machine h.example.invalid password synthnetrc2', 'synthnetrc2']]) assert.ok(covers(text, value), text);
  for (const text of ['name="password_hint" value="Your pet"', 'key="password_min_length" value="8"',
    'https://first.last.example.name@example.invalid/', 'The machine password is expired']) {
    assert.deepEqual(run(text).candidates.map((c) => text.slice(c.start, c.end)), [], text);
  }
});

/* ---------- #8 quoted-window correction (RED-first): an uninspected quoted suffix fails closed ---------- */
// QUOTE_WINDOW is module-private and deliberately NOT imported here. Its 65536 bound, opening quote counted,
// is reproduced as a fixed literal only to size obviously-synthetic inputs; no realistic credential exists.
const QWIN = 65536; /* units counted from the opening quote, opening quote included */
const qc = (n) => `password="${'S'.repeat(n)}"\n`; /* closed quoted assignment, n content units */
const qo = (n) => `password="${'S'.repeat(n)}`; /* unterminated, true EOF, n content units */
const FULL = [QWIN - 2, QWIN - 1]; /* content fits the window -> stays fully covered COMPLETE */
const PAST = [QWIN, QWIN + 1, 70000]; /* content runs past the window -> FAILURE/QUOTE_WINDOW_EXCEEDED */

test('#8 quote window: content up to the bound keeps full coverage as COMPLETE (closed, EOF-at-edge, escaped)', () => {
  for (const n of FULL) {
    for (const maker of [qc, qo]) {
      const result = run(maker(n));
      assert.equal(result.status, 'COMPLETE', `full ${n}`);
      // Full coverage: the one assigned PASSWORD spans all n content units, never a short prefix span.
      assert.equal(result.candidates.length, 1, `full count ${n}`);
      assert.equal(result.candidates[0].subtype, 'PASSWORD', `full subtype ${n}`);
      assert.equal(result.candidates[0].end - result.candidates[0].start, n, `full span ${n}`);
    }
  }
  // A closing quote exactly at the edge (position QWIN from the opener) closes the whole content, not a prefix.
  const edge = run(qc(QWIN - 1));
  assert.equal(edge.status, 'COMPLETE');
  assert.equal(edge.candidates[0].end - edge.candidates[0].start, QWIN - 1);
  // An escaped quote inside the window still closes; the fix preserves existing escaping behaviour.
  const escText = 'password="a\\"bc"';
  const esc = run(escText);
  assert.equal(esc.status, 'COMPLETE');
  assert.equal(esc.candidates.length, 1);
  assert.equal(escText.slice(esc.candidates[0].start, esc.candidates[0].end), 'a\\"bc');
});

test('#8 quote window: a quoted value past the bound fails closed as QUOTE_WINDOW_EXCEEDED (assignment, CLI/spaced, Kubernetes name/value)', () => {
  const callers = {
    assignment: { closed: (n) => `password="${'S'.repeat(n)}"`, eof: (n) => `password="${'S'.repeat(n)}` },
    'cli-flag': { closed: (n) => `--password "${'S'.repeat(n)}"`, eof: (n) => `--password "${'S'.repeat(n)}` },
    'k8s-named-value': { closed: (n) => `name: DB_PASSWORD\nvalue: "${'S'.repeat(n)}"`, eof: (n) => `name: DB_PASSWORD\nvalue: "${'S'.repeat(n)}` },
  };
  for (const n of PAST) {
    for (const [name, forms] of Object.entries(callers)) {
      for (const [form, make] of Object.entries(forms)) {
        const text = form === 'closed' ? `${make(n)} synthtail` : make(n);
        const result = run(text);
        assert.equal(result.status, 'FAILURE', `${name} ${n} ${form}`);
        assert.deepEqual(result.reasons, ['QUOTE_WINDOW_EXCEEDED'], `${name} ${n} ${form}`);
        // Nothing is reported: no candidate, so no prefix span, prefix fingerprint or success-shaped reason.
        assert.equal(result.candidates.length, 0, `${name} ${n} ${form}`);
        assert.equal(JSON.stringify(result).includes('synthtail'), false, `${name} ${n} ${form}`);
      }
    }
  }
});

test('#8 quote window: an escaped quote at the edge is not a close, and a backslash over the edge is not closure', () => {
  // The window holds 65535 content units; a backslash at edge-1 escapes the quote at the edge, so the value is
  // not closed there and the tail that follows is uninspected.
  const escEdge = ['password="', 'S'.repeat(QWIN - 2), '\\', '"', 'synthtail', '"'].join('');
  const result = run(escEdge);
  assert.equal(result.status, 'FAILURE', 'escaped-edge');
  assert.deepEqual(result.reasons, ['QUOTE_WINDOW_EXCEEDED'], 'escaped-edge');
  assert.equal(result.candidates.length, 0, 'escaped-edge');
  assert.equal(JSON.stringify(result).includes('synthtail'), false, 'escaped-edge-privacy');
});

test('#8 quote window: an over-window reference/mask-looking prefix cannot be excluded to hide an uninspected tail', () => {
  // The visible window is exactly the content width and looks like a mask (a reference), but real content
  // continues past the window. Excluding the prefix as a reference must not read as a silent COMPLETE.
  const masked = ['password="', '*'.repeat(QWIN - 1), 'synthsecret-tail', '"'].join('');
  const result = run(masked);
  assert.equal(result.status, 'FAILURE', 'masked-over-window');
  assert.deepEqual(result.reasons, ['QUOTE_WINDOW_EXCEEDED'], 'masked-over-window');
  assert.equal(result.candidates.length, 0, 'masked-over-window');
  assert.equal(JSON.stringify(result).includes('synthsecret-tail'), false, 'masked-over-window-privacy');
  // Even with a tenant fingerprint key present, a failure yields no prefix fingerprint and no candidate.
  const keyed = run(`password="${'S'.repeat(70000)}"`, { fingerprintKey: new Uint8Array(32).fill(5) });
  assert.equal(keyed.status, 'FAILURE', 'keyed-over-window');
  assert.deepEqual(keyed.reasons, ['QUOTE_WINDOW_EXCEEDED'], 'keyed-over-window');
  assert.equal(keyed.candidates.length, 0, 'keyed-over-window');
});

/* Generated public-synthetic controls: no source import or last-byte escape predicate. A boundary quote
 * closes after an EVEN backslash run; an ODD run escapes it. Each negative is a separate test so a RED
 * assertion in one caller/key/edge case does not suppress the other generated cases. */
const quoteCallers = [
  { name: 'assignment', prefix: 'password=', rule: 'context.key-assignment' },
  { name: 'cli', prefix: '--password ', rule: 'context.cli-flag' },
  { name: 'kubernetes', prefix: 'name: DB_PASSWORD\nvalue: ', rule: 'context.named-value' },
];
const quoteKeys = [
  { name: 'unkeyed', options: {}, keyed: false },
  { name: 'keyed', options: { fingerprintKey: new Uint8Array(32).fill(9) }, keyed: true },
];
function fullQuoteFacts(result, start, length, rule, keyed) {
  assert.equal(result.status, 'COMPLETE');
  assert.equal(result.reasons.length, 0);
  assert.equal(result.candidates.length, 1);
  const candidate = result.candidates[0];
  assert.equal(candidate.start, start);
  assert.equal(candidate.end, start + length);
  assert.equal(candidate.subtype, 'PASSWORD');
  assert.equal(candidate.rule, rule);
  assert.equal(candidate.evidence.claim.sensitivity, 'SECRET');
  assert.equal(candidate.evidence.claim.reversible, false);
  assert.equal(Object.hasOwn(candidate, 'fingerprint'), keyed);
  if (keyed) assert.equal(/^[0-9a-f]{32}$/u.test(candidate.fingerprint), true);
}
function quoteFailureFacts(result) {
  assert.equal(result.status, 'FAILURE');
  assert.deepEqual(result.reasons, ['QUOTE_WINDOW_EXCEEDED']);
  assert.deepEqual(result.candidates, []);
  assert.equal(JSON.stringify(result).includes('synthetic-uninspected-tail.invalid'), false);
  assert.equal(JSON.stringify(result).includes('fingerprint'), false);
}
for (const caller of quoteCallers) {
  for (const key of quoteKeys) {
    const label = `#8 generated quote window: ${caller.name}/${key.name}`;
    const start = caller.prefix.length + 1;
    test(`${label} near-window closed and true-EOF positive controls`, () => {
      for (const quote of ['"', "'", '`']) {
        for (const length of [QWIN - 3, QWIN - 2, QWIN - 1]) {
          const content = fill(length, 'SyntheticWindow0');
          for (const ending of ['', `${quote}\nport=443`]) {
            fullQuoteFacts(run(`${caller.prefix}${quote}${content}${ending}`, key.options),
              start, length, caller.rule, key.keyed);
          }
        }
      }
    });
    test(`${label} true EOF at the edge with odd/even trailing backslashes`, () => {
      for (const slashCount of [1, 2, 3, 4]) {
        const content = fill(QWIN - 1 - slashCount) + '\\'.repeat(slashCount);
        fullQuoteFacts(run(`${caller.prefix}"${content}`, key.options),
          start, QWIN - 1, caller.rule, key.keyed);
      }
    });
    for (const slashCount of [0, 2, 4]) {
      test(`${label} even backslash run ${slashCount} closes exactly at boundary`, () => {
        for (const quote of ['"', "'", '`']) {
          const content = fill(QWIN - 1 - slashCount) + '\\'.repeat(slashCount);
          fullQuoteFacts(run(`${caller.prefix}${quote}${content}${quote}\nport=443`, key.options),
            start, QWIN - 1, caller.rule, key.keyed);
        }
      });
    }
    test(`${label} odd/even backslash controls close inside the window`, () => {
      for (const quote of ['"', "'", '`']) {
        for (const slashCount of [1, 2, 3, 4]) {
          const before = fill(QWIN - 6 - slashCount) + '\\'.repeat(slashCount);
          const odd = slashCount % 2 === 1;
          const content = odd ? `${before}${quote}S` : before;
          fullQuoteFacts(run(`${caller.prefix}${quote}${content}${quote}\nport=443`, key.options),
            start, content.length, caller.rule, key.keyed);
        }
      }
    });
    for (const length of [QWIN, QWIN + 1]) {
      for (const form of ['closed', 'eof']) {
        test(`${label} content length ${length}/${form} refuses uninspected suffix`, () => {
          const ending = form === 'closed' ? '"\nport=443' : '';
          quoteFailureFacts(run(`${caller.prefix}"${fill(length)}${ending}`, key.options));
        });
      }
    }
    for (const slashCount of [1, 3]) {
      for (const quote of ['"', "'", '`']) {
        test(`${label} odd backslash run ${slashCount}/${quote} escapes boundary quote`, () => {
          const content = fill(QWIN - 1 - slashCount) + '\\'.repeat(slashCount);
          quoteFailureFacts(run(`${caller.prefix}${quote}${content}${quote}synthetic-uninspected-tail.invalid${quote}`,
            key.options));
        });
      }
    }
    test(`${label} backslash at boundary cannot hide a later escaped quote`, () => {
      const content = fill(QWIN - 1);
      quoteFailureFacts(run(`${caller.prefix}"${content}\\"synthetic-uninspected-tail.invalid"`, key.options));
    });
    test(`${label} mask-looking inspected prefix cannot hide a tail`, () => {
      quoteFailureFacts(run(`${caller.prefix}"${'*'.repeat(QWIN - 1)}synthetic-uninspected-tail.invalid"`, key.options));
    });
  }
}
