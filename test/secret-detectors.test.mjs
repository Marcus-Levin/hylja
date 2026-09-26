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
    [T.gitlab, 'ACCESS_TOKEN', 'format.gitlab-pat'], [T.slack, 'ACCESS_TOKEN', 'format.slack-token'],
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
  const has = (subtype, value) => assert.ok(found.some(([s, , v]) => s === subtype && v === value), `${subtype} ${value}`);
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
