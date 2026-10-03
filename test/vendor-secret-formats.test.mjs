import assert from 'node:assert/strict';
import { test } from 'node:test';
import { composeClassification } from '../dist/classification.js';
import { detectInfrastructure } from '../dist/infrastructure-identifiers.js';
import { detectNormalizedCandidates } from '../dist/normalized-detection.js';
import { detectSecrets, MAX_TEXT_UNITS, SECRET_PRODUCER } from '../dist/secret-detectors.js';

// #141 vendor credential token shapes. Every value is assembled at runtime from deterministic, obviously
// synthetic alphabets, so no literal credential is committed and none of them is valid for any service.
// Supported-shape notes live with the rules in src/secret-detectors.ts: the prefixes are primary-documented,
// the body bounds are this detector's supported scope, not a vendor guarantee.
const HEX = '0123456789abcdef';
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const B64 = `${ALNUM}-_`;
const LABEL = `${ALNUM}-`;
const gen = (alphabet, n, offset = 0) => Array.from({ length: n }, (_, i) => alphabet[(i * 7 + offset) % alphabet.length]).join('');
const alpha = (n, offset = 0) => gen(ALNUM, n, offset);

// Section-separated Slack body in the documented style; `-` separates sections and the final section is the secret.
const slackBody = ['1-', 'A', '0123456789', '-', '1234567890123', '-'].join('');
const V = {
  slackApp: ['xapp-', slackBody, alpha(32, 3)].join(''),
  slackRotating: ['xoxe.', 'xapp-', slackBody, alpha(32, 5)].join(''),
  huggingface: ['hf_', alpha(34, 1)].join(''),
  shopify: ['shpat_', gen(HEX, 32, 2)].join(''),
  // 22 + 43 characters over a base64url body, the 69-character total the vendor documents. The segments stay
// label-shaped here so #9 also reads the value as a dotted name; a body with `_` is covered separately.
sendgrid: ['SG.', gen(B64, 18, 4), '-', gen(B64, 3, 21), '.', gen(LABEL, 43, 9)].join(''),
/** Same shape with `_` in both segments, so the accepted charset is exercised, not only `[A-Za-z0-9-]`. */
sendgridUnderscore: ['SG.', gen(B64, 22, 4), '.', gen(B64, 43, 21)].join(''),
};

const run = (text, more = {}) => detectSecrets({ text, inputRef: 'vendor-case.invalid', ...more });
const spans = (text, result) => result.candidates.map((candidate) => [candidate.subtype, candidate.rule, text.slice(candidate.start, candidate.end)]);
const context = Object.freeze({ interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
const compose = (evidence) => composeClassification({ detectorEvidence: evidence }, context);

test('vendor token families emit exact spans, stable rule ids and subtypes with no field context', () => {
  for (const [value, subtype, rule] of [
    [V.slackApp, 'ACCESS_TOKEN', 'format.slack-app-token'],
    [V.slackRotating, 'ACCESS_TOKEN', 'format.slack-app-token'],
    [V.huggingface, 'ACCESS_TOKEN', 'format.huggingface-token'],
    [V.shopify, 'ACCESS_TOKEN', 'format.shopify-admin-token'],
    [V.sendgrid, 'API_KEY', 'format.sendgrid-api-key'],
  ]) {
    // No credential-shaped key, header or URL around the value: the shape alone must carry the finding.
    const text = `before ${value} after`;
    const result = run(text);
    assert.deepEqual(spans(text, result), [[subtype, rule, value]], rule);
    assert.deepEqual(spans(text, result).filter(([, id]) => id === rule), [[subtype, rule, value]], rule);
    const [candidate] = result.candidates;
    assert.equal(candidate.basis, 'FORMAT', rule);
    assert.equal(candidate.start, text.indexOf(value), rule);
    assert.equal(candidate.end, candidate.start + value.length, rule);
  }
});

test('a SendGrid key at the end of a sentence keeps its span; sentence punctuation is not part of it', () => {
  const text = `rotate the key ${V.sendgrid}.`;
  assert.deepEqual(spans(text, run(text)), [['API_KEY', 'format.sendgrid-api-key', V.sendgrid]]);
  const underscore = `rotate the key ${V.sendgridUnderscore}.`;
  assert.deepEqual(spans(underscore, run(underscore)),
    [['API_KEY', 'format.sendgrid-api-key', V.sendgridUnderscore]]);
  assert.equal(V.sendgrid.length, 69, 'the documented key length is what this synthetic value models');
});

test('near misses outside the supported body bounds are true negatives', () => {
  for (const [family, text] of [
    ['slack short body', `xapp-${alpha(8)}`],
    ['slack long body', `xapp-${alpha(260)}`],
    ['slack wrong charset', `xapp-_${alpha(20)}`],
    ['slack embedded', `refxapp-${slackBody}${alpha(32)}`],
    ['huggingface short body', `hf_${alpha(29)}`],
    ['huggingface long body', `hf_${alpha(65)}`],
    ['huggingface wrong charset', `hf_-${alpha(30)}`],
    ['huggingface embedded', `whf_${alpha(34)}`],
    ['shopify short body', `shpat_${alpha(29)}`],
    ['shopify long body', `shpat_${alpha(65)}`],
    ['shopify wrong charset', `shpat_-${alpha(32)}`],
    ['shopify embedded', `xshpat_${gen(HEX, 32)}`],
    ['sendgrid short segment', `SG.${alpha(7)}.${alpha(20)}`],
    ['sendgrid long segment', `SG.${alpha(22)}.${alpha(65)}`],
    ['sendgrid wrong charset', `SG.${alpha(20)}!${alpha(3)}.${alpha(20)}`],
    ['sendgrid extra segment', `SG.${alpha(12)}.${alpha(12)}.${alpha(12)}`],
    ['sendgrid embedded', `mailSG.${alpha(12)}.${alpha(12)}`],
    ['sendgrid prefix only', 'SG.'],
  ]) assert.deepEqual(spans(text, run(text)), [], `${family}: ${text.slice(0, 40)}`);
});

test('out-of-scope vendor prefixes stay true negatives and are reported as coverage limits', () => {
  // #141 is bounded to shpat_; Shopify's shpca_/shppa_ families and other vendors are not recognized here.
  for (const text of [`shpca_${gen(HEX, 32, 4)}`, `shppa_${gen(HEX, 32, 6)}`, `xwfp-${alpha(30)}`,
    'sk-', gen(HEX, 40)]) {
    assert.deepEqual(spans(text, run(text)), [], text.slice(0, 24));
  }
  // The pre-existing generic sk- rule is untouched by this change and still covers its own shape.
  assert.deepEqual(spans(`sk-${alpha(30)}`, run(`sk-${alpha(30)}`)),
    [['API_KEY', 'format.sk-prefixed-api-key', `sk-${alpha(30)}`]]);
});

test('boundary characters next to a supported shape are a boundary, not part of the value', () => {
  for (const [value, expected] of [[V.huggingface, V.huggingface], [V.shopify, V.shopify],
    [`${V.huggingface}_suffix`, V.huggingface], [`X_${V.shopify}`, V.shopify]]) {
    const text = `before ${value} after`;
    const found = spans(text, run(text));
    assert.equal(found.length, 1, text.slice(0, 40));
    assert.equal(text.slice(run(text).candidates[0].start, run(text).candidates[0].end), expected, text.slice(0, 40));
  }
});

test('a `-`-joined tail stays inside the Slack span, exactly as the pre-existing xox* rule behaves', () => {
  // Slack documents `-`-separated token sections, so a trailing `-suffix` cannot be separated from the body.
  // The new rule over-covers here in the same way the unchanged `format.slack-token` rule already does.
  for (const [value, rule] of [[`${V.slackApp}-suffix`, 'format.slack-app-token'],
    [`${['xoxb-1-', alpha(32, 7)].join('')}-suffix`, 'format.slack-token']]) {
    const text = `before ${value} after`;
    assert.deepEqual(spans(text, run(text)), [['ACCESS_TOKEN', rule, value]], rule);
  }
});

test('a credential key beside a vendor shape keeps the FORMAT evidence, not the context one', () => {
  // Both rules see the same value; the documented strength order keeps FORMAT and drops the weaker CONTEXT span.
  const text = `SENDGRID_API_KEY=${V.sendgrid}`;
  assert.deepEqual(spans(text, run(text)), [['API_KEY', 'format.sendgrid-api-key', V.sendgrid]]);
  assert.equal(run(text).candidates[0].basis, 'FORMAT');
});

test('findings are SECRET, non-reversible, value-free and keyed by a domain-separated tenant fingerprint', () => {
  const text = `key=${V.sendgrid} hf=${V.huggingface}`;
  const result = run(text);
  assert.deepEqual(spans(text, result), [['API_KEY', 'format.sendgrid-api-key', V.sendgrid],
    ['ACCESS_TOKEN', 'format.huggingface-token', V.huggingface]]);
  for (const candidate of result.candidates) {
    assert.equal(candidate.evidence.claim.semanticType, 'CREDENTIAL_OR_SECRET', candidate.rule);
    assert.equal(candidate.evidence.claim.sensitivity, 'SECRET', candidate.rule);
    assert.equal(candidate.evidence.claim.reversible, false, candidate.rule);
    assert.equal(candidate.evidence.provenance.producerId, SECRET_PRODUCER.id);
  }
  const plain = JSON.stringify(result);
  for (const value of [V.sendgrid, V.huggingface]) assert.ok(!plain.includes(value), 'a candidate never carries its value');
  assert.ok(!plain.includes('fingerprint'), 'no fingerprint without a key');

  const { createHmac } = globalThis.process.getBuiltinModule('node:crypto');
  const keyA = new Uint8Array(32).fill(3), keyB = new Uint8Array(32).fill(4);
  const a = run(text, { fingerprintKey: keyA }), again = run(text, { fingerprintKey: keyA }), b = run(text, { fingerprintKey: keyB });
  assert.equal(a.candidates[0].fingerprint, again.candidates[0].fingerprint);
  assert.notEqual(a.candidates[0].fingerprint, b.candidates[0].fingerprint);
  assert.notEqual(a.candidates[0].fingerprint, a.candidates[1].fingerprint);
  assert.match(a.candidates[0].fingerprint, /^[0-9a-f]{32}$/);
  // Domain-separated: not the plain HMAC of the value, so a reused tenant key cannot correlate with it.
  assert.notEqual(a.candidates[0].fingerprint, createHmac('sha256', keyA).update(V.sendgrid).digest('hex').slice(0, 32));
  assert.ok(!JSON.stringify(a).includes(V.sendgrid));
});

test('composition keeps the credential claim SECRET and non-reversible next to weaker identifier evidence', () => {
  const text = `sendgrid ${V.sendgrid} in env`;
  const secret = run(text);
  const infra = detectInfrastructure({ text, inputRef: 'vendor-case.invalid' });
  // The dotted key shape is also visible to #9 as a name; both channels feed the same composer.
  assert.ok(infra.candidates.some((item) => item.semanticType === 'HOST_OR_SERVICE'), 'infrastructure overlap is real here');
  const alone = compose(secret.candidates.map((candidate) => candidate.evidence));
  assert.equal(alone.status, 'RESOLVED');
  assert.equal(alone.semanticType, 'CREDENTIAL_OR_SECRET');
  assert.equal(alone.subtype, 'API_KEY');
  assert.equal(alone.sensitivity, 'SECRET');
  assert.equal(alone.reversible, false);
  const together = compose([...secret.candidates.map((candidate) => candidate.evidence), ...infra.candidates.map((item) => item.evidence)]);
  assert.equal(together.sensitivity, 'SECRET');
  assert.equal(together.reversible, false);
  assert.ok(['RESOLVED', 'UNRESOLVED'].includes(together.status), together.status);
});

test('normalized detection reports the vendor key as SECRET evidence with exact original spans', () => {
  const input = `rotate ${V.sendgrid} then ${V.huggingface}`;
  const result = detectNormalizedCandidates({ input, inputRef: 'vendor-case.invalid',
    scope: { tenantRef: 'tenant-a', projectRef: 'project-a' } });
  assert.equal(result.status, 'COMPLETE');
  const secrets = result.candidates.filter((item) => item.source === 'SECRET');
  assert.deepEqual(secrets.map((item) => [item.rule, input.slice(item.original.span.start, item.original.span.end)]), [
    ['format.sendgrid-api-key', V.sendgrid], ['format.huggingface-token', V.huggingface],
  ]);
  assert.ok(secrets.every((item) => item.original.kind === 'ORIGINAL_EXACT' && item.basis === 'FORMAT'));
  assert.ok(secrets.every((item) => item.evidence.claim.sensitivity === 'SECRET' && item.evidence.claim.reversible === false));
  assert.ok(!JSON.stringify(result).includes(V.sendgrid), 'a normalized candidate never carries its value');
});

test('adversarial repetitions of the new prefixes stay inside the existing work budget', () => {
  for (const text of ['xapp-'.repeat(200_000), 'xoxe.xapp-'.repeat(150_000), 'hf_'.repeat(300_000),
    `hf_${'a'.repeat(1 << 19)}`, 'shpat_'.repeat(200_000), `shpat_${'a'.repeat(1 << 19)}`,
    `SG.${'a'.repeat(1 << 19)}`, `SG.${'a-'.repeat(200_000)}.${'b_'.repeat(200_000)}`,
    `SG.${'a'.repeat(70)}.`, `${'SG.'.repeat(150_000)}${'.'.repeat(300_000)}`]) {
    const started = process.hrtime.bigint();
    const result = run(text.slice(0, MAX_TEXT_UNITS));
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(['COMPLETE', 'FAILURE'].includes(result.status), text.slice(0, 20));
    // Catches super-linear matching; not a performance SLA.
    assert.ok(elapsedMs < 5000, `${text.slice(0, 20)}: ${elapsedMs}ms`);
  }
});

test('a dotted name that looks like a SendGrid key is accepted over-cover, and fails safe as SECRET', () => {
  // Documented scope trade-off of the SG. rule: any two 8..64-character labels behind a literal `SG` first label
  // match. The cost is an over-cloak of a rare name; the direction is a SECRET finding, never a clean result.
  for (const text of ['get SG.internal.services ok', 'SG.Internal.Services']) {
    assert.deepEqual(spans(text, run(text)), [['API_KEY', 'format.sendgrid-api-key', text.startsWith('get') ? 'SG.internal.services' : text]], text);
  }
  // A lowercase host name, a short label or a reserved TLD stays outside the rule.
  for (const text of ['host sg.internal.services', 'SG.example.invalid', 'SG.mail.example.invalid']) {
    assert.deepEqual(spans(text, run(text)), [], text);
  }
});

test('public development measurement: per-subtype candidate recall, false positives and true negatives', (t) => {
  // Public, synthetic, unscored development evidence over assembled shapes. It is not held-out data, a
  // release gate, or a statement about live-token validity or outbound leakage.
  const positive = [
    [V.slackApp, 'ACCESS_TOKEN'], [V.slackRotating, 'ACCESS_TOKEN'], [V.huggingface, 'ACCESS_TOKEN'],
    [V.shopify, 'ACCESS_TOKEN'], [V.sendgrid, 'API_KEY'],
  ];
  const negative = [
    `xapp-${alpha(8)}`, `xapp-${alpha(260)}`, `xapp-_${alpha(20)}`, `xapp-`, `xoxe.`,
    `hf_${alpha(29)}`, `hf_${alpha(65)}`, `hf_-${alpha(30)}`, 'hf_',
    `shpat_${alpha(29)}`, `shpat_${alpha(65)}`, `shpat_-${alpha(32)}`, `shpca_${gen(HEX, 32)}`, `shppa_${gen(HEX, 32)}`,
    `SG.${alpha(7)}.${alpha(20)}`, `SG.${alpha(22)}.${alpha(65)}`, `SG.${alpha(12)}.${alpha(12)}.${alpha(12)}`,
    'SG.', 'SG.mail.example.invalid',
  ];
  const stats = { ACCESS_TOKEN: { tp: 0, fp: 0, fn: 0 }, API_KEY: { tp: 0, fp: 0, fn: 0 } };
  const knownOverCover = ['get SG.internal.services ok', 'SG.Internal.Services'];
  for (const [value, subtype] of positive) {
    const text = `before ${value} after`;
    const got = spans(text, run(text));
    const hit = got.find(([found, , matched]) => found === subtype && matched === value);
    if (hit) stats[subtype].tp++;
    else stats[subtype].fn++;
    // Any extra candidate on a bare shape is a false positive for the detector's supported scope.
    stats[subtype].fp += got.length - (hit ? 1 : 0);
  }
  const trueNegatives = { ACCESS_TOKEN: 0, API_KEY: 0 };
  for (const text of negative) {
    const got = run(text).candidates;
    assert.deepEqual(got.map((candidate) => [candidate.subtype, text.slice(candidate.start, candidate.end)]), [], text.slice(0, 32));
    const subtype = /^SG\./u.test(text) ? 'API_KEY' : 'ACCESS_TOKEN';
    trueNegatives[subtype]++;
  }
  for (const [subtype, { tp, fp, fn }] of Object.entries(stats)) {
    t.diagnostic(`${subtype}: recall ${tp}/${tp + fn}, false positives ${fp}, true negatives ${trueNegatives[subtype]}`);
    assert.equal(fn, 0, `${subtype} false negatives`);
    assert.equal(fp, 0, `${subtype} false positives`);
  }
  t.diagnostic('coverage limits: body bounds are detector scope; out-of-scope vendor families stay undetected');
  // The one accepted over-cover class, counted separately so it is never read as a clean result.
  for (const text of knownOverCover) assert.equal(run(text).candidates.length, 1, text);
  t.diagnostic(`known over-cover: ${knownOverCover.length} dotted-name shapes read as a key (SECRET, fail-safe)`);
});