import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { createNameDictionary } from '../dist/contact-candidates.js';
import { detectNormalizedCandidates } from '../dist/normalized-detection.js';

const scope = Object.freeze({ tenantRef: 'tenant-a', projectRef: 'project-a' });
const run = (input, rest = {}) => detectNormalizedCandidates({ input, inputRef: 'synthetic-case', scope, ...rest });
const b64 = (value) => Buffer.from(value, 'utf8').toString('base64');
const hex = (value) => Buffer.from(value, 'utf8').toString('hex');
const pct = (value) => [...Buffer.from(value, 'utf8')].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');

test('raw text candidates have exact root offsets and source-specific evidence', () => {
  const names = createNameDictionary(scope, ['Synthetic Visitor']);
  const input = 'Synthetic Visitor wrote synthetic@example.com and password=synthetic-pass.invalid to build.tenant-a.invalid:443';
  const result = run(input, { names });
  assert.equal(result.status, 'COMPLETE');
  for (const [source, subtype, value] of [
    ['CONTACT', 'NAME', 'Synthetic Visitor'], ['CONTACT', 'EMAIL', 'synthetic@example.com'],
    ['SECRET', 'PASSWORD', 'synthetic-pass.invalid'], ['INFRASTRUCTURE', 'HOST_OR_SERVICE', 'build.tenant-a.invalid'],
  ]) {
    const candidate = result.candidates.find((item) => item.source === source && item.subtype === subtype &&
      item.original.kind === 'ORIGINAL_EXACT' && input.slice(item.original.span.start, item.original.span.end) === value);
    assert.ok(candidate, `${source}/${subtype}`);
    assert.equal(candidate.view.viewId, 0);
    assert.equal(candidate.view.representation, 'RAW');
    assert.equal(candidate.evidence.provenance.inputRef.includes(value), false);
  }
  assert.equal(JSON.stringify(result).includes('synthetic-pass.invalid'), false);
});

test('folded Unicode matches map to covering original ranges without rewriting input', () => {
  const input = 'email=ｓｙｎｔｈｅｔｉｃ＠ｅｘａｍｐｌｅ．ｃｏｍ password=synthe\u200btic-pass.invalid';
  const result = run(input);
  assert.equal(result.status, 'COMPLETE');
  const email = result.candidates.find((item) => item.source === 'CONTACT' && item.subtype === 'EMAIL' &&
    item.view.representation === 'FOLDED');
  assert.ok(email);
  assert.equal(email.original.kind, 'ORIGINAL_COVER');
  assert.equal(input.slice(email.original.span.start, email.original.span.end), 'ｓｙｎｔｈｅｔｉｃ＠ｅｘａｍｐｌｅ．ｃｏｍ');
  const secret = result.candidates.find((item) => item.source === 'SECRET' && item.subtype === 'PASSWORD' &&
    item.view.representation === 'FOLDED');
  assert.ok(secret);
  assert.equal(secret.original.kind, 'ORIGINAL_COVER');
  assert.equal(input.slice(secret.original.span.start, secret.original.span.end), 'synthe\u200btic-pass.invalid');
});

test('decoded secret evidence retains every repeated outer encoded run and never claims an exact source span', () => {
  const plaintext = 'password=synthetic-pass.invalid';
  const encoded = b64(plaintext);
  const input = `left=${encoded} right=${encoded}`;
  const result = run(input);
  assert.equal(result.status, 'COMPLETE');
  const secret = result.candidates.find((item) => item.source === 'SECRET' && item.subtype === 'PASSWORD' &&
    item.view.encodingPath.includes('BASE64'));
  assert.ok(secret);
  assert.equal(secret.original.kind, 'ENCODED_RUNS');
  assert.equal(secret.original.spans.length, 2);
  assert.deepEqual(secret.original.spans.map((span) => input.slice(span.start, span.end)), [encoded, encoded]);
  assert.equal(secret.view.span.end > secret.view.span.start, true);
  assert.equal(JSON.stringify(result).includes(plaintext), false);
});

test('nested decoded candidates attribute to outer runs, including when a decoded view is folded', () => {
  const inner = pct('ｐａｓｓｗｏｒｄ=synthetic-pass.invalid');
  const outer = b64(`x=${inner}`);
  const input = `payload=${outer}`;
  const result = run(input);
  assert.equal(result.status, 'COMPLETE');
  const secret = result.candidates.find((item) => item.source === 'SECRET' && item.subtype === 'PASSWORD' &&
    item.view.encodingPath.join('>') === 'BASE64>PERCENT' && item.view.representation === 'FOLDED');
  assert.ok(secret);
  assert.equal(secret.original.kind, 'ENCODED_RUNS');
  assert.equal(input.slice(secret.original.spans[0].start, secret.original.spans[0].end), outer);
});

test('binary strings retain only the encoded envelope, never a fabricated decoded-byte offset', () => {
  const encoded = Buffer.concat([Buffer.from([0]), Buffer.from('password=synthetic-pass.invalid')]).toString('base64');
  const input = `blob=${encoded}`;
  const result = run(input);
  const secret = result.candidates.find((item) => item.source === 'SECRET' && item.subtype === 'PASSWORD' &&
    item.view.form === 'STRINGS');
  assert.ok(secret);
  assert.equal(secret.original.kind, 'ENCODED_RUNS');
  assert.equal(input.slice(secret.original.spans[0].start, secret.original.spans[0].end), encoded);
});

test('byte input reports UTF-8 text offsets, never original byte spans', () => {
  const text = 'é password=synthetic-pass.invalid';
  const result = run(new TextEncoder().encode(text));
  assert.equal(result.status, 'COMPLETE');
  const secret = result.candidates.find((item) => item.source === 'SECRET' && item.subtype === 'PASSWORD' &&
    item.view.viewId === 0 && item.view.representation === 'RAW');
  assert.ok(secret);
  assert.equal(secret.original.kind, 'UTF8_TEXT');
  assert.equal(secret.original.coverage, 'EXACT');
  assert.equal(text.slice(secret.original.span.start, secret.original.span.end), 'synthetic-pass.invalid');
  assert.notEqual(secret.original.span.start, Buffer.from(text).indexOf('synthetic-pass.invalid'));

  const encoded = b64('password=synthetic-pass.invalid');
  const nestedText = `é payload=${encoded}`;
  const nested = run(new TextEncoder().encode(nestedText));
  const decoded = nested.candidates.find((item) => item.source === 'SECRET' && item.subtype === 'PASSWORD' &&
    item.view.encodingPath.includes('BASE64'));
  assert.ok(decoded);
  assert.equal(decoded.original.kind, 'UTF8_ENCODED_RUNS');
  assert.equal(nestedText.slice(decoded.original.spans[0].start, decoded.original.spans[0].end), encoded);
});

test('depth and expansion limits stay PARTIAL and expose opaque original envelopes', () => {
  let encoded = 'password=synthetic-pass.invalid';
  for (let depth = 0; depth < 4; depth++) encoded = b64(encoded);
  const input = `payload=${encoded}`;
  const limited = run(input, { budget: { maxDepth: 1 } });
  assert.equal(limited.status, 'PARTIAL');
  assert.ok(limited.reasons.includes('NORMALIZATION_DEPTH_LIMIT'));
  assert.ok(limited.uninspected.some((item) => item.original.kind === 'ENCODED_RUNS' &&
    item.original.spans.some((span) => input.slice(span.start, span.end) === encoded)));
  assert.equal(limited.candidates.some((item) => item.source === 'SECRET' && item.subtype === 'PASSWORD'), false);
  const expanded = run(`payload=${b64('password=synthetic-pass.invalid')}`, { budget: { maxDecodedUnits: 1 } });
  assert.equal(expanded.status, 'PARTIAL');
  assert.ok(expanded.reasons.includes('NORMALIZATION_EXPANSION_LIMIT'));
});

test('normalization failures and detector exhaustion cannot become COMPLETE', () => {
  const invalidBytes = run(Uint8Array.from([0xff, 0xfe]));
  assert.equal(invalidBytes.status, 'FAILURE');
  assert.deepEqual(invalidBytes.reasons, ['NORMALIZATION_INVALID_UTF8']);
  assert.deepEqual(invalidBytes.candidates, []);
  const many = Array.from({ length: 257 }, (_, index) => `s${index}@example.com`).join(' ');
  const exhausted = run(many);
  assert.equal(exhausted.status, 'PARTIAL');
  assert.ok(exhausted.reasons.includes('CONTACT_TOO_MANY_CANDIDATES'));
  assert.equal(exhausted.candidates.filter((item) => item.source === 'CONTACT').length, 0);
  assert.ok(exhausted.uninspected.some((item) => item.reason === 'CONTACT_TOO_MANY_CANDIDATES' &&
    item.original.kind === 'ORIGINAL_EXACT'));
  const invalidKey = run('password=synthetic-pass.invalid', { fingerprintKey: new Uint8Array(1) });
  assert.equal(invalidKey.status, 'PARTIAL');
  assert.ok(invalidKey.uninspected.some((item) => item.reason === 'SECRET_INVALID_FINGERPRINT_KEY'));
});

test('quoted structured phone fields reach the seam as exact root spans, once per occurrence', () => {
  // #140: a quoted JSON value, a quoted property and an XML element/attribute put a delimiter between the
  // phone keyword and the digits. The #6 seam must still report the PHONE candidate, with exact root offsets,
  // and must not double-count one occurrence through the #7 parsed field that covers the same text.
  const digits = `2025550${String(133).padStart(3, '0')}`;
  for (const input of [`{"phone":"${digits}","port":"443"}`, `phone="${digits}"`,
    `<contact><phone>${digits}</phone><port>443</port></contact>`, `<phone number="${digits}"/>`]) {
    const result = run(input);
    assert.equal(result.status, 'COMPLETE', input);
    const phones = result.candidates.filter((item) => item.source === 'CONTACT' && item.subtype === 'PHONE');
    assert.equal(phones.length, 1, input);
    const [phone] = phones;
    assert.equal(phone.basis, 'KEYWORD_CONTEXT', input);
    assert.equal(phone.view.representation, 'RAW', input);
    assert.equal(phone.original.kind, 'ORIGINAL_EXACT', input);
    assert.equal(input.slice(phone.original.span.start, phone.original.span.end), digits, input);
    // The seam carries metadata only: neither the digits nor the key text that selected the rule appears.
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes(digits), false, input);
    assert.equal(serialized.includes('phone"'), false, input);
  }
  // A number that is not adjacent to a phone keyword keeps its behaviour inside the same structured input.
  const negative = run(`{"port":"${digits}","note":"call the phone later","ticket":"${digits}"}`);
  assert.equal(negative.candidates.some((item) => item.source === 'CONTACT' && item.subtype === 'PHONE'), false);
  // A keyword inside a completed attribute is not key/value context for the element text that follows it.
  // `<id phone="">…</id>` parses as an empty `@phone` attribute plus the `id` text, so the digits are the
  // element's value and no phone keyword names them.
  for (const input of [`<id phone="">${digits}</id>`, `<contact phone="">${digits}</contact>`,
    `<id data-phone="">${digits}</id>`]) {
    const result = run(input);
    assert.equal(result.status, 'COMPLETE', input);
    assert.equal(result.candidates.filter((item) => item.source === 'CONTACT' && item.subtype === 'PHONE').length,
      0, input);
  }
  // The empty attribute of one element neither suppresses nor supplies context for a sibling phone element.
  const siblingsInput = `<contact><id phone=""></id><phone>${digits}</phone><port>443</port></contact>`;
  const siblings = run(siblingsInput);
  assert.equal(siblings.status, 'COMPLETE');
  const siblingPhones = siblings.candidates.filter((item) => item.source === 'CONTACT' && item.subtype === 'PHONE');
  assert.equal(siblingPhones.length, 1);
  assert.equal(siblingPhones[0].basis, 'KEYWORD_CONTEXT');
  assert.equal(siblingPhones[0].original.kind, 'ORIGINAL_EXACT');
  assert.equal(siblingsInput.slice(siblingPhones[0].original.span.start, siblingPhones[0].original.span.end), digits);
});

test('mismatched tenant name dictionary stays partial and never supplies a name candidate', () => {
  const names = createNameDictionary(scope, ['Synthetic Visitor']);
  const result = run('Synthetic Visitor', { scope: { tenantRef: 'tenant-b', projectRef: 'project-a' }, names });
  assert.equal(result.status, 'PARTIAL');
  assert.ok(result.reasons.includes('CONTACT_NAME_DICTIONARY_SCOPE_MISMATCH'));
  assert.equal(result.candidates.some((item) => item.source === 'CONTACT' && item.subtype === 'NAME'), false);
  assert.ok(result.uninspected.some((item) => item.reason === 'CONTACT_NAME_DICTIONARY_SCOPE_MISMATCH'));
});

test('property: bounded supported encodings either surface a planted secret or report incomplete inspection', () => {
  const encoders = [b64, hex, pct];
  for (let index = 0; index < 90; index++) {
    const value = `password=synthetic-pass-${index}.invalid`;
    const encoded = encoders[index % encoders.length](value);
    const result = run(`payload=${encoded}`);
    assert.ok(result.candidates.some((item) => item.source === 'SECRET' && item.subtype === 'PASSWORD' &&
      item.original.kind === 'ENCODED_RUNS') || result.status !== 'COMPLETE', `${index}`);
    assert.equal(JSON.stringify(result).includes(value), false);
  }
});

test('adversarial long encoded-looking input remains bounded and explicitly opaque', () => {
  const input = 'A'.repeat(1 << 20);
  const result = run(input);
  assert.equal(result.status, 'PARTIAL');
  assert.ok(result.reasons.includes('NORMALIZATION_RUN_TOO_LONG'));
  assert.ok(result.candidates.length <= 3 * 256);
  assert.ok(result.uninspected.length <= 1024);
  assert.equal(result.uninspected[0].original.kind, 'ORIGINAL_EXACT');
  assert.equal(input.length, 1 << 20);
});

test('compatibility expansion is PARTIAL with an opaque root even under a 256 MiB heap', () => {
  const script = `
    import { detectNormalizedCandidates } from './dist/normalized-detection.js';
    const result = detectNormalizedCandidates({
      input: '\\uFDFA'.repeat(1 << 20), inputRef: 'synthetic-expansion',
      scope: { tenantRef: 'tenant-a', projectRef: 'project-a' },
    });
    process.stdout.write(JSON.stringify({ status: result.status, reasons: result.reasons,
      opaque: result.uninspected.length, kind: result.uninspected[0]?.original.kind }));
  `;
  const child = spawnSync(process.execPath, ['--max-old-space-size=256', '--input-type=module', '-e', script],
    { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 });
  assert.equal(child.status, 0, `child exit ${child.status}, signal ${child.signal}`);
  const result = JSON.parse(child.stdout);
  assert.equal(result.status, 'PARTIAL');
  assert.ok(result.reasons.includes('FOLD_FAILURE'));
  assert.ok(result.opaque > 0);
  assert.equal(result.kind, 'ORIGINAL_EXACT');
});
