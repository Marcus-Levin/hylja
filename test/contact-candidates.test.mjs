import assert from 'node:assert/strict';
import { test } from 'node:test';
import { composeClassification } from '../dist/classification.js';
import {
  generateContactCandidates, createNameDictionary, MAX_TEXT_UNITS, CONTACT_PRODUCER,
} from '../dist/contact-candidates.js';

// Synthetic only: example.com/.invalid domains, the 555-01xx fictional range, invented names.
const scopeA = Object.freeze({ tenantRef: 'tenant-a.invalid', projectRef: 'project-a.invalid' });
const scopeB = Object.freeze({ tenantRef: 'tenant-b.invalid', projectRef: 'project-b.invalid' });
const namesA = createNameDictionary(scopeA, ['Orla Synthetica', 'Brannick Testvold', 'Orla']);
const namesB = createNameDictionary(scopeB, ['Quillon Fakeworth']);
const run = (text, more = {}) => generateContactCandidates({ text, inputRef: 'field-a.invalid', scope: scopeA,
  names: namesA, ...more });
const spans = (text, result) => result.candidates.map((c) => [c.subtype, text.slice(c.start, c.end)]);
const phones = (text, more) => spans(text, run(text, more)).filter(([subtype]) => subtype === 'PHONE');

// Runtime-assembled, obviously synthetic structured rows: `20255501xx` is the fictional 555-01xx range, and
// every host is `example.com`/`.invalid`. Nothing below is a real contact value.
const docDigits = (last) => `2025550${String(last).padStart(3, '0')}`;
const jsonField = (key, value) => `{"${key}":"${value}"}`;
const xmlElement = (key, value) => `<${key}>${value}</${key}>`;

function prng(seed) {
  let state = seed >>> 0;
  return () => { state = (state + 0x6d2b79f5) >>> 0; let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const pick = (random, list) => list[Math.floor(random() * list.length)];

test('finds synthetic EMAIL, PHONE and configured NAME candidates with exact spans', () => {
  const text = 'Escalate to Orla Synthetica <orla.s@support.example.com>, phone +1 202-555-0143.';
  assert.deepEqual(spans(text, run(text)), [
    ['NAME', 'Orla Synthetica'], ['NAME', 'orla'], ['EMAIL', 'orla.s@support.example.com'],
    ['PHONE', '+1 202-555-0143'],
  ]);
});

test('technical values that look numeric are not phone candidates', () => {
  for (const text of [
    'connect 192.0.2.10:8443', 'version 10.20.300.4000', 'date 2026-09-26', 'at 2026-09-26T10:00:00Z',
    'uuid 123e4567-e89b-12d3-a456-426614174000', 'mac 00:1B:44:11:3A:B7', 'net 198.51.100.0/24',
    'request id 20260926123456', 'port 443 and 8443', 'epoch 1790000000000', 'sha 3f2a1b9c0d4e5f60718293a4b5c6d7e8',
    'host node-2025550143.example.com', 'path /var/log/2025550143/app', 'ref #2025550143', 'k=2025550143',
    'v2025.555.0143', 'user id: 2025550143x',
  ]) assert.deepEqual(spans(text, run(text)).filter(([s]) => s === 'PHONE'), [], text);
});

test('phone layouts: international, grouped, parenthesized and keyword-introduced digit runs', () => {
  for (const [text, expected] of [
    ['call +1 202 555 0147 now', '+1 202 555 0147'], ['(202) 555-0199', '(202) 555-0199'],
    ['tel: 2025550188', '2025550188'], ['Mobil 0046 70 000 0000', '0046 70 000 0000'],
    ['fax. 202.555.0100', '202.555.0100'], ['ring 202-555-0111.', '202-555-0111'],
  ]) assert.deepEqual(spans(text, run(text)).filter(([s]) => s === 'PHONE'), [['PHONE', expected]], text);
  // A bare digit run without a prefix or keyword is ambiguous and deliberately not emitted.
  assert.deepEqual(spans('2025550188', run('2025550188')), []);
});

test('email boundaries: no partial local parts, trailing dots or TLD-less hosts', () => {
  for (const [text, expected] of [
    ['mail a.b-c+tag@mail.example.com.', ['a.b-c+tag@mail.example.com']],
    ['git@host-without-tld', []], ['x@example.c', []], ['..a@example.com', ['a@example.com']],
    ['user@@example.com', []], ['first@example.com,second@example.invalid', ['first@example.com', 'second@example.invalid']],
  ]) assert.deepEqual(spans(text, run(text)).filter(([s]) => s === 'EMAIL').map(([, v]) => v), expected, text);
});

test('configured names are tenant/project scoped: another scope never matches or leaks', () => {
  const text = 'Quillon Fakeworth and Orla Synthetica joined.';
  const a = run(text);
  assert.deepEqual(spans(text, a), [['NAME', 'Orla Synthetica']]);
  const mismatch = run(text, { names: namesB });
  assert.deepEqual(spans(text, mismatch), []);
  assert.deepEqual(mismatch.reasons, ['NAME_DICTIONARY_SCOPE_MISMATCH']);
  assert.equal(mismatch.status, 'PARTIAL');
  // Same tenant, different project is also a mismatch.
  const otherProject = run(text, { scope: { tenantRef: scopeA.tenantRef, projectRef: 'project-z.invalid' } });
  assert.ok(otherProject.reasons.includes('NAME_DICTIONARY_SCOPE_MISMATCH'));
  for (const result of [a, mismatch, otherProject]) assert.ok(!JSON.stringify(result).includes('Quillon'));
  // A forged dictionary object is not a dictionary.
  const forged = run(text, { names: { tenantRef: scopeA.tenantRef, names: ['Quillon Fakeworth'] } });
  assert.ok(forged.reasons.includes('INVALID_NAME_DICTIONARY'));
  assert.equal(forged.status, 'PARTIAL');
  assert.deepEqual(spans(text, forged), []);
});

test('results carry spans and evidence, never the matched values', () => {
  const text = 'Orla Synthetica orla.s@support.example.com +1 202-555-0143';
  const serialized = JSON.stringify(run(text));
  for (const value of ['Orla', 'orla.s', 'support.example.com', '555-0143']) assert.ok(!serialized.includes(value), value);
});

test('evidence is valid v1 detector evidence that composes conservatively without sensitivity', () => {
  const result = run('desk.s@support.example.com');
  const [candidate] = result.candidates;
  assert.equal(candidate.evidence.provenance.producerId, CONTACT_PRODUCER.id);
  const composed = composeClassification({ detectorEvidence: result.candidates.map((c) => c.evidence) },
    { interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
  assert.equal(composed.status, 'UNRESOLVED');
  assert.deepEqual(composed.reasons, ['MISSING_SENSITIVITY']);
  assert.ok(composed.evidence.every((record) => record.status === 'FOUND' && record.source === 'detector'));
  // With trusted-config sensitivity added, the same evidence resolves to PERSON/EMAIL.
  const configured = composeClassification({ detectorEvidence: result.candidates.map((c) =>
    ({ ...c.evidence, claim: { ...c.evidence.claim, sensitivity: 'CONFIDENTIAL' } })) },
  { interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
  assert.equal(configured.status, 'RESOLVED');
  assert.equal(configured.subtype, 'EMAIL');
  assert.equal(composed.reversible, false);
  // Distinct ids for every candidate so composition cannot collapse them.
  const many = run('a@example.com b@example.com c@example.com');
  assert.equal(new Set(many.candidates.map((c) => c.evidence.id)).size, 3);
});

test('trusted field hints cover the trimmed field; payload text cannot set them', () => {
  const result = run('  Orlaith Unlisted  ', { fieldHint: 'NAME' });
  assert.deepEqual(spans('  Orlaith Unlisted  ', result), [['NAME', 'Orlaith Unlisted']]);
  assert.equal(result.candidates[0].basis, 'FIELD_HINT');
  assert.equal(run('text', { fieldHint: 'SECRET' }).status, 'FAILURE');
});

test('code-point spans stay aligned after astral characters', () => {
  const text = '📞🧪 Orla: orla@example.com';
  const email = run(text).candidates.find((c) => c.subtype === 'EMAIL');
  assert.equal([...text].slice(email.codePointStart, email.codePointEnd).join(''), 'orla@example.com');
  assert.equal(email.end - email.start, email.codePointEnd - email.codePointStart);
});

test('failures are explicit and never read as "no contact data"', () => {
  for (const [request, reason] of [
    [{ text: 42, inputRef: 'x', scope: scopeA }, 'INVALID_REQUEST'],
    [{ text: 'a', inputRef: '', scope: scopeA }, 'INVALID_REQUEST'],
    [{ text: 'a', inputRef: 'x', scope: { tenantRef: 'a' } }, 'INVALID_REQUEST'],
    [{ text: 'a'.repeat(MAX_TEXT_UNITS + 1), inputRef: 'x', scope: scopeA }, 'INPUT_TOO_LARGE'],
    [{ text: 'bad \uD800 surrogate', inputRef: 'x', scope: scopeA }, 'INVALID_TEXT'],
    [{ text: Array.from({ length: 5000 }, (_, i) => `u${i}@example.com`).join(' '), inputRef: 'x', scope: scopeA },
      'TOO_MANY_CANDIDATES'],
  ]) {
    const result = generateContactCandidates(request);
    assert.equal(result.status, 'FAILURE', reason);
    assert.deepEqual(result.reasons, [reason]);
    assert.deepEqual(result.candidates, []);
  }
  const getter = { inputRef: 'x', scope: scopeA };
  Object.defineProperty(getter, 'text', { get() { throw new Error('synthetic-planted.invalid'); } });
  assert.deepEqual(generateContactCandidates(getter).reasons, ['INVALID_REQUEST']);
  // A decomposed character elsewhere no longer disables name matching; offsets map back to the input.
  const decomposed = 'Cafe\u0301 Orla Synthetica';
  assert.deepEqual(spans(decomposed, run(decomposed)), [['NAME', 'Orla Synthetica']]);
  assert.equal(run(decomposed).status, 'COMPLETE');
});

test('name dictionaries reject malformed configuration', () => {
  for (const [scope, names] of [
    [{ tenantRef: '', projectRef: 'p' }, []], [scopeA, 'Orla'], [scopeA, ['']], [scopeA, ['1234']],
    [scopeA, [' padded']], [scopeA, ['x'.repeat(129)]], [scopeA, Array.from({ length: 10_001 }, () => 'Name')],
  ]) assert.throws(() => createNameDictionary(scope, names), TypeError);
  // Regex metacharacters in a configured name are literal.
  const dict = createNameDictionary(scopeA, ['A.B (Synthetic)']);
  assert.deepEqual(spans('AxB (Synthetic) and A.B (Synthetic)', run('AxB (Synthetic) and A.B (Synthetic)', { names: dict })),
    [['NAME', 'A.B (Synthetic']]);
});

test('property: planted synthetic emails and phones are found at their exact spans', () => {
  const random = prng(0x3737);
  const fillers = ['status ok', 'port 8443', 'v1.2.3', 'id 20260926123456', 'at 2026-09-26', '192.0.2.44:443',
    'Ünïcödé 🧪 text', 'path /srv/app', '—', 'retry=3'];
  for (let runIndex = 0; runIndex < 300; runIndex++) {
    const planted = [];
    let text = '';
    for (let part = 0; part < 6; part++) {
      text += `${pick(random, fillers)} `;
      if (random() < 0.5) {
        const value = random() < 0.5 ? `user${runIndex}x${part}@team${part}.example.com` :
          `+1 202-555-01${String(Math.floor(random() * 100)).padStart(2, '0')}`;
        planted.push([value.includes('@') ? 'EMAIL' : 'PHONE', text.length, value]);
        text += `${value} `;
      }
    }
    const result = run(text);
    assert.equal(result.status, 'COMPLETE');
    for (const [subtype, start, value] of planted) {
      assert.ok(result.candidates.some((c) => c.subtype === subtype && c.start === start &&
        c.end === start + value.length), `${text} :: ${value}`);
    }
    // No filler produces a candidate: every candidate is one of the planted values.
    assert.equal(result.candidates.length, planted.length, text);
  }
});

test('adversarial inputs stay within a bounded-work budget', () => {
  for (const text of ['a'.repeat(200_000) + '@', '1-'.repeat(100_000), `${'a.'.repeat(60_000)}@example.com`,
    '('.repeat(100_000) + '1'.repeat(10), `${'x@'.repeat(80_000)}`]) {
    const started = process.hrtime.bigint();
    const result = run(text);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(['COMPLETE', 'FAILURE'].includes(result.status));
    // Generous ceiling: this catches catastrophic backtracking, not a performance SLA.
    assert.ok(elapsedMs < 5000, `${elapsedMs}ms`);
  }
});

test('synthetic golden set: per-subtype recall, precision and false negatives are reported', (t) => {
  // Each row: text and expected [subtype, value] pairs. Not held-out data; a development check only.
  const golden = [
    ['Primary: Orla Synthetica (orla.s@support.example.com), backup Brannick Testvold +1 202-555-0171',
      [['NAME', 'Orla Synthetica'], ['EMAIL', 'orla.s@support.example.com'], ['NAME', 'orla'],
        ['NAME', 'Brannick Testvold'], ['PHONE', '+1 202-555-0171']]],
    ['GET https://api.example.com:8443/health 503 from 192.0.2.10 at 2026-09-26T10:00:00Z', []],
    ['{"owner":"brannick.t@eng.example.invalid","tel":"(202) 555-0123","port":443}',
      [['EMAIL', 'brannick.t@eng.example.invalid'], ['PHONE', '(202) 555-0123']]],
    [`{"owner":"orla.s@support.example.com","phone":"${docDigits(133)}","port":"443"}`,
      [['NAME', 'orla'], ['EMAIL', 'orla.s@support.example.com'], ['PHONE', docDigits(133)]]],
    [`<contact><phone>${docDigits(144)}</phone><email>orla.s@support.example.com</email></contact>`,
      [['PHONE', docDigits(144)], ['NAME', 'orla'], ['EMAIL', 'orla.s@support.example.com']]],
    ['trace 123e4567-e89b-12d3-a456-426614174000 build 2026.09.26.1 rev 10.20.30.40', []],
    ['tel: 2025550133 / mobile 202 555 0144', [['PHONE', '2025550133'], ['PHONE', '202 555 0144']]],
    ['Contact orla via ticket 2025550166', [['NAME', 'orla']]],
  ];
  const stats = { NAME: { tp: 0, fp: 0, fn: 0 }, EMAIL: { tp: 0, fp: 0, fn: 0 }, PHONE: { tp: 0, fp: 0, fn: 0 } };
  for (const [text, expected] of golden) {
    const got = spans(text, run(text)).map(([s, v]) => `${s}:${v}`);
    const want = expected.map(([s, v]) => `${s}:${v}`);
    for (const item of got) stats[item.split(':')[0]][want.includes(item) ? 'tp' : 'fp']++;
    for (const item of want) if (!got.includes(item)) stats[item.split(':')[0]].fn++;
  }
  for (const [subtype, { tp, fp, fn }] of Object.entries(stats)) {
    t.diagnostic(`${subtype}: recall ${tp}/${tp + fn}, precision ${tp}/${tp + fp}, false negatives ${fn}`);
    assert.equal(fn, 0, `${subtype} false negatives`);
    assert.equal(fp, 0, `${subtype} false positives`);
  }
  // These counts cover the golden subset above only. The four known recall-biased PHONE over-candidates
  // (`range 1000-2000`, `ISBN …`, `price 1 234 567 kr`, `order 12345-67890`) are deliberately not in that
  // subset and are pinned separately in "known over-cloaks are pinned", so a perfect number here is a subset
  // result, never an overall precision or false-cloak measurement.
  t.diagnostic(`golden subset: ${golden.length} rows, 4 known PHONE over-candidates excluded and pinned elsewhere`);
});

test('review regressions: parenthesized and keyword-prefixed phones are found with exact spans', () => {
  for (const [text, expected] of [
    ['(call 202-555-0143)', '202-555-0143'], ['(+1 202 555 0143)', '+1 202 555 0143'],
    ['phone: 202-555-0143).', '202-555-0143'], ['Orla (202-555-0143)', '202-555-0143'],
    ['tel:+12025550143', '+12025550143'], ['phone:2025550143', '2025550143'], ['phone=2025550143', '2025550143'],
    ['Phone #2025550143', '2025550143'], ['tel=+1 202 555 0143', '+1 202 555 0143'],
    ['phone number: 2025550143', '2025550143'], ['mob 202 555 0143', '202 555 0143'],
    ['see (202) 555-0199)', '(202) 555-0199'],
  ]) assert.deepEqual(spans(text, run(text)).filter(([s]) => s === 'PHONE'), [['PHONE', expected]], text);
});

test('structured quoted values keep the phone keyword context with an exact-number span', () => {
  // The same digits a plain `phone 2025550133` emits are missed when a JSON string, a quoted property or an XML
  // element/attribute puts a quote or `>` between the keyword and the value. Keyword context is per occurrence,
  // so the span must stay on the digits themselves: the delimiters are never part of the candidate.
  const value = docDigits(133);
  for (const text of [
    jsonField('phone', value), jsonField('tel', value), `{"phone" :"${value}"}`, `{"phone" : "${value}"}`,
    `{"phone"  :  "${value}"}`, `{"phone":"${value}", "port":"443"}`,
    `{phone: "${value}"}`, `phone: "${value}"`, `phone = "${value}"`, `phone="${value}"`, `phone='${value}'`,
    `PHONE="${value}"`, `data-phone="${value}"`, `phone = ${value}`,
    xmlElement('phone', value), `<phone>\n  ${value}\n</phone>`, `<phone number="${value}"/>`,
    `<phone number='${value}' />`, `<contact><phone>${value}</phone><port>443</port></contact>`,
    `<ns:phone>${value}</ns:phone>`,
    // An earlier element's completed `phone` attribute neither suppresses nor misdirects the real phone element.
    `<id phone=""></id><phone>${value}</phone>`,
  ]) {
    const result = run(text);
    assert.deepEqual(phones(text), [['PHONE', value]], JSON.stringify(text));
    assert.equal(result.candidates.filter((c) => c.subtype === 'PHONE').length, 1, JSON.stringify(text));
    assert.equal(result.candidates.find((c) => c.subtype === 'PHONE').basis, 'KEYWORD_CONTEXT', JSON.stringify(text));
    assert.equal(result.status, 'COMPLETE', JSON.stringify(text));
  }
  // Two structured fields are two occurrences: each key supplies context for its own value only.
  const pair = `{"phone":"${value}","mobile":"202 555 0144"}`;
  assert.deepEqual(phones(pair), [['PHONE', value], ['PHONE', '202 555 0144']], pair);
  assert.deepEqual(run(pair).candidates.filter((c) => c.subtype === 'PHONE').map((c) => c.basis),
    ['KEYWORD_CONTEXT', 'KEYWORD_CONTEXT'], pair);
  // A keyword-separated value and a structured value are the same candidate, so a name dictionary, a field
  // hint or a tenant scope cannot tell them apart and the structured spelling cannot dodge the phone check.
  assert.deepEqual(phones(jsonField('phone', value), { fieldHint: 'NAME' }).map(([, v]) => v), [value]);
});

test('only adjacent structured key/value context supplies the phone keyword', () => {
  const value = docDigits(166);
  for (const text of [
    // Non-phone keys: a numeric identifier keeps its behaviour whatever shape the digits have.
    jsonField('port', value), jsonField('user_id', value), jsonField('id', value), `{"count":${value}}`,
    // Keys outside the v1 phone vocabulary. `phoneNumber`/`faxNumber` are inside it (a `\b`-delimited keyword
    // plus the optional `number` suffix), so those are measured as emitted rather than listed here.
    jsonField('phone_number', value), jsonField('mobilePhoneNumber', value), jsonField('phone-no', value),
    jsonField('homePhone', value),
    // Phone-like key, non-phone value: identifiers, dates and too-short values stay refused.
    jsonField('phone', '123e4567-e89b-12d3-a456-426614174000'), jsonField('phone', '2026-09-26T10:00:00Z'),
    jsonField('phone', '2026-09-26'), jsonField('phone', '443'),
    // A keyword that is not adjacent to the number cannot reach it, however close the text.
    `{"note":"call the phone later","ticket":"${value}"}`, `The phone was replaced. Ticket ${value} opened.`,
    `phone: see ticket ${value}`, '<phone>see ticket ' + value + '</phone>',
    // Cross-field reach is not adjacency: a keyword inside a completed attribute names neither the element text
    // that follows the start tag nor the next field's value. `<id phone="">` parses as an empty `@phone`
    // attribute plus the `id` text, so the digits belong to the element, not to the keyword.
    `<id phone="">${value}</id>`, `<id data-phone="">${value}</id>`, `<id phone="" >${value}</id>`,
    `phone="" ${value}`, `{"phone":"","id":"${value}"}`, `<contact phone="">${value}</contact>`,
    // Declared conservative misses: attributes on the phone element itself, and a keyword outside a tag. Base
    // missed both as well; widening the start-tag grammar is a separate, visible decision.
    `<phone lang="en">${value}</phone>`, `phone>${value}`,
    // Documented bound: an unquoted key keeps the four-code-unit separator cap of the base rule, so a wide
    // whitespace gap is not keyword context. Inside a quoted key/value shape the whitespace is bounded by the
    // surrounding window instead, because both quotes and the single separator identify the value.
    `phone:      ${value}`,
  ]) assert.deepEqual(phones(text), [], JSON.stringify(text));
});

test('structured phone evidence stays privacy-safe and keeps Unicode-aligned spans', () => {
  const value = docDigits(177);
  const text = jsonField('phone', value);
  const result = run(text);
  const phone = result.candidates.find((c) => c.subtype === 'PHONE');
  assert.ok(phone);
  assert.equal(phone.evidence.provenance.producerId, CONTACT_PRODUCER.id);
  assert.equal(phone.evidence.claim.semanticType, 'PERSON');
  assert.equal(phone.evidence.claim.subtype, 'PHONE');
  assert.equal(phone.evidence.claim.sensitivity, undefined);
  // Neither the digits nor the key text that produced the candidate leaves the seam.
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes(value), false);
  assert.equal(serialized.includes('"phone"'), false);
  // An astral character before a quoted structured value shifts both offset families by the same amount.
  const astral = `\u{1f4de} ${text}`;
  const astralPhone = run(astral).candidates.find((c) => c.subtype === 'PHONE');
  assert.equal([...astral].slice(astralPhone.codePointStart, astralPhone.codePointEnd).join(''), value);
  assert.equal(astralPhone.end - astralPhone.start, astralPhone.codePointEnd - astralPhone.codePointStart);
});

test('public synthetic development measurement: phone-like keys, numeric identifiers and vocabulary bounds', (t) => {
  // Runtime-assembled, obviously synthetic rows on public development data. This measures #37's own behaviour;
  // it is not held-out data, not a scored evaluation, and says nothing about egress or production traffic.
  const bare = docDigits(122);
  const grouped = `+1 ${bare.replace(/^(\d{3})(\d{3})(\d{4})$/u, '$1-$2-$3')}`;
  const owner = 'Orla Synthetica';
  const mailbox = 'orla.s@support.example.com';
  const rows = [
    // [category, key spelling, text, expected [subtype, value] pairs]
    ['KEYWORD_CONTEXT', 'phone', jsonField('phone', bare), [['PHONE', bare]]],
    ['KEYWORD_CONTEXT', 'tel', jsonField('tel', bare), [['PHONE', bare]]],
    ['KEYWORD_CONTEXT', 'phone + wide json gap', `{"phone"  :  "${bare}"}`, [['PHONE', bare]]],
    ['KEYWORD_CONTEXT', 'phone number', `<phone number="${bare}"/>`, [['PHONE', bare]]],
    // CamelCase forms are inside the v1 vocabulary already: a `\b`-delimited keyword plus its optional
    // `number` suffix, which is why `phoneNumber: 2025550122` was already keyword context before #140.
    ['KEYWORD_CONTEXT', 'phoneNumber', jsonField('phoneNumber', bare), [['PHONE', bare]]],
    ['KEYWORD_CONTEXT', 'faxNumber', jsonField('faxNumber', bare), [['PHONE', bare]]],
    // Value shape alone decides these, with or without a recognized key.
    ['VALUE_SHAPE', 'mobilePhoneNumber', jsonField('mobilePhoneNumber', grouped), [['PHONE', grouped]]],
    ['NON_PHONE_KEY', 'port', jsonField('port', bare), []],
    ['NON_PHONE_KEY', 'user_id', jsonField('user_id', bare), []],
    ['NON_PHONE_KEY', 'count', `{"count":${bare}}`, []],
    ['OUTSIDE_VOCABULARY', 'phone_number', jsonField('phone_number', bare), []],
    ['OUTSIDE_VOCABULARY', 'mobilePhoneNumber', jsonField('mobilePhoneNumber', bare), []],
    ['OUTSIDE_VOCABULARY', 'homePhone', jsonField('homePhone', bare), []],
    ['NON_PHONE_VALUE', 'phone + uuid', jsonField('phone', '123e4567-e89b-12d3-a456-426614174000'), []],
    ['NON_PHONE_VALUE', 'phone + timestamp', jsonField('phone', '2026-09-26T10:00:00Z'), []],
    ['NON_PHONE_VALUE', 'phone + date', jsonField('phone', '2026-09-26'), []],
    ['NON_PHONE_VALUE', 'phone + short', jsonField('phone', '443'), []],
    ['DISTANT_KEYWORD', 'phone in prose', `{"note":"call the phone later","ticket":"${bare}"}`, []],
    ['CROSS_FIELD_KEYWORD', 'empty phone attribute + element text', `<id phone="">${bare}</id>`, []],
    ['CROSS_FIELD_KEYWORD', 'phone key with empty value + id', `{"phone":"","id":"${bare}"}`, []],
    // Declared recall bias, disclosed rather than hidden: an epoch-shaped identifier under a vocabulary phone
    // key is emitted. The plain `phone 1790000000000` spelling already did this before #140; a digit-count or
    // shape rule that refuses it would be a separate, visible precision decision.
    ['RECALL_BIAS', 'phone + epoch-shaped identifier', jsonField('phone', '1790000000000'),
      [['PHONE', '1790000000000']]],
    ['BOUNDED_GAP', 'phone + wide unquoted gap', `phone:      ${bare}`, []],
    // NAME and EMAIL under the same structured context are unaffected and still resolve per subtype.
    ['STRUCTURED_CONTACT', 'json owner/email/phone',
      `{"owner":"${owner}","email":"${mailbox}","phone":"${bare}"}`,
      [['NAME', owner], ['NAME', 'orla'], ['EMAIL', mailbox], ['PHONE', bare]]],
    ['STRUCTURED_CONTACT', 'xml owner/email/phone',
      `<contact><owner>${owner}</owner><email>${mailbox}</email><phone>${bare}</phone></contact>`,
      [['NAME', owner], ['NAME', 'orla'], ['EMAIL', mailbox], ['PHONE', bare]]],
  ];
  const counts = new Map();
  const bySubtype = { NAME: { found: 0, expected: 0 }, EMAIL: { found: 0, expected: 0 }, PHONE: { found: 0, expected: 0 } };
  let phoneFound = 0;
  for (const [category, key, text, expected] of rows) {
    counts.set(category, (counts.get(category) ?? 0) + 1);
    const result = run(text);
    assert.deepEqual(spans(text, result), expected, `${category}/${key}: ${text}`);
    for (const [subtype] of expected) bySubtype[subtype].expected++;
    for (const [subtype] of spans(text, result)) bySubtype[subtype].found++;
    const phone = result.candidates.find((c) => c.subtype === 'PHONE');
    if (phone) { phoneFound++; assert.equal(phone.basis, category === 'VALUE_SHAPE' ? 'PATTERN' : 'KEYWORD_CONTEXT', key); }
  }
  const summary = [...counts].sort().map(([category, count]) => `${category}=${count}`).join(' ');
  t.diagnostic(`#37 phone-key measurement over ${rows.length} synthetic rows: ${summary}`);
  t.diagnostic(`PHONE candidates ${phoneFound}/${rows.filter(([, , , expected]) => expected.some(([s]) => s === 'PHONE')).length} rows ` +
    `have one; NAME ${bySubtype.NAME.found}/${bySubtype.NAME.expected}, EMAIL ${bySubtype.EMAIL.found}/${bySubtype.EMAIL.expected}, ` +
    `PHONE ${bySubtype.PHONE.found}/${bySubtype.PHONE.expected} candidates match their expected span`);
  for (const [subtype, count] of Object.entries(bySubtype)) {
    assert.equal(count.found, count.expected, `${subtype} candidates across the measured rows`);
  }
});

test('review regressions: non-ASCII and RFC local parts are never truncated', () => {
  for (const [text, expected] of [
    ['åsa.test@example.se', 'åsa.test@example.se'], ['müller@example.com', 'müller@example.com'],
    ["o'brien@example.com", "o'brien@example.com"],
    ['josé@example.com', 'josé@example.com'], ['user@exämple.com', 'user@exämple.com'],
    ['user@example.com-', 'user@example.com'], ['user@example.xn--p1ai', 'user@example.xn--p1ai'],
    [`u@${'a.'.repeat(12)}example.com`, `u@${'a.'.repeat(12)}example.com`],
    ['mailto:user@example.com', 'user@example.com'],
  ]) assert.deepEqual(spans(text, run(text)).filter(([s]) => s === 'EMAIL').map(([, v]) => v), [expected], text);
});

test('known over-cloaks are pinned so a precision change is a visible decision', () => {
  // Recall bias: these non-phone digit groups are emitted as PHONE candidates today (see plan).
  for (const text of ['range 1000-2000', 'ISBN 978-3-16-148410-0', 'price 1 234 567 kr', 'order 12345-67890']) {
    assert.equal(spans(text, run(text)).filter(([s]) => s === 'PHONE').length, 1, text);
  }
});

test('evidence ids are unique across fields and composition never collides', () => {
  const a = run('a@example.com', { inputRef: 'field-a.invalid' });
  const b = run('a@example.com', { inputRef: 'field-b.invalid' });
  assert.notEqual(a.candidates[0].evidence.id, b.candidates[0].evidence.id);
  const composed = composeClassification({ detectorEvidence: [...a.candidates, ...b.candidates].map((c) => c.evidence) },
    { interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
  assert.ok(!composed.reasons.includes('DUPLICATE_EVIDENCE_ID'));
  // A COMPLETE result never exceeds the composer's per-channel limit.
  assert.equal(run(Array.from({ length: 257 }, (_, i) => `u${i}@example.com`).join(' ')).status, 'FAILURE');
  assert.equal(run(Array.from({ length: 256 }, (_, i) => `u${i}@example.com`).join(' ')).candidates.length, 256);
});

test('throwing scope getters fail closed as INVALID_REQUEST', () => {
  const scope = {};
  Object.defineProperty(scope, 'tenantRef', { enumerable: true, get() { throw new Error('synthetic.invalid'); } });
  assert.deepEqual(generateContactCandidates({ text: 'x', inputRef: 'x', scope }).reasons, ['INVALID_REQUEST']);
});

test('a 10k-name dictionary scans 1 MiB of adversarial text within a bounded-work budget', () => {
  const names = Array.from({ length: 10_000 }, (_, i) => `Orla Synthname${i.toString(36)} Testvold`);
  const dict = createNameDictionary(scopeA, names);
  for (const text of ['Orla Synthname '.repeat(69_000).slice(0, MAX_TEXT_UNITS), 'lorem ipsum dolor '.repeat(58_000)]) {
    const started = process.hrtime.bigint();
    const result = run(text, { names: dict });
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.equal(result.status, 'COMPLETE');
    // Catches super-linear matching; not a performance SLA.
    assert.ok(elapsedMs < 5000, `${elapsedMs}ms`);
  }
  const text = 'ping orla synthnameA testvold today';
  assert.deepEqual(spans(text, run(text, { names: dict })), [['NAME', 'orla synthnameA testvold']]);
});

test('review regressions: quotes, backticks, paths and URL queries stay outside email spans', () => {
  for (const [text, expected] of [
    ["'user@example.com'", ['user@example.com']], ['`user@example.com`', ['user@example.com']],
    ['"user@example.com"', ['user@example.com']], ['&user@example.com', ['user@example.com']],
    ['?user@example.com', ['user@example.com']], ['https://example.com/path?user=foo@example.com', ['foo@example.com']],
    ['~/.ssh/id@host.example', ['id@host.example']], ['path/to/file@v2.example', ['file@v2.example']],
  ]) assert.deepEqual(spans(text, run(text)).filter(([s]) => s === 'EMAIL').map(([, v]) => v), expected, text);
  // Documented limits: rarer RFC atext starts later, and local parts over 64 characters are not emitted.
  assert.deepEqual(spans('user=x@example.com', run('user=x@example.com')).map(([, v]) => v), ['x@example.com']);
  assert.deepEqual(run(`${'l'.repeat(65)}@example.com`).candidates, []);
});

test('review regressions: names ending in combining marks keep their full span', () => {
  const cases = [
    ['फ़ेक सीता', 'x फ़ेक सीता y'],
    ['Test Kİ', 'call Test Kİ.'],
    ['Fake Aa̱', 'hi Fake Aa̱ there'],
  ];
  for (const [name, text] of cases) {
    const dict = createNameDictionary(scopeA, [name]);
    assert.deepEqual(spans(text, run(text, { names: dict })), [['NAME', name]], name);
  }
  // A configured name never matches inside a longer word that only differs by a trailing mark.
  const ram = createNameDictionary(scopeA, ['राम']);
  assert.deepEqual(spans('रामा', run('रामा', { names: ram })), []);
});

test('dotted runs have a single email start and stay within a bounded-work budget', () => {
  for (const text of ['a.'.repeat(MAX_TEXT_UNITS / 2 - 2) + '@x', 'é.'.repeat(MAX_TEXT_UNITS / 2 - 2),
    'x@' + 'a.'.repeat(MAX_TEXT_UNITS / 2 - 4)]) {
    const started = process.hrtime.bigint();
    run(text);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(elapsedMs < 2000, `${elapsedMs}ms`);
  }
});

// #37 constructor snapshot seam: a dictionary is a single-read structural snapshot of a trusted
// configuration. The helpers below derive fixed booleans/counts only, so a failing assertion can never
// print a planted exception message or a caller object.
function fixedDictionaryError(call) {
  try { call(); return false; } catch (error) {
    return error instanceof TypeError && error.message === 'Invalid name dictionary';
  }
}
const dictionarySpans = (text, names) => spans(text, run(text, { names }));

test('a counting scope getter cannot retarget the dictionary after validation', () => {
  const reads = { tenantRef: 0, projectRef: 0 };
  const diverted = Object.create({});
  Object.defineProperty(diverted, 'tenantRef', { enumerable: true,
    get() { reads.tenantRef++; return reads.tenantRef === 1 ? 'tenant-a.invalid' : 'tenant-x.invalid'; } });
  Object.defineProperty(diverted, 'projectRef', { enumerable: true,
    get() { reads.projectRef++; return reads.projectRef === 1 ? 'project-a.invalid' : 'project-x.invalid'; } });
  const text = 'Orla Synthetica joined the review';
  const names = createNameDictionary(diverted, ['Orla Synthetica']);
  // Each scope field is read once: the value validated is the value bound.
  assert.deepEqual(reads, { tenantRef: 1, projectRef: 1 });
  const validated = generateContactCandidates({ text, inputRef: 'field-a.invalid',
    scope: { tenantRef: 'tenant-a.invalid', projectRef: 'project-a.invalid' }, names });
  assert.deepEqual(spans(text, validated), [['NAME', 'Orla Synthetica']]);
  assert.equal(validated.status, 'COMPLETE');
  // The tuple a second read would have produced never becomes the bound scope.
  const retargeted = generateContactCandidates({ text, inputRef: 'field-a.invalid',
    scope: { tenantRef: 'tenant-x.invalid', projectRef: 'project-x.invalid' }, names });
  assert.deepEqual(spans(text, retargeted), []);
  assert.ok(retargeted.reasons.includes('NAME_DICTIONARY_SCOPE_MISMATCH'));
});

test('names are snapshotted by index: a hostile iterator never runs to copy them', () => {
  const hostiles = [];
  for (const source of [['Orla Synthetica'], Object.freeze(['Orla Synthetica'])]) {
    const names = source.slice();
    Object.defineProperty(names, Symbol.iterator, { configurable: true,
      value() { hostiles.push(true); return [][Symbol.iterator](); } });
    const names2 = createNameDictionary(scopeA, names);
    assert.equal(hostiles.length, 0);
    assert.deepEqual(dictionarySpans('Orla Synthetica joined', names2), [['NAME', 'Orla Synthetica']]);
  }
});

test('each name entry is read exactly once, and a lying length cannot re-enumerate', () => {
  const reads = [0, 0];
  const names = ['Orla Synthetica', 'Brannick Testvold'];
  for (const index of [0, 1]) {
    Object.defineProperty(names, String(index), { configurable: true,
      get() { reads[index]++; return index === 0 ? 'Orla Synthetica' : 'Brannick Testvold'; } });
  }
  const text = 'Orla Synthetica and Brannick Testvold';
  assert.deepEqual(dictionarySpans(text, createNameDictionary(scopeA, names)),
    [['NAME', 'Orla Synthetica'], ['NAME', 'Brannick Testvold']]);
  assert.deepEqual(reads, [1, 1]);
  // A length that claims entries the array never holds is refused once, with the length read once.
  // The proxy stands in for an array whose length lies: Array.isArray still approves it, so the one
  // trusted read of its length and indices is what decides, never its iterator.
  let lengthReads = 0;
  const lying = new Proxy(['Orla Synthetica'], { get(target, key) {
    if (key === 'length') { lengthReads++; return 2; }
    return Reflect.get(target, key);
  } });
  assert.equal(Array.isArray(lying), true);
  assert.equal(fixedDictionaryError(() => createNameDictionary(scopeA, lying)), true);
  assert.equal(lengthReads, 1);
});

test('a throwing scope field, names length or name accessor fails with the fixed dictionary error', () => {
  const throwingLength = new Proxy(['Orla Synthetica'], { get(target, key) {
    if (key === 'length') throw new Error('synthetic-planted-length.invalid');
    return Reflect.get(target, key);
  } });
  const throwingIndex = new Proxy(['Orla Synthetica'], { get(target, key) {
    if (key === '0') throw new Error('synthetic-planted-index.invalid');
    return Reflect.get(target, key);
  } });
  const hostileScope = {};
  Object.defineProperty(hostileScope, 'tenantRef', { enumerable: true,
    get() { throw new Error('synthetic-planted-scope.invalid'); } });
  Object.defineProperty(hostileScope, 'projectRef', { enumerable: true, value: 'project-a.invalid' });
  for (const call of [
    () => createNameDictionary(hostileScope, ['Orla Synthetica']),
    () => createNameDictionary(scopeA, throwingLength),
    () => createNameDictionary(scopeA, throwingIndex),
    () => createNameDictionary(scopeA, ['Orla Synthetica', , 'Brannick Testvold']),
  ]) assert.equal(fixedDictionaryError(call), true);
});

test('ordinary, frozen, null-prototype, inherited-accessor and accessor scopes and arrays still construct', () => {
  const scopes = [
    scopeA,
    Object.freeze({ tenantRef: scopeA.tenantRef, projectRef: scopeA.projectRef }),
    Object.assign(Object.create(null), { tenantRef: scopeA.tenantRef, projectRef: scopeA.projectRef }),
    Object.create({ get tenantRef() { return scopeA.tenantRef; }, get projectRef() { return scopeA.projectRef; } }),
    { get tenantRef() { return scopeA.tenantRef; }, get projectRef() { return scopeA.projectRef; } },
  ];
  const nameLists = [
    ['Orla Synthetica'],
    Object.freeze(['Orla Synthetica']),
    Object.assign(['Orla Synthetica'], Object.create(null)),
  ];
  for (const scope of scopes) {
    for (const list of nameLists) {
      const names = createNameDictionary(scope, list);
      const text = 'Orla Synthetica joined';
      const result = generateContactCandidates({ text, inputRef: 'field-a.invalid', scope: scopeA, names });
      assert.deepEqual(spans(text, result), [['NAME', 'Orla Synthetica']]);
      assert.equal(result.status, 'COMPLETE');
    }
  }
  // An entry read through an accessor keeps its exact UTF and regex-literal spelling.
  const utf = 'Caf\u00e9 Synthetic', literal = 'A.B (Synthetic)';
  const accessed = [utf, literal];
  Object.defineProperty(accessed, '0', { configurable: true, get() { return utf; } });
  Object.defineProperty(accessed, '1', { configurable: true, get() { return literal; } });
  const dict = createNameDictionary(scopeA, accessed);
  const text = 'A.B (Synthetic) and Caf\u00e9 Synthetic';
  assert.deepEqual(dictionarySpans(text, dict), [['NAME', 'A.B (Synthetic'], ['NAME', 'Caf\u00e9 Synthetic']]);
});

test('mutating the caller scope or names after construction cannot retarget the snapshot', () => {
  const scope = { tenantRef: scopeA.tenantRef, projectRef: scopeA.projectRef };
  const names = ['Orla Synthetica'];
  const text = 'Orla Synthetica and Quillon Fakeworth';
  const names1 = createNameDictionary(scope, names);
  scope.tenantRef = 'tenant-b.invalid';
  scope.projectRef = 'project-b.invalid';
  names.push('Quillon Fakeworth');
  names[0] = 'Quillon Fakeworth';
  assert.deepEqual(dictionarySpans(text, names1), [['NAME', 'Orla Synthetica']]);
});

test('fresh two-handle dictionaries stay isolated in both scope directions', () => {
  const text = 'Orla Synthetica joined';
  const a = createNameDictionary(scopeA, ['Orla Synthetica']);
  const b = createNameDictionary(scopeB, ['Orla Synthetica']);
  const underA = generateContactCandidates({ text, inputRef: 'field-a.invalid', scope: scopeA, names: a });
  const bUnderA = generateContactCandidates({ text, inputRef: 'field-a.invalid', scope: scopeA, names: b });
  const aUnderB = generateContactCandidates({ text, inputRef: 'field-a.invalid', scope: scopeB, names: a });
  assert.deepEqual(spans(text, underA), [['NAME', 'Orla Synthetica']]);
  assert.deepEqual(spans(text, bUnderA), []);
  assert.deepEqual(spans(text, aUnderB), []);
  for (const result of [bUnderA, aUnderB]) {
    assert.ok(result.reasons.includes('NAME_DICTIONARY_SCOPE_MISMATCH'));
    assert.equal(result.status, 'PARTIAL');
  }
});

test('second rereview regressions: leading dots and invisible marks do not hide contacts', () => {
  for (const [text, expected] of [
    ['.john@example.com', ['john@example.com']], ["'.john@example.com", ['john@example.com']], ['Contact me...john@example.com', ['john@example.com']],
    ['first..last@example.com', ['last@example.com']], ['user@example.cóm', ['user@example.cóm']],
  ]) assert.deepEqual(spans(text, run(text)).filter(([s]) => s === 'EMAIL').map(([, v]) => v), expected, text);
  for (const text of ['Orla Synthetica️', 'Orla͏ Synthetica', '͏Orla Synthetica', 'Orla︎ Synthetica',
    ' ́Orla Synthetica']) {
    const names = spans(text, run(text)).filter(([s]) => s === 'NAME').map(([, v]) => v.replace(/[͏︎️]/gu, ''));
    assert.ok(names.includes('Orla Synthetica'), JSON.stringify(text));
  }
});
