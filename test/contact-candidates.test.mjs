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
    ['git@host-without-tld', []], ['x@example.c', []], ['..a@example.com', []],
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
