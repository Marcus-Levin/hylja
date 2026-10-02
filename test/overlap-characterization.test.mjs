import assert from 'node:assert/strict';
import { test } from 'node:test';
import { composeClassification } from '../dist/classification.js';
import { detectNormalizedCandidates } from '../dist/normalized-detection.js';
import { createNameDictionary } from '../dist/contact-candidates.js';
import { detectSecrets } from '../dist/secret-detectors.js';
import { parseStructured, rewriteFieldValues } from '../dist/structured-parsers.js';

// Accepted-v1 characterization only: #3 composition, #6/#8 candidate retention and #7 rewrite primitives on
// overlapping, nested, identical and adjacent spans. No proposed module is used here, so every assertion
// below describes accepted behavior that #114 must preserve. Synthetic values only: reserved `.invalid`
// hosts, invented names, invented tokens.
const scope = Object.freeze({ tenantRef: 'tenant-a.invalid', projectRef: 'project-a.invalid' });
const context = Object.freeze({ interactionRef: 'syn-interaction-1', sourceRef: 'syn-source-1', trust: 'CONTROL' });
const names = createNameDictionary(scope, ['Ariadne Exampleperson']);
const PERSON = 'Ariadne Exampleperson';
const PASSWORD = 'syn-pass-4f2b9c7e1d.invalid';
const TOKEN = 'syn-tok-4f2b9c7e1d.invalid';
const detect = (input, rest = {}) =>
  detectNormalizedCandidates({ input, inputRef: 'syn-overlap-unit', scope, names, ...rest });
const bySpan = (candidates) => [...candidates].sort((a, b) => a.view.span.start - b.view.span.start ||
  b.view.span.end - a.view.span.end).map((item) => `${item.source}/${item.subtype ?? '-'}:${item.view.span.start}-${item.view.span.end}`);
const evidence = (id, semanticType, subtype, extra = {}) => ({
  version: 1,
  id,
  status: 'FOUND',
  provenance: { inputRef: 'syn-unit-1', producerId: 'syn.producer', producerVersion: '1' },
  claim: { semanticType, subtype, ...extra },
});
const permutations = (items) => {
  const out = [];
  const walk = (rest, prefix) => {
    if (!rest.length) { out.push(prefix); return; }
    rest.forEach((item, index) => walk([...rest.slice(0, index), ...rest.slice(index + 1)], [...prefix, item]));
  };
  walk(items, []);
  return out;
};

test('accepted #8 keeps every overlapping candidate: a format token inside a containing header value', () => {
  const jwt = ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJzdWIiOiJzeW50aGV0aWMtY2xhaW0iLCJleHAiOjE4MzgzNDA4MDB9',
    'c3ludGhldGljc2lnbmF0dXJlLXZhbHVlLTAx'].join('.');
  const text = `Authorization: Bearer ${jwt}`;
  const result = detectSecrets({ text, inputRef: 'syn-header-unit' });
  assert.equal(result.status, 'COMPLETE');
  assert.deepEqual(result.candidates.map((item) => [item.subtype, item.rule, item.start, item.end]), [
    ['ACCESS_TOKEN', 'context.key-assignment', 15, 152],
    ['ACCESS_TOKEN', 'format.jwt', 22, 152],
  ]);
  // The containing header value and the nested format match keep separate evidence ids; neither is dropped.
  assert.equal(new Set(result.candidates.map((item) => item.evidence.id)).size, 2);
  const [outer, inner] = result.candidates;
  assert.ok(outer.start <= inner.start && outer.end >= inner.end);
  assert.equal(outer.evidence.claim.semanticType, 'CREDENTIAL_OR_SECRET');
  assert.equal(outer.evidence.claim.sensitivity, 'SECRET');
  assert.equal(outer.evidence.claim.reversible, false);
});

test('accepted #6 keeps a native SECRET nested inside larger PERSON and URL evidence', () => {
  const input = JSON.stringify({ endpoint: `https://user:${PASSWORD}@svc.example.invalid/v1` });
  const result = detect(input);
  assert.equal(result.status, 'COMPLETE');
  const spans = bySpan(result.candidates);
  const secret = result.candidates.find((item) => item.source === 'SECRET' && item.subtype === 'PASSWORD');
  const url = result.candidates.find((item) => item.rule === 'format.url');
  const email = result.candidates.find((item) => item.source === 'CONTACT' && item.subtype === 'EMAIL');
  assert.ok(secret && url && email, spans.join(' '));
  // Nested: a wider URL span and a wider PERSON/EMAIL span both contain the secret span.
  assert.ok(url.view.span.start < secret.view.span.start && url.view.span.end > secret.view.span.end);
  assert.ok(email.view.span.start <= secret.view.span.start && email.view.span.end > secret.view.span.end);
  assert.notDeepEqual(email.view.span, secret.view.span);
  assert.equal(secret.original.kind, 'ORIGINAL_EXACT');
  assert.equal(input.slice(secret.original.span.start, secret.original.span.end), PASSWORD);
  // Every overlapping candidate keeps its own evidence id and producer attribution.
  assert.equal(new Set(result.candidates.map((item) => item.evidence.id)).size, result.candidates.length);
  assert.deepEqual([...new Set(result.candidates.map((item) => item.evidence.provenance.producerId))].sort(),
    ['hylja.contact-candidates', 'hylja.infrastructure-identifiers', 'hylja.secret-detectors']);
});

test('accepted #6 reports equal contradictory spans from different detectors instead of choosing one', () => {
  const input = JSON.stringify({ endpoint: `https://user:${PASSWORD}@svc.example.invalid/v1` });
  const result = detect(input);
  const start = result.candidates.find((item) => item.source === 'SECRET').view.span.start;
  const end = result.candidates.find((item) => item.source === 'SECRET').view.span.end;
  const equal = result.candidates.filter((item) => item.view.span.start === start && item.view.span.end === end);
  // The same byte range is a credential AND a host: accepted v1 reports both and ranks neither.
  assert.deepEqual(equal.map((item) => [item.source, item.subtype ?? '-']).sort(),
    [['INFRASTRUCTURE', 'HOST_OR_SERVICE'], ['SECRET', 'PASSWORD']]);
  for (const item of equal) assert.equal(item.original.kind, 'ORIGINAL_EXACT');
  assert.equal(JSON.stringify(result).includes(PASSWORD), false);
});

test('accepted #3 composes a nested SECRET/PERSON pair as unresolved with the SECRET floor preserved', () => {
  const pair = [
    evidence('ev.secret.1', 'CREDENTIAL_OR_SECRET', 'PASSWORD', { sensitivity: 'SECRET' }),
    evidence('ev.person.1', 'PERSON', 'NAME', { sensitivity: 'INTERNAL' }),
  ];
  for (const order of permutations(pair)) {
    const composed = composeClassification({ detectorEvidence: order }, context);
    assert.equal(composed.status, 'UNRESOLVED');
    assert.equal(composed.semanticType, 'UNKNOWN');
    // Highest claimed sensitivity is retained; a contradicting non-secret claim cannot lower it.
    assert.equal(composed.sensitivity, 'SECRET');
    assert.equal(composed.reversible, false);
    assert.equal(composed.scope, 'request');
    assert.ok(composed.reasons.includes('CONFLICTING_SEMANTIC_TYPE'));
    assert.deepEqual(composed.reasons, [...composed.reasons].sort());
    assert.equal(composed.evidence.length, 2);
    assert.equal(composeClassification({ detectorEvidence: order }, context).reasons.join(),
      composed.reasons.join());
  }
});

test('accepted #3 keeps the credential floor when a semantic judgment swaps confidence between the pair', () => {
  const pair = [
    evidence('ev.secret.1', 'CREDENTIAL_OR_SECRET', 'PASSWORD', { sensitivity: 'SECRET' }),
    evidence('ev.person.1', 'PERSON', 'NAME', { sensitivity: 'INTERNAL' }),
  ];
  const semantic = (id, semanticType, confidence) => ({
    version: 1,
    id,
    status: 'FOUND',
    provenance: { inputRef: 'syn-unit-1', producerId: 'syn.shadow', producerVersion: '1',
      questionSetVersion: 'syn-questions-1', modelId: 'syn-model-1' },
    claim: { semanticType, confidence },
  });
  for (const [highId, lowId] of [['ev.secret.1', 'ev.person.1'], ['ev.person.1', 'ev.secret.1']]) {
    const composed = composeClassification({ detectorEvidence: pair,
      semanticJudgments: [semantic('ev.sem.high', highId === 'ev.secret.1' ? 'CREDENTIAL_OR_SECRET' : 'PERSON', 0.99),
        semantic('ev.sem.low', lowId === 'ev.secret.1' ? 'CREDENTIAL_OR_SECRET' : 'PERSON', 0.01)] }, context);
    assert.equal(composed.sensitivity, 'SECRET');
    assert.equal(composed.reversible, false);
    assert.equal(composed.status, 'UNRESOLVED');
    assert.ok(composed.reasons.includes('CONFLICTING_SEMANTIC_TYPE'));
  }
  // A confident PUBLIC semantic judgment about a credential region still cannot downgrade the floor.
  const downgrade = composeClassification({ detectorEvidence: pair,
    semanticJudgments: [semantic('ev.sem.public', 'CREDENTIAL_OR_SECRET', 0.99)] }, context);
  assert.equal(downgrade.sensitivity, 'SECRET');
  assert.equal(downgrade.reversible, false);
});

test('accepted #6 keeps repeated identical field values at their own source locations', () => {
  const input = JSON.stringify({ accessToken: TOKEN, refreshToken: TOKEN });
  const result = detect(input);
  const spans = result.candidates.filter((item) => item.field && item.source === 'SECRET')
    .map((item) => `${item.field.span.start}-${item.field.span.end}`);
  assert.deepEqual(spans, ['16-42', '60-86']);
  assert.equal(new Set(result.candidates.filter((item) => item.field).map((item) => item.field.pathRef)).size, 2);
  for (const item of result.candidates.filter((candidate) => candidate.field)) {
    assert.equal(item.original.kind, 'ORIGINAL_EXACT');
    assert.equal(input.slice(item.original.span.start, item.original.span.end), TOKEN);
  }
  assert.equal(JSON.stringify(result).includes(TOKEN), false);
});

test('accepted #6 keeps overlapping candidates from different sources on the same span and field', () => {
  const input = JSON.stringify({ token: TOKEN });
  const result = detect(input);
  const overlapped = result.candidates.filter((item) => item.original.kind === 'ORIGINAL_EXACT' &&
    input.slice(item.original.span.start, item.original.span.end) === TOKEN);
  assert.deepEqual([...new Set(overlapped.map((item) => `${item.source}/${item.subtype ?? '-'}/${item.rule ?? '-'}`))].sort(),
    ['INFRASTRUCTURE/HOST_OR_SERVICE/format.dns-name', 'SECRET/ACCESS_TOKEN/context.field-key',
      'SECRET/ACCESS_TOKEN/context.key-assignment']);
  assert.equal(new Set(overlapped.map((item) => item.evidence.id)).size, overlapped.length);
});

test('accepted #7 rewrites several overlapping field values in one verified pass', () => {
  const input = JSON.stringify({ endpoint: `https://user:${PASSWORD}@svc.example.invalid/v1`, token: TOKEN });
  const parsed = parseStructured(input, 'JSON');
  assert.equal(parsed.status, 'COMPLETE');
  const out = rewriteFieldValues(input, 'JSON', parsed.fields.map((field) => ({ field, replacement: '****' })));
  assert.equal(out.status, 'OK');
  assert.equal(out.text, '{"endpoint":"****","token":"****"}');
  assert.equal(out.text.includes(PASSWORD), false);
  assert.equal(out.text.includes(TOKEN), false);
  // Key paths survive and only the edited values changed.
  const after = parseStructured(out.text, 'JSON');
  assert.deepEqual(after.fields.map((field) => field.path.join('.')), ['endpoint', 'token']);
  assert.deepEqual(after.fields.map((field) => field.value), ['****', '****']);
});

test('accepted #7 refuses ambiguous and commented sources instead of rewriting them', () => {
  const duplicateKeys = `{"password":"syn-pass.invalid","password":"syn-pass.invalid"}`;
  const parsed = parseStructured(duplicateKeys, 'JSON');
  assert.deepEqual([parsed.status, parsed.reasons], ['COMPLETE', ['DUPLICATE_KEY']]);
  assert.deepEqual(rewriteFieldValues(duplicateKeys, 'JSON',
    parsed.fields.map((field) => ({ field, replacement: '****' }))), { status: 'FAILURE', reason: 'SOURCE_AMBIGUOUS' });

  const commented = '# synthetic note\nPASSWORD=syn-pass.invalid\n';
  const env = parseStructured(commented, 'DOTENV');
  assert.equal(env.status, 'COMPLETE');
  assert.equal(env.comments.length, 1);
  assert.deepEqual(rewriteFieldValues(commented, 'DOTENV',
    env.fields.map((field) => ({ field, replacement: 'redacted' }))), { status: 'FAILURE', reason: 'SOURCE_HAS_COMMENTS' });

  const bare = 'PASSWORD=syn-pass.invalid\n';
  const bareFields = parseStructured(bare, 'DOTENV').fields;
  assert.deepEqual(rewriteFieldValues(bare, 'DOTENV', [{ field: bareFields[0], replacement: '****' }]),
    { status: 'FAILURE', reason: 'UNENCODABLE_REPLACEMENT' });
  const removable = rewriteFieldValues(bare, 'DOTENV', [{ field: bareFields[0], replacement: 'redacted' }]);
  assert.deepEqual(removable, { status: 'OK', text: 'PASSWORD=redacted\n' });
});

test('accepted #7 rewrites an escaped field value as a whole covering span', () => {
  const input = '{"password":"syn\\\\u0074hetic-pass.invalid","region":"eu"}';
  const parsed = parseStructured(input, 'JSON');
  const out = rewriteFieldValues(input, 'JSON', [{ field: parsed.fields[0], replacement: '****' }]);
  assert.deepEqual(out, { status: 'OK', text: '{"password":"****","region":"eu"}' });
  assert.equal(out.text.includes('u0074hetic-pass'), false);
  // The escaped spelling in the source is what the rewrite removed; the decoded value never existed as bytes.
  assert.equal(input.slice(parsed.fields[0].valueStart, parsed.fields[0].valueEnd), 'syn\\\\u0074hetic-pass.invalid');
});

test('accepted #6 covers non-BMP and invisible characters with a source span, never with a folded offset', () => {
  const input = '{"password":"syn-\\ud83d\\ude00-pass.invalid"}';
  const result = detect(input);
  assert.equal(result.status, 'COMPLETE');
  const hinted = result.candidates.filter((item) => item.field && item.source === 'SECRET');
  assert.equal(hinted.length, 1);
  assert.equal(hinted[0].field.verbatim, false);
  assert.equal(hinted[0].original.kind, 'ORIGINAL_COVER');
  assert.equal(hinted[0].original.span.start, hinted[0].field.span.start);
  assert.equal(hinted[0].original.span.end, hinted[0].field.span.end);
  assert.equal(JSON.stringify(result).includes('\\ud83d\\ude00-pass'), false);
});

test('accepted #6 folds a real invisible character back onto a covering raw span', () => {
  // `JSON.stringify` keeps an actual U+200B in the source text, so the compatibility fold has work to do and
  // the mapped span really is a covering one. A literal backslash-u escape would fold nothing and assert
  // nothing, which is why this group uses the real character.
  const input = JSON.stringify({ password: 'syn\u200b-pass.invalid' });
  assert.equal(input.includes('\u200b'), true);
  const result = detect(input);
  const folded = result.candidates.filter((item) => item.view.representation === 'FOLDED');
  assert.equal(result.status, 'COMPLETE');
  assert.ok(folded.length >= 1);
  for (const item of folded) {
    assert.equal(item.original.kind, 'ORIGINAL_COVER');
    assert.ok(input.slice(item.original.span.start, item.original.span.end).includes('\u200b'));
  }
  const raw = result.candidates.filter((item) => item.view.representation === 'RAW' && item.field);
  assert.equal(raw.length, 1);
  // The verbatim raw reading is exact; the folded readings of the same occurrence only claim a covering span.
  assert.equal(raw[0].original.kind, 'ORIGINAL_EXACT');
  assert.equal(raw[0].field.verbatim, true);
  assert.deepEqual(raw[0].view.span, folded[0].view.span);
  // The raw and folded readings of the same occurrence keep separate evidence and the same raw location.
  assert.equal(new Set(result.candidates.map((item) => item.evidence.id)).size, result.candidates.length);
});
