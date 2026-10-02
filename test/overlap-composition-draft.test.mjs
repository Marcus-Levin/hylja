import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { checkEgress, createKnownOriginals } from '../dist/egress-sentinel.js';
import { createNameDictionary } from '../dist/contact-candidates.js';
import { createCandidateConfig } from '../dist/configured-candidates.js';
import { detectNormalizedCandidates } from '../dist/normalized-detection.js';
import { parseStructured } from '../dist/structured-parsers.js';
import { applyOverlapRewrite, composeOverlapRegions, coveredWindowUnits, planOverlapRewrite,
  MAX_FINDINGS, MIN_ECHO_WINDOW } from '../dist/overlap-composition-draft.js';

// Synthetic only. Reserved `.invalid` hosts, invented names, invented tokens and an invented canary.
// The planted originals are registered with #19 directly in this file, independently of any candidate,
// classification or region the draft produces, so a sentinel catch is never credit for a merge.
const scope = Object.freeze({ tenantRef: 'tenant-a.invalid', projectRef: 'project-a.invalid' });
const context = Object.freeze({ interactionRef: 'syn-interaction-1', sourceRef: 'syn-source-1', trust: 'CONTROL' });
const names = createNameDictionary(scope, ['Ariadne Exampleperson']);
const PERSON = 'Ariadne Exampleperson';
const PASSWORD = 'syn-pass-4f2b9c7e1d.invalid';
const TOKEN = 'syn-tok-4f2b9c7e1d.invalid';
const CANARY = 'hylja-synthetic-canary-9f2a.invalid';
const MASK = '****';
const sentinelScope = Object.freeze({ tenantRef: 'tenant-b.invalid', projectRef: 'project-b.invalid' });
const destination = Object.freeze({ id: 'model-gateway.invalid', profileDigest: 'sha256-profile-synthetic' });
const known = createKnownOriginals(sentinelScope, new Uint8Array(32).fill(11), [
  { kind: 'ORIGINAL', value: PASSWORD, ref: 'planted.secret.1' },
  { kind: 'ORIGINAL', value: PERSON, ref: 'planted.person.1' },
  { kind: 'ORIGINAL', value: TOKEN, ref: 'planted.token.1' },
  { kind: 'CANARY', value: CANARY, ref: 'canary.1' },
]);
const enc = (text) => new TextEncoder().encode(text);
const sentinel = (text) => checkEgress({ bytes: enc(text), scope: sentinelScope, destination, authorized: destination, known });
const detect = (input, rest = {}) =>
  detectNormalizedCandidates({ input, inputRef: 'syn-overlap-unit', scope, names, ...rest });
const compose = (findings, more = {}) => composeOverlapRegions({ findings, context, ...more });
const reasonsOf = (result) => [...result.reasons].sort();
const memberIndex = (region) => region.members.map((member) => `${member.semanticType}/${member.subtype ?? '-'}:${member.span.start}-${member.span.end}`);
const regionWith = (composition, semanticType) =>
  composition.regions.find((region) => region.members.some((member) => member.semanticType === semanticType));
const permutations = (items) => {
  const out = [];
  const walk = (rest, prefix) => {
    if (!rest.length) { out.push(prefix); return; }
    rest.forEach((item, index) => walk([...rest.slice(0, index), ...rest.slice(index + 1)], [...prefix, item]));
  };
  walk(items, []);
  return out;
};
/** A second trusted detector's finding in the #6 candidate shape, as #6 itself would emit it. */
const finding = ({ id, start, end, semanticType, subtype, sensitivity, source = 'SECRET', rule = 'syn.rule',
  basis = 'FORMAT', viewId = 0, representation = 'RAW', original, inputRef = 'syn-overlap-unit',
  producerId = 'syn.detector', field = undefined, ...rest }) => ({
  source,
  ...(subtype === undefined ? {} : { subtype }),
  rule,
  basis,
  view: { viewId, span: { start, end }, representation, form: 'TEXT', encodingPath: ['ROOT'] },
  original: original ?? { kind: 'ORIGINAL_EXACT', span: { start, end } },
  evidence: { version: 1, id, status: 'FOUND',
    provenance: { inputRef, producerId, producerVersion: '1' },
    claim: { semanticType, ...(subtype === undefined ? {} : { subtype }),
      ...(sensitivity === undefined ? {} : { sensitivity }) } },
  ...(field === undefined ? {} : { field }),
  ...rest,
});
const secretFinding = (over) => finding({ semanticType: 'CREDENTIAL_OR_SECRET', subtype: 'PASSWORD',
  sensitivity: 'SECRET', ...over });
const personFinding = (over) => finding({ source: 'CONTACT', rule: 'syn.dictionary', basis: 'DICTIONARY',
  semanticType: 'PERSON', subtype: 'NAME', sensitivity: 'INTERNAL', ...over });

test('a native SECRET nested inside wider PERSON and URL evidence keeps the secret floor in one region', () => {
  const input = JSON.stringify({ owner: PERSON, endpoint: `https://user:${PASSWORD}@svc.example.invalid/v1` });
  const detection = detect(input);
  assert.equal(detection.status, 'COMPLETE');
  const composition = compose(detection.candidates);
  assert.equal(composition.retention.received, detection.candidates.length);
  assert.equal(composition.retention.retained, detection.candidates.length);
  assert.equal(composition.retention.rejected, 0);
  assert.equal(composition.status, 'UNRESOLVED');
  const endpoint = regionWith(composition, 'CREDENTIAL_OR_SECRET');
  assert.equal(endpoint.obligations.nonReversibleFloor, true);
  assert.equal(endpoint.composed.sensitivity, 'SECRET');
  assert.equal(endpoint.composed.reversible, false);
  assert.ok(endpoint.composed.reasons.includes('CONFLICTING_SEMANTIC_TYPE'));
  // The wider URL and PERSON/EMAIL spans and the narrower SECRET span are one region, not a winner.
  assert.deepEqual([...new Set(endpoint.obligations.semanticTypes)].sort(),
    ['CREDENTIAL_OR_SECRET', 'HOST_OR_SERVICE', 'NETWORK_IDENTIFIER', 'PERSON']);
  assert.ok(endpoint.members.some((member) => member.semanticType === 'CREDENTIAL_OR_SECRET'));
  assert.ok(endpoint.members.some((member) => member.semanticType === 'PERSON'));
  assert.ok(endpoint.members.some((member) => member.semanticType === 'NETWORK_IDENTIFIER'));
  assert.ok(endpoint.relations.includes('CONTAINING') && endpoint.relations.includes('IDENTICAL'));
  assert.deepEqual(composition.refusals, []);
  assert.deepEqual(composition.adjacencies, []);
  assert.equal(composition.retention.duplicateEvidence, 0);
  assert.deepEqual(composition.retention.bySource, { CONTACT: 2, INFRASTRUCTURE: 3, SECRET: 1 });
  // Every overlapping candidate keeps its own evidence reference and source location.
  assert.equal(new Set(endpoint.members.map((member) => member.evidenceRef)).size, endpoint.members.length);
  for (const member of endpoint.members) {
    assert.equal(member.original.kind, 'ORIGINAL_EXACT');
    assert.ok(member.original.span.start >= 0 && member.original.span.end <= input.length);
    assert.ok(endpoint.span.start <= member.span.start && member.span.end <= endpoint.span.end);
    assert.equal(input.slice(member.span.start, member.span.end).length, member.span.end - member.span.start);
  }
  const owner = composition.regions.find((region) => region !== endpoint);
  assert.equal(owner.obligations.nonReversibleFloor, false);
  // #37 emits no sensitivity of its own, so accepted v1 keeps the name region unresolved for #4 policy.
  assert.equal(owner.composed.sensitivity, 'UNKNOWN');
  assert.equal(owner.composed.status, 'UNRESOLVED');
  assert.ok(owner.composed.reasons.includes('MISSING_SENSITIVITY'));
});

test('detector scores and arrival order cannot weaken a nested secret obligation', () => {
  const findings = [
    secretFinding({ id: 'syn.secret.1', start: 5, end: 15, score: 0.2 }),
    personFinding({ id: 'syn.person.1', start: 0, end: 20, score: 0.99 }),
    finding({ id: 'syn.url.1', start: 0, end: 20, semanticType: 'NETWORK_IDENTIFIER', subtype: 'URL',
      source: 'INFRASTRUCTURE', rule: 'syn.url', sensitivity: 'INTERNAL', score: 0.95 }),
    finding({ id: 'syn.host.1', start: 8, end: 12, semanticType: 'HOST_OR_SERVICE', source: 'INFRASTRUCTURE',
      rule: 'syn.host', sensitivity: 'INTERNAL', score: 0.1 }),
  ];
  const baseline = compose(findings);
  assert.equal(baseline.status, 'UNRESOLVED');
  assert.equal(baseline.regions.length, 1);
  assert.deepEqual(baseline.retention.bySource, { CONTACT: 1, INFRASTRUCTURE: 2, SECRET: 1 });
  assert.deepEqual(baseline.retention.bySemanticType, { CREDENTIAL_OR_SECRET: 1, HOST_OR_SERVICE: 1,
    NETWORK_IDENTIFIER: 1, PERSON: 1 });
  assert.equal(baseline.regions[0].obligations.nonReversibleFloor, true);
  assert.equal(baseline.regions[0].composed.sensitivity, 'SECRET');
  assert.equal(baseline.regions[0].composed.reversible, false);
  assert.deepEqual(baseline.regions[0].relations, ['CONTAINING', 'IDENTICAL']);
  for (const order of permutations(findings)) assert.deepEqual(compose(order), baseline);
  // Swapping every score (including the secret's, to the highest value) changes nothing.
  const swapped = findings.map((item) => ({ ...item, score: 0.99 - item.score }));
  assert.deepEqual(compose(swapped), baseline);
  assert.equal(JSON.stringify(baseline).includes('0.99'), false);
  assert.equal(JSON.stringify(baseline).includes('score'), false);
});

test('equal contradictory spans from two detectors stay one region holding both claims', () => {
  const findings = [
    secretFinding({ id: 'syn.secret.1', start: 10, end: 30 }),
    finding({ id: 'syn.host.1', start: 10, end: 30, semanticType: 'HOST_OR_SERVICE', source: 'INFRASTRUCTURE',
      rule: 'syn.host', sensitivity: 'INTERNAL' }),
  ];
  const composition = compose(findings);
  assert.equal(composition.status, 'UNRESOLVED');
  assert.equal(composition.regions.length, 1);
  const [region] = composition.regions;
  assert.deepEqual(region.members.map((member) => member.evidenceRef).sort(), ['syn.host.1', 'syn.secret.1']);
  assert.deepEqual([...region.obligations.semanticTypes].sort(), ['CREDENTIAL_OR_SECRET', 'HOST_OR_SERVICE']);
  assert.deepEqual([...region.obligations.conflicts].sort(), ['SEMANTIC_TYPE', 'SENSITIVITY']);
  assert.deepEqual(region.relations, ['IDENTICAL']);
  assert.equal(region.obligations.nonReversibleFloor, true);
  assert.equal(region.composed.sensitivity, 'SECRET');
  assert.equal(region.composed.reversible, false);
  assert.ok(region.composed.reasons.includes('CONFLICTING_SEMANTIC_TYPE'));
});

test('containing, partially intersecting and adjacent findings yield deterministic regions', () => {
  const containing = compose([personFinding({ id: 'a', start: 0, end: 20 }), secretFinding({ id: 'b', start: 5, end: 10 })]);
  assert.equal(containing.regions.length, 1);
  assert.deepEqual(containing.regions[0].relations, ['CONTAINING']);
  assert.deepEqual(memberIndex(containing.regions[0]), ['PERSON/NAME:0-20', 'CREDENTIAL_OR_SECRET/PASSWORD:5-10']);

  const partial = compose([secretFinding({ id: 'a', start: 0, end: 10 }), personFinding({ id: 'b', start: 5, end: 15 })]);
  assert.equal(partial.regions.length, 1);
  assert.deepEqual(partial.regions[0].relations, ['PARTIAL']);
  assert.deepEqual(partial.regions[0].span, { start: 0, end: 15 });

  const adjacent = compose([secretFinding({ id: 'a', start: 0, end: 10 }), personFinding({ id: 'b', start: 10, end: 20 })]);
  assert.equal(adjacent.regions.length, 2);
  assert.deepEqual(adjacent.adjacencies.map((item) => item.regionRefs), [['region-0', 'region-1']]);
  assert.deepEqual(adjacent.regions.map((region) => region.span), [{ start: 0, end: 10 }, { start: 10, end: 20 }]);
  assert.deepEqual(adjacent.regions.map((region) => region.obligations.nonReversibleFloor), [true, false]);

  // Region refs, member order and adjacency do not depend on arrival order.
  assert.deepEqual(compose([personFinding({ id: 'b', start: 10, end: 20 }), secretFinding({ id: 'a', start: 0, end: 10 })]),
    adjacent);
  assert.deepEqual(compose([secretFinding({ id: 'b', start: 5, end: 10 }), personFinding({ id: 'a', start: 0, end: 20 })]),
    containing);
  // A one-unit gap is not adjacency.
  const apart = compose([secretFinding({ id: 'a', start: 0, end: 10 }), personFinding({ id: 'b', start: 11, end: 20 })]);
  assert.deepEqual(apart.adjacencies, []);
  assert.equal(apart.regions.length, 2);
});

test('duplicate findings consolidate into one region while every evidence reference is retained', () => {
  const one = secretFinding({ id: 'syn.secret.a', start: 4, end: 12 });
  const twin = secretFinding({ id: 'syn.secret.b', start: 4, end: 12, inputRef: 'syn-other-unit',
    producerId: 'syn.other-detector' });
  const composition = compose([one, twin]);
  assert.equal(composition.regions.length, 1);
  const [region] = composition.regions;
  assert.equal(region.members.length, 2);
  assert.deepEqual(region.members.map((member) => member.evidenceRef).sort(), ['syn.secret.a', 'syn.secret.b']);
  assert.deepEqual(region.members.map((member) => member.duplicateIdentity), [true, true]);
  assert.equal(composition.retention.received, 2);
  assert.equal(composition.retention.retained, 2);
  assert.equal(composition.retention.duplicateEvidence, 2);
  // Each duplicate keeps its own producer and input reference.
  assert.deepEqual(region.members.map((member) => member.producerId).sort(), ['syn.detector', 'syn.other-detector']);
  assert.equal(region.composed.status, 'RESOLVED');
  assert.equal(region.composed.sensitivity, 'SECRET');
});

test('repeated identical field values keep separate source locations and separate regions', () => {
  const input = JSON.stringify({ accessToken: TOKEN, refreshToken: TOKEN });
  const composition = compose(detect(input).candidates);
  assert.equal(composition.regions.length, 2);
  assert.deepEqual(composition.regions.map((region) => region.span), [{ start: 16, end: 42 }, { start: 60, end: 86 }]);
  const fieldSpans = composition.regions.map((region) => region.members.find((member) => member.field).field.span);
  assert.deepEqual(fieldSpans, [{ start: 16, end: 42 }, { start: 60, end: 86 }]);
  assert.equal(new Set(composition.regions.map((region) =>
    region.members.find((member) => member.field).field.pathRef)).size, 2);
  assert.equal(JSON.stringify(composition).includes(TOKEN), false);
});

test('a decoded field value is one covering region, never an invented exact span', () => {
  const input = '{"password":"syn\\\\u0074hetic-pass.invalid","region":"eu"}';
  const composition = compose(detect(input).candidates);
  const region = regionWith(composition, 'CREDENTIAL_OR_SECRET');
  assert.ok(region.members.length >= 2);
  // The union of an exact text match and a covering decoded-field match is a covering region.
  assert.equal(region.original.kind, 'ORIGINAL_COVER');
  assert.deepEqual(region.original.span, { start: 13, end: 41 });
  const fieldMember = region.members.find((member) => member.field);
  assert.equal(fieldMember.field.verbatim, false);
  assert.equal(fieldMember.original.kind, 'ORIGINAL_COVER');
  assert.deepEqual(fieldMember.original.span, fieldMember.field.span);
  assert.equal(region.span.start, 13);
  assert.equal(region.span.end, 41);
  assert.equal(input.slice(region.span.start, region.span.end), 'syn\\\\u0074hetic-pass.invalid');
  assert.equal(region.obligations.nonReversibleFloor, true);
});

test('non-BMP and invisible input keep a covering original span and a bounded region', () => {
  const astral = compose(detect('{"password":"syn-\\ud83d\\ude00-pass.invalid"}').candidates);
  const astralRegion = regionWith(astral, 'CREDENTIAL_OR_SECRET');
  assert.equal(astralRegion.original.kind, 'ORIGINAL_COVER');
  assert.deepEqual(astralRegion.original.span, { start: 13, end: 42 });
  assert.equal(astralRegion.members.filter((member) => member.field).every((member) => member.field.verbatim === false),
    true);
  const invisible = compose(detect('{"password":"syn\\u200b-pass.invalid"}').candidates);
  const invisibleRegion = regionWith(invisible, 'CREDENTIAL_OR_SECRET');
  assert.equal(invisibleRegion.obligations.nonReversibleFloor, true);
  for (const member of invisibleRegion.members) {
    assert.ok(member.original.kind === 'ORIGINAL_COVER' || member.original.kind === 'ORIGINAL_EXACT');
    assert.ok(member.span.end > member.span.start && member.span.end <= 46);
  }
  assert.equal(JSON.stringify(invisible).includes('u200b-pass'), false);
});

test('findings from different normalized views over the same original bytes are a typed refusal', () => {
  const input = JSON.stringify({ url: 'https://svc.example.invalid/v1?access_token=syn%2Dtok%2D4f2b9c7e1d.invalid' });
  const composition = compose(detect(input).candidates);
  const coordinateSpaces = [...new Set(composition.regions.map((region) => region.coordinateSpace))].sort();
  assert.equal(coordinateSpaces.length, 2);
  assert.deepEqual(composition.refusals.map((item) => item.reason), ['CROSS_VIEW_OVERLAP']);
  assert.equal(composition.status, 'UNRESOLVED');
  // Nothing is merged or dropped: both coordinate spaces keep every protected member and the floor.
  assert.equal(composition.regions.length, 2);
  assert.deepEqual(composition.regions.map((region) => region.obligations.nonReversibleFloor), [true, true]);
  assert.equal(composition.retention.retained, composition.retention.received);
  const decoded = composition.regions.find((region) => region.encodingPath.length > 0);
  assert.equal(decoded.viewId, 1);
  assert.deepEqual([...decoded.encodingPath], ['PERCENT']);
  assert.equal(decoded.original.kind, 'ENCODED_RUNS');
  assert.equal(decoded.refusals, undefined);
});

test('a protected region overlapping an opaque location is a typed refusal, not a clean region', () => {
  // Unsupported XML markup leaves #6 PARTIAL with a whole-input opaque location while the text scan still
  // finds the credential: the region inside it must stay unresolved, never read as inspected-and-clean.
  const input = '<svc><password><![CDATA[syn-pass.invalid]]></password></svc>';
  const detection = detect(input);
  assert.equal(detection.status, 'PARTIAL');
  assert.ok(detection.uninspected.length > 0);
  const composition = compose(detection.candidates, { uninspected: detection.uninspected });
  const opaque = composition.refusals.filter((item) => item.reason === 'OPAQUE_LOCATION_OVERLAP');
  assert.equal(opaque.length >= 1, true);
  assert.equal(composition.status, 'UNRESOLVED');
  for (const item of opaque) {
    assert.ok(item.regionRefs.length > 0);
    assert.equal(JSON.stringify(item).includes('syn-pass.invalid'), false);
  }
  assert.ok(regionWith(composition, 'CREDENTIAL_OR_SECRET').obligations.nonReversibleFloor);
});

test('foreign and stale input bindings are refused explicitly and never echo their input', () => {
  const foreign = compose([secretFinding({ id: 'a', start: 0, end: 10 }),
    secretFinding({ id: 'b', start: 5, end: 15, original: { kind: 'UTF8_TEXT', span: { start: 5, end: 15 }, coverage: 'EXACT' } })]);
  assert.deepEqual([...new Set(foreign.refusals.map((item) => item.reason))].sort(),
    ['COORDINATE_SPACE_FOREIGN', 'CROSS_VIEW_OVERLAP']);
  assert.equal(foreign.status, 'UNRESOLVED');
  assert.equal(foreign.regions.length, 2);
  assert.ok(foreign.regions.every((region) => region.obligations.nonReversibleFloor));

  const rejected = compose([secretFinding({ id: 'a', start: 10, end: 5 })]);
  assert.equal(rejected.status, 'UNRESOLVED');
  assert.deepEqual(reasonsOf(rejected), ['INVALID_FINDING']);
  assert.equal(rejected.retention.received, 1);
  assert.equal(rejected.retention.rejected, 1);
  assert.equal(rejected.retention.retained, 0);
  assert.deepEqual(rejected.regions, []);

  const hostile = composeOverlapRegions({ findings: { length: 1, 0: secretFinding({ id: 'a', start: 0, end: 4 }) }, context });
  assert.equal(hostile.status, 'REJECTED');
  assert.deepEqual(reasonsOf(hostile), ['INVALID_REQUEST']);

  const throwing = Object.defineProperty({}, 'findings', { get() { throw new Error(PASSWORD); } });
  const failed = composeOverlapRegions(throwing, context);
  assert.equal(failed.status, 'REJECTED');
  assert.deepEqual(reasonsOf(failed), ['INVALID_REQUEST']);
  assert.equal(JSON.stringify(failed).includes(PASSWORD), false);
});

test('an irreversible constant rewrite covers every overlapping region and the exact bytes pass #19', () => {
  const input = JSON.stringify({ owner: PERSON, endpoint: `https://user:${PASSWORD}@svc.example.invalid/v1`,
    accessToken: TOKEN });
  const detection = detect(input);
  const composition = compose(detection.candidates);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'PLANNED', reasonsOf(plan).join());
  assert.deepEqual(reasonsOf(plan), []);
  assert.ok(plan.regions.every((region) => region.decision === 'REPLACE_FIELD_VALUE'));
  assert.equal(new Set(plan.regions.map((region) => `${region.fieldSpan.start}-${region.fieldSpan.end}`)).size,
    plan.regions.length);
  const applied = applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' });
  assert.equal(applied.status, 'REWRITTEN', applied.status === 'REFUSED' ? applied.reasons.join() : '');

  // 1. Source location: every planned span is a real value span of the parsed source.
  const before = parseStructured(input, 'JSON');
  for (const region of plan.regions) {
    assert.equal(before.fields.some((field) => field.valueStart === region.fieldSpan.start &&
      field.valueEnd === region.fieldSpan.end), true);
  }
  // 2. Rewrite: the covered original text is gone and the keys survive.
  for (const original of [PERSON, PASSWORD, TOKEN]) assert.equal(applied.text.includes(original), false);
  // 3. Structured reparse, checked independently of the rewriter's own round trip.
  const after = parseStructured(applied.text, 'JSON');
  assert.equal(after.status, 'COMPLETE');
  assert.deepEqual(after.fields.map((field) => field.path.join('.')), before.fields.map((field) => field.path.join('.')));
  // 4. Candidate retention after the rewrite: nothing planted is still reported.
  const recheck = detect(applied.text);
  assert.deepEqual(recheck.candidates.filter((item) => item.source === 'SECRET'), []);
  // 5. Final bytes: the independent sentinel sees no planted original and no canary.
  const finalBytes = sentinel(applied.text);
  assert.deepEqual([finalBytes.decision, finalBytes.reasons], ['ALLOW', []]);
  assert.equal(Buffer.from(finalBytes.release).equals(Buffer.from(enc(applied.text))), true);
  // Provenance is privacy safe: digests, spans and evidence references only.
  assert.equal(JSON.stringify(applied.provenance).includes(PASSWORD), false);
  assert.match(applied.provenance.sourceDigest, /^[0-9a-f]{64}$/u);
  assert.match(applied.provenance.replacementDigest, /^[0-9a-f]{64}$/u);
  assert.equal(applied.provenance.rewrittenFields, plan.regions.length);
  // A sentinel ALLOW on the original bytes would have been impossible; it is the independent backstop.
  assert.equal(sentinel(input).decision, 'BLOCK');
});

test('an unresolvable overlap fails explicitly and the sentinel blocks the bytes independently', () => {
  // The credential is in a JSON *key*: #7 rewrites field values, so no accepted path covers this region.
  const input = `{"secret=${PASSWORD}":"eu-west"}`;
  const detection = detect(input);
  const composition = compose(detection.candidates);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'REFUSED');
  assert.deepEqual(reasonsOf(plan), ['REGION_NOT_FIELD_BOUNDED']);
  assert.ok(plan.regions.some((region) => region.decision === 'REFUSED'));
  const applied = applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' });
  assert.equal(applied.status, 'REFUSED');
  assert.deepEqual(reasonsOf(applied), ['REFUSED_PLAN']);
  // The only catch here is the sentinel's: it is not credit for a merge or a transformation.
  const finalBytes = sentinel(input);
  assert.equal(finalBytes.decision, 'BLOCK');
  assert.ok(finalBytes.reasons.includes('KNOWN_ORIGINAL_DETECTED'));
  assert.deepEqual(finalBytes.findings.filter((item) => item.kind === 'KNOWN_ORIGINAL').map((item) => item.rule),
    ['planted.secret.1']);
});

test('the accepted rewriter refuses ambiguous, commented and unencodable sources', () => {
  const duplicateKeys = `{"accessToken":"${TOKEN}","accessToken":"${TOKEN}"}`;
  const duplicatePlan = planOverlapRewrite({ composition: compose(detect(duplicateKeys).candidates),
    source: duplicateKeys, format: 'JSON', replacement: MASK });
  assert.equal(duplicatePlan.status, 'REFUSED');
  assert.deepEqual(reasonsOf(duplicatePlan), ['SOURCE_AMBIGUOUS']);

  const commented = `# synthetic configuration\nPASSWORD=${PASSWORD}\n`;
  const commentPlan = planOverlapRewrite({ composition: compose(detect(commented).candidates),
    source: commented, format: 'DOTENV', replacement: 'redacted' });
  assert.equal(commentPlan.status, 'REFUSED');
  assert.deepEqual(reasonsOf(commentPlan), ['SOURCE_HAS_COMMENTS']);

  const bare = `PASSWORD=${PASSWORD}\nDB_HOST=db.example.invalid\n`;
  const bareComposition = compose(detect(bare).candidates);
  const maskPlan = planOverlapRewrite({ composition: bareComposition, source: bare, format: 'DOTENV', replacement: MASK });
  assert.equal(maskPlan.status, 'PLANNED', reasonsOf(maskPlan).join());
  const maskApplied = applyOverlapRewrite({ plan: maskPlan, composition: bareComposition, source: bare, format: 'DOTENV' });
  assert.deepEqual(maskApplied, { status: 'REFUSED', reasons: ['UNENCODABLE_REPLACEMENT'] });
  const textPlan = planOverlapRewrite({ composition: bareComposition, source: bare, format: 'DOTENV',
    replacement: 'redacted' });
  const textApplied = applyOverlapRewrite({ plan: textPlan, composition: bareComposition, source: bare, format: 'DOTENV' });
  assert.equal(textApplied.status, 'REWRITTEN');
  assert.equal(textApplied.text.includes(PASSWORD), false);
  // The safe rewrite still does not release: #19's own credential-assignment pattern blocks it.
  const blocked = sentinel(textApplied.text);
  assert.equal(blocked.decision, 'BLOCK');
  assert.deepEqual(blocked.reasons, ['HIGH_RISK_PATTERN']);
  assert.equal(blocked.findings.some((item) => item.kind === 'KNOWN_ORIGINAL'), false);
});

test('a replacement that echoes the covered original, or an invalid one, is refused', () => {
  const input = JSON.stringify({ accessToken: TOKEN });
  const composition = compose(detect(input).candidates);
  const echo = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: TOKEN.slice(0, 10) });
  assert.equal(echo.status, 'REFUSED');
  assert.deepEqual(reasonsOf(echo), ['REPLACEMENT_ECHOES_ORIGINAL']);
  assert.equal(JSON.stringify(echo).includes(TOKEN.slice(0, 10)), false);
  for (const replacement of ['', 'x'.repeat(65), 'line\nbreak', '  padded  ']) {
    const invalid = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement });
    assert.equal(invalid.status, 'REFUSED', replacement);
    assert.deepEqual(reasonsOf(invalid), ['REPLACEMENT_INVALID'], replacement);
  }
  assert.equal(MIN_ECHO_WINDOW, 8);
});

test('an incomplete finding set still cannot release a literal surviving original', () => {
  // A candidate source that missed the mirror copy must not turn into a release: the post-condition is about
  // the bytes, not about the candidate list the caller happened to compose from.
  const input = JSON.stringify({ accessToken: TOKEN, note: `mirror ${TOKEN}` });
  const partial = detect(input).candidates.filter((item) => item.original.span.start < 50);
  const composition = compose(partial);
  assert.equal(composition.regions.length, 1);
  assert.equal(composition.retention.retained, partial.length);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'PLANNED', reasonsOf(plan).join());
  assert.deepEqual(applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' }),
    { status: 'REFUSED', reasons: ['ORIGINAL_SPAN_STILL_PRESENT'] });
});

test('a separator variant no detector reports is an independent sentinel catch, not a rewrite success', () => {
  // `SYN TOK 4F2B9C7E1D INVALID` is the same value with different case and separators: no #6 candidate source
  // reports it, and it shares no literal 8-unit window with the covered original, so the draft's post-condition
  // cannot see it. The rewrite legitimately succeeds; only #19, on the exact serialized bytes, refuses the
  // release. That catch is the sentinel's alone and is never credit for the rewrite.
  const input = JSON.stringify({ accessToken: TOKEN, note: 'mirror SYN TOK 4F2B9C7E1D INVALID' });
  const composition = compose(detect(input).candidates);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'PLANNED', reasonsOf(plan).join());
  const applied = applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' });
  assert.equal(applied.status, 'REWRITTEN');
  assert.equal(applied.text.includes(TOKEN), false);
  const finalBytes = sentinel(applied.text);
  assert.equal(finalBytes.decision, 'BLOCK');
  assert.deepEqual(finalBytes.reasons, ['KNOWN_ORIGINAL_DETECTED']);
  assert.deepEqual(finalBytes.findings.map((item) => item.rule), ['planted.token.1']);
});

test('a decoded view has no accepted rewrite path and is refused, not approximated', () => {
  const encoded = Buffer.from(`x=${PASSWORD}`, 'utf8').toString('base64');
  const composition = compose(detect(encoded).candidates);
  assert.ok(composition.regions.length > 0);
  assert.ok(composition.regions.every((region) => region.viewId === 1));
  const plan = planOverlapRewrite({ composition, source: encoded, format: 'DOTENV', replacement: MASK });
  assert.equal(plan.status, 'REFUSED');
  assert.deepEqual(reasonsOf(plan), ['ENCODED_VIEW_NOT_REWRITABLE']);
  assert.ok(plan.regions.every((region) => region.decision === 'REFUSED'));
  assert.equal(sentinel(encoded).decision, 'BLOCK');
});

test('a stale source binding refuses to splice spans into different bytes', () => {
  const input = JSON.stringify({ accessToken: TOKEN });
  const composition = compose(detect(input).candidates);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'PLANNED');
  const other = applyOverlapRewrite({ plan, composition, source: JSON.stringify({ accessToken: 'syn-other.invalid' }), format: 'JSON' });
  assert.deepEqual(other, { status: 'REFUSED', reasons: ['STALE_SOURCE_BINDING'] });
  const wrongFormat = applyOverlapRewrite({ plan, composition, source: input, format: 'DOTENV' });
  assert.deepEqual(wrongFormat, { status: 'REFUSED', reasons: ['FORMAT_MISMATCH'] });
});

test('bounds are typed refusals: too many findings, an over-wide region and a hostile array', () => {
  const many = Array.from({ length: MAX_FINDINGS + 1 }, (unused, index) =>
    secretFinding({ id: `syn.secret.${index}`, start: 0, end: 4 }));
  const overLimit = compose(many);
  assert.equal(overLimit.status, 'REJECTED');
  assert.deepEqual(reasonsOf(overLimit), ['FINDING_LIMIT']);
  assert.deepEqual(overLimit.regions, []);

  // Distinct disjoint spans beyond the region bound are reported as uncomposed, never quietly dropped.
  const disjoint = compose(Array.from({ length: MAX_FINDINGS }, (unused, index) =>
    secretFinding({ id: `syn.secret.${index}`, start: index * 10, end: index * 10 + 4 })));
  assert.equal(disjoint.status, 'UNRESOLVED');
  assert.ok(reasonsOf(disjoint).includes('REGION_LIMIT'));
  assert.equal(disjoint.regions.length, 256);
  assert.equal(disjoint.retention.retained, MAX_FINDINGS);
  assert.equal(disjoint.retention.uncomposed, MAX_FINDINGS - 256);
  assert.ok(disjoint.regions.every((region) => region.obligations.nonReversibleFloor));

  // #3's own per-channel bound: a region wider than the composer's channel cannot resolve.
  const wide = compose(Array.from({ length: 257 }, (unused, index) =>
    secretFinding({ id: `syn.secret.${index}`, start: 0, end: 4 })));
  assert.equal(wide.regions.length, 1);
  assert.equal(wide.regions[0].members.length, 257);
  assert.equal(wide.regions[0].composed.status, 'UNRESOLVED');
  assert.ok(wide.regions[0].composed.reasons.includes('INVALID_EVIDENCE'));
  assert.equal(wide.regions[0].obligations.nonReversibleFloor, true);

  let reads = 0;
  const lying = new Proxy([], {
    get(target, property) { if (property === 'length') { reads++; return 3; } return Reflect.get(target, property); },
  });
  const bounded = compose(lying);
  assert.ok(['REJECTED', 'UNRESOLVED', 'COMPOSED'].includes(bounded.status));
  assert.ok(reads <= 1, `length read ${reads} times`);
  const nonArray = compose({ 0: secretFinding({ id: 'a', start: 0, end: 4 }), length: 1 });
  assert.equal(nonArray.status, 'REJECTED');
  assert.deepEqual(reasonsOf(nonArray), ['INVALID_REQUEST']);
});

test('the draft emits references, spans and reason codes only, and no treatment or score surface', () => {
  const input = JSON.stringify({ owner: PERSON, accessToken: TOKEN, canary: CANARY });
  const detection = detect(input);
  const composition = compose(detection.candidates);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  const applied = applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' });
  const serialized = [JSON.stringify(composition), JSON.stringify(plan),
    JSON.stringify(applied.status === 'REWRITTEN' ? applied.provenance : applied)].join('');
  for (const planted of [PERSON, PASSWORD, TOKEN, CANARY]) assert.equal(serialized.includes(planted), false);
  for (const word of ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE', 'BLOCK', 'REQUIRE_REVIEW']) {
    assert.equal(serialized.includes(word), false, word);
  }
  assert.deepEqual(Object.keys(composition).sort(),
    ['adjacencies', 'reasons', 'refusals', 'regions', 'retention', 'status', 'version']);
  assert.deepEqual(Object.keys(composition.regions[0]).sort(),
    ['composed', 'coordinateSpace', 'encodingPath', 'fieldFormats', 'members', 'obligations', 'original',
      'regionRef', 'relations', 'representations', 'span', 'viewId']);
  assert.deepEqual(Object.keys(composition.retention).sort(),
    ['bySemanticType', 'bySource', 'duplicateEvidence', 'received', 'rejected', 'retained', 'uncomposed']);
  assert.equal(composition.retention.uncomposed, 0);
  assert.equal(applied.status, 'REWRITTEN');
});

test('a #10 configured finding composes as evidence and is rewritten, never dropped as unreadable', () => {
  // Accepted #6 emits a fourth source, CONFIGURED, whenever the integration supplies a trusted handle.
  // A configured customer term is protected evidence exactly like a credential: dropping it because the
  // draft only knew three source names would lose coverage while the rewrite still reported success.
  const configured = createCandidateConfig(scope, {
    terms: [{ term: 'Northwind Synthetic AB', semanticType: 'CUSTOMER_OR_PARTNER', sensitivity: 'CONFIDENTIAL' }] });
  const input = JSON.stringify({ owner: 'Northwind Synthetic AB', accessToken: TOKEN });
  const detection = detectNormalizedCandidates({ input, inputRef: 'syn-configured-unit', scope, configured });
  const composition = compose(detection.candidates, { uninspected: detection.uninspected });
  assert.equal(composition.retention.rejected, 0);
  assert.equal(composition.retention.uncomposed, 0);
  assert.equal(composition.retention.retained, detection.candidates.length);
  assert.equal(composition.retention.bySource.CONFIGURED, 1);
  const owner = composition.regions.find((region) =>
    region.members.some((member) => member.semanticType === 'CUSTOMER_OR_PARTNER'));
  assert.ok(owner, JSON.stringify(composition.regions.map((region) => region.regionRef)));
  assert.deepEqual(owner.obligations.semanticTypes, ['CUSTOMER_OR_PARTNER']);
  assert.equal(owner.obligations.nonReversibleFloor, false);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'PLANNED', reasonsOf(plan).join());
  const applied = applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' });
  assert.equal(applied.status, 'REWRITTEN', applied.status === 'REFUSED' ? applied.reasons.join() : '');
  assert.equal(applied.text.includes('Northwind Synthetic AB'), false);
  assert.equal(applied.text.includes(TOKEN), false);
  assert.equal(sentinel(applied.text).decision, 'ALLOW');
});

test('a finding source this draft does not know blocks the rewrite instead of being dropped', () => {
  // A #6 source added after this draft was written: it is named, readable and protected, and this draft has
  // not been reviewed against it. Dropping it would lose coverage silently; releasing past it is worse.
  const future = { ...secretFinding({ id: 'syn.future.1', start: 0, end: 12 }), source: 'FUTURE_SOURCE' };
  const composition = compose([future, secretFinding({ id: 'syn.secret.1', start: 40, end: 66 })]);
  assert.equal(composition.retention.rejected, 1);
  assert.equal(composition.retention.uncomposed, 1);
  assert.deepEqual(reasonsOf(composition), ['UNKNOWN_FINDING_SOURCE']);
  const input = JSON.stringify({ accessToken: TOKEN, region: 'eu' });
  // The unreadable finding is counted as unrepresented, so the plan refuses rather than rewriting blind.
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'REFUSED');
  assert.deepEqual(reasonsOf(plan), ['INCOMPLETE_CANDIDATE_SET']);
  assert.ok(plan.regions.every((region) => region.decision === 'REFUSED'));
});

test('a rewritten constant that echoes a covered original is refused by the function that returns bytes', () => {
  const input = JSON.stringify({ accessToken: TOKEN });
  const composition = compose(detect(input).candidates);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'PLANNED');
  const tampered = { ...plan, replacement: TOKEN.slice(0, 8),
    replacementDigest: createHash('sha256').update(TOKEN.slice(0, 8)).digest('hex') };
  const applied = applyOverlapRewrite({ plan: tampered, composition, source: input, format: 'JSON' });
  assert.deepEqual(applied, { status: 'REFUSED', reasons: ['REPLACEMENT_ECHOES_ORIGINAL'] });
  assert.equal(applied.text, undefined);
});

test('a plan that names an unrelated field is refused instead of rewriting it and calling it protected', () => {
  const input = JSON.stringify({ accessToken: PASSWORD, innocent: 'keep-me-please' });
  const composition = compose(detect(input).candidates);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'PLANNED');
  const innocent = parseStructured(input, 'JSON').fields.find((field) => field.path[0] === 'innocent');
  const forged = { ...plan, regions: [{ regionRef: 'region-0', decision: 'REPLACE_FIELD_VALUE',
    fieldSpan: { start: innocent.valueStart, end: innocent.valueEnd }, fieldRef: 'a'.repeat(16),
    evidenceRefs: ['syn.fake.1'] }] };
  const applied = applyOverlapRewrite({ plan: forged, composition, source: input, format: 'JSON' });
  assert.deepEqual(applied, { status: 'REFUSED', reasons: ['PLAN_BINDING_MISMATCH'] });
  // The legitimate plan still rewrites the credential field and leaves the innocent one alone.
  const honest = applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' });
  assert.equal(honest.status, 'REWRITTEN');
  assert.equal(honest.text.includes(PASSWORD), false);
  assert.equal(honest.text.includes('keep-me-please'), true);
});

test('a surviving window of a covered original refuses the rewrite, not only a surviving whole value', () => {
  // The covered field is wider than the secret, so only the secret is in the un-composed mirror. A
  // whole-value comparison would see nothing left; an 8-unit window of the covered original does.
  const input = JSON.stringify({ accessToken: `Bearer ${TOKEN}`, note: `mirror ${TOKEN}` });
  const partial = detect(input).candidates.filter((item) => item.view.span.start < 50);
  const composition = compose(partial);
  assert.equal(composition.regions.length, 1);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'PLANNED', reasonsOf(plan).join());
  assert.deepEqual(applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' }),
    { status: 'REFUSED', reasons: ['ORIGINAL_SPAN_STILL_PRESENT'] });
  // With every #6 finding composed, both fields are rewritten and the release is clean.
  const whole = compose(detect(input).candidates);
  const wholePlan = planOverlapRewrite({ composition: whole, source: input, format: 'JSON', replacement: MASK });
  const wholeApplied = applyOverlapRewrite({ plan: wholePlan, composition: whole, source: input, format: 'JSON' });
  assert.equal(wholeApplied.status, 'REWRITTEN');
  assert.equal(sentinel(wholeApplied.text).decision, 'ALLOW');
});

test('two occurrences of one value inside one decoded field value are not duplicates', () => {
  const input = '{"password":"syn\\u002dpass.invalid and syn\\u002dpass.invalid"}';
  const detection = detect(input);
  const occurrences = detection.candidates.filter((item) => item.field)
    .map((item) => `${item.source}:${item.field.valueSpan.start}-${item.field.valueSpan.end}`);
  assert.ok(new Set(occurrences).size >= 3, occurrences.join(' '));
  const composition = compose(detection.candidates);
  assert.equal(composition.retention.duplicateEvidence, 0);
  assert.equal(composition.regions.flatMap((region) => region.members).some((member) => member.duplicateIdentity),
    false);
});

test('relation reporting is bounded by member pairs, not by an unreachable count', () => {
  const many = Array.from({ length: 100 }, (unused, index) =>
    secretFinding({ id: `syn.many.${index}`, start: 0, end: 4 }));
  const composition = compose(many);
  assert.equal(composition.regions.length, 1);
  assert.equal(composition.regions[0].members.length, 100);
  assert.deepEqual(composition.regions[0].relations, ['IDENTICAL']);
  assert.ok(reasonsOf(composition).includes('RELATION_LIMIT'));
});

test('two original-location families in one view only refuse when they actually overlap', () => {
  const overlapping = compose([secretFinding({ id: 'a', start: 0, end: 10 }),
    secretFinding({ id: 'b', start: 5, end: 15,
      original: { kind: 'UTF8_TEXT', span: { start: 5, end: 15 }, coverage: 'EXACT' } })]);
  assert.deepEqual([...new Set(overlapping.refusals.map((item) => item.reason))].sort(),
    ['COORDINATE_SPACE_FOREIGN', 'CROSS_VIEW_OVERLAP']);
  const disjoint = compose([secretFinding({ id: 'a', start: 0, end: 10 }),
    secretFinding({ id: 'b', start: 50, end: 60,
      original: { kind: 'UTF8_TEXT', span: { start: 50, end: 60 }, coverage: 'EXACT' } })]);
  assert.deepEqual(disjoint.refusals, []);
  assert.equal(disjoint.regions.length, 2);
});

test('a region wider than the composer evidence ceiling keeps its obligation floor and blocks the rewrite', () => {
  const wide = compose(Array.from({ length: 300 }, (unused, index) =>
    secretFinding({ id: `syn.secret.${index}`, start: 0, end: 4 })));
  const [region] = wide.regions;
  assert.equal(region.members.length, 300);
  // Accepted #3 refuses to resolve past its per-channel bound, so the region floor comes from obligations.
  assert.equal(region.composed.status, 'UNRESOLVED');
  assert.ok(region.composed.reasons.includes('INVALID_EVIDENCE'));
  assert.equal(region.obligations.highestSensitivity, 'SECRET');
  assert.equal(region.obligations.nonReversibleFloor, true);
  const input = JSON.stringify({ accessToken: TOKEN });
  const plan = planOverlapRewrite({ composition: wide, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'REFUSED');
  assert.deepEqual(reasonsOf(plan), ['REGION_EVIDENCE_INCOMPLETE']);
});

test('a real zero-width character folds onto a covering raw span', () => {
  // `JSON.stringify` keeps an actual U+200B in the source text, so the compatibility fold has work to do.
  const input = JSON.stringify({ password: 'syn\u200b-pass.invalid' });
  assert.equal(input.includes('\u200b'), true);
  const folded = detect(input).candidates.filter((item) => item.view.representation === 'FOLDED');
  assert.ok(folded.length >= 1);
  for (const item of folded) {
    assert.equal(item.original.kind, 'ORIGINAL_COVER');
    assert.ok(item.original.span.start >= 13 && item.original.span.end <= input.length);
  }
  const composition = compose(detect(input).candidates);
  const region = regionWith(composition, 'CREDENTIAL_OR_SECRET');
  assert.equal(region.obligations.nonReversibleFloor, true);
  assert.deepEqual([...region.representations].sort(), ['FOLDED', 'RAW']);
  assert.equal(JSON.stringify(composition).includes('\u200b'), false);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  assert.equal(plan.status, 'PLANNED', reasonsOf(plan).join());
  const applied = applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' });
  assert.equal(applied.status, 'REWRITTEN');
  assert.equal(applied.text.includes('\u200b-pass'), false);
});

test('the surviving-run threshold is half a covered original, never below the window floor', () => {
  assert.equal(coveredWindowUnits(0), 0);
  assert.equal(coveredWindowUnits(-3), 0);
  assert.equal(coveredWindowUnits(2.5), 0);
  assert.equal(coveredWindowUnits(4), 4);
  assert.equal(coveredWindowUnits(8), 8);
  assert.equal(coveredWindowUnits(16), 8);
  assert.equal(coveredWindowUnits(26), 13);
  assert.equal(coveredWindowUnits(33), 17);
  assert.equal(coveredWindowUnits('16'), 0);
  // A mirror sharing only a short affix does not trip the literal check; the independent sentinel does.
  const input = JSON.stringify({ accessToken: TOKEN, note: 'mirror SYN TOK 4F2B9C7E1D INVALID' });
  const composition = compose(detect(input).candidates);
  const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: MASK });
  const applied = applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' });
  assert.equal(applied.status, 'REWRITTEN');
  // A mirror sharing more than half of a covered original is caught by the draft itself, before any sentinel.
  const partialInput = JSON.stringify({ accessToken: TOKEN, note: `mirror ${TOKEN}` });
  const partial = compose(detect(partialInput).candidates.filter((item) => item.view.span.start < 50));
  const partialPlan = planOverlapRewrite({ composition: partial, source: partialInput, format: 'JSON', replacement: MASK });
  assert.deepEqual(applyOverlapRewrite({ plan: partialPlan, composition: partial, source: partialInput,
    format: 'JSON' }), { status: 'REFUSED', reasons: ['ORIGINAL_SPAN_STILL_PRESENT'] });
});

test('composition and rewriting stay bounded in time and memory on a wide structured input', () => {
  // A synthetic document with many credential-keyed fields, measured three ways inside one bounded child.
  // #6's own per-source cap reports 256 findings, so a rewrite can cover 256 of the 2,000 values whatever the
  // values look like: bounded work, bounded regions, and an honest residual that a final-byte check over the
  // actual serialized bytes is still required to judge. The three scenarios differ in one variable each, so
  // each outcome is attributable to that variable rather than asserted:
  //  - `long`: realistic-length, mutually distinct values that share a literal suffix. The post-condition is
  //    literal, and a value past #6's cap then shares more than half of a covered original, so the rewrite
  //    refuses conservatively instead of reporting success. This is the wide case at realistic value lengths.
  //  - `short`: short, mutually distinct values. No surviving value shares a literal run with a covered
  //    original, so the rewrite succeeds and the values #6 never reported are still in the bytes.
  //  - `repeat`: the same short values, repeated. Same length, same document size, only distinctness removed,
  //    and a surviving copy of a covered value is refused. Short length is therefore not what made `short`
  //    succeed; a surviving literal run of a covered original is.
  const script = `
    import { detectNormalizedCandidates } from './dist/normalized-detection.js';
    import { composeOverlapRegions, planOverlapRewrite, applyOverlapRewrite } from './dist/overlap-composition-draft.js';
    const scope = { tenantRef: 'tenant-a.invalid', projectRef: 'project-a.invalid' };
    const context = { interactionRef: 'syn-i', sourceRef: 'syn-s', trust: 'CONTROL' };
    const values = {
      long: (index) => 'syn-pass-' + index + '-4f2b9c7e1d.invalid',
      short: (index) => 'pw' + index.toString(36).padStart(5, '0'),
      repeat: (index) => 'pw' + (index % 8).toString(36).padStart(5, '0'),
    };
    const results = {};
    for (const [name, value] of Object.entries(values)) {
      const fields = Array.from({ length: 2000 }, (unused, index) =>
        '"password' + index + '":"' + value(index) + '"').join(',');
      const input = '{' + fields + '}';
      const detection = detectNormalizedCandidates({ input, inputRef: 'syn-bounded-overlap', scope });
      const composition = composeOverlapRegions({ findings: detection.candidates, context });
      const plan = planOverlapRewrite({ composition, source: input, format: 'JSON', replacement: '****' });
      const applied = applyOverlapRewrite({ plan, composition, source: input, format: 'JSON' });
      results[name] = { units: input.length, status: composition.status,
        findings: detection.candidates.length, regions: composition.regions.length,
        uncomposed: composition.retention.uncomposed, plan: plan.status, planned: plan.regions.length,
        applied: applied.status, reasons: applied.status === 'REFUSED' ? applied.reasons : [],
        rewritten: applied.status === 'REWRITTEN' ? applied.provenance.rewrittenFields : 0,
        residual: applied.status === 'REWRITTEN' ? applied.text.includes(value(1999)) : null };
    }
    process.stdout.write(JSON.stringify(results));
  `;
  const child = spawnSync(process.execPath, ['--max-old-space-size=256', '--input-type=module', '-e', script],
    { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 });
  assert.equal(child.status, 0, `child exit ${child.status}, signal ${child.signal}`);
  const result = JSON.parse(child.stdout);
  // Bounded work is the same in all three: 256 findings, 256 regions, 256 planned field decisions, none
  // uncomposed, whatever the values are. Only the final-byte post-condition differs between them.
  for (const [name, scenario] of Object.entries(result)) {
    assert.equal(scenario.status, 'COMPOSED', name);
    assert.equal(scenario.findings, 256, name);
    assert.equal(scenario.regions, 256, name);
    assert.equal(scenario.uncomposed, 0, name);
    assert.equal(scenario.plan, 'PLANNED', name);
    assert.equal(scenario.planned, 256, name);
  }
  assert.ok(result.long.units > result.short.units, 'the long scenario really carries the longer values');
  assert.equal(result.short.units, result.repeat.units, 'the control is the same document size');
  // The wide case at realistic value lengths refuses: two protected values that share half of one of them
  // literally make each other look surviving, and the draft refuses rather than calling that protected.
  assert.equal(result.long.applied, 'REFUSED');
  assert.deepEqual(result.long.reasons, ['ORIGINAL_SPAN_STILL_PRESENT']);
  assert.equal(result.long.rewritten, 0);
  assert.equal(result.long.residual, null);
  // Short and mutually distinct: the rewrite succeeds, and the values past #6's own candidate cap are still
  // in the bytes. Reported, not hidden.
  assert.equal(result.short.applied, 'REWRITTEN');
  assert.equal(result.short.rewritten, 256);
  assert.equal(result.short.residual, true, 'values past #6 own candidate cap keep their synthetic text: reported, not hidden');
  // Same length, same document, only distinctness removed: a surviving copy of a covered value refuses too.
  assert.equal(result.repeat.applied, 'REFUSED');
  assert.deepEqual(result.repeat.reasons, ['ORIGINAL_SPAN_STILL_PRESENT']);
  assert.equal(result.repeat.rewritten, 0);
});
