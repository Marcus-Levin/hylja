import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { composeClassificationUnits, createContactSensitivity, MAX_UNITS, MAX_UNIT_EVIDENCE } from '../dist/classification-units.js';
import { extendSubtypeRegistry } from '../dist/classification.js';
import { createCandidateConfig } from '../dist/configured-candidates.js';
import { createNameDictionary } from '../dist/contact-candidates.js';
import { detectNormalizedCandidates } from '../dist/normalized-detection.js';

// Synthetic only: invented organisations, .invalid project names, made-up identifiers and contact values.
const A = Object.freeze({ tenantRef: 'tenant-a', projectRef: 'project-a' });
const B = Object.freeze({ tenantRef: 'tenant-b', projectRef: 'project-b' });
const context = Object.freeze({ interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' });
const configA = createCandidateConfig(A, {
  terms: [
    { term: 'Northwind Synthetic AB', semanticType: 'CUSTOMER_OR_PARTNER', sensitivity: 'CONFIDENTIAL' },
    { term: 'Project Synthetic Kestrel', semanticType: 'PROJECT_OR_CONTRACT', sensitivity: 'RESTRICTED' },
  ],
  patterns: [{ template: 'PMP-{9:4}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG', sensitivity: 'INTERNAL' }],
  fieldHints: [{ path: 'asset.owner', semanticType: 'CUSTOMER_OR_PARTNER', sensitivity: 'CONFIDENTIAL' }],
});
/** A configured term that deliberately covers the same text a configured PERSON name covers. */
const overlapConfig = createCandidateConfig(A, {
  terms: [{ term: 'Orla Synthetica', semanticType: 'CUSTOMER_OR_PARTNER', sensitivity: 'CONFIDENTIAL' }],
  patterns: [{ template: 'PMP-{9:4}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG', sensitivity: 'INTERNAL' }],
});
const names = createNameDictionary(A, ['Orla Synthetica', 'Brannick Testvold']);
const b64 = (value) => Buffer.from(value, 'utf8').toString('base64');
const detect = (input, rest = {}) => detectNormalizedCandidates({ input, inputRef: 'input-a.invalid', scope: A, configured: configA, ...rest });
const compose = (detection, rest = {}) => composeClassificationUnits({
  detection, inputRef: 'input-a.invalid', scope: A, context, ...rest,
});
const run = (input, rest = {}, composeRest = {}) => compose(detect(input, rest), composeRest);
const covered = (input, unit) => {
  const original = unit.location.original;
  if (!('span' in original)) return null;
  return input.slice(original.span.start, original.span.end);
};
/** Subtypes the unit's own detector records claim, whatever the composition could resolve from them. */
const claimed = (unit, subtype) => unit.detectorEvidence.some((record) =>
  record.claim.semanticType === 'PERSON' && record.claim.subtype === subtype);

test('#10 configured dictionary and template sources reach v1 units with exact original provenance', () => {
  const input = 'Northwind Synthetic AB signed for Project Synthetic Kestrel with pump PMP-0042';
  const result = run(input);
  assert.equal(result.status, 'COMPLETE');
  const found = result.units.map((unit) => [unit.classification.semanticType, unit.classification.sensitivity,
    unit.location.original.kind, covered(input, unit)]);
  assert.ok(found.some(([type, sensitivity, kind, value]) =>
    type === 'CUSTOMER_OR_PARTNER' && sensitivity === 'CONFIDENTIAL' && kind === 'ORIGINAL_EXACT' && value === 'Northwind Synthetic AB'));
  assert.ok(found.some(([type, sensitivity, , value]) =>
    type === 'PROJECT_OR_CONTRACT' && sensitivity === 'RESTRICTED' && value === 'Project Synthetic Kestrel'));
  assert.ok(found.some(([type, sensitivity, , value]) =>
    type === 'ENGINEERING_IDENTIFIER' && sensitivity === 'INTERNAL' && value === 'PMP-0042'));
  for (const unit of result.units) assert.equal(unit.classification.status, 'RESOLVED', unit.ref);
});

test('each occurrence is its own unit with its own fresh opaque reference', () => {
  const input = 'write to orla@example.invalid and again to orla@example.invalid';
  const result = run(input, { names });
  const addresses = result.units.filter((unit) => claimed(unit, 'EMAIL'));
  assert.equal(addresses.length, 2);
  assert.notEqual(addresses[0].ref, addresses[1].ref);
  assert.deepEqual(addresses.map((unit) => covered(input, unit)),
    ['orla@example.invalid', 'orla@example.invalid']);
  assert.equal(new Set(result.units.map((unit) => unit.ref)).size, result.units.length);
  assert.deepEqual(addresses.map((unit) => unit.location.original.kind), ['ORIGINAL_EXACT', 'ORIGINAL_EXACT']);
});

test('disjoint entities in one long field stay distinct units', () => {
  const input = 'Orla Synthetica, Brannick Testvold and erik.svensson@example.invalid were copied';
  const result = run(input, { names });
  const values = result.units.map((unit) => covered(input, unit)).sort();
  assert.ok(values.includes('Orla Synthetica'));
  assert.ok(values.includes('Brannick Testvold'));
  assert.ok(values.includes('erik.svensson@example.invalid'));
  assert.ok(result.units.length >= 3);
  assert.equal(new Set(result.units.map((unit) => unit.ref)).size, result.units.length);
  // The nested domain inside the address is reported on its own unit, not swallowed into the address's.
  assert.ok(result.units.some((unit) => unit.location.span.start > 0 &&
    covered(input, unit) === 'example.invalid'));
});

test('repeated occurrences inside one encoded envelope stay distinct units', () => {
  const decoded = 'password=synthetic-pass.invalid\nsecond password=synthetic-pass.invalid';
  const encoded = b64(decoded);
  const input = `left=${encoded} right=${encoded}`;
  const result = run(input);
  const secrets = result.units.filter((unit) => unit.sources.includes('SECRET'));
  assert.equal(secrets.length, 2);
  assert.notEqual(secrets[0].ref, secrets[1].ref);
  for (const unit of secrets) {
    // Both occurrences of the decoded text share one encoded envelope and are still two units, each with its
    // own in-view span (offsets into the decoded view, not into the source text).
    assert.ok(unit.location.encodingPath.includes('BASE64'));
    assert.equal(unit.location.original.kind, 'ENCODED_RUNS');
    assert.equal(unit.location.original.spans.length, 2);
    assert.deepEqual(unit.location.original.spans.map((span) => input.slice(span.start, span.end)), [encoded, encoded]);
  }
  assert.deepEqual(secrets.map((unit) => unit.location.span), [{ start: 9, end: 31 }, { start: 48, end: 70 }]);
  assert.deepEqual(secrets.map((unit) => decoded.slice(unit.location.span.start, unit.location.span.end)),
    ['synthetic-pass.invalid', 'synthetic-pass.invalid']);
});

test('overlapping claims keep every source in one unit and the conflict stays UNRESOLVED', () => {
  const input = 'Orla Synthetica signed the note about PMP-0042';
  const result = run(input, { names, configured: overlapConfig });
  const overlapping = result.units.filter((unit) => unit.sources.includes('CONTACT') && unit.sources.includes('CONFIGURED'));
  assert.equal(overlapping.length, 1);
  const unit = overlapping[0];
  assert.equal(unit.kind, 'OCCURRENCE');
  assert.equal(covered(input, unit), 'Orla Synthetica');
  const producers = unit.detectorEvidence.map((record) => record.provenance.producerId).sort();
  assert.deepEqual(producers, ['hylja.configured-candidates', 'hylja.contact-candidates']);
  assert.equal(unit.classification.status, 'UNRESOLVED');
  assert.ok(unit.classification.reasons.includes('CONFLICTING_SEMANTIC_TYPE'));
  assert.equal(unit.classification.semanticType, 'UNKNOWN');
  // The stronger configured sensitivity is retained even though the unit cannot resolve.
  assert.equal(unit.classification.sensitivity, 'CONFIDENTIAL');
  // The separate occurrence is not swallowed by the conflicting unit.
  assert.ok(result.units.some((other) => other !== unit && covered(input, other) === 'PMP-0042'));
});

test('a credential and the contact inside the same span stay one unresolved unit at SECRET', () => {
  const input = 'password=orla@example.invalid';
  const result = run(input, { names });
  const merged = result.units.filter((unit) => unit.sources.includes('SECRET') && unit.sources.includes('CONTACT'));
  assert.equal(merged.length, 1);
  assert.equal(merged[0].classification.status, 'UNRESOLVED');
  assert.ok(merged[0].classification.reasons.includes('CONFLICTING_SEMANTIC_TYPE'));
  assert.equal(merged[0].classification.sensitivity, 'SECRET');
  assert.equal(merged[0].classification.reversible, false);
});

test('unrelated entities across one long decoded field never become one whole-field identity', () => {
  const input = '{"asset":{"owner":"Northwind\\u0020Synthetic AB and Orla Synthetica and erik.svensson@example.invalid"}}';
  const detection = detect(input, { names, formats: ['JSON'] });
  const result = compose(detection);
  const fieldUnits = result.units.filter((unit) => unit.location.field);
  const whole = fieldUnits.filter((unit) => unit.kind === 'WHOLE_VALUE');
  const occurrences = fieldUnits.filter((unit) => unit.kind === 'OCCURRENCE');
  assert.equal(whole.length, 1);
  assert.equal(whole[0].location.original.kind, 'ORIGINAL_COVER');
  assert.equal(whole[0].location.field.verbatim, false);
  assert.ok(occurrences.length >= 2, `expected distinct field occurrences, got ${occurrences.length}`);
  assert.equal(new Set(occurrences.map((unit) => unit.ref)).size, occurrences.length);
  const wholeLength = whole[0].location.field.valueSpan.end - whole[0].location.field.valueSpan.start;
  for (const unit of occurrences) {
    const length = unit.location.field.valueSpan.end - unit.location.field.valueSpan.start;
    assert.ok(length < wholeLength, `${length} < ${wholeLength}`);
  }
  assert.equal(occurrences.some((unit) => claimed(unit, 'EMAIL')), true);
  assert.equal(occurrences.some((unit) => claimed(unit, 'NAME')), true);
});

test('a trusted #7 field hint reaches the unit as a whole-value unit with honest exact provenance', () => {
  const input = '{"asset":{"owner":"Northwind Synthetic AB"}}';
  const result = run(input, { formats: ['JSON'] });
  const whole = result.units.find((unit) => unit.kind === 'WHOLE_VALUE' && unit.location.field);
  assert.ok(whole);
  assert.equal(whole.classification.semanticType, 'CUSTOMER_OR_PARTNER');
  assert.equal(whole.classification.sensitivity, 'CONFIDENTIAL');
  assert.equal(whole.classification.status, 'RESOLVED');
  assert.equal(whole.location.original.kind, 'ORIGINAL_EXACT');
  assert.equal(input.slice(whole.location.original.span.start, whole.location.original.span.end), 'Northwind Synthetic AB');
  assert.equal(whole.location.field.hintSource, 'NONE');
  assert.equal(whole.location.field.verbatim, true);
  assert.match(whole.location.field.pathRef, /^[0-9a-f]{16}$/);
  assert.equal(JSON.stringify(result).includes('owner'), false);
});

test('an escaped field value keeps a covering span and never an invented exact offset', () => {
  const input = '{"asset":{"owner":"Northwind\\u0020Synthetic AB"}}';
  const result = run(input, { formats: ['JSON'] });
  const whole = result.units.find((unit) => unit.kind === 'WHOLE_VALUE' && unit.location.field);
  assert.ok(whole);
  assert.equal(whole.location.original.kind, 'ORIGINAL_COVER');
  assert.equal(whole.location.field.verbatim, false);
  assert.equal(input.slice(whole.location.original.span.start, whole.location.original.span.end),
    'Northwind\\u0020Synthetic AB');
});

test('absent contact sensitivity leaves PERSON units UNRESOLVED and never guesses one', () => {
  const result = run('reach Orla Synthetica at orla@example.invalid', { names });
  const people = result.units.filter((unit) => unit.classification.evidence.some((record) =>
    record.source === 'detector' && record.claim?.semanticType === 'PERSON'));
  assert.ok(people.length >= 2);
  for (const unit of people) {
    assert.equal(unit.classification.status, 'UNRESOLVED');
    assert.equal(unit.classification.sensitivity, 'UNKNOWN');
    assert.ok(unit.classification.reasons.includes('MISSING_SENSITIVITY'));
  }
  assert.equal(JSON.stringify(result).includes('hylja.contact-sensitivity'), false);
});

test('a trusted tenant/project contact sensitivity resolves PERSON units at exactly that sensitivity', () => {
  const sensitivity = createContactSensitivity(A, [{ subtype: 'NAME', sensitivity: 'CONFIDENTIAL' },
    { subtype: 'EMAIL', sensitivity: 'INTERNAL' }]);
  const result = run('reach Orla Synthetica at orla@example.invalid', { names }, { contactSensitivity: sensitivity });
  const bySubtype = new Map(result.units.map((unit) => [unit.classification.subtype, unit.classification]));
  assert.equal(result.status, 'COMPLETE');
  assert.equal(bySubtype.get('NAME').status, 'RESOLVED');
  assert.equal(bySubtype.get('NAME').sensitivity, 'CONFIDENTIAL');
  assert.equal(bySubtype.get('EMAIL').status, 'RESOLVED');
  assert.equal(bySubtype.get('EMAIL').sensitivity, 'INTERNAL');
  assert.equal(bySubtype.get('EMAIL').semanticType, 'PERSON');
  assert.equal(JSON.stringify(result).includes('orla@example.invalid'), false);
});

test('a foreign, forged or malformed contact sensitivity handle supplies no sensitivity and fails conservatively', () => {
  const input = 'reach Orla Synthetica at orla@example.invalid';
  const foreign = createContactSensitivity(B, [{ subtype: 'NAME', sensitivity: 'PUBLIC' }]);
  const forged = { tenantRef: 'tenant-a', projectRef: 'project-a' };
  const cases = [[foreign, 'CONTACT_SENSITIVITY_SCOPE_MISMATCH'], [forged, 'CONTACT_SENSITIVITY_INVALID_CONFIG'],
    [{ toJSON: () => ({}) }, 'CONTACT_SENSITIVITY_INVALID_CONFIG'], ['not-a-handle', 'CONTACT_SENSITIVITY_INVALID_CONFIG']];
  for (const [handle, reason] of cases) {
    const result = run(input, { names }, { contactSensitivity: handle });
    assert.equal(result.status, 'PARTIAL', reason);
    assert.ok(result.reasons.includes(reason), reason);
    const person = result.units.find((unit) => claimed(unit, 'NAME'));
    assert.equal(person.classification.status, 'UNRESOLVED', reason);
    assert.equal(person.classification.sensitivity, 'UNKNOWN', reason);
    assert.ok(person.classification.reasons.includes('MISSING_SENSITIVITY'), reason);
  }
  assert.throws(() => createContactSensitivity(A, [{ subtype: 'NAME', sensitivity: 'TOP_SECRET' }]), /Invalid contact sensitivity/);
  assert.throws(() => createContactSensitivity(A, [{ subtype: 'NAME', sensitivity: 'INTERNAL' },
    { subtype: 'NAME', sensitivity: 'CONFIDENTIAL' }]), /Invalid contact sensitivity/);
  assert.throws(() => createContactSensitivity(A, [{ subtype: 'DOMAIN', sensitivity: 'INTERNAL' }]), /Invalid contact sensitivity/);
});

test('tenant A configuration never influences tenant B: no configured candidate, no sensitivity, no evidence', () => {
  const input = 'Northwind Synthetic AB with pump PMP-0042 and Orla Synthetica';
  const tenantB = { scope: B, names: createNameDictionary(B, ['Orla Synthetica']) };
  const detection = detect(input, tenantB);
  assert.equal(detection.status, 'PARTIAL');
  assert.ok(detection.reasons.includes('CONFIGURED_CONFIG_SCOPE_MISMATCH'));
  assert.equal(detection.candidates.some((candidate) => candidate.source === 'CONFIGURED' && candidate.basis !== 'CONTEXT'), false);
  const result = compose(detection, { scope: B,
    contactSensitivity: createContactSensitivity(A, [{ subtype: 'NAME', sensitivity: 'CONFIDENTIAL' }]) });
  assert.equal(result.status, 'PARTIAL');
  assert.ok(result.reasons.includes('CONTACT_SENSITIVITY_SCOPE_MISMATCH'));
  assert.equal(result.units.some((unit) => unit.classification.semanticType === 'CUSTOMER_OR_PARTNER'), false);
  const person = result.units.find((unit) => claimed(unit, 'NAME'));
  assert.equal(person.classification.status, 'UNRESOLVED');
  assert.equal(person.classification.sensitivity, 'UNKNOWN');
});

test('a configured sensitivity is never weakened by a weaker trusted contact sensitivity', () => {
  const detection = detect('Orla Synthetica at orla@example.invalid', { names, configured: overlapConfig });
  const result = compose(detection, {
    contactSensitivity: createContactSensitivity(A, [{ subtype: 'NAME', sensitivity: 'PUBLIC' }]),
  });
  const merged = result.units.find((unit) => unit.sources.length > 1);
  assert.ok(merged);
  assert.equal(merged.classification.status, 'UNRESOLVED');
  assert.ok(merged.classification.reasons.includes('CONFLICTING_SEMANTIC_TYPE'));
  assert.ok(merged.classification.reasons.includes('CONFLICTING_SENSITIVITY'));
  assert.equal(merged.classification.sensitivity, 'CONFIDENTIAL');
  assert.deepEqual(merged.detectorEvidence.map((record) => record.provenance.producerId).sort(),
    ['hylja.configured-candidates', 'hylja.contact-candidates']);
});

test('no configured term, key name, raw value or source path appears in a serialized result', () => {
  const input = '{"customer":"Northwind Synthetic AB","owner":"Orla Synthetica","password":"synthetic-pass.invalid"}';
  const result = run(input, { names, formats: ['JSON'] });
  const serialized = JSON.stringify(result);
  assert.ok(result.units.length >= 3);
  for (const secret of ['Northwind Synthetic AB', 'Orla Synthetica', 'synthetic-pass.invalid', 'asset.owner',
    '"customer"', '"owner"', '"password"']) {
    assert.equal(serialized.includes(secret), false, secret);
  }
});

test('#10 candidate, view and field caps stay PARTIAL with opaque locations, never a quiet empty result', () => {
  const flood = Array.from({ length: 300 }, (_, index) => `Northwind Synthetic AB ${index}`).join(' ');
  const result = run(flood);
  assert.equal(result.status, 'PARTIAL');
  assert.ok(result.reasons.some((reason) => reason.startsWith('CONFIGURED_')), result.reasons.join(','));
  assert.ok(result.uninspected.some((item) => item.reason.startsWith('CONFIGURED_') &&
    item.original.kind === 'ORIGINAL_EXACT'));
});

test('a foreign #10 handle still leaves the tenant-independent engineering-key rule running', () => {
  const input = 'part_number: SYN-P-1 for Northwind Synthetic AB';
  const detection = detect(input, { configured: configA, scope: B });
  assert.equal(detection.status, 'PARTIAL');
  assert.ok(detection.reasons.includes('CONFIGURED_CONFIG_SCOPE_MISMATCH'));
  const configured = detection.candidates.filter((candidate) => candidate.source === 'CONFIGURED');
  assert.deepEqual(configured.map((candidate) => [candidate.basis, candidate.rule]), [['CONTEXT', 'context.engineering-key']]);
  const result = compose(detection, { scope: B });
  assert.equal(result.status, 'PARTIAL');
  assert.equal(result.units.length, 1);
  // The generic rule emits no configured sensitivity, so its unit stays unresolved by design.
  assert.equal(result.units[0].classification.status, 'UNRESOLVED');
  assert.ok(result.units[0].classification.reasons.includes('MISSING_SENSITIVITY'));
  assert.deepEqual(result.units[0].detectorEvidence.map((record) => record.claim), [
    { semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'PART_NUMBER' }]);
});

test('the evidence cap splits a crossing chain instead of dropping or overloading one unit', () => {
  // Every pair of neighbours crosses, so without the cap they would all collapse into one unit.
  const candidates = Array.from({ length: 300 }, (_, index) => syntheticCandidate(index, index * 3, index * 3 + 10));
  const result = syntheticDetection(candidates);
  assert.equal(result.status, 'COMPLETE');
  assert.equal(result.units.length, 2);
  assert.deepEqual(result.units.map((unit) => unit.detectorEvidence.length), [MAX_UNIT_EVIDENCE, 300 - MAX_UNIT_EVIDENCE]);
  assert.equal(new Set(result.units.flatMap((unit) => unit.detectorEvidence.map((record) => record.id))).size, 300);
});

test('a unit whose original location cannot be stated honestly reports it and keeps no invented span', () => {
  const result = syntheticDetection([
    syntheticCandidate(0, 4, 9),
    syntheticCandidate(1, 4, 9, { original: { kind: 'UTF8_TEXT', span: { start: 4, end: 9 }, coverage: 'EXACT' } }),
  ]);
  assert.equal(result.status, 'PARTIAL');
  assert.deepEqual(result.reasons, ['UNIT_LOCATION_UNRESOLVED']);
  assert.equal(result.units.length, 1);
  assert.equal('original' in result.units[0].location, false);
  assert.equal(result.uninspected.length, 1);
  assert.equal(result.uninspected[0].reason, 'UNIT_LOCATION_UNRESOLVED');
  assert.equal(result.uninspected[0].original.kind, 'ORIGINAL_EXACT');
});

test('byte input reports UTF-8 text offsets and unions them as a covering span', () => {
  const result = syntheticDetection([
    syntheticCandidate(0, 0, 10, { original: { kind: 'UTF8_TEXT', span: { start: 0, end: 10 }, coverage: 'EXACT' } }),
    syntheticCandidate(1, 4, 16, { original: { kind: 'UTF8_TEXT', span: { start: 4, end: 16 }, coverage: 'EXACT' } }),
  ]);
  assert.equal(result.status, 'COMPLETE');
  assert.deepEqual(result.units[0].location.original,
    { kind: 'UTF8_TEXT', span: { start: 0, end: 16 }, coverage: 'COVER' });
  const bytes = new TextEncoder().encode('Northwind Synthetic AB and Orla Synthetica');
  const detected = composeClassificationUnits({
    detection: detectNormalizedCandidates({ input: bytes, inputRef: 'input-a.invalid', scope: A, configured: configA }),
    inputRef: 'input-a.invalid', scope: A, context,
  });
  const customer = detected.units.find((unit) => unit.classification.semanticType === 'CUSTOMER_OR_PARTNER');
  assert.ok(customer);
  assert.equal(customer.location.original.kind, 'UTF8_TEXT');
  assert.equal(customer.location.original.coverage, 'EXACT');
  assert.equal(new TextDecoder().decode(bytes.slice(customer.location.original.span.start,
    customer.location.original.span.end)), 'Northwind Synthetic AB');
});

test('crossing occurrences in one decoded envelope union their outer runs', () => {
  const runs = (spans) => ({ kind: 'ENCODED_RUNS', spans: spans.map(([start, end]) => ({ start, end })) });
  const result = syntheticDetection([
    syntheticCandidate(0, 0, 10, { original: runs([[2, 40]]) }),
    syntheticCandidate(1, 4, 16, { original: runs([[50, 90], [100, 120]]) }),
  ]);
  assert.deepEqual(result.units.length, 1);
  assert.deepEqual(result.units[0].location.original.spans,
    [{ start: 2, end: 40 }, { start: 50, end: 90 }, { start: 100, end: 120 }]);
});

test('a failed detection result and a forged subtype registry are refused with fixed codes', () => {
  const failed = compose({
    status: 'FAILURE', reasons: ['NORMALIZATION_INVALID_UTF8'], contentType: 'UNKNOWN',
    candidates: [], uninspected: [],
  });
  assert.equal(failed.status, 'FAILURE');
  assert.deepEqual(failed.reasons, ['DETECTION_FAILURE', 'NORMALIZATION_INVALID_UTF8']);
  const forged = composeClassificationUnits({ detection: { status: 'COMPLETE', reasons: [], contentType: 'TEXT',
    uninspected: [], candidates: [syntheticCandidate(0, 0, 4)] },
    inputRef: 'input-a.invalid', scope: A, context, registry: { PERSON: ['NAME'] } });
  assert.equal(forged.status, 'FAILURE');
  assert.deepEqual(forged.reasons, ['COMPOSITION_FAILURE']);
  const extended = composeClassificationUnits({ detection: { status: 'COMPLETE', reasons: [], contentType: 'TEXT',
    uninspected: [], candidates: [syntheticCandidate(0, 0, 4)] },
    inputRef: 'input-a.invalid', scope: A, context,
    registry: extendSubtypeRegistry({ PERSON: ['SYNTHETIC_ALIAS'] }) });
  assert.equal(extended.status, 'COMPLETE');
  assert.equal(extended.units.length, 1);
});

test('a repeated occurrence inside one decoded #7 field value stays a distinct unit with its own span', () => {
  // #7 decodes this value, so every match in it reports the whole field span in the view: the in-value
  // occurrence offsets are the only thing that tells the two occurrences apart.
  const input = '{"asset":{"note":"Northwind\\u0020Synthetic AB and Northwind\\u0020Synthetic AB"}}';
  const result = run(input, { formats: ['JSON'] });
  const units = result.units.filter((unit) => unit.classification.semanticType === 'CUSTOMER_OR_PARTNER');
  assert.equal(units.length, 2);
  assert.notEqual(units[0].ref, units[1].ref);
  assert.deepEqual(units.map((unit) => unit.location.field.valueSpan), [{ start: 0, end: 22 }, { start: 27, end: 49 }]);
  for (const unit of units) {
    assert.equal(unit.classification.status, 'RESOLVED');
    assert.equal(unit.classification.sensitivity, 'CONFIDENTIAL');
    assert.equal(unit.location.original.kind, 'ORIGINAL_COVER');
    assert.equal(unit.detectorEvidence.length, 1);
  }
  assert.equal(input.slice(units[0].location.original.span.start, units[0].location.original.span.end),
    'Northwind\\u0020Synthetic AB and Northwind\\u0020Synthetic AB');
  assert.equal(JSON.stringify(result).includes('Northwind'), false);
});

test('entity- and percent-decoded values report every repeated occurrence once', () => {
  // #7 decodes the entity, so both occurrences live in one non-verbatim field value and are two units.
  const entity = run('<note>Northwind&#32;Synthetic AB and Northwind&#32;Synthetic AB</note>', { formats: ['XML'] });
  const entityUnits = entity.units.filter((unit) => unit.classification.semanticType === 'CUSTOMER_OR_PARTNER');
  assert.equal(entityUnits.length, 2);
  assert.notEqual(entityUnits[0].ref, entityUnits[1].ref);
  assert.deepEqual([...new Set(entityUnits.map((unit) => unit.location.original.kind))], ['ORIGINAL_COVER']);
  assert.equal(entity.units.every((unit) => unit.classification.status === 'RESOLVED'), true);
  // #6 instead decodes the percent runs into one view text carrying both occurrences as outer runs: the
  // accepted per-envelope representation, unchanged here, is one unit naming both runs.
  const percent = run('{"note":"Northwind%20Synthetic%20AB and Northwind%20Synthetic%20AB"}', { formats: ['JSON'] });
  const percentUnits = percent.units.filter((unit) => unit.classification.semanticType === 'CUSTOMER_OR_PARTNER');
  assert.equal(percentUnits.length, 1);
  assert.equal(percentUnits[0].location.original.kind, 'ENCODED_RUNS');
  assert.equal(percentUnits[0].location.original.spans.length, 2);
});

test('the per-occurrence identity keeps every source\'s repeats inside one decoded field value', () => {
  const decoded = (escaped, verbatim) => ['{"asset":{"note":"' + escaped + '"}}', '{"asset":{"note":"' + verbatim + '"}}'];
  const cases = [
    ['CONTACT', ...decoded('orla\\u0040example.invalid and brannick\\u0040example.invalid',
      'orla@example.invalid and brannick@example.invalid')],
    // Two lines, because #8's key-assignment rule over-covers to the end of its own line: two credentials on
    // one line are one over-covering match by design, not a dropped occurrence.
    ['SECRET', ...decoded('password\\u003dsynthetic-pass-1.invalid\\npassword\\u003dsynthetic-pass-2.invalid',
      'password=synthetic-pass-1.invalid\\npassword=synthetic-pass-2.invalid')],
    ['INFRASTRUCTURE', ...decoded('host\\u002da.example.invalid and host\\u002db.example.invalid',
      'host-a.example.invalid and host-b.example.invalid')],
  ];
  for (const [source, escaped, verbatim] of cases) {
    const decodedResult = run(escaped, { formats: ['JSON'] });
    const fieldUnits = decodedResult.units.filter((unit) => unit.sources.includes(source) && unit.location.field);
    const spans = fieldUnits.map((unit) => `${unit.location.field.valueSpan.start}-${unit.location.field.valueSpan.end}`);
    assert.equal(spans.length, 2, `${source} decoded: ${JSON.stringify(spans)}`);
    assert.notEqual(spans[0], spans[1], source);
    assert.equal(new Set(fieldUnits.map((unit) => unit.ref)).size, 2, source);
    // The verbatim spelling of the same field already reported both occurrences before this fix; it must not
    // gain a duplicate.
    const verbatimUnits = run(verbatim, { formats: ['JSON'] }).units.filter((unit) => unit.sources.includes(source));
    assert.ok(verbatimUnits.length >= 2, `${source} verbatim`);
    assert.equal(new Set(verbatimUnits.map((unit) => unit.ref)).size, verbatimUnits.length, `${source} verbatim`);
  }
});

test('one occurrence inside one decoded field value is still reported exactly once', () => {
  const input = '{"asset":{"note":"Northwind\\u0020Synthetic AB"}}';
  const result = run(input, { formats: ['JSON'] });
  const customer = result.units.filter((unit) => unit.classification.semanticType === 'CUSTOMER_OR_PARTNER');
  assert.equal(customer.length, 1);
  assert.equal(customer[0].kind, 'OCCURRENCE');
  assert.deepEqual(customer[0].location.field.valueSpan, { start: 0, end: 22 });
  assert.equal(customer[0].detectorEvidence.length, 1);
  assert.equal(result.uninspected.length, 0);
  // A trusted field hint over the same value keeps its own whole-value unit and never duplicates the match.
  const hinted = run('{"asset":{"owner":"Northwind\\u0020Synthetic AB"}}', { formats: ['JSON'] });
  assert.deepEqual(hinted.units.map((unit) => unit.kind).sort(), ['OCCURRENCE', 'WHOLE_VALUE']);
});

test('real seam reason codes are carried through unchanged', () => {
  const cases = ['A'.repeat(1 << 20), '{"asset":{"note":', new TextEncoder().encode('\uFDFA'.repeat(1 << 16)),
    new TextEncoder().encode('caf\u00e9 password=synthetic-pass.invalid')];
  for (const input of cases) {
    const detection = detect(input, { formats: ['JSON'] });
    assert.equal(result_status_matches(detection), true);
    const result = compose(detection);
    assert.equal(result.status, detection.status === 'FAILURE' ? 'FAILURE' : 'PARTIAL', String(input).slice(0, 20));
    for (const reason of detection.reasons) assert.ok(result.reasons.includes(reason), `${reason} in ${result.reasons}`);
    assert.equal(result.reasons.includes('DETECTION_UNREADABLE_REASON'), false, detection.reasons.join(','));
    assert.equal(result.uninspected.length, detection.uninspected.length);
  }
  const partial = compose(detect('A'.repeat(1 << 20)));
  assert.equal(partial.status, 'PARTIAL');
  assert.ok(partial.reasons.includes('NORMALIZATION_RUN_TOO_LONG'));
  assert.equal(partial.reasons.includes('DETECTION_UNREADABLE_REASON'), false);
  assert.ok(partial.uninspected.length > 0);
  const bytes = compose(detect(new TextEncoder().encode('caf\u00e9 password=synthetic-pass.invalid')));
  const secret = bytes.units.find((unit) => unit.sources.includes('SECRET'));
  assert.equal(secret.location.original.kind, 'UTF8_TEXT');
  assert.equal(secret.location.original.coverage, 'EXACT');
});

test('#10 whole-scan-unit match composes, and a foreign or malformed match fact is still refused', () => {
  // Paired control: the same configured detection the seam always composed, now carrying the boolean #6
  // reports beside the unchanged coverage span, still reaches a unit with the same placement.
  const detection = detect('Northwind Synthetic AB signed for pump PMP-0042');
  const configured = detection.candidates.filter((item) => item.source === 'CONFIGURED');
  assert.ok(configured.length > 0, 'the detection carries configured candidates');
  assert.ok(configured.every((item) => typeof item.wholeUnitMatch === 'boolean'),
    'every configured candidate reports one boolean whole-scan-unit match');
  const paired = compose(detection);
  assert.equal(paired.status, 'COMPLETE');
  assert.ok(paired.units.length > 0, 'the match fact does not cost the detection any unit');

  // An extended coverage whose matcher never reached the end is reported false, and the fact changes no
  // grouping: the same detection without it composes to the same units in the same places.
  const extended = detect('pump PMP-0042-UNCONFIGURED');
  const tail = extended.candidates.filter((item) => item.source === 'CONFIGURED');
  assert.ok(tail.length > 0 && tail.every((item) => item.wholeUnitMatch === false),
    'a template plus an unconfigured tail is not a whole-scan-unit match');
  const stripped = { ...extended, candidates: extended.candidates.map((item) => {
    const copy = { ...item };
    delete copy.wholeUnitMatch;
    return copy;
  }) };
  const withFact = compose(extended);
  const without = compose(stripped);
  assert.equal(withFact.units.length, without.units.length, 'the fact merges no unit and drops none');
  assert.deepEqual(JSON.parse(JSON.stringify(withFact.units)), JSON.parse(JSON.stringify(without.units)),
    'unit grouping, placement and evidence are unchanged by the fact');
  // The unit keeps no match member: composition places by the occurrence span, so the fact is evidence only.
  assert.equal(JSON.stringify(paired.units).includes('wholeUnitMatch'), false, 'a unit never carries the match fact');

  // Fault controls: a non-boolean fact, a fact on a source with no configured matcher behind it, and the
  // numeric offset members this seam accepted before are all malformed records, not hints.
  const foreign = [...detect('password=synthetic-pass.invalid').candidates,
    ...detect('build.tenant-a.invalid:443').candidates].filter((item) => item.source !== 'CONFIGURED');
  const contact = detect('Orla Synthetica', { names }).candidates.find((item) => item.source === 'CONTACT');
  assert.ok(foreign.length > 0 && contact, 'the non-configured controls exist');
  const composed = (candidates) => composeClassificationUnits({ detection: { ...detection, candidates },
    inputRef: 'input-a.invalid', scope: A, context }).reasons;
  for (const malformed of [{ wholeUnitMatch: 'true' }, { wholeUnitMatch: 1 }, { wholeUnitMatch: null },
    { matchStart: 0, matchEnd: 17 }, { matchStart: 0, matchEnd: Number.MAX_SAFE_INTEGER },
    { matchEnd: 17 }, { matchStart: 0 }]) {
    assert.deepEqual(composed([{ ...configured[0], ...malformed }]), ['INVALID_DETECTION'], JSON.stringify(malformed));
  }
  for (const candidate of [...foreign, contact]) {
    assert.deepEqual(composed([{ ...candidate, wholeUnitMatch: true }]), ['INVALID_DETECTION'],
      `${candidate.source} has no configured matcher behind it`);
  }
});

test('an unknown key inside a detection record is refused, and a planted reason is replaced, not echoed', () => {
  const real = detect('Orla Synthetica', { names });
  const extraClaimKey = { ...real, candidates: [syntheticCandidate(0, 0, 4)] };
  extraClaimKey.candidates[0].evidence = { ...extraClaimKey.candidates[0].evidence,
    claim: { semanticType: 'PERSON', subtype: 'NAME', sensitivity: 'CONFIDENTIAL', trusted: true } };
  assert.deepEqual(composeClassificationUnits({ detection: extraClaimKey, inputRef: 'input-a.invalid',
    scope: A, context }).reasons, ['INVALID_DETECTION']);

  const extraCandidateKey = { ...real, candidates: [{ ...real.candidates[0], matchedText: 'synthetic.invalid' }] };
  assert.deepEqual(composeClassificationUnits({ detection: extraCandidateKey, inputRef: 'input-a.invalid',
    scope: A, context }).reasons, ['INVALID_DETECTION']);

  // A detection reason that is not an uppercase code token is caller text; it must never be copied out.
  const planted = { ...real, reasons: ['NORMALIZATION_DEPTH_LIMIT', 'borrowed value synthetic.invalid'] };
  const result = composeClassificationUnits({ detection: planted, inputRef: 'input-a.invalid', scope: A, context });
  assert.deepEqual(result.reasons, ['DETECTION_UNREADABLE_REASON', 'NORMALIZATION_DEPTH_LIMIT']);
  assert.equal(JSON.stringify(result).includes('synthetic.invalid'), false);
  // The same holds for an opaque location reason, whose region is kept even when its text is not code-shaped.
  const opaqueText = { ...real, uninspected: [{ reason: 'borrowed value synthetic.invalid', viewId: 0,
    viewSpan: { start: 0, end: 4 }, original: { kind: 'ORIGINAL_EXACT', span: { start: 0, end: 4 } } }] };
  const opaqueResult = composeClassificationUnits({ detection: opaqueText, inputRef: 'input-a.invalid',
    scope: A, context });
  assert.equal(opaqueResult.uninspected[0].reason, 'UNREADABLE_OPAQUE_REASON');
  assert.equal(JSON.stringify(opaqueResult).includes('synthetic.invalid'), false);
  assert.equal(opaqueResult.status, 'PARTIAL');
});

test('malformed detection inputs are refused with a fixed code and never echo caller text', () => {
  const thrower = { get detection() { throw new Error('synthetic.invalid'); } };
  const real = detect('Orla Synthetica', { names });
  const cases = [
    { detection: null, inputRef: 'input-a.invalid', scope: A, context },
    { detection: 'text', inputRef: 'input-a.invalid', scope: A, context },
    { detection: [], inputRef: 'input-a.invalid', scope: A, context },
    { detection: thrower, inputRef: 'input-a.invalid', scope: A, context },
    { detection: real, inputRef: '', scope: A, context },
    { detection: real, inputRef: 'input-a.invalid', scope: { tenantRef: '', projectRef: 'p' }, context },
    { detection: real, inputRef: 'input-a.invalid', scope: A, context: { interactionRef: '', sourceRef: 's', trust: 'CONTROL' } },
    { detection: real, inputRef: 'input-a.invalid', scope: A, context: { ...context, trust: 'MODEL' } },
    { detection: { ...real, candidates: [{ source: 'CONTACT' }] }, inputRef: 'input-a.invalid', scope: A, context },
    { detection: { ...real, candidates: Object.assign(Object.create(null), { length: 1, 0: 'x' }) },
      inputRef: 'input-a.invalid', scope: A, context },
  ];
  for (const request of cases) {
    const result = composeClassificationUnits(request);
    assert.equal(result.status, 'FAILURE', JSON.stringify(Object.keys(request)));
    assert.deepEqual(result.units, []);
    assert.ok(result.reasons.length > 0);
    assert.equal(result.reasons.some((reason) => /synthetic|invalid\.invalid/iu.test(reason)), false, String(result.reasons));
  }
  const symboled = { ...real, candidates: [{ ...real.candidates[0], [Symbol('synthetic.invalid')]: 1 }] };
  const refused = composeClassificationUnits({ detection: symboled, inputRef: 'input-a.invalid', scope: A, context });
  assert.equal(refused.status, 'FAILURE');
  assert.deepEqual(refused.reasons, ['INVALID_DETECTION']);
  const getter = { ...real, get candidates() { throw new Error('synthetic.invalid'); } };
  assert.deepEqual(composeClassificationUnits({ detection: getter, inputRef: 'input-a.invalid', scope: A, context }).reasons,
    ['INVALID_DETECTION']);
  const hostile = new Proxy({ ...real, toJSON: () => ({ status: 'COMPLETE', candidates: [] }) }, {
    get(target, key) { if (key === 'candidates') throw new Error('synthetic.invalid'); return Reflect.get(target, key); },
    ownKeys() { throw new Error('synthetic.invalid'); },
  });
  const proxied = composeClassificationUnits({ detection: hostile, inputRef: 'input-a.invalid', scope: A, context });
  assert.deepEqual(proxied.reasons, ['INVALID_DETECTION']);
  const badClaim = { ...real, candidates: [syntheticCandidate(0, 0, 4)] };
  badClaim.candidates[0].evidence = { ...badClaim.candidates[0].evidence,
    claim: { semanticType: 'PERSON', confidence: 'high' } };
  assert.deepEqual(composeClassificationUnits({ detection: badClaim, inputRef: 'input-a.invalid', scope: A, context }).reasons,
    ['INVALID_DETECTION']);
  const unknownKind = syntheticDetection([syntheticCandidate(0, 0, 4,
    { original: { kind: 'ORIGINAL_GUESS', span: { start: 0, end: 4 } } })]);
  assert.deepEqual(unknownKind.reasons, ['INVALID_DETECTION']);
  const listProxy = { ...real, candidates: new Proxy([real.candidates[0]], {
    getOwnPropertyDescriptor() { throw new Error('synthetic.invalid'); },
  }) };
  assert.deepEqual(composeClassificationUnits({ detection: listProxy, inputRef: 'input-a.invalid', scope: A, context }).reasons,
    ['INVALID_DETECTION']);
  const requestProxy = new Proxy({ detection: real, inputRef: 'input-a.invalid', scope: A, context }, {
    ownKeys() { throw new Error('synthetic.invalid'); },
  });
  assert.deepEqual(composeClassificationUnits(requestProxy).reasons, ['INVALID_REQUEST']);
});

test('property: generated #7 formats reach units with honest covering provenance', () => {
  const term = 'Northwind Synthetic AB';
  const jsonEscaped = 'Northwind\\u0020Synthetic AB';
  const xmlEscaped = 'Northwind&#32;Synthetic AB';
  const cases = [
    [`note: ${term}`, {}, 'ORIGINAL_EXACT'],
    [`name: ${term}`, { formats: ['YAML'] }, 'ORIGINAL_EXACT'],
    [`<note>${xmlEscaped}</note>`, { formats: ['XML'] }, 'ORIGINAL_COVER'],
    [`{"note":"${jsonEscaped}"}`, { formats: ['JSON'] }, 'ORIGINAL_COVER'],
    [`[section]\nnote=${term}\n`, { formats: ['INI'] }, 'ORIGINAL_EXACT'],
    [`note=${term}\n`, { formats: ['DOTENV'] }, 'ORIGINAL_EXACT'],
  ];
  for (const [input, rest, expected] of cases) {
    const result = run(input, rest);
    const customer = result.units.filter((unit) => unit.classification.semanticType === 'CUSTOMER_OR_PARTNER');
    assert.ok(customer.length >= 1, input);
    assert.equal(customer.every((unit) => unit.classification.status === 'RESOLVED'), true, input);
    assert.deepEqual([...new Set(customer.map((unit) => unit.location.original.kind))], [expected], input);
    assert.equal(JSON.stringify(result).includes('Northwind'), false, input);
  }
});

const syntheticCandidate = (index, start, end, extra = {}) => ({
  source: 'CONTACT', basis: 'PATTERN',
  evidence: { version: 1, id: `synthetic.evidence.${index}`, status: 'FOUND',
    provenance: { inputRef: 'n6-synthetic', producerId: 'hylja.contact-candidates', producerVersion: '2' },
    claim: { semanticType: 'PERSON', subtype: 'NAME' } },
  view: { viewId: 0, span: { start, end }, representation: 'RAW', form: 'TEXT', encodingPath: [] },
  original: { kind: 'ORIGINAL_EXACT', span: { start, end } },
  ...extra,
});
const syntheticDetection = (candidates, rest = {}) => compose({
  status: 'COMPLETE', reasons: [], contentType: 'TEXT', uninspected: [], candidates, ...rest,
});
const result_status_matches = (detection) => ['COMPLETE', 'PARTIAL', 'FAILURE'].includes(detection.status);

test('a unit cap reports opaque coverage instead of a truncated success', () => {
  const text = Array.from({ length: MAX_UNITS + 5 }, (_, index) => `u${index}@example.invalid`).join(' ');
  const result = run(text);
  assert.equal(result.status, 'PARTIAL');
  assert.ok(result.reasons.includes('CONTACT_TOO_MANY_CANDIDATES'));
  assert.ok(result.uninspected.length > 0);

  const oversized = compose({
    status: 'COMPLETE', reasons: [], contentType: 'TEXT', uninspected: [],
    candidates: Array.from({ length: MAX_UNITS + 3 }, (_, index) => ({
      source: 'CONTACT', basis: 'PATTERN',
      evidence: { version: 1, id: `synthetic.evidence.${index}`, status: 'FOUND',
        provenance: { inputRef: 'n6-synthetic', producerId: 'hylja.contact-candidates', producerVersion: '2' },
        claim: { semanticType: 'PERSON', subtype: 'NAME' } },
      view: { viewId: 0, span: { start: index * 4, end: index * 4 + 2 }, representation: 'RAW', form: 'TEXT', encodingPath: [] },
      original: { kind: 'ORIGINAL_EXACT', span: { start: index * 4, end: index * 4 + 2 } },
    })),
  });
  assert.equal(oversized.status, 'PARTIAL');
  assert.deepEqual(oversized.reasons, ['UNIT_LIMIT']);
  assert.equal(oversized.units.length, MAX_UNITS);
  assert.equal(oversized.uninspected.length, 3);
  assert.ok(oversized.uninspected.every((item) => item.reason === 'UNIT_LIMIT' && item.original.kind === 'ORIGINAL_EXACT'));
});

test('property: generated documents and encodings report every planted occurrence with honest provenance', () => {
  const cases = [];
  for (let index = 0; index < 8; index++) {
    const term = 'Northwind  Synthetic AB';
    cases.push([`note: ${term} end`, {}, 'ORIGINAL_EXACT'],
      [JSON.stringify({ note: term }), { formats: ['JSON'] }, 'ORIGINAL_EXACT'],
      [`note=${term}`, {}, 'ORIGINAL_EXACT'],
      [`payload=${b64(`note: ${term}`)}`, {}, 'ENCODED_RUNS'],
      [`{"asset":{"owner":"${term.replace(/[ ]/gu, '\\u0020')}"}}`, { formats: ['JSON'] }, 'ORIGINAL_COVER']);
  }
  for (const [input, rest, expected] of cases) {
    const result = run(input, rest);
    const customer = result.units.filter((unit) => unit.classification.semanticType === 'CUSTOMER_OR_PARTNER');
    assert.ok(customer.length >= 1, input);
    for (const unit of customer) {
      assert.equal(unit.classification.status, 'RESOLVED', input);
      assert.equal(unit.location.original.kind, expected, input);
    }
    assert.equal(JSON.stringify(result).includes('Northwind'), false, input);
  }
});

test('the same request always composes the same units and references', () => {
  const input = 'Northwind Synthetic AB met PMP-0042 and Orla Synthetica';
  assert.equal(JSON.stringify(run(input, { names })), JSON.stringify(run(input, { names })));
});

test('bounded work: adversarial configured and contact payloads stay inside a generous ceiling', () => {
  const heavy = `${'Northwind Synthetic AB '.repeat(4_000)} ${b64('Orla Synthetica orla@example.invalid')}`;
  const started = process.hrtime.bigint();
  const result = run(`${heavy}${heavy}`);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(['COMPLETE', 'PARTIAL'].includes(result.status));
  assert.ok(result.units.length <= MAX_UNITS);
  assert.ok(elapsedMs < 20_000, `${elapsedMs}ms`);
});

test('a bounded composition still runs under a 256 MiB heap with a generated repetition payload', () => {
  const script = `
    import { composeClassificationUnits, MAX_UNITS } from './dist/classification-units.js';
    import { detectNormalizedCandidates } from './dist/normalized-detection.js';
    import { createCandidateConfig } from './dist/configured-candidates.js';
    const scope = { tenantRef: 'tenant-a', projectRef: 'project-a' };
    const config = createCandidateConfig(scope,
      { terms: [{ term: 'Northwind Synthetic AB', semanticType: 'CUSTOMER_OR_PARTNER', sensitivity: 'CONFIDENTIAL' }] });
    const compose = (input, ref) => composeClassificationUnits({ detection: detectNormalizedCandidates(
      { input, inputRef: ref, scope, configured: config }), inputRef: ref, scope,
      context: { interactionRef: 'interaction-a.invalid', sourceRef: 'source-a.invalid', trust: 'UNTRUSTED' } });
    const moderate = compose('Northwind Synthetic AB '.repeat(200), 'heap-small');
    const flood = compose('Northwind Synthetic AB '.repeat(20_000), 'heap-flood');
    process.stdout.write(JSON.stringify({ moderate: { status: moderate.status, units: moderate.units.length },
      flood: { status: flood.status, units: flood.units.length, reasons: flood.reasons, opaque: flood.uninspected.length },
      max: MAX_UNITS }));
  `;
  const child = spawnSync(process.execPath, ['--max-old-space-size=256', '--input-type=module', '-e', script],
    { encoding: 'utf8', timeout: 60_000, maxBuffer: 4096 });
  assert.equal(child.status, 0, `child exit ${child.status}, signal ${child.signal}`);
  const result = JSON.parse(child.stdout);
  assert.equal(result.moderate.status, 'COMPLETE');
  assert.equal(result.moderate.units, 200);
  assert.equal(result.flood.status, 'PARTIAL');
  assert.equal(result.flood.units, 0);
  assert.ok(result.flood.reasons.includes('CONFIGURED_TOO_MANY_CANDIDATES'));
  assert.ok(result.flood.opaque > 0);
  assert.ok(result.flood.units <= result.max);
});