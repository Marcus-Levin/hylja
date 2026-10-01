// Behavioral tests for the PROPOSED #67 Gym annotation export schema.
// Evaluation-only, NON-ENFORCING and unwired: nothing here classifies content, selects a treatment,
// authorizes release, registers a #39 oracle or proves tenant isolation. Assertions are on exported
// behavior (fixed reason codes, derived label states, deterministic ordering), never on the prose of
// the design document.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  validateGymAnnotationArtifact, gymEffectiveLabel, gymReviewQueue, gymOracleEligibility,
  GYM_PRIORITY_WEIGHTS,
} from './gym-annotation-schema.mjs';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const exampleName = 'docs/examples/gym-annotation-export-draft-0.1.json';
const example = JSON.parse(readFileSync(resolve(sourceRoot, exampleName), 'utf8'));
/** Fixed evaluation clock: eligibility tests never depend on the wall clock. */
const CLOCK = '2026-01-20T00:00:00Z';
const PROBE = 'synthetic-do-not-echo-probe.invalid';
/** Every string shape an artifact may legitimately contain; nothing else can be written. */
const LEAF_SHAPES = [
  /^(?:[a-z]+)-[a-z0-9]+(?:-[a-z0-9]+)*$/u,                    // opaque prefixed ref
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u,                    // UTC timestamp
  /^[a-z0-9][a-z0-9._-]{0,31}\/[a-z0-9][a-z0-9._-]{0,31}$/u,     // version/questionnaire ref
  /^[a-z0-9][a-z0-9._-]{0,31}$/u,                               // version label
  /^hylja\.[a-z][a-z0-9-]{0,31}\/[0-9]{1,3}$/u,                  // declared producer
  /^[A-Z][A-Z0-9_]{0,63}$/u,                                    // semantic / enum name
  /^[A-Z]{2}$/u,                                                // jurisdiction code
  /^(?:\/[A-Za-z0-9_.-]{1,64}){1,16}$/u,                         // bounded pointer
];

function artifact() { return structuredClone(example); }
function occurrence(target, ref) {
  return target.occurrences.find((entry) => entry.occurrenceRef === ref);
}
function reasons(target) { return validateGymAnnotationArtifact(target).reasons; }
function judged(overrides = {}) {
  return { status: 'LABELED',
    semantic: { semanticType: 'ENGINEERING_IDENTIFIER', domain: 'PLM', subtype: 'DRAWING_NUMBER' },
    privacy: { personalData: 'UNKNOWN', specialCategory: 'UNKNOWN', jurisdictions: [] },
    sensitivity: 'INTERNAL', confidence: 'HIGH', ...overrides };
}
function entry(version, role, groundTruth, extra = {}) {
  return { version, decidedByRoleRef: role, decidedAt: '2026-01-16T08:00:00Z', groundTruth, ...extra };
}

test('the committed export example is a valid, value-free, unreviewed development artifact', () => {
  const result = validateGymAnnotationArtifact(example);
  assert.equal(result.status, 'VALID');
  assert.deepEqual([...result.reasons], []);
  assert.equal(example.releaseAuthority, false);
  assert.equal(example.evaluationOnly, true);
  assert.equal(example.containsProtectedValues, false);
  assert.equal(example.rawMaterialIncluded, false);
  assert.equal(example.partition, 'DEVELOPMENT');
  // No key anywhere may carry a value, a note, a digest or a treatment.
  const forbidden = new Set(['value', 'values', 'text', 'note', 'notes', 'digest', 'sha256', 'fingerprint',
    'treatment', 'treatments', 'policy', 'authorization', 'keep', 'raw', 'original', 'preview', 'snippet']);
  const walk = (node) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (node === null || typeof node !== 'object') return;
    for (const [key, value] of Object.entries(node)) {
      assert.ok(!forbidden.has(key), `unexpected value-bearing key ${key}`);
      walk(value);
    }
  };
  walk(example);
  for (const source of example.sources) {
    // Raw material is referenced by an opaque store handle only, and only for non-synthetic imports.
    assert.ok(source.rawMaterialRef === null || /^store-[a-z0-9-]+$/u.test(source.rawMaterialRef));
  }
});

test('no free-form string leaf can carry content into an artifact', () => {
  // Every string leaf in the committed example is one of a small set of strict shapes, so a value,
  // a tenant dictionary term or a pasted sentence has no field to travel in.
  const sweep = (node, trail) => {
    if (Array.isArray(node)) return node.forEach((value, index) => sweep(value, `${trail}/${index}`));
    if (node === null || typeof node !== 'object') {
      if (typeof node === 'string') {
        assert.ok(LEAF_SHAPES.some((shape) => shape.test(node)),
          `unconstrained string leaf at ${trail}`);
      } else {
        assert.ok(node === null || ['boolean', 'number'].includes(typeof node), `leaf type at ${trail}`);
      }
      return;
    }
    for (const [key, value] of Object.entries(node)) sweep(value, `${trail}/${key}`);
  };
  sweep(example, 'artifact');
  // Negative controls: each of these previously-accepted carriers is now a rejection.
  const probes = [
    ['dictionaryState as a tenant term', ['occurrences', 0, 'dictionaryState'],
      'tenant-term-northstar-plc-tag-123', 'DICTIONARY_STATE_INVALID'],
    ['dictionaryState as free text', ['occurrences', 0, 'dictionaryState'], 'customer said it is fine',
      'DICTIONARY_STATE_INVALID'],
    ['dictionaryState as a number', ['occurrences', 0, 'dictionaryState'], 42, 'DICTIONARY_STATE_INVALID'],
    ['dictionaryState as an object', ['occurrences', 0, 'dictionaryState'], { note: 'x' },
      'DICTIONARY_STATE_INVALID'],
    ['sourcePath with prose', ['fields', 0, 'sourcePath'], '/input/customer Northstar drawing 100284/A',
      'BAD_SOURCE_PATH'],
    ['sourcePath with markup', ['fields', 0, 'sourcePath'], '/input/"quoted"<script>alert(1)</script>',
      'BAD_SOURCE_PATH'],
    ['sourcePath with a pointer escape', ['fields', 0, 'sourcePath'], '/input/a~1b', 'BAD_SOURCE_PATH'],
    ['sourcePath with an empty segment', ['fields', 0, 'sourcePath'], '/input//text', 'BAD_SOURCE_PATH'],
    ['sourcePath as a native path', ['fields', 0, 'sourcePath'], '../etc/passwd', 'BAD_SOURCE_PATH'],
    ['questionnaireVersion as prose', ['provenance', 'questionnaireVersion'],
      'tenant engineer confirmed the tag by mail', 'PROVENANCE_INCOMPLETE'],
    ['toolchainVersion as prose', ['provenance', 'toolchainVersion'], 'annotator laptop build notes',
      'PROVENANCE_INCOMPLETE'],
  ];
  for (const [label, trail, value, code] of probes) {
    const target = artifact();
    let node = target;
    for (const key of trail.slice(0, -1)) node = node[key];
    node[trail.at(-1)] = value;
    assert.ok(reasons(target).includes(code), `${label} must be rejected as ${code}`);
  }
  // A second view of the same import path and normalization is a duplicate, not a reinterpretation.
  const secondView = artifact();
  secondView.fields.push({ ...structuredClone(secondView.fields[0]), fieldRef: 'field-2' });
  secondView.sources[0].fieldCount = 2;
  assert.ok(reasons(secondView).includes('DUPLICATE_FIELD_VIEW'));
  // A different normalization of the same path is a separate, legal view with its own lengths.
  const otherView = artifact();
  const normalized = { ...structuredClone(otherView.fields[0]), fieldRef: 'field-2', normalization: 'NFC' };
  otherView.fields.push(normalized);
  otherView.sources[0].fieldCount = 2;
  assert.ok(!reasons(otherView).includes('DUPLICATE_FIELD_VIEW'));
});

test('ground truth and policy preference are mechanically separate spaces', () => {
  const mixed = artifact();
  occurrence(mixed, 'occ-0001').labelHistory[0].groundTruth.treatment = 'KEEP';
  assert.ok(reasons(mixed).includes('GROUND_TRUTH_INVALID'));
  const note = artifact();
  occurrence(note, 'occ-0001').labelHistory[0].note = 'tenant engineer confirmed by mail';
  assert.ok(reasons(note).includes('LABEL_HISTORY_INVALID'));
  const preferenceLeak = artifact();
  occurrence(preferenceLeak, 'occ-0001').labelHistory[0].taskPreference = { status: 'LABELED', taskRef: 'task-demo-0001' };
  assert.ok(reasons(preferenceLeak).includes('TASK_PREFERENCE_INVALID'));
  // A KEEP preference for a port does not change the port's semantic label or sensitivity.
  const port = occurrence(example, 'occ-0004');
  assert.equal(port.labelHistory[0].taskPreference.preferredRepresentation, 'KEEP');
  assert.equal(port.labelHistory[0].groundTruth.semantic.subtype, 'PORT');
  assert.equal(port.labelHistory[0].groundTruth.sensitivity, 'INTERNAL');
});

test('authority, protected-value and blind-partition claims are rejected', () => {
  for (const [key, value, code] of [
    ['releaseAuthority', true, 'RELEASE_AUTHORITY_CLAIM'],
    ['containsProtectedValues', true, 'PROTECTED_VALUE_FIELD'],
    ['rawMaterialIncluded', true, 'RAW_MATERIAL_CLAIM'],
    ['evaluationOnly', false, 'EVALUATION_ONLY_REQUIRED'],
    ['partition', 'HELD_OUT', 'BLIND_PARTITION_FORBIDDEN'],
    ['partition', 'BLIND', 'BLIND_PARTITION_FORBIDDEN'],
  ]) {
    const target = artifact();
    target[key] = value;
    assert.ok(reasons(target).includes(code), `${key}=${value} must be rejected`);
  }
  const rawImport = artifact();
  rawImport.sources[0].importKind = 'TENANT_APPROVED_RAW';
  assert.ok(reasons(rawImport).includes('SOURCE_INVALID'));
});

test('tenant scope cannot be relabelled as global, and global scope accepts only synthetic imports', () => {
  const escalated = artifact();
  escalated.scope.level = 'GLOBAL';
  assert.ok(reasons(escalated).includes('SCOPE_ESCALATION_ATTEMPT'));
  const mixed = artifact();
  mixed.scope = { level: 'GLOBAL' };
  mixed.retention.class = 'DERIVED_SYNTHETIC';
  assert.ok(reasons(mixed).includes('GLOBAL_SOURCE_NOT_SYNTHETIC'));
  const wrongRetention = artifact();
  wrongRetention.retention.class = 'DERIVED_SYNTHETIC';
  assert.ok(reasons(wrongRetention).includes('RETENTION_SCOPE_CONFLICT'));
  const withoutProject = artifact();
  delete withoutProject.scope.projectRef;
  assert.ok(reasons(withoutProject).includes('SCOPE_CONFLICT'));
  // Positive control: a global artifact derived only from synthetic imports is representable.
  const global = artifact();
  global.scope = { level: 'GLOBAL' };
  global.retention.class = 'DERIVED_SYNTHETIC';
  global.status = 'REVIEWED';
  global.sources = [global.sources[0]];
  global.fields = [global.fields[0]];
  global.occurrences = global.occurrences.filter((entry) => entry.fieldRef === 'field-0');
  global.occurrences = global.occurrences.map((entry) => ({ ...entry, labelHistory: entry.labelHistory.slice(0, 1) }));
  assert.equal(validateGymAnnotationArtifact(global).status, 'VALID');
});

test('source-side identity is a decoded code-point span and byte coordinates must be declared', () => {
  const outOfBounds = artifact();
  occurrence(outOfBounds, 'occ-0001').span.end = 400;
  assert.ok(reasons(outOfBounds).includes('SPAN_OUT_OF_BOUNDS'));
  const empty = artifact();
  occurrence(empty, 'occ-0001').span.end = occurrence(empty, 'occ-0001').span.start;
  assert.ok(reasons(empty).includes('SPAN_INVALID'));
  const bytes = artifact();
  occurrence(bytes, 'occ-0001').span.unit = 'UTF8_BYTE';
  assert.ok(reasons(bytes).includes('SPAN_UNIT_NOT_ALLOWED'));
  const utf16 = artifact();
  occurrence(utf16, 'occ-0001').span.unit = 'UTF16_CODE_UNIT';
  assert.ok(reasons(utf16).includes('SPAN_UNIT_NOT_ALLOWED'));
  // An ASCII field cannot carry a derived byte span, and a DERIVED field must carry one.
  const redundant = artifact();
  occurrence(redundant, 'occ-0001').span.derivedByteSpan = { unit: 'UTF8_BYTE', start: 12, end: 20 };
  assert.ok(reasons(redundant).includes('BYTE_MAPPING_INCONSISTENT'));
  const missing = artifact();
  missing.fields[1].byteMapping = 'DERIVED';
  assert.ok(reasons(missing).includes('BYTE_MAPPING_INCONSISTENT'));
  const backward = artifact();
  backward.fields[1].byteMapping = 'DERIVED';
  for (const ref of ['occ-0005', 'occ-0006']) occurrence(backward, ref).span.derivedByteSpan = {
    unit: 'UTF8_BYTE', start: 1, end: 20 };
  assert.ok(reasons(backward).includes('BYTE_MAPPING_INCONSISTENT'));
  // Positive control: a verified non-ASCII byte coordinate is accepted and stays in range.
  const derived = artifact();
  derived.fields[1].byteMapping = 'DERIVED';
  occurrence(derived, 'occ-0005').span.derivedByteSpan = { unit: 'UTF8_BYTE', start: 7, end: 25 };
  occurrence(derived, 'occ-0006').span.derivedByteSpan = { unit: 'UTF8_BYTE', start: 30, end: 55 };
  assert.equal(validateGymAnnotationArtifact(derived).status, 'VALID');
  const shorter = artifact();
  shorter.fields[1].byteLength = 40;
  assert.ok(reasons(shorter).includes('BYTE_MAPPING_INCONSISTENT'));
});

test('occurrence identity, repeats, overlaps and relationships are checked', () => {
  const duplicate = artifact();
  const sameSpan = structuredClone(occurrence(duplicate, 'occ-0001'));
  sameSpan.occurrenceRef = 'occ-0008';
  duplicate.occurrences.push(sameSpan);
  assert.ok(reasons(duplicate).includes('DUPLICATE_OCCURRENCE_SPAN'));
  const sameRef = artifact();
  sameRef.occurrences.push({ ...structuredClone(occurrence(sameRef, 'occ-0001')), span: { unit: 'CODE_POINT', start: 70, end: 80 } });
  assert.ok(reasons(sameRef).includes('DUPLICATE_REF'));
  const dangling = artifact();
  occurrence(dangling, 'occ-0001').fieldRef = 'field-9';
  assert.ok(reasons(dangling).includes('DANGLING_REF'));
  const missingTarget = artifact();
  occurrence(missingTarget, 'occ-0001').relationships =
    [{ kind: 'SAME_AS', targetOccurrenceRef: 'occ-0099', status: 'SETTLED' }];
  assert.ok(reasons(missingTarget).includes('DANGLING_REF'));
  const selfLink = artifact();
  occurrence(selfLink, 'occ-0001').relationships =
    [{ kind: 'SAME_AS', targetOccurrenceRef: 'occ-0001', status: 'SETTLED' }];
  assert.ok(reasons(selfLink).includes('SELF_RELATIONSHIP'));
  const repeatedRelation = artifact();
  const relation = { kind: 'SAME_AS', targetOccurrenceRef: 'occ-0001', status: 'SETTLED' };
  occurrence(repeatedRelation, 'occ-0002').relationships = [relation, { ...relation }];
  assert.ok(reasons(repeatedRelation).includes('DUPLICATE_RELATIONSHIP'));
  // A repeated value in two fields and an overlapping span are representable, not deduplicated.
  assert.equal(validateGymAnnotationArtifact(example).status, 'VALID');
  assert.equal(occurrence(example, 'occ-0001').entityRef, occurrence(example, 'occ-0002').entityRef);
  assert.ok(occurrence(example, 'occ-0007').span.start < occurrence(example, 'occ-0001').span.end);
});

test('field identity stays inside the declared source and its coverage is consistent', () => {
  const native = artifact();
  native.fields[0].sourcePath = '../etc/passwd';
  assert.ok(reasons(native).includes('BAD_SOURCE_PATH'));
  const absolute = artifact();
  absolute.fields[0].sourcePath = '/etc/shadow';
  // A JSON Pointer is allowed to look absolute, so a rejected pointer must fail the grammar itself.
  absolute.fields[0].sourcePath = '/input/text/../../secret';
  assert.ok(reasons(absolute).includes('BAD_SOURCE_PATH'));
  const coverage = artifact();
  coverage.sources[0].fieldCount = 2;
  assert.ok(reasons(coverage).includes('COVERAGE_MISMATCH'));
  const orphan = artifact();
  orphan.fields[0].importRef = 'import-demo-0009';
  assert.ok(reasons(orphan).includes('DANGLING_REF'));
  const opaqueRef = artifact();
  occurrence(opaqueRef, 'occ-0001').occurrenceRef = '100284/A';
  assert.ok(reasons(opaqueRef).includes('OCCURRENCE_INVALID'));
});

test('candidate provenance is complete, declared and consistent with the origin', () => {
  const undeclared = artifact();
  occurrence(undeclared, 'occ-0001').proposalProducers = ['hylja.unlisted-candidate-source/1'];
  assert.ok(reasons(undeclared).includes('PROPOSAL_PROVENANCE_INVALID'));
  const manualNoReason = artifact();
  delete occurrence(manualNoReason, 'occ-0003').missReason;
  assert.ok(reasons(manualNoReason).includes('MANUAL_WITHOUT_MISS_REASON'));
  const manualWithProducer = artifact();
  occurrence(manualWithProducer, 'occ-0003').proposalProducers = ['hylja.infrastructure-identifiers/1'];
  assert.ok(reasons(manualWithProducer).includes('MANUAL_WITHOUT_MISS_REASON'));
  const proposedWithReason = artifact();
  occurrence(proposedWithReason, 'occ-0001').missReason = 'DETECTOR_MISS_CONFIRMED';
  assert.ok(reasons(proposedWithReason).includes('PROPOSED_WITH_MISS_REASON'));
  const proposedNoProducer = artifact();
  occurrence(proposedNoProducer, 'occ-0001').proposalProducers = [];
  assert.ok(reasons(proposedNoProducer).includes('PROPOSED_WITH_MISS_REASON'));
  const noProvenance = artifact();
  delete noProvenance.provenance.createdAt;
  assert.ok(reasons(noProvenance).includes('PROVENANCE_INCOMPLETE'));
  const duplicateProducer = artifact();
  duplicateProducer.provenance.proposalProducers =
    [...duplicateProducer.provenance.proposalProducers, 'hylja.contact-candidates/2'];
  assert.ok(reasons(duplicateProducer).includes('DUPLICATE_REF'));
  // A manual-only artifact declares no producer, which is legal; a proposed one may not.
  const manualOnly = artifact();
  manualOnly.provenance.proposalProducers = [];
  manualOnly.fields = manualOnly.fields.map((field) => ({ ...field, proposalProducers: [] }));
  manualOnly.occurrences = manualOnly.occurrences.map((entry) => {
    const source = entry.origin === 'PROPOSED'
      ? { ...entry, origin: 'MANUAL', proposalProducers: [], missReason: 'DETECTOR_MISS_CONFIRMED' }
      : entry;
    return { ...source, labelHistory: source.labelHistory.slice(0, 1) };
  });
  assert.equal(validateGymAnnotationArtifact(manualOnly).status, 'VALID');
  const undeclaredProposal = artifact();
  undeclaredProposal.provenance.proposalProducers = [];
  assert.ok(reasons(undeclaredProposal).includes('PROPOSAL_PROVENANCE_INVALID'));
});

test('label history is append-only, ordered and never silently overwritten', () => {
  const gap = artifact();
  occurrence(gap, 'occ-0002').labelHistory = [occurrence(gap, 'occ-0002').labelHistory[1]];
  assert.ok(reasons(gap).includes('LABEL_HISTORY_INVALID'));
  const duplicateVersion = artifact();
  const history = occurrence(duplicateVersion, 'occ-0002').labelHistory;
  history.push({ ...structuredClone(history[1]), version: 2 });
  assert.ok(reasons(duplicateVersion).includes('LABEL_HISTORY_INVALID'));
  const earlyAdjudication = artifact();
  const early = occurrence(earlyAdjudication, 'occ-0002').labelHistory;
  early[0].adjudication = { resolution: 'ADJUDICATED' };
  assert.ok(reasons(earlyAdjudication).includes('ADJUDICATION_NOT_FINAL'));
  // A correction is a new append that keeps both prior entries.
  const corrected = artifact();
  const target = occurrence(corrected, 'occ-0002');
  const before = target.labelHistory.length;
  target.labelHistory.push(entry(before + 1, 'role-reviewer-1', judged(), { adjudication: { resolution: 'ADJUDICATED' } }));
  assert.equal(validateGymAnnotationArtifact(corrected).status, 'VALID');
  assert.equal(target.labelHistory.length, before + 1);
  assert.equal(gymEffectiveLabel(corrected, 'occ-0002').state, 'ADJUDICATED');
  const unresolved = artifact();
  const open = occurrence(unresolved, 'occ-0002');
  open.labelHistory.push(entry(3, 'role-reviewer-1', judged(), { adjudication: { resolution: 'UNRESOLVED' } }));
  assert.equal(gymEffectiveLabel(unresolved, 'occ-0002').state, 'UNRESOLVED');
});

test('disagreement, UNKNOWN and abstention are distinct preserved states', () => {
  assert.equal(gymEffectiveLabel(example, 'occ-0002').state, 'OPEN_DISAGREEMENT');
  assert.deepEqual(gymEffectiveLabel(example, 'occ-0002').decidedByRoleRefs,
    ['role-annotator-1', 'role-annotator-2']);
  assert.equal(gymEffectiveLabel(example, 'occ-0005').state, 'UNDECIDED');
  assert.equal(occurrence(example, 'occ-0005').labelHistory[0].groundTruth.status, 'UNKNOWN');
  assert.equal(occurrence(example, 'occ-0006').labelHistory[0].groundTruth.status, 'ABSTAINED');
  // A preference can be recorded while the semantic question is escalated as a policy question.
  assert.equal(gymEffectiveLabel(example, 'occ-0006').hasTaskPreference, true);
  const withdrawal = artifact();
  const decided = occurrence(withdrawal, 'occ-0001');
  decided.labelHistory.push(entry(2, 'role-annotator-2',
    { status: 'UNKNOWN', unknownReason: 'CONFLICTING_EVIDENCE' }));
  assert.equal(gymEffectiveLabel(withdrawal, 'occ-0001').state, 'OPEN_DISAGREEMENT');
  // Answering an earlier UNKNOWN resolves it into a single uncorroborated assertion, not a conflict.
  const answered = artifact();
  occurrence(answered, 'occ-0005').labelHistory.push(entry(2, 'role-annotator-3', judged()));
  assert.equal(gymEffectiveLabel(answered, 'occ-0005').state, 'SOLE_ENTRY');
  // A human UNKNOWN in the middle must never hide a conflict: disagreement is measured against the
  // newest earlier assertion, so [LABELED(A), UNKNOWN, LABELED(B)] is still contested.
  const sandwiched = artifact();
  const target = occurrence(sandwiched, 'occ-0001');
  target.labelHistory = [target.labelHistory[0], entry(2, 'role-annotator-2',
    { status: 'UNKNOWN', unknownReason: 'CONFLICTING_EVIDENCE' }),
  entry(3, 'role-annotator-3', judged({ semantic: { semanticType: 'ENGINEERING_IDENTIFIER', domain: 'PLM',
    subtype: 'PARTITION_NUMBER' } }))];
  assert.equal(validateGymAnnotationArtifact(sandwiched).status, 'VALID');
  assert.equal(gymEffectiveLabel(sandwiched, 'occ-0001').state, 'OPEN_DISAGREEMENT');
  assert.deepEqual(gymEffectiveLabel(sandwiched, 'occ-0001').versions, [1, 2, 3]);
  // The same assertion re-stated after the doubt is agreement between two matching assertions; a
  // different payload, including a different confidence band, is a different assertion.
  const restated = artifact();
  const restatedTarget = occurrence(restated, 'occ-0001');
  restatedTarget.labelHistory = [restatedTarget.labelHistory[0], entry(2, 'role-annotator-2',
    { status: 'UNKNOWN', unknownReason: 'INSUFFICIENT_CONTEXT' }),
  entry(3, 'role-annotator-2', structuredClone(restatedTarget.labelHistory[0].groundTruth))];
  assert.equal(gymEffectiveLabel(restated, 'occ-0001').state, 'AGREED');
  const rebanded = artifact();
  const rebandedTarget = occurrence(rebanded, 'occ-0001');
  rebandedTarget.labelHistory = [rebandedTarget.labelHistory[0], entry(2, 'role-annotator-2',
    { status: 'UNKNOWN', unknownReason: 'INSUFFICIENT_CONTEXT' }),
  entry(3, 'role-annotator-2', judged())];
  assert.equal(gymEffectiveLabel(rebanded, 'occ-0001').state, 'OPEN_DISAGREEMENT');
  // No majority vote: a 2-to-1 split stays contested.
  const split = artifact();
  const splitTarget = occurrence(split, 'occ-0001');
  const alternative = judged({ semantic: { semanticType: 'ENGINEERING_IDENTIFIER', domain: 'PLM',
    subtype: 'PARTITION_NUMBER' } });
  splitTarget.labelHistory = [splitTarget.labelHistory[0], entry(2, 'role-annotator-2', alternative),
    entry(3, 'role-annotator-3', splitTarget.labelHistory[0].groundTruth)];
  assert.equal(gymEffectiveLabel(split, 'occ-0001').state, 'OPEN_DISAGREEMENT');
  // Only an explicit adjudication settles any of these.
  for (const candidate of [sandwiched, split]) {
    const disputed = occurrence(candidate, 'occ-0001');
    disputed.labelHistory.push(entry(4, 'role-reviewer-1', judged(),
      { adjudication: { resolution: 'ADJUDICATED' } }));
    assert.equal(gymEffectiveLabel(candidate, 'occ-0001').state, 'ADJUDICATED');
  }
  const badUnknown = artifact();
  occurrence(badUnknown, 'occ-0005').labelHistory[0].groundTruth =
    { status: 'UNKNOWN', unknownReason: 'INSUFFICIENT_CONTEXT', sensitivity: 'PUBLIC' };
  assert.ok(reasons(badUnknown).includes('GROUND_TRUTH_INVALID'));
  const contradictory = artifact();
  occurrence(contradictory, 'occ-0001').labelHistory[0].groundTruth.privacy =
    { personalData: 'NO', specialCategory: 'YES', jurisdictions: [] };
  assert.ok(reasons(contradictory).includes('GROUND_TRUTH_INVALID'));
  const unknownRef = artifact();
  assert.equal(gymEffectiveLabel(unknownRef, 'occ-0099'), null);
  assert.equal(gymEffectiveLabel(unknownRef, PROBE), null);
});

test('task fidelity contracts are task-owner authored, opaque-target and separately scoped', () => {
  const predicates = artifact();
  predicates.taskFidelityContracts[0].requirements[0].predicates = ['FORMAT', 'EXISTENCE'];
  assert.ok(reasons(predicates).includes('FIDELITY_CONTRACT_INVALID'));
  const rawTarget = artifact();
  rawTarget.taskFidelityContracts[0].requirements[0].targetRef = '100284/A';
  assert.ok(reasons(rawTarget).includes('FIDELITY_CONTRACT_INVALID'));
  const danglingTarget = artifact();
  danglingTarget.taskFidelityContracts[0].requirements[0].targetRef = 'occ-0099';
  assert.ok(reasons(danglingTarget).includes('DANGLING_REF'));
  const noOwner = artifact();
  delete noOwner.taskFidelityContracts[0].ownerRoleRef;
  assert.ok(reasons(noOwner).includes('FIDELITY_CONTRACT_INVALID'));
  const duplicateTarget = artifact();
  duplicateTarget.taskFidelityContracts[0].requirements.push(
    { targetRef: 'occ-0003', predicates: ['KIND'] });
  assert.ok(reasons(duplicateTarget).includes('DUPLICATE_REF'));
  // An entity-level target resolves through the shared entityRef of a repeated value.
  const entityTarget = artifact();
  entityTarget.taskFidelityContracts[0].requirements = [{ targetRef: 'entity-0001', predicates: ['CONSISTENCY'] }];
  assert.equal(validateGymAnnotationArtifact(entityTarget).status, 'VALID');
  assert.equal(gymEffectiveLabel(entityTarget, 'occ-0002').hasFidelityContract, true);
  assert.equal(gymEffectiveLabel(entityTarget, 'occ-0004').hasFidelityContract, false);
});

test('an ambiguous, unreviewed, tombstoned, expired or empty artifact is ineligible ground truth', () => {
  const eligible = gymOracleEligibility(example, CLOCK);
  assert.equal(eligible.eligible, false);
  assert.deepEqual([...eligible.reasons], ['ARTIFACT_UNREVIEWED', 'OPEN_DISAGREEMENT_PRESENT',
    'UNDECIDED_LABEL_PRESENT', 'UNVERIFIED_BYTE_MAPPING_PRESENT']);
  const reviewed = artifact();
  reviewed.status = 'REVIEWED';
  reviewed.fields[1].byteMapping = 'DERIVED';
  occurrence(reviewed, 'occ-0005').span.derivedByteSpan = { unit: 'UTF8_BYTE', start: 7, end: 25 };
  occurrence(reviewed, 'occ-0006').span.derivedByteSpan = { unit: 'UTF8_BYTE', start: 30, end: 55 };
  const disputed = occurrence(reviewed, 'occ-0002');
  disputed.labelHistory.push(entry(3, 'role-reviewer-1', judged(), { adjudication: { resolution: 'ADJUDICATED' } }));
  for (const ref of ['occ-0005', 'occ-0006']) {
    const target = occurrence(reviewed, ref);
    target.labelHistory.push(entry(2, 'role-annotator-1', judged()));
  }
  assert.equal(validateGymAnnotationArtifact(reviewed).status, 'VALID');
  const settled = gymOracleEligibility(reviewed, CLOCK);
  assert.equal(settled.eligible, true);
  assert.deepEqual([...settled.reasons], []);
  // Permanently unresolved human disagreement stays ineligible: it is not a silent majority vote.
  const stuck = structuredClone(reviewed);
  occurrence(stuck, 'occ-0002').labelHistory = [
    occurrence(stuck, 'occ-0002').labelHistory[0],
    entry(2, 'role-reviewer-1', judged(), { adjudication: { resolution: 'UNRESOLVED' } }),
  ];
  assert.deepEqual([...gymOracleEligibility(stuck, CLOCK).reasons], ['UNRESOLVED_ADJUDICATION_PRESENT']);
  // An unadjudicated conflict hidden behind a human UNKNOWN is ineligible too, not flattened to agreed.
  const sandwiched = structuredClone(reviewed);
  const contested = occurrence(sandwiched, 'occ-0002');
  contested.labelHistory = [contested.labelHistory[0], entry(2, 'role-annotator-2',
    { status: 'UNKNOWN', unknownReason: 'CONFLICTING_EVIDENCE' }),
  entry(3, 'role-annotator-3', judged({ semantic: { semanticType: 'ENGINEERING_IDENTIFIER', domain: 'PLM',
    subtype: 'PARTITION_NUMBER' } }))];
  assert.equal(gymEffectiveLabel(sandwiched, 'occ-0002').state, 'OPEN_DISAGREEMENT');
  assert.deepEqual([...gymOracleEligibility(sandwiched, CLOCK).reasons], ['OPEN_DISAGREEMENT_PRESENT']);
  // A deletion is a deletion: a tombstone can never be replayed as registered ground truth.
  const tombstoned = structuredClone(reviewed);
  tombstoned.retention.deletionState = 'TOMBSTONED';
  tombstoned.retention.tombstonedAt = '2026-02-01T00:00:00Z';
  tombstoned.occurrences = [];
  tombstoned.taskFidelityContracts = [];
  const tombstoneResult = gymOracleEligibility(tombstoned, CLOCK);
  assert.equal(tombstoneResult.eligible, false);
  assert.ok(tombstoneResult.reasons.includes('ARTIFACT_TOMBSTONED'));
  assert.ok(tombstoneResult.reasons.includes('NO_OCCURRENCES'));
  // An empty artifact has no ground truth to register.
  const empty = structuredClone(reviewed);
  empty.occurrences = [];
  empty.taskFidelityContracts = [];
  assert.ok(gymOracleEligibility(empty, CLOCK).reasons.includes('NO_OCCURRENCES'));
  // Retention expiry is enforced, and an unusable clock fails closed instead of assuming "valid".
  assert.ok(gymOracleEligibility(reviewed, '2026-06-01T00:00:00Z').reasons.includes('ARTIFACT_EXPIRED'));
  assert.ok(!gymOracleEligibility(reviewed, CLOCK).reasons.includes('ARTIFACT_EXPIRED'));
  assert.ok(gymOracleEligibility(reviewed, Date.parse(CLOCK)).eligible, 'epoch-millisecond clock');
  assert.ok(gymOracleEligibility(reviewed, 'nonsense').reasons.includes('EXPIRY_UNVERIFIABLE'));
  // A superseded artifact is reported as superseded, not merely unreviewed.
  const superseded = artifact();
  superseded.status = 'SUPERSEDED';
  assert.ok(gymOracleEligibility(superseded, CLOCK).reasons.includes('ARTIFACT_SUPERSEDED'));
  assert.ok(!gymOracleEligibility(superseded, CLOCK).reasons.includes('ARTIFACT_UNREVIEWED'));
  assert.equal(gymOracleEligibility({ artifactVersion: 'gym-annotation/0.1-draft' }, CLOCK).eligible, false);
});

test('review prioritization is deterministic, non-learned and never drops an occurrence', () => {
  const queue = gymReviewQueue(example);
  assert.equal(queue.length, example.occurrences.length);
  assert.equal(queue[0].occurrenceRef, 'occ-0002');
  for (let index = 1; index < queue.length; index++) {
    assert.ok(queue[index - 1].score >= queue[index].score, 'queue must be sorted by score');
  }
  for (const row of queue) {
    const expected = row.factors.reduce((total, factor) => total + GYM_PRIORITY_WEIGHTS[factor], 0);
    assert.equal(row.score, expected);
    assert.ok(row.score <= Object.values(GYM_PRIORITY_WEIGHTS).reduce((a, b) => a + b, 0));
  }
  // Order depends on artifact content, never on input array order.
  const shuffled = artifact();
  shuffled.occurrences.reverse();
  assert.deepEqual(JSON.parse(JSON.stringify(gymReviewQueue(shuffled))), JSON.parse(JSON.stringify(queue)));
  assert.deepEqual(JSON.parse(JSON.stringify(gymReviewQueue(JSON.parse(JSON.stringify(example))))),
    JSON.parse(JSON.stringify(queue)));
  // A low score is never a statement about sensitivity: the port and the confirmed miss both appear.
  const refs = queue.map((row) => row.occurrenceRef);
  assert.ok(refs.includes('occ-0004') && refs.includes('occ-0003') && refs.includes('occ-0001'));
  // A second annotator resolving the open disagreement reorders the queue deterministically.
  const adjudicated = artifact();
  const disputed = occurrence(adjudicated, 'occ-0002');
  disputed.labelHistory.push(entry(3, 'role-reviewer-1', judged(), { adjudication: { resolution: 'ADJUDICATED' } }));
  const reordered = gymReviewQueue(adjudicated);
  const settledRow = reordered.find((row) => row.occurrenceRef === 'occ-0002');
  assert.ok(!settledRow.factors.includes('OPEN_DISAGREEMENT'));
  assert.ok(settledRow.score < queue[0].score);
  // Resolving the disagreement reorders the queue deterministically rather than hiding the row.
  assert.notEqual(reordered[0].occurrenceRef, queue[0].occurrenceRef);
  assert.ok(reordered.length === queue.length);
  assert.deepEqual(JSON.parse(JSON.stringify(gymReviewQueue(adjudicated))),
    JSON.parse(JSON.stringify(reordered)));
  // An invalid or unreadable artifact yields an empty queue, never a partial ordering.
  assert.deepEqual([...gymReviewQueue({ artifactVersion: 'gym-annotation/0.1-draft' })], []);
  assert.deepEqual([...gymReviewQueue(PROBE)], []);
});

test('every label status and preference status is representable, and malformed variants are rejected', () => {
  const abstained = artifact();
  occurrence(abstained, 'occ-0006').labelHistory[0].groundTruth =
    { status: 'ABSTAINED', abstainReason: 'NOT_MY_CALL' };
  assert.ok(reasons(abstained).includes('GROUND_TRUTH_INVALID'));
  const unknownPreference = artifact();
  occurrence(unknownPreference, 'occ-0004').labelHistory[0].taskPreference =
    { status: 'UNKNOWN', taskRef: 'task-demo-0001' };
  assert.equal(validateGymAnnotationArtifact(unknownPreference).status, 'VALID');
  assert.equal(gymEffectiveLabel(unknownPreference, 'occ-0004').hasTaskPreference, false);
  const preferenceLeak = artifact();
  occurrence(preferenceLeak, 'occ-0004').labelHistory[0].taskPreference =
    { status: 'UNKNOWN', taskRef: 'task-demo-0001', preferredRepresentation: 'KEEP' };
  assert.ok(reasons(preferenceLeak).includes('TASK_PREFERENCE_INVALID'));
  const badPreference = artifact();
  occurrence(badPreference, 'occ-0004').labelHistory[0].taskPreference =
    { status: 'LABELED', taskRef: 'task-demo-0001', destinationRef: 'sink-profile-demo-external',
      exactValueRequired: 'MAYBE', preferredRepresentation: 'KEEP' };
  assert.ok(reasons(badPreference).includes('TASK_PREFERENCE_INVALID'));
  const badSink = artifact();
  occurrence(badSink, 'occ-0004').labelHistory[0].taskPreference.destinationRef = 'plc-gateway-07.example.invalid';
  assert.ok(reasons(badSink).includes('TASK_PREFERENCE_INVALID'));
});

test('degenerate field and source records fail closed', () => {
  const noLength = artifact();
  delete noLength.fields[0].codePointLength;
  assert.ok(reasons(noLength).includes('FIELD_INVALID'));
  const noSourceKind = artifact();
  delete noSourceKind.sources[0].importKind;
  assert.ok(reasons(noSourceKind).includes('SOURCE_INVALID'));
  const syntheticWithStore = artifact();
  syntheticWithStore.sources[0].rawMaterialRef = 'store-restricted-demo-01';
  assert.ok(reasons(syntheticWithStore).includes('RAW_MATERIAL_CLAIM'));
  const sanitizedWithoutStore = artifact();
  sanitizedWithoutStore.sources[1].rawMaterialStore = 'NONE';
  assert.ok(reasons(sanitizedWithoutStore).includes('RAW_MATERIAL_CLAIM'));
  const badEntity = artifact();
  occurrence(badEntity, 'occ-0001').entityRef = 'Node Alpha';
  assert.ok(reasons(badEntity).includes('BAD_REF'));
  const badPath = artifact();
  badPath.fields[0].sourcePath = 'input/text';
  assert.ok(reasons(badPath).includes('BAD_SOURCE_PATH'));
});

test('retention, deletion and tombstoning are explicit', () => {
  const inconsistent = artifact();
  inconsistent.retention.deletionState = 'ACTIVE';
  inconsistent.retention.tombstonedAt = '2026-02-01T00:00:00Z';
  assert.ok(reasons(inconsistent).includes('TOMBSTONE_CONFLICT'));
  const undated = artifact();
  undated.retention.deletionState = 'TOMBSTONED';
  assert.ok(reasons(undated).includes('TOMBSTONE_CONFLICT'));
  const tombstone = artifact();
  tombstone.retention.deletionState = 'TOMBSTONED';
  tombstone.retention.tombstonedAt = '2026-02-01T00:00:00Z';
  assert.ok(reasons(tombstone).includes('TOMBSTONE_CONFLICT'));
  tombstone.occurrences = [];
  tombstone.taskFidelityContracts = [];
  assert.equal(validateGymAnnotationArtifact(tombstone).status, 'VALID');
  const missingExpiry = artifact();
  delete missingExpiry.retention.expiresAt;
  assert.ok(reasons(missingExpiry).includes('RETENTION_INVALID'));
  const unknownVersion = artifact();
  unknownVersion.artifactVersion = 'gym-annotation/9.9';
  assert.ok(reasons(unknownVersion).includes('UNSUPPORTED_ARTIFACT_VERSION'));
});

test('malformed, hostile and oversized artifacts fail closed without echoing content', () => {
  for (const raw of [undefined, null, PROBE, 42, [], new Map(), () => PROBE]) {
    const result = validateGymAnnotationArtifact(raw);
    assert.equal(result.status, 'INVALID');
    assert.ok(result.reasons.length > 0);
    assert.ok(!JSON.stringify(result).includes(PROBE));
  }
  const throwingGetter = artifact();
  Object.defineProperty(throwingGetter, 'occurrences', { get() { throw new Error(PROBE); }, enumerable: true });
  const getterResult = validateGymAnnotationArtifact(throwingGetter);
  assert.equal(getterResult.status, 'INVALID');
  assert.ok(!JSON.stringify(getterResult).includes(PROBE));
  const proxy = new Proxy(artifact(), { ownKeys() { throw new Error(PROBE); } });
  const proxyResult = validateGymAnnotationArtifact(proxy);
  assert.equal(proxyResult.status, 'INVALID');
  assert.ok(!JSON.stringify(proxyResult).includes(PROBE));
  assert.equal(gymEffectiveLabel(proxy, 'occ-0001'), null);
  assert.deepEqual([...gymReviewQueue(proxy)], []);
  assert.equal(gymOracleEligibility(proxy).eligible, false);
  // The occurrence bound is applied before any per-item validation work.
  const oversized = artifact();
  oversized.occurrences = Array.from({ length: 5000 }, (_, index) => ({ occurrenceRef: `occ-${index}` }));
  const bounded = validateGymAnnotationArtifact(oversized);
  assert.ok(bounded.reasons.includes('ARTIFACT_TOO_LARGE'));
  // The bound is applied before any per-item validation work.
  assert.ok(!bounded.reasons.includes('OCCURRENCE_INVALID'));
});
