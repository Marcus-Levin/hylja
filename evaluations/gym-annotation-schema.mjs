// #67 PROPOSED Gym annotation export schema. Evaluation-only, NON-ENFORCING and UNWIRED.
//
// This module checks the *shape, separation, scope and provenance* of the proposed
// `gym-annotation/0.1-draft` export described in docs/specs/gym-annotation-design.md. It is a
// development aid for that design: it does not classify content, select a treatment, authorize
// release or restoration, register a #39 oracle, promote anything to global scope, or feed the
// Policy Engine. It is not wired into src/, any adapter, or any runtime path, and it is not an
// authentication, authorization or tenancy boundary: scope labels inside an artifact are
// self-declared data, exactly like #39 fixture metadata, so a caller able to fabricate an
// artifact can fabricate its scope. It reads no files, opens no network connection and holds no
// state. Failures return fixed reason codes only and never echo input content.
//
// Value-free by construction: every string leaf in an artifact is an opaque ref, a fixed enum, a
// bounded version label, a UTC timestamp, an uppercase name, a two-letter code, a producer id, or a
// pointer segment of key/token characters. There is no value, preview, note, digest or fingerprint
// field and no free-text field of any kind, so a tenant dictionary term, a customer name or a pasted
// value has no place to go.
//
// Frozen vocabulary is reused from the existing modules so the proposal cannot drift from the
// contract names: sensitivity (#3), policy treatment vocabulary (#4) and the draft-2 privacy and
// task-fidelity vocabularies from the PROPOSED information model. Reusing those names does not
// accept decision 010 or wire that draft anywhere.
import { SENSITIVITIES } from '../dist/classification.js';
import { POLICY_TREATMENTS } from '../dist/policy.js';
import { ATTRIBUTE_STATES, FIDELITY_PREDICATES } from '../dist/information-model-draft.js';

export const GYM_ARTIFACT_VERSION = 'gym-annotation/0.1-draft';
export const GYM_ARTIFACT_KINDS = Object.freeze([
  'ANNOTATION_EXPORT', 'TENANT_DICTIONARY_PROPOSAL', 'CALIBRATION_SET_PROPOSAL',
  'TASK_PREFERENCE_PROPOSAL', 'HARD_NEGATIVE_SET_PROPOSAL', 'TAXONOMY_EVIDENCE_PROPOSAL',
]);
export const GYM_ARTIFACT_STATUSES = Object.freeze(['DRAFT_UNREVIEWED', 'REVIEWED', 'SUPERSEDED']);
/** DEVELOPMENT is the only partition a Gym artifact may ever claim; blind families stay blind. */
export const GYM_PARTITIONS = Object.freeze(['DEVELOPMENT']);
export const GYM_SCOPE_LEVELS = Object.freeze(['TENANT', 'GLOBAL']);
export const GYM_RETENTION_CLASSES = Object.freeze(['TENANT_RESTRICTED', 'DERIVED_SYNTHETIC']);
export const GYM_DELETION_STATES = Object.freeze(['ACTIVE', 'TOMBSTONED']);
/** Un-sanitized raw import is deliberately absent: it is a separate, reviewed change. */
export const GYM_IMPORT_KINDS = Object.freeze(['SYNTHETIC_GENERATED', 'TENANT_APPROVED_SANITIZED']);
export const GYM_RAW_MATERIAL_STORES = Object.freeze(['NONE', 'RESTRICTED_TENANT_IMPORT']);
export const GYM_UNIT_KINDS = Object.freeze(['TEXT_UNIT', 'STRUCTURED_FIELD']);
export const GYM_NORMALIZATIONS = Object.freeze(['IDENTITY', 'NFC', 'NFKC']);
/**
 * IDENTICAL: the decoded field is ASCII, so code-point offsets equal UTF-8 byte offsets and no
 * derived coordinate exists. DERIVED: a UTF-8 byte span is carried and was verified against the
 * decoded bytes. UNVERIFIED: no byte coordinate is asserted, so byte-coordinate consumers (the #5
 * seam) must treat the field as untested rather than guess a mapping.
 */
export const GYM_BYTE_MAPPINGS = Object.freeze(['IDENTICAL', 'DERIVED', 'UNVERIFIED']);
export const GYM_COVERAGE = Object.freeze(['COMPLETE', 'PARTIAL', 'FAILURE']);
export const GYM_ORIGINS = Object.freeze(['PROPOSED', 'MANUAL']);
/** A fixed enum, not a dictionary term: a tenant term must never be written into an artifact. */
export const GYM_DICTIONARY_STATES = Object.freeze(['MATCHED', 'NO_MATCH', 'UNKNOWN', 'NOT_APPLICABLE']);
export const GYM_MISS_REASONS = Object.freeze([
  'DETECTOR_MISS_CONFIRMED', 'STRUCTURED_FIELD_MISSED', 'COMPOUND_OR_COMPOSITE_SPAN',
  'CONTEXT_REFERENCE_MISSED',
]);
export const GYM_RELATIONSHIP_KINDS =
  Object.freeze(['SAME_AS', 'ALIAS_OF', 'REFERENCES', 'PART_OF', 'DERIVED_FROM']);
export const GYM_RELATIONSHIP_STATUSES = Object.freeze(['SETTLED', 'OPEN_DISAGREEMENT', 'UNRESOLVED']);
export const GYM_LABEL_STATUSES = Object.freeze(['LABELED', 'UNKNOWN', 'ABSTAINED']);
export const GYM_UNKNOWN_REASONS = Object.freeze([
  'INSUFFICIENT_CONTEXT', 'AMBIGUOUS_SUBTYPE', 'NO_ACCESS_TO_SOURCE_SYSTEM', 'CONFLICTING_EVIDENCE',
]);
/** POLICY_QUESTION_ESCALATED is the explicit "this is a policy decision, not my semantic call". */
export const GYM_ABSTAIN_REASONS = Object.freeze([
  'NOT_QUALIFIED_FOR_DOMAIN', 'OUT_OF_OWNERSHIP', 'TIME_BUDGET', 'POLICY_QUESTION_ESCALATED',
]);
export const GYM_CONFIDENCE_BANDS = Object.freeze(['HIGH', 'MEDIUM', 'LOW']);
export const GYM_PREFERENCE_STATUSES = Object.freeze(['LABELED', 'UNKNOWN']);
export const GYM_EXACT_VALUE_REQUIRED = Object.freeze(['YES', 'SOMETIMES', 'NO']);
export const GYM_ADJUDICATION_RESOLUTIONS = Object.freeze(['ADJUDICATED', 'UNRESOLVED']);
export const GYM_LABEL_STATES = Object.freeze([
  'SOLE_ENTRY', 'AGREED', 'OPEN_DISAGREEMENT', 'ADJUDICATED', 'UNRESOLVED', 'UNDECIDED',
]);

/**
 * Deterministic, non-learned review-order weights. The score is a display order for human
 * attention: it is not a probability, not a calibrated risk measure and never a decision input.
 * Every component describes *evidence about a label*, never the value of a label.
 */
export const GYM_PRIORITY_WEIGHTS = Object.freeze({
  OPEN_DISAGREEMENT: 40, UNDECIDED: 25, LOW_CONFIDENCE: 20, MEDIUM_CONFIDENCE: 8,
  MANUAL_CANDIDATE_MISS: 15, PARTIAL_FIELD_COVERAGE: 15, DICTIONARY_NO_MATCH: 10,
  DICTIONARY_UNKNOWN: 5, UNSEEN_SUBTYPE: 10, PREFERENCE_WITHOUT_FIDELITY: 10,
  MISSING_ENTITY_LINK: 5,
});
export const GYM_BOUNDS = Object.freeze({
  sources: 64, fields: 512, occurrences: 4096, labelsPerOccurrence: 64, relationships: 16,
  fidelityContracts: 64, requirementsPerContract: 256, producers: 32, jurisdictions: 16,
  refLength: 64, pathLength: 256, pointerSegments: 16, reasons: 32,
});

const REF = /^([a-z]+)-[a-z0-9]+(?:-[a-z0-9]+)*$/u;
/**
 * A source path is a *bounded* pointer: RFC 6901 escaping (`~0`, `~1`) is not supported in v0, and
 * each segment is a short key/token. This keeps a pointer from carrying spaces, quotes, markup or
 * any other free-form content, at the cost of a documented restriction on exotic JSON keys.
 */
const POINTER_SEGMENT = /^[A-Za-z0-9_.-]{1,64}$/u;
const PRODUCER = /^hylja\.[a-z][a-z0-9-]{0,31}\/[0-9]{1,3}$/u;
const VERSION_LABEL = /^[a-z0-9][a-z0-9._-]{0,31}$/u;
const VERSION_REF = /^[a-z0-9][a-z0-9._-]{0,31}\/[a-z0-9][a-z0-9._-]{0,31}$/u;
const NAME = /^[A-Z][A-Z0-9_]{0,63}$/u;
const JURISDICTION = /^[A-Z]{2}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

/** Snapshot own enumerable data descriptors once; getters, symbols and exotic prototypes fail. */
function shape(value, required, optional = []) {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length > required.length + optional.length) return null;
    const allowed = new Set([...required, ...optional]);
    const result = Object.create(null);
    for (const key of keys) {
      if (typeof key !== 'string' || !allowed.has(key)) return null;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return null;
      result[key] = descriptor.value;
    }
    for (const key of required) if (!Object.hasOwn(result, key)) return null;
    return result;
  } catch { return null; }
}
function list(value, max) {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
    const keys = Reflect.ownKeys(value);
    const length = Object.getOwnPropertyDescriptor(value, 'length')?.value;
    if (typeof length !== 'number' || !Number.isSafeInteger(length) || length > max) return null;
    if (keys.length !== length + 1) return null;
    const result = [];
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return null;
      result.push(descriptor.value);
    }
    return result;
  } catch { return null; }
}
function inSet(value, set) { return typeof value === 'string' && set.includes(value); }
function member(value, set) { return inSet(value, set) ? value : undefined; }
/** Opaque, prefixed, lower-case refs. The grammar rejects dotted hosts, IPs, URLs and paths. */
function ref(value, prefixes) {
  if (typeof value !== 'string' || value.length > GYM_BOUNDS.refLength) return undefined;
  const match = REF.exec(value);
  return match && prefixes.includes(match[1]) ? value : undefined;
}
function count(value) { return Number.isSafeInteger(value) && value >= 0 ? value : undefined; }
function offset(value) { return Number.isSafeInteger(value) && value >= 0 ? value : undefined; }
function timestamp(value) { return typeof value === 'string' && TIMESTAMP.test(value) ? value : undefined; }
function name(value) { return typeof value === 'string' && NAME.test(value) ? value : undefined; }
function versionLabel(value) {
  return typeof value === 'string' && VERSION_LABEL.test(value) ? value : undefined;
}
/** Tool/questionnaire identity such as `gym-annotator/0.1-draft`: bounded, no free text. */
function versionRef(value) {
  return typeof value === 'string' && VERSION_REF.test(value) ? value : undefined;
}
function producer(value) { return typeof value === 'string' && PRODUCER.test(value) ? value : undefined; }
function producerList(value, allowed) {
  const items = list(value, GYM_BOUNDS.producers);
  if (!items) return null;
  const result = [];
  for (const item of items) {
    const entry = producer(item);
    if (!entry || (allowed !== undefined && !allowed.includes(entry))) return null;
    result.push(entry);
  }
  return result;
}
function frozen(value) { return Object.freeze(value); }
/**
 * Top-level collections are bounded before any per-item work, so an oversized artifact is rejected
 * as oversized rather than walked. Returns the item array, 'TOO_LARGE', or null for a bad shape.
 */
function topList(value, max) {
  const items = list(value, max);
  if (items) return items;
  try {
    return Array.isArray(value) && value.length > max ? 'TOO_LARGE' : null;
  } catch { return null; }
}
function collect(result, fail) {
  if (result === 'TOO_LARGE') { fail('ARTIFACT_TOO_LARGE'); return []; }
  if (!result) { fail('ARTIFACT_INVALID_SHAPE'); return []; }
  return result;
}

/* ------------------------------- label state ------------------------------- */

function samePayload(left, right) { return JSON.stringify(left) === JSON.stringify(right); }
/**
 * The effective label is the newest history entry. There is no edit and no delete: a correction is
 * a new append. Disagreement is measured against the newest *earlier assertion*, not against the
 * immediately previous entry, so a human `UNKNOWN` in the middle can never hide a conflict:
 *   - a final `adjudication` entry decides the occurrence either way;
 *   - a newest `UNKNOWN`/`ABSTAINED` entry after an assertion is an open disagreement (a
 *     qualification, not a silent withdrawal), and is `UNDECIDED` only when nothing asserted yet;
 *   - a newest asserted entry with no earlier assertion is `SOLE_ENTRY` (recorded, uncorroborated),
 *     which is also the state reached by answering an earlier `UNKNOWN` or abstention;
 *   - otherwise the newest assertion is compared with the newest earlier assertion: identical
 *     payloads are `AGREED`, different ones are `OPEN_DISAGREEMENT`. A 2-to-1 split therefore stays
 *     contested: there is no majority vote here.
 */
function labelState(history) {
  if (!history.length) return 'UNDECIDED';
  const newest = history[history.length - 1];
  if (newest.adjudication) return newest.adjudication === 'ADJUDICATED' ? 'ADJUDICATED' : 'UNRESOLVED';
  const asserted = history.filter((entry) => entry.groundTruth.status === 'LABELED');
  if (newest.groundTruth.status !== 'LABELED') {
    return asserted.length ? 'OPEN_DISAGREEMENT' : 'UNDECIDED';
  }
  if (asserted.length < 2) return 'SOLE_ENTRY';
  const previous = asserted[asserted.length - 2];
  return samePayload(previous.groundTruth, newest.groundTruth) ? 'AGREED' : 'OPEN_DISAGREEMENT';
}

/* --------------------------------- parsing --------------------------------- */

function parseGroundTruth(raw, fail) {
  const record = shape(raw, ['status'],
    ['semantic', 'privacy', 'sensitivity', 'confidence', 'unknownReason', 'abstainReason']);
  if (!record) { fail('GROUND_TRUTH_INVALID'); return null; }
  const status = member(record.status, GYM_LABEL_STATUSES);
  // The critical separation is mechanical: this key set can never carry a treatment, a preference,
  // a free-text note or a raw value, because every other key is rejected above.
  if (status === 'UNKNOWN') {
    if (Object.keys(record).length !== 2 || !member(record.unknownReason, GYM_UNKNOWN_REASONS)) {
      fail('GROUND_TRUTH_INVALID');
      return null;
    }
    return { status, unknownReason: record.unknownReason };
  }
  if (status === 'ABSTAINED') {
    if (Object.keys(record).length !== 2 || !member(record.abstainReason, GYM_ABSTAIN_REASONS)) {
      fail('GROUND_TRUTH_INVALID');
      return null;
    }
    return { status, abstainReason: record.abstainReason };
  }
  if (!status) { fail('GROUND_TRUTH_INVALID'); return null; }
  const semantic = shape(record.semantic, ['semanticType', 'subtype'], ['domain']);
  const privacy = shape(record.privacy, ['personalData', 'specialCategory', 'jurisdictions']);
  const jurisdictions = privacy ? list(privacy.jurisdictions, GYM_BOUNDS.jurisdictions) : null;
  const semanticType = semantic ? name(semantic.semanticType) : undefined;
  const subtype = semantic ? name(semantic.subtype) : undefined;
  const domain = semantic && semantic.domain !== undefined ? name(semantic.domain) : undefined;
  if (!semantic || !privacy || !jurisdictions || !semanticType || !subtype ||
      (semantic.domain !== undefined && !domain) ||
      !member(privacy.personalData, ATTRIBUTE_STATES) || !member(privacy.specialCategory, ATTRIBUTE_STATES) ||
      new Set(jurisdictions).size !== jurisdictions.length || jurisdictions.some((code) => !JURISDICTION.test(code)) ||
      !inSet(record.sensitivity, SENSITIVITIES) || !member(record.confidence, GYM_CONFIDENCE_BANDS) ||
      Object.keys(record).length !== 5) { fail('GROUND_TRUTH_INVALID'); return null; }
  if (privacy.specialCategory === 'YES' && privacy.personalData !== 'YES') {
    fail('GROUND_TRUTH_INVALID');
    return null;
  }
  return {
    status,
    semantic: { semanticType, subtype, ...(domain !== undefined ? { domain } : {}) },
    privacy: { personalData: privacy.personalData, specialCategory: privacy.specialCategory,
      jurisdictions: [...jurisdictions].sort() },
    sensitivity: record.sensitivity, confidence: record.confidence,
  };
}

function parsePreference(raw, fail) {
  const record = shape(raw, ['status', 'taskRef'],
    ['destinationRef', 'exactValueRequired', 'preferredRepresentation']);
  const status = record ? member(record.status, GYM_PREFERENCE_STATUSES) : undefined;
  const taskRef = record ? ref(record.taskRef, ['task']) : undefined;
  if (!status || !taskRef) { fail('TASK_PREFERENCE_INVALID'); return null; }
  // A policy preference is advisory evidence about one destination and one task. It is never a
  // treatment decision, never a semantic label and never a permission.
  if (status === 'UNKNOWN') {
    if (Object.keys(record).length !== 2) { fail('TASK_PREFERENCE_INVALID'); return null; }
    return { status, taskRef };
  }
  const destinationRef = ref(record.destinationRef, ['sink']);
  if (!destinationRef || !member(record.exactValueRequired, GYM_EXACT_VALUE_REQUIRED) ||
      !member(record.preferredRepresentation, POLICY_TREATMENTS) || Object.keys(record).length !== 5) {
    fail('TASK_PREFERENCE_INVALID');
    return null;
  }
  return { status, taskRef, destinationRef, exactValueRequired: record.exactValueRequired,
    preferredRepresentation: record.preferredRepresentation };
}

function parseHistory(raw, fail) {
  const items = list(raw, GYM_BOUNDS.labelsPerOccurrence);
  if (!items || !items.length) { fail('LABEL_HISTORY_INVALID'); return []; }
  const history = [];
  for (let index = 0; index < items.length; index++) {
    const entry = shape(items[index], ['version', 'decidedByRoleRef', 'decidedAt', 'groundTruth'],
      ['taskPreference', 'adjudication']);
    const decider = entry ? ref(entry.decidedByRoleRef, ['role']) : undefined;
    if (!entry || entry.version !== index + 1 || !decider || !timestamp(entry.decidedAt)) {
      fail('LABEL_HISTORY_INVALID');
      continue;
    }
    const groundTruth = parseGroundTruth(entry.groundTruth, fail);
    if (!groundTruth) continue;
    const preference = entry.taskPreference === undefined ? undefined :
      parsePreference(entry.taskPreference, fail);
    let adjudication;
    if (entry.adjudication !== undefined) {
      const record = shape(entry.adjudication, ['resolution']);
      adjudication = record ? member(record.resolution, GYM_ADJUDICATION_RESOLUTIONS) : undefined;
      if (!adjudication) { fail('ADJUDICATION_INVALID'); continue; }
      // Only the newest append may adjudicate; an adjudication buried mid-history is ambiguous.
      if (index !== items.length - 1) { fail('ADJUDICATION_NOT_FINAL'); continue; }
    }
    history.push(Object.freeze({ version: entry.version, decidedByRoleRef: decider, adjudication,
      groundTruth: Object.freeze(groundTruth),
      ...(preference ? { taskPreference: Object.freeze(preference) } : {}) }));
  }
  if (!history.length) { fail('LABEL_HISTORY_INVALID'); return []; }
  return history;
}

function parse(raw) {
  const reasons = new Set();
  const fail = (reason) => { if (reasons.size < GYM_BOUNDS.reasons) reasons.add(reason); };
  const top = shape(raw, ['artifactVersion', 'artifactId', 'artifactKind', 'status', 'evaluationOnly',
    'releaseAuthority', 'partition', 'containsProtectedValues', 'rawMaterialIncluded', 'scope',
    'retention', 'provenance', 'sources', 'fields', 'occurrences', 'taskFidelityContracts']);
  if (!top) { fail('ARTIFACT_INVALID_SHAPE'); return { reasons, artifact: null }; }
  // Four claims that must never be true in a Gym artifact, checked before anything else.
  if (top.artifactVersion !== GYM_ARTIFACT_VERSION) fail('UNSUPPORTED_ARTIFACT_VERSION');
  if (!ref(top.artifactId, ['artifact'])) fail('BAD_REF');
  if (!member(top.artifactKind, GYM_ARTIFACT_KINDS)) fail('BAD_ENUM');
  if (!member(top.status, GYM_ARTIFACT_STATUSES)) fail('BAD_ENUM');
  if (top.releaseAuthority !== false) fail('RELEASE_AUTHORITY_CLAIM');
  if (top.evaluationOnly !== true) fail('EVALUATION_ONLY_REQUIRED');
  if (top.containsProtectedValues !== false) fail('PROTECTED_VALUE_FIELD');
  if (top.rawMaterialIncluded !== false) fail('RAW_MATERIAL_CLAIM');
  if (!member(top.partition, GYM_PARTITIONS)) fail('BLIND_PARTITION_FORBIDDEN');

  const scope = shape(top.scope, ['level'], ['tenantRef', 'projectRef']);
  const level = scope ? member(scope.level, GYM_SCOPE_LEVELS) : undefined;
  if (!scope || !level) fail('SCOPE_CONFLICT');
  const tenantRef = scope && scope.tenantRef !== undefined ? ref(scope.tenantRef, ['tenant']) : undefined;
  const projectRef = scope && scope.projectRef !== undefined ? ref(scope.projectRef, ['project']) : undefined;
  // A tenant artifact is never relabelled as global in place: promotion is a new artifact.
  if (level === 'TENANT' && (!tenantRef || !projectRef)) fail('SCOPE_CONFLICT');
  if (level === 'GLOBAL' && (tenantRef || projectRef)) fail('SCOPE_ESCALATION_ATTEMPT');

  const retention = shape(top.retention, ['class', 'expiresAt', 'deletionState', 'tombstonedAt']);
  const retentionClass = retention ? member(retention.class, GYM_RETENTION_CLASSES) : undefined;
  const deletionState = retention ? member(retention.deletionState, GYM_DELETION_STATES) : undefined;
  if (!retention || !retentionClass || !deletionState || !timestamp(retention.expiresAt)) {
    fail('RETENTION_INVALID');
  } else if ((level === 'TENANT') !== (retentionClass === 'TENANT_RESTRICTED')) {
    fail('RETENTION_SCOPE_CONFLICT');
  } else if (deletionState === 'ACTIVE') {
    if (retention.tombstonedAt !== null) fail('TOMBSTONE_CONFLICT');
  } else if (!timestamp(retention.tombstonedAt)) fail('TOMBSTONE_CONFLICT');

  const provenance = shape(top.provenance, ['createdAt', 'questionnaireVersion', 'vocabularyVersion',
    'informationModelVersion', 'toolchainVersion', 'intelligenceBundleRef', 'proposalProducers']);
  // Declared producers are collected independently, so one unusable provenance field does not turn
  // every field and occurrence check into a second, misleading reason code. An empty list is legal:
  // a manual-only artifact proposes nothing.
  const listed = provenance ? producerList(provenance.proposalProducers) : null;
  const distinct = listed !== null && new Set(listed).size === listed.length;
  const producers = distinct ? listed : [];
  if (!provenance || !timestamp(provenance.createdAt) || !versionRef(provenance.questionnaireVersion) ||
      !versionLabel(provenance.vocabularyVersion) || !versionLabel(provenance.informationModelVersion) ||
      !versionRef(provenance.toolchainVersion) || !ref(provenance.intelligenceBundleRef, ['bundle']) ||
      listed === null) fail('PROVENANCE_INCOMPLETE');
  else if (!distinct) fail('DUPLICATE_REF');

  const sources = new Map();
  const sourceItems = collect(topList(top.sources, GYM_BOUNDS.sources), fail);
  for (const item of sourceItems ?? []) {
    const source = shape(item, ['importRef', 'importKind', 'rawMaterialStore', 'rawMaterialRef', 'fieldCount']);
    const importRef = source ? ref(source.importRef, ['import']) : undefined;
    const importKind = source ? member(source.importKind, GYM_IMPORT_KINDS) : undefined;
    const store = source ? member(source.rawMaterialStore, GYM_RAW_MATERIAL_STORES) : undefined;
    const fieldCount = source ? count(source.fieldCount) : undefined;
    if (!source || !importRef || !importKind || !store || fieldCount === undefined) {
      fail('SOURCE_INVALID');
      continue;
    }
    if (sources.has(importRef)) { fail('DUPLICATE_REF'); continue; }
    const synthetic = importKind === 'SYNTHETIC_GENERATED';
    // Synthetic material has no restricted store; approved sanitized material does and stays there.
    if (synthetic && (store !== 'NONE' || source.rawMaterialRef !== null)) fail('RAW_MATERIAL_CLAIM');
    if (!synthetic && (store !== 'RESTRICTED_TENANT_IMPORT' || !ref(source.rawMaterialRef, ['store']))) {
      fail('RAW_MATERIAL_CLAIM');
    }
    if (level === 'GLOBAL' && !synthetic) fail('GLOBAL_SOURCE_NOT_SYNTHETIC');
    sources.set(importRef, { importRef, importKind, fieldCount });
  }

  const fields = new Map();
  const fieldViews = new Set();
  const fieldItems = collect(topList(top.fields, GYM_BOUNDS.fields), fail);
  for (const item of fieldItems ?? []) {
    const field = shape(item, ['fieldRef', 'importRef', 'sourcePath', 'unitKind', 'codePointLength',
      'byteLength', 'normalization', 'byteMapping', 'proposalCoverage', 'proposalProducers']);
    const fieldRef = field ? ref(field.fieldRef, ['field']) : undefined;
    const importRef = field ? ref(field.importRef, ['import']) : undefined;
    const codePointLength = field ? count(field.codePointLength) : undefined;
    const byteLength = field ? count(field.byteLength) : undefined;
    if (!field || !fieldRef || !importRef || codePointLength === undefined || byteLength === undefined) {
      fail('FIELD_INVALID');
      continue;
    }
    if (fields.has(fieldRef)) { fail('DUPLICATE_REF'); continue; }
    if (!sources.has(importRef)) { fail('DANGLING_REF'); continue; }
    // A source path is a bounded, escape-free pointer: no spaces, quotes, markup or empty segments.
    const segments = typeof field.sourcePath === 'string' && field.sourcePath.length <= GYM_BOUNDS.pathLength
      ? field.sourcePath.split('/').slice(1) : null;
    if (!segments || !field.sourcePath.startsWith('/') || segments.length === 0 ||
        segments.length > GYM_BOUNDS.pointerSegments ||
        segments.some((part) => part === '.' || part === '..' || !POINTER_SEGMENT.test(part))) {
      fail('BAD_SOURCE_PATH');
    }
    if (!member(field.unitKind, GYM_UNIT_KINDS) || !member(field.normalization, GYM_NORMALIZATIONS) ||
        !member(field.byteMapping, GYM_BYTE_MAPPINGS) || !member(field.proposalCoverage, GYM_COVERAGE) ||
        !producerList(field.proposalProducers, producers)) fail('FIELD_INVALID');
    // UTF-8 encodes every code point in one to four bytes, so a byte length can never be smaller.
    // `IDENTICAL` additionally asserts an ASCII field, where the two lengths are the same number.
    if (byteLength < codePointLength) fail('BYTE_MAPPING_INCONSISTENT');
    if (field.byteMapping === 'IDENTICAL' && byteLength !== codePointLength) fail('BYTE_MAPPING_INCONSISTENT');
    // One field record per (import, path, normalization) view: a second view of the same text is a
    // second record with its own lengths and spans, never this record reinterpreted.
    const viewKey = `${importRef} ${String(field.sourcePath)} ${String(field.normalization)}`;
    if (fieldViews.has(viewKey)) { fail('DUPLICATE_FIELD_VIEW'); continue; }
    fieldViews.add(viewKey);
    fields.set(fieldRef, { fieldRef, importRef, byteMapping: member(field.byteMapping, GYM_BYTE_MAPPINGS),
      coverage: member(field.proposalCoverage, GYM_COVERAGE), codePointLength, byteLength });
  }
  for (const source of sources.values()) {
    let declared = 0;
    for (const field of fields.values()) if (field.importRef === source.importRef) declared++;
    if (declared !== source.fieldCount) fail('COVERAGE_MISMATCH');
  }

  const contracts = [];
  const contractItems = collect(topList(top.taskFidelityContracts, GYM_BOUNDS.fidelityContracts), fail);
  for (const item of contractItems ?? []) {
    const contract = shape(item, ['contractRef', 'taskRef', 'ownerRoleRef', 'requirements']);
    const contractRef = contract ? ref(contract.contractRef, ['contract', 'label']) : undefined;
    const taskRef = contract ? ref(contract.taskRef, ['task']) : undefined;
    const ownerRoleRef = contract ? ref(contract.ownerRoleRef, ['role']) : undefined;
    if (!contract || !contractRef || !taskRef || !ownerRoleRef) {
      fail('FIDELITY_CONTRACT_INVALID');
      continue;
    }
    if (contracts.some((entry) => entry.contractRef === contractRef)) { fail('DUPLICATE_REF'); continue; }
    const requirements = list(contract.requirements, GYM_BOUNDS.requirementsPerContract);
    if (!requirements || !requirements.length) { fail('FIDELITY_CONTRACT_INVALID'); continue; }
    const targets = new Set();
    for (const raw of requirements) {
      const requirement = shape(raw, ['targetRef', 'predicates']);
      const targetRef = requirement ? ref(requirement.targetRef, ['occ', 'entity']) : undefined;
      const predicates = requirement ? list(requirement.predicates, FIDELITY_PREDICATES.length) : null;
      if (!requirement || !targetRef || !predicates || !predicates.length ||
          new Set(predicates).size !== predicates.length ||
          predicates.some((predicate) => !inSet(predicate, FIDELITY_PREDICATES))) {
        fail('FIDELITY_CONTRACT_INVALID');
        continue;
      }
      if (targets.has(targetRef)) { fail('DUPLICATE_REF'); continue; }
      targets.add(targetRef);
    }
    contracts.push({ contractRef, taskRef, ownerRoleRef, targets: [...targets] });
  }

  const occurrences = [];
  const occurrenceItems = collect(topList(top.occurrences, GYM_BOUNDS.occurrences), fail);
  if (deletionState === 'TOMBSTONED' && occurrenceItems.length) fail('TOMBSTONE_CONFLICT');
  if (deletionState === 'TOMBSTONED' && contractItems.length) fail('TOMBSTONE_CONFLICT');
  const seenSpans = new Set();
  for (const item of occurrenceItems ?? []) {
    const occurrence = shape(item, ['occurrenceRef', 'fieldRef', 'span', 'origin', 'proposalProducers',
      'dictionaryState', 'relationships', 'labelHistory'], ['missReason', 'entityRef']);
    const occurrenceRef = occurrence ? ref(occurrence.occurrenceRef, ['occ']) : undefined;
    const fieldRef = occurrence ? ref(occurrence.fieldRef, ['field']) : undefined;
    if (!occurrence || !occurrenceRef || !fieldRef) { fail('OCCURRENCE_INVALID'); continue; }
    if (occurrences.some((entry) => entry.occurrenceRef === occurrenceRef)) { fail('DUPLICATE_REF'); continue; }
    const field = fields.get(fieldRef);
    if (!field) { fail('DANGLING_REF'); continue; }
    const span = shape(occurrence.span, ['unit', 'start', 'end'], ['derivedByteSpan']);
    const start = span ? offset(span.start) : undefined;
    const end = span ? offset(span.end) : undefined;
    if (!span || start === undefined || end === undefined || start >= end) { fail('SPAN_INVALID'); continue; }
    // A source-side identity is always a decoded code-point span. A UTF-8 byte offset is an
    // encoding- and serializer-dependent coordinate and may only appear as a verified derivation.
    if (span.unit !== 'CODE_POINT') fail('SPAN_UNIT_NOT_ALLOWED');
    if (end > field.codePointLength) fail('SPAN_OUT_OF_BOUNDS');
    const spanKey = `${fieldRef}/${start}/${end}`;
    if (seenSpans.has(spanKey)) { fail('DUPLICATE_OCCURRENCE_SPAN'); continue; }
    seenSpans.add(spanKey);
    let byteStart;
    let byteEnd;
    if (span.derivedByteSpan !== undefined) {
      const derived = shape(span.derivedByteSpan, ['unit', 'start', 'end']);
      byteStart = derived ? offset(derived.start) : undefined;
      byteEnd = derived ? offset(derived.end) : undefined;
      if (field.byteMapping !== 'DERIVED' || !derived || derived.unit !== 'UTF8_BYTE' ||
          byteStart === undefined || byteEnd === undefined || byteStart >= byteEnd ||
          byteEnd > field.byteLength || byteStart < start || byteEnd < end) fail('BYTE_MAPPING_INCONSISTENT');
    } else if (field.byteMapping === 'DERIVED') fail('BYTE_MAPPING_INCONSISTENT');

    const origin = member(occurrence.origin, GYM_ORIGINS);
    const occurrenceProducers = producerList(occurrence.proposalProducers, producers);
    if (!origin || !occurrenceProducers) fail('PROPOSAL_PROVENANCE_INVALID');
    else if (origin === 'PROPOSED' &&
        (occurrenceProducers.length === 0 || occurrence.missReason !== undefined)) {
      fail('PROPOSED_WITH_MISS_REASON');
    } else if (origin === 'MANUAL' &&
        (occurrenceProducers.length !== 0 || !member(occurrence.missReason, GYM_MISS_REASONS))) {
      // A manual candidate is a claim that the proposer missed something, so it carries a reason
      // and no producer; a proposed candidate carries at least one producer and no miss reason.
      fail('MANUAL_WITHOUT_MISS_REASON');
    }
    const dictionaryState = member(occurrence.dictionaryState, GYM_DICTIONARY_STATES);
    if (!dictionaryState) fail('DICTIONARY_STATE_INVALID');
    const entityRef = occurrence.entityRef !== undefined ? ref(occurrence.entityRef, ['entity']) : undefined;
    if (occurrence.entityRef !== undefined && !entityRef) fail('BAD_REF');

    const relationships = [];
    const relationItems = list(occurrence.relationships, GYM_BOUNDS.relationships);
    if (!relationItems) fail('OCCURRENCE_INVALID');
    for (const raw of relationItems ?? []) {
      const relation = shape(raw, ['kind', 'targetOccurrenceRef', 'status']);
      const kind = relation ? member(relation.kind, GYM_RELATIONSHIP_KINDS) : undefined;
      const target = relation ? ref(relation.targetOccurrenceRef, ['occ']) : undefined;
      const status = relation ? member(relation.status, GYM_RELATIONSHIP_STATUSES) : undefined;
      if (!relation || !kind || !target || !status) { fail('RELATIONSHIP_INVALID'); continue; }
      if (target === occurrenceRef) { fail('SELF_RELATIONSHIP'); continue; }
      if (relationships.some((entry) => entry.kind === kind && entry.target === target)) {
        fail('DUPLICATE_RELATIONSHIP');
        continue;
      }
      relationships.push({ kind, target, status });
    }

    const history = parseHistory(occurrence.labelHistory, fail);
    const newest = history.length ? history[history.length - 1] : undefined;
    const labeled = newest !== undefined && newest.groundTruth.status === 'LABELED';
    occurrences.push({
      occurrenceRef, fieldRef, start, end, byteStart, byteEnd, field, entityRef,
      origin: origin ?? 'PROPOSED', dictionaryState, relationships, history,
      state: labelState(history),
      confidence: labeled ? newest.groundTruth.confidence : undefined,
      subtype: labeled ? newest.groundTruth.semantic.subtype : undefined,
      sensitivity: labeled ? newest.groundTruth.sensitivity : undefined,
      preference: newest ? newest.taskPreference : undefined,
    });
  }
  for (const occurrence of occurrences) {
    for (const relation of occurrence.relationships) {
      if (!occurrences.some((entry) => entry.occurrenceRef === relation.target)) fail('DANGLING_REF');
    }
  }
  for (const contract of contracts) {
    for (const target of contract.targets) {
      const known = occurrences.some((entry) => entry.occurrenceRef === target || entry.entityRef === target);
      if (!known) fail('DANGLING_REF');
    }
  }
  const artifact = reasons.size ? null : frozen({
    artifactId: top.artifactId, artifactKind: top.artifactKind, status: top.status, level,
    deletionState, expiresAt: retention.expiresAt, occurrences, contracts,
  });
  return { reasons, artifact };
}

/* ------------------------------- public API ------------------------------- */

/** Fixed reason codes only: no path, value, span, ref, version or exception detail is returned. */
export function validateGymAnnotationArtifact(raw) {
  try {
    const { reasons } = parse(raw);
    return frozen({ status: reasons.size ? 'INVALID' : 'VALID', reasons: frozen([...reasons].sort()) });
  } catch {
    return frozen({ status: 'INVALID', reasons: frozen(['ARTIFACT_UNREADABLE']) });
  }
}

/** Derived per-occurrence label state, or null when the artifact is invalid or unreadable. */
export function gymEffectiveLabel(raw, occurrenceRef) {
  try {
    const { reasons, artifact } = parse(raw);
    if (reasons.size || !artifact || typeof occurrenceRef !== 'string') return null;
    const occurrence = artifact.occurrences.find((entry) => entry.occurrenceRef === occurrenceRef);
    if (!occurrence) return null;
    const targets = (entry) => contractTargets(artifact, entry);
    return frozen({
      occurrenceRef, fieldRef: occurrence.fieldRef, state: occurrence.state,
      versions: occurrence.history.map((entry) => entry.version),
      decidedByRoleRefs: [...new Set(occurrence.history.map((entry) => entry.decidedByRoleRef))].sort(),
      hasTaskPreference: occurrence.preference !== undefined && occurrence.preference.status === 'LABELED',
      hasFidelityContract: targets(occurrence),
    });
  } catch {
    return null;
  }
}
function contractTargets(artifact, occurrence) {
  return artifact.contracts.some((contract) => contract.targets.includes(occurrence.occurrenceRef) ||
    (occurrence.entityRef !== undefined && contract.targets.includes(occurrence.entityRef)));
}

/**
 * A deterministic, non-learned review order over one artifact. It is a display order for human
 * attention: not a probability, not a calibrated risk measure and never a decision input. It never
 * changes a label, a sensitivity value, a treatment or a policy outcome, and it never adds, drops
 * or merges occurrences. An invalid or unreadable artifact yields an empty queue, never a partial
 * ordering. Ties break on source position and then opaque ref, so the order is stable and
 * independent of input array order.
 */
export function gymReviewQueue(raw) {
  try {
    const { reasons, artifact } = parse(raw);
    if (reasons.size || !artifact) return frozen([]);
    const subtypeCounts = new Map();
    for (const occurrence of artifact.occurrences) {
      if (occurrence.subtype) subtypeCounts.set(occurrence.subtype, (subtypeCounts.get(occurrence.subtype) ?? 0) + 1);
    }
    const rows = artifact.occurrences.map((occurrence) => {
      const factors = [];
      let score = 0;
      const add = (factor) => {
        const weight = GYM_PRIORITY_WEIGHTS[factor];
        if (weight > 0) { score += weight; factors.push(factor); }
      };
      if (occurrence.state === 'OPEN_DISAGREEMENT') add('OPEN_DISAGREEMENT');
      if (occurrence.state === 'UNDECIDED' || occurrence.state === 'UNRESOLVED') add('UNDECIDED');
      if (occurrence.confidence === 'LOW') add('LOW_CONFIDENCE');
      else if (occurrence.confidence === 'MEDIUM') add('MEDIUM_CONFIDENCE');
      if (occurrence.origin === 'MANUAL') add('MANUAL_CANDIDATE_MISS');
      if (occurrence.field.coverage === 'PARTIAL') add('PARTIAL_FIELD_COVERAGE');
      if (occurrence.dictionaryState === 'NO_MATCH') add('DICTIONARY_NO_MATCH');
      else if (occurrence.dictionaryState === 'UNKNOWN') add('DICTIONARY_UNKNOWN');
      // First sighting inside this artifact only; a cross-artifact novelty signal needs the
      // aggregate store and is explicitly out of MVP scope.
      if (occurrence.subtype && subtypeCounts.get(occurrence.subtype) === 1) add('UNSEEN_SUBTYPE');
      if (occurrence.preference && occurrence.preference.status === 'LABELED' &&
          !contractTargets(artifact, occurrence)) add('PREFERENCE_WITHOUT_FIDELITY');
      if (occurrence.entityRef === undefined && occurrence.relationships.length === 0) add('MISSING_ENTITY_LINK');
      return { occurrence, score, factors: factors.sort() };
    });
    rows.sort((left, right) => right.score - left.score ||
      left.occurrence.start - right.occurrence.start ||
      (left.occurrence.fieldRef < right.occurrence.fieldRef ? -1 :
        left.occurrence.fieldRef > right.occurrence.fieldRef ? 1 : 0) ||
      (left.occurrence.occurrenceRef < right.occurrence.occurrenceRef ? -1 :
        left.occurrence.occurrenceRef > right.occurrence.occurrenceRef ? 1 : 0));
    return frozen(rows.map((row) => frozen({ occurrenceRef: row.occurrence.occurrenceRef,
      fieldRef: row.occurrence.fieldRef, score: row.score, factors: frozen(row.factors) })));
  } catch {
    return frozen([]);
  }
}

/**
 * Whether an artifact may be registered as development ground truth for #5/#39 replay.
 *
 * Blockers, all of which fail closed: an unreviewed or superseded artifact; a tombstoned one, so a
 * deletion cannot be replayed away; an expired one, or one whose expiry cannot be read, so a retention
 * rule is enforced rather than ignored; an empty one, which has no ground truth to register; an open
 * disagreement, a permanently unresolved adjudication or an undecided label, so recorded human
 * ambiguity is never silently flattened into an authoritative label; and a field whose UTF-8 byte
 * mapping was never verified, so a byte-coordinate consumer cannot guess a join.
 *
 * `now` is an optional evaluation clock (epoch milliseconds or an ISO-8601 UTC string) so callers and
 * tests are deterministic; an unusable value blocks rather than defaulting to "not expired". This is a
 * local schema gate, not #39 eligibility, and never an authorization decision. A Gym artifact is
 * authored after observing candidate output, so it can never serve as the *independent* oracle of a
 * frozen or blind protocol in any case.
 */
export function gymOracleEligibility(raw, now) {
  try {
    const { reasons, artifact } = parse(raw);
    if (reasons.size || !artifact) return frozen({ eligible: false, reasons: frozen(['ARTIFACT_INVALID']) });
    const blockers = new Set();
    if (artifact.status === 'SUPERSEDED') blockers.add('ARTIFACT_SUPERSEDED');
    else if (artifact.status !== 'REVIEWED') blockers.add('ARTIFACT_UNREVIEWED');
    if (artifact.deletionState === 'TOMBSTONED') blockers.add('ARTIFACT_TOMBSTONED');
    const clock = clockMs(now);
    if (clock === undefined) blockers.add('EXPIRY_UNVERIFIABLE');
    else if (clock > Date.parse(artifact.expiresAt)) blockers.add('ARTIFACT_EXPIRED');
    if (!artifact.occurrences.length) blockers.add('NO_OCCURRENCES');
    for (const occurrence of artifact.occurrences) {
      if (occurrence.state === 'OPEN_DISAGREEMENT') blockers.add('OPEN_DISAGREEMENT_PRESENT');
      else if (occurrence.state === 'UNRESOLVED') blockers.add('UNRESOLVED_ADJUDICATION_PRESENT');
      else if (occurrence.state === 'UNDECIDED') blockers.add('UNDECIDED_LABEL_PRESENT');
      if (occurrence.field.byteMapping === 'UNVERIFIED') blockers.add('UNVERIFIED_BYTE_MAPPING_PRESENT');
    }
    return frozen({ eligible: blockers.size === 0, reasons: frozen([...blockers].sort()) });
  } catch {
    return frozen({ eligible: false, reasons: frozen(['ARTIFACT_INVALID']) });
  }
}
/** An evaluation clock, or undefined when the caller supplied something unusable. */
function clockMs(now) {
  if (now === undefined) return Date.now();
  if (typeof now === 'number') return Number.isSafeInteger(now) ? now : undefined;
  if (typeof now === 'string' && TIMESTAMP.test(now)) return Date.parse(now);
  return undefined;
}
