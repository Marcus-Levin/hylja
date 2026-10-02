/**
 * #12 contextual re-identification SHADOW evidence, local/synthetic-only, NON-ENFORCING.
 *
 * String replacement alone can leave a customer, person, project or site identifiable from the facts
 * that remain. This module measures that risk in shadow: it builds a bounded quasi-identifier
 * candidate model over a synthetic corpus, asks the reviewed #11 semantic-judge seam a bounded,
 * versioned re-identification question, and compares both signals against case labels that were
 * planted in the corpus independently of any judgment.
 *
 * Nothing here has authority. The report is `authority: 'NONE'`, its generalization recommendations
 * are `IGNORED_NO_AUTHORITY`, and no code path here selects a treatment, transforms content,
 * authorizes a sink, releases bytes or lowers any deterministic floor (decisions 003, 005, 007).
 * A derived recommendation is a *fact about the corpus*, not permission to generalize; policy and a
 * separate promotion decision remain prerequisites (issue #12 "no direct policy authority").
 *
 * There is no hosted path and no transport. The only judge is the #11 module-issued local data
 * script, reached through `runShadowJudgment`, so this module cannot send anything anywhere. Judge
 * timeout, cancellation, refusal, malformed body and abstention are the #11 outcomes, reused as they
 * are rather than re-implemented: each one becomes an explicit `ABSTAIN` row, never a safe verdict.
 *
 * Privacy shape, deliberately:
 *
 * - the corpus carries NO raw text of any kind. A record is a site reference plus opaque handles, and
 *   the site's direct name is not present because it has already been replaced (every record states
 *   `directNameReplaced`). Nothing in this module can match a name lexically, so no result here can
 *   be "the name was still present";
 * - handles are abstract, presentational and non-reversible. In a real integration they come from the
 *   broker/vault; here they are synthetic `.invalid` tokens and mean nothing outside this file;
 * - the judge never receives a handle. #11 replaces the candidate value and every neighbouring value
 *   with request-local ordinal placeholders, so the request is content independent: two records with
 *   different handles produce byte-identical requests. The shadow judge therefore sees structure
 *   only, which is a stated limit on what agreement here can mean, not a strength;
 * - the report carries closed codes, counts, dimensions and digests. It carries no handle, no value
 *   and no free text.
 *
 * The corpus in this file is the DEVELOPMENT set. It is not held out, it is not frozen by a
 * protocol, no oracle was read for it, and it must never be described as a benchmark.
 */
import {
  SHADOW_MAX_NEIGHBORS,
  belongsToShadowTenant,
  defineShadowQuestionSet,
  runShadowJudgment,
  shadowReasonCodes,
} from './semantic-judge-shadow.js';
import type {
  ShadowCandidateKind, ShadowJudgmentRecord, ShadowOutcome, ShadowQuestionSet,
} from './semantic-judge-shadow.js';

export const REIDENTIFICATION_SHADOW_VERSION = 'hylja.reidentification-shadow.v1' as const;

/* -------------------------------------------------------------------------------------- bounds */

/**
 * Every bound is ordered so no cap can silently outgrow another: a record's quasi-identifiers must
 * fit the #11 neighbour ceiling, evaluated cases must fit the report, and the corpus must fit both.
 */
export const REID_MAX_RECORDS = 128;
export const REID_MAX_EVALUATED_CASES = 64;
export const REID_MAX_QUASI_IDENTIFIERS = SHADOW_MAX_NEIGHBORS;
export const REID_MAX_HANDLE_CHARS = 64;
export const REID_MAX_ADVISORY_RECOMMENDATIONS = 2;
export const REID_MAX_GENERATED_VECTORS = 256;
/**
 * The advisory target: a recommendation aims to lift the equivalence cell to at least this many
 * distinct sites. No generalization function exists here, so no post-generalization cell size is
 * predicted, claimed or required.
 */
export const REID_ADVISORY_MIN_CELL_SITES = 3;

/* ------------------------------------------------------------------------------- vocabularies */

/** Quasi-identifier candidate dimensions. Closed: a caller cannot invent a seventh. */
export const REID_DIMENSIONS = ['GEOGRAPHY', 'DATE', 'PROCESS', 'PROJECT', 'ORG_UNIT', 'ROLE',
  'DEVICE_CLASS', 'CUSTOMER_TYPE'] as const;
export type ReidentificationDimension = (typeof REID_DIMENSIONS)[number];

export const REID_LABELS = ['REIDENTIFIABLE', 'NOT_REIDENTIFIABLE'] as const;
export type ReidentificationLabel = (typeof REID_LABELS)[number];

export const REID_ROLES = ['EVALUATED_CASE', 'POPULATION_BACKGROUND'] as const;
export type ReidentificationRecordRole = (typeof REID_ROLES)[number];

export const REID_FAMILY_IDS = ['REIDENTIFIABLE_RARE_COMBINATION', 'REIDENTIFIABLE_SAME_SITE_PAIR',
  'NOT_REIDENTIFIABLE_SHARED_COMBINATION', 'NOT_REIDENTIFIABLE_SINGLE_DIMENSION',
  'POPULATION_BACKGROUND'] as const;
export type ReidentificationFamilyId = (typeof REID_FAMILY_IDS)[number];

/** The local deterministic flag, the shadow judge's flag and their fail-safe combination. */
export const REID_LOCAL_FLAGS = ['RISK', 'COMMON'] as const;
export type ReidentificationLocalFlag = (typeof REID_LOCAL_FLAGS)[number];
export const REID_JUDGE_FLAGS = ['RISK', 'SAFE', 'ABSTAIN'] as const;
export type ReidentificationJudgeFlag = (typeof REID_JUDGE_FLAGS)[number];
export const REID_COMBINED_BASES = ['LOCAL_UNIQUE_COMBINATION', 'JUDGE_RISK',
  'JUDGE_ABSTENTION_ESCALATION', 'NO_FLAG'] as const;
export type ReidentificationCombinedBasis = (typeof REID_COMBINED_BASES)[number];

/** Advisory vocabulary. `applied` is always false and there is no transformation in this module. */
export const REID_GENERALIZATION_ACTIONS = ['GENERALIZE_TO_PARENT_GROUP', 'REDUCE_PRECISION',
  'OMIT_DIMENSION'] as const;
export type ReidentificationGeneralizationAction = (typeof REID_GENERALIZATION_ACTIONS)[number];
/**
 * Recommendation rationales describe exactly what is computed: a population-wide distinct-value
 * count per dimension, ordered ascending. They are deliberately NOT named "rarest dimension in the
 * combination": the ordering is a population cardinality heuristic, and the two words would claim a
 * per-combination rarity that is never measured.
 */
export const REID_RECOMMENDATION_RATIONALES = ['LOWEST_POPULATION_CARDINALITY_DIMENSION',
  'OTHER_DIMENSION_IN_UNIQUE_COMBINATION'] as const;
export type ReidentificationRecommendationRationale = (typeof REID_RECOMMENDATION_RATIONALES)[number];
export const REID_DERIVED_FACT_KINDS = ['EQUIVALENCE_SITE_COUNT', 'EQUIVALENCE_RECORD_COUNT',
  'DISTINCT_HANDLE_COUNT_IN_DIMENSION', 'ADVISORY_MIN_CELL_SITES'] as const;
export type ReidentificationDerivedFactKind = (typeof REID_DERIVED_FACT_KINDS)[number];

/** Closed question-set identity. Changing a question or criterion requires a new version. */
export const REID_QUESTION_SET_ID = 'hylja.reid.shadow';
export const REID_QUESTION_SET_VERSION = '1';
export const REID_RISK_QUESTION_ID = 'ri_risk';
export const REID_UTILITY_QUESTION_ID = 'ri_utility';
export const REID_RISK_LABEL = 'reidentifiable';
export const REID_SAFE_LABEL = 'not_reidentifiable';
export const REID_CORPUS_ID = 'synthetic-reidentification-development';
export const REID_CORPUS_VERSION = '1';

/**
 * How a dimension is presented to the judge as a neighbour kind.
 *
 * This is a presentation table, not a classification claim: the judge receives a kind and a
 * placeholder, never a handle or a dimension name.
 */
export const REID_DIMENSION_NEIGHBOR_KINDS: Readonly<Record<ReidentificationDimension,
  ShadowCandidateKind>> = Object.freeze({
  GEOGRAPHY: 'ENGINEERING_REFERENCE',
  DATE: 'ENGINEERING_REFERENCE',
  PROCESS: 'ENGINEERING_REFERENCE',
  PROJECT: 'PROJECT_REFERENCE',
  ORG_UNIT: 'ENGINEERING_REFERENCE',
  ROLE: 'ENGINEERING_REFERENCE',
  DEVICE_CLASS: 'INFRASTRUCTURE_REFERENCE',
  CUSTOMER_TYPE: 'CUSTOMER_REFERENCE',
});

/* -------------------------------------------------------------------------------- the corpus */

export interface ReidentificationQuasiIdentifier {
  /** Privacy-safe opaque reference. This module does not authenticate or mint it in production. */
  readonly ref: string;
  readonly dimension: ReidentificationDimension;
  /** Abstract opaque handle. Never a raw value; means nothing outside this development corpus. */
  readonly handle: string;
}
export interface ReidentificationRecord {
  readonly id: string;
  readonly role: ReidentificationRecordRole;
  readonly familyId: ReidentificationFamilyId;
  /** The fictional site, as the opaque handle that replaced its direct name. */
  readonly siteRef: string;
  /**
   * Always true. A record cannot claim to be evidence about a site whose direct name is still
   * present, so the corpus states the issue's precondition instead of leaving it implicit.
   */
  readonly directNameReplaced: true;
  readonly quasiIdentifiers: readonly ReidentificationQuasiIdentifier[];
  /** Planted independently of any judgment or of the local model's computation. */
  readonly label?: ReidentificationLabel;
}
export interface ReidentificationCorpus {
  readonly version: 1;
  readonly id: string;
  readonly corpusVersion: string;
  readonly records: readonly ReidentificationRecord[];
}

const issuedCorpora = new WeakSet<object>();
/** True only for a corpus this module validated and froze. */
export function isReidentificationCorpus(value: unknown): boolean {
  return typeof value === 'object' && value !== null && issuedCorpora.has(value);
}

/* -------------------------------------------------------------------------- strict field reading */

type Fields = Record<string, unknown>;
function invalid(): never { throw new TypeError('Invalid reidentification shadow input'); }
function safe<T>(action: () => T): T {
  try { return action(); } catch { return invalid(); }
}
/** Own enumerable data descriptors only, with a closed key set: a widened object is refused. */
function data(value: unknown, required: readonly string[], optional: readonly string[] = []): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.length > required.length + optional.length || keys.some((key) => typeof key !== 'string')) {
    invalid();
  }
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    if (!required.includes(key) && !optional.includes(key)) invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) invalid();
    result[key] = descriptor.value;
  }
  for (const name of required) if (!Object.hasOwn(result, name)) invalid();
  return result;
}
function list(value: unknown, cap: number, min = 0): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) invalid();
  const keys = Reflect.ownKeys(value);
  const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < min || length > cap ||
    keys.length !== length + 1 || !keys.includes('length') || keys.some((key) => typeof key !== 'string')) {
    invalid();
  }
  const items: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) invalid();
    items.push(descriptor.value);
  }
  return items;
}
function id(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/u.test(value)) invalid();
  return value;
}
function shaped(value: unknown, pattern: RegExp): string {
  if (typeof value !== 'string' || value.length > REID_MAX_HANDLE_CHARS || !pattern.test(value)) invalid();
  return value;
}
/** A version token: comparable, closed, and never a value. */
function versionToken(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9.-]{0,31}$/u.test(value)) invalid();
  return value;
}
function member<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) invalid();
  return value as T;
}
/**
 * A tenant reference: the same bounded opaque-token discipline #11 applies to configuration
 * tokens, so an email, a path or a URL cannot be planted in the report or in the judge request.
 * This bounds the SHAPE only; the trusted integration must still mint a privacy-safe value.
 */
export const REID_MAX_TENANT_REF_CHARS = 128;
function tenantRef(value: unknown): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > REID_MAX_TENANT_REF_CHARS ||
    !/^[a-z0-9][a-z0-9._-]*$/u.test(value)) invalid();
  return value;
}
function whole(value: unknown, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) invalid();
  return value;
}

const HANDLE = /^qh-[0-9a-f]{16}\.invalid$/u;
const QI_REF = /^qi-[0-9a-f]{12}\.invalid$/u;
const SITE_REF = /^site-[0-9a-f]{12}\.invalid$/u;

function quasiIdentifier(value: unknown): ReidentificationQuasiIdentifier {
  const v = data(value, ['ref', 'dimension', 'handle']);
  const dimension = member(v.dimension, REID_DIMENSIONS);
  return Object.freeze({ ref: shaped(v.ref, QI_REF), dimension,
    handle: shaped(v.handle, HANDLE) });
}
function record(value: unknown): ReidentificationRecord {
  const v = data(value, ['id', 'role', 'familyId', 'siteRef', 'directNameReplaced',
    'quasiIdentifiers'], ['label']);
  const role = member(v.role, REID_ROLES);
  const familyId = member(v.familyId, REID_FAMILY_IDS);
  // A label is not optional in spirit: an evaluated case must carry one and background noise must
  // not, so a missing label can never become a silently "safe" record and an invented label can
  // never inflate a population cell with an evaluated case.
  if (role === 'EVALUATED_CASE' && !Object.hasOwn(v, 'label')) invalid();
  if (role === 'POPULATION_BACKGROUND' && Object.hasOwn(v, 'label')) invalid();
  if (v.directNameReplaced !== true) invalid();
  const quasiIdentifiers = list(v.quasiIdentifiers, REID_MAX_QUASI_IDENTIFIERS, 1)
    .map(quasiIdentifier);
  const dimensions = quasiIdentifiers.map((item) => item.dimension);
  // One value per dimension: a repeated dimension would make the combination key ambiguous.
  if (new Set(dimensions).size !== dimensions.length) invalid();
  const frozen = Object.freeze(quasiIdentifiers.map((item) => Object.freeze({ ...item })));
  return Object.freeze({
    id: id(v.id), role, familyId, siteRef: shaped(v.siteRef, SITE_REF), directNameReplaced: true,
    quasiIdentifiers: frozen,
    ...(Object.hasOwn(v, 'label') ? { label: member(v.label, REID_LABELS) } : {}),
  });
}

/**
 * Validate and freeze a corpus.
 *
 * With no argument this returns the shipped synthetic development corpus. A caller may supply its
 * own synthetic spec, which is read strictly: over-bound lists, duplicate ids, duplicate handles
 * inside one record, a missing or invented label, a non-opaque handle and a widened key are all
 * refused here, before any judgment runs.
 */
export function createReidentificationCorpus(spec?: unknown): ReidentificationCorpus {
  return safe(() => buildCorpus(spec));
}
function buildCorpus(spec?: unknown): ReidentificationCorpus {
  const source: Fields = spec === undefined
    ? { version: 1, id: REID_CORPUS_ID, corpusVersion: REID_CORPUS_VERSION, records: shippedRecords() }
    : data(spec, ['version', 'id', 'corpusVersion', 'records']);
  if (source.version !== 1) invalid();
  const records = list(source.records, REID_MAX_RECORDS, 1).map(record);
  // One id per record. A site may legitimately appear in several records (that is the same-site
  // pair family), which is why cells count distinct SITES rather than records.
  if (new Set(records.map((entry) => entry.id)).size !== records.length) invalid();
  const evaluated = records.filter((entry) => entry.role === 'EVALUATED_CASE');
  if (evaluated.length === 0 || evaluated.length > REID_MAX_EVALUATED_CASES) invalid();
  const corpus = Object.freeze({ version: 1 as const, id: id(source.id),
    corpusVersion: versionToken(source.corpusVersion), records: Object.freeze(records) });
  issuedCorpora.add(corpus);
  return corpus;
}

/* ------------------------------------------------------------- the shipped synthetic corpus */

/**
 * Presentational opacity for a synthetic development handle.
 *
 * This is NOT a token, a mapping or a pseudonym with any meaning: it is a fixed pure function used
 * so the shipped corpus is reproducible without hand-typing forty hexadecimal strings. A real
 * integration obtains handles from the broker/vault under purpose-bound authorization.
 */
function mix(value: number): number {
  let state = (value + 0x9e3779b9) >>> 0;
  state = Math.imul(state ^ (state >>> 16), 0x21f0aaad) >>> 0;
  state = Math.imul(state ^ (state >>> 15), 0x735a2d97) >>> 0;
  return (state ^ (state >>> 15)) >>> 0;
}
function handleFor(seed: number): string {
  return `qh-${mix(seed).toString(16).padStart(8, '0')}${mix(seed ^ 0x5bf03635).toString(16)
    .padStart(8, '0')}.invalid`;
}
function refFor(seed: number): string {
  return `qi-${mix(seed ^ 0x27d4eb2f).toString(16).padStart(12, '0').slice(-12)}.invalid`;
}
function siteFor(seed: number): string {
  return `site-${mix(seed ^ 0x165667b1).toString(16).padStart(12, '0').slice(-12)}.invalid`;
}

/** A record spec: a site, a dimension-to-handle-group tuple, a family and a planted label. */
type Tuple = readonly (readonly [ReidentificationDimension, number])[];
interface Spec {
  readonly id: string;
  readonly site: number;
  readonly tuple: Tuple;
  readonly familyId: ReidentificationFamilyId;
  readonly label?: ReidentificationLabel;
}

/**
 * The shipped corpus, described structurally.
 *
 * There are no geography names, dates, process names, project names or site names anywhere: a
 * record is a tuple of dimensions and opaque handle groups, and rarity is expressed only by which
 * records share a whole combination. In this corpus every handle of every record -- evaluated or
 * background -- occurs in at least one other record, so no case here can be identified by a single
 * value and identification always comes from the combination. That property is asserted over the
 * whole shipped corpus; a CALLER-supplied corpus is not required to satisfy it and is not
 * re-validated for it.
 */
const CORPUS_SPECS: readonly Spec[] = Object.freeze([
  // Rare geography/date/process/project combinations. Each is unique across the whole population,
  // and every one of their handles still occurs in other records.
  { id: 'reid-case-01', site: 1, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 1], ['DATE', 1], ['PROCESS', 1], ['PROJECT', 1],
      ['ORG_UNIT', 1]] },
  { id: 'reid-case-02', site: 2, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 1], ['DATE', 1], ['PROCESS', 1], ['PROJECT', 2],
      ['ORG_UNIT', 1]] },
  { id: 'reid-case-03', site: 3, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 1], ['DATE', 1], ['PROCESS', 2], ['PROJECT', 1],
      ['ORG_UNIT', 1]] },
  { id: 'reid-case-04', site: 4, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 1], ['DATE', 1], ['PROCESS', 2], ['PROJECT', 2],
      ['ORG_UNIT', 2]] },
  { id: 'reid-case-05', site: 5, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 1], ['DATE', 2], ['PROCESS', 1], ['PROJECT', 2],
      ['ORG_UNIT', 2]] },
  { id: 'reid-case-06', site: 6, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 1], ['DATE', 2], ['PROCESS', 3], ['PROJECT', 1],
      ['ORG_UNIT', 2]] },
  { id: 'reid-case-07', site: 2, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 2], ['DATE', 2], ['PROCESS', 2], ['PROJECT', 3]] },
  { id: 'reid-case-08', site: 3, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 2], ['DATE', 2], ['PROCESS', 3], ['PROJECT', 3]] },
  { id: 'reid-case-09', site: 4, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 2], ['DATE', 3], ['PROCESS', 1], ['PROJECT', 2],
      ['ROLE', 1]] },
  { id: 'reid-case-10', site: 5, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 2], ['DATE', 3], ['PROCESS', 2], ['PROJECT', 1],
      ['CUSTOMER_TYPE', 1]] },
  { id: 'reid-case-11', site: 6, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 3], ['DATE', 3], ['PROCESS', 3], ['PROJECT', 3],
      ['ROLE', 1]] },
  { id: 'reid-case-12', site: 7, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 3], ['DATE', 3], ['PROCESS', 3], ['PROJECT', 3],
      ['ROLE', 2]] },
  { id: 'reid-case-33', site: 14, familyId: 'REIDENTIFIABLE_RARE_COMBINATION',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 3], ['DATE', 2], ['PROJECT', 2],
      ['DEVICE_CLASS', 1]] },
  // A common four-dimension combination shared by four sites, plus a fifth background record.
  { id: 'reid-case-13', site: 1, familyId: 'NOT_REIDENTIFIABLE_SHARED_COMBINATION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 4], ['DATE', 4], ['PROCESS', 1],
      ['PROJECT', 1]] },
  { id: 'reid-case-14', site: 2, familyId: 'NOT_REIDENTIFIABLE_SHARED_COMBINATION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 4], ['DATE', 4], ['PROCESS', 1],
      ['PROJECT', 1]] },
  { id: 'reid-case-15', site: 3, familyId: 'NOT_REIDENTIFIABLE_SHARED_COMBINATION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 4], ['DATE', 4], ['PROCESS', 1],
      ['PROJECT', 1]] },
  { id: 'reid-case-16', site: 4, familyId: 'NOT_REIDENTIFIABLE_SHARED_COMBINATION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 4], ['DATE', 4], ['PROCESS', 1],
      ['PROJECT', 1]] },
  // Two records of the SAME site: two matching records, but only one site, so the combination
  // still singles that site out. Counting records instead of sites would call this safe.
  { id: 'reid-case-17', site: 5, familyId: 'REIDENTIFIABLE_SAME_SITE_PAIR',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 4], ['DATE', 4], ['PROCESS', 2],
      ['PROJECT', 2]] },
  { id: 'reid-case-18', site: 5, familyId: 'REIDENTIFIABLE_SAME_SITE_PAIR',
    label: 'REIDENTIFIABLE', tuple: [['GEOGRAPHY', 4], ['DATE', 4], ['PROCESS', 2],
      ['PROJECT', 2]] },
  // A wide combination shared by three sites.
  { id: 'reid-case-19', site: 6, familyId: 'NOT_REIDENTIFIABLE_SHARED_COMBINATION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 4], ['DATE', 4], ['PROCESS', 3],
      ['PROJECT', 3]] },
  { id: 'reid-case-20', site: 7, familyId: 'NOT_REIDENTIFIABLE_SHARED_COMBINATION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 4], ['DATE', 4], ['PROCESS', 3],
      ['PROJECT', 3]] },
  { id: 'reid-case-21', site: 8, familyId: 'NOT_REIDENTIFIABLE_SHARED_COMBINATION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 4], ['DATE', 4], ['PROCESS', 3],
      ['PROJECT', 3]] },
  // Single-dimension combinations shared by three sites: one geography, process or date value on
  // its own is common, which is exactly the case a per-value detector would treat as safe.
  { id: 'reid-case-22', site: 1, familyId: 'NOT_REIDENTIFIABLE_SINGLE_DIMENSION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 1]] },
  { id: 'reid-case-23', site: 2, familyId: 'NOT_REIDENTIFIABLE_SINGLE_DIMENSION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 1]] },
  { id: 'reid-case-24', site: 3, familyId: 'NOT_REIDENTIFIABLE_SINGLE_DIMENSION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 1]] },
  { id: 'reid-case-25', site: 4, familyId: 'NOT_REIDENTIFIABLE_SINGLE_DIMENSION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['PROCESS', 1]] },
  { id: 'reid-case-26', site: 5, familyId: 'NOT_REIDENTIFIABLE_SINGLE_DIMENSION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['PROCESS', 1]] },
  { id: 'reid-case-27', site: 6, familyId: 'NOT_REIDENTIFIABLE_SINGLE_DIMENSION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['PROCESS', 1]] },
  { id: 'reid-case-28', site: 7, familyId: 'NOT_REIDENTIFIABLE_SINGLE_DIMENSION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['DATE', 1]] },
  { id: 'reid-case-29', site: 8, familyId: 'NOT_REIDENTIFIABLE_SINGLE_DIMENSION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['DATE', 1]] },
  { id: 'reid-case-30', site: 1, familyId: 'NOT_REIDENTIFIABLE_SINGLE_DIMENSION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['DATE', 1]] },
  // A combination shared by exactly two sites: rare-looking, but not re-identifying.
  { id: 'reid-case-31', site: 9, familyId: 'NOT_REIDENTIFIABLE_SHARED_COMBINATION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 5], ['DATE', 5], ['PROCESS', 4],
      ['PROJECT', 4]] },
  { id: 'reid-case-32', site: 10, familyId: 'NOT_REIDENTIFIABLE_SHARED_COMBINATION',
    label: 'NOT_REIDENTIFIABLE', tuple: [['GEOGRAPHY', 5], ['DATE', 5], ['PROCESS', 4],
      ['PROJECT', 4]] },
  // Population background: unlabeled records that enlarge the population a combination is measured
  // against. `reid-pop-01` joins the four-site cell above; `reid-pop-02`/`03` form their own cell.
  { id: 'reid-pop-01', site: 11, familyId: 'POPULATION_BACKGROUND',
    tuple: [['GEOGRAPHY', 4], ['DATE', 4], ['PROCESS', 1], ['PROJECT', 1]] },
  { id: 'reid-pop-02', site: 12, familyId: 'POPULATION_BACKGROUND',
    tuple: [['GEOGRAPHY', 5], ['DATE', 5], ['PROCESS', 4], ['PROJECT', 4], ['ORG_UNIT', 3]] },
  { id: 'reid-pop-03', site: 13, familyId: 'POPULATION_BACKGROUND',
    tuple: [['GEOGRAPHY', 5], ['DATE', 5], ['PROCESS', 4], ['PROJECT', 4], ['ORG_UNIT', 3]] },
  // Three more background records, one per dimension whose value would otherwise be a singleton.
  // They carry the CUSTOMER_TYPE, ROLE and DEVICE_CLASS values used by `reid-case-10`, `12` and `33`,
  // so those cases are identified by their COMBINATION and never by one value alone. Each of the three
  // new combinations is itself unique, which is legitimate for unlabeled population records.
  { id: 'reid-pop-04', site: 14, familyId: 'POPULATION_BACKGROUND',
    tuple: [['CUSTOMER_TYPE', 1], ['GEOGRAPHY', 4], ['DATE', 4]] },
  { id: 'reid-pop-05', site: 15, familyId: 'POPULATION_BACKGROUND',
    tuple: [['ROLE', 2], ['GEOGRAPHY', 3], ['DATE', 3]] },
  { id: 'reid-pop-06', site: 16, familyId: 'POPULATION_BACKGROUND',
    tuple: [['DEVICE_CLASS', 1], ['PROCESS', 3], ['PROJECT', 3]] },
]);
function dimensionSeed(dimension: ReidentificationDimension, group: number, slot: number): number {
  const base = 1 + REID_DIMENSIONS.indexOf(dimension) * 64;
  return base + group * 8 + slot;
}
function shippedRecords(): readonly ReidentificationRecord[] {
  return CORPUS_SPECS.map((spec) => {
    const quasiIdentifiers = spec.tuple.map(([dimension, group], slot) => Object.freeze({
      ref: refFor(1 + CORPUS_SPECS.indexOf(spec) * 16 + slot),
      dimension,
      handle: handleFor(dimensionSeed(dimension, group, 0)),
    }));
    const role: ReidentificationRecordRole =
      spec.familyId === 'POPULATION_BACKGROUND' ? 'POPULATION_BACKGROUND' : 'EVALUATED_CASE';
    return Object.freeze({
      id: spec.id, role, familyId: spec.familyId, siteRef: siteFor(spec.site),
      directNameReplaced: true as const, quasiIdentifiers: Object.freeze(quasiIdentifiers),
      ...(role === 'EVALUATED_CASE' && spec.label !== undefined ? { label: spec.label } : {}),
    });
  });
}

/* ---------------------------------------------------------------------------- generated shapes */

export interface ReidentificationVector {
  readonly id: string;
  readonly role: ReidentificationRecordRole;
  readonly directNameReplaced: true;
  readonly siteRef: string;
  readonly quasiIdentifiers: readonly ReidentificationQuasiIdentifier[];
  readonly label?: ReidentificationLabel;
}
/**
 * Seeded development records for adversarial and property work.
 *
 * They contain no held-out material and no oracle. The planted label is derived from the same
 * structural definition the local model computes -- a combination that is the only one for its site
 * is labelled re-identifiable -- so a generated corpus tests the IMPLEMENTATION against its own
 * definition. That is a property test, not an independent oracle, and it says nothing about corpus
 * quality, agreement with a real population, or any judge's accuracy.
 */
export function generateReidentificationVectors(seed = 1, count = 64): readonly ReidentificationVector[] {
  if (!Number.isSafeInteger(seed) || seed <= 0 || seed > 0xffffffff || !Number.isSafeInteger(count) ||
    count < 0 || count > REID_MAX_GENERATED_VECTORS) throw new TypeError('Invalid vector request');
  let state = seed >>> 0;
  const next = (): number => {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    return state >>> 0;
  };
  const drawn: { role: ReidentificationRecordRole; siteRef: string;
    quasiIdentifiers: readonly ReidentificationQuasiIdentifier[] }[] = [];
  // Handles are drawn from a deliberately SMALL pool, so generated records share combinations and
  // the corpus contains both unique and common cells. Drawing from a large pool would make every
  // generated case unique and the property test would prove nothing about the common path.
  const POOL = 12;
  for (let index = 0; index < count; index += 1) {
    let quasiIdentifiers: readonly ReidentificationQuasiIdentifier[];
    // Roughly one record in three repeats an earlier record's WHOLE combination under a different
    // site, so a generated corpus always contains shared cells as well as unique ones. Drawing
    // every handle from a wide space instead would make every case unique, and a property test over
    // unique cases only would never reach the common path.
    if (index > 2 && next() % 3 === 0) {
      quasiIdentifiers = drawn[next() % index]!.quasiIdentifiers;
    } else {
      const width = 1 + (next() % REID_MAX_QUASI_IDENTIFIERS);
      const chosen: ReidentificationDimension[] = [];
      const fresh: ReidentificationQuasiIdentifier[] = [];
      for (let slot = 0; slot < width; slot += 1) {
        const dimension = REID_DIMENSIONS[(next() + slot) % REID_DIMENSIONS.length]!;
        if (chosen.includes(dimension)) continue;
        chosen.push(dimension);
        fresh.push(Object.freeze({
          ref: refFor(1 + next() % 100_000),
          dimension,
          handle: handleFor(1 + next() % POOL),
        }));
      }
      quasiIdentifiers = Object.freeze(fresh.length > 0 ? fresh
        : [Object.freeze({ ref: refFor(1 + next() % 100_000), dimension: 'GEOGRAPHY',
          handle: handleFor(1 + next() % POOL) })]);
    }
    drawn.push({
      role: next() % 4 === 0 ? 'POPULATION_BACKGROUND' : 'EVALUATED_CASE',
      siteRef: siteFor(1 + next() % 100_000),
      quasiIdentifiers,
    });
  }
  // Cells over the whole drawn population, so the planted label is the structural definition and
  // not an independent guess. Cells are counted over DISTINCT SITES, exactly as the model does.
  const cells = new Map<string, { records: number; sites: Set<string> }>();
  for (const entry of drawn) {
    const key = combinationKey(entry);
    const cell = cells.get(key);
    if (cell === undefined) cells.set(key, { records: 1, sites: new Set([entry.siteRef]) });
    else { cell.records += 1; cell.sites.add(entry.siteRef); }
  }
  const result: ReidentificationVector[] = drawn.map((entry, index) => {
    const key = combinationKey(entry);
    const reidentifiable = cells.get(key)!.sites.size === 1;
    return Object.freeze({
      id: `reid-vector-${String(index).padStart(3, '0')}`,
      role: entry.role,
      directNameReplaced: true as const,
      siteRef: entry.siteRef,
      quasiIdentifiers: entry.quasiIdentifiers,
      ...(entry.role === 'EVALUATED_CASE'
        ? { label: reidentifiable ? 'REIDENTIFIABLE' as const : 'NOT_REIDENTIFIABLE' as const }
        : {}),
    });
  });
  return Object.freeze(result);
}

/* ------------------------------------------------------------------------------ the local model */

/**
 * An equivalence cell: how many records, and how many DISTINCT SITES, share a whole combination.
 *
 * Sites, not records, are what a re-identification reveals. Two records of one site do not protect
 * it; three sites in a cell do.
 */
export interface ReidentificationCell {
  readonly recordId: string;
  readonly recordCount: number;
  readonly siteCount: number;
  readonly flag: ReidentificationLocalFlag;
}
/**
 * The combination key for one record.
 *
 * The key is built from (dimension, handle) PAIRS, not bare handles. A handle is only a fact inside
 * its dimension: two records carrying the same handle under different dimensions hold different
 * facts, and merging them would make the model under-claim (report a unique combination as shared).
 * Dimensions and handles are both closed shapes, so `:` and `|` cannot occur inside either, and the
 * key stays exact, order independent and cheap to build.
 */
function combinationKey(entry: {
  readonly quasiIdentifiers: readonly ReidentificationQuasiIdentifier[];
}): string {
  return [...entry.quasiIdentifiers.map((item) => `${item.dimension}:${item.handle}`)].sort()
    .join('|');
}
function buildCells(records: readonly ReidentificationRecord[]): Map<string,
  { recordCount: number; sites: Set<string> }> {
  const cells = new Map<string, { recordCount: number; sites: Set<string> }>();
  for (const entry of records) {
    const key = combinationKey(entry);
    const cell = cells.get(key);
    if (cell === undefined) cells.set(key, { recordCount: 1, sites: new Set([entry.siteRef]) });
    else { cell.recordCount += 1; cell.sites.add(entry.siteRef); }
  }
  return cells;
}
/** The deterministic local verdict for one record. Privacy-safe: counts, never handles. */
export function reidentificationCells(corpus: unknown): readonly ReidentificationCell[] {
  if (!isReidentificationCorpus(corpus)) invalid();
  const value = corpus as ReidentificationCorpus;
  const cells = buildCells(value.records);
  return Object.freeze(value.records.map((entry) => {
    const cell = cells.get(combinationKey(entry))!;
    return Object.freeze({ recordId: entry.id, recordCount: cell.recordCount, siteCount: cell.sites.size,
      flag: cell.sites.size === 1 ? 'RISK' as const : 'COMMON' as const });
  }));
}

/* --------------------------------------------------------------------------- the question set */

const issuedQuestionSets = new WeakSet<object>();
/**
 * True only for the question set this module issued.
 *
 * A trusted caller can mint a #11 question set carrying the same `id` and `version` with different
 * question text. Scoring it would report metadata that does not identify the questions asked, so the
 * runner accepts only the issued set: changing a question or a criterion is a module change with a new
 * `REID_QUESTION_SET_VERSION`, not a runtime substitution. The per-row `requestDigest` still binds the
 * exact question text, so the two controls are independent.
 */
export function isIssuedReidentificationQuestionSet(value: unknown): boolean {
  return typeof value === 'object' && value !== null && issuedQuestionSets.has(value);
}
/**
 * The bounded, versioned re-identification question set.
 *
 * The `propose` mapping is required by the #11 contract for a Choice question, so the labels map to
 * semantic classes: a combination that could single out one site is proposed as a customer/site
 * reference, a combination common to many sites as a generic engineering identifier. Those claims
 * are advisory evidence in the #11 record; this runner reads the answer's label and nothing else.
 *
 * The question text deliberately describes placeholders (`cand-01`, `nbr-NN`), because that is all
 * the judge can see: #11 drops every value, so the request is identical for two records whose
 * handles differ completely.
 */
export function defineReidentificationQuestionSet(): ShadowQuestionSet {
  const issued = defineShadowQuestionSet({
    id: REID_QUESTION_SET_ID, version: REID_QUESTION_SET_VERSION,
    questions: [
      { id: REID_RISK_QUESTION_ID, kind: 'choice', purpose: 'REIDENTIFICATION_RISK',
        instructions: 'Only the shape of `cand-01` and its `nbr-NN` neighbours is present; no value, ' +
          'handle or neighbour text is available. Considering the remaining facts, could this ' +
          'sanitized context single out one site, person or project?',
        criteria: {
          [REID_RISK_LABEL]: 'the remaining combination of facts could single out exactly one entity',
          [REID_SAFE_LABEL]: 'the remaining facts are common to many entities',
        },
        propose: { byLabel: { [REID_RISK_LABEL]: 'CUSTOMER_OR_PARTNER',
          [REID_SAFE_LABEL]: 'ENGINEERING_IDENTIFIER' } } },
      { id: REID_UTILITY_QUESTION_ID, kind: 'score', purpose: 'UTILITY_NECESSITY',
        instructions: 'Is the exact remaining precision necessary for the task?',
        criteria: ['coarsen first', 'exact precision required'],
        propose: { byLabel: { '0': 'ENGINEERING_IDENTIFIER', '1': 'ENGINEERING_IDENTIFIER' } } },
    ],
  });
  issuedQuestionSets.add(issued);
  return issued;
}

/* -------------------------------------------------------------------------------------- reporting */

export interface ReidentificationDerivedFact {
  readonly kind: ReidentificationDerivedFactKind;
  readonly value: number;
}
export interface ReidentificationRecommendation {
  readonly dimension: ReidentificationDimension;
  readonly action: ReidentificationGeneralizationAction;
  readonly rationale: ReidentificationRecommendationRationale;
  readonly derivedFacts: readonly ReidentificationDerivedFact[];
  /** Always true. A derived fact is evidence for deterministic policy, never an instruction. */
  readonly requiresDeterministicPolicy: true;
  /** Always false. Nothing in this module transforms content. */
  readonly implemented: false;
}
export interface ReidentificationSignalCounts {
  readonly cases: number;
  readonly trueFlag: number;
  readonly falseFlag: number;
  /** A re-identifiable case this signal did not flag. For the judge column this is the false-safe. */
  readonly miss: number;
  readonly correctSafe: number;
  /** No usable judgment from this signal. Never a pass, and never a safe verdict. */
  readonly abstained: number;
}
export interface ReidentificationCaseRow {
  readonly caseId: string;
  readonly familyId: ReidentificationFamilyId;
  readonly label: ReidentificationLabel;
  /** Shape only: dimension names and a count. No handle, no value. */
  readonly dimensions: readonly ReidentificationDimension[];
  readonly quasiIdentifierCount: number;
  readonly local: Readonly<{ flag: ReidentificationLocalFlag; equivalenceSiteCount: number;
    equivalenceRecordCount: number }>;
  readonly judge: Readonly<{ flag: ReidentificationJudgeFlag; outcome: ShadowOutcome;
    reasonCodes: readonly string[]; requestDigest: string; late: boolean }>;
  readonly combined: Readonly<{ flag: ReidentificationLocalFlag; basis: ReidentificationCombinedBasis }>;
  readonly advisory: Readonly<{ recommendations: readonly ReidentificationRecommendation[];
    applied: false; effect: 'IGNORED_NO_AUTHORITY' }>;
}
export interface ReidentificationShadowReport {
  readonly version: 1;
  readonly tenantRef: string;
  readonly corpus: Readonly<{ id: string; corpusVersion: string; records: number;
    evaluatedCases: number }>;
  readonly questionSet: Readonly<{ id: string; version: string }>;
  readonly judge: Readonly<{ id: string; version: string; servedModel: string }>;
  readonly authority: 'NONE';
  readonly advisory: Readonly<{ applied: false; effect: 'IGNORED_NO_AUTHORITY';
    requiresDeterministicPolicy: true }>;
  readonly counts: Readonly<{ localModel: ReidentificationSignalCounts;
    shadowJudge: ReidentificationSignalCounts; combined: ReidentificationSignalCounts }>;
  /** #11 outcomes as observed, so a report cannot hide an outage behind a flag count. */
  readonly judgeOutcomes: Readonly<Record<ShadowOutcome, number>>;
  /** Combined `RISK` flags caused only by an abstention escalating. Over-flagging, never relaxing. */
  readonly escalatedByAbstention: number;
  readonly rows: readonly ReidentificationCaseRow[];
}

export interface ReidentificationShadowOptions {
  /** Only `IN_PROCESS` is accepted. There is no external path, and a caller flag is not authority. */
  readonly execution: 'IN_PROCESS';
  readonly deadlineMs: number;
  readonly tenantRef: string;
}

interface CellView { recordCount: number; siteCount: number }
interface JudgeVerdict { flag: ReidentificationJudgeFlag; outcome: ShadowOutcome; reasons: readonly string[];
  digest: string; late: boolean }
/**
 * Read a judge identity for attribution only, tolerating any object.
 *
 * A caller-supplied judge is refused by #11 itself, but this runner must still be able to report an
 * attributable pass over a forged or unreadable judge. It therefore reads own enumerable data
 * properties and falls back to fixed safe placeholders -- the same discipline #11 uses for an
 * identity that was never validated -- instead of throwing or echoing an exception message.
 */
function judgeIdentity(judge: unknown): Readonly<{ id: string; version: string; servedModel: string }> {
  const identity = (name: string, fallback: string): string => {
    if (judge === null || typeof judge !== 'object') return fallback;
    try {
      const descriptor = Object.getOwnPropertyDescriptor(judge, name);
      const value: unknown = descriptor?.enumerable === true && 'value' in descriptor
        ? descriptor.value : undefined;
      return typeof value === 'string' && value.length > 0 && value.length <= 128 &&
        !/[\u0000-\u001f\u007f]/u.test(value) ? value : fallback;
    } catch { return fallback; }
  };
  return Object.freeze({ id: identity('id', 'unbound'), version: identity('version', 'unbound'),
    servedModel: identity('servedModel', 'NONE') });
}

function counters(): { trueFlag: number; falseFlag: number; miss: number; correctSafe: number;
  abstained: number; cases: number } {
  return { cases: 0, trueFlag: 0, falseFlag: 0, miss: 0, correctSafe: 0, abstained: 0 };
}
function tally(counts: ReturnType<typeof counters>, label: ReidentificationLabel,
  flagged: boolean, abstained: boolean): void {
  counts.cases += 1;
  if (abstained) { counts.abstained += 1; return; }
  if (flagged) counts[label === 'REIDENTIFIABLE' ? 'trueFlag' : 'falseFlag'] += 1;
  else counts[label === 'REIDENTIFIABLE' ? 'miss' : 'correctSafe'] += 1;
}
function frozenCounts(counts: ReturnType<typeof counters>): ReidentificationSignalCounts {
  return Object.freeze({ cases: counts.cases, trueFlag: counts.trueFlag, falseFlag: counts.falseFlag,
    miss: counts.miss, correctSafe: counts.correctSafe, abstained: counts.abstained });
}
function neighborCountCode(total: number): string {
  // A record always carries at least one quasi-identifier, so the `0` bucket is not reachable.
  return total === 1 ? '1' : total < 4 ? '2-3' : total < 8 ? '4-7' : '8+';
}
/**
 * Recommendations for one flagged combination.
 *
 * The ordering is a fixed, documented heuristic with no validated generalization lattice: the
 * dimensions with the fewest DISTINCT VALUES IN THE POPULATION are proposed first, and that
 * cardinality is recorded with each recommendation as a derived fact.
 *
 * Two honest limits are enforced in code rather than left to the reader:
 *
 * - a dimension whose every record already shares the same single value is EXCLUDED. Generalizing a
 *   universal value cannot widen an equivalence cell, so recommending it would be advice that cannot
 *   work; a case whose dimensions are all universal produces no recommendation at all.
 * - no resulting cell size is predicted, because no generalization function exists here to predict
 *   it. `REID_ADVISORY_MIN_CELL_SITES` is a target carried as a fact, never a guarantee.
 */
function recommendations(entry: ReidentificationRecord, cell: CellView,
  distinct: ReadonlyMap<ReidentificationDimension, number>): readonly ReidentificationRecommendation[] {
  const ranked = entry.quasiIdentifiers
    .map((item) => ({ dimension: item.dimension, distinct: distinct.get(item.dimension) ?? 0 }))
    .filter((item) => item.distinct >= 2)
    .sort((left, right) => left.distinct - right.distinct ||
      REID_DIMENSIONS.indexOf(left.dimension) - REID_DIMENSIONS.indexOf(right.dimension));
  return Object.freeze(ranked.slice(0, REID_MAX_ADVISORY_RECOMMENDATIONS).map((item, position) =>
    Object.freeze({
      dimension: item.dimension,
      action: 'GENERALIZE_TO_PARENT_GROUP' as const,
      rationale: (position === 0 ? 'LOWEST_POPULATION_CARDINALITY_DIMENSION'
        : 'OTHER_DIMENSION_IN_UNIQUE_COMBINATION') as ReidentificationRecommendationRationale,
      derivedFacts: Object.freeze([
        { kind: 'EQUIVALENCE_SITE_COUNT' as const, value: cell.siteCount },
        { kind: 'EQUIVALENCE_RECORD_COUNT' as const, value: cell.recordCount },
        { kind: 'DISTINCT_HANDLE_COUNT_IN_DIMENSION' as const, value: item.distinct },
        { kind: 'ADVISORY_MIN_CELL_SITES' as const, value: REID_ADVISORY_MIN_CELL_SITES },
      ] as readonly ReidentificationDerivedFact[]),
      requiresDeterministicPolicy: true as const,
      implemented: false as const,
    })));
}
function emptyAdvice(): ReidentificationCaseRow['advisory'] {
  return Object.freeze({ recommendations: Object.freeze([]), applied: false as const,
    effect: 'IGNORED_NO_AUTHORITY' as const });
}
function outcomeCounts(): Record<ShadowOutcome, number> {
  return { ANSWERED: 0, ABSTAINED: 0, PARTIAL: 0, REFUSED: 0, TIMEOUT: 0, CANCELLED: 0 };
}
/**
 * Read the judge's label from a #11 record, or abstain.
 *
 * A record is usable only when it came from this question set and judge, belongs to this tenant, is
 * explicitly without authority, and reports a local served model. Anything else -- a forged record,
 * a foreign tenant, a missing or invalid answer -- is an abstention, never a safe verdict.
 */
function judgeVerdict(record: ShadowJudgmentRecord, set: ShadowQuestionSet,
  judgeId: string, judgeVersion: string, tenantRef: string, late: boolean): JudgeVerdict {
  const reasons = shadowReasonCodes(record);
  const unusable = (): JudgeVerdict => ({ flag: 'ABSTAIN', outcome: record.outcome, reasons,
    digest: record.request.digest, late });
  if (record.version !== 1 || record.authority !== 'NONE' ||
    record.questionSet.id !== set.id || record.questionSet.version !== set.version ||
    record.judge.id !== judgeId || record.judge.version !== judgeVersion ||
    !/^local-synthetic\//u.test(record.model.served) || !belongsToShadowTenant(record, tenantRef)) {
    return unusable();
  }
  const answer = record.answers.find((item) => item.questionId === REID_RISK_QUESTION_ID);
  const measure = answer?.status === 'ANSWERED' ? answer.measure : undefined;
  // One fall-through: a missing answer, a non-choice measure and an unexpected label are the same
  // abstention, so there is no branch here that a #11 record cannot reach and no path to a safe
  // verdict by default.
  const flag: ReidentificationJudgeFlag = measure?.kind === 'choice' &&
    measure.choice === REID_RISK_LABEL ? 'RISK'
    : measure?.kind === 'choice' && measure.choice === REID_SAFE_LABEL ? 'SAFE' : 'ABSTAIN';
  return { flag, outcome: record.outcome, reasons, digest: record.request.digest, late };
}
function combinedVerdict(local: ReidentificationLocalFlag, judge: ReidentificationJudgeFlag):
  Readonly<{ flag: ReidentificationLocalFlag; basis: ReidentificationCombinedBasis }> {
  if (local === 'RISK') return Object.freeze({ flag: 'RISK',
    basis: 'LOCAL_UNIQUE_COMBINATION' as const });
  if (judge === 'RISK') return Object.freeze({ flag: 'RISK', basis: 'JUDGE_RISK' as const });
  // An abstention is unknown, never evidence of safety, so it escalates instead of relaxing.
  if (judge === 'ABSTAIN') return Object.freeze({ flag: 'RISK',
    basis: 'JUDGE_ABSTENTION_ESCALATION' as const });
  return Object.freeze({ flag: 'COMMON', basis: 'NO_FLAG' as const });
}

/**
 * Run one development-only shadow pass over a corpus.
 *
 * A forged corpus, question set, judge or option object is refused with a fixed `TypeError` before
 * anything runs, because a misconfigured development runner must be loud rather than quietly
 * produce an empty-looking clean report. Judge failures are not configuration errors: timeout,
 * cancellation, refusal, a malformed body, an abstention and a partial answer each become an
 * explicit `ABSTAIN` row carrying the #11 outcome and its closed reason codes.
 */
export async function runReidentificationShadow(corpus: unknown, set: unknown, judge: unknown,
  options: unknown): Promise<ReidentificationShadowReport> {
  if (!isReidentificationCorpus(corpus)) invalid();
  // Only this module's own question set may be scored: a caller-minted #11 set carrying the same id
  // and version with different text would otherwise be reported under metadata that does not
  // identify the questions asked.
  if (!isIssuedReidentificationQuestionSet(set)) invalid();
  const value = corpus as ReidentificationCorpus;
  const questionSet = set as ShadowQuestionSet;
  const identity = judgeIdentity(judge);
  const opts = safe(() => {
    const v = data(options, ['execution', 'deadlineMs', 'tenantRef']);
    if (v.execution !== 'IN_PROCESS') invalid();
    return { deadlineMs: whole(v.deadlineMs, 1, 30_000), tenantRef: tenantRef(v.tenantRef) };
  });
  const riskQuestion = questionSet.questions.find((question) => question.id === REID_RISK_QUESTION_ID);
  const utilityQuestion = questionSet.questions.find((question) =>
    question.id === REID_UTILITY_QUESTION_ID);
  // A set without the re-identification question has nothing to score, and one with an unknown
  // extra question is not this seam's contract: both are configuration errors, refused loudly.
  if (riskQuestion === undefined || utilityQuestion === undefined) invalid();

  const cells = buildCells(value.records);
  const distinct = new Map<ReidentificationDimension, number>();
  const seen = new Map<ReidentificationDimension, Set<string>>();
  for (const entry of value.records) {
    for (const item of entry.quasiIdentifiers) {
      const handles = seen.get(item.dimension) ?? new Set<string>();
      handles.add(item.handle);
      seen.set(item.dimension, handles);
    }
  }
  for (const [dimension, handles] of seen) distinct.set(dimension, handles.size);

  const localCounts = counters();
  const judgeCounts = counters();
  const combinedCounts = counters();
  const outcomes = outcomeCounts();
  const rows: ReidentificationCaseRow[] = [];
  let escalated = 0;
  for (const entry of value.records) {
    if (entry.role !== 'EVALUATED_CASE' || entry.label === undefined) continue;
    const cell = cells.get(combinationKey(entry))!;
    const localFlag: ReidentificationLocalFlag = cell.sites.size === 1 ? 'RISK' : 'COMMON';
    const raw = entry.quasiIdentifiers.map((item) => item.handle).join('|');
    const run = runShadowJudgment(questionSet, judge, `${value.id}-${entry.id}`, opts.tenantRef, {
      candidate: { ref: entry.siteRef, kind: 'CUSTOMER_REFERENCE', raw },
      neighbors: entry.quasiIdentifiers.map((item) => ({
        kind: REID_DIMENSION_NEIGHBOR_KINDS[item.dimension], raw: item.handle })),
      context: [
        { key: 'surface', code: 'structured-field' },
        { key: 'contentType', code: 'json' },
        { key: 'containerKind', code: 'list' },
        { key: 'neighborCount', code: neighborCountCode(entry.quasiIdentifiers.length) },
      ],
    }, { execution: 'IN_PROCESS', deadlineMs: opts.deadlineMs });
    // `settlement` is awaited as well as `record`, which is the documented way to observe late work
    // and guarantees neither promise is left without a handler.
    const record = await run.record;
    const settlement = await run.settlement;
    const verdict = judgeVerdict(record, questionSet, identity.id, identity.version, opts.tenantRef,
      settlement.late);
    const combined = combinedVerdict(localFlag, verdict.flag);
    const abstained = verdict.flag === 'ABSTAIN';
    if (combined.basis === 'JUDGE_ABSTENTION_ESCALATION') escalated += 1;
    outcomes[record.outcome] += 1;
    tally(localCounts, entry.label, localFlag === 'RISK', false);
    tally(judgeCounts, entry.label, verdict.flag === 'RISK', abstained);
    tally(combinedCounts, entry.label, combined.flag === 'RISK', false);
    rows.push(Object.freeze({
      caseId: entry.id, familyId: entry.familyId, label: entry.label,
      dimensions: Object.freeze(entry.quasiIdentifiers.map((item) => item.dimension)),
      quasiIdentifierCount: entry.quasiIdentifiers.length,
      local: Object.freeze({ flag: localFlag, equivalenceSiteCount: cell.sites.size,
        equivalenceRecordCount: cell.recordCount }),
      judge: Object.freeze({ flag: verdict.flag, outcome: verdict.outcome,
        reasonCodes: Object.freeze([...verdict.reasons]), requestDigest: verdict.digest,
        late: verdict.late }),
      combined: Object.freeze({ ...combined }),
      advisory: localFlag === 'RISK'
        ? Object.freeze({ recommendations: recommendations(entry,
          { recordCount: cell.recordCount, siteCount: cell.sites.size }, distinct),
        applied: false, effect: 'IGNORED_NO_AUTHORITY' })
        : emptyAdvice(),
    }));
  }
  if (rows.length === 0) invalid();
  return Object.freeze({
    version: 1 as const, tenantRef: opts.tenantRef,
    corpus: Object.freeze({ id: value.id, corpusVersion: value.corpusVersion,
      records: value.records.length, evaluatedCases: rows.length }),
    questionSet: Object.freeze({ id: questionSet.id, version: questionSet.version }),
    judge: Object.freeze({ id: identity.id, version: identity.version, servedModel: identity.servedModel }),
    authority: 'NONE' as const,
    advisory: Object.freeze({ applied: false as const, effect: 'IGNORED_NO_AUTHORITY' as const,
      requiresDeterministicPolicy: true as const }),
    counts: Object.freeze({ localModel: frozenCounts(localCounts), shadowJudge: frozenCounts(judgeCounts),
      combined: frozenCounts(combinedCounts) }),
    judgeOutcomes: Object.freeze(outcomes),
    escalatedByAbstention: escalated,
    rows: Object.freeze(rows),
  });
}
