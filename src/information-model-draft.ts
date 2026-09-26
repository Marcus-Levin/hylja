/**
 * PROPOSED draft for decision 010 (#66/#68). NOT wired into classification v1, policy or any adapter.
 * Every result here is advisory evidence for review and evaluation; none selects a treatment,
 * authorizes release or restoration, or replaces the deterministic Policy Engine.
 */
import { SENSITIVITIES } from './classification.js';
import type { Sensitivity } from './classification.js';

export const INFORMATION_MODEL_DRAFT_VERSION = 'draft-1' as const;
const MAX_ITEMS = 256;

function plain(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> | null {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length > required.length + optional.length) return null;
    const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (typeof key !== 'string' || !required.includes(key) && !optional.includes(key)) return null;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return null;
      result[key] = descriptor.value;
    }
    for (const key of required) if (!Object.hasOwn(result, key)) return null;
    return result;
  } catch { return null; }
}
/** Snapshot a dense plain array through descriptors; a Proxy or accessor makes it invalid. */
function items(value: unknown, max = MAX_ITEMS): unknown[] | null {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
    const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
    if (typeof length !== 'number' || !Number.isSafeInteger(length) || length > max) return null;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== length + 1) return null;
    const result: unknown[] = [];
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return null;
      result.push(descriptor.value);
    }
    return result;
  } catch { return null; }
}
function inSet<T extends string>(value: unknown, set: readonly T[]): value is T {
  return typeof value === 'string' && set.includes(value as T);
}
function ref(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value);
}
function name(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/u.test(value);
}
const rank = (value: Sensitivity): number => SENSITIVITIES.indexOf(value);
const highest = (values: Iterable<Sensitivity>): Sensitivity | undefined => {
  let result: Sensitivity | undefined;
  for (const value of values) if (result === undefined || rank(value) > rank(result)) result = value;
  return result;
};

/* ---------- Sensitivity: deterministic floor, semantic may only raise concern ---------- */

/** DETERMINISTIC covers detector, parser and trusted configured sources; SEMANTIC is any model judgment. */
export const EVIDENCE_ORIGINS = ['DETERMINISTIC', 'SEMANTIC'] as const;
export type EvidenceOrigin = (typeof EVIDENCE_ORIGINS)[number];
export const CLAIM_STATUSES = ['FOUND', 'ABSTAIN', 'FAILURE'] as const;
export type ClaimStatus = (typeof CLAIM_STATUSES)[number];
export interface SensitivityClaimDraft {
  origin: EvidenceOrigin;
  status: ClaimStatus;
  sensitivity?: Sensitivity;
  /** Deterministic credential evidence fixes a SECRET floor (decision 009). */
  credential?: boolean;
}
export const RESOLUTION_STATES = ['RESOLVED', 'RESOLVED_CONSERVATIVELY', 'UNRESOLVED'] as const;
export type ResolutionState = (typeof RESOLUTION_STATES)[number];
export interface SensitivityResolutionDraft {
  state: ResolutionState;
  /** Highest agreed deterministic sensitivity; UNKNOWN when no deterministic floor exists. */
  floor: Sensitivity | 'UNKNOWN';
  /** Never below `floor`; retains the highest concern seen even when unresolved. */
  effective: Sensitivity | 'UNKNOWN';
  /** Ordered steps a semantic judgment raised above the floor; a metering signal, not a decision. */
  escalationSteps: number;
  reasons: readonly string[];
}
const BLOCKING_SENSITIVITY_REASONS = new Set([
  'INVALID_EVIDENCE', 'MISSING_DETERMINISTIC_EVIDENCE', 'DETERMINISTIC_CONFLICT', 'DETERMINISTIC_FAILURE',
  // A semantic abstention equals an absent judge: it claims no escalation and leaves the floor intact.
  // A semantic FAILURE is not: the judge may have escalated, so it stays fail-closed (v1 parity).
  'SEMANTIC_FAILURE', 'MISSING_SENSITIVITY',
]);

/**
 * Proposed composition: disagreement below or above a single agreed deterministic floor resolves
 * CONSERVATIVELY (floor kept, escalation applied, disagreement retained); anything that leaves the
 * floor itself uncertain stays UNRESOLVED. Adding a claim can never lower `effective`.
 */
export function resolveSensitivityDraft(claims: unknown): SensitivityResolutionDraft {
  const reasons = new Set<string>();
  const deterministic = new Set<Sensitivity>();
  const semantic = new Set<Sensitivity>();
  let credential = false;
  const list = items(claims);
  if (!list) reasons.add('INVALID_EVIDENCE');
  for (const raw of list ?? []) {
    const claim = plain(raw, ['origin', 'status'], ['sensitivity', 'credential']);
    if (!claim || !inSet(claim.origin, EVIDENCE_ORIGINS) || !inSet(claim.status, CLAIM_STATUSES) ||
      (Object.hasOwn(claim, 'sensitivity') && (claim.status !== 'FOUND' || !inSet(claim.sensitivity, SENSITIVITIES))) ||
      (Object.hasOwn(claim, 'credential') && (claim.status !== 'FOUND' || typeof claim.credential !== 'boolean'))) {
      reasons.add('INVALID_EVIDENCE');
      continue;
    }
    const origin = claim.origin;
    if (claim.status !== 'FOUND') {
      reasons.add(`${origin}_${claim.status === 'FAILURE' ? 'FAILURE' : 'ABSTAINED'}`);
      continue;
    }
    // A semantic credential opinion is only concern; it cannot establish the deterministic floor.
    if (claim.credential === true && origin === 'DETERMINISTIC') credential = true;
    const target = origin === 'DETERMINISTIC' ? deterministic : semantic;
    if (claim.credential === true) target.add('SECRET');
    if (claim.sensitivity !== undefined) target.add(claim.sensitivity as Sensitivity);
    else if (claim.credential !== true) reasons.add('MISSING_SENSITIVITY');
  }
  if (credential) deterministic.add('SECRET');
  if (deterministic.size > 1 && !credential) reasons.add('DETERMINISTIC_CONFLICT');
  if (!deterministic.size) reasons.add('MISSING_DETERMINISTIC_EVIDENCE');
  const floor = credential ? 'SECRET' : highest(deterministic);
  const concern = highest([...deterministic, ...semantic]);
  if (floor !== undefined) {
    for (const value of semantic) {
      if (rank(value) > rank(floor)) reasons.add('SEMANTIC_ESCALATION');
      if (rank(value) < rank(floor)) reasons.add('SEMANTIC_BELOW_FLOOR_IGNORED');
    }
  }
  if (credential && [...deterministic].some((value) => value !== 'SECRET')) reasons.add('CREDENTIAL_FLOOR_APPLIED');
  const blocked = [...reasons].some((reason) => BLOCKING_SENSITIVITY_REASONS.has(reason));
  const state: ResolutionState = blocked ? 'UNRESOLVED' :
    reasons.has('SEMANTIC_ESCALATION') || reasons.has('SEMANTIC_BELOW_FLOOR_IGNORED') ||
      reasons.has('CREDENTIAL_FLOOR_APPLIED') ? 'RESOLVED_CONSERVATIVELY' : 'RESOLVED';
  const effective = concern ?? 'UNKNOWN';
  return Object.freeze({
    state, floor: floor ?? 'UNKNOWN', effective,
    escalationSteps: floor !== undefined && concern !== undefined ? rank(concern) - rank(floor) : 0,
    reasons: Object.freeze([...reasons].sort()),
  });
}

/* ---------- Privacy/regulatory attributes: raise-only, UNKNOWN is never "no" ---------- */

export const ATTRIBUTE_STATES = ['YES', 'NO', 'UNKNOWN'] as const;
export type AttributeState = (typeof ATTRIBUTE_STATES)[number];
export interface AttributeClaimDraft { origin: EvidenceOrigin; status: ClaimStatus; value?: 'YES' | 'NO' }
export interface AttributeResolutionDraft { value: AttributeState; reasons: readonly string[] }

/**
 * Used for contextual attributes such as `personalData` and `specialCategory`. YES dominates; NO needs
 * deterministic or trusted-context evidence with no failure or contrary claim. A model's NO alone is
 * UNKNOWN, and the result is never a legal determination.
 */
export function resolveAttributeDraft(claims: unknown): AttributeResolutionDraft {
  const reasons = new Set<string>();
  const seen = { DETERMINISTIC: new Set<string>(), SEMANTIC: new Set<string>() };
  const list = items(claims);
  if (!list) reasons.add('INVALID_EVIDENCE');
  for (const raw of list ?? []) {
    const claim = plain(raw, ['origin', 'status'], ['value']);
    if (!claim || !inSet(claim.origin, EVIDENCE_ORIGINS) || !inSet(claim.status, CLAIM_STATUSES) ||
      (claim.status === 'FOUND') !== inSet(claim.value, ['YES', 'NO'] as const)) {
      reasons.add('INVALID_EVIDENCE');
      continue;
    }
    if (claim.status === 'FOUND') seen[claim.origin].add(claim.value as string);
    else reasons.add(`${claim.origin}_${claim.status === 'FAILURE' ? 'FAILURE' : 'ABSTAINED'}`);
  }
  const yes = seen.DETERMINISTIC.has('YES') || seen.SEMANTIC.has('YES');
  const no = seen.DETERMINISTIC.has('NO') || seen.SEMANTIC.has('NO');
  if (yes && no) reasons.add('ATTRIBUTE_CONFLICT');
  if (yes && !seen.DETERMINISTIC.has('YES')) reasons.add('SEMANTIC_ONLY_ASSERTION');
  if (!yes && seen.SEMANTIC.has('NO') && !seen.DETERMINISTIC.has('NO')) reasons.add('SEMANTIC_NEGATIVE_IGNORED');
  const deterministicNo = seen.DETERMINISTIC.has('NO') && !yes && !reasons.has('INVALID_EVIDENCE') &&
    !reasons.has('DETERMINISTIC_FAILURE') && !reasons.has('SEMANTIC_FAILURE');
  if (!yes && !deterministicNo) reasons.add('ATTRIBUTE_UNKNOWN');
  return Object.freeze({
    value: yes ? 'YES' : deterministicNo ? 'NO' : 'UNKNOWN',
    reasons: Object.freeze([...reasons].sort()),
  });
}

/* ---------- Task fidelity (#68): what the task needs, not what policy allows ---------- */

export const FIDELITY_PREDICATES = [
  'EXACT_VALUE', 'EXISTENCE', 'KIND', 'FORMAT', 'SYNTAX', 'RELATIONSHIP', 'CONSISTENCY', 'GENERALIZED',
  'NOT_REQUIRED',
] as const;
export type FidelityPredicate = (typeof FIDELITY_PREDICATES)[number];
/** Released-form vocabulary. WITHHELD is non-release (BLOCK/REQUIRE_REVIEW), never a transformer output. */
export const REPRESENTATIONS = [
  'EXACT', 'IDENTITY_SYNTHETIC', 'OPAQUE_TOKEN', 'SEMANTIC_PLACEHOLDER', 'GENERALIZED', 'REMOVED', 'WITHHELD',
] as const;
export type Representation = (typeof REPRESENTATIONS)[number];
/** Nearest existing policy vocabulary, for documentation and review only. */
export const REPRESENTATION_TREATMENT_HINT: Readonly<Record<Representation, string>> = Object.freeze({
  EXACT: 'KEEP', IDENTITY_SYNTHETIC: 'SYNTHETIC', OPAQUE_TOKEN: 'TOKENIZE', SEMANTIC_PLACEHOLDER: 'MASK',
  GENERALIZED: 'GENERALIZE', REMOVED: 'REMOVE', WITHHELD: 'BLOCK|REQUIRE_REVIEW',
});
const RELEASED: readonly Representation[] = REPRESENTATIONS.filter((value) => value !== 'WITHHELD');
const SATISFIES: Readonly<Record<FidelityPredicate, readonly Representation[]>> = Object.freeze({
  EXACT_VALUE: ['EXACT'],
  // REMOVED erases existence: the #68 failure where a dropped apiKey reads as "no credential supplied".
  EXISTENCE: ['EXACT', 'IDENTITY_SYNTHETIC', 'OPAQUE_TOKEN', 'SEMANTIC_PLACEHOLDER', 'GENERALIZED'],
  KIND: ['EXACT', 'IDENTITY_SYNTHETIC', 'OPAQUE_TOKEN', 'SEMANTIC_PLACEHOLDER', 'GENERALIZED'],
  FORMAT: ['EXACT', 'IDENTITY_SYNTHETIC'],
  // Container syntax is a transformer obligation for any released form; see the transformation contract.
  SYNTAX: RELEASED,
  RELATIONSHIP: ['EXACT', 'IDENTITY_SYNTHETIC', 'OPAQUE_TOKEN'],
  CONSISTENCY: ['EXACT', 'IDENTITY_SYNTHETIC', 'OPAQUE_TOKEN'],
  GENERALIZED: ['EXACT', 'GENERALIZED'],
  NOT_REQUIRED: REPRESENTATIONS,
});
/** Decision 009: secrets never get exact release, synthetic identities or reversible tokens. */
export const SECRET_REPRESENTATIONS: readonly Representation[] = Object.freeze(['SEMANTIC_PLACEHOLDER', 'REMOVED', 'WITHHELD']);

export interface FidelityAssessmentDraft {
  /** Forms that would satisfy every predicate within the secret ceiling. Advisory, not permitted. */
  satisfying: readonly Representation[];
  /** Predicates no form within the ceiling can satisfy. */
  unmet: readonly FidelityPredicate[];
  /** e.g. USE_WITHOUT_REVEAL: a trusted local effect may use the value; the model receives only the result. */
  advice: readonly ('USE_WITHOUT_REVEAL' | 'TASK_UNSOLVABLE_WITHOUT_RELEASE')[];
}

/**
 * Pure fidelity cost information for policy and evaluation. Fidelity can raise the cost of a
 * restrictive treatment; it never widens what policy permits and it never yields a treatment.
 */
export function assessFidelityDraft(predicates: unknown, secret: boolean): FidelityAssessmentDraft {
  const list = items(predicates, FIDELITY_PREDICATES.length);
  if (typeof secret !== 'boolean' || !list || !list.length || list.some((value) => !inSet(value, FIDELITY_PREDICATES)) ||
    new Set(list).size !== list.length) throw new TypeError('Invalid fidelity request');
  const wanted = list as FidelityPredicate[];
  const ceiling = secret ? SECRET_REPRESENTATIONS : REPRESENTATIONS;
  const satisfying = ceiling.filter((form) => wanted.every((predicate) => SATISFIES[predicate].includes(form)));
  const unmet = wanted.filter((predicate) => !ceiling.some((form) => SATISFIES[predicate].includes(form)));
  const advice: FidelityAssessmentDraft['advice'][number][] = [];
  if (secret && wanted.includes('EXACT_VALUE')) advice.push('USE_WITHOUT_REVEAL');
  if (!satisfying.some((form) => form !== 'WITHHELD')) advice.push('TASK_UNSOLVABLE_WITHOUT_RELEASE');
  return Object.freeze({
    satisfying: Object.freeze(satisfying), unmet: Object.freeze(unmet.sort()), advice: Object.freeze(advice),
  });
}

/* ---------- Semantic placeholders: typed, unambiguously synthetic, not reversible ---------- */

const PLACEHOLDER = /^\[hylja:protected:([A-Z][A-Z0-9_]{0,63})\]$/u;
/** Exposes only kind and presence. Derived facts such as emptiness or format validity need policy approval. */
export function semanticPlaceholder(kind: string): string {
  if (!name(kind)) throw new TypeError('Invalid placeholder kind');
  return `[hylja:protected:${kind}]`;
}
export function parseSemanticPlaceholder(text: unknown): { kind: string } | null {
  if (typeof text !== 'string' || text.length > 96) return null;
  const match = PLACEHOLDER.exec(text);
  return match ? Object.freeze({ kind: match[1]! }) : null;
}

/* ---------- Task fidelity contract and #39 oracle annotation schema ---------- */

export interface FidelityRequirementDraft { targetRef: string; predicates: readonly FidelityPredicate[] }
/** Owned by an independent task reviewer; targets are occurrence or entity refs, never raw values. */
export interface TaskFidelityContractDraft {
  version: typeof INFORMATION_MODEL_DRAFT_VERSION;
  taskRef: string;
  requirements: readonly FidelityRequirementDraft[];
}
function predicateList(value: unknown): FidelityPredicate[] | null {
  const list = items(value, FIDELITY_PREDICATES.length);
  if (!list || !list.length || new Set(list).size !== list.length ||
    list.some((predicate) => !inSet(predicate, FIDELITY_PREDICATES))) return null;
  if (list.includes('NOT_REQUIRED') && list.length > 1) return null;
  return list as FidelityPredicate[];
}
export function validateTaskFidelityContractDraft(raw: unknown): TaskFidelityContractDraft | null {
  const contract = plain(raw, ['version', 'taskRef', 'requirements']);
  if (!contract || contract.version !== INFORMATION_MODEL_DRAFT_VERSION || !ref(contract.taskRef)) return null;
  const list = items(contract.requirements);
  if (!list || !list.length) return null;
  const targets = new Set<string>();
  const requirements: FidelityRequirementDraft[] = [];
  for (const entry of list) {
    const requirement = plain(entry, ['targetRef', 'predicates']);
    const predicates = requirement && predicateList(requirement.predicates);
    if (!requirement || !predicates || !ref(requirement.targetRef) || targets.has(requirement.targetRef)) return null;
    targets.add(requirement.targetRef);
    requirements.push(Object.freeze({ targetRef: requirement.targetRef, predicates: Object.freeze(predicates) }));
  }
  return Object.freeze({ version: INFORMATION_MODEL_DRAFT_VERSION, taskRef: contract.taskRef,
    requirements: Object.freeze(requirements) });
}

/**
 * One planted-oracle occurrence. Trust is deliberately absent: it is bound from the interaction
 * context, never annotated per value. Treatment is absent: a separate policy reviewer owns it.
 */
export interface OracleAnnotationDraft {
  version: typeof INFORMATION_MODEL_DRAFT_VERSION;
  occurrenceRef: string;
  entityRef?: string;
  semantic: { semanticType: string; domain?: string; subtype?: string };
  privacy: { personalData: AttributeState; specialCategory: AttributeState; jurisdictions: readonly string[] };
  sensitivity: Sensitivity;
}
export function validateOracleAnnotationDraft(raw: unknown): OracleAnnotationDraft | null {
  const record = plain(raw, ['version', 'occurrenceRef', 'semantic', 'privacy', 'sensitivity'], ['entityRef']);
  if (!record || record.version !== INFORMATION_MODEL_DRAFT_VERSION || !ref(record.occurrenceRef) ||
    (Object.hasOwn(record, 'entityRef') && !ref(record.entityRef)) || !inSet(record.sensitivity, SENSITIVITIES)) return null;
  const semantic = plain(record.semantic, ['semanticType'], ['domain', 'subtype']);
  if (!semantic || !name(semantic.semanticType) || (Object.hasOwn(semantic, 'domain') && !name(semantic.domain)) ||
    (Object.hasOwn(semantic, 'subtype') && !name(semantic.subtype))) return null;
  const privacy = plain(record.privacy, ['personalData', 'specialCategory', 'jurisdictions']);
  const jurisdictions = privacy && items(privacy.jurisdictions, 16);
  if (!privacy || !inSet(privacy.personalData, ATTRIBUTE_STATES) || !inSet(privacy.specialCategory, ATTRIBUTE_STATES) ||
    !jurisdictions || new Set(jurisdictions).size !== jurisdictions.length ||
    jurisdictions.some((code) => typeof code !== 'string' || !/^[A-Z]{2}$/u.test(code))) return null;
  // Special-category data is personal data; a contradiction is an annotation error, not a label.
  if (privacy.specialCategory === 'YES' && privacy.personalData !== 'YES') return null;
  return Object.freeze({
    version: INFORMATION_MODEL_DRAFT_VERSION, occurrenceRef: record.occurrenceRef,
    ...(Object.hasOwn(record, 'entityRef') ? { entityRef: record.entityRef as string } : {}),
    semantic: Object.freeze({ semanticType: semantic.semanticType,
      ...(Object.hasOwn(semantic, 'domain') ? { domain: semantic.domain as string } : {}),
      ...(Object.hasOwn(semantic, 'subtype') ? { subtype: semantic.subtype as string } : {}) }),
    privacy: Object.freeze({ personalData: privacy.personalData, specialCategory: privacy.specialCategory,
      jurisdictions: Object.freeze([...(jurisdictions as string[])].sort()) }),
    sensitivity: record.sensitivity,
  });
}
