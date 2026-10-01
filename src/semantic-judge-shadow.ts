/**
 * #11 bounded semantic-judge SHADOW seam, local/synthetic-only.
 *
 * A semantic judge may classify, score, recommend or abstain. It never selects a treatment, never
 * grants release, and never lowers deterministic credential evidence (decisions 003, 007, 009).
 * Everything produced here is evidence for later deterministic policy.
 *
 * There is NO external execution path in this version. Three separate controls would be required
 * first -- core destination policy for the judge sink itself, an authenticated binding to the real
 * routed judge destination, and an independent #19 check of the exact serialized outbound bytes --
 * and none of them exists yet, so `EXTERNAL` execution is refused unconditionally. A caller flag
 * claiming synthetic, safe, local or trusted content is never an authorization primitive: the option
 * shape rejects unknown keys, and the only executable judge is a module-issued, data-only
 * in-process double. That double is not a network client, not authentication, and not interception.
 *
 * Request minimization happens here, locally: the caller supplies raw candidate and neighbouring
 * text and the core replaces every one of them with request-local ordinal placeholders before a
 * request exists. Raw values therefore cannot reach the request object, its serialized bytes, the
 * record, or the diagnostics. The candidate vocabulary has no credential kind, so a known
 * credential is not representable as judge input at all. A minimized request is branded, so the
 * narrow protocol adapter can only ever translate a request this module issued.
 *
 * Every outcome is an explicit conservative record. A missing, malformed, abstained, refused,
 * timed-out or cancelled judgment is recorded as such, never as "no problem", and a failure can
 * only add reasons: it never returns a treatment, grants release, or lowers a deterministic floor.
 * `runShadowJudgment` never throws and neither of the two promises it returns ever rejects, because
 * a caller that observes only `settlement` -- the documented way to watch late work -- would
 * otherwise leave a rejection unhandled and lose the process to Node's default behavior. It reads
 * the caller's input exactly once, through the same validating snapshot that builds the request.
 *
 * The judge answers a provider-independent canonical shape. A documented provider wire shape is
 * translated by a separate narrow adapter; see docs/contracts/semantic-judge-shadow.md.
 */
import { createHash } from 'node:crypto';
import { SEMANTIC_CLASSES, SENSITIVITIES } from './classification.js';
import type { SemanticClass, Sensitivity } from './classification.js';

export const SHADOW_JUDGE_VERSION = 'hylja.semantic-judge-shadow.v1' as const;

/* -------------------------------------------------------------------------------------- bounds */

export const SHADOW_MAX_REQUEST_BYTES = 32 * 1024;
export const SHADOW_MAX_RESPONSE_BYTES = 32 * 1024;
export const SHADOW_MAX_QUESTIONS = 32;
export const SHADOW_MAX_NEIGHBORS = 8;
export const SHADOW_MAX_CONTEXT_ENTRIES = 8;
export const SHADOW_MIN_DEADLINE_MS = 1;
export const SHADOW_MAX_DEADLINE_MS = 30_000;
export const SHADOW_MAX_SCRIPT_LATENCY_MS = 60_000;
/**
 * A local script may answer at most the whole question set. The parser allows a surplus of
 * `expected.size + SHADOW_MAX_QUESTIONS` keys and the script adds one documented padding key, so a
 * module-issued judge can never outrun the parser and turn an ordinary run into a refusal.
 */
export const SHADOW_MAX_SCRIPT_ANSWER_KEYS = SHADOW_MAX_QUESTIONS;
/**
 * Copy ceilings for anything a caller hands this module. A script and a provider body are DATA:
 * they are copied into inert JSON values (own enumerable data descriptors only, no getter,
 * `toJSON`, custom prototype, function, symbol, cycle, hole or non-finite number) before they are
 * validated, measured, parsed or recorded.
 */
export const SHADOW_MAX_JSON_DEPTH = 12;
export const SHADOW_MAX_JSON_KEYS = 4096;
/**
 * Deliberately above `SHADOW_MAX_RESPONSE_BYTES`: an oversized response must still be refused by
 * the documented size check, not by the copy that protects the check. The request and response
 * serializers stop at four and eight times their own limits for the same reason.
 */
export const SHADOW_MAX_RESPONSE_COPY_BYTES = SHADOW_MAX_RESPONSE_BYTES * 2;
export const SHADOW_MAX_JSON_STRING = SHADOW_MAX_RESPONSE_COPY_BYTES;
/** Documented System One limits: at most 255 Choice options, and 2 to 10 Score levels. */
export const SHADOW_MAX_CHOICE_OPTIONS = 255;
export const SHADOW_MIN_SCORE_LEVELS = 2;
export const SHADOW_MAX_SCORE_LEVELS = 10;

/* ------------------------------------------------------------------------------- vocabularies */

/** The documented question kinds. Hylja never invents a fourth. */
export const SHADOW_QUESTION_KINDS = ['noul', 'choice', 'score'] as const;
export type ShadowQuestionKind = (typeof SHADOW_QUESTION_KINDS)[number];

/** Bounded judgments this seam may ask; see architecture.md "Semantic judgment boundary". */
export const SHADOW_JUDGMENT_PURPOSES = [
  'PERSON_IDENTITY',
  'CONTACT_IDENTITY',
  'INFRASTRUCTURE_IDENTITY',
  'CUSTOMER_IDENTITY',
  'UTILITY_NECESSITY',
  'REIDENTIFICATION_RISK',
  'CONTEXT_KIND',
] as const;
export type ShadowJudgmentPurpose = (typeof SHADOW_JUDGMENT_PURPOSES)[number];

/**
 * Candidate kinds are bounded and deliberately contain no credential/secret kind: a known
 * credential is not representable as judge input, so no #8 finding can enter a judge request.
 */
export const SHADOW_CANDIDATE_KINDS = [
  'PERSON_REFERENCE',
  'CONTACT_REFERENCE',
  'INFRASTRUCTURE_REFERENCE',
  'CUSTOMER_REFERENCE',
  'PROJECT_REFERENCE',
  'ENGINEERING_REFERENCE',
  'AMBIGUOUS_TOKEN',
] as const;
export type ShadowCandidateKind = (typeof SHADOW_CANDIDATE_KINDS)[number];

/** Approved non-secret context: a closed key to closed-code table, never free text. */
export const SHADOW_CONTEXT_CODES: Readonly<Record<string, readonly string[]>> = Object.freeze({
  surface: Object.freeze(['chat-message', 'log-line', 'config-file', 'structured-field', 'script-line',
    'url', 'command-line', 'unknown']),
  contentType: Object.freeze(['text', 'json', 'xml', 'yaml', 'toml', 'ini', 'dotenv', 'log', 'url',
    'connection-string', 'script']),
  fieldKind: Object.freeze(['name', 'email', 'phone', 'host', 'ip', 'port', 'path', 'url',
    'customer-term', 'project-term', 'engineering-id', 'cloud-id', 'unknown']),
  containerKind: Object.freeze(['none', 'list', 'map', 'key-value', 'attribute']),
  script: Object.freeze(['unknown', 'latin', 'cyrillic', 'greek', 'cjk', 'arabic', 'hebrew',
    'devanagari', 'other']),
  neighborCount: Object.freeze(['0', '1', '2-3', '4-7', '8+']),
  positionInField: Object.freeze(['alone', 'start', 'middle', 'end']),
});
export const SHADOW_CONTEXT_KEYS = Object.freeze(Object.keys(SHADOW_CONTEXT_CODES).sort());
export type ShadowContextEntry = Readonly<{ key: string; code: string }>;

/**
 * The deterministic treatment vocabulary, restated only so the shadow record can name what a
 * judgment was not allowed to do. No field of a record is ever set from a treatment.
 */
export const SHADOW_TREATMENTS = ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE',
  'BLOCK', 'REQUIRE_REVIEW'] as const;
export type ShadowTreatment = (typeof SHADOW_TREATMENTS)[number];
/** The treatment an adversarial judge most wants. A legitimate question set may name this label. */
export const ADVERSARIAL_KEEP_LABEL = 'keep_original_value';

export const SHADOW_OUTCOMES = ['ANSWERED', 'ABSTAINED', 'PARTIAL', 'REFUSED', 'TIMEOUT',
  'CANCELLED'] as const;
export type ShadowOutcome = (typeof SHADOW_OUTCOMES)[number];

/** Closed reason codes. No model text, adapter text or exception text ever becomes a reason. */
export const SHADOW_REASON_CODES = [
  'ABSTAINED', 'ADAPTER_REFUSED', 'ADAPTER_THREW', 'CANCELLED', 'CONFIDENCE_OUT_OF_RANGE',
  'DUPLICATE_ANSWER_ID', 'DUPLICATE_QUESTION_ID', 'INCOMPLETE_ANSWERS', 'INVALID_CONTEXT',
  'INVALID_REQUEST', 'MALFORMED_RESPONSE', 'MISSING_ANSWER', 'MISSING_DESTINATION_POLICY',
  'MISSING_ROUTE_BINDING', 'MISSING_BYTE_VERIFICATION', 'MODEL_ALIAS_NOT_PINNED', 'MODEL_ID_NOT_LOCAL',
  'MODEL_ID_REQUIRED', 'NOUL_OUT_OF_RANGE', 'PROBABILITIES_MISMATCH', 'PROBABILITY_OUT_OF_RANGE',
  'PROVIDER_OVERLOADED', 'PROVIDER_RATE_LIMITED', 'PROVIDER_REJECTED', 'PROVIDER_UNAUTHORIZED',
  'QUESTION_ID_REVEALS_VALUE', 'REQUEST_TOO_LARGE', 'RESPONSE_TOO_LARGE', 'SCORE_LEVELS_INVALID',
  'SCORE_NOT_FINITE', 'SELECTED_NOT_MOST_PROBABLE', 'TIMED_OUT', 'TOO_MANY_CONTEXT_ENTRIES',
  'TOO_MANY_NEIGHBORS', 'TOO_MANY_QUESTIONS', 'TYPE_MISMATCH', 'UNAUTHORIZED_CONTEXT_CODE',
  'UNKNOWN_ANSWER', 'UNKNOWN_CHOICE_LABEL', 'UNEXPECTED_FIELD', 'UNEXPECTED_PROVIDER_STATUS',
  'UNSUPPORTED_EXECUTION', 'UNAPPROVED_CONTEXT',
] as const;
export type ShadowReasonCode = (typeof SHADOW_REASON_CODES)[number];

/* ------------------------------------------------------------------------- provider-neutral wire */

/** Canonical, provider-independent answers. Adapters translate documented wire shapes into these. */
export type ShadowCanonicalAnswer =
  | Readonly<{ kind: 'noul'; noul: number }>
  | Readonly<{ kind: 'choice'; choice: string; probabilities: Readonly<Record<string, number>>;
    confidence: number }>
  | Readonly<{ kind: 'score'; score: number; probabilities: Readonly<Record<string, number>>;
    confidence: number }>;
export interface ShadowCanonicalPayload {
  /** Served-model label as reported by the provider. A local double may only claim `local-synthetic/*`. */
  servedModel: string;
  answers: Readonly<Record<string, unknown>>;
  usage?: Readonly<{ inputTokens: number; outputTokens: number }>;
}

/* -------------------------------------------------------------------------------- question sets */

export type ShadowCriteria = Readonly<Record<string, string>> | readonly string[] |
  Readonly<{ true?: string; false?: string }>;
export interface ShadowProposal {
  readonly semanticType?: SemanticClass;
  /** choice: label -> proposed class or `NONE`; score: level index string -> class or `NONE`. */
  readonly byLabel?: Readonly<Record<string, SemanticClass | 'NONE'>>;
}
export interface ShadowQuestion {
  readonly id: string;
  readonly kind: ShadowQuestionKind;
  readonly purpose: ShadowJudgmentPurpose;
  /** Bounded question text from trusted configuration. The core never writes raw text into one. */
  readonly instructions: string;
  /** choice: 2..255 label/description options; score: 2..10 ordered levels; noul: optional meanings. */
  readonly criteria?: ShadowCriteria;
  /** Evidence proposal only. Sensitivity is a deterministic floor and is never accepted here. */
  readonly propose?: ShadowProposal;
}
export interface ShadowQuestionSet {
  readonly id: string;
  readonly version: string;
  readonly questions: readonly ShadowQuestion[];
}

/* ------------------------------------------------------------------------------------- requests */

export interface ShadowCandidate {
  /** Opaque, integration-assigned reference. This seam does not authenticate it. */
  readonly ref: string;
  readonly kind: ShadowCandidateKind;
  /** Local-only. Never serialized, never recorded, never logged. */
  readonly raw: string;
}
export interface ShadowNeighbor {
  readonly kind: ShadowCandidateKind;
  /** Local-only surrounding text. Never serialized, never recorded. */
  readonly raw: string;
}
export interface ShadowCandidateInput {
  readonly candidate: ShadowCandidate;
  readonly neighbors?: readonly ShadowNeighbor[];
  readonly context?: readonly ShadowContextEntry[];
}
export interface ShadowRunOptions {
  /** The only executable transport in this version; `EXTERNAL` is refused before any request. */
  readonly execution: 'IN_PROCESS' | 'EXTERNAL';
  readonly deadlineMs: number;
  readonly signal?: AbortSignal;
  /** Deterministic floor from the trusted integration. Recorded only; nothing can lower it. */
  readonly deterministicFloor?: Sensitivity | 'UNKNOWN';
}
export interface MinimizedShadowRequest {
  readonly version: 1;
  readonly interactionRef: string;
  readonly tenantRef: string;
  readonly questionSet: Readonly<{ id: string; version: string }>;
  readonly judge: Readonly<{ id: string; version: string; transport: 'IN_PROCESS' }>;
  readonly model: Readonly<{ requested: string }>;
  readonly state: {
    /** Request-local ordinal placeholders: not tokens, not resolvable, not authority. */
    readonly candidate: Readonly<{ placeholder: string; kind: ShadowCandidateKind }>;
    readonly neighbors: readonly Readonly<{ placeholder: string; kind: ShadowCandidateKind }>[];
    readonly context: readonly ShadowContextEntry[];
  };
  readonly questions: readonly Readonly<{
    id: string; kind: ShadowQuestionKind; purpose: ShadowJudgmentPurpose; instructions: string;
    criteria?: ShadowCriteria;
  }>[];
}

/* -------------------------------------------------------------------------------------- records */

const requestBrands = new WeakSet<object>();
/** True only for a question set this module defined. Used by the narrow protocol adapter. */
export function isIssuedShadowQuestionSet(value: unknown): boolean {
  return typeof value === 'object' && value !== null && SHADOW_BRANDS.get(value) === 'set';
}
/** True only for a minimized request this module built, so an adapter cannot translate a forgery. */
export function isIssuedShadowRequest(value: unknown): boolean {
  return typeof value === 'object' && value !== null && requestBrands.has(value);
}

export type ShadowAnswerReason = ShadowReasonCode | 'NONE';
export interface ShadowAnswerRecord {
  readonly questionId: string;
  readonly kind: ShadowQuestionKind;
  readonly status: 'ANSWERED' | 'ABSTAINED' | 'MISSING' | 'INVALID';
  readonly reason: ShadowAnswerReason;
  readonly measure?:
    | Readonly<{ kind: 'noul'; noul: number }>
    | Readonly<{ kind: 'choice'; choice: string; probabilities: Readonly<Record<string, number>>;
      confidence: number; selectionIsProviderClaimed: true }>
    | Readonly<{ kind: 'score'; score: number; probabilities: Readonly<Record<string, number>>;
      confidence: number; level: number; levelIsLocallyDerived: true }>;
  /** Evidence proposal only. `NONE` means this judgment abstains from any semantic claim. */
  readonly proposal: Readonly<{ semanticType: SemanticClass | 'NONE'; confidence: number | 'NONE' }>;
}
/** A shadow proposal as the #3 composer expects a channel-bound evidence input. */
export interface ShadowSemanticEvidence {
  readonly version: 1;
  readonly id: string;
  readonly status: 'FOUND';
  readonly provenance: Readonly<{
    inputRef: string; producerId: string; producerVersion: string;
    questionSetVersion: string; modelId: string;
  }>;
  readonly claim: Readonly<{ semanticType: SemanticClass; confidence: number }>;
}
export interface ShadowSettlement {
  /** True when the judge's work settled only after the record was already final. */
  readonly late: boolean;
}
export interface ShadowJudgmentRecord {
  readonly version: 1;
  readonly outcome: ShadowOutcome;
  readonly reasons: readonly ShadowReasonCode[];
  readonly interactionRef: string;
  readonly tenantRef: string;
  readonly candidateRef: string;
  readonly questionSet: Readonly<{ id: string; version: string }>;
  readonly judge: Readonly<{ id: string; version: string; transport: 'IN_PROCESS' }>;
  /** `served` is a `local-synthetic/*` development label; it is never a hosted model claim. */
  readonly model: Readonly<{ requested: string; served: string }>;
  readonly request: Readonly<{ digest: string; bytes: number }>;
  readonly answers: readonly ShadowAnswerRecord[];
  /**
   * Provider-independent evidence proposals, shaped for the #3 composer's `semanticJudgments`
   * channel. The channel names the source, so a record carries no `source` field of its own; a caller
   * supplies these separately, and nothing here can turn them into a treatment.
   */
  readonly evidence: readonly ShadowSemanticEvidence[];
  /** Echoed for record-keeping and evaluation. Nothing in this record can lower it. */
  readonly deterministicFloor: Readonly<{ sensitivity: Sensitivity | 'UNKNOWN'; source: 'INTEGRATION' | 'NONE' }>;
  /** Always `NONE`: a shadow judgment has no policy, release or authorization effect. */
  readonly authority: 'NONE';
  readonly advisory: Readonly<{ suggestedTreatment: 'NONE'; effect: 'IGNORED_NO_AUTHORITY' }>;
  readonly metadata: Readonly<{
    latencyMs: number;
    responseBytes: number;
    deadlineMs: number;
    usage: Readonly<{ inputTokens: number; outputTokens: number }> | 'NONE';
  }>;
}

/* -------------------------------------------------------------------------------- the judge double */

export interface LocalJudgeScript {
  readonly id: string;
  readonly version: string;
  /** Must be a `local-synthetic/*` label: a local double may never claim a hosted served model. */
  readonly servedModel: string;
  readonly latencyMs: number;
  readonly mode: 'ANSWER' | 'REFUSE';
  /** Canonical answers keyed by question id. Arbitrary shapes are validated, not trusted. */
  readonly answers?: Readonly<Record<string, unknown>>;
  /**
   * Deterministic padding, used to exercise the response-size refusal. Padding large enough to pass
   * the size limit is reported as an `UNKNOWN_ANSWER` reason, never as part of a judgment.
   */
  readonly responsePadBytes?: number;
}
export interface ShadowJudge extends LocalJudgeScript { readonly issued: true }

/* --------------------------------------------------------------------------- strict field reading */

type Fields = Record<string, unknown>;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const SHADOW_BRANDS = new WeakMap<object, 'set' | 'judge'>();
class Invalid extends Error { constructor(readonly code: ShadowReasonCode) { super(code); } }
function fail(code: ShadowReasonCode): never { throw new Invalid(code); }

/**
 * One bounded key snapshot, then own data descriptors only, so a Proxy cannot answer twice.
 *
 * An unknown or surplus key is always `UNEXPECTED_FIELD`, never a silent pass-through: an added
 * `treatment`, `sensitivity`, `trust` or `instructions` field is a provider or caller widening this
 * contract, and it must not reach a record. `code` is the context's own closed code, so the same
 * reader reports `INVALID_REQUEST` for a caller-supplied request and `MALFORMED_RESPONSE` for a
 * provider response instead of conflating the two.
 */
function fields(value: unknown, required: readonly string[], optional: readonly string[] = [],
  code: ShadowReasonCode = 'INVALID_REQUEST'): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(code);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) fail(code);
  if (keys.length > required.length + optional.length) fail('UNEXPECTED_FIELD');
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    if (!required.includes(key) && !optional.includes(key)) fail('UNEXPECTED_FIELD');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail(code);
    result[key] = descriptor.value;
  }
  for (const name of required) if (!Object.hasOwn(result, name)) fail(code);
  return result;
}
function label(value: unknown, limit = 128, code: ShadowReasonCode = 'INVALID_REQUEST'): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > limit || value.trim() !== value ||
    CONTROL.test(value)) fail(code);
  return value;
}
function token(value: unknown, limit = 64): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > limit ||
    !/^[a-z0-9][a-z0-9._-]*$/u.test(value)) fail('INVALID_REQUEST');
  return value;
}
/** Question ids travel as request metadata, so they get a closed, lowercase-only shape. */
function questionId(value: unknown): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > 32 ||
    !/^[a-z][a-z0-9_]*$/u.test(value)) fail('QUESTION_ID_REVEALS_VALUE');
  return value;
}
function text(value: unknown, limit: number): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > limit || CONTROL.test(value)) {
    fail('INVALID_REQUEST');
  }
  return value;
}
function member<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) fail('INVALID_REQUEST');
  return value as T;
}
function unit(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) {
    fail('PROBABILITY_OUT_OF_RANGE');
  }
  return value;
}
function boundedCount(value: unknown, min: number, max: number, code: ShadowReasonCode): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) fail(code);
  return value;
}
function codes(values: Iterable<ShadowReasonCode>): readonly ShadowReasonCode[] {
  return Object.freeze([...new Set(values)].sort());
}
/** Exact UTF-8 length without allocating, so a copy budget and a byte ceiling stay exact. */
function utf8Length(text: string): number {
  let length = 0;
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit < 0x80) length += 1;
    else if (unit < 0x800) length += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff && index + 1 < text.length &&
      text.charCodeAt(index + 1) >= 0xdc00 && text.charCodeAt(index + 1) <= 0xdfff) {
      length += 4; index += 1;
    } else length += 3;
  }
  return length;
}

/* ----------------------------------------------------------------- bounded, data-only JSON */

interface JsonBudget { keys: number; bytes: number; }
function jsonBudget(): JsonBudget {
  return { keys: SHADOW_MAX_JSON_KEYS, bytes: SHADOW_MAX_RESPONSE_COPY_BYTES };
}
/**
 * Copy one JSON value through own enumerable DATA descriptors, with a depth, key, string and byte
 * budget.
 *
 * This is the data-only boundary. `JSON.stringify` would consult `toJSON`, read accessors through
 * [[Get]] and walk a prototype chain; none of that happens here, so a caller-supplied getter,
 * function, symbol, cycle, hole or non-finite number is refused instead of executed. A `Proxy`'s
 * traps are the one thing JavaScript still runs before they can be contained, and any trap that
 * throws is reported as this context's closed code by the callers below.
 */
function copyJsonData(value: unknown, budget: JsonBudget, code: ShadowReasonCode,
  depth = 0): unknown {
  if (depth > SHADOW_MAX_JSON_DEPTH) fail(code);
  if (value === null) return null;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail(code);
    return value;
  }
  if (typeof value === 'string') {
    if (value.length > SHADOW_MAX_JSON_STRING) fail(code);
    budget.bytes -= utf8Length(value);
    if (budget.bytes < 0) fail(code);
    return value;
  }
  if (Array.isArray(value)) {
    const result: unknown[] = [];
    for (const item of arrayOf(value, SHADOW_MAX_JSON_KEYS, code, 0)) {
      budget.keys -= 1;
      if (budget.keys < 0) fail(code);
      result.push(copyJsonData(item, budget, code, depth + 1));
    }
    return Object.freeze(result);
  }
  if (value === null || typeof value !== 'object' ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(code);
  const keys = Reflect.ownKeys(value);
  if (keys.length > SHADOW_MAX_JSON_KEYS || keys.some((key) => typeof key !== 'string')) fail(code);
  // A null-prototype target, so a `__proto__` key stays inert data instead of a prototype write.
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    budget.keys -= 1;
    if (budget.keys < 0) fail(code);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail(code);
    result[key] = copyJsonData(descriptor.value, budget, code, depth + 1);
  }
  return Object.freeze(result);
}

interface SerializeState { parts: string[]; bytes: number; ceiling: number; code: ShadowReasonCode; }
function emit(state: SerializeState, text: string): void {
  state.bytes += utf8Length(text);
  if (state.bytes > state.ceiling) fail(state.code);
  state.parts.push(text);
}
function jsonString(text: string, state: SerializeState): void {
  let out = '"';
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit === 0x22) out += '\\"';
    else if (unit === 0x5c) out += '\\\\';
    else if (unit === 0x08) out += '\\b';
    else if (unit === 0x09) out += '\\t';
    else if (unit === 0x0a) out += '\\n';
    else if (unit === 0x0c) out += '\\f';
    else if (unit === 0x0d) out += '\\r';
    else if (unit < 0x20) out += `\\u${unit.toString(16).padStart(4, '0')}`;
    else if (unit >= 0xd800 && unit <= 0xdfff) {
      const next = index + 1 < text.length ? text.charCodeAt(index + 1) : 0;
      if (unit <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) { out += text[index]! + text[index + 1]!; index += 1; }
      // A lone surrogate escapes, as well-formed JSON does, so the encoding stays reversible.
      else out += `\\u${unit.toString(16).padStart(4, '0')}`;
    } else out += text[index]!;
  }
  emit(state, `${out}"`);
}
function serializeJson(value: unknown, state: SerializeState, depth = 0): void {
  if (depth > SHADOW_MAX_JSON_DEPTH) fail(state.code);
  if (value === null) { emit(state, 'null'); return; }
  if (typeof value === 'boolean') { emit(state, value ? 'true' : 'false'); return; }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail(state.code);
    emit(state, String(value)); return;
  }
  if (typeof value === 'string') { jsonString(value, state); return; }
  if (Array.isArray(value)) {
    const items = arrayOf(value, SHADOW_MAX_JSON_KEYS, state.code, 0);
    emit(state, '[');
    for (let index = 0; index < items.length; index += 1) {
      if (index > 0) emit(state, ',');
      serializeJson(items[index], state, depth + 1);
    }
    emit(state, ']');
    return;
  }
  if (value === null || typeof value !== 'object' ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(state.code);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) fail(state.code);
  emit(state, '{');
  let first = true;
  for (const key of keys as string[]) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail(state.code);
    if (!first) emit(state, ',');
    first = false;
    jsonString(key, state);
    emit(state, ':');
    serializeJson(descriptor.value, state, depth + 1);
  }
  emit(state, '}');
}
/**
 * Bounded, data-only JSON serialization with a byte ceiling.
 *
 * The ceiling is always a multiple of the documented limit the caller is about to check, so hitting
 * it means the value is already over that limit: the caller's own closed over-limit code is the
 * right answer, and the work stays linear in the ceiling rather than in an oversized input.
 */
function jsonBytes(value: unknown, ceiling: number, code: ShadowReasonCode): Uint8Array {
  const state: SerializeState = { parts: [], bytes: 0, ceiling, code };
  serializeJson(value, state, 0);
  return new TextEncoder().encode(state.parts.join(''));
}
function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}
function now(): number {
  return typeof performance === 'object' ? performance.now() : Date.now();
}

/* -------------------------------------------------------------------------------- question sets */

/**
 * Trusted configuration operation, not per-request input. Structural validation only: the core
 * cannot know whether an instruction embeds protected text, and it never writes raw text into one.
 */
export function defineShadowQuestionSet(spec: unknown): ShadowQuestionSet {
  try {
    return readShadowQuestionSet(spec);
  } catch (error) {
    // A caller's own Proxy exception is not a Hylja reason code, so it never leaves this module.
    throw error instanceof Invalid ? error : new Invalid('INVALID_REQUEST');
  }
}
function readShadowQuestionSet(spec: unknown): ShadowQuestionSet {
  const v = fields(spec, ['id', 'version', 'questions']);
  const questions: ShadowQuestion[] = [];
  const seen = new Set<string>();
  for (const item of arrayOf(v.questions, SHADOW_MAX_QUESTIONS, 'TOO_MANY_QUESTIONS', 1)) {
    questions.push(validateQuestion(item, seen));
  }
  const result = Object.freeze({ id: token(v.id), version: token(v.version),
    questions: Object.freeze(questions) });
  SHADOW_BRANDS.set(result, 'set');
  return result;
}
function validateQuestion(raw: unknown, seen: Set<string>): ShadowQuestion {
  const v = fields(raw, ['id', 'kind', 'purpose', 'instructions'], ['criteria', 'propose']);
  const id = questionId(v.id);
  if (seen.has(id)) fail('DUPLICATE_QUESTION_ID');
  seen.add(id);
  const kind = member(v.kind, SHADOW_QUESTION_KINDS);
  const question = { id, kind, purpose: member(v.purpose, SHADOW_JUDGMENT_PURPOSES),
    instructions: text(v.instructions, 1024) };
  if (kind === 'choice') {
    const criteria = choiceCriteria(v.criteria);
    return Object.freeze({ ...question, criteria: Object.freeze(criteria),
      ...(v.propose === undefined ? {} : { propose: proposal(v.propose, Object.keys(criteria)) }) });
  }
  if (kind === 'score') {
    const criteria = scoreLevels(v.criteria);
    const levels = Object.freeze(criteria.map((_level, index) => String(index)));
    return Object.freeze({ ...question, criteria: Object.freeze(criteria),
      ...(v.propose === undefined ? {} : { propose: proposal(v.propose, levels) }) });
  }
  if (v.criteria !== undefined) {
    const c = fields(v.criteria, [], ['true', 'false']);
    return Object.freeze({ ...question, criteria: Object.freeze({
      ...(c.true === undefined ? {} : { true: text(c.true, 512) }),
      ...(c.false === undefined ? {} : { false: text(c.false, 512) }),
    }), ...(v.propose === undefined ? {} : { propose: proposal(v.propose, []) }) });
  }
  return Object.freeze(v.propose === undefined ? question : { ...question, propose: proposal(v.propose, []) });
}
function arrayOf(value: unknown, max: number, code: ShadowReasonCode, min: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail(code);
  const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < min || length > max) fail(code);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== length + 1 || !keys.includes('length') ||
    keys.some((key) => typeof key !== 'string')) fail(code);
  const result: unknown[] = [];
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) fail(code);
    result.push(descriptor.value);
  }
  return result;
}
function choiceCriteria(value: unknown): Record<string, string> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('INVALID_REQUEST');
  const keys = Reflect.ownKeys(value);
  if (keys.length < 2 || keys.length > SHADOW_MAX_CHOICE_OPTIONS ||
    keys.some((key) => typeof key !== 'string')) fail('INVALID_REQUEST');
  const result: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const key of keys as string[]) {
    if (!/^[a-z][a-z0-9_]{0,31}$/u.test(key)) fail('UNKNOWN_CHOICE_LABEL');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('INVALID_REQUEST');
    result[key] = text(descriptor.value, 512);
  }
  return result;
}
function scoreLevels(value: unknown): readonly string[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail('SCORE_LEVELS_INVALID');
  const levels: string[] = [];
  for (const level of arrayOf(value, SHADOW_MAX_SCORE_LEVELS, 'SCORE_LEVELS_INVALID',
    SHADOW_MIN_SCORE_LEVELS)) levels.push(text(level, 512));
  return levels;
}
/** A proposal may name a semantic class only. Sensitivity, reversibility and scope are excluded. */
function proposal(value: unknown, choices: readonly string[]): ShadowProposal {
  const v = fields(value, [], ['semanticType', 'byLabel']);
  if (choices.length > 0) {
    // A labelled question maps each option or level to a class. A bare `semanticType` beside it
    // would be silently ignored and the question would abstain forever, so it is refused instead
    // of being trusted as configuration that does nothing.
    if (v.semanticType !== undefined || v.byLabel === undefined) fail('INVALID_REQUEST');
    return Object.freeze({ byLabel: frozenByLabel(v.byLabel, choices) });
  }
  if (v.semanticType === undefined || v.byLabel !== undefined) fail('INVALID_REQUEST');
  member(v.semanticType, SEMANTIC_CLASSES);
  return Object.freeze({ semanticType: v.semanticType as SemanticClass });
}
function frozenByLabel(value: unknown, choices: readonly string[]): Readonly<Record<string,
  SemanticClass | 'NONE'>> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('INVALID_REQUEST');
  const byLabel: Record<string, SemanticClass | 'NONE'> = Object.create(null) as
    Record<string, SemanticClass | 'NONE'>;
  // Own data descriptors only, as for every other object this module reads: an accessor here would
  // run caller code during trusted configuration.
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')) fail('INVALID_REQUEST');
  for (const key of keys as string[]) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('INVALID_REQUEST');
    if (!choices.includes(key)) fail('UNKNOWN_CHOICE_LABEL');
    const mapped = descriptor.value;
    if (mapped !== 'NONE') member(mapped, SEMANTIC_CLASSES);
    byLabel[key] = mapped as SemanticClass | 'NONE';
  }
  return Object.freeze(byLabel);
}

/* ---------------------------------------------------------------------------------- request build */

function contextEntries(value: unknown): readonly ShadowContextEntry[] {
  if (value === undefined) return Object.freeze([]);
  const entries: ShadowContextEntry[] = [];
  for (const item of arrayOf(value, SHADOW_MAX_CONTEXT_ENTRIES, 'TOO_MANY_CONTEXT_ENTRIES', 0)) {
    const entry = fields(item, ['key', 'code']);
    const key = label(entry.key, 64);
    const code = label(entry.code, 64);
    if (!Object.hasOwn(SHADOW_CONTEXT_CODES, key)) fail('UNAPPROVED_CONTEXT');
    if (!(SHADOW_CONTEXT_CODES[key] as readonly string[]).includes(code)) fail('UNAUTHORIZED_CONTEXT_CODE');
    entries.push(Object.freeze({ key, code }));
  }
  if (new Set(entries.map((entry) => entry.key)).size !== entries.length) fail('INVALID_CONTEXT');
  return Object.freeze(entries);
}
function neighborKinds(value: unknown): readonly ShadowCandidateKind[] {
  if (value === undefined) return Object.freeze([]);
  const kinds: ShadowCandidateKind[] = [];
  for (const item of arrayOf(value, SHADOW_MAX_NEIGHBORS, 'TOO_MANY_NEIGHBORS', 0)) {
    const entry = fields(item, ['kind', 'raw']);
    kinds.push(member(entry.kind, SHADOW_CANDIDATE_KINDS));
    // Read for validation only. Surrounding text is dropped here and never stored or returned.
    if (!text(entry.raw, 4096).length) fail('INVALID_REQUEST');
  }
  return Object.freeze(kinds);
}
function placeholder(prefix: string, index: number): string {
  return `${prefix}-${String(index + 1).padStart(2, '0')}`;
}
interface PreparedShadowRequest {
  readonly request: MinimizedShadowRequest;
  readonly requestBytes: Uint8Array;
  /** Attribution taken from the same validated snapshot, never from a second read. */
  readonly candidateRef: string;
}
/**
 * Local minimization, and the single validated read of the caller's input.
 *
 * The candidate, its neighbours and its context are each read once, through `fields()`, and the
 * values that survive validation are the only ones used. A caller object that answers differently
 * on a second read therefore cannot substitute a value that was never validated.
 */
function prepareShadowRequest(interactionRef: unknown, tenantRef: unknown, set: unknown,
  judge: unknown, input: unknown): PreparedShadowRequest {
  try {
    return readShadowRequest(interactionRef, tenantRef, set, judge, input);
  } catch (error) {
    throw error instanceof Invalid ? error : new Invalid('INVALID_REQUEST');
  }
}
function readShadowRequest(interactionRef: unknown, tenantRef: unknown, set: unknown, judge: unknown,
  input: unknown): PreparedShadowRequest {
  if (SHADOW_BRANDS.get(set as object) !== 'set') fail('INVALID_REQUEST');
  if (SHADOW_BRANDS.get(judge as object) !== 'judge') fail('INVALID_REQUEST');
  const top = fields(input, ['candidate'], ['neighbors', 'context']);
  const candidate = fields(top.candidate, ['ref', 'kind', 'raw']);
  const ref = label(candidate.ref, 256);
  const kind = member(candidate.kind, SHADOW_CANDIDATE_KINDS);
  // Read for validation only. The value is dropped here and is never stored or returned.
  if (!text(candidate.raw, 4096).length) fail('INVALID_REQUEST');
  const setValue = set as ShadowQuestionSet;
  const judgeValue = judge as ShadowJudge;
  const request: MinimizedShadowRequest = {
    version: 1,
    interactionRef: label(interactionRef, 256),
    tenantRef: label(tenantRef, 256),
    questionSet: Object.freeze({ id: setValue.id, version: setValue.version }),
    judge: Object.freeze({ id: judgeValue.id, version: judgeValue.version, transport: 'IN_PROCESS' }),
    model: Object.freeze({ requested: 'local-synthetic' }),
    state: Object.freeze({
      candidate: Object.freeze({ placeholder: placeholder('cand', 0), kind }),
      neighbors: Object.freeze(neighborKinds(top.neighbors)
        .map((neighborKind, index) => Object.freeze({ placeholder: placeholder('nbr', index),
          kind: neighborKind }))),
      context: contextEntries(top.context),
    }),
    questions: Object.freeze(setValue.questions.map((question) => Object.freeze({
      id: question.id, kind: question.kind, purpose: question.purpose,
      instructions: question.instructions,
      ...(question.criteria === undefined ? {} : { criteria: question.criteria }),
    }))),
  };
  // The ceiling is a multiple of the documented limit, so passing it still reports REQUEST_TOO_LARGE.
  const requestBytes = jsonBytes(request, SHADOW_MAX_REQUEST_BYTES * 4, 'REQUEST_TOO_LARGE');
  if (requestBytes.length > SHADOW_MAX_REQUEST_BYTES) fail('REQUEST_TOO_LARGE');
  const frozen = Object.freeze(request);
  // A minimized request is branded. A provider adapter may only translate a request this seam
  // issued, so a hand-built object cannot smuggle raw text into an outbound judge state.
  requestBrands.add(frozen);
  return Object.freeze({ request: frozen, requestBytes, candidateRef: ref });
}
/** Local minimization. Raw candidate and neighbouring text never reach the returned request. */
export function minimizeShadowRequest(interactionRef: unknown, tenantRef: unknown, set: unknown,
  judge: unknown, input: unknown): MinimizedShadowRequest {
  return prepareShadowRequest(interactionRef, tenantRef, set, judge, input).request;
}

/* -------------------------------------------------------------------------------- canonical parse */

export interface ParsedShadowPayload {
  readonly answers: Readonly<Record<string, ShadowCanonicalAnswer>>;
  /** Per-question closed reason for an answer that was present but rejected, keyed by question id. */
  readonly invalid: Readonly<Record<string, ShadowReasonCode>>;
  readonly servedModel: string;
  readonly usage: Readonly<{ inputTokens: number; outputTokens: number }> | null;
  readonly problems: readonly ShadowReasonCode[];
}
/** Strict validation of the canonical payload against the question set. Throws only closed codes. */
export function parseShadowJudgePayload(payload: unknown, set: unknown): ParsedShadowPayload {
  try {
    return readShadowJudgePayload(payload, set);
  } catch (error) {
    // A caller's own Proxy exception is not a Hylja reason code: a provider body that cannot even be
    // read is one malformed response.
    throw error instanceof Invalid ? error : new Invalid('MALFORMED_RESPONSE');
  }
}
function readShadowJudgePayload(payload: unknown, set: unknown): ParsedShadowPayload {
  if (SHADOW_BRANDS.get(set as object) !== 'set') fail('INVALID_REQUEST');
  const setValue = set as ShadowQuestionSet;
  const v = fields(payload, ['servedModel', 'answers'], ['usage'], 'MALFORMED_RESPONSE');
  const servedModel = label(v.servedModel, 128, 'MALFORMED_RESPONSE');
  let usage: { inputTokens: number; outputTokens: number } | null = null;
  if (Object.hasOwn(v, 'usage')) {
    const u = fields(v.usage, ['inputTokens', 'outputTokens'], [], 'MALFORMED_RESPONSE');
    if (typeof u.inputTokens !== 'number' || !Number.isSafeInteger(u.inputTokens) || u.inputTokens < 0 ||
      typeof u.outputTokens !== 'number' || !Number.isSafeInteger(u.outputTokens) || u.outputTokens < 0) {
      fail('MALFORMED_RESPONSE');
    }
    usage = Object.freeze({ inputTokens: u.inputTokens as number, outputTokens: u.outputTokens as number });
  }
  const expected = new Map(setValue.questions.map((question) => [question.id, question]));
  const raw = v.answers;
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(raw))) fail('MALFORMED_RESPONSE');
  const ids = Reflect.ownKeys(raw);
  // A module-issued local judge answers at most the whole set plus one documented padding key, so
  // this bound can only be reached by an externally supplied body, which is refused as malformed.
  if (ids.length > expected.size + SHADOW_MAX_QUESTIONS) fail('MALFORMED_RESPONSE');
  const problems = new Set<ShadowReasonCode>();
  // This version runs local doubles only, so a hosted served-model label is a closed problem here
  // and not merely a string the record happens to echo.
  if (!/^local-synthetic\//u.test(servedModel)) problems.add('MODEL_ID_NOT_LOCAL');
  const answers: Record<string, ShadowCanonicalAnswer> = Object.create(null) as
    Record<string, ShadowCanonicalAnswer>;
  const invalid: Record<string, ShadowReasonCode> = Object.create(null) as
    Record<string, ShadowReasonCode>;
  for (const id of ids as string[]) {
    if (typeof id !== 'string' || id.length > 32) fail('MALFORMED_RESPONSE');
    const descriptor = Object.getOwnPropertyDescriptor(raw, id);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('MALFORMED_RESPONSE');
    if (!expected.has(id)) { problems.add('UNKNOWN_ANSWER'); continue; }
    if (Object.hasOwn(answers, id)) { problems.add('DUPLICATE_ANSWER_ID'); continue; }
    try {
      answers[id] = validateCanonicalAnswer(descriptor.value, expected.get(id)!);
    } catch (error) {
      const code = error instanceof Invalid ? error.code : 'MALFORMED_RESPONSE';
      // A rejected answer stays visible as that question's own closed reason, never as a silent gap.
      invalid[id] = code;
      problems.add(code);
    }
  }
  return Object.freeze({ answers: Object.freeze(answers), invalid: Object.freeze(invalid), servedModel,
    usage, problems: codes(problems) });
}
function validateCanonicalAnswer(raw: unknown, question: ShadowQuestion): ShadowCanonicalAnswer {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) fail('MALFORMED_RESPONSE');
  const kindValue = Object.getOwnPropertyDescriptor(raw, 'kind');
  if (!kindValue?.enumerable || !('value' in kindValue)) fail('MALFORMED_RESPONSE');
  const kind = member(kindValue.value, SHADOW_QUESTION_KINDS);
  if (kind !== question.kind) fail('TYPE_MISMATCH');
  const v = fields(raw, kind === 'noul' ? ['kind', 'noul'] : ['kind'], kind === 'noul' ? [] :
    kind === 'choice' ? ['choice', 'probabilities', 'confidence'] :
    ['score', 'probabilities', 'confidence'], 'MALFORMED_RESPONSE');
  if (kind === 'noul') {
    if (typeof v.noul !== 'number' || !Number.isFinite(v.noul) || v.noul < 0 || v.noul > 1) {
      fail('NOUL_OUT_OF_RANGE');
    }
    return Object.freeze({ kind, noul: v.noul });
  }
  if (kind === 'choice') {
    const criteria = choiceCriteria(question.criteria);
    const probabilities = probabilityMap(v.probabilities, Object.keys(criteria));
    if (typeof v.confidence !== 'number' || !Number.isFinite(v.confidence) || v.confidence < 0 ||
      v.confidence > 1) fail('CONFIDENCE_OUT_OF_RANGE');
    const choice = v.choice;
    if (typeof choice !== 'string' || choice.length < 1 || choice.length > 64 ||
      !Object.hasOwn(criteria, choice)) fail('UNKNOWN_CHOICE_LABEL');
    // The documented selection is the highest-probability option; a tie keeps the claim.
    if (probabilities[choice]! < Math.max(...Object.values(probabilities))) {
      fail('SELECTED_NOT_MOST_PROBABLE');
    }
    return Object.freeze({ kind, choice, probabilities, confidence: v.confidence });
  }
  const levels = scoreLevels(question.criteria);
  const probabilities = probabilityMap(v.probabilities, levels.map((_level, index) => String(index)));
  if (typeof v.confidence !== 'number' || !Number.isFinite(v.confidence) || v.confidence < 0 ||
    v.confidence > 1) fail('CONFIDENCE_OUT_OF_RANGE');
  if (typeof v.score !== 'number' || !Number.isFinite(v.score)) fail('SCORE_NOT_FINITE');
  return Object.freeze({ kind, score: v.score, probabilities, confidence: v.confidence });
}
function probabilityMap(raw: unknown, keys: readonly string[]): Readonly<Record<string, number>> {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(raw))) fail('PROBABILITIES_MISMATCH');
  const own = Reflect.ownKeys(raw);
  if (own.length !== keys.length || keys.some((key) => !own.includes(key))) fail('PROBABILITIES_MISMATCH');
  const result: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(raw, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('PROBABILITIES_MISMATCH');
    result[key] = unit(descriptor.value);
  }
  return Object.freeze(result);
}

/* -------------------------------------------------------------------------------- the judge double */

/**
 * The only executable judge. It is a data script, not a caller-supplied function, so it cannot open
 * a socket, read a credential or reach a network. A `local-synthetic/*` served model is mandatory so
 * a local double can never be mistaken for a hosted judgment in an evaluation record.
 */
export function createLocalShadowJudge(script: unknown): ShadowJudge {
  try {
    return readLocalShadowJudge(script);
  } catch (error) {
    // A caller's own Proxy exception is not a Hylja reason code, so it never leaves this module.
    throw error instanceof Invalid ? error : new Invalid('INVALID_REQUEST');
  }
}
function readLocalShadowJudge(script: unknown): ShadowJudge {
  const v = fields(script, ['id', 'version', 'servedModel', 'latencyMs', 'mode'],
    ['answers', 'responsePadBytes']);
  const servedModel = label(v.servedModel, 128);
  if (!/^local-synthetic\/[a-z0-9][a-z0-9._-]{0,63}$/u.test(servedModel)) fail('MODEL_ID_NOT_LOCAL');
  const judge: ShadowJudge = Object.freeze({
    id: token(v.id), version: token(v.version), servedModel, issued: true,
    latencyMs: boundedCount(v.latencyMs, 0, SHADOW_MAX_SCRIPT_LATENCY_MS, 'INVALID_REQUEST'),
    mode: member(v.mode, ['ANSWER', 'REFUSE']),
    ...(v.answers === undefined ? {} : { answers: answerMap(v.answers) }),
    ...(v.responsePadBytes === undefined ? {} :
      { responsePadBytes: boundedCount(v.responsePadBytes, 0, SHADOW_MAX_RESPONSE_COPY_BYTES,
        'INVALID_REQUEST') }),
  });
  SHADOW_BRANDS.set(judge, 'judge');
  return judge;
}
/**
 * Copy the script's answers into inert, frozen JSON data.
 *
 * The seam accepts data, never behavior: an accessor, a function, a `toJSON` method, a symbol, a
 * cycle, a hole, a non-finite number, a custom prototype or anything over the copy bounds is
 * refused HERE, so nothing a caller supplied can be executed later by parsing, measuring or
 * recording. One budget covers the whole map, so total work stays bounded.
 */
function answerMap(value: unknown): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('INVALID_REQUEST');
  const keys = Reflect.ownKeys(value);
  if (keys.length > SHADOW_MAX_SCRIPT_ANSWER_KEYS || keys.some((key) => typeof key !== 'string')) {
    fail('INVALID_REQUEST');
  }
  const budget = jsonBudget();
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys as string[]) {
    budget.keys -= 1;
    if (key.length > 32) fail('INVALID_REQUEST');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('INVALID_REQUEST');
    result[key] = copyJsonData(descriptor.value, budget, 'INVALID_REQUEST', 0);
  }
  return Object.freeze(result);
}
function judgePayload(judge: ShadowJudge): ShadowCanonicalPayload | null {
  if (judge.mode === 'REFUSE') return null;
  const answers: Record<string, unknown> = { ...(judge.answers ?? {}) };
  if (judge.responsePadBytes) answers.padding = 'x'.repeat(judge.responsePadBytes);
  return Object.freeze({ servedModel: judge.servedModel, answers: Object.freeze(answers) });
}

/* ---------------------------------------------------------------------------------- execution */

function delay(ms: number, signal: AbortSignal): Promise<'elapsed' | 'aborted'> {
  return new Promise((resolve) => {
    if (signal.aborted) { resolve('aborted'); return; }
    const onAbort = (): void => { clearTimeout(timer); resolve('aborted'); };
    const timer = setTimeout(() => { signal.removeEventListener('abort', onAbort); resolve('elapsed'); }, ms);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}
function stopped(controller: AbortController): Promise<'stopped'> {
  return new Promise((resolve) => {
    if (controller.signal.aborted) { resolve('stopped'); return; }
    controller.signal.addEventListener('abort', () => { resolve('stopped'); }, { once: true });
  });
}
function blankRecord(outcome: ShadowOutcome, reasons: readonly ShadowReasonCode[],
  deadlineMs: number, latencyMs: number,
  floor: { sensitivity: Sensitivity | 'UNKNOWN'; source: 'INTEGRATION' | 'NONE' } =
  { sensitivity: 'UNKNOWN', source: 'NONE' }): ShadowJudgmentRecord {
  return Object.freeze({
    version: 1, outcome, reasons: codes(reasons),
    interactionRef: 'unbound', tenantRef: 'unbound', candidateRef: 'unbound',
    questionSet: Object.freeze({ id: 'unbound', version: 'unbound' }),
    judge: Object.freeze({ id: 'unbound', version: 'unbound', transport: 'IN_PROCESS' }),
    model: Object.freeze({ requested: 'local-synthetic', served: 'NONE' }),
    request: Object.freeze({ digest: sha256(new Uint8Array(0)), bytes: 0 }),
    answers: Object.freeze([]), evidence: Object.freeze([]),
    // Identity is a fixed, safe, unbound placeholder here; the floor is echoed once it was read.
    deterministicFloor: Object.freeze({ ...floor }),
    authority: 'NONE',
    advisory: Object.freeze({ suggestedTreatment: 'NONE', effect: 'IGNORED_NO_AUTHORITY' }),
    metadata: Object.freeze({ latencyMs: Math.max(0, Math.round(latencyMs)), responseBytes: 0,
      deadlineMs, usage: 'NONE' }),
  });
}
/**
 * The same conservative record for a request that really was built and then failed or never
 * answered. Identity metadata survives, because an outage nobody can attribute to an interaction and
 * tenant is not reviewable evidence; no answer, proposal, served model or treatment appears.
 */
function idleRecord(outcome: ShadowOutcome, reasons: readonly ShadowReasonCode[],
  floor: { sensitivity: Sensitivity | 'UNKNOWN'; source: 'INTEGRATION' | 'NONE' }, deadlineMs: number,
  latencyMs: number, request: MinimizedShadowRequest, set: ShadowQuestionSet, judge: ShadowJudge,
  candidateRef: string, requestBytes: Uint8Array): ShadowJudgmentRecord {
  return Object.freeze({
    version: 1, outcome, reasons: codes(reasons),
    interactionRef: request.interactionRef, tenantRef: request.tenantRef, candidateRef,
    questionSet: Object.freeze({ id: set.id, version: set.version }),
    judge: Object.freeze({ id: judge.id, version: judge.version, transport: 'IN_PROCESS' }),
    model: Object.freeze({ requested: request.model.requested, served: 'NONE' }),
    request: Object.freeze({ digest: sha256(requestBytes), bytes: requestBytes.length }),
    answers: Object.freeze([]), evidence: Object.freeze([]),
    deterministicFloor: Object.freeze({ ...floor }),
    authority: 'NONE',
    advisory: Object.freeze({ suggestedTreatment: 'NONE', effect: 'IGNORED_NO_AUTHORITY' }),
    metadata: Object.freeze({ latencyMs: Math.max(0, Math.round(latencyMs)), responseBytes: 0,
      deadlineMs, usage: 'NONE' }),
  });
}
function settled(record: ShadowJudgmentRecord, late: boolean): ShadowRun {
  return { record: Promise.resolve(record), settlement: Promise.resolve(Object.freeze({ late })) };
}
export interface ShadowRun {
  /** The final, frozen, privacy-safe record. It never carries a treatment or an authorization. */
  readonly record: Promise<ShadowJudgmentRecord>;
  /** Resolves once the judge's in-flight work has definitely settled. */
  readonly settlement: Promise<ShadowSettlement>;
}

/**
 * Run one bounded shadow judgment.
 *
 * Every outcome, including a timeout, an outage, a malformed body, an abstention or an unapproved
 * context, is an explicit conservative record. There is no code path here that selects a treatment,
 * grants release, relaxes protected egress or lowers deterministic credential evidence.
 *
 * Nothing throws out of this function and neither promise it returns ever rejects: a caller that
 * observes only `settlement` -- the documented way to watch late work -- cannot leave an unhandled
 * rejection behind, and a caller that observes `record` always gets a typed, conservative result.
 */
export function runShadowJudgment(set: unknown, judge: unknown, interactionRef: unknown, tenantRef: unknown,
  input: unknown, options: unknown): ShadowRun {
  try {
    return startShadowRun(set, judge, interactionRef, tenantRef, input, options);
  } catch {
    // Defense in depth: a caller-controlled object that no closed code describes is an invalid
    // request, never an exception the caller must handle.
    return settled(blankRecord('REFUSED', ['INVALID_REQUEST'], 0, 0), false);
  }
}
function startShadowRun(set: unknown, judge: unknown, interactionRef: unknown, tenantRef: unknown,
  input: unknown, options: unknown): ShadowRun {
  const started = now();
  if (SHADOW_BRANDS.get(set as object) !== 'set' || SHADOW_BRANDS.get(judge as object) !== 'judge') {
    return settled(blankRecord('REFUSED', ['INVALID_REQUEST'], 0, 0), false);
  }
  const setValue = set as ShadowQuestionSet;
  const judgeValue = judge as ShadowJudge;
  let deadlineMs = 0;
  let signal: AbortSignal | undefined;
  const floor: { sensitivity: Sensitivity | 'UNKNOWN'; source: 'INTEGRATION' | 'NONE' } =
    { sensitivity: 'UNKNOWN', source: 'NONE' };
  try {
    const v = fields(options, ['execution', 'deadlineMs'], ['signal', 'deterministicFloor']);
    if (v.execution !== 'IN_PROCESS') {
      // Refused before any request exists: this version has no external path at all.
      return settled(blankRecord('REFUSED', ['UNSUPPORTED_EXECUTION', 'MISSING_DESTINATION_POLICY',
        'MISSING_ROUTE_BINDING', 'MISSING_BYTE_VERIFICATION'], 0, 0), false);
    }
    deadlineMs = boundedCount(v.deadlineMs, SHADOW_MIN_DEADLINE_MS, SHADOW_MAX_DEADLINE_MS,
      'INVALID_REQUEST');
    if (Object.hasOwn(v, 'signal')) {
      // The abort API is required up front: a signal-shaped object without it is a refusal, not a
      // TypeError raised from inside this function.
      if (v.signal === null || typeof v.signal !== 'object' ||
        typeof (v.signal as { aborted?: unknown }).aborted !== 'boolean' ||
        typeof (v.signal as { addEventListener?: unknown }).addEventListener !== 'function' ||
        typeof (v.signal as { removeEventListener?: unknown }).removeEventListener !== 'function') {
        return settled(blankRecord('REFUSED', ['INVALID_REQUEST'], deadlineMs, 0, floor), false);
      }
      signal = v.signal as AbortSignal;
    }
    if (Object.hasOwn(v, 'deterministicFloor')) {
      floor.sensitivity = v.deterministicFloor === 'UNKNOWN' ? 'UNKNOWN' :
        member(v.deterministicFloor, SENSITIVITIES);
      floor.source = 'INTEGRATION';
    }
  } catch (error) {
    return settled(blankRecord('REFUSED', [error instanceof Invalid ? error.code : 'INVALID_REQUEST'],
      deadlineMs, 0, floor), false);
  }
  let prepared: PreparedShadowRequest;
  try {
    // One validated read of the caller's input. `candidateRef`, the request and its bytes all come
    // from this single snapshot, so no caller object is read again after it was validated.
    prepared = prepareShadowRequest(interactionRef, tenantRef, set, judge, input);
  } catch (error) {
    return settled(blankRecord('REFUSED', [error instanceof Invalid ? error.code : 'INVALID_REQUEST'],
      deadlineMs, 0, floor), false);
  }
  const { request, requestBytes, candidateRef } = prepared;
  const state = { final: false, late: false, failed: false };
  // Two independent controls, deliberately: caller cancellation aborts the judge's own work, while
  // the seam's deadline only stops WAITING. That is what makes a genuinely late result observable --
  // the same situation a real network adapter faces when a response lands after its deadline.
  const caller = new AbortController();
  const waiting = new AbortController();
  const detach = (): void => { signal?.removeEventListener('abort', forward); };
  const forward = (): void => { caller.abort(); waiting.abort(); };
  if (signal) {
    if (signal.aborted) forward();
    else signal.addEventListener('abort', forward, { once: true });
  }
  const timer = setTimeout(() => { waiting.abort(); }, deadlineMs);
  // The judge's work is promise-contained: a late settlement is observed and discarded, never
  // merged into the final record and never surfaced as an unhandled rejection.
  const judged = delay(judgeValue.latencyMs, caller.signal).then(() => {
    const late = state.final;
    if (late) state.late = true;
    let payload: ShadowCanonicalPayload | null = null;
    try { payload = late ? null : judgePayload(judgeValue); } catch { state.failed = true; }
    return Object.freeze({ late, payload });
  }, () => {
    state.failed = true;
    return Object.freeze({ late: state.final, payload: null });
  });

  const work = Promise.race([
    judged.then((result) => ({ type: 'judged' as const, result })),
    stopped(waiting).then(() => ({ type: 'stopped' as const })),
  ]).then((outcome) => {
    // The record is final from this point, whether or not what follows succeeds.
    state.final = true;
    try {
      clearTimeout(timer);
      detach();
      if (outcome.type === 'judged') {
        if (outcome.result.payload !== null) {
          return buildRecord(request, setValue, judgeValue, candidateRef, requestBytes, floor, deadlineMs,
            started, outcome.result.payload);
        }
        // Order matters and must not depend on which promise settles first: a cancelled caller wins
        // over a transport failure, and a transport failure wins over a plain refusal.
        if (signal?.aborted === true) {
          return idleRecord('CANCELLED', ['CANCELLED'], floor, deadlineMs, now() - started, request,
            setValue, judgeValue, candidateRef, requestBytes);
        }
        return idleRecord('REFUSED', [state.failed ? 'ADAPTER_THREW' : 'ADAPTER_REFUSED'], floor, deadlineMs,
          now() - started, request, setValue, judgeValue, candidateRef, requestBytes);
      }
      return idleRecord(signal?.aborted === true ? 'CANCELLED' : 'TIMEOUT',
        [signal?.aborted === true ? 'CANCELLED' : 'TIMED_OUT'], floor, deadlineMs, now() - started, request,
        setValue, judgeValue, candidateRef, requestBytes);
    } catch (error) {
      // An answer this module did not build could still fail to be interpreted. That is an explicit
      // conservative record, never a rejected promise a caller has to remember to handle.
      return idleRecord('REFUSED', [error instanceof Invalid ? error.code : 'INVALID_REQUEST'], floor,
        deadlineMs, now() - started, request, setValue, judgeValue, candidateRef, requestBytes);
    }
  });

  // `settlement` waits for the judge's own work even after the record is final, and resolves even
  // when the record path failed, so no caller of either promise can end up with an unhandled one.
  const settlement = judged.then((result) => {
    clearTimeout(timer);
    return Object.freeze({ late: result.late || state.late });
  }, () => Object.freeze({ late: state.late }));
  return { record: work, settlement };
}

/* -------------------------------------------------------------------------------- record builder */

function buildRecord(request: MinimizedShadowRequest, set: ShadowQuestionSet, judge: ShadowJudge,
  candidateRef: string, requestBytes: Uint8Array,
  floor: { sensitivity: Sensitivity | 'UNKNOWN'; source: 'INTEGRATION' | 'NONE' },
  deadlineMs: number, started: number, payload: ShadowCanonicalPayload | null): ShadowJudgmentRecord {
  const reasons = new Set<ShadowReasonCode>();
  // Size first, parse second: an oversized body is never interpreted, so no part of it can reach a
  // record, a proposal or an evidence entry. Both steps are inside one guard, because a payload this
  // module did not build may still be uninterpretable, and a record promise that rejects would take
  // the process down with it under Node's default unhandled-rejection behavior.
  let parsed: ParsedShadowPayload | null = null;
  let responseBytes = 0;
  try {
    responseBytes = payload === null ? 0 :
      jsonBytes(payload, SHADOW_MAX_RESPONSE_BYTES * 8, 'RESPONSE_TOO_LARGE').length;
    if (payload !== null && responseBytes > SHADOW_MAX_RESPONSE_BYTES) {
      return idleRecord('REFUSED', ['RESPONSE_TOO_LARGE'], floor, deadlineMs, now() - started, request, set,
        judge, candidateRef, requestBytes);
    }
    parsed = payload === null ? null : parseShadowJudgePayload(payload, set);
  } catch (error) {
    return idleRecord('REFUSED', [error instanceof Invalid ? error.code : 'MALFORMED_RESPONSE'], floor,
      deadlineMs, now() - started, request, set, judge, candidateRef, requestBytes);
  }
  if (parsed === null) reasons.add('ADAPTER_REFUSED');
  else {
    for (const problem of parsed.problems) reasons.add(problem);
    if (!/^local-synthetic\//u.test(parsed.servedModel)) reasons.add('MODEL_ID_NOT_LOCAL');
  }

  const answers: ShadowAnswerRecord[] = [];
  let answered = 0;
  let abstained = 0;
  for (const question of set.questions) {
    const answer = parsed === null ? undefined : parsed.answers[question.id];
    if (answer === undefined) {
      const rejected = parsed?.invalid[question.id];
      const problem = rejected ?? (parsed?.problems.includes('UNKNOWN_ANSWER') === true ? 'UNKNOWN_ANSWER' :
        'MISSING_ANSWER');
      reasons.add(problem);
      answers.push(Object.freeze({ questionId: question.id, kind: question.kind,
        status: rejected === undefined ? 'MISSING' : 'INVALID', reason: problem,
        proposal: Object.freeze({ semanticType: 'NONE', confidence: 'NONE' }) }));
      continue;
    }
    const record = measureAnswer(question, answer);
    answers.push(record);
    if (record.status === 'ANSWERED') answered++;
    else { abstained++; reasons.add('ABSTAINED'); }
  }
  const complete = answered + abstained === set.questions.length;
  if (!complete) reasons.add('INCOMPLETE_ANSWERS');
  const outcome: ShadowOutcome = parsed === null ? 'REFUSED' : !complete ? 'PARTIAL' :
    answered > 0 ? 'ANSWERED' : 'ABSTAINED';
  const servedModel = parsed === null ? 'NONE' : parsed.servedModel;
  const evidence = answers
    .filter((record) => record.status === 'ANSWERED' && record.proposal.semanticType !== 'NONE')
    .map((record) => semanticEvidence(set, judge, servedModel, candidateRef, record));
  return Object.freeze({
    version: 1, outcome, reasons: codes(reasons),
    interactionRef: request.interactionRef, tenantRef: request.tenantRef, candidateRef,
    questionSet: Object.freeze({ id: set.id, version: set.version }),
    judge: Object.freeze({ id: judge.id, version: judge.version, transport: 'IN_PROCESS' }),
    model: Object.freeze({ requested: request.model.requested, served: servedModel }),
    request: Object.freeze({ digest: sha256(requestBytes), bytes: requestBytes.length }),
    answers: Object.freeze(answers), evidence: Object.freeze(evidence),
    deterministicFloor: Object.freeze({ ...floor }),
    authority: 'NONE',
    advisory: Object.freeze({ suggestedTreatment: 'NONE', effect: 'IGNORED_NO_AUTHORITY' }),
    metadata: Object.freeze({ latencyMs: Math.max(0, Math.round(now() - started)), responseBytes,
      deadlineMs, usage: parsed?.usage ?? 'NONE' }),
  });
}
function measureAnswer(question: ShadowQuestion, answer: ShadowCanonicalAnswer): ShadowAnswerRecord {
  const base = { questionId: question.id, kind: question.kind, reason: 'NONE' } as const;
  if (answer.kind === 'noul') {
    const semanticType = question.propose?.semanticType ?? 'NONE';
    return Object.freeze({ ...base, status: semanticType === 'NONE' ? 'ABSTAINED' : 'ANSWERED',
      measure: Object.freeze({ kind: 'noul', noul: answer.noul }),
      proposal: Object.freeze({ semanticType,
        confidence: semanticType === 'NONE' ? 'NONE' : answer.noul }) });
  }
  if (answer.kind === 'choice') {
    const proposed = question.propose?.byLabel?.[answer.choice] ?? 'NONE';
    return Object.freeze({ ...base, status: proposed === 'NONE' ? 'ABSTAINED' : 'ANSWERED',
      measure: Object.freeze({ kind: 'choice', choice: answer.choice,
        probabilities: answer.probabilities, confidence: answer.confidence,
        selectionIsProviderClaimed: true as const }),
      proposal: Object.freeze({ semanticType: proposed,
        confidence: proposed === 'NONE' ? 'NONE' : answer.confidence }) });
  }
  // `level` is derived here by argmax over the reported distribution, never interpolated from the
  // expected score: the provider documents that score levels are not numerically calibrated.
  let level = '0';
  let best = -1;
  for (const [key, value] of Object.entries(answer.probabilities)) {
    if (value > best) { best = value; level = key; }
  }
  const proposed = question.propose?.byLabel?.[level] ?? 'NONE';
  return Object.freeze({ ...base, status: proposed === 'NONE' ? 'ABSTAINED' : 'ANSWERED',
    measure: Object.freeze({ kind: 'score', score: answer.score, probabilities: answer.probabilities,
      confidence: answer.confidence, level: Number(level), levelIsLocallyDerived: true as const }),
    proposal: Object.freeze({ semanticType: proposed,
      confidence: proposed === 'NONE' ? 'NONE' : answer.confidence }) });
}
function semanticEvidence(set: ShadowQuestionSet, judge: ShadowJudge, servedModel: string,
  candidateRef: string, record: ShadowAnswerRecord): ShadowSemanticEvidence {
  // A shadow judgment never claims a sensitivity, reversibility or scope: the deterministic floor and
  // the Policy Engine own those. Only a bounded confidence accompanies the proposed semantic class.
  return Object.freeze({
    version: 1,
    id: `shadow.${set.id}.${set.version}.${record.questionId}`,
    status: 'FOUND',
    provenance: Object.freeze({ inputRef: candidateRef, producerId: `shadow.${judge.id}`,
      producerVersion: judge.version, questionSetVersion: `${set.id}@${set.version}`,
      modelId: servedModel === 'NONE' ? `local-synthetic/${judge.version}` : servedModel }),
    claim: Object.freeze({ semanticType: record.proposal.semanticType as SemanticClass,
      confidence: record.proposal.confidence as number }),
  });
}

/* ------------------------------------------------------------------------------------- utilities */

/** Sensitivity rank for evaluating floors. Higher is more restrictive; `UNKNOWN` is below PUBLIC. */
export function shadowSensitivityRank(sensitivity: Sensitivity | 'UNKNOWN'): number {
  const index = SENSITIVITIES.indexOf(sensitivity as Sensitivity);
  return index < 0 ? -1 : index;
}
/**
 * Read exactly the named own data properties of an object, tolerating any other key.
 *
 * Used for record inspection, where the object legitimately has many keys. This is deliberately not
 * `fields()`: that reader refuses a widened shape, which is correct for a caller or provider
 * object and wrong for a record this module itself produced.
 */
function selected(value: unknown, names: readonly string[]): Fields | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const result: Fields = Object.create(null) as Fields;
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor?.enumerable || !('value' in descriptor)) return null;
    result[name] = descriptor.value;
  }
  return result;
}
/**
 * Congruence check for replaying a record inside a tenant. This is not authentication: a caller able
 * to fabricate a record fabricates its answer too. Cross-tenant replay is refused.
 */
export function belongsToShadowTenant(record: unknown, tenantRef: unknown): boolean {
  try {
    const v = selected(record, ['version', 'tenantRef']);
    return v !== null && v.version === 1 && v.tenantRef === label(tenantRef, 256);
  } catch { return false; }
}
/** The closed reason codes of a record, tolerating any record shape. Never throws. */
export function shadowReasonCodes(record: unknown): readonly string[] {
  try {
    const v = selected(record, ['reasons']);
    if (v === null || !Array.isArray(v.reasons) || v.reasons.length > 128) return Object.freeze([]);
    const codes = (v.reasons as unknown[]).filter((item): item is string => typeof item === 'string');
    return codes.every((code) => (SHADOW_REASON_CODES as readonly string[]).includes(code))
      ? Object.freeze([...new Set(codes)].sort()) : Object.freeze([]);
  } catch { return Object.freeze([]); }
}
export interface ShadowVector {
  readonly id: string;
  readonly tenantRef: string;
  readonly interactionRef: string;
  readonly candidateRef: string;
  readonly deadlineMs: number;
  readonly neighborCount: number;
  readonly contextCount: number;
  readonly candidateKind: ShadowCandidateKind;
}
/** Seeded development vectors: tenant, ref and bounds variation with no held-out or oracle data. */
export function generateShadowVectors(seed = 1, count = 64): readonly ShadowVector[] {
  if (!Number.isSafeInteger(seed) || seed <= 0 || seed > 0xffffffff || !Number.isSafeInteger(count) ||
    count < 0 || count > 512) throw new TypeError('Invalid shadow vector request');
  let state = seed >>> 0;
  const next = (): number => {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    return state >>> 0;
  };
  const result: ShadowVector[] = [];
  for (let index = 0; index < count; index++) {
    const ordinal = next() % 97;
    result.push(Object.freeze({
      id: `shadow-vector-${String(index).padStart(3, '0')}`,
      tenantRef: `tenant-${ordinal}.invalid`,
      interactionRef: `interaction-${ordinal}-${index}.invalid`,
      candidateRef: `candidate-${ordinal}-${next() % 53}.invalid`,
      deadlineMs: 1 + next() % 250,
      neighborCount: next() % (SHADOW_MAX_NEIGHBORS + 1),
      contextCount: next() % (SHADOW_MAX_CONTEXT_ENTRIES + 1),
      candidateKind: SHADOW_CANDIDATE_KINDS[next() % SHADOW_CANDIDATE_KINDS.length]!,
    }));
  }
  return Object.freeze(result);
}
