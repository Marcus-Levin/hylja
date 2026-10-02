/**
 * #27 bounded OFFLINE champion/challenger replay and shadow comparison substrate.
 *
 * This module compares two independently provided deterministic evaluators over locally generated,
 * obviously synthetic development cases and reports what it observed: explicit privacy-marker
 * outcomes, utility-expectation outcomes, latency and errors, cost as explicitly unmeasured, and a
 * human-review recommendation. It is **development evidence, not a release gate**.
 *
 * What it is not, by construction:
 * - it never promotes, replaces, rolls back or releases a bundle, and it writes no registry entry;
 *   `promotion.state` is always `UNAVAILABLE` with the external gates enumerated as fixed codes;
 * - it never executes a candidate package, model or hosted transport: the two evaluators are
 *   in-process functions supplied by the trusted caller, and this module imports no network,
 *   process-spawning or dynamic-evaluation API;
 * - it never turns a fixture expectation, an annotation, an evaluator self-report or a caller flag
 *   into authority. Privacy and utility outcomes are computed from harness-owned observations;
 * - it never holds a production registry pin, performs held-out scoring or grants authenticated
 *   rights, so `productionEligibility` is always `UNAVAILABLE`;
 * - it reads no held-out or blind case (only `DEVELOPMENT_FAMILY_IDS` families are accepted), and it
 *   exposes no bulk mapping lookup, no protected original and no candidate value in any record.
 *
 * Privacy outcome is the harness's own observation of the emission it was handed: the planted
 * synthetic marker is derived here from the case key, the declared expectation is *verified* against
 * the case text, and the containment scan runs through intrinsics captured at module load, so a
 * permissive evaluator that releases the marker is recorded as `MARKER_EMITTED` no matter what it
 * claims and no assignment inside `evaluate` can rewire that judgement. Replacing one of the
 * observed intrinsics is reported as `HARNESS_INTRINSIC_TAMPERED` rather than absorbed. A realm that
 * was already mutated before this module was loaded cannot be seen by identity comparison, so every
 * captured primitive is also asked one known answer once at load: if the realm cannot answer them,
 * this module refuses to compare anything and returns `HARNESS_REALM_UNTRUSTED`. Unknown,
 * malformed, missing, foreign-tenant, stale-digest, timed-out and cancelled work stays an explicit
 * `UNKNOWN`/`REJECTED` result; it is never counted as a denial and never silently falls back to the
 * champion. `runChampionReplay` never throws and never rejects, including for a cancellation signal
 * whose own accessors or listeners throw.
 *
 * Records bind only minted ordinal case references, keyed scope pseudonyms, the pinned bundle
 * reference and closed reason codes, so no raw case text, emission, exception message or provider
 * string can reach a report. See docs/contracts/champion-replay-contract.md.
 */
import { createHash, createHmac } from 'node:crypto';
import { DEVELOPMENT_FAMILY_IDS } from './evaluation-partitions.js';
import { canonicalJson } from './canonical-json.js';

export const REPLAY_VERSION = 'hylja.replay-shadow.v1' as const;

/* -------------------------------------------------------------------------------------- bounds */

export const REPLAY_MAX_CASES = 128;
export const REPLAY_MAX_CASE_BYTES = 8 << 10;
export const REPLAY_MAX_EMISSION_BYTES = 8 << 10;
export const REPLAY_MAX_TASK_ANSWER_CHARS = 512;
export const REPLAY_MIN_DEADLINE_MS = 1;
export const REPLAY_MAX_DEADLINE_MS = 5_000;
export const REPLAY_DEFAULT_DEADLINE_MS = 1_000;
/** Whole-run wall-clock cap; a case that would exceed it becomes an explicit unknown. */
export const REPLAY_MAX_RUN_MS = 30_000;
export const REPLAY_MAX_DISAGREEMENTS = 64;
export const REPLAY_MAX_ANNOTATIONS = REPLAY_MAX_CASES;
export const REPLAY_MAX_RECORDS = REPLAY_MAX_CASES * 2;
/** Nodes the freeze may visit per record at the maximum corpus size; measured shape is ~22. */
export const REPLAY_MAX_FREEZE_NODES_PER_RECORD = 24;
/** Aggregate allowance on top of the record budget, for the run, sides, disagreements and reasons. */
export const REPLAY_MAX_FREEZE_AGGREGATE_NODES = 1024;
export const REPLAY_MAX_FREEZE_NODES =
  REPLAY_MAX_RECORDS * REPLAY_MAX_FREEZE_NODES_PER_RECORD + REPLAY_MAX_FREEZE_AGGREGATE_NODES;
export const REPLAY_RUN_KEY_BYTES = 32;
export const REPLAY_MAX_OBJECT_KEYS = 64;
export const REPLAY_MARKER_PREFIX = 'SYNTHETIC-MARKER-';

/* --------------------------------------------------------------------------------- vocabularies */

/** Fixed run order. There is no parallel evaluation harness and no scheduling input. */
export const REPLAY_ROLES = ['CHAMPION', 'CHALLENGER'] as const;
export type ReplayRole = (typeof REPLAY_ROLES)[number];

export const REPLAY_RUN_STATUSES = ['INVALID', 'PARTIAL', 'COMPLETE'] as const;
export type ReplayRunStatus = (typeof REPLAY_RUN_STATUSES)[number];

export const REPLAY_CASE_STATUSES = ['MEASURED', 'UNKNOWN', 'REJECTED'] as const;
export type ReplayCaseStatus = (typeof REPLAY_CASE_STATUSES)[number];

export const REPLAY_PRIVACY_OUTCOMES = ['MARKER_WITHHELD', 'MARKER_EMITTED', 'NOT_APPLICABLE', 'UNKNOWN'] as const;
export type ReplayPrivacyOutcome = (typeof REPLAY_PRIVACY_OUTCOMES)[number];

export const REPLAY_UTILITY_OUTCOMES = ['MATCH', 'MISMATCH', 'UNKNOWN'] as const;
export type ReplayUtilityOutcome = (typeof REPLAY_UTILITY_OUTCOMES)[number];

/** What an evaluator says happened. Recorded as a claim; never the measured outcome. */
export const REPLAY_EVALUATOR_CLAIMS = ['MARKER_WITHHELD', 'MARKER_RELEASED', 'NO_MARKER_PRESENT', 'UNKNOWN'] as const;
export type ReplayEvaluatorClaim = (typeof REPLAY_EVALUATOR_CLAIMS)[number];

export const REPLAY_ANNOTATION_VERDICTS = ['AGREED', 'DISAGREED', 'UNRESOLVED'] as const;
export type ReplayAnnotationVerdict = (typeof REPLAY_ANNOTATION_VERDICTS)[number];

export const REPLAY_ANNOTATION_SOURCES = ['PROPOSED', 'MANUAL'] as const;
export type ReplayAnnotationSource = (typeof REPLAY_ANNOTATION_SOURCES)[number];

export const REPLAY_REVIEW_RECOMMENDATIONS = ['HUMAN_REVIEW_RECOMMENDED', 'NO_FINDING_IN_THIS_SUBSET'] as const;
export type ReplayReviewRecommendation = (typeof REPLAY_REVIEW_RECOMMENDATIONS)[number];

/** Every reason a record, a side summary or a run can carry. Nothing else is ever recorded. */
/** How the optional annotation evidence for a case resolved. Never an outcome, never authority. */
export const REPLAY_ANNOTATION_STATES = ['NONE', 'AGREED', 'DISAGREED', 'UNRESOLVED', 'CONFLICT', 'INVALID'] as const;
export type ReplayAnnotationState = (typeof REPLAY_ANNOTATION_STATES)[number];

export const REPLAY_REASON_CODES = [
  'ANNOTATION_CASE_UNKNOWN',
  'ANNOTATION_CONFLICT',
  'ANNOTATION_DISAGREEMENT',
  'ANNOTATION_INVALID',
  'ANNOTATION_UNRESOLVED',
  'BUNDLE_CONTENT_PIN_MISMATCH',
  'BUNDLE_PIN_MISMATCH',
  'BUNDLE_REFERENCE_INVALID',
  'CANCELLED',
  'CASE_COUNT_EXCEEDED',
  'CASE_FAMILY_NOT_DEVELOPMENT',
  'CASE_KEY_DUPLICATE',
  'CASE_MARKER_EXPECTATION_MISMATCH',
  'CASE_REJECTED',
  'CASE_SPEC_INVALID',
  'CASE_TEXT_INVALID',
  'CASE_TEXT_TOO_LARGE',
  'CASE_UNKNOWN',
  'DEADLINE_EXCEEDED',
  'DISAGREEMENTS_TRUNCATED',
  'EMISSION_TOO_LARGE',
  'EVALUATOR_CLAIM_MISMATCH',
  'EVALUATOR_ERROR',
  'EVALUATOR_RESULT_MALFORMED',
  'FOREIGN_TENANT_SCOPE',
  'HARNESS_INTRINSIC_TAMPERED',
  'HARNESS_REALM_UNTRUSTED',
  'INVALID_OPTIONS',
  'INVALID_SPEC',
  'MARKER_EMITTED_OBSERVED',
  'RUN_BUDGET_EXCEEDED',
  'TASK_ANSWER_TOO_LARGE',
  'UTILITY_MISMATCH_OBSERVED',
] as const;
export type ReplayReasonCode = (typeof REPLAY_REASON_CODES)[number];

/** The external gates this substrate can never satisfy, recorded on every report. */
export const REPLAY_PROMOTION_GATES = [
  'AUTHENTICATED_PRODUCTION_REGISTRY_REQUIRED',
  'HUMAN_APPROVAL_REQUIRED',
  'HELD_OUT_SCORING_REQUIRED',
  'INDEPENDENT_BUNDLE_INTEGRITY_REQUIRED',
  'PRODUCTION_EGRESS_EVIDENCE_REQUIRED',
] as const;
export type ReplayPromotionGate = (typeof REPLAY_PROMOTION_GATES)[number];

/** Thrown only for a malformed caller input; never for an evaluator, deadline or annotation fault. */
export class ReplayInputError extends Error {
  constructor(readonly code: ReplayReasonCode) {
    // A fixed code: the offending value, path and message never appear.
    super(`champion replay rejected (${code})`);
    this.name = 'ReplayInputError';
  }
}

/* --------------------------------------------------------------------------------------- types */

export interface ReplayBundleRef {
  readonly id: string;
  readonly version: string;
  /** Independently pinned SHA-256 of the exact bundle content, from a trusted control plane. */
  readonly digest: string;
}

export interface ReplayScope {
  readonly tenantId: string;
  readonly projectId?: string;
}

export interface ReplayTrustContext {
  readonly version: 1;
  readonly scope: ReplayScope;
  readonly runId: string;
  /** Per-run HMAC key. Trusted input: never from a corpus, an evaluator or a report. */
  readonly runKey: Uint8Array;
  readonly pins: { readonly champion: ReplayBundleRef; readonly challenger: ReplayBundleRef };
}

export interface ReplayCase {
  readonly version: 1;
  /** Authoring key. It reaches no record; the harness mints ordinal references instead. */
  readonly caseKey: string;
  readonly family: string;
  readonly scope: ReplayScope;
  readonly text: string;
  /** Fixture expectation only: not runtime authority, and never a pass criterion on its own. */
  readonly marker: { readonly expectation: 'DENY' | 'NONE' };
  readonly task: { readonly prompt: string; readonly expectedAnswer: string };
}

/** Everything an evaluator may see: no expectation, no pins, no other side, no report. */
export interface ReplayCaseView {
  readonly caseRef: string;
  readonly family: string;
  readonly text: string;
  readonly task: Readonly<{ prompt: string }>;
}

export interface ReplayEvaluatorResult {
  readonly version: 1;
  readonly claim: ReplayEvaluatorClaim;
  /** Exactly what this evaluator would hand onward, bounded and synthetic. */
  readonly emission: string;
  readonly taskAnswer?: string;
}

export interface ReplayEvaluator {
  readonly bundle: ReplayBundleRef;
  evaluate(view: ReplayCaseView): ReplayEvaluatorResult | Promise<ReplayEvaluatorResult>;
}

/** Optional #67-style provenance-bearing input. Advisory only; never a label of record. */
export interface ReplayAnnotation {
  readonly version: 1;
  readonly caseKey: string;
  readonly verdict: ReplayAnnotationVerdict;
  readonly source: ReplayAnnotationSource;
}

export interface ReplaySpec {
  readonly trusted: ReplayTrustContext;
  readonly cases: readonly ReplayCase[];
  readonly champion: ReplayEvaluator;
  readonly challenger: ReplayEvaluator;
  readonly annotations?: readonly ReplayAnnotation[];
}

export interface ReplayOptions {
  readonly deadlineMs?: number;
  readonly signal?: AbortSignal;
}

export interface ReplayAuditRecord {
  readonly version: 1;
  readonly runRef: string;
  readonly caseRef: string;
  readonly casePseudonym: string;
  readonly role: ReplayRole;
  readonly scopePseudonym: Readonly<{ tenant: string; project?: string }>;
  readonly bundle: ReplayBundleRef;
  readonly status: ReplayCaseStatus;
  readonly annotation: ReplayAnnotationState;
  readonly privacy: ReplayPrivacyOutcome;
  readonly privacyClaim: ReplayEvaluatorClaim;
  readonly utility: ReplayUtilityOutcome;
  readonly reasons: readonly ReplayReasonCode[];
  /** Harness-measured wall clock for this case and side. An observation, never a budget verdict. */
  readonly elapsedMs: number;
  readonly digest: string;
}

export interface ReplaySideSummary {
  readonly role: ReplayRole;
  readonly bundle: ReplayBundleRef;
  readonly pinState: 'PINNED' | 'MISMATCHED' | 'UNAVAILABLE';
  readonly cases: Readonly<{ total: number; measured: number; unknown: number; rejected: number }>;
  readonly privacy: Readonly<{ withheld: number; emitted: number; notApplicable: number; unknown: number }>;
  readonly utility: Readonly<{ match: number; mismatch: number; unknown: number }>;
  readonly errors: number;
  readonly latencyMs: Readonly<{ total: number; max: number }>;
  readonly cost: Readonly<{ state: 'UNMEASURED'; reason: 'OFFLINE_NO_COST_SIGNAL' }>;
  readonly review: Readonly<{
    recommendation: ReplayReviewRecommendation;
    authority: 'NONE';
    reasons: readonly ReplayReasonCode[];
  }>;
}

export interface ReplayDisagreement {
  readonly caseRef: string;
  readonly field: 'PRIVACY' | 'UTILITY';
  readonly champion: string;
  readonly challenger: string;
}

export interface ReplayReport {
  readonly version: 1;
  readonly status: ReplayRunStatus;
  readonly run: Readonly<{
    runRef: string;
    scopePseudonym: Readonly<{ tenant: string; project?: string }>;
    corpusRef: string;
    cases: number;
    annotations: Readonly<{
      provided: number; agreed: number; disagreed: number; unresolved: number;
      conflicting: number; rejected: number; authority: 'NONE';
    }>;
  }>;
  readonly sides: Readonly<Record<ReplayRole, ReplaySideSummary>>;
  readonly disagreements: readonly ReplayDisagreement[];
  readonly shadow: Readonly<{
    mode: 'OFFLINE_DEVELOPMENT'; execution: 'IN_PROCESS'; hostedTransport: 'NONE';
    candidateExecution: 'NONE'; authority: 'NONE';
  }>;
  readonly promotion: Readonly<{
    state: 'UNAVAILABLE'; authority: 'NONE'; gates: readonly ReplayPromotionGate[];
  }>;
  readonly productionEligibility: Readonly<{ state: 'UNAVAILABLE'; authority: 'NONE' }>;
  readonly records: readonly ReplayAuditRecord[];
  readonly reasons: readonly ReplayReasonCode[];
}

/* ------------------------------------------------------------- captured intrinsics */

/**
 * The evaluated function runs between both sides of every measurement, and a JavaScript process has
 * mutable built-ins, so every prototype method and static this module calls is captured once, here,
 * at module load, and called through a wrapper below. ES module evaluation happens before any
 * caller's module body can run, so an `evaluate` handed to this module cannot have influenced any
 * of these references.
 *
 * The captured set is deliberately the *complete* call closure of this module, not a selection:
 * anything left live could turn a refusal into a silent acceptance (an unknown key admitted, an
 * opaque token or a malformed digest accepted, a released marker recorded without its reason) or
 * fabricate a run-level reason code. `intrinsicsIntact()` compares every entry of `OBSERVED_INTRINSICS`
 * with its live counterpart at each case boundary and once before the corpus is read, and a
 * replacement is recorded as `HARNESS_INTRINSIC_TAMPERED`.
 *
 * This is evidence integrity, not sandboxing. An in-process evaluator can still corrupt the host
 * process: globals this module does not call, the shared canonical-JSON helper's own internals (so
 * a record digest is not tamper-proof), timers and memory. The trusted caller is responsible for
 * what code it passes; see the contract.
 */
const applyFn = Reflect.apply;
const ownKeysFn = Reflect.ownKeys;
const getOwnPropertyDescriptorFn = Object.getOwnPropertyDescriptor;
const getPrototypeOfFn = Object.getPrototypeOf;
const hasOwnFn = Object.hasOwn;
const objectKeysFn = Object.keys;
const objectCreateFn = Object.create;
const objectFreezeFn = Object.freeze;
const isArrayFn = Array.isArray;
const arrayIncludesFn = Array.prototype.includes;
const arraySomeFn = Array.prototype.some;
const arrayPushFn = Array.prototype.push;
const arrayMapFn = Array.prototype.map;
const arrayFilterFn = Array.prototype.filter;
const arrayEveryFn = Array.prototype.every;
const arrayFlatMapFn = Array.prototype.flatMap;
const arraySortFn = Array.prototype.sort;
const stringCodeUnitFn = String.prototype.charCodeAt;
const stringRepeatFn = String.prototype.repeat;
const stringSliceFn = String.prototype.slice;
const promiseThenFn = Promise.prototype.then;
const promiseCatchFn = Promise.prototype.catch;
const promiseResolveFn = Promise.resolve;
/** `Promise.resolve` is a static method that uses `this`, so it is applied to its own constructor. */
const promiseCtorFn = Promise;
const stringCtorFn = String;
const isSafeIntegerFn = Number.isSafeInteger;
const numberToStringFn = Number.prototype.toString;
const mathFloorFn = Math.floor;
const mathMaxFn = Math.max;
const dateNowFn = Date.now;
const setTimeoutFn = setTimeout;
const clearTimeoutFn = clearTimeout;

/** Captured aliases. Each is called through `apply`, so no `this` lookup happens at the call site. */
function hasValue(values: readonly unknown[], needle: unknown): boolean {
  return applyFn(arrayIncludesFn, values, [needle]) as boolean;
}

/**
 * Membership by `===` alone, with no prototype method at all. The reason vocabulary, the closed
 * vocabularies and the case-key reservation use this, so a mutated membership check can neither empty
 * a reason list nor turn every case into a duplicate.
 */
function scanIndex(values: readonly string[], needle: string): number {
  for (let index = 0; index < values.length; index += 1) if (values[index] === needle) return index;
  return -1;
}

/**
 * Decimal index keys without `String` and without a prototype method: the bounded array reader reaches
 * an element descriptor through a key this builds, so it never coerces through a mutable global.
 */
const DECIMAL_DIGITS: readonly string[] = freezeValue(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']);
function decimalKey(index: number): string {
  if (index < 10) return DECIMAL_DIGITS[index] as string;
  if (index < 100) {
    const tens = mathFloorFn(index / 10);
    return `${DECIMAL_DIGITS[tens] as string}${DECIMAL_DIGITS[index - tens * 10] as string}`;
  }
  // Three digits: the remainder keeps its own tens digit, so 101 is "101" and not "11".
  const hundreds = mathFloorFn(index / 100);
  const remainder = index - hundreds * 100;
  const tens = mathFloorFn(remainder / 10);
  return `${DECIMAL_DIGITS[hundreds] as string}${DECIMAL_DIGITS[tens] as string}${
    DECIMAL_DIGITS[remainder - tens * 10] as string}`;
}
function anyValue<T>(values: readonly T[], predicate: (value: T, index: number) => boolean): boolean {
  return applyFn(arraySomeFn, values, [predicate]) as boolean;
}
function addValue<T>(values: T[], item: T): number {
  return applyFn(arrayPushFn, values, [item]) as number;
}
function mapValues<T, U>(values: readonly T[], convert: (value: T, index: number) => U): U[] {
  return applyFn(arrayMapFn, values, [convert]) as U[];
}
function selectValues<T>(values: readonly T[], predicate: (value: T, index: number) => boolean): T[] {
  return applyFn(arrayFilterFn, values, [predicate]) as T[];
}
function allValues<T>(values: readonly T[], predicate: (value: T, index: number) => boolean): boolean {
  return applyFn(arrayEveryFn, values, [predicate]) as boolean;
}
function flatMapValues<T, U>(values: readonly T[], convert: (value: T, index: number) => U[]): U[] {
  return applyFn(arrayFlatMapFn, values, [convert]) as U[];
}
function sortValues(values: string[]): string[] {
  applyFn(arraySortFn, values, [undefined]);
  return values;
}
/** One UTF-16 code unit of `text`, obtained through the two captured intrinsics only. */
function unitAt(text: string, index: number): number {
  return applyFn(stringCodeUnitFn, text, [index]) as number;
}
function repeatChar(character: string, count: number): string {
  return applyFn(stringRepeatFn, character, [count]) as string;
}
function sliceText(value: string, start: number, end: number): string {
  return applyFn(stringSliceFn, value, [start, end]) as string;
}
function freezeValue<T>(value: T): T {
  return objectFreezeFn(value);
}
function nullObject(): Fields {
  return objectCreateFn(null) as Fields;
}
function hexOf(value: number, radix: number): string {
  return applyFn(numberToStringFn, value, [radix]) as string;
}
/** A deadline that cannot be armed is not a deadline, so the timer functions are captured too. */
function armTimer(callback: () => void, delayMs: number): unknown {
  return applyFn(setTimeoutFn, undefined, [callback, delayMs]);
}
function dropTimer(handle: unknown): void {
  applyFn(clearTimeoutFn, undefined, [handle]);
}
function thenWork<T>(work: Promise<T>, onSettled: (result: BoundedOutcome<T>) => void): void {
  applyFn(promiseThenFn, work, [
    (value: T) => onSettled({ status: 'SETTLED', value }),
    () => onSettled({ status: 'FAILED' }),
  ]);
}
/**
 * Attach a no-op rejection handler so a late rejection cannot become an unhandled rejection, and
 * swallow a refusal to attach it. This runs from promise handlers and timer callbacks, where an
 * exception has no caller to catch it and would end the caller's process.
 */
function ignoreRejection(work: unknown): void {
  try { applyFn(promiseCatchFn, work, [() => undefined]); } catch { /* not thenable: nothing to attach */ }
}

/** Clearing a deadline timer must never throw out of a timer callback either. */
function safeDropTimer(handle: unknown): void {
  try { dropTimer(handle); } catch { /* nothing else can be done from here */ }
}

/** Coerce through the captured constructor, so a non-string argument cannot throw from node:crypto. */
function coerceString(value: unknown): string {
  return applyFn(stringCtorFn, undefined, [value]) as string;
}

function freezeEntry(entry: readonly [string, () => unknown, unknown]): readonly [string, () => unknown, unknown] {
  return objectFreezeFn(entry);
}

/**
 * The identity table. Each entry is `(label, live reader, captured reference)`: the reader performs
 * its lookup at check time, so a replacement made after this module was loaded is what the
 * comparison sees. A mismatch means an intrinsic this module depends on was replaced.
 */
/**
 * The identity table. Each entry is `(label, live reader, captured reference)`: the reader performs
 * the lookup at check time, so a replacement after module load is what the comparison sees. A
 * mismatch means an intrinsic this module depends on was replaced.
 */
const OBSERVED_INTRINSICS: readonly (readonly [string, () => unknown, unknown])[] = freezeValue([
  freezeEntry(['Reflect.apply', () => Reflect.apply, applyFn]),
  freezeEntry(['Reflect.ownKeys', () => Reflect.ownKeys, ownKeysFn]),
  freezeEntry(['Object.getOwnPropertyDescriptor', () => Object.getOwnPropertyDescriptor, getOwnPropertyDescriptorFn]),
  freezeEntry(['Object.getPrototypeOf', () => Object.getPrototypeOf, getPrototypeOfFn]),
  freezeEntry(['Object.hasOwn', () => Object.hasOwn, hasOwnFn]),
  freezeEntry(['Object.keys', () => Object.keys, objectKeysFn]),
  freezeEntry(['Object.create', () => Object.create, objectCreateFn]),
  freezeEntry(['Object.freeze', () => Object.freeze, objectFreezeFn]),
  freezeEntry(['Array.isArray', () => Array.isArray, isArrayFn]),
  freezeEntry(['Array.prototype.includes', () => Array.prototype.includes, arrayIncludesFn]),
  freezeEntry(['Array.prototype.some', () => Array.prototype.some, arraySomeFn]),
  freezeEntry(['Array.prototype.push', () => Array.prototype.push, arrayPushFn]),
  freezeEntry(['Array.prototype.map', () => Array.prototype.map, arrayMapFn]),
  freezeEntry(['Array.prototype.filter', () => Array.prototype.filter, arrayFilterFn]),
  freezeEntry(['Array.prototype.every', () => Array.prototype.every, arrayEveryFn]),
  freezeEntry(['Array.prototype.flatMap', () => Array.prototype.flatMap, arrayFlatMapFn]),
  freezeEntry(['Array.prototype.sort', () => Array.prototype.sort, arraySortFn]),
  freezeEntry(['String.prototype.charCodeAt', () => String.prototype.charCodeAt, stringCodeUnitFn]),
  freezeEntry(['String.prototype.repeat', () => String.prototype.repeat, stringRepeatFn]),
  freezeEntry(['String.prototype.slice', () => String.prototype.slice, stringSliceFn]),
  freezeEntry(['Promise.prototype.then', () => Promise.prototype.then, promiseThenFn]),
  freezeEntry(['Promise.prototype.catch', () => Promise.prototype.catch, promiseCatchFn]),
  freezeEntry(['Promise.resolve', () => Promise.resolve, promiseResolveFn]),
  freezeEntry(['Promise', () => Promise, promiseCtorFn]),
  freezeEntry(['String', () => String, stringCtorFn]),
  freezeEntry(['Number.isSafeInteger', () => Number.isSafeInteger, isSafeIntegerFn]),
  freezeEntry(['Number.prototype.toString', () => Number.prototype.toString, numberToStringFn]),
  freezeEntry(['Math.floor', () => Math.floor, mathFloorFn]),
  freezeEntry(['Math.max', () => Math.max, mathMaxFn]),
  freezeEntry(['Date.now', () => Date.now, dateNowFn]),
  freezeEntry(['setTimeout', () => setTimeout, setTimeoutFn]),
  freezeEntry(['clearTimeout', () => clearTimeout, clearTimeoutFn]),
]);

/** True only while every captured intrinsic is still the one this module loaded. */
function intrinsicsIntact(): boolean {
  for (let index = 0; index < OBSERVED_INTRINSICS.length; index += 1) {
    const entry = OBSERVED_INTRINSICS[index] as readonly [string, () => unknown, unknown];
    if (entry[1]() !== entry[2]) return false;
  }
  return true;
}

/**
 * Load-time known-answer self-test.
 *
 * Identity comparison cannot see a primitive that was already replaced when this module was loaded,
 * which is exactly what a caller's own module body can do before the first `import`. Rather than
 * documenting that as an undetectable hole, every captured primitive is asked one known answer once, at
 * load: if the realm cannot answer them, this module refuses to compare anything and every run returns
 * an explicit `INVALID` report with `HARNESS_REALM_UNTRUSTED` (and the authoring helper refuses the
 * same way). A realm that answers the known answers but is broken in some other way stays outside what
 * this can see, and the contract says so.
 */
function realmSelfCheck(): boolean {
  try {
    const probe = freezeValue<Record<string, number>>({});
    try { probe.added = 1; } catch { /* a strict-mode refusal is the expected outcome here */ }
    // Known answers, listed rather than branched: each entry asks one captured primitive something
    // this module depends on being able to ask it.
    const answered: readonly boolean[] = [
      unitAt('A', 0) === 65,
      unitAt('abc', 2) === 99,
      sliceText('abcdef', 1, 3) === 'bc',
      repeatChar('0', 3) === '000',
      coerceString(7) === '7',
      hasValue(['a', 'b'], 'a') && !hasValue(['a'], 'z'),
      anyValue([1, 2], (value) => value > 1) && !anyValue([1], (value) => value > 1),
      mapValues([1, 2], (value) => value * 2).length === 2,
      selectValues([1, 2], (value) => value > 1).length === 1,
      allValues([1], () => true) && !allValues([1], () => false),
      flatMapValues([1], (value) => [value, value]).length === 2,
      sortValues(['b', 'a', 'c'])[0] === 'a',
      addValue([], 'x') === 1,
      isArrayFn([]) && !isArrayFn({}),
      getPrototypeOfFn({}) === Object.prototype && getPrototypeOfFn(nullObject()) === null,
      hasOwnFn({ a: 1 }, 'a') && !hasOwnFn({}, 'a'),
      objectKeysFn({ a: 1 }).length === 1 && ownKeysFn({ a: 1 }).length === 1,
      getOwnPropertyDescriptorFn({ a: 1 }, 'a')?.value === 1,
      isLowerHexDigest('a'.repeat(64)) && !isLowerHexDigest('nope'),
      isOpaqueToken('hylja.detectors-1') && !isOpaqueToken('not a valid token'),
      scanIndex(['a', 'b'], 'b') === 1 && scanIndex(['a'], 'z') === -1,
      decimalKey(0) === '0' && decimalKey(7) === '7' && decimalKey(9) === '9',
      decimalKey(10) === '10' && decimalKey(42) === '42' && decimalKey(99) === '99',
      decimalKey(100) === '100' && decimalKey(101) === '101' && decimalKey(109) === '109',
      decimalKey(110) === '110' && decimalKey(128) === '128',
      containsText('xxSYNTHETIC-MARKER-abc', 'SYNTHETIC-MARKER-abc') &&
        !containsText('nothing here', 'SYNTHETIC-MARKER-abc'),
      objectKeysFn(probe).length === 0,
      isSafeIntegerFn(1) && !isSafeIntegerFn(1.5),
      mathMaxFn(1, 2) === 2 && mathFloorFn(2.7) === 2,
      dateNowFn() > 1600000000000,
      // Reflect.apply must invoke the captured target with the receiver and arguments this module
      // passes it; the probe ignores its own arguments so it tests apply, not a live method.
      applyFn(() => 42, 'abc', []) === 42,
      // Applied exactly as `observe` applies it: the captured constructor is the receiver.
      applyFn(promiseResolveFn, promiseCtorFn, [null]) !== null,
      typeof promiseThenFn === 'function' && typeof promiseCatchFn === 'function',
      typeof setTimeoutFn === 'function' && typeof clearTimeoutFn === 'function',
    ];
    for (let index = 0; index < answered.length; index += 1) if (answered[index] === false) return false;
    return true;
  } catch {
    // A primitive that cannot even be called is an untrusted realm, not a crash.
    return false;
  }
}

/**
 * Exact substring containment over captured intrinsics only. The marker is ASCII, but the emission
 * is not, so this compares UTF-16 code units. Work is bounded by the emission cap times the marker
 * length (33), and the first-character check skips almost every position.
 */
function containsText(haystack: string, needle: string): boolean {
  const limit = haystack.length - needle.length;
  if (limit < 0) return false;
  const first = unitAt(needle, 0);
  for (let start = 0; start <= limit; start += 1) {
    if (unitAt(haystack, start) !== first) continue;
    let offset = 1;
    while (offset < needle.length && unitAt(haystack, start + offset) === unitAt(needle, offset)) {
      offset += 1;
    }
    if (offset === needle.length) return true;
  }
  return false;
}

/* --------------------------------------------------------------------------------- validation */

type Fields = Record<string, unknown>;

function fail(code: ReplayReasonCode): never {
  throw new ReplayInputError(code);
}

/**
 * Opaque identity, bundle and run labels: no `@`, `/`, `:`, whitespace or free text, and a lowercase
 * 64-character hex digest. Both shapes are scanned by code unit over the captured intrinsic rather than
 * through `RegExp.prototype.test`, so a mutated pattern implementation can neither admit a free-text
 * label into a report nor change whether a digest is a digest.
 */
const MAX_SAFE_TOKEN_LENGTH = 128;

function isDigitUnit(unit: number): boolean {
  return unit >= 0x30 && unit <= 0x39;
}

function isUpperUnit(unit: number): boolean {
  return unit >= 0x41 && unit <= 0x5a;
}

function isLowerUnit(unit: number): boolean {
  return unit >= 0x61 && unit <= 0x7a;
}

function isTokenStart(unit: number): boolean {
  return isDigitUnit(unit) || isUpperUnit(unit) || isLowerUnit(unit);
}

function isTokenTail(unit: number): boolean {
  return isTokenStart(unit) || unit === 0x2e || unit === 0x5f || unit === 0x3d || unit === 0x2d;
}

function isOpaqueToken(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_SAFE_TOKEN_LENGTH) return false;
  if (!isTokenStart(unitAt(value, 0))) return false;
  for (let index = 1; index < value.length; index += 1) {
    if (!isTokenTail(unitAt(value, index))) return false;
  }
  return true;
}

function isLowerHexDigest(value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== 64) return false;
  for (let index = 0; index < 64; index += 1) {
    const unit = unitAt(value, index);
    if (!isDigitUnit(unit) && !(unit >= 0x61 && unit <= 0x66)) return false;
  }
  return true;
}
const PSEUDONYM_DOMAIN = 'hylja.replay-shadow.pseudonym.v1';

/**
 * Own enumerable **data** descriptors only, from one bounded key snapshot, so a Proxy cannot change
 * between reflections and no caller getter runs. Unknown keys are a refusal, never a default.
 */
function fields(value: unknown, required: readonly string[], optional: readonly string[] = [],
  code: ReplayReasonCode = 'INVALID_SPEC'): Fields {
  if (value === null || typeof value !== 'object' || isArrayFn(value) ||
    !hasValue([Object.prototype, null], getPrototypeOfFn(value))) fail(code);
  const keys = ownKeysFn(value);
  if (keys.length > REPLAY_MAX_OBJECT_KEYS || anyValue(keys, (key) => typeof key !== 'string')) fail(code);
  const result = nullObject();
  for (const key of keys as string[]) {
    if (!hasValue(required, key) && !hasValue(optional, key)) fail(code);
    const descriptor = getOwnPropertyDescriptorFn(value, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) fail(code);
    result[key] = descriptor.value;
  }
  for (const name of required) if (!hasOwnFn(result, name)) fail(code);
  return result;
}

function arrayOf(value: unknown, limit: number, code: ReplayReasonCode): unknown[] {
  if (!isArrayFn(value) || getPrototypeOfFn(value) !== Array.prototype) fail(code);
  const keys = ownKeysFn(value);
  if (keys.length > limit + 1 || anyValue(keys, (key) => typeof key !== 'string')) fail(code);
  const length = value.length;
  if (length > limit) fail(code);
  const items: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = getOwnPropertyDescriptorFn(value, decimalKey(index));
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) fail(code);
    addValue(items, descriptor.value);
  }
  return items;
}

function member<T extends string>(value: unknown, choices: readonly T[], code: ReplayReasonCode): T {
  if (typeof value !== 'string' || scanIndex(choices, value) < 0) fail(code);
  return value as T;
}

function token(value: unknown, code: ReplayReasonCode): string {
  if (!isOpaqueToken(value)) fail(code);
  return value;
}

function integer(value: unknown, min: number, max: number, code: ReplayReasonCode): number {
  if (typeof value !== 'number' || !isSafeIntegerFn(value) || value < min || value > max) fail(code);
  return value;
}

/** Bounded UTF-8 measurement; returns `cap + 1` as soon as the value is over the cap. */
function utf8Length(text: string, cap: number): number {
  let total = 0;
  for (let index = 0; index < text.length; index += 1) {
    const unit = unitAt(text, index);
    if (unit < 0x80) total += 1;
    else if (unit < 0x800) total += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff) { total += 4; index += 1; }
    else total += 3;
    if (total > cap) return cap + 1;
  }
  return total;
}

/**
 * True only for a bounded string of Unicode scalar values, so a marker search and a record can never
 * disagree. `allowEmpty` is for evaluator output: an empty emission is a withheld marker and an
 * empty answer is an ordinary utility mismatch, not a malformed result.
 */
function isText(value: unknown, maxChars: number, allowEmpty = false): value is string {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0) || value.length > maxChars) return false;
  for (let index = 0; index < value.length; index += 1) {
    const unit = unitAt(value, index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = index + 1 < value.length ? unitAt(value, index + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function readScope(value: unknown, code: ReplayReasonCode): ReplayScope {
  const v = fields(value, ['tenantId'], ['projectId'], code);
  const tenantId = token(v.tenantId, code);
  return hasOwnFn(v, 'projectId')
    ? { tenantId, projectId: token(v.projectId, code) }
    : { tenantId };
}

function sameScope(left: ReplayScope, right: ReplayScope): boolean {
  return left.tenantId === right.tenantId && left.projectId === right.projectId;
}

function readBundleRef(value: unknown, code: ReplayReasonCode): ReplayBundleRef {
  const v = fields(value, ['id', 'version', 'digest'], [], code);
  const id = token(v.id, code);
  const version = token(v.version, code);
  if (!isLowerHexDigest(v.digest)) fail(code);
  return { id, version, digest: v.digest };
}

function sameBundle(left: ReplayBundleRef, right: ReplayBundleRef): boolean {
  return left.id === right.id && left.version === right.version && left.digest === right.digest;
}

/** Scope- and run-keyed, truncated pseudonym. Not a credential, not a bearer token, not authority. */
function pseudonym(runKey: Uint8Array, parts: readonly (string | number)[]): string {
  const bytes = canonicalJson([PSEUDONYM_DOMAIN, ...parts]);
  return sliceText(createHmac('sha256', runKey).update(bytes).digest('hex'), 0, 32);
}

function recordDigest(runKey: Uint8Array, body: Fields): string {
  return createHmac('sha256', runKey).update(canonicalJson(body)).digest('hex');
}

/**
 * The reason vocabulary: de-duplicated and sorted with **no** array method at all. This is the one
 * place that must survive a broken realm, because it is what every refusal, record and side summary
 * is written in: a captured `push` that cannot append must never be able to empty it.
 */
function codes(values: Iterable<ReplayReasonCode>): ReplayReasonCode[] {
  const unique: string[] = [];
  let length = 0;
  for (const value of values) {
    let present = false;
    for (let index = 0; index < length; index += 1) {
      if (unique[index] === value) { present = true; break; }
    }
    if (present) continue;
    unique[length] = value;
    length += 1;
  }
  unique.length = length;
  if (length > 1) sortValues(unique);
  return unique as ReplayReasonCode[];
}

/**
 * Freeze a report this module built, so a consumer cannot post-edit a record, a summary or the
 * promotion surface it just read.
 *
 * The node budget is derived from the largest report the bounds can produce -- 256 records at
 * `REPLAY_MAX_FREEZE_NODES_PER_RECORD` nodes each, plus the aggregates -- so it cannot be exhausted
 * at any accepted corpus size, and a test at the documented maximum asserts that every record is
 * frozen. `freezeReport` also freezes `records` first, so even an exhausted budget could never reach
 * a headline field. Only arrays and plain objects are visited, by index: no iterator protocol.
 */
function deepFreeze<T>(value: T, depth = 0, budget = { nodes: 0 }): T {
  budget.nodes += 1;
  if (depth > 4 || budget.nodes > REPLAY_MAX_FREEZE_NODES ||
    value === null || typeof value !== 'object') return value;
  if (isArrayFn(value)) {
    for (let index = 0; index < (value as readonly unknown[]).length; index += 1) {
      deepFreeze((value as readonly unknown[])[index], depth + 1, budget);
    }
  } else if (getPrototypeOfFn(value) === Object.prototype || getPrototypeOfFn(value) === null) {
    const record = value as Record<string, unknown>;
    const keys = objectKeysFn(record);
    for (let index = 0; index < keys.length; index += 1) deepFreeze(record[keys[index] as string], depth + 1, budget);
  }
  return freezeValue(value);
}

/* ------------------------------------------------------- synthetic development corpus (local) */

/**
 * The substrate's own marker derivation. A `DENY` case must actually contain this string, so a
 * planted marker is a harness verification rather than a fixture claim, and the same case key
 * always derives the same obviously synthetic, non-routable marker.
 */
export function replayMarkerFor(caseKey: string): string {
  // The argument is coerced through the captured constructor: a JavaScript caller passing a
  // non-string gets this module's marker for its string form, not a TypeError from node:crypto.
  return `${REPLAY_MARKER_PREFIX}${sliceText(createHash('sha256').update(coerceString(caseKey)).digest('hex'), 0, 16)}`;
}

/**
 * Obviously synthetic, non-routable templates: `.invalid`/`example.invalid` names and the
 * documentation range 192.0.2.0/24 only. Nothing here is derived from real traffic or a held-out
 * case, and a marker only ever appears where the substrate itself derived it.
 */
const TEXT_TEMPLATES: readonly ((marker: string, ordinal: number) => string)[] = freezeValue([
  (marker, n) => `contact ${marker}@replay.example.invalid about site plant-synthetic.example.invalid ref ${n}`,
  (marker, n) => `2026-01-0${(n % 9) + 1}T00:00:00Z level=info actor=${marker} host=node-synthetic.example.invalid`,
  (marker) => `{"actor":"${marker}","site":"plant-synthetic.example.invalid","port":8443}`,
  (marker) => `actor: ${marker}\nsite: plant-synthetic.example.invalid`,
  (marker) => `actor = "${marker}"\nsite = "plant-synthetic.example.invalid"`,
  (marker) => `[audit]\nactor=${marker}\nsite=plant-synthetic.example.invalid`,
  (marker) => `SYNTHETIC_ACTOR=${marker}\nSYNTHETIC_SITE=plant-synthetic.example.invalid`,
  (marker) => `https://replay.example.invalid/report?actor=${marker}&site=plant-synthetic.example.invalid`,
  (marker) => `host=node-synthetic.example.invalid;user=${marker};db=replay`,
  (marker) => `<audit actor="${marker}"><site>plant-synthetic.example.invalid</site></audit>`,
  (marker) => `replay-cli --actor ${marker} --site plant-synthetic.example.invalid`,
  (marker, n) => `from 192.0.2.${(n % 254) + 1} path /var/synthetic/replay/${marker}.txt`,
]);

function controlText(family: string, ordinal: number): string {
  return `routine ${family} status note ${ordinal} for plant-synthetic.example.invalid`;
}

/**
 * Author locally generated, obviously synthetic development cases. This is a development authoring
 * aid: it reads no corpus, no held-out payload and no blind seed, and it throws a typed
 * `ReplayInputError` for a malformed request rather than returning a partial corpus.
 */
export function generateSyntheticReplayCorpus(spec: unknown): ReplayCase[] {
  if (!REALM_TRUSTED) fail('HARNESS_REALM_UNTRUSTED');
  const v = fields(spec, ['version', 'scope', 'count', 'seed']);
  if (v.version !== 1) fail('INVALID_SPEC');
  const scope = readScope(v.scope, 'INVALID_SPEC');
  const count = integer(v.count, 1, REPLAY_MAX_CASES, 'INVALID_SPEC');
  const seed = integer(v.seed, 0, 0xffffffff, 'INVALID_SPEC');
  const cases: ReplayCase[] = [];
  for (let index = 1; index <= count; index += 1) {
    const family = DEVELOPMENT_FAMILY_IDS[(seed + index) % DEVELOPMENT_FAMILY_IDS.length] as string;
    const caseKey = `dev-${hexOf(seed, 16)}-${index}`;
    const planted = index % 3 !== 0;
    addValue(cases, {
      version: 1,
      caseKey,
      family,
      scope,
      text: planted
        ? (TEXT_TEMPLATES[(seed + index) % TEXT_TEMPLATES.length] as (
          marker: string, ordinal: number) => string)(replayMarkerFor(caseKey), index)
        : controlText(family, index),
      marker: { expectation: planted ? 'DENY' : 'NONE' },
      task: { prompt: `REPLAY-TASK-${index}-${family}`, expectedAnswer: `REPLAY-ANSWER-${index}-${family}` },
    });
  }
  return cases;
}

/* ----------------------------------------------------------------------------- run preparation */

interface PreparedCase {
  readonly caseRef: string;
  /**
   * Authoring key, held in this process only: it never reaches a record or a digest. It is `null`
   * when the supplied case was too malformed to yield one, and annotation evidence never attaches
   * to a case that has no usable key.
   */
  readonly caseKey: string | null;
  readonly pseudonym: string;
  readonly family: string;
  readonly text: string;
  readonly prompt: string;
  readonly expectedAnswer: string;
  readonly markerExpectation: 'DENY' | 'NONE';
  readonly marker: string;
  readonly annotation: ReplayAnnotationState;
  readonly reasons: readonly ReplayReasonCode[];
  readonly rejected: boolean;
}

interface PreparedSide {
  readonly bundle: ReplayBundleRef;
  readonly evaluate: (view: ReplayCaseView) => unknown;
  readonly pinState: 'PINNED' | 'MISMATCHED';
  /** Set when the declared bundle does not equal the independently pinned reference. */
  readonly pinReason: ReplayReasonCode | null;
}

interface PreparedRun {
  readonly scope: ReplayScope;
  readonly scopePseudonym: { readonly tenant: string; readonly project?: string };
  readonly runKey: Uint8Array;
  readonly runRef: string;
  readonly sides: Readonly<Record<ReplayRole, PreparedSide>>;
  readonly cases: readonly PreparedCase[];
  readonly corpusRef: string;
  readonly annotations: ReplayReport['run']['annotations'];
}

function readCase(value: unknown, scope: ReplayScope, caseRef: string, seen: string[]): PreparedCase {
  const reasons: ReplayReasonCode[] = [];
  const reject = (code: ReplayReasonCode): PreparedCase => {
    addValue(reasons, code);
    return {
      caseRef, caseKey: null, pseudonym: '', family: '', text: '', prompt: '', expectedAnswer: '',
      markerExpectation: 'NONE', marker: '', annotation: 'NONE', reasons: codes(reasons), rejected: true,
    };
  };
  let v: Fields;
  let caseKey: string;
  let family: string;
  let caseScope: ReplayScope;
  let text: string;
  let expectation: 'DENY' | 'NONE';
  let task: Fields;
  try {
    v = fields(value, ['version', 'caseKey', 'family', 'scope', 'text', 'marker', 'task'], [],
      'CASE_SPEC_INVALID');
    if (v.version !== 1 || !isText(v.caseKey, 256)) return reject('CASE_SPEC_INVALID');
    caseKey = v.caseKey;
    // The first occurrence of a key reserves it whatever its own validity turns out to be, so
    // "first wins" cannot be turned around by the later copy's shape.
    if (scanIndex(seen, caseKey) >= 0) return reject('CASE_KEY_DUPLICATE');
    addValue(seen, caseKey);
    if (typeof v.family !== 'string' || scanIndex(DEVELOPMENT_FAMILY_IDS as readonly string[], v.family) < 0) {
      return reject('CASE_FAMILY_NOT_DEVELOPMENT');
    }
    family = v.family;
    caseScope = readScope(v.scope, 'CASE_SPEC_INVALID');
    if (!isText(v.text, REPLAY_MAX_CASE_BYTES * 2)) return reject('CASE_TEXT_INVALID');
    if (utf8Length(v.text, REPLAY_MAX_CASE_BYTES) > REPLAY_MAX_CASE_BYTES) return reject('CASE_TEXT_TOO_LARGE');
    text = v.text;
    expectation = member(fields(v.marker, ['expectation'], [], 'CASE_SPEC_INVALID').expectation,
      ['DENY', 'NONE'] as const, 'CASE_SPEC_INVALID');
    task = fields(v.task, ['prompt', 'expectedAnswer'], [], 'CASE_SPEC_INVALID');
    if (!isText(task.prompt, REPLAY_MAX_TASK_ANSWER_CHARS) || !isText(task.expectedAnswer, REPLAY_MAX_TASK_ANSWER_CHARS)) {
      return reject('CASE_SPEC_INVALID');
    }
  } catch (error) {
    return reject(error instanceof ReplayInputError ? error.code : 'CASE_SPEC_INVALID');
  }
  if (!sameScope(caseScope, scope)) return reject('FOREIGN_TENANT_SCOPE');
  // The declared expectation is verified, never believed: the derived marker must be present for a
  // `DENY` case and absent for a `NONE` one, so a label cannot switch privacy measurement off.
  const marker = replayMarkerFor(caseKey);
  const planted = containsText(text, marker);
  if (planted !== (expectation === 'DENY')) return reject('CASE_MARKER_EXPECTATION_MISMATCH');
  return {
    caseRef,
    caseKey,
    pseudonym: '',
    family,
    text,
    prompt: task.prompt as string,
    expectedAnswer: task.expectedAnswer as string,
    markerExpectation: expectation,
    marker: expectation === 'DENY' ? marker : '',
    annotation: 'NONE',
    reasons: [],
    rejected: false,
  };
}

function readAnnotations(value: unknown, cases: readonly PreparedCase[]): {
  entries: Record<string, ReplayAnnotationState[]>;
  summary: ReplayReport['run']['annotations'];
} {
  const items = arrayOf(value, REPLAY_MAX_ANNOTATIONS, 'INVALID_SPEC');
  // Plain arrays through the captured membership check: no Set or Map prototype in this module.
  const caseKeys = selectValues(mapValues(cases, (entry) => entry.caseKey), (key) => key !== null) as string[];
  const states = nullObject() as Record<string, ReplayAnnotationState[]>;
  const append = (key: string, state: ReplayAnnotationState): void => {
    const existing = states[key];
    if (existing !== undefined) { addValue(existing, state); return; }
    const created: ReplayAnnotationState[] = [];
    addValue(created, state);
    states[key] = created;
  };
  const tally: Record<'AGREED' | 'DISAGREED' | 'UNRESOLVED', number> = { AGREED: 0, DISAGREED: 0, UNRESOLVED: 0 };
  let rejected = 0;
  let conflicting = 0;
  for (const item of items) {
    // The case key is read on its own first, so evidence that is malformed for any other reason
    // is still attributed to its case as `INVALID` instead of looking like no evidence at all.
    let caseKey = '';
    try {
      const descriptor = item !== null && typeof item === 'object' && !isArrayFn(item)
        ? getOwnPropertyDescriptorFn(item, 'caseKey') : undefined;
      if (descriptor && descriptor.enumerable && 'value' in descriptor && typeof descriptor.value === 'string' &&
        descriptor.value.length <= 256) caseKey = descriptor.value;
    } catch { caseKey = ''; }
    let verdict: ReplayAnnotationVerdict | null = null;
    try {
      const v = fields(item, ['version', 'caseKey', 'verdict', 'source'], [], 'ANNOTATION_INVALID');
      if (v.version !== 1 || typeof v.caseKey !== 'string' || v.caseKey !== caseKey || v.caseKey.length > 256) {
        throw new ReplayInputError('ANNOTATION_INVALID');
      }
      verdict = member(v.verdict, REPLAY_ANNOTATION_VERDICTS, 'ANNOTATION_INVALID');
      member(v.source, REPLAY_ANNOTATION_SOURCES, 'ANNOTATION_INVALID');
    } catch {
      verdict = null;
    }
    if (verdict === null || scanIndex(caseKeys, caseKey) < 0) {
      rejected += 1;
      // An annotation whose case key resolves to nothing -- an empty key, an unknown case, or a
      // case too malformed to have one -- is rejected without attaching to any record.
      if (scanIndex(caseKeys, caseKey) >= 0) append(caseKey, 'INVALID');
      continue;
    }
    append(caseKey, verdict);
  }
  const attached = objectKeysFn(states);
  for (let index = 0; index < attached.length; index += 1) {
    const caseKey = attached[index] as string;
    const verdicts = states[caseKey] ?? [];
    const distinct: ReplayAnnotationState[] = [];
    for (const verdict of verdicts) if (scanIndex(distinct, verdict) < 0) addValue(distinct, verdict);
    let state: ReplayAnnotationState;
    if (scanIndex(verdicts, 'INVALID') >= 0) state = 'INVALID';
    else if (distinct.length > 1) { state = 'CONFLICT'; conflicting += 1; }
    else state = distinct[0] as ReplayAnnotationState;
    states[caseKey] = [state];
    if (state === 'AGREED' || state === 'DISAGREED' || state === 'UNRESOLVED') tally[state] += 1;
  }
  return {
    entries: states,
    summary: {
      provided: items.length,
      agreed: tally.AGREED,
      disagreed: tally.DISAGREED,
      unresolved: tally.UNRESOLVED,
      conflicting,
      rejected,
      authority: 'NONE',
    },
  };
}

/** Spec keys for the two fixed roles; the run order itself is the closed role vocabulary. */
const SIDECAR_KEYS: Readonly<Record<ReplayRole, string>> = freezeValue({
  CHAMPION: 'champion', CHALLENGER: 'challenger',
});

function prepare(spec: unknown): PreparedRun {
  const v = fields(spec, ['trusted', 'cases', 'champion', 'challenger'], ['annotations']);
  const trust = fields(v.trusted, ['version', 'scope', 'runId', 'runKey', 'pins']);
  if (trust.version !== 1) fail('INVALID_SPEC');
  const scope = readScope(trust.scope, 'INVALID_SPEC');
  const runId = token(trust.runId, 'INVALID_SPEC');
  const runKey = trust.runKey;
  if (!(runKey instanceof Uint8Array) || runKey.length !== REPLAY_RUN_KEY_BYTES) fail('INVALID_SPEC');
  const pins = fields(trust.pins, ['champion', 'challenger']);
  const sides: Record<ReplayRole, PreparedSide> = {} as Record<ReplayRole, PreparedSide>;
  for (let index = 0; index < REPLAY_ROLES.length; index += 1) {
    const role = REPLAY_ROLES[index] as ReplayRole;
    const raw = fields(v[SIDECAR_KEYS[role]], ['bundle', 'evaluate']);
    if (typeof raw.evaluate !== 'function') fail('INVALID_SPEC');
    const bundle = readBundleRef(raw.bundle, 'BUNDLE_REFERENCE_INVALID');
    const pin = readBundleRef(pins[SIDECAR_KEYS[role]], 'INVALID_SPEC');
    const pinReason = sameBundle(bundle, pin) ? null
      : (bundle.id !== pin.id || bundle.version !== pin.version
        ? 'BUNDLE_PIN_MISMATCH' : 'BUNDLE_CONTENT_PIN_MISMATCH');
    sides[role] = {
      bundle,
      evaluate: raw.evaluate as (view: ReplayCaseView) => unknown,
      pinState: pinReason === null ? 'PINNED' : 'MISMATCHED',
      pinReason,
    };
  }
  if (!isArrayFn(v.cases) || getPrototypeOfFn(v.cases) !== Array.prototype) fail('INVALID_SPEC');
  const items = arrayOf(v.cases, REPLAY_MAX_CASES, 'CASE_COUNT_EXCEEDED');
  if (items.length === 0) fail('CASE_COUNT_EXCEEDED');
  const seen: string[] = [];
  const annotated = mapValues(items, (item, index) => readCase(item, scope, `case-${index + 1}`, seen));
  const annotationInput = hasOwnFn(v, 'annotations') ? v.annotations : [];
  const annotation = readAnnotations(annotationInput, annotated);
  const runKeyCopy = new Uint8Array(runKey);
  const scopePseudonym = {
    tenant: pseudonym(runKeyCopy, ['scope', runId, scope.tenantId]),
    ...(scope.projectId === undefined ? {} : { project: pseudonym(runKeyCopy, ['project', runId, scope.tenantId, scope.projectId]) }),
  };
  const cases = mapValues(annotated, (entry) => ({
    ...entry,
    pseudonym: pseudonym(runKeyCopy, ['case', runId, scope.tenantId, scope.projectId ?? '', entry.caseRef]),
    annotation: entry.caseKey === null ? 'NONE' : (annotation.entries[entry.caseKey]?.[0] ?? 'NONE'),
    reasons: [
      ...entry.reasons,
      ...(entry.caseKey === null ? [] : flatMapValues(annotation.entries[entry.caseKey] ?? [], (state) => (
        state === 'CONFLICT' ? ['ANNOTATION_CONFLICT' as const]
          : state === 'INVALID' ? ['ANNOTATION_INVALID' as const]
            : state === 'DISAGREED' ? ['ANNOTATION_DISAGREEMENT' as const]
              : state === 'UNRESOLVED' ? ['ANNOTATION_UNRESOLVED' as const] : []))),
    ],
  }));
  return {
    scope,
    scopePseudonym,
    runKey: runKeyCopy,
    runRef: pseudonym(runKeyCopy, ['run', runId, scope.tenantId, scope.projectId ?? '']),
    sides,
    cases,
    corpusRef: pseudonym(runKeyCopy, ['corpus', runId, scope.tenantId, scope.projectId ?? '',
      // Through the captured map: a replaced Array.prototype.map must not forge this reference.
      ...mapValues(cases, (entry) => `${entry.caseRef}:${entry.markerExpectation}`)]),
    annotations: annotation.summary,
  };
}

/* ------------------------------------------------------------------------- bounded evaluation */

type BoundedOutcome<T> =
  | { readonly status: 'SETTLED'; readonly value: T }
  | { readonly status: 'DEADLINE_EXCEEDED' }
  | { readonly status: 'CANCELLED' }
  | { readonly status: 'FAILED' };

/**
 * A caller cancellation aborts the wait; the deadline only stops waiting, so a genuinely late answer
 * stays observable and is discarded instead of merged.
 *
 * `settle` happens first and every listener operation is guarded: the option is duck-typed, so a
 * hand-rolled signal, wrapper or polyfill whose `addEventListener`/`removeEventListener` throws must
 * not be able to leave this promise unsettled (an unhandled rejection plus a permanently pending
 * run). The deadline remains the backstop when the signal cannot be used.
 */
function bounded<T>(work: Promise<T>, deadlineMs: number, signal: AbortSignal | undefined): Promise<BoundedOutcome<T>> {
  return new Promise((settle) => {
    let done = false;
    let timer: unknown;
    const discard = (result: BoundedOutcome<T>): void => {
      if (done) return;
      done = true;
      safeDropTimer(timer);
      settle(result);
      if (signal !== undefined) {
        try { signal.removeEventListener('abort', onAbort); } catch { /* unusable signal: nothing to detach */ }
      }
      ignoreRejection(work);
    };
    function onAbort(): void { discard({ status: 'CANCELLED' }); }
    // The timer is armed and then explicitly dropped on any failure in the rest of this executor:
    // a deadline that outlives the call would fire in the caller's process, with no caller to catch
    // anything it threw. `ignoreRejection` is guarded for the same reason.
    try {
      timer = armTimer(() => { discard({ status: 'DEADLINE_EXCEEDED' }); }, deadlineMs);
      if (signal !== undefined) {
        try { signal.addEventListener('abort', onAbort, { once: true }); } catch { /* deadline remains the backstop */ }
        if (isAborted(signal)) onAbort();
      }
      thenWork(work, (settled) => { discard(settled); });
    } catch {
      done = true;
      safeDropTimer(timer);
      ignoreRejection(work);
      settle({ status: 'FAILED' });
    }
  });
}

/**
 * Read a signal's state defensively. A signal that cannot be interrogated is treated as aborted,
 * which is the direction that refuses to measure rather than the one that records a clean result.
 */
function isAborted(signal: AbortSignal | undefined): boolean {
  if (signal === undefined) return false;
  try { return signal.aborted === true; } catch { return true; }
}

function readEvaluatorResult(value: unknown): { claim: ReplayEvaluatorClaim; emission: string; taskAnswer?: string } {
  const v = fields(value, ['version', 'claim', 'emission'], ['taskAnswer'], 'EVALUATOR_RESULT_MALFORMED');
  if (v.version !== 1) fail('EVALUATOR_RESULT_MALFORMED');
  const claim = member(v.claim, REPLAY_EVALUATOR_CLAIMS, 'EVALUATOR_RESULT_MALFORMED');
  if (typeof v.emission !== 'string' || !isText(v.emission, REPLAY_MAX_EMISSION_BYTES * 2, true)) {
    fail('EVALUATOR_RESULT_MALFORMED');
  }
  if (utf8Length(v.emission, REPLAY_MAX_EMISSION_BYTES) > REPLAY_MAX_EMISSION_BYTES) fail('EMISSION_TOO_LARGE');
  let taskAnswer: string | undefined;
  if (hasOwnFn(v, 'taskAnswer')) {
    if (typeof v.taskAnswer !== 'string') fail('EVALUATOR_RESULT_MALFORMED');
    if (v.taskAnswer.length > REPLAY_MAX_TASK_ANSWER_CHARS) fail('TASK_ANSWER_TOO_LARGE');
    if (!isText(v.taskAnswer, REPLAY_MAX_TASK_ANSWER_CHARS, true)) fail('EVALUATOR_RESULT_MALFORMED');
    taskAnswer = v.taskAnswer;
  }
  return taskAnswer === undefined ? { claim, emission: v.emission } : { claim, emission: v.emission, taskAnswer };
}

/**
 * Harness-measured elapsed time. It is reported as measured, never clamped to the deadline: the
 * deadline bounds *waiting for an async answer*, so a synchronously blocking evaluator legitimately
 * records more than it, and a clamped number would understate real work.
 */
function elapsed(from: number): number {
  return mathMaxFn(0, dateNowFn() - from);
}

interface Observation {
  readonly status: ReplayCaseStatus;
  readonly privacy: ReplayPrivacyOutcome;
  readonly claim: ReplayEvaluatorClaim;
  readonly utility: ReplayUtilityOutcome;
  readonly reasons: readonly ReplayReasonCode[];
  readonly elapsedMs: number;
}

async function observe(run: PreparedRun, role: ReplayRole, entry: PreparedCase, deadlineMs: number,
  startedAt: number, signal: AbortSignal | undefined): Promise<Observation> {
  const reasons: ReplayReasonCode[] = [...entry.reasons];
  const side = run.sides[role];
  const unknown = (code: ReplayReasonCode): Observation => ({
    status: 'UNKNOWN', privacy: 'UNKNOWN', claim: 'UNKNOWN', utility: 'UNKNOWN',
    reasons: codes([...reasons, code]), elapsedMs: 0,
  });
  const rejected = (code: ReplayReasonCode): Observation => ({
    status: 'REJECTED', privacy: 'UNKNOWN', claim: 'UNKNOWN', utility: 'UNKNOWN',
    reasons: codes([...reasons, code]), elapsedMs: 0,
  });
  // A rejected case keeps its own specific reason; `CASE_REJECTED` is the side-level aggregate.
  if (entry.rejected) return rejected(entry.reasons[entry.reasons.length - 1] as ReplayReasonCode);
  if (side.pinState === 'MISMATCHED') {
    // A stale, renamed or substituted reference rejects the side; it never falls back to the other.
    return rejected(side.pinReason ?? 'BUNDLE_PIN_MISMATCH');
  }
  if (isAborted(signal)) return unknown('CANCELLED');
  if (dateNowFn() - startedAt >= REPLAY_MAX_RUN_MS) return unknown('RUN_BUDGET_EXCEEDED');
  const view = freezeValue({
    caseRef: entry.caseRef,
    family: entry.family,
    text: entry.text,
    task: freezeValue({ prompt: entry.prompt }),
  });
  if (!intrinsicsIntact()) addValue(reasons, 'HARNESS_INTRINSIC_TAMPERED');
  const callStarted = dateNowFn();
  let outcome: BoundedOutcome<unknown>;
  try {
    const pending = applyFn(promiseResolveFn, promiseCtorFn, [side.evaluate(view)]) as Promise<unknown>;
    outcome = await bounded(pending, deadlineMs, signal);
  } catch {
    return { ...unknown('EVALUATOR_ERROR'), elapsedMs: elapsed(callStarted) };
  }
  const elapsedMs = elapsed(callStarted);
  // The environment is re-checked after the call: an evaluator may have replaced one of the
  // intrinsics this observation depends on, which is reported rather than silently absorbed.
  const tampered = !intrinsicsIntact();
  if (tampered && !hasValue(reasons, 'HARNESS_INTRINSIC_TAMPERED')) addValue(reasons, 'HARNESS_INTRINSIC_TAMPERED');
  if (outcome.status === 'CANCELLED') return { ...unknown('CANCELLED'), elapsedMs };
  if (outcome.status === 'DEADLINE_EXCEEDED') return { ...unknown('DEADLINE_EXCEEDED'), elapsedMs };
  if (outcome.status === 'FAILED') return { ...unknown('EVALUATOR_ERROR'), elapsedMs };
  let result: { claim: ReplayEvaluatorClaim; emission: string; taskAnswer?: string };
  try {
    result = readEvaluatorResult(outcome.value);
  } catch (error) {
    const code = error instanceof ReplayInputError ? error.code : 'EVALUATOR_RESULT_MALFORMED';
    return { ...unknown(code), elapsedMs };
  }
  // The privacy outcome is the harness's own observation, not the evaluator's claim, and it is made
  // through module-load-captured intrinsics so no assignment inside `evaluate` can rewire it.
  const privacy: ReplayPrivacyOutcome = entry.markerExpectation === 'NONE'
    ? 'NOT_APPLICABLE' : containsText(result.emission, entry.marker) ? 'MARKER_EMITTED' : 'MARKER_WITHHELD';
  const expectedClaim: ReplayEvaluatorClaim = privacy === 'MARKER_EMITTED' ? 'MARKER_RELEASED'
    : privacy === 'MARKER_WITHHELD' ? 'MARKER_WITHHELD'
      : privacy === 'NOT_APPLICABLE' ? 'NO_MARKER_PRESENT' : 'UNKNOWN';
  if (result.claim !== expectedClaim) addValue(reasons, 'EVALUATOR_CLAIM_MISMATCH');
  if (privacy === 'MARKER_EMITTED') addValue(reasons, 'MARKER_EMITTED_OBSERVED');
  const utility: ReplayUtilityOutcome = result.taskAnswer === undefined ? 'UNKNOWN'
    : result.taskAnswer === entry.expectedAnswer ? 'MATCH' : 'MISMATCH';
  if (utility === 'MISMATCH') addValue(reasons, 'UTILITY_MISMATCH_OBSERVED');
  return { status: 'MEASURED', privacy, claim: result.claim, utility, reasons: codes(reasons), elapsedMs };
}

function record(run: PreparedRun, role: ReplayRole, entry: PreparedCase, observation: Observation): ReplayAuditRecord {
  const body: Fields = {
    version: 1,
    runRef: run.runRef,
    caseRef: entry.caseRef,
    casePseudonym: entry.pseudonym,
    role,
    scopePseudonym: run.scopePseudonym,
    bundle: run.sides[role].bundle,
    status: observation.status,
    annotation: entry.annotation,
    privacy: observation.privacy,
    privacyClaim: observation.claim,
    utility: observation.utility,
    reasons: observation.reasons,
    elapsedMs: observation.elapsedMs,
  };
  return { ...(body as Omit<ReplayAuditRecord, 'digest'>), digest: recordDigest(run.runKey, body) };
}

function summarize(role: ReplayRole, side: PreparedSide, records: readonly ReplayAuditRecord[]): ReplaySideSummary {
  let measured = 0;
  let unknown = 0;
  let rejected = 0;
  let withheld = 0;
  let emitted = 0;
  let notApplicable = 0;
  let privacyUnknown = 0;
  let match = 0;
  let mismatch = 0;
  let utilityUnknown = 0;
  let totalMs = 0;
  let maxMs = 0;
  const reviewReasons: ReplayReasonCode[] = [];
  for (const entry of records) {
    if (entry.status === 'MEASURED') measured += 1;
    else if (entry.status === 'UNKNOWN') unknown += 1;
    else rejected += 1;
    if (entry.privacy === 'MARKER_WITHHELD') withheld += 1;
    else if (entry.privacy === 'MARKER_EMITTED') emitted += 1;
    else if (entry.privacy === 'NOT_APPLICABLE') notApplicable += 1;
    else privacyUnknown += 1;
    if (entry.utility === 'MATCH') match += 1;
    else if (entry.utility === 'MISMATCH') mismatch += 1;
    else utilityUnknown += 1;
    totalMs += entry.elapsedMs;
    maxMs = mathMaxFn(maxMs, entry.elapsedMs);
    for (const reason of entry.reasons) addValue(reviewReasons, reason);
  }
  // Every reason is a code some record actually carries, plus the two status aggregates. A deadline
  // or a caller cancellation is therefore never reported as an evaluator error.
  if (unknown > 0) addValue(reviewReasons, 'CASE_UNKNOWN');
  if (rejected > 0) addValue(reviewReasons, 'CASE_REJECTED');
  const reasons = codes(reviewReasons);
  return {
    role,
    bundle: side.bundle,
    pinState: side.pinState,
    cases: { total: records.length, measured, unknown, rejected },
    privacy: { withheld, emitted, notApplicable, unknown: privacyUnknown },
    utility: { match, mismatch, unknown: utilityUnknown },
    /** Cases that produced no usable evaluation result: malformed output, evaluator error, deadline, cancellation or budget. */
    errors: unknown,
    latencyMs: { total: totalMs, max: maxMs },
    cost: { state: 'UNMEASURED', reason: 'OFFLINE_NO_COST_SIGNAL' },
    review: {
      recommendation: reasons.length > 0 ? 'HUMAN_REVIEW_RECOMMENDED' : 'NO_FINDING_IN_THIS_SUBSET',
      authority: 'NONE',
      reasons,
    },
  };
}

/* -------------------------------------------------------------------------------- entry point */

function readOptions(options: unknown): { deadlineMs: number; signal: AbortSignal | undefined } {
  const v = fields(options ?? {}, [], ['deadlineMs', 'signal'], 'INVALID_OPTIONS');
  const deadlineMs = hasOwnFn(v, 'deadlineMs')
    ? integer(v.deadlineMs, REPLAY_MIN_DEADLINE_MS, REPLAY_MAX_DEADLINE_MS, 'INVALID_OPTIONS')
    : REPLAY_DEFAULT_DEADLINE_MS;
  let signal: AbortSignal | undefined;
  if (hasOwnFn(v, 'signal')) {
    // The option is duck-typed, so every read can run caller code: a throwing accessor is a refused
    // option (`INVALID_OPTIONS`), never an exception out of the entry point.
    const candidate = v.signal;
    let usable = false;
    if (candidate !== null && typeof candidate === 'object') {
      try {
        usable = typeof (candidate as { aborted?: unknown }).aborted === 'boolean' &&
          typeof (candidate as { addEventListener?: unknown }).addEventListener === 'function' &&
          typeof (candidate as { removeEventListener?: unknown }).removeEventListener === 'function';
      } catch {
        usable = false;
      }
    }
    if (!usable) fail('INVALID_OPTIONS');
    signal = candidate as AbortSignal;
  }
  return { deadlineMs, signal };
}

/**
 * Sentinels for "no identity was established": a well-formed but obviously non-real bundle
 * reference and reference digest, so a strict downstream validator needs no special case for the
 * invalid report. They are not a bundle, not a run and not a key.
 */
const ZERO_DIGEST = repeatChar('0', 64);
const ZERO_PSEUDONYM = repeatChar('0', 32);
const UNAVAILABLE_LABEL = 'unavailable';

function invalidReport(reasons: readonly ReplayReasonCode[]): ReplayReport {
  const empty = (role: ReplayRole): ReplaySideSummary => ({
    role,
    bundle: { id: UNAVAILABLE_LABEL, version: UNAVAILABLE_LABEL, digest: ZERO_DIGEST },
    pinState: 'UNAVAILABLE',
    cases: { total: 0, measured: 0, unknown: 0, rejected: 0 },
    privacy: { withheld: 0, emitted: 0, notApplicable: 0, unknown: 0 },
    utility: { match: 0, mismatch: 0, unknown: 0 },
    errors: 0,
    latencyMs: { total: 0, max: 0 },
    cost: { state: 'UNMEASURED', reason: 'OFFLINE_NO_COST_SIGNAL' },
    review: { recommendation: 'NO_FINDING_IN_THIS_SUBSET', authority: 'NONE', reasons: [] },
  });
  return deepFreeze({
    version: 1,
    status: 'INVALID',
    run: {
      runRef: ZERO_PSEUDONYM, scopePseudonym: { tenant: ZERO_PSEUDONYM }, corpusRef: ZERO_PSEUDONYM, cases: 0,
      annotations: {
        provided: 0, agreed: 0, disagreed: 0, unresolved: 0, conflicting: 0, rejected: 0, authority: 'NONE',
      },
    },
    sides: { CHAMPION: empty('CHAMPION'), CHALLENGER: empty('CHALLENGER') },
    disagreements: [],
    shadow: {
      mode: 'OFFLINE_DEVELOPMENT', execution: 'IN_PROCESS', hostedTransport: 'NONE',
      candidateExecution: 'NONE', authority: 'NONE',
    },
    promotion: { state: 'UNAVAILABLE', authority: 'NONE', gates: REPLAY_PROMOTION_GATES },
    productionEligibility: { state: 'UNAVAILABLE', authority: 'NONE' },
    records: [],
    reasons: codes(reasons),
  });
}

/**
 * Run one bounded offline comparison. This never rejects and never throws: a malformed request
 * becomes an explicit `INVALID` report, and every evaluator, deadline, cancellation, scope or
 * annotation fault becomes an explicit per-case `UNKNOWN`/`REJECTED` record.
 */
export async function runChampionReplay(spec: unknown, options?: unknown): Promise<ReplayReport> {
  if (!REALM_TRUSTED) return invalidReport(['HARNESS_REALM_UNTRUSTED']);
  const startedAt = dateNowFn();
  // Checked before the corpus is read: the run reference and corpus reference are derived here, so a
  // run in an already-mutated environment says so even when it never reaches a case boundary.
  const tamperedAtStart = !intrinsicsIntact();
  try {
    // Options are validated first: a malformed request must not make the harness read a corpus.
    const { deadlineMs, signal } = readOptions(options);
    const run = prepare(spec);
    const records: ReplayAuditRecord[] = [];
    for (let index = 0; index < run.cases.length; index += 1) {
      const entry = run.cases[index] as PreparedCase;
      for (let slot = 0; slot < REPLAY_ROLES.length; slot += 1) {
        const role = REPLAY_ROLES[slot] as ReplayRole;
        const observation = await observe(run, role, entry, deadlineMs, startedAt, signal);
        addValue(records, record(run, role, entry, observation));
      }
    }
    const perSide: Record<ReplayRole, ReplayAuditRecord[]> = {
      CHAMPION: selectValues(records, (entry) => entry.role === 'CHAMPION'),
      CHALLENGER: selectValues(records, (entry) => entry.role === 'CHALLENGER'),
    };
    const disagreements: ReplayDisagreement[] = [];
    const runReasons: ReplayReasonCode[] = [];
    if (tamperedAtStart) addValue(runReasons, 'HARNESS_INTRINSIC_TAMPERED');
    for (let index = 0; index < run.cases.length; index += 1) {
      const champion = perSide.CHAMPION[index] as ReplayAuditRecord;
      const challenger = perSide.CHALLENGER[index] as ReplayAuditRecord;
      for (const [field, key] of [['PRIVACY', 'privacy'], ['UTILITY', 'utility']] as const) {
        const left = champion[key];
        const right = challenger[key];
        if (left === right) continue;
        if (disagreements.length >= REPLAY_MAX_DISAGREEMENTS) {
          addValue(runReasons, 'DISAGREEMENTS_TRUNCATED');
          break;
        }
        addValue(disagreements, { caseRef: champion.caseRef, field, champion: left, challenger: right });
      }
    }
    if (isAborted(signal)) addValue(runReasons, 'CANCELLED');
    for (const aggregate of ['RUN_BUDGET_EXCEEDED', 'HARNESS_INTRINSIC_TAMPERED'] as const) {
      if (anyValue(records, (entry) => hasValue(entry.reasons, aggregate))) addValue(runReasons, aggregate);
    }
    // Records are frozen first, so even an exhausted node budget could never leave a record
    // editable or reach a headline field.
    deepFreeze(records);
    return deepFreeze({
      version: 1,
      status: allValues(records, (entry) => entry.status === 'MEASURED') ? 'COMPLETE' : 'PARTIAL',
      run: {
        runRef: run.runRef,
        scopePseudonym: run.scopePseudonym,
        corpusRef: run.corpusRef,
        cases: run.cases.length,
        annotations: run.annotations,
      },
      sides: {
        CHAMPION: summarize('CHAMPION', run.sides.CHAMPION, perSide.CHAMPION),
        CHALLENGER: summarize('CHALLENGER', run.sides.CHALLENGER, perSide.CHALLENGER),
      },
      disagreements,
      shadow: {
        mode: 'OFFLINE_DEVELOPMENT', execution: 'IN_PROCESS', hostedTransport: 'NONE',
        candidateExecution: 'NONE', authority: 'NONE',
      },
      promotion: { state: 'UNAVAILABLE', authority: 'NONE', gates: REPLAY_PROMOTION_GATES },
      productionEligibility: { state: 'UNAVAILABLE', authority: 'NONE' },
      records,
      reasons: codes(runReasons),
    });
  } catch (error) {
    // No caller-controlled value, message or stack leaves this seam.
    const reasons = [error instanceof ReplayInputError ? error.code : 'INVALID_SPEC' as ReplayReasonCode];
    if (tamperedAtStart) addValue(reasons, 'HARNESS_INTRINSIC_TAMPERED');
    return invalidReport(reasons);
  }
}

/**
 * Evaluated last, once every captured reference and every shape table above it is initialized: a
 * load-time self-test that ran before its own dependencies could only ever report an untrusted realm.
 * `runChampionReplay` and `generateSyntheticReplayCorpus` read it at call time.
 */
const REALM_TRUSTED = realmSelfCheck();
