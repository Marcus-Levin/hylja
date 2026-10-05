/**
 * Accepted-v1 classification units over the #6/#7 composition seam, plus the one trusted contact-sensitivity
 * configuration #10/#37 could not supply. Pure and NON-ENFORCING: it groups per-occurrence candidates into
 * units, composes each unit with the accepted `composeClassification`, and returns metadata only. It never
 * rewrites input, selects a treatment, creates a mapping, authenticates anybody, sends bytes or proves
 * anything about egress. Semantic evidence still never authorizes an effect: a `RESOLVED` unit is an input to
 * deterministic policy, not a decision.
 *
 * Grouping (deterministic and bounded; candidates are placed in result order, per scan line, and no search over
 * subsets of occurrences is ever performed):
 * - a **scan line** is one text unit one detector pass read: a view representation (`viewId` + `RAW`/`FOLDED`)
 *   or one #7 parsed field (#7 format + field span + request-bound key-path digest). Candidates from different
 *   lines never merge, so the same occurrence read by two passes keeps two units and two references;
 * - candidates are placed by their **occurrence span**, which is the match offset inside the decoded field
 *   value for a #7 field and the in-view span otherwise. A decoded field value reports its whole field span in
 *   the view, so grouping by view span alone would make every candidate in one value look like the same
 *   occurrence and collapse unrelated entities into one whole-field identity;
 * - within a line, candidates merge **only when they strictly cross** — one starts inside the other and ends
 *   outside it — or when they cover exactly the same occurrence. Disjoint, adjacent and nested spans stay
 *   distinct, so two occurrences of the same value inside one decoded envelope are two units with their own
 *   spans and references, a configured name inside an email local part keeps its own unit instead of dragging
 *   the address into it, and one over-covering detector match can never swallow the entities inside it;
 * - a **whole-value** candidate (a trusted #7/#10 key-path hint covering a whole field value, `FIELD_HINT`)
 *   never merges with anything, in either direction. It keeps its own unit and leaves the occurrences inside
 *   that value as their own units, so a hint can neither absorb nor hide them;
 * - merging stops at the composer's per-channel evidence limit, and the next candidate starts a new unit, so
 *   every candidate is retained in some unit;
 * - a candidate joins the **last group it relates to**, found by scanning that line's groups from the most
 *   recent backwards: a nested, disjoint or whole-value candidate never joins one, so splitting can only
 *   produce more units, never fewer, and no candidate is ever dropped by grouping. That backwards scan is bounded
 *   by the groups on one line and skips any group already at the evidence cap; the seam's per-source candidate
 *   caps keep a line to a few hundred candidates, so this is bounded work rather than a search;
 *
 * A crossing overlap keeps every contributing source's evidence in one unit, so no detector can be discarded
 * in favour of a weaker neighbour, and a disagreement between those claims (class, subtype or sensitivity)
 * leaves the unit `UNRESOLVED` under the accepted composer with the highest claimed sensitivity retained. A
 * nested or disjoint occurrence is reported as its own unit rather than merged, because the composer resolves
 * one unit at a time and nothing is lost by keeping both: the outer claim still covers its own span and the
 * inner one keeps its own reference and location.
 *
 * Each unit carries its own opaque `ref`, derived from the caller's per-request `inputRef` and the unit
 * index, so two same-value occurrences can never share a reference (the analogue of the reviewed #4 A/B
 * defect), and every unit's location is either exactly one contributor's location or a covering/envelope
 * union of its contributors — never an invented exact offset. A unit whose provenance cannot be stated
 * homogeneously reports `UNIT_LOCATION_UNRESOLVED`, keeps no `original`, and is recorded as opaque.
 *
 * Trust and limits:
 * - `contactSensitivity` is a trusted, tenant/project-bound opaque handle built in this process. For a PERSON
 *   subtype it configures, it **completes** that candidate's claim: the composed channel receives a record from
 *   producer `hylja.contact-sensitivity` carrying the candidate's own semantic type and subtype plus the
 *   configured sensitivity, because the accepted composer refuses to resolve a unit while any contributing
 *   claim carries no sensitivity and #37 emits none by design. The completion is metadata about the candidate
 *   the detector already found; it cannot assert a different type or subtype, and the detector's own record is
 *   never deleted — every unit retains all of its contributing records in `detectorEvidence`. Absent, foreign,
 *   forged or malformed, no completion is emitted, the result is `PARTIAL` where the handle was refused, and
 *   the affected units keep the raw claim and stay `UNRESOLVED` with `MISSING_SENSITIVITY`. Nothing is ever
 *   guessed from formatting, a payload never asserts a sensitivity, and a weaker configured contact
 *   sensitivity can never overwrite a stronger configured detector claim (`CONFLICTING_SENSITIVITY` leaves
 *   the unit unresolved at the highest claim);
 * - building a handle consumes trusted integration inputs. It does **not** authenticate an identity, a
 *   principal or a project, and a handle minted in this process is unforgeable only in the sense that no other
 *   process can mint one;
 * - `COMPLETE` means every supplied candidate was composed into a unit. It is never "clean", never an
 *   authorization and never a statement about the bytes. Anything uninspected stays in `uninspected`, and any
 *   cap that truncates the unit set is `PARTIAL` with an opaque location per dropped candidate, never a
 *   success-shaped truncation; a `COMPLETE` detection that nevertheless carries opaque coverage is downgraded to
 *   `PARTIAL` with `UNINSPECTED_COVERAGE`;
 * - malformed, throwing, proxied or symbol-bearing inputs are refused whole with a fixed reason code, and no
 *   caller text is ever echoed: unknown keys inside any record are refused, and a detection reason or opaque
 *   location reason that is not an uppercase code token becomes `DETECTION_UNREADABLE_REASON` or
 *   `UNREADABLE_OPAQUE_REASON` instead of being copied.
 */
import { createHash } from 'node:crypto';
import { composeClassification, SCOPES, SENSITIVITIES, TRUST_LEVELS, type Classification, type ClassificationClaim,
  type ClassificationContext, type EvidenceProvenance, type Sensitivity, type SubtypeRegistry } from './classification.js';
import { CONTACT_SUBTYPES, type CandidateScope } from './contact-candidates.js';
import { ENCODINGS, type Encoding } from './normalization.js';
import { FORMATS, type Format } from './structured-parsers.js';
import type { NormalizedCandidate, OpaqueLocation, OriginalLocation,
  ParsedFieldLocation, ViewLocation } from './normalized-detection.js';

/** Trusted configuration producer for configured contact sensitivity. Detector evidence, never model output. */
export const CONTACT_SENSITIVITY_PRODUCER = Object.freeze({ id: 'hylja.contact-sensitivity', version: '1' });
/** Units per request. The #6/#7 seam caps each source at 256 candidates, so this is a hard ceiling, not a tuned threshold. */
export const MAX_UNITS = 1024;
/** Evidence per unit. Matches the v1 composer's per-channel limit, so no unit is refused for its own size. */
export const MAX_UNIT_EVIDENCE = 256;
const MAX_CANDIDATES = 4096;
const MAX_OPAQUE = 4096;
const MAX_RUNS = 1024;
const MAX_PATH = 8;
/** Detection reasons copied through. Beyond this the result is refused rather than silently shortened. */
const MAX_REASONS = 512;
const SOURCES: readonly NormalizedCandidate['source'][] = Object.freeze(
  ['SECRET', 'INFRASTRUCTURE', 'CONTACT', 'CONFIGURED'] as const);

export interface Span { readonly start: number; readonly end: number }
export interface UnitLocation {
  readonly viewId: number;
  /** Offset into the view the contributing candidates were scanned in, covering every occurrence in the unit. */
  readonly span: Span;
  readonly representation: ViewLocation['representation'];
  readonly form: ViewLocation['form'];
  readonly encodingPath: readonly Encoding[];
  /**
   * Exactly one contributor's original location, or the covering/envelope union of the contributors'. Absent
   * only with `UNIT_LOCATION_UNRESOLVED`, which also records the unit as opaque.
   */
  readonly original?: OriginalLocation;
  /** Present when every contributor came from one #7 field. Key names are never emitted, only the digest. */
  readonly field?: ParsedFieldLocation;
}

/* ---------- Trusted contact sensitivity ---------- */

declare const contactSensitivityBrand: unique symbol;
/** Opaque handle; configured sensitivities are only reachable through the module-private registry below. */
export interface ContactSensitivityHandle { readonly [contactSensitivityBrand]: true }
/**
 * Minimal on purpose: one configured sensitivity per PERSON subtype for one tenant and project. It is not a
 * per-person table and carries no value; a unit's sensitivity comes from this map or from a detector claim,
 * never from an inference about the text.
 */
export interface ContactSensitivityEntry { subtype: 'NAME' | 'EMAIL' | 'PHONE'; sensitivity: Sensitivity }
interface SensitivityState { scope: CandidateScope; bySubtype: ReadonlyMap<string, Sensitivity> }
const sensitivityRegistry = new WeakMap<object, SensitivityState>();

function label(value: unknown, limit = 256): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
function inSet<T extends string>(value: unknown, set: readonly T[]): value is T {
  return typeof value === 'string' && (set as readonly unknown[]).includes(value);
}
/**
 * Own enumerable data properties, and **only** the expected keys: a getter, a `Proxy` trap, a symbol key, an
 * inherited value or an unknown key is refused rather than interpreted, so nothing a caller invents inside a
 * detection record can travel into a serialized unit.
 */
function data(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
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
/**
 * A reason code: an uppercase token, no spaces, no control characters. A real seam reason is one of these
 * (`NORMALIZATION_DEPTH_LIMIT`, `PARSER_JSON_DUPLICATE_KEY`, `CONFIGURED_CONFIG_SCOPE_MISMATCH`, ...), so a
 * reason that is not code-shaped is caller-planted text and is replaced by a fixed code instead of echoed.
 */
function reasonCode(value: unknown): string | null {
  return label(value, 256) && /^[A-Z][A-Z0-9_]{2,63}$/u.test(value as string) ? value as string : null;
}
/** A bounded dense array of own data properties. A `Proxy`, a hole, a symbol key or an extra own key is refused. */
function list(value: unknown, max: number): readonly unknown[] | null {
  if (!Array.isArray(value)) return null;
  try {
    const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
    if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0 || length > max) return null;
    if (Reflect.ownKeys(value).length !== length + 1) return null;
    const out: unknown[] = [];
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return null;
      out.push(descriptor.value);
    }
    return out;
  } catch { return null; }
}

/**
 * Bind configured PERSON sensitivities to exactly one tenant and project. Errors never include configured text.
 */
export function createContactSensitivity(scope: CandidateScope, entries: readonly ContactSensitivityEntry[]): ContactSensitivityHandle {
  const invalid = (): never => { throw new TypeError('Invalid contact sensitivity configuration'); };
  try {
    if (!scope || !label(scope.tenantRef) || !label(scope.projectRef)) return invalid();
    const rows = list(entries, CONTACT_SUBTYPES.length);
    if (!rows) return invalid();
    const bySubtype = new Map<string, Sensitivity>();
    for (const row of rows) {
      // Exactly `subtype` and `sensitivity`: an extra key is an unagreed claim, not a default.
      const entry = data(row, ['subtype', 'sensitivity']);
      if (!entry || !inSet(entry.subtype, CONTACT_SUBTYPES) || !inSet(entry.sensitivity, SENSITIVITIES)) return invalid();
      if (bySubtype.has(entry.subtype)) return invalid();
      bySubtype.set(entry.subtype, entry.sensitivity);
    }
    const handle = Object.freeze(Object.create(null)) as ContactSensitivityHandle;
    sensitivityRegistry.set(handle, { scope: Object.freeze({ tenantRef: scope.tenantRef, projectRef: scope.projectRef }),
      bySubtype: new Map(bySubtype) });
    return handle;
  } catch { return invalid(); }
}

/* ---------- Reading a #6/#7 result without trusting its shape ---------- */

interface Read1 {
  readonly source: NormalizedCandidate['source'];
  readonly basis: string;
  /** View span: where the candidate sits in the view, which for a decoded value is the whole field span. */
  readonly span: Span;
  /** Where the occurrence itself sits: inside the decoded field value, else the view span. */
  readonly occurrence: Span;
  readonly view: ViewLocation;
  readonly original: OriginalLocation;
  readonly field: ParsedFieldLocation | null;
  readonly evidence: ContributingEvidence;
  readonly semanticType: string;
  readonly subtype: string | null;
}
function spanOf(value: unknown): Span | null {
  const record = data(value, ['start', 'end']);
  if (!record) return null;
  const start = record.start;
  const end = record.end;
  if (typeof start !== 'number' || typeof end !== 'number' || !Number.isSafeInteger(start) ||
      !Number.isSafeInteger(end) || start < 0 || end <= start) return null;
  return Object.freeze({ start, end });
}
function originalOf(value: unknown): OriginalLocation | null {
  const record = data(value, ['kind'], ['span', 'spans', 'coverage']);
  if (!record) return null;
  if (record.kind === 'ORIGINAL_EXACT' || record.kind === 'ORIGINAL_COVER') {
    const at = spanOf(record.span);
    return at ? Object.freeze({ kind: record.kind, span: at }) : null;
  }
  if (record.kind === 'UTF8_TEXT') {
    const at = spanOf(record.span);
    if (!at || !inSet(record.coverage, ['EXACT', 'COVER'])) return null;
    return Object.freeze({ kind: 'UTF8_TEXT', span: at, coverage: record.coverage });
  }
  if (record.kind === 'ENCODED_RUNS' || record.kind === 'UTF8_ENCODED_RUNS') {
    const runs = list(record.spans, MAX_RUNS);
    if (!runs || runs.length === 0) return null;
    const spans: Span[] = [];
    for (const run of runs) {
      const at = spanOf(run);
      if (!at) return null;
      spans.push(at);
    }
    return Object.freeze({ kind: record.kind, spans: Object.freeze(spans) }) as OriginalLocation;
  }
  return null;
}
function viewOf(value: unknown): ViewLocation | null {
  const record = data(value, ['viewId', 'span', 'representation', 'form', 'encodingPath']);
  if (!record || typeof record.viewId !== 'number' || !Number.isSafeInteger(record.viewId) ||
      record.viewId < 0 || !inSet(record.representation, ['RAW', 'FOLDED']) ||
      !inSet(record.form, ['TEXT', 'STRINGS'])) return null;
  const at = spanOf(record.span);
  const path = list(record.encodingPath, MAX_PATH);
  if (!at || !path || path.some((step) => !inSet(step, ENCODINGS))) return null;
  return Object.freeze({ viewId: record.viewId, span: at, representation: record.representation,
    form: record.form, encodingPath: Object.freeze(path.map((step) => step as Encoding)) });
}
function fieldOf(input: unknown): ParsedFieldLocation | null {
  const record = data(input, ['format', 'pathRef', 'hintSource', 'hintDepth', 'highRisk', 'span', 'valueSpan', 'verbatim']);
  if (!record || !inSet(record.format, FORMATS) || !label(record.pathRef, 128) ||
      !inSet(record.hintSource, ['PATH', 'NAME_SIBLING', 'NONE']) || typeof record.hintDepth !== 'number' ||
      !Number.isSafeInteger(record.hintDepth) || record.hintDepth < -1 || record.hintDepth > 128 ||
      typeof record.highRisk !== 'boolean' || typeof record.verbatim !== 'boolean') return null;
  const at = spanOf(record.span);
  const inside = spanOf(record.valueSpan);
  if (!at || !inside) return null;
  return Object.freeze({ format: record.format as Format, pathRef: record.pathRef,
    hintSource: record.hintSource, hintDepth: record.hintDepth, highRisk: record.highRisk,
    span: at, valueSpan: inside, verbatim: record.verbatim });
}
/** A contributing v1 detector-evidence record exactly as its producer emitted it. Never rewritten here. */
export interface ContributingEvidence {
  readonly version: 1;
  readonly id: string;
  readonly status: 'FOUND';
  readonly provenance: EvidenceProvenance;
  readonly claim: ClassificationClaim;
}
/** A v1 `FOUND` detector-evidence record: own data only, exactly the accepted keys, privacy-safe labels. */
function evidenceOf(value: unknown): { evidence: ContributingEvidence; semanticType: string; subtype: string | null } | null {
  const record = data(value, ['version', 'id', 'status', 'provenance', 'claim']);
  if (!record || record.version !== 1 || record.status !== 'FOUND' || !label(record.id)) return null;
  const provenance = data(record.provenance, ['inputRef', 'producerId', 'producerVersion']);
  if (!provenance || !label(provenance.inputRef, 1024) || !label(provenance.producerId) ||
      !label(provenance.producerVersion)) return null;
  const claim = data(record.claim, ['semanticType'],
    ['subtype', 'sensitivity', 'reversible', 'scope', 'confidence']);
  if (!claim || !label(claim.semanticType, 64)) return null;
  if (Object.hasOwn(claim, 'subtype') && !label(claim.subtype, 64)) return null;
  if (Object.hasOwn(claim, 'sensitivity') && !inSet(claim.sensitivity, SENSITIVITIES)) return null;
  if (Object.hasOwn(claim, 'reversible') && typeof claim.reversible !== 'boolean') return null;
  if (Object.hasOwn(claim, 'scope') && !inSet(claim.scope, SCOPES)) return null;
  if (Object.hasOwn(claim, 'confidence') && (typeof claim.confidence !== 'number' ||
      !Number.isFinite(claim.confidence) || claim.confidence < 0 || claim.confidence > 1)) return null;
  return { evidence: value as ContributingEvidence, semanticType: claim.semanticType,
    subtype: Object.hasOwn(claim, 'subtype') ? claim.subtype as string : null };
}
function candidateOf(value: unknown): Read1 | null {
  const record = data(value, ['source', 'basis', 'evidence', 'view', 'original'],
    ['subtype', 'rule', 'fidelity', 'fingerprint', 'field', 'wholeUnitMatch']);
  if (!record || !inSet(record.source, SOURCES) || !label(record.basis, 64)) return null;
  if (Object.hasOwn(record, 'subtype') && !label(record.subtype, 64)) return null;
  if (Object.hasOwn(record, 'rule') && !label(record.rule, 128)) return null;
  // #6 carries one boolean beside the coverage span: whether #10's own matcher matched the whole text unit
  // it scanned. It is read through this same closed boundary, must be a boolean, and may appear only on a
  // `CONFIGURED` candidate, because no other source has a configured matcher behind it. The numeric offset
  // members an earlier draft accepted are not in the accepted key list at all, so a record carrying one is
  // malformed exactly like any other unknown member. Whatever this reader concludes, the member is
  // deliberately **not** kept on the unit: composition places by the occurrence span, so a host that
  // invented the fact changes nothing here.
  if (Object.hasOwn(record, 'wholeUnitMatch') &&
      (typeof record.wholeUnitMatch !== 'boolean' || record.source !== 'CONFIGURED')) return null;
  const evidence = evidenceOf(record.evidence);
  const view = viewOf(record.view);
  const original = originalOf(record.original);
  if (!evidence || !view || !original) return null;
  const field = Object.hasOwn(record, 'field') ? fieldOf(record.field) : null;
  if (Object.hasOwn(record, 'field') && !field) return null;
  return Object.freeze({ source: record.source, basis: record.basis, span: view.span,
    occurrence: field ? field.valueSpan : view.span, view, original,
    field, evidence: evidence.evidence, semanticType: evidence.semanticType, subtype: evidence.subtype });
}
function opaqueOf(value: unknown): OpaqueLocation | null {
  const record = data(value, ['reason', 'viewId', 'viewSpan', 'original']);
  if (!record || typeof record.viewId !== 'number' ||
      !Number.isSafeInteger(record.viewId) || record.viewId < 0) return null;
  const reason = reasonCode(record.reason);
  const viewSpan = spanOf(record.viewSpan);
  const original = originalOf(record.original);
  if (!viewSpan || !original) return null;
  return Object.freeze({ reason: reason ?? 'UNREADABLE_OPAQUE_REASON', viewId: record.viewId, viewSpan, original });
}

/* ---------- Unit locations ---------- */

/** Strictly crossing spans, or exactly the same occurrence. Anything nested or disjoint stays its own unit. */
function crosses(left: Span, right: Span): boolean {
  if (sameSpan(left, right)) return true;
  return (left.start < right.start && right.start < left.end && left.end < right.end) ||
    (right.start < left.start && left.start < right.end && right.end < left.end);
}
function sameSpan(left: Span, right: Span): boolean { return left.start === right.start && left.end === right.end; }
function sameOriginal(left: OriginalLocation, right: OriginalLocation): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === 'ENCODED_RUNS' || left.kind === 'UTF8_ENCODED_RUNS') {
    const a = left as Extract<OriginalLocation, { spans: readonly Span[] }>;
    const b = right as Extract<OriginalLocation, { spans: readonly Span[] }>;
    return a.spans.length === b.spans.length && a.spans.every((run, index) => sameSpan(run, b.spans[index]!));
  }
  if (left.kind === 'UTF8_TEXT') {
    const other = right as Extract<OriginalLocation, { kind: 'UTF8_TEXT' }>;
    return left.coverage === other.coverage && sameSpan(left.span, other.span);
  }
  return sameSpan((left as { span: Span }).span, (right as { span: Span }).span);
}
function unionSpan(members: readonly Read1[]): Span {
  let start = Number.MAX_SAFE_INTEGER;
  let end = 0;
  for (const member of members) {
    if (member.span.start < start) start = member.span.start;
    if (member.span.end > end) end = member.span.end;
  }
  return Object.freeze({ start, end });
}
/**
 * One contributor's location verbatim, or a covering/envelope union. Mixed families are refused rather than
 * approximated, because a union that silently dropped a contributor's envelope would over-claim coverage.
 */
function originalUnion(members: readonly Read1[]): OriginalLocation | null {
  const first = members[0]!.original;
  if (members.every((member) => sameOriginal(member.original, first))) return first;
  // A string-source claim, a byte-source claim and an encoded envelope are different provenance families and
  // are never combined: one family's union would claim the other's offsets.
  const family = (kind: OriginalLocation['kind']): 'STRING' | 'BYTE' | 'RUN' =>
    kind === 'ORIGINAL_EXACT' || kind === 'ORIGINAL_COVER' ? 'STRING' :
      kind === 'UTF8_TEXT' ? 'BYTE' : 'RUN';
  if (members.some((member) => family(member.original.kind) !== family(first.kind))) return null;
  const at = unionSpan(members);
  if (first.kind === 'ORIGINAL_EXACT' || first.kind === 'ORIGINAL_COVER') {
    return Object.freeze({ kind: 'ORIGINAL_COVER', span: at });
  }
  if (first.kind === 'UTF8_TEXT') return Object.freeze({ kind: 'UTF8_TEXT', span: at, coverage: 'COVER' });
  const runs = new Map<string, Span>();
  for (const member of members) {
    const location = member.original;
    if (location.kind !== first.kind) return null;
    for (const run of location.spans) runs.set(`${run.start}-${run.end}`, run);
  }
  const spans = [...runs.values()].sort((a, b) => a.start - b.start || a.end - b.end);
  if (spans.length > MAX_RUNS) return null;
  return Object.freeze({ kind: first.kind, spans: Object.freeze(spans) }) as OriginalLocation;
}
/** Field metadata is identical for every candidate of one #7 field; anything else is refused, not guessed. */
function fieldUnion(members: readonly Read1[]): ParsedFieldLocation | null {
  const withField = members.filter((member) => member.field !== null);
  if (withField.length === 0) return null;
  if (withField.length !== members.length) return null;
  const first = withField[0]!.field!;
  for (const member of withField) {
    const field = member.field!;
    if (field.format !== first.format || field.pathRef !== first.pathRef || field.hintSource !== first.hintSource ||
        field.hintDepth !== first.hintDepth || field.highRisk !== first.highRisk ||
        field.verbatim !== first.verbatim || !sameSpan(field.span, first.span)) return null;
  }
  let start = Number.MAX_SAFE_INTEGER;
  let end = 0;
  for (const member of withField) {
    const value = member.field!.valueSpan;
    if (value.start < start) start = value.start;
    if (value.end > end) end = value.end;
  }
  return Object.freeze({ ...first, valueSpan: Object.freeze({ start, end }) });
}
function unitLocation(members: readonly Read1[]): { location: UnitLocation; unresolved: boolean } {
  const first = members[0]!;
  const original = originalUnion(members);
  const field = fieldUnion(members);
  const unresolved = original === null || (members.some((member) => member.field !== null) && field === null);
  return {
    location: Object.freeze({ viewId: first.view.viewId, span: unionSpan(members),
      representation: first.view.representation, form: first.view.form,
      encodingPath: first.view.encodingPath,
      ...(original ? { original } : {}),
      ...(field ? { field } : {}) }),
    unresolved,
  };
}

/* ---------- Composition ---------- */

export interface ClassificationUnit {
  /** Opaque, per-unit reference. Unique inside a request, and derived so two units never share one. */
  readonly ref: string;
  /** OCCURRENCE: one or more overlapping occurrences. WHOLE_VALUE: a trusted field hint covering a value. */
  readonly kind: 'OCCURRENCE' | 'WHOLE_VALUE';
  /** Detector sources that contributed evidence, in candidate order. Carries no value or key name. */
  readonly sources: readonly NormalizedCandidate['source'][];
  /** Every contributing detector record, in candidate order, exactly as its producer emitted it. */
  readonly detectorEvidence: readonly ContributingEvidence[];
  readonly location: UnitLocation;
  readonly classification: Classification;
}
export interface ClassificationUnitResult {
  /** COMPLETE means every supplied candidate was composed into a unit. Never "clean", never an authorization. */
  readonly status: 'COMPLETE' | 'PARTIAL' | 'FAILURE';
  readonly reasons: readonly string[];
  readonly units: readonly ClassificationUnit[];
  /** Everything the composition did not inspect, including units dropped by the unit cap. */
  readonly uninspected: readonly OpaqueLocation[];
}
export interface ClassificationUnitRequest {
  /** A #6/#7 composition result for one request. Read once, defensively; never trusted to be well formed. */
  readonly detection: unknown;
  /**
   * Privacy-safe opaque reference for this request, never a value or path. Unit references and configured
   * sensitivity evidence are derived from it, so a trusted integration must pass a fresh value per request:
   * that, and nothing in this module, is what keeps units uncorrelatable across requests.
   */
  readonly inputRef: string;
  readonly scope: CandidateScope;
  /** Trusted interaction/source context for the accepted composer. Separately supplied; not derived from text. */
  readonly context: ClassificationContext;
  readonly contactSensitivity?: ContactSensitivityHandle;
  readonly registry?: SubtypeRegistry;
}
function failure(reason: string): ClassificationUnitResult {
  return Object.freeze({ status: 'FAILURE', reasons: Object.freeze([reason]), units: Object.freeze([]),
    uninspected: Object.freeze([]) });
}
/**
 * The configured claim for one contact candidate: the candidate's own semantic type and subtype plus the
 * sensitivity the trusted configuration assigns to that subtype. It completes a claim #37 deliberately leaves
 * without one, and can never assert a class or subtype the detector did not find.
 */
function completionOf(member: Read1, state: SensitivityState, unitRef: string, index: number, ordinal: number): ContributingEvidence | null {
  if (member.semanticType !== 'PERSON' || member.subtype === null) return null;
  const sensitivity = state.bySubtype.get(member.subtype);
  if (sensitivity === undefined) return null;
  return Object.freeze({
    version: 1 as const,
    id: `${CONTACT_SENSITIVITY_PRODUCER.id}.${member.subtype.toLowerCase()}.${index}.${ordinal}`,
    status: 'FOUND' as const,
    provenance: Object.freeze({ inputRef: unitRef, producerId: CONTACT_SENSITIVITY_PRODUCER.id,
      producerVersion: CONTACT_SENSITIVITY_PRODUCER.version }),
    claim: Object.freeze({ semanticType: member.semanticType, subtype: member.subtype, sensitivity }),
  });
}

export function composeClassificationUnits(request: ClassificationUnitRequest): ClassificationUnitResult {
  let fields: Record<string, unknown> | null = null;
  try { fields = data(request, ['detection', 'inputRef', 'scope', 'context'], ['contactSensitivity', 'registry']); }
  catch { return failure('INVALID_REQUEST'); }
  if (!fields) return failure('INVALID_REQUEST');
  const detection = fields.detection;
  const inputRef = fields.inputRef;
  const handle = fields.contactSensitivity;
  const registry = fields.registry;
  if (!label(inputRef, 1024)) return failure('INVALID_REQUEST');
  const tenantRef = data(fields.scope, ['tenantRef', 'projectRef']);
  if (!tenantRef || !label(tenantRef.tenantRef) || !label(tenantRef.projectRef)) return failure('INVALID_SCOPE');
  const boundary = data(fields.context, ['interactionRef', 'sourceRef', 'trust']);
  if (!boundary || !label(boundary.interactionRef) || !label(boundary.sourceRef, 1024) ||
      !inSet(boundary.trust, TRUST_LEVELS)) return failure('INVALID_CONTEXT');
  const composerContext: ClassificationContext = Object.freeze({ interactionRef: boundary.interactionRef,
    sourceRef: boundary.sourceRef, trust: boundary.trust });

  const reasons = new Set<string>();
  let state: SensitivityState | null = null;
  if (handle !== undefined) {
    state = (typeof handle === 'object' && handle !== null ? sensitivityRegistry.get(handle) : undefined) ?? null;
    if (!state) reasons.add('CONTACT_SENSITIVITY_INVALID_CONFIG');
    else if (state.scope.tenantRef !== tenantRef.tenantRef || state.scope.projectRef !== tenantRef.projectRef) {
      // Another tenant's or project's configuration must never resolve here, and the caller must see it failed.
      reasons.add('CONTACT_SENSITIVITY_SCOPE_MISMATCH');
      state = null;
    }
  }

  const result = data(detection, ['status', 'reasons', 'candidates', 'uninspected'], ['contentType']);
  if (!result || !inSet(result.status, ['COMPLETE', 'PARTIAL', 'FAILURE'])) return failure('INVALID_DETECTION');
  const detectionReasons = list(result.reasons, MAX_REASONS);
  const candidates = list(result.candidates, MAX_CANDIDATES);
  const uninspected = list(result.uninspected, MAX_OPAQUE);
  if (!detectionReasons || !candidates || !uninspected) return failure('INVALID_DETECTION');
  const opaque: OpaqueLocation[] = [];
  for (const item of uninspected) {
    const location = opaqueOf(item);
    if (!location) return failure('INVALID_DETECTION');
    opaque.push(location);
  }
  const copiedReasons = (items: readonly unknown[]): void => {
    for (const reason of items) reasons.add(reasonCode(reason) ?? 'DETECTION_UNREADABLE_REASON');
  };
  if (result.status === 'FAILURE') {
    // A failed composition has no candidates; its reasons are still reported, never as a clean result.
    copiedReasons(detectionReasons);
    reasons.add('DETECTION_FAILURE');
    return Object.freeze({ status: 'FAILURE', reasons: Object.freeze([...reasons].sort()), units: Object.freeze([]),
      uninspected: Object.freeze(opaque) });
  }
  copiedReasons(detectionReasons);
  // A `COMPLETE` claim contradicted by carried opaque coverage is not accepted as complete: the seam never
  // reports an uninspected range without a reason, so this combination can only come from a hand-built result.
  if (result.status === 'COMPLETE' && opaque.length > 0) reasons.add('UNINSPECTED_COVERAGE');

  /* ---------- Group candidates into units ---------- */

  interface Group { kind: 'OCCURRENCE' | 'WHOLE_VALUE'; occurrence: Span; members: Read1[] }
  const lines = new Map<string, Group[]>();
  for (const item of candidates) {
    const candidate = candidateOf(item);
    if (!candidate) return failure('INVALID_DETECTION');
    // The line is the text unit one detector pass read. Everything that can differ about how a candidate was
    // located is part of the key, so two candidates on one line share a view location by construction.
    const key = candidate.field ?
      `f|${candidate.view.viewId}|${candidate.view.representation}|${candidate.field.format}|` +
        `${candidate.field.span.start}-${candidate.field.span.end}|${candidate.field.pathRef}` :
      `v|${candidate.view.viewId}|${candidate.view.representation}|${candidate.view.form}|` +
        candidate.view.encodingPath.join('>');
    let groups = lines.get(key);
    if (!groups) lines.set(key, groups = []);
    const whole = candidate.basis === 'FIELD_HINT';
    let target: Group | null = null;
    if (!whole) {
      // Join the most recent group this candidate relates to. Scanning backwards is what keeps two candidates
      // covering the *same* occurrence together even when a nested candidate (a domain inside an address, say)
      // was grouped between them, and it still refuses every nested or disjoint candidate.
      for (let index = groups.length - 1; index >= 0; index--) {
        const group = groups[index]!;
        if (group.kind !== 'OCCURRENCE' || group.members.length >= MAX_UNIT_EVIDENCE) continue;
        if (!crosses(group.occurrence, candidate.occurrence) &&
            !group.members.some((member) => sameSpan(member.occurrence, candidate.occurrence))) continue;
        target = group;
        break;
      }
    }
    if (target) {
      target.members.push(candidate);
      target.occurrence = { start: Math.min(target.occurrence.start, candidate.occurrence.start),
        end: Math.max(target.occurrence.end, candidate.occurrence.end) };
      continue;
    }
    groups.push({ kind: whole ? 'WHOLE_VALUE' : 'OCCURRENCE', occurrence: candidate.occurrence,
      members: [candidate] });
  }

  /* ---------- Compose one unit per group ---------- */

  const inputDigest = createHash('sha256').update(inputRef).digest('hex');
  const units: ClassificationUnit[] = [];
  for (const groups of lines.values()) {
    for (const group of groups) {
      const index = units.length;
      if (index >= MAX_UNITS) {
        // Truncated coverage is an inspection gap per dropped candidate, never a quiet success.
        reasons.add('UNIT_LIMIT');
        if (opaque.length < MAX_OPAQUE) {
          opaque.push(Object.freeze({ reason: 'UNIT_LIMIT', viewId: group.members[0]!.view.viewId,
            viewSpan: unionSpan(group.members), original: group.members[0]!.original }));
        } else reasons.add('UNINSPECTED_TRUNCATED');
        continue;
      }
      const ref = `cu-${createHash('sha256').update(`${inputDigest}\u0000unit\u0000${index}`).digest('hex').slice(0, 32)}-${index}`;
      const { location, unresolved } = unitLocation(group.members);
      if (unresolved) {
        reasons.add('UNIT_LOCATION_UNRESOLVED');
        if (opaque.length < MAX_OPAQUE) {
          // One contributor's own original location, never a synthesized one: this unit's region could not be
          // stated in the original text, and the first contributor's location is real metadata.
          opaque.push(Object.freeze({ reason: 'UNIT_LOCATION_UNRESOLVED', viewId: location.viewId,
            viewSpan: location.span, original: group.members[0]!.original }));
        } else reasons.add('UNINSPECTED_TRUNCATED');
      }
      const sources = [...new Set(group.members.map((member) => member.source))];
      // The composed channel carries a configured completion where one applies and the detector's own record
      // everywhere else; the detector records themselves are always retained on the unit.
      const detectorEvidence = [...group.members.map((member) => member.evidence)];
      const channel: object[] = group.members.map((member, ordinal) =>
        (state ? completionOf(member, state, ref, index, ordinal) : null) ?? member.evidence);
      let classification: Classification;
      try {
        classification = registry === undefined ?
          composeClassification({ detectorEvidence: channel }, composerContext) :
          composeClassification({ detectorEvidence: channel }, composerContext, registry as SubtypeRegistry);
      } catch { return failure('COMPOSITION_FAILURE'); }
      units.push(Object.freeze({ ref, kind: group.kind, sources: Object.freeze(sources),
        detectorEvidence: Object.freeze(detectorEvidence), location, classification }));
    }
  }
  return Object.freeze({ status: reasons.size ? 'PARTIAL' : 'COMPLETE', reasons: Object.freeze([...reasons].sort()),
    units: Object.freeze(units), uninspected: Object.freeze(opaque) });
}
