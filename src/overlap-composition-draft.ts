/**
 * #114 overlap composition DRAFT (PROPOSED, unwired).
 *
 * Pure, bounded and NON-ENFORCING. It composes *already emitted* detector findings into overlap regions,
 * keeps every finding's own evidence and source location, and derives a **coverage obligation set** per
 * region. It selects no treatment, ranks no score, creates no mapping, authorizes nothing and sends
 * nothing. It calls only accepted v1 seams: #3 `composeClassification` for per-region classification and
 * #7 `parseStructured`/`rewriteFieldValues` for the one rewrite path that already exists. Anything those
 * seams cannot cover becomes a typed refusal, never a weaker outcome.
 *
 * The three rules this draft exists to state, all deterministic:
 * 1. **No winner.** Overlapping findings are a *set union* of obligations over one covered region. There
 *    is no score, confidence, arrival order or detector priority anywhere in the result, so a wider
 *    PERSON/URL/engineering span can never displace a nested native SECRET finding. #6/#8 candidates carry
 *    no score at all, and a confidence attached by any producer is neither read nor emitted.
 * 2. **No loss.** Every accepted finding keeps its own evidence reference, producer, input reference and
 *    view/field/original location. Consolidation is expressed by the region, never by deleting a member.
 *    Findings in different coordinate spaces that overlap the same original bytes are a typed refusal with
 *    both sets kept, not a merge, and a finding this draft cannot read or cannot recognise is counted as
 *    unrepresented and blocks the rewrite rather than being skipped.
 * 3. **No partial release.** A rewrite is all-or-nothing over the regions, the replacement is one opaque
 *    constant the trusted integration chooses, and the rewriter's own verification plus this module's
 *    re-derived plan, independent reparse and surviving-run post-condition decide it. Any doubt is a typed
 *    refusal that leaves the bytes untransformed for #13 to withhold.
 *
 * It composes over, and does not replace, the accepted per-occurrence classification-unit seam: units stay
 * the policy input per occurrence, regions are the coverage input for a rewrite, and #13 owes both.
 *
 * STATUS: draft for review, linked to #114 and its owners #3/#7/#8/#37/#40/#68. It is **not** wired into
 * classification v1, policy or any adapter. Proposed decision 010 and the taxonomy/multidimensional drafts
 * are not adopted here: this module has no treatment vocabulary, no fidelity predicates and no placeholder
 * grammar, so final treatment/fidelity semantics stay behind #66/#68 and the #13 engine.
 */
import { createHash } from 'node:crypto';
import { SENSITIVITIES, composeClassification, type Classification, type ClassificationContext,
  type Sensitivity } from './classification.js';
import { FORMATS, isParseHost, parseStructured, rewriteFieldValues, type Format } from './structured-parsers.js';
import type { Encoding } from './normalization.js';
import type { NormalizedCandidate, OriginalLocation, ParsedFieldLocation, Span, ViewLocation }
  from './normalized-detection.js';

export const OVERLAP_DRAFT_VERSION = 'hylja.overlap-composition-draft.v1' as const;
/** Findings accepted per composition. More is a typed rejection, never a silent truncation. */
export const MAX_FINDINGS = 512;
/** Members per region before that region stops being reported (`REGION_MEMBER_LIMIT`). */
export const MAX_REGION_MEMBERS = 1024;
/** Member pairs classified per region before relation reporting stops (`RELATION_LIMIT`). */
export const MAX_RELATION_PAIRS = 4096;
/** Regions per composition; the cross-space comparison is bounded by this and reports `REGION_LIMIT`. */
export const MAX_REGIONS = 256;
/** Opaque locations accepted per composition. */
export const MAX_UNINSPECTED = 256;
/**
 * Longest accepted source string, in UTF-16 code units: 16 777 216, which is the largest `maxInputUnits`
 * #6 accepts as an opt-in budget, in the same unit (#6 counts UTF-16 code units for string input and bytes
 * only for byte input). It is not #6's *default* ceiling, which is 1 048 576 units: a source past that
 * default becomes a #6 view only when the trusted caller opted into the larger budget, and otherwise #6
 * reports `NORMALIZATION_INPUT_TOO_LARGE` and this module composes no finding from it. A source this large
 * can exhaust #7's cooperative parse deadline, which refuses the parse instead of truncating it; that
 * refusal surfaces here as `SOURCE_NOT_COMPLETE`.
 */
export const MAX_SOURCE_UNITS = 1 << 24;
/** Floor for the surviving-run check: a covered original always counts as surviving in full below this. */
export const MIN_ECHO_WINDOW = 8;
/** Longest accepted replacement constant. */
export const MAX_REPLACEMENT_UNITS = 64;
/** Windows the rewrite post-condition may probe before it refuses rather than under-checking. */
export const MAX_ECHO_PROBES = 1 << 16;

const TRUST_LEVELS = ['CONTROL', 'TRUSTED', 'VERIFIED_EXTERNAL', 'UNTRUSTED', 'HOSTILE'] as const;
const SCOPES = ['request', 'session', 'project', 'tenant'] as const;
/** The #6 candidate sources, enumerated from the accepted type so a new #6 source cannot be dropped here. */
export const FINDING_SOURCES =
  ['SECRET', 'INFRASTRUCTURE', 'CONTACT', 'CONFIGURED'] as const satisfies readonly NormalizedCandidate['source'][];
export type FindingSource = NormalizedCandidate['source'];
/** Compile-time exhaustiveness: a #6 source missing from FINDING_SOURCES fails the build, not a release. */
type UnlistedFindingSource = Exclude<FindingSource, (typeof FINDING_SOURCES)[number]>;
type AssertNever<T extends never> = T;
type UnlistedFindingSourceIsNever = AssertNever<UnlistedFindingSource>;
/** The assertion is part of this annotation, so the exhaustiveness check is a read rather than dead code. */
const SOURCES: readonly (FindingSource | UnlistedFindingSourceIsNever)[] = FINDING_SOURCES;
const CONTROL = /[\u0000-\u001f\u007f]/u;
/**
 * Original-location families. `EXACT` and `COVER` differ in precision, not in coordinate space: a #6
 * field candidate in the root view is a covering span of the same offsets as a view-level candidate.
 */
const FAMILIES: Readonly<Record<OriginalLocation['kind'], string>> = Object.freeze({
  ORIGINAL_EXACT: 'ORIGINAL', ORIGINAL_COVER: 'ORIGINAL', ENCODED_RUNS: 'ENCODED_RUNS',
  UTF8_TEXT: 'UTF8_TEXT', UTF8_ENCODED_RUNS: 'UTF8_ENCODED_RUNS',
});
const FAMILY_ORDER: readonly string[] = ['ORIGINAL', 'UTF8_TEXT', 'ENCODED_RUNS', 'UTF8_ENCODED_RUNS'];

/* ---------- Result types ---------- */

export type OverlapCompositionStatus = 'COMPOSED' | 'UNRESOLVED' | 'REJECTED';
export type RegionRelation = 'IDENTICAL' | 'CONTAINING' | 'CONTAINED' | 'PARTIAL';

export interface OverlapMember {
  /** Deterministic `region-N-mK` reference in member order, never derived from a source value. */
  readonly memberRef: string;
  /** The #3 evidence id this member carries, retained even when the span is consolidated. */
  readonly evidenceRef: string;
  readonly producerId: string;
  readonly inputRef: string;
  readonly source: (typeof SOURCES)[number];
  readonly semanticType: string;
  readonly subtype?: string;
  readonly sensitivity: Sensitivity | 'UNKNOWN';
  readonly rule?: string;
  readonly basis?: string;
  /** View span. Offsets are comparable only inside this region's coordinate space. */
  readonly span: Span;
  readonly view: ViewLocation;
  readonly original: OriginalLocation;
  readonly field?: ParsedFieldLocation;
  /** True when another accepted member has the same detector identity and span. */
  readonly duplicateIdentity: boolean;
}

export interface RegionObligations {
  /** Union of claimed semantic types, sorted. A union, never a maximum and never a winner. */
  readonly semanticTypes: readonly string[];
  readonly subtypes: readonly string[];
  /** Highest claimed sensitivity. Lower claims stay visible in `members`. */
  readonly highestSensitivity: Sensitivity | 'UNKNOWN';
  /** True when any member is a credential, claims SECRET, or is marked non-reversible. */
  readonly nonReversibleFloor: boolean;
  readonly conflicts: readonly string[];
}

export interface OverlapRegion {
  readonly regionRef: string;
  /** Privacy-safe coordinate-space id `v<viewId>|<family>`. Offsets compare only inside one space. */
  readonly coordinateSpace: string;
  readonly viewId: number;
  readonly span: Span;
  readonly original: OriginalLocation;
  readonly encodingPath: readonly Encoding[];
  readonly representations: readonly ViewLocation['representation'][];
  readonly fieldFormats: readonly Format[];
  readonly members: readonly OverlapMember[];
  readonly obligations: RegionObligations;
  /** Ordered per-region #3 composition of exactly these members' evidence. */
  readonly composed: Classification;
  readonly relations: readonly RegionRelation[];
}

export interface OverlapRefusal {
  readonly refusalRef: string;
  readonly reason: string;
  readonly regionRefs: readonly string[];
}

export interface OverlapComposition {
  readonly version: typeof OVERLAP_DRAFT_VERSION;
  /**
   * COMPOSED: every finding was read and every region resolved. UNRESOLVED: a region, an overlap or a
   * finding needs #4 policy or #13 transformation; nothing accepted was dropped. REJECTED: the request was
   * unreadable, so no finding was composed at all.
   */
  readonly status: OverlapCompositionStatus;
  readonly reasons: readonly string[];
  /** Candidate recall measured *before* consolidation and before any policy or egress outcome. */
  readonly retention: Readonly<{
    received: number;
    retained: number;
    rejected: number;
    /**
     * Received findings no region represented: unreadable or unrecognised ones, and any accepted past a
     * bound. The rewrite refuses past a non-zero value rather than releasing the coverage it does have.
     */
    uncomposed: number;
    duplicateEvidence: number;
    bySource: Readonly<Record<string, number>>;
    bySemanticType: Readonly<Record<string, number>>;
  }>;
  readonly regions: readonly OverlapRegion[];
  /** Touching but not overlapping regions inside one coordinate space, in region order. */
  readonly adjacencies: readonly Readonly<{ regionRefs: readonly [string, string] }>[];
  readonly refusals: readonly OverlapRefusal[];
}

export interface OverlapCompositionRequest {
  /** Emitted detector findings in the #6 candidate shape. Unknown extra keys are ignored, never trusted. */
  readonly findings: readonly unknown[];
  /** Separately bound trusted context, exactly as #3 requires. */
  readonly context: ClassificationContext;
  /** #6 opaque locations. A protected region inside one is an unresolved overlap, not a clean region. */
  readonly uninspected?: readonly unknown[];
}

export interface RegionRewriteDecision {
  readonly regionRef: string;
  readonly decision: 'REPLACE_FIELD_VALUE' | 'REFUSED';
  readonly reasons: readonly string[];
  readonly fieldSpan?: Span;
  /** Source-bound digest of the #7 key path. Key names are payload content and are never emitted. */
  readonly fieldRef?: string;
  readonly evidenceRefs: readonly string[];
}

export interface OverlapRewritePlan {
  readonly version: typeof OVERLAP_DRAFT_VERSION;
  readonly status: 'PLANNED' | 'REFUSED';
  readonly reasons: readonly string[];
  readonly sourceDigest: string;
  readonly format: Format;
  /** The caller's opaque constant. It carries no part of any covered original (checked before planning). */
  readonly replacement: string;
  readonly replacementDigest: string;
  readonly regions: readonly RegionRewriteDecision[];
}

export interface OverlapRewriteProvenance {
  readonly version: typeof OVERLAP_DRAFT_VERSION;
  readonly sourceDigest: string;
  readonly replacementDigest: string;
  readonly format: Format;
  readonly regions: readonly Readonly<{ regionRef: string; fieldSpan: Span; fieldRef: string;
    evidenceRefs: readonly string[] }>[];
  readonly rewrittenFields: number;
}

export type AppliedRewrite =
  | Readonly<{ status: 'REWRITTEN'; text: string; provenance: OverlapRewriteProvenance }>
  | Readonly<{ status: 'REFUSED'; reasons: readonly string[] }>;

/* ---------- Bounded, non-echoing readers ---------- */

function plain(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null ? value as Record<string, unknown> : null;
}
/** Descriptor read, never a getter: an accessor or a throwing Proxy trap cannot run, and cannot echo. */
function own(object: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}
function label(value: unknown, limit = 256): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && value.trim() === value &&
    !CONTROL.test(value);
}
function oneOf<T extends string>(value: unknown, set: readonly T[]): value is T {
  return typeof value === 'string' && (set as readonly string[]).includes(value);
}
interface List { values: unknown[]; length: number; invalid: boolean }
function list(value: unknown, max: number): List {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    return { values: [], length: 0, invalid: true };
  }
  // One descriptor read decides both the bound and the loop length, so a Proxy cannot grow this mid-read.
  const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0) {
    return { values: [], length: 0, invalid: true };
  }
  if (length > max) return { values: [], length, invalid: true };
  const values: unknown[] = [];
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return { values, length, invalid: true };
    values.push(descriptor.value);
  }
  return { values, length, invalid: false };
}
function readSpan(value: unknown): Span | null {
  const object = plain(value);
  if (!object) return null;
  const start = own(object, 'start');
  const end = own(object, 'end');
  if (typeof start !== 'number' || !Number.isSafeInteger(start) || start < 0 || start >= MAX_SOURCE_UNITS ||
    typeof end !== 'number' || !Number.isSafeInteger(end) || end <= start || end > MAX_SOURCE_UNITS) return null;
  return Object.freeze({ start, end });
}
function readView(value: unknown): ViewLocation | null {
  const object = plain(value);
  if (!object) return null;
  const viewId = own(object, 'viewId');
  const span = readSpan(own(object, 'span'));
  const representation = own(object, 'representation');
  const form = own(object, 'form');
  const path = list(own(object, 'encodingPath'), 8);
  if (typeof viewId !== 'number' || !Number.isSafeInteger(viewId) || viewId < 0 ||
    !span || !oneOf(representation, ['RAW', 'FOLDED'] as const) || !oneOf(form, ['TEXT', 'STRINGS'] as const) ||
    path.invalid || !path.values.every((item) => label(item, 32))) return null;
  return Object.freeze({ viewId, span, representation, form, encodingPath: Object.freeze(path.values) as Encoding[] });
}
function readOriginal(value: unknown): OriginalLocation | null {
  const object = plain(value);
  if (!object) return null;
  const kind = own(object, 'kind');
  if (kind === 'ORIGINAL_EXACT' || kind === 'ORIGINAL_COVER') {
    const span = readSpan(own(object, 'span'));
    return span ? Object.freeze({ kind, span }) : null;
  }
  if (kind === 'UTF8_TEXT') {
    const span = readSpan(own(object, 'span'));
    const coverage = own(object, 'coverage');
    return span && oneOf(coverage, ['EXACT', 'COVER'] as const) ? Object.freeze({ kind, span, coverage }) : null;
  }
  if (kind === 'ENCODED_RUNS' || kind === 'UTF8_ENCODED_RUNS') {
    const runs = list(own(object, 'spans'), 1024);
    if (runs.invalid || runs.values.length === 0) return null;
    const spans: Span[] = [];
    for (const item of runs.values) {
      const span = readSpan(item);
      if (!span) return null;
      spans.push(span);
    }
    return Object.freeze({ kind, spans: Object.freeze(spans) });
  }
  return null;
}
function readField(value: unknown): ParsedFieldLocation | null {
  const object = plain(value);
  if (!object) return null;
  const format = own(object, 'format');
  const pathRef = own(object, 'pathRef');
  const hintSource = own(object, 'hintSource');
  const hintDepth = own(object, 'hintDepth');
  const highRisk = own(object, 'highRisk');
  const span = readSpan(own(object, 'span'));
  const valueSpan = readSpan(own(object, 'valueSpan'));
  const verbatim = own(object, 'verbatim');
  if (!oneOf(format, FORMATS) || !label(pathRef, 128) || !oneOf(hintSource, ['PATH', 'NAME_SIBLING', 'NONE'] as const) ||
    typeof hintDepth !== 'number' || !Number.isSafeInteger(hintDepth) || hintDepth < -1 || hintDepth > 64 ||
    typeof highRisk !== 'boolean' || !span || !valueSpan || typeof verbatim !== 'boolean') return null;
  return Object.freeze({ format, pathRef, hintSource, hintDepth, highRisk, span, valueSpan, verbatim });
}
interface ReadEvidence {
  evidenceRef: string;
  producerId: string;
  producerVersion: string;
  inputRef: string;
  semanticType: string;
  subtype?: string;
  sensitivity: Sensitivity | 'UNKNOWN';
  nonReversible: boolean;
}
function readEvidence(value: unknown): ReadEvidence | null {
  const object = plain(value);
  if (!object || own(object, 'version') !== 1 || own(object, 'status') !== 'FOUND') return null;
  const id = own(object, 'id');
  const provenance = plain(own(object, 'provenance'));
  const claim = plain(own(object, 'claim'));
  if (!label(id, 256) || !provenance || !claim) return null;
  const inputRef = own(provenance, 'inputRef');
  const producerId = own(provenance, 'producerId');
  const producerVersion = own(provenance, 'producerVersion');
  const semanticType = own(claim, 'semanticType');
  if (!label(inputRef, 1024) || !label(producerId, 256) || !label(producerVersion, 256) ||
    !label(semanticType, 64)) return null;
  const subtype = own(claim, 'subtype');
  if (subtype !== undefined && !label(subtype, 64)) return null;
  const sensitivity = own(claim, 'sensitivity');
  if (sensitivity !== undefined && !oneOf(sensitivity, SENSITIVITIES)) return null;
  if (own(claim, 'scope') !== undefined && !oneOf(own(claim, 'scope'), SCOPES)) return null;
  const reversible = own(claim, 'reversible');
  if (reversible !== undefined && typeof reversible !== 'boolean') return null;
  // A detector confidence is deliberately not read: this draft has no score surface to trade off.
  return { evidenceRef: id, producerId, producerVersion, inputRef, semanticType,
    ...(subtype === undefined ? {} : { subtype }),
    sensitivity: (sensitivity ?? 'UNKNOWN') as Sensitivity | 'UNKNOWN',
    nonReversible: sensitivity === 'SECRET' || semanticType === 'CREDENTIAL_OR_SECRET' || reversible === true };
}
interface ReadFinding {
  source: FindingSource;
  rule?: string;
  basis?: string;
  view: ViewLocation;
  original: OriginalLocation;
  field?: ParsedFieldLocation;
  evidence: ReadEvidence;
}
/** A finding whose source name is readable but is not a #6 source: kept visible, never silently dropped. */
type FindingProblem = 'INVALID_FINDING' | 'UNKNOWN_FINDING_SOURCE';
function readFinding(value: unknown): { finding: ReadFinding } | { problem: FindingProblem } {
  const object = plain(value);
  if (!object) return { problem: 'INVALID_FINDING' };
  const source = own(object, 'source');
  const view = readView(own(object, 'view'));
  const original = readOriginal(own(object, 'original'));
  const evidence = readEvidence(own(object, 'evidence'));
  if (!oneOf(source, SOURCES)) {
    // An unknown source is a #6 contract change this draft has not been reviewed against. Reporting it
    // separately keeps it visible instead of folding it into the unreadable bucket.
    return typeof source === 'string' && label(source, 64) ? { problem: 'UNKNOWN_FINDING_SOURCE' }
      : { problem: 'INVALID_FINDING' };
  }
  if (!view || !original || !evidence) return { problem: 'INVALID_FINDING' };
  const subtype = own(object, 'subtype');
  const rule = own(object, 'rule');
  const basis = own(object, 'basis');
  if (subtype !== undefined && !label(subtype, 64)) return { problem: 'INVALID_FINDING' };
  if (rule !== undefined && !label(rule, 128)) return { problem: 'INVALID_FINDING' };
  if (basis !== undefined && !label(basis, 64)) return { problem: 'INVALID_FINDING' };
  const rawField = own(object, 'field');
  const field = rawField === undefined ? undefined : readField(rawField);
  if (rawField !== undefined && !field) return { problem: 'INVALID_FINDING' };
  return { finding: { source, ...(rule === undefined ? {} : { rule }), ...(basis === undefined ? {} : { basis }), view,
    original, ...(field ? { field } : {}), evidence } };
}

/* ---------- Composition ---------- */

function empty(): OverlapComposition {
  return Object.freeze({ version: OVERLAP_DRAFT_VERSION, status: 'REJECTED' as const,
    reasons: Object.freeze(['INVALID_REQUEST']),
    retention: Object.freeze({ received: 0, retained: 0, rejected: 0, uncomposed: 0, duplicateEvidence: 0,
      bySource: Object.freeze({}), bySemanticType: Object.freeze({}) }),
    regions: Object.freeze([]), adjacencies: Object.freeze([]), refusals: Object.freeze([]) });
}
/** Runs beyond this count are compared through their bounding span, which over-reports overlap, never under. */
const MAX_ENVELOPE_SPANS = 64;
function envelopeOf(original: OriginalLocation): readonly Span[] {
  if (original.kind !== 'ENCODED_RUNS' && original.kind !== 'UTF8_ENCODED_RUNS') return [original.span];
  if (original.spans.length <= MAX_ENVELOPE_SPANS) return original.spans;
  let start = Infinity;
  let end = -Infinity;
  for (const span of original.spans) {
    start = Math.min(start, span.start);
    end = Math.max(end, span.end);
  }
  return [Object.freeze({ start, end })];
}
function exactOf(original: OriginalLocation): boolean {
  return original.kind === 'ORIGINAL_EXACT' || (original.kind === 'UTF8_TEXT' && original.coverage === 'EXACT');
}
function spansOverlap(left: readonly Span[], right: readonly Span[]): boolean {
  for (const one of left) for (const other of right) {
    if (one.start < other.end && other.start < one.end) return true;
  }
  return false;
}
/** The union of the members' original envelopes, never narrower than any member's. */
function unionOriginal(members: readonly ReadFinding[]): OriginalLocation {
  const kind = members[0]!.original.kind;
  if (kind === 'ENCODED_RUNS' || kind === 'UTF8_ENCODED_RUNS') {
    const unique = new Map<string, Span>();
    for (const member of members) for (const span of envelopeOf(member.original)) {
      unique.set(`${span.start}-${span.end}`, span);
    }
    return Object.freeze({ kind, spans: Object.freeze([...unique.values()]
      .sort((left, right) => left.start - right.start || left.end - right.end)) });
  }
  let start = Infinity;
  let end = -Infinity;
  let exact = true;
  for (const member of members) {
    for (const span of envelopeOf(member.original)) {
      start = Math.min(start, span.start);
      end = Math.max(end, span.end);
    }
    if (!exactOf(member.original)) exact = false;
  }
  const span = Object.freeze({ start, end });
  if (kind === 'UTF8_TEXT') return Object.freeze({ kind, span, coverage: exact ? 'EXACT' : 'COVER' });
  return Object.freeze({ kind: exact ? 'ORIGINAL_EXACT' : 'ORIGINAL_COVER', span });
}
function relationsOf(members: readonly ReadFinding[], reasons: Set<string>): readonly RegionRelation[] {
  const found = new Set<RegionRelation>();
  let pairs = 0;
  for (let left = 0; left < members.length; left++) {
    for (let right = left + 1; right < members.length; right++) {
      // A real work bound, not a count of distinct relation kinds (of which there are only four).
      if (pairs >= MAX_RELATION_PAIRS) {
        reasons.add('RELATION_LIMIT');
        return Object.freeze([...found].sort());
      }
      pairs++;
      const one = members[left]!.view.span;
      const other = members[right]!.view.span;
      if (one.start === other.start && one.end === other.end) found.add('IDENTICAL');
      else if (one.start <= other.start && one.end >= other.end) found.add('CONTAINING');
      else if (other.start <= one.start && other.end >= one.end) found.add('CONTAINED');
      else if (one.start < other.end && other.start < one.end) found.add('PARTIAL');
    }
  }
  return Object.freeze([...found].sort());
}
function obligationsOf(members: readonly ReadFinding[]): RegionObligations {
  const semanticTypes = new Set<string>();
  const subtypes = new Set<string>();
  const sensitivities = new Set<Sensitivity>();
  let nonReversibleClaims = 0;
  for (const member of members) {
    semanticTypes.add(member.evidence.semanticType);
    if (member.evidence.subtype !== undefined) subtypes.add(member.evidence.subtype);
    if (member.evidence.sensitivity !== 'UNKNOWN') sensitivities.add(member.evidence.sensitivity);
    if (member.evidence.nonReversible) nonReversibleClaims++;
  }
  const conflicts = new Set<string>();
  if (semanticTypes.size > 1) conflicts.add('SEMANTIC_TYPE');
  if (subtypes.size > 1) conflicts.add('SUBTYPE');
  if (sensitivities.size > 1) conflicts.add('SENSITIVITY');
  const highest = sensitivities.size === 0 ? 'UNKNOWN' : SENSITIVITIES[[...sensitivities]
    .reduce((top, value) => Math.max(top, SENSITIVITIES.indexOf(value)), 0)]!;
  return Object.freeze({ semanticTypes: Object.freeze([...semanticTypes].sort()),
    subtypes: Object.freeze([...subtypes].sort()), highestSensitivity: highest,
    nonReversibleFloor: nonReversibleClaims > 0, conflicts: Object.freeze([...conflicts].sort()) });
}
/**
 * Detector identity and occurrence, mirroring the accepted #6 de-duplication identity: view id and
 * representation, source, semantic type and subtype, rule, in-view span, original envelope and, for a #7
 * field, its format, field span, path digest **and the in-value occurrence offsets**. Two occurrences of one
 * value inside one decoded field value share a view span and a field span, so without the in-value offsets
 * they would collapse into one another here as well.
 */
function identityOf(finding: ReadFinding): string {
  return `${finding.view.viewId}|${finding.view.representation}|${finding.source}|` +
    `${finding.evidence.semanticType}|${finding.evidence.subtype ?? ''}|${finding.rule ?? ''}|` +
    `${finding.view.span.start}-${finding.view.span.end}|${originalKey(finding.original)}|` +
    `${finding.field ? `${finding.field.format}|${finding.field.pathRef}|${finding.field.span.start}-` +
      `${finding.field.span.end}|${finding.field.valueSpan.start}-${finding.field.valueSpan.end}` : ''}`;
}
function originalKey(original: OriginalLocation): string {
  if (original.kind === 'ENCODED_RUNS' || original.kind === 'UTF8_ENCODED_RUNS') {
    return `${original.kind}:${original.spans.map((span) => `${span.start}-${span.end}`).join(',')}`;
  }
  return original.kind === 'UTF8_TEXT'
    ? `${original.kind}:${original.coverage}:${original.span.start}-${original.span.end}`
    : `${original.kind}:${original.span.start}-${original.span.end}`;
}
function sortedCounts(counts: Record<string, number>): Readonly<Record<string, number>> {
  return Object.freeze(Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right))));
}

/**
 * Compose emitted detector findings into overlap regions. Never throws, never echoes an input value and
 * never drops an accepted finding: a request it cannot read is REJECTED, and a finding it cannot read is
 * counted, refused and reported, so a caller can see that coverage was lost.
 */
export function composeOverlapRegions(request: unknown): OverlapComposition {
  try {
    const object = plain(request);
    const context = object ? plain(own(object, 'context')) : null;
    if (!object || !context) return empty();
    const interactionRef = own(context, 'interactionRef');
    const sourceRef = own(context, 'sourceRef');
    const trust = own(context, 'trust');
    if (!label(interactionRef) || !label(sourceRef, 1024) || !oneOf(trust, TRUST_LEVELS)) {
      return Object.freeze({ ...empty(), reasons: Object.freeze(['INVALID_CONTEXT']) });
    }
    const findings = list(own(object, 'findings'), MAX_FINDINGS);
    if (findings.invalid) {
      return Object.freeze({ ...empty(), reasons: Object.freeze([findings.length > MAX_FINDINGS ?
        'FINDING_LIMIT' : 'INVALID_REQUEST']) });
    }
    const opaqueRequest = own(object, 'uninspected');
    const opaque = opaqueRequest === undefined ? { values: [], length: 0, invalid: false }
      : list(opaqueRequest, MAX_UNINSPECTED);
    if (opaque.invalid) return Object.freeze({ ...empty(), reasons: Object.freeze(['INVALID_UNINSPECTED']) });
    const typedContext: ClassificationContext = { interactionRef, sourceRef, trust };

    const reasons = new Set<string>();
    const accepted: ReadFinding[] = [];
    for (const item of findings.values) {
      const read = readFinding(item);
      // A finding this draft cannot read, or cannot recognise the source of, is never silently dropped: it is
      // counted, reported and left unrepresented, which a rewrite refuses rather than ignores.
      if ('finding' in read) accepted.push(read.finding);
      else reasons.add(read.problem);
    }
    const bySource: Record<string, number> = {};
    const bySemanticType: Record<string, number> = {};
    for (const finding of accepted) {
      bySource[finding.source] = (bySource[finding.source] ?? 0) + 1;
      const type = finding.evidence.semanticType;
      bySemanticType[type] = (bySemanticType[type] ?? 0) + 1;
    }

    interface Space { viewId: number; family: string; members: ReadFinding[] }
    const spaces = new Map<string, Space>();
    for (const finding of accepted) {
      const viewId = finding.view.viewId;
      const family = FAMILIES[finding.original.kind];
      const key = `${viewId}|${family}`;
      const space = spaces.get(key);
      if (space) space.members.push(finding);
      else spaces.set(key, { viewId, family, members: [finding] });
    }
    const ordered = [...spaces.values()].sort((left, right) => left.viewId - right.viewId ||
      FAMILY_ORDER.indexOf(left.family) - FAMILY_ORDER.indexOf(right.family));

    const identityCounts = new Map<string, number>();
    for (const finding of accepted) {
      const key = identityOf(finding);
      identityCounts.set(key, (identityCounts.get(key) ?? 0) + 1);
    }

    let counter = 0;
    let represented = 0;
    const regions: OverlapRegion[] = [];
    for (const space of ordered) {
      const ordered = [...space.members].sort((left, right) =>
        left.view.span.start - right.view.span.start || right.view.span.end - left.view.span.end ||
        left.source.localeCompare(right.source) ||
        left.evidence.semanticType.localeCompare(right.evidence.semanticType) ||
        (left.evidence.subtype ?? '').localeCompare(right.evidence.subtype ?? '') ||
        left.evidence.evidenceRef.localeCompare(right.evidence.evidenceRef));
      const groups: ReadFinding[][] = [];
      let group: ReadFinding[] = [];
      let reach = -1;
      for (const member of ordered) {
        // Strict overlap only: touching spans stay separate regions and become an adjacency relation.
        if (group.length > 0 && member.view.span.start >= reach) {
          groups.push(group);
          group = [];
          reach = -1;
        }
        group.push(member);
        reach = Math.max(reach, member.view.span.end);
      }
      if (group.length > 0) groups.push(group);
      for (const groupMembers of groups) {
        if (regions.length >= MAX_REGIONS) { reasons.add('REGION_LIMIT'); break; }
        if (groupMembers.length > MAX_REGION_MEMBERS) { reasons.add('REGION_MEMBER_LIMIT'); break; }
        const start = Math.min(...groupMembers.map((member) => member.view.span.start));
        const end = Math.max(...groupMembers.map((member) => member.view.span.end));
        const regionRef = `region-${counter++}`;
        const readMembers: OverlapMember[] = groupMembers.map((member, index) => ({
          memberRef: `${regionRef}-m${index}`,
          evidenceRef: member.evidence.evidenceRef,
          producerId: member.evidence.producerId,
          inputRef: member.evidence.inputRef,
          source: member.source,
          semanticType: member.evidence.semanticType,
          ...(member.evidence.subtype === undefined ? {} : { subtype: member.evidence.subtype }),
          sensitivity: member.evidence.sensitivity,
          ...(member.rule === undefined ? {} : { rule: member.rule }),
          ...(member.basis === undefined ? {} : { basis: member.basis }),
          span: member.view.span,
          view: member.view,
          original: member.original,
          ...(member.field ? { field: member.field } : {}),
          duplicateIdentity: (identityCounts.get(identityOf(member)) ?? 0) > 1,
        }));
        const composed = composeClassification({ detectorEvidence: groupMembers.map((member) => ({
          version: 1,
          id: member.evidence.evidenceRef,
          status: 'FOUND',
          provenance: { inputRef: member.evidence.inputRef, producerId: member.evidence.producerId,
            producerVersion: member.evidence.producerVersion },
          claim: { semanticType: member.evidence.semanticType,
            ...(member.evidence.subtype === undefined ? {} : { subtype: member.evidence.subtype }),
            ...(member.evidence.sensitivity === 'UNKNOWN' ? {} : { sensitivity: member.evidence.sensitivity }),
            // Reversibility is a recommendation that follows the credential floor; it is never widened here.
            ...(member.evidence.nonReversible ? { reversible: false } : {}) },
        })) }, typedContext);
        if (composed.status !== 'RESOLVED') reasons.add('REGION_UNRESOLVED');
        represented += groupMembers.length;
        regions.push(Object.freeze({ regionRef, coordinateSpace: `v${space.viewId}|${space.family}`,
          viewId: space.viewId, span: Object.freeze({ start, end }), original: unionOriginal(groupMembers),
          encodingPath: Object.freeze([...new Set(groupMembers.flatMap((member) => member.view.encodingPath))]),
          representations: Object.freeze([...new Set(groupMembers.map((member) => member.view.representation))].sort()),
          fieldFormats: Object.freeze([...new Set(groupMembers.flatMap((member) => member.field ? [member.field.format] : []))]
            .sort()),
          members: Object.freeze(readMembers), obligations: obligationsOf(groupMembers), composed,
          relations: relationsOf(groupMembers, reasons) }));
      }
    }

    // Adjacency: touching regions inside one coordinate space, in region order.
    const adjacencies: { regionRefs: readonly [string, string] }[] = [];
    for (let left = 0; left < regions.length; left++) {
      for (let right = left + 1; right < regions.length; right++) {
        const one = regions[left]!;
        const other = regions[right]!;
        if (one.coordinateSpace !== other.coordinateSpace) continue;
        if (one.span.end === other.span.start) adjacencies.push({ regionRefs: [one.regionRef, other.regionRef] });
        else if (other.span.end === one.span.start) adjacencies.push({ regionRefs: [other.regionRef, one.regionRef] });
      }
    }

    // Overlaps one coordinate space cannot express: two families in the same view, or two views whose
    // original envelopes cover the same bytes. Both sides are kept; the overlap is a typed refusal.
    const refusals: { refusalRef: string; reason: string; regionRefs: readonly string[] }[] = [];
    const familiesByView = new Map<number, Set<string>>();
    for (const region of regions) {
      const family = region.coordinateSpace.split('|')[1]!;
      const families = familiesByView.get(region.viewId) ?? new Set<string>();
      families.add(family);
      familiesByView.set(region.viewId, families);
    }
    for (const [viewId, families] of familiesByView) {
      // Two families in one view is only an unresolvable overlap when their envelopes actually meet;
      // disjoint original spans are two regions that simply came from different bindings.
      const here = regions.filter((region) => region.viewId === viewId);
      const overlaps = here.some((one, index) => here.slice(index + 1).some((other) =>
        one.coordinateSpace !== other.coordinateSpace &&
        spansOverlap(envelopeOf(one.original), envelopeOf(other.original))));
      if (families.size < 2 || !overlaps) continue;
      refusals.push({ refusalRef: `refusal-${refusals.length}`, reason: 'COORDINATE_SPACE_FOREIGN',
        regionRefs: here.map((region) => region.regionRef) });
    }
    for (let left = 0; left < regions.length; left++) {
      for (let right = left + 1; right < regions.length; right++) {
        const one = regions[left]!;
        const other = regions[right]!;
        if (one.coordinateSpace === other.coordinateSpace) continue;
        if (!spansOverlap(envelopeOf(one.original), envelopeOf(other.original))) continue;
        refusals.push({ refusalRef: `refusal-${refusals.length}`, reason: 'CROSS_VIEW_OVERLAP',
          regionRefs: [one.regionRef, other.regionRef] });
      }
    }
    for (const item of opaque.values) {
      const entry = plain(item);
      const original = entry ? readOriginal(own(entry, 'original')) : null;
      if (!original) { reasons.add('INVALID_UNINSPECTED'); continue; }
      const hits = regions.filter((region) => spansOverlap(envelopeOf(original), envelopeOf(region.original)));
      if (hits.length === 0) continue;
      refusals.push({ refusalRef: `refusal-${refusals.length}`, reason: 'OPAQUE_LOCATION_OVERLAP',
        regionRefs: hits.map((region) => region.regionRef) });
    }
    if (refusals.length > 0) reasons.add('UNRESOLVED_OVERLAP');

    let duplicateEvidence = 0;
    for (const finding of accepted) if ((identityCounts.get(identityOf(finding)) ?? 0) > 1) duplicateEvidence++;
    return Object.freeze({ version: OVERLAP_DRAFT_VERSION,
      status: reasons.size === 0 ? 'COMPOSED' as const : 'UNRESOLVED' as const,
      reasons: Object.freeze([...reasons].sort()),
      retention: Object.freeze({ received: findings.length, retained: accepted.length,
        rejected: findings.length - accepted.length, uncomposed: findings.length - represented,
        duplicateEvidence, bySource: sortedCounts(bySource), bySemanticType: sortedCounts(bySemanticType) }),
      regions: Object.freeze(regions), adjacencies: Object.freeze(adjacencies),
      refusals: Object.freeze(refusals.map((refusal) => Object.freeze(refusal))) });
  } catch {
    // A hostile object graph never becomes a reason string, a partial region set or a throw.
    return empty();
  }
}

/* ---------- Rewrite planning over the one accepted path (#7 field-value rewriting) ---------- */

function digest(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}
function asComposition(value: unknown): OverlapComposition {
  const object = plain(value);
  return object && own(object, 'version') === OVERLAP_DRAFT_VERSION && Array.isArray(own(object, 'regions')) &&
    oneOf(own(object, 'status'), ['COMPOSED', 'UNRESOLVED', 'REJECTED'] as const)
    ? value as OverlapComposition : empty();
}
function refusedPlan(reasons: readonly string[], composition: OverlapComposition, source: string, format: Format): OverlapRewritePlan {
  const sorted = Object.freeze([...new Set(reasons)].sort());
  // A refused plan carries no constant: a rejected replacement must not travel back to a caller or a log.
  return Object.freeze({ version: OVERLAP_DRAFT_VERSION, status: 'REFUSED' as const, reasons: sorted,
    sourceDigest: digest(source), format, replacement: '', replacementDigest: digest(''),
    regions: Object.freeze(composition.regions.map((region) => Object.freeze({ regionRef: region.regionRef,
      decision: 'REFUSED' as const, reasons: sorted,
      evidenceRefs: Object.freeze(region.members.map((member) => member.evidenceRef)) }))) });
}

/**
 * The surviving run of a covered original that refuses a rewrite: half its length, never below
 * `MIN_ECHO_WINDOW`, and the whole of it for a value shorter than that. A literal half of a protected value
 * surviving anywhere in the output is not a rewrite that protected anything, while a shared affix shorter
 * than that is not evidence that this value survived; every longer variant (case, separator, encoding,
 * decoding, splitting) belongs to the independent #19 check, not to this literal one.
 */
export function coveredWindowUnits(coveredLength: number): number {
  if (!Number.isSafeInteger(coveredLength) || coveredLength <= 0) return 0;
  return coveredLength < MIN_ECHO_WINDOW ? coveredLength
    : Math.max(MIN_ECHO_WINDOW, Math.ceil(coveredLength / 2));
}

/** Does the replacement carry any window of a covered original? Shared by the plan and the apply. */
function replacementEchoes(replacement: string, covered: readonly string[]): boolean {
  for (let at = 0; at + MIN_ECHO_WINDOW <= replacement.length; at++) {
    const window = replacement.slice(at, at + MIN_ECHO_WINDOW);
    if (covered.some((text) => text.includes(window))) return true;
  }
  return false;
}

/**
 * Plan the only rewrite this draft can justify: replace the trusted #7 field value that covers each region
 * with one opaque constant. Every region must be coverable; one uncovered region refuses the whole plan,
 * because a partial release is not a protected release.
 */
export function planOverlapRewrite(request: unknown): OverlapRewritePlan {
  try {
    const object = plain(request);
    const composition = asComposition(object ? own(object, 'composition') : null);
    const source = object ? own(object, 'source') : null;
    const format = object ? own(object, 'format') : null;
    const replacement = object ? own(object, 'replacement') : null;
    const host = object ? own(object, 'host') : undefined;
    if (typeof source !== 'string' || source.length > MAX_SOURCE_UNITS) {
      return refusedPlan(['INVALID_SOURCE'], composition, typeof source === 'string' ? source : '',
        oneOf(format, FORMATS) ? format : 'JSON');
    }
    if (!oneOf(format, FORMATS)) return refusedPlan(['INVALID_FORMAT'], composition, source, 'JSON');
    if (typeof replacement !== 'string' || replacement.length === 0 ||
      replacement.length > MAX_REPLACEMENT_UNITS || replacement.trim() !== replacement ||
      CONTROL.test(replacement)) return refusedPlan(['REPLACEMENT_INVALID'], composition, source, format);
    if (composition.status === 'REJECTED') return refusedPlan(['INVALID_COMPOSITION'], composition, source, format);
    if (composition.regions.length === 0) return refusedPlan(['NO_REGIONS'], composition, source, format);
    // A finding this draft could not read, or could not recognise, would otherwise be rewritten past: an
    // incomplete candidate set is not a licence to release what it did cover.
    if (composition.retention.uncomposed > 0) {
      return refusedPlan(['INCOMPLETE_CANDIDATE_SET'], composition, source, format);
    }
    if (host !== undefined && !isParseHost(host)) return refusedPlan(['INVALID_HOST'], composition, source, format);

    // The replacement may not carry any window of a covered original: no echoed, derived or truncated value.
    const covered = composition.regions.map((region) => source.slice(region.span.start, region.span.end));
    if (replacementEchoes(replacement, covered)) {
      return refusedPlan(['REPLACEMENT_ECHOES_ORIGINAL'], composition, source, format);
    }

    const parsed = parseStructured(source, format, undefined, host);
    const decisions: RegionRewriteDecision[] = composition.regions.map((region) => {
      const evidenceRefs = Object.freeze(region.members.map((member) => member.evidenceRef));
      const refuse = (reason: string): RegionRewriteDecision => Object.freeze({ regionRef: region.regionRef,
        decision: 'REFUSED' as const, reasons: Object.freeze([reason]), evidenceRefs });
      // A decoded view has no byte-level map back to the original, so no accepted rewriter covers it.
      if (region.viewId !== 0) return refuse('ENCODED_VIEW_NOT_REWRITABLE');
      // Evidence the accepted composer could not even read means this region's obligation set is unknown;
      // rewriting it would claim a protection the composition never established.
      if (region.composed.reasons.includes('INVALID_EVIDENCE')) return refuse('REGION_EVIDENCE_INCOMPLETE');
      if (parsed.status !== 'COMPLETE' || parsed.coverage !== 'FULL') return refuse('SOURCE_NOT_COMPLETE');
      if (parsed.reasons.includes('DUPLICATE_KEY')) return refuse('SOURCE_AMBIGUOUS');
      if (parsed.comments.length > 0) return refuse('SOURCE_HAS_COMMENTS');
      // The smallest parsed value span containing the whole region covers every member inside it.
      const covering = parsed.fields.filter((field) => field.valueStart <= region.span.start &&
        field.valueEnd >= region.span.end)
        .sort((left, right) => left.valueStart - right.valueStart || left.valueEnd - right.valueEnd)[0];
      if (!covering) return refuse('REGION_NOT_FIELD_BOUNDED');
      return Object.freeze({ regionRef: region.regionRef, decision: 'REPLACE_FIELD_VALUE' as const,
        reasons: Object.freeze([]), fieldSpan: Object.freeze({ start: covering.valueStart, end: covering.valueEnd }),
        // Key names are payload content: only a source-bound digest of the path is ever emitted.
        fieldRef: createHash('sha256').update(`overlap-draft.field-path.v1 ${digest(source)} ${
          JSON.stringify(covering.path)}`).digest('hex').slice(0, 16),
        evidenceRefs });
    });
    const refusalReasons = [...new Set(decisions.flatMap((item) =>
      item.decision === 'REFUSED' ? item.reasons : []))].sort();
    return Object.freeze({ version: OVERLAP_DRAFT_VERSION, status: refusalReasons.length > 0 ? 'REFUSED' : 'PLANNED',
      reasons: Object.freeze(refusalReasons), sourceDigest: digest(source), format, replacement,
      replacementDigest: digest(replacement), regions: Object.freeze(decisions) });
  } catch {
    return refusedPlan(['INTERNAL_ERROR'], empty(), '', 'JSON');
  }
}

/** The decision list a plan carries, read back with the same bounds a caller had to write it with. */
function readDecisions(plan: Record<string, unknown>): RegionRewriteDecision[] | null {
  const planned = list(own(plan, 'regions'), MAX_REGIONS);
  if (planned.invalid || planned.values.length === 0) return null;
  const decisions: RegionRewriteDecision[] = [];
  for (const value of planned.values) {
    const decision = plain(value);
    const fieldSpan = decision ? readSpan(own(decision, 'fieldSpan')) : null;
    const fieldRef = decision ? own(decision, 'fieldRef') : null;
    const evidence = decision ? list(own(decision, 'evidenceRefs'), MAX_FINDINGS) : null;
    if (!decision || !label(own(decision, 'regionRef'), 64) || own(decision, 'decision') !== 'REPLACE_FIELD_VALUE' ||
      !fieldSpan || !label(fieldRef, 128) || !evidence || evidence.invalid ||
      !evidence.values.every((item) => label(item, 256))) return null;
    decisions.push({ regionRef: String(own(decision, 'regionRef')), decision: 'REPLACE_FIELD_VALUE',
      reasons: [], fieldSpan, fieldRef, evidenceRefs: evidence.values as string[] });
  }
  return decisions;
}
/** A supplied plan is usable only when it is exactly the plan this composition and source derive. */
function samePlan(one: readonly RegionRewriteDecision[], other: readonly RegionRewriteDecision[]): boolean {
  if (one.length !== other.length) return false;
  return one.every((decision, index) => {
    const mine = other[index]!;
    return decision.regionRef === mine.regionRef && decision.decision === mine.decision &&
      decision.fieldSpan!.start === mine.fieldSpan!.start && decision.fieldSpan!.end === mine.fieldSpan!.end &&
      decision.fieldRef === mine.fieldRef && JSON.stringify(decision.evidenceRefs) === JSON.stringify(mine.evidenceRefs);
  });
}

/**
 * Apply a plan through the accepted #7 rewriter. The plan is a reviewable artifact, not an authority: this
 * function re-derives it from the composition, the exact source bytes and the constant, and refuses anything
 * that does not match. It then verifies the rewrite independently of #7's own claim — every derived span must
 * still be a real value span, the output must reparse to the same key paths, and no `MIN_ECHO_WINDOW` window
 * of any covered original may survive anywhere in the output.
 */
export function applyOverlapRewrite(request: unknown): AppliedRewrite {
  try {
    const object = plain(request);
    const plan = object ? plain(own(object, 'plan')) : null;
    const composition = asComposition(object ? own(object, 'composition') : null);
    const source = object ? own(object, 'source') : null;
    const format = object ? own(object, 'format') : null;
    const host = object ? own(object, 'host') : undefined;
    const refuse = (...codes: readonly string[]): AppliedRewrite => Object.freeze({ status: 'REFUSED' as const,
      reasons: Object.freeze(codes.length === 0 ? ['REFUSED_PLAN'] : codes) });
    if (!plan || typeof source !== 'string' || source.length > MAX_SOURCE_UNITS) return refuse('INVALID_REQUEST');
    if (own(plan, 'version') !== OVERLAP_DRAFT_VERSION) return refuse('INVALID_PLAN');
    if (own(plan, 'status') !== 'PLANNED') return refuse('REFUSED_PLAN');
    const planFormat = own(plan, 'format');
    const replacement = own(plan, 'replacement');
    if (!oneOf(planFormat, FORMATS) || typeof replacement !== 'string' || replacement.length === 0 ||
      replacement.length > MAX_REPLACEMENT_UNITS || replacement.trim() !== replacement ||
      CONTROL.test(replacement)) return refuse('INVALID_PLAN');
    if (!oneOf(format, FORMATS) || format !== planFormat) return refuse('FORMAT_MISMATCH');
    // Bind the plan to the exact source bytes: spans from another revision are never spliced.
    if (digest(source) !== own(plan, 'sourceDigest')) return refuse('STALE_SOURCE_BINDING');
    if (composition.status === 'REJECTED') return refuse('INVALID_COMPOSITION');
    // Re-derive: the region set, each covering field, the constant's echo rule and every source-level
    // refusal are re-established here from the composition, so a plan is never a way around them.
    const derived = planOverlapRewrite({ composition, source, format: planFormat, replacement,
      ...(host === undefined ? {} : { host }) });
    if (derived.status !== 'PLANNED') return refuse(...derived.reasons);
    const supplied = readDecisions(plan);
    const rederived = readDecisions(derived as unknown as Record<string, unknown>);
    if (!supplied || !rederived || !samePlan(supplied, rederived)) return refuse('PLAN_BINDING_MISMATCH');
    // Independent echo rule on the covered originals of the regions actually being rewritten.
    if (replacementEchoes(replacement, derived.regions.map((decision) => {
      const region = composition.regions.find((item) => item.regionRef === decision.regionRef);
      return region ? source.slice(region.span.start, region.span.end) : '';
    }))) return refuse('REPLACEMENT_ECHOES_ORIGINAL');

    const parsed = parseStructured(source, planFormat, undefined, host);
    if (parsed.status !== 'COMPLETE' || parsed.coverage !== 'FULL') return refuse('SOURCE_NOT_COMPLETE');
    const edits = new Map<string, { field: (typeof parsed.fields)[number]; evidenceRefs: string[] }>();
    const provenance: { regionRef: string; fieldSpan: Span; fieldRef: string; evidenceRefs: readonly string[] }[] = [];
    for (const decision of rederived) {
      const field = parsed.fields.find((item) => item.valueStart === decision.fieldSpan!.start &&
        item.valueEnd === decision.fieldSpan!.end);
      if (!field) return refuse('FIELD_SPAN_NOT_IN_SOURCE');
      const key = `${decision.fieldSpan!.start}-${decision.fieldSpan!.end}`;
      const existing = edits.get(key);
      if (existing) existing.evidenceRefs.push(...decision.evidenceRefs);
      else edits.set(key, { field, evidenceRefs: [...decision.evidenceRefs] });
      provenance.push({ regionRef: decision.regionRef, fieldSpan: decision.fieldSpan!, fieldRef: decision.fieldRef!,
        evidenceRefs: Object.freeze([...decision.evidenceRefs]) });
    }
    const rewritten = rewriteFieldValues(source, planFormat, [...edits.values()].map((edit) => ({
      field: edit.field, replacement })));
    if (rewritten.status !== 'OK') return refuse(rewritten.reason);
    // Independent reparse: key paths and field count, not #7's own round-trip claim.
    const after = parseStructured(rewritten.text, planFormat, undefined, host);
    if (after.status !== 'COMPLETE' || after.fields.length !== parsed.fields.length ||
      after.fields.some((field, index) => JSON.stringify(field.path) !==
        JSON.stringify(parsed.fields[index]!.path))) return refuse('ROUND_TRIP_MISMATCH');
    // Post-condition: no surviving run of any covered original, at or above half its length, is left
    // anywhere in the output. Refusing is the answer when the check cannot complete within its probe budget.
    let probes = 0;
    for (const region of composition.regions) {
      const covered = source.slice(region.span.start, region.span.end);
      const window = coveredWindowUnits(covered.length);
      for (let at = 0; at + window <= covered.length; at++) {
        if (++probes > MAX_ECHO_PROBES) return refuse('POSTCONDITION_BUDGET');
        if (rewritten.text.includes(covered.slice(at, at + window))) {
          return refuse('ORIGINAL_SPAN_STILL_PRESENT');
        }
      }
    }
    return Object.freeze({ status: 'REWRITTEN' as const, text: rewritten.text,
      provenance: Object.freeze({ version: OVERLAP_DRAFT_VERSION, sourceDigest: digest(source),
        replacementDigest: digest(replacement), format: planFormat, regions: Object.freeze(provenance),
        rewrittenFields: edits.size }) });
  } catch {
    return Object.freeze({ status: 'REFUSED' as const, reasons: Object.freeze(['INTERNAL_ERROR']) });
  }
}
