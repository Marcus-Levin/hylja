/**
 * #6 detection composition. Pure and NON-ENFORCING: normalization, bounded deterministic candidate
 * sources and offset provenance are joined here without transforming input or selecting policy effects.
 * The result contains metadata only; raw and decoded text live only for this call. A non-COMPLETE result
 * must be treated as opaque by a later policy integration.
 *
 * #7 parsed fields are composed here too. Every supported field's decoded value is scanned with #8, #9 and
 * #37, and a trusted #7 key hint feeds #8's FIELD_KEY rule, so structural meaning reaches detection without
 * trusting payload text. Provenance stays honest: a value written verbatim in the source keeps exact spans,
 * while escaped, percent- or entity-decoded values, and values of decoded views, only ever claim a covering
 * span or the encoded envelope. Malformed, unsupported, opaque and over-budget parser states stay PARTIAL
 * with their own opaque locations, so a structured parse can never read as "nothing hidden here".
 *
 * Limits of this composition:
 * - a value that is verbatim in its view is only re-scanned for its trusted key hint; the view scan already
 *   covered that text, so a value with no credential-like key in its path gains no duplicate candidate;
 * - #7's `highRisk` flag is reported as metadata, but a field flagged only by a non-ASCII key or a sibling
 *   whose value #8 does not recognize still yields no candidate here; that gap needs an agreed #8 vocabulary;
 * - every view is parsed by its own content-type hint, and the root additionally runs the caller's trusted
 *   `formats`. That list is *added* to the hinted format, never substituted for it, so a wrong or hostile
 *   assertion can add a parse but can never suppress the parse the hint named. Encoded YAML/TOML/connection
 *   strings still stay unparsed unless their decoded view itself sniffs as a supported structure, and a
 *   requested format that does not hold is reported as opaque;
 * - field values composed per request are capped. The view that exhausts the budget, and every later view
 *   that would have been parsed, are recorded as uninspected rather than silently skipped;
 * - #7's own time budget is per parse call, not per request, and its clock is the host-owned `host` reading
 *   this seam forwards. A time-expired or clock-less parse is `FAILURE` with the whole view opaque, and the
 *   view text is still scanned in full by the detectors below, so a bounded parse can never hide a value;
 * - repeated protected text inside one decoded view is reported once per occurrence, each with its own
 *   in-view span and evidence id. Only a repeat of the very same occurrence is suppressed.
 *
 * #10 configured sources run here too. When the integration supplies a trusted configuration handle, its term
 * dictionaries, engineering templates and #7 key-path field hints join the same per-occurrence candidates under
 * the same tenant and project, so a configured claim keeps exactly the provenance every other source gets here:
 * an exact span for text written verbatim in a string root, a covering span for folded, escaped or decoded
 * text, and the encoded envelope for a decoded view. Beside that unchanged coverage a configured candidate also
 * carries `wholeUnitMatch`, the one fact about the text unit #10 itself scanned: whether its own matcher matched
 * that whole unit, rather than only the part coverage then extended over. It is a boolean precisely because this
 * seam relocates coverage after folding, parsing and decoding while the scanned unit does not move: a #7 field
 * hint matches the decoded value it was handed, whose offset is not the offset of its coverage in the view. The
 * member comes from the compiled trusted configuration, never from caller text or a host assertion, so
 * whole-value corroboration can be required of a genuine matcher without widening what any detector sees and
 * without claiming that a nested, folded or decoded match sits at the same coordinates as its coverage.
 * Without a handle nothing from #10
 * runs and no reason is added, because the integration simply configured no configured source. A forged or foreign handle is PARTIAL
 * with its own opaque location and no configured claim; only #10's tenant-independent engineering-key rule
 * still runs. A #7 field whose value is verbatim in its view is read here for its trusted key-path hint only,
 * exactly like the #8 key hint above, because the view scan already covered that text.
 */
import { createHash } from 'node:crypto';
import { detectConfigured, type CandidateConfigHandle } from './configured-candidates.js';
import { generateContactCandidates, type CandidateScope, type NameDictionary } from './contact-candidates.js';
import { detectInfrastructure, type InfraFidelity } from './infrastructure-identifiers.js';
import { DEFAULT_BUDGET, foldForDetection, mapFoldedSpan, normalizeInput, sniffContentType,
  type ContentType, type DetectionFold, type Encoding, type NormalizedView,
  type NormalizationResult } from './normalization.js';
import { DEFAULT_PARSE_BUDGET, FORMATS, isParseHost, parseStructured, type Format, type ParsedField } from './structured-parsers.js';
import { detectSecrets, subtypeForKey } from './secret-detectors.js';
import type { ClassificationClaim, EvidenceProvenance } from './classification.js';

const MAX_DETECTOR_UNITS = 1 << 20;
const MAX_SCANNED_VIEWS = DEFAULT_BUDGET.maxViews + 1;
const MAX_PER_SOURCE = 256;
/** Field values composed across every view of one request. Beyond it the remainder is opaque, never dropped. */
const MAX_FIELD_SCANS = 1024;
/** Trusted format hints a caller may add for formats no content hint can reach (YAML, TOML, connection strings). */
const MAX_REQUESTED_FORMATS = 3;
/** #7's default field cap bounds each parse; this bounds the composition itself across all views. */
const NO_FORMATS: readonly Format[] = Object.freeze([]);
/** Sibling keys #7 treats as naming the value next to them; only their parsed value can become a key hint. */
const NAME_SIBLING_KEYS = Object.freeze(['name', 'key']);
/** Content-type hints mapped to the one #7 format that can structure them. A hint is verified by parsing. */
const HINTED_FORMATS: Readonly<Record<ContentType, readonly Format[]>> = Object.freeze({
  JSON: Object.freeze(['JSON'] as const), XML: Object.freeze(['XML'] as const),
  DOTENV: Object.freeze(['DOTENV'] as const), INI: Object.freeze(['INI'] as const),
  URL: Object.freeze(['URL'] as const), LOG: Object.freeze(['LOG'] as const),
  TEXT: NO_FORMATS, BINARY_LIKE: NO_FORMATS,
});

export interface Span { readonly start: number; readonly end: number }
/** UTF-16 offsets. Byte input is decoded as UTF-8; this seam never claims byte offsets. */
export type OriginalLocation =
  | Readonly<{ kind: 'ORIGINAL_EXACT'; span: Span }>
  | Readonly<{ kind: 'ORIGINAL_COVER'; span: Span }>
  | Readonly<{ kind: 'ENCODED_RUNS'; spans: readonly Span[] }>
  | Readonly<{ kind: 'UTF8_TEXT'; span: Span; coverage: 'EXACT' | 'COVER' }>
  | Readonly<{ kind: 'UTF8_ENCODED_RUNS'; spans: readonly Span[] }>;
export interface ViewLocation {
  /** Offset into the normalized view's text; a STRINGS view is extracted text, not a decoded-byte map. */
  readonly viewId: number;
  readonly span: Span;
  readonly representation: 'RAW' | 'FOLDED';
  readonly form: NormalizedView['form'];
  readonly encodingPath: readonly Encoding[];
}
export interface CandidateEvidence {
  readonly version: 1;
  readonly id: string;
  readonly status: 'FOUND';
  readonly provenance: EvidenceProvenance;
  readonly claim: ClassificationClaim;
}
/** Where a candidate came from a #7 parsed field. Carries structure and offsets only, never a value or key name. */
export interface ParsedFieldLocation {
  /** The #7 format whose parse produced the field. */
  readonly format: Format;
  /** Privacy-safe digest of the #7 key path. Key names are payload content and are never emitted. */
  readonly pathRef: string;
  /**
   * Where #8's trusted credential-key hint came from: a key-path segment #8 recognizes, or a sibling
   * `name`/`key` field whose value #8 recognizes (`{"name":"DB_PASSWORD","value":"x"}`,
   * `<name>DB_PASSWORD</name><value>x</value>`). NONE means #7 flagged the field but no key text in the
   * structure yielded a credential subtype, so no whole-value candidate is claimed here.
   */
  readonly hintSource: 'PATH' | 'NAME_SIBLING' | 'NONE';
  /** Index of the key-path segment used as the hint, or -1 for a sibling or no hint. */
  readonly hintDepth: number;
  /** #7's trusted structural credential flag, inherited from the key path and name/value siblings. */
  readonly highRisk: boolean;
  /** #7 source span of the value inside the view, end-exclusive. */
  readonly span: Span;
  /** Match offsets inside the decoded field value. The decoded value itself is never emitted. */
  readonly valueSpan: Span;
  /**
   * True when the view text at `span` is identical to the decoded value, so `valueSpan` offsets are also
   * exact view offsets. False for escaped, percent- or entity-decoded values, whose source holds a different
   * spelling: such a candidate only ever claims a covering span, never an exact original offset.
   */
  readonly verbatim: boolean;
}
export interface NormalizedCandidate {
  readonly source: 'SECRET' | 'INFRASTRUCTURE' | 'CONTACT' | 'CONFIGURED';
  readonly subtype?: string;
  readonly rule?: string;
  readonly basis: string;
  readonly fidelity?: Readonly<InfraFidelity>;
  readonly fingerprint?: string;
  readonly evidence: CandidateEvidence;
  readonly view: ViewLocation;
  readonly original: OriginalLocation;
  /**
   * For a `CONFIGURED` candidate: whether #10's own matcher matched the **whole text unit it scanned**, which
   * `view.span` and `original` cannot show on their own because #10 extends a template match forward over the
   * rest of the identifier. `view.span` and `original` stay that wider coverage, unchanged, in every base;
   * this flag answers about the scanned unit alone and is deliberately not a coordinate, so a folded, parsed
   * or decoded placement never turns it into a claim that the match sits at the coverage's offsets. It is
   * `false` when coverage extended past the match, and `true` for a `DICTIONARY`, `FIELD_HINT` or `CONTEXT`
   * basis, which never extend. Absent for every source other than `CONFIGURED`.
   */
  readonly wholeUnitMatch?: boolean;
  /** Present when the candidate came from a #7 parsed field rather than from scanning a whole view. */
  readonly field?: ParsedFieldLocation;
}
export interface OpaqueLocation {
  readonly reason: string;
  readonly viewId: number;
  readonly viewSpan: Span;
  readonly original: OriginalLocation;
}
export interface NormalizedDetectionResult {
  /** COMPLETE means only that supported scans ran within bounds, never that text is clean or releasable. */
  readonly status: 'COMPLETE' | 'PARTIAL' | 'FAILURE';
  readonly reasons: readonly string[];
  readonly contentType: ContentType | 'UNKNOWN';
  readonly candidates: readonly NormalizedCandidate[];
  readonly uninspected: readonly OpaqueLocation[];
}
export interface NormalizedDetectionRequest {
  readonly input: unknown;
  /**
   * Privacy-safe opaque reference, never a value or raw source path. The #7 field path digests are bound to
   * it, so a trusted integration must pass a fresh value per request: that is what keeps key paths from
   * being correlated across requests.
   */
  readonly inputRef: string;
  readonly scope: CandidateScope;
  readonly names?: NameDictionary;
  /**
   * Trusted #10 configuration handle, already bound by its own constructor to exactly the tenant and project
   * in `scope`. It selects what this request treats as configured evidence (customer, project, business and
   * engineering terms, templates and #7 field hints); it grants nothing and authorizes no release. A handle
   * from another tenant or project, or a forged object, never matches here: the result is PARTIAL with an
   * opaque location. Omitting it means the integration configured no configured source.
   */
  readonly configured?: CandidateConfigHandle;
  /**
   * Trusted #7 formats the integration asserts for the input it passes, for formats no content hint reaches
   * (YAML, TOML, CONNECTION_STRING). The root is parsed by the union of this list and the format its own
   * content hint names, so a format asserted here never suppresses the hinted parse. Decoded views are new
   * text and are parsed by their own content-type hint, so encoded YAML/TOML stays unparsed unless its
   * decoded view itself sniffs as a supported structure. This selects parsers only; it grants nothing and
   * authorizes no release.
   */
  readonly formats?: readonly Format[];
  /** Optional trusted tenant key for #8 candidate fingerprints. */
  readonly fingerprintKey?: Uint8Array;
  /** #6 validates this bounded budget; opt-in larger budgets can cost more request time. */
  readonly budget?: unknown;
  /**
   * Host-owned capability forwarded to #7: a required `now` returning **milliseconds** on a monotonic
   * reading, which its time budget is measured against. Payload text never supplies it and it authorizes
   * nothing; omitting it uses the module default, and anything else is refused as `INVALID_HOST`.
   */
  readonly host?: unknown;
}

/** One detector finding before placement: spans are relative to whatever unit that detector was given. */
interface Detected {
  start: number;
  end: number;
  /** #10's one boolean fact about the unit its own matcher scanned. Never an offset. */
  wholeUnitMatch?: boolean;
  subtype?: string;
  rule?: string;
  basis: string;
  evidence: CandidateEvidence;
  fidelity?: Readonly<InfraFidelity>;
  fingerprint?: string;
}
/** A view span and the original-source location #6 provenance derives for it. */
export interface Placed { view: ViewLocation; original: OriginalLocation; field?: ParsedFieldLocation }
/**
 * The bounded text unit an outside detector was handed. `source` records what the trusted caller
 * passed to #6: `BYTES` yields `UTF8_TEXT`, which this repository documents as offsets into decoded
 * UTF-8 text and never as byte-source offsets.
 */
export type ExternalSpanTarget = Readonly<{
  kind: 'VIEW';
  viewId: number;
  representation: 'RAW' | 'FOLDED';
  unit: Span;
  source: 'STRING' | 'BYTES';
}> | Readonly<{
  kind: 'FIELD';
  viewId: number;
  format: Format;
  fieldIndex: number;
  unit: Span;
  source: 'STRING' | 'BYTES';
}>;

function label(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
function span(start: number, end: number): Span { return Object.freeze({ start, end }); }
function isFormat(value: unknown): value is Format {
  return typeof value === 'string' && (FORMATS as readonly unknown[]).includes(value);
}
function path(views: readonly NormalizedView[], view: NormalizedView): readonly Encoding[] {
  const encodings: Encoding[] = [];
  for (let cursor: NormalizedView | undefined = view; cursor && cursor.parent !== null; cursor = views[cursor.parent]) {
    encodings.push(cursor.encoding);
  }
  return Object.freeze(encodings.reverse());
}
/**
 * Descendants have no byte-level offset map. Their only defensible original location is each outer run.
 * `exact` is false when the matched text is a decoded or folded spelling of the original: the caller has
 * text that is not verbatim in the source, so only a covering span or the envelope is claimed.
 */
function originalOf(views: readonly NormalizedView[], view: NormalizedView, location: Span,
  representation: 'RAW' | 'FOLDED', encodedOrigins: Map<number, OriginalLocation>,
  sourceIsString: boolean, exact: boolean): OriginalLocation {
  if (view.parent === null) {
    if (sourceIsString) {
      return Object.freeze({ kind: representation === 'RAW' && exact ? 'ORIGINAL_EXACT' : 'ORIGINAL_COVER', span: location });
    }
    return Object.freeze({ kind: 'UTF8_TEXT', span: location,
      coverage: representation === 'RAW' && exact ? 'EXACT' : 'COVER' });
  }
  let outer = view;
  while (outer.parent !== 0) outer = views[outer.parent!]!;
  const cached = encodedOrigins.get(outer.id);
  if (cached) return cached;
  const result = Object.freeze({ kind: sourceIsString ? 'ENCODED_RUNS' : 'UTF8_ENCODED_RUNS',
    spans: Object.freeze(outer.occurrences.map((item) => span(item.start, item.end))) }) as OriginalLocation;
  encodedOrigins.set(outer.id, result);
  return result;
}
function originalKey(location: OriginalLocation): string {
  if (location.kind === 'ENCODED_RUNS' || location.kind === 'UTF8_ENCODED_RUNS') {
    return `${location.kind}:${location.spans.map((at) => `${at.start}-${at.end}`).join(',')}`;
  }
  if (location.kind === 'UTF8_TEXT') return `UTF8_TEXT:${location.coverage}:${location.span.start}-${location.span.end}`;
  return `${location.kind}:${location.span.start}-${location.span.end}`;
}
function failure(reason: string): NormalizedDetectionResult {
  return Object.freeze({ status: 'FAILURE', reasons: Object.freeze([reason]), contentType: 'UNKNOWN',
    candidates: Object.freeze([]), uninspected: Object.freeze([]) });
}
/** The one place a view span becomes a #6 `Placed`, shared by this seam and `placeExternalSpan`. */
function placeSpan(views: readonly NormalizedView[], view: NormalizedView, at: Span,
  representation: 'RAW' | 'FOLDED', field: ParsedFieldLocation | undefined, exact: boolean,
  sourceIsString: boolean, encodedOrigins: Map<number, OriginalLocation>): Placed {
  return Object.freeze({
    view: Object.freeze({ viewId: view.id, span: at, representation, form: view.form,
      encodingPath: path(views, view) }),
    original: originalOf(views, view, at, representation, encodedOrigins, sourceIsString, exact),
    ...(field ? { field } : {}),
  });
}
/**
 * A FIELD placement has no caller-supplied #7 key path and therefore no path digest of its own. The
 * placeholder is derived from the view and field index alone, so it names no payload content, but it
 * is also **not** comparable with the `pathRef` values `detectNormalizedCandidates` emits.
 */
function pathRefPlaceholder(viewId: number, fieldIndex: number): string {
  return `external-field-${viewId}-${fieldIndex}`;
}

/**
 * Place a span an OUTSIDE detector produced against a view it was given, using the same #6/#7
 * provenance this seam derives for its own candidates.
 *
 * A candidate source that is not this module (a bounded local worker, for example) reports offsets
 * in a text unit *it* was handed, never in the original source. Two units are supported, and each
 * is re-derived here rather than believed:
 *
 * - `VIEW`: the worker received exactly `view.text`, or exactly `foldForDetection(view.text).text`
 *   when `representation` is `FOLDED`. A folded span is mapped back through the fold and can only
 *   ever claim a covering span, because the folded spelling is not the source spelling.
 * - `FIELD`: the worker received exactly the decoded value of #7 field `fieldIndex` of `format` in
 *   that view. The parse is repeated here, so a caller cannot name a field the worker did not see.
 *   A value written verbatim in the view keeps exact offsets; an escaped, percent- or entity-decoded
 *   value claims its field's covering span, never an invented original offset.
 *
 * The caller must bind the text it actually sent with a digest; this function returns the `original`
 * envelope and the `view`/`field` provenance to keep with the outside candidate. It never rewrites
 * input, transforms a value, grants trust or selects any effect. Returns `null` for anything outside
 * the bounded, parseable surface rather than inventing a location.
 */
export function placeExternalSpan(normalized: NormalizationResult, target: ExternalSpanTarget): Placed | null {
  try {
    if (normalized === null || typeof normalized !== 'object' || normalized.status === 'FAILURE') return null;
    const views = normalized.views;
    if (!Array.isArray(views) || views.length === 0 || views.length > MAX_SCANNED_VIEWS) return null;
    const view = views[target.viewId];
    if (!view || view.id !== target.viewId || typeof view.text !== 'string' ||
      typeof view.form !== 'string') return null;
    const unit: Span = target.unit;
    if (!Number.isSafeInteger(unit.start) || !Number.isSafeInteger(unit.end) ||
      unit.start < 0 || unit.end <= unit.start) return null;
    const sourceIsString = target.source === 'STRING';
    const origins = new Map<number, OriginalLocation>();
    if (target.kind === 'VIEW') {
      if (target.representation === 'FOLDED') {
        let folded: DetectionFold;
        try { folded = foldForDetection(view.text); } catch { return null; }
        if (unit.end > folded.text.length) return null;
        let mapped: { start: number; end: number };
        try { mapped = mapFoldedSpan(folded, unit.start, unit.end); } catch { return null; }
        // A folded spelling is not the source spelling, so this can only ever be a covering span.
        return placeSpan(views, view, span(mapped.start, mapped.end), 'FOLDED', undefined, false,
          sourceIsString, origins);
      }
      if (target.representation !== 'RAW' || unit.end > view.text.length) return null;
      return placeSpan(views, view, unit, 'RAW', undefined, true, sourceIsString, origins);
    }
    if (target.kind !== 'FIELD' || typeof target.format !== 'string' || !isFormat(target.format) ||
      !Number.isSafeInteger(target.fieldIndex) || target.fieldIndex < 0 || target.fieldIndex > 1 << 16) {
      return null;
    }
    let parsed: ReturnType<typeof parseStructured>;
    try {
      // #7 is asked for exactly this view's size, so a large view is parsed rather than rejected.
      parsed = parseStructured(view.text, target.format,
        { ...DEFAULT_PARSE_BUDGET, maxInputUnits: view.text.length || 1 });
    } catch { return null; }
    const parsedField = parsed.fields[target.fieldIndex];
    if (!parsedField || !parsedField.value || unit.end > parsedField.value.length) return null;
    const fieldSpan = span(parsedField.valueStart, parsedField.valueEnd);
    const verbatim = view.text.slice(fieldSpan.start, fieldSpan.end) === parsedField.value;
    const field = Object.freeze({ format: target.format, pathRef: pathRefPlaceholder(view.id, target.fieldIndex),
      hintSource: 'NONE' as const, hintDepth: -1, highRisk: parsedField.highRisk, span: fieldSpan,
      valueSpan: span(unit.start, unit.end), verbatim });
    const at = verbatim ? span(fieldSpan.start + unit.start, fieldSpan.start + unit.end) : fieldSpan;
    return placeSpan(views, view, at, 'RAW', field, verbatim, sourceIsString, origins);
  } catch { return null; }
}

/**
 * Run #8, #9 and #37 on every bounded normalized view and on its compatibility fold when it changes, then
 * compose #7 parsed fields and their trusted key hints. Evidence inputRefs identify view/representation/field
 * units; v1 evidence alone cannot rewrite the original. A caller must keep the `original` envelope with each
 * candidate and separately enforce policy.
 */
export function detectNormalizedCandidates(request: NormalizedDetectionRequest): NormalizedDetectionResult {
// #10's `configured` handle and PR111's #7 `host` clock are read exactly once here, together, from the
  // one snapshot below. Both are optional and independent: neither is required for the other, and neither
  // authorizes anything.
  let input: unknown, inputRef: unknown, scope: unknown, names: unknown, fingerprintKey: unknown, budget: unknown, formats: unknown,
    configured: unknown, host: unknown;
  try { ({ input, inputRef, scope, names, fingerprintKey, budget, formats, configured, host } = request); }
  catch { return failure('INVALID_REQUEST'); }
  let tenantRef: unknown, projectRef: unknown;
  try {
    if (scope === null || typeof scope !== 'object') return failure('INVALID_REQUEST');
    ({ tenantRef, projectRef } = scope as Record<string, unknown>);
  } catch { return failure('INVALID_REQUEST'); }
  if (!label(inputRef, 1024) || !label(tenantRef, 256) || !label(projectRef, 256)) return failure('INVALID_REQUEST');
  let requestedFormats: readonly Format[] | undefined;
  if (formats !== undefined) {
    // Snapshot one bounded element per index from descriptors: a Proxy cannot then grow this list, change it
    // mid-iteration, or hand a different format to each read.
    let count: unknown;
    try {
      if (!Array.isArray(formats)) return failure('INVALID_FORMATS');
      count = Object.getOwnPropertyDescriptor(formats, 'length')?.value;
      if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 1 || count > MAX_REQUESTED_FORMATS) {
        return failure('INVALID_FORMATS');
      }
    } catch { return failure('INVALID_FORMATS'); }
    const unique: Format[] = [];
    for (let index = 0; index < count; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(formats, String(index));
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor) || !isFormat(descriptor.value)) {
        return failure('INVALID_FORMATS');
      }
      if (!unique.includes(descriptor.value)) unique.push(descriptor.value);
    }
    requestedFormats = Object.freeze(unique);
  }
  // #7 owns the definition of a usable host clock, so a host that is not one is refused here with the
  // same shape check the parser applies: a parse that cannot be time-bounded is not run at all.
  if (host !== undefined && !isParseHost(host)) return failure('INVALID_HOST');

  const normalized = normalizeInput(input, budget);
  if (normalized.status === 'FAILURE') return failure(`NORMALIZATION_${normalized.reasons[0] ?? 'FAILURE'}`);
  const sourceIsString = typeof input === 'string';
  const reasons = new Set<string>(normalized.reasons.map((reason) => `NORMALIZATION_${reason}`));
  const candidates: NormalizedCandidate[] = [];
  const encodedOrigins = new Map<number, OriginalLocation>();
  /**
   * One entry per distinct piece of evidence. Identity is per occurrence, never per envelope: every
   * occurrence inside one decoded view shares the same `ENCODED_RUNS` envelope, so the in-view span, the
   * #7 format, the field span and the **in-value occurrence offsets** are what keep two occurrences of the
   * same protected text apart. The in-value offsets are not redundant with the view span: a value #7 decoded
   * (an escape or an entity) reports its whole field span in the view for every match inside it, so without
   * them two occurrences of the same text in one decoded value would collapse into one candidate and the
   * second would vanish with no reason and no opaque location. A value that #6 decoded is a different case: it
   * is verbatim inside its own view, so its matches already differ by in-view span. A repeat of the very same
   * occurrence still suppresses: same view span *and* same in-value span is the same occurrence read twice.
   */
  const seen = new Set<string>();
  const uninspected: OpaqueLocation[] = normalized.uninspected.map((item) => {
    const view = normalized.views[item.viewId]!;
    const viewSpan = span(item.start, item.end);
    return Object.freeze({ reason: item.reason, viewId: view.id, viewSpan,
      original: originalOf(normalized.views, view, viewSpan, 'RAW', encodedOrigins, sourceIsString, true) });
  });
  const markOpaque = (reason: string, view: NormalizedView, at?: Span): void => {
    reasons.add(reason);
    if (uninspected.length >= 1024) { reasons.add('UNINSPECTED_TRUNCATED'); return; }
    const viewSpan = at ?? span(0, view.text.length);
    uninspected.push(Object.freeze({ reason, viewId: view.id, viewSpan,
      original: originalOf(normalized.views, view, viewSpan, 'RAW', encodedOrigins, sourceIsString, true) }));
  };
  const counts = { SECRET: 0, INFRASTRUCTURE: 0, CONTACT: 0, CONFIGURED: 0 };
  const inputDigest = createHash('sha256').update(inputRef).digest('hex').slice(0, 32);
  const locate = (view: NormalizedView, at: Span, representation: 'RAW' | 'FOLDED',
    exact: boolean): Placed => placeSpan(normalized.views, view, at, representation, undefined, exact,
      sourceIsString, encodedOrigins);
  const accept = (view: NormalizedView, source: NormalizedCandidate['source'], items: readonly Detected[],
    place: (start: number, end: number) => Placed): void => {
    for (const item of items) {
      const at = place(item.start, item.end);
      const identity = `${at.view.viewId}|${at.view.representation}|${source}|${item.subtype ?? ''}|${item.rule ?? ''}|` +
        `${at.view.span.start}-${at.view.span.end}|${originalKey(at.original)}|` +
        `${at.field ? `${at.field.format}|${at.field.span.start}-${at.field.span.end}|${at.field.pathRef}|` +
          `${at.field.valueSpan.start}-${at.field.valueSpan.end}` : ''}`;
      if (seen.has(identity)) continue;
      if (counts[source] >= MAX_PER_SOURCE) { markOpaque(`${source}_CANDIDATE_LIMIT`, view); break; }
      seen.add(identity);
      counts[source]++;
      candidates.push(Object.freeze({ source, ...(item.subtype ? { subtype: item.subtype } : {}),
        ...(item.rule ? { rule: item.rule } : {}), basis: item.basis,
        ...(item.wholeUnitMatch === undefined ? {} : { wholeUnitMatch: item.wholeUnitMatch }),
        ...(item.fidelity ? { fidelity: item.fidelity } : {}),
        ...(item.fingerprint ? { fingerprint: item.fingerprint } : {}), evidence: item.evidence,
        ...at }));
    }
  };

  /**
   * #10 over one scanned text unit. `fieldHintsOnly` is set for a #7 field whose value is verbatim in its
   * view: the view scan already covered that text, so only the trusted key-path hint is new here.
   */
  const runConfigured = (view: NormalizedView, text: string, unitRef: string,
    place: (start: number, end: number) => Placed, fieldPath?: readonly string[], fieldHintsOnly = false): void => {
    let result: ReturnType<typeof detectConfigured>;
    try {
      result = detectConfigured({ text, inputRef: unitRef, scope: { tenantRef, projectRef },
        ...(configured === undefined ? {} : { config: configured as CandidateConfigHandle }),
        ...(fieldPath === undefined ? {} : { fieldPath }) });
    } catch { markOpaque('CONFIGURED_INTERNAL_ERROR', view); return; }
    if (result.status !== 'COMPLETE') {
      // An invalid or out-of-scope configuration is an inspection gap like any other, never "nothing there".
      for (const reason of result.reasons) markOpaque(`CONFIGURED_${reason}`, view);
    }
    if (result.status === 'FAILURE') return;
    const items = (fieldHintsOnly ? result.candidates.filter((item) => item.basis === 'FIELD_HINT') : result.candidates)
      .map((item) => ({ start: item.start, end: item.end, wholeUnitMatch: item.wholeUnitMatch,
        ...(item.subtype ? { subtype: item.subtype } : {}), rule: item.rule, basis: item.basis, evidence: item.evidence }));
    accept(view, 'CONFIGURED', items, place);
  };

  /* ---------- #7 parsed fields: trusted key hints, decoded values, honest provenance ---------- */

  /**
   * Privacy-safe path digest, bound to this request: key names are payload content, and a digest that could
   * be compared across requests would still leak "these two messages share a key here". The unlinkability is
   * exactly as strong as the trusted integration's `inputRef` discipline, which this seam does not and cannot
   * enforce: two requests with distinct `inputRef`s produce digests that cannot be correlated, while a caller
   * that reuses one `inputRef` across messages would let key paths be correlated within its own traffic.
   * Equal paths inside one result share a digest, so a consumer can correlate fields without any key ever
   * being emitted.
   */
  const pathRefOf = (segments: readonly string[]): string =>
    createHash('sha256').update(`field-path.v1\u0000${inputDigest}\u0000${JSON.stringify(segments)}`).digest('hex').slice(0, 16);
  /** Deepest path segment #8 recognizes as a credential key. Structural, and never taken from payload prose. */
  const hintDepthOf = (segments: readonly string[]): number => {
    for (let index = segments.length - 1; index >= 0; index--) if (subtypeForKey(segments[index]!)) return index;
    return -1;
  };
  /**
   * Trusted key hint for one #7 field: the deepest credential-like key-path segment, else the value of a
   * `name`/`key` sibling that #7 matched as naming this field's value, else nothing. Both come from the
   * parse, never from free text, so neither lets payload prose choose a subtype.
   */
  const hintOf = (field: ParsedField, siblings: ReadonlyMap<string, string>): {
    source: ParsedFieldLocation['hintSource']; depth: number; key: string | undefined } => {
    const depth = hintDepthOf(field.path);
    if (depth >= 0) return { source: 'PATH', depth, key: field.path[depth]! };
    if (!field.highRisk) return { source: 'NONE', depth: -1, key: undefined };
    // The sibling shares this field's parent path, which is empty for a top-level `name`/`value` pair.
    const parent = field.path.slice(0, -1);
    for (const name of NAME_SIBLING_KEYS) {
      const sibling = siblings.get(`${JSON.stringify(parent)}\u0000${name}`);
      if (sibling !== undefined && subtypeForKey(sibling)) return { source: 'NAME_SIBLING', depth: -1, key: sibling };
    }
    return { source: 'NONE', depth: -1, key: undefined };
  };
  let fieldScans = 0;
  let fieldLimitReached = false;
  /** The one #7 format a view's content hint names. A hint is a guess; only parsing can confirm it. */
  const hintedFormats = (view: NormalizedView): readonly Format[] => {
    const hint = view.id === 0 ? normalized.contentType : sniffContentType(view.text);
    return hint === 'UNKNOWN' ? NO_FORMATS : HINTED_FORMATS[hint];
  };
  /**
   * The #7 formats parsed for one view. Every view is parsed by its own content hint, and the root
   * additionally runs the caller's trusted list as a union: a caller assertion is a second opinion about
   * the root payload, not a replacement for the parse the hint named, so a wrong or hostile list cannot
   * suppress the hinted parse. The asserted formats run first, so a caller's own reading still leads the
   * candidate order. Bounded by construction: at most `MAX_REQUESTED_FORMATS` already-validated,
   * de-duplicated formats plus the one hinted format.
   */
  const formatsFor = (view: NormalizedView): readonly Format[] => {
    const hinted = hintedFormats(view);
    if (view.id !== 0 || !requestedFormats) return hinted;
    const union: Format[] = [...requestedFormats];
    for (const format of hinted) if (!union.includes(format)) union.push(format);
    return Object.freeze(union);
  };
  const scanFields = (view: NormalizedView): void => {
    const list = formatsFor(view);
    if (list.length === 0) return;
    if (fieldLimitReached) {
      // The request-wide field budget is spent, so this view's fields are never parsed. That is an
      // inspection gap like any other: the whole view is marked opaque instead of being silently skipped.
      markOpaque('PARSED_FIELD_SCAN_LIMIT', view);
      return;
    }
    for (const format of list) {
      let parsed: ReturnType<typeof parseStructured>;
      try {
        // #7 is asked for exactly this view's size, so a large view is parsed rather than rejected on size.
        parsed = parseStructured(view.text, format, { ...DEFAULT_PARSE_BUDGET, maxInputUnits: view.text.length || 1 },
          host);
      } catch { markOpaque(`PARSER_${format}_INTERNAL_ERROR`, view); continue; }
      if (parsed.status !== 'COMPLETE') {
        // An opaque, malformed, unsupported or over-budget parse is an inspection gap, not "nothing there".
        reasons.add(`PARSER_${format}_${parsed.status}`);
        for (const at of parsed.opaque) markOpaque(`PARSER_${format}_${at.reason}`, view, span(at.start, at.end));
      }
      // A #7 reason is never dropped, not even on a COMPLETE parse: a duplicate key is a structural
      // ambiguity that #13's rewriter refuses, and a caller deciding what to transform cannot see it from
      // the candidates alone. Only COMMENTS is exempt, because comment text is still inside the view text
      // this seam scans in full, so it is an inspection gap nowhere.
      for (const reason of parsed.reasons) {
        if (reason === 'COMMENTS') continue;
        reasons.add(`PARSER_${format}_${reason}`);
      }
      // #7 key paths indexed once per parse, so a `name`/`key` sibling can supply a field's key hint. The sibling
      // key is compared case-insensitively, as #7 does; a repeated path keeps the last parsed value.
      const siblings = new Map<string, string>();
      for (const item of parsed.fields) {
        siblings.set(`${JSON.stringify(item.path.slice(0, -1))}\u0000${item.path[item.path.length - 1]!.toLowerCase()}`,
          item.value);
      }
      for (let index = 0; index < parsed.fields.length; index++) {
        const field = parsed.fields[index]!;
        if (fieldScans >= MAX_FIELD_SCANS) {
          fieldLimitReached = true;
          markOpaque('PARSED_FIELD_SCAN_LIMIT', view, span(field.valueStart, view.text.length));
          return;
        }
        fieldScans++;
        if (!field.value) continue;
        // Verbatim field text was already scanned as part of this view, so only the trusted key hint is new.
        const verbatim = view.text.slice(field.valueStart, field.valueEnd) === field.value;
        const hint = hintOf(field, siblings);
        const fieldKey = hint.key;
        const pathRef = pathRefOf(field.path);
        const fieldSpan = span(field.valueStart, field.valueEnd);
        const unitRef = `n6-${inputDigest}-v${view.id}-${format.toLowerCase()}-f${index}`;
        const place = (start: number, end: number): Placed => ({
          ...locate(view, verbatim ? span(field.valueStart + start, field.valueStart + end) : fieldSpan, 'RAW', verbatim),
          field: Object.freeze({ format, pathRef, hintSource: hint.source, hintDepth: hint.depth,
            highRisk: field.highRisk, span: fieldSpan, valueSpan: span(start, end), verbatim }),
        });
        if (configured !== undefined && verbatim) {
          // The view scan already covered this value's text, so only the trusted #10 key-path hint is new here.
          runConfigured(view, field.value, unitRef, place, field.path, true);
        }
        if (verbatim && fieldKey === undefined) continue;
        try {
          const secret = detectSecrets({ text: field.value, inputRef: unitRef,
            ...(fieldKey === undefined ? {} : { fieldKey }),
            ...(fingerprintKey === undefined ? {} : { fingerprintKey: fingerprintKey as Uint8Array }) });
          if (secret.status === 'FAILURE') markOpaque(`SECRET_${secret.reasons[0] ?? 'FAILURE'}`, view);
          else accept(view, 'SECRET', secret.candidates, place);
        } catch { markOpaque('SECRET_INTERNAL_ERROR', view); }
        if (verbatim) continue;
        // A decoded or escaped value is text no view scan ever saw, so all three sources run over it.
        try {
          const infra = detectInfrastructure({ text: field.value, inputRef: unitRef });
          if (infra.status === 'FAILURE') markOpaque(`INFRASTRUCTURE_${infra.reasons[0] ?? 'FAILURE'}`, view);
          else accept(view, 'INFRASTRUCTURE', infra.candidates.map((item) => ({ ...item, subtype: item.subtype ?? item.semanticType })), place);
        } catch { markOpaque('INFRASTRUCTURE_INTERNAL_ERROR', view); }
        try {
          const contact = generateContactCandidates({ text: field.value, inputRef: unitRef,
            scope: { tenantRef, projectRef }, ...(names === undefined ? {} : { names: names as NameDictionary }) });
          if (contact.status !== 'COMPLETE') {
            for (const reason of contact.reasons) markOpaque(`CONTACT_${reason}`, view);
          }
          if (contact.status !== 'FAILURE') accept(view, 'CONTACT', contact.candidates, place);
        } catch { markOpaque('CONTACT_INTERNAL_ERROR', view); }
        if (configured !== undefined) runConfigured(view, field.value, unitRef, place, field.path);
      }
    }
  };

  let scannedViews = 0;
  for (const view of normalized.views) {
    if (scannedViews++ >= MAX_SCANNED_VIEWS) {
      // One root-wide opaque location covers all views that this composition budget did not scan.
      markOpaque('VIEW_SCAN_LIMIT', normalized.views[0]!);
      break;
    }
    if (view.text.length > MAX_DETECTOR_UNITS) { markOpaque('VIEW_TOO_LARGE', view); continue; }
    let folded: ReturnType<typeof foldForDetection>;
    try { folded = foldForDetection(view.text); }
    catch { markOpaque('FOLD_FAILURE', view); continue; }
    for (const representation of ['RAW', 'FOLDED'] as const) {
      if (representation === 'FOLDED' && folded.text === view.text) continue;
      const text = representation === 'RAW' ? view.text : folded.text;
      if (text.length > MAX_DETECTOR_UNITS) { markOpaque('FOLDED_VIEW_TOO_LARGE', view); continue; }
      const unitRef = `n6-${inputDigest}-v${view.id}-${representation.toLowerCase()}`;
      const place = (start: number, end: number): Placed =>
        locate(view, representation === 'RAW' ? span(start, end) : mapFoldedSpan(folded, start, end), representation, true);
      try {
        const secret = detectSecrets({ text, inputRef: unitRef,
          ...(fingerprintKey === undefined ? {} : { fingerprintKey: fingerprintKey as Uint8Array }) });
        if (secret.status === 'FAILURE') markOpaque(`SECRET_${secret.reasons[0] ?? 'FAILURE'}`, view);
        else accept(view, 'SECRET', secret.candidates, place);
      } catch { markOpaque('SECRET_INTERNAL_ERROR', view); }
      try {
        const infra = detectInfrastructure({ text, inputRef: unitRef });
        if (infra.status === 'FAILURE') markOpaque(`INFRASTRUCTURE_${infra.reasons[0] ?? 'FAILURE'}`, view);
        else accept(view, 'INFRASTRUCTURE', infra.candidates.map((item) => ({ ...item, subtype: item.subtype ?? item.semanticType })), place);
      } catch { markOpaque('INFRASTRUCTURE_INTERNAL_ERROR', view); }
      try {
        const contact = generateContactCandidates({ text, inputRef: unitRef,
          scope: { tenantRef, projectRef }, ...(names === undefined ? {} : { names: names as NameDictionary }) });
        if (contact.status !== 'COMPLETE') {
          for (const reason of contact.reasons) markOpaque(`CONTACT_${reason}`, view);
        }
        if (contact.status !== 'FAILURE') accept(view, 'CONTACT', contact.candidates, place);
      } catch { markOpaque('CONTACT_INTERNAL_ERROR', view); }
      if (configured !== undefined) runConfigured(view, text, unitRef, place);
    }
    scanFields(view);
  }
  return Object.freeze({ status: reasons.size ? 'PARTIAL' : 'COMPLETE',
    reasons: Object.freeze([...reasons].sort()), contentType: normalized.contentType,
    candidates: Object.freeze(candidates), uninspected: Object.freeze(uninspected) });
}
