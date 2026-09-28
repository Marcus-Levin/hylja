/**
 * #6 detection composition. Pure and NON-ENFORCING: normalization, bounded deterministic candidate
 * sources and offset provenance are joined here without transforming input or selecting policy effects.
 * The result contains metadata only; raw and decoded text live only for this call. A non-COMPLETE result
 * must be treated as opaque by a later policy integration.
 */
import { createHash } from 'node:crypto';
import { generateContactCandidates, type CandidateScope, type NameDictionary } from './contact-candidates.js';
import { detectInfrastructure, type InfraFidelity } from './infrastructure-identifiers.js';
import { DEFAULT_BUDGET, foldForDetection, mapFoldedSpan, normalizeInput,
  type ContentType, type Encoding, type NormalizedView } from './normalization.js';
import { detectSecrets } from './secret-detectors.js';
import type { ClassificationClaim, EvidenceProvenance } from './classification.js';

const MAX_DETECTOR_UNITS = 1 << 20;
const MAX_SCANNED_VIEWS = DEFAULT_BUDGET.maxViews + 1;
const MAX_PER_SOURCE = 256;

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
export interface NormalizedCandidate {
  readonly source: 'SECRET' | 'INFRASTRUCTURE' | 'CONTACT';
  readonly subtype?: string;
  readonly rule?: string;
  readonly basis: string;
  readonly fidelity?: Readonly<InfraFidelity>;
  readonly fingerprint?: string;
  readonly evidence: CandidateEvidence;
  readonly view: ViewLocation;
  readonly original: OriginalLocation;
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
  /** Privacy-safe opaque reference, never a value or raw source path. */
  readonly inputRef: string;
  readonly scope: CandidateScope;
  readonly names?: NameDictionary;
  /** Optional trusted tenant key for #8 candidate fingerprints. */
  readonly fingerprintKey?: Uint8Array;
  /** #6 validates this bounded budget; opt-in larger budgets can cost more request time. */
  readonly budget?: unknown;
}

function label(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
function span(start: number, end: number): Span { return Object.freeze({ start, end }); }
function path(views: readonly NormalizedView[], view: NormalizedView): readonly Encoding[] {
  const encodings: Encoding[] = [];
  for (let cursor: NormalizedView | undefined = view; cursor && cursor.parent !== null; cursor = views[cursor.parent]) {
    encodings.push(cursor.encoding);
  }
  return Object.freeze(encodings.reverse());
}
/** Descendants have no byte-level offset map. Their only defensible original location is each outer run. */
function originalOf(views: readonly NormalizedView[], view: NormalizedView, location: Span,
  representation: 'RAW' | 'FOLDED', encodedOrigins: Map<number, OriginalLocation>,
  sourceIsString: boolean): OriginalLocation {
  if (view.parent === null) {
    if (sourceIsString) {
      return Object.freeze({ kind: representation === 'RAW' ? 'ORIGINAL_EXACT' : 'ORIGINAL_COVER', span: location });
    }
    return Object.freeze({ kind: 'UTF8_TEXT', span: location,
      coverage: representation === 'RAW' ? 'EXACT' : 'COVER' });
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
function failure(reason: string): NormalizedDetectionResult {
  return Object.freeze({ status: 'FAILURE', reasons: Object.freeze([reason]), contentType: 'UNKNOWN',
    candidates: Object.freeze([]), uninspected: Object.freeze([]) });
}

/**
 * Run #8, #9 and #37 on every bounded normalized view and on its compatibility fold when it changes.
 * Evidence inputRefs identify view/representation units; v1 evidence alone cannot rewrite the original.
 * A caller must keep the `original` envelope with each candidate and separately enforce policy.
 */
export function detectNormalizedCandidates(request: NormalizedDetectionRequest): NormalizedDetectionResult {
  let input: unknown, inputRef: unknown, scope: unknown, names: unknown, fingerprintKey: unknown, budget: unknown;
  try { ({ input, inputRef, scope, names, fingerprintKey, budget } = request); }
  catch { return failure('INVALID_REQUEST'); }
  let tenantRef: unknown, projectRef: unknown;
  try {
    if (scope === null || typeof scope !== 'object') return failure('INVALID_REQUEST');
    ({ tenantRef, projectRef } = scope as Record<string, unknown>);
  } catch { return failure('INVALID_REQUEST'); }
  if (!label(inputRef, 1024) || !label(tenantRef, 256) || !label(projectRef, 256)) return failure('INVALID_REQUEST');

  const normalized = normalizeInput(input, budget);
  if (normalized.status === 'FAILURE') return failure(`NORMALIZATION_${normalized.reasons[0] ?? 'FAILURE'}`);
  const sourceIsString = typeof input === 'string';
  const reasons = new Set<string>(normalized.reasons.map((reason) => `NORMALIZATION_${reason}`));
  const candidates: NormalizedCandidate[] = [];
  const encodedOrigins = new Map<number, OriginalLocation>();
  const uninspected: OpaqueLocation[] = normalized.uninspected.map((item) => {
    const view = normalized.views[item.viewId]!;
    const viewSpan = span(item.start, item.end);
    return Object.freeze({ reason: item.reason, viewId: view.id, viewSpan,
      original: originalOf(normalized.views, view, viewSpan, 'RAW', encodedOrigins, sourceIsString) });
  });
  const markOpaque = (reason: string, view: NormalizedView): void => {
    reasons.add(reason);
    if (uninspected.length >= 1024) { reasons.add('UNINSPECTED_TRUNCATED'); return; }
    const viewSpan = span(0, view.text.length);
    uninspected.push(Object.freeze({ reason, viewId: view.id, viewSpan,
      original: originalOf(normalized.views, view, viewSpan, 'RAW', encodedOrigins, sourceIsString) }));
  };
  const counts = { SECRET: 0, INFRASTRUCTURE: 0, CONTACT: 0 };
  const inputDigest = createHash('sha256').update(inputRef).digest('hex').slice(0, 32);
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
    const encodingPath = path(normalized.views, view);
    for (const representation of ['RAW', 'FOLDED'] as const) {
      if (representation === 'FOLDED' && folded.text === view.text) continue;
      const text = representation === 'RAW' ? view.text : folded.text;
      if (text.length > MAX_DETECTOR_UNITS) { markOpaque('FOLDED_VIEW_TOO_LARGE', view); continue; }
      const unitRef = `n6-${inputDigest}-v${view.id}-${representation.toLowerCase()}`;
      const place = (start: number, end: number): { view: ViewLocation; original: OriginalLocation } => {
        const inView = representation === 'RAW' ? span(start, end) : mapFoldedSpan(folded, start, end);
        const viewSpan = span(inView.start, inView.end);
        return { view: Object.freeze({ viewId: view.id, span: viewSpan, representation, form: view.form,
          encodingPath }),
        original: originalOf(normalized.views, view, viewSpan, representation, encodedOrigins, sourceIsString) };
      };
      const accept = (source: NormalizedCandidate['source'], items: readonly {
        start: number; end: number; subtype?: string; rule?: string; basis: string; evidence: CandidateEvidence;
        fidelity?: Readonly<InfraFidelity>; fingerprint?: string;
      }[]): void => {
        for (const item of items) {
          if (counts[source] >= MAX_PER_SOURCE) { markOpaque(`${source}_CANDIDATE_LIMIT`, view); break; }
          counts[source]++;
          candidates.push(Object.freeze({ source, ...(item.subtype ? { subtype: item.subtype } : {}),
            ...(item.rule ? { rule: item.rule } : {}), basis: item.basis,
            ...(item.fidelity ? { fidelity: item.fidelity } : {}),
            ...(item.fingerprint ? { fingerprint: item.fingerprint } : {}), evidence: item.evidence,
            ...place(item.start, item.end) }));
        }
      };
      try {
        const secret = detectSecrets({ text, inputRef: unitRef,
          ...(fingerprintKey === undefined ? {} : { fingerprintKey: fingerprintKey as Uint8Array }) });
        if (secret.status === 'FAILURE') markOpaque(`SECRET_${secret.reasons[0] ?? 'FAILURE'}`, view);
        else accept('SECRET', secret.candidates);
      } catch { markOpaque('SECRET_INTERNAL_ERROR', view); }
      try {
        const infra = detectInfrastructure({ text, inputRef: unitRef });
        if (infra.status === 'FAILURE') markOpaque(`INFRASTRUCTURE_${infra.reasons[0] ?? 'FAILURE'}`, view);
        else accept('INFRASTRUCTURE', infra.candidates.map((item) => ({ ...item, subtype: item.subtype ?? item.semanticType })));
      } catch { markOpaque('INFRASTRUCTURE_INTERNAL_ERROR', view); }
      try {
        const contact = generateContactCandidates({ text, inputRef: unitRef,
          scope: { tenantRef, projectRef }, ...(names === undefined ? {} : { names: names as NameDictionary }) });
        if (contact.status !== 'COMPLETE') {
          for (const reason of contact.reasons) markOpaque(`CONTACT_${reason}`, view);
        }
        if (contact.status !== 'FAILURE') accept('CONTACT', contact.candidates);
      } catch { markOpaque('CONTACT_INTERNAL_ERROR', view); }
    }
  }
  return Object.freeze({ status: reasons.size ? 'PARTIAL' : 'COMPLETE',
    reasons: Object.freeze([...reasons].sort()), contentType: normalized.contentType,
    candidates: Object.freeze(candidates), uninspected: Object.freeze(uninspected) });
}
