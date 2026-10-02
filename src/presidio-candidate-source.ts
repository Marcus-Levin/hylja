/**
 * #113 narrow Presidio candidate source: protocol translation only. Pure, evaluation-only and
 * NON-ENFORCING. It transforms no value, resolves no mapping, contacts no remote recognizer, makes
 * no policy decision, authorizes no effect and holds no state between calls.
 *
 * What it does: bound one local worker's request, validate its untrusted reply, translate Python
 * end-exclusive CODE-POINT offsets into Hylja UTF-16 spans, map detector-native entity types through
 * an explicit versioned table into the **currently accepted** v1 contract, and attach the resulting
 * evidence to the #6/#7 provenance the text was actually read from.
 *
 * What it deliberately does not do:
 * - It never trusts a worker claim as authority. A Presidio score is a *detector* score: not a
 *   calibrated probability, not a Hylja sensitivity, not source trust, and not permission to
 *   release. No `sensitivity`, `reversible`, `scope` or `confidence` field is ever emitted, and
 *   `ClassificationContext.trust` stays whatever the trusted integration supplied. The analyzer
 *   **version, language and NER capability** a reply reports back are checked against the values the
 *   trusted configuration pinned and a disagreement is refused, so only the trusted value is ever
 *   carried into a result. A worker can neither place an attacker-chosen string in a shared report
 *   through them nor erase `NO_NER`/`NO_TEXT_CONTEXT` by claiming a capability the pin does not have
 *   - which on its own would have turned a degraded run into a clean `COMPLETE`.
 * - It never reports a string it cannot vouch for. A reply's free text - an entity type, a pattern
 *   name, a recognizer id - is untrusted content, and a grammar check does not change that: a planted
 *   value that happens to be identifier-shaped is still a planted value, and repeating it in two
 *   fields of one reply is one worker agreeing with itself, not corroboration. Type names are
 *   therefore reported only when they are members of `PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES` and
 *   a recognizer id only when it is one of `PRESIDIO_PINNED_RECOGNIZER_IDS`; everything else becomes a
 *   count, a boolean or a closed code. That is an honest evidence loss (`entityType: null`,
 *   `unpinnedUnsupportedTypes`, `recognizerIdUnpinned`, `patternNameReported`), never a disclosure,
 *   and it never promotes a dropped label to a candidate.
 * - It does not reconstruct evidence that Presidio's own pipeline removed. Score thresholds,
 *   allow-lists, context enhancement and duplicate suppression all run upstream of this boundary;
 *   the reply reports what those stages were configured to do, and `limitations` names the evidence
 *   that is therefore *not* observable here. Only the explicitly enabled decision-process seam adds
 *   anything back, and only its vouched-for identifiers and booleans.
 * - It never invents an original offset. A span only ever reaches the original source through
 *   #6's own `placeExternalSpan`, so a decoded view, a folded spelling or an escaped field value
 *   claims a covering span or the encoded envelope exactly as it does for Hylja's own detectors.
 *
 * Candidate evidence ids are derived from the caller's per-request `inputRef`, never from the analysed
 * text. #6 binds its own evidence ids the same way, precisely so that "these two messages share this
 * content here" cannot be read off an id; a text-derived tag would also be a cheap offline oracle for
 * confirming a guessed value. The analysed text's digest travels only in the binding the worker must
 * echo, never into an id.
 */
import { createHash } from 'node:crypto';
import { DEFAULT_SUBTYPES } from './classification.js';
import type { SemanticClass } from './classification.js';
import { foldForDetection } from './normalization.js';
import { DEFAULT_PARSE_BUDGET, parseStructured } from './structured-parsers.js';
import type { EvidenceProvenance } from './classification.js';
import { placeExternalSpan } from './normalized-detection.js';
import type { CandidateEvidence } from './normalized-detection.js';
import type { NormalizedView, NormalizationResult } from './normalization.js';
import type { ExternalSpanTarget, Placed } from './normalized-detection.js';
import type { Format } from './structured-parsers.js';

/** Recorded producer identity for every candidate this source emits. */
export const PRESIDIO_PRODUCER_ID = 'presidio-analyzer';
/** Wire protocol shared with the local Python worker. Version changes are a new constant, not an edit. */
export const PRESIDIO_WORKER_PROTOCOL = 'hylja.presidio.worker';
export const PRESIDIO_WORKER_PROTOCOL_VERSION = 1;
/** Version of the entity table below. Any change to it must bump this string. */
export const PRESIDIO_MAPPING_VERSION = 'presidio-entity-map/1';
/**
 * The only offset unit accepted. Presidio indexes Python `str`, which is code points; Hylja indexes
 * JavaScript strings, which are UTF-16 code units. A worker that declares anything else is refused
 * rather than read, because a UTF-16 reply silently reinterpreted as code points rewrites the wrong
 * substring on any non-BMP text.
 */
export const PRESIDIO_OFFSET_UNIT = 'CODE_POINT';
/** Largest analysed text this adapter will put on a worker, in UTF-16 code units. */
export const PRESIDIO_MAX_ANALYSIS_UNITS = 1 << 20;
/** Largest reply line accepted from a worker, in bytes. */
export const PRESIDIO_MAX_REPLY_BYTES = 1 << 20;
/** Largest result array accepted from a worker. Overflow is a bounded failure, never a truncation. */
export const PRESIDIO_MAX_RESULTS = 256;
/**
 * Most results that may be placed against a #7 FIELD target in one analysis. Each placement repeats
 * the #7 parse, so a worker that returns hundreds of results for one field would otherwise make the
 * *parent* repeat hundreds of full-view parses. Past this bound the remaining results are dropped and
 * the run reports `REPLY_RESULT_LIMIT`; they are never silently discarded.
 */
export const PRESIDIO_MAX_FIELD_PLACEMENTS = 16;

export type PresidioReason =
  | 'INVALID_ANALYSIS_REQUEST'
  | 'INVALID_WORKER_REPLY'
  | 'REPLY_BINDING_MISMATCH'
  | 'REPLY_OFFSET_UNIT_UNSUPPORTED'
  | 'REPLY_RESULT_LIMIT'
  | 'UNSUPPORTED_REPORT_LIMIT'
  | 'PRODUCER_VERSION_MISMATCH'
  | 'REPLY_LANGUAGE_MISMATCH'
  | 'NER_CAPABILITY_MISMATCH'
  | 'SPAN_NOT_INTEGER'
  | 'SPAN_OUT_OF_RANGE'
  | 'SPAN_REVERSED'
  | 'SPAN_TEXT_UNPAIRED_SURROGATE'
  | 'UNSUPPORTED_ENTITY_TYPE'
  | 'SCORE_OUT_OF_RANGE'
  | 'WORKER_REPORTED_FAILURE'
  | 'NO_NER_CAPABILITY';

export interface PresidioEntityMapping {
  readonly semanticType: SemanticClass;
  readonly subtype?: string;
  /** The Hylja candidate family whose existing contract this record joins (not the producing detector). */
  readonly source: 'CONTACT' | 'INFRASTRUCTURE' | 'SECRET';
}

/**
 * Explicit, versioned, detector-native -> accepted-v1 table. Only Presidio entity types whose meaning
 * Hylja v1 actually accepts appear here; everything else is reported as `UNSUPPORTED_ENTITY_TYPE` in
 * the result rather than coerced onto the nearest class. This table does not adopt #65/#66 or the
 * proposed decision-010 dimensions: it is a fixed v1 lookup, and adding a row is a reviewable edit.
 *
 * A row is admitted only if the accepted v1 registry actually knows its class and subtype, so a
 * future row naming a class or subtype v1 does not accept cannot silently create a candidate: it is
 * simply absent from the accepted table and therefore reported as an unsupported entity type. The
 * committed suite asserts every admitted row against `DEFAULT_SUBTYPES`.
 */
const DECLARED_ENTITY_MAPPING: Readonly<Record<string, PresidioEntityMapping>> = Object.freeze({
  PERSON: Object.freeze({ semanticType: 'PERSON', source: 'CONTACT' }),
  EMAIL_ADDRESS: Object.freeze({ semanticType: 'PERSON', subtype: 'EMAIL', source: 'CONTACT' }),
  PHONE_NUMBER: Object.freeze({ semanticType: 'PERSON', subtype: 'PHONE', source: 'CONTACT' }),
  IP_ADDRESS: Object.freeze({ semanticType: 'NETWORK_IDENTIFIER', subtype: 'IP', source: 'INFRASTRUCTURE' }),
  URL: Object.freeze({ semanticType: 'NETWORK_IDENTIFIER', subtype: 'URL', source: 'INFRASTRUCTURE' }),
  MAC_ADDRESS: Object.freeze({ semanticType: 'NETWORK_IDENTIFIER', subtype: 'MAC', source: 'INFRASTRUCTURE' }),
});
function admitted(mapping: PresidioEntityMapping): boolean {
  const subtypes = DEFAULT_SUBTYPES[mapping.semanticType];
  return subtypes !== undefined && (mapping.subtype === undefined || subtypes.includes(mapping.subtype));
}
export const PRESIDIO_ENTITY_MAPPING: Readonly<Record<string, PresidioEntityMapping>> = Object.freeze(
  Object.fromEntries(Object.entries(DECLARED_ENTITY_MAPPING).filter(([, mapping]) => admitted(mapping))));

/** Version of the two reportable-label vocabularies below. Any change to either must bump this string. */
export const PRESIDIO_LABEL_VOCABULARY_VERSION = 'presidio-label-vocabulary/1';

/**
 * The finite set of detector-native entity-type names this repository vouches for as real
 * pinned-release (`presidio-analyzer` 2.2.364) types that the accepted v1 mapping does **not**
 * admit, so a refused type can be reported *by name* instead of only as a count.
 *
 * A name reaching a shared result is a disclosure channel: a worker that puts an analysed value into
 * `entityType` gets it printed, and a fail-closed decision does not make that safe. So a name is
 * reportable only when it is a constant committed here - never because the worker repeated it twice,
 * and never because it satisfies a grammar. Grammar-checking (the reply schema still does) proves
 * shape, not identity: a planted value that happens to be identifier-shaped is still a planted value.
 *
 * This list is deliberately the set this repository can vouch for from its own committed records, and
 * it is **not** a claim to be the upstream catalogue's complete entity list. A type outside it is
 * therefore reported as a count under `entityType: null` plus `unpinnedUnsupportedTypes` - an honest
 * evidence loss, never a disclosure and never a claim of nonexistent coverage. Adding a row is a
 * reviewable edit citing the pinned source, exactly like adding a mapping row.
 *
 * The residual limit of *any* vocabulary approach, stated rather than hidden: an analysed value that
 * happened to equal one of these committed names exactly would be printed as that name. These are ten
 * fixed uppercase identifiers this repository already publishes, not value-shaped tokens, and dropping
 * every name would itself cost the coverage evidence #40 needs - so the trade is deliberate, pinned and
 * versioned.
 */
export const PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES: readonly string[] = Object.freeze([
  'CRYPTO', 'CREDIT_CARD', 'DATE_TIME', 'IBAN_CODE', 'LOCATION', 'MEDICAL_LICENSE', 'NRP',
  'US_DRIVER_LICENSE', 'US_PASSPORT', 'US_SSN',
]);

/**
 * Recognizer class names whose `recognizerId` may cross into a result by name: exactly the
 * recognizers the pinned configuration enables (`evaluations/presidio-worker/manifest.json`). The
 * pinned worker substitutes that manifest's own name for Presidio's per-process `EntityRecognizer.id`,
 * so these are constants this repository already commits. Anything else is reported as the boolean
 * `recognizerIdUnpinned` and its label is dropped - a pattern name is never carried at all, because
 * one measured value ("IPv4") is not a vocabulary and pattern names are detector-internal free text.
 * Adding a name here and to the manifest is one reviewed change; neither can widen the other.
 */
export const PRESIDIO_PINNED_RECOGNIZER_IDS: readonly string[] = Object.freeze([
  'EmailRecognizer', 'IpRecognizer', 'MacAddressRecognizer', 'PhoneRecognizer', 'UrlRecognizer',
  'UsSsnRecognizer',
]);

/** Presidio score is detector evidence. It never becomes Hylja `confidence` or any sensitivity. */
export interface PresidioProducerEvidence {
  /** Recognizer-reported score in [0, 1], exactly as the worker reported it. */
  readonly score: number;
  /** Detector-native entity type this candidate was mapped from. */
  readonly entityType: string;
  /** The mapping version that produced the Hylja claim. */
  readonly mappingVersion: typeof PRESIDIO_MAPPING_VERSION;
  /**
   * Optional, allowlisted decision-process evidence. `text_match` and the raw `pattern` Presidio also
   * offers on this seam are never read by the worker and have no field here.
   */
  readonly seam?: PresidioSeamEvidence;
  /** Configured upstream filtering, recorded so a reader can see what could have removed evidence. */
  readonly filtering: PresidioFilteringProvenance;
}

export interface PresidioFilteringProvenance {
  /** Engine/recognizer score threshold in force. `null` when the worker did not report one. */
  readonly scoreThreshold: number | null;
  readonly deduplicate: boolean;
  /** Count only. Presidio allow lists hold values, so no allow-list entry can ever be carried here. */
  readonly allowListCount: number;
  readonly allowListMatch: 'NONE' | 'EXACT' | 'REGEX';
  /** Whether context enhancement ran, and whether it could see words from the analysed text. */
  readonly context: 'UNAVAILABLE_NO_NLP' | 'DISABLED' | 'TEXT_DERIVED' | 'EXPLICIT_CONTEXT_ONLY';
  /** Whether the decision-process seam was requested and returned for this analysis. */
  readonly decisionProcess: 'NOT_REQUESTED' | 'REQUESTED';
}

export interface PresidioSeamEvidence {
  /** The worker reported decision-process metadata for this result at all. */
  readonly reported: boolean;
  /**
   * The configured recognizer's class name, carried **only** when it is a member of
   * `PRESIDIO_PINNED_RECOGNIZER_IDS`. Absent otherwise: the id is worker-chosen free text.
   */
  readonly recognizerId?: string;
  /** A recognizer id was reported and withheld because it is not a pinned recognizer. */
  readonly recognizerIdUnpinned: boolean;
  /**
   * A pattern name was reported and withheld. Presidio pattern names are detector-internal free text
   * derived from the analysed run, and this repository has pinned no vocabulary for them, so only the
   * fact that one existed survives.
   */
  readonly patternNameReported: boolean;
  /** Whether Presidio says it enhanced this score from context. A boolean, so it is safe to carry. */
  readonly enhancedByContext?: boolean;
}

export interface PresidioCandidate extends Placed {
  readonly source: 'CONTACT' | 'INFRASTRUCTURE' | 'SECRET';
  readonly subtype?: string;
  readonly rule: string;
  readonly basis: string;
  readonly evidence: CandidateEvidence;
  readonly producer: PresidioProducerEvidence;
}

export interface PresidioUnsupportedEntity {
  /**
   * A member of this repository's pinned vocabulary `PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES`, or
   * `null` for a worker-chosen label this adapter cannot vouch for. `null` carries a count only: a
   * repeated label is the same untrusted worker answering twice, not corroboration.
   */
  readonly entityType: string | null;
  readonly count: number;
}

export interface PresidioCandidateResult {
  /**
   * COMPLETE means only that the worker answered a well-formed reply for exactly this bound input
   * with a usable runtime. It is never "the text is clean", never a release permission, and never a
   * claim that the recognizers saw everything (see `limitations`).
   */
  readonly status: 'COMPLETE' | 'PARTIAL' | 'FAILURE';
  readonly reasons: readonly PresidioReason[];
  /** Fixed, content-free limitation codes. These describe evidence this boundary cannot observe. */
  readonly limitations: readonly string[];
  readonly candidates: readonly PresidioCandidate[];
  /**
   * Detector-native types this adapter refused. A name appears only from the pinned vocabulary; the
   * single `entityType: null` entry carries the count of every refused result whose type the worker
   * chose, so those labels are dropped rather than reported.
   */
  readonly unsupported: readonly PresidioUnsupportedEntity[];
  /**
   * How many unsupported entity types the worker *declared* that this adapter never saw a result for.
   * Their names are deliberately not carried: a declared name with no result behind it is a
   * worker-chosen free-form label, and it would otherwise be the one remaining channel by which a
   * worker could place an attacker-chosen string in a shared report.
   */
  readonly declaredUnsupportedTypes: number;
  /**
   * How many **distinct** refused entity-type labels were dropped rather than named, because they are
   * not in the pinned vocabulary. Value-free and unsorted, so the loss is visible and never a channel.
   */
  readonly unpinnedUnsupportedTypes: number;
  /** Digest-bound producer/version evidence for the run, safe to keep in a shared report. */
  readonly provenance: PresidioProvenance;
  /** Worker-reported runtime facts. Absent when the reply was unusable. */
  readonly filtering?: PresidioFilteringProvenance;
}

export interface PresidioProvenance {
  readonly producerId: typeof PRESIDIO_PRODUCER_ID;
  /** Worker-reported analyzer version, or `UNREPORTED`. Never a digest of third-party bytes. */
  readonly producerVersion: string;
  readonly mappingVersion: typeof PRESIDIO_MAPPING_VERSION;
  /** Which pinned label vocabulary produced the type names this record carries. */
  readonly labelVocabularyVersion: typeof PRESIDIO_LABEL_VOCABULARY_VERSION;
  readonly offsetUnit: typeof PRESIDIO_OFFSET_UNIT;
  readonly language: string;
  /** Whether the run had an NER-capable engine. `false` is an explicit, recorded capability limit. */
  readonly nerAvailable: boolean;
  readonly textDigest: string;
}

const MAX_LABEL = 256;
const MAX_TOKEN = 64;
const MAX_CODE_POINTS = PRESIDIO_MAX_ANALYSIS_UNITS;
const LIMITATIONS = Object.freeze({
  /** Recognizer-internal deny lists, pattern rejections and per-entity thresholds are upstream. */
  UPSTREAM_SCORE_THRESHOLD: 'UPSTREAM_SCORE_THRESHOLD',
  UPSTREAM_ALLOW_LIST: 'UPSTREAM_ALLOW_LIST',
  UPSTREAM_CONTEXT_ENHANCEMENT: 'UPSTREAM_CONTEXT_ENHANCEMENT',
  UPSTREAM_DUPLICATE_SUPPRESSION: 'UPSTREAM_DUPLICATE_SUPPRESSION',
  /** No NER: names/locations that only a language model would find are simply absent here. */
  NO_NER: 'NO_NER',
  /**
   * No text-derived context. This belongs to the engine rather than to the enhancer's switch: without
   * an NER-capable engine there are no tokens or lemmas, so a context stage that reads the analysed
   * text cannot run at all, whatever the configuration asked it to do.
   */
  NO_TEXT_CONTEXT: 'NO_TEXT_CONTEXT',
  /** The reply is the analyzer's post-filtering result; recognizer output before it is not observable. */
  POST_FILTER_REPLY_ONLY: 'POST_FILTER_REPLY_ONLY',
  UNSUPPORTED_ENTITY_TYPES: 'UNSUPPORTED_ENTITY_TYPES',
} as const);

function label(value: unknown, max = MAX_LABEL): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
/** Identifier grammar shared with the audit ledger: no `@ / : . whitespace`, so no value rides in. */
function token(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_TOKEN &&
    /^[A-Za-z][A-Za-z0-9_]{0,63}$/u.test(value);
}
/** Version/language identifiers may start with a digit but keep the same separator restrictions. */
function versionToken(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_TOKEN &&
    /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u.test(value);
}
function hexDigest(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value); }
function failure(reasons: readonly PresidioReason[], unsupported: readonly PresidioUnsupportedEntity[] = [],
  limitations: readonly string[] = []): PresidioCandidateResult {
  const all = [...new Set([...reasons])].sort();
  return Object.freeze({ status: all.length ? 'FAILURE' : 'COMPLETE', reasons: Object.freeze(all),
    limitations: Object.freeze([...new Set(limitations)].sort()), candidates: Object.freeze([]),
    unsupported: Object.freeze(unsupported), declaredUnsupportedTypes: 0, unpinnedUnsupportedTypes: 0,
    provenance: Object.freeze({ producerId: PRESIDIO_PRODUCER_ID, producerVersion: 'UNREPORTED',
      mappingVersion: PRESIDIO_MAPPING_VERSION, labelVocabularyVersion: PRESIDIO_LABEL_VOCABULARY_VERSION,
      offsetUnit: PRESIDIO_OFFSET_UNIT, language: 'UNREPORTED',
      nerAvailable: false, textDigest: 'UNBOUND' }) });
}

/* ------------------------------------------------------------------ offset conversion ------- */

/** Code-point index -> UTF-16 offset, plus a flag for text Python and V8 would not round-trip. */
interface CodePointMap {
  readonly offsets: Uint32Array;
  readonly codePoints: number;
  readonly unpaired: boolean;
}

/**
 * Build the code-point -> UTF-16 index for one analysed text.
 *
 * Text containing an unpaired surrogate is reported, not repaired: `TextEncoder` replaces it with
 * U+FFFD, so the worker would analyse different characters than Hylja holds, and Python's `len()`
 * still counts the lone surrogate as one code point. Sending such text would make every subsequent
 * offset a guess, so the analysis is refused instead.
 */
export function codePointIndex(text: string): CodePointMap | null {
  if (typeof text !== 'string' || text.length > MAX_CODE_POINTS) return null;
  const offsets = new Uint32Array(text.length + 1);
  let codePoints = 0;
  let unpaired = false;
  for (let index = 0; index < text.length;) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = text.charCodeAt(index + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) { unpaired = true; index++; }
      else index += 2;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) { unpaired = true; index++; }
    else index++;
    offsets[++codePoints] = index;
  }
  return Object.freeze({ offsets, codePoints, unpaired });
}

export type CodePointSpan =
  | Readonly<{ ok: true; start: number; end: number }>
  | Readonly<{ ok: false; reason: PresidioReason }>;

/**
 * Translate one end-exclusive Python code-point span into a Hylja UTF-16 span. The result is
 * guaranteed to start and end on code-point boundaries, so it can never cut a surrogate pair.
 */
export function codePointSpanToUtf16(map: CodePointMap, start: unknown, end: unknown): CodePointSpan {
  if (map.unpaired) return Object.freeze({ ok: false, reason: 'SPAN_TEXT_UNPAIRED_SURROGATE' });
  for (const value of [start, end]) {
    if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
      return Object.freeze({ ok: false, reason: 'SPAN_NOT_INTEGER' });
    }
  }
  const from = start as number;
  const to = end as number;
  if (from < 0 || to > map.codePoints) return Object.freeze({ ok: false, reason: 'SPAN_OUT_OF_RANGE' });
  if (from >= to) return Object.freeze({ ok: false, reason: 'SPAN_REVERSED' });
  return Object.freeze({ ok: true, start: map.offsets[from]!, end: map.offsets[to]! });
}

/* ------------------------------------------------------------------ request preparation ----- */

export interface PresidioScopeContext {
  /** Privacy-safe opaque request identity. Never a value, a path or a case identifier. */
  readonly requestId: string;
  /** The #6 evidence input reference this analysis belongs to. */
  readonly inputRef: string;
  readonly tenantRef: string;
  readonly projectRef: string;
  /**
   * The analyzer version the trusted configuration pinned, exactly as the worker will report it. It
   * is required rather than optional: without it the only version evidence available would be a
   * worker-supplied string, and a worker that can name itself can put an attacker-chosen token in a
   * shared report. A reply that disagrees is `PRODUCER_VERSION_MISMATCH` with no candidate.
   */
  readonly expectedProducerVersion: string;
  /** The language the trusted configuration pinned; a disagreement is `REPLY_LANGUAGE_MISMATCH`. */
  readonly expectedLanguage: string;
  /**
   * Whether the pinned configuration has an NER-capable engine. Required for the same reason as the
   * version and the language: `runtime.nerAvailable` is a worker claim, and on its own it would decide
   * COMPLETE vs PARTIAL and whether `NO_NER`/`NO_TEXT_CONTEXT` appear in a shared record. A worker
   * claiming a capability the pin does not have would erase the coverage limits and turn a degraded
   * run into a clean one. A disagreement is `NER_CAPABILITY_MISMATCH` with no candidate, and every
   * limitation decision uses the **pinned** value.
   */
  readonly expectedNerAvailable: boolean;
}

export interface PresidioAnalysisPlan {
  readonly binding: Readonly<{
    version: typeof PRESIDIO_WORKER_PROTOCOL_VERSION;
    protocol: typeof PRESIDIO_WORKER_PROTOCOL;
    requestId: string;
    inputRef: string;
    tenantRef: string;
    projectRef: string;
    representation: 'RAW' | 'FOLDED';
    textDigest: string;
  }>;
  /** The exact single newline-terminated line written to the worker. It holds only synthetic text from #6. */
  readonly line: string;
  readonly normalized: NormalizationResult;
  /**
   * A frozen **copy** of the target, not the caller's object. Freezing the plan alone would leave the
   * caller's live object deciding where every offset is credited: mutating it between preparation and
   * completion would move a finding onto a different substring while every binding check still passed,
   * because the binding describes the text the worker saw, not where the answer lands.
   */
  readonly target: ExternalSpanTarget;
  readonly map: CodePointMap;
  readonly text: string;
  /**
   * Digest of the caller's scope references and per-request `inputRef`. This is the only thing a
   * candidate evidence id is derived from, so an id reveals nothing about the analysed content and
   * cannot be compared across tenants, projects or requests.
   */
  readonly refDigest: string;
  /** The trusted pinned analyzer version, language and NER capability, copied into every record. */
  readonly expectedProducerVersion: string;
  readonly expectedLanguage: string;
  readonly expectedNerAvailable: boolean;
}

export type PresidioPreparation = Readonly<{ ok: true; plan: PresidioAnalysisPlan }>
  | Readonly<{ ok: false; reason: PresidioReason }>;

const isSpanKind = (target: ExternalSpanTarget): boolean =>
  target.kind === 'VIEW' || (target.kind === 'FIELD' && typeof target.format === 'string');
const utf8 = new TextEncoder();

/**
 * Derive the exact text a worker will see, straight from the #6 result and the trusted target, then
 * bind it. The caller cannot supply the text, so a worker can never be handed content that the
 * provenance it will be credited with does not describe:
 *
 * - `VIEW`/`RAW` is exactly `view.text`.
 * - `VIEW`/`FOLDED` is exactly #6's own `foldForDetection(view.text).text`; the adapter never folds.
 * - `FIELD` is exactly the decoded value of the named #7 field, taken from a parse repeated here.
 *   An escaped, percent- or entity-decoded value therefore *is* analysable, and #6 will later claim
 *   only a covering span for it rather than an invented original offset.
 *
 * That repeated parse is called without #6's optional `host` argument, so #7's cooperative deadline
 * still applies from its own default clock - nothing about the deadline is dropped - but a caller
 * cannot inject #6's clock into this seam. Each repeat is charged against `PRESIDIO_MAX_FIELD_PLACEMENTS`
 * so an untrusted result count cannot multiply the parent's work.
 */
export function preparePresidioAnalysis(normalized: NormalizationResult, target: ExternalSpanTarget,
  scope: PresidioScopeContext): PresidioPreparation {
  try {
    if (!isSpanKind(target) || !label(scope?.requestId, MAX_LABEL) || !label(scope?.inputRef, 1024) ||
      !label(scope?.tenantRef, MAX_LABEL) || !label(scope?.projectRef, MAX_LABEL) ||
      !versionToken(scope?.expectedProducerVersion) || !versionToken(scope?.expectedLanguage) ||
      typeof scope?.expectedNerAvailable !== 'boolean') {
      return Object.freeze({ ok: false, reason: 'INVALID_ANALYSIS_REQUEST' });
    }
    const views: readonly NormalizedView[] = normalized?.views ?? [];
    const view = views[target.viewId];
    if (!view || typeof view.text !== 'string') return Object.freeze({ ok: false, reason: 'INVALID_ANALYSIS_REQUEST' });
    let text: string;
    if (target.kind === 'VIEW' && target.representation === 'RAW') text = view.text;
    else if (target.kind === 'VIEW' && target.representation === 'FOLDED') text = foldForDetection(view.text).text;
    else if (target.kind === 'FIELD') {
      // #7 is asked for exactly this view's size, so a large view is parsed rather than rejected.
      const parsed = parseStructured(view.text, target.format,
        { ...DEFAULT_PARSE_BUDGET, maxInputUnits: view.text.length || 1 });
      const field = parsed.fields[target.fieldIndex];
      if (!field?.value) return Object.freeze({ ok: false, reason: 'INVALID_ANALYSIS_REQUEST' });
      text = field.value;
    } else return Object.freeze({ ok: false, reason: 'INVALID_ANALYSIS_REQUEST' });
    if (text.length === 0 || text.length > MAX_CODE_POINTS) {
      return Object.freeze({ ok: false, reason: 'INVALID_ANALYSIS_REQUEST' });
    }
    const map = codePointIndex(text);
    if (!map || map.unpaired) return Object.freeze({ ok: false, reason: 'INVALID_ANALYSIS_REQUEST' });
    const textDigest = createHash('sha256').update(text).digest('hex');
    const binding = Object.freeze({
      version: PRESIDIO_WORKER_PROTOCOL_VERSION, protocol: PRESIDIO_WORKER_PROTOCOL,
      requestId: scope.requestId, inputRef: scope.inputRef, tenantRef: scope.tenantRef,
      projectRef: scope.projectRef,
      representation: target.kind === 'VIEW' ? target.representation : ('RAW' as const),
      textDigest,
    });
    const line = `${JSON.stringify({ ...binding, offsetUnit: PRESIDIO_OFFSET_UNIT, text })}\n`;
    // JSON escaping can expand a UTF-16 unit to six bytes, so the cheap bound is exact only when it fits.
    if (line.length * 6 > PRESIDIO_MAX_REPLY_BYTES && utf8.encode(line).byteLength > PRESIDIO_MAX_REPLY_BYTES) {
      return Object.freeze({ ok: false, reason: 'INVALID_ANALYSIS_REQUEST' });
    }
    return Object.freeze({ ok: true, plan: Object.freeze({ binding, line, normalized,
      // A frozen copy: the caller's own object must not stay able to move the answer's placement.
      target: Object.freeze({ ...target }) as ExternalSpanTarget,
      map, text,
      // #6 binds its own evidence ids to the caller's per-request `inputRef`. This goes one step further
      // and mixes in the tenant and project refs, so even a caller that reuses one `inputRef` across
      // scopes cannot correlate two tenants' candidates through their evidence ids.
      refDigest: createHash('sha256').update(
        `presidio-ref.v1\u0000${scope.tenantRef}\u0000${scope.projectRef}\u0000${scope.inputRef}`).digest('hex').slice(0, 32),
      expectedProducerVersion: scope.expectedProducerVersion, expectedLanguage: scope.expectedLanguage,
      expectedNerAvailable: scope.expectedNerAvailable }) });
  } catch { return Object.freeze({ ok: false, reason: 'INVALID_ANALYSIS_REQUEST' }); }
}

/* ------------------------------------------------------------------ reply validation -------- */

interface RawResult { entityType: unknown; start: unknown; end: unknown; score: unknown; seam?: unknown }
/** A declared-type entry exactly as it arrives: `entityType` is a string here and nowhere below. */
type DeclaredUnsupported = Readonly<{ entityType: string; count: number }>;
interface RawReply {
  binding: Record<string, unknown>;
  status: 'OK' | 'PARTIAL' | 'FAILURE';
  offsetUnit: unknown;
  results: RawResult[];
  /** The producer sent more results than the adapter will ever read. Never a truncation. */
  overflow: boolean;
  /** The producer named more unsupported entity types than the bound. Named, never a truncation. */
  unsupportedOverflow: boolean;
  filtering: PresidioFilteringProvenance;
  runtime: { version: string; language: string; nerAvailable: boolean };
  unsupported: DeclaredUnsupported[];
}

const CONTEXTS = ['UNAVAILABLE_NO_NLP', 'DISABLED', 'TEXT_DERIVED', 'EXPLICIT_CONTEXT_ONLY'] as const;
const ALLOW_LIST_MATCHES = ['NONE', 'EXACT', 'REGEX'] as const;
const DECISION_PROCESS = ['NOT_REQUESTED', 'REQUESTED'] as const;

function ownData(value: unknown, required: readonly string[], optional: readonly string[] = []):
Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const keys = Reflect.ownKeys(value);
  if (keys.length < required.length || keys.length > required.length + optional.length) return null;
  const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== 'string' || (!required.includes(key) && !optional.includes(key))) return null;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return null;
    out[key] = descriptor.value;
  }
  for (const key of required) if (!Object.hasOwn(out, key)) return null;
  return out;
}
/** `tooLong` separates "the producer sent more than the cap" from a structurally malformed array. */
function boundedArray(value: unknown, cap: number): { items: unknown[]; tooLong: false } | { tooLong: true } | null {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
  const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 0) return null;
  if (length > cap) return { tooLong: true };
  const items: unknown[] = [];
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return null;
    items.push(descriptor.value);
  }
  return { items, tooLong: false };
}
function numberInRange(value: unknown, low: number, high: number): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= low && value <= high ? value : null;
}
function parseFiltering(raw: unknown): PresidioFilteringProvenance | null {
  const value = ownData(raw, ['scoreThreshold', 'deduplicate', 'allowListCount', 'allowListMatch',
    'context', 'decisionProcess']);
  if (!value) return null;
  const threshold = value.scoreThreshold === null ? null : numberInRange(value.scoreThreshold, 0, 1);
  if (value.scoreThreshold !== null && threshold === null) return null;
  const count = numberInRange(value.allowListCount, 0, 4096);
  if (count === null || typeof value.deduplicate !== 'boolean' ||
    typeof value.allowListMatch !== 'string' || !(ALLOW_LIST_MATCHES as readonly string[]).includes(value.allowListMatch) ||
    typeof value.context !== 'string' || !(CONTEXTS as readonly string[]).includes(value.context) ||
    typeof value.decisionProcess !== 'string' || !(DECISION_PROCESS as readonly string[]).includes(value.decisionProcess)) {
    return null;
  }
  return Object.freeze({ scoreThreshold: threshold, deduplicate: value.deduplicate, allowListCount: count,
    allowListMatch: value.allowListMatch as PresidioFilteringProvenance['allowListMatch'],
    context: value.context as PresidioFilteringProvenance['context'],
    decisionProcess: value.decisionProcess as PresidioFilteringProvenance['decisionProcess'] });
}
function parseRuntime(raw: unknown): RawReply['runtime'] | null {
  const value = ownData(raw, ['version', 'language', 'nerAvailable']);
  if (!value || !versionToken(value.version) || !versionToken(value.language) || typeof value.nerAvailable !== 'boolean') return null;
  return Object.freeze({ version: value.version, language: value.language, nerAvailable: value.nerAvailable });
}
function parseSeam(raw: unknown): { ok: true; value: PresidioProducerEvidence['seam'] } | { ok: false } {
  if (raw === undefined || raw === null) return { ok: true, value: undefined };
  const value = ownData(raw, [], ['patternName', 'recognizerId', 'enhancedByContext']);
  if (!value || Reflect.ownKeys(value).length === 0) return { ok: false };
  // Shape first: a seam that is not the declared object is a malformed reply whatever it holds.
  if (value.patternName !== undefined && !token(value.patternName)) return { ok: false };
  if (value.recognizerId !== undefined && !token(value.recognizerId)) return { ok: false };
  if (value.enhancedByContext !== undefined && typeof value.enhancedByContext !== 'boolean') return { ok: false };
  // Then disclosure control, which is a different and stricter question than the grammar above: a
  // planted value that satisfies that grammar is still a planted value. A recognizer id survives only
  // as a committed constant; a pattern name never survives at all; the booleans always do.
  const reported = value.recognizerId;
  const pinned = typeof reported === 'string' && PRESIDIO_PINNED_RECOGNIZER_IDS.includes(reported);
  return { ok: true, value: Object.freeze({
    reported: true,
    ...(pinned ? { recognizerId: reported as string } : {}),
    recognizerIdUnpinned: typeof reported === 'string' && !pinned,
    patternNameReported: value.patternName !== undefined,
    ...(value.enhancedByContext === undefined ? {} : { enhancedByContext: value.enhancedByContext as boolean }),
  }) };
}

function parseReply(raw: unknown): RawReply | null {
  const value = ownData(raw, ['version', 'protocol', 'requestId', 'inputRef', 'tenantRef', 'projectRef',
    'representation', 'textDigest', 'offsetUnit', 'status', 'results', 'filtering', 'runtime', 'unsupported']);
  if (!value || value.version !== PRESIDIO_WORKER_PROTOCOL_VERSION || value.protocol !== PRESIDIO_WORKER_PROTOCOL) {
    return null;
  }
  if (typeof value.status !== 'string' || !['OK', 'PARTIAL', 'FAILURE'].includes(value.status)) return null;
  if (value.representation !== 'RAW' && value.representation !== 'FOLDED') return null;
  for (const key of ['requestId', 'inputRef', 'tenantRef', 'projectRef'] as const) {
    if (!label(value[key], 1024)) return null;
  }
  if (!hexDigest(value.textDigest)) return null;
  const results = boundedArray(value.results, PRESIDIO_MAX_RESULTS);
  if (results === null) return null;
  const filtering = parseFiltering(value.filtering);
  const runtime = parseRuntime(value.runtime);
  const unsupportedRaw = boundedArray(value.unsupported, 64);
  if (!filtering || !runtime || unsupportedRaw === null) return null;
  const unsupported: DeclaredUnsupported[] = [];
  const declaredTypes = new Set<string>();
  for (const item of (unsupportedRaw.tooLong ? [] : unsupportedRaw.items)) {
    const entry = ownData(item, ['entityType', 'count']);
    const count = entry ? numberInRange(entry.count, 1, 1 << 20) : null;
    if (!entry || !token(entry.entityType) || count === null) return null;
    // A repeated type is refused rather than last-wins, so a declared count cannot be quietly replaced.
    if (declaredTypes.has(entry.entityType as string)) return null;
    declaredTypes.add(entry.entityType as string);
    unsupported.push(Object.freeze({ entityType: entry.entityType as string, count }));
  }
  const parsedResults: RawResult[] = [];
  if (!results.tooLong) {
    for (const item of results.items) {
      const entry = ownData(item, ['entityType', 'start', 'end', 'score'], ['seam']);
      if (!entry || !token(entry.entityType)) return null;
      parsedResults.push({ entityType: entry.entityType, start: entry.start, end: entry.end,
        score: entry.score, seam: entry.seam });
    }
  }
  return { binding: value, status: value.status as RawReply['status'], offsetUnit: value.offsetUnit,
    results: parsedResults, overflow: results.tooLong, unsupportedOverflow: unsupportedRaw.tooLong,
    filtering, runtime, unsupported };
}

/* ------------------------------------------------------------------ composition ------------- */

/**
 * Validate an untrusted worker reply against the exact request that was issued and compose the
 * accepted-v1 evidence it supports.
 *
 * The reply must echo the whole binding: protocol, request, input reference, tenant, project,
 * representation and analysed-text digest. Any difference is `REPLY_BINDING_MISMATCH` and yields no
 * candidate, because a reply for another input, request or tenant is not evidence about this one. A
 * reply that names no supported offset unit is refused before any span is read, and one whose reported
 * analyzer version or language is not the value the trusted configuration pinned is refused before a
 * single worker-supplied string reaches a provenance record or a shared report.
 */
export function completePresidioAnalysis(plan: PresidioAnalysisPlan, raw: string): PresidioCandidateResult {
  let parsed: RawReply | null = null;
  try {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > PRESIDIO_MAX_REPLY_BYTES ||
      !raw.endsWith('\n') || raw.indexOf('\n') !== raw.length - 1) return failure(['INVALID_WORKER_REPLY']);
    parsed = parseReply(JSON.parse(raw.slice(0, -1)));
  } catch { return failure(['INVALID_WORKER_REPLY']); }
  if (!parsed) return failure(['INVALID_WORKER_REPLY']);
  const binding = plan.binding;
  if (parsed.binding.protocol !== binding.protocol ||
    parsed.binding.requestId !== binding.requestId || parsed.binding.inputRef !== binding.inputRef ||
    parsed.binding.tenantRef !== binding.tenantRef || parsed.binding.projectRef !== binding.projectRef ||
    parsed.binding.representation !== binding.representation || parsed.binding.textDigest !== binding.textDigest) {
    return failure(['REPLY_BINDING_MISMATCH']);
  }
  if (parsed.offsetUnit !== PRESIDIO_OFFSET_UNIT) return failure(['REPLY_OFFSET_UNIT_UNSUPPORTED']);
  // The reported identity of the engine is checked, then discarded: every provenance record below
  // carries the trusted pinned value, so a worker-chosen token can never reach a shared report.
  if (parsed.runtime.version !== plan.expectedProducerVersion) return failure(['PRODUCER_VERSION_MISMATCH']);
  if (parsed.runtime.language !== plan.expectedLanguage) return failure(['REPLY_LANGUAGE_MISMATCH']);
  if (parsed.runtime.nerAvailable !== plan.expectedNerAvailable) return failure(['NER_CAPABILITY_MISMATCH']);
  const provenance: PresidioProvenance = Object.freeze({
    producerId: PRESIDIO_PRODUCER_ID, producerVersion: plan.expectedProducerVersion,
    mappingVersion: PRESIDIO_MAPPING_VERSION, labelVocabularyVersion: PRESIDIO_LABEL_VOCABULARY_VERSION,
    offsetUnit: PRESIDIO_OFFSET_UNIT,
    language: plan.expectedLanguage, nerAvailable: plan.expectedNerAvailable, textDigest: binding.textDigest,
  });
  if (parsed.status === 'FAILURE') {
    // An unavailable runtime or a missing model is never a successful zero-findings answer.
    return Object.freeze({ status: 'FAILURE',
      reasons: Object.freeze([
        'WORKER_REPORTED_FAILURE',
        ...(plan.expectedNerAvailable ? [] : ['NO_NER_CAPABILITY'] as PresidioReason[]),
      ].sort() as PresidioReason[]),
      limitations: Object.freeze(limitationsOf(parsed.filtering, !plan.expectedNerAvailable).sort()),
      // No declared label survives on this branch either. A worker answering `FAILURE` is an
      // *ordinary* diagnostic path - an unusable manifest, an import error - and its reply is exactly
      // where a planted type name is most likely to be pasted. Only the count is kept.
      candidates: Object.freeze([]), unsupported: Object.freeze([]),
      declaredUnsupportedTypes: parsed.unsupported.length, unpinnedUnsupportedTypes: 0,
      provenance, filtering: parsed.filtering });
  }
  // A reply may exceed both bounds at once; each loss is named rather than only the first one found.
  if (parsed.overflow) {
    return failure(parsed.unsupportedOverflow
      ? ['REPLY_RESULT_LIMIT', 'UNSUPPORTED_REPORT_LIMIT'] : ['REPLY_RESULT_LIMIT'], []);
  }
  const reasons = new Set<PresidioReason>();
  const limitations = new Set<string>(limitationsOf(parsed.filtering, false));
  if (parsed.unsupportedOverflow) {
    // A worker naming more unsupported types than the bound is itself evidence loss, so it is named
    // here rather than dropped by a cap that says nothing.
    reasons.add('UNSUPPORTED_REPORT_LIMIT');
    limitations.add(LIMITATIONS.UNSUPPORTED_ENTITY_TYPES);
  }
  // Two independent counts for one type: what the worker declared, and what this adapter actually
  // refused. They are merged once at the end with `max` for a *pinned* type, so declaring a type in
  // `unsupported` *and* returning results of that type cannot inflate the number, and neither can it
  // deflate it. An unpinned label cannot be merged by name without reporting it, so its results are
  // summed into one count-free bucket instead.
  const declaredUnsupported = new Map<string, number>(
    parsed.unsupported.map((item) => [item.entityType, item.count]));
  const namedUnsupported = new Map<string, number>();
  const unpinnedTypes = new Set<string>();
  let unpinnedResults = 0;
  const candidates: PresidioCandidate[] = [];
  const seen = new Set<string>();
  let fieldPlacements = 0;
  for (const item of parsed.results) {
    const entityType = item.entityType as string;
    const mapping = PRESIDIO_ENTITY_MAPPING[entityType];
    if (!mapping) {
      reasons.add('UNSUPPORTED_ENTITY_TYPE');
      limitations.add(LIMITATIONS.UNSUPPORTED_ENTITY_TYPES);
      if (PRESIDIO_DECLARED_UNSUPPORTED_ENTITY_TYPES.includes(entityType)) {
        namedUnsupported.set(entityType, (namedUnsupported.get(entityType) ?? 0) + 1);
      } else {
        // The label is kept in a local set for counting only. It is never read again and never
        // reaches the result: a worker's own free text is not evidence of what it detected.
        unpinnedTypes.add(entityType);
        unpinnedResults += 1;
      }
      continue;
    }
    const score = numberInRange(item.score, 0, 1);
    if (score === null) { reasons.add('SCORE_OUT_OF_RANGE'); continue; }
    const span = codePointSpanToUtf16(plan.map, item.start, item.end);
    if (!span.ok) { reasons.add(span.reason); continue; }
    const identity = `${entityType}|${span.start}-${span.end}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    if (plan.target.kind === 'FIELD') {
      // #7 is re-parsed inside `placeExternalSpan` so a caller cannot name a field the worker did
      // not see. That repeat is charged here so untrusted result counts cannot multiply the work.
      if (++fieldPlacements > PRESIDIO_MAX_FIELD_PLACEMENTS) { reasons.add('REPLY_RESULT_LIMIT'); break; }
    }
    // The location comes from #6/#7, never from the worker's arithmetic.
    const placed = placeExternalSpan(plan.normalized, Object.freeze({ ...plan.target, unit: span }));
    if (!placed) { reasons.add('INVALID_ANALYSIS_REQUEST'); continue; }
    const evidenceProvenance: EvidenceProvenance = Object.freeze({ inputRef: binding.inputRef,
      producerId: PRESIDIO_PRODUCER_ID, producerVersion: plan.expectedProducerVersion });
    const evidence: CandidateEvidence = Object.freeze({ version: 1,
      id: `presidio-${plan.refDigest}-${candidates.length + 1}`, status: 'FOUND', provenance: evidenceProvenance,
      claim: Object.freeze({ semanticType: mapping.semanticType,
        ...(mapping.subtype === undefined ? {} : { subtype: mapping.subtype }) }) });
    const seam = parseSeam(item.seam);
    if (!seam.ok) { reasons.add('INVALID_WORKER_REPLY'); continue; }
    const producer: PresidioProducerEvidence = Object.freeze({ score, entityType,
      mappingVersion: PRESIDIO_MAPPING_VERSION, ...(seam.value ? { seam: seam.value } : {}),
      filtering: parsed.filtering });
    candidates.push(Object.freeze({ ...placed, source: mapping.source, ...(mapping.subtype ? { subtype: mapping.subtype } : {}),
      rule: PRESIDIO_MAPPING_VERSION, basis: `PRESIDIO:${entityType}`,
      evidence, producer }));
  }
  // A pinned type the adapter actually refused keeps its name and the larger of the two counts. An
  // unpinned one contributes a single `null` bucket so the dropped evidence stays countable, and a
  // type the worker *only declared* - no result to back it, pinned or not - is a bare count as before.
  let declaredOnly = 0;
  for (const [entityType, count] of declaredUnsupported) {
    if (namedUnsupported.has(entityType)) {
      namedUnsupported.set(entityType, Math.max(count, namedUnsupported.get(entityType) ?? 0));
      continue;
    }
    if (unpinnedTypes.has(entityType)) continue;
    declaredOnly += 1;
  }
  const unsupported: PresidioUnsupportedEntity[] = [...namedUnsupported.entries()]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([entityType, count]) => Object.freeze({ entityType, count }));
  if (unpinnedTypes.size) {
    unsupported.push(Object.freeze({ entityType: null, count: unpinnedResults }));
  }
  if (unsupported.length) limitations.add(LIMITATIONS.UNSUPPORTED_ENTITY_TYPES);
  // A run without a NER-capable engine, or one the worker itself marked partial, never reads
  // COMPLETE: evidence these stages would have produced is simply not present, and COMPLETE must
  // not hide that. Neither does it read as a zero-findings success or as a hard failure: the
  // recognizers that did run reported genuinely, and the missing capability is named instead.
  // Only a *hard* reason - a refused span, an unmapped type, a score out of range - fails a run.
  const degraded = parsed.status === 'PARTIAL' || !plan.expectedNerAvailable;
  if (!plan.expectedNerAvailable) reasons.add('NO_NER_CAPABILITY');
  limitationsOf(parsed.filtering, !plan.expectedNerAvailable).forEach((item) => limitations.add(item));
  const hard = [...reasons].filter((reason) => reason !== 'NO_NER_CAPABILITY');
  const status = hard.length ? (candidates.length ? 'PARTIAL' : 'FAILURE') : (degraded ? 'PARTIAL' : 'COMPLETE');
  return Object.freeze({
    status,
    reasons: Object.freeze([...reasons].sort()), limitations: Object.freeze([...limitations].sort()),
    candidates: Object.freeze(candidates), unsupported: Object.freeze(unsupported),
    declaredUnsupportedTypes: declaredOnly, unpinnedUnsupportedTypes: unpinnedTypes.size,
    provenance, filtering: parsed.filtering });
}

/** Fixed, content-free statements of what this boundary cannot see. */
function limitationsOf(filtering: PresidioFilteringProvenance, noNer: boolean): string[] {
  const items: string[] = [LIMITATIONS.POST_FILTER_REPLY_ONLY];
  if (filtering.scoreThreshold === null || filtering.scoreThreshold > 0) items.push(LIMITATIONS.UPSTREAM_SCORE_THRESHOLD);
  if (filtering.allowListCount > 0) items.push(LIMITATIONS.UPSTREAM_ALLOW_LIST);
  if (filtering.deduplicate) items.push(LIMITATIONS.UPSTREAM_DUPLICATE_SUPPRESSION);
  if (filtering.context === 'UNAVAILABLE_NO_NLP' || filtering.context === 'EXPLICIT_CONTEXT_ONLY' ||
    filtering.context === 'TEXT_DERIVED') {
    items.push(LIMITATIONS.UPSTREAM_CONTEXT_ENHANCEMENT);
  }
  // `NO_TEXT_CONTEXT` follows the *engine*, not the enhancer's switch. With no NER-capable engine there
  // are no tokens or lemmas, so a context stage reading the analysed text cannot produce anything even
  // when a configuration asked it to; reporting that loss only when the switch said "unavailable" would
  // understate the coverage gap of a no-NLP configuration that reported itself as merely disabled.
  if (noNer || filtering.context === 'UNAVAILABLE_NO_NLP' || filtering.context === 'EXPLICIT_CONTEXT_ONLY') {
    items.push(LIMITATIONS.NO_TEXT_CONTEXT);
  }
  if (noNer) items.push(LIMITATIONS.NO_NER);
  return items;
}

/** Re-exported so a caller can name the #7 formats this adapter can analyse as a field target. */
export type PresidioFieldFormat = Format;
