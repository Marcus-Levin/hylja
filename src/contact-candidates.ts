/**
 * #37 bounded deterministic candidate source for PERSON NAME, EMAIL and PHONE. Pure and NON-ENFORCING:
 * it emits classification v1 detector evidence and spans only. It never returns matched text, selects a
 * treatment or authorizes release. Input is text the caller has already normalized (#6/#7 are pending).
 */
import type { ClassificationClaim, EvidenceProvenance } from './classification.js';

/** Input record for the v1 `detectorEvidence` channel; the composer assigns `source` itself. */
export interface DetectorEvidenceInput {
  version: 1;
  id: string;
  status: 'FOUND';
  provenance: EvidenceProvenance;
  claim: ClassificationClaim;
}

export const CONTACT_PRODUCER = Object.freeze({ id: 'hylja.contact-candidates', version: '1' });
export const CONTACT_SUBTYPES = ['NAME', 'EMAIL', 'PHONE'] as const;
export type ContactSubtype = (typeof CONTACT_SUBTYPES)[number];
export const MAX_TEXT_UNITS = 1 << 20;
const MAX_NAMES = 10_000;
const MAX_CANDIDATES = 4096;

export interface CandidateScope { tenantRef: string; projectRef: string }
export interface ContactCandidate {
  subtype: ContactSubtype;
  /** UTF-16 code-unit span into the normalized input, end-exclusive. */
  start: number;
  end: number;
  /** Unicode code-point span of the same range, end-exclusive. */
  codePointStart: number;
  codePointEnd: number;
  /** How the candidate was found; `FIELD_HINT` means a trusted schema hint covered the whole field. */
  basis: 'PATTERN' | 'KEYWORD_CONTEXT' | 'DICTIONARY' | 'FIELD_HINT';
  evidence: DetectorEvidenceInput;
}
export interface CandidateResult {
  status: 'COMPLETE' | 'FAILURE';
  /** Opaque codes; a FAILURE is never evidence that the input holds no contact data. */
  reasons: readonly string[];
  candidates: readonly ContactCandidate[];
}
export interface CandidateRequest {
  text: string;
  /** Privacy-safe reference to the normalized field or text unit, never raw content. */
  inputRef: string;
  scope: CandidateScope;
  names?: NameDictionary;
  /** Trusted schema/field hint from the integration, never from payload text. */
  fieldHint?: ContactSubtype;
}

function label(value: unknown, limit = 256): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit &&
    value.trim() === value && !/[\u0000-\u001f\u007f]/u.test(value);
}

/* ---------- Tenant/project-scoped configured names ---------- */

declare const nameDictionaryBrand: unique symbol;
/** Opaque handle; names are only reachable through the module-private registry below. */
export interface NameDictionary { readonly [nameDictionaryBrand]: true }
interface DictionaryState { scope: CandidateScope; pattern: RegExp | null }
const dictionaries = new WeakMap<object, DictionaryState>();

function escape(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}
/** Trusted configuration: bind configured names to exactly one tenant and project. */
export function createNameDictionary(scope: CandidateScope, names: readonly string[]): NameDictionary {
  if (!scope || !label(scope.tenantRef) || !label(scope.projectRef) || !Array.isArray(names) ||
    names.length > MAX_NAMES) throw new TypeError('Invalid name dictionary');
  const normalized = new Set<string>();
  for (const name of names) {
    if (!label(name, 128) || !/\p{L}/u.test(name)) throw new TypeError('Invalid name dictionary');
    normalized.add(name.normalize('NFC').replace(/\s+/gu, ' '));
  }
  // Longest first so "Ada Lovelace" wins over "Ada" at the same position.
  const alternatives = [...normalized].sort((a, b) => b.length - a.length || (a < b ? -1 : 1))
    .map((name) => escape(name).replace(/ /gu, '\\s+'));
  const handle = Object.freeze(Object.create(null)) as NameDictionary;
  dictionaries.set(handle, {
    scope: Object.freeze({ tenantRef: scope.tenantRef, projectRef: scope.projectRef }),
    pattern: alternatives.length ?
      new RegExp(`(?<![\\p{L}\\p{N}_])(?:${alternatives.join('|')})(?![\\p{L}\\p{N}_])`, 'giu') : null,
  });
  return handle;
}

/* ---------- Patterns (bounded quantifiers; no nested unbounded repetition) ---------- */

// Local part: dot-atom without leading/trailing/double dots. Domain: labels plus an alphabetic TLD.
const EMAIL = /(?<![A-Za-z0-9%+_-])[A-Za-z0-9%+_-](?:[A-Za-z0-9%+_-]|\.(?=[A-Za-z0-9%+_-])){0,63}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,24}(?![A-Za-z0-9-]|\.[A-Za-z0-9])/gu;
// A run of digits with phone separators. Boundaries exclude tokens such as hosts, versions and UUIDs.
const PHONE = /(?<![\p{L}\p{N}_.:/@#=-])(?:\+|00)?\(?\d{1,4}\)?(?:[ \-.]?\(?\d{1,4}\)?){1,7}(?![\p{L}\p{N}_@]|[.:\-/]\d)/gu;
const PHONE_KEYWORD = /(?:\b(?:tel|telephone|phone|mobile|mobil|cell|fax|telefon|tfn|ring)\b|☎)[\s.:#=-]{0,4}$/iu;

function digitsOf(text: string): string {
  return text.replace(/\D/gu, '');
}
/** Reject shapes that are technical values, not phone numbers. Recall bias: keep when unsure. */
function plausiblePhone(match: string, before: string): 'PATTERN' | 'KEYWORD_CONTEXT' | null {
  const digits = digitsOf(match);
  const keyword = PHONE_KEYWORD.test(before);
  if (digits.length < 7 || digits.length > 15) return null;
  const international = match.startsWith('+') || match.startsWith('00');
  const separators = match.replace(/[\d+]/gu, '');
  // Dotted quads, versions and dotted dates: only dots as separators and no international prefix.
  if (!international && separators.length && /^\.+$/u.test(separators) && !keyword) return null;
  // ISO dates and date-times: YYYY-MM-DD.
  if (/^\d{4}-\d{2}-\d{2}$/u.test(match)) return null;
  // Bare digit runs (IDs, timestamps, counters) need an international prefix or a phone keyword.
  if (!separators.replace(/[()]/gu, '').length && !international && !keyword) return null;
  // Unbalanced parentheses are not a phone layout.
  if ((match.match(/\(/gu)?.length ?? 0) !== (match.match(/\)/gu)?.length ?? 0)) return null;
  return keyword ? 'KEYWORD_CONTEXT' : 'PATTERN';
}

/* ---------- Generation ---------- */

function evidenceFor(subtype: ContactSubtype, index: number, inputRef: string): DetectorEvidenceInput {
  return Object.freeze({
    version: 1, id: `${CONTACT_PRODUCER.id}.${subtype.toLowerCase()}.${index}`, status: 'FOUND',
    provenance: Object.freeze({ inputRef, producerId: CONTACT_PRODUCER.id, producerVersion: CONTACT_PRODUCER.version }),
    // No sensitivity: that is policy metadata. v1 composition therefore stays UNRESOLVED until a
    // trusted configuration supplies it, which is the conservative default.
    claim: Object.freeze({ semanticType: 'PERSON', subtype }),
  });
}

function failure(reason: string): CandidateResult {
  return Object.freeze({ status: 'FAILURE', reasons: Object.freeze([reason]), candidates: Object.freeze([]) });
}

/**
 * Emit every NAME/EMAIL/PHONE candidate in `text`. Overlapping candidates are all kept (for example a
 * configured name inside an email local part): merging belongs to classification composition, which
 * must not discard the stronger protected evidence.
 */
export function generateContactCandidates(request: CandidateRequest): CandidateResult {
  let text: unknown, inputRef: unknown, scope: unknown, names: unknown, fieldHint: unknown;
  try {
    ({ text, inputRef, scope, names, fieldHint } = request);
  } catch { return failure('INVALID_REQUEST'); }
  if (typeof text !== 'string' || !label(inputRef, 1024) || scope === null || typeof scope !== 'object') {
    return failure('INVALID_REQUEST');
  }
  const { tenantRef, projectRef } = scope as Partial<CandidateScope>;
  if (!label(tenantRef) || !label(projectRef)) return failure('INVALID_REQUEST');
  if (fieldHint !== undefined && !(CONTACT_SUBTYPES as readonly unknown[]).includes(fieldHint)) {
    return failure('INVALID_REQUEST');
  }
  if (text.length > MAX_TEXT_UNITS) return failure('INPUT_TOO_LARGE');
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(text)) {
    return failure('INVALID_TEXT');
  }

  const reasons = new Set<string>();
  const found: { subtype: ContactSubtype; start: number; end: number; basis: ContactCandidate['basis'] }[] = [];
  let dictionary: DictionaryState | undefined;
  if (names !== undefined) {
    dictionary = typeof names === 'object' && names !== null ? dictionaries.get(names) : undefined;
    if (!dictionary) reasons.add('INVALID_NAME_DICTIONARY');
    else if (dictionary.scope.tenantRef !== tenantRef || dictionary.scope.projectRef !== projectRef) {
      // Another tenant's or project's names must never match here.
      reasons.add('NAME_DICTIONARY_SCOPE_MISMATCH');
      dictionary = undefined;
    }
  } else reasons.add('NO_NAME_DICTIONARY');

  if (fieldHint !== undefined) {
    const start = text.length - text.trimStart().length;
    const end = text.trimEnd().length;
    if (end > start) found.push({ subtype: fieldHint as ContactSubtype, start, end, basis: 'FIELD_HINT' });
  }
  for (const match of text.matchAll(EMAIL)) {
    found.push({ subtype: 'EMAIL', start: match.index, end: match.index + match[0].length, basis: 'PATTERN' });
  }
  for (const match of text.matchAll(PHONE)) {
    // Trim a trailing separator the pattern may have consumed before a boundary.
    const value = match[0].replace(/[ \-.]+$/u, '');
    const basis = plausiblePhone(value, text.slice(Math.max(0, match.index - 24), match.index));
    if (basis) found.push({ subtype: 'PHONE', start: match.index, end: match.index + value.length, basis });
  }
  if (dictionary?.pattern) {
    dictionary.pattern.lastIndex = 0;
    const source = text.normalize('NFC');
    // Offsets are only valid when NFC normalization did not change the text; otherwise report it.
    if (source !== text) reasons.add('NAME_MATCHING_SKIPPED_NON_NFC');
    else for (const match of source.matchAll(dictionary.pattern)) {
      found.push({ subtype: 'NAME', start: match.index, end: match.index + match[0].length, basis: 'DICTIONARY' });
    }
  }
  if (found.length > MAX_CANDIDATES) return failure('TOO_MANY_CANDIDATES');

  found.sort((a, b) => a.start - b.start || a.end - b.end ||
    CONTACT_SUBTYPES.indexOf(a.subtype) - CONTACT_SUBTYPES.indexOf(b.subtype));
  const unique = found.filter((item, index) => index === 0 || item.start !== found[index - 1]!.start ||
    item.end !== found[index - 1]!.end || item.subtype !== found[index - 1]!.subtype);
  const counters: Record<ContactSubtype, number> = { NAME: 0, EMAIL: 0, PHONE: 0 };
  const candidates = unique.map((item) => {
    const codePointStart = [...text.slice(0, item.start)].length;
    return Object.freeze({
      subtype: item.subtype, start: item.start, end: item.end, codePointStart,
      codePointEnd: codePointStart + [...text.slice(item.start, item.end)].length, basis: item.basis,
      evidence: evidenceFor(item.subtype, counters[item.subtype]++, inputRef),
    });
  });
  return Object.freeze({ status: 'COMPLETE', reasons: Object.freeze([...reasons].sort()),
    candidates: Object.freeze(candidates) });
}
