/**
 * #37 bounded deterministic candidate source for PERSON NAME, EMAIL and PHONE. Pure and NON-ENFORCING:
 * it emits classification v1 detector evidence and spans only. It never returns matched text, selects a
 * treatment or authorizes release. Input is text the caller has already normalized (#6/#7 are pending).
 */
import { createHash } from 'node:crypto';
import type { ClassificationClaim, EvidenceProvenance } from './classification.js';

/** Input record for the v1 `detectorEvidence` channel; the composer assigns `source` itself. */
export interface DetectorEvidenceInput {
  version: 1;
  id: string;
  status: 'FOUND';
  provenance: EvidenceProvenance;
  claim: ClassificationClaim;
}

export const CONTACT_PRODUCER = Object.freeze({ id: 'hylja.contact-candidates', version: '2' });
export const CONTACT_SUBTYPES = ['NAME', 'EMAIL', 'PHONE'] as const;
export type ContactSubtype = (typeof CONTACT_SUBTYPES)[number];
export const MAX_TEXT_UNITS = 1 << 20;
/** Matches the v1 composer's per-channel limit, so every COMPLETE result can be composed. */
export const MAX_CANDIDATES = 256;
const MAX_NAMES = 10_000;
const MAX_NAME_TOKENS = 16;

export interface CandidateScope { tenantRef: string; projectRef: string }
export interface ContactCandidate {
  subtype: ContactSubtype;
  /** UTF-16 code-unit span into the input, end-exclusive. */
  start: number;
  end: number;
  /** Unicode code-point span of the same range, end-exclusive. */
  codePointStart: number;
  codePointEnd: number;
  /** How the candidate was found; `FIELD_HINT` means a trusted schema hint covered the whole field. */
  basis: 'PATTERN' | 'KEYWORD_CONTEXT' | 'DICTIONARY' | 'FIELD_HINT';
  evidence: DetectorEvidenceInput;
}
/**
 * COMPLETE: every requested source ran over the whole input. PARTIAL: some requested source did not run
 * (see reasons); the candidates are real but absence proves nothing. FAILURE: nothing ran. Only COMPLETE
 * may be read as "these sources found nothing else", and even that is not proof of no personal data.
 */
export interface CandidateResult {
  status: 'COMPLETE' | 'PARTIAL' | 'FAILURE';
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

/* ---------- Text folding shared by names and input: NFC per cluster, with an offset map ---------- */

// Marks belong to their token: Indic/Thai/Arabic vowel signs and case-fold marks (İ -> i + U+0307).
const TOKEN = /[\p{L}\p{N}_][\p{L}\p{M}\p{N}_]*/gu;
/** Per folded code unit: original start and end of the cluster it came from. */
interface Folded { text: string; origin: number[]; originEnd: number[] }
/**
 * NFC-normalize and lower-case each base character with its combining marks, recording for every folded
 * code unit the original offset of its cluster. Offsets therefore survive decomposed input. Compositions
 * that span clusters (e.g. conjoining Hangul jamo) are not joined; #6 owns full normalization.
 */
function fold(text: string): Folded {
  let folded = '';
  const origin: number[] = [];
  const originEnd: number[] = [];
  for (const match of text.matchAll(/\P{M}\p{M}*|\p{M}+/gsu)) {
    // Invisible default-ignorable marks (U+034F, variation selectors) must not split or extend a token.
    const piece = match[0].normalize('NFC').toLowerCase().replace(/(?=\p{M})\p{Default_Ignorable_Code_Point}/gu, '');
    for (let unit = 0; unit < piece.length; unit++) {
      origin.push(match.index);
      originEnd.push(match.index + match[0].length);
    }
    folded += piece;
  }
  return { text: folded, origin, originEnd };
}
/** Separator between two tokens: whitespace runs compare equal, anything else must match exactly. */
function separator(text: string): string {
  return text.replace(/\s+/gu, ' ');
}

/* ---------- Tenant/project-scoped configured names: a token trie, linear in input tokens ---------- */

declare const nameDictionaryBrand: unique symbol;
/** Opaque handle; names are only reachable through the module-private registry below. */
export interface NameDictionary { readonly [nameDictionaryBrand]: true }
interface TrieNode { terminal: boolean; next: Map<string, TrieNode> }
interface DictionaryState { scope: CandidateScope; root: TrieNode }
const dictionaries = new WeakMap<object, DictionaryState>();
const edge = (sep: string, token: string): string => `${sep}\u0000${token}`;

/**
 * Trusted configuration: bind configured names to exactly one tenant and project. Names match as token
 * sequences, case-insensitively, with the same separators between tokens (whitespace runs are equal);
 * punctuation before the first or after the last token is ignored.
 */
export function createNameDictionary(scope: CandidateScope, names: readonly string[]): NameDictionary {
  if (!scope || !label(scope.tenantRef) || !label(scope.projectRef) || !Array.isArray(names) ||
    names.length > MAX_NAMES) throw new TypeError('Invalid name dictionary');
  const root: TrieNode = { terminal: false, next: new Map() };
  for (const name of names) {
    if (!label(name, 128) || !/\p{L}/u.test(name)) throw new TypeError('Invalid name dictionary');
    const folded = fold(name).text;
    const tokens = [...folded.matchAll(TOKEN)];
    if (!tokens.length || tokens.length > MAX_NAME_TOKENS) throw new TypeError('Invalid name dictionary');
    let node = root;
    tokens.forEach((token, index) => {
      const previous = tokens[index - 1];
      const key = edge(previous ? separator(folded.slice(previous.index + previous[0].length, token.index)) : '',
        token[0]);
      let child = node.next.get(key);
      if (!child) node.next.set(key, child = { terminal: false, next: new Map() });
      node = child;
    });
    node.terminal = true;
  }
  const handle = Object.freeze(Object.create(null)) as NameDictionary;
  dictionaries.set(handle, { scope: Object.freeze({ tenantRef: scope.tenantRef, projectRef: scope.projectRef }), root });
  return handle;
}
/** Longest configured name at each token start; non-overlapping, O(tokens x MAX_NAME_TOKENS). */
function matchNames(text: string, root: TrieNode): { start: number; end: number }[] {
  const folded = fold(text);
  const tokens = [...folded.text.matchAll(TOKEN)];
  const spans: { start: number; end: number }[] = [];
  for (let index = 0; index < tokens.length;) {
    let node = root.next.get(edge('', tokens[index]![0]));
    let longest = node?.terminal ? index : -1;
    for (let next = index + 1; node && next < tokens.length && next - index < MAX_NAME_TOKENS; next++) {
      const before = tokens[next - 1]!;
      node = node.next.get(edge(separator(folded.text.slice(before.index + before[0].length, tokens[next]!.index)),
        tokens[next]![0]));
      if (node?.terminal) longest = next;
    }
    if (longest < 0) { index++; continue; }
    const first = tokens[index]!, last = tokens[longest]!;
    // End at the end of the cluster holding the last folded unit, so no trailing mark or letter is lost.
    spans.push({ start: folded.origin[first.index]!, end: folded.originEnd[last.index + last[0].length - 1]! });
    index = longest + 1;
  }
  return spans;
}

/* ---------- Patterns (bounded quantifiers; no nested unbounded repetition) ---------- */

// Local part: Unicode letters/digits (RFC 6531) and the atext that appears in practice. It may not start
// with an apostrophe, and rarer atext (`/ = ? & ~ { } \``) is excluded so quotes, paths and URL queries are
// not swallowed. The lookbehinds exclude every start character and a `.` that follows a local character, so a
// match starts at the token start, a dotted run has a single start (bounded work), and a leading `.` or
// `...` in prose does not hide the address. 64 is the RFC 5321 local-part limit.
const LOCAL_START = '[\\p{L}\\p{M}\\p{N}_%+-]';
const LOCAL = "[\\p{L}\\p{M}\\p{N}_%+'-]";
const EMAIL = new RegExp(`(?<![\\p{L}\\p{M}\\p{N}_%+-])(?<![\\p{L}\\p{M}\\p{N}_%+'-]\\.)${LOCAL_START}(?:${LOCAL}|\\.(?=${LOCAL})){0,63}@` +
  '(?:[\\p{L}\\p{N}](?:[\\p{L}\\p{M}\\p{N}-]{0,61}[\\p{L}\\p{M}\\p{N}])?\\.){1,16}(?:xn--[a-z0-9-]{1,59}|\\p{L}[\\p{L}\\p{M}]{1,47})' +
  '(?![\\p{L}\\p{M}\\p{N}]|\\.[\\p{L}\\p{N}])', 'gu');
// Digit groups with phone separators. `:`, `=` and `#` may precede (keyword forms such as `tel:`).
const PHONE = /(?<![\p{L}\p{N}_./@-])(?:\+|00)?\(?\d{1,4}\)?(?:[ \-.]?\(?\d{1,4}\)?){1,7}(?![\p{L}\p{N}_@]|[.:\-/]\d)/gu;
const PHONE_KEYWORD = /(?:\b(?:tel|telephone|phone|mobile|mob|mobil|cell|fax|telefon|tfn|tlf|ring)(?:\s*(?:number|no\.?|nr\.?|#))?|☎)[\s.:#=-]{0,4}$/iu;
const BARE_PREFIX = /[:=#]$/u;

/** Drop an unbalanced leading `(` or trailing `)` that belongs to surrounding prose. */
function balance(start: number, value: string): { start: number; value: string } {
  let open = (value.match(/\(/gu) ?? []).length;
  let close = (value.match(/\)/gu) ?? []).length;
  while (close > open && value.endsWith(')')) { value = value.slice(0, -1); close--; }
  while (open > close && value.startsWith('(')) { value = value.slice(1); start++; open--; }
  // Parentheses wrapping the whole number are prose, not part of the number.
  if (/^\([^()]*\)$/u.test(value)) { value = value.slice(1, -1); start++; }
  return { start, value: value.replace(/[ \-.]+$/u, '') };
}
/** Reject shapes that are technical values, not phone numbers. Recall bias: keep when unsure. */
function plausiblePhone(value: string, before: string): 'PATTERN' | 'KEYWORD_CONTEXT' | null {
  const digits = value.replace(/\D/gu, '');
  const keyword = PHONE_KEYWORD.test(before);
  if (digits.length < 7 || digits.length > 15) return null;
  // A bare `k=`, `#` or `x:` prefix without a phone keyword marks a key/value or reference, not a phone.
  if (!keyword && BARE_PREFIX.test(before)) return null;
  const international = value.startsWith('+') || value.startsWith('00');
  const separators = value.replace(/[\d+]/gu, '');
  // Dotted quads, versions and dotted dates: only dots as separators and no international prefix.
  if (!international && separators.length && /^\.+$/u.test(separators) && !keyword) return null;
  if (/^\d{4}-\d{2}-\d{2}$/u.test(value)) return null;
  // Bare digit runs (IDs, timestamps, counters) need an international prefix or a phone keyword.
  if (!separators.replace(/[()]/gu, '').length && !international && !keyword) return null;
  if ((value.match(/\(/gu) ?? []).length !== (value.match(/\)/gu) ?? []).length) return null;
  return keyword ? 'KEYWORD_CONTEXT' : 'PATTERN';
}

/* ---------- Generation ---------- */

function evidenceFor(subtype: ContactSubtype, start: number, end: number, inputRef: string): DetectorEvidenceInput {
  // Unique across fields and positions so composing several fields never collides.
  const field = createHash('sha256').update(inputRef).digest('hex').slice(0, 16);
  return Object.freeze({
    version: 1, id: `${CONTACT_PRODUCER.id}.${subtype.toLowerCase()}.${field}.${start}-${end}`, status: 'FOUND',
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
  let text: unknown, inputRef: unknown, names: unknown, fieldHint: unknown, tenantRef: unknown, projectRef: unknown;
  try {
    let scope: unknown;
    ({ text, inputRef, scope, names, fieldHint } = request);
    if (scope === null || typeof scope !== 'object') return failure('INVALID_REQUEST');
    ({ tenantRef, projectRef } = scope as Record<string, unknown>);
  } catch { return failure('INVALID_REQUEST'); }
  if (typeof text !== 'string' || !label(inputRef, 1024) || !label(tenantRef) || !label(projectRef)) {
    return failure('INVALID_REQUEST');
  }
  if (fieldHint !== undefined && !(CONTACT_SUBTYPES as readonly unknown[]).includes(fieldHint)) {
    return failure('INVALID_REQUEST');
  }
  if (text.length > MAX_TEXT_UNITS) return failure('INPUT_TOO_LARGE');
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(text)) {
    return failure('INVALID_TEXT');
  }

  const reasons = new Set<string>();
  let partial = false;
  let dictionary: DictionaryState | undefined;
  if (names !== undefined) {
    dictionary = typeof names === 'object' && names !== null ? dictionaries.get(names) : undefined;
    if (!dictionary) { reasons.add('INVALID_NAME_DICTIONARY'); partial = true; }
    else if (dictionary.scope.tenantRef !== tenantRef || dictionary.scope.projectRef !== projectRef) {
      // Another tenant's or project's names must never match here, and the caller must see that it failed.
      reasons.add('NAME_DICTIONARY_SCOPE_MISMATCH');
      partial = true;
      dictionary = undefined;
    }
  } else reasons.add('NO_NAME_DICTIONARY');

  const found: { subtype: ContactSubtype; start: number; end: number; basis: ContactCandidate['basis'] }[] = [];
  const add = (item: (typeof found)[number]): boolean => found.push(item) <= MAX_CANDIDATES;
  if (fieldHint !== undefined) {
    const start = text.length - text.trimStart().length;
    const end = text.trimEnd().length;
    if (end > start) add({ subtype: fieldHint as ContactSubtype, start, end, basis: 'FIELD_HINT' });
  }
  for (const match of text.matchAll(EMAIL)) {
    if (!add({ subtype: 'EMAIL', start: match.index, end: match.index + match[0].length, basis: 'PATTERN' })) {
      return failure('TOO_MANY_CANDIDATES');
    }
  }
  for (const match of text.matchAll(PHONE)) {
    const { start, value } = balance(match.index, match[0]);
    const basis = plausiblePhone(value, text.slice(Math.max(0, start - 32), start));
    if (basis && !add({ subtype: 'PHONE', start, end: start + value.length, basis })) return failure('TOO_MANY_CANDIDATES');
  }
  if (dictionary) {
    for (const span of matchNames(text, dictionary.root)) {
      if (!add({ subtype: 'NAME', ...span, basis: 'DICTIONARY' })) return failure('TOO_MANY_CANDIDATES');
    }
  }

  found.sort((a, b) => a.start - b.start || a.end - b.end ||
    CONTACT_SUBTYPES.indexOf(a.subtype) - CONTACT_SUBTYPES.indexOf(b.subtype));
  const unique = found.filter((item, index) => index === 0 || item.start !== found[index - 1]!.start ||
    item.end !== found[index - 1]!.end || item.subtype !== found[index - 1]!.subtype);
  // Candidates are sorted by start, so code-point offsets are counted incrementally (linear overall).
  let counted = 0, countedPoints = 0;
  const points = (from: number, to: number): number => {
    let total = 0;
    for (let unit = from; unit < to; unit++) {
      const code = text.charCodeAt(unit);
      if (code < 0xdc00 || code > 0xdfff) total++;
    }
    return total;
  };
  const candidates = unique.map((item) => {
    countedPoints += points(counted, item.start);
    counted = item.start;
    const codePointStart = countedPoints;
    return Object.freeze({
      subtype: item.subtype, start: item.start, end: item.end, codePointStart,
      codePointEnd: codePointStart + points(item.start, item.end), basis: item.basis,
      evidence: evidenceFor(item.subtype, item.start, item.end, inputRef),
    });
  });
  return Object.freeze({ status: partial ? 'PARTIAL' : 'COMPLETE', reasons: Object.freeze([...reasons].sort()),
    candidates: Object.freeze(candidates) });
}
