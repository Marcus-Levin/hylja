/**
 * #10 configured customer, project, business and engineering candidate sources. Pure and NON-ENFORCING.
 * A trusted configuration (term dictionaries, engineering ID templates, field hints) is bound to exactly
 * one tenant and project behind an opaque handle. Results carry spans and v1 evidence, never configured
 * terms or matched text. A generic engineering-key rule runs independently and is labelled separately.
 */
import { createHash } from 'node:crypto';
import { DEFAULT_SUBTYPES, SENSITIVITIES } from './classification.js';
import type { ClassificationClaim, EvidenceProvenance, Sensitivity } from './classification.js';

export const CONFIGURED_PRODUCER = Object.freeze({ id: 'hylja.configured-candidates', version: '1' });
export const CONFIGURED_TYPES = ['CUSTOMER_OR_PARTNER', 'PROJECT_OR_CONTRACT', 'BUSINESS_CONFIDENTIAL', 'ENGINEERING_IDENTIFIER'] as const;
export type ConfiguredType = (typeof CONFIGURED_TYPES)[number];
export const MAX_TEXT_UNITS = 1 << 20;
/** Matches the v1 composer's per-channel limit. */
export const MAX_CANDIDATES = 256;
const MAX_TERMS = 10_000, MAX_TERM_TOKENS = 16, MAX_PATTERNS = 64, MAX_HINTS = 256, MAX_TEMPLATE = 64;

export interface DetectorEvidenceInput {
  version: 1;
  id: string;
  status: 'FOUND';
  provenance: EvidenceProvenance;
  claim: ClassificationClaim;
}
export interface CandidateScope { tenantRef: string; projectRef: string }
interface Classified { semanticType: ConfiguredType; subtype?: string; sensitivity?: Sensitivity }
export interface TermEntry extends Classified { term: string }
/**
 * `{A}` uppercase letter, `{a}` lowercase letter, `{9}` digit, `{X}` uppercase letter or digit, with an
 * optional count `{9:4}` or range `{9:2-6}`; everything else is literal. A variable-length placeholder must
 * be followed by a literal or the end, so matching never backtracks between adjacent placeholders.
 */
export interface PatternEntry extends Classified { template: string }
/** A #7 key path such as `asset.tag` or `items.*.drawing`; `*` matches one segment. */
export interface FieldHintEntry extends Classified { path: string }
export interface CandidateConfig { terms?: readonly TermEntry[]; patterns?: readonly PatternEntry[]; fieldHints?: readonly FieldHintEntry[] }

export interface ConfiguredCandidate extends Classified {
  /** `dictionary.term`, `pattern.<index>`, `field-hint.<index>` (tenant configuration) or `context.engineering-key` (generic). */
  rule: string;
  basis: 'DICTIONARY' | 'PATTERN' | 'FIELD_HINT' | 'CONTEXT';
  start: number;
  end: number;
  evidence: DetectorEvidenceInput;
}
export interface ConfiguredResult {
  /** COMPLETE: every requested source ran. PARTIAL: the configuration was invalid or out of scope (see reasons). */
  status: 'COMPLETE' | 'PARTIAL' | 'FAILURE';
  reasons: readonly string[];
  candidates: readonly ConfiguredCandidate[];
}
export interface ConfiguredRequest {
  text: string;
  inputRef: string;
  scope: CandidateScope;
  config?: CandidateConfigHandle;
  /** Trusted parser key path (#7) for `text` when it is a single field value. */
  fieldPath?: readonly string[];
}

function label(value: unknown, limit = 256): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
function classified(entry: unknown): Classified | null {
  if (!entry || typeof entry !== 'object') return null;
  const { semanticType, subtype, sensitivity } = entry as Record<string, unknown>;
  if (!(CONFIGURED_TYPES as readonly unknown[]).includes(semanticType)) return null;
  const type = semanticType as ConfiguredType;
  if (subtype !== undefined && (typeof subtype !== 'string' || !DEFAULT_SUBTYPES[type].includes(subtype))) return null;
  if (type === 'ENGINEERING_IDENTIFIER' && subtype === undefined) return null;
  if (sensitivity !== undefined && !(SENSITIVITIES as readonly unknown[]).includes(sensitivity)) return null;
  return { semanticType: type, ...(subtype !== undefined ? { subtype } : {}), ...(sensitivity !== undefined ? { sensitivity: sensitivity as Sensitivity } : {}) };
}

/* ---------- Folding and term trie (linear in input tokens) ---------- */

const TOKEN = /[\p{L}\p{N}_][\p{L}\p{M}\p{N}_]*/gu;
interface Folded { text: string; origin: number[]; originEnd: number[] }
function fold(text: string): Folded {
  let folded = '';
  const origin: number[] = [], originEnd: number[] = [];
  for (const match of text.matchAll(/\P{M}\p{M}*|\p{M}+/gsu)) {
    const piece = match[0].normalize('NFC').toLowerCase().replace(/(?=\p{M})\p{Default_Ignorable_Code_Point}/gu, '');
    for (let unit = 0; unit < piece.length; unit++) { origin.push(match.index); originEnd.push(match.index + match[0].length); }
    folded += piece;
  }
  return { text: folded, origin, originEnd };
}
const separator = (text: string): string => text.replace(/\s+/gu, ' ');
const edge = (sep: string, token: string): string => `${sep}\u0000${token}`;
interface TrieNode { entry?: number; next: Map<string, TrieNode> }

/* ---------- Templates ---------- */

const CLASSES: Readonly<Record<string, string>> = Object.freeze({ A: 'A-Z', a: 'a-z', '9': '0-9', X: 'A-Z0-9' });
/** Compile a template to a bounded, backtracking-free regex source, or null when invalid or ambiguous. */
function compileTemplate(template: unknown): string | null {
  if (!label(template, MAX_TEMPLATE)) return null;
  let source = '', placeholders = 0, pendingVariable = false;
  for (let index = 0; index < template.length;) {
    const placeholder = /^\{([Aa9X])(?::(\d{1,2})(?:-(\d{1,2}))?)?\}/u.exec(template.slice(index));
    if (placeholder) {
      if (pendingVariable) return null;
      const min = placeholder[2] ? Number(placeholder[2]) : 1;
      const max = placeholder[3] ? Number(placeholder[3]) : min;
      if (min < 1 || max < min || max > 32) return null;
      source += `[${CLASSES[placeholder[1]!]}]{${min}${max === min ? '' : `,${max}`}}`;
      pendingVariable = max !== min;
      placeholders++;
      index += placeholder[0].length;
      continue;
    }
    const char = template[index]!;
    if (char === '{' || char === '}') return null;
    // Only regex syntax characters are escaped; `\\-` is not a valid escape outside a class in `u` mode.
    source += char.replace(/[.*+?^${}()|[\]\\/]/gu, '\\$&');
    pendingVariable = false;
    index++;
  }
  // A template must constrain something; a bare literal belongs in the term dictionary.
  return placeholders ? `(?<![A-Za-z0-9_-])${source}(?![A-Za-z0-9_-])` : null;
}

/* ---------- Configuration handle ---------- */

declare const configBrand: unique symbol;
/** Opaque handle; configured terms are only reachable through the module-private registry. */
export interface CandidateConfigHandle { readonly [configBrand]: true }
interface Compiled {
  scope: CandidateScope;
  entries: Classified[];
  root: TrieNode;
  patterns: { regex: RegExp; entry: Classified }[];
  hints: { path: readonly string[]; entry: Classified }[];
}
const registry = new WeakMap<object, Compiled>();

/**
 * Trusted configuration: bind terms, templates and field hints to one tenant and project. Errors never
 * include configured text (`Invalid candidate configuration` only).
 */
export function createCandidateConfig(scope: CandidateScope, config: CandidateConfig): CandidateConfigHandle {
  const invalid = (): never => { throw new TypeError('Invalid candidate configuration'); };
  try {
    if (!scope || !label(scope.tenantRef) || !label(scope.projectRef) || !config || typeof config !== 'object') invalid();
    const { terms = [], patterns = [], fieldHints = [] } = config;
    if (!Array.isArray(terms) || !Array.isArray(patterns) || !Array.isArray(fieldHints) || terms.length > MAX_TERMS ||
      patterns.length > MAX_PATTERNS || fieldHints.length > MAX_HINTS) invalid();
    const compiled: Compiled = { scope: Object.freeze({ tenantRef: scope.tenantRef, projectRef: scope.projectRef }), entries: [],
      root: { next: new Map() }, patterns: [], hints: [] };
    for (const entry of terms as unknown[]) {
      const meta = classified(entry);
      const term = (entry as Record<string, unknown>)?.term;
      if (!meta || !label(term, 256) || !/[\p{L}\p{N}]/u.test(term)) invalid();
      const folded = fold(term as string).text;
      const tokens = [...folded.matchAll(TOKEN)];
      if (!tokens.length || tokens.length > MAX_TERM_TOKENS) invalid();
      let node = compiled.root;
      tokens.forEach((token, index) => {
        const previous = tokens[index - 1];
        const key = edge(previous ? separator(folded.slice(previous.index + previous[0].length, token.index)) : '', token[0]);
        let child = node.next.get(key);
        if (!child) node.next.set(key, child = { next: new Map() });
        node = child;
      });
      compiled.entries.push(meta!);
      node.entry = compiled.entries.length - 1;
    }
    for (const entry of patterns as unknown[]) {
      const meta = classified(entry);
      const source = compileTemplate((entry as Record<string, unknown>)?.template);
      if (!meta || !source) invalid();
      compiled.patterns.push({ regex: new RegExp(source!, 'gu'), entry: meta! });
    }
    for (const entry of fieldHints as unknown[]) {
      const meta = classified(entry);
      const path = (entry as Record<string, unknown>)?.path;
      if (!meta || !label(path, 256)) invalid();
      const segments = (path as string).split('.');
      if (segments.length > 16 || segments.some((segment) => !segment)) invalid();
      compiled.hints.push({ path: Object.freeze(segments), entry: meta! });
    }
    const handle = Object.freeze(Object.create(null)) as CandidateConfigHandle;
    registry.set(handle, compiled);
    return handle;
  } catch { return invalid(); }
}

/* ---------- Generic engineering-key context (independent of any tenant configuration) ---------- */

const ENGINEERING_KEYS: readonly [RegExp, string][] = [
  [/^(?:part|article|material)(?:no|nr|num|number|id)?$/u, 'PART_NUMBER'], [/^(?:drawing|dwg)(?:no|nr|num|number|id)?$/u, 'DRAWING_NUMBER'],
  [/^(?:item)(?:no|nr|num|number|id)$/u, 'ITEM_ID'], [/^(?:document|doc)(?:no|nr|num|number|id)$/u, 'DOCUMENT_ID'],
  [/^(?:asset|equipment)(?:tag|no|nr|number|id)$/u, 'ASSET_TAG'], [/^(?:functionallocation|funcloc|floc)$/u, 'FUNCTIONAL_LOCATION'],
  [/^plc(?:tag|address)$/u, 'PLC_TAG'], [/^(?:scada|historian|opc)(?:tag|point|node|nodeid)?$/u, 'SCADA_TAG'],
];
const KEY_VALUE = /(?<![\w-])["']?([A-Za-z][\w.-]{0,63})["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9][\w./:#-]{0,127})/gu;

/* ---------- Detection ---------- */

interface Found extends Classified { rule: string; basis: ConfiguredCandidate['basis']; start: number; end: number }
function failure(reason: string): ConfiguredResult {
  return Object.freeze({ status: 'FAILURE', reasons: Object.freeze([reason]), candidates: Object.freeze([]) });
}
function hintMatches(hint: readonly string[], path: readonly string[]): boolean {
  return hint.length === path.length && hint.every((segment, index) => segment === '*' || segment === path[index]);
}

/**
 * Run the configured sources and the generic engineering-key rule. A configuration from another tenant or
 * project, or a forged object, never matches: the result is PARTIAL and only generic candidates remain.
 */
export function detectConfigured(request: ConfiguredRequest): ConfiguredResult {
  let text: unknown, inputRef: unknown, config: unknown, fieldPath: unknown, tenantRef: unknown, projectRef: unknown;
  try {
    let scope: unknown;
    ({ text, inputRef, scope, config, fieldPath } = request);
    if (!scope || typeof scope !== 'object') return failure('INVALID_REQUEST');
    ({ tenantRef, projectRef } = scope as Record<string, unknown>);
  } catch { return failure('INVALID_REQUEST'); }
  if (typeof text !== 'string' || !label(inputRef, 1024) || !label(tenantRef) || !label(projectRef)) return failure('INVALID_REQUEST');
  if (fieldPath !== undefined && (!Array.isArray(fieldPath) || fieldPath.length > 64 || fieldPath.some((s) => typeof s !== 'string'))) {
    return failure('INVALID_REQUEST');
  }
  if (text.length > MAX_TEXT_UNITS) return failure('INPUT_TOO_LARGE');
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(text)) return failure('INVALID_TEXT');

  const reasons = new Set<string>();
  let compiled: Compiled | undefined;
  if (config !== undefined) {
    compiled = config && typeof config === 'object' ? registry.get(config) : undefined;
    if (!compiled) reasons.add('INVALID_CONFIG');
    else if (compiled.scope.tenantRef !== tenantRef || compiled.scope.projectRef !== projectRef) {
      reasons.add('CONFIG_SCOPE_MISMATCH');
      compiled = undefined;
    }
  } else reasons.add('NO_CONFIG');
  const partial = reasons.has('INVALID_CONFIG') || reasons.has('CONFIG_SCOPE_MISMATCH');

  const found: Found[] = [];
  const add = (item: Found): void => {
    found.push(item);
    if (found.length > MAX_CANDIDATES) throw new RangeError('too many');
  };
  try {
    if (compiled) {
      if (fieldPath) {
        compiled.hints.forEach(({ path, entry }, index) => {
          const start = text.length - text.trimStart().length, end = text.trimEnd().length;
          if (end > start && hintMatches(path, fieldPath as string[])) add({ ...entry, rule: `field-hint.${index}`, basis: 'FIELD_HINT', start, end });
        });
      }
      const folded = fold(text);
      const tokens = [...folded.text.matchAll(TOKEN)];
      for (let index = 0; index < tokens.length;) {
        let node = compiled.root.next.get(edge('', tokens[index]![0]));
        let longest = node?.entry !== undefined ? { last: index, entry: node.entry } : null;
        for (let next = index + 1; node && next < tokens.length && next - index < MAX_TERM_TOKENS; next++) {
          const before = tokens[next - 1]!;
          node = node.next.get(edge(separator(folded.text.slice(before.index + before[0].length, tokens[next]!.index)), tokens[next]![0]));
          if (node?.entry !== undefined) longest = { last: next, entry: node.entry };
        }
        if (!longest) { index++; continue; }
        const first = tokens[index]!, last = tokens[longest.last]!;
        add({ ...compiled.entries[longest.entry]!, rule: 'dictionary.term', basis: 'DICTIONARY',
          start: folded.origin[first.index]!, end: folded.originEnd[last.index + last[0].length - 1]! });
        index = longest.last + 1;
      }
      compiled.patterns.forEach(({ regex, entry }, index) => {
        regex.lastIndex = 0;
        for (const match of text.matchAll(regex)) add({ ...entry, rule: `pattern.${index}`, basis: 'PATTERN', start: match.index, end: match.index + match[0].length });
      });
    }
    for (const match of text.matchAll(KEY_VALUE)) {
      const key = match[1]!.toLowerCase().replace(/[^a-z]/gu, '');
      const subtype = ENGINEERING_KEYS.find(([pattern]) => pattern.test(key))?.[1];
      if (!subtype) continue;
      const start = match.index + match[0].length - match[2]!.length;
      add({ semanticType: 'ENGINEERING_IDENTIFIER', subtype, rule: 'context.engineering-key', basis: 'CONTEXT', start, end: start + match[2]!.length });
    }
  } catch { return failure('TOO_MANY_CANDIDATES'); }

  found.sort((a, b) => a.start - b.start || a.end - b.end || a.rule.localeCompare(b.rule));
  const field = createHash('sha256').update(inputRef).digest('hex').slice(0, 16);
  const candidates = found.map((item, index) => Object.freeze({
    semanticType: item.semanticType, ...(item.subtype ? { subtype: item.subtype } : {}),
    ...(item.sensitivity ? { sensitivity: item.sensitivity } : {}), rule: item.rule, basis: item.basis, start: item.start, end: item.end,
    evidence: Object.freeze({
      version: 1 as const, id: `${CONFIGURED_PRODUCER.id}.${item.basis.toLowerCase()}.${field}.${item.start}-${item.end}.${index}`,
      status: 'FOUND' as const,
      provenance: Object.freeze({ inputRef, producerId: CONFIGURED_PRODUCER.id, producerVersion: CONFIGURED_PRODUCER.version }),
      // Sensitivity only comes from trusted configuration; generic context candidates stay unresolved.
      claim: Object.freeze({ semanticType: item.semanticType, ...(item.subtype ? { subtype: item.subtype } : {}),
        ...(item.sensitivity ? { sensitivity: item.sensitivity } : {}) }),
    }),
  }));
  return Object.freeze({ status: partial ? 'PARTIAL' : 'COMPLETE', reasons: Object.freeze([...reasons].sort()),
    candidates: Object.freeze(candidates) });
}
