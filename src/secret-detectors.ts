/**
 * #8 deterministic secret and credential detectors. Pure and NON-ENFORCING: they emit classification v1
 * detector evidence (CREDENTIAL_OR_SECRET, SECRET, non-reversible) with spans and optional keyed
 * fingerprints. Results never contain the secret value, and nothing here selects a treatment or proves
 * zero egress; that needs #13 transformation and the #19 sentinel on the actual outbound bytes.
 */
import { createHash, createHmac } from 'node:crypto';
import type { ClassificationClaim, EvidenceProvenance } from './classification.js';

export const SECRET_PRODUCER = Object.freeze({ id: 'hylja.secret-detectors', version: '1' });
export const SECRET_SUBTYPES = [
  'PASSWORD', 'API_KEY', 'PRIVATE_KEY', 'ACCESS_TOKEN', 'REFRESH_TOKEN', 'COOKIE', 'CONNECTION_SECRET',
  'CERTIFICATE_SECRET',
] as const;
export type SecretSubtype = (typeof SECRET_SUBTYPES)[number];
export const MAX_TEXT_UNITS = 1 << 20;
/** Matches the v1 composer's per-channel limit, so every COMPLETE result can be composed. */
export const MAX_CANDIDATES = 256;

export interface DetectorEvidenceInput {
  version: 1;
  id: string;
  status: 'FOUND';
  provenance: EvidenceProvenance;
  claim: ClassificationClaim;
}
export interface SecretCandidate {
  subtype: SecretSubtype;
  /** Stable rule id, e.g. `format.github-token`, `context.key-assignment`; never the value. */
  rule: string;
  /** FORMAT: the value's own syntax. CONTEXT: a credential-like key, header or URL userinfo. */
  basis: 'FORMAT' | 'CONTEXT' | 'FIELD_KEY';
  /** UTF-16 span of the secret value (not its key or header name), end-exclusive. */
  start: number;
  end: number;
  /** Keyed HMAC-SHA256 prefix when a tenant fingerprint key is supplied; never an unkeyed hash. */
  fingerprint?: string;
  evidence: DetectorEvidenceInput;
}
export interface SecretResult {
  /** COMPLETE: every rule ran over the whole input. FAILURE: nothing is reported; treat the input as opaque. */
  status: 'COMPLETE' | 'FAILURE';
  reasons: readonly string[];
  candidates: readonly SecretCandidate[];
}
export interface SecretRequest {
  text: string;
  /** Privacy-safe reference to the field or text unit, never raw content. */
  inputRef: string;
  /** Trusted parser field key (#7). When credential-like, the whole value is a candidate. */
  fieldKey?: string;
  /** Tenant-scoped key of at least 32 bytes for fingerprints; without it no fingerprint is produced. */
  fingerprintKey?: Uint8Array;
}

/* ---------- Key context ---------- */

const KEY_SUBTYPES: readonly [RegExp, SecretSubtype][] = [
  [/refreshtoken/u, 'REFRESH_TOKEN'],
  [/privatekey|sshkey|pem$/u, 'PRIVATE_KEY'],
  [/connectionstring|accountkey|sharedaccess|sastoken|^sas$|^sig$/u, 'CONNECTION_SECRET'],
  [/cookie|sessionid|^sid$|^session$/u, 'COOKIE'],
  [/apikey|accesskey|clientsecret|secretkey|appkey|^secret$|secret$/u, 'API_KEY'],
  // `token` only as a suffix: `access_token`, `x-auth-token`, but not `tokenizer`.
  [/tokens?$|bearer|authorization|^auth$|jwt/u, 'ACCESS_TOKEN'],
  [/password|passwd|passphrase|^pwd$|^pass$|pwd$/u, 'PASSWORD'],
];
/** Credential subtype for a key such as `DB_PASSWORD`, `apiKey`, `x-api-key` or `Client Secret`, else null. */
export function subtypeForKey(key: string): SecretSubtype | null {
  const compact = key.toLowerCase().replace(/[^a-z0-9]/gu, '');
  if (!compact || compact.length > 64) return null;
  for (const [pattern, subtype] of KEY_SUBTYPES) if (pattern.test(compact)) return subtype;
  return null;
}
/** Values that reference a secret rather than contain one: env/template references and Hylja placeholders. */
function isReference(value: string): boolean {
  return /^(?:\$\{[A-Za-z_][\w.-]*\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{\{\s*[\w.-]+\s*\}\}|\[hylja:protected:[A-Z0-9_]+\])$/u.test(value) ||
    /^(?:\*{3,}|<[\w -]{1,40}>|null|none|true|false)$/iu.test(value);
}

/* ---------- Format rules (bounded; each anchored by a literal prefix or block marker) ---------- */

interface Rule { id: string; subtype: SecretSubtype; pattern: RegExp; group?: number }
const B = '(?<![A-Za-z0-9_-])';
const E = '(?![A-Za-z0-9_-])';
const FORMAT_RULES: readonly Rule[] = [
  { id: 'format.aws-access-key-id', subtype: 'API_KEY', pattern: new RegExp(`${B}(?:AKIA|ASIA|AGPA|AROA)[0-9A-Z]{16}${E}`, 'gu') },
  { id: 'format.github-token', subtype: 'ACCESS_TOKEN', pattern: new RegExp(`${B}gh[pousr]_[A-Za-z0-9]{36,255}${E}`, 'gu') },
  { id: 'format.github-fine-grained-pat', subtype: 'ACCESS_TOKEN', pattern: new RegExp(`${B}github_pat_[A-Za-z0-9_]{22,255}${E}`, 'gu') },
  { id: 'format.gitlab-pat', subtype: 'ACCESS_TOKEN', pattern: new RegExp(`${B}glpat-[A-Za-z0-9_-]{20,255}${E}`, 'gu') },
  { id: 'format.slack-token', subtype: 'ACCESS_TOKEN', pattern: new RegExp(`${B}xox[abposr]-[A-Za-z0-9-]{10,255}${E}`, 'gu') },
  { id: 'format.slack-webhook', subtype: 'API_KEY',
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]{6,32}\/[A-Za-z0-9]{6,32}\/[A-Za-z0-9]{12,64}/gu },
  { id: 'format.stripe-key', subtype: 'API_KEY', pattern: new RegExp(`${B}(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}${E}`, 'gu') },
  { id: 'format.google-api-key', subtype: 'API_KEY', pattern: new RegExp(`${B}AIza[0-9A-Za-z_-]{35}${E}`, 'gu') },
  { id: 'format.sk-prefixed-api-key', subtype: 'API_KEY', pattern: new RegExp(`${B}sk-[A-Za-z0-9_-]{20,255}${E}`, 'gu') },
  { id: 'format.npm-token', subtype: 'ACCESS_TOKEN', pattern: new RegExp(`${B}npm_[A-Za-z0-9]{36}${E}`, 'gu') },
  { id: 'format.jwt', subtype: 'ACCESS_TOKEN',
    pattern: new RegExp(`${B}eyJ[A-Za-z0-9_-]{5,4096}\\.eyJ[A-Za-z0-9_-]{5,8192}\\.[A-Za-z0-9_-]{0,4096}${E}`, 'gu') },
];

/* ---------- Private key blocks: linear marker scan (a lazy regex would rescan per BEGIN) ---------- */

const KEY_BEGIN = /-----BEGIN (?:(?:[A-Z0-9]+ ){0,3}PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/gu;
const KEY_END = /-----END (?:(?:[A-Z0-9]+ ){0,3}PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/gu;
/** Each block spans BEGIN..END; an unterminated block runs to the end of the text (never truncated). */
function keyBlocks(text: string, out: Found[]): void {
  KEY_BEGIN.lastIndex = 0;
  for (let begin = KEY_BEGIN.exec(text); begin; begin = KEY_BEGIN.exec(text)) {
    KEY_END.lastIndex = begin.index + begin[0].length;
    const end = KEY_END.exec(text);
    const stop = end ? end.index + end[0].length : text.length;
    out.push({ subtype: 'PRIVATE_KEY', rule: begin[0].includes('PGP') ? 'format.pgp-private-key' : 'format.pem-private-key',
      basis: 'FORMAT', start: begin.index, end: stop });
    KEY_BEGIN.lastIndex = stop;
    if (!end) break;
  }
}

/* ---------- Context rules: headers, URL userinfo, key assignments ---------- */

const HEADER = /(?<![\w-])(Proxy-Authorization|Authorization|Cookie|Set-Cookie|X-Api-Key|Api-Key|X-Auth-Token)[ \t]*:[ \t]*([^\r\n]{1,8192})/giu;
const USERINFO = /[A-Za-z][A-Za-z0-9+.-]{0,31}:\/\/[^\s/?#@:]{0,256}:([^\s/?#@]{1,256})@/gu;
// `key = value`, `key: value`, `"key": "value"`, `--key value`-free; values quoted or bare.
const ASSIGNMENT = /(?<![\w-])(["']?)([A-Za-z_][\w.-]{0,63})\1[ \t]*(?:=|:)[ \t]*(?:"((?:[^"\\\r\n]|\\.){1,4096})"|'([^'\r\n]{1,4096})'|(\$\{[A-Za-z_][\w.-]{0,127}\}|\{\{\s*[\w.-]{1,128}\s*\}\}|\[hylja:protected:[A-Z0-9_]{1,64}\]|[^\s"',;&}{)\]]{1,4096}))/gu;

interface Found { subtype: SecretSubtype; rule: string; basis: SecretCandidate['basis']; start: number; end: number }

function headerCandidates(text: string, out: Found[]): void {
  for (const match of text.matchAll(HEADER)) {
    const name = match[1]!.toLowerCase();
    // A quote ends the value: headers are often embedded in quoted command lines.
    let value = match[2]!.split(/["'`]/u, 1)[0]!.replace(/\s+$/u, '');
    let start = match.index + match[0].length - match[2]!.length;
    let subtype: SecretSubtype = 'ACCESS_TOKEN';
    if (name.endsWith('authorization')) {
      const scheme = /^(Bearer|Basic|Token|Digest|Negotiate|AWS4-HMAC-SHA256|ApiKey)\s+/iu.exec(value);
      if (scheme) { start += scheme[0].length; value = value.slice(scheme[0].length); }
      if (scheme && /^basic$/iu.test(scheme[1]!)) subtype = 'PASSWORD';
    } else if (name.includes('cookie')) {
      subtype = 'COOKIE';
      // Set-Cookie attributes after the first `;` are not secret.
      if (name === 'set-cookie') value = value.split(';', 1)[0]!;
    } else subtype = 'API_KEY';
    if (value && !isReference(value) && !/^(?:Bearer|Basic|Token|Digest|Negotiate)$/iu.test(value)) {
      out.push({ subtype, rule: `context.header.${name}`, basis: 'CONTEXT', start, end: start + value.length });
    }
  }
}
function userinfoCandidates(text: string, out: Found[]): void {
  for (const match of text.matchAll(USERINFO)) {
    const end = match.index + match[0].length - 1;
    const value = match[1]!;
    if (!isReference(value)) out.push({ subtype: 'PASSWORD', rule: 'context.url-userinfo', basis: 'CONTEXT', start: end - value.length, end });
  }
}
function assignmentCandidates(text: string, out: Found[]): void {
  for (const match of text.matchAll(ASSIGNMENT)) {
    const subtype = subtypeForKey(match[2]!);
    if (!subtype) continue;
    const group = match[3] !== undefined ? 3 : match[4] !== undefined ? 4 : 5;
    const value = match[group]!;
    // Header schemes are handled by the header rule; `Authorization: Bearer` alone is not a value.
    if (isReference(value) || /^(?:Bearer|Basic|Token|Digest|Negotiate)$/iu.test(value)) continue;
    const offset = match[0].length - value.length - (group === 5 ? 0 : 1);
    out.push({ subtype, rule: 'context.key-assignment', basis: 'CONTEXT', start: match.index + offset,
      end: match.index + offset + value.length });
  }
}

/* ---------- Detection ---------- */

function failure(reason: string): SecretResult {
  return Object.freeze({ status: 'FAILURE', reasons: Object.freeze([reason]), candidates: Object.freeze([]) });
}
function label(value: unknown, limit = 1024): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

/**
 * Run every rule over `text`. Overlapping candidates (a JWT inside an Authorization header) are all kept;
 * composition must not discard the stronger evidence. A FAILURE reports nothing and must be treated as opaque.
 */
export function detectSecrets(request: SecretRequest): SecretResult {
  let text: unknown, inputRef: unknown, fieldKey: unknown, fingerprintKey: unknown;
  try { ({ text, inputRef, fieldKey, fingerprintKey } = request); } catch { return failure('INVALID_REQUEST'); }
  if (typeof text !== 'string' || !label(inputRef) || fieldKey !== undefined && typeof fieldKey !== 'string') {
    return failure('INVALID_REQUEST');
  }
  if (fingerprintKey !== undefined && (!(fingerprintKey instanceof Uint8Array) || fingerprintKey.length < 32)) {
    return failure('INVALID_FINGERPRINT_KEY');
  }
  if (text.length > MAX_TEXT_UNITS) return failure('INPUT_TOO_LARGE');
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(text)) return failure('INVALID_TEXT');

  const found: Found[] = [];
  if (fieldKey !== undefined) {
    const subtype = subtypeForKey(fieldKey);
    const start = text.length - text.trimStart().length, end = text.trimEnd().length;
    if (subtype && end > start && !isReference(text.slice(start, end))) {
      found.push({ subtype, rule: 'context.field-key', basis: 'FIELD_KEY', start, end });
    }
  }
  for (const rule of FORMAT_RULES) {
    for (const match of text.matchAll(rule.pattern)) {
      found.push({ subtype: rule.subtype, rule: rule.id, basis: 'FORMAT', start: match.index, end: match.index + match[0].length });
      if (found.length > MAX_CANDIDATES) return failure('TOO_MANY_CANDIDATES');
    }
  }
  keyBlocks(text, found);
  headerCandidates(text, found);
  userinfoCandidates(text, found);
  assignmentCandidates(text, found);
  // Same span and subtype: keep the FORMAT rule, the strongest evidence.
  const strength = { FORMAT: 0, FIELD_KEY: 1, CONTEXT: 2 };
  found.sort((a, b) => a.start - b.start || a.end - b.end || a.subtype.localeCompare(b.subtype) ||
    strength[a.basis] - strength[b.basis] || a.rule.localeCompare(b.rule));
  const unique = found.filter((item, index) => index === 0 || item.start !== found[index - 1]!.start ||
    item.end !== found[index - 1]!.end || item.subtype !== found[index - 1]!.subtype);
  if (unique.length > MAX_CANDIDATES) return failure('TOO_MANY_CANDIDATES');

  const field = createHash('sha256').update(inputRef).digest('hex').slice(0, 16);
  const candidates = unique.map((item) => {
    const fingerprint = fingerprintKey === undefined ? undefined :
      createHmac('sha256', fingerprintKey as Uint8Array).update(text.slice(item.start, item.end)).digest('hex').slice(0, 32);
    return Object.freeze({
      subtype: item.subtype, rule: item.rule, basis: item.basis, start: item.start, end: item.end,
      ...(fingerprint ? { fingerprint } : {}),
      evidence: Object.freeze({
        version: 1, id: `${SECRET_PRODUCER.id}.${item.subtype.toLowerCase()}.${field}.${item.start}-${item.end}`,
        status: 'FOUND',
        provenance: Object.freeze({ inputRef, producerId: SECRET_PRODUCER.id, producerVersion: SECRET_PRODUCER.version }),
        claim: Object.freeze({ semanticType: 'CREDENTIAL_OR_SECRET', subtype: item.subtype, sensitivity: 'SECRET',
          reversible: false }),
      }) as DetectorEvidenceInput,
    });
  });
  return Object.freeze({ status: 'COMPLETE', reasons: Object.freeze([]), candidates: Object.freeze(candidates) });
}
