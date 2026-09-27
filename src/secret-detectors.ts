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
  [/privatekey|sshkey|keypem$/u, 'PRIVATE_KEY'],
  [/connectionstring|accountkey|sharedaccess|sastoken|^sas$|^sig$/u, 'CONNECTION_SECRET'],
  [/cookie|sessionid|sessid$|^sid$|^session$/u, 'COOKIE'],
  [/apikey|accesskey|clientsecret|secretkey|appkey|^secret$|secret$/u, 'API_KEY'],
  [/credentials?$/u, 'PASSWORD'],
  // `token` only as a suffix (`access_token`, `x-auth-token`, not `tokenizer`); usage counters are not secrets.
  [/^(?!(?:input|output|max|total|num|prompt|completion|cached|reasoning)tokens?$).*tokens?$|bearer|authorization|^auth$|^jwt$|jwttoken$/u,
    'ACCESS_TOKEN'],
  [/password|passwd|passphrase|^pwd$|^pass$|pwd$|pass$/u, 'PASSWORD'],
];
/** Credential subtype for a key such as `DB_PASSWORD`, `apiKey`, `x-api-key` or `Client Secret`, else null. */
export function subtypeForKey(key: string): SecretSubtype | null {
  const compact = key.toLowerCase().replace(/[^a-z0-9]/gu, '');
  if (!compact || compact.length > 64) return null;
  for (const [pattern, subtype] of KEY_SUBTYPES) if (pattern.test(compact)) return subtype;
  return null;
}
/**
 * Whole values that reference a secret rather than contain one: env/template references, Hylja
 * placeholders and explicit masks. The *entire* value must match; `${X}rest` is not a reference.
 */
function isReference(value: string): boolean {
  return /^(?:\$\{[A-Za-z_][\w.-]*\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%|\{\{\s*[\w.-]+\s*\}\}|\[hylja:protected:[A-Z0-9_]+\])$/u.test(value) ||
    /^(?:\*{3,}|<(?:redacted|hidden|masked|secret|password|token|api[-_ ]?key|your[-_ ][\w -]{1,30})>|null|none|true|false)$/iu.test(value);
}
const SCHEME_WORD = /^(?:Bearer|Basic|Token|Digest|Negotiate)$/iu;

/* ---------- Format rules (bounded; each anchored by a literal prefix) ---------- */

interface Rule { id: string; subtype: SecretSubtype; pattern: RegExp }
// Prefix tokens have alphanumeric bodies; `_`/`-` next to them (`X_ghp_…`, `ghp_…-suffix`) is a boundary.
const B = '(?<![A-Za-z0-9])';
const E = '(?![A-Za-z0-9])';
const FORMAT_RULES: readonly Rule[] = [
  { id: 'format.aws-access-key-id', subtype: 'API_KEY', pattern: new RegExp(`${B}(?:AKIA|ASIA|AGPA|AROA)[0-9A-Z]{16}${E}`, 'gu') },
  { id: 'format.github-token', subtype: 'ACCESS_TOKEN', pattern: new RegExp(`${B}gh[pousr]_[A-Za-z0-9]{36,255}${E}`, 'gu') },
  { id: 'format.github-fine-grained-pat', subtype: 'ACCESS_TOKEN', pattern: new RegExp(`${B}github_pat_[A-Za-z0-9_]{22,255}${E}`, 'gu') },
  { id: 'format.gitlab-pat', subtype: 'ACCESS_TOKEN', pattern: new RegExp(`${B}glpat-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])`, 'gu') },
  { id: 'format.slack-token', subtype: 'ACCESS_TOKEN', pattern: new RegExp(`${B}xox[abposr]-[A-Za-z0-9-]{10,255}(?![A-Za-z0-9-])`, 'gu') },
  { id: 'format.slack-webhook', subtype: 'API_KEY',
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]{6,32}\/[A-Za-z0-9]{6,32}\/[A-Za-z0-9]{12,64}/gu },
  { id: 'format.stripe-key', subtype: 'API_KEY', pattern: new RegExp(`${B}(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}${E}`, 'gu') },
  { id: 'format.google-api-key', subtype: 'API_KEY', pattern: new RegExp(`${B}AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])`, 'gu') },
  { id: 'format.sk-prefixed-api-key', subtype: 'API_KEY', pattern: new RegExp(`${B}sk-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])`, 'gu') },
  { id: 'format.npm-token', subtype: 'ACCESS_TOKEN', pattern: new RegExp(`${B}npm_[A-Za-z0-9]{36}${E}`, 'gu') },
  // JWE compact form (five parts, the key part may be empty) and JWT (three parts, signature may be empty).
  { id: 'format.jwe', subtype: 'ACCESS_TOKEN',
    pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,8192}\.[A-Za-z0-9_-]{0,8192}\.[A-Za-z0-9_-]{1,8192}\.[A-Za-z0-9_-]{1,65536}\.[A-Za-z0-9_-]{0,8192}(?![A-Za-z0-9_-])/gu },
  { id: 'format.jwt', subtype: 'ACCESS_TOKEN',
    pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,8192}\.eyJ[A-Za-z0-9_-]{5,65536}\.[A-Za-z0-9_-]{0,8192}(?![A-Za-z0-9_-])/gu },
];

/* ---------- Private key blocks: linear marker scan (a lazy regex would rescan per BEGIN) ---------- */

const KEY_BEGIN = /-----BEGIN (?:(?:[A-Z0-9]+ ){0,3}PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|---- BEGIN SSH2 (?:ENCRYPTED )?PRIVATE KEY ----|PuTTY-User-Key-File-\d+:/gu;
const KEY_END = /-----END (?:(?:[A-Z0-9]+ ){0,3}PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|---- END SSH2 (?:ENCRYPTED )?PRIVATE KEY ----|Private-MAC:[ \t]*[0-9A-Fa-f]*/gu;
/** Each block spans BEGIN..END; an unterminated block runs to the end of the text (never truncated). */
function keyBlocks(text: string, out: Found[]): void {
  KEY_BEGIN.lastIndex = 0;
  for (let begin = KEY_BEGIN.exec(text); begin; begin = KEY_BEGIN.exec(text)) {
    KEY_END.lastIndex = begin.index + begin[0].length;
    const end = KEY_END.exec(text);
    const stop = end ? end.index + end[0].length : text.length;
    const rule = begin[0].includes('PGP') ? 'format.pgp-private-key' : begin[0].includes('SSH2') ? 'format.ssh2-private-key' :
      begin[0].startsWith('PuTTY') ? 'format.putty-private-key' : 'format.pem-private-key';
    out.push({ subtype: 'PRIVATE_KEY', rule, basis: 'FORMAT', start: begin.index, end: stop });
    KEY_BEGIN.lastIndex = stop;
    if (!end) break;
  }
}

/* ---------- Value reading: over-cover rather than stop inside a secret ---------- */

interface Found { subtype: SecretSubtype; rule: string; basis: SecretCandidate['basis']; start: number; end: number }
// Memo of the last newline search, so repeated lookups on one long line stay linear overall.
let lineMemo: { text: string; from: number; newline: number } | null = null;
function lineEnd(text: string, from: number): number {
  let newline: number;
  if (lineMemo && lineMemo.text === text && from >= lineMemo.from && from <= lineMemo.newline) newline = lineMemo.newline;
  else {
    const found = text.indexOf('\n', from);
    newline = found < 0 ? text.length : found;
    lineMemo = { text, from, newline };
  }
  return newline > from && text[newline - 1] === '\r' ? newline - 1 : newline;
}
/** Start of the line containing `at`, looking back at most 256 units (callers only need nearby context). */
function lineStart(text: string, at: number): number {
  const floor = Math.max(0, at - 256);
  for (let index = at - 1; index >= floor; index--) if (text[index] === '\n') return index + 1;
  return floor;
}
/**
 * Read the value that starts at `at`. Quoted values run to the matching unescaped quote, or to the end of
 * the line when unterminated. YAML block scalars (`|`, `>`) take the following more-indented lines. Bare
 * values stop at a context terminator: `line` runs to end of line (YAML, .env, properties), `json` stops
 * at `,}]`/whitespace, `query` at `&`/`#`/whitespace, `inline` at whitespace or a quote.
 */
function readValue(text: string, at: number, context: 'line' | 'json' | 'query' | 'inline'): { start: number; end: number } | null {
  const eol = lineEnd(text, at);
  if (at >= eol) return null;
  const quote = text[at];
  if (quote === '"' || quote === "'" || quote === '`') {
    let index = at + 1;
    for (; index < eol; index++) {
      if (text[index] === '\\') { index++; continue; }
      if (text[index] === quote) break;
    }
    // Unterminated: cover to end of line (a truncated log line still hides its secret).
    return index > at + 1 ? { start: at + 1, end: Math.min(index, eol) } : index >= eol ? { start: at, end: eol } : null;
  }
  if ((quote === '|' || quote === '>') && /^[|>][+-]?[ \t]*$/u.test(text.slice(at, eol))) {
    const indent = (line: number): number => { let i = line; while (text[i] === ' ' || text[i] === '\t') i++; return i - line; };
    const base = indent(lineStart(text, at));
    let end = eol, next = eol + (text[eol] === '\r' ? 2 : 1);
    while (next < text.length) {
      const stop = lineEnd(text, next);
      if (text.slice(next, stop).trim() && indent(next) <= base) break;
      end = stop;
      next = stop + (text[stop] === '\r' ? 2 : 1);
    }
    return end > eol ? { start: eol + 1, end } : null;
  }
  let end = at;
  if (context === 'line') end = eol;
  else {
    const stop = context === 'json' ? /[\s,}\]]/u : context === 'query' ? /[\s&#]/u : /[\s"'`]/u;
    while (end < eol && !stop.test(text[end]!)) end++;
  }
  while (end > at && (text[end - 1] === ' ' || text[end - 1] === '\t')) end--;
  return end > at ? { start: at, end } : null;
}

/* ---------- Context rules ---------- */

// `key sep` only: values are read separately, so a non-credential key never hides a later assignment
// inside its own value (`{"env":"DB_PASSWORD=x"}`, `msg=password=x`).
const KEY_SEP = /(?<![\w.$-])(--?|\$env:|export[ \t]+|ENV[ \t]+)?(["'<]?)([A-Za-z_][\w.-]{0,63})(["'>]?)[ \t]*(:=|=>|=|:(?!\/\/))[ \t]*/gu;
function assignmentCandidates(text: string, out: Found[]): void {
  KEY_SEP.lastIndex = 0;
  for (let match = KEY_SEP.exec(text); match; match = KEY_SEP.exec(text)) {
    const subtype = subtypeForKey(match[3]!);
    if (!subtype) continue;
    const at = match.index + match[0].length;
    const before = match.index > 0 ? text[match.index - 1] : '\n';
    // Only a key near the start of its line gets end-of-line values; the check looks back at most 64 units.
    const head = lineStart(text, match.index);
    const context = match[2] === '"' || match[2] === "'" ? 'json' : before === '?' || before === '&' ? 'query' :
      match.index - head <= 64 &&
      /^[ \t]*(?:--?|export[ \t]+|ENV[ \t]+)?["']?$/u.test(text.slice(head, match.index + (match[1]?.length ?? 0)))
        ? 'line' : 'inline';
    const value = readValue(text, at, context);
    if (!value) continue;
    const raw = text.slice(value.start, value.end);
    // Only an Authorization *header* key makes a bare scheme word empty; elsewhere `password=Basic` is a value.
    if (isReference(raw) || subtype === 'ACCESS_TOKEN' && /authorization/iu.test(match[3]!) && SCHEME_WORD.test(raw)) continue;
    // `PWD=/home/...` in an env dump is the working directory, not a password.
    if (/^pwd$/iu.test(match[3]!) && /^[/~]/u.test(raw)) continue;
    out.push({ subtype, rule: 'context.key-assignment', basis: 'CONTEXT', ...value });
    // Anything inside a credential value is already covered: resume after it (keeps scanning linear).
    KEY_SEP.lastIndex = Math.max(KEY_SEP.lastIndex, value.end);
  }
}
// Space-separated forms: `--password value`, `ENV DB_PASSWORD value`, `.netrc` `password value`, `curl -u user:pass`.
const FLAG_SPACE = /(?<![\w-])--([A-Za-z][\w-]{0,63})[ \t]+(?!-)/gu;
const LINE_SPACE = /^[ \t]*(?:ENV[ \t]+)?([A-Za-z_][\w.-]{0,63})[ \t]+(?![=:])/gmu;
const NETRC = /(?<![\w-])(?:login[ \t]+\S+[ \t]+)?password[ \t]+/gu;
const CURL_USER = /(?<![\w-])(?:-u|--user)[ \t]+[^\s:]{1,256}:/gu;
function spacedCandidates(text: string, out: Found[]): void {
  for (const [pattern, keyGroup, rule] of [[FLAG_SPACE, 1, 'context.cli-flag'], [LINE_SPACE, 1, 'context.line-key'],
    [NETRC, 0, 'context.netrc'], [CURL_USER, 0, 'context.curl-user']] as const) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(text); match; match = pattern.exec(text)) {
      if (!match[0].length) { pattern.lastIndex++; continue; }
      const subtype = keyGroup ? subtypeForKey(match[keyGroup]!) : 'PASSWORD';
      if (!subtype) continue;
      const value = readValue(text, match.index + match[0].length, 'inline');
      if (value && !isReference(text.slice(value.start, value.end))) {
        out.push({ subtype, rule, basis: 'CONTEXT', ...value });
        pattern.lastIndex = Math.max(pattern.lastIndex, value.end);
      }
    }
  }
}
// XML elements named like credentials: `<password>…</password>`.
const XML_ELEMENT = /<([A-Za-z_][\w.-]{0,63})(?:\s[^<>]{0,1024})?>([^<]{1,65536})<\/\1>/gu;
function xmlCandidates(text: string, out: Found[]): void {
  for (const match of text.matchAll(XML_ELEMENT)) {
    const subtype = subtypeForKey(match[1]!);
    const inner = match[2]!;
    if (!subtype || !inner.trim() || isReference(inner.trim())) continue;
    const start = match.index + match[0].length - inner.length - match[1]!.length - 3;
    out.push({ subtype, rule: 'context.xml-element', basis: 'CONTEXT', start, end: start + inner.length });
  }
}

const HEADER = /(?<![\w-])(Proxy-Authorization|Authorization|Cookie|Set-Cookie|X-Api-Key|Api-Key|X-Auth-Token)[ \t]*:[ \t]*/giu;
function headerCandidates(text: string, out: Found[]): void {
  for (const match of text.matchAll(HEADER)) {
    const name = match[1]!.toLowerCase();
    let start = match.index + match[0].length;
    let end = lineEnd(text, start);
    // Inside a quoted command line (`-H "Authorization: Bearer x"`) the enclosing quote ends the header.
    const opener = text[match.index - 1];
    if (opener === '"' || opener === "'") {
      const close = text.indexOf(opener, start);
      if (close >= 0 && close < end) end = close;
    }
    while (end > start && (text[end - 1] === ' ' || text[end - 1] === '\t')) end--;
    let subtype: SecretSubtype = subtypeForKey(name) ?? 'API_KEY';
    if (name.endsWith('authorization')) {
      subtype = 'ACCESS_TOKEN';
      const scheme = /^(Bearer|Basic|Token|Digest|Negotiate|AWS4-HMAC-SHA256|ApiKey)(?:[ \t]+|$)/iu.exec(text.slice(start, Math.min(end, start + 32)));
      if (scheme) start += scheme[0].length;
      if (scheme && /^basic$/iu.test(scheme[1]!)) subtype = 'PASSWORD';
    } else if (name.includes('cookie')) subtype = 'COOKIE';
    // Set-Cookie attributes after the first unquoted `;` are not secret; everything else runs to the end.
    if (name === 'set-cookie') {
      let index = start, quoted = false;
      for (; index < end; index++) { if (text[index] === '"') quoted = !quoted; else if (text[index] === ';' && !quoted) break; }
      end = index;
    }
    if (end > start && !isReference(text.slice(start, end))) {
      out.push({ subtype, rule: `context.header.${name}`, basis: 'CONTEXT', start, end });
    }
  }
}
// URL userinfo: the password runs from the first `:` after the user to the *last* `@` in the token, so
// `p@ss` is covered in full.
const URL_START = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}:\/\//gu;
function userinfoCandidates(text: string, out: Found[]): void {
  URL_START.lastIndex = 0;
  for (let match = URL_START.exec(text); match; match = URL_START.exec(text)) {
    const from = match.index + match[0].length;
    let to = from;
    while (to < text.length && to - from < 4096 && !/[\s"'<>`]/u.test(text[to]!)) to++;
    // Resume after this token: each character is scanned by at most one URL.
    URL_START.lastIndex = Math.max(to, from);
    const token = text.slice(from, to);
    const last = token.lastIndexOf('@');
    if (last < 0) continue;
    const at = from + last;
    const colon = text.indexOf(':', from);
    if (colon < 0 || colon >= at) continue;
    const value = text.slice(colon + 1, at);
    if (value && !isReference(value)) out.push({ subtype: 'PASSWORD', rule: 'context.url-userinfo', basis: 'CONTEXT', start: colon + 1, end: at });
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
  try {
    if (fingerprintKey !== undefined && (!(fingerprintKey instanceof Uint8Array) || !(fingerprintKey.length >= 32))) {
      return failure('INVALID_FINGERPRINT_KEY');
    }
  } catch { return failure('INVALID_FINGERPRINT_KEY'); }
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
  spacedCandidates(text, found);
  xmlCandidates(text, found);
  if (found.length > 4 * MAX_CANDIDATES) return failure('TOO_MANY_CANDIDATES');
  // Same span and subtype: keep the FORMAT rule, the strongest evidence.
  const strength = { FORMAT: 0, FIELD_KEY: 1, CONTEXT: 2 };
  found.sort((a, b) => a.start - b.start || a.end - b.end || a.subtype.localeCompare(b.subtype) ||
    strength[a.basis] - strength[b.basis] || a.rule.localeCompare(b.rule));
  const unique = found.filter((item, index) => index === 0 || item.start !== found[index - 1]!.start ||
    item.end !== found[index - 1]!.end || item.subtype !== found[index - 1]!.subtype);
  if (unique.length > MAX_CANDIDATES) return failure('TOO_MANY_CANDIDATES');

  const field = createHash('sha256').update(inputRef).digest('hex').slice(0, 16);
  // Domain-separated so a tenant key reused for other HMACs never correlates with secret fingerprints.
  // Anyone holding the key can still test guesses of low-entropy values; keep the key in the trusted plane.
  const fingerprints: (string | undefined)[] = [];
  try {
    for (const item of unique) {
      fingerprints.push(fingerprintKey === undefined ? undefined : createHmac('sha256', fingerprintKey as Uint8Array)
        .update(`hylja.secret-fingerprint.v1\u0000${text.slice(item.start, item.end)}`).digest('hex').slice(0, 32));
    }
  } catch { return failure('INVALID_FINGERPRINT_KEY'); }
  const candidates = unique.map((item, index) => {
    const fingerprint = fingerprints[index];
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
