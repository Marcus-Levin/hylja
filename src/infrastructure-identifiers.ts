/**
 * #9 infrastructure, network, cloud and filesystem identifier detectors. Pure and NON-ENFORCING: they
 * emit classification v1 detector evidence with spans and derived, non-secret fidelity facts (IP scope,
 * well-known port service, path style, name class). They never return the matched text, select a
 * treatment or authorize release. Candidate generation favours recall; policy controls over-cloaking.
 */
import { createHash } from 'node:crypto';
import type { ClassificationClaim, EvidenceProvenance, SemanticClass } from './classification.js';

export const INFRA_PRODUCER = Object.freeze({ id: 'hylja.infrastructure-identifiers', version: '1' });
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
/** Derived facts that can preserve task semantics without revealing the value (#68 fidelity). */
export interface InfraFidelity {
  ipVersion?: 4 | 6;
  /** Address or name class; DOCUMENTATION covers RFC 5737/3849 ranges and reserved example names. */
  scope?: 'DOCUMENTATION' | 'PRIVATE' | 'LOOPBACK' | 'LINK_LOCAL' | 'SHARED' | 'MULTICAST' | 'UNSPECIFIED' | 'PUBLIC' |
    'RESERVED_NAME';
  /** Well-known service for a port, e.g. `https` for 443; the number itself is the value. */
  wellKnownService?: string;
  scheme?: string;
  pathStyle?: 'POSIX' | 'WINDOWS' | 'UNC';
  cloud?: 'AWS' | 'AZURE' | 'GCP';
}
export interface InfraCandidate {
  semanticType: SemanticClass;
  subtype?: string;
  rule: string;
  basis: 'FORMAT' | 'CONTEXT';
  /** UTF-16 span, end-exclusive. */
  start: number;
  end: number;
  fidelity: Readonly<InfraFidelity>;
  evidence: DetectorEvidenceInput;
}
export interface InfraResult {
  /** COMPLETE: every rule ran over the whole input. FAILURE: nothing reported; treat the input as opaque. */
  status: 'COMPLETE' | 'FAILURE';
  reasons: readonly string[];
  candidates: readonly InfraCandidate[];
}
export interface InfraRequest {
  text: string;
  /** Privacy-safe reference to the field or text unit, never raw content. */
  inputRef: string;
}

interface Found {
  semanticType: SemanticClass; subtype?: string; rule: string; basis: InfraCandidate['basis'];
  start: number; end: number; fidelity: InfraFidelity;
}
class TooMany extends Error {}
function add(out: Found[], found: Found): void {
  out.push(found);
  if (out.length > 4 * MAX_CANDIDATES) throw new TooMany();
}

/* ---------- Fidelity facts ---------- */

type Scope = NonNullable<InfraFidelity['scope']>;
type Cloud = NonNullable<InfraFidelity['cloud']>;

const WELL_KNOWN: Readonly<Record<number, string>> = Object.freeze({
  20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3', 123: 'ntp',
  143: 'imap', 389: 'ldap', 443: 'https', 445: 'smb', 465: 'smtps', 502: 'modbus', 587: 'submission', 636: 'ldaps',
  993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle', 1883: 'mqtt', 2049: 'nfs', 2375: 'docker', 2376: 'docker-tls',
  3306: 'mysql', 3389: 'rdp', 4840: 'opc-ua', 5432: 'postgresql', 5672: 'amqp', 5985: 'winrm', 5986: 'winrm-https',
  6379: 'redis', 6443: 'kubernetes-api', 8080: 'http-alt', 8443: 'https-alt', 8883: 'mqtt-tls', 9092: 'kafka',
  9200: 'elasticsearch', 20000: 'dnp3', 27017: 'mongodb', 44818: 'ethernet-ip', 47808: 'bacnet',
});
function ipv4Scope(octets: number[]): Scope {
  const [a, b, c] = octets as [number, number, number, number];
  if (a === 192 && b === 0 && c === 2 || a === 198 && b === 51 && c === 100 || a === 203 && b === 0 && c === 113) return 'DOCUMENTATION';
  if (a === 10 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168) return 'PRIVATE';
  if (a === 127) return 'LOOPBACK';
  if (a === 169 && b === 254) return 'LINK_LOCAL';
  if (a === 100 && b >= 64 && b <= 127) return 'SHARED';
  if (a >= 224 && a <= 239) return 'MULTICAST';
  if (a === 0) return 'UNSPECIFIED';
  return 'PUBLIC';
}
function ipv6Scope(groups: number[]): Scope {
  if (groups[0] === 0x2001 && groups[1] === 0x0db8) return 'DOCUMENTATION';
  if (groups.every((group) => group === 0)) return 'UNSPECIFIED';
  if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1) return 'LOOPBACK';
  if ((groups[0]! & 0xffc0) === 0xfe80) return 'LINK_LOCAL';
  if ((groups[0]! & 0xfe00) === 0xfc00) return 'PRIVATE';
  if ((groups[0]! & 0xff00) === 0xff00) return 'MULTICAST';
  return 'PUBLIC';
}
const RESERVED_NAMES = /(?:^|\.)(?:example\.(?:com|net|org)|example|invalid|test|localhost)$/iu;
function nameScope(name: string): Scope {
  if (RESERVED_NAMES.test(name)) return 'RESERVED_NAME';
  if (/\.(?:local|internal|lan|corp|home\.arpa|intranet)$/iu.test(name)) return 'PRIVATE';
  return 'PUBLIC';
}

/* ---------- Network identifiers ---------- */

// Bounded patterns; lookarounds keep version strings (`v1.2.3.4`, `1.2.3.4.5`) and longer tokens out.
const IPV4 = /(?<![\w.-])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?:\/(3[0-2]|[12]?\d))?(?![\w-]|\.\d)/gu;
const IPV6 = /(?<![\w:.])((?:[0-9A-Fa-f]{1,4}:|:){2,7}(?:[0-9A-Fa-f]{1,4}|:)?)(?:%[\w.-]{1,32})?(?:\/(12[0-8]|1[01]\d|[1-9]?\d))?(?![\w:.])/gu;
const MAC = /(?<![\w:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}(?![\w:-])/gu;
function parseIpv6(text: string): number[] | null {
  const parts = text.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  if (parts.length === 1 && head.length !== 8) return null;
  if (head.length + tail.length > (parts.length === 2 ? 7 : 8)) return null;
  const groups = [...head, ...Array<string>(8 - head.length - tail.length).fill('0'), ...tail];
  if (groups.some((group) => !/^[0-9A-Fa-f]{1,4}$/u.test(group))) return null;
  return groups.map((group) => parseInt(group, 16));
}
function networkCandidates(text: string, out: Found[]): void {
  for (const match of text.matchAll(IPV4)) {
    const octets = match[1]!.split('.').map(Number);
    const fidelity: InfraFidelity = { ipVersion: 4, scope: ipv4Scope(octets) };
    add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: match[2] ? 'SUBNET' : 'IP', rule: 'format.ipv4', basis: 'FORMAT',
      start: match.index, end: match.index + match[0].length, fidelity });
  }
  for (const match of text.matchAll(MAC)) {
    add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: 'MAC', rule: 'format.mac', basis: 'FORMAT',
      start: match.index, end: match.index + match[0].length, fidelity: {} });
  }
  for (const match of text.matchAll(IPV6)) {
    // `12:30:45` and MAC addresses are not IPv6: require all eight groups or a `::`.
    const groups = parseIpv6(match[1]!.replace(/:$/u, match[1]!.endsWith('::') ? ':' : ''));
    if (!groups || !match[1]!.includes('::') && match[1]!.split(':').length !== 8) continue;
    add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: match[2] ? 'SUBNET' : 'IP', rule: 'format.ipv6', basis: 'FORMAT',
      start: match.index, end: match.index + match[0].length, fidelity: { ipVersion: 6, scope: ipv6Scope(groups) } });
  }
}

/* ---------- Names, URLs and ports ---------- */

// File extensions that look like TLDs; a dotted name ending in one is a file, not a host, outside a URL.
const FILE_SUFFIX = new Set(['json', 'html', 'htm', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'md', 'txt', 'yml', 'yaml', 'xml', 'csv',
  'log', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'pdf', 'zip', 'gz', 'tgz', 'tar', 'py', 'java', 'go', 'rs', 'sh', 'exe', 'dll', 'so',
  'css', 'lock', 'toml', 'ini', 'cfg', 'conf', 'bak', 'tmp', 'jar', 'war', 'class', 'c', 'h', 'cpp', 'hpp', 'cs', 'rb', 'php',
  'sql', 'db', 'dat', 'bin', 'iso', 'img', 'env', 'pem', 'crt', 'key', 'pub', 'map', 'd', 'test', 'spec', 'min', 'bz2', 'xz',
  'docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt', 'dwg', 'dxf', 'step', 'stp', 'iges', 'igs', 'stl', 'nc', 'gcode']);
const DOMAIN = /(?<![\w.@/-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,16}[A-Za-z][A-Za-z0-9-]{0,23}[A-Za-z0-9]?)(?::(\d{1,5}))?(?![\w-]|\.[A-Za-z0-9])/gu;
const URL_RE = /(?<![\w+.-])([A-Za-z][A-Za-z0-9+.-]{0,31}):\/\/([^\s"'<>`/?#]{1,512})([^\s"'<>`]{0,8192})/gu;
function portFidelity(port: string): InfraFidelity {
  const service = WELL_KNOWN[Number(port)];
  return service ? { wellKnownService: service } : {};
}
function nameCandidates(text: string, out: Found[]): void {
  for (const match of text.matchAll(DOMAIN)) {
    const name = match[1]!;
    const last = name.slice(name.lastIndexOf('.') + 1).toLowerCase();
    // `package.json` is a file; `build.tenant-a.invalid` is a host. Reserved names always count.
    if (FILE_SUFFIX.has(last) && !RESERVED_NAMES.test(name) || /^\d+$/u.test(last)) continue;
    const scope = nameScope(name);
    add(out, { semanticType: 'HOST_OR_SERVICE', rule: 'format.dns-name', basis: 'FORMAT', start: match.index,
      end: match.index + name.length, fidelity: { scope } });
    if (match[2] !== undefined && Number(match[2]) <= 65535) {
      const start = match.index + name.length + 1;
      add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT', rule: 'format.host-port', basis: 'FORMAT', start,
        end: start + match[2].length, fidelity: portFidelity(match[2]) });
    }
  }
  for (const match of text.matchAll(URL_RE)) {
    const scheme = match[1]!.toLowerCase();
    add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: 'URL', rule: 'format.url', basis: 'FORMAT', start: match.index,
      end: match.index + match[0].length, fidelity: { scheme } });
    // The authority host is also a HOST candidate even when it is a single label (`http://db01:5432`).
    const authority = match[2]!;
    const at = authority.lastIndexOf('@');
    const hostPort = authority.slice(at + 1);
    const hostStart = match.index + match[1]!.length + 3 + at + 1;
    const port = /^(\[[^\]]{1,64}\]|[^:]{1,255})(?::(\d{1,5}))?$/u.exec(hostPort);
    if (port && port[1] && !/^\[|^[\d.]+$/u.test(port[1])) {
      add(out, { semanticType: 'HOST_OR_SERVICE', rule: 'format.url-host', basis: 'FORMAT', start: hostStart,
        end: hostStart + port[1].length, fidelity: { scope: nameScope(port[1]) } });
    }
    if (port?.[2] !== undefined && Number(port[2]) <= 65535) {
      const start = hostStart + port[1]!.length + 1;
      add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT', rule: 'format.url-port', basis: 'FORMAT', start,
        end: start + port[2].length, fidelity: portFidelity(port[2]) });
    }
  }
}

/* ---------- Paths ---------- */

const POSIX_PATH = /(?<![\w:/.~\\-])(~?\/(?:[\w.@+-]{1,255}\/){1,64}[\w.@+-]{0,255})/gu;
const WINDOWS_PATH = /(?<![\w\\])([A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\t]{1,255}\\){0,64}[^\\/:*?"<>|\r\n\t ]{0,255})/gu;
const UNC_PATH = /(?<![\w\\])(\\\\[\w.-]{1,255}\\[^\\/:*?"<>|\r\n\t ]{1,255}(?:\\[^\\/:*?"<>|\r\n\t ]{1,255}){0,64})/gu;
function pathCandidates(text: string, out: Found[]): void {
  for (const [pattern, style, rule] of [[POSIX_PATH, 'POSIX', 'format.posix-path'], [WINDOWS_PATH, 'WINDOWS', 'format.windows-path'],
    [UNC_PATH, 'UNC', 'format.unc-path']] as const) {
    for (const match of text.matchAll(pattern)) {
      const value = match[1]!.replace(/[.,;:)\]]+$/u, '');
      // A URL path is part of the URL candidate; bare `/` separators (`a / b`) are not paths.
      if (value.length < 3) continue;
      add(out, { semanticType: 'FILE_OR_RESOURCE_PATH', rule, basis: 'FORMAT', start: match.index, end: match.index + value.length,
        fidelity: { pathStyle: style } });
    }
  }
}

/* ---------- Cloud identifiers ---------- */

const GUID = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}';
const ARN = /(?<![\w:-])arn:aws(?:-[a-z]{2,10}){0,2}:[a-z0-9-]{1,64}:[a-z0-9-]{0,32}:(\d{12})?:[^\s"'`<>,]{1,1024}/gu;
const AZURE_ID = new RegExp(`/subscriptions/(${GUID})(?:/resourceGroups/([\\w().-]{1,90}))?(?:/providers/[^\\s"'\`<>,]{1,1024})?`, 'giu');
const GCP_PROJECT = /(?<![\w-])projects\/([a-z][a-z0-9-]{4,28}[a-z0-9])(?![\w-])/gu;
const BUCKET_URI = /(?<![\w+.-])(?:s3|gs|abfss?|wasbs?):\/\/([a-z0-9][a-z0-9._@-]{1,221}[a-z0-9])/gu;
const BUCKET_HOST = /(?<![\w.-])([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.(?:s3(?:[.-][a-z0-9-]{1,32})?\.amazonaws\.com|blob\.core\.windows\.net|dfs\.core\.windows\.net)(?![\w-])/gu;
const SERVICE_ACCOUNT = /(?<![\w.+-])[a-z][a-z0-9-]{4,62}@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com(?![\w-])/gu;
// Keyed cloud identifiers: `"subscriptionId": "<guid>"`, `aws_account_id = 123456789012`, `tenant: <guid>`.
const CLOUD_KEY = new RegExp(`(?<![\\w-])["']?([A-Za-z_][\\w.-]{0,63})["']?[ \\t]*[:=][ \\t]*["']?(${GUID}|\\d{12})(?![\\w-])`, 'gu');
const KEYED_SUBTYPE: readonly [RegExp, string][] = [
  [/tenant|directory/u, 'TENANT_ID'], [/subscription/u, 'SUBSCRIPTION_ID'], [/account|client|application|appid|principal|object/u, 'ACCOUNT_ID'],
];
function cloudCandidates(text: string, out: Found[]): void {
  const push = (subtype: string, rule: string, start: number, end: number, cloud: Cloud): void =>
    add(out, { semanticType: 'CLOUD_RESOURCE', subtype, rule, basis: 'FORMAT', start, end, fidelity: { cloud } });
  for (const match of text.matchAll(ARN)) {
    push('ARN', 'format.aws-arn', match.index, match.index + match[0].length, 'AWS');
    if (match[1]) {
      const start = match.index + match[0].indexOf(`:${match[1]}:`) + 1;
      push('ACCOUNT_ID', 'format.aws-arn-account', start, start + 12, 'AWS');
    }
  }
  for (const match of text.matchAll(AZURE_ID)) {
    const subscription = match.index + '/subscriptions/'.length;
    push('SUBSCRIPTION_ID', 'format.azure-subscription', subscription, subscription + 36, 'AZURE');
    if (match[2]) {
      const group = match.index + match[0].toLowerCase().indexOf('/resourcegroups/') + '/resourceGroups/'.length;
      push('RESOURCE_GROUP', 'format.azure-resource-group', group, group + match[2].length, 'AZURE');
    }
  }
  for (const match of text.matchAll(GCP_PROJECT)) {
    const start = match.index + 'projects/'.length;
    push('PROJECT_ID', 'format.gcp-project', start, start + match[1]!.length, 'GCP');
  }
  for (const match of text.matchAll(BUCKET_URI)) {
    const start = match.index + match[0].length - match[1]!.length;
    push('BUCKET', 'format.bucket-uri', start, start + match[1]!.length, /^gs/u.test(match[0]) ? 'GCP' : /^s3/u.test(match[0]) ? 'AWS' : 'AZURE');
  }
  for (const match of text.matchAll(BUCKET_HOST)) {
    push('BUCKET', 'format.bucket-host', match.index, match.index + match[1]!.length, match[0].includes('amazonaws') ? 'AWS' : 'AZURE');
  }
  for (const match of text.matchAll(SERVICE_ACCOUNT)) {
    push('SERVICE_ACCOUNT', 'format.gcp-service-account', match.index, match.index + match[0].length, 'GCP');
  }
  for (const match of text.matchAll(CLOUD_KEY)) {
    const key = match[1]!.toLowerCase().replace(/[^a-z]/gu, '');
    const subtype = KEYED_SUBTYPE.find(([pattern]) => pattern.test(key))?.[1] ?? (/aws|cloud|azure|gcp/u.test(key) ? 'ACCOUNT_ID' : null);
    if (!subtype || match[2]!.length === 12 && !/account/u.test(key)) continue;
    const start = match.index + match[0].length - match[2]!.length;
    add(out, { semanticType: 'CLOUD_RESOURCE', subtype, rule: 'context.cloud-key', basis: 'CONTEXT', start, end: start + match[2]!.length,
      fidelity: {} });
  }
}

/* ---------- Keyed host, service and environment names ---------- */

// Single-label hosts (`db01`) and environments have no format; a naming key supplies the context.
const NAME_KEY = /(?<![\w-])["']?((?:[A-Za-z]+[_.-]?)?(?:host(?:name)?|server|endpoint|service|address|node|instance|cluster|env|environment|stage|tier))["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9][\w.-]{0,254})/giu;
function keyedCandidates(text: string, out: Found[]): void {
  for (const match of text.matchAll(NAME_KEY)) {
    const key = match[1]!.toLowerCase();
    const value = match[2]!;
    if (/^(?:true|false|null|none|\d+)$/iu.test(value)) continue;
    const start = match.index + match[0].length - value.length;
    const environment = /(?:^|[_.-])(?:env|environment|stage|tier)$/u.test(key) || /^(?:env|environment|stage|tier)$/u.test(key);
    add(out, { semanticType: environment ? 'APPLICATION_OR_ENVIRONMENT' : 'HOST_OR_SERVICE', rule: 'context.name-key',
      basis: 'CONTEXT', start, end: start + value.length, fidelity: environment ? {} : { scope: nameScope(value) } });
  }
}

/* ---------- Detection ---------- */

function failure(reason: string): InfraResult {
  return Object.freeze({ status: 'FAILURE', reasons: Object.freeze([reason]), candidates: Object.freeze([]) });
}
function label(value: unknown, limit = 1024): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
/**
 * Run every rule over `text` (caller-normalized; #6 decoded views are scanned separately). Overlapping
 * candidates (a URL and its host) are all kept; composition must not discard stronger evidence.
 */
export function detectInfrastructure(request: InfraRequest): InfraResult {
  let text: unknown, inputRef: unknown;
  try { ({ text, inputRef } = request); } catch { return failure('INVALID_REQUEST'); }
  if (typeof text !== 'string' || !label(inputRef)) return failure('INVALID_REQUEST');
  if (text.length > MAX_TEXT_UNITS) return failure('INPUT_TOO_LARGE');
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(text)) return failure('INVALID_TEXT');
  const found: Found[] = [];
  try {
    networkCandidates(text, found);
    nameCandidates(text, found);
    pathCandidates(text, found);
    cloudCandidates(text, found);
    keyedCandidates(text, found);
  } catch (error) {
    return failure(error instanceof TooMany ? 'TOO_MANY_CANDIDATES' : 'INTERNAL_ERROR');
  }
  found.sort((a, b) => a.start - b.start || a.end - b.end || a.rule.localeCompare(b.rule));
  const unique = found.filter((item, index) => index === 0 || item.start !== found[index - 1]!.start ||
    item.end !== found[index - 1]!.end || item.semanticType !== found[index - 1]!.semanticType ||
    item.subtype !== found[index - 1]!.subtype);
  if (unique.length > MAX_CANDIDATES) return failure('TOO_MANY_CANDIDATES');
  const field = createHash('sha256').update(inputRef).digest('hex').slice(0, 16);
  const candidates = unique.map((item) => Object.freeze({
    semanticType: item.semanticType, ...(item.subtype ? { subtype: item.subtype } : {}), rule: item.rule, basis: item.basis,
    start: item.start, end: item.end, fidelity: Object.freeze({ ...item.fidelity }),
    evidence: Object.freeze({
      version: 1 as const,
      id: `${INFRA_PRODUCER.id}.${(item.subtype ?? item.semanticType).toLowerCase()}.${field}.${item.start}-${item.end}`,
      status: 'FOUND' as const,
      provenance: Object.freeze({ inputRef, producerId: INFRA_PRODUCER.id, producerVersion: INFRA_PRODUCER.version }),
      // No sensitivity: that is policy metadata; v1 composition stays UNRESOLVED until configuration adds it.
      claim: Object.freeze({ semanticType: item.semanticType, ...(item.subtype ? { subtype: item.subtype } : {}) }),
    }),
  }));
  return Object.freeze({ status: 'COMPLETE', reasons: Object.freeze([]), candidates: Object.freeze(candidates) });
}
