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
  scope?: 'DOCUMENTATION' | 'PRIVATE' | 'LOOPBACK' | 'LINK_LOCAL' | 'SHARED' | 'MULTICAST' | 'UNSPECIFIED' | 'RESERVED' |
    'PUBLIC' | 'RESERVED_NAME';
  /** Well-known service for a port, e.g. `https` for 443; the number itself is the value. */
  wellKnownService?: string;
  /** Well-known scheme, or OTHER for custom schemes (which can name a tenant). */
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
function ipv4Scope(octets: number[], prefix?: number): Scope {
  const [a, b, c, d] = octets as [number, number, number, number];
  // A prefix shorter than /24 covers more than the documentation block.
  const narrow = prefix === undefined || prefix >= 24;
  if (narrow && (a === 192 && b === 0 && c === 2 || a === 198 && b === 51 && c === 100 || a === 203 && b === 0 && c === 113)) return 'DOCUMENTATION';
  if (a === 10 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168) return 'PRIVATE';
  if (a === 127) return 'LOOPBACK';
  if (a === 169 && b === 254) return 'LINK_LOCAL';
  if (a === 100 && b >= 64 && b <= 127) return 'SHARED';
  if (a >= 224 && a <= 239) return 'MULTICAST';
  if (a === 0) return 'UNSPECIFIED';
  if (a === 198 && (b === 18 || b === 19) || a >= 240 || a === 192 && b === 0 && c === 0 || a === 255 && b === 255 && c === 255 && d === 255) return 'RESERVED';
  return 'PUBLIC';
}
function ipv6Scope(groups: number[], prefix?: number): Scope {
  const narrow = prefix === undefined || prefix >= 32;
  if (narrow && (groups[0] === 0x2001 && groups[1] === 0x0db8 || (groups[0]! & 0xfff0) === 0x3ff0 && (prefix === undefined || prefix >= 20))) return 'DOCUMENTATION';
  // IPv4-mapped: the embedded IPv4 decides.
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    return ipv4Scope([groups[6]! >> 8, groups[6]! & 255, groups[7]! >> 8, groups[7]! & 255]);
  }
  if (groups.every((group) => group === 0)) return 'UNSPECIFIED';
  if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1) return 'LOOPBACK';
  if ((groups[0]! & 0xffc0) === 0xfe80) return 'LINK_LOCAL';
  if ((groups[0]! & 0xfe00) === 0xfc00 || (groups[0]! & 0xffc0) === 0xfec0) return 'PRIVATE';
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
// `-`/`_` adjacency (`10.0.0.1-10.0.0.5`, `ip-10.0.0.1`, `10.0.0.1_eth0`) is a boundary; letters and more dots are not.
// Octets are validated numerically, so zero-padded forms (`10.001.002.003`) are found too.
const IPV4 = /(?<![A-Za-z0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?(?::(\d{1,5}))?(?![A-Za-z0-9]|\.\d)/gu;
// Optional embedded IPv4 tail (`::ffff:192.0.2.1`), brackets and a trailing `:port` after `]`.
const IPV6 = /(?<![\w:.])(\[)?((?:[0-9A-Fa-f]{1,4}:|:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{1,4}|:)?)(?:%[\w.-]{1,32})?(?:\/(\d{1,3}))?(?:\](?::(\d{1,5}))?)?(?![\w:]|\.[0-9A-Fa-f])/gu;
const MAC = /(?<![\w:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}(?![\w:-])/gu;
function parseIpv6(raw: string): number[] | null {
  let text = raw;
  const embedded = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u.exec(text);
  if (embedded) {
    const octets = embedded.slice(1).map(Number);
    if (octets.some((octet) => octet > 255)) return null;
    text = text.slice(0, embedded.index) + `${((octets[0]! << 8) | octets[1]!).toString(16)}:${((octets[2]! << 8) | octets[3]!).toString(16)}`;
  }
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
    const prefix = match[2] !== undefined ? Number(match[2]) : undefined;
    if (octets.some((octet) => octet > 255) || prefix !== undefined && prefix > 32) continue;
    const fidelity: InfraFidelity = { ipVersion: 4, scope: ipv4Scope(octets, prefix) };
    const end = match.index + match[1]!.length + (match[2] !== undefined ? match[2].length + 1 : 0);
    add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: prefix !== undefined ? 'SUBNET' : 'IP', rule: 'format.ipv4', basis: 'FORMAT',
      start: match.index, end, fidelity });
    if (match[3] !== undefined && Number(match[3]) <= 65535) {
      add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT', rule: 'format.ip-port', basis: 'FORMAT', start: end + 1,
        end: end + 1 + match[3].length, fidelity: portFidelity(match[3]) });
    }
  }
  for (const match of text.matchAll(MAC)) {
    add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: 'MAC', rule: 'format.mac', basis: 'FORMAT',
      start: match.index, end: match.index + match[0].length, fidelity: {} });
  }
  for (const match of text.matchAll(IPV6)) {
    const address = match[2]!;
    const groups = parseIpv6(address.replace(/:$/u, address.endsWith('::') ? ':' : ''));
    // `12:30:45` and MACs are not IPv6: require all eight groups or a `::`. Hex words (`dead::beef`, `a::b`) need a digit.
    const tailGroups = address.includes('.') ? 7 : 8;
    if (!groups || !address.includes('::') && address.split(':').length !== tailGroups ||
      address.includes('::') && !/\d/u.test(address) && address.split(':').filter(Boolean).length < 3) continue;
    const prefix = match[3] !== undefined ? Number(match[3]) : undefined;
    if (prefix !== undefined && prefix > 128) continue;
    const start = match.index + (match[1] ? 1 : 0);
    const end = start + match[0].length - (match[1] ? 1 : 0) - (match[4] !== undefined ? match[4].length + 2 : match[1] && match[0].endsWith(']') ? 1 : 0);
    add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: prefix !== undefined ? 'SUBNET' : 'IP', rule: 'format.ipv6', basis: 'FORMAT',
      start, end, fidelity: { ipVersion: 6, scope: ipv6Scope(groups, prefix) } });
    if (match[4] !== undefined && Number(match[4]) <= 65535) {
      const portStart = match.index + match[0].length - match[4].length;
      add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT', rule: 'format.ip-port', basis: 'FORMAT', start: portStart,
        end: portStart + match[4].length, fidelity: portFidelity(match[4]) });
    }
  }
}

/* ---------- Names, URLs and ports ---------- */

// File extensions that look like TLDs; a dotted name ending in one is a file, not a host, outside a URL.
const FILE_SUFFIX = new Set(['json', 'html', 'htm', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'md', 'txt', 'yml', 'yaml', 'xml', 'csv',
  'log', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'pdf', 'zip', 'gz', 'tgz', 'tar', 'py', 'java', 'go', 'rs', 'sh', 'exe', 'dll', 'so',
  'css', 'lock', 'toml', 'ini', 'cfg', 'conf', 'bak', 'tmp', 'jar', 'war', 'class', 'c', 'h', 'cpp', 'hpp', 'cs', 'rb', 'php',
  'sql', 'db', 'dat', 'bin', 'iso', 'img', 'env', 'pem', 'crt', 'key', 'pub', 'map', 'd', 'test', 'spec', 'min', 'bz2', 'xz',
  'docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt', 'dwg', 'dxf', 'step', 'stp', 'iges', 'igs', 'stl', 'nc', 'gcode']);
// Names may follow `/` (URL paths, nested URLs) and `@` (user@host); IDN labels are included.
const DOMAIN = /(?<![\p{L}\p{N}_.-])((?:[\p{L}\p{N}](?:[\p{L}\p{M}\p{N}-]{0,61}[\p{L}\p{M}\p{N}])?\.){1,32}(?:xn--[a-z0-9-]{1,59}|\p{L}[\p{L}\p{M}\p{N}-]{0,61}[\p{L}\p{M}\p{N}]))\.?(?::(\d{1,5}))?(?![\p{L}\p{N}_-]|\.[\p{L}\p{N}])/gu;
// A last label that is a real or reserved TLD; `obj.method.call`, `java.util.List` and `e.g` are code or prose.
const TLDS = new Set(['com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'io', 'ai', 'app', 'dev', 'cloud', 'tech',
  'online', 'site', 'xyz', 'name', 'pro', 'mobi', 'aero', 'coop', 'museum', 'jobs', 'travel', 'asia', 'arpa', 'local', 'internal',
  'lan', 'corp', 'intranet', 'home', 'invalid', 'test', 'example', 'localhost', 'onion', 'services', 'systems', 'company', 'global',
  'network', 'digital', 'group', 'solutions', 'industries', 'energy', 'engineering', 'email', 'link', 'live', 'store', 'shop', 'blog']);
function isTld(label: string): boolean {
  const lower = label.toLowerCase();
  return TLDS.has(lower) || /^[a-z]{2}$/u.test(lower) || lower.startsWith('xn--') || /[^\u0000-\u007f]/u.test(lower);
}
const URL_RE = /(?<![\w+.-])([A-Za-z][A-Za-z0-9+.-]{0,31}):\/\/([^\s"'<>`/?#]{1,512})([^\s"'<>`]{0,8192})/gu;
const SCHEMES = new Set(['http', 'https', 'ws', 'wss', 'ftp', 'ftps', 'sftp', 'ssh', 'git', 'file', 'ldap', 'ldaps', 'smb', 'nfs', 'mqtt',
  'mqtts', 'amqp', 'amqps', 'redis', 'rediss', 'postgres', 'postgresql', 'mysql', 'mongodb', 'mongodb+srv', 'jdbc', 'opc.tcp', 'modbus',
  'tcp', 'udp', 's3', 's3a', 'gs', 'abfs', 'abfss', 'wasb', 'wasbs', 'hdfs', 'kafka', 'grpc', 'grpcs', 'rtsp', 'sip', 'telnet']);
function portFidelity(port: string): InfraFidelity {
  const service = WELL_KNOWN[Number(port)];
  return service ? { wellKnownService: service } : {};
}
function nameCandidates(text: string, out: Found[]): void {
  for (const match of text.matchAll(DOMAIN)) {
    const name = match[1]!;
    const last = name.slice(name.lastIndexOf('.') + 1).toLowerCase();
    // `package.json` is a file; `build.tenant-a.invalid` is a host. Reserved names always count.
    if (FILE_SUFFIX.has(last) && !RESERVED_NAMES.test(name) || !isTld(last)) continue;
    const scope = nameScope(name);
    add(out, { semanticType: 'HOST_OR_SERVICE', rule: 'format.dns-name', basis: 'FORMAT', start: match.index,
      end: match.index + name.length, fidelity: { scope } });
    if (match[2] !== undefined && Number(match[2]) <= 65535) {
      const start = match.index + match[0].length - match[2].length;
      add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT', rule: 'format.host-port', basis: 'FORMAT', start,
        end: start + match[2].length, fidelity: portFidelity(match[2]) });
    }
  }
  for (const match of text.matchAll(URL_RE)) {
    const scheme = match[1]!.toLowerCase();
    // Trailing prose punctuation is not part of the URL; an unmatched `)` is prose too.
    let rest = match[3]!;
    while (/[.,;:!?'\]}]$/u.test(rest) || rest.endsWith(')') && (rest.match(/\(/gu) ?? []).length < (rest.match(/\)/gu) ?? []).length) {
      rest = rest.slice(0, -1);
    }
    add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: 'URL', rule: 'format.url', basis: 'FORMAT', start: match.index,
      end: match.index + match[1]!.length + 3 + match[2]!.length + rest.length, fidelity: { scheme: SCHEMES.has(scheme) ? scheme : 'OTHER' } });
    // The authority host is also a HOST candidate even when it is a single label (`http://db01:5432`).
    const authority = match[2]!;
    const at = authority.lastIndexOf('@');
    const hostPort = authority.slice(at + 1);
    const hostStart = match.index + match[1]!.length + 3 + at + 1;
    const port = /^(\[[^\]]{1,64}\]|[^:]{1,255})(?::(\d{1,5}))?$/u.exec(hostPort);
    const host = port?.[1]?.replace(/\.$/u, '');
    if (port && host && !/^\[|^[\d.]+$/u.test(host)) {
      add(out, { semanticType: 'HOST_OR_SERVICE', rule: 'format.url-host', basis: 'FORMAT', start: hostStart,
        end: hostStart + host.length, fidelity: { scope: nameScope(host) } });
    }
    if (port?.[2] !== undefined && Number(port[2]) <= 65535) {
      const start = hostStart + port[1]!.length + 1;
      add(out, { semanticType: 'NETWORK_IDENTIFIER', subtype: 'PORT', rule: 'format.url-port', basis: 'FORMAT', start,
        end: start + port[2].length, fidelity: portFidelity(port[2]) });
    }
  }
}

/* ---------- Paths ---------- */

// `:` is a boundary so colon-separated lists (`PATH=/a:/b`, `-v /x:/y`) yield every path.
const POSIX_PATH = /(?<![\w/.~\\-])(~?\/(?:[\w.@+-]{1,255}\/){1,64}[\w.@+-]{0,255})/gu;
// Windows drive paths with either separator, and `\\?\` long-path prefixes.
const WINDOWS_PATH = /(?<![\w\\])((?:\\\\\?\\)?[A-Za-z]:[\\/](?:[^\\/:*?"<>|\r\n\t]{1,255}[\\/]){0,64}[^\\/:*?"<>|\r\n\t ]{0,255})/gu;
const FILE_URL = /(?<![\w+.-])file:\/\/(?:localhost)?(\/[^\s"'<>`]{1,4096})/giu;
const UNC_PATH = /(?<![\w\\])(\\\\[\w.-]{1,255}\\[^\\/:*?"<>|\r\n\t ]{1,255}(?:\\[^\\/:*?"<>|\r\n\t ]{1,255}){0,64})/gu;
function pathCandidates(text: string, out: Found[]): void {
  for (const [pattern, style, rule] of [[POSIX_PATH, 'POSIX', 'format.posix-path'], [WINDOWS_PATH, 'WINDOWS', 'format.windows-path'],
    [UNC_PATH, 'UNC', 'format.unc-path']] as const) {
    for (const match of text.matchAll(pattern)) {
      const value = match[1]!.replace(/[.,;:)\]]+$/u, '');
      // Bare `/` separators (`a / b`) are not paths.
      if (value.length < 3) continue;
      let end = match.index + value.length;
      // A quoted path may contain spaces: cover it to the closing quote on the same line.
      const quote = text[match.index - 1];
      if (quote === '"' || quote === "'") {
        const close = text.indexOf(quote, end);
        const newline = text.indexOf('\n', end);
        if (close > end && (newline < 0 || close < newline)) end = close;
      }
      add(out, { semanticType: 'FILE_OR_RESOURCE_PATH', rule, basis: 'FORMAT', start: match.index, end, fidelity: { pathStyle: style } });
    }
  }
  for (const match of text.matchAll(FILE_URL)) {
    const path = match[1]!;
    const start = match.index + match[0].length - path.length;
    add(out, { semanticType: 'FILE_OR_RESOURCE_PATH', rule: 'format.file-url', basis: 'FORMAT', start, end: start + path.length,
      fidelity: { pathStyle: /^\/[A-Za-z]:/u.test(path) ? 'WINDOWS' : 'POSIX' } });
  }
}

/* ---------- Cloud identifiers ---------- */

const GUID = '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}';
const ARN = /(?<![\w:-])arn:aws(?:-[a-z]{1,10}){0,2}:[a-z0-9-]{1,64}:[a-z0-9-]{0,32}:(\d{12})?:[^\s"'`<>,]{1,1024}/gu;
const AZURE_ID = new RegExp(`/subscriptions/(${GUID})(?:/resourceGroups/([\\w().-]{1,90}))?(?:/providers/[^\\s"'\`<>,]{1,1024})?`, 'giu');
// GCP resource names need a GCP collection after the project (`projects/p/zones/...`), not a local `~/projects/x`.
const GCP_PROJECT = /(?<![\w~.-])projects\/([a-z][a-z0-9-]{4,28}[a-z0-9])(?=\/(?:zones|locations|global|regions|instances|topics|subscriptions|secrets|datasets|databases|buckets|serviceAccounts|logs|sinks|metrics|jobs)\b)/gu;
const GCP_PROJECT_KEY = /(?<![\w-])["']?(?:gcp[_-]?|google[_-]?)?project(?:[_-]?id)?["']?[ \t]*[:=][ \t]*["']?([a-z][a-z0-9-]{4,28}[a-z0-9])(?![\w-])/giu;
const BUCKET_URI = /(?<![\w+.-])(?:s3a?|s3n|gs|abfss?|wasbs?):\/\/([a-z0-9][a-z0-9._@-]{1,221}[a-z0-9])/gu;
const BUCKET_PATH = /(?<![\w.-])(?:storage\.googleapis\.com|s3(?:[.-][a-z0-9-]{1,32})?\.amazonaws\.com)\/([a-z0-9][a-z0-9._-]{1,221}[a-z0-9])/gu;
const BUCKET_HOST = /(?<![\w.-])([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.(?:s3(?:[.-][a-z0-9-]{1,32})?\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|dfs\.core\.windows\.net)(?![\w-])/gu;
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
    push('BUCKET', 'format.bucket-host', match.index, match.index + match[1]!.length,
      match[0].includes('amazonaws') ? 'AWS' : match[0].includes('googleapis') ? 'GCP' : 'AZURE');
  }
  for (const match of text.matchAll(BUCKET_PATH)) {
    const start = match.index + match[0].length - match[1]!.length;
    push('BUCKET', 'format.bucket-path', start, start + match[1]!.length, match[0].includes('googleapis') ? 'GCP' : 'AWS');
  }
  for (const match of text.matchAll(GCP_PROJECT_KEY)) {
    const start = match.index + match[0].length - match[1]!.length;
    add(out, { semanticType: 'CLOUD_RESOURCE', subtype: 'PROJECT_ID', rule: 'context.gcp-project-key', basis: 'CONTEXT', start,
      end: start + match[1]!.length, fidelity: { cloud: 'GCP' } });
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
const NAME_KEY = /(?<![\w-])["']?((?:[A-Za-z]+[_.-]?)?(?:host(?:[_.-]?name)?|server(?:[_.-]?name)?|data source|endpoint|service|address|node|instance|cluster|env|environment|stage|tier))["']?[ \t]*[:=][ \t]*["']?(?:(?:tcp|np|lpc):)?([A-Za-z0-9][\w.-]{0,254})(?![\w.-]*(?::\/\/|@))/giu;
function keyedCandidates(text: string, out: Found[]): void {
  for (const match of text.matchAll(NAME_KEY)) {
    const key = match[1]!.toLowerCase();
    const value = match[2]!;
    if (/^(?:true|false|null|none|\d+)$/iu.test(value) || /^v?\d+(?:\.\d+)+/u.test(value)) continue;
    // A single label must look like a host (`db01`, `sql-synthetic`); `Main` after `address=` is prose.
    const environmentKey = /(?:^|[_.-])(?:env|environment|stage|tier)$/u.test(match[1]!.toLowerCase());
    if (!environmentKey && !/[.\d-]/u.test(value)) continue;
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
