/**
 * #33 dependency evidence: the exact locked dependency set and the SBOM that claims to describe it.
 *
 * Both inputs are untrusted build products. A lockfile is accepted only when its bytes are exactly
 * `JSON.stringify(JSON.parse(bytes), null, 2) + "\n"`, the format npm writes, which is what rejects
 * duplicate keys, alternative number spellings and hand-edited escapes without a bespoke parser. The
 * SBOM is read as CycloneDX JSON (bom-1.5 schema) and reduced to the same normalized set, so a
 * tailored, truncated or invented SBOM cannot pass as the locked tree. Nothing here contacts a
 * registry, resolves a version, scans for vulnerabilities or decides whether a release may proceed.
 */
import { decodeBase64Strict, isLowerHex } from './byte-encoding.js';

export const DEPENDENCY_EVIDENCE_VERSION = 'hylja.dependency-evidence.v1' as const;
export const MAX_LOCKFILE_BYTES = 8 << 20;
export const MAX_SBOM_BYTES = 32 << 20;
export const MAX_DEPENDENCIES = 20_000;
export const MAX_JSON_DEPTH = 32;
/** Node budget for the depth walk; the byte caps already bound the document. */
const MAX_JSON_NODES = 1 << 22;
/** Lockfile formats this gate understands; anything else is refused rather than guessed at. */
export const SUPPORTED_LOCKFILE_VERSIONS = Object.freeze([2, 3]);
export const SUPPORTED_SBOM_SPEC_VERSIONS = Object.freeze(['1.4', '1.5']);
/** Pin algorithms this gate can both parse and cross-check against an SBOM SHA-512 content hash. */
export const SUPPORTED_INTEGRITY_ALGORITHMS = Object.freeze(['sha256', 'sha384', 'sha512'] as const);

/**
 * Fixed failure vocabulary. These are also release denial codes, so the gate forwards a reader's
 * reason unchanged instead of sniffing message text. A hostile package name, path or byte never
 * reaches a message or a reason.
 */
export const DEPENDENCY_EVIDENCE_REASONS = Object.freeze([
  'LOCKFILE_EVIDENCE_MALFORMED', 'LOCKFILE_INTEGRITY_INVALID', 'SBOM_EVIDENCE_MALFORMED',
] as const);
/**
 * Parse failures, distinct from the comparison issues below. A reader failure means the document could
 * not be used at all; a comparison issue means two readable documents disagree. Both are published
 * release denial codes, and the two lists are disjoint.
 */
export type DependencyEvidenceReason = (typeof DEPENDENCY_EVIDENCE_REASONS)[number];

export class DependencyEvidenceFailure extends Error {
  constructor(readonly reason: DependencyEvidenceReason) {
    super('dependency evidence is unusable');
    this.name = 'DependencyEvidenceFailure';
  }
}

export interface LockedDependency {
  /** Lockfile key, e.g. `node_modules/example`. */
  path: string;
  name: string;
  version: string;
  /** Subresource-integrity value, or null when the entry is not pinned. */
  integrity: string | null;
  resolved: string | null;
  /** True for a workspace/link entry, which legitimately has no registry resolution. */
  link: boolean;
}
export interface LockedDependencySet {
  lockfileVersion: number;
  root: { name: string; version: string };
  dependencies: readonly LockedDependency[];
}
export interface SbomComponent {
  /** `cdx:npm:package:path` property, or null when the component carries none. */
  path: string | null;
  name: string;
  version: string;
  purl: string | null;
  /** Lowercase hex SHA-512 of the component content, or null when the SBOM states none. */
  contentSha512Hex: string | null;
  /** True when the component lists hashes but none of them is SHA-512. */
  unsupportedHashAlgorithm: boolean;
}
export interface SbomDependencySet {
  bomFormat: 'CycloneDX';
  specVersion: string;
  root: { name: string; version: string } | null;
  components: readonly SbomComponent[];
}

export type DependencyIssueCode =
  | 'LOCKED_DEPENDENCY_ABSENT_FROM_SBOM'
  | 'SBOM_COMPONENT_ABSENT_FROM_LOCKFILE'
  | 'SBOM_COMPONENT_DUPLICATE'
  | 'SBOM_COMPONENT_PATH_MISSING'
  | 'DEPENDENCY_VERSION_MISMATCH'
  | 'DEPENDENCY_CONTENT_MISMATCH'
  | 'DEPENDENCY_CONTENT_MISSING'
  | 'DEPENDENCY_CONTENT_ALGORITHM_UNSUPPORTED'
  | 'DEPENDENCY_NOT_INTEGRITY_PINNED'
  | 'DEPENDENCY_RESOLUTION_MISSING'
  | 'LOCKFILE_ROOT_VERSION_MISMATCH'
  | 'DEPENDENCY_NOT_IN_PUBLISHED_SET'
  | 'DEPENDENCY_MISSING_FROM_PUBLISHED_SET';

export const DEPENDENCY_ISSUE_CODES: readonly DependencyIssueCode[] = Object.freeze([
  'DEPENDENCY_CONTENT_ALGORITHM_UNSUPPORTED', 'DEPENDENCY_CONTENT_MISMATCH', 'DEPENDENCY_CONTENT_MISSING',
  'DEPENDENCY_MISSING_FROM_PUBLISHED_SET',
  'DEPENDENCY_NOT_INTEGRITY_PINNED', 'DEPENDENCY_NOT_IN_PUBLISHED_SET', 'DEPENDENCY_RESOLUTION_MISSING',
  'DEPENDENCY_VERSION_MISMATCH', 'LOCKED_DEPENDENCY_ABSENT_FROM_SBOM', 'LOCKFILE_ROOT_VERSION_MISMATCH',
  'SBOM_COMPONENT_ABSENT_FROM_LOCKFILE', 'SBOM_COMPONENT_DUPLICATE', 'SBOM_COMPONENT_PATH_MISSING',
] as DependencyIssueCode[]);

const decoder = new TextDecoder('utf-8', { fatal: true });
const MAX_ID = 512;

function reject(reason: DependencyEvidenceReason): never { throw new DependencyEvidenceFailure(reason); }
/**
 * The reader decides which document it is reading, so a shape defect is named against that one and
 * forwarded to the release gate unchanged. The code is passed explicitly rather than held in module
 * state, so a shape check can never be attributed to the wrong document.
 */
function asObject(value: unknown, code: DependencyEvidenceReason): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) reject(code);
  return value as Record<string, unknown>;
}
function asBoundedString(value: unknown, code: DependencyEvidenceReason, allowEmpty = false): string {
  if (typeof value !== 'string' || value.length > MAX_ID || /[\u0000-\u001f\u007f]/.test(value)) reject(code);
  if (!allowEmpty && value.length === 0) reject(code);
  return value;
}
/** Iterative depth measurement: a hostile document cannot make this recurse or allocate per level. */
function assertDepth(value: unknown, cap: number, code: DependencyEvidenceReason): void {
  const stack: [unknown, number][] = [[value, 1]];
  let visited = 0;
  while (stack.length > 0) {
    const frame = stack.pop() as [unknown, number];
    const current = frame[0];
    if (typeof current !== 'object' || current === null) continue;
    if (frame[1] > cap) reject(code);
    if (++visited > MAX_JSON_NODES) reject(code);
    const children = Array.isArray(current) ? current : Object.values(current as object);
    for (const child of children) stack.push([child, frame[1] + 1]);
  }
}
/** Parse and require the exact byte form npm writes, which also rejects duplicate JSON keys. */
function parseNpmJson(bytes: Uint8Array, maxBytes: number, reason: DependencyEvidenceReason): unknown {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) reject(reason);
  if (bytes.length > maxBytes) reject(reason);
  let text: string;
  try { text = decoder.decode(bytes); } catch { reject(reason); }
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { reject(reason); }
  try { assertDepth(parsed, MAX_JSON_DEPTH, reason); } catch (error) {
    if (error instanceof DependencyEvidenceFailure) throw error;
    reject(reason);
  }
  let reserialized: string;
  try { reserialized = `${JSON.stringify(parsed, null, 2)}\n`; } catch { reject(reason); }
  if (reserialized !== text) reject(reason);
  return parsed;
}
/**
 * Accept only a canonical `sha256|sha384|sha512` pin whose base64 decodes to the algorithm's digest
 * length. A malformed or unsupported pin is unusable evidence, refused here: it must never reach the
 * comparison as "no expectation", which would silently skip the content cross-check.
 */
function readIntegrityPin(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || value.length > 256) reject('LOCKFILE_INTEGRITY_INVALID');
  const match = /^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (match === null) reject('LOCKFILE_INTEGRITY_INVALID');
  const algorithm = match?.[1] as 'sha256' | 'sha384' | 'sha512';
  const expected = algorithm === 'sha256' ? 32 : algorithm === 'sha384' ? 48 : 64;
  const decoded = decodeBase64Strict(match?.[2] as string, expected);
  if (decoded === null || decoded.length !== expected) reject('LOCKFILE_INTEGRITY_INVALID');
  return value;
}
function packageNameFromPath(path: string): string {
  const marker = 'node_modules/';
  const index = path.lastIndexOf(marker);
  return index === -1 ? path : path.slice(index + marker.length);
}


/**
 * Read the exact locked dependency set. Every non-root entry is reported as it appears, including
 * unpinned or unresolved ones, so the comparison can name the pinning gap instead of hiding it.
 */
export function readLockedDependencies(bytes: Uint8Array): LockedDependencySet {
  const document = asObject(parseNpmJson(bytes, MAX_LOCKFILE_BYTES, 'LOCKFILE_EVIDENCE_MALFORMED'),
    'LOCKFILE_EVIDENCE_MALFORMED');
  const version = document['lockfileVersion'];
  if (typeof version !== 'number' || !SUPPORTED_LOCKFILE_VERSIONS.includes(version)) {
    reject('LOCKFILE_EVIDENCE_MALFORMED');
  }
  const packages = asObject(document['packages'], 'LOCKFILE_EVIDENCE_MALFORMED');
  const keys = Object.keys(packages);
  if (keys.length > MAX_DEPENDENCIES + 1) reject('LOCKFILE_EVIDENCE_MALFORMED');
  const rootEntry = asObject(packages[''] ?? null, 'LOCKFILE_EVIDENCE_MALFORMED');
  const root = {
    name: asBoundedString(rootEntry['name'] ?? document['name'], 'LOCKFILE_EVIDENCE_MALFORMED'),
    version: asBoundedString(rootEntry['version'] ?? document['version'], 'LOCKFILE_EVIDENCE_MALFORMED'),
  };
  const dependencies: LockedDependency[] = [];
  for (const path of keys) {
    if (path === '') continue;
    if (path.length > MAX_ID || path.startsWith('/') || path.includes('\\') || path.split('/').includes('..')) {
      reject('LOCKFILE_EVIDENCE_MALFORMED');
    }
    const entry = asObject(packages[path], 'LOCKFILE_EVIDENCE_MALFORMED');
    const link = entry['link'] === true;
    const integrity = readIntegrityPin(entry['integrity']);
    const resolved = entry['resolved'];
    dependencies.push({
      path,
      name: asBoundedString(entry['name'] ?? packageNameFromPath(path), 'LOCKFILE_EVIDENCE_MALFORMED'),
      version: asBoundedString(entry['version'], 'LOCKFILE_EVIDENCE_MALFORMED'),
      integrity,
      resolved: typeof resolved === 'string' && resolved.length <= 1024 ? resolved : null,
      link,
    });
  }
  dependencies.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  return { lockfileVersion: version, root, dependencies };
}

/** An absent or empty hash list is a missing content pin; a non-SHA-512 list is an unusable one. */
function readHashes(component: Record<string, unknown>): { sha512: string | null; unsupported: boolean } {
  const hashes = component['hashes'];
  if (hashes === undefined || hashes === null) return { sha512: null, unsupported: false };
  if (!Array.isArray(hashes) || hashes.length > 16) reject('SBOM_EVIDENCE_MALFORMED');
  if (hashes.length === 0) return { sha512: null, unsupported: false };
  let sha512: string | null = null;
  for (const item of hashes) {
    const hash = asObject(item, 'SBOM_EVIDENCE_MALFORMED');
    const algorithm = asBoundedString(hash['alg'], 'SBOM_EVIDENCE_MALFORMED');
    const content = asBoundedString(hash['content'], 'SBOM_EVIDENCE_MALFORMED');
    if (algorithm === 'SHA-512') {
      if (!isLowerHex(content, 128)) reject('SBOM_EVIDENCE_MALFORMED');
      sha512 = content;
    }
  }
  return { sha512, unsupported: sha512 === null };
}
function readPathProperty(component: Record<string, unknown>): string | null {
  const properties = component['properties'];
  if (properties === undefined || properties === null) return null;
  if (!Array.isArray(properties) || properties.length > 64) reject('SBOM_EVIDENCE_MALFORMED');
  let path: string | null = null;
  for (const item of properties) {
    const property = asObject(item, 'SBOM_EVIDENCE_MALFORMED');
    if (asBoundedString(property['name'], 'SBOM_EVIDENCE_MALFORMED') === 'cdx:npm:package:path') {
      path = asBoundedString(property['value'], 'SBOM_EVIDENCE_MALFORMED');
    }
  }
  return path;
}

/** Read a CycloneDX JSON SBOM into the same normalized set shape as the lockfile. */
export function readSbomComponents(bytes: Uint8Array): SbomDependencySet {
  const document = asObject(parseNpmJson(bytes, MAX_SBOM_BYTES, 'SBOM_EVIDENCE_MALFORMED'),
    'SBOM_EVIDENCE_MALFORMED');
  if (document['bomFormat'] !== 'CycloneDX') reject('SBOM_EVIDENCE_MALFORMED');
  const specVersion = asBoundedString(document['specVersion'], 'SBOM_EVIDENCE_MALFORMED');
  if (!SUPPORTED_SBOM_SPEC_VERSIONS.includes(specVersion)) reject('SBOM_EVIDENCE_MALFORMED');
  const list = document['components'];
  if (!Array.isArray(list)) reject('SBOM_EVIDENCE_MALFORMED');
  if (list.length > MAX_DEPENDENCIES) reject('SBOM_EVIDENCE_MALFORMED');
  const components: SbomComponent[] = [];
  for (const item of list) {
    const component = asObject(item, 'SBOM_EVIDENCE_MALFORMED');
    asBoundedString(component['type'], 'SBOM_EVIDENCE_MALFORMED');
    const hashes = readHashes(component);
    const purl = component['purl'];
    components.push({
      path: readPathProperty(component),
      name: asBoundedString(component['name'], 'SBOM_EVIDENCE_MALFORMED'),
      version: asBoundedString(component['version'], 'SBOM_EVIDENCE_MALFORMED'),
      purl: typeof purl === 'string' && purl.length <= 512 ? purl : null,
      contentSha512Hex: hashes.sha512,
      unsupportedHashAlgorithm: hashes.unsupported,
    });
  }
  const metadata = document['metadata'] === undefined ? null : asObject(document['metadata'], 'SBOM_EVIDENCE_MALFORMED');
  const rootComponent = metadata === null || metadata['component'] === undefined
    ? null : asObject(metadata['component'], 'SBOM_EVIDENCE_MALFORMED');
  const root = rootComponent === null ? null : {
    name: asBoundedString(rootComponent['name'], 'SBOM_EVIDENCE_MALFORMED', true),
    version: asBoundedString(rootComponent['version'], 'SBOM_EVIDENCE_MALFORMED'),
  };
  return { bomFormat: 'CycloneDX', specVersion, root, components };
}

/**
 * The hex SHA-512 a `sha512-` pin commits to. Parsing already refused anything malformed, so this
 * cannot be null for a well-formed SHA-512 pin; a well-formed sha256/sha384 pin yields null and the
 * caller reports the content binding as unproven rather than skipping the check.
 */
function integritySha512Hex(integrity: string): string | null {
  if (!integrity.startsWith('sha512-')) return null;
  const bytes = decodeBase64Strict(integrity.slice('sha512-'.length), 64);
  if (bytes === null || bytes.length !== 64) return null;
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Compare the locked set, the SBOM and an optional independently published set. Returns a sorted,
 * deduplicated list of fixed codes; an empty list means the two documents describe the same pinned
 * tree. This never contacts a registry, so it is a consistency proof, not a vulnerability verdict.
 */
export function compareDependencyEvidence(
  lock: LockedDependencySet, sbom: SbomDependencySet,
  published?: readonly { name: string; version: string }[],
): readonly DependencyIssueCode[] {
  const codes = new Set<DependencyIssueCode>();
  const lockedByPath = new Map(lock.dependencies.map((entry) => [entry.path, entry]));
  const sbomByPath = new Map<string, SbomComponent>();
  for (const component of sbom.components) {
    if (component.path === null) { codes.add('SBOM_COMPONENT_PATH_MISSING'); continue; }
    if (sbomByPath.has(component.path)) { codes.add('SBOM_COMPONENT_DUPLICATE'); continue; }
    sbomByPath.set(component.path, component);
    if (!lockedByPath.has(component.path)) codes.add('SBOM_COMPONENT_ABSENT_FROM_LOCKFILE');
  }
  for (const entry of lock.dependencies) {
    if (entry.integrity === null) codes.add('DEPENDENCY_NOT_INTEGRITY_PINNED');
    if (entry.resolved === null && !entry.link) codes.add('DEPENDENCY_RESOLUTION_MISSING');
    const component = sbomByPath.get(entry.path);
    if (component === undefined) { codes.add('LOCKED_DEPENDENCY_ABSENT_FROM_SBOM'); continue; }
    if (component.version !== entry.version || component.name !== entry.name) {
      codes.add('DEPENDENCY_VERSION_MISMATCH');
    }
    if (component.unsupportedHashAlgorithm) codes.add('DEPENDENCY_CONTENT_ALGORITHM_UNSUPPORTED');
    else if (component.contentSha512Hex === null) codes.add('DEPENDENCY_CONTENT_MISSING');
    else if (entry.integrity === null) {
      // No pin and no content hash to compare: the binding is already unproven by the pin code.
    } else if (integritySha512Hex(entry.integrity) === null) {
      // A supported but non-SHA-512 pin cannot be cross-checked against the SBOM's SHA-512, so the
      // content binding is reported as unproven instead of being skipped in silence.
      codes.add('DEPENDENCY_CONTENT_ALGORITHM_UNSUPPORTED');
    } else if (integritySha512Hex(entry.integrity) !== component.contentSha512Hex) {
      codes.add('DEPENDENCY_CONTENT_MISMATCH');
    }
  }
  if (sbom.root !== null && sbom.root.version !== lock.root.version) codes.add('LOCKFILE_ROOT_VERSION_MISMATCH');
  if (published !== undefined) {
    const locked = new Set(lock.dependencies.map((entry) => `${entry.name}\u0000${entry.version}`));
    const expected = new Set(published.map((entry) => `${entry.name}\u0000${entry.version}`));
    for (const key of locked) if (!expected.has(key)) codes.add('DEPENDENCY_NOT_IN_PUBLISHED_SET');
    for (const key of expected) if (!locked.has(key)) codes.add('DEPENDENCY_MISSING_FROM_PUBLISHED_SET');
  }
  return Object.freeze(DEPENDENCY_ISSUE_CODES.filter((code) => codes.has(code)));
}
