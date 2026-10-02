/**
 * #33 release integrity gate: strict promotion failure on missing, mismatched or critical evidence.
 *
 * The gate answers one question — "does the exact set of bytes offered for release match signed
 * evidence produced from those same bytes, and do those bytes still satisfy the release owner's
 * independent expectation?" — and it fails closed on every uncertainty.
 *
 * Trust model, stated once:
 * - TRUSTED INPUT, never read from the evidence: the signing keys, the expected release version and
 *   source commit, the artifact name, the release channel (tenant scope and destination profile), the
 *   required adapter conformance suites, the trusted scanner identities, the severity that blocks,
 *   the clock, the maximum evidence age, and the optional independent lockfile/dependency pins.
 * - UNTRUSTED INPUT: the evidence document and the subject bytes (artifact, lockfile, SBOM,
 *   conformance evidence, scanner evidence). They are parsed, bounded, digest-bound and signed; they
 *   never grant authority to themselves.
 * - The signature proves that a holder of a trusted key asserted these bindings. It does NOT prove the
 *   signer was honest, that the build was reproducible, that the bytes came from a reviewed commit or
 *   that a conformance run really happened. A recomputed digest binds bytes; it is not publisher
 *   provenance. Those are owner gates, listed in docs/contracts/release-integrity-contract.md.
 *
 * The gate has no network access, no signing ability, no write path, and no publish or promote step.
 */
import { createPublicKey, verify as edVerify } from 'node:crypto';
import { CanonicalJsonFailure, canonicalJson, parseCanonicalJson, sha256Hex } from './canonical-json.js';
import { decodeBase64Strict, isLowerHex } from './byte-encoding.js';
import {
  compareDependencyEvidence, readLockedDependencies, readSbomComponents, DependencyEvidenceFailure,
} from './dependency-evidence.js';
import type { LockedDependencySet, SbomDependencySet } from './dependency-evidence.js';
import { ADAPTER_CONFORMANCE_VERSION, CONFORMANCE_VIOLATIONS } from './adapter-conformance.js';

export const RELEASE_INTEGRITY_VERSION = 'hylja.release-integrity.v1' as const;
export const RELEASE_EVIDENCE_FORMAT = 'hylja-release-evidence/v1' as const;
export const RELEASE_EXPECTATION_FORMAT = 'hylja-release-expectation/v1' as const;
/** Severity vocabulary aligned with `npm audit --audit-level`; index order is the blocking order. */
export const SEVERITY_ORDER = Object.freeze(['info', 'low', 'moderate', 'high', 'critical'] as const);
export type Severity = (typeof SEVERITY_ORDER)[number];

export const MAX_EVIDENCE_BYTES = 256 * 1024;
export const MAX_ARTIFACT_BYTES = 512 << 20;
export const MAX_ATTESTATION_BYTES = 4 << 20;
export const MAX_ARTIFACT_NAME = 128;
export const MAX_ADAPTERS = 32;
export const MAX_FINDINGS = 10_000;
export const MAX_CASES = 64;
const MAX_CLOCK_MS = 30 * 24 * 60 * 60 * 1000;
const ARTIFACT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
/** RFC 8032 Ed25519 signatures are R||S, 64 octets. */
const SIGNATURE_BYTES = 64;
/** The widest Ed25519 public key encoding this gate accepts is a 44-octet SPKI DER blob. */
const MAX_PUBLIC_KEY_BYTES = 128;

/**
 * The complete denial vocabulary, defined once and sorted. `ReleaseDenialCode` is derived from this
 * list, so a code can never be reported without being published here, and the reported set is
 * deterministic. Nothing outside this file is part of the vocabulary.
 */
export const RELEASE_DENIAL_CODES = Object.freeze([
  'ARTIFACT_DIGEST_MISMATCH', 'ARTIFACT_EVIDENCE_MISSING', 'ARTIFACT_NAME_NOT_ALLOWED', 'ARTIFACT_SIZE_MISMATCH',
  'CHANNEL_PROFILE_MISMATCH', 'CHANNEL_SCOPE_MISMATCH', 'CHECK_UNAVAILABLE', 'CONFORMANCE_ADAPTER_MISSING',
  'CONFORMANCE_ADAPTER_UNKNOWN', 'CONFORMANCE_CASE_NOT_PASSING', 'CONFORMANCE_DIGEST_MISMATCH', 'CONFORMANCE_EVIDENCE_DUPLICATE',
  'CONFORMANCE_EVIDENCE_MALFORMED', 'CONFORMANCE_EVIDENCE_MISSING', 'CONFORMANCE_EVIDENCE_STALE', 'CONFORMANCE_FAILED',
  'CONFORMANCE_SCOPE_MISMATCH', 'CONFORMANCE_SUBJECT_MISMATCH', 'CONFORMANCE_SUITE_MISMATCH', 'CONFORMANCE_VERSION_MISMATCH',
  'CONFORMANCE_VIOLATION_REPORTED', 'DEPENDENCY_CONTENT_ALGORITHM_UNSUPPORTED', 'DEPENDENCY_CONTENT_MISMATCH', 'DEPENDENCY_CONTENT_MISSING',
  'DEPENDENCY_MISSING_FROM_PUBLISHED_SET', 'DEPENDENCY_NOT_INTEGRITY_PINNED', 'DEPENDENCY_NOT_IN_PUBLISHED_SET',
  'DEPENDENCY_RESOLUTION_MISSING', 'DEPENDENCY_VERSION_MISMATCH', 'EVIDENCE_EXPIRED', 'EVIDENCE_FUTURE_DATED',
  'EVIDENCE_MALFORMED', 'EVIDENCE_MISSING', 'EVIDENCE_NOT_CANONICAL', 'EVIDENCE_NOT_JSON',
  'EVIDENCE_NOT_UTF8', 'EVIDENCE_TOO_LARGE', 'EVIDENCE_TOO_OLD', 'EVIDENCE_UNSUPPORTED_FORMAT', 'EVIDENCE_WINDOW_INVALID',
  'EXPECTATION_INVALID', 'FINDING_BLOCKS_PROMOTION', 'FUNCTIONAL_TESTS_UNPROVEN', 'LOCKED_DEPENDENCY_ABSENT_FROM_SBOM',
  'LOCKFILE_DIGEST_MISMATCH', 'LOCKFILE_EVIDENCE_MALFORMED', 'LOCKFILE_EVIDENCE_MISSING', 'LOCKFILE_INTEGRITY_INVALID',
  'LOCKFILE_NOT_INDEPENDENTLY_PINNED', 'LOCKFILE_ROOT_VERSION_MISMATCH', 'PLANTED_EGRESS_UNPROVEN', 'RELEASE_VERSION_MISMATCH',
  'SBOM_COMPONENT_ABSENT_FROM_LOCKFILE', 'SBOM_COMPONENT_DUPLICATE', 'SBOM_COMPONENT_PATH_MISSING', 'SBOM_DIGEST_MISMATCH',
  'SBOM_EVIDENCE_MALFORMED', 'SBOM_EVIDENCE_MISSING', 'SCANNER_DIGEST_MISMATCH', 'SCANNER_EVIDENCE_MALFORMED',
  'SCANNER_EVIDENCE_MISSING', 'SCANNER_EVIDENCE_STALE', 'SCANNER_INCOMPLETE', 'SCANNER_NOT_TRUSTED',
  'SCANNER_SUBJECT_MISMATCH', 'SIGNATURE_INVALID', 'SIGNATURE_MALFORMED', 'SIGNING_KEY_UNKNOWN',
  'SOURCE_COMMIT_MISMATCH',
] as const);
export type ReleaseDenialCode = (typeof RELEASE_DENIAL_CODES)[number];

export interface ReleaseSubject {
  /** The exact bytes that would be published, read at the release boundary. */
  artifact: Uint8Array;
  lockfile: Uint8Array;
  sbom: Uint8Array;
  /** Canonical conformance evidence documents, one per required adapter. */
  conformance: readonly { adapterId: string; bytes: Uint8Array }[];
  scanner: Uint8Array;
}
export interface TrustedSigningKey { keyId: string; publicKeySpkiBase64: string }
export interface RequiredConformance { adapterId: string; suiteSha256: string }
export interface ReleaseExpectation {
  /** Required in the expectation *file* form; tolerated when absent for in-process callers. */
  format?: string;
  releaseVersion: string;
  commit: string;
  artifactName: string;
  channel: { scopeRef: string; profileId: string };
  signingKeys: readonly TrustedSigningKey[];
  requiredConformance: readonly RequiredConformance[];
  requiredScannerIds: readonly string[];
  blockAtSeverity: Severity;
  /** Trusted wall clock in epoch milliseconds. Never taken from the evidence. */
  now: number;
  maxAgeMs: number;
  expectedLockSha256?: string;
  expectedDependencies?: readonly { name: string; version: string }[];
}
export interface ReleaseVerification {
  status: 'RELEASE_EVIDENCE_VERIFIED' | 'RELEASE_PROMOTION_DENIED';
  /** Sorted, deduplicated fixed codes. Verified evidence is necessary, never sufficient, for release. */
  reasons: readonly ReleaseDenialCode[];
}

const verified: ReleaseVerification = Object.freeze({ status: 'RELEASE_EVIDENCE_VERIFIED', reasons: Object.freeze([]) });
function denied(codes: Iterable<ReleaseDenialCode>): ReleaseVerification {
  const unique = new Set(codes);
  return Object.freeze({
    status: 'RELEASE_PROMOTION_DENIED',
    reasons: Object.freeze(RELEASE_DENIAL_CODES.filter((code) => unique.has(code))),
  });
}

/* ---------- strict readers for untrusted JSON ---------- */

class EvidenceFailure extends Error {
  constructor(readonly code: ReleaseDenialCode) { super('release evidence is unusable'); this.name = 'EvidenceFailure'; }
}
function reject(code: ReleaseDenialCode): never { throw new EvidenceFailure(code); }
const CANONICAL_CODES: Readonly<Record<string, ReleaseDenialCode>> = Object.freeze({
  NOT_UTF8: 'EVIDENCE_NOT_UTF8', NOT_JSON: 'EVIDENCE_NOT_JSON', NOT_CANONICAL: 'EVIDENCE_NOT_CANONICAL',
  TOO_LARGE: 'EVIDENCE_TOO_LARGE', NOT_UNICODE: 'EVIDENCE_MALFORMED', STRING_TOO_LONG: 'EVIDENCE_MALFORMED',
  NOT_AN_INTEGER: 'EVIDENCE_MALFORMED', NOT_CANONICALIZABLE: 'EVIDENCE_MALFORMED', NOT_AN_OBJECT: 'EVIDENCE_MALFORMED',
  DEPTH_EXCEEDED: 'EVIDENCE_MALFORMED', MEMBER_EXCEEDED: 'EVIDENCE_MALFORMED',
});
function asObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) reject('EVIDENCE_MALFORMED');
  return value as Record<string, unknown>;
}
function asArray(value: unknown, max: number): unknown[] {
  if (!Array.isArray(value) || value.length > max) reject('EVIDENCE_MALFORMED');
  return value;
}
function asString(value: unknown, max = 256, pattern?: RegExp): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) reject('EVIDENCE_MALFORMED');
  if (pattern !== undefined && !pattern.test(value)) reject('EVIDENCE_MALFORMED');
  if (/[\u0000-\u001f\u007f]/.test(value)) reject('EVIDENCE_MALFORMED');
  return value;
}
function asInteger(value: unknown, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    reject('EVIDENCE_MALFORMED');
  }
  return value;
}
function asDigest(value: unknown): string {
  if (typeof value !== 'string' || !isLowerHex(value, 64)) reject('EVIDENCE_MALFORMED');
  return value;
}
function asBoolean(value: unknown): boolean {
  if (typeof value !== 'boolean') reject('EVIDENCE_MALFORMED');
  return value;
}
/** Exactly the listed members: an unknown or missing field is a structural rejection, not a default. */
function shape(value: unknown, names: readonly string[]): Record<string, unknown> {
  const record = asObject(value);
  const keys = Object.keys(record);
  if (keys.length !== names.length || keys.some((key) => !names.includes(key))) reject('EVIDENCE_MALFORMED');
  return record;
}

/* ---------- evidence payload ---------- */

interface EvidencePayload {
  format: string;
  issuedAt: number;
  expiresAt: number;
  release: { version: string; commit: string; scopeRef: string; profileId: string };
  artifact: { name: string; sha256: string; bytes: number };
  dependencies: { lockSha256: string; sbomSha256: string };
  adapters: { adapterId: string; evidenceSha256: string }[];
  scanner: { evidenceSha256: string };
}
function readPayload(document: Record<string, unknown>): EvidencePayload {
  const record = shape(document, ['format', 'issuedAt', 'expiresAt', 'release', 'artifact', 'dependencies',
    'adapters', 'scanner', 'signature']);
  if (record['format'] !== RELEASE_EVIDENCE_FORMAT) reject('EVIDENCE_UNSUPPORTED_FORMAT');
  const release = shape(record['release'], ['version', 'commit', 'scopeRef', 'profileId']);
  const artifact = shape(record['artifact'], ['name', 'sha256', 'bytes']);
  const dependencies = shape(record['dependencies'], ['lockSha256', 'sbomSha256']);
  const scanner = shape(record['scanner'], ['evidenceSha256']);
  const adapters = asArray(record['adapters'], MAX_ADAPTERS).map((item) => {
    const entry = shape(item, ['adapterId', 'evidenceSha256']);
    return { adapterId: asString(entry['adapterId'], 64, IDENTIFIER), evidenceSha256: asDigest(entry['evidenceSha256']) };
  });
  // Two claims for one adapter are ambiguous, not first-wins: refuse the document.
  if (new Set(adapters.map((entry) => entry.adapterId)).size !== adapters.length) reject('EVIDENCE_MALFORMED');
  return {
    format: RELEASE_EVIDENCE_FORMAT,
    issuedAt: asInteger(record['issuedAt'], 0, Number.MAX_SAFE_INTEGER),
    expiresAt: asInteger(record['expiresAt'], 0, Number.MAX_SAFE_INTEGER),
    release: {
      version: asString(release['version'], 128),
      commit: asString(release['commit'], 64, COMMIT),
      scopeRef: asString(release['scopeRef'], 64, IDENTIFIER),
      profileId: asString(release['profileId'], 64, IDENTIFIER),
    },
    artifact: {
      name: asString(artifact['name'], MAX_ARTIFACT_NAME),
      sha256: asDigest(artifact['sha256']),
      bytes: asInteger(artifact['bytes'], 0, MAX_ARTIFACT_BYTES),
    },
    dependencies: { lockSha256: asDigest(dependencies['lockSha256']), sbomSha256: asDigest(dependencies['sbomSha256']) },
    adapters, scanner: { evidenceSha256: asDigest(scanner['evidenceSha256']) },
  };
}

/* ---------- expectation ---------- */

/** Every structural problem in the trusted input is an expectation error, never an evidence verdict. */
function readExpectation(input: ReleaseExpectation): ReleaseExpectation {
  try { return readExpectationFields(input); }
  catch (error) {
    if (error instanceof EvidenceFailure) throw new EvidenceFailure('EXPECTATION_INVALID');
    throw error;
  }
}
function readExpectationFields(input: ReleaseExpectation): ReleaseExpectation {
  if (input === null || typeof input !== 'object') reject('EXPECTATION_INVALID');
  const channel = shape(input.channel, ['scopeRef', 'profileId']);
  const signingKeys = asArray(input.signingKeys, 16).map((item) => {
    const key = shape(item, ['keyId', 'publicKeySpkiBase64']);
    const keyId = asString(key['keyId'], 64, IDENTIFIER);
    const publicKeySpkiBase64 = asString(key['publicKeySpkiBase64'], 256, BASE64);
    // A trusted key that is not a usable Ed25519 public key is a configuration error, not a signature
    // failure: refuse it here so verification can never silently degrade to "no trusted key".
    const der = decodeBase64Strict(publicKeySpkiBase64, MAX_PUBLIC_KEY_BYTES);
    if (der === null) reject('EXPECTATION_INVALID');
    try {
      if (createPublicKey({ key: der, format: 'der', type: 'spki' }).asymmetricKeyType !== 'ed25519') {
        reject('EXPECTATION_INVALID');
      }
    } catch { reject('EXPECTATION_INVALID'); }
    return { keyId, publicKeySpkiBase64 };
  });
  if (input.format !== undefined && input.format !== RELEASE_EXPECTATION_FORMAT) reject('EXPECTATION_INVALID');
  if (signingKeys.length === 0 || new Set(signingKeys.map((key) => key.keyId)).size !== signingKeys.length) {
    reject('EXPECTATION_INVALID');
  }
  const requiredConformance = asArray(input.requiredConformance, MAX_ADAPTERS).map((item) => {
    const entry = shape(item, ['adapterId', 'suiteSha256']);
    return { adapterId: asString(entry['adapterId'], 64, IDENTIFIER), suiteSha256: asDigest(entry['suiteSha256']) };
  });
  if (requiredConformance.length === 0
      || new Set(requiredConformance.map((entry) => entry.adapterId)).size !== requiredConformance.length) {
    reject('EXPECTATION_INVALID');
  }
  const requiredScannerIds = asArray(input.requiredScannerIds, 16).map((entry) => asString(entry, 64, IDENTIFIER));
  if (requiredScannerIds.length === 0 || new Set(requiredScannerIds).size !== requiredScannerIds.length) {
    reject('EXPECTATION_INVALID');
  }
  if (!(SEVERITY_ORDER as readonly string[]).includes(input.blockAtSeverity)) reject('EXPECTATION_INVALID');
  if (!Number.isSafeInteger(input.now) || (input.now as number) < 0) reject('EXPECTATION_INVALID');
  if (!Number.isSafeInteger(input.maxAgeMs) || (input.maxAgeMs as number) <= 0
      || (input.maxAgeMs as number) > MAX_CLOCK_MS) reject('EXPECTATION_INVALID');
  const artifactName = asString(input.artifactName, MAX_ARTIFACT_NAME);
  if (!ARTIFACT_NAME.test(artifactName)) reject('EXPECTATION_INVALID');
  if (input.expectedLockSha256 !== undefined && !isLowerHex(input.expectedLockSha256, 64)) {
    reject('EXPECTATION_INVALID');
  }
  let expectedDependencies: { name: string; version: string }[] | undefined;
  if (input.expectedDependencies !== undefined) {
    const list = asArray(input.expectedDependencies, 20_000);
    expectedDependencies = list.map((item) => {
      const entry = shape(item, ['name', 'version']);
      return { name: asString(entry['name'], 256), version: asString(entry['version'], 128) };
    });
  }
  return {
    releaseVersion: asString(input.releaseVersion, 128),
    commit: asString(input.commit, 64, COMMIT),
    artifactName,
    channel: { scopeRef: asString(channel['scopeRef'], 64, IDENTIFIER), profileId: asString(channel['profileId'], 64, IDENTIFIER) },
    signingKeys, requiredConformance, requiredScannerIds,
    blockAtSeverity: input.blockAtSeverity, now: input.now as number, maxAgeMs: input.maxAgeMs as number,
    ...(input.expectedLockSha256 === undefined ? {} : { expectedLockSha256: input.expectedLockSha256 }),
    ...(expectedDependencies === undefined ? {} : { expectedDependencies }),
  };
}

/* ---------- attestation documents ---------- */

interface ConformanceAttestation {
  version: string; cases: readonly ConformanceAttestationCase[];
  adapterId: string; suiteSha256: string; scopeRef: string;
  subject: { artifactSha256: string; lockSha256: string; sbomSha256: string };
  completedAt: number; functionalTests: string; plantedEgress: string; overall: string;
}
/** An attestation shape defect is reported against the attestation, never against the envelope. */
function readConformanceAttestation(bytes: Uint8Array): ConformanceAttestation {
  try { return readConformanceAttestationFields(bytes); }
  catch (error) {
    if (error instanceof EvidenceFailure) throw new EvidenceFailure('CONFORMANCE_EVIDENCE_MALFORMED');
    throw error;
  }
}
interface ConformanceAttestationCase {
  id: string; kind: string; requirements: readonly string[]; violations: readonly string[]; outcome: string;
}
function readConformanceAttestationFields(bytes: Uint8Array): ConformanceAttestation {
  if (bytes.length === 0) reject('CONFORMANCE_EVIDENCE_MISSING');
  const document = shape(parseAttestation(bytes, 'CONFORMANCE_EVIDENCE_MALFORMED'),
    ['schemaVersion', 'version', 'suiteId', 'suiteSha256', 'adapterId', 'scopeRef', 'subject', 'completedAt',
      'cases', 'functionalTests', 'plantedEgress', 'overall']);
  if (document['schemaVersion'] !== 1) reject('CONFORMANCE_EVIDENCE_MALFORMED');
  asString(document['suiteId'], 64, IDENTIFIER);
  const subject = shape(document['subject'], ['artifactSha256', 'lockSha256', 'sbomSha256']);
  const cases: ConformanceAttestationCase[] = asArray(document['cases'], MAX_CASES).map((item) => {
    const entry = shape(item, ['id', 'kind', 'requirements', 'violations', 'outcome']);
    const requirements = asArray(entry['requirements'], MAX_CASES).map((value) => asString(value, 64));
    // An unrecognised invariant name is malformed evidence, never an acceptable unknown.
    const violations = asArray(entry['violations'], MAX_CASES).map((value) => {
      const name = asString(value, 64);
      if (!(CONFORMANCE_VIOLATIONS as readonly string[]).includes(name)) reject('CONFORMANCE_EVIDENCE_MALFORMED');
      return name;
    });
    return {
      id: asString(entry['id'], 64, IDENTIFIER), kind: asString(entry['kind'], 32),
      requirements, violations, outcome: asString(entry['outcome'], 8),
    };
  });
  if (cases.length === 0) reject('CONFORMANCE_EVIDENCE_MALFORMED');
  return {
    version: asString(document['version'], 64),
    cases,
    adapterId: asString(document['adapterId'], 64, IDENTIFIER),
    suiteSha256: asDigest(document['suiteSha256']),
    scopeRef: asString(document['scopeRef'], 64, IDENTIFIER),
    subject: {
      artifactSha256: asDigest(subject['artifactSha256']),
      lockSha256: asDigest(subject['lockSha256']),
      sbomSha256: asDigest(subject['sbomSha256']),
    },
    completedAt: asInteger(document['completedAt'], 0, Number.MAX_SAFE_INTEGER),
    functionalTests: asString(document['functionalTests'], 8),
    plantedEgress: asString(document['plantedEgress'], 8),
    overall: asString(document['overall'], 8),
  };
}
interface ScannerAttestation {
  scannerId: string; completed: boolean; completedAt: number;
  lockSha256: string; sbomSha256: string; findings: { severity: Severity }[];
}
function readScannerAttestation(bytes: Uint8Array): ScannerAttestation {
  try { return readScannerAttestationFields(bytes); }
  catch (error) {
    if (error instanceof EvidenceFailure) throw new EvidenceFailure('SCANNER_EVIDENCE_MALFORMED');
    throw error;
  }
}
function readScannerAttestationFields(bytes: Uint8Array): ScannerAttestation {
  if (bytes.length === 0) reject('SCANNER_EVIDENCE_MISSING');
  const document = shape(parseAttestation(bytes, 'SCANNER_EVIDENCE_MALFORMED'),
    ['schemaVersion', 'scannerId', 'completed', 'completedAt', 'lockSha256', 'sbomSha256', 'findings']);
  if (document['schemaVersion'] !== 1) reject('SCANNER_EVIDENCE_MALFORMED');
  const findings = asArray(document['findings'], MAX_FINDINGS).map((item) => {
    const entry = shape(item, ['severity', 'ruleId', 'packageName', 'version']);
    const severity = asString(entry['severity'], 16);
    if (!(SEVERITY_ORDER as readonly string[]).includes(severity)) reject('SCANNER_EVIDENCE_MALFORMED');
    asString(entry['ruleId'], 128);
    asString(entry['packageName'], 256);
    asString(entry['version'], 128);
    return { severity: severity as Severity };
  });
  return {
    scannerId: asString(document['scannerId'], 64, IDENTIFIER),
    completed: asBoolean(document['completed']),
    completedAt: asInteger(document['completedAt'], 0, Number.MAX_SAFE_INTEGER),
    lockSha256: asDigest(document['lockSha256']),
    sbomSha256: asDigest(document['sbomSha256']),
    findings,
  };
}
/** Attestation documents are canonical too, so an edited verdict changes their digest. */
function parseAttestation(bytes: Uint8Array, code: ReleaseDenialCode): Record<string, unknown> {
  try { return asObject(parseCanonicalJson(bytes, MAX_ATTESTATION_BYTES)); }
  catch (error) {
    if (error instanceof EvidenceFailure) throw error;
    if (error instanceof CanonicalJsonFailure) reject(code);
    throw error;
  }
}

/* ---------- signature ---------- */

function readSignature(document: Record<string, unknown>): { keyId: string; value: string } {
  // Anything wrong inside the signature member is a signature defect, never a payload verdict.
  const member: unknown = document['signature'];
  if (member === null || typeof member !== 'object' || Array.isArray(member)) reject('SIGNATURE_MALFORMED');
  const signature = member as Record<string, unknown>;
  const keys = Object.keys(signature);
  if (keys.length !== 3 || keys.some((key) => !['algorithm', 'keyId', 'value'].includes(key))) {
    reject('SIGNATURE_MALFORMED');
  }
  if (signature['algorithm'] !== 'ed25519') reject('SIGNATURE_MALFORMED');
  const keyId = signature['keyId'];
  const value = signature['value'];
  if (typeof keyId !== 'string' || !IDENTIFIER.test(keyId)) reject('SIGNATURE_MALFORMED');
  if (typeof value !== 'string' || value.length === 0 || value.length > 128 || !BASE64.test(value)) {
    reject('SIGNATURE_MALFORMED');
  }
  return { keyId, value };
}
function verifySignature(document: Record<string, unknown>, expectation: ReleaseExpectation): void {
  const { keyId, value } = readSignature(document);
  const signatureBytes = decodeBase64Strict(value, SIGNATURE_BYTES);
  if (signatureBytes === null || signatureBytes.length !== SIGNATURE_BYTES) reject('SIGNATURE_MALFORMED');
  const key = expectation.signingKeys.find((candidate) => candidate.keyId === keyId);
  // No fallback: an unknown key id is refused, never verified against "any" trusted key.
  if (key === undefined) reject('SIGNING_KEY_UNKNOWN');
  const publicKeyBytes = decodeBase64Strict(key.publicKeySpkiBase64, MAX_PUBLIC_KEY_BYTES);
  if (publicKeyBytes === null) reject('EXPECTATION_INVALID');
  let payloadBytes: Uint8Array;
  try {
    // The signature covers the canonical bytes of the payload without the signature member, so a
    // signature can never be moved to a different document that reuses the same field names.
    const { signature: ignored, ...payload } = document;
    void ignored;
    payloadBytes = canonicalJson(payload);
  } catch { reject('EVIDENCE_NOT_CANONICAL'); }
  let valid = false;
  try {
    const publicKey = createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' });
    if (publicKey.asymmetricKeyType !== 'ed25519') reject('EXPECTATION_INVALID');
    valid = edVerify(null, payloadBytes, publicKey, signatureBytes);
  } catch (error) {
    if (error instanceof EvidenceFailure) throw error;
    valid = false;
  }
  if (!valid) reject('SIGNATURE_INVALID');
}

/* ---------- the gate ---------- */

/**
 * Verify release evidence. Returns `RELEASE_EVIDENCE_VERIFIED` only when every check below held for
 * the exact bytes supplied; otherwise `RELEASE_PROMOTION_DENIED` with fixed codes. It never signs,
 * never writes, never contacts a network and never reports content, digests, paths or key ids.
 */
export function verifyReleaseEvidence(input: {
  evidence: Uint8Array; subject: ReleaseSubject; expectation: ReleaseExpectation;
}): ReleaseVerification {
  try {
    const expectation = readExpectation(input?.expectation as ReleaseExpectation);
    const evidence = input?.evidence;
    if (!(evidence instanceof Uint8Array) || evidence.length === 0) return denied(['EVIDENCE_MISSING']);
    if (evidence.length > MAX_EVIDENCE_BYTES) return denied(['EVIDENCE_TOO_LARGE']);
    let document: Record<string, unknown>;
    try { document = asObject(parseCanonicalJson(evidence, MAX_EVIDENCE_BYTES)); }
    catch (error) {
      if (error instanceof EvidenceFailure) return denied([error.code]);
      if (error instanceof CanonicalJsonFailure) return denied([CANONICAL_CODES[error.code] ?? 'EVIDENCE_MALFORMED']);
      return denied(['CHECK_UNAVAILABLE']);
    }
    // Structure first (a strict allowlist, no interpretation), then authentication, then semantics:
    // an unauthenticated payload never reaches a release decision.
    let payload: EvidencePayload;
    try { payload = readPayload(document); }
    catch (error) {
      if (error instanceof EvidenceFailure) return denied([error.code]);
      return denied(['EVIDENCE_MALFORMED']);
    }
    try { verifySignature(document, expectation); }
    catch (error) {
      if (error instanceof EvidenceFailure) return denied([error.code]);
      return denied(['CHECK_UNAVAILABLE']);
    }

    const codes: ReleaseDenialCode[] = [];
    const now = expectation.now;
    if (payload.expiresAt <= payload.issuedAt) codes.push('EVIDENCE_WINDOW_INVALID');
    if (payload.issuedAt > now) codes.push('EVIDENCE_FUTURE_DATED');
    if (payload.expiresAt <= now) codes.push('EVIDENCE_EXPIRED');
    if (now - payload.issuedAt > expectation.maxAgeMs) codes.push('EVIDENCE_TOO_OLD');
    if (payload.release.version !== expectation.releaseVersion) codes.push('RELEASE_VERSION_MISMATCH');
    if (payload.release.commit !== expectation.commit) codes.push('SOURCE_COMMIT_MISMATCH');
    if (payload.release.scopeRef !== expectation.channel.scopeRef) codes.push('CHANNEL_SCOPE_MISMATCH');
    if (payload.release.profileId !== expectation.channel.profileId) codes.push('CHANNEL_PROFILE_MISMATCH');
    if (!ARTIFACT_NAME.test(payload.artifact.name) || payload.artifact.name !== expectation.artifactName) {
      codes.push('ARTIFACT_NAME_NOT_ALLOWED');
    }

    const subject = input.subject;
    const artifact = subject?.artifact;
    if (!(artifact instanceof Uint8Array) || artifact.length === 0 || artifact.length > MAX_ARTIFACT_BYTES) {
      codes.push('ARTIFACT_EVIDENCE_MISSING');
    } else {
      // The digest binds the exact bytes offered now to the bytes that were signed and tested.
      if (sha256Hex(artifact) !== payload.artifact.sha256) codes.push('ARTIFACT_DIGEST_MISMATCH');
      if (artifact.length !== payload.artifact.bytes) codes.push('ARTIFACT_SIZE_MISMATCH');
    }
    const lockfile = subject?.lockfile;
    if (!(lockfile instanceof Uint8Array) || lockfile.length === 0) {
      codes.push('LOCKFILE_EVIDENCE_MISSING');
    } else if (sha256Hex(lockfile) !== payload.dependencies.lockSha256) {
      codes.push('LOCKFILE_DIGEST_MISMATCH');
    }
    const sbom = subject?.sbom;
    if (!(sbom instanceof Uint8Array) || sbom.length === 0) {
      codes.push('SBOM_EVIDENCE_MISSING');
    } else if (sha256Hex(sbom) !== payload.dependencies.sbomSha256) {
      codes.push('SBOM_DIGEST_MISMATCH');
    }
    const lockfilePresent = lockfile instanceof Uint8Array && lockfile.length > 0;
    const sbomPresent = sbom instanceof Uint8Array && sbom.length > 0;
    if (lockfilePresent && expectation.expectedLockSha256 !== undefined
        && sha256Hex(lockfile) !== expectation.expectedLockSha256) {
      codes.push('LOCKFILE_NOT_INDEPENDENTLY_PINNED');
    }
    if (lockfilePresent && sbomPresent) {
      // Each document is judged against its own reader, so a swapped pair is named, not guessed at.
      let locked: LockedDependencySet | null = null;
      let components: SbomDependencySet | null = null;
      try { locked = readLockedDependencies(lockfile); }
      catch (error) { codes.push(readerReason(error, 'LOCKFILE_EVIDENCE_MALFORMED')); }
      try { components = readSbomComponents(sbom); }
      catch (error) { codes.push(readerReason(error, 'SBOM_EVIDENCE_MALFORMED')); }
      if (locked !== null && components !== null) {
        for (const issue of compareDependencyEvidence(locked, components, expectation.expectedDependencies)) {
          codes.push(issue);
        }
      }
    }

    codes.push(...verifyConformance(payload, subject, expectation, now));
    codes.push(...verifyScanner(payload, subject, expectation, now));
    return codes.length === 0 ? verified : denied(codes);
  } catch (error) {
    if (error instanceof EvidenceFailure) return denied([error.code]);
    if (error instanceof CanonicalJsonFailure) return denied([CANONICAL_CODES[error.code] ?? 'EVIDENCE_MALFORMED']);
    return denied(['CHECK_UNAVAILABLE']);
  }
}

/** A reader's own fixed reason is forwarded unchanged; anything unexpected is unusable evidence. */
function readerReason(error: unknown, fallback: ReleaseDenialCode): ReleaseDenialCode {
  if (error instanceof DependencyEvidenceFailure) return error.reason;
  return fallback;
}
function verifyConformance(
  payload: EvidencePayload, subject: ReleaseSubject, expectation: ReleaseExpectation, now: number,
): ReleaseDenialCode[] {
  const codes: ReleaseDenialCode[] = [];
  const supplied = subject?.conformance;
  const entries = Array.isArray(supplied) ? supplied : [];
  const byAdapter = new Map<string, Uint8Array>();
  for (const entry of entries) {
    const adapterId = typeof entry?.adapterId === 'string' ? entry.adapterId : '';
    if (byAdapter.has(adapterId)) codes.push('CONFORMANCE_EVIDENCE_DUPLICATE');
    else if (entry?.bytes instanceof Uint8Array) byAdapter.set(adapterId, entry.bytes);
    else codes.push('CONFORMANCE_EVIDENCE_MISSING');
  }
  const claimed = new Set(payload.adapters.map((entry) => entry.adapterId));
  for (const adapterId of claimed) {
    if (!expectation.requiredConformance.some((entry) => entry.adapterId === adapterId)) {
      codes.push('CONFORMANCE_ADAPTER_UNKNOWN');
    }
  }
  for (const required of expectation.requiredConformance) {
    const claim = payload.adapters.find((entry) => entry.adapterId === required.adapterId);
    if (claim === undefined) { codes.push('CONFORMANCE_ADAPTER_MISSING'); continue; }
    const bytes = byAdapter.get(required.adapterId);
    if (bytes === undefined) { codes.push('CONFORMANCE_EVIDENCE_MISSING'); continue; }
    if (sha256Hex(bytes) !== claim.evidenceSha256) { codes.push('CONFORMANCE_DIGEST_MISMATCH'); continue; }
    let attestation: ConformanceAttestation;
    try { attestation = readConformanceAttestation(bytes); }
    catch (error) {
      codes.push(error instanceof EvidenceFailure ? error.code : 'CONFORMANCE_EVIDENCE_MALFORMED');
      continue;
    }
    if (attestation.adapterId !== required.adapterId) { codes.push('CONFORMANCE_SUBJECT_MISMATCH'); continue; }
    // The suite digest is pinned by the release owner, so a passing easier suite is not accepted.
    if (attestation.suiteSha256 !== required.suiteSha256) { codes.push('CONFORMANCE_SUITE_MISMATCH'); continue; }
    if (attestation.scopeRef !== expectation.channel.scopeRef) { codes.push('CONFORMANCE_SCOPE_MISMATCH'); continue; }
    if (attestation.subject.artifactSha256 !== payload.artifact.sha256
        || attestation.subject.lockSha256 !== payload.dependencies.lockSha256
        || attestation.subject.sbomSha256 !== payload.dependencies.sbomSha256) {
      codes.push('CONFORMANCE_SUBJECT_MISMATCH');
      continue;
    }
    if (attestation.completedAt > now || now - attestation.completedAt > expectation.maxAgeMs) {
      codes.push('CONFORMANCE_EVIDENCE_STALE');
      continue;
    }
    // A summary that contradicts its own cases is not a pass: the gate reads both.
    if (attestation.version !== ADAPTER_CONFORMANCE_VERSION) {
      codes.push('CONFORMANCE_VERSION_MISMATCH');
      continue;
    }
    if (attestation.cases.some((entry) => entry.outcome !== 'PASS')) codes.push('CONFORMANCE_CASE_NOT_PASSING');
    if (attestation.cases.some((entry) => entry.violations.length > 0)) codes.push('CONFORMANCE_VIOLATION_REPORTED');
    if (attestation.plantedEgress !== 'PASS') codes.push('PLANTED_EGRESS_UNPROVEN');
    if (attestation.functionalTests !== 'PASS') codes.push('FUNCTIONAL_TESTS_UNPROVEN');
    if (attestation.overall !== 'PASS') codes.push('CONFORMANCE_FAILED');
  }
  return codes;
}

function verifyScanner(
  payload: EvidencePayload, subject: ReleaseSubject, expectation: ReleaseExpectation, now: number,
): ReleaseDenialCode[] {
  const codes: ReleaseDenialCode[] = [];
  const raw = subject?.scanner;
  if (!(raw instanceof Uint8Array) || raw.length === 0) return ['SCANNER_EVIDENCE_MISSING'];
  if (sha256Hex(raw) !== payload.scanner.evidenceSha256) return ['SCANNER_DIGEST_MISMATCH'];
  let attestation: ScannerAttestation;
  try { attestation = readScannerAttestation(raw); }
  catch (error) { return [error instanceof EvidenceFailure ? error.code : 'SCANNER_EVIDENCE_MALFORMED']; }
  if (!expectation.requiredScannerIds.includes(attestation.scannerId)) codes.push('SCANNER_NOT_TRUSTED');
  if (!attestation.completed) codes.push('SCANNER_INCOMPLETE');
  if (attestation.lockSha256 !== payload.dependencies.lockSha256
      || attestation.sbomSha256 !== payload.dependencies.sbomSha256) {
    codes.push('SCANNER_SUBJECT_MISMATCH');
  }
  if (attestation.completedAt > now || now - attestation.completedAt > expectation.maxAgeMs) {
    codes.push('SCANNER_EVIDENCE_STALE');
  }
  const blockAt = SEVERITY_ORDER.indexOf(expectation.blockAtSeverity);
  if (attestation.findings.some((finding) => SEVERITY_ORDER.indexOf(finding.severity) >= blockAt)) {
    codes.push('FINDING_BLOCKS_PROMOTION');
  }
  return codes;
}
