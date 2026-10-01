import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  RELEASE_DENIAL_CODES, RELEASE_EVIDENCE_FORMAT, RELEASE_EXPECTATION_FORMAT, verifyReleaseEvidence,
} from '../dist/release-integrity.js';
import { CONFORMANCE_REQUIREMENTS, CONFORMANCE_VIOLATIONS } from '../dist/adapter-conformance.js';
import { DEPENDENCY_EVIDENCE_REASONS, DEPENDENCY_ISSUE_CODES } from '../dist/dependency-evidence.js';
import { main as runGateCli } from '../dist/release-gate-cli.js';
import { canonicalJson } from '../dist/canonical-json.js';
import {
  PLANTED_CLOAKABLE, SYNTHETIC_ADAPTER, SYNTHETIC_ARTIFACT, SYNTHETIC_ARTIFACT_NAME,
  SYNTHETIC_COMMIT, SYNTHETIC_DEPENDENCIES, SYNTHETIC_OTHER_ARTIFACT_NAME, SYNTHETIC_OTHER_KEY_ID,
  SYNTHETIC_OTHER_PROFILE, SYNTHETIC_OTHER_SCOPE, SYNTHETIC_PROFILE, SYNTHETIC_RELEASE_VERSION,
  SYNTHETIC_INTEGRITY, SYNTHETIC_KEY_ID as SYNTHETIC_SIGNER_KEY_ID, SYNTHETIC_SCOPE, bypassSyntheticAdapter,
  buildSyntheticReleaseBundle, createSyntheticSigner, encodingCloakAdapter,
  sha256Hex, syntheticConformanceEvidence, syntheticConformanceSuite, syntheticLockfile,
  syntheticLockfileBytes, syntheticSbom, syntheticSbomBytes,
} from '../scripts/synthetic-release-substrate.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const encode = (value) => new TextEncoder().encode(value);
const verify = (bundle) => verifyReleaseEvidence({
  evidence: bundle.evidence, subject: bundle.subject, expectation: bundle.expectation,
});
const denied = (bundle, code, note = '') => {
  const result = verify(bundle);
  assert.equal(result.status, 'RELEASE_PROMOTION_DENIED', `expected denial ${code}, got ${result.status}`);
  assert.ok(result.reasons.includes(code), `expected ${code} in ${JSON.stringify(result.reasons)} ${note}`);
  return result;
};
const verified = (bundle) => {
  const result = verify(bundle);
  assert.equal(result.status, 'RELEASE_EVIDENCE_VERIFIED', `expected verification, got ${JSON.stringify(result.reasons)}`);
  assert.deepEqual(result.reasons, []);
  return result;
};

test('a canonical signed evidence document over the exact subject bytes verifies', () => {
  const bundle = buildSyntheticReleaseBundle();
  // Positive control: the substrate evidence really is canonical, so the gate parses exact bytes.
  const reparsed = JSON.parse(Buffer.from(bundle.evidence).toString('utf8'));
  assert.deepEqual(Buffer.from(canonicalJson(reparsed)), Buffer.from(bundle.evidence));
  assert.equal(reparsed.format, RELEASE_EVIDENCE_FORMAT);
  verified(bundle);
});

test('a post-test change to the release artifact is denied even with a valid signature', () => {
  const bundle = buildSyntheticReleaseBundle();
  const substituted = new Uint8Array([...bundle.subject.artifact, 0x20, 0x0a]);
  const result = denied({ ...bundle, subject: { ...bundle.subject, artifact: substituted } }, 'ARTIFACT_DIGEST_MISMATCH');
  assert.ok(result.reasons.includes('ARTIFACT_SIZE_MISMATCH'));
  denied({ ...bundle, subject: { ...bundle.subject, artifact: SYNTHETIC_ARTIFACT.subarray(1) } }, 'ARTIFACT_SIZE_MISMATCH');
  // An empty artifact is an absent subject, not a verified empty release.
  denied({ ...bundle, subject: { ...bundle.subject, artifact: new Uint8Array(0) } }, 'ARTIFACT_EVIDENCE_MISSING');
});

test('a post-test change to the lockfile or SBOM is denied', () => {
  const bundle = buildSyntheticReleaseBundle();
  const extended = syntheticLockfile();
  extended.packages['node_modules/synthetic-delta-extra'] = {
    version: '9.9.9',
    resolved: 'https://registry.synthetic.invalid/synthetic-delta-extra/-/synthetic-delta-extra-9.9.9.tgz',
    integrity: 'sha512-c3ludGhldGljRGVsdGFFeHRyYWluZWdpc3RlZDEyMzQ1Njc4OWFiY2RlZmdoaWprMG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OWFiY2RlZg==',
  };
  denied({ ...bundle, subject: { ...bundle.subject, lockfile: syntheticLockfileBytes(extended) } },
    'LOCKFILE_DIGEST_MISMATCH');
  const trimmed = syntheticSbom();
  trimmed.components.pop();
  denied({ ...bundle, subject: { ...bundle.subject, sbom: syntheticSbomBytes(trimmed) } }, 'SBOM_DIGEST_MISMATCH');
});

test('a post-test change to the conformance or scanner evidence is denied', () => {
  // The evidence bound into the signature is a failing run; rewriting the verdict to a pass changes
  // the bytes, so the digest binding catches it even though the rewritten document is well formed.
  const bundle = buildSyntheticReleaseBundle({
    adapter: bypassSyntheticAdapter(),
    findings: [{ severity: 'low', ruleId: 'synthetic-rule-low', packageName: 'synthetic-alpha-parser', version: '1.2.3' }],
  });
  assert.equal(bundle.conformanceDocument.overall, 'FAIL');
  assert.equal(bundle.scannerDocument.findings.length, 1);
  const forgedPass = { ...bundle.conformanceDocument, plantedEgress: 'PASS', overall: 'PASS' };
  assert.notDeepEqual(Buffer.from(canonicalJson(forgedPass)), Buffer.from(bundle.subject.conformance[0].bytes));
  denied({
    ...bundle,
    subject: { ...bundle.subject, conformance: [{ adapterId: SYNTHETIC_ADAPTER, bytes: canonicalJson(forgedPass) }] },
  }, 'CONFORMANCE_DIGEST_MISMATCH');
  const clearedScan = { ...bundle.scannerDocument, findings: [] };
  denied({ ...bundle, subject: { ...bundle.subject, scanner: canonicalJson(clearedScan) } }, 'SCANNER_DIGEST_MISMATCH');
});

test('a tailored SBOM that omits a locked dependency is denied', () => {
  const trimmed = syntheticSbom();
  trimmed.components.splice(1, 1);
  denied(buildSyntheticReleaseBundle({ sbom: trimmed }), 'LOCKED_DEPENDENCY_ABSENT_FROM_SBOM');
});

test('an SBOM component that is absent from the lockfile is denied', () => {
  const lock = syntheticLockfile();
  const sbomDocument = syntheticSbom(lock);
  sbomDocument.components.push({
    'bom-ref': 'synthetic-omega-injected@1.0.0', type: 'library', name: 'synthetic-omega-injected',
    version: '1.0.0', purl: 'pkg:npm/synthetic-omega-injected@1.0.0',
    properties: [{ name: 'cdx:npm:package:path', value: 'node_modules/synthetic-omega-injected' }],
    hashes: [],
  });
  denied(buildSyntheticReleaseBundle({ lockfile: syntheticLockfileBytes(lock), sbom: sbomDocument }),
    'SBOM_COMPONENT_ABSENT_FROM_LOCKFILE');
});

test('a component whose SBOM version or content hash differs from the locked entry is denied', () => {
  const lock = syntheticLockfile();
  const wrongVersion = syntheticSbom(lock);
  wrongVersion.components[0].version = '9.9.9';
  wrongVersion.components[0].purl = `pkg:npm/${wrongVersion.components[0].name}@9.9.9`;
  denied(buildSyntheticReleaseBundle({ sbom: wrongVersion }), 'DEPENDENCY_VERSION_MISMATCH');

  const wrongHash = syntheticSbom(lock);
  wrongHash.components[0].hashes[0].content = 'a'.repeat(128);
  denied(buildSyntheticReleaseBundle({ sbom: wrongHash }), 'DEPENDENCY_CONTENT_MISMATCH');
});

test('a lockfile entry without an integrity pin or resolution is denied', () => {
  const unpinned = syntheticLockfile();
  delete unpinned.packages['node_modules/synthetic-beta-normalizer'].integrity;
  denied(buildSyntheticReleaseBundle({ lock: unpinned }), 'DEPENDENCY_NOT_INTEGRITY_PINNED');

  const unresolved = syntheticLockfile();
  delete unresolved.packages['node_modules/synthetic-beta-normalizer'].resolved;
  denied(buildSyntheticReleaseBundle({ lock: unresolved }), 'DEPENDENCY_RESOLUTION_MISSING');
});

test('a dependency outside the independently published set is denied', () => {
  const lock = syntheticLockfile();
  lock.packages['node_modules/synthetic-epsilon-unreviewed'] = {
    version: '3.1.4',
    resolved: 'https://registry.synthetic.invalid/synthetic-epsilon-unreviewed/-/synthetic-epsilon-unreviewed-3.1.4.tgz',
    integrity: SYNTHETIC_INTEGRITY['synthetic-epsilon-unreviewed'],
  };
  const bundle = buildSyntheticReleaseBundle({
    lock,
    sbom: syntheticSbom(lock),
    expectedDependencies: SYNTHETIC_DEPENDENCIES.map(({ name, version }) => ({ name, version })),
  });
  denied(bundle, 'DEPENDENCY_NOT_IN_PUBLISHED_SET');
  // A dependency that disappears without being removed from the published set is also refused.
  const removed = syntheticLockfile();
  delete removed.packages['node_modules/synthetic-gamma-sink'];
  denied(buildSyntheticReleaseBundle({
    lock: removed,
    expectedDependencies: SYNTHETIC_DEPENDENCIES.map(({ name, version }) => ({ name, version })),
  }), 'DEPENDENCY_MISSING_FROM_PUBLISHED_SET');
});

test('an independently pinned lockfile digest that does not match is denied', () => {
  denied(buildSyntheticReleaseBundle({ expectedLockSha256: sha256Hex(encode('other-lockfile-bytes')) }),
    'LOCKFILE_NOT_INDEPENDENTLY_PINNED');
  verified(buildSyntheticReleaseBundle({ expectedLockSha256: sha256Hex(syntheticLockfileBytes()) }));
});

test('a signature from a different key is denied and an untrusted key id is never consulted', () => {
  const other = createSyntheticSigner(SYNTHETIC_OTHER_KEY_ID);
  const bundle = buildSyntheticReleaseBundle();
  // Same claimed keyId, different private key: the trusted public key must reject the signature.
  denied({ ...bundle, evidence: other.sign(bundle.payload, { claimedKeyId: SYNTHETIC_SIGNER_KEY_ID }) },
    'SIGNATURE_INVALID');
  // A single flipped signature bit from the right key is rejected too.
  denied({ ...bundle, evidence: bundle.signer.sign(bundle.payload, { corrupt: true }) }, 'SIGNATURE_INVALID');
  // A document signed by an untrusted key is refused before any key is consulted.
  denied({ ...bundle, evidence: other.sign(bundle.payload) }, 'SIGNING_KEY_UNKNOWN');
  // A trusted set that does not contain the claimed key id must not fall back to any other key.
  denied({
    ...bundle,
    expectation: { ...bundle.expectation, signingKeys: [{ keyId: SYNTHETIC_OTHER_KEY_ID, publicKeySpkiBase64: other.publicKeySpkiBase64 }] },
  }, 'SIGNING_KEY_UNKNOWN');
  // A signed document from another channel, presented with a channel that trusts its key, still fails.
  const foreign = buildSyntheticReleaseBundle({ scopeRef: SYNTHETIC_OTHER_SCOPE });
  denied({
    ...foreign,
    expectation: { ...foreign.expectation, channel: { scopeRef: SYNTHETIC_SCOPE, profileId: SYNTHETIC_PROFILE } },
  }, 'CHANNEL_SCOPE_MISMATCH');
});

test('a mutated signed payload and a malformed signature encoding are denied', () => {
  const bundle = buildSyntheticReleaseBundle();
  const parsed = JSON.parse(Buffer.from(bundle.evidence).toString('utf8'));
  const mutated = buildSyntheticReleaseBundle({ evidence: canonicalJson({ ...parsed, release: { ...parsed.release, version: '9.9.9-synthetic' } }) });
  denied(mutated, 'SIGNATURE_INVALID');

  for (const signature of [
    { ...parsed.signature, value: 'not base64!!' },
    { ...parsed.signature, value: Buffer.from([1, 2, 3]).toString('base64') },
    { ...parsed.signature, value: `${parsed.signature.value}=` },
    { ...parsed.signature, algorithm: 'rsa-pss' },
    { ...parsed.signature, value: '' },
  ]) {
    denied(buildSyntheticReleaseBundle({ evidence: canonicalJson({ ...parsed, signature }) }), 'SIGNATURE_MALFORMED');
  }
});

test('evidence for another tenant scope or destination profile cannot promote this channel', () => {
  denied(buildSyntheticReleaseBundle({ scopeRef: SYNTHETIC_OTHER_SCOPE }), 'CHANNEL_SCOPE_MISMATCH');
  denied(buildSyntheticReleaseBundle({ profileId: SYNTHETIC_OTHER_PROFILE }), 'CHANNEL_PROFILE_MISMATCH');
});

test('the independently expected release version and source commit must match', () => {
  const bundle = buildSyntheticReleaseBundle();
  denied({ ...bundle, expectation: { ...bundle.expectation, releaseVersion: '9.9.9-synthetic' } },
    'RELEASE_VERSION_MISMATCH');
  denied({ ...bundle, expectation: { ...bundle.expectation, commit: '0'.repeat(40) } }, 'SOURCE_COMMIT_MISMATCH');
  verified({
    ...bundle,
    expectation: { ...bundle.expectation, releaseVersion: SYNTHETIC_RELEASE_VERSION, commit: SYNTHETIC_COMMIT },
  });
});

test('stale, expired, future-dated and inverted evidence windows are denied', () => {
  const now = 1_700_000_000_000;
  denied(buildSyntheticReleaseBundle({ now, issuedAt: now - 7_200_000, expiresAt: now + 3_600_000 }), 'EVIDENCE_TOO_OLD');
  denied(buildSyntheticReleaseBundle({ now, issuedAt: now - 7_200_000, expiresAt: now - 3_600_000 }), 'EVIDENCE_EXPIRED');
  denied(buildSyntheticReleaseBundle({ now, issuedAt: now + 1_000, expiresAt: now + 7_200_000 }), 'EVIDENCE_FUTURE_DATED');
  denied(buildSyntheticReleaseBundle({ now, issuedAt: now - 1_000, expiresAt: now - 10_000 }), 'EVIDENCE_WINDOW_INVALID');
});

test('stale conformance or scanner evidence is denied at the release boundary', () => {
  const now = 1_700_000_000_000;
  const base = buildSyntheticReleaseBundle({ now });
  const subject = {
    artifactSha256: base.payload.artifact.sha256,
    lockSha256: base.payload.dependencies.lockSha256,
    sbomSha256: base.payload.dependencies.sbomSha256,
  };
  const staleConformance = syntheticConformanceEvidence(subject, { completedAt: now - 86_400_000 });
  denied(buildSyntheticReleaseBundle({
    now,
    conformance: staleConformance,
    requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: staleConformance.suiteSha256 }],
  }), 'CONFORMANCE_EVIDENCE_STALE');
  denied(buildSyntheticReleaseBundle({ now, scannerCompletedAt: now - 86_400_000 }), 'SCANNER_EVIDENCE_STALE');
  const futureScan = buildSyntheticReleaseBundle({ now, scannerCompletedAt: now + 60_000 });
  denied(futureScan, 'SCANNER_EVIDENCE_STALE');
});

test('B1: an encoded planted original cannot be promoted, and B4: a malformed pin denies', () => {
  // The harness is the detector: an adapter that "cloaks" by base64/hex instead of substituting
  // produces failing evidence, so the signed bundle is refused.
  const bundle = buildSyntheticReleaseBundle({ adapter: encodingCloakAdapter() });
  assert.equal(bundle.conformanceDocument.plantedEgress, 'FAIL');
  assert.equal(bundle.conformanceDocument.overall, 'FAIL');
  denied(bundle, 'PLANTED_EGRESS_UNPROVEN');
  denied(bundle, 'CONFORMANCE_FAILED');

  // A malformed integrity pin in the locked tree is unusable evidence, never a clean comparison.
  const malformed = buildSyntheticReleaseBundle();
  const relocked = syntheticLockfile();
  relocked.packages['node_modules/synthetic-alpha-parser'].integrity = 'sha512-!!!not-base64!!!';
  const relockedBundle = buildSyntheticReleaseBundle({ lock: relocked, sbom: syntheticSbom(relocked) });
  denied(relockedBundle, 'LOCKFILE_INTEGRITY_INVALID', 'a malformed pin is named, not lumped in');
  // A structurally broken lockfile is still reported as unusable evidence.
  denied({ ...malformed, subject: { ...malformed.subject, lockfile: encode('{"lockfileVersion":3}') } },
    'LOCKFILE_EVIDENCE_MALFORMED');

  // A supported but non-SHA-512 pin leaves the SBOM content binding unproven.
  const sha256Lock = syntheticLockfile();
  sha256Lock.packages['node_modules/synthetic-alpha-parser'].integrity =
    `sha256-${Buffer.alloc(32, 0x42).toString('base64')}`;
  const sha256Bundle = buildSyntheticReleaseBundle({ lock: sha256Lock, sbom: syntheticSbom(sha256Lock) });
  denied(sha256Bundle, 'DEPENDENCY_CONTENT_ALGORITHM_UNSUPPORTED');
});

test('N1: a conformance attestation that contradicts itself is refused', () => {
  const bundle = buildSyntheticReleaseBundle();
  const base = bundle.conformanceDocument;
  const pinned = [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: base.suiteSha256 }];
  const withCases = (cases, overrides = {}) => {
    const document = { ...base, ...overrides, cases };
    return buildSyntheticReleaseBundle({ conformance: document, requiredConformance: pinned });
  };
  const passingCase = base.cases[0];
  // Every case failed, yet the summary claims a pass: the gate has read the per-case outcome and
  // must not ignore it.
  const failing = { ...passingCase, outcome: 'FAIL', violations: ['PLANTED_ORIGINAL_RELEASED'] };
  denied(withCases(base.cases.map(() => failing)), 'CONFORMANCE_CASE_NOT_PASSING');
  denied(withCases(base.cases.map(() => failing)), 'CONFORMANCE_VIOLATION_REPORTED');
  // A summary that also reports the failure is denied for both the summary and the cases.
  const honest = { ...base, cases: [failing], overall: 'FAIL', plantedEgress: 'FAIL' };
  denied(buildSyntheticReleaseBundle({ conformance: honest, requiredConformance: pinned }), 'CONFORMANCE_FAILED');
  denied(buildSyntheticReleaseBundle({ conformance: honest, requiredConformance: pinned }), 'PLANTED_EGRESS_UNPROVEN');
  // An unknown violation code is malformed evidence, not an unknown-but-acceptable value.
  denied(withCases([{ ...passingCase, violations: ['SOMETHING_ELSE'] }]), 'CONFORMANCE_EVIDENCE_MALFORMED');
  // An attestation from another harness version is not this gate's evidence.
  denied(withCases(base.cases, { version: 'hylja.adapter-conformance.v0' }), 'CONFORMANCE_VERSION_MISMATCH');
  // A case whose requirements are all met but whose outcome is FAIL is still read.
  denied(withCases([{ ...passingCase, outcome: 'FAIL' }]), 'CONFORMANCE_CASE_NOT_PASSING');
  // Control: the untouched attestation still verifies.
  verified(bundle);
});

test('a passing ordinary functional test is not planted-egress conformance', () => {
  const bundle = buildSyntheticReleaseBundle({ adapter: bypassSyntheticAdapter() });
  // The same adapter double passes the ordinary functional requirement ...
  assert.equal(bundle.conformanceDocument.functionalTests, 'PASS');
  assert.equal(bundle.conformanceDocument.plantedEgress, 'FAIL');
  assert.equal(bundle.conformanceDocument.overall, 'FAIL');
  // ... and the release gate refuses to promote it.
  denied(bundle, 'PLANTED_EGRESS_UNPROVEN');
  denied(bundle, 'CONFORMANCE_FAILED');
  // The compliant double over the identical suite and subject passes every case.
  const good = buildSyntheticReleaseBundle();
  assert.equal(good.conformanceDocument.functionalTests, 'PASS');
  assert.equal(good.conformanceDocument.overall, 'PASS');
  verified(good);
});

test('conformance evidence for another channel, subject or suite cannot promote this release', () => {
  const base = buildSyntheticReleaseBundle();
  const subject = {
    artifactSha256: base.payload.artifact.sha256,
    lockSha256: base.payload.dependencies.lockSha256,
    sbomSha256: base.payload.dependencies.sbomSha256,
  };
  const foreign = syntheticConformanceEvidence(subject, { scopeRef: SYNTHETIC_OTHER_SCOPE });
  denied(buildSyntheticReleaseBundle({
    conformance: foreign,
    requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: foreign.suiteSha256 }],
  }), 'CONFORMANCE_SCOPE_MISMATCH');

  const otherSubject = syntheticConformanceEvidence({ ...subject, artifactSha256: sha256Hex(encode('a different artifact')) });
  denied(buildSyntheticReleaseBundle({
    conformance: otherSubject,
    requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: otherSubject.suiteSha256 }],
  }), 'CONFORMANCE_SUBJECT_MISMATCH');

  // A weaker suite is refused even when it passes: the suite digest is pinned independently.
  const weaker = syntheticConformanceSuite();
  weaker.cases = weaker.cases.filter((entry) => entry.kind === 'FUNCTIONAL' || entry.kind === 'PLANTED_EGRESS');
  const weakerEvidence = syntheticConformanceEvidence(subject, { suite: weaker });
  assert.equal(weakerEvidence.overall, 'PASS', 'the weaker suite really does pass on its own terms');
  assert.notEqual(weakerEvidence.suiteSha256, base.conformanceDocument.suiteSha256);
  denied(buildSyntheticReleaseBundle({
    conformance: weakerEvidence,
    requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: base.conformanceDocument.suiteSha256 }],
  }), 'CONFORMANCE_SUITE_MISMATCH');
});

test('missing, unknown, duplicate or non-passing conformance evidence is denied', () => {
  const bundle = buildSyntheticReleaseBundle();
  const bytes = bundle.conformanceDocument;
  denied({ ...bundle, subject: { ...bundle.subject, conformance: [] } }, 'CONFORMANCE_EVIDENCE_MISSING');
  denied(buildSyntheticReleaseBundle({
    adapters: [{ adapterId: 'synthetic-adapter-unknown', evidenceSha256: sha256Hex(canonicalJson(bytes)) }],
    requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: bytes.suiteSha256 }],
  }), 'CONFORMANCE_ADAPTER_UNKNOWN');
  denied(buildSyntheticReleaseBundle({
    adapters: [],
    requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: bytes.suiteSha256 }],
  }), 'CONFORMANCE_ADAPTER_MISSING');
  denied({
    ...bundle,
    subject: {
      ...bundle.subject,
      conformance: [
        { adapterId: SYNTHETIC_ADAPTER, bytes: canonicalJson(bytes) },
        { adapterId: SYNTHETIC_ADAPTER, bytes: canonicalJson(bytes) },
      ],
    },
  }, 'CONFORMANCE_EVIDENCE_DUPLICATE');
  const notPassing = { ...bytes, overall: 'FAIL', plantedEgress: 'FAIL' };
  denied(buildSyntheticReleaseBundle({
    conformance: notPassing,
    requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: notPassing.suiteSha256 }],
  }), 'CONFORMANCE_FAILED');
  const noPlantedCase = { ...bytes, plantedEgress: 'NOT_RUN' };
  denied(buildSyntheticReleaseBundle({
    conformance: noPlantedCase,
    requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: noPlantedCase.suiteSha256 }],
  }), 'PLANTED_EGRESS_UNPROVEN');
});

test('absent, untrusted, incomplete or off-subject scanner evidence is denied', () => {
  const bundle = buildSyntheticReleaseBundle();
  denied({ ...bundle, subject: { ...bundle.subject, scanner: new Uint8Array(0) } }, 'SCANNER_EVIDENCE_MISSING');
  denied(buildSyntheticReleaseBundle({ scanner: { ...bundle.scannerDocument, scannerId: 'synthetic-scanner-untrusted' } }),
    'SCANNER_NOT_TRUSTED');
  denied(buildSyntheticReleaseBundle({ scanner: { ...bundle.scannerDocument, completed: false } }), 'SCANNER_INCOMPLETE');
  denied(buildSyntheticReleaseBundle({
    scanner: { ...bundle.scannerDocument, lockSha256: sha256Hex(encode('other lockfile')) },
  }), 'SCANNER_SUBJECT_MISMATCH');
});

test('a finding at or above the policy severity blocks promotion', () => {
  const finding = { severity: 'critical', ruleId: 'synthetic-rule-1', packageName: 'synthetic-alpha-parser', version: '1.2.3' };
  verified(buildSyntheticReleaseBundle());
  denied(buildSyntheticReleaseBundle({ findings: [finding] }), 'FINDING_BLOCKS_PROMOTION');
  const moderate = { ...finding, severity: 'moderate' };
  verified(buildSyntheticReleaseBundle({ findings: [moderate] }));
  denied(buildSyntheticReleaseBundle({ findings: [moderate], blockAtSeverity: 'moderate' }), 'FINDING_BLOCKS_PROMOTION');
  // An unrecognised severity is never treated as harmless.
  denied(buildSyntheticReleaseBundle({ findings: [{ ...finding, severity: 'catastrophic' }] }), 'SCANNER_EVIDENCE_MALFORMED');
  denied(buildSyntheticReleaseBundle({ findings: [{ ...finding, severity: 'critical' }], blockAtSeverity: 'info' }),
    'FINDING_BLOCKS_PROMOTION');
});

test('malformed, non-canonical and out-of-bounds untrusted evidence is denied without echoing it', () => {
  const bundle = buildSyntheticReleaseBundle();
  const canonical = Buffer.from(bundle.evidence).toString('utf8');
  const malformed = [
    Buffer.from(bundle.evidence).subarray(0, 40),
    Buffer.from(`${canonical} `),
    Buffer.from(canonical.replace('"issuedAt"', '"IssuedAt"')),
    Buffer.from('[]'),
    Buffer.from('null'),
    Buffer.from(`{"format":"${RELEASE_EVIDENCE_FORMAT}"}`),
    Buffer.from([0x7b, 0xff, 0xfe, 0x7d]),
    Buffer.concat([Buffer.from(canonical), Buffer.alloc(4 << 20, 0x20)]),
  ];
  for (const evidence of malformed) {
    const result = verifyReleaseEvidence({ evidence, subject: bundle.subject, expectation: bundle.expectation });
    assert.equal(result.status, 'RELEASE_PROMOTION_DENIED');
    assert.ok(result.reasons.length > 0);
    for (const reason of result.reasons) assert.ok(RELEASE_DENIAL_CODES.includes(reason), reason);
  }
  // A duplicate JSON key cannot survive a canonical round trip, even where the duplicate value is
  // the one that would be used last.
  const duplicated = Buffer.from(canonical.replace('"adapters":', '"adapters":"shadowed","adapters":'), 'utf8');
  assert.notEqual(duplicated.toString('utf8'), canonical);
  denied(buildSyntheticReleaseBundle({ evidence: duplicated }), 'EVIDENCE_NOT_CANONICAL');
});

test('unexpected evidence fields, non-integer numbers and unlisted names are denied', () => {
  const bundle = buildSyntheticReleaseBundle();
  const parsed = JSON.parse(Buffer.from(bundle.evidence).toString('utf8'));
  denied(buildSyntheticReleaseBundle({ evidence: canonicalJson({ ...parsed, extra: 'synthetic-extra-claim' }) }),
    'EVIDENCE_MALFORMED');
  // A non-integer timestamp is not canonical JSON, and a string where an integer belongs is a
  // structural rejection once the bytes are canonical.
  denied(buildSyntheticReleaseBundle({ evidence: encode(JSON.stringify({ ...parsed, issuedAt: 1.5 })) }),
    'EVIDENCE_MALFORMED');
  denied(buildSyntheticReleaseBundle({ evidence: encode(JSON.stringify({ ...parsed, artifact: { ...parsed.artifact, bytes: '4096' } })) }),
    'EVIDENCE_MALFORMED');
  // An exponent spelling of an integer value is canonical-equivalent, so only the signature fails.
  denied(buildSyntheticReleaseBundle({ evidence: encode(JSON.stringify({ ...parsed, issuedAt: 1.7e12 })) }),
    'SIGNATURE_INVALID');
  denied(buildSyntheticReleaseBundle({ artifactName: SYNTHETIC_OTHER_ARTIFACT_NAME }), 'ARTIFACT_NAME_NOT_ALLOWED');
  denied(buildSyntheticReleaseBundle({ artifactName: '../synthetic-escape.tgz' }), 'ARTIFACT_NAME_NOT_ALLOWED');
  denied(buildSyntheticReleaseBundle({ evidence: encode(JSON.stringify({ ...parsed, format: 'other-evidence/v9' })) }),
    'EVIDENCE_UNSUPPORTED_FORMAT');
});

test('an invalid trusted expectation denies instead of passing', () => {
  const bundle = buildSyntheticReleaseBundle();
  const other = createSyntheticSigner(SYNTHETIC_OTHER_KEY_ID);
  for (const expectation of [
    { ...bundle.expectation, format: RELEASE_EXPECTATION_FORMAT, releaseVersion: '' },
    { ...bundle.expectation, commit: 'not-a-commit' },
    { ...bundle.expectation, now: Number.NaN },
    { ...bundle.expectation, maxAgeMs: 0 },
    { ...bundle.expectation, blockAtSeverity: 'severe' },
    { ...bundle.expectation, signingKeys: [] },
    { ...bundle.expectation, signingKeys: [{ keyId: SYNTHETIC_OTHER_KEY_ID, publicKeySpkiBase64: 'AAAA' }] },
    { ...bundle.expectation, requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: 'nope' }] },
    { ...bundle.expectation, expectedLockSha256: 'not-a-digest' },
    { ...bundle.expectation, channel: { scopeRef: '', profileId: SYNTHETIC_PROFILE } },
  ]) {
    const result = verifyReleaseEvidence({ evidence: bundle.evidence, subject: bundle.subject, expectation });
    assert.equal(result.status, 'RELEASE_PROMOTION_DENIED', JSON.stringify(expectation));
    assert.ok(result.reasons.includes('EXPECTATION_INVALID'), JSON.stringify(result.reasons));
  }
  void other;
});

test('a missing subject input is denied with its own code', () => {
  const bundle = buildSyntheticReleaseBundle();
  denied({ ...bundle, subject: { ...bundle.subject, artifact: undefined } }, 'ARTIFACT_EVIDENCE_MISSING');
  denied({ ...bundle, subject: { ...bundle.subject, lockfile: undefined } }, 'LOCKFILE_EVIDENCE_MISSING');
  denied({ ...bundle, subject: { ...bundle.subject, sbom: undefined } }, 'SBOM_EVIDENCE_MISSING');
  denied({ ...bundle, subject: { ...bundle.subject, scanner: undefined } }, 'SCANNER_EVIDENCE_MISSING');
  denied({ ...bundle, subject: { ...bundle.subject, conformance: [] } }, 'CONFORMANCE_EVIDENCE_MISSING');
  denied({ ...bundle, subject: undefined }, 'ARTIFACT_EVIDENCE_MISSING');
});

test('unparsable lockfile and SBOM evidence is denied with fixed codes only', () => {
  const bundle = buildSyntheticReleaseBundle();
  const secretish = '{"lockfileVersion":3,"note":"' + PLANTED_CLOAKABLE + '"';
  for (const lockfile of [encode('{'), encode('[]'), encode(secretish)]) {
    const result = verifyReleaseEvidence({
      evidence: bundle.evidence, subject: { ...bundle.subject, lockfile }, expectation: bundle.expectation,
    });
    assert.equal(result.status, 'RELEASE_PROMOTION_DENIED');
    assert.ok(result.reasons.includes('LOCKFILE_EVIDENCE_MALFORMED'), JSON.stringify(result.reasons));
    assert.ok(!JSON.stringify(result).includes(PLANTED_CLOAKABLE), 'planted content must not be echoed');
  }
  for (const sbom of [encode('{'), encode('{"bomFormat":"SPDX","specVersion":"1.5"}'), encode('[]')]) {
    const result = verifyReleaseEvidence({
      evidence: bundle.evidence, subject: { ...bundle.subject, sbom }, expectation: bundle.expectation,
    });
    assert.equal(result.status, 'RELEASE_PROMOTION_DENIED');
    assert.ok(result.reasons.includes('SBOM_EVIDENCE_MALFORMED'), JSON.stringify(result.reasons));
  }
});

test('every published code, dependency issue and harness invariant is part of one vocabulary', () => {
  const sorted = [...RELEASE_DENIAL_CODES].sort();
  assert.deepEqual([...RELEASE_DENIAL_CODES], sorted, 'the published vocabulary must stay sorted');
  assert.equal(new Set(RELEASE_DENIAL_CODES).size, RELEASE_DENIAL_CODES.length, 'no duplicate codes');
  // Dependency comparison issues are reported directly by the gate, so they are release codes, and so
  // are the reader's own parse failures, which the gate forwards unchanged.
  for (const code of [...DEPENDENCY_ISSUE_CODES, ...DEPENDENCY_EVIDENCE_REASONS]) {
    assert.ok(RELEASE_DENIAL_CODES.includes(code), `${code} must be a published release denial code`);
  }
  assert.deepEqual([...DEPENDENCY_ISSUE_CODES], [...DEPENDENCY_ISSUE_CODES].sort());
  assert.deepEqual([...DEPENDENCY_EVIDENCE_REASONS], [...DEPENDENCY_EVIDENCE_REASONS].sort());
  assert.equal(DEPENDENCY_ISSUE_CODES.filter((code) => DEPENDENCY_EVIDENCE_REASONS.includes(code)).length, 0,
    'a parse failure and a comparison issue are different things');
  // Harness invariants are reported inside the attestation and reach the gate as one code; the N1
  // group proves a reported violation denies, and the vocabulary itself stays fixed and unique.
  assert.ok(RELEASE_DENIAL_CODES.includes('CONFORMANCE_VIOLATION_REPORTED'));
  assert.equal(new Set(CONFORMANCE_VIOLATIONS).size, CONFORMANCE_VIOLATIONS.length);
  assert.equal(new Set(CONFORMANCE_VIOLATIONS).size, CONFORMANCE_VIOLATIONS.length);
  assert.equal(new Set(CONFORMANCE_REQUIREMENTS).size, CONFORMANCE_REQUIREMENTS.length);
});

test('the gate reports only fixed codes and never echoes subject or evidence content', () => {
  const bundle = buildSyntheticReleaseBundle({ artifactName: SYNTHETIC_OTHER_ARTIFACT_NAME, adapter: bypassSyntheticAdapter() });
  const rendered = JSON.stringify(verify(bundle));
  assert.ok(!rendered.includes(PLANTED_CLOAKABLE));
  assert.ok(!rendered.includes(SYNTHETIC_ARTIFACT_NAME));
  assert.ok(!rendered.includes(sha256Hex(SYNTHETIC_ARTIFACT)), 'digests must not be reported');
  assert.ok(!rendered.includes(SYNTHETIC_COMMIT));
  assert.ok(!rendered.includes('synthetic-signing-key-1'));
  for (const reason of JSON.parse(rendered).reasons) assert.ok(RELEASE_DENIAL_CODES.includes(reason));
});

test('deterministic denial codes are sorted, bounded and free of duplicates', () => {
  const bundle = buildSyntheticReleaseBundle({
    scopeRef: SYNTHETIC_OTHER_SCOPE, profileId: SYNTHETIC_OTHER_PROFILE, adapter: bypassSyntheticAdapter(),
  });
  const first = verify(bundle);
  assert.deepEqual(first, verify(bundle));
  assert.deepEqual([...first.reasons].sort(), [...first.reasons]);
  assert.equal(new Set(first.reasons).size, first.reasons.length);
  assert.ok(first.reasons.length <= RELEASE_DENIAL_CODES.length);
});

test('seeded byte-level mutations of the evidence never verify', () => {
  const bundle = buildSyntheticReleaseBundle();
  const original = Buffer.from(bundle.evidence);
  let verifiedCount = 0;
  for (let index = 0; index < 64; index++) {
    const mutated = Buffer.from(original);
    const position = (index * 37) % mutated.length;
    mutated[position] ^= 1 << (index % 8);
    if (verifyReleaseEvidence({ evidence: mutated, subject: bundle.subject, expectation: bundle.expectation })
      .status === 'RELEASE_EVIDENCE_VERIFIED') verifiedCount += 1;
  }
  assert.equal(verifiedCount, 0, 'no single-byte mutation may verify');
});

test('structural and defensive denials never fall through to a pass', () => {
  const bundle = buildSyntheticReleaseBundle();
  const parsed = JSON.parse(Buffer.from(bundle.evidence).toString('utf8'));
  const withSignature = (signature) => buildSyntheticReleaseBundle({
    evidence: canonicalJson({ ...parsed, signature }),
  });
  // Two claims for one adapter are ambiguous, not first-wins.
  const claim = parsed.adapters[0];
  denied(buildSyntheticReleaseBundle({ adapters: [claim, { ...claim }] }), 'EVIDENCE_MALFORMED');
  // A signature member that is not a well-formed three-field object is a signature defect.
  for (const signature of [null, 'ed25519', [], { algorithm: 'ed25519' },
    { algorithm: 'ed25519', keyId: SYNTHETIC_SIGNER_KEY_ID, value: parsed.signature.value, extra: 1 },
    { algorithm: 'ed25519', keyId: 'not a valid id', value: parsed.signature.value },
    { algorithm: 'ed25519', keyId: SYNTHETIC_SIGNER_KEY_ID, value: `${parsed.signature.value.slice(0, -1)}A` }]) {
    denied(withSignature(signature), 'SIGNATURE_MALFORMED');
  }
  // Conformance and scanner documents are canonical and allowlisted too: a signed document that is
  // itself malformed is rejected on structure, not on its digest.
  for (const extra of [{ note: 'synthetic-extra' }, { schemaVersion: 2 }]) {
    const document = { ...bundle.conformanceDocument, ...extra };
    denied(buildSyntheticReleaseBundle({
      conformance: document,
      requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: document.suiteSha256 }],
    }), 'CONFORMANCE_EVIDENCE_MALFORMED');
  }
  for (const extra of [{ note: 'synthetic-extra' }, { scannerId: 7 }]) {
    denied(buildSyntheticReleaseBundle({ scanner: { ...bundle.scannerDocument, ...extra } }),
      'SCANNER_EVIDENCE_MALFORMED');
  }
  // Editing a conformance document after signing changes its bytes, so the signed digest refuses it
  // before the document is even read.
  const edited = { ...bundle.conformanceDocument, scopeRef: 'synthetic-tenant-b.invalid' };
  denied({
    ...bundle,
    subject: { ...bundle.subject, conformance: [{ adapterId: SYNTHETIC_ADAPTER, bytes: canonicalJson(edited) }] },
  }, 'CONFORMANCE_DIGEST_MISMATCH');
  // A conformance entry without bytes is missing evidence, not a silently skipped adapter.
  denied({
    ...bundle,
    subject: { ...bundle.subject, conformance: [{ adapterId: SYNTHETIC_ADAPTER }] },
  }, 'CONFORMANCE_EVIDENCE_MISSING');
  // An absent trusted expectation denies instead of skipping the checks.
  denied({ ...bundle, expectation: undefined }, 'EXPECTATION_INVALID');
  denied({ ...bundle, expectation: {} }, 'EXPECTATION_INVALID');
  // A dependency scan of bytes that are neither a lockfile nor an SBOM is unusable, not clean.
  denied({ ...bundle, subject: { ...bundle.subject, sbom: bundle.subject.lockfile } }, 'SBOM_EVIDENCE_MALFORMED');
  denied({ ...bundle, subject: { ...bundle.subject, lockfile: bundle.subject.sbom } }, 'LOCKFILE_EVIDENCE_MALFORMED');
});

test('the release gate CLI verifies signed evidence and denies a substituted artifact', () => {
  const sandbox = mkdtempSync(join(tmpdir(), 'hylja-release-gate-'));
  const subjectDir = join(sandbox, 'subject');
  const expectationPath = join(sandbox, 'expectation.json');
  const evidencePath = join(sandbox, 'evidence.json');
  try {
    mkdirSync(subjectDir);
    const bundle = buildSyntheticReleaseBundle();
    writeFileSync(join(subjectDir, SYNTHETIC_ARTIFACT_NAME), bundle.subject.artifact);
    writeFileSync(join(subjectDir, 'package-lock.json'), bundle.subject.lockfile);
    writeFileSync(join(subjectDir, 'sbom.json'), bundle.subject.sbom);
    writeFileSync(join(subjectDir, 'scanner.json'), bundle.subject.scanner);
    writeFileSync(join(subjectDir, `${SYNTHETIC_ADAPTER}.conformance.json`), bundle.subject.conformance[0].bytes);
    writeFileSync(evidencePath, bundle.evidence);
    writeFileSync(expectationPath, JSON.stringify({
      format: RELEASE_EXPECTATION_FORMAT,
      ...bundle.expectation,
      subject: {
        artifact: SYNTHETIC_ARTIFACT_NAME,
        lockfile: 'package-lock.json',
        sbom: 'sbom.json',
        scanner: 'scanner.json',
        conformance: [{ adapterId: SYNTHETIC_ADAPTER, file: `${SYNTHETIC_ADAPTER}.conformance.json` }],
      },
    }));
    const run = (...args) => spawnSync(process.execPath, [join(root, 'dist', 'release-gate-cli.js'), ...args],
      { encoding: 'utf8', timeout: 60_000 });
    assert.equal(run().status, 2, 'no arguments must be a usage error');
    assert.equal(run(evidencePath).status, 2, 'one argument must be a usage error');
    assert.equal(run(evidencePath, expectationPath, subjectDir, 'extra').status, 2, 'extra arguments must be refused');
    const good = run(evidencePath, expectationPath, subjectDir);
    assert.equal(good.status, 0, `expected exit 0, got ${good.stdout}${good.stderr}`);
    assert.deepEqual(JSON.parse(good.stdout), { status: 'RELEASE_EVIDENCE_VERIFIED', reasons: [] });
    assert.ok(!good.stdout.includes(SYNTHETIC_ARTIFACT_NAME), 'the CLI must not echo subject names');

    writeFileSync(join(subjectDir, SYNTHETIC_ARTIFACT_NAME), Buffer.concat([Buffer.from(bundle.subject.artifact), Buffer.from('x')]));
    const substituted = run(evidencePath, expectationPath, subjectDir);
    assert.equal(substituted.status, 1);
    assert.ok(JSON.parse(substituted.stdout).reasons.includes('ARTIFACT_DIGEST_MISMATCH'),
      JSON.stringify(substituted.stdout));

    const absent = run(join(sandbox, 'absent.json'), expectationPath, subjectDir);
    assert.equal(absent.status, 1);
    assert.deepEqual(JSON.parse(absent.stdout).reasons, ['EVIDENCE_MISSING']);
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
});

test('the release gate CLI refuses redirected, ambiguous and unreadable inputs in process', () => {
  const sandbox = mkdtempSync(join(tmpdir(), 'hylja-release-cli-'));
  const subjectDir = join(sandbox, 'subject');
  const capture = (args) => {
    const out = [];
    const err = [];
    const stdout = process.stdout.write;
    const stderr = process.stderr.write;
    const previousExit = process.exitCode;
    process.stdout.write = (chunk) => { out.push(String(chunk)); return true; };
    process.stderr.write = (chunk) => { err.push(String(chunk)); return true; };
    process.exitCode = undefined;
    try { runGateCli(['node', 'release-gate-cli.js', ...args]); return { out: out.join(''), err: err.join(''), code: process.exitCode }; }
    finally {
      process.stdout.write = stdout;
      process.stderr.write = stderr;
      process.exitCode = previousExit;
    }
  };
  try {
    mkdirSync(subjectDir);
    const bundle = buildSyntheticReleaseBundle();
    const expectation = {
      format: RELEASE_EXPECTATION_FORMAT,
      ...bundle.expectation,
      subject: {
        artifact: SYNTHETIC_ARTIFACT_NAME,
        lockfile: 'package-lock.json',
        sbom: 'sbom.json',
        scanner: 'scanner.json',
        conformance: [{ adapterId: SYNTHETIC_ADAPTER, file: 'conformance.json' }],
      },
    };
    const write = (name, bytes) => writeFileSync(join(subjectDir, name), bytes);
    write(SYNTHETIC_ARTIFACT_NAME, bundle.subject.artifact);
    write('package-lock.json', bundle.subject.lockfile);
    write('sbom.json', bundle.subject.sbom);
    write('scanner.json', bundle.subject.scanner);
    write('conformance.json', bundle.subject.conformance[0].bytes);
    const evidencePath = join(sandbox, 'evidence.json');
    const expectationPath = join(sandbox, 'expectation.json');
    writeFileSync(evidencePath, bundle.evidence);
    writeFileSync(expectationPath, JSON.stringify(expectation, null, 2));

    // A wrong argument count is a usage error and reads nothing.
    assert.equal(capture([]).code, 2);
    assert.equal(capture([evidencePath, expectationPath]).code, 2);
    assert.equal(capture([evidencePath, expectationPath, subjectDir, 'extra']).code, 2);
    assert.equal(capture([evidencePath, expectationPath, 7]).code, 2, 'a non-string argument is a usage error');
    assert.equal(capture([evidencePath, expectationPath, '']).code, 2);
    assert.match(capture([evidencePath]).err, /usage/);

    const good = capture([evidencePath, expectationPath, subjectDir]);
    assert.equal(good.code, 0);
    assert.deepEqual(JSON.parse(good.out), { status: 'RELEASE_EVIDENCE_VERIFIED', reasons: [] });

    // A redirected subject path is refused instead of being followed.
    const realLock = join(subjectDir, 'real-lock.json');
    writeFileSync(realLock, bundle.subject.lockfile);
    symlinkSync(realLock, join(subjectDir, 'package-lock.json.real'));
    const redirected = join(sandbox, 'redirected-subject');
    mkdirSync(redirected);
    for (const name of ['sbom.json', 'scanner.json', 'conformance.json', SYNTHETIC_ARTIFACT_NAME]) {
      symlinkSync(join(subjectDir, name), join(redirected, name));
    }
    symlinkSync(realLock, join(redirected, 'package-lock.json'));
    const redirectedRun = capture([evidencePath, expectationPath, redirected]);
    assert.equal(redirectedRun.code, 1);
    assert.deepEqual(JSON.parse(redirectedRun.out).reasons, ['CHECK_UNAVAILABLE']);

    // A duplicated key in the trusted expectation file is refused, not resolved last-wins.
    const duplicated = join(sandbox, 'duplicated-expectation.json');
    writeFileSync(duplicated, JSON.stringify(expectation, null, 2)
      .replace('"artifactName"', '"artifactName":"synthetic-other.tgz","artifactName"'));
    const ambiguous = capture([evidencePath, duplicated, subjectDir]);
    assert.equal(ambiguous.code, 1);
    assert.deepEqual(JSON.parse(ambiguous.out).reasons, ['EXPECTATION_INVALID']);

    // A missing subject file, a subject directory that is a file, and a trailing path are all denied.
    assert.deepEqual(JSON.parse(capture([evidencePath, expectationPath, join(sandbox, 'absent')]).out).reasons,
      ['CHECK_UNAVAILABLE']);
    assert.deepEqual(JSON.parse(capture([evidencePath, expectationPath, expectationPath]).out).reasons,
      ['CHECK_UNAVAILABLE']);
    // Nothing above printed a path, a digest or a package name.
    for (const run of [good, redirectedRun, ambiguous]) {
      assert.ok(!run.out.includes(sandbox));
      assert.ok(!run.out.includes(sha256Hex(SYNTHETIC_ARTIFACT)));
    }
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
});
