#!/usr/bin/env node
/**
 * #33 offline synthetic release-evidence demonstration.
 *
 *   npm run check:release          (requires `npm run build` first)
 *
 * Builds a complete synthetic release in memory with an ephemeral Ed25519 key that is discarded,
 * then walks the promotion gate through one positive and several negative cases. Nothing is fetched,
 * published, signed for real or written to disk, and no production value, host or credential appears
 * anywhere in the substrate. The output is one fixed JSON summary; exit 0 means every expectation
 * held, and a non-zero exit means a case did not behave as specified.
 *
 * This is a demonstration of the gate's decisions, not a release: the gate itself never signs,
 * writes, publishes or promotes anything.
 */
import { verifyReleaseEvidence } from '../dist/release-integrity.js';
import { canonicalJson } from '../dist/canonical-json.js';
import {
  SYNTHETIC_ADAPTER, SYNTHETIC_ARTIFACT, SYNTHETIC_INTEGRITY, SYNTHETIC_OTHER_KEY_ID,
  SYNTHETIC_OTHER_SCOPE, bypassSyntheticAdapter, buildSyntheticReleaseBundle, createSyntheticSigner,
  encodingCloakAdapter, sha256Hex, syntheticLockfile, syntheticLockfileBytes, syntheticSbom,
  unboundReleaseAdapter,
} from './synthetic-release-substrate.mjs';

const results = [];
function check(id, expectedStatus, expectedCode, bundle) {
  const outcome = verifyReleaseEvidence({
    evidence: bundle.evidence, subject: bundle.subject, expectation: bundle.expectation,
  });
  const held = outcome.status === expectedStatus
    && (expectedCode === null || outcome.reasons.includes(expectedCode));
  results.push({ id, held, status: outcome.status, reasons: outcome.reasons });
}

const base = buildSyntheticReleaseBundle();
check('verified-exact-bytes', 'RELEASE_EVIDENCE_VERIFIED', null, base);
check('post-test-artifact-substitution', 'RELEASE_PROMOTION_DENIED', 'ARTIFACT_DIGEST_MISMATCH', {
  ...base, subject: { ...base.subject, artifact: new Uint8Array([...base.subject.artifact, 0x20]) },
});
const relocked = syntheticLockfile();
relocked.packages['node_modules/synthetic-epsilon-unreviewed'] = {
  version: '3.1.4',
  resolved: 'https://registry.synthetic.invalid/synthetic-epsilon-unreviewed/-/synthetic-epsilon-unreviewed-3.1.4.tgz',
  integrity: SYNTHETIC_INTEGRITY['synthetic-epsilon-unreviewed'],
};
check('post-test-lockfile-substitution', 'RELEASE_PROMOTION_DENIED', 'LOCKFILE_DIGEST_MISMATCH', {
  ...base, subject: { ...base.subject, lockfile: syntheticLockfileBytes(relocked) },
});
const tailored = syntheticSbom();
tailored.components = [];
check('tailored-sbom', 'RELEASE_PROMOTION_DENIED', 'LOCKED_DEPENDENCY_ABSENT_FROM_SBOM',
  buildSyntheticReleaseBundle({ sbom: tailored }));
const other = createSyntheticSigner(SYNTHETIC_OTHER_KEY_ID);
check('forged-signature', 'RELEASE_PROMOTION_DENIED', 'SIGNATURE_INVALID',
  { ...base, evidence: other.sign(base.payload, { claimedKeyId: base.signer.keyId }) });
check('untrusted-signing-key', 'RELEASE_PROMOTION_DENIED', 'SIGNING_KEY_UNKNOWN',
  { ...base, evidence: other.sign(base.payload) });
check('other-channel-scope', 'RELEASE_PROMOTION_DENIED', 'CHANNEL_SCOPE_MISMATCH',
  buildSyntheticReleaseBundle({ scopeRef: SYNTHETIC_OTHER_SCOPE }));
check('critical-scanner-finding', 'RELEASE_PROMOTION_DENIED', 'FINDING_BLOCKS_PROMOTION',
  buildSyntheticReleaseBundle({
    findings: [{ severity: 'critical', ruleId: 'synthetic-rule', packageName: 'synthetic-alpha-parser', version: '1.2.3' }],
  }));
check('adapter-skips-planted-egress-check', 'RELEASE_PROMOTION_DENIED', 'PLANTED_EGRESS_UNPROVEN',
  buildSyntheticReleaseBundle({ adapter: bypassSyntheticAdapter() }));
check('independently-pinned-lockfile', 'RELEASE_PROMOTION_DENIED', 'LOCKFILE_NOT_INDEPENDENTLY_PINNED',
  buildSyntheticReleaseBundle({ expectedLockSha256: sha256Hex(SYNTHETIC_ARTIFACT) }));
check('missing-scanner-evidence', 'RELEASE_PROMOTION_DENIED', 'SCANNER_EVIDENCE_MISSING', {
  ...base, subject: { ...base.subject, scanner: new Uint8Array(0) },
});
const editedConformance = { ...base.conformanceDocument, scopeRef: 'synthetic-tenant-b.invalid' };
check('conformance-evidence-edited-after-signing', 'RELEASE_PROMOTION_DENIED', 'CONFORMANCE_DIGEST_MISMATCH', {
  ...base,
  subject: { ...base.subject, conformance: [{ adapterId: SYNTHETIC_ADAPTER, bytes: canonicalJson(editedConformance) }] },
});
check('duplicate-conformance-evidence', 'RELEASE_PROMOTION_DENIED', 'CONFORMANCE_EVIDENCE_DUPLICATE', {
  ...base,
  subject: { ...base.subject, conformance: [...base.subject.conformance, ...base.subject.conformance] },
});

// The two review-driven harness shapes: a recoverable encoding of a planted original, and a payload
// that is not the copy the pre-send control cleared.
check('adapter-encodes-planted-original', 'RELEASE_PROMOTION_DENIED', 'PLANTED_EGRESS_UNPROVEN',
  buildSyntheticReleaseBundle({ adapter: encodingCloakAdapter() }));
check('adapter-releases-unbound-bytes', 'RELEASE_PROMOTION_DENIED', 'CONFORMANCE_FAILED',
  buildSyntheticReleaseBundle({ adapter: unboundReleaseAdapter() }));
// A malformed integrity pin is unusable locked evidence, not a silently skipped comparison.
const malformedPin = buildSyntheticReleaseBundle();
const malformedLock = syntheticLockfile();
malformedLock.packages['node_modules/synthetic-alpha-parser'].integrity = 'sha512-!!!not-base64!!!';
check('malformed-integrity-pin', 'RELEASE_PROMOTION_DENIED', 'LOCKFILE_INTEGRITY_INVALID',
  buildSyntheticReleaseBundle({ lock: malformedLock, sbom: syntheticSbom(malformedLock) }));
// An attestation that contradicts its own per-case outcomes is refused.
const contradicting = {
  ...malformedPin.conformanceDocument,
  cases: malformedPin.conformanceDocument.cases.map((entry) => ({ ...entry, outcome: 'FAIL' })),
};
check('self-contradicting-conformance', 'RELEASE_PROMOTION_DENIED', 'CONFORMANCE_CASE_NOT_PASSING',
  buildSyntheticReleaseBundle({
    conformance: contradicting,
    requiredConformance: [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: contradicting.suiteSha256 }],
  }));

const failed = results.filter((entry) => !entry.held);
process.stdout.write(`${JSON.stringify({
  status: failed.length === 0 ? 'SYNTHETIC_RELEASE_GATE_CONSISTENT' : 'SYNTHETIC_RELEASE_GATE_INCONSISTENT',
  cases: results.length,
  failed: failed.map((entry) => entry.id),
  adapter: SYNTHETIC_ADAPTER,
})}\n`);
process.exitCode = failed.length === 0 ? 0 : 1;
