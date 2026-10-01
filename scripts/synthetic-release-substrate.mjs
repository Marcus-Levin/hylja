/**
 * SYNTHETIC, OFFLINE, TEST/DEMO-ONLY release substrate for #33.
 *
 * Everything here is invented: package names, registry hosts, artifact bytes, digests, keys and
 * commit ids. Nothing is fetched, published or trusted, and the Ed25519 key is generated in memory
 * and discarded. This module is never imported by `src/`; it exists so the release gate can be
 * exercised (positive and negative) without a production artifact, a real signing service or any
 * secret in the repository.
 */
import { createHash, createPrivateKey, generateKeyPairSync, sign as edSign } from 'node:crypto';
import { canonicalJson } from '../dist/canonical-json.js';
import { runAdapterConformance } from '../dist/adapter-conformance.js';
import { RELEASE_EVIDENCE_FORMAT, SEVERITY_ORDER } from '../dist/release-integrity.js';

/* ---------- synthetic values (obviously non-routable, no production identifiers) ---------- */

export const SYNTHETIC_COMMIT = '5f0c9a1d4b8e37c2a0f6b19d8e4c37a5b0d9e8f4';
/** Fixed synthetic clock for standalone substrate use; the bundle passes its own `now`. */
export const SYNTHETIC_NOW = 1_700_000_000_000;
export const SYNTHETIC_RELEASE_VERSION = '0.1.0-synthetic';
export const SYNTHETIC_SCOPE = 'synthetic-tenant-a.invalid';
export const SYNTHETIC_OTHER_SCOPE = 'synthetic-tenant-b.invalid';
export const SYNTHETIC_PROFILE = 'synthetic-release-profile-a';
export const SYNTHETIC_OTHER_PROFILE = 'synthetic-release-profile-b';
export const SYNTHETIC_ARTIFACT_NAME = 'hylja-synthetic-release-0.1.0-synthetic.tgz';
export const SYNTHETIC_OTHER_ARTIFACT_NAME = 'hylja-synthetic-release-0.1.0-synthetic-evil.tgz';
export const SYNTHETIC_DESTINATION = 'synthetic-release-destination.invalid';
export const SYNTHETIC_OTHER_DESTINATION = 'synthetic-redirect-destination.invalid';
export const SYNTHETIC_ADAPTER = 'synthetic-adapter-a';
export const SYNTHETIC_OTHER_ADAPTER = 'synthetic-adapter-b';
export const SYNTHETIC_SUITE_ID = 'synthetic-conformance-v1';
export const SYNTHETIC_SCANNER = 'synthetic-scanner-v1';
/** #19 known-originals scope and destination profile the harness owns; the adapter never sees them. */
export const SYNTHETIC_SENTINEL_SCOPE = Object.freeze({
  tenantRef: 'synthetic-tenant-a.invalid', projectRef: 'synthetic-project-a.invalid',
});
export const SYNTHETIC_PROFILE_DIGEST = 'sha256-synthetic-release-profile-digest';
export const SYNTHETIC_KEY_ID = 'synthetic-signing-key-1';
export const SYNTHETIC_OTHER_KEY_ID = 'synthetic-signing-key-2';
/** Planted synthetic originals. Obviously synthetic tokens, never a real secret or customer value. */
export const PLANTED_CLOAKABLE = 'SYNTHETIC-PLANTED-ORIGINAL-7f3a.invalid';
export const PLANTED_UNCLOAKABLE = 'SYNTHETIC-PLANTED-NESTED-9c1e.invalid';
export const CLOAKED_TOKEN = 'synthetic-entity-4d2f.invalid';
/** Appended by the unbound-release double after the control cleared the clean bytes. */
export const SYNTHETIC_APPENDED_PAYLOAD = 'appended-after-check.invalid';

const text = (value) => new TextEncoder().encode(value);
export const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const SYNTHETIC_DEPENDENCIES = Object.freeze([
  { path: 'node_modules/synthetic-alpha-parser', name: 'synthetic-alpha-parser', version: '1.2.3' },
  { path: 'node_modules/synthetic-beta-normalizer', name: 'synthetic-beta-normalizer', version: '0.4.1' },
  { path: 'node_modules/synthetic-gamma-sink', name: 'synthetic-gamma-sink', version: '2.0.0-beta.1' },
]);
export const SYNTHETIC_INTEGRITY = Object.freeze({
  "synthetic-alpha-parser": "sha512-zURZOyW+4k5UUZRgIDM/0OiwiMhzMSVPYvejblNt/1xpt6otUzUf6smUsttWHphDngyEEWLs6trXlu5jhlpzfA==",
  "synthetic-beta-normalizer": "sha512-A3BBtCuv4zdmT4dbrwMGizTYu2ooq90LKGQhipP4Jwi11NspE3RVMGmuU0wJnHwnuEd5ddHSClIvcB2XVuKidw==",
  "synthetic-gamma-sink": "sha512-dySEaNNDWmkF2ebP+TipBj6t8VkI8dxhD9++uQrH+dkYmfmTG8ybkPFpHxKh/yotkeHWP5asioB9gC5ffWIvCQ==",
  "synthetic-delta-extra": "sha512-Pgwp1Sa99K19FgkNadMUku934m+vqCSzBc0I+nLRIg+BMgxvA0C6whtBaZznSEsWg6J0dtD5e+zw8n+7OJ6c8w==",
  "synthetic-epsilon-unreviewed": "sha512-54IxYcVeTFkYZp/rqf6jXI7hiXvl+jTs9fedKEAsGrQU29BfXg2MOzDOPXvVAESzqfz4r2ESLtd0SBLs9F/4jw==",
  "synthetic-zeta-new": "sha512-9egR0IiEONLKwE+Dt/OW+e71RWXo6UtQGhI6lt8Y66ndmQufZimOh2DoT6WN1xxHdSjKK8QxMg6g+mSHi1TP2A==",
});


/** The synthetic SBOM states content hashes, as npm does: hex SHA-512 of the same pinned bytes. */
const integrityHex = (name) => Buffer.from(
  SYNTHETIC_INTEGRITY[name].slice('sha512-'.length), 'base64').toString('hex');

export const SYNTHETIC_ARTIFACT = text(JSON.stringify({
  format: 'synthetic-release-artifact/v1',
  name: SYNTHETIC_ARTIFACT_NAME,
  note: 'synthetic bytes for the #33 offline release gate; not a publishable package',
  components: ['synthetic-policy-core'],
}) + '\n');

export function syntheticLockfile() {
  const packages = {
    '': {
      name: 'synthetic-release-app',
      version: '0.1.0',
      license: 'UNLICENSED',
      devDependencies: Object.fromEntries(
        SYNTHETIC_DEPENDENCIES.map((entry) => [entry.name, entry.version]),
      ),
    },
  };
  for (const entry of SYNTHETIC_DEPENDENCIES) {
    packages[entry.path] = {
      version: entry.version,
      resolved: `https://registry.synthetic.invalid/${entry.name}/-/${entry.name}-${entry.version}.tgz`,
      integrity: SYNTHETIC_INTEGRITY[entry.name],
      license: 'Apache-2.0',
    };
  }
  return { name: 'synthetic-release-app', version: '0.1.0', lockfileVersion: 3, requires: true, packages };
}

export function syntheticSbom(lock = syntheticLockfile()) {
  return {
    $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000033',
    version: 1,
    metadata: {
      // npm derives this root name from the checkout directory, so it is deliberately not the
      // package name here: the cross-check must not depend on it.
      component: { 'bom-ref': 'synthetic-release-app@0.1.0', type: 'application', name: 'synthetic-checkout-dir', version: lock.packages[''].version },
    },
    components: Object.entries(lock.packages).filter(([key]) => key !== '').map(([key, value]) => ({
      'bom-ref': `${key.split('/').pop()}@${value.version}`,
      type: 'library',
      name: key.split('/').pop(),
      version: value.version,
      purl: `pkg:npm/${key.split('/').pop()}@${value.version}`,
      properties: [{ name: 'cdx:npm:package:path', value: key }],
      hashes: [{ alg: 'SHA-512', content: integrityHex(key.split('/').pop()) }],
    })),
  };
}

export function syntheticLockfileBytes(lock = syntheticLockfile()) {
  return text(JSON.stringify(lock, null, 2) + '\n');
}
export function syntheticSbomBytes(sbom = syntheticSbom()) {
  return text(JSON.stringify(sbom, null, 2) + '\n');
}

/* ---------- synthetic adapter conformance suite and doubles ---------- */

const CLEAN_FIELD = 'endpoint = synthetic-endpoint-a.invalid';
const CLOAKED_FIELD = `endpoint = ${CLOAKED_TOKEN}`;

/** The harness owns the case list; the digest is over these exact case bytes. */
export function syntheticConformanceSuite() {
  return {
    suiteId: SYNTHETIC_SUITE_ID,
    cases: [
      {
        id: 'functional-clean-request', kind: 'FUNCTIONAL',
        fields: [{ id: 'field-0', text: CLEAN_FIELD }],
        opaquePart: null,
        authorizedDestinationId: SYNTHETIC_DESTINATION,
        sendDestinationId: SYNTHETIC_DESTINATION,
        expectedFields: [{ id: 'field-0', text: CLEAN_FIELD }],
        expectedSendCount: 1,
        requirements: ['FUNCTIONAL_MATCH', 'PRE_SEND_CHECK_CONSULTED', 'DESTINATION_BOUND'],
      },
      {
        id: 'planted-egress-cloakable', kind: 'PLANTED_EGRESS',
        fields: [{ id: 'field-0', text: `contact = ${PLANTED_CLOAKABLE}` }],
        opaquePart: null,
        authorizedDestinationId: SYNTHETIC_DESTINATION,
        sendDestinationId: SYNTHETIC_DESTINATION,
        expectedFields: null,
        expectedSendCount: 1,
        requirements: ['PLANTED_ORIGINAL_ABSENT', 'PRE_SEND_CHECK_CONSULTED', 'DESTINATION_BOUND'],
      },
      {
        id: 'planted-egress-nested', kind: 'PLANTED_EGRESS',
        fields: [{ id: 'field-0', text: `nested = ${PLANTED_UNCLOAKABLE}` }],
        opaquePart: null,
        authorizedDestinationId: SYNTHETIC_DESTINATION,
        sendDestinationId: SYNTHETIC_DESTINATION,
        expectedFields: null,
        expectedSendCount: 0,
        requirements: ['PLANTED_ORIGINAL_ABSENT', 'DESTINATION_BOUND'],
      },
      {
        id: 'opaque-part-declared', kind: 'OPAQUE_PART',
        fields: [{ id: 'field-0', text: CLEAN_FIELD }],
        opaquePart: { id: 'opaque-attachment-0' },
        authorizedDestinationId: SYNTHETIC_DESTINATION,
        sendDestinationId: SYNTHETIC_DESTINATION,
        expectedFields: null,
        expectedSendCount: 0,
        requirements: ['OPAQUE_NOT_RELEASED', 'DECLARED_UNSUPPORTED'],
      },
      {
        id: 'redirect-not-authorized', kind: 'DESTINATION_BINDING',
        fields: [{ id: 'field-0', text: CLEAN_FIELD }],
        opaquePart: null,
        authorizedDestinationId: SYNTHETIC_DESTINATION,
        sendDestinationId: SYNTHETIC_OTHER_DESTINATION,
        expectedFields: null,
        expectedSendCount: 0,
        requirements: ['DESTINATION_BOUND', 'PRE_SEND_CHECK_CONSULTED'],
      },
    ],
  };
}

/**
 * A compliant synthetic double: it cloaks a cloakable planted value, refuses the nested value it
 * cannot transform, declares and blocks the opaque part, and always routes the exact outbound
 * bytes through the injected pre-send control before capturing anything.
 */
export function compliantSyntheticAdapter(overrides = {}) {
  const declaration = {
    operations: ['model.input'],
    inspectableParts: ['body.field-0'],
    unsupportedParts: ['opaque-attachment-0', 'nested-value'],
    sinks: [SYNTHETIC_DESTINATION],
    ...overrides.declaration,
  };
  return {
    adapterId: overrides.adapterId ?? SYNTHETIC_ADAPTER,
    declaredCoverage: declaration,
    release(request, controls) {
      if (request.opaquePart) return { fields: [], decision: 'BLOCKED' };
      const fields = request.fields.map((field) => ({
        id: field.id,
        text: field.text.includes(PLANTED_CLOAKABLE)
          ? field.text.replace(PLANTED_CLOAKABLE, CLOAKED_TOKEN)
          : field.text,
      }));
      if (fields.some((field) => field.text.includes(PLANTED_UNCLOAKABLE))) {
        return { fields: [], decision: 'BLOCKED' };
      }
      const decision = controls.preSendCheck({
        destinationId: request.sendDestinationId,
        authorizedDestinationId: request.authorizedDestinationId,
        bytes: text(fields.map((field) => field.text).join('\n')),
      });
      // #19 discipline: send the private copy the control cleared, never the caller's own buffer.
      if (decision.decision !== 'ALLOW' || !decision.release) return { fields: [], decision: 'BLOCKED' };
      controls.send(request.sendDestinationId, decision.release);
      return { fields, decision: 'SENT' };
    },
  };
}

/**
 * A compromised synthetic double that "cloaks" by encoding instead of substituting: the planted
 * original is still recoverable from the released bytes, in the project's own canonical views.
 */
export function encodingCloakAdapter(overrides = {}) {
  return {
    adapterId: overrides.adapterId ?? SYNTHETIC_ADAPTER,
    declaredCoverage: overrides.declaration ?? {
      operations: ['model.input'], inspectableParts: ['body.field-0'],
      unsupportedParts: ['opaque-attachment-0', 'nested-value'], sinks: [SYNTHETIC_DESTINATION],
    },
    release(request, controls) {
      if (request.opaquePart) return { fields: [], decision: 'BLOCKED' };
      const fields = request.fields.map((field) => ({
        id: field.id,
        text: field.text.includes(PLANTED_CLOAKABLE)
          ? field.text.replace(PLANTED_CLOAKABLE, Buffer.from(PLANTED_CLOAKABLE).toString('base64'))
          : field.text.includes(PLANTED_UNCLOAKABLE)
            ? field.text.replace(PLANTED_UNCLOAKABLE, Buffer.from(PLANTED_UNCLOAKABLE).toString('hex'))
            : field.text,
      }));
      if (fields.some((field) => field.text.includes(PLANTED_UNCLOAKABLE))) return { fields: [], decision: 'BLOCKED' };
      controls.send(request.sendDestinationId, text(fields.map((field) => field.text).join('\n')));
      return { fields, decision: 'SENT' };
    },
  };
}

/**
 * A compromised synthetic double that shows clean bytes to the injected pre-send control and then
 * releases different bytes: the check is consulted but bound to nothing.
 */
export function unboundReleaseAdapter(overrides = {}) {
  return {
    adapterId: overrides.adapterId ?? SYNTHETIC_ADAPTER,
    declaredCoverage: overrides.declaration ?? {
      operations: ['model.input'], inspectableParts: ['body.field-0'],
      unsupportedParts: ['opaque-attachment-0', 'nested-value'], sinks: [SYNTHETIC_DESTINATION],
    },
    release(request, controls) {
      if (request.opaquePart) return { fields: [], decision: 'BLOCKED' };
      const clean = request.fields.map((field) => ({
        id: field.id,
        text: field.text.replace(PLANTED_CLOAKABLE, CLOAKED_TOKEN),
      })).filter((field) => !field.text.includes(PLANTED_UNCLOAKABLE));
      if (request.fields.some((field) => field.text.includes(PLANTED_UNCLOAKABLE))) {
        return { fields: [], decision: 'BLOCKED' };
      }
      const decision = controls.preSendCheck({
        destinationId: request.sendDestinationId,
        authorizedDestinationId: request.authorizedDestinationId,
        bytes: text(clean.map((field) => field.text).join('\n')),
      }).decision;
      if (decision !== 'ALLOW') return { fields: [], decision: 'BLOCKED' };
      // Different bytes than the ones the control just cleared.
      const released = text([...clean.map((field) => field.text), `appended = ${SYNTHETIC_APPENDED_PAYLOAD}`].join('\n'));
      controls.send(request.sendDestinationId, released);
      return { fields: clean, decision: 'SENT' };
    },
  };
}

/**
 * A compromised synthetic double: ordinary functional correctness is preserved, but the pre-send
 * control is never consulted, nothing is cloaked, opaque parts are released anyway and an
 * unobserved redirect is followed. This is the #33 adversarial update shape.
 */
export function bypassSyntheticAdapter(overrides = {}) {
  return {
    adapterId: overrides.adapterId ?? SYNTHETIC_ADAPTER,
    declaredCoverage: overrides.declaration ?? {
      operations: ['model.input'],
      inspectableParts: ['body.field-0'],
      unsupportedParts: [],
      sinks: [SYNTHETIC_DESTINATION, SYNTHETIC_OTHER_DESTINATION],
    },
    release(request, controls) {
      const fields = request.fields.map((field) => ({ id: field.id, text: field.text }));
      // Tampering with the harness-owned record is attempted and must be impossible; the leak
      // below is recorded anyway, and a self-report must never buy a conformance pass.
      if (typeof controls.captured === 'function') {
        const record = controls.captured();
        try { record.length = 0; record.push({ sequence: 0, destinationId: '', bytes: new Uint8Array(0) }); }
        catch { /* the captured record is an immutable copy */ }
      }
      controls.send(request.sendDestinationId, text(fields.map((field) => field.text).join('\n')));
      return { fields, decision: 'SENT', plantedEgress: 'PASS', overall: 'PASS', conformance: 'PASS' };
    },
  };
}

/* ---------- synthetic evidence construction ---------- */

export function createSyntheticSigner(keyId = SYNTHETIC_KEY_ID) {
  const pair = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { format: 'der', type: 'spki' },
    privateKeyEncoding: { format: 'der', type: 'pkcs8' },
  });
  const privateKey = createPrivateKey({ key: pair.privateKey, format: 'der', type: 'pkcs8' });
  return {
    keyId,
    publicKeySpkiBase64: pair.publicKey.toString('base64'),
    /** Sign a payload object into canonical evidence bytes with a detached signature field. */
    sign(payload, { corrupt = false, claimedKeyId } = {}) {
      const body = Buffer.from(canonicalJson(payload));
      let value = edSign(null, body, privateKey);
      if (corrupt) { value = Buffer.from(value); value[0] ^= 0x01; }
      // Assembly lives with the signer, not in the gate: the gate can only ever verify evidence.
      return canonicalJson({
        ...payload, signature: { algorithm: 'ed25519', keyId: claimedKeyId ?? keyId, value: value.toString('base64') },
      });
    },
  };
}

export function syntheticConformanceEvidence(subject, {
  adapter = compliantSyntheticAdapter(), scopeRef = SYNTHETIC_SCOPE, completedAt = SYNTHETIC_NOW,
  suite = syntheticConformanceSuite(),
} = {}) {
  return runAdapterConformance({
    adapter,
    suite,
    scopeRef,
    sentinelScope: SYNTHETIC_SENTINEL_SCOPE,
    destinationProfileDigest: SYNTHETIC_PROFILE_DIGEST,
    subject: {
      artifactSha256: subject.artifactSha256,
      lockSha256: subject.lockSha256,
      sbomSha256: subject.sbomSha256,
    },
    planted: [PLANTED_CLOAKABLE, PLANTED_UNCLOAKABLE],
    completedAt,
  });
}

export function syntheticScannerEvidence(subject, {
  scannerId = SYNTHETIC_SCANNER, completedAt = SYNTHETIC_NOW, findings = [],
} = {}) {
  return {
    schemaVersion: 1,
    scannerId,
    completed: true,
    completedAt,
    lockSha256: subject.lockSha256,
    sbomSha256: subject.sbomSha256,
    findings: findings.map((finding) => ({
      severity: finding.severity, ruleId: finding.ruleId, packageName: finding.packageName, version: finding.version,
    })),
  };
}

export const SEVERITIES = SEVERITY_ORDER;

/**
 * Build a complete synthetic release bundle. Every returned expectation value is supplied here by
 * the "trusted integration" and is never read back out of the evidence document.
 */
export function buildSyntheticReleaseBundle(options = {}) {
  const now = options.now ?? 1_700_000_000_000;
  const maxAgeMs = options.maxAgeMs ?? 3_600_000;
  const artifact = options.artifact ?? SYNTHETIC_ARTIFACT;
  const lock = options.lock ?? syntheticLockfile();
  const lockfile = options.lockfile ?? syntheticLockfileBytes(lock);
  const sbomDocument = options.sbom ?? syntheticSbom(lock);
  const sbom = options.sbomBytes ?? syntheticSbomBytes(sbomDocument);
  const signer = options.signer ?? createSyntheticSigner();
  const artifactSha256 = sha256Hex(artifact);
  const lockSha256 = sha256Hex(lockfile);
  const sbomSha256 = sha256Hex(sbom);
  const subject = { artifactSha256, lockSha256, sbomSha256 };

  const conformanceDocument = options.conformance
    ?? syntheticConformanceEvidence(subject, {
      ...(options.adapter === undefined ? {} : { adapter: options.adapter }),
      ...(options.scopeRefOverride === undefined ? {} : { scopeRef: options.scopeRefOverride }),
      ...(options.suite === undefined ? {} : { suite: options.suite }),
      completedAt: options.completedAt ?? now - 1_000,
    });
  const conformanceBytes = canonicalJson(conformanceDocument);
  const conformanceSha256 = sha256Hex(conformanceBytes);
  const scannerDocument = options.scanner
    ?? syntheticScannerEvidence(subject, {
      ...(options.findings === undefined ? {} : { findings: options.findings }),
      ...(options.scannerId === undefined ? {} : { scannerId: options.scannerId }),
      completedAt: options.scannerCompletedAt ?? now - 2_000,
    });
  const scannerBytes = canonicalJson(scannerDocument);

  const conformance = options.adapters ?? [{ adapterId: SYNTHETIC_ADAPTER, evidenceSha256: conformanceSha256 }];
  const payload = {
    format: RELEASE_EVIDENCE_FORMAT,
    issuedAt: options.issuedAt ?? now - 5_000,
    expiresAt: options.expiresAt ?? now + maxAgeMs,
    release: {
      version: options.releaseVersion ?? SYNTHETIC_RELEASE_VERSION,
      commit: options.commit ?? SYNTHETIC_COMMIT,
      scopeRef: options.scopeRef ?? SYNTHETIC_SCOPE,
      profileId: options.profileId ?? SYNTHETIC_PROFILE,
    },
    artifact: {
      name: options.artifactName ?? SYNTHETIC_ARTIFACT_NAME,
      sha256: artifactSha256,
      bytes: artifact.length,
    },
    dependencies: { lockSha256, sbomSha256 },
    adapters: conformance,
    scanner: { evidenceSha256: sha256Hex(scannerBytes) },
  };
  const evidence = options.evidence ?? signer.sign(payload, { corrupt: options.corruptSignature });

  const expectation = {
    releaseVersion: SYNTHETIC_RELEASE_VERSION,
    commit: SYNTHETIC_COMMIT,
    artifactName: SYNTHETIC_ARTIFACT_NAME,
    channel: { scopeRef: SYNTHETIC_SCOPE, profileId: SYNTHETIC_PROFILE },
    signingKeys: options.signingKeys ?? [{ keyId: signer.keyId, publicKeySpkiBase64: signer.publicKeySpkiBase64 }],
    requiredConformance: options.requiredConformance
      ?? [{ adapterId: SYNTHETIC_ADAPTER, suiteSha256: conformanceDocument.suiteSha256 }],
    requiredScannerIds: options.requiredScannerIds ?? [SYNTHETIC_SCANNER],
    blockAtSeverity: options.blockAtSeverity ?? 'critical',
    now,
    maxAgeMs,
    ...(options.expectedLockSha256 === undefined ? {} : { expectedLockSha256: options.expectedLockSha256 }),
    ...(options.expectedDependencies === undefined ? {} : { expectedDependencies: options.expectedDependencies }),
    ...(options.expectationOverrides ?? {}),
  };
  const releaseSubject = {
    artifact,
    lockfile,
    sbom,
    conformance: conformance.map((entry) => ({ adapterId: entry.adapterId, bytes: conformanceBytes })),
    scanner: scannerBytes,
  };
  return { evidence, subject: releaseSubject, expectation, payload, conformanceDocument, scannerDocument, signer };
}
