import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  DEPENDENCY_ISSUE_CODES, MAX_SBOM_BYTES, compareDependencyEvidence, readLockedDependencies,
  readSbomComponents,
} from '../dist/dependency-evidence.js';
import {
  PLANTED_CLOAKABLE, SYNTHETIC_INTEGRITY, syntheticLockfile, syntheticLockfileBytes, syntheticSbom,
  syntheticSbomBytes,
} from '../scripts/synthetic-release-substrate.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const encode = (value) => new TextEncoder().encode(value);
const read = (lock = syntheticLockfile()) => ({
  lock: readLockedDependencies(syntheticLockfileBytes(lock)),
  sbom: readSbomComponents(syntheticSbomBytes(syntheticSbom(lock))),
});
const issues = (lockDocument = syntheticLockfile(), sbomDocument = syntheticSbom(lockDocument)) => {
  const { lock } = read(lockDocument);
  return compareDependencyEvidence(lock, readSbomComponents(syntheticSbomBytes(sbomDocument)));
};

test('the lockfile and SBOM are read into the same normalized component set', () => {
  const { lock, sbom } = read();
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(lock.root, { name: 'synthetic-release-app', version: '0.1.0' });
  assert.deepEqual(lock.dependencies.map((entry) => entry.path), [
    'node_modules/synthetic-alpha-parser', 'node_modules/synthetic-beta-normalizer', 'node_modules/synthetic-gamma-sink',
  ]);
  for (const entry of lock.dependencies) {
    assert.match(entry.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/);
    assert.match(entry.resolved, /^https:\/\/registry\.synthetic\.invalid\//);
  }
  assert.equal(sbom.bomFormat, 'CycloneDX');
  assert.equal(sbom.specVersion, '1.5');
  // The root component name npm derives from the checkout directory is deliberately not trusted.
  assert.deepEqual(sbom.root, { name: 'synthetic-checkout-dir', version: '0.1.0' });
  assert.deepEqual(sbom.components.map((entry) => entry.name), [
    'synthetic-alpha-parser', 'synthetic-beta-normalizer', 'synthetic-gamma-sink',
  ]);
  assert.deepEqual(issues(), []);
});

test('a tailored SBOM is detected against the locked dependency set', () => {
  const trimmed = syntheticSbom();
  trimmed.components.pop();
  assert.ok(issues(syntheticLockfile(), trimmed).includes('LOCKED_DEPENDENCY_ABSENT_FROM_SBOM'));
  const empty = syntheticSbom();
  empty.components = [];
  assert.deepEqual(issues(syntheticLockfile(), empty), ['LOCKED_DEPENDENCY_ABSENT_FROM_SBOM']);
});

test('an SBOM component with no locked entry is detected', () => {
  const sbomDocument = syntheticSbom();
  sbomDocument.components.push({
    type: 'library', name: 'synthetic-omega-injected', version: '1.0.0',
    purl: 'pkg:npm/synthetic-omega-injected@1.0.0',
    properties: [{ name: 'cdx:npm:package:path', value: 'node_modules/synthetic-omega-injected' }],
  });
  assert.ok(issues(syntheticLockfile(), sbomDocument).includes('SBOM_COMPONENT_ABSENT_FROM_LOCKFILE'));
  // A component with no npm path property cannot be matched to a locked entry at all.
  const noPath = syntheticSbom();
  delete noPath.components[0].properties;
  assert.ok(issues(syntheticLockfile(), noPath).includes('SBOM_COMPONENT_PATH_MISSING'));
  const duplicate = syntheticSbom();
  duplicate.components.push({ ...duplicate.components[0] });
  assert.ok(issues(syntheticLockfile(), duplicate).includes('SBOM_COMPONENT_DUPLICATE'));
});

test('version, content hash and root version drift are detected', () => {
  const wrongVersion = syntheticSbom();
  wrongVersion.components[1].version = '9.9.9';
  assert.ok(issues(syntheticLockfile(), wrongVersion).includes('DEPENDENCY_VERSION_MISMATCH'));
  const wrongHash = syntheticSbom();
  wrongHash.components[1].hashes = [{ alg: 'SHA-512', content: 'b'.repeat(128) }];
  assert.ok(issues(syntheticLockfile(), wrongHash).includes('DEPENDENCY_CONTENT_MISMATCH'));
  const missingHash = syntheticSbom();
  missingHash.components[1].hashes = [];
  assert.ok(issues(syntheticLockfile(), missingHash).includes('DEPENDENCY_CONTENT_MISSING'));
  const wrongAlgorithm = syntheticSbom();
  wrongAlgorithm.components[1].hashes = [{ alg: 'MD5', content: 'b'.repeat(32) }];
  assert.ok(issues(syntheticLockfile(), wrongAlgorithm).includes('DEPENDENCY_CONTENT_ALGORITHM_UNSUPPORTED'));
  const wrongRoot = syntheticSbom();
  wrongRoot.metadata.component.version = '9.9.9';
  assert.ok(issues(syntheticLockfile(), wrongRoot).includes('LOCKFILE_ROOT_VERSION_MISMATCH'));
});

test('an unpinned or unresolved lockfile entry is detected', () => {
  const unpinned = syntheticLockfile();
  delete unpinned.packages['node_modules/synthetic-alpha-parser'].integrity;
  assert.ok(issues(unpinned).includes('DEPENDENCY_NOT_INTEGRITY_PINNED'));
  // An unsupported algorithm is unusable pin evidence and is refused by the reader, not reported as
  // a comparison issue that could be mistaken for a checked-but-clean entry.
  for (const weak of ['md5-AAAAAAAAAAAAAAAAAAAAAA==', 'sha1-Ym9ndXM=']) {
    const lock = syntheticLockfile();
    lock.packages['node_modules/synthetic-alpha-parser'].integrity = weak;
    assert.throws(() => readLockedDependencies(syntheticLockfileBytes(lock)), /dependency evidence/i);
  }
  const unresolved = syntheticLockfile();
  delete unresolved.packages['node_modules/synthetic-alpha-parser'].resolved;
  assert.ok(issues(unresolved).includes('DEPENDENCY_RESOLUTION_MISSING'));
});

test('B4: a malformed integrity pin is refused instead of silently skipping the content check', () => {
  for (const [label, value] of [
    ['not base64', 'sha512-!!!not-base64!!!'],
    ['wrong decoded length', `sha512-${Buffer.alloc(32, 0x41).toString('base64')}`],
    ['unsupported algorithm', 'sha1-Ym9ndXM='],
    ['missing separator', 'sha512bogus'],
    ['non-canonical padding', 'sha512-QUJD='],
  ]) {
    const lock = syntheticLockfile();
    lock.packages['node_modules/synthetic-alpha-parser'].integrity = value;
    assert.throws(() => readLockedDependencies(syntheticLockfileBytes(lock)),
      /dependency evidence/i, `a ${label} pin must be refused at parse time`);
  }
  // A supported but non-SHA-512 pin cannot be cross-checked against the SBOM's SHA-512, so the
  // content binding is unproven and must be reported rather than skipped in silence.
  const sha256Lock = syntheticLockfile();
  sha256Lock.packages['node_modules/synthetic-alpha-parser'].integrity = `sha256-${Buffer.alloc(32, 0x42).toString('base64')}`;
  const { lock: locked256, sbom: sbom256 } = read(sha256Lock);
  assert.ok(compareDependencyEvidence(locked256, sbom256).includes('DEPENDENCY_CONTENT_ALGORITHM_UNSUPPORTED'));
  // Control: a well-formed SHA-512 pin with a matching SBOM content hash reports nothing.
  assert.deepEqual(issues(), []);
});

test('an independently published dependency set is enforced in both directions', () => {
  const { lock, sbom } = read();
  const published = lock.dependencies.map((entry) => ({ name: entry.name, version: entry.version }));
  assert.deepEqual(compareDependencyEvidence(lock, sbom, published), []);
  assert.deepEqual(compareDependencyEvidence(lock, sbom, published.slice(0, 2)), ['DEPENDENCY_NOT_IN_PUBLISHED_SET']);
  assert.deepEqual(compareDependencyEvidence(lock, sbom, []), ['DEPENDENCY_NOT_IN_PUBLISHED_SET']);
  const extended = syntheticLockfile();
  extended.packages['node_modules/synthetic-zeta-new'] = {
    version: '1.1.1',
    resolved: 'https://registry.synthetic.invalid/synthetic-zeta-new/-/synthetic-zeta-new-1.1.1.tgz',
    integrity: SYNTHETIC_INTEGRITY['synthetic-zeta-new'],
  };
  const { lock: newLock, sbom: newSbom } = read(extended);
  assert.deepEqual(compareDependencyEvidence(newLock, newSbom, published), ['DEPENDENCY_NOT_IN_PUBLISHED_SET']);
});

test('malformed and bounded dependency evidence is refused with fixed codes and no echo', () => {
  const plant = `{"lockfileVersion":3,"note":"${PLANTED_CLOAKABLE}","packages":{}}`;
  for (const bytes of [encode(''), encode('{'), encode('[]'), encode('null'), encode(plant), Buffer.from([0xff, 0xfe]),
    encode('{"lockfileVersion":1,"packages":{}}'), encode('{"lockfileVersion":3}'),
    encode('{"lockfileVersion":3,"packages":null}')]) {
    assert.throws(() => readLockedDependencies(bytes), (error) => {
      assert.match(error.message, /dependency evidence/i);
      assert.ok(!error.message.includes(PLANTED_CLOAKABLE));
      return true;
    });
  }
  for (const bytes of [encode(''), encode('{'), encode('[]'), encode('{"bomFormat":"SPDX"}'),
    encode('{"bomFormat":"CycloneDX"}'), encode('{"bomFormat":"CycloneDX","specVersion":"9.9","components":[]}'),
    encode('{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library"}]}'),
    Buffer.concat([Buffer.from('{"bomFormat":"CycloneDX","specVersion":"1.5","components":['), Buffer.alloc(MAX_SBOM_BYTES, 0x20)])]) {
    assert.throws(() => readSbomComponents(bytes), /dependency evidence/i);
  }
  // Deeply nested JSON is refused rather than walked.
  const deep = `${'['.repeat(4096)}${']'.repeat(4096)}`;
  assert.throws(() => readLockedDependencies(encode(`{"lockfileVersion":3,"packages":${deep}}`)), /dependency evidence/i);
  const deepSbom = `${'['.repeat(4096)}${']'.repeat(4096)}`;
  assert.throws(() => readSbomComponents(encode(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":${deepSbom}}`)),
    /dependency evidence/i);
});

test('non-registry entries, links and root shapes are reported rather than guessed', () => {
  const lock = syntheticLockfile();
  lock.packages['vendor/synthetic-local-copy'] = { version: '1.0.0', link: true };
  const withLink = readLockedDependencies(syntheticLockfileBytes(lock));
  const entry = withLink.dependencies.find((item) => item.path === 'vendor/synthetic-local-copy');
  assert.deepEqual({ path: entry.path, name: entry.name, link: entry.link },
    { path: 'vendor/synthetic-local-copy', name: 'vendor/synthetic-local-copy', link: true });
  // A link entry legitimately has no registry resolution, and it is not in the npm SBOM either.
  const codes = compareDependencyEvidence(withLink, readSbomComponents(syntheticSbomBytes(syntheticSbom())));
  assert.ok(codes.includes('LOCKED_DEPENDENCY_ABSENT_FROM_SBOM'));
  assert.equal(codes.includes('DEPENDENCY_RESOLUTION_MISSING'), false);
  const noRoot = syntheticLockfile();
  delete noRoot.packages[''];
  assert.throws(() => readLockedDependencies(syntheticLockfileBytes(noRoot)), /dependency evidence/i);
  const traversal = syntheticLockfile();
  traversal.packages['node_modules/../../escape'] = { version: '1.0.0' };
  assert.throws(() => readLockedDependencies(syntheticLockfileBytes(traversal)), /dependency evidence/i);
  // A component that is not an object, and a properties member that is not a list, are refused.
  const notAComponent = { bomFormat: 'CycloneDX', specVersion: '1.5', components: ['synthetic-alpha-parser'] };
  assert.throws(() => readSbomComponents(encode(`${JSON.stringify(notAComponent, null, 2)}\n`)),
    /dependency evidence/i);
  const badProperties = syntheticSbom();
  badProperties.components[0].properties = { name: 'cdx:npm:package:path' };
  assert.throws(() => readSbomComponents(syntheticSbomBytes(badProperties)), /dependency evidence/i);
});

test('every reported issue code is part of the published fixed set', () => {
  const wrongVersion = syntheticSbom();
  wrongVersion.components[1].version = '9.9.9';
  const wrongHash = syntheticSbom();
  wrongHash.components[1].hashes = [{ alg: 'SHA-512', content: 'b'.repeat(128) }];
  for (const code of issues(syntheticLockfile(), wrongVersion).concat(issues(syntheticLockfile(), wrongHash))) {
    assert.ok(DEPENDENCY_ISSUE_CODES.includes(code), code);
  }
});

test('this repository lockfile matches its own ephemeral CycloneDX SBOM', () => {
  const sbom = spawnSync('npm', ['run', '--silent', 'sbom'], { cwd: root, encoding: 'buffer', timeout: 120_000, maxBuffer: 64 << 20 });
  assert.equal(sbom.status, 0, `npm sbom failed: ${sbom.stderr?.toString('utf8').slice(0, 200)}`);
  const lock = readLockedDependencies(readFileSync(join(root, 'package-lock.json')));
  const components = readSbomComponents(sbom.stdout);
  assert.equal(components.bomFormat, 'CycloneDX');
  assert.equal(components.specVersion, '1.5');
  assert.ok(components.components.length > 0, 'the ephemeral SBOM must not be empty');
  assert.deepEqual(compareDependencyEvidence(lock, components), []);
  // Every locked entry is integrity pinned, which is the pinning invariant this repository relies on.
  for (const entry of lock.dependencies) {
    assert.match(entry.integrity, /^sha(256|384|512)-/);
  }
  // A tailored copy of the real SBOM is detected against the real lockfile.
  const tailored = JSON.parse(sbom.stdout.toString('utf8'));
  const lockedCount = lock.dependencies.length;
  tailored.components = tailored.components.slice(1, lockedCount);
  assert.ok(lockedCount >= 1, 'the locked tree must be non-empty for this negative to mean anything');
  const tailoredBytes = encode(`${JSON.stringify(tailored, null, 2)}\n`);
  assert.ok(compareDependencyEvidence(lock, readSbomComponents(tailoredBytes))
    .includes('LOCKED_DEPENDENCY_ABSENT_FROM_SBOM'));
  // The same document with a hand-added duplicate key is not accepted as an SBOM at all.
  const duplicated = Buffer.concat([Buffer.from('{"bomFormat":"CycloneDX",'), Buffer.from(sbom.stdout)]);
  assert.throws(() => readSbomComponents(duplicated), /dependency evidence/i);
});
