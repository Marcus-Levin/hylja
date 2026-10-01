#!/usr/bin/env node
/**
 * #33 ephemeral SBOM semantic check.
 *
 *   npm run --silent sbom | node scripts/check-sbom.mjs
 *   node scripts/check-sbom.mjs <sbom.json> [package-lock.json]
 *
 * A parseable SBOM is not evidence. This reduces the CycloneDX document and the lockfile to the same
 * normalized dependency set and requires them to be identical, so a truncated, tailored or invented
 * SBOM fails here instead of being waved through as valid JSON. It prints one fixed status and one
 * code list, never a package name, version, path or digest, and it writes nothing.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { compareDependencyEvidence, readLockedDependencies, readSbomComponents } from '../dist/dependency-evidence.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MAX = 64 << 20;

function finish(status, codes) {
  process.stdout.write(`${JSON.stringify({ status, codes })}\n`);
  process.exitCode = status === 'DEPENDENCY_EVIDENCE_CONSISTENT' ? 0 : 1;
}
/**
 * Read one named file. The path comes from the operator, so the only bounds that matter here are
 * the size cap and the refusal to report anything read: no symlink following, no echo, no write.
 */
function readBounded(path) {
  const bytes = readFileSync(resolve(path));
  if (bytes.length === 0 || bytes.length > MAX) throw new Error('UNUSABLE');
  return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}
function ephemeralSbom() {
  const result = spawnSync('npm', ['run', '--silent', 'sbom'], { cwd: root, maxBuffer: MAX, timeout: 120_000 });
  if (result.error || result.status !== 0 || !result.stdout || result.stdout.length === 0) throw new Error('UNUSABLE');
  return new Uint8Array(result.stdout.buffer, result.stdout.byteOffset, result.stdout.byteLength);
}

const [, , sbomArgument, lockArgument] = process.argv;
try {
  const sbom = sbomArgument === undefined ? ephemeralSbom() : readBounded(sbomArgument);
  const lock = readBounded(lockArgument ?? join(root, 'package-lock.json'));
  const codes = compareDependencyEvidence(readLockedDependencies(lock), readSbomComponents(sbom));
  if (codes.length > 0) finish('DEPENDENCY_EVIDENCE_MISMATCH', codes);
  else finish('DEPENDENCY_EVIDENCE_CONSISTENT', []);
} catch {
  // Never print a parser reason, a path, an OS message or any part of the documents.
  finish('DEPENDENCY_EVIDENCE_UNUSABLE', ['DEPENDENCY_EVIDENCE_UNUSABLE']);
}
