#!/usr/bin/env node
/**
 * #33 release gate command line: the exact release-boundary invocation.
 *
 *   node dist/release-gate-cli.js <evidence.json> <expectation.json> <subject-dir>
 *
 * It reads exactly those three paths, verifies the evidence against the bytes in the subject
 * directory, prints one JSON object of fixed codes on stdout and exits 0 only for
 * `RELEASE_EVIDENCE_VERIFIED`. It never signs, writes, publishes, promotes or contacts a network,
 * and it never prints a path, digest, package name, key id or subject byte.
 *
 * TRUST BOUNDARY: the expectation file is the trusted input. This command authenticates nothing
 * about where that file came from: obtain it from the release owner's reviewed configuration or from
 * the release environment, never from the build that produced the artifact. A verified result is a
 * necessary, not sufficient, release condition, and `now` inside the expectation file is only as
 * trustworthy as that file.
 */
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { RELEASE_EXPECTATION_FORMAT, verifyReleaseEvidence } from './release-integrity.js';
import type { ReleaseDenialCode, ReleaseExpectation } from './release-integrity.js';

const MAX_EVIDENCE = 256 * 1024;
const MAX_EXPECTATION = 256 * 1024;
const MAX_ARTIFACT = 512 << 20;
const MAX_ATTESTATION = 4 << 20;
const MAX_LOCKFILE = 8 << 20;
const MAX_SBOM = 32 << 20;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const USAGE = 'usage: release-gate-cli <evidence.json> <expectation.json> <subject-dir>\n';

class GateInputFailure extends Error {
  constructor(readonly codes: readonly ReleaseDenialCode[]) {
    super('release gate input is unusable');
    this.name = 'GateInputFailure';
  }
}
function emit(status: 'RELEASE_EVIDENCE_VERIFIED' | 'RELEASE_PROMOTION_DENIED', reasons: readonly string[]): void {
  process.stdout.write(`${JSON.stringify({ status, reasons })}\n`);
  process.exitCode = status === 'RELEASE_EVIDENCE_VERIFIED' ? 0 : 1;
}
/**
 * Read one named file inside a directory. The name is a single plain path component, every
 * component is refused if it is a symlink, the file must be singly linked and regular and its size
 * is bounded, so a redirected or swapped path cannot make the gate verify bytes other than the ones
 * offered at the boundary.
 */
function readBoundedFile(directory: string, name: unknown, max: number): Uint8Array {
  if (typeof name !== 'string' || name.length === 0 || !SAFE_NAME.test(name) || isAbsolute(name)) {
    throw new GateInputFailure(['CHECK_UNAVAILABLE']);
  }
  let descriptor: number | undefined;
  try {
    if (realpathSync(directory) !== directory) throw new GateInputFailure(['CHECK_UNAVAILABLE']);
    const path = join(directory, name);
    if (lstatSync(path).isSymbolicLink()) throw new GateInputFailure(['CHECK_UNAVAILABLE']);
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size === 0 || stat.size > max) {
      throw new GateInputFailure(['CHECK_UNAVAILABLE']);
    }
    const bytes = readFileSync(descriptor);
    if (bytes.length === 0 || bytes.length > max) throw new GateInputFailure(['CHECK_UNAVAILABLE']);
    return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  } catch (error) {
    if (error instanceof GateInputFailure) throw error;
    throw new GateInputFailure(['CHECK_UNAVAILABLE']);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}
/**
 * The trusted expectation file may be laid out compact or indented, but it must be a faithful
 * serialization of its own parse. That still refuses duplicate JSON keys, alternative number
 * spellings and hand-edited escapes in the file that defines the trust anchors.
 */
function readExpectationFile(path: string): ReleaseExpectation {
  const bytes = readBoundedFile(resolve(path, '..'), basename(path), MAX_EXPECTATION);
  let text: string;
  let parsed: unknown;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    parsed = JSON.parse(text);
  } catch { throw new GateInputFailure(['EXPECTATION_INVALID']); }
  const accepted = [JSON.stringify(parsed), JSON.stringify(parsed, null, 2), `${JSON.stringify(parsed, null, 2)}\n`];
  if (!accepted.includes(text) || parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new GateInputFailure(['EXPECTATION_INVALID']);
  }
  return parsed as unknown as ReleaseExpectation;
}

export function main(argv: readonly string[]): void {
  const args = argv.slice(2);
  if (args.length !== 3) {
    process.stderr.write(USAGE);
    process.exitCode = 2;
    return;
  }
  // Resolve inside the guarded region: `main` is exported, so a non-string element must be a usage
  // error rather than an uncaught throw.
  if (args.some((value) => typeof value !== 'string' || value.length === 0)) {
    process.stderr.write(USAGE);
    process.exitCode = 2;
    return;
  }
  const resolved = args.map((value) => resolve(value));
  const evidencePath = resolved[0];
  const expectationPath = resolved[1];
  const subjectDirectory = resolved[2];
  if (evidencePath === undefined || expectationPath === undefined || subjectDirectory === undefined) {
    process.stderr.write(USAGE);
    process.exitCode = 2;
    return;
  }
  try {
    const expectation = readExpectationFile(expectationPath);
    if (expectation.format !== RELEASE_EXPECTATION_FORMAT) throw new GateInputFailure(['EXPECTATION_INVALID']);
    const described = (expectation as unknown as { subject?: Record<string, unknown> }).subject;
    if (described === null || typeof described !== 'object' || Array.isArray(described)) {
      throw new GateInputFailure(['EXPECTATION_INVALID']);
    }
    let evidence: Uint8Array;
    try { evidence = readBoundedFile(resolve(evidencePath, '..'), basename(evidencePath), MAX_EVIDENCE); }
    catch { throw new GateInputFailure(['EVIDENCE_MISSING']); }
    const conformanceList = Array.isArray(described['conformance']) ? described['conformance'] : [];
    const subject = {
      artifact: readBoundedFile(subjectDirectory, described['artifact'], MAX_ARTIFACT),
      lockfile: readBoundedFile(subjectDirectory, described['lockfile'], MAX_LOCKFILE),
      sbom: readBoundedFile(subjectDirectory, described['sbom'], MAX_SBOM),
      scanner: readBoundedFile(subjectDirectory, described['scanner'], MAX_ATTESTATION),
      conformance: conformanceList.map((item) => {
        const entry = (item ?? {}) as { adapterId?: unknown; file?: unknown };
        return {
          adapterId: typeof entry.adapterId === 'string' ? entry.adapterId : '',
          bytes: readBoundedFile(subjectDirectory, entry.file, MAX_ATTESTATION),
        };
      }),
    };
    const result = verifyReleaseEvidence({ evidence, subject, expectation });
    emit(result.status, result.reasons);
  } catch (error) {
    // Any unreadable, redirected, oversized or malformed input is a denial with a fixed code.
    // Fixed codes only: a path, an OS error message and a subject byte never reach stdout.
    emit('RELEASE_PROMOTION_DENIED', error instanceof GateInputFailure ? error.codes : ['CHECK_UNAVAILABLE']);
  }
}

// Only the direct invocation runs the gate; importing this module for tests is side-effect free.
if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) main(process.argv);
