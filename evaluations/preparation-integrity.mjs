#!/usr/bin/env node
/**
 * NON-NORMATIVE, NON-ENFORCING public #39 preparation integrity aid.
 * There is no approval, release, scoring, candidate, route, capture or blind-data API.
 * Only fixed repository-relative PUBLIC development files are read and hashed.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { devNull } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST = 'docs/research/issue-39-v0-preparation-draft-p0.1.json';
// These identifiers are NOT file paths supplied by the draft, caller, command line or environment.
const PUBLIC = Object.freeze({
  CORPUS_PREP: 'docs/research/issue-39-corpus-protocol-prep-p0.1.md',
  DEV_FIXTURE: 'docs/research/issue-39-public-development-fixtures-p0.1.json',
  DEV_ORACLE_PROPOSAL: 'docs/research/issue-39-public-development-oracle-p0.1.json',
  DEV_RUBRIC_PROPOSAL: 'docs/research/issue-39-public-rubric-p0.1.md',
  OPEN_GATES: 'docs/research/issue-39-v0-open-gates-p0.1.md',
});
const NAMES = Object.freeze([MANIFEST, ...Object.values(PUBLIC)]);
const MAX_FILE_BYTES = 512 * 1024;
const VALID = Object.freeze({ status: 'PREPARATION_VALID_BUT_NOT_ELIGIBLE', reason: 'PUBLIC_DRAFT_ONLY' });
const DENIED = Object.freeze({ status: 'SCORED_V0_DENIED', reason: 'EXTERNAL_APPROVAL_BOUNDARY_ABSENT' });
const invalid = (reason) => ({ status: 'PREPARATION_INVALID', reason });

class PreparationFailure extends Error {
  constructor(reason) { super('Public preparation check failed'); this.reason = reason; }
}
function fail(reason) { throw new PreparationFailure(reason); }
function shape(value, names) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype) fail('SCHEMA_INVALID');
  const keys = Object.keys(value);
  if (keys.length !== names.length || keys.some((key) => !names.includes(key))) fail('SCHEMA_INVALID');
  return value;
}
function literalArray(value, names) {
  if (!Array.isArray(value) || value.length !== names.length ||
      value.some((item, index) => item !== names[index])) fail('SCHEMA_INVALID');
}
function validateDraft(input) {
  const draft = shape(input, ['schemaVersion', 'draftId', 'normative', 'enforcing', 'protocolVersion',
    'frozen', 'scored', 'releaseAuthority', 'gates', 'observations', 'publicSha256']);
  if (draft.schemaVersion !== 1 || draft.draftId !== 'issue-39-v0-preparation-draft-p0.1' ||
      draft.normative !== false || draft.enforcing !== false || draft.protocolVersion !== null ||
      draft.frozen !== false || draft.scored !== false || draft.releaseAuthority !== false) fail('SCHEMA_INVALID');
  const gates = shape(draft.gates, ['scope', 'destinationPolicyTreatments', 'independentTaskRubric',
    'blindCustody', 'candidateEligibilityChronology']);
  if (Object.values(gates).some((state) => state !== 'PENDING')) fail('SCHEMA_INVALID');
  const observations = shape(draft.observations, ['preparationSourceRevision', 'referenceEligibility',
    'publicDevProposal', 'otherDevelopmentFamilies', 'blindFamilies', 'actualRouteAndCapture',
    'preTuningLock', 'finalV0Freeze']);
  if (typeof observations.preparationSourceRevision !== 'string' ||
      !/^[0-9a-f]{40}$/.test(observations.preparationSourceRevision) ||
      observations.referenceEligibility !== 'EXPLORATORY_INELIGIBLE_PRE_LOCK' ||
      observations.otherDevelopmentFamilies !== 'PLANNING_UNTESTED' ||
      observations.blindFamilies !== 'PLANNING_UNTESTED' ||
      observations.actualRouteAndCapture !== 'NOT_ESTABLISHED' ||
      observations.preTuningLock !== 'NOT_ESTABLISHED' ||
      observations.finalV0Freeze !== 'NOT_ESTABLISHED') fail('SCHEMA_INVALID');
  literalArray(observations.publicDevProposal, ['D01', 'D02', 'D05']);
  const hashes = shape(draft.publicSha256, Object.keys(PUBLIC));
  if (Object.values(hashes).some((hash) => typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash))) {
    fail('SCHEMA_INVALID');
  }
  return { revision: observations.preparationSourceRevision, hashes };
}

function assertRegularPublicPath(name) {
  // The only caller passes literals from NAMES. Check EVERY directory component, not just
  // the leaf: an ancestor symlink must never redirect a read outside this checkout.
  let current = root;
  const parts = name.split('/');
  for (const [index, part] of parts.entries()) {
    if (!part || part === '.' || part === '..' || part.includes(sep)) fail('PUBLIC_FILE_UNSAFE');
    current = join(current, part);
    let entry;
    try { entry = lstatSync(current); }
    catch (error) {
      if (error?.code === 'ENOENT') fail('PUBLIC_FILE_MISSING');
      fail('CHECK_UNAVAILABLE');
    }
    if (entry.isSymbolicLink() ||
        (index === parts.length - 1 ? !entry.isFile() || entry.nlink !== 1 : !entry.isDirectory())) {
      fail('PUBLIC_FILE_UNSAFE');
    }
  }
  return current;
}
function readRegularPublic(name) {
  const current = assertRegularPublicPath(name);
  // O_NOFOLLOW refuses a swapped leaf; the realpath check also rejects a redirected ancestor.
  let descriptor;
  try {
    if (realpathSync(current) !== current || realpathSync(root) !== root) fail('PUBLIC_FILE_UNSAFE');
    descriptor = openSync(current, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_FILE_BYTES) fail('PUBLIC_FILE_UNSAFE');
    const content = readFileSync(descriptor);
    if (content.length > MAX_FILE_BYTES) fail('PUBLIC_FILE_UNSAFE');
    return content;
  } catch (error) {
    if (error instanceof PreparationFailure) throw error;
    if (error?.code === 'ENOENT') fail('PUBLIC_FILE_MISSING');
    if (error?.code === 'ELOOP') fail('PUBLIC_FILE_UNSAFE');
    fail('CHECK_UNAVAILABLE');
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function git(args, raw = false) {
  // Ignore caller Git overrides and global/system config, including fsmonitor helpers.
  // No hooks, filters or diff drivers are needed: cat-file reads raw object bytes,
  // ls-tree/index read metadata only, and local fsmonitor is explicitly disabled.
  const env = {
    ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_'))),
    GIT_CONFIG_GLOBAL: devNull, GIT_CONFIG_NOSYSTEM: '1', GIT_NO_REPLACE_OBJECTS: '1',
    HOME: devNull, XDG_CONFIG_HOME: devNull,
  };
  const result = spawnSync('git', ['-c', 'core.fsmonitor=false', '-c', `core.hooksPath=${devNull}`,
    '-C', root, ...args], {
    encoding: raw ? 'buffer' : 'utf8', maxBuffer: raw ? MAX_FILE_BYTES + 8192 : 64 * 1024,
    timeout: 15_000, windowsHide: true, env,
  });
  if (result.error || result.signal || result.status === null) fail('CHECK_UNAVAILABLE');
  return { status: result.status, stdout: result.stdout };
}
function requireRepositoryAndIndex() {
  const location = git(['rev-parse', '--show-toplevel']);
  if (location.status !== 0 || resolve(location.stdout.trimEnd()) !== root) fail('CHECK_UNAVAILABLE');
  // A repository-local graft can fabricate revision ancestry even with Git replacement
  // objects disabled. Git resolves the worktree's own metadata path; never read or echo it.
  const graft = git(['rev-parse', '--git-path', 'info/grafts']);
  if (graft.status !== 0 || !graft.stdout.trimEnd() || /[\r\n\0]/u.test(graft.stdout.trimEnd())) {
    fail('CHECK_UNAVAILABLE');
  }
  try { lstatSync(resolve(root, graft.stdout.trimEnd())); fail('GIT_REVISION_INVALID'); }
  catch (error) {
    if (error instanceof PreparationFailure) throw error;
    if (error?.code !== 'ENOENT') fail('CHECK_UNAVAILABLE');
  }
  const index = git(['ls-files', '--stage', '-z', '--', ...NAMES]);
  if (index.status !== 0) fail('CHECK_UNAVAILABLE');
  const found = new Map();
  for (const line of index.stdout.split('\0').filter(Boolean)) {
    const entry = /^(100644) ([0-9a-f]{40,64}) 0\t(.+)$/u.exec(line);
    if (!entry || !NAMES.includes(entry[3]) || found.has(entry[3])) fail('PUBLIC_FILE_UNSAFE');
    found.set(entry[3], entry[2]);
  }
  if (found.size !== NAMES.length) fail('PUBLIC_FILE_UNTRACKED');
  // Compare index objects explicitly to HEAD: skip-worktree / assume-unchanged may
  // otherwise hide staged divergence from a worktree-oriented diff.
  const tree = git(['ls-tree', '-r', '-z', 'HEAD', '--', ...NAMES]);
  if (tree.status !== 0) fail('CHECK_UNAVAILABLE');
  const head = new Map();
  for (const line of tree.stdout.split('\0').filter(Boolean)) {
    const entry = /^(100644) blob ([0-9a-f]{40,64})\t(.+)$/u.exec(line);
    if (!entry || !NAMES.includes(entry[3]) || head.has(entry[3])) fail('PUBLIC_FILE_CHANGED');
    head.set(entry[3], entry[2]);
  }
  if (head.size !== NAMES.length || NAMES.some((name) => found.get(name) !== head.get(name))) {
    fail('PUBLIC_FILE_CHANGED');
  }
}
function assertHeadBytes(name, bytes) {
  // These are fixed literal paths. cat-file returns a RAW HEAD blob, not a filtered
  // checkout, and we neither print nor hash its contents. HEAD and manifest are
  // unkeyed reproducibility anchors only, never external attestations or authority.
  const blob = git(['cat-file', 'blob', `HEAD:${name}`], true);
  if (blob.status !== 0) fail('PUBLIC_FILE_CHANGED');
  if (!blob.stdout.equals(bytes)) fail('PUBLIC_FILE_CHANGED');
}
function assertSourceRevision(revision) {
  const commit = git(['rev-parse', '--verify', '--quiet', `${revision}^{commit}`]);
  if (commit.status !== 0 || commit.stdout.trimEnd() !== revision) fail('GIT_REVISION_INVALID');
  const ancestry = git(['merge-base', '--is-ancestor', revision, 'HEAD']);
  if (ancestry.status !== 0) fail('GIT_REVISION_INVALID');
}

/** No parameters or path selectors. Success is ONLY integrity of an unapproved public draft. */
export function verifyPreparation(...args) {
  if (args.length) return invalid('INPUT_REJECTED');
  try {
    // Reject missing and redirected paths before Git comparison; do not read untracked bytes.
    for (const name of NAMES) assertRegularPublicPath(name);
    requireRepositoryAndIndex();
    let manifest;
    try {
      const bytes = readRegularPublic(MANIFEST);
      assertHeadBytes(MANIFEST, bytes);
      manifest = JSON.parse(bytes.toString('utf8'));
      // Canonical form rejects ignored duplicate JSON keys, unknown escaped keys and
      // non-UTF-8 replacement decoding; last-wins parsing is not an integrity rule.
      if (!bytes.equals(Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8'))) fail('SCHEMA_INVALID');
    } catch (error) {
      if (error instanceof PreparationFailure) throw error;
      fail('SCHEMA_INVALID');
    }
    const { revision, hashes } = validateDraft(manifest);
    assertSourceRevision(revision);
    for (const [id, name] of Object.entries(PUBLIC)) {
      const bytes = readRegularPublic(name);
      assertHeadBytes(name, bytes);
      const actual = createHash('sha256').update(bytes).digest('hex');
      if (actual !== hashes[id]) fail('PUBLIC_HASH_MISMATCH');
    }
    return VALID;
  } catch (error) {
    return invalid(error instanceof PreparationFailure ? error.reason : 'CHECK_UNAVAILABLE');
  }
}

/** Always deny. No self-attested draft field can cross a future external approval boundary. */
export function requireScoredV0() { return DENIED; }

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = process.argv.length === 2 ? verifyPreparation() : invalid('INPUT_REJECTED');
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.status !== 'PREPARATION_VALID_BUT_NOT_ELIGIBLE') process.exitCode = 1;
}
