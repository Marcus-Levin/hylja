import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync, appendFileSync, linkSync, existsSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { requireScoredV0 } from './preparation-integrity.mjs';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifestName = 'docs/research/issue-39-v0-preparation-draft-p0.1.json';
const scriptName = 'evaluations/preparation-integrity.mjs';
const publicNames = [
  'docs/research/issue-39-corpus-protocol-prep-p0.1.md',
  'docs/research/issue-39-public-development-fixtures-p0.1.json',
  'docs/research/issue-39-public-development-oracle-p0.1.json',
  'docs/research/issue-39-public-rubric-p0.1.md',
  'docs/research/issue-39-v0-open-gates-p0.1.md',
];
const fixtureName = publicNames[1];
const oracleName = publicNames[2];
const planted = 'synthetic-do-not-echo-probe.invalid';

function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim();
}
function commit(root, message) {
  git(root, '-c', 'user.name=Synthetic Test', '-c', 'user.email=test@example.invalid',
    'commit', '--quiet', '-m', message);
}
function setup(t) {
  // All adversarial paths and Git operations are confined to a disposable synthetic repo.
  const disposable = mkdtempSync(join(tmpdir(), 'hylja-preparation-test-'));
  t.after(() => rmSync(disposable, { recursive: true, force: true }));
  const root = join(disposable, 'repo');
  mkdirSync(root);
  for (const name of [...publicNames, scriptName]) {
    mkdirSync(dirname(join(root, name)), { recursive: true });
    cpSync(join(sourceRoot, name), join(root, name));
  }
  git(root, 'init', '--quiet', '--initial-branch=main');
  git(root, 'add', '--', ...publicNames, scriptName);
  commit(root, 'synthetic public source observation');
  const manifest = JSON.parse(readFileSync(join(sourceRoot, manifestName), 'utf8'));
  manifest.observations.preparationSourceRevision = git(root, 'rev-parse', 'HEAD');
  writeFileSync(join(root, manifestName), `${JSON.stringify(manifest, null, 2)}\n`);
  git(root, 'add', '--', manifestName);
  commit(root, 'synthetic preparation draft');
  return { root, disposable, manifest, script: join(root, scriptName) };
}
function replaceManifest({ root, manifest }, mutate) {
  mutate(manifest);
  writeFileSync(join(root, manifestName), `${JSON.stringify(manifest, null, 2)}\n`);
  git(root, 'add', '--', manifestName);
  commit(root, 'synthetic manifest change');
}
async function verify(context) {
  const { verifyPreparation } = await import(pathToFileURL(context.script).href);
  return verifyPreparation();
}
const valid = { status: 'PREPARATION_VALID_BUT_NOT_ELIGIBLE', reason: 'PUBLIC_DRAFT_ONLY' };
const invalid = (reason) => ({ status: 'PREPARATION_INVALID', reason });

test('intact tracked public bytes and all PENDING choices are preparation-only, never scored', async (t) => {
  const context = setup(t);
  assert.deepEqual(await verify(context), valid);
  assert.deepEqual(requireScoredV0(), {
    status: 'SCORED_V0_DENIED', reason: 'EXTERNAL_APPROVAL_BOUNDARY_ABSENT',
  });
});

test('an unstaged or staged public change cannot be pinned by an unchanged manifest', async (t) => {
  const context = setup(t);
  appendFileSync(join(context.root, fixtureName), `\n${planted}\n`);
  assert.deepEqual(await verify(context), invalid('PUBLIC_FILE_CHANGED'));
  git(context.root, 'add', '--', fixtureName);
  assert.deepEqual(await verify(context), invalid('PUBLIC_FILE_CHANGED'));
});

test('staged index divergence is rejected even when public worktree bytes match HEAD', async (t) => {
  const context = setup(t);
  const file = join(context.root, fixtureName);
  const original = readFileSync(file);
  appendFileSync(file, `\n${planted}\n`);
  git(context.root, 'add', '--', fixtureName);
  writeFileSync(file, original);
  assert.deepEqual(await verify(context), invalid('PUBLIC_FILE_CHANGED'));
});

test('assume-unchanged and skip-worktree cannot conceal matching modified public bytes and draft', async (t) => {
  for (const flag of ['--assume-unchanged', '--skip-worktree']) {
    await t.test(flag, async (subtest) => {
      const context = setup(subtest);
      const fixture = join(context.root, fixtureName);
      appendFileSync(fixture, `\n${planted}\n`);
      context.manifest.publicSha256.DEV_FIXTURE = createHash('sha256')
        .update(readFileSync(fixture)).digest('hex');
      writeFileSync(join(context.root, manifestName), `${JSON.stringify(context.manifest, null, 2)}\n`);
      git(context.root, 'update-index', flag, '--', fixtureName, manifestName);
      const hidden = spawnSync('git', ['-C', context.root, 'diff', '--quiet', 'HEAD', '--', fixtureName, manifestName]);
      assert.equal(hidden.status, 0);
      assert.deepEqual(await verify(context), invalid('PUBLIC_FILE_CHANGED'));
      const cli = spawnSync(process.execPath, [context.script], { cwd: context.root, encoding: 'utf8' });
      assert.equal(cli.status, 1);
      assert.deepEqual(JSON.parse(cli.stdout), invalid('PUBLIC_FILE_CHANGED'));
      assert.equal(cli.stderr, '');
      assert.equal(cli.stdout.includes(planted), false);
      assert.equal(cli.stdout.includes(context.manifest.publicSha256.DEV_FIXTURE), false);
    });
  }
});

test('global Git fsmonitor cannot run a helper during valid public preparation', (t) => {
  const context = setup(t);
  const home = join(context.disposable, 'synthetic-home');
  mkdirSync(home);
  const marker = join(home, 'hook-invoked');
  const helper = join(home, 'synthetic-fsmonitor.sh');
  writeFileSync(helper, `#!/bin/sh\nprintf 'invoked' > '${marker}'\nexit 0\n`);
  chmodSync(helper, 0o755);
  writeFileSync(join(home, '.gitconfig'), `[core]\n  fsmonitor = ${helper}\n`);
  const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: home };
  delete env.GIT_CONFIG_GLOBAL;
  delete env.GIT_CONFIG_NOSYSTEM;
  const cli = spawnSync(process.execPath, [context.script], { cwd: context.root, encoding: 'utf8', env });
  assert.equal(cli.status, 0);
  assert.deepEqual(JSON.parse(cli.stdout), valid);
  assert.equal(cli.stderr, '');
  assert.equal(existsSync(marker), false);
});

test('a committed hash mismatch is rejected without exposing the source hash', async (t) => {
  const context = setup(t);
  replaceManifest(context, (manifest) => { manifest.publicSha256.DEV_FIXTURE = '0'.repeat(64); });
  assert.deepEqual(await verify(context), invalid('PUBLIC_HASH_MISMATCH'));
});

test('missing or untracked allowlisted public files are rejected', async (t) => {
  const missing = setup(t);
  rmSync(join(missing.root, fixtureName));
  assert.deepEqual(await verify(missing), invalid('PUBLIC_FILE_MISSING'));
  const untracked = setup(t);
  git(untracked.root, 'rm', '--cached', '--quiet', '--', oracleName);
  assert.deepEqual(await verify(untracked), invalid('PUBLIC_FILE_UNTRACKED'));
});

test('symlinked public file and symlinked parent cannot redirect the verifier', async (t) => {
  const leaf = setup(t);
  const outside = join(leaf.disposable, 'outside.synthetic');
  writeFileSync(outside, planted);
  rmSync(join(leaf.root, fixtureName));
  symlinkSync(outside, join(leaf.root, fixtureName));
  assert.deepEqual(await verify(leaf), invalid('PUBLIC_FILE_UNSAFE'));
  const parent = setup(t);
  const detached = join(parent.disposable, 'outside-research');
  renameSync(join(parent.root, 'docs/research'), detached);
  symlinkSync(detached, join(parent.root, 'docs/research'));
  assert.deepEqual(await verify(parent), invalid('PUBLIC_FILE_UNSAFE'));
});

test('a hardlinked public path cannot silently read another path to the same inode', async (t) => {
  const context = setup(t);
  linkSync(join(context.root, fixtureName), join(context.disposable, 'outside.synthetic'));
  assert.deepEqual(await verify(context), invalid('PUBLIC_FILE_UNSAFE'));
});

test('manifest path escape and arbitrary API-supplied file/root paths are not accepted', async (t) => {
  const escaped = setup(t);
  replaceManifest(escaped, (manifest) => {
    manifest.publicSha256['../../outside.synthetic'] = '0'.repeat(64);
  });
  assert.deepEqual(await verify(escaped), invalid('SCHEMA_INVALID'));
  const ordinary = setup(t);
  const { verifyPreparation } = await import(pathToFileURL(ordinary.script).href);
  assert.deepEqual(verifyPreparation({ path: join(ordinary.disposable, 'outside.synthetic') }),
    invalid('INPUT_REJECTED'));
});

test('unknown fields, forged frozen/approved/protocol flags and embedded restricted claims fail closed', async (t) => {
  const mutations = [
    (m) => { m.frozen = true; },
    (m) => { m.scored = true; },
    (m) => { m.releaseAuthority = true; },
    (m) => { m.protocolVersion = 'v0'; },
    (m) => { m.approved = true; },
    (m) => { m.gates.scope = 'APPROVED'; },
    (m) => { m.gates.blindCustody = { selfSigned: true }; },
    (m) => { m.observations.blindDigest = 'f'.repeat(64); },
    (m) => { m.seed = planted; },
    (m) => { m.approvals = { signedBy: 'self', signature: 'f'.repeat(64) }; },
  ];
  for (const mutation of mutations) {
    const context = setup(t);
    replaceManifest(context, mutation);
    assert.deepEqual(await verify(context), invalid('SCHEMA_INVALID'));
    assert.deepEqual(requireScoredV0(context.manifest), {
      status: 'SCORED_V0_DENIED', reason: 'EXTERNAL_APPROVAL_BOUNDARY_ABSENT',
    });
  }
});

test('duplicate JSON keys cannot hide a forged frozen claim behind a last-wins value', async (t) => {
  const context = setup(t);
  const file = join(context.root, manifestName);
  const original = readFileSync(file, 'utf8');
  writeFileSync(file, original.replace('"frozen": false,', '"frozen": true,\n  "frozen": false,'));
  git(context.root, 'add', '--', manifestName);
  commit(context.root, 'synthetic duplicate claim');
  assert.deepEqual(await verify(context), invalid('SCHEMA_INVALID'));
});

test('a missing or substituted exact Git source observation is not eligible', async (t) => {
  const context = setup(t);
  replaceManifest(context, (manifest) => { manifest.observations.preparationSourceRevision = '0'.repeat(40); });
  assert.deepEqual(await verify(context), invalid('GIT_REVISION_INVALID'));
});

test('no candidate, callback, local route or capture is consulted for preparation status', async (t) => {
  const context = setup(t);
  mkdirSync(join(context.root, 'evaluations/candidates'), { recursive: true });
  writeFileSync(join(context.root, 'evaluations/candidates/reference.mjs'),
    `throw new Error(${JSON.stringify(planted)});\n`);
  assert.deepEqual(await verify(context), valid);
  assert.equal(context.manifest.observations.actualRouteAndCapture, 'NOT_ESTABLISHED');
  assert.deepEqual(requireScoredV0(() => { throw new Error(planted); }), {
    status: 'SCORED_V0_DENIED', reason: 'EXTERNAL_APPROVAL_BOUNDARY_ABSENT',
  });
});

test('CLI reports fixed codes only, without planted originals, filenames, values or hashes', (t) => {
  const context = setup(t);
  appendFileSync(join(context.root, fixtureName), `\n${planted}\n`);
  const run = spawnSync(process.execPath, [context.script], { cwd: context.root, encoding: 'utf8' });
  assert.equal(run.status, 1);
  assert.deepEqual(JSON.parse(run.stdout), invalid('PUBLIC_FILE_CHANGED'));
  assert.equal(run.stderr, '');
  assert.equal(run.stdout.includes(planted), false);
  assert.equal(run.stdout.includes(fixtureName), false);
  assert.equal(run.stdout.includes(context.manifest.publicSha256.DEV_FIXTURE), false);
  const selected = spawnSync(process.execPath, [context.script, join(context.disposable, 'outside.synthetic')],
    { cwd: context.root, encoding: 'utf8' });
  assert.equal(selected.status, 1);
  assert.deepEqual(JSON.parse(selected.stdout), invalid('INPUT_REJECTED'));
  assert.equal(selected.stderr, '');
});
