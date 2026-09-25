import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const guard = resolve(root, 'scripts', 'check-fixtures.mjs');
const planted = 'synthetic-planted-example.invalid';

function git(cwd, ...args) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, 'test Git operation should succeed');
}

function withRepository(run) {
  const repo = mkdtempSync(join(tmpdir(), 'hylja-fixture-guard-'));
  try {
    git(repo, 'init', '-q');
    cpSync(join(root, '.gitignore'), join(repo, '.gitignore'));
    run(repo);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
}

function stage(repo, path, contents) {
  const file = join(repo, path);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, contents);
  git(repo, 'add', '-f', '--', path);
  return file;
}

function check(repo, cwd = repo) {
  const result = spawnSync(process.execPath, [guard], { cwd, encoding: 'utf8' });
  assert.equal(result.error, undefined, 'the fixture guard should launch');
  const output = `${result.stdout}\n${result.stderr}`;
  assert.ok(!output.includes(planted), 'the guard must not echo planted fixture contents');
  return { status: result.status, output };
}

test('force-added private fixtures are rejected without printing their contents', () => {
  withRepository((repo) => {
    const path = `test/fixtures/private/${planted}.env`;
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), `password=${planted}\n`);
    git(repo, 'check-ignore', '-q', '--', path);
    git(repo, 'add', '-f', '--', path);
    const result = check(repo);
    assert.notEqual(result.status, 0);
    assert.match(result.output, /fixture guard: rejected tracked path/);
  });
});

test('tracked fixture blobs are scanned from the Git index, not the worktree', () => {
  withRepository((repo) => {
    const file = stage(repo, 'test/fixtures/regression/case.txt', `api_key=${planted}\n`);
    writeFileSync(file, 'ordinary synthetic text\n');
    const result = check(repo);
    assert.notEqual(result.status, 0);
    assert.match(result.output, /fixture guard: rejected credential-like content/);
  });
});

test('synthetic golden fixtures permit explicitly synthetic credential-shaped values', () => {
  withRepository((repo) => {
    stage(repo, 'test/fixtures/synthetic-golden/case.json',
      readFileSync(join(root, 'test', 'fixtures', 'synthetic-golden', 'credential.json')));
    const result = check(repo);
    assert.equal(result.status, 0, 'an obviously synthetic, designated golden fixture is allowed');
  });
});

test('golden fixtures cannot use the allowlist for non-synthetic credentials', () => {
  withRepository((repo) => {
    stage(repo, 'test/fixtures/synthetic-golden/case.txt', 'password=not-an-example\n');
    const result = check(repo);
    assert.notEqual(result.status, 0);
    assert.match(result.output, /fixture guard: rejected credential-like content/);
  });
});

test('force-added build artifacts are rejected even when text is harmless', () => {
  withRepository((repo) => {
    const path = 'dist/index.js';
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), 'export const example = 1;\n');
    git(repo, 'check-ignore', '-q', '--', path);
    git(repo, 'add', '-f', '--', path);
    const result = check(repo);
    assert.notEqual(result.status, 0);
    assert.match(result.output, /fixture guard: rejected tracked path/);
  });
});

test('tracked fixture symlinks cannot redirect inspection to a private target', () => {
  withRepository((repo) => {
    const path = 'test/fixtures/regression/linked.txt';
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    symlinkSync('../../outside.txt', join(repo, path));
    git(repo, 'add', '-f', '--', path);
    const result = check(repo);
    assert.notEqual(result.status, 0);
    assert.match(result.output, /fixture guard: rejected tracked path/);
  });
});

test('tracked binary fixture blobs are rejected without printing them', () => {
  withRepository((repo) => {
    const path = 'test/fixtures/regression/data.bin';
    stage(repo, path, Buffer.from([0, 1, 2, 3]));
    const result = check(repo);
    assert.notEqual(result.status, 0);
    assert.match(result.output, /fixture guard: rejected fixture content/);
  });
});

test('calling the guard from a subdirectory cannot hide tracked root files', () => {
  withRepository((repo) => {
    stage(repo, 'dist/index.js', 'synthetic placeholder\n');
    mkdirSync(join(repo, 'test'));
    const result = check(repo, join(repo, 'test'));
    assert.notEqual(result.status, 0);
    assert.match(result.output, /fixture guard: must run from repository root/);
  });
});
