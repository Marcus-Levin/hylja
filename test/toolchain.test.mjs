import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('npm test executes runtime tests and fails when one fails', () => {
  const sandbox = mkdtempSync(join(tmpdir(), 'hylja-runtime-probe-'));
  try {
    cpSync(join(root, 'package.json'), join(sandbox, 'package.json'));
    cpSync(join(root, 'tsconfig.json'), join(sandbox, 'tsconfig.json'));
    mkdirSync(join(sandbox, 'src'));
    cpSync(join(root, 'src', 'index.ts'), join(sandbox, 'src', 'index.ts'));
    symlinkSync(join(root, 'node_modules'), join(sandbox, 'node_modules'), 'dir');
    mkdirSync(join(sandbox, 'scripts'));
    cpSync(join(root, 'scripts', 'check-fixtures.mjs'), join(sandbox, 'scripts', 'check-fixtures.mjs'));
    assert.equal(spawnSync('git', ['init', '-q'], { cwd: sandbox }).status, 0);
    mkdirSync(join(sandbox, 'test'));
    writeFileSync(join(sandbox, 'test', 'failure.test.mjs'),
      "import { test } from 'node:test';\ntest('runtime probe', () => { throw new Error('intentional runtime failure'); });\n");

    // Node marks a test child process as already in a runner; clear that marker
    // so a nested npm invocation really executes its own test files.
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    const result = spawnSync('npm', ['test'], { cwd: sandbox, encoding: 'utf8', timeout: 30_000, env });
    assert.equal(result.error, undefined, 'npm test should start and finish');
    assert.notEqual(result.status, 0, 'npm test must reject a failing executable test');
    assert.match(`${result.stdout}\n${result.stderr}`, /intentional runtime failure/,
      'the failure must come from the runtime test, not the compiler or missing dependencies');
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
});
