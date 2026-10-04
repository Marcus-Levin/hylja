/**
 * Proves the repository's own `tsconfig.json` really rejects an unused capture, through the pinned
 * compiler that already builds this repository. The probe extends the real configuration in a
 * temporary directory and changes only the file set and the output location, so the diagnostic comes
 * from the shipped options rather than from a copy of them in this file.
 *
 * The check is the compiler's own behaviour, not a text match against `tsconfig.json`: the assertion
 * is the numeric diagnostic code and the fixed symbol name, never a path from this machine. It proves
 * a compile-time guard only, and says nothing about protected egress.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
/** The pinned compiler already present in `node_modules`; this test installs and downloads nothing. */
const TSC = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
/** An obviously synthetic capture; no repository, customer or production value. */
const UNUSED_MODULE = ['export {};', 'const UNUSED_CAPTURE = ArrayBuffer.isView;', ''].join('\n');
const USED_MODULE = [
  'export {};', 'const USED_CAPTURE = ArrayBuffer.isView;', 'export type CaptureProbe = typeof USED_CAPTURE;', '',
].join('\n');

/**
 * Type-checks synthetic modules with the repository's own compiler options. The child is bounded by
 * a timeout and a buffer, and the sandbox is removed on every path out.
 * @param {Readonly<Record<string, string>>} sources file name to synthetic module source
 * @returns {{ status: number, output: string }} the exit status and the compiler's own diagnostics
 */
function compile(sources) {
  const sandbox = mkdtempSync(join(tmpdir(), 'hylja-unused-probe-'));
  try {
    const base = JSON.parse(readFileSync(join(root, 'tsconfig.json'), 'utf8'));
    const options = { ...base.compilerOptions, rootDir: '.', outDir: 'out' };
    writeFileSync(join(sandbox, 'tsconfig.json'),
      `${JSON.stringify({ compilerOptions: options, files: Object.keys(sources), include: [] }, null, 2)}\n`);
    for (const [name, source] of Object.entries(sources)) writeFileSync(join(sandbox, name), source);
    const result = spawnSync(process.execPath, [TSC, '-p', 'tsconfig.json'], {
      cwd: sandbox, encoding: 'utf8', timeout: 30_000, maxBuffer: 1 << 20,
    });
    assert.equal(result.error, undefined, 'the pinned compiler must start and finish');
    assert.equal(result.signal, null, 'the pinned compiler must not be killed');
    return { status: result.status ?? -1, output: `${result.stdout}${result.stderr}` };
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
}

test('an unused local capture fails this repository type-check configuration', () => {
  const unused = compile({ 'unused-capture.ts': UNUSED_MODULE });
  assert.notEqual(unused.status, 0, 'an unread capture must fail the type check');
  assert.match(unused.output, /error TS6133: 'UNUSED_CAPTURE' is declared but its value is never read\./u,
    'the refusal must be the unused-declaration diagnostic from the repository configuration itself');
});

test('a capture that is used passes the same configuration', () => {
  const used = compile({ 'used-capture.ts': USED_MODULE });
  assert.equal(used.status, 0, `a used capture must type-check; compiler said: ${used.output}`);
  assert.doesNotMatch(used.output, /TS6133/u, 'the control must not be refused as unused');
});
