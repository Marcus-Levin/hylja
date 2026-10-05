#!/usr/bin/env node
/**
 * TEST-ONLY harness for `test/run-node-subprocess.test.mjs`. Not a suite member and not an entry point.
 *
 * It is the "runner" that is interrupted: it starts one real stalled fixture run (whose process tree has a
 * real descendant) through the helper under a long bound, and then either waits to be signalled (`wait`)
 * or exits normally as soon as the descendant has been published (`exit`). The test observes, from the
 * OS, whether the descendant survived this process. It prints nothing.
 *
 *   wait F   run the stalled fixture, publish its descendant pid to F, and wait to be interrupted
 *   exit F   the same, then call `process.exit(0)` once the descendant pid is published
 */
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runNodeFixture } from './run-node-subprocess.mjs';

const FIXTURE = fileURLToPath(new URL('./run-node-subprocess-fixture.mjs', import.meta.url));
const [mode, file, ...rest] = process.argv.slice(2);
if ((mode !== 'wait' && mode !== 'exit') || typeof file !== 'string' || rest.length > 0) {
  process.exitCode = 2;
} else {
  runNodeFixture({ entry: FIXTURE, args: ['descendant', file], boundMs: 60_000 }).then(() => {});
  if (mode === 'exit') {
    const poll = setInterval(() => {
      if (!existsSync(file)) return;
      clearInterval(poll);
      process.exit(0);
    }, 5);
  }
}
