// #250: a deliberately failing `node --test` file, used as a fixed control for the test-only subprocess
// helper. Not a suite member: it lives under `test/support/`, so the suite glob never collects it.
//
// Its whole purpose is to FAIL, so that the helper can be shown to preserve an ordinary non-zero exit
// together with the TAP the real runner produced. A helper that turned every non-zero exit into a
// transport failure, or dropped the runner's output, would make the confidentiality observation in
// `test/synthetic-conversation-demo.e2e.test.mjs` impossible.
//
// The failing assertion carries a fixed message and a fixed operand. Nothing here is planted or
// protected, and nothing captured from it is ever compared as a string by the suite.
import assert from 'node:assert/strict';
import { test } from 'node:test';

test('this control really fails, so the helper can be shown to keep its TAP and its exit code', () => {
  assert.equal('run-node-subprocess failing control' === 'a different fixed operand', true,
    'this control fails on purpose');
});
