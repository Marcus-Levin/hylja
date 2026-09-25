import assert from 'node:assert/strict';
import { test } from 'node:test';
import { HYLJA_FOUNDATION_VERSION } from '../dist/index.js';

test('the built Node module loads and exposes its foundation version', () => {
  assert.equal(HYLJA_FOUNDATION_VERSION, '0.0.0');
});
