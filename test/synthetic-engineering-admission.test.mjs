/**
 * Public behavior of the bounded synthetic engineering-reference admission helper.
 *
 * Synthetic only: invented `.invalid` tenant and project references and fabricated engineering values.
 * The credential-shaped value below is a made-up, obviously sequential string used only to prove that
 * #8 evidence refuses this seam; it is not a key, is not routable and is never stored as a mapping.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createCandidateConfig } from '../dist/configured-candidates.js';
import {
  ADMISSION_REFUSALS, inspectSyntheticEngineeringReference, MAX_SYNTHETIC_BYTES,
} from '../dist/synthetic-engineering-admission.js';

const A = Object.freeze({ tenantRef: 'tenant-a.invalid', projectRef: 'project-a.invalid' });
const B = Object.freeze({ tenantRef: 'tenant-b.invalid', projectRef: 'project-b.invalid' });
const ASSET_TAG = Object.freeze({ template: 'SYNTHETIC-ASSET-{X:1-32}',
  semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG', sensitivity: 'INTERNAL' });
const config = createCandidateConfig(A, { patterns: [ASSET_TAG] });
const drawingConfig = createCandidateConfig(A, { patterns: [{ ...ASSET_TAG, subtype: 'DRAWING_NUMBER',
  sensitivity: 'CONFIDENTIAL' }] });
const noSensitivityConfig = createCandidateConfig(A, { patterns: [{ template: ASSET_TAG.template,
  semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG' }] });
const partialConfig = createCandidateConfig(A, { patterns: [ASSET_TAG],
  terms: [{ term: 'PUMP0042', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG', sensitivity: 'INTERNAL' }] });
const conflictingConfig = createCandidateConfig(A, { patterns: [ASSET_TAG,
  { template: 'SYNTHETIC-ASSET-{9:8}', semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'DOCUMENT_ID', sensitivity: 'CONFIDENTIAL' }] });

const GOOD = 'SYNTHETIC-ASSET-PUMP0042';
const bytes = (value) => new TextEncoder().encode(value);
const inspect = (original, more = {}, handle = config, scope = A) =>
  inspectSyntheticEngineeringReference({ version: 1, original, scope, configured: handle,
    inputRef: 'field-a.invalid', ...more });

test('a genuine configured synthetic identifier is classified with a reversible session recommendation', () => {
  const result = inspect(bytes(GOOD));
  assert.deepEqual(result, { version: 1, outcome: 'CLASSIFIED', semanticType: 'ENGINEERING_IDENTIFIER',
    subtype: 'ASSET_TAG', sensitivity: 'INTERNAL', reversibility: 'SESSION_RECOMMENDED',
    sourceDigest: result.sourceDigest, classificationDigest: result.classificationDigest });
  assert.match(result.sourceDigest, /^[0-9a-f]{64}$/u);
  assert.match(result.classificationDigest, /^[0-9a-f]{64}$/u);
  assert.notEqual(result.sourceDigest, result.classificationDigest);
});

test('the reported subtype and sensitivity come from the configured source, not from a fixed label', () => {
  assert.equal(inspect(bytes(GOOD), {}, drawingConfig).subtype, 'DRAWING_NUMBER');
  assert.equal(inspect(bytes(GOOD), {}, drawingConfig).sensitivity, 'CONFIDENTIAL');
  assert.equal(inspect(bytes(GOOD), { fieldKey: 'asset_tag' }).outcome, 'CLASSIFIED');
});

test('the result is owned evidence: frozen, no original text, no byte buffer, no effect handle', () => {
  const result = inspect(bytes(GOOD));
  assert.ok(Object.isFrozen(result));
  for (const key of ['original', 'text', 'bytes', 'handle', 'mapping', 'key', 'policy', 'approval']) {
    assert.equal(Object.hasOwn(result, key), false, `${key} must not be an output member`);
  }
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes('SYNTHETIC'), false);
  assert.equal(serialized.includes('PUMP'), false);
});

test('ordinary, malformed, non-ASCII and unconfigured values refuse with fixed codes', () => {
  const cases = [
    [bytes('PUMP-0042'), 'OUT_OF_SYNTHETIC_GRAMMAR'],
    [bytes('synthetic-asset-pump0042'), 'OUT_OF_SYNTHETIC_GRAMMAR'],
    [bytes('SYNTHETIC-ASSET-PUMP 0042'), 'OUT_OF_SYNTHETIC_GRAMMAR'],
    [bytes('SYNTHETIC_ASSET_PUMP0042'), 'OUT_OF_SYNTHETIC_GRAMMAR'],
    [bytes('SYNTHETIC-ASSET-'), 'OUT_OF_SYNTHETIC_GRAMMAR'],
    [bytes('SYNTHETIC-ASSET-PUMP-0042'), 'OUT_OF_SYNTHETIC_GRAMMAR'],
    [new Uint8Array(0), 'INVALID_ORIGINAL'],
    [bytes('SYNTHETIC-ASSET-Ä'), 'INVALID_ORIGINAL'],
    ['not-bytes', 'INVALID_ORIGINAL'],
    [{}, 'INVALID_ORIGINAL'],
  ];
  for (const [value, reason] of cases) {
    const result = inspect(value);
    assert.deepEqual(result, { version: 1, outcome: 'REFUSED', reason }, `${reason} for a refused value`);
  }
});

test('the 128-byte bound is enforced before the grammar, not after it', () => {
  assert.equal(MAX_SYNTHETIC_BYTES, 128);
  assert.equal(inspect(new Uint8Array(MAX_SYNTHETIC_BYTES).fill(0x41)).reason, 'OUT_OF_SYNTHETIC_GRAMMAR');
  assert.equal(inspect(new Uint8Array(MAX_SYNTHETIC_BYTES + 1).fill(0x41)).reason, 'INVALID_ORIGINAL');
});

test('a grammar-shaped value that also carries credential evidence refuses', () => {
  const overlap = 'SYNTHETIC-ASSET-AKIA0123456789ABCDEF';
  assert.equal(inspect(bytes(overlap)).reason, 'SECRET_EVIDENCE');
  assert.equal(inspect(bytes(GOOD), { fieldKey: 'DB_PASSWORD' }).reason, 'SECRET_EVIDENCE');
  assert.equal(inspect(bytes(GOOD), { fieldKey: 'x-api-key' }).reason, 'SECRET_EVIDENCE');
});

test('foreign, forged and absent configuration refuses as an incomplete inspection', () => {
  assert.equal(inspect(bytes(GOOD), {}, config, B).reason, 'INCOMPLETE_INSPECTION');
  assert.equal(inspect(bytes(GOOD), {}, Object.freeze(Object.create(null))).reason, 'INCOMPLETE_INSPECTION');
  assert.equal(inspect(bytes(GOOD), { configured: undefined }).reason, 'NO_CONFIGURED_CORROBORATION');
});

test('unknown sensitivity, partial coverage and conflicting evidence refuse', () => {
  assert.equal(inspect(bytes(GOOD), {}, noSensitivityConfig).reason, 'UNKNOWN_SENSITIVITY');
  assert.equal(inspect(bytes(GOOD), {}, partialConfig).reason, 'PARTIAL_CANDIDATE');
  assert.equal(inspect(bytes('SYNTHETIC-ASSET-00421234'), {}, conflictingConfig).reason, 'CONFLICTING_EVIDENCE');
  assert.equal(inspect(bytes(GOOD), {}, createCandidateConfig(A, { terms: [] })).reason,
    'NO_CONFIGURED_CORROBORATION');
});

test('hostile record shapes and accessors refuse without throwing or echoing a value', () => {
  const base = { version: 1, original: bytes(GOOD), scope: A, configured: config, inputRef: 'field-a.invalid' };
  const shapes = [null, undefined, 'text', 7, [base], Object.assign(Object.create({ inherited: 1 }), base),
    { ...base, extra: 'x' }, { ...base, version: 2 }, { ...base, inputRef: '' },
    { ...base, [Symbol('s')]: 1 },
    Object.defineProperty({ ...base }, 'original', { enumerable: true, get: () => { throw new Error('planted'); } }),
    new Proxy({ ...base }, { getPrototypeOf: () => { throw new Error('planted'); } }),
    new Proxy({ ...base }, { ownKeys: () => { throw new Error('planted'); } }),
    new Proxy({ ...base }, { getOwnPropertyDescriptor: () => { throw new Error('planted'); } })];
  for (const shape of shapes) {
    const result = inspectSyntheticEngineeringReference(shape);
    assert.equal(result.outcome, 'REFUSED', 'a hostile shape must refuse');
    assert.ok(ADMISSION_REFUSALS.includes(result.reason));
    assert.equal(JSON.stringify(result).includes('planted'), false);
  }
});

test('a caller getter is never invoked: the record is read through descriptors only', () => {
  const base = { version: 1, original: bytes(GOOD), scope: A, configured: config, inputRef: 'field-a.invalid' };
  let reads = 0;
  const trapped = new Proxy({ ...base }, { get: () => { reads += 1; throw new Error('planted'); } });
  assert.deepEqual(inspectSyntheticEngineeringReference(trapped), inspectSyntheticEngineeringReference({ ...base }));
  assert.equal(reads, 0);
});

test('caller byte changes after the call cannot change the evidence already returned', () => {
  const original = bytes(GOOD);
  const captured = inspect(original);
  assert.deepEqual([...original], [...bytes(GOOD)], 'the caller keeps its own buffer');
  original.fill(0x41);
  assert.deepEqual(inspect(bytes(GOOD)), captured);
  assert.notEqual(inspect(original).sourceDigest, captured.sourceDigest);
});

test('digests bind the classification to the private original and to a fresh source reference', () => {
  const first = inspect(bytes(GOOD));
  assert.deepEqual(inspect(bytes(GOOD)), first);
  assert.equal(inspect(bytes('SYNTHETIC-ASSET-PUMP0043')).sourceDigest === first.sourceDigest, false);
  const other = inspect(bytes(GOOD), { inputRef: 'field-b.invalid' });
  assert.equal(other.sourceDigest, first.sourceDigest, 'the source digest is the original alone');
  assert.notEqual(other.classificationDigest, first.classificationDigest, 'a fresh reference rebinds the evidence');
});

test('every refusal this seam emits is in the closed vocabulary', () => {
  const seen = new Set([...ADMISSION_REFUSALS]);
  assert.equal(seen.size, ADMISSION_REFUSALS.length);
  assert.deepEqual([...seen].sort(), [...ADMISSION_REFUSALS].sort());
});
