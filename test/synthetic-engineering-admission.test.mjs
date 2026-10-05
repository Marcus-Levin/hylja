/**
 * Public behavior of the bounded synthetic engineering-reference admission helper.
 *
 * Synthetic only: invented `.invalid` tenant and project references and fabricated engineering values.
 * The credential-shaped value below is a made-up, obviously sequential string used only to prove that
 * #8 evidence refuses this seam; it is not a key, is not routable and is never stored as a mapping.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
const EXACT_LENGTH = 17;
// A one-digit template that matches exactly one value of the synthetic namespace and nothing after it.
const exactConfig = createCandidateConfig(A, { patterns: [{ template: 'SYNTHETIC-ASSET-{9:1}',
  semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG', sensitivity: 'INTERNAL' }] });
const rangeConfig = createCandidateConfig(A, { patterns: [{ template: 'SYNTHETIC-ASSET-{9:1-4}',
  semanticType: 'ENGINEERING_IDENTIFIER', subtype: 'ASSET_TAG', sensitivity: 'INTERNAL' }] });
const bytes = (value) => new TextEncoder().encode(value);
const inspect = (original, more = {}, handle = config, scope = A) =>
  inspectSyntheticEngineeringReference({ version: 1, original, scope, configured: handle,
    inputRef: 'field-a.invalid', ...more });
const RECORD = Object.freeze({ version: 1, original: bytes(GOOD), scope: A, configured: config,
  inputRef: 'field-a.invalid' });
const refuse = (value) => {
  const result = inspectSyntheticEngineeringReference(value);
  assert.equal(result.outcome, 'REFUSED', 'a planted shape must refuse');
  assert.ok(ADMISSION_REFUSALS.includes(result.reason), `${result.reason} is a fixed refusal code`);
  assert.equal(JSON.stringify(result).includes('planted'), false, 'no planted text is echoed');
  return result;
};

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

test('an inherited fieldKey never escapes: a planted getter cannot answer with planted text', () => {
  const base = { version: 1, original: bytes(GOOD), scope: A, configured: config, inputRef: 'field-a.invalid' };
  // The caller supplies no own fieldKey. Reading the omitted optional member must not walk to
  // Object.prototype, where a planted getter would throw and its text would escape as the thrown error
  // instead of leaving this seam as one of its fixed refusal codes.
  let planted = 'planted-inherited-field.invalid';
  Object.defineProperty(Object.prototype, 'fieldKey', {
    configurable: true,
    get() { throw new Error(planted); },
  });
  let result;
  try {
    result = inspectSyntheticEngineeringReference({ ...base });
  } finally {
    delete Object.prototype.fieldKey;
  }
  assert.ok(planted, 'the getter was planted');
  assert.equal(JSON.stringify(result).includes('planted'), false, 'no planted text reaches the caller');
  if (result.outcome === 'REFUSED') {
    assert.ok(ADMISSION_REFUSALS.includes(result.reason), `${result.reason} is a fixed refusal code`);
  } else {
    // A getter that answers rather than throws changes no evidence, so a legitimate classification stands.
    assert.equal(result.outcome, 'CLASSIFIED');
  }
});

test('caller byte changes after the call cannot change the evidence already returned', () => {
  const original = bytes(GOOD);
  const captured = inspect(original);
  // Boolean comparison only: a failed assertion here must never print the caller's byte array.
  const unchanged = original.length === GOOD.length && original.every((byte, index) => byte === GOOD.charCodeAt(index));
  assert.equal(unchanged, true, 'the caller keeps its own buffer');
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

test('review: only a genuine whole configured match corroborates; coverage alone does not', () => {
  // Positive controls: the configured template itself matches the entire value.
  assert.equal(inspect(bytes('SYNTHETIC-ASSET-1'), {}, exactConfig).outcome, 'CLASSIFIED');
  assert.equal(inspect(bytes('SYNTHETIC-ASSET-0042'), {}, rangeConfig).outcome, 'CLASSIFIED');
  // #10 extends a pattern match over the rest of the identifier. That is coverage, not corroboration:
  // the unconfigured tail was never matched by the genuine source, so it cannot be admitted. Both refusals
  // below are the same fact seen through the real seam: a coverage of `0..length` and a matcher that
  // stopped short of it, reported as one boolean and never as a coordinate this seam could verify.
  assert.equal(inspect(bytes('SYNTHETIC-ASSET-1UNCONFIGURED'), {}, exactConfig).reason, 'PARTIAL_CANDIDATE');
  assert.equal(inspect(bytes('SYNTHETIC-ASSET-12'), {}, exactConfig).reason, 'PARTIAL_CANDIDATE');
  assert.equal(inspect(bytes('SYNTHETIC-ASSET-1UNCONFIGURED'), {}, config).outcome, 'CLASSIFIED',
    'a template that genuinely matches the whole value is still admitted');
});

test('review: every member, optional ones included, must be an own enumerable data property', () => {
  const hidden = { ...RECORD };
  Object.defineProperty(hidden, 'fieldKey', { value: 'DB_PASSWORD', enumerable: false });
  assert.equal(inspectSyntheticEngineeringReference(hidden).reason, 'INVALID_REQUEST');
  let reads = 0;
  const accessor = Object.defineProperty({ ...RECORD }, 'fieldKey',
    { enumerable: true, get: () => { reads += 1; return 'DB_PASSWORD'; } });
  assert.equal(inspectSyntheticEngineeringReference(accessor).reason, 'INVALID_REQUEST');
  assert.equal(reads, 0, 'an accessor descriptor is refused, never invoked');
  assert.equal(inspectSyntheticEngineeringReference({ ...RECORD, fieldKey: 'DB_PASSWORD' }).reason,
    'SECRET_EVIDENCE', 'the ordinary data-property control still refuses for its own reason');
});

test('review: the nested scope is closed, own, non-inherited and free of a session field', () => {
  const scoped = (scope) => inspectSyntheticEngineeringReference({ ...RECORD, scope });
  assert.equal(scoped({ ...A }).outcome, 'CLASSIFIED');
  assert.equal(scoped({ ...A, sessionId: 'session-1' }).reason, 'INVALID_REQUEST');
  assert.equal(scoped(Object.create(A)).reason, 'INVALID_REQUEST');
  assert.equal(scoped({ tenantRef: A.tenantRef, projectRef: undefined }).reason, 'INVALID_REQUEST');
  let reads = 0;
  const trapped = new Proxy({ ...A }, { get: () => { reads += 1; throw new Error('planted'); } });
  assert.deepEqual(scoped(trapped), scoped({ ...A }), 'descriptors answer a get-only Proxy without running it');
  assert.equal(reads, 0);
  const accessor = {};
  Object.defineProperty(accessor, 'tenantRef', { enumerable: true, get: () => { reads += 1; return A.tenantRef; } });
  Object.defineProperty(accessor, 'projectRef', { enumerable: true, value: A.projectRef });
  assert.equal(inspectSyntheticEngineeringReference({ ...RECORD, scope: accessor }).reason, 'INVALID_REQUEST');
  assert.equal(reads, 0, 'an accessor scope descriptor is refused, never invoked');
});

test('review: reflection, byte and serialization failures refuse with a fixed code, never a planted error', () => {
  const genuine = bytes(GOOD);
  const lengthTrap = new Proxy(genuine, { get: () => { throw new Error('planted-length'); } });
  const indexTrap = new Proxy(genuine, { get: (target, key, receiver) => {
    if (key === '0') throw new Error('planted-byte');
    return Reflect.get(target, key, receiver);
  } });
  assert.equal(refuse({ ...RECORD, original: lengthTrap }).reason, 'INVALID_ORIGINAL');
  assert.equal(refuse({ ...RECORD, original: indexTrap }).reason, 'INVALID_ORIGINAL');
  assert.equal(refuse({ ...RECORD, inputRef: 'field-\ud800' }).reason, 'INVALID_REQUEST');
  assert.equal(refuse({ ...RECORD, scope: { tenantRef: 'tenant-a\ud800', projectRef: A.projectRef } }).reason,
    'INVALID_REQUEST');
});

test('review: a proxied element is never read, so nothing is coerced and nothing is read twice', () => {
  const genuine = bytes(GOOD);
  let elementReads = 0;
  const coercing = new Proxy(genuine, { get: (target, key, receiver) => {
    if (typeof key === 'string' && /^\d+$/u.test(key)) elementReads += 1;
    if (key === '0') return { valueOf: () => 0x41, toString: () => 'A' };
    return Reflect.get(target, key, receiver);
  } });
  assert.equal(refuse({ ...RECORD, original: coercing }).reason, 'INVALID_ORIGINAL');
  assert.equal(elementReads, 0, 'a proxied element is never reached, so it can never be coerced');
  const result = inspect(bytes(GOOD));
  assert.equal(result.outcome, 'CLASSIFIED');
  assert.equal(result.sourceDigest, createHash('sha256')
    .update(`hylja.synthetic-engineering-admission.source.v1\0${GOOD}`).digest('hex'),
  'the owned bytes, the owned text and the source digest are one congruent value');
});

test('review: no brand check or prototype trap runs before the byte refusal', () => {
  // A `Proxy` trap throws when the host brand-checks with `instanceof` or reads a prototype, so the refusal
  // is only truthful when the intrinsic length accessor is reached first and the engine refuses it itself.
  const trapped = new Proxy(bytes(GOOD), { getPrototypeOf: () => { throw new Error('planted-prototype'); } });
  let prototypeTraps = 0;
  const counted = new Proxy(bytes(GOOD), { getPrototypeOf: () => { prototypeTraps += 1; return Uint8Array.prototype; } });
  assert.equal(refuse({ ...RECORD, original: trapped }).reason, 'INVALID_ORIGINAL');
  assert.equal(refuse({ ...RECORD, original: counted }).reason, 'INVALID_ORIGINAL');
  assert.equal(prototypeTraps, 0, 'the typed-array internal slot refuses a Proxy before any prototype trap runs');
});

test('review: a genuine byte array behind a Proxy prototype is admitted with zero prototype traps', () => {
  // A real typed-array internal slot does not prove a trap-free prototype chain. Both values below are
  // genuine `Uint8Array`s whose **prototype** is a `Proxy`, so a brand check that reads a prototype chain
  // walks that chain: the first trap throws, which refuses a value that is in fact owned bytes, and the
  // second runs without refusing. Nothing here may walk it, so each shape is admitted exactly as the
  // ordinary control is, and the only diagnostics are the two fixed booleans below.
  let thrown = 0;
  let counted = 0;
  const refusing = Object.setPrototypeOf(bytes(GOOD), new Proxy(Object.getPrototypeOf(Uint8Array.prototype),
    { getPrototypeOf: () => { thrown += 1; throw new Error('planted-prototype'); } }));
  const honest = Object.setPrototypeOf(bytes(GOOD), new Proxy(Object.getPrototypeOf(Uint8Array.prototype),
    { getPrototypeOf: () => { counted += 1; return Uint8Array.prototype; } }));
  const ordinary = inspect(bytes(GOOD));
  assert.equal(ordinary.outcome, 'CLASSIFIED', 'the paired ordinary value is the control');
  for (const value of [refusing, honest]) {
    const result = inspect(value);
    assert.deepEqual(result, ordinary, 'a genuine byte array is admitted whatever its prototype answers');
    assert.equal(JSON.stringify(result).includes('planted'), false, 'no planted text is echoed');
  }
  assert.equal(thrown, 0, 'a throwing prototype trap is never run');
  assert.equal(counted, 0, 'no caller-controlled prototype chain is walked at any stage');
});

test('review: the byte kind is the engine kind, never a tag the caller can write', () => {
  // Both reads this seam must never use accept the object below: an ordinary `value[Symbol.toStringTag]`
  // returns exactly what the caller wrote, and `Object.prototype.toString` builds `[object Uint8Array]`
  // out of that same caller-written tag. The intrinsic getter applied directly to the value reports no
  // byte kind for it, because it answers from the internal slot the engine stores for the object itself.
  const spoof = { [Symbol.toStringTag]: 'Uint8Array', length: GOOD.length, 0: GOOD.charCodeAt(0) };
  assert.equal(spoof[Symbol.toStringTag], 'Uint8Array', 'the caller-written tag claims byte storage');
  assert.equal(Object.prototype.toString.call(spoof), '[object Uint8Array]', 'the forbidden read agrees');
  assert.equal(refuse({ ...RECORD, original: spoof }).reason, 'INVALID_ORIGINAL');
  // A genuine `Buffer` and a genuine subclass are byte storage whatever tag they advertise, so they are
  // admitted exactly as the ordinary value is: the kind is read from the engine, never from the caller.
  class SpoofedTag extends Uint8Array { get [Symbol.toStringTag]() { return 'Uint8ClampedArray'; } }
  assert.deepEqual(inspect(Buffer.from(GOOD, 'ascii')), inspect(bytes(GOOD)), 'a Buffer is byte storage');
  assert.deepEqual(inspect(new SpoofedTag(bytes(GOOD))), inspect(bytes(GOOD)));
  const wrongKinds = [new Uint8ClampedArray(GOOD.length), new Int8Array(GOOD.length),
    new Uint16Array(GOOD.length), new Float64Array(GOOD.length), new DataView(new ArrayBuffer(GOOD.length))];
  for (const value of wrongKinds) {
    assert.equal(refuse({ ...RECORD, original: value }).reason, 'INVALID_ORIGINAL');
  }
  assert.equal(refuse({ ...RECORD, original: new Proxy(bytes(GOOD), { get: () => { throw new Error('planted'); } }) })
    .reason, 'INVALID_ORIGINAL', 'a proxied look-alike has no internal slot for either intrinsic to find');
});

test('review: a copy failure part-way through the loop still zero-fills the allocation', () => {
  // A thrown failure inside the copy loop is the one partial path the refusal branch cannot reach, so the
  // cleanup has to be structural: the buffer is allocated before any byte is read and must be cleaned on
  // every exit. `String.fromCharCode` is the module's own text construction, so injecting here exercises a
  // real throw after allocation rather than a caller-shaped input the boundary already rejects earlier.
  const cleaned = [];
  const realFill = Uint8Array.prototype.fill;
  const realFromCharCode = String.fromCharCode;
  Uint8Array.prototype.fill = function record(value) { cleaned.push(this); return realFill.apply(this, arguments); };
  String.fromCharCode = () => { throw new Error('planted-copy'); };
  let result;
  try {
    result = inspectSyntheticEngineeringReference({ ...RECORD, original: bytes(GOOD) });
  } finally { String.fromCharCode = realFromCharCode; Uint8Array.prototype.fill = realFill; }
  assert.equal(result.outcome, 'REFUSED');
  assert.equal(result.reason, 'INVALID_ORIGINAL');
  assert.equal(JSON.stringify(result).includes('planted'), false, 'no planted error text is echoed');
  assert.ok(cleaned.some((buffer) => buffer.length === GOOD.length),
    'the partial allocation is zero-filled before the refusal returns');
  assert.ok(cleaned.every((buffer) => buffer.every((byte) => byte === 0)),
    'every owned byte observed by the cleanup is zero');
});

test('review: the owned allocation is zero-filled on a copy refusal, not only on the success path', () => {
  const planted = new Uint8Array([...bytes(GOOD).slice(0, 4), 0xff]);
  const cleaned = [];
  const real = Uint8Array.prototype.fill;
  Uint8Array.prototype.fill = function record(value) { cleaned.push(this); return real.apply(this, arguments); };
  let result;
  try {
    result = inspectSyntheticEngineeringReference({ ...RECORD, original: planted });
  } finally { Uint8Array.prototype.fill = real; }
  assert.equal(result.reason, 'INVALID_ORIGINAL');
  assert.ok(cleaned.some((buffer) => buffer.length === planted.length),
    'the allocated copy is cleaned up before the refusal returns');
  assert.ok(cleaned.every((buffer) => buffer.every((byte) => byte === 0)),
    'every owned byte observed by the cleanup is zero');
});
