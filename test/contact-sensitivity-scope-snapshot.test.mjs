import assert from 'node:assert/strict';
import { test } from 'node:test';
import { composeClassificationUnits, createContactSensitivity } from '../dist/classification-units.js';
import { createNameDictionary } from '../dist/contact-candidates.js';
import { detectNormalizedCandidates } from '../dist/normalized-detection.js';

// Public synthetic configuration only; these handles grant no authentication or effect authority.
const context = Object.freeze({ interactionRef: 'contact-interaction.invalid',
  sourceRef: 'contact-source.invalid', trust: 'UNTRUSTED' });
const entries = Object.freeze([{ subtype: 'EMAIL', sensitivity: 'CONFIDENTIAL' }]);
const scopeFor = (index) => ({ tenantRef: `synthetic-tenant-${index}.invalid`,
  projectRef: `synthetic-project-${index}.invalid` });

function consume(handle, scope) {
  const inputRef = 'contact-snapshot-request.invalid';
  const detection = detectNormalizedCandidates({ input: 'synthetic-contact@example.invalid', inputRef,
    scope, names: createNameDictionary(scope, []) });
  assert.equal(detection.status === 'COMPLETE', true, 'synthetic detection is complete');
  const result = composeClassificationUnits({ detection, inputRef, scope, context,
    contactSensitivity: handle });
  const contacts = result.units.filter((unit) => unit.detectorEvidence.some((record) =>
    record.claim.semanticType === 'PERSON' && record.claim.subtype === 'EMAIL'));
  assert.equal(contacts.length, 1, 'actual contact consumer has one email unit');
  return { result, classification: contacts[0].classification };
}

function assertBound(handle, expected, foreign) {
  const same = consume(handle, expected);
  assert.equal(same.result.status === 'COMPLETE', true, 'captured scope remains usable');
  assert.equal(same.classification.status === 'RESOLVED', true);
  assert.equal(same.classification.sensitivity === 'CONFIDENTIAL', true);
  assert.equal(same.classification.evidence.some((record) =>
    record.provenance?.producerId === 'hylja.contact-sensitivity'), true);
  for (const scope of [{ ...expected, tenantRef: foreign.tenantRef },
    { ...expected, projectRef: foreign.projectRef }, foreign]) {
    const other = consume(handle, scope);
    assert.equal(other.result.status === 'PARTIAL', true);
    assert.equal(other.result.reasons.includes('CONTACT_SENSITIVITY_SCOPE_MISMATCH'), true);
    assert.equal(other.classification.status === 'UNRESOLVED', true);
    assert.equal(other.classification.sensitivity === 'UNKNOWN', true);
    assert.equal(other.classification.reasons.includes('MISSING_SENSITIVITY'), true);
    assert.equal(other.classification.evidence.some((record) =>
      record.provenance?.producerId === 'hylja.contact-sensitivity'), false);
  }
}

function changingScope(mode, field, first, later) {
  let reads = 0;
  const target = { ...first };
  const answer = () => ++reads === 1 ? first[field] : later[field];
  const scope = mode === 'getter' ? Object.defineProperty(target, field, {
    enumerable: true, configurable: true, get: answer,
  }) : new Proxy(target, {
    get(object, key, receiver) {
      return key === field ? answer() : Reflect.get(object, key, receiver);
    },
  });
  return { scope, target, reads: () => reads };
}

for (const mode of ['getter', 'proxy']) {
  for (const field of ['tenantRef', 'projectRef']) {
    for (let index = 0; index < 3; index++) {
      test(`${mode} ${field} captures its first label and cannot retarget variant ${index}`, () => {
        const first = scopeFor(index);
        const later = scopeFor(index + 10);
        const changing = changingScope(mode, field, first, later);
        const handle = createContactSensitivity(changing.scope, entries);
        // Mutation after construction must not retarget either captured field.
        for (const key of ['tenantRef', 'projectRef']) {
          Object.defineProperty(changing.target, key, { value: later[key], configurable: true });
        }
        assertBound(handle, first, later);
        assert.equal(changing.reads(), 1, 'one read of the selected field');
      });
    }
  }
}

for (const kind of ['ordinary', 'null-prototype', 'inherited']) {
  test(`${kind} scope remains compatible and later mutation cannot retarget the handle`, () => {
    const first = scopeFor(30);
    const later = scopeFor(31);
    const owner = kind === 'null-prototype' ? Object.assign(Object.create(null), first) : { ...first };
    const scope = kind === 'inherited' ? Object.create(owner) : owner;
    const handle = createContactSensitivity(scope, entries);
    Object.assign(owner, later);
    assertBound(handle, first, later);
  });
}

function refused(scope) {
  let error;
  try { createContactSensitivity(scope, entries); } catch (caught) { error = caught; }
  assert.equal(error instanceof TypeError, true, 'fixed boundary TypeError');
  assert.equal(error.message === 'Invalid contact sensitivity configuration', true, 'fixed safe message');
  assert.equal(Object.hasOwn(error, 'cause'), false, 'no forwarded cause');
  return error;
}

for (const mode of ['getter', 'proxy']) {
  for (const field of ['tenantRef', 'projectRef']) {
    test(`${mode} ${field} refuses every malformed first value despite a later valid label`, () => {
      const valid = scopeFor(40);
      for (const value of [undefined, null, 0, {}, '', ' synthetic.invalid', 'synthetic.invalid ',
        'synthetic\u0000.invalid', 'x'.repeat(257)]) {
        const changing = changingScope(mode, field, { ...valid, [field]: value }, valid);
        refused(changing.scope);
        assert.equal(changing.reads(), 1, 'invalid first label is not reread');
      }
    });

    test(`${mode} ${field} never needs a second read that would throw`, () => {
      const first = scopeFor(50);
      let reads = 0;
      const answer = () => {
        if (++reads > 1) throw new Error('synthetic-late-read.invalid');
        return first[field];
      };
      const target = { ...first };
      const scope = mode === 'getter' ? Object.defineProperty(target, field, { get: answer }) :
        new Proxy(target, { get(object, key, receiver) {
          return key === field ? answer() : Reflect.get(object, key, receiver);
        } });
      let handle;
      let threw = false;
      try { handle = createContactSensitivity(scope, entries); } catch { threw = true; }
      assert.equal(threw, false, 'a valid first read suffices for construction');
      assertBound(handle, first, scopeFor(51));
      assert.equal(reads, 1);
    });

    test(`${mode} ${field} contains finite throws in fresh safe errors without inspecting the exception`, () => {
      let exceptionReads = 0;
      const hostile = new Proxy({}, { get() { exceptionReads++; throw new Error('synthetic-error.invalid'); },
        ownKeys() { exceptionReads++; throw new Error('synthetic-error.invalid'); } });
      const target = scopeFor(60);
      const answer = () => { throw hostile; };
      const scope = mode === 'getter' ? Object.defineProperty(target, field, { get: answer }) :
        new Proxy(target, { get(object, key, receiver) {
          return key === field ? answer() : Reflect.get(object, key, receiver);
        } });
      const first = refused(scope);
      const second = refused(scope);
      assert.equal(first === second, false, 'fresh errors for independent refusals');
      assert.equal(first === hostile || second === hostile, false, 'exception object is never forwarded');
      assert.equal(exceptionReads, 0, 'no exception properties inspected');
      assert.equal(first.stack.includes('synthetic-error.invalid'), false);
      assert.equal(second.stack.includes('synthetic-error.invalid'), false);
    });
  }
}

test('null and missing-field scopes retain fixed safe refusals', () => {
  for (const scope of [null, undefined, {}, { tenantRef: 'synthetic-tenant.invalid' },
    { projectRef: 'synthetic-project.invalid' }]) refused(scope);
});
