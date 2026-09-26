import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SENSITIVITIES } from '../dist/classification.js';
import {
  resolveSensitivityDraft, resolveAttributeDraft, assessFidelityDraft, FIDELITY_PREDICATES, REPRESENTATIONS,
  SECRET_REPRESENTATIONS, semanticPlaceholder, parseSemanticPlaceholder, validateTaskFidelityContractDraft,
  validateOracleAnnotationDraft,
} from '../dist/information-model-draft.js';

// Seeded generator so property failures replay exactly.
function prng(seed) {
  let state = seed >>> 0;
  return () => { state = (state + 0x6d2b79f5) >>> 0; let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const pick = (random, list) => list[Math.floor(random() * list.length)];
const det = (sensitivity, more = {}) => ({ origin: 'DETERMINISTIC', status: 'FOUND', sensitivity, ...more });
const sem = (sensitivity, more = {}) => ({ origin: 'SEMANTIC', status: 'FOUND', sensitivity, ...more });
const rank = (value) => SENSITIVITIES.indexOf(value);
function randomClaim(random) {
  const origin = pick(random, ['DETERMINISTIC', 'SEMANTIC']);
  const status = pick(random, ['FOUND', 'FOUND', 'FOUND', 'ABSTAIN', 'FAILURE']);
  if (status !== 'FOUND') return { origin, status };
  return random() < 0.1 ? { origin, status, credential: true } : { origin, status, sensitivity: pick(random, SENSITIVITIES) };
}

test('agreed deterministic evidence resolves without a semantic judge', () => {
  assert.deepEqual({ ...resolveSensitivityDraft([det('INTERNAL'), det('INTERNAL')]) },
    { state: 'RESOLVED', floor: 'INTERNAL', effective: 'INTERNAL', escalationSteps: 0, reasons: [] });
});

test('#66 escalation: deterministic INTERNAL vs semantic CONFIDENTIAL resolves conservatively upward', () => {
  const result = resolveSensitivityDraft([det('INTERNAL'), sem('CONFIDENTIAL')]);
  assert.equal(result.state, 'RESOLVED_CONSERVATIVELY');
  assert.equal(result.floor, 'INTERNAL');
  assert.equal(result.effective, 'CONFIDENTIAL');
  assert.equal(result.escalationSteps, 1);
  assert.deepEqual(result.reasons, ['SEMANTIC_ESCALATION']);
});

test('#66 downgrade: a semantic PUBLIC judgment never lowers a deterministic floor', () => {
  const result = resolveSensitivityDraft([det('CONFIDENTIAL'), sem('PUBLIC')]);
  assert.equal(result.state, 'RESOLVED_CONSERVATIVELY');
  assert.equal(result.effective, 'CONFIDENTIAL');
  assert.deepEqual(result.reasons, ['SEMANTIC_BELOW_FLOOR_IGNORED']);
});

test('deterministic credential evidence fixes SECRET against every contrary claim', () => {
  const result = resolveSensitivityDraft([det(undefined, { credential: true, sensitivity: undefined }),
    det('PUBLIC'), sem('PUBLIC')].map((claim) => Object.fromEntries(Object.entries(claim).filter(([, v]) => v !== undefined))));
  assert.equal(result.floor, 'SECRET');
  assert.equal(result.effective, 'SECRET');
  assert.equal(result.state, 'RESOLVED_CONSERVATIVELY');
  assert.ok(result.reasons.includes('CREDENTIAL_FLOOR_APPLIED'));
});

test('a semantic credential opinion is concern, not a deterministic floor', () => {
  const result = resolveSensitivityDraft([det('INTERNAL'), { origin: 'SEMANTIC', status: 'FOUND', credential: true }]);
  assert.equal(result.floor, 'INTERNAL');
  assert.equal(result.effective, 'SECRET');
  assert.equal(result.escalationSteps, 3);
});

test('uncertain floors stay UNRESOLVED and retain the highest concern', () => {
  for (const [claims, reason] of [
    [[det('INTERNAL'), det('RESTRICTED')], 'DETERMINISTIC_CONFLICT'],
    [[sem('CONFIDENTIAL')], 'MISSING_DETERMINISTIC_EVIDENCE'],
    [[det('INTERNAL'), { origin: 'SEMANTIC', status: 'FAILURE' }], 'SEMANTIC_FAILURE'],
    [[det('INTERNAL'), { origin: 'DETERMINISTIC', status: 'FAILURE' }], 'DETERMINISTIC_FAILURE'],
    [[{ origin: 'DETERMINISTIC', status: 'FOUND' }], 'MISSING_SENSITIVITY'],
    [[], 'MISSING_DETERMINISTIC_EVIDENCE'],
  ]) {
    const result = resolveSensitivityDraft(claims);
    assert.equal(result.state, 'UNRESOLVED', reason);
    assert.ok(result.reasons.includes(reason), reason);
  }
  assert.equal(resolveSensitivityDraft([det('INTERNAL'), det('RESTRICTED')]).effective, 'RESTRICTED');
});

test('a semantic abstention is an absent judge and cannot lower anything', () => {
  const result = resolveSensitivityDraft([det('CONFIDENTIAL'), { origin: 'SEMANTIC', status: 'ABSTAIN' }]);
  assert.equal(result.state, 'RESOLVED');
  assert.equal(result.effective, 'CONFIDENTIAL');
  assert.deepEqual(result.reasons, ['SEMANTIC_ABSTAINED']);
});

test('malformed, forged or accessor-backed evidence fails closed without echoing it', () => {
  const planted = 'synthetic-planted-value.invalid';
  const getter = { origin: 'DETERMINISTIC', status: 'FOUND' };
  Object.defineProperty(getter, 'sensitivity', { enumerable: true, get: () => 'PUBLIC' });
  for (const claims of [
    null, 'PUBLIC', [det('PUBLIC', { note: planted })], [det('TOP_SECRET')], [{ ...det('PUBLIC'), origin: 'CONTROL' }],
    [getter], [{ origin: 'SEMANTIC', status: 'ABSTAIN', sensitivity: 'PUBLIC' }],
    Array.from({ length: 257 }, () => det('PUBLIC')),
  ]) {
    const result = resolveSensitivityDraft(claims);
    assert.equal(result.state, 'UNRESOLVED');
    assert.ok(result.reasons.includes('INVALID_EVIDENCE'));
    assert.ok(!JSON.stringify(result).includes(planted));
  }
});

test('property: effective is never below any deterministic claim and adding a claim never lowers it', () => {
  const random = prng(0x6606);
  for (let run = 0; run < 2000; run++) {
    const claims = Array.from({ length: Math.floor(random() * 6) }, () => randomClaim(random));
    const before = resolveSensitivityDraft(claims);
    for (const claim of claims) {
      if (claim.origin === 'DETERMINISTIC' && claim.status === 'FOUND' && before.effective !== 'UNKNOWN') {
        assert.ok(rank(before.effective) >= rank(claim.credential ? 'SECRET' : claim.sensitivity));
      }
    }
    const after = resolveSensitivityDraft([...claims, randomClaim(random)]);
    if (before.effective !== 'UNKNOWN') assert.ok(rank(after.effective) >= rank(before.effective), JSON.stringify(claims));
    if (before.floor !== 'UNKNOWN' && after.floor !== 'UNKNOWN') assert.ok(rank(after.floor) >= rank(before.floor) ||
      after.state === 'UNRESOLVED');
    // Composition is order-independent.
    const shuffled = [...claims].sort(() => random() - 0.5);
    assert.deepEqual({ ...resolveSensitivityDraft(shuffled) }, { ...before });
    // Semantic disagreement never yields a plain RESOLVED.
    const semanticValues = claims.filter((c) => c.origin === 'SEMANTIC' && c.status === 'FOUND');
    if (before.state === 'RESOLVED') {
      for (const c of semanticValues) assert.equal(c.credential ? 'SECRET' : c.sensitivity, before.floor);
    }
  }
});

test('personal-data attribute: YES dominates, model NO alone is UNKNOWN, failures block NO', () => {
  const d = (value) => ({ origin: 'DETERMINISTIC', status: 'FOUND', value });
  const s = (value) => ({ origin: 'SEMANTIC', status: 'FOUND', value });
  assert.equal(resolveAttributeDraft([d('NO')]).value, 'NO');
  assert.equal(resolveAttributeDraft([s('NO')]).value, 'UNKNOWN');
  assert.equal(resolveAttributeDraft([d('NO'), s('YES')]).value, 'YES');
  assert.ok(resolveAttributeDraft([d('NO'), s('YES')]).reasons.includes('ATTRIBUTE_CONFLICT'));
  assert.ok(resolveAttributeDraft([s('YES')]).reasons.includes('SEMANTIC_ONLY_ASSERTION'));
  assert.equal(resolveAttributeDraft([d('NO'), { origin: 'SEMANTIC', status: 'FAILURE' }]).value, 'UNKNOWN');
  assert.equal(resolveAttributeDraft([]).value, 'UNKNOWN');
  assert.equal(resolveAttributeDraft([d('MAYBE')]).value, 'UNKNOWN');
  const random = prng(0x6666);
  for (let run = 0; run < 1000; run++) {
    const claims = Array.from({ length: Math.floor(random() * 5) }, () => {
      const status = pick(random, ['FOUND', 'FOUND', 'ABSTAIN', 'FAILURE']);
      const origin = pick(random, ['DETERMINISTIC', 'SEMANTIC']);
      return status === 'FOUND' ? { origin, status, value: pick(random, ['YES', 'NO']) } : { origin, status };
    });
    const before = resolveAttributeDraft(claims).value;
    const after = resolveAttributeDraft([...claims, { origin: pick(random, ['DETERMINISTIC', 'SEMANTIC']), status: 'FOUND', value: 'YES' }]).value;
    assert.equal(after, 'YES');
    if (before === 'YES') assert.equal(resolveAttributeDraft([...claims, d('NO')]).value, 'YES');
  }
});

test('#68 fidelity: a dropped credential fails EXISTENCE; a placeholder keeps it without the value', () => {
  const apiKey = assessFidelityDraft(['EXISTENCE', 'KIND'], true);
  assert.deepEqual(apiKey.satisfying, ['SEMANTIC_PLACEHOLDER']);
  assert.ok(!apiKey.satisfying.includes('REMOVED'));
  assert.deepEqual(apiKey.unmet, []);
});

test('#68 fidelity: port 443 needs EXACT; hostnames keep relationships via synthetic identity', () => {
  assert.deepEqual(assessFidelityDraft(['EXACT_VALUE'], false).satisfying, ['EXACT']);
  assert.deepEqual(assessFidelityDraft(['RELATIONSHIP', 'CONSISTENCY', 'KIND'], false).satisfying,
    ['EXACT', 'IDENTITY_SYNTHETIC', 'OPAQUE_TOKEN']);
  assert.deepEqual(assessFidelityDraft(['GENERALIZED'], false).satisfying, ['EXACT', 'GENERALIZED']);
});

test('#68 fidelity: an exact secret requirement is unmet and points to USE without reveal', () => {
  const result = assessFidelityDraft(['EXACT_VALUE'], true);
  assert.deepEqual(result.satisfying, []);
  assert.deepEqual(result.unmet, ['EXACT_VALUE']);
  assert.deepEqual(result.advice, ['USE_WITHOUT_REVEAL', 'TASK_UNSOLVABLE_WITHOUT_RELEASE']);
});

test('property: secrets stay within the non-reversible ceiling and predicates only narrow forms', () => {
  const subsets = [];
  for (let mask = 1; mask < 1 << FIDELITY_PREDICATES.length; mask++) {
    const subset = FIDELITY_PREDICATES.filter((_, index) => mask & (1 << index));
    if (!subset.includes('NOT_REQUIRED') || subset.length === 1) subsets.push(subset);
  }
  for (const subset of subsets) {
    for (const secret of [true, false]) {
      const result = assessFidelityDraft(subset, secret);
      assert.ok(result.satisfying.every((form) => REPRESENTATIONS.includes(form)));
      if (secret) assert.ok(result.satisfying.every((form) => SECRET_REPRESENTATIONS.includes(form)));
      assert.ok(!('treatment' in result) && !('decision' in result));
      for (const predicate of FIDELITY_PREDICATES.filter((p) => !subset.includes(p) && p !== 'NOT_REQUIRED')) {
        const wider = assessFidelityDraft([...subset.filter((p) => p !== 'NOT_REQUIRED'), predicate], secret);
        assert.ok(wider.satisfying.every((form) => result.satisfying.includes(form)));
      }
    }
  }
});

test('fidelity requests reject malformed input', () => {
  for (const [predicates, secret] of [[[], false], [['EXACT_VALUE', 'EXACT_VALUE'], false], [['KEEP'], false],
    [['EXACT_VALUE'], 'no'], ['EXACT_VALUE', false]]) {
    assert.throws(() => assessFidelityDraft(predicates, secret), TypeError);
  }
});

test('semantic placeholders are typed, bounded and never look like a usable credential', () => {
  const text = semanticPlaceholder('API_KEY');
  assert.equal(text, '[hylja:protected:API_KEY]');
  assert.deepEqual({ ...parseSemanticPlaceholder(text) }, { kind: 'API_KEY' });
  for (const bad of ['api_key', 'API KEY', '', 'A'.repeat(65)]) assert.throws(() => semanticPlaceholder(bad), TypeError);
  for (const text of ['[hylja:protected:API_KEY] ', 'API_KEY_PRESENT', '[hylja:protected:]', 42, null]) {
    assert.equal(parseSemanticPlaceholder(text), null);
  }
});

const contract = {
  version: 'draft-1', taskRef: 'task-d02.invalid',
  requirements: [
    { targetRef: 'occ-port-attempted', predicates: ['EXACT_VALUE'] },
    { targetRef: 'occ-api-key', predicates: ['EXISTENCE', 'KIND'] },
    { targetRef: 'entity-host-a', predicates: ['RELATIONSHIP', 'CONSISTENCY'] },
    { targetRef: 'occ-trace', predicates: ['NOT_REQUIRED'] },
  ],
};

test('task fidelity contracts validate strictly and bind requirements to refs, not values', () => {
  const valid = validateTaskFidelityContractDraft(contract);
  assert.equal(valid.requirements.length, 4);
  assert.ok(Object.isFrozen(valid.requirements[0].predicates));
  for (const mutate of [
    (c) => { c.version = 1; }, (c) => { c.requirements = []; }, (c) => { c.treatment = 'KEEP'; },
    (c) => { c.requirements[1].targetRef = 'occ-port-attempted'; },
    (c) => { c.requirements[3].predicates = ['NOT_REQUIRED', 'KIND']; },
    (c) => { c.requirements[0].predicates = ['KEEP']; },
    (c) => { c.requirements[0].targetRef = 'has space'; },
  ]) {
    const copy = structuredClone(contract);
    mutate(copy);
    assert.equal(validateTaskFidelityContractDraft(copy), null);
  }
});

const annotation = {
  version: 'draft-1', occurrenceRef: 'occ-client-ip', entityRef: 'entity-client-a',
  semantic: { semanticType: 'NETWORK_IDENTIFIER', subtype: 'IP' },
  privacy: { personalData: 'YES', specialCategory: 'NO', jurisdictions: ['SE', 'EU'] },
  sensitivity: 'CONFIDENTIAL',
};

test('oracle annotations keep IP semantics separate from its contextual personal-data attribute', () => {
  const valid = validateOracleAnnotationDraft(annotation);
  assert.equal(valid.semantic.semanticType, 'NETWORK_IDENTIFIER');
  assert.equal(valid.privacy.personalData, 'YES');
  assert.deepEqual(valid.privacy.jurisdictions, ['EU', 'SE']);
  assert.ok(!('trust' in valid) && !('treatment' in valid));
});

test('oracle annotations reject trust, treatment, contradictions and malformed fields', () => {
  for (const mutate of [
    (a) => { a.trust = 'CONTROL'; }, (a) => { a.treatment = 'KEEP'; }, (a) => { a.sensitivity = 'UNKNOWN'; },
    (a) => { a.privacy.specialCategory = 'YES'; a.privacy.personalData = 'UNKNOWN'; },
    (a) => { a.privacy.jurisdictions = ['SE', 'SE']; }, (a) => { a.privacy.jurisdictions = ['sweden']; },
    (a) => { a.semantic.semanticType = 'person'; }, (a) => { a.semantic.raw = 'synthetic-value.invalid'; },
    (a) => { delete a.privacy.personalData; }, (a) => { a.occurrenceRef = ''; },
  ]) {
    const copy = structuredClone(annotation);
    mutate(copy);
    assert.equal(validateOracleAnnotationDraft(copy), null);
  }
});
