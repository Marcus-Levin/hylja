import assert from 'node:assert/strict';
import { test } from 'node:test';
import { composeClassification, SEMANTIC_CLASSES, TRUST_LEVELS } from '../dist/classification.js';
import {
  decidePolicy, decideReviewedPolicy, POLICY_TREATMENTS, POLICY_OPERATIONS, KNOWN_POLICY_BUNDLE,
} from '../dist/policy.js';

const copy = (value) => structuredClone(value);
const subject = { principalId: 'principal-a.invalid', workloadId: 'workload-a.invalid' };
const context = {
  tenantId: 'tenant-a.invalid', projectId: 'project-a.invalid',
  sessionId: 'session-a.invalid', purpose: 'diagnostic-a.invalid',
};
const source = { kind: 'tool.result', ref: 'tool-source-a.invalid', trustZone: 'LOCAL' };
const sinks = {
  local: { kind: 'local.tool', ref: 'tool-local.example.invalid', trustZone: 'LOCAL', profileId: 'local.invalid' },
  enterprise: { kind: 'model', ref: 'enterprise.example.invalid', trustZone: 'EXTERNAL', profileId: 'enterprise.invalid' },
  web: { kind: 'web', ref: 'web.example.invalid', trustZone: 'EXTERNAL', profileId: 'web.invalid' },
};
const sensitivities = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'SECRET'];
const ALL_TRUST = [...TRUST_LEVELS];
const release = ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE'];
const profiles = [
  { id: 'local.invalid', sink: sinks.local, exposure: 'LOCAL', permittedTreatments: release,
    maxCleartextSensitivity: 'SECRET' },
  { id: 'enterprise.invalid', sink: sinks.enterprise, exposure: 'EXTERNAL', permittedTreatments: release,
    maxCleartextSensitivity: 'INTERNAL' },
  { id: 'web.invalid', sink: sinks.web, exposure: 'EXTERNAL', permittedTreatments: ['KEEP', 'MASK', 'REMOVE'],
    maxCleartextSensitivity: 'PUBLIC' },
];
function rule(id, profileId, semanticType, values, operations, decision, sourceTrust = ALL_TRUST, reviewTreatments) {
  return { id: `${id}.invalid`, profileId, semanticType, sensitivities: values,
    sourceTrust, operations, decision, ...(reviewTreatments ? { reviewTreatments } : {}) };
}
function bundle() {
  const rules = [];
  for (const semanticType of SEMANTIC_CLASSES) {
    rules.push(rule(`local-use-${semanticType}`, 'local.invalid', semanticType, sensitivities, ['USE'], 'KEEP'));
    rules.push(rule(`local-display-${semanticType}`, 'local.invalid', semanticType, sensitivities, ['DISPLAY'], 'MASK'));
    rules.push(rule(`enterprise-public-${semanticType}`, 'enterprise.invalid', semanticType,
      ['PUBLIC'], ['SEND'], 'KEEP'));
    rules.push(rule(`enterprise-internal-${semanticType}`, 'enterprise.invalid', semanticType,
      ['INTERNAL'], ['SEND'], 'TOKENIZE'));
    rules.push(rule(`enterprise-confidential-${semanticType}`, 'enterprise.invalid', semanticType,
      ['CONFIDENTIAL'], ['SEND'], 'SYNTHETIC'));
    rules.push(rule(`enterprise-review-${semanticType}`, 'enterprise.invalid', semanticType,
      ['RESTRICTED'], ['SEND'], 'REQUIRE_REVIEW', ALL_TRUST, ['GENERALIZE', 'REMOVE']));
    rules.push(rule(`web-public-${semanticType}`, 'web.invalid', semanticType,
      ['PUBLIC'], ['SEND'], 'KEEP'));
  }
  rules.push(rule('enterprise-credential-remove', 'enterprise.invalid', 'CREDENTIAL_OR_SECRET',
    ['SECRET'], ['SEND'], 'REMOVE'));
  return { ...KNOWN_POLICY_BUNDLE, profiles: copy(profiles), rules };
}
function classification(semanticType = 'PERSON', sensitivity = 'CONFIDENTIAL', trust = 'TRUSTED') {
  return composeClassification({ detectorEvidence: [{
    version: 1, id: 'detector-a.invalid', status: 'FOUND',
    provenance: { inputRef: 'field-a.invalid', producerId: 'detector-a.invalid', producerVersion: 'pack-1' },
    claim: { semanticType, sensitivity },
  }] }, { interactionRef: 'interaction-a.invalid', sourceRef: source.ref, trust });
}
function scenario({ destination = sinks.enterprise, semanticType = 'PERSON', sensitivity = 'CONFIDENTIAL',
  trust = 'TRUSTED', operation = 'SEND', evidence = classification(semanticType, sensitivity, trust) } = {}) {
  const boundary = {
    interactionRef: 'interaction-a.invalid', authenticated: { subject: copy(subject), context: copy(context) },
    observed: { source: { ...source, trust }, destination: copy(destination) },
    policy: copy(KNOWN_POLICY_BUNDLE),
  };
  const request = {
    version: 1, interactionRef: boundary.interactionRef, subject: copy(subject), context: copy(context),
    source: copy(source), destination: copy(destination), classification: evidence, operation,
    policy: copy(KNOWN_POLICY_BUNDLE),
  };
  return { request, boundary, policy: bundle() };
}
function evaluate(s) { return decidePolicy(s.request, s.boundary, s.policy); }
function expectDecision(value, state, treatment) {
  assert.equal(value.version, 1);
  assert.equal(value.state, state);
  assert.equal(value.treatment, treatment);
  assert.ok(typeof value.reason === 'string' && value.reason.length);
  assert.equal(Object.hasOwn(value, 'payload'), false, 'a decision never carries bytes');
  assert.equal(Object.hasOwn(value, 'effect'), false, 'a decision never performs effects');
}
function outcome(s, held, treatment = 'GENERALIZE') {
  return { version: 1, decisionRef: held.decisionRef, policy: copy(s.boundary.policy),
    binding: { interactionRef: s.boundary.interactionRef, subject: copy(s.boundary.authenticated.subject),
      context: copy(s.boundary.authenticated.context), source: copy(s.boundary.observed.source),
      destination: copy(s.boundary.observed.destination) },
    reviewerRef: 'reviewer-a.invalid', treatment };
}

test('vocabulary includes all eight policy treatments and distinct SEND/USE/DISPLAY/EXPORT', () => {
  assert.deepEqual(POLICY_TREATMENTS,
    ['KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE', 'BLOCK', 'REQUIRE_REVIEW']);
  assert.deepEqual(POLICY_OPERATIONS, ['SEND', 'USE', 'DISPLAY', 'EXPORT']);
});

test('synthetic class × source trust × actual sink matrix selects explicit rule, not unknown fallback', () => {
  let checked = 0;
  for (const semanticType of SEMANTIC_CLASSES) for (const trust of TRUST_LEVELS) {
    const credential = semanticType === 'CREDENTIAL_OR_SECRET';
    for (const [destination, operation, state, treatment] of [
      [sinks.local, 'USE', 'SELECTED', 'KEEP'],
      [sinks.enterprise, 'SEND', 'SELECTED', credential ? 'REMOVE' : 'SYNTHETIC'],
      [sinks.web, 'SEND', 'DENIED', 'BLOCK'],
    ]) {
      const s = scenario({ destination, semanticType, sensitivity: credential ? 'SECRET' : 'CONFIDENTIAL',
        trust, operation });
      assert.equal(s.request.classification.status, 'RESOLVED', semanticType);
      expectDecision(evaluate(s), state, treatment);
      checked++;
    }
  }
  assert.equal(checked, 180);
});

test('operation separation requires independent explicit USE, DISPLAY and EXPORT rules', () => {
  for (const operation of POLICY_OPERATIONS) {
    const s = scenario({ destination: sinks.local, operation });
    expectDecision(evaluate(s), operation === 'USE' || operation === 'DISPLAY' ? 'SELECTED' : 'DENIED',
      operation === 'USE' ? 'KEEP' : operation === 'DISPLAY' ? 'MASK' : 'BLOCK');
  }
  const s = scenario({ destination: sinks.local, operation: 'EXPORT' });
  s.policy.rules.push(rule('explicit-export', 'local.invalid', 'PERSON', ['CONFIDENTIAL'], ['EXPORT'], 'REMOVE'));
  expectDecision(evaluate(s), 'SELECTED', 'REMOVE');
  assert.equal(evaluate(scenario({ destination: sinks.enterprise, operation: 'EXPORT' })).state, 'DENIED');
});

test('actual route, claim, profile sink and exposure must all agree, including redirects', () => {
  const original = scenario();
  expectDecision(evaluate(original), 'SELECTED', 'SYNTHETIC');
  for (const mutate of [
    s => { s.boundary.observed.destination = copy(sinks.web); },
    s => { s.request.destination.profileId = 'unknown.invalid'; },
    s => { delete s.boundary.observed.destination.profileId; },
    s => { s.policy.profiles[1].sink.ref = 'redirect.example.invalid'; },
    s => { s.policy.profiles[1].exposure = 'LOCAL'; },
    s => { s.policy.profiles.splice(1, 1); },
    s => { s.policy.profiles[1].id = 'unknown.invalid'; },
    s => { s.policy.profiles.push(copy(s.policy.profiles[1])); },
  ]) {
    const s = scenario();
    mutate(s);
    expectDecision(evaluate(s), 'DENIED', 'BLOCK');
  }
});

test('no missing, unknown, stale or conflicting bundle ID/version permits protected release', () => {
  expectDecision(evaluate(scenario()), 'SELECTED', 'SYNTHETIC');
  for (const mutate of [
    s => { delete s.request.policy; },
    s => { delete s.boundary.policy; },
    s => { s.request.policy.version = '2'; },
    s => { s.boundary.policy.id = 'unknown.invalid'; },
    s => { s.policy.version = '2'; },
    s => { s.policy.id = 'unknown.invalid'; },
    s => { s.policy.rules.push(copy(s.policy.rules[0])); },
  ]) {
    const s = scenario();
    mutate(s);
    expectDecision(evaluate(s), 'DENIED', 'BLOCK');
  }
});

test('binding mismatches for authenticated principal/workload/tenant/project/session/purpose and source fail closed', () => {
  expectDecision(evaluate(scenario()), 'SELECTED', 'SYNTHETIC');
  const fields = [
    s => { s.request.subject.principalId = 'principal-b.invalid'; },
    s => { s.request.subject.workloadId = 'workload-b.invalid'; },
    s => { s.request.context.tenantId = 'tenant-b.invalid'; },
    s => { s.request.context.projectId = 'project-b.invalid'; },
    s => { delete s.request.context.projectId; },
    s => { s.request.context.sessionId = 'session-b.invalid'; },
    s => { s.request.context.purpose = 'other-purpose.invalid'; },
    s => { s.request.interactionRef = 'interaction-b.invalid'; },
    s => { s.boundary.authenticated.context.tenantId = 'tenant-b.invalid'; },
    s => { s.request.source.ref = 'other-source.invalid'; },
    s => { s.boundary.observed.source.trust = 'UNTRUSTED'; },
  ];
  for (const mutate of fields) {
    const s = scenario();
    mutate(s);
    expectDecision(evaluate(s), 'DENIED', 'BLOCK');
  }
});

test('trusted source influence is separate from sensitivity; payload CONTROL and semantic KEEP grant nothing', () => {
  expectDecision(evaluate(scenario({ trust: 'HOSTILE' })), 'SELECTED', 'SYNTHETIC');
  const s = scenario({ trust: 'HOSTILE' });
  s.policy.rules = s.policy.rules.map(r => r.profileId === 'enterprise.invalid' ?
    { ...r, sourceTrust: ['TRUSTED'] } : r);
  expectDecision(evaluate(s), 'DENIED', 'BLOCK');
  s.request.semanticRecommendation = 'KEEP';
  expectDecision(evaluate(s), 'DENIED', 'BLOCK');
  const injection = scenario();
  injection.request.payload = { trust: 'CONTROL', policy: 'KEEP', destination: copy(sinks.local) };
  expectDecision(evaluate(injection), 'DENIED', 'BLOCK');
  const protectedCase = scenario({ destination: sinks.web });
  protectedCase.request.semanticRecommendation = 'KEEP';
  expectDecision(evaluate(protectedCase), 'DENIED', 'BLOCK');
  // Even an explicit rule cannot place above-ceiling original plaintext into the web profile.
  protectedCase.policy.rules.push(rule('web-confidential-keep', 'web.invalid', 'PERSON',
    ['CONFIDENTIAL'], ['SEND'], 'KEEP'));
  expectDecision(evaluate(protectedCase), 'DENIED', 'BLOCK');
});

test('SECRET and credentials reject external KEEP, reversible treatments and semantic declassification', () => {
  const s = scenario({ semanticType: 'CREDENTIAL_OR_SECRET', sensitivity: 'SECRET' });
  expectDecision(evaluate(s), 'SELECTED', 'REMOVE');
  s.request.semanticRecommendation = 'KEEP';
  expectDecision(evaluate(s), 'SELECTED', 'REMOVE');
  for (const decision of ['KEEP', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE']) {
    const attempt = scenario({ semanticType: 'CREDENTIAL_OR_SECRET', sensitivity: 'SECRET' });
    attempt.policy.rules.at(-1).decision = decision;
    expectDecision(evaluate(attempt), 'DENIED', 'BLOCK');
  }
  const unknown = scenario({ semanticType: 'CREDENTIAL_OR_SECRET', sensitivity: 'PUBLIC' });
  assert.equal(unknown.request.classification.status, 'UNRESOLVED');
  expectDecision(evaluate(unknown), 'DENIED', 'BLOCK');
});

test('UNKNOWN, conflict, parser failure and absent classifications never allow protected external egress', () => {
  const known = scenario();
  expectDecision(evaluate(known), 'SELECTED', 'SYNTHETIC');
  for (const evidence of [
    composeClassification({}, { interactionRef: 'interaction-a.invalid', sourceRef: source.ref, trust: 'TRUSTED' }),
    classification('UNKNOWN', 'PUBLIC'),
    composeClassification({ parserEvidence: [{ version: 1, id: 'parser-a.invalid', status: 'FAILURE',
      provenance: { inputRef: 'field-a.invalid', producerId: 'parser-a.invalid', producerVersion: 'pack-1' } }] },
    { interactionRef: 'interaction-a.invalid', sourceRef: source.ref, trust: 'TRUSTED' }),
    undefined,
  ]) {
    const s = scenario();
    s.request.classification = evidence;
    expectDecision(evaluate(s), 'DENIED', 'BLOCK');
  }
});

test('review is held, separate, attributable and bounded to current policy approved treatments', () => {
  const s = scenario({ sensitivity: 'RESTRICTED' });
  const held = evaluate(s);
  expectDecision(held, 'HELD', 'REQUIRE_REVIEW');
  assert.match(held.decisionRef, /^[a-f0-9]{64}$/u);
  expectDecision(decideReviewedPolicy(s.request, s.boundary, s.policy, held, undefined), 'HELD', 'REQUIRE_REVIEW');
  expectDecision(decideReviewedPolicy(s.request, s.boundary, s.policy, held,
    { ...outcome(s, held), treatment: 'KEEP' }), 'HELD', 'REQUIRE_REVIEW');
  expectDecision(decideReviewedPolicy(s.request, s.boundary, s.policy, held,
    outcome(s, held)), 'SELECTED', 'GENERALIZE');
  expectDecision(decideReviewedPolicy(s.request, s.boundary, s.policy, held,
    outcome(s, held, 'REMOVE')), 'SELECTED', 'REMOVE');
  expectDecision(evaluate(s), 'HELD', 'REQUIRE_REVIEW');
});

test('review cannot borrow another tenant, route, action, version or decision; stale rules fail closed', () => {
  const s = scenario({ sensitivity: 'RESTRICTED' });
  const held = evaluate(s);
  expectDecision(held, 'HELD', 'REQUIRE_REVIEW');
  for (const mutate of [
    r => { r.binding.context.tenantId = 'tenant-b.invalid'; },
    r => { r.binding.subject.principalId = 'principal-b.invalid'; },
    r => { r.binding.context.projectId = 'project-b.invalid'; },
    r => { r.binding.context.sessionId = 'session-b.invalid'; },
    r => { r.binding.context.purpose = 'other-purpose.invalid'; },
    r => { r.binding.source.ref = 'other-source.invalid'; },
    r => { r.binding.destination = copy(sinks.web); },
    r => { r.policy.version = '2'; },
    r => { r.decisionRef = '0'.repeat(64); },
    r => { delete r.reviewerRef; },
  ]) {
    const review = outcome(s, held);
    mutate(review);
    expectDecision(decideReviewedPolicy(s.request, s.boundary, s.policy, held, review), 'HELD', 'REQUIRE_REVIEW');
  }
  const changed = scenario({ sensitivity: 'RESTRICTED' });
  changed.policy.rules = changed.policy.rules.filter(r => r.id !== 'enterprise-review-PERSON.invalid');
  expectDecision(decideReviewedPolicy(changed.request, changed.boundary, changed.policy, held,
    outcome(s, held)), 'DENIED', 'BLOCK');
  const widened = scenario({ sensitivity: 'RESTRICTED' });
  widened.policy.rules.find(r => r.id === 'enterprise-review-PERSON.invalid').reviewTreatments.push('MASK');
  expectDecision(decideReviewedPolicy(widened.request, widened.boundary, widened.policy, held,
    outcome(s, held)), 'DENIED', 'BLOCK');
  const otherAction = scenario({ sensitivity: 'RESTRICTED', operation: 'EXPORT' });
  expectDecision(decideReviewedPolicy(otherAction.request, otherAction.boundary, otherAction.policy,
    held, outcome(s, held)), 'DENIED', 'BLOCK');
});

test('duplicate matching rules, malformed profiles, and profile treatment ceilings deny rather than first match', () => {
  expectDecision(evaluate(scenario()), 'SELECTED', 'SYNTHETIC');
  const s = scenario();
  s.policy.rules.push(rule('overlap', 'enterprise.invalid', 'PERSON',
    ['CONFIDENTIAL'], ['SEND'], 'KEEP'));
  expectDecision(evaluate(s), 'DENIED', 'BLOCK');
  for (const mutate of [
    policy => { policy.profiles[1].permittedTreatments = ['KEEP']; },
    policy => { policy.profiles[1].maxCleartextSensitivity = 'PUBLIC';
      policy.rules.find(r => r.id === 'enterprise-confidential-PERSON.invalid').decision = 'KEEP'; },
    policy => { policy.profiles[1].permittedTreatments = ['KEEP', 'BLOCK']; },
    policy => { policy.rules.find(r => r.id === 'enterprise-confidential-PERSON.invalid').sourceTrust = []; },
  ]) {
    const attempt = scenario();
    mutate(attempt.policy);
    expectDecision(evaluate(attempt), 'DENIED', 'BLOCK');
  }
});

test('decisions replay exactly from durable non-secret policy/context/classification, regardless rule order', () => {
  const s = scenario({ destination: sinks.enterprise, sensitivity: 'RESTRICTED' });
  const held = evaluate(s);
  expectDecision(held, 'HELD', 'REQUIRE_REVIEW');
  const replay = copy(s);
  replay.policy.rules.reverse();
  replay.policy.profiles.reverse();
  assert.deepEqual(evaluate(replay), held);
  assert.deepEqual(decideReviewedPolicy(replay.request, replay.boundary, replay.policy,
    copy(held), copy(outcome(s, held))),
  decideReviewedPolicy(s.request, s.boundary, s.policy, held, outcome(s, held)));
  assert.equal(JSON.stringify(held).includes('field-a.invalid'), false);
  assert.equal(JSON.stringify(held).includes('principal-a.invalid'), false);
});
