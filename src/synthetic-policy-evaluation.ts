/**
 * Synthetic #4 policy evaluation seam, NON-ENFORCING. The separately supplied boundary,
 * composer output and bundle pins are fixture controls, NOT authenticated production facts.
 * Neither a SELECTED treatment nor a reviewed outcome authorizes plaintext or sends bytes.
 */
import { composeClassification } from './classification.js';
import { decidePolicy, decideReviewedPolicy, digestClassification, digestPolicyBundle,
  KNOWN_POLICY_BUNDLE } from './policy.js';
import type { DestinationProfile, PolicyBoundary, PolicyBundle, PolicyDecision, PolicyRequest,
  PolicyRule, TrustedReviewOutcome } from './policy.js';

export type SyntheticPolicyKind = 'public' | 'confidential' | 'restricted' | 'credential' |
  'local-use' | 'unresolved' | 'explicit-block';
export interface SyntheticPolicyFixture {
  request: PolicyRequest;
  boundary: PolicyBoundary;
  bundle: PolicyBundle;
}
export interface SyntheticPolicyAdapter {
  decide(request: PolicyRequest, boundary: PolicyBoundary, bundle: PolicyBundle):
    PolicyDecision | Promise<PolicyDecision>;
  reviewed(request: PolicyRequest, boundary: PolicyBoundary, bundle: PolicyBundle,
    previous: PolicyDecision, outcome: unknown): PolicyDecision | Promise<PolicyDecision>;
}
/** Only allowlisted test IDs/states, never a decision's raw reason, reference or request. */
export interface SyntheticPolicyFinding {
  id: string;
  expected: 'DENIED' | 'HELD' | 'SELECTED';
  outcome: 'pass' | 'fail';
}
/** The actual #4 pure decisions are a subject under test, not an authorization adapter. */
export const REAL_SYNTHETIC_POLICY_ADAPTER: SyntheticPolicyAdapter = Object.freeze({
  decide: decidePolicy,
  reviewed: decideReviewedPolicy,
});
const clone = <T>(value: T): T => structuredClone(value);
type Tenant = 'a' | 'b';
function sink(tenant: Tenant, exposure: 'LOCAL' | 'EXTERNAL') {
  return exposure === 'LOCAL' ?
    { kind: 'local.tool', ref: `local-${tenant}.example.invalid`, trustZone: 'LOCAL',
      profileId: `local-${tenant}.invalid` } :
    { kind: 'model', ref: `model-${tenant}.example.invalid`, trustZone: 'EXTERNAL',
      profileId: `profile-${tenant}.invalid` };
}
function syntheticBundle(): PolicyBundle {
  const profiles: DestinationProfile[] = [];
  const rules: PolicyRule[] = [];
  for (const tenant of ['a', 'b'] as const) {
    const external = sink(tenant, 'EXTERNAL');
    const local = sink(tenant, 'LOCAL');
    profiles.push({ id: external.profileId, sink: external, exposure: 'EXTERNAL',
      permittedTreatments: ['KEEP', 'MASK', 'SYNTHETIC', 'GENERALIZE', 'REMOVE'],
      maxCleartextSensitivity: 'PUBLIC' });
    profiles.push({ id: local.profileId, sink: local, exposure: 'LOCAL',
      permittedTreatments: ['KEEP', 'MASK', 'REMOVE'], maxCleartextSensitivity: 'CONFIDENTIAL' });
    for (const [label, semanticType, sensitivity, operation, decision, reviewTreatments] of [
      ['public', 'PERSON', 'PUBLIC', 'SEND', 'KEEP'],
      ['confidential', 'PERSON', 'CONFIDENTIAL', 'SEND', 'SYNTHETIC'],
      ['restricted', 'PERSON', 'RESTRICTED', 'SEND', 'REQUIRE_REVIEW', ['GENERALIZE', 'REMOVE']],
      ['credential', 'CREDENTIAL_OR_SECRET', 'SECRET', 'SEND', 'REMOVE'],
      ['block', 'PERSON', 'INTERNAL', 'SEND', 'BLOCK'],
    ] as const) rules.push({ id: `rule-${tenant}-${label}.invalid`, profileId: external.profileId,
      semanticType, sensitivities: [sensitivity], sourceTrust: ['TRUSTED'], operations: [operation],
      decision, ...(reviewTreatments ? { reviewTreatments: [...reviewTreatments] } : {}) });
    rules.push({ id: `rule-${tenant}-local-use.invalid`, profileId: local.profileId,
      semanticType: 'PERSON', sensitivities: ['CONFIDENTIAL'], sourceTrust: ['TRUSTED'],
      operations: ['USE'], decision: 'KEEP' });
  }
  return { ...KNOWN_POLICY_BUNDLE, profiles, rules };
}
/** Fixture author builds a separately pinned trusted composer record and policy snapshot. */
export function makeSyntheticPolicyFixture(tenant: Tenant, kind: SyntheticPolicyKind = 'confidential',
  candidateRef = `candidate-${tenant}.invalid`): SyntheticPolicyFixture {
  if (tenant !== 'a' && tenant !== 'b' || !/^[a-z][a-z0-9-]{0,63}\.invalid$/u.test(candidateRef)) {
    throw new TypeError('Invalid synthetic policy fixture');
  }
  const interactionRef = `interaction-${tenant}.invalid`;
  const source = { kind: 'tool.result', ref: `source-${tenant}.example.invalid`, trustZone: 'LOCAL' };
  const destination = sink(tenant, kind === 'local-use' ? 'LOCAL' : 'EXTERNAL');
  const context = { tenantId: `tenant-${tenant}.invalid`, projectId: `project-${tenant}.invalid`,
    sessionId: `session-${tenant}.invalid`, purpose: 'synthetic-diagnostic' };
  const subject = { principalId: `principal-${tenant}.invalid`, workloadId: `workload-${tenant}.invalid` };
  const classifierContext = { interactionRef, sourceRef: source.ref, trust: 'TRUSTED' as const };
  const sensitivity = kind === 'public' ? 'PUBLIC' : kind === 'restricted' ? 'RESTRICTED' :
    kind === 'credential' ? 'SECRET' : kind === 'explicit-block' ? 'INTERNAL' : 'CONFIDENTIAL';
  const semanticType = kind === 'credential' ? 'CREDENTIAL_OR_SECRET' : 'PERSON';
  const classification = kind === 'unresolved' ?
    composeClassification({ parserEvidence: [{ version: 1, id: `parser-${tenant}.invalid`, status: 'FAILURE',
      provenance: { inputRef: `input-${tenant}.invalid`, producerId: 'synthetic-parser.invalid',
        producerVersion: '1' } }] }, classifierContext) :
    composeClassification({ detectorEvidence: [{ version: 1, id: `detector-${tenant}.invalid`, status: 'FOUND',
      provenance: { inputRef: `input-${tenant}.invalid`, producerId: 'synthetic-detector.invalid',
        producerVersion: '1' }, claim: { semanticType, subtype: kind === 'credential' ? 'API_KEY' : 'NAME',
        sensitivity } }] }, classifierContext);
  const bundle = syntheticBundle();
  // Pin these values before constructing the separately mutable request; never repin after mutation.
  const classificationDigest = digestClassification(classification);
  const policyDigest = digestPolicyBundle(bundle);
  const boundary: PolicyBoundary = { interactionRef, candidateRef, classificationDigest,
    authenticated: { subject: clone(subject), context: clone(context) },
    observed: { source: { ...source, trust: 'TRUSTED' }, destination: clone(destination) },
    policy: { ...KNOWN_POLICY_BUNDLE, digest: policyDigest } };
  const request: PolicyRequest = { version: 1, interactionRef, candidateRef,
    subject: clone(subject), context: clone(context), source: clone(source),
    destination: clone(destination), classification: clone(classification),
    operation: kind === 'local-use' ? 'USE' : 'SEND', policy: clone(KNOWN_POLICY_BUNDLE) };
  return { request, boundary, bundle };
}
function review(fixture: SyntheticPolicyFixture, held: PolicyDecision): TrustedReviewOutcome {
  if (held.state !== 'HELD' || !held.decisionRef) throw new TypeError('Invalid synthetic review fixture');
  const b = fixture.boundary;
  return { version: 1, decisionRef: held.decisionRef, policy: clone(b.policy),
    binding: { interactionRef: b.interactionRef, candidateRef: b.candidateRef,
      classificationDigest: b.classificationDigest,
      subject: clone(b.authenticated.subject), context: clone(b.authenticated.context),
      source: clone(b.observed.source), destination: clone(b.observed.destination) },
    reviewerRef: 'reviewer-synthetic.invalid', treatment: 'GENERALIZE' };
}
type State = PolicyDecision['state'];
type Treatment = PolicyDecision['treatment'];
function conforms(value: unknown, state: State, treatment: Treatment): boolean {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
    const keys = Reflect.ownKeys(value);
    if (keys.length < 4 || keys.length > 5 || keys.some((key) => typeof key !== 'string' ||
      !['version', 'state', 'treatment', 'reason', 'decisionRef'].includes(key))) return false;
    const v = value as Record<string, unknown>;
    if (v.version !== 1 || v.state !== state || v.treatment !== treatment ||
      typeof v.reason !== 'string' || !v.reason.length || v.reason.length > 64) return false;
    return state === 'DENIED' ? !Object.hasOwn(v, 'decisionRef') :
      typeof v.decisionRef === 'string' && /^[a-f0-9]{64}$/u.test(v.decisionRef);
  } catch { return false; }
}
interface Check {
  id: string;
  fixture: SyntheticPolicyFixture;
  state: State;
  treatment: Treatment;
  previous?: PolicyDecision;
  outcome?: unknown;
  review: boolean;
}
/** Positive controls and adversarial cases call the injected adapter; expected outcomes are fixed independently. */
export async function runSyntheticPolicyInvariants(adapter: SyntheticPolicyAdapter = REAL_SYNTHETIC_POLICY_ADAPTER):
  Promise<readonly SyntheticPolicyFinding[]> {
  let decide: SyntheticPolicyAdapter['decide'];
  let reviewed: SyntheticPolicyAdapter['reviewed'];
  try {
    // Snapshot hostile method getters once and never echo caller-thrown errors.
    const first = adapter?.decide;
    const second = adapter?.reviewed;
    if (typeof first !== 'function' || typeof second !== 'function') throw new TypeError();
    decide = (request, boundary, bundle) => Reflect.apply(first, adapter, [request, boundary, bundle]) as PolicyDecision;
    reviewed = (request, boundary, bundle, prior, approval) => Reflect.apply(second, adapter,
      [request, boundary, bundle, prior, approval]) as PolicyDecision;
  } catch { throw new TypeError('Invalid synthetic policy adapter'); }
  const checks: Check[] = [];
  function add(id: string, fixture: SyntheticPolicyFixture, state: State, treatment: Treatment,
    previous?: PolicyDecision, outcome?: unknown): void {
    checks.push({ id, fixture, state, treatment, review: previous !== undefined,
      ...(previous ? { previous } : {}), ...(outcome !== undefined ? { outcome } : {}) });
  }
  for (const tenant of ['a', 'b'] as const) {
    for (const [kind, state, treatment] of [
      ['public', 'SELECTED', 'KEEP'], ['confidential', 'SELECTED', 'SYNTHETIC'],
      ['restricted', 'HELD', 'REQUIRE_REVIEW'], ['credential', 'SELECTED', 'REMOVE'],
      ['local-use', 'SELECTED', 'KEEP'], ['unresolved', 'DENIED', 'BLOCK'],
      ['explicit-block', 'DENIED', 'BLOCK'],
    ] as const) add(`${tenant}-${kind}`, makeSyntheticPolicyFixture(tenant, kind), state, treatment);
    const negative = (id: string, change: (f: SyntheticPolicyFixture) => void) => {
      const fixture = makeSyntheticPolicyFixture(tenant);
      change(fixture);
      add(`${tenant}-${id}`, fixture, 'DENIED', 'BLOCK');
    };
    const other = tenant === 'a' ? 'b' : 'a';
    negative('wrong-tenant', (f) => { f.request.context.tenantId = `tenant-${other}.invalid`; });
    negative('wrong-project', (f) => { f.request.context.projectId = `project-${other}.invalid`; });
    negative('wrong-session', (f) => { f.request.context.sessionId = `session-${other}.invalid`; });
    negative('wrong-principal', (f) => { f.request.subject.principalId = `principal-${other}.invalid`; });
    negative('wrong-purpose', (f) => { f.request.context.purpose = `purpose-${other}.invalid`; });
    negative('wrong-candidate', (f) => { f.request.candidateRef = `candidate-${other}.invalid`; });
    negative('missing-profile', (f) => { f.request.destination.profileId = 'missing-profile.invalid'; });
    negative('route-mismatch', (f) => { f.boundary.observed.destination.ref = 'redirect.example.invalid'; });
    negative('bundle-swap', (f) => {
      f.bundle.rules.find((rule) => rule.id === `rule-${tenant}-confidential.invalid`)!.decision = 'KEEP';
    });
    negative('classification-swap', (f) => {
      f.request.classification = makeSyntheticPolicyFixture(tenant, 'public').request.classification;
    });
    negative('untrusted-semantic-advice', (f) => {
      f.bundle.rules.find((rule) => rule.id === `rule-${tenant}-confidential.invalid`)!.decision = 'BLOCK';
      // An approved BLOCK snapshot must have its own independently pinned digest.
      f.boundary.policy.digest = digestPolicyBundle(f.bundle);
      f.request.semanticRecommendation = 'KEEP';
    });
    negative('unknown-bundle', (f) => { f.request.policy.version = '2'; });
    negative('unsupported-operation', (f) => { f.request.operation = 'EXPORT'; });
    const a = makeSyntheticPolicyFixture(tenant, 'restricted', `unit-${tenant}-one.invalid`);
    const b = makeSyntheticPolicyFixture(tenant, 'restricted', `unit-${tenant}-two.invalid`);
    const otherTenant = makeSyntheticPolicyFixture(other, 'restricted', `unit-${other}-one.invalid`);
    // Reference fixture fingerprints are calculated from the reviewed #4 policy, never from
    // the injected adapter's output; the expected state/treatment is separately enumerated.
    const heldA = decidePolicy(a.request, a.boundary, a.bundle);
    const heldB = decidePolicy(b.request, b.boundary, b.bundle);
    const heldOther = decidePolicy(otherTenant.request, otherTenant.boundary, otherTenant.bundle);
    const approvedA = review(a, heldA);
    add(`${tenant}-review-own-candidate`, a, 'SELECTED', 'GENERALIZE', heldA, approvedA);
    add(`${tenant}-review-other-candidate`, b, 'HELD', 'REQUIRE_REVIEW', heldB, approvedA);
    add(`${tenant}-review-other-tenant`, otherTenant, 'HELD', 'REQUIRE_REVIEW', heldOther, approvedA);
    add(`${tenant}-review-missing`, a, 'HELD', 'REQUIRE_REVIEW', heldA);
    add(`${tenant}-review-forged-candidate`, a, 'HELD', 'REQUIRE_REVIEW', heldA,
      { ...approvedA, binding: { ...approvedA.binding, candidateRef: `unit-${tenant}-two.invalid` } });
    const staleRoute = clone(a);
    staleRoute.boundary.observed.destination.ref = 'redirect.example.invalid';
    add(`${tenant}-review-stale-route`, staleRoute, 'DENIED', 'BLOCK', heldA, approvedA);
    const staleBundle = clone(a);
    staleBundle.bundle.rules.find((rule) => rule.id === `rule-${tenant}-restricted.invalid`)!.decision = 'BLOCK';
    add(`${tenant}-review-stale-bundle`, staleBundle, 'DENIED', 'BLOCK', heldA, approvedA);
  }
  const findings: SyntheticPolicyFinding[] = [];
  for (const item of checks) {
    let verdict: SyntheticPolicyFinding['outcome'] = 'fail';
    try {
      const f = item.fixture;
      const decision: unknown = item.review ? await reviewed(f.request, f.boundary, f.bundle,
        item.previous as PolicyDecision, item.outcome) : await decide(f.request, f.boundary, f.bundle);
      if (conforms(decision, item.state, item.treatment)) verdict = 'pass';
    } catch { /* Raw adapter errors are not report data or successful denials. */ }
    findings.push({ id: item.id, expected: item.state, outcome: verdict });
  }
  return findings;
}
