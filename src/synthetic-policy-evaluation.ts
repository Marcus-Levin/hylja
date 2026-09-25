/** SYNTHETIC evaluation-only adapter for #4 pure policy decisions; NON-ENFORCING, no broker or byte send. */
import { decidePolicy, decideReviewedPolicy } from './policy.js';
import type { PolicyBoundary, PolicyBundle, PolicyDecision, PolicyRequest } from './policy.js';

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
export interface SyntheticPolicyFinding {
  id: string;
  expected: 'DENIED' | 'HELD' | 'SELECTED';
  outcome: 'pass' | 'fail';
}
/** The real #4 implementation is only an injectable subject under test, never authorization. */
export const REAL_SYNTHETIC_POLICY_ADAPTER: SyntheticPolicyAdapter = Object.freeze({
  decide: decidePolicy,
  reviewed: decideReviewedPolicy,
});
export function makeSyntheticPolicyFixture(_tenant: 'a' | 'b', _kind: SyntheticPolicyKind = 'confidential',
  _candidateRef?: string): SyntheticPolicyFixture {
  return { request: {} as PolicyRequest, boundary: {} as PolicyBoundary, bundle: {} as PolicyBundle };
}
export async function runSyntheticPolicyInvariants(_adapter: SyntheticPolicyAdapter = REAL_SYNTHETIC_POLICY_ADAPTER):
  Promise<readonly SyntheticPolicyFinding[]> { return []; }
