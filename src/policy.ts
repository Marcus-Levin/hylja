import type { Classification, SemanticClass, Sensitivity, Trust } from './classification.js';
import type { Destination, Endpoint, RequestContext, Subject } from './interaction-envelope.js';

/** Policy is a pure decision seam. Only a trusted integration may supply boundary, bundle and review. */
export const POLICY_TREATMENTS = [
  'KEEP', 'MASK', 'TOKENIZE', 'SYNTHETIC', 'GENERALIZE', 'REMOVE', 'BLOCK', 'REQUIRE_REVIEW',
] as const;
export type Treatment = (typeof POLICY_TREATMENTS)[number];
export type ReleaseTreatment = Exclude<Treatment, 'BLOCK' | 'REQUIRE_REVIEW'>;
export const POLICY_OPERATIONS = ['SEND', 'USE', 'DISPLAY', 'EXPORT'] as const;
export type PolicyOperation = (typeof POLICY_OPERATIONS)[number];
export const KNOWN_POLICY_BUNDLE = Object.freeze({ id: 'hylja.foundation', version: '1' });
export interface PolicyRequest {
  version: 1;
  interactionRef: string;
  subject: Subject;
  context: RequestContext;
  source: Endpoint;
  destination: Destination;
  classification: Classification;
  operation: PolicyOperation;
  policy: { id: string; version: string };
  /** Classification/model advice is never a policy rule or authorization. */
  semanticRecommendation?: Treatment;
}
export interface PolicyBoundary {
  interactionRef: string;
  authenticated: { subject: Subject; context: RequestContext };
  observed: { source: Endpoint & { trust: Trust }; destination: Destination };
  policy: { id: string; version: string };
}
export interface DestinationProfile {
  id: string;
  sink: Destination;
  exposure: 'LOCAL' | 'EXTERNAL';
  permittedTreatments: readonly ReleaseTreatment[];
  maxCleartextSensitivity: Sensitivity;
}
export interface PolicyRule {
  id: string;
  profileId: string;
  semanticType: SemanticClass;
  sensitivities: readonly Sensitivity[];
  sourceTrust: readonly Trust[];
  operations: readonly PolicyOperation[];
  decision: Treatment;
  reviewTreatments?: readonly ReleaseTreatment[];
}
export interface PolicyBundle {
  id: string;
  version: string;
  profiles: readonly DestinationProfile[];
  rules: readonly PolicyRule[];
}
export interface PolicyDecision {
  version: 1;
  state: 'DENIED' | 'HELD' | 'SELECTED';
  treatment: Treatment;
  reason: string;
  /** Unkeyed replay fingerprint, NOT an authorization token or proof of review. */
  decisionRef?: string;
}
export interface TrustedReviewOutcome {
  version: 1;
  decisionRef: string;
  policy: { id: string; version: string };
  binding: {
    interactionRef: string;
    subject: Subject;
    context: RequestContext;
    source: Endpoint & { trust: Trust };
    destination: Destination;
  };
  reviewerRef: string;
  treatment: ReleaseTreatment;
}

export function decidePolicy(_request: unknown, _boundary: unknown, _bundle: unknown): PolicyDecision {
  return { version: 1, state: 'DENIED', treatment: 'BLOCK', reason: 'NOT_IMPLEMENTED' };
}

export function decideReviewedPolicy(_request: unknown, _boundary: unknown, _bundle: unknown,
  _held: unknown, _outcome: unknown): PolicyDecision {
  return { version: 1, state: 'DENIED', treatment: 'BLOCK', reason: 'NOT_IMPLEMENTED' };
}
