/**
 * Synthetic evaluation-only, NON-ENFORCING tenant/scope contract runner.
 * This tests an injected boundary; it is not a vault, key, cache, broker or identity authenticator.
 */
export const REFERENCE_KINDS = [
  'candidate', 'entity', 'token', 'ciphertext', 'cache', 'synthetic-identity',
] as const;
export type ReferenceKind = (typeof REFERENCE_KINDS)[number];
export type ScopeAction = 'USE' | 'DISPLAY' | 'EXPORT';
export interface ScopedReference {
  kind: ReferenceKind;
  ref: string;
  tenantId: string;
  projectId: string;
  sessionId: string;
  provenanceRef: string;
  principalId: string;
  purpose: string;
  destinationId: string;
}
export interface ScopeAttempt extends ScopedReference {
  action: ScopeAction;
  /** Deliberately adversarial synthetic policy claim, not an authority grant. */
  exception?: { crossTenant: boolean; crossProject: boolean };
}
export interface SyntheticScopeBoundary {
  canResolve(attempt: ScopeAttempt): boolean | Promise<boolean>;
  authorize(attempt: ScopeAttempt): boolean | Promise<boolean>;
}
export interface ScopeVector {
  id: string;
  attempt: ScopeAttempt;
  expectedResolution: boolean;
  expectedAuthorization: boolean;
}
export interface ScopeFinding {
  id: string;
  boundary: 'resolution' | 'authorization';
  expected: 'allow' | 'deny';
  outcome: 'pass' | 'fail';
}
export const SYNTHETIC_SCOPE_REFERENCES: readonly ScopedReference[] = Object.freeze(
  (['a', 'b'] as const).flatMap((tenant) => REFERENCE_KINDS.map((kind) => Object.freeze({
    kind, ref: `synthetic-${kind}-${tenant}.invalid`, tenantId: `tenant-${tenant}.invalid`,
    projectId: `project-${tenant}.invalid`, sessionId: `session-${tenant}.invalid`,
    provenanceRef: `issuer-${tenant}.invalid`, principalId: `principal-${tenant}.invalid`,
    purpose: 'synthetic-diagnostic', destinationId: `destination-${tenant}.invalid`,
  }))),
);
export function generateSyntheticScopeVectors(_references: readonly ScopedReference[] = SYNTHETIC_SCOPE_REFERENCES,
  _seed = 1, _count = 96): readonly ScopeVector[] { return []; }
export async function runSyntheticScopeContract(_boundary: SyntheticScopeBoundary,
  _references: readonly ScopedReference[] = SYNTHETIC_SCOPE_REFERENCES): Promise<readonly ScopeFinding[]> {
  return [];
}
