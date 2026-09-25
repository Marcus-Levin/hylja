/**
 * Runnable SYNTHETIC evaluation-only, NON-ENFORCING scope/authorization contract.
 * An injected boundary is tested with planted A/B contexts; it authenticates nothing.
 * No real vault, KMS/key, broker, cache or transport isolation is proved by this module.
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
function invalid(): never { throw new TypeError('Invalid synthetic scope contract input'); }
function referenceList(references: readonly ScopedReference[]): ScopedReference[] {
  try {
    if (!Array.isArray(references) || references.length < 2 || references.length > 32) invalid();
    const result = references.map((input) => {
      if (!input || typeof input !== 'object' || Array.isArray(input) ||
        ![null, Object.prototype].includes(Object.getPrototypeOf(input))) invalid();
      const keys = Reflect.ownKeys(input);
      const expected = ['kind', 'ref', 'tenantId', 'projectId', 'sessionId',
        'provenanceRef', 'principalId', 'purpose', 'destinationId'];
      if (keys.length !== expected.length || keys.some((key) => typeof key !== 'string' || !expected.includes(key))) invalid();
      const values: Record<string, string> = {};
      for (const key of expected) {
        const field = Object.getOwnPropertyDescriptor(input, key);
        if (!field || !field.enumerable || !('value' in field) || typeof field.value !== 'string' ||
          field.value.length < 1 || field.value.length > 256 || /[\u0000-\u001f\u007f]/u.test(field.value)) invalid();
        values[key] = field.value;
      }
      if (!REFERENCE_KINDS.includes(values.kind as ReferenceKind)) invalid();
      return values as unknown as ScopedReference;
    });
    if (new Set(result.map((item) => item.ref)).size !== result.length ||
      new Set(result.map((item) => item.tenantId)).size < 2 ||
      REFERENCE_KINDS.some((kind) => new Set(result.filter((item) => item.kind === kind)
        .map((item) => item.tenantId)).size < 2)) invalid();
    return result;
  } catch { return invalid(); }
}
function otherTenant(reference: ScopedReference, references: readonly ScopedReference[]): ScopedReference {
  const other = references.find((item) => item.tenantId !== reference.tenantId);
  if (!other) invalid();
  return other;
}
function forged(current: string, role: string): string {
  const first = `synthetic-forged-${role}.invalid`;
  return current === first ? `synthetic-forged-${role}-alternate.invalid` : first;
}
function unknownRef(references: readonly ScopedReference[], index: number): string {
  for (let variant = 0; variant <= references.length; variant++) {
    const value = `synthetic-unknown-${index}-${variant}.invalid`;
    if (!references.some((reference) => reference.ref === value)) return value;
  }
  return invalid();
}
const mutationLabels = [
  'cross-tenant', 'wrong-project', 'wrong-session', 'forged-provenance',
  'wrong-principal', 'wrong-purpose', 'wrong-destination', 'cross-tenant-exception',
  'unknown-reference',
] as const;
function negative(reference: ScopedReference, references: readonly ScopedReference[],
  label: (typeof mutationLabels)[number], index: number): ScopeAttempt {
  const other = otherTenant(reference, references);
  const base: ScopeAttempt = { ...reference, action: 'USE' };
  switch (label) {
    case 'cross-tenant': return { ...base, tenantId: other.tenantId };
    case 'wrong-project': return { ...base, projectId: forged(reference.projectId, 'project') };
    case 'wrong-session': return { ...base, sessionId: forged(reference.sessionId, 'session') };
    case 'forged-provenance': return { ...base, provenanceRef: forged(reference.provenanceRef, 'provenance') };
    case 'wrong-principal': return { ...base, principalId: forged(reference.principalId, 'principal') };
    case 'wrong-purpose': return { ...base, purpose: forged(reference.purpose, 'purpose') };
    case 'wrong-destination': return { ...base, destinationId: forged(reference.destinationId, 'destination') };
    case 'cross-tenant-exception': return { ...base, tenantId: other.tenantId,
      exception: { crossTenant: true, crossProject: true } };
    case 'unknown-reference': return { ...base, ref: unknownRef(references, index) };
  }
}
/** Seeded property-style negative variations; finite cap avoids accidental test-time exhaustion. */
export function generateSyntheticScopeVectors(references: readonly ScopedReference[] = SYNTHETIC_SCOPE_REFERENCES,
  seed = 1, count = 96): readonly ScopeVector[] {
  if (!Number.isSafeInteger(seed) || seed <= 0 || seed > 0xffffffff ||
    !Number.isSafeInteger(count) || count < 0 || count > 256) invalid();
  const fixtures = referenceList(references);
  let state = seed >>> 0;
  function next(): number {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    return state >>> 0;
  }
  const result: ScopeVector[] = [];
  for (let index = 0; index < count; index++) {
    const reference = fixtures[next() % fixtures.length];
    const label = mutationLabels[index % mutationLabels.length];
    if (!reference || !label) invalid();
    result.push({ id: `generated-${index}-${reference.kind}-${label}`,
      attempt: negative(reference, fixtures, label, index), expectedResolution: false, expectedAuthorization: false });
  }
  return result;
}
function staticVectors(fixtures: readonly ScopedReference[]): ScopeVector[] {
  const vectors: ScopeVector[] = [];
  for (const [index, reference] of fixtures.entries()) {
    vectors.push({ id: `static-${index}-${reference.kind}-authorized-use`,
      attempt: { ...reference, action: 'USE' }, expectedResolution: true, expectedAuthorization: true });
    for (const label of mutationLabels) vectors.push({
      id: `static-${index}-${reference.kind}-${label}`,
      attempt: negative(reference, fixtures, label, index + 1024),
      expectedResolution: false, expectedAuthorization: false,
    });
    vectors.push({ id: `static-${index}-${reference.kind}-display-not-use`,
      attempt: { ...reference, action: 'DISPLAY' }, expectedResolution: true, expectedAuthorization: false });
    vectors.push({ id: `static-${index}-${reference.kind}-export-not-display`,
      attempt: { ...reference, action: 'EXPORT' }, expectedResolution: true, expectedAuthorization: false });
  }
  return vectors;
}
/** Both positive and negative cases call the supplied boundary, never pre-deny locally. */
export async function runSyntheticScopeContract(boundary: SyntheticScopeBoundary,
  references: readonly ScopedReference[] = SYNTHETIC_SCOPE_REFERENCES): Promise<readonly ScopeFinding[]> {
  const fixtures = referenceList(references);
  if (typeof boundary?.canResolve !== 'function' || typeof boundary.authorize !== 'function') invalid();
  const findings: ScopeFinding[] = [];
  for (const vector of [...staticVectors(fixtures), ...generateSyntheticScopeVectors(fixtures)]) {
    for (const [name, expected, evaluate] of [
      ['resolution', vector.expectedResolution, boundary.canResolve.bind(boundary)],
      ['authorization', vector.expectedAuthorization, boundary.authorize.bind(boundary)],
    ] as const) {
      let outcome: ScopeFinding['outcome'] = 'fail';
      try {
        // Exceptions and malformed results are failures, not evidence that a negative case was denied.
        const actual: unknown = await evaluate(vector.attempt);
        if (typeof actual === 'boolean' && actual === expected) outcome = 'pass';
      } catch { /* Raw errors are deliberately not recorded. */ }
      findings.push({ id: vector.id, boundary: name,
        expected: expected ? 'allow' : 'deny', outcome });
    }
  }
  return findings;
}
