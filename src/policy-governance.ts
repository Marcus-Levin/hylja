/**
 * #28 bounded OFFLINE policy governance substrate: versioned configuration snapshots, narrow
 * time-limited exceptions, a bounded policy-diff simulation, and separate approval / audit hooks.
 *
 * What this is: a deterministic, provider- and harness-independent substrate over synthetic data.
 * It keeps a **versioned policy configuration** (a governance revision plus an independent content
 * pin over the exact #4 bundle), **narrow exception objects** bound to one tenant, project,
 * subject, purpose, semantic class, sensitivity, destination and operation with an automatic expiry
 * and an explicit revocation, a **bounded simulation** that reports the classes, sinks and
 * operations a candidate configuration would newly expose, and hooks that require a *separately
 * supplied* approval and a *separately supplied* #20 audit record before any activation.
 *
 * What this is NOT, by construction:
 *
 * - It is **NON-ENFORCING**. Nothing here selects a treatment, transforms content, resolves an
 *   original, brokers anything, sends a byte or authorizes an effect. `decidePolicy` remains the
 *   only decision identity, `hylja.foundation` version `1` remains the only supported policy
 *   schema, and an exception evaluation carries `authority: 'NONE'` and `grantsTreatment: false`.
 * - It has **no** global or wildcard bypass: tenant, project, subject, purpose, class,
 *   sensitivity, destination and operation are single-valued and all required, an exception must
 *   expire within a hard ceiling, and an `UNSUPPORTED` policy id/version is refused rather than
 *   extended. A governance revision is a registry bookkeeping number, never a policy version.
 * - It has **no** provider API, HTTP or admin server, persistence, authentication service, key
 *   management, production registry or distribution mechanism, real signing authority,
 *   vault/mapping lookup, transport, #13 treatment semantics, #19 send path, deployment or
 *   managed-network enforcement. #48's administrative-plane reuse decision stays open; this is a
 *   separately reviewable bounded foundation, not product adoption.
 * - **Authentication and project membership are trusted integration obligations.** An approval is
 *   a structural assertion that a trusted integration authenticated an approver and bound it to
 *   project membership; this module verifies congruence, digests, windows and scope, and never
 *   claims to have authenticated anyone. A request string, a metadata field or a model output can
 *   supply none of these. The congruence digests here are unkeyed commitments, not credentials.
 * - **The audit is #20's, not this module's.** Approval and audit are separate inputs; an
 *   unavailable, sealed or out-of-scope audit leaves a high-risk activation **unchanged** with a
 *   fixed refusal rather than a partial promotion.
 *
 * Everything a refusal can carry is a fixed code from `GOVERNANCE_REASON_CODES`. No raw original,
 * policy-request content, free-text purpose, caller object or exception message reaches an
 * outcome, a simulation report or an audit record, and every untrusted container is read once from
 * a bounded own-key snapshot of own data descriptors with its declared length capped before any
 * sort, hash, parse or comparison.
 *
 * See docs/contracts/policy-governance-contract.md.
 */
import { appendAuditEvent, gateHighRiskEffect } from './audit-ledger.js';
import type {
  AuditAppendFinding, AuditAppendResult, AuditBundleComponent, AuditTrustedContext,
} from './audit-ledger.js';
import { canonicalJson, sha256Hex } from './canonical-json.js';
import { SEMANTIC_CLASSES, SENSITIVITIES, TRUST_LEVELS, composeClassification } from './classification.js';
import type { SemanticClass, Sensitivity, Trust } from './classification.js';
import {
  KNOWN_POLICY_BUNDLE, POLICY_OPERATIONS, POLICY_TREATMENTS, decidePolicy, digestClassification,
  digestPolicyBundle,
} from './policy.js';
import type {
  PolicyBundle, PolicyDecision, PolicyOperation, ReleaseTreatment, Treatment,
} from './policy.js';
import type { Destination, Subject } from './interaction-envelope.js';

export const POLICY_GOVERNANCE_VERSION = 'hylja.policy-governance.v1' as const;

/**
 * Governance schema versions this build understands. Deliberately distinct from the accepted #4
 * policy schema identity: a governance `revision` counts configuration activations, while
 * `hylja.foundation` version `1` is the only decision identity. A configuration here can never
 * widen what `decidePolicy` accepts, because the governance module only ever hands #4 the bundle
 * it was given and compares against `KNOWN_POLICY_BUNDLE`.
 */
export const GOVERNANCE_CONFIG_VERSIONS = [1] as const;
export type GovernanceConfigVersion = (typeof GOVERNANCE_CONFIG_VERSIONS)[number];

/** The digest standing for "no configuration has ever been activated in this registry". */
export const GOVERNANCE_ZERO_DIGEST = '0'.repeat(64);

/* -------------------------------------------------------------------------------------- bounds */

export interface GovernanceLimits {
  /** Cap on the registry's exception list, enforced before any scan. */
  exceptions: number;
  /** Cap on simulation probes, enforced from the declared array length before any comparison. */
  probes: number;
  /** Cap on reported simulation findings; never above `probes`. */
  findings: number;
  /** Cap on a governance revision. */
  revision: number;
  /** Hard ceiling on one exception's lifetime, measured from `issuedAt`. */
  exceptionTtlMs: number;
  /** Hard ceiling on one approval's validity window. */
  approvalTtlMs: number;
  /** Cap on a bounded identifier token. */
  identifier: number;
  /** Cap on a destination reference. */
  reference: number;
  /** Cap on own keys inspected for any crossing object. */
  keys: number;
}
export const GOVERNANCE_LIMITS: Readonly<GovernanceLimits> = Object.freeze({
  exceptions: 256,
  probes: 256,
  findings: 256,
  revision: 1_000_000,
  exceptionTtlMs: 24 * 60 * 60 * 1000,
  approvalTtlMs: 60 * 60 * 1000,
  identifier: 128,
  reference: 2048,
  keys: 32,
});
/** Hard ceiling on one exception's lifetime, measured from its `issuedAt`. */
export const GOVERNANCE_MAX_EXCEPTION_TTL_MS = GOVERNANCE_LIMITS.exceptionTtlMs;
/** Hard ceiling on one approval's validity window. */
export const GOVERNANCE_MAX_APPROVAL_TTL_MS = GOVERNANCE_LIMITS.approvalTtlMs;
const LIMIT = GOVERNANCE_LIMITS;

/* --------------------------------------------------------------------------- fixed vocabulary */

/** Every code a refusal or an outcome can carry. Nothing caller-authored appears anywhere. */
export const GOVERNANCE_REASON_CODES = [
  'APPROVAL_EXPIRED', 'APPROVAL_MISMATCH', 'APPROVAL_MISSING', 'APPROVAL_NOT_YET_VALID',
  'COMPARED', 'NARROWED_DESTINATION_OR_TREATMENT', 'NEWLY_EXPOSED_SINK_OR_CLASS',
  'APPROVAL_TTL_EXCEEDED', 'AUDIT_EVIDENCE_INVALID', 'AUDIT_SCOPE_MISMATCH', 'AUDIT_UNAVAILABLE',
  'CONFIGURATION_ACTIVATED', 'CONFIGURATION_ALREADY_ACTIVE', 'CONFIGURATION_CONTENT_CHANGED',
  'CONFIGURATION_POLICY_VERSION_UNSUPPORTED', 'CONFIGURATION_STALE', 'CONFIGURATION_UNAVAILABLE',
  'CONFIGURATION_VERSION_UNSUPPORTED', 'EXCEPTION_ABOVE_TREATMENT_CEILING',
  'EXCEPTION_ALREADY_REGISTERED', 'EXCEPTION_APPLICABLE', 'EXCEPTION_BINDING_MISMATCH',
  'EXCEPTION_CAPACITY', 'EXCEPTION_CONFIG_SUPERSEDED', 'EXCEPTION_CONTENT_CHANGED',
  'EXCEPTION_EXPIRED', 'EXCEPTION_NOT_YET_ACTIVE', 'EXCEPTION_REGISTERED',
  'EXCEPTION_REVOCATION_RECORDED', 'EXCEPTION_REVOKED', 'EXCEPTION_SCOPE_MISMATCH',
  'EXCEPTION_TTL_EXCEEDED', 'EXCEPTION_WINDOW_INVALID', 'EXCEPTION_UNKNOWN',
  'INVALID_APPROVAL', 'INVALID_AUDIT_HOOK', 'INVALID_BINDING', 'INVALID_CLOCK',
  'INVALID_CONFIGURATION', 'INVALID_EXCEPTION', 'INVALID_PROBES', 'INVALID_REGISTRY',
  'INVALID_SCOPE', 'INVALID_SPEC', 'PROFILE_UNAVAILABLE', 'REGISTRY_UNAVAILABLE',
  'SIMULATION_COMPARED', 'SIMULATION_UNAVAILABLE',
] as const;
export type GovernanceReasonCode = (typeof GOVERNANCE_REASON_CODES)[number];

/** The administrative operations an approval and its audit record may name. */
export const GOVERNANCE_OPERATIONS = ['DEPLOY', 'UPDATE'] as const;
export type GovernanceOperation = (typeof GOVERNANCE_OPERATIONS)[number];

export const GOVERNANCE_PROMOTION_GATES = [
  'AUTHENTICATED_APPROVER_REQUIRED',
  'AUTHENTICATED_PROJECT_MEMBERSHIP_REQUIRED',
  'PRODUCTION_POLICY_REGISTRY_REQUIRED',
  'PRODUCTION_DISTRIBUTION_REQUIRED',
  'HUMAN_APPROVAL_REQUIRED',
  'DEPLOYED_ENFORCEMENT_REQUIRED',
] as const;
export type GovernancePromotionGate = (typeof GOVERNANCE_PROMOTION_GATES)[number];

/** Always-present refusal: the offending value, path and message never appear. */
export class PolicyGovernanceError extends Error {
  constructor(readonly code: GovernanceReasonCode) {
    super(`policy governance rejected (${code})`);
    this.name = 'PolicyGovernanceError';
  }
}

/* -------------------------------------------------------------------------------- types */

export interface GovernanceScope {
  readonly tenantId: string;
  readonly projectId: string;
}
export interface ExceptionDestination {
  readonly profileId: string;
  readonly sinkRef: string;
}
export interface ExceptionApprovalBinding {
  readonly subject: Subject;
  readonly semanticType: SemanticClass;
  readonly sensitivity: Sensitivity;
  readonly destination: ExceptionDestination;
  readonly operation: PolicyOperation;
}

/** A validated, frozen, single-revision policy configuration snapshot. */
export interface PolicyConfiguration {
  readonly version: 1;
  readonly configVersion: GovernanceConfigVersion;
  /** Governance activation counter. Not a policy version, and not comparable to one. */
  readonly revision: number;
  readonly createdAt: string;
  /** The administrative purpose this revision is activated for. Bounded opaque token. */
  readonly purpose: string;
  readonly policy: { readonly id: string; readonly version: string };
  /** Independently pinned SHA-256 over the exact #4 bundle content. */
  readonly bundleDigest: string;
  /** The bundle itself, handed unchanged to `decidePolicy`/`digestPolicyBundle`. */
  readonly bundle: PolicyBundle;
}

/** A validated, frozen, narrow, self-expiring exception. */
export interface PolicyException {
  readonly version: 1;
  readonly id: string;
  readonly scope: GovernanceScope;
  readonly subject: Subject;
  readonly purpose: string;
  readonly semanticType: SemanticClass;
  readonly sensitivity: Sensitivity;
  readonly destination: ExceptionDestination;
  readonly operation: PolicyOperation;
  readonly treatment: ReleaseTreatment;
  /** The configuration revision this exception was evaluated against. */
  readonly configRevision: number;
  readonly issuedAt: string;
  readonly expiresAt: string;
  /** Content commitment over the normalized fields above. Unkeyed: not a credential. */
  readonly digest: string;
}

export interface RegisteredException {
  readonly exception: PolicyException;
  revokedAt: string | null;
}

/**
 * A synthetic in-memory registry for exactly one tenant/project.
 *
 * Plain, inspectable and mutable by anyone with host access, exactly like #20's in-memory ledger:
 * this structure offers no tamper resistance of its own, which is why the configuration content
 * pin and the exception digest are re-verified on every read. It is not a production registry, a
 * distribution channel, a durable store or an administrative domain.
 */
export interface PolicyRegistry {
  version: 1;
  scope: GovernanceScope;
  config: PolicyConfiguration | null;
  exceptions: RegisteredException[];
  maxExceptions: number;
  /** An integrating sink clears this when it cannot commit; every change then refuses. */
  accepting: boolean;
}

/** The separately supplied #20 hook. This module never mints an approval or an audit record. */
export interface GovernanceAuditHook {
  version: 1;
  /** Must equal the registry scope, or nothing is recorded and nothing changes. */
  scope: GovernanceScope;
  /** An #20 `AuditLedger` for exactly this scope. */
  ledger: unknown;
  /** An #20 `AuditTrustedContext` for exactly this scope, carrying the two secret keys. */
  trusted: AuditTrustedContext;
  /** The integrating deployment's declared intelligence-bundle component versions. */
  components: readonly { readonly id: AuditBundleComponent; readonly version: string }[];
  correlationRef: string;
  occurredAt: string;
}

export interface GovernanceOutcome {
  readonly version: 1;
  readonly state: 'APPLIED' | 'DENIED';
  readonly reason: GovernanceReasonCode;
  readonly revision: number | null;
  readonly configDigest: string | null;
  readonly targetDigest: string | null;
  /** Always `NONE`. A synthetic registry write is not a production promotion. */
  readonly authority: 'NONE';
  readonly effect: 'SYNTHETIC_REGISTRY_ONLY' | 'IGNORED_NO_AUTHORITY';
  readonly promotion: Readonly<{ state: 'UNAVAILABLE'; gates: readonly GovernancePromotionGate[] }>;
  /**
   * What #20 reported, or `NOT_ATTEMPTED` when this refusal was decided before any audit append.
   * `finding` is `NOT_ATTEMPTED` in that case rather than one of #20's codes, so a refusal never
   * reports an audit outcome it did not observe.
   */
  readonly audit: Readonly<{ status: 'RECORDED' | 'RESTRICTED' | 'NOT_ATTEMPTED';
    finding: AuditAppendFinding | 'NOT_ATTEMPTED' }>;
}

export interface ExceptionEvaluation {
  readonly version: 1;
  readonly exceptionId: string;
  readonly state: 'APPLICABLE' | 'DENIED';
  readonly reason: GovernanceReasonCode;
  /** Always `NONE`. */
  readonly authority: 'NONE';
  /** Always `false`. An exception never selects, relaxes or grants a treatment. */
  readonly grantsTreatment: false;
  /** Always `true`. #4 `decidePolicy`/`decideReviewedPolicy` remain the only decision identity. */
  readonly requiresPolicyDecision: true;
  readonly expiresAt: string | null;
  /** The exception's content commitment. Unkeyed, and not a credential. */
  readonly digest: string | null;
}

export interface SimulationProbe {
  readonly version: 1;
  readonly profileId: string;
  readonly semanticType: SemanticClass;
  readonly sensitivity: Sensitivity;
  readonly operation: PolicyOperation;
  readonly sourceTrust: Trust;
  readonly probeId: string;
}
/**
 * `NEW_EXPOSURE` -- the candidate lets more out for this probe than the baseline did.
 * `SINK_REBOUND` -- the decision level did not rise, but the candidate points this profile at an
 *   exact sink reference the baseline did not, so the *destination itself* is newly exposed.
 * `NARROWED` -- the candidate is strictly more restrictive than the baseline for this probe, whether
 *   through the decision level, a raised cleartext ceiling or a destination the baseline did not
 *   declare. It is reported rather than folded into `UNCHANGED`, and it is never counted as an
 *   exposure.
 * `UNCHANGED` / `UNAVAILABLE` -- nothing moved, or neither configuration declares the probe's profile.
 */
export type SimulationFindingKind = 'NEW_EXPOSURE' | 'SINK_REBOUND' | 'NARROWED' | 'UNCHANGED' |
  'UNAVAILABLE';
export interface SimulationSide {
  readonly state: PolicyDecision['state'];
  readonly treatment: Treatment;
  readonly reason: string;
}
export interface SimulationFinding {
  readonly probeId: string;
  readonly kind: SimulationFindingKind;
  /** Closed reason for the finding. Never caller text. */
  readonly reason: GovernanceReasonCode;
  readonly profileId: string;
  /** The exact sink reference each bundle declares for this profile, or `null` when it declares none. */
  readonly baselineSink: string | null;
  readonly candidateSink: string | null;
  readonly semanticType: SemanticClass;
  readonly sensitivity: Sensitivity;
  readonly operation: PolicyOperation;
  readonly sourceTrust: Trust;
  readonly baseline: SimulationSide | null;
  readonly candidate: SimulationSide | null;
}
export interface SimulationReport {
  readonly version: 1;
  readonly status: 'COMPARED' | 'UNAVAILABLE';
  readonly finding: GovernanceReasonCode;
  readonly authority: 'NONE';
  /** Always `UNAVAILABLE`: a simulation reports, it never activates. */
  readonly activation: Readonly<{ state: 'UNAVAILABLE'; effect: 'IGNORED_NO_AUTHORITY' }>;
  readonly candidate: Readonly<{ revision: number; configurationDigest: string;
    bundleDigest: string }>;
  readonly baseline: Readonly<{ revision: number | null; configurationDigest: string | null }>;
  readonly probes: Readonly<{ evaluated: number; denied: number; unavailable: number }>;
  readonly newlyExposed: Readonly<{ classes: readonly SemanticClass[];
    /** Exact sink references the candidate newly exposes, sorted and de-duplicated. */
    sinks: readonly string[];
    /** The profile ids those sinks are reached through, for attribution. */
    profiles: readonly string[];
    operations: readonly PolicyOperation[]; count: number }>;
  readonly findings: readonly SimulationFinding[];
  readonly promotion: Readonly<{ state: 'UNAVAILABLE'; gates: readonly GovernancePromotionGate[] }>;
}

/* ------------------------------------------------------------ strict structural readers */

type Fields = Record<string, unknown>;
function fail(code: GovernanceReasonCode): never { throw new PolicyGovernanceError(code); }

/**
 * One bounded own-key snapshot, own **data** descriptors only, closed key set, no getters, no
 * inherited properties and no second enumeration, so a time-varying Proxy can neither grow the
 * inspected work set nor smuggle a value in.
 */
function fields(value: unknown, required: readonly string[],
  optional: readonly string[] = []): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('INVALID_SPEC');
  const keys = Reflect.ownKeys(value);
  if (keys.length > LIMIT.keys || keys.some((key) => typeof key !== 'string')) fail('INVALID_SPEC');
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    if (!required.includes(key) && !optional.includes(key)) fail('INVALID_SPEC');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('INVALID_SPEC');
    result[key] = descriptor.value;
  }
  for (const name of required) if (!Object.hasOwn(result, name)) fail('INVALID_SPEC');
  return result;
}

/** Declared length read first and capped first, so an over-long array is refused in O(1). */
function items<T>(value: unknown, convert: (part: unknown, index: number) => T, limit: number): T[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail('INVALID_SPEC');
  const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (!Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > limit) {
    fail('INVALID_SPEC');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== (length as number) + 1 || keys.some((key) => typeof key !== 'string') ||
    !keys.includes('length')) fail('INVALID_SPEC');
  const result: T[] = [];
  for (let index = 0; index < (length as number); index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('INVALID_SPEC');
    result.push(convert(descriptor.value, index));
  }
  return result;
}
function text(value: unknown, limit: number): string {
  if (typeof value !== 'string' || !value.length || value.length > limit ||
    value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) fail('INVALID_SPEC');
  return value;
}
/**
 * A bounded opaque identity/version/scope token. No `@`, `/`, `:`, whitespace or free text, so an
 * email, a URL, a host, a path or a pattern (`*`) cannot be planted in a field read verbatim. This
 * bounds the SHAPE only; the trusted integration must still mint a privacy-safe value.
 */
function identifier(value: unknown): string {
  const result = text(value, LIMIT.identifier);
  if (!/^[A-Za-z0-9][A-Za-z0-9._=-]*$/u.test(result)) fail('INVALID_SPEC');
  return result;
}
/**
 * A destination reference: one opaque token or absolute URI, never prose, whitespace or a pattern.
 * The exact sink ref is what a #4 profile binds, so it is compared, never interpreted.
 */
function sinkRef(value: unknown): string {
  const result = text(value, LIMIT.reference);
  if (/\s/u.test(result) || !/[A-Za-z0-9]/u.test(result)) fail('INVALID_SPEC');
  return result;
}
function member<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) fail('INVALID_SPEC');
  return value as T;
}
function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum) {
    fail('INVALID_SPEC');
  }
  return value as number;
}
function hexDigest(value: unknown): string {
  const result = text(value, 64);
  if (!/^[a-f0-9]{64}$/u.test(result)) fail('INVALID_SPEC');
  return result;
}
interface Instant { readonly stamp: string; readonly ms: number }
/**
 * A UTC millisecond stamp with millisecond precision. The exact round trip is required, so an
 * imaginary date such as `2026-02-31T00:00:00.000Z` (which `Date.parse` happily rolls forward) is
 * a fixed refusal rather than a silently different instant.
 */
function instant(value: unknown): Instant {
  const stamp = text(value, 24);
  const ms = Date.parse(stamp);
  if (!Number.isFinite(ms) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(stamp) ||
    new Date(ms).toISOString() !== stamp) fail('INVALID_CLOCK');
  return { stamp, ms };
}
function scope(value: unknown): GovernanceScope {
  const v = fields(value, ['tenantId', 'projectId']);
  return Object.freeze({ tenantId: identifier(v.tenantId), projectId: identifier(v.projectId) });
}
function subjectOf(value: unknown): Subject {
  const v = fields(value, ['principalId'], ['workloadId']);
  const principalId = identifier(v.principalId);
  return Object.freeze(Object.hasOwn(v, 'workloadId')
    ? { principalId, workloadId: identifier(v.workloadId) }
    : { principalId });
}
function destinationOf(value: unknown): ExceptionDestination {
  const v = fields(value, ['profileId', 'sinkRef']);
  return Object.freeze({ profileId: identifier(v.profileId), sinkRef: sinkRef(v.sinkRef) });
}
function sameScope(left: GovernanceScope, right: GovernanceScope): boolean {
  return left.tenantId === right.tenantId && left.projectId === right.projectId;
}
function sameSubject(left: Subject, right: Subject): boolean {
  return left.principalId === right.principalId && left.workloadId === right.workloadId;
}
function sameDestination(left: ExceptionDestination, right: ExceptionDestination): boolean {
  return left.profileId === right.profileId && left.sinkRef === right.sinkRef;
}

/* -------------------------------------------------------------------------- issued objects */

const issuedConfigurations = new WeakSet<object>();
const issuedExceptions = new WeakSet<object>();
const issuedRegistries = new WeakSet<object>();

function isIssued<T extends object>(set: WeakSet<object>, value: unknown): value is T {
  return typeof value === 'object' && value !== null && set.has(value);
}

/* ------------------------------------------------------------------- configuration reading */

const CONFIG_REQUIRED = ['version', 'configVersion', 'revision', 'createdAt', 'purpose', 'policy',
  'bundleDigest'] as const;

interface ConfigurationView {
  readonly version: 1;
  readonly configVersion: number;
  readonly revision: number;
  readonly createdAt: string;
  readonly purpose: string;
  readonly policy: { readonly id: string; readonly version: string };
  readonly bundleDigest: string;
}
function configurationView(value: unknown): ConfigurationView {
  const v = fields(value, [...CONFIG_REQUIRED], ['bundle']);
  if (v.version !== 1) fail('INVALID_CONFIGURATION');
  const policy = fields(v.policy, ['id', 'version']);
  return Object.freeze({
    version: 1 as const,
    configVersion: v.configVersion as number,
    revision: integer(v.revision, LIMIT.revision),
    createdAt: instant(v.createdAt).stamp,
    purpose: identifier(v.purpose),
    policy: Object.freeze({ id: text(policy.id, LIMIT.identifier),
      version: text(policy.version, LIMIT.identifier) }),
    bundleDigest: hexDigest(v.bundleDigest),
  });
}

/**
 * Content commitment over a configuration revision.
 *
 * An unkeyed replay commitment, **not** a credential, a signature or proof of approval. Only a
 * digest pinned independently by the trusted control plane is authoritative, and this module never
 * mints one: the value it compares against always arrives inside a separately supplied approval.
 */
export function digestPolicyConfiguration(value: unknown): string {
  const view = configurationView(value);
  return sha256Hex(canonicalJson({
    version: view.version, configVersion: view.configVersion, revision: view.revision,
    createdAt: view.createdAt, purpose: view.purpose, policy: view.policy,
    bundleDigest: view.bundleDigest,
  }));
}

/**
 * Validate and freeze one configuration snapshot.
 *
 * The accepted #4 identity is preserved exactly: `policy.id`/`policy.version` must equal
 * `KNOWN_POLICY_BUNDLE`, and an unknown pair is refused with a typed
 * `CONFIGURATION_POLICY_VERSION_UNSUPPORTED` rather than extending `decidePolicy`'s wire
 * allowlist. The governance schema version is checked separately, so a newer governance
 * configuration is refused with `CONFIGURATION_VERSION_UNSUPPORTED` instead of being read under
 * today's rules. `pinnedDigest`, when the trusted control plane supplies one, must equal the
 * recomputed **configuration** commitment (`digestPolicyConfiguration`, which binds the revision,
 * creation instant, administrative purpose and the bundle content pin): a substituted bundle or a
 * substituted revision is refused here, before any revision is compared and before any exception
 * or approval is evaluated.
 */
export function createPolicyConfiguration(spec: unknown): PolicyConfiguration {
  const v = fields(spec, ['version', 'configVersion', 'revision', 'createdAt', 'purpose', 'bundle'],
    ['pinnedDigest']);
  if (v.version !== 1) fail('INVALID_SPEC');
  const configVersion = v.configVersion;
  if (!GOVERNANCE_CONFIG_VERSIONS.includes(configVersion as GovernanceConfigVersion)) {
    fail('CONFIGURATION_VERSION_UNSUPPORTED');
  }
  const identity = fields(v.bundle, ['id', 'version', 'profiles', 'rules']);
  if (identity.id !== KNOWN_POLICY_BUNDLE.id || identity.version !== KNOWN_POLICY_BUNDLE.version) {
    fail('CONFIGURATION_POLICY_VERSION_UNSUPPORTED');
  }
  const revision = integer(v.revision, LIMIT.revision);
  const createdAt = instant(v.createdAt).stamp;
  const purpose = identifier(v.purpose);
  let bundleDigest: string;
  try { bundleDigest = digestPolicyBundle(v.bundle); } catch { fail('CONFIGURATION_CONTENT_CHANGED'); }
  const built = Object.freeze({
    version: 1 as const,
    configVersion: 1 as const,
    revision,
    createdAt,
    purpose,
    policy: Object.freeze({ id: KNOWN_POLICY_BUNDLE.id, version: KNOWN_POLICY_BUNDLE.version }),
    bundleDigest,
  });
  if (Object.hasOwn(v, 'pinnedDigest') &&
    hexDigest(v.pinnedDigest) !== digestPolicyConfiguration(built)) {
    fail('CONFIGURATION_CONTENT_CHANGED');
  }
  const configuration: PolicyConfiguration = Object.freeze({ ...built,
    bundle: v.bundle as PolicyBundle });
  issuedConfigurations.add(configuration);
  return configuration;
}

/**
 * Re-derive the pinned content commitment of an issued configuration's bundle.
 *
 * The snapshot holds the caller's bundle object, so the pin is re-verified from content before
 * every read. A bundle mutated after issuance or after an approval is therefore
 * `CONFIGURATION_CONTENT_CHANGED` rather than a silently evaluated substitute.
 */
function bundleRepinned(configuration: PolicyConfiguration): boolean {
  try { return digestPolicyBundle(configuration.bundle) === configuration.bundleDigest; }
  catch { return false; }
}

/* ---------------------------------------------------------------------- exception reading */

const EXCEPTION_REQUIRED = ['version', 'id', 'scope', 'subject', 'purpose', 'semanticType',
  'sensitivity', 'destination', 'operation', 'treatment', 'configRevision', 'issuedAt',
  'expiresAt'] as const;
const RELEASE_TREATMENTS: readonly ReleaseTreatment[] =
  POLICY_TREATMENTS.filter((item): item is ReleaseTreatment =>
    item !== 'BLOCK' && item !== 'REQUIRE_REVIEW');

interface ExceptionView {
  readonly version: 1;
  readonly id: string;
  readonly scope: GovernanceScope;
  readonly subject: Subject;
  readonly purpose: string;
  readonly semanticType: SemanticClass;
  readonly sensitivity: Sensitivity;
  readonly destination: ExceptionDestination;
  readonly operation: PolicyOperation;
  readonly treatment: ReleaseTreatment;
  readonly configRevision: number;
  readonly issuedAt: string;
  readonly expiresAt: string;
}
function exceptionView(value: unknown): ExceptionView {
  const v = fields(value, [...EXCEPTION_REQUIRED], ['digest']);
  if (v.version !== 1) fail('INVALID_EXCEPTION');
  const issuedAt = instant(v.issuedAt);
  const expiresAt = instant(v.expiresAt);
  if (expiresAt.ms <= issuedAt.ms) fail('EXCEPTION_WINDOW_INVALID');
  if (expiresAt.ms - issuedAt.ms > LIMIT.exceptionTtlMs) fail('EXCEPTION_TTL_EXCEEDED');
  const semanticType = member(v.semanticType, SEMANTIC_CLASSES);
  const sensitivity = member(v.sensitivity, SENSITIVITIES);
  const treatment = member(v.treatment, RELEASE_TREATMENTS);
  // An exception may only ever narrow inside the irreversible ceiling. This is applied for every
  // exposure, which is strictly stricter than #4's exposure-conditional SECRET/credential rule and
  // therefore never relaxes it; the #4 seam independently refuses the same selections again.
  if ((sensitivity === 'SECRET' || semanticType === 'CREDENTIAL_OR_SECRET') &&
    treatment !== 'MASK' && treatment !== 'REMOVE') fail('EXCEPTION_ABOVE_TREATMENT_CEILING');
  return Object.freeze({
    version: 1 as const,
    id: identifier(v.id),
    scope: scope(v.scope),
    subject: subjectOf(v.subject),
    purpose: identifier(v.purpose),
    semanticType,
    sensitivity,
    destination: destinationOf(v.destination),
    operation: member(v.operation, POLICY_OPERATIONS),
    treatment,
    configRevision: integer(v.configRevision, LIMIT.revision),
    issuedAt: issuedAt.stamp,
    expiresAt: expiresAt.stamp,
  });
}

/** Content commitment over the normalized exception. Unkeyed: not a credential. */
export function digestPolicyException(value: unknown): string {
  const view = exceptionView(value);
  return sha256Hex(canonicalJson({
    version: view.version, id: view.id, scope: view.scope, subject: view.subject,
    purpose: view.purpose, semanticType: view.semanticType, sensitivity: view.sensitivity,
    destination: view.destination, operation: view.operation, treatment: view.treatment,
    configRevision: view.configRevision, issuedAt: view.issuedAt, expiresAt: view.expiresAt,
  }));
}

/**
 * Validate and freeze one narrow exception.
 *
 * Every dimension is single-valued and required: tenant, project, subject, purpose, semantic
 * class, sensitivity, exact destination (profile plus exact sink reference), operation and the
 * configuration revision it was evaluated against. There is no wildcard, no default and no
 * global form, and the lifetime is capped at `GOVERNANCE_LIMITS.exceptionTtlMs` measured from
 * `issuedAt`, so a "temporary" exception cannot be minted as a permanent one.
 */
export function createPolicyException(spec: unknown): PolicyException {
  const view = exceptionView(spec);
  const exception: PolicyException = Object.freeze({
    ...view,
    digest: digestPolicyException(view),
  });
  issuedExceptions.add(exception);
  return exception;
}

/* --------------------------------------------------------------------------- the registry */

/**
 * Create the synthetic in-memory registry for one tenant/project. Not a production registry, a
 * distribution channel, a durable store, an administrative domain or a source of authority.
 */
export function createPolicyRegistry(scopeValue: unknown, options?: unknown): PolicyRegistry {
  let target: GovernanceScope;
  try { target = scope(scopeValue); } catch { fail('INVALID_SCOPE'); }
  let maxExceptions = LIMIT.exceptions;
  if (options !== undefined) {
    const o = fields(options, ['maxExceptions']);
    maxExceptions = integer(o.maxExceptions, LIMIT.exceptions);
  }
  const registry: PolicyRegistry = {
    version: 1,
    scope: target,
    config: null,
    exceptions: [],
    maxExceptions,
    accepting: true,
  };
  issuedRegistries.add(registry);
  return registry;
}

interface RegistryView {
  readonly registry: PolicyRegistry;
  readonly scope: GovernanceScope;
}
function registryView(value: unknown): RegistryView {
  if (!isIssued<PolicyRegistry>(issuedRegistries, value)) fail('INVALID_REGISTRY');
  return { registry: value, scope: value.scope };
}

/** Re-derive the active configuration's **configuration** commitment, or the zero digest. */
function activeDigest(registry: PolicyRegistry): string | null {
  const configuration = registry.config;
  if (configuration === null) return null;
  if (!isIssued<PolicyConfiguration>(issuedConfigurations, configuration) ||
    !bundleRepinned(configuration)) return null;
  return digestPolicyConfiguration(configuration);
}
function activeConfigurationDigest(registry: PolicyRegistry): string {
  return activeDigest(registry) ?? GOVERNANCE_ZERO_DIGEST;
}

/* -------------------------------------------------------------------------- the audit hook */

interface AuditHookView {
  /**
   * True only when the hook's **declared** scope, the scope of the **ledger it carries** and the
   * scope of its **trusted context** all name exactly the registry's tenant and project. A caller
   * cannot satisfy this by asserting a scope on the hook: the ledger's own field is what #20 stamps
   * onto the entry and the receipt.
   */
  readonly scopesAgree: boolean;
  readonly scope: GovernanceScope;
  readonly ledger: unknown;
  readonly trusted: AuditTrustedContext;
  readonly components: readonly { readonly id: AuditBundleComponent; readonly version: string }[];
  readonly correlationRef: string;
  readonly occurredAt: string;
}

/**
 * #20's own stream-scope shape, read through this module's existing bounded descriptor reader.
 *
 * `projectId` is optional in `AuditScope`, so the reader keeps it optional and the comparison is
 * exact: a stream that carries no project is **not** congruent with a registry scoped to one. This
 * reuses #20's exported `AuditLedger.scope` value and nothing else -- no stream reader, no entry
 * validation and no ledger core is reproduced here.
 */
interface ReadAuditScope { readonly tenantId: string; readonly projectId?: string }
function readAuditScope(value: unknown): ReadAuditScope {
  const v = fields(value, ['tenantId'], ['projectId']);
  const tenantId = identifier(v.tenantId);
  return Object.hasOwn(v, 'projectId') ? { tenantId, projectId: identifier(v.projectId) }
    : { tenantId };
}
function sameAuditScope(read: ReadAuditScope, expected: GovernanceScope): boolean {
  return read.tenantId === expected.tenantId && read.projectId === expected.projectId;
}
/** #20's exported `AuditLedger` shape, read once and only for its scope. */
function readLedgerScope(value: unknown): ReadAuditScope {
  // Any shape failure is this hook's refusal code: the append is never attempted on a value that is
  // not an #20 ledger, so there is nothing for #20 to reject later.
  try {
    const v = fields(value, ['version', 'scope', 'entries', 'maxEntries', 'accepting']);
    if (v.version !== 1) fail('INVALID_AUDIT_HOOK');
    return readAuditScope(v.scope);
  } catch { fail('INVALID_AUDIT_HOOK'); }
}
/**
 * #20's exported `AuditTrustedContext` keys, read only far enough to see its scope. A trusted
 * context that cannot be read this far is left to #20's own validation, which refuses it; only an
 * unreadable **scope** is a pre-append refusal here.
 */
function readTrustedScope(value: unknown): ReadAuditScope | null {
  try {
    const v = fields(value, ['version', 'scope', 'actor', 'integrationId', 'actorBinding',
      'pseudonymKey', 'chainKey']);
    if (v.version !== 1) return null;
    return readAuditScope(v.scope);
  } catch { return null; }
}

function auditHookView(value: unknown, expected: GovernanceScope): AuditHookView {
  const v = fields(value, ['version', 'scope', 'ledger', 'trusted', 'components', 'correlationRef',
    'occurredAt']);
  if (v.version !== 1) fail('INVALID_AUDIT_HOOK');
  const components = items(v.components, (part) => {
    const c = fields(part, ['id', 'version']);
    return Object.freeze({ id: text(c.id, LIMIT.identifier) as AuditBundleComponent,
      version: identifier(c.version) });
  }, 12);
  if (components.length === 0) fail('INVALID_AUDIT_HOOK');
  const declared = scope(v.scope);
  // The ledger's own scope is read here, **before** any append, so a foreign stream is refused
  // rather than committed into and noticed afterwards.
  const ledgerScope = readLedgerScope(v.ledger);
  const trustedScope = readTrustedScope(v.trusted);
  const scopesAgree = sameAuditScope(declared, expected) &&
    sameAuditScope(ledgerScope, expected) &&
    (trustedScope === null || sameAuditScope(trustedScope, expected));
  return { scopesAgree, scope: declared, ledger: v.ledger, trusted: v.trusted as AuditTrustedContext,
    components: Object.freeze(components), correlationRef: text(v.correlationRef, 512),
    occurredAt: instant(v.occurredAt).stamp };
}

/**
 * Record one administrative operation through #20 and report the audit outcome.
 *
 * The draft's pinned policy identity comes from the configuration this module already validated,
 * never from the caller, so a draft cannot assert a bundle digest. The record carries no free text,
 * no purpose, no exception body and no original: #20 pseudonymizes the correlation reference and
 * keeps the chain itself.
 */
function recordAudit(hook: AuditHookView, configuration: PolicyConfiguration,
  operation: GovernanceOperation, outcome: 'APPLIED' | 'DENIED'): AuditAppendResult {
  return appendAuditEvent(hook.ledger, {
    version: 1,
    kind: 'POLICY_OPERATION',
    operation,
    outcome,
    reason: outcome === 'APPLIED' ? 'ADMIN_APPLIED' : 'ADMIN_DENIED',
    occurredAt: hook.occurredAt,
    bundle: { policy: { id: configuration.policy.id, version: configuration.policy.version,
      digest: configuration.bundleDigest }, components: hook.components },
    correlationRef: hook.correlationRef,
  }, hook.trusted);
}

const PROMOTION: Readonly<{ state: 'UNAVAILABLE'; gates: readonly GovernancePromotionGate[] }> =
  Object.freeze({ state: 'UNAVAILABLE' as const, gates: GOVERNANCE_PROMOTION_GATES });

/**
 * The audit precondition for a registry write: the append must be committed **and** land in this
 * registry's own scope.
 *
 * #20 derives an entry's scope from the ledger it was appended to and stamps it on the receipt, so
 * the receipt — not the hook's self-declared `scope` field — is the fact about where the evidence
 * actually went. A hook that declares tenant A while carrying tenant B's ledger and tenant B's
 * trusted context passes the declared-scope comparison and would otherwise commit tenant A's
 * `ADMIN_APPLIED` into tenant B's chain; comparing the committed scope here is what closes that.
 *
 * Honest residual, unchanged by this check: the foreign-stream record itself is already committed
 * when the mismatch is found. What is guaranteed is that **no activation, registration or
 * revocation follows**, so a mis-scoped audit sink can cost an orphan `ADMIN_APPLIED` record and
 * never a promotion. Detecting the misconfiguration before the append would mean re-reading the
 * ledger's own scope here, which is #20's reader and not this module's to fork.
 */
function auditGateAllows(appended: AuditAppendResult, expected: GovernanceScope):
{ permitted: true } | { permitted: false; reason: 'AUDIT_UNAVAILABLE' | 'AUDIT_EVIDENCE_INVALID'
  | 'AUDIT_SCOPE_MISMATCH'; summary: AuditSummary } {
  const gate = gateHighRiskEffect(appended);
  const summary: AuditSummary = { status: appended.status, finding: appended.finding };
  if (!gate.permitted) {
    return { permitted: false,
      reason: gate.finding === 'EVIDENCE_UNAVAILABLE' ? 'AUDIT_UNAVAILABLE' : 'AUDIT_EVIDENCE_INVALID',
      summary };
  }
  const committed = appended.receipt?.scope;
  if (committed === undefined || !sameCommittedScope(committed, expected)) {
    return { permitted: false, reason: 'AUDIT_SCOPE_MISMATCH', summary };
  }
  return { permitted: true };
}

/**
 * Exact scope congruence against #20's receipt scope, whose `projectId` is optional there. A
 * stream that carries no project is therefore **not** congruent with a registry scoped to one, and
 * an absent receipt is not congruent with anything.
 */
function sameCommittedScope(receiptScope: { tenantId: string; projectId?: string },
  expected: GovernanceScope): boolean {
  return receiptScope.tenantId === expected.tenantId &&
    receiptScope.projectId === expected.projectId;
}

interface AuditSummary {
  status: 'RECORDED' | 'RESTRICTED' | 'NOT_ATTEMPTED';
  finding: AuditAppendFinding | 'NOT_ATTEMPTED';
}
function deny(reason: GovernanceReasonCode, extra: {
  revision?: number | null; configDigest?: string | null; targetDigest?: string | null;
  audit?: AuditSummary;
} = {}): GovernanceOutcome {
  return Object.freeze({
    version: 1 as const,
    state: 'DENIED' as const,
    reason,
    revision: extra.revision ?? null,
    configDigest: extra.configDigest ?? null,
    targetDigest: extra.targetDigest ?? null,
    authority: 'NONE' as const,
    effect: 'IGNORED_NO_AUTHORITY' as const,
    promotion: PROMOTION,
    audit: extra.audit ?? { status: 'NOT_ATTEMPTED' as const, finding: 'NOT_ATTEMPTED' as const },
  });
}

/**
 * Append a best-effort `ADMIN_DENIED` record and return the denial. A denial never depends on the
 * record succeeding: an audit outage cannot turn a refusal into a partial promotion, and it cannot
 * turn a denial into anything else either.
 */
function denyAudited(hook: AuditHookView, configuration: PolicyConfiguration, reason: GovernanceReasonCode,
  extra: { revision?: number | null; configDigest?: string | null; targetDigest?: string | null } = {}):
GovernanceOutcome {
  const result = recordAudit(hook, configuration, 'UPDATE', 'DENIED');
  return deny(reason, { ...extra, audit: { status: result.status, finding: result.finding } });
}

/* -------------------------------------------------------------------------- the approval */

/** Turn a reader failure into its fixed code: untrusted input denies, it never throws. */
function denialOf(error: unknown): GovernanceReasonCode {
  return error instanceof PolicyGovernanceError ? error.code : 'INVALID_SPEC';
}

interface ApprovalView {
  readonly version: unknown;
  readonly authority: unknown;
  readonly approvalRef: string;
  readonly scope: GovernanceScope;
  readonly approver: Subject;
  readonly purpose: string;
  readonly operation: unknown;
  readonly revision: number;
  readonly configDigest: string;
  readonly targetDigest: string;
  readonly binding: unknown;
  readonly validFrom: Instant;
  readonly validUntil: Instant;
}

/**
 * Read the approval envelope. `version`, `authority`, `operation` and `binding` are deliberately
 * left opaque here: a malformed envelope is a caller error and is thrown, while a well-formed
 * envelope carrying a wrong, unsupported or unbound claim is a governance decision that denies.
 */
/**
 * Read the approval envelope.
 *
 * Every failure anywhere in it -- a missing or unknown key, a hostile getter, an oversize container,
 * a planted free-text purpose, a malformed digest or an inverted window -- is the single fixed code
 * `INVALID_APPROVAL`. Nothing is echoed, defaulted, or partially trusted. Value-level claims that
 * are structurally fine (an unsupported authority, the wrong operation, a missing binding) are left
 * to `approvalValid`, which turns them into their own governance decision code.
 */
function approvalView(value: unknown): ApprovalView {
  try {
    const v = fields(value, ['version', 'authority', 'approvalRef', 'scope', 'approver', 'purpose',
      'operation', 'revision', 'configDigest', 'targetDigest', 'validFrom', 'validUntil'],
      ['binding']);
    const validFrom = instant(v.validFrom);
    const validUntil = instant(v.validUntil);
    if (validUntil.ms <= validFrom.ms) fail('INVALID_APPROVAL');
    return Object.freeze({
      version: v.version,
      authority: v.authority,
      approvalRef: identifier(v.approvalRef),
      scope: scope(v.scope),
      approver: subjectOf(v.approver),
      purpose: identifier(v.purpose),
      operation: v.operation,
      revision: integer(v.revision, LIMIT.revision),
      configDigest: hexDigest(v.configDigest),
      targetDigest: hexDigest(v.targetDigest),
      binding: v.binding,
      validFrom,
      validUntil,
    });
  } catch { fail('INVALID_APPROVAL'); }
}

interface ApprovalCheck { readonly binding: ExceptionApprovalBinding | null }

/**
 * Verify the approval's membership claims and its window.
 *
 * `configDigest` binds the approval to the **currently active** configuration, or the zero digest
 * when the registry has never activated one: an approval minted against a configuration that has
 * since been replaced cannot activate or register anything. `targetDigest` binds it to the exact
 * object, so an approval for one revision, exception or destination cannot be replayed onto
 * another.
 */
function approvalValid(approval: ApprovalView, scopeValue: GovernanceScope, purpose: string,
  operation: GovernanceOperation, revision: number, configDigest: string, targetDigest: string,
  now: Instant, bindingRequired: boolean): ApprovalCheck | GovernanceReasonCode {
  if (approval.version !== 1 || approval.authority !== 'TRUSTED_INTEGRATION') return 'INVALID_APPROVAL';
  if (approval.operation !== operation) return 'APPROVAL_MISMATCH';
  if (approval.validUntil.ms - approval.validFrom.ms > LIMIT.approvalTtlMs) return 'APPROVAL_TTL_EXCEEDED';
  if (now.ms < approval.validFrom.ms) return 'APPROVAL_NOT_YET_VALID';
  if (now.ms >= approval.validUntil.ms) return 'APPROVAL_EXPIRED';
  if (!sameScope(approval.scope, scopeValue) || approval.purpose !== purpose ||
    approval.revision !== revision || approval.configDigest !== configDigest ||
    approval.targetDigest !== targetDigest) return 'APPROVAL_MISMATCH';
  if (!bindingRequired) return Object.hasOwn(approval, 'binding') && approval.binding !== undefined
    ? 'INVALID_APPROVAL' : { binding: null };
  if (approval.binding === undefined) return 'INVALID_APPROVAL';
  const b = fields(approval.binding, ['subject', 'semanticType', 'sensitivity', 'destination',
    'operation']);
  const binding = Object.freeze({
    subject: subjectOf(b.subject),
    semanticType: member(b.semanticType, SEMANTIC_CLASSES),
    sensitivity: member(b.sensitivity, SENSITIVITIES),
    destination: destinationOf(b.destination),
    operation: member(b.operation, POLICY_OPERATIONS),
  });
  return { binding };
}

/** The request tuple an exception is evaluated against, read strictly. */
interface BindingView {
  readonly scope: GovernanceScope;
  readonly subject: Subject;
  readonly purpose: string;
  readonly semanticType: SemanticClass;
  readonly sensitivity: Sensitivity;
  readonly destination: ExceptionDestination;
  readonly operation: PolicyOperation;
}
/** The exception tuple an approval binding must name, read strictly. */
function bindingView(value: unknown): BindingView {
  const v = fields(value, ['scope', 'subject', 'purpose', 'semanticType', 'sensitivity',
    'destination', 'operation']);
  return Object.freeze({
    scope: scope(v.scope),
    subject: subjectOf(v.subject),
    purpose: identifier(v.purpose),
    semanticType: member(v.semanticType, SEMANTIC_CLASSES),
    sensitivity: member(v.sensitivity, SENSITIVITIES),
    destination: destinationOf(v.destination),
    operation: member(v.operation, POLICY_OPERATIONS),
  });
}

/* --------------------------------------------------------------- configuration activation */

/**
 * Activate a configuration revision in the synthetic registry.
 *
 * Order matters and is part of the contract: identity and content re-verification, then staleness,
 * then approval, then audit, and only then the registry write. So an altered bundle, a stale or
 * replayed revision, a missing/forged/substituted/expired approval and an unavailable audit each
 * leave the registry **exactly** as it was; there is no partial promotion. A recorded
 * `ADMIN_APPLIED` event is therefore always followed by the write it describes.
 */
export function activatePolicyConfiguration(registryValue: unknown, configurationValue: unknown,
  approvalValue: unknown, auditValue: unknown, nowValue: unknown): GovernanceOutcome {
  let view: RegistryView;
  try { view = registryView(registryValue); } catch (error) { return deny(denialOf(error)); }
  const registry = view.registry;
  if (!isIssued<PolicyConfiguration>(issuedConfigurations, configurationValue)) {
    fail('INVALID_CONFIGURATION');
  }
  const configuration = configurationValue;
  const targetDigest = digestPolicyConfiguration(configuration);
  const active = registry.config;
  const revision = configuration.revision;
  const common = { revision, configDigest: configuration.bundleDigest, targetDigest };

  let now: Instant;
  let hook: AuditHookView;
  let approval: ApprovalView | undefined;
  try {
    now = instant(nowValue);
    hook = auditHookView(auditValue, view.scope);
    if (approvalValue !== undefined && approvalValue !== null) approval = approvalView(approvalValue);
  } catch (error) { return deny(denialOf(error), common); }

  if (!registry.accepting) return deny('REGISTRY_UNAVAILABLE', common);
  if (!hook.scopesAgree) return deny('AUDIT_SCOPE_MISMATCH', common);
  // Content first: a bundle altered after issuance or after approval never reaches a comparison.
  if (!bundleRepinned(configuration)) return denyAudited(hook, configuration,
    'CONFIGURATION_CONTENT_CHANGED', common);
  if (active !== null) {
    if (!isIssued<PolicyConfiguration>(issuedConfigurations, active) || !bundleRepinned(active)) {
      return denyAudited(hook, configuration, 'CONFIGURATION_CONTENT_CHANGED', common);
    }
    if (configuration.bundleDigest === active.bundleDigest && revision === active.revision) {
      return denyAudited(hook, configuration, 'CONFIGURATION_ALREADY_ACTIVE', common);
    }
    if (revision <= active.revision) return denyAudited(hook, configuration, 'CONFIGURATION_STALE',
      common);
  }
  if (approval === undefined) return denyAudited(hook, configuration, 'APPROVAL_MISSING', common);
  const verdict = approvalValid(approval, view.scope, configuration.purpose, 'DEPLOY', revision,
    activeConfigurationDigest(registry), targetDigest, now, false);
  if (typeof verdict === 'string') return denyAudited(hook, configuration, verdict, common);
  const appended = recordAudit(hook, configuration, 'DEPLOY', 'APPLIED');
  const gate = auditGateAllows(appended, view.scope);
  if (!gate.permitted) return deny(gate.reason, { ...common, audit: gate.summary });
  registry.config = configuration;
  return Object.freeze({
    version: 1 as const,
    state: 'APPLIED' as const,
    reason: 'CONFIGURATION_ACTIVATED' as const,
    revision,
    configDigest: configuration.bundleDigest,
    targetDigest,
    authority: 'NONE' as const,
    effect: 'SYNTHETIC_REGISTRY_ONLY' as const,
    promotion: PROMOTION,
    audit: { status: appended.status, finding: appended.finding },
  });
}

/* ------------------------------------------------------------ exception registration */

/**
 * Register a narrow exception in the synthetic registry.
 *
 * The exception is bound to one configuration revision, so activating a newer revision
 * supersedes it automatically (see `evaluatePolicyException`) rather than leaving it live against a
 * configuration nobody approved it for. Registration is refused for an exception already present
 * under the same identifier, including one that was revoked: a revocation cannot be undone by
 * re-registering.
 */
export function registerPolicyException(registryValue: unknown, exceptionValue: unknown,
  approvalValue: unknown, auditValue: unknown, nowValue: unknown): GovernanceOutcome {
  let view: RegistryView;
  try { view = registryView(registryValue); } catch (error) { return deny(denialOf(error)); }
  const registry = view.registry;
  if (!isIssued<PolicyException>(issuedExceptions, exceptionValue)) fail('INVALID_EXCEPTION');
  const exception = exceptionValue;
  const active = registry.config;
  const configuration = active;
  const targetDigest = exception.digest;
  const common = { revision: exception.configRevision, configDigest: configuration?.bundleDigest ?? null,
    targetDigest };

  let now: Instant;
  let hook: AuditHookView;
  let approval: ApprovalView | undefined;
  try {
    now = instant(nowValue);
    hook = auditHookView(auditValue, view.scope);
    if (approvalValue !== undefined && approvalValue !== null) approval = approvalView(approvalValue);
  } catch (error) { return deny(denialOf(error), common); }

  if (!registry.accepting) return deny('REGISTRY_UNAVAILABLE', common);
  if (!hook.scopesAgree) return deny('AUDIT_SCOPE_MISMATCH', common);
  if (configuration === undefined || configuration === null) return deny('CONFIGURATION_UNAVAILABLE',
    common);
  if (!isIssued<PolicyConfiguration>(issuedConfigurations, configuration) ||
    !bundleRepinned(configuration)) return denyAudited(hook, configuration,
    'CONFIGURATION_CONTENT_CHANGED', common);
  if (!sameScope(exception.scope, view.scope)) return denyAudited(hook, configuration,
    'EXCEPTION_SCOPE_MISMATCH', common);
  if (exception.configRevision !== configuration.revision) return denyAudited(hook, configuration,
    'CONFIGURATION_STALE', common);
  if (registry.exceptions.length >= registry.maxExceptions) return denyAudited(hook, configuration,
    'EXCEPTION_CAPACITY', common);
  if (registry.exceptions.some((item) => item.exception.id === exception.id)) {
    return denyAudited(hook, configuration, 'EXCEPTION_ALREADY_REGISTERED', common);
  }
  if (digestPolicyException(exception) !== exception.digest) return denyAudited(hook, configuration,
    'EXCEPTION_CONTENT_CHANGED', common);
  if (approval === undefined) return denyAudited(hook, configuration, 'APPROVAL_MISSING', common);
  const verdict = approvalValid(approval, view.scope, exception.purpose, 'UPDATE',
    exception.configRevision, activeConfigurationDigest(registry), targetDigest, now, true);
  if (typeof verdict === 'string') return denyAudited(hook, configuration, verdict, common);
  const binding = verdict.binding!;
  if (!sameSubject(binding.subject, exception.subject) ||
    binding.semanticType !== exception.semanticType ||
    binding.sensitivity !== exception.sensitivity ||
    !sameDestination(binding.destination, exception.destination) ||
    binding.operation !== exception.operation) {
    return denyAudited(hook, configuration, 'APPROVAL_MISMATCH', common);
  }
  const appended = recordAudit(hook, configuration, 'UPDATE', 'APPLIED');
  const gate = auditGateAllows(appended, view.scope);
  if (!gate.permitted) return deny(gate.reason, { ...common, audit: gate.summary });
  registry.exceptions.push({ exception, revokedAt: null });
  return Object.freeze({
    version: 1 as const,
    state: 'APPLIED' as const,
    reason: 'EXCEPTION_REGISTERED' as const,
    revision: exception.configRevision,
    configDigest: configuration.bundleDigest,
    targetDigest,
    authority: 'NONE' as const,
    effect: 'SYNTHETIC_REGISTRY_ONLY' as const,
    promotion: PROMOTION,
    audit: { status: appended.status, finding: appended.finding },
  });
}

/** Revoke an exception. Narrowing authority is fail-closed, but it is still approved and audited. */
export function revokePolicyException(registryValue: unknown, exceptionValue: unknown,
  approvalValue: unknown, auditValue: unknown, nowValue: unknown): GovernanceOutcome {
  let view: RegistryView;
  try { view = registryView(registryValue); } catch (error) { return deny(denialOf(error)); }
  const registry = view.registry;
  const configuration = registry.config;
  const common = { revision: null, configDigest: configuration?.bundleDigest ?? null,
    targetDigest: null };
  let identifierValue: string;
  let now: Instant;
  let hook: AuditHookView;
  let approval: ApprovalView | undefined;
  try {
    identifierValue = identifier(exceptionValue);
    now = instant(nowValue);
    hook = auditHookView(auditValue, view.scope);
    if (approvalValue !== undefined && approvalValue !== null) approval = approvalView(approvalValue);
  } catch (error) { return deny(denialOf(error), common); }
  const registered = registry.exceptions.find((item) => item.exception.id === identifierValue);
  if (!registry.accepting || configuration === null || configuration === undefined) {
    return deny('REGISTRY_UNAVAILABLE', common);
  }
  if (!hook.scopesAgree) return deny('AUDIT_SCOPE_MISMATCH', common);
  if (!isIssued<PolicyConfiguration>(issuedConfigurations, configuration) ||
    !bundleRepinned(configuration)) return denyAudited(hook, configuration,
    'CONFIGURATION_CONTENT_CHANGED', common);
  if (registered === undefined) return denyAudited(hook, configuration, 'EXCEPTION_UNKNOWN', common);
  if (approval === undefined) return denyAudited(hook, configuration, 'APPROVAL_MISSING', common);
  const verdict = approvalValid(approval, view.scope, registered.exception.purpose, 'UPDATE',
    registered.exception.configRevision, activeConfigurationDigest(registry), registered.exception.digest,
    now, true);
  if (typeof verdict === 'string') return denyAudited(hook, configuration, verdict, common);
  const binding = verdict.binding!;
  if (!sameSubject(binding.subject, registered.exception.subject) ||
    binding.semanticType !== registered.exception.semanticType ||
    binding.sensitivity !== registered.exception.sensitivity ||
    !sameDestination(binding.destination, registered.exception.destination) ||
    binding.operation !== registered.exception.operation) {
    return denyAudited(hook, configuration, 'APPROVAL_MISMATCH', common);
  }
  const appended = recordAudit(hook, configuration, 'UPDATE', 'APPLIED');
  const gate = auditGateAllows(appended, view.scope);
  if (!gate.permitted) return deny(gate.reason, { ...common, audit: gate.summary });
  registered.revokedAt = now.stamp;
  return Object.freeze({
    version: 1 as const,
    state: 'APPLIED' as const,
    reason: 'EXCEPTION_REVOCATION_RECORDED' as const,
    revision: registered.exception.configRevision,
    configDigest: configuration.bundleDigest,
    targetDigest: registered.exception.digest,
    authority: 'NONE' as const,
    effect: 'SYNTHETIC_REGISTRY_ONLY' as const,
    promotion: PROMOTION,
    audit: { status: appended.status, finding: appended.finding },
  });
}

/* --------------------------------------------------------------- exception applicability */

function evaluation(exceptionId: string, state: 'APPLICABLE' | 'DENIED', reason: GovernanceReasonCode,
  registered?: RegisteredException): ExceptionEvaluation {
  return Object.freeze({
    version: 1 as const,
    exceptionId,
    state,
    reason,
    authority: 'NONE' as const,
    grantsTreatment: false as const,
    requiresPolicyDecision: true as const,
    expiresAt: registered?.exception.expiresAt ?? null,
    digest: registered?.exception.digest ?? null,
  });
}

/**
 * Answer whether one live exception covers one bound request tuple.
 *
 * This is the whole of an exception's effect, and it is deliberately not an effect: `APPLICABLE`
 * carries `authority: 'NONE'` and `grantsTreatment: false`. The caller still has to run #4
 * `decidePolicy`/`decideReviewedPolicy`, which independently refuses an unsafe treatment, an
 * unresolved classification, an unsupported policy identity and every missing binding, and a
 * broker authorization is still required wherever one exists. Refusal order is content, clock,
 * revocation, expiry, scope, tuple, then configuration supersession, and every refusal is a fixed
 * code: no planted value, request content or exception message is echoed.
 */
export function evaluatePolicyException(registryValue: unknown, exceptionIdValue: unknown,
  bindingValue: unknown, nowValue: unknown): ExceptionEvaluation {
  const exceptionId = ((): string => {
    try { return identifier(exceptionIdValue); } catch { fail('EXCEPTION_UNKNOWN'); }
  })();
  let view: RegistryView;
  try { view = registryView(registryValue); } catch (error) {
    return evaluation(exceptionId, 'DENIED', denialOf(error));
  }
  const registry = view.registry;
  if (!registry.accepting) return evaluation(exceptionId, 'DENIED', 'REGISTRY_UNAVAILABLE');
  const registered = registry.exceptions.find((item) => item.exception.id === exceptionId);
  if (registered === undefined) return evaluation(exceptionId, 'DENIED', 'EXCEPTION_UNKNOWN');
  const exception = registered.exception;
  if (!isIssued<PolicyException>(issuedExceptions, exception) ||
    digestPolicyException(exception) !== exception.digest) {
    return evaluation(exceptionId, 'DENIED', 'EXCEPTION_CONTENT_CHANGED', registered);
  }
  if (registered.revokedAt !== null) return evaluation(exceptionId, 'DENIED', 'EXCEPTION_REVOKED',
    registered);
  let now: Instant;
  let binding: ReturnType<typeof bindingView>;
  try { now = instant(nowValue); } catch { return evaluation(exceptionId, 'DENIED', 'INVALID_CLOCK',
    registered); }
  if (now.ms >= Date.parse(exception.expiresAt)) return evaluation(exceptionId, 'DENIED',
    'EXCEPTION_EXPIRED', registered);
  if (now.ms < Date.parse(exception.issuedAt)) return evaluation(exceptionId, 'DENIED',
    'EXCEPTION_NOT_YET_ACTIVE', registered);
  try { binding = bindingView(bindingValue); } catch {
    return evaluation(exceptionId, 'DENIED', 'INVALID_BINDING', registered);
  }
  if (!sameScope(binding.scope, view.scope) || !sameScope(binding.scope, exception.scope)) {
    return evaluation(exceptionId, 'DENIED', 'EXCEPTION_SCOPE_MISMATCH', registered);
  }
  if (!sameSubject(binding.subject, exception.subject) || binding.purpose !== exception.purpose ||
    binding.semanticType !== exception.semanticType ||
    binding.sensitivity !== exception.sensitivity ||
    !sameDestination(binding.destination, exception.destination) ||
    binding.operation !== exception.operation) {
    return evaluation(exceptionId, 'DENIED', 'EXCEPTION_BINDING_MISMATCH', registered);
  }
  const active = registry.config;
  if (active === null) return evaluation(exceptionId, 'DENIED', 'CONFIGURATION_UNAVAILABLE', registered);
  if (!isIssued<PolicyConfiguration>(issuedConfigurations, active) || !bundleRepinned(active)) {
    return evaluation(exceptionId, 'DENIED', 'CONFIGURATION_CONTENT_CHANGED', registered);
  }
  if (active.revision !== exception.configRevision) {
    return evaluation(exceptionId, 'DENIED', 'EXCEPTION_CONFIG_SUPERSEDED', registered);
  }
  return evaluation(exceptionId, 'APPLICABLE', 'EXCEPTION_APPLICABLE', registered);
}

/* ---------------------------------------------------------------------------- simulation */

/**
 * The fixed synthetic binding the simulation evaluates. It is deliberately **not** a tenant's live
 * request context: a structural comparison must never be mistaken for a tenant evaluation, and no
 * real principal, project or session is implied. The destination is always the exact sink the
 * candidate or baseline bundle itself declares for the probed profile.
 */
const PROBE_BINDING = Object.freeze({
  interactionRef: 'hylja.governance.simulation.interaction.invalid',
  candidateRef: 'hylja.governance.simulation.candidate.invalid',
  subject: Object.freeze({ principalId: 'hylja.governance.simulation.principal.invalid' }),
  context: Object.freeze({
    tenantId: 'hylja.governance.simulation.tenant.invalid',
    projectId: 'hylja.governance.simulation.project.invalid',
    sessionId: 'hylja.governance.simulation.session.invalid',
    purpose: 'hylja.governance.simulation.purpose.invalid',
  }),
  source: Object.freeze({ kind: 'tool.result',
    ref: 'hylja.governance.simulation.source.invalid', trustZone: 'LOCAL' }),
});
const PROBE_CLASSIFIERS = Object.freeze({ id: 'hylja.governance.simulation.detector.invalid',
  producerId: 'hylja.governance.simulation.detector.invalid', producerVersion: '1' });

/**
 * Release level, used only to order two #4 outcomes against each other. `DENIED` is 0, `HELD` is
 * 10 and a selected treatment is 20 + its position in the restriction order
 * (`REMOVE` 1 … `KEEP` 6), so a candidate is a new exposure exactly when it lets more out.
 */
const RESTRICTION_ORDER: readonly Treatment[] = ['REMOVE', 'MASK', 'TOKENIZE', 'SYNTHETIC',
  'GENERALIZE', 'KEEP'];
function releaseLevel(decision: PolicyDecision): number {
  if (decision.state === 'DENIED') return 0;
  if (decision.state === 'HELD') return 10;
  const rank = RESTRICTION_ORDER.indexOf(decision.treatment);
  return 20 + (rank < 0 ? 0 : rank + 1);
}
function side(decision: PolicyDecision): SimulationSide {
  return Object.freeze({ state: decision.state, treatment: decision.treatment, reason: decision.reason });
}
function probeClassification(semanticType: SemanticClass, sensitivity: Sensitivity, trust: Trust) {
  return composeClassification({ detectorEvidence: [{
    version: 1 as const, id: PROBE_CLASSIFIERS.id, status: 'FOUND' as const,
    provenance: { inputRef: PROBE_BINDING.candidateRef, producerId: PROBE_CLASSIFIERS.producerId,
      producerVersion: PROBE_CLASSIFIERS.producerVersion },
    claim: { semanticType, sensitivity },
  }] }, { interactionRef: PROBE_BINDING.interactionRef, sourceRef: PROBE_BINDING.source.ref, trust });
}
/**
 * The exact sink a bundle declares for a probe's profile, or `null` when it declares none.
 * A profile id alone is not a destination: #4 binds the full sink, so the diff compares the sink and
 * its trust zone.
 */
function probeSink(bundle: PolicyBundle, probe: SimulationProbe): Destination | null {
  return bundle.profiles.find((item) => item.id === probe.profileId)?.sink ?? null;
}

/**
 * Run the real #4 seam over one probe, one bundle and one exact destination.
 *
 * A bundle that does not declare the probed profile is still evaluated rather than skipped: #4 then
 * answers `PROFILE_MISMATCH`/`DENIED`, which is exactly what an integration would observe for a
 * request aimed at a destination that configuration does not declare. Skipping the side would hide
 * the "candidate adds a destination" transition, which is the exposure #28 asks to be reported.
 */
function probeDecision(bundle: PolicyBundle, probe: SimulationProbe, destination: Destination,
  classification: ReturnType<typeof probeClassification>): PolicyDecision {
  const boundary = {
    interactionRef: PROBE_BINDING.interactionRef,
    candidateRef: PROBE_BINDING.candidateRef,
    classificationDigest: digestClassification(classification),
    authenticated: { subject: PROBE_BINDING.subject, context: PROBE_BINDING.context },
    observed: { source: { ...PROBE_BINDING.source, trust: probe.sourceTrust }, destination },
    policy: { ...KNOWN_POLICY_BUNDLE, digest: digestPolicyBundle(bundle) },
  };
  const request = {
    version: 1 as const,
    interactionRef: PROBE_BINDING.interactionRef,
    candidateRef: PROBE_BINDING.candidateRef,
    subject: PROBE_BINDING.subject,
    context: PROBE_BINDING.context,
    source: PROBE_BINDING.source,
    destination,
    classification,
    operation: probe.operation,
    policy: { id: KNOWN_POLICY_BUNDLE.id, version: KNOWN_POLICY_BUNDLE.version },
  };
  return decidePolicy(request, boundary, bundle);
}
function probeView(value: unknown, position: number): SimulationProbe {
  const v = fields(value, ['version', 'profileId', 'semanticType', 'sensitivity', 'operation',
    'sourceTrust'], ['probeId']);
  if (v.version !== 1) fail('INVALID_PROBES');
  const semanticType = member(v.semanticType, SEMANTIC_CLASSES);
  const sensitivity = member(v.sensitivity, SENSITIVITIES);
  // A credential classification is always SECRET (decision 009); a probe claiming otherwise is
  // ambiguous rather than a scenario, so it is refused instead of silently reported.
  if (semanticType === 'CREDENTIAL_OR_SECRET' && sensitivity !== 'SECRET') fail('INVALID_PROBES');
  return Object.freeze({
    version: 1 as const,
    profileId: identifier(v.profileId),
    semanticType,
    sensitivity,
    operation: member(v.operation, POLICY_OPERATIONS),
    sourceTrust: member(v.sourceTrust, TRUST_LEVELS) as Trust,
    probeId: Object.hasOwn(v, 'probeId') ? identifier(v.probeId) : `probe-${String(position).padStart(4, '0')}`,
  });
}

/**
 * Compare an active configuration with a candidate over a bounded probe set.
 *
 * The report is computed by **running the real #4 seam twice per probe** — once over the active
 * bundle and once over the candidate bundle — and diffing the release levels, so a "newly exposed
 * class/sink/operation" is an observed transition, not a modelled guess. There is no second
 * evaluator here.
 *
 * It is strictly a report. It takes no approval, returns `activation: 'UNAVAILABLE'` and
 * `authority: 'NONE'`, and its result is structurally unusable as an activation or a registration
 * input: both accept only objects this module issued. Nothing here promotes, deploys, distributes
 * or relaxes a floor, and every finding carries closed fields, counts and digests only.
 */
export function simulatePolicyConfiguration(registryValue: unknown, configurationValue: unknown,
  probesValue: unknown): SimulationReport {
  // A forged identity for an object this module issued is a caller error and is loud; an
  // unreadable registry is an operational fact and is reported as unavailable, never compared.
  if (!isIssued<PolicyConfiguration>(issuedConfigurations, configurationValue)) {
    fail('INVALID_CONFIGURATION');
  }
  const configuration = configurationValue;
  const targetDigest = digestPolicyConfiguration(configuration);
  let view: RegistryView;
  const base = Object.freeze({
    version: 1 as const,
    finding: 'SIMULATION_UNAVAILABLE' as GovernanceReasonCode,
    authority: 'NONE' as const,
    activation: Object.freeze({ state: 'UNAVAILABLE' as const,
      effect: 'IGNORED_NO_AUTHORITY' as const }),
    candidate: Object.freeze({ revision: configuration.revision, configurationDigest: targetDigest,
      bundleDigest: configuration.bundleDigest }),
    promotion: PROMOTION,
  });
  const unavailable = (baselineRevision: number | null, baselineDigest: string | null) =>
    Object.freeze({ ...base, status: 'UNAVAILABLE' as const,
      baseline: Object.freeze({ revision: baselineRevision, configurationDigest: baselineDigest }),
      probes: Object.freeze({ evaluated: 0, denied: 0, unavailable: 0 }),
      newlyExposed: Object.freeze({ classes: Object.freeze([]) as readonly SemanticClass[],
        sinks: Object.freeze([]) as readonly string[],
        profiles: Object.freeze([]) as readonly string[],
        operations: Object.freeze([]) as readonly PolicyOperation[], count: 0 }),
      findings: Object.freeze([]) as readonly SimulationFinding[] });
  try { view = registryView(registryValue); } catch { return unavailable(null, null); }
  const registry = view.registry;
  const active = registry.config;

  // Content before comparison, and the probe cap before any evaluation work.
  if (!bundleRepinned(configuration)) return unavailable(null, null);
  if (active === null) return unavailable(null, null);
  if (!isIssued<PolicyConfiguration>(issuedConfigurations, active) || !bundleRepinned(active)) {
    return unavailable(null, null);
  }
  let probes: SimulationProbe[];
  try { probes = items(probesValue, (part, position) => probeView(part, position), LIMIT.probes); }
  catch (error) {
    if (error instanceof PolicyGovernanceError) fail('INVALID_PROBES');
    fail('INVALID_PROBES');
  }
  const seen = new Set<string>();
  for (const probe of probes) {
    if (seen.has(probe.probeId)) fail('INVALID_PROBES');
    seen.add(probe.probeId);
  }
  const findings: SimulationFinding[] = [];
  let denied = 0;
  let unavailableCount = 0;
  const classes = new Set<SemanticClass>();
  const sinks = new Set<string>();
  const profiles = new Set<string>();
  const operations = new Set<PolicyOperation>();
  for (const probe of probes) {
    const classification = probeClassification(probe.semanticType, probe.sensitivity,
      probe.sourceTrust);
    const baselineSinkView = probeSink(active.bundle, probe);
    const candidateSinkView = probeSink(configuration.bundle, probe);
    const baselineSink = baselineSinkView?.ref ?? null;
    const candidateSink = candidateSinkView?.ref ?? null;
    if (baselineSinkView === null && candidateSinkView === null) {
      // Neither configuration declares this profile, so there is nothing to compare. This is the
      // only "not comparable" case: a profile present on exactly one side is still evaluated.
      unavailableCount += 1;
      findings.push(Object.freeze({ probeId: probe.probeId, kind: 'UNAVAILABLE' as const,
        reason: 'PROFILE_UNAVAILABLE' as GovernanceReasonCode, profileId: probe.profileId,
        baselineSink: null, candidateSink: null, semanticType: probe.semanticType,
        sensitivity: probe.sensitivity, operation: probe.operation, sourceTrust: probe.sourceTrust,
        baseline: null, candidate: null }));
      continue;
    }
    // Each side is evaluated against the exact sink **its own** configuration declares for this
    // profile, which is what that configuration really does with the route. When one side declares
    // no profile, it is evaluated against the sink the other side declares: #4 then answers
    // `PROFILE_MISMATCH`/`DENIED`, exactly as it would for a request aimed at a destination that
    // configuration does not declare. Skipping that side instead would hide both the
    // "candidate adds a destination" and the "candidate rebinds a destination" transitions, which are
    // the exposures #28 asks to be reported.
    const declared = (bundle: PolicyBundle): Destination | undefined =>
      bundle.profiles.find((item) => item.id === probe.profileId)?.sink;
    const destination = declared(configuration.bundle) ?? declared(active.bundle);
    if (destination === undefined) return unavailable(null, null);
    const before = probeDecision(active.bundle, probe, declared(active.bundle) ?? destination,
      classification);
    const after = probeDecision(configuration.bundle, probe, destination, classification);
    if (before.state === 'DENIED') denied += 1;
    // Three independent observations. A relaxation of the decision level is an exposure. A candidate
    // pointing a profile at an exact sink the baseline did not is a newly exposed destination even
    // when the level is identical on both sides. A candidate that is strictly *more* restrictive --
    // a removed profile, a rebind to a tighter destination, a lowered ceiling -- is narrowing, is
    // reported as `NARROWED`, and is never counted as an exposure.
    const relaxed = releaseLevel(after) > releaseLevel(before);
    // Moving a destination from an external trust zone into a local one cannot increase exposure,
    // even where the decision level is identical on both sides, so it is narrowing rather than a new
    // exposure. Only that exact direction counts: an unrecognised zone never produces a narrowing.
    const zoneNarrowed = baselineSinkView !== null && candidateSinkView !== null &&
      baselineSinkView.trustZone === 'EXTERNAL' && candidateSinkView.trustZone === 'LOCAL';
    const narrowed = releaseLevel(after) < releaseLevel(before) || zoneNarrowed;
    const rebound = candidateSink !== baselineSink && candidateSink !== null && !narrowed;
    const exposed = relaxed || rebound;
    if (exposed) {
      classes.add(probe.semanticType);
      operations.add(probe.operation);
      if (candidateSink !== null) sinks.add(candidateSink);
      profiles.add(probe.profileId);
    }
    findings.push(Object.freeze({ probeId: probe.probeId,
      kind: (relaxed ? 'NEW_EXPOSURE' : rebound ? 'SINK_REBOUND'
        : narrowed ? 'NARROWED' : 'UNCHANGED') as SimulationFindingKind,
      reason: (exposed ? 'NEWLY_EXPOSED_SINK_OR_CLASS' : narrowed ? 'NARROWED_DESTINATION_OR_TREATMENT'
        : 'COMPARED') as GovernanceReasonCode,
      profileId: probe.profileId, baselineSink, candidateSink, semanticType: probe.semanticType,
      sensitivity: probe.sensitivity, operation: probe.operation, sourceTrust: probe.sourceTrust,
      baseline: side(before), candidate: side(after) }));
  }
  const selected = findings.length > LIMIT.findings ? findings.slice(0, LIMIT.findings) : findings;
  const selectedExposed = selected.filter((item) => item.kind === 'NEW_EXPOSURE' ||
    item.kind === 'SINK_REBOUND');
  return Object.freeze({
    version: 1 as const,
    status: 'COMPARED' as const,
    finding: 'SIMULATION_COMPARED' as GovernanceReasonCode,
    authority: 'NONE' as const,
    activation: base.activation,
    candidate: base.candidate,
    baseline: Object.freeze({ revision: active.revision,
      configurationDigest: digestPolicyConfiguration(active) }),
    probes: Object.freeze({ evaluated: probes.length, denied, unavailable: unavailableCount }),
    newlyExposed: Object.freeze({
      classes: Object.freeze([...classes].sort()),
      sinks: Object.freeze([...sinks].sort()),
      profiles: Object.freeze([...profiles].sort()),
      operations: Object.freeze([...operations].sort()),
      count: selectedExposed.length,
    }),
    findings: Object.freeze(selected),
    promotion: PROMOTION,
  });
}