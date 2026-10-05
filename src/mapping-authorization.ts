/**
 * Purpose-bound broker authorization for exactly one mapping reference (issue #163).
 *
 * This module answers a single question: may the authenticated caller perform this operation on this
 * one mapping, for this purpose, in this session, into this actual destination and profile, right now?
 * It is a **pure decision seam**, like `decidePolicy`, and it is not one of the treatment-selection
 * decisions: it never selects a treatment, never resolves or decrypts a value, never reveals plaintext,
 * never sends bytes and never performs an effect.
 *
 * Authority and what this seam does not do
 * - This seam is workload-bound for every operation it supports. A subject is a `principalId` **and** a
 *   nonempty `workloadId`, and that holds in three places: the untrusted request's subject, the host's
 *   authenticated subject and the grant's principal. A coherent principal-only request/host/grant is
 *   outside this seam and denies as malformed; the optional `workloadId` of the general envelope
 *   `Subject` does not widen it here.
 * - The untrusted request carries no authority. Subject, tenant/project/session, purpose, the actual
 *   destination/profile and the current time are supplied **separately** by the trusted integration;
 *   a caller-asserted trust label, payload field, model string or request timestamp cannot create any
 *   of them. The host authenticates the principal/workload, binds the purpose and session, observes
 *   the routed destination, reads the current mapping record and the explicit grant, and supplies the
 *   clock. This module authenticates nobody and verifies no issuer, proof, token or key.
 * - `USE`, `DISPLAY` and `EXPORT` are separate permissions and each needs its **own** explicit grant;
 *   there is no wildcard, tenant fallback, default allow or inheritance between operations or subjects.
 * - A credential or `SECRET` mapping is refused outright at this seam. It never becomes a reversible
 *   mapping that a grant can unlock (decision 009).
 * - Cross-tenant resolution is unconditional: a mapping is authorized only inside the exact tenant,
 *   project and session scope it was issued in, and no grant or exception lifts that.
 *
 * The result is `{version, state, reason}` and nothing else: no mapping metadata, grant, identifier,
 * plaintext, credential or release capability is echoed. An `AUTHORIZED` result grants nothing by
 * itself - a downstream broker must still re-check lifecycle and current revision, run the Policy
 * Engine, authenticate the caller, audit the decision and perform the effect itself.
 */
import { SEMANTIC_CLASSES, SENSITIVITIES } from './classification.js';
import type { SemanticClass, Sensitivity } from './classification.js';
import type { Destination, RequestContext, Subject } from './interaction-envelope.js';

/** The three brokered operations; none of them implies another. */
export const MAPPING_AUTHORIZATION_OPERATIONS = ['USE', 'DISPLAY', 'EXPORT'] as const;
export type MappingOperation = (typeof MAPPING_AUTHORIZATION_OPERATIONS)[number];

/** Mapping lifecycle from the security model; only `ACTIVE` is authorizable. */
export const MAPPING_LIFECYCLES = [
  'CREATED', 'ACTIVE', 'EXPIRED', 'REVOKED', 'DELETED', 'QUARANTINED',
] as const;
export type MappingLifecycle = (typeof MAPPING_LIFECYCLES)[number];

/** Every outcome this seam can return; fixed codes that never echo an input value. */
export const MAPPING_AUTHORIZATION_REASONS = [
  'AUTHORIZED',
  'INVALID_REQUEST', 'INVALID_CONTEXT', 'CONTEXT_MISMATCH', 'UNKNOWN_MAPPING',
  'MAPPING_NOT_ACTIVE', 'MAPPING_EXPIRED', 'MAPPING_REVOKED', 'NON_REVERSIBLE_MAPPING',
  'NO_GRANT', 'GRANT_MISMATCH', 'STALE_REVISION', 'SCOPE_MISMATCH',
  'OPERATION_NOT_GRANTED', 'GRANT_EXPIRED',
] as const;
export type MappingAuthorizationReason = (typeof MAPPING_AUTHORIZATION_REASONS)[number];

/** This seam narrows the envelope `Subject`: a workload identity is required, never optional. */
export interface WorkloadSubject extends Subject { workloadId: string }

/** Untrusted, bounded. Content here is a claim; none of it authenticates anything. */
export interface MappingAuthorizationRequest {
  version: 1;
  mappingRef: string;
  subject: WorkloadSubject;
  context: RequestContext;
  destination: Destination;
  operation: MappingOperation;
}

/** Independently supplied by the trusted host; never derived from request or model content. */
export interface MappingHostContext {
  authenticated: { subject: WorkloadSubject; context: RequestContext };
  observed: { destination: Destination };
}

/** The single current mapping record as the trusted host holds it. */
export interface TrustedMappingMetadata {
  version: 1;
  mappingRef: string;
  scope: { tenantId: string; projectId?: string; sessionId: string };
  lifecycle: MappingLifecycle;
  semanticType: SemanticClass;
  sensitivity: Sensitivity;
  /** Monotonic; a grant for any other revision is refused. */
  revision: number;
  /** Epoch milliseconds; at or after this instant the mapping is expired. */
  expiresAt: number;
}

/** One explicit, purpose-bound, finite grant for one operation. */
export interface TrustedMappingGrant {
  version: 1;
  mappingRef: string;
  revision: number;
  principal: WorkloadSubject;
  context: RequestContext;
  destination: Destination;
  operation: MappingOperation;
  expiresAt: number;
}

/** Host-owned time. A request timestamp is never read as time. */
export interface MappingHostClock { now: number }

export interface MappingAuthorizationDecision {
  version: 1;
  state: 'AUTHORIZED' | 'DENIED';
  reason: MappingAuthorizationReason;
}

// In-process values are untrusted structurally: own data descriptors only, no getters, no inherited
// properties, no model strings and no arbitrary exception text. Every record is validated once and the
// normalized copy is what the decision reads, so a caller object cannot change under it.
type Fields = Record<string, unknown>;
const MAX_KEYS = 32;
const REF_LIMIT = 256;
const ENDPOINT_REF_LIMIT = 2048;
class Invalid extends Error { constructor(readonly code: string) { super(code); } }
function fail(code: string): never { throw new Invalid(code); }
function fields(value: unknown, required: readonly string[], optional: readonly string[] = []): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('INVALID_INPUT');
  // A single bounded key snapshot prevents Proxy ownKeys from changing between reflections.
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_KEYS || keys.some((key) => typeof key !== 'string')) fail('INVALID_INPUT');
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    if (!required.includes(key) && !optional.includes(key)) fail('INVALID_INPUT');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('INVALID_INPUT');
    result[key] = descriptor.value;
  }
  for (const name of required) if (!Object.hasOwn(result, name)) fail('INVALID_INPUT');
  return result;
}
function text(value: unknown, limit = REF_LIMIT): string {
  if (typeof value !== 'string' || !value.length || value.length > limit || value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)) fail('INVALID_INPUT');
  return value;
}
function member<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) fail('INVALID_INPUT');
  return value as T;
}
/** An epoch-millisecond instant: a finite safe integer, never a fraction, string or sentinel. */
function instant(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) fail('INVALID_INPUT');
  return value;
}
function revision(value: unknown): number {
  const parsed = instant(value);
  if (parsed < 1) fail('INVALID_INPUT');
  return parsed;
}
/** Workload-bound at this seam: both halves of the identity are required and nonempty. */
function parseSubject(value: unknown): WorkloadSubject {
  const v = fields(value, ['principalId', 'workloadId']);
  return { principalId: text(v.principalId), workloadId: text(v.workloadId) };
}
function parseContext(value: unknown): RequestContext {
  const v = fields(value, ['tenantId', 'sessionId', 'purpose'], ['projectId']);
  return { tenantId: text(v.tenantId),
    ...(Object.hasOwn(v, 'projectId') ? { projectId: text(v.projectId) } : {}),
    sessionId: text(v.sessionId), purpose: text(v.purpose) };
}
function parseDestination(value: unknown): Destination {
  const v = fields(value, ['kind', 'ref', 'trustZone', 'profileId']);
  return { kind: text(v.kind), ref: text(v.ref, ENDPOINT_REF_LIMIT), trustZone: text(v.trustZone),
    profileId: text(v.profileId) };
}
/** The tenant/project/session triple a mapping or grant is bound to, in one canonical key order. */
function scope(value: unknown): { tenantId: string; projectId?: string; sessionId: string } {
  const v = fields(value, ['tenantId', 'sessionId'], ['projectId']);
  return { tenantId: text(v.tenantId),
    ...(Object.hasOwn(v, 'projectId') ? { projectId: text(v.projectId) } : {}),
    sessionId: text(v.sessionId) };
}
function scopeOf(context: RequestContext): { tenantId: string; projectId?: string; sessionId: string } {
  return { tenantId: context.tenantId,
    ...(Object.hasOwn(context, 'projectId') ? { projectId: context.projectId } : {}),
    sessionId: context.sessionId };
}
function parseRequest(value: unknown): MappingAuthorizationRequest {
  const v = fields(value, ['version', 'mappingRef', 'subject', 'context', 'destination', 'operation']);
  if (v.version !== 1) fail('INVALID_REQUEST');
  return { version: 1, mappingRef: text(v.mappingRef), subject: parseSubject(v.subject),
    context: parseContext(v.context), destination: parseDestination(v.destination),
    operation: member(v.operation, MAPPING_AUTHORIZATION_OPERATIONS) };
}
function parseHost(value: unknown): MappingHostContext {
  const v = fields(value, ['authenticated', 'observed']);
  const authenticated = fields(v.authenticated, ['subject', 'context']);
  const observed = fields(v.observed, ['destination']);
  return { authenticated: { subject: parseSubject(authenticated.subject),
      context: parseContext(authenticated.context) },
    observed: { destination: parseDestination(observed.destination) } };
}
function parseMapping(value: unknown): TrustedMappingMetadata {
  const v = fields(value, ['version', 'mappingRef', 'scope', 'lifecycle', 'semanticType',
    'sensitivity', 'revision', 'expiresAt']);
  if (v.version !== 1) fail('INVALID_CONTEXT');
  return { version: 1, mappingRef: text(v.mappingRef), scope: scope(v.scope),
    lifecycle: member(v.lifecycle, MAPPING_LIFECYCLES), semanticType: member(v.semanticType, SEMANTIC_CLASSES),
    sensitivity: member(v.sensitivity, SENSITIVITIES), revision: revision(v.revision),
    expiresAt: instant(v.expiresAt) };
}
function parseGrant(value: unknown): TrustedMappingGrant {
  const v = fields(value, ['version', 'mappingRef', 'revision', 'principal', 'context',
    'destination', 'operation', 'expiresAt']);
  if (v.version !== 1) fail('INVALID_CONTEXT');
  return { version: 1, mappingRef: text(v.mappingRef), revision: revision(v.revision),
    principal: parseSubject(v.principal), context: parseContext(v.context),
    destination: parseDestination(v.destination),
    operation: member(v.operation, MAPPING_AUTHORIZATION_OPERATIONS), expiresAt: instant(v.expiresAt) };
}
/**
 * The one authoritative grant-shape normalizer: a complete, valid grant becomes an owned, frozen
 * record built only from primitives this module validated, and every other value is `null`.
 *
 * This is **structural normalization and nothing else**. A `null` means only that the value is not a
 * grant of the schema above; it says nothing about authority, provenance, currentness, scope
 * congruence, lifecycle, expiry or whether an effect would have been valid, and a record it accepts
 * is not evidence that any of those hold. Callers still own their own refusals, their own order and
 * their own vocabulary: the seam below answers `INVALID_CONTEXT`, and a boundary that cannot name a
 * lifecycle about a value it never proved it holds names nothing at all.
 *
 * Sharing one reader is the point. It is what stops a second copy of this schema from drifting out of
 * step with the first and silently reading a different set of fields, so no consumer of a grant can
 * accept, reject or attribute one differently from another.
 *
 * The returned record owns every nested principal, context and destination: each is a new record of
 * this module's own making, never an alias into the source, so a caller that edits its own object
 * afterwards cannot reach into what a later check reads. A reflection, enumeration, descriptor or
 * index fault inside the read is caught here, so this function never throws and never carries
 * exception text back to its caller.
 */
export function normalizeMappingGrant(value: unknown): TrustedMappingGrant | null {
  try {
    return Object.freeze(parseGrant(value));
  } catch {
    // An absent value, a value of another type, and a hostile value that faults mid-read are all
    // the same answer here: no record, no partial record, and nothing that names a planted value.
    return null;
  }
}
function parseClock(value: unknown): MappingHostClock {
  const v = fields(value, ['now']);
  return { now: instant(v.now) };
}
/** Both sides are freshly normalized by the same parsers, so key order is already canonical. */
function equal(left: unknown, right: unknown): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function denied(reason: MappingAuthorizationReason): MappingAuthorizationDecision {
  return { version: 1, state: 'DENIED', reason };
}
function lifecycleReason(lifecycle: MappingLifecycle): MappingAuthorizationReason {
  if (lifecycle === 'EXPIRED') return 'MAPPING_EXPIRED';
  if (lifecycle === 'REVOKED' || lifecycle === 'DELETED') return 'MAPPING_REVOKED';
  return 'MAPPING_NOT_ACTIVE'; // CREATED, QUARANTINED
}

/**
 * Decides one purpose-bound operation on one mapping reference.
 *
 * The fixed order below is the contract: request shape, then each trusted input's shape, then the
 * request/host congruence, then the mapping, then the grant, then the operation. The first failing
 * check names the reason, so a caller cannot learn more than the fixed code.
 */
export function authorizeMappingOperation(requestValue: unknown, hostValue: unknown,
  mappingValue: unknown, grantValue: unknown, clockValue: unknown): MappingAuthorizationDecision {
  try {
    let request: MappingAuthorizationRequest;
    let host: MappingHostContext;
    let mapping: TrustedMappingMetadata;
    let clock: MappingHostClock;
    try { request = parseRequest(requestValue); } catch { return denied('INVALID_REQUEST'); }
    try { host = parseHost(hostValue); } catch { return denied('INVALID_CONTEXT'); }
    try { mapping = parseMapping(mappingValue); } catch { return denied('INVALID_CONTEXT'); }
    try { clock = parseClock(clockValue); } catch { return denied('INVALID_CONTEXT'); }
    // The grant's shape is validated with the other trusted inputs, before congruence and lifecycle,
    // so a malformed grant names INVALID_CONTEXT even when a later check would also fail. A grant that
    // is simply absent is not malformed: it keeps its own NO_GRANT check after the mapping checks.
    let grant: TrustedMappingGrant | undefined;
    if (grantValue !== undefined) {
      const normalized = normalizeMappingGrant(grantValue);
      if (normalized === null) return denied('INVALID_CONTEXT');
      grant = normalized;
    }
    const authenticated = host.authenticated;
    // The untrusted request may only restate what the host authenticated and observed.
    if (!equal(request.subject, authenticated.subject) ||
      !equal(request.context, authenticated.context) ||
      !equal(request.destination, host.observed.destination)) return denied('CONTEXT_MISMATCH');
    if (request.mappingRef !== mapping.mappingRef) return denied('UNKNOWN_MAPPING');
    if (mapping.lifecycle !== 'ACTIVE') return denied(lifecycleReason(mapping.lifecycle));
    if (clock.now >= mapping.expiresAt) return denied('MAPPING_EXPIRED');
    // Accepted floor: credentials and secrets are not reversible mappings (decision 009).
    if (mapping.semanticType === 'CREDENTIAL_OR_SECRET' || mapping.sensitivity === 'SECRET') {
      return denied('NON_REVERSIBLE_MAPPING');
    }
    if (!equal(mapping.scope, scopeOf(authenticated.context))) return denied('SCOPE_MISMATCH');
    // An absent grant is a denial, never an implicit allow.
    if (grant === undefined) return denied('NO_GRANT');
    if (grant.mappingRef !== mapping.mappingRef) return denied('GRANT_MISMATCH');
    // A grant pins one exact revision; an older or newer one is not the current mapping.
    if (grant.revision !== mapping.revision) return denied('STALE_REVISION');
    if (!equal(grant.principal, authenticated.subject) ||
      !equal(scopeOf(grant.context), mapping.scope)) return denied('SCOPE_MISMATCH');
    if (grant.context.purpose !== authenticated.context.purpose) return denied('GRANT_MISMATCH');
    if (!equal(grant.destination, host.observed.destination)) return denied('GRANT_MISMATCH');
    // One grant authorizes its own operation only; USE never implies DISPLAY, nor DISPLAY EXPORT.
    if (grant.operation !== request.operation) return denied('OPERATION_NOT_GRANTED');
    if (clock.now >= grant.expiresAt) return denied('GRANT_EXPIRED');
    return { version: 1, state: 'AUTHORIZED', reason: 'AUTHORIZED' };
  } catch {
    // A hostile value that survived the parsers still yields a fixed denial and no exception detail.
    return denied('INVALID_CONTEXT');
  }
}