/**
 * One bound runtime `USE` executor for exactly one opaque mapping reference (issue #211).
 *
 * `createBoundMappingUse(trustedHost)` binds one reference, one tenant/project/session scope, one
 * entity, one registry, one audit substrate, one pinned policy handoff and one **private synchronous
 * resource** at construction. `use()` takes no argument: the caller supplies no operation, no
 * authority, no grant, no key and no effect, and receives one fixed code - `USED`, `NOT_FOUND`,
 * `WITHHELD` or `FAILED` - and nothing else. There is no reference argument, no enumeration, no scan
 * and no bulk path, so this is not a mapping lookup API (decision 004).
 *
 * Binding the target does **not** freeze authority. The authenticated subject and context, the actual
 * observed route, the current explicit grant, the current key version and the host clock are read
 * from the host at the start of every `use()` and again after every external callback, so a grant
 * that is revoked, a route that changes or a key that rotates mid-flight is observed rather than
 * spent. The host is trusted to answer honestly and coherently; this module authenticates nobody.
 *
 * The fixed order inside one `use()` is the contract:
 *   1. capture every callback function **and receiver** once, before any guard runs;
 *   2. read the current coherent authority; require the bound scope; read the real registry `current`
 *      and require `FOUND` and `ACTIVE`;
 *   3. require an actual `AUTHORIZED` decision from `authorizeMappingOperation` for `USE`;
 *   4. require an actual `SELECTED`/`KEEP` decision from `decidePolicy` for `USE`;
 *   5. require the audit substrate's recorded actor to be this authenticated subject;
 *   6. load the sealed material and the DEK - the only awaits, and no plaintext exists yet;
 *   7. after that callback, and after **every** later external callback, re-observe the coherent
 *      authority, re-read the real registry, reauthorize and rerun the real policy, requiring an
 *      unchanged revision and key version and congruence with the actor, scope, classification,
 *      destination and policy decision already recorded;
 *   8. record the authorization attempt and the policy decision through the real
 *      `appendAuditEvent`, gating each one on `gateHighRiskEffect` applied to the value that
 *      `appendAuditEvent` itself returned, then re-observe again;
 *   9. from the last guard to the effect there is no await, no host property lookup and no dynamic
 *      function lookup: the real `openMappingPayload` opens an independently established expected
 *      AAD and the **captured** synchronous backend decides on the recovered bytes;
 *  10. only a primitive boolean from that backend becomes `USED` or `NOT_FOUND`. Every owned byte
 *      buffer - the envelope copies, the DEK copy and the recovered plaintext - is overwritten in one
 *      `finally` on the success path and on every exceptional path.
 *
 * Refusal vocabulary. Every internal refusal - a refused registry read, a denied authorization, a
 * `BLOCK` or `HELD` policy decision, an absent audit record, a superseded revision, a rotated key, an
 * expired instant, a changed actor or route, an opaque hostile callback, a reentrant or overlapping
 * call, or an opener refusal - is one fixed `WITHHELD`. The internal reason never reaches the caller.
 * `FAILED` is reserved for the one thing a refusal cannot describe: the effect was reached and could
 * not be completed, which is a backend that threw or returned something other than a primitive
 * boolean. Neither `WITHHELD` nor `FAILED` ever performs, claims or reports a `USE`.
 *
 * What this is not
 * - **Not a broker, vault, store or index.** It resolves no original, holds no mapping table, exposes
 *   no bulk lookup, makes no transaction and has no lock, retry, recovery or transport. The registry,
 *   the audit substrate, the key and the backend are the host's.
 * - **Not key custody.** The DEK is supplied by the host, copied once, used once and overwritten here.
 *   Generation, wrapping, rotation, storage and destruction are key-management obligations this
 *   module neither performs nor claims.
 * - **Not authentication and not a fresh-authority authority.** Every identity, route, clock and grant
 *   is a trusted obligation of the host; a coherent but dishonest host is answered coherently and
 *   dishonestly. Cross-tenant resolution is nonetheless structurally refused: the scope is bound at
 *   construction, and an observation outside it never reaches the registry, the grant or the effect.
 * - **Not durable audit.** The ledger is a host-owned substrate. `gateHighRiskEffect` is a pure
 *   structural check, which is exactly why the value passed to it is the one `appendAuditEvent`
 *   returned, in this process, un-cached and un-reconstructed. This module records `ALLOWED`
 *   decisions only; privacy-safe evidence of a *refusal* stays the integrating host's obligation.
 * - **Not zeroization.** Overwriting owned buffers in JavaScript is best-effort hygiene: copies held
 *   inside native crypto, garbage-collected buffers and swapped pages are not covered.
 * - **Not a protected-egress safety claim.** A `USE` here spends plaintext on one local synchronous
 *   resource; no bytes leave this process. Nothing here is a KMS/HSM binding, a production vault or a
 *   substitute for human review of a proposed design.
 */
import { TRUST_LEVELS } from './classification.js';
import type { Classification, Trust } from './classification.js';
import { AUDIT_BUNDLE_COMPONENTS, appendAuditEvent, gateHighRiskEffect } from './audit-ledger.js';
import type { AuditBundleComponent, AuditLedger, AuditTrustedContext } from './audit-ledger.js';
import { decidePolicy } from './policy.js';
import type { PolicyBundle, PolicyDecision } from './policy.js';
import { authorizeMappingOperation } from './mapping-authorization.js';
import type { TrustedMappingGrant, WorkloadSubject } from './mapping-authorization.js';
import type { MappingMetadataRecord, MappingMetadataRegistry } from './mapping-metadata-registry.js';
import { MAPPING_AEAD_LIMITS, openMappingPayload } from './mapping-aead.js';
import type { MappingSealedEnvelope } from './mapping-aead.js';
import type { Destination, Endpoint, RequestContext } from './interaction-envelope.js';

/** The closed outcome vocabulary. `USED` is the only claim that a resource actually resolved. */
export const MAPPING_USE_CODES = ['USED', 'NOT_FOUND', 'WITHHELD', 'FAILED'] as const;
export type MappingUseCode = (typeof MAPPING_USE_CODES)[number];

/** The only thing a caller ever receives: one fixed code, no reason, no reference, no metadata. */
export interface MappingUseResult { readonly version: 1; readonly code: MappingUseCode }

export interface MappingUseScope { tenantId: string; projectId: string; sessionId: string }

/**
 * One coherent observation of the host's current authority, read fresh at every observation point.
 * Nothing here is cached across a `use()`, and no part of it is frozen at construction.
 */
export interface MappingUseAuthority {
  version: 1;
  subject: WorkloadSubject;
  context: RequestContext;
  destination: Destination;
  grant: TrustedMappingGrant;
  keyVersion: string;
  now: number;
}

/** The sealed record, its DEK and the control-plane claims they are bound to. */
export interface MappingUseMaterial {
  version: 1;
  envelope: MappingSealedEnvelope;
  key: Uint8Array;
  mappingRevision: string;
  keyVersion: string;
}

/** The pinned classification handoff and the independently pinned control-plane bundle identity. */
export interface MappingUsePolicy {
  version: 1;
  interactionRef: string;
  candidateRef: string;
  source: Endpoint & { trust: Trust };
  classification: Classification;
  /** Independently pinned content commitment over `classification`; a drift is a refusal. */
  classificationDigest: string;
  /** Independently pinned control-plane identity of this exact `bundle` snapshot. */
  policy: { id: string; version: string; digest: string };
  bundle: PolicyBundle;
}

export interface MappingUseAudit {
  ledger: AuditLedger;
  context: AuditTrustedContext;
  components: readonly { id: AuditBundleComponent; version: string }[];
}

/**
 * The private synchronous resource. One primitive boolean in, nothing out. It is bound at
 * construction, and it must not retain, copy, log or forward the bytes it is handed: this module
 * overwrites its own copy immediately after the call and cannot do anything about a retained one.
 */
export interface MappingUseBackend { lookup(identifier: Uint8Array): boolean }

/** The trusted host. Host configuration, not untrusted request content; the caller never sees it. */
export interface MappingUseHost {
  version: 1;
  mappingRef: string;
  scope: MappingUseScope;
  entityId: string;
  registry: MappingMetadataRegistry;
  audit: MappingUseAudit;
  policy: MappingUsePolicy;
  backend: MappingUseBackend;
  /** Current coherent authority. May return a promise; its answers must be honest. */
  authority(): unknown;
  /** Current sealed material and DEK for the bound reference. May return a promise. */
  material(): unknown;
}

/** The one object an untrusted caller receives. It carries no setter, no selector and no argument. */
export interface BoundMappingUse { use(): Promise<MappingUseResult> }

// ---------------------------------------------------------------------------------------------
// Internal refusal vocabulary. These codes never leave this module: they steer control flow, and a
// caller sees one fixed `WITHHELD` for all of them. `Refusal` is recognised by a module-private brand
// under a guard, so a hostile thrown proxy cannot make classification throw out of the boundary.
// ---------------------------------------------------------------------------------------------
type Denial =
  | 'REENTRY' | 'HOST_FAULT' | 'INVALID_AUTHORITY' | 'SCOPE_MISMATCH' | 'NOT_CURRENT'
  | 'NOT_ACTIVE' | 'UNAUTHORIZED' | 'POLICY_REFUSED' | 'MATERIAL_INVALID' | 'MATERIAL_STALE'
  | 'AUDIT_REFUSED' | 'AUDIT_ACTOR' | 'SUPERSEDED' | 'NOT_CONGRUENT' | 'CLOCK' | 'OPEN_REFUSED'
  | 'BACKEND_CONTRACT';
const REFUSAL_BRAND: unique symbol = Symbol('hylja.mapping-use.refusal');

class Refusal extends Error {
  constructor(readonly code: Denial) { super(code); this.name = 'Refusal'; }
  readonly brand: typeof REFUSAL_BRAND = REFUSAL_BRAND;
}

/** Non-reflective and guarded: a trap while classifying degrades to `undefined`, never an escape. */
function isRefusal(error: unknown): boolean {
  try {
    if (error === null || typeof error !== 'object') return false;
    const candidate = error as { brand?: unknown };
    if (candidate.brand !== REFUSAL_BRAND) return false;
    return true;
  } catch { return false; }
}
function fail(code: Denial): never { throw new Refusal(code); }
/** Runs one host call site. A throwing host callback is a refusal, never an escaped exception. */
function attempt<T>(invoke: () => T): T {
  try { return invoke(); } catch (error) { if (isRefusal(error)) throw error; fail('HOST_FAULT'); }
}

// ---------------------------------------------------------------------------------------------
// Defensive structural readers for values crossing the boundary. Own data descriptors only, bounded
// keys, no getters and no inherited properties, so one snapshot is what every later check reads.
// ---------------------------------------------------------------------------------------------
type Fields = Record<string, unknown>;
const MAX_KEYS = 16;
const REF_LIMIT = 2048;
/** The AEAD identifier shape. An entity id is a bounded token, never an email, URL or free text. */
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._=-]{0,127}$/u;
const REVISION = /^\d{1,12}$/u;
const KEY_VERSION = /^\d{1,12}(?:\.\d{1,12}){0,3}$/u;

function fields(value: unknown, required: readonly string[], optional: readonly string[] = []): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('INVALID_AUTHORITY');
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_KEYS || keys.some((key) => typeof key !== 'string')) fail('INVALID_AUTHORITY');
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    if (!required.includes(key) && !optional.includes(key)) fail('INVALID_AUTHORITY');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail('INVALID_AUTHORITY');
    result[key] = descriptor.value;
  }
  for (const name of required) if (!Object.hasOwn(result, name)) fail('INVALID_AUTHORITY');
  return result;
}
function text(value: unknown, limit = REF_LIMIT): string {
  if (typeof value !== 'string' || !value.length || value.length > limit || value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)) fail('INVALID_AUTHORITY');
  return value;
}
function member<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) fail('INVALID_AUTHORITY');
  return value as T;
}
function instant(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) fail('INVALID_AUTHORITY');
  return value;
}
function subject(value: unknown): WorkloadSubject {
  const v = fields(value, ['principalId', 'workloadId']);
  return { principalId: text(v.principalId), workloadId: text(v.workloadId) };
}
function context(value: unknown): RequestContext {
  const v = fields(value, ['tenantId', 'sessionId', 'purpose'], ['projectId']);
  return { tenantId: text(v.tenantId),
    ...(Object.hasOwn(v, 'projectId') ? { projectId: text(v.projectId) } : {}),
    sessionId: text(v.sessionId), purpose: text(v.purpose) };
}
function destination(value: unknown): Destination {
  const v = fields(value, ['kind', 'ref', 'trustZone', 'profileId']);
  return { kind: text(v.kind, 256), ref: text(v.ref), trustZone: text(v.trustZone, 256),
    profileId: text(v.profileId, 256) };
}
/**
 * A defensive copy of the host's grant. Shape is normalized here so repeated reads cannot see a
 * changed object; the authoritative semantic check stays with `authorizeMappingOperation`.
 */
function grant(value: unknown): TrustedMappingGrant {
  const v = fields(value, ['version', 'mappingRef', 'revision', 'principal', 'context',
    'destination', 'operation', 'expiresAt']);
  return Object.freeze({ version: v.version as 1, mappingRef: text(v.mappingRef, 256),
    revision: v.revision as number, principal: v.principal as WorkloadSubject,
    context: v.context as RequestContext, destination: v.destination as Destination,
    operation: v.operation as TrustedMappingGrant['operation'], expiresAt: v.expiresAt as number });
}
function equal(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

/** One owned copy of one byte source. The declared length is validated before any allocation. */
function snapshotBytes(value: unknown, maximum: number): Uint8Array {
  if (!(value instanceof Uint8Array)) fail('MATERIAL_INVALID');
  const declared: unknown = value.byteLength;
  if (typeof declared !== 'number' || !Number.isSafeInteger(declared) || declared < 0 ||
    declared > maximum) fail('MATERIAL_INVALID');
  const copy = new Uint8Array(declared);
  for (let index = 0; index < declared; index += 1) {
    const byte: unknown = value[index];
    if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 0xff) {
      copy.fill(0);
      fail('MATERIAL_INVALID');
    }
    copy[index] = byte;
  }
  return copy;
}

const USED: MappingUseResult = Object.freeze({ version: 1, code: 'USED' } as const);
const NOT_FOUND: MappingUseResult = Object.freeze({ version: 1, code: 'NOT_FOUND' } as const);
const WITHHELD: MappingUseResult = Object.freeze({ version: 1, code: 'WITHHELD' } as const);
const FAILED: MappingUseResult = Object.freeze({ version: 1, code: 'FAILED' } as const);

// ---------------------------------------------------------------------------------------------
// Construction-time bindings. Every one of these is host configuration: an unusable binding throws a
// fixed `TypeError` carrying no supplied value, and there is no option that weakens a gate.
// ---------------------------------------------------------------------------------------------
interface PolicyBinding {
  interactionRef: string; candidateRef: string; source: Endpoint & { trust: Trust };
  classification: Classification; classificationDigest: string;
  policy: { id: string; version: string; digest: string }; bundle: PolicyBundle;
}
interface AuditBinding { ledger: AuditLedger; context: AuditTrustedContext; components: readonly { id: AuditBundleComponent; version: string }[] }
interface FixedBindings {
  mappingRef: string; scope: MappingUseScope; entityId: string;
  registry: MappingMetadataRegistry; readCurrent: MappingMetadataRegistry['current'];
  audit: AuditBinding; policy: PolicyBinding; backend: MappingUseBackend;
  authority: () => unknown; material: () => unknown;
}
function bindings(hostValue: unknown): FixedBindings {
  try {
    const host = fields(hostValue, ['version', 'mappingRef', 'scope', 'entityId', 'registry',
      'audit', 'policy', 'backend', 'authority', 'material']);
    if (host.version !== 1) fail('INVALID_AUTHORITY');
    const registry = host.registry as MappingMetadataRegistry;
    if (registry === null || typeof registry !== 'object' || registry.version !== 1 ||
      typeof registry.current !== 'function') fail('INVALID_AUTHORITY');
    const scopeSource = fields(host.scope, ['tenantId', 'projectId', 'sessionId']);
    const scope: MappingUseScope = Object.freeze({ tenantId: text(scopeSource.tenantId, 256),
      projectId: text(scopeSource.projectId, 256), sessionId: text(scopeSource.sessionId, 256) });
    const entityId = text(host.entityId, 128);
    if (!IDENTIFIER.test(entityId)) fail('INVALID_AUTHORITY');
    const policySource = fields(host.policy, ['version', 'interactionRef', 'candidateRef', 'source',
      'classification', 'classificationDigest', 'policy', 'bundle']);
    if (policySource.version !== 1) fail('INVALID_AUTHORITY');
    const classification = policySource.classification as Classification;
    if (classification === null || typeof classification !== 'object' ||
      classification.version !== 1 || classification.status !== 'RESOLVED' ||
      classification.semanticType === 'CREDENTIAL_OR_SECRET' ||
      classification.sensitivity === 'SECRET') fail('INVALID_AUTHORITY');
    const source = fields(policySource.source, ['kind', 'ref', 'trustZone', 'trust']);
    const identity = fields(policySource.policy, ['id', 'version', 'digest']);
    const policy: PolicyBinding = Object.freeze({
      interactionRef: text(policySource.interactionRef, 256),
      candidateRef: text(policySource.candidateRef, 256),
      source: Object.freeze({ kind: text(source.kind, 256), ref: text(source.ref),
        trustZone: text(source.trustZone, 256), trust: member(source.trust, TRUST_LEVELS) }),
      classification,
      classificationDigest: text(policySource.classificationDigest, 64),
      policy: Object.freeze({ id: text(identity.id, 256), version: text(identity.version, 256),
        digest: text(identity.digest, 64) }),
      bundle: policySource.bundle as PolicyBundle });
    const auditSource = fields(host.audit, ['ledger', 'context', 'components']);
    const ledger = auditSource.ledger as AuditLedger;
    const contextValue = auditSource.context as AuditTrustedContext;
    if (ledger === null || typeof ledger !== 'object' || ledger.version !== 1 ||
      contextValue === null || typeof contextValue !== 'object' || contextValue.version !== 1) {
      fail('INVALID_AUTHORITY');
    }
    const components = componentsOf(auditSource.components);
    const backend = host.backend as MappingUseBackend;
    if (backend === null || typeof backend !== 'object' ||
      typeof host.authority !== 'function' || typeof host.material !== 'function') {
      fail('INVALID_AUTHORITY');
    }
    const authority = host.authority as () => unknown;
    const material = host.material as () => unknown;
    return Object.freeze({ mappingRef: text(host.mappingRef, 256), scope, entityId,
      registry, readCurrent: registry.current,
      audit: Object.freeze({ ledger, context: contextValue, components }),
      policy, backend, authority, material });
  } catch {
    // Host configuration is either usable or it is not: one fixed `TypeError`, never the supplied
    // value and never a partial binding.
    throw new TypeError('Invalid mapping use host');
  }
}
function componentsOf(value: unknown): readonly { id: AuditBundleComponent; version: string }[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 12) fail('INVALID_AUTHORITY');
  return Object.freeze(value.map((part) => {
    const c = fields(part, ['id', 'version']);
    const id = text(c.id, 128);
    if (!(AUDIT_BUNDLE_COMPONENTS as readonly string[]).includes(id)) fail('INVALID_AUTHORITY');
    return Object.freeze({ id: id as AuditBundleComponent, version: text(c.version, 128) });
  }));
}

/**
 * Creates the one bound executor.
 *
 * Construction fixes the reference, the scope, the entity, the registry, the audit substrate, the
 * pinned policy handoff and the backend. It freezes **no** authority: the identity, context, route,
 * grant, key version and clock are re-read by every `use()`. A second `use()` that overlaps an
 * unfinished one is refused immediately, before any host call, because an overlapping effect on one
 * reference has no coherent snapshot to spend.
 */
export function createBoundMappingUse(hostValue: unknown): BoundMappingUse {
  const fixed = bindings(hostValue);
  let busy = false;
  /** The caller supplies nothing. Reentry is refused synchronously, before the first await. */
  const use = async (): Promise<MappingUseResult> => {
    if (busy) return WITHHELD;
    busy = true;
    try {
      return await run(fixed);
    } catch (error) {
      // A refusal is `WITHHELD`. Anything else escaped a host callback inside the effect segment -
      // a backend that threw is the honest case - so the effect was reached and never completed.
      return isRefusal(error) ? WITHHELD : FAILED;
    } finally {
      busy = false;
    }
  };
  return Object.freeze({ use });
}

// ---------------------------------------------------------------------------------------------
// The ordered USE path.
// ---------------------------------------------------------------------------------------------
interface Captured {
  fixed: FixedBindings;
  authority: () => unknown;
  material: () => unknown;
  /** The backend method and its receiver, captured together before any guard runs. */
  lookup: (identifier: Uint8Array) => boolean;
  receiver: MappingUseBackend;
}
interface Observation {
  now: number; subject: WorkloadSubject; context: RequestContext; destination: Destination;
  grant: TrustedMappingGrant; keyVersion: string;
}
interface Material {
  envelope: MappingSealedEnvelope;
  key: Uint8Array;
  revision: string;
  keyVersion: string;
}
interface State { observation: Observation; revision: number; decision: PolicyDecision }

/**
 * Captures every callback function and every receiver this call will use, once, before the first
 * guard. A method swapped, re-pointed or re-targeted after this point cannot change what runs, and no
 * property of the host is read again after the last guard below.
 */
function capture(fixed: FixedBindings): Captured {
  return Object.freeze({
    fixed,
    authority: attempt(() => fixed.authority),
    material: attempt(() => fixed.material),
    lookup: attempt(() => {
      const backend = fixed.backend;
      const lookup = backend.lookup;
      if (typeof lookup !== 'function') fail('HOST_FAULT');
      return lookup;
    }),
    receiver: fixed.backend,
  });
}

/** One coherent authority observation, normalized once. The bound scope is a structural gate. */
function observe(captured: Captured): Observation {
  const raw = attempt(() => captured.authority());
  if (raw === null || typeof raw !== 'object') fail('INVALID_AUTHORITY');
  const v = fields(raw, ['version', 'subject', 'context', 'destination', 'grant', 'keyVersion', 'now']);
  if (v.version !== 1) fail('INVALID_AUTHORITY');
  const observed = context(v.context);
  const scope = captured.fixed.scope;
  if (observed.tenantId !== scope.tenantId || observed.projectId !== scope.projectId ||
    observed.sessionId !== scope.sessionId) fail('SCOPE_MISMATCH');
  const keyVersion = text(v.keyVersion, 48);
  if (!KEY_VERSION.test(keyVersion)) fail('INVALID_AUTHORITY');
  return Object.freeze({ now: instant(v.now), subject: subject(v.subject), context: observed,
    destination: destination(v.destination), grant: grant(v.grant), keyVersion });
}

/** A real registry read. Only a `FOUND`, `ACTIVE` record at a live instant reaches anything else. */
function liveRecord(captured: Captured, now: number): MappingMetadataRecord {
  const { registry, readCurrent, mappingRef, scope } = captured.fixed;
  return attempt(() => {
    const found = readCurrent.call(registry, { version: 1, mappingRef,
      scope: { tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId } },
    { now });
    if (found === null || typeof found !== 'object' || found.state !== 'FOUND') fail('NOT_CURRENT');
    const record = found.metadata;
    if (record === null || typeof record !== 'object' || record.state !== 'ACTIVE') fail('NOT_ACTIVE');
    return record;
  });
}

/** The real purpose-bound authorization seam, for `USE` only, on the grant this observation read. */
function authorize(captured: Captured, observed: Observation, record: MappingMetadataRecord): void {
  const { mappingRef, policy: pinned } = captured.fixed;
  const semanticType = pinned.classification.semanticType;
  const decision = attempt(() => authorizeMappingOperation(
    { version: 1, mappingRef, subject: { ...observed.subject }, context: { ...observed.context },
      destination: { ...observed.destination }, operation: 'USE' },
    { authenticated: { subject: { ...observed.subject }, context: { ...observed.context } },
      observed: { destination: { ...observed.destination } } },
    { version: 1, mappingRef: record.mappingRef, scope: { ...record.scope },
      lifecycle: record.state, semanticType, sensitivity: pinned.classification.sensitivity,
      revision: record.revision, expiresAt: record.expiresAt },
    observed.grant, { now: observed.now }));
  if (decision.state !== 'AUTHORIZED') fail('UNAUTHORIZED');
}

/** The real Policy Engine, for `USE`, over the pinned bundle and the freshly observed authority. */
function selectPolicy(captured: Captured, observed: Observation): PolicyDecision {
  const pinned = captured.fixed.policy;
  const decision = attempt(() => decidePolicy(
    { version: 1, interactionRef: pinned.interactionRef, candidateRef: pinned.candidateRef,
      subject: { ...observed.subject }, context: { ...observed.context },
      source: { kind: pinned.source.kind, ref: pinned.source.ref, trustZone: pinned.source.trustZone },
      destination: { ...observed.destination }, classification: pinned.classification,
      operation: 'USE', policy: { id: pinned.policy.id, version: pinned.policy.version } },
    { interactionRef: pinned.interactionRef, candidateRef: pinned.candidateRef,
      classificationDigest: pinned.classificationDigest,
      authenticated: { subject: { ...observed.subject }, context: { ...observed.context } },
      observed: { source: { ...pinned.source }, destination: { ...observed.destination } },
      policy: { ...pinned.policy } },
    pinned.bundle));
  if (decision.state !== 'SELECTED' || decision.treatment !== 'KEEP' || decision.decisionRef === undefined) {
    fail('POLICY_REFUSED');
  }
  return decision;
}

/**
 * The recorded actor must be the authenticated subject. The audit ledger takes the actor from its
 * trusted context and never from a draft, so a host recording someone else's USE under this
 * executor's reference is refused before anything is written.
 */
function bindAuditActor(captured: Captured, observed: Observation): void {
  const contextValue = captured.fixed.audit.context;
  const actor = attempt(() => contextValue.actor as { principalId: unknown; workloadId?: unknown });
  if (actor === null || typeof actor !== 'object' || actor.principalId !== observed.subject.principalId) {
    fail('AUDIT_ACTOR');
  }
  if ((actor.workloadId ?? null) !== observed.subject.workloadId) fail('AUDIT_ACTOR');
}

/** Loads the sealed record and the DEK into owned copies. This is the only awaiting boundary. */
async function loadMaterial(captured: Captured, owned: Uint8Array[]): Promise<Material> {
  let raw: unknown;
  try { raw = await captured.material(); } catch (error) {
    if (isRefusal(error)) throw error;
    fail('HOST_FAULT');
  }
  const v = fields(raw, ['version', 'envelope', 'key', 'mappingRevision', 'keyVersion']);
  if (v.version !== 1) fail('MATERIAL_INVALID');
  const revision = text(v.mappingRevision, 12);
  const keyVersion = text(v.keyVersion, 48);
  if (!REVISION.test(revision) || !KEY_VERSION.test(keyVersion)) fail('MATERIAL_INVALID');
  const envelope = fields(v.envelope, ['version', 'nonce', 'ciphertext', 'tag']);
  if (envelope.version !== 1) fail('MATERIAL_INVALID');
  const nonce = snapshotBytes(envelope.nonce, MAPPING_AEAD_LIMITS.nonceBytes);
  const tag = snapshotBytes(envelope.tag, MAPPING_AEAD_LIMITS.tagBytes);
  const ciphertext = snapshotBytes(envelope.ciphertext, MAPPING_AEAD_LIMITS.ciphertextBytes);
  if (ciphertext.byteLength === 0) {
    nonce.fill(0); tag.fill(0);
    fail('MATERIAL_INVALID');
  }
  const key = snapshotBytes(v.key, MAPPING_AEAD_LIMITS.keyBytes);
  owned.push(nonce, tag, ciphertext, key);
  return { envelope: Object.freeze({ version: 1, nonce, ciphertext, tag }), key,
    revision, keyVersion };
}

/**
 * The recheck that runs after every external callback: authority, clock, registry, authorization and
 * policy are all read again, and the material must still be the material this instant would use.
 */
function recheck(captured: Captured, material: Material, previous: State): State {
  const observed = observe(captured);
  if (observed.now < previous.observation.now) fail('CLOCK');
  if (!equal(observed.subject, previous.observation.subject) ||
    !equal(observed.context, previous.observation.context) ||
    !equal(observed.destination, previous.observation.destination)) fail('NOT_CONGRUENT');
  if (observed.keyVersion !== previous.observation.keyVersion) fail('MATERIAL_STALE');
  const record = liveRecord(captured, observed.now);
  if (record.revision !== previous.revision) fail('SUPERSEDED');
  authorize(captured, observed, record);
  const decision = selectPolicy(captured, observed);
  if (decision.decisionRef !== previous.decision.decisionRef) fail('NOT_CONGRUENT');
  if (material.revision !== String(record.revision) || material.keyVersion !== observed.keyVersion) {
    fail('MATERIAL_STALE');
  }
  return { observation: observed, revision: record.revision, decision };
}

/** Appends one decision and gates the effect on the value the real append itself returned. */
function appendDecision(captured: Captured, observed: Observation, state: State, kind: 'attempt'
  | 'policy'): void {
  const { ledger, context: auditContext, components } = captured.fixed.audit;
  const pinned = captured.fixed.policy;
  const base = {
    version: 1 as const,
    operation: 'USE' as const,
    outcome: 'ALLOWED' as const,
    occurredAt: attempt(() => new Date(observed.now).toISOString()),
    bundle: { policy: pinned.policy, components },
    correlationRef: captured.fixed.mappingRef,
  };
  const draft = kind === 'attempt'
    ? { ...base, kind: 'AUTHORIZATION_ATTEMPT' as const, reason: 'RESOLUTION_AUTHORIZED' as const,
      entityRef: captured.fixed.mappingRef, interactionRef: pinned.interactionRef,
      classification: { semanticType: pinned.classification.semanticType,
        sensitivity: pinned.classification.sensitivity } }
    : { ...base, kind: 'POLICY_DECISION' as const, reason: 'POLICY_ALLOWED' as const,
      candidateRef: pinned.candidateRef,
      decision: { state: state.decision.state, treatment: state.decision.treatment,
        digest: state.decision.decisionRef ?? '0'.repeat(64) } };
  const appended = attempt(() => appendAuditEvent(ledger, draft, auditContext));
  const gate = attempt(() => gateHighRiskEffect(appended));
  if (!gate.permitted) fail('AUDIT_REFUSED');
}

/** The whole ordered path. Every owned byte buffer is overwritten in the `finally` below. */
async function run(fixed: FixedBindings): Promise<MappingUseResult> {
  const captured = capture(fixed);
  const owned: Uint8Array[] = [];
  try {
    const observed = observe(captured);
    const record = liveRecord(captured, observed.now);
    authorize(captured, observed, record);
    const decision = selectPolicy(captured, observed);
    bindAuditActor(captured, observed);

    const material = await loadMaterial(captured, owned);
    let state = recheck(captured, material, { observation: observed, revision: record.revision,
      decision });

    appendDecision(captured, state.observation, state, 'attempt');
    state = recheck(captured, material, state);
    appendDecision(captured, state.observation, state, 'policy');
    state = recheck(captured, material, state);

    // ---- Sealed effect segment. No await, no host property lookup and no dynamic function lookup
    // from here to the backend call: every value below was established before the last guard. ----
    const { tenantId, projectId } = captured.fixed.scope;
    const scope = Object.freeze({ tenantId, projectId, entityId: captured.fixed.entityId,
      classification: captured.fixed.policy.classification.semanticType,
      mappingRevision: String(state.revision), keyVersion: material.keyVersion });
    const { envelope, key } = material;
    const { lookup, receiver } = captured;
    const opened = openMappingPayload({ scope, envelope, key });
    if (opened.status !== 'OPENED') fail('OPEN_REFUSED');
    const plaintext = opened.plaintext;
    owned.push(plaintext);
    const outcome = lookup.call(receiver, plaintext);
    if (outcome === true) return USED;
    if (outcome === false) return NOT_FOUND;
    return fail('BACKEND_CONTRACT');
  } finally {
    for (const buffer of owned) buffer.fill(0);
    owned.length = 0;
  }
}