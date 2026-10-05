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
 *   1. bind every callback function and its receiver once, at construction. The backend object is
 *      bound there with its `lookup` method, so a method re-pointed, swapped or re-targeted
 *      afterwards is never invoked, and a host callback method runs with the host as its receiver;
 *   2. read the current coherent authority; require the bound scope;
 *   3. require the audit substrate's recorded actor to be this authenticated subject, and capture the
 *      owned immutable audit identity: the trusted context's actor is read once into a frozen snapshot
 *      congruent with the authenticated subject, and the appends below are handed that snapshot rather
 *      than the host's live actor;
 *   4. require an actual `SELECTED`/`KEEP` decision from `decidePolicy` for `USE` over the pinned
 *      bundle;
 *   5. read the real registry `current` and require `FOUND` and `ACTIVE`;
 *   6. require an actual `AUTHORIZED` decision from `authorizeMappingOperation` for `USE`. A refusal
 *      at either of these two - and only one that names its own class - records one privacy-safe
 *      `DENIED` decision before it is returned, which is the whole of the refusal evidence below;
 *   7. load the sealed material and the DEK into owned copies. Every authority answer and the
 *      material answer may be a promise and is awaited before it is read, and no plaintext exists at
 *      any of those awaits;
 *   8. after that callback, and after **every** later external callback, re-observe the coherent
 *      authority, require the live audit actor to still be the captured one, rerun the real policy
 *      over the pinned bundle and require the same decision reference, re-read the real registry,
 *      reauthorize on the claim that read reduced to owned values, and require an unchanged revision
 *      and key version and congruence with the actor, scope, classification and destination already
 *      recorded;
 *   9. record the authorization attempt and the policy decision through the real
 *      `appendAuditEvent`, gating each one on `gateHighRiskEffect` applied to the value that
 *      `appendAuditEvent` itself returned, then re-observe again;
 *  10. the last answer this call awaits is one more authority observation. From the continuation
 *      that reads it to the effect there is no await at all: that one continuation runs the whole
 *      final guard and the effect itself, so no queued revocation, no late host property read and no
 *      dynamic function lookup can land between the guard and the opener or the backend. Every
 *      remaining host-owned read is ordered before the last one, which is the real registry read on
 *      the captured `current`, and captured classification primitives and one captured `Reflect.apply`
 *      feed the real `openMappingPayload` on an independently established expected AAD, with the
 *      `lookup` binding captured at construction invoked on the backend object bound at construction;
 *  11. only a primitive boolean from that backend becomes `USED` or `NOT_FOUND`. Every owned byte
 *      buffer - each envelope copy, the DEK copy and the recovered plaintext - is enrolled the
 *      moment it comes into existence and overwritten in one `finally` on the success path and on
 *      every exceptional path, including a copy interrupted by a throwing byte read.
 *
 * The order inside steps 2-6 and inside every recheck is deliberate, and it is one rule: the
 * authority answer, the live audit actor, the pinned policy bundle and the registry read are all
 * host-owned reads, so they happen as early as each guard needs them and the fresh registry read is
 * the **last** host-owned read of the call. Everything after it - the authorization, the material
 * congruence, the effect scope - reads only values this module already owns.
 *
 * Refusal vocabulary. Every internal refusal - a refused registry read, a denied authorization, a
 * `BLOCK` or `HELD` policy decision, an absent audit record, a superseded revision, a rotated key, an
 * expired instant, a changed actor or route, an opaque hostile callback, a reentrant or overlapping
 * call, or an opener refusal - is one fixed `WITHHELD`. The internal reason never reaches the caller.
 * `FAILED` is reserved for the one thing a refusal cannot describe: the sealed effect segment was
 * reached and could not be completed, which is an opener or a backend that threw. A reflection,
 * enumeration or index fault out of any host value is a `WITHHELD` like any other guard refusal,
 * never an escape and never a `FAILED`; that holds inside the sealed segment too, because its whole
 * final guard is normalized as well and only the opener and the backend themselves are not. A
 * backend that answers with anything but a primitive boolean is a `WITHHELD` too: a claim is never
 * bought by a malformed answer. Neither `WITHHELD` nor `FAILED` ever performs, claims or reports a
 * `USE`.
 *
 * Refusal evidence. Two refusal classes, and only those two, leave a record, and only where this call
 * has already established the actor: the real registry reports the bound record as no longer live or
 * no longer `ACTIVE` (`LIFECYCLE_DENIED`), and the real authorization seam reports no grant at all or
 * a grant that has already expired (`RESOLUTION_DENIED`). Each is recorded by the same real
 * `appendAuditEvent`, with the same owned identity, the same frozen context and the same pinned
 * bundle identity the accepted path uses, as one `AUTHORIZATION_ATTEMPT` / `USE` / `DENIED` event, and
 * each costs no material load and no backend call, because both guards run before any sealed byte
 * exists. Everything else records nothing: an unreadable or foreign authority, a policy `BLOCK` or
 * `HELD`, a grant that is misbound rather than absent or expired, an audit actor that is not the
 * authenticated subject, a host fault, and every refusal raised after the material load. The decision
 * is taken where the refusal is raised, from that refusal's own fixed class - there is no catch-all
 * logger, no inferred identity and no reconstructed draft, so a malformed, foreign or trapped value
 * can never be filed as evidence about somebody. A record never changes a code: the call is already
 * `WITHHELD`, no effect follows a denial, and the appended result is deliberately not read, so a
 * ledger that cannot commit leaves the same `WITHHELD`, no exception and no effect.
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
 *   returned, in this process, un-cached and un-reconstructed. This module records the two `ALLOWED`
 *   decisions of the accepted path and one `DENIED` decision for an attributable refusal, and
 *   nothing else; privacy-safe evidence for every other refusal stays the integrating host's
 *   obligation.
 * - **Not zeroization.** Overwriting owned buffers in JavaScript is best-effort hygiene: copies held
 *   inside native crypto, garbage-collected buffers and swapped pages are not covered.
 * - **Not a protected-egress safety claim.** A `USE` here spends plaintext on one local synchronous
 *   resource; no bytes leave this process. Nothing here is a KMS/HSM binding, a production vault or a
 *   substitute for human review of a proposed design.
 */
import { TRUST_LEVELS } from './classification.js';
import type { Classification, Trust } from './classification.js';
import { AUDIT_BUNDLE_COMPONENTS, appendAuditEvent, gateHighRiskEffect } from './audit-ledger.js';
import type { AuditBundleComponent, AuditLedger, AuditReasonCode, AuditTrustedContext } from './audit-ledger.js';
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
 * The private synchronous resource. One primitive boolean in, nothing out. The object **and** its
 * `lookup` method are bound at construction, and a `lookup` installed afterwards is never invoked.
 *
 * **Host obligation, mandatory.** The backend must not retain, copy, log or forward the bytes it is
 * handed: it decides and returns. It must not keep a reference to that buffer, must not store its
 * contents anywhere, must not write them to a log, a metric, a trace or an error message, and must
 * not pass them on to another party, process or transport. The recovered plaintext exists here for
 * the duration of one call and this module overwrites its own copy in the same continuation, in a
 * `finally`, whether the call returned `true` or `false`; a copy the backend kept survives that.
 *
 * That obligation is on the host, not something this module can verify, and this interface makes no
 * custody or zeroization claim: nothing here can observe what the backend did with the buffer after
 * it returned, cannot reach a copy it kept, and cannot force native memory to be zeroed. The
 * executor states the duty and, in the limits above, that it is unproven.
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
/**
 * The two denial classes that are recorded. Both are members of the ledger's own closed reason
 * vocabulary, so a record needs no new schema, no new kind, no new operation and no new permission:
 * `AUTHORIZATION_ATTEMPT` / `USE` / `DENIED` is already a legal event with this exact shape.
 */
type DenialEvidence = Extract<AuditReasonCode, 'RESOLUTION_DENIED' | 'LIFECYCLE_DENIED'>;
const REFUSAL_BRAND: unique symbol = Symbol('hylja.mapping-use.refusal');

class Refusal extends Error {
  constructor(readonly code: Denial, readonly evidence?: DenialEvidence) { super(code); this.name = 'Refusal'; }
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
function fail(code: Denial, evidence?: DenialEvidence): never { throw new Refusal(code, evidence); }
/**
 * The refusal's own recorded class, read under a guard. A value that is not this module's branded
 * refusal, whose class is not one of the two fixed codes, or whose read traps, yields no class - so
 * the recording decision below can never be driven by a caller-supplied value.
 */
function denialClass(error: unknown): DenialEvidence | undefined {
  try {
    if (error === null || typeof error !== 'object') return undefined;
    const candidate = error as { brand?: unknown; evidence?: unknown };
    if (candidate.brand !== REFUSAL_BRAND) return undefined;
    const evidence = candidate.evidence;
    if (evidence !== 'RESOLUTION_DENIED' && evidence !== 'LIFECYCLE_DENIED') return undefined;
    return evidence;
  } catch { return undefined; }
}
/** Runs one synchronous call site. A throwing host callback is a refusal, never an escaped exception. */
function attempt<T>(invoke: () => T): T {
  try { return invoke(); } catch (error) { if (isRefusal(error)) throw error; fail('HOST_FAULT'); }
}

/**
 * One captured `Reflect.apply`, read once at module load. `fn.call(recv, x)` and `fn.apply(recv, xs)`
 * resolve a mutable property of the function object at the moment they run, which is exactly the
 * dynamic lookup the sealed effect segment forbids; this reference cannot be re-pointed afterwards.
 */
const REFLECT_APPLY = Reflect.apply;
/** One captured opener reference. The effect segment invokes this binding, never a lookup. */
const OPEN_PAYLOAD = openMappingPayload;
/** Invokes one captured function on its own receiver. No `.call`, no `.apply`, no property lookup. */
function invoke<T>(fn: (...args: never[]) => T, thisArg: unknown, args: readonly unknown[]): T {
  return REFLECT_APPLY(fn, thisArg, args);
}
/**
 * One host answer, awaited: a value or a promise, because a callback that is documented as possibly
 * asynchronous is awaited before anything reads it. A throw and a rejection are the same refusal, so
 * no rejected promise escapes this module and no promise outlives the call that awaited it.
 */
async function ask<T>(call: () => T | PromiseLike<T>): Promise<T> {
  try { return await call(); } catch (error) { if (isRefusal(error)) throw error; fail('HOST_FAULT'); }
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
  // The nested identities are normalized here too, not carried by reference: the authorization seam
  // reads them later, and a grant whose inner objects stayed host-owned would be a host property read
  // inside the sealed effect segment.
  return Object.freeze({ version: v.version as 1, mappingRef: text(v.mappingRef, 256),
    revision: v.revision as number, principal: subject(v.principal), context: context(v.context),
    destination: destination(v.destination),
    operation: v.operation as TrustedMappingGrant['operation'], expiresAt: v.expiresAt as number });
}
function equal(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}
/**
 * One owned, immutable copy of the audit actor identity. The ledger takes the actor from the trusted
 * context, so the executor owns the value it hands over: a host that mutates its own actor object
 * mid-flight cannot re-attribute a decision this executor recorded.
 *
 * The **whole** read is normalized as one guard, not just the property access: the prototype check,
 * the key enumeration and the descriptor reads that `fields` performs are inside that guard too.
 * This function runs again inside the sealed effect segment, where the live actor is the last
 * host-owned read before the fresh registry read, so a trap raised by a hostile actor object there
 * would otherwise leave the segment as an unbranded exception and be reported as a reached effect.
 * A trap anywhere in the read is one refusal like any other, never an escape.
 */
interface AuditActor { readonly principalId: string; readonly workloadId?: string }
function auditActor(value: AuditTrustedContext): AuditActor {
  return attempt((): AuditActor => {
    const v = fields(value.actor, ['principalId'], ['workloadId']);
    return Object.freeze({ principalId: text(v.principalId, 256),
      ...(Object.hasOwn(v, 'workloadId') ? { workloadId: text(v.workloadId, 256) } : {}) });
  });
}

/** One owned copy of one byte source. The declared length is validated before any allocation. */
function snapshotBytes(value: unknown, maximum: number): Uint8Array {
  if (!(value instanceof Uint8Array)) fail('MATERIAL_INVALID');
  const declared: unknown = value.byteLength;
  if (typeof declared !== 'number' || !Number.isSafeInteger(declared) || declared < 0 ||
    declared > maximum) fail('MATERIAL_INVALID');
  const copy = new Uint8Array(declared);
  try {
    for (let index = 0; index < declared; index += 1) {
      const byte: unknown = value[index];
      if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 0xff) {
        copy.fill(0);
        fail('MATERIAL_INVALID');
      }
      copy[index] = byte;
    }
  } catch (error) {
    // A byte source that throws mid-copy - a trapping proxy, a torn buffer - leaves a partial copy
    // behind. That copy is already owned, so it is overwritten here rather than abandoned; a
    // hostile source never gets an uncleaned DEK or envelope buffer and never an escaped exception.
    copy.fill(0);
    if (isRefusal(error)) throw error;
    fail('MATERIAL_INVALID');
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
  /** The validated host object itself, kept only as the receiver for its own callback methods. */
  host: object;
  registry: MappingMetadataRegistry; readCurrent: MappingMetadataRegistry['current'];
  audit: AuditBinding; policy: PolicyBinding;
  /** The backend object, kept as the receiver, and the one `lookup` binding read here, once. */
  backend: MappingUseBackend; lookup: (identifier: Uint8Array) => boolean;
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
    // The private resource's method is bound HERE, once, on the backend object bound above, and the
    // effect segment invokes this binding for the life of the executor. A host that re-points
    // `backend.lookup` after construction has replaced a property this module no longer reads, so
    // the replacement is never invoked on the recovered bytes and the binding cannot be swapped at
    // any later point in the call either.
    const lookup = backend.lookup;
    if (typeof lookup !== 'function') fail('INVALID_AUTHORITY');
    const authority = host.authority as () => unknown;
    const material = host.material as () => unknown;
    return Object.freeze({ mappingRef: text(host.mappingRef, 256), scope, entityId,
      host: hostValue as object,
      registry, readCurrent: registry.current,
      audit: Object.freeze({ ledger, context: contextValue, components }),
      policy, backend, lookup, authority, material });
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
 * pinned policy handoff, the backend object and its `lookup` method. It freezes **no** authority: the
 * identity, context, route, grant, key version and clock are re-read by every `use()`. A second
 * `use()` that overlaps an unfinished one is refused immediately, before any host call, because an
 * overlapping effect on one reference has no coherent snapshot to spend.
 */
export function createBoundMappingUse(hostValue: unknown): BoundMappingUse {
  const fixed = bindings(hostValue);
  let busy = false;
  /** The caller supplies nothing. Reentry is refused synchronously, before the first await. */
  const use = async (): Promise<MappingUseResult> => {
    if (busy) return WITHHELD;
    busy = true;
    try {
      return await prepare(fixed);
    } catch (error) {
      // A refusal is `WITHHELD`. Anything else escaped the sealed effect segment itself - an opener
      // or a backend that threw is the honest case - so the effect was reached and never completed.
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
  /** The host object, and therefore the receiver every one of its own callback methods runs with. */
  host: object;
  authority: () => unknown;
  material: () => unknown;
  /** The backend object, kept as the receiver for the `lookup` binding fixed at construction. */
  receiver: MappingUseBackend;
  /** The classification primitives this call governs, read once. The host object is not re-read. */
  classification: { readonly semanticType: string; readonly sensitivity: string };
  /** The owned immutable audit identity, and the frozen context the append is actually handed. */
  actor: AuditActor;
  auditContext: AuditTrustedContext;
}
interface Observation {
  now: number; subject: WorkloadSubject; context: RequestContext; destination: Destination;
  /** An authority answer that carries no grant at all: absent is a fact, not a malformed value, and
   *  it reaches the real authorization seam as its own `NO_GRANT` row rather than as a boundary
   *  refusal that no seam ever saw. */
  grant: TrustedMappingGrant | undefined; keyVersion: string;
}
interface Material {
  envelope: MappingSealedEnvelope;
  key: Uint8Array;
  revision: string;
  keyVersion: string;
}
interface State { observation: Observation; revision: number; decision: PolicyDecision }

/**
 * Carries this call's own view of the fixed bindings: the host callbacks run with the host as their
 * receiver, and the audit identity, the classification primitives and the frozen context the append
 * is handed are read here. The backend's `lookup` is **not** read here: it was bound once at
 * construction, so this module reads no property of the host or of its backend again at any later
 * point, and in particular none between the last guard below and the effect.
 */
function capture(fixed: FixedBindings): Captured {
  const classification = fixed.policy.classification;
  const actor = auditActor(fixed.audit.context);
  return Object.freeze({
    fixed,
    host: fixed.host,
    authority: attempt(() => fixed.authority),
    material: attempt(() => fixed.material),
    receiver: fixed.backend,
    classification: Object.freeze({
      semanticType: attempt(() => text(classification.semanticType, 64)),
      sensitivity: attempt(() => text(classification.sensitivity, 64)) }),
    actor,
    auditContext: Object.freeze({ ...fixed.audit.context, actor }),
  });
}

/**
 * One coherent authority observation, normalized once. The bound scope is a structural gate. The
 * answer may be a promise because a host callback is documented as possibly asynchronous: it is
 * awaited here, before anything reads it, and never outside the call that awaited it.
 */
async function observe(captured: Captured): Promise<Observation> {
  const raw = await ask(() => invoke(captured.authority, captured.host, []));
  if (raw === null || typeof raw !== 'object') fail('INVALID_AUTHORITY');
  const v = fields(raw, ['version', 'subject', 'context', 'destination', 'keyVersion', 'now'],
    ['grant']);
  if (v.version !== 1) fail('INVALID_AUTHORITY');
  const observed = context(v.context);
  const scope = captured.fixed.scope;
  if (observed.tenantId !== scope.tenantId || observed.projectId !== scope.projectId ||
    observed.sessionId !== scope.sessionId) fail('SCOPE_MISMATCH');
  const keyVersion = text(v.keyVersion, 48);
  if (!KEY_VERSION.test(keyVersion)) fail('INVALID_AUTHORITY');
  // An omitted grant, and a grant carried as the absent value, are both handed on as absent: the
  // authorization seam owns that row and denies it as `NO_GRANT`. A grant that is present but
  // structurally wrong is still this boundary's refusal - `WITHHELD`, with no evidence and no actor.
  const supplied = Object.hasOwn(v, 'grant') && v.grant !== undefined ? grant(v.grant) : undefined;
  return Object.freeze({ now: instant(v.now), subject: subject(v.subject), context: observed,
    destination: destination(v.destination), grant: supplied, keyVersion });
}

/**
 * The registry record reduced to the five values every guard below uses. A real registry read yields
 * this owned, frozen claim inside the same synchronous step that called the host: the captured
 * `current` runs on the captured registry, and nothing in the sealed effect segment reads a property
 * of the object it returned.
 */
interface RecordClaim {
  readonly mappingRef: string;
  readonly scope: { readonly tenantId: string; readonly projectId?: string; readonly sessionId: string };
  readonly lifecycle: 'ACTIVE';
  readonly revision: number;
  readonly expiresAt: number;
}

/** A real registry read. Only a `FOUND`, `ACTIVE` record at a live instant reaches anything else. */
function liveRecord(captured: Captured, now: number): RecordClaim {
  const { registry, readCurrent, mappingRef, scope } = captured.fixed;
  return attempt(() => {
    const found = invoke(readCurrent, registry, [{ version: 1, mappingRef,
      scope: { tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId } },
    { now }]);
    if (found === null || typeof found !== 'object') fail('NOT_CURRENT');
    if (found.state !== 'FOUND') {
      // The registry's own reason is what makes this refusal attributable, so it is read here rather
      // than inferred: only a record this registry holds and reports as no longer live is the
      // lifecycle denial this call records. An unknown reference, a refused read and a trap all
      // record nothing, because none of them is evidence about a record that existed.
      fail('NOT_CURRENT', found.reason === 'NOT_LIVE' ? 'LIFECYCLE_DENIED' : undefined);
    }
    const record: MappingMetadataRecord = found.metadata;
    if (record === null || typeof record !== 'object' || record.state !== 'ACTIVE') {
      fail('NOT_ACTIVE', 'LIFECYCLE_DENIED');
    }
    const recordScope = fields(record.scope, ['tenantId', 'projectId', 'sessionId']);
    const claim: RecordClaim = Object.freeze({ mappingRef: text(record.mappingRef, 256),
      scope: Object.freeze({ tenantId: text(recordScope.tenantId, 256),
        ...(Object.hasOwn(recordScope, 'projectId') ? { projectId: text(recordScope.projectId, 256) }
          : {}),
        sessionId: text(recordScope.sessionId, 256) }),
      lifecycle: 'ACTIVE', revision: instant(record.revision), expiresAt: instant(record.expiresAt) });
    // The record the registry returned must be this executor's own record in the bound scope, or the
    // read is not the current-record seam this call bound at construction.
    if (claim.mappingRef !== mappingRef || !equal(claim.scope,
      { tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId })) {
      fail('SCOPE_MISMATCH');
    }
    return claim;
  });
}

/** The real purpose-bound authorization seam, for `USE` only, on the grant this observation read. */
function authorize(captured: Captured, observed: Observation, claim: RecordClaim): void {
  const { mappingRef } = captured.fixed;
  const { semanticType, sensitivity } = captured.classification;
  // The decision and its reason are read inside one guard, so a trap on a hostile answer is a refusal
  // like any other rather than an escape - and, inside the sealed segment, rather than an exception
  // that would be mistaken for a reached effect.
  const denial = attempt((): 'AUTHORIZED' | DenialEvidence | undefined => {
    const decision = authorizeMappingOperation(
      { version: 1, mappingRef, subject: { ...observed.subject }, context: { ...observed.context },
        destination: { ...observed.destination }, operation: 'USE' },
      { authenticated: { subject: { ...observed.subject }, context: { ...observed.context } },
        observed: { destination: { ...observed.destination } } },
      { version: 1, mappingRef: claim.mappingRef, scope: { ...claim.scope },
        lifecycle: claim.lifecycle, semanticType, sensitivity,
        revision: claim.revision, expiresAt: claim.expiresAt },
      observed.grant, { now: observed.now });
    if (decision.state === 'AUTHORIZED') return 'AUTHORIZED';
    // Only an absent grant and an expired grant are recorded. Every other denial this seam can return
    // - a grant for another operation, revision, principal, destination or purpose - is a refusal the
    // host's own misbound authority produced, and it records nothing.
    return decision.reason === 'NO_GRANT' || decision.reason === 'GRANT_EXPIRED'
      ? 'RESOLUTION_DENIED' : undefined;
  });
  if (denial !== 'AUTHORIZED') fail('UNAUTHORIZED', denial);
}

/**
 * The two guards that may leave evidence behind, in the same order they always run, and the only
 * place a refusal here is recorded.
 *
 * The record is written between the guard that refused and the refusal that is rethrown, at the stage
 * where this call has already established the scope, the authenticated subject and the audit identity
 * congruent with it - so there is no identity to infer and nothing to reconstruct. Both guards run
 * before any material is loaded, so a record here costs no sealed read, no recovered byte and no
 * backend call. Everything refused elsewhere in this call records nothing.
 */
function attribute(captured: Captured, observed: Observation): RecordClaim {
  let claim: RecordClaim;
  try {
    claim = liveRecord(captured, observed.now);
  } catch (error) {
    deny(captured, observed, error);
    throw error;
  }
  try {
    authorize(captured, observed, claim);
  } catch (error) {
    deny(captured, observed, error);
    throw error;
  }
  return claim;
}

/**
 * Records one privacy-safe denial for the refusal that is already being raised, and only when that
 * refusal carries its own fixed class. The error is not caught and re-classified, and nothing is
 * inferred from it: a value that is not this module's branded refusal, or one that names no class,
 * writes nothing and is rethrown untouched.
 *
 * The draft carries the same pseudonymized reference the accepted path's first decision carries, the
 * same pinned classification primitives, the same frozen context holding the owned actor, and the
 * same pinned bundle identity. The ledger takes the actor from that context and pseudonymizes every
 * reference, so no original, no raw reference, no reason value from any host and no exception text
 * is reachable from the recorded event.
 *
 * The appended result is deliberately not read: this call is already refused, no effect depends on
 * the record, and `WITHHELD` is the honest code for a substrate that could not commit it.
 */
function deny(captured: Captured, observed: Observation, error: unknown): void {
  const denial = denialClass(error);
  if (denial === undefined) return;
  const { ledger, components } = captured.fixed.audit;
  const pinned = captured.fixed.policy;
  const draft = {
    version: 1 as const,
    kind: 'AUTHORIZATION_ATTEMPT' as const,
    operation: 'USE' as const,
    outcome: 'DENIED' as const,
    reason: denial,
    occurredAt: attempt(() => new Date(observed.now).toISOString()),
    bundle: { policy: pinned.policy, components },
    correlationRef: captured.fixed.mappingRef,
    entityRef: captured.fixed.mappingRef,
    interactionRef: pinned.interactionRef,
    classification: { semanticType: captured.classification.semanticType,
      sensitivity: captured.classification.sensitivity },
  };
  attempt(() => { appendAuditEvent(ledger, draft, captured.auditContext); });
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
 * The recorded actor must be the authenticated subject, and must still be that actor. The ledger
 * takes the actor from its trusted context and never from a draft, so the executor hands the append
 * its own frozen snapshot of that actor; the host's live actor is re-read at every recheck and a
 * host that swaps its actor mid-flight is refused before anything it would misattribute is written.
 */
function bindAuditActor(captured: Captured, observed: Observation): void {
  const actor = captured.actor;
  if (actor.principalId !== observed.subject.principalId ||
    (actor.workloadId ?? null) !== observed.subject.workloadId) fail('AUDIT_ACTOR');
  const live = auditActor(captured.fixed.audit.context);
  if (live.principalId !== actor.principalId || (live.workloadId ?? null) !== (actor.workloadId ?? null)) {
    fail('AUDIT_ACTOR');
  }
}

/** Loads the sealed record and the DEK into owned copies. This is the material awaiting boundary. */
async function loadMaterial(captured: Captured, owned: Uint8Array[]): Promise<Material> {
  const raw = await ask(() => invoke(captured.material, captured.host, []));
  const v = fields(raw, ['version', 'envelope', 'key', 'mappingRevision', 'keyVersion']);
  if (v.version !== 1) fail('MATERIAL_INVALID');
  const revision = text(v.mappingRevision, 12);
  const keyVersion = text(v.keyVersion, 48);
  if (!REVISION.test(revision) || !KEY_VERSION.test(keyVersion)) fail('MATERIAL_INVALID');
  const envelope = fields(v.envelope, ['version', 'nonce', 'ciphertext', 'tag']);
  if (envelope.version !== 1) fail('MATERIAL_INVALID');
  // Each copy is enrolled in cleanup the moment it exists, never after the whole load succeeds: a
  // failure on a later copy cannot abandon the DEK or envelope bytes an earlier copy already holds.
  const nonce = snapshotBytes(envelope.nonce, MAPPING_AEAD_LIMITS.nonceBytes);
  owned.push(nonce);
  const tag = snapshotBytes(envelope.tag, MAPPING_AEAD_LIMITS.tagBytes);
  owned.push(tag);
  const ciphertext = snapshotBytes(envelope.ciphertext, MAPPING_AEAD_LIMITS.ciphertextBytes);
  owned.push(ciphertext);
  if (ciphertext.byteLength === 0) fail('MATERIAL_INVALID');
  const key = snapshotBytes(v.key, MAPPING_AEAD_LIMITS.keyBytes);
  owned.push(key);
  return { envelope: Object.freeze({ version: 1, nonce, ciphertext, tag }), key,
    revision, keyVersion };
}

/** What a fresh observation must still match. Pure over values this module already owns. */
function congruent(observed: Observation, previous: State): void {
  if (observed.now < previous.observation.now) fail('CLOCK');
  if (!equal(observed.subject, previous.observation.subject) ||
    !equal(observed.context, previous.observation.context) ||
    !equal(observed.destination, previous.observation.destination)) fail('NOT_CONGRUENT');
  if (observed.keyVersion !== previous.observation.keyVersion) fail('MATERIAL_STALE');
}

/**
 * The recheck itself, with no await in it: the whole guard set one fresh observation must pass. The
 * ordering is deliberate and is the reason the last guard is the fresh registry read. The live audit
 * actor and the pinned policy bundle are host-owned objects and are read first; the registry read
 * follows, and after it every remaining step reads only owned copies.
 */
function verified(captured: Captured, material: Material, previous: State,
  observed: Observation): State {
  congruent(observed, previous);
  bindAuditActor(captured, observed);
  const decision = selectPolicy(captured, observed);
  if (decision.decisionRef !== previous.decision.decisionRef) fail('NOT_CONGRUENT');
  const claim = liveRecord(captured, observed.now);
  if (claim.revision !== previous.revision) fail('SUPERSEDED');
  authorize(captured, observed, claim);
  if (material.revision !== String(claim.revision) ||
    material.keyVersion !== observed.keyVersion) fail('MATERIAL_STALE');
  return { observation: observed, revision: claim.revision, decision };
}

/**
 * The recheck that runs after every external callback: one fresh observation, then the whole guard
 * set above with nothing suspended between the observation and the answer.
 */
async function recheck(captured: Captured, material: Material, previous: State): Promise<State> {
  return verified(captured, material, previous, await observe(captured));
}

/** Appends one decision and gates the effect on the value the real append itself returned. */
function appendDecision(captured: Captured, observed: Observation, state: State, kind: 'attempt'
  | 'policy'): void {
  const { ledger, components } = captured.fixed.audit;
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
      classification: { semanticType: captured.classification.semanticType,
        sensitivity: captured.classification.sensitivity } }
    : { ...base, kind: 'POLICY_DECISION' as const, reason: 'POLICY_ALLOWED' as const,
      candidateRef: pinned.candidateRef,
      decision: { state: state.decision.state, treatment: state.decision.treatment,
        digest: state.decision.decisionRef ?? '0'.repeat(64) } };
  const appended = attempt(() => appendAuditEvent(ledger, draft, captured.auditContext));
  const gate = attempt(() => gateHighRiskEffect(appended));
  if (!gate.permitted) fail('AUDIT_REFUSED');
}

/**
 * The whole ordered path, and the sealed effect segment at its end.
 *
 * The last answer this call awaits is the final authority observation. Everything below that line is
 * one synchronous continuation: `sealed` runs the entire final guard and then the effect, with no
 * await, no host property lookup and no dynamic function lookup between them, and the plaintext the
 * backend is handed is enrolled in the cleanup list and overwritten in the `finally` below before
 * this function's promise is even settled. A revocation queued by any host callback can therefore no
 * longer land between the fresh registry read and the opener or the backend.
 *
 * A reflection, enumeration or index fault out of a host value anywhere in here is one refusal -
 * `WITHHELD` - and never an escaped exception that would be reported as a reached effect.
 */
async function prepare(fixed: FixedBindings): Promise<MappingUseResult> {
  const owned: Uint8Array[] = [];
  let sealing = false;
  try {
    const captured = capture(fixed);
    const observed = await observe(captured);
    bindAuditActor(captured, observed);
    const decision = selectPolicy(captured, observed);
    const claim = attribute(captured, observed);

    const material = await loadMaterial(captured, owned);
    let state: State = { observation: observed, revision: claim.revision, decision };
    state = await recheck(captured, material, state);

    appendDecision(captured, state.observation, state, 'attempt');
    state = await recheck(captured, material, state);
    appendDecision(captured, state.observation, state, 'policy');
    // The last suspension of this call. The continuation that resumes here is already the sealed one.
    const final = await observe(captured);
    sealing = true;
    return sealed(captured, material, state, final, owned);
  } catch (error) {
    // A throw raised inside the sealed segment is a reached effect that could not be completed, so
    // it escapes to the caller of `use()` as `FAILED` instead of being downgraded to a refusal.
    if (sealing) throw error;
    if (isRefusal(error)) throw error;
    return fail('HOST_FAULT');
  } finally {
    // Every owned byte buffer - each envelope copy, the DEK copy and the recovered plaintext - is
    // overwritten here, on the success path and on every exceptional path, in the same continuation
    // that spent or refused the effect.
    for (const buffer of owned) buffer.fill(0);
    owned.length = 0;
  }
}

/**
 * The sealed effect segment: the final guard and the effect, in the one continuation the last
 * awaited answer resumed into. `verified` is the same guard set every recheck runs, with its own
 * fresh registry read; `spend` follows it immediately. The scope, the classification primitive, the
 * invocation mechanics and both buffers were all established while guards could still run, and the
 * only host object touched from here on is the backend, through the `lookup` binding captured at
 * construction on its captured receiver.
 */
function sealed(captured: Captured, material: Material, previous: State, observed: Observation,
  owned: Uint8Array[]): MappingUseResult {
  const state = verified(captured, material, previous, observed);
  const { tenantId, projectId } = captured.fixed.scope;
  const scope = Object.freeze({ tenantId, projectId, entityId: captured.fixed.entityId,
    classification: captured.classification.semanticType,
    mappingRevision: String(state.revision), keyVersion: material.keyVersion });
  const { envelope, key } = material;
  const opened = OPEN_PAYLOAD({ scope, envelope, key });
  if (opened.status !== 'OPENED') fail('OPEN_REFUSED');
  const plaintext = opened.plaintext;
  owned.push(plaintext);
  const outcome = invoke(captured.fixed.lookup, captured.receiver, [plaintext]);
  if (outcome === true) return USED;
  if (outcome === false) return NOT_FOUND;
  return fail('BACKEND_CONTRACT');
}