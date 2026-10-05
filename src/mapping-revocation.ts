/**
 * One bound audited revocation owner for exactly one opaque mapping reference (issue #238).
 *
 * `createBoundMappingRevocation(host)` binds one reference, one tenant/project/session scope, the
 * current-record registry, the audit substrate, one pinned administrative purpose and one pinned
 * policy identity at construction. `revoke()` takes no argument: the caller supplies no operation,
 * no reference, no revision, no authority, no grant and no effect, and receives one fixed code -
 * `REVOKED`, `UNRECORDED` or `WITHHELD` - and nothing else. There is no reference argument, no
 * enumeration, no scan and no bulk path, so this is not a mapping lookup API (decision 004).
 *
 * **Revocation authority is administrative, and independently trusted.** The authority answer is a
 * complete, closed, bound decision: it names the exact bound reference, the exact bound scope, the
 * exact current revision, the pinned administrative purpose and one closed administrative role, and
 * it expires at an instant the host clock has not reached. There is no `grant` field anywhere in the
 * accepted shape, so a `USE` grant cannot even be supplied here, and no boolean from a model, a
 * payload or a caller ever authorizes anything: the decision is the closed `ALLOW`/`DENY` value
 * inside a decision this module validates in full. This module authenticates nobody and proves no
 * host authenticity; a coherent but dishonest host is answered coherently and dishonestly.
 *
 * The fixed order inside one `revoke()` is the contract:
 *   1. bind every callback function and its receiver once, at construction: the host's `authority`
 *      method, the registry object with its `current` and `transition` methods, and the audit
 *      substrate. A method re-pointed, swapped or re-targeted afterwards is never invoked, and the
 *      host callback runs with the host as its receiver;
 *   2. observe one coherent current administrative authority; require the bound scope and the
 *      pinned administrative purpose, require the closed role and `ALLOW`, and require the pinned
 *      reference and an unexpired decision;
 *   3. require the audit substrate's recorded actor to be this authenticated administrative subject,
 *      and capture that identity as an owned immutable snapshot congruent with the ledger's;
 *   4. read the real registry `current`; require `FOUND` and `ACTIVE` and take the pinned revision
 *      from that read, so the compare-and-set is decided by the registry's own record;
 *   5. record the authorized intent through the real `appendAuditEvent` and gate it on
 *      `gateHighRiskEffect` applied to the value `appendAuditEvent` itself returned. An audit
 *      outage here withholds **before** the mutation, so nothing is revoked without evidence;
 *   6. re-observe after every external callback: the authority answer, the live audit actor and the
 *      registry read are the host-owned reads of each pass, and the fresh registry read is the last
 *      of them;
 *   7. the last answer this call awaits is the final authority observation. From the continuation
 *      that reads it, the whole final guard and the mutation run **in that same continuation**:
 *      there is no `await` at all between the last registry guard and the registry `transition`, so
 *      nothing a host callback queues can land between them;
 *   8. record the applied result through the real `appendAuditEvent` and gate it the same way. A
 *      fault here is `UNRECORDED`: the mapping stays revoked, nothing is revived, and no audited
 *      success is claimed.
 *
 * Retry and idempotency semantics are the **registry's own**, and this module adds none. The
 * registry is monotonic: the first successful call moves the record to `REVOKED` at
 * `revision + 1`, `REVOKE` on a `REVOKED` record is the reducer's idempotent repeat, and a terminal
 * entry is a tombstone that is never removed, never revived and never evicted. A later `revoke()`
 * reads `NOT_LIVE` through the real `current` seam and is refused with zero mutation, so a retry can
 * never undo, re-activate, extend or restore anything. There is no rollback, no compensating action
 * and no recovery here, and none is claimed.
 *
 * What this module is not
 * - **Not a registry, store, vault or index.** It creates no record, resolves no original, holds no
 *   mapping table, exposes no bulk lookup, makes no transaction and has no lock or transport. The
 *   registry, the audit substrate and the administrative decision are the host's, and the current
 *   record, its revision and every lifecycle transition belong to the shipped registry.
 * - **Not key custody and not key destruction.** No key, DEK, envelope or plaintext is read, copied
 *   or destroyed here: revocation is a metadata transition, and the record's cryptographic material
 *   and its custody remain host obligations this module neither performs nor claims.
 * - **Not durable audit.** The ledger is a host-owned in-memory substrate and `gateHighRiskEffect`
 *   is a pure structural check, which is exactly why the value passed to it is the one
 *   `appendAuditEvent` returned, in this process, un-cached and un-reconstructed.
 * - **Not authentication and not separation of duties enforced.** Every identity, role, purpose,
 *   clock and decision proof is a trusted obligation of the host. This module checks congruence and
 *   currentness; it cannot check that the decision really came from an authorization service.
 * - **Not the parent #18 acceptance.** Integrated lifecycle, durable encrypted storage, an
 *   authenticated service, recovery and key destruction all stay open.
 * - **Not a protected-egress claim.** No byte leaves this process and no plaintext exists here.
 */
import { AUDIT_BUNDLE_COMPONENTS, appendAuditEvent, gateHighRiskEffect } from './audit-ledger.js';
import type { AuditBundleComponent, AuditLedger, AuditTrustedContext } from './audit-ledger.js';
import type { MappingMetadataRecord, MappingMetadataRegistry } from './mapping-metadata-registry.js';
import type { WorkloadSubject } from './mapping-authorization.js';
import type { RequestContext } from './interaction-envelope.js';

/**
 * The closed outcome vocabulary. `REVOKED` is the only claim that the registry applied the
 * transition **and** that its result was recorded; `UNRECORDED` is the honest answer for a mutation
 * whose audited completion cannot be proved; `WITHHELD` claims zero mutation.
 */
export const MAPPING_REVOCATION_CODES = ['REVOKED', 'UNRECORDED', 'WITHHELD'] as const;
export type MappingRevocationCode = (typeof MAPPING_REVOCATION_CODES)[number];

/** The only thing a caller ever receives: one fixed code, no reason, no reference, no metadata. */
export interface MappingRevocationResult { readonly version: 1; readonly code: MappingRevocationCode }

/** The three closed administrative decisions. A boolean is never an accepted authority value. */
export const MAPPING_REVOCATION_DECISIONS = ['ALLOW', 'DENY'] as const;
export type MappingRevocationDecision = (typeof MAPPING_REVOCATION_DECISIONS)[number];

/**
 * The only role whose decision this owner accepts. There is no wildcard, no default role and no
 * inheritance: a `USE` workload, a model or a caller cannot answer in any accepted shape.
 */
export const MAPPING_REVOCATION_ROLES = ['MAPPING_ADMIN'] as const;
export type MappingRevocationRole = (typeof MAPPING_REVOCATION_ROLES)[number];

export interface MappingRevocationScope { tenantId: string; projectId: string; sessionId: string }

/**
 * One coherent observation of the host's current administrative authority, read fresh at every
 * observation point. The accepted shape is **closed**: there is no `grant` key, no model field and
 * no caller-authored trust label, so a `USE` grant has no place to sit in it.
 */
export interface MappingRevocationAuthority {
  version: 1;
  subject: WorkloadSubject;
  context: RequestContext;
  decision: MappingRevocationDecision;
  role: MappingRevocationRole;
  /** The exact reference this decision was issued for; a decision for another one is refused. */
  mappingRef: string;
  /** The exact scope this decision was issued for; a foreign scope never reaches the registry. */
  scope: MappingRevocationScope;
  /** The exact record revision this decision was issued against; a stale one is refused. */
  revision: number;
  /** The instant this decision stops authorizing; the host clock must not have reached it. */
  expiresAt: number;
  /** Host-owned time. A request timestamp is never read as time. */
  now: number;
}

export interface MappingRevocationAudit {
  ledger: AuditLedger;
  context: AuditTrustedContext;
  components: readonly { id: AuditBundleComponent; version: string }[];
}

/**
 * The trusted host. Host configuration, not untrusted request content; the caller never sees it.
 * `authority` is the **explicit host integration obligation**: this module owns no administrative
 * authorization seam of its own and verifies no proof, token or issuer behind that answer.
 */
export interface MappingRevocationHost {
  version: 1;
  mappingRef: string;
  scope: MappingRevocationScope;
  /** The one purpose whose administrative decision may authorize a revocation here. */
  adminPurpose: string;
  interactionRef: string;
  registry: MappingMetadataRegistry;
  audit: MappingRevocationAudit;
  /** The independently pinned control-plane policy identity recorded with every event. */
  policy: { id: string; version: string; digest: string };
  /** Current administrative authority. May return a promise; its answer must be honest. */
  authority(): unknown;
}

/** The one object an untrusted caller receives. It carries no setter, no selector and no argument. */
export interface BoundMappingRevocation { revoke(): Promise<MappingRevocationResult> }

// ---------------------------------------------------------------------------------------------
// Internal refusal vocabulary. These codes never leave this module: they steer control flow, and a
// caller sees one fixed code. `Refusal` is recognised by a module-private brand under a guard, so a
// hostile thrown proxy cannot make classification throw out of the boundary.
// ---------------------------------------------------------------------------------------------
type Denial =
  | 'REENTRY' | 'HOST_FAULT' | 'INVALID_AUTHORITY' | 'SCOPE_MISMATCH' | 'NOT_AUTHORIZED'
  | 'NOT_CURRENT' | 'NOT_ACTIVE' | 'SUPERSEDED' | 'CLOCK' | 'NOT_CONGRUENT' | 'AUDIT_ACTOR'
  | 'AUDIT_REFUSED' | 'APPLY_REFUSED';
const REFUSAL_BRAND: unique symbol = Symbol('hylja.mapping-revocation.refusal');

class Refusal extends Error {
  constructor(readonly code: Denial) { super(code); this.name = 'Refusal'; }
  readonly brand: typeof REFUSAL_BRAND = REFUSAL_BRAND;
}

/** Non-reflective and guarded: a trap while classifying degrades to `undefined`, never an escape. */
function isRefusal(error: unknown): boolean {
  try {
    if (error === null || typeof error !== 'object') return false;
    return (error as { brand?: unknown }).brand === REFUSAL_BRAND;
  } catch { return false; }
}
function fail(code: Denial): never { throw new Refusal(code); }
/** Runs one synchronous call site. A throwing host callback is a refusal, never an escaped exception. */
function attempt<T>(invoke: () => T): T {
  try { return invoke(); } catch (error) { if (isRefusal(error)) throw error; fail('HOST_FAULT'); }
}
/**
 * One captured `Reflect.apply`, read once at module load. `fn.call(recv, x)` resolves a mutable
 * property of the function object at the moment it runs, which is exactly the dynamic lookup the
 * sealed segment forbids; this reference cannot be re-pointed afterwards.
 */
const REFLECT_APPLY = Reflect.apply;
/** Invokes one captured function on its own receiver. No `.call`, no `.apply`, no property lookup. */
function invoke<T>(fn: (...args: never[]) => T, thisArg: unknown, args: readonly unknown[]): T {
  return REFLECT_APPLY(fn, thisArg, args);
}
/** One host answer, awaited: a value or a promise, so no answer is ever read half-settled. */
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
function revision(value: unknown): number {
  const parsed = instant(value);
  if (parsed < 1) fail('INVALID_AUTHORITY');
  return parsed;
}
function subject(value: unknown): WorkloadSubject {
  const v = fields(value, ['principalId', 'workloadId']);
  return { principalId: text(v.principalId, 256), workloadId: text(v.workloadId, 256) };
}
function context(value: unknown): RequestContext {
  const v = fields(value, ['tenantId', 'sessionId', 'purpose'], ['projectId']);
  return { tenantId: text(v.tenantId, 256),
    ...(Object.hasOwn(v, 'projectId') ? { projectId: text(v.projectId, 256) } : {}),
    sessionId: text(v.sessionId, 256), purpose: text(v.purpose, 256) };
}
function scopeOf(value: unknown): MappingRevocationScope {
  const v = fields(value, ['tenantId', 'projectId', 'sessionId']);
  return Object.freeze({ tenantId: text(v.tenantId, 256), projectId: text(v.projectId, 256),
    sessionId: text(v.sessionId, 256) });
}

/**
 * One owned, immutable copy of the audit actor identity. The ledger takes the actor from the trusted
 * context, so this module owns the value it hands over: a host that mutates its own actor object
 * mid-flight cannot re-attribute a revocation this module recorded.
 *
 * The **whole** read is normalized as one guard, because this runs inside the sealed segment, where
 * the live actor is the last host-owned read before the fresh registry read; a trap raised by a
 * hostile actor object there is one refusal like any other, never an escape.
 */
interface AuditActor { readonly principalId: string; readonly workloadId?: string }
function auditActor(value: AuditTrustedContext): AuditActor {
  return attempt((): AuditActor => {
    const v = fields(value.actor, ['principalId'], ['workloadId']);
    return Object.freeze({ principalId: text(v.principalId, 256),
      ...(Object.hasOwn(v, 'workloadId') ? { workloadId: text(v.workloadId, 256) } : {}) });
  });
}

const REVOKED: MappingRevocationResult = Object.freeze({ version: 1, code: 'REVOKED' } as const);
const UNRECORDED: MappingRevocationResult = Object.freeze({ version: 1, code: 'UNRECORDED' } as const);
const WITHHELD: MappingRevocationResult = Object.freeze({ version: 1, code: 'WITHHELD' } as const);

// ---------------------------------------------------------------------------------------------
// Construction-time bindings. Every one of these is host configuration: an unusable binding throws a
// fixed `TypeError` carrying no supplied value, and there is no option that weakens a gate.
// ---------------------------------------------------------------------------------------------
interface AuditBinding {
  ledger: AuditLedger;
  context: AuditTrustedContext;
  components: readonly { id: AuditBundleComponent; version: string }[];
}
interface FixedBindings {
  mappingRef: string;
  scope: MappingRevocationScope;
  adminPurpose: string;
  interactionRef: string;
  policy: { id: string; version: string; digest: string };
  /** The validated host object itself, kept only as the receiver for its own callback method. */
  host: object;
  registry: MappingMetadataRegistry;
  readCurrent: MappingMetadataRegistry['current'];
  applyTransition: MappingMetadataRegistry['transition'];
  audit: AuditBinding;
  authority: () => unknown;
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
function bindings(hostValue: unknown): FixedBindings {
  try {
    const host = fields(hostValue, ['version', 'mappingRef', 'scope', 'adminPurpose', 'interactionRef',
      'registry', 'audit', 'policy', 'authority']);
    if (host.version !== 1) fail('INVALID_AUTHORITY');
    const registry = host.registry as MappingMetadataRegistry;
    if (registry === null || typeof registry !== 'object' || registry.version !== 1 ||
      typeof registry.current !== 'function' || typeof registry.transition !== 'function' ||
      typeof host.authority !== 'function') fail('INVALID_AUTHORITY');
    const auditSource = fields(host.audit, ['ledger', 'context', 'components']);
    const ledger = auditSource.ledger as AuditLedger;
    const contextValue = auditSource.context as AuditTrustedContext;
    if (ledger === null || typeof ledger !== 'object' || ledger.version !== 1 ||
      contextValue === null || typeof contextValue !== 'object' || contextValue.version !== 1) {
      fail('INVALID_AUTHORITY');
    }
    const identity = fields(host.policy, ['id', 'version', 'digest']);
    // The registry's own methods are bound here, once. A `current` or `transition` installed on the
    // registry object after this point has replaced a property this module no longer reads, so the
    // replacement is never invoked on the sealed segment's behalf.
    const readCurrent = registry.current;
    const applyTransition = registry.transition;
    const authority = host.authority as () => unknown;
    return Object.freeze({
      mappingRef: text(host.mappingRef, 256),
      scope: scopeOf(host.scope),
      adminPurpose: text(host.adminPurpose, 256),
      interactionRef: text(host.interactionRef, 256),
      policy: Object.freeze({ id: text(identity.id, 256), version: text(identity.version, 256),
        digest: text(identity.digest, 64) }),
      host: hostValue as object,
      registry, readCurrent, applyTransition,
      audit: Object.freeze({ ledger, context: contextValue,
        components: componentsOf(auditSource.components) }),
      authority,
    });
  } catch {
    // Host configuration is either usable or it is not: one fixed `TypeError`, never the supplied
    // value and never a partial binding.
    throw new TypeError('Invalid mapping revocation host');
  }
}

/**
 * Creates the one bound revocation owner.
 *
 * Construction fixes the reference, the scope, the administrative purpose, the interaction, the
 * registry object with its `current` and `transition` methods, the audit substrate, the pinned
 * policy identity and the host's own `authority` method. It freezes **no** authority: the
 * administrative subject, decision, role, pinned revision, expiry and clock are re-read by every
 * `revoke()`. A second `revoke()` that overlaps an unfinished one is refused immediately, before any
 * host call, because an overlapping mutation on one reference has no coherent snapshot to apply.
 */
export function createBoundMappingRevocation(hostValue: unknown): BoundMappingRevocation {
  const fixed = bindings(hostValue);
  let busy = false;
  /** The caller supplies nothing. Reentry is refused synchronously, before the first await. */
  const revoke = async (): Promise<MappingRevocationResult> => {
    if (busy) return WITHHELD;
    busy = true;
    try {
      return await prepare(fixed);
    } catch {
      // Every path out of `prepare` is a refusal before the mutation segment: zero mutation, one
      // fixed code, no reason and no detail. A fault after the mutation is an explicit `UNRECORDED`
      // inside `prepare`, never an exception that reaches here.
      return WITHHELD;
    } finally {
      busy = false;
    }
  };
  return Object.freeze({ revoke });
}

// ---------------------------------------------------------------------------------------------
// The ordered revocation path.
// ---------------------------------------------------------------------------------------------
interface Captured {
  fixed: FixedBindings;
  /** The host object, and therefore the receiver its own `authority` method runs with. */
  host: object;
  authority: () => unknown;
  /** The owned immutable audit identity, and the frozen context the append is actually handed. */
  actor: AuditActor;
  auditContext: AuditTrustedContext;
}
interface Observation {
  now: number;
  subject: WorkloadSubject;
  context: RequestContext;
  decision: MappingRevocationDecision;
  revision: number;
  expiresAt: number;
}

/**
 * Carries this call's own view of the fixed bindings: the host callback runs with the host as its
 * receiver, and the audit identity and frozen context the append is handed are read here. The
 * registry's `current` and `transition` are **not** read here: they were bound once at construction,
 * so this module reads no property of the host or of its registry again at any later point, and in
 * particular none between the last guard below and the mutation.
 */
function capture(fixed: FixedBindings): Captured {
  const actor = auditActor(fixed.audit.context);
  return Object.freeze({
    fixed,
    host: fixed.host,
    authority: attempt(() => fixed.authority),
    actor,
    auditContext: Object.freeze({ ...fixed.audit.context, actor }),
  });
}

/**
 * One coherent administrative authority observation, normalized once.
 *
 * The bound scope is a structural gate and the pinned administrative purpose is a second one: a
 * decision issued for any other purpose - including the purpose a `USE` grant would carry - never
 * reaches the registry. The decision is the closed `ALLOW`/`DENY` value inside this complete shape;
 * a bare boolean, a missing field, an unknown field, a foreign role, a decision naming another
 * reference or another scope, a stale pinned revision or an expired decision is refused, and each of
 * those refusals carries no detail back.
 */
async function observe(captured: Captured): Promise<Observation> {
  const raw = await ask(() => invoke(captured.authority, captured.host, []));
  const v = fields(raw, ['version', 'subject', 'context', 'decision', 'role', 'mappingRef', 'scope',
    'revision', 'expiresAt', 'now']);
  if (v.version !== 1) fail('INVALID_AUTHORITY');
  const observed = context(v.context);
  const bound = captured.fixed.scope;
  if (observed.tenantId !== bound.tenantId || observed.projectId !== bound.projectId ||
    observed.sessionId !== bound.sessionId) fail('SCOPE_MISMATCH');
  // The purpose is bound at construction: only the administrative purpose may authorize this owner.
  if (observed.purpose !== captured.fixed.adminPurpose) fail('SCOPE_MISMATCH');
  if (text(v.mappingRef, 256) !== captured.fixed.mappingRef) fail('NOT_CONGRUENT');
  const decision = member(v.decision, MAPPING_REVOCATION_DECISIONS);
  if (member(v.role, MAPPING_REVOCATION_ROLES) === undefined) fail('INVALID_AUTHORITY');
  if (decision !== 'ALLOW') fail('NOT_AUTHORIZED');
  const now = instant(v.now);
  const expiresAt = instant(v.expiresAt);
  if (now >= expiresAt) fail('NOT_AUTHORIZED');
  return Object.freeze({ now, subject: subject(v.subject), context: observed, decision,
    revision: revision(v.revision), expiresAt });
}

/**
 * The recorded actor must be the authenticated administrative subject, and must still be that actor.
 * The ledger takes the actor from its trusted context and never from a draft, so this module hands
 * the append its own frozen snapshot of that actor; the host's live actor is re-read at every
 * recheck and a host that swaps its actor mid-flight is refused before anything it would
 * misattribute is written.
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

/**
 * A real registry read. Only a `FOUND` record reaches anything else, and only an `ACTIVE` one can be
 * revoked: a tombstone is already terminal, so a repeat call is refused with zero mutation instead
 * of claiming a second effect.
 */
function liveRecord(captured: Captured, now: number): MappingMetadataRecord {
  const { registry, readCurrent, mappingRef, scope } = captured.fixed;
  return attempt(() => {
    const found = invoke(readCurrent, registry, [{ version: 1, mappingRef,
      scope: { tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId } },
    { now }]);
    if (found === null || typeof found !== 'object' || found.state !== 'FOUND') fail('NOT_CURRENT');
    const record = found.metadata as MappingMetadataRecord;
    if (record === null || typeof record !== 'object' || record.state !== 'ACTIVE') fail('NOT_ACTIVE');
    const recordScope = fields(record.scope, ['tenantId', 'projectId', 'sessionId']);
    if (text(record.mappingRef, 256) !== mappingRef || text(recordScope.tenantId, 256) !== scope.tenantId ||
      text(recordScope.projectId, 256) !== scope.projectId ||
      text(recordScope.sessionId, 256) !== scope.sessionId) fail('SCOPE_MISMATCH');
    return record;
  });
}

/** What a fresh observation must still match. Pure over values this module already owns. */
function congruent(observed: Observation, previous: Observation): void {
  if (observed.now < previous.now) fail('CLOCK');
  if (observed.subject.principalId !== previous.subject.principalId ||
    (observed.subject.workloadId ?? null) !== (previous.subject.workloadId ?? null) ||
    observed.context.purpose !== previous.context.purpose ||
    observed.decision !== previous.decision) fail('NOT_CONGRUENT');
  if (observed.revision !== previous.revision) fail('SUPERSEDED');
}

/**
 * Appends one lifecycle event and gates on the value the real append itself returned. The `outcome`
 * and `reason` pair is the ledger's own closed vocabulary: the authorized intent before the mutation
 * and the applied administrative result after it. A refusal here is one refusal like any other.
 */
function appendLifecycle(captured: Captured, now: number, phase: 'intent' | 'applied'): void {
  const { ledger, components } = captured.fixed.audit;
  const { policy, mappingRef, interactionRef } = captured.fixed;
  const base = {
    version: 1 as const,
    kind: 'MAPPING_LIFECYCLE' as const,
    operation: 'REVOKE' as const,
    occurredAt: attempt(() => new Date(now).toISOString()),
    bundle: { policy, components },
    correlationRef: mappingRef,
    entityRef: mappingRef,
    interactionRef,
  };
  // The ledger's closed vocabulary has no separate "administrative allowed" reason, so the
  // authorized intent before the mutation is `ALLOWED`/`RESOLUTION_AUTHORIZED` and the applied
  // administrative result after it is `APPLIED`/`ADMIN_APPLIED`. No other pair is ever written.
  const draft = phase === 'applied'
    ? { ...base, outcome: 'APPLIED' as const, reason: 'ADMIN_APPLIED' as const }
    : { ...base, outcome: 'ALLOWED' as const, reason: 'RESOLUTION_AUTHORIZED' as const };
  const appended = attempt(() => appendAuditEvent(ledger, draft, captured.auditContext));
  const gate = attempt(() => gateHighRiskEffect(appended));
  if (!gate.permitted) fail('AUDIT_REFUSED');
}

/**
 * The whole ordered path, and the sealed mutation segment at its end.
 *
 * The last answer this call awaits is the final authority observation. Everything below that line is
 * one synchronous continuation: `sealed` runs the entire final guard and then the registry
 * mutation, with no await, no host property lookup and no dynamic function lookup between them.
 * Anything a host callback queues - a rotation, a deletion, a swapped record - can therefore no
 * longer land between the last registry guard and the compare-and-set.
 *
 * A reflection, enumeration or index fault out of a host value anywhere in here is one refusal -
 * `WITHHELD`, claiming zero mutation - and never an escaped exception.
 */
async function prepare(fixed: FixedBindings): Promise<MappingRevocationResult> {
  try {
    const captured = capture(fixed);
    const first = await observe(captured);
    bindAuditActor(captured, first);
    const record = liveRecord(captured, first.now);
    // The compare-and-set is pinned to the revision this call's own fresh registry read observed.
    let previous = first;
    let pinned = revision(record.revision);
    if (previous.revision !== pinned) fail('SUPERSEDED');

    // Audit outage before the mutation withholds: nothing is revoked without recorded intent.
    appendLifecycle(captured, previous.now, 'intent');

    previous = await recheck(captured, previous);
    const applied = sealed(captured, previous, pinned);
    // The applied result is recorded after the mutation and never before it: a fault here leaves the
    // mapping revoked and reports `UNRECORDED`, which revives nothing and claims no audited success.
    try {
      appendLifecycle(captured, previous.now, 'applied');
    } catch {
      return UNRECORDED;
    }
    return applied;
  } catch (error) {
    if (isRefusal(error)) throw error;
    return fail('HOST_FAULT');
  }
}

/**
 * The recheck that runs after every external callback: one fresh authority observation, then the
 * whole guard set, with nothing suspended between the observation and the answer.
 */
async function recheck(captured: Captured, previous: Observation): Promise<Observation> {
  const observed = await observe(captured);
  congruent(observed, previous);
  bindAuditActor(captured, observed);
  const record = liveRecord(captured, observed.now);
  if (revision(record.revision) !== previous.revision) fail('SUPERSEDED');
  return observed;
}

/**
 * The sealed segment: the final guard and the mutation, in the one continuation the last awaited
 * answer resumed into. The administrative proof, the audit identity and the pinned revision were all
 * established while guards could still run, and the only objects touched from here on are the two
 * registry methods captured at construction on the registry object captured at construction.
 */
function sealed(captured: Captured, previous: Observation, pinned: number): MappingRevocationResult {
  // The live audit actor is the last host-owned read before the fresh registry read, and that read
  // is the last guard before the mutation. Both are inside the sealed continuation, and a trap
  // raised by either is still one refusal - `WITHHELD`, zero mutation - not an escaped exception.
  bindAuditActor(captured, previous);
  const record = liveRecord(captured, previous.now);
  if (revision(record.revision) !== pinned) fail('SUPERSEDED');
  const { registry, applyTransition, mappingRef, scope } = captured.fixed;
  const applied = attempt(() => invoke(applyTransition, registry, [{ version: 1, mappingRef,
    scope: { tenantId: scope.tenantId, projectId: scope.projectId, sessionId: scope.sessionId },
    expectedRevision: pinned, action: 'REVOKE' }, { now: previous.now }]));
  // From here the mutation segment has been reached, so nothing is claimed as `WITHHELD`: either the
  // registry's own answer reports the applied revocation, or the answer is `UNRECORDED` - the
  // mapping is not revived, rolled back or second-guessed, and no audited success is claimed.
  if (applied === null || typeof applied !== 'object' || applied.state !== 'CHANGED') {
    return UNRECORDED;
  }
  const after = applied.metadata as MappingMetadataRecord;
  if (after === null || typeof after !== 'object' || after.state !== 'REVOKED') return UNRECORDED;
  const afterScope = fields(after.scope, ['tenantId', 'projectId', 'sessionId']);
  if (text(after.mappingRef, 256) !== mappingRef || text(afterScope.tenantId, 256) !== scope.tenantId ||
    text(afterScope.projectId, 256) !== scope.projectId ||
    text(afterScope.sessionId, 256) !== scope.sessionId ||
    revision(after.revision) !== pinned + 1) return UNRECORDED;
  return REVOKED;
}