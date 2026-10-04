/**
 * Bounded ephemeral mapping metadata registry (issue #180).
 *
 * This module owns the **current** mapping metadata record for every reference it holds, in one
 * in-process `Map`, and applies every lifecycle change through
 * [`applyMappingLifecycleCommand`](../docs/contracts/mapping-lifecycle.md). It is the compare-and-set seam that
 * [mapping-lifecycle.md](../docs/contracts/mapping-lifecycle.md) explicitly does not provide: the
 * reducer proposes the next record for one record the host supplied, and this registry is the host
 * that owns the current one, so two callers pinned to the same expected revision cannot both apply.
 *
 * What this module is not
 * - It is **not** authorization. A request carries no subject, workload, principal, purpose,
 *   destination or grant, so nothing here proves a caller may read, insert or transition a record.
 *   The trusted integration must authenticate the caller and authorize every call itself;
 *   [`authorizeMappingOperation`](../docs/contracts/mapping-authorization.md) is the separate
 *   purpose-bound decision.
 *   An `INSERTED`, `FOUND`, `CHANGED` or `UNCHANGED` result grants nothing.
 * - It is **not** durable storage. The map is process-local, in memory and lost on exit. There is no
 *   transaction, row lock, replication, rollback detection, restore path, KMS/HSM binding, audit
 *   record, key destruction, cache invalidation or scheduler. Atomicity is **single Node event-loop**
 *   only: two callers in one process cannot interleave inside one synchronous operation, and nothing
 *   here holds across processes, machines or restarts.
 * - It resolves nothing. No original value, ciphertext, key, key version, DEK, blind index, alias or
 *   plaintext is accepted, stored, returned or inferred, and there is no lookup API for one.
 *
 * Invariants it holds for every input
 * - The key is a four-level structural path - tenant, project, session, then mapping reference - and
 *   never a delimited string, so delimiter-shaped identifiers cannot collide and two scopes holding
 *   the same reference stay isolated. A foreign scope and an unknown reference are the same answer.
 * - A mapping is created `CREATED` at revision 1 and only that: the request has no field for a state
 *   or a revision, so a caller cannot backdate, pre-activate or pre-increment one. The reference,
 *   the scope and the expiry are fixed at creation and are immutable for the life of the entry.
 * - A transition reads the registry's **own** current record. No caller-supplied record is accepted,
 *   so a cached copy cannot decide a compare-and-set.
 * - Expiry is restrictive at every operation: the first observation at or after `expiresAt` latches
 *   the entry expired, drives `EXPIRE` through the same reducer, and a clock that moves backwards is
 *   refused. Neither can be undone, so an observed expiry is never reversed by a later rollback.
 * - A terminal entry is a tombstone. It is never removed, never revived, and never evicted, so a full
 *   registry refuses a new insert rather than reclaiming one.
 * - Malformed, hostile or simply unreadable input fails restrictively: a fixed refusal code, never a
 *   throw out of this module, never exception text and never an echo of a planted value. Nothing is
 *   logged.
 */
import { MAPPING_LIFECYCLE_ACTIONS, applyMappingLifecycleCommand } from './mapping-lifecycle.js';
import type { MappingLifecycleAction, MappingLifecycleRecord, MappingLifecycleReason, MappingLifecycleScope,
  MappingLifecycleState } from './mapping-lifecycle.js';

/** The three-part scope every record is locked into; identical in meaning to the reducer's. */
export type MappingMetadataScope = MappingLifecycleScope;

/**
 * The reducer's own record, in the reducer's own numbering domain. There is no translation between
 * the two numbering domains: creation is revision 1 and every effective change adds exactly one.
 */
export type MappingMetadataRecord = MappingLifecycleRecord;

/** Bounded in-process capacity: a positive safe integer, at most 4096. */
export interface MappingMetadataRegistryOptions { capacity: number }

/** The three operations, and nothing else. There is no removal, no scan and no enumeration. */
export interface MappingMetadataRegistry {
  readonly version: 1;
  readonly capacity: number;
  readonly size: number;
  /** Creates one `CREATED` record at revision 1. There is no other way to add one. */
  insert(request: unknown, clock: unknown): MappingMetadataInsertResult;
  /** Returns the current record only when the scope matches and the lifecycle is live. */
  current(request: unknown, clock: unknown): MappingMetadataCurrentResult;
  /** Applies one command against the registry's own current record, or refuses. */
  transition(request: unknown, clock: unknown): MappingMetadataTransitionResult;
}

/** Every refusal this registry returns; fixed codes that never echo an input value. */
export const MAPPING_METADATA_REASONS = [
  'INVALID_REQUEST', 'INVALID_CLOCK', 'INVALID_EXPIRY', 'CLOCK_ROLLBACK', 'DUPLICATE_MAPPING',
  'REGISTRY_FULL', 'UNKNOWN_MAPPING', 'NOT_LIVE', 'STALE_REVISION', 'INVALID_TRANSITION',
  'REVISION_OVERFLOW',
] as const;
export type MappingMetadataReason = (typeof MAPPING_METADATA_REASONS)[number];

export interface MappingMetadataRefusal { version: 1; state: 'REFUSED'; reason: MappingMetadataReason }
export interface MappingMetadataAbsent { version: 1; state: 'ABSENT'; reason: MappingMetadataReason }

export type MappingMetadataInsertResult =
  | { version: 1; state: 'INSERTED'; metadata: MappingMetadataRecord }
  | MappingMetadataRefusal;
export type MappingMetadataCurrentResult =
  | { version: 1; state: 'FOUND'; metadata: MappingMetadataRecord }
  | MappingMetadataAbsent
  | MappingMetadataRefusal;
export type MappingMetadataTransitionResult =
  | { version: 1; state: 'CHANGED'; metadata: MappingMetadataRecord }
  | { version: 1; state: 'UNCHANGED'; metadata: MappingMetadataRecord }
  | MappingMetadataRefusal;

/**
 * The only states a lookup may return and the only states an observation may expire. Every other state
 * - `EXPIRED`, `REVOKED`, `DELETED` - is a tombstone: it stays, it never moves back, and it is never
 * evicted.
 */
const LIVE = new Set<MappingLifecycleState>(['CREATED', 'ACTIVE']);


// In-process values are untrusted structurally: own data properties only, no getters, no inherited or
// symbol keys, no unknown keys, no array. Every request is validated once and the normalized frozen
// copy is what the operation reads, so a caller object cannot change under it.
type Fields = Record<string, unknown>;
const MAX_KEYS = 16;
const REF_LIMIT = 256;
const MAX_CAPACITY = 4096;
const INSERT_KEYS = ['version', 'mappingRef', 'scope', 'expiresAt'];
const LOOKUP_KEYS = ['version', 'mappingRef', 'scope'];
const TRANSITION_KEYS = ['version', 'mappingRef', 'scope', 'expectedRevision', 'action'];

/**
 * Internal refusal sentinel. The reason lives in a module-private identity map, never on the object,
 * so classifying a thrown value reads no property, message, `toString`, `reason` or getter off it.
 */
class Invalid extends Error { }
const REFUSALS = new WeakMap<object, MappingMetadataReason>();
function fail(reason: MappingMetadataReason): never {
  const error = new Invalid();
  REFUSALS.set(error, reason);
  throw error;
}
/**
 * Total classification of any thrown value, including a caller-planted one. Identity against the
 * module-private map is the only lookup, and neither `typeof` nor a `WeakMap` key comparison invokes
 * anything on the value, so a proxy whose traps throw cannot make this classify fail or escape. A
 * value this module did not create is refused as an invalid request and no detail of it is read.
 */
function reasonOf(thrown: unknown): MappingMetadataReason {
  if (typeof thrown !== 'object' || thrown === null) return 'INVALID_REQUEST';
  return REFUSALS.get(thrown) ?? 'INVALID_REQUEST';
}
function fields(value: unknown, required: readonly string[], reason: MappingMetadataReason): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(reason);
  // One bounded key snapshot keeps a Proxy ownKeys from changing between reflections.
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_KEYS || keys.some((key) => typeof key !== 'string')) fail(reason);
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    if (!required.includes(key)) fail(reason);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) fail(reason);
    result[key] = descriptor.value;
  }
  for (const name of required) if (!Object.hasOwn(result, name)) fail(reason);
  return result;
}
function text(value: unknown, reason: MappingMetadataReason): string {
  if (typeof value !== 'string' || !value.length || value.length > REF_LIMIT || value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)) fail(reason);
  return value;
}
function member(value: unknown, choices: readonly string[], reason: MappingMetadataReason): string {
  if (typeof value !== 'string' || !choices.includes(value)) fail(reason);
  return value;
}
/** A nonnegative safe-integer epoch-millisecond instant; never a fraction, string or sentinel. */
function instant(value: unknown, reason: MappingMetadataReason): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) fail(reason);
  return value;
}
function parseScope(value: unknown, reason: MappingMetadataReason): MappingMetadataScope {
  const v = fields(value, ['tenantId', 'projectId', 'sessionId'], reason);
  return Object.freeze({ tenantId: text(v.tenantId, reason), projectId: text(v.projectId, reason),
    sessionId: text(v.sessionId, reason) });
}
/** The host clock, supplied separately. A timestamp inside a request is an unknown key, not time. */
function parseClock(value: unknown): number {
  const reason = 'INVALID_CLOCK';
  const v = fields(value, ['now'], reason);
  return instant(v.now, reason);
}
function parseLookup(value: unknown): { mappingRef: string; scope: MappingMetadataScope } {
  const reason = 'INVALID_REQUEST';
  const v = fields(value, LOOKUP_KEYS, reason);
  if (v.version !== 1) fail(reason);
  return { mappingRef: text(v.mappingRef, reason), scope: parseScope(v.scope, reason) };
}
function parseInsert(value: unknown): { mappingRef: string; scope: MappingMetadataScope; expiresAt: number } {
  const reason = 'INVALID_REQUEST';
  const v = fields(value, INSERT_KEYS, reason);
  if (v.version !== 1) fail(reason);
  return { mappingRef: text(v.mappingRef, reason), scope: parseScope(v.scope, reason),
    expiresAt: instant(v.expiresAt, reason) };
}
function parseTransition(value: unknown): {
  mappingRef: string; scope: MappingMetadataScope; expectedRevision: number; action: MappingLifecycleAction;
} {
  const reason = 'INVALID_REQUEST';
  const v = fields(value, TRANSITION_KEYS, reason);
  if (v.version !== 1) fail(reason);
  // One numbering domain, the reducer's own: creation is revision 1, so the smallest value a caller
  // may pin is 1 and nothing is translated on the way to the reducer.
  const expected = instant(v.expectedRevision, reason);
  if (expected < 1) fail(reason);
  return { mappingRef: text(v.mappingRef, reason), scope: parseScope(v.scope, reason),
    expectedRevision: expected,
    action: member(v.action, MAPPING_LIFECYCLE_ACTIONS, reason) as MappingLifecycleAction };
}
function refused(reason: MappingMetadataReason): MappingMetadataRefusal {
  return Object.freeze({ version: 1, state: 'REFUSED', reason });
}
function absent(reason: MappingMetadataReason): MappingMetadataAbsent {
  return Object.freeze({ version: 1, state: 'ABSENT', reason });
}
/**
 * Maps one reducer refusal onto this registry's fixed codes. The registry builds both the record and
 * the command from values it has already normalized, so only the revision, the table and the clock
 * conditions can occur; anything else is reported as a refused request rather than guessed at, and
 * can never leave a record more usable.
 */
function transitionReason(reason: MappingLifecycleReason): MappingMetadataReason {
  if (reason === 'STALE_REVISION') return 'STALE_REVISION';
  if (reason === 'REVISION_OVERFLOW') return 'REVISION_OVERFLOW';
  // `INVALID_TRANSITION`, `EXPIRY_REACHED` and `NOT_EXPIRED` are all one answer here: this action is
  // not available to this record at this instant, and none of them leaves the record changed.
  if (reason === 'INVALID_TRANSITION' || reason === 'EXPIRY_REACHED' || reason === 'NOT_EXPIRED') {
    return 'INVALID_TRANSITION';
  }
  return 'INVALID_REQUEST';
}

interface Entry {
  mappingRef: string;
  scope: MappingMetadataScope;
  state: MappingLifecycleState;
  revision: number;
  createdAt: number;
  expiresAt: number;
  /** The highest instant ever observed for this entry; a lower one is a refused rollback. */
  observedAt: number;
  /** Latched the first time an instant at or after `expiresAt` was observed; never cleared. */
  expired: boolean;
}
type RefIndex = Map<string, Entry>;
type SessionIndex = Map<string, RefIndex>;
type ProjectIndex = Map<string, SessionIndex>;
type ScopeIndex = Map<string, ProjectIndex>;

/** A frozen copy of the current record. A caller can neither mutate it nor alias the stored entry. */
function snapshot(entry: Entry): MappingMetadataRecord {
  return Object.freeze({ version: 1, mappingRef: entry.mappingRef,
    scope: Object.freeze({ ...entry.scope }), state: entry.state, revision: entry.revision,
    createdAt: entry.createdAt, expiresAt: entry.expiresAt });
}
/** The record exactly as the reducer validates it: the stored one, at `revision + 1`. */
function reducerRecord(entry: Entry): MappingLifecycleRecord {
  return { version: 1, mappingRef: entry.mappingRef, scope: entry.scope, state: entry.state,
    revision: entry.revision, createdAt: entry.createdAt, expiresAt: entry.expiresAt };
}
function reducerCommand(entry: Entry, expectedRevision: number, action: MappingLifecycleAction): {
  version: 1; mappingRef: string; scope: MappingMetadataScope; expectedRevision: number;
  action: MappingLifecycleAction;
} {
  return { version: 1, mappingRef: entry.mappingRef, scope: entry.scope,
    expectedRevision, action };
}
/** One write of one reducer result back into the entry, in the reducer's own revision numbering. */
function commit(entry: Entry, record: { state: MappingLifecycleState; revision: number }): void {
  entry.state = record.state;
  entry.revision = record.revision;
}

/**
 * Creates one bounded registry over an empty private map.
 *
 * The options are host configuration, not untrusted input: an unusable capacity throws a `TypeError`
 * carrying fixed text, never the supplied value. There is no option to disable expiry, to evict, to
 * weaken a check or to make a transition unconditional.
 */
export function createMappingMetadataRegistry(optionsValue: unknown): MappingMetadataRegistry {
  const index: ScopeIndex = new Map();
  let size = 0;
  let capacity = 0;
  try {
    const options = fields(optionsValue, ['capacity'], 'INVALID_REQUEST');
    const requested = instant(options.capacity, 'INVALID_REQUEST');
    if (requested < 1 || requested > MAX_CAPACITY) fail('INVALID_REQUEST');
    capacity = requested;
  } catch {
    throw new TypeError('invalid mapping metadata registry options');
  }

  /** A structural four-level path, never a delimited string: no identifier can forge another's key. */
  function locate(scope: MappingMetadataScope, mappingRef: string): Entry | undefined {
    const projects = index.get(scope.tenantId);
    if (projects === undefined) return undefined;
    const sessions = projects.get(scope.projectId);
    if (sessions === undefined) return undefined;
    const refs = sessions.get(scope.sessionId);
    if (refs === undefined) return undefined;
    return refs.get(mappingRef);
  }
  function place(scope: MappingMetadataScope, mappingRef: string, entry: Entry): void {
    let projects = index.get(scope.tenantId);
    if (projects === undefined) { projects = new Map(); index.set(scope.tenantId, projects); }
    let sessions = projects.get(scope.projectId);
    if (sessions === undefined) { sessions = new Map(); projects.set(scope.projectId, sessions); }
    let refs = sessions.get(scope.sessionId);
    if (refs === undefined) { refs = new Map(); sessions.set(scope.sessionId, refs); }
    refs.set(mappingRef, entry);
  }

  /**
   * Records one observation of `now` against an existing entry, and expires it if it is due.
   *
   * Expiry is restrictive at every operation, so this runs before any answer is formed. The latch is
   * set before the reducer is consulted, so a refusal at an exhausted revision cannot clear it, and a
   * clock that moves backwards is refused before it can be mistaken for a live entry. Expiry observed
   * here consumes a revision through the same reducer and the same table as any other change.
   */
  function observe(entry: Entry, now: number): void {
    if (now < entry.observedAt) fail('CLOCK_ROLLBACK');
    entry.observedAt = now;
    if (entry.expired || now < entry.expiresAt) return;
    entry.expired = true;
    if (!LIVE.has(entry.state)) return;
    const applied = applyMappingLifecycleCommand(reducerRecord(entry),
      reducerCommand(entry, entry.revision, 'EXPIRE'), { now });
    if (applied.state === 'REFUSED') return;
    commit(entry, applied.record);
  }
  function isLive(entry: Entry, now: number): boolean {
    return !entry.expired && LIVE.has(entry.state) && now < entry.expiresAt;
  }

  const insert = (requestValue: unknown, clockValue: unknown): MappingMetadataInsertResult => {
    try {
      const request = parseInsert(requestValue);
      const now = parseClock(clockValue);
      // Reference before capacity: a full registry still names the reference it already holds. A
      // duplicate insert is an operation on the held record like any other, so it observes it first:
      // expiry latches here exactly as it does in `current` and `transition`, and a clock that moved
      // backwards is refused rather than answered as a plain duplicate.
      const held = locate(request.scope, request.mappingRef);
      if (held !== undefined) { observe(held, now); return refused('DUPLICATE_MAPPING'); }
      if (request.expiresAt <= now) return refused('INVALID_EXPIRY');
      if (size >= capacity) return refused('REGISTRY_FULL');
      const entry: Entry = { mappingRef: request.mappingRef, scope: request.scope, state: 'CREATED',
        revision: 1, createdAt: now, expiresAt: request.expiresAt, observedAt: now, expired: false };
      place(request.scope, request.mappingRef, entry);
      size += 1;
      return Object.freeze({ version: 1, state: 'INSERTED', metadata: snapshot(entry) });
    } catch (error) { return refused(reasonOf(error)); }
  };

  const current = (requestValue: unknown, clockValue: unknown): MappingMetadataCurrentResult => {
    try {
      const request = parseLookup(requestValue);
      const now = parseClock(clockValue);
      // A foreign scope and an unknown reference are the same answer, so neither discloses the other.
      const entry = locate(request.scope, request.mappingRef);
      if (entry === undefined) return absent('UNKNOWN_MAPPING');
      observe(entry, now);
      if (!isLive(entry, now)) return absent('NOT_LIVE');
      return Object.freeze({ version: 1, state: 'FOUND', metadata: snapshot(entry) });
    } catch (error) { return refused(reasonOf(error)); }
  };

  const transition = (requestValue: unknown, clockValue: unknown): MappingMetadataTransitionResult => {
    try {
      const request = parseTransition(requestValue);
      const now = parseClock(clockValue);
      const entry = locate(request.scope, request.mappingRef);
      if (entry === undefined) return refused('UNKNOWN_MAPPING');
      // Expiry first, then the compare-and-set against this entry's own revision. A caller that read
      // the record before an expiry was observed names a revision this registry no longer holds.
      observe(entry, now);
      const applied = applyMappingLifecycleCommand(reducerRecord(entry),
        reducerCommand(entry, request.expectedRevision, request.action), { now });
      if (applied.state === 'REFUSED') return refused(transitionReason(applied.reason));
      commit(entry, applied.record);
      return Object.freeze({ version: 1, state: applied.state, metadata: snapshot(entry) });
    } catch (error) { return refused(reasonOf(error)); }
  };

  const registry: MappingMetadataRegistry = {
    version: 1,
    capacity,
    get size(): number { return size; },
    insert,
    current,
    transition,
  };
  return Object.freeze(registry);
}
