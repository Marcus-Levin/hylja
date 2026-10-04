/**
 * Bounded monotonic mapping lifecycle transitions (issue #169).
 *
 * This module is a **pure reducer** over one trusted current mapping metadata record and one explicit
 * lifecycle command. It proposes the next record, or refuses. It is the metadata half of the lifecycle
 * in [vault.md](../docs/vault.md) and [security-model.md](../docs/security-model.md): monotonic
 * revisions, explicit lifecycle records and terminal states that are never revived.
 *
 * What this module is not
 * - It is **not** authorization. A lifecycle command names no subject, purpose, destination or grant.
 *   The host must authenticate the caller and authorize the change itself; see
 *   [mapping-authorization.md](../docs/contracts/mapping-authorization.md) for the separate purpose-bound
 *   decision. Nothing here proves a caller may perform any lifecycle change.
 * - It is **not** storage and **not** a compare-and-set. `expectedRevision` is compared against the one
 *   record the host supplied; there is no row lock, transaction, rollback detection or durable write
 *   here, and a `CHANGED` result is a *proposed* next record, not an applied effect.
 * - It is **not** a scheduler. Expiry is automatic in the design; this function only answers an
 *   explicit `EXPIRE` proposal at the instant the host's clock reports.
 * - It destroys no key, wraps no DEK, performs no cryptographic deletion, invalidates no cache,
 *   records no audit evidence and touches no backup or restore path.
 * - It resolves nothing. No original value, ciphertext, key, key version or blind index is accepted,
 *   returned or inferred.
 *
 * Invariants it holds for every input
 * - Lifecycle moves forward only, along one fixed table. There is no reactivation, restoration,
 *   expiry extension, touch, rollback, quarantine or any other state or action.
 * - `createdAt`, `expiresAt`, `scope` and `mappingRef` are immutable through every command.
 * - Every effective change increments `revision` exactly once and refuses to wrap; a repeated terminal
 *   command returns the same record with no increment.
 * - The result is metadata and fixed codes only, every returned object is frozen, and no input object is
 *   ever mutated, aliased or retained.
 * - Malformed, hostile or simply unreadable input fails restrictively: a fixed refusal code, never a
 *   throw, never exception text and never an echo of a planted value.
 */
/** The lifecycle states this reducer can hold or propose; the terminal three are never left. */
export const MAPPING_LIFECYCLE_STATES = ['CREATED', 'ACTIVE', 'EXPIRED', 'REVOKED', 'DELETED'] as const;
export type MappingLifecycleState = (typeof MAPPING_LIFECYCLE_STATES)[number];

/** The four explicit commands. There is no extend, touch, restore, quarantine or back action. */
export const MAPPING_LIFECYCLE_ACTIONS = ['ACTIVATE', 'EXPIRE', 'REVOKE', 'DELETE'] as const;
export type MappingLifecycleAction = (typeof MAPPING_LIFECYCLE_ACTIONS)[number];

/** Every refusal this reducer can return; fixed codes that never echo an input value. */
export const MAPPING_LIFECYCLE_REASONS = [
  'INVALID_RECORD', 'INVALID_COMMAND', 'INVALID_CLOCK', 'UNKNOWN_MAPPING', 'SCOPE_MISMATCH',
  'STALE_REVISION', 'REVISION_OVERFLOW', 'INVALID_TRANSITION', 'EXPIRY_REACHED', 'NOT_EXPIRED',
] as const;
export type MappingLifecycleReason = (typeof MAPPING_LIFECYCLE_REASONS)[number];

/** The narrowest scope a mapping is issued in; every one of its three parts must match a command. */
export interface MappingLifecycleScope {
  tenantId: string;
  projectId: string;
  sessionId: string;
}

/** One trusted current mapping metadata record: lifecycle, scope and monotonic revision only. */
export interface MappingLifecycleRecord {
  version: 1;
  mappingRef: string;
  scope: MappingLifecycleScope;
  state: MappingLifecycleState;
  revision: number;
  createdAt: number;
  expiresAt: number;
}

/** One explicit lifecycle command, pinned to the exact record and revision it was decided against. */
export interface MappingLifecycleCommand {
  version: 1;
  mappingRef: string;
  scope: MappingLifecycleScope;
  expectedRevision: number;
  action: MappingLifecycleAction;
}

/** Host-owned time. A record or command timestamp is never read as "now". */
export interface MappingLifecycleClock { now: number }

export type MappingLifecycleResult =
  | { version: 1; state: 'CHANGED'; record: MappingLifecycleRecord }
  | { version: 1; state: 'UNCHANGED'; record: MappingLifecycleRecord }
  | { version: 1; state: 'REFUSED'; reason: MappingLifecycleReason };

/**
 * The whole lifecycle, as a literal table. A missing entry is not a transition; an entry equal to the
 * current state is the idempotent repeat of a terminal command. There is no other edge, in either
 * direction, between any two states.
 */
const TRANSITIONS: Record<MappingLifecycleState, Readonly<Partial<Record<MappingLifecycleAction,
  MappingLifecycleState>>>> = {
  CREATED: { ACTIVATE: 'ACTIVE', EXPIRE: 'EXPIRED', REVOKE: 'REVOKED', DELETE: 'DELETED' },
  ACTIVE: { EXPIRE: 'EXPIRED', REVOKE: 'REVOKED', DELETE: 'DELETED' },
  EXPIRED: { EXPIRE: 'EXPIRED', DELETE: 'DELETED' },
  REVOKED: { REVOKE: 'REVOKED', DELETE: 'DELETED' },
  DELETED: { DELETE: 'DELETED' },
};

// In-process values are untrusted structurally: own data properties only, no getters, no inherited or
// symbol keys, no unknown keys, no array. Every record is validated once and the normalized frozen copy
// is what the transition reads, so a caller object cannot change under it.
type Fields = Record<string, unknown>;
const MAX_KEYS = 16;
const REF_LIMIT = 256;
class Invalid extends Error { constructor(readonly reason: MappingLifecycleReason) { super(reason); } }
function fail(reason: MappingLifecycleReason): never { throw new Invalid(reason); }
function fields(value: unknown, required: readonly string[], reason: MappingLifecycleReason): Fields {
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
function text(value: unknown, reason: MappingLifecycleReason, limit = REF_LIMIT): string {
  if (typeof value !== 'string' || !value.length || value.length > limit || value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)) fail(reason);
  return value;
}
function member(value: unknown, choices: readonly string[], reason: MappingLifecycleReason): string {
  if (typeof value !== 'string' || !choices.includes(value)) fail(reason);
  return value;
}
/** A nonnegative safe-integer epoch-millisecond instant; never a fraction, string or sentinel. */
function instant(value: unknown, reason: MappingLifecycleReason): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) fail(reason);
  return value;
}
/** A monotonic revision: a positive safe integer, so a proposal can be compared and advanced by one. */
function revision(value: unknown, reason: MappingLifecycleReason): number {
  const parsed = instant(value, reason);
  if (parsed < 1) fail(reason);
  return parsed;
}
function parseScope(value: unknown, reason: MappingLifecycleReason): MappingLifecycleRecord['scope'] {
  const v = fields(value, ['tenantId', 'projectId', 'sessionId'], reason);
  return { tenantId: text(v.tenantId, reason), projectId: text(v.projectId, reason),
    sessionId: text(v.sessionId, reason) };
}
function parseRecord(value: unknown): MappingLifecycleRecord {
  const reason = 'INVALID_RECORD';
  const v = fields(value, ['version', 'mappingRef', 'scope', 'state', 'revision', 'createdAt', 'expiresAt'],
    reason);
  if (v.version !== 1) fail(reason);
  const state = member(v.state, MAPPING_LIFECYCLE_STATES, reason) as MappingLifecycleState;
  const createdAt = instant(v.createdAt, reason);
  const expiresAt = instant(v.expiresAt, reason);
  // A record whose own window is incoherent is malformed, not merely due to expire.
  if (createdAt >= expiresAt) fail(reason);
  return Object.freeze({
    version: 1, mappingRef: text(v.mappingRef, reason), scope: Object.freeze(parseScope(v.scope, reason)),
    state, revision: revision(v.revision, reason), createdAt, expiresAt,
  });
}
function parseCommand(value: unknown): MappingLifecycleCommand {
  const reason = 'INVALID_COMMAND';
  const v = fields(value, ['version', 'mappingRef', 'scope', 'expectedRevision', 'action'], reason);
  if (v.version !== 1) fail(reason);
  return Object.freeze({
    version: 1, mappingRef: text(v.mappingRef, reason),
    scope: Object.freeze(parseScope(v.scope, reason)),
    expectedRevision: revision(v.expectedRevision, reason),
    action: member(v.action, MAPPING_LIFECYCLE_ACTIONS, reason) as MappingLifecycleAction,
  });
}
function parseClock(value: unknown): MappingLifecycleClock {
  const reason = 'INVALID_CLOCK';
  const v = fields(value, ['now'], reason);
  const now = instant(v.now, reason);
  return { now };
}
function refused(reason: MappingLifecycleReason): MappingLifecycleResult {
  return Object.freeze({ version: 1, state: 'REFUSED', reason });
}
function proposal(state: 'CHANGED' | 'UNCHANGED', record: MappingLifecycleRecord): MappingLifecycleResult {
  return Object.freeze({ version: 1, state, record });
}
/** The same scope values, never the caller's objects. */
function scopeEqual(left: MappingLifecycleRecord['scope'], right: MappingLifecycleRecord['scope']): boolean {
  return left.tenantId === right.tenantId && left.projectId === right.projectId &&
    left.sessionId === right.sessionId;
}

/**
 * Computes the next record one explicit command would propose for one current record.
 *
 * The fixed order below is the contract: every input's shape, then reference, scope, revision, then the
 * transition table, then the clock conditions, then the revision increment. The first failing check
 * names the reason, so a caller cannot learn more than the fixed code.
 */
export function applyMappingLifecycleCommand(currentValue: unknown, commandValue: unknown,
  clockValue: unknown): MappingLifecycleResult {
  try {
    let current: MappingLifecycleRecord;
    let command: MappingLifecycleCommand;
    let clock: MappingLifecycleClock;
    try { current = parseRecord(currentValue); } catch { return refused('INVALID_RECORD'); }
    try { command = parseCommand(commandValue); } catch { return refused('INVALID_COMMAND'); }
    try { clock = parseClock(clockValue); } catch { return refused('INVALID_CLOCK'); }
    // A host clock earlier than the record's own creation instant is not a trustworthy "now".
    if (clock.now < current.createdAt) return refused('INVALID_CLOCK');
    // Only the exact record the host holds may move: reference, then the whole scope, then the revision.
    if (command.mappingRef !== current.mappingRef) return refused('UNKNOWN_MAPPING');
    if (!scopeEqual(command.scope, current.scope)) return refused('SCOPE_MISMATCH');
    if (command.expectedRevision !== current.revision) return refused('STALE_REVISION');
    // The table, not a comparison, decides what may follow: no reactivation, restoration or rollback.
    const target = TRANSITIONS[current.state][command.action];
    if (target === undefined) return refused('INVALID_TRANSITION');
    // An action whose target is the state it is already in is the idempotent repeat of a terminal
    // command: the same record, no revision increment, and no new clock condition to satisfy.
    if (target === current.state) return proposal('UNCHANGED', current);
    if (command.action === 'ACTIVATE' && clock.now >= current.expiresAt) return refused('EXPIRY_REACHED');
    if (command.action === 'EXPIRE' && clock.now < current.expiresAt) return refused('NOT_EXPIRED');
    if (current.revision === Number.MAX_SAFE_INTEGER) return refused('REVISION_OVERFLOW');
    // Expiry, creation, scope and reference are carried through untouched.
    return proposal('CHANGED', Object.freeze({ ...current, state: target, revision: current.revision + 1 }));
  } catch {
    // A hostile value that survived the parsers still yields a fixed code and no exception detail.
    return refused('INVALID_RECORD');
  }
}
