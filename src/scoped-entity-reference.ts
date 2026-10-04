/**
 * Keyed, scope-bound entity reference derivation (issue #168).
 *
 * One pure function turns a host-owned entity ID, a host HMAC key and an **explicitly chosen** scope into
 * one deterministic opaque reference. That reference is the keyed identity component of [#14]; it is not
 * alias resolution, not a synthetic person generator and not an issuance authority.
 *
 * What this module is
 * - A deterministic keyed derivation: the same complete input and key always give the same token text,
 *   and across the generated synthetic cases in the focused test, changing the key, the scope kind, any
 *   scope identifier, the entity ID, the accepted-v1 semantic class or the key version gave a different
 *   token every time. That is an observed result over those cases, not a claim that HMAC cannot collide.
 * - A scope *binder*. `TENANT`, `PROJECT`, `SESSION` and `REQUEST` are cumulative and explicit: each kind
 *   requires exactly its own identifiers and refuses every missing or unexpected one. There is no
 *   fallback, no implicit widening and no way to derive a narrow reference from a broad one.
 * - A domain-separated, unambiguous serialization. The message is a versioned domain string followed by
 *   length-framed components, so no two distinct tuples can flatten to the same bytes. The token carries
 *   the full 256-bit HMAC-SHA256 digest as lowercase hex behind the fixed `her1:` prefix. It is never an
 *   unkeyed hash, a truncated digest, a caller-selected algorithm or a raw concatenation.
 * - A non-echoing seam. The only labels it returns are the token and the four-value scope kind. Arbitrary
 *   caller text, `keyVersion` above all, is bound into the derivation and never handed back: a bounded
 *   identifier from a closed alphabet can still be chosen to equal a scope ID or the key's own hex.
 *
 * What this module is not
 * - Not a mapping, not a blind index over originals, and not a lookup: there is no original value, alias,
 *   prompt or candidate text as input, no retrieval, no store, no cache and no registry. Collision
 *   handling against an entity registry is a later obligation (#14), not this function's claim.
 * - Not authorization. A token is not a capability, not an authenticated reference and not proof that the
 *   scope, key or entity was ever issued. A broader scope here is a host selection that grants no
 *   permission. `CREDENTIAL_OR_SECRET` is refused outright (decision 009); credentials are not
 *   synthetic identities.
 * - Not an enforcement boundary: it authenticates nobody, sends no bytes and performs no integration
 *   effect. Parents #13 and #10 remain requirements for integrated entity resolution.
 *
 * Hostile input: a proxied request or key refuses outright, whether the proxy forwards a valid object's
 * prototype, keys and descriptors or throws from a trap. A trap that throws *another* Proxy is handled
 * without inspecting what was thrown, because reflecting over an arbitrary value can throw again; the
 * fixed refusal code is recorded out of band before this module throws, so the caller learns only the
 * class of check that failed.
 *
 * Key handling: the caller's key is snapshotted once into a copy this function allocates, so a key that
 * changes after the call cannot change the reference; that owned copy is cleared on every exit, including
 * a refusal taken after the copy exists. The caller's own key material is never modified, and no global
 * zeroization is claimed.
 */
import { createHmac } from 'node:crypto';
import { types } from 'node:util';
import { SEMANTIC_CLASSES } from './classification.js';
import type { SemanticClass } from './classification.js';

/** Cumulative scope kinds; each one names exactly the identifiers it binds. */
export const ENTITY_REFERENCE_SCOPE_KINDS = ['TENANT', 'PROJECT', 'SESSION', 'REQUEST'] as const;
export type EntityReferenceScopeKind = (typeof ENTITY_REFERENCE_SCOPE_KINDS)[number];

/** Every outcome of a refusal; fixed codes that never echo an input value. */
export const ENTITY_REFERENCE_REFUSALS = [
  'INVALID_REQUEST', 'SCOPE_FIELDS_INVALID', 'CREDENTIAL_REFUSED',
] as const;
export type EntityReferenceRefusal = (typeof ENTITY_REFERENCE_REFUSALS)[number];

/** Fixed token prefix; the token is this prefix plus the full 256-bit digest as lowercase hex. */
export const ENTITY_REFERENCE_TOKEN_PREFIX = 'her1:';
export const ENTITY_REFERENCE_KEY_BYTES = 32;
export const ENTITY_REFERENCE_MAX_ID_UNITS = 128;

/**
 * The request. Every field is host-owned: no original value, alias, prompt text or candidate span is
 * accepted here, and `key` is the host's own HMAC key rather than anything a payload supplied.
 * `keyVersion` binds the derivation and is deliberately not part of the result.
 */
export interface ScopedEntityReferenceRequest {
  scope: EntityReferenceScopeKind;
  tenantId: string;
  projectId?: string;
  sessionId?: string;
  requestId?: string;
  entityId: string;
  /** Accepted classification v1 class; drafts and unknown values are refused. */
  semanticType: SemanticClass;
  keyVersion: string;
  key: Uint8Array;
}

/** A frozen record holding the opaque token and the one closed, non-arbitrary label the host bound. */
export interface DerivedEntityReference {
  readonly version: 1;
  readonly state: 'DERIVED';
  readonly token: string;
  readonly scope: EntityReferenceScopeKind;
}
export interface RefusedEntityReference {
  readonly version: 1;
  readonly state: 'REFUSED';
  readonly reason: EntityReferenceRefusal;
}
export type EntityReferenceResult = DerivedEntityReference | RefusedEntityReference;

// In-process values are untrusted structurally: own enumerable data properties only, no getters, no
// inherited or symbol keys, no unknown keys. Every value is read once into a normalized copy.
type Fields = Record<string, unknown>;
const MAX_KEYS = 12;
const SCOPE_ID_NAMES = ['tenantId', 'projectId', 'sessionId', 'requestId'] as const;
const REQUIRED_KEYS = ['scope', 'entityId', 'semanticType', 'keyVersion', 'key'] as const;
/** The complete closed field set; anything else on the request is malformed input. */
const REQUEST_KEYS: readonly string[] = Object.freeze([...REQUIRED_KEYS, ...SCOPE_ID_NAMES]);
const SCOPE_FIELDS: Readonly<Record<EntityReferenceScopeKind, readonly string[]>> = Object.freeze({
  TENANT: Object.freeze(['tenantId']),
  PROJECT: Object.freeze(['tenantId', 'projectId']),
  SESSION: Object.freeze(['tenantId', 'projectId', 'sessionId']),
  REQUEST: Object.freeze(['tenantId', 'projectId', 'sessionId', 'requestId']),
});
/** Versioned domain separation for the keyed message; a future version changes this string. */
const DOMAIN = 'hylja.scoped-entity-reference.v1';
/** One closed, explicit ASCII alphabet: no delimiter, separator or non-ASCII unit is accepted. */
const SAFE_ID = new RegExp(`^[A-Za-z0-9._-]{1,${ENTITY_REFERENCE_MAX_ID_UNITS}}$`, 'u');
const HEX_256 = /^[0-9a-f]{64}$/u;

/**
 * The fixed code for the refusal this module is raising, recorded *before* the throw and read in the
 * catch without looking at the thrown value. Reflecting over an arbitrary throw is itself unsafe: a
 * caller-thrown Proxy can throw again from `getPrototypeOf`, so `instanceof` in the catch would escape.
 * The slot holds one code at a time; the entry point resets it and this function is synchronous, so no
 * other call can observe it.
 */
let internalRefusal: EntityReferenceRefusal | undefined;

class Refuse extends Error {}
function refuse(code: EntityReferenceRefusal): never {
  internalRefusal = code;
  throw new Refuse();
}
function refused(reason: EntityReferenceRefusal): RefusedEntityReference {
  return Object.freeze({ version: 1, state: 'REFUSED', reason });
}
function snapshot(value: unknown): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) refuse('INVALID_REQUEST');
  // A proxied request refuses outright, transparent or throwing: this seam reads a plain host object,
  // and a trap would otherwise be able to report one shape here and another one a line later.
  if (types.isProxy(value)) refuse('INVALID_REQUEST');
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) refuse('INVALID_REQUEST');
  // One bounded own-key snapshot: each field is read exactly once, from the shape this call validated.
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_KEYS || keys.some((key) => typeof key !== 'string')) refuse('INVALID_REQUEST');
  const result: Fields = Object.create(null) as Fields;
  for (const key of keys as string[]) {
    if (!REQUEST_KEYS.includes(key)) refuse('INVALID_REQUEST');
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) refuse('INVALID_REQUEST');
    result[key] = descriptor.value;
  }
  for (const name of REQUIRED_KEYS) if (!Object.hasOwn(result, name)) refuse('INVALID_REQUEST');
  return result;
}
function member<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) refuse('INVALID_REQUEST');
  return value as T;
}
/** Bounded, nonempty, closed-alphabet identifier. Anything else is malformed input. */
function identifier(value: unknown): string {
  if (typeof value !== 'string' || !SAFE_ID.test(value)) refuse('INVALID_REQUEST');
  return value;
}
/**
 * %TypedArray%.prototype's own `length` getter reads the internal slot. An own data property can shadow
 * `view.length` on a real view - `Object.defineProperty(view, 'length', {value: 32})` succeeds and V8
 * reports the shadowed value - so the length trusted here is the one the prototype getter reports. An
 * index read is not shadowable: a typed array always answers an element read with its own element.
 */
const intrinsicLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype) as object, 'length')?.get;

/**
 * Snapshot the host key into a copy this function owns. Intrinsic identity comes first: `isProxy`
 * refuses a proxied view without running a trap, and `isUint8Array` accepts only the real brand, so a
 * 16-bit view that spoofs `Symbol.toStringTag` is not a byte view. The length is then read through the
 * intrinsic getter and checked as a primitive safe integer *before* any allocation or byte read.
 */
function ownedKey(value: unknown): Uint8Array {
  if (types.isProxy(value) || !types.isUint8Array(value)) refuse('INVALID_REQUEST');
  if (intrinsicLength === undefined) refuse('INVALID_REQUEST');
  const length: unknown = Reflect.apply(intrinsicLength, value, []) as unknown;
  if (typeof length !== 'number' || !Number.isSafeInteger(length) ||
    length !== ENTITY_REFERENCE_KEY_BYTES) refuse('INVALID_REQUEST');
  const copy = new Uint8Array(ENTITY_REFERENCE_KEY_BYTES);
  let complete = false;
  try {
    for (let index = 0; index < ENTITY_REFERENCE_KEY_BYTES; index += 1) {
      const byte: unknown = (value as Uint8Array)[index];
      if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) {
        refuse('INVALID_REQUEST');
      }
      copy[index] = byte;
    }
    complete = true;
    return copy;
  } finally {
    // Every unsuccessful exit clears the copy allocated here. The caller's handler holds only the value
    // returned from this function, so it cannot reach a partially filled local copy on a refusal.
    if (!complete) copy.fill(0);
  }
}
/** Length framing, so no delimiter-free or delimiter-like identifier can alias another tuple. */
function frame(value: string): string { return `${value.length}:${value}`; }

/**
 * Derive one opaque, keyed, scope-bound reference.
 *
 * The order is the contract: request shape, then the scope variant, then the identifiers, then the
 * accepted-v1 class, then the key, then the digest. The first failure names its fixed code, so a caller
 * learns nothing beyond the class of check that failed.
 */
export function deriveScopedEntityReference(requestValue: unknown): EntityReferenceResult {
  let owned: Uint8Array | undefined;
  internalRefusal = undefined;
  try {
    const fields = snapshot(requestValue);
    const scope = member(fields.scope, ENTITY_REFERENCE_SCOPE_KINDS);
    const required = SCOPE_FIELDS[scope];
    // Presence first: a missing or unexpected scope identifier is a scope-variant failure, never a
    // partially accepted tuple with the extra or missing half dropped.
    for (const name of required) if (!Object.hasOwn(fields, name)) refuse('SCOPE_FIELDS_INVALID');
    for (const name of SCOPE_ID_NAMES) {
      if (!required.includes(name) && Object.hasOwn(fields, name)) refuse('SCOPE_FIELDS_INVALID');
    }
    const ids = required.map((name) => identifier(fields[name]));
    const entityId = identifier(fields.entityId);
    // The key version binds the derivation and is not returned: it is arbitrary caller text.
    const keyVersion = identifier(fields.keyVersion);
    const semanticType = member(fields.semanticType, SEMANTIC_CLASSES);
    // Credentials and secrets are not synthetic identities (accepted decision 009).
    if (semanticType === 'CREDENTIAL_OR_SECRET') refuse('CREDENTIAL_REFUSED');
    owned = ownedKey(fields.key);
    const message = [DOMAIN, scope, ...ids, entityId, semanticType, keyVersion].map(frame).join('|');
    const digest = createHmac('sha256', owned).update(message).digest('hex');
    if (!HEX_256.test(digest)) refuse('INVALID_REQUEST');
    return Object.freeze({ version: 1, state: 'DERIVED', token: `${ENTITY_REFERENCE_TOKEN_PREFIX}${digest}`,
      scope });
  } catch {
    // The thrown value is never inspected - no `instanceof`, no prototype walk, no property read,
    // because an arbitrary caller-thrown Proxy can throw again from any of those. Only the fixed code
    // recorded out of band is used; anything else is the one non-specific refusal.
    return refused(internalRefusal ?? 'INVALID_REQUEST');
  } finally {
    // Only the copy allocated here is cleared, on every exit including a later refusal. The caller's
    // key is untouched, and nothing here claims to zeroize memory or any other key copy.
    owned?.fill(0);
  }
}
