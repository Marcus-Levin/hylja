import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { SEMANTIC_CLASSES } from './classification.js';
import type { SemanticClass } from './classification.js';

/**
 * Bounded scope-bound AEAD primitive for small mapping byte payloads (issue #162).
 *
 * One `sealMappingPayload` / `openMappingPayload` pair over `Uint8Array`, fixed AES-256-GCM with a
 * fresh cryptographically random 96-bit nonce and the full 16-byte tag. The nonce and the algorithm
 * are never caller-selected, and a 32-byte data-encryption key is supplied by the host and never
 * retained in the sealed record. The AAD is an unambiguous versioned canonical serialization of
 * `tenantId`, `projectId`, `entityId`, `classification`, `mappingRevision` and `keyVersion`, so every
 * required scope component is authenticated. `openMappingPayload` takes the expected scope and the
 * key **separately** from the sealed record: the ciphertext can never choose its own authority.
 *
 * What this is not. It is not a vault, a broker, an envelope-key manager, a KMS/HSM adapter, a blind
 * index, a store, a lifecycle or freshness authority, or a production encryption readiness claim. It
 * authenticates nobody, persists nothing, sends nothing and grants no USE/DISPLAY/EXPORT permission.
 * Per the accepted security model, a *valid* old envelope is not a *fresh authorized* mapping: the
 * trusted store or broker must supply the current expected revision and key scope, and the #15/#16
 * integration must exist before any mapping is persisted. A caller that already holds a DEK and the
 * ciphertext can read the payload by calling `openMappingPayload` itself; this module narrows the
 * crypto, it does not authorize anyone.
 *
 * Failure handling. Every refusal is one fixed code from `MAPPING_AEAD_REFUSALS`, carries no caller
 * text, and never carries a native error, message or cause. Nothing is written to a log. Refusal
 * identification is non-reflective and guarded, so a hostile thrown `Proxy` cannot make the boundary
 * itself throw. A declared byte length is validated as a primitive, nonnegative safe integer before
 * any buffer is allocated, so a lying or oversized claim never buys an allocation. Bytes produced by
 * `decipher.update` before the tag is verified are never returned: they are held and discarded unless
 * `final` authenticates. Owned transient copies of caller key, payload, AAD, sealed-body and
 * decipher bytes are overwritten on the success path and on every exceptional path; that is
 * best-effort hygiene in JavaScript, not a zeroization guarantee for copies held inside native
 * crypto, garbage-collected buffers or swapped pages. A buffer this module returns to the caller, and
 * a buffer the caller supplied, are never overwritten by that hygiene.
 */
const ALGORITHM = 'aes-256-gcm' as const;
const encoder = new TextEncoder();

export const MAPPING_AEAD_VERSION = 1 as const;

export interface MappingAeadLimits {
  plaintextBytes: number; ciphertextBytes: number; keyBytes: number; nonceBytes: number;
  tagBytes: number; identifierChars: number;
}
/** Fixed bounds. Every one is checked before any work proportional to a caller's input. */
export const MAPPING_AEAD_LIMITS: Readonly<MappingAeadLimits> = Object.freeze({
  plaintextBytes: 65536, ciphertextBytes: 65536, keyBytes: 32, nonceBytes: 12, tagBytes: 16,
  identifierChars: 128,
});
const LIMIT = MAPPING_AEAD_LIMITS;

/** Closed outcome vocabulary. Only `SEALED` and `OPENED` are successes; the rest are refusals. */
export const MAPPING_AEAD_FINDINGS = [
  'SEALED', 'OPENED', 'INVALID_INPUT', 'INVALID_CONTEXT', 'INVALID_KEY', 'SECRET_NOT_REVERSIBLE',
  'INVALID_PAYLOAD', 'PAYLOAD_TOO_LARGE', 'INVALID_ENVELOPE', 'AUTHENTICATION_FAILED',
  'CRYPTO_UNAVAILABLE',
] as const;
export type MappingAeadFinding = (typeof MAPPING_AEAD_FINDINGS)[number];
export type MappingAeadRefusal = Exclude<MappingAeadFinding, 'SEALED' | 'OPENED'>;
export const MAPPING_AEAD_REFUSALS: readonly MappingAeadRefusal[] = Object.freeze(
  MAPPING_AEAD_FINDINGS.filter((finding): finding is MappingAeadRefusal =>
    finding !== 'SEALED' && finding !== 'OPENED'));

/** The complete scope bound into the AAD. A field is present in one serialization or in none. */
export interface MappingScope {
  tenantId: string;
  projectId: string;
  entityId: string;
  /** Accepted classification v1 vocabulary only. `CREDENTIAL_OR_SECRET` is refused outright. */
  classification: SemanticClass;
  mappingRevision: string;
  keyVersion: string;
}
export interface MappingSealRequest {
  scope: MappingScope;
  plaintext: Uint8Array;
  /** Host-supplied 32-byte data-encryption key. Held by the caller; never stored in the envelope. */
  key: Uint8Array;
}
export interface MappingOpenRequest {
  /** The expected scope, supplied independently of the ciphertext. It is the only authority. */
  scope: MappingScope;
  envelope: MappingSealedEnvelope;
  key: Uint8Array;
}
/** The sealed record: version, nonce, ciphertext and tag. It carries no key and no authority. */
export interface MappingSealedEnvelope {
  version: 1;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}
export type MappingSealResult =
  | Readonly<{ version: 1; status: 'SEALED'; finding: 'SEALED'; envelope: MappingSealedEnvelope }>
  | Readonly<{ version: 1; status: 'REFUSED'; finding: MappingAeadRefusal }>;
export type MappingOpenResult =
  | Readonly<{ version: 1; status: 'OPENED'; finding: 'OPENED'; plaintext: Uint8Array; bytes: number }>
  | Readonly<{ version: 1; status: 'REFUSED'; finding: MappingAeadRefusal }>;

// ---------------------------------------------------------------------------------------------
// Defensive structural readers. Every value crossing this boundary is treated as hostile: one
// bounded own-key snapshot, own data descriptors only, no getters, no inherited properties and no
// re-enumeration, so a time-varying Proxy cannot expand the work set or smuggle a value in. A
// reflective failure is the same fixed refusal as a malformed record, never an escaped error.
// ---------------------------------------------------------------------------------------------
type Fields = Record<string, unknown>;
/** Private brand of this module's own refusals. It is module-private, never placed on a returned
 *  result and never handed to caller code, so caller code cannot forge it. */
const REFUSAL_BRAND: unique symbol = Symbol('hylja.mapping-aead.refusal');

class Refusal extends Error {
  /** The fixed code is the whole message. No caller text, native message or cause is ever kept. */
  constructor(readonly code: MappingAeadRefusal) {
    super(code);
    this.name = 'Refusal';
  }
  /** Compared by strict equality only. This type is never recognised by a prototype walk. */
  readonly brand: typeof REFUSAL_BRAND = REFUSAL_BRAND;
}

/** Recognises one of this module's own refusals without reflection, and cannot itself throw.
 *
 *  `instanceof` walks `error.[[GetPrototypeOf]]`, so a hostile thrown `Proxy` can trap that call and
 *  throw a second time from inside our own catch block; that is how a planted error escaped this
 *  boundary before. This reads one private brand under a guard instead: a trap on that read degrades
 *  to `undefined` and the caller falls back to its fixed refusal code. The code is re-checked against
 *  the closed refusal vocabulary, so even a forged brand could only select another fixed code. */
function refusalCode(error: unknown): MappingAeadRefusal | undefined {
  try {
    if (error === null || typeof error !== 'object') return undefined;
    const candidate = error as { brand?: unknown; code?: unknown };
    if (candidate.brand !== REFUSAL_BRAND) return undefined;
    const code: unknown = candidate.code;
    return typeof code === 'string' && (MAPPING_AEAD_REFUSALS as readonly string[]).includes(code)
      ? (code as MappingAeadRefusal)
      : undefined;
  } catch {
    // Reading a property of a hostile thrown Proxy can throw again. Identification must never be able
    // to escape, so a trap here degrades to the fixed fallback refusal.
    return undefined;
  }
}
function fail(code: MappingAeadRefusal): never { throw new Refusal(code); }
function fields(value: unknown, required: readonly string[], cap: number,
  code: MappingAeadRefusal = 'INVALID_INPUT'): Fields {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail(code);
    const keys = Reflect.ownKeys(value);
    if (keys.length > cap || keys.some((key) => typeof key !== 'string')) fail(code);
    const result: Fields = Object.create(null) as Fields;
    for (const key of keys as string[]) {
      if (!required.includes(key)) fail(code);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !('value' in descriptor)) fail(code);
      result[key] = descriptor.value;
    }
    for (const name of required) if (!Object.hasOwn(result, name)) fail(code);
    return result;
  } catch (error) {
    // One of our own refusals keeps its code; anything else, including a hostile thrown Proxy, is
    // this fixed code. `refusalCode` is guarded, so this catch cannot itself throw out of the call.
    const own = refusalCode(error);
    if (own !== undefined) throw error;
    fail(code);
  }
}
/** One bounded copy of one byte source: the declared length is read once, validated as a primitive,
 *  nonnegative safe integer **before** any buffer is allocated, then each index is read exactly once,
 *  so a source that changes between reads cannot change under the copy and a lying or oversized
 *  length claim cannot buy an allocation or a bound bypass. A non-byte element is refused rather than
 *  silently coerced, and a partial copy is overwritten before it is abandoned. */
function snapshotBytes(value: unknown, maximum: number, invalid: MappingAeadRefusal,
  oversized: MappingAeadRefusal): Uint8Array {
  let copy: Uint8Array | undefined;
  try {
    if (!(value instanceof Uint8Array)) fail(invalid);
    const declared: unknown = value.byteLength;
    if (typeof declared !== 'number' || !Number.isSafeInteger(declared) || declared < 0) fail(invalid);
    if (declared > maximum) fail(oversized);
    copy = new Uint8Array(declared);
    for (let index = 0; index < declared; index += 1) {
      const byte: unknown = value[index];
      if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 0xff) fail(invalid);
      copy[index] = byte;
    }
    return copy;
  } catch (error) {
    // A rejected or half-filled copy never leaves this module uncleared.
    clear(copy);
    const own = refusalCode(error);
    if (own !== undefined) throw error;
    fail(invalid);
  }
}
function clear(bytes: Uint8Array | undefined): void { if (bytes) bytes.fill(0); }
/** Overwrites every owned buffer in one list and drops the references. Best effort, never a
 *  zeroization guarantee, and never applied to a buffer the caller supplied or one returned to it. */
function clearAll(owned: Uint8Array[]): void {
  for (const bytes of owned) bytes.fill(0);
  owned.length = 0;
}
function join(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.byteLength; }
  return out;
}
/** Identifiers are bounded tokens, not free text: an email, URL, path or planted original is
 *  structurally excluded from a field that is read verbatim into the AAD. */
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._=-]{0,127}$/u;
/** A revision is a control-plane counter and a key version a control-plane number. Neither is a
 *  name, so neither can carry a person, customer or project name into authenticated bytes. */
const REVISION = /^\d{1,12}$/u;
const KEY_VERSION = /^\d{1,12}(?:\.\d{1,12}){0,3}$/u;
const AAD_FIELDS = ['tenantId', 'projectId', 'entityId', 'classification', 'mappingRevision',
  'keyVersion'] as const;

function mappingScope(value: unknown): MappingScope {
  const v = fields(value, AAD_FIELDS, 8, 'INVALID_CONTEXT');
  const classification = v.classification;
  if (typeof classification !== 'string' || !SEMANTIC_CLASSES.includes(classification as SemanticClass)) {
    fail('INVALID_CONTEXT');
  }
  // Decision 009: credentials and secrets are not ordinary reversible synthetic identities. A
  // secret/credential class is refused here in both directions, not merely discouraged.
  if (classification === 'CREDENTIAL_OR_SECRET') fail('SECRET_NOT_REVERSIBLE');
  const token = (name: string): string => {
    const raw: unknown = v[name];
    if (typeof raw !== 'string' || !IDENTIFIER.test(raw)) fail('INVALID_CONTEXT');
    return raw;
  };
  const numeric = (name: string, pattern: RegExp): string => {
    const raw: unknown = v[name];
    if (typeof raw !== 'string' || !pattern.test(raw)) fail('INVALID_CONTEXT');
    return raw;
  };
  return Object.freeze({
    tenantId: token('tenantId'), projectId: token('projectId'), entityId: token('entityId'),
    classification: classification as SemanticClass,
    mappingRevision: numeric('mappingRevision', REVISION), keyVersion: numeric('keyVersion', KEY_VERSION),
  });
}
/** Exactly one byte string per scope: a version byte, then each field in one fixed order with a
 *  32-bit big-endian length prefix. Length prefixes make concatenation unambiguous, so no pair of
 *  field values can share one serialization, and field order is not caller-controlled. */
function canonicalAad(scope: MappingScope): Uint8Array {
  const parts = AAD_FIELDS.map((field) => encoder.encode(scope[field]));
  let total = 1;
  for (const part of parts) total += 4 + part.byteLength;
  const aad = new Uint8Array(total);
  aad[0] = MAPPING_AEAD_VERSION;
  let offset = 1;
  for (const part of parts) {
    aad[offset] = (part.byteLength >>> 24) & 0xff;
    aad[offset + 1] = (part.byteLength >>> 16) & 0xff;
    aad[offset + 2] = (part.byteLength >>> 8) & 0xff;
    aad[offset + 3] = part.byteLength & 0xff;
    aad.set(part, offset + 4);
    offset += 4 + part.byteLength;
  }
  return aad;
}
/** A 32-byte host key. An all-zero key is refused: it is empty and publicly derivable, so a
 *  ciphertext authenticating under it would authenticate nothing. Key generation, custody, rotation,
 *  wrapping and destruction are key-management obligations this module neither performs nor claims. */
function dek(value: unknown): Uint8Array {
  const key = snapshotBytes(value, LIMIT.keyBytes, 'INVALID_KEY', 'INVALID_KEY');
  try {
    if (key.byteLength !== LIMIT.keyBytes) fail('INVALID_KEY');
    let filled = false;
    for (let index = 0; index < key.byteLength && !filled; index += 1) filled = key[index] !== 0;
    if (!filled) fail('INVALID_KEY');
    return key;
  } catch (error) {
    // A rejected copy of key bytes is owned here and nowhere else, so it is overwritten here.
    clear(key);
    throw error;
  }
}
function envelopeOf(value: unknown): MappingSealedEnvelope {
  const v = fields(value, ['version', 'nonce', 'ciphertext', 'tag'], 6, 'INVALID_ENVELOPE');
  if (v.version !== MAPPING_AEAD_VERSION) fail('INVALID_ENVELOPE');
  let nonce: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  try {
    nonce = snapshotBytes(v.nonce, LIMIT.nonceBytes, 'INVALID_ENVELOPE', 'INVALID_ENVELOPE');
    tag = snapshotBytes(v.tag, LIMIT.tagBytes, 'INVALID_ENVELOPE', 'INVALID_ENVELOPE');
    ciphertext = snapshotBytes(v.ciphertext, LIMIT.ciphertextBytes, 'INVALID_ENVELOPE',
      'INVALID_ENVELOPE');
    // One sealed value is never empty: an empty payload is refused at seal time, so an empty body is
    // a malformed record rather than a valid envelope of zero bytes.
    if (nonce.byteLength !== LIMIT.nonceBytes || tag.byteLength !== LIMIT.tagBytes ||
      ciphertext.byteLength === 0) fail('INVALID_ENVELOPE');
    return Object.freeze({ version: MAPPING_AEAD_VERSION, nonce, ciphertext, tag });
  } catch (error) {
    // Snapshots taken before the malformed field are owned here; on the path that delivers nothing,
    // every one of them is overwritten.
    clear(nonce);
    clear(tag);
    clear(ciphertext);
    throw error;
  }
}

function sealWith(scope: MappingScope, key: Uint8Array, plaintext: Uint8Array): MappingSealedEnvelope {
  let aad: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  const body: Uint8Array[] = [];
  try {
    aad = canonicalAad(scope);
    nonce = snapshotBytes(randomBytes(LIMIT.nonceBytes), LIMIT.nonceBytes, 'CRYPTO_UNAVAILABLE',
      'CRYPTO_UNAVAILABLE');
    const cipher = createCipheriv(ALGORITHM, key, nonce);
    cipher.setAAD(aad, { plaintextLength: plaintext.byteLength });
    // Both cipher output buffers are owned by this call, and `join` copies them into the returned
    // ciphertext. They are therefore overwritten on the way out, success or not.
    body.push(cipher.update(plaintext));
    body.push(cipher.final());
    tag = snapshotBytes(cipher.getAuthTag(), LIMIT.tagBytes, 'CRYPTO_UNAVAILABLE',
      'CRYPTO_UNAVAILABLE');
    // On this path the nonce and tag are the returned record's own arrays, so they are not cleared.
    return Object.freeze({ version: MAPPING_AEAD_VERSION, nonce, ciphertext: join(body), tag });
  } catch {
    // Nothing is delivered on this path, so every snapshot above is an owned transient copy.
    clear(nonce);
    clear(tag);
    // A native failure is a fixed refusal here: this direction produces no plaintext, so the cause
    // carries nothing an attacker could use, and it never reaches the caller.
    fail('CRYPTO_UNAVAILABLE');
  } finally {
    clearAll(body);
    clear(aad);
  }
}
function openWith(scope: MappingScope, key: Uint8Array, envelope: MappingSealedEnvelope): Uint8Array {
  let aad: Uint8Array | undefined;
  const pending: Uint8Array[] = [];
  try {
    aad = canonicalAad(scope);
    const decipher = createDecipheriv(ALGORITHM, key, envelope.nonce);
    decipher.setAAD(aad, { plaintextLength: envelope.ciphertext.byteLength });
    // `update` returns bytes that are not yet authenticated. They are held here, never returned,
    // and overwritten unless `final` verifies the full 16-byte tag over the exact AAD.
    pending.push(decipher.update(envelope.ciphertext));
    decipher.setAuthTag(envelope.tag);
    pending.push(decipher.final());
    // `join` copies the authenticated bytes into a fresh buffer. The pending parts are this module's
    // own decipher output and are never the buffer handed back to the caller, so the finally below
    // can overwrite them on the success path as well as on every exceptional path.
    return join(pending);
  } catch {
    // Authentication failure, a wrong scope, a wrong key and a native error are one indistinguishable
    // fixed refusal. The native message and cause are never inspected, logged or returned.
    fail('AUTHENTICATION_FAILED');
  } finally {
    // Runs on the success path and on every exceptional path. `pending` holds only this call's own
    // decipher output - never a caller buffer and never the copy returned above - so this can
    // neither withhold the plaintext nor wipe the returned one.
    clearAll(pending);
    clear(aad);
  }
}

/**
 * Seals one small byte payload under one scope with one host-supplied DEK.
 *
 * The caller's bytes are snapshotted into owned buffers first, so a later mutation of the submitted
 * plaintext cannot reach the sealed record and nothing aliases a caller-owned array. A refusal never
 * throws and never returns a partial result.
 */
export function sealMappingPayload(requestValue: unknown): MappingSealResult {
  const refuse = (finding: MappingAeadRefusal): MappingSealResult =>
    Object.freeze({ version: MAPPING_AEAD_VERSION, status: 'REFUSED', finding });
  let key: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    const request = fields(requestValue, ['scope', 'plaintext', 'key'], 4);
    const target = mappingScope(request.scope);
    key = dek(request.key);
    plaintext = snapshotBytes(request.plaintext, LIMIT.plaintextBytes, 'INVALID_PAYLOAD',
      'PAYLOAD_TOO_LARGE');
    if (plaintext.byteLength === 0) fail('INVALID_PAYLOAD');
    return Object.freeze({ version: MAPPING_AEAD_VERSION, status: 'SEALED', finding: 'SEALED',
      envelope: sealWith(target, key, plaintext) });
  } catch (error) {
    // Non-reflective: see `refusalCode`. A hostile thrown Proxy is one fixed refusal, never an escape.
    return refuse(refusalCode(error) ?? 'CRYPTO_UNAVAILABLE');
  } finally {
    clear(key);
    clear(plaintext);
  }
}

/**
 * Opens one sealed record under an independently supplied expected scope and key.
 *
 * The expected scope is the only authority: no field of the ciphertext is read to decide which scope
 * to authenticate, so a transplanted, downgraded or replayed record cannot authenticate itself. A
 * valid old envelope under a matching scope still opens here; whether that mapping is current and
 * authorized is the trusted store's and broker's decision, not this primitive's.
 */
export function openMappingPayload(requestValue: unknown): MappingOpenResult {
  const refuse = (finding: MappingAeadRefusal): MappingOpenResult =>
    Object.freeze({ version: MAPPING_AEAD_VERSION, status: 'REFUSED', finding });
  let key: Uint8Array | undefined;
  let envelope: MappingSealedEnvelope | undefined;
  try {
    const request = fields(requestValue, ['scope', 'envelope', 'key'], 4);
    const expected = mappingScope(request.scope);
    key = dek(request.key);
    envelope = envelopeOf(request.envelope);
    const plaintext = openWith(expected, key, envelope);
    return Object.freeze({ version: MAPPING_AEAD_VERSION, status: 'OPENED', finding: 'OPENED',
      plaintext, bytes: plaintext.byteLength });
  } catch (error) {
    // Non-reflective: see `refusalCode`. A hostile thrown Proxy is one fixed refusal, never an escape.
    return refuse(refusalCode(error) ?? 'AUTHENTICATION_FAILED');
  } finally {
    // Owned transient copies only: the returned plaintext is a separate buffer that is never touched
    // here, and nothing the caller supplied is reachable from either copy.
    clear(key);
    if (envelope) { clear(envelope.nonce); clear(envelope.ciphertext); clear(envelope.tag); }
  }
}
