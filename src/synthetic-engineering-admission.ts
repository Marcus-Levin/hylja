/**
 * #248 bounded synthetic engineering-reference admission. Pure, NON-ENFORCING and ADVISORY ONLY.
 *
 * This module decides nothing. It reads a closed version-1 record carrying a caller's private original
 * bytes, a tenant/project `CandidateScope`, a genuine `CandidateConfigHandle`, an opaque `inputRef` and
 * an optional trusted `fieldKey`; it snapshots the bytes into one owned copy, and then asks the real
 * #8 `detectSecrets`, the real #6 `detectNormalizedCandidates` and the real v1 `composeClassification`
 * whether one whole-value configured `ENGINEERING_IDENTIFIER` corroborates a value that matches the
 * synthetic-only grammar `^SYNTHETIC-ASSET-[A-Z0-9]{1,64}$` inside at most 128 ASCII bytes.
 *
 * "Whole value" is a matched unit, not a covered one: #10 extends a template match over the rest of an
 * identifier, and this seam additionally requires the genuine matcher to report that it matched the whole
 * unit it scanned, so an unconfigured tail that coverage reached is refused instead of admitted
 * ([decision 012](../../docs/decisions/012-synthetic-engineering-custody-preconditions.md) 1).
 *
 * On success it returns owned classification and digest evidence plus a **reversible session
 * recommendation**. That recommendation is a semantic suggestion for a later owner, not a grant, not a
 * mapping, not a key, not a prepared-effect handle and not an authorization: `USE`/`KEEP` never authorize
 * `CREATE`, and a future `CREATE` needs its own closed, current, purpose-bound `MAPPING_ADMIN` approval
 * ([decision 012](../../docs/decisions/012-synthetic-engineering-custody-preconditions.md)). A semantic
 * model may classify; deterministic policy and authorization decide effects
 * ([decision 003](../../docs/decisions/003-semantic-judgment-does-not-own-effects.md)).
 *
 * The secret floor is absolute ([decision 009](../../docs/decisions/009-secrets-are-not-synthetic-identities.md)):
 * any secret or credential evidence, a secret-like trusted field context, protected evidence overlapping
 * the value, an incomplete or partial inspection, a foreign or forged configuration handle, unknown
 * sensitivity, conflicting evidence or a non-reversible composition all refuse with one fixed code,
 * regardless of scores, ordering or how much configured engineering evidence exists.
 *
 * Nothing is logged here. `sourceDigest` and `classificationDigest` are evidence bound to one private
 * original, not anonymized customer data and not authority.
 *
 * The byte boundary is honest rather than defensive prose, and it never reads a prototype. The
 * `%TypedArray%.prototype.length` accessor validates the internal slot a `Proxy` never has and is the
 * **first** thing that touches the caller's value - no brand check, prototype read or trap runs before it -
 * so proxied bytes are refused by the engine itself before any element is read. The byte **kind** is then
 * settled by `%TypedArray%.prototype[Symbol.toStringTag]`, likewise captured at module load and applied
 * directly to the value, so it answers from the same internal slot instead of from a tag a caller can write,
 * override with a getter or have a `Proxy` answer for. A genuine typed array whose own prototype is a
 * `Proxy` is therefore admitted exactly as an ordinary one is: an internal slot proves what the value is, and
 * says nothing at all about its prototype chain, so nothing here walks one. The at most 128 elements that
 * are read are each read once as a plain ASCII integer. Every caller supplied member - including the nested
 * scope and the optional `fieldKey` - is an own enumerable data descriptor, and every failure inside the
 * boundary leaves as one fixed refusal code rather than an exception carrying planted text. The owned copy
 * is zero-filled on every exit, including a failure thrown part-way through copying it.
 */
import { createHash } from 'node:crypto';
import { composeClassification, type ClassificationClaim, type ClassificationContext, type Sensitivity } from './classification.js';
import { canonicalJson, sha256Hex } from './canonical-json.js';
import type { CandidateConfigHandle, CandidateScope } from './configured-candidates.js';
import { detectNormalizedCandidates } from './normalized-detection.js';
import { detectSecrets } from './secret-detectors.js';

export const ADMISSION_PRODUCER = Object.freeze({ id: 'hylja.synthetic-engineering-admission', version: '1' });
/** The exact whole-value grammar. Nothing outside it is admitted. */
export const SYNTHETIC_REFERENCE_GRAMMAR = '^SYNTHETIC-ASSET-[A-Z0-9]{1,64}$';
/** CTO bound: the owned snapshot never exceeds this many bytes, whatever the grammar allows. */
export const MAX_SYNTHETIC_BYTES = 128;
/** Fixed refusal vocabulary. Never a value, a path, an exception or a caller's own text. */
export const ADMISSION_REFUSALS = [
  'INVALID_REQUEST', 'INVALID_ORIGINAL', 'OUT_OF_SYNTHETIC_GRAMMAR', 'INCOMPLETE_INSPECTION',
  'SECRET_EVIDENCE', 'PROTECTED_OVERLAP', 'NO_CONFIGURED_CORROBORATION', 'PARTIAL_CANDIDATE',
  'CONFLICTING_EVIDENCE', 'UNRESOLVED_CLASSIFICATION', 'UNKNOWN_SENSITIVITY', 'NOT_REVERSIBLE',
] as const;
export type AdmissionRefusal = (typeof ADMISSION_REFUSALS)[number];

export interface SyntheticAdmissionRequest {
  version: 1;
  /** The caller's private original. Snapshotted once, bounded, ASCII-only. Never echoed back. */
  original: Uint8Array;
  /** Detector scope. `tenantRef`/`projectRef` only: there is no session field in a detector scope. */
  scope: CandidateScope;
  /** Genuine handle from `createCandidateConfig` only. A forged or foreign object refuses. */
  configured: CandidateConfigHandle;
  /** Opaque source reference. A fresh value per request is what keeps evidence ids unlinkable. */
  inputRef: string;
  /** Optional trusted parser key path for `original` as a single field value. */
  fieldKey?: string;
}
export type SyntheticAdmissionResult =
  | Readonly<{ version: 1; outcome: 'REFUSED'; reason: AdmissionRefusal }>
  | Readonly<{ version: 1; outcome: 'CLASSIFIED'; semanticType: 'ENGINEERING_IDENTIFIER'; subtype: string;
    sensitivity: Sensitivity; reversibility: 'SESSION_RECOMMENDED'; sourceDigest: string; classificationDigest: string }>;

const GRAMMAR = /^SYNTHETIC-ASSET-[A-Z0-9]{1,64}$/u;
const REQUIRED = ['version', 'original', 'scope', 'configured', 'inputRef'] as const;
const OPTIONAL = ['fieldKey'] as const;
const SCOPE_MEMBERS = ['tenantRef', 'projectRef'] as const;
const INTERACTION_REF = 'synthetic-engineering-admission.v1';
const DOMAIN = 'hylja.synthetic-engineering-admission.source.v1\0';
/** A lone surrogate is not a UTF-16 string, so it never belongs in a reference, a key path or a digest. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u;

type TypedArrayLength = (this: unknown) => number;
type TypedArrayTag = (this: unknown) => unknown;
/**
 * `%TypedArray%.prototype.length`. This accessor validates the typed-array internal slot, which a `Proxy`
 * never carries: calling it on a proxy is a plain host `TypeError` from the engine itself, with no trap and
 * no caller-controlled text. It is therefore the one honest way to tell genuine owned bytes from a
 * caller-supplied look-alike before any element is read.
 */
const TYPED_ARRAY_LENGTH = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype), 'length')?.get as TypedArrayLength | undefined;
/**
 * `%TypedArray%.prototype[Symbol.toStringTag]`, captured once at module load and applied **directly to the
 * value** with `.call`. The engine answers it from the typed-array internal slot it stores for the object
 * itself: the array-type name for a genuine typed array, and `undefined` for anything that has no such slot
 * - a `Proxy`, a `DataView`, a plain object. It reads no prototype chain, so no `getPrototypeOf` trap runs
 * here and none can, and it cannot be redirected by anything a caller controls. That is exactly why neither
 * of the two readable alternatives is acceptable: `Object.prototype.toString` and an ordinary
 * `value[Symbol.toStringTag]` both report whatever tag the caller wrote, and either caller getter runs.
 */
const TYPED_ARRAY_TAG = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag)?.get as TypedArrayTag | undefined;
/** The one kind admitted: what the engine itself calls byte storage. A `Buffer` or subclass reports this too. */
const BYTE_KIND = 'Uint8Array';

function refused(reason: AdmissionRefusal): SyntheticAdmissionResult {
  return Object.freeze({ version: 1, outcome: 'REFUSED', reason });
}
function label(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value) && !LONE_SURROGATE.test(value);
}
/** The same closed boundary the record has, applied to the nested detector scope: own, enumerable, data-only. */
function closedData(object: object, allowed: readonly string[]): Record<string, unknown> | null {
  if (Array.isArray(object)) return null;
  if (object === null || typeof object !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(object))) {
    return null;
  }
  const keys = Reflect.ownKeys(object);
  if (keys.length > allowed.length) return null;
  const fields: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    // An accessor, a non-enumerable property, a symbol or an unknown member is a malformed record, never
    // a member to be quietly skipped: the descriptor is refused without the accessor being invoked.
    if (typeof key !== 'string' || !allowed.includes(key)) return null;
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return null;
    fields[key] = descriptor.value;
  }
  return fields;
}
/** Everything read from the caller is read here, once, through own enumerable data descriptors. */
function snapshot(value: unknown): { request: SyntheticAdmissionRequest | AdmissionRefusal } {
  try {
    const fields = closedData(value as object, [...REQUIRED, ...OPTIONAL]);
    if (!fields || Array.isArray(value) || value === null || typeof value !== 'object') {
      return { request: 'INVALID_REQUEST' };
    }
    if (REQUIRED.some((key) => !Object.hasOwn(fields, key))) return { request: 'INVALID_REQUEST' };
    const scope = closedData(fields.scope as object, SCOPE_MEMBERS);
    if (!scope || SCOPE_MEMBERS.some((key) => !Object.hasOwn(scope, key))) return { request: 'INVALID_REQUEST' };
    // The snapshot record itself carries a null prototype, like the `fields` it is built from. An optional
    // member the caller omitted must therefore read as `undefined` here rather than walk to
    // `Object.prototype`, where a caller-planted getter would run and answer with planted text instead of
    // the fixed refusal this module promises. No prototype chain is read at any stage, present or absent.
    const request = Object.freeze(Object.assign(Object.create(null) as Record<string, unknown>, {
      version: fields.version, original: fields.original,
      scope: Object.freeze(Object.assign(Object.create(null),
        { tenantRef: scope.tenantRef, projectRef: scope.projectRef })),
      configured: fields.configured, inputRef: fields.inputRef,
      ...(Object.hasOwn(fields, 'fieldKey') ? { fieldKey: fields.fieldKey } : {}),
    }));
    return { request: request as unknown as SyntheticAdmissionRequest };
  } catch { return { request: 'INVALID_REQUEST' }; }
}
/**
 * One owned copy of the original. The **intrinsic length accessor is the first** thing that touches the
 * caller's value: it validates the typed-array internal slot, which a `Proxy` never carries, so a proxied
 * look-alike is refused by the engine itself. Nothing runs before that refusal - no `instanceof`, no
 * prototype read, no trap - and the byte kind is then settled by the intrinsic `@@toStringTag` getter
 * applied directly to the value, which reads that same internal slot rather than any prototype chain. Both
 * answers come from the engine's own record of the object, so neither is a caller claim and neither walks
 * anything the caller chose. A `Proxy` around caller bytes therefore never reaches the copy at all: there
 * is no trap to run, no trap to throw and no element that could be answered twice with different values.
 * A genuine typed array with a caller-chosen prototype reaches it too, and reaches it identically. Each
 * element is then read exactly once and accepted only as a plain ASCII integer, so no coercion, comparison
 * or text construction can ever turn one value into another.
 *
 * Allocation and copying share **one** cleanup path. The buffer is allocated before a single byte is read,
 * so every partial state - a rejected byte, a thrown conversion, an out-of-memory allocation - is covered by
 * the same `finally`; ownership is handed to the caller only by clearing the local reference on the one
 * successful return, so a buffer the caller owns is never zero-filled and an abandoned one always is.
 */
function ownCopy(original: unknown): { bytes: Uint8Array; text: string } | AdmissionRefusal {
  let owned: Uint8Array | undefined;
  try {
    // The intrinsic length accessor is the FIRST thing that touches the caller's value. It validates the
    // typed-array internal slot, which a `Proxy` never carries, so a proxied look-alike is refused by the
    // engine itself before any brand check, prototype read or trap can run at all.
    if (!TYPED_ARRAY_LENGTH || !TYPED_ARRAY_TAG) return 'INVALID_ORIGINAL';
    const length: unknown = TYPED_ARRAY_LENGTH.call(original);
    if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 1 || length > MAX_SYNTHETIC_BYTES) {
      return 'INVALID_ORIGINAL';
    }
    // The kind, from the engine and never from the caller. A genuine internal slot says what the value is
    // and says nothing about its prototype chain, so this asks a second captured intrinsic rather than
    // walking a prototype an `instanceof` would have had to walk: a wrong typed kind, a `DataView` and a
    // plain object carrying a spoofed `Symbol.toStringTag` all refuse, while a genuine byte array is byte
    // storage whatever prototype it carries or advertises.
    const kind: unknown = TYPED_ARRAY_TAG.call(original);
    if (kind !== BYTE_KIND) return 'INVALID_ORIGINAL';
    // The `unknown` boundary is kept, not cast away: the engine's two answers are the whole narrowing this
    // seam accepts, and `typeof` is the only check left that cannot run caller code. `Reflect.get` with an
    // in-range index is the element read `original[index]` makes - the typed-array internal slot, no
    // prototype - so nothing about the copy changes.
    if (typeof original !== 'object' || original === null) return 'INVALID_ORIGINAL';
    owned = new Uint8Array(length);
    let text = '';
    for (let index = 0; index < length; index += 1) {
      const byte: unknown = Reflect.get(original, index);
      // Validated before it is stored **and** before the text is built, so the owned bytes, the owned text
      // and the digest derived from that text can never describe different values.
      if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 0x7f) return 'INVALID_ORIGINAL';
      owned[index] = byte;
      text += String.fromCharCode(byte);
    }
    const copy = { bytes: owned, text };
    owned = undefined;
    return copy;
  } catch { return 'INVALID_ORIGINAL'; }
  finally { owned?.fill(0); }
}

/**
 * Fixed refusal or owned classification/digest evidence. The returned object holds no original text, no
 * byte buffer, no caller alias and no prepared-effect handle. Owned byte copies are zero-filled on the
 * way out; that is the only cleanup claimed (no heap, GC or host-copy claim).
 */
export function inspectSyntheticEngineeringReference(value: unknown): SyntheticAdmissionResult {
  const { request } = snapshot(value);
  if (typeof request === 'string') return refused(request);
  const { original, scope, configured, inputRef, fieldKey } = request;
  if (request.version !== 1 || !label(inputRef, 1024) || !label(scope.tenantRef, 256) ||
    !label(scope.projectRef, 256) || fieldKey !== undefined && !label(fieldKey, 256)) {
    return refused('INVALID_REQUEST');
  }
  const owned = ownCopy(original);
  if (typeof owned === 'string') return refused(owned);
  const { bytes, text } = owned;
  try {
    if (!GRAMMAR.test(text)) return refused('OUT_OF_SYNTHETIC_GRAMMAR');
    // The real #8 runs first: a secret-like trusted field context, or any credential the value itself
    // carries, is the floor and nothing below it can overturn it.
    // The request handed to #8 carries a null prototype and names every member #8 destructures, itself
    // included. An absent member then reads as `undefined` rather than walking to `Object.prototype`,
    // so a caller-planted getter cannot be invoked by the detection seam on this module's behalf.
    const secrets = detectSecrets(Object.assign(Object.create(null), { text, inputRef, fieldKey }));
    if (secrets.status !== 'COMPLETE') return refused('INCOMPLETE_INSPECTION');
    if (secrets.candidates.length) return refused('SECRET_EVIDENCE');
    const detected = detectNormalizedCandidates({ input: text, inputRef, scope,
      configured: configured as CandidateConfigHandle });
    if (detected.status !== 'COMPLETE' || detected.uninspected.length) return refused('INCOMPLETE_INSPECTION');
    const records: unknown[] = [];
    let agreed: { subtype: string; sensitivity: Sensitivity } | null = null;
    for (const candidate of detected.candidates) {
      if (candidate.source !== 'CONFIGURED') return refused('PROTECTED_OVERLAP');
      if (candidate.original.kind !== 'ORIGINAL_EXACT') return refused('PARTIAL_CANDIDATE');
      if (candidate.original.span.start !== 0 || candidate.original.span.end !== text.length) {
        return refused('PARTIAL_CANDIDATE');
      }
      // #10 extends a template match over the rest of the identifier so a value is never covered in part.
      // That wider span is coverage, not corroboration: decision 012 requires the genuine source to have
      // matched the **whole unit it scanned**, so the boolean #6 reports beside the coverage must be true.
      // A candidate with no reported fact, or a false one, cannot be shown to be a whole-value match, and
      // the flag is only ever read from a configured candidate this call itself produced: the caller
      // supplies bytes, scope and a handle, never candidate evidence.
      if (candidate.wholeUnitMatch !== true) return refused('PARTIAL_CANDIDATE');
      const claim = candidate.evidence.claim;
      if (claim.sensitivity === undefined) return refused('UNKNOWN_SENSITIVITY');
      if (claim.semanticType !== 'ENGINEERING_IDENTIFIER' || !claim.subtype) return refused('PARTIAL_CANDIDATE');
      if (claim.sensitivity === 'SECRET') return refused('SECRET_EVIDENCE');
      if (agreed && (agreed.subtype !== claim.subtype || agreed.sensitivity !== claim.sensitivity)) {
        return refused('CONFLICTING_EVIDENCE');
      }
      agreed = { subtype: claim.subtype, sensitivity: claim.sensitivity };
      // #6 states the channel, not the record: this module is the detector that owns these records.
      // Exactly the five v1 evidence members cross over; the composer supplies the channel itself.
      const { version, id, status, provenance } = candidate.evidence;
      records.push(Object.freeze({ version, id, status, provenance, claim }));
    }
    if (!agreed) return refused('NO_CONFIGURED_CORROBORATION');
    // The whole-value grammar detector recommends session reversibility and carries the configured
    // sensitivity, so the real v1 composer still owns every conflict and reversal gate.
    const claim: ClassificationClaim = Object.freeze({ semanticType: 'ENGINEERING_IDENTIFIER',
      subtype: agreed.subtype, sensitivity: agreed.sensitivity, reversible: true, scope: 'session' });
    const grammar = Object.freeze({ version: 1 as const,
      id: `${ADMISSION_PRODUCER.id}.grammar.${createHash('sha256').update(inputRef).digest('hex').slice(0, 16)}`,
      provenance: Object.freeze({ inputRef, producerId: ADMISSION_PRODUCER.id, producerVersion: ADMISSION_PRODUCER.version }),
      status: 'FOUND' as const, claim });
    const context: ClassificationContext = { interactionRef: INTERACTION_REF, sourceRef: inputRef, trust: 'TRUSTED' };
    const classification = composeClassification({ detectorEvidence: [...records, grammar] }, context);
    if (classification.status !== 'RESOLVED' || classification.semanticType !== 'ENGINEERING_IDENTIFIER' ||
      classification.subtype !== agreed.subtype) return refused('UNRESOLVED_CLASSIFICATION');
    if (classification.sensitivity === 'UNKNOWN') return refused('UNKNOWN_SENSITIVITY');
    if (classification.sensitivity !== agreed.sensitivity || classification.sensitivity === 'SECRET') {
      return refused('CONFLICTING_EVIDENCE');
    }
    if (classification.reversible !== true || classification.scope !== 'session') return refused('NOT_REVERSIBLE');
    // `text` is the owned copy byte-for-byte, so this is exactly `DOMAIN || original`.
    const sourceDigest = createHash('sha256').update(`${DOMAIN}${text}`).digest('hex');
    const classificationDigest = sha256Hex(canonicalJson({ version: 1, producer: ADMISSION_PRODUCER.id,
      producerVersion: ADMISSION_PRODUCER.version, inputRef, sourceDigest, semanticType: classification.semanticType,
      subtype: classification.subtype, sensitivity: classification.sensitivity,
      reversible: classification.reversible, scope: classification.scope }));
    return Object.freeze({ version: 1, outcome: 'CLASSIFIED', semanticType: 'ENGINEERING_IDENTIFIER',
      subtype: classification.subtype, sensitivity: classification.sensitivity,
      reversibility: 'SESSION_RECOMMENDED', sourceDigest, classificationDigest });
  } catch {
    // No reflection, coercion or serialization failure may escape as an exception with planted text in it.
    return refused('INVALID_REQUEST');
  } finally { bytes.fill(0); }
}
