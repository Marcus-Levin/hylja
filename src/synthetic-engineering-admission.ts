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
const INTERACTION_REF = 'synthetic-engineering-admission.v1';
const DOMAIN = 'hylja.synthetic-engineering-admission.source.v1\0';

function refused(reason: AdmissionRefusal): SyntheticAdmissionResult {
  return Object.freeze({ version: 1, outcome: 'REFUSED', reason });
}
function label(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}
/** Everything read from the caller is read here, once, through own enumerable data descriptors. */
function snapshot(value: unknown): { request: SyntheticAdmissionRequest | AdmissionRefusal } {
  try {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return { request: 'INVALID_REQUEST' };
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) return { request: 'INVALID_REQUEST' };
    const keys = Reflect.ownKeys(value);
    const names: readonly string[] = [...REQUIRED, ...OPTIONAL];
    if (keys.length < REQUIRED.length || keys.length > names.length ||
      keys.some((key) => typeof key !== 'string' || !names.includes(key))) {
      return { request: 'INVALID_REQUEST' };
    }
    const read = (key: string): unknown => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return undefined;
      return descriptor.value;
    };
    const fields: Record<string, unknown> = { version: read('version'), original: read('original'),
      configured: read('configured'), inputRef: read('inputRef') };
    const scope = read('scope');
    if (!scope || typeof scope !== 'object') return { request: 'INVALID_REQUEST' };
    fields.scope = Object.freeze({ tenantRef: (scope as Record<string, unknown>).tenantRef,
      projectRef: (scope as Record<string, unknown>).projectRef });
    const fieldKey = read('fieldKey');
    if (fieldKey !== undefined) fields.fieldKey = fieldKey;
    return { request: fields as unknown as SyntheticAdmissionRequest };
  } catch { return { request: 'INVALID_REQUEST' }; }
}
/**
 * One owned copy of the original, taken through at most `MAX_SYNTHETIC_BYTES` typed-array element reads
 * inside a `try`. A `Proxy` may answer with the caller's own bytes inside those bounds; the copy is
 * still owned, still bounded and still never trusted as provenance.
 */
function ownCopy(original: unknown): { bytes: Uint8Array; text: string } | AdmissionRefusal {
  if (!(original instanceof Uint8Array)) return 'INVALID_ORIGINAL';
  const length = original.length;
  if (!Number.isSafeInteger(length) || length < 1 || length > MAX_SYNTHETIC_BYTES) return 'INVALID_ORIGINAL';
  const bytes = new Uint8Array(length);
  let text = '';
  for (let index = 0; index < length; index += 1) {
    const byte = original[index]!;
    if (byte < 0 || byte > 0x7f) return 'INVALID_ORIGINAL';
    bytes[index] = byte;
    text += String.fromCharCode(byte);
  }
  return { bytes, text };
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
    const secrets = detectSecrets({ text, inputRef, ...(fieldKey === undefined ? {} : { fieldKey }) });
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
  } finally { bytes.fill(0); }
}
