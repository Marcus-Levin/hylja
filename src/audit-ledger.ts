import { createHash, createHmac } from 'node:crypto';
import { SEMANTIC_CLASSES, SENSITIVITIES } from './classification.js';
import type { SemanticClass, Sensitivity } from './classification.js';
import { POLICY_TREATMENTS } from './policy.js';
import type { PolicyDecision, Treatment } from './policy.js';

/**
 * Minimal privacy-safe audit event contract and append/tamper-evidence core for issue #20.
 *
 * This is a bounded, provider-independent seam over synthetic data. It does not authenticate its
 * caller, does not grant USE/DISPLAY/EXPORT or any other permission, and never resolves, stores or
 * emits a protected original. Every failure is a fixed code: no caller text is echoed and nothing is
 * logged. Storage scope is an in-memory synthetic substrate; this is not a production durable audit
 * service and not an external checkpoint authority.
 */

export const AUDIT_SCHEMA_VERSION = 1 as const;

export const AUDIT_KINDS = [
  'CLOAK', 'POLICY_DECISION', 'AUTHORIZATION_ATTEMPT', 'MAPPING_LIFECYCLE',
  'KEY_OPERATION', 'POLICY_OPERATION',
] as const;
export type AuditKind = (typeof AUDIT_KINDS)[number];

export const AUDIT_OPERATIONS = [
  'CLOAK', 'SEND', 'USE', 'DISPLAY', 'EXPORT', 'CREATE', 'READ', 'EXPIRE', 'REVOKE', 'DELETE',
  'ROTATE', 'DESTROY', 'DEPLOY', 'UPDATE',
] as const;
export type AuditOperation = (typeof AUDIT_OPERATIONS)[number];

/** Closed kind/operation table. A reserved kind records what a later producer would record, never
 *  an effect: AUTHORIZATION_ATTEMPT and MAPPING_LIFECYCLE are schemas for #17/#18, not brokers. */
export const AUDIT_KIND_OPERATIONS: Readonly<Record<AuditKind, readonly AuditOperation[]>> = Object.freeze({
  CLOAK: ['CLOAK'],
  POLICY_DECISION: ['SEND', 'USE', 'DISPLAY', 'EXPORT'],
  AUTHORIZATION_ATTEMPT: ['USE', 'DISPLAY', 'EXPORT'],
  MAPPING_LIFECYCLE: ['CREATE', 'READ', 'EXPIRE', 'REVOKE', 'DELETE'],
  KEY_OPERATION: ['CREATE', 'ROTATE', 'DESTROY'],
  POLICY_OPERATION: ['DEPLOY', 'UPDATE'],
});

export const AUDIT_OUTCOMES = ['ALLOWED', 'DENIED', 'APPLIED'] as const;
export type AuditOutcome = (typeof AUDIT_OUTCOMES)[number];

/** Closed reason vocabulary. There is no caller-authored error or exception text anywhere. */
export const AUDIT_REASON_CODES = [
  'APPLIED', 'POLICY_ALLOWED', 'POLICY_DENIED', 'RESOLUTION_AUTHORIZED', 'RESOLUTION_DENIED',
  'LIFECYCLE_DENIED', 'ADMIN_APPLIED', 'ADMIN_DENIED',
] as const;
export type AuditReasonCode = (typeof AUDIT_REASON_CODES)[number];

/** Only these reason codes may accompany these outcomes. */
const AUDIT_OUTCOME_REASONS: Readonly<Record<AuditOutcome, readonly AuditReasonCode[]>> = Object.freeze({
  ALLOWED: ['POLICY_ALLOWED', 'RESOLUTION_AUTHORIZED'],
  DENIED: ['POLICY_DENIED', 'RESOLUTION_DENIED', 'LIFECYCLE_DENIED', 'ADMIN_DENIED'],
  APPLIED: ['APPLIED', 'ADMIN_APPLIED'],
});

export const AUDIT_BUNDLE_COMPONENTS = [
  'NORMALIZATION', 'PARSER', 'DETECTOR', 'LOCAL_CLASSIFIER', 'SEMANTIC_PROVIDER',
  'SEMANTIC_QUESTION_SET', 'CLASSIFICATION_POLICY', 'TRANSFORMATION', 'AUTHORIZATION_POLICY',
] as const;
export type AuditBundleComponent = (typeof AUDIT_BUNDLE_COMPONENTS)[number];

export const AUDIT_APPEND_FINDINGS = [
  'RECORDED', 'AUDIT_UNAVAILABLE', 'INVALID_DRAFT', 'INVALID_CONTEXT', 'INVALID_LEDGER',
  'KEY_UNAVAILABLE', 'SCOPE_MISMATCH', 'EVENT_CAPACITY',
] as const;
export type AuditAppendFinding = (typeof AUDIT_APPEND_FINDINGS)[number];

export const AUDIT_VERIFICATION_FINDINGS = [
  'VERIFIED_TO_ANCHOR', 'NO_ANCHOR', 'CHAIN_BROKEN', 'ENTRY_MISSING', 'TAIL_TRUNCATED',
  'CHECKPOINT_DIGEST_MISMATCH', 'SCOPE_MISMATCH', 'ANCHOR_INVALID', 'KEY_UNAVAILABLE',
  'INVALID_CONTEXT', 'INVALID_LEDGER',
] as const;
export type AuditVerificationFinding = (typeof AUDIT_VERIFICATION_FINDINGS)[number];

export const AUDIT_ACCESS_FINDINGS = [
  'OK', 'SCOPE_MISMATCH', 'INVALID_AUTHORITY', 'INVALID_LEDGER', 'INVALID_QUERY',
  'EXPORT_NOT_AUTHORIZED',
] as const;
export type AuditAccessFinding = (typeof AUDIT_ACCESS_FINDINGS)[number];

export interface AuditLimits {
  draftKeys: number; refs: number; identity: number; bundleComponents: number; checkpoints: number;
  ledgerEntries: number; defaultLedgerEntries: number; queryLimit: number; defaultQueryLimit: number;
  keyBytes: number;
}
/** Bounds. Every limit is enforced before allocation of proportional work. */
export const AUDIT_LIMITS: Readonly<AuditLimits> = Object.freeze({
  draftKeys: 16,
  refs: 512,
  identity: 128,
  bundleComponents: 12,
  checkpoints: 64,
  ledgerEntries: 100_000,
  defaultLedgerEntries: 4096,
  queryLimit: 1000,
  defaultQueryLimit: 100,
  keyBytes: 32,
});
const LIMIT = AUDIT_LIMITS;

const ZERO_DIGEST = '0'.repeat(64);
const DIGEST = /^[a-f0-9]{64}$/u;
/** Identity, bundle and version tokens: no '@', no '/', no ':', no whitespace, so an email, URL,
 *  host, path or free-text purpose cannot be stored in a field that is read verbatim. */
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._=-]{0,127}$/u;
/** A key version is a control-plane numeric version, not a name: this keeps key-rotation
 *  attribution exact while structurally excluding any realistic person, customer or project name. */
const KEY_VERSION = /^\d{1,12}(?:\.\d{1,12}){0,3}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const DECISION_STATES = ['DENIED', 'HELD', 'SELECTED'] as const satisfies readonly PolicyDecision['state'][];

export interface AuditScope { tenantId: string; projectId?: string }

export interface AuditActorRef {
  integrationId: string;
  /** The basis the supplying integration claims. This core records the claim and never verifies it. */
  actorBinding: 'AUTHENTICATED_UPSTREAM';
  principalId: string;
  workloadId?: string;
}

export interface AuditBundleIdentity {
  policy: { id: string; version: string; digest: string };
  components: readonly { id: AuditBundleComponent; version: string }[];
}

export interface AuditClassificationRef { semanticType: SemanticClass; sensitivity: Sensitivity }

export interface AuditEvent {
  version: 1;
  kind: AuditKind;
  operation: AuditOperation;
  outcome: AuditOutcome;
  reason: AuditReasonCode;
  occurredAt: string;
  scope: AuditScope;
  actor: AuditActorRef;
  bundle: AuditBundleIdentity;
  /** Scope-bound keyed pseudonyms. The caller's opaque reference is never stored. */
  correlationRef: string;
  entityRef?: string;
  interactionRef?: string;
  candidateRef?: string;
  keyVersion?: string;
  classification?: AuditClassificationRef;
  decision?: { state: PolicyDecision['state']; treatment: Treatment; digest: string };
}

export interface AuditEntry {
  version: 1;
  sequence: number;
  prevDigest: string;
  entryDigest: string;
  event: AuditEvent;
}

export interface AuditCheckpoint {
  version: 1;
  scope: AuditScope;
  sequence: number;
  entryDigest: string;
}

export interface AuditTrustedContext {
  version: 1;
  scope: AuditScope;
  actor: { principalId: string; workloadId?: string };
  integrationId: string;
  actorBinding: 'AUTHENTICATED_UPSTREAM';
  /** Secret, scope-bound HMAC key for reference pseudonymization. Supplied by a trusted handoff. */
  pseudonymKey: Uint8Array;
  /** Secret chain-integrity key. The ledger never retains it; verification recomputes with it. */
  chainKey: Uint8Array;
}

export interface AuditLedger {
  version: 1;
  scope: AuditScope;
  /** Plain, inspectable and mutable by anyone with host access: this structure offers no tamper
   *  resistance of its own, which is exactly why verification is anchored to retained checkpoints. */
  entries: readonly AuditEntry[];
  maxEntries: number;
  /** An integrating sink clears this when its durable store cannot commit. */
  accepting: boolean;
}

export interface AuditReceipt {
  version: 1;
  scope: AuditScope;
  sequence: number;
  entryDigest: string;
  correlationRef: string;
  occurredAt: string;
}

export interface AuditAppendResult {
  version: 1;
  status: 'RECORDED' | 'RESTRICTED';
  finding: AuditAppendFinding;
  receipt?: AuditReceipt;
}

export interface AuditVerification {
  version: 1;
  status: 'VERIFIED' | 'UNANCHORED' | 'TAMPERED' | 'UNAVAILABLE';
  finding: AuditVerificationFinding;
  entriesChecked: number;
  anchorsChecked: number;
  /** Highest sequence covered by an independently retained checkpoint. 0 means no anchor at all. */
  anchoredThrough: number;
  /** Entries newer than the newest retained checkpoint. These are not tamper-evident yet. */
  unanchoredEntries: number;
}

export interface AuditQuery {
  fromSequence?: number;
  toSequence?: number;
  kinds?: readonly AuditKind[];
  limit?: number;
}

export interface AuditAccessAuthority {
  version: 1;
  scope: AuditScope;
  principalId: string;
  /** Export is a separate, explicitly asserted permission. Reading never implies it. */
  exportAuthorized?: boolean;
}

export interface AuditReadResult {
  version: 1;
  status: 'OK' | 'RESTRICTED';
  finding: AuditAccessFinding;
  entries?: readonly AuditEntry[];
  matched: number;
  truncated: boolean;
}

export type AuditExportResult = AuditReadResult;

export interface AuditGate {
  version: 1;
  permitted: boolean;
  finding: 'EVIDENCE_RECORDED' | 'EVIDENCE_UNAVAILABLE' | 'EVIDENCE_INVALID';
}

// ---------------------------------------------------------------------------------------------
// Defensive structural readers. Every value crossing this boundary is treated as hostile: one
// bounded own-key snapshot, own data descriptors only, no getters, no inherited properties, no
// re-enumeration, so a time-varying Proxy cannot expand the work set or smuggle a value in.
// ---------------------------------------------------------------------------------------------
type Fields = Record<string, unknown>;
class Invalid extends Error { constructor(readonly code: string) { super(code); } }
function fail(code: string): never { throw new Invalid(code); }
function fields(value: unknown, required: readonly string[], optional: readonly string[],
  cap: number): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('INVALID_INPUT');
  const keys = Reflect.ownKeys(value);
  if (keys.length > cap || keys.some((key) => typeof key !== 'string')) fail('INVALID_INPUT');
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
function text(value: unknown, limit: number): string {
  if (typeof value !== 'string' || !value.length || value.length > limit ||
    value.trim() !== value || /[\u0000-\u001f\u007f]/u.test(value)) fail('INVALID_INPUT');
  return value;
}
/** A bounded identifier token, not free text. See TOKEN. */
function token(value: unknown): string {
  const result = text(value, LIMIT.identity);
  if (!TOKEN.test(result)) fail('INVALID_INPUT');
  return result;
}
/** A caller-supplied opaque reference. Validated and bounded, then immediately pseudonymized. */
function ref(value: unknown): string {
  return text(value, LIMIT.refs);
}
function keyVersion(value: unknown): string {
  const result = text(value, 48);
  if (!KEY_VERSION.test(result)) fail('INVALID_INPUT');
  return result;
}
function digest(value: unknown): string {
  const result = text(value, 64);
  if (!DIGEST.test(result)) fail('INVALID_INPUT');
  return result;
}
function member<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) fail('INVALID_INPUT');
  return value as T;
}
function items<T>(value: unknown, convert: (part: unknown) => T, limit: number,
  nonempty = false): T[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail('INVALID_INPUT');
  // The declared length is read first and bounded first: an over-long array is refused from this
  // one O(1) descriptor read, without materialising a key set proportional to it. Only a container
  // inside the length bound has its own-key set enumerated, and exactly once.
  const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (!Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > limit ||
    (nonempty && length === 0)) fail('INVALID_INPUT');
  const keys = Reflect.ownKeys(value);
  if (keys.length !== (length as number) + 1 || keys.some((key) => typeof key !== 'string') ||
    !keys.includes('length')) fail('INVALID_INPUT');
  const result: T[] = [];
  for (let i = 0; i < (length as number); i++) {
    const part = Object.getOwnPropertyDescriptor(value, String(i));
    if (!part?.enumerable || !('value' in part)) fail('INVALID_INPUT');
    result.push(convert(part.value));
  }
  return result;
}
function counter(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    fail('INVALID_INPUT');
  }
  return value as number;
}
function scope(value: unknown): AuditScope {
  const v = fields(value, ['tenantId'], ['projectId'], 4);
  return Object.freeze({ tenantId: token(v.tenantId),
    ...(Object.hasOwn(v, 'projectId') ? { projectId: token(v.projectId) } : {}) });
}
function equal(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}
function when(value: unknown): string {
  const stamp = text(value, 24);
  if (!TIMESTAMP.test(stamp) || !Number.isFinite(Date.parse(stamp))) fail('INVALID_INPUT');
  return stamp;
}
function secretKey(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength < LIMIT.keyBytes ||
    value.byteLength > 128) fail('KEY_UNAVAILABLE');
  // An all-zero key is not a key: it is empty, publicly derivable, and a chain "verified" under it
  // would authenticate nothing. That single degenerate case is refused here. Key *quality* beyond it
  // - distribution, generation, custody, rotation, destruction - stays a key-management obligation
  // this module neither performs nor claims.
  let filled = false;
  for (let i = 0; i < value.byteLength && !filled; i += 1) filled = value[i] !== 0;
  if (!filled) fail('KEY_UNAVAILABLE');
  return value;
}

function hash(value: string): string { return createHash('sha256').update(value).digest('hex'); }

/** Scope-bound, role-separated keyed pseudonym. The caller's reference is not retained anywhere. */
function pseudonym(key: Uint8Array, target: AuditScope, tag: string, raw: string): string {
  const bound = `${target.tenantId}\u0000${target.projectId ?? ''}\u0000${tag}\u0000${raw}`;
  return `${tag}_${createHmac('sha256', key).update(bound).digest('hex').slice(0, 32)}`;
}

/** Canonical, key-ordered entry preimage. Built only from normalized fields, never from caller JSON. */
function preimage(entry: { sequence: number; prevDigest: string; event: AuditEvent }): string {
  return JSON.stringify({
    version: AUDIT_SCHEMA_VERSION, sequence: entry.sequence, prevDigest: entry.prevDigest,
    event: entry.event,
  });
}
function entryDigest(chainKey: Uint8Array, body: { sequence: number; prevDigest: string; event: AuditEvent }): string {
  return createHmac('sha256', chainKey).update(preimage(body)).digest('hex');
}

// ---------------------------------------------------------------------------------------------
// Event schema. Required/optional field sets are declared per kind, so there is no shared bag of
// optional metadata and no field that any kind accepts by accident.
// ---------------------------------------------------------------------------------------------
const BASE_REQUIRED = ['version', 'kind', 'operation', 'outcome', 'reason', 'occurredAt', 'bundle',
  'correlationRef'] as const;
const REQUIRED_BY_KIND: Readonly<Record<AuditKind, readonly string[]>> = Object.freeze({
  CLOAK: [...BASE_REQUIRED, 'entityRef'],
  POLICY_DECISION: [...BASE_REQUIRED, 'decision', 'candidateRef'],
  AUTHORIZATION_ATTEMPT: [...BASE_REQUIRED, 'entityRef'],
  MAPPING_LIFECYCLE: [...BASE_REQUIRED, 'entityRef'],
  KEY_OPERATION: [...BASE_REQUIRED, 'keyVersion'],
  POLICY_OPERATION: [...BASE_REQUIRED],
});
const OPTIONAL_BY_KIND: Readonly<Record<AuditKind, readonly string[]>> = Object.freeze({
  CLOAK: ['interactionRef', 'classification'],
  POLICY_DECISION: ['interactionRef'],
  AUTHORIZATION_ATTEMPT: ['interactionRef', 'classification'],
  MAPPING_LIFECYCLE: ['interactionRef', 'classification'],
  KEY_OPERATION: [],
  POLICY_OPERATION: [],
});
/** Ref-like drafts are only accepted for kinds that legitimately reference an entity. */
const REF_FIELDS = ['entityRef', 'correlationRef', 'interactionRef', 'candidateRef'] as const;

function bundle(value: unknown): AuditBundleIdentity {
  const v = fields(value, ['policy', 'components'], [], 4);
  const p = fields(v.policy, ['id', 'version', 'digest'], [], 4);
  const components = items(v.components, (part) => {
    const c = fields(part, ['id', 'version'], [], 4);
    return { id: member(c.id, AUDIT_BUNDLE_COMPONENTS), version: token(c.version) };
  }, LIMIT.bundleComponents, true);
  const ids = components.map((component) => component.id);
  if (new Set(ids).size !== ids.length) fail('INVALID_INPUT');
  return Object.freeze({
    policy: Object.freeze({ id: token(p.id), version: token(p.version), digest: digest(p.digest) }),
    components: Object.freeze(components.sort((a, z) => (a.id < z.id ? -1 : a.id > z.id ? 1 : 0)).map(
      (component) => Object.freeze(component))) });
}
function classification(value: unknown): AuditClassificationRef {
  const v = fields(value, ['semanticType', 'sensitivity'], [], 4);
  return Object.freeze({ semanticType: member(v.semanticType, SEMANTIC_CLASSES),
    sensitivity: member(v.sensitivity, SENSITIVITIES) });
}
function decision(value: unknown): NonNullable<AuditEvent['decision']> {
  const v = fields(value, ['state', 'treatment', 'digest'], [], 4);
  return Object.freeze({ state: member(v.state, DECISION_STATES),
    treatment: member(v.treatment, POLICY_TREATMENTS), digest: digest(v.digest) });
}

/** Normalizes a caller draft into an immutable, fully privacy-safe event. */
function event(value: unknown, target: AuditScope, actor: AuditActorRef,
  trusted: { pseudonymKey: Uint8Array }): AuditEvent {
  const probe = fields(value, [], [...BASE_REQUIRED, 'entityRef', 'interactionRef', 'candidateRef',
    'keyVersion', 'classification', 'decision'], LIMIT.draftKeys);
  const kind = member(probe.kind, AUDIT_KINDS);
  const v = fields(value, REQUIRED_BY_KIND[kind], OPTIONAL_BY_KIND[kind], LIMIT.draftKeys);
  if (v.version !== AUDIT_SCHEMA_VERSION) fail('INVALID_INPUT');
  const operation = member(v.operation, AUDIT_OPERATIONS);
  if (!AUDIT_KIND_OPERATIONS[kind].includes(operation)) fail('INVALID_INPUT');
  const outcome = member(v.outcome, AUDIT_OUTCOMES);
  const reason = member(v.reason, AUDIT_REASON_CODES);
  if (!AUDIT_OUTCOME_REASONS[outcome].includes(reason)) fail('INVALID_INPUT');
  const built: AuditEvent = {
    version: AUDIT_SCHEMA_VERSION, kind, operation, outcome, reason, occurredAt: when(v.occurredAt),
    scope: target, actor, bundle: bundle(v.bundle),
    correlationRef: pseudonym(trusted.pseudonymKey, target, 'cor', ref(v.correlationRef)),
  };
  for (const field of REF_FIELDS) {
    if (!Object.hasOwn(v, field)) continue;
    const raw = ref(v[field]);
    const tag = field === 'entityRef' ? 'ent' : field === 'correlationRef' ? 'cor'
      : field === 'interactionRef' ? 'int' : 'cnd';
    Object.assign(built, { [field]: pseudonym(trusted.pseudonymKey, target, tag, raw) });
  }
  if (Object.hasOwn(v, 'keyVersion')) Object.assign(built, { keyVersion: keyVersion(v.keyVersion) });
  if (Object.hasOwn(v, 'classification')) {
    Object.assign(built, { classification: classification(v.classification) });
  }
  if (Object.hasOwn(v, 'decision')) Object.assign(built, { decision: decision(v.decision) });
  return Object.freeze(built);
}

/** Validates a stored actor record. Identity tokens are read verbatim, so the supplying integration
 *  must supply authenticated identity identifiers, never a protected original. */
function actorRef(value: unknown): AuditActorRef {
  const a = fields(value, ['integrationId', 'actorBinding', 'principalId'], ['workloadId'], 6);
  if (a.actorBinding !== 'AUTHENTICATED_UPSTREAM') fail('INVALID_INPUT');
  return Object.freeze({ integrationId: token(a.integrationId), actorBinding: 'AUTHENTICATED_UPSTREAM' as const,
    principalId: token(a.principalId),
    ...(Object.hasOwn(a, 'workloadId') ? { workloadId: token(a.workloadId) } : {}) });
}
/** The actor comes from the trusted context only: a draft can never assert who did something. */
function contextActor(c: Fields): AuditActorRef {
  if (c.actorBinding !== 'AUTHENTICATED_UPSTREAM') fail('INVALID_INPUT');
  const a = fields(c.actor, ['principalId'], ['workloadId'], 4);
  return Object.freeze({ integrationId: token(c.integrationId), actorBinding: 'AUTHENTICATED_UPSTREAM' as const,
    principalId: token(a.principalId),
    ...(Object.hasOwn(a, 'workloadId') ? { workloadId: token(a.workloadId) } : {}) });
}
const CONTEXT_KEYS = ['version', 'scope', 'actor', 'integrationId', 'actorBinding', 'pseudonymKey',
  'chainKey'] as const;
function trustedFields(contextValue: unknown): Fields {
  const c = fields(contextValue, CONTEXT_KEYS, [], 8);
  if (c.version !== AUDIT_SCHEMA_VERSION) fail('INVALID_INPUT');
  return c;
}
function trustedParts(c: Fields, target: AuditScope): {
  chainKey: Uint8Array; pseudonymKey: Uint8Array; actor: AuditActorRef;
} {
  if (!equal(scope(c.scope), target)) fail('SCOPE_MISMATCH');
  return { chainKey: secretKey(c.chainKey), pseudonymKey: secretKey(c.pseudonymKey), actor: contextActor(c) };
}

/**
 * Creates one in-memory stream for exactly one tenant/project. This is a synthetic substrate: it
 * provides no durability, no replication, no separate administrative boundary and no anchor of its
 * own. Production audit durability and the external checkpoint authority are future work.
 */
export function createInMemoryAuditLedger(scopeValue: unknown, options?: unknown): AuditLedger {
  try {
    const target = scope(scopeValue);
    let maxEntries = LIMIT.defaultLedgerEntries;
    if (options !== undefined) {
      const o = fields(options, ['maxEntries'], [], 2);
      maxEntries = counter(o.maxEntries, 1, LIMIT.ledgerEntries);
    }
    return { version: AUDIT_SCHEMA_VERSION, scope: target, entries: [], maxEntries, accepting: true };
  } catch { throw new TypeError('Invalid audit ledger scope'); }
}

/** Appends one event. Returns a typed restrictive failure; nothing here grants an effect. A receipt
 *  is issued only for a commit confirmed in this substrate, never for a reported-but-unkept write. */
export function appendAuditEvent(ledgerValue: unknown, draftValue: unknown,
  contextValue: unknown): AuditAppendResult {
  const restricted = (finding: AuditAppendFinding): AuditAppendResult =>
    ({ version: AUDIT_SCHEMA_VERSION, status: 'RESTRICTED', finding });
  let stream: StreamHead;
  try { stream = streamHead(ledgerValue); } catch { return restricted('INVALID_LEDGER'); }
  let trusted: { chainKey: Uint8Array; pseudonymKey: Uint8Array; actor: AuditActorRef };
  try {
    trusted = trustedParts(trustedFields(contextValue), stream.scope);
  } catch (error) {
    const code = error instanceof Invalid ? error.code : '';
    if (AUDIT_APPEND_FINDINGS.includes(code as AuditAppendFinding)) {
      return restricted(code as AuditAppendFinding);
    }
    return restricted('INVALID_CONTEXT');
  }
  if (!stream.accepting) return restricted('AUDIT_UNAVAILABLE');
  if (stream.length >= stream.maxEntries) return restricted('EVENT_CAPACITY');
  let built: AuditEvent;
  try {
    built = event(draftValue, stream.scope, trusted.actor, { pseudonymKey: trusted.pseudonymKey });
  } catch {
    return restricted('INVALID_DRAFT');
  }
  // All-or-nothing: the entry is fully built and authenticated before the stream is touched.
  const target = stream.scope;
  const sequence = stream.length + 1;
  const digest = entryDigest(trusted.chainKey, { sequence, prevDigest: stream.prevDigest, event: built });
  const record = Object.freeze({ version: AUDIT_SCHEMA_VERSION, sequence,
    prevDigest: stream.prevDigest, entryDigest: digest, event: built });
  // A sink that cannot commit (sealed, read-only or non-extensible array), or that reports a write
  // it did not perform, is an audit outage: not an exception the caller has to catch, and not a
  // reason to proceed unrecorded. The write into a caller-supplied container is a dynamic call that
  // can succeed and store nothing, so the commit is *confirmed* before any receipt exists: this
  // exact record must be readable at the slot it occupies in this exact array (the 0-based index
  // just below its 1-based sequence), and the array's own length must be the one value that grew by
  // one (it equals that 1-based sequence). Unconfirmed is AUDIT_UNAVAILABLE, which
  // gateHighRiskEffect never turns into `permitted`.
  const entries = stream.entries;
  try {
    entries.push(record);
    const stored = Object.getOwnPropertyDescriptor(entries, String(sequence - 1));
    const size = Object.getOwnPropertyDescriptor(entries, 'length');
    if (!stored || !('value' in stored) || stored.value !== record || !size ||
      size.value !== sequence) return restricted('AUDIT_UNAVAILABLE');
  } catch { return restricted('AUDIT_UNAVAILABLE'); }
  return { version: AUDIT_SCHEMA_VERSION, status: 'RECORDED', finding: 'RECORDED',
    receipt: Object.freeze({ version: AUDIT_SCHEMA_VERSION, scope: target, sequence,
      entryDigest: digest, correlationRef: built.correlationRef, occurredAt: built.occurredAt }) };
}

/**
 * Bounded append-path view of one stream. Only the array identity, **one** length read and the
 * entry that becomes the chain predecessor are inspected, so appending costs one event instead of
 * re-validating the whole stream; whole-stream validation is a verification/read concern, where it
 * happens once per call. The captured `entries` array and `length` are exactly the ones the append
 * pushes into and extends, never a second read of a time-varying container. The append path
 * therefore does **not** enumerate the container's own key set: doing so per event would make
 * append cost quadratic in stream length, which is itself an audit-outage risk. A container
 * carrying extra own keys is instead refused as `INVALID_LEDGER` by the paths that do enumerate it
 * (verification, checkpoint, read and export).
 *
 * Honest storage trust boundary: confirming the commit proves that this record is in **this**
 * in-memory array at **this** sequence at **this** moment. It is not external durability,
 * replication or retention, and a container that lies about both the write and the read-back cannot
 * be distinguished in language. Those remain obligations of the integrating storage adapter and its
 * commit acknowledgment.
 */
interface StreamHead {
  scope: AuditScope; entries: AuditEntry[]; maxEntries: number; accepting: boolean;
  length: number; prevDigest: string;
}
function streamHead(value: unknown): StreamHead {
  const v = fields(value, ['version', 'scope', 'entries', 'maxEntries', 'accepting'], [], 6);
  if (v.version !== AUDIT_SCHEMA_VERSION || typeof v.accepting !== 'boolean') fail('INVALID_INPUT');
  const maxEntries = counter(v.maxEntries, 1, LIMIT.ledgerEntries);
  const entries = v.entries;
  if (!Array.isArray(entries) || Object.getPrototypeOf(entries) !== Array.prototype) fail('INVALID_INPUT');
  const length: unknown = Object.getOwnPropertyDescriptor(entries, 'length')?.value;
  if (!Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > maxEntries) {
    fail('INVALID_INPUT');
  }
  const prevDigest = (length as number) === 0 ? ZERO_DIGEST
    : entry(Object.getOwnPropertyDescriptor(entries, String((length as number) - 1))?.value).entryDigest;
  return { scope: scope(v.scope), entries: entries as AuditEntry[], maxEntries, accepting: v.accepting,
    length: length as number, prevDigest };
}

/**
 * Fully validated view of one stream, used by verification, checkpoint minting and read/export.
 * Every entry is rebuilt from its own bounded descriptors, so callers receive independent frozen
 * copies rather than a live alias into the submitted ledger.
 */
interface StreamInspect {
  scope: AuditScope; entries: readonly AuditEntry[]; maxEntries: number; accepting: boolean;
}
function streamInspect(value: unknown): StreamInspect {
  const v = fields(value, ['version', 'scope', 'entries', 'maxEntries', 'accepting'], [], 6);
  if (v.version !== AUDIT_SCHEMA_VERSION || typeof v.accepting !== 'boolean') fail('INVALID_INPUT');
  const maxEntries = counter(v.maxEntries, 1, LIMIT.ledgerEntries);
  const entries = items(v.entries, (part) => entry(part), maxEntries);
  return { scope: scope(v.scope), entries, maxEntries, accepting: v.accepting };
}
function entry(value: unknown): AuditEntry {
  const v = fields(value, ['version', 'sequence', 'prevDigest', 'entryDigest', 'event'], [], 6);
  if (v.version !== AUDIT_SCHEMA_VERSION) fail('INVALID_INPUT');
  const sequence = counter(v.sequence, 1, LIMIT.ledgerEntries);
  return Object.freeze({ version: AUDIT_SCHEMA_VERSION, sequence, prevDigest: digest(v.prevDigest),
    entryDigest: digest(v.entryDigest), event: eventView(v.event) });
}
function eventView(value: unknown): AuditEvent {
  const v = fields(value, ['version', 'kind', 'operation', 'outcome', 'reason', 'occurredAt', 'scope',
    'actor', 'bundle', 'correlationRef'],
    ['entityRef', 'interactionRef', 'candidateRef', 'keyVersion', 'classification', 'decision'], 16);
  if (v.version !== AUDIT_SCHEMA_VERSION) fail('INVALID_INPUT');
  const kind = member(v.kind, AUDIT_KINDS);
  const operation = member(v.operation, AUDIT_OPERATIONS);
  if (!AUDIT_KIND_OPERATIONS[kind].includes(operation)) fail('INVALID_INPUT');
  const outcome = member(v.outcome, AUDIT_OUTCOMES);
  const reason = member(v.reason, AUDIT_REASON_CODES);
  if (!AUDIT_OUTCOME_REASONS[outcome].includes(reason)) fail('INVALID_INPUT');
  const built: AuditEvent = { version: AUDIT_SCHEMA_VERSION, kind, operation, outcome, reason,
    occurredAt: when(v.occurredAt), scope: scope(v.scope), actor: actorRef(v.actor), bundle: bundle(v.bundle),
    correlationRef: pseudonymText(v.correlationRef, 'cor') };
  for (const [field, tag] of [['entityRef', 'ent'], ['interactionRef', 'int'],
    ['candidateRef', 'cnd']] as const) {
    if (Object.hasOwn(v, field)) Object.assign(built, { [field]: pseudonymText(v[field], tag) });
  }
  if (Object.hasOwn(v, 'keyVersion')) Object.assign(built, { keyVersion: keyVersion(v.keyVersion) });
  if (Object.hasOwn(v, 'classification')) Object.assign(built, { classification: classification(v.classification) });
  if (Object.hasOwn(v, 'decision')) Object.assign(built, { decision: decision(v.decision) });
  return Object.freeze(built);
}
function pseudonymText(value: unknown, tag: string): string {
  const result = text(value, tag.length + 34);
  if (result.length !== tag.length + 33 || !result.startsWith(`${tag}_`) ||
    !/^[a-f0-9]{32}$/u.test(result.slice(tag.length + 1))) fail('INVALID_INPUT');
  return result;
}

/**
 * Produces the anchor record that an **independently retained** store must hold. The ledger never
 * keeps it: an anchor held only inside the ledger proves nothing.
 */
export function createAuditCheckpoint(ledgerValue: unknown, contextValue: unknown, sequence?: unknown): AuditCheckpoint {
  try {
    const stream = streamInspect(ledgerValue);
    // The chain key is required here so an unprivileged caller cannot mint anchors; it is dropped.
    trustedParts(trustedFields(contextValue), stream.scope);
    const wanted = sequence === undefined ? stream.entries.length
      : counter(sequence, 1, LIMIT.ledgerEntries);
    const found = stream.entries.find((item) => item.sequence === wanted);
    if (!found) fail('INVALID_INPUT');
    return Object.freeze({ version: AUDIT_SCHEMA_VERSION, scope: stream.scope, sequence: wanted,
      entryDigest: found.entryDigest });
  } catch { throw new TypeError('Invalid audit ledger state'); }
}

function anchor(value: unknown): AuditCheckpoint {
  const v = fields(value, ['version', 'scope', 'sequence', 'entryDigest'], [], 6);
  if (v.version !== AUDIT_SCHEMA_VERSION) fail('INVALID_INPUT');
  return { version: AUDIT_SCHEMA_VERSION, scope: scope(v.scope),
    sequence: counter(v.sequence, 1, LIMIT.ledgerEntries), entryDigest: digest(v.entryDigest) };
}
function verification(status: AuditVerification['status'], finding: AuditVerificationFinding,
  entriesChecked = 0, anchorsChecked = 0, anchoredThrough = 0): AuditVerification {
  return { version: AUDIT_SCHEMA_VERSION, status, finding, entriesChecked, anchorsChecked,
    anchoredThrough, unanchoredEntries: entriesChecked - anchoredThrough };
}

/**
 * Verifies a stream against independently retained checkpoints.
 *
 * Internal chain integrity alone is **not** tamper evidence: it detects modification of entries the
 * attacker could not re-key, but a party holding the chain key can rewrite a whole stream, and no
 * check inside the ledger can see the difference. Only an anchor the ledger does not control can.
 * `UNANCHORED` is therefore the honest answer for a consistent stream with no retained checkpoint.
 */
export function verifyAuditStream(ledgerValue: unknown, contextValue: unknown,
  checkpoints: unknown): AuditVerification {
  let stream: StreamInspect;
  try { stream = streamInspect(ledgerValue); } catch { return verification('UNAVAILABLE', 'INVALID_LEDGER'); }
  let chainKey: Uint8Array;
  try {
    chainKey = trustedParts(trustedFields(contextValue), stream.scope).chainKey;
  } catch (error) {
    const code = error instanceof Invalid ? error.code : '';
    if (code === 'KEY_UNAVAILABLE') return verification('UNAVAILABLE', 'KEY_UNAVAILABLE');
    return verification('UNAVAILABLE', 'INVALID_CONTEXT');
  }
  let anchors: AuditCheckpoint[];
  try {
    anchors = items(checkpoints, anchor, LIMIT.checkpoints);
  } catch {
    return verification('UNAVAILABLE', 'ANCHOR_INVALID');
  }
  const entries = stream.entries;
  if (anchors.some((item, index) => index > 0 && item.sequence <= anchors[index - 1]!.sequence)) {
    return verification('UNAVAILABLE', 'ANCHOR_INVALID');
  }
  if (anchors.some((item) => !equal(item.scope, stream.scope))) {
    return verification('TAMPERED', 'SCOPE_MISMATCH', entries.length, anchors.length);
  }
  // A tenant-substituted entry cannot pass scope congruence, and its re-keyed digest still fails.
  if (entries.some((item) => !equal(item.event.scope, stream.scope))) {
    return verification('TAMPERED', 'SCOPE_MISMATCH', entries.length, anchors.length);
  }
  for (const item of anchors) {
    const found = entries.find((candidate) => candidate.sequence === item.sequence);
    if (!found) {
      return verification('TAMPERED', item.sequence > entries.length ? 'TAIL_TRUNCATED'
        : 'ENTRY_MISSING', entries.length, anchors.length);
    }
    if (found.entryDigest !== item.entryDigest) {
      return verification('TAMPERED', 'CHECKPOINT_DIGEST_MISMATCH', entries.length, anchors.length);
    }
  }
  let prevDigest = ZERO_DIGEST;
  for (let i = 0; i < entries.length; i += 1) {
    const item = entries[i]!;
    if (item.sequence !== i + 1 || item.prevDigest !== prevDigest ||
      entryDigest(chainKey, item) !== item.entryDigest) {
      return verification('TAMPERED', 'CHAIN_BROKEN', entries.length, anchors.length);
    }
    prevDigest = item.entryDigest;
  }
  const anchoredThrough = anchors.length ? anchors[anchors.length - 1]!.sequence : 0;
  return anchors.length
    ? verification('VERIFIED', 'VERIFIED_TO_ANCHOR', entries.length, anchors.length, anchoredThrough)
    : verification('UNANCHORED', 'NO_ANCHOR', entries.length, 0, 0);
}

function authority(value: unknown, exporting: boolean): AuditAccessAuthority {
  const v = fields(value, ['version', 'scope', 'principalId'], exporting ? ['exportAuthorized'] : [], 6);
  if (v.version !== AUDIT_SCHEMA_VERSION) fail('INVALID_INPUT');
  if (Object.hasOwn(v, 'exportAuthorized') && v.exportAuthorized !== true) fail('INVALID_INPUT');
  if (exporting && v.exportAuthorized !== true) fail('NOT_EXPORT_AUTHORIZED');
  return { version: AUDIT_SCHEMA_VERSION, scope: scope(v.scope), principalId: token(v.principalId),
    ...(Object.hasOwn(v, 'exportAuthorized') ? { exportAuthorized: true as const } : {}) };
}
interface BoundedQuery {
  fromSequence: number; toSequence: number; kinds: readonly AuditKind[] | undefined; limit: number;
}
function query(value: unknown): BoundedQuery {
  const v = fields(value, [], ['fromSequence', 'toSequence', 'kinds', 'limit'], 6);
  const fromSequence = Object.hasOwn(v, 'fromSequence') ? counter(v.fromSequence, 1, LIMIT.ledgerEntries) : 1;
  const toSequence = Object.hasOwn(v, 'toSequence') ? counter(v.toSequence, 1, LIMIT.ledgerEntries)
    : LIMIT.ledgerEntries;
  const limit = Object.hasOwn(v, 'limit') ? counter(v.limit, 1, LIMIT.queryLimit)
    : LIMIT.defaultQueryLimit;
  let kinds: readonly AuditKind[] | undefined;
  if (Object.hasOwn(v, 'kinds')) {
    const chosen = items(v.kinds, (part) => member(part, AUDIT_KINDS), AUDIT_KINDS.length, true);
    if (new Set(chosen).size !== chosen.length) fail('INVALID_INPUT');
    kinds = chosen;
  }
  if (fromSequence > toSequence) fail('INVALID_INPUT');
  return { fromSequence, toSequence, kinds, limit };
}
function select(entries: readonly AuditEntry[], q: BoundedQuery): { entries: AuditEntry[]; matched: number } {
  const matched = entries.filter((item) => item.sequence >= q.fromSequence &&
    item.sequence <= q.toSequence && (!q.kinds || q.kinds.includes(item.event.kind)));
  // Already independent frozen copies from the bounded snapshot: a read result cannot be used to
  // reach back into the submitted ledger or into another reader's result.
  return { entries: matched.slice(0, q.limit), matched: matched.length };
}

/**
 * Bounded, scope-isolated read of one tenant/project stream. Scope isolation is enforced **per
 * entry** against the trusted access scope, not merely against the ledger's declared label, so a
 * relabelled or partly substituted stream returns no entry at all. There is no cross-tenant listing
 * and no bulk API of any kind: the ledger holds pseudonyms and privacy-safe metadata, never
 * originals.
 */
export function readAuditEvents(ledgerValue: unknown, authorityValue: unknown,
  queryValue: unknown): AuditReadResult {
  return access(ledgerValue, authorityValue, queryValue, false);
}

/** Export is a separately asserted permission over the same scope-isolated, bounded selection. */
export function exportAuditEvents(ledgerValue: unknown, authorityValue: unknown,
  queryValue: unknown): AuditExportResult {
  return access(ledgerValue, authorityValue, queryValue, true);
}
function access(ledgerValue: unknown, authorityValue: unknown, queryValue: unknown,
  exporting: boolean): AuditReadResult {
  const denied = (finding: AuditAccessFinding): AuditReadResult =>
    ({ version: AUDIT_SCHEMA_VERSION, status: 'RESTRICTED', finding, matched: 0, truncated: false });
  let snapshot: StreamInspect;
  try { snapshot = streamInspect(ledgerValue); } catch { return denied('INVALID_LEDGER'); }
  let a: AuditAccessAuthority;
  try { a = authority(authorityValue, exporting); } catch (error) {
    const code = error instanceof Invalid ? error.code : 'INVALID_AUTHORITY';
    if (code === 'NOT_EXPORT_AUTHORIZED') return denied('EXPORT_NOT_AUTHORIZED');
    return denied('INVALID_AUTHORITY');
  }
  if (!equal(a.scope, snapshot.scope)) return denied('SCOPE_MISMATCH');
  // Per-entry scope congruence, the same guard verifyAuditStream applies, checked against the
  // trusted access scope before any selection: a ledger relabelled to another tenant, or one stream
  // with a single substituted entry, discloses neither the foreign events nor any foreign metadata
  // (pseudonyms, digests, actor or bundle identity). One foreign entry denies the whole read.
  if (snapshot.entries.some((item) => !equal(item.event.scope, a.scope))) {
    return denied('SCOPE_MISMATCH');
  }
  let q: BoundedQuery;
  try { q = query(queryValue); } catch { return denied('INVALID_QUERY'); }
  const selected = select(snapshot.entries, q);
  return { version: AUDIT_SCHEMA_VERSION, status: 'OK', finding: 'OK', entries: selected.entries,
    matched: selected.matched, truncated: selected.matched > selected.entries.length };
}

/**
 * Converts an append result into the audit precondition for a dependent high-risk effect. A
 * `permitted` result means only that the required evidence was recorded: it is never an
 * authorization to resolve, reveal, release, transform or send anything.
 *
 * Stated limit: this is a pure structural check on the value it is handed. It cannot bind a receipt
 * to an entry that is actually committed in a stream, so a caller that fabricates or replays a
 * `RECORDED` result gets `permitted: true`. The integrating effect must therefore pass the result it
 * received **directly** from `appendAuditEvent`, in the same process, without re-serializing,
 * caching across tenants or reconstructing it. A caller able to call this function with invented
 * input can satisfy the precondition; that is an obligation on the call site, not something this
 * module can prove.
 */
export function gateHighRiskEffect(result: unknown): AuditGate {
  try {
    const v = fields(result, ['version', 'status', 'finding'], ['receipt'], 6);
    if (v.version !== AUDIT_SCHEMA_VERSION) fail('INVALID_INPUT');
    const status = member(v.status, ['RECORDED', 'RESTRICTED']);
    const finding = member(v.finding, AUDIT_APPEND_FINDINGS);
    if (status === 'RECORDED' && finding !== 'RECORDED') fail('INVALID_INPUT');
    const receipt = status === 'RECORDED' ? receiptOf(v.receipt) : undefined;
    if (status === 'RECORDED' && !receipt) fail('INVALID_INPUT');
    if (finding === 'AUDIT_UNAVAILABLE') {
      return { version: AUDIT_SCHEMA_VERSION, permitted: false, finding: 'EVIDENCE_UNAVAILABLE' };
    }
    return { version: AUDIT_SCHEMA_VERSION, permitted: status === 'RECORDED',
      finding: status === 'RECORDED' ? 'EVIDENCE_RECORDED' : 'EVIDENCE_INVALID' };
  } catch {
    return { version: AUDIT_SCHEMA_VERSION, permitted: false, finding: 'EVIDENCE_INVALID' };
  }
}
function receiptOf(value: unknown): AuditReceipt | undefined {
  try {
    const v = fields(value, ['version', 'scope', 'sequence', 'entryDigest', 'correlationRef',
      'occurredAt'], [], 8);
    if (v.version !== AUDIT_SCHEMA_VERSION) return undefined;
    return { version: AUDIT_SCHEMA_VERSION, scope: scope(v.scope),
      sequence: counter(v.sequence, 1, LIMIT.ledgerEntries), entryDigest: digest(v.entryDigest),
      correlationRef: pseudonymText(v.correlationRef, 'cor'), occurredAt: when(v.occurredAt) };
  } catch { return undefined; }
}

/** Exact, deterministic serialization of one entry. Fixed key order; no caller text can vary it. */
export function serializeAuditEntry(value: unknown): string {
  try { return preimage(entry(value)); } catch { throw new TypeError('Invalid audit entry'); }
}
export function serializeAuditCheckpoint(value: unknown): string {
  try { return JSON.stringify(anchor(value)); } catch { throw new TypeError('Invalid audit checkpoint'); }
}

/**
 * Content commitment over an exact intelligence-bundle identity. Unkeyed replay commitment, not an
 * authorization token: only a digest pinned independently by the trusted control plane is
 * authoritative, and computing it from an attacker-supplied bundle proves nothing.
 */
export function digestAuditBundle(value: unknown): string {
  try { return hash(JSON.stringify(bundle(value))); } catch { throw new TypeError('Invalid audit bundle'); }
}