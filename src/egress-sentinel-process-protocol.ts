/**
 * Wire protocol for the optional #147 egress sentinel local child process. Pure: no child process, no
 * clock, no I/O, no randomness and no global state.
 *
 * One check is one frame in each direction over the child's stdin/stdout. The frame is a fixed magic,
 * a kind byte, a big-endian body length and a sequence of `tag | length | bytes` fields that must
 * appear in exactly the documented order. Positions rather than names carry the structure, so a
 * duplicate, reordered, unknown or truncated field cannot be represented: the decoder refuses it. A
 * missing final newline is a truncated reply and a second newline is a duplicate reply, and both are
 * separate outcomes rather than one generic parse error.
 *
 * The request carries the exact bytes to check plus an EXPLICIT known-original registration: either
 * `null` (no known originals to protect) or a bounded registration with its own tenant/project scope.
 * A process-local `KnownOriginalsHandle` is a WeakMap key and is therefore never serialized, never
 * empty-object-encoded and never silently turned into `null`; the child rebuilds its own handle from
 * the registration it was given. The parent validates that the registration scope equals the check
 * scope before it spawns anything.
 *
 * The reply carries no bytes. It echoes a binding (request id, tenant/project, observed and authorized
 * destination and profile, and a digest of the payload the child actually checked) so a replayed,
 * foreign or forged reply cannot authorize a release, plus a decision, the sentinel's own fixed reason
 * codes and finding refs. A reason that is not a fixed sentinel code, or a ref that is not one the
 * parent itself registered, is a malformed reply: no child-selected string reaches an ordinary result.
 *
 * Originals and the sentinel key exist here only as bounded copies inside local IPC. Nothing in this
 * module persists, logs or reports them, and no framing here proves heap or RSS erasure.
 */
import { sha256Hex } from './canonical-json.js';
import { MAX_MESSAGE_BYTES } from './egress-sentinel.js';

export const EGRESS_SENTINEL_PROCESS_PROTOCOL = 'hylja.egress-sentinel-process.v1' as const;

/** Every bound the parent and the child agree on. The parent caps the request before it spawns. */
export const EGRESS_SENTINEL_PROCESS_LIMITS = Object.freeze({
  /** Host-owned absolute deadline from spawn to completion. Output never resets it. */
  minDeadlineMs: 100,
  maxDeadlineMs: 600_000,
  defaultDeadlineMs: 30_000,
  defaultCleanupGraceMs: 2_000,
  maxCleanupGraceMs: 60_000,
  /** Matches the sentinel's own message cap, so an oversize message is refused before serialization. */
  maxPayloadBytes: MAX_MESSAGE_BYTES,
  maxRequestBytes: 8 << 20,
  maxResponseBytes: 1 << 20,
  maxStdoutBytes: 1 << 20,
  maxStderrBytes: 64 << 10,
  maxLabelChars: 256,
  maxProfileDigestChars: 128,
  maxKnownEntries: 4096,
  maxKnownValueChars: 4096,
  minKeyBytes: 32,
  maxKeyBytes: 64,
  maxReasons: 32,
  maxRules: 256,
});

/**
 * The reason codes `checkEgress` can return. A reply may report only these, so a child that echoes a
 * value, a path or any other free text is a malformed reply rather than a report. Adding a reason code
 * to `src/egress-sentinel.ts` requires adding it here; that is deliberate, not drift.
 */
const SENTINEL_BLOCK_REASONS: ReadonlySet<string> = new Set([
  'CANARY_DETECTED',
  'DESTINATION_MISMATCH',
  'HIGH_RISK_PATTERN',
  'INVALID_CHECK',
  'KNOWN_ORIGINALS_INVALID',
  'KNOWN_ORIGINALS_REQUIRED',
  'KNOWN_ORIGINALS_SCOPE_MISMATCH',
  'KNOWN_ORIGINAL_DETECTED',
  'MESSAGE_TOO_LARGE',
  'OPAQUE_CONTENT',
  'OPAQUE_EMBEDDED',
  'SENTINEL_BUDGET',
  'SENTINEL_ERROR',
  'UNINSPECTED_CONTENT',
]);

/** True only for a reason code this sentinel version can actually produce. */
export function isSentinelBlockReason(value: unknown): boolean {
  return typeof value === 'string' && SENTINEL_BLOCK_REASONS.has(value);
}

const MAGIC = Uint8Array.from([0x48, 0x53, 0x50, 0x50]); // "HSPP"
const KIND_REQUEST = 0x01;
const KIND_RESPONSE = 0x02;
const NEWLINE = 0x0a;
const HEADER_BYTES = MAGIC.byteLength + 5;
const FIELD_HEADER_BYTES = 5;

const F_REQUEST_ID = 1;
const F_TENANT = 2;
const F_PROJECT = 3;
const F_OBSERVED_ID = 4;
const F_OBSERVED_PROFILE = 5;
const F_AUTHORIZED_ID = 6;
const F_AUTHORIZED_PROFILE = 7;
const F_PAYLOAD = 8;
const F_KNOWN_TENANT = 9;
const F_KNOWN_PROJECT = 10;
const F_KNOWN_KEY = 11;
const F_ENTRY_KIND = 20;
const F_ENTRY_REF = 21;
const F_ENTRY_VALUE = 22;

const R_REQUEST_ID = 30;
const R_TENANT = 31;
const R_PROJECT = 32;
const R_OBSERVED_ID = 33;
const R_OBSERVED_PROFILE = 34;
const R_AUTHORIZED_ID = 35;
const R_AUTHORIZED_PROFILE = 36;
const R_PAYLOAD_DIGEST = 37;
const R_DECISION = 38;
const R_REASON_COUNT = 39;
const R_REASON = 40;
const R_RULE = 50;

const DECISION_ALLOW = 0x01;
const DECISION_BLOCK = 0x02;
const KIND_ORIGINAL = 0x01;
const KIND_CANARY = 0x02;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

const REQUEST_KEYS: ReadonlySet<string> = new Set(['bytes', 'scope', 'destination', 'authorized', 'known']);
const SCOPE_KEYS: ReadonlySet<string> = new Set(['tenantRef', 'projectRef']);
const DESTINATION_KEYS: ReadonlySet<string> = new Set(['id', 'profileDigest']);
const REGISTRATION_KEYS: ReadonlySet<string> = new Set(['scope', 'key', 'entries']);
const ENTRY_KEYS: ReadonlySet<string> = new Set(['kind', 'ref', 'value']);

/** Failure codes this pure layer can produce. Every one is restrictive at the runner boundary. */
export type SentinelProtocolFailure =
  | 'INVALID_REQUEST'
  | 'REQUEST_TOO_LARGE'
  | SentinelReplyFailure;

/** The subset of reply failures a parent runner can report verbatim as its own block code. */
export type SentinelReplyFailure =
  | 'REPLY_MALFORMED'
  | 'REPLY_TOO_LARGE'
  | 'REPLY_DUPLICATE'
  | 'REPLY_BINDING_MISMATCH';

export type SentinelProtocolResult<T, C extends SentinelProtocolFailure = SentinelProtocolFailure> =
  | Readonly<{ ok: true; value: T }>
  | Readonly<{ ok: false; code: C }>;

function failed<T, C extends SentinelProtocolFailure>(code: C): SentinelProtocolResult<T, C> {
  return Object.freeze({ ok: false as const, code });
}

/* ---------- Request snapshot: the parent's private, already-capped image ---------- */

export interface SentinelProcessScope { readonly tenantRef: string; readonly projectRef: string }
export interface SentinelProcessDestination { readonly id: string; readonly profileDigest: string }
export interface SentinelProcessKnownEntry {
  readonly kind: 'ORIGINAL' | 'CANARY';
  /** Privacy-safe label the parent chose. It is the only label a child may report back. */
  readonly ref: string;
  readonly value: string;
}
export interface SentinelProcessKnownRegistration {
  /** The registration's own scope. It must equal the check scope or the request is refused. */
  readonly scope: SentinelProcessScope;
  readonly key: Uint8Array;
  readonly entries: readonly SentinelProcessKnownEntry[];
}
export interface SentinelProcessSnapshot {
  readonly requestId: string;
  readonly scope: SentinelProcessScope;
  readonly observed: SentinelProcessDestination;
  readonly authorized: SentinelProcessDestination;
  /** A private copy of the caller's bytes. The caller holds no reference to it. */
  readonly payload: Uint8Array;
  readonly payloadDigest: string;
  /** `null` only when the caller passed an explicit `null`. */
  readonly known: SentinelProcessKnownRegistration | null;
  readonly registeredRefs: readonly string[];
}

function isLabel(value: unknown, maxChars: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxChars && value.trim() === value &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function exactKeys(value: object, allowed: ReadonlySet<string>): boolean {
  let names: string[];
  let symbols: symbol[];
  try {
    names = Object.getOwnPropertyNames(value);
    symbols = Object.getOwnPropertySymbols(value);
  } catch { return false; }
  if (symbols.length !== 0 || names.length !== allowed.size) return false;
  for (const name of names) if (!allowed.has(name)) return false;
  return true;
}

function snapshotScope(value: unknown): SentinelProcessScope | null {
  if (typeof value !== 'object' || value === null || !exactKeys(value, SCOPE_KEYS)) return null;
  const record = value as Record<string, unknown>;
  const tenantRef = record.tenantRef;
  const projectRef = record.projectRef;
  if (!isLabel(tenantRef, EGRESS_SENTINEL_PROCESS_LIMITS.maxLabelChars) ||
    !isLabel(projectRef, EGRESS_SENTINEL_PROCESS_LIMITS.maxLabelChars)) return null;
  return Object.freeze({ tenantRef, projectRef });
}

function snapshotDestination(value: unknown): SentinelProcessDestination | null {
  if (typeof value !== 'object' || value === null || !exactKeys(value, DESTINATION_KEYS)) return null;
  const record = value as Record<string, unknown>;
  const id = record.id;
  const profileDigest = record.profileDigest;
  if (!isLabel(id, EGRESS_SENTINEL_PROCESS_LIMITS.maxLabelChars) ||
    !isLabel(profileDigest, EGRESS_SENTINEL_PROCESS_LIMITS.maxProfileDigestChars)) return null;
  return Object.freeze({ id, profileDigest });
}

function sameScope(left: SentinelProcessScope, right: SentinelProcessScope): boolean {
  return left.tenantRef === right.tenantRef && left.projectRef === right.projectRef;
}

function snapshotRegistration(
  value: unknown,
  scope: SentinelProcessScope,
): SentinelProcessKnownRegistration | null | 'invalid' {
  const limits = EGRESS_SENTINEL_PROCESS_LIMITS;
  if (typeof value !== 'object' || value === null || !exactKeys(value, REGISTRATION_KEYS)) return 'invalid';
  const record = value as Record<string, unknown>;
  const ownScope = snapshotScope(record.scope);
  if (!ownScope || !sameScope(ownScope, scope)) return 'invalid';
  const key = record.key;
  // The key is capped here, before any child exists, so an undersized key cannot reach the child and
  // be reported as a crash instead of a refusal.
  if (!(key instanceof Uint8Array) || key.byteLength < limits.minKeyBytes || key.byteLength > limits.maxKeyBytes) {
    return 'invalid';
  }
  const entriesValue = record.entries;
  if (!Array.isArray(entriesValue) || entriesValue.length > limits.maxKnownEntries) {
    return 'invalid';
  }
  const entries: SentinelProcessKnownEntry[] = [];
  const refs = new Set<string>();
  for (const item of entriesValue as unknown[]) {
    if (typeof item !== 'object' || item === null || !exactKeys(item as object, ENTRY_KEYS)) return 'invalid';
    const entry = item as Record<string, unknown>;
    const kind = entry.kind;
    const ref = entry.ref;
    const text = entry.value;
    if (kind !== 'ORIGINAL' && kind !== 'CANARY') return 'invalid';
    if (!isLabel(ref, 128) || refs.has(ref)) return 'invalid';
    if (typeof text !== 'string' || text.length === 0 || text.length > limits.maxKnownValueChars) {
      return 'invalid';
    }
    refs.add(ref);
    entries.push(Object.freeze({ kind, ref, value: text }));
  }
  return Object.freeze({
    scope: ownScope,
    // A private copy: later caller mutation of the submitted key cannot reach the frame.
    key: Uint8Array.from(key),
    entries: Object.freeze(entries),
  });
}

/** Host-owned per-request id. Randomness lives in the runner; this module stays pure. */
export function newSentinelRequestId(random: Uint32Array): string {
  const a = random[0] ?? 0;
  const b = random[1] ?? 0;
  return `r${(a >>> 0).toString(16).padStart(8, '0')}${(b >>> 0).toString(16).padStart(8, '0')}`;
}

/**
 * Validate, cap and copy the whole request into the private image the child will be asked to check.
 * Anything outside the exact documented shape - an unknown key, an omitted `known`, a caller-owned
 * handle, a getter, a proxy or a nested mismatch - is refused here, before any child process exists.
 */
export function snapshotSentinelRequest(request: unknown, requestId: string): SentinelProtocolResult<SentinelProcessSnapshot> {
  const limits = EGRESS_SENTINEL_PROCESS_LIMITS;
  if (typeof request !== 'object' || request === null || !exactKeys(request, REQUEST_KEYS)) {
    return failed('INVALID_REQUEST');
  }
  const record = request as Record<string, unknown>;
  if (!isLabel(requestId, 64)) return failed('INVALID_REQUEST');
  const bytes = record.bytes;
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > limits.maxPayloadBytes) return failed('INVALID_REQUEST');
  const scope = snapshotScope(record.scope);
  if (!scope) return failed('INVALID_REQUEST');
  const observed = snapshotDestination(record.destination);
  const authorized = snapshotDestination(record.authorized);
  if (!observed || !authorized) return failed('INVALID_REQUEST');
  // An explicit `null` means "no known originals to protect". Omission, a handle, a string or any
  // other shape is refused rather than silently treated as `null`.
  const knownValue = record.known;
  let known: SentinelProcessKnownRegistration | null;
  if (knownValue === null) known = null;
  else {
    const registration = snapshotRegistration(knownValue, scope);
    if (registration === 'invalid' || registration === null) return failed('INVALID_REQUEST');
    known = registration;
  }
  // The copy is taken from the underlying buffer, never through an overridable iterator.
  const payload = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength).slice();
  const registeredRefs = known === null
    ? Object.freeze([])
    : Object.freeze(known.entries.map((entry) => entry.ref));
  return Object.freeze({
    ok: true as const,
    value: Object.freeze({
      requestId,
      scope,
      observed,
      authorized,
      payload,
      payloadDigest: sha256Hex(payload),
      known,
      registeredRefs,
    }),
  });
}

/* ---------- Framing ---------- */

class FrameWriter {
  private readonly parts: Uint8Array[] = [];
  private size = 0;

  private push(tag: number, bytes: Uint8Array): void {
    const header = new Uint8Array(FIELD_HEADER_BYTES);
    header[0] = tag;
    new DataView(header.buffer).setUint32(1, bytes.byteLength, false);
    this.parts.push(header, bytes);
    this.size += FIELD_HEADER_BYTES + bytes.byteLength;
  }

  byte(tag: number, value: number): void { this.push(tag, Uint8Array.from([value])); }

  u32(tag: number, value: number): void {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, false);
    this.push(tag, bytes);
  }

  raw(tag: number, value: Uint8Array): void { this.push(tag, value); }

  text(tag: number, value: string): void { this.push(tag, encoder.encode(value)); }

  /** MAGIC | kind | body length | body | LF. The trailing newline is what makes truncation visible. */
  finish(kind: number, maxBytes: number): Uint8Array | null {
    if (HEADER_BYTES + this.size + 1 > maxBytes) return null;
    const frame = new Uint8Array(HEADER_BYTES + this.size + 1);
    frame.set(MAGIC, 0);
    frame[4] = kind;
    new DataView(frame.buffer).setUint32(5, this.size, false);
    let at = HEADER_BYTES;
    for (const part of this.parts) { frame.set(part, at); at += part.byteLength; }
    frame[frame.byteLength - 1] = NEWLINE;
    return frame;
  }
}

type FrameStep =
  | Readonly<{ kind: 'field'; tag: number; bytes: Uint8Array }>
  | Readonly<{ kind: 'done' }>
  | Readonly<{ kind: 'bad' }>;

class FrameReader {
  private at = 0;
  private readonly view: DataView;

  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  step(): FrameStep {
    if (this.at === this.bytes.byteLength) return Object.freeze({ kind: 'done' as const });
    if (this.bytes.byteLength - this.at < FIELD_HEADER_BYTES) return Object.freeze({ kind: 'bad' as const });
    const tag = this.bytes[this.at] as number;
    const length = this.view.getUint32(this.at + 1, false);
    if (this.bytes.byteLength - this.at - FIELD_HEADER_BYTES < length) return Object.freeze({ kind: 'bad' as const });
    const start = this.at + FIELD_HEADER_BYTES;
    this.at = start + length;
    return Object.freeze({ kind: 'field' as const, tag, bytes: this.bytes.subarray(start, this.at) });
  }
}

/**
 * Read a whole frame from raw bytes, trailing newline included. Enforces magic, kind and the declared
 * length, so a truncated frame, a missing newline or trailing bytes are all refused here.
 */
function openFrame(bytes: Uint8Array, kind: number): FrameReader | null {
  if (bytes.byteLength < HEADER_BYTES + 1) return null;
  for (let index = 0; index < MAGIC.byteLength; index++) if (bytes[index] !== MAGIC[index]) return null;
  if (bytes[4] !== kind) return null;
  const declared = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(5, false);
  if (declared + HEADER_BYTES + 1 !== bytes.byteLength) return null;
  if (bytes[bytes.byteLength - 1] !== NEWLINE) return null;
  return new FrameReader(bytes.subarray(HEADER_BYTES, bytes.byteLength - 1));
}

function fieldBytes(step: FrameStep, tag: number): Uint8Array | null {
  if (step.kind !== 'field' || step.tag !== tag) return null;
  return step.bytes;
}

function fieldText(step: FrameStep, tag: number, maxChars: number): string | null {
  const bytes = fieldBytes(step, tag);
  if (bytes === null || bytes.byteLength === 0 || bytes.byteLength > maxChars * 4) return null;
  let text: string;
  try { text = decoder.decode(bytes); } catch { return null; }
  return isLabel(text, maxChars) ? text : null;
}

function fieldByte(step: FrameStep, tag: number): number | null {
  const bytes = fieldBytes(step, tag);
  if (bytes === null || bytes.byteLength !== 1) return null;
  return bytes[0] as number;
}

/** Encode the request frame, trailing newline included. Null means it exceeded `maxRequestBytes`. */
export function encodeRequestFrame(snapshot: SentinelProcessSnapshot): Uint8Array | null {
  const writer = new FrameWriter();
  writer.text(F_REQUEST_ID, snapshot.requestId);
  writer.text(F_TENANT, snapshot.scope.tenantRef);
  writer.text(F_PROJECT, snapshot.scope.projectRef);
  writer.text(F_OBSERVED_ID, snapshot.observed.id);
  writer.text(F_OBSERVED_PROFILE, snapshot.observed.profileDigest);
  writer.text(F_AUTHORIZED_ID, snapshot.authorized.id);
  writer.text(F_AUTHORIZED_PROFILE, snapshot.authorized.profileDigest);
  writer.raw(F_PAYLOAD, snapshot.payload);
  const known = snapshot.known;
  if (known !== null) {
    writer.text(F_KNOWN_TENANT, known.scope.tenantRef);
    writer.text(F_KNOWN_PROJECT, known.scope.projectRef);
    writer.raw(F_KNOWN_KEY, known.key);
    for (const entry of known.entries) {
      writer.byte(F_ENTRY_KIND, entry.kind === 'CANARY' ? KIND_CANARY : KIND_ORIGINAL);
      writer.text(F_ENTRY_REF, entry.ref);
      writer.text(F_ENTRY_VALUE, entry.value);
    }
  }
  return writer.finish(KIND_REQUEST, EGRESS_SENTINEL_PROCESS_LIMITS.maxRequestBytes);
}

/** Rebuild the check from a complete request frame. The digest is recomputed here, never trusted. */
export function decodeRequestFrame(bytes: Uint8Array): SentinelProtocolResult<SentinelProcessSnapshot> {
  const limits = EGRESS_SENTINEL_PROCESS_LIMITS;
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > limits.maxRequestBytes) return failed('REQUEST_TOO_LARGE');
  const reader = openFrame(bytes, KIND_REQUEST);
  if (reader === null) return failed('INVALID_REQUEST');
  const requestId = fieldText(reader.step(), F_REQUEST_ID, 64);
  const tenantRef = fieldText(reader.step(), F_TENANT, limits.maxLabelChars);
  const projectRef = fieldText(reader.step(), F_PROJECT, limits.maxLabelChars);
  const observedId = fieldText(reader.step(), F_OBSERVED_ID, limits.maxLabelChars);
  const observedProfile = fieldText(reader.step(), F_OBSERVED_PROFILE, limits.maxProfileDigestChars);
  const authorizedId = fieldText(reader.step(), F_AUTHORIZED_ID, limits.maxLabelChars);
  const authorizedProfile = fieldText(reader.step(), F_AUTHORIZED_PROFILE, limits.maxProfileDigestChars);
  const payload = fieldBytes(reader.step(), F_PAYLOAD);
  if (requestId === null || tenantRef === null || projectRef === null || observedId === null ||
    observedProfile === null || authorizedId === null || authorizedProfile === null || payload === null ||
    payload.byteLength > limits.maxPayloadBytes) {
    return failed('INVALID_REQUEST');
  }
  const scope = Object.freeze({ tenantRef, projectRef });
  const step = reader.step();
  let known: SentinelProcessKnownRegistration | null = null;
  if (step.kind === 'field' && step.tag === F_KNOWN_TENANT) {
    const knownTenant = fieldText(step, F_KNOWN_TENANT, limits.maxLabelChars);
    const knownProject = fieldText(reader.step(), F_KNOWN_PROJECT, limits.maxLabelChars);
    const key = fieldBytes(reader.step(), F_KNOWN_KEY);
    if (knownTenant === null || knownProject === null || key === null ||
      knownTenant !== tenantRef || knownProject !== projectRef ||
      key.byteLength < limits.minKeyBytes || key.byteLength > limits.maxKeyBytes) {
      return failed('INVALID_REQUEST');
    }
    const entries: SentinelProcessKnownEntry[] = [];
    for (;;) {
      const kindStep = reader.step();
      if (kindStep.kind === 'done') break;
      if (kindStep.kind === 'bad' || kindStep.tag !== F_ENTRY_KIND) return failed('INVALID_REQUEST');
      const kindByte = fieldByte(kindStep, F_ENTRY_KIND);
      const ref = fieldText(reader.step(), F_ENTRY_REF, 128);
      const valueStep = reader.step();
      const value = fieldText(valueStep, F_ENTRY_VALUE, limits.maxKnownValueChars);
      if ((kindByte !== KIND_ORIGINAL && kindByte !== KIND_CANARY) || ref === null || value === null) {
        return failed('INVALID_REQUEST');
      }
      if (entries.length >= limits.maxKnownEntries) return failed('INVALID_REQUEST');
      entries.push(Object.freeze({ kind: kindByte === KIND_CANARY ? 'CANARY' : 'ORIGINAL', ref, value }));
    }
    known = Object.freeze({
      scope,
      key: Uint8Array.from(key),
      entries: Object.freeze(entries),
    });
  } else if (step.kind !== 'done') {
    return failed('INVALID_REQUEST');
  }
  if (reader.step().kind !== 'done') return failed('INVALID_REQUEST');
  const payloadCopy = new Uint8Array(payload);
  return Object.freeze({
    ok: true as const,
    value: Object.freeze({
      requestId,
      scope,
      observed: Object.freeze({ id: observedId, profileDigest: observedProfile }),
      authorized: Object.freeze({ id: authorizedId, profileDigest: authorizedProfile }),
      payload: payloadCopy,
      payloadDigest: sha256Hex(payloadCopy),
      known,
      registeredRefs: Object.freeze(known === null ? [] : known.entries.map((entry) => entry.ref)),
    }),
  });
}

/* ---------- Response ---------- */

export interface SentinelProcessResponse {
  readonly decision: 'ALLOW' | 'BLOCK';
  readonly reasonCodes: readonly string[];
  readonly rules: readonly string[];
}

export interface SentinelProcessReply {
  readonly requestId: string;
  readonly tenantRef: string;
  readonly projectRef: string;
  readonly observedId: string;
  readonly observedProfileDigest: string;
  readonly authorizedId: string;
  readonly authorizedProfileDigest: string;
  readonly payloadDigest: string;
  readonly response: SentinelProcessResponse;
}

/** Encode a reply for the child. The parent re-derives every binding field and never trusts these. */
export function encodeResponseFrame(reply: SentinelProcessReply): Uint8Array | null {
  const writer = new FrameWriter();
  writer.text(R_REQUEST_ID, reply.requestId);
  writer.text(R_TENANT, reply.tenantRef);
  writer.text(R_PROJECT, reply.projectRef);
  writer.text(R_OBSERVED_ID, reply.observedId);
  writer.text(R_OBSERVED_PROFILE, reply.observedProfileDigest);
  writer.text(R_AUTHORIZED_ID, reply.authorizedId);
  writer.text(R_AUTHORIZED_PROFILE, reply.authorizedProfileDigest);
  writer.text(R_PAYLOAD_DIGEST, reply.payloadDigest);
  writer.byte(R_DECISION, reply.response.decision === 'ALLOW' ? DECISION_ALLOW : DECISION_BLOCK);
  writer.u32(R_REASON_COUNT, reply.response.reasonCodes.length);
  for (const reason of reply.response.reasonCodes) writer.text(R_REASON, reason);
  for (const rule of reply.response.rules) writer.text(R_RULE, rule);
  return writer.finish(KIND_RESPONSE, EGRESS_SENTINEL_PROCESS_LIMITS.maxResponseBytes);
}

/**
 * Validate the child's whole stdout, trailing newline included, against the request the parent
 * actually sent. A truncated reply,
 * a second reply, an unknown field, a free-text reason, a foreign ref or any binding difference is a
 * separate restrictive failure; nothing from stdout is ever echoed.
 */
export function decodeResponseFrame(
  bytes: Uint8Array,
  snapshot: SentinelProcessSnapshot,
): SentinelProtocolResult<SentinelProcessResponse, SentinelReplyFailure> {
  const limits = EGRESS_SENTINEL_PROCESS_LIMITS;
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > limits.maxResponseBytes) return failed('REPLY_TOO_LARGE');
  const reader = openFrame(bytes, KIND_RESPONSE);
  if (reader === null) return failed('REPLY_MALFORMED');
  const requestId = fieldText(reader.step(), R_REQUEST_ID, 64);
  const tenantRef = fieldText(reader.step(), R_TENANT, limits.maxLabelChars);
  const projectRef = fieldText(reader.step(), R_PROJECT, limits.maxLabelChars);
  const observedId = fieldText(reader.step(), R_OBSERVED_ID, limits.maxLabelChars);
  const observedProfile = fieldText(reader.step(), R_OBSERVED_PROFILE, limits.maxProfileDigestChars);
  const authorizedId = fieldText(reader.step(), R_AUTHORIZED_ID, limits.maxLabelChars);
  const authorizedProfile = fieldText(reader.step(), R_AUTHORIZED_PROFILE, limits.maxProfileDigestChars);
  const payloadDigest = fieldText(reader.step(), R_PAYLOAD_DIGEST, 64);
  const decision = fieldByte(reader.step(), R_DECISION);
  const countStep = reader.step();
  const countBytes = fieldBytes(countStep, R_REASON_COUNT);
  if (countBytes === null || countBytes.byteLength !== 4) return failed('REPLY_MALFORMED');
  const count = new DataView(countBytes.buffer, countBytes.byteOffset, countBytes.byteLength).getUint32(0, false);
  if (requestId === null || tenantRef === null || projectRef === null || observedId === null ||
    observedProfile === null || authorizedId === null || authorizedProfile === null || payloadDigest === null ||
    (decision !== DECISION_ALLOW && decision !== DECISION_BLOCK) ||
    count > limits.maxReasons ||
    requestId !== snapshot.requestId || tenantRef !== snapshot.scope.tenantRef ||
    projectRef !== snapshot.scope.projectRef || observedId !== snapshot.observed.id ||
    observedProfile !== snapshot.observed.profileDigest || authorizedId !== snapshot.authorized.id ||
    authorizedProfile !== snapshot.authorized.profileDigest || payloadDigest !== snapshot.payloadDigest) {
    return failed('REPLY_BINDING_MISMATCH');
  }
  const reasonCodes: string[] = [];
  for (let index = 0; index < count; index++) {
    const reason = fieldText(reader.step(), R_REASON, 64);
    if (reason === null || !isSentinelBlockReason(reason)) return failed('REPLY_MALFORMED');
    reasonCodes.push(reason);
  }
  const rules: string[] = [];
  const allowed = new Set(snapshot.registeredRefs);
  for (;;) {
    const step = reader.step();
    if (step.kind === 'done') break;
    if (step.kind === 'bad' || step.tag !== R_RULE || rules.length >= limits.maxRules) {
      return failed('REPLY_MALFORMED');
    }
    const rule = fieldText(step, R_RULE, 128);
    if (rule === null || !allowed.has(rule)) return failed('REPLY_MALFORMED');
    rules.push(rule);
  }
  // An ALLOW with a reason or a ref, or a BLOCK with neither, is internally inconsistent.
  if ((decision === DECISION_ALLOW) !== (reasonCodes.length === 0 && rules.length === 0)) {
    return failed('REPLY_MALFORMED');
  }
  return Object.freeze({
    ok: true as const,
    value: Object.freeze({
      decision: decision === DECISION_ALLOW ? 'ALLOW' : 'BLOCK',
      reasonCodes: Object.freeze(reasonCodes),
      rules: Object.freeze(rules),
    }),
  });
}

/**
 * Classify raw child stdout before parsing. A missing final newline is truncation; a second newline is
 * a duplicate reply; the two are distinct outcomes so neither hides the other.
 */
export function classifyReplyFraming(bytes: Uint8Array): 'OK' | 'REPLY_MALFORMED' | 'REPLY_DUPLICATE' {
  if (bytes.byteLength === 0) return 'REPLY_MALFORMED';
  if (bytes[bytes.byteLength - 1] !== NEWLINE) return 'REPLY_MALFORMED';
  const body = bytes.byteLength - 1;
  for (let index = 0; index < body; index++) if (bytes[index] === NEWLINE) return 'REPLY_DUPLICATE';
  return 'OK';
}