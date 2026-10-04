/**
 * Wire protocol for the optional #147 egress sentinel local child process. Pure: no child process, no
 * clock, no I/O, no randomness and no global state.
 *
 * One check is one frame in each direction over the child's stdin/stdout. The frame is a fixed magic,
 * a kind byte, a big-endian body length and a sequence of `tag | length | bytes` fields that must
 * appear in exactly the documented order. Positions rather than names carry the structure, so a
 * duplicate, reordered, unknown or truncated field cannot be represented: the decoder refuses it. The
 * frame is BINARY and length-delimited, not newline-delimited text: only the single trailing byte
 * after the declared body is a newline, so a length field, an id or a payload byte that happens to be
 * `0x0a` is ordinary data. A body shorter than the declared length, or a missing trailing newline, is
 * a truncated reply; bytes past one complete frame are a duplicate reply or extra trailing output,
 * and all three are separate restrictive outcomes rather than one generic parse error.
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
 * Caller-supplied byte arrays are admitted and copied through captured standard intrinsics only. Byte
 * identity and length come from the typed array's own internal slots, never from a caller property,
 * method, iterator or prototype lookup, so an own `byteLength`, `set` or `Symbol.iterator` accessor is
 * ignored rather than called. This is a local wrapper boundary, not a JavaScript sandbox.
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

/**
 * Copy the exact own DATA properties of a caller object into a bounded map.
 *
 * Names alone are not a sufficient check: an accessor can be an own enumerable property whose name
 * matches and whose value only exists if it is invoked. So each accepted property is copied through
 * `getOwnPropertyDescriptor`, an accessor or a symbol is refused without being read, and every
 * reflection call is contained - a `Proxy` trap that throws produces a refusal, never an exception
 * that escapes into the caller.
 */
function ownDataProperties(value: unknown, allowed: ReadonlySet<string>): Map<string, unknown> | null {
  if (typeof value !== 'object' || value === null) return null;
  let names: string[];
  let symbols: symbol[];
  try {
    names = Object.getOwnPropertyNames(value);
    symbols = Object.getOwnPropertySymbols(value);
  } catch { return null; }
  if (symbols.length !== 0 || names.length !== allowed.size) return null;
  const out = new Map<string, unknown>();
  for (const name of names) {
    if (!allowed.has(name)) return null;
    let descriptor: PropertyDescriptor | undefined;
    try { descriptor = Object.getOwnPropertyDescriptor(value, name); } catch { return null; }
    if (descriptor === undefined || !('value' in descriptor)) return null;
    out.set(name, descriptor.value);
  }
  return out;
}

/**
 * The captured `%TypedArray%.prototype.byteLength` accessor.
 *
 * `byteLength` is an ordinary prototype accessor, so `bytes.byteLength` executes any own accessor a
 * caller defined on an otherwise genuine array - and that code runs BEFORE any restriction exists,
 * where containment cannot retract what it already disclosed. Calling the intrinsic accessor with the
 * value as `this` reads the typed array's own length slot instead: a `Proxy`, a plain object and a
 * detached or tampered buffer have no such slot and raise a TypeError, and no caller property,
 * method, iterator or prototype lookup runs on the way there.
 */
const TYPED_ARRAY_PROTOTYPE: object = Object.getPrototypeOf(Uint8Array.prototype);
/** The one byte prototype a caller array must actually have, captured before any call arrives. */
const UINT8_ARRAY_PROTOTYPE: object = Uint8Array.prototype;
const TYPED_BYTE_LENGTH_DESCRIPTOR: PropertyDescriptor | undefined =
  Object.getOwnPropertyDescriptor(TYPED_ARRAY_PROTOTYPE, 'byteLength');

function noTypedByteLength(): never {
  throw new TypeError('the typed array byteLength accessor is unavailable');
}

const TYPED_BYTE_LENGTH: () => number =
  TYPED_BYTE_LENGTH_DESCRIPTOR === undefined || TYPED_BYTE_LENGTH_DESCRIPTOR.get === undefined
    ? noTypedByteLength
    : TYPED_BYTE_LENGTH_DESCRIPTOR.get;

/** Byte length of a byte array already known to be one, read from internal state only. */
function byteArrayLength(bytes: Uint8Array): number {
  return Reflect.apply(TYPED_BYTE_LENGTH, bytes, []);
}

/**
 * True only for genuine byte identity.
 *
 * Step one is a trap-free brand check: the captured `Uint8Array.prototype.slice` requires typed array
 * internal slots on its receiver, so a `Proxy` fails it before any `get`, `has`, `ownKeys`,
 * `getOwnPropertyDescriptor` or `getPrototypeOf` trap of its own can run. Step two reads the prototype
 * only after that check has established a genuine typed array, where no caller code and no trap is
 * reachable, so a narrow view, a subclass instance and a re-prototyped array are refused rather than
 * silently converted, and only an actual `Uint8Array` is admitted.
 *
 * This is a local wrapper check, not a sandbox. It does not make in-process inspection safe against
 * arbitrary hostile JavaScript and does not defend against global intrinsic tampering.
 */
function isByteArray(value: unknown): value is Uint8Array {
  try {
    Reflect.apply(Uint8Array.prototype.slice, value, [0, 0]);
    return Object.getPrototypeOf(value) === UINT8_ARRAY_PROTOTYPE;
  } catch { return false; }
}

/**
 * Copy caller bytes through public standard intrinsics only. `slice`, `set`, `subarray` and any
 * iterator are all overridable per instance, so none of them is reachable through the caller's own
 * object: the length comes from the intrinsic length slot and the copy is written into a buffer this
 * module allocated.
 */
function copyBytes(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(byteArrayLength(bytes));
  out.set(bytes);
  return out;
}

/**
 * Indexed, bounded snapshot of a caller array. Reading `length` and then each index descriptor avoids
 * a caller iterator, a caller `Symbol.iterator`, an accessor element and a sparse hole: any of those
 * is refused here rather than executed.
 */
function ownIndexedItems(value: unknown, maxEntries: number): unknown[] | null {
  if (!Array.isArray(value)) return null;
  let length: number;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (descriptor === undefined || !('value' in descriptor) || typeof descriptor.value !== 'number') return null;
    length = descriptor.value;
    if (!Number.isSafeInteger(length) || length < 0 || length > maxEntries) return null;
    if (Object.getOwnPropertyNames(value).length !== length + 1) return null;
  } catch { return null; }
  const items: unknown[] = [];
  try {
    for (let index = 0; index < length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !('value' in descriptor)) return null;
      items.push(descriptor.value);
    }
  } catch { return null; }
  return items;
}

function snapshotScope(value: unknown): SentinelProcessScope | null {
  const record = ownDataProperties(value, SCOPE_KEYS);
  if (record === null) return null;
  const tenantRef = record.get('tenantRef');
  const projectRef = record.get('projectRef');
  if (!isLabel(tenantRef, EGRESS_SENTINEL_PROCESS_LIMITS.maxLabelChars) ||
    !isLabel(projectRef, EGRESS_SENTINEL_PROCESS_LIMITS.maxLabelChars)) return null;
  return Object.freeze({ tenantRef, projectRef });
}

function snapshotDestination(value: unknown): SentinelProcessDestination | null {
  const record = ownDataProperties(value, DESTINATION_KEYS);
  if (record === null) return null;
  const id = record.get('id');
  const profileDigest = record.get('profileDigest');
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
  const record = ownDataProperties(value, REGISTRATION_KEYS);
  if (record === null) return 'invalid';
  const ownScope = snapshotScope(record.get('scope'));
  if (!ownScope || !sameScope(ownScope, scope)) return 'invalid';
  const key = record.get('key');
  // The key is capped here, before any child exists, so an undersized key cannot reach the child and
  // be reported as a crash instead of a refusal. The cap reads the intrinsic length slot, so a caller
  // accessor named `byteLength` is not invoked to make this decision.
  if (!isByteArray(key)) return 'invalid';
  const keyLength = byteArrayLength(key);
  if (keyLength < limits.minKeyBytes || keyLength > limits.maxKeyBytes) return 'invalid';
  const items = ownIndexedItems(record.get('entries'), limits.maxKnownEntries);
  if (items === null) return 'invalid';
  const entries: SentinelProcessKnownEntry[] = [];
  const refs = new Set<string>();
  for (const item of items) {
    const entry = ownDataProperties(item, ENTRY_KEYS);
    if (entry === null) return 'invalid';
    const kind = entry.get('kind');
    const ref = entry.get('ref');
    // An original value is CONTENT, not an identifier: bounded, non-empty UTF-8 text whose newlines,
    // spaces and tabs are ordinary data. Only labels and refs are restricted to identifier shape.
    const text = entry.get('value');
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
    key: copyBytes(key),
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
  // Every reflection step above is already bounded, but this boundary is caller-supplied and therefore
  // hostile by assumption: a planted exception anywhere in the inspection is contained here and
  // reported as the same fixed refusal, never propagated into a synchronous throw out of `check`.
  try {
    return snapshotSentinelRequestRefused(request, requestId);
  } catch { return failed('INVALID_REQUEST'); }
}

function snapshotSentinelRequestRefused(
  request: unknown,
  requestId: string,
): SentinelProtocolResult<SentinelProcessSnapshot> {
  const limits = EGRESS_SENTINEL_PROCESS_LIMITS;
  const record = ownDataProperties(request, REQUEST_KEYS);
  if (record === null) return failed('INVALID_REQUEST');
  if (!isLabel(requestId, 64)) return failed('INVALID_REQUEST');
  const bytes = record.get('bytes');
  // Admitted by native brand, never by a caller property: `instanceof` would walk a `Proxy`'s
  // prototype trap and `bytes.byteLength` would run a caller accessor.
  if (!isByteArray(bytes)) return failed('INVALID_REQUEST');
  if (byteArrayLength(bytes) > limits.maxPayloadBytes) return failed('INVALID_REQUEST');
  const scope = snapshotScope(record.get('scope'));
  if (!scope) return failed('INVALID_REQUEST');
  const observed = snapshotDestination(record.get('destination'));
  const authorized = snapshotDestination(record.get('authorized'));
  if (!observed || !authorized) return failed('INVALID_REQUEST');
  // An explicit `null` means "no known originals to protect". Omission, a handle, a string or any
  // other shape is refused rather than silently treated as `null`.
  const knownValue = record.get('known');
  let known: SentinelProcessKnownRegistration | null;
  if (knownValue === null) known = null;
  else {
    const registration = snapshotRegistration(knownValue, scope);
    if (registration === 'invalid' || registration === null) return failed('INVALID_REQUEST');
    known = registration;
  }
  // Copied through public intrinsics, never through a caller-overridable method or iterator.
  const payload = copyBytes(bytes);
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

/**
 * Original and canary VALUE text, decoded separately from every identifier.
 *
 * A value is content: strict UTF-8, non-empty and bounded, but newlines, spaces and tabs are ordinary
 * data and are preserved byte for byte. Only labels, refs, digests and reason codes go through
 * `isLabel`; applying an identifier restriction here made a valid multiline original fail to decode.
 */
function fieldContent(step: FrameStep, tag: number, maxChars: number): string | null {
  const bytes = fieldBytes(step, tag);
  if (bytes === null || bytes.byteLength === 0 || bytes.byteLength > maxChars * 4) return null;
  let text: string;
  try { text = decoder.decode(bytes); } catch { return null; }
  return text.length > 0 && text.length <= maxChars ? text : null;
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
      const value = fieldContent(valueStep, F_ENTRY_VALUE, limits.maxKnownValueChars);
      if ((kindByte !== KIND_ORIGINAL && kindByte !== KIND_CANARY) || ref === null || value === null) {
        return failed('INVALID_REQUEST');
      }
      if (entries.length >= limits.maxKnownEntries) return failed('INVALID_REQUEST');
      entries.push(Object.freeze({ kind: kindByte === KIND_CANARY ? 'CANARY' : 'ORIGINAL', ref, value }));
    }
    known = Object.freeze({
      scope,
      key: copyBytes(key),
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
 * Classify raw child stdout before parsing, using the declared frame length rather than a content
 * scan. This is a binary frame: a length field, a request id or a payload byte may legitimately be
 * `0x0a`, and scanning for that byte misclassifies a perfectly valid reply as a duplicate one. A
 * missing trailing newline or a short body is truncation; bytes past the first complete frame are
 * either a second frame (duplicate reply) or trailing output; both stay restrictive and distinct.
 */
export function classifyReplyFraming(bytes: Uint8Array): 'OK' | 'REPLY_MALFORMED' | 'REPLY_DUPLICATE' {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < HEADER_BYTES + 1) return 'REPLY_MALFORMED';
  let frameEnd: number;
  try {
    for (let index = 0; index < MAGIC.byteLength; index++) if (bytes[index] !== MAGIC[index]) return 'REPLY_MALFORMED';
    if (bytes[4] !== KIND_RESPONSE) return 'REPLY_MALFORMED';
    const declared = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(5, false);
    if (declared + HEADER_BYTES + 1 > bytes.byteLength) return 'REPLY_MALFORMED';
    frameEnd = HEADER_BYTES + declared + 1;
    if (bytes[frameEnd - 1] !== NEWLINE) return 'REPLY_MALFORMED';
  } catch { return 'REPLY_MALFORMED'; }
  if (frameEnd === bytes.byteLength) return 'OK';
  // A concatenated second frame is a duplicate reply. Anything else after one complete frame is
  // extra trailing output. Neither is found by looking for `0x0a` inside the first frame.
  const extra = bytes.subarray(frameEnd);
  for (let index = 0; index < MAGIC.byteLength; index++) if (extra[index] !== MAGIC[index]) return 'REPLY_MALFORMED';
  return 'REPLY_DUPLICATE';
}