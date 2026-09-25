/** Provider-neutral operation vocabulary. This module describes interactions, never release permission. */
export const INTERACTION_OPERATIONS = [
  'model.input', 'model.output', 'tool.call', 'tool.result',
  'mcp.list', 'mcp.resource', 'mcp.prompt', 'mcp.call', 'mcp.result',
  'file.list', 'file.read', 'file.search', 'file.write', 'file.diff',
  'shell.command', 'shell.stdout', 'shell.stderr',
  'skill.load', 'skill.resource', 'skill.execute',
  'memory.read', 'memory.write', 'web.request', 'web.response',
  'agent.handoff', 'agent.result',
] as const;

export type InteractionOperation = (typeof INTERACTION_OPERATIONS)[number];
export type JsonValue = null | string | number | boolean | JsonValue[] | { [key: string]: JsonValue };
export interface Subject { principalId: string; workloadId?: string }
export interface RequestContext { tenantId: string; projectId?: string; sessionId: string; purpose: string }
export interface Endpoint { kind: string; ref: string; trustZone: string }
export interface Destination extends Endpoint { profileId: string }
export interface Proof { ref: string; issuedAt: string; expiresAt: string }
export interface Provenance extends Proof {
  kind: 'identity' | 'request' | 'source' | 'route';
  authority: 'authenticated' | 'adapter-observed';
}
export interface AdapterMetadata {
  adapter: string;
  provider?: string;
  model?: string;
  correlationId?: string;
}
export interface Representation { mediaType?: string; encodings?: string[] }
export type Stream = { mode: 'complete' } | {
  mode: 'stream'; id: string; sequence: number; final: boolean;
  cancelled: boolean; inspection: 'unverified';
};
export interface InteractionEnvelope {
  version: 1;
  id: string;
  occurredAt: string;
  operation: InteractionOperation;
  subject: Subject;
  source: Endpoint;
  destination: Destination;
  context: RequestContext;
  payload: JsonValue;
  provenance: Provenance[];
  representation?: Representation;
  stream?: Stream;
  metadata?: AdapterMetadata;
}
export interface BoundaryContext {
  /** Supplied by an already authenticated adapter/broker, never by envelope or model content. */
  authenticated: {
    subject: Subject;
    context: RequestContext;
    identityProof: Proof;
    requestProof: Proof;
  };
  /** Observed intercepted boundary AND actual route, including redirect/profile changes. */
  observed: {
    source: Endpoint;
    destination: Destination;
    sourceProof: Proof;
    routeProof: Proof;
  };
}
export interface InteractionDraft {
  operation: InteractionOperation;
  payload: JsonValue;
  representation?: Representation;
  stream?: Stream;
  metadata?: AdapterMetadata;
}

// Proof freshness is checked here, not proof authenticity. Only an already trusted integration
// may supply BoundaryContext; accepting it from a caller-controlled JSON body defeats the seam.
const MAX_AGE_MS = 5 * 60 * 1000;
const MAX_WIRE_BYTES = 1_048_576;
const MAX_JSON_NODES = 100_000;
const boundEnvelopes = new WeakSet<object>();

type RecordValue = Record<string, unknown>;
class EnvelopeError extends TypeError {}
function fail(where: string): never { throw new EnvelopeError(`Invalid interaction envelope: ${where}`); }
function safe<T>(action: () => T): T {
  try { return action(); } catch (error) {
    // JSON.parse, proxies and unexpected JS object traps can include attacker-controlled text.
    if (error instanceof EnvelopeError) throw error;
    throw new EnvelopeError('Invalid interaction envelope');
  }
}
function bytes(value: string): number {
  if (value.length > MAX_WIRE_BYTES) fail('wire length');
  return new TextEncoder().encode(value).byteLength;
}
function record(value: unknown, required: readonly string[], optional: readonly string[], where: string): RecordValue {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(where);
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail(where);
  if (Object.getOwnPropertySymbols(value).length !== 0) fail(where);
  const entries = Object.entries(Object.getOwnPropertyDescriptors(value));
  for (const [key, descriptor] of entries) {
    if (!descriptor.enumerable || !('value' in descriptor) ||
      (!required.includes(key) && !optional.includes(key))) fail(`${where}: unexpected field`);
  }
  for (const key of required) if (!Object.hasOwn(value, key)) fail(`${where}.${key}`);
  return value as RecordValue;
}
function text(value: unknown, where: string, limit = 256): string {
  if (typeof value !== 'string' || !value.length || value.length > limit ||
    value !== value.trim() || /[\u0000-\u001f\u007f]/u.test(value)) fail(where);
  return value;
}
function timestamp(value: unknown, where: string): { text: string; time: number } {
  const result = text(value, where);
  const time = Date.parse(result);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== result) fail(where);
  return { text: result, time };
}
function proof(value: unknown, where: string, now: number): Proof {
  const v = record(value, ['ref', 'issuedAt', 'expiresAt'], [], where);
  const issued = timestamp(v.issuedAt, `${where}.issuedAt`);
  const expires = timestamp(v.expiresAt, `${where}.expiresAt`);
  if (issued.time > now || issued.time < now - MAX_AGE_MS ||
    expires.time <= now || expires.time - issued.time > MAX_AGE_MS) fail(`${where}: stale evidence`);
  return { ref: text(v.ref, `${where}.ref`), issuedAt: issued.text, expiresAt: expires.text };
}
function subject(value: unknown): Subject {
  const v = record(value, ['principalId'], ['workloadId'], 'subject');
  return { principalId: text(v.principalId, 'subject.principalId'),
    ...(Object.hasOwn(v, 'workloadId') ? { workloadId: text(v.workloadId, 'subject.workloadId') } : {}) };
}
function requestContext(value: unknown): RequestContext {
  const v = record(value, ['tenantId', 'sessionId', 'purpose'], ['projectId'], 'context');
  return {
    tenantId: text(v.tenantId, 'context.tenantId'),
    ...(Object.hasOwn(v, 'projectId') ? { projectId: text(v.projectId, 'context.projectId') } : {}),
    sessionId: text(v.sessionId, 'context.sessionId'), purpose: text(v.purpose, 'context.purpose'),
  };
}
function endpoint(value: unknown, destination: false): Endpoint;
function endpoint(value: unknown, destination: true): Destination;
function endpoint(value: unknown, destination: boolean): Endpoint | Destination {
  const where = destination ? 'destination' : 'source';
  const v = record(value, destination ? ['kind', 'ref', 'trustZone', 'profileId'] : ['kind', 'ref', 'trustZone'], [], where);
  return {
    kind: text(v.kind, `${where}.kind`), ref: text(v.ref, `${where}.ref`, 2048),
    trustZone: text(v.trustZone, `${where}.trustZone`),
    ...(destination ? { profileId: text(v.profileId, 'destination.profileId') } : {}),
  };
}
function boundary(value: unknown, now: number): {
  subject: Subject; context: RequestContext; source: Endpoint;
  destination: Destination; provenance: Provenance[];
} {
  const b = record(value, ['authenticated', 'observed'], [], 'trusted boundary');
  const authenticated = record(b.authenticated, ['subject', 'context', 'identityProof', 'requestProof'], [], 'authenticated boundary');
  const observed = record(b.observed, ['source', 'destination', 'sourceProof', 'routeProof'], [], 'observed boundary');
  const identity = proof(authenticated.identityProof, 'identity proof', now);
  const request = proof(authenticated.requestProof, 'request proof', now);
  const sourceProof = proof(observed.sourceProof, 'source proof', now);
  const route = proof(observed.routeProof, 'route proof', now);
  return {
    subject: subject(authenticated.subject), context: requestContext(authenticated.context),
    source: endpoint(observed.source, false), destination: endpoint(observed.destination, true),
    provenance: [
      { kind: 'identity', authority: 'authenticated', ...identity },
      { kind: 'request', authority: 'authenticated', ...request },
      { kind: 'source', authority: 'adapter-observed', ...sourceProof },
      { kind: 'route', authority: 'adapter-observed', ...route },
    ],
  };
}
interface JsonBudget { nodes: number; bytes: number }
function jsonValue(value: unknown, depth = 0, ancestors = new Set<object>(),
  budget: JsonBudget = { nodes: 0, bytes: 0 }): JsonValue {
  if (depth > 32 || ++budget.nodes > MAX_JSON_NODES) fail('JSON payload bounds');
  budget.bytes += typeof value === 'string' ? bytes(value) : 32;
  if (budget.bytes > MAX_WIRE_BYTES) fail('JSON payload bounds');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'object') fail('JSON payload data');
  if (ancestors.has(value)) fail('JSON payload cycle');
  ancestors.add(value);
  let result: JsonValue;
  if (Array.isArray(value)) {
    if (value.length > 10_000 || Object.keys(value).length !== value.length ||
      Object.getOwnPropertySymbols(value).length) fail('JSON payload array');
    const items: JsonValue[] = [];
    for (let index = 0; index < value.length; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !('value' in descriptor)) fail('JSON payload array descriptor');
      items.push(jsonValue(descriptor.value, depth + 1, ancestors, budget));
    }
    result = items;
  } else {
    const object = record(value, [], Object.keys(value), 'JSON payload descriptor');
    if (Object.keys(object).length > 10_000) fail('JSON payload size');
    const entries: [string, JsonValue][] = [];
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(object))) {
      if (!('value' in descriptor)) fail('JSON payload descriptor');
      budget.bytes += bytes(key);
      if (budget.bytes > MAX_WIRE_BYTES) fail('JSON payload bounds');
      entries.push([key, jsonValue(descriptor.value, depth + 1, ancestors, budget)]);
    }
    result = Object.fromEntries(entries) as { [key: string]: JsonValue };
  }
  ancestors.delete(value);
  return result;
}
function representation(value: unknown): Representation {
  const v = record(value, [], ['mediaType', 'encodings'], 'representation');
  const result: Representation = {};
  if (Object.hasOwn(v, 'mediaType')) {
    const mediaType = text(v.mediaType, 'representation.mediaType');
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+\/[a-z0-9!#$%&'*+.^_`|~-]+$/iu.test(mediaType)) fail('representation.mediaType');
    result.mediaType = mediaType;
  }
  if (Object.hasOwn(v, 'encodings')) {
    const input = jsonValue(v.encodings);
    if (!Array.isArray(input) || input.length > 8) fail('representation.encodings');
    const encodings = input.map((encoding) => {
      const name = text(encoding, 'representation.encoding');
      if (!/^[a-z0-9][a-z0-9._-]*$/iu.test(name)) fail('representation.encoding');
      return name;
    });
    if (new Set(encodings.map((encoding) => encoding.toLowerCase())).size !== encodings.length) fail('representation.duplicate encoding');
    result.encodings = encodings;
  }
  return result;
}
function metadata(value: unknown): AdapterMetadata {
  const v = record(value, ['adapter'], ['provider', 'model', 'correlationId'], 'adapter metadata');
  return {
    adapter: text(v.adapter, 'metadata.adapter'),
    ...(Object.hasOwn(v, 'provider') ? { provider: text(v.provider, 'metadata.provider') } : {}),
    ...(Object.hasOwn(v, 'model') ? { model: text(v.model, 'metadata.model') } : {}),
    ...(Object.hasOwn(v, 'correlationId') ? { correlationId: text(v.correlationId, 'metadata.correlationId') } : {}),
  };
}
function stream(value: unknown): Stream {
  const v = record(value, ['mode'], ['id', 'sequence', 'final', 'cancelled', 'inspection'], 'stream');
  if (v.mode === 'complete') {
    if (Object.keys(v).length !== 1) fail('complete stream metadata');
    return { mode: 'complete' };
  }
  if (v.mode !== 'stream') fail('stream.mode');
  for (const key of ['id', 'sequence', 'final', 'cancelled', 'inspection']) {
    if (!Object.hasOwn(v, key)) fail(`stream.${key}`);
  }
  if (!Number.isSafeInteger(v.sequence) || (v.sequence as number) < 0 ||
    typeof v.final !== 'boolean' || typeof v.cancelled !== 'boolean' ||
    (v.final && v.cancelled) || v.inspection !== 'unverified') fail('stream fragment state');
  return { mode: 'stream', id: text(v.id, 'stream.id'), sequence: v.sequence as number,
    final: v.final, cancelled: v.cancelled, inspection: 'unverified' };
}
function provenance(value: unknown): Provenance[] {
  if (!Array.isArray(value) || value.length !== 4) fail('provenance chain');
  return value.map((part) => {
    const v = record(part, ['kind', 'authority', 'ref', 'issuedAt', 'expiresAt'], [], 'provenance');
    if (!['identity', 'request', 'source', 'route'].includes(v.kind as string) ||
      !['authenticated', 'adapter-observed'].includes(v.authority as string)) fail('provenance authority');
    return {
      kind: v.kind as Provenance['kind'], authority: v.authority as Provenance['authority'],
      ref: text(v.ref, 'provenance.ref'), issuedAt: timestamp(v.issuedAt, 'provenance.issuedAt').text,
      expiresAt: timestamp(v.expiresAt, 'provenance.expiresAt').text,
    };
  });
}
function same(left: unknown, right: unknown): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function freezeTree<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const part of Object.values(value)) freezeTree(part);
    Object.freeze(value);
  }
  return value;
}
function bind(value: InteractionEnvelope, trusted: ReturnType<typeof boundary>, previous?: InteractionEnvelope): InteractionEnvelope {
  if (!same(value.subject, trusted.subject) || !same(value.context, trusted.context) ||
    !same(value.source, trusted.source) || !same(value.destination, trusted.destination) ||
    !same(value.provenance, trusted.provenance)) fail('authenticated/observed boundary mismatch');
  const fragment = value.stream?.mode === 'stream' ? value.stream : undefined;
  if (previous !== undefined) {
    if (!boundEnvelopes.has(previous) || !fragment || previous.stream?.mode !== 'stream' ||
      previous.stream.final || previous.stream.cancelled || fragment.sequence !== previous.stream.sequence + 1 ||
      fragment.id !== previous.stream.id || value.operation !== previous.operation ||
      !same(value.subject, previous.subject) || !same(value.context, previous.context) ||
      !same(value.source, previous.source) || !same(value.destination, previous.destination) ||
      !same(value.provenance, previous.provenance) || !same(value.metadata, previous.metadata) ||
      !same(value.representation, previous.representation)) fail('stream fragment context/order');
  } else if (fragment && fragment.sequence !== 0) fail('stream must start at sequence zero');
  // In-process tamper resistance, not proof of identity or an egress authorization.
  freezeTree(value);
  boundEnvelopes.add(value);
  return value;
}

/** Normalize a draft with independently supplied, already trusted adapter/broker evidence. */
export function createInteractionEnvelope(input: unknown, trustedContext: unknown, previous?: InteractionEnvelope): InteractionEnvelope {
  return safe(() => {
    const now = Date.now();
    const trusted = boundary(trustedContext, now);
    const raw = record(input, ['operation', 'payload'], ['representation', 'stream', 'metadata'], 'draft');
    if (!INTERACTION_OPERATIONS.includes(raw.operation as InteractionOperation)) fail('operation');
    const envelope: InteractionEnvelope = {
      version: 1, id: globalThis.crypto.randomUUID(), occurredAt: new Date(now).toISOString(),
      operation: raw.operation as InteractionOperation,
      subject: trusted.subject, source: trusted.source, destination: trusted.destination,
      context: trusted.context, payload: jsonValue(raw.payload), provenance: trusted.provenance,
      ...(Object.hasOwn(raw, 'representation') ? { representation: representation(raw.representation) } : {}),
      ...(Object.hasOwn(raw, 'stream') ? { stream: stream(raw.stream) } : {}),
      ...(Object.hasOwn(raw, 'metadata') ? { metadata: metadata(raw.metadata) } : {}),
    };
    if (bytes(JSON.stringify(envelope)) > MAX_WIRE_BYTES) fail('wire length');
    return bind(envelope, trusted, previous);
  });
}

/** Parse a wire envelope only against fresh, independent trusted context (including actual route). */
export function parseInteractionEnvelope(serialized: string, trustedContext: unknown, previous?: InteractionEnvelope): InteractionEnvelope {
  return safe(() => {
    if (typeof serialized !== 'string' || bytes(serialized) > MAX_WIRE_BYTES) fail('wire length');
    const now = Date.now();
    const trusted = boundary(trustedContext, now);
    const raw: unknown = JSON.parse(serialized);
    const v = record(raw, ['version', 'id', 'occurredAt', 'operation', 'subject', 'source',
      'destination', 'context', 'payload', 'provenance'], ['representation', 'stream', 'metadata'], 'wire');
    if (v.version !== 1 || !INTERACTION_OPERATIONS.includes(v.operation as InteractionOperation)) fail('version/operation');
    const id = text(v.id, 'id');
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(id)) fail('id');
    const occurredAt = timestamp(v.occurredAt, 'occurredAt');
    if (occurredAt.time > now || occurredAt.time < now - MAX_AGE_MS) fail('stale interaction');
    const envelope: InteractionEnvelope = {
      version: 1, id, occurredAt: occurredAt.text, operation: v.operation as InteractionOperation,
      subject: subject(v.subject), source: endpoint(v.source, false), destination: endpoint(v.destination, true),
      context: requestContext(v.context), payload: jsonValue(v.payload), provenance: provenance(v.provenance),
      ...(Object.hasOwn(v, 'representation') ? { representation: representation(v.representation) } : {}),
      ...(Object.hasOwn(v, 'stream') ? { stream: stream(v.stream) } : {}),
      ...(Object.hasOwn(v, 'metadata') ? { metadata: metadata(v.metadata) } : {}),
    };
    return bind(envelope, trusted, previous);
  });
}

/** Serialization cannot turn a hand-constructed claim into a bound interaction. Never an egress decision. */
export function serializeInteractionEnvelope(value: InteractionEnvelope): string {
  return safe(() => {
    if (typeof value !== 'object' || value === null || !boundEnvelopes.has(value)) fail('not a bound/verified interaction');
    return JSON.stringify(value);
  });
}
