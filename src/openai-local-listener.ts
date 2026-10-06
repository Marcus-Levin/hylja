/**
 * #261 bounded local-capability HTTP surface. Composes #236 unchanged; no classification, policy,
 * upstream transport, authentication proof, restoration or persistent evidence provisioning here.
 * The host and its finite synchronous inspection/observation callbacks remain trusted. A capability
 * gates local access only, not subject/tenant authenticity. See docs/contracts/openai-local-listener.md.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:net';
import type { LoopbackServer, LoopbackSocket } from 'node:net';
import { setTimeout, clearTimeout } from 'node:timers';
import type { WorkerTimer } from 'node:timers';
import { createOpenAiLocalConversation } from './openai-local-conversation.js';
import type { OpenAiLocalConversation, LocalConversationObservation, LocalConversationRefusal } from './openai-local-conversation.js';
import { translateOpenAiTextRequest, OPENAI_TEXT_REQUEST_ENDPOINT } from './openai-text-request.js';
import { digestPolicyBundle } from './policy.js';
import { snapshotSentinelRequest } from './egress-sentinel-process-protocol.js';
import { TRUST_LEVELS } from './classification.js';

type Fields = Record<string, unknown>;
type PublicCode = 'ACCESS_DENIED' | 'REQUEST_REFUSED' | 'REQUEST_TOO_LARGE' | 'REQUEST_TIMEOUT'
  | 'RELEASE_REFUSED' | 'BUSY' | 'UPSTREAM_UNAVAILABLE' | 'UPSTREAM_TIMEOUT';
export type LocalListenerState = 'IDLE' | 'STARTING' | 'LISTENING' | 'CLOSING' | 'CLOSED' | 'FAILED';
export type LocalListenerStart = Readonly<{ status: 'LISTENING'; port: number }>
  | Readonly<{ status: 'REFUSED'; code: 'HOST_INVALID' | 'START_FAILED' | 'CLOSED' }>;
export interface OpenAiLocalListener {
  start(): Promise<LocalListenerStart>;
  close(): Promise<void>;
  readonly state: LocalListenerState;
}
const PUBLIC = Object.freeze({
  ACCESS_DENIED: [401, 'Unauthorized'], REQUEST_REFUSED: [400, 'Bad Request'],
  REQUEST_TOO_LARGE: [413, 'Payload Too Large'], REQUEST_TIMEOUT: [408, 'Request Timeout'],
  RELEASE_REFUSED: [403, 'Forbidden'], BUSY: [429, 'Too Many Requests'],
  UPSTREAM_UNAVAILABLE: [502, 'Bad Gateway'], UPSTREAM_TIMEOUT: [504, 'Gateway Timeout'],
} as const);
const encoder = new TextEncoder();
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const VALUE = /^[\t\x20-\x7e]*$/u;
const CONTENT = /^application\/json(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:"utf-8"|utf-8)[ \t]*)?$/iu;
const LENGTH = /^[1-9][0-9]*$/u;
const MAX_HEAD = 8192;
const MAX_BODY = 65536;
const AGE = 300_000;

/** Snapshot a bounded own-data tree. No getters, functions, inherited fields, symbols or sparse arrays. */
function tree(value: unknown, budget = { nodes: 0, units: 0 }, depth = 0): unknown {
  if (++budget.nodes > 100_000 || depth > 24) throw new Error();
  if (typeof value === 'string') {
    budget.units += value.length;
    if (budget.units > 8_388_608) throw new Error();
    return value;
  }
  if (value === null || typeof value === 'boolean' || typeof value === 'number') return value;
  if (typeof value !== 'object') throw new Error();
  const keys = Reflect.ownKeys(value);
  if (keys.length > 4097) throw new Error();
  if (Array.isArray(value)) {
    const length = Object.getOwnPropertyDescriptor(value, 'length')?.value as unknown;
    if (typeof length !== 'number' || length > 4096 || keys.length !== length + 1) throw new Error();
    const out: unknown[] = [];
    for (let i = 0; i < length; i++) {
      const d = Object.getOwnPropertyDescriptor(value, String(i));
      if (!d?.enumerable || !('value' in d)) throw new Error();
      out.push(tree(d.value, budget, depth + 1));
    }
    return Object.freeze(out);
  }
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error();
  const out: Fields = Object.create(null) as Fields;
  for (const key of keys) {
    if (typeof key !== 'string') throw new Error();
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d?.enumerable || !('value' in d)) throw new Error();
    out[key] = tree(d.value, budget, depth + 1);
  }
  return Object.freeze(out);
}
function fields(value: unknown, required: readonly string[], optional: readonly string[] = []): Fields {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error();
  const keys = Reflect.ownKeys(value);
  if (keys.length > required.length + optional.length) throw new Error();
  const out: Fields = Object.create(null) as Fields;
  for (const key of keys) {
    if (typeof key !== 'string' || ![...required, ...optional].includes(key)) throw new Error();
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d?.enumerable || !('value' in d)) throw new Error();
    out[key] = d.value;
  }
  if (required.some(key => !Object.hasOwn(out, key))) throw new Error();
  return out;
}
function label(value: unknown, limit = 256): string {
  if (typeof value !== 'string' || !value.length || value.length > limit || value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)) throw new Error();
  return value;
}
function integer(value: unknown, low: number, high: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < low || value > high) throw new Error();
  return value;
}
interface Window { issued: number; expires: number }
/** Structural evidence validation independent of freshness: stale but well-formed data can only refuse. */
function boundaryWindows(value: unknown): Window[] {
  const b = fields(value, ['authenticated', 'observed']);
  const a = fields(b['authenticated'], ['subject', 'context', 'identityProof', 'requestProof']);
  const o = fields(b['observed'], ['source', 'destination', 'sourceProof', 'routeProof']);
  const s = fields(a['subject'], ['principalId'], ['workloadId']);
  const c = fields(a['context'], ['tenantId', 'sessionId', 'purpose'], ['projectId']);
  for (const v of Object.values(s)) label(v);
  for (const v of Object.values(c)) label(v);
  for (const [name, required] of [['source', ['kind', 'ref', 'trustZone']],
    ['destination', ['kind', 'ref', 'trustZone', 'profileId']]] as const) {
    const endpoint = fields(o[name], required);
    for (const [key, v] of Object.entries(endpoint)) label(v, key === 'ref' ? 2048 : 256);
  }
  return [a['identityProof'], a['requestProof'], o['sourceProof'], o['routeProof']].map(value => {
    const p = fields(value, ['ref', 'issuedAt', 'expiresAt']);
    label(p['ref']);
    const issuedText = label(p['issuedAt']);
    const expiresText = label(p['expiresAt']);
    const issued = Date.parse(issuedText);
    const expires = Date.parse(expiresText);
    if (!Number.isFinite(issued) || !Number.isFinite(expires) ||
      new Date(issued).toISOString() !== issuedText || new Date(expires).toISOString() !== expiresText ||
      expires <= issued) throw new Error();
    return { issued, expires };
  });
}
function digest(value: string): Uint8Array {
  // Existing native declaration returns hex; encode the fixed 64 ASCII bytes for native comparison.
  return encoder.encode(createHash('sha256').update(value).digest('hex'));
}
interface HostSnapshot { listenPort: number; capabilityDigest: Uint8Array; conversation: Fields; windows: Window[] }
function snapshot(host: unknown): HostSnapshot {
  const h = fields(host, ['listenPort', 'callerToken', 'conversation']);
  const listenPort = integer(h['listenPort'], 0, 65535);
  if (listenPort !== 0 && listenPort < 1024) throw new Error();
  const token = h['callerToken'];
  if (typeof token !== 'string' || !TOKEN.test(token)) throw new Error();
  const c = fields(h['conversation'], ['port', 'timeoutMs', 'observe', 'sender', 'receiver']);
  const port = integer(c['port'], 1, 65535);
  if (port === listenPort || c['timeoutMs'] !== 10_000 || typeof c['observe'] !== 'function') throw new Error();
  const conversation: Fields = { port, timeoutMs: 10_000 };
  const windows: Window[] = [];
  for (const side of ['sender', 'receiver']) {
    const inspectName = side === 'sender' ? 'inspectOriginal' : 'inspect';
    const names = ['boundary', 'policyBundle', 'scope', 'known', 'sentinel', inspectName];
    if (side === 'sender') names.push('sourceTrust');
    const input = fields(c[side], names);
    if (typeof input[inspectName] !== 'function') throw new Error();
    const pinned: Fields = {};
    pinned['boundary'] = tree(input['boundary']);
    windows.push(...boundaryWindows(pinned['boundary']));
    pinned['policyBundle'] = tree(input['policyBundle']);
    digestPolicyBundle(pinned['policyBundle']); // Reuse policy's structural authority, not its decisions.
    const sentinel = fields(input['sentinel'], ['deadlineMs'], ['cleanupGraceMs']);
    if (sentinel['deadlineMs'] !== 10_000) throw new Error();
    if (Object.hasOwn(sentinel, 'cleanupGraceMs')) integer(sentinel['cleanupGraceMs'], 0, 1000);
    pinned['sentinel'] = Object.freeze(sentinel);
    const taken = snapshotSentinelRequest({ bytes: new Uint8Array(0), scope: input['scope'],
      known: input['known'], destination: { id: 'snapshot.invalid', profileDigest: '0'.repeat(64) },
      authorized: { id: 'snapshot.invalid', profileDigest: '0'.repeat(64) } }, 'listener.snapshot.invalid');
    if (!taken.ok) throw new Error();
    pinned['scope'] = taken.value.scope;
    pinned['known'] = taken.value.known;
    taken.value.payload.fill(0);
    if (side === 'sender') {
      if (!(TRUST_LEVELS as readonly unknown[]).includes(input['sourceTrust'])) throw new Error();
      pinned['sourceTrust'] = input['sourceTrust'];
    }
    // Inspectors retain their own accepted data snapshot as receiver, never a response socket or token.
    const receiver = Object.freeze({ ...pinned, [inspectName]: input[inspectName] });
    const inspect = input[inspectName] as (...args: unknown[]) => unknown;
    pinned[inspectName] = (...args: unknown[]): unknown => Reflect.apply(inspect, receiver, args);
    conversation[side] = Object.freeze(pinned);
  }
  const senderAuth = ((conversation['sender'] as Fields)['boundary'] as Fields)['authenticated'] as Fields;
  const receiverAuth = ((conversation['receiver'] as Fields)['boundary'] as Fields)['authenticated'] as Fields;
  for (const name of ['subject', 'context']) {
    // Closed, validated private records: canonical key order avoids treating caller insertion order as identity.
    const left = Object.entries(senderAuth[name] as Fields).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    const right = Object.entries(receiverAuth[name] as Fields).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    if (JSON.stringify(left) !== JSON.stringify(right)) throw new Error();
  }
  const observe = c['observe'] as () => LocalConversationObservation;
  const observationReceiver = Object.freeze({ ...conversation, observe });
  conversation['observe'] = (): LocalConversationObservation => Reflect.apply(observe, observationReceiver, []);
  // #236 itself remains authority for its nested structural host validity. No exchange opens here.
  if (createOpenAiLocalConversation({ ...conversation, onReply: async (): Promise<void> => {} }).state === 'FAILED') {
    throw new Error();
  }
  return { listenPort, capabilityDigest: digest(token), conversation: Object.freeze(conversation), windows };
}
/** Exhaustive post-preflight mapping. New composed codes must make an explicit public decision here. */
const COMPOSED_OUTCOMES: Readonly<Record<LocalConversationRefusal, PublicCode | null>> = Object.freeze({
  HOST_INVALID: 'RELEASE_REFUSED', ENDPOINT_REFUSED: 'RELEASE_REFUSED',
  INVALID_ARGUMENTS: 'RELEASE_REFUSED', CONVERSATION_BUSY: 'BUSY', CANCELLED: null,
  TRANSPORT_FAILED: 'UPSTREAM_UNAVAILABLE', RESPONSE_REFUSED: 'UPSTREAM_UNAVAILABLE',
  RESPONSE_TRUNCATED: 'UPSTREAM_UNAVAILABLE', RESPONSE_TOO_LARGE: 'UPSTREAM_UNAVAILABLE',
  RESPONSE_TIMEOUT: 'UPSTREAM_TIMEOUT', CONVERSATION_FAILED: null,
  SENDER_BUSY: 'BUSY', RECEIVER_BUSY: 'BUSY', INTERACTION_REFUSED: 'RELEASE_REFUSED',
  ROUTE_REFUSED: 'RELEASE_REFUSED', SCOPE_REFUSED: 'RELEASE_REFUSED', INSPECTION_REFUSED: 'RELEASE_REFUSED',
  POLICY_DENIED: 'RELEASE_REFUSED', POLICY_HELD: 'RELEASE_REFUSED', POLICY_NOT_KEEP: 'RELEASE_REFUSED',
  SENTINEL_BLOCKED: 'RELEASE_REFUSED', ROUTE_CHANGED: 'RELEASE_REFUSED', POLICY_STALE: 'RELEASE_REFUSED',
  DISPATCH_FAILED: 'UPSTREAM_UNAVAILABLE', SENDER_FAILED: null, IMAGE_REFUSED: 'RELEASE_REFUSED',
  RELEASE_FAILED: null, RECEIVER_FAILED: null, ENDPOINT_NOT_SUPPORTED: 'RELEASE_REFUSED',
  BODY_NOT_TEXT: 'RELEASE_REFUSED', BODY_TOO_LARGE: 'RELEASE_REFUSED', MALFORMED_JSON: 'RELEASE_REFUSED',
  AMBIGUOUS_BODY: 'RELEASE_REFUSED', PARSE_BUDGET_EXCEEDED: 'RELEASE_REFUSED', BODY_NOT_OBJECT: 'RELEASE_REFUSED',
  UNEXPECTED_FIELD: 'RELEASE_REFUSED', MISSING_FIELD: 'RELEASE_REFUSED', INVALID_FIELD: 'RELEASE_REFUSED',
  UNSUPPORTED_TOOLS: 'RELEASE_REFUSED', UNSUPPORTED_CONTENT: 'RELEASE_REFUSED', UNSUPPORTED_ROLE: 'RELEASE_REFUSED',
  INVALID_MESSAGE: 'RELEASE_REFUSED', STREAMING_NOT_SUPPORTED: 'RELEASE_REFUSED', NO_MESSAGES: 'RELEASE_REFUSED',
  TOO_MANY_MESSAGES: 'RELEASE_REFUSED', TRANSLATION_ERROR: null, UNSUPPORTED_OBJECT: 'RELEASE_REFUSED',
  NO_CHOICES: 'RELEASE_REFUSED', MULTIPLE_CHOICES: 'RELEASE_REFUSED', INVALID_CHOICE: 'RELEASE_REFUSED',
  UNSUPPORTED_FINISH_REASON: 'RELEASE_REFUSED', INVALID_USAGE: 'RELEASE_REFUSED',
});
interface Frame { head: number; body: number }
function parseHead(text: string, port: number, capabilityDigest: Uint8Array): Frame | PublicCode {
  const lines = text.split('\r\n');
  const line = lines.shift();
  if (lines.length > 64) return 'REQUEST_TOO_LARGE';
  const headers = new Map<string, string>();
  let auth: string | null = null;
  let duplicateAuth = false;
  let malformed = false;
  for (const field of lines) {
    const at = field.indexOf(':');
    const name = field.slice(0, at);
    const value = field.slice(at + 1).replace(/^[ \t]+|[ \t]+$/gu, '');
    if (at <= 0 || !NAME.test(name) || !VALUE.test(value)) { malformed = true; continue; }
    const key = name.toLowerCase();
    if (key === 'authorization') { if (auth !== null) duplicateAuth = true; auth = value; }
    else if (headers.has(key)) malformed = true;
    headers.set(key, value);
  }
  if (duplicateAuth || auth === null || !/^Bearer [A-Za-z0-9_-]{43}$/u.test(auth)) return 'ACCESS_DENIED';
  const supplied = digest(auth.slice(7));
  const authorized = timingSafeEqual(supplied, capabilityDigest);
  supplied.fill(0);
  if (!authorized) return 'ACCESS_DENIED';
  if (malformed || line !== 'POST /v1/chat/completions HTTP/1.1' || headers.get('host') !== `127.0.0.1:${port}`) {
    return 'REQUEST_REFUSED';
  }
  for (const name of headers.keys()) {
    if (['transfer-encoding', 'content-encoding', 'expect', 'upgrade', 'origin', 'proxy-authorization',
      'forwarded', 'openai-organization', 'openai-project'].includes(name) ||
      /^(?:x-forwarded-|x-hylja-|x-context-|x-tenant-|x-session-|x-purpose-|x-principal-)/u.test(name)) {
      return 'REQUEST_REFUSED';
    }
  }
  const length = headers.get('content-length');
  if (length === undefined || !LENGTH.test(length) || !CONTENT.test(headers.get('content-type') ?? '')) {
    return 'REQUEST_REFUSED';
  }
  const body = Number(length);
  if (!Number.isSafeInteger(body) || body > MAX_BODY) return 'REQUEST_TOO_LARGE';
  return { head: text.length + 4, body };
}
function headEnd(bytes: Uint8Array, length: number): number {
  for (let at = 0; at + 3 < length; at++) {
    if (bytes[at] === 13 && bytes[at + 1] === 10 && bytes[at + 2] === 13 && bytes[at + 3] === 10) return at;
  }
  return -1;
}
function latin1(bytes: Uint8Array): string {
  let text = '';
  for (const byte of bytes) text += String.fromCharCode(byte);
  return text;
}
export function createOpenAiLocalListener(host: unknown): OpenAiLocalListener {
  let pinned: HostSnapshot;
  try { pinned = snapshot(host); } catch {
    return Object.freeze({ start: (): Promise<LocalListenerStart> => Promise.resolve({ status: 'REFUSED', code: 'HOST_INVALID' }),
      close: (): Promise<void> => Promise.resolve(), get state(): LocalListenerState { return 'FAILED'; } });
  }
  let state: LocalListenerState = 'IDLE';
  let server: LoopbackServer | null = null;
  let port = 0;
  let starting: Promise<LocalListenerStart> | null = null;
  let closing: Promise<void> | null = null;
  let expired = false;
  let active: OpenAiLocalConversation | null = null;
  const sockets = new Set<LoopbackSocket>();
  const exchanges = new Set<Promise<void>>();
  const current = (): boolean => {
    const now = Date.now();
    if (pinned.windows.some(w => w.issued > now || w.expires <= now || w.issued < now - AGE || w.expires - w.issued > AGE)) {
      expired = true;
    }
    return !expired;
  };
  current(); // An already-stale but structurally valid host can bind only in refusal mode.
  const observe = pinned.conversation['observe'] as () => LocalConversationObservation;
  const guardedObserve = (): LocalConversationObservation => {
    const result = observe();
    if (!current()) throw new Error(); // Private expiry latch, never forged route evidence.
    return result;
  };
  const accept = (socket: LoopbackSocket): void => {
    socket.on('error', () => {});
    let disconnected = false;
    let writing = false;
    let consumed = false;
    let readTimer: WorkerTimer | null = null;
    let writerStop: (() => void) | null = null;
    let owner: OpenAiLocalConversation | null = null;
    const buffer = new Uint8Array(sockets.size < 4 ? MAX_HEAD + MAX_BODY : 0);
    let length = 0;
    let frame: Frame | null = null;
    const wipe = (): void => { buffer.fill(0); };
    const stopRead = (): void => { if (readTimer !== null) clearTimeout(readTimer); readTimer = null; wipe(); };
    const destroy = (): void => { socket.destroy(); };
    socket.on('close', () => {
      disconnected = true;
      sockets.delete(socket);
      stopRead();
      owner?.cancel();
      writerStop?.();
    });
    /** Starts native write synchronously in receiver's guarded release turn. No host reads or awaits. */
    const write = (body: string, code: PublicCode | null): Promise<void> => new Promise((resolve, reject) => {
      if (disconnected || socket.destroyed || !socket.writable || writing || state !== 'LISTENING') { reject(); return; }
      const bytes = encoder.encode(body);
      if (bytes.byteLength > MAX_BODY) { bytes.fill(0); reject(); return; }
      const status = code === null ? [200, 'OK'] as const : PUBLIC[code];
      const head = encoder.encode(`HTTP/1.1 ${status[0]} ${status[1]}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: ${bytes.byteLength}\r\nConnection: close\r\n\r\n`);
      const image = new Uint8Array(head.byteLength + bytes.byteLength);
      image.set(head); image.set(bytes, head.byteLength);
      bytes.fill(0); head.fill(0);
      let settled = false;
      let timer: WorkerTimer | null = null;
      const finish = (ok: boolean): void => {
        if (settled) return;
        settled = true;
        if (timer !== null) clearTimeout(timer);
        writerStop = null;
        image.fill(0);
        if (ok) { socket.end(); resolve(); } else { destroy(); reject(); }
      };
      writerStop = (): void => finish(false);
      // Last private lifetime/connection check immediately precedes native handoff.
      if (code === null && !current()) {
        // No native write began. Preserve the live socket for the coarse expiry refusal after #236 settles.
        image.fill(0); writerStop = null; reject(); return;
      }
      if (disconnected || state !== 'LISTENING') { finish(false); return; }
      writing = true;
      try { socket.write(image, error => finish(error === undefined)); }
      catch { finish(false); return; }
      if (!settled) { timer = setTimeout(() => finish(false), 5000); timer.unref(); }
    });
    const deny = (code: PublicCode): void => {
      consumed = true; stopRead();
      if (disconnected || writing || socket.destroyed) return;
      const body = JSON.stringify({ error: { message: code, type: 'hylja_refusal', param: null, code } });
      void write(body, code).catch(destroy);
    };
    if (state !== 'LISTENING') { destroy(); return; }
    const atCapacity = sockets.size >= 4;
    sockets.add(socket); // Every owned socket, including a refusal writer, participates in close().
    if (atCapacity) { deny('BUSY'); return; }
    const deadline = Date.now() + 5000;
    readTimer = setTimeout(() => deny('REQUEST_TIMEOUT'), 5000);
    readTimer.unref();
    socket.on('end', () => {
      if (consumed && !writing) { owner?.cancel(); destroy(); }
      else if (!consumed && !writing) deny('REQUEST_REFUSED');
    });
    socket.on('data', chunk => {
      if (consumed) { if (!writing) { owner?.cancel(); destroy(); } return; }
      if (Date.now() >= deadline) { deny('REQUEST_TIMEOUT'); return; }
      if (chunk.byteLength > buffer.byteLength - length) { deny('REQUEST_TOO_LARGE'); return; }
      buffer.set(chunk, length); length += chunk.byteLength;
      if (frame === null) {
        const at = headEnd(buffer, length);
        if (at < 0) { if (length > MAX_HEAD) deny('REQUEST_TOO_LARGE'); return; }
        if (at + 4 > MAX_HEAD) { deny('REQUEST_TOO_LARGE'); return; }
        const parsed = parseHead(latin1(buffer.subarray(0, at)), port, pinned.capabilityDigest);
        if (typeof parsed === 'string') { deny(parsed); return; }
        frame = parsed;
      }
      const total = frame.head + frame.body;
      if (length < total) return;
      if (length !== total) { deny('REQUEST_REFUSED'); return; }
      let body: string;
      try { body = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(frame.head, total)); }
      catch { deny('REQUEST_REFUSED'); return; }
      const decoded = translateOpenAiTextRequest({ endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body });
      if (decoded.status === 'REFUSED') {
        if (decoded.reason === 'TRANSLATION_ERROR') { consumed = true; stopRead(); destroy(); }
        else deny(['BODY_TOO_LARGE', 'PARSE_BUDGET_EXCEEDED', 'TOO_MANY_MESSAGES'].includes(decoded.reason)
          ? 'REQUEST_TOO_LARGE' : 'REQUEST_REFUSED');
        return;
      }
      if (!current()) { deny('RELEASE_REFUSED'); return; }
      if (active !== null) { deny('BUSY'); return; }
      consumed = true; stopRead();
      owner = createOpenAiLocalConversation({ ...pinned.conversation, observe: guardedObserve,
        onReply: (reply: string): Promise<void> => write(reply, null) });
      active = owner;
      // Enroll before exchange invokes synchronous trusted callbacks (which can call close reentrantly).
      let settle: () => void = () => {};
      const tracked = new Promise<void>(resolve => { settle = resolve; });
      exchanges.add(tracked);
      void owner.exchange({ body }).then(result => {
        if (disconnected || state !== 'LISTENING' || writing) return;
        if (!current()) { deny('RELEASE_REFUSED'); return; }
        if (result.status === 'REFUSED') {
          const code = COMPOSED_OUTCOMES[result.code];
          if (code === null) destroy(); else deny(code);
        }
      }).catch(destroy).finally(() => {
        if (active === owner) active = null;
        exchanges.delete(tracked); settle();
      });
    });
  };
  const start = (): Promise<LocalListenerStart> => {
    if (state === 'CLOSING' || state === 'CLOSED') return Promise.resolve({ status: 'REFUSED', code: 'CLOSED' });
    if (starting !== null) return starting;
    if (state !== 'IDLE') return Promise.resolve({ status: 'REFUSED', code: 'CLOSED' });
    state = 'STARTING';
    starting = new Promise(resolve => {
      let settled = false;
      const fail = (): void => {
        if (settled) return;
        settled = true; state = 'FAILED';
        resolve({ status: 'REFUSED', code: 'START_FAILED' });
      };
      try {
        server = createServer({ allowHalfOpen: true }, accept);
        server.on('error', fail);
        server.listen({ host: '127.0.0.1', port: pinned.listenPort }, () => {
          if (settled) return;
          const address = server?.address();
          if (address === null || typeof address !== 'object' || address.address !== '127.0.0.1' ||
            address.port === pinned.conversation['port']) { fail(); server?.close(() => {}); return; }
          settled = true; port = address.port; state = 'LISTENING';
          resolve(Object.freeze({ status: 'LISTENING', port }));
        });
      } catch { fail(); }
    });
    return starting;
  };
  const close = (): Promise<void> => {
    if (closing !== null) return closing;
    closing = (async (): Promise<void> => {
      if (state === 'STARTING') await starting;
      state = 'CLOSING';
      active?.cancel();
      for (const socket of sockets) socket.destroy();
      const stopped = new Promise<void>(resolve => {
        if (server === null) { resolve(); return; }
        try { server.close(resolve); } catch { resolve(); }
      });
      await Promise.all([stopped, ...exchanges]);
      pinned.capabilityDigest.fill(0);
      for (const side of ['sender', 'receiver']) {
        const known = (pinned.conversation[side] as Fields)['known'] as { key: Uint8Array } | null;
        known?.key.fill(0);
      }
      state = 'CLOSED';
    })();
    return closing;
  };
  return Object.freeze({ start, close, get state(): LocalListenerState { return state; } });
}
