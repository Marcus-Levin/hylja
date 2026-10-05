/**
 * Bounded local conversation owner (#236). One call owns one complete text conversation over an
 * **owned numeric-loopback transport**: it composes the accepted complete-text sender
 * ([openai-text-sender.ts](openai-text-sender.ts)) and the accepted KEEP-only complete-response receiver
 * ([openai-keep-receiver.ts](openai-keep-receiver.ts)) - it does not replace either, and it decides
 * nothing about classification, policy, treatment or authorization. One request, one bounded complete
 * reply, one guarded application release, or one fixed refusal.
 *
 * What this is NOT. It is not a gateway, a listener, a launcher, a provider client, a credential or
 * vault path, a redirect/ retry/ streaming design, an authentication implementation or a production
 * send point. The trusted host supplies the already authenticated boundary, the pinned policy commit,
 * the classification evidence and the application sink; **nothing here authenticates any of them**.
 * Genuine whole-image classification, an authenticated context and destination binding remain
 * mandatory host obligations, and detector absence never clears a unit: that is the sender's and the
 * receiver's own rule, and this owner neither relaxes nor re-implements it.
 *
 * The trust boundary is deliberately narrow:
 *
 * - The endpoint is **one numeric loopback port bound at construction**. There is no host name, no URL,
 *   no name resolution, no TLS and no caller-supplied route: the only routable destination this owner
 *   has is `127.0.0.1:<captured port>`, and it is never re-derived, re-read or redirected. A port that
 *   is not a plain usable loopback port is `ENDPOINT_REFUSED` before anything can exist. The request
 *   route is this module's own constant, and the caller supplies exactly one member, `body`.
 * - The **handoff is synchronous**. Between the sender's last check and `socket.write` there is no
 *   callback, no `await` and no host input: the guards are read and the exact sender-checked bytes are
 *   written in one turn. The only thing after that write is the kernel's loopback handshake, which
 *   carries no authority; the actual remote endpoint is confirmed as soon as it exists, and a mismatch
 *   closes the socket and fails the exchange.
 * - The reply is parsed by **one narrow supported profile**, decided here and refused rather than
 *   permissively tolerated: `HTTP/1.1 200 OK`, a bounded header block of exactly this shape, one
 *   `Content-Length`, no `Transfer-Encoding`, a JSON `Content-Type`, no duplicate header name, and a
 *   body of exactly the declared length that must decode as UTF-8. Chunked, opaque, incomplete,
 *   oversized, mislabelled or undecodable replies are refused, never truncated and never guessed.
 * - Cancellation is **owned**, sticky and one-way: it propagates to the sender, the receiver and the
 *   live socket, and this owner can never dispatch again afterwards.
 * - Every refusal is a fixed code. No exception message, transport error, parser excerpt, socket
 *   address, status line or byte offset ever reaches a result, and no result carries bytes, a digest
 *   or a handle.
 */
import { createConnection } from 'node:net';
import type { LoopbackSocket } from 'node:net';
import { clearTimeout, setTimeout } from 'node:timers';
import type { WorkerTimer } from 'node:timers';
import { createOpenAiKeepReceiver } from './openai-keep-receiver.js';
import type { KeepReceiverHost, KeepReceiveRefusal } from './openai-keep-receiver.js';
import { createOpenAiTextSender } from './openai-text-sender.js';
import type { TextSenderHost, TextSendRefusal } from './openai-text-sender.js';
import { OPENAI_TEXT_REQUEST_ENDPOINT } from './openai-text-request.js';
import { OPENAI_TEXT_RESPONSE_ENDPOINT, OPENAI_TEXT_RESPONSE_LIMITS } from './openai-text-response.js';
import type { SentinelProcessDestination } from './egress-sentinel-process-protocol.js';

/**
 * Every refusal is one of these fixed codes, or one of the two composed owners' own fixed codes, which
 * pass through unchanged. No code carries a field name, byte offset, excerpt, exception message,
 * transport error or any part of the input.
 */
export const OPENAI_LOCAL_CONVERSATION_REFUSALS = Object.freeze([
  /** The trusted host is not the exact declared shape; this owner can never exchange. */
  'HOST_INVALID',
  /** No usable numeric loopback port was bound at construction. */
  'ENDPOINT_REFUSED',
  /** The call was not exactly `{ body }`; no route, endpoint or treatment can travel in it. */
  'INVALID_ARGUMENTS',
  /** One exchange is already in flight. There is no queue, no pool and no replay. */
  'CONVERSATION_BUSY',
  /** `cancel()` was observed, or this owner was already cancelled. */
  'CANCELLED',
  /** The owned socket could not be opened, or failed before a complete framed reply arrived. */
  'TRANSPORT_FAILED',
  /** The reply is outside the supported framing profile, or its body is not decodable UTF-8. */
  'RESPONSE_REFUSED',
  /** The peer closed before the declared body length arrived. */
  'RESPONSE_TRUNCATED',
  /** The reply exceeded the fixed header block bound before a complete head was seen. */
  'RESPONSE_TOO_LARGE',
  /** The exchange did not complete inside the bound. */
  'RESPONSE_TIMEOUT',
  /** Fail-closed catch-all for an unexpected internal failure; carries no detail either. */
  'CONVERSATION_FAILED',
] as const);

export type LocalConversationRefusal =
  (typeof OPENAI_LOCAL_CONVERSATION_REFUSALS)[number] | TextSendRefusal | KeepReceiveRefusal;
export type LocalConversationResult =
  | Readonly<{ status: 'COMPLETED' }>
  | Readonly<{ status: 'REFUSED'; code: LocalConversationRefusal }>;
export type LocalConversationState = 'IDLE' | 'BUSY' | 'CANCELLED' | 'FAILED';
/** A failure of the owned transport only, before it can become a sender or receiver refusal. */
type TransportCode = 'TRANSPORT_FAILED' | 'RESPONSE_REFUSED' | 'RESPONSE_TRUNCATED'
  | 'RESPONSE_TOO_LARGE' | 'RESPONSE_TIMEOUT' | 'CANCELLED';

/** What the trusted host observes at the send and release points. Each owner re-validates it itself. */
export interface LocalConversationObservation {
  readonly destination: SentinelProcessDestination;
  readonly commit: Readonly<{ id: string; version: string; digest: string }>;
}

/**
 * The trusted integration host. Every member arrives from an already authenticated adapter or broker;
 * none of them arrives from a request header, body, model text or launcher flag, and none of them
 * authenticates itself here. `sender` and `receiver` are the two accepted owner hosts **without** their
 * transport and release point: this owner supplies both, so a host cannot retarget the socket or the
 * application sink after construction.
 */
export interface OpenAiLocalConversationHost {
  /** The one numeric loopback TCP port. Never a host name, a URL or a caller-selected route. */
  readonly port: number;
  /** Exchange deadline in milliseconds, bounded by this module's own fixed range. */
  readonly timeoutMs: number;
  /** Independently observed destination/profile and the committed policy identity, for both owners. */
  observe(): LocalConversationObservation;
  /** The application sink: called once, only through the receiver's own release point. */
  onReply(reply: string): Promise<void>;
  /** The accepted sender host minus its `sendPoint`. */
  readonly sender: Omit<TextSenderHost, 'sendPoint'>;
  /** The accepted receiver host minus its `releasePoint`. */
  readonly receiver: Omit<KeepReceiverHost, 'releasePoint'>;
}

export interface OpenAiLocalConversation {
  /** One complete conversation per call. A second concurrent call is refused, not queued. */
  exchange(input: unknown): Promise<LocalConversationResult>;
  /** Owner-owned, sticky cancellation. After it, this owner can never dispatch again. */
  cancel(): void;
  readonly state: LocalConversationState;
}

/* ---------- Fixed bounds, keys and the supported reply profile ---------- */

/** The one literal destination family. A name would start resolution; a literal starts nothing. */
const LOOPBACK = '127.0.0.1';
const LIMITS = Object.freeze({
  /** Whole response header block including the terminator, before a complete head must have been seen. */
  maxHeadBytes: 4_096,
  maxHeaderFields: 32,
  minTimeoutMs: 1,
  maxTimeoutMs: 120_000,
});
/** The reply body bound is the strict response codec's own bound, reused rather than restated. */
const MAX_REPLY_BODY_BYTES = OPENAI_TEXT_RESPONSE_LIMITS.maxResponseBytes;

const HOST_KEYS = ['port', 'timeoutMs', 'observe', 'onReply', 'sender', 'receiver'];
const SENDER_KEYS = ['boundary', 'sourceTrust', 'policyBundle', 'scope', 'known', 'sentinel', 'inspectOriginal'];
const RECEIVER_KEYS = ['boundary', 'policyBundle', 'scope', 'known', 'sentinel', 'inspect'];
const ARGUMENT_KEYS = ['body'];

const STATUS_LINE = 'HTTP/1.1 200 OK';
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const HEADER_VALUE = /^[\t\x20-\x7e]*$/u;
const LENGTH = /^[1-9][0-9]*$/u;
const CONTENT_TYPE = /^application\/json(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*"?utf-8"?)?$/iu;
const CR = 13;
const LF = 10;

type Fields = Record<string, unknown>;

/**
 * Own enumerable DATA properties only, and exactly the declared set. A getter, a symbol key, an
 * unknown key or a hostile trap is refused without being invoked. This is the reason the two composed
 * owners' hosts are copied here rather than spread by the host: both re-validate what they are given,
 * but a getter would already have run before either could refuse it.
 */
function declared(value: unknown, names: readonly string[]): Fields | null {
  if (value === null || typeof value !== 'object') return null;
  // A revoked Proxy throws from every trap, the array check included, so the whole structural refusal
  // is inside one containment.
  let keys: (string | symbol)[];
  try { if (Array.isArray(value)) return null; keys = Reflect.ownKeys(value); } catch { return null; }
  if (keys.length !== names.length) return null;
  const out: Fields = Object.create(null) as Fields;
  for (const key of keys) {
    if (typeof key !== 'string' || !names.includes(key)) return null;
    let descriptor: PropertyDescriptor | undefined;
    try { descriptor = Object.getOwnPropertyDescriptor(value, key); } catch { return null; }
    if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) return null;
    out[key] = descriptor.value;
  }
  return out;
}

function refused(code: LocalConversationRefusal): LocalConversationResult {
  return Object.freeze({ status: 'REFUSED' as const, code });
}

/** The only routable endpoint this owner accepts: a plain TCP port, never `0`, never a name. */
function boundedInteger(value: unknown, min: number, max: number): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max ? value : null;
}

/* ---------- The narrow supported reply profile ---------- */

interface ReplyFrame {
  /** Byte length of the header block, including the blank line that ends it. */
  readonly headBytes: number;
  /** The declared body length. Exactly this many bytes are used and no more. */
  readonly bodyBytes: number;
}

/** Byte-exact latin1 mapping of a bounded header block. Every byte becomes exactly one code unit. */
function latin1(bytes: Uint8Array): string {
  let text = '';
  for (let at = 0; at < bytes.byteLength; at += 1) text += String.fromCharCode(bytes[at] ?? 0);
  return text;
}

/**
 * The whole supported profile, in one fail-closed reader. Anything outside it - another status line,
 * another protocol version, a chunked or compressed body, a missing, duplicated, empty, non-numeric or
 * oversized `Content-Length`, a missing or non-JSON `Content-Type`, an empty, malformed or
 * out-of-range header field - is refused here, before any body byte is used and before the strict
 * response codec is ever reached. No permissive fallback, no default header, no guessed length.
 */
function replyFrameOf(head: Uint8Array): ReplyFrame | null {
  const lines = latin1(head).split('\r\n');
  if (lines.shift() !== STATUS_LINE) return null;
  if (lines.length === 0 || lines.length > LIMITS.maxHeaderFields) return null;
  const seen = new Set<string>();
  let bodyBytes: number | null = null;
  let contentType: string | null = null;
  for (const line of lines) {
    const at = line.indexOf(':');
    if (at <= 0) return null;
    const name = line.slice(0, at);
    const value = line.slice(at + 1).replace(/^[ \t]+/u, '').replace(/[ \t]+$/u, '');
    if (!TOKEN.test(name) || !HEADER_VALUE.test(value)) return null;
    const key = name.toLowerCase();
    if (seen.has(key)) return null;
    seen.add(key);
    if (key === 'transfer-encoding') return null;
    if (key === 'content-length') {
      if (!LENGTH.test(value)) return null;
      bodyBytes = Number.parseInt(value, 10);
    } else if (key === 'content-type') contentType = value;
  }
  if (bodyBytes === null || bodyBytes > MAX_REPLY_BODY_BYTES) return null;
  if (contentType === null || !CONTENT_TYPE.test(contentType)) return null;
  return Object.freeze({ headBytes: head.byteLength + 4, bodyBytes });
}

/** Offset of the first CRLFCRLF, or -1. Bounded by the caller's own head cap. */
function headEnd(bytes: Uint8Array): number {
  for (let at = 0; at + 3 < bytes.byteLength; at += 1) {
    if ((bytes[at] ?? 0) === CR && (bytes[at + 1] ?? 0) === LF &&
      (bytes[at + 2] ?? 0) === CR && (bytes[at + 3] ?? 0) === LF) return at;
  }
  return -1;
}

function join(chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) total += chunk.byteLength;
  const all = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) { all.set(chunk, at); at += chunk.byteLength; }
  return all;
}

const decoder = new TextDecoder('utf-8', { fatal: true });
/** Strict UTF-8 or a throw. A reply that is not decodable text is outside the profile, not a repair job. */
function decodeText(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/* ---------- The owner ---------- */

/**
 * Create a bounded local conversation owner bound to one trusted host and one captured loopback
 * endpoint. Construction never throws and never opens a socket: an unusable host or an unusable
 * endpoint yields a permanently restrictive owner instead of an echo of a caller value.
 */
export function createOpenAiLocalConversation(host: unknown): OpenAiLocalConversation {
  const fields = declared(host, HOST_KEYS);
  const sender = fields === null ? null : declared(fields['sender'], SENDER_KEYS);
  const receiver = fields === null ? null : declared(fields['receiver'], RECEIVER_KEYS);
  const observe = fields === null ? undefined : fields['observe'];
  const onReply = fields === null ? undefined : fields['onReply'];
  const port = fields === null ? null : boundedInteger(fields['port'], 1, 65_535);
  const timeoutMs = fields === null
    ? null : boundedInteger(fields['timeoutMs'], LIMITS.minTimeoutMs, LIMITS.maxTimeoutMs);
  if (sender === null || receiver === null || typeof observe !== 'function' || typeof onReply !== 'function') {
    return restrictive('HOST_INVALID');
  }
  // The endpoint is checked before any owner exists, so an unusable port can never reach a socket, and
  // an in-range one is captured once here and never re-read.
  if (port === null) return restrictive('ENDPOINT_REFUSED');
  if (timeoutMs === null) return restrictive('HOST_INVALID');

  let busy = false;
  let cancelled = false;
  let stop: (() => void) | null = null;
  let reply: Uint8Array | null = null;
  let transportCode: TransportCode | null = null;

  /**
   * One owned exchange over the captured endpoint. It resolves only when a complete, strictly framed
   * reply body is in hand; every other end - refusal, truncation, oversize, timeout, cancellation,
   * socket error or a close that arrives first - settles once with a fixed code. Buffers this owner
   * allocated are zeroed in that one place, on every outcome.
   */
  const receive = (image: Uint8Array): Promise<Uint8Array | null> => new Promise((resolve) => {
    const chunks: Uint8Array[] = [];
    let received = 0;
    let frame: ReplyFrame | null = null;
    let timer: WorkerTimer | null = null;
    let settled = false;
    const done = (body: Uint8Array | null, code: TransportCode | null): void => {
      if (settled) return;
      settled = true;
      if (timer !== null) { clearTimeout(timer); timer = null; }
      stop = null;
      for (const chunk of chunks) chunk.fill(0);
      chunks.length = 0;
      try { socket.destroy(); } catch { /* already closed or never opened */ }
      if (body === null) transportCode = code;
      resolve(body);
    };
    let socket: LoopbackSocket;
    try { socket = createConnection({ port, host: LOOPBACK, localAddress: LOOPBACK, family: 4 }); }
    catch { resolve(null); return; }
    const open = socket;
    stop = (): void => { try { open.destroy(); } catch { /* already closed */ } };
    open.on('error', () => { done(null, cancelled ? 'CANCELLED' : 'TRANSPORT_FAILED'); });
    open.on('close', () => { done(null, cancelled ? 'CANCELLED' : 'RESPONSE_TRUNCATED'); });
    open.on('connect', () => {
      // The endpoint actually reached, confirmed as soon as it exists. The image is already queued in
      // the kernel's buffer for the captured literal, so a mismatch here cannot have gone anywhere else.
      if (open.remotePort !== port || open.remoteAddress !== LOOPBACK ||
        open.remoteFamily !== 'IPv4' || open.localAddress !== LOOPBACK) done(null, 'TRANSPORT_FAILED');
    });
    open.on('data', (chunk) => {
      if (settled) return;
      chunks.push(chunk);
      received += chunk.byteLength;
      if (frame === null) {
        // The head bound ends an endless header block; nothing is parsed before the profile can be read.
        if (received > LIMITS.maxHeadBytes) { done(null, 'RESPONSE_TOO_LARGE'); return; }
        const bytes = join(chunks);
        const at = headEnd(bytes);
        if (at < 0) return;
        const parsed = replyFrameOf(bytes.subarray(0, at));
        if (parsed === null) { done(null, 'RESPONSE_REFUSED'); return; }
        frame = parsed;
      }
      const expected = frame.headBytes + frame.bodyBytes;
      if (received < expected) return;
      // Exactly the declared bytes are used. Anything after them is surplus this owner never parses.
      const all = join(chunks);
      done(all.slice(frame.headBytes, expected), null);
    });

    // The synchronous handoff. Every guard is read and the exact sender-checked bytes are handed to the
    // owned socket in this one synchronous turn: the promise executor runs inside the call itself, so
    // no callback, no `await` and no host input separates them.
    if (cancelled || open.destroyed || !open.writable || open.bytesWritten !== 0) {
      done(null, cancelled ? 'CANCELLED' : 'TRANSPORT_FAILED');
      return;
    }
    open.write(image);
    open.end();
    timer = setTimeout(() => { done(null, 'RESPONSE_TIMEOUT'); }, timeoutMs);
    timer.unref();
  });

  // The two composed owners, each given the transport or release point this module owns. Their own
  // host validation still runs, so nothing here widens what either one accepts.
  const senderOwner = createOpenAiTextSender({
    ...sender,
    sendPoint: {
      observe: (): LocalConversationObservation => (observe as () => LocalConversationObservation)(),
      sendExact: async (checked: Uint8Array): Promise<void> => {
        reply = await receive(checked);
        if (reply === null) throw new Error();
      },
    },
  });
  const receiverOwner = createOpenAiKeepReceiver({
    ...receiver,
    releasePoint: {
      observe: (): LocalConversationObservation => (observe as () => LocalConversationObservation)(),
      releaseExact: async (image: Uint8Array): Promise<void> => {
        await (onReply as (text: string) => Promise<void>)(decodeText(image));
      },
    },
  });

  const run = async (input: unknown): Promise<LocalConversationResult> => {
    const call = declared(input, ARGUMENT_KEYS);
    if (call === null) return refused('INVALID_ARGUMENTS');
    // The route is this module's constant. The caller's body is the only thing that travels.
    const sent = await senderOwner.send({ endpoint: OPENAI_TEXT_REQUEST_ENDPOINT, body: call['body'] });
    if (cancelled) return refused('CANCELLED');
    if (sent.status === 'REFUSED') {
      return refused(sent.code === 'DISPATCH_FAILED' ? transportCode ?? 'TRANSPORT_FAILED' : sent.code);
    }
    const bytes = reply;
    reply = null;
    if (bytes === null) return refused('TRANSPORT_FAILED');
    let body: string | null = null;
    try { body = decodeText(bytes); } catch { body = null; }
    bytes.fill(0);
    if (body === null) return refused('RESPONSE_REFUSED');
    const received = await receiverOwner.receive({
      endpoint: OPENAI_TEXT_RESPONSE_ENDPOINT, body,
    });
    return received.status === 'RELEASED'
      ? Object.freeze({ status: 'COMPLETED' as const }) : refused(received.code);
  };

  return Object.freeze({
    /**
     * Run one bounded conversation, or refuse it with a fixed code. The admission claim is taken
     * synchronously, before any stage runs, so a concurrent call is refused rather than queued.
     */
    exchange: (input: unknown): Promise<LocalConversationResult> => {
      if (busy) return Promise.resolve(refused('CONVERSATION_BUSY'));
      if (cancelled) return Promise.resolve(refused('CANCELLED'));
      busy = true;
      transportCode = null;
      return run(input).catch(() => refused('CONVERSATION_FAILED')).finally(() => { busy = false; });
    },
    cancel: (): void => {
      if (cancelled) return;
      cancelled = true;
      const destroy = stop;
      stop = null;
      if (destroy !== null) destroy();
      senderOwner.cancel();
      receiverOwner.cancel();
    },
    get state(): LocalConversationState {
      return cancelled ? 'CANCELLED' : busy ? 'BUSY' : 'IDLE';
    },
  });
}

/** A permanently restrictive owner: one fixed code, no socket, nothing to cancel. */
function restrictive(code: LocalConversationRefusal): OpenAiLocalConversation {
  return Object.freeze({
    exchange: (): Promise<LocalConversationResult> => Promise.resolve(refused(code)),
    cancel: (): void => { /* an unusable owner owns nothing to cancel */ },
    get state(): LocalConversationState { return 'FAILED'; },
  });
}