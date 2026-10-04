/**
 * #164 strict, text-only OpenAI `/v1/chat/completions` request translation. Pure, bounded and
 * NON-ENFORCING: it parses one untrusted native request body and returns either a normalized
 * `InteractionDraft` or a fixed reason-coded refusal. It has no transport, no socket, no HTTP server or
 * client, no provider SDK, no credential handling and no network capability of any kind, so this
 * repository cannot send a model request from this module.
 *
 * What a result is NOT: a translation is not policy, authorization, classification, a destination
 * decision or a release permission. `TRANSLATED` means the request was fully parsed and matched the
 * allowlist below. It never means safe, clean, inspected, approved or authorized. Nothing here decides
 * USE, DISPLAY or EXPORT, and nothing here authenticates a caller.
 *
 * Every accepted request is a **complete, non-streamed, text-only** message list. Anything outside that
 * subset is refused by name instead of being dropped, forwarded or silently narrowed, so an unsupported
 * native field can never reach a downstream stage as if it had been checked. This module creates no
 * `BoundaryContext`, no provenance proof and no subject, tenant, purpose, destination or profile: those
 * come only from an independently authenticated adapter, and a payload cannot mint them. Provider and
 * model travel as non-authority protocol metadata only ([decision 006](../docs/decisions/006-adapter-first-multi-surface-core.md)).
 *
 * The complete native wire text is parsed with the bounded `#7` structured parser. A duplicate object key
 * at any depth makes the body ambiguous, because two readers disagree about which value is the request;
 * that is refused before any allowlist decision, including for a container the allowlist would refuse
 * anyway. Only after the parse has proved the text well formed, complete and unambiguous is the validated
 * text decoded with the platform parser, which is the same reader the rest of this repository uses.
 */
import { parseStructured } from './structured-parsers.js';
import type { InteractionDraft, JsonValue } from './interaction-envelope.js';

/** The one native path this seam translates. Anything else, including an absolute URL, is unsupported. */
export const OPENAI_TEXT_REQUEST_ENDPOINT = '/v1/chat/completions';

/**
 * Fixed, non-negotiable bounds. They are exported for the future gateway and for evidence; they are not
 * caller-supplied, and a serialized caller claim could not raise them even if this module read one.
 */
export const OPENAI_TEXT_REQUEST_LIMITS = Object.freeze({
  /** Whole native request body, measured in UTF-8 bytes, not UTF-16 code units. */
  maxRequestBytes: 65_536,
  maxMessages: 64,
  maxModelLength: 256,
  /** Nesting depth and scalar-field count handed to the bounded parser, below its own maximums. */
  maxParseDepth: 16,
  maxParseFields: 512,
});

/**
 * Every refusal is one of these fixed codes. No code carries the offending field, byte offset, parser
 * excerpt, exception message or any part of the input, so a refusal can be logged without leaking a
 * planted value. `TRANSLATION_ERROR` is a fail-closed catch-all for an unexpected internal failure and
 * carries no detail either.
 */
export const OPENAI_TEXT_REQUEST_REFUSALS = Object.freeze([
  'INVALID_ARGUMENTS',
  'ENDPOINT_NOT_SUPPORTED',
  'BODY_NOT_TEXT',
  'BODY_TOO_LARGE',
  'MALFORMED_JSON',
  'AMBIGUOUS_BODY',
  'PARSE_BUDGET_EXCEEDED',
  'BODY_NOT_OBJECT',
  'UNEXPECTED_FIELD',
  'MISSING_FIELD',
  'INVALID_FIELD',
  'UNSUPPORTED_TOOLS',
  'UNSUPPORTED_CONTENT',
  'UNSUPPORTED_ROLE',
  'INVALID_MESSAGE',
  'STREAMING_NOT_SUPPORTED',
  'NO_MESSAGES',
  'TOO_MANY_MESSAGES',
  'TRANSLATION_ERROR',
] as const);

export type OpenAiTextRequestRefusal = (typeof OPENAI_TEXT_REQUEST_REFUSALS)[number];
/** The only three roles of this text subset. Any other role, spelling or type is unsupported. */
export type OpenAiTextRole = 'system' | 'user' | 'assistant';
/** One complete native message, preserved in wire order with its text exactly as decoded. */
export interface OpenAiTextMessage { readonly role: OpenAiTextRole; readonly content: string }
export type OpenAiTextRequestResult =
  | { readonly status: 'TRANSLATED'; readonly draft: InteractionDraft }
  | { readonly status: 'REFUSED'; readonly reason: OpenAiTextRequestRefusal };

interface Fields { readonly [key: string]: unknown }
interface Arguments { readonly endpoint: unknown; readonly body: unknown }

const ADAPTER = 'hylja.openai-text-request';
const PROVIDER = 'openai';
const CONTROL = /[\u0000-\u001f\u007f]/u;
/** An unpaired surrogate cannot round-trip through UTF-8; encoding it would silently yield U+FFFD. */
const INVALID_UNICODE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u;
const ROLES: ReadonlySet<string> = new Set<OpenAiTextRole>(['system', 'user', 'assistant']);
const TOP_LEVEL: ReadonlySet<string> = new Set(['model', 'messages', 'stream']);
const TOP_LEVEL_TOOLS: ReadonlySet<string> = new Set(['tools', 'tool_choice', 'functions', 'function_call', 'parallel_tool_calls']);
const MESSAGE_FIELDS: ReadonlySet<string> = new Set(['role', 'content']);
const MESSAGE_TOOLS: ReadonlySet<string> = new Set(['tool_calls', 'tool_call_id', 'function_call']);
/** Whole-input parser reasons that name a bound, not malformed syntax. */
const BUDGET_REASONS: ReadonlySet<string> = new Set([
  'INPUT_TOO_LARGE', 'FIELD_LIMIT', 'DEPTH_LIMIT', 'PATH_LIMIT', 'COMMENT_LIMIT',
  'TIME_BUDGET_EXPIRED', 'CLOCK_UNAVAILABLE',
]);

class Refused extends Error {
  constructor(readonly reason: OpenAiTextRequestRefusal) { super(reason); }
}
function refuse(reason: OpenAiTextRequestRefusal): never { throw new Refused(reason); }
function refusal(reason: OpenAiTextRequestRefusal): OpenAiTextRequestResult {
  return Object.freeze({ status: 'REFUSED', reason });
}
/** Own enumerable string keys only. Every object inspected here is a freshly decoded JSON value. */
function keysOf(value: object): readonly string[] {
  return Object.keys(value);
}
function utf8Bytes(value: string): number { return new TextEncoder().encode(value).byteLength; }

/**
 * Reads the caller's options object once. Only own enumerable **data** properties count: a getter, an
 * accessor, a symbol key, an inherited `endpoint`, an extra key or a hostile trap is refused rather than
 * executed twice or read through the prototype chain.
 */
function readArguments(input: unknown): Arguments {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) refuse('INVALID_ARGUMENTS');
  const prototype: unknown = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) refuse('INVALID_ARGUMENTS');
  const keys = Reflect.ownKeys(input);
  if (keys.length !== 2) refuse('INVALID_ARGUMENTS');
  let endpoint: unknown;
  let body: unknown;
  for (const key of keys) {
    if (key !== 'endpoint' && key !== 'body') refuse('INVALID_ARGUMENTS');
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) refuse('INVALID_ARGUMENTS');
    if (key === 'endpoint') endpoint = descriptor.value; else body = descriptor.value;
  }
  if (endpoint === undefined || body === undefined) refuse('INVALID_ARGUMENTS');
  return { endpoint, body };
}

/** The endpoint is matched exactly: no normalization, no trailing slash, no query, no absolute URL. */
function endpointOf(value: unknown): void {
  if (typeof value !== 'string' || value !== OPENAI_TEXT_REQUEST_ENDPOINT) refuse('ENDPOINT_NOT_SUPPORTED');
}
/** Complete native wire text only, bounded in UTF-8 bytes. An already-parsed object is refused. */
function wireTextOf(value: unknown): string {
  if (typeof value !== 'string') refuse('BODY_NOT_TEXT');
  if (value.length > OPENAI_TEXT_REQUEST_LIMITS.maxRequestBytes) refuse('BODY_TOO_LARGE');
  if (utf8Bytes(value) > OPENAI_TEXT_REQUEST_LIMITS.maxRequestBytes) refuse('BODY_TOO_LARGE');
  return value;
}
/**
 * Bounded, complete, unambiguous. `COMPLETE` here means the whole body was read as JSON structure and
 * fields with nothing opaque left over, which is a completeness statement and never a safety one. Any
 * bound overrun, malformed token, trailing content, unpaired surrogate in the raw text, or a duplicate
 * key at any depth refuses the request before a single value is used.
 */
function decodedDocument(text: string): unknown {
  const parsed = parseStructured(text, 'JSON', {
    maxInputUnits: OPENAI_TEXT_REQUEST_LIMITS.maxRequestBytes,
    maxDepth: OPENAI_TEXT_REQUEST_LIMITS.maxParseDepth,
    maxFields: OPENAI_TEXT_REQUEST_LIMITS.maxParseFields,
    maxTimeMs: 2_000,
  });
  if (parsed.status !== 'COMPLETE' || parsed.coverage !== 'FULL' || parsed.opaque.length) {
    if (parsed.status === 'FAILURE' && BUDGET_REASONS.has(parsed.reasons[0] ?? '')) refuse('PARSE_BUDGET_EXCEEDED');
    refuse('MALFORMED_JSON');
  }
  if (parsed.reasons.includes('DUPLICATE_KEY')) refuse('AMBIGUOUS_BODY');
  try {
    return JSON.parse(text) as unknown;
  } catch {
    // Unreachable for text the bounded parser already accepted; still a fixed code if it ever happens.
    refuse('MALFORMED_JSON');
  }
}
function modelOf(value: unknown): string {
  if (typeof value !== 'string' || !value.length || value.length > OPENAI_TEXT_REQUEST_LIMITS.maxModelLength ||
    value !== value.trim() || CONTROL.test(value) || INVALID_UNICODE.test(value)) refuse('INVALID_FIELD');
  return value;
}
function completeText(value: unknown): string {
  if (typeof value !== 'string' || INVALID_UNICODE.test(value)) refuse('UNSUPPORTED_CONTENT');
  return value;
}
/** `stream` is accepted only as an explicit `false`, which keeps this request a complete message. */
function completeOnly(value: unknown): void {
  if (value === true) refuse('STREAMING_NOT_SUPPORTED');
  if (value !== false) refuse('INVALID_FIELD');
}
/** One native message object: `role` and `content` and nothing else. Nothing is dropped silently. */
function messageOf(value: unknown): OpenAiTextMessage {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) refuse('INVALID_MESSAGE');
  const record = value as Fields;
  for (const key of keysOf(record)) {
    if (MESSAGE_TOOLS.has(key)) refuse('UNSUPPORTED_TOOLS');
    if (!MESSAGE_FIELDS.has(key)) refuse('UNEXPECTED_FIELD');
  }
  if (!Object.hasOwn(record, 'role') || !Object.hasOwn(record, 'content')) refuse('MISSING_FIELD');
  const role = record['role'];
  if (typeof role !== 'string' || !ROLES.has(role)) refuse('UNSUPPORTED_ROLE');
  return Object.freeze({ role: role as OpenAiTextRole, content: completeText(record['content']) });
}
/** Top-level allowlist first, then the bounded, ordered, non-empty message list it must carry. */
function allowedMessageList(record: Fields): readonly OpenAiTextMessage[] {
  for (const key of keysOf(record)) {
    if (TOP_LEVEL_TOOLS.has(key)) refuse('UNSUPPORTED_TOOLS');
    if (!TOP_LEVEL.has(key)) refuse('UNEXPECTED_FIELD');
  }
  if (!Object.hasOwn(record, 'model')) refuse('MISSING_FIELD');
  if (!Object.hasOwn(record, 'messages')) refuse('MISSING_FIELD');
  const messages = record['messages'];
  if (!Array.isArray(messages)) refuse('INVALID_FIELD');
  if (!messages.length) refuse('NO_MESSAGES');
  if (messages.length > OPENAI_TEXT_REQUEST_LIMITS.maxMessages) refuse('TOO_MANY_MESSAGES');
  return Object.freeze(messages.map((message) => messageOf(message)));
}
function payloadOf(messages: readonly OpenAiTextMessage[]): JsonValue {
  const items: JsonValue[] = messages.map((message) => Object.freeze({
    role: message.role, content: message.content,
  }));
  Object.freeze(items);
  return Object.freeze({ messages: items });
}
/**
 * Translate one untrusted native request. Pure: the same input always yields the same draft, and no
 * clock, identifier or timestamp is read here. The draft is frozen whole and never aliases the input.
 */
function translate(args: Arguments): OpenAiTextRequestResult {
  endpointOf(args.endpoint);
  const text = wireTextOf(args.body);
  const document = decodedDocument(text);
  if (document === null || typeof document !== 'object' || Array.isArray(document)) refuse('BODY_NOT_OBJECT');
  const record = document as Fields;
  const messages = allowedMessageList(record);
  const model = modelOf(record['model']);
  if (Object.hasOwn(record, 'stream')) completeOnly(record['stream']);
  const draft: InteractionDraft = Object.freeze({
    operation: 'model.input',
    payload: payloadOf(messages),
    stream: Object.freeze({ mode: 'complete' as const }),
    metadata: Object.freeze({ adapter: ADAPTER, provider: PROVIDER, model }),
  });
  return Object.freeze({ status: 'TRANSLATED' as const, draft });
}

/**
 * Translate one OpenAI-compatible text chat-completions request, or refuse it with a fixed code.
 * See `docs/contracts/openai-text-request.md`. This authenticates nobody, sends nothing and releases
 * nothing: a downstream gateway still needs an authenticated boundary, `decidePolicy` and the
 * independent egress sentinel before a byte may leave.
 */
export function translateOpenAiTextRequest(input: unknown): OpenAiTextRequestResult {
  let args: Arguments;
  try {
    args = readArguments(input);
  } catch {
    // The caught value is discarded without being inspected. `readArguments` reports every one of its
    // own refusals as `INVALID_ARGUMENTS`, so the mapping is lossless, and any other thrown value is a
    // caller-controlled object whose prototype chain can throw again: an `instanceof`, a property read
    // or any other reflective inspection inside this catch would leave the fixed-refusal boundary from
    // inside the handler, propagating a planted message and stack out of the function.
    return refusal('INVALID_ARGUMENTS');
  }
  try {
    return translate(args);
  } catch (error) {
    return refusal(error instanceof Refused ? error.reason : 'TRANSLATION_ERROR');
  }
}