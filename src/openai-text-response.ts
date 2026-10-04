/**
 * #170 strict, text-only OpenAI `/v1/chat/completions` response translation. Pure, bounded and
 * NON-ENFORCING: it parses one untrusted inbound chat-completion body and returns either a normalized
 * `InteractionDraft` for `model.output` with separate frozen protocol metadata, or a fixed
 * reason-coded refusal. It has no transport, no socket, no HTTP server or client, no provider SDK, no
 * credential handling and no network capability of any kind, so this repository cannot receive or send
 * a model response from this module.
 *
 * What a result is NOT: a translation is not inspection, classification, policy, authorization, a
 * destination decision or a release permission. `TRANSLATED` means the inbound text was fully parsed
 * and matched the allowlist below. It never means safe, clean, inspected, approved, authorized or
 * free of a credential. Protected model output stays **untrusted text**: nothing here looks inside
 * it, substitutes an original, or grants `USE`, `DISPLAY` or `EXPORT`.
 *
 * Every accepted body is a **complete, non-streamed, text-only** single choice. Anything outside that
 * subset is refused by name instead of being dropped, forwarded or silently narrowed, so an
 * unsupported native field can never reach a downstream stage as if it had been checked. This module
 * creates no `BoundaryContext`, no provenance proof and no subject, tenant, purpose, destination,
 * session or profile: those come only from an independently authenticated adapter, and a response
 * cannot mint them. The native `id`, `created`, `finish_reason` and optional `usage` travel beside
 * the draft as frozen protocol metadata and stay out of the payload, so a normalized interaction can
 * never be confused with a provider billing or identity record
 * ([decision 006](../docs/decisions/006-adapter-first-multi-surface-core.md)).
 *
 * The complete native wire text is parsed with the bounded `#7` structured parser. A duplicate object
 * key at any depth makes the body ambiguous, because two readers disagree about which value is the
 * response; that is refused before any allowlist decision, including for a container the allowlist
 * would refuse anyway. Only after the parse has proved the text well formed, complete and unambiguous
 * is the validated text decoded with the platform parser, which is the same reader the rest of this
 * repository uses.
 */
import { types as nodeUtilTypes } from 'node:util';
import { parseStructured } from './structured-parsers.js';
import type { InteractionDraft, JsonValue } from './interaction-envelope.js';

/** The one native path this seam intercepts. Anything else, including an absolute URL, is unsupported. */
export const OPENAI_TEXT_RESPONSE_ENDPOINT = '/v1/chat/completions';

/**
 * Fixed, non-negotiable bounds. They are exported for the future gateway and for evidence; they are not
 * caller-supplied, and a serialized caller claim could not raise them even if this module read one.
 */
export const OPENAI_TEXT_RESPONSE_LIMITS = Object.freeze({
  /** Whole native response body, measured in UTF-8 bytes, not UTF-16 code units. */
  maxResponseBytes: 65_536,
  /** Native `id` and `model` protocol strings, in UTF-16 code units. */
  maxIdentifierLength: 256,
  /** Exactly one complete, non-streamed choice is accepted. */
  maxChoices: 1,
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
export const OPENAI_TEXT_RESPONSE_REFUSALS = Object.freeze([
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
  'UNSUPPORTED_OBJECT',
  'STREAMING_NOT_SUPPORTED',
  'NO_CHOICES',
  'MULTIPLE_CHOICES',
  'INVALID_CHOICE',
  'UNSUPPORTED_TOOLS',
  'UNSUPPORTED_CONTENT',
  'UNSUPPORTED_ROLE',
  'UNSUPPORTED_FINISH_REASON',
  'INVALID_USAGE',
  'TRANSLATION_ERROR',
] as const);

export type OpenAiTextResponseRefusal = (typeof OPENAI_TEXT_RESPONSE_REFUSALS)[number];
/** The only two finish reasons of this complete text subset. Anything else is unsupported. */
export type OpenAiTextFinishReason = 'stop' | 'length';
/**
 * Optional native token counts, preserved exactly as sent and validated only for internal consistency.
 * They are protocol metadata: not billing evidence, not policy input and never an authority.
 */
export interface OpenAiTextUsage {
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly total_tokens: number;
}
/** Frozen native protocol metadata kept beside the draft, never merged into the payload. */
export interface OpenAiTextResponseProtocol {
  readonly id: string;
  readonly created: number;
  readonly finish_reason: OpenAiTextFinishReason;
  readonly usage?: OpenAiTextUsage;
}
export type OpenAiTextResponseResult =
  | { readonly status: 'TRANSLATED'; readonly draft: InteractionDraft; readonly protocol: OpenAiTextResponseProtocol }
  | { readonly status: 'REFUSED'; readonly reason: OpenAiTextResponseRefusal };

interface Fields { readonly [key: string]: unknown }
interface Arguments { readonly endpoint: unknown; readonly body: unknown }
/** The one accepted choice, reduced to what the draft and the protocol metadata actually need. */
interface TranslatedChoice { readonly content: string; readonly finishReason: OpenAiTextFinishReason }

const ADAPTER = 'hylja.openai-text-response';
const PROVIDER = 'openai';
const COMPLETE_OBJECT = 'chat.completion';
/** The streaming object is a different wire format, not a variant of the complete one. */
const STREAMING_OBJECT = 'chat.completion.chunk';
const CONTROL = /[\u0000-\u001f\u007f]/u;
/** An unpaired surrogate cannot round-trip through UTF-8; encoding it would silently yield U+FFFD. */
const INVALID_UNICODE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u;
const TOP_LEVEL: ReadonlySet<string> = new Set(['id', 'object', 'created', 'model', 'choices', 'usage']);
const TOP_LEVEL_REQUIRED: readonly string[] = ['id', 'object', 'created', 'model', 'choices'];
const CHOICE_FIELDS: ReadonlySet<string> = new Set(['index', 'message', 'finish_reason']);
const CHOICE_TOOLS: ReadonlySet<string> = new Set(['tool_calls', 'function_call', 'tool_call_id']);
const MESSAGE_FIELDS: ReadonlySet<string> = new Set(['role', 'content']);
const MESSAGE_TOOLS: ReadonlySet<string> = new Set(['tool_calls', 'function_call', 'tool_call_id']);
/** A refusal is a content carrier of this subset, not text content, so it is refused as content. */
const MESSAGE_CONTENT: ReadonlySet<string> = new Set(['refusal']);
const USAGE_FIELDS: readonly string[] = ['prompt_tokens', 'completion_tokens', 'total_tokens'];
const FINISH_REASONS: ReadonlySet<string> = new Set<OpenAiTextFinishReason>(['stop', 'length']);
const MESSAGE_ROLE = 'assistant';
/** Whole-input parser reasons that name a bound, not malformed syntax. */
const BUDGET_REASONS: ReadonlySet<string> = new Set([
  'INPUT_TOO_LARGE', 'FIELD_LIMIT', 'DEPTH_LIMIT', 'PATH_LIMIT', 'COMMENT_LIMIT',
  'TIME_BUDGET_EXPIRED', 'CLOCK_UNAVAILABLE',
]);

class Refused extends Error {
  constructor(readonly reason: OpenAiTextResponseRefusal) { super(reason); }
}
function refuse(reason: OpenAiTextResponseRefusal): never { throw new Refused(reason); }
function refusal(reason: OpenAiTextResponseRefusal): OpenAiTextResponseResult {
  return Object.freeze({ status: 'REFUSED', reason });
}
/** Own enumerable string keys only. Every object inspected here is a freshly decoded JSON value. */
function keysOf(value: object): readonly string[] {
  return Object.keys(value);
}
function utf8Bytes(value: string): number { return new TextEncoder().encode(value).byteLength; }

/**
 * Reads the caller's options object once. A Proxy is refused outright by an intrinsic brand check, so
 * a forwarding, revoked or hostile proxy never reaches the prototype, key or descriptor reads below and
 * no trap of its own can run. Among the remaining plain objects only own enumerable **data** properties
 * count: a getter, an accessor, a symbol key, an inherited `endpoint` or an extra key is refused rather
 * than executed twice or read through the prototype chain.
 */
function readArguments(input: unknown): Arguments {
  if (input === null || typeof input !== 'object') refuse('INVALID_ARGUMENTS');
  if (nodeUtilTypes.isProxy(input)) refuse('INVALID_ARGUMENTS');
  if (Array.isArray(input)) refuse('INVALID_ARGUMENTS');
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
  if (typeof value !== 'string' || value !== OPENAI_TEXT_RESPONSE_ENDPOINT) refuse('ENDPOINT_NOT_SUPPORTED');
}
/** Complete native wire text only, bounded in UTF-8 bytes. An already-parsed object is refused. */
function wireTextOf(value: unknown): string {
  if (typeof value !== 'string') refuse('BODY_NOT_TEXT');
  if (value.length > OPENAI_TEXT_RESPONSE_LIMITS.maxResponseBytes) refuse('BODY_TOO_LARGE');
  if (utf8Bytes(value) > OPENAI_TEXT_RESPONSE_LIMITS.maxResponseBytes) refuse('BODY_TOO_LARGE');
  return value;
}
/**
 * Bounded, complete, unambiguous. `COMPLETE` here means the whole body was read as JSON structure and
 * fields with nothing opaque left over, which is a completeness statement and never a safety one. Any
 * bound overrun, malformed token, trailing content (including an SSE `data:` line or `[DONE]` marker),
 * unpaired surrogate in the raw text, or a duplicate key at any depth refuses the body before a single
 * value is used.
 */
function decodedDocument(text: string): unknown {
  const parsed = parseStructured(text, 'JSON', {
    maxInputUnits: OPENAI_TEXT_RESPONSE_LIMITS.maxResponseBytes,
    maxDepth: OPENAI_TEXT_RESPONSE_LIMITS.maxParseDepth,
    maxFields: OPENAI_TEXT_RESPONSE_LIMITS.maxParseFields,
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
/** The native object discriminator. Streaming is its own object and its own refusal. */
function objectOf(value: unknown): void {
  if (value === STREAMING_OBJECT) refuse('STREAMING_NOT_SUPPORTED');
  if (value !== COMPLETE_OBJECT) refuse('UNSUPPORTED_OBJECT');
}
/** A bounded, non-empty protocol identifier. It is a label, never an identity, tenant or proof. */
function identifierOf(value: unknown): string {
  if (typeof value !== 'string' || !value.length || value.length > OPENAI_TEXT_RESPONSE_LIMITS.maxIdentifierLength ||
    value !== value.trim() || CONTROL.test(value) || INVALID_UNICODE.test(value)) refuse('INVALID_FIELD');
  return value;
}
/** A safe nonnegative integer. It is never read as a clock, a freshness proof or an ordering claim. */
function createdOf(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) refuse('INVALID_FIELD');
  return value;
}
function finishReasonOf(value: unknown): OpenAiTextFinishReason {
  if (typeof value !== 'string' || !FINISH_REASONS.has(value)) refuse('UNSUPPORTED_FINISH_REASON');
  return value as OpenAiTextFinishReason;
}
/** Assistant text exactly as decoded. Empty content is a valid complete answer and is preserved. */
function contentOf(value: unknown): string {
  if (typeof value !== 'string' || INVALID_UNICODE.test(value)) refuse('UNSUPPORTED_CONTENT');
  return value;
}
/** One native message: `role` and `content` and nothing else. Nothing is dropped silently. */
function messageOf(value: unknown): string {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) refuse('INVALID_FIELD');
  const record = value as Fields;
  for (const key of keysOf(record)) {
    if (MESSAGE_TOOLS.has(key)) refuse('UNSUPPORTED_TOOLS');
    if (MESSAGE_CONTENT.has(key)) refuse('UNSUPPORTED_CONTENT');
    if (!MESSAGE_FIELDS.has(key)) refuse('UNEXPECTED_FIELD');
  }
  if (!Object.hasOwn(record, 'role') || !Object.hasOwn(record, 'content')) refuse('MISSING_FIELD');
  if (record['role'] !== MESSAGE_ROLE) refuse('UNSUPPORTED_ROLE');
  return contentOf(record['content']);
}
/** One complete native choice: `index: 0`, an assistant message and a known finish reason. */
function choiceOf(value: unknown): TranslatedChoice {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) refuse('INVALID_CHOICE');
  const record = value as Fields;
  for (const key of keysOf(record)) {
    if (CHOICE_TOOLS.has(key)) refuse('UNSUPPORTED_TOOLS');
    if (!CHOICE_FIELDS.has(key)) refuse('UNEXPECTED_FIELD');
  }
  if (!Object.hasOwn(record, 'index') || !Object.hasOwn(record, 'message') ||
    !Object.hasOwn(record, 'finish_reason')) refuse('MISSING_FIELD');
  if (record['index'] !== 0) refuse('INVALID_FIELD');
  const content = messageOf(record['message']);
  return { content, finishReason: finishReasonOf(record['finish_reason']) };
}
/** Exactly one choice, so an unexamined alternative answer can never be dropped on the floor. */
function singleChoiceOf(value: unknown): TranslatedChoice {
  if (!Array.isArray(value)) refuse('INVALID_FIELD');
  if (!value.length) refuse('NO_CHOICES');
  if (value.length > OPENAI_TEXT_RESPONSE_LIMITS.maxChoices) refuse('MULTIPLE_CHOICES');
  return choiceOf(value[0]);
}
function tokenCountOf(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) refuse('INVALID_USAGE');
  return value;
}
/** Exactly three counts that add up. An inconsistent or oversized usage block is refused, not repaired. */
function usageOf(value: unknown): OpenAiTextUsage {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) refuse('INVALID_USAGE');
  const record = value as Fields;
  const keys = keysOf(record);
  if (keys.length !== USAGE_FIELDS.length) refuse('INVALID_USAGE');
  for (const key of keys) if (!USAGE_FIELDS.includes(key)) refuse('INVALID_USAGE');
  for (const key of USAGE_FIELDS) if (!Object.hasOwn(record, key)) refuse('INVALID_USAGE');
  const prompt = tokenCountOf(record['prompt_tokens']);
  const completion = tokenCountOf(record['completion_tokens']);
  const total = tokenCountOf(record['total_tokens']);
  if (!Number.isSafeInteger(prompt + completion) || total !== prompt + completion) refuse('INVALID_USAGE');
  return Object.freeze({ prompt_tokens: prompt, completion_tokens: completion, total_tokens: total });
}
/** The single assistant message, frozen whole. It never carries a role, id, usage or authority claim. */
function payloadOf(content: string): JsonValue {
  const messages: JsonValue[] = [Object.freeze({ role: MESSAGE_ROLE, content })];
  Object.freeze(messages);
  return Object.freeze({ messages });
}
/**
 * Translate one untrusted native response. Pure: the same input always yields the same result, and no
 * clock, identifier or timestamp is read here. The draft and the protocol metadata are frozen whole and
 * never alias the input.
 */
function translate(args: Arguments): OpenAiTextResponseResult {
  endpointOf(args.endpoint);
  const text = wireTextOf(args.body);
  const document = decodedDocument(text);
  if (document === null || typeof document !== 'object' || Array.isArray(document)) refuse('BODY_NOT_OBJECT');
  const record = document as Fields;
  for (const key of keysOf(record)) if (!TOP_LEVEL.has(key)) refuse('UNEXPECTED_FIELD');
  for (const key of TOP_LEVEL_REQUIRED) if (!Object.hasOwn(record, key)) refuse('MISSING_FIELD');
  objectOf(record['object']);
  const id = identifierOf(record['id']);
  const model = identifierOf(record['model']);
  const created = createdOf(record['created']);
  const choice = singleChoiceOf(record['choices']);
  const usage = Object.hasOwn(record, 'usage') ? usageOf(record['usage']) : undefined;
  const draft: InteractionDraft = Object.freeze({
    operation: 'model.output',
    payload: payloadOf(choice.content),
    stream: Object.freeze({ mode: 'complete' as const }),
    metadata: Object.freeze({ adapter: ADAPTER, provider: PROVIDER, model }),
  });
  const protocol: OpenAiTextResponseProtocol = Object.freeze({
    id, created, finish_reason: choice.finishReason,
    ...(usage === undefined ? {} : { usage }),
  });
  return Object.freeze({ status: 'TRANSLATED' as const, draft, protocol });
}

/**
 * Translate one complete OpenAI-compatible text chat-completions response, or refuse it with a fixed
 * code. See `docs/contracts/openai-text-response.md`. This authenticates nobody, inspects nothing,
 * sends nothing and releases nothing: a downstream gateway still needs an authenticated boundary,
 * `decidePolicy` and the independent egress sentinel before any byte may leave.
 */
export function translateOpenAiTextResponse(input: unknown): OpenAiTextResponseResult {
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