import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  OPENAI_TEXT_RESPONSE_ENDPOINT, OPENAI_TEXT_RESPONSE_LIMITS, OPENAI_TEXT_RESPONSE_REFUSALS,
  translateOpenAiTextResponse,
} from '../dist/openai-text-response.js';
import { OPENAI_TEXT_REQUEST_ENDPOINT, translateOpenAiTextRequest } from '../dist/openai-text-request.js';

// Synthetic, obviously non-routable development values only.
const ENDPOINT = '/v1/chat/completions';
const ID = 'chatcmpl-synthetic-a';
const CREATED = 1_735_689_600;
const MODEL = 'synthetic-model-a.invalid';
const PLANTED = [
  'synthetic-planted-secret@example.invalid',
  'sk-synthetic-planted.invalid',
  'synthetic-planted-bearer-token.invalid',
];

const ANSWER = [{ index: 0, message: { role: 'assistant', content: 'synthetic answer' }, finish_reason: 'stop' }];
const wire = (value) => JSON.stringify(value);
/** A plain native response object, so a test can build wire text or the arguments object from it. */
const completion = (overrides = {}) => ({ id: ID, object: 'chat.completion', created: CREATED, model: MODEL, choices: ANSWER, ...overrides });
const withContent = (content, overrides = {}) => completion({
  choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }], ...overrides,
});
/** The exact two-property arguments object the seam accepts. */
const request = (overrides = {}) => ({ endpoint: ENDPOINT, body: wire(completion(overrides)) });
const say = (content, overrides = {}) => request({
  choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }], ...overrides,
});
const one = (message, finish = 'stop') => [{ index: 0, message, finish_reason: finish }];
const answer = (content, finish = 'stop') => one({ role: 'assistant', content }, finish);
const finishSay = (content, finish) => request({ choices: answer(content, finish) });
const refuse = (result, expected) => assert.deepEqual(result, { status: 'REFUSED', reason: expected });
const reason = (result) => {
  assert.equal(result.status, 'REFUSED', `expected a refusal, got ${JSON.stringify(result)}`);
  assert.deepEqual(Object.keys(result).sort(), ['reason', 'status']);
  return result.reason;
};
const translated = (result) => {
  assert.equal(result.status, 'TRANSLATED', `expected a translated draft, got ${JSON.stringify(result)}`);
  assert.deepEqual(Object.keys(result).sort(), ['draft', 'protocol', 'status']);
  return result;
};

/**
 * One row per unsupported branch of the accepted subset. Every row names a complete native response
 * body and the single refusal reason it must produce; none may be silently dropped, narrowed or
 * forwarded, because an unreported native field could reach a later stage as if it had been checked.
 */
const ALLOWLIST_MATRIX = [
  // Endpoint: only the exact chat-completions path this seam intercepts.
  ['endpoint: responses path', { endpoint: '/v1/responses', body: wire(completion()) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: legacy completions path', { endpoint: '/v1/completions', body: wire(completion()) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: trailing slash', { endpoint: '/v1/chat/completions/', body: wire(completion()) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: query string', { endpoint: '/v1/chat/completions?stream=false', body: wire(completion()) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: absolute URL', { endpoint: 'https://api.example.invalid/v1/chat/completions', body: wire(completion()) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: empty string', { endpoint: '', body: wire(completion()) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: not a string', { endpoint: null, body: wire(completion()) }, 'ENDPOINT_NOT_SUPPORTED'],

  // Arguments: one object, two own enumerable data properties, read once each.
  ['arguments: undefined', undefined, 'INVALID_ARGUMENTS'],
  ['arguments: null', null, 'INVALID_ARGUMENTS'],
  ['arguments: bare text', 'synthetic', 'INVALID_ARGUMENTS'],
  ['arguments: array', [], 'INVALID_ARGUMENTS'],
  ['arguments: empty object', {}, 'INVALID_ARGUMENTS'],
  ['arguments: endpoint only', { endpoint: ENDPOINT }, 'INVALID_ARGUMENTS'],
  ['arguments: body only', { body: wire(completion()) }, 'INVALID_ARGUMENTS'],
  ['arguments: unknown extra key', { endpoint: ENDPOINT, body: wire(completion()), policy: 'ALLOW' }, 'INVALID_ARGUMENTS'],
  ['arguments: symbol key', { endpoint: ENDPOINT, body: wire(completion()), [Symbol('extra')]: 1 }, 'INVALID_ARGUMENTS'],
  ['arguments: getter body', { endpoint: ENDPOINT, get body() { throw new TypeError('synthetic getter'); } }, 'INVALID_ARGUMENTS'],
  ['arguments: throwing proxy', new Proxy({ endpoint: ENDPOINT, body: '{}' }, { ownKeys() { throw new TypeError('synthetic trap'); } }), 'INVALID_ARGUMENTS'],
  ['arguments: transparent forwarding proxy', new Proxy(request(), {}), 'INVALID_ARGUMENTS'],
  ['arguments: revoked proxy', (() => { const revocable = Proxy.revocable(request(), {}); revocable.revoke(); return revocable.proxy; })(), 'INVALID_ARGUMENTS'],
  ['arguments: prototype-inherited', Object.assign(Object.create({ endpoint: ENDPOINT }), { body: wire(completion()) }), 'INVALID_ARGUMENTS'],

  // Body: complete native wire text only, well formed and complete.
  ['body: not text', { endpoint: ENDPOINT, body: 5 }, 'BODY_NOT_TEXT'],
  ['body: null', { endpoint: ENDPOINT, body: null }, 'BODY_NOT_TEXT'],
  ['body: already-parsed object', { endpoint: ENDPOINT, body: completion() }, 'BODY_NOT_TEXT'],
  ['body: empty text', { endpoint: ENDPOINT, body: '' }, 'MALFORMED_JSON'],
  ['body: truncated object', { endpoint: ENDPOINT, body: '{"id":"chatcmpl-synthetic-a","choices":[' }, 'MALFORMED_JSON'],
  ['body: trailing content', { endpoint: ENDPOINT, body: `${wire(completion())} trailing` }, 'MALFORMED_JSON'],
  ['body: two documents', { endpoint: ENDPOINT, body: `${wire(completion())}${'{}'}` }, 'MALFORMED_JSON'],
  ['body: unterminated string', { endpoint: ENDPOINT, body: '{"id":"chatcmpl-synthetic-a","choices":[{"message":{"content":"a}]}' }, 'MALFORMED_JSON'],
  ['body: server-sent event line', { endpoint: ENDPOINT, body: `data: ${wire(completion())}\n\n` }, 'MALFORMED_JSON'],
  ['body: event-stream with terminating chunk marker', { endpoint: ENDPOINT, body: `${wire(completion())}\ndata: [DONE]\n\n` }, 'MALFORMED_JSON'],
  ['body: number document', { endpoint: ENDPOINT, body: '5' }, 'BODY_NOT_OBJECT'],
  ['body: array document', { endpoint: ENDPOINT, body: '[]' }, 'BODY_NOT_OBJECT'],
  ['body: string document', { endpoint: ENDPOINT, body: '"synthetic"' }, 'BODY_NOT_OBJECT'],
  ['body: null document', { endpoint: ENDPOINT, body: 'null' }, 'BODY_NOT_OBJECT'],

  // Top level: id, object, created, model, choices and optional usage, nothing else.
  ['top level: system_fingerprint', request({ system_fingerprint: 'fp_synthetic' }), 'UNEXPECTED_FIELD'],
  ['top level: service_tier', request({ service_tier: 'default' }), 'UNEXPECTED_FIELD'],
  ['top level: error envelope', request({ error: { message: 'synthetic', code: 'synthetic' } }), 'UNEXPECTED_FIELD'],
  ['top level: prompt_logprobs', request({ prompt_logprobs: 1 }), 'UNEXPECTED_FIELD'],
  ['top level: max_tokens', request({ max_tokens: 16 }), 'UNEXPECTED_FIELD'],
  ['top level: tools echoed back', request({ tools: [] }), 'UNEXPECTED_FIELD'],
  ['top level: prototype key', { endpoint: ENDPOINT, body: JSON.stringify(JSON.parse(`{"id":"${ID}","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[],"__proto__":{"polluted":true}}`)) }, 'UNEXPECTED_FIELD'],
  ['top level: id missing', request({ id: undefined }), 'MISSING_FIELD'],
  ['top level: object missing', request({ object: undefined }), 'MISSING_FIELD'],
  ['top level: created missing', request({ created: undefined }), 'MISSING_FIELD'],
  ['top level: model missing', request({ model: undefined }), 'MISSING_FIELD'],
  ['top level: choices missing', request({ choices: undefined }), 'MISSING_FIELD'],

  // Object: the complete chat-completion object only. Streaming is a different object, not a variant.
  ['object: streaming chunk', request({ object: 'chat.completion.chunk' }), 'STREAMING_NOT_SUPPORTED'],
  ['object: legacy text completion', request({ object: 'text_completion' }), 'UNSUPPORTED_OBJECT'],
  ['object: listing', request({ object: 'list' }), 'UNSUPPORTED_OBJECT'],
  ['object: mixed case', request({ object: 'Chat.Completion' }), 'UNSUPPORTED_OBJECT'],
  ['object: empty', request({ object: '' }), 'UNSUPPORTED_OBJECT'],
  ['object: number', request({ object: 7 }), 'UNSUPPORTED_OBJECT'],
  ['object: null', request({ object: null }), 'UNSUPPORTED_OBJECT'],

  // Identifiers: bounded non-empty protocol strings, never authority.
  ['id: empty', request({ id: '' }), 'INVALID_FIELD'],
  ['id: number', request({ id: 7 }), 'INVALID_FIELD'],
  ['id: over length', request({ id: 'i'.repeat(257) }), 'INVALID_FIELD'],
  ['id: control character', request({ id: 'bad\nid' }), 'INVALID_FIELD'],
  ['id: leading space', request({ id: ' id' }), 'INVALID_FIELD'],
  ['id: escaped unpaired surrogate', { endpoint: ENDPOINT, body: `{"id":"\\ud83d","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[]}` }, 'INVALID_FIELD'],
  ['model: empty', request({ model: '' }), 'INVALID_FIELD'],
  ['model: over length', request({ model: 'm'.repeat(257) }), 'INVALID_FIELD'],
  ['model: control character', request({ model: 'bad\nmodel' }), 'INVALID_FIELD'],
  ['model: number', request({ model: 7 }), 'INVALID_FIELD'],

  // created: a safe nonnegative integer, checked for safety and not trusted as a clock.
  ['created: negative', request({ created: -1 }), 'INVALID_FIELD'],
  ['created: fractional', request({ created: 1.5 }), 'INVALID_FIELD'],
  ['created: string', request({ created: '1735689600' }), 'INVALID_FIELD'],
  ['created: null', request({ created: null }), 'INVALID_FIELD'],
  ['created: boolean', request({ created: true }), 'INVALID_FIELD'],
  ['created: overflowing literal', { endpoint: ENDPOINT, body: `{"id":"${ID}","object":"chat.completion","created":1e400,"model":"${MODEL}","choices":[]}` }, 'INVALID_FIELD'],

  // Choices: exactly one complete, non-streamed choice.
  ['choices: empty list', request({ choices: [] }), 'NO_CHOICES'],
  ['choices: two entries', request({ choices: [...answer('a'), ...answer('b')] }), 'MULTIPLE_CHOICES'],
  ['choices: not an array', request({ choices: 'synthetic' }), 'INVALID_FIELD'],
  ['choices: object', request({ choices: {} }), 'INVALID_FIELD'],
  ['choices: null', request({ choices: null }), 'INVALID_FIELD'],
  ['choices: string entry', request({ choices: ['synthetic'] }), 'INVALID_CHOICE'],
  ['choices: null entry', request({ choices: [null] }), 'INVALID_CHOICE'],
  ['choices: array entry', request({ choices: [[]] }), 'INVALID_CHOICE'],

  // Choice object: index, message and finish_reason, nothing else.
  ['choice field: logprobs', request({ choices: [{ index: 0, message: { role: 'assistant', content: 'a' }, finish_reason: 'stop', logprobs: null }] }), 'UNEXPECTED_FIELD'],
  ['choice field: unknown', request({ choices: [{ index: 0, message: { role: 'assistant', content: 'a' }, finish_reason: 'stop', extra: 1 }] }), 'UNEXPECTED_FIELD'],
  ['choice field: prototype key', { endpoint: ENDPOINT, body: `{"id":"${ID}","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[{"index":0,"message":{"role":"assistant","content":"a"},"finish_reason":"stop","__proto__":{"polluted":true}}]}` }, 'UNEXPECTED_FIELD'],
  ['choice: index missing', request({ choices: [{ message: { role: 'assistant', content: 'a' }, finish_reason: 'stop' }] }), 'MISSING_FIELD'],
  ['choice: index one', request({ choices: [{ index: 1, message: { role: 'assistant', content: 'a' }, finish_reason: 'stop' }] }), 'INVALID_FIELD'],
  ['choice: index string', request({ choices: [{ index: '0', message: { role: 'assistant', content: 'a' }, finish_reason: 'stop' }] }), 'INVALID_FIELD'],
  ['choice: index float', request({ choices: [{ index: 0.5, message: { role: 'assistant', content: 'a' }, finish_reason: 'stop' }] }), 'INVALID_FIELD'],
  ['choice: finish_reason missing', request({ choices: [{ index: 0, message: { role: 'assistant', content: 'a' } }] }), 'MISSING_FIELD'],
  ['choice: finish_reason tool_calls', request({ choices: answer('a', 'tool_calls') }), 'UNSUPPORTED_FINISH_REASON'],
  ['choice: finish_reason content_filter', request({ choices: answer('a', 'content_filter') }), 'UNSUPPORTED_FINISH_REASON'],
  ['choice: finish_reason mixed case', request({ choices: answer('a', 'Stop') }), 'UNSUPPORTED_FINISH_REASON'],
  ['choice: finish_reason null', request({ choices: answer('a', null) }), 'UNSUPPORTED_FINISH_REASON'],
  ['choice: message missing', request({ choices: [{ index: 0, finish_reason: 'stop' }] }), 'MISSING_FIELD'],
  ['choice: message not an object', request({ choices: [{ index: 0, message: 'synthetic', finish_reason: 'stop' }] }), 'INVALID_FIELD'],
  ['choice: message array', request({ choices: [{ index: 0, message: [], finish_reason: 'stop' }] }), 'INVALID_FIELD'],

  // Message: exactly role and content. Tool, function and refusal carriers are unsupported.
  ['message: tool_calls', request({ choices: one({ role: 'assistant', content: 'a', tool_calls: [] }) }), 'UNSUPPORTED_TOOLS'],
  ['message: function_call', request({ choices: one({ role: 'assistant', content: 'a', function_call: { name: 'synthetic' } }) }), 'UNSUPPORTED_TOOLS'],
  ['message: tool_call_id', request({ choices: one({ role: 'assistant', content: 'a', tool_call_id: 'call-synthetic' }) }), 'UNSUPPORTED_TOOLS'],
  ['message: refusal', request({ choices: one({ role: 'assistant', content: 'a', refusal: 'synthetic' }) }), 'UNSUPPORTED_CONTENT'],
  ['message: audio', request({ choices: one({ role: 'assistant', content: 'a', audio: {} }) }), 'UNEXPECTED_FIELD'],
  ['message: annotations', request({ choices: one({ role: 'assistant', content: 'a', annotations: [] }) }), 'UNEXPECTED_FIELD'],
  ['message: reasoning', request({ choices: one({ role: 'assistant', content: 'a', reasoning: 'synthetic' }) }), 'UNEXPECTED_FIELD'],
  ['message: name', request({ choices: one({ role: 'assistant', content: 'a', name: 'synthetic' }) }), 'UNEXPECTED_FIELD'],
  ['message: logprobs', request({ choices: one({ role: 'assistant', content: 'a', logprobs: [] }) }), 'UNEXPECTED_FIELD'],
  ['message: role missing', request({ choices: one({ content: 'a' }) }), 'MISSING_FIELD'],
  ['message: content missing', request({ choices: one({ role: 'assistant' }) }), 'MISSING_FIELD'],
  ['message: role user', request({ choices: one({ role: 'user', content: 'a' }) }), 'UNSUPPORTED_ROLE'],
  ['message: role tool', request({ choices: one({ role: 'tool', content: 'a' }) }), 'UNSUPPORTED_ROLE'],
  ['message: role developer', request({ choices: one({ role: 'developer', content: 'a' }) }), 'UNSUPPORTED_ROLE'],
  ['message: role trailing space', request({ choices: one({ role: 'assistant ', content: 'a' }) }), 'UNSUPPORTED_ROLE'],
  ['message: role null', request({ choices: one({ role: null, content: 'a' }) }), 'UNSUPPORTED_ROLE'],
  ['message: role number', request({ choices: one({ role: 1, content: 'a' }) }), 'UNSUPPORTED_ROLE'],
  ['message: content null', request({ choices: one({ role: 'assistant', content: null }) }), 'UNSUPPORTED_CONTENT'],
  ['message: content number', request({ choices: one({ role: 'assistant', content: 5 }) }), 'UNSUPPORTED_CONTENT'],
  ['message: content boolean', request({ choices: one({ role: 'assistant', content: true }) }), 'UNSUPPORTED_CONTENT'],
  ['message: content object', request({ choices: one({ role: 'assistant', content: { text: 'a' } }) }), 'UNSUPPORTED_CONTENT'],
  ['message: content text part array', request({ choices: one({ role: 'assistant', content: [{ type: 'text', text: 'a' }] }) }), 'UNSUPPORTED_CONTENT'],
  ['message: content audio part array', request({ choices: one({ role: 'assistant', content: [{ type: 'audio', audio: { data: 'synthetic.invalid' } }] }) }), 'UNSUPPORTED_CONTENT'],
  ['message: content nested part array', request({ choices: one({ role: 'assistant', content: [['a']] }) }), 'UNSUPPORTED_CONTENT'],
  ['message: escaped unpaired surrogate', { endpoint: ENDPOINT, body: `{"id":"${ID}","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[{"index":0,"message":{"role":"assistant","content":"\\ud83d"},"finish_reason":"stop"}]}` }, 'UNSUPPORTED_CONTENT'],

  // usage: exactly three token counts that add up, as protocol metadata only.
  ['usage: not an object', request({ usage: 6 }), 'INVALID_USAGE'],
  ['usage: array', request({ usage: [] }), 'INVALID_USAGE'],
  ['usage: null', request({ usage: null }), 'INVALID_USAGE'],
  ['usage: empty object', request({ usage: {} }), 'INVALID_USAGE'],
  ['usage: missing total_tokens', request({ usage: { prompt_tokens: 1, completion_tokens: 2 } }), 'INVALID_USAGE'],
  ['usage: extra key', request({ usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3, prompt_tokens_details: {} } }), 'INVALID_USAGE'],
  ['usage: negative count', request({ usage: { prompt_tokens: -1, completion_tokens: 2, total_tokens: 1 } }), 'INVALID_USAGE'],
  ['usage: fractional count', request({ usage: { prompt_tokens: 1.5, completion_tokens: 2, total_tokens: 3.5 } }), 'INVALID_USAGE'],
  ['usage: string count', request({ usage: { prompt_tokens: '1', completion_tokens: 2, total_tokens: 3 } }), 'INVALID_USAGE'],
  ['usage: inconsistent total', request({ usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 4 } }), 'INVALID_USAGE'],
  ['usage: unsafe total', request({ usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: Number.MAX_SAFE_INTEGER + 2 } }), 'INVALID_USAGE'],
  ['usage: prototype key', { endpoint: ENDPOINT, body: `{"id":"${ID}","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[{"index":0,"message":{"role":"assistant","content":"a"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"__proto__":{"polluted":true}}}` }, 'INVALID_USAGE'],
];

test('the exported endpoint, limits and refusal vocabulary are closed and frozen', () => {
  assert.equal(OPENAI_TEXT_RESPONSE_ENDPOINT, '/v1/chat/completions');
  assert.deepEqual({ ...OPENAI_TEXT_RESPONSE_LIMITS }, {
    maxResponseBytes: 65_536, maxIdentifierLength: 256, maxChoices: 1, maxParseDepth: 16, maxParseFields: 512,
  });
  assert.equal(Object.isFrozen(OPENAI_TEXT_RESPONSE_LIMITS), true);
  assert.ok(Object.isFrozen(OPENAI_TEXT_RESPONSE_REFUSALS));
  assert.deepEqual([...OPENAI_TEXT_RESPONSE_REFUSALS].sort(), [...new Set(OPENAI_TEXT_RESPONSE_REFUSALS)].sort());
  for (const code of OPENAI_TEXT_RESPONSE_REFUSALS) assert.match(code, /^[A-Z][A-Z_]{3,63}$/u);
});

test('an ordinary complete text response translates to one model.output draft', () => {
  const content = 'first line\nsecond line\n\n  indented last line\n';
  const result = translated(translateOpenAiTextResponse(say(content, { usage: { prompt_tokens: 4, completion_tokens: 9, total_tokens: 13 } })));
  assert.deepEqual(result.draft, {
    operation: 'model.output',
    payload: { messages: [{ role: 'assistant', content }] },
    stream: { mode: 'complete' },
    metadata: { adapter: 'hylja.openai-text-response', provider: 'openai', model: MODEL },
  });
  assert.deepEqual(result.protocol, {
    id: ID, created: CREATED, finish_reason: 'stop', usage: { prompt_tokens: 4, completion_tokens: 9, total_tokens: 13 },
  });
});

test('protocol metadata travels beside the draft and never inside it', () => {
  const result = translated(translateOpenAiTextResponse(say('synthetic answer')));
  assert.deepEqual(Object.keys(result.protocol).sort(), ['created', 'finish_reason', 'id']);
  assert.deepEqual(Object.keys(result.draft).sort(), ['metadata', 'operation', 'payload', 'stream']);
  assert.deepEqual(Object.keys(result.draft.payload).sort(), ['messages']);
  assert.deepEqual(Object.keys(result.draft.payload.messages[0]).sort(), ['content', 'role']);
  const serialized = JSON.stringify(result.draft);
  for (const forbidden of ['usage', 'finish_reason', 'created', 'subject', 'destination', 'provenance',
    'tenant', 'purpose', 'profileId', 'principalId', 'sessionId', 'trustZone', 'CONTROL']) {
    assert.ok(!serialized.includes(forbidden), `the draft must not carry ${forbidden}`);
  }
});

test('both accepted finish reasons translate and no other finish reason does', async (t) => {
  for (const finish of ['stop', 'length']) {
    await t.test(`finish_reason ${finish}`, () => {
      const result = translated(translateOpenAiTextResponse(finishSay('synthetic answer', finish)));
      assert.equal(result.protocol.finish_reason, finish);
      assert.deepEqual(result.draft.stream, { mode: 'complete' });
    });
  }
});

test('usage is optional, and when present it is exactly three counts that add up', async (t) => {
  await t.test('a response without usage translates', () => {
    const result = translated(translateOpenAiTextResponse(say('synthetic answer')));
    assert.deepEqual(Object.hasOwn(result.protocol, 'usage'), false);
    assert.deepEqual(result.protocol, { id: ID, created: CREATED, finish_reason: 'stop' });
  });
  await t.test('zero counts translate and stay zero', () => {
    const result = translated(translateOpenAiTextResponse(say('', { usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 } })));
    assert.deepEqual(result.protocol.usage, { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 });
    assert.equal(result.draft.payload.messages[0].content, '');
  });
  await t.test('usage is not billing authority and grants nothing', () => {
    const result = translateOpenAiTextResponse(say('synthetic answer', { usage: { prompt_tokens: 4, completion_tokens: 9, total_tokens: 13 } }));
    const serialized = JSON.stringify(result);
    for (const forbidden of ['billing', 'cost', 'credit', 'price', 'invoice', 'charged']) {
      assert.ok(!serialized.includes(forbidden), `usage must not assert ${forbidden}`);
    }
  });
});

test('empty assistant content is allowed and preserved', () => {
  const result = translated(translateOpenAiTextResponse(say('')));
  assert.deepEqual(result.draft.payload.messages, [{ role: 'assistant', content: '' }]);
  assert.equal(result.protocol.finish_reason, 'stop');
});

test('ordinary Unicode is preserved exactly, including astral characters and combining marks', () => {
  const cases = [
    'plain ascii text',
    'lines\nwith\r\nwindows and\ttabs',
    'ünïcödé with combining ́ marks',
    '日本語のテキストです',
    'emoji 😀🚀 and a family 👩‍👩‍👧‍👦 sequence',
    'right to left ‮safe‬ marker',
    'an escaped astral character 🚀 round-trips as its code point',
    'quotes "double" \'single\' and backslash \\ and tab\tinside',
    'control-free content with {} [] and : characters',
    'zero width joiner 👩‍👩‍👧‍👦 and a combining ring ȩ́',
  ];
  for (const content of cases) {
    const result = translated(translateOpenAiTextResponse(say(content)));
    assert.deepEqual(result.draft.payload.messages, [{ role: 'assistant', content }]);
  }
});

test('generated Unicode content survives the round trip byte for byte', () => {
  const generated = (() => {
    const points = [];
    for (let point = 0x20; point <= 0x7e; point += 1) points.push(point);
    for (let point = 0xa0; point <= 0x2ff; point += 7) points.push(point);
    for (let point = 0x3040; point <= 0x9fff; point += 41) points.push(point);
    for (let point = 0x1f300; point <= 0x1f6ff; point += 13) points.push(point);
    for (let point = 0x10000; point <= 0x10ffff; point += 4093) points.push(point);
    return String.fromCodePoint(...points);
  })();
  const result = translated(translateOpenAiTextResponse(say(generated)));
  assert.equal(result.draft.payload.messages[0].content, generated);
  assert.equal(result.draft.payload.messages[0].content.length, generated.length);
});

test('a translated response means parsed, never safe, clean, authorized or releasable', () => {
  const result = translateOpenAiTextResponse(say('synthetic answer'));
  assert.equal(result.status, 'TRANSLATED');
  const serialized = JSON.stringify(result);
  for (const forbidden of ['safe', 'clean', 'authorized', 'ALLOW', 'USE', 'DISPLAY', 'EXPORT', 'policy',
    'treatment', 'verdict', 'protected', 'release']) {
    assert.ok(!serialized.includes(forbidden), `a translation must not assert ${forbidden}`);
  }
});

test('every produced object is deeply frozen and no output aliases a previous result', () => {
  const input = say('synthetic answer', { usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } });
  const first = translateOpenAiTextResponse(input);
  const second = translateOpenAiTextResponse(input);
  assert.deepEqual(first, second);
  const result = translated(first);
  for (const part of [result, result.draft, result.draft.payload, result.draft.payload.messages,
    result.draft.payload.messages[0], result.draft.stream, result.draft.metadata, result.protocol, result.protocol.usage]) {
    assert.equal(Object.isFrozen(part), true);
  }
  assert.notEqual(first.draft, second.draft);
  assert.notEqual(first.protocol, second.protocol);
  assert.notEqual(first.draft.payload.messages, second.draft.payload.messages);
  assert.equal(Object.getPrototypeOf(result.draft.payload), Object.prototype);
  assert.equal(Object.getPrototypeOf(result.draft.payload.messages), Array.prototype);
  assert.equal(Object.isFrozen(result.draft.metadata), true);
  assert.throws(() => { result.draft.metadata.model = 'mutated.invalid'; }, TypeError,
    'a deeply frozen result must reject a write to its protocol metadata');
});

test('a null-prototype argument object with own data properties is accepted', () => {
  const source = Object.create(null);
  source['endpoint'] = ENDPOINT;
  source['body'] = wire(completion());
  assert.equal(translateOpenAiTextResponse(source).status, 'TRANSLATED');
});

test('caller properties are read only through descriptors, never through an invoked getter', () => {
  let accessorRan = false;
  refuse(translateOpenAiTextResponse({
    endpoint: ENDPOINT,
    get body() { accessorRan = true; return wire(completion()); },
  }), 'INVALID_ARGUMENTS');
  assert.equal(accessorRan, false, 'an accessor argument must be refused without being invoked');
  assert.equal(translateOpenAiTextResponse(request()).status, 'TRANSLATED',
    'ordinary data properties must still translate after the accessor refusal');
});

test('a transparent proxy argument is refused with the fixed refusal and runs no trap', () => {
  // The original acceptance criterion is that caller proxies refuse, not merely that a hostile proxy
  // throws: a forwarding proxy that presents the right prototype, keys and descriptors must never
  // reach TRANSLATED, because it can answer a second, different answer to any later reader of the
  // same object. Detection has to be an intrinsic brand check, so no prototype, key or descriptor
  // read can run a trap first, and a revoked proxy is refused by the same fixed code path.
  const traps = { get: 0, ownKeys: 0, getOwnPropertyDescriptor: 0, getPrototypeOf: 0 };
  const count = (name) => (target, ...rest) => { traps[name] += 1; return Reflect[name](target, ...rest); };
  const forwarding = new Proxy({ endpoint: ENDPOINT, body: wire(completion()) }, {
    get: count('get'),
    ownKeys: count('ownKeys'),
    getOwnPropertyDescriptor: count('getOwnPropertyDescriptor'),
    getPrototypeOf: count('getPrototypeOf'),
  });
  refuse(translateOpenAiTextResponse(forwarding), 'INVALID_ARGUMENTS');
  assert.deepEqual(traps, { get: 0, ownKeys: 0, getOwnPropertyDescriptor: 0, getPrototypeOf: 0 },
    'a proxy argument must be refused before any reflective read can run one of its traps');
  const revocable = Proxy.revocable({ endpoint: ENDPOINT, body: wire(completion()) }, {});
  revocable.revoke();
  let escaped = true;
  let outcome = null;
  try {
    outcome = translateOpenAiTextResponse(revocable.proxy);
    escaped = false;
  } catch (unused) {
    outcome = null;
  }
  assert.equal(escaped, false, 'a revoked proxy argument must return a fixed refusal, never throw');
  refuse(outcome, 'INVALID_ARGUMENTS');
});

test('a value thrown while reading arguments is discarded without inspection and cannot escape', () => {
  // The argument proxy throws a value whose own prototype trap throws as well, so *inspecting* the
  // thrown value (an `instanceof` prototype walk, a property read, anything reflective) throws again
  // and would leave the fixed-refusal boundary from inside the catch. The catch must therefore
  // discard the caught value unconditionally. An escaping baseline is caught here and reduced to a
  // boolean, so no planted message or stack can ever reach the TAP report.
  const planted = 'synthetic-throwing-proxy.invalid';
  const hostile = new Proxy({ endpoint: ENDPOINT, body: wire(completion()) }, {
    ownKeys() { throw new Proxy({}, { getPrototypeOf() { throw new Error(planted); } }); },
  });
  let escaped = true;
  let outcome = null;
  try {
    outcome = translateOpenAiTextResponse(hostile);
    escaped = false;
  } catch (unused) {
    outcome = null;
  }
  assert.equal(escaped, false, 'argument validation must not let a thrown value escape as a fixed refusal');
  refuse(outcome, 'INVALID_ARGUMENTS');
  assert.equal(Object.isFrozen(outcome), true);
});

test('the allowlist matrix refuses every unsupported branch with its own fixed reason', async (t) => {
  for (const [label, input, expected] of ALLOWLIST_MATRIX) {
    await t.test(label, () => { refuse(translateOpenAiTextResponse(input), expected); });
  }
});

test('ambiguous duplicate object keys are refused, including escaped-equivalent and nested duplicates', async (t) => {
  const cases = [
    ['duplicate top-level key', `{"id":"${ID}","id":"chatcmpl-synthetic-b","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[]}`],
    ['escaped equivalent key', `{"id":"${ID}","\\u0069d":"chatcmpl-synthetic-b","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[]}`],
    ['duplicate key inside a choice', `{"id":"${ID}","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[{"index":0,"message":{"role":"assistant","content":"a"},"finish_reason":"stop","finish_reason":"length"}]}`],
    ['duplicate key inside a message', `{"id":"${ID}","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[{"index":0,"message":{"role":"assistant","role":"user","content":"a"},"finish_reason":"stop"}]}`],
    ['duplicate key inside usage', `{"id":"${ID}","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[],"usage":{"prompt_tokens":1,"prompt_tokens":2,"completion_tokens":0,"total_tokens":1}}`],
    ['duplicate key inside a rejected container', `{"id":"${ID}","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[{"index":0,"message":{"role":"assistant","content":[{"type":"text","type":"image_url"}]},"finish_reason":"stop"}]}`],
  ];
  for (const [label, body] of cases) {
    await t.test(label, () => { refuse(translateOpenAiTextResponse({ endpoint: ENDPOINT, body }), 'AMBIGUOUS_BODY'); });
  }
});

test('the identifier length bound is exact at 256 units', async (t) => {
  await t.test('an identifier of exactly the cap translates', () => {
    const result = translated(translateOpenAiTextResponse(say('synthetic answer', { id: 'i'.repeat(256), model: 'm'.repeat(256) })));
    assert.equal(result.protocol.id.length, 256);
    assert.equal(result.draft.metadata.model.length, 256);
  });
  await t.test('an identifier one unit over the cap is refused', () => {
    refuse(translateOpenAiTextResponse(say('synthetic answer', { id: 'i'.repeat(257) })), 'INVALID_FIELD');
  });
});

test('the response byte cap is measured in UTF-8 bytes and applies to a complete response', async (t) => {
  const cap = OPENAI_TEXT_RESPONSE_LIMITS.maxResponseBytes;
  const ofBytes = (target) => {
    const skeleton = wire(withContent(''));
    const padding = target - Buffer.byteLength(skeleton, 'utf8');
    assert.ok(padding >= 0);
    return { body: wire(withContent('x'.repeat(padding))), padding };
  };
  await t.test('a response of exactly the cap translates with its text intact', () => {
    const { body, padding } = ofBytes(cap);
    assert.equal(Buffer.byteLength(body, 'utf8'), cap);
    const result = translated(translateOpenAiTextResponse({ endpoint: ENDPOINT, body }));
    assert.equal(result.draft.payload.messages[0].content.length, padding);
  });
  await t.test('a response one byte over the cap is refused', () => {
    const { body } = ofBytes(cap + 1);
    refuse(translateOpenAiTextResponse({ endpoint: ENDPOINT, body }), 'BODY_TOO_LARGE');
  });
  await t.test('a multibyte response under the cap in code units but over it in bytes is refused', () => {
    const body = wire(withContent('é'.repeat(32_769)));
    assert.ok(body.length < cap);
    assert.ok(Buffer.byteLength(body, 'utf8') > cap);
    refuse(translateOpenAiTextResponse({ endpoint: ENDPOINT, body }), 'BODY_TOO_LARGE');
  });
});

test('the bounded parse budget is exact at 512 scalar fields', () => {
  // The cap counts scalar fields across the whole body, not containers. This body contributes eight
  // scalars of its own (id, object, created, model, index, finish_reason, role, content), so 504 extra
  // scalar fields reach the 512-field cap exactly. The transition is located by a bounded search rather
  // than assumed: the largest accepted body must be refused by the allowlist, and one field more by the
  // budget.
  const ofFields = (count) => {
    const extra = Object.fromEntries(Array.from({ length: count }, (unused, index) => [`synthetic_key_${index}`, index]));
    return { endpoint: ENDPOINT, body: wire(completion({ extra })) };
  };
  const fits = (count) => translateOpenAiTextResponse(ofFields(count)).reason === 'UNEXPECTED_FIELD';
  assert.equal(fits(0), true, 'no extra field is inside the budget');
  let low = 0;
  let high = 512;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (fits(middle)) low = middle; else high = middle - 1;
  }
  assert.equal(low, 504, '504 extra scalar fields plus the 8 body scalars fill the 512-field cap');
  refuse(translateOpenAiTextResponse(ofFields(low + 1)), 'PARSE_BUDGET_EXCEEDED');
});

test('the bounded parse budget is exact at depth 16', () => {
  const ofDepth = (depth) => ({
    endpoint: ENDPOINT,
    body: wire(completion({ extra: JSON.parse(`${'['.repeat(depth)}${']'.repeat(depth)}`) })),
  });
  const fits = (depth) => translateOpenAiTextResponse(ofDepth(depth)).reason === 'UNEXPECTED_FIELD';
  let low = 1;
  let high = 40;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (fits(middle)) low = middle; else high = middle - 1;
  }
  assert.equal(low, 16, 'a 16-deep unknown value sits exactly at the depth-16 cap');
  refuse(translateOpenAiTextResponse(ofDepth(low + 1)), 'PARSE_BUDGET_EXCEEDED');
});

test('unknown synthetic-looking tokens stay literal text: no substitution, no authority', () => {
  const content = [
    PLANTED[0], PLANTED[1], PLANTED[2],
    'contact synthetic-person-a@example.invalid about synthetic-project-b.invalid',
    'AKIAIOSFODNN7EXAMPLE', 'ghp_0123456789abcdefghijklmnopqrstuvwxyz',
    '-----BEGIN RSA PRIVATE KEY-----',
  ].join('\n');
  const result = translated(translateOpenAiTextResponse(say(content)));
  assert.equal(result.draft.payload.messages[0].content, content, 'model output text is translated verbatim');
  for (const planted of PLANTED) {
    assert.ok(result.draft.payload.messages[0].content.includes(planted), 'text stays literal, never substituted');
    assert.ok(!JSON.stringify(result.draft.metadata).includes(planted), 'a token never becomes metadata');
  }
  const serialized = JSON.stringify(result);
  for (const forbidden of ['original', 'uncloak', 'mapping', 'restore', 'CONTROL', 'profileId', 'destination']) {
    assert.ok(!serialized.includes(forbidden), `the decoder must not assert ${forbidden}`);
  }
});

test('the request and response codecs compose over one synthetic exchange, with no transport', () => {
  assert.equal(OPENAI_TEXT_REQUEST_ENDPOINT, OPENAI_TEXT_RESPONSE_ENDPOINT,
    'both seams translate the one intercepted path');
  const question = 'synthetic question with a planted value ' + PLANTED[0];
  const answerText = 'synthetic answer with a planted value ' + PLANTED[1];
  const asked = translateOpenAiTextRequest({
    endpoint: ENDPOINT,
    body: wire({ model: MODEL, messages: [{ role: 'user', content: question }] }),
  });
  const answered = translateOpenAiTextResponse(request({
    usage: { prompt_tokens: 7, completion_tokens: 7, total_tokens: 14 },
  }));
  assert.equal(asked.status, 'TRANSLATED');
  assert.equal(answered.status, 'TRANSLATED');
  assert.equal(asked.draft.operation, 'model.input');
  assert.equal(answered.draft.operation, 'model.output');
  assert.deepEqual(asked.draft.metadata.model, answered.draft.metadata.model);
  assert.deepEqual(asked.draft.payload.messages, [{ role: 'user', content: question }]);
  assert.deepEqual(answered.draft.payload.messages, [{ role: 'assistant', content: 'synthetic answer' }]);
  assert.deepEqual(Object.keys(asked.draft.stream), ['mode']);
  assert.deepEqual(Object.keys(answered.draft.stream), ['mode']);
});

test('no refusal reason or diagnostic carries a planted original, a parser excerpt or a native error', async (t) => {
  const refusals = [
    say(PLANTED[0], { system_fingerprint: 'fp_synthetic' }),
    say(PLANTED[0], { object: 'chat.completion.chunk' }),
    request({ choices: answer(PLANTED[0], 'tool_calls') }),
    request({ choices: one({ role: 'assistant', content: PLANTED[0], tool_calls: [{ id: 'call-synthetic' }] }) }),
    request({ choices: one({ role: 'assistant', content: [{ type: 'text', text: PLANTED[1] }] }) }),
    request({ usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 9 }, id: PLANTED[2] }),
    { endpoint: ENDPOINT, body: `{"id":"${ID}","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[{"index":0,"message":{"role":"assistant","content":"${PLANTED[0]}"` },
    { endpoint: ENDPOINT, body: `{"id":"${ID}","id":"${PLANTED[0]}","object":"chat.completion","created":${CREATED},"model":"${MODEL}","choices":[]}` },
    { endpoint: ENDPOINT, body: 5 },
    undefined,
  ];
  for (const [index, input] of refusals.entries()) {
    await t.test(`refusal ${index} is a fixed code`, () => {
      const result = translateOpenAiTextResponse(input);
      assert.equal(result.status, 'REFUSED');
      assert.ok(OPENAI_TEXT_RESPONSE_REFUSALS.includes(result.reason));
      const serialized = JSON.stringify(result);
      for (const planted of PLANTED) assert.ok(!serialized.includes(planted));
      assert.ok(!/Error|exception|at Object|\.ts:\d/u.test(serialized));
      assert.match(serialized, /^\{"status":"REFUSED","reason":"[A-Z_]+"\}$/u);
    });
  }
});

test('every refusal reason exercised above belongs to the exported closed vocabulary', () => {
  const exercised = new Set([
    ...ALLOWLIST_MATRIX.map((row) => row[2]),
    'AMBIGUOUS_BODY', 'PARSE_BUDGET_EXCEEDED', 'BODY_TOO_LARGE',
  ]);
  for (const code of exercised) {
    assert.ok(OPENAI_TEXT_RESPONSE_REFUSALS.includes(code), `${code} must be in the closed vocabulary`);
  }
  // TRANSLATION_ERROR is reserved for an unexpected internal failure and carries no detail, so it is
  // exported but deliberately not produced by any response in this matrix.
  assert.ok(OPENAI_TEXT_RESPONSE_REFUSALS.includes('TRANSLATION_ERROR'));
  assert.ok(!exercised.has('TRANSLATION_ERROR'));
  assert.equal(reason(translateOpenAiTextResponse(undefined)), 'INVALID_ARGUMENTS');
  assert.equal(reason(translateOpenAiTextResponse(request({ object: 'chat.completion.chunk' }))), 'STREAMING_NOT_SUPPORTED');
});