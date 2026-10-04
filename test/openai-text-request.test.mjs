import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  OPENAI_TEXT_REQUEST_ENDPOINT, OPENAI_TEXT_REQUEST_LIMITS, OPENAI_TEXT_REQUEST_REFUSALS,
  translateOpenAiTextRequest,
} from '../dist/openai-text-request.js';

// Synthetic, obviously non-routable development values only.
const ENDPOINT = '/v1/chat/completions';
const MODEL = 'synthetic-model-a.invalid';
const PLANTED = [
  'synthetic-planted-secret@example.invalid',
  'sk-synthetic-planted.invalid',
  'synthetic-planted-bearer-token.invalid',
];

const wire = (value) => JSON.stringify(value);
const request = (value) => ({ endpoint: ENDPOINT, body: wire(value) });
const ask = (content, extra = {}) => request({ model: MODEL, messages: [{ role: 'user', content }], ...extra });
const turn = (count, content) => ({
  model: MODEL,
  messages: Array.from({ length: count }, (unused, index) => ({ role: 'user', content: `${content}-${index}` })),
});
const refuse = (result, reason) => assert.deepEqual(result, { status: 'REFUSED', reason });
const draft = (result) => {
  assert.equal(result.status, 'TRANSLATED', `expected a translated draft, got ${JSON.stringify(result)}`);
  assert.deepEqual(Object.keys(result).sort(), ['draft', 'status']);
  return result.draft;
};
const payloadMessages = (result) => draft(result).payload.messages;
const reason = (result) => {
  assert.equal(result.status, 'REFUSED', `expected a refusal, got ${JSON.stringify(result)}`);
  assert.deepEqual(Object.keys(result).sort(), ['reason', 'status']);
  return result.reason;
};

/**
 * One row per unsupported branch of the allowlist. Every row names a complete native request and the
 * single refusal reason it must produce; none of them may be silently forwarded or silently dropped.
 */
const ALLOWLIST_MATRIX = [
  // Endpoint: only the exact chat-completions path is accepted.
  ['endpoint: responses path', { endpoint: '/v1/responses', body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: legacy completions path', { endpoint: '/v1/completions', body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: trailing slash', { endpoint: '/v1/chat/completions/', body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: query string', { endpoint: '/v1/chat/completions?stream=false', body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: uppercase path', { endpoint: '/V1/Chat/Completions', body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: absolute URL', { endpoint: 'https://api.example.invalid/v1/chat/completions', body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: relative path without a leading slash', { endpoint: 'v1/chat/completions', body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: empty string', { endpoint: '', body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: not a string', { endpoint: null, body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }, 'ENDPOINT_NOT_SUPPORTED'],
  ['endpoint: prototype-inherited', Object.assign(Object.create({ endpoint: ENDPOINT }), { body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }), 'INVALID_ARGUMENTS'],

  // Body: complete native wire text only, well formed and complete.
  ['body: not text', { endpoint: ENDPOINT, body: 5 }, 'BODY_NOT_TEXT'],
  ['body: null', { endpoint: ENDPOINT, body: null }, 'BODY_NOT_TEXT'],
  ['body: already-parsed object', { endpoint: ENDPOINT, body: { model: MODEL, messages: [{ role: 'user', content: 'a' }] } }, 'BODY_NOT_TEXT'],
  ['body: empty text', { endpoint: ENDPOINT, body: '' }, 'MALFORMED_JSON'],
  ['body: truncated array', { endpoint: ENDPOINT, body: '{"model":"m","messages":[' }, 'MALFORMED_JSON'],
  ['body: trailing content', { endpoint: ENDPOINT, body: '{"model":"m","messages":[]} trailing' }, 'MALFORMED_JSON'],
  ['body: two documents', { endpoint: ENDPOINT, body: '{"model":"m","messages":[]}{}' }, 'MALFORMED_JSON'],
  ['body: unterminated string', { endpoint: ENDPOINT, body: '{"model":"m","messages":[{"role":"user","content":"a}]}' }, 'MALFORMED_JSON'],
  ['body: escaped unpaired surrogate in content', { endpoint: ENDPOINT, body: '{"model":"m","messages":[{"role":"user","content":"\\ud800"}]}' }, 'UNSUPPORTED_CONTENT'],
  ['body: number document', { endpoint: ENDPOINT, body: '5' }, 'BODY_NOT_OBJECT'],
  ['body: array document', { endpoint: ENDPOINT, body: '[]' }, 'BODY_NOT_OBJECT'],
  ['body: string document', { endpoint: ENDPOINT, body: '"synthetic"' }, 'BODY_NOT_OBJECT'],
  ['body: null document', { endpoint: ENDPOINT, body: 'null' }, 'BODY_NOT_OBJECT'],

  // Arguments: one object, two own data properties, read once each.
  ['arguments: undefined', undefined, 'INVALID_ARGUMENTS'],
  ['arguments: null', null, 'INVALID_ARGUMENTS'],
  ['arguments: bare text', 'synthetic', 'INVALID_ARGUMENTS'],
  ['arguments: array', [], 'INVALID_ARGUMENTS'],
  ['arguments: empty object', {}, 'INVALID_ARGUMENTS'],
  ['arguments: endpoint only', { endpoint: ENDPOINT }, 'INVALID_ARGUMENTS'],
  ['arguments: body only', { body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }) }, 'INVALID_ARGUMENTS'],
  ['arguments: unknown extra key', { endpoint: ENDPOINT, body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }), policy: 'ALLOW' }, 'INVALID_ARGUMENTS'],
  ['arguments: symbol key', { endpoint: ENDPOINT, body: wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] }), [Symbol('extra')]: 1 }, 'INVALID_ARGUMENTS'],
  ['arguments: getter body', { endpoint: ENDPOINT, get body() { throw new TypeError('synthetic getter'); } }, 'INVALID_ARGUMENTS'],
  ['arguments: throwing proxy', new Proxy({ endpoint: ENDPOINT, body: '{}' }, { ownKeys() { throw new TypeError('synthetic trap'); } }), 'INVALID_ARGUMENTS'],

  // Top-level allowlist: nothing outside model, messages and stream:false.
  ['top level: temperature', ask('a', { temperature: 0.2 }), 'UNEXPECTED_FIELD'],
  ['top level: top_p', ask('a', { top_p: 0.5 }), 'UNEXPECTED_FIELD'],
  ['top level: max_tokens', ask('a', { max_tokens: 16 }), 'UNEXPECTED_FIELD'],
  ['top level: user', ask('a', { user: 'synthetic-user.invalid' }), 'UNEXPECTED_FIELD'],
  ['top level: stop', ask('a', { stop: ['\n'] }), 'UNEXPECTED_FIELD'],
  ['top level: n', ask('a', { n: 2 }), 'UNEXPECTED_FIELD'],
  ['top level: response_format', ask('a', { response_format: { type: 'json_object' } }), 'UNEXPECTED_FIELD'],
  ['top level: metadata', ask('a', { metadata: {} }), 'UNEXPECTED_FIELD'],
  ['top level: seed', ask('a', { seed: 7 }), 'UNEXPECTED_FIELD'],
  ['top level: prototype key', ask('a', JSON.parse('{"__proto__":{"polluted":true}}')), 'UNEXPECTED_FIELD'],

  // Tools and tool calls are refused as unsupported, never forwarded.
  ['tools: tools array', ask('a', { tools: [] }), 'UNSUPPORTED_TOOLS'],
  ['tools: tool_choice', ask('a', { tool_choice: 'auto' }), 'UNSUPPORTED_TOOLS'],
  ['tools: functions array', ask('a', { functions: [] }), 'UNSUPPORTED_TOOLS'],
  ['tools: function_call', ask('a', { function_call: 'auto' }), 'UNSUPPORTED_TOOLS'],
  ['tools: parallel_tool_calls', ask('a', { parallel_tool_calls: true }), 'UNSUPPORTED_TOOLS'],
  ['tools: message tool_calls', request({ model: MODEL, messages: [{ role: 'user', content: 'a', tool_calls: [] }] }), 'UNSUPPORTED_TOOLS'],
  ['tools: message tool_call_id', request({ model: MODEL, messages: [{ role: 'user', content: 'a', tool_call_id: 'call-1' }] }), 'UNSUPPORTED_TOOLS'],
  ['tools: message function_call', request({ model: MODEL, messages: [{ role: 'user', content: 'a', function_call: { name: 'synthetic' } }] }), 'UNSUPPORTED_TOOLS'],

  // Streaming is out of scope for this seam in both directions.
  ['stream: true', ask('a', { stream: true }), 'STREAMING_NOT_SUPPORTED'],
  ['stream: numeric', ask('a', { stream: 1 }), 'INVALID_FIELD'],
  ['stream: string', ask('a', { stream: 'false' }), 'INVALID_FIELD'],
  ['stream: null', ask('a', { stream: null }), 'INVALID_FIELD'],
  ['stream: object', ask('a', { stream: {} }), 'INVALID_FIELD'],

  // Model is a bounded non-empty id and never authority.
  ['model: empty', request({ model: '', messages: [{ role: 'user', content: 'a' }] }), 'INVALID_FIELD'],
  ['model: number', request({ model: 5, messages: [{ role: 'user', content: 'a' }] }), 'INVALID_FIELD'],
  ['model: null', request({ model: null, messages: [{ role: 'user', content: 'a' }] }), 'INVALID_FIELD'],
  ['model: over length', request({ model: 'm'.repeat(257), messages: [{ role: 'user', content: 'a' }] }), 'INVALID_FIELD'],
  ['model: control character', request({ model: 'bad\nmodel', messages: [{ role: 'user', content: 'a' }] }), 'INVALID_FIELD'],
  ['model: leading space', request({ model: ' model', messages: [{ role: 'user', content: 'a' }] }), 'INVALID_FIELD'],
  ['model: missing', request({ messages: [{ role: 'user', content: 'a' }] }), 'MISSING_FIELD'],
  ['model: array', request({ model: ['synthetic'], messages: [{ role: 'user', content: 'a' }] }), 'INVALID_FIELD'],
  ['model: escaped unpaired surrogate', { endpoint: ENDPOINT, body: '{"model":"\\ud83d","messages":[{"role":"user","content":"a"}]}' }, 'INVALID_FIELD'],

  // Messages: a bounded, non-empty array of complete text messages.
  ['messages: missing', request({ model: MODEL }), 'MISSING_FIELD'],
  ['messages: empty list', request({ model: MODEL, messages: [] }), 'NO_MESSAGES'],
  ['messages: string', request({ model: MODEL, messages: 'synthetic' }), 'INVALID_FIELD'],
  ['messages: object', request({ model: MODEL, messages: {} }), 'INVALID_FIELD'],
  ['messages: null', request({ model: MODEL, messages: null }), 'INVALID_FIELD'],
  ['messages: string entry', request({ model: MODEL, messages: ['synthetic'] }), 'INVALID_MESSAGE'],
  ['messages: null entry', request({ model: MODEL, messages: [null] }), 'INVALID_MESSAGE'],
  ['messages: array entry', request({ model: MODEL, messages: [[]] }), 'INVALID_MESSAGE'],
  ['messages: over the count cap', request(turn(65, 'm')), 'TOO_MANY_MESSAGES'],
  ['messages: missing role', request({ model: MODEL, messages: [{ content: 'a' }] }), 'MISSING_FIELD'],
  ['messages: missing content', request({ model: MODEL, messages: [{ role: 'user' }] }), 'MISSING_FIELD'],

  // Roles: only the three literal roles of this text subset.
  ['role: tool', request({ model: MODEL, messages: [{ role: 'tool', content: 'a' }] }), 'UNSUPPORTED_ROLE'],
  ['role: function', request({ model: MODEL, messages: [{ role: 'function', content: 'a' }] }), 'UNSUPPORTED_ROLE'],
  ['role: developer', request({ model: MODEL, messages: [{ role: 'developer', content: 'a' }] }), 'UNSUPPORTED_ROLE'],
  ['role: mixed case', request({ model: MODEL, messages: [{ role: 'User', content: 'a' }] }), 'UNSUPPORTED_ROLE'],
  ['role: trailing space', request({ model: MODEL, messages: [{ role: 'user ', content: 'a' }] }), 'UNSUPPORTED_ROLE'],
  ['role: empty', request({ model: MODEL, messages: [{ role: '', content: 'a' }] }), 'UNSUPPORTED_ROLE'],
  ['role: number', request({ model: MODEL, messages: [{ role: 42, content: 'a' }] }), 'UNSUPPORTED_ROLE'],
  ['role: null', request({ model: MODEL, messages: [{ role: null, content: 'a' }] }), 'UNSUPPORTED_ROLE'],

  // Content: text only. Multimodal, binary and opaque parts are refused, not forwarded.
  ['content: text part array', request({ model: MODEL, messages: [{ role: 'user', content: [{ type: 'text', text: 'a' }] }] }), 'UNSUPPORTED_CONTENT'],
  ['content: image part array', request({ model: MODEL, messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: 'https://example.invalid/a.png' } }] }] }), 'UNSUPPORTED_CONTENT'],
  ['content: audio part array', request({ model: MODEL, messages: [{ role: 'user', content: [{ type: 'input_audio', input_audio: { data: 'synthetic-audio.invalid', format: 'wav' } }] }] }), 'UNSUPPORTED_CONTENT'],
  ['content: nested part array', request({ model: MODEL, messages: [{ role: 'user', content: [['a']] }] }), 'UNSUPPORTED_CONTENT'],
  ['content: object', request({ model: MODEL, messages: [{ role: 'user', content: { text: 'a' } }] }), 'UNSUPPORTED_CONTENT'],
  ['content: null', request({ model: MODEL, messages: [{ role: 'user', content: null }] }), 'UNSUPPORTED_CONTENT'],
  ['content: number', request({ model: MODEL, messages: [{ role: 'user', content: 5 }] }), 'UNSUPPORTED_CONTENT'],
  ['content: boolean', request({ model: MODEL, messages: [{ role: 'user', content: true }] }), 'UNSUPPORTED_CONTENT'],

  // Nested allowlist: a message carries role and content and nothing else.
  ['message field: name', request({ model: MODEL, messages: [{ role: 'user', content: 'a', name: 'synthetic-user' }] }), 'UNEXPECTED_FIELD'],
  ['message field: refusal', request({ model: MODEL, messages: [{ role: 'user', content: 'a', refusal: 'synthetic' }] }), 'UNEXPECTED_FIELD'],
  ['message field: attachments', request({ model: MODEL, messages: [{ role: 'user', content: 'a', attachments: [] }] }), 'UNEXPECTED_FIELD'],
  ['message field: image_url', request({ model: MODEL, messages: [{ role: 'user', content: 'a', image_url: { url: 'https://example.invalid/a.png' } }] }), 'UNEXPECTED_FIELD'],
  ['message field: input_audio', request({ model: MODEL, messages: [{ role: 'user', content: 'a', input_audio: {} }] }), 'UNEXPECTED_FIELD'],
  ['message field: audio', request({ model: MODEL, messages: [{ role: 'user', content: 'a', audio: {} }] }), 'UNEXPECTED_FIELD'],
  ['message field: file', request({ model: MODEL, messages: [{ role: 'user', content: 'a', file: {} }] }), 'UNEXPECTED_FIELD'],
  ['message field: cache_control', request({ model: MODEL, messages: [{ role: 'user', content: 'a', cache_control: { type: 'ephemeral' } }] }), 'UNEXPECTED_FIELD'],
  ['message field: prototype key', request(JSON.parse('{"model":"synthetic-model-a.invalid","messages":[{"role":"user","content":"a","__proto__":{"polluted":true}}]}')), 'UNEXPECTED_FIELD'],
];

test('the exported endpoint, limits and refusal vocabulary are closed and frozen', () => {
  assert.equal(OPENAI_TEXT_REQUEST_ENDPOINT, '/v1/chat/completions');
  assert.deepEqual({ ...OPENAI_TEXT_REQUEST_LIMITS }, {
    maxRequestBytes: 65_536, maxMessages: 64, maxModelLength: 256, maxParseDepth: 16, maxParseFields: 512,
  });
  assert.equal(Object.isFrozen(OPENAI_TEXT_REQUEST_LIMITS), true);
  assert.ok(Object.isFrozen(OPENAI_TEXT_REQUEST_REFUSALS));
  assert.deepEqual([...OPENAI_TEXT_REQUEST_REFUSALS].sort(), [...new Set(OPENAI_TEXT_REQUEST_REFUSALS)].sort());
  for (const code of OPENAI_TEXT_REQUEST_REFUSALS) assert.match(code, /^[A-Z][A-Z_]{3,63}$/u);
});

test('an ordinary multiline text request translates to a complete model.input draft', () => {
  const content = 'first line\nsecond line\n\n  indented last line\n';
  const translated = draft(translateOpenAiTextRequest(request({
    model: MODEL, messages: [{ role: 'system', content: 'be terse\n' }, { role: 'user', content }],
  })));
  assert.equal(translated.operation, 'model.input');
  assert.deepEqual(translated.stream, { mode: 'complete' });
  assert.deepEqual(translated.payload.messages, [
    { role: 'system', content: 'be terse\n' },
    { role: 'user', content },
  ]);
});

test('normal Unicode is preserved exactly, including astral characters and combining marks', () => {
  const cases = [
    'plain ascii text',
    'lines\nwith\r\nwindows and\ttabs',
    'ünïcödé with combining ́ marks',
    '日本語のテキストです',
    'emoji 😀🚀 and a family 👩‍👩‍👧‍👦 sequence',
    'right to left \u202esafe\u202c marker',
    'an escaped astral character \ud83d\ude80 round-trips as its code point',
    'quotes "double" \'single\' and backslash \\ and tab\tinside',
    'control-free content with {} [] and : characters',
  ];
  for (const content of cases) {
    const translated = payloadMessages(translateOpenAiTextRequest(ask(content)));
    assert.equal(translated.length, 1);
    assert.equal(translated[0].content, content);
    assert.equal(translated[0].role, 'user');
  }
});

test('the selected model is protocol metadata and the draft carries no boundary claims', () => {
  const translated = draft(translateOpenAiTextRequest(ask('a')));
  assert.deepEqual(translated.metadata, { adapter: 'hylja.openai-text-request', provider: 'openai', model: MODEL });
  assert.deepEqual(Object.keys(translated).sort(), ['metadata', 'operation', 'payload', 'stream']);
  assert.deepEqual(Object.keys(translated.payload).sort(), ['messages']);
  assert.deepEqual(Object.keys(translated.payload.messages[0]).sort(), ['content', 'role']);
  const serialized = JSON.stringify(translated);
  for (const forbidden of ['subject', 'destination', 'provenance', 'tenant', 'purpose', 'profileId', 'principalId',
    'sessionId', 'trustZone', 'CONTROL']) {
    assert.ok(!serialized.includes(forbidden), `draft must not carry ${forbidden}`);
  }
});

test('a translated request means parsed, never safe, clean, authorized or releasable', () => {
  const result = translateOpenAiTextRequest(ask('a'));
  assert.equal(result.status, 'TRANSLATED');
  const serialized = JSON.stringify(result);
  for (const forbidden of ['safe', 'clean', 'authorized', 'ALLOW', 'USE', 'DISPLAY', 'EXPORT', 'policy',
    'treatment', 'verdict', 'protected']) {
    assert.ok(!serialized.includes(forbidden), `a translation must not assert ${forbidden}`);
  }
  assert.deepEqual(Object.keys(result).sort(), ['draft', 'status']);
});

test('every produced object is frozen and no output aliases caller input state', () => {
  const first = translateOpenAiTextRequest(ask('shared content'));
  const second = translateOpenAiTextRequest(ask('shared content'));
  assert.deepEqual(first, second);
  const translated = draft(first);
  for (const part of [translated, translated.payload, translated.payload.messages, translated.payload.messages[0],
    translated.stream, translated.metadata]) {
    assert.equal(Object.isFrozen(part), true);
  }
  assert.notEqual(first.draft, second.draft);
  assert.notEqual(first.draft.payload, second.draft.payload);
  assert.notEqual(first.draft.payload.messages, second.draft.payload.messages);
  assert.equal(Object.getPrototypeOf(translated.payload), Object.prototype);
  assert.equal(Object.getPrototypeOf(translated.payload.messages), Array.prototype);
});

test('a null-prototype argument object with own data properties is accepted', () => {
  const source = Object.create(null);
  source['endpoint'] = ENDPOINT;
  source['body'] = wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] });
  assert.equal(draft(translateOpenAiTextRequest(source)).operation, 'model.input');
});

test('caller properties are read only through descriptors, never through a getter or a proxy get', () => {
  const body = wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }] });
  let accessorRan = false;
  refuse(translateOpenAiTextRequest({
    endpoint: ENDPOINT,
    get body() { accessorRan = true; return body; },
  }), 'INVALID_ARGUMENTS');
  assert.equal(accessorRan, false, 'an accessor argument must be refused without being invoked');
  const reads = { get: 0 };
  const proxied = new Proxy({ endpoint: ENDPOINT, body }, {
    get(target, key, receiver) { reads.get += 1; return Reflect.get(target, key, receiver); },
  });
  assert.equal(draft(translateOpenAiTextRequest(proxied)).operation, 'model.input');
  assert.equal(reads.get, 0, 'validated arguments must be snapshotted through descriptors, not read again');
});

test('a value thrown while reading arguments is discarded without inspection and cannot escape', () => {
  // The argument proxy throws a value whose own prototype trap throws as well, so *inspecting* the
  // thrown value (an `instanceof` prototype walk, a property read, anything reflective) throws again
  // and would leave the fixed-refusal boundary from inside the catch. The catch must therefore
  // discard the caught value unconditionally. An escaping baseline is caught here and reduced to a
  // boolean, so no planted message or stack can ever reach the TAP report.
  const planted = 'synthetic-throwing-proxy.invalid';
  const hostile = new Proxy({ endpoint: ENDPOINT, body: wire({ model: MODEL, messages: [] }) }, {
    ownKeys() { throw new Proxy({}, { getPrototypeOf() { throw new Error(planted); } }); },
  });
  let escaped = true;
  let outcome = null;
  try {
    outcome = translateOpenAiTextRequest(hostile);
    escaped = false;
  } catch (unused) {
    outcome = null;
  }
  assert.equal(escaped, false, 'argument validation must not let a thrown value escape as a fixed refusal');
  refuse(outcome, 'INVALID_ARGUMENTS');
  assert.equal(Object.isFrozen(outcome), true);
});

test('stream:false is accepted and still translates to a complete non-streaming draft', () => {
  const translated = draft(translateOpenAiTextRequest(ask('a', { stream: false })));
  assert.deepEqual(translated.stream, { mode: 'complete' });
  assert.equal(translated.payload.messages.length, 1);
});

test('the allowlist matrix refuses every unsupported branch with its own fixed reason', async (t) => {
  for (const [label, input, expected] of ALLOWLIST_MATRIX) {
    await t.test(label, () => { refuse(translateOpenAiTextRequest(input), expected); });
  }
});

test('ambiguous duplicate object keys are refused, including escaped-equivalent and nested duplicates', async (t) => {
  const cases = [
    ['duplicate top-level key', '{"model":"m","model":"n","messages":[{"role":"user","content":"a"}]}'],
    ['escaped equivalent key', '{"model":"m","\\u006dodel":"n","messages":[{"role":"user","content":"a"}]}'],
    ['duplicate key inside a message', '{"model":"m","messages":[{"role":"user","role":"system","content":"a"}]}'],
    ['duplicate key inside a rejected content array', '{"model":"m","messages":[{"role":"user","content":[{"type":"text","type":"image_url"}]}]}'],
    ['duplicate key inside a rejected tool container', '{"model":"m","messages":[{"role":"user","content":"a"}],"tools":[{"type":"function","type":"file"}]}'],
    ['duplicate message element key', '{"model":"m","messages":[{"role":"user","content":"a","name":"x","name":"y"}]}'],
  ];
  for (const [label, body] of cases) {
    await t.test(label, () => { refuse(translateOpenAiTextRequest({ endpoint: ENDPOINT, body }), 'AMBIGUOUS_BODY'); });
  }
});

test('bounded parse budgets refuse restrictively: depth excess, field excess and unterminated containers', async (t) => {
  const deep = '['.repeat(40) + ']'.repeat(40);
  const fields = Object.fromEntries(Array.from({ length: 600 }, (unused, index) => [`synthetic_key_${index}`, index]));
  const cases = [
    ['depth excess in an unknown field', wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }], extra: JSON.parse(deep) })],
    ['field excess in an unknown object', wire({ model: MODEL, messages: [{ role: 'user', content: 'a' }], extra: fields })],
  ];
  for (const [label, body] of cases) {
    await t.test(label, () => { refuse(translateOpenAiTextRequest({ endpoint: ENDPOINT, body }), 'PARSE_BUDGET_EXCEEDED'); });
  }
});

test('the request byte cap is measured in UTF-8 bytes and applies to a complete request', async (t) => {
  const cap = OPENAI_TEXT_REQUEST_LIMITS.maxRequestBytes;
  const ofBytes = (target) => {
    const skeleton = wire({ model: MODEL, messages: [{ role: 'user', content: '' }] });
    const padding = target - Buffer.byteLength(skeleton, 'utf8');
    assert.ok(padding >= 0);
    return { body: wire({ model: MODEL, messages: [{ role: 'user', content: 'x'.repeat(padding) }] }), padding };
  };
  await t.test('a body of exactly the cap is translated with its text intact', () => {
    const { body, padding } = ofBytes(cap);
    assert.equal(Buffer.byteLength(body, 'utf8'), cap);
    const translated = payloadMessages(translateOpenAiTextRequest({ endpoint: ENDPOINT, body }));
    assert.equal(translated[0].content.length, padding);
  });
  await t.test('a body one byte over the cap is refused', () => {
    const { body } = ofBytes(cap + 1);
    refuse(translateOpenAiTextRequest({ endpoint: ENDPOINT, body }), 'BODY_TOO_LARGE');
  });
  await t.test('a multibyte body under the cap in code units but over it in bytes is refused', () => {
    const body = wire({ model: MODEL, messages: [{ role: 'user', content: 'é'.repeat(32_769) }] });
    assert.ok(body.length < cap);
    assert.ok(Buffer.byteLength(body, 'utf8') > cap);
    refuse(translateOpenAiTextRequest({ endpoint: ENDPOINT, body }), 'BODY_TOO_LARGE');
  });
});

test('generated bounded message lists preserve content and ordering up to the cap', async (t) => {
  const cap = OPENAI_TEXT_REQUEST_LIMITS.maxMessages;
  await t.test('a single message at the cap preserves order, roles and text', () => {
    const roles = ['system', 'user', 'assistant'];
    const messages = Array.from({ length: cap }, (unused, index) => ({
      role: roles[index % 3], content: `synthetic-turn-${index}-é😀`,
    }));
    const translated = payloadMessages(translateOpenAiTextRequest(request({ model: MODEL, messages })));
    assert.equal(translated.length, cap);
    for (const [index, message] of translated.entries()) {
      assert.deepEqual(message, messages[index]);
    }
  });
  await t.test('the same request translated twice is identical', () => {
    const body = wire(turn(16, 'synthetic-turn'));
    assert.deepEqual(translateOpenAiTextRequest({ endpoint: ENDPOINT, body }),
      translateOpenAiTextRequest({ endpoint: ENDPOINT, body }));
  });
});

test('no refusal reason or diagnostic carries a planted original, a parser excerpt or a native error', async (t) => {
  const refusals = [
    ask(PLANTED[0], { temperature: 0.1 }),
    ask(PLANTED[0], { stream: true }),
    ask(PLANTED[0], { tools: [{ type: 'function', function: { name: 'synthetic' } }] }),
    request({ model: MODEL, messages: [{ role: 'user', content: [{ type: 'text', text: PLANTED[1] }] }] }),
    request({ model: MODEL, messages: [{ role: 'user', content: PLANTED[0] }], metadata: { authorization: PLANTED[2] } }),
    { endpoint: ENDPOINT, body: `{"model":"${MODEL}","messages":[{"role":"user","content":"${PLANTED[0]}"` },
    { endpoint: ENDPOINT, body: `{"model":"${MODEL}","model":"${MODEL}","messages":[{"role":"user","content":"${PLANTED[0]}"}]}` },
    { endpoint: ENDPOINT, body: `{"model":"${MODEL}","messages":[{"role":"user","content":"${PLANTED[0]}"}],"extra":{"${PLANTED[2]}":1}}` },
    { endpoint: ENDPOINT, body: 5 },
    undefined,
  ];
  for (const [index, input] of refusals.entries()) {
    await t.test(`refusal ${index} is a fixed code`, () => {
      const result = translateOpenAiTextRequest(input);
      assert.equal(result.status, 'REFUSED');
      assert.ok(OPENAI_TEXT_REQUEST_REFUSALS.includes(result.reason));
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
    assert.ok(OPENAI_TEXT_REQUEST_REFUSALS.includes(code), `${code} must be in the closed vocabulary`);
  }
  // TRANSLATION_ERROR is reserved for an unexpected internal failure and carries no detail, so it is
  // exported but deliberately not produced by any request in this matrix.
  assert.ok(OPENAI_TEXT_REQUEST_REFUSALS.includes('TRANSLATION_ERROR'));
  assert.ok(!exercised.has('TRANSLATION_ERROR'));
});