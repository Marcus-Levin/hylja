# OpenAI text response translation contract (#170)

Status: draft foundation contract for a pure, bounded inbound protocol translation seam. It describes
observable behavior of [`src/openai-text-response.ts`](../../src/openai-text-response.ts). It is **not**
response inspection, classification, policy, authorization, transport or a release control.
Implementation status lives only in [capabilities.md](../capabilities.md).

Scope: translate one untrusted, complete native OpenAI-compatible `/v1/chat/completions` **text
response** into an [`InteractionDraft`](interaction-envelope.md) for `model.output`, with the native
protocol fields preserved beside it. Nothing else. The module parses; a future gateway still needs an
authenticated boundary, conservative inbound inspection, `decidePolicy` and the independent egress
sentinel before anything may be released
([threat-model.md](../threat-model.md), [evaluation.md](../evaluation.md), [slice 3](../specs/slice-3-openai-compatible-gateway.md)).

## Authority

1. A translation is **evidence of parsing, never of permission**. `TRANSLATED` means the body was fully
   read and matched the allowlist below. It never means safe, clean, inspected, approved, authorized or
   free of a credential, and it never decides USE, DISPLAY or EXPORT
   ([decision 003](../decisions/003-semantic-judgment-does-not-own-effects.md),
   [decision 007](../decisions/007-fail-closed-for-protected-egress.md)).
2. **Protected model output stays untrusted text.** The decoder never looks inside the assistant text,
   never substitutes an original, never restores a cloaked value and never grants authority from it.
   Unknown synthetic-looking tokens in the content stay literal text.
3. This module creates **no** `BoundaryContext`, provenance proof, subject, tenant, project, session,
   purpose, destination, profile or trust zone. Those come only from an independently authenticated
   adapter or broker. A response cannot mint them, and no caller-supplied object can stand in for one.
4. Provider and model travel as **non-authority protocol metadata** (`adapter`, `provider`, `model`)
   only. They cannot select a destination, profile, trust zone or policy, exactly as
   [the envelope contract](interaction-envelope.md) requires for `metadata`.
5. The adapter owns **no privacy policy** and sits at **no receive point**. It is a codec building block
   for [slice 3](../specs/slice-3-openai-compatible-gateway.md) under
   [decision 006](../decisions/006-adapter-first-multi-surface-core.md), and it classifies nothing.
6. Unsupported native content is **refused by name**, never forwarded, never dropped and never narrowed
   ([adapter contract](adapter-contract.md)): an unreported field could otherwise reach a later stage as
   if it had been checked.

## Interface

One pure function, one frozen result:

```ts
translateOpenAiTextResponse(input: { endpoint: unknown; body: unknown }): OpenAiTextResponseResult
```

`input` is one object with exactly two own enumerable **data** properties, `endpoint` and `body`. A
getter, an accessor, a symbol key, an inherited property, a third key or a hostile trap is refused; the
arguments are snapshotted through property descriptors and never read again, so a caller object cannot
answer twice. A null-prototype object with two data properties is accepted.

`OpenAiTextResponseResult` is a discriminated union:

- `{ status: 'TRANSLATED', draft: InteractionDraft, protocol: OpenAiTextResponseProtocol }`, where the
  draft is `operation: 'model.output'`, `stream: { mode: 'complete' }`, `payload` holding exactly
  `{ messages: [{ role: 'assistant', content }] }` with the assistant text exactly as decoded, and
  `metadata` carrying adapter, provider and the reported model. `protocol` is the frozen native metadata
  `{ id, created, finish_reason, usage? }`, kept **beside** the draft so a normalized interaction can
  never be confused with a provider record. The whole result is deeply frozen and aliases nothing from
  the input.
- `{ status: 'REFUSED', reason }`, where `reason` is one of the fixed codes below and nothing else.

`body` is the **complete native wire text**, never an already-parsed object. `endpoint` must equal
`/v1/chat/completions` exactly: no trailing slash, no query, no absolute URL, no case folding.

## Accepted subset

| Level | Accepted | Everything else |
|---|---|---|
| Endpoint | `/v1/chat/completions` | refused, including `/v1/responses`, `/v1/completions`, absolute URLs |
| Top level | `id`, `object`, `created`, `model`, `choices`, optional `usage`, nothing else | refused |
| `object` | exactly `chat.completion` | `chat.completion.chunk` refused as streaming, any other value refused |
| `id`, `model` | non-empty, at most 256 units, no control characters, no unpaired surrogate | refused |
| `created` | a safe nonnegative integer, never read as a clock or a freshness proof | refused |
| Choices | exactly one entry | refused |
| Choice fields | `index` (exactly `0`), `message`, `finish_reason`, nothing else | refused |
| `finish_reason` | `stop` or `length` | refused |
| Message fields | `role`, `content` and nothing else | refused |
| `role` | `assistant` | refused |
| `content` | a JSON string of complete Unicode text, **including the empty string** | refused |
| `usage` | exactly `{ prompt_tokens, completion_tokens, total_tokens }`, each a nonnegative safe integer, `total_tokens` their exact safe sum | refused |

Assistant text is preserved exactly as decoded, including multiline text, combining marks, astral
characters and an empty answer. `usage` is **protocol metadata**: it is validated only for internal
consistency and is never billing evidence, policy input or an authority. A missing `usage` is accepted
and the `usage` key is then absent from `protocol`.

## Refusals

Every refusal is one fixed code. No code carries the offending field name, byte offset, parser excerpt,
exception message or any part of the input, so a refusal is safe to log; a planted value never reappears
in a result.

| Code | Meaning |
|---|---|
| `INVALID_ARGUMENTS` | the options object is not exactly two own enumerable data properties |
| `ENDPOINT_NOT_SUPPORTED` | any endpoint other than the exact chat-completions path |
| `BODY_NOT_TEXT` | the body is not native wire text (including an already-parsed object) |
| `BODY_TOO_LARGE` | the body exceeds the UTF-8 byte cap |
| `MALFORMED_JSON` | the body is not complete, well-formed JSON, including an SSE `data:` line, a `[DONE]` marker, trailing content or a raw unpaired surrogate |
| `AMBIGUOUS_BODY` | a duplicate object key at any depth, including an escaped-equivalent key or a duplicate inside a container the allowlist would refuse anyway |
| `PARSE_BUDGET_EXCEEDED` | the bounded parse hit a depth, field, size or time bound |
| `BODY_NOT_OBJECT` | the document is not a JSON object |
| `UNEXPECTED_FIELD` | any field outside the allowlist, at the top level or inside a choice or message |
| `MISSING_FIELD` | a required field is absent |
| `INVALID_FIELD` | a present field has the wrong type or an out-of-bound value: `index` other than `0`, a bad `created`, an out-of-bound `id` or `model`, or a `message` that is not an object |
| `UNSUPPORTED_OBJECT` | any `object` value other than `chat.completion` |
| `STREAMING_NOT_SUPPORTED` | the streaming object `chat.completion.chunk`, and therefore every stream fragment and SSE frame |
| `NO_CHOICES` | the choice list is empty |
| `MULTIPLE_CHOICES` | more than one choice, so an unexamined alternative answer can never be dropped |
| `INVALID_CHOICE` | a choice entry is not an object |
| `UNSUPPORTED_TOOLS` | `tool_calls`, `function_call` or `tool_call_id` at choice or message level |
| `UNSUPPORTED_CONTENT` | content is not a string of complete Unicode text, or a `refusal` field is present: multimodal parts, binary, nested or opaque arrays and objects |
| `UNSUPPORTED_ROLE` | any role other than the literal `assistant`, including another spelling or a non-string |
| `UNSUPPORTED_FINISH_REASON` | any finish reason other than `stop` or `length`, including `tool_calls` and `content_filter` |
| `INVALID_USAGE` | `usage` is not an object, is not exactly those three keys, holds a non-integer or negative count, or a `total_tokens` that is not the exact safe sum |
| `TRANSLATION_ERROR` | fail-closed catch-all for an unexpected internal failure; carries no detail either |

Refusal is the **more restrictive** outcome everywhere: a bound overrun, an ambiguous body or an
unsupported field can only produce a refusal, never a narrower draft. An unsupported native extension is
never silently dropped, so a later stage cannot receive a field it believes was checked.

## Bounds and completeness

The body is bounded at 65,536 **UTF-8 bytes** (not UTF-16 code units), at 256 units for `id` and
`model`, at exactly one choice, and at depth 16 with 512 scalar fields in the bounded parse. These are
fixed constants in the module, not caller-supplied options. The parser counts scalar fields, not
containers: a complete response of this shape contributes eight scalars of its own, so an unknown object
with 504 scalar fields reaches the cap exactly and 505 is refused; an unknown value nested 16 levels
deep is accepted and 17 is refused.

Parsing uses the bounded [structured parser](../architecture.md#detection-pipeline) first and the
platform JSON decoder second. The bounded pass is what makes the second pass safe: it has already proved
the text well formed, structurally complete and free of duplicate keys, so no reader can disagree about
which value is the response. The module does not add a JSON library, a second parser or a general
duplicate-key scanner of its own.

Text that decodes to an unpaired surrogate is refused rather than translated, because UTF-8 encoding
would silently replace it with U+FFFD and the promise of exact text would be broken by a silent
substitution.

## Deliberately absent

No streaming or SSE fragments, no request translation, no tool translation, no response inspection or
classification, no streaming holdback, no socket, HTTP server or client, no provider SDK, no credential
handling, no final-byte check, no policy, no identity, no original restoration, no hosted-tool
interception, and no part of the gateway ([#21](https://github.com/Marcus-Levin/hylja/issues/21)). Nothing
here proves inbound protection or protected egress: it sends no bytes, receives none over a transport
and authenticates nobody. Inbound response inspection, streaming holdback and actual release remain
declared as uncovered rather than partially protected ([integrations.md](../integrations.md)).

Evidence: [`test/openai-text-response.test.mjs`](../../test/openai-text-response.test.mjs), an
executable allowlist/unsupported matrix plus exact byte, field and depth boundaries, duplicate keys,
both finish reasons, optional usage, ordinary and generated Unicode, deep freezing, planted-token
literalness, and one local composition of this decoder with the request codec.