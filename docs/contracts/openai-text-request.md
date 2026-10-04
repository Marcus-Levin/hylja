# OpenAI text request translation contract (#164)

Status: draft foundation contract for a pure, bounded protocol translation seam. It describes observable
behavior of [`src/openai-text-request.ts`](../../src/openai-text-request.ts). It is **not** a gateway,
transport, authorization layer, policy decision or release control. Implementation status lives only in
[capabilities.md](../capabilities.md).

Scope: translate one untrusted, complete native OpenAI-compatible `/v1/chat/completions` **text request**
into an [`InteractionDraft`](interaction-envelope.md). Nothing else. The module parses; a future send path
still needs an authenticated boundary, `decidePolicy` and the independent egress sentinel before any byte
may leave ([threat-model.md](../threat-model.md), [evaluation.md](../evaluation.md)).

## Authority

1. A translation is **evidence of parsing, never of permission**. `TRANSLATED` means the body was fully
   read and matched the allowlist below. It never means safe, clean, inspected, approved or authorized,
   and it never decides USE, DISPLAY or EXPORT
   ([decision 003](../decisions/003-semantic-judgment-does-not-own-effects.md),
   [decision 007](../decisions/007-fail-closed-for-protected-egress.md)).
2. This module creates **no** `BoundaryContext`, provenance proof, subject, tenant, project, session,
   purpose, destination, profile or trust zone. Those come only from an independently authenticated
   adapter or broker. A payload cannot mint them, and no caller-supplied object can stand in for one.
3. Provider and model travel as **non-authority protocol metadata** (`adapter`, `provider`, `model`)
   only. They cannot select a destination, profile, trust zone or policy, exactly as
   [the envelope contract](interaction-envelope.md) requires for `metadata`.
4. The adapter owns **no privacy policy** and sits at **no send point**. It is a codec building block for
   [slice 3](../specs/slice-3-openai-compatible-gateway.md) under
   [decision 006](../decisions/006-adapter-first-multi-surface-core.md), and it can classify nothing.
5. Unsupported native content is **refused by name**, never forwarded, never dropped and never narrowed
   ([adapter contract](adapter-contract.md)): an unreported field could otherwise reach a later stage as
   if it had been checked.

## Interface

One pure function, one frozen result:

```ts
translateOpenAiTextRequest(input: { endpoint: unknown; body: unknown }): OpenAiTextRequestResult
```

`input` is one object with exactly two own enumerable **data** properties, `endpoint` and `body`. A
getter, an accessor, a symbol key, an inherited property, a third key or a hostile trap is refused; the
arguments are snapshotted through property descriptors and never read again, so a caller object cannot
answer twice. A null-prototype object with two data properties is accepted.

`OpenAiTextRequestResult` is a discriminated union:

- `{ status: 'TRANSLATED', draft: InteractionDraft }`, where the draft is
  `operation: 'model.input'`, `stream: { mode: 'complete' }`, `payload: { messages: [...] }` in native
  order with each message exactly `{ role, content }`, and `metadata` carrying adapter, provider and the
  selected model. The whole result is frozen and aliases nothing from the input.
- `{ status: 'REFUSED', reason }`, where `reason` is one of the fixed codes below and nothing else.

`body` is the **complete native wire text**, never an already-parsed object. `endpoint` must equal
`/v1/chat/completions` exactly: no trailing slash, no query, no absolute URL, no case folding.

## Accepted subset

| Level | Accepted | Everything else |
|---|---|---|
| Endpoint | `/v1/chat/completions` | refused, including `/v1/responses`, `/v1/completions`, absolute URLs |
| Top level | `model` (non-empty, at most 256 units, no control characters, no unpaired surrogate), `messages`, optional `stream: false` | refused |
| Message count | 1 to 64 | refused |
| Message fields | `role`, `content` and nothing else | refused |
| Roles | `system`, `user`, `assistant` | refused |
| Content | a JSON string of complete Unicode text | refused |

Message text is preserved exactly as decoded, including multiline text, combining marks and astral
characters. `stream: false` is accepted and still yields one complete, non-streamed draft.

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
| `MALFORMED_JSON` | the body is not complete, well-formed JSON, or holds an unpaired surrogate in the raw text |
| `AMBIGUOUS_BODY` | a duplicate object key at any depth, including an escaped-equivalent key or a duplicate inside a container the allowlist would refuse anyway |
| `PARSE_BUDGET_EXCEEDED` | the bounded parse hit a depth, field, size or time bound |
| `BODY_NOT_OBJECT` | the document is not a JSON object |
| `UNEXPECTED_FIELD` | any field outside the allowlist, top level or inside a message |
| `MISSING_FIELD` | a required field is absent |
| `INVALID_FIELD` | a present field has the wrong type or an out-of-bound value, including `stream` values other than `false` |
| `UNSUPPORTED_TOOLS` | tools, tool choice, functions, tool calls or a tool-call id are present |
| `UNSUPPORTED_CONTENT` | content is not a string of complete Unicode text: multimodal parts, binary, nested or opaque arrays and objects |
| `UNSUPPORTED_ROLE` | any role other than the three literal roles, including another spelling or a non-string |
| `INVALID_MESSAGE` | a message entry is not an object |
| `STREAMING_NOT_SUPPORTED` | `stream: true` |
| `NO_MESSAGES` | the message list is empty |
| `TOO_MANY_MESSAGES` | the message list is over the count cap |
| `TRANSLATION_ERROR` | fail-closed catch-all for an unexpected internal failure; carries no detail either |

Refusal is the **more restrictive** outcome everywhere: a bound overrun, an ambiguous body or an
unsupported field can only produce a refusal, never a narrower draft.

## Bounds and completeness

The body is bounded at 65,536 **UTF-8 bytes** (not UTF-16 code units), at 64 messages, at a 256-unit model
id, and at depth 16 with 512 scalar fields in the bounded parse. These are fixed constants in the module,
not caller-supplied options.

Parsing uses the bounded [structured parser](../architecture.md#detection-pipeline) first and the
platform JSON decoder second. The bounded pass is what makes the second pass safe: it has already proved
the text well formed, structurally complete and free of duplicate keys, so no reader can disagree about
which value is the request. The module does not add a JSON library, a second parser or a general
duplicate-key scanner of its own.

Text that decodes to an unpaired surrogate is refused rather than translated, because UTF-8 encoding would
silently replace it with U+FFFD and the promise of exact text would be broken by a silent substitution.

## Deliberately absent

No streaming or SSE, no response decoder, no tool translation, no socket, HTTP server or client, no
provider SDK, no credential handling, no final-byte check, no policy, no identity, no original
restoration, no hosted-tool interception, and no part of the gateway
([#21](https://github.com/Marcus-Levin/hylja/issues/21)). Nothing here proves protected egress: it sends
no bytes and authenticates nobody. Multimodal, tool and streaming coverage remain declared as uncovered
rather than partially protected ([integrations.md](../integrations.md)).

Evidence: [`test/openai-text-request.test.mjs`](../../test/openai-text-request.test.mjs), an executable
allowlist matrix covering every refusal branch plus positive text, Unicode, ordering and each bound.