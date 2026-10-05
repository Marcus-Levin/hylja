# Bounded local OpenAI conversation owner contract (#236)

Status: draft foundation contract for [#236](https://github.com/Marcus-Levin/hylja/issues/236), child of
[#21](https://github.com/Marcus-Levin/hylja/issues/21) and
[#22](https://github.com/Marcus-Levin/hylja/issues/22). It documents observable behavior of
[`src/openai-local-conversation.ts`](../../src/openai-local-conversation.ts). It is **not** a gateway, a
listener, a provider client, an authentication implementation, a credential or vault path, a redirect,
retry or streaming design, or a global protection claim. Implementation status lives only in
[capabilities.md](../capabilities.md); the whole-message `MASK` it composes is accepted
[decision 011](../decisions/011-policy-selected-whole-message-mask.md), while
[decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) stays **proposed**.

## Why this exists, and what it is not

[openai-text-sender.md](openai-text-sender.md) and [openai-keep-receiver.md](openai-keep-receiver.md) own one
half of a complete text conversation each, but each takes its transport or release point as a trusted host
function, so neither owns a socket and the joined evidence so far
([openai-conversation.e2e test](../../test/openai-conversation.e2e.test.mjs)) is test-local. This module
composes the same two accepted owners **without replacing either** and owns the narrow loopback transport
itself: one call runs one request, one bounded complete reply and one guarded release, or refuses with a
fixed code and does neither. It **authenticates nobody** - the boundary, the pinned policy commit, the
classification evidence, the observed destination and the application sink are trusted because the host
authenticates them, exactly as the [policy contract](policy-contract.md) and the
[sentinel process contract](egress-sentinel-process.md) state - decides nothing, restores nothing and
narrows nothing either owner accepts, so a unit the detector stack covers nothing in is still
`INSPECTION_REFUSED`: detector absence never clears a unit.

## Interface

```ts
createOpenAiLocalConversation(host: unknown): {
  exchange(input: unknown): Promise<{ status: 'COMPLETED' } | { status: 'REFUSED'; code: LocalConversationRefusal }>;
  cancel(): void;
  readonly state: 'IDLE' | 'BUSY' | 'CANCELLED' | 'FAILED';
}
```

Three members, nothing else: no prepared-byte handle, no replay, no `AbortSignal`. Cancellation is
owner-owned, sticky and one-way. Construction never throws and never opens a socket; an unusable host or
endpoint yields a permanently restrictive owner whose state is `FAILED`.

`exchange(input)` takes exactly `{ body }`, so **no caller value can carry an endpoint, a destination, a
treatment or a release point**: any other own key is `INVALID_ARGUMENTS` and opens no socket. One exchange
is in flight at a time, claimed synchronously, so a second concurrent call is `CONVERSATION_BUSY`.

### The trusted host

Exactly six own **data** properties, where `sender` and `receiver` are the two accepted owner hosts
**minus** their `sendPoint` and `releasePoint`: this module supplies both, so a host cannot retarget the
socket or the application sink after construction. Any unknown key, accessor, symbol key, missing member,
non-function member or hostile trap (a revoked Proxy included) is `HOST_INVALID` and opens nothing.

| Member | Meaning |
|---|---|
| `port` | the one numeric loopback TCP port, `1`-`65535`; anything else is `ENDPOINT_REFUSED` at construction |
| `timeoutMs` | exchange deadline, `1`-`120_000`; out of range is `HOST_INVALID`, never silently clamped |
| `observe()` | independently observed destination/profile and the committed policy identity, for both owners |
| `onReply(text)` | the application sink: called once, only through the receiver's own release point |
| `sender` | `boundary`, `sourceTrust`, `policyBundle`, `scope`, `known`, `sentinel`, `inspectOriginal` |
| `receiver` | `boundary`, `policyBundle`, `scope`, `known`, `sentinel`, `inspect` |

## The owned transport

**The endpoint is captured, never re-derived.** One numeric port is captured at construction and read only
from the closure; the destination is the literal `127.0.0.1` with `localAddress` pinned to the same literal
and `family: 4`. There is no host name, no URL, no name resolution, no TLS, no proxy and no redirect.

**Readiness is a required member of the send point this owner supplies**, so the endpoint is confirmed
**before** any byte exists on the wire: `waitUntilReady()` opens the one bounded connection, checks
`connecting` is false and that `remotePort`, `remoteAddress`, `remoteFamily` and `localAddress` all match
that captured endpoint, and captures the socket's `write` and `end` functions. A mismatch closes the
socket and fails the exchange. Readiness sends nothing, approves nothing and decides nothing; it is
awaited only after the inspection, the policy decisions, the derivation and the real child `ALLOW`, and
the composed sender then re-reads the route, commit, evidence freshness and cancellation **after** it.

**The handoff is immediate.** Once those guards are read, one synchronous turn calls the captured
`write(image)` with the **exact sender-checked bytes** on the already connected socket and then `end()`:
the promise executor runs inside the sender's own dispatch call, so no callback, no `await` and no host
input separates them. That write is preceded by a re-read of cancellation and of `destroyed`,
`connecting`, `writable` and `bytesWritten === 0`. The kernel may still hold the write in its own buffer;
that carries no authority, and the endpoint was confirmed before the write rather than after it.

**Exactly one supported reply profile**, decided here and refused rather than tolerated:

| Element | Accepted value |
|---|---|
| status line | exactly `HTTP/1.1 200 OK` |
| header block | at most `4096` bytes **of head, terminator included**, at most `32` fields |
| field names/values | RFC token names, visible ASCII or tab values, no duplicate name |
| `Transfer-Encoding` | absent; its presence is refused, never parsed |
| `Content-Encoding` | absent; this owner implements no decompression, so even `identity` is refused |
| `Content-Length` | exactly one, `^[1-9][0-9]*$`, at most `65536` bytes |
| `Content-Type` | `application/json`, optionally with `charset=utf-8` or `charset="utf-8"`; an unmatched quote is refused |
| body | exactly the declared length, decodable as **strict UTF-8** |

**The header bound is on the header block alone**, never on the bytes coalesced with it: the CRLFCRLF
terminator is located first and the bound applied to its offset plus those four bytes, so a valid body
larger than `4096` bytes is accepted identically whether the peer coalesced it with the head, segmented
it, or split the terminator across two reads. Only an unterminated block that already passes the bound is
`RESPONSE_TOO_LARGE`. The declared body length is a second, independent bound.

Chunked, compressed, opaque, truncated, mislabelled, oversized, duplicated, empty-length and undecodable
replies are refused, never truncated and never guessed. **Surplus after the declared length is ignored,
not refused**: the first reply's exactly declared bytes are cut, the remainder is never parsed, and the
socket is closed rather than drained — the accepted one-response profile terminates the connection
instead of reading past what it authorized. Bytes after the declared length never reach a codec. The
body bound is the strict response codec's own `maxResponseBytes`, reused rather than
restated, and no codec rule is re-implemented here. One exchange settles once: every received chunk and
every concatenation this owner allocated for it are zeroed in that one place, the socket is destroyed, and
the reply buffer is zeroed after its single decode or when the exchange ends without one, on the accepted
path and on every refusal alike, as is any socket that was prepared but never dispatched. The `unref`'d
deadline timer is cleared. That claims the buffers
**this module allocated** and nothing else: no erasure of immutable strings, caller input, runtime, peer
or child copies, and no heap, RSS or swap erasure is claimed or proved.

## The accepted path

1. Validate the call shape and this module's fixed route, then run the composed **sender** unchanged -
   strict request codec, private ORIGINAL image, snapshot-bound inspection evidence over it, the real `SEND`
   policy decision per unit with its accepted `KEEP`/`MASK` plan, and the real fixed-worker child over the
   final bytes.
2. Await the sender's readiness on the captured endpoint, then hand the exact checked bytes over
   immediately on the connected socket, read one bounded reply under the profile above, decode it as
   strict UTF-8, then run the
   composed **receiver** over that text unchanged - its own strict codec, private canonical image,
   inspection, real policy decision per unit, real fixed-worker child and guarded release - for exactly one
   `onReply` call.

Both owners keep their own accepted paths and refusal vocabularies in full, and their codes pass through
unchanged. Nothing is retried, and a failed release is reported, not rolled back.

## Refusals

Every refusal is one fixed code, or one of the two composed owners' own fixed codes. No code carries a
field name, byte offset, excerpt, exception message, transport error, socket address, status line or any
part of the input, and no result carries bytes, a digest or a handle.

| Code | Meaning |
|---|---|
| `HOST_INVALID` | the trusted host is not the exact declared shape, or the deadline is out of range |
| `ENDPOINT_REFUSED` | no usable numeric loopback port was bound at construction |
| `INVALID_ARGUMENTS` | the call was not exactly `{ body }` |
| `CONVERSATION_BUSY` | one exchange is already in flight; no queue, pool or replay |
| `CANCELLED` | `cancel()` was observed, or this owner was already cancelled |
| `TRANSPORT_FAILED` | the owned socket could not be opened, is not the captured endpoint, or failed early |
| `RESPONSE_REFUSED` | the reply is outside the supported profile, or its body is not decodable UTF-8 |
| `RESPONSE_TRUNCATED` | the peer closed before the declared body length arrived |
| `RESPONSE_TOO_LARGE` | the header-block bound was passed before a complete head was seen |
| `RESPONSE_TIMEOUT` | the exchange did not complete inside the bound |
| `CONVERSATION_FAILED` | fail-closed catch-all for an unexpected internal failure |

## Limits, absent surface and evidence

- **The host is trusted.** An unauthenticated boundary, a profile digest not derived from the committed
  profile, an inspection callback that classifies nothing real and an `onReply` that ignores or reshapes
  the text it is given all pass straight through. The composed owners' re-reads are congruence checks, not
  authentication: deriving the profile digest and producing genuine whole-image detector evidence for
  every unit are integration-host obligations.
- **The peer is a loopback peer.** No redirect, retry, TLS, proxy or name resolution is followed or
  supported; only `127.0.0.1` on the captured port is reachable, for the duration of one exchange. One
  complete non-streamed reply: a stream fragment, tool call, multimodal part or second choice is the
  strict codec's refusal, not a partial read.
- **Deliberately absent:** no HTTP listener, gateway route, provider SDK, credential, API key, vault or
  broker, no original restoration, no streaming or SSE fragment, no tools or hosted-tool interception, no
  direct mapping lookup and no claim of global protection. A production authenticated conversation path
  remains host adapter work ([threat-model.md](../threat-model.md)).
- **Not an evaluation result.** The evidence is unscored, synthetic and non-enforcing: not a held-out
  result, a comparative win or promotion evidence ([evaluation.md](../evaluation.md)).

[`test/openai-local-conversation.e2e.test.mjs`](../../test/openai-local-conversation.e2e.test.mjs) runs
eight cases over a real `node:http` peer and raw `node:net` peers on `127.0.0.1`
(`node --test test/openai-local-conversation.e2e.test.mjs`, route:
[synthetic-e2e.md](../development/synthetic-e2e.md)): the accepted conversation, with a real detector run,
a real policy `MASK`, both real fixed-worker children, one connection and one parsed request compared
against an independently declared masked image, and one guarded release of a declared canonical image; an
unresolved inspection and an upstream sentinel block that reach no socket, the first followed by a real
positive exchange on the same peer and sink; a registered original in the reply that releases nothing while
the control on the
same owner releases; chunked, non-200, oversize-length, duplicate-length, truncated and header-flood
replies, each followed by a positive control on the same peer; a reply larger than the header bound
accepted identically whether the peer coalesced it with the head or split the terminator across two reads,
three mislabelled or malformed header cases refused, and a balanced quoted charset plus a surplus-tailed
first reply accepted with the surplus ignored; accepted `observe`/`onReply` methods proven to run on the
host receiver they were validated on; a silent peer that times out and a cancelled
in-flight exchange with a sticky `CANCELLED` owner; and unusable hosts, endpoints, deadlines and call
shapes that never dispatch. Unexercised by that suite: `CONVERSATION_FAILED`, the endpoint-mismatch branch
of `TRANSPORT_FAILED`, and an undecodable-UTF-8 body. Every fixture value is obviously synthetic and
non-routable; no provider, credential or network is used.