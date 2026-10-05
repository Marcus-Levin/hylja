# Bounded local-capability OpenAI listener (#261)

Status: foundation runtime contract under accepted [decision 013](../decisions/013-local-listener-caller-gate.md).
Scope is the admitted synthetic milestone, not production authentication or adoption of the
[draft gateway slice](../specs/slice-3-openai-compatible-gateway.md) or proposed decision 010.
Implementation and durable limits live in [capabilities](../capabilities.md).

## Surface and trusted host

[`src/openai-local-listener.ts`](../../src/openai-local-listener.ts) exports
`createOpenAiLocalListener(host: unknown)` returning only `start()`, `close()` and `state`.
`start()` resolves `{ status: 'LISTENING', port }` or `{ status: 'REFUSED', code }`;
construction and bind refusals are fixed `HOST_INVALID` and `START_FAILED`, with no native details.
Repeated starts share the same start result while live; after close they return `CLOSED`, never revive.
`close()` is idempotent, cancels the active owner, destroys every owned client socket, closes the
server, and awaits enrolled exchange promises. States are `IDLE`, `STARTING`, `LISTENING`,
`CLOSING`, `CLOSED`, `FAILED`. Structurally unusable hosts never bind.

The host has exactly three own enumerable data properties:

- `listenPort`: `0` (OS-assigned) or `1024..65535`, distinct from the captured upstream port;
- `callerToken`: exactly 43 base64url characters, provisioned by the host with at least 256 random bits;
- `conversation`: the [#236 host](openai-local-conversation.md) minus `onReply`, exactly
  `port`, `timeoutMs`, `observe`, `sender`, `receiver`.

The upstream remains #236's numeric loopback endpoint. Transport timeout and both sentinel deadlines
must be `10000` ms. Optional sentinel cleanup grace is `0..1000` ms (the runner's default otherwise).
No host-provided `onReply`, `sendPoint`, `releasePoint`, extra key, getter, symbol or missing member is
accepted. Nested boundary and policy data are bounded own-data snapshots; boundary structure and
canonical timestamps are validated without treating stale evidence as structural invalidity.
Sender and receiver must pin the same authenticated subject and request context; differing principals,
workloads, tenant/project/session or purpose never bind. Their separate proof intervals are still intersected.
Policy bundle validation and scope/registration copying reuse their existing authorities.
Callback references are captured once on their accepted data snapshots, containing the declared
conversation/inspection members, never a caller token or response socket. Caller-side mutation after
construction cannot retarget the pinned data or replace an accepted method. Callbacks themselves
remain trusted, finite code; this is not a JavaScript sandbox or authentication of host assertions.

Only a SHA-256 digest of the capability is retained in listener-owned storage. The existing hash API
returns hex, so the fixed 64 ASCII digest bytes are compared with native `timingSafeEqual`.
Syntax proves no entropy; distinct listeners require independently provisioned capabilities.
No capability is logged, forwarded, echoed, turned into a principal proof or reversible mapping.
Host-owned copies and immutable runtime strings are outside any erasure claim.

## Inbound HTTP profile and bounds

Literal `127.0.0.1` bind only. One request per connection; all responses say `Connection: close`.
Exactly `POST /v1/chat/completions HTTP/1.1` in origin-form, with numeric
`Host: 127.0.0.1:<bound port>`: no alternate endpoint, absolute URI, query or slash variant.
Exactly one `Authorization: Bearer <capability>` with case-sensitive bearer spelling.
Duplicate/missing/malformed/forged auth returns coarse 401. Head byte/field bounds take precedence
when the head cannot be admitted; among bounded parseable heads auth is checked before route/profile.

The head including CRLFCRLF is at most 8192 bytes, at most 64 fields, RFC-token field names,
visible ASCII/tab values, no folds and no duplicate names. Exactly one positive canonical decimal
`Content-Length` at most 65536 and JSON content type, optionally the single balanced UTF-8 charset
parameter. Body must be complete strict UTF-8. The body text is passed unchanged to the existing
strict request codec, then unchanged to `exchange({ body })`; no field stripping or defaults.
Preflight distinguishes request-codec refusals from the same code names on an upstream reply.

Refused headers: Transfer-Encoding, Content-Encoding (including identity), Expect, Upgrade, Origin,
Proxy-Authorization, Forwarded, OpenAI-Organization, OpenAI-Project and the X-Forwarded-, X-Hylja-,
X-Context-, X-Tenant-, X-Session-, X-Purpose-, X-Principal- families. Other well-formed harmless headers
are validated and ignored, never forwarded. No header, body or model text selects host authority.

Four admitted sockets at most, one active exchange, no queue. Excess sockets receive fixed BUSY
without a request buffer; their bounded refusal writers are also owned by close. Admission does not
claim aggregate OS/process memory or a defense against arbitrary connection floods.
The single absolute head/body read deadline is five seconds, never reset by progress; an owned
73728-byte buffer caps accumulation. Surplus observed before dispatch refuses, never starts a
pipeline; later surplus cancels the exchange. EOF before completeness refuses. EOF after a full
request, before response writing, is cancellation: send-half-closed clients are not supported.
Client closure cancels the owner and destroys its socket. Disconnected clients get no error write.

## Guarded response, lifetime and shutdown

Each admitted valid request gets a fresh [conversation owner](openai-local-conversation.md), using
[sender](openai-text-sender.md), [receiver](openai-keep-receiver.md), codecs, real policy and fixed
sentinel children unchanged. The listener adds no upstream transport or classification authority.
Its private `onReply` belongs to that request's socket alone. Only receiver-guarded canonical bytes
become a 200 response: a fixed JSON head with computed byte length and one native write, begun in
the existing release-guard turn without an intervening await. Body is capped at 65536 bytes, and
writer completion is bounded to five seconds. Framing buffers are wiped on completion, cancellation
or write failure; listener request buffers are wiped on every ending. No string, heap, RSS or swap
erasure of host, peer, inspector, runtime or child copies is claimed.

Usable life is the intersection of all eight pinned sender/receiver identity/request/source/route
proofs, with `issued <= now < expires`, issue no older than five minutes, and window no longer than
five minutes. Evidence is never refreshed by constructing a new owner or by capability possession.
A structurally valid stale host can bind only refusal mode. Admission, captured observation wrappers
(after the trusted observation returns), and the private final client write check re-read the entire
intersection. Failure latches private expiry; the public result is coarse 403 regardless of a nested
refusal or throw. No invented route evidence is used to represent expiry. Existing owner guards
remain unchanged. Even expiry during finite response framing can emit the fixed 403 before any 200
write. Earlier allowed upstream or client bytes cannot be rolled back.

An exchange is enrolled before synchronous host callbacks can reenter close. Close cancels and
awaits these promises; there is no invented #236 drain/dispose/child API. Tests inspect actual native
transport destruction/close and OS signal-0 worker liveness after settlement. A half-open fixture
peer owns its remote half and is cleaned up by the fixture, not claimed as listener-owned.
The unchanged runner's `CLEANUP_UNCONFIRMED` remains a restrictive quarantined outcome, not proof of
termination under an OS-level failure; this bounded synthetic lifecycle evidence makes no such claim.
Finite callbacks remain a host obligation: a timer cannot preempt synchronous code that never returns.
Persistent operation, real caller authentication and evidence provisioning require separate authority.

## Fixed public outcomes and exhaustive nested mapping

Every public error body is exactly
`{"error":{"message":"<CODE>","type":"hylja_refusal","param":null,"code":"<CODE>"}}`.
Message is the fixed code itself, never an inner reason, path, parser excerpt, planted original,
capability, digest or native exception. Status/reason phrases are fixed HTTP literals.

| Condition | HTTP / code |
|---|---|
| Missing/forged/malformed/duplicate capability | 401 ACCESS_DENIED |
| Unsupported/malformed HTTP or request codec | 400 REQUEST_REFUSED |
| Head/body/field/message/parse bound | 413 REQUEST_TOO_LARGE |
| Absolute read deadline | 408 REQUEST_TIMEOUT |
| Inspection/policy/sentinel/context/evidence refusal; unsupported complete upstream body | 403 RELEASE_REFUSED |
| Socket/admission/exchange busy | 429 BUSY |
| Upstream unavailable, truncated, invalid framing | 502 UPSTREAM_UNAVAILABLE |
| Upstream transport timeout | 504 UPSTREAM_TIMEOUT |

Preflight exhausts the request codec: BODY_TOO_LARGE, PARSE_BUDGET_EXCEEDED and TOO_MANY_MESSAGES
map 413; TRANSLATION_ERROR closes without details; every other request-codec code maps 400.
After successful preflight, the compile-time exhaustive `Record<LocalConversationRefusal, ...>` maps:

- TRANSPORT_FAILED, RESPONSE_REFUSED, RESPONSE_TRUNCATED, RESPONSE_TOO_LARGE and DISPATCH_FAILED to 502;
- RESPONSE_TIMEOUT to 504; CONVERSATION_BUSY, SENDER_BUSY and RECEIVER_BUSY to 429;
- CANCELLED, CONVERSATION_FAILED, SENDER_FAILED, RECEIVER_FAILED, RELEASE_FAILED and TRANSLATION_ERROR
  to withhold/close without an error body;
- every remaining declared nested code to 403: HOST_INVALID, ENDPOINT_REFUSED, INVALID_ARGUMENTS,
  INTERACTION_REFUSED, ROUTE_REFUSED, SCOPE_REFUSED, INSPECTION_REFUSED, POLICY_DENIED, POLICY_HELD,
  POLICY_NOT_KEEP, SENTINEL_BLOCKED, ROUTE_CHANGED, POLICY_STALE, IMAGE_REFUSED,
  ENDPOINT_NOT_SUPPORTED, BODY_NOT_TEXT, BODY_TOO_LARGE, MALFORMED_JSON, AMBIGUOUS_BODY,
  PARSE_BUDGET_EXCEEDED, BODY_NOT_OBJECT, UNEXPECTED_FIELD, MISSING_FIELD, INVALID_FIELD,
  UNSUPPORTED_TOOLS, UNSUPPORTED_CONTENT, UNSUPPORTED_ROLE, INVALID_MESSAGE,
  STREAMING_NOT_SUPPORTED, NO_MESSAGES, TOO_MANY_MESSAGES, UNSUPPORTED_OBJECT, NO_CHOICES,
  MULTIPLE_CHOICES, INVALID_CHOICE, UNSUPPORTED_FINISH_REASON and INVALID_USAGE.

Private expiry overrides all nested results to coarse 403 on a still-connected unwritten socket.
No original-specific oracle, retry or idempotency. A client's auto-retry is another freshly guarded
exchange and can dispatch allowed bytes again. An unexpected internal error withholds/closes.

## Evidence and exclusions

[`test/openai-local-listener.e2e.test.mjs`](../../test/openai-local-listener.e2e.test.mjs) exercises
real synthetic upstream/client wire, actual bound ALLOW/BLOCK worker frames, MASK selected by real
policy over real detector evidence, strict malformed raw clients, a native non-streamed HTTP client,
refusal groups with positive controls, all eight stale proof windows, real-clock admission/dispatch/
release/framing expiry, cancellation, contention, shutdown stages and actual worker/process liveness.
The diagnostic subprocess is
[`test/support/openai-local-listener-diagnostic-probe.mjs`](../../test/support/openai-local-listener-diagnostic-probe.mjs).
All captured values become boolean/count assertions; fixed diagnostics never echo protected material.
The unchanged #236 suite remains separate evidence. Run routes are in
[synthetic-e2e.md](../development/synthetic-e2e.md).

Host fixture labels are declared assumptions, never detector-absence clearance or a generic classifier.
No provider/model API, real SDK, held-out data, utility result, production authentication,
multi-tenant service, streaming/tools/images, restoration/vault/broker/persistence,
bypass-resistant managed egress or production release is proved or authorized.
