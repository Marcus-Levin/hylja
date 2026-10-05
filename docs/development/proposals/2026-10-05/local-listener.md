# Proposed bounded child: local-capability HTTP loopback listener
Status: proposed dispatch brief, not an authorized live issue.

## Gate, objective and dependencies

**Implementation gate:** explicit human acceptance of
[decision 013 (PROPOSED)](../../../decisions/013-local-listener-caller-gate.md)
is required before runtime wiring. This packet records no acceptance.
The single human choice is the narrow local-capability access model; production identity
and inspection authority are excluded. Header behavior, tooling and status codes below
are CTO technical recommendations, not additional CEO questions.

Recommend one next child of [#21](https://github.com/Marcus-Levin/hylja/issues/21):
a non-streamed OpenAI-shaped HTTP client against a synthetic loopback upstream, composed
through [#236](https://github.com/Marcus-Levin/hylja/issues/236) unchanged.
Read [capabilities](../../../capabilities.md) for implementation and limits,
[#36](https://github.com/Marcus-Levin/hylja/issues/36) for roadmap status and order,
the [draft slice](../../../specs/slice-3-openai-compatible-gateway.md), and the
[conversation](../../../contracts/openai-local-conversation.md),
[sender](../../../contracts/openai-text-sender.md) and
[receiver](../../../contracts/openai-keep-receiver.md) contracts.
Listener before [#17](https://github.com/Marcus-Levin/hylja/issues/17) is justified only
because irreversible KEEP/MASK resolves no mappings. Parent #21 dependencies are unchanged.

## Proposed scope and files

New implementation files after authorization:
- `src/openai-local-listener.ts`
- `test/openai-local-listener.e2e.test.mjs`
- `docs/contracts/openai-local-listener.md`

Minimal integration edits: `src/node-net.d.ts`, `src/node-crypto.d.ts` only for missing
native declarations; `package.json` only if a focused script is necessary;
`docs/capabilities.md`, `docs/development/synthetic-e2e.md`, `docs/README.md` for honest routing.
These are proposed scope, not permission granted by this packet. No dependency/lockfile change.
Prerequisites: net-server declarations and `timingSafeEqual` are absent.
`randomBytes` already exists in `src/node-mapping-crypto.d.ts`; this listener does not need
it because the host provisions the capability. Verify native API shapes and add only the
narrow missing declarations for server lifecycle and constant-time digest comparison.
Reuse conversation, sender, receiver, codecs, real policy and sentinel modules unchanged.
Reuse synthetic fixture patterns without importing a test that schedules tests.

## Construction and access

Propose `createOpenAiLocalListener(host)` with `start()`, `close()` and `state`;
these are new APIs to implement, not existing #236 APIs.
Closed own-data host: `listenPort` (0 or 1024–65535, distinct from upstream),
`callerToken`, and `conversation` (the #236 host minus `onReply`). Reject extra keys,
accessors, invalid ports and unusable nested hosts before binding. Bind only `127.0.0.1`.
Pin one context, profile, commit and upstream port; no headers/body/query/model text may
select authority, identity, classification, treatment or route.

One capability per listener, provisioned with cryptographic randomness of at least
256 bits. Token syntax does not establish entropy; distinct provisioning is required,
reuse is misconfiguration. Retain only its digest after construction; compare fixed-length
digests in constant time. Require exactly one `Authorization: Bearer` value with strict
syntax (43 base64url characters); absent/forged/duplicate auth denies. Never forward or echo auth.
No tokens in git, logs, command-line examples or diagnostic assertions; only synthetic
test tokens. No principal/tenant proof is derived from possession or loopback location.
The gate does not authenticate human/workload identity, tenant membership or host evidence.

## Bounded-lifetime evidence (option a)

Usable life is the intersection of ALL pinned sender/receiver identityProof, requestProof,
sourceProof and routeProof windows. These remain trusted synthetic fixture evidence, not
proof of an arbitrary actual caller. A fresh #236 owner is not fresh evidence; reused
requestProof is a synthetic harness premise, never per-request authentication.
Per [envelope contract](../../../contracts/interaction-envelope.md) and source,
MAX_AGE_MS = 5 min: at construction/exchange require issuedAt <= now, issuedAt >= now−5 min,
expiresAt > now and expiresAt−issuedAt <= 5 min, across both boundaries. Stale construction
latches a refusal-only listener (no exchanges); correct-token requests get fixed 403 RELEASE_REFUSED.
Listener-owned observation wrappers must refuse outside the whole pinned intersection;
existing owners still re-read their envelope snapshots immediately before dispatch/release:
issuedAt <= now < expiresAt, window <= 5 min and occurredAt within the last 5 min.
Pinning context keeps no proof valid. Never extend windows, override the clock or mint/
reissue proofs from possession or loopback. This is not a long-lived operational gateway.
Persistent operation requires a separately proposed/authorized per-request host evidence
API and independent identity/request/source/route evidence; absence blocks that future child.

## Proposed strict inbound profile and resource bounds

- Exactly `POST /v1/chat/completions HTTP/1.1`, origin-form, no query or trailing slash.
  Host exactly `127.0.0.1:<bound port>`; no absolute-form, redirect or alternate endpoint.
- Head at most 8192 bytes including terminator, at most 64 fields; token names, bounded
  visible ASCII/tab values, no folded lines, duplicate names or framing ambiguity.
- Exactly one positive canonical decimal `Content-Length`, body at most 65536 bytes
  and no larger than the strict request codec cap. JSON content type with only optional
  balanced UTF-8 charset; strict UTF-8 decode, no repair or truncation.
- Refuse Transfer-Encoding, Content-Encoding, Expect, Upgrade, Origin,
  Proxy-Authorization, Forwarded, X-Forwarded-*, OpenAI-Organization,
  OpenAI-Project and X-Hylja-* (case-insensitive). They must not claim route or authority.
  Validate/bound other well-formed headers, ignore and never forward them, including
  SDK-shaped headers. Unknown harmless headers need no CEO decision.
- One request per connection, no keepalive/pipeline processing; refuse surplus input
  before dispatch when observed, close rather than parse any later surplus as a request.
  Ambiguous/incomplete framing refuses before upstream.
- Maximum four admitted sockets and one active exchange, no queue; reject excess
  admission, including partially read connections. One absolute 5-second head/body
  read deadline, never reset by progress; bound copies and a 5-second response write.
  At most 65536 response body bytes plus fixed response head; no unbounded write queue.
  Fixed sentinel deadline 10 seconds per check and #236 transport timeout 10 seconds.
- Pass body unchanged as `exchange({ body })`; do not strip or default JSON fields.
  Sender codec remains field authority: tools, images, streaming, unknown top-level
  or nested fields refuse before upstream. Validate the HTTP profile before any owner work.

## Composition and lifecycle prerequisites

Create a fresh #236 owner per accepted request, claiming the exchange slot synchronously.
The listener privately supplies `onReply(reply): Promise<void>` bound to that client's
socket and cancellation state. No external sink callback or socket retargeting is allowed.
Only receiver-guarded canonical body bytes become a 200 response with fixed JSON content
label, computed UTF-8 Content-Length and Connection: close. Start the private native write
in the guarded release turn, without an intervening await. Frame no unchecked payload.
A partially executed socket write cannot be rolled back; do not report it as undone.

Source inspection: #236 captures `observe` and `onReply` and invokes each on the supplied
host receiver; it awaits `onReply`, so a stalled reply callback can stall the exchange.
`cancel()` reaches both composed owners and the live upstream socket; it is sticky.
Owned transport buffers are wiped and sockets destroyed at settlement/finally;
surplus upstream reply bytes are ignored and the socket closed, not drained.
Its transport deadline begins at readiness, not at inspection or response writing.
Timers cannot interrupt synchronous host callbacks; inspectors and callbacks must be finite.

**Prerequisite to a bounded shutdown claim:** #236 exposes only exchange/cancel/state,
no disposer, child handle or awaitable drain. Track exchange promises, cancel on disconnect
and close, bound the private reply writer, destroy all admitted sockets, and prove fixed
workers exit after settlement. Do not invent a conversation `dispose()` or `drain()`.
If the existing child runner cannot establish shutdown within these bounds, stop and
propose a separately authorized lifecycle prerequisite; do not edit #236 in this child.
Unbounded trusted inspection is not solved by a timer or Promise.race.
Wipe listener-owned buffers on every ending; no immutable-string, heap/RSS/swap erasure claim.

## Fixed public refusal table

Each row has an independently declared fixed OpenAI-shaped error body, with fixed message,
`type: hylja_refusal`, fixed code and `param: null`; no reflected fields or inner reasons.

| Condition | HTTP | Public code |
|---|---|---|
| Invalid auth (including duplicate auth) | 401 | ACCESS_DENIED |
| Inbound request HTTP/codec unsupported or malformed input | 400 | REQUEST_REFUSED |
| Head/body byte or field bound | 413 | REQUEST_TOO_LARGE |
| Read deadline | 408 | REQUEST_TIMEOUT |
| Inspection/policy/sentinel/context/evidence refusal; unsupported complete reply codec | 403 | RELEASE_REFUSED |
| Busy/admission cap | 429 | BUSY |
| Upstream/transport unavailable, truncated or invalid reply framing | 502 | UPSTREAM_UNAVAILABLE |
| Upstream transport deadline | 504 | UPSTREAM_TIMEOUT |

Closed/disconnected sockets receive no attempted error write. Startup invalidity fails
without binding. Unexpected internal failures withhold and close, never expose details.
Future contract must exhaustively map ALL #236, sender, receiver and both codec outcomes;
unsupported complete inbound replies are coarse 403, never fine reasons. Only real transport
availability uses 502/504; no policy/known-original oracle. No listener retries or idempotency:
a client auto-retry is a fresh fully re-guarded exchange and may send another allowed
upstream request. Never expose fine policy/sentinel reasons or planted strings.

## Proposed behavior-first acceptance evidence

Write failing behavior tests first and retain red output, then green evidence.
Capture actual upstream wire bytes and actual client wire bytes, not only callback values.
Use raw HTTP clients for malformed framing and a non-streamed HTTP client for the control;
fetch plus SDK-shaped headers is not proof of a real OpenAI SDK or coding agent.
For each negative group run a valid control on the same listener/peer where still live;
a closed listener requires a fresh positive listener. Assert fixed literals via booleans,
counts and fixed codes, never token/body/buffer equality diagnostics that could echo data.

- Accepted synthetic secret: real detector, real MASK policy, both fixed sentinel children,
  one independently declared masked upstream image and canonical client response image;
  no auth, caller headers or protected originals in upstream bytes.
- Absent/forged/malformed/duplicate and cross-listener token; context overrides; absolute
  URL, Host/path/query/method mismatch; redirect reply toward a decoy: zero decoy contact.
  Pre-dispatch refusals assert zero upstream connections AND zero payload bytes.
  A redirect reply necessarily follows an upstream request; it contacts no redirect target.
- Tools/images/stream and unknown body fields; head/body bounds, duplicate length/auth,
  chunked/compressed/Expect, invalid UTF-8, truncated request and slowloris: zero upstream.
- Suppressed fixture inspection leaving an original for the real outbound sentinel:
  zero upstream contact. Registered inbound original: upstream request occurred but zero
  protected client bytes; coarse fixed 403, no reason-specific oracle.
- Cancellation before dispatch and after request arrival; busy; close during inspection,
  child check, upstream read and response write: no later release, all sockets disposed,
  no stranded worker. Synthetic token comparisons/log capture reveal no token on failure.
- Synthetic already-expired evidence (no five-minute sleep), correct token and valid body:
  fixed 403 RELEASE_REFUSED, zero upstream connections/payload; valid control on a freshly
  provisioned listener. Exercise expiry of each proof in either boundary independently.
  Expiry between admission and dispatch/release is re-read: zero late payload/release bytes
  respectively (readiness may connect); do not undo bytes already sent before expiry.
- Unusable hosts and sink injection (`onReply`, releasePoint/sendPoint) never bind;
  one request cannot redirect another request's response socket.

No real provider API, credentials, model traffic, private or held-out data.

## Proposed verification and product success

After authorization, run from root: `npm ci --ignore-scripts --no-fund`,
`npm run check:fixtures`, `npm run check:docs`, `npm run check:diagnostic-assertions`,
`npm run build`, `npm run typecheck`,
`node --test test/openai-local-listener.e2e.test.mjs`,
`node --test test/openai-local-conversation.e2e.test.mjs`, and `git diff --check`.
Require independent exact-head review and full exact-head CI per the canonical workflow.
This prose packet itself needs only install, docs check and diff whitespace check.

Proposed success: one synthetic non-streamed OpenAI-shaped HTTP exchange within ALL pinned
evidence windows through the owned privacy mechanics, not persistent operational service.
It does not prove production authentication, host authenticity,
tenant membership, broker/restoration/persistence, multi-tenant isolation, bypass resistance,
real SDK/provider integration, contextual privacy or reasoning utility. Local process
compromise is out of scope. Fixture inspection labels are not generic classifiers;
zero findings never clear a unit. Generic default classification requires a separate
proposal and human gate. No policy widening or proposed 010 adoption. Broad agent utility
requires generic inspection, tools/streaming, provider integration and utility evidence later;
whole-message masking alone proves none of that.
