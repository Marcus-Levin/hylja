# KEEP-only complete-text OpenAI request sender contract (#201)

Status: draft foundation contract for issue #201, child of [#21](https://github.com/Marcus-Levin/hylja/issues/21)
and [#19](https://github.com/Marcus-Levin/hylja/issues/19). It documents observable behavior of
[`src/openai-keep-sender.ts`](../../src/openai-keep-sender.ts). It is **not** a gateway, a listener, a
provider client, an authentication implementation, a credential or vault path, a transformation engine,
a response release or a global protection claim. Implementation status lives only in
[capabilities.md](../capabilities.md).

## Why this exists

The seams below it all refuse to send. The strict codec parses and never releases; the policy seam
selects a treatment and never sends; the sentinel child checks exact bytes and never sends. The only
existing end-to-end composition is a **test-local** send point
([openai-process-sendpoint-e2e.md](openai-process-sendpoint-e2e.md)) whose trusted boundary, policy pin
and classification fixture are wired independently of the body it checks, which makes it evidence for a
lifecycle, not request authorization.

This module is the smallest actual runtime effect owner: one call translates, builds the exact private
serialized request image, binds classification evidence to that image, takes a real deterministic `SEND`
policy decision, runs the real fixed-worker sentinel child over the exact bytes, and performs exactly one
trusted transport dispatch — or refuses with a fixed code and sends nothing.

## What it is not

- It **authenticates nobody**. `boundary`, `sourceTrust`, `policyBundle`, `scope`, `known`, the policy
  commit and the transport arrive from a trusted host and are trusted because that host authenticates
  them, exactly as the [policy contract](policy-contract.md) and the
  [sentinel process contract](egress-sentinel-process.md) already state. Nothing here re-verifies a
  principal, a tenant, a proof signature or a control plane.
- It **cannot prove that an arbitrary injected transport honors its contract**. The trusted exact-byte
  transport is an integration-host obligation; a host that sends something other than the bytes it is
  handed, follows a redirect, retries or resolves DNS elsewhere breaks this module's guarantee without
  this module being able to detect it.
- It is **not a sandbox**. No memory, RSS, CPU or process bound is claimed; the sentinel child remains an
  ordinary local process per its own contract.
- It implements **no treatment**. Only `KEEP` releases. `MASK`, `REMOVE`, every other treatment and
  `REQUIRE_REVIEW` all withhold, because transformation semantics
  ([#68](https://github.com/Marcus-Levin/hylja/issues/68)) and the information model
  ([#66](https://github.com/Marcus-Levin/hylja/issues/66)) are unadopted, and a held state is not a
  transformation ([decision 007](../decisions/007-fail-closed-for-protected-egress.md)).
- It is **not response release**. Nothing here inspects, withholds or releases a provider reply, and it
  makes no claim about hosted or provider-side tools.

## Interface

```ts
createOpenAiKeepSender(host: unknown): {
  send(input: unknown): Promise<{ status: 'SENT' } | { status: 'REFUSED'; code: KeepSendRefusal }>;
  cancel(): void;
  readonly state: 'IDLE' | 'BUSY' | 'CANCELLED' | 'FAILED';
}
```

Three members, nothing else. There is **no public `READY`/prepared-byte handle, no `prepare`, and no
replayable `sendPrepared`**: a `SENT` result carries no bytes, no digest and no handle, so nothing a
caller holds can be mutated after a check, re-sent, or sent twice. Cancellation is sender-owned and
sticky; there is no caller `AbortSignal`, callback or hook.

`send(input)` takes exactly what the strict codec takes: one object with `endpoint` and `body`. A caller
therefore supplies **endpoint and body only**. Authority, classification, destination, profile, keys,
policy and treatment cannot travel in a payload field — the codec refuses any extra own key, and
provider and model remain non-authority protocol metadata
([openai-text-request.md](openai-text-request.md), [decision 006](../decisions/006-adapter-first-multi-surface-core.md)).

One send is in flight at a time. The admission claim is taken synchronously before any stage runs, so a
second concurrent call is refused with `SENDER_BUSY` rather than queued, pooled or replayed.

### The trusted host

`createOpenAiKeepSender` accepts an object with exactly these eight own **data** properties. Anything
else — an unknown key, an accessor, a symbol key, a missing member, a non-function `inspect` or
`sendExact`, a `sourceTrust` that is not a trust level — yields a permanently restrictive sender whose
state is `FAILED` and whose every `send` is `HOST_INVALID`. Construction never throws and never sends.
`known` is the one member whose absence is not a neutral default: only a registration object or an
explicit `null` is accepted, so a missing or `undefined` `known` is `HOST_INVALID` like any other missing
member, never a silent empty registration.

| Member | Meaning |
| --- | --- |
| `boundary` | the independently authenticated subject/context and the observed source/destination with proofs, for [`createInteractionEnvelope`](../../src/interaction-envelope.ts) |
| `sourceTrust` | source trust observed for this interaction, never a payload or model claim |
| `policyBundle` | the committed policy snapshot |
| `scope` | tenant/project the sentinel checks under; must equal the authenticated context |
| `known` | the explicit known-originals registration, or an explicit `null` |
| `sentinel` | host-owned runner configuration for the module's fixed compiled worker |
| `inspect(image, binding)` | the whole-image, snapshot-bound classification handoff |
| `sendPoint` | `{ observe(), sendExact(image) }`: independently observed route/profile and the exact-byte transport |

Structural validity is the only thing this module checks about its host. Everything else is re-checked by
the authority that owns it: the envelope validates the boundary, `decidePolicy` validates the bundle, the
pinned digests and the classification, and the sentinel runner validates its own request. No engine is
duplicated here. The whole structural refusal is contained: a hostile object that throws from its own
traps, a revoked Proxy included, yields the permanently restrictive sender rather than an exception out
of `createOpenAiKeepSender`, and no exception text ever reaches a result.

`observe()` returns `{ destination: { id, profileDigest }, commit: { id, version, digest } }`. It is
called once before the check and once more in the same synchronous turn as the dispatch. **Redirects are
prohibited**: a destination that differs from the one the check was made against is `ROUTE_CHANGED`, never
a followed location, and a changed commit is `POLICY_STALE`. `observe()` is trusted host code and may call
`cancel()`; sticky cancellation is therefore re-read **after** that last callback, so nothing it does can
be outrun by a dispatch.

### The accepted methods are captured, not looked up again

`inspect`, `observe` and `sendExact` are read exactly once, during structural validation, and each is
then invoked as that captured function reference **on the receiver it was validated on**:

- the send point keeps its own object as the receiver of both its methods, so a host method that reads
  its own state — the current route, the current commit — still sees it, and `observe()` is still called
  fresh for every send and again at the dispatch point;
- `inspect` keeps the validated data-property snapshot it was accepted on;
- the invocation itself is a direct call through the trusted `Reflect.apply`, which reads no property of
  the host object and never looks up `.call`, `.bind` or `.apply` on it.

The consequence is structural, not a further conditional guard: **no property of the trusted host is read
after the last guard**. Looking `sendExact` back up on the send point at dispatch would be host code
running inside the protected window — one Proxy `get` trap away from a cancellation, a swap or any other
side effect reaching a dispatch that has already passed every check. It is never looked up, so a send
point that is a supported Proxy is invoked exactly as a plain object would be.

The corollary is deliberate: **a host that replaces `sendPoint.observe` or `sendPoint.sendExact` after
construction does not retarget a sender that already exists.** This sender stays bound to the members it
accepted; a host that needs a different transport constructs a new sender. A host that wants to cancel a
send calls `cancel()`, which is sender-owned and sticky and is read again after the last callback.

Invoking the captured transport is still host code. Its honesty, and anything its own receiver does, stay
integration-host obligations.

## The captured scope and registration the child is asked to check under

`scope` and `known` are host-owned objects this module neither owns nor can freeze: a host may rewrite
either of them between the moment it handed them over and the moment a child is spawned. The request the
child is asked to check is therefore captured into **private copies before `inspect` is called**, through
the existing sentinel snapshot seam
([egress-sentinel-process.md](egress-sentinel-process.md)) — `snapshotSentinelRequest` — which already
owns that validation and copying. Nothing here re-implements it, and no second context validator or
wrapper exists.

What the capture owns, for this one send:

- the exact image bytes, as a private copy that is then handed to the runner;
- the **check scope**, validated and frozen from own data descriptors;
- the registration: **its own scope**, its **key bytes** (a private copy, never the host's array) and its
  **entry list**, each capped by that seam's own bounds;
- the observed destination and the authorized destination, exactly as they were bound above.

Those captured fields — not `trusted.scope` and not `trusted.known` — are what the runner is asked to
check, so a host that rewrites its own scope, registration scope, key array or entry list while the finite
inspection runs cannot retarget the real child. The scope the child runs under is compared to the **bound
envelope's** context, never to an earlier alias of the host object. An unknown own key, an oversized
registration, a registration scope that is not the check scope, an unsupported value or a hostile trap is
`SENTINEL_BLOCKED` here, before any child exists and before any host callback below has run: the same
fixed refusal the runner's own check returns for the same input.

When the snapshot is refused, the scope is re-read through own data descriptors and the fallback can only
restrict: the read never invokes an accessor, but a Proxy `getOwnPropertyDescriptor` trap can still run, and
a trap that throws is caught and yields no value. The refusal is `SCOPE_REFUSED` when that read cannot supply
a `tenantRef` equal to the bound envelope's `tenantId`, or a `projectRef` equal to its `projectId` where the
envelope defines one; otherwise it stays `SENTINEL_BLOCKED`. Neither outcome reaches a child, so the branch
cannot turn a refusal into a check or a dispatch.

The per-operation binding token is this send's **own generated interaction identity**, never a fixed global
id, and the runner still mints the real per-child request id when it spawns. Nothing about the child's own
request identity is invented or faked here, and the authorized destination is still the route the
authenticated boundary carried.

This is **not** a rule that revokes on host-side mutation. A host that rewrites its own members to the same
values is checked under exactly the captured ones and dispatches normally; what cannot happen is a child
being asked about a scope or registration this send never bound. The provisional byte and key copies are
**zeroed in a `finally` when the send ends** — including on an inspection, policy or sentinel refusal —
and are never reachable from a result, a binding, a finding or the sent bytes.

Scope of the claim, stated narrowly. This is a **local snapshot-ownership property of this one module over
two of its own host members**. It says nothing about any other egress path, about a host that builds a
*different* registration before the next send, about the sentinel's own detection quality, about
inspection correctness or finiteness, or about transport honesty — those stay host obligations. One
measured nuance: rewriting the host's key array alone is not a bypass, because the child fingerprints the
registration entries and the payload under the same key of one request frame; the scope and entry aliases
are what matter. This is **not** a production result and **not** a held-out result.

## The exact private image

The image is fixed and allowlisted, and the caller contributes no header at all:

```text
POST /v1/chat/completions HTTP/1.1
Host: <observed destination id>
Content-Type: application/json; charset=utf-8
Content-Length: <UTF-8 byte length of the body>

{"model":"<model>","messages":[{"role":"<role>","content":"<content>"}, ...]}
```

Message order, Unicode (including astral and combining characters) and every literal in the decoded
text are preserved exactly: there is no treatment anywhere in this path, so the checked image is the sent
image. `stream: false` is accepted by the codec and still yields this one complete, non-streamed image.
A destination label is structurally validated (non-empty, bounded, no control character and no ordinary
space) before it can be interpolated into a header, so a hostile observed label cannot inject a header.
An ordinary space is refused here for the same reason a control character is: it would already make the
emitted header value ambiguous, and an unusable observed label is `ROUTE_REFUSED` before any image is
built.

The image is snapshotted before any `await` and never leaves this module: the sentinel's own private
`ALLOW` copy is the only representation the transport receives, handed over exactly once.

## The snapshot-bound inspection handoff

`inspect` receives a **separate copy** of the image plus a binding:

```ts
{ version: 1, interactionRef, imageDigest, units: readonly {
    unitRef: string; kind: 'METADATA' | 'MODEL' | 'MESSAGE'; digest: string }[] }
```

`units` covers the whole image in wire order: the header block (`METADATA`), the model as its exact
image bytes (`MODEL`), then one unit per message content (`MESSAGE`). `imageDigest` is the SHA-256 of the
sender's own private snapshot, and `interactionRef` is the id of the interaction envelope this sender
just created for this exact request.

The inspector answers with:

```ts
{ version: 1, interactionRef, imageDigest, coverage: 'COMPLETE', remainder: 'NONE',
  units: readonly { unitRef, classificationDigest, classification }[] }
```

A finding is usable only when **all** of the following hold, and each is re-derived here rather than
believed:

- the result is structurally exact, `coverage` is `COMPLETE`, `remainder` is `NONE`, and it echoes this
  sender's own `interactionRef` and `imageDigest` exactly;
- there is **exactly one** finding per declared unit: no missing unit, no duplicate, no invented unit;
- the finding's `classification` is `RESOLVED` and carries at least one `FOUND` **detector** record;
- `digestClassification(classification)` — recomputed over the record this sender will actually decide
  over — equals the `classificationDigest` the inspector pinned.

Anything else is `INSPECTION_REFUSED`, including a thrown callback, a returned `undefined`, an unknown own
key, an empty finding list, a substituted record and an unresolved remainder. **`coverage: 'COMPLETE'`
alone never authorizes**: it is a completeness statement, and completeness was never a safety claim
anywhere in this repository. Detector absence is never clearance — a model-only `PUBLIC` judgment with no
detector evidence stays unresolved and refuses
([classification contract](classification-contract.md), [decision 003](../decisions/003-semantic-judgment-does-not-own-effects.md)).
A caller-supplied or substituted digest never authorizes; the digest is recomputed, and the sender
fabricates no evidence of its own.

## The accepted path

1. Translate with the strict codec; any codec refusal passes through unchanged.
2. Observe the route and policy commit; validate the destination label.
3. Build the exact image and bind it to a fresh interaction envelope from the trusted boundary.
4. Take the snapshot-bound inspection evidence over the whole image.
5. `decidePolicy` for **every** unit with a distinct candidate reference, and require `SELECTED` with
   treatment `KEEP` for all of them.
6. One check in the real fixed-worker child process over the exact bytes, with the authorized destination
   taken from the authenticated boundary rather than from the observation, under the scope and registration
   captured privately before the inspection.
7. Re-observe the route, profile and policy commit, re-read the boundary evidence's freshness, then
   re-read sticky cancellation, and dispatch — all in one synchronous turn, with no callback and no
   `await` between the last check and `sendExact`.

**Step 7 is ordered, and the order is the guarantee.** The final `observe()` is host code, so it runs
first and every structural and freshness check it can invalidate follows it; cancellation is read again
last, immediately before the transport call. It is the **last host code that runs at all**, because the
transport method itself was captured during validation rather than read off the host here: the dispatch
call invokes that captured function on the receiver it was accepted on, so no host property lookup, Proxy
trap or method swap can reach a dispatch that has already passed every check. The freshness re-read is the
[envelope contract's own rule](interaction-envelope.md): the clock at the dispatch point must still fall
inside every snapshotted proof's issue/expiry interval, within the five-minute interaction age. An
unchanged proof digest is **not** a current proof — a window that closed while the trusted callback and
the child process were running authorizes nothing, and the identity, context and observed route it
authorized cannot be bound to this dispatch. The envelope is not recreated, because a new interaction
identity would invalidate the image digest, every unit reference and every pinned classification and
policy decision already taken over it.

Nothing is retried. A failed dispatch is reported, not rolled back: a transport that partially executed
its effect cannot be undone by this module, and the `SENT`/`REFUSED` result says only what the sender
itself observed.

## Refusals

Every refusal is one fixed code, or one of the strict codec's own fixed codes. No code carries a field
name, byte offset, exception message, transport error, sentinel reason or any part of the input.

| Code | Meaning |
| --- | --- |
| `HOST_INVALID` | the trusted host is not the exact declared shape; this sender can never dispatch |
| `SENDER_BUSY` | one send is already in flight; there is no queue, pool or replay |
| `CANCELLED` | `cancel()` was observed, including inside the final host observation, or this sender was already cancelled |
| `INTERACTION_REFUSED` | the trusted boundary could not be bound to this interaction, or the evidence it was bound under is no longer current at the dispatch point |
| `ROUTE_REFUSED` | the observed destination, profile digest or commit is not usable |
| `SCOPE_REFUSED` | the sentinel scope the child would run under does not belong to the authenticated tenant/project, or could not be established from own data descriptors after a refused snapshot |
| `INSPECTION_REFUSED` | empty, partial, foreign, unresolved, substituted or unbound inspection evidence |
| `POLICY_DENIED` | the real policy seam denied: unknown or stale policy, foreign context, profile or rule mismatch |
| `POLICY_HELD` | the real policy seam held the decision for review |
| `POLICY_NOT_KEEP` | a real selected treatment that is not `KEEP` |
| `SENTINEL_BLOCKED` | the child did not `ALLOW` these bytes, the request could not be snapshotted at all, or the check could not run |
| `ROUTE_CHANGED` | the route or profile changed between the check and the dispatch |
| `POLICY_STALE` | the committed policy identity changed between the decision and the dispatch |
| `DISPATCH_FAILED` | the trusted transport failed or did not confirm |
| `SENDER_FAILED` | fail-closed catch-all for an unexpected internal failure. No boundary the accepted host surface can supply reaches one, so this code is fixed and fail-closed but unexercised |

## Limits, stated honestly

- **The transport is trusted.** Redirects, retries, DNS rebinding, proxying and a host that ignores the
  bytes it is given are outside what this module can observe or prevent.
- **The host is trusted.** An authenticated boundary that is not actually authenticated, a profile digest
  that is not derived from the committed profile, and an inspection callback that classifies nothing real
  all pass straight through this seam. Deriving the profile digest from the committed profile record and
  producing genuine detector evidence are integration-host obligations. The dispatch-point freshness
  re-read is a congruence check, exactly like the envelope's: it re-reads intervals the host supplied and
  authenticates no proof.
- **Finite trusted callback and transport behavior is assumed, not enforced.** There is no hard timeout
  on `inspect` or on `sendExact`; a callback that never returns leaves this send pending. The sentinel's
  own absolute deadline covers the child, and nothing else. What that finiteness does buy is the
  dispatch-point re-read: a send that outlives the boundary evidence it was assembled under is refused
  with `INTERACTION_REFUSED` instead of dispatching on expired proof.
- **One unit per message, whole image per send.** There is no streaming holdback, no interleaved tool
  argument handling, no chunk abort handling and no backpressure; streaming input is refused by the codec
  ([slice 3 spec](../specs/slice-3-openai-compatible-gateway.md)).
- **No bypass resistance is claimed.** A caller that reaches the same network path without going through
  this sender is not covered by anything here.
- **Not an evaluation result.** The evidence below is unscored, synthetic and non-enforcing; it is not a
  held-out result, a comparative win or promotion evidence ([evaluation.md](../evaluation.md)).

## Deliberately absent

No HTTP listener, no gateway route, no provider SDK, no credential, API key, vault or broker, no response
inspection or release, no streaming, no tools, no multimodal or binary content, no transformation or
original restoration, no audit ledger call, no scoring, no held-out protocol, and no claim of global
protection. A production authenticated send path remains host adapter work.

Evidence: [`test/openai-keep-sender.test.mjs`](../../test/openai-keep-sender.test.mjs), an executable
matrix over the accepted path (a real sentinel child and a real loopback capture of exactly the declared
image), whole-image coverage, every refusal code except the `SENDER_FAILED` catch-all, cancellation and
contention, a destination label carrying an ordinary space and boundary evidence that cannot be bound at
all, a cancellation raised inside the final host observation and boundary evidence that expires under
real elapsed time inside the trusted inspection, an accepted send point that is a Proxy whose `get` trap
cancels the sender if the transport method is read back off it, the receiver a captured transport keeps
and the later method swap that cannot retarget it, a host that rewrites its own scope, registration scope, key
array and entry list mid-inspection while the planted original still withholds under the privately captured
tenant A (with a benign rewrite to the same values still dispatching, so no automatic revocation rule is
invented), an unknown registration key staying one fixed restrictive refusal, a revoked-Proxy host, and the
"later caller or inspection-copy mutation changes no released byte" property. It calls no provider, holds no
credential, reaches the network only on `127.0.0.1` on an OS-assigned ephemeral port, and every fixture value
is obviously synthetic and non-routable.