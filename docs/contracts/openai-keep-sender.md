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
duplicated here.

`observe()` returns `{ destination: { id, profileDigest }, commit: { id, version, digest } }`. It is
called once before the check and once more in the same synchronous turn as the dispatch. **Redirects are
prohibited**: a destination that differs from the one the check was made against is `ROUTE_CHANGED`, never
a followed location, and a changed commit is `POLICY_STALE`.

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
A destination label is structurally validated (non-empty, bounded, no control character or space) before
it can be interpolated into a header, so a hostile observed label cannot inject a header.

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
   taken from the authenticated boundary rather than from the observation.
7. Re-check cancellation, route, profile and policy commit, and dispatch — all in one synchronous turn,
   with no `await` between the last check and `sendExact`.

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
| `CANCELLED` | `cancel()` was observed, or this sender was already cancelled |
| `INTERACTION_REFUSED` | the trusted boundary could not be bound to this interaction |
| `ROUTE_REFUSED` | the observed destination, profile digest or commit is not usable |
| `SCOPE_REFUSED` | the sentinel scope does not belong to the authenticated tenant/project |
| `INSPECTION_REFUSED` | empty, partial, foreign, unresolved, substituted or unbound inspection evidence |
| `POLICY_DENIED` | the real policy seam denied: unknown or stale policy, foreign context, profile or rule mismatch |
| `POLICY_HELD` | the real policy seam held the decision for review |
| `POLICY_NOT_KEEP` | a real selected treatment that is not `KEEP` |
| `SENTINEL_BLOCKED` | the child did not `ALLOW` these bytes, or the check could not run at all |
| `ROUTE_CHANGED` | the route or profile changed between the check and the dispatch |
| `POLICY_STALE` | the committed policy identity changed between the decision and the dispatch |
| `DISPATCH_FAILED` | the trusted transport failed or did not confirm |
| `SENDER_FAILED` | fail-closed catch-all for an unexpected internal failure |

## Limits, stated honestly

- **The transport is trusted.** Redirects, retries, DNS rebinding, proxying and a host that ignores the
  bytes it is given are outside what this module can observe or prevent.
- **The host is trusted.** An authenticated boundary that is not actually authenticated, a profile digest
  that is not derived from the committed profile, and an inspection callback that classifies nothing real
  all pass straight through this seam. Deriving the profile digest from the committed profile record and
  producing genuine detector evidence are integration-host obligations.
- **Finite trusted callback and transport behavior is assumed, not enforced.** There is no hard timeout
  on `inspect` or on `sendExact`; a callback that never returns leaves this send pending. The sentinel's
  own absolute deadline covers the child, and nothing else.
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
image), whole-image coverage, every refusal code, cancellation and contention, and the "later caller or
inspection-copy mutation changes no released byte" property. It calls no provider, holds no credential,
reaches the network only on `127.0.0.1` on an OS-assigned ephemeral port, and every fixture value is
obviously synthetic and non-routable.