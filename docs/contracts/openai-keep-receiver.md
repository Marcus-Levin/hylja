# KEEP-only complete-response OpenAI inbound receiver contract (#212)

Status: draft foundation contract for issue #212, child of [#21](https://github.com/Marcus-Levin/hylja/issues/21).
It documents observable behavior of [`src/openai-keep-receiver.ts`](../../src/openai-keep-receiver.ts). It
is **not** a gateway, a listener, a transport, a provider client, an authentication implementation, a
credential or vault path, a transformation engine, a streaming design or a hosted-tool interceptor.
Implementation status lives only in [capabilities.md](../capabilities.md).

## Why this exists

The seams below it all refuse to release: the strict codec parses and never releases, the policy seam
selects a treatment and never releases, and the sentinel child checks exact bytes and never releases. The
only shipped inbound end-to-end evidence before this was **test-local**
([openai-response-inspection-e2e.md](openai-response-inspection-e2e.md)), which runs a real chain and records
a capture, but whose trusted boundary, benign fixture claim and sentinel key are wired inside a test file and
which owns no runtime effect at all. The sibling outbound unit
([openai-keep-sender.md](openai-keep-sender.md)) is the smallest actual runtime effect owner for a request;
this is the same discipline on the inbound path.

This module is the smallest inbound runtime effect owner: one call translates, builds the exact private
canonical body image of the accepted response, binds classification evidence to that image, takes a real
deterministic `SEND` policy decision for **every** declared unit, runs the real fixed-worker sentinel child
over the exact bytes, and performs exactly one trusted release — or refuses with a fixed code and releases
nothing.

## What it is not

- It **authenticates nobody**. `boundary`, `policyBundle`, `scope`, `known`, the policy commit and the release
  point arrive from a trusted host and are trusted because that host authenticates them, exactly as the
  [policy contract](policy-contract.md) and the [sentinel process contract](egress-sentinel-process.md) already
  state. Nothing here re-verifies a principal, a tenant, a proof signature or a control plane.
- **Provider source trust is always `UNTRUSTED`** and is not a host or caller input. The envelope's own source
  record carries no trust member, and the policy boundary here pins `UNTRUSTED`. Protected model output is
  untrusted text at its own source; a token-shaped string, an instruction or a claim inside it grants no
  authority, selects no route and triggers no restoration
  ([decision 003](../decisions/003-semantic-judgment-does-not-own-effects.md),
  [007](../decisions/007-fail-closed-for-protected-egress.md)).
- It **cannot prove that an arbitrary injected release point honors its contract**. Handing over the exact bytes
  is an integration-host obligation; a host that releases something else, retries, or follows a redirect breaks
  this module's guarantee without this module being able to detect it.
- It implements **no treatment**. Only `KEEP` releases. `MASK`, `REMOVE`, every other treatment and
  `REQUIRE_REVIEW` all withhold, because transformation semantics
  ([#68](https://github.com/Marcus-Levin/hylja/issues/68)) and the information model
  ([#66](https://github.com/Marcus-Levin/hylja/issues/66)) are unadopted, and a held state is not a
  transformation. Proposed [decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md)
  is **not** exercised, adopted or wired here.
- It handles **no streaming, no tools and no multimodal content**: the strict codec refuses those by name
  ([openai-text-response.md](openai-text-response.md)).

## Interface

```ts
createOpenAiKeepReceiver(host: unknown): {
  receive(input: unknown): Promise<{ status: 'RELEASED' } | { status: 'REFUSED'; code: KeepReceiveRefusal }>;
  cancel(): void;
  readonly state: 'IDLE' | 'BUSY' | 'CANCELLED' | 'FAILED';
}
```

Three members, nothing else. There is **no public `READY`/prepared-byte handle, no `prepare`, and no replayable
`releasePrepared`**: a `RELEASED` result carries no bytes, no digest and no handle. Cancellation is
receiver-owned and sticky; there is no caller `AbortSignal`, callback or hook.

`receive(input)` takes exactly what the strict codec takes: one object with `endpoint` and `body`. A caller
therefore supplies **endpoint and body only**. Authority, classification, destination, profile, keys, policy
and treatment cannot travel in a payload field — the codec refuses any extra own key, and provider, model,
`id`, `created`, `usage` and `finish_reason` remain non-authority protocol metadata
([openai-text-response.md](openai-text-response.md),
[decision 006](../decisions/006-adapter-first-multi-surface-core.md)).

One receive is in flight at a time. The admission claim is taken synchronously before any stage runs, so a
second concurrent call is refused with `RECEIVER_BUSY` rather than queued, pooled or replayed.

### The trusted host

`createOpenAiKeepReceiver` accepts an object with exactly these seven own **data** properties. Anything else —
an unknown key (a `sourceTrust`, a `destination` or a `transport` among them), an accessor, a symbol key, a
missing member, a non-function `inspect`, `observe` or `releaseExact` — yields a permanently restrictive
receiver whose state is `FAILED` and whose every `receive` is `HOST_INVALID`. Construction never throws and
never releases.

| Member | Meaning |
| --- | --- |
| `boundary` | the independently authenticated subject/context and the observed source/destination with proofs, for [`createInteractionEnvelope`](../../src/interaction-envelope.ts) |
| `policyBundle` | the committed policy snapshot |
| `scope` | tenant/project the sentinel checks under; must equal the authenticated context |
| `known` | the explicit known-originals registration, or an explicit `null` |
| `sentinel` | host-owned runner configuration for the module's fixed compiled worker |
| `inspect(image, binding)` | the whole-image, snapshot-bound classification handoff |
| `releasePoint` | `{ observe(), releaseExact(image) }`: independently observed route/profile and the exact-byte release |

Structural validity is the only thing this module checks about its host. Everything else is re-checked by the
authority that owns it: the envelope validates the boundary, `decidePolicy` validates the bundle, the pinned
digests and the classification, and the sentinel runner validates its own request. No policy engine, envelope
rule or sentinel rule is duplicated here. The whole structural refusal is contained: a hostile object that
throws from its own traps, a revoked Proxy included, yields the permanently restrictive receiver rather than an
exception out of `createOpenAiKeepReceiver`. `known` is the one member whose absence is not a neutral
default: only a registration object or an explicit `null` is accepted, so a missing or `undefined`
`known` is `HOST_INVALID` like any other missing member, never a silent empty registration.

`observe()` returns `{ destination: { id, profileDigest }, commit: { id, version, digest } }`, is called once
before the check and once more in the same synchronous turn as the release, and is validated structurally
(bounded, non-empty, no control character, lowercase hex profile digest). This unit builds no header, so an
ordinary space is legal in the label here; **redirects are prohibited**: a destination that differs from the one
the check was made against is `ROUTE_CHANGED`, never a followed location, and a changed commit is
`POLICY_STALE`.

### The accepted methods are captured, not looked up again

`inspect`, `observe` and `releaseExact` are read exactly once, during structural validation, and each is then
invoked as that captured function reference **on the receiver it was validated on**: the release point keeps
its own object as the receiver of both its methods, `inspect` keeps the validated data-property snapshot it was
accepted on, and each invocation is a direct call through the trusted `Reflect.apply`, which reads no property
of the host object. The consequence is structural, not a further conditional guard: **no property of the trusted
host is read after the last guard**. The corollary is deliberate: **a host that replaces `releasePoint.observe`
or `releasePoint.releaseExact` after construction does not retarget a receiver that already exists.** Invoking
the captured release point is still host code; its honesty stays an integration-host obligation.

## The captured scope and registration the child is asked to check under

`scope` and `known` are host-owned objects this module neither owns nor can freeze: a host may rewrite
either of them between the moment it handed them over and the moment a child is spawned. The request the
child is asked to check is therefore captured into **private copies before `inspect` is called**, through
the existing sentinel snapshot seam
([egress-sentinel-process.md](egress-sentinel-process.md)) — `snapshotSentinelRequest` — which already
owns that validation and copying. Nothing here re-implements it, and no second context validator or
wrapper exists.

What the capture owns, for this one receive:

- the exact image bytes, as a private copy that is then handed to the runner;
- the **check scope**, validated and frozen from own data descriptors;
- the registration: **its own scope**, its **key bytes** (a private copy, never the host's array) and its
  **entry list**, each capped by that seam's own bounds;
- the observed destination and the authorized destination, exactly as they were bound above.

Those captured fields — not `trusted.scope` and not `trusted.known` — are what the runner is asked to
check, so a host that rewrites its own scope, registration scope, key array or entry list while the
finite inspection runs cannot retarget the real child. The scope the child runs under is compared to the
**bound envelope's** context, never to an earlier alias of the host object. An unknown own key, an
oversized registration, a registration scope that is not the check scope, an unsupported value or a
hostile trap is `SENTINEL_BLOCKED` here, before any child exists and before any host callback below has
run: the same fixed refusal the runner's own check returns for the same input.

When the snapshot is refused, the scope is re-read through own data descriptors and the fallback can only
restrict: the read never invokes an accessor, but a Proxy `getOwnPropertyDescriptor` trap can still run, and
a trap that throws is caught and yields no value. The refusal is `SCOPE_REFUSED` when that read cannot supply
a `tenantRef` equal to the bound envelope's `tenantId`, or a `projectRef` equal to its `projectId` where the
envelope defines one; otherwise it stays `SENTINEL_BLOCKED`. Neither outcome reaches a child, so the branch
cannot turn a refusal into a check or a release.

The per-operation binding token is this receive's **own generated interaction identity**, never a fixed
global id, and the runner still mints the real per-child request id when it spawns. Nothing about the
child's own request identity is invented or faked here, and the authorized destination is still the route
the authenticated boundary carried.

This is **not** a rule that revokes on host-side mutation. A host that rewrites its own members to the
same values is checked under exactly the captured ones and releases normally; what cannot happen is a child
being asked about a scope or registration this receive never bound. The provisional byte and key copies
are **zeroed in a `finally` when the receive ends** — including on an inspection, policy or sentinel
refusal — and are never reachable from a result, a binding, a finding or the released bytes.

Scope of the claim, stated narrowly. This is a **local snapshot-ownership property of this one module over
two of its own host members**. It says nothing about any other egress path, about a host that builds a
*different* registration before the next receive, about the sentinel's own detection quality, about
inspection correctness or finiteness, or about transport honesty — those stay host obligations. One
measured nuance: rewriting the host's key array alone is not a bypass, because the child fingerprints the
registration entries and the payload under the same key of one request frame; the scope and entry aliases
are what matter. This is **not** a production result, **not** a held-out result, and **not** an exercise
of proposed
[decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md).

## The exact private canonical image

The image is the **body bytes of the accepted complete response**, and nothing else: no status line, no header,
no transport framing and no credential, so there is no header a hostile observed label could inject into. It is
serialized by the existing canonical JSON seam ([canonical-json.ts](../../src/canonical-json.ts)): no
insignificant whitespace, members in canonical order, minimal string escaping, integers only. One accepted
response therefore has exactly one image, and the image digest cannot mean two documents. The assistant text,
every protocol member and every literal are preserved exactly as the codec decoded them; there is no treatment
anywhere in this path, so the checked image is the released image.

The image is snapshotted before any `await` and never leaves this module: the sentinel's own private `ALLOW`
copy is the only representation the release point receives, handed over exactly once.

## The snapshot-bound per-unit inspection handoff

The image is decomposed into exactly three units, each pinned to a real, contiguous byte range of it, in wire
order:

| Unit | Kind | Exact bytes it covers |
|---|---|---|
| `u0` | `PROTOCOL` | the choice envelope up to and including `{"content":`, which carries the finish reason |
| `u1` | `MESSAGE` | the assistant content as its exact JSON literal |
| `u2` | `PROTOCOL` | the trailing role literal plus **every** remaining protocol member: `created`, `id`, `model`, `object` and optional `usage` |

Together the three ranges are the whole image: every variable field — id, model, protocol metadata and
assistant content — is inside a declared unit, with no gap and no overlap.

`inspect` receives a **separate copy** of the image plus a binding
`{ version: 1, interactionRef, imageDigest, units }`, and answers with
`{ version: 1, interactionRef, imageDigest, coverage: 'COMPLETE', remainder: 'NONE', units: readonly {
unitRef, classificationDigest, classification }[] }`.

A finding is usable only when **all** of the following hold, and each is re-derived here rather than believed:
the result is structurally exact, `coverage` is `COMPLETE`, `remainder` is `NONE` and it echoes this receiver's
own `interactionRef` and `imageDigest`; there is **exactly one** finding per declared unit (no missing,
duplicate or invented unit); the classification is `RESOLVED` and carries at least one `FOUND` **detector**
record; and `digestClassification(classification)` — recomputed over the record this receiver will actually
decide over — equals the pinned `classificationDigest`.

Anything else is `INSPECTION_REFUSED`, including a thrown callback, a returned `undefined`, an unknown own key,
an empty finding list, a substituted record and an unresolved remainder. **`coverage: 'COMPLETE'` alone never
authorizes**: completeness was never a safety claim anywhere in this repository. **Detector absence is never
clearance**: a semantic-only `PUBLIC` judgment with no detector evidence refuses, and this module never turns an
absent or partial finding into a `PUBLIC` assumption of its own. It fabricates no evidence, and a
caller-supplied or substituted digest never authorizes because the digest is recomputed.

## The accepted path

1. Translate with the strict codec; every codec refusal passes through unchanged, so unsupported fields,
   duplicate keys, opaque or multimodal content, an assistant `refusal`, multiple choices, tools and every
   stream fragment or SSE frame refuse before an image, a callback, a decision or a child exists.
2. Observe the route and policy commit; validate the destination label.
3. Build the exact canonical image and bind it to a fresh interaction envelope from the trusted boundary.
4. Take the snapshot-bound inspection evidence over the whole image.
5. `decidePolicy` with operation `SEND` for **every** unit with a distinct candidate reference, and require
   `SELECTED` with treatment `KEEP` for all of them, under the pinned `UNTRUSTED` provider source trust.
6. One check in the real fixed-worker child process over the exact bytes, with the authorized destination taken
   from the authenticated boundary rather than from the observation, under the scope and registration
   captured privately before the inspection.
7. Re-observe the route, profile and policy commit, re-read the boundary evidence's freshness, then re-read
   sticky cancellation, and release — all in one synchronous turn, with no callback and no `await` between the
   last check and `releaseExact`.

**Step 7 is ordered, and the order is the guarantee.** The final `observe()` is host code, so it runs first and
every structural and freshness check it can invalidate follows it; cancellation is read again last,
immediately before the release call. It is the **last host code that runs at all**, because the release method
was captured during validation rather than read off the host here. The freshness re-read is the
[envelope contract's own rule](interaction-envelope.md): the clock at the release point must still fall inside
every snapshotted proof's issue/expiry interval, within the five-minute interaction age. An unchanged proof
digest is **not** a current proof. The envelope is not recreated, because a new interaction identity would
invalidate the image digest, every unit reference and every pinned classification and policy decision.

Nothing is retried. A failed release is reported, not rolled back: a release point that partially executed its
effect cannot be undone by this module, and the `RELEASED`/`REFUSED` result says only what this module observed.

## Refusals

Every refusal is one fixed code, or one of the strict codec's own fixed codes. No code carries a field name,
byte offset, parser excerpt, exception message, release error, sentinel reason or any part of the input.

| Code | Meaning |
|---|---|
| `HOST_INVALID` | the trusted host is not the exact declared shape; this receiver can never release |
| `RECEIVER_BUSY` | one receive is already in flight; there is no queue, pool or replay |
| `CANCELLED` | `cancel()` was observed, including inside the final host observation, or this receiver was already cancelled |
| `IMAGE_REFUSED` | the accepted response cannot be serialized as one canonical image under the fixed serializer bounds (a string or member bound, or a number outside the integer-only form) |
| `INTERACTION_REFUSED` | the trusted boundary could not be bound to this interaction, or the evidence it was bound under is no longer current at the release point |
| `ROUTE_REFUSED` | the observed destination, profile digest or commit is not usable |
| `SCOPE_REFUSED` | the sentinel scope the child would run under does not belong to the authenticated tenant/project, or could not be established from own data descriptors after a refused snapshot |
| `INSPECTION_REFUSED` | empty, partial, foreign, unresolved, substituted or unbound inspection evidence |
| `POLICY_DENIED` | the real policy seam denied: unknown or stale policy, foreign context, profile or rule mismatch, or a classification whose trust is not the pinned `UNTRUSTED` |
| `POLICY_HELD` | the real policy seam held the decision for review |
| `POLICY_NOT_KEEP` | a real selected treatment that is not `KEEP` |
| `SENTINEL_BLOCKED` | the child did not `ALLOW` these bytes, the request could not be snapshotted at all, or the check could not run |
| `ROUTE_CHANGED` | the route or profile changed between the check and the release |
| `POLICY_STALE` | the committed policy identity changed between the decision and the release |
| `RELEASE_FAILED` | the trusted release point failed or did not confirm |
| `RECEIVER_FAILED` | fail-closed catch-all for an unexpected internal failure; carries no detail either |

## Limits, stated honestly

- **The release point is trusted.** Retries, DNS or routing changes, a host that ignores the bytes it is given
  and a partially executed release are outside what this module can observe or prevent.
- **The host is trusted.** An authenticated boundary that is not actually authenticated, a profile digest that is
  not derived from the committed profile and an inspection callback that classifies nothing real all pass
  straight through. Deriving the profile digest from the committed profile record and producing genuine detector
  evidence are integration-host obligations; the release-point re-reads are congruence checks and authenticate
  no proof.
- **Finite trusted callback behavior is assumed, not enforced.** There is no hard timeout on `inspect` or on
  `releaseExact`; a callback that never returns leaves this receive pending. The sentinel's own absolute deadline
  covers the child, and nothing else.
- **Canonicalization is stricter than the codec.** The image is serialized by the existing canonical seam, so a
  response the codec accepts can still be refused as `IMAGE_REFUSED` when one string or member exceeds that
  serializer's fixed bound. That is a fixed, fail-closed bound, not a truncation: no shortened image is ever
  released.
- **No bypass resistance is claimed.** A caller that obtains the same response bytes without going through this
  receiver is not covered by anything here, and nothing here intercepts a live provider connection.
- **Not an evaluation result.** The evidence below is unscored, synthetic and non-enforcing; it is not a held-out
  result, a comparative win or promotion evidence ([evaluation.md](../evaluation.md)).

## Deliberately absent

No HTTP listener or response writing, no gateway route, no provider SDK, no credential, API key, vault or broker,
no original restoration, no streaming or SSE fragment, no tool or hosted-tool interception, no multimodal or
binary content, no transformation, no audit ledger call, no scoring, no held-out protocol, and no claim of global
protection. A production authenticated inbound path remains host adapter work ([#21](https://github.com/Marcus-Levin/hylja/issues/21),
[threat-model.md](../threat-model.md)).

Evidence: [`test/openai-keep-receiver.e2e.test.mjs`](../../test/openai-keep-receiver.e2e.test.mjs): an
executable matrix over the accepted path (a real fixed-worker child over the exact private image and an
in-memory release capture compared against an independently written literal), whole-image unit coverage pinned
to declared byte ranges, planted originals and a canary in the assistant content, the model metadata and the
protocol id, the codec refusals and withholding refusal codes it exercises (the `RECEIVER_FAILED` catch-all
and codec codes such as `BODY_TOO_LARGE` and `INVALID_CHOICE` are named above but **not** exercised by this
suite), cancellation raised inside the trusted
inspection and inside the final observation, boundary evidence that expires under real elapsed time inside that
inspection, evidence that cannot be bound at all, a release point that is a Proxy whose `get` trap cancels the
receiver if the release method is read back off it, the receiver a captured method keeps and the later method
swap that cannot retarget it, a host that rewrites its own scope, registration scope, key array and entry
list mid-inspection while the planted original still withholds under the privately captured tenant A (with a
benign rewrite to the same values still releasing, so no automatic revocation rule is invented), an unknown
registration key staying one fixed restrictive refusal, revoked-Proxy hosts, and the "later caller or
inspection-copy mutation changes no released byte" property. It calls no provider, holds no credential and
reaches no network at all; every fixture value is obviously synthetic and non-routable.