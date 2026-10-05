# Complete-text OpenAI request sender contract (#201, whole-message MASK #218)

Status: draft foundation contract for [#201](https://github.com/Marcus-Levin/hylja/issues/201) and
[#218](https://github.com/Marcus-Levin/hylja/issues/218), children of
[#21](https://github.com/Marcus-Levin/hylja/issues/21). It documents observable behavior of
[`src/openai-text-sender.ts`](../../src/openai-text-sender.ts). It is **not** a gateway, a listener, a
provider client, an authentication implementation, a credential or vault path, a general
transformation engine, a response release or a global protection claim. Implementation status lives only
in [capabilities.md](../capabilities.md).

The authorization for the single treatment below is
[decision 011](../decisions/011-policy-selected-whole-message-mask.md). Transformation semantics
([#68](https://github.com/Marcus-Levin/hylja/issues/68)) and the information model
([#66](https://github.com/Marcus-Levin/hylja/issues/66)) stay **unadopted**, and
[decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) stays **proposed**.

## What changed from the KEEP-only sender

This module was KEEP-only: any selected treatment other than `KEEP` refused with `POLICY_NOT_KEEP`. It
now releases two cases and refuses everything else:

| Unit kind | Accepted real decision |
| --- | --- |
| `METADATA`, `MODEL` | `SELECTED` with `KEEP` |
| `MESSAGE` | `SELECTED` with `KEEP`, or `SELECTED` with `MASK` |

Everything else about the accepted path is unchanged: the same trusted host, the same
ORIGINAL-image-bound inspection handoff, the same real `decidePolicy` call per unit, the same fixed
sentinel child over the exact released bytes, the same dispatch-point guards, the same captured
transport, the same refusal vocabulary, and the same three-member sender surface. The old KEEP-only
contract name, `openai-keep-sender.md`, is now a navigation redirect to this document; the accepted
[decision 011](../decisions/011-policy-selected-whole-message-mask.md) links it and stays valid.

## The one transformation

A `MESSAGE` unit whose real policy decision is `SELECTED` with treatment `MASK` is replaced **whole**
by the fixed literal:

```text
[hylja:masked]
```

The literal is generic and original-independent. It carries no kind, format, validity, emptiness,
fidelity or other derived fact; it is not a typed placeholder, not a per-field or per-span rewrite, not
a fingerprint, not a mapping and not reversible, and nothing here restores an original. Two messages
carrying byte-identical text are two separate units with separate references, so one selected unit can
never rewrite a byte in another: there is no global replace of matching text anywhere in this path.
Its only visibility is the minimal irreversible presence and structure a masked unit has.

A string that merely looks like the marker, arriving in the caller's input, is ordinary untrusted
content: it is neither rewritten nor read as Hylja-issued. Only a real `MASK` decision produces the
literal.

**Who selects it.** Only the real Policy Engine. There is no caller-selected treatment, no substitute
text, no replacement callback and no payload field that can carry one: the codec refuses any extra own
key ([openai-text-request.md](openai-text-request.md),
[decision 003](../decisions/003-semantic-judgment-does-not-own-effects.md)).

**KEEP bytes and rebuilt framing.** A `KEEP` message keeps its exact original literal bytes, roles and
order; a `KEEP` model keeps its exact original literal bytes. The trusted JSON body and HTTP framing are
rebuilt from the final units, and `Content-Length` is the only header field recomputed, as
`UTF8(finalBody).byteLength`. The original `METADATA` unit digest covers a header that may now differ,
so a masked send's header digest is recomputed rather than reused; a final unit digest is never a copied
original digest.

**Relabelling never happens.** Masked text is not marked `PUBLIC`, not reclassified, and not bound to a
clearance; its classification evidence stays the classification real policy decided over.

## The private plan and its derivation

The policy loop writes one **private, discriminated** entry per unit, and nothing else can:

- `treatment: 'KEEP'` for any unit kind, or `treatment: 'MASK'` for a `MESSAGE` unit only;
- each entry binds the original unit reference and digest to the classification digest that was used, the
  observed policy commit, the decision fingerprint and the transformation version.

The plan is then turned into the final image deterministically, and every step is fail-closed. The
rebuilt body is re-parsed by the same strict codec the caller's original had to pass and compared
against the plan: roles, order, count and every literal must decode back exactly. A final unit digest
must reproduce the plan (the masked units carry the digest of the literal's JSON bytes; every other
`KEEP` unit still carries its own original digest), and any mismatch, codec refusal or exception
withholds the send as `SENDER_FAILED`. No partial image, no substitute literal and no original comes
back out of the derivation.

These commitments are **congruence evidence about one change and nothing else**. They are not clearance,
not authorization, not a principal identity and not a bearer capability
([decision 008](../decisions/008-minimize-raw-data-retention.md)).

## Interface

```ts
createOpenAiTextSender(host: unknown): {
  send(input: unknown): Promise<{ status: 'SENT' } | { status: 'REFUSED'; code: TextSendRefusal }>;
  cancel(): void;
  readonly state: 'IDLE' | 'BUSY' | 'CANCELLED' | 'FAILED';
}
```

Three members, nothing else. There is **no public `READY`/prepared-byte handle, no `prepare`, and no
replayable `sendPrepared`**: a `SENT` result carries no bytes, no digest and no handle. The final image
is not a handle either: it exists inside this module, is checked by the sentinel child and is dropped
when the send ends. Cancellation is sender-owned and sticky; there is no caller `AbortSignal`, callback
or hook. One send is in flight at a time and a second concurrent call is refused, not queued.

`send(input)` takes exactly what the strict codec takes: one object with `endpoint` and `body`. The
caller supplies endpoint and body only.

### The trusted host

`createOpenAiTextSender` accepts an object with exactly these eight own **data** properties — the
[#201](https://github.com/Marcus-Levin/hylja/issues/201) set, with the inspection member renamed to
state its binding: `boundary`, `sourceTrust`, `policyBundle`, `scope`, `known`, `sentinel`,
`inspectOriginal` and `sendPoint`. Anything else — an unknown key, an accessor, a symbol key, a
missing member, a non-function `inspectOriginal`, `observe` or `sendExact`, a `sourceTrust` that is not
a trust level, a missing or `undefined` `known` — yields a permanently restrictive sender whose state
is `FAILED` and whose every `send` is `HOST_INVALID`. Construction never throws and never sends.

`inspectOriginal(image, binding)` is the whole-image, snapshot-bound classification handoff and is
bound to the **ORIGINAL** image. There is exactly one inspection callback and no second one: the final
image is never inspected here, it is derived from the original's decisions and then checked as bytes by
the sentinel child. `observe()` returns `{ destination: { id, profileDigest }, commit: { id, version,
digest } }` and is called once before the check and once more in the same synchronous turn as the
dispatch; redirects are prohibited (`ROUTE_CHANGED`), and a changed commit is `POLICY_STALE`.

Structural validity is the only thing this module checks about its host. `inspectOriginal`, `observe`
and `sendExact` are read once during validation and then invoked as those captured function references
on the receiver they were accepted on, so no trusted-host property is read after the last guard and a
later host-side method swap cannot retarget an existing sender. `observe` and `sendExact` keep the send
point's own object as their receiver. `inspectOriginal` runs on the accepted **own-data-property
snapshot** of the host: a frozen shallow copy carrying exactly the members that were validated, so a
callback that reads its own host state — `this.sendPoint`, `this.boundary`, its own classification
fixtures — sees the host's own members and not the wrappers this module installs over them. The raw
method is never called again through any other name. Everything else is re-checked by the authority
that owns it: the envelope, `decidePolicy` and the sentinel runner. Invoking the captured transport is
still host code.

## The captured scope and registration

`scope` and `known` are host-owned and mutable. The scope, the registration (its own scope, its key
bytes and its entry list), the observed destination and the authorized destination are captured into
**private copies before `inspectOriginal` runs**, through the existing sentinel snapshot seam
(`snapshotSentinelRequest`), and those copies are what the child is later handed. A host that rewrites
its own members while the finite inspection runs therefore cannot retarget the real child, and the
captured registration is never lost or rebuilt for the masked path: the child is asked about the final
bytes under exactly the scope and registration this send captured before inspection. The captured scope
is compared against the bound envelope, never against an earlier host alias. An unknown own key, an
oversized registration, a registration scope that is not the check scope or an unsupported value is
`SENTINEL_BLOCKED` before any child exists; a scope that cannot be shown to belong to the authenticated
tenant/project is `SCOPE_REFUSED`.

This is a **local snapshot-ownership property of this one module over two of its own host members**. It
is not a rule that revokes on host-side mutation, and it says nothing about any other egress path.

## The images

```text
POST /v1/chat/completions HTTP/1.1
Host: <observed destination id>
Content-Type: application/json; charset=utf-8
Content-Length: <UTF-8 byte length of the body>

{"model":"<model>","messages":[{"role":"<role>","content":"<content>"}, ...]}
```

Both images are private. The ORIGINAL image is snapshotted before any `await` and never leaves this
module; the trusted inspector receives its own copy, which it may scribble on; the final image is built
inside this module from the plan; and the released bytes are the sentinel's own private `ALLOW` copy over
the final image, handed over exactly once. Message order, Unicode (including astral and combining
characters) and every literal in a `KEEP` unit are preserved exactly. `stream: false` yields this one
complete, non-streamed image.

This send owns a fixed set of byte buffers, and **every one of them is zeroed when the send ends**, on
the accepted path and on every refusal alike: the framed ORIGINAL image; the private copy of it handed
to `inspectOriginal`; the rebuilt FINAL image and the private copy of it handed to the sentinel check;
the head and body encode buffers each image is framed from; the encode buffer behind each unit digest;
and, from the sentinel snapshot seam, the captured request payload and the captured registration key.
The wipe is one enrollment list consulted from a single `finally`, so a refusal taken before the
inspection ever runs clears the ORIGINAL image too, and a derivation that fails after it has already
framed its final image clears that image where it abandoned it. None of these buffers is ever reachable
from a result, a binding, a finding, a plan entry or the sent bytes.

**That is a statement about the buffers this module allocated, and about nothing else.** It claims no
erasure of the immutable JS strings this module holds (the body text, the message literals, the model
literal), of the caller's own input, of a copy the trusted inspector or the transport makes for itself
or hands onward, of the bytes inside the sentinel child, of any other process's or the runtime's memory,
or of anything recoverable through a heap inspection. Caller-retained and cross-process copies are
outside this contract.

## The accepted path

1. Translate with the strict codec; any codec refusal passes through unchanged.
2. Observe the route and policy commit; validate the destination label.
3. Build the exact ORIGINAL image and bind it to a fresh interaction envelope from the trusted boundary.
4. Capture the check scope, registration and destinations privately, then take the snapshot-bound
   inspection evidence over the whole ORIGINAL image.
5. `decidePolicy` for **every** unit with a distinct candidate reference, and record one private plan
   entry per unit. `METADATA` and `MODEL` require `KEEP`; a `MESSAGE` unit accepts `KEEP` or `MASK`.
6. Rebuild the final image from the plan, re-parse it through the strict codec and check its congruence.
7. One check in the real fixed-worker child process over the **exact final bytes**, under the scope and
   registration captured before the inspection.
8. Re-observe the route, profile and policy commit, re-read the boundary evidence's freshness, then
   re-read sticky cancellation, and dispatch — all in one synchronous turn, with no callback and no
   `await` between the last check and `sendExact`.

**Step 8 is ordered, and the order is the guarantee.** The final `observe()` is host code, so it runs
first and every structural and freshness check it can invalidate follows it; cancellation is read again
last, immediately before the transport call. The freshness re-read is the
[envelope contract's own rule](interaction-envelope.md): an unchanged proof digest is **not** a current
proof. The envelope is not recreated, because a new interaction identity would invalidate every digest,
unit reference and pinned decision already taken. Nothing is retried: a failed dispatch is reported, not
rolled back.

## Refusals

Every refusal is one fixed code, or one of the strict codec's own fixed codes. No code carries a field
name, byte offset, exception message, transport error, sentinel reason, literal or any part of the input.

| Code | Meaning |
| --- | --- |
| `HOST_INVALID` | the trusted host is not the exact declared shape; this sender can never dispatch |
| `SENDER_BUSY` | one send is already in flight; there is no queue, pool or replay |
| `CANCELLED` | `cancel()` was observed, including inside the final host observation, or this sender was already cancelled |
| `INTERACTION_REFUSED` | the trusted boundary could not be bound to this interaction, or the evidence it was bound under is no longer current at the dispatch point |
| `ROUTE_REFUSED` | the observed destination, profile digest or commit is not usable |
| `SCOPE_REFUSED` | the scope the child would run under does not belong to the authenticated tenant/project, or could not be established from own data descriptors after a refused snapshot |
| `INSPECTION_REFUSED` | empty, partial, foreign, unresolved, substituted or unbound inspection evidence |
| `POLICY_DENIED` | the real policy seam denied: unknown or stale policy, foreign context, profile or rule mismatch |
| `POLICY_HELD` | the real policy seam held the decision for review; a held state is never a transformation |
| `POLICY_NOT_KEEP` | a real selected treatment this unit does not implement for that unit kind: any treatment on `METADATA` or `MODEL`, and `REMOVE` or any other treatment on a `MESSAGE` |
| `SENTINEL_BLOCKED` | the child did not `ALLOW` the final bytes, the request could not be snapshotted at all, or the check could not run |
| `ROUTE_CHANGED` | the route or profile changed between the check and the dispatch |
| `POLICY_STALE` | the committed policy identity changed between the decision and the dispatch |
| `DISPATCH_FAILED` | the trusted transport failed or did not confirm |
| `SENDER_FAILED` | fail-closed for a deterministic derivation failure, and for an unexpected internal failure. The derivation case is exercised by a masked rebuild that outgrows the codec's own byte bound; no accepted host surface reaches the internal-failure case, so that one is fixed but unexercised |

A known-original or canary registration that already holds the mask literal is a real collision: the
fixed child finds it in the final bytes and the whole send is `SENTINEL_BLOCKED` with no dispatch
([decision 009](../decisions/009-secrets-are-not-synthetic-identities.md)). A registered original that
survives in a `KEEP` unit withholds the same way.

## Limits, stated honestly

- **The transport is trusted.** Redirects, retries, DNS rebinding, proxying and a host that ignores the
  bytes it is given are outside what this module can observe or prevent.
- **The host is trusted.** An authenticated boundary that is not authenticated, a profile digest not
  derived from the committed profile, and an inspection callback that classifies nothing real all pass
  through this seam. The dispatch-point re-reads are congruence checks, not authentication. A masked
  send is no more trustworthy than a `KEEP` send.
- **Finite trusted callback and transport behavior is assumed, not enforced.** There is no hard timeout
  on `inspectOriginal` or on `sendExact`; the sentinel's own absolute deadline covers the child only.
- **One unit per message, whole image per send.** No streaming holdback, no interleaved tool argument
  handling, no chunk abort handling and no backpressure; streaming input is refused by the codec.
- **Originals exist in this process for the duration of one send.** They are held in private copies so
  real policy can decide over them, and the buffers this module allocated are zeroed when the send ends.
  No erasure of the immutable strings this module holds, of the caller's input, of copies inside the
  runtime, the inspector, the transport or the child is claimed, and nothing here restores an original.
- **A mask is not a utility claim.** Nothing here measures whether a masked conversation still works,
  and no held-out, comparative or promotion result follows from it.
- **Not an evaluation result.** The evidence below is unscored, synthetic and non-enforcing
  ([evaluation.md](../evaluation.md)).

## Deliberately absent

No HTTP listener, no gateway route, no provider SDK, no credential, API key, vault or broker, no
response inspection or release, no streaming, no tools, no multimodal or binary content, no typed,
per-field, per-span or reversible transformation, no second sender, no audit ledger call, no scoring and
no claim of global protection. A production authenticated send path remains host adapter work.

Evidence: [`test/openai-text-sender.e2e.test.mjs`](../../test/openai-text-sender.e2e.test.mjs). The
KEEP controls, alias and snapshot ownership, freshness, cancellation, contention and unusable-host
cases are retained; the additions are the mixed and all-masked positives over a real loopback capture
and a real fixed child with the final image declared as a literal, exact UTF-8 length, duplicate
occurrences treated as separate units, marker lookalikes and a registered literal collision, and the
withholding controls for a `MASK` decision on `METADATA` or `MODEL`, every other treatment and a held
review; the inspection callback's receiver (the accepted data-property snapshot, with a normal masked
release as its control); the owned-buffer zeroing of the inspection copy on both a masked send and an
inspection refusal, asserted only as a count of zero bytes; and a masked rebuild that crosses the
codec's own byte bound, which exercises the derivation-refusal branch for the first time. It calls no
provider, holds no credential, reaches the network only on `127.0.0.1` on an OS-assigned ephemeral port,
and every fixture value is obviously synthetic and non-routable.