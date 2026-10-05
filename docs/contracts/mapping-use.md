# Bound runtime USE executor

Status: contract for [`src/mapping-use.ts`](../../src/mapping-use.ts) ([#211](https://github.com/Marcus-Levin/hylja/issues/211)). It defines one runtime executor for `USE` on **exactly one** opaque mapping reference. The other seams named here own their own contracts and are not restated: [mapping-authorization.md](mapping-authorization.md), [policy-contract.md](policy-contract.md), [audit-ledger-contract.md](audit-ledger-contract.md), [mapping-metadata-registry.md](mapping-metadata-registry.md), [mapping-aead.md](mapping-aead.md), [mapping-lifecycle.md](mapping-lifecycle.md). Implementation status lives only in [capabilities.md](../capabilities.md); [`test/mapping-use.e2e.test.mjs`](../../test/mapping-use.e2e.test.mjs) is the authoritative record of every assertion.

## The one operation this executor has

`createBoundMappingUse(trustedHost)` binds one reference, one tenant/project/session scope, one entity, the current-record registry, the audit substrate, the pinned policy handoff and one **private synchronous resource** at construction, and returns `{ use(): Promise<{ version: 1, code }> }`. That object is the whole interface.

- `use()` takes **no argument**. The caller supplies no operation, no reference, no authority, no grant, no key, no callback and no effect.
- The result is one fixed code out of `USED`, `NOT_FOUND`, `WITHHELD`, `FAILED` and nothing else. There is no reason, no reference, no identifier, no byte count and no exception. An unusable host is refused at construction with one fixed `TypeError` carrying no supplied value.
- There is no reference argument, no enumeration, no scan and no bulk path, so this is not a mapping lookup API ([decision 004](../decisions/004-brokered-vault-no-direct-mapping-api.md)). The original value is never returned to any caller; it is spent on one local synchronous resource that already knows its own record's identifier.
- `USE` never implies `DISPLAY` or `EXPORT`. Those are separate grants on a separate seam and have no path here.
- A second `use()` that overlaps an unfinished one is refused immediately, before any host call, because an overlapping effect on one reference has no coherent snapshot to spend. A sequential second use is a fresh observation, not a cached one.

## Bound at construction, never frozen as authority

Bound: the reference, the scope, the entity, the registry object, the audit ledger and its trusted context, the pinned classification, bundle and digests, the backend object, and the `authority`, `material` and `backend.lookup` callables.

**Not** bound: the authenticated subject and context, the observed route, the explicit grant, the current key version and the clock. Those are a host obligation, read again at the start of every `use()` and again after every external callback. A grant revoked, a route changed or a key rotated between two observations is observed, not spent.

## The order inside one `use()`

1. **Capture** every callback function **and its receiver** once, before any guard. A method re-pointed, swapped or re-targeted after this point cannot change what runs.
2. **Observe** one coherent current authority; require the bound scope, so a foreign scope never reaches the registry, the grant, the policy or the resource.
3. **Read** the real registry `current`; require `FOUND` and `ACTIVE`.
4. **Authorize** with the real `authorizeMappingOperation` for `USE`; require `AUTHORIZED`.
5. **Select** with the real `decidePolicy` for `USE` over the independently pinned classification digest and bundle digest; require `SELECTED` and `KEEP`.
6. **Bind the audit actor**: the recorded actor must be this authenticated subject. The ledger takes the actor from its trusted context and never from a draft.
7. **Load** the sealed record and the DEK into owned copies. These are the only awaits, and no plaintext exists while they run.
8. **Recheck after every external callback** - the material load and each audit append: observe again, require a clock that has not moved backwards, require the actor, context and route to be unchanged, re-read the real registry, require an unchanged revision and key version, reauthorize, rerun the real policy, require the same decision reference, and require the material to still be the material this instant would use.
9. **Record** the authorization attempt and the policy decision with the real `appendAuditEvent`, gating each on `gateHighRiskEffect` applied to the value `appendAuditEvent` itself returned - never a fabricated `RECORDED` result - and recheck again.
10. **Effect**: from the last guard to the backend call there is no `await`, no host property lookup and no dynamic function lookup. The real `openMappingPayload` opens an independently established expected scope; the **captured** synchronous backend decides on the recovered bytes.
11. **Clean up**: every owned byte buffer - the envelope copies, the DEK copy and the recovered plaintext - is overwritten in one `finally`, on the success path and on every exceptional path.

## The fixed codes

| Code | Exactly when |
|---|---|
| `USED` | the captured backend returned the primitive boolean `true` |
| `NOT_FOUND` | the captured backend returned the primitive boolean `false` |
| `WITHHELD` | any guard refused: an unreadable or foreign scope, an absent or non-`ACTIVE` record, a denied authorization, a `BLOCK` or `HELD` policy decision, a stale revision, a rotated key, a moved or expired instant, an absent or incongruent audit record, a changed actor or route, an opaque or throwing host callback, an overlapping call, or an opener refusal |
| `FAILED` | the effect was reached and could not be completed: the backend threw |

Nothing else maps to a `USE`. A backend that answers with anything but a primitive boolean withholds; its exception text never reaches the caller.

## Limits

- **The host is trusted, not authenticated.** This module verifies no principal, no workload, no token, no issuer, no key and no grant. A coherent but dishonest host is answered coherently and dishonestly. A host that lies *about* identity is not caught; a host that changes the world between two observations is.
- **Snapshot coherence is an obligation, not a proof.** The registry's own compare-and-set and single-event-loop atomicity are its contract's; this executor adds re-observation, nothing stronger. Two `use()` calls on two executors over one reference in one process can still interleave.
- **Key custody is the host's.** The DEK is supplied, copied once, used once and overwritten here. Generation, wrapping, rotation, storage, escrow and destruction are key-management obligations this module neither performs nor claims.
- **Audit durability is the host's.** The ledger is an in-memory substrate with no replication, no anchor of its own and no external checkpoint authority. `gateHighRiskEffect` is a pure structural check, which is exactly why the value passed to it is the one `appendAuditEvent` returned, in this process. This executor records `ALLOWED` decisions only; privacy-safe evidence of a *refusal* stays the integrating host's obligation.
- **Overwriting owned buffers is hygiene, not zeroization.** Copies held inside native crypto, garbage-collected buffers and swapped pages are not covered, and a backend that retains the bytes it was handed is outside this module's reach.
- **Not a protected-egress claim.** No byte leaves this process. There is no transport, no KMS/HSM binding, no production vault, no transaction, no lock, no retry, no recovery and no rate limit here.
- **Not acceptance.** [Slice 2](../specs/slice-2-vault-and-reversible-identities.md) stays a draft and [decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) is **proposed**; nothing here adopts a proposal or changes classification v1, policy or any adapter.

## Verification

```text
npm run build && npm run typecheck && node --test test/mapping-use.e2e.test.mjs
```

Fifteen cases in one file over one explicitly ephemeral in-process scenario. The observable counters are the host's own `authority` callback, its `material` callback, its backend and the audit ledger; the file makes **no** claim about calls the executor makes into `openMappingPayload`, because that call is internal to the shipped module. `npm run check:fixtures` and `npm run check:docs` are the repository guards.