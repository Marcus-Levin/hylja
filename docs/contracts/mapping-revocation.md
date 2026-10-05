# Bound audited mapping revocation owner

Status: contract for [`src/mapping-revocation.ts`](../../src/mapping-revocation.ts) ([#238](https://github.com/Marcus-Levin/hylja/issues/238)), a bounded child of [#18](https://github.com/Marcus-Levin/hylja/issues/18). It defines one coordinator for a lifecycle **mutation** on **exactly one** opaque mapping reference. The seams it composes own their own contracts and are not restated: [mapping-metadata-registry.md](mapping-metadata-registry.md), [mapping-lifecycle.md](mapping-lifecycle.md), [audit-ledger-contract.md](audit-ledger-contract.md), [mapping-use.md](mapping-use.md). Implementation status lives only in [capabilities.md](../capabilities.md).

## The one operation

`createBoundMappingRevocation(trustedHost)` binds one reference, one tenant/project/session scope, one pinned administrative purpose, one interaction, the current-record registry object with its `current` and `transition` methods, the audit substrate, one pinned policy identity and the host's own `authority` method. `revoke()` takes **no argument** and returns one fixed code: `REVOKED`, `UNRECORDED` or `WITHHELD`. There is no reason, reference, identifier, revision or exception, no reference argument, no enumeration and no bulk path, so this is not a mapping lookup API (decision 004). It creates no record, resolves no original and destroys no key.

## Administrative authorization, never a `USE` grant

The accepted authority answer is a **complete, closed, bound** decision: subject, context, `decision` (`ALLOW`/`DENY`), `role` (one closed value, `MAPPING_ADMIN`), the exact bound `mappingRef`, the exact bound `scope`, the exact current `revision`, `expiresAt` and `now`. Every field is required, no unknown key is accepted, and the pinned scope, purpose, reference and revision are each checked against what this owner bound or freshly read. The decision's own `scope` and the scope its `context` carries are checked **independently**, each against the bound scope, so a decision issued for a foreign scope cannot authorize anything by pointing at a matching context. A missing field, an extra field, a foreign scope or reference, a stale pinned revision, a decision for another purpose, a role outside the closed set, an expired decision and a bare boolean are all the same refusal.

**`USE` never authorizes revocation, structurally.** There is no `grant` key anywhere in the accepted shape, so a purpose-bound `USE` grant cannot even be supplied; the audit actor must be the authenticated administrative subject, and the administrative purpose is pinned at construction. [mapping-authorization.md](mapping-authorization.md) is deliberately not called here: it supports `USE`/`DISPLAY`/`EXPORT` only, and a revocation is not one of those.

The decision itself is an **explicit host integration obligation**. This module authenticates nobody, verifies no proof, token or issuer, and proves no host authenticity. What it checks is congruence and currentness; what it cannot check is that the decision came from a real authorization service, and separation of duties is a claim inside the host's answer, not a property enforced here.

## The order inside one `revoke()`

Every callback function and its receiver are bound once, at construction, so a method re-pointed or swapped afterwards is never invoked and a host method runs with the host as its receiver. The audit destination is settled next, before any host callback: the recorded actor must be the authenticated administrative subject, and **both the ledger's and the trusted context's tenant/project must be the bound scope**, because the append itself only checks those two against each other and would otherwise record this reference into a foreign stream. The actor and that scope are captured as the owned immutable snapshot the append is actually handed.

Then: observe the current authority; read the real registry `current` and require `FOUND` and `ACTIVE`, taking the pinned revision from that read as an owned copy; **record the authorized intent** through the real `appendAuditEvent`, gated on `gateHighRiskEffect` applied to the value the append itself returned; then await the raw authority answer **once more**. That raw answer is the last thing the call awaits: the continuation that reads it normalizes it and runs the whole final guard set - authority shape, congruence with the first observation, live actor, live audit scope, and a fresh registry `current` **last** - and then the captured compare-and-set, with no `await`, no host property lookup and no dynamic function lookup anywhere in it. Anything a host callback queues - a denial, an expiry, a rotation, a deletion, a swapped record - therefore cannot land between the last guard and the mutation. The mutation is marked attempted immediately before `transition` is invoked, so nothing from that point on can leave through a path that claims zero mutation.

## The fixed codes

| Code | Exactly when |
|---|---|
| `REVOKED` | the registry confirmed `CHANGED` with the bound reference and scope, `REVOKED`, at exactly the pinned revision plus one, **and** that confirmed applied result was recorded and gated |
| `UNRECORDED` | the mutation segment was reached and its completion cannot be proved: the registry threw, answered with anything malformed or unconfirmed (including `UNCHANGED`), returned a record that is not the one pinned, or the applied-result append or its gate failed. Nothing is revived, rolled back or second-guessed |
| `WITHHELD` | any guard refused before the mutation attempt, which claims **zero mutation**: an unreadable, foreign or absent audit destination, an unreadable or foreign scope or purpose, another reference, a `DENY`, an expired decision, a non-administrative role, an absent or incongruent audit actor, an absent or non-`ACTIVE` record, a stale or moved revision, a moved clock, a hostile or opaque callback, an overlapping call, or an unusable host at construction |

A **confirmed registry refusal** - a closed `{version: 1, state: 'REFUSED', reason}` carrying one of the registry's own reason codes - is the registry stating that it applied nothing, so that call is `WITHHELD` with **no** applied event. Only a confirmed `CHANGED` earns the applied event; every other answer shape after an attempted mutation is `UNRECORDED` and records no applied success.

An audit outage **before** the mutation is `WITHHELD`: nothing is revoked without recorded intent. A fault **after** an attempted mutation is `UNRECORDED`, never `REVOKED` and never `WITHHELD`.

## Retry, idempotency and concurrency

These are the registry's semantics, and this module adds none. The registry is monotonic: the applied call moves the record to `REVOKED` at `revision + 1`, `REVOKE` on a `REVOKED` record is the reducer's idempotent repeat, and a terminal entry is a tombstone that is never removed, revived or evicted. A later `revoke()` reads `NOT_LIVE` through the real `current` seam and is refused with zero mutation, so a retry can never undo, re-activate, extend or restore anything. Two owners pinned at one revision cannot both apply: the loser's registry read or compare-and-set refuses. There is **no rollback, compensating action or recovery here, and none is claimed**.

## Limits

- **Not a registry, store, vault or index.** It owns no record, no table, no transaction and no lock; the current record, its revision and every lifecycle transition belong to the shipped registry.
- **Not key custody and not key destruction.** No key, DEK, envelope or plaintext is read here; cryptographic material and its custody remain host obligations.
- **Not durable audit.** The ledger is a host-owned in-memory substrate with no replication and no external anchor; `gateHighRiskEffect` is a pure structural check, which is why the value passed to it is the one `appendAuditEvent` returned, in this process. Refusal evidence is the integrating host's obligation, exactly as in [mapping-use.md](mapping-use.md).
- **Snapshots stop mutation, not a malicious host.** Captured methods, receivers, identity and scopes stop a host from editing its own configuration mid-call. The sealed segment is a scheduling fact, not a lock: re-entrant code inside it stays trusted, and two coordinators in two processes are outside every claim here. The one thing it does establish is that nothing scheduled between the last guard and the compare-and-set can land in between: what a host queued while the last authority answer was pending has already been observed by the final guards.
- **Not the parent #18 acceptance**, and not a protected-egress claim: no byte leaves this process.

## Verification

```text
npm run build && npm run typecheck && node --test test/mapping-revocation.e2e.test.mjs
```

Twenty-seven cases in one file over one explicitly ephemeral in-process scenario, using the real registry, the real audit append and gate, the real bound `USE` executor with the real AEAD seam and the real authorization and policy seams: the accepted path and the real `USE` around it, retry and idempotency, concurrency, administrative refusal, the audit outage on each side of the mutation, the mutation segment's own answer shapes, the sealed segment, and construction. The assertions are the shipped modules' own observable behaviour: fixed codes, registry records read back through `current`, ledger entries read back out of the stream, the seam call counters of the host's own delegating registry view, and the `USE` host's own counters.