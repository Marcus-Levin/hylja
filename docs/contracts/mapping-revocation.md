# Bound audited mapping revocation owner

Status: contract for [`src/mapping-revocation.ts`](../../src/mapping-revocation.ts) ([#238](https://github.com/Marcus-Levin/hylja/issues/238)), a bounded child of [#18](https://github.com/Marcus-Levin/hylja/issues/18). It defines one coordinator for a lifecycle **mutation** on **exactly one** opaque mapping reference. The seams it composes own their own contracts and are not restated: [mapping-metadata-registry.md](mapping-metadata-registry.md), [mapping-lifecycle.md](mapping-lifecycle.md), [audit-ledger-contract.md](audit-ledger-contract.md), [mapping-use.md](mapping-use.md). Implementation status lives only in [capabilities.md](../capabilities.md).

## The one operation

`createBoundMappingRevocation(trustedHost)` binds one reference, one tenant/project/session scope, one pinned administrative purpose, one interaction, the current-record registry object with its `current` and `transition` methods, the audit substrate, one pinned policy identity and the host's own `authority` method. `revoke()` takes **no argument** and returns one fixed code: `REVOKED`, `UNRECORDED` or `WITHHELD`. There is no reason, reference, identifier, revision or exception, no reference argument, no enumeration and no bulk path, so this is not a mapping lookup API (decision 004). It creates no record, resolves no original and destroys no key.

## Administrative authorization, never a `USE` grant

The accepted authority answer is a **complete, closed, bound** decision: subject, context, `decision` (`ALLOW`/`DENY`), `role` (one closed value, `MAPPING_ADMIN`), the exact bound `mappingRef`, the exact bound `scope`, the exact current `revision`, `expiresAt` and `now`. Every field is required, no unknown key is accepted, and the pinned scope, purpose, reference and revision are each checked against what this owner bound or freshly read. A missing field, an extra field, a foreign scope or reference, a stale pinned revision, a decision for another purpose, a role outside the closed set, an expired decision and a bare boolean are all the same refusal.

**`USE` never authorizes revocation, structurally.** There is no `grant` key anywhere in the accepted shape, so a purpose-bound `USE` grant cannot even be supplied; the audit actor must be the authenticated administrative subject, and the administrative purpose is pinned at construction. [mapping-authorization.md](mapping-authorization.md) is deliberately not called here: it supports `USE`/`DISPLAY`/`EXPORT` only, and a revocation is not one of those.

The decision itself is an **explicit host integration obligation**. This module authenticates nobody, verifies no proof, token or issuer, and proves no host authenticity. What it checks is congruence and currentness; what it cannot check is that the decision came from a real authorization service, and separation of duties is a claim inside the host's answer, not a property enforced here.

## The order inside one `revoke()`

Every callback function and its receiver are bound once, at construction, so a method re-pointed or swapped afterwards is never invoked and a host method runs with the host as its receiver. Then: observe the current authority; require the audit substrate's recorded actor to be that administrative subject and capture it as an owned immutable snapshot; read the real registry `current` and require `FOUND` and `ACTIVE`, taking the pinned revision from that read; **record the authorized intent** through the real `appendAuditEvent`, gated on `gateHighRiskEffect` applied to the value the append itself returned; re-observe and re-read after every external callback. The last awaited answer is the final authority observation, and from that continuation the whole final guard and the mutation run with no `await` between them, the last host-owned read being the fresh registry read. Finally the applied result is recorded the same way.

The live audit actor and the registry read are the host-owned reads of each pass; the read order puts the audit actor first and the registry last, and everything after the registry read works on values this module already owns.

## The fixed codes

| Code | Exactly when |
|---|---|
| `REVOKED` | the registry applied `REVOKE` for the bound reference and scope at exactly the pinned revision plus one, **and** that applied result was recorded and gated |
| `UNRECORDED` | the mutation segment was reached and audited completion cannot be proved: the applied-result append or its gate failed, or the registry's own answer was not the applied `REVOKED` record. Nothing is revived, rolled back or second-guessed |
| `WITHHELD` | any guard refused before the mutation, which claims **zero mutation**: an unreadable or foreign scope or purpose, another reference, a `DENY`, an expired decision, a non-administrative role, an absent or incongruent audit actor, an absent or non-`ACTIVE` record, a stale or moved revision, a moved clock, a hostile or opaque callback, an overlapping call, or an unusable host at construction |

An audit outage **before** the mutation is `WITHHELD`: nothing is revoked without recorded intent. A fault **after** an applied mutation is `UNRECORDED`, never `REVOKED`.

## Retry, idempotency and concurrency

These are the registry's semantics, and this module adds none. The registry is monotonic: the applied call moves the record to `REVOKED` at `revision + 1`, `REVOKE` on a `REVOKED` record is the reducer's idempotent repeat, and a terminal entry is a tombstone that is never removed, revived or evicted. A later `revoke()` reads `NOT_LIVE` through the real `current` seam and is refused with zero mutation, so a retry can never undo, re-activate, extend or restore anything. Two owners pinned at one revision cannot both apply: the loser's registry read or compare-and-set refuses. There is **no rollback, compensating action or recovery here, and none is claimed**.

## Limits

- **Not a registry, store, vault or index.** It owns no record, no table, no transaction and no lock; the current record, its revision and every lifecycle transition belong to the shipped registry.
- **Not key custody and not key destruction.** No key, DEK, envelope or plaintext is read here; cryptographic material and its custody remain host obligations.
- **Not durable audit.** The ledger is a host-owned in-memory substrate with no replication and no external anchor; `gateHighRiskEffect` is a pure structural check, which is why the value passed to it is the one `appendAuditEvent` returned, in this process. Refusal evidence is the integrating host's obligation, exactly as in [mapping-use.md](mapping-use.md).
- **Snapshots stop mutation, not a malicious host.** Captured methods, receivers and identity stop a host from editing its own configuration mid-call. The sealed segment is a scheduling fact, not a lock; re-entrant code inside it stays trusted, and two coordinators in two processes are outside every claim here.
- **Not the parent #18 acceptance**, and not a protected-egress claim: no byte leaves this process.

## Verification

```text
npm run build && npm run typecheck && node --test test/mapping-revocation.e2e.test.mjs
```

Nineteen cases in one file over one explicitly ephemeral in-process scenario, using the real registry, the real audit append and gate, the real bound `USE` executor with the real AEAD seam and the real authorization and policy seams. The assertions are the shipped modules' own observable behaviour: fixed codes, registry records read back through `current`, ledger entries read back out of the stream, and the `USE` host's own counters.