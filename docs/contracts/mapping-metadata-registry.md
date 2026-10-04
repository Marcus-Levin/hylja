# Bounded ephemeral mapping metadata registry contract

Status: draft foundation contract for issue #180. This documents an **in-process current-record seam for mapping metadata only**, not a vault, not a broker, not authentication, not authorization, not plaintext resolution and not durable storage. Implementation status belongs only in [capabilities.md](../capabilities.md).

`createMappingMetadataRegistry` owns the **current** mapping metadata record for every reference it holds, in one private in-process `Map`, and applies every lifecycle change through [`applyMappingLifecycleCommand`](mapping-lifecycle.md). It is the compare-and-set seam that [mapping-lifecycle.md](mapping-lifecycle.md) explicitly does not provide: the reducer proposes the next record for one record the host supplied, while this registry owns the current one, so two callers pinned to the same expected revision cannot both apply.

## Inputs and authority

Three operations, and nothing else: `insert`, `current` and `transition`. There is no remove, scan, enumerate or resolve.

- **request** (untrusted, bounded, structurally validated once): `version`, one `mappingRef`, a three-part `scope` of `tenantId`/`projectId`/`sessionId`, and per operation `expiresAt` on insert or `expectedRevision` and `action` on transition. Unknown keys - including `original`, `ciphertext`, `dek`, `apiKey` or any other secret-bearing field - are refused.
- **clock** (independently supplied host clock): `{ now }` in epoch milliseconds. A timestamp inside a request is an unknown key, not time. The registry **trusts** this clock and cannot establish that it is correct, monotonic or aligned with any other component.
- **options** (host configuration): `capacity`, a positive safe integer of at most 4096, supplied once at creation. An unusable value throws a fixed `TypeError` and never echoes the supplied value.

The registry carries no identity, workload, principal, purpose, destination or grant, so it proves nothing about whether a caller may insert, read or transition a record. **The trusted integration must authenticate the caller and authorize every call itself**; [`authorizeMappingOperation`](mapping-authorization.md) is the separate purpose-bound decision. An `INSERTED`, `FOUND`, `CHANGED` or `UNCHANGED` result grants nothing, and a refusal is never an effect either.

## Rules it holds for every input

- **Structural key, never a delimited string.** The key is the four-level path tenant, project, session, mapping reference, so delimiter-shaped identifiers cannot collide and two scopes holding the same reference stay isolated. A foreign scope and an unknown reference are the same answer, so neither discloses the other.
- **Creation is `CREATED` at revision 1 and only that.** The insert request has no field for a state or a revision, so a caller cannot backdate, pre-activate or pre-increment a record. The reference, the scope, `createdAt` and `expiresAt` are fixed at creation and immutable for the life of the entry.
- **One numbering domain, the reducer's own.** Revisions are positive as [mapping-lifecycle.md](mapping-lifecycle.md) defines them: creation is 1 and each effective change adds exactly one. The smallest pinnable `expectedRevision` is 1. There is no zero-based offset and no translation.
- **A transition reads the registry's own current record.** No caller-supplied record is accepted, so a cached copy cannot decide a compare-and-set.
- **Expiry is restrictive at every operation.** The first observation at or after `expiresAt` latches the entry expired and drives `EXPIRE` through the same reducer table; a clock that moves backwards is refused with `CLOCK_ROLLBACK`. Neither can be undone, so an observed expiry is never reversed by a later clock rollback.
- **A terminal entry is a tombstone.** `EXPIRED`, `REVOKED` and `DELETED` are never removed, never revived and never evicted, so a full registry refuses a new insert rather than reclaiming one.
- **Fail closed and never echo.** Malformed, hostile or unreadable input refuses with one of the fixed codes `INVALID_REQUEST`, `INVALID_CLOCK`, `INVALID_EXPIRY`, `CLOCK_ROLLBACK`, `DUPLICATE_MAPPING`, `REGISTRY_FULL`, `UNKNOWN_MAPPING`, `NOT_LIVE`, `STALE_REVISION`, `INVALID_TRANSITION` or `REVISION_OVERFLOW`. The module never throws out of an operation, never returns exception text and never logs anything.

## Limits

- **This is not durable storage.** The map is process-local, in memory and lost on exit. There is no transaction, row lock, replication, compare-and-set across processes, rollback detection, restore path, cache invalidation or scheduler. Atomicity is **single Node event-loop** only.
- **This stores metadata only.** No original value, ciphertext, key, key version, DEK, blind index, alias or plaintext is accepted, stored, returned or inferred, and there is no lookup API for one. Original values are resolved through the broker under purpose-bound authorization.
- **No KMS/HSM, audit or destruction claim.** Nothing here reaches a KMS or HSM, buffers or records audit evidence, destroys a key, sends bytes, or touches a backup or restore path.
- **Parent [#15](https://github.com/Marcus-Levin/hylja/issues/15) stays open** for relational encrypted persistence, an authenticated service and production-configured storage acceptance, and [#18](https://github.com/Marcus-Levin/hylja/issues/18) remains the open parent for integrated lifecycle. The broker side is [vault.md](../vault.md) and slice 2 ([slice-2-vault-and-reversible-identities.md](../specs/slice-2-vault-and-reversible-identities.md)).

## Threats and evidence

Addressed here: a caller-supplied record deciding a compare-and-set, two racing commands at one revision both applying, a stale command overwriting the final record, cross-scope reads and writes through a colliding or forged identifier, expiry reversed by a clock rollback, identity revival of a terminal entry, and a full registry silently evicting a tombstone.

How the acceptance tests prove the boundary - and what they do not: [`test/mapping-metadata-registry.test.mjs`](../../test/mapping-metadata-registry.test.mjs) drives the exact positive create/activate/current path through the reducer, races two commands pinned to one expected revision and asserts exactly one applies while the losing stale command refuses without overwriting, replays the same race against a test-local incomplete cached-record design to show both apply, and covers duplicate, full, stale, unknown, foreign, invalid-transaction, malformed-request and malformed-clock refusals, expiry latch and clock rollback, tombstone non-revival, generated scope and revision permutations, delimiter-shaped identifiers, and caller mutation of a supplied scope. It asserts the literal set of observed refusal codes and that the reducer's unreachable `REVISION_OVERFLOW` ceiling is never reached.

Those are synthetic in-process assertions on this module's own choices. They do not prove that a vault, database, broker or scheduler applies an effect, that any caller was authenticated or authorized, that persistence survives a restart, or that a cross-tenant deployment isolates anything. No full suite or coverage run, no held-out data and no network traffic is involved here.