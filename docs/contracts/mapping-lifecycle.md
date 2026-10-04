# Bounded mapping lifecycle contract

Status: draft foundation contract for issue #169. This documents a **pure reducer for one trusted current mapping metadata record and one explicit lifecycle command**. It is not storage, not a compare-and-set, not authorization, not audit, not key destruction and not a scheduler. Implementation status belongs only in [capabilities.md](../capabilities.md).

`applyMappingLifecycleCommand` answers exactly one question: given the one current record the trusted host holds, and one explicit command pinned to that record, what is the **next** record this proposal would produce? It never applies a change. Its answer is a proposed record or a fixed refusal code; nothing else. Lifecycle is the broker side of [vault.md](../vault.md) and [security-model.md](../security-model.md#mapping-lifecycle), and it is metadata only: it resolves no original, reads no key and performs no effect.

## Inputs and authority

Three values arrive separately. The command carries none of the authority.

- **current record** (one trusted current mapping metadata record): `version`, an opaque `mappingRef`, the exact `scope` of `tenantId`/`projectId`/`sessionId`, one `state`, a positive monotonic `revision`, `createdAt` and `expiresAt` in epoch milliseconds.
- **command** (one explicit lifecycle command): `version`, the same `mappingRef`, the same three-part `scope`, the `expectedRevision` the caller decided against, and one `action`.
- **host clock**: `{ now }` in epoch milliseconds, supplied by the host.

A command is a **proposal**, not a right. It names no subject, workload, principal, purpose, destination or grant, so this seam cannot decide whether anybody may perform it. The trusted integration must authenticate the caller, authorize the change, and enforce the compare-and-set against the current row in storage. Time comes only from the clock argument: a timestamp inside a record or a command is data, never "now".

Shapes and bounds are validated once, before any transition: plain data properties only (no getters, no inherited or symbol keys, no unknown keys, no array), bounded opaque identifiers, nonnegative safe-integer instants, a positive safe-integer revision, `createdAt < expiresAt` and `now >= createdAt`. Every value inspected repeatedly is the normalized frozen copy. A malformed record, command or clock, an oversized field, a throwing accessor or a proxy produces a fixed refusal; the module never throws and never returns exception text.

## Result

The result is one frozen object and nothing more:

- `CHANGED` with a **new** record, when the command changes the lifecycle;
- `UNCHANGED` with a **normalized frozen** copy of the current record, when the command repeats a terminal state the record is already in;
- `REFUSED` with one fixed code from `MAPPING_LIFECYCLE_REASONS`, carrying no record, no identifier and no echoed value.

The envelope carries no original value, ciphertext, key, key version, blind index, plaintext or capability, and the records it does return are metadata only. Inputs are never mutated, and no returned object aliases an input object.

## Transition matrix

States are `CREATED`, `ACTIVE`, `EXPIRED`, `REVOKED`, `DELETED`. Actions are `ACTIVATE`, `EXPIRE`, `REVOKE`, `DELETE`. `QUARANTINED` exists in the security model but is **not** a state this reducer holds or proposes. Expiry is inclusive: at and after `expiresAt` the record is expired.

| current state | `ACTIVATE` | `EXPIRE` | `REVOKE` | `DELETE` |
|---|---|---|---|---|
| `CREATED` | `ACTIVE` before `expiresAt`, else `EXPIRY_REACHED` | `EXPIRED` at or after `expiresAt`, else `NOT_EXPIRED` | `REVOKED` | `DELETED` |
| `ACTIVE` | `INVALID_TRANSITION` | `EXPIRED` at or after `expiresAt`, else `NOT_EXPIRED` | `REVOKED` | `DELETED` |
| `EXPIRED` | `INVALID_TRANSITION` | `UNCHANGED` `EXPIRED` | `INVALID_TRANSITION` | `DELETED` |
| `REVOKED` | `INVALID_TRANSITION` | `INVALID_TRANSITION` | `UNCHANGED` `REVOKED` | `DELETED` |
| `DELETED` | `INVALID_TRANSITION` | `INVALID_TRANSITION` | `INVALID_TRANSITION` | `UNCHANGED` `DELETED` |

Every cell is reached only through the reference, scope and revision checks below, and a refusal in an earlier check never reaches a later one.

## Check order

The first failing check names the reason, so a caller cannot learn more than the fixed code.

| # | Check | Reason on failure |
|---|---|---|
| 1 | current record shape, bounds and window | `INVALID_RECORD` |
| 2 | command shape, bounds and action | `INVALID_COMMAND` |
| 3 | clock shape, and `now >= createdAt` | `INVALID_CLOCK` |
| 4 | `mappingRef` equals the current record's | `UNKNOWN_MAPPING` |
| 5 | tenant, project and session all equal the current record's scope | `SCOPE_MISMATCH` |
| 6 | `expectedRevision` equals the current revision | `STALE_REVISION` |
| 7 | the action has an entry in the matrix for this state | `INVALID_TRANSITION` |
| 8 | `ACTIVATE` before `expiresAt`, `EXPIRE` at or after it | `EXPIRY_REACHED` / `NOT_EXPIRED` |
| 9 | the revision can advance by one | `REVISION_OVERFLOW` |
| 10 | otherwise | `CHANGED` / `UNCHANGED` |

Row 1 precedes row 2: a malformed record never reaches a command check, and a malformed command never reaches a clock check. Rows 4, 5 and 6 are checked in that order, so a proposal that is wrong in more than one way reports the reference first. Row 7 precedes row 8, so an `EXPIRE` from an `EXPIRED` record is the idempotent repeat rather than a clock verdict. Row 9 is reached only by an effective change, so a repeated terminal command never fails on an exhausted revision.

## Guarantees

- **Monotonic, exactly-once revisions.** Every effective change increments `revision` by exactly one and refuses at `Number.MAX_SAFE_INTEGER` rather than wrapping. A refused or unchanged proposal consumes no revision. A rolled-back or replayed proposal is refused by row 6; nothing here detects a rollback that already happened in storage.
- **No revival.** `EXPIRED`, `REVOKED` and `DELETED` have no outgoing edge except `DELETE`, which moves `EXPIRED` and `REVOKED` to `DELETED`. There is no activation or restoration from a terminal state, at any clock, under any revision.
- **No implicit extension.** `createdAt`, `expiresAt`, `scope` and `mappingRef` are immutable through every command. There is no touch, sliding renewal, expiry extension, reactivation, quarantine or new state, and no command carries a time or state field of its own.
- **Idempotent terminal repeats.** Re-issuing `EXPIRE`, `REVOKE` or `DELETE` against a record already in that state returns `UNCHANGED` with the same record and no increment, but only for a matching current revision: a stale repeat is still `STALE_REVISION`.
- **Scope-locked transitions.** A command can move only the record whose reference and full three-part scope it names. A tenant, project or session mismatch changes nothing, so no proposal crosses a scope boundary.
- **Fail closed.** Absent, malformed, hostile or unverifiable input refuses with a fixed code. There is no default allow, no implicit expiry pass, no partial transition and no path where a failure makes a record more usable.

## Limits

- **This proposes, it does not persist.** A `CHANGED` result is the next record, not an applied change. There is no transaction, row lock, compare-and-set, rollback detection, cache invalidation or scheduler here. The host must perform the atomic compare-and-set against the current revision; if it does not, monotonicity is not enforced by this repository.
- **This authorizes nothing.** A command carries no identity or purpose, so a `CHANGED` result is not a permission. The trusted integration must authenticate the caller and authorize the change itself; [`authorizeMappingOperation`](mapping-authorization.md) is a separate seam that answers a different question about a different record and still grants nothing by itself.
- **No effect of any kind.** Nothing here destroys a DEK, performs cryptographic deletion, purges a ciphertext, invalidates a cache, buffers or records audit evidence, sends bytes, reaches a KMS/HSM, or touches a backup or restore path. Automatic expiry, retention cleanup and backup/restore behavior are [slice 2](../specs/slice-2-vault-and-reversible-identities.md) and vault concerns, still unimplemented.
- **The inputs are trusted because the integration supplies them.** This function cannot establish that the record is the current one, that the revision is the newest, or that the caller may act. [#15](https://github.com/Marcus-Levin/hylja/issues/15), [#16](https://github.com/Marcus-Levin/hylja/issues/16), [#17](https://github.com/Marcus-Levin/hylja/issues/17) and [#20](https://github.com/Marcus-Levin/hylja/issues/20) remain prerequisites of integrated lifecycle and recovery, and parent [#18](https://github.com/Marcus-Levin/hylja/issues/18) stays open.

## Threats and evidence

Addressed here: transition mistakes such as reviving a revoked or expired record, extending an expiry implicitly, activating after expiry, or skipping a terminal state; stale and replayed revision proposals; and cross-scope state changes attempted with another tenant's, project's or session's command.

New surfaces introduced: a command channel that a host must authorize, an `expectedRevision` it must enforce transactionally, and a `now` it must own. Each is an input the integration must get right.

How the acceptance tests prove the boundary - and what they do not: [`test/mapping-lifecycle.test.mjs`](../../test/mapping-lifecycle.test.mjs) asserts the literal matrix for all twenty state/action pairs before expiry and again at exactly the expiry instant, the inclusive expiry boundary, non-revival of every terminal state under every action and clock, one-increment-per-change with a refused overflow, reference, scope and revision swaps and their documented precedence, immutability of expiry, creation and scope, idempotent terminal repeats against both matching and stale revisions, deterministically generated command sequences that stay monotonic and never leave a terminal state, the fixed result shape with no originals or keys, frozen outputs that do not alias or mutate inputs, malformed and hostile record, command and clock shapes applied to complete otherwise-valid inputs, and that every refusal code the reducer returns is one of its fixed codes. It also projects proposed `ACTIVE`, `EXPIRED`, `REVOKED` and `DELETED` records onto [`authorizeMappingOperation`](mapping-authorization.md) **locally, in the test**, to show that the record this reducer proposes as `ACTIVE` still authorizes before expiry and that the terminal records it proposes authorize nothing for `USE`, `DISPLAY` or `EXPORT`.

That projection is a test-local adaptation of metadata between two separate seams. It is **not** an integration, not a claim that a caller can authorize a lifecycle change, and not evidence that any lifecycle effect is enforced anywhere. These are synthetic in-process assertions on this function's own choices. They do not prove that a vault or database applies a transition, that a scheduler expires anything, that a caller was authenticated, or that a DEK was destroyed. No cross-tenant, backup-restore or key-deletion behavior is exercised here; [#18](https://github.com/Marcus-Levin/hylja/issues/18) remains the open parent for integrated lifecycle.
