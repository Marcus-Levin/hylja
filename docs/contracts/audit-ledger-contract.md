# Privacy-safe audit ledger contract

Status: draft foundation contract for issue #20. This documents the executable seam in
[`src/audit-ledger.ts`](../../src/audit-ledger.ts), **not** a production durable audit service, an
external checkpoint authority, an authorization broker, a mapping vault, or an enforcement
boundary. Implementation status belongs only in [capabilities.md](../capabilities.md).

## Scope and honest storage boundary

The module records privacy-safe evidence that a decision happened, who or what integration claims
it happened, under which exact intelligence bundle and decision digest, in one tenant/project
stream. Storage is an **in-memory synthetic substrate**: one plain object per tenant/project, no
durability, no replication, no separate administrative boundary from the process, and no anchor of
its own. `createInMemoryAuditLedger` produces a structure that anyone with host access can inspect
and rewrite; that is deliberate, because it is the reason verification is anchored to checkpoints
retained elsewhere. A production audit service, durable append-only storage, a separate audit
administrative domain, retention/deletion policy, and an independent checkpoint authority are all
future work.

## Event schema

An event is built from **two** separately supplied values. `appendAuditEvent(ledger, draft,
trustedContext)` takes a `draft` that may contain only the allowlisted fields for its `kind`, and a
`trustedContext` that carries scope, actor, and the two secret keys. A draft **cannot** assert
`actor`, `scope`, `tenantId`, `projectId`, `integrationId`, or any key: those names are not in any
draft's allowlist, so a forged authority in the draft is `INVALID_DRAFT` rather than a recorded
claim. This is the structural form of "supplied trusted integration context" versus "self-asserted
authority".

Always present: `version`, `kind`, `operation`, `outcome`, `reason`, `occurredAt`, `bundle`,
`correlationRef`, `scope`, `actor`. Per-kind extras are declared in `REQUIRED_BY_KIND` /
`OPTIONAL_BY_KIND`:

| kind | operations | required extras | optional extras |
| --- | --- | --- | --- |
| `CLOAK` | `CLOAK` | `entityRef` | `interactionRef`, `classification` |
| `POLICY_DECISION` | `SEND` `USE` `DISPLAY` `EXPORT` | `decision`, `candidateRef` | `interactionRef` |
| `AUTHORIZATION_ATTEMPT` | `USE` `DISPLAY` `EXPORT` | `entityRef` | `interactionRef`, `classification` |
| `MAPPING_LIFECYCLE` | `CREATE` `READ` `EXPIRE` `REVOKE` `DELETE` | `entityRef` | `interactionRef`, `classification` |
| `KEY_OPERATION` | `CREATE` `ROTATE` `DESTROY` | `keyVersion` | none |
| `POLICY_OPERATION` | `DEPLOY` `UPDATE` | none | none |

`AUTHORIZATION_ATTEMPT` and `MAPPING_LIFECYCLE` are **reserved schemas for #17 and #18**. They
record what a future broker or lifecycle operation would record, including denials and correlation.
This issue implements neither a broker nor a vault and depends on neither; recording an authorized
`USE` event grants nothing, and the module has no `USE`/`DISPLAY`/`EXPORT` field, capability or
grant of any kind.

There is no raw payload, no free-text metadata bag, no arbitrary source/destination reference, no
purpose text, no provenance string, no query, no exception message and no caller-authored error text
anywhere in the schema. `reason` is one of eight fixed codes, and `outcome` must agree with it
(`ALLOWED` pairs only with `POLICY_ALLOWED`/`RESOLUTION_AUTHORIZED`, `DENIED` only with
`POLICY_DENIED`/`RESOLUTION_DENIED`/`LIFECYCLE_DENIED`/`ADMIN_DENIED`, `APPLIED` only with
`APPLIED`/`ADMIN_APPLIED`). Failures are returned as fixed codes (`INVALID_DRAFT`,
`INVALID_CONTEXT`, `INVALID_LEDGER`, `KEY_UNAVAILABLE`, `SCOPE_MISMATCH`, `EVENT_CAPACITY`,
`AUDIT_UNAVAILABLE`) or as a fixed-message `TypeError` from the three serialization/digest helpers.
A code naming the *submitted* value is used where the source is known: an unreadable stream is
`INVALID_LEDGER` on append, verification and read/export, never a caller or authority failure. The
module contains no logging call of any kind, asserted by test over the source, test and compiled
output.

## Privacy of the recorded evidence

Caller-supplied opaque references (`entityRef`, `correlationRef`, `interactionRef`,
`candidateRef`) are **never stored**. Each is replaced by a scope-bound keyed pseudonym
`ent_`/`cor_`/`int_`/`cnd_` + the first 32 hex characters of
`HMAC-SHA256(pseudonymKey, tenantId ␀ projectId ␀ role ␀ reference)`. The tenant/project and role
are inside the MAC input, so the same raw reference never collides across tenants, projects or
roles, and the same reference is correlatable within one stream without the ledger holding the
reference. The raw value is discarded after the MAC.

Fields read **verbatim** are only identity/version tokens: `tenantId`, `projectId`,
`integrationId`, `principalId`, `workloadId`, bundle `id`/`version`, component `version`, and
`keyVersion`. All are constrained to `[A-Za-z0-9][A-Za-z0-9._=-]{0,127}`, which structurally
excludes an email address, URL, host, path or free-text purpose; `keyVersion` is additionally
restricted to a numeric version. Verbatim actor identity is required: administrative key and policy
operations must be **attributable**. The residual limit is explicit — a protected original that is
itself a legal token (for example `jane.quinte` in a principal identifier) cannot be distinguished
from an identity, so the trusted integration must supply authenticated identity identifiers. That
is an upstream obligation, not something this module can prove.

`classification` is restricted to a #3 `SEMANTIC_CLASSES` × `SENSITIVITIES` pair, and `decision` to
a #4 `state`/`treatment`/digest triple. `bundle` carries the exact pinned policy `id`, `version`
and 64-hex content digest plus an ordered, duplicate-free list of allowlisted
`AUDIT_BUNDLE_COMPONENTS` versions, so a reader can name the exact intelligence bundle. The digest
and decision digest are unkeyed replay commitments, not authorization tokens; only a digest pinned
independently by the trusted control plane is authoritative.

## Bounded, defensive reading of caller values

Every crossing value — draft, context, ledger, entry, checkpoint array, query, authority — is read
through one bounded `Reflect.ownKeys` snapshot with a key cap, own **data** descriptors only, no
getters, no inherited properties, and no second enumeration. A time-varying Proxy therefore cannot
grow the inspected key set between a size check and a value read. Arrays are checked against a
declared length, the key count, and per-index descriptors, and the declared `length` — an O(1) own
data property — is bounded **before** the key set is enumerated, so an over-long container is refused
without work proportional to it. Objects carry no such cheap size: a plain object, or a hostile
`ownKeys` trap that reports millions of keys, costs one enumeration before it can be refused. These
bounds therefore bound the *inspected* work the module performs; they are not immunity from
arbitrary host-level resource exhaustion, and no such guarantee is claimed.

Two paths read a stream, with deliberately different scopes. The **append path** inspects the array
identity, takes **one** `length` read, validates only the entry it will extend, pushes into exactly
that captured array and confirms the commit; it does not re-validate the whole stream, because doing
so makes append cost quadratic in stream length and an audit sink that degrades as evidence
accumulates is itself an audit-outage risk. It also does **not** enumerate the container's own key
set, for the same reason: a container carrying extra own keys is refused as `INVALID_LEDGER` by the
paths that do enumerate it (verification, checkpoint, read and export). The **verification,
checkpoint and read/export paths** rebuild every entry from its own bounded descriptors. An append
into a stream already corrupt further back therefore succeeds and is reported by `verifyAuditStream`
as `CHAIN_BROKEN` — or `SCOPE_MISMATCH` when a tenant-substituted entry is what is corrupt — not by
the append; this is a stated limit, not a detection claim at append time.

## Append, tamper evidence and anchoring

`appendAuditEvent` returns `{ status: 'RECORDED', receipt }` or a typed restrictive failure. It is
all-or-nothing: the event is fully validated, pseudonymized and HMAC'd before the stream is touched,
so a rejected append never advances the sequence, never writes a partial entry and never leaves a
gap. It does not throw for a caller-supplied value.

**The commit is confirmed, not assumed.** The write into a caller-supplied container is a dynamic
call that can return normally and store nothing — an own no-op `push`, or a `Proxy` whose
`set`/`defineProperty` traps report success without writing. Before any receipt exists, the module
reads the record back through its own bounded descriptors: this exact record must be readable at the
slot it occupies in this exact array, and the array's own `length` must be the one value that grew by
one. A container that is sealed, read-only, non-extensible, mis-reports its length, stores a
different record, lies about the read-back, or refuses the descriptor read is `AUDIT_UNAVAILABLE` —
the same code as a sink that has cleared `accepting`. An uncommittable or unverifiable ledger is
therefore a typed audit outage rather than an exception a caller could catch and route around, and no
dependent high-risk effect proceeds against it. A decorated container is also never left looking like
healthy empty evidence: `verifyAuditStream`, `readAuditEvents` and `exportAuditEvents` refuse the
same array as `INVALID_LEDGER` instead of reporting an empty stream.

Honest storage trust boundary: confirmation proves that the record is in **this** array at **this**
sequence at **this** moment. It is not durability, replication or retention, and a container that
lies about both the write and the read-back cannot be distinguished in language (this is pinned by
test as a stated limit). The two HMAC keys are additionally refused when all-zero, because an empty
publicly derivable key would make a "verified" chain authenticate nothing; every other property of
key quality — distribution, generation, custody, rotation, destruction — remains a key-management
obligation this module neither performs nor claims.

At `maxEntries` the append returns `EVENT_CAPACITY` and changes nothing. `accepting: false` models an
audit sink that cannot commit and returns `AUDIT_UNAVAILABLE`.

Each entry carries `sequence`, `prevDigest`, and
`entryDigest = HMAC-SHA256(chainKey, canonicalJson({ version, sequence, prevDigest, event }))`,
where the canonical JSON is built only from normalized fields in fixed key order, never from caller
JSON. The ledger retains no key: verification recomputes from the supplied `chainKey`.

`verifyAuditStream(ledger, trustedContext, checkpoints)` is explicit that **internal chain
integrity is not tamper evidence**. A party holding the chain key can rewrite an entire stream and
produce a perfectly self-consistent chain; nothing inside the ledger can detect that. Only a
checkpoint the ledger does not control can, so verification returns one of:

| status | finding | meaning |
| --- | --- | --- |
| `VERIFIED` | `VERIFIED_TO_ANCHOR` | consistent and equal to every retained checkpoint, **through `anchoredThrough`** |
| `UNANCHORED` | `NO_ANCHOR` | chain consistent but **no retained checkpoint**; nothing is claimed |
| `TAMPERED` | `CHAIN_BROKEN` | modification, reordering, insertion, gap, or a chain-key change |
| `TAMPERED` | `ENTRY_MISSING` | a checkpointed sequence is absent from the stream (deletion) |
| `TAMPERED` | `TAIL_TRUNCATED` | the stream ends before a retained checkpoint |
| `TAMPERED` | `CHECKPOINT_DIGEST_MISMATCH` | a key holder rewrote an entry; the anchor disagrees |
| `TAMPERED` | `SCOPE_MISMATCH` | an entry or checkpoint belongs to another tenant/project |
| `UNAVAILABLE` | `ANCHOR_INVALID` / `KEY_UNAVAILABLE` / `INVALID_CONTEXT` / `INVALID_LEDGER` | cannot judge |

`VERIFIED` is scoped to `anchoredThrough`, and `unanchoredEntries` reports how many entries are
newer than the newest retained checkpoint. A consistent chain with no anchor is `UNANCHORED`, never
`VERIFIED`: a recomputed unauthenticated chain must not be describable as detected without an
anchor. `createAuditCheckpoint` produces the `{ version, scope, sequence, entryDigest }` record that
an **independently retained** store must hold; the ledger never keeps it, and minting one requires a
matching scope and the chain key. A checkpoint held only inside the ledger proves nothing. An
attacker who controls both the chain key and the anchor retention can still forge a consistent
anchored chain; that requires a real anchor authority (append-only external/WORM retention,
transparency log, notarization) and is future work.

## Read, export and availability gate

`readAuditEvents` and `exportAuditEvents` require an authority whose `scope` equals the stream
scope exactly; anything else is `SCOPE_MISMATCH` with no entries returned. **Scope isolation is
per entry, not merely per declared label**: every delivered entry's own `scope` must equal the
trusted access scope before anything is selected, exactly as `verifyAuditStream` requires. A ledger
whose outer label was switched to another tenant while its entries still belong to the first, or a
stream into which one substituted entry was spliced, returns `SCOPE_MISMATCH` with **no entries and
no foreign metadata** — not a pseudonym, digest, actor, bundle or tenant identifier — whether or not
the query would have selected those entries. One foreign entry denies the whole read rather than
returning the in-scope remainder. Selection is bounded
(sequence range, `kind` filter, `limit` ≤ 1000, default 100) and reports `matched` and `truncated`.
Returned entries are independent, deeply frozen rebuilds of the stored evidence: two readers never
share an object, no delivered copy aliases the ledger, and a reader cannot reach back through a
result to mutate stored evidence. Byte fidelity is unaffected — a delivered copy serializes
identically to the entry it came from. Export is a separate explicitly asserted permission
(`exportAuthorized: true`), and a read authority that carries the flag is rejected, so reading never
implies exporting. There is no cross-tenant listing, no search and no bulk API of any kind; the
stream holds pseudonyms and privacy-safe metadata only.

`gateHighRiskEffect(appendResult)` converts an append result into the audit precondition for a
dependent high-risk effect: `EVIDENCE_UNAVAILABLE` and `EVIDENCE_INVALID` are never `permitted`.
`permitted: true` means only that the required evidence was recorded — it is **not** an
authorization to resolve, reveal, release, transform or send anything, and the module never performs
any of those. The gate is a **pure structural check on the value it is handed**: it cannot bind a
receipt to an entry that is actually committed in a stream, so a caller that fabricates or replays a
`RECORDED` result gets `permitted: true`. The integrating effect must therefore pass the result it
received directly from `appendAuditEvent`, in the same process, without re-serializing, caching
across tenants or reconstructing it. Preventing a fabricated result is a call-site obligation that
this module cannot discharge, and is pinned by test rather than left implicit.

## Threat coverage and limits

The synthetic tests exercise: planted originals in every pseudonymized and verbatim field and the
exact serialized bytes of entries, receipts and checkpoints; identity-shaped and URL-shaped planted
originals rejected in verbatim fields; drafts attempting to assert actor/scope/keys; 64 generated
tenant/project variations proving reference non-correlation across tenants; hostile values
(`null`, arrays, `Date`, `Map`, `Set`, inherited-prototype objects, throwing getters, and Proxies
that throw on `get`, `ownKeys` or `getOwnPropertyDescriptor`, plus over-cap key sets and oversized
references); modified, deleted, reordered, tail-truncated, emptied, key-holder-rewritten and
cross-tenant-substituted streams; changed, wrong-scope, duplicate, unsorted and over-count
checkpoints; append unavailability, uncommittable streams and capacity; a generated matrix of sinks
that accept a write and discard, substitute or hide it, with a positive control that every `RECORDED`
result corresponds to a record readable in that array; atomicity of rejected appends; append bounded
work over a 2,000-entry stream; an over-long `entries` array refused before its key set is
enumerated; all-zero HMAC keys refused; a caller-supplied `occurredAt` recorded verbatim and bound by
the digest; relabelled and partly substituted streams refused on read **and** export, with 32
generated tenant substitutions returning nothing; frozen, non-aliasing read/export copies; absence of
grant-like fields, keys in the ledger, and logging. The stated limits that remain are also pinned by
test rather than left implicit: a container that lies about both the write and the commit read-back,
and a fabricated append result passed to `gateHighRiskEffect`.

Not covered here, and therefore not claimed: buffering tamper-evident evidence locally across a sink
outage (the security model allows "buffer where allowed **or** block"; only the blocking branch is
implemented, so an outage denies the dependent high-risk effect rather than deferring it);
production durability, replication or backup of audit
evidence; an external checkpoint/WORM/transparency authority; key management, key rotation and KMS
integration for the two HMAC keys (only the all-zero case is refused here); authenticated identity
and project membership for actor
attribution (an upstream obligation this module cannot check); separation of duties for
administrators; retention, expiry and deletion of audit evidence; multi-writer concurrency,
sequence arbitration and distributed append ordering; **auditing of the audit trail itself** — no
event kind or operation records a read or an export, and `fromSequence` + `limit` walks a whole
stream in `ceil(n/1000)` calls, so bulk enumeration is neither recorded nor rate-limited and a future
`AUDIT_ACCESS` kind/operation is needed; **integrity re-checking on read** — `readAuditEvents` and
`exportAuditEvents` structurally validate and rebuild each entry, enforce per-entry scope congruence
and enforce query bounds, but do not recompute chain digests, so an anchored integrity judgement on a
read result is **conditional on the caller separately running `verifyAuditStream` against a
retained checkpoint**; whole-stream validation on
the append path (see above: a stream already corrupt away from the append head is caught at
verification, not at append); fabrication or replay of an append **result** passed to
`gateHighRiskEffect`; abuse/rate signals such as bulk-resolution and enumeration detection; and
integration with the #17 broker, #18 lifecycle, #19 Egress Sentinel or any adapter. A protected
original that is a legal token in an identity field is not detectable here. **`occurredAt` is
caller-supplied and unverified**: there is no injected clock, only a shape and `Date.parse`
acceptance check, so a caller can backdate, forward-date or roll over the calendar date of any event
and the HMAC-bound value still looks authoritative; a trusted clock is future work. A confirmed
commit proves presence in this in-memory array, not durability. The two HMAC keys are
supplied by the caller and never rotated, versioned or destroyed by this module, and key management
for them is future work.