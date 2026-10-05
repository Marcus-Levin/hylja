# Purpose-bound mapping authorization contract

Status: draft foundation contract for issue #163. This documents a **pure authorization decision seam for one mapping reference**, not a deployed broker, not authentication, not key access, not plaintext resolution, not USE execution, not reveal, not rate limiting and not durable audit. Implementation status belongs only in [capabilities.md](../capabilities.md).

`authorizeMappingOperation` answers exactly one question: may the authenticated caller perform this operation on this one mapping, for this purpose, in this session, into this actual destination and profile, right now? It does not select a treatment; treatment selection remains exclusively `decidePolicy` in [`src/policy.ts`](../../src/policy.ts) under [policy-contract.md](policy-contract.md). This seam is **additional** to that decision, never a replacement for it. Its operations and lifecycle rules are the broker side of [vault.md](../vault.md) and [security-model.md](../security-model.md); [authorization-contract.md](authorization-contract.md) states the surrounding intent.

## Inputs and authority

Five values arrive separately; the untrusted request carries none of the authority.

- **request** (untrusted, bounded): `version`, one `mappingRef`, `subject`/`workload`, `tenant`/`project`/`session`/`purpose`, a declared `destination`/`profileId`, and the requested `operation` (`USE`, `DISPLAY` or `EXPORT`).
- **host context** (independently supplied): the authenticated `subject` and request context, and the **actual** observed `destination`/`profileId` of the real routed sink.
- **mapping metadata** (one trusted current record): `mappingRef`, tenant/project/session scope, `lifecycle`, `semanticType`, `sensitivity`, a monotonic `revision` and an `expiresAt` instant.
- **grant** (one explicit trusted grant): the `mappingRef` and exact `revision` it covers, the `principal`/workload, the tenant/project/session scope, the bound `purpose`, the actual `destination`/`profileId`, one `operation`, and a finite `expiresAt`.
- **host clock**: `{ now }` in epoch milliseconds.

The three identity records - the request's `subject`, the host's authenticated `subject` and the grant's `principal` - must each carry a **nonempty** `workloadId` for every operation this seam supports. This seam is workload-bound: it exports a narrowed `WorkloadSubject` (`principalId` plus a required `workloadId`) rather than the envelope's general `Subject`, whose `workloadId` is optional for human contexts. A coherent principal-only request/host/grant is malformed at this seam and denies; it is not an alternate authorized path here, and integration with human-only contexts stays a separate human gate.

The trusted integration - not this module - authenticates the human principal and workload identity, binds the purpose and session, observes the routed destination including redirects, reads the current mapping record, evaluates the grant, and owns the clock. **Required trusted inputs are never constructed from request fields, payload content, model output, wire metadata or a caller-supplied trust label**, and no such label creates authority. A timestamp inside the request is rejected as an unknown field; time comes only from the host clock argument. Provenance of these values is a congruence check between separately supplied records, not proof of authenticity, and is only as trustworthy as the integration that supplies them.

Shapes and bounds are validated once, before any decision: plain data properties only (no getters, no inherited or symbol keys, no unknown keys, no array), bounded string lengths, safe-integer instants and revisions. Every value that is inspected repeatedly is the normalized copy. A malformed record, an oversized field, a throwing accessor or proxy produces a fixed denial; the module never throws and never returns exception text.

## The one shared grant normalizer

`normalizeMappingGrant(value)` is the single authoritative reader of the grant shape in this repository. It answers `TrustedMappingGrant | null`: a complete, valid grant becomes an owned record, and **every** other value is `null`. `authorizeMappingOperation` reads its grant through it, and so does the bound `USE` executor in [`src/mapping-use.ts`](../../src/mapping-use.ts), which previously kept its own mirrored copy of this schema - the drift that produced the false denial attribution in [#17](https://github.com/Marcus-Levin/hylja/issues/17)'s follow-up. One reader means one set of eight mandatory fields, one set of bounds and one set of refusals; a grant cannot be structurally valid to one consumer and structurally wrong to another.

It is **structural normalization and nothing else**, and this is the property that keeps it safe to share: `null` says only that the value is not a grant of the schema above, never that it is unauthorized, foreign, forged or stale, and an accepted record is never evidence of authority, currentness, scope congruence, lifecycle or expiry. It decides no precedence. The seam below still owns the `INVALID_CONTEXT` refusal and row 2 of the order; a boundary that cannot name a lifecycle about a value it never proved it held names nothing at all.

The returned record is frozen and owns every nested `principal`, `context` and `destination`: each is a new record built from primitives this module validated, never an alias into the source object. A caller that edits its own grant afterwards therefore cannot change what a later check reads, and a host-owned nested object is never carried into a later read. A reflection, enumeration, descriptor or index fault inside the read is caught inside the function, so it never throws and never carries exception text back to its caller - the same fixed-answer rule the seam itself obeys.

## Decision order

The result is `{version: 1, state: 'AUTHORIZED' | 'DENIED', reason}` and nothing else: no mapping metadata, no grant, no identifier, no plaintext, no opaque credential and no release capability is echoed. The checks run in a fixed order and the first failure names its reason:

| # | Check | Reason on failure |
|---|---|---|
| 1 | request shape and bounds | `INVALID_REQUEST` |
| 2 | host context, mapping, clock and grant shapes | `INVALID_CONTEXT` |
| 3 | request subject, context and destination equal the authenticated/observed host context | `CONTEXT_MISMATCH` |
| 4 | `mappingRef` equals the trusted current mapping | `UNKNOWN_MAPPING` |
| 5 | lifecycle is `ACTIVE` | `MAPPING_NOT_ACTIVE` / `MAPPING_EXPIRED` / `MAPPING_REVOKED` |
| 6 | `now` is before the mapping expiry | `MAPPING_EXPIRED` |
| 7 | the mapping is not a credential/`SECRET` mapping | `NON_REVERSIBLE_MAPPING` |
| 8 | mapping scope equals the authenticated tenant/project/session | `SCOPE_MISMATCH` |
| 9 | an explicit grant was supplied at all | `NO_GRANT` |
| 10 | the grant names that mapping | `GRANT_MISMATCH` |
| 11 | the grant pins the current revision | `STALE_REVISION` |
| 12 | grant principal/workload and scope equal the authenticated identity and mapping scope | `SCOPE_MISMATCH` |
| 13 | grant purpose equals the bound purpose | `GRANT_MISMATCH` |
| 14 | grant destination/profile equals the actual observed sink | `GRANT_MISMATCH` |
| 15 | the grant covers the requested operation | `OPERATION_NOT_GRANTED` |
| 16 | `now` is before the grant expiry | `GRANT_EXPIRED` |
| 17 | otherwise | `AUTHORIZED` |

Every code in that table is a member of the module's fixed `MAPPING_AUTHORIZATION_REASONS` list, so a denial never discloses which input differed beyond the class of check that failed.

Two points in that table matter when more than one check would fail at once. Row 2 validates the **shape of every trusted input, including the grant**, before row 3 congruence and before the mapping's lifecycle, so a revoked mapping presented with a malformed grant is `INVALID_CONTEXT`, not `MAPPING_REVOKED`. A grant that is simply **absent** is not malformed: it stays undefined through row 2 and is refused by its own row 9 `NO_GRANT`, after the mapping checks and before any grant-content check that would need a grant to exist. An `undefined` grant therefore never reaches the normalizer; a grant that is `null`, a non-object or structurally wrong does, and `null` from it is row 2's `INVALID_CONTEXT`.

## Guarantees

- **Workload-bound identity.** Every supported operation needs a nonempty `workloadId` in the request subject, in the host's authenticated subject and in the grant principal. A request that omits it is `INVALID_REQUEST`; an authenticated host subject or a grant principal that omits or blanks it is `INVALID_CONTEXT`. Coherent all-absent records deny for all three operations, and a caller-supplied trust label cannot supply the missing workload.
- **Operation separation.** `USE`, `DISPLAY` and `EXPORT` each need their own explicit grant for their own exact operation. A `USE` grant never authorizes `DISPLAY`, `DISPLAY` never authorizes `EXPORT`, and there is no wildcard operation, wildcard scope, wildcard purpose or wildcard destination.
- **Unconditional cross-tenant nonresolution.** A mapping authorizes only inside the exact tenant, project and session it was issued in. A caller from another tenant, a grant minted for another tenant, a project or session swap and a purpose swap all deny; no exception, flag or field on the request lifts it. Migration remains separately authorized and audited reissuance.
- **Non-reversible floor.** A mapping whose semantic type is `CREDENTIAL_OR_SECRET` or whose sensitivity is `SECRET` is refused at this seam for every operation. Credentials are not reversible mappings a grant can unlock ([decision 009](../decisions/009-secrets-are-not-synthetic-identities.md)); trusted tools obtain real credentials through ordinary secret management.
- **Lifecycle and freshness.** Only `ACTIVE` mappings inside their expiry authorize, and only a grant that pins the current monotonic revision does. A replayed older revision, a rolled-back record or an expired grant denies.
- **Fail closed.** Absent, mismatched, forged or unverifiable inputs deny. There is no default allow, no tenant fallback and no path where a failure makes a flow less restrictive, as [decision 007](../decisions/007-fail-closed-for-protected-egress.md) requires for protected egress.
- **No direct lookup.** The module takes one already-resolved reference and returns a decision. It is not a bulk mapping lookup API, and it resolves nothing.

## Limits

- This predicate **grants nothing by itself**. An `AUTHORIZED` result means only that these five supplied records agreed. A downstream broker must independently re-check the current lifecycle and revision, run the Policy Engine, authenticate the caller, record privacy-safe audit evidence and perform the actual effect.
- Nothing here authenticates anybody, verifies an issuer, proof, token, signature or certificate, reaches a KMS/HSM, selects or wraps a key, retrieves ciphertext, decrypts, resolves a mapping reference, injects a real value into a tool, reveals plaintext to a human surface, executes an `EXPORT`, rate-limits, buffers audit evidence or persists anything.
- The metadata, grant and host context are supplied by the caller of this pure seam. Their authenticity, freshness and completeness are upstream obligations that this module cannot establish.
- [#15](https://github.com/Marcus-Levin/hylja/issues/15) and [#16](https://github.com/Marcus-Levin/hylja/issues/16) remain prerequisites of later integrated broker resolution, not of this pure metadata decision. Parent [#17](https://github.com/Marcus-Levin/hylja/issues/17), including audited use-without-reveal acceptance, stays open. [Slice 2](../specs/slice-2-vault-and-reversible-identities.md) remains draft.

## Threats and evidence

Addressed here: bulk/unknown reference probing, forged or model-invented mapping references, cross-tenant and scope-swapped resolution, purpose and principal confusion, operation escalation from `USE` to reveal or export, replay of stale grants, expired/revoked mapping use, credential mappings becoming reversible, a caller-asserted trust label or timestamp becoming authority, and a principal-only identity pair being treated as an authorized workload.

New surfaces introduced: trusted per-call metadata, grant and host-context lookups, revision binding, a host-owned clock and a required workload identity in three records. Each is an input the integration must get right.

How the acceptance tests prove the boundary - and what they do not: [`test/mapping-authorization.test.mjs`](../../test/mapping-authorization.test.mjs) asserts literal decisions for a matching synthetic context and grant, for every one-field swap of request, host, mapping and grant, for the full operation matrix in both directions, for tenant A/B scope permutations including a tenant-B grant against a tenant-A mapping, for each lifecycle and expiry boundary, for a coherent workload-absent request/host/grant on each of `USE`, `DISPLAY` and `EXPORT`, for combined-invalid records that pin the documented check order (a malformed grant outranks a revoked mapping; congruence outranks every later mapping and grant check; an absent grant still reaches its own row), and for malformed and hostile shapes applied to complete otherwise-valid records so each case reaches the validator it names. Two further cases exercise the shared normalizer through its own public export: a complete valid grant round-trips into a structurally identical record whose three nested records are **not** the source objects, editing every one of the caller's own records afterwards leaves that snapshot exactly as normalized, and re-normalizing the result is stable; and thirty-six shapes outside the schema - absent, null, non-object, array, empty, wrong version, each missing mandatory field, a nested record missing or extending a field, an out-of-vocabulary operation, a zero/fractional/unsafe revision or expiry, an oversized or padded reference, an unknown key, a symbol key, a hidden field, an accessor, `ownKeys` / `getOwnPropertyDescriptor` / `getPrototypeOf` traps, an inherited prototype and an over-keyed record - each answer `null` without throwing, with the same shape still denied as `INVALID_CONTEXT` through the seam rather than silently becoming an absent grant. These are synthetic in-process assertions on this function's own choices. They do **not** prove that any protected value was or was not disclosed, that a caller was authenticated, that a real broker or vault enforces this, or that downstream audit and effect handling exists.