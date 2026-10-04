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

The trusted integration - not this module - authenticates the human principal and workload identity, binds the purpose and session, observes the routed destination including redirects, reads the current mapping record, evaluates the grant, and owns the clock. **Required trusted inputs are never constructed from request fields, payload content, model output, wire metadata or a caller-supplied trust label**, and no such label creates authority. A timestamp inside the request is rejected as an unknown field; time comes only from the host clock argument. Provenance of these values is a congruence check between separately supplied records, not proof of authenticity, and is only as trustworthy as the integration that supplies them.

Shapes and bounds are validated once, before any decision: plain data properties only (no getters, no inherited or symbol keys, no unknown keys, no array), bounded string lengths, safe-integer instants and revisions. Every value that is inspected repeatedly is the normalized copy. A malformed record, an oversized field, a throwing accessor or proxy produces a fixed denial; the module never throws and never returns exception text.

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

## Guarantees

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

Addressed here: bulk/unknown reference probing, forged or model-invented mapping references, cross-tenant and scope-swapped resolution, purpose and principal confusion, operation escalation from `USE` to reveal or export, replay of stale grants, expired/revoked mapping use, credential mappings becoming reversible, and a caller-asserted trust label or timestamp becoming authority.

New surfaces introduced: trusted per-call metadata, grant and host-context lookups, revision binding and a host-owned clock. Each is an input the integration must get right.

How the acceptance tests prove the boundary - and what they do not: [`test/mapping-authorization.test.mjs`](../../test/mapping-authorization.test.mjs) asserts literal decisions for a matching synthetic context and grant, for every one-field swap of request, host, mapping and grant, for the full operation matrix in both directions, for tenant A/B scope permutations including a tenant-B grant against a tenant-A mapping, for each lifecycle and expiry boundary, for malformed and hostile shapes, and that the returned decision echoes nothing. Those are synthetic in-process assertions on this function's own choices. They do **not** prove that any protected value was or was not disclosed, that a caller was authenticated, that a real broker or vault enforces this, or that downstream audit and effect handling exists.