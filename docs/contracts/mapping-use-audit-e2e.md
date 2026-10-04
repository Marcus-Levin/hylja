# Audited USE of a scoped encrypted mapping (synthetic, ephemeral)

Status: draft evidence document for issue #197. It documents one **synthetic integration test**,
[`test/mapping-use-audit.e2e.test.mjs`](../../test/mapping-use-audit.e2e.test.mjs), which joins five
already-shipped seams over one explicitly ephemeral in-process scenario and changes no contract, adds
no treatment semantics, adopts no proposed decision and claims no production capability. No runtime
source changed: this is a test and this document. Implementation status belongs only in
[capabilities.md](../capabilities.md); this document checks nothing off there and leaves
[Slice 2](../specs/slice-2-vault-and-reversible-identities.md) a draft and its parents
[#15](https://github.com/Marcus-Levin/hylja/issues/15),
[#16](https://github.com/Marcus-Levin/hylja/issues/16),
[#17](https://github.com/Marcus-Levin/hylja/issues/17) and
[#18](https://github.com/Marcus-Levin/hylja/issues/18) open.

## What it joins

| Seam | Source | Contract |
| --- | --- | --- |
| Keyed scope-bound reference derivation | [`src/scoped-entity-reference.ts`](../../src/scoped-entity-reference.ts) | [scoped-entity-reference.md](scoped-entity-reference.md) |
| Bounded ephemeral mapping metadata registry (**current-record owner**) | [`src/mapping-metadata-registry.ts`](../../src/mapping-metadata-registry.ts) | [mapping-metadata-registry.md](mapping-metadata-registry.md) |
| Purpose-bound mapping authorization | [`src/mapping-authorization.ts`](../../src/mapping-authorization.ts) | [mapping-authorization.md](mapping-authorization.md) |
| Source-to-sink policy decision | [`src/policy.ts`](../../src/policy.ts) | [policy-contract.md](policy-contract.md) |
| Privacy-safe audit append, availability gate and chain verification | [`src/audit-ledger.ts`](../../src/audit-ledger.ts) | [audit-ledger-contract.md](audit-ledger-contract.md) |
| Mapping AEAD seal/open | [`src/mapping-aead.ts`](../../src/mapping-aead.ts) | [mapping-aead.md](mapping-aead.md) |

Each seam keeps its own contract unchanged. The difference from
[#188](mapping-registry-roundtrip-e2e.md) is the tail: that file ends at a DISPLAY release, while this
one adds a real `decidePolicy` decision, a real `appendAuditEvent` whose own result
`gateHighRiskEffect` must permit, a second registry currency read **after** the audit, and a resource
effect whose success is decided by an independently provisioned backend rather than by the open call.
The registry is still the record authority: there is no fixture-owned current record, no test-owned
revision and no second authority anywhere in the file.

## The ordered gate path

`useMapping` is the trusted host path under test, and its order is the contract it pins:

1. a fresh registry `current` read, before anything else is decided;
2. an actual `AUTHORIZED` decision from the real authorization seam for exactly the requested
   operation, on an explicitly supplied grant;
3. an actual `SELECTED` + `KEEP` decision from the real Policy Engine for `USE`, over a pinned
   bundle whose content digest is carried into the boundary;
4. real `appendAuditEvent` calls for the authorization attempt and the policy decision, each one
   gated by `gateHighRiskEffect` on the result `appendAuditEvent` itself returned in the same
   process;
5. a **second** fresh registry currency read, after the audit and before any effect;
6. the real `openMappingPayload` call at that confirmed revision;
7. the real resource lookup, whose success depends on the recovered identifier.

Withhold at any gate and the counted opener and the counted effect both stay where they were. The
path never reports `USED` without one real opener call and one real backend lookup.

## The scenario is explicitly ephemeral and synthetic

Every input is an invented, non-routable literal: `.invalid` tenant, project, session, principal,
workload, purpose, sink, profile, integration and detector names; fixed byte fills as DEK, HMAC and
audit key material; one fixed synthetic epoch instant; one planted marker string; one synthetic
resource handle. Two tenant scopes are used, and a second scope is deliberately refused by the
registry so a foreign scope cannot reach the record.

**Explicitly trusted fixtures, none of them a mechanism:** the host workload identity, the
destination and its profile, the classification evidence, the policy bundle, the audit bundle
identity, every grant, the audit sink's `accepting` flag, the DEK and HMAC key, the audit pseudonym
and chain keys, the clock and the resource backend are all literal test fixtures. There is **no real
authentication**, **no durable audit** (the ledger is the shipped in-memory substrate), **no key
management or KMS/HSM**, **no network effect**, **no production broker**, and **no secret or
production mapping data** anywhere in the file.

## The honest boundary: ciphertext-only mapping, one trusted resource

The mapping is ciphertext-only, end to end. The registry record carries one fixed metadata key set,
the scenario object exposes no plaintext, original or ciphertext property, the sealed record carries
no key or scope, and every recorded event, receipt, checkpoint and serialized entry is checked for
the planted marker.

The single cleartext instance is the synthetic resource backend, and it is **separately provisioned
out of band** with the handle its own resource owns. That is the boundary stated rather than hidden: a
real resource system legitimately knows the identifier of its own record, and this file supplies that
trusted resource as a literal fixture rather than pretending the identifier is unknowable. The backend
compares the recovered bytes **inside its own closure** and returns only a status code, a boolean and
a byte count, so the identifier is never returned to this file, logged, asserted, captured as an
audit field or shown to any caller. No bulk mapping lookup API is created and no original is mapped
to a caller anywhere in the file.

## What the test verifies

1. **The accepted USE effect.** A `USED` outcome is returned only after one real opener call and one
   real backend lookup, against a backend provisioned with an independent literal handle, with the
   outcome's key set fixed. The actual shipped audit chain is verified with the scope-bound fixture
   keys against an independently minted checkpoint (`VERIFIED_TO_ANCHOR`, both entries anchored), and
   the same stream with no checkpoint is honestly `UNANCHORED`. The recorded entries are exactly two
   `ALLOWED` decisions - `AUTHORIZATION_ATTEMPT/USE/RESOLUTION_AUTHORIZED` and
   `POLICY_DECISION/USE/POLICY_ALLOWED` - and the serialized evidence contains neither the planted
   original, nor the mapping reference, nor the resource outcome.
2. **USE does not imply DISPLAY or EXPORT.** A `USE` grant spent as `DISPLAY` or `EXPORT` is
   `OPERATION_NOT_GRANTED` with no opener call and no effect, a `DISPLAY` grant cannot be spent as a
   `USE`, and each refusal is evidenced as a denial event with its own operation. A positive control
   on the same record keeps the refusals non-vacuous.
3. **Missing, foreign, stale and misbound grants.** No grant, a grant for another mapping reference,
   a grant pinned to a superseded revision, a grant issued to another workload, a grant bound to
   another purpose or another destination, and an already-expired grant each withhold with their own
   fixed reason and zero opener and effect calls. A foreign tenant scope is the registry's own
   `UNKNOWN_MAPPING`, and a foreign workload is refused even against a coherent-looking grant.
4. **Revoked and expired registry records.** A revocation applied through the registry's own
   transition at its own expected revision makes the next attempt `NOT_LIVE`, the tombstone record
   read back through a real idempotent command is refused by the authorization seam itself
   (`MAPPING_REVOKED`), and the registry's own expiry refuses the record at its expiry instant. The
   positive control precedes both.
5. **A real `BLOCK` or `HELD` policy decision.** Over bundles that differ only in the one rule's
   decision, the real Policy Engine answers `DENIED` and `HELD`; both withhold before any audit
   allow-event, before any opener call and before any effect, and each is evidenced by exactly one
   denial event with no `ALLOWED` and no `APPLIED` entry in that stream.
6. **Unaccepted or malformed audit evidence.** A real sink that cannot commit produces the shipped
   `AUDIT_UNAVAILABLE`, which the shipped gate turns into `EVIDENCE_UNAVAILABLE` and never into
   `permitted`; a `RECORDED` claim with no receipt and a value that is not an append result both
   produce `EVIDENCE_INVALID`. In every case the opener and effect counters stay at zero and the
   stream records nothing. The accepting sink on the identical scenario opens and spends once.
7. **Currency after the audit.** A genuine `REVOKE` injected at exactly the point between the audit
   and the second currency read is refused with zero opener and effect calls, while the audit trail
   stays honest: two `ALLOWED` decisions, verified to an anchor, and no event claiming an execution.
   The **positive fault control** then runs the deliberately incomplete host - identical steps with
   only that second read removed - which does open the revoked mapping and does perform the effect at
   the same instant. That is the fault this file forbids, kept in-test so the refusal is loadbearing.
8. **Resource success depends on the identifier.** With a backend provisioned for a handle the
   resource does not own, the opener really runs, the ciphertext really decrypts, and the effect still
   does not succeed; the correctly provisioned backend succeeds on the same ciphertext. A mapping whose
   ciphertext still belongs to a superseded revision is refused by the AEAD itself, so no lookup is
   ever attempted with bytes that did not authenticate.
9. **Scope isolation and ciphertext-only state.** Another tenant's authority reads nothing from this
   stream (`SCOPE_MISMATCH`, no entries at all) and the stream does not verify under a foreign trusted
   context. The registry key set, the scenario object's key set, the sealed record's key set and one
   serializable image are all asserted to be free of the original.

### Mutants that make the denial tests load-bearing

Each of these was applied to a throwaway copy of the test and reverted; each turns exactly its own
test red and leaves the other eight green:

| Mutant | Test that catches it |
| --- | --- |
| Post-audit currency read removed | 7, revocation between audit and effect |
| `gateHighRiskEffect` result ignored | 6, unaccepted or malformed audit evidence |
| Opener call treated as success regardless of the backend match | 8, identifier-dependent resource success |
| Policy decision skipped | 5, real `BLOCK` / `HELD` |

## Limits

- **Not a broker, a store or a vault.** The path is a local orchestrator of six shipped seams: no
  transaction, no row lock, no concurrency control, no rate limit, no retry, no KMS/HSM binding, no
  index, no recovery and no transport.
- **Not an enforcement boundary.** The test proves these seams compose over one synthetic scenario
  without opening ciphertext, spending a resource or recording an effect on a denied path. It
  authenticates nobody and is not a protected-egress safety claim under
  [decision 007](../decisions/007-fail-closed-for-protected-egress.md).
- **The gate path and the currency recheck are test-local host logic.** Standing between a stored
  ciphertext and an effect is the broker's duty; here the broker is this file. No runtime API changed
  to provide it, and the pure seams still authorize or permit the stale triple handed to them, which
  the test asserts rather than hides. In particular `gateHighRiskEffect` is a pure structural check:
  a caller able to pass it an invented `RECORDED` result satisfies the precondition, which is why the
  path passes the result `appendAuditEvent` returned in the same process.
- **The resource backend is a fixture, not a resource system.** It models one trusted local lookup
  that knows its own identifier. It proves nothing about identity federation, account resolution,
  a real datastore or a real service, and it deliberately has no cross-resource or bulk lookup.
- **Not acceptance.** Audited use-without-reveal acceptance is not met by this document;
  [Slice 2](../specs/slice-2-vault-and-reversible-identities.md) remains a draft and its parents
  stay open. [Decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md)
  is **proposed**: comparative custody and scoring are not adopted, not implemented and not exercised
  here.
- **No comparative, held-out or production evidence.** No network of any kind, no provider traffic, no
  credentials, no real authentication, no durable audit and no production data of any kind.

## Running it

```text
npm run --silent build && node --test test/mapping-use-audit.e2e.test.mjs
```

The full CI sequence, including the fixture guard and the shared suite, runs at the pinned head in CI;
this document quotes only the focused runs recorded for this change.