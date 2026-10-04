# Audited USE of a scoped encrypted mapping (synthetic, ephemeral)

Status: draft evidence document for [#197](https://github.com/Marcus-Levin/hylja/issues/197). It describes one **synthetic
integration test**, [`test/mapping-use-audit.e2e.test.mjs`](../../test/mapping-use-audit.e2e.test.mjs): nine cases over
one explicitly ephemeral in-process scenario with synthetic fixtures, joining six already-shipped seams with no contract
change, no added treatment semantics, no adopted proposal and no runtime source change. Implementation status belongs only
in [capabilities.md](../capabilities.md); the test file is the authoritative record of every assertion.

## Seams

Joining [deriveScopedEntityReference](../../src/scoped-entity-reference.ts) ([contract](scoped-entity-reference.md)),
[createMappingMetadataRegistry](../../src/mapping-metadata-registry.ts) ([contract](mapping-metadata-registry.md), the
current-record owner), [authorizeMappingOperation](../../src/mapping-authorization.ts) ([contract](mapping-authorization.md)),
[decidePolicy](../../src/policy.ts) ([contract](policy-contract.md)), [appendAuditEvent](../../src/audit-ledger.ts) with
`gateHighRiskEffect` ([contract](audit-ledger-contract.md)) and [sealMappingPayload](../../src/mapping-aead.ts)
([contract](mapping-aead.md)). No fixture-owned current record and no test-owned revision. Unlike
[#188](mapping-registry-roundtrip-e2e.md), which ends at a DISPLAY release, the tail here adds a real policy decision, an
audited append whose own result the gate must permit, a second currency read after the audit, and an effect decided by an
independently provisioned backend rather than by the open call.

## The ordered path

`useMapping` is the test host's USE path; this order is what the cases pin. Two counters - real `openMappingPayload`
calls and real backend lookups - show a refused path making neither, and `USED` returns only after both, once each.

0. **Operation.** This host performs USE only, so a request for DISPLAY or EXPORT is refused before any registry read,
   authorization, policy decision, opener call or effect, as the host's own `OPERATION_NOT_SUPPORTED`, with one denied
   `AUTHORIZATION_ATTEMPT` under that operation; a matching grant buys nothing and is never reported as missing.
1. **Fresh registry currency**, read before anything else is decided.
2. **Actual authorization**: a real `AUTHORIZED` decision from the authorization seam for USE, on the caller's supplied
   grant, including an explicit absence of one.
3. **Actual policy**: a real `SELECTED` and `KEEP` decision from the Policy Engine for USE, over a pinned bundle whose
   content digest is carried into the boundary.
4. **Real audit, then the real gate**: `appendAuditEvent` for the authorization attempt and for the policy decision,
   each gated by `gateHighRiskEffect` on the result `appendAuditEvent` returned in-process.
5. **Currency rechecked** after the audit and before any effect, so a revocation landing in that window cannot be spent
   on the pre-audit snapshot.
6. **Real AEAD open** at that confirmed revision.
7. **Real resource effect**: the backend's own lookup, whose success depends on the recovered identifier.

## Fixtures, and the exact reach of the privacy assertions

Every input is an invented, non-routable literal: `.invalid` names, fixed DEK, HMAC and audit key fills, one fixed epoch
instant, one planted marker string, one synthetic handle. **Explicitly trusted fixtures, none of them a mechanism**:
workload identity, destination, classification evidence, policy bundle, audit bundle identity, grants, the sink's
`accepting` flag, the audit pseudonym and chain keys, the clock and the resource backend. There is **no real
authentication**, **no durable audit**, **no KMS/HSM**, **no network effect**, **no production broker**, and no real or
production data.

Ciphertext-only is scoped to the mapping: the registry record, the scenario object and the AEAD envelope hold ciphertext
and non-secret metadata, and the scenario object's complete key set is asserted. Two things are deliberately not
ciphertext-only and are not claimed to be - the source literal planted original is a legitimate fixture input, and the
resource backend is separately provisioned out of band with the cleartext handle its own resource owns, as a real
resource system legitimately does. No assertion operand, logged field or audit field receives the raw original, a key or
the recovered identifier: the backend compares the recovered bytes inside its own closure and returns only a status code,
a boolean and a byte count. Plaintext exists transiently in the opener's result and is overwritten in-process on a
best-effort basis, which is hygiene, not zeroization. **Not** every serialized image is checked for mapping-reference
absence: the scenario image deliberately contains the opaque mapping reference and is checked only for the marker and the
original, while the reference-absence checks are the narrower audit-side ones - the serialized entries, the minted
checkpoint and the append receipt.

## Verification

```text
npm run build && node --test test/mapping-use-audit.e2e.test.mjs test/mapping-registry-roundtrip.e2e.test.mjs
```

Nine cases here and ten in the round-trip file: **19/19 passed, 0 failures, 0 skips** at head
`51bf26988cb86c758711396a902730f89c7d7c12`, repeated by the second independent review at that head. It is a focused pair
over built `dist/` outputs, not the whole suite; no full-suite, coverage, install, provider or network run is claimed.
The link check is `npm run check:docs`.

## Limits

- **Not a broker, store or vault.** Six shipped seams composed locally: no transaction, lock, retry, rate limit, index,
  recovery, transport or KMS binding.
- **The gate path and the currency recheck are test-local host logic.** Standing between a stored ciphertext and an effect is
  a broker's duty; here the broker is the test file, and the pure seams still authorize or permit the stale triple handed
  to them. `gateHighRiskEffect` is a pure structural check, which is why the path gates the `appendAuditEvent` result.
- **Not an enforcement boundary.** It authenticates nobody and sends no bytes; it is not a protected-egress safety
  claim under [decision 007](../decisions/007-fail-closed-for-protected-egress.md). There is no comparative, held-out or
  production evidence here: no network, provider traffic, credentials, real authentication, durable audit or real data.
- **The resource backend is a fixture**, not a resource system: nothing here proves identity federation, account
  resolution, a datastore or a service, and it has no cross-resource or bulk lookup.
- **Operation separation is covered only in the directions each file exercises.** A DISPLAY grant spent as USE, and a USE
  grant asked for another operation, are refused here; the round-trip file pins the direct-core `OPERATION_NOT_GRANTED`
  cases for its own paths. No case in either file spends an EXPORT grant as a USE.
- **Not acceptance.** [Slice 2](../specs/slice-2-vault-and-reversible-identities.md) stays a draft, its parent issues stay
  open, and [decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) is **proposed**:
  comparative custody and scoring are not adopted, not implemented and not exercised here.
