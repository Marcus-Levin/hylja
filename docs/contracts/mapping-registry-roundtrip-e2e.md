# Registry-backed synthetic mapping round trip (synthetic, ephemeral)

Status: draft evidence document for issue #188. It documents one **synthetic integration test**,
[`test/mapping-registry-roundtrip.e2e.test.mjs`](../../test/mapping-registry-roundtrip.e2e.test.mjs),
which joins four already-shipped seams over one explicitly ephemeral in-process scenario and changes no
contract, adds no treatment semantics, adopts no proposed decision and claims no production capability.
Implementation status belongs only in [capabilities.md](../capabilities.md); this document checks
nothing off there and leaves parents [#15](https://github.com/Marcus-Levin/hylja/issues/15),
[#17](https://github.com/Marcus-Levin/hylja/issues/17) and
[#18](https://github.com/Marcus-Levin/hylja/issues/18) open.

## What it joins

| Seam | Source | Contract |
| --- | --- | --- |
| Keyed scope-bound reference derivation | [`src/scoped-entity-reference.ts`](../../src/scoped-entity-reference.ts) | [scoped-entity-reference.md](scoped-entity-reference.md) |
| Bounded ephemeral mapping metadata registry (**current-record owner**) | [`src/mapping-metadata-registry.ts`](../../src/mapping-metadata-registry.ts) | [mapping-metadata-registry.md](mapping-metadata-registry.md) |
| Purpose-bound mapping authorization | [`src/mapping-authorization.ts`](../../src/mapping-authorization.ts) | [mapping-authorization.md](mapping-authorization.md) |
| Mapping AEAD seal/open | [`src/mapping-aead.ts`](../../src/mapping-aead.ts) | [mapping-aead.md](mapping-aead.md) |

Each seam keeps its own contract unchanged. The difference from
[#176](mapping-roundtrip-e2e.md) is the record authority: that file's "current record" was an object in
the fixture, which is the design
[mapping-metadata-registry.md](mapping-metadata-registry.md) exists to forbid. Here the shipped
registry owns the current record and the test only reads it - there is no fixture-owned `Map`, no
test-owned revision and no second authority anywhere in the file.

## The scenario is explicitly ephemeral and synthetic

Three in-process tenant scopes, all invented and non-routable: `.invalid` tenant, project, session,
principal, workload, purpose, sink and profile names; fixed byte fills as DEK and HMAC key material;
one fixed synthetic epoch instant; one planted marker string. Two scopes deliberately share the **same
original, entity id, DEK, HMAC key and key version**, so every difference observed between them is
attributable to the tenant scope alone. The DEK, the HMAC key, the grants, the clock and every
ciphertext are ephemeral: they live only for the test process and are never persisted, serialized
into a snapshot or sent anywhere.

The scenario object holds the sealed record, the host-held key material, the entity id and the opaque
`her1:` reference. It holds no original value and no plaintext, so the only value it can ever release
is what `openMappingPayload` decrypts from the ciphertext it stores. **Authentication, key provision,
grants, the clock and the registry itself are test fixtures, not mechanisms**: the DEK and HMAC key
are literal byte arrays, the authenticated subject and the grant are literal records, the clock is a
literal instant, and the registry is a real shipped in-process map with no durability, no
authentication and no transaction.

## What the test verifies

1. **DISPLAY round-trip exactness.** The release path makes one fresh `current` read, pins `DISPLAY`
   *after* caller options are applied, and permits one real `openMappingPayload` call only on an
   actual `AUTHORIZED` decision from the real seam. The restored bytes are compared against an
   independent literal by a trusted test-local inspector that returns one boolean, and the counted
   opener is called exactly once. With no grant the seam denies `NO_GRANT` and the opener is called
   **zero** times.
2. **USE does not imply DISPLAY or EXPORT.** A `USE` grant authorizes `USE`, denies `DISPLAY` and
   `EXPORT` with `OPERATION_NOT_GRANTED`, and resolves nothing; a `DISPLAY` grant cannot be spent as a
   `USE`; and an `EXPORT` grant handed to the DISPLAY path is refused even when the caller names
   `EXPORT`, because the path fixes its own operation. Positive controls on the same record show the
   refusals are not vacuous.
3. **One revision authority, compare-and-set.** Two real registry transitions pinned to the same
   literal revision apply exactly one; the loser is `STALE_REVISION` and a fresh read still shows the
   winner's record, with creation, expiry, scope and reference carried through untouched.
4. **Revocation denies a coherent cached triple.** A cached `ACTIVE` snapshot, the grant that matches
   it and the untouched ciphertext are captured while the record is live, then presented together
   after a real registry revocation: the release is refused before opening, and the counted opener is
   still at exactly the value it had before the revocation. With no cached snapshot the registry's own
   read refuses first
   (`NOT_LIVE`), and the registry's own record for the tombstone is read back through a real
   idempotent terminal command, because `current` never returns a tombstone. The attribution is stated
   in the test: the pure authorization seam trusts the snapshot the host hands it, so on its own it
   does authorize that stale triple.
5. **Positive fault control.** A deliberately incomplete test-local host that primes one cache and
   never reads the registry again **does** release the revoked mapping at the same instant the correct
   host withholds. That is the fault this file exists to catch, kept in-test so the refusal above is
   provably non-vacuous.
6. **The registry's own expiry and clock rollback deny.** The first observation at or after
   `expiresAt` latches the expiry, the read answers `NOT_LIVE`, the release withholds without any
   further opener call, the latched `EXPIRED` record and its revision come back through a real command,
   reactivation is `INVALID_TRANSITION`, and a clock that moves backwards afterwards is
   `CLOCK_ROLLBACK` on both the read and the release path.
7. **Unknown and foreign scope refuse before opening.** A reference the registry never held and a
   foreign scope inside the same registry are both `UNKNOWN_MAPPING`, and neither a release nor a USE
   attempt makes an opener call. When the current record is supplied with a coherent foreign-scope host
   context, the authorization seam itself answers `SCOPE_MISMATCH`.
8. **Controlled same-original, same-entity, same-key scope contrast.** Both records are brought to the
   same literal current and sealed revision before the cross-tenant open, so only the tenant can
   explain the refusal: the cross open is `AUTHENTICATION_FAILED` with no plaintext, and each record
   then still releases the same literal under its own scope.
9. **Old envelope versus current revision.** An envelope sealed at the creation revision still opens
   cryptographically under its own old AAD - that fact is isolated and asserted directly - but under
   the fresh record's revision an actually `AUTHORIZED` DISPLAY release is withheld
   `AUTHENTICATION_FAILED` with zero plaintext. After the controlled host re-seal, which draws a fresh
   asserted-different nonce from the shipped primitive, the current envelope releases the literal.
10. **Ciphertext-only metadata.** The registry returns metadata under one fixed key set, the scenario
    object exposes no plaintext, original or ciphertext property, the sealed record carries no key or
    scope, and the one serializable image contains no planted marker. Every assertion compares fixed
    codes, booleans, counts and lengths; no assertion receives a crypto result, a byte buffer or a
    plaintext operand, so a failure prints enums and numbers only.

## Limits

- **Not a broker or a store.** The release path is a local orchestrator of four shipped seams, not a
  deployed broker: no Policy Engine call, no audit ledger, no rate limit, no retry, no concurrency
  control and no transactional write.
- **Still no claim beyond the in-process registry.** The registry is real and owns the current record,
  but it is process-local and memory-only. Nothing here proves persistence across a restart, a row
  lock, multi-process atomicity, restore, backup or key destruction.
- **Not an enforcement boundary.** The test proves these four seams compose over one synthetic
  scenario without releasing a planted value on a denied path. It authenticates nobody and is not a
  protected-egress safety claim under
  [decision 007](../decisions/007-fail-closed-for-protected-egress.md).
- **The currency check is host-side test logic.** Refusing a superseded cached snapshot is the trusted
  store or broker's duty; here the host is this test file. No runtime API changed to provide it, and
  the pure seam still authorizes a stale triple handed to it, which the test asserts rather than
  hides.
- **Not acceptance.** Parents [#15](https://github.com/Marcus-Levin/hylja/issues/15),
  [#16](https://github.com/Marcus-Levin/hylja/issues/16),
  [#17](https://github.com/Marcus-Levin/hylja/issues/17) and
  [#18](https://github.com/Marcus-Levin/hylja/issues/18) remain open; audited use-without-reveal
  acceptance is unmet; [Slice 2](../specs/slice-2-vault-and-reversible-identities.md) remains a
  draft. [Decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) is
  proposed and is neither adopted nor exercised here.
- **Not a vault, KMS/HSM, index or transport.** No persistence, no equality search, no recovery, no
  external send, no network of any kind, no comparative or held-out evidence.

## Running it

```text
npm run --silent build && node --test test/mapping-registry-roundtrip.e2e.test.mjs
```

The full CI sequence, including the fixture guard and the shared suite, runs at the pinned head in CI;
this document quotes only the focused runs recorded for this change.