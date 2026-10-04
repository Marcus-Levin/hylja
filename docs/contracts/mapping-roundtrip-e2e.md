# Mapping round-trip integration evidence (synthetic, ephemeral)

Status: draft evidence document for issue #176. It documents one **synthetic integration test**,
[`test/mapping-roundtrip.e2e.test.mjs`](../../test/mapping-roundtrip.e2e.test.mjs), which joins four
already-shipped, accepted-v1 seams over one explicitly ephemeral in-process fixture. It changes no
contract, adds no treatment semantics, adopts no proposed decision, and claims no production
capability. Implementation status belongs only in [capabilities.md](../capabilities.md); this document
checks nothing off there and leaves parent [#15](https://github.com/Marcus-Levin/hylja/issues/15) open.

## What it joins

| Seam | Source | Contract |
| --- | --- | --- |
| Mapping AEAD seal/open | [`src/mapping-aead.ts`](../../src/mapping-aead.ts) | [mapping-aead.md](mapping-aead.md) |
| Keyed scope-bound reference derivation | [`src/scoped-entity-reference.ts`](../../src/scoped-entity-reference.ts) | [scoped-entity-reference.md](scoped-entity-reference.md) |
| Mapping lifecycle reducer | [`src/mapping-lifecycle.ts`](../../src/mapping-lifecycle.ts) | [mapping-lifecycle.md](mapping-lifecycle.md) |
| Purpose-bound mapping authorization | [`src/mapping-authorization.ts`](../../src/mapping-authorization.ts) | [mapping-authorization.md](mapping-authorization.md) |

Each seam keeps its own contract unchanged. The integration supplies the *context* they were written
without - a host-held current record, an authenticated workload, an explicit grant and a clock - and
none of them authorizes anything by itself.

## The fixture is explicitly ephemeral and synthetic

Three in-process tenant fixtures, all values invented and non-routable: `*.invalid` tenant, project,
session, principal, workload, purpose, sink and profile names; fixed byte fills as DEK and HMAC key
material; one fixed synthetic epoch instant; one planted literal marker string. The fixtures live only
for the duration of the test process, are never written to disk, never serialized to a snapshot and
never sent anywhere.

A fixture holds **AEAD ciphertext plus non-secret metadata only**: `{version, nonce, ciphertext, tag}`
from `sealMappingPayload`, the opaque `her1:` reference, the tenant/project/session scope, the current
lifecycle state and revision, and the expiry instant. It holds no original value, no plaintext buffer,
no store, no index, no blind-index equality lookup and no reversible credential alias. After
construction, the only copy of the synthetic original anywhere in the process is the independent
literal constant in the test file.

**Authentication, key provision, clock and current-record authority are test fixtures, not
mechanisms.** The DEK and HMAC key are literal byte arrays in the test, the authenticated subject is a
literal record, the grant is a literal record and the clock is a literal instant. Nothing here
authenticates a principal, verifies a proof, wraps or rotates a key, reads a real store, observes a
real destination or survives the test process. The "current record" is an object in the test process
that the reducer commits to; it is not a database row, a transaction or a compare-and-set.

`openMappingPayload` overwrites the sealed-record buffers it is handed on every exit, so the test
copies the envelope for each open attempt. That is a harness detail of an ephemeral fixture, not
persistence, retention or durability.

## What the test verifies

1. **DISPLAY round-trip exactness.** With no grant the seam denies `NO_GRANT` and nothing is opened.
   After an actual `AUTHORIZED` DISPLAY decision from `authorizeMappingOperation`, one
   `openMappingPayload` call under the independently supplied expected scope returns bytes that equal
   an independent literal expected outcome, compared byte for byte.
2. **Ciphertext-only fixture image.** The serialized fixture never contains the planted marker. The
   assertion is a marker search, never a ciphertext-versus-plaintext inequality: a valid AES-256-GCM
   ciphertext may equal its plaintext byte for byte, so that inequality is not a property of any AEAD
   and is not relied on anywhere here.
3. **USE does not imply DISPLAY or EXPORT.** A `USE` grant authorizes `USE` and denies `DISPLAY` and
   `EXPORT` with `OPERATION_NOT_GRANTED`; a `DISPLAY` request under that grant withholds any release.
   The trusted test-local USE callback returns only the fixed non-secret outcome `USED`, and the model
   capture holds only that outcome and the opaque reference, never an original or a byte of one.
4. **Scope-bound references.** The same synthetic original in two tenants yields two distinct opaque
   `her1:` references from the existing keyed derivation. A foreign reference, tenant, session or
   subject denies at the seam (`UNKNOWN_MAPPING`, `SCOPE_MISMATCH`), a foreign observed destination
   denies at the grant's own destination binding (`GRANT_MISMATCH`), and tenant B's ciphertext opened
   under tenant A's expected scope and key is one indistinguishable `AUTHENTICATION_FAILED` with no
   plaintext field.
5. **Zero plaintext on crypto failure.** Wrong key, wrong classification, wrong revision, wrong key
   version, foreign entity, tampered ciphertext and tampered tag each return the fixed refusal with no
   `plaintext` and no `bytes` field, and no planted marker in the serialized refusal. A control case
   opens the untouched record, so the refusals are not vacuous.
6. **Lifecycle commits to the current revision.** Activation commits a monotonic increment through the
   real reducer; creation, expiry, scope and reference are unchanged by the transition. A stale
   `expectedRevision` is `STALE_REVISION` and never mutates the current record, a grant pinned to a
   superseded revision denies even against a record the host reads now, a cached snapshot of the
   record cannot authorize a grant pinned to the current revision, and `ACTIVATE` on an `ACTIVE`
   record is `INVALID_TRANSITION`.
7. **Expiry, revocation and deletion cannot resolve.** `EXPIRED` denies `MAPPING_EXPIRED`, `REVOKED`
   and `DELETED` deny `MAPPING_REVOKED`, reactivation of an expired record is `INVALID_TRANSITION`, a
   repeated terminal command is idempotent (`UNCHANGED`, same revision) and an expired grant on a live
   fixture denies `GRANT_EXPIRED` while a live grant on the same fixture still releases the literal.

Every assertion compares fixed codes, states, booleans, lengths, tokens and byte arrays. A failure
prints a code or a length, never a key byte, a plaintext byte or a native error.

## Limits

- **Not a broker.** The release helper in the test is a local orchestrator of the four shipped seams,
  not a deployed broker. It has no Policy Engine call, no audit ledger, no rate limit, no retry, no
  concurrency control and no transactional write.
- **No compare-and-set or race safety.** `expectedRevision` is compared against the one record the
  test process holds. There is no row lock, no transaction, no rollback detection and no claim about
  distributed races or concurrent writers.
- **Not fresh by itself.** A valid old envelope still authenticates under a matching scope. Currency,
  lifecycle and authority come from the trusted host record and the explicit grant, and here that host
  is the test process itself.
- **Not a vault, store, index or transport.** No persistence, no lookup, no equality search, no
  recovery, no backup, no external send, no network of any kind.
- **Not an enforcement boundary.** The test proves that these four seams compose without leaking a
  planted synthetic value across a denied path. It does not prove that a production vault or broker
  exists, and it is not a protected-egress safety claim under
  [decision 007](../decisions/007-fail-closed-for-protected-egress.md).
- **Not acceptance.** Parent [#15](https://github.com/Marcus-Levin/hylja/issues/15),
  [#16](https://github.com/Marcus-Levin/hylja/issues/16) and
  [#17](https://github.com/Marcus-Levin/hylja/issues/17) remain open, audited use-without-reveal
  acceptance is unmet, and [Slice 2](../specs/slice-2-vault-and-reversible-identities.md) remains a
  draft. [Decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) is
  proposed and is neither adopted nor exercised here.

## Running it

```text
npm run --silent build && node --test test/mapping-roundtrip.e2e.test.mjs
```

The full CI sequence, including the fixture guard and the shared suite, runs at the pinned head in CI;
this document quotes only the focused run recorded for this change.