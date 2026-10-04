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

Seven in-process tenant fixtures, all values invented and non-routable: `*.invalid` tenant, project,
session, principal, workload, purpose, sink and profile names; fixed byte fills as DEK and HMAC key
material; one fixed synthetic epoch instant; one planted literal marker string. The fixtures live only
for the duration of the test process, are never written to disk, never serialized to a snapshot and
never sent anywhere. Two of them (`alpha` and `alpha-alt`) deliberately share the **same original,
the same entity id, the same DEK, the same HMAC key and the same key version**, so that every
difference observed between them is attributable to the tenant scope alone.

A fixture holds **AEAD ciphertext plus non-secret metadata only**: `{version, nonce, ciphertext, tag}`
from `sealMappingPayload`, the opaque `her1:` reference, the tenant/project/session scope, the current
lifecycle state and revision, and the expiry instant. It holds no original value, no plaintext buffer,
no store, no index, no blind-index equality lookup and no reversible credential alias. The claim proved
here is scoped to what the fixture *holds and emits*: no fixture property and no serialized fixture
image contains the original. It is **not** a process-wide memory claim - nothing here inspects or
guarantees the absence of copies inside the JavaScript heap, garbage-collected buffers, native crypto or
swapped pages.

**Authentication, key provision, clock and current-record authority are test fixtures, not
mechanisms.** The DEK and HMAC key are literal byte arrays in the test, the authenticated subject is a
literal record, the grant is a literal record and the clock is a literal instant. Nothing here
authenticates a principal, verifies a proof, wraps or rotates a key, reads a real store, observes a
real destination or survives the test process. The "current record" is an object in the test process
that the reducer commits to; it is not a database row, a transaction or a compare-and-set.

Three gates stand between a fixture and a plaintext on the DISPLAY path, in this order: the mapping
snapshot presented to the seam must still be the fixture's authoritative current record, the operation
is pinned to `DISPLAY` *after* caller options are applied, and only an actual `AUTHORIZED` decision
from the real seam permits one real `openMappingPayload` call. The second gate is why a caller cannot
substitute its own operation: the release helper never reads an operation from its options.

**One revision authority.** Each fixture holds a single authoritative current record, and the expected
AAD revision, the authorization metadata and the grant revision are all read from it. Nothing caches a
frozen copy of the revision at seal time, and a revision embedded in an envelope is never read back as
authority: the expected scope is recomputed from the current record on every open. A fixture's stored
ciphertext is therefore sealed under whatever revision was current when it was sealed, which for the
reserved `foxtrot` fixture starts at the creation revision `'1'`. Where a test needs the stored
ciphertext to describe the current record, the trusted host re-seals the value under the current
revision; that re-seal draws a fresh synthetic nonce from the shipped primitive on every call and the
test asserts the nonce is not reused. This is **controlled synthetic host setup, not a lifecycle
rotation, rewrap, key rotation or store**: the reducer rotates nothing, the same DEK is deliberately
reused so that only the revision differs, and nothing here writes, persists or migrates a record.

**Caller buffers and primitive hygiene.** The accepted AEAD contract is explicit that
`openMappingPayload` never overwrites a buffer the caller supplied and never overwrites the plaintext
it returns; it clears only the owned snapshots it took of the key and the envelope, and that hygiene is
best effort in JavaScript, not a zeroization guarantee for copies held inside native crypto,
garbage-collected buffers or swapped pages. The test clones the envelope for each open attempt so that
repeated attempts over one fixture do not share buffers: that is harness convenience for reuse, not
retention, persistence or durability, and it is not a claim that the primitive mutates caller memory.
On the release path the restored bytes are handed to a trusted test-local inspector that returns one
boolean and are then overwritten by the release helper, so they do not outlive the inspection. That
overwrite is best-effort hygiene in JavaScript, not a zeroization guarantee for any other copy.

**Assertions never receive a crypto object.** No assertion in the test receives a crypto result, a byte
buffer, or a plaintext-versus-null operand. Every AEAD result is read through one fixed-field
projection that returns enum strings, numbers and internally computed booleans only, byte equality is
decided inside a local helper and asserted as one boolean, and the release path returns only `outcome`,
`code`, `released`, `matched` and `bytes` - there is no field on that record a buffer could enter. A
separate check walks a value graph and reports one boolean on whether it holds a byte buffer or the
planted marker; it fails closed on anything unreadable, symbol-keyed or deeper than its own bound, and
it is exercised both against a graph that holds the bytes and against a caught assertion built from the
projection, so the projection's own safety is asserted rather than assumed.

## What the test verifies

1. **DISPLAY round-trip exactness.** With no grant the seam denies `NO_GRANT` and nothing is opened.
   After an actual `AUTHORIZED` DISPLAY decision from `authorizeMappingOperation`, one
   `openMappingPayload` call under the expected scope recomputed from the current record restores bytes
   that equal an independent literal expected outcome, compared byte for byte.
2. **Ciphertext-only fixture image.** The serialized fixture never contains the planted marker. The
   assertion is a marker search, never a ciphertext-versus-plaintext inequality: a valid AES-256-GCM
   ciphertext may equal its plaintext byte for byte, so that inequality is not a property of any AEAD
   and is not relied on anywhere here.
3. **USE does not imply DISPLAY or EXPORT.** A `USE` grant authorizes `USE` and denies `DISPLAY` and
   `EXPORT` with `OPERATION_NOT_GRANTED`; a `DISPLAY` request under that grant withholds any release.
   The trusted test-local USE callback returns only the fixed non-secret outcome `USED`, and the model
   capture holds only that outcome and the opaque reference, never an original or a byte of one.
4. **The operation is pinned per path.** The release path pins `DISPLAY` and the USE path pins `USE`
   *after* caller options are applied, so no option can substitute an operation. A `USE` grant asked
   for as `USE` or `EXPORT` on the DISPLAY path is denied `OPERATION_NOT_GRANTED` with no open, and a
   `DISPLAY` grant cannot be spent as a `USE`. Positive controls on the same fixture show the USE grant
   authorizing `USE` and the DISPLAY grant authorizing exactly one DISPLAY release, so the refusals are
   not vacuous.
5. **Scope-bound references.** The same synthetic original in two tenants yields two distinct opaque
   `her1:` references from the existing keyed derivation. A foreign reference, tenant, session or
   subject denies at the seam (`UNKNOWN_MAPPING`, `SCOPE_MISMATCH`), a foreign observed destination
   denies at the grant's own destination binding (`GRANT_MISMATCH`), and tenant B's ciphertext opened
   under tenant A's expected scope and key is one indistinguishable `AUTHENTICATION_FAILED` with no
   plaintext field.
6. **Controlled same-original, same-entity, same-key scope contrast.** `alpha` and `alpha-alt` share the
   original, the entity id, the DEK, the HMAC key and the key version, and differ only in tenant,
   project and session. Their SESSION-scope references differ, the same contrast holds at the narrower
   TENANT derivation scope, and their ciphertexts do not open in each other's scope even with identical
   plaintext bytes and an identical key, because the AAD binds the tenant. Both records are first
   brought to the *same literal current revision `2`* and the same sealed revision - through the real
   reducer and a controlled host re-seal - before the cross-tenant open, so state, key, entity, value
   and revision are identical across the contrast and the tenant scope is the only difference that can
   explain the refusal. The positive controls then release those same two envelopes, with no re-seal in
   between, each under its own current scope, restoring the same independent literal.
7. **Zero plaintext on crypto failure.** Wrong key, wrong classification, wrong revision, wrong key
   version, foreign entity, tampered ciphertext and tampered tag each return the fixed refusal with no
   `plaintext` and no `bytes` field, and no planted marker in the serialized refusal. Every one of
   those assertions is made against the fixed-field projection, never against the result object, so a
   regression that returned `OPENED` on this path would still print only codes and booleans. A control
   case opens the untouched record, so the refusals are not vacuous.
8. **The diagnostic path cannot print plaintext.** An intentionally `OPENED` result whose `plaintext`
   field really is a byte buffer is pushed through the same projection; the projection still yields only
   fixed codes, numbers and booleans. A deliberately failing assertion over it therefore reaches a
   caught error carrying only two fixed codes, and the graph check asserts that neither the error nor
   its `actual`/`expected` operands holds a buffer or the planted marker. The same check is asserted to
   fire positively on a graph that does hold the bytes, so the negative result is not vacuous.
9. **One current revision authority.** A fixture built at the creation revision `'1'` is activated
   through the real reducer to the literal revision `'2'` and deliberately left un-re-sealed. Its
   untouched ciphertext is a coherent *old* record that still authenticates under its own seal revision,
   yet with the current metadata and a current `DISPLAY` grant the seam returns an actual `AUTHORIZED`
   decision and the release still withholds `AUTHENTICATION_FAILED`, because the expected AAD revision
   is the current record's. After the controlled host re-seal - with a fresh, asserted-different nonce -
   the same fixture's current envelope releases the literal. This is the behavior the previous iteration
   got wrong: a frozen copy of the seal revision acted as a second authority and released the old
   envelope.
10. **Lifecycle commits to the current revision.** Activation commits the literal revision `2` through
   the real reducer; creation, expiry, scope and reference are unchanged by the transition. A stale
   `expectedRevision` is `STALE_REVISION` and never mutates the current record, a grant pinned to a
   superseded revision denies even against a record the host reads now, a cached snapshot of the
   record cannot authorize a grant pinned to the current revision, and `ACTIVATE` on an `ACTIVE`
   record is `INVALID_TRANSITION`.
11. **A coherent cached snapshot cannot supersede the current record.** The stale triple - the cached
   `ACTIVE` snapshot at revision `2`, a grant coherent with it (same reference, revision, scope and
   destination, unexpired), and the fixture's own untouched ciphertext - is captured while the record is
   genuinely active, released once under the live record, then presented again after a real revocation
   to revision `3`. It withholds `SNAPSHOT_SUPERSEDED` with no open, while the live current record
   denies `MAPPING_REVOKED` at the seam for the same ciphertext. The test states the attribution
   explicitly: called on its own, the pure seam authorizes that stale triple, because a pure decision
   seam trusts the snapshot the host hands it.
12. **Expiry, revocation and deletion cannot resolve.** `EXPIRED` denies `MAPPING_EXPIRED`, `REVOKED`
    and `DELETED` deny `MAPPING_REVOKED`, reactivation of an expired record is `INVALID_TRANSITION`, a
    repeated terminal command is idempotent (`UNCHANGED`, and the same revision as the state captured
    independently before that command) and an expired grant on a live fixture denies `GRANT_EXPIRED`
    while a live grant on the same fixture still releases the literal. Each expected revision is a
    literal (`2` after activation, `3` after expiry or revocation, `4` after deletion), never a
    comparison against whatever the reducer returned.

Every assertion compares fixed codes, states, booleans, lengths and tokens. No assertion receives a
crypto result object, a byte buffer, or a plaintext-versus-null operand. Plaintext equality is decided
by a local helper that returns one boolean, so an assertion failure prints `true`/`false` and never a
byte of the synthetic original, a key byte or a native error. The model-visible capture admits only
fixed outcome labels (`RELEASED`, `WITHHELD`, `USED`) and the opaque reference.

## Limits

- **Not a broker.** The release helper in the test is a local orchestrator of the four shipped seams,
  not a deployed broker. It has no Policy Engine call, no audit ledger, no rate limit, no retry, no
  concurrency control and no transactional write.
- **No compare-and-set or race safety.** `expectedRevision` is compared against the one record the
  test process holds. There is no row lock, no transaction, no rollback detection and no claim about
  distributed races or concurrent writers.
- **Current-record authority is host-side fixture code, not a shipped seam.** The snapshot check that
  refuses a superseded snapshot is local harness logic modelling what a trusted store or broker must do;
  `authorizeMappingOperation` itself has no store and cannot tell a current snapshot from a cached one.
  A stale snapshot that reaches the seam with a coherent grant is authorized, and the test asserts that
  fact rather than hiding it.
- **Not fresh by itself.** `openMappingPayload` authenticates whatever expected scope it is handed, so a
  valid old envelope still authenticates under a scope that matches the revision it was sealed with.
  What this file adds is the trusted side of that contract: the expected revision always comes from the
  authoritative current record, which is what makes an old-but-valid envelope refuse. Currency,
  lifecycle and authority come from the trusted host record and the explicit grant, and here that host
  is the test process itself.
- **The graph check is bounded, not a taint analysis.** It inspects own data properties to a fixed
  depth and treats anything it cannot examine as unsafe. It is evidence that these particular assertion
  operands are free of planted bytes, not a general proof that no code path can ever print one.
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