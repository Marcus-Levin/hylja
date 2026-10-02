# Release integrity contract (#33)

Status: bounded #33 slice, **NON-ENFORCING for any real release**. Implementation status lives in [plan.md](../plan.md#current-state); this document is the interface, the trust boundaries and the limits.

This contract answers one question at a release boundary: **do the exact bytes offered for release match signed evidence produced from those same bytes, and do those bytes still satisfy the release owner's independent expectation?** It never signs, writes, publishes, promotes, or contacts a network. Verified evidence is a *necessary, not sufficient*, release condition.

## What exists

| Piece | File | Role |
|---|---|---|
| Bounded canonical JSON | [`src/canonical-json.ts`](../../src/canonical-json.ts) | Deterministic serialization, duplicate-key rejection, SHA-256 over exact bytes. |
| Strict byte encodings | [`src/byte-encoding.ts`](../../src/byte-encoding.ts) | Canonical base64 and lowercase-hex checks. |
| Dependency evidence | [`src/dependency-evidence.ts`](../../src/dependency-evidence.ts) | Locked dependency set, CycloneDX SBOM set, and their comparison. |
| Adapter conformance | [`src/adapter-conformance.ts`](../../src/adapter-conformance.ts) | Synthetic harness that observes what an adapter actually released, using the in-tree #19 final-byte check. |
| Promotion gate | [`src/release-integrity.ts`](../../src/release-integrity.ts) | `verifyReleaseEvidence`: strict failure on missing, mismatched or critical evidence. |
| Release gate CLI | [`src/release-gate-cli.ts`](../../src/release-gate-cli.ts) | The exact release-boundary invocation. |
| Offline substrate | `scripts/synthetic-release-substrate.mjs`, `scripts/synthetic-release-demo.mjs` | Synthetic, in-memory, ephemeral-key evidence and a 13-case demonstration. |
| Ephemeral SBOM check | `scripts/check-sbom.mjs` | Semantic SBOM/lockfile cross-check, replacing a parse-only check. |

## Exact invocation

```bash
# Offline synthetic demonstration (no artifact, no network, ephemeral in-memory key).
npm run build
npm run check:release
# -> {"status":"SYNTHETIC_RELEASE_GATE_CONSISTENT","cases":13,"failed":[],"adapter":"synthetic-adapter-a"}

# The real release boundary, once a signing authority exists (see open gates).
npm run build
node dist/release-gate-cli.js <evidence.json> <expectation.json> <subject-dir>
# exit 0 and {"status":"RELEASE_EVIDENCE_VERIFIED","reasons":[]} only when every check held.
# Any other result is exit 1 with fixed codes; a wrong argument count is exit 2 and reads nothing.

# Ephemeral dependency SBOM, semantically checked against the lockfile.
npm run --silent sbom > /tmp/hylja-sbom.json && npm run --silent check:sbom -- /tmp/hylja-sbom.json
```

`check:release` and `check:sbom` are also CI steps; `npm test` runs the whole synthetic suite.

## Trust boundaries

**Trusted input, never read from the evidence** (`ReleaseExpectation`): trusted Ed25519 public keys (`keyId` -> SPKI DER base64), the expected release version, the expected source commit, the expected artifact name, the release channel (`scopeRef` tenant scope and `profileId` destination profile), the required adapter conformance suite digests, the trusted scanner identities, the severity that blocks promotion, the wall clock `now`, the maximum evidence age, and the optional independent `expectedLockSha256` / `expectedDependencies` pins. None of these may come from the build, the evidence document, a manifest field or an untrusted caller asserting that something was tested.

**Untrusted input**: the canonical evidence document and the subject bytes (artifact, lockfile, SBOM, conformance evidence, scanner evidence) read at the boundary. They are size-bounded, strictly allowlisted, digest-bound and signed. They can never grant authority to themselves; the only channel for "this was tested" is a digest-bound attestation document produced by the conformance harness and countersigned by a trusted key.

**The gate's own limits**: it authenticates nothing about *where the expectation file came from*. Obtain it from the release owner's reviewed configuration or the release environment. It also does not authenticate the subject directory against a concurrent hostile filesystem beyond refusing symlinked, multiply-linked, empty and oversized files.

## Evidence and attestation formats

The signed evidence document (`hylja-release-evidence/v1`) is **canonical JSON** (RFC 8785 style: sorted UTF-16 keys, no insignificant whitespace, integers only). It carries only bindings and claims:

```json
{"adapters":[{"adapterId":"...","evidenceSha256":"..."}],"artifact":{"bytes":0,"name":"...","sha256":"..."},
 "dependencies":{"lockSha256":"...","sbomSha256":"..."},"expiresAt":0,"format":"hylja-release-evidence/v1",
 "issuedAt":0,"release":{"commit":"...","profileId":"...","scopeRef":"...","version":"..."},
 "scanner":{"evidenceSha256":"..."},"signature":{"algorithm":"ed25519","keyId":"...","value":"..."}}
```

* The signature is RFC 8032 Ed25519 (64-octet `R||S`) over the canonical bytes of the document **without** the `signature` member, verified through `node:crypto` with a null algorithm. A canonical round trip is required for parsing, so duplicate keys, alternative number spellings, re-ordered keys and hand-edited escapes are refused before verification, and two claims for the same adapter are refused rather than resolved first-wins.
* The gate module contains **no function that produces evidence bytes**. Assembly and signing live with the signer (`scripts/synthetic-release-substrate.mjs` here); the gate can only verify.
* The `expectation` file form (`hylja-release-expectation/v1`) adds a `subject` section naming the files to read: `artifact`, `lockfile`, `sbom`, `scanner`, `conformance[] = {adapterId, file}`. Names are single plain path components.
* Conformance evidence is the harness output (`hylja.adapter-conformance.v1`): `suiteId`, `suiteSha256`, `adapterId`, `scopeRef`, the `subject` digests it was exercised against, `completedAt`, per-case `requirements`/`violations`/`outcome`, and the separate `functionalTests`, `plantedEgress` and `overall` verdicts. `violations` is drawn from a fixed vocabulary (`ADAPTER_ERROR`, `BUDGET_EXCEEDED`, `PLANTED_ORIGINAL_RELEASED`, `PLANTED_ORIGINAL_RETURNED`, `UNREVIEWED_RELEASE_BYTES`, `UNBOUND_RELEASE_BYTES`); an unrecognised name is malformed evidence. The document contains no request text, field value or captured byte.
* Scanner evidence is a normalized report (`schemaVersion`, `scannerId`, `completed`, `completedAt`, the `lockSha256`/`sbomSha256` it scanned, and findings with `severity` from the `npm audit` vocabulary `info|low|moderate|high|critical`).

## What the gate checks, in order

1. **Structure**: canonical bytes, strict allowlist, bounds. Unknown or missing fields are a rejection, not a default.
2. **Signature**: the claimed `keyId` must be in the trusted set (no fallback to "any" key), the key must be a usable Ed25519 public key, and the Ed25519 verification must pass. An unauthenticated payload never reaches a release decision.
3. **Freshness and identity**: `issuedAt <= now < expiresAt`, age within `maxAgeMs`, and the release version, source commit, channel scope and channel profile must equal the independent expectation. The artifact name must be in the trusted allowlist.
4. **Exact tested bytes**: the SHA-256 and length of the artifact, lockfile and SBOM offered now must equal the signed claims.
5. **Dependency evidence**: the lockfile and the CycloneDX SBOM are reduced to the same normalized set and must be identical, every locked entry must carry a resolution (unless it is a `link`), and an optional independently published set must match exactly. An integrity pin is validated at parse time: it must be a canonical `sha256`, `sha384` or `sha512` value whose base64 decodes to that algorithm's digest length, otherwise the locked tree is unusable evidence (`LOCKFILE_INTEGRITY_INVALID`). A pin that parses but cannot be cross-checked against the SBOM's SHA-512 content hash (a `sha256`/`sha384` pin) is reported as `DEPENDENCY_CONTENT_ALGORITHM_UNSUPPORTED` rather than skipped, and a `sha512` pin whose content hash differs is `DEPENDENCY_CONTENT_MISMATCH`. A lockfile or SBOM that is not byte-identical to npm's own serialization is refused, which is what rejects duplicate JSON keys.
6. **Adapter conformance**: for each required adapter, digest-bound evidence from this harness's version, pinned `suiteSha256`, matching channel scope, matching subject digests, fresh `completedAt`, every case `outcome === 'PASS'` with no reported `violations`, and `functionalTests`, `plantedEgress` and `overall` all `PASS`. A summary that contradicts its own cases, an unknown violation name or a foreign harness version is a denial. An unknown, missing or duplicated adapter is a denial.
7. **Scanner evidence**: digest-bound, a trusted scanner id, `completed`, the same lockfile/SBOM digests, fresh, and no finding at or above `blockAtSeverity`.

Any failure denies with a sorted, deduplicated set of fixed codes from `RELEASE_DENIAL_CODES`; an internal error denies with `CHECK_UNAVAILABLE`. Results never contain a path, digest, package name, key id, subject byte or exception message.

## Adapter conformance: a green unit test is not conformance

`runAdapterConformance` gives an adapter only an append-only controlled capture and an injected pre-send control. Every outcome is computed from the harness's own observations, never from a self-report, so a returned `conformance: 'PASS'` field, an attempt to edit the capture record, or an exception cannot buy a pass. `functionalTests` is derived only from the ordinary functional requirement and is deliberately reported separately from `plantedEgress` and `overall`, so the synthetic bypass adapter passes `functionalTests` and still fails the gate with `PLANTED_EGRESS_UNPROVEN` and `CONFORMANCE_FAILED`.

Two properties are inherited from the project's own **#19 Egress Sentinel** rather than reinvented at a weaker standard:

* **The pre-send control is a real final-byte check.** It runs `checkEgress` over the adapter's outbound bytes with a harness-owned known-originals registry built from the planted synthetic values, across the same bounded canonical views. A planted original that is still recoverable after base64, hex, percent or escape decoding is therefore not "absent". On ALLOW the control hands back a **private copy of exactly the bytes it cleared**; a BLOCK hands back nothing.
* **What left the boundary is re-checked independently.** After the adapter returns, the harness inspects every captured record and every returned field itself. A record is additionally required to be byte-identical to the copy the control cleared (`UNBOUND_RELEASE_BYTES`), which is #19's "send `release`, not your own buffer" rule, and a record the independent check would not release is `UNREVIEWED_RELEASE_BYTES`. That check is **per record**: records are never joined, so it says nothing about a value an adapter reassembles from two records it released separately (see *Limits*).

Bounded work is explicit: at most 1 MiB per record, 16 records per case, 64 cases, 8 KiB per field and **4 MiB of total inspected bytes per run**; exceeding a bound fails the case with `BUDGET_EXCEEDED` rather than continuing. The planted-value length is capped at the #19 registry's own limit, so a value the sentinel cannot index is an input error instead of a silently unmatched value.

## Limits and residual risk

* A **recomputed digest binds bytes; it is not publisher provenance.** This gate proves that the offered bytes are the bytes a trusted signer bound to a version, commit, channel, dependency set and conformance run. It does not prove the signer was honest, that the build was reproducible, that the source commit was reviewed, or that a conformance run really happened. Reproducible builds, an attested build platform and keyless attestation (SLSA provenance, GitHub artifact attestations) remain owner decisions.
* The **conformance harness is synthetic and in-process**. It models "skips the pre-send check", "leaks a planted original", "declares a part unsupported but releases it" and "follows an unobserved redirect". A bypass that leaves the process (a raw socket, a hosted action) is not expressible here and must be declared uncovered coverage.
* **Conformance inspection is per record, with no cross-record concatenation detection.** Each bounded capture record is bound to the copy the pre-send control cleared and re-checked independently, and each returned field is checked on its own. A planted original deliberately **split across two records to the same authorized destination**, each half short enough to clear the control on its own, is therefore graded as two individually clean records and is *not* reported as planted egress. The same single-record scope applies to the #19 sentinel this harness calls. Reassembly across records is the destination application's concern; detecting the join is a declared limit here, **not** a supported guarantee.
* A **signer that lies about conformance results is not detectable here**: the evidence is digest-bound, not re-executed. Pinning the suite digest independently, running the harness in the same job as the build, and attesting that job are the mitigations, and they are owner gates.
* **Lockfile and SBOM parsing is bounded and format-pinned** to npm's serialization. A future npm format change fails closed and needs an explicit update. Only CycloneDX 1.4/1.5, lockfile versions 2/3 and `sha256`/`sha384`/`sha512` integrity pins are supported; anything else is refused rather than reinterpreted.
* **The strongest dependency pins are optional.** `expectedLockSha256` and `expectedDependencies` are the only inputs that ground the dependency set independently of the signature. With neither supplied, the signature is the only anchor for the locked tree; the owner should choose that posture deliberately at the release boundary.
* There is **no publication, promotion, registry, or GitHub trust policy** here, and no repository write permission was added. The threat-model "Supply-chain bypass" mitigation is only partially discharged: pinning, scanning, SBOM, conformance and a promotion gate exist offline, while key custody and the trust root do not.
* Scanner evidence is **normalized input**, not a scanner: `npm audit --audit-level=high` remains the live scanner in CI, and this repository has one integrity-pinned direct dependency (TypeScript 5.9.3) and zero known vulnerabilities.
* `check:sbom` compares **documents**: it proves the ephemeral SBOM describes exactly the locked tree (no truncation, tailoring or invention), and it does not by itself prove the *installed bytes* were hashed, because npm may reuse lockfile integrity metadata. `npm ci --ignore-scripts` remains the independent installed-bytes integrity control.
* The CLI **refuses a subject or expectation directory reached through a symlinked ancestor**, because `realpath` of the directory must equal the resolved path. That is fail-closed, but it also means a macOS temporary directory (`/tmp` -> `/private/tmp`) is rejected: point the gate at a real path.
* Timing, memory and CPU are bounded by fixed caps (256 KiB evidence, 512 MiB artifact, 20 000 dependencies, 32 depth, 4096 canonical members); no unbounded parsing, regex or network path exists.

## Open owner gates (explicitly unresolved)

1. **Signing authority and key custody**: which key signs a Hylja release, where the private key lives, and how it is rotated and revoked. Nothing in this repository may hold a signing secret.
2. **GitHub or CI trust policy**: the workflow identity, permissions and trust root for attested provenance (for example artifact attestations with a protected environment). No workflow here publishes, promotes or holds write permission.
3. **Conformance suite ownership**: the reviewed adapter list, the pinned suite digests and who may add a case.
4. **Severity policy sign-off**: the `blockAtSeverity` threshold and the scanner identities trusted for promotion.
5. **Reproducibility and reproducibility evidence**: whether builds are made reproducible and how that is verified.
6. **Posture on independent dependency pins**: whether the release boundary will supply `expectedLockSha256` and `expectedDependencies`, or rely on the signature alone.
