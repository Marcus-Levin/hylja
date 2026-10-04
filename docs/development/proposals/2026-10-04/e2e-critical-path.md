# E2E critical path — proposal

**Proposal only, dated 2026-10-04** against repo `main` at `2e88ca065473f8c7020a7a0e66b0f465e0f95f07`. It prioritizes the path to MVPs so public synthetic development E2E tests can be **specified and written now**. It satisfies nothing, closes nothing, and claims no implemented cloaking path. Per [capabilities.md](../../../capabilities.md), the transformation engine, vault, broker, gateway and every send point are **not implemented**.

Companion rows: [core-issues.md](core-issues.md) (21 issues), [roadmap-issues.md](roadmap-issues.md) (22 issues). Status, priority, criteria and checkmarks stay at their live issue URLs.

Decisions 001–009 are accepted. **[010](../../../decisions/010-separate-information-dimensions-and-task-fidelity.md) is `proposed`**, so [#65](https://github.com/Marcus-Levin/hylja/issues/65)/[#66](https://github.com/Marcus-Levin/hylja/issues/66)/[#68](https://github.com/Marcus-Levin/hylja/issues/68) carry no authority. [#13](https://github.com/Marcus-Levin/hylja/issues/13)'s first acceptance item depends on **accepted** #68 semantics — a real dependency this plan sequences around, not bypasses. A human may narrow or accept a decision explicitly; this proposal does neither.

## Dependency table

| Milestone | Outcome (**PLANNED — not implemented, not runnable**) | Scopes | Gate before a *passing integrated* run |
|---|---|---|---|
| **M1** irreversible-only text cloaking | Planted synthetic text → candidate → classification → `decidePolicy` → rewrite (policy-selected KEEP/MASK/REMOVE only) → independent sentinel over the exact serialized **body and metadata** → emitted cloaked payload + privacy-safe #20 evidence | [#13](https://github.com/Marcus-Levin/hylja/issues/13), [#19](https://github.com/Marcus-Levin/hylja/issues/19), [#20](https://github.com/Marcus-Levin/hylja/issues/20) | actual transformation + send-point implementation; ▲ accepted treatment/overlap semantics for integrated rewrite |
| **M2** encrypted scoped reversibility | Canonical entities in the narrowest authorized scope; envelope-encrypted originals; USE ≠ DISPLAY ≠ EXPORT; expiry/revocation; unconditional cross-tenant non-resolution | [#14](https://github.com/Marcus-Levin/hylja/issues/14)–[#18](https://github.com/Marcus-Levin/hylja/issues/18) | ▲ accepted semantics for reversible treatment; real reversible persistence blocked until #16 crypto is verified |
| **M3** local gateway + authorized round-trip | Denied release sends zero upstream bytes; only sentinel-approved bytes are sent; inbound inspected conservatively; restoration only under brokered authorization | [#21](https://github.com/Marcus-Levin/hylja/issues/21), [#22](https://github.com/Marcus-Levin/hylja/issues/22) | endpoint/caller/actual-sink configuration supplied before **real** model-backed integration; test identity or stub proves no real authentication |

Reversible TOKENIZE/SYNTHETIC behavior belongs **after M2**. Nothing in M1 creates a reversible person, host or customer mapping.

## Reuse existing seams — no new generic abstraction

| Reuse | Source | Contract | Focused test |
|---|---|---|---|
| Normalized events, provenance | [src/interaction-envelope.ts](../../../../src/interaction-envelope.ts) | [interaction-envelope.md](../../../contracts/interaction-envelope.md) | [test/interaction-envelope.test.mjs](../../../../test/interaction-envelope.test.mjs) |
| Parsers + opaque/failure status | [src/structured-parsers.ts](../../../../src/structured-parsers.ts) | [architecture.md](../../../architecture.md#detection-pipeline) | [test/structured-parsers.test.mjs](../../../../test/structured-parsers.test.mjs) |
| Secret/credential detection | [src/secret-detectors.ts](../../../../src/secret-detectors.ts) | [classification-contract.md](../../../contracts/classification-contract.md) | [test/secret-detectors.test.mjs](../../../../test/secret-detectors.test.mjs) |
| Candidates and classification units | [src/contact-candidates.ts](../../../../src/contact-candidates.ts), [src/configured-candidates.ts](../../../../src/configured-candidates.ts) | [classification-unit-contract.md](../../../contracts/classification-unit-contract.md) | [test/contact-candidates.test.mjs](../../../../test/contact-candidates.test.mjs) |
| The one treatment decision identity | `decidePolicy` in [src/policy.ts](../../../../src/policy.ts) | [policy-contract.md](../../../contracts/policy-contract.md) | [test/policy.test.mjs](../../../../test/policy.test.mjs) |
| Final-byte independent check (**core exists**) | [src/egress-sentinel.ts](../../../../src/egress-sentinel.ts) | [threat-model.md](../../../threat-model.md#priority-abuse-cases) | [test/egress-sentinel.test.mjs](../../../../test/egress-sentinel.test.mjs) |
| Privacy-safe audit correlation | [src/audit-ledger.ts](../../../../src/audit-ledger.ts) | [audit-ledger-contract.md](../../../contracts/audit-ledger-contract.md) | [test/audit-ledger.test.mjs](../../../../test/audit-ledger.test.mjs) |
| Adapter conformance | [src/adapter-conformance.ts](../../../../src/adapter-conformance.ts) | [adapter-contract.md](../../../contracts/adapter-contract.md) | [test/adapter-conformance.test.mjs](../../../../test/adapter-conformance.test.mjs) |
| Synthetic tenant scope for tests | [src/synthetic-scope-contract.ts](../../../../src/synthetic-scope-contract.ts) | [synthetic-evaluation-seam.md](../../../contracts/synthetic-evaluation-seam.md) | [test/synthetic-scope-contract.test.mjs](../../../../test/synthetic-scope-contract.test.mjs) |
| Offline in-memory synthetic harness precedent | [scripts/synthetic-release-demo.mjs](../../../../scripts/synthetic-release-demo.mjs) | [release-integrity-contract.md](../../../contracts/release-integrity-contract.md) | run `npm run check:release` after build |

## Executable preparation brief — **PRELIMINARY / NOT READY**

All children below are **PRELIMINARY / NOT READY**: this document proposes them, it does not demonstrate readiness. Test paths below are **future files that do not exist yet**; the commands run only once they do.

**E1 — typed restrictive failures and structure-preserving rewrite ([#13](https://github.com/Marcus-Levin/hylja/issues/13))**

- Observable: malformed/opaque parser status, stale/overlapping locations, an unavailable generator, invalid JSON/XML/**YAML** output and a mid-stream exception each return a typed restrictive failure — no partial success, no silent KEEP, no relaxed authorized action; supported formats stay valid.
- Future tests: `test/transformation-failure.test.mjs`, `test/transformation-fidelity.test.mjs`.
- Permitted: pure in-process typed failures and rewrite. [evaluation.md](../../../evaluation.md) expressly permits pre-vault synthetic invariant and property tests, so no blanket gate applies to them.
- Non-goals: **no integrated accepted-v1 rewrite is claimed or invented here**, and no draft is adopted. Overlap treatment (including [#114](https://github.com/Marcus-Levin/hylja/issues/114)) is **not** auto-denied; compatible overlaps are not automatically failures — their semantics await the required acceptance. Treatment semantics for integrated rewrite carry the ▲ 010/#66/#68 dependency.

**E2 — sentinel at a controlled local sink ([#19](https://github.com/Marcus-Levin/hylja/issues/19))**

- Observable: the shipped sentinel runs on the exact serialized bytes immediately before a controlled local sink, returns its private ALLOW copy, and that copy is what is sent; no unchecked chunk follows the decision.
- Future test: `test/egress-sendpoint.e2e.test.mjs`. **Explicitly distinguish** captured fixture bytes and a local transport from real gateway/network coverage — a scoped fixture E2E proof is **not** managed egress or a production boundary.
- Non-goals: no provider network traffic or credentials. [#147](https://github.com/Marcus-Levin/hylja/issues/147) subprocess bounding is a process/resource hardening follow-up, **not** a universal dependency here.

**E3 — broker contract preparation, then vault-backed integration ([#17](https://github.com/Marcus-Levin/hylja/issues/17), [#15](https://github.com/Marcus-Levin/hylja/issues/15), [#18](https://github.com/Marcus-Levin/hylja/issues/18), [#16](https://github.com/Marcus-Levin/hylja/issues/16))**

- Order, no circularity: **E3a** defines the authorization contract plus a **trusted store interface and test fixture** (USE executes a trusted local operation without returning plaintext; DISPLAY does not imply EXPORT; unknown/forged/cross-tenant/model-invented tokens fail safely and are audited). **E3b** [#15](https://github.com/Marcus-Levin/hylja/issues/15)/[#16](https://github.com/Marcus-Levin/hylja/issues/16) implement that interface with encrypted scope. **E3c** the integration validates E3a against E3b. Contract preparation and actual encrypted restoration are separate steps.
- #18 expiry/revocation lifecycle must be enforced for the relevant restoration; full production backup/DR stays [#31](https://github.com/Marcus-Levin/hylja/issues/31).
- Non-goals: no direct mapping lookup API ([004](../../../decisions/004-brokered-vault-no-direct-mapping-api.md)); no real reversible persistence before #16 crypto is verified; an injectable identity proves no real authentication.

**E4 — local gateway boundary ([#21](https://github.com/Marcus-Levin/hylja/issues/21), [#22](https://github.com/Marcus-Levin/hylja/issues/22))**

- Observable: policy denial stops release before upstream contact; only sentinel-approved bytes are sent; streaming holdback leaks no prefix across SSE/UTF-8/tool-argument deltas or a late denial; unsupported, opaque and unknown nested content fails closed; inbound is inspected and held conservatively with **no restoration**.
- Future tests: `test/gateway-egress.e2e.test.mjs`, `test/gateway-inbound.e2e.test.mjs`. A stub transport covers gateway logic only and is **not** real gateway integration.
- Gates: endpoint, caller and actual-sink configuration must be supplied before real model-backed integration. No credentials, procurement or key-vendor choice is required for an offline or controlled local fixture; that is an open question, not an added prerequisite.

**Verification commands** (quoted from `package.json` `scripts`; they run **after** the future files exist, after `npm run build`):

```
npm run build
npm run typecheck
node --test test/text-cloaking.e2e.test.mjs
node --test test/transformation-failure.test.mjs
node --test test/transformation-fidelity.test.mjs
node --test test/egress-sendpoint.e2e.test.mjs
node --test test/gateway-egress.e2e.test.mjs
node --test test/gateway-inbound.e2e.test.mjs
```

## E2E negative cases

| Negative case | Milestone | Status |
|---|---|---|
| Planted synthetic secret sends **zero** bytes to the controlled sink | M1 (E2) | specifiable now; runs after E1 + E2 |
| Sentinel / required-verification outage fails closed on high-risk egress | M1 (E2) | specifiable now; runs after E2 |
| Unsupported media type, opaque/embedded binary, unknown nested field denied | M1 (E1), M3 (E4) | specifiable now; M3 runs after E4 |
| Split streaming boundaries leak no prefix or complete secret | M3 (E4) | **planned** — needs the gateway |
| No cross-tenant, forged or expired restoration | M2 (E3), M3 (E4) | **planned** — needs encrypted scope + broker |
| Model-fabricated or invented token denied | M2 (E3), M3 (E4) | **planned** |
| No plaintext in logs or audit; correlation only | every milestone | specifiable now; re-checked each milestone |
| Holdback composes with inbound inspection before any release claim | M3 (E4) | **planned**, ordered |

## Preservation, ownership and gates

| Item | Disposition |
|---|---|
| [#13](https://github.com/Marcus-Levin/hylja/issues/13) **10** unchecked items, failure/negative and overlap sections | preserved verbatim; E1 claims only the bounded criteria in the table below |
| [#21](https://github.com/Marcus-Levin/hylja/issues/21) **7** unchecked items + enforced-boundary narrative | preserved verbatim; E4 claims only the bounded criteria below |
| [#22](https://github.com/Marcus-Levin/hylja/issues/22) **5** unchecked items + inbound narrative | preserved verbatim; E4 claims only the bounded criteria below |
| Every other audited parent's checkboxes, narratives and checked marks | preserved unchanged; see [core-issues.md](core-issues.md) and [roadmap-issues.md](roadmap-issues.md) |
| ▲ [#65](https://github.com/Marcus-Levin/hylja/issues/65)/[#66](https://github.com/Marcus-Levin/hylja/issues/66)/[#68](https://github.com/Marcus-Levin/hylja/issues/68) and [010](../../../decisions/010-separate-information-dimensions-and-task-fidelity.md) | explicit human-adoption dependency for the treatment and overlap semantics integrated #13 requires; **not** wholly off-path |
| [#39](https://github.com/Marcus-Levin/hylja/issues/39) | gates scored/held-out and associated release claims. It does **not** gate specifying or running public development E2E, and [#20](https://github.com/Marcus-Levin/hylja/issues/20) privacy-safe synthetic audit evidence needs no held-out freeze |
| [#48](https://github.com/Marcus-Levin/hylja/issues/48) all-sixteen subsystem decisions, commercial and comparative campaigns | **not** first-E2E prerequisites; keep their adoption and release scopes |
| [#88](https://github.com/Marcus-Levin/hylja/issues/88) editorial P2 and [#36](https://github.com/Marcus-Levin/hylja/issues/36) B1 | **optional maintenance**, not E2E prerequisites; keep their dated evidence and checked marks |
| [#147](https://github.com/Marcus-Levin/hylja/issues/147) | process/resource hardening follow-up; no universal dependency |
| Credentials, procurement, key-vendor, harness and identity choices | open questions to record. Endpoint/caller/actual-sink configuration is required before real model-backed integration; test identity and stubs prove no real authentication |

## Bounded criteria claimed (preliminary)

Only criteria these children actually claim. **Every unclaimed parent obligation stays at its live issue URL.**

| Parent criterion | Claimed by | Observable evidence |
|---|---|---|
| #13 secret handling: no reversible synthetic secret aliases | E1 | fixture test; no secret alias resolves, sentinel ALLOW copy carries none |
| #13 failure/negative cases incl. unavailable generator, invalid JSON/XML/YAML | E1 | typed failure test; no partial success reaches a sink |
| #13 format validity under property tests | E1 | `test/transformation-fidelity.test.mjs` round-trips |
| #13 transformer cannot choose a less restrictive action | E1 | assertion the transformer receives, never selects, the treatment |
| #13 provenance keeps source location, candidate, transformation and sentinel outcomes distinct | E1 | structured evidence assertion |
| #19 planted marker blocked before send; outage restrictive | E2 | `test/egress-sendpoint.e2e.test.mjs` over controlled sink bytes |
| #21 denied release never reaches upstream; unsupported/opaque fails closed; hosted limits labelled | E4 (**planned**) | `test/gateway-egress.e2e.test.mjs` |
| #21 split SSE/UTF-8/tool-delta and late-denial no-prefix; authenticated caller bound to actual sink | E4 (**planned**, needs endpoint/sink configuration) | `test/gateway-egress.e2e.test.mjs` |
| #22 naive global replacement not used; unauthorized originals stay synthetic/redacted | E4 (**planned**) | entity-bound restoration assertion |
| #22 replay/invented-ID/quoted-uncloak/late-suffix denial | E4 (**planned**) | denial table, fixed codes, no originals |

**Unclaimed and retained:** #13 item 1 (accepted #68 semantics), the #114 overlap integration and obligation-satisfying-rewrite items, #13's protocol/OS/data-type fidelity breadth, #21's destination-profile/redirect binding and backpressure bounds, and #22's held-out exactness item (held-out execution needs #39).

## Invariants carried unchanged

Secret and credential irreversibility ([009](../../../decisions/009-secrets-are-not-synthetic-identities.md); implemented limits on [#8](https://github.com/Marcus-Levin/hylja/issues/8)); USE ≠ DISPLAY ≠ EXPORT; unconditional cross-tenant isolation; final serialized body **and** metadata check with no unchecked chunk after it; authenticated actual-sink binding; conservative inbound until #22; audit correlation without raw payloads; expiry and revocation denial; model-fabricated token denial; fail-closed on missing safe release ([007](../../../decisions/007-fail-closed-for-protected-egress.md)). Semantic judgment never owns effects ([003](../../../decisions/003-semantic-judgment-does-not-own-effects.md)).

## Limits of this revision

This revision performed no build, test, network or source re-audit. Verification actually run: `git diff --check` (clean) and `npm run check:docs` (ok). Unverified: sentinel runtime behavior, existence of merge SHAs cited in the two row reports, and custodian/signing-owner/trial availability. The previous author attempt for this proposal timed out after staging; its corrections were applied here rather than hidden.
