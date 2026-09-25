# Development plan

This plan is the single authoritative home for implementation status. Architecture and specifications describe accepted behavior; they do not prove implementation.

## Current state

**Foundation toolchain #1 and normalized interaction envelope #2 implemented; no enforcement runtime.** Product direction and the backlog remain foundation-only. The TypeScript source still contains no identity authenticator, production adapter/broker, policy engine, vault, egress sentinel, transport interceptor or privacy boundary; milestone 0's policy/security tests depend on later issues.

Local #1 evidence (Node 22.22.3, npm 11.15.0): the red command `node --test test/*.test.mjs` failed with 0/6 passing before the runner/guard existed; its deliberately throwing runtime probe was ignored by the old typecheck-only `npm test` (which exited 0 with dependencies installed). After implementation, locked `npm ci --ignore-scripts --no-fund`, `npm run build`, `npm run typecheck`, `npm test`, and `npm run test:coverage` passed; disposable synthetic negative cases reject force-added ignored private fixture paths, tracked credential-like fixture blobs, generated artifacts, binary/symlinked fixtures, and guard execution from a subdirectory. The designated synthetic golden fixture is accepted. The Node test runner reports line/branch coverage for this small toolchain and compiled module, not coverage of future enforcement behavior. `npm run audit:deps` reported zero known vulnerabilities locally; `npm run --silent sbom` produced parseable CycloneDX JSON. CI is configured to run these gates from the lockfile without installing lifecycle scripts or persisting SBOM artifacts; no remote CI run is claimed here.

Threat coverage for #1 is limited to supply-chain hygiene (locked integrity-pinned dependency, local audit/SBOM, pinned CI actions) and accidental tracked-fixture/CI-output disclosure (Git-index guard, ignored private paths, no planted value in guard output). New surfaces are npm installation, the Git-backed guard and test runner, and CI network/runner output. The guard uses bounded deterministic patterns, **not** exhaustive secret/PII detection; encoded values, contextual identifiers, and non-fixture files still need human review and future controls. No customer/production data or semantic/policy behavior is involved, so downstream utility, model latency/cost, held-out and shadow comparisons are not applicable to this toolchain slice. CI has not yet been independently observed in GitHub.

Local #2 evidence (Node 22.22.3, npm 11.15.0; based on reviewed #1 head `39f11f1`): after locked `npm ci --ignore-scripts --no-fund`, baseline `npm test` exited 0 (10/10). Nine public behavior tests were written first and the existing `npm test` runner then exited 1 with 10 pass / 9 fail against compileable unimplemented envelope exports (fixture guard/build passed; no missing dependency). Security regression tests for non-echoing errors and bounded UTF-8/branching input also failed before their fixes (21 pass / 2 fail). After implementation, a clean locked `npm ci --ignore-scripts --no-fund`, `npm run build`, `npm run typecheck`, `npm test` and `npm run test:coverage` all exited 0; tests reported 23/23 passing, with the envelope compiled module at 98.77% line, 86.10% branch and 100% function coverage. These numbers are test coverage of a schema/binding module, **not** release safety or enforcement coverage; no remote CI for #2 is claimed.

#2 synthetic golden/regression cases exercise exact JSON round trips for all 26 initial operation families, unknown/unversioned/malformed rejection, four fresh ordered proof claims against separately supplied identity/request/source/actual-route context, forged/stale/missing provenance, mismatch across principal/workload/tenant/project/session/purpose/source/destination/profile/redirect, payload and metadata `CONTROL` claims, stream continuity/cancellation, malformed representation, immutable payloads, non-echoing errors, and UTF-8/traversal limits. A deterministic 64-case tenant/project/principal/route variation set checks each mismatch against an otherwise identical, positively parseable binding (stable proof timestamps); no protected release permission is produced. This addresses untrusted-content promotion, poisoned model/tool claims, tenant/confused-deputy mixups, route/profile substitution and a limited fragment-context aspect of streaming leaks. The new attack surface is the adapter-to-core trusted-context handoff and its proof/clock/redirect lifecycle: #2 checks congruence/freshness only, **not** authentication or cryptographic proof integrity. Upstream adapters/brokers must authenticate principals/workloads, verify project membership, observe effective routes including redirects, guard the context argument, and track stream history; a caller able to fabricate that argument can fabricate authority. A replayed first fragment within the freshness window or an unobserved redirect remains possible without later stateful enforcement; this module neither decodes representations nor inspects data or transmits bytes. Policy authorization, secret handling, brokered uncloak, holdback and independent exact-byte egress checks remain future work. No real/private corpus was used; synthetic in-memory examples are all reserved `.invalid`/`example.invalid` values. Utility evidence is exact payload/schema round trip, **not** downstream task success or fidelity under cloaking. An informational local 1,000-cycle synthetic create/serialize/parse measurement was 177.34 ms total (~0.177 ms/cycle); this is neither a traffic-latency SLA nor a benchmark versus #1, which had no envelope. No model/semantic calls or external egress occur, so model latency/cost and actual privacy-release metrics are not applicable.

Implementation work is tracked from [roadmap issue #36](https://github.com/Marcus-Levin/hylja/issues/36), with scoped implementation issues #1-#35 and #37 carrying their own dependencies and acceptance criteria. A separate [comparative reuse/buy/build campaign #38](https://github.com/Marcus-Levin/hylja/issues/38) may propose later scope changes; it does not itself prove implementation or alter accepted security invariants.

## Dependency-ordered milestones

### 0. Foundation and executable contracts

Goal: establish TypeScript toolchain, normalized interaction envelope, classification model, policy vocabulary, deterministic security invariants, and synthetic eval harness.

Exit evidence:

- strict TypeScript build and tests;
- synthetic fixtures only;
- runnable synthetic contract/property tests for tenant-scoped policy/authorization, blocked-secret behavior, forged policy context, and fail-closed decisions (no passing placeholders); storage, cache, and broker isolation are proved again when those components exist;
- threat cases mapped to specific negative tests, including classification conflict and missing destination/profile context.

Primary issues: #1-#5.

### 1. Text cloaking proof

Goal: local synthetic text request -> deterministic and configured candidate generation -> optional local or independently guarded semantic shadow judgment -> policy -> transformation -> independent check of the exact serialized egress.

Initial categories: PERSON (including EMAIL/PHONE), CREDENTIAL_OR_SECRET, HOST, IP/URL, CUSTOMER/PROJECT. PERSON/EMAIL/PHONE must have an explicit candidate source and synthetic acceptance cases; shadow judgment is not that source.

No production vault yet beyond minimal development fixture state. No unverified hosted semantic request, opaque protected content, or unchecked stream is silently released; this slice is not a production traffic claim.

Primary issues: #6-#13, #19, and #37 (PERSON/EMAIL/PHONE candidate source).

### 2. Reversible identity and vault

Goal: encrypted scoped mappings, entity consistency, brokered USE/DISPLAY operations, lifecycle/retention, and exact authorized round-trip restoration. No production original is persisted before encryption; privacy-safe audit and unconditional tenant isolation are prerequisites for brokered reveal.

Primary issues: #14-#18, with the audit prerequisite in #20.

### 3. Model gateway proof

Goal: OpenAI-compatible local gateway using the same core contracts, authenticated caller/destination binding, streaming policy, inbound/outbound enforcement, destination profiles, and audit evidence. #21 first proves conservative inbound inspection without uncloak; #22 adds authorized response restoration. Unsupported protected formats and hosted-tool bypasses are denied or explicitly outside supported coverage, never silently forwarded.

Primary issues: #20-#22; full bidirectional restoration is the collective exit, not #21 alone.

### 4. Agent surfaces

Goal: MCP request/result protection, file and shell boundaries, CLI harness launcher, then additional provider/harness adapters against shared conformance tests.

Primary issues: #23-#26.

### 5. Enterprise hardening

Goal: workload identity, KMS/HSM operations, full multi-tenant hardening, tamper-evident audit, behavior signals, backup/recovery, network bypass resistance, policy exceptions, and incident response. Baseline tenant isolation, authentication and audit required by earlier slices are not deferred to this milestone; complete managed-egress claims wait for #32.

Primary issues: #27-#33.

### 6. Semantic long tail

Goal: extend earlier candidate sources and shadow judgment into evaluated contextual re-identification risk, deeper business/engineering classification, multimodal/nested content, and broader enterprise DLP/industrial information protection. Earlier #10-#12 work does not by itself authorize production re-identification claims.

Primary issues: #12 and #34, building on #10-#11.

### 7. Deployment profiles

Goal: package and verify local, customer VPC, on-premises and air-gapped capabilities against the boundaries proved above.

Primary issue: #35.

## Sequencing rule

A later integration does not bypass an unproved earlier boundary. For example, do not add five harness adapters before one gateway has proved normalization, classification, policy, egress sentinel, and end-to-end utility against the shared eval suite.

Foundation issues #1-#5 and the comparative campaign #38 may proceed in parallel. Freeze #39's synthetic comparison protocol against a minimal executable #5 evaluation seam before scored candidate comparisons. A disposable reference baseline is not an enforcement runtime or a reason to complete bespoke #6-#26 first.

Obtain the reviewed per-subsystem #48 reuse/wrap/buy/build/defer decision before committing to broad bespoke detector, proxy, vault, or adapter implementation. Unavailable critical evidence yields an explicitly unverified/deferred role, not an inferred security pass.

This evidence gate does not weaken the accepted contracts, Policy Engine, broker, or final egress boundary. Changes to implementation scope require explicit review before adoption; changes to accepted architectural direction also require a new decision record.

Each implementation issue states dependencies and acceptance criteria. The shared security/evaluation requirements in roadmap issue #36 apply to all implementation work.
