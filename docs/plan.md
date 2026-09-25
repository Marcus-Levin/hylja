# Development plan

This plan is the single authoritative home for implementation status. Architecture and specifications describe accepted behavior; they do not prove implementation.

## Current state

**Foundation established; implementation not started.** Product direction, architecture, security model, threat model, contracts, evaluation policy, synthetic examples, and the dependency-ordered implementation backlog are now in the repository. The TypeScript source contains no enforcement runtime and must not be represented as a privacy boundary.

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
