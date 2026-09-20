# Development plan

This plan is the single authoritative home for implementation status. Architecture and specifications describe accepted behavior; they do not prove implementation.

## Current state

**Foundation established; implementation not started.** Product direction, architecture, security model, threat model, contracts, evaluation policy, synthetic examples, and the dependency-ordered implementation backlog are now in the repository. The TypeScript source contains no enforcement runtime and must not be represented as a privacy boundary.

Implementation work is tracked from [roadmap issue #36](https://github.com/Marcus-Levin/hylja/issues/36), with scoped issues #1-#35 carrying their own dependencies and acceptance criteria.

## Dependency-ordered milestones

### 0. Foundation and executable contracts

Goal: establish TypeScript toolchain, normalized interaction envelope, classification model, policy vocabulary, deterministic security invariants, and synthetic eval harness.

Exit evidence:

- strict TypeScript build and tests;
- synthetic fixtures only;
- contract/property tests for tenant isolation, blocked-secret behavior, and fail-closed policy;
- threat model mapped to tests.

Primary issues: #1-#5.

### 1. Text cloaking proof

Goal: local text request -> deterministic detection -> semantic shadow judgment -> policy -> transformation -> independent egress check.

Initial categories: PERSON, EMAIL/PHONE, CREDENTIAL_OR_SECRET, HOST, IP/URL, CUSTOMER/PROJECT.

No production vault yet beyond minimal development fixture state.

Primary issues: #6-#13 and #19.

### 2. Reversible identity and vault

Goal: encrypted scoped mappings, entity consistency, brokered USE/DISPLAY operations, lifecycle/retention, and exact authorized round-trip restoration.

Primary issues: #14-#18.

### 3. Model gateway proof

Goal: OpenAI-compatible local gateway using the same core contracts, streaming policy, inbound/outbound enforcement, destination profiles, and audit evidence.

Primary issues: #20-#22.

### 4. Agent surfaces

Goal: MCP request/result protection, file and shell boundaries, CLI harness launcher, then additional provider/harness adapters against shared conformance tests.

Primary issues: #23-#26.

### 5. Enterprise hardening

Goal: workload identity, KMS/HSM integration, multi-tenancy, tamper-evident audit, behavior signals, backup/recovery, network bypass resistance, policy exceptions, incident response, and deployment profiles.

Primary issues: #27-#33 and #35.

### 6. Semantic long tail

Goal: contextual re-identification risk, business/engineering classification, multimodal/nested content, and broader enterprise DLP/industrial information protection.

Primary issues: #10-#12 and #34.

## Sequencing rule

A later integration does not bypass an unproved earlier boundary. For example, do not add five harness adapters before one gateway has proved normalization, classification, policy, egress sentinel, and end-to-end utility against the shared eval suite.

Each implementation issue states dependencies and acceptance criteria. The shared security/evaluation requirements in roadmap issue #36 apply to all implementation work.
