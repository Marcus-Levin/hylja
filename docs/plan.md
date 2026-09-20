# Development plan

This plan is the single authoritative home for implementation status. Architecture and specifications describe accepted behavior; they do not prove implementation.

## Current state

**Foundation only.** Product direction, architecture, security model, threat model, contracts, evaluation policy, synthetic examples, and implementation backlog are being established. The TypeScript source contains no enforcement runtime and must not be represented as a privacy boundary.

## Dependency-ordered milestones

### 0. Foundation and executable contracts

Goal: establish TypeScript toolchain, normalized interaction envelope, classification model, policy vocabulary, deterministic security invariants, and synthetic eval harness.

Exit evidence:

- strict TypeScript build and tests;
- synthetic fixtures only;
- contract/property tests for tenant isolation, blocked-secret behavior, and fail-closed policy;
- threat model mapped to tests.

### 1. Text cloaking proof

Goal: local text request -> deterministic detection -> semantic shadow judgment -> policy -> transformation -> independent egress check.

Initial categories: PERSON, EMAIL/PHONE, CREDENTIAL_OR_SECRET, HOST, IP/URL, CUSTOMER/PROJECT.

No production vault yet beyond minimal development fixture state.

### 2. Reversible identity and vault

Goal: encrypted scoped mappings, entity consistency, brokered USE/DISPLAY operations, lifecycle/retention, and exact authorized round-trip restoration.

### 3. Model gateway proof

Goal: OpenAI-compatible local gateway using the same core contracts, streaming policy, inbound/outbound enforcement, destination profiles, and audit evidence.

### 4. Agent surfaces

Goal: MCP request/result protection, file and shell boundaries, CLI harness launcher, then additional provider/harness adapters against shared conformance tests.

### 5. Enterprise hardening

Goal: workload identity, KMS/HSM integration, multi-tenancy, tamper-evident audit, behavior signals, backup/recovery, network bypass resistance, policy exceptions, incident response, and deployment profiles.

### 6. Semantic long tail

Goal: contextual re-identification risk, business/engineering classification, multimodal/nested content, and broader enterprise DLP/industrial information protection.

## Sequencing rule

A later integration does not bypass an unproved earlier boundary. For example, do not add five harness adapters before one gateway has proved normalization, classification, policy, egress sentinel, and end-to-end utility against the shared eval suite.

Implementation work is tracked in GitHub Issues. Each issue states dependencies, security threats addressed, new attack surfaces, acceptance tests, and evaluation requirements.
