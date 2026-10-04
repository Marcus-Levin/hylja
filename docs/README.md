# Documentation

Hylja follows the same documentation discipline used in Verdande: product direction, accepted architecture, current capability, research, contracts, and evaluation evidence are separate so that one concept has one authoritative home.

## Start here

- [Capabilities and limits](capabilities.md) - what the software implements today and what it does not. Read before changing or evaluating the implementation.
- [Task route map](#task-route-map) - the exact entry points for a given kind of work.

## Steering

- [Charter](charter.md) - promise, first proof, and initial limits.
- [Architecture](architecture.md) - trust zones, planes, ownership, and data flows.
- [Security model](security-model.md) - crown jewels, invariants, authorization, crypto boundaries.
- [Threat model](threat-model.md) - attackers, abuse cases, and required mitigations.
- [Evaluation policy](evaluation.md) - corpora, metrics, champion/challenger, shadow promotion.

## Domain design

- [Classification](classification.md) - semantic classes, sensitivity, trust, provenance.
- [Flow control](flow-control.md) - source-to-sink policy and destination profiles.
- [Cloaking](cloaking.md) - transformations, fidelity, identity consistency, contextual re-identification.
- [Vault](vault.md) - storage, encryption, brokered resolution, retention, integrity.
- [Interactions](interactions.md) - model, tool, MCP, file, shell, skill, memory, web, and agent events.
- [Integrations](integrations.md) - harness/provider adapters and coverage levels.
- [Deployment](deployment.md) - local, VPC, on-premises, SaaS, and air-gapped models.
- [Operations](operations/README.md) - runtime failure, audit, incident, backup, and recovery guidance.
- [References](references.md) - primary security, privacy, Jev, and inspiration sources.

## Task route map

Each row is the starting point for one kind of work, not a status list. [Capabilities and limits](capabilities.md) holds what the software does today; GitHub issues (with [#36](https://github.com/Marcus-Levin/hylja/issues/36) as the roadmap checklist) hold status, priority and dependency order.

| If the task is about | Read first | Then | Language |
|---|---|---|---|
| Detection, normalization, parsers, candidate sources, classification units | [classification.md](classification.md), [classification-contract.md](contracts/classification-contract.md), [classification-unit-contract.md](contracts/classification-unit-contract.md) | [`src/normalized-detection.ts`](../src/normalized-detection.ts), [`src/structured-parsers.ts`](../src/structured-parsers.ts), [`src/contact-candidates.ts`](../src/contact-candidates.ts) and the focused tests named in [capabilities.md](capabilities.md#capabilities) | TypeScript core |
| Policy, authorization, governance, exceptions | [flow-control.md](flow-control.md), [policy-contract.md](contracts/policy-contract.md), [policy-governance-contract.md](contracts/policy-governance-contract.md) | [`src/policy.ts`](../src/policy.ts), [`src/policy-governance.ts`](../src/policy-governance.ts) | TypeScript core |
| The final-byte egress check or its known limits | [threat-model.md](threat-model.md#priority-abuse-cases), [evaluation.md](evaluation.md#independent-egress-sentinel) | [`src/egress-sentinel.ts`](../src/egress-sentinel.ts) module header | TypeScript core |
| Semantic judgment, re-identification, champion/challenger | [evaluation.md](evaluation.md), [semantic-judge-shadow.md](contracts/semantic-judge-shadow.md), [reidentification-shadow.md](contracts/reidentification-shadow.md), [champion-replay-contract.md](contracts/champion-replay-contract.md) | [`src/semantic-judge-shadow.ts`](../src/semantic-judge-shadow.ts), [`src/reidentification-shadow.ts`](../src/reidentification-shadow.ts), [`src/champion-replay.ts`](../src/champion-replay.ts) | TypeScript core |
| Adapters and a harness/provider surface | [integrations.md](integrations.md), [adapter-contract.md](contracts/adapter-contract.md), [interaction-envelope.md](contracts/interaction-envelope.md) | [`src/interaction-envelope.ts`](../src/interaction-envelope.ts), [`src/adapter-conformance.ts`](../src/adapter-conformance.ts) | TypeScript core |
| Audit, release integrity, SBOM, dependencies | [audit-ledger-contract.md](contracts/audit-ledger-contract.md), [release-integrity-contract.md](contracts/release-integrity-contract.md) | [`src/audit-ledger.ts`](../src/audit-ledger.ts), [`src/release-integrity.ts`](../src/release-integrity.ts) | TypeScript core |
| Public evaluation scaffolding and preparation integrity | [evaluation.md](evaluation.md), [synthetic-evaluation-seam.md](contracts/synthetic-evaluation-seam.md) | [`evaluations/README.md`](../evaluations/README.md) | JavaScript (Node ESM) |
| Synthetic end-to-end evidence runs, or the gated M1/M2/M3 path they do not cover | [development/synthetic-e2e.md](development/synthetic-e2e.md) | the three evidence contracts it routes: [openai-request-sendpoint-e2e.md](contracts/openai-request-sendpoint-e2e.md), [openai-response-inspection-e2e.md](contracts/openai-response-inspection-e2e.md), [mapping-roundtrip-e2e.md](contracts/mapping-roundtrip-e2e.md); the dated [E2E critical-path proposal](development/proposals/2026-10-04/e2e-critical-path.md) (proposal, not authority) | JavaScript (Node ESM, test-only) over the TypeScript core |
| The pinned Presidio worker, manifest or trial | [`evaluations/presidio-worker/README.md`](../evaluations/presidio-worker/README.md) | [`evaluations/README.md`](../evaluations/README.md) | **Python worker**, JS transport/bridge |
| Package screening, provenance verification, sandbox helpers | [`scripts/research/README.md`](../scripts/research/README.md) | [`docs/research/issue-46-presidio-provenance-runtime-prescreen-2026-10-01.md`](research/issue-46-presidio-provenance-runtime-prescreen-2026-10-01.md) | **Python** (research-only, outside CI) |
| Bounded developer handoffs: capability report, GitHub projection, large-document comparison, session inventory | [`development/agent-handoff.md`](development/agent-handoff.md) | [`scripts/development/agent-handoff.mjs`](../scripts/development/agent-handoff.mjs) | JavaScript (Node ESM, outside the core) |
| Delegating development work: writer/reviewer lanes, issue brief contract, review rounds, evidence ledger | [`development/pipeline.md`](development/pipeline.md) | [`.agents/skills/hylja-development/SKILL.md`](../.agents/skills/hylja-development/SKILL.md), [`.pi/agents/hylja-implementer.md`](../.pi/agents/hylja-implementer.md), [`.pi/agents/hylja-reviewer.md`](../.pi/agents/hylja-reviewer.md), [`.github/ISSUE_TEMPLATE/agent-task.yml`](../.github/ISSUE_TEMPLATE/agent-task.yml) | Markdown and YAML (developer tooling, native Pi) |
| Proposed information dimensions or task fidelity (#65/#66/#68) | [decision 010](decisions/010-separate-information-dimensions-and-task-fidelity.md) - read its **status line first** | [information-model-draft.md](contracts/information-model-draft.md), [transformation-semantics-draft.md](contracts/transformation-semantics-draft.md), [`src/information-model-draft.ts`](../src/information-model-draft.ts), [`src/taxonomy-draft.ts`](../src/taxonomy-draft.ts) | TypeScript, **proposed/unwired** |
| The human annotation/active-learning proposal | [specs/gym-annotation-design.md](specs/gym-annotation-design.md) | [`evaluations/gym-annotation-schema.mjs`](../evaluations/gym-annotation-schema.mjs) | JavaScript, **proposed/unwired** |
| Comparative, reuse or adoption evidence | [research/](research/) dated records (evidence, not authority) | the issue it supports: [#38](https://github.com/Marcus-Levin/hylja/issues/38), [#39](https://github.com/Marcus-Levin/hylja/issues/39), [#48](https://github.com/Marcus-Levin/hylja/issues/48) | Markdown records |
| Retired development-plan history | [docs/plan.md](plan.md) | the immutable snapshot it links | Markdown, frozen |

The core is TypeScript on Node.js and provider- and harness-independent. Python appears only in the pinned upstream Presidio worker and in research-only Python helpers; neither is part of the core, `npm test` or CI. Proposed drafts are **not** accepted: read the status line of every decision and draft you rely on, and never wire one into accepted classification v1, policy, an adapter or authoritative labels.

## Decisions - `decisions/`

Accepted architectural decisions are numbered sequentially. New evidence that changes an accepted direction gets a new decision or an explicit superseding note. A decision marked **proposed** has no authority until a human reviewer accepts it. Issue numbers and decision numbers are separate series.

## Contracts - `contracts/`

Stable interfaces shared by core components and adapters. Contracts define observable behavior without prescribing a specific implementation library.

## Specifications - `specs/`

Implementation slices in dependency order. A specification may be draft, accepted, implemented, or superseded. What is implemented lives in [capabilities.md](capabilities.md).

## Examples - `examples/`

Synthetic examples only. Examples illustrate expected behavior but do not establish policy or implementation status.

## Research - `research/`

Investigations and source records, dated and attributed. Research may motivate a decision but is not itself authority.

## Retired - `plan.md`

[Development plan](plan.md) was retired. Its dated evidence is preserved byte-for-byte at an immutable Git commit that `plan.md` links; it is a historical snapshot, not current state.
