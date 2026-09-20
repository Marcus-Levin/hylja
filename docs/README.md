# Documentation

Hylja follows the same documentation discipline used in Verdande: product direction, accepted architecture, implementation status, research, contracts, and evaluation evidence are separate so that one concept has one authoritative home.

## Steering

- [Charter](charter.md) - promise, first proof, and initial limits.
- [Architecture](architecture.md) - trust zones, planes, ownership, and data flows.
- [Security model](security-model.md) - crown jewels, invariants, authorization, crypto boundaries.
- [Threat model](threat-model.md) - attackers, abuse cases, and required mitigations.
- [Development plan](plan.md) - current state and dependency-ordered implementation roadmap.
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

## Decisions - `decisions/`

Accepted architectural decisions are numbered sequentially. New evidence that changes an accepted direction gets a new decision or an explicit superseding note.

## Contracts - `contracts/`

Stable interfaces shared by core components and adapters. Contracts define observable behavior without prescribing a specific implementation library.

## Specifications - `specs/`

Implementation slices in dependency order. A specification may be draft, accepted, implemented, or superseded. Current implementation status remains in [plan.md](plan.md).

## Examples - `examples/`

Synthetic examples only. Examples illustrate expected behavior but do not establish policy or implementation status.

## Research - `research/`

Investigations and source records. Research may motivate a decision but is not itself authority.
