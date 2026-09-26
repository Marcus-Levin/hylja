# Hylja

Hylja is a semantic information-control layer for AI and agentic systems. It protects sensitive information as data crosses trust boundaries while preserving enough structure and meaning for AI systems to remain useful.

The name comes from Old Norse *hylja*: to hide, cover, or conceal.

> Detection proposes. Semantic judgment understands. Policy decides. The vault remembers. The gateway enforces.

## Status

Foundation only. This repository currently defines product direction, security invariants, architecture, contracts, evaluation policy, and implementation slices. It does **not** yet provide a production privacy boundary.

Implementation status has one authoritative home: [docs/plan.md](docs/plan.md).

![Hylja concept illustration showing information cloaked between a source and an AI provider](docs/assets/hylja-concept.png)

## Start here

- [VISION.md](VISION.md) - product direction and experience.
- [CONTEXT.md](CONTEXT.md) - shared vocabulary.
- [docs/charter.md](docs/charter.md) - promise, first proof, and limits.
- [docs/architecture.md](docs/architecture.md) - trust zones, planes, components, and flows.
- [docs/security-model.md](docs/security-model.md) - crown jewels, invariants, and security boundaries.
- [docs/threat-model.md](docs/threat-model.md) - attacker model and abuse cases.
- [docs/evaluation.md](docs/evaluation.md) - evaluation and continuous-improvement policy.
- [docs/plan.md](docs/plan.md) - current state and dependency-ordered roadmap.
- [docs/README.md](docs/README.md) - documentation map.

## Intended surfaces

Hylja is designed to intercept more than ordinary chat. The architecture covers model input/output, tool calls/results, MCP, files, shell, skills, memory, web access, agent handoffs, and provider-specific harnesses.

## Technology direction

The reference implementation is TypeScript on Node.js. The core remains provider- and harness-independent; adapters translate native surfaces into normalized interaction events.

## Security posture

Hylja is designed as an enforcement system, not an advisory filter. Production guarantees must be backed by deterministic policy, cryptographic controls, auditable authorization, bounded failure behavior, and continuous evaluation. Jev or another semantic model may supply judgments, but it never grants authority by itself.
