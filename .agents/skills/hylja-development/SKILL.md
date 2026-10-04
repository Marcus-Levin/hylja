---
name: hylja-development
description: Run authorized Hylja development work as native Pi subagent lanes - one independent implementer, one independent reviewer. Use when the user delegates, parallelizes, reviews or hands off a Hylja task in this repository. Not for decisions needing a human design gate.
---

# Hylja development pipeline

Coordinator-only entrypoint. Root orchestrates and publishes; children never push, merge, edit or
close an issue or pull request. The coordinator procedure, its stop conditions and its publish gates
are [docs/development/pipeline.md](../../../docs/development/pipeline.md). Read that page before
dispatching a lane.

Role configuration is the frontmatter of [hylja-implementer.md](../../../.pi/agents/hylja-implementer.md)
and [hylja-reviewer.md](../../../.pi/agents/hylja-reviewer.md): the model and deadline pins, the tool
allowlists, the three-principle list, `async: false`, the workflow-guard `extensions:` entry and the
acceptance roles. Read a profile rather than this page for those.

Dispatch a worker with a handoff that carries the outcome, the exact pointers with their decision
status lines, scope and non-goals, the exact verification commands, the budget, the retained
evidence paths and every human gate. That handoff is enough for the worker: it reads its role body,
`AGENTS.md`, its named pointers and its commands, and needs neither this skill nor the pipeline page.

Force the project skill with `/skill:hylja-development` after `/reload`; confirm the workflow guard
loaded once (`pi list`) before dispatch. Installation, guard behaviour, evidence lookup, the optional
root-owned [native lane CLI](../../../docs/development/pipeline-reference.md#native-lane-cli), the
historical #147 proposal and the stated limits are in
[pipeline-reference.md](../../../docs/development/pipeline-reference.md).