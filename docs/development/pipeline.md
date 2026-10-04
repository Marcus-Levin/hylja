# Development pipeline

Delegating Hylja development work to independent native Pi subagents: one implementer, one reviewer,
coordinated by the root session. Developer tooling, not runtime core and not a security boundary:
`src/` imports nothing from it, it adds no dependency, executable or policy, and changes no contract,
security invariant or evaluation protocol. See [capabilities.md](../capabilities.md); rules stay in
[AGENTS.md](../../AGENTS.md).

## Roles

| | Implementer | Reviewer |
|---|---|---|
| Model | `opencode-go/space-bunny-free:max` | `openai-codex/gpt-6.1-sol:max` |
| Deadline | 20 minutes | 15 minutes |
| Shape | fresh context, `AGENTS.md` inherited; read, grep, find, ls, edit, write, bash | fresh context; read, grep, find, ls, bash |

Both take only three pstack principles, `inheritSkills: false`, `allowNestedSubagents: false`. The
reviewer's `bash` is validation-only, not an OS sandbox, so its prompt forbids mutating tracked files.

## How the principles actually load

The three principle files are installed with `disable-model-invocation: true`, and
`buildSkillInjection` filters such skills out of every child prompt, even explicitly selected ones, so
a `skills:` entry resolves the name and delivers no content. Both role prompts name the three installed
paths and require a bounded read of each, in full, once, before task work, with INCOMPLETE if one is
missing or unreadable. **Explicit reading is the mechanism; automatic injection is neither fixed nor
relied on.**

## Install and use

Prerequisite: native Pi with `pi-subagents` loaded (`pi list`). Role configuration is the frontmatter
above; `~/.agents/pstack-models.md` is untouched.

- Interactive: `/skill:hylja-development` forces the project skill; `/reload` after editing it.
- Headless: `--no-skills --skill .agents/skills/hylja-development` loads only that skill; without
  `--no-skills`, every discovered global skill is also eligible for automatic selection.
- Grant project trust once: `/trust`, or `--approve`.
- Launch: `subagent({ agent: "hylja-implementer", task: <brief>, cwd: <worktree>, async: true })`.

Another checkout needs no installer: copy each `principle-*/SKILL.md` from the pinned upstream pstack
commit into `~/.agents/skills/<name>/`, MIT license kept.

## Admission and concurrency

The coordinator admits only *ready* issues: an accepted brief and no unmet human gate on its critical
path. It admits at most as many independent issues as it has free concurrency, never faking parallelism
on gated work. It owns isolation, merge and closure; children never push, merge or close.
One routine reviewer per task; a wider panel only for a concrete contested design question.

## Issue brief contract

Use [.github/ISSUE_TEMPLATE/agent-task.yml](../../.github/ISSUE_TEMPLATE/agent-task.yml): observable
outcome, pointers with decision status lines, bounded scope and non-goals, acceptance as executable
examples, invariants that must not change, exact verification commands, and real prerequisites and human
gates. Prefer a runnable example over a plan; never weaken a security contract or human gate.

## Implement, then verify

A contract change writes the failing behavior test first, keeps its red output, then goes green. The
lane ends only with a green run of the brief's exact commands and a commit; a known failure, a partial
build or a missing prerequisite ends it INCOMPLETE with its reason. Prose-only changes need no test; no
test greps implementation or prose.

## Review

The reviewer starts after an implementer commit exists and reviews that exact SHA and its changed
surface: it confirms `git rev-parse HEAD`, reads the diff and changed sources, and trusts source over
the author's summary. It reuses prior-round evidence only where identity (SHA, blob, path, contract
version) is unchanged. Each round returns every actionable finding at once, separates an introduced
regression from a pre-existing follow-up, and needs a contract clause, source location or reproduction
for a blocker; no open-ended probe sweep.

Verdicts: `APPROVED`, `CHANGES REQUESTED`, `INCOMPLETE`. The run-level deadline is terminal, so an
expired review has no verdict and the coordinator records INCOMPLETE. Silence, timeout or an
unresolved provider error is never approval.

## Two-round limit, retries, pause, evidence

After two failed review rounds on one task the patch loop stops: reframe, root-cause, or take the design
question to a human. A fresh run does not reset the count. A transient provider error waits 2.5 s and
retries unchanged, same session, provider and model, with no fallback; an unresolved failure is recorded
with its message. The ledger belongs with the pull request evidence, not a status file: author/reviewer
minutes, context size, command durations, retries, rounds and per-round states. A user pause cancels
owned work and preserves evidence and worktrees.

## Limits

Nothing here is measured: no throughput, cost or defect-rate improvement is claimed. Pins, deadlines
and verdicts are configuration and prompt contracts, not enforcement boundaries.

## Proposed execution brief for #147 (proposal, not applied)

For a human to accept before dispatch. It satisfies no acceptance item: the live checklist stays
authoritative, unsatisfied and blocking, and it adds no cancellation or timeout boundary.

**Outcome.** An optional one-check local Node subprocess wrapper around `checkEgress`: the parent can
withhold release, stay responsive and terminate a stalled check. Local lifecycle isolation only, not a
gateway, effect boundary, OS sandbox or RSS cap.

**Accepted authority.** [006](../decisions/006-adapter-first-multi-surface-core.md),
[007](../decisions/007-fail-closed-for-protected-egress.md),
[008](../decisions/008-minimize-raw-data-retention.md), the
[`src/egress-sentinel.ts`](../../src/egress-sentinel.ts) module header and its
[capabilities.md](../capabilities.md) row, and the bounded local subprocess pattern in
[`evaluations/README.md`](../../evaluations/README.md); read each status line first. Parent #88 stays
open; no proposed taxonomy or fidelity model is adopted.

**Bounded scope.** `src/egress-sentinel-process.ts`, `-worker.ts`, `-protocol.ts`,
`test/egress-sentinel-process.test.mjs`, `docs/contracts/egress-sentinel-process.md`, minimum Node shim
declarations, one capability row, one local-IPC limits clarification. No sentinel algorithm,
dependency, policy, test-budget, scheduling or provider-traffic change.

**Verifiable units, red then green.** (1) Protocol: framing, snapshot caps, response binding,
handle-registration refusals. (2) Worker and shims: fixed argv, minimal environment, one check per child.
(3) Lifecycle: spawn deadline, cancellation, stall termination, cleanup confirmation, quarantine.
(4) Snapshot copies: caller-mutation refusal, tenant/project/profile binding. (5) Tiny stdlib-only
synthetic child end to end: responsiveness, trickled-output deadline, positive control, restrictive
failures, planted diagnostic capture. (6) Contract, capability row, overhead limits.

**Commands**, existing [`package.json`](../../package.json) scripts: `npm ci --ignore-scripts
--no-fund`; per unit `npm run --silent build` then `node --test
test/egress-sentinel-process.test.mjs`; before review `npm run --silent check:fixtures`,
`npm run --silent check:docs`, `npm run --silent typecheck`, `npm test`, `npm run --silent
test:coverage`.

**Stops.** Product development is paused; this does not resume it. A genuine design
ambiguity in accepted authority stops the lane for a human; no required criterion moves into a
nonblocking design block.