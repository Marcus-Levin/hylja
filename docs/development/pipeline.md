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

Prerequisite: native Pi with `pi-subagents` loaded (`pi list`). Role configuration is the frontmatter of
[`.pi/agents/hylja-implementer.md`](../../.pi/agents/hylja-implementer.md) and
[`.pi/agents/hylja-reviewer.md`](../../.pi/agents/hylja-reviewer.md); `~/.agents/pstack-models.md` is
untouched. Tested installation: pi-subagents 0.75.0 on Pi 1.0.0, whose release notes record the fix for
background children failing on Pi 1.0.0 with a missing `@earendil-works/pi-agent-core/node` export;
0.74.0 does not work on Pi 1.0.0. Foreground children do not depend on that fix. No extra script or
package is added to this repository.

- Interactive: `/skill:hylja-development` forces the project skill; `/reload` after editing it.
- Headless: `--no-skills --skill .agents/skills/hylja-development` loads only that skill; without
  `--no-skills`, every discovered global skill is also eligible for automatic selection.
- Grant project trust once: `/trust`, or `--approve`.
- Launch: `subagent({ agent: "hylja-implementer", task: <brief>, cwd: <worktree>, async: false })`. Both role profiles set `async: false`, so a lane is a foreground native child and its result returns in-session. Each profile's `extensions:` value is an allowlist rather than empty, so ambient extension loading stays disabled in the child while the project workflow guard loads; builtin tools, the providers the host registered, and host-required child extensions still load.

Another checkout needs no installer: copy each `principle-*/SKILL.md` from the pinned upstream pstack
commit into `~/.agents/skills/<name>/`, MIT license kept.

## Workflow guard

`.pi/extensions/hylja-workflow-guard.ts` is a Pi adapter over the pure helper
`.pi/lib/hylja-command-guard.mjs`; both are developer tooling, and neither is in the tracked typecheck
or build scope (`tsconfig.json` includes `src/**/*.ts`). It exists because one run spent eight minutes
on `find / -name hylja-implementer.md` after the exact path had been supplied; a prompt alone did not
prevent the recurrence.

Two guarantees, both decided before the tool executes, both logged nowhere:

| Call | Decision |
|---|---|
| `find` with a machine-wide absolute root | blocked with a fixed reason naming the allowed roots |
| `timeout` omitted | set to 120 s, Pi's builtin bash having no default |
| `timeout` present, 0 < t <= 300 | preserved unchanged |
| `timeout` > 300 s | clamped to 300 s |
| `timeout` malformed, non-finite or <= 0 | blocked with a fixed reason |
| any other tool | untouched |

Wiring: project extension discovery loads it for the coordinator (`<cwd>/.pi/extensions/`), and both
role profiles declare `extensions: ../extensions/hylja-workflow-guard.ts`, an allowlist that keeps
ambient extensions off in a foreground child while the host-required child extensions, the registered
providers and the builtin tools still resolve. The relative entry resolves against the agent file's own
directory, which is what pi-subagents does for a path-like `extensions` entry; the profiles' other
settings are unchanged.

Limits, stated so no one reads more into it: it is a workflow guard, not a shell sandbox, a command
parser or an enforcement boundary. It splits a command textually on control separators and whitespace,
strips quotes and inspects only the leading tokens of each segment. Dynamic expansion, `eval`, aliases,
value-taking wrappers, indirectly invoked `find`, MCP or another harness that reaches a shell, and any
other API are outside it; the timeout default still bounds those calls, and nothing proves a permitted
command is safe, bounded or correct. Unlisted absolute roots, `/tmp` and `$HOME`-relative searches are
allowed on purpose, so the guard cannot block scoped repository discovery or the installed skill paths.

Evidence: `node --test test/hylja-workflow-guard.test.mjs` exercises the helper and the adapter
directly, including the exact command shape that failed, quoted and absolute-executable variants, scoped
discovery, the timeout default, preservation, clamp and refusal, that no other tool is mutated, and that
each role profile's declared path resolves to an existing file. The load path itself is proven by a
native smoke run, not by this document.

## Admission and concurrency

The coordinator admits only *ready* issues: an accepted brief and no unmet human gate on its critical
path. Root dispatches admitted lanes as independent foreground sessions in their own worktrees,
concurrently where its host supports concurrent native sessions; gated work runs one lane at a time, and
parallelism is never faked. It owns isolation, merge and closure; children never push, merge or close.
One routine reviewer per task, launched after the implementer commit exists; a wider panel only for a
concrete contested design question.

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

`async: true` is an optional mode, not the pipeline default: the single background run in this
installation exceeded its budget without a result, so this document promises no background lifecycle,
ordering or timing.

## Limits

Nothing here is measured: no throughput, cost or defect-rate improvement is claimed. Pins, deadlines
and verdicts are configuration and prompt contracts, not enforcement boundaries. The workflow guard
removes one observed stall; it is not a measured gain and it is not a safety property.

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