---
name: hylja-development
description: Run authorized Hylja development work as native Pi subagent lanes - one independent implementer, one independent reviewer. Use when the user delegates, parallelizes, reviews or hands off a Hylja task in this repository. Not for decisions needing a human design gate.
---

# Hylja development pipeline

Coordinator contract. Root orchestrates; children never do. Rules: [docs/development/pipeline.md](../../../docs/development/pipeline.md).

## Prerequisites

- Native Pi with `pi-subagents` loaded (`pi list`). Tested installation: pi-subagents 0.75.0 on Pi 1.0.0; 0.75.0 is the release that restored background children on Pi 1.0.0 after Pi dropped `@earendil-works/pi-agent-core/node`, and foreground children are unaffected either way. Global pstack skills are installed; this project's skill comes from `.agents/skills/`. Force it with `/skill:hylja-development`; `/reload` after edits.
- Role profiles are [`.pi/agents/hylja-implementer.md`](../../../.pi/agents/hylja-implementer.md) and [`.pi/agents/hylja-reviewer.md`](../../../.pi/agents/hylja-reviewer.md); their frontmatter is the configuration.
- One branch and one linked worktree per issue, never reused with unreviewed work.

## Principle loading

The principle files are installed with `disable-model-invocation: true`, so the extension filters them
out of child prompt injection: `skills:` entries deliver names, not contents. Both role prompts name
the paths and require a full read first. An unreadable path is INCOMPLETE.

## Workflow guard

Load [`.pi/extensions/hylja-workflow-guard.ts`](../../../.pi/extensions/hylja-workflow-guard.ts). Project
extension discovery loads it for this coordinator session, and each role profile lists it explicitly
under `extensions:` because an allowlist disables ambient extensions in a child. Confirm it is loaded
once per session (`pi list`) before dispatching a lane; an absent guard is a setup failure, not a
silently weaker run.

It refuses two things: a `find` whose search root is a machine-wide absolute root, and a malformed bash
timeout. It also guarantees every builtin bash call a finite timeout (120s default, 300s ceiling, a
tighter explicit value preserved). Refusals name the allowed roots and log no command, argument or
output.

Persistent operating rules, because a prompt alone did not stop the recurrence:

- The initial handoff uses the exact entry points already supplied: brief pointers, decision paths,
  `.pi/agents/`, this skill, `docs/development/pipeline.md`, and the three installed principle paths.
  Do not rediscover them by searching the machine.
- Search a filesystem only when a pointer is absent, and then only inside the repository worktree or a
  root named in the brief or in these paths (for example the home directory holding the installed
  skills). Scoped `find .`, `find src` and `grep` stay allowed.
- A guard refusal is a setup finding: use the exact path you were given, or report that the pointer is
  missing. Never retry the same search in another quoting, wrapper or executable form.
- Root owns the wall clock. Watch public tool progress in the session and stop a command that has run
  past its named budget instead of waiting for the deadline; the guard's timeout bounds a single call,
  not the lane budget.

It is a workflow guard, not a shell sandbox or a command parser: dynamic expansion, `eval`, aliases,
value-taking wrappers, indirect execution and other APIs are outside it, and it proves nothing about
what a permitted command does.

## Native lane controller (optional, no coordinator turn)

`node scripts/development/run-native-lane.mjs --config <absolute config.json>` runs one lane with no
coordinator-model turn: the CLI launches Pi once with the installed `pi-subagents`, the project workflow
guard and the opt-in controller `.pi/lib/hylja-native-lane.ts`, and the controller answers the single
fixed input `hylja-native-lane` through the documented foreground delegation API. Give it the role,
worktree, task, a deadline no greater than that profile's, the session and evidence paths, and the exact
`pi`, `subagents`, `guard` and `controller` paths. There is no model override (a `model` key is refused),
no background mode, no role fallback and no nesting. Read
[pipeline.md](../../../docs/development/pipeline.md#native-lane-controller-no-coordinator-model-turn) for
the evidence it requires and for its stated limits: completed is not approved, missing or mismatched
runtime evidence is a setup failure, and no speedup has been measured.

## Admit

1. Take issues whose brief states outcome, pointers, scope, acceptance, invariants, exact verification commands, prerequisites and human gates. Form: `.github/ISSUE_TEMPLATE/agent-task.yml`.
2. Admit only independent issues. Root dispatches the admitted lanes concurrently, in their own worktrees, when its host supports concurrent native sessions; gated work runs one lane at a time and never fakes parallelism. You own isolation, merge and closure. Children never push, merge or close.

## Implement lane

`subagent({ agent: "hylja-implementer", task: <brief>, cwd: <worktree>, async: false })`.

A foreground native child is the default: root launches the lane and the result arrives in-session. Pinned to `opencode-go/space-bunny-free:max`, 20-minute deadline, fresh context, `AGENTS.md` inherited, three principles read explicitly, ambient extensions off with the workflow guard as the only allowlisted one, no nested agents. Required before the lane ends: red test first for a contract change, green verification commands, a commit. Anything unmet ends INCOMPLETE with the reason, never an implicit pass.

## Review lane

Only after the implementer commit exists, one independent review of that exact SHA:
`subagent({ agent: "hylja-reviewer", task: <SHA, brief, changed surface>, cwd: <worktree>, async: false })`.

Pinned to `openai-codex/gpt-6.1-sol:max`, 15-minute deadline, read and `bash` only, with the workflow guard loaded as its one allowlisted extension. It reviews that exact SHA and changed surface from source, not the author's claims, reuses unchanged evidence by identity, and batches every actionable finding. A blocker cites a contract, a source location or a reproduction.

Verdicts: APPROVED, CHANGES REQUESTED, INCOMPLETE. Expiry, a missing verdict or an unresolved error is
INCOMPLETE; approval is never inferred from silence.

## Two-round limit

After two failed review rounds on one task, stop patching. Reframe, root-cause, or take the question to a
human first. A fresh run does not reset the count.

## Transient failures

Wait 2.5 seconds and retry unchanged, same session, provider and model, while the budget lasts. No
fallback. Record an unresolved failure honestly. `async: true` is optional here: the one background run
in this installation outlived its budget and was never proven, so no lifecycle, ordering or timing is
promised for it.

## Evidence, pause, reporting

Evidence for a finished lane, or the record a review handoff needs: which paths to read, and what the
handoff must name. [pipeline.md](../../../docs/development/pipeline.md#evidence-lookup).

Keep author and reviewer minutes, context size, command durations, retries, rounds and states in the
pull request evidence. A user pause cancels owned work, preserving evidence and worktrees; setup never
resumes product work. Report what ran, with real counts and the unproven surface. Claim no unmeasured
throughput gain.
