# Development pipeline

Delegating Hylja development work to independent native Pi subagents: one implementer, one reviewer,
coordinated by the root session. Developer tooling, not runtime core and not a security boundary:
`src/` imports nothing from it, it adds no dependency, executable or policy, and changes no contract,
security invariant or evaluation protocol. See [capabilities.md](../capabilities.md); rules stay in
[AGENTS.md](../../AGENTS.md).

This page is the coordinator procedure. Installation, workflow-guard behaviour, evidence-lookup
detail and the historical #147 proposal are disclosed in
[pipeline-reference.md](pipeline-reference.md) and are read only on those branches. Role pins,
deadlines, tool allowlists and the workflow-guard wiring are the frontmatter of
[`.pi/agents/hylja-implementer.md`](../../.pi/agents/hylja-implementer.md) and
[`.pi/agents/hylja-reviewer.md`](../../.pi/agents/hylja-reviewer.md).

## Roles and principle loading

Each role works in its own worktree with its own profile pins, and `bash` is the reviewer's
validation tool rather than an OS sandbox, which is why its prompt forbids mutating tracked files. The
three principle files carry `disable-model-invocation: true`, so `buildSkillInjection` filters them
out of every child prompt and a `skills:` entry delivers a name and no content. Both prompts name the
three installed paths and require a full read of each before task work, with INCOMPLETE when one is
missing. **Explicit reading is the mechanism; automatic injection is neither fixed nor relied on.**

## Coordinator procedure

1. **Confirm setup.** The coordinator session shows the workflow guard loaded once (`pi list`). An
   absent guard is a setup failure, not a silently weaker run.
2. **Admit.** Take only issues whose brief states outcome, pointers with decision status lines, scope
   and non-goals, acceptance as executable examples, invariants that must not change, exact
   verification commands, prerequisites and human gates:
   [.github/ISSUE_TEMPLATE/agent-task.yml](../../.github/ISSUE_TEMPLATE/agent-task.yml). Admit only
   independent issues with no unmet human gate on the critical path.
3. **Hand off.** Each handoff carries outcome, pointers, scope, exact commands, budget, retained
   evidence paths and human gates. A worker reads its role body, `AGENTS.md`, its named pointers and
   its commands; it needs neither this page nor the skill to do the work you handed it.
4. **Dispatch.** `subagent({ agent: "hylja-implementer", task: <brief>, cwd: <worktree>, async: false })`
   in a fresh branch and worktree per issue, never reused with unreviewed work. Run admitted lanes
   concurrently where the host supports concurrent native sessions; gated work runs one lane at a
   time, and parallelism is never faked. One branch and worktree per issue keeps lanes isolated.
5. **Review.** After the implementer commit exists, one independent review of that exact SHA:
   `subagent({ agent: "hylja-reviewer", task: <SHA, brief, changed surface>, cwd: <worktree>, async: false })`.
   It confirms `git rev-parse HEAD`, reads the diff and changed sources, trusts source over the
   author's summary, reuses prior-round evidence only where identity (SHA, blob, path, contract
   version) is unchanged, and returns every actionable finding of the round at once, separating an
   introduced regression from a pre-existing follow-up. A blocker cites a contract clause, a source
   location or a reproduction; no open-ended probe sweep. A wider panel only for a concrete contested
   design question.
6. **Verdict.** `APPROVED`, `CHANGES REQUESTED` or `INCOMPLETE`. The run deadline is terminal, so an
   expired review has no verdict and the coordinator records INCOMPLETE. Silence, a timeout or an
   unresolved provider error is never approval.
7. **Stop conditions.** Two failed review rounds on one task end the patch loop: reframe, root-cause,
   or take the design question to a human, and keep the failed-round count across a fresh run. A
   transient provider error waits 2.5 s and retries unchanged, same session, provider and model, with
   no fallback; record an unresolved failure with its message. Root owns the wall clock and stops a
   command that passes its named budget. A user pause cancels owned work and preserves evidence and
   worktrees; setup never resumes product work.
8. **Publish and close.** Root publishes alone, after the user's explicit authorization, approval of
   the exact head and green CI at that head. Close an issue only against its acceptance criteria.
9. **Report.** Record in the pull request evidence: author and reviewer minutes, command durations,
   retries, rounds and per-round states; the model that ran, read from the run metadata's `model`
   field rather than a requested model or a frontmatter intent; and usage counters kept apart from a
   live context-window figure. Claim no unmeasured throughput, cost or defect-rate gain.

## Evidence lookup

Read the exact paths the launch supplied, never a filename rebuilt from a remembered pattern. A
supplied path that resolves to nothing is reported as unavailable, not replaced by a wider search.
[Handoff and artifact detail](pipeline-reference.md#evidence-lookup).

## Limits

Nothing here is measured. Pins, deadlines and verdicts are configuration and prompt contracts, not
enforcement boundaries. The workflow guard removes one observed stall; it is not a measured gain and
not a safety property. [Guard behaviour and its stated limits](pipeline-reference.md#workflow-guard).