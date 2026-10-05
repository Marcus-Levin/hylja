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
[`.pi/agents/hylja-implementer.md`](../../.pi/agents/hylja-implementer.md),
[`.pi/agents/hylja-reviewer.md`](../../.pi/agents/hylja-reviewer.md) and the dedicated writer
fallback [`.pi/agents/hylja-implementer-sol61.md`](../../.pi/agents/hylja-implementer-sol61.md).

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
   time, and parallelism is never faked. One branch and worktree per issue keeps lanes isolated. The
   implementer lane ends only with a green run of every brief-specified command plus a commit; a known
   failure, a partial build or a missing prerequisite ends it INCOMPLETE with its reason.
5. **Review.** After the implementer commit exists, one independent review of that exact SHA:
   `subagent({ agent: "hylja-reviewer", task: <SHA, brief, changed surface>, cwd: <worktree>, async: false })`.
   It confirms `git rev-parse HEAD`, reads the diff and changed sources, trusts source over the
   author's summary, reuses prior-round evidence only where identity (SHA, blob, path, contract
   version) is unchanged, and returns every actionable finding of the round at once, separating an
   introduced regression from a pre-existing follow-up. A blocker cites a contract clause, a source
   location or a reproduction; no open-ended probe sweep. A wider panel only for a concrete contested
   design question. **Reviewed surface:** review binds the final clean source SHA and the scoped
   base-to-head diff. Unpublished intermediate document history is not a publication gate: root does
   not amend, squash, rebase or reopen a settled decision just to polish intermediate commits when the
   final artifact and its acceptance proof are correct. A real merge conflict, a lost blob or an
   unmet acceptance criterion still blocks. Source refs and failed-round evidence are preserved either
   way, and the exact-head, green-CI and owned-cleanup requirements of step 8 are unchanged.
6. **Verdict.** `APPROVED`, `CHANGES REQUESTED` or `INCOMPLETE`. The run deadline is terminal, so an
   expired review has no verdict and the coordinator records INCOMPLETE. Silence, a timeout or an
   unresolved provider error is never approval.
7. **Stop conditions.** Two failed review rounds on one task end the patch loop: reframe, root-cause,
   or take the design question to a human, and keep the failed-round count across a fresh run. A
   transient provider error waits 2.5 s and retries unchanged, same session, provider and model, with
   no fallback; record an unresolved failure with its message. One exception is authorized and
   explicit: after the default writer route has actually failed, not merely returned exit 2 or an
   INCOMPLETE verdict, and the previous child has settled, root may dispatch
   `subagent({ agent: "hylja-implementer-sol61", ... })` in a fresh lane. It preserves the failed
   lane's worktree evidence and its uncommitted work, uses fresh context and fresh evidence paths, and
   never re-routes a run by itself. Root owns the wall clock and stops a command that passes its named
   budget. A user pause cancels owned work and preserves evidence and
   worktrees; setup never resumes product work.
8. **Publish and close.** Root publishes alone. An authorized reviewable draft pull request is created
   and published for review before approval and CI; merging or releasing it still requires the user's
   explicit authorization, approval of the exact head and green CI at that head. That approval binds
   the whole published tree at that head, not the shape of the commits underneath it. Close an issue
   only when its acceptance criteria are satisfied. After the merged content is verified to have
   landed, root
   removes only the branches and worktrees it owns, preserving commits, evidence and needed commit
   references, and leaving unmerged work in place.
9. **Report.** Record in the pull request evidence: author and reviewer minutes, command durations,
   retries, rounds and per-round states; the model that ran, read from the run metadata's `model`
   field rather than a requested model or a frontmatter intent; and usage counters kept apart from a
   live context-window figure. Claim no unmeasured throughput, cost or defect-rate gain.

## Evidence lookup

Read the exact paths the launch supplied, never a filename rebuilt from a remembered pattern. A
supplied path that resolves to nothing is reported as unavailable, not replaced by a wider search.
[Handoff and artifact detail](pipeline-reference.md#evidence-lookup).

## Optional: the native lane CLI

Root may instead run one lane through `node scripts/development/run-native-lane.mjs --config <absolute
config.json>`, which launches Pi itself, so no coordinator model turn carries the lane. Its config,
the evidence it requires, and its bounds are
[Native lane CLI](pipeline-reference.md#native-lane-cli), read only on that branch. It adds no
authority, invariant or gate: completed is not approved, and no speedup has been measured.

## Limits

Nothing here is measured. Pins, deadlines and verdicts are configuration and prompt contracts, not
enforcement boundaries. The workflow guard removes one observed stall; it is not a measured gain and
not a safety property. [Guard behaviour and its stated limits](pipeline-reference.md#workflow-guard).