# Development pipeline

Coordinator procedure for authorized Hylja delegation: one implementer, one independent reviewer.
Ordinary direct execution remains the default in [AGENTS.md](../../AGENTS.md). This procedure adds no
runtime contract, security boundary or evaluation authority.

Configuration belongs in the frontmatter of [hylja-implementer.md](../../.pi/agents/hylja-implementer.md),
[hylja-reviewer.md](../../.pi/agents/hylja-reviewer.md) and the dedicated
[writer fallback](../../.pi/agents/hylja-implementer-sol61.md). Read those profiles before launch;
requested settings are not evidence of the model, tools or extensions that actually ran.

## Coordinator procedure

1. **Admit one outcome.** Use the [issue brief](../../.github/ISSUE_TEMPLATE/agent-task.yml): observable
   outcome, source pointers and decision status lines, scope and non-goals, behavioral acceptance,
   unchanged invariants, exact checks, prerequisites, human gates and delivery budget. Defer adjacent
   work; an unmet human gate on the critical path blocks admission.
2. **Reserve the finish.** Before the first setup attempt, record the task's start and absolute UTC
   deadline if imposed, otherwise "no task deadline"; record role/native lane limits separately.
   Record command caps, finishing reserves and [retry policy](pipeline-reference.md#retry-and-fallback-policy).
   Setup, contact, waits and recovery count toward applicable task/lane limits. A lane's hard stop is
   the earliest applicable task, role or native runtime deadline; a resume or new child does not renew
   the task window or an expired lane. Re-scope before
   dispatch if the complete outcome cannot fit; required checks are not optional work.
3. **Prepare setup.** Allocate a branch/worktree per issue. In the effective child checkout, verify
   base, owned state, executable agent discovery, required paths, dependencies and pinned toolchain.
   Reuse an unreviewed tree only through an explicit recovery handoff binding its exact source and
   retained failures. Plan one initial in-lane guard qualification: coordinator `pi list`, profile
   declarations and source composition alone do not qualify a child. Setup failure stops dependent
   work, not by substituting another model, provider or harness.
4. **Hand off once.** Supply the admitted brief, exact cwd/base, permitted routine actions, remaining
   clock and finishing reserve, applicable retry policy and returned evidence paths. Declare any
   expected missing evidence. Resolve prerequisites before launch, rather than making the worker
   repeatedly ask for paths or ordinary permissions. Workers read their role body, `AGENTS.md`,
   principles and relevant inputs before dependent steps; they need neither this page nor the skill.
5. **Execute.** For authorized multi-step or parallel delegation, use one top-level native async
   workflow; children launch inside it under their declared profiles. Isolate concurrent writers;
   dependency-gated work is sequential. Qualify the guard's native load and
   [effective command ceiling](pipeline-reference.md#workflow-guard) in the initial setup before
   expensive validation. Consume native completion notifications without polling or automatic
   successor launches. Before admitting each command, observe current UTC and require
   `now + command cap + remaining required lane work + reporting margin <= lane hard stop`;
   also require remaining delivery work (including review/publication) to fit the task deadline, if
   imposed. Recheck at delivery: an expired conditional approval is refusal, not permission. If the
   remaining outcome no longer fits, stop and report it; no silent deadline or budget reset.
6. **Check readiness, then review.** Inspect the author's actual terminal receipt, scoped committed
   tree and complete required-check evidence. A report, `ok: true` or partial green run alone is not
   readiness; required native acceptance must actually have been evaluated and passed. Only then
   dispatch a fresh independent reviewer of the exact clean SHA and scoped base-to-head diff, with
   the brief and retained RED/GREEN paths. Reviewer behavior and verdict criteria live in its role
   body. A wider panel needs a concrete contested design question, not routine validation.
7. **Close the loop.** Record APPROVED, CHANGES REQUESTED or INCOMPLETE with the actual reason. An
   expired review, unresolved provider error or missing required evidence is INCOMPLETE, never
   approval. Two failed review rounds end the patch loop; retain that count across recovery and
   reframe, root-cause or escalate the design question. Preserve failed evidence and source refs.
   Review binds the final tree: cosmetic intermediate history is not a new gate; lost blobs, merge
   conflicts and unmet acceptance still block. Stop over-budget owned work through supported exact
   handles; on user pause preserve work and evidence, and let setup grant no restart authority.
8. **Publish and report.** Root publishes alone. An authorized reviewable draft PR may precede
   approval and CI; merge/release still requires explicit user authorization, exact-head approval and
   green CI there. Close issues only when acceptance is satisfied. Keep a compact evidence record in
   the PR or owning research record: SHA and outcome, command exits/counts/durations, raw receipt
   paths, author/reviewer time, retries/rounds, actual serving metadata, separate usage counters and
   unproven surface. Checkpoints report working, committed/reviewed, blocking and remaining-fit
   facts—not tool-call volume. Verify merged content before cleaning only owned branches/worktrees;
   leave unmerged work preserved.

## Disclosed reference

Read only the branch needed:

- [Install and use](pipeline-reference.md#install-and-use): skill invocation and installation.
- [Workflow guard](pipeline-reference.md#workflow-guard): native load and exact-command approval.
- [Retry and fallback policy](pipeline-reference.md#retry-and-fallback-policy): standing defaults,
  overridden by task/session restrictions; no automatic role fallback.
- [Evidence lookup](pipeline-reference.md#evidence-lookup): returned artifact paths and attribution.
- [Native lane CLI](pipeline-reference.md#native-lane-cli): optional root-owned single-lane transport,
  not a fallback for a failed governed workflow without explicit authorization.

## Limits

The clock checks above are coordinator obligations, not new executable guards. Existing tool caps and
native timeouts do not prove hard preemption, descendant closure or private containment. No speedup
has been measured; completed is not approved, and AI review is not human design adoption.
