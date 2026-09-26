# Invitation: independent engineering-task reviewer for a synthetic benchmark

**PUBLIC INVITATION — not an answer-key approval, custody appointment or score.** You do not need to know Hylja. It is an early research project about keeping a code/engineering assistant useful without revealing information that should stay private. These **made-up practice cases run in a local test setup**, not on live traffic or through a deployed privacy safeguard.

## What we would ask you to do

The *reference candidate* is the experimental program being tested. Independently write what a *correct engineering answer* to each public practice task would say; **do not derive the answer from that program's output**:

- **D01 support conversation:** preserve the correct escalation order and communication roles without requiring real or original contact details.
- **D02 diagnostic log:** identify the attempted-versus-expected HTTPS port mismatch and the relevant troubleshooting conclusion. If the privacy decision blocks the attempt, mark the task **unsolved**, not correctly diagnosed.
- **D05 JSON configuration:** check parseable JSON and the correct HTTPS endpoint/port, path, operating-system and output-file behavior using the altered task text the program actually receives, not original protected names.

You would judge whether each task was solved and how much useful detail its answer needs—not tune the program being tested. A **separately appointed scoring reviewer** must decide exactly how scores count matched information, leaks in text or metadata, unanswered tasks and severe failures. One person may volunteer for more than one role, but conflicts need disclosure and independent review; two invitations alone do not approve the full test plan. If the local test destination was not reliably monitored, a missing capture is **untested**, not proof of no leak; a confirmed block may prevent that send but still does not solve the engineering task.

[#65](https://github.com/Marcus-Levin/hylja/issues/65) and [#66](https://github.com/Marcus-Levin/hylja/issues/66) are unfinished studies of information categories and which task details must survive. We can discuss public tasks now, but **#39 cannot lock its expected-answer key or final test rules** until the relevant results appear in a revised proposal and receive independent review. Before developing a *new* reference program eligible for scoring, the team must first lock which cases are supported or excluded, independently written answers and control examples (including cases where no information should be hidden), public versus blind (*held-back*) case groups under restricted custody, and policy/task/scoring rules. A separate final lock of exact test materials and runner precedes any blind scoring; the current public program was built before the first lock and remains practice-only.

## An easy first reply

> I am willing / not willing to review independent engineering task outcomes. My relevant experience is ____. I have / have not developed or tuned the candidate; any exposure to its results is ____. My questions about D01/D02/D05 task correctness or necessary task detail are ____. This reply is **not** approval of answers, scoring or blind custody.

Do not include personal contact details, real engineering/customer data or hidden examples in a public reply. At a later, separate **actual sign-off**, a restricted approval record would identify the reviewer, exact revised task/rubric version, checks for correct task outcomes, rationale, objections and date. The separate scoring reviewer and the person responsible for the test procedure must record their own decisions too.

## If you might also help with hidden cases

H01–H04 are **planning IDs**, not existing cases. Authoring future hidden *synthetic* cases or holding their answers is an additional, independently reviewed role—not part of accepting this invitation. Before creating anything, agree on structurally distinct public and hidden case groups, an encrypted access-controlled store **outside Git, PRs, CI and candidate-accessible worktrees**, separate access identities, explicit denial to candidate developers and CI, access logging, retention and isolated scoring. Another worktree under the **same operating-system user** is not access separation. Anyone who accesses hidden case contents, labels or answers must not develop, tune or direct the candidate while that held-out set remains eligible. Do **not** send hidden content, seeds, answers, restricted paths, keys or sensitive digests to us here; ask only whether you could take the role.

## Public reading (proposals, not approved answers)

- [Public development fixtures](issue-39-public-development-fixtures-p0.1.json) and [task/rubric proposal](issue-39-public-rubric-p0.1.md).
- [#39 open-gates packet](issue-39-v0-open-gates-p0.1.md) and [#39 issue](https://github.com/Marcus-Levin/hylja/issues/39) — required reviews and the #65/#66 dependency.
- [The plan](../plan.md#current-state) alone records implementation status.

This invitation neither approves where information may be sent nor permits scored #40–#47 comparisons or a #48 product choice. It does not prove production interception, safe release or restoration.
