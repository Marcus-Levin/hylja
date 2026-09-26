# Invitation: independent privacy-policy reviewer for a synthetic benchmark

**PUBLIC INVITATION — not an approval or policy rule.** You do not need to know Hylja. It is an early research project about keeping an engineering assistant useful without revealing information that should stay private. The examples are **made up and run only in a local test setup**; this is not live traffic or a deployed privacy safeguard.

## What we would ask you to do

The *reference candidate* is the experimental program being tested, not a reviewer. For three public practice tasks—D01 (support conversation), D02 (diagnostic log) and D05 (JSON configuration)—independently decide which made-up information may stay (`KEEP`), must be permanently hidden (`MASK`) or must stop a send (`BLOCK`), depending on the specified destination (where it would go). Say what useful task detail may remain. If the destination cannot be verified, decide a cautious default; a practice-case description is **not** permission to send anything.

One open question is D02: should a visibly synthetic token-shaped string be permanently hidden while troubleshooting continues, or should the whole attempt be blocked? Public materials discuss candidate behavior, so we cannot promise you have never seen it. Disclose any prior exposure and decide on policy grounds: **neither match nor oppose a candidate result merely because of that result**. Do not develop, tune or direct changes to the candidate while serving as its independent policy reviewer.

Two studies are unfinished: [#65 information categories](https://github.com/Marcus-Levin/hylja/issues/65) and [#66 how privacy, severity, source reliability and useful task detail differ](https://github.com/Marcus-Levin/hylja/issues/66). What a value *is*, whether it is personal data, how sensitive it is, how trustworthy the evidence is, what detail the task needs and what action policy allows are different questions. We can discuss public examples now, but cannot lock the expected-answer key or test rules for [#39](https://github.com/Marcus-Levin/hylja/issues/39)—or ask for your final sign-off—until the relevant #65/#66 results appear in a revised version and are independently reviewed.

## An easy first reply

> I am willing / not willing to serve as an independent policy reviewer. My relevant experience is ____. I have / have not developed or tuned this candidate; any prior exposure to its results is ____. I can review the public proposal, but this reply is **not approval** of treatments or a benchmark freeze. My unresolved policy questions are ____.

Do not put personal contact details or real customer/employee/credential data in a public reply. At a later, separate **actual sign-off**, a restricted approval record would identify the reviewer and exact revised proposal, say what happens to each supported example of made-up information at each specified destination, what useful detail may remain, why, any objections and the date. A separately designated person responsible for the test procedure must check conflicts and other requirements; accepting this invitation authorizes nothing.

## Public reading (proposals, not approved answers)

- [#39 open-gates packet](issue-39-v0-open-gates-p0.1.md) — decisions and independence requirements.
- [Public development treatment/rubric proposal](issue-39-public-rubric-p0.1.md) and [proposed correct labels for practice cases](issue-39-public-development-oracle-p0.1.json) — synthetic review inputs, **not** frozen truth.
- [#39 issue](https://github.com/Marcus-Levin/hylja/issues/39) — acceptance and the #65/#66 pre-freeze dependency; [the plan](../plan.md#current-state) alone records implementation status.

H01–H04 are placeholders for future *blind tests*: made-up cases and answers withheld from candidate developers. Do **not** request or send their contents or answers here, in Git, PRs, CI, chat or any workspace the developers can access. Separate custody and independent review have not been established. The current public reference program was built before test rules were agreed in advance; it is practice-only, not a fair untouched program for a scored comparison. This invitation authorizes no #40–#47 comparison or #48 product choice.
