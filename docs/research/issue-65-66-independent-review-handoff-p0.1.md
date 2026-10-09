# Independent human review handoff for #65 and #66

**PUBLIC REVIEW PACKET — not a role appointment, accepted taxonomy, accepted decision 010, #39 approval, benchmark lock or score.** This packet contains only public synthetic examples. Keep reviewer identities, acceptance, conflict declarations, restricted approval records, real data and future blind material out of Git, issues, PRs, CI and chat. Capabilities/limits: [docs/capabilities.md](../capabilities.md); task status: GitHub issues, task status in the GitHub issues; the [frozen plan snapshot @f838fc2](https://github.com/Marcus-Levin/hylja/blob/f838fc2dc8da0402338d4dfd1c028392a9f4b9ee/docs/plan.md#current-state) is the dated record, not current state.

## Start with the short application review

Send an outside application specialist only the [20–30 minute brief](issue-65-66-application-review-brief-p0.1.md) first. It is self-contained and requires no PR, code or standards reading. Their job is to correct domain categories and task-detail assumptions from work experience. The project team turns that feedback into a revised, versioned proposal and handles source, security, legal and policy checks with qualified reviewers. The short reply alone is **not** full #65/#66 independent sign-off.

This longer packet is for the coordinator and any person accepting the subsequent formal independent-review role. Give the formal reviewer a fixed summary of decisions, sources and changes rather than asking them to reconstruct the project from a moving PR.

Use the [2026-10-01 fixed review snapshot](issue-65-66-review-snapshot-2026-10-01.md) for that summary. It pins the existing proposals to `522430ea68d28777fcff4cdf2f49d3fd2826eb31`, preserves the prior discussion preferences, and asks for separate verdicts on eight concrete findings. The pinned drafts remain the artifacts under review; the snapshot is a cross-checked summary of them, not a replacement. Include the snapshot's exact revision or bytes in the private record; it is a review aid, not approval.

## What the formal reviewer is being asked to decide

The [#65 taxonomy issue](https://github.com/Marcus-Levin/hylja/issues/65) asks **what kind of information a value is**. The [#66 information-model issue](https://github.com/Marcus-Levin/hylja/issues/66) asks where contextual privacy, disclosure sensitivity, source influence, task needs and policy treatment belong. A label such as `NETWORK_IDENTIFIER / PORT` does not decide whether a value may go to a model. Task usefulness does not grant permission to send it.

The reviewer checks a **fixed exact revision** of the lead's proposal, challenges its evidence and examples, and records one of `ADOPT`, `AMEND`, `REJECT` or `DEFER` for each finding. A passing build or an AI review cannot replace this human judgment. The reviewer may conclude that only a bounded subset is ready for a proposed #39 v0; that is distinct from accepting the full #65/#66 issues.

## Before reviewing content

1. Through an approved restricted route, the lead and reviewer each personally accept or decline their own role and state expertise, authorship or direction of the research, candidate-development or tuning involvement, prior exposure to candidate outputs, proposed #39 roles, and conflicts. A separately designated checker who is independent of **both** the lead and reviewer declares their own conflicts and checks the role separation. A nomination or willingness message is not acceptance or approval.
2. Record the exact commit or immutable document revision being reviewed. If the proposal changes, inspect the delta and record a new verdict for the changed revision. Do not approve a moving branch by name alone.
3. Keep the review record and any access details in the approved restricted location. A public status may later name only the checked revision, decision scope, unresolved gaps and a privacy-safe attestation after independent disclosure review; it must not reveal private identities or blind answers.

## #65: challenge the taxonomy

Use the [source index](issue-65-public-source-index-p0.1.md), [taxonomy draft](issue-65-taxonomy-draft-p0.1.md) and [design interview notes](issue-65-66-grill-working-notes-p0.1.md). Check cited sources for the **specific term and limit** claimed; a standards title or vendor vocabulary is not proof that Hylja can detect or parse a format. Mark unsourced or untested entries as research candidates rather than supported classes.

| Check | Concrete question for the reviewer |
| --- | --- |
| Semantic boundaries | Does `PERSON` mean a natural-person entity? Does the neutral working `IDENTIFIER` family handle a shared mailbox and a company bank account without calling them personal data? Should contact points be separate? |
| Engineering content | Are an equipment tag and a process topology, or a part number and a bill of materials, placed in different identifier/content homes? Which domains and subtypes have reviewed sources and executable recognition evidence? |
| Ambiguity and tenant scope | Could an ID-shaped string in a part-number field be misclassified? Are syntax, field structure, semantic context and tenant/project dictionaries distinguished, with no cross-tenant lookup? |
| Overlaps and relationships | Can one occurrence have contextual privacy attributes while keeping its semantic identity, such as an IP that may identify a person? Can a relationship such as customer-to-product be protected even when its components look ordinary? |
| Current-code comparison | What changes in the present classifier and policy selectors? This unreleased project needs a coordinated internal cutover and version labels for historical evaluation evidence, **not** a backward-compatible v1 reader or old-record migration. |

Use only obviously synthetic, non-routable examples. Do not add real national identifiers or valid-looking identity numbers to the review packet, tests or comments. A qualified legal/policy human separately checks jurisdiction-specific handling; taxonomy review does not decide law or destination treatment.

## #66: challenge the separate information model

Use [proposed decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md), the [unwired draft contract](../contracts/information-model-draft.md) and the [interview notes](issue-65-66-grill-working-notes-p0.1.md). The executable drafts now use neutral `IDENTIFIER` and task predicate `VALUE_SHAPE`, without the old-version migration helper. Review those boundaries, then identify exact revisions needed before any accepted contract or implementation.

| Check | Concrete question for the reviewer |
| --- | --- |
| Independent homes | Are semantic identity, tri-state privacy attributes, sensitivity, influence trust from bound integration context, task fidelity and policy treatment genuinely separate? Can untrusted payload text forge none of their authority? |
| Conflict and failure | Does a sound deterministic sensitivity floor survive a lower semantic claim? Is higher semantic concern retained and metered? Does explicit abstention differ from a failed semantic call, and do uncertain/failing records remain held? |
| Privacy uncertainty | Is `UNKNOWN` distinct from `NO`? Can a model's `NO` alone ever clear a concern? How are conflicting `YES` and `NO` claims recorded without turning these attributes into legal opinions? |
| Task detail | Do per-task and per-occurrence/entity predicates express exact port `443`, valid JSON, primary-to-backup order, and consistent references separately? Does `VALUE_SHAPE` differ from classifier `FORMAT` evidence and container `SYNTAX`? |
| Secret and unresolved limits | Does a secret placeholder reveal only independently established kind and presence, with no fingerprint, length or validity by default? Is spoofed placeholder-shaped input untrusted? Does an unresolved result expose at most a policy-approved placeholder, removal or withholding? |
| Binding | Must a trusted integration authenticate and bind task, occurrence refs, actual destination, classification/policy versions and request digest before consuming a fidelity contract? Does a missing or mismatched binding hold the request? |

For each objection, give a short, reproducible counterexample using public synthetic values and say whether it blocks a v0-relevant finding, only a broader domain, or the proposed decision itself. Do not tune a classifier against future blind cases.

## Private verdict format

The restricted record should contain: accepted role and independence check; exact reviewed revision; sources actually verified; an `ADOPT`/`AMEND`/`REJECT`/`DEFER` decision with rationale and objections for each #65/#66 finding; supported versus deferred domains and exact v0-relevant labels/predicates; any required re-review; date and reviewer authentication. Record **two separate conclusions**: whether the bounded findings are ready to be proposed to #39's protocol owners, and whether the full #65/#66 issue deliverables have been met. Neither conclusion approves an oracle, destination treatment, task answer, score, blind custody or #39 freeze.

The [pre-freeze worksheet](issue-39-65-66-prefreeze-worksheet-p0.1.md) lists the remaining owners. A separate policy reviewer decides what may be sent to the observed destination; a separate engineering-task reviewer decides correct task outcomes; a scoring reviewer decides metrics; independent blind controls and chronology checks follow. Keep #39 pending until those distinct decisions and executable evidence exist.
