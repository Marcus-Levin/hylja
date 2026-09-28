# #65/#66 design interview — working notes p0.1

**Status: discussion preferences from 2026-09-28, pending independent human review.** This is a public, non-authoritative record of design direction. It is not an accepted taxonomy, decision 010, glossary, destination policy, #39 oracle or benchmark lock. Keep identities, conflict declarations, private review records and future blind material outside Git, PRs, issues and chat. The [pre-freeze worksheet](issue-39-65-66-prefreeze-worksheet-p0.1.md) lists the distinct review gates; [the plan](../plan.md#current-state) alone records implementation status.

## Agreed directions, with open edges

| Topic | Discussion preference | Still open before acceptance |
| --- | --- | --- |
| Private review route | Use a restricted decision record for each person's role acceptance, conflicts, exact draft version, rationale and objections. | Select and independently check the route and access; obtain each person's own statement. A nomination or this interview is not a review signature. |
| #65 semantic hierarchy | `PERSON` denotes a natural-person entity. Contact/national identifiers belong to a separate identifier family, and non-identifier engineering content belongs to `ENGINEERING_INFORMATION` with domains. Personal-data status is a separate attribute. | Set the identifier family's name and boundary for service mailboxes, corporate financial identifiers and online IDs; settle subtype and overlap rules, sourced domain coverage, tenant-specific evidence and a v1 migration map. The current [`PERSON` mapping](../../src/classification.ts) is unchanged. |
| #66 disagreement | Keep a sound deterministic sensitivity floor; a semantic judge may raise concern, never lower it. Retain both claims and use proposed `RESOLVED_CONSERVATIVELY` for a sound floor plus disagreement. Uncertain or failed deterministic evidence stays `UNRESOLVED`. | Decide semantic abstention/failure, escalation caps, denial-of-service measurement, and explicit policy handling. The existing v1 classifier and policy remain unchanged. |
| #66 task fidelity | An independently authored task contract states what details must survive for a task and occurrence/entity. It never grants permission to send. A non-reversible placeholder may preserve a secret's kind and presence, subject to destination policy. | Decide exact predicate vocabulary, safe derived facts, spoofed placeholder handling, binding/digest rules and the representation ceiling for unresolved sensitivity. A separate policy reviewer chooses destination treatment. |
| #39 blind custody | Prefer a custodian separate from candidate development when available. | Appoint and check the custodian, independent hidden-case author/reviewer, audited restricted storage outside candidate access and isolated scoring before any hidden case is written. This preference makes no appointment. |

## Proposed glossary language for review

These are candidate meanings, not additions to the accepted [shared language](../../CONTEXT.md) yet.

| Term | Candidate meaning | Boundary to test next |
| --- | --- | --- |
| `PERSON` | A natural-person entity, distinct from its email address, phone number or account identifiers. | A name can denote a person; a service account or mailbox might not. |
| Identifier family | A semantic home for contact and national identifiers, possibly extending to online and financial identifiers after boundary review. The family name must not itself decide whether an occurrence is personal data. | Corporate bank identifiers and shared addresses expose why `PERSONAL_IDENTIFIER` may be too broad a name. |
| `ENGINEERING_INFORMATION` | Engineering content such as geometry, a bill of materials, a process topology or a control setpoint that is not merely an identifier. | The domain describes where it belongs; sensitivity and destination treatment remain separate. |
| `RESOLVED_CONSERVATIVELY` | A proposed classification state retaining a sound deterministic sensitivity floor and a semantic disagreement while using the more concerning sensitivity. | It grants no release by itself; an explicit versioned policy rule would be required. |

## Next interview branches

Resolve identifier-family naming and ambiguous examples; source-supported engineering domains and v1 migration; privacy `YES`/`NO`/`UNKNOWN` authority; semantic abstention, failure and escalation abuse; fidelity predicates and secret-safe derived facts; then authenticated task/destination binding. Separate #39 policy, task, scoring and blind-control reviewers decide their own gates after reviewed #65/#66 findings. The already selected narrow D01/D02/D05 proposal and prospective pre-tuning requirement are not reopened here.
