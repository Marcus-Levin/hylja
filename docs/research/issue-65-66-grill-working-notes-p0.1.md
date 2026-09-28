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

## Second interview round: agreed discussion preferences

The user agreed with the recommended directions on 2026-09-28. The independent reviewer has not accepted or checked them. Agreement with the recommendation to keep unfilled roles pending does **not** establish that people or a restricted review route are available.

| Topic | Discussion preference | Still open before acceptance |
| --- | --- | --- |
| Identifier naming | Replace the draft's potentially misleading `PERSONAL_IDENTIFIER` umbrella with a neutral working name, `IDENTIFIER`, for contact, national-person, online and financial domains. Keep `ENGINEERING_IDENTIFIER` distinct and specify overlap precedence. Neither the family name nor domain decides `personalData`. | Independently review final names and boundaries, including whether contact points need their own semantic type; update the v1 mapping and policy selectors only through a versioned v2 contract. |
| Ambiguous evidence | Treat a pattern as a clue, not sufficient proof of a semantic subtype. Require validated format plus credible field or source context for a specific national-person ID subtype; ambiguous values remain protected and uncertain. Tenant-specific engineering identifiers require tenant-scoped structure or dictionary evidence. | Define claim and abstention thresholds without using real identifiers, and test negative controls such as part-number fields. |
| Privacy attributes | Use `YES`/`NO`/`UNKNOWN`. Credible evidence may raise a `YES` concern; `NO` requires deterministic or trusted-context support, and missing evidence is `UNKNOWN`. These attributes are not legal determinations. | Identify who can vouch for trusted context, how contradictory claims resolve, and which jurisdictions or attributes v0 supports. |
| Semantic abstention and failure | With a sound deterministic floor, an explicit semantic abstention is an absent opinion. A semantic timeout, invalid response or failure is unresolved and held. Meter and route excessive semantic escalations for review without silently lowering protection. | Define review routing, budgets, effect of review backlog, and explicit policy handling of `RESOLVED_CONSERVATIVELY`; do not let a cost cap release protected content. |
| Secret placeholders | For the first version, reveal only kind and presence. Do not reveal fingerprints, length, validity or other derived facts by default. Placeholder-shaped input is untrusted and must be escaped or flagged, never authenticated merely by its text. | Review typed representation, request binding and exact task predicates; destination policy still decides whether any placeholder can be sent. |
| Private review availability | Keep all unfilled #65/#66 and #39 gates pending. | Availability of independent policy, task, scoring, blind-control reviewers and an approved restricted route was not established in the answer. Obtain acceptances and conflict checks privately. |

## Proposed glossary language for review

These are candidate meanings, not additions to the accepted [shared language](../../CONTEXT.md) yet.

| Term | Candidate meaning | Boundary to test next |
| --- | --- | --- |
| `PERSON` | A natural-person entity, distinct from its email address, phone number or account identifiers. | A name can denote a person; a service account or mailbox might not. |
| Identifier family | A semantic home for contact and national identifiers, possibly extending to online and financial identifiers after boundary review. The family name must not itself decide whether an occurrence is personal data. | Corporate bank identifiers and shared addresses expose why `PERSONAL_IDENTIFIER` may be too broad a name. |
| `ENGINEERING_INFORMATION` | Engineering content such as geometry, a bill of materials, a process topology or a control setpoint that is not merely an identifier. | The domain describes where it belongs; sensitivity and destination treatment remain separate. |
| `RESOLVED_CONSERVATIVELY` | A proposed classification state retaining a sound deterministic sensitivity floor and a semantic disagreement while using the more concerning sensitivity. | It grants no release by itself; an explicit versioned policy rule would be required. |

## Next interview branches

Independently review the provisional identifier-family naming, ambiguous examples, privacy authority, semantic failure handling and placeholder limit above. Resolve source-supported engineering domains and v1 migration; exact fidelity predicates and occurrence rules; authenticated task/destination binding; and the representation ceiling for unresolved records. Separate #39 policy, task, scoring and blind-control reviewers decide their own gates after reviewed #65/#66 findings. The already selected narrow D01/D02/D05 proposal and prospective pre-tuning requirement are not reopened here.
