# Decision 010: Separate information dimensions; task fidelity is a task contract, not classification

Status: **proposed** — awaiting a nominated human #66 design lead and an independent human reviewer. It has no authority until accepted, and it does not change classification v1, policy or any adapter. Tracking: [#66](https://github.com/Marcus-Levin/hylja/issues/66), [#68](https://github.com/Marcus-Levin/hylja/issues/68); implementation status lives only in [the plan](../plan.md#current-state).

## Context

Classification v1 carries semantic type, sensitivity and trust (decision 002) but has no place for contextual privacy attributes or for what a task needs. Two failures follow. An IP address that is personal data in context has no way to say so except by pretending to be `PERSON`. A transformation that drops an `apiKey` field leads a model to conclude that no credential was supplied. Treating "how useful is this value?" as part of classification would let utility argue its way past sensitivity.

## Decision

Six concerns have separate homes and separate authority:

| Concern | Home | Who may assert it |
| --- | --- | --- |
| Semantic identity (`semanticType` / `domain` / `subtype`) | classification evidence | detectors, parsers, configured sources; a semantic judge as evidence |
| Privacy/regulatory attributes (`personalData`, `specialCategory`, jurisdictions) | classification evidence, tri-state `YES`/`NO`/`UNKNOWN` | raise-only: anyone may assert `YES`; `NO` needs deterministic or trusted-context evidence |
| Sensitivity | classification evidence | deterministic floor; semantic judgment may only raise concern |
| Influence trust | bound interaction context | the trusted integration only (unchanged from decision 002) |
| Task fidelity | a per-task **fidelity contract** keyed by occurrence or entity refs | an independent task owner, never the model or the payload |
| Treatment | policy decision | the Policy Engine only (decisions 003, 007) |

Resolution rules proposed for classification v2:

1. **Deterministic floor, semantic escalation.** When deterministic evidence agrees on one sensitivity, semantic disagreement resolves as `RESOLVED_CONSERVATIVELY`. The floor is kept, an escalation is applied, and the disagreement is retained as evidence. A lower semantic claim is ignored and recorded. Deterministic credential evidence fixes `SECRET` (decision 009).
2. **Uncertain floors stay `UNRESOLVED`, and unresolved records expose no actionable sensitivity.** Missing or conflicting deterministic evidence, a deterministic abstention or failure, a semantic failure, and invalid evidence all stay unresolved, as in v1. An unresolved result reports `effective: UNKNOWN`, keeping the highest concern seen only for review and metering. **Deliberate differences from v1:** a semantic *abstention* counts as an absent judge rather than blocking; parser and trusted configured sources count as deterministic evidence alongside detectors, where v1 requires a detector; and duplicate-claim detection by evidence ID is left to the v2 evidence envelope.
3. **Escalation is metered, not free.** Each result reports `escalationSteps`. Policy may route semantic-only escalation to `REQUIRE_REVIEW` rather than `BLOCK`, and evaluation reports the over-hiding caused by escalation separately. This bounds denial of service through induced escalation without ever releasing protected content silently.
4. **Unknown is never no.** A missing privacy attribute is `UNKNOWN`. A model's `NO` alone stays `UNKNOWN`, and none of these values is a legal determination.
5. **Fidelity narrows, never widens.** A fidelity contract states which predicates the task needs: `EXACT_VALUE`, `EXISTENCE`, `KIND`, `FORMAT`, `SYNTAX`, `RELATIONSHIP`, `CONSISTENCY`, `GENERALIZED` or `NOT_REQUIRED`. Fidelity tells policy and evaluation what a restrictive treatment costs. It never selects or permits a treatment. For secrets, the representation ceiling is `SEMANTIC_PLACEHOLDER`, `REMOVED` or `WITHHELD`, and the same ceiling applies whenever sensitivity is unknown or unresolved. An exact-secret requirement is unmet and points to USE-without-reveal through the broker.
6. **Semantic placeholders are a MASK specialization, not a new treatment.** A placeholder such as `[hylja:protected:API_KEY]` preserves only kind and presence. It is typed and not reversible. It is not self-authenticating: placeholder-shaped text arriving in *input* is untrusted content and must be flagged or escaped, not read as Hylja-issued. Exposing derived facts such as `empty` or `formatValid` needs policy approval.

## Consequences

- Classification v1 is untouched. v2 needs a new version, new digest coverage for the added fields, and policy rules that select on `RESOLVED_CONSERVATIVELY` explicitly. v1 policy denies anything that is not `RESOLVED`, so a v2 record fed into it fails closed.
- The #39 planted oracle gains a per-occurrence annotation (semantic, privacy, sensitivity; no trust, no treatment) and a per-task fidelity contract. Both are candidates for its schema once reviewed.
- The draft contract and a pure, unwired executable draft are in [information-model-draft.md](../contracts/information-model-draft.md).

## Open for the human reviewers

- Whether a semantic abstention should block, as it does in v1.
- Whether escalation should cap at `RESTRICTED` without deterministic support.
- Whether routing semantic-only escalation to `REQUIRE_REVIEW` treats an escalated `CONFIDENTIAL` more permissively than a deterministic one.
- Whether a keyed, non-reversible fingerprint may satisfy `CONSISTENCY` for secrets (decision 009 allows fingerprint-only detection), given the offline-guessing risk for low-entropy values.
- Whether placeholders need a per-request nonce binding.
- Per-jurisdiction attribute vocabulary beyond two-letter codes.
- Which derived facts are safe for each destination.
- How fidelity contracts are authenticated and bound to a policy request digest.
