# Information model draft (classification v2 candidate)

Status: **draft for review**, proposed with [decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md). The executable draft [`src/information-model-draft.ts`](../../src/information-model-draft.ts) is pure and **not wired** into [`classification.ts`](../../src/classification.ts), [`policy.ts`](../../src/policy.ts) or any adapter. Its outputs are evidence for review and evaluation. They grant no treatment, release or restoration.

## Sensitivity resolution

`resolveSensitivityDraft(claims)` takes `{ origin: DETERMINISTIC | SEMANTIC, status: FOUND | ABSTAIN | FAILURE, sensitivity?, credential? }` records.

| Situation | State | `effective` |
| --- | --- | --- |
| Deterministic claims agree, no semantic disagreement | `RESOLVED` | the agreed value |
| Semantic claim above the agreed floor (#66 "INTERNAL vs CONFIDENTIAL") | `RESOLVED_CONSERVATIVELY`, `SEMANTIC_ESCALATION`, `escalationSteps` > 0 | the higher value |
| Semantic claim below the floor (e.g. judge says `PUBLIC`) | `RESOLVED_CONSERVATIVELY`, `SEMANTIC_BELOW_FLOOR_IGNORED` | the floor |
| Deterministic credential evidence | floor `SECRET`; contrary deterministic claims add `CREDENTIAL_FLOOR_APPLIED` | `SECRET` |
| Semantic credential opinion only | escalation to `SECRET`; floor unchanged | `SECRET` |
| Deterministic conflict, no deterministic evidence, any failure, missing sensitivity, invalid evidence | `UNRESOLVED` | highest concern seen, or `UNKNOWN` |
| Semantic abstention | no effect (reason retained) | unchanged |

Checked properties: `effective` never falls below any deterministic claim; adding a claim never lowers `effective`; results are order-independent; semantic disagreement never produces plain `RESOLVED`; malformed input fails closed without echoing its values.

## Privacy and regulatory attributes

`resolveAttributeDraft(claims)` resolves one contextual attribute (`personalData`, `specialCategory`) to `YES`/`NO`/`UNKNOWN`. `YES` dominates and records `ATTRIBUTE_CONFLICT` when contradicted. `NO` requires deterministic or trusted-context evidence, with no failure and no contrary claim. A semantic `NO` alone is `UNKNOWN`. An IP address therefore stays semantically `NETWORK_IDENTIFIER / IP` and may carry `personalData: YES`, without being relabeled `PERSON`. None of these values is a legal opinion.

## Task fidelity

A fidelity contract belongs to a **task** and is keyed by occurrence or entity refs, so it answers "per candidate, per task, or both" with both. Its author is an independent task owner, never the payload or the model. `validateTaskFidelityContractDraft` enforces refs rather than values, unique targets, known predicates, and `NOT_REQUIRED` only on its own.

| Predicate | Meaning | Forms that can satisfy it |
| --- | --- | --- |
| `EXACT_VALUE` | exact bytes must survive (port `443` for HTTPS diagnosis) | EXACT |
| `EXISTENCE` | the value's presence must be visible (`apiKey` was supplied) | all released forms except REMOVED |
| `KIND` | the semantic kind must be recognizable | EXACT, IDENTITY_SYNTHETIC, OPAQUE_TOKEN, SEMANTIC_PLACEHOLDER, GENERALIZED |
| `FORMAT` | value shape (URL scheme, path style, extension) | EXACT, IDENTITY_SYNTHETIC |
| `SYNTAX` | the container stays valid (JSON parses) | any released form; a transformer obligation |
| `RELATIONSHIP` | links to other occurrences or entities survive (primary→backup) | EXACT, IDENTITY_SYNTHETIC, OPAQUE_TOKEN |
| `CONSISTENCY` | the same entity gets the same representation within scope | EXACT, IDENTITY_SYNTHETIC, OPAQUE_TOKEN |
| `GENERALIZED` | a coarser value suffices (subnet class, city) | EXACT, GENERALIZED |
| `NOT_REQUIRED` | the task does not need it | any |

`WITHHELD` (BLOCK/REQUIRE_REVIEW) satisfies only `NOT_REQUIRED`. Representations hint at existing treatments: EXACT→KEEP, IDENTITY_SYNTHETIC→SYNTHETIC, OPAQUE_TOKEN→TOKENIZE, SEMANTIC_PLACEHOLDER→MASK, GENERALIZED→GENERALIZE, REMOVED→REMOVE.

`assessFidelityDraft(predicates, secret)` returns the forms that satisfy every predicate, any unmet predicates, and advice. For secrets the ceiling is SEMANTIC_PLACEHOLDER/REMOVED/WITHHELD, and an `EXACT_VALUE` requirement returns `USE_WITHOUT_REVEAL`: a trusted local effect uses the credential and the model sees only the outcome, such as `401`. Checked properties: every secret result stays within the ceiling, and adding a predicate never enlarges the satisfying set. The result carries no treatment or decision field.

## Semantic placeholders

`semanticPlaceholder('API_KEY')` returns `[hylja:protected:API_KEY]`, and `parseSemanticPlaceholder` recognizes only that exact grammar, which lets a future egress sentinel validate it. A placeholder holds no mapping, so it cannot be reversed. For structured payloads the field stays in place with the placeholder as its value, so JSON stays valid and `EXISTENCE` holds. In unstructured text the placeholder replaces the span. Derived facts beyond presence (`empty`, `formatValid`) are not emitted by this draft.

## #39 oracle annotation (proposed schema)

`validateOracleAnnotationDraft` accepts one planted occurrence:

```ts
{ version: 'draft-1', occurrenceRef, entityRef?,
  semantic: { semanticType, domain?, subtype? },          // names from the #65 taxonomy once reviewed
  privacy: { personalData, specialCategory, jurisdictions }, // tri-state; codes like 'EU', 'SE'
  sensitivity }
```

Trust is not annotated, because it comes from the interaction context. Treatment is not annotated, because a separate policy reviewer owns it. `specialCategory: YES` requires `personalData: YES`. Unknown fields, including anything that could hold a raw value, are rejected.

## Migration path

1. Human review accepts or amends decision 010.
2. Classification v2 adds `domain`, privacy attributes and `RESOLVED_CONSERVATIVELY`, with a new version and digest coverage. v1 records and policy stay unchanged, and v1 policy keeps denying anything that is not `RESOLVED`.
3. Policy adds explicit rules for `RESOLVED_CONSERVATIVELY`, optionally routing semantic-only escalation to `REQUIRE_REVIEW`. It also accepts a bound fidelity-contract digest as a cost input, never as a selector that widens release.
4. The transformation engine (#13) implements placeholders and fidelity checks; the egress sentinel (#19) recognizes placeholders.

## Proposed #39 evaluation cases (synthetic, not fixtures)

- API key present vs absent: REMOVED must be scored as a fidelity failure, and a placeholder as a pass with zero secret bytes.
- Port `443` vs `8443` kept exact alongside a secret-shaped token in the same task (negative and adversarial controls together).
- Host identity hidden while host-role relationships and repeated references stay consistent.
- A documentation-range IP with `personalData: YES` in context, scored as `NETWORK_IDENTIFIER / IP`, not `PERSON`.
- Semantic escalation rate on harmless values (over-hiding), reported separately from leak rate.
- A placeholder that an agent tries to execute as a credential: no real credential is ever resolved from it.
