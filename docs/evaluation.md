# Evaluation and continuous improvement

Hylja treats evaluation as part of the product security boundary. No classifier, detector, transformation, policy, or adapter change becomes authoritative merely because it looks better on a few examples.

## Evaluation layers

1. **Normalization** - safe decoding and canonicalization expose hidden content without changing semantics unexpectedly.
2. **Candidate generation** - protected spans/fields become candidates with high recall.
3. **Deterministic classification** - parsers, regexes, schemas, and dictionaries classify known structures correctly.
4. **Semantic classification** - Jev or another judge handles contextual ambiguity.
5. **Policy** - source-to-sink decisions select the correct treatment.
6. **Transformation** - output stays syntactically valid and preserves required semantics.
7. **Entity resolution** - aliases and related fields stay coherent.
8. **Authorization/uncloak** - only permitted originals are used/revealed.
9. **End-to-end leakage** - protected originals do not reach disallowed sinks.
10. **Utility** - the downstream agent can still solve representative tasks.

## Corpora

Maintain distinct sets:

- synthetic golden cases with planted ground truth;
- generated structured cases across JSON/XML/YAML/.env/logs/scripts/URLs/connection strings;
- deterministic edge cases;
- sanitized production regressions;
- adversarial/red-team bypass cases;
- highly restricted real incident cases where synthetic reproduction is impossible;
- a frozen held-out set not used to tune questions, thresholds, or rules.

The eval corpus itself is sensitive infrastructure. Restricted real incidents are encrypted, access-controlled, minimized, and converted to synthetic regression cases whenever possible.

## Core metrics

Privacy metrics:

- recall by semantic/sensitivity class;
- weighted leakage risk;
- credential/SECRET plaintext escapes (release target: zero in held-out suites);
- Egress Sentinel catches;
- cross-tenant resolution failures;
- unauthorized uncloak attempts.

Utility metrics:

- false-cloak/over-cloak rate;
- downstream task success;
- syntax/config validity;
- fidelity-contract preservation;
- round-trip restoration accuracy.

Semantic-judge metrics:

- precision/recall by class;
- calibration/Brier score;
- confidence distribution;
- abstention/review rate;
- latency and cost;
- amount of raw/minimized context sent externally.

Operational metrics:

- end-to-end latency;
- detector/parser time;
- semantic-judge time and calls;
- vault/KMS operations;
- policy decision time;
- blocked/allowed flows by sink and class.

## Weighted consequence

A missed port is not equivalent to a missed private key. Release decisions weight class, sensitivity, sink risk, and exposure scope rather than optimizing a single global accuracy number.

## Property-based tests

Generate thousands of planted values and structures. Required properties include:

- planted protected values never appear in disallowed outbound payloads;
- JSON/XML/YAML remain valid after transformation;
- authorized round-trip uncloak restores exactly where exact restoration is the contract;
- blocked secrets cannot be restored;
- same entity is stable within scope;
- unrelated scopes do not correlate by default;
- tenant A tokens/ciphertext/mappings never resolve under tenant B;
- expired/revoked mappings do not resolve;
- unknown synthetic-looking tokens never gain authority.

## Independent egress sentinel

The final outbound check should not be identical to primary detection. It can combine deterministic secret scanners, fingerprints of known originals, canary identities, policy assertions, and separate high-risk patterns. A sentinel catch blocks release and becomes a regression case.

## Champion/challenger lifecycle

1. Observe privacy-safe production evidence.
2. Capture a counterexample or opportunity.
3. Establish ground truth through synthetic generation or human adjudication.
4. Implement a challenger: detector, parser, question set, threshold, policy, or transformation change.
5. Replay golden, regression, adversarial, and held-out suites.
6. Run challenger in shadow mode on representative traffic where allowed.
7. Compare privacy, utility, latency, cost, and human intervention.
8. Promote through an explicit reviewed release gate.
9. Keep rollback to the prior intelligence bundle immediate.

Production evidence may propose improvements. It never silently modifies production policy.

## Deterministic migration

Repeated semantic patterns should move down the detector ladder when stable:

1. exact deterministic recognition;
2. structured/parser recognition;
3. local statistical candidate generation;
4. semantic judgment;
5. conservative review/block.

A mature system should often use *less* Jev for well-understood patterns, reducing cost and increasing explainability.

## Intelligence bundle

Every decision records the versioned bundle that produced it, for example:

```text
normalization-pack: 1
parser-pack: 1
detector-pack: 1
local-classifier: none
semantic-provider: jev
semantic-question-set: 1
classification-policy: 1
transformation-pack: 1
authorization-policy: 1
```

The exact served semantic-model identity should be recorded when available.
