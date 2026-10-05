# Decision 012: Synthetic engineering custody preconditions

Status: accepted technical direction under the project owner's explicit overnight delegation of CTO
decisions, 2026-10-04. Implementation is tracked only in
[#248](https://github.com/Marcus-Levin/hylja/issues/248); what is implemented lives only in
[capabilities.md](../capabilities.md). This record authorizes a direction and changes no runtime
behavior by itself.

## Context

Capacity-one ephemeral custody has no honest way to propose reversibility today: configured evidence
alone supplies none, and the v1 composer consequently produces `reversible: false`. That gate must not
be bypassed ([decision 003](003-semantic-judgment-does-not-own-effects.md)). The custody owner also
needs to be smaller than a full effect implementation, and
[decision 010](010-separate-information-dimensions-and-task-fidelity.md) remains **proposed** and is not
adopted here.

## Decision

1. **A synthetic-only namespace.** An admission helper may cover exactly one explicitly synthetic ASCII
   engineering-reference namespace, at most 128 bytes, using the grammar
   `^SYNTHETIC-ASSET-[A-Z0-9]{1,64}$`. Ordinary engineering values, real PII, arbitrary credentials and
   unknown representations stay unsupported. The corroboration is a genuine tenant/project-scoped
   configured source that matches the **whole** value as `ENGINEERING_IDENTIFIER` with complete matched
   source provenance, composed through the real v1 composer from real `detectSecrets` and
   `detectNormalizedCandidates` evidence.
2. **A recommendation, never an effect.** Inside that synthetic scope a whole-value grammar detector may
   recommend session-scoped reversibility. That recommendation is evidence for a later owner. Semantic
   advice never decides effects, and no `valueKind` label substitutes for a detector.
3. **Default non-reversibility and an absolute secret floor.** Any secret or credential evidence, a
   secret-like trusted field context, protected evidence overlapping the value, partial or uninspected
   inspection, a foreign or forged configuration, unknown sensitivity, conflicting evidence or a
   non-reversible composition refuses with one fixed code, regardless of scores or ordering. A secret is
   never relabelled, and no reversible credential mapping is created by default
   ([decision 009](009-secrets-are-not-synthetic-identities.md), [decision 004](004-brokered-vault-no-direct-mapping-api.md)).
4. **Digest evidence is not authorization, and is not anonymization.** A bound digest over a private
   original is evidence only. It is never logged as anonymized customer data, and no plaintext lifetime
   is extended by it ([decision 008](008-minimize-raw-data-retention.md)).
5. **A future `CREATE` is a separate, closed approval.** Before any future implementation creates a
   mapping, it needs its own closed, current, purpose-bound, scoped `MAPPING_ADMIN` approval plus
   privacy-safe audit gates, enforced by deterministic policy and authorization. `USE` and `KEEP` do not
   authorize `CREATE`; `CREATE` is not added to the core PolicyOperation or the core grant model, and it
   is not a borrowed grant, a revocation approval or an authentication claim.
6. **Attribution.** This is an experimental, synthetic-only admission prerequisite recorded under the
   project owner's delegation of CTO decisions. Implementation is tracked in
   [#248](https://github.com/Marcus-Levin/hylja/issues/248).

## Not authorized here

Adoption of decision 010, [#66](https://github.com/Marcus-Levin/hylja/issues/66) or
[#68](https://github.com/Marcus-Levin/hylja/issues/68); any `CREATE` operation, grant, key, registry
record or custody effect; any production privacy-risk, privacy or utility acceptance; and
[#48](https://github.com/Marcus-Levin/hylja/issues/48), which remains a human decision. No production
deployment is authorized by this record.
