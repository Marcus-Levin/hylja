# Bounded synthetic engineering-reference admission

Status: contract for [`src/synthetic-engineering-admission.ts`](../../src/synthetic-engineering-admission.ts) ([#248](https://github.com/Marcus-Levin/hylja/issues/248)), a bounded pure prerequisite for capacity-one ephemeral custody and a child of [#15](https://github.com/Marcus-Levin/hylja/issues/15)/[#16](https://github.com/Marcus-Levin/hylja/issues/16). It resolves one missing reversibility **recommendation** and nothing else. What the software implements lives only in [capabilities.md](../capabilities.md).

## What it is, and what it is not

`inspectSyntheticEngineeringReference(value)` inspects one caller's private original and returns either a fixed refusal or owned classification and digest evidence plus a **reversible session recommendation**.

It creates no mapping, key, grant, plaintext release, registry record or audit entry. It returns no prepared-effect handle. It decides no effect: a semantic detector may classify and recommend, while deterministic policy and authorization decide what happens ([decision 003](../decisions/003-semantic-judgment-does-not-own-effects.md)).

It is **not** authority to create anything. `USE` and `KEEP` never authorize `CREATE`, and no `CREATE` operation is added to the core Policy Engine or the core grant model. A future `CREATE` needs its own closed, current, purpose-bound, scoped `MAPPING_ADMIN` approval with privacy-safe audit gates, recorded in [decision 012](../decisions/012-synthetic-engineering-custody-preconditions.md). This contract grants nothing towards that step.

## Scope: an explicitly synthetic, ASCII-only engineering reference

The whole value must match `^SYNTHETIC-ASSET-[A-Z0-9]{1,64}$` and the owned copy is at most 128 bytes. Ordinary engineering values, real PII, arbitrary credentials, other namespaces and unknown representations are **not** supported and refuse. The grammar is the only thing that makes this helper's recommendation safe to publish at all; it is a narrow, obviously synthetic namespace, not a general identifier format.

The configured corroboration is a **whole-value match**, not a whole-value span. #10 extends a template match forward over the rest of an identifier so a value is never *covered* in part; that wider span is coverage. This seam requires the matched offsets #10 and #6 report beside it (`matchStart`/`matchEnd`, through #6's `NormalizedCandidate`) to be `0..length` as well, so an unconfigured tail that coverage happened to reach refuses instead of being admitted.

## The input record

A closed version-1 record. Every member is read once, before any downstream call, through **own enumerable data descriptors**: a plain object prototype (or a null prototype), an exact member set, no symbol keys, no accessor, no inherited value. A caller getter is never invoked; a `Proxy` that answers only `get` is therefore answered from descriptors and never runs the trap.

| Member | Meaning |
|---|---|
| `version` | must be exactly `1` |
| `original` | the caller's private original bytes, copied into one owned buffer of at most 128 bytes; every byte must be ASCII |
| `scope` | the detector scope, `tenantRef` and `projectRef` only, itself a closed record read through own enumerable data descriptors: an extra member (`sessionId` above all), an inherited member, an accessor or a non-enumerable property refuses. There is **no session field** in a detector scope; `session` is the later reversibility recommendation, not detector configuration |
| `configured` | a genuine `CandidateConfigHandle` from `createCandidateConfig`, already bound to one tenant and project. A forged object or a handle from another scope refuses; there is no other way to obtain one |
| `inputRef` | an opaque source reference. A **fresh** value per request is what keeps evidence ids and path digests unlinkable; a caller that reuses one value correlates its own traffic |
| `fieldKey` | optional trusted parser key path for the original as a single field value. It is read from the caller, never from the value's own text |

The bytes are read from `original` only after the `%TypedArray%.prototype.length` accessor has accepted it. That accessor validates the typed-array internal slot, which a `Proxy` never carries, so a proxied look-alike is refused by the engine itself before any element is read: no trap runs, no trap message reaches the caller, and no element can be answered twice with different values. Each element is then read **once** and accepted only as a plain integer in `0x00..0x7f`, so no coercion, comparison or text construction can turn one value into another. A `Proxy` over the record or the scope is a different case: it is answered from descriptors, so a `get`-only proxy runs nothing and an accessor descriptor is refused without being invoked. The caller's own buffer is never modified.

Every reference, key path and scope member is also checked for lone surrogates, and the whole detection and composition step runs inside the boundary that owns the copy. A reflection, coercion or canonical-serialization failure therefore leaves as one fixed refusal code, never as an exception carrying planted text.

## What actually runs

Real seams only, in this order:

1. the real `detectSecrets` over the owned text with the trusted `fieldKey`, then the real `detectNormalizedCandidates` with the genuine configured handle, then the real v1 `composeClassification`;
2. a whole-value grammar detector record, produced by this module with its own producer id, carrying the **configured** sensitivity and a `reversible: true`, `scope: 'session'` claim. The real composer still owns every conflict and reversal gate - this module never supplies a host `valueKind` label, never relabels a secret, and never bypasses a gate.

Admitted means all of: detection `COMPLETE` with **zero** uninspected locations; zero secret or credential findings from `detectSecrets`; every candidate produced by `detectNormalizedCandidates` a configured one whose **coverage** (`ORIGINAL_EXACT`, span `0..length`) *and* whose **matched** offsets are `0..length`; one agreed subtype and one known, non-`SECRET` sensitivity across all of them; a `RESOLVED` `ENGINEERING_IDENTIFIER` classification; and `reversible: true` with `scope: 'session'` as the composer itself computed them. Ordinary, oversized, non-ASCII, malformed, unconfigured and uninspected values all refuse before any downstream effect.

## The fixed codes

`INVALID_REQUEST`, `INVALID_ORIGINAL`, `OUT_OF_SYNTHETIC_GRAMMAR`, `INCOMPLETE_INSPECTION`, `SECRET_EVIDENCE`, `PROTECTED_OVERLAP`, `NO_CONFIGURED_CORROBORATION`, `PARTIAL_CANDIDATE`, `CONFLICTING_EVIDENCE`, `UNRESOLVED_CLASSIFICATION`, `UNKNOWN_SENSITIVITY`, `NOT_REVERSIBLE`.

A code never carries a value, a path, a caller's text or an exception message. Any secret or credential evidence, a secret-like trusted field context, protected evidence overlapping the value, a partial or uninspected representation, a foreign or forged configuration, unknown sensitivity, conflicting evidence or a non-reversible composition refuses **regardless of scores, ordering, or how much configured engineering evidence exists** ([decision 009](../decisions/009-secrets-are-not-synthetic-identities.md)).

## The output

On success, one frozen owned record: `outcome: 'CLASSIFIED'`, the semantic type, the configured subtype, the known non-`SECRET` sensitivity, `reversibility: 'SESSION_RECOMMENDED'`, a `sourceDigest` over the private original and a `classificationDigest` that binds the classification to that digest and to the source reference.

No original text, no byte buffer, no mutable caller alias and no effect handle is returned. `sourceDigest` and `classificationDigest` are **evidence, not authorization**, and they are not anonymized customer data: they must not be logged as if they were, and nothing is logged by this module at all.

## Retention and cleanup

The module owns its temporary byte copy and zero-fills it on **every** exit path: a refusal part-way through copying, a failure thrown while copying or converting, a refusal from detection, and the success path all clean up the same allocated buffer before returning. Ownership is handed to the caller only on the one successful return, so a buffer the caller still owns is never zero-filled and an abandoned one always is. That is the only cleanup claimed: it makes **no** heap, garbage-collection, string-interning or host-memory-zeroization claim about any other copy the runtime may hold.

## Known limits

- A pure classification seam with no authentication, no registry, no key and no outbound bytes. It is evidence that this value looks admissible, not proof of anything about protected egress.
- The grammar, the 128-byte bound and the configured corroboration are checked against the text this call sees. Nothing here proves the caller supplied the value the surrounding system actually holds.
- `PROTECTED_OVERLAP` covers non-secret infrastructure or contact evidence over the value. The synthetic grammar makes that rare enough that no current positive fixture produces it.
