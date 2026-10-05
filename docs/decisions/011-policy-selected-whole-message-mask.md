# Decision 011: Policy-selected whole-message generic mask

Status: accepted technical direction under the project owner's delegated CTO authority, 2026-10-04.
Implementation is tracked only in [#218](https://github.com/Marcus-Levin/hylja/issues/218); what is
implemented lives only in [capabilities.md](../capabilities.md). This record authorizes a direction and
changes no runtime behavior by itself.

## Context

The owned complete-text sender is KEEP-only: any selected treatment other than `KEEP` refuses
([sender contract](../contracts/openai-keep-sender.md)). Policy may already select irreversible `MASK` or
`REMOVE` for an external destination ([policy contract](../contracts/policy-contract.md)), so a
policy-selected `MASK` currently has no release path in that seam. Transformation semantics stay
unadopted: [decision 010](010-separate-information-dimensions-and-task-fidelity.md) remains **proposed**.

## Decision

1. **One new release.** A complete `MESSAGE` unit whose real Policy Engine decision is `SELECTED` with
   treatment `MASK` is replaced inside the owned complete-text sender by the fixed literal
   `[hylja:masked]`. `METADATA` and `MODEL` units still require `SELECTED` `KEEP`; masking them and every
   other treatment refuses exactly as today. Only the real policy seam selects a treatment — never a
   caller, model, payload or marker ([decision 003](003-semantic-judgment-does-not-own-effects.md)).
2. **The literal is generic and original-independent.** No typed placeholder, no fidelity predicate, no
   field-level or span-level rewrite, no global replace of matching text, no fingerprint, no derived facts
   (kind, format, validity, emptiness), no mapping, no reversibility, and no reusable or bearer authority.
   The literal carries no secret's kind or format. Its only visibility is minimal irreversible presence and
   structure, which this approved generic representation accepts.
3. **KEEP bytes and rebuilt framing.** A `KEEP` unit keeps its literal bytes, role and order unchanged. The
   trusted JSON body and HTTP framing are rebuilt from the final units, and `Content-Length` is explicitly
   and narrowly authorized to be recomputed as `UTF8(finalBody).byteLength`. The original metadata unit
   digest does not cover a changed header, and masked text is never relabelled `PUBLIC` or otherwise
   reclassified.
4. **Congruence evidence, not clearance.** Private evidence binds the original interaction, unit and image,
   the classification, the policy commit, the selected decision and treatment, the transformation version,
   and the final unit and image. It proves congruence of that change only: no clearance, no authorization,
   no principal identity, no bearer capability, no retention of originals
   ([decision 008](008-minimize-raw-data-retention.md)).
5. **Refusals stay closed.** Unresolved, unsupported, absent, held, denied or failed evidence refuses. Final
   codec bounds and re-parse are fail-closed: a representation the trusted codec refuses is not released. A
   marker-shaped string arriving in input is untrusted content and is never read as Hylja-issued. A
   known-original registration that collides with the literal blocks
   ([decision 007](007-fail-closed-for-protected-egress.md), [decision 009](009-secrets-are-not-synthetic-identities.md)).
6. **Verification unchanged.** Known-original and canary registrations are retained, the fixed sentinel
   checks the exact final private bytes, and the final fresh route, policy-commit, proof and cancellation
   guards stay as they are, in the same synchronous turn before dispatch.
7. **Host obligations unchanged.** Host authentication, inspection authenticity, finiteness of trusted
   callbacks and transport trust remain exactly as the sender contract states them. A masked send is no more
   trustworthy than a `KEEP` send.

## Not authorized here

Adoption of decision 010, [#66](https://github.com/Marcus-Levin/hylja/issues/66),
[#68](https://github.com/Marcus-Levin/hylja/issues/68) or full
[#13](https://github.com/Marcus-Levin/hylja/issues/13); any held-out utility claim; any typed, per-field,
per-span or reversible transformation; any second sender, stream or non-text surface; and any true
business or privacy-risk acceptance, which remains a human decision outside this scope.
