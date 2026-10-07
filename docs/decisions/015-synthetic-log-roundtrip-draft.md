# Decision 015: Isolated public-synthetic log round-trip draft

Status: PROPOSED. Not adopted; human design review is pending. This record grants no
classification, treatment, CREATE, custody, authentication, DISPLAY, EXPORT or runtime
policy authority. Work tracking belongs to [#270](https://github.com/Marcus-Levin/hylja/issues/270).
Implementation and durable product limits belong to [capabilities](../capabilities.md),
not this proposal.

## Problem and example

A pure synthetic-reference admission recommendation is not a round-trip owner.
For example, a message and two log events may contain the same public
`SYNTHETIC-ASSET-A1`: replacing each independently can lose equality, while returning
an uninspected log suffix can expose an original. A successful replacement does not
itself permit restoration. [Accepted decision 012](012-synthetic-engineering-custody-preconditions.md)
authorizes a recommendation only, not a CREATE or restoration effect.

## Proposed experiment

Keep a separate, public, non-enforcing experiment under `evaluations/mvp-roundtrip-draft/`.
Freeze one closed ASCII JSON message/log schema rather than rewriting arbitrary text.
Only whole asset values matching accepted 012's explicitly synthetic namespace are
candidates. A pure function validates the whole unit, preserves enums, event order,
equality and integer ticks, and emits scoped opaque draft references in one canonical
cloaked image. Failure returns only a fixed refusal, never an inspected prefix.

References are unkeyed SHA-256 commitments to domain, scope, session, context and asset.
Every input is a public fixture label. They are deterministic, dictionary-recomputable,
not authenticated, not bearer credentials, not anonymous, and not suitable for private
originals. Fresh context labels separate fixture runs; reusing labels deliberately
reproduces references. No real tenant isolation or cryptographic custody is claimed.

The [draft seam specification](../specs/mvp-synthetic-roundtrip-draft.md) defines the
pure API and future component handoffs. A future isolated owner would retain only one
public synthetic original and allow one reference at a time under explicitly hypothetical
fixture-purpose DISPLAY checks. A future integration would own one fixed public
attachment and exact bytes supplied to a deterministic local responder. Those later
components are separate gated assignments, not effects granted or implemented here.
There is no bulk originals lookup API, and provider text never supplies authority.

## Required separation

- No accepted `src/` imports, index exports, adapters, policy bundles or evaluation scoring.
- No decision 010 taxonomy/information-model adoption, fabricated v1 evidence, or bypass
  around `decidePolicy`. This is hypothetical fixture transformation, not a treatment decision.
- No private data, reversible credentials, keys, KMS, store, network or provider traffic.
- No permissive partial parse, unknown field, opaque attachment or arbitrary free-text pass-through.
- No restoration from a token alone: unknown, foreign, stale, expired or revoked fixture
  references must refuse in a later owner. USE, DISPLAY and EXPORT remain distinct.
- No AI review, passing tests or commit automatically adopts this proposal or opens a human gate.

## Consequences and gates

The experiment can test bounded parsing and transformation invariants without pretending
that accepted admission supplies effects. Narrow input grammar and canonical compact JSON
sacrifice arbitrary log support and formatting fidelity intentionally. The only original
values are public synthetic markers; exact original byte restoration would be a later,
purpose-bound fixture demonstration, not private mapping custody.

[003](003-semantic-judgment-does-not-own-effects.md),
[004](004-brokered-vault-no-direct-mapping-api.md),
[007](007-fail-closed-for-protected-egress.md),
[008](008-minimize-raw-data-retention.md) and
[009](009-secrets-are-not-synthetic-identities.md) remain unchanged.
A real product implementation still needs human adoption, genuine classification and
configured corroboration, deterministic policy, closed CREATE approval, authenticated
subjects/scopes, broker authorization, custody, privacy-safe audit and independent final-byte
egress controls. No part of this proposal substitutes for those gates or held-out evaluation.
