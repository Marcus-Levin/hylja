# Decision 016: Isolated public-synthetic multi-asset pilot draft

Status: PROPOSED. Not adopted; human design review is pending. ISOLATED / NON-ENFORCING /
PUBLIC_DRAFT_ONLY. This proposal grants no classification, treatment, CREATE, authentication,
custody, DISPLAY, EXPORT, provider or scoring authority. Work tracking belongs only to
[#271](https://github.com/Marcus-Levin/hylja/issues/271); product implementation and durable
limits belong only to [capabilities](../capabilities.md).

## Problem and proposed boundary

A variable task declaring two assets needs consistent replacement across both the task and
all log events, including repeated assets, unsorted ticks and zero-error assets. Replacing a
prefix before noticing a malformed last event would expose a partial image. The proposed
pure seam validates the complete bounded canonical ASCII unit, then replaces every whole
asset slot atomically. It preserves declared order, event order, equality, ticks and enums.
The [pilot specification](../specs/synthetic-pilot-draft.md) freezes schemas, caps, exact
reference framing, result/refusal shapes and task meaning before implementation.

Keep this experiment separate under `evaluations/synthetic-pilot-draft/`. It neither changes
nor supersedes [proposed015](015-synthetic-log-roundtrip-draft.md), whose fixed experiment
and no-provider contract remain unchanged. [Proposed010](010-separate-information-dimensions-and-task-fidelity.md)
is not adopted. [Accepted012](012-synthetic-engineering-custody-preconditions.md)'s whole
synthetic namespace is only a public fixture constraint here, not configured corroboration,
v1 composition, CREATE or restoration authority.

## Reference and authority separation

References are unkeyed SHA-256 over a new public domain and length-framed public
scope/session/context/asset labels. They are dictionary-recomputable and forgeable, not
secret tokens, identity, authentication, custody, anonymization or private-data unlinkability.
No originals list, originals map, enumeration or lookup API is returned. Changing a context
label separates public fixture references subject to hash collision assumptions, not real
cross-tenant authentication.

A future separately reviewed owner/controller must authorize one reference at a time using
independent purpose, operation, destination, context, revision and clock inputs. Provider
text supplies none of those; USE is not DISPLAY and DISPLAY is not EXPORT. A mixed
valid/invalid response must release no partial displayed answer. Future CLI and native-model
utility evidence require their own finite method/effect gates and public context admission.
They are not implemented or admitted by this P1 contract; no harness becomes a core dependency.

## Consequences and gates

Compact canonical ASCII and closed schemas intentionally refuse arbitrary logs, free text,
unknown fields, escapes, duplicates, alternate numbers, Unicode and trailing material. The
experiment preserves task relationships but makes no production privacy or utility promise.
No secret or credential mapping, accepted-runtime import, policy bypass, private/held-out
input, provider effect or authoritative scoring belongs in the pure seam.

[003](003-semantic-judgment-does-not-own-effects.md),
[004](004-brokered-vault-no-direct-mapping-api.md),
[005](005-evaluation-precedes-authority.md),
[007](007-fail-closed-for-protected-egress.md),
[008](008-minimize-raw-data-retention.md),
[009](009-secrets-are-not-synthetic-identities.md) and
[014](014-authenticated-local-request-evidence.md) remain unchanged. A real product still
requires human adoption, genuine classification/corroboration, deterministic policy,
closed CREATE approval, authenticated subjects/scopes, broker authorization, custody, audit
and independent final-byte egress control. Passing public tests, AI review or a commit
substitutes for none of these gates or the frozen held-out evaluation protocol.
