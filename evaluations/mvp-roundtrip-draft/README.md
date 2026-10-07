# Public-synthetic round-trip draft experiment

Status: PROPOSED / PUBLIC_DRAFT_ONLY / NON-ENFORCING. Not adopted; no accepted
classification, policy, CREATE, custody, DISPLAY, authentication, provider or scoring authority.
See [decision 015](../../docs/decisions/015-synthetic-log-roundtrip-draft.md) and the
[closed draft seam specification](../../docs/specs/mvp-synthetic-roundtrip-draft.md).
Product capabilities and durable limits have their single home in
[capabilities](../../docs/capabilities.md).

## Pure seam

[`transform.mjs`](transform.mjs) consumes three compact ASCII JSON strings: public fixture
scope/session/context labels, a fixed synthetic summary-task message, and one closed-schema
synthetic log. It returns either one complete cloaked image with scoped opaque references or
one fixed atomic refusal. No originals/map are returned; there is no lookup API. All asset
values must match the whole `SYNTHETIC-ASSET-[A-Z0-9]{1,64}` namespace.

This is hypothetical draft fixture transformation, **not** an accepted treatment selection.
No accepted source module or policy is imported, relabelled or bypassed. SHA-256 references
are deterministic public-data digests, dictionary-recomputable, not secret/authenticated/
anonymous, and never restoration authority. Only public synthetic markers may be supplied.
The module has no file, socket, child, provider, model, key, registry or restoration effects.
It is not a full round-trip demo or protected-egress boundary. Later owner/restoration and
attachment/responder methods need their own gates and exact reviewed component contracts.

## Verification

The explicit focused command (not part of default `npm test` or CI suite enumeration) is:

```sh
node --test evaluations/mvp-roundtrip-draft/transform.test.mjs
```

[`transform.test.mjs`](transform.test.mjs) is deterministic public development evidence for
pure schema/transformation invariants. It covers complete-image original absence, repeated
asset identity, changed scope/session/context, whole-value grammar, closed schema and
noncanonical/duplicate refusal, atomic refusal, exact log byte/event limits, preservation,
frozen outputs and 1000 bounded generated context cases. It uses Node's test runner and no
new dependencies or experimental IO. Passing tests do not adopt the proposal, authenticate
scope labels, prove cryptographic unlinkability, grant effects or authorize scored evaluation.

RED/GREEN command output and run-specific counts belong to the external author evidence
packet, not product capability documentation. The RED checkpoint is against an explicit
all-refusing new-draft baseline; it is not an existing product defect. The repository's
fixture guard checks indexed paths, and the docs guard checks indexed Markdown links.
The default diagnostic-assertion guard does **not** enumerate these new draft tests.
No test logs compare raw captured output or original-bearing objects.
