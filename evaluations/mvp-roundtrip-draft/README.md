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

The explicit focused commands (not part of default `npm test` or CI suite enumeration) are:

```sh
node --test evaluations/mvp-roundtrip-draft/transform.test.mjs
node --test evaluations/mvp-roundtrip-draft/owner.test.mjs
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

## S2 one-reference fixture owner

[`owner.mjs`](owner.mjs) is a synchronous, isolated proposed owner for exactly one public
synthetic original and its unchanged S1 reference. `createDraftOwner(configJson, contextJson,
original)` accepts only bounded primitives; its frozen handle exposes only `displayOne` and
`revoke`. The [S2 specification](../../docs/specs/mvp-synthetic-roundtrip-draft.md#s2-one-reference-scoped-fixture-owner)
freezes the exact closed JSON configuration, independent DISPLAY request, separate hypothetical
administrative request, fixed refusals, revision conflicts and restrictive lifecycle semantics.
No lookup/enumeration surface, reference-as-authority, caller callbacks or experimental IO exists.

DISPLAY requires the complete bound reference, fixture scope/session/context, fixed summary
purpose/operation, separately bound destination, current revision and active clock interval.
Observed expiry and invalid/rollback clocks latch terminal refusal; revision-2 revocation cannot
be replayed at revision 1 or revived. Dropping the public original reference is not secure erasure.
Request labels and numeric fixture clocks are unauthenticated; response text must not supply them.
These predicates grant no accepted DISPLAY/CREATE, broker, custody, trusted time, audit or policy.
Only the owner component is exercised; the fixed file/responder integration remains separately gated.

[`owner.test.mjs`](owner.test.mjs) covers exact restoration, frozen bound/no-bulk handle behavior,
foreign/forged/prefix reference refusals, independently varied request components, malformed,
unknown, duplicate, escaped, nested and oversize inputs, no caller-object inspection, expiry
boundary/stickiness, invalid-clock/rollback deletion, separate administrative revocation,
stale/current revision conflicts, idempotency and 1000 bounded generated identity/lifecycle cases.
The valid behavior RED uses an explicit all-refusing new-draft baseline, not an existing-product
defect. Public synthetic pure tests establish neither authenticated tenant isolation nor a full
round-trip, private restoration, final-byte egress, responder/model utility or scored evaluation.
No passing test, commit or AI review adopts proposed015 or opens any human/product gate.

## S3 fixed public file and deterministic responder

[`integration.mjs`](integration.mjs) composes the unchanged pure seams with one fixed
[`public synthetic attachment`](fixed-synthetic-log.json), a bounded read-only regular-file
adapter, an actual ASCII byte boundary to an in-process deterministic responder, strict reply
validation and one independently configured fixture-purpose DISPLAY. There is no model inference,
provider, network, socket, child, private input, caller path/callback or accepted runtime wiring.
The [S3 specification](../../docs/specs/mvp-synthetic-roundtrip-draft.md#s3-fixed-attachment-and-deterministic-responder-integration)
owns the exact interfaces, byte/refusal semantics, finite scenarios and integration limits.

After a separate full-code/source/method and finite-command experimental gate:

```sh
node --test evaluations/mvp-roundtrip-draft/integration.test.mjs
node evaluations/mvp-roundtrip-draft/demo.mjs
```

The demo prints one public synthetic result with the actual responder-consumed/returned byte
captures, independent DISPLAY request, and displayed answer, or one fixed refusal. It accepts no
path/options. A fresh fixture owner per run does not prove shared durable revocation/currentness
or accepted CREATE authority. These explicit focused tests/demo are not default npm test or CI.
Independent reproduction needs its own method gate, not the writer's permission.

[`integration.test.mjs`](integration.test.mjs) distinguishes physical fixed-file reproduction
from injected primitive-text/scenario cases. It checks exact original absence over actual outbound
captures, failure counting including zero and maximum count, order/enum/tick/equality fidelity,
one exact restored answer, atomic fixed refusals, request/lifecycle isolation and strict response
schema/count/reference checks. Injected invalid attachment cases do not exercise OS fault paths;
tests never mutate the fixture. The component RED uses an explicit pure all-refusing baseline,
not an existing product defect. Output/counts belong to the external run-specific evidence packet.

Only public synthetic values may be captured or displayed here. Read flags require supported
numeric constants, but do not prove ancestor/hard-link/mount confinement, concurrent-file
atomicity, finite native blocking or kernel containment. Native failure reproduction, private
custody/erasure, real authorization/tenants, actual model/provider utility, protected egress,
held-out scoring and human adoption remain unproven. Passing this draft grants none of them.
