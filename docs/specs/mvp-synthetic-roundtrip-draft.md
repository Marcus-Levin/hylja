# Public-synthetic log round-trip draft seam

Status: PROPOSED / NON-ENFORCING / PUBLIC_DRAFT_ONLY. Not adopted, not a product
classification/effect contract. [Decision 015](../decisions/015-synthetic-log-roundtrip-draft.md)
owns the proposal; [capabilities](../capabilities.md) owns product implementation/limits.
No authority is granted by this specification. No private or held-out data is used.

## S1 pure transformation interface

`transformDraft(contextJson, messageJson, logJson)` in
[`transform.mjs`](../../evaluations/mvp-roundtrip-draft/transform.mjs) takes exactly the
three described primitive string inputs. It is synchronous. It has no experimental IO,
caller callbacks, time, randomness, key generation, policy, authorization or accepted-runtime
dependencies. Extra JavaScript positional arguments are ignored, not interpreted as authority.
No attachment file is read; the log is one caller-supplied string.

All three inputs must be nonempty printable ASCII compact JSON. Character and UTF-8
byte counts are identical. Pre-parse limits are 512 bytes for context, 512 for message
and 16384 for log. No coercion of a non-string occurs. Every object has an exact key set;
key order may vary. After full schema validation, `JSON.stringify(parsed) === original`
must hold: whitespace, escape spellings, duplicate members, negative zero, alternate number
spellings and trailing material refuse. Unknown or missing keys never pass through.
No broad Unicode normalization, encoded-view detection or arbitrary text rewriting occurs.

### Closed schema version 1

Context, supplied separately as public fixture labels, is:

```json
{"version":1,"scope":"SYNTHETIC-SCOPE-A","session":"SYNTHETIC-SESSION-A","context":"SYNTHETIC-CONTEXT-A"}
```

The corresponding whole-string grammars are `^SYNTHETIC-SCOPE-[A-Z0-9]{1,32}$`,
`^SYNTHETIC-SESSION-[A-Z0-9]{1,32}$` and `^SYNTHETIC-CONTEXT-[A-Z0-9]{1,32}$`.
They are public labels, not authenticated tenant/project/session identities. A fixture caller
must change at least one label to separate a new context. Reusing all three reproduces tokens.

Message has exactly `version`, `task`, `asset`:

```json
{"version":1,"task":"SUMMARIZE_FAILURES","asset":"SYNTHETIC-ASSET-A1"}
```

Task is exactly `SUMMARIZE_FAILURES`: the future responder is to count ERROR events for
this message's asset. No prompt/free text, path, metadata or authorization field is admitted.

Log has exactly `version`, `events`. Its dense JSON array has 1..128 events:

```json
{"version":1,"events":[{"asset":"SYNTHETIC-ASSET-A1","tick":1,"level":"ERROR","code":"FAILURE"}]}
```

Each event has exactly `asset`, `tick`, `level`, `code`. `tick` is an integer in 0..1000000.
`level` is `INFO` or `ERROR`; `code` is `START`, `STOP` or `FAILURE`. No relationship between
level and code is enforced; both are faithfully retained. Ticks need not be unique or ordered.
All versions are the number `1`. Every asset is a string matching the **whole** value
`^SYNTHETIC-ASSET-[A-Z0-9]{1,64}$`, the namespace from
[accepted decision 012](../decisions/012-synthetic-engineering-custody-preconditions.md).
Ordinary identifiers, PII, credentials, token-shaped originals and all other fields refuse.
Namespace resemblance is not accepted configured corroboration or a v1 reversible composition:
this draft neither imports nor calls the admission/classification functions.

### Result and reference identity

On success the only members are:

```text
{status: 'TRANSFORMED', cloakedJson: string, references: readonly string[]}
```

The result and references array are frozen. `cloakedJson` is the complete ASCII canonical
compact JSON image, at most 32768 bytes, with keys emitted in this order:

```text
{version: 1, mode: 'PUBLIC_DRAFT_ONLY',
 message: {version: 1, task: 'SUMMARIZE_FAILURES', asset: reference},
 log: {version: 1, events: [{asset: reference, tick, level, code}, ...]}}
```

No context labels, originals or original-to-reference map are returned. Each reference is
`DRAFT-REF-` plus 64 lower-case SHA-256 hex characters, computed over UTF-8 bytes of:

```text
JSON.stringify(['hylja.public-synthetic-roundtrip-draft.reference.v1',
                context.scope, context.session, context.context, originalAsset])
```

Array framing prevents component concatenation ambiguity. Equality is stable independently
of input key/event order, across repeats with exactly the same label tuple and original.
Changing any scope/session/context component changes reference identity (subject to SHA-256
collision assumptions). Distinct original assets have distinct references under that same
assumption. The unique references list is in first-occurrence order, message before log, at
most 129 entries; it contains tokens only and grants no lookup or restoration capability.
The internal cache holds original-to-token equality only within one call and is never exported.

This unkeyed public-data derivation is deliberately dictionary-recomputable and forgeable.
It offers no secrecy, authentication, tenant proof, bearer authority or private-data unlinkability.
It must never be reused as the production scoped-reference primitive. Scope changes in these
tests are fixture separation, not proof of authenticated cross-tenant security.

Any malformed/unknown/oversize/noncanonical input or implementation exception returns exactly:

```text
{status: 'REFUSED', reason: 'TRANSFORM_REFUSED'}
```

That result is frozen and has no image/references/details. No prefix, exception text, planted
value or partially transformed array leaves on refusal. All inputs are validated before output
construction. Nothing is logged or persisted by the subject. Runtime strings, caller copies,
GC/heap/swap erasure, synchronous CPU preemption and cryptographic hash collisions are unproven.

### Fidelity and loss

Accepted enums/ticks and event order/count are preserved exactly; same-asset relationships
across message and log survive. Only complete asset field values are replaced. Input member
order is not preserved: output uses the fixed order above. Formatting/comments/extra fields,
arbitrary logs and opaque content are refused, never silently removed or generalized. This
schema proves no utility for actual logs, contextual re-identification safety, or final egress.

## Future handoffs (interfaces only; separate gates before implementation)

All following behavior remains hypothetical draft fixture semantics, not accepted CREATE,
DISPLAY or custody authority. Integration must not change reviewed S1 schemas silently.

### S2: one-reference scoped fixture owner

Proposed construction inputs: one public synthetic original, its S1 context-label tuple,
a single purpose `SYNTHETIC-LOG-SUMMARY`, fixture operation `DISPLAY`, finite expiry and
initial current revision. An owner privately retains only that one original/reference pair.
No bulk mapping enumeration or originals API is permitted. The fixed later demonstration uses
one asset repeated throughout the message/log; S1's wider multi-asset case confers no owner capacity.

Proposed operation: `displayOne(reference, fixtureRequest, now)` returns one synthetic original
or one fixed non-echoing refusal, not a collection. The closed fixture request must independently
match the owner's label tuple, exact purpose and operation; provider text can supply only the
reference. Current ACTIVE state, current revision and `now < expiresAt` are mandatory.
Unknown/foreign reference, purpose mismatch, USE/EXPORT substitution, expiry, revoked/deleted
state, stale revision or invalid request denies without revealing an original. Lifecycle changes
are monotonic; revocation cannot be undone by replay. These are fixture checks, not principal
or workload authentication, broker policy, registry/audit durability or private custody.
Exact construction/request/lifecycle representations require Root's S2 assignment and review.

### S3: fixed attachment and deterministic responder integration

Proposed handoff: a separately gated integration owner reads only one fixed public synthetic
attachment, calls S1, and supplies **exactly** `cloakedJson` to an in-process deterministic local
responder. It must capture exact input/output byte images without substituting reconstructed
objects as evidence. No real provider, model, socket, child or attachment IO is exercised in S1.
Root must approve the complete method/source and finite commands before any experimental IO.

Proposed responder output is one bounded compact ASCII JSON string (1024-byte ceiling):
`{version: 1, summary: 'FAILURES_FOUND' | 'NO_FAILURES', reference: token, errorCount: integer}`.
It contains exactly one reference: the message asset, and errorCount is the number of log
ERROR events with that token (0..128). Summary must agree with count. Response text cannot
assert a purpose, owner identity or grant. The integration independently validates this schema
and reference, asks S2 for that single fixture-purpose DISPLAY operation, then builds a fixed
synthetic displayed answer. Malformed/unknown/foreign/stale response refuses with no partial
answer or raw diagnostic echo. Response parsing/restoration is not an S1 export or test claim.

## Threat coverage and evidence limits

S1 tests exercise whole-value restrictions, original absence in the complete returned image,
repeat equality, scope-label separation, preservation, closed-schema/duplicate refusal,
atomic refusal after late errors, exact byte/event bounds and 1000 deterministic public
property cases. [Tests](../../evaluations/mvp-roundtrip-draft/transform.test.mjs) perform no
experimental IO and are outside the repository's default npm test suite. No held-out scoring,
provider context, authenticated egress, private restore, expiry/revocation execution, or full
round-trip is established. Public references are intentionally not authority against forgery.
Accepted secret floor, decidePolicy identity, USE/DISPLAY/EXPORT separation and human gates remain
unchanged. Future production effects require all accepted policy/authentication/custody/audit and
independent final-byte checks; this experiment proves a pure seam only.
