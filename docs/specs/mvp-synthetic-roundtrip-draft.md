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

The isolated proposed [`owner.mjs`](../../evaluations/mvp-roundtrip-draft/owner.mjs) exports
only `createDraftOwner(configJson, contextJson, original)`. All arguments are primitives;
config/context are nonempty printable ASCII compact JSON capped at 512 bytes each. Original
matches S1's whole synthetic asset grammar (17..80 ASCII bytes). Exact closed key sets and
`JSON.stringify(parsed) === input` refuse duplicates, escapes, alternate numbers, whitespace,
unknown/missing/nested fields and trailing material; input key order may vary. Extra positional
JavaScript arguments are ignored, not authority. No caller objects, callbacks or coercion occur.

Configuration has exactly these members:

```json
{"version":1,"purpose":"SYNTHETIC-LOG-SUMMARY","operation":"DISPLAY","destination":"SYNTHETIC-DISPLAY-A","adminDestination":"SYNTHETIC-ADMIN-A","createdAt":10,"expiresAt":100,"revision":1}
```

Purpose/operation are fixed literals. Destination grammars are
`^SYNTHETIC-DISPLAY-[A-Z0-9]{1,32}$` and `^SYNTHETIC-ADMIN-[A-Z0-9]{1,32}$`.
Times are integers in 0..1000000; `createdAt < expiresAt`; initial revision is exactly 1.
Context is unchanged S1 version/scope/session/context JSON. Construction calls unchanged
`transformDraft` with that context, original, fixed task `SUMMARIZE_FAILURES`, and exactly
one log event `{asset: original, tick: 0, level: 'INFO', code: 'START'}`. It requires the complete
TRANSFORMED result and exactly one reference, retaining only that public original/reference
pair plus bounded metadata. No reference derivation/lookup export is added to S1.

Construction returns frozen `{status: 'OWNED', owner}`; owner is frozen with only two bound
methods, `displayOne(reference, requestJson, now)` and `revoke(adminRequestJson, now)`.
It exposes no original, reference, enumeration, collection lookup or metadata read API.
Successful display returns frozen `{status: 'DISPLAYED', value: original}`. Any constructor
or operation refusal returns only frozen `{status: 'REFUSED', reason: 'OWNER_REFUSED'}`;
no handle, partial value or diagnostic echo accompanies refusal.

DISPLAY request is a separately supplied primitive compact ASCII JSON string (512-byte cap)
with exactly `version`, `scope`, `session`, `context`, `purpose`, `operation`, `destination`,
`revision`. Version is 1, label tuple matches S1 context, purpose is `SYNTHETIC-LOG-SUMMARY`,
operation is `DISPLAY`, destination matches configuration and revision equals current revision.
Only one primitive candidate reference matching the complete S1 grammar and bound reference
is accepted, never a prefix, array or foreign token. USE/EXPORT and response-shaped attempts
to manufacture authority refuse. Provider/responder text supplies only the candidate reference;
S3 must independently supply fixture configuration/request, never derive them from response.

Administrative request is separately supplied primitive JSON with the same bounds/canonical
checks, exactly `version`, `scope`, `session`, `context`, `administrativePurpose`, `operation`,
`destination`, `revision`. Tuple/version must match, administrativePurpose is exactly
`SYNTHETIC-OWNER-LIFECYCLE`, operation exactly `REVOKE`, destination matches adminDestination,
and revision is current. DISPLAY/USE requests cannot revoke. ACTIVE revision 1 revokes to
REVOKED revision 2, drops the retained original and returns frozen
`{status: 'REVOKED', revision: 2}`. Correct repeat at revision 2 is idempotent; revision 1
replay conflicts and refuses. No renewal, activation, deletion command or revival exists.
No accepted MAPPING_ADMIN/CREATE grant is borrowed or inferred.

Every operation observes independently supplied primitive `now` first, even if its request
or candidate later refuses. This public fixture clock is not real-time/kernel authority.
Valid observations are integers in 0..1000000, at least the last observation (initially
createdAt); they advance the high-water mark even on a denied request. ACTIVE with
`now >= expiresAt` becomes permanently EXPIRED revision 2 and drops original. Invalid or
rollback observation while ACTIVE becomes permanently DELETED revision 2 and drops original.
Both refuse all later operations, including rollback/revocation. REVOKED remains terminal;
only valid monotonic observations and a matching revision-2 admin request may acknowledge
idempotent revocation, even after expiry. Invalid/rollback observations refuse without
changing that terminal state. Display requires ACTIVE/current revision and
`createdAt <= now < expiresAt` at the synchronous operation itself. No async gap, timer,
callback, renewal or implicit fresh deadline exists. Terminal states never reveal originals.

These are restrictive hypothetical fixture predicates, not authentication, accepted policy,
a broker, custody, audit/registry durability, trusted clocks or secure erasure. Dropping one
runtime string reference does not erase caller, returned, GC/heap/swap copies. Public labels
and digest predictability confer no authority. S1's multi-asset support confers no owner capacity.
[`owner.test.mjs`](../../evaluations/mvp-roundtrip-draft/owner.test.mjs) is public, unscored,
pure component evidence; S3 integration and any real effects still require separate gates.

### S3: fixed attachment and deterministic responder integration

The isolated proposed [`integration.mjs`](../../evaluations/mvp-roundtrip-draft/integration.mjs)
composes S1/S2 unchanged. `runFixedDraft(scenario = 'VALID')` reads only
[`fixed-synthetic-log.json`](../../evaluations/mvp-roundtrip-draft/fixed-synthetic-log.json)
through a module-relative fixed file URL. No caller path, callback, upload, configuration,
request, clock or responder injection API exists. `runInjectedDraft(logJson, scenario = 'VALID')`
accepts primitive synthetic log text only; its cases are not physical filesystem fault evidence.
Both admit only the finite scenario literals in the module; nonprimitive/unknown scenarios refuse
before file effects. Root's full-method/finite-command gate precedes experimental execution;
independent reproduction requires its own gate. S1 itself still has no attachment/responder IO.

The fixed file contains only `SYNTHETIC-ASSET-A1`, also the separately fixed message's asset.
The reader requires present numeric `O_RDONLY`, `O_NOFOLLOW`, `O_NONBLOCK`, opens read-only,
checks descriptor regular-file status and size 1..16384, and reads into one owned 16385-byte
Uint8Array using positive-progress bounded `readSync` calls until zero-byte EOF. Overflow,
size mismatch, nonprintable/non-ASCII bytes or native exceptions refuse. The descriptor is
closed in `finally` before downstream work; a close exception withholds success. There is no
unbounded `readFileSync` allocation. The complete text then passes unchanged S1 canonical/schema
checks and the stricter one-fixed-original constraint. No prefix or partial answer is returned.

Exactly S1's `cloakedJson` is encoded to ASCII bytes. The in-process deterministic responder
captures the numeric byte snapshot it actually consumes and parses that snapshot; its returned
Uint8Array is captured at the controller, not reconstructed from parsed response fields. There
is no model inference, provider, network, socket, child or retry. The response is compact ASCII
JSON capped at 1024 bytes, with exactly `version`, `summary`, `reference`, `errorCount`:
`{version: 1, summary: 'FAILURES_FOUND' | 'NO_FAILURES', reference: token, errorCount: integer}`.
Count is ERROR events for the bound message reference, 0..128, irrespective of code. The
controller independently validates closed schema, canonical bytes, version, reference and exact
count/summary agreement against its admitted image before S2. Response text supplies no purpose,
owner identity, destination, revision, clock or grant.

Independent literal fixture config/context/request select S2's summary-purpose DISPLAY at
`now = 20`, createdAt 10, expiresAt 100, revision 1, destination `SYNTHETIC-DISPLAY-A`.
Only that one response reference is submitted. Each run constructs a fresh public fixture owner;
this is not shared lifecycle/currentness, authentication or accepted CREATE authority. On success,
one frozen result contains `status: 'DISPLAYED'`, `mode: 'PUBLIC_DRAFT_ONLY'`, integer `errorCount`,
`answer` (at most 256 bytes), and a frozen `trace`. Answer is exactly
`Synthetic log summary for SYNTHETIC-ASSET-A1: <count> ERROR events.`
Trace holds `attachmentKind` (`FIXED_FILE` or `INJECTED_TEXT`), immutable numeric `attachmentBytes`,
actual immutable `consumedBytes`/`returnedBytes`, independent `displayRequestJson` and `displayNow`.
These public original-bearing attachment/display artifacts are not outbound responder context.
Any refusal is exactly frozen `{status: 'REFUSED', reason: 'INTEGRATION_REFUSED'}` with no trace,
answer, exception, path or partial output. Extra positional arguments confer no authority.

The finite injected scenarios cover wrong purpose/destination/USE/EXPORT, foreign scope/session/
context, stale revision, expired/revoked/rollback fixture owners, unknown/foreign/malformed
references, malformed/oversize/non-ASCII/duplicate/escaped/trailing responses, wrong count type,
negative/over/disagreeing count, disagreeing summary and authority smuggling. Invalid synthetic
attachment text and no-failure utility are in-memory cases, never claims of physical OS failure.
The fixed fixture is never mutated by tests. Exact original absence is checked over complete
actual responder byte captures; event order/count/tick/enum fidelity and restored answer are
checked separately. Tests are public unscored development evidence, outside default CI enumeration.

The reader requires a trusted stable local directory/file and POSIX-style constants; unsupported
platforms refuse. Flag presence does not prove hostile ancestor, hard-link or mount confinement,
concurrent-file atomicity, finite native blocking, CPU preemption or kernel containment. Owned
buffer wiping does not prove string/heap/caller/swap erasure. No private restoration, real-tenant
isolation, protected-egress safety, accepted policy, model utility, held-out score or human adoption
is established. [`demo.mjs`](../../evaluations/mvp-roundtrip-draft/demo.mjs) prints only this public
synthetic result or a fixed refusal; it accepts no CLI path/options.

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
