# Public-synthetic multi-asset pilot draft

Status: PROPOSED / ISOLATED / NON-ENFORCING / PUBLIC_DRAFT_ONLY. No accepted policy,
classification, CREATE, DISPLAY, custody, authentication, provider or scoring authority.
[Decision016](../decisions/016-synthetic-multi-asset-pilot-draft.md) owns the proposal;
[capabilities](../capabilities.md) owns product implementation and durable limits.

## P1 frozen pure interface

[`transform.mjs`](../../evaluations/synthetic-pilot-draft/transform.mjs) exports only synchronous
`transformPilot(contextJson, messageJson, logJson)` and
`derivePilotReference(contextJson, asset)`. All inspected caller inputs are primitive strings;
extra positional arguments are ignored, never authority. No caller-object enumeration,
coercion, callbacks, time, randomness, I/O, keys or accepted-runtime dependencies exist.

All JSON inputs are nonempty printable ASCII compact JSON. Before parsing, context is capped
at512 bytes, message at1024 and log at16384. ASCII byte counts equal string lengths.
Every parsed object has the exact specified key set. Input key order may vary, but
`JSON.stringify(parsed) === input` must hold after complete schema validation and before
reference/output construction. This rejects whitespace, duplicate members, escape spellings,
noncanonical numbers (including negative zero), Unicode and trailing material. No arbitrary
text or opaque suffix is passed through. Every input is validated before ANY output is built.

### Closed schemas

Context has exactly numeric `version:1`, `scope`, `session`, `context`. Whole-string grammars
are unchanged from Gate1: `SYNTHETIC-SCOPE-[A-Z0-9]{1,32}`,
`SYNTHETIC-SESSION-[A-Z0-9]{1,32}`, `SYNTHETIC-CONTEXT-[A-Z0-9]{1,32}`.
These are public labels, not tenants/principals/trusted identities.

Message has exactly numeric `version:1`, `task:'ERROR_COUNTS'|'FIRST_ERRORS'`, and
`assets`: a dense array of1..8 distinct whole strings matching
`SYNTHETIC-ASSET-[A-Z0-9]{1,64}` (17..80 bytes). No reference-shaped originals,
ordinary identifiers, credentials, free text, paths or authority fields are admitted.

Log has exactly numeric `version:1` and `events`: a dense array of1..128 records.
Each has exactly `asset` (same whole namespace), integer `tick` in0..1000000,
`level:'INFO'|'ERROR'`, `code:'START'|'STOP'|'FAILURE'`. No level/code relationship
is imposed. Ticks may repeat or be unsorted. The distinct log asset set must equal the
message's declared asset set, independent of order. Every declared asset therefore has at
least one event, but can have zero ERROR events. Missing/extra assets refuse atomically.
The fixture namespace from [accepted012](../decisions/012-synthetic-engineering-custody-preconditions.md)
is not configured corroboration, classification or effect authorization.

### Exact public reference derivation

`derivePilotReference` independently validates the complete context and whole asset string.
Let `frame(s)` be the decimal ASCII byte length of `s`, followed by `:`, followed by `s`.
The SHA-256 input is the UTF-8 encoding of this exact concatenation, with no separator,
terminator or JSON escaping beyond each frame:

```text
frame('hylja.public-synthetic-pilot-draft.reference.v1') +
frame(context.scope) + frame(context.session) + frame(context.context) + frame(asset)
```

Reference format is `DRAFT-PILOT-REF-` plus64 lowercase hexadecimal digest characters.
Same context tuple/asset gives the same reference across both APIs, tasks and key/event
orders. Changing ANY tuple dimension or asset separates references subject to SHA-256
collision assumptions. Framing prevents concatenation ambiguity; unkeyed public digests
remain dictionary-recomputable/forgeable, not secret, anonymous, authenticated or authority.

### Closed frozen results

Derivation success is exactly frozen
`{status:'DERIVED',mode:'PUBLIC_DRAFT_ONLY',reference:string}`.
Transform success is exactly frozen
`{status:'TRANSFORMED',mode:'PUBLIC_DRAFT_ONLY',cloakedJson:string,references:readonly string[]}`.
`references` is frozen, unique and in declared message asset order, never an original list/map.
No original or context label appears in any returned field. There is no lookup API.

`cloakedJson` is one complete compact ASCII image capped at32768 bytes, emitted in this
fixed member order (all message and log asset slots are replaced):

```text
{version:1,mode:'PUBLIC_DRAFT_ONLY',
 message:{version:1,task:<unchanged task>,assets:[<references in declared order>]},
 log:{version:1,events:[{asset:<reference>,tick:<unchanged>,level:<unchanged>,code:<unchanged>},...]}}
```

Any malformed, nonprimitive, unknown, oversize, noncanonical, mismatched or late-invalid
input, or implementation exception, returns only frozen
`{status:'REFUSED',reason:'PILOT_TRANSFORM_REFUSED'}` from either API. No reference,
image, inspected prefix, exception detail, planted value or partial array is returned.
Internal per-call equality mapping is ephemeral and never exposed.

### Byte-bound reachability

| Unit | Cap | Reachable canonical bound | Boundary evidence |
|---|---:|---|---|
| Context |512|Less than256: three labels of at most48/50/50 bytes plus fixed framing|Maximal valid labels admitted; raw512/513-byte malformed inputs refused|
| Message |1024|Less than800: eight80-byte assets plus fixed framing and either task|Maximal valid declaration admitted; raw1024/1025-byte malformed inputs refused|
| Log |16384|Reachable with128 events, matching at most8 assets and variable integer ticks|Schema-valid canonical16384-byte input admitted;16385-byte input differing only in valid tick length refused|
| Cloak |32768|Less than22000: each event at most141 bytes, each reference80 bytes, at most128 events and8 message refs, fixed framing less than512 bytes|Maximum-shaped reachable input admitted below cap; over-cap valid output is unreachable|

Raw exact/over refusals at unreachable caps are not valid-at-cap acceptance or branch/order
proof: identical fixed refusals cannot distinguish cap from schema rejection. Source inspection
establishes the pre-parse guards independently. The output guard is defensive; no fabricated
over-limit branch exercise is claimed. Input log cap can further narrow the conservative
cloak bound. Hash collisions, runtime string/caller/heap/swap erasure and CPU preemption
are unproven; this seam sends no bytes and authenticates nobody.

## Future P2/P3/utility handoffs: unimplemented, not admitted

Task meaning is fixed for later responders: ERROR_COUNTS counts ERROR level events per
asset, irrespective of code. FIRST_ERRORS returns the earliest ERROR tick per asset with
stable original input-index tie breaking, or explicit no-error result. Declared asset order
and event indices remain available through the cloak. P1 implements no responder.

A separately reviewed one-reference owner/controller must bind independent purpose, DISPLAY
operation, destination, context, revision and clock; provider text supplies only candidate
references/task data and NO authority. USE does not imply DISPLAY; DISPLAY does not imply
EXPORT. No bulk originals API or reversible credential mapping is permitted. Mixed
valid/invalid replies release NO partial displayed answer. P1 implements no owner/restoration.

A future bounded CLI may consume variable public synthetic inputs and a generic external
response JSON seam, with a default offline deterministic responder. No provider/harness
runtime dependency is selected here. Actual stdin/stdout, attachment/responder/model effects
need separately frozen methods/commands and admissions. Public original/cloaked native utility
runs need separately frozen blind requests and exact-model qualification; they are not scored,
held-out, adopted or authorized by this contract. P1 implements none of those later effects.

## Pure evidence limits

[`transform.test.mjs`](../../evaluations/synthetic-pilot-draft/transform.test.mjs) exercises
bounded synthetic schemas, equality/order/enums/ticks, atomic fixed refusal, no originals,
immutability, derivation and generated independent context variation. It is public unscored
component evidence, not protected-egress safety, private restoration or model utility.
Legacy015/Gate1 remains unchanged. Default product CI and diagnostic enumeration do not
exercise these pilot tests; dedicated pilot integration/CI is a later assignment.
