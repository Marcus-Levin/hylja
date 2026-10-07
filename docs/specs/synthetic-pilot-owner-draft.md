# Public-synthetic pilot one-reference owner draft

Status: PROPOSED / ISOLATED / NON-ENFORCING / PUBLIC_DRAFT_ONLY under
[proposed016](../decisions/016-synthetic-multi-asset-pilot-draft.md). Not adopted; no
accepted CREATE, DISPLAY, authentication, custody, policy or evaluation authority.
[Capabilities](../capabilities.md) alone owns product implementation and durable limits.
This contract is frozen before the new owner behavior tests and implementation.

## Pure factory and reference binding

[`owner.mjs`](../../evaluations/synthetic-pilot-draft/owner.mjs) exports ONLY synchronous
`createPilotOwner(configJson, contextJson, original)`. Inputs are primitive strings;
no caller objects, coercion, callbacks, I/O, time source, randomness, model, keys or
accepted policy dependency. Extra positional arguments are ignored, never authority.
The factory validates the entire unit before exposing any handle. It uses ONLY reviewed
[`derivePilotReference`](../../evaluations/synthetic-pilot-draft/transform.mjs) from the
[P1 contract](synthetic-pilot-draft.md) for reference/context/original validation and
reference derivation, never a copied hash grammar or the legacy015 domain.

Context is capped at512 printable ASCII bytes and follows P1's exact closed compact
canonical version/scope/session/context grammar; input key order may vary as in P1.
Original is a whole `SYNTHETIC-ASSET-[A-Z0-9]{1,64}` public marker (17..80 ASCII bytes).
Accepted012's namespace is a fixture constraint, not CREATE or restoration authority.

Config is nonempty printable ASCII compact JSON capped at1024 bytes. Exactly these
members in exactly this order, with no unknown/missing/duplicate/escaped/noncanonical
members, Unicode, array, primitive or nested-object substitutes:

```text
{version:1,displayPurpose:'SYNTHETIC-PILOT-RESULT',
 displayDestination:<whole SYNTHETIC-DISPLAY-[A-Z0-9]{1,32}>,
 adminPurpose:'SYNTHETIC-OWNER-LIFECYCLE',
 adminDestination:<whole SYNTHETIC-ADMIN-[A-Z0-9]{1,32}>,
 createdAt:<integer0..1000000>,expiresAt:<integer0..1000000>,revision:1}
```

`createdAt < expiresAt`. Parsing checks primitive, length and printable ASCII first.
Closed schema/order checks and exact JSON round-trip reject alternate numeric spellings,
negative-zero JSON, escapes, whitespace, trailing text and duplicate keys.
Each handle privately retains exactly ONE validated public original/reference/context/config
and independent fixture lifecycle state. No module-shared mappings, caches or tenant state.

Success is EXACT frozen `{status:'OWNED',mode:'PUBLIC_DRAFT_ONLY',displayOne,revoke}`.
There is no original/reference/map/list/accessor/bulk lookup surface. Every factory or
method failure is the same frozen `{status:'REFUSED',reason:'PILOT_OWNER_REFUSED'}`;
no mode, value, reference, prefix, exception detail or partial handle accompanies refusal.

## Independent one-reference requests

`displayOne(reference, requestJson, now)` accepts only a primitive whole
`DRAFT-PILOT-REF-` plus64 lowercase hexadecimal characters (80 bytes) matching its bound
reference. Foreign, unknown, legacy, stale, prefix, array and object references refuse.
Request JSON is nonempty printable ASCII, capped at1024 bytes, closed/canonical with
exact member order:

```text
{version:1,scope:<bound scope>,session:<bound session>,context:<bound context>,
 purpose:'SYNTHETIC-PILOT-RESULT',operation:'DISPLAY',
 destination:<independently configured display destination>,revision:<current1or2>}
```

DISPLAY requires a valid clock observation, not closed, current revision1, exact reference
and fully matching request. Repeated eligible DISPLAY is permitted, not single-use.
Success is EXACT frozen
`{status:'DISPLAYED',mode:'PUBLIC_DRAFT_ONLY',original:<one bound marker>,revision:1}`.

`revoke(adminJson, now)` uses the same cap/canonical/order/eight-member request schema,
with purpose `SYNTHETIC-OWNER-LIFECYCLE`, operation `REVOKE`, independently configured
admin destination and current revision. DISPLAY/USE grants cannot revoke; admin grants
cannot display. USE is not DISPLAY; DISPLAY is not EXPORT. Provider text supplies NO
purpose, operation grant, destination, context, revision or clock. These independent public
fixture labels authenticate nothing and are not production authorization or trusted time.

Proper initial revoke closes the owner and advances revision1 to2, returning EXACT frozen
`{status:'REVOKED',mode:'PUBLIC_DRAFT_ONLY',revision:2}`. A proper current-revision2
repeat is idempotent. Revision1 is stale afterward and refuses. No renewal, reactivation,
rebinding, deletion command or configuration mutation API exists.

## Sticky fixture lifecycle

Initial revision1, high-water=`createdAt`, closed=false. EVERY display/revoke invocation
observes `now` FIRST, even if candidate/request/grant later refuses. Primitive finite safe
integers0..1000000 at least the high-water mark are valid; equal observations are allowed,
and numeric-0 equals0. Valid observations advance high-water even on denied calls.
`now >= expiresAt` permanently closes without itself changing revision.

Invalid, nonfinite, fractional, out-of-range, wrong-type or rollback observations permanently
close and immediately refuse that invocation, without coercion/enumeration. No later valid
observation reopens closure. Proper admin may acknowledge closure caused by expiry or
an earlier invalid clock if this invocation's clock is valid/monotonic and its grant matches
current revision: first acknowledgment advances to2; repeats require2. Closed is NOT the
same as an invalid current observation. Wrong admin can advance time/trigger expiry but
cannot advance revision. No closure/revocation path returns an original or reactivates.

## Evidence and explicit limits

[`owner.test.mjs`](../../evaluations/synthetic-pilot-draft/owner.test.mjs) exercises positive
factory/display/lifecycle behavior against a new all-refusing baseline (not a product defect),
fixed negative shapes, hostile primitives, exact restoration, context separation, independent
owners and at least1000 bounded generated public identity/lifecycle cases. Boolean/numeric
assertions do not print planted values. Focused runner:

```sh
node --test evaluations/synthetic-pilot-draft/owner.test.mjs
```

Maximal valid config/context/display/admin schemas are below their caps. Raw exact/over
cap malformed refusals are NOT valid-at-cap acceptance or cutoff-order branch evidence;
source inspection establishes pre-parse bounds. Public unkeyed references remain forgeable
and dictionary-recomputable. This seam authenticates nobody, sends no bytes, persists no
state and proves no private custody, erasure, trusted clock, OS protection, authenticated
cross-tenant isolation, model utility or held-out score. Closing a public fixture owner is
logical lifecycle control, not caller/returned/string/heap/swap erasure.

P3 separately owns the multi-reference controller and complete reply validation before any
restoration, internal staging of individual eligible values, and whole-answer refusal if any
later owner denies, with no partial displayed answer or trace. P2 tests do not establish that
atomicity or CLI behavior. Reconstructing fresh fixture owners across runs is not persistent
or global revocation/currentness. Dedicated pilot CI is separately gated; default product
CI and diagnostic enumeration exclude these pilot tests. Passing tests/AI review/commit
adopts none of proposed010/015/016 or the accepted policy/authentication/custody/evaluation
gates. Legacy015/Gate1 and accepted core remain unchanged.
