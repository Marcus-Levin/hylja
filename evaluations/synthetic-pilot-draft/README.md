# Public-synthetic multi-asset pilot draft

Status: PROPOSED / ISOLATED / NON-ENFORCING / PUBLIC_DRAFT_ONLY. No accepted runtime,
classification, policy, CREATE, DISPLAY, custody, authentication, provider or scoring authority.
See [decision016](../../docs/decisions/016-synthetic-multi-asset-pilot-draft.md) and the
[frozen pilot contract](../../docs/specs/synthetic-pilot-draft.md). Product implementation and
durable limits belong only to [capabilities](../../docs/capabilities.md).

## Pure P1 seam

[`transform.mjs`](transform.mjs) exports only `transformPilot(contextJson,messageJson,logJson)`
and `derivePilotReference(contextJson,asset)`. Primitive bounded canonical ASCII inputs only:
closed public context labels, either ERROR_COUNTS or FIRST_ERRORS,1..8 distinct declared
synthetic assets and1..128 ordered events whose asset set exactly matches the declaration.
It preserves all task/equality/order/tick/enum data and replaces all whole asset slots, or
returns one frozen fixed refusal without partial output. References are public unkeyed,
dictionary-recomputable/forgeable SHA-256 values in a distinct length-framed pilot domain,
not identity, custody, authentication, anonymization or restoration authority. No originals
list/map/enumeration/lookup is returned. No provider/harness dependency or subject I/O exists.

This P1 unit implements no owner, responder, CLI, attachment, stdin/stdout or model execution.
Those later units require separate contracts/review/method admissions. The
[legacy015 experiment](../mvp-roundtrip-draft/README.md) is unchanged and not authority for
this pilot. Public fixture grammar from accepted012 is not CREATE/DISPLAY authorization.

## Explicit pure verification

```sh
node --test evaluations/synthetic-pilot-draft/transform.test.mjs
```

[`transform.test.mjs`](transform.test.mjs) is public unscored deterministic component evidence,
including1000 bounded generated multi-asset cases with independent scope/session/context/task
variation. The RED checkpoint uses an explicit new all-refusing baseline, not a product defect;
run-specific raw outputs/counts/times live in the external author evidence packet.

The explicit runner is not in default `npm test`, coverage or product CI enumeration.
Default diagnostic assertion guarding checks only its pre-existing named test file, not these
pilot tests. Assertions here compare booleans/numbers and never print planted inputs/results.
Fixture/docs guards use the indexed owned paths. Dedicated pilot CI is a later integration
assignment; passing product guards is not evidence that product CI ran this suite.

The contract documents which byte caps are reachable. Unreachable exact raw caps exercise
malformed refusal, not valid acceptance or proof of cutoff order. Source inspection establishes
pre-parse bounds. No fabricated output-over-cap branch, protected egress, authenticated tenant
isolation, private restoration/erasure, real model utility, held-out scoring or adoption is claimed.

## P2 pure one-reference fixture owner

[`owner.mjs`](owner.mjs) exports only `createPilotOwner(configJson,contextJson,original)`;
its [separate frozen owner contract](../../docs/specs/synthetic-pilot-owner-draft.md) is
PROPOSED / NON-ENFORCING / PUBLIC_DRAFT_ONLY under016, not adopted authority.
It binds exactly one public marker using unchanged P1 derivation, exposing only a frozen
status/mode/`displayOne`/`revoke` handle and fixed non-echoing failures, no originals list,
map, reference property or bulk lookup. Independent fixture configuration and ordered closed
DISPLAY/admin requests bind purpose, operation, destination, tuple, revision and supplied clock.
Provider text supplies none of these. USE is not DISPLAY; DISPLAY is not EXPORT.

Every invocation observes time first, including denied calls. Invalid/rollback/expiry clocks
close permanently; valid denied observations advance the high-water mark. Only a proper
current administrative request advances revision to2, and valid current2 acknowledgment is
idempotent even after closure. No reactivation/rebinding/renewal exists. Public labels/time
are not authenticated identity, trusted clocks, accepted CREATE/DISPLAY or private custody.
A fresh owner is separate fixture state, not persistent/global revocation/currentness.

Explicit finite pure component verification:

```sh
node --test evaluations/synthetic-pilot-draft/owner.test.mjs
```

[`owner.test.mjs`](owner.test.mjs) uses a NEW all-refusing factory RED baseline and unchanged
GREEN behavior tests, including1000 bounded generated identity/lifecycle cases, independent
owners and adversarial closed/canonical/primitive/reference/purpose/clock/revision checks.
Run-specific raw receipts remain external. Default product tests/CI/diagnostic guarding do not
enumerate this suite; dedicated pilot CI is a separate integration assignment. Passing P2
establishes no multi-reference whole-answer atomicity, CLI/stdin/stdout, actual model utility,
authenticated tenants, OS protection, private erasure, held-out scoring or human adoption.
P3 must validate a complete reply before restoring, stage individual eligible values internally,
and refuse the whole displayed answer/trace on any later owner denial, with no partial output.

## P3 isolated controller, offline responder and reusable CLI contract

The [separate P3 specification](../../docs/specs/synthetic-pilot-cli-draft.md) freezes
`preparePilot(inputJson)` / `completePilot(inputJson,replyJson,controlsJson)`, independent
per-reference public fixture owners, reference-only provider replies, whole-answer staging,
and an explicitly OFFLINE deterministic `respondPilot(cloakedJson)`. Provider output never
supplies purpose, grant, context, destination, revision or clock. Semantically incorrect but
schema-valid replies are not silently recomputed. No complete-answer API accepts bare refs
as a bulk-original lookup. Input is bounded closed public JSON, not arbitrary production logs.

The CLI has exactly one verb `cloak`, `display` or `demo`, with one canonical compact ASCII
stdin packet and optional single terminal LF. It takes NO path/options/provider credential,
opens no file and makes no network/model calls. Stdout is one complete cloak or displayed
answer JSON plus LF; logical refusal is exactly
`{"status":"REFUSED","reason":"PILOT_CONTROLLER_REFUSED"}` plus LF, exit2. Success exits0;
I/O exception exits1 without raw stderr. Logical late denial emits no answer prefix; OS
failure after a write began may leave partial bytes and is not transactional rollback.
Descriptor0/1 provenance, native blocking, authentication, confinement and erasure are unproven.

From the repository root, pass the documented generic packets on stdin:

```sh
node evaluations/synthetic-pilot-draft/cli.mjs cloak
node evaluations/synthetic-pilot-draft/cli.mjs display
node evaluations/synthetic-pilot-draft/cli.mjs demo
```

`cloak` packet: `{version:1,inputJson:<public input JSON string>}`.
`display` packet: `{version:1,inputJson:<input>,replyJson:<external response JSON string>,controlsJson:<independent controls JSON string>}`.
`demo` packet: `{version:1,inputJson:<input>,controlsJson:<controls>}` uses only the deterministic
offline responder. Field order and inner schemas/caps are specified in the P3 contract.
For reusable public examples, `cases.mjs` exports12 immutable `{id,inputJson,controlsJson}`
objects, without answers/ground truth. Example packet construction (no subject execution):

```js
import { pilotCases } from './evaluations/synthetic-pilot-draft/cases.mjs';
const sample = pilotCases[3];
const demoPacket = JSON.stringify({ version: 1, inputJson: sample.inputJson, controlsJson: sample.controlsJson });
const cloakPacket = JSON.stringify({ version: 1, inputJson: sample.inputJson });
// Send cloakPacket to cloak; supply returned cloak to your separately admitted responder.
// Put its canonical reply in the replyJson field of a display packet; keep controls separate.
```

Dedicated verification explicitly enumerates all five pilot suites, including actual public
stdin/stdout subprocess cases (not native model traffic):

```sh
npm run test:synthetic-pilot-draft
```

[Dedicated synthetic CI](../../.github/workflows/synthetic-pilot-draft.yml) runs these suites
and explicitly guards all five assertion files with the unchanged diagnostic checker.
Default product suite/diagnostic enumeration is unchanged; those defaults alone still do NOT
verify the pilot. Actual published CI, independent review and native-model utility observations
need their own receipts/gates; no local run or offline response is a substitute.
Public preparation originals/cloaks are bounded below the planned8192-byte per-arm context
cap, but future independent preparation must freeze complete blind prompts/ground truth and
actual native subjects before model effects. No corpus tuning, authoritative scoring,
held-out result, human adoption, merge, release or private production support is implied.
