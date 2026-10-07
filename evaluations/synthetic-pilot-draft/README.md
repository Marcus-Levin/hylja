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
