# Champion/challenger replay and shadow comparison contract (#27)

Status: bounded #27 slice, **OFFLINE, development-only and NON-ENFORCING**. Implementation status
lives in [capabilities.md](../capabilities.md); evaluation rules and the promotion lifecycle remain in
[evaluation.md](../evaluation.md). This document is the interface, the trust boundaries and the
declared limits.

## What this is

A small, provider-independent substrate that compares two **independently provided deterministic
evaluators** over locally generated, obviously synthetic development cases and reports only what the
harness itself observed:

| Piece | File | Role |
| --- | --- | --- |
| Replay/shadow comparison | [`src/champion-replay.ts`](../../src/champion-replay.ts) | `runChampionReplay`, `generateSyntheticReplayCorpus`, `replayMarkerFor` |
| Bundle vocabulary | [`src/evaluation-partitions.ts`](../../src/evaluation-partitions.ts) | Development family IDs; blind families are refused |

It exists so that a candidate bundle can be *observed* against a champion before anyone proposes a
change. It is not a release gate, a scoring run, an authorization surface or a registry.

## Inputs, from three separately supplied sides

1. **Trusted context** (never from a corpus, an evaluator or a report): version, `scope`
   (`tenantId`, optional `projectId`), a `runId` token, a per-run 32-byte `runKey`, and
   **independently pinned** `{id, version, digest}` bundle references for `champion` and
   `challenger`. The digest is a control-plane pin over the exact bundle content; computing it from
   whatever a candidate hands over would defeat it.
2. **Corpus**: development cases with a `caseKey`, a development `family`, a `scope`, synthetic
   `text`, a `marker.expectation` of `DENY`/`NONE`, and a `task` prompt with an expected answer.
   `generateSyntheticReplayCorpus` authors locally generated cases from `count` and `seed` alone.
3. **Evaluators**: `{bundle, evaluate(view)}` for each side. `view` is a frozen copy of
   `{caseRef, family, text, task.prompt}` and nothing else: no expectation, no pins, no run key, no
   other side's result, no report. The evaluator returns `{version, claim, emission, taskAnswer?}`.

Optional **#67-style annotation evidence** (`{version, caseKey, verdict, source}`) may be supplied.
It is provenance-bearing and advisory: it is recorded per case, it can add reason codes, and it can
never change a measured outcome, a side summary, the promotion surface or any production state.

## What the harness measures

* **Privacy marker outcome** — computed here, not reported. The substrate derives the planted marker
  from the case key (`SYNTHETIC-MARKER-<16 hex>`, obviously synthetic and non-routable) and
  *verifies* the declared expectation against the case text: a `DENY` case must actually contain the
  derived marker and a `NONE` case must not, otherwise the case is `REJECTED`
  (`CASE_MARKER_EXPECTATION_MISMATCH`). A label therefore cannot switch the measurement off. An emission
  containing that marker is `MARKER_EMITTED`; otherwise `MARKER_WITHHELD`; a case with no planted
  marker is `NOT_APPLICABLE`; anything unmeasured is `UNKNOWN`. The evaluator's own `claim` is
  recorded separately and a disagreement (`EVALUATOR_CLAIM_MISMATCH`) is its own reason code.
* **Utility expectation outcome** — `MATCH`, `MISMATCH` or `UNKNOWN`, comparing the returned
  `taskAnswer` with the case's expected answer. A mismatch is an observation for a human, never a
  failed run and never a promotion input.
* **Latency and errors** — `elapsedMs` is the harness's own measurement, reported as measured and
  never clamped: `deadlineMs` bounds *waiting for an async answer*, so a synchronously blocking
  evaluator legitimately records more than its deadline and a clamped number would understate real
  work (a declared limit, not a bound on synchronous code). `errors` counts cases that produced **no
  usable evaluation result** — malformed output, evaluator throw/rejection, deadline, cancellation or
  budget exhaustion — and is not a count of evaluator faults alone.
* **Cost** — always `{state: 'UNMEASURED', reason: 'OFFLINE_NO_COST_SIGNAL'}`. There is no offline
  cost signal, so no number, estimate or extrapolation is ever produced.
* **Human-review recommendation** — `HUMAN_REVIEW_RECOMMENDED` with closed reason codes, or
  `NO_FINDING_IN_THIS_SUBSET`, always with `authority: 'NONE'`. The reasons are exactly the union of
  the codes its own records carry, plus `CASE_UNKNOWN`/`CASE_REJECTED` when a case was not measured;
  a deadline or a caller cancellation is therefore never reported as an `EVALUATOR_ERROR`.
* **Disagreements** — per case, which of `PRIVACY`/`UTILITY` differs between the two sides. There is
  no score, no winner and no ranking.

## What it can never do

`promotion` is `{state: 'UNAVAILABLE', authority: 'NONE', gates: REPLAY_PROMOTION_GATES}` and
`productionEligibility` is always `UNAVAILABLE`. The five gates are external and unsatisfiable here:
`AUTHENTICATED_PRODUCTION_REGISTRY_REQUIRED`, `HUMAN_APPROVAL_REQUIRED`,
`HELD_OUT_SCORING_REQUIRED`, `INDEPENDENT_BUNDLE_INTEGRITY_REQUIRED`,
`PRODUCTION_EGRESS_EVIDENCE_REQUIRED`. A challenger therefore cannot replace, promote, roll back or
release the champion; `shadow` is `{mode: 'OFFLINE_DEVELOPMENT', execution: 'IN_PROCESS',
hostedTransport: 'NONE', candidateExecution: 'NONE', authority: 'NONE'}`. No candidate package, model
or hosted transport is executed: the two evaluators are in-process functions supplied by the trusted
caller, and the module imports only `node:crypto` and two in-tree modules. Unknown keys anywhere —
`promote`, `authorization`, an extra field on an evaluator result — are refusals, not defaults: a
flag is never an authorization primitive.

## Explicit unknowns and rejections

`runChampionReplay` never throws and never rejects. A malformed request becomes an `INVALID` report;
everything else becomes a per-case record:

| Condition | Result |
| --- | --- |
| declared bundle id/version differs from the pin | `REJECTED`, `BUNDLE_PIN_MISMATCH`, evaluator never called |
| declared bundle content digest differs | `REJECTED`, `BUNDLE_CONTENT_PIN_MISMATCH`, evaluator never called |
| case scope differs from the trusted scope (including an omitted project) | `REJECTED`, `FOREIGN_TENANT_SCOPE`, evaluator never called |
| duplicate `caseKey` (the first occurrence reserves it whatever its own validity), blind/non-development family, unverified marker, oversized or invalid case text | `REJECTED` with its own code |
| evaluator threw, or its promise rejected | `UNKNOWN`, `EVALUATOR_ERROR` |
| malformed, unknown, missing or structurally hostile evaluator result (unknown claim, non-object, `Proxy`, accessor, unknown key) | `UNKNOWN`, `EVALUATOR_RESULT_MALFORMED` |
| emission over `REPLAY_MAX_EMISSION_BYTES`, or task answer over `REPLAY_MAX_TASK_ANSWER_CHARS` | `UNKNOWN`, `EMISSION_TOO_LARGE` / `TASK_ANSWER_TOO_LARGE` |
| per-case deadline exceeded | `UNKNOWN`, `DEADLINE_EXCEEDED` |
| caller cancellation, or a signal that cannot be interrogated | `UNKNOWN`, `CANCELLED`; a late result is discarded, and a late rejection never becomes an unhandled rejection |
| an observation intrinsic was replaced before or between cases | the observation is still made with the captured reference; `HARNESS_INTRINSIC_TAMPERED` is recorded on the run and on every record, and no armed timer survives the call |
| a replaced `Promise.resolve`/`Promise` | the captured constructor is used, so no case is lost and no deadline timer outlives the call |
| a realm that fails the load-time self-test (mutated before this module was imported) | both entry points refuse explicitly: `INVALID` with `HARNESS_REALM_UNTRUSTED`, and the authoring helper throws the same code |
| a `NONE` case whose text really contains its derived marker, or a `DENY` case that does not | `REJECTED`, `CASE_MARKER_EXPECTATION_MISMATCH` |
| annotation evidence whose case key resolves to nothing (empty, unknown, or a malformed case) | counted in `run.annotations.rejected`, attached to no record |
| whole-run wall-clock budget reached | `UNKNOWN`, `RUN_BUDGET_EXCEEDED` |
| conflicting, unresolved, disagreed or invalid annotation evidence | recorded per case as `CONFLICT`/`UNRESOLVED`/`DISAGREED`/`INVALID` with `ANNOTATION_CONFLICT` / `ANNOTATION_UNRESOLVED` / `ANNOTATION_DISAGREEMENT` / `ANNOTATION_INVALID`; outcomes unchanged |

None of these is a pass, and none falls back to the other side. A rejected or unknown case is
counted in exactly one privacy bucket (`unknown`) and one utility bucket (`unknown`), so an
unmeasured case can never hide inside a count.

## Records

One record per case and side: `{version, runRef, caseRef, casePseudonym, role, scopePseudonym,
bundle, status, annotation, privacy, privacyClaim, utility, reasons, elapsedMs, digest}`. They bind
minted ordinal case references (`case-1…case-N`), a run reference, a scope pseudonym and the bundle
reference, and carry closed reason codes only. Case keys, case text, planted markers, emissions,
tenant labels, task answers, evaluator exception messages and provider strings never enter a record
or a report. `runRef`, `scopePseudonym`, `casePseudonym`, `corpusRef` and each record `digest` are
HMAC-SHA256 over canonical JSON under the trusted per-run key and the run's scope, so the same case
replayed under another tenant or another run key produces unrelated values: no global digest can
correlate two tenants, and none is a bearer credential.

Every reference in a report is shape-valid on **both** paths: the invalid report carries the
well-formed sentinels `unavailable`/`unavailable` with an all-zero digest and an all-zero reference
digest, so a strict downstream validator needs no special case for a refused request. Those
sentinels are not a bundle, not a run and not a key, and they cannot collide with a real one.

A returned report is deep-frozen: every record, its nested references and reason list, both side
summaries, the disagreements, the shadow/promotion/eligibility surfaces, the run block and the run
reasons, so nothing a consumer just read can be edited in place. The freeze visits at most
`REPLAY_MAX_FREEZE_NODES` nodes (`REPLAY_MAX_RECORDS x REPLAY_MAX_FREEZE_NODES_PER_RECORD` plus an
aggregate allowance), which the largest report the bounds can produce cannot reach — the measured
shape is about 22 nodes per record, so the worst case the bounds allow uses roughly 90 % of the
budget — and `records` are frozen before the headline fields, so even an exhausted budget could not
leave a record editable or reach a headline field. A test at the documented maximum (128 cases, 256
records) asserts that all of it is frozen. **Adding a field to a record changes that shape**: raise
`REPLAY_MAX_FREEZE_NODES_PER_RECORD` with it, or the freeze would silently truncate again. This is **not**
tamper-proofing: the digest is a same-run unkeyed commitment, not a signature, and a same-trust
caller can always build a different report.

## Observation integrity, and what it is not

The evaluated function runs between both sides of every measurement, and JavaScript built-ins are
mutable. Every prototype method and static this module calls is therefore captured once at module
load, before any caller's module body can run, and each is invoked through a wrapper that calls it
with the captured `Reflect.apply` (so a call site performs no prototype lookup at all, not even
`Function.prototype.call`):

* `Reflect.apply`, `Reflect.ownKeys`;
* `Object.create`, `Object.freeze`, `Object.keys`, `Object.hasOwn`, `Object.getPrototypeOf`,
  `Object.getOwnPropertyDescriptor`;
* `Array.isArray` and `Array.prototype` `includes`, `some`, `push`, `map`, `filter`, `every`,
  `flatMap`, `sort`;
* `String.prototype` `charCodeAt`, `repeat`, `slice`;
* `Promise.prototype.then`, `Promise.prototype.catch`, `Promise.resolve` (applied to its own captured
  `Promise` constructor, since it uses its receiver), the `String` constructor used for the marker's
  argument coercion, and `Math.floor` for the decimal index keys the bounded array reader builds —
  `RegExp.prototype.test` is deliberately **not** in the set, because the opaque-token and digest
  shapes are scanned by code unit instead of through a pattern implementation;
* `Number.isSafeInteger`, `Number.prototype.toString`, `Math.max`, `Date.now`, `setTimeout`,
  `clearTimeout`.

The set is the module's **complete call closure** — every prototype method, static and global function
it calls, audited site by site — not a selection: `Set` and `Map` were removed in favour of arrays
through the captured membership check, and anything left live would have turned a refusal into a
silent acceptance — an unknown key admitted, an opaque token or malformed digest accepted, a released
marker recorded without its reason, a forged corpus reference — or fabricated a run-level reason
code. A *deliberate* residual is that a call which runs from a timer callback or a promise handler
has no caller to catch it, so `safeDropTimer` and `ignoreRejection` guard themselves: an armed timer
can never outlive the call that armed it, because `bounded` drops it and settles explicitly if
anything in its executor throws. A realm mutated **before** this module is loaded cannot be seen by identity comparison, because the
captured reference and the live one are then the same object — that is the one mutation
`intrinsicsIntact()` cannot catch, and the only actor who can perform it is the caller's own module
body, before the first `import`. Rather than leave that as a documented hole, every captured
primitive is asked **one known answer once, at load**. If the realm cannot answer them, both entry
points refuse explicitly: `runChampionReplay` returns an `INVALID` report carrying
`HARNESS_REALM_UNTRUSTED` and `generateSyntheticReplayCorpus` throws that code, so **no report is
produced from a realm this module cannot vouch for**. Three dependencies were removed as well, so the
worst pre-load mutations cannot reach the behaviour in the first place: the opaque token and hex
digest shapes are scanned by code unit rather than through `RegExp.prototype.test` (which this module
therefore no longer calls), the reason vocabulary, the closed vocabularies and the case-key reservation
use `===` scans rather than a membership method, and the reason list itself is de-duplicated with no
array method at all. What remains is the honest residual: a pre-load mutation that still answers every
known answer while being broken in some other way is outside what identity comparison or a known
answer can detect, so this module assumes it was loaded into an unmodified realm. Separately, the
bounded wait's executor guard is not reachable through a normal `import()`, since producing the broken
promise implementation it defends against means breaking the host's own module machinery first.
Containment is an explicit code-unit scan over the captured references rather than a call to
`String.prototype.includes`. Each entry of `OBSERVED_INTRINSICS` carries a live reader, and the table
is compared at every case boundary and once before the corpus is read, so a replacement is recorded as
`HARNESS_INTRINSIC_TAMPERED` on the record, in the side summary and on the run; the observation
itself stays true, and a run in a mutated environment — including one mutated before the run — is
never presented as clean.

What remains live, stated plainly: the iterator protocol (`for...of`) over module-local tables, the
internals of the shared canonical-JSON helper that derives a record digest (so a digest is not
tamper-proof), the `node:crypto` bindings (immutable in an ES module), `globalThis` properties this
module does not call, memory, and the caller itself. This is evidence integrity, **not sandboxing**;
the trusted caller remains responsible for what code it passes to `evaluate`.

## Bounds

At most 128 cases, 8 KiB per case and per emission, 512-character task answers, 64 keys per supplied
object, 128 annotations, a per-case deadline of 1–5000 ms (default 1000 ms), a 30 s whole-run
budget, 64 disagreements, and at most 128 records per side. The report freeze is bounded as described
above. The whole-run budget is **not** exercised by the committed suite — it needs more than 30 s of
deliberate waiting — so it is verified by one bounded local experiment instead: 128 cases x 2 sides at
about 130 ms per case returned in about 30.1 s with `PARTIAL`, 26 records
`UNKNOWN`/`RUN_BUDGET_EXCEEDED`, that reason present on the run, and all 256 records and the run
reasons frozen. That is a development observation of the bound on one host, not a service SLA. Object inputs are read from own
enumerable data descriptors after one bounded key snapshot, so a `Proxy`, an accessor, a custom
prototype or an extra key is a bounded refusal rather than an executed or reflected value. Cases are
evaluated sequentially in the fixed role order `CHAMPION` then `CHALLENGER`; there is no parallel
evaluation harness and no scheduling input.

## Declared limits and residual risk

* **The marker check is exact UTF-8 substring containment.** An emission that releases an encoded,
  case-folded, split, compressed or recombined form of the marker is recorded as `MARKER_WITHHELD`.
  That is a declared coverage gap, not a privacy guarantee: #19's canonical views remain the
  independent control at a real send point, and this module is not a substitute for it.
* **A fixture expectation, an annotation and an evaluator claim are labels, not authority.** They are
  compared and recorded, never trusted; the harness owns every outcome it reports. Marker presence
  is verified against the case text, so a `NONE` label cannot switch privacy measurement off.
* **The deadline bounds waiting, not synchronous work.** A deadline and a whole-run budget cannot
  interrupt an evaluator that blocks the thread; bounded work holds for settlement, not for a
  caller's own CPU use inside `evaluate`.
* **Cancellation is duck-typed.** A signal that cannot be interrogated is treated as aborted, and
  listener bookkeeping that throws is ignored with the deadline as the backstop, so a hostile or
  polyfilled signal can neither hang a run nor escape as an exception. A real
  `AbortController().signal` is unaffected.
* **The trusted context is trusted, not verified.** This module does not authenticate the caller,
  authenticate or verify the pins, resolve a real registry, distribute a bundle, check its signature
  or reproduce a build. Obtain `scope`, `runKey` and `pins` from the reviewed control plane; a
  caller able to fabricate them can fabricate a comparison.
* **Development corpora are an operator obligation.** Bounds, closed vocabularies, scope equality and
  marker verification are enforced; whether a supplied case text is genuinely synthetic is not, and
  no real, customer or held-out case may be fed to it.
* **No blind or held-out data**, no scored protocol, no #39 v0 freeze, no production registry, no
  rollback path, and no downstream task utility claim. Latency is a local development observation, not
  a service SLA.
* **Development counts are not scores.** A `NO_FINDING_IN_THIS_SUBSET` recommendation means no finding
  in this synthetic subset; it is not an accuracy, safety or approval result.
