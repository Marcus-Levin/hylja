# Semantic judge shadow contract (#11)

Status: draft foundation contract for a local/synthetic-only shadow seam. It describes observable
behavior of [`src/semantic-judge-shadow.ts`](../../src/semantic-judge-shadow.ts) and the narrow
protocol adapter [`src/typesafe-system-one-adapter.ts`](../../src/typesafe-system-one-adapter.ts). It
is not authorization, not policy and not an egress control. Implementation status lives only in
[capabilities.md](../capabilities.md).

Scope and dependencies follow [issue #11](https://github.com/Marcus-Levin/hylja/issues/11):
[#3](https://github.com/Marcus-Levin/hylja/issues/3) classification,
[#5](https://github.com/Marcus-Levin/hylja/issues/5) evaluation vocabulary,
[#6](https://github.com/Marcus-Levin/hylja/issues/6) normalization and
[#10](https://github.com/Marcus-Levin/hylja/issues/10) configured candidate sources. The seam consumes
none of them for authority; it emits evidence for [#3](https://github.com/Marcus-Levin/hylja/issues/3)
and remains subject to [#4](https://github.com/Marcus-Levin/hylja/issues/4) policy.

## Authority

1. A semantic judgment is evidence. It may propose a semantic class with a bounded confidence, and
   nothing else. It never names a sensitivity, subtype, scope, reversibility, trust, purpose or
   treatment (decisions [002](../decisions/002-sensitivity-and-trust-are-separate.md),
   [003](../decisions/003-semantic-judgment-does-not-own-effects.md),
   [009](../decisions/009-secrets-are-not-synthetic-identities.md)).
2. Every record carries `authority: 'NONE'` and `advisory: { suggestedTreatment: 'NONE', effect:
   'IGNORED_NO_AUTHORITY' }`. No code path in the module can select a treatment, grant release,
   authorize a sink or lower deterministic evidence. Semantic failure cannot relax protected egress
   (decision [007](../decisions/007-fail-closed-for-protected-egress.md)).
3. Shadow means no policy authority, **not** permission to transmit. A hosted judge is its own
   external sink (see below).
4. A judge cannot be a candidate source. PERSON/EMAIL/PHONE and customer/project candidates come from
   #37 and #10; shadow judgment never supplies a missing category.

## Question sets

`defineShadowQuestionSet` is a trusted-configuration operation, not per-request input. A set carries
an id and a version, and 1..32 questions of exactly the three documented System One kinds:

| Kind | Documented shape | Evidence a question may propose |
| --- | --- | --- |
| `noul` | yes/no probability; optional `criteria: { true, false }` | one semantic class |
| `choice` | 2..255 labelled options | class per selected option |
| `score` | 2..10 ordered levels | class per level index, derived locally |

Rules:

- question ids are lowercase identifiers, because an id travels as request metadata and the
  provider states that ids are never sent to the model; a value-shaped id is refused
  (`QUESTION_ID_REVEALS_VALUE`);
- instruction and criteria text comes from trusted configuration. The core validates structure and
  never writes raw input text into either;
- a `propose` block may name a semantic class only. Sensitivity, reversibility and scope are not
  accepted as shadow claims, and an unknown field is `UNEXPECTED_FIELD`;
- a `noul` question proposes one class (`semanticType`); a `choice` or `score` question maps every
  option or level (`byLabel`). A bare `semanticType` on a labelled question, or `byLabel` on a Noul,
  is refused (`INVALID_REQUEST`) rather than accepted and silently ignored, which would leave the
  question abstaining forever;
- a duplicate id, an over-long question set or an out-of-range option or level count is refused
  before any request exists;
- changing a set changes its version. A record from a previous version is not comparable evidence.

## Minimization

`minimizeShadowRequest` builds the only object an adapter may translate:

- the raw candidate value and every neighbouring text fragment are read for validation and then
  dropped; they are replaced by request-local ordinal placeholders (`cand-01`, `nbr-01`, ...) plus
  the caller's candidate/neighbour kind;
- approved context is a closed key to closed-code table (`surface`, `contentType`, `fieldKind`,
  `containerKind`, `script`, `neighborCount`, `positionInField`), at most eight entries, one per key.
  An unknown key is `UNAPPROVED_CONTEXT` and an unlisted code is `UNAUTHORIZED_CONTEXT_CODE`, so a
  value cannot ride in as "context";
- the request carries interaction, tenant, candidate, question-set, judge and model references that
  the trusted integration assigned. The seam does not authenticate those references; the integration
  must mint privacy-safe opaque refs, exactly as for every other seam in this repository;
- the request is branded. A forged or copied request object cannot be translated, so raw text cannot
  be smuggled into a judge state through an adapter;
- `request.digest` covers the minimized view. Two runs over different raw values with the same
  references, kinds and context produce the same digest, which is the testable form of "the raw
  value was omitted".

A known credential is not representable: the candidate-kind vocabulary has no credential or secret
kind, so a #8 finding cannot become judge input even by mistake.

## Execution, timeout and cancellation

`runShadowJudgment` returns `{ record, settlement }`:

| Situation | Record | Notes |
| --- | --- | --- |
| complete, well-formed answer | `ANSWERED` | evidence proposals for the answered questions |
| answer present but rejected | per answer `INVALID` with its own closed reason | outcome `PARTIAL` |
| answer absent, or for an unknown question id | `MISSING` / `UNKNOWN_ANSWER` | outcome `PARTIAL` |
| proposal maps to no class | `ABSTAINED` | no evidence entry |
| deadline elapsed | `TIMEOUT` / `TIMED_OUT` | no answers, no evidence |
| caller aborted before or during the run | `CANCELLED` / `CANCELLED` | independent of which promise settles first |
| transport refused or threw | `REFUSED` with `ADAPTER_REFUSED` / `ADAPTER_THREW` | |
| response over 32 KiB | `REFUSED` / `RESPONSE_TOO_LARGE` | checked before parsing |
| `execution: 'EXTERNAL'` or anything else | `REFUSED` with `UNSUPPORTED_EXECUTION`, `MISSING_DESTINATION_POLICY`, `MISSING_ROUTE_BINDING`, `MISSING_BYTE_VERIFICATION` | refused before a request exists |

Two independent controls make a late result observable, as a real network adapter must handle it:
caller cancellation aborts the judge's own work, while the deadline only stops *waiting*.
`settlement.late` reports whether the judge's work settled after the record was already final; a late
answer is discarded and never merged into the record. Failures never produce an empty-looking
success: the outcome is always explicit and every reason is a closed code.

`runShadowJudgment` never throws and neither promise it returns ever rejects. A hostile or
time-varying caller object, a script that cannot be interpreted, or a caller object whose `Proxy`
traps throw all resolve a conservative record with closed codes; identity that was never validated
is reported as the fixed placeholder `unbound`, never as the value that failed. This matters
because `settlement` is the documented way to observe late work: a rejected `record` promise would
have no handler attached and would terminate the process under Node's default
`--unhandled-rejections=throw`.

The caller's `input` is read exactly once. The candidate, its neighbours and its context are taken
from a single validated descriptor snapshot, so an object that answers differently on a second read
cannot substitute a value that was never validated for the one that was.

An option object with an unknown key (`safe`, `synthetic`, `trusted`, `destinationPolicy`,
`routeBinding`, `byteVerified`, `authorization`, ...) is refused. A caller flag is not an
authorization primitive, and neither is a token-shaped string in a candidate reference.

## Data-only input and output

A local script, and any body a protocol adapter validates, is **data**, never behavior:

- `createLocalShadowJudge` copies each answer through own enumerable **data** descriptors into frozen
  JSON values under a depth, key, string and byte budget (`SHADOW_MAX_JSON_DEPTH`,
  `SHADOW_MAX_JSON_KEYS`, `SHADOW_MAX_JSON_STRING`, `SHADOW_MAX_RESPONSE_COPY_BYTES`). An accessor,
  a function, a `toJSON` method, a symbol, a BigInt, a cycle, a sparse array, a non-finite number, a
  custom prototype or an over-budget value is refused there, with `INVALID_REQUEST`, **before any
  caller code can run**. Nothing a caller supplied is executed later by parsing, measuring or
  recording, and later caller mutation cannot change an issued judge.
- A script may answer at most `SHADOW_MAX_SCRIPT_ANSWER_KEYS` keys (the whole question set). The
  parser allows a surplus of `expected.size + SHADOW_MAX_QUESTIONS` keys, so a module-issued judge
  can never produce a payload the seam then refuses to interpret: a surplus answer is an explicit
  `UNKNOWN_ANSWER` reason, not a failed run.
- Serialization for the size checks is Hylja's own bounded walk, not `JSON.stringify`: it reads only
  own enumerable data descriptors, never consults `toJSON`, a prototype or `[[Get]]`, and stops at a
  byte ceiling that is a multiple of the documented limit, so an oversized request or response is
  still refused by its own closed over-limit code.
- A caller `Proxy`'s traps are the one thing JavaScript still runs before they can be contained. A
  trap that throws is reported as the context's own closed code (`INVALID_REQUEST` for
  configuration and requests, `MALFORMED_RESPONSE` for responses), so no caller exception message
  leaves this module or its adapter.

## Records and privacy

- Every record is frozen, versioned, and carries question-set and judge versions, the requested and
  served model, the request digest and byte count, per-question answers with the provider's
  probability distribution and confidence, latency, response bytes, deadline and token usage.
- Nothing in a record, a reason, a thrown code or a diagnostic contains a raw value, a model answer's
  free text, a provider error body or an arbitrary exception message. Rubric text a provider echoes in
  a Score legend is shape-checked and counted, never returned.
- Failure, timeout and cancellation **after a request was built**, and any refusal of a response the
  seam could not interpret, keep interaction, tenant, candidate, question-set and judge identity plus
  the echoed deterministic floor, so an outage is attributable without carrying anything protected. A
  refusal decided **before** a request exists — `EXTERNAL`, a forged set or judge, input that cannot
  be validated — carries the fixed `unbound` placeholder instead, because no identity was ever
  validated; it never carries an unvalidated or raw value, and the floor is echoed once it was read.
  `deterministicFloor` is a caller assertion recorded for evaluation; nothing in this module reads it,
  and no field of a record can lower it.
- Evidence is shaped for the #3 composer's `semanticJudgments` channel (`version`, `id`, `status`,
  `provenance`, `claim`). The channel names the source, so a record carries no `source` field of its
  own, and a claim carries `semanticType` plus `confidence` only. A caller supplies the evidence to
  the composer separately.
- `belongsToShadowTenant` is congruence for replay, not authentication: a caller able to fabricate a
  record fabricates its answer. Cross-tenant replay is refused.

## Why there is no external path here

Sending a judge request would need three controls that do not exist yet:

1. core destination policy authorizing the judge sink and profile for its own outbound request;
2. an authenticated binding to the actual routed judge destination, not a claimed one;
3. an independent [#19](https://github.com/Marcus-Levin/hylja/issues/19) check of the exact
   serialized outbound bytes, including metadata, immediately before send.

Until all three exist, only local judgment or obviously synthetic input is permitted. The executable
judge here is a module-issued data script: it cannot open a socket, read a credential or reach a
network, and its served-model label must be `local-synthetic/*` so a development double can never be
mistaken for a hosted judgment in evaluation evidence. A fake local transport is not network
authentication and not interception, and no model-generated token text acquires control trust.

## Narrow protocol adapter

`src/typesafe-system-one-adapter.ts` translates one issued minimized request into the documented
System One body and validates one response body. It has no transport, no credential handling, no SDK
dependency and no I/O, so the repository cannot send a judge request from it.

Primary sources inspected on 2026-09-28 (re-verify before any hosted integration; nothing is
installed, executed or contacted):

- `https://docs.typesafe.ai/api` -- `POST /v1/systemone`, request `{ state, model, questions }`,
  response `{ model, answers, usage: { input_tokens, output_tokens } }`, question types `noul`,
  `choice` (at most 255 options), `score` (2..10 levels), answers `{ type, noul }`,
  `{ type, choice, probabilities, confidence }`, `{ type, score, legend, probabilities, confidence }`,
  statuses 401/422/429/529.
- `https://docs.typesafe.ai/primitives` -- a question id identifies its answer, is never sent to the
  model and is not used in inference.
- `https://docs.typesafe.ai/models` -- `jev-latest` and `jev-preview` are aliases that move between
  releases; the response `model` field reports the versioned id that answered. Hylja records served
  model evidence, so a moving alias is refused (`MODEL_ALIAS_NOT_PINNED`) and a model id is required
  explicitly (`MODEL_ID_REQUIRED`).
- `https://docs.typesafe.ai/primitives/choice|score|noul`, `/confidence` -- every answer is
  constrained to the supplied options or levels, `choice` is the highest-probability option,
  `probabilities` covers every option or level, and only Choice and Score carry `confidence`.
- `https://docs.typesafe.ai/model-jaggedness/jev-1.13` -- score levels are weak in numerical
  calibration and must not be interpolated into a magnitude; a question and its negation are not
  complementary; adversarial state content can move an answer. A discrete level is therefore derived
  locally by argmax and marked `levelIsLocallyDerived`.
- npm `@typesafe-ai/sdk@0.6.0` `dist/index.d.mts` and `dist/index.mjs`, inspected as a downloaded
  tarball only -- published request/answer types, `POST /v1/systemone`, `GET /v1/models`,
  `x-typesafe-request-id`, `APITimeoutError`, `APIUserAbortError`, `RateLimitError` (429) and
  `InternalServerError` (any 5xx, including the documented 529 overload status).

Adapter rules:

- request translation is bound to the issued question set and requires an explicit pinned model id;
- structural defects throw a closed code, per-answer defects become closed problems, so one bad answer
  cannot hide the rest;
- an unknown field anywhere in a response is refused rather than passed through, so a provider
  addition, a model-generated field and a proxy-smuggled instruction are one malformed response;
- documented provider statuses map to distinct closed reasons (`PROVIDER_UNAUTHORIZED`,
  `PROVIDER_REJECTED`, `PROVIDER_RATE_LIMITED`, `PROVIDER_OVERLOADED`); every other status,
  including a success code, is `UNEXPECTED_PROVIDER_STATUS`. No status code is ever a judgment;
- a `null` Choice criteria description is not accepted: Hylja question sets supply text for every
  option so that the question is reproducible and reviewable.

## Threat → test map (local synthetic evidence only)

| Threat | Case |
| --- | --- |
| semantic-service privacy paradox | minimized request, wire body and record are asserted to contain no raw candidate, neighbour or context value; digest is content independent |
| judge outage relaxing protection | timeout, cancellation, refusal and thrown transport each produce an explicit outcome with no answers, no evidence and no treatment |
| late answer changing a final record | deadline stops waiting only; `settlement.late` observed and the late payload discarded |
| judge failure mislabelled as a real answer | per-answer `INVALID`/`MISSING` status, closed reasons, `INCOMPLETE_ANSWERS` |
| oversized or malformed metadata | `RESPONSE_TOO_LARGE` before parsing; usage, served model and answer-shape validation |
| a rejected promise, or an exception thrown out of the entry point | `record` and `settlement` resolve for every input; a child process running the documented settlement-only usage exits 0 |
| adversarial KEEP suggestion | a `keep_original_value` option yields a semantic claim only; shadow evidence alone stays `UNRESOLVED`, a deterministic `SECRET` credential floor survives, and policy denies the external sink with `semanticRecommendation: 'KEEP'` |
| model-generated control text | `treatment`, `sensitivity`, `trust`, `instructions` and `authorization` fields are `UNEXPECTED_FIELD`; question ids are shape-constrained |
| caller flags as authorization | `safe`/`synthetic`/`trusted`/`destinationPolicy`/`routeBinding`/`byteVerified` options are refused |
| external send by configuration | `EXTERNAL` is refused with the three missing-control codes and no request bytes |
| forged question set, judge or request | brand checks refuse look-alike objects, so raw text cannot enter a request |
| cross-tenant replay | generated tenant/ref/bounds vectors stay tenant bound; a foreign tenant ref fails `belongsToShadowTenant` |
| provider/protocol drift | documented limits enforced (255 options, 2..10 levels); a moving model alias refused; an unknown response field refused |

Known limits, stated rather than hidden:

- caller-supplied references (`interactionRef`, `tenantRef`, `candidateRef`) are trusted to be
  privacy-safe opaque; the integration must mint them, and this seam does not sanitize them;
- question instruction and criteria text is trusted configuration; this seam cannot verify that it
  embeds no protected text, only that the core never writes raw input text into it;
- reported probabilities are checked for complete, finite, in-range coverage of exactly the supplied
  options or levels, but they are **not** required to sum to 1. That is a deliberate relaxation of the
  documented distribution: a sum check would need an invented numeric tolerance, and a distribution
  that does not normalize cannot change the locally derived argmax. A sum assertion is a candidate
  evaluation question, not something this seam may calibrate;
- a Score `score` reported by the provider is recorded but never used as the level, and a level is
  never interpolated (see the model-jaggedness note above);
- a timed-out run leaves the local double's own script timer pending, so a process can stay alive up
  to `SHADOW_MAX_SCRIPT_LATENCY_MS`. The deadline only stops waiting; the late settlement is still
  observable through `settlement.late`;
- the local judge is a deterministic script; no model, provider, latency or cost behavior is measured
  here, and served-model, latency and usage metadata describe the double, not a hosted model;
- no score is computed against any #39 protocol, and no held-out corpus, blind split, planted oracle
  or custodian record was read, generated or compared in this work;
- semantic accuracy, over-cloaking and downstream utility are unmeasured; only the conservative
  behavior of the seam is tested.