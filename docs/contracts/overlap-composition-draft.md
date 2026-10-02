# Overlap composition and rewrite DRAFT (#114, proposed)

Status: **proposed, unwired, non-enforcing.** This is a reviewable design and a bounded executable draft,
[`src/overlap-composition-draft.ts`](../../src/overlap-composition-draft.ts), for
[#114](https://github.com/Marcus-Levin/hylja/issues/114) and its owners
[#3](https://github.com/Marcus-Levin/hylja/issues/3),
[#7](https://github.com/Marcus-Levin/hylja/issues/7),
[#8](https://github.com/Marcus-Levin/hylja/issues/8),
[#37](https://github.com/Marcus-Levin/hylja/issues/37),
[#40](https://github.com/Marcus-Levin/hylja/issues/40) and
[#68](https://github.com/Marcus-Levin/hylja/issues/68), with the integration left to
[#13](https://github.com/Marcus-Levin/hylja/issues/13). Implementation status lives only in
[plan.md](../plan.md#current-state).

Nothing here is wired into [`classification.ts`](../../src/classification.ts),
[`policy.ts`](../../src/policy.ts) or any adapter. It does not create a second composer, a second
transformation engine, a second audit ledger or a second evaluation harness: it calls the accepted #3
composer and the accepted #7 rewriter, and it leaves treatment selection, fidelity and release to #4, #13 and
[#19](https://github.com/Marcus-Levin/hylja/issues/19). Proposed
[decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md), the taxonomy draft and
the multidimensional information model remain **proposed** and are not adopted here: this contract
deliberately has no treatment vocabulary, no fidelity predicates and no placeholder grammar.

### Relationship to the accepted classification-unit seam

Main already carries an **accepted** per-occurrence seam,
[`classification-units.ts`](../../src/classification-units.ts) with
[its contract](classification-unit-contract.md), and it remains the owner of v1 classification. This draft is
not a replacement for it and produces nothing it can consume in its place:

- an accepted **unit** is one occurrence, or a crossing overlap of occurrences on one scan line, resolved by
  the accepted #3 composer; nested, disjoint and whole-value-hint candidates deliberately stay separate units;
- a draft **region** is the transitive closure of *overlapping* spans in one coordinate space, and its purpose
  is coverage: a rewrite operates on bytes, so one set of obligations must hold over the whole covered region;
- therefore #13 must still decide **every accepted unit** (policy input) **and** satisfy every draft region
  (coverage input). Fusing them would either hide a nested credential inside a wider unit or hide a wider
  obligation inside a nested unit, which is exactly the failure this issue describes.

## What the upstream overlap rules are, and are not

[Presidio's documented overlap handling](https://presidio.dataprivacystack.org/anonymizer/#handling-overlaps-between-entities)
and its pinned `RecognizerResult` conflict handling resolve overlaps by keeping a higher-scoring entity or the
containing span. That is an upstream library default recorded here as **source evidence**, not as a Hylja
policy decision, an observed Hylja vulnerability or a comparative benchmark. Hylja has no global score
ranking to apply: #6/#8/#9/#37 candidates carry no score at all, so the draft reads no score, emits no score
and has no field in which a score could be traded off. A confidence attached by any producer is neither
consumed nor reproduced.

## The three rules

1. **No winner — obligations are a union.** Findings whose spans overlap in one coordinate space become one
   region whose obligation set is the union of its members' claims. A wider PERSON, URL or engineering span
   and a narrower native SECRET span in the same region are both obligations; neither displaces the other,
   and the region's `obligations.nonReversibleFloor` is set by the credential member, not by span width,
   detector order or any rank.
2. **No loss — consolidation is expressed, never by deletion.** Every accepted finding keeps its own member
   reference, evidence reference, producer, input reference, view location, #7 field location and original
   envelope, whether or not its span was consolidated. `retention` counts received, retained, rejected,
   uncomposed and duplicate evidence **before** consolidation, separately from any policy or egress outcome.
3. **No partial release.** A rewrite is all-or-nothing across the regions. One region that no accepted path
   covers refuses the whole plan. Nothing falls back to the unmodified text.

## Composition

`composeOverlapRegions({ findings, context, uninspected })` reads emitted detector findings in the #6
candidate shape. It never throws, never echoes an input value and never drops an accepted finding: an
unreadable request is `REJECTED`, and an unreadable or unrecognised finding is counted in `retention.rejected`
and `retention.uncomposed` and reported as `INVALID_FINDING` or `UNKNOWN_FINDING_SOURCE`, so lost coverage is
visible and a rewrite refuses past it.

| Situation | Result |
| --- | --- |
| Same view, overlapping or identical spans | one region, members ordered deterministically, `relations` `IDENTICAL` / `CONTAINING` / `CONTAINED` / `PARTIAL` |
| Same view, spans that touch but do not overlap | two regions plus an `adjacencies` entry; adjacency never merges and never claims coverage of the gap |
| Same span, contradictory types (a credential that is also a host) | one region, `obligations.conflicts` includes `SEMANTIC_TYPE`, composed classification `UNRESOLVED` with the SECRET floor retained |
| Same span and identity from two producers or two requests | one region; both evidence references are retained and both members are marked `duplicateIdentity` |
| Two occurrences of one value inside one decoded field value | two members, **not** duplicates: the accepted #6 identity keys on the in-value occurrence offsets, and this draft keys on the same occurrence identity (view, representation, source, class, rule, span, original envelope, field format/span/path digest and in-value offsets) |
| Repeated identical field values | one region per occurrence, each with its own #7 field span and source-bound path digest |
| Escaped, percent- or entity-decoded field value | region `original` is `ORIGINAL_COVER`, never an invented exact span |
| Different normalized views whose original envelopes cover the same bytes | both sets kept, `CROSS_VIEW_OVERLAP` refusal, `UNRESOLVED` |
| Two different original-location families in one view whose original envelopes meet (string root versus byte root) | both kept, `COORDINATE_SPACE_FOREIGN` and `CROSS_VIEW_OVERLAP` refusals, `UNRESOLVED`; disjoint original spans in one view are two ordinary regions |
| Region overlapping a #6 opaque location | `OPAQUE_LOCATION_OVERLAP` refusal, `UNRESOLVED`; a parser or budget gap never reads as inspected-and-clean |
| More findings than `MAX_FINDINGS` | `REJECTED` / `FINDING_LIMIT`, nothing truncated silently |
| A source this draft does not know (`UNKNOWN_FINDING_SOURCE`) | counted in `retention.rejected` and `retention.uncomposed`, reported, and the rewrite refuses with `INCOMPLETE_CANDIDATE_SET` |

The accepted sources are enumerated from the #6 candidate type (`FINDING_SOURCES`), so all four of `SECRET`,
`INFRASTRUCTURE`, `CONTACT` and #10's `CONFIGURED` compose as evidence, and adding a fifth source to #6 fails
this module's **build** rather than silently dropping that source's findings at runtime.

Coordinate space is `v<viewId>|<family>` with families `ORIGINAL`, `UTF8_TEXT`, `ENCODED_RUNS` and
`UTF8_ENCODED_RUNS`. `EXACT` versus `COVER` is a precision difference inside the `ORIGINAL` family, because a
#6 decoded-field candidate and a view-level candidate in the root view address the same offsets. Region refs
(`region-N`), member refs (`region-N-mK`) and ordering are deterministic functions of the finding set alone:
all arrival orders and all score assignments of the same findings produce an identical result.

Each region also carries the ordered per-region **accepted #3 composition** of exactly its members' evidence.
That composition is the #3 result, not a new classifier: a conflicting region is `UNRESOLVED`, a credential
member keeps `sensitivity: SECRET` and `reversible: false`, and an unknown claim keeps the region unresolved
for #4. The draft adds no treatment, no review state and no authorization.

Bounds: 512 findings, 1024 members and 256 regions per composition, 4096 member pairs classified per region
(`MAX_RELATION_PAIRS`), 256 opaque locations, and a source of at most 16 777 216 UTF-16 code units
(`MAX_SOURCE_UNITS`). Reaching the region or relation-pair bound is reported (`REGION_LIMIT`,
`RELATION_LIMIT`) and exceeding the member bound is reported (`REGION_MEMBER_LIMIT`); in each case the
unrepresented findings are counted in `retention.uncomposed`; work stays linear in findings apart from the
bounded pairwise relation and cross-space comparisons.

`MAX_SOURCE_UNITS` is that largest accepted **opt-in** `maxInputUnits` in #6's own unit, not #6's default
ceiling, which is 1 048 576 units: a source longer than that becomes a #6 view only when the trusted caller
opted into a larger budget, and otherwise #6 reports `NORMALIZATION_INPUT_TOO_LARGE` and this module composes
no finding from it, so the plan refuses `NO_REGIONS` rather than composing past a gap. A source this large can
also exhaust #7's cooperative parse deadline, which refuses the parse rather than truncating it and surfaces
here as `SOURCE_NOT_COMPLETE`.

## Rewrite: only the path that already exists

`planOverlapRewrite({ composition, source, format, replacement })` plans the single rewrite this draft can
justify with accepted contracts: replace the trusted #7 field value that covers each region with one opaque
constant supplied by the trusted integration. The covering field is the *smallest* parsed value span that
contains the whole region, so overlapping members inside one field are covered by one edit. `fieldRef` is a
digest of the #7 key path bound to the source digest; key names are payload content and are never emitted.

| Refusal | Meaning |
| --- | --- |
| `REGION_NOT_FIELD_BOUNDED` | the region is not inside any parsed field value (for example protected text in a JSON **key**, or a span crossing two fields). #7 rewrites values only. |
| `ENCODED_VIEW_NOT_REWRITABLE` | the region lives in a decoded view, which has no byte-level map back to the original. #13 must rewrite the encoded envelope or the source. |
| `SOURCE_NOT_COMPLETE` / `SOURCE_AMBIGUOUS` / `SOURCE_HAS_COMMENTS` | the accepted #7 parser refused the source; the rewriter would refuse it too. |
| `REPLACEMENT_INVALID` | empty, oversized, padded or control-character constant. |
| `INCOMPLETE_CANDIDATE_SET` | the composition left a supplied finding unrepresented (unreadable, unknown source, or past a bound): the draft will not rewrite past coverage it does not have. |
| `REGION_EVIDENCE_INCOMPLETE` | the accepted composer could not read this region's evidence set, so its obligation set is unknown. |
| `INVALID_HOST` | a forwarded parse host is not a usable #7 host object. |
| `REPLACEMENT_ECHOES_ORIGINAL` | the constant contains an 8-unit window of a covered original: no echoed, derived or truncated value. |
| `PLAN_BINDING_MISMATCH` | the supplied plan is not the plan this composition, source and constant derive (a tampered region set, span or evidence reference). |
| `POSTCONDITION_BUDGET` | the surviving-run check could not complete inside its probe budget, so the draft refuses instead of under-checking. |
| `STALE_SOURCE_BINDING` / `FORMAT_MISMATCH` | the source bytes or the format are not the ones the plan was made from. |
| `FIELD_SPAN_NOT_IN_SOURCE` | the planned span is no longer a real value span of a re-parse. |
| `UNENCODABLE_REPLACEMENT` / `ROUND_TRIP_MISMATCH` | #7 could not encode the constant for that syntax, or its own round trip disagreed. |
| `ORIGINAL_SPAN_STILL_PRESENT` | after the rewrite, a literal run of at least `coveredWindowUnits(length)` of a covered original — half its length, never fewer than 8 units and the whole value when it is shorter — still exists somewhere in the output. |

`applyOverlapRewrite({ plan, composition, source, format, host? })` treats the plan as a **reviewable
artifact, not an authority**. It re-derives the plan from the composition, the exact source bytes, the format
and the plan's own constant, and refuses anything that does not match, so the region set, each covering field,
the echo rule and every source-level refusal are re-established in the function that returns bytes. It then
verifies the rewrite independently of #7's own claim: each derived span must still be a real value span of a
re-parse, the output must reparse to the same key paths and field count, and no surviving run of a covered
original may remain. Its `provenance` carries only digests, spans, evidence references and a rewritten-field
count — never a value and never a mapping reference, so no reversible alias can be created here.

The surviving-run post-condition is **literal** and proportional: `coveredWindowUnits(length)` is half a
covered original's length, never below `MIN_ECHO_WINDOW` (8), and the whole value below that. A surviving run
of at least that length anywhere in the output is `ORIGINAL_SPAN_STILL_PRESENT`. The rule is deliberately
stronger than a whole-value comparison, because a covered field is usually wider than the protected value
inside it and a partial copy of that value is still a copy.

Known limits of this draft, stated rather than hidden:

- The surviving-run post-condition is a **literal** check. A case or separator variant that no candidate
  source reported and that shares no literal run with a covered original (`SYN TOK 4F2B9C7E1D INVALID` for
  `syn-tok-4f2b9c7e1d.invalid`) is not a literal run: the rewrite legitimately succeeds and only #19 on the
  exact serialized bytes refuses the release. That catch is the sentinel's alone and is never credit for a
  merge or a transformation. Conversely two protected values that share half of one of them literally make
  each other look surviving, and the rewrite refuses conservatively.
- **`REWRITTEN` is not a completeness signal.** It says the regions this composition describes were rewritten
  and no covered run survived. Findings the caller never received — for example the ones #6 never emitted
  because it reached its own per-source candidate cap — are outside it, and that residual is the
  integration's to judge with #19.
- Whole-field replacement is deliberately coarse. It protects every obligation inside a field, but it also
  rewrites unprotected bytes in that field. Per-occurrence fidelity is #13 and #66/#68's subject.
- `applyOverlapRewrite` verifies everything it can from the composition, the source bytes and the constant.
  What it cannot know is the caller's own coverage: a composition built from a partial finding set is applied
  faithfully and completely **for those findings**. #19 remains the independent backstop for everything else.
- Nothing here binds to an interaction, authenticates a caller, holds a stream back, meters a treatment or
  records an effect. All of that is #13's and the audit ledger's.

## Separate outcomes

The four outcome kinds are measured and asserted separately, never collapsed:

| Outcome | Where it is observed | What it does not prove |
| --- | --- | --- |
| Candidate retention | `composition.retention` before consolidation | nothing about treatment, rewrite or egress |
| Classification composition | `region.composed` (#3) | nothing about authorized effects |
| Source location | `region.original`, `member.view`, `member.field`, plan `fieldSpan` | nothing about the bytes that will be sent |
| Rewrite | `applyOverlapRewrite` result and its provenance | nothing about protected release |
| Final bytes | #19 `checkEgress` on the exact serialized bytes | nothing about authorization, which is #4/#13's |

A #19 catch in any case is an independent catch. Where a case has both a successful rewrite and a sentinel
block, the block is reported as a sentinel outcome only.

## Not decided here

- Which treatment each region receives, how obligations that cannot be combined are resolved, and any
  ordering among treatments: #66/#68 and #4, not this draft.
- Fidelity predicates, placeholder grammar and reversible identity semantics: the information-model draft and
  #13, not this draft.
- The transport, holdback and streaming behavior for a partially rewritten region: #13.
- Whether Hylja adopts any third-party anonymizer: unrelated and open.

## Pending #13 obligations

Where no accepted path exists, the draft refuses and names the obligation: rewrite protected text outside
parsed field values (keys, syntax, inter-field text); rewrite decoded views or their encoded envelopes in the
original source; choose per-occurrence treatments when a whole-field replacement is too coarse; decide whether
a refusal withholds the whole message or holds back one region; carry transformation provenance into the
privacy-safe evidence path; and register these reason codes in the release/audit vocabulary.
