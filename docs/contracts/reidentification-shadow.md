# Contextual re-identification shadow contract (#12)

Status: draft foundation contract for a local/synthetic-only shadow measurement seam. It describes
observable behavior of [`src/reidentification-shadow.ts`](../../src/reidentification-shadow.ts)
built on the reviewed [#11 shadow seam](semantic-judge-shadow.md). It is not authorization, not
policy, not a transformation and not an egress control. Implementation status lives only in
[plan.md](../plan.md).

Scope follows [issue #12](https://github.com/Marcus-Levin/hylja/issues/12): a re-identification
question set, a quasi-identifier candidate model, generalization recommendations as advisory
signals, and a synthetic unique-combination corpus. The issue's dependency is
[#11](https://github.com/Marcus-Levin/hylja/issues/11); no other runtime seam is used or changed.

## Authority

1. The report is `authority: 'NONE'`, and its advisory block is `{ applied: false, effect:
   'IGNORED_NO_AUTHORITY', requiresDeterministicPolicy: true }`. No code path here selects a
   treatment, transforms content, generalizes a value, authorizes a sink or releases bytes
   (decisions [003](../decisions/003-semantic-judgment-does-not-own-effects.md),
   [005](../decisions/005-evaluation-precedes-authority.md),
   [007](../decisions/007-fail-closed-for-protected-egress.md)).
2. A generalization recommendation is a *derived fact about a corpus*, not an instruction. Its
   `derivedFacts` (equivalence site and record counts, distinct-handle counts, the advisory target)
   are evidence that deterministic policy would have to evaluate. `implemented` is always `false`:
   there is no generalization function in this module, and therefore no predicted post-generalization
   cell size.
3. Issue #12 requires a separate promotion decision before any of this can influence a release. No
   such decision exists, and nothing here is wired into classification, policy, transformation or an
   adapter send point.
4. A shadow flag is not a finding about a real entity. It is a measurement on a synthetic corpus.

## The corpus

`createReidentificationCorpus()` returns the shipped **development** corpus; a caller may pass its
own synthetic spec, which is read strictly.

- A record is a `siteRef` plus quasi-identifiers `{ ref, dimension, handle }`. It carries **no text
  of any kind**: no site name, geography, date, process or project name exists anywhere in the
  corpus, so this seam cannot produce a lexical match and "the name was still present" is not an
  available failure mode. Every record states `directNameReplaced: true`, which is the issue's
  precondition, and that key is refused when it is absent or false.
- `handle` and `ref` are abstract opaque `.invalid` tokens minted by a fixed pure function so the
  corpus is reproducible. Their opacity is **presentational**: the corpus is entirely synthetic and
  committed in this repository, so nothing is hidden by them. In a real integration a handle comes
  from the broker/vault under purpose-bound authorization; this module never mints or resolves one.
- A record is either an `EVALUATED_CASE` (it carries a planted `label`) or `POPULATION_BACKGROUND`
  (it must not). That asymmetry is enforced: a missing label on a case and an invented label on a
  background record are both refused, so a record can never become silently "safe".
- `familyId` names the corpus family so a reader can see what a case is for:
  `REIDENTIFIABLE_RARE_COMBINATION`, `REIDENTIFIABLE_SAME_SITE_PAIR`,
  `NOT_REIDENTIFIABLE_SHARED_COMBINATION`, `NOT_REIDENTIFIABLE_SINGLE_DIMENSION`,
  `POPULATION_BACKGROUND`.
- Bounds: `REID_MAX_RECORDS` 128 records, `REID_MAX_EVALUATED_CASES` 64 evaluated cases,
  `REID_MAX_QUASI_IDENTIFIERS` 8 quasi-identifiers per record. `REID_MAX_QUASI_IDENTIFIERS` is
  `#11`'s neighbour ceiling, so a record always fits the reviewed seam.

The shipped corpus has 39 records (33 evaluated, 6 unlabeled population background) across 16
synthetic sites, covers all eight dimensions
(`GEOGRAPHY`, `DATE`, `PROCESS`, `PROJECT`, `ORG_UNIT`, `ROLE`, `DEVICE_CLASS`, `CUSTOMER_TYPE`) and
plants 15 `REIDENTIFIABLE` and 18 `NOT_REIDENTIFIABLE` labels. Rarity is expressed only by sharing,
and **in this corpus** every handle of every record -- evaluated or background -- occurs in at least
one other record, so no case here can be identified by a single value and identification comes from
the **combination**. Three background records (`reid-pop-04`..`reid-pop-06`) exist precisely to carry
the `CUSTOMER_TYPE`, `ROLE` and `DEVICE_CLASS` values that would otherwise be singletons; each of
their own combinations is unique, which is legitimate for unlabeled population records. The sharing
property is asserted over the whole shipped corpus rather than over one case, and it is a property
**of that corpus**: a caller-supplied corpus is not required to satisfy it, is not re-validated for
it, and may legitimately contain a value that identifies its site on its own. `reid-case-01` is the
issue's negative case: a rare geography/date/process/project combination (plus an org unit) that is
the only one for its site.

## The local quasi-identifier model

`reidentificationCells(corpus)` groups records by their whole, order-independent combination and
reports, per record, the number of matching records and the number of matching **distinct sites**.

- A cell is keyed on **(dimension, handle) pairs**, not on bare handles. A handle is only a fact inside
  its dimension, so two records carrying one handle under different dimensions hold different facts;
  merging them would make the model under-claim and report a unique combination as a shared one.
- Uniqueness is `siteCount === 1`. A cell with two records of the *same* site is still
  re-identifying (`reid-case-17`/`reid-case-18`): what leaks is the site, and two records of one site
  protect nothing.
- A cell with two or more sites is not re-identifying, however rare it looks
  (`reid-case-31`/`reid-case-32` share one combination across exactly two sites).
- A single geography, process or date value shared by several sites is not re-identifying on its own
  (`reid-case-22`..`reid-case-30`).
- Cells are population-relative: adding records that share nothing with a case cannot change that
  case's verdict. That is asserted, not assumed.
- Cells are computed by a linear map pass over closed dimension and handle shapes, so the key is exact and the
  work is bounded by the record cap.
- The local model is deterministic evidence. It is not a judgment, it is not a policy input yet, and
  it can be wrong in the same way any k-anonymity-style heuristic is: it only knows the corpus it is
  given.

## The question set

`defineReidentificationQuestionSet()` issues a two-question set (`hylja.reid.shadow@1`) through
[#11's `defineShadowQuestionSet`](semantic-judge-shadow.md): a `choice` question with purpose
`REIDENTIFICATION_RISK` and a `score` question with purpose `UTILITY_NECESSITY`.

- **Only the issued set may be scored.** A trusted caller can mint a #11 set carrying the same `id`
  and `version` with different question text; `isIssuedReidentificationQuestionSet` brands the set
  this module issues and the runner refuses anything else, because reporting metadata that does not
  identify the questions asked is itself misleading evidence. Changing a question or a criterion is a
  module change with a new `REID_QUESTION_SET_VERSION`, not a runtime substitution. The per-row
  `requestDigest` binds the exact question text independently, so the two controls do not rely on
  each other.

- The `propose` mapping is required by the #11 contract for a Choice question, so the two labels map
  to semantic classes (`CUSTOMER_OR_PARTNER` for a combination that could single out one entity,
  `ENGINEERING_IDENTIFIER` for one common to many). Those are advisory claims inside a #11 record;
  this runner reads the answer's **label** and nothing else, and consumes no evidence entry.
- The question text describes placeholders (`cand-01`, `nbr-NN`) because that is all the judge can
  see. #11 replaces the candidate value and every neighbouring value with request-local ordinal
  placeholders, so **two records whose handles differ completely produce byte-identical requests**.
  The digest comparison in the test suite is the measurable form of that claim.
- Consequently, agreement between the shadow judge and the planted labels in this version says
  something about how a structural-only signal is treated, **not** about a judge's ability to detect
  re-identification. A hosted judge that could see a policy-authorized representation of the
  combination would be a different, separately reviewed design with its own destination policy,
  route binding and #19 byte check.

## Judging through #11

`runReidentificationShadow` drives `runShadowJudgment` per case and reuses its failure semantics
rather than inventing a second adapter:

| Situation | #11 record | Row |
| --- | --- | --- |
| answered with `reidentifiable` | `ANSWERED` / `PARTIAL` | judge `RISK` |
| answered with `not_reidentifiable` | `ANSWERED` / `PARTIAL` | judge `SAFE` |
| risk question not answered | `PARTIAL`, `MISSING_ANSWER` | judge `ABSTAIN` |
| malformed or oversized answer | `PARTIAL` or `REFUSED` with a closed code | judge `ABSTAIN` |
| deadline elapsed | `TIMEOUT` / `TIMED_OUT`, `late` observable | judge `ABSTAIN` |
| transport refused or forged judge | `REFUSED` | judge `ABSTAIN` |

A record is usable only when it came from this question set and judge, is `authority: 'NONE'`,
reports a `local-synthetic/*` served model and belongs to the run's tenant; anything else is an
abstention. The runner passes only `{ execution: 'IN_PROCESS', deadlineMs }` to #11, so there is no
path from this module to a network. A caller flag (`synthetic`, `trusted`, `safe`,
`destinationPolicy`, `authorization`, ...) is an unknown option key and is refused: a flag is not
an authorization primitive, and `execution: 'EXTERNAL'` is refused before any request exists.
`tenantRef` is a bounded opaque token (`REID_MAX_TENANT_REF_CHARS`, 128 characters, the lowercase
token shape #11 uses for configuration), so an email, a path or a URL cannot be planted in the report
or in the judge request. That bounds the shape only; the trusted integration must still mint a
privacy-safe value.

`settlement` is awaited as well as `record`, so a late answer is observed and discarded instead of
being merged into the row or left as an unhandled rejection.

## The report

`runReidentificationShadow(corpus, set, judge, options)` returns a frozen, versioned report with
three independent count columns, each over the same rows:

| Column | What it measures |
| --- | --- |
| `localModel` | the deterministic equivalence-cell verdict |
| `shadowJudge` | the #11 judgment: `trueFlag`, `falseFlag`, `miss`, `correctSafe`, `abstained` |
| `combined` | the fail-safe combination used as the shadow finding |

`miss` means a case labelled re-identifiable that a signal did not flag. For the judge column that
is exactly a **false-safe judgment**, and it is counted as a miss rather than as a pass.
`abstained` means no usable judgment; it is never a pass and never a safe verdict.

The combination is deliberately one-directional:

- local `RISK` → `RISK` (`LOCAL_UNIQUE_COMBINATION`);
- otherwise judge `RISK` → `RISK` (`JUDGE_RISK`);
- otherwise judge `ABSTAIN` → `RISK` (`JUDGE_ABSTENTION_ESCALATION`);
- otherwise `COMMON` (`NO_FLAG`), which requires the deterministic model **and** an affirmative safe
  judgment.

An abstention therefore escalates instead of relaxing. That is the fail-safe direction and it has a
cost, so the report states it: `escalatedByAbstention` counts flags produced only by escalation, and
those cases appear as `falseFlag` in the combined column rather than being quietly absorbed.

Each row carries the case id, family, planted label, dimension names and count, the local verdict
with its cell counts, the judge verdict with the #11 outcome, closed reason codes, request digest
and late flag, the combined verdict with its basis, and the advisory recommendations.

## Privacy shape

- No handle, quasi-identifier reference, site reference or corpus text reaches the judge request or
  the report; both are asserted over the whole corpus.
- The report carries closed codes, counts, dimension names and digests. There is no field named for a
  treatment, an authorization, a sensitivity, a trust level or a scope.
- The tenant is part of the minimized request, so digests from one tenant's run cannot be matched
  against another tenant's run. Per-record tenant congruence is checked inside the runner before a
  row is built; a record that is not tenant bound is an abstention.
- A judge whose identity cannot be read is reported with the fixed placeholders `unbound` and
  `NONE`, never with an exception message or a caller string.
- Corpus and report inputs are read as data: own enumerable data descriptors, closed key sets, no
  prototype chain, no `toJSON`, no accessor invocation, and a fixed `TypeError` for a throwing
  `Proxy`. A refused spec never runs caller code (asserted with invocation counters).

## Threat → test map (local synthetic evidence only)

| Threat | Case |
| --- | --- |
| contextual re-identification after a direct name is cloaked | the issue's negative case `reid-case-01`: unique rare geography/date/process/project combination, every handle shared elsewhere, local `RISK`, combined `RISK` |
| false-safe judgment read as a pass | a judge answering `not_reidentifiable` everywhere: `shadowJudge.miss` equals the number of re-identifiable cases, `combined.miss` is 0, and no recommendation is applied |
| outage or abstention reducing protection | refusal, timeout, missing answer, malformed answer, oversized response and forged judge each abstain, and the combination escalates; `escalatedByAbstention` names the over-flag cost |
| a caller flag as external-send authority | `synthetic`/`trusted`/`safe`/`destinationPolicy`/`authorization`/`EXTERNAL` options are refused before any request |
| raw neighbouring protected text in a judge request | content-independent request digests over a handle-permuted corpus; no handle in any request or report |
| lexical name-only matching as proof | the corpus and the report contain no name at all; an allowlist asserts every corpus string is an opaque token, id or closed code |
| a widened corpus spec smuggling data | accessor, `toJSON` on a record, a quasi-identifier and a corpus object, an inherited `toJSON`, throwing `Proxy`, function value, raw-looking handle, email-shaped handle, routable handle, invented label, unknown dimension, repeated dimension, over-bound list, duplicate id, widened record are each refused, with invocation counters proving no caller code ran |
| a single value identifying a case on its own | the sharing property is asserted over the WHOLE shipped corpus (every handle of every record occurs in at least one other record), and the `CUSTOMER_TYPE`, `ROLE` and `DEVICE_CLASS` singletons that used to violate it are gone |
| a cell merging two different facts | a dimension-swapped handle pair is asserted to stay two `RISK` cells, while a genuinely shared `(dimension, handle)` combination is asserted to stay one `COMMON` cell |
| question-set substitution under identical metadata | a caller-minted set with the same `id` and `version` but different text is refused; the brand predicate is asserted for the issued set, a spread copy and a substituted set |
| advice that cannot work | a dimension whose only value every record shares is excluded from the recommendations, and the rationale names state that the ordering is population cardinality rather than combination rarity |
| an unbounded or value-shaped tenant reference | email-, path-, uppercase- and scheme-shaped `tenantRef` values and an over-long token are each refused |
| a caller-authored corpus changing a verdict | a handle-permuted or widened corpus keeps every existing case's verdict |
| cross-tenant evidence reuse | tenant-bound digests, fixed placeholders for an unreadable judge identity |
| unbounded or generated input | 16 seeded generated corpora (both unique and shared cells), count identities, the record cap accepted at the limit and refused above it, and a generous bounded-work budget at the caps |

## Stated limits

- This is a **development** measurement on a synthetic structural corpus. It is not a held-out set,
  it is not frozen by a protocol, no planted oracle was read for it, no #39 score is computed from
  it, and it must never be described as a benchmark or as evidence about real populations.
- The corpus has no real text, so the module cannot demonstrate detection of re-identification in
  natural text, from a real vault, or across a real destination. It demonstrates the *measurement
  seam*: candidate model, bounded question, honest counting, fail-safe combination and advisory-only
  recommendations.
- The shadow judge cannot see the combination in this version, because #11 minimizes every value.
  Judge agreement here is therefore not evidence of semantic re-identification skill, and the
  always-risk and always-safe configurations in the tests are scripted doubles, not model behavior.
- The uniqueness model is a k-anonymity-style heuristic over one synthetic population. It has no
  adversary model, no linkage attack, no differencing/auxiliary-knowledge analysis and no defence
  against a population that changes between runs. A cell of one site in a 39-record corpus says
  nothing about a real site's uniqueness in a real population.
- Cells are keyed on `(dimension, handle)` pairs, so a handle is treated as a fact **only inside its
  dimension**. A caller that reuses one handle across two dimensions gets two independent facts, not
  one merged cell. That direction can over-flag (it never merges two different facts into one), but it
  does mean the model does not notice a caller who deliberately assigns the same handle to what is
  really one underlying value across dimensions; a dimension-blind caller therefore gets a stricter
  (more flagging) reading, not a laxer one.
- The sharing property described above holds for the shipped corpus only. A caller-supplied corpus may
  contain a value that identifies its site by itself, and the module will then measure that value's
  combination cell without complaining.
- The recommendation ordering is by population cardinality (fewest distinct values in the population
  first), and a dimension whose every record already shares one value is excluded because generalizing
  a universal value cannot widen a cell. There is no validated generalization lattice, no parent-group
  mapping, no utility estimate and no predicted resulting cell size, so a recommendation cannot be
  treated as "this generalization would be sufficient".
- Nothing is generalized, masked, generalized-in-place or removed, and no transformation code exists
  here. Over-cloaking and utility are unmeasured.
- Cross-record concatenation of two individually harmless combinations is not analyzed, and a case's
  verdict can only be as good as the population it is measured against.
- Timing, cost, latency and model behavior are unmeasured; the local judge is a deterministic script.
  The one wall-clock assertion in the suite is a bounded-work sanity check with a deliberately
  generous budget, not a service latency claim.
- References (`siteRef`, `ref`, `tenantRef`) are shape-bounded here but are trusted to be
  privacy-safe; the integration must mint them. This module neither authenticates nor sanitizes them,
  and the corpus's own handles are presentational, as described above.
- Question instruction and criteria text is trusted configuration fixed in this module. The runner
  accepts only the set it issues, so a runtime substitution is refused, but the text is still not
  machine-checked for protected content -- nothing in this seam writes text into it.
- The runner is a development tool, not an adapter. It refuses configuration loudly, it assumes a
  trusted in-process caller, and it is not wired into any runtime path.
