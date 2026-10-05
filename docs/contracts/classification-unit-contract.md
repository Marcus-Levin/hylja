# Configured-source and classification-unit composition contract

Status: draft contract for the #37/#10 integration slice. This documents a **pure, NON-ENFORCING** seam, **not** a deployment approval, an adapter, an identity authenticator, a transformation, an egress control or a guarantee about released bytes. Implementation status belongs only in [capabilities.md](../capabilities.md).

## Inputs and authority

`composeClassificationUnits(request)` consumes values the trusted integration supplies separately:

- `detection`: one #6/#7 composition result (`detectNormalizedCandidates`), read once through own enumerable data descriptors. Getters, `Proxy` traps, symbol keys, non-plain prototypes, holes, **unknown keys** and over-bound arrays are refused, not interpreted, so nothing a caller invents inside a detection record can travel into a serialized unit. A malformed result is a whole `FAILURE` (`INVALID_DETECTION`); caller text is never echoed.
- `inputRef`: a privacy-safe opaque reference for the request. Unit references and configured contact-sensitivity evidence are derived from its digest, so **freshness per request is a trusted-caller obligation**; this module cannot enforce it and does not claim cross-request unlinkability beyond that.
- `scope`: the tenant and project the request runs under.
- `context`: the accepted classification context (`interactionRef`, `sourceRef`, `trust`). It is copied, never read through a caller object, and never derived from payload text.
- `contactSensitivity`: an optional trusted, tenant/project-bound opaque handle from `createContactSensitivity`.
- `registry`: an optional accepted subtype registry from `extendSubtypeRegistry`; anything else is refused.

The module **consumes trusted integration inputs; it authenticates nothing**. A handle minted in the same process is unforgeable only in the sense that no other process can mint one. Source trust remains the integration's observation, not a payload or model assertion.

Detection reason codes and opaque-location reasons are carried through only when they are uppercase code tokens; anything else becomes `DETECTION_UNREADABLE_REASON` or `UNREADABLE_OPAQUE_REASON`, so a caller-planted sentence is never copied into a result. A `COMPLETE` detection that nevertheless carries opaque coverage is downgraded to `PARTIAL` with `UNINSPECTED_COVERAGE`, because the seam never reports an uninspected range without a reason.

## Grouping

Grouping is deterministic, linear in practice, and never searches over subsets of occurrences:

1. a **scan line** is one text unit one detector pass read — a view representation (`viewId`, `RAW`/`FOLDED`, form, encoding path) or one #7 parsed field (#7 format, field span, request-bound key-path digest). Candidates from different lines never merge;
2. candidates are placed by their **occurrence span** — the match offset inside the decoded field value for a #7 field, the in-view span otherwise — because a decoded value reports its whole field span in the view and grouping by view span alone would collapse every candidate in one value into one identity;
3. within a line a candidate joins the most recent group it *relates to*: the same occurrence span, or a strictly crossing span (one starts inside the other and ends outside it). Disjoint, adjacent and nested spans stay separate, so repeated or disjoint occurrences inside one encoded envelope remain distinct units with distinct references, a configured name inside an email local part keeps its own unit, and one over-covering detector match cannot swallow the entities inside it;
4. a **whole-value** candidate (a trusted #7/#10 key-path hint, `basis: FIELD_HINT`) never merges in either direction;
5. merging stops at the composer's per-channel evidence limit (`MAX_UNIT_EVIDENCE`, 256); the next candidate starts a new unit, so no candidate is dropped by grouping.

Every candidate ends up in exactly one unit, so no detector's evidence is discarded. A group keeps all contributing detector records verbatim on the unit (`detectorEvidence`), and the unit's location is either one contributor's location unchanged or a covering/envelope union of the contributors' — never an invented exact offset. Provenance families (string offsets, UTF-8 text offsets, encoded envelopes) are never combined into one claim, and a unit that cannot state its location honestly reports `UNIT_LOCATION_UNRESOLVED`, keeps no `original`, and is recorded as opaque.

Each unit carries its own opaque `ref` derived from the caller's `inputRef` digest and the unit index, so two same-value occurrences can never share a reference (the analogue of the reviewed #4 A/B defect), plus its view, representation, form, encoding path and, for a #7 field, the format, request-bound path digest, hint source/depth, `highRisk` flag, field span, match span and verbatim flag. Key names are payload content and are never emitted.

## Upstream seam: one candidate per occurrence

Grouping can only keep what the #6/#7 seam reports, so the seam's de-duplication identity is part of this contract. Identity is **per occurrence, never per envelope**: view id, representation, source, subtype, rule, in-view span, original location, and — for a #7 field — its format, field span, request-bound key-path digest **and the in-value occurrence offsets**. The in-value offsets are not redundant: a value #7 decoded (escaped, entity-decoded) reports its *whole* field span in the view for every match inside it, so without them two occurrences of the same text in one decoded value collapsed into one candidate and the second vanished with no reason and no opaque location. A repeat of the very same occurrence is still suppressed: identical view span *and* identical in-value span is the same occurrence read twice. This applies to every source the seam runs (#8, #9, #37 and #10), not only to configured terms; it corrects a pre-existing collapse of repeated contacts, hosts and credentials inside decoded field values that was present at base.

A #6 **decoded view** keeps its own accepted representation instead: identical disjoint copies of one decoded run collapse into a single view whose `ENCODED_RUNS` envelope names every outer occurrence, and the in-view span of a match inside that view is its position in the decoded text. Two occurrences of one protected value *inside* that view text are two candidates, two units and two references.

## One whole-scan-unit match beside coverage (#10)

#10 extends a template match forward over the rest of the identifier (`expand`) so a value is never covered in part. That widened span is **coverage**, not corroboration: `view.span` and `original` keep reporting it exactly as before. Beside it, a `CONFIGURED` candidate carries `wholeUnitMatch` — one boolean, not offsets.

`wholeUnitMatch` answers exactly one question: did #10's own matcher match the **whole scanned unit** it ran over? For `PATTERN` the scanned unit is the extended identifier and the flag is true only when the template match reached that unit's end, so a template plus an unconfigured tail that coverage happens to reach is false. `DICTIONARY`, `FIELD_HINT` and `CONTEXT` never extend: their match *is* their scanned unit, so the flag is true there. The member is absent for every source other than `CONFIGURED`.

It is a fact about the unit #10 scanned and **not** a coordinate in the same domain as `view.span` or `original`. Those are derived after normalization: a `FIELD_HINT` on a parsed JSON value matches the decoded value it was handed while its coverage sits at that field's offset in the view, a folded match is mapped back to a covering span, and a decoded view reports an envelope. Only the boolean survives all of that unchanged, and only a consumer that already holds the coverage and its own original location can combine the two. Nothing here states that a nested, folded or decoded match sits at the same offsets as its coverage.

The flag comes from the registry-compiled configuration inside #10, never from caller text and never from a host assertion, so a consumer can require **whole-value corroboration** instead of whole-value coverage. It changes no span, no identity and no grouping rule in this contract.

Composition reads it through the same closed-descriptor boundary as every other candidate member: it must be a boolean, and it may appear only on a `CONFIGURED` candidate, since no other source has a configured matcher behind it. A non-boolean value, the same fact on a foreign source, or the numeric offset members an earlier draft of this seam accepted is a malformed detection record and is refused with `INVALID_DETECTION`, exactly like any other unknown member. The flag is then deliberately **not** kept on the unit: grouping places by the occurrence span, so a host that supplied its own fact changes nothing here.

## Configured contact sensitivity

`createContactSensitivity(scope, entries)` binds one configured `Sensitivity` per PERSON subtype (`NAME`, `EMAIL`, `PHONE`) to exactly one tenant and project behind an opaque handle. It is deliberately minimal: not a per-person table, no value, no default, no inheritance. A malformed, unknown, duplicated or out-of-scope entry is refused at construction with a fixed message that contains no configured text.

The accepted composer refuses to resolve a unit while any contributing claim carries no sensitivity, and #37 emits none by design. So where a trusted handle configures a subtype, the composed channel receives a record from producer `hylja.contact-sensitivity` carrying **the candidate's own** semantic type and subtype plus the configured sensitivity. It completes a claim; it cannot assert a class or subtype the detector did not find, and the detector's own record is retained on the unit.

- **Absent** handle: no completion, units stay `UNRESOLVED` with `MISSING_SENSITIVITY`. Absence is not an error and adds no reason.
- **Foreign** (another tenant or project), **forged** or **malformed** handle: no completion, `PARTIAL` with `CONTACT_SENSITIVITY_SCOPE_MISMATCH` or `CONTACT_SENSITIVITY_INVALID_CONFIG`, and the affected units stay `UNRESOLVED`.
- A weaker configured contact sensitivity never overwrites a stronger configured detector claim: the composer keeps the highest claimed sensitivity and reports `CONFLICTING_SENSITIVITY`, leaving the unit `UNRESOLVED`.

Sensitivity is policy metadata. A payload never asserts one, no semantic model is involved, and nothing here is authorization.

## Output and limits

`COMPLETE` means every supplied candidate was composed into a unit. It is never "clean", never a permission and never a statement about bytes. `PARTIAL` carries the detection's own reasons plus the composition's (`CONTACT_SENSITIVITY_*`, `UNIT_LIMIT`, `UNIT_LOCATION_UNRESOLVED`, `UNINSPECTED_TRUNCATED`). `FAILURE` carries one fixed code and no units.

- Caps are conservative and never success-shaped: `MAX_UNITS` (1024) units per request, `MAX_UNIT_EVIDENCE` (256) evidence per unit, bounded candidate, reason, opaque-location, encoded-run and encoding-path counts. A unit beyond the cap is recorded as opaque with `UNIT_LIMIT`, not dropped.
- Unread and skipped ranges are carried through unchanged in `uninspected`, including everything #6/#7 did not inspect.
- Results never contain raw text, configured terms, key names, source paths or caller exception messages: spans, digests, producer ids, closed rule names and fixed reason codes only.
- **Explicit gate (follow-on, not this slice):** the seam runs #10 only when the integration supplies a configuration handle, so #10's tenant-independent generic engineering-key rule (`part_number: …`) also stays inactive for a request with no handle. Enabling it unconditionally would add candidates to every request that configures nothing — a broader behavioural change to the seam than this slice makes — so it is left as a declared gate rather than changed silently here.
- Declared residuals: this slice does **not** transform, cloak, authorize, verify egress, persist, bind an interaction, pin a classification digest for a reviewer, or wire #13/#19. Over-covering detector matches stay separate units rather than merged, so a downstream policy must decide every unit, not just the longest one. A `RESOLVED` unit is an input to deterministic policy, never a decision.

## Consumer checklist (obligations this pure seam cannot enforce)

1. pass a **fresh** `inputRef` per request, so unit references and completion ids cannot be correlated across messages;
2. pass the `detection`, the `scope` and the `contactSensitivity` handle from **one** request: this module cannot verify that a supplied detection belongs to the supplied scope, so cross-pairing a tenant-A detection with a tenant-B scope would mislabel it;
3. read `unit.classification` for decisions, not `unit.detectorEvidence[].claim`, which is the detector's raw record and is retained for provenance only;
4. decide **every** unit, including those a whole-value field hint or an over-covering detector match deliberately left separate;
5. treat `PARTIAL`, `FAILURE` and any non-empty `uninspected` as opaque input to deterministic policy, never as clean content;
6. when a decision needs whole-value corroboration rather than whole-value coverage, require the configured candidate's own `wholeUnitMatch` to be `true`, beside the `view.span` and `original` location you already hold — and read it as what the matcher saw in its own scanned unit, never as an offset that must equal the coverage.
