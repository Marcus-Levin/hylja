# Hylja Gym: human annotation and active-learning design (proposed)

Status: **proposed design, not accepted, not implemented, non-normative.** Tracked by
[#67](https://github.com/Marcus-Levin/hylja/issues/67), with [#65](https://github.com/Marcus-Levin/hylja/issues/65),
[#66](https://github.com/Marcus-Levin/hylja/issues/66), [#39](https://github.com/Marcus-Levin/hylja/issues/39),
[#27](https://github.com/Marcus-Levin/hylja/issues/27) and
[decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) as inputs. Nothing here
changes classification v1, [policy](../flow-control.md), any adapter or any accepted invariant; nothing here accepts
decision 010, appoints a reviewer or a custodian, freezes a #39 protocol, or claims a promotion. Implementation
status lives only in [capabilities.md](../capabilities.md). This document proposes a *design and a data format*; it is
not a live upload service, an annotation UI build, a training system or a production-learning loop. It is filed under
`specs/` for discoverability next to the other proposed designs; it is a proposed design, not an implementation
slice.

## 1. What the Gym is, and what it is not

The Gym is a supervised, human-in-the-loop path that turns **approved or synthetic material** into versioned,
provenance-bearing evidence about Hylja's semantic vocabulary, its per-tenant dictionaries, its calibration data and
its task-fidelity examples. Its output is an **artifact**, and artifacts only travel along the existing
`annotation -> dataset -> evaluation -> review -> change` path in [evaluation.md](../evaluation.md).

The Gym is explicitly **not**:

- an authority path. No annotation, adjudication, aggregate or priority score is read by the Policy Engine, the
  Authorization Broker, the vault, a transformer or the Egress Sentinel. Human feedback never changes production
  authority ([security invariant 12](../security-model.md#security-invariants), accepted
  [decision 003](../decisions/003-semantic-judgment-does-not-own-effects.md) and
  [005](../decisions/005-evaluation-precedes-authority.md));
- a prerequisite for the first enforcement proof. Slice 1 ([spec](slice-1-text-cloaking-proof.md)) and the
  [#38](https://github.com/Marcus-Levin/hylja/issues/38) campaign proceed without it; #67 is a **non-blocking
  upstream data source** for [#27](https://github.com/Marcus-Levin/hylja/issues/27), exactly as that issue states;
- an online learner. Nothing is fitted at annotation time, no bandit, no reward model, no RLHF, no hosted
  training call. Every "learning" artifact is a file a human reviews;
- a corpus of production traffic. The MVP can run entirely on synthetic generated material, so it needs no vault,
  broker or real importer to produce its first useful artifact;
- a multimodal, OCR or binary system. Text, log lines and bounded parsed structured fields only, matching the
  #5 seam's declared text coverage.

## 2. Roles are separated, and none of them is appointed here

The Gym has roles, not people. Who fills them is an open gate (§15), and this document appoints nobody.

| Role | May do | May **not** do |
| --- | --- | --- |
| Annotator (tenant) | propose candidates, create manual missing candidates, append semantic/privacy/sensitivity labels, record a task preference, abstain | adjudicate, edit or delete a label, change a policy, see another tenant's artifact, see a held-out case |
| Adjudicator (reviewer) | append an adjudication entry (`ADJUDICATED` or `UNRESOLVED`) to a disputed occurrence | rewrite history, promote scope, authorize release |
| Task owner (independent) | author a task-fidelity contract for one task and its destination | set a treatment, or set a semantic label |
| Policy reviewer | review expected per-destination treatments for evaluation, separately from annotators | decide a semantic ground truth, or consume a Gym preference as a decision |
| Evaluator | register a development artifact through the #5 seam, run the queue, record the artifact identity | promote anything, or certify held-out material |
| Tenant administrator | approve import sources, retention class and deletion requests | adjudicate labels or approve global promotion alone |

The same identity may not hold two of the first five roles for the same artifact. That is a design rule for the
reviewer to accept or reject; it is not enforced anywhere in code today.

## 3. The critical separation: three label spaces, three owners

A user answering "what should Hylja do with this?" must never teach the classifier "what is this?". The three
spaces below are **logically and structurally separate** in the export format: a record can only carry the keys
its own space allows, and every other key is rejected. That is a mechanical property of the schema, not a UI
convention.

| Space | Question | Vocabulary | Owner | Home |
| --- | --- | --- | --- | --- |
| `groundTruth` | What *is* this occurrence? | semantic identity (`semanticType`, `domain`, `subtype` from the #65 vocabulary once reviewed), privacy attributes (tri-state), sensitivity, confidence | annotator, adjudicated by a reviewer | classification evidence |
| `taskFidelity` | What must survive for one task? | the fidelity predicates of decision 010 (`EXACT_VALUE`, `EXISTENCE`, `KIND`, `VALUE_SHAPE`, `SYNTAX`, `RELATIONSHIP`, `CONSISTENCY`, `GENERALIZED`, `NOT_REQUIRED`) | independent task owner | a per-task fidelity contract keyed by occurrence/entity ref |
| `taskPreference` | What would *this* person prefer for *this* destination and task? | existing treatment names (`KEEP`…`REQUIRE_REVIEW`) as **preference labels only**, plus exact-value necessity | annotator or task owner, reviewed by a policy reviewer | an organization-scoped preference dataset |

Worked example, taken from the committed example artifact: a port occurrence carries
`semantic: NETWORK_IDENTIFIER / IT / PORT`, `sensitivity: INTERNAL` **and**
`taskPreference.preferredRepresentation: KEEP`. The preference does not touch the semantic label, the sensitivity
or any other occurrence of `443`. Symmetrically, `SYNTHETIC` chosen for a hostname never makes the hostname a
lower-sensitivity value. Three consequences follow:

1. **A preference is not a treatment.** Only the Policy Engine selects treatments
   ([decision 003](../decisions/003-semantic-judgment-does-not-own-effects.md),
   [007](../decisions/007-fail-closed-for-protected-egress.md)). A Gym preference has no destination
   authority: `destinationRef` is an opaque label, and the #39 fixture rule that unauthenticated profile text is
   data, not `CONTROL` provenance, applies unchanged.
2. **A preference cannot lower sensitivity.** No code path reads `taskPreference` into a sensitivity resolution.
3. **A human sensitivity label is evidence, not a floor decision.** Under the proposed rules of decision 010 a
   human claim would join the sensitivity-claim list as a third evidence origin next to `DETERMINISTIC` and
   `SEMANTIC`; it may raise concern above a deterministic floor and may never lower one, and it can never displace
   deterministic credential evidence fixing `SECRET`
   ([decision 009](../decisions/009-secrets-are-not-synthetic-identities.md)). That mapping is **contingent on
   decision 010 being accepted plus an explicit vocabulary decision** about the new origin, not on acceptance alone;
   until then Gym sensitivity labels are advisory dataset content consumed only by evaluation, never by a runtime
   resolver.

## 4. Occurrence model: source-field identity, spans, repeats, overlaps, relationships

### 4.1 Field identity

An occurrence is bound to a **field**, not to a file path and not to a serialized document offset:

- `importRef` is an opaque per-import handle minted by the tool, never a filesystem path, URL or tenant name;
- `sourcePath` is a **bounded, escape-free JSON Pointer** ([RFC 6901](https://www.rfc-editor.org/rfc/rfc6901)
  syntax with a documented v0 restriction: the `~0`/`~1` escapes are **not** supported, and every segment is 1-64
  characters of `[A-Za-z0-9_.-]`, with no `.` or `..` segment and at most 16 segments). The pointer addresses the
  **decoded** import document, so a native path, a URL, a serialized-file offset, or a segment carrying spaces,
  quotes or markup is rejected. A Gym artifact therefore cannot become a filesystem or exfiltration handle, and it
  cannot carry free text in a path;
- `unitKind` distinguishes a whole text unit (a log line) from a parsed structured field, because the same text has
  different meaning in a JSON value and in a line of a log;
- `normalization` names the **view the spans address**. A second view of the same text (for example an NFC view of
  the same field) is a second `field` record with its own `codePointLength`/`byteLength` and its own spans, never the
  same record reinterpreted: the format rejects a repeated `(importRef, sourcePath, normalization)` triple with
  `DUPLICATE_FIELD_VIEW`, so a consumer can never apply normalization to spans it was not measured against;
- the field records its decoded `codePointLength` and `byteLength` so a consumer can check its own decoding
  instead of trusting an offset.

### 4.2 Code-point spans versus UTF-8 bytes

This is the single most error-prone join in the design, so it is explicit:

- **A source-side identity is always a zero-based, half-open Unicode code-point span** `[start, end)` into the
  *decoded* field, before normalization. A UTF-8 byte offset is an encoding- and serializer-dependent coordinate:
  the same code-point range has different byte offsets in UTF-8, UTF-16 and a re-serialized canonical field, so a
  byte offset cannot identify a source value. The v0 format therefore **rejects** `UTF8_BYTE` and
  `UTF16_CODE_UNIT` as a source span unit.
- The candidate-facing side of Hylja speaks different units today: #37 reports UTF-16 code-unit *and* code-point
  spans ([`src/contact-candidates.ts`](../../src/contact-candidates.ts)), while the #5 seam and the D05 projector
  work in UTF-8 byte spans of the candidate-visible field bytes
  ([`evaluations/d05-canonical-json-spans.mjs`](../../evaluations/d05-canonical-json-spans.mjs)). A Gym span is
  therefore joined through a **declared** field-level `byteMapping`:
  - `IDENTICAL` - the decoded field is ASCII, code-point offsets equal UTF-8 byte offsets, and the format
    **forbids** a derived byte span (a redundant one usually means the field is not ASCII after all, which would
    silently break every downstream join);
  - `DERIVED` - each span must carry a `derivedByteSpan` in `UTF8_BYTE` that was verified against the decoded
    bytes. The format checks it is inside the field's byte length and that it does not start before the code-point
    offset, since every code point occupies at least one byte;
  - `UNVERIFIED` - no byte coordinate is asserted. Byte-coordinate consumers must mark the field `untested`.
    They must **not** guess a mapping, and an unverifiable mapping is never a silent nearest-match.
- Normalization is declared (`IDENTITY`, `NFC`, `NFKC`; see
  [UAX #15](https://www.unicode.org/reports/tr15/)), never assumed. Unicode normalization can change length and
  composition, so a normalized view needs its own verified mapping rather than the same offsets reused.
- Code points are used rather than grapheme clusters because they are the minimal unambiguous source identity for
  a *value boundary*; where a human must see a whole user-perceived character,
  [UAX #29](https://www.unicode.org/reports/tr29/) grapheme segmentation is a presentation concern, not a stored
  offset. [RFC 3629](https://www.rfc-editor.org/rfc/rfc3629) is the UTF-8 definition the byte-length bound relies on.
- Unpaired surrogates, lone `\uFFFE`/`\uFFFF`, truncated multi-byte sequences and overlong encodings make the
  decoded field unrepresentable, not partially representable: the field is rejected and its occurrences are
  `untested`.

### 4.3 Repeats, overlaps and relationships

- **Repeats are separate occurrences.** Two identical values in two fields, or twice in one field, are two
  occurrences. Deduplicating them would silently delete evidence about consistency
  (`CONSISTENCY`/`RELATIONSHIP` fidelity) and about multi-tenant mismatch. An occurrence is therefore identified
  by `(fieldRef, codePointStart, codePointEnd)` plus its opaque ref, and an artifact may not contain two
  occurrences with the same triple.
- **Overlaps are allowed and explicit.** A compound value (`100284/A rev C`) can overlap a shorter one
  (`100284/A`). Overlap is not resolved by the schema; it is resolved by a documented, predeclared attribution
  rule at scoring time ([evaluation.md](../evaluation.md#core-metrics)), because "which candidate gets the credit"
  is a scoring decision, not an annotation fact. A `MANUAL` occurrence created to express a different span
  granularity says so through `missReason: COMPOUND_OR_COMPOSITE_SPAN`.
- **Entities and relationships are human claims, separately reviewable.** An `entityRef` groups occurrences that
  are believed to be the same thing; `relationships` assert `SAME_AS`, `ALIAS_OF`, `REFERENCES`, `PART_OF` or
  `DERIVED_FROM` between two occurrences, each with its own state (`SETTLED`, `OPEN_DISAGREEMENT`, `UNRESOLVED`).
  A relationship is never inferred from string equality, and an unlinked repeat stays two independent
  occurrences. Same-entity claims are the seed of consistency evidence, never a mapping: Hylja resolves no value
  from a Gym entity ([no bulk mapping lookup](../vault.md)).

## 5. Proposals and manual missing candidates

| Origin | Meaning | Required record |
| --- | --- | --- |
| `PROPOSED` | a candidate source (detector, parser field, configured tenant dictionary) raised it | at least one `proposalProducers` entry, declared in the artifact provenance; no `missReason` |
| `MANUAL` | a human says the proposer missed something | no producer, plus one `missReason`: `DETECTOR_MISS_CONFIRMED`, `STRUCTURED_FIELD_MISSED`, `COMPOUND_OR_COMPOSITE_SPAN`, `CONTEXT_REFERENCE_MISSED` |

A `MANUAL` occurrence is the only route to a *candidate miss* claim, and it is the highest-value input in the whole
loop: it is the seed of a sanitized regression case in the #5/#39 dev corpus and, eventually, of a detector
change through the normal champion/challenger path. It still changes nothing by itself. A user's dictionary answer
is a fixed enum (`MATCHED` / `NO_MATCH` / `UNKNOWN` / `NOT_APPLICABLE`) and never a dictionary **term**: the tenant's
terms live in the separate, tenant-scoped dictionary artifact (§9), and the export format rejects any other value,
so a term cannot be smuggled into an annotation, an issue body or a log through this field.

The field-level `proposalCoverage` (`COMPLETE` / `PARTIAL` / `FAILURE`) travels with the field for the same reason:
"the proposer found nothing else" is only meaningful for `COMPLETE`, and even then only for the named producers.
`PARTIAL` means absence proves nothing, and the Gym must not present an empty `PARTIAL` field as clean. A
user-supplied *negative* answer is also explicit: a proposed occurrence judged to be noise is not deleted, it is
contradicted by an appended label (a different semantic identity, or an abstention with a stated reason) and can then
be adjudicated and reused as a hard negative. There is deliberately no `NOT_SENSITIVE` label value: "not sensitive"
is a sensitivity judgement about a context, not a kind of thing, and a negative answer that only says "noise" cannot be
scored against a planted expectation.

## 6. Append-only labels: disagreement, UNKNOWN, abstention

- **No edit, no delete.** A label is an entry in `labelHistory` with a strictly increasing `version`, a
  `decidedByRoleRef`, a timestamp and one `groundTruth` record, plus an optional `taskPreference`. A correction is
  a new append. The tool must not offer in-place editing, and an artifact version is never rewritten.
- **`UNKNOWN` and `ABSTAINED` are answers, not missing fields.** `UNKNOWN` means the annotator looked and could
  not determine the answer (`INSUFFICIENT_CONTEXT`, `AMBIGUOUS_SUBTYPE`, `NO_ACCESS_TO_SOURCE_SYSTEM`,
  `CONFLICTING_EVIDENCE`). `ABSTAINED` means the annotator declined (`NOT_QUALIFIED_FOR_DOMAIN`,
  `OUT_OF_OWNERSHIP`, `TIME_BUDGET`, `POLICY_QUESTION_ESCALATED`). A payload that claims `UNKNOWN` while also
  carrying a sensitivity is rejected. `UNKNOWN` is never read as "not sensitive".
- **The effective label is the newest entry**, and agreement is **order-independent**: it means *every* recorded
  assertion in the history carries the identical payload, so an older dissent can never be outvoted by a later
  repeat. An intervening `UNKNOWN` changes nothing:
  - a final entry carrying `adjudication: ADJUDICATED` -> `ADJUDICATED`; with `UNRESOLVED` -> `UNRESOLVED`;
  - newest is `UNKNOWN`/`ABSTAINED` and some earlier entry asserted -> `OPEN_DISAGREEMENT` (a qualification, not a
    deletion); newest is `UNKNOWN`/`ABSTAINED` and nothing asserted yet -> `UNDECIDED`;
  - newest asserts a value and only one assertion exists -> `SOLE_ENTRY` (recorded, uncorroborated). This is also
    the state reached by answering an earlier `UNKNOWN` or abstention: a resolution, not a conflict;
  - otherwise the newest assertion is compared with *all* earlier assertions: identical payloads everywhere are
    `AGREED`, and any difference - including a different confidence band - is `OPEN_DISAGREEMENT`.
  - `[A,B,A]`, `[B,A,A]`, `[A,A,B]`, `[A,B,B]` and a 2-to-1 split are therefore all contested, and only an explicit
    adjudication settles any of them. Nothing is lost either way: the history is immutable, so an earlier dissent
    stays visible after adjudication.
- **No majority vote, ever.** Adjudication is an explicit act by a reviewer role, recorded with a resolution. A
  repeat of the same answer by the same or another annotator is not a resolution, and neither is a chronological
  win.
- **Rationales are fixed codes.** v0 has no free-text rationale field in any space, and the two version-shaped
  provenance fields are bounded `name/version` identifiers rather than prose. A free-text field is the easiest way
  for a protected value to enter an artifact, an issue body or a chat message, so longer rationales belong in the
  restricted review record, referenced by an opaque ref. This is a deliberate usability cost.

## 7. Scope, provenance and tenant isolation

- Every artifact carries one `scope`: `TENANT` with an opaque `tenantRef` and `projectRef`, or `GLOBAL` for a
  synthetic-derived artifact. A tenant artifact is never relabelled global in place; promotion produces a **new**
  artifact (§9) with its own refs, provenance and reviewer.
- Scope labels inside an artifact are **self-declared data**, exactly like #39 fixture metadata. The format can
  check internal consistency (`TENANT` requires both refs; a `GLOBAL` artifact may not carry tenant refs; a
  `GLOBAL` artifact may only contain synthetic-generated imports; retention class must match the scope level), but
  it authenticates nothing. Actual tenant isolation is the broker/storage boundary's job, and the MVP session has
  no persisting importer that could violate it, because the MVP can run on synthetic material only.
- `provenance` records `createdAt`, `questionnaireVersion`, `vocabularyVersion` (the #65 vocabulary a label was
  authored against), `informationModelVersion`, `toolchainVersion`, `intelligenceBundleRef` and the declared
  `proposalProducers`. Every per-occurrence and per-field producer must be declared there, so a later annotator
  cannot add a producer the artifact header does not record.
- Vocabulary version binding is a hard rule: `vocabularyVersion` and `informationModelVersion` are part of the
  artifact identity. A vocabulary change (for example if #65 review renames a subtype) means a **new artifact
  version**; labels are not re-interpreted under a vocabulary they were not written for.
- Role refs (`role-annotator-1`) are opaque and scoped to one artifact. The Gym does not need, store or derive a
  person's identity, and a rejected artifact or an error never echoes a ref, a span or a value.

## 8. Prioritization: a small deterministic proposal

Active learning here means **ordering a fixed set of occurrences for human attention** by how much a review is
expected to change what we know. It does not mean sampling, weighting, fitting or hiding.

The proposed score is an integer sum of fixed weights over evidence about the *label*, computed from one artifact
alone, with a stable tie-break (score, then source position, then field ref, then occurrence ref):

| Factor | Weight | Why it is high value |
| --- | --- | --- |
| `OPEN_DISAGREEMENT` | 40 | humans actively disagree; a second opinion resolves it |
| `UNDECIDED` / permanently `UNRESOLVED` | 25 | the current state is unusable for evaluation |
| `LOW` / `MEDIUM` confidence | 20 / 8 | self-reported uncertainty, strongest where the annotator said so |
| `MANUAL` candidate miss | 15 | a confirmed detector miss with a stated reason |
| field coverage `PARTIAL` | 15 | absence proves nothing, so sampling there is informative |
| dictionary `NO_MATCH` / `UNKNOWN` | 10 / 5 | most engineering identifiers need tenant evidence |
| first sighting of the subtype in this artifact | 10 | new vocabulary, checked by taxonomy review |
| preference recorded with no fidelity contract | 10 | the exact "utility claim without a task need" case |
| no entity link and no relationship | 5 | consistency evidence is missing |

This is deliberately small and inspectable, and it is a **review order, not a probability**: it is not calibrated,
not comparable across scopes or versions, and not usable as a confidence in any model. The MVP deliberately does
**not** implement committee disagreement, expected-model-change, margin sampling or a bandit
([Settles 2009](https://pages.cs.wisc.edu/~settles/active-learning-literature-survey.pdf) surveys the space; the
smallest useful strategy here is a deterministic queue).

Three rules keep prioritization from quietly weakening protection:

1. **Ordering never changes a label, a sensitivity value, a treatment or a policy outcome.** The score is not an
   input to any resolver, and a low score is not a statement about how sensitive a value is: every factor
   describes evidence *about* a label, never the label's value.
2. **Ordering never removes anything.** The queue contains every occurrence in the artifact, and a bounded review
   budget may only choose where to start, never what exists. Any per-class/per-state selection must report
   coverage beside it, and a class with zero reviewed occurrences is `untested`, never `pass`
   ([evaluation.md](../evaluation.md)).
3. **A queued item is not a display licence.** A `SECRET`-labeled or credential-shaped occurrence is reviewed from
   shape, field and context only; the artifact holds no value, so ordering cannot disclose anything. A semantic
   placeholder arriving in imported text is untrusted content and is never read as Hylja-issued
   ([decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md)).

## 9. Data products, scopes, and what may be promoted

Each product is a **separately versioned artifact** with its own `artifactKind`, scope, provenance and reviewer.
They are not columns of one table and are not merged at read time.

| `artifactKind` | Content | Default scope | Promotion |
| --- | --- | --- | --- |
| `ANNOTATION_EXPORT` | occurrences plus their label histories | tenant/project | only as a promoted, value-free aggregate (§9.2) |
| `TENANT_DICTIONARY_PROPOSAL` | proposed terms and templates for the tenant's own vocabulary | tenant/project | never promoted; tenant vocabulary is the tenant's |
| `CALIBRATION_SET_PROPOSAL` | labelled examples for confidence/calibration review | tenant, or global only from synthetic data | global promotion requires the promotion review below |
| `TASK_PREFERENCE_PROPOSAL` | preference labels per task and destination | organization | never consumed by a policy engine; usable as a reviewed input to a #39 treatment proposal |
| `HARD_NEGATIVE_SET_PROPOSAL` | confirmed lookalikes and noise values | tenant, or global only from synthetic data | same as calibration |
| `TAXONOMY_EVIDENCE_PROPOSAL` | counts and examples *about kinds* (which subtypes occur, which are confused) | global | the primary legitimate tenant-to-global path |

### 9.1 Permitted promotion (tenant to global)

Only **value-free aggregate evidence** may cross a scope boundary, and only as a new `GLOBAL` artifact whose
sources are synthetic-generated:

- subtype occurrence counts, confusion matrices and disagreement rates, with a minimum cell size so a rare
  tenant-specific value cannot be re-identified by counting;
- taxonomy *proposals* about kinds and their evidence requirements (for example "engineering drawing numbers need
  tenant-dictionary evidence here"), not tenant terms;
- calibration or hard-negative sets **regenerated from synthetic material** with the same shape, never copied from
  tenant rows;
- sanitized regression *shapes* (a field key pattern, a structural form) with the value removed.

### 9.2 Forbidden promotion

The following can never leave their scope, in any form, including through an aggregate:

- any raw or normalized value, and any dictionary term, template, customer, project, person, host or asset name;
- reversible mapping material, blind indexes, digests or fingerprints of protected values (a keyed or unkeyed
  digest of a low-entropy value is guessable offline, which is why decision 010's provisional choice excludes
  fingerprints);
- free text, screenshots, transcripts or attachments of imported material;
- anything derived from a restricted real incident, a private dataset, or a held-out/blind partition;
- cross-tenant *row-level* merges: "tenant A plus tenant B" is not a promotion, it is a new artifact needing its
  own review, and a two-tenant merge that is not separately authorized is a cross-tenant disclosure;
- an annotation that carries treatment authority, an approval flag, or a `policyVersion` that a runtime could read.

Promotion is a reviewed act with an approver, a reason and a destination scope recorded in the new artifact's
provenance. A tenant administrator cannot approve it alone, and no AI review substitutes for it
([#38](https://github.com/Marcus-Levin/hylja/issues/38) requires a human-owned decision for such gates).

## 10. Access, retention, deletion and imported raw material

**Raw imported material is not Gym data.** It lives in a restricted, tenant-scoped import store (or, in the
synthetic-first MVP, it does not exist at all), and only opaque handles cross into an artifact.

| Concern | Proposed rule | Status |
| --- | --- | --- |
| Import | `SYNTHETIC_GENERATED` or `TENANT_APPROVED_SANITIZED` only. Un-sanitized raw import of real customer/project material is a **separate, reviewed change** and is not in the MVP. | proposed |
| Store | tenant-scoped restricted store, tenant-scoped keys, no shared index, no cross-tenant read path | proposed; not built |
| Lifetime | shortest workable: synthetic material is disposable; approved sanitized material has a proposed maximum retention (a starting proposal is 30 days, reviewed per tenant) and is destroyed on expiry or on request | proposed; numbers need human sign-off |
| Annotation artifact | retained while the tenant needs it; versioned and immutable; a new version supersedes rather than replaces | proposed |
| Deletion | `TOMBSTONED` artifacts keep only the header, refs and `tombstonedAt`; all occurrences and contracts are removed. Deleting the imported material destroys the narrowly scoped import first, because the labels are meaningless without it. | proposed |
| Deletion evidence | a tombstone with a reason code, never a silent in-place removal, so a replay cannot resurrect deleted material | proposed |
| Read access | role-based and tenant-scoped: annotator (own tenant, labeled items), adjudicator (own tenant, disputed items), task owner (own tasks), policy reviewer (preference dataset), evaluator (development artifacts only), tenant administrator (import/retention/deletion only) | proposed |
| Write access | append-only; no API can edit, delete or re-scope a label | proposed |
| Audit | privacy-safe: opaque artifact/occurrence refs, role ref, action code, timestamp, reason code. No values, spans of values, prompts or captures. | proposed |
| Bulk access | no bulk export, search or enumeration API across tenants or artifacts; a per-tenant export is a human-initiated, logged file transfer | proposed |

**Excluded from ordinary logs, Git, CI and issue bodies.** Imported material never enters a log line, a stack
trace, a metric label, a test name, a fixture, a snapshot, a PR description or a chat message. The repository's
existing fixture guard checks *tracked paths* for the repository's own synthetic corpus; it does **not** read the
content of a documentation example, so for this format the value-free property is enforced structurally instead:
every string leaf of an artifact is an opaque ref, a fixed enum, a bounded version label, a UTC timestamp, an
uppercase name, a two-letter code, a declared producer id, or a bounded pointer segment, and there is no value,
note, digest or fingerprint field at all (§12). Because the MVP session does not persist imported material, it adds
no new path for raw material to reach disk; any future persisting importer needs its own review, threat statement
and retention design.

**Blindness and private datasets.** The Gym has no access to held-out material. `partition` is `DEVELOPMENT` only;
an artifact claiming a blind partition is rejected. Annotators never see H-family material, blind oracle labels,
task answers or seeds, and a Gym artifact can never become the *independent* oracle of a scored protocol, because
its labels are authored after observing candidate output ([evaluation.md](../evaluation.md#corpora)). A
tenant's private dataset is reachable only through that tenant's own approved import, and a restricted incident
store stays outside the Gym entirely: an incident is converted into a *synthetic* regression case by its owner,
not uploaded for annotation.

## 11. Human annotation never changes production authority

```text
approved or synthetic import  (restricted store, tenant-scoped)
        |
        v
human annotation  ->  versioned, provenance-bearing artifact  (no values, no authority)
        |
        v
evaluation / replay  (#5 seam, #39 development families, #27 challenger)
        |
        v
review + approval  (human, recorded, out of band)
        |
        v
proposed change  (dictionary entry, detector, question set, calibration, policy version)
```

Properties of that path, each of which a reviewer can check:

- there is **no runtime read path** from an artifact to a resolver, policy engine, broker or sentinel. Grep-able
  evidence: the only consumer proposed here is `evaluations/`, and the format's own `releaseAuthority: false`,
  `evaluationOnly: true`, `containsProtectedValues: false` flags are checked before anything else;
- a label cannot select a treatment, cannot grant USE/DISPLAY/EXPORT, and cannot create a mapping; a
  `KEEP` preference for a port is dataset content, not a decision;
- a `SYNTHETIC` preference never creates a synthetic identity, and a credential is never given a reversible
  mapping ([decision 009](../decisions/009-secrets-are-not-synthetic-identities.md));
- escalation of a tenant's annotations to a *deterministic floor* is a policy change requiring its own review and
  is measured as over-hiding as well as recall, per decision 010's escalation-meters rule;
- rollback stays the immediate prior bundle, and no artifact participates in a rollback.

## 12. The proposed export format (`gym-annotation/0.1-draft`)

A minimal, versioned, strict JSON artifact. Strict means: exact key sets, unknown keys rejected, opaque prefixed
refs, fixed enums, bounded collections, fixed reason codes.

```text
artifactVersion   "gym-annotation/0.1-draft"      format version; a schema change is a new version
artifactId        opaque artifact ref (prefixed, lower-case, no value can satisfy the grammar)
artifactKind      ANNOTATION_EXPORT | TENANT_DICTIONARY_PROPOSAL | CALIBRATION_SET_PROPOSAL |
                  TASK_PREFERENCE_PROPOSAL | HARD_NEGATIVE_SET_PROPOSAL | TAXONOMY_EVIDENCE_PROPOSAL
status            DRAFT_UNREVIEWED | REVIEWED | SUPERSEDED
evaluationOnly    true            always, in every version of this format
releaseAuthority  false           always; a claim of authority is a rejection, not a mode
partition         "DEVELOPMENT"   the only partition this format admits
containsProtectedValues false      raw values, digests and fingerprints are not representable
rawMaterialIncluded   false       imported material is referenced only by an opaque store handle
scope             { level: TENANT|GLOBAL, tenantRef?, projectRef? }
retention         { class, expiresAt, deletionState, tombstonedAt }
provenance        { createdAt, questionnaireVersion, vocabularyVersion, informationModelVersion,
                    toolchainVersion, intelligenceBundleRef, proposalProducers[] }
sources[]         { importRef, importKind, rawMaterialStore, rawMaterialRef, fieldCount }
fields[]          { fieldRef, importRef, sourcePath (bounded, escape-free pointer), unitKind,
                    codePointLength, byteLength, normalization, byteMapping, proposalCoverage,
                    proposalProducers[] }
occurrences[]     { occurrenceRef, fieldRef, span{unit,start,end,derivedByteSpan?}, origin,
                    proposalProducers[], missReason?, dictionaryState (four-value enum), entityRef?,
                    relationships[], labelHistory[] }
  labelHistory[]  { version, decidedByRoleRef, decidedAt, groundTruth, taskPreference?, adjudication? }
    groundTruth    LABELED: { semantic{semanticType,domain?,subtype}, privacy{personalData,
                              specialCategory,jurisdictions[]}, sensitivity, confidence }
                   UNKNOWN: { unknownReason }      ABSTAINED: { abstainReason }
    taskPreference LABELED: { taskRef, destinationRef, exactValueRequired, preferredRepresentation }
                   UNKNOWN: { taskRef }
    adjudication   { resolution: ADJUDICATED | UNRESOLVED }   final entry only
taskFidelityContracts[] { contractRef, taskRef, ownerRoleRef,
                          requirements[]{ targetRef, predicates[] } }
```

Every string in that sketch is an opaque ref, a fixed enum, a bounded version label, a UTC timestamp, an
uppercase name, a two-letter code, a declared producer id, or a pointer segment of `[A-Za-z0-9_.-]`. There is no
field a value, a dictionary term, a note or a digest can be written into, which is what makes the "value-free"
property in §10 and §9.2 mechanical rather than aspirational.

Deliberate omissions, each of which is a decision rather than an oversight:

- **no value, preview, snippet, digest, fingerprint or free-text rationale field** anywhere. Rationales are fixed
  reason codes; the longer record lives in the restricted review store, referenced by an opaque ref. The two
  version-shaped provenance fields (`questionnaireVersion`, `toolchainVersion`) are bounded `name/version`
  identifiers, not prose, so "no free text" holds for every field in the format;
- **no `trust` field** - influence trust is bound from the interaction context, never annotated per value
  ([decision 002](../decisions/002-sensitivity-and-trust-are-separate.md));
- **no treatment/authorization/policy field** in `groundTruth` - strict key sets make the separation mechanical;
- **no `datasetScores` or `passed` field** - an artifact is input to evaluation, never its outcome;
- **no timestamped value history** - only labels are versioned, so a stale value cannot be replayed;
- **no `retention`-less artifact** - expiry and deletion state are mandatory, and every timestamp in the format
  must be a **real instant**, not merely a well-shaped string: `2026-13-01T00:00:00Z` and the rolled-over
  `2026-02-30T00:00:00Z` are both rejected (`RETENTION_TIMESTAMP_INVALID`), because a retention deadline that
  silently moves, or a date a gate cannot read, is exactly the failure mode a retention rule must not have;
- **no free-form `dictionaryState`** - it is a four-value enum, because the tenant's dictionary *terms* belong in the
  separate tenant-scoped dictionary artifact, never inside an annotation;
- **no duplicate field view** - one record per `(importRef, sourcePath, normalization)`.

The committed example is
[`docs/examples/gym-annotation-export-draft-0.1.json`](../examples/gym-annotation-export-draft-0.1.json): two
fields, seven occurrences, all obviously synthetic opaque refs. It deliberately contains **no source text at all** -
it demonstrates proposed/agreed, an open disagreement, a manual confirmed miss, a `KEEP` preference on a port, an
`UNKNOWN`, a `POLICY_QUESTION_ESCALATED` abstention that still carries a preference, an overlapping compound span,
a repeated value joined by `SAME_AS` with a shared `entityRef`, a `UNVERIFIED` byte mapping, and one task-fidelity
contract with no corresponding treatment. Field lengths in it are illustrative: the restricted store holds the
material. Its `createdAt`/`expiresAt` are kept as originally written, so under any wall clock after `2026-04-01`
the eligibility predicate additionally reports `ARTIFACT_EXPIRED`: that is the retention rule working, and tests
pass an explicit evaluation clock for determinism.

## 13. The evaluation-only validator

[`evaluations/gym-annotation-schema.mjs`](../../evaluations/gym-annotation-schema.mjs) is a small, **unwired**
checker for the format above. It is evaluation-only and NON-ENFORCING, reads no files and opens no network
connection, reuses the frozen sensitivity / treatment / fidelity / privacy vocabularies from the existing modules so
the proposal cannot drift from contract names, and returns fixed reason codes only. It is not a tenancy,
authentication or authorization boundary: the scope inside an artifact is self-declared data. It is a text file with
no raw control bytes, so it stays greppable and diffable as reviewable evidence.

Purity: `validateGymAnnotationArtifact`, `gymEffectiveLabel` and `gymReviewQueue` are pure and time-independent.
`gymOracleEligibility` is the one function that consults a clock - `Date.now()` by default - so it is deterministic
only when a caller passes `now`; tests and reproducible replays must. Validation itself never reads a clock, which
keeps an artifact's shape independent of when it is checked.

Its behaviors are the observable part of this proposal: strict key sets (so mixing spaces or adding a value field
is a rejection), span-unit and byte-mapping rules, occurrence/relationship/reference integrity, append-only version
sequences with order-independent agreement, adjudication placement, coverage consistency, a bounded escape-free
pointer grammar, fixed-enum leaves, real-instant timestamp validation, scope-escalation and blind-partition
rejection, the derived label-state function, the deterministic review queue, a local development-ground-truth
eligibility predicate that honours deletion, expiry and emptiness and fails closed on an input it cannot read, and
bounded, non-echoing failure on malformed, hostile or oversized artifacts.
[`evaluations/gym-annotation-schema.test.mjs`](../../evaluations/gym-annotation-schema.test.mjs) exercises those
behaviors with synthetic artifacts; the interface and its limits are documented in
[`evaluations/README.md`](../../evaluations/README.md).

Known limits, stated rather than implied:

- **role separation is not enforced.** An artifact in which the role that made the original assertion also appends
  the `ADJUDICATED` entry validates and is reported eligible. The rule in §2 is a design rule for a human process, and
  nothing in this development aid can tell two opaque role refs apart;
- **artifact kinds carry no kind-specific content requirements.** `TENANT_DICTIONARY_PROPOSAL` and the other product
  kinds are validated as an enum only: the checker does **not** enforce §9 promotion policy per kind, and a
  `GLOBAL`-scope dictionary proposal would still validate on the enum. Promotion remains a reviewed human act;
- **the checker has no clock and does not decode.** Expiry is consulted only by the eligibility predicate (with an
  optional explicit evaluation clock, failing closed when unusable), and the surrogate/normalization/byte-length
  rules in §4.2 belong to a future importer and UI, not here;
- **timestamp strictness is a documented choice, not a calendar library.** A timestamp must round-trip through
  `Date.parse` and the ISO string, so out-of-range months, days, hours, minutes and seconds are rejected. That
  accepts every instant ECMAScript can represent and no rolled-over or imaginary one; it does not attempt
  leap-second or calendar-reform semantics, which this format does not need;
- it reports one generic `FIELD_INVALID` code rather than a per-field reason, and it does not detect duplicate JSON
  keys (that needs a raw-byte pre-parse, as the D05 projector does). A missing or duplicated producer list also
  fails the per-occurrence containment checks, so such an artifact reports several codes at once; the artifact is
  invalid either way. Within a single record each defect keeps its own code, so a bad `retention.class`
  (`BAD_ENUM`) is never reported as an unreadable date (`RETENTION_TIMESTAMP_INVALID`);
- **cost is bounded but not free at the maximum.** A single maximal legal artifact (64 sources, 512 fields, 4096
  occurrences with 64 label entries each, 64 contracts with 256 requirements) parses in roughly 2 s per entry
  point, and `gymEffectiveLabel` is the most expensive of them because order-independent agreement compares the
  newest assertion against every earlier one. That is a development-aid cost, not a service budget; the 20 behavior
  groups run in about 0.2 s in total, and no threshold was raised or added.

## 14. Integration with #5/#39 evaluation and later #27 promotion

| Gym concept | Existing seam | Rule |
| --- | --- | --- |
| `fields[].fieldRef` | #5's evaluator-minted `field-N` refs | opaque ordinals minted by the evaluator, never caller-authored |
| `occurrences[].span` (code points) | #5 oracle UTF-8 byte occurrence offsets | join only through a declared, verified `byteMapping`; otherwise `untested` |
| `labels.groundTruth` | the draft-2 oracle annotation record (`occurrenceRef`, `entityRef?`, `semantic`, `privacy`, `sensitivity`) in [contracts/information-model-draft.md](../contracts/information-model-draft.md) | a *mapping proposal*, not an identity; trust and treatment stay absent |
| `labels.taskPreference` | #5 `expectedTreatments` | **never** mapped: preference is not an oracle expectation, and the #39 policy reviewer owns expected treatments |
| `labelHistory` disagreement | #5 has no disagreement concept | an artifact with an open, undecided or unresolved label, or one that is unreviewed, superseded, tombstoned, expired, unreadably dated or empty, is **ineligible** as registered ground truth |
| `partition: DEVELOPMENT` | #39 development vs held-out families | Gym artifacts are development/regression evidence only |
| `artifactId@version`, `scope`, `provenance` | #27 bundle registry and replay record | recorded with every replay, including the reason the artifact was admitted |
| dictionary proposals | #10 configured candidate sources | a reviewed, tenant-scoped configuration change, never a runtime annotation read |

Two consequences worth stating plainly:

1. **The Gym cannot supply #39's independent oracle.** #39 requires the planted oracle to be authored and
   reviewed independently of any candidate's output. A Gym annotation exists *because* someone looked at proposed
   candidates and their classifications, so it is development evidence and a regression source. Promoting it into
   held-out scoring would break the independence rule, and the local eligibility predicate above is a schema gate,
   not #39 eligibility.
2. **#27 promotion stays where it is.** A Gym artifact enters replay as challenger evidence. The champion bundle,
   its thresholds, its policy and its question set change only through the #27 release gate with recorded
   privacy/utility/latency comparisons and immediate rollback. Conflicting and unknown labels stay explicit in
   every report; they are never averaged into a fake consensus, and a Gym artifact can never promote itself.

## 15. Unresolved gates (human ownership, authentication and acceptance)

These are decisions, not questions to be answered later by an implementer. Each blocks something specific.

| # | Gate | Blocks | Needs a human decision on |
| --- | --- | --- | --- |
| G1 | Who is the annotation **custodian**, and who may adjudicate? | any real annotation activity | appointment, role separation, removal procedure |
| G2 | **Authentication** of annotators, reviewers and importers, and tenant/project membership proof | any import of tenant-approved material | SSO/MFA and workload identity direction; the format deliberately assumes no authenticated identity |
| G3 | Accept or amend **decision 010** and the #65/#66 vocabulary | stable `vocabularyVersion` values; the human-evidence mapping in §3 | the open reviewer questions listed in decision 010 |
| G4 | Import eligibility: what counts as "approved/safe" material, and may unsanitized real material ever be imported? | the second import kind | tenant data-owner approval, sanitization bar, DPIA-style assessment |
| G5 | Retention periods, deletion SLA and the restricted-store design | the `expiresAt` default and any importer | concrete numbers, key scope, destruction evidence |
| G6 | Promotion approver and the minimum cell size for aggregate statistics | any tenant-to-global artifact | approver role, threshold, audit requirement |
| G7 | Inter-annotator agreement method and threshold, and whether two annotators are required at all | any "agreed" claim used as a quality gate | method choice (see §17) and a minimum-agreement bar per class |
| G8 | Whether `SOLE_ENTRY` may be used as evaluation ground truth, or only `AGREED`/`ADJUDICATED` | the local eligibility predicate | reviewer ruling. This gate is now consequential: because agreement requires a matching second assertion or an explicit adjudication (section 6), ruling out `SOLE_ENTRY` needs one further blocker in the local predicate, which as written still admits a single uncorroborated assertion. |
| G9 | Whether a deterministic sensitivity **floor** may ever be raised by tenant annotations, and how over-hiding is bounded | any "Gym improves recall" claim | policy review plus an over-hiding metric |
| G10 | #39 protocol freeze ordering: whether any Gym artifact may be admitted to a development family after the pre-tuning lock | scored comparisons | the protocol steward, under independent review |

## 16. MVP scope and explicit exclusions

In scope: paste or open approved or synthetic text, log lines and bounded parsed structured fields **in a local
session that does not persist the imported material** (so the MVP needs no restricted store); propose candidates
from existing producers; create manual missing candidates with a reason; label semantic type/domain/subtype,
privacy attributes and sensitivity; record a task preference in a separate space; accept a task owner's fidelity
contract; `UNKNOWN` and abstention; append-only history with adjudication; append-only disagreement preservation;
deterministic review queue; versioned export; evaluation through the existing seam.

Out of scope, deliberately: online learning or any fit at annotation time; RLHF, reward models or preference
optimization; hosted model or judge calls (a judge may propose candidates, but the Gym adds no model traffic and
no external sink); OCR, images, audio, archives and other binary/opaque content; PDF/DOCX rendering; multi-user
live collaboration and reconciliation; an importer for unsanitized real material; a bulk annotation or bulk mapping
API; automatic promotion of anything; anything that changes classification v1 or policy.

## 17. Evidence basis, and how to read it

**Reviewed contract evidence in this repository** (authoritative, and what this design is bound to): the
classification contract and v1 composer, policy treatments, the draft-2 information model and its fidelity
predicates, the #5 seam and its evaluator-minted refs and in-memory capture, the D05 span projector's documented
ASCII/unescaped boundary, the #39 corpus/protocol and rubric proposals, the fixture guard, and the fixture-derived
facts this design reuses (opaque ordinal refs, no payload echo, code-point versus UTF-8 byte distinction).

**Research recommendations, not verified in this repository.** These motivate choices; they are not authority, and
none of them was executed or adopted here:

- *Inter-annotator agreement*: K. Krippendorff, *Content Analysis: An Introduction to Its Methodology*, and
  Krippendorff, "Reliability in Content Analysis", *Human Communication Research* (2004), for alpha and the
  level-appropriate metric choice; J. Cohen, "A Coefficient of Agreement for Nominal Scales",
  *Educational and Psychological Measurement* (1960), and E. W. Scott, "Interrater Agreement among Multiple
  Raters", *Psychological Bulletin* (1955), for the two-rater coefficients. Practical consequence used here:
  agreement needs multiple coders and a level-appropriate metric, so a single annotator yields **no** coefficient
  and the design therefore records states rather than reporting a number. G7 must choose a method before any
  agreement number is published.
- *Active learning*: B. Settles, *Active Learning Literature Survey*, University of Wisconsin-Madison technical
  report (2009); Lewis & Gale, "A Sequential Algorithm for Training Text Classifiers", ICML (1994), for uncertainty
  sampling; Dagan & Engelson, "Committee-Based Sampling for Training Probabilistic Classifiers", ICML (1995), for
  committee disagreement; Melville & Gammerman, "Active Learning for Probabilistic Models Using the Expected Error
  Reduction", ICML (2001), and Cohn & Ghahramani, "Active Learning with Statistical Models", *Journal of Artificial
  Intelligence Research* (1996), for expected-model-change. Used only to justify deferring these: with a single
  annotator, a small artifact and no scored pipeline yet, a deterministic queue is the honest MVP.
- *Hard negatives / dataset documentation*: Liu et al., "Blind Instruction Tuning", ACL (2023), for mined false
  labels as an error source, and Gebru et al., "Datasheets for Datasets", *CACM* (2021), and Mitchell et al.,
  "Model Cards for Model Reporting", FAT* (2019), for documenting an artifact's purpose, limits and intended
  use. Cited as reasons to keep a `TAXONOMY_EVIDENCE` and `HARD_NEGATIVE` product with its own scope, not as an
  adopted practice.
- *Unicode and encoding*: [UAX #15](https://www.unicode.org/reports/tr15/) (normalization),
  [UAX #29](https://www.unicode.org/reports/tr29/) (grapheme clusters),
  [RFC 3629](https://www.rfc-editor.org/rfc/rfc3629) (UTF-8), and
  [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) (JSON Pointer). These are primary specifications for the
  span and pointer rules in §4.
- *Data protection*: GDPR principles of data minimisation and storage limitation, Article 9 special categories,
  Article 22 automated individual decision-making, and the Article 29 WP29 Opinion 05/2014 on anonymisation
  techniques (WP216) for the pseudonymisation/anonymisation boundary. Used as reasons for minimization, retention
  and the "human labels are not a legal determination" rule, never as a compliance conclusion. The Swedish
  national-ID question remains with IMY and qualified legal review as already recorded in the #65 draft.
- *Governance*: NIST AI RMF 1.0 (2023) MAP/MEASURE/MANAGE framing as a candidate vocabulary for the gates in §15.
  Not reviewed in this repository.

## 18. Coverage of #67's acceptance criteria

| #67 criterion | Where |
| --- | --- |
| Ground-truth annotation and policy preference explicitly separate | §3, §12 (strict key sets), validator groups "ground truth and policy preference are mechanically separate spaces" and "no free-form string leaf can carry content into an artifact" |
| Candidate proposal + manual missing-candidate annotation | §5, `origin`/`missReason`/`proposalCoverage`, validator group "candidate provenance is complete, declared and consistent with the origin" |
| Tenant/project scoping and provenance | §7, §9, §10, validator groups "tenant scope cannot be relabelled as global…" and "candidate provenance…" |
| Human disagreement / unknown handling | §6, derived label states measured against the newest earlier assertion, validator group "disagreement, UNKNOWN and abstention are distinct preserved states" |
| Active-learning prioritization defined | §8, `gymReviewQueue`, validator group "review prioritization is deterministic, non-learned and never drops an occurrence" |
| No annotation directly changes production authority | §1, §11, `releaseAuthority: false`, §14 |
| Minimal versioned dataset/export format proposed | §12, the committed example, §13 |
| Integration with #39/evaluation described | §10 (blindness), §13, §14 (including the deletion/expiry/emptiness eligibility blockers) |
| Privacy/retention constraints for uploaded real-world data | §10, §12 (no value/note/digest field anywhere), plus §1's synthetic-first MVP |
| MVP avoids full RLHF infrastructure | §1, §16 |

## 19. Open design questions for the reviewers

1. Should a `TAXONOMY_EVIDENCE` promotion require a minimum cell size large enough that a tenant-specific value
   cannot be re-identified by counting, and what is that number per subtype?
2. Is `SOLE_ENTRY` acceptable development ground truth, or must every registered occurrence be `AGREED` or
   `ADJUDICATED`? (G8)
3. Should a `GLOBAL` `TAXONOMY_EVIDENCE` artifact cite the tenant artifacts it was derived from by opaque ref, or
   cite none at all to avoid a correlation channel?
4. Do we need a `DERIVED_FROM` relation between occurrences and a *sanitized regression case* in a #5 dev case, or
   is the artifact ref in provenance sufficient?
5. Should the queue be stratified per semantic class so a bounded review budget cannot concentrate on one domain?
6. Should a *noise* answer (a candidate the annotator rejects as a false positive) be modelled as a contradicting
   `groundTruth` entry (as proposed), as its own label status, or as a separate `hardNegative` field?
7. Does the `GYM_BYTE_MAPPINGS: DERIVED` path need a signed or custodied mapping record before any non-ASCII
   artifact may feed #5 replay, or is an evaluator-local verification plus an `UNVERIFIED` fallback sufficient?
