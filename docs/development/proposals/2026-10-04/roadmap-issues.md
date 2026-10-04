# Roadmap group — backlog clarity and slicing proposals

**Next phase, not current work.** The first runnable synthetic end-to-end path is prioritized in [e2e-critical-path.md](e2e-critical-path.md); pipeline preparation remains current work while product implementation is paused.

Snapshot: `issues-roadmap.json` fetched 2026-10-04, 22 issues (#30–#48, plus #65, #66, #68).
Repo main inspected at `2e88ca065473f8c7020a7a0e66b0f465e0f95f07`.
**All work remains paused by the user.** Nothing below authorizes starting work; it sets execution scope *when* work resumes.

These are proposals, not a second status tracker. Status, priority and dependency order live in the issues; [docs/capabilities.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/capabilities.md) is the capability authority. Every original criterion, checkbox value and mark stays unchanged on its live issue URL; nothing is deleted or re-ticked here.

---

## Audit rows

### Enterprise controls

**#30 Add behavioral signals, abuse detection, and step-up controls** — **slice (preliminary)**.
Five deliverables in one ticket (event model, baselines, risk signals, throttle/step-up/block, alert hooks); the restrict-only invariant is testable without the broker.
Pointers: [security-model.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/security-model.md), [threat-model.md#bulk-enumeration](https://github.com/Marcus-Levin/hylja/blob/main/docs/threat-model.md).
Effect prerequisites: #17 (unimplemented), #20 (implemented). Questions: none blocking.
Smallest observable preparation: a tenant-partitioned behavior event record plus a property test that lowering a risk score never widens a previously denied USE/DISPLAY/EXPORT.

**#31 Implement backup, disaster recovery, and incident-response operations** — **slice (preliminary)**.
Recovery design, credential/role separation, key rotation and incident runbooks separate cleanly; #18 owns only synthetic fixture-level snapshot/deletion semantics.
Pointers: [threat-model.md#backup-compromise](https://github.com/Marcus-Levin/hylja/blob/main/docs/threat-model.md).
Effect prerequisites: #16/#18/#29 unimplemented; #20 implemented.
Smallest observable preparation: the issue's own written adversarial scenario (older backup after tenant-scoped key destruction cannot resurrect the mapping; unaffected tenant restores with its own keys) drafted as a `test/<name>` **template** for the production-equivalent isolated synthetic recovery environment — the scenario is **written, not verified executable**, and production-equivalent isolation stays a requirement.

**#32 Enforce managed egress and bypass resistance** — **keep, with a preparatory child**.
Acceptance is already a binary observable claim with named negatives.
Pointers: [architecture.md#independent-egress-control](https://github.com/Marcus-Levin/hylja/blob/main/docs/architecture.md).
Effect prerequisites: #21/#23/#24/#25/#26 unimplemented. This is **not** a claim that nothing can run: [docs/evaluation.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/evaluation.md) expressly permits pre-vault synthetic invariant tests.
Smallest observable preparation: the enumerated direct-route inventory plus a synthetic invariant test for the direct-route list. Satisfies no checkbox on its own — say so rather than tick one.

**#33 Add supply-chain, build provenance, SBOM, and release integrity** — **clarify (preliminary)**.
The merged foundation is recorded in the body; residual scope is signing custody, attested build, scanner severity policy and conformance ownership. That residual scope is **partly implementation/integration, not only a human decision**.
Pointers: [release-integrity-contract.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/contracts/release-integrity-contract.md), `npm run audit:deps` / `sbom` / `check:sbom`.
Questions: who owns signing authority and custody (human). Smallest observable preparation: a named owner plus a written promotion trust policy; the CLI already fails closed.

**#34 Add multimodal and nested-content extraction architecture** — **keep, deferred**.
Acceptance is bounded and adversarial; the charter excludes OCR/binary rewriting from the first proof.
Foundation/completion: **#19 sentinel core implemented; extractor/send-point integration unmet.**
Pointers: [charter.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/charter.md).
Effect prerequisites: #6 done; #13/#19 integration unimplemented.

**#35 Package deployment profiles** — **keep, blocked (preliminary)**.
Foundation/completion: **#28 offline governance foundation implemented; deployment/runtime criteria unmet.**
A capability matrix alone would cache `docs/capabilities.md`; the **sovereignty/air-gap matrix is not a duplicate** — it enumerates where plaintext, ciphertext, semantic context and keys may exist per profile, and air-gapped claims need dependency, update, judge, KMS and telemetry paths shown local or disabled.
Pointers: [capabilities.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/capabilities.md).
Effect prerequisites: #28/#29/#31/#32 unimplemented.

### Roadmap and detection

**#36 Hylja implementation roadmap** — **reconcile** (proposal B1).
#36 already defines closure-only semantics: "This checklist tracks child issue closure", each child owns its scope/status/dependencies, and "a source or synthetic foundation does not complete a runtime milestone". **Keep that meaning and every mark.** There is no box-meaning ambiguity to fix, and no per-row live capability cache is wanted.
Pointers: [docs/README.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/README.md).
Effect prerequisites: none. Smallest observable preparation: prose-only reconciliation (see B1) — no checkbox value changes, no relocation of requirements into `AGENTS.md`.

**#37 Implement PERSON/EMAIL/PHONE deterministic candidate generation** — **clarify (preliminary)**.
`src/contact-candidates.ts` and `src/classification-units.ts` ship with contracts and focused tests while all five acceptance boxes are unchecked.
Pointers: [classification-unit-contract.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/contracts/classification-unit-contract.md).
Downstream end-to-end egress evidence is **explicitly pending** in the issue until transformation and sentinel boundaries run; it is not a prerequisite standing over every candidate-source acceptance item.
Smallest observable preparation: name which acceptance bullets remain unproven (held-out recall/false-positive characterization per NAME/EMAIL/PHONE) without unticking any box. End-to-end criteria remain unmet.

### Reuse / buy / build campaign (#38 parent, #48 decision)

**#38 Evaluate existing privacy/cloaking solutions before committing build scope** — **keep as parent epic**.
Outcome, prerequisites, child list, decision rules, deliverables and non-goals are well-formed and correctly delegate scope. **#38's two-axis evidence schema is authoritative**; #39 delegates to it, not the reverse. No defect to fix here.
Smallest observable preparation: none of its own; every checklist item is satisfied by a child or an explicit access-limited blocker.

**#39 Build shared synthetic engineering corpus and freeze comparative evaluation protocol** — **slice** (proposal B2, corrected).
Public synthetic development corpus, manifest draft and reference records already exist, so children are bounded extensions/reconciliation, not new foundations.
Pointers: [evaluation.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/evaluation.md), [decision 005](https://github.com/Marcus-Levin/hylja/blob/main/docs/decisions/005-evaluation-precedes-authority.md).
Effect prerequisites: the **freeze** gates scored #40–#45/#47; preparatory corpus work does not.
Questions/human: independent blind custodian appointment, approved pre-tuning chronology.
Smallest observable preparation: a committed public manifest carrying an explicit "not frozen, not eligible" status. `evaluations/preparation-integrity.mjs` is a **drift check** (per `evaluations/README.md`) — not baseline execution and not task grading.

**#40 Benchmark local detection: Presidio vs OpenAI Privacy Filter** — **slice (corrected)**.
Foundation/completion: **native/Presidio/union DEV observations exist and are unscored; all required scored comparisons — Presidio *and* Privacy Filter — remain pending.** The prior claim that only the Privacy Filter arm is outstanding was wrong.
Outstanding obligations retained: subtype-separated scored results, Swedish identifier case families (personnummer/samordningsnummer, checksum/date shapes, organisationsnummer), country/language and recognizer configuration actually loaded, engineering controls (ports, paths, connection strings) separated from policy-driven over-cloaking, diagnostic-disclosure capture in the isolated synthetic runner, and deployment/resource/utility requirements.
Pointers: [issue-40-matched-development-comparison-2026-10-02.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/research/issue-40-matched-development-comparison-2026-10-02.md).
Effect prerequisites: #39 freeze for scored arms; #46 lightweight prescreen before executing third-party packages, full #46 due diligence before adoption.

**#41 Measure Jev's incremental value** — **keep, deferred**.
Acceptance already states the honest deferral when no qualified #40 winner exists, and isolates any external raw-context arm. Pointers: [semantic-judge-shadow.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/contracts/semantic-judge-shadow.md). Smallest observable preparation: desk disposition only; no scored claim is available.

**#42 Compare end-to-end privacy proxies** — **clarify (corrected)**.
Candidates are **not** established as unrunnable; use **conditional access/execution dispositions**: version/config/license/tier + provenance recorded per candidate, `untested` with **no observed outcome** where execution is unavailable, and affected critical choices deferred rather than inferred.
Pointers: [adapter-contract.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/contracts/adapter-contract.md).
Effect prerequisites: #39 freeze for scoring.

**#43 Benchmark engineering fidelity and safe restoration** — **slice (preliminary)**.
Split workload/rubric design (unblocked) from scored execution (blocked on #39 freeze). Pointers: [issue-43-68-synthetic-dev-test-plans-v0.1.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/research/issue-43-68-synthetic-dev-test-plans-v0.1.md). Smallest observable preparation: the #68 requirement-extraction memo — no scored result claim.

**#44 Evaluate mapping-vault and use-without-reveal reuse** — **keep**.
Acceptance is two-axis and honest about untested commercial capabilities; missing documentation alone is not an observed failure. Pointers: [vault.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/vault.md).

**#45 Build harness/MCP/tool/bypass coverage matrix** — **keep**.
Already defines `enforced` as independently executed planted evidence *and* zero bytes on denial; source-only cells stay source-inspected/unverified. Pointers: `threat-model.md`, `capabilities.md`. Complete managed-egress coverage still requires #32.

**#46 Verify dependency/license/maintenance/supply-chain suitability** — **keep, partly executed (corrected)**.
Two Presidio prescreen records exist. **Register coverage is not adoption**: full license/supply-chain due diligence over the actual inspected artifact, exit/replaceability and #33-derived requirements remain outstanding.
Pointers: [scripts/research/README.md](https://github.com/Marcus-Levin/hylja/blob/main/scripts/research/README.md) (research-only, outside CI).

**#47 Compare commercial agent-privacy platforms** — **clarify (corrected)**.
**3 of 5 acceptance items are checked** (data-boundary/deployment assumptions, public pricing/terms, buy/integrate/build gap analysis with a DEFER conclusion). The matrix under frozen #39 and supported differentiators remain unchecked.
Pointers: [issue-47-commercial-public-terms-2026-10-02.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/research/issue-47-commercial-public-terms-2026-10-02.md).
Effect prerequisites: #39 freeze plus trial access (procurement-adjacent human gate). Smallest observable preparation: none without access; keep the issue open on its DEFER disposition rather than closing on source-only evidence.

**#48 Decide reuse / buy / build scope and revise the roadmap** — **slice** (proposal B3, corrected).
Full scope: **all sixteen subsystem decisions**, each of the nine decision-quality fields, the #2→#3→#4→#17→#19 flow trace with demonstrated differentiation, the smallest defensible proof, the dependency order, the full #6–#35/#37/#65–#68 reconciliation (plus #1/#5 only if their implementation choices change), ADRs for accepted architecture changes and #38 closure links. **"Five effect-critical subsystems only" was a false narrowing and is dropped.**
Pointers: [issue-48-subsystem-decision-cards-v0.1.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/research/issue-48-subsystem-decision-cards-v0.1.md), [docs/README.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/README.md).

### Proposed design records (all proposed, all unwired)

**#65 Research and define classification taxonomy** — **clarify** (proposal B4).
Draft, source index, source-gap supplement and review snapshot exist, **but the taxonomy itself records partial PII coverage and source gaps**: document existence does not establish that only a human decision remains. Keep the whole parent scope (8 acceptance items).
Pointers: [information-model-draft.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/contracts/information-model-draft.md).
Questions: the `IDENTIFIER` vs `PERSONAL_IDENTIFIER` boundary is a provisional preference in an existing record to **challenge**, not an unanswered sponsor question.

**#66 Separate semantic classification, privacy attributes, sensitivity, trust, task fidelity** — **clarify** (proposal B4).
Draft contract plus `src/information-model-draft.ts` plus [decision 010](https://github.com/Marcus-Levin/hylja/blob/main/docs/decisions/010-separate-information-dimensions-and-task-fidelity.md), which is **proposed**; private role acceptance, conflict checks and independent human review are pending. Keep the whole parent scope (7 acceptance items). Accepted decisions 001–009 stay authoritative.

**#68 Preserve task semantics when cloaking protected values** — **clarify** (proposal B4).
[transformation-semantics-draft.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/contracts/transformation-semantics-draft.md) states it is AI-authored and AI-reviewed only, which satisfies no human adoption gate. Keep the whole parent scope (8 acceptance items); required #43 evidence and final adoption remain separately pending. Pointers: [decision 009](https://github.com/Marcus-Levin/hylja/blob/main/docs/decisions/009-secrets-are-not-synthetic-identities.md).

---

## Priority proposals — PRELIMINARY, NOT READY

**Status for B1–B4: PRELIMINARY, NOT READY.** No complete criterion → named future owner → observable proof mapping is supplied for any of them. The owners below are proposals; they are not a mapping, and nothing here claims "all criteria mapped". Whole parent scopes are preserved regardless of which children are chosen.

### B1 — #36 roadmap reconciliation (prose only)

- **Issue:** [#36](https://github.com/Marcus-Levin/hylja/issues/36).
- **One observable outcome:** #36 states its existing closure-only rule where the checklist lives, and its prose no longer repeats rules that already live in `AGENTS.md`.
- **Pointers:** [docs/README.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/README.md); `AGENTS.md`; [threat-model.md#threat-model-outputs](https://github.com/Marcus-Levin/hylja/blob/main/docs/threat-model.md) for the retained per-issue threat/attack-surface obligation.
- **Scope / non-goals:** in scope — restating the closure-only meaning already stated; pruning duplicated "Shared requirements" prose **only** where the per-issue "state threats addressed and attack surfaces introduced" obligation is retained (or linked to the specific threat-model output) alongside `AGENTS.md`. Out of scope — re-ordering, adding issues, changing any `[x]`/`[ ]` value, adding a per-row live capability cache, relocating requirements into `AGENTS.md`.
- **Unmet prerequisites / human questions:** none; this is issue-text prose.
- **Verification:** prose-only. No build and no `npm test`. `npm run check:docs` (if a tracked relative Markdown link changes) checks repository Markdown links, not issue URLs or external reports.
- **Acceptance retained:** every existing checkbox value stays byte-identical, including #27's row and the closure-only sentences.

### B2 — #39 parent epic plus three bounded children

- **Issue:** [#39](https://github.com/Marcus-Levin/hylja/issues/39) as parent epic; its **ten** acceptance checkboxes stay verbatim on the parent.
- **One observable outcome:** a committed public manifest carrying an explicit "not frozen, not eligible" status, plus a named custodian and an approved pre-tuning chronology recorded — with no retroactive eligibility for already-exposed DEV material.
- **Pointers:** [evaluation.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/evaluation.md); `docs/research/issue-39-v0-preparation-draft-p0.1.json`; `docs/research/issue-39-v0-open-gates-p0.1.md`; [synthetic-evaluation-seam.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/contracts/synthetic-evaluation-seam.md); `evaluations/README.md`.
- **Children (proposed):**
  1. **Public development corpus + manifest schema extension.** Observable: manifest committed; `npm run check:fixtures` green; drift checks via `evaluations/preparation-integrity.mjs` (drift only, no baseline execution, no task grading).
  2. **Executable non-enforcing no-Jev baseline.** Observable: built, then focused compiled-module tests green (build first); run emits `PREPARATION_VALID_BUT_NOT_ELIGIBLE / PUBLIC_DRAFT_ONLY`.
  3. **v0 freeze package + custody handoff.** Observable: independent oracle and blind custody in place, structurally independent held-out families, accepted #65/#66 vocabulary, approved supported scope, destination/policy treatments, downstream task/rubric, scoring rules and critical gates, complete version/hash coverage (supported scope, oracle, destination/policy and downstream-task config, blind split, scoring), and a #38 link to the frozen protocol version. **Freeze happens before tuning, followed by the executable final-v0 freeze. This child is the human gate.**
- **Non-goals:** no scored comparison; no held-out contents in Git, PRs or CI; no retune of v0 after outcomes; no retroactive credit for exposed DEV evidence.
- **Verification:** `npm run check:fixtures`; `npm run build` **before** any compiled-module test; `node evaluations/preparation-integrity.mjs` (drift only).
- **Mapping status:** owners are proposed; the criterion→owner→observable proof map is **not supplied** and the proposal stays preliminary.

### B3 — #48 parent epic plus three children

- **Issue:** [#48](https://github.com/Marcus-Levin/hylja/issues/48) as parent epic; its **seven** acceptance checkboxes stay verbatim on the parent.
- **One observable outcome:** a register where each of #39–#47 has a result or an explicit evidence/access-limited blocker, plus decision cards for all sixteen subsystems.
- **Children (proposed):**
  1. **Child-disposition register** for #39–#47. Observable: one disposition line per child, result or explicit blocker.
  2. **Subsystem decision cards — all sixteen**, prioritizing the effect-critical ones (#2 envelope, #3 classification, #4 Policy Engine, #17 brokered USE/DISPLAY/EXPORT, #19 final-byte sentinel) without dropping the other eleven. Observable: cards in the `issue-48-subsystem-decision-cards-v0.1.md` format, each carrying the nine decision-quality fields, the #2→#3→#4→#17→#19 flow trace, and only demonstrated differentiation.
  3. **Reconciliation and closure.** Observable: smallest defensible proof with dependency order; one-line dispositions across #6–#35, #37 and #65–#68 (+#1/#5 only if their implementation choices change); reviewed decisions **before** any issue edit; ADRs for accepted architecture changes (not for every edit); #38 links to the final decision and revised roadmap.
- **Non-goals:** no adoption without #46 full due diligence; no source-only adoption; no issue edit before its decision (and any required ADR) is reviewed.
- **Verification:** documentation review, not script; `npm run check:docs` if tracked relative Markdown links change (no build, no `npm test` for prose-only work).
- **Mapping status:** preliminary; no criterion→owner→observable proof map supplied.

### B4 — #65 / #66 / #68 review against all 23 criteria

- **Issues:** [#65](https://github.com/Marcus-Levin/hylja/issues/65) (8), [#66](https://github.com/Marcus-Levin/hylja/issues/66) (7), [#68](https://github.com/Marcus-Levin/hylja/issues/68) (8).
- **One observable outcome:** each of the 23 criteria is marked **satisfied by cited evidence / partially satisfied (bounded finding) / open**, with an accept/revise/reject disposition per issue and named reservations.
- **Pointers:** [decision 010](https://github.com/Marcus-Levin/hylja/blob/main/docs/decisions/010-separate-information-dimensions-and-task-fidelity.md) (status line first), [information-model-draft.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/contracts/information-model-draft.md), [transformation-semantics-draft.md](https://github.com/Marcus-Levin/hylja/blob/main/docs/contracts/transformation-semantics-draft.md), `docs/research/issue-65-taxonomy-draft-p0.1.md` and its source index/supplement.
- **Scope / non-goals:** in scope — review all 23 original criteria against existing evidence, following the existing independent lead/reviewer/conflict records and exact-revision review pointers; a **non-adopting review of the #68 draft may occur now**. Out of scope — authoring further drafts, implementing into classification v1/policy/adapters, changing accepted decisions 001–009, or treating a `proposed` record as settled.
- **Still-open obligations beyond the human decision:** #65's partial PII coverage and source gaps; #66's unresolved dimension questions (where fidelity lives, escalation DoS bound, digest/binding fields); #68's required #43 evidence and final adoption, which remain **separately pending** rather than delivered by this review. Task-owned fidelity is an existing provisional preference to challenge, not an unanswered sponsor question.
- **Verification:** prose-only — no build, no `npm test`; `npm run check:docs` only for tracked relative Markdown links.
- **Mapping status:** preliminary; human acceptance is not the sole outstanding deliverable.

---

## Preserved criteria mapping — PRELIMINARY

All criteria below stay verbatim on their live issue URLs; nothing is re-ticked or deleted. This table proposes where a criterion would live under each plan. **It is not a complete criterion → owner → observable proof mapping**, and no claim of "all criteria mapped" is made.

| Original criteria (count from live body) | Status | Proposed home |
|---|---|---|
| #39's 10 acceptance boxes + objective/scope/ground-truth/freeze/metrics/fixture/sequencing paragraphs | Preserved verbatim on the issue | Parent #39; children 1–3 extend and reconcile (owner assignment preliminary) |
| #39's independent oracle, blind custody, structurally independent held-out families, accepted #65/#66 vocabulary, approved scope, destination treatments, task/rubric, scoring/critical gates, full hash coverage, #38 link, freeze-before-tuning | Preserved as requirements | B2 child 3 (human gate) — owner proposed, proof not supplied |
| #48's 7 acceptance boxes + all 16 subsystems + 9 decision-quality fields + flow trace + differentiation + reconciliation range | Preserved verbatim | Parent #48; children 1–3 |
| #47's 5 items, 3 checked (data boundaries, public terms, gap analysis) | Preserved; 2 remain unchecked | Unchanged on #47 |
| #36's every `[x]`/`[ ]` value and closure-only sentences | Preserved byte-identical | Unchanged on #36; B1 is prose only |
| #36 "Shared requirements" | Not deleted, not relocated into `AGENTS.md` alone | Duplicated prose prunable only if the per-issue threat/attack-surface obligation is retained or linked to `docs/threat-model.md#threat-model-outputs` |
| #37's 5 acceptance boxes, incl. pending downstream egress evidence | Preserved, unchecked | Unchanged on #37; egress evidence pending, not a standing prerequisite |
| #40's 9 base + 6 additional comparison requirements | Preserved; Presidio **and** Privacy Filter scored arms pending | Unchanged on #40 |
| #65/#66/#68's 8/7/8 criteria | Preserved verbatim | Unchanged; B4 reviews them against evidence |
| Decision 010 `proposed`; decisions 001–009 accepted | Unchanged | Unchanged |

## Honest limits

Navigation: [README.md](README.md) (outcome and reading order), [e2e-critical-path.md](e2e-critical-path.md) (M1/M2/M3 briefs and the **PRELIMINARY / NOT READY** criteria mapping), [core-issues.md](core-issues.md) (the other 21 rows).

- **No new audit was performed.** This document applies corrections from the independent source review (`backlog-review-report.md`) to this group's proposals. No source re-reading, browsing, tests, build, CI, historical logs, SDK or repository search.
- Items the review could not settle, flagged **unverified**: availability of the independent blind custodian (#39), the signing/custody owner (#33), trial access (#47), and external role/access availability.
- "Effect prerequisites" above means a named scope that must exist before an *effect* (enforcement, egress, scored result) is claimable. It does **not** define every blocker by module absence; pre-vault synthetic invariant tests are permitted by `docs/evaluation.md`.
- Vendor, harness and identity choices (#16/#17/#25/#28) are **open questions**, not newly mandatory adoption gates on preparatory units. Required authentication still gates effects; an injectable or signed test assertion proves no real authentication.
- `test/<name>` references are **templates**, not executable checks. Build runs before compiled-module tests; prose-only edits need neither.
- This is not a runtime audit or human design approval. All product work stays paused.