# Backlog proposals, 2026-10-04

**Proposal only, dated 2026-10-04** against repo `main` at `2e88ca065473f8c7020a7a0e66b0f465e0f95f07`. Not a status tracker, and it goes stale. Product implementation is paused while the development pipeline is fixed; pipeline preparation remains current work and the prioritization below is for the **next phase**. No issue is satisfied, closed or re-ticked here, and no live status or checkmark is edited.

Authority homes stay put: [docs/capabilities.md](../../../capabilities.md) owns what is implemented and its limits; live GitHub issues own acceptance criteria, status and priority; dated measurements live with the record that produced them.

## Read these three

- [e2e-critical-path.md](e2e-critical-path.md) — the compact dependency table, the executable-preparation brief, and the preservation/ownership/gates table for the first runnable synthetic end-to-end path.
- [core-issues.md](core-issues.md) — 21 audited rows: #8, #11, #13–#29, #88, #114, #147.
- [roadmap-issues.md](roadmap-issues.md) — 22 audited rows: #30–#48, #65, #66, #68.

All **43** audited rows are preserved with their original acceptance checkbox values, adversarial paragraphs, narrative security obligations and checked marks unchanged at their live issue URLs.

## What the critical path aims at

Three stages matching the charter's slices, all **planned — not implemented and not runnable today**: M1 irreversible-only text cloaking ([slice 1](../../../specs/slice-1-text-cloaking-proof.md)), M2 encrypted scoped reversibility ([slice 2](../../../specs/slice-2-vault-and-reversible-identities.md)), M3 a local OpenAI-compatible gateway with an authorized round-trip ([slice 3](../../../specs/slice-3-openai-compatible-gateway.md)). Public synthetic **development** E2E tests can be specified and written now; a *passing* integrated cloaking path additionally needs actual MVP implementation and the applicable accepted semantics. None of this is a production or held-out release claim.

Invariants the path never trades away: secret and credential irreversibility, USE ≠ DISPLAY ≠ EXPORT, cross-tenant isolation, the final serialized body-and-metadata check with no unchecked chunk after it, authenticated actual-sink binding, conservative inbound until [#22](https://github.com/Marcus-Levin/hylja/issues/22), audit correlation without raw payloads, expiry/revocation denial, and model-fabricated token denial.

## What is not a prerequisite

[#65](https://github.com/Marcus-Levin/hylja/issues/65)/[#66](https://github.com/Marcus-Levin/hylja/issues/66)/[#68](https://github.com/Marcus-Levin/hylja/issues/68) and [decision 010](../../../decisions/010-separate-information-dimensions-and-task-fidelity.md) remain an explicit human-adoption dependency for the treatment and overlap semantics integrated [#13](https://github.com/Marcus-Levin/hylja/issues/13) requires. Editorial [#88](https://github.com/Marcus-Levin/hylja/issues/88)/[#36](https://github.com/Marcus-Levin/hylja/issues/36) maintenance and the comparative/commercial campaigns are not first-E2E prerequisites; all of them keep their own adoption and release scopes. [#39](https://github.com/Marcus-Levin/hylja/issues/39) gates scored/held-out and associated release claims, not public development E2E.

## Verification of this revision

`git diff --check` (clean) and `npm run check:docs` (ok). No build, no full test suite, no network or source re-audit; this is a prose-only change.
