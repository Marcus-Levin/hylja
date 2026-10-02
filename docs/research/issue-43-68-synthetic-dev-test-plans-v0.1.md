# Synthetic development-only test plans v0.1 — fidelity, credential presence, re-identification, USE authorization

**Prepared 2026-10-01 (UTC) for [#43](https://github.com/Marcus-Levin/hylja/issues/43), [#68](https://github.com/Marcus-Levin/hylja/issues/68), [#12](https://github.com/Marcus-Levin/hylja/issues/12)/[#66](https://github.com/Marcus-Levin/hylja/issues/66) and [#17](https://github.com/Marcus-Levin/hylja/issues/17). Plans only — nothing here is implemented, executed, scored or approved.**

Companions: the [role/surface dossier](issue-38-48-role-surface-conformance-dossier-v0.1.md), the [reconciliation table](issue-38-48-affected-issue-reconciliation-v0.1.md), the [#39 open-gates packet](issue-39-v0-open-gates-p0.1.md) and the [public rubric](issue-39-public-rubric-p0.1.md).

## 0. Boundaries these plans deliberately respect

* **Development-only.** These are *public, synthetic, non-scored* plans for the existing non-enforcing [#5](https://github.com/Marcus-Levin/hylja/issues/5) evaluation seam and the existing pure modules. They are **not** blind seeds, not a new corpus, and not a parallel harness: **no new blind material, no new runner, no new scoring path.** Anything scored stays behind the existing [#39](https://github.com/Marcus-Levin/hylja/issues/39) freeze and blind custody.
* **No tuning against held-out data.** Nothing here reads blind payloads, labels, answers, seeds, keys, hashes or store locations, and nothing here may be back-propagated into held-out expectations.
* **Synthetic and non-routable only.** Every planted value is generated in-process or written to `.invalid` names, `example.com`/`example.invalid` hosts, documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and RFC-reserved style tokens. No real-looking hostname, customer, employee, credential, session or secret is ever created, committed or logged.
* **Ground truth is evaluator-side.** Planted originals live in the test harness only. Reports, diffs, captured bytes and telemetry are treated as sensitive synthetic test artifacts and are never written to the repository.
* **No authority.** A test here can show a seam behaves as coded. It cannot grant release, authorize egress, prove a vault, or satisfy any human gate. Semantic evidence never authorizes an effect.
* **Not yet runnable in full.** Each plan names the pure module it currently *could* exercise and the runtime pieces that do not exist yet. Until those exist, the honest state is `untested`, not pass.

---

## Plan A — Engineering fidelity and safe restoration (#43 → #68)

**Question.** Can an agent complete the task from the protected representation, and can a generated change be restored back without touching an unintended value?

**Dev-only cases (synthetic, in-process).** A log diagnosis where an attempted HTTPS port must remain distinguishable from the expected alternate port and from a documented path; a JSON/YAML/`dotenv` edit that must stay schema- and reference-valid; a PowerShell/Bash/Python script edit carrying synthetic hosts, paths, accounts and URLs; one canonical entity reachable through several aliases; and one deliberately ambiguous case where the *same string* denotes two different entities.

**Properties, each stated as an assertion that must fail on a counterexample.**

1. Whole-task correctness is graded, not entity detection. A change that removes the protected value but breaks the task is a **fail**, and an unchanged task is not a pass by default.
2. Container validity: JSON, YAML and `dotenv` remain syntactically valid and key-complete after transformation; a transformation that repairs validity by dropping a key is recorded as a fidelity violation.
3. Exact intended restoration: every restored value matches the intended entity **and** nothing else changed. Assert on a whole-output diff, not only the restored span.
4. **Wrong-entity restoration** is an explicit negative: an alias of entity B appearing where entity A was intended must not resolve.
5. **Unsafe global replacement** is an explicit negative: a value that legitimately appears as a non-protected token in another field must not be rewritten.
6. Relationship preservation: repeated references to one entity resolve consistently after restoration, and references between two entities do not merge.
7. Reasoning effects: run the same task with protected and synthetic values and compare the produced change structure; record differences as a utility observation, not as an automatic failure.
8. Representation contract: a *typed non-reversible placeholder* that preserves only kind/shape must never be presented as an exact restoration.

**Runnable today:** parts of 3–6 as pure transformations over in-memory strings, if and when #13 exists. **Blocked:** the agent arm, the whole-task grader, and any comparison against a candidate.

---

## Plan B — Credential presence versus credential meaning (#43, #13, #68)

**Question.** Can a transformation preserve *approved non-secret semantics* — presence, kind, format family, length class, where-used — without ever creating a reversible alias for the secret itself?

**Dev-only cases.** A planted synthetic token in a config key, in an auth header, in a URL userinfo slot, in a log line and in a shell command. For each, three separately graded variants: (i) the credential is **present**, (ii) the credential is **absent**, and (iii) the credential is **present but malformed/expired-shaped**. The distinction matters: a consumer that branches on credential presence must be able to tell (i) from (ii).

**Properties.**

1. No treatment may produce a **reversible** representation of a SECRET/credential value. There is no token, hash-with-known-input, keyed fingerprint or reversible encoding that reconstructs the original. A deterministic masked shape is permitted only because it is irreversible by construction.
2. Irreversibility is asserted by construction *and* by negative test: the released bytes must not be derivable back to the original by any transform in the plan's catalogue, and the vault must hold no mapping row for that value.
3. Presence semantics survive where policy allows: after release, a consumer can still distinguish present / absent / malformed and can still locate *where* the value belonged.
4. Format family may be preserved (for example "a bearer token was configured here") but **not** its entropy shape to the point of being a usable credential, and never its prefix/suffix that would identify the real provider account.
5. Metadata, provenance, errors, traces and audit evidence must not leak the planted original either — including a length that is unique among the corpus.
6. A blocked secret is terminal for that flow: it is not restorable, and a later "uncloak" attempt must fail safely and be recorded without the original.
7. A denied flow must put **zero bytes** at the controlled sink.

**Runnable today:** none end-to-end. **Blocked:** #13 transformation, #19 exact-byte release check, and any real sink.

---

## Plan C — Contextual re-identification, advisory only (#12, #66)

**Question.** After direct identifiers are replaced, can the *remaining combination* of facts still single out a customer, person, site or project?

**Dev-only cases.** Synthetic sanitized payloads where the residual facts are individually generic but jointly rare: a country/region qualifier, a coarse month, an unusual process or equipment stage, a project code fragment, a product-version string, and a rare combination of several of these. Include deliberate negative controls — combinations that are common and therefore identifying to nobody.

**Properties.**

1. The signal is **advisory only**. No case in this plan may select `KEEP`, `MASK`, `BLOCK`, a treatment, a generalization strength or any release, and no case may raise trust or lower sensitivity. Promotion to a policy input requires a separate reviewed decision.
2. Precision/recall is measured as *true/false re-identification flags* against planted synthetic ground truth, reported separately from any candidate-detection metric.
3. Direct-identifier replacement alone is never treated as sufficient: a case can pass candidate detection and still fail this plan.
4. The judge request is itself protected egress. In any external-judge variant, the request must be minimized to quasi-identifier *structure*, must be authorized against the judge's own destination profile, and must pass a #19-style exact-byte check of the serialized request before send. If minimization or verification cannot be established, **the external judge is skipped** and the deterministic/local path decides.
5. Outage, abstention or an unparseable judge answer must never reduce restriction — it may only escalate to review or deny.
6. Ground-truth combinations are never placed in the repository; the plan generates them in-process.

**Runnable today:** nothing. **Blocked:** #11 judge destination authorization, #12 question set, and any external judge at all.

---

## Plan D — USE authorization without reveal (#17, #44, #14–#16)

**Question.** Can a trusted local operation use a real original **without** the caller ever receiving plaintext, while an unauthorized caller gets nothing?

**Dev-only cases.** Two synthetic tenants, two synthetic projects each, one shared synthetic identity name deliberately reused across tenants, one synthetic host that appears in both, one expired mapping and one revoked mapping. A synthetic trusted local tool stands in for the trusted effect; a synthetic caller stands in for an ordinary agent.

**Properties.**

1. **USE returns no plaintext.** The trusted local operation receives the value only inside the effect; the caller's response must contain no substring of the original — asserted on the whole serialized response, not on the obvious field.
2. USE does not imply DISPLAY, and DISPLAY does not imply EXPORT. Each is a separate operation with its own decision, and each denial is an explicit negative case.
3. Cross-tenant isolation: tenant A's token, ciphertext, mapping row, cache entry or synthetic identity must not resolve under tenant B **even when an exception policy is supplied**. A shared display name across tenants must still map to two different synthetic values.
4. Forged, unknown and synthetic-looking tokens fail safely and are recorded without the original.
5. Expired and revoked mappings do not resolve; stale replayed material does not resolve.
6. Bulk enumeration is resisted: sequential, random and wide-search token resolution is rate-limited and purpose-bound, and **no bulk plaintext lookup interface exists** in the design under test.
7. Mapping swap/confusion: substituting ciphertext or metadata so that synthetic entity A resolves to original B must fail.
8. Failure behaviour: if vault, KMS or authorization is unavailable, the result is **no uncloak** — never a plaintext fallback and never a partially revealed value.
9. Audit evidence for allow, deny and failed resolution contains only opaque references, never an original.
10. Authorization binds authenticated subject/workload, tenant/project, purpose, session, operation and the **actual** trusted destination. A caller able to fabricate that context has fabricated authority — so the test asserts the context is supplied by the trusted integration and is not read from request payload, headers, model output or launcher flags.

**Runnable today:** parts of 3–6 as pure contract assertions against a synthetic authorization double, mirroring the existing strict-double/loose-double split — but **no vault, key, cache or broker exists**, so 1, 7, 8 and any real storage claim are `untested`. **Blocked:** #15, #16 and #17. (#20 is closed at its bounded non-enforcing ledger scope, which supplies no broker-produced events yet; its event producers arrive with #17/#18 and are not a reason to reopen it.)

---

## Cross-cutting rules for all four plans

* Every plan must be replayable against a versioned, pinned configuration, and every observation must record provenance separately from observed outcome.
* A denied or failed case that is not captured at the actual controlled sink is **unobserved**, never a pass.
* Any candidate arm is compared only on matched pinned configurations; an unexecuted arm has **no observed outcome** and is reported as such.
* Human gates (#65, #66, #68, #39 freeze, blind custody) are prerequisites for anything scored. These plans deliberately stop at the edge of scoring.
