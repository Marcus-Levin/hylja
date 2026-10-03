# #40 matched, unscored public-development comparison: native baseline vs pinned Presidio vs their union

**Dated research evidence, 2026-10-02. Corrected and re-run on 2026-10-02 after an independent review
returned REQUEST_CHANGES for `b3af062a`; section 1 and section 8 record what that review changed and
what it superseded. Not a benchmark, not a score, not #39 v0, not a freeze, not a held-out result, not
an adoption decision and not a #40 closure.** Implementation and run status live only in
[the plan](../plan.md#current-state); this document separates what was **measured**, what is a
**source claim** and what remains an **explicit unknown**. The full issue text is
[#40](https://github.com/Marcus-Levin/hylja/issues/40); the reuse question it feeds is
[#48](https://github.com/Marcus-Levin/hylja/issues/48)'s, and any scored comparison still requires
#39's frozen protocol.

The runner is [`evaluations/matched-development-comparison.mjs`](../../evaluations/matched-development-comparison.mjs);
the pre-execution screen verifier is
[`evaluations/presidio-worker/verify_selected_runtime.py`](../../evaluations/presidio-worker/verify_selected_runtime.py);
the deterministic evidence is
[`test/matched-development-comparison.test.mjs`](../../test/matched-development-comparison.test.mjs).
It reuses the #113 owners rather than re-implementing them: the Presidio arm is
`runPresidioDevelopmentArm`, extracted from `evaluations/presidio-development-trial.mjs` with the
trial's printed record **byte-identical before and after** the extraction; the native arm is #6's own
`detectNormalizedCandidates`; the scoring owner is `src/evaluation.ts` (#5). Nothing in `src/` changed.

---

## 0. Corrections to the first run of this document (superseded, not deleted)

The first version of this document was measured on `/tmp/hylja113/worker-venv` and published at
`b3af062a`. An independent review of that exact head returned REQUEST_CHANGES with three blockers.
This section records what was wrong; the corrected sections that follow replace the affected claims.
The first run's numbers are **superseded**, not re-labelled conformant.

| Was claimed at `b3af062a` | What is true | Where |
| --- | --- | --- |
| "**50 of 51** present and byte-identical" and the 51st, `zipp 3.23.0`, is absent from the local cache | **All 51 pinned digests are present.** The wheel cached as `setuptools-84.0.0-py3-none-any.whl` has digest `51a52592…`, size 818216 and 343 members, which are exactly the `zipp 3.23.0` record's | §1 |
| "The extra local wheel … `setuptools 84.0.0` … is screened by neither the manifest nor the #46 record" | Its bytes **are** inside the screened digest set, recorded under a name that does not correspond to the artifact. The defect is a **name/digest mismatch in one screen record**, not an unscreened extra | §1 |
| "Neither changes what runs: neither is imported by the analyzer" | True of an import and irrelevant to the question. `setuptools` installs `distutils-precedence.pth`, whose `import …` line `site` **executes at interpreter startup**, and both sandbox wrappers run the venv interpreter without `-S` and with `SETUPTOOLS_USE_DISTUTILS` absent, so the hook ran on **every** worker start | §1 |
| "4 877 installed library files … 13 further entries are pip-generated console scripts" | Not reproducible and incomplete. The prior venv holds **9 586 files**, of which **5 027 are not members of any selected wheel**, **52 distributions** (the 50 plus `pip` and `setuptools`), **1 `.pth` hook** and **4 146 byte-compiled entries** | §1 |
| "`falsePositives` … includes … detections of values that were never planted, so it is an **over-generation** count" and a `Precision` column | The stated definition is false for the incomplete control set that was used: several "false positives" were **exact-span, exact-label detections of occurrences the independent oracle plants** and the controls did not name. The precision column implied a measurement it was not | §3, §4 |
| "…and `control-6` … are misses **for Presidio alone** … **The native arm finds all three**" | Contradicted by the same run's own record. There is **no native candidate at the planted port's span at all**; the earlier `LABEL_MATCH_SPAN_MISMATCH` verdict came only from a *different* value carrying the same label elsewhere in the field | §4.2 |
| "fragments such as the `example.in` / `persona.de` parts of a synthetic `.invalid` mailbox" | No `persona` and no `.de` string exists anywhere in the public fixtures. The example was invented. It is also wrong in the #113 document, which is corrected there | §4.3, §8 |
| "`PORT` candidates for `:443` and `:12`" | The measured spans cover only the digits, with no leading colon | §4.3 |

### 0.1 Second correction round (independent review of `f0d8e1f`)

The second review of the corrected head returned REQUEST_CHANGES with one blocker and four non-blocking
findings, all in the **new untrusted-boundary code** rather than in the measurement. All are fixed here,
and **no measured number in §4 changes** — the review independently reproduced them. What changed is the
verifier's own boundary: the helper's `status` is now derived by the bridge from the checks it accepted
and a disagreement is refused (B1); a helper refusal carries its own fixed cause instead of collapsing to
one shape rejection (M1); a **symlink** in the runtime is counted and refused rather than skipped, and
the per-file hash is read in bounded chunks (M2); the name-identity and screen-coverage checks are one
check whose `ok` is computed from two counters, so `ok` and `code` can never disagree (M3); and the
README names the limit it actually emits (M4).

### 0.2 Third correction round (independent review of `8883971`)

The third review of the corrected head returned REQUEST_CHANGES with one blocker and four notes, again
all in the **verification boundary** and none in the measurement. All are fixed here and **no measured
number in §4 changes** — the review independently reproduced them from the public fixtures, and the
corrected run after these fixes is identical to the one before them apart from wall clock.

The blocker was the same defect class the previous round removed, one path over: `RUNTIME_FILE_PROVENANCE`
could report `ok: false` with `code: null`, because the check was the conjunction of six conditions while
the code ladder named only two. A file the verifier cannot read is a genuine runtime defect — a module
Python can import whose provenance cannot be established — and the record reported that as
`VERIFICATION_OUTPUT_SHAPE_REJECTED`, sending a reader to the protocol instead of to the runtime. Every
cause now has its own fixed code, chosen by a documented priority and counted in the detail whichever is
chosen: `NON_REGULAR_RUNTIME_ENTRY`, `RUNTIME_ENTRY_UNREADABLE`,
`RUNTIME_FILE_TOO_LARGE_TO_COMPARE`, `RUNTIME_SCAN_TRUNCATED`, `RUNTIME_FILE_NOT_IN_SELECTED_WHEELS`,
`RUNTIME_SELECTED_FILE_MISSING`. The non-blocking notes are fixed in the same seam: a pin record naming an
artifact that cannot identify itself is now reported by its own cause
(`ARTIFACT_OWNS_NO_SINGLE_TOP_LEVEL_DIST_INFO`) instead of collapsing the reply; the helper's previously
dead `PIN_CHECKS` constant is **wired** into a completeness check on its own check list rather than
deleted; the non-regular regression now covers a **symlinked directory and a FIFO** as well as a symlinked
file; and a duplicated sentence in this repository's plan is removed.

---

## 1. Pre-execution verification of the selected runtime (the corrected account)

Nothing was executed before the pin was re-verified from what was already on this host, and the
verification is now a committed, re-runnable program rather than a prose claim. All of it is offline;
no package was downloaded, installed, updated or re-screened for this run.

```
# 1. name identity + screen coverage + runtime identity, all from files on this host
python3 evaluations/presidio-worker/verify_selected_runtime.py \
  evaluations/presidio-worker/manifest.json <wheel-dir> <screen-report.json> <site-packages-dir>
```

The verifier imports nothing from the environment it verifies, executes no code from it, keeps no file
content (every comparison is on a digest) and prints one JSON line of counts and fixed codes. The
comparison bridge runs it on the **host** with a plain interpreter — not with the worker's sandbox
wrapper, which cannot see the wheel directory or the candidate runtime — and treats its stdout as
untrusted content: every field is re-derived from a closed vocabulary in
`verificationRecord()` and anything else is refused.

### 1.1 What the pinned record set actually is

| Check | Result |
| --- | --- |
| Manifest artifact records | 51, each with a SHA-256, a size, `yanked: false`, 0 advisories |
| `PINNED_DIGESTS_PRESENT` | **51 of 51 digests present** in the cached wheel directory |
| `SELECTED_ARTIFACTS_NAME_AND_SCREEN_VERIFIED` | **50 selected, 1 excluded**, and all **50** selected artifacts have a `#46` screen record under their **own** normalized name, `OK`, not yanked, advisory-free, with the same observed digest; the screen report is **51 records / 51 `OK` / 0 yanked / 0 advisories**, 14 with native code, 28 without a PEP 639 `License-Expression`. The excluded record is the `zipp 3.23.0` one: its digest, size and member count are those of **`setuptools 84.0.0`**, whose own top-level `METADATA` declares `Name: setuptools, Version: 84.0.0`. No `zipp` artifact exists on this host; `zipp 3.23.0` appears only as a **vendored** copy inside that wheel (`setuptools/_vendor/zipp-3.23.0.dist-info`). Reading a vendored `METADATA` instead of the wheel's own would have made this check agree with itself. One check covers both halves — name identity and screen coverage — so its `ok` is computed from two counters and can never report a pass beside a failure code |
| `PINNED_RECORDS_ALL_RESOLVED` | **`ok: false`** — reported as its own check precisely so that the superseded full-stack claim stays visible while the executed subset can still be verified |

**The honest statement about the prior screen is therefore:** the `#46` screen is a complete
**digest** set, and one of its 51 records names a package the bytes are not. It is not a "51-artifact
runtime" in any sense a reader could act on, and no earlier claim in this repository that it was is
adopted here. `evaluations/presidio-worker/manifest.json` carries this as a dated `corrections[]`
entry; **the `zipp` record itself is preserved unchanged** as the historical pin and is *excluded*
rather than deleted or silently renamed.

The screen was **not re-run** — it needs live OSV queries — and the committed
`scripts/research/prescreen_pypi_artifacts.py` is a later revision than the reviewed git object the
manifest names, so the screen's own records are prior approved evidence, not a fresh result here.

### 1.2 The startup-hook question, answered

`setuptools 84.0.0` ships `distutils-precedence.pth` containing a single line beginning `import`.
CPython's `site` module `exec()`s any `.pth` line that begins `import `, at interpreter startup, before
the program runs. The prior sandbox wrapper ran the venv interpreter (which is the system Python, `site`
on) with `--clearenv` and an explicit `--setenv` list that does **not** set
`SETUPTOOLS_USE_DISTUTILS`, so `os.environ.get(var, 'local') == 'local'` was true and
`_distutils_hack.add_shim()` inserted a `sys.meta_path` finder on **every one of the five worker process
starts** per run. Absence of an analyzer import was never evidence about this.

Confirmed as interpreter semantics in an **owned disposable venv** that created and removed its own
synthetic `.pth` (no third-party code executed):

| Interpreter start | The `import` line in a `.pth` ran |
| --- | --- |
| default, variable absent | **yes** |
| `SETUPTOOLS_USE_DISTUTILS=stdlib` | yes (the line is exec'd; only `add_shim()` is suppressed) |
| `SETUPTOOLS_USE_DISTUTILS=local` | yes |
| `-S` | **no** — `.pth` processing is suppressed entirely |

### 1.3 The corrected runtime

The corrected run executes a **fresh, owned 50-artifact runtime** built without any installer code:

| Check | Result on `/tmp/hylja140b/venv` |
| --- | --- |
| Construction | `python3 -m venv --without-pip`, then the 50 selected wheels' members extracted with the Python standard library only. **No installer of any kind ran**, nothing was downloaded, and `pip` and `setuptools` are therefore **absent** |
| `RUNTIME_FILE_PROVENANCE` | **4 609 installed files, 4 609 byte-verified** against their wheel members, 0 foreign, 0 missing, 0 too large to compare, **0 non-regular entries, 0 unreadable, no truncation** — a symlink, a FIFO or an unreadable file would each be refused and named |
| `RUNTIME_DISTRIBUTION_SET` | **50 distributions installed, 50 selected, 0 unexpected, 0 missing** |
| `RUNTIME_STARTUP_HOOKS` | **0 `.pth` files, 0 byte-compiled entries** — so there is no startup hook to execute |
| `DECLARED_EXECUTED_SUBSET` | the manifest's declared subset (**50**) equals the verified selection (**50**) |
| Overall | `VERIFIED_WITH_EXCLUSIONS` — the executed subset is verified; one **pin** record remains excluded and is listed |

**The status is derived, never asserted, twice.** The helper computes its own `status` from the
executed-subset checks, and the bridge then **re-derives it from the checks it accepted** and refuses a
reply whose declared status disagrees — so a helper that claimed `VERIFIED` beside a failing
`RUNTIME_STARTUP_HOOKS` would be recorded as no verification at all, not as a verified one. The record's
`executionEnvironment` carries the accepted checks, each with its own `ok` and code, so a reader sees
which check passed and that `PINNED_RECORDS_ALL_RESOLVED` is deliberately not ok in a verified run
instead of having to infer it from a green status. A helper refusal reports its own fixed cause
(`MANIFEST_OR_SCREEN_UNREADABLE`, `WHEEL_DIRECTORY_UNREADABLE`,
`RUNTIME_SITE_PACKAGES_NOT_A_DIRECTORY`, `MANIFEST_ARTIFACT_RECORDS`, …), and that code is carried into
the record rather than collapsed into one shape rejection.

The same verifier pointed at the **prior** `/tmp/hylja113/worker-venv` returns `MISMATCH` and
independently reproduces the reviewer's inventory: 9 586 installed files, 5 027 not from a selected
wheel, 52 distributions (2 unexpected), 1 `.pth` hook, 4 146 byte-compiled entries. That environment was
**read only** and was not executed; `/tmp/hylja113` was not mutated.

**What is still not screened.** `#46`'s screen is published-digest agreement plus license/advisory
metadata and an OSV version query: not signature verification, not an authenticated publisher
conclusion, not a transitive or maintenance review, not an adoption decision. 28 of the 51 wheels declare
no PEP 639 `License-Expression`. The new name-identity check is **not** a replacement for any of that; it
answers a question a digest-only screen cannot.

## 2. What was run, and with what identity

```
W=/tmp/hylja140b                      # fresh owned scratch; /tmp/hylja113 is read-only input, untouched
python3 -m venv --without-pip $W/venv # then the 50 selected wheel members, stdlib extraction
# $W/bwrap-python-140b: bwrap --unshare-all --clearenv, the venv read-only at /work, and the COMMITTED
# evaluations/presidio-worker directory read-only at /trial, so the worker opens the committed
# manifest and worker script byte-for-byte instead of a copy of them.
flock /tmp/hylja-agentic-campaign/test.lock \
  node evaluations/matched-development-comparison.mjs \
    --python $W/bwrap-python-140b --worker /trial/presidio_worker.py \
    --manifest evaluations/presidio-worker/manifest.json --worker-manifest /trial/manifest.json \
    --workdir $W --tenant tenant-synthetic-01 --project project-synthetic-01 \
    --verify-script evaluations/presidio-worker/verify_selected_runtime.py \
    --verify-manifest evaluations/presidio-worker/manifest.json \
    --wheels <wheel-dir> --screen <screen-report.json> --site-packages $W/venv/lib/python3.14/site-packages
```

Identity recorded by the run itself: protocol `hylja.presidio.worker` v1, mapping
`presidio-entity-map/1`, label vocabulary `presidio-label-vocabulary/1`, producer `presidio-analyzer`
`2_2_364` (`presidio-analyzer==2.2.364`), language `en`, `nerAvailable: false`, host manifest digest
`fec3650b8f8b2f05d1e509bdbda5299f902aaa39821f4221fff2e3816d3e6363`, execution environment
`VERIFIED_WITH_EXCLUSIONS / 50`. **No threshold, recognizer set, language, country filter, allow list,
context enhancer or NLP weight changed**, no new dependency was installed, no model was downloaded, and
the Privacy Filter was not installed, screened or run.

**Reproducibility:** two independent corrected runs produced **identical records apart from
wall-clock milliseconds**. Wall clock, this host, one-shot, one worker process per field, **5 worker
processes** per run: Presidio arm **2.21–2.39 s** for D01's one field and **8.74–10.24 s** for D02's four;
native arm **17–23 ms** per case. Those are process-spawn-and-import dominated, are not a latency SLA,
and no peak-RSS figure was re-measured (the #113 record's 119 MiB per worker process stands as that
author measurement). The corrected runtime is measurably **slower** per process than the first run's
(~1.1 s / ~4.1–4.8 s); the cause was not investigated and no claim is made about it.

## 3. The control set, and what an unmatched event now means

**15 controls**, declared in the script before any arm runs, read off the public fixture text and never
derived from candidate output. **Every scored label is a currently accepted v1 class/subtype** — nothing
from proposed decision 010 or the #65/#66/#68 drafts. The set is an extension of the earlier eight, and
the extension comes **only** from the independent `#39` public development oracle draft:

| Ref | Case / field | scored v1 label | group | declaration | oracle draft label |
| --- | --- | --- | --- | --- | --- |
| `control-1` | D01 / field-0 | `PERSON/NAME` | CONTACT | `#113` trial control | `PERSON.NAME` |
| `control-2` | D01 / field-0 | `PERSON/EMAIL` | CONTACT | `#113` trial control | `PERSON.EMAIL` |
| `control-3` | D01 / field-0 | `PERSON/PHONE` | CONTACT | `#113` trial control | `PERSON.PHONE` |
| `control-9` | D01 / field-0 | `PERSON/NAME` | CONTACT | oracle occurrence | `PERSON.NAME` |
| `control-10` | D01 / field-0 | `PERSON/EMAIL` | CONTACT | oracle occurrence | `PERSON.EMAIL` |
| `control-11` | D01 / field-0 | `CUSTOMER_OR_PARTNER` | BUSINESS | oracle occurrence | `CUSTOMER_OR_PARTNER.CUSTOMER_NAME` |
| `control-12` | D01 / field-0 | `PROJECT_OR_CONTRACT` | BUSINESS | oracle occurrence | `PROJECT_OR_CONTRACT.PROJECT_ID` |
| `control-4` | D02 / field-0 | `NETWORK_IDENTIFIER/IP` | ENGINEERING | `#113` trial control | `NETWORK_IDENTIFIER.IP` |
| `control-5` | D02 / field-0 | `HOST_OR_SERVICE` | ENGINEERING | `#113` trial control | `HOST_OR_SERVICE.HOSTNAME` |
| `control-13` | D02 / field-0 | `USER_ACCOUNT` | CONTACT | oracle occurrence | `USER_ACCOUNT.ACCOUNT_NAME` |
| `control-14` | D02 / field-0 | `APPLICATION_OR_ENVIRONMENT` | ENGINEERING | oracle occurrence | `APPLICATION_OR_ENVIRONMENT.CORRELATION_ID` |
| `control-8` | D02 / field-0 | `CREDENTIAL_OR_SECRET/ACCESS_TOKEN` (`SECRET`) | SECRET | comparison control | `CREDENTIAL_OR_SECRET.ACCESS_TOKEN` |
| `control-15` | D02 / field-1 | `HOST_OR_SERVICE` | ENGINEERING | oracle occurrence | `HOST_OR_SERVICE.HOSTNAME` |
| `control-6` | D02 / field-1 | `NETWORK_IDENTIFIER/PORT` | ENGINEERING | comparison control | – |
| `control-7` | D02 / field-1 | `NETWORK_IDENTIFIER/URL` | ENGINEERING | comparison control | – |

Three properties make this a set and not a list:

* **Every v1-admissible occurrence the oracle draft plants for these two cases is included.** The draft's
  own subtypes (`CUSTOMER_NAME`, `PROJECT_ID`, `HOSTNAME`, `ACCOUNT_NAME`, `CORRELATION_ID`) are carried
  as `oracleDraftLabel` cross-references only: v1 accepts none of them, so scoring against them would be
  scoring against draft taxonomy. The draft is development-only with **no scoring authority**.
* **Each oracle-derived control is bound to the oracle's own span.** `plantDevelopmentControl()` compares
  the computed span with the declared one and drops the control as
  `CONTROL_SPAN_DISAGREES_WITH_DECLARED_ORACLE_SPAN` if they differ, so the set cannot drift away from the
  independent source it claims to extend.
* **No control is dropped silently, ever.** A value that is absent, repeated, or whose field is missing
  is recorded as a named drop, and the run refuses to proceed if a declared control vanished without one.
  `droppedControls` was empty for both cases.

### 3.1 Why the earlier `falsePositives` column was wrong, and what replaces it

#5's `falsePositives` is `emitted events − events matched to a control`. That arithmetic is the owner's
and stays in the record, but on the earlier eight-control subset several of those events were **exact-span,
exact-label detections of occurrences the oracle plants** — the backup mailbox and the repeated host — so
the number was not a false-positive count and the derived `Precision` column implied a measurement it was
not. The correct reading is per event, and the record now carries it (`unmatchedByCategory`,
`unmatchedByCategoryAndLabel`):

| Category | Meaning |
| --- | --- |
| `DUPLICATE_OF_PLANTED_OCCURRENCE` | the same span and label as a planted occurrence, beyond the one already matched. A real detection the owner's arithmetic counts twice |
| `PLANTED_OCCURRENCE_LABEL_DIFFERS` | the exact span of a planted occurrence under a different label — a labelling disagreement, not a new value |
| `ORACLE_DECLARED_NEGATIVE_CONTRADICTED` | the event **overlaps** one of the oracle draft's `unplantedNegatives` whose `notA` list names this candidate's own accepted-v1 class. The **only** category that is an established error against an independent declaration |
| `UNRESOLVED` | everything else: neither a planted occurrence nor a declared error. **Not** a measured false positive |

The negative list is read from the committed oracle draft at run time (**9 negatives** for these two
cases), and only its **class** part is used, because a negative declares *specific* classes and not
that a span carries nothing: `N-f1409371f5` declares the HTTPS port `443` to be neither a phone nor a
credential and says nothing about `NETWORK_IDENTIFIER.PORT`, so a `PORT` candidate there stays
unresolved rather than being called an error. Overlap rather than span-equality is used because the
declaration covers a span and a candidate inside it contradicts it just as much as one equal to it.

## 4. Measured results

Per case, per arm, on the corrected runtime. `matched` is #5's own count; the per-control breakdown in
the record is checked against it and the run **throws rather than print** if the two ever disagree. The
`owner falsePositives` column is #5's arithmetic and is reported under its own name for traceability;
**it is not a precision measurement** and §3.1 says what each event in it actually is.

| Case | Arm | Events | Planted | Matched | Misses | owner `falsePositives` |
| --- | --- | --- | --- | --- | --- | --- |
| D01-DEV-001 | NATIVE | 5 | 7 | **3** | 4 | 2 |
| D01-DEV-001 | PRESIDIO | 5 | 7 | **1** | 6 | 4 |
| D01-DEV-001 | COMBINED | 9 | 7 | **3** | 4 | 6 |
| D02-DEV-001 | NATIVE | 9 | 8 | **5** | 3 | 4 |
| D02-DEV-001 | PRESIDIO | 5 | 8 | **1** | 7 | 4 |
| D02-DEV-001 | COMBINED | 12 | 8 | **5** | 3 | 7 |
| **total** | NATIVE | 14 | **15** | **8** | 7 | 6 |
| **total** | PRESIDIO | 10 | **15** | **2** | 13 | 8 |
| **total** | COMBINED | 21 | **15** | **8** | 7 | 13 |

### 4.1 Per subtype and per #37 requirement — never merged into one PERSON row

| Case | Arm | `PERSON/NAME` | `PERSON/EMAIL` | `PERSON/PHONE` | `NETWORK_IDENTIFIER/IP` | `HOST_OR_SERVICE` | `NETWORK_IDENTIFIER/PORT` | `NETWORK_IDENTIFIER/URL` | `CREDENTIAL_OR_SECRET/ACCESS_TOKEN` | `USER_ACCOUNT` | `APPLICATION_OR_ENVIRONMENT` | `CUSTOMER_OR_PARTNER` | `PROJECT_OR_CONTRACT` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| D01 | NATIVE | 0/2 | **2/2** | **1/1** | – | – | – | – | – | – | – | 0/1 | 0/1 |
| D01 | PRESIDIO | 0/2 | 0/2 | **1/1** | – | – | – | – | – | – | – | 0/1 | 0/1 |
| D01 | COMBINED | 0/2 | **2/2** | **1/1** | – | – | – | – | – | – | – | 0/1 | 0/1 |
| D02 | NATIVE | – | – | – | **1/1** | **2/2** | 0/1 | **1/1** | **1/1** | 0/1 | 0/1 | – | – |
| D02 | PRESIDIO | – | – | – | **1/1** | 0/2 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | – | – |
| D02 | COMBINED | – | – | – | **1/1** | **2/2** | 0/1 | **1/1** | **1/1** | 0/1 | 0/1 | – | – |

### 4.2 Critical false negatives, listed individually

The outcome vocabulary is narrow and states what was measured: `MATCHED`; `SPAN_COVERED_LABEL_DIFFERS`
(an event covers the control's exact span under a different label); `NO_CANDIDATE_AT_SPAN` (**no event
covers the control's span**). `sameLabelElsewhere` counts events on the same field carrying the
control's label at a *different* span; those are not candidates for this control, and reading them as
one is exactly how a missing generation turns into an apparent near miss.

* **`control-1` and `control-9` (`PERSON/NAME`) — a miss in all three arms.** The native arm is
  configured **by omission only**: no tenant name dictionary, no `#10` configured handle, no asserted
  `#7` format, because building a dictionary from the fixture's own planted names would be tuning a
  detector against the cases being measured. #37 finds NAME only through a tenant/project-scoped
  dictionary, so **NAME recall for a *configured* native deployment is not measured here.** Presidio
  cannot look for a name at all in this configuration. Neither is recovered by a judge, a sentinel or the
  union: `NO_CANDIDATE_AT_SPAN` in all three arms, which is the point.
* **`control-2` and `control-10` (`PERSON/EMAIL`) — a miss for Presidio alone.**
  `EmailRecognizer` requires `tldextract.extract(...).fqdn != ""`, and `.invalid` is not a public suffix,
  so both results are invalidated before the reply. The native pattern finds both.
* **`control-5` and `control-15` (`HOST_OR_SERVICE`), `control-8`
  (`CREDENTIAL_OR_SECRET/ACCESS_TOKEN`) — a miss for Presidio alone.** This configuration has no
  recognizer for a bare DNS name and no credential recognizer.
* **`control-6` (`NETWORK_IDENTIFIER/PORT`, the expected service port) — a miss for every arm, and it is
  missing candidate generation, not a span-level near miss.** There is **no** native candidate at that
  span. The native arm's only `PORT` events cover the digits of the *attempted* port in field-1 and a
  stack-frame line number in field-2; the record shows `NO_CANDIDATE_AT_SPAN` with `sameLabelElsewhere: 1`
  for this control, which is the honest verdict. Presidio finds neither value.
* **`control-7` (`NETWORK_IDENTIFIER/URL`) — matched by native and by the union, not by Presidio.**
  Presidio's URL event on that field has the right label at a **different** span
  (`NO_CANDIDATE_AT_SPAN`, `sameLabelElsewhere: 1`), so its URL recognizer did not reproduce the planted
  URL's extent. Whether it truncated the URL or extended past it cannot be told from a record that
  deliberately carries no span text; #113's separate measurement attributes Presidio's URL behaviour on
  these inputs to stopping at a TLD it recognises. A near miss is never counted as recall.
* **`control-11`, `control-12`, `control-13`, `control-14` — a miss for every arm.** The customer,
  project, operator account and correlation id need #10's tenant-scoped configured sources, which the
  unconfigured native arm does not run, and this Presidio configuration has no recognizer for them. This
  is a measurement of an **unconfigured** baseline and says nothing about a configured one.

### 4.3 Over-generation, classified rather than summed

| Case | Arm | matched | owner's count | what those events actually are |
| --- | --- | --- | --- | --- |
| D01 | NATIVE | 3/7 | 2 | 2 × `UNRESOLVED:HOST_OR_SERVICE` |
| D01 | PRESIDIO | 1/7 | 4 | 4 × `UNRESOLVED:NETWORK_IDENTIFIER/URL` |
| D01 | COMBINED | 3/7 | 6 | the same 2 + the same 4 |
| D02 | NATIVE | 5/8 | 4 | 1 × `DUPLICATE_OF_PLANTED_OCCURRENCE:CREDENTIAL_OR_SECRET/ACCESS_TOKEN`, 1 × `ORACLE_DECLARED_NEGATIVE_CONTRADICTED:HOST_OR_SERVICE`, 2 × `UNRESOLVED:NETWORK_IDENTIFIER/PORT` |
| D02 | PRESIDIO | 1/8 | 4 | 4 × `UNRESOLVED:NETWORK_IDENTIFIER/URL` |
| D02 | COMBINED | 5/8 | 7 | the same 7, the duplicate folded away by the union |

So across the whole corrected run there is **exactly one established error**: the native arm's
`HOST_OR_SERVICE` candidate inside the log's stack-frame span, which the oracle draft declares unplanted
with `HOST_OR_SERVICE.HOSTNAME` in its `notA` list. Everything else is either a duplicate, a resolved
label disagreement, or **unresolved** — and unresolved is not a false positive, it is the absence of an
independent declaration about that span.

Which substrings the `UNRESOLVED` events cover is **not established here**: the record deliberately
carries no span text, and the earlier document's example fragments (`example.in`, `persona.de`) were
invented — `persona` and `.de` appear nowhere in the public fixtures. The two native `HOST_OR_SERVICE`
events in D01 sit inside the two synthetic `.invalid` mailboxes' domain parts and the two `PORT` events
cover digits, but that is a reading of the fixture, not a measurement of the run.

### 4.4 What combining added, and what it removed

| Case | Union events | Identical in both arms | Native only | Presidio only | Distinct native keys | Native emitted | Intra-arm duplicates |
| --- | --- | --- | --- | --- | --- | --- | --- |
| D01 | 9 | 1 | 4 | 4 | 5 | 5 | native 0, presidio 0 |
| D02 | 12 | 1 | 7 | 4 | 8 | 9 | native 1, presidio 0 |

On these 15 controls, adding the pinned Presidio configuration to the native baseline **added no
control recall** (8/15 native, 8/15 combined) and **added 8 unmatched events** (D01 +4, D02 +4), every
one of them `UNRESOLVED`. The union also folds events away, and the record now names the two different
reasons separately, because the earlier single `duplicateEventsRemoved` figure conflated them: **1**
cross-arm identical event per case (`identicalToBothArms`), and in D02 **1** intra-arm duplicate from two
`#6` rules matching one occurrence.

The union is a **measurement-only event set**. It applies no policy, resolves no mapping, composes no
classification and merges no overlapping spans. A production merge belongs to #13/#114, and #114's
vendor-independent evidence-to-rewrite overlap contract is required whichever reuse option is eventually
selected; a candidate source that misses a finding cannot have that miss restored by any composition.

### 4.5 Upstream filtering, deduplication and coverage limits

The Presidio arm is `PARTIAL` on both cases with reasons `['NO_NER_CAPABILITY']` and the limitation set
exactly `NO_NER`, `NO_TEXT_CONTEXT`, `POST_FILTER_REPLY_ONLY`, `UPSTREAM_DUPLICATE_SUPPRESSION`,
`UPSTREAM_SCORE_THRESHOLD` — identical to the recorded #113 run. These describe evidence this boundary
**cannot observe**: recognizer output before per-entity thresholds and deduplication, allow-list removal,
context enhancement, and anything an NER-capable engine would have contributed. The `US_SSN`
recognizer's weak patterns are dropped by Presidio's own threshold before the reply, which is the
concrete instance of `UPSTREAM_SCORE_THRESHOLD`. Inexact placements, declared unsupported types, unpinned
unsupported results and unpinned labels were **0** for both cases.

`UPSTREAM_ALLOW_LIST` and `UPSTREAM_CONTEXT_ENHANCEMENT` are **not** in this run's set because the
pinned configuration has an empty allow list and no text context. That means the pinned profile does
**not** exercise the case #40 asks about — whether an upstream allow list or a high-scoring competing
finding can suppress native SECRET protection. The composition side is covered deterministically in the
committed suite instead: with an allow list reported by the adapter, `UPSTREAM_ALLOW_LIST` is recorded
as a limitation **and** the native `CREDENTIAL_OR_SECRET/ACCESS_TOKEN` control stays matched in the
combined arm. That test drives the adapter's allow-list branch with the stdlib-only fake worker; the real
upstream-suppression path remains **unexercised**.

### 4.6 Diagnostic disclosure, measured on the corrected stack

* **Normal path.** The printed record of the corrected run contains **none** of the 15 planted values,
  no span text, no worker label, no traceback and no sandbox or host path — checked over the whole
  serialized record. Every string in it is a committed constant, an accepted-v1 class/subtype, an
  evaluator-minted ordinal or a numeric count. The record does name the **public fixture ids** it ran
  (`D01-DEV-001`, `D02-DEV-001`) and the family ids, so a reviewer can find the inputs; the earlier
  test comment claiming the record "never carries the fixture's case id" was inaccurate about this record
  and is corrected in the suite.
* **Failure path.** Re-running the same bridge with a worker script that does not exist inside the
  sandbox produced, for every field, a named `WORKER_CRASHED`, **zero** Presidio candidates and `FAILURE`
  for the Presidio arm, while the native arm and the union were unchanged (the union collapses onto the
  native events, so the combined per-control outcomes are identical to the native ones). The child's own
  diagnostic reached **no** field of the record; `Traceback`, `No such file`, the worker file name, `/trial/`,
  `/work/` and the home directory are all absent from it.
* **Synthetic failure paths in the committed suite.** The stdlib-only fake worker is driven in `crash`
  and `raise` modes, the second writing a planted value into a traceback on stderr; both give a named
  bounded failure, zero candidates, every control a miss, and a record with no planted value.
* **Trace-on is not re-measured here.** The #113 record's measurement (14 599 bytes on stderr over one
  97-character text) stands as its author's measurement. This run adds no new trace-on evidence. The
  transport's count-and-discard of stderr remains the only thing keeping trace output out of a report.

## 5. What this does and does not establish

**Established by measurement, on two public development cases, on one host, on a verified runtime:**

* On this control set the **unconfigured native baseline** matched 8 of 15 controls; the **pinned
  Presidio configuration** matched 2 of 15; their union matched the same 8 of 15.
* Per #37 subtype: Presidio missed both EMAIL occurrences and could not look for a NAME; the native arm
  found EMAIL and PHONE by pattern and had no NAME source configured at all.
* On engineering content, Presidio contributed only the documentation-range IPv4 and four
  URL-fragment-shaped events per case, none coinciding with a planted control, and its URL event on the
  field holding the planted URL did not reproduce that URL's extent.
* The combination cost 8 additional unmatched events and 0 additional matched controls on these inputs,
  and folded 1 cross-arm identical event per case plus 1 intra-arm duplicate.
* Exactly **one** over-generation event in the whole run is an established error against an independent
  declaration; the rest are a duplicate or unresolved.
* The Presidio arm costs **2.2–2.4 s** and **8.7–10.2 s** for one and four analysed fields
  respectively, one-shot, one process per field, against a native arm measured at **17–23 ms** per case.
* The corrected runtime holds 50 name-and-digest-verified screened distributions, 4 609 byte-verified
  files, and **zero** startup hooks and zero byte-compiled entries.

**Explicitly not established, and not claimed anywhere above:**

* **No winner, loser, or adoption recommendation.** Two public development cases on one partition are an
  unscored probe. #39's frozen protocol, blind custody and held-out split remain prerequisites for
  anything scored, and #48's reuse decision is a human one.
* **No downstream task-utility or protected-egress evidence.** Nothing is sent in any arm, so #5 reports
  `secret-plaintext-escape` and `task-correctness` as **untested** for all three arms and both cases.
  Candidate over-generation is *not* measured unnecessary cloaking, and neither is measured task failure.
* **No policy outcome.** No treatment was applied, no policy was consulted, and the planted `MASK`
  treatment is shape-completion for #5 only.
* **Not a #39 v0 freeze, not blind custody, not held-out evidence, not #46 adoption due diligence, not a
  closure of #40, and not a correction of #113's own acceptance** — root owns that.
* **Privacy Filter: pending.** Not installed, not screened, not run. Recorded as
  `PENDING / NOT_INSTALLED_NOT_SCREENED_NOT_RUN`, never as a zero.
* **Not measured here:** a configured native `#37` NAME dictionary or `#10` configured candidates;
  Swedish identifier families; any NLP- or model-backed Presidio profile; a URL-recognizer threshold
  sweep; a persistent or pooled worker; peak RSS on this run; upstream allow-list suppression of native
  SECRET on the real configuration; maintenance, packaging, energy and deployment cost; and why the
  corrected runtime's per-process wall clock is higher than the first run's.
* **Rule-versus-model attribution.** This arm is the self-contained-recognizer profile: regex,
  `ipaddress`, `phonenumbers` and the suffix snapshot, with no language model. Everything measured here is
  therefore attributable to **rules and checksums**, not to a model.
* **Scores are not probabilities.** Presidio's scores are carried as detector evidence only; no
  `confidence`, sensitivity, trust or calibration claim is made, and none reaches the record.
* **The execution-environment claim is about the executed subset.** `VERIFIED_WITH_EXCLUSIONS` means the 50
  artifacts this run executed are verified and no startup hook exists; it is **not** a statement that the
  51 pinned records all correspond to the artifacts they name, and the record says so in a fixed code.

## 6. Reproducing or challenging this

The deterministic suite reproduces the arm wiring, the control planting and the oracle-span binding, the
per-control breakdown, the owner-agreement invariant, the union property and its two fold reasons, the
unmatched-event classification, the oracle-negative loader, the allow-list/SECRET composition case, both
failure paths, both fail-closed guards, the screen verifier's name/hook/distribution refusals, the
verifier's output re-derivation, and the record's privacy properties **without any third-party stack**:

```
npm run build && node --test test/matched-development-comparison.test.mjs
python3 evaluations/presidio-worker/verify_selected_runtime.py <manifest> <wheels> <screen> <site-packages>
```

A reviewer who has verified §1 may repeat the bounded corrected run itself. It is `scored: false`,
`enforcing: false`, synthetic-only and network-unshared, and its whole output is **counts, codes and
evaluator-minted ordinals**. Three things a reviewer should check rather than trust: the record's
`executionEnvironment` block against the verifier's own output; `identity.hostManifestDigest` against the
committed manifest (and, if they bind the manifest into the sandbox the documented way, the bytes the
worker opened); and the fact that the run sent nothing (`sentBytes: 0`, `capturedReleases: 0`, and #5
reporting both claims as untested for every arm).

## 7. Residual limits a reviewer must weigh

* The binding is congruence, not authentication, and the sandbox wrapper is containment, not a resource
  limit: it sets no memory, CPU, tmpfs or process-group cap. The prior artifacts' wrapper shape is
  unchanged; only the bound runtime and the manifest binding differ.
* The screen behind the manifest remains #46's lightweight host screen. The name-identity check added here
  is a **new, narrow** check; it is not signature verification, not an authenticated publisher conclusion
  and not a transitive or maintenance review.
* Per-process resource limits only. A child that forks is outside what is measured.
* A `COMPLETE` or `PARTIAL` arm status means only that a well-formed reply arrived for exactly this bound
  input with the pinned identity. It is not "the text is clean" and not a release permission.
* **The `UNRESOLVED` category is a measurement limit, not a detector verdict.** Turning it into a verdict
  needs a declared negative or a planted occurrence for each span, which for these two fixtures means
  extending the #39 oracle draft under #39's own authority — not editing this comparison.
* The independent adversarial review of the pinned manifest itself is still outstanding.
* The corrected runtime's higher per-process wall clock is unexplained, and this document makes no claim
  about it.

## 8. Cross-references

* `evaluations/presidio-worker/manifest.json` — the dated `corrections[]` entry and the
  `executionEnvironment` block that declares the 50-artifact executed subset. The `zipp` record is
  preserved unchanged.
* `evaluations/presidio-worker/README.md` — the corrected reproduction command, the verifier, and the
  corrected non-claims.
* `docs/research/issue-113-presidio-reuse-recommendation-2026-10-02.md` — its Stage 2 measurements are
  unaffected by the environment correction (they are the same rules and the same configuration), and its
  invented `persona.de` fragment example is corrected in place there with a pointer to §0.
* `docs/plan.md` — the single dated status paragraph for this work, and the #113/#113-reopened state root
  owns.