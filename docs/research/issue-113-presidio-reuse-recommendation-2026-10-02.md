# Presidio reuse options for #113 — measured evidence and a qualified recommendation

**Research evidence for [#113](https://github.com/Marcus-Levin/hylja/issues/113) Stage 2 and
[#40](https://github.com/Marcus-Levin/hylja/issues/40). Not a benchmark, not an adoption decision,
not a scored comparison.** Implementation and run status live in
[the plan](../plan.md#current-state); this document separates what was **measured**, what is a **source
claim**, and what remains an **explicit unknown**. Adoption remains
[#48](https://github.com/Marcus-Levin/hylja/issues/48)'s decision, and any scored comparison still
requires #39's frozen protocol.

## 1. What was measured, and how

One pinned configuration of `presidio-analyzer==2.2.364`, installed **offline** from the 51 screened
wheels in `evaluations/presidio-worker/manifest.json` into a disposable virtual environment, and run in
a network-unshared `bwrap` sandbox against public development cases. The #46 host screen reported
**51/51 `OK`**, 0 yanked, 0 OSV advisories at the pinned versions. The configuration is Presidio's own
`NoOpNlpEngine` with six explicitly registered self-contained recognizers (`EmailRecognizer`,
`IpRecognizer`, `MacAddressRecognizer`, `PhoneRecognizer`, `UrlRecognizer`, `UsSsnRecognizer`), one
language (`en`), no country set, no allow list, a no-op context enhancer, and `tldextract` rebound to
its bundled snapshot. **No NLP weights are downloaded or loaded.** The exact reproduction command is in
[the worker README](../../evaluations/presidio-worker/README.md).

| Measurement | Value |
| --- | --- |
| Wall clock, one analysis, one process, through the sandboxed transport | **1.01–1.07 s** (9 samples over 3 texts × 3 rounds) |
| Python + `spacy`/`presidio_analyzer` import | **756 ms** |
| Analyzer engine construction after import | **0.6 ms** |
| First `analyze()` call (lazy recognizer load + suffix-snapshot init) | **123 ms** |
| Steady-state `analyze()`, 44-character text, 20-call mean | **1.68 ms** |
| Steady-state `analyze()`, 4 021-character text | **3.33 ms** |
| Peak RSS of one worker process | **122 220 KiB (119 MiB)** |
| Screened install footprint | **51 wheels, 77.3 MiB**, 14 of them containing native code |
| Wheels declaring no PEP 639 `License-Expression` | **28 of 51** (legacy `License` field only) |
| `presidio_analyzer` wheel | **266 299 bytes** compressed (the manifest's pinned `sizeBytes`, matching the published digest); 724 458 bytes uncompressed across 182 members, 161 Python modules, 112 recognizer modules |

These are **author measurements on one host** (Linux x86_64, CPython 3.14.4, one-shot process per
call). They are not a latency SLA, not a throughput figure, and not a comparison against any Hylja
baseline, which was not run on the same inputs.

### Candidate detection, per case and per #37 subtype

Two public development cases, controls authored from the fixture text, no send and no capture, so #5
reports escape and task claims as `untested`:

| Case | Planted | Matched | Misses | False positives | Recall / precision |
| --- | --- | --- | --- | --- | --- |
| D01-DEV-001 | 3 | **1** | 2 | 4 | 0.33 / 0.20 |
| D02-DEV-001 | 2 | **1** | 1 | 4 | 0.50 / 0.20 |

Separately by the three #37 subtypes, as #40 requires, and **not** hidden by any semantic judgment or
sentinel catch:

| Subtype | Found | Missed | Note |
| --- | --- | --- | --- |
| NAME | 0 | 1 | No recognizer exists for it in this configuration. 2.2.364 ships no `PERSON` recognizer outside its NLP-engine recognizers, and `NoOpNlpEngine` reports zero supported entities. |
| EMAIL | 0 | 1 | `EmailRecognizer.validate_result` requires `tldextract.extract(...).fqdn != ""`, and `.invalid` is not a public suffix, so the result is invalidated. |
| PHONE | 1 | 0 | `+1 202-555-0101` found at score 0.40. |
| IP (networking, not #37) | 1 | 0 | `192.0.2.17` at 0.60. |
| Bare host | 0 | 1 | No recognizer for a DNS name without a scheme; Hylja's native `#9` covers this. |
| US_SSN | 0 | 0 | The "very weak" 0.05 patterns were removed by Presidio's own per-entity threshold before the reply. |

The four false positives per case are the URL recognizer matching fragments such as `persona.de` and
`example.in` inside ordinary text and truncating a real URL at a TLD it recognises. `MAC_ADDRESS` and
`IP_ADDRESS` behaved correctly.

### Diagnostic disclosure, measured on the real stack

#40 asks for runner/stdout/stderr/exception/trace disclosure to be captured separately. With
`return_decision_process` **and** Presidio's `log_decision_process` both **enabled** in a pinned
manifest, over text containing a planted `synthetic-planted-trace-91ac.invalid` value:

* **Trace-on really does produce output.** It is not a no-op: a single 97-character text produced
  **14 599 bytes on stderr** across two `[decision_process]` log lines. That output contains the
  recognizer names and the **full compiled regex patterns**, i.e. configuration detail. It does *not*
  contain the analysed values or `text_match` for this trace stage, and no path or traceback.
* **The reply carried no planted value, no `text_match`, no `pattern` and no `recognition_metadata`**;
  only the two grammar-checked seam identifiers (`patternName: "IPv4"`, `recognizerId: "IpRecognizer"`).
  Measured on the wire, on the head that produced this document; the adapter now reports only the pinned
  recognizer class name of those two and never the pattern name (see the label paragraph below).
* **The transport's outcome contained none of it** — verified end to end through
  `runPresidioWorker`: 898 reply bytes, and none of the planted values, `text_match`, `Traceback`,
  `decision_process` or the pattern text appears in the returned object. stderr is counted and dropped,
  and that is the *only* thing keeping trace output out of a report, so it must never be relaxed.
* The fake-worker failure path was separately checked: a deliberate `RuntimeError` carrying a planted
  value reaches no channel — not stdout, not stderr, not any report field — because the outcome is a
  fixed code and the traceback is never materialised.

**Corrected after this document was written (2026-10-02, root-reproduced).** The measurement above is a
property of the *real pinned configuration on a well-behaved reply*, and it did not cover the reporting
path itself. Root ran a probe through the delivered adapter with a worker that deliberately pasted a
planted, grammar-legal token into an unmapped result's `entityType` (and into its `unsupported`
declaration), and separately into both `AnalysisExplanation` identifiers of a **supported** result, and
the exact plaintext then appeared in the returned result. So a real Presidio reply is not the only thing
that has to be safe: an *untrusted* one is, and no fail-closed decision makes a plaintext report safe.
The adapter now reports a type name only from its committed vocabulary, a recognizer id only when it is
one of the six recognizers the pinned manifest enables, and a pattern name never; every other label
becomes a count or a boolean. Nothing in this document's measured findings changes — the counts, the
recalls, the misses, the false positives, the timings and the recommendation are the same measurements
of the same pinned stack — but the disclosure statement above was too narrow, and it is corrected
here rather than left standing.

**Residual, stated rather than closed:** if a future configuration ever routed Presidio's tracing to
*stdout*, the transport would bound the bytes and kill the child (`WORKER_OUTPUT_LIMIT`) and the
validator would refuse the frame, so the outcome is still a named bounded failure — but the bound
would be doing the work rather than the discard. Trace-on is therefore not recommended for this
configuration.

### Attribution: rules/checksums/context versus the NLP model

The configuration measured **is** the self-contained-recognizer profile: regex patterns, `ipaddress`,
`phonenumbers` and the suffix-snapshot check, with no language model. So every measured finding above
is attributable to **rules and checksums**, not to a model. That is the whole attribution this issue
can make, and it is stated here as a limit of the evidence rather than as a comparison:

* **Measured:** this configuration found 1 of 3 D01 controls and 1 of 2 D02 controls, missed the
  synthetic `.invalid` email and the bare host, could not look for a person name at all, and produced
  four URL-fragment false positives per case.
* **Source claim, not a measurement:** Hylja's native `#37` and `#9` are *designed and unit-tested* to
  cover synthetic `.invalid` emails and bare DNS names. **No Hylja baseline was run on these two
  inputs**, so this document does not say which detector is better on them. The upstream test suite for
  `#37` is evidence about Hylja, not a same-input comparison.
* **Untested:** downstream task utility. The trial sends nothing, so #5 reports the task claim as
  `untested`. Four false cloaks per case would over-cloak *if* the candidate were ever transformed and
  used; whether that actually breaks a task is a measurement nobody has made, and no such claim is made
  here.

**The model-backed profile was not measured.** Anything about what spaCy NER would add for names and
locations is a source claim or an unknown, not a result.

## 2. Source claims (inspected, not executed)

* `presidio_analyzer` 2.2.364 `PREDEFINED_RECOGNIZERS` lists nine locale-agnostic recognizers
  (phone, credit card, crypto, date, email, IP, IBAN, medical licence, URL); names and locations come
  from the NLP-engine recognizers.
* `NoOpNlpEngine`'s own docstring: it is "intended for AnalyzerEngine configurations where all active
  recognizers are self-contained and do not require NLP artifacts", it "loads no external model", and
  the default lemma-based enhancer "cannot use context words from the analyzed text" without tokens.
  Presidio itself warns about that pairing; the trial installs an explicit no-op enhancer instead.
* `RecognizerRegistry.validate_nlp_engine_compatibility` refuses `NoOpNlpEngine` when any
  `SpacyRecognizer` is registered, and `load_predefined_recognizers` adds one, so the trial registers its
  recognizers explicitly. That is the main reason a *correct* no-NLP configuration must be hand-built.
* `EmailRecognizer`, `IpRecognizer`, `MacAddressRecognizer`, `UrlRecognizer` and `UsSsnRecognizer`
  contain no reference to `nlp_artifacts`; `PhoneRecognizer` does (it consumes
  `NlpArtifacts`, though it does not need a model for the result).
* 2.2.364 ships `se_personnummer_recognizer.py` and `se_organisationsnummer_recognizer.py`. **They were
  not enabled and not executed in this trial**, so their behaviour on synthetic or real Swedish
  identifiers is an unknown here. The upstream entity catalogue is documentation, not evidence that the
  selected artifact behaves as documented.

## 3. Explicit unknowns

| Unknown | Why it matters | What would resolve it |
| --- | --- | --- |
| What a spaCy-backed profile finds for NAME and locations | Option 4 rests on it, and so does option 3 configured with a model. It is **one of two** unmeasured sources of value, not the only one — see the Swedish row | Screen `en_core_web_lg` (or a smaller English model) plus its transitive weights under #46, then run the same two public cases **and** a Swedish-family probe through the identical adapter |
| Whether Presidio's URL false positives survive threshold tuning | 4 per case is most of the measured unnecessary cloaking | Re-run with an explicit `requestScoreThreshold` and record the threshold/precision trade-off; this is a configuration sweep, not a detector change |
| Whether `SePersonnummerRecognizer`/`SeOrganisationsnummerRecognizer` are worth enabling | **The other** unmeasured source of value: rule-based, self-contained, never enabled here, and Hylja has no native equivalent. #40 asks for Swedish identifier families | Enable both in a manifest variant, screen nothing new, and run the synthetic families against #65/#66's **proposed** vocabulary |
| Whether a persistent worker is acceptable operationally | The one-shot cost is ~0.9 s and ~119 MiB per call; amortised it is ~1.7 ms per short text | A lifecycle experiment (process reuse, failure isolation, model-load failure) — **not** required by this issue and not built |
| Upstream maintenance cadence and the cost of tracking it | Option 2's real cost is re-validation, not the port | Desk research against release history; deliberately out of scope for this runner |
| Hylja baseline recall on the same inputs | No comparative claim is possible without it | #40's comparative run under #39's frozen protocol. The existing public reference is exploratory and ineligible |

## 4. The four options, compared

Measured facts are marked **M**; the rest are source claims or unknowns from §2–§3.

| | 1. Reference only | 2. Port selected recognizers | 3. Local analyzer candidate source | 4. Direct model adapter |
| --- | --- | --- | --- | --- |
| **Critical misses (#37 NAME/EMAIL/PHONE)** | **M** No runtime effect: misses stay visible | Projection: the compact recognizers are the ones that miss the synthetic email; the name gap is model-shaped, so a port does not close it | **M** 1/3 D01, 1/2 D02; EMAIL missed by the suffix check, NAME undetectable | Addresses NAME only *if* the gain is the model — but so does option 3 with a model, and neither was measured |
| **Unnecessary cloaking / task utility** | **M** None added | Projection: porting the URL recognizer would import its fragment false positives | **M** 4 false positives per case; **downstream utility untested** (nothing is sent) | Unknown; a NER model would typically raise recall and false positives together |
| **Latency / resources** | **M** Zero | Projection: zero runtime cost; the real cost is maintenance | **M** 1.01–1.07 s and 119 MiB per one-shot call; 1.68 ms amortised; 51 wheels / 77.3 MiB installed | Unknown; a model adds weights and GPU/CPU questions |
| **Packaging** | **M** Nothing installed | **M** MIT notice is required by the source licence and recorded in the manifest; 28/51 screened wheels declare no PEP 639 expression. The port's own runtime cost is a projection | **M** 51 wheels, 14 with native code, Python on the critical path | Weights are a separate screened artifact class this issue deliberately avoided |
| **On-prem / air-gapped** | **M** Trivially yes | Projection: yes | **M** Yes — the trial already runs network-unshared, offline, with no runtime download | Depends on the model's licence and weights |
| **Ongoing maintenance** | **M** No code to track; the reference does drift stale | Projection: re-validate every ported pattern per upstream release | Projection: a Python dependency lifecycle inside a TypeScript product; this issue's runner is explicitly not that | Projection: model refresh policy |
| **Evidence needed before adoption** | none | Equivalence measurement against the ported patterns | The measured cost argues against it as a runtime dependency; adoption is #48's call | One screened model-backed profile measured on the same cases |

## 5. Recommendation

**Reference-only, qualified defer** (option 1) for Hylja's local candidate generation. This is a
deferral of *runtime reuse*, not a finding that Presidio is worse, and it does not declare a local
winner: the Hylja baseline was not run on these inputs, so no comparative claim is made in either
direction.

Reasoning, in order of weight:

1. **The measured arm shows no benefit that would justify any runtime dependency.** In this
   configuration Presidio found 1 of 3 D01 controls and 1 of 2 D02 controls, could not look for a
   person name at all, discarded the synthetic `.invalid` email through its suffix check, and produced
   four URL-fragment false positives per case. Whatever a same-input baseline would score, those are
   the facts about *this* arm, and they are not the profile of a dependency worth adding.
2. **The cost of reaching them is measured and large.** A one-shot call costs about a second and
   119 MiB; 51 wheels and 77.3 MiB sit on the critical path, 14 with native code. The amortised 1.7 ms
   buys the recognizers whose false positives then have to be tuned away.
3. **The plausible value is concentrated in the model and in the rule-based recognizers this trial did
   not enable** — both unmeasured. The model (option 4, or option 3 configured with a model) is the part
   this issue deliberately did not screen; and 2.2.364 also ships Swedish rule-based recognizers
   (`se_personnummer_recognizer.py`, `se_organisationsnummer_recognizer.py`) that were never enabled
   and whose incremental value over Hylja's own detectors is unknown. So the honest statement is that
   **two unmeasured sources of value remain open**, not that only one does — and adopting the whole
   framework to reach them would pay packaging and lifecycle cost that no measurement yet justifies.

What would change this conclusion, and is deliberately **not** built here:

* One screened, model-backed profile measured on the same two public cases **plus** the Swedish
  identifier families #40's appendix proposes and #65/#66's **proposed** (not accepted) vocabulary
  names. If that profile finds names and Swedish identifiers without wrecking precision, the comparison
  to make is **option 4 versus option 2**, not "Presidio versus nothing".
* A **matched public-development baseline probe** of Hylja's own `#37`/`#9`/`#6` over these two cases
  with the exact configuration and inputs recorded. That would be an **unscored** exploratory probe, not
  a #39 comparison, and it is the single cheapest thing that would replace the source claim in §1 with a
  measurement. It needs no new gate; it needs to be labelled unscored and never tuned against.
* A precision sweep over the URL recognizer, cheap, configuration-only, recorded as a threshold
  trade-off rather than a detector change.
* #40's own comparative run, which requires #39's frozen protocol. The figures here are unscored
  public-development probes and **must not** be read as measured detector superiority in either
  direction.

Option 2 (a selective port) stays the cheapest path to *any* Presidio-derived recognizer later,
because the measured self-contained recognizers are small, self-contained and MIT-licensed — but the
measurement says the ones this configuration exercised miss an email that Hylja's own unit tests target,
so the case for porting them would have to be made on the unmeasured Swedish recognizers or on the
unmeasured model, not on what was run here.

## 6. Boundaries

This document proposes nothing for production and decides nothing. It is not a #39 scored comparison,
not #48's reuse decision, not a #46 adoption review, and not a claim about detector superiority. No
accepted v1 classifier or policy contract changes with it; decision 010 and the taxonomy,
multidimensional and #65/#66/#68 drafts remain **proposed**; #114's vendor-independent overlap
protection is required whichever detector or reuse option is eventually selected, and a candidate
source that misses a finding cannot have that miss restored by any composition or merge.
