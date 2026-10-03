# Pinned local Presidio worker — interface, invocation and limits

**Evaluation-only, synthetic-only, UNSCORED and NON-ENFORCING.** Nothing here is adoption of
Presidio, a production configuration, a gateway, a new taxonomy, a second evaluation framework, a
#scored #40 comparison or a #48 selection. Current capabilities and limits live in
[docs/capabilities.md](../../docs/capabilities.md) and live run status in the GitHub issues; the dated run record is
[the retired plan's frozen snapshot](https://github.com/Marcus-Levin/hylja/blob/f838fc2dc8da0402338d4dfd1c028392a9f4b9ee/docs/plan.md#current-state), not
current state. This file describes the interface and how to repeat
the run.

## Files

| File | Role |
| --- | --- |
| `presidio_worker.py` | Bounded local worker: one request line in, one reply line out. Every recognizer, language, threshold and filtering choice is read from the manifest, not from this file. |
| `manifest.json` | The pinned configuration: exact artifact identities and digests, licenses, advisory results, Python runtime, enabled recognizers, requested entity set, score thresholds, context handling, duplicate suppression, allow lists and the decision-process seam. Contains no protected configuration value. |
| `../presidio-development-trial.mjs` | The evaluation bridge: projects #39 public development fixtures, runs the adapter per field, registers events with #5 and prints a privacy-safe record. |
| `../matched-development-comparison.mjs` | The incremental #40 matched, **unscored** public-development comparison: the same adapter arm, the current native baseline and their measurement-only union over the same cases and the same planted controls. It adds no threshold, recognizer or dependency, and it is not a scored comparison. |
| `verify_selected_runtime.py` | The pre-execution screen verifier: standard library only, reads the manifest, the wheel directory, the #46 screen report and a candidate runtime's `site-packages`, and prints counts and fixed codes only. It answers three questions a digest-only screen cannot: does each **pinned record's name** match the artifact it names, is every runtime file a byte-identical member of a selected wheel (a symlink, FIFO or device is refused, not skipped, because Python imports through one), and does the runtime carry a `.pth` startup hook or byte-compiled entry. Its `status` is derived from those checks, and the bridge re-derives it from the checks it accepted. A failing check always names its own cause — `NON_REGULAR_RUNTIME_ENTRY`, `RUNTIME_ENTRY_UNREADABLE`, `RUNTIME_FILE_TOO_LARGE_TO_COMPARE`, `RUNTIME_SCAN_TRUNCATED`, `RUNTIME_FILE_NOT_IN_SELECTED_WHEELS` or `RUNTIME_SELECTED_FILE_MISSING` — because a check that fails without saying why cannot be carried into a record and the cause is lost. |

The adapter itself is `src/presidio-candidate-source.ts` (pure protocol/spans/mapping) and
`src/presidio-worker-process.ts` (the bounded child process). The generated fake worker used by the
deterministic suite is `test/fixtures/presidio-fake-worker/fake_worker.py`; it imports no third-party
package, so the whole binding, span, privacy and resource contract is tested without a screened stack.

## Protocol

One request line on stdin, one reply line on stdout, per process. `PRESIDIO_OFFSET_UNIT` is
`CODE_POINT`: Presidio indexes Python `str`, Hylja indexes UTF-16, and a reply in any other unit is
refused rather than reinterpreted. The request carries the analysed text, an opaque `requestId`, the
#6 `inputRef`, the tenant/project refs, the representation and a SHA-256 digest of the text. The
worker must echo all of it; any difference is `REPLY_BINDING_MISMATCH` and yields no candidate.

**The caller never supplies the analysed text.** The adapter re-derives it from the #6 result and the
named target, so a worker can never be handed content that the provenance it is credited with does not
describe. Unpaired surrogates are refused before the request exists: `TextEncoder` would replace them
with U+FFFD, so the worker would be analysing different characters than Hylja holds while `len()`
still counted each lone surrogate as one code point.

**stderr is counted and dropped.** A Python traceback carries source text, host paths and values, so
the transport never materialises it, never reports it and never lets it into an error message. Spawn
errors carry a `path` argument for the same reason. Every failure is a fixed code.

**The analyzer identity is pinned in all three fields, not claimed by the worker.** The trusted scope
must supply `expectedProducerVersion`, `expectedLanguage` and `expectedNerAvailable`; the adapter
compares all three with the reply and carries only the pinned values into any provenance record,
limitation decision or report. A worker that names itself differently is `PRODUCER_VERSION_MISMATCH` or
`REPLY_LANGUAGE_MISMATCH`, and one that claims an NER capability its pin denies is
`NER_CAPABILITY_MISMATCH` — otherwise a buggy or substituted worker could erase its own `NO_NER` /
`NO_TEXT_CONTEXT` coverage limits and turn a degraded run into a clean `COMPLETE`. The trial bridge
reads all three from `manifest.json` (`artifacts[presidio-analyzer].version`, `configuration.language`,
`configuration.nlpEngine.nerAvailable`).

**The placement target is a frozen copy.** The adapter never keeps the caller's own target object, so
mutating a reused object between preparation and completion cannot move a finding onto a different
substring while every binding check still passes.

**Candidate evidence ids are request-scoped.** They are derived from the caller's scope refs and
per-request `inputRef`, never from the analysed text, so they correlate neither across tenants nor
across requests and confirm no guessed value offline.

## Reproducing the screened trial

The wheels are **not** in this repository. A reviewer rebuilds the disposable environment:

```
WORK=/tmp/hylja113
python3 -m venv $WORK/pv
$WORK/pv/bin/python -m pip download --only-binary=:all: --dest $WORK/wheels presidio-analyzer==2.2.364
# the #46 host screen, read from the reviewed Git object rather than copied into the repository
git -C "$REPO" show 7136c9af48b484a0e43b544cbb668ac4eaf046bd:scripts/research/prescreen_pypi_artifacts.py > $WORK/prescreen.py
python3 $WORK/prescreen.py $WORK/wheels $WORK/prescreen.json
python3 -m venv $WORK/worker-venv
$WORK/worker-venv/bin/python -m pip install --no-index --find-links $WORK/wheels presidio-analyzer
```

Install **offline from the screened directory** (`--no-index --find-links`). Never install from an
index inside the trial, and never install an sdist: a wheel-only resolution is what the manifest's 51
artifact records describe.

A sandbox wrapper keeps the run contained and offline. Write it outside the repository, because it is
disposable infrastructure, not a product:

```
cat > $WORK/bwrap-python <<'EOF'
#!/bin/sh
exec bwrap --unshare-all --die-with-parent --new-session --clearenv \
  --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 --ro-bind /bin /bin \
  --ro-bind $WORK/worker-venv /work --ro-bind $WORK/trial /trial \
  --proc /proc --dev /dev --tmpfs /tmp --chdir /trial \
  --setenv PATH /work/bin --setenv LANG C.UTF-8 --setenv LC_ALL C.UTF-8 \
  --setenv PYTHONHASHSEED 0 --setenv PYTHONDONTWRITEBYTECODE 1 --setenv PYTHONNOUSERSITE 1 \
  --setenv PYTHONUNBUFFERED 1 --setenv HOME /tmp --setenv TMPDIR /tmp \
  /work/bin/python "$@"
EOF
chmod +x $WORK/bwrap-python
mkdir -p $WORK/trial
cp evaluations/presidio-worker/presidio_worker.py evaluations/presidio-worker/manifest.json $WORK/trial/
```

Then run the bridge (`npm run build` first, because it imports `dist/`):

```
node evaluations/presidio-development-trial.mjs \
  --python $WORK/bwrap-python --worker /trial/presidio_worker.py \
  --manifest evaluations/presidio-worker/manifest.json --worker-manifest /trial/manifest.json \
  --workdir $WORK/trial --tenant tenant-synthetic-01 --project project-synthetic-01

# `--manifest` is the host path the bridge reads the pin from; `--worker-manifest` is the path the worker
# itself opens, which inside the sandbox is a different path and defaults to `--manifest`.
```

`--python` may equally be the venv interpreter directly. That removes the network namespace, not the
offline configuration: `tldextract` is reconfigured to its bundled snapshot either way, and
`REGEX_TIMEOUT_SECONDS` bounds Presidio's regex execution either way.

The matched comparison takes the same arguments and reads the same pin from the same manifest. It adds the
pre-execution verification inputs, and **a run without them accepts no third-party execution evidence** -
the record says so with the fixed limit
`EXECUTION_ENVIRONMENT_NOT_VERIFIED_NO_THIRD_PARTY_EXECUTION_EVIDENCE_ACCEPTED`:

```
python3 -m venv --without-pip $W/venv        # no pip, no setuptools, therefore no .pth startup hook
# then extract the verified selected wheels' members into $W/venv/.../site-packages with the
# standard library only: no installer code of any kind runs, and nothing is downloaded.

python3 verify_selected_runtime.py \
  manifest.json $W/wheels $W/prescreen.json $W/venv/lib/python3.14/site-packages
# VERIFIED            every pinned record resolves to the artifact it names
# VERIFIED_WITH_EXCLUSIONS  the executed subset is verified and the excluded records are listed
# MISMATCH            a check failed; this run's numbers are not acceptable evidence

node ../matched-development-comparison.mjs \
  --python $W/bwrap-python --worker /trial/presidio_worker.py \
  --manifest manifest.json --worker-manifest /trial/manifest.json \
  --workdir $W --tenant tenant-synthetic-01 --project project-synthetic-01 \
  --verify-script verify_selected_runtime.py --verify-manifest manifest.json \
  --wheels $W/wheels --screen $W/prescreen.json --site-packages $W/venv/lib/python3.14/site-packages
```

It reuses this directory's worker and manifest rather than a second pinned configuration, and its
measured result is recorded in
[the matched comparison record](../../docs/research/issue-40-matched-development-comparison-2026-10-02.md).
It sends nothing, so every arm's escape and task claims stay `untested`, and its combined arm is a
measurement-only event union — not a merge, not a policy outcome and not a #39 or #40 result.

**Bind the committed directory, not a copy of it.** `--ro-bind <repo>/evaluations/presidio-worker /trial`
makes the worker open the committed `manifest.json` and `presidio_worker.py` byte-for-byte. A copy made
by a previous step is byte-identical only until someone edits one side; the record's `hostManifestDigest`
is a fact about the host copy, and the binding is what makes it a fact about the worker's copy too.

## What the configuration deliberately does not have

* **No NER.** `NoOpNlpEngine` is Presidio's own engine for configurations whose recognizers are all
  self-contained. It loads no external model, so this trial downloads and loads **no NLP weights**.
  The cost is explicit and measured: 2.2.364 has no `PERSON` recognizer outside its NLP-engine
  recognizers, so this configuration cannot find a person name at all. `PERSON` remains in the
  Hylja mapping table because a different configuration could emit it; this trial never exercises it.
* **No remote recognizer.** Every enabled recognizer is local and regex/checksum based, and the run
  is additionally network-unshared.
* **No runtime model download.** `TRANSFORMERS_OFFLINE`/`HF_HUB_OFFLINE` are set, and `tldextract` is
  rebound to `TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True, cache_dir=None)`. That last
  rebinding is required: Presidio's `EmailRecognizer.validate_result` calls the module-level
  `tldextract.extract`, which is a closure over the default instance and fetches the public suffix
  list on first use.
* **No allow list.** `allowListMatch: NONE` with an empty list. Presidio allow lists hold *values*, so
  the reply reports a **count only** and the adapter has no field that could carry one.
* **No context enhancement.** `LemmaContextAwareEnhancer` needs tokens and lemmas the no-op engine does
  not produce, so an explicit no-op enhancer is installed and the manifest records `DISABLED`.

## Evidence the filtering stages remove

The reply Presidio produces is its **post-filter** output, and the adapter never reconstructs what
came before it. `limitations` in every result names the evidence this boundary cannot observe:

| Code | What is lost |
| --- | --- |
| `POST_FILTER_REPLY_ONLY` | Recognizer output before thresholding, dedup and allow-list removal is simply not visible. |
| `UPSTREAM_SCORE_THRESHOLD` | `requestScoreThreshold: null` means Presidio applies its own per-entity recognizer thresholds, which are not reported. The trial shows this concretely: `US_SSN`'s "very weak" 0.05 patterns are dropped. |
| `UPSTREAM_DUPLICATE_SUPPRESSION` | `EntityRecognizer.remove_duplicates` collapses overlapping spans before the reply. |
| `UPSTREAM_ALLOW_LIST` | Present whenever an allow list is configured. |
| `UPSTREAM_CONTEXT_ENHANCEMENT` | Context-derived score adjustments, and the context words themselves, never cross the boundary. |
| `NO_NER` / `NO_TEXT_CONTEXT` | The engine has no NER and therefore no tokens or lemmas, so names, locations and text-derived context are absent. `NO_TEXT_CONTEXT` follows the **engine**, not the enhancer's switch: a configuration reporting `DISABLED` still has no tokens to read. |
| `UNSUPPORTED_ENTITY_TYPES` | A detector-native type with no accepted-v1 mapping, such as `US_SSN`. Reported, never coerced onto the nearest class. A type this repository does not pin is reported as a count only (`entityType: null` plus `unpinnedUnsupportedTypes`), because a worker's own label is untrusted content. `UNSUPPORTED_REPORT_LIMIT` names the case where a worker declared more distinct types than the bound. |

The one supported seam that adds evidence back is `AnalysisExplanation` (`decisionProcess: true`).
Presidio also offers `text_match` (the matched text) and `pattern` on it; the worker never reads them
and the protocol has no field for them.

The two identifiers it does carry, `patternName` and `recognizerId`, cross the wire held to an
identifier grammar — and that grammar is a **shape** check, not a disclosure control: a planted value
that happens to be identifier-shaped is still a planted value, and a worker repeating one string in two
fields is one worker agreeing with itself, not corroboration. So the adapter reports:

| Seam field | What a result carries |
| --- | --- |
| `recognizerId` | The class name **only** when it is one of the six recognizers the pinned manifest enables (`PRESIDIO_PINNED_RECOGNIZER_IDS`); otherwise nothing plus `recognizerIdUnpinned: true`. |
| `patternName` | Never the label — only `patternNameReported: true/false`. One measured value (`IPv4`) is not a vocabulary, and Presidio pattern names are detector-internal free text. |
| `enhancedByContext` | The boolean, which is safe to carry and is the part that speaks to rule-versus-context attribution. |

`recognizerId` is the **class name** of the configured recognizer, not Presidio's own
`EntityRecognizer.id`, which embeds a per-process counter and therefore changes between runs of the
same pinned configuration. The manifest records this, and the adapter's recognizer vocabulary is
exactly that manifest's enabled set: adding a recognizer to one without the other is a reviewed change
to both, not a label the adapter invents at run time.

## Non-claims and residual limits

- **The manifest is a 51-record pin with a corrected 50-artifact executed subset, not a 51-artifact
  runtime.** Its `corrections[]` entry records that the `zipp 3.23.0` record's digest, size and member
  count are those of `setuptools 84.0.0`, whose own metadata says so; `zipp 3.23.0` exists on this host
  only as a copy vendored inside that wheel. The record is preserved unchanged and **excluded**, never
  deleted or silently renamed. A record whose artifact cannot identify itself at all is a separate pin defect and is reported as `ARTIFACT_OWNS_NO_SINGLE_TOP_LEVEL_DIST_INFO`. `screen.nameIdentityLimit` records why the #46 screen could not have
  caught this: it compares downloaded bytes to published records and never checks that a record's **name**
  matches the artifact it names. A run that has not passed `verify_selected_runtime.py` has demonstrated
  no execution identity, whatever the manifest says.
- **`setuptools` is a startup hook, not an inert library.** `distutils-precedence.pth` is exec'd by
  `site` at interpreter startup whenever its variable is absent or `local`, which is what `--clearenv`
  plus an explicit `--setenv` list produces. Neither wrapper passes `-S`, so an interpreter that has that
  distribution on its path runs its shim at every start regardless of whether the analyzer imports
  anything. The corrected runtime is built with `--without-pip` and standard-library wheel extraction, so
  it has neither `pip` nor `setuptools` and therefore no hook; a runtime verification that finds one is
  `MISMATCH`.

- The screen behind the manifest is #46's lightweight host screen: published-digest agreement,
  artifact license/advisory metadata and an OSV version query per package. It is **not** signature
  verification, not an authenticated publisher conclusion, not a transitive or maintenance review and
  not an adoption decision. `verify_selected_runtime.py` adds a **narrow new** check - record-name
  identity, runtime file provenance and startup hooks - and is not a substitute for any of the above.
  28 of the 51 pinned records declare no PEP 639 `License-Expression` and carry only
  a legacy `License` field; that metadata gap is recorded, not resolved, and it is a gate for any future
  packaging or adoption work.
- The transport *declares* a fixed minimal worker environment; it does not fully control it. Node's coverage
  instrumentation rewrites `child_process.spawn` and adds `NODE_V8_COVERAGE` to the child, which the
  deterministic suite caught. The authoritative environment boundary for the trial is therefore the sandbox's
  `--clearenv` with its explicit `--setenv` list, not the transport's `env` option.
- Per-process resource limits only. The transport bounds startup time, execution time, stdout bytes,
  stderr bytes, reply size and candidate count, and SIGKILLs the child on every failure path, but a
  worker that forks is outside what it measures. A child that produces no `close` event within the reap
  grace period is reported as `killedNotReaped: true` **beside** the reason the kill was issued, so a
  timed-out worker is never described as cleanly reaped.
- A `COMPLETE` result means only that a well-formed reply arrived for exactly this bound input with a
  usable runtime and the pinned analyzer identity. It is not "the text is clean", not a release
  permission, and not a claim that the recognizers saw everything.
- The two deadlines bound different phases, and the distinction is asserted rather than assumed: the
  **startup** deadline runs from spawn to the worker's first stdout byte, and the **execution**
  deadline runs from that byte to process exit. A one-shot worker that answers only at the end is
  therefore bounded by the startup deadline; a worker that writes its reply and then stalls is bounded
  by the execution deadline.
- This worker answers a *complete* protocol frame on every failure path, binding included, so an
  unusable, absent or non-object manifest is named `WORKER_REPORTED_FAILURE` with zero candidates
  rather than refused as a malformed frame. (A refusal that happens **before** the request can be
  parsed — bad protocol, wrong offset unit, a text that is too large — necessarily echoes an empty
  binding, so the adapter refuses that frame as `INVALID_WORKER_REPLY`. Both outcomes are fail-closed;
  only the first is nameable.)
- **The worker's own post-processing is bounded, not just what the parent retains.** `WORKER_OUTPUT_LIMIT`
  fires only *after* the child has already written past the cap, and the startup deadline is the only
  thing bounding what the child does before its first stdout byte — which is where the result array is
  filled and the whole reply is serialised. So `MAX_REPORTED_RESULTS = 4096` is a **child-side** bound
  and it is load-bearing: a stub-engine probe measured a 1 MiB adversarial input producing 400 000
  findings, 83 MiB of child RSS and a ~10 MB reply with the cap removed. Past the cap the worker
  refuses with a named `FAILURE` → `WORKER_REPORTED_FAILURE`; it never truncates. The adapter's own
  `REPLY_RESULT_LIMIT` (256) is the tighter, earlier bound on the normal overflow path. Both bounds are
  pinned by [`test/presidio-worker-boundary.test.mjs`](../../test/presidio-worker-boundary.test.mjs),
  which drives the real worker's `main()` against a synthetic stdlib engine.
- **The sandbox wrapper below is containment, not a resource limit.** It sets no memory cap, no CPU cap,
  no tmpfs size and no process-group cap, so the child's pre-output work is bounded only by the
  worker's own `MAX_REPORTED_RESULTS` and by the host. The offline install also reads `$WORK/wheels` on
  the host **after** the screen, which is #46's own declared digest/reopen TOCTOU under a trusted local
  filesystem; the screen verified the bytes it downloaded, not the bytes the venv later opened.
- `logDecisionProcess` is a pinnable runtime flag, and it is **not** recommended for this configuration.
  Measured with trace-on *and* the decision-process seam enabled over a 97-character text containing a
  planted value: **14 599 bytes of trace output on stderr** across two `[decision_process]` lines,
  carrying recognizer names and full compiled regex patterns (configuration detail). It did **not**
  carry the analysed values or `text_match` at this stage, and the 898-byte reply carried no planted
  value, no `text_match`, no `pattern` and no `recognition_metadata`; only the two grammar-checked
  seam identifiers crossed the boundary (`patternName: "IPv4"`, `recognizerId: "IpRecognizer"`), and of
  those the adapter's own record carries only the pinned recognizer class name. Presidio's
  `AnalysisExplanation` does hold the matched text,
  which is why the worker reads only `pattern_name` from it and the protocol has no field for the rest.
  **The transport's count-and-discard of stderr is the only thing keeping trace output out of a report.**
  If tracing were ever routed to stdout instead, the bound would be `WORKER_OUTPUT_LIMIT` plus an
  `INVALID_WORKER_REPLY` refusal rather than a discard — still fail-closed, but weaker.
- The sandbox wrapper in this README is disposable infrastructure that has never been reviewed as code.
  Containment here is the wrapper plus the offline configuration inside the worker, not a claim that
  `RLIMIT`-style per-process bounds make the run unconstrained.
- A Presidio score is a detector score. It is carried in `producer.score` and never becomes a Hylja
  `sensitivity`, `confidence`, `reversible`, `scope` or source `trust`; a candidate composed through
  `composeClassification` stays `UNRESOLVED` until trusted configuration supplies a sensitivity.
- **Every string this boundary reports is a committed constant, a closed code or a trusted pin.** A
  reply's entity type, pattern name and recognizer id are untrusted content, so only pinned
  vocabulary members are reported by name and everything else becomes a count, a boolean or a closed
  code; the shared trial record additionally omits `provenance.textDigest`, which is a binding digest
  of the analysed text rather than a reportable field. The regression that holds this walks every
  string a returned result can contain, so a future reportable field has to be justified to pass it.
- The evaluation bridge sends nothing: there is no `send` call and no socket, so #5 reports the
  secret-escape and task claims as `untested`. The controls it scores are development controls
  authored from the public fixture text, not the official #39 oracle, and a miss is reported as a miss.
  Nothing in this file establishes #39 v0 eligibility, a pre-tuning or final-v0 lock, a scored #40
  comparison or a #48 choice.
- The trial's observed recall and precision over two public development cases are a smoke/conformance
  measurement of one pinned configuration, not a benchmark.
- The #40 matched comparison runs the same two cases with the same manifest and adds the native baseline
  and a measurement-only union. Those figures are an **unscored public-development probe**, not a
  benchmark, not a winner and not a #40 or #48 result, and the union's event count can be *lower* than
  one arm's because it folds exactly identical duplicates rather than because it removed a finding. It
  executed a **verified 50-artifact subset** in a fresh runtime with no startup hook, which is a
  **different environment** from the #113 run above; that run is not re-attributed to it, and neither has
  been independently re-run.
