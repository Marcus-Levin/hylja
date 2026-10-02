# Research sandbox helpers (#46 Presidio screen)

**Research-only. Not part of the Hylja core, adapters, Policy Engine, `npm test`, CI or any enforcement path.** These scripts exist so an independent reviewer can repeat — or challenge — the checks recorded in [the 2026-10-01 provenance and runtime follow-up](../../docs/research/issue-46-presidio-provenance-runtime-prescreen-2026-10-01.md). Implementation and run status live in [the plan](../../docs/plan.md#current-state); this file only describes the tooling.

Nothing here may be pointed at real, customer, production or held-out data. The only inputs these helpers accept are the pinned public artifacts named in that document.

## Files

| File | Role |
| --- | --- |
| `sandbox-run.sh` | The only thing that starts a payload. Builds one `bwrap` argument vector and either `exec`s it or prints it (`--print`). |
| `install-wheels.py` | Offline installer used inside the sandbox. No network, no imports from archives, no archive execution; strict member-name rules and a digest re-read of every written file. |
| `trial_driver.py` | Trusted driver: creates the throwaway venv, installs, runs the child, then reads its result through the fixed schema. |
| `smoke_child.py` | Untrusted-side smoke: imports the screened candidate and exercises a fixed API surface on synthetic in-memory values. |
| `bounded_run.py` | Bounded, typed execution of the untrusted child: output counted and discarded, hard output ceiling, wall-clock deadline, fixed failure codes. |
| `child_result_schema.py` | The untrusted-result boundary: booleans, range-checked integers and fixed codes only; rejected entries are counted, never named. |
| `verify_attestations.py` | Offline PEP 740 / Sigstore bundle verification, run with a pinned trust anchor. |
| `prescreen_pypi_artifacts.py` | Host-side, network-using prescreen helper: downloaded wheel digest vs independently fetched PyPI metadata, the wheel's own `METADATA`, and an OSV version query. |
| `selftest.py` | Deterministic tests for the helpers themselves. No candidate code, no network, no sandbox. |

## Isolation and bounds the runner enforces

`--unshare-all` (user, PID, network, IPC, UTS, cgroup), `--clearenv`, `--die-with-parent`, `--new-session`; read-only binds of `/usr`, `/bin`, `/lib`, `/lib64` and of the caller-supplied work directory at `/work`; a private tmpfs `/tmp`; a minimal `/dev` and `/proc`. Before the payload starts, a prelude applies `RLIMIT_AS` 2 GiB, `RLIMIT_CPU` 240 s, `RLIMIT_FSIZE` 16 MiB, `RLIMIT_NPROC` 64, `RLIMIT_NOFILE` 1024 and `RLIMIT_CORE` 0, and a 300 s whole-run kill is enforced outside. Each driver step has its own 120 s deadline and a 64 KiB per-step output ceiling (`bounded_run.py`). The step deadline is **not** tunable from the environment inside the sandbox: `sandbox-run.sh` runs `--clearenv` plus an explicit `--setenv` list that does not include `HANDOFF_STEP_TIMEOUT_SECONDS`, so the driver's environment read always falls back to its 120 s default, and a test lowers the deadline by passing `timeout=` to `run_bounded` directly. `HANDOFF_WALL_CLOCK_SECONDS` (default 300 s) is different: it is read on the host before the sandbox is built, so it does take effect. There is no home, repository, credential or host-data mount and no network inside a run.

**Runtime-execution gate (state this precisely, do not overclaim).** `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE` and `RLIMIT_CORE` are **per process**, and `RLIMIT_NPROC` is **per real UID**. None is an aggregate bound over a process tree; `--unshare-cgroup` only namespaces the hierarchy and sets no `memory.max`, `cpu.max` or `pids.max`; bubblewrap 0.11.1 has no `--rlimit` option, which is why a prelude applies them. The cap is deliberately conservative for a one-process smoke. An aggregate memory/CPU/process bound would need a delegated cgroup or another privileged mechanism that this screen does not have, so **a workload that forks is outside what this harness measures**, and the driver is written for a fixed, small number of steps rather than for untrusted concurrency.

If something fails under these constraints, **the fix is to record the gap, not to relax a flag**. `HANDOFF_PYTHON` exists only to select the interpreter for the offline verification run, whose extra packages are the Sigstore reference implementation.

## What is treated as untrusted

The child process runs third-party candidate code, and two separate boundaries keep its influence out of the report.

**Execution.** `trial_driver.py` never calls `subprocess.run` with unbounded pipes. It goes through `bounded_run.run_bounded`, which reads each stream in at most one 64 KiB chunk at a time, **counts and drops** it (nothing accumulates across reads and no child byte is carried into a report; a chunk is transiently materialised in the reader before it is counted, and because the ceiling is tested after a chunk is counted, the reported total can exceed the cap by at most one chunk), kills the child's whole process group with `OUTPUT_LIMIT_EXCEEDED` when the per-step ceiling is crossed, enforces a wall-clock deadline (`STEP_TIMEOUT`), and maps spawn failure, memory exhaustion and any other error to fixed codes (`SPAWN_FAILED`, `STEP_MEMORY_EXHAUSTED`, `STEP_ERROR`). A hung or hostile child can therefore never raise through the driver, never lose an already-collected verdict, and never put a traceback on a reviewer's console: the driver emits exactly one JSON report, or one fixed `driver_error_code` line. **One boundary sits outside that guarantee:** the outer wall-clock kill (`timeout --signal=KILL $HANDOFF_WALL_CLOCK_SECONDS`) is not the driver, so if it fires while the driver is still running, the run is killed with exit status **124** and neither the JSON report nor the `driver_error_code` line is written — no stdout and no stderr at all. With the shipped defaults that needs all three steps to hang (3 x 120 s > 300 s) and only `smoke_child` runs candidate code, so every candidate-induced path still yields a report; the outcome is fail-closed and traceback-free either way.

**Result.** The child's result file is accepted solely through `child_result_schema`: keys outside the fixed table are counted, not named; values may be booleans, integers inside a fixed range, or one of this repository's fixed codes; anything else becomes `UNRECOGNIZED_CODE` or `OUT_OF_RANGE`; submitted key names are looked up, never echoed. **Separately from that child-value namespace**, `read_result` can return `RESULT_READ_ERROR:<PythonExceptionTypeName>` when opening the fixed result path fails, and the driver emits it as `child_result_error_code`; that suffix is a Python exception class name raised on the trusted side by that `open()`, not text supplied by the child. The child supplies **no version, entity-type or exception-class string at all** — the driver derives the runtime versions itself from installed metadata with a strict grammar and compares them to the recorded pins. A child result remains a self-report: the report marks it `candidate_result_is_advisory`.

## Running

Self-tests (safe anywhere; they install nothing and import nothing from archives):

```
python3 scripts/research/selftest.py
```

Attestation verification, offline, against a pinned trust anchor. `WORKDIR` must contain a copy of `verify_attestations.py`, plus `pinned-trusted-root.json`, `sigstore-tuf-15.root.json`, `sigstore-tuf-14.targets.json`, `evidence/` (freshly fetched PyPI provenance objects and GitHub records) and `wheels/`. `HANDOFF_PYTHON` must be `/work/...` or `/usr/bin/python3` and points at the prescreened virtualenv holding the Sigstore reference implementation:

```
HANDOFF_PYTHON=/work/venv/bin/python \
  bash scripts/research/sandbox-run.sh WORKDIR WORKDIR/verify_attestations.py
```

Anonymizer smoke. `WORKDIR` must contain copies of `trial_driver.py`, `bounded_run.py`, `child_result_schema.py`, `install-wheels.py` **and** `smoke_child.py` (the driver inserts its own directory on `sys.path` to reach the schema), plus the four screened wheels under `wheels/`:

```
bash scripts/research/sandbox-run.sh WORKDIR WORKDIR/trial_driver.py
```

Host-side prescreen of downloaded wheels (this is the only script that uses the network):

```
python3 scripts/research/prescreen_pypi_artifacts.py <download-dir> <output-json>
```

The two sandbox commands each print one JSON object on stdout: fixed check verdicts and booleans/counts, never candidate text. The host-side prescreen is different — it writes its records to the `<output-json>` file you name and writes no records to stdout (its only stdout output is a single `{"outcome": "USAGE"}` line, on a wrong argument count, before anything is screened); that file carries fixed codes, booleans, counts and grammar-checked values, never candidate text.

## Review expectations

`install-wheels.py`, `sandbox-run.sh`, `trial_driver.py`, `bounded_run.py`, `child_result_schema.py` and `prescreen_pypi_artifacts.py` are **security-sensitive**: they decide what may be installed, what may be visible, what may be retained in memory and what may be recorded. Review them as hostile-input boundaries before reuse. `smoke_child.py` and `verify_attestations.py` are evidence-producing code for one dated screen and are expected to be re-pinned, not generalised.

`selftest.py` is deterministic and covers those boundaries with inert fixtures only: installer refusal paths (traversal, absolute and backslash names, symlink members, member-count and total-size bounds, directory conflicts, non-zip wheels, symlinked wheels), the untrusted-result schema (unknown keys, wrong types, `bool`/`int` confusion, non-object input, fixed-code replacement, out-of-range integers, oversized files), the bounded child execution (stdout flood, stderr flood, hang, missing executable, planted sentinel bytes), the isolation flags the runner declares, and the host-side prescreen helper (a matching pin accepted with metadata read from the artifact itself; absent, mismatched-digest and mismatched-size pins refused before the archive is opened; oversize artifact, metadata expansion bomb, member-count bound, malformed archive and missing metadata refused with fixed codes; and a record that never echoes a member or file name).

**Not every implemented refusal is covered.** `screen_local_artifact` can return fourteen outcome codes; `PrescreenHelperTest` asserts nine of them, and **five have no committed self-test**: `ARTIFACT_UNREADABLE`, `EXPECTED_DIGEST_MALFORMED`, `MEMBER_TOO_LARGE`, `METADATA_COMPRESSION_RATIO_EXCEEDED` and `METADATA_UNREADABLE`. (`MEMBER_TOO_LARGE` *is* asserted in `InstallerTest`, but for the **installer's** own member bound, not this helper's `MAX_MEMBER_BYTES` check.) The `main()`-level fixed codes are unasserted as well, because only the offline `screen_local_artifact` path is unit-tested: `FILENAME_UNPARSEABLE`, `PUBLISHED_RECORD_UNAVAILABLE`, `OSV_QUERY_FAILED`, `SKIPPED_UNVERIFIED_ARTIFACT` and the CLI's `USAGE`. Two bounds that this screen's safety case advertises — the prescreen's per-member size and its metadata compression ratio — are therefore implemented and reachable but **not** regression-covered; treat them as an open gap, not as evidence. Adding these inert cases is a test-suite scope change rather than a documentation change and is left as follow-up work, and the three index/OSV codes cannot be covered by this self-test at all, because it is deterministic and offline by design.
