# Local authentication preparation: controls-only checkpoint

**INCOMPLETE.** This dated record preserves a fresh #269 recovery's non-sensitive controls, not certificate-issuance or authentication evidence. Private-material experiments were deliberately not started because complete inspection of every mandatory input could not be certified from the retained read chronology after context compaction. No retrospective inspection is offered as qualification of an earlier experiment.

Authority remains [decision 014](../../decisions/014-authenticated-local-request-evidence.md), whose status is **accepted bounded technical design**, not implemented authentication. [Capabilities](../../capabilities.md) alone owns implemented behavior and limits; [#269](https://github.com/Marcus-Levin/hylja/issues/269) owns this preparation's acceptance and work status. This record changes none of them and does not admit A/P/B/C, close prerequisites, or prove protected egress.

## Recovery identity and custody

The execution checkout was `issue269-night-recovery-20261006`, branch `agentic/issue269-night-recovery-20261006`, initially clean at `b92cccc2e740fd61b7bad5b1c1a24aae655f688e`. Root selected native Sol-medium, not a fallback. Root must verify actual serving metadata; this record does not claim an independent review or a particular runtime routing fact from the requested profile alone.

Root's boot-settlement evidence established that the old in-process writer could not remain live. It established neither a terminal successful experiment nor an engineering approval; the shutdown cause remains unproven. Historical F1 design failure and the old infrastructure-incomplete attempt are distinct from these controls. No retry or resumption of the old experiment occurred.

Observed preflight: Node `v24.15.0`, npm `10.9.9`, executable `/usr/bin/openssl` reporting `OpenSSL 3.5.5 27 Jan 2026`. All Node/npm commands used the isolated toolchain prefix supplied by root, not ambient npm. No installation or dependency/lockfile change occurred. No installed `node_modules` declarations were available. OpenSSL's version is not evidence that issuance works here or on hosted CI.

The sole tracked output is this record. Evidence lives outside the repository under the root-owned run directory:

```text
/home/marcus/.local/state/hylja-delivery/overnight-2026-10-06.60PdYO/
  prep269-recovery-brief.md
  issue269.json
  primary/
  prep269-scratch/pipe-control.mjs
  prep269-scratch/pipe-control-result.json
  prep269-scratch/issuer-tls.mjs
```

`prep269-scratch/` was observed mode `0700`. The last file is an **UNEXECUTED, unvalidated draft**, not a reproducible issuer or TLS method accepted by this record. It must not be run merely because it is preserved. Root's pre-execution safety inspection identified unbounded issuer settlement after timeout, potentially throwing asynchronous signal callbacks, an unsettled listen promise on error, and missing awaited server closure on exceptional paths. These are method prerequisites, not an engineering-review round; the draft was not patched or executed. There is no `issuer-tls-result.json`, generated credential, temporary issuer directory, or TLS probe result from this recovery. No private key, session secret, credential fingerprint, full certificate, or protected payload was created or persisted by the executed controls. No upstream, provider, or external network interaction occurred.

## Observed command and control inventory

The recovery brief expressly admitted one harmless `true` command with timeout `0` as a workflow-guard negative control. It was refused for invalid timeout before shell execution and was not retried. This is an expected setup control, not a product failure or successful callback/extension-count proof. The canonical tool transcript, rather than a reconstructed error string, owns the exact refusal.

The following driver was invoked once using the pinned Node path, with an outer bash timeout no greater than 300 seconds:

```text
PATH=/home/marcus/.local/state/hylja-delivery/issue269-recovery.sD2tQ8/toolchain/bin:/usr/bin:/bin
node /home/marcus/.local/state/hylja-delivery/overnight-2026-10-06.60PdYO/prep269-scratch/pipe-control.mjs
```

It returned exit `0`, `CONTROL_PASS`, with two controls and zero private-material or TLS probes:

| Control | Owned group leader | Terminal result | Cleanup observation | Measured duration |
| --- | --- | --- | --- | --- |
| Actual shell pipe carrying `synthetic-pipe-control.invalid` | 136131 | awaited `close`, code 0; exact output; no stderr | group absence `ESRCH` | 19 ms |
| Deliberate owned-group abort | 136134 | live group observed; SIGTERM sent; awaited `close`, signal SIGTERM | group absence `ESRCH` | 107 ms |

Both child groups were fresh detached groups spawned by this driver. PID validation required an integer greater than 1, within signed int32, and different from the driver. The fixed wrapper was invoked through `/bin/bash --noprofile --norc`, with minimal `PATH`/`LC_ALL`, no inherited tracing or loader environment. Signal success alone was not counted as cleanup. No shared, guessed, old, or reused PID was signalled.

These are local observations, not a general cleanup guarantee. The driver sets a two-second kill timer, caps retained stdout at 1024 bytes, and checks group absence for at most one second after close. Its awaited close itself has no separately bounded settlement fallback; stderr is counted, not buffered. Consequently it is **not** a qualified reusable absolute-deadline cleanup method for a private-material experiment. A future separately admitted driver must retain UNKNOWN on unconfirmed settlement instead of claiming the timer guarantees termination. Group absence does not prove escaped-process absence, hostile-host protection, or memory/swap erasure. No sockets were opened by these controls.

## Source identities and inspection limits

Public cache manifests pin Node `v24.15.0` and OpenSSL `openssl-3.5.5` sources; they are public evidence, not authority. The process-group addendum supplied the complete `process.kill` API section, Node JS/native implementation chain, bundled libuv Unix implementation, and Linux `kill(2)` manual before the controls. Source provenance and hashes are retained in `primary/process-group/manifest.json`.

Observed SHA-256 identities:

| Retained input/artifact | SHA-256 |
| --- | --- |
| `prep269-scratch/pipe-control.mjs` | `938dcf83ab3592177363113532ead9a746bb201340c16f28a595dc794ed5f4b1` |
| `prep269-scratch/pipe-control-result.json` | `1e30f9045c0b806a26997cd36a97ddce0bfaed9a6a25028ebebd290c0eea7abf` |
| `primary/pipe-control-wrapper.sh` | `902371883931a11eb9585428b763accb5322a03d16dc305e51f04b97fd50948d` |
| `primary/process-group/manifest.json` | `07e8fcf60e05f4222b32f3d411c6912ba398fc76b439f32a7cc949748ca7d107` |
| `primary/process-group/node-process-kill-api-section.md` | `57c8e2a36eb4f2bf7a1fb52cba92924e14d2a4658216f0460514bde6932b84d2` |
| `primary/process-group/node-process-per-thread.js` | `f3bca509ca9ae6be403fcbc0133c45760c6cc76f21f890c8f494f2934efc9e7b` |
| `primary/process-group/node-process-methods.cc` | `6f2d27513a933dd3d076c0ffe2f95a1846ba1d1060f7ccfbc6eb2df6692a34eb` |
| `primary/process-group/node-libuv-unix-process.c` | `cedc79cb473c0dde5c270ff2ee7b7956cbdfe0b3aceba19597b9a75a21e119f0` |
| `primary/process-group/linux-kill.2.html` | `7d953c559068736beefc6f1b246dc25c22509a81439a17f07cf3bcae990b5506` |
| `prep269-scratch/issuer-tls.mjs` (**unexecuted**) | `9fba959e8e704261550befe67f4bc966d7e31922e3309d1b53cf5f78513f94c6` |

Read calls covered the briefs, repository authorities and declarations, Node TLS/crypto/X509/child-process inputs, OpenSSL command documents, pipe-loader sources, and release notes. Some outputs were truncated. In particular, earlier large ranges for `openssl-req.c`, `openssl-apps-lib.c`, and `openssl-release-notes.md` cannot establish contiguous full inspection merely because follow-up offsets exist. Complete inspection of **every** mandatory input remains uncertified; the writer stopped rather than use a blanket full-read assertion. The report outside the repository names the attempted-read inventory and this limitation. No issuer/TLS observation is inferred from these reads or the draft script.

## Remaining admission prerequisites

All requested certificate issuance and native authentication probes are **NOT PROVEN**: separate CA/server/client generation and issuance; foreign-CA, expired, future, and mismatched-key controls; DER/chain/key-match bounds; server `secureConnection`/`authorized`; usable peer X509/DER/validity shapes; supported TLS version/ALPN; application acceptance/denial and actual socket cleanup. Names, localhost, a CSR, or a generated key would not establish tenant or possession evidence.

Resumption identification/refusal, early-data withholding, native pre-parser memory bounds, and hosted-CI issuer/runtime compatibility are also **NOT PROVEN**. Post-handshake 16 KiB DER checks would not bound native pre-handshake allocation. Configuration alone would not demonstrate resumption or early-data refusal. No new declarations are supplied or verified here.

Future A must own native server/socket enrollment and opaque connection handles, not accept socket-shaped caller objects. Exact independently enrolled certificates, coherent current enrollment/grant revisions and availability leases, certificate validity and live revocation remain separate requirements. Post-handshake probe windows must not renew expired origins. Four-socket/no-queue/five-second bounds need actual measured settlement. Final synchronous guard/write ordering must retain private state, liveness, deadline and once-only effects after trusted callbacks, with no await or callback between last guard and write. These are requirements linked to decision 014, **not implementations or new accepted design**.

The smallest follow-up is a separately admitted source-complete issuer/TLS preparation recovery with independently bounded process/socket settlement; hosted-CI reproducibility needs its own admitted support/verification seam afterward, without silent binary/dependency assumptions or skips. There is no production issuer, SDK conformity, wrong-tuple OS/native fault, registry/authenticator, managed-egress, tenant isolation, restoration, utility, scoring, held-out or release-safety proof in this checkpoint.

Prose gates and the committed head belong to the external writer report. They validate repository hygiene only, not the missing experiments. Root alone publishes; independent exact-head review and human implementation/merge gates remain outstanding.

## Separately admitted non-private cleanup qualification — 2026-10-06, 23:37 UTC

This is a **new prerequisite unit**, not a reset or retry of the ended issuer/TLS attempt above. The original incomplete checkpoint at `9ba28cde658769535d958ccd9df4025555efdcf9`, old measurements, unsafe drafts and reports remain preserved. Root supplied a cleanup-only brief with fixed checkpoint 23:50 UTC/end 23:55 UTC. The later first-wave workflow failure at `state.set('firstWave')` concerned an undefined output-path mapping; it was not a private experiment or a cleanup result. No schema workaround, provider/harness switch or overlapping writer was used here.

All 37 inputs mandatory for **this smaller unit** were freshly read to EOF before execution. Exact returned ranges, continuation trailers and per-file EOF completion are durably recorded in `cleanup-qualification-scratch/read-ledger.md`, beneath the run directory named above. Long files used contiguous chunks of at most 300 lines; no byte-truncated response was accepted. This ledger does not retroactively certify the old attempt's uncertain reads or inspect/admit any OpenSSL/TLS/crypto operation. Decisions 007/008 remain accepted foundation direction, decision 014 accepted bounded technical design, and the gateway slice draft.

### New method and actual observations

New outside-repository artifacts:

```text
cleanup-qualification-scratch/bounded-cleanup.mjs
cleanup-qualification-scratch/run-controls.mjs
cleanup-qualification-scratch/method-manifest.json
cleanup-qualification-scratch/pre-execution.sha256
cleanup-qualification-scratch/input-identities.sha256
cleanup-qualification-scratch/read-ledger.md
cleanup-qualification-scratch/result.json
cleanup-qualification-scratch/native-terminal.txt
```

Only the unchanged three-line public `pipe-control-wrapper.sh` was spawned, using the fixed `/bin/bash --noprofile --norc` argv, detached dedicated groups, and explicit `PATH=/usr/bin:/bin`, `LC_ALL=C`. No shell flags, third fixture, child service, process queue, private material or socket was added. Root agreed before execution that source-evidenced exceptional handling plus pure transition controls suffices for this unit; it does not establish native exceptional-fault behavior.

Each case captures an absolute deadline of at most 3000 ms, intersected with the suite's one 10000 ms deadline. Spawn/stdio/terminal callbacks share that deadline and one settlement path. Retained stdout is capped at 1024 bytes; stderr is never retained and its count is capped, with 1025 meaning cap exceeded rather than an exact oversized total. Signal exceptions normalize to fixed allowlisted outcomes; no captured subprocess text or native exception is printed. UNKNOWN is sticky and stops subsequent controls.

Termination ownership requires the fresh validated PID, successful spawn, no exit/close/settlement, a live group check, and time remaining. Cancellation makes exactly one SIGKILL attempt at 100 ms while the leader remains live. Exit revokes termination authority and cancels the cancellation timer; no delayed escalation or termination signal follows reaping/settlement. After observed close, one immediate **non-signalling** group-existence check is permitted for that just-owned group. Only actual exit/reaping, close and `ESRCH` can count as successful OS cleanup.

On expiry, spawn/stdio/signal failure or unconfirmed absence, the method resolves finite sanitized UNKNOWN, revokes signaling, destroys its streams and unreferences the child handle. That is local reporting/resource release, **not evidence the OS child/group terminated**. It retains unknown status without a delayed or recycled-PID kill. Timers cannot preempt synchronous callbacks/native calls or a stalled event loop; no kernel-stall bound is claimed.

The new driver ran exactly once under Node `v24.15.0`, pinned npm `10.9.9` tooling, with outer timeout 15 seconds. Native exit was **0**, status `NON_PRIVATE_CONTROLS_PASS`; the complete result was read back from disk:

| New native control | Fresh owned leader | Actual terminal/absence facts | Duration |
| --- | --- | --- | --- |
| Exact harmless OS pipe | 162521 | exit and close code 0; 31 exact synthetic stdout bytes; stderr 0; immediate `ESRCH`; no termination signal | 7 ms |
| Deliberate owned-group cancellation | 162524 | live group confirmed; one SIGKILL; exit and close signal SIGKILL; stdout/stderr 0; immediate `ESRCH` | 103 ms |

Suite duration was **111 ms**: **26 pure controls passed**, **2 native controls passed**, **0 UNKNOWN results**, **2 groups sequentially**, **0 sockets/private-material/TLS/OpenSSL/upstream operations**, and no retry. Stream release and signaling revocation were observed true for both cases. The cancellation case intentionally has no exact-output match; its success criterion is the deliberate terminal signal plus close/absence, not pipe-output acceptance.

The pure controls exercise sticky UNKNOWN on spawn/child/stdio/signal errors, expiry/missing close, `EPERM`/other/present absence, missing exit/close, PID exclusions, single-attempt ownership and post-exit refusal. They also execute the caught-signal helper against synthetic throws and a throwing error-code getter. Pure state transitions and synthetic exceptions are **not mocked native cleanup evidence**, permission failures or OS fault observations. No product contract, repository test or fabricated RED was added.

Observed SHA-256 identities for the frozen new evidence:

| Artifact | SHA-256 |
| --- | --- |
| `bounded-cleanup.mjs` | `80b6d65e651dc99ea70bc336f28c20e9cf36a7a716ed32939949803c1ae89045` |
| `run-controls.mjs` | `bfa1d4eea058dee6561b82da27844e113e01fcde2686649233e9d94247aea041` |
| `method-manifest.json` | `6fd437f0a7e5c95c414696fb08ef0851380ddd266e7237961c9e99e7dbf893a6` |
| `read-ledger.md` | `6afd513c4770f0e9649a14f7ce6a7b86d3df3407c3552578e6ef7c417496b36c` |
| `result.json` | `c0cefd7d47bfc5f53b9fb71ff467b8067304ffad05d3e589a6228f06b9dbb19c` |
| `native-terminal.txt` | `7650855c978427c33d7e8215d8878f73bcf7452db7978cbd0c6c53ba88d15af2` |

The same source-chain identities listed above were rechecked and retained in `input-identities.sha256`; the additionally fully read Node child-process document hashes to `a7faa746c3681fd0cdf708237bc840006ceceace519dcdf89360b4ea9e508538`. The API/source basis is the pinned Node 24.15.0 process-kill section and JS/native/libuv chain plus captured Linux manual, **not whole process.md reading, a kernel version pin or hosted-CI evidence**.

### What this narrower result does not establish

The artifact provides measured cleanup for these two fresh harmless groups and finite exceptional reporting semantics supported by source/pure controls. Real missing-close, native `EPERM`, spawn failure, kernel stall and termination on UNKNOWN remain **NOT PROVEN**. Escaped groups, hostile-host protection, heap/swap erasure and platform/CI portability remain excluded. Native guard/profile resolution and callbacks require root's actual metadata consumption; no new timeout-zero control or self-certified extension count was substituted.

This success neither fixes nor admits the preserved unsafe issuer/TLS draft. All private issuance, TLS/X509/API/declaration, resumption/early-data, native parser, A/P/B/C, production, protected-egress and hosted-CI prerequisites above remain unproven. Root alone arbitrates any next admission, review or publication. Green prose gates for this exact addition and the resulting commit are recorded in the separate cleanup-qualification report.

## Separately admitted issuer/TLS preparation — incomplete read-only settlement

Root admitted a distinct two-phase memory-only issuer/pinned-TLS preparation unit after the cleanup checkpoint at `c152e9be289cf49de084bb0022ed40c0cbd0339d`. This unit is **INCOMPLETE**: mandatory source inspection was not qualified, no issuer/TLS method was completed or frozen, and no phase-1 native preflight or phase-2 private experiment ran. Phase-2 permission was neither requested nor granted. Earlier failures and cleanup observations above remain historical evidence, not a retry or retrospective qualification.

Context compaction left uncertainty about early batched read truncation and EOF claims. The new `private-preparation-scratch/read-ledger.md` explicitly withdraws those claims with per-input **NOT QUALIFIED** markers and separates subsequent complete reference reads from the still-incomplete mandatory inventory. Source manifests and line counts do not establish inspection. This unit did not complete the Node TLS/crypto/X509/child-process, OpenSSL command/loader/release-note, or process-group source chain. No speculative method or prior unsafe draft was executed, imported, repaired or admitted.

After receiving the uncertainty report, root expressly directed immediate scoped incomplete settlement: no further source reads, speculative method freeze, probe, key generation or TLS socket; only this append, ledger correction and named prose/whitespace gates. The fixed checkpoint 2026-10-07 00:35 UTC/end 00:45 UTC was not extended. New work consisted of reads, metadata inventory and owned ledger/report writing. **Zero new native controls, issuer operations, key generations, process groups or network/TLS sockets** were exercised; there is no new method, issuer, TLS or cleanup result to accept. Requested native Sol-medium routing is not proof of actual serving metadata; root must consume the runtime evidence separately.

**Socket wording clarification:** the earlier controls' “no sockets”/“0 sockets” wording means **no network/TLS sockets**. Child-process stdio uses AF_UNIX socketpairs; the earlier counters did not measure their absence. This clarification does not invent a new socket measurement or change the recorded native exit/close/group-absence observations.

All certificate issuance, custody, TLS/X509/API/declaration controls, resumption/early-data intervention, native parser bounds and hosted-CI reproducibility remain **NOT PROVEN** by this unit. It implements or admits no A/P/B/C, product authentication, protected egress, production adoption or release. Authority and implementation status retain their linked homes above. The external `reports/prep269-private-preparation-r1.md` owns the exact append commit, actual prose-gate counts, incomplete ledger and remaining review gates. Root alone decides any separately admitted successor or publication; this settlement supplies neither.
