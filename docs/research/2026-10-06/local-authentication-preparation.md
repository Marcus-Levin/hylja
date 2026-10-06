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
