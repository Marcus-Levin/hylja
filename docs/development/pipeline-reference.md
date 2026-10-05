# Development pipeline reference

Disclosed detail for the coordinator procedure in [pipeline.md](pipeline.md). Read the section that
the pipeline page points you to, and skip this file on a routine lane: a worker needs its role body,
its pointers and its commands, nothing here. Guard behaviour, installation, evidence lookup and the
historical #147 proposal are the branches this file holds.

## Workflow guard

`.pi/extensions/hylja-workflow-guard.ts` is a Pi adapter over the pure helper
`.pi/lib/hylja-command-guard.mjs`; both are developer tooling, and neither is in the tracked typecheck
or build scope (`tsconfig.json` includes `src/**/*.ts`). It exists because one run spent eight minutes
on `find / -name hylja-implementer.md` after the exact path had been supplied; a prompt alone did not
prevent the recurrence.

Two guarantees, both decided before the tool executes, both logged nowhere:

| Call | Decision |
|---|---|
| `find` with a machine-wide absolute root | blocked with a fixed reason naming the allowed roots |
| `timeout` omitted on a builtin bash call | set to 120 s, Pi's builtin bash having no default |
| `timeout` present, 0 < t <= 300 | preserved unchanged |
| `timeout` > 300 s | clamped to 300 s |
| `timeout` malformed, non-finite or <= 0 | blocked with a fixed reason |
| any other tool | untouched, and no timeout applied |

Wiring: the adapter takes the `tool_call` handler context and forwards `ctx.cwd` as the session
directory, because a foreground child runs inside the parent process where `process.cwd()` is the
coordinator's directory, not the child's worktree.

Wiring: project extension discovery loads it for the coordinator (`<cwd>/.pi/extensions/`), and both
role profiles declare `extensions: ../extensions/hylja-workflow-guard.ts`, an allowlist that keeps
ambient extensions off in a foreground child while the host-required child extensions, the registered
providers and the builtin tools still resolve. The relative entry resolves against the agent file's own
directory, which is what pi-subagents does for a path-like `extensions` entry; the profiles' other
settings are unchanged.

Operating rules that the guard does not enforce, because a prompt alone did not stop the recurrence:

- The handoff uses the exact entry points already supplied: brief pointers, decision paths,
  `.pi/agents/`, the project skill, the pipeline documents and the three installed principle paths.
  Do not rediscover them by searching the machine.
- Search a filesystem only when a pointer is absent, and then only inside the repository worktree or a
  root named in the brief or in those paths, for example the home directory holding the installed
  skills. Scoped `find .`, `find src` and `grep` stay allowed.
- A guard refusal is a setup finding: use the exact path you were given, or report that the pointer is
  missing. Never retry the same search in another quoting, wrapper or executable form.
- Root owns the wall clock. Watch public tool progress in the session and stop a command that has run
  past its named budget instead of waiting for the deadline; the guard's timeout bounds a single call,
  not the lane budget.

Limits, stated so no one reads more into it: it is a workflow guard, not a shell sandbox, a command
parser or an enforcement boundary. It splits a command textually on control separators and whitespace,
strips quotes and inspects only the leading tokens of each segment. Dynamic expansion, `eval`, aliases,
value-taking wrappers, indirectly invoked `find`, MCP or another harness that reaches a shell, and any
other API are outside it. The timeout applies only to calls that reach this session's guarded builtin
`bash`; other tools and other APIs receive no bound from this guard, and nothing proves a permitted
command is safe, bounded or correct. Unlisted absolute roots, `/tmp` and `$HOME`-relative searches are
allowed on purpose, so the guard cannot block scoped repository discovery or the installed skill paths.

Evidence: `node --test test/hylja-workflow-guard.test.mjs` exercises the helper and the adapter
directly, including the exact command shape that failed, quoted and absolute-executable variants, scoped
discovery, the timeout default, preservation, clamp and refusal, that no other tool is mutated, and that
each role profile's declared path resolves to an existing file. The load path itself is proven by a
native smoke run, not by this document.

## Install and use

Prerequisite: native Pi with `pi-subagents` loaded (`pi list`). Role configuration is the frontmatter of
[`.pi/agents/hylja-implementer.md`](../../.pi/agents/hylja-implementer.md) and
[`.pi/agents/hylja-reviewer.md`](../../.pi/agents/hylja-reviewer.md); `~/.agents/pstack-models.md` is
untouched. Tested installation: pi-subagents 0.75.0 on Pi 1.0.0, whose release notes record the fix for
background children failing on Pi 1.0.0 with a missing `@earendil-works/pi-agent-core/node` export;
0.74.0 does not work on Pi 1.0.0. Foreground children do not depend on that fix. No extra script or
package is added to this repository.

- Interactive: `/skill:hylja-development` forces the project skill; `/reload` after editing it.
- Headless: `--no-skills --skill .agents/skills/hylja-development` loads only that skill; without
  `--no-skills`, every discovered global skill is also eligible for automatic selection.
- Grant project trust once: `/trust`, or `--approve`.
- Launch: `subagent({ agent: "hylja-implementer", task: <brief>, cwd: <worktree>, async: false })`. Both
  role profiles set `async: false`, so a lane is a foreground native child and its result returns
  in-session. Each profile's `extensions:` value is an allowlist rather than empty, so ambient extension
  loading stays disabled in the child while the project workflow guard loads; builtin tools, the
  providers the host registered, and host-required child extensions still load.
- Another checkout needs no installer: copy each `principle-*/SKILL.md` from the pinned upstream
  pstack commit into `~/.agents/skills/<name>/`, MIT license kept.

`async: true` is an optional mode, not the pipeline default: the single background run in this
installation exceeded its budget without a result, so no background lifecycle, ordering or timing is
promised.

## Native lane CLI

`.pi/lib/hylja-native-lane.ts` (the opt-in controller) and `scripts/development/run-native-lane.mjs`
(the root-owned CLI) are developer tooling, outside the tracked build and typecheck scope exactly as the
guard adapter is. Root runs one lane with `node scripts/development/run-native-lane.mjs --config
<absolute config.json>`. The CLI launches Pi once with the three extensions named in its config, the one
fixed input the controller answers, and the one structured foreground delegation call into
`pi-subagents`. No coordinator model takes part in that process; nothing here is a measured speedup,
and a run under this CLI is still one lane: no model override, no background mode, no role fallback, no
nesting, and no child that launches another lane.

The config is root-owned, bounded and absolute. Every path field must start with `/`; `key` and `task`
are non-empty text (`task` capped at 1 MiB); `agent` is `hylja-implementer` or `hylja-reviewer`;
`timeoutMs` is a positive integer no greater than that role profile's own frontmatter deadline; an
optional `softBudgetMs` is a positive integer strictly below `timeoutMs`; an optional
`requiredReferences` list is described below; a `model` key is refused rather than ignored.

```json
{
  "key": "issue-182-round2",
  "agent": "hylja-reviewer",
  "task": "<the full handoff brief>",
  "cwd": "/abs/path/to/worktree",
  "timeoutMs": 900000,
  "softBudgetMs": 360000,
  "sessionDir": "/abs/fresh/dir/sessions",
  "receipt": "/abs/fresh/dir/receipt.json",
  "verification": "/abs/fresh/dir/verification.json",
  "progress": "/abs/fresh/dir/progress.jsonl",
  "dispatch": "/abs/fresh/dir/dispatch.json",
  "pi": "/home/operator/.pi/agent/bin/pi",
  "subagents": "/home/operator/.pi/agent/npm/node_modules/pi-subagents",
  "guard": "/abs/path/to/worktree/.pi/extensions/hylja-workflow-guard.ts",
  "controller": "/abs/path/to/worktree/.pi/lib/hylja-native-lane.ts",
  "requiredReferences": [
    { "label": "required contract", "path": "/abs/fresh/dir/retained-contract.md" },
    { "label": "retained red log", "path": "/abs/fresh/dir/207-evidence/RED.log" }
  ]
}
```

The four entrypoint fields are not interchangeable. `pi` is the executable Pi itself is spawned as.
`subagents` is the trusted installed package **directory** holding its `package.json`, because both the
`--extension` argument and the delegation and preflight modules resolve from it, and every resolved
module URL must stay inside that directory; a file path, a nested entrypoint or a different copy on disk
is a setup failure. `guard` and `controller` are the two extension **file** paths, named exactly, never
searched for.

The four evidence paths must be fresh: an existing `receipt`, `verification`, `progress` or `dispatch`
file is `SETUP_FAILED_STALE_EVIDENCE`, so a previous run's evidence can never pass as this run's.

**When `requiredReferences` is configured** (and only then): it is one structured declaration, never
prose that is parsed. The only accepted shape is an array of at most 16 `{ label, path }` entries, a
non-empty label of at most 128 characters with no control character, and an absolute path of at most
4096 characters. Anything else — a bare path string, a label-to-path map, a primitive entry, an
unknown field, an empty label, a relative or overbound path, a control character in a label, or an
overbound count — is `SETUP_FAILED_REQUIRED_REFERENCE` in both readers, never a repaired value, and no
declared label or path is echoed into any record. An absent key and an explicit empty list are the
same assertion of no references, and run no probe at all.

Admission is file metadata alone: each path must be an existing regular file the launching process can
open for reading. Nothing is read from the file, no path is resolved, searched for, or substituted for
another file, and nothing is inferred from the task prose. The CLI probes before it spawns Pi and the
controller probes again before it resolves the launch contract, so a missing, directory, unreadable or
otherwise non-regular entry is the fixed reference refusal with zero dispatch: no launch contract, no
child process, no persisted dispatch record, no armed timer, and every existing artifact left exactly
as it was. A non-regular path is refused from its metadata before it is opened, because the open is
the only unbounded step in admission: a FIFO with no writer makes a blocking read-only open wait for a
writer, and both probes run before any watchdog exists to bound that wait. The one open that remains
is read-only, never a write, and non-blocking where the platform carries `O_NONBLOCK`; on a platform
without that flag the open is an ordinary read-only one and no non-blocking guarantee is made there.
The opened descriptor's own `fstat` decides readability, so a path that becomes a FIFO between the
stat and the open is refused rather than admitted, and the descriptor is closed in a `finally` on
every path. No content is read on any path. Symlinks are followed, so a link to a readable regular
file is admitted and a broken one is missing. Admitted labels and exact paths are rendered once, into
the one effective task that both the launch contract and the dispatched request carry, inside the
existing 1 MiB raw cap; an effective task past that cap fails restrictively rather than dropping a
pointer. A process that bypasses file permissions admits what it can actually open, so admission is
not approval and no promise is made that a path still exists, or is still readable, when the leaf
reads it.

The controller resolves `resolveSubagentLaunchContract` for this exact task, cwd, fresh context, parent
model registry and the one bridge value it declares (`LANE_BRIDGE_INPUT`, `{ mode: 'off' }` — off
explicitly, not left to a default) before it emits anything, then persists the expected launch digest,
the declared guard identity, the effective model and the dispatch tuple, and only then dispatches.

Before the CLI reports a lane it binds that persisted tuple to the leaf's public terminal receipt
(literal result, cumulative usage, actual model, thinking and status), to one listing of
`{sessionDir}/subagent-artifacts/` for `*_meta.json` and `*_output.md` only, and to a runtime record
whose `runId`, `agent`, model and `launchContractDigest` match, whose `launchResolvedExtensions` is the
installed launch-resolved schema (`version: 1`, `source: "launch-resolved"`, ambient extensions off,
the declared guard path, the declared number of configured extensions, and every `omitted` ledger
entry present and zero). All four resolved lists — `runtime`, `configured`, `required` and
`effective` — are validated together before any is read: each must be present and an array of
non-empty digest strings, and every `configured`, `runtime` and `required` digest must occur in
`effective`. A missing, mistyped or non-string list is refused, never defaulted to an empty list; an
explicitly empty list is a valid assertion of an empty set and stays distinct from missing evidence.
Any missing, reused or mismatched part is a setup failure with a fixed code,
never an inferred pass. Exit codes: `0` verified completed lane, `2` setup or evidence failure
(INCOMPLETE), `3` the leaf finished non-completed. A `completed` leaf is not approval: the verdict is
only the leaf's own literal `APPROVED`, `CHANGES REQUESTED` or `INCOMPLETE` line.

Four bindings carry that last rule, each refused rather than inferred:

| Pair | Refused |
|---|---|
| the fired terminal deadline and the native close | the deadline is latched before the stop, so a child that closes zero after the watchdog fired is `SETUP_FAILED_NON_COMPLETED_STATUS` with `deadlineExceeded: true`, never a verified lane |
| the receipt's `verdict` field and the literal first line of `result.text` | the field must equal that line, or the text carries no declared verdict and the field is the `INCOMPLETE` fallback the controller assigns it. Empty text, an unbound field and a contradiction are malformed |
| the discovered `_meta.json` and `_output.md` | both must be the same artifact stem, so `_0_meta.json` beside `_1_output.md` is two attempts, never one pair |
| the public output and the bound verdict line | the output must lead with the literal line the receipt binds; the terminal text appearing somewhere inside it is not proof of a verdict |

Author results are covered by that second row: an author's result that declares no reviewer verdict
stays `INCOMPLETE`, and can never resolve to an approval. Progress records are parsed, not trusted: a
line that is not a plain object becomes a fixed `{"event": "malformed"}` snapshot rather than a thrown
property read.

Acceptance is reported, never assumed. A direct-API run of either role resolves `not-required`, because
each role profile disables the native writer gate through the deprecated `false` shorthand, so the
record carries no native writer acceptance evidence: `writerAcceptanceGate` says `not-required` and
`acceptanceProvesApproval` is `false`. A run whose gate did resolve reports `checked`; an actual
acceptance failure is refused. Root admits a writer lane separately, by verifying its clean committed
scoped paths and its evidence, before any approval.

Bounds: progress records carry model, runId, elapsed milliseconds and tool count only, and
`recentOutput`, tool arguments, raw sessions and provider reasoning are never read or written. The
persisted progress file is bounded by one window with two halves that the writer and the reader share
as a single constant: at most 256 records and at most 128 KiB of serialized UTF-8 bytes, measured
after JSON escaping because that is what is written. Retention at the writer is therefore available at
the reader — a record the writer keeps is a record the CLI's bounded positional read can still reach —
which a record count alone did not establish. An ordinary lane with ordinary metadata keeps the same
256 records it always did; a lane whose accepted metadata is long keeps fewer, because the byte window
binds before the record count does, so that oversized tail is deliberately not byte-identical to what
a count-only window persisted. Cancellation reaches only the exact owned tuple
persisted at dispatch, inside the running process.
Owned shutdown is finite: the watchdog latches the deadline and stops the CLI's own child one minute
past the native request timeout, sends SIGTERM, then SIGKILL after 10 s, then waits at most 10 s more
for `close` — never an indefinite wait.

**When `softBudgetMs` is configured** (and only then): the child learns the two numbers once, in its
initial task, as one role-aware paragraph — reviewer: report a literal verdict and stay read-only;
writer: finish the checks, commit, then report — and that paragraph grants no authority the role body
does not already carry. Root receives exactly one bounded numeric `soft_budget_reached` progress
snapshot at the soft budget, which appears in the verification record's `progress` array. That snapshot
is pinned inside both halves of that window: when a busy leaf's own later updates would push it out of
the tail root reads after the child exits, it joins as the oldest survivor and the ordinary records it
displaces are dropped from the oldest end, so neither bound is raised, the surviving records keep
their chronological order and the newest updates are the ones kept. Pinning it costs the window
nothing it was already allowed to keep, and it is a warning for the reader and nothing more: it is
never delivered to the running child, and
it never cancels, kills, deletes, resets or approves anything. The hard path is unchanged and finite —
native request timeout, plus the one-minute watchdog, SIGTERM, SIGKILL after 10 s, at most 10 s more
for `close`. A lane that reaches it reports INCOMPLETE with `deadlineExceeded: true`, keeps its
worktree, receipt, dispatch, progress and artifact files for recovery, and is never an approval; a
recovery handoff must name the exact source SHA whose tree the resumed lane runs, so a resumed lane is
provably the same code and not a re-implementation of it.

Evidence: `node --test test/hylja-native-lane.test.mjs test/hylja-workflow-guard.test.mjs` drives the
real controller and CLI exports against a fake event API, a fake preflight and a synthetic temporary
platform (49 tests, 39 of them in the lane file). Two of them
fake only the child transport, so the shipped default platform is what runs: the default filesystem
must read the progress tail with bounded positional descriptor reads and close every descriptor it
opens, and the default signal hooks must own SIGINT and SIGTERM, stop the owned child once and be
removed on completion. Faking those two adapters had passed while the defaults read the whole progress
file and registered no listener at all. One case injects only the clock, so the real watchdog is fired
by its recorded timer rather than by waiting out a ten-minute budget, and proves that identical
completed approval evidence is refused after expiry and verified without it. The optional soft budget
is driven by an injected `now` and `arm` pair whose cancel closure is recorded, so a case can fire,
repeat, refuse and drain a soft budget deterministically; the shipped default `arm` has its own case
so the fake clock is not the only path that can warn. One case fires that warning and then pushes more
owned updates than the file keeps, settles, and reads the file back through the shipped `readProgress`,
because the warning only matters if root's own reader still finds exactly one of it. Two further
cases drive the same real controller and the same shipped reader with the longest metadata the
contract accepts: one at 4096-character model and runId values, one with a JSON-escaped and a
multibyte field, each pushing more owned updates past both bounds. They assert the persisted file
stays inside both halves of the window, that exactly one warning reaches the reader with a finite
elapsed count, that the newest update and chronological order survive, and that reader and writer
clamp to the same constant. The retained RED shows what they caught first: a 2,116,489-byte file
holding 256 records against a 131,072-byte reader window, and 9,427,849 bytes of escaped and multibyte
metadata. A window counted in characters rather than serialized bytes fails the second case, so the
escape and multibyte cases are what keep the byte count honest. The lane file
keeps a planted candidate note and
the leaf's own evidence and proves a hard deadline leaves both untouched, reports INCOMPLETE and arms
no surviving timer. The required-reference cases use a real temporary file: the positive case admits a
real readable file and asserts that the exact generated label and path reach the fake native request
and the one effective task, while every negative case — bare string, map, primitive entry, unknown
field, empty or overbound label, relative or overbound path, overbound count, missing path, directory,
unreadable, non-regular, and an absent metadata seam — is refused with zero dispatch, no preflight
call, no armed timer and the planted artifact preserved. The unreadable branch is driven through the
injected metadata probe in both readers, because a mode-000 file is genuinely readable to a root
process and a permission bit would prove nothing there; the real-fs branches (missing, directory,
regular readable file) run the shipped probe unpatched.
One case refuses the structured `{ label: "", path }` shape over a real readable file — not the
primitive `['']` entry — in both readers, then drives the shipped entry point with that exact config
path and asserts it emits nothing, and runs the CLI to assert zero spawns and nothing written; the
identical file under a non-empty label is admitted by both readers, so the label is what is refused.
A FIFO-without-writer cannot be probed in the test runner itself without an unbounded wait there, so
one bounded subprocess control does it instead: the child imports the real controller, runs the real
probe over a real `mkfifo` FIFO that no writer ever opens, and then builds the real controller around
it with the probe unpatched, under a 15 s wall clock. The retained RED is that control hitting the
bound — `ETIMEDOUT` at 15,000 ms, killed mid-probe — because the shipped probe opened before it
checked regularity; after the fix the same control reports non-regular metadata refused, zero preflight
calls, zero dispatch and no persisted dispatch record, in about 90 ms. The root process never opens
that FIFO. A platform without a named pipe reports a skip with the reason, never a silent pass.
Metadata admission proves neither later availability nor content approval, and the retained control
covers one POSIX FIFO rather than every non-regular file type.
A read-only
smoke on root's own installed Pi ran from
`/tmp/hylja-overnight-2026-10-04/native-helper-live-smoke` (receipt, dispatch, progress and
verification records beside it). It exercised launch and evidence plumbing on a reviewer lane, and its
`receipt.json`, `verification.json`, and the `subagent-artifacts/` `*_0_meta.json` and `*_output.md`
next to them are the public schema those fixtures and refusals are written against. It is not code
approval, and independent review of this helper is still pending. No throughput claim has been
measured.

## Evidence lookup

One run searched `~/.pi` while its launch carried an explicit `--session-dir`, then reported the model
and run ID unavailable; the metadata was in that session's `subagent-artifacts/` all along. Read the
paths the launch supplied. Never rebuild an artifact filename from a remembered pattern: a guessed one
misses a run that exists and reads as absent evidence.

- The handoff carries what the launch or the run returned: the files named by `outputReference`,
  `outputPathMapping` or `artifactPaths`; otherwise the session directory the launch actually used,
  `sessionDir` or an external `--session-dir`, together with the child's `runId` and agent name.
- Given returned paths, open exactly those. Given only a session directory, list
  `{sessionDir}/subagent-artifacts/` once and take the entries whose name starts with
  `{runId}_{agent}`; the rest of each name comes from that listing, never from a schema. One run wrote
  `..._hylja-implementer_0_output.md` and a sibling `_0_meta.json`, so the assumed
  `{runId}_{agent}_output.md` names a file that does not exist.
- The `*_output.md` entry is the child's public final artifact and the `*_meta.json` entry its
  metadata: `runId`, `agent`, timing, usage, exit code, the resolved model and the resolved acceptance
  ledger. Those two plus the child's returned output are the evidence surface; the `.jsonl` entry, the
  raw native session transcript and provider reasoning blocks, stays closed.
- A supplied path that resolves to nothing is reported as unavailable, not replaced by a wider search.

A review handoff states, before the reviewer is dispatched, the exact retained paths of the RED and
GREEN check artifacts behind each changed behaviour, and names the expected evidence that does not
exist. The reviewer then reads those records instead of pausing to ask for them. A design or security
question still travels to a human through root; this routes evidence only.

Three reported figures stay distinct when the metadata is written up:

| Figure | Read it from |
|---|---|
| model that ran | the `model` field of the run's `*_meta.json`; its `requestedModel` is the request, and the `model:` frontmatter of [`hylja-implementer.md`](../../.pi/agents/hylja-implementer.md) declares an intent. Neither is runtime evidence |
| usage | the cumulative input, output and cache counters in that same metadata, or `/subagent-cost` for parent-plus-child totals |
| context size | a live window figure read as such, never a usage counter: a cumulative total bills every turn of the run, so quoting it as the context window overstates it |

## Historical: proposed execution brief for #147 (superseded, not a dispatch gate)

Kept verbatim for the record. Later issues and the user's authorization moved past this proposal, so
its text is history and not a current dispatch gate, admission rule or scope change; its stop
statement describes the state when it was written. Issue [#147](https://github.com/Marcus-Levin/hylja/issues/147)
stays the authority on whether that work is admitted or resumed.

For a human to accept before dispatch. It satisfies no acceptance item: the live checklist stays
authoritative, unsatisfied and blocking, and it adds no cancellation or timeout boundary.

**Outcome.** An optional one-check local Node subprocess wrapper around `checkEgress`: the parent can
withhold release, stay responsive and terminate a stalled check. Local lifecycle isolation only, not a
gateway, effect boundary, OS sandbox or RSS cap.

**Accepted authority.** [006](../decisions/006-adapter-first-multi-surface-core.md),
[007](../decisions/007-fail-closed-for-protected-egress.md),
[008](../decisions/008-minimize-raw-data-retention.md), the
[`src/egress-sentinel.ts`](../../src/egress-sentinel.ts) module header and its
[capabilities.md](../capabilities.md) row, and the bounded local subprocess pattern in
[`evaluations/README.md`](../../evaluations/README.md); read each status line first. Parent #88 stays
open; no proposed taxonomy or fidelity model is adopted.

**Bounded scope.** `src/egress-sentinel-process.ts`, `-worker.ts`, `-protocol.ts`,
`test/egress-sentinel-process.test.mjs`, `docs/contracts/egress-sentinel-process.md`, minimum Node shim
declarations, one capability row, one local-IPC limits clarification. No sentinel algorithm,
dependency, policy, test-budget, scheduling or provider-traffic change.

**Verifiable units, red then green.** (1) Protocol: framing, snapshot caps, response binding,
handle-registration refusals. (2) Worker and shims: fixed argv, minimal environment, one check per child.
(3) Lifecycle: spawn deadline, cancellation, stall termination, cleanup confirmation, quarantine.
(4) Snapshot copies: caller-mutation refusal, tenant/project/profile binding. (5) Tiny stdlib-only
synthetic child end to end: responsiveness, trickled-output deadline, positive control, restrictive
failures, planted diagnostic capture. (6) Contract, capability row, overhead limits.

**Commands**, existing [`package.json`](../../package.json) scripts: `npm ci --ignore-scripts
--no-fund`; per unit `npm run --silent build` then `node --test
test/egress-sentinel-process.test.mjs`; before review `npm run --silent check:fixtures`,
`npm run --silent check:docs`, `npm run --silent typecheck`, `npm test`, `npm run --silent
test:coverage`.

**Stops.** Product development is paused; this does not resume it. A genuine design
ambiguity in accepted authority stops the lane for a human; no required criterion moves into a
nonblocking design block.