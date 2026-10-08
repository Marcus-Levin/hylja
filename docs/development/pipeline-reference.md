# Development pipeline reference

On-demand reference for [pipeline.md](pipeline.md). Read only the named branch: guard, installation,
retry policy, native lane CLI or evidence lookup. The historical #147 proposal is not a dispatch gate.
Workers need only their role body and supplied inputs, unless the brief names a section here.

## Workflow guard

`.pi/extensions/hylja-workflow-guard.ts` is a Pi adapter over the pure helper
`.pi/lib/hylja-command-guard.mjs`; both are developer tooling, and neither is in the tracked typecheck
or build scope (`tsconfig.json` includes `src/**/*.ts`). It exists because one run spent eight minutes
on `find / -name hylja-implementer.md` after the exact path had been supplied; a prompt alone did not
prevent the recurrence.

Two protections—search scope and bash timeout arguments—decided before execution. Ordinary
installation logs neither:

| Call | Decision |
|---|---|
| `find` with a machine-wide absolute root | blocked with a fixed reason naming the allowed roots |
| `timeout` omitted on a builtin bash call | set to 120 s, Pi's builtin bash having no default |
| `timeout` present, 0 < t <= 300 | preserved unchanged |
| `timeout` > 300 s, ordinary installation or unmatched approval | clamped to 300 s |
| exact approved session cwd and whole command, explicit `timeout` > 300 s | clamped to 600 s |
| `timeout` malformed, non-finite or <= 0 | blocked with a fixed reason |
| any other tool | untouched, and no timeout applied |

The default export/load path always installs the ordinary guard above; profiles are unchanged.
A coordinator-owned run wrapper may explicitly import `installHyljaWorkflowGuard` from the same
adapter and call `installHyljaWorkflowGuard(pi, { cwd, commands })` instead of installing the default.
The approval is one exact absolute session cwd (at most 4096 characters, no control characters) and
one or two distinct nonempty whole command strings (at most 16384 characters each, no NUL).
Validation commands are standalone canonical `npm test` or `npm run test:coverage` invocations,
possibly with coordinator-owned fixed PATH, log, exit and elapsed recording. Setup may reserve one
slot for the harmless qualification probe below; do not chain validation commands into any slot.
Command safety is a coordinator obligation, not parsed or verified by the guard. There is no general ceiling option, config discovery, environment inference,
repository marker or model-supplied authorization.

Installation validates and privately snapshots the record and array once. Missing approval keeps
ordinary behaviour; malformed approval throws the fixed `Invalid Hylja validation approval` before
registering any handler, with no partial grant or input echoed. Mutation after installation cannot
widen the snapshot. Only exact equality of `ctx.cwd` and the entire command string selects the fixed
600 s explicit ceiling: no normalization, shell parsing, substring or wrapper inference. Whitespace,
extra commands, changed logging and a different cwd all retain 300 s. Omitted timeout remains 120 s,
positive values through 300 s remain unchanged, and malformed timeout and forbidden machine-wide
find remain refused even for an approved string. The same helper owns all refusal decisions.
The guard authenticates nobody and cannot verify shell safety or coordinator authority; trusted
run-owned configuration is not a new authorization boundary. Root owns native-load smoke and any
subsequent expensive validation; these tests execute no approved shell commands.

**Native qualification.** A run wrapper can opt into fixed startup and applied-timeout receipts with
`installHyljaWorkflowGuard(pi, { cwd, commands }, true)`. The factory registers callbacks only;
`appendEntry` belongs in `session_start` or `tool_call`, after Pi binds its runtime. Receipt failure
sticks for that installation and returns a fixed bash block; it does not rely on the host propagating
hook exceptions. Receipts contain a version and, for allowed bash calls, the applied numeric timeout;
no command, raw argument, output, cwd or protected value is recorded. Other tools remain untouched.
The receipt describes this adapter's decision, not later hooks, hard preemption or descendant closure.

A fourth argument `{ hardStopMs, reserveSeconds }` adds executable admission against a snapshotted
absolute UTC stop: `hardStopMs` is a positive safe-integer epoch millisecond; `reserveSeconds` is an
integer from 0 through 86400 including remaining required work and reporting margin. The adapter
reads fresh UTC at each allowed bash call and requires its applied cap plus that fixed reserve to fit
(rounding fractional milliseconds up). Exhaustion, invalid time or clock rollback closes the window
permanently for that installation. Other tools remain untouched. Root must choose the stop within all
applicable deadlines and a conservative reserve; this does not discover native deadlines, track
completed work, enforce the final backend launch time, preempt a running command or prove cleanup.

Before expensive work, inspect available load errors and qualify the same native installation with
finite positive timeout inputs. `# SYNTHETIC-GUARD-PROBE; find /` with 15 s must receive the guard's
fixed machine-wide-search refusal; it is entirely a shell comment if the guard is absent. A zero
timeout can be rejected by Pi itself and proves no hook execution. For an approved 600 s ceiling,
reserve one exact command slot for a fixed harmless `printf` probe and bind its runtime receipt and
successful result from the same unchanged installation; configuration or a mock receipt is not native
execution. A probe is an explicit setup effect, never an extra validation grant. Check fresh UTC again
before the real command.
When native deadline fields are unavailable, provide a conservative absolute lane stop whose bound
is earlier than every applicable native cap; record the derivation before dispatch rather than waiting
for a field the public API does not expose. Unknown qualification still stops dependent effects.

Wiring: the adapter takes the `tool_call` handler context and forwards `ctx.cwd` as the session
directory, because a foreground child runs inside the parent process where `process.cwd()` is the
coordinator's directory, not the child's worktree.

Wiring: project extension discovery loads it for the coordinator (`<cwd>/.pi/extensions/`), and every
role profile, the writer fallback included, declares
`extensions: ../extensions/hylja-workflow-guard.ts`, an allowlist that keeps
ambient extensions off in a foreground child while the host-required child extensions, the registered
providers and the builtin tools still resolve. The relative entry resolves against the agent file's own
directory, which is what pi-subagents does for a path-like `extensions` entry; the profiles' other
settings are unchanged.

Search discipline remains a prompt obligation: use supplied entry points; when a pointer is absent,
search only the worktree or a brief-named root. Scoped `find .`, `find src` and `grep` remain allowed.
Treat a refusal as a setup finding, not an invitation to retry through another quoting, wrapper or
executable. The [coordinator procedure](pipeline.md#coordinator-procedure) owns the delivery clock;
the guard adjusts a single call's timeout, not the lane budget.

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
discovery, the timeout default, preservation, ordinary and approved clamps, exact-command/cwd mismatches,
malformed setup refusal, snapshot mutation, independent forbidden-find refusal, opt-in receipt lifecycle
and sticky receipt failure, window snapshots, equality/late admission and sticky clock rollback,
that no other tool is mutated, and that each role profile's declared path resolves to an existing file. The load path itself is proven by a
native smoke run, not by this document.

## Install and use

Prerequisite: native Pi with `pi-subagents` loaded (`pi list`). Role configuration is the frontmatter of
[`.pi/agents/hylja-implementer.md`](../../.pi/agents/hylja-implementer.md),
[`.pi/agents/hylja-reviewer.md`](../../.pi/agents/hylja-reviewer.md) and
[`.pi/agents/hylja-implementer-sol61.md`](../../.pi/agents/hylja-implementer-sol61.md);
`~/.agents/pstack-models.md` is untouched. Tested installation: pi-subagents 0.75.0 on Pi 1.0.0, whose release notes record the fix for
background children failing on Pi 1.0.0 with a missing `@earendil-works/pi-agent-core/node` export;
0.74.0 does not work on Pi 1.0.0. Foreground children do not depend on that fix. Nothing is added to
install: the workflow guard and the optional native lane CLI are already tracked in this repository,
they live outside the tracked build and typecheck scope, and they add no new package dependency.

- Interactive: `/skill:hylja-development` forces the project skill; `/reload` after editing it.
- Headless: `--no-skills --skill .agents/skills/hylja-development` loads only that skill; without
  `--no-skills`, every discovered global skill is also eligible for automatic selection.
- Grant project trust once: `/trust`, or `--approve`.
- Launch according to the [coordinator procedure](pipeline.md#coordinator-procedure). Leaf profiles
  retain `async: false`; a top-level async workflow does not change those pins. Each profile's
  `extensions:` allowlist disables ambient extensions while retaining the project guard, builtin
  tools, registered providers and host-required child extensions.
- Another checkout needs no installer: copy each `principle-*/SKILL.md` from the pinned upstream
  pstack commit into `~/.agents/skills/<name>/`, MIT license kept.

The historical background run exceeded its budget without a result. Coordinator workflow mode is
not evidence of child completion, ordering or timely closure; inspect actual terminal receipts.

## Retry and fallback policy

The handoff states the applicable policy; task/session restrictions override these standing defaults.
Recovery preserves the original delivery window and failed-round count, not a fresh budget.

- A transient provider error waits 2.5 s and retries unchanged in the same session, provider and model;
  record an unresolved failure with its message. A stricter no-retry task disables this default.
- Only root may explicitly dispatch the dedicated writer fallback after the default writer route
  actually failed and its child settled. Exit 2, INCOMPLETE or missing acceptance evidence is not a
  provider outage. Preserve the prior worktree and uncommitted work; use fresh context and evidence
  paths. A task forbidding fallback overrides this exception. No child or CLI selects it automatically.
- A launch, extension, tooling or workflow failure blocks that lane. Preserve its partial diff and
  report the exact failure and run/cwd/ref before a permitted same-protocol retry. Switching to the
  native lane CLI or another execution protocol requires explicit owner authorization.

## Native lane CLI

`.pi/lib/hylja-native-lane.ts` (the opt-in controller) and `scripts/development/run-native-lane.mjs`
(the root-owned CLI) are developer tooling, outside the tracked build and typecheck scope exactly as the
guard adapter is. Root runs one lane with `node scripts/development/run-native-lane.mjs --config
<absolute config.json>`. The CLI launches Pi once with the three extensions named in its config, the one
fixed input the controller answers, and the one structured foreground delegation call into
`pi-subagents`. No coordinator model takes part in that process; nothing here is a measured speedup,
and a run under this CLI is still one lane: no model override, no background mode, no automatic role
fallback, no nesting, and no child that launches another lane.

The [dedicated writer fallback](../../.pi/agents/hylja-implementer-sol61.md) is admitted by `agent`.
Both `checkInstall` and `verifyArtifacts` require its exact model pin; the default writer/reviewer
checks require only a `:max` suffix plus profile/preflight/metadata equality, so the suffix check alone
admits a foreign `:max` route. This is not general failover. The CLI never retries, re-routes or carries
an attempt forward, and leaves refused/timed-out work and evidence intact. Dispatch permission belongs
to [Retry and fallback policy](#retry-and-fallback-policy). Like the default writer, this role's
`writerAcceptanceGate` is not approval and `acceptanceProvesApproval` stays `false`.

The config is root-owned, bounded and absolute. Every path field must start with `/`; `key` and `task`
are non-empty text (`task` capped at 1 MiB); `agent` is `hylja-implementer`, `hylja-reviewer` or
`hylja-implementer-sol61`; `timeoutMs` is a positive integer no greater than that role profile's own
frontmatter deadline; an
optional `softBudgetMs` is a positive integer strictly below `timeoutMs`; an optional
`requiredReferences` list is described below; a `model` key is refused rather than ignored.

**How the config is read is part of that bound.** It is read through one descriptor the CLI owns and
closes on every path: metadata first, then one non-blocking read-only open, then the opened
descriptor's own type and size, then exactly one read of at most 65,537 bytes. The window is bytes,
not decoded characters, and the single byte past it is the oversize signal, so a config that only fits
by character count is refused rather than truncated and parsed. That one read must also be complete: it
has to deliver every byte the opened descriptor reports, because a truncated config can still be a
parseable JSON prefix followed by bytes that are not JSON. A short read is therefore refused with no
retry and no repair, never admitted as the prefix it delivered. The close belongs to the same
admission. It is attempted on every path, and a close that fails withholds the bytes already read:
this process does not report cleanup it did not get. A path that is not a regular file, one that
becomes non-regular between the metadata check and the open, one past the window, one whose read falls
short of its own descriptor, one whose close fails, bytes that are not UTF-8, and a read that fails are
all `SETUP_FAILED_LANE_CONFIG` with zero children, one fixed record and nothing echoed, because no
watchdog exists yet to bound a wait. Withholding the bytes on a failed close is a refusal of the read,
not a claim that the descriptor was closed anyway. That is a claim about a POSIX host that carries
`O_NONBLOCK` and about the bytes this process allocates, reads and attempts to release; it is not a
bound on I/O latency against a remote or otherwise slow filesystem, and not a guarantee about what a
concurrent writer changes between the stat and the open.

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
(INCOMPLETE), `3` the leaf finished non-completed. What is printed alongside them is fixed: a setup
refused before any child is launched prints exactly one bounded JSON line carrying only the fixed
`verdict` and the fixed setup code — never a config path, a task, a declared reference, a detail or a
thrown message — so an exit 2 is never silent and cannot be read as a lane that never ran; a launched
lane prints its one full verification record and nothing else. A `completed` leaf is not approval: the
verdict is only the leaf's own literal `APPROVED`, `CHANGES REQUESTED` or `INCOMPLETE` line.

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

Acceptance is reported, never assumed. A direct-API run of either writer role or of the reviewer resolves
`not-required`, because each role profile disables the native writer gate through the deprecated `false`
shorthand, so the
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
Shutdown schedule: the watchdog latches the deadline and stops the CLI's own child one minute
past the native request timeout, sends SIGTERM, then SIGKILL after 10 s, then schedules at most 10 s
more for `close`. These timer/signal steps do not prove hard preemption of a stalled event loop,
all-descendant closure or private erasure.

**When `softBudgetMs` is configured** (and only then): the child learns the two numbers once, in its
initial task, as one role-aware paragraph — reviewer: report a literal verdict and stay read-only;
writer, fallback writer included: finish the checks, commit, then report — and that paragraph grants no
authority the role body does not already carry. Root receives exactly one bounded numeric
`soft_budget_reached` progress
snapshot at the soft budget, which appears in the verification record's `progress` array. That snapshot
is pinned inside both halves of that window: when a busy leaf's own later updates would push it out of
the tail root reads after the child exits, it joins as the oldest survivor and the ordinary records it
displaces are dropped from the oldest end, so neither bound is raised, the surviving records keep
their chronological order and the newest updates are the ones kept. Pinning it costs the window
nothing it was already allowed to keep, and it is a warning for the reader and nothing more: it is
never delivered to the running child, and
it never cancels, kills, deletes, resets or approves anything. The shutdown schedule above is
unchanged. A lane that reaches it reports INCOMPLETE with `deadlineExceeded: true`, keeps its
worktree, receipt, dispatch, progress and artifact files for recovery, and is never an approval; a
recovery handoff must name the exact source SHA whose tree the resumed lane runs, so a resumed lane is
provably the same code and not a re-implementation of it.

**Evidence.** Focused checks for this branch, run from the worktree root with this repository's
dependencies installed:

```bash
node --test test/hylja-native-lane.test.mjs
node --test test/hylja-workflow-guard.test.mjs
```

Both files are in `npm test`, so a green CI run at the reviewed head already contains them. The
normative contract is the section above; its executable evidence is:
[`hylja-native-lane.test.mjs`](../../test/hylja-native-lane.test.mjs) writes config admission,
evidence binding, the deadline and progress window, and the fallback role as cases over the real
controller, CLI, filesystem and signal adapters, a fake Pi event API, a fake preflight module, a fake
native transport and synthetic temporary directories, plus bounded subprocess controls over a real
`mkfifo` FIFO and real spawned CLI processes;
[`hylja-workflow-guard.test.mjs`](../../test/hylja-workflow-guard.test.mjs) writes the guard's two
guarantees, its fixed reasons and each role profile's declared extension path. Counts, durations and
retained RED logs belong to the run that produced them and the pull request that reports them; this
page caches none.

Honest limits: no case needs a local Pi installation, calls a provider, reaches the network or reads a
session transcript; one case type-checks the controller with the repository's own TypeScript because
`tsconfig.json` does not cover `.pi/`; the FIFO control covers one non-regular file type, and a
platform without a named pipe reports a named skip rather than a silent pass. A green run proves the
paths those cases drive and nothing beyond them: not an installed Pi, not a real lane, not throughput,
and not approval.

## Evidence lookup

Use returned paths rather than rebuilding filenames or searching a session store. Run-id prefixes
and artifact suffixes vary; unavailable evidence is not permission for a machine-wide search.

- The handoff carries what the launch or the run returned: the files named by `outputReference`,
  `outputPathMapping` or `artifactPaths`; otherwise the session directory the launch actually used,
  `sessionDir` or an external `--session-dir`, together with the child's `runId` and agent name.
- Given returned paths, open exactly those. Given only a session directory, list
  `{sessionDir}/subagent-artifacts/` once and take the entries whose name starts with
  `{runId}_{agent}`; take the remaining suffix from that listing, never from an assumed schema.
- The `*_output.md` entry is the child's public final artifact and the `*_meta.json` entry its
  metadata: `runId`, `agent`, timing, usage, exit code, the resolved model and the resolved acceptance
  ledger. These and the returned output are the routine evidence surface; raw native sessions and
  provider reasoning stay closed.
- A supplied path that resolves to nothing is reported as unavailable, not replaced by a wider search.

A review handoff states, before the reviewer is dispatched, the exact retained paths of the RED and
GREEN check artifacts behind each changed behaviour, and names the expected evidence that does not
exist. The reviewer then reads those records instead of pausing to ask for them. A design or security
question still travels to a human through root; this routes evidence only.

Three reported figures stay distinct when the metadata is written up:

| Figure | Read it from |
|---|---|
| resolved model | the run's `*_meta.json` `model` field; `requestedModel` and profile frontmatter are intent. A resolved launch without a successful serving receipt does not establish actual serving or effort; report that limit |
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