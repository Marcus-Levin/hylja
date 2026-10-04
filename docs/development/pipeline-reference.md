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