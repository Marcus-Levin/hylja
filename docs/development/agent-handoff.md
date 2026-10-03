# Bounded developer handoff

`scripts/development/agent-handoff.mjs` is developer tooling for handing work between sessions and tasks
in this repository. It answers four narrow questions inside a configured byte budget, so a task does not
guess what exists, does not pull a raw external response into model context, does not start an unbounded
comparison, and does not have to describe a session it cannot read. Tracking: [#137](https://github.com/Marcus-Levin/hylja/issues/137).

It is **not** Hylja runtime core and not a security boundary. `src/` imports nothing from here,
`src/index.ts` exports none of it, it adds no dependency, it selects no model or harness, it stores no
orchestration policy, and it authenticates nobody. What it produces is developer evidence, not an
authoritative classification, policy decision, evaluation label or adoption record. See
[capabilities.md](../capabilities.md) for what the software itself implements.

## Commands

```sh
npm run --silent agent:handoff -- capabilities
npm run --silent agent:handoff -- project-github --input response.json --kind issue
npm run --silent agent:handoff -- compare HEAD:docs/plan.md docs/plan.md
npm run --silent agent:handoff -- session-handoff --input inventory.jsonl
node scripts/development/agent-handoff.mjs --help
```

Use `--silent`, or the direct `node` command, whenever stdout is consumed as one JSON document. npm writes
its own banner and script header around a normal `npm run`, and that output is not part of the cap the
helper guarantees.

| Command | What it answers | What it never does |
|---|---|---|
| `capabilities` | which optional commands exist on `PATH`, with resolved paths, the work tree, and **name presence only** for a small set of environment names | run, install, authenticate or configure any of them; read an account, credential or authentication file; read, test or emit an environment value |
| `project-github` | the state, labels, refs, timestamps and counts of a GitHub JSON response, within a byte cap | print, log or commit the raw response, a body, a title, a comment, a patch or an author login |
| `compare` | whether two documents are identical by Git blob identity, and which line numbers differ with per-line digests | print source text; run an unbounded diff; spawn an unbounded process |
| `session-handoff` | which sessions exist, which are user chats and which are workers, their ids, opaque primary-log locators, fork/resume edges, and which are inaccessible | open, read, summarise or export a session log, a transcript or hidden reasoning; scan for sessions; guess a kind or an access state |

## Options

Every bound is configurable inside a fixed range. A value outside the range is the refusal
`option-out-of-range`, never a silent clamp.

| Option | Applies to | Default | Range |
|---|---|---|---|
| `--max-output-bytes N` | all | 4096 | 256 - 262144 |
| `--timeout-ms N` | all | 5000 | 1 - 120000 |
| `--max-raw-bytes N` | `project-github`, `session-handoff` | 8388608 | 1024 - 33554432 |
| `--input <path\|->` | `project-github`, `session-handoff` | `-` (stdin) | - |
| `--capture <dir>` | `project-github` | none | - |
| `--kind <kind>` | `project-github` | `auto` | `auto`, `issue`, `pull`, `list`, `comment` |

Bounds that are not options, exported as `LIMITS` for tests: 500 inventory records, 500 GitHub records,
64 labels, 20 line proofs, 16777216 scanned bytes per operand, 120 characters per scalar and 400 per
path. An inventory or a response above its record bound is refused with `records-above-bound`, not
sliced down to the bound with a completeness claim.

`session-handoff` accepts `{"sessions": [...]}`, a bare JSON array, JSONL with one record per line, or a
single record object on its own, which is a one-row inventory in both the JSON and the JSONL reading.

## Output contract

- stdout is one compact JSON document with **no trailing newline**, and its UTF-8 byte length never
  exceeds `--max-output-bytes`. `--help` is the only unbounded text output.
- Every projected value is a bounded printable-ASCII scalar, a safe integer, a boolean, or a value from a
  fixed vocabulary. A value of any other shape is dropped, never truncated into something that looks valid.
- Reduction is explicit, ordered and identity-preserving. Every record is kept at the richest field tier
  that fits; only if no tier fits every record are records dropped, and then at the identity tier, largest
  count first. `output.tier` names the tier, `output.fieldsProjected` names the surviving fields and
  `output.fieldsWithheld` counts the schema fields that tier excluded — a count of names in the whitelist,
  not of supplied keys. A supplied key only appears there if the record actually has it.
- Loss accounting describes what happened, not what was eligible. `output.truncated` is true for **any**
  loss the budget forced: a withheld field or a dropped record.
- `omitted.*` counts the supplied key occurrences of the records that were **projected**, and each count is
  the disposition of that key in the **selected (final) projection** — the tier and record set that were
  actually printed. Records the budget dropped are reported by `recordsOmitted` / `sessionsOmitted` and are
  outside this scope. This is an output-disposition summary, not a command-wide inspection audit. Every
  occurrence lands in exactly one category:

  | Category | Meaning in the selected projection |
  |---|---|
  | `projectedKeys` | validated and emitted as its own output field |
  | `derivedKeys` | emitted inside another field, a session relationship edge |
  | `groupedKeys` | placed the session in an emitted group (`kind`), reported apart from derivation |
  | `rejectedKeys` | refused by the selected tier: wrong shape, unknown enum, unsafe length, or a self relationship |
  | `withheldKeys` | a whitelisted key the selected tier excluded, so nothing was emitted from it |
  | `contentKeys` / `credentialKeys` / `otherKeys` | outside the whitelist: never read, counted by class only |

  Those counts always sum to `omitted.inputKeys`. `project-github` derives and groups nothing, so it
  reports no `derivedKeys` or `groupedKeys` category at all rather than reporting a structural zero.
  `valuesReadFromOmittedKeys` is `false` and describes the three class-counted categories only: no value
  behind one of those is ever read, which is why counting them cannot mean reading them. It says nothing
  about whitelisted fields.
- **Fitting may inspect whitelisted metadata that the final output does not contain.** To choose a tier the
  helper first tries richer projections, and reading a whitelisted field is part of that attempt. A value
  can therefore be read and validated while a richer tier was being tried and then be withheld — or
  rejected — by the tier that was finally selected, so `withheldKeys` means "not emitted", not "never
  inspected". This applies only to whitelisted metadata. The content, credential and other-key classes stay
  excluded from reading entirely, in every attempt.
- A cap smaller than the mandatory envelope is the refusal `output-cap-unrepresentable`. A result that
  cannot state what it dropped is not returned.

```json
{"tool":"agent-handoff","command":"project-github","limits":{"outputBytes":4096,"rawBytes":8388608,"timeoutMs":5000},
 "output":{"capBytes":4096,"truncated":true,"tier":0,"fieldsProjected":["id","number","state"],
 "fieldsWithheld":15,"recordsRead":200,"recordsProjected":12,"recordsOmitted":188,"recordsIgnored":0},
 "kind":"list","items":[{"id":2000,"number":0,"state":"open"}],
 "omitted":{"inputKeys":48,"projectedKeys":36,"rejectedKeys":0,"withheldKeys":0,"contentKeys":12,
 "credentialKeys":0,"otherKeys":0,"valuesReadFromOmittedKeys":false},
 "raw":{"printed":false,"captured":false,"capturePath":null},
 "notes":["Only the whitelisted metadata fields are read. ..."]}
```

## Refusals

A refusal prints one fixed code on stderr and no input-derived value, and prints no partial result:
`agent handoff: refused; <code>` (exit 1) or `agent handoff: budget; <code>` (exit 3).

| Code | Cause |
|---|---|
| `usage-invalid`, `option-out-of-range` | unknown command or option, missing operand, bound outside its range |
| `command-unavailable` | a `rev:path` operand was requested and `git` is not on `PATH` |
| `input-unreadable`, `input-malformed`, `input-above-raw-bound`, `input-not-a-regular-path` | the bounded stdin or file read failed, did not parse, exceeded `--max-raw-bytes`, or was not a regular file |
| `input-shape-mismatch` | the response shape does not match `--kind` |
| `session-record-invalid`, `records-above-bound` | a record is not an object or has no safe id (the record index is reported, never its content); an inventory or a GitHub response is above the record bound |
| `capture-directory-unusable`, `capture-verification-unavailable`, `capture-inside-work-tree`, `capture-inside-repository`, `capture-exists` | see below |
| `operand-unresolvable`, `operand-not-a-regular-path`, `operand-above-scan-bound` | a comparison operand is missing, is a symbolic link or non-regular file, or is above the scan bound |
| `output-cap-unrepresentable` | the cap cannot hold the mandatory envelope |
| `command-budget-exceeded`, `scan-budget-exceeded` | a spawned `git` or the line scan exceeded `--timeout-ms` |

## Privacy and safety properties

- **One command, bounded.** The only command ever spawned is `git`, with an argv array, no shell, and the
  configured timeout, and only when the `PATH` lookup found it: `capabilities` runs one
  `rev-parse --show-toplevel`; `compare` may run `rev-parse`, `cat-file` and `hash-object`. Every Git probe
  runs with `gitProbeEnvironment()`, a fresh object per call holding a `PATH` (plus `SystemRoot` and
  `PATHEXT` on Windows) and nothing else, so an inherited `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`,
  `GIT_OBJECT_DIRECTORY`, `GIT_INDEX_FILE`, `GIT_CEILING_DIRECTORIES`, `HOME` or any credential variable
  cannot answer for it. The object is deliberately not frozen or shared: Node's `child_process` assigns
  `NODE_V8_COVERAGE` onto the environment object it is handed when that variable is set in the caller,
  which is how `node --test --experimental-test-coverage` covers a program that spawns with a restricted
  environment. A frozen object would make that assignment throw and turn a coverage run into a refusal.
  Availability is resolved by a `PATH` lookup that never executes the candidate, so a command reported
  unavailable is never invoked.
- **Whitelist projection.** `project-github` reads only the fields named in `GITHUB_FIELDS`, and only their
  values, and only as far as a chosen tier needs them. Every key outside that list is counted by class and
  its value is never read, in any attempt. Bodies, titles, comments, patches, diff hunks, file paths in a
  diff and author logins are not projected at all. Native GitHub keys are accounted under the keys a
  response really has: `head` and `base` are read through their `ref` child and reported as `headRef` /
  `baseRef`, so they are projected occurrences, not unread ones. In `session-handoff` the grouping key
  `kind` and the two edge keys are read too, and each is reported by what it produced in the selected
  projection: an emitted group, an emitted edge, or a refusal. A whitelisted field read while a richer tier
  was being tried is reported only by the disposition of the tier finally selected; see the fitting note
  above.
- **Raw stays out of context.** The raw response is never printed. `--capture <dir>` stores it as
  `github-response-<sha256 prefix>.json` with mode `0600`, and refuses a missing, symlinked or
  group/world-writable directory, and any existing destination. A rerun of the same response is therefore
  `capture-exists`, not an overwrite.
- **Capture containment is physical, not inherited.** Before writing, the destination's real path is walked
  to the filesystem root without running Git, and **every** directory in that chain is checked twice: for
  Git's own metadata entries `HEAD` / `config` / `objects` / `refs`, which is what a bare repository has and
  a work tree has not, so a bare root and any directory beneath it are refused
  (`capture-inside-repository`); and for a `.git` entry, which covers a normal repository, a linked worktree
  and a submodule alike (`capture-inside-work-tree`). Any ancestor that cannot be examined fails closed with
  `capture-verification-unavailable`. The sanitized Git probe runs afterwards only as a cross-check, and
  cannot override the walk in either direction.
- **No session content.** `session-handoff` accepts explicit safe metadata only. A primary-log locator is
  carried through as an opaque string and is never opened. Transcript, message, reasoning, prompt and
  credential-shaped keys are outside the whitelist: they are dropped and counted, and their values are never
  read at any tier. Fork and resume edges are reported as `resolved: false` when the referenced id is not in
  the inventory; a self reference or an unsafe value is refused and counted as `rejectedKeys` rather than as a
  relationship; and an unlisted kind or access state is reported as unknown rather than guessed. The optional
  whitelisted fields follow the fitting note above: a locator or timestamp may be inspected while a richer
  tier was tried, and withheld by the tier finally selected.
- **Environment presence is by name.** `capabilities` reports whether a listed environment name is defined
  and never reads, tests or emits its value. That says nothing about whether a credential exists, is
  non-empty, is valid or is accepted by any service.
- **Bounded comparison.** Identity first: a Git blob object id when `git` is available, otherwise a
  SHA-256 prefix computed in process. Identical identities skip the scan entirely. Otherwise the scan is one
  linear pass under an active deadline, and a proof is a line number with per-line digests. Both operands
  are bounded by refusal before they are read, so a reported scan is complete over both of them and says
  so with `scan.complete`; a difference in operand length is a content difference, reported in
  `left.bytes` / `right.bytes`, and is not labelled a truncation. There is no character-level quadratic
  diff and no source text in the output.
- **No echoing.** Diagnostics are fixed codes. Planted values in a response body, an inventory transcript
  or an unsafe identifier stay out of stdout, stderr and the exit status;
  [`test/agent-handoff.test.mjs`](../../test/agent-handoff.test.mjs) asserts this on every case.

## Material limits

- An inventory is what a human curated. This tool cannot discover sessions, cannot tell a deleted session
  from an inaccessible one, and does not reconcile an inventory against the tracker. An access shortfall is
  reported as `access: inaccessible`, never resolved by inference.
- A projection is a bounded summary of a public API response. It is not a substitute for reading an issue
  when the decision needs its body, and it cannot detect a field the whitelist does not know about.
- A comparison proves byte or line identity, not meaning. Two documents can differ in every proof and be
  equivalent prose. Because each operand is bounded by refusal rather than truncated to a prefix, there is
  no partial-scan case: an operand above the scan bound is refused rather than partially compared.
- The counts in `omitted.*` are dispositions of the selected projection over the retained records. They are
  not an inspection audit: this tool does not report which values were read while fitting a tier, and a
  `withheldKeys` occurrence may have been read during a richer attempt. Only the three class-counted
  categories carry a never-read guarantee, and that guarantee holds for every attempt.
- The minimum output cap that fits depends on the envelope, which the loss accounting above made larger
  than the first version: one GitHub envelope at the identity tier is about 810 bytes and one session
  envelope about 970. A cap below that is `output-cap-unrepresentable`, not a reduced result.
- Git blob identity is `git hash-object` identity: it does not apply filters, so a working-tree file whose
  committed form differs by an end-of-line or clean filter compares as different. That is a property of the
  command, not a defect in the tool, and the line proofs are the fallback.
- Availability is a POSIX-shaped `PATH` lookup. A command installed outside `PATH`, a shell function or an
  alias is reported unavailable.
- No claim is made about coverage, scale or performance beyond the bounds above. The bounds are per
  process, with no aggregate CPU or memory limit.

## Tests

[`test/agent-handoff.test.mjs`](../../test/agent-handoff.test.mjs) is wired by the existing
`test/*.test.mjs` glob and covers, on synthetic data only: an unavailable `gh` that must not be executed,
an empty `PATH`, a slow `git` against the child timeout, an injected clock against the scan deadline, a
200-record response against a 1024-byte cap, the 500/501 record-bound boundary, identity retention under a
tight cap, field-only loss reported as truncation, key accounting that sums to `inputKeys` for both
commands and counts only retained records, rejected values, consulted `head`/`base` keys, an emitted
`kind` grouping and refused relationship edges, a capture refused inside a work tree under an inherited
`GIT_DIR`/`GIT_WORK_TREE` override, inside Git metadata storage, in a descendant of a bare repository, on
an unverifiable ancestor, and on rerun, a capture still accepted beside a bare repository, one-row JSONL,
planted transcript, reasoning and credential keys, environment presence by name, an unequal-length complete
comparison, and a Git-blob comparison that must not print a line. The unreadable-ancestor case needs a
non-root process; as root it reports itself as skipped rather than passing. One case runs the helper with
`NODE_V8_COVERAGE` set, which is the state the coverage runner creates, so the probe's environment handling
stays exercised in an ordinary run instead of only under `npm run test:coverage`.
