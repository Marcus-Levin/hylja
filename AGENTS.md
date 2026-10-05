# Working on Hylja

This file guides agents developing this repository. It keeps Hylja's authority, security, and evaluation requirements and adds the practical workflow discipline adapted from Pi's agent guide: read before you edit, run the real pinned commands, stage explicit paths, report honest evidence, and review the exact head independently. See [Attribution](#attribution) for the pinned upstream source and the scope of the adaptation.

## Find the relevant authority

Before implementation, read [docs/charter.md](docs/charter.md), [docs/architecture.md](docs/architecture.md), [docs/security-model.md](docs/security-model.md), [docs/threat-model.md](docs/threat-model.md), [docs/evaluation.md](docs/evaluation.md), and what the software implements today in [docs/capabilities.md](docs/capabilities.md). Then use the [task route map](docs/README.md#task-route-map) to reach the exact slice, contract, decision, source and test for your task. Read the current slice in [docs/specs](docs/specs/) and the **status line** of every decision in [docs/decisions](docs/decisions/) you rely on.

One fact has one authoritative home. What is implemented and its limits belong only in [docs/capabilities.md](docs/capabilities.md); work status, priority and dependency order belong only in GitHub issues ([#36](https://github.com/Marcus-Levin/hylja/issues/36) is the roadmap checklist); dated measurements and their attribution live with the pull request or research record that produced them. Do not copy any of these into architecture, README, or research documents; link to the home instead. Research is evidence, not authority. Accepted design changes get a new decision record rather than silently rewriting history.

A record marked **proposed** has no authority until a human accepts it. Do not wire a proposed decision, draft taxonomy, or draft information model into accepted runtime classification or policy, an adapter, or authoritative evaluation labels, scoring, and promotion, and do not weaken an accepted v1 contract or the held-out protocol to make a draft fit. An isolated, clearly labeled, non-enforcing draft module or test on synthetic data is allowed while its proposed status stays visible in its own record. Check the status line of every decision record you rely on.

## Security invariants

- Never add real customer, employee, infrastructure, secret, credential, or production mapping data to the repository, fixtures, logs, snapshots, or issue bodies.
- Synthetic examples must be obviously synthetic and non-routable where possible (`example.com`, `.invalid`, documentation IP ranges).
- A semantic model may classify, score, or recommend. Deterministic policy and authorization decide effects.
- No adapter may bypass the Policy Engine for convenience.
- No failure in semantic classification may make protected egress less restrictive.
- USE does not imply DISPLAY; DISPLAY does not imply EXPORT.
- Secret/credential detection defaults to block or irreversible redaction; do not create reversible password/API-key mappings by default.
- Never create a direct bulk mapping lookup API. Original values are resolved through the broker under purpose-bound authorization.
- Keep plaintext lifetimes short. Do not log raw protected values or model traffic by default.
- Cross-tenant token, key, mapping, cache, or synthetic-identity resolution is a security defect.

## Communication

- Keep answers short, direct, and technical. No fluff, no emoji in commits, issues, PR comments, or code.
- Explain a non-trivial design or defect as problem, concrete example or short trace, then solution. Say why the solution is required and separate it from optional complexity.
- When the user asks a question, answer it first, then make edits or run commands.
- When responding to feedback or a review, state explicitly whether you agree or disagree before describing what you changed.
- Work in the harness and with the model the user selected for the run, and name what actually served the request, including any fallback or routing. Never claim a review, run, or model you did not perform.
- Report limits honestly. "Not proven here" is a valid, expected result.

## Inspect before you edit

- Read files in full before wide-ranging changes, before editing a file you have not fully inspected, and when investigating or auditing. Search snippets are for locating code, not for judging it.
- Check installed type declarations in `node_modules` (and the repository's own `src/*.d.ts` shims) for external API shapes; do not guess.
- Ask before deleting functionality that looks intentional. This repository is unreleased, so removing a contract is a design change, not a compatibility chore — but say so explicitly rather than dropping it quietly.
- Keep TypeScript strict and its syntax narrow: no `any` unless unavoidable, no dynamic type imports, no `enum`, `namespace`/`module`, `import =` or `export =`, and no loosening `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, or `verbatimModuleSyntax` to make code compile. The constructor parameter properties in the existing fixed-code error classes are accepted; `erasableSyntaxOnly` is deliberately not enabled, so do not rewrite boundary error classes for style.
- Treat untrusted input at the boundary: validate once, snapshot what you will inspect repeatedly (do not re-enumerate a caller object you already capped), bound sizes, and return fixed, non-echoing errors that never carry planted values back to the caller.

## Boundaries

Hylja is TypeScript on Node.js. Keep the core provider- and harness-independent: the harness you happen to work in is a property of the run, never a product dependency. Model, MCP, shell, file, skill, and harness integrations live behind narrow adapters; an adapter translates a native surface into normalized interaction events and owns no privacy policy. Prefer pure functions for parsing, classification composition, policy, and transformations so they can be property-tested and replayed.

A core module is not an enforcement boundary by itself. A pure policy, audit, or sentinel module that authenticates nothing and sends no bytes is evidence for a seam, not proof of protected-egress safety; say which one you delivered.

## Commands

Install exactly as CI does: `npm ci --ignore-scripts --no-fund` (Node 24, npm 10, lockfile-driven, no lifecycle scripts).

- `npm run check:fixtures` — tracked-path and synthetic-fixture guard. Run it before committing anything touching `test/fixtures/**`, `.gitignore`, or generated output.
- `npm run build` — compiles `src/**/*.ts` into `dist/`. Tests import `../dist/*.js`, so build before running any test.
- `npm run typecheck` — `tsc --noEmit` under the same strict config.
- `npm test` — fixture guard, build, then `node --test` over the suite list in [package.json](package.json). Read the script before quoting a count; the suite list changes.
- `npm run test:coverage` — the same tests with Node coverage. These numbers measure contract exercise, not enforcement, coverage of production traffic, or release safety.
- `node --test test/<name>.test.mjs` — bounded focused run while iterating, after a build.
- `node evaluations/preparation-integrity.mjs` — the public, non-enforcing preparation scaffold. Intact state exits 0 with `PREPARATION_VALID_BUT_NOT_ELIGIBLE / PUBLIC_DRAFT_ONLY`; that status never authorizes scoring, custody, a freeze, or release.
- `npm run audit:deps`, `npm run sbom` and `npm run check:sbom` — CI gates. The SBOM is ephemeral; never commit it or other generated output (`dist/`, `coverage/`, `artifacts/` are ignored).

[package.json](package.json) `scripts` is the one canonical command list and [.github/workflows/ci.yml](.github/workflows/ci.yml) the one canonical step sequence; verify any command you document here against both before writing it down, and quote CI run links rather than asserting a green run you did not see.

No test or script may call a real provider API, use real credentials, reach the network for model traffic, or read private or held-out data. Put ad-hoc scratch scripts in a temp file, run them, and delete them; do not embed long scripts inline in shell commands.

## Tests and evidence

Every security-sensitive feature ships with evaluation evidence: deterministic tests for known invariants, property-based tests for transformations and tenant isolation, adversarial cases for bypasses, and end-to-end utility tests where cloaking can change reasoning. A skipped or placeholder cross-tenant test is not foundation evidence.

- Write the failing behavior test first when you add or change a contract, and keep the red checkpoint as evidence of what the test actually caught.
- Validate the change you made: focused file first, then the full CI sequence when the change touches shared core, policy, crypto, provenance, or serialized bytes. Do not run broad suites for prose-only changes.
- Prose-only changes need no new test, and a test that greps implementation or documentation text is not evidence for a document.
- Fixtures stay obviously synthetic and non-routable. Under the guard, only `test/fixtures/synthetic-golden/` may contain credential-like assignments, and only with obviously synthetic values (`synthetic-*.invalid`).
- Record what you actually ran, the real pass counts, and the explicit unproven surface. Report it in the pull request or the research record that owns the work; update [docs/capabilities.md](docs/capabilities.md) only when the implementation or a durable limit itself changed.
- Public docs, public fixtures, and public research are **not** a held-out suite. Do not optimize a detector against the held-out suite: never tune questions, thresholds, or detectors against held-out data. A production miss becomes a sanitized regression case; it does not automatically alter policy.

## Dependencies

- Keep direct dependencies pinned to exact versions (no `^` or `~`). Treat dependency and `package-lock.json` diffs as reviewed code.
- Refresh lockfile metadata with `npm install --package-lock-only --ignore-scripts`; never run lifecycle scripts unless the user asks.
- Read the release notes for an update whose behavior change could affect parsing, crypto, or policy, and evaluate the effect before applying it.
- Keep CI action references pinned. Do not add a dependency to make a test easier without saying why the existing toolchain cannot.

## Git, worktrees, and parallel sessions

Multiple sessions may work on this repository at once, each in its own branch and worktree. Any git operation that touches unstaged, staged, or untracked files outside your own changes can destroy someone else's work.

- Work on the branch and worktree assigned to you. Do not switch, reset, or rebase another session's worktree.
- Stage explicit paths (`git add <path> <path>`); never `git add -A` or `git add .`. Run `git status` before committing and confirm you staged only your files.
- Never run `git reset --hard`, `git checkout .`, `git clean -fd`, a blanket `git stash` without a pathspec, `git commit --no-verify`, or force-push, and never stage or discard unrelated unowned uncommitted work. Assigned read-only inspection of another session's commits or shared authorized inputs is expected, not a violation.
- If you own a specific in-progress change that is blocking you, preserve just those paths reversibly (`git stash push -- <path>`) and name them. Restore them when you resume that work, or record that the preservation is superseded; do not reapply it over newer published state just to clear the record. Never blanket-stash or blanket-reset, and never treat a stash as a place to park another session's work.
- On rebase or merge conflicts, resolve only files you modified, and only inside your own checkout. If a conflict lands in a file you did not modify, leave that file alone, record the exact path, branch, and commit, then coordinate with the owner or orchestrator and continue the rest of your authorized integration work instead of stalling. Escalate only genuine ownership ambiguity, a destructive choice, or an accepted design change beyond your authorization.
- Commit messages are concise and technical (`docs:`, `fix:`, `feat:`), no emoji, and state the behavior change. Never commit generated artifacts or lockfile churn you did not cause.
- Clean up only what you own: a branch or worktree may be removed once its accepted evidence is merged or recorded in its pull request and issue. Preserve commits, evidence references, and linked issue/PR numbers.

## Delegation, review, merge, and issues

- Keep implementation and review separate. When review is delegated, it must be a different agent working from the pushed or shared state, not the author's own summary.
- The delegated implementer/reviewer lanes for this repository are documented in [docs/development/pipeline.md](docs/development/pipeline.md), entered through [.agents/skills/hylja-development/SKILL.md](.agents/skills/hylja-development/SKILL.md) and the two role agents in [.pi/agents/](.pi/agents/hylja-implementer.md). That path adds process only: it changes no rule in this file and no contract.
- Review and approve an exact head SHA. A reviewed SHA that has since changed is not a review of the current head.
- Report the exact SHA, the commands you actually ran with their results, and the honest remaining limits. Never manufacture approval, and never present AI review as the human design gate.
- Merge only with the user's explicit authorization, exact-head approval, and green CI at that head. Proposed design (decision records, drafts, contracts, taxonomies) needs human review before it is wired in.
- Close an issue only when its acceptance criteria are satisfied, and reference issues explicitly (`closes #N`, one keyword per issue) so closure is not accidental.
- Never push, open or merge a PR, or close or edit issues when the task assigns those actions to someone else; prepare the evidence and hand it over.

## Instruction precedence

Current user and session instructions, and the task's stated authorization, govern. Standing authorization for ordinary work — implement, test, and commit on your own branch — persists across steps; do not ask again before each routine action. Do all concrete, reversible work the authorization already covers before asking anything. Ask only where the needed authorization or an actual human adoption gate is missing, or where the action would destroy another session's work or history. Dependencies and contract changes are reviewed code inside an authorized scope, not a reason to stop. Higher-priority instructions always win over this file.

## Attribution

Adapted ideas (workflow structure, communication and git discipline) derive from Pi's `AGENTS.md` at the pinned commit [`25cc5c7bf4cbc76b2e134c729eb8d57d521ed749`](https://github.com/earendil-works/pi/blob/25cc5c7bf4cbc76b2e134c729eb8d57d521ed749/AGENTS.md), MIT licensed. Pi's monorepo paths, commands, generated-model rules, and upstream rules are deliberately not carried over. This attribution covers only the adapted portions; the rest of this file is Hylja's own and no upstream license is claimed over it.

```text
MIT License

Copyright (c) 2025 Mario Zechner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
