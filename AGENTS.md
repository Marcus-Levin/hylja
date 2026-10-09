# Working on Hylja

Standing rules for Hylja work. Product knowledge lives in the docs tree; start from
[docs/README.md](docs/README.md). Attribution at the end.

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
- When the user asks a question, answer it first, then make edits or run commands.
- On feedback or a review, state whether you agree or disagree before describing what you changed.
- Never claim a review, run, or model you did not perform. Report limits honestly; "not proven here" is a valid result.

## Working rules

- Read files in full before wide-ranging changes and before editing a file you have not fully inspected. Search snippets locate code, not judge it.
- Check installed type declarations in `node_modules` (and the repository's `src/*.d.ts` shims) for external API shapes; do not guess.
- Ask before deleting functionality that looks intentional. Removing a contract is a design change, so say so explicitly rather than dropping it quietly.
- Keep TypeScript strict and narrow: no `any` unless unavoidable, no `enum`, no `namespace`/`module`, no `import =`/`export =`, and never loosen `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, or `verbatimModuleSyntax` to make code compile.
- Validate untrusted input once at the boundary, snapshot what you inspect repeatedly, bound sizes, and return fixed non-echoing errors.

## Boundaries

Hylja is TypeScript on Node.js. The core stays provider- and harness-independent: the harness you work in is a property of the run, not a product dependency. Model, MCP, shell, file, skill, and harness integrations live behind narrow adapters that own no privacy policy. A pure module that authenticates nothing and sends no bytes is evidence for a seam, not proof of protected-egress safety; say which one you delivered.

## Commands

Install exactly as CI does: `npm ci --ignore-scripts --no-fund` (Node 24, npm 10).

- `npm test` — fixture guard, build, then `node --test` over the suite in package.json; read the script before quoting a count.
- `npm run test:coverage` — same with coverage; contract exercise, not production coverage.
- `npm run build`, `npm run typecheck` — compile `src/**/*.ts` and typecheck under the strict config.
- `npm run check:fixtures`, `npm run check:docs`, `npm run check:diagnostic-assertions` — static gates.
- `npm run audit:deps`, `npm run sbom`, `npm run check:sbom` — CI gates; never commit generated output.
- `node --test test/<name>.test.mjs` — bounded focused run while iterating, after a build.

[package.json](package.json) `scripts` and [.github/workflows/ci.yml](.github/workflows/ci.yml) are canonical. No test or script may call a real provider API, use real credentials, reach the network for model traffic, or read private or held-out data. Put ad-hoc scratch scripts in a temp file, run them, and delete them.

## Tests and evidence

- Write the failing behavior test first when you add or change a contract, and keep the red checkpoint as evidence of what the test caught.
- Validate focused file first, then the full CI sequence when the change touches shared core, policy, crypto, provenance, or serialized bytes.
- Fixtures stay obviously synthetic; only `test/fixtures/synthetic-golden/` may contain credential-like assignments, and only with `synthetic-*.invalid` values.
- Record what you actually ran, the real pass counts, and the explicit unproven surface. Update [docs/capabilities.md](docs/capabilities.md) only when implemented behavior or a durable limit itself changed.

## Dependencies

- Keep direct dependencies pinned to exact versions; treat dependency and lockfile diffs as reviewed code. Refresh metadata with `npm install --package-lock-only --ignore-scripts`; never run lifecycle scripts unless the user asks.
- Read the release notes for an update whose behavior change could affect parsing, crypto, or policy. Keep CI action references pinned.

## Git, worktrees, and parallel sessions

Multiple sessions may work on this repository at once, each in its own branch and worktree. Any git operation that touches files outside your own changes can destroy someone else's work.

- Work on the branch and worktree assigned to you; never switch, reset, or rebase another session's worktree.
- Stage explicit paths; never `git add -A` or `git add .`. Run `git status` before committing and confirm you staged only your files.
- Never run `git reset --hard`, `git checkout .`, `git clean -fd`, a blanket `git stash`, `git commit --no-verify`, or force-push, and never stage or discard unowned uncommitted work.
- On conflicts, resolve only files you modified. A conflict in a file you did not modify stays untouched; record path, branch, and commit, then coordinate.
- Commit messages are concise and technical (`docs:`, `fix:`, `feat:`), no emoji, and state the behavior change. Clean up only branches and worktrees you own.

## Delegation and merge

- Execute directly unless delegation is authorized. Delegated lane roles are configured in `.pi/agents/`; keep implementation and review separate, and a reviewer works from the pushed or shared state, not the author's summary.
- Review and approve an exact head SHA. A SHA that has since changed is not a review of the current head.
- Merge only with the user's explicit authorization, exact-head approval, and green CI at that head. Never present AI review as the human design gate.
- Close an issue only when its acceptance criteria are satisfied, with an explicit `closes #N` reference. When a task assigns publication to someone else, prepare the evidence and hand it over; never push, merge, or edit issues on their behalf.

## Instruction precedence

Current user and session instructions and the task's authorization govern; higher-priority instructions win. Work toward one observable outcome within scope. Ordinary implementation, tests, and commits on your own branch remain authorized across steps: complete that reversible work without renewed permission prompts. Escalate missing authority, human adoption gates, and risks to another session's work or history.

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
