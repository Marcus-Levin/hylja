# Synthetic end-to-end evidence route

Route only. This document points at the executable synthetic end-to-end runs that exist today, the
evidence record each one carries, and the exact command that runs it. It holds **no status, no
checkbox and no implementation claim of its own**: what the software implements and what it does not
lives only in [capabilities.md](../capabilities.md), and work status, priority and dependency order
live only in the GitHub issues ([#36](https://github.com/Marcus-Levin/hylja/issues/36) is the roadmap
checklist). Read a decision's status line before relying on it: [decision
010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) is **proposed**.

## The runs

Each row is a test file, the evidence contract describing its observable behaviour, and the focused
command. Tests import `../dist/*.js`, so build once before any of them.

| Run | Test | Evidence record | Focused command |
|---|---|---|---|
| Request send point ([#174](https://github.com/Marcus-Levin/hylja/issues/174)) | [`test/openai-request-sendpoint.e2e.test.mjs`](../../test/openai-request-sendpoint.e2e.test.mjs) | [openai-request-sendpoint-e2e.md](../contracts/openai-request-sendpoint-e2e.md) | `node --test test/openai-request-sendpoint.e2e.test.mjs` |
| Complete-response inspection ([#175](https://github.com/Marcus-Levin/hylja/issues/175)) | [`test/openai-response-inspection.e2e.test.mjs`](../../test/openai-response-inspection.e2e.test.mjs) | [openai-response-inspection-e2e.md](../contracts/openai-response-inspection-e2e.md) | `node --test test/openai-response-inspection.e2e.test.mjs` |
| Mapping round trip ([#176](https://github.com/Marcus-Levin/hylja/issues/176)) | [`test/mapping-roundtrip.e2e.test.mjs`](../../test/mapping-roundtrip.e2e.test.mjs) | [mapping-roundtrip-e2e.md](../contracts/mapping-roundtrip-e2e.md) | `node --test test/mapping-roundtrip.e2e.test.mjs` |
| HTTP framing round trip ([#209](https://github.com/Marcus-Levin/hylja/issues/209)) | [`test/openai-http-roundtrip.e2e.test.mjs`](../../test/openai-http-roundtrip.e2e.test.mjs) | [openai-text-sender.md](../contracts/openai-text-sender.md), [openai-text-response.md](../contracts/openai-text-response.md) | `node --test test/openai-http-roundtrip.e2e.test.mjs` |
| Complete-text request sender, KEEP and policy-selected whole-message MASK ([#218](https://github.com/Marcus-Levin/hylja/issues/218)) | [`test/openai-text-sender.e2e.test.mjs`](../../test/openai-text-sender.e2e.test.mjs) | [openai-text-sender.md](../contracts/openai-text-sender.md) | `node --test test/openai-text-sender.e2e.test.mjs` |
| Bounded local conversation owner: real sender, real receiver and the module's own loopback transport, one request, one guarded release ([#236](https://github.com/Marcus-Levin/hylja/issues/236)) | [`test/openai-local-conversation.e2e.test.mjs`](../../test/openai-local-conversation.e2e.test.mjs) | [openai-local-conversation.md](../contracts/openai-local-conversation.md) | `node --test test/openai-local-conversation.e2e.test.mjs` |
| Egress send point, earlier fixture evidence | [`test/egress-sendpoint.e2e.test.mjs`](../../test/egress-sendpoint.e2e.test.mjs) | [egress-sendpoint-e2e.md](egress-sendpoint-e2e.md) | `node --test test/egress-sendpoint.e2e.test.mjs` |
| Whole synthetic conversation: real detection, policy-selected whole-message MASK, both real fixed-worker children, one real loopback transfer and one KEEP-only release ([#228](https://github.com/Marcus-Levin/hylja/issues/228)) | [`test/openai-conversation.e2e.test.mjs`](../../test/openai-conversation.e2e.test.mjs) | [openai-text-sender.md](../contracts/openai-text-sender.md), [openai-keep-receiver.md](../contracts/openai-keep-receiver.md) | `node --test test/openai-conversation.e2e.test.mjs` |

```sh
npm ci --ignore-scripts --no-fund   # once per worktree; lockfile-driven, no lifecycle scripts
npm run test:e2e                   # every listed run in one command; check:fixtures and build run first
```

The listed files also match the `test/*.test.mjs` glob in the [`npm test`](../../package.json) script,
so the full suite reruns them. `npm run check:docs` and `npm run check:fixtures` cover the evidence
records and the tracked paths.

## What these runs are

Each one joins **already-shipped, accepted-v1 seams** inside one test file over explicitly synthetic,
invented, non-routable fixtures (`*.invalid`, loopback, made-up names). Nothing in `src/` changes
because of them, and no proposed module is wired into accepted classification, policy or an adapter.
Concretely:

- **Synthetic-only trusted context.** The `PolicyBoundary`, the pinned bundle and classification
  digests, the known-originals handle and the sentinel key are **supplied by the test**. They are
  trusted because a trusted integration would supply them, not because anything here authenticates a
  principal, workload, tenant membership, session or control plane. The modules under test still
  re-check every binding themselves.
- **Test-local current-record authority.** In the round-trip run the authoritative current mapping
  record, the authenticated subject, the grant and the clock are objects in the test process. They are
  not a database row, a transaction or a compare-and-set. Current-record freshness is host-side
  fixture logic the seams cannot supply on their own.
- **Literal key material, ephemeral fixtures.** DEK and HMAC key material are fixed byte arrays in the
  test. There is no KMS/HSM binding, no key wrap, rotation or provisioning. Ciphertext-holding
  fixtures are in-process, never written to disk or sent. Buffer-hygiene claims are best-effort
  JavaScript behaviour, not zeroization guarantees for copies inside native crypto, garbage-collected
  buffers or swapped pages, and the graph check over assertion operands is bounded, not a taint
  analysis.
- **Local loopback or in-memory capture only.** Where a socket exists it is `node:net` on `127.0.0.1`
  and an OS-assigned ephemeral port; where a capture exists it is an in-memory model-context capture of
  the sentinel's own private ALLOW copy. No provider traffic, no credential, no network, no real sink.

**These runs are not** a gateway, a vault, a broker, an authenticated caller, an adapter at a real send
point, KMS/HSM integration or production plaintext protection. They are not a held-out or scored
result, they authorize no freeze, custody, scoring, promotion or release, and they establish nothing
about any production path. Each is evidence for a seam, not an enforcement boundary; per
[capabilities.md](../capabilities.md#assurance-governance-and-release-seams), no adapter sits at a real
send point in this repository.

## What a test-only join carries

A new test file that joins unchanged accepted-v1 seams over synthetic fixtures carries its evidence
as pointers rather than as a new document: the test path and focused command from the table above, the
seam sources it exercises, and this document's shared limits cited rather than restated. The reviewed
head SHA, the run IDs, the model that actually ran and the real test counts go in the pull request,
where a reviewer can check them against the commit.

Write a normative contract when a change alters a runtime API or an obligation the seams are held to.
Composing already-contracted seams differently over a new fixture is not such a change.

## Synthetic seam integration is not the real M1/M2/M3 path

The plain-language distinction: what runs today is a **harness proving that existing pure seams
compose** over a fixture and that every other outcome sends or releases nothing. What remains is a
**gated path where a transformation, a vault and a gateway decide effects at real boundaries** with a
real transport behind them. Those two are not interchangeable, and no passing run above closes the gap.

The dated [E2E critical-path
proposal](proposals/2026-10-04/e2e-critical-path.md) sequences that path (M1 irreversible-only text
cloaking, M2 encrypted scoped reversibility, M3 local gateway and authorized round trip) and names the
gate each milestone needs before an integrated passing run. It is a **proposal dated 2026-10-04, not
current authority**; read it for sequencing, not for state. Remaining work stays at its live parent
issues [#13](https://github.com/Marcus-Levin/hylja/issues/13) through
[#22](https://github.com/Marcus-Levin/hylja/issues/22). The related specs are drafts: [slice
1](../specs/slice-1-text-cloaking-proof.md), [slice
2](../specs/slice-2-vault-and-reversible-identities.md), [slice
3](../specs/slice-3-openai-compatible-gateway.md).

## Human gates, separate from runnable evidence

Two gates are **not** runnable work and nothing above satisfies or waives either:

- **Taxonomy and task-fidelity adoption.** The information dimensions, taxonomy and transformation
  semantics exist only as proposed records: [decision
  010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) (`proposed`), tracked by
  [#65](https://github.com/Marcus-Levin/hylja/issues/65),
  [#66](https://github.com/Marcus-Levin/hylja/issues/66) and
  [#68](https://github.com/Marcus-Levin/hylja/issues/68). Accepted classification v1 keeps its current
  vocabulary. A green run, a merged test or a passing checker accepts nothing.
- **Prospective protocol freeze and scoring custody.** A frozen v0 protocol, an independent blind
  custodian, an accepted destination/task rubric and an approved pre-tuning chronology are open on
  [#39](https://github.com/Marcus-Levin/hylja/issues/39). The public synthetic runs above neither gate
  nor require that gate; they are development evidence, not held-out results.

## Where to go next

[docs/README.md](../README.md) has the task route map. For what any of the joined seams implements
today and its declared limits, read [capabilities.md](../capabilities.md) and the seam's own module
header rather than a restatement of it here.