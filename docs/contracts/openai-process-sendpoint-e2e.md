# OpenAI process send-point end-to-end evidence contract (#190)

Status: draft **evidence** contract for a test-only integration seam. It describes observable behavior of
[`test/openai-process-sendpoint.e2e.test.mjs`](../../test/openai-process-sendpoint.e2e.test.mjs) only. It is
**not** a gateway, an adapter, a transport, an authorization layer, a policy decision, a release control or
an OS-level resource bound. The seam it exercises is documented in
[egress-sentinel-process.md](egress-sentinel-process.md); implementation status lives only in
[capabilities.md](../capabilities.md).

Scope: wire the shipped strict text-only codec
([`translateOpenAiTextRequest`](../../src/openai-text-request.ts)), the shipped deterministic policy seam
([`decidePolicy`](../../src/policy.ts)) and the shipped **fixed-worker** local sentinel process runner
([`createSentinelProcessRunner`](../../src/egress-sentinel-process.ts)) together inside one test file, and
connect that seam to a real loopback TCP sink on an OS-assigned ephemeral port. Nothing in this file is
production code and nothing in `src/` changes.

## What the fixtures are, and are not

- The trusted boundary, the policy bundle and its pinned digest, the classification evidence, the sentinel
  key and the known-original registration are **trusted-test supplied fixtures**. They are not authenticated
  identities, not a control plane and not a broker. The modules under test still re-check every one of them.
- The child is the module's **fixed compiled sibling**, resolved from `import.meta.url`. There is no
  configurable worker, no mock checker and no in-thread fallback anywhere in this file: a check that did not
  run in a real child simply withholds the release.
- The sink is a **synthetic loopback** endpoint on `127.0.0.1` and an ephemeral port. It is not a provider,
  not a gateway, not a product adapter and not a production send point. No request leaves the machine.
- The wire image is built by a **test-local serializer** over the translated draft. That is serialization, not
  treatment: the send point implements no transformation at all.
- The run is **unscored and non-enforcing**. It is not a public evaluation record, not a held-out result and
  not promotion evidence.
- Every value is invented and obviously synthetic: `*.invalid` names, loopback, a made-up person and host.

## What this evidence proves, and what it does not

Proves, for these narrow synthetic fixtures only: a byte reaches the sink only when the codec translated a
complete text request, the real policy decision was `SELECTED` with treatment `KEEP`, and the **real child
process** returned `ALLOW` over the exact serialized image, **metadata included**. Every other outcome is
zero bytes **and** zero connections at the sink.

Does **not** prove protected egress. The seam authenticates nobody, holds no credential, trusts no caller,
binds no real routed destination, caps no memory, CPU or process count, and enforces no rule beyond what the
shipped seams already enforce. A passing run is a passing lifecycle, withholding and privacy test, not an
enforcement proof and not an OS-sandbox result.

## Accepted path

An accepted, complete, non-streamed text request translates, a trusted-boundary `decidePolicy` selects `KEEP`,
the fixed child returns `ALLOW` over the exact serialized bytes, and the sink receives exactly the
**independently declared** literal wire image — which a reviewer can read in the test and compare with what
arrived, without running the pipeline. The downstream synthetic utility fixture still finds the literal
protocol `https` and the literal port `443` in the received body, which is what proves the accepted path
**keeps** text intact instead of rewriting it. An explicit `stream: false` request produces the same image.

The only representation that may be sent is the runner's private ALLOW copy. A caller buffer rewritten with a
planted value after the check changes neither the released copy nor a single received byte.

## Refusal paths, all zero contact

| Stage | Case | Observable result |
|---|---|---|
| sentinel child | planted `ORIGINAL` in the checked image | `SENTINEL_BLOCK` / `KNOWN_ORIGINAL_DETECTED` with the registered ref, no release, no connection |
| sentinel child | planted `CANARY` reintroduced in the metadata | `SENTINEL_BLOCK` / `CANARY_DETECTED` with the registered ref, no release, no connection |
| sentinel child | observed destination id, or observed profile digest, that the decision did not authorize | `SENTINEL_BLOCK` / `DESTINATION_MISMATCH`, no release, no connection |
| runner lifecycle | `cancel()` observed first on a genuinely active check | `CANCELLED`, no release, runner returns to `IDLE` and remains usable |
| runner configuration | unsupported own key, or a deadline below the module's floor | `INVALID_REQUEST` before any child exists, runner `IDLE`, no connection |
| request snapshot | an omitted registration, or a registration whose own scope differs | `INVALID_REQUEST` before any child exists, runner `IDLE`, no connection |

Zero contact is asserted as a fixed triple plus an empty capture list: zero requests, zero accepted
connections, zero received bytes. A block is never converted into a send, and an absent check is never
converted into a pass.

## Determinism, ownership and privacy bounds

- Cancellation is **runner-owned and deterministic**: the check is started and cancelled in the same
  synchronous turn, so the stop is observed before the fixed child can answer. There is no injected clock.
- Every await in the file is bounded and **every timer and socket is owned**: an await this file creates is
  cleared on both the success and the failure path, and the sink destroys its sockets before it closes.
  Correctness never depends on a sleep.
- Assertions carry fixed counts, codes and booleans only. Byte images are compared with `Buffer.equals` and
  reported as a boolean, so a failing assertion cannot print a buffer or a planted value into TAP output. No
  refusal, decision, sentinel finding or captured request is asserted to contain a planted value.

## Deliberately absent

No gateway, no authentication, no credential handling, no provider SDK, no HTTPS, no real destination, no
transformation, no original restoration, no scoring, no enforcement, no subprocess framing or lifecycle
matrix (those live in [`test/egress-sentinel-process.test.mjs`](../../test/egress-sentinel-process.test.mjs))
and no codec or policy refusal matrix (those live in
[`test/openai-request-sendpoint.e2e.test.mjs`](../../test/openai-request-sendpoint.e2e.test.mjs)). The codec under test
remains non-enforcing per [the text request contract](openai-text-request.md); the policy seam remains a pure decision
surface per [the policy contract](policy-contract.md); the runner remains an optional local lifecycle wrapper,
not an effect boundary, per [the sentinel process contract](egress-sentinel-process.md).

Evidence:

```
npm run build
node --test test/openai-process-sendpoint.e2e.test.mjs test/openai-request-sendpoint.e2e.test.mjs
```
