# OpenAI request send-point end-to-end evidence contract (#174)

Status: draft **evidence** contract for a test-only integration seam. It describes observable behavior of
[`test/openai-request-sendpoint.e2e.test.mjs`](../../test/openai-request-sendpoint.e2e.test.mjs) only. It is
**not** a gateway, an adapter, a transport, an authorization layer, a policy decision, a release control or
a transformation engine. Implementation status lives only in [capabilities.md](../capabilities.md).

Scope: wire the shipped strict text-only codec
([`translateOpenAiTextRequest`](../../src/openai-text-request.ts)), the shipped deterministic policy seam
([`decidePolicy`](../../src/policy.ts)) and the shipped independent sentinel
([`checkEgress`](../../src/egress-sentinel.ts)) together inside one test file, and connect that seam to a
real loopback TCP sink on an OS-assigned ephemeral port. Nothing in this file is production code and nothing
in `src/` changes.

## What the fixtures are, and are not

- The trusted boundary, the policy bundle and its pinned digest, the classification evidence, the known-originals
  handle and the sentinel key are **trusted-test supplied fixtures**. They are not authenticated identities,
  not a control plane and not a broker. The modules under test still re-check every one of them themselves.
- The sink is a **synthetic loopback** endpoint on `127.0.0.1` and an ephemeral port. It is not a provider, not
  a gateway, not a product adapter and not a production send point. No request leaves the machine.
- The wire image is built by a **test-local serializer** over the translated draft. That is serialization, not
  treatment: the send point implements no transformation at all.
- The run is **unscored and non-enforcing**. It is not a public evaluation record, not a held-out result and not
  promotion evidence. The deliberate upstream miss in one case is counted as a miss, never as recall success.
- Every value is invented and obviously synthetic: `*.invalid` names, loopback, a made-up person name and host.

## What this evidence proves, and what it does not

Proves, for these narrow synthetic fixtures only: a byte reaches the sink only when the codec translated the
request, the real policy decision was `SELECTED` with treatment `KEEP`, and the sentinel returned `ALLOW` over
the exact serialized image. Every other outcome is zero bytes **and** zero connections to the sink.

Does **not** prove protected egress. The seam authenticates nobody, holds no credential, trusts no caller,
enforces no rule beyond what the shipped seams already enforce, and stands in for no
[slice 3](../specs/slice-3-openai-compatible-gateway.md) gateway. It is a test-harness
result, not an enforcement boundary.

## Accepted path

An accepted, complete, non-streamed text request translates, a trusted-boundary `decidePolicy` selects `KEEP`
for a `PUBLIC` candidate, the sentinel allows the exact bytes, and the sink receives exactly the independently
declared wire image. A downstream synthetic utility fixture then reads the received body and still finds the
literal protocol `https` and the literal port `443`, which is what proves the accepted path **keeps** text
intact instead of rewriting it. An explicit `stream: false` request produces the same serialized image.

The returned allowed copy is the sole representation sent. A caller buffer rewritten with a planted marker
after the check does not change a single received byte.

## Refusal paths, all zero contact

| Stage | Case | Observable result |
|---|---|---|
| codec | `stream: true`, tools, unknown field, unsupported role, duplicate key | fixed refusal code, no release, no connection |
| codec | any endpoint other than `/v1/chat/completions` | `ENDPOINT_NOT_SUPPORTED`, no connection |
| policy | `DENIED` (block rule) or `HELD` (review rule) | no release, no connection |
| policy | `SELECTED` with a treatment other than `KEEP` | withheld: this seam transforms nothing |
| policy | mismatched destination, mismatched tenant, wrong classification digest, wrong bundle digest, missing boundary | `DENIED`, no release, no connection |
| sentinel | planted original the primary evidence missed, in the body or reintroduced in metadata (including encoded) | `KNOWN_ORIGINAL_DETECTED`, no release, no connection |
| sentinel | outage, unusable check input, unauthorized destination or profile, cross-tenant known-originals handle | restrictive reason, no release, no connection |

The primary-evidence miss and the independent sentinel catch are asserted as **separately named** outcomes: the
miss is `detectSecrets(...).candidates === []` on the planted text, and the catch is
`reason === ['KNOWN_ORIGINAL_DETECTED']` from the sentinel over the same bytes that would have gone on the wire.

## Leak and determinism bounds

No refusal, decision, sentinel finding or regression record is asserted to contain a planted original or any
prefix of one, and the assertions carry fixed privacy-safe labels so a leak cannot be echoed into TAP output.
Every socket read is driven by a declared `Content-Length`, so completeness is observed rather than guessed.
Cleanup and every await are bounded by a deterministic deadline; there are no sleeps and no timing-based
correctness claims.

## Deliberately absent

No gateway, no authentication, no credential handling, no provider SDK, no HTTPS, no real destination, no
transformation, no original restoration, no scoring, no enforcement, and no part of
[#21](https://github.com/Marcus-Levin/hylja/issues/21). The codec under test remains non-enforcing per
[the text request contract](openai-text-request.md); the policy seam remains a pure decision surface per
[the policy contract](policy-contract.md); the sentinel remains the last independent check per
[the threat model](../threat-model.md) and [the evaluation protocol](../evaluation.md).

Evidence: [`test/openai-request-sendpoint.e2e.test.mjs`](../../test/openai-request-sendpoint.e2e.test.mjs), run
with `npm run build && node --test test/openai-request-sendpoint.e2e.test.mjs`.