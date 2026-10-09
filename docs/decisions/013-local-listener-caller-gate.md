# Decision 013: One local listener capability, not production identity

Status: accepted technical direction by explicit project-owner approval, 2026-10-05.
The owner authorized the recommended narrow local-access design and implementation;
this acceptance covers the bounded synthetic milestone below, not production risk or release.
Implementation is tracked in [#261](https://github.com/Marcus-Levin/hylja/issues/261).

## Context and authority

A loopback HTTP surface adds an inbound caller to the composed local conversation path.
Network location cannot confer trust ([security model](../security-model.md#identity-and-access)).
This decision narrows access to one local capability; it does not fulfill the production
caller/workload authentication required by [#21](https://github.com/Marcus-Levin/hylja/issues/21)
or adopt the [draft gateway slice](../specs/slice-3-openai-compatible-gateway.md).
Implementation and durable limits belong in [capabilities](../capabilities.md);
status and dependency order belong in [#36](https://github.com/Marcus-Levin/hylja/issues/36).

Supporting accepted direction: [001](001-enforcement-core-not-advisory-filter.md),
[003](003-semantic-judgment-does-not-own-effects.md),
[006](006-adapter-first-multi-surface-core.md),
[007](007-fail-closed-for-protected-egress.md),
[008](008-minimize-raw-data-retention.md),
[009](009-secrets-are-not-synthetic-identities.md), and
[011](011-policy-selected-whole-message-mask.md) (accepted delegated technical direction).
The [conversation](../contracts/openai-local-conversation.md),
[sender](../contracts/openai-text-sender.md) and
[receiver](../contracts/openai-keep-receiver.md) retain their contracts unchanged.

## Decision

1. One listener binds literal `127.0.0.1`, one host-provisioned random bearer capability,
   and one pinned host context: subject, tenant/project/session, purpose, profile,
   policy commit and numeric-loopback upstream. Requests cannot override any of these.
   Loopback is exposure reduction, never identity or authorization.
2. Possession gates local access only. It authenticates neither a human/workload nor
   tenant membership, validates no host boundary, and cannot satisfy #21 production
   authentication. Existing host proofs and inspection remain host obligations;
   capability possession must not be minted into an authenticated-principal proof.
   This synthetic milestone is bounded-lifetime: all pinned sender/receiver evidence
   windows cap usable life; a fresh owner renews no proof and context pinning preserves
   no freshness. Reused requestProof is a harness premise, not per-request authentication.
3. Different listeners require different capabilities. Reuse is misconfiguration,
   not automatic context or tenant isolation. Provision using cryptographic randomness
   of at least 256 bits; syntax validation cannot prove entropy.
4. After construction retain only the capability digest in listener-owned storage;
   compare fixed-length digests in constant time. Require exactly one unambiguous
   bearer Authorization header; absent, forged, malformed or duplicate auth denies.
   Never forward auth. Never store tokens in git, logs, command-line examples or
   diagnostic assertions. Tests use only obviously synthetic tokens and non-echoing
   assertions. Host-owned copies remain a provisioning obligation, not heap-erasure proof.
5. Each accepted request gets a fresh conversation owner and a privately bound response
   socket. The listener supplies `onReply`; neither caller nor host may provide it or
   retarget the sink. Reuse #236 unchanged, including real policy and fixed sentinel
   children. No listener classification or policy authority is introduced.
6. Bound and validate HTTP input; ignore harmless unknown headers without forwarding.
   Refuse authority/route-claiming headers, duplicates and ambiguous framing. Unknown
   endpoints/body fields refuse before upstream; unsupported content stays unsupported.
   Use fixed non-echoing errors: deterministic input/auth/policy refusals are 4xx;
   502/504 are only upstream/transport availability, never a known-original oracle.
   Policy/sentinel reasons specific to planted strings are never exposed.
7. Bound admission, reads and resources, cancel in-flight work and dispose owned sockets
   and children. Existing `cancel()` is sticky, not an awaitable drain/dispose API;
   shutdown guarantees require explicit lifecycle evidence, not assumptions.
   Local process compromise remains out of scope; no OS sandbox or host validation claim.

## Exclusions and consequences

No provider credential, restoration, broker, persistence, multi-tenant service, default
clean classification, policy widening, or adoption of proposed
[010](010-separate-information-dimensions-and-task-fidelity.md).
A zero detector finding is never clearance. Generic default classification requires a
separate proposal and human gate; fixture labels are not general classifiers.
Whole-message masking proves privacy mechanics, not reasoning utility.

Listener before [#17](https://github.com/Marcus-Levin/hylja/issues/17) is a bounded proof
choice: irreversible KEEP/MASK resolves no mappings. Parent #21 dependencies remain unchanged.
The 2026-10-05 planning brief that preceded this record was a proposal, not authority; this record is the accepted gate. The admitted child issue supplies runtime scope, prerequisites and acceptance; this record changes no runtime behavior by itself.

## Acceptance scope and intended product proof

The owner's approval adopts only this narrowly described local-capability access model,
explicitly excluding production identity and inspection authority. Implementation still needs
behavior-first evidence, independent exact-head review and green CI; merge needs explicit
authorization. The draft slice and proposed decision 010 remain unadopted.
Success would be one non-streamed OpenAI-shaped HTTP client completing a guarded exchange
against a synthetic loopback upstream within the intersection of pinned evidence windows,
not a long-lived operational gateway. This child proves neither a real OpenAI SDK nor
coding-agent utility, production authentication, provider integration or bypass resistance.
Generic inspection, tools/streaming, real provider integration and utility evidence remain
later milestones under their own gates and the [evaluation policy](../evaluation.md).
