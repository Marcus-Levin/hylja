# Envelope-only source inspection — 2026-10-09

Preliminary, source-only, non-enforcing evidence for [#45](https://github.com/Marcus-Levin/hylja/issues/45), not a conformance result or design decision. [Capabilities](../capabilities.md) is the only current implementation-status home; the issue owns work status and acceptance. This record adopts no design and completes no parent acceptance gate.

## Candidate and method

Candidate source: `b03c30fe13ce938db80abc4ca9b81cb688039e50` (tree `149fe03193b29b538ee8ab6163c12d75a2dc21e5`). No tested harness, configuration or harness version exists here.

| Inspected input | Exact blob |
|---|---|
| [src/interaction-envelope.ts](../../src/interaction-envelope.ts) | `ef8566c6b54ffaef8ec4a6db1d4395af62b0e13c` |
| [test/interaction-envelope.test.mjs](../../test/interaction-envelope.test.mjs) | `d874a2405851f032f3e2eeec53519a57975da121` |
| [interaction-envelope contract](../contracts/interaction-envelope.md) | `77c0cd7a5f7c744ecda9eae805f7c6034418bb8a` |

The retained envelope-only preparation checkpoint ran `2026-10-09T10:06:30.147Z`–`10:11:59.189Z`; native author duration was 328939 ms, with 34 tool calls. Root accepted source preparation, **not APPROVED** or independent review. Its full governance/source/test/contract reads preceded its once-only fixed developer-search refusal. Initial/final source identity checks at `10:08:45Z`/`10:09:20Z` each recorded actual exit 0 and the same clean candidate identity. Their timestamp deltas were 0 seconds at one-second resolution, not subsecond measurements. Fresh product tests: **0**; existing test titles below are definitions, not observed passes. Prose RED/GREEN: N/A.

Retained evidence identifiers: `ENVELOPE_SOURCE_CHECKPOINT`, `ISSUE45-ENVELOPE-SOURCE-ROOT-DISPOSITION`, and `01-initial-identity.log`/`02-final-identity.log`. The separately admitted docs author independently read these inputs and the complete named governance, contracts, source, tests, package, CI and static guards before its own once-only refusal. Its scoped diff, checks and clean commit receipts belong to the managed author report, not a product-execution claim.

The preparation's native requested/resolved route was fresh `openai-codex/gpt-6.1-sol:high`; no fallback or profile change was recorded. HAPI/native Pi/Sol are run attribution only, not a tested Hylja interception configuration, model-serving authentication, OS sandbox or preemption proof. Native checked readiness concerns artifact preparation, not engineering approval or human adoption.

Both the [adapter contract](../contracts/adapter-contract.md) and envelope contract are **draft foundation contracts**. Decisions [003](../decisions/003-semantic-judgment-does-not-own-effects.md), [006](../decisions/006-adapter-first-multi-surface-core.md), [007](../decisions/007-fail-closed-for-protected-egress.md) and [008](../decisions/008-minimize-raw-data-retention.md) are **accepted foundation direction**. [014](../decisions/014-authenticated-local-request-evidence.md) is **accepted bounded technical design**, choices 1 and 2 only; it supplies no implemented authenticator or effect grant here. No human acceptance is inferred from this research.

## Four source-inspected/unverified groups

All facts in this section are **source-inspected/unverified**. Source pointers refer to the pinned module above; contract paragraph openings and test titles are exact pointers to the linked inputs.

### 1. Vocabulary and non-authority metadata

- Source: `INTERACTION_OPERATIONS`, `InteractionDraft`, `InteractionEnvelope`, `createInteractionEnvelope`, `parseInteractionEnvelope`, `metadata`, `record`.
- Contract: `InteractionOperation` code block; paragraphs “Version 1 payloads are limited to JSON data” and “Payload-supplied identity, purpose, session”; adapter opening ownership statement and questions 1–3.
- Existing tests: `all 26 initial operation families round-trip as versioned normalized interactions`; `malformed, unknown, unversioned and extra policy fields fail before interpretation`; `correlation/provider/model and payload CONTROL text never establish identity or release authority`.

The fixed 26-name vocabulary includes model, tool, MCP, file, shell, skill, memory, web and agent operations. Creation/parsing check membership; parsing checks version 1 and a UUIDv4-shaped ID. Closed adapter/provider/model/correlation metadata and authority-looking payload strings are data, not trusted identity or release authority. **An operation name does not intercept a surface.** The complete module has no imports; creation calls `globalThis.crypto.randomUUID()`. No external API shape, cryptographic strength or credential authenticity was investigated.

### 2. Independent context, proof congruence and freshness

- Source: `BoundaryContext`, `boundary`, `subject`, `requestContext`, `endpoint`, `timestamp`, `proof`, `provenance`, `same`, `bind`, creation/parsing.
- Contract: paragraph “`createInteractionEnvelope(draft, trustedContext, previous?)` copies” and its “congruence/freshness checking, not cryptographic verification” limitation; adapter paragraph “For each supported flow”; decision 014 “Authority and source evidence”.
- Existing tests: `authenticated identity/request and observed source/actual route come only from independent trusted context`; `absent, unauthenticated, stale, or malformed trusted evidence cannot be promoted by wire provenance`; `actual routing/profile and redirect changes reject claimed safe destination, including missing profile`; `local destinations also need an observed valid profile; neither path silently defaults`.

Creation copies security fields from a separate context. Parsing compares wire claims with that context, including ordered identity/request entries marked `authenticated` and source/route entries marked `adapter-observed`. Proof issue age and interval are bounded to five minutes; the occurrence must fall inside every proof interval and parsing also checks current occurrence age. Subject/workload, tenant/optional project, session/purpose, source and actual route/profile must agree. These checks **assume upstream authentication and actual route observation**. They verify neither credentials, project membership, proof origins nor live redirects; caller control of both inputs defeats the premise. No policy/effect grant follows.

### 3. Unverified stream sequence, context and terminal flags

- Source: `Stream`, `stream`, `bind`, `representation`, `metadata`.
- Contract: final paragraph “Representation descriptors identify declared media/encoding layers”; adapter question 5 and protected-flow stop requirements.
- Existing tests: `stream fragments require contiguous order, stable trust context, and only unverified inspection state`; `time-varying adapter objects cannot become bound unsupported operations or invalid streams`.

A fragment starts at sequence zero; subsequent fragments require a locally branded previous fragment, contiguous safe-integer sequence, the same stream ID/operation and stable security context, provenance, metadata and representation. Previous final/cancelled fragments refuse continuation; final and cancelled cannot both be true. Inspection remains `unverified`. The caller retains/orders previous fragments: this is **not buffering, holdback, reassembly, split-secret detection, cancellation transport or zero-byte denial**. Terminal flags do not grant clearance.

### 4. Local brand, immutable JSON clone, fixed errors and serialization

- Source: private `boundEnvelopes` WeakSet, `record`, `jsonValue`, `freezeTree`, `bind`, `bytes`, `text`, `timestamp`, `representation`, `fail`, `safe`, `serializeInteractionEnvelope`.
- Contract: context paragraph's immutable-object/once-only snapshot requirements; final paragraph's bounds, fixed errors and duplicate-key warning.
- Existing tests: `capped adapter keys are never enumerated a second time for descriptors`; `malformed wire, extra keys and hostile objects never echo synthetic planted values in errors`; `a forged instance of a previously observed failure cannot echo planted data`; `representation descriptors and JSON payloads must be valid and immutable, not inspection claims`; `wire limits count UTF-8 bytes and reject repeated acyclic branching input`; `near-limit JSON fields round-trip while oversized key maps reject promptly`.

Closed records capture one own-key list and enumerable data descriptors. JSON copying rejects cycles, unsupported values/descriptors, nonfinite numbers and sparse/extra array structure, then recursively freezes the independent clone. Inspected bounds: 1,048,576 UTF-8 wire bytes and conservative traversal budget; depth 32; 100,000 nodes; 10,000 object keys/array elements; default trimmed nonempty text 256 code units; endpoint refs 2,048; at most eight encoding names with case-insensitive duplicates refused. Public failures are fixed `TypeError('Invalid interaction envelope')`, including caught hostile exceptions.

Serialization requires the local brand and returns normalized JSON; **it does not recheck proof expiry** or authorize release. A copied object cannot inherit the brand; parsing needs independent context again. Standard `JSON.parse` collapses duplicate raw keys instead of rejecting them. Checked normalized serialization is not evidence that forwarding original raw wire is safe: later integration needs differential-parser and exact-byte release controls. Descriptors neither decode nor inspect payloads. Branding is not portable authentication, credential verification, erasure, arbitrary callback preemption or an OS sandbox.

## Separate illustrative coverage cells

These are at most four unexecuted projections, **not** the full sixteen-row matrix or a vendor comparison. They are separate from the source-inspected/unverified facts above.

| Potential surface | Coverage | Evidence provenance | Observed outcome |
|---|---|---|---|
| Model input/output | not tested | untested | NONE |
| Streaming fragments | not tested | untested | NONE |
| Local tool and named MCP interactions | not tested | untested | NONE |
| File/shell/skill/memory/web/agent interactions | not tested | untested | NONE |

No cell is enforced, source-enforced, observed pass/fail, passthrough, unsupported or outside candidate architecture on this evidence. Vocabulary presence or absence establishes none of those outcomes.

## Limits and preserved gates

Inspection excludes translator/parser/normalization/adapter-conformance implementation, environment, telemetry/logging, provider-hosted actions, alternate endpoints and bypass implementation. No whole-repository absence claim follows. There was no product import, build, test, harness/provider/vendor/private/held-out execution, custody or TLS experiment. No authentication, authorization, policy enforcement, sink release, restoration, managed network bypass resistance or scored conformance was proven.

The original broad #45 failure is not repaired. Root's separate two-seam preparation failed at `09:58:47Z` on a guessed missing helper, exit 1; its parser-comprehension claim remains retracted. The earlier `node:crypto` import claim is corrected only for this completely inspected envelope module: no imports, global UUID call only. This dated record reopens no failed unit or closed review round and grants no publication or parent-completion authority.

Future separately admitted independent execution would need a pinned candidate plus actual harness/version/configuration, planted synthetic cases, actual authorized sink release and **zero bytes at the actual sink on denial before any protected fragment leaves**. Controls must cover policy/review/context denial, bypass/alternate endpoints, required-check failure/outage, redirect/profile changes, streaming and serialization. Complete managed coverage additionally needs separately proven deployed bypass controls. No such execution is scheduled or performed here; original human design, custody, frozen evaluation, review and effect gates remain.
