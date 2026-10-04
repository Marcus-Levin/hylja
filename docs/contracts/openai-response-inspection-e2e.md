# Complete-response inspection E2E contract (#175)

Status: **synthetic, non-enforcing end-to-end evidence** over accepted v1 exports. It describes observable
behavior of one executable test over public fixtures. It is **not** a product adapter, a gateway, a
transport, an authentication proof, a broker, a streaming design or a release control. Implementation
status lives only in [capabilities.md](../capabilities.md).

Scope: take one complete, non-streamed, text-only native OpenAI-compatible
`/v1/chat/completions` **response** and run it through the shipped deterministic chain —
[`translateOpenAiTextResponse`](../../src/openai-text-response.ts), then real
[`detectSecrets`](../../src/secret-detectors.ts), real
[`composeClassification`](../../src/classification.ts), real
[`decidePolicy`](../../src/policy.ts) — and hand the **final serialized representation** to the
independent [`checkEgress`](../../src/egress-sentinel.ts), whose ALLOW copy is what a controlled
in-memory model-context capture records. Nothing else. The translation half is specified in
[openai-text-response.md](openai-text-response.md); the policy and sentinel halves keep their own
contracts ([policy-contract.md](policy-contract.md) and the evaluation and threat model records,
[evaluation.md](../evaluation.md), [threat-model.md](../threat-model.md)).

## What the evidence is

- **One complete text response.** A single `chat.completion` with exactly one assistant choice. There is
  **no chunk path**: streaming, SSE fragments and `tool_calls` are refused by the translator and are
  exercised here only as refusals.
- **Real stages, fixture bindings.** Every stage under test is the shipped module. The `PolicyBoundary`,
  the policy bundle pin, the benign fixture claim, the sentinel key and the known-originals handle are
  **test fixtures**, not authenticated identities. The trusted boundary is supplied exactly as a trusted
  integration would supply it, and the modules under test still check every binding themselves.
- **An in-memory capture, not a sink and not a transport.** The capture records the sentinel's own
  private ALLOW copy. There is no socket, no HTTP server or client, no provider traffic and no credential.
  A release is therefore observed from the recorded bytes, not inferred from a flag.
- **Invented, non-routable fixtures.** Everything is a `*.invalid` name or a documentation literal. The
  planted credential-shaped string is made up and is not a live token.

## What the evidence proves, precisely

1. **Safe complete response.** The declared protocol metadata, draft shape, and the serialized
   model-context image are compared against **independently written literal expected values**, and the
   recorded capture equals that literal byte for byte. Literal troubleshooting facts (protocol id,
   `created`, `finish_reason`, usage triple, adapter/provider/model metadata, message role) are asserted
   alongside, so a failure names the field that drifted.
2. **Planted synthetic credential.** The real detector finds it (`format.github-token`,
   `ACCESS_TOKEN`), the real composer resolves `CREDENTIAL_OR_SECRET`/`SECRET`/`reversible: false`, and
   real policy returns `DENIED`/`BLOCK`/`RULE_BLOCK`. The final bytes are never serialized and the
   capture is empty. No observable the pipeline produced contains the planted value.
3. **Deliberately incomplete primary evidence.** A protected synthetic original that candidate detection
   genuinely misses (asserted as an empty candidate list) is still caught by the independent final-byte
   check with `KNOWN_ORIGINAL_DETECTED`, in plain and Base64 form. The test distinguishes the two layers
   explicitly: it asserts that the candidate list is empty, that policy selected, and that the sentinel
   refused. A positive control over the same chain captures a benign answer, so a BLOCK is a finding and
   not a chain that refuses everything.
4. **Unsupported responses.** Tool calls, the streaming object, malformed text and unknown top-level
   fields are refused by name, and each refuses before any detection, classification, policy call,
   serialization or capture.
5. **Every other restrictive outcome.** Missing boundary data, a mismatched authenticated context, a
   mismatched classification digest, a `HELD`/`REQUIRE_REVIEW` decision and an unavailable sentinel each
   produce zero captured bytes.
6. **Absence of restoration authority.** Placeholder-shaped, forged and scope-shaped token text in the
   assistant turn is carried through byte-identically; no original is substituted and no original appears
   in the capture. This is an **absence of restoration authority in this chain**, not production broker
   proof: no broker, vault, mapping store or uncloak path is configured, called or imported, and none of
   those are implemented in this repository.

## What it is not

No gateway, no request translation, no tool interception, no streaming holdback, no real authenticated
caller, no live transport, no network, no held-out or scored result, no production original, and no
evidence that a real gateway would behave this way. Declared limits and uncovered surfaces stay as
recorded in [capabilities.md](../capabilities.md) and [integrations.md](../integrations.md). The
information-model draft and
[decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md) are proposed and
are not exercised or adopted here; the accepted records
([003](../decisions/003-semantic-judgment-does-not-own-effects.md),
[004](../decisions/004-brokered-vault-no-direct-mapping-api.md),
[007](../decisions/007-fail-closed-for-protected-egress.md),
[009](../decisions/009-secrets-are-not-synthetic-identities.md)) govern. Slice 3 remains a draft and
this evidence does not implement any part of it.

Evidence: [`test/openai-response-inspection.e2e.test.mjs`](../../test/openai-response-inspection.e2e.test.mjs).