# Slice 1: Text cloaking proof

Status: draft.

## Goal

Prove the core information-control loop using synthetic text only.

## Required journey

1. Receive normalized `model.input` text and establish authenticated policy context and a supported text/structured-fragment representation. Unsupported or undecodable protected outbound content is denied rather than passed through opaque.
2. Generate planted person/name/email/phone and customer/project candidates alongside deterministic credential, host/IP/URL detections. Candidate generation must not depend on shadow-only judgment to supply a missing category.
3. Classify deterministic patterns locally; record bounded normalization/field/key/span provenance and retain unresolved or conflicting evidence for conservative policy.
4. For ambiguous candidates, produce a minimized shadow semantic-judge request. If the judge is external, use the core Policy Engine to authorize the actual judge sink/profile under authenticated context, then apply a #19-equivalent independent check to the exact post-serialization request bytes (body and metadata) immediately before send. This is a separate protected egress from the later model request; no unchecked mutation or stream chunk may follow its check. Until that path is proved, use only local/synthetic calls or skip the judge; never send known secrets or raw protected candidates by default.
5. Apply deterministic source-to-sink policy, with unknown/missing context, judge outage, and unproved content treated conservatively. A judge cannot authorize release or downgrade a deterministic secret match.
6. Transform content while preserving valid text/structured fragments; failure or malformed output denies release instead of returning the original.
7. Inspect the exact post-transformation, post-serialization bytes with an independent egress sentinel immediately before release; no uninspected mutation or stream chunk may follow its decision.
8. Emit the cloaked payload and allowlisted privacy-safe evidence without raw originals in payload metadata, references, errors, logs, or judge traces.

## Acceptance

- zero planted credential/SECRET plaintext escapes across held-out synthetic fixtures, including escaped/encoded values and fields/keys within the declared text coverage;
- an independent fixture oracle (not the detector's output) checks actual serialized outbound bytes, including the judge request where used; configured-to-cloak/block originals never reach the disallowed sink;
- unsupported representation, parser/detector/transformer/required-sentinel failure, missing trusted destination context, and judge outage never silently release protected plaintext;
- held-out synthetic PERSON/EMAIL/PHONE and customer/project candidate-source tests cover the promised initial categories, and false-cloak and downstream utility metrics are reported;
- privacy-safe evidence and each decision record the intelligence-bundle version without persisting raw originals;
- the text-only synthetic proof is not evidence of production-grade contextual re-identification, binary/hosted-tool, or general agent-surface coverage.
