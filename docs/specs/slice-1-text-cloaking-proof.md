# Slice 1: Text cloaking proof

Status: draft.

## Goal

Prove the core information-control loop using synthetic text only.

## Required journey

1. Receive normalized `model.input` text.
2. Detect planted credentials, host/IP/URL, person/email/phone, customer/project candidates.
3. Classify deterministic patterns locally.
4. Produce a minimized semantic-judge request for ambiguous candidates in shadow mode.
5. Apply deterministic source-to-sink policy.
6. Transform content while preserving valid text/structured fragments.
7. Run independent egress sentinel.
8. Emit cloaked payload and privacy-safe evidence.

## Acceptance

- zero planted credential/SECRET plaintext escapes across held-out fixtures;
- deterministic outage path is conservative;
- exact outbound payload contains no known protected originals for classes configured to cloak/block;
- false-cloak and utility metrics are reported;
- every result records intelligence-bundle version.
