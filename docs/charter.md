# Product charter

## Promise

Allow AI systems and agents to work with useful enterprise context without exposing more real information than the destination is authorized to receive.

Hylja intercepts interactions, recognizes protected information, preserves meaning through appropriate substitutions, controls source-to-sink flows, and restores real values only at trusted boundaries under explicit authorization.

## First executable proof

The first proof is deliberately small:

1. Accept a text interaction containing synthetic people, infrastructure identifiers, customer/project identifiers, and secrets.
2. Detect exact structured secrets and infrastructure identifiers deterministically.
3. Submit only bounded, minimized context to a semantic classifier for ambiguous candidates.
4. Apply a deterministic policy that distinguishes KEEP, SYNTHETIC, TOKENIZE, GENERALIZE, REDACT, and BLOCK.
5. Preserve a reversible person/host/customer mapping in an encrypted local vault while never storing blocked credentials as reversible mappings.
6. Send a cloaked request through one OpenAI-compatible local gateway.
7. Receive a response, resolve known synthetic entities under authorization, and return an authorized restored response.
8. Prove through tests that planted protected values did not leave the egress boundary and that round-trip restoration is exact where allowed.
9. Record privacy-safe audit evidence and the exact intelligence bundle used.

## What success means

- High-risk protected values do not cross disallowed sinks in plaintext.
- Useful structure remains available to the model: configuration syntax, protocol semantics, entity relationships, and relevant engineering context survive where policy permits.
- A caller can use a real resource without necessarily learning its real identifier.
- A semantic classifier outage cannot silently turn a protected flow into an allowed plaintext flow.
- Every authorization and transformation can be explained from durable, non-secret evidence.
- Evaluation catches regressions before changes become production policy.

## Initial limits

The first proof is text-first and local. It does not initially promise full desktop interception, browser-wide traffic control, OCR, image redaction, binary rewriting, arbitrary hosted-MCP coverage, or air-gapped semantic classification. Those become later slices after the core policy/vault/eval model is proved.

Hylja is not a legal-compliance oracle. Policy may encode organizational decisions and regulatory requirements, but a model classification never determines legal permissibility by itself.
