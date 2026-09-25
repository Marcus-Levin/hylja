# Product charter

## Promise

Allow AI systems and agents to work with useful enterprise context without exposing more real information than the destination is authorized to receive.

Hylja intercepts interactions, recognizes protected information, preserves meaning through appropriate substitutions, controls source-to-sink flows, and restores real values only at trusted boundaries under explicit authorization.

## First executable proof

The first end-to-end proof is deliberately small and spans three staged slices: synthetic text cloaking, encrypted reversible identities, then one local model gateway. The text slice alone does not claim a vault, live gateway, or production protection.

1. Accept a text interaction containing synthetic people, infrastructure identifiers, customer/project identifiers, and secrets.
2. Generate person/email/phone and customer/project candidates; detect exact structured secrets and infrastructure identifiers deterministically.
3. Submit only bounded, policy-authorized, minimized context to a semantic classifier for ambiguous candidates; shadow mode does not exempt that external request from egress controls.
4. Apply deterministic policy using KEEP, MASK, TOKENIZE, SYNTHETIC, GENERALIZE, REMOVE, or BLOCK; REQUIRE_REVIEW withholds release until separately authorized.
5. Preserve reversible person/host/customer mappings only after the encrypted scoped vault and broker exist; never store blocked credentials as reversible mappings.
6. Send a cloaked request through one OpenAI-compatible local gateway.
7. Receive a response, resolve known synthetic entities under authorization, and return an authorized restored response.
8. Prove on planted synthetic fixtures that protected values did not leave the boundary in the actual serialized release and that authorized round-trip restoration is exact where allowed.
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
