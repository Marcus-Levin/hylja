# Working on Hylja

This file guides agents developing this repository.

## Find the relevant authority

Before implementation, read [docs/charter.md](docs/charter.md), [docs/architecture.md](docs/architecture.md), [docs/security-model.md](docs/security-model.md), [docs/threat-model.md](docs/threat-model.md), [docs/evaluation.md](docs/evaluation.md), and the current state in [docs/plan.md](docs/plan.md#current-state). Read the current slice in [docs/specs](docs/specs/) and accepted decisions in [docs/decisions](docs/decisions/).

One fact has one authoritative home. Do not copy implementation status into architecture, README, or research documents; link to the plan instead. Research is evidence, not authority. Accepted design changes get a new decision record rather than silently rewriting history.

## Security invariants

- Never add real customer, employee, infrastructure, secret, credential, or production mapping data to the repository, fixtures, logs, snapshots, or issue bodies.
- Synthetic examples must be obviously synthetic and non-routable where possible (`example.com`, `.invalid`, documentation IP ranges).
- A semantic model may classify, score, or recommend. Deterministic policy and authorization decide effects.
- No adapter may bypass the Policy Engine for convenience.
- No failure in semantic classification may make protected egress less restrictive.
- USE does not imply DISPLAY; DISPLAY does not imply EXPORT.
- Secret/credential detection defaults to block or irreversible redaction; do not create reversible password/API-key mappings by default.
- Never create a direct bulk mapping lookup API. Original values are resolved through the broker under purpose-bound authorization.
- Keep plaintext lifetimes short. Do not log raw protected values or model traffic by default.
- Cross-tenant token, key, mapping, cache, or synthetic-identity resolution is a security defect.

## Development approach

Hylja is TypeScript on Node.js. Keep the core provider- and harness-independent. Model, MCP, shell, file, skill, and harness integrations live behind narrow adapters. Prefer pure functions for parsing, classification composition, policy, and transformations so they can be property-tested and replayed.

Every security-sensitive feature ships with evaluation evidence. Add deterministic tests for known invariants, property-based tests for transformations and tenant isolation, adversarial cases for bypasses, and end-to-end utility tests where cloaking can change reasoning.

Do not optimize a detector against the held-out suite. A production miss becomes a sanitized regression case; it does not automatically alter policy.
