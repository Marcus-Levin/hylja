# Decision 001: Hylja is an enforcement core, not an advisory filter

Status: accepted foundation direction.

## Decision

Hylja sits on enforceable information-flow boundaries. Supported protected flows cannot bypass policy because a classifier is unavailable or because an adapter prefers convenience.

## Consequences

- adapters must be able to stop/transform supported flows;
- coverage gaps are explicit;
- high-risk failure behavior is restrictive;
- browser/UI-only protection is not described as full agent protection.
