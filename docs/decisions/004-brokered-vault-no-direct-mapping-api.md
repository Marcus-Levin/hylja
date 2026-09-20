# Decision 004: Brokered vault; no direct mapping lookup API

Status: accepted foundation direction.

The reversible mapping store is accessed through an authorization broker. Hylja does not expose a generic endpoint that returns originals by token.

USE, DISPLAY, and EXPORT are distinct permissions. Prefer USE without reveal whenever a trusted local tool can consume the original on behalf of the caller.
