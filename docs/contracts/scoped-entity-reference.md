# Scoped entity reference contract

Status: draft foundation contract for issue #168. This documents a **pure keyed derivation of one opaque entity reference**, not a vault, not a mapping store, not a blind index over originals, not alias or collision resolution, not a synthetic person generator, not a KMS and not an issuance authority. Implementation status belongs only in [capabilities.md](../capabilities.md).

`deriveScopedEntityReference` answers one question: given a host-owned entity ID, the host's own HMAC key and one explicitly chosen scope, what is the deterministic opaque reference for that tuple? It is the **keyed identity component of [#14](https://github.com/Marcus-Levin/hylja/issues/14)**, not that issue's completion. Parents [#13](https://github.com/Marcus-Levin/hylja/issues/13) and [#10](https://github.com/Marcus-Levin/hylja/issues/10) remain requirements for integrated entity resolution; this function invokes no transformation and no candidate source.

## Inputs

One host-owned object. Nothing in it comes from prompt text, a model answer, a tool result or a payload field.

| Field | Requirement |
|---|---|
| `scope` | one of `TENANT`, `PROJECT`, `SESSION`, `REQUEST` |
| `tenantId`, `projectId`, `sessionId`, `requestId` | bounded nonempty ASCII identifiers, exactly as the scope variant requires |
| `entityId` | bounded nonempty ASCII identifier |
| `semanticType` | an accepted classification v1 `SemanticClass` |
| `keyVersion` | bounded nonempty ASCII identifier |
| `key` | the host's own 32-byte HMAC key as a `Uint8Array` |

There is no original value, alias, prompt or candidate input, and no retrieval, store, cache or authority proof. The identifiers come from the closed alphabet `[A-Za-z0-9._-]`, one to 128 units each; `keyVersion` is bounded the same way. Every one of those fields is read once, from own enumerable data properties, into a normalized copy: no getters, no inherited or symbol keys, no unknown keys, no array. Anything malformed, oversized, out of alphabet or hostile refuses with a fixed code and never throws.

## Scope variants are cumulative and explicit

Each kind binds exactly its own identifiers. There is no fallback, no partial acceptance and no implicit widening.

| Scope | Required identifiers | Refused |
|---|---|---|
| `TENANT` | `tenantId` | any of `projectId`, `sessionId`, `requestId` |
| `PROJECT` | `tenantId`, `projectId` | `sessionId`, `requestId` |
| `SESSION` | `tenantId`, `projectId`, `sessionId` | `requestId` |
| `REQUEST` | `tenantId`, `projectId`, `sessionId`, `requestId` | - |

Choosing a broader scope is a host selection and **grants no permission**. A `TENANT`-scoped reference is not a substitute for the `REQUEST`-scoped one, and a narrow reference cannot be derived from a broad one.

## Derivation

1. **Keyed, not hashed.** The reference is HMAC-SHA256 over a message, with the host's 32-byte key. Never an unkeyed hash, never a truncated digest, never a caller-selected algorithm. The algorithm is fixed in code, not an argument.
2. **Versioned and domain-separated.** The message starts with the domain string `hylja.scoped-entity-reference.v1`. A future serialization is a new version, not a silent rewrite.
3. **Unambiguous.** Every component is length-framed as `<unit-length>:<value>` and joined with `|`, in this order: domain, scope kind, the scope identifiers in tenant/project/session/request order, `entityId`, `semanticType`, `keyVersion`. Framing is why delimiter-like identifiers cannot alias: `tenant=ab, project=c` and `tenant=a, project=bc` are different tuples and derive different references.
4. **Full digest, fixed prefix.** The token is the fixed prefix `her1:` followed by the complete 256-bit digest in lowercase hex. It is never shortened to a display length.
5. **Key handling.** The caller's key is snapshotted once into a copy this function allocates, and that owned copy is cleared after the digest is taken. The caller's own key material is never modified. This is the only copy this module claims to clear; **no global zeroization is claimed** - not of the caller's buffer, a heap snapshot, or any other key copy.

## Result

One frozen record, either:

- `{version: 1, state: 'DERIVED', token, scope, keyVersion}`, where `scope` and `keyVersion` are the two non-sensitive labels the host bound, or
- `{version: 1, state: 'REFUSED', reason}`, where `reason` is one of the fixed codes `INVALID_REQUEST`, `SCOPE_FIELDS_INVALID`, `CREDENTIAL_REFUSED`.

The record holds primitives only. **No scope identifier and no key material appears in a result**, and no alias to the caller's objects is retained.

## Guarantees

- **Deterministic.** The same complete input and key always produce a literally identical reference, independent of property order.
- **Scope- and key-bound.** Changing the key, the scope kind, any scope identifier, the entity ID, the accepted-v1 class or the key version always produces a different reference, checked over a generated synthetic matrix in the focused test. That test makes **no claim about the mathematical absence of HMAC collisions**; collision handling against an entity registry is a later obligation of [#14](https://github.com/Marcus-Levin/hylja/issues/14), not of this function.
- **Non-reversible floor.** `CREDENTIAL_OR_SECRET` is refused outright, and unknown or draft classes are refused as malformed ([decision 009](../decisions/009-secrets-are-not-synthetic-identities.md)). Credentials are not synthetic identities here ([vault.md](../vault.md), [decision 004](../decisions/004-brokered-vault-no-direct-mapping-api.md)).
- **No bulk lookup.** The function takes one host-owned entity ID and returns one token. There is no original retrieval, no mapping database, no token resolution and no direct mapping API ([decision 004](../decisions/004-brokered-vault-no-direct-mapping-api.md)).
- **Fail closed.** A malformed, oversized, out-of-alphabet, proxied or accessor-backed input, including a hostile value whose trap throws, returns a fixed non-echoing refusal. No native message, stack or planted value reaches the caller. Raw inputs stay ephemeral; nothing is persisted ([decision 008](../decisions/008-minimize-raw-data-retention.md)).

## Limits

- A token is **not a mapping, not a capability and not an authenticated reference**. Nothing here proves the scope, key or entity was ever issued, or that the same host would derive the same token again.
- The trusted integration authenticates the scope, the key and the entity issuance. This pure module authenticates nobody, sends no bytes, stores nothing and performs no integration effect; it is **evidence for a seam, not an enforcement boundary**.
- Out of scope: alias and collision registry, canonicalization, any fidelity or round-trip claim, KMS/HSM or production key custody, blind indexes over originals, [#14](https://github.com/Marcus-Levin/hylja/issues/14) completion, and [slice 2](../specs/slice-2-vault-and-reversible-identities.md), which remains draft.

## Threats and evidence

Addressed here: accidental global correlation of one entity across tenants, scope confusion between kind and identifiers, tuple aliasing through delimiter-like identifiers, an unkeyed or truncated reference, a credential class becoming a synthetic identity, and malformed or hostile inputs leaking exception detail.

How the acceptance tests prove the boundary - and what they do not: [`test/scoped-entity-reference.test.mjs`](../../test/scoped-entity-reference.test.mjs) asserts determinism, the exact `her1:` + full-hex token shape and the absence of every scope identifier and the key bytes from the record, an independent recomputation of the documented framing, a nine-way distinctness matrix over key, scope identifiers, kind, entity, class and key version, the complete scope-variant presence matrix in both directions, delimiter-like and kind-swap non-aliasing, the credential and unknown-class refusals, the identifier alphabet and bound at the 128-unit limit, the 32-byte view-only key rules including a key whose `length` or index getter throws, the full malformed/proxy/accessor case list with no exception detail in any result, frozen output with no alias to the input and no mutation of the caller, and coverage of every refusal code the module can return. Those are synthetic in-process assertions over this function's own choices. They do **not** prove that any protected value was or was not disclosed, that a caller, key or scope was authenticated, that a real vault or broker enforces anything, or that token collision handling exists.
