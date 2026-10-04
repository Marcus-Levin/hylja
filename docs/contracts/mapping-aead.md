# Mapping AEAD primitive contract

Status: draft foundation contract for issue #162. This documents the executable seam in
[`src/mapping-aead.ts`](../../src/mapping-aead.ts): a bounded authenticated-encryption primitive for
small mapping byte payloads. It is **not** a vault, an authorization broker, a KMS/HSM adapter, an
envelope-key manager, a blind index, a mapping store, a lifecycle or freshness authority, or a
production encryption readiness claim. Implementation status belongs only in
[capabilities.md](../capabilities.md).

## Surface

| Call | Input | Success | Refusal |
| --- | --- | --- | --- |
| `sealMappingPayload({ scope, plaintext, key })` | small byte payload, expected scope, host 32-byte DEK | `{ status: 'SEALED', envelope }` | `{ status: 'REFUSED', finding }` |
| `openMappingPayload({ scope, envelope, key })` | **independently supplied** expected scope and key, sealed record | `{ status: 'OPENED', plaintext, bytes }` | `{ status: 'REFUSED', finding }` |

Exported values: `MAPPING_AEAD_VERSION`, `MAPPING_AEAD_LIMITS`, `MAPPING_AEAD_FINDINGS`,
`MAPPING_AEAD_REFUSALS`, `sealMappingPayload`, `openMappingPayload`. There is no key-management,
broker, storage, indexing or policy surface in this module.

`MAPPING_AEAD_LIMITS`: `plaintextBytes` 65536, `ciphertextBytes` 65536, `keyBytes` 32, `nonceBytes`
12, `tagBytes` 16, `identifierChars` 128.

### Findings

Every refusal is one fixed code. No code carries caller text, a native error, a message or a cause,
and nothing is logged.

| finding | meaning |
| --- | --- |
| `INVALID_INPUT` | the request record itself is structurally wrong: not a plain object, missing a required field, an unknown field, an accessor instead of a data property, or a reflective failure |
| `INVALID_CONTEXT` | a scope field is malformed, or `classification` is outside accepted classification v1 |
| `INVALID_KEY` | the key is not a byte view, is not exactly 32 bytes, or is all zeroes |
| `SECRET_NOT_REVERSIBLE` | `classification` is `CREDENTIAL_OR_SECRET` |
| `INVALID_PAYLOAD` | the payload is not a byte view, is not made of bytes, or is empty |
| `PAYLOAD_TOO_LARGE` | the payload exceeds 65536 bytes |
| `INVALID_ENVELOPE` | the sealed record is malformed: wrong version, wrong nonce or tag length, empty or oversized body, unknown field |
| `AUTHENTICATION_FAILED` | on `open`, the tag did not authenticate under the expected scope and key |
| `CRYPTO_UNAVAILABLE` | on `seal`, the platform AEAD call failed |

## Cryptography

Fixed AES-256-GCM. The 96-bit nonce is drawn from `randomBytes` inside `sealMappingPayload` and the
full 16-byte tag is stored; neither the algorithm nor the nonce is caller-selected, and there is no
deterministic mode. The key is a 32-byte data-encryption key supplied by the host and is never
stored in, or derivable from, the sealed record. Encryption is not deterministic: repeated writes of
one payload under one scope and key produce distinct nonces, ciphertexts and tags, and equality
lookup is deliberately not provided here.

## Sealed record and scope binding

The sealed record is exactly `{ version, nonce, ciphertext, tag }` with own data properties only. It
carries **no** key and **no** scope field, so there is no ciphertext metadata that could choose its own
authority. `openMappingPayload` reads no field of the record to decide which scope to authenticate:
the expected scope and the key are supplied separately by the caller, which is the only authority.

The associated data is an unambiguous versioned canonical serialization of `tenantId`, `projectId`,
`entityId`, `classification`, `mappingRevision` and `keyVersion`: one version byte, then the six
fields in that fixed order, each prefixed by its 32-bit big-endian UTF-8 byte length. Length prefixes
remove concatenation ambiguity, so no two distinct scopes share one serialization, and field order is
not caller-controlled. Every required component is bound.

Field rules. The three identifiers are bounded tokens (`[A-Za-z0-9][A-Za-z0-9._=-]{0,127}`), so an
email, URL, path or planted original is structurally excluded from a field read verbatim into the
AAD. `mappingRevision` is `1`-to-`12` digits; `keyVersion` is up to four dotted numeric components,
so a key version is a control-plane number and never a name. `classification` comes from the
accepted classification v1 vocabulary in [`src/classification.ts`](../../src/classification.ts);
no draft taxonomy is wired in, and an unknown label is refused rather than mapped. Under accepted
[decision 009](../decisions/009-secrets-are-not-synthetic-identities.md), `CREDENTIAL_OR_SECRET` is
refused in both directions: credentials are not reversible synthetic mappings.

Empty payloads are refused consistently. `seal` refuses a zero-byte payload as `INVALID_PAYLOAD`, and
`open` refuses a zero-byte body as `INVALID_ENVELOPE`, so no valid envelope of zero bytes exists.

## Material limits

- **A valid old envelope is not a fresh authorized mapping.** AEAD context detects a record
  transplanted across tenant, entity, class, revision or key version. It does not detect a *correct*
  older record for the same scope: an old revision and a retired key version still authenticate. The
  trusted store or broker must supply the current expected revision and key scope, and check
  lifecycle state, revocation and expiry, before any resolution ([vault.md](../vault.md) Integrity).
  This primitive has no opinion about freshness, and grants no restoration permission.
- **Not an enforcement boundary.** It authenticates nobody, persists nothing and sends no bytes. No
  caller, subject, key, envelope or scope is authenticated; a caller that already holds a DEK and the
  record can decrypt by calling `openMappingPayload`. Narrowing the crypto is not authorizing a
  reader.
- **No key management.** No KEK wrapping, KMS/HSM/Vault-class binding, key generation, rotation,
  escrow, backup or cryptographic deletion. Key quality beyond refusing an all-zero key is a key
  management obligation this module neither performs nor claims. The caller owns DEK lifecycle.
- **No store, issuer, index or transport.** No relational store, no synthetic-identity issuance, no
  blind index or equality lookup, no restoration permission, no external send, no plaintext
  production persistence, and no direct bulk mapping lookup. The [#15](https://github.com/Marcus-Levin/hylja/issues/15)
  and [#16](https://github.com/Marcus-Levin/hylja/issues/16) integration is required before any
  mapping is persisted, and production recovery remains a separate slice.
- **Copying is one pass.** Caller byte inputs are snapshotted into owned buffers before use and
  results are fresh plain `Uint8Array` copies, so no output aliases a caller key or payload. A byte
  source that yields a non-byte is refused instead of coerced. Overwriting owned transient key and
  payload copies after use is best-effort hygiene in JavaScript, **not** a zeroization guarantee for
  copies held inside native crypto, garbage-collected buffers or swapped pages.

## Evidence

[`test/mapping-aead.test.mjs`](../../test/mapping-aead.test.mjs) uses real Node crypto with
generated synthetic byte cases and a local host-supplied test DEK. It is not a managed-key proof.
It covers byte-exact round-trips, nonce/ciphertext/tag uniqueness over repeated writes, every
individual scope swap and revision/key-version swap in both directions, independent tenant A and
tenant B keys, nonce, tag and ciphertext tampering, size and shape limits, malformed and hostile
inputs, and the refusal shape. Failure assertions compare fixed codes, lengths and digests and never
print a payload byte.

Run it with `npm run --silent build && node --test test/mapping-aead.test.mjs`.
