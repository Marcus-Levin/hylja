# Security model

Hylja is treated as a high-assurance security boundary rather than a convenience filter.

## Crown jewels

From highest sensitivity downward:

1. KMS/HSM root capabilities and key-management authority.
2. Real-to-synthetic reversible mapping material.
3. Authorization and source-to-sink policy configuration.
4. Mapping metadata and blind indexes.
5. Audit and behavioral metadata.
6. Synthetic/cloaked agent traffic.

Architecture should make compromise of any one layer insufficient to reconstruct all originals.

## Security invariants

1. No SECRET plaintext may cross an external boundary unless a specific approved policy explicitly allows that exact class and sink.
2. A failure in semantic judgment cannot make protected egress less restrictive.
3. No synthetic token or mapping may resolve across tenants.
4. USE permission does not imply DISPLAY; DISPLAY does not imply EXPORT.
5. An untrusted model cannot create authority by generating a token, entity ID, or instruction that resembles trusted Hylja metadata.
6. Untrusted content cannot promote itself to control-plane trust.
7. All supported external sinks pass through an enforcement point; unsupported bypass paths are reported as coverage gaps.
8. Credentials and secrets are blocked/redacted by default rather than stored as reversible synthetic mappings.
9. Plaintext is held only for the shortest operation necessary and is excluded from normal logs, traces, and audit records.
10. Mapping integrity is versioned and authenticated; ciphertext cannot be safely transplanted between tenant/entity contexts.
11. A data-plane component should not hold both bulk ciphertext access and unrestricted root decryption authority.
12. Production observations may propose but never automatically deploy changes to security policy or classifier behavior.

## Cryptography

Use established authenticated encryption and managed key systems. The default direction is envelope encryption:

- random data-encryption keys (DEKs) for mapping scopes;
- tenant/project-scoped key hierarchy where useful;
- KEKs managed by KMS/HSM/Vault-class infrastructure;
- AEAD associated data binds tenant, entity ID, classification, and mapping version;
- encryption keys never committed or stored alongside plaintext data;
- separate HMAC/blind-index keys when deterministic lookup is genuinely required.

Do not use deterministic encryption as a convenience for equality lookup. Prefer a keyed blind index with explicit threat analysis.

## Identity and access

No implicit trust is granted from network location. Human and workload identities are authenticated independently. Production direction favors SSO/OIDC and strong MFA for humans, and short-lived workload identities/mTLS/SPIFFE-like mechanisms for services where available.

Authorization evaluates subject, tenant, project, purpose, destination, data class, operation, and session. Behavioral risk may narrow permission but never make a forbidden action permissible.

## Mapping lifecycle

Mappings are explicit lifecycle records: CREATED, ACTIVE, EXPIRED, REVOKED, DELETED, with optional QUARANTINED. Each record tracks scope, origin, key version, creation, last use, expiry, and retention policy. Narrow scopes are preferred: request/session/project before tenant-wide stable identities.

Cryptographic deletion may be used by destroying a narrowly scoped DEK, followed by ordinary record cleanup according to retention policy.

## Failure rules

- semantic judge unavailable -> deterministic conservative path, never plaintext bypass;
- vault/KMS unavailable -> no uncloak;
- policy engine unavailable -> deny protected external release;
- Egress Sentinel unavailable -> block high-risk protected egress;
- audit sink unavailable -> buffer tamper-evident evidence where allowed or block high-risk reveal;
- synthetic generator unavailable -> use a safer deterministic tokenization mode if policy permits;
- behavioral analytics unavailable -> core authorization remains unchanged.
