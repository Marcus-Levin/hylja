# Mapping Vault

The Mapping Vault stores only the minimum reversible state required to preserve useful synthetic identities and authorize restoration.

## No direct lookup database

The vault is not exposed as a convenient key/value API. Callers request an operation through the Cloak/Uncloak Broker. The broker evaluates subject, tenant, project, entity, purpose, destination, operation, session, and policy before accessing the original.

## Storage direction

A transactional relational store such as PostgreSQL is a sensible initial candidate for mapping lifecycle, uniqueness, versioning, and tenant constraints. A graph database is not required for V1; relationship projections can be derived from relational entity tables using only synthetic IDs where possible.

Separate stores/logical boundaries are preferred for:

- reversible mappings;
- non-secret metadata;
- audit evidence;
- keys/KMS state.

## Encryption

Use envelope encryption with AEAD before any real or production original is persisted; earlier schema work uses synthetic fixtures only and exposes no plaintext production storage path. Associated data binds ciphertext to tenant, entity, type, and mapping version. KEKs live in a managed KMS/HSM/Vault-class service; application storage holds ciphertext, wrapped DEK, key reference, and metadata, not root keys.

Equality lookup, if required, uses a separate tenant-scoped keyed blind index and separate key. Avoid deterministic ciphertext.

## Authorization operations

- `USE`: broker may inject/use the original in a trusted local operation without returning plaintext.
- `DISPLAY`: reveal to an authorized human/trusted UI.
- `EXPORT`: exceptional retrieval, strongly controlled and auditable.

## Integrity

Mappings use monotonic revisions. Sensitive mapping changes should prefer expire/create-new over silent mutation. AEAD context detects ciphertext transplanted across tenant/entity/type/version, but an older valid ciphertext can still pass authentication: resolution also checks a trusted current revision, lifecycle state, and revocation/expiry before use, including after cache and backup restore.

## Lifecycle and retention

Mappings record origin, scope, created/last-used/expiry timestamps, retention rule, classification, and key version. Expiry is automatic. Tenant/project deletion may include cryptographic deletion of narrowly scoped DEKs followed by record cleanup.

## Backups

Backups are encrypted with separate access control, monitored, restore-tested, and never restored into development with production keys or real customer mappings.
