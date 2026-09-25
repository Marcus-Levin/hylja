# Slice 2: Vault and reversible identities

Status: draft.

## Goal

Add encrypted scoped mappings and brokered restoration without creating a direct plaintext lookup service.

## Required behavior

- canonical entities with aliases and relationships, with authenticated Hylja issuance separate from untrusted model-visible token text;
- stable synthetic identities within the narrowest authorized request/session/project/tenant scope;
- envelope-encrypted originals before any real or production mapping persistence; schema-only or synthetic fixture work must not become a plaintext production vault;
- purpose-bound USE and DISPLAY authorization paths with EXPORT separately restricted, plus privacy-safe audit evidence for denied resolution and lifecycle changes;
- expiry/revocation/deletion that also rejects stale-cache and rolled-back valid ciphertext, with current monotonic revision and key scope checked before resolution;
- unconditional cross-tenant nonresolution for tokens, ciphertext, mappings, caches and synthetic identities: no policy exception can turn a tenant-A reference into a tenant-B one; migration requires separate authenticated, audited reissuance;
- exact authorized round-trip restoration where policy permits, never blanket string replacement;
- unknown, model-invented, swapped, forged and out-of-scope tokens fail safely without revealing originals;
- secrets remain non-reversible by default.

Acceptance uses planted synthetic tenant A/B fixtures, intra-tenant scope swaps, forged references, expiry/revocation, stale/rollback records, and authorized USE without DISPLAY. Backup/restore deletion behavior is first checked with a synthetic fixture; production recovery belongs to the later recovery slice.
