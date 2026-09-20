# Slice 2: Vault and reversible identities

Status: draft.

## Goal

Add encrypted scoped mappings and brokered restoration without creating a direct plaintext lookup service.

## Required behavior

- canonical entities with aliases and relationships;
- stable synthetic identities within scope;
- envelope-encrypted originals;
- USE and DISPLAY authorization paths;
- expiry/revocation/deletion;
- tenant isolation;
- exact authorized round-trip restoration;
- unknown/forged tokens fail safely;
- secrets remain non-reversible by default.
