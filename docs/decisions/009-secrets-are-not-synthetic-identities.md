# Decision 009: Credentials and secrets are not ordinary synthetic identities

Status: accepted foundation direction.

Passwords, API keys, access tokens, private keys, cookies, and similar credentials default to block/redact/fingerprint handling. They are not stored as reversible fake-to-real mappings for an external agent. Trusted tools obtain real credentials through normal secret-management mechanisms.
