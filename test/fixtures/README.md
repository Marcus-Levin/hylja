# Synthetic fixture rules

Fixtures and examples in this repository must contain only planted, obviously synthetic values; use reserved `example.com`, `.invalid`, or documentation IP addresses. Never commit real people, customer environments, incidents, infrastructure, credentials, key material, logs, or production mappings. Restricted/real cases belong in separately controlled storage, not in Git.

The tracked-fixture guard scans staged Git blobs (including files added with `git add -f`), not just the working tree. `fixtures/private/`, `fixtures/restricted/`, `fixtures/local/`, `fixtures/raw/`, `fixtures/real/`, and `fixtures/production/` paths are forbidden. Generated build/test artifacts and local credential files are forbidden even when force-added. Binary and symlinked fixtures are forbidden.

Only files below `fixtures/synthetic-golden/` may contain credential-shaped assignments, and their values must be explicit `synthetic-*.invalid` examples. Those examples are test data, never working credentials. Do not copy realistic secrets into tests or test output. The guard is a bounded repository hygiene check, not an exhaustive secret scanner; human review remains necessary.
