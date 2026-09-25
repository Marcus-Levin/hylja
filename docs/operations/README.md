# Operations

Operational controls are part of the security boundary.

## Audit

Record cloak/uncloak/use/display/export/delete/key-rotation/policy-change/failed-authorization/break-glass actions without raw protected values. Use an allowlisted evidence schema with opaque scoped IDs or keyed pseudonyms: arbitrary source/destination refs, query strings, purpose text, provenance, payloads, exception messages, judge requests, and error/trace fields are not safe merely because they are called metadata. Test injected synthetic secrets in each route, including failure paths. Audit storage should be append-oriented and protected under a different administrative boundary from the mapping store where practical.

## Behavioral signals

Track bulk resolution, enumeration attempts, cross-project requests, unusual reveal volume, new destination/harness, repeated DISPLAY attempts where USE would suffice, and large high-sensitivity flows. Behavioral risk can throttle/block/require step-up authentication; it never makes forbidden actions permissible.

## Incident response

Required operations include freeze tenant/project, revoke active sessions, block destination, rotate affected credentials, rotate/destroy mapping keys, identify impacted flows, preserve evidence, and deploy a known-good intelligence/policy bundle.

## Backup and recovery

Backups are encrypted, access-restricted, restore-tested, and separated from ordinary production credentials. Recovery must preserve tenant/key boundaries. Development and test environments use synthetic data rather than production backup copies.

## Hardening

Bound normalization, archive expansion, regex execution, JSON/XML depth, payload size, concurrency, streaming buffers, and semantic-judge calls. Reject or quarantine resource-exhaustion inputs rather than allowing the privacy layer to become a denial-of-service amplifier.
