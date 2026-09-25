# Authorization contract

Status: draft foundation contract.

Original values are resolved only through purpose-bound operations.

Operations:

- USE: apply the original inside a trusted operation without revealing plaintext to the caller.
- DISPLAY: reveal to an authorized human/trusted UI.
- EXPORT: retrieve original values outside normal brokered use; exceptional and strongly controlled.

Authorization uses the authenticated principal/workload and tenant, trusted caller-bound purpose and session, project (when present), authenticated Hylja mapping/entity reference and classification, requested USE/DISPLAY/EXPORT operation, actual sink/profile/trust zone, and policy/exception version. These are checked against the interaction's authoritative provenance and the mapping's authenticated scope; payload-supplied or model/tool-asserted values cannot supply or override them. Missing, expired, revoked, or mismatched context denies resolution and reveal. No direct or bulk mapping lookup returns originals.

USE never implies DISPLAY, and DISPLAY never implies EXPORT. Unknown, forged, or model-invented tokens have no authority even if their syntax resembles an issued token.

**Cross-tenant nonresolution is unconditional:** a token, mapping, key, or entity issued under one tenant never resolves under another tenant, including through an exception. Project/session scope exceptions may be explicitly authorized only *within the same tenant*. Migration requires separately authorized and audited source/target operations that reissue a new mapping/token under the destination tenant; it never makes a source-tenant token resolvable there.
