# Authorization contract

Status: draft foundation contract.

Original values are resolved only through purpose-bound operations.

Operations:

- USE: apply the original inside a trusted operation without revealing plaintext to the caller.
- DISPLAY: reveal to an authorized human/trusted UI.
- EXPORT: retrieve original values outside normal brokered use; exceptional and strongly controlled.

Authorization inputs include principal/workload identity, tenant, project, session, entity, classification, purpose, destination, operation, and policy/exception version.

Unknown or model-invented tokens have no authority. A token valid in one tenant or scope is invalid elsewhere unless an explicit cross-scope policy exists.
