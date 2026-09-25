# Cloaking and transformation

Cloaking protects the real representation while retaining the minimum semantics needed for the downstream task.

## Transformation strategies and denial

KEEP, MASK, TOKENIZE, SYNTHETIC, GENERALIZE, and REMOVE are policy-selected treatments; BLOCK is a no-release decision, not a transformer. REQUIRE_REVIEW also withholds release pending a new authorized decision. REDACT is informal shorthand for irreversible masking or removal.

| Strategy | Use |
|---|---|
| KEEP | Destination is authorized for the exact value. |
| MASK | Preserve rough shape while removing content. |
| TOKENIZE | Replace with opaque stable reference. |
| SYNTHETIC | Replace with realistic consistent value/entity. |
| GENERALIZE | Reduce precision: exact address -> city, date -> month, age -> range. |
| REMOVE | Delete content that is not required. |
| BLOCK | Refuse the flow, especially for secrets or unsafe destinations. |

## Secret handling

Passwords, API keys, private keys, access tokens, cookies, and comparable secrets are not ordinary reversible identities. Default behavior is block, irreversible redaction, or fingerprint-only detection. If a trusted local operation must use a credential, the operation should obtain it from its normal secret-management system rather than teaching the AI a fake reversible password.

## Entity consistency

Related values belong to a canonical entity. A person can include name, aliases, email, phone, pronouns, and relations. A server can include hostname, IP, environment, role, and service endpoints. Synthetic identity generation operates on the entity so references remain coherent over the configured scope.

## Scope

Stable identities are scoped narrowly: request, session, project, then tenant only when needed. The same real person should not automatically map to the same synthetic identity across unrelated customers or projects.

## Fidelity contracts

Synthetic data must preserve task-relevant properties. Example fidelity requirements:

- URL scheme/protocol;
- operating-system path style;
- file extension and structured syntax;
- data type and approximate length where needed;
- service role (`database-host`, `mcp-server`) without real hostname;
- geography class when relevant but not exact location;
- relationships between person, email, account, and organization;
- known protocol ports when their semantics are needed for diagnosis.

A fake value must not accidentally change the model's reasoning. Port `1433` may need to remain `1433` if SQL Server semantics are part of the problem, while the hostname is changed.

## Contextual re-identification

Direct identifiers may be gone while rare facts still reveal the entity. Hylja treats re-identification risk as a separate signal. Policy may generalize location, dates, customer descriptions, plant/process combinations, or other quasi-identifiers when the combination is too distinctive.

## Return path

Uncloaking is entity-aware rather than naive string replacement. Models may change case, inflect names, abbreviate, or refer by alias. The trusted broker resolves known synthetic identities and may use originals in a local tool without revealing them to the model.
