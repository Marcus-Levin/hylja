# Shared language

| Term | Meaning |
|---|---|
| Interaction | One normalized boundary-crossing event such as model input, tool result, file read, or MCP call. |
| Source | Where information originated: user, file, database, tool, MCP, memory, web, environment, etc. |
| Sink | Where information is about to go: model provider, tool, public web, GitHub, memory, shell/network destination, etc. |
| Trust zone | A boundary inside which a stated set of identities, services, and data controls are trusted. Network location alone does not establish trust. |
| Candidate | A span, field, entity, or artifact proposed for sensitive-data classification. Detection proposes; it does not grant a final policy result. |
| Entity | A canonical protected object such as a person, server, customer, project, asset, credential, or identifier. |
| Sensitivity | How damaging disclosure could be: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, SECRET. |
| Trust | How much influence a source may have: CONTROL, TRUSTED, VERIFIED_EXTERNAL, UNTRUSTED, HOSTILE. |
| Classification | Semantic type plus sensitivity, trust, provenance, confidence, reversibility, and lifecycle metadata. |
| Cloak | Apply a transformation before data crosses a trust boundary. |
| Uncloak | Resolve a protected representation to an original value under explicit authorization. |
| Synthetic identity | A realistic substitute preserving selected semantics without disclosing the original. |
| Token | An opaque high-entropy reference with no recoverable secret embedded in it. |
| Mapping | The protected relationship between an original value/entity and its outward representation. |
| Mapping Vault | Encrypted storage for the minimum reversible mapping state required by Hylja. |
| Use | Permission for a trusted broker to use the original value without revealing it to the caller. |
| Display | Permission to reveal the original to an authorized human or trusted UI. |
| Export | Exceptional permission to retrieve original values outside the normal brokered operation. |
| Fidelity contract | Properties a transformation must preserve for the downstream task, such as protocol, OS path style, data type, or entity relationships. |
| Policy Engine | Deterministic component that decides KEEP, MASK, TOKENIZE, SYNTHETIC, GENERALIZE, REMOVE, BLOCK, or REQUIRE_REVIEW. |
| Semantic judge | Jev or another bounded semantic classifier supplying judgments or probabilities; it never establishes authority. |
| Egress Sentinel | Independent final control that scans outbound content for leakage and policy violations before release. |
| Harness adapter | Integration translating a CLI, SDK, desktop app, IDE, web app, or agent runtime into normalized interactions. |
| Provider adapter | Integration translating provider-neutral model requests into a provider's native API and events. |
| Provenance | Where data came from and which transformations/classifications it passed through. |
| Intelligence bundle | Versioned combination of normalizers, parsers, detectors, semantic questions/model, policy, and transformation rules used for one decision. |
| Champion | Current production intelligence/policy bundle. |
| Challenger | Candidate bundle evaluated through replay, shadow, and release gates before promotion. |
