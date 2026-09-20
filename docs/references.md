# References

These sources inform Hylja's design; they do not replace Hylja's accepted decisions and tests.

## Semantic judgment

- TypeSafe.ai / Jev documentation: https://docs.typesafe.ai/
- TypeSafe.ai: https://typesafe.ai/

Hylja uses the System One/Jev pattern as a bounded semantic judgment layer: semantic questions produce structured judgments, while deterministic code retains authority and side effects.

## Security architecture

- NIST SP 800-207, Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final
- NIST SP 800-207A, cloud-native access-control model: https://csrc.nist.gov/pubs/sp/800/207/a/final
- OWASP AI Agent Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html
- OWASP MCP Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Authorization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

## Privacy

- European Commission, GDPR principles including data minimisation and storage limitation: https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/principles-gdpr_en

Reversible pseudonymization remains sensitive/personal data where applicable; Hylja treats mapping material as crown-jewel data rather than assuming synthetic outward values make the system anonymous.

## Product inspiration

- InCountry AgentCloak: https://incountry.com/

AgentCloak demonstrates the usefulness of reversible substitution for AI traffic. Hylja's intended scope is broader: semantic enterprise information control across model, tool, MCP, file, shell, skill, memory, web, and agent boundaries, with explicit source-to-sink policy and evaluation.
