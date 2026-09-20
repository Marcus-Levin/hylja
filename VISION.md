# Vision

AI systems should be able to work with realistic enterprise context without requiring organizations to expose every real identity, credential, infrastructure identifier, customer name, project detail, or engineering reference to every model and tool involved.

Hylja is the semantic information-control layer between trusted enterprise information and AI/agent systems. It detects protected information, understands its role, applies deterministic policy, substitutes a useful representation when possible, blocks unsafe disclosure when necessary, and restores real values only at an authorized trust boundary.

## The experience

A user or agent works normally. Hylja sits underneath the interaction and handles the privacy boundary:

1. Intercept the interaction regardless of whether it is chat, a model call, MCP, a tool call, a file read, shell output, a skill resource, memory, web traffic, or an agent handoff.
2. Parse and normalize the content without storing more raw data than necessary.
3. Generate sensitive-information candidates using deterministic rules, structured parsers, local models, and domain knowledge.
4. Use semantic judgment only where context is genuinely needed.
5. Apply source-to-sink policy using sensitivity, trust, caller identity, purpose, destination, and required fidelity.
6. Keep the protected mapping inside a hardened vault and expose synthetic, generalized, tokenized, masked, or blocked representations outside the trust boundary.
7. Restore originals only when an authorized local consumer needs them; prefer use-without-reveal over returning plaintext to an agent.
8. Record privacy-safe evidence for audit, evaluation, and continuous improvement.

## Product direction

Hylja begins with text-based engineering workflows and a local/enterprise gateway. It expands only after each trust boundary is proved. The long-term product should support CLI, SDK, desktop, web, IDE, MCP, agent-to-agent, on-premises, customer-VPC, and air-gapped deployments without moving privacy policy into provider-specific adapters.

The deepest abstraction is not redaction. It is controlled information flow:

- what information may leave a trust zone;
- what representation may cross;
- which destination may receive it;
- what untrusted information may influence an agent;
- where a protected value may be used without being revealed;
- how the system proves those decisions later.

## Continuous improvement

Hylja should become simpler and more deterministic as it learns. Semantic classifiers handle ambiguous cases; repeated stable patterns should migrate into deterministic parsers and detectors. Production observations may propose improvements, but never silently modify production security policy. Every change is replayed, compared in shadow mode when appropriate, and promoted through explicit release gates.
