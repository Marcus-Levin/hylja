# Source-to-sink flow control

Hylja protects information flows, not only model prompts.

## Sources

Examples: user input, files, environment variables, logs, databases, email, Git repositories, tool results, MCP resources, memory, clipboard, web pages, agent outputs.

## Sinks

Examples: model providers, hosted MCP, local/remote tools, arbitrary HTTP, email, GitHub issues/PRs, Slack/Teams, shell/network commands, telemetry/logs, persistent memory, file writes, agent handoffs.

## Decision inputs

A policy decision considers:

- caller/workload identity;
- tenant/project/session;
- source and provenance;
- semantic type and sensitivity;
- trust classification;
- current representation state;
- destination profile;
- operation (`send`, `use`, `display`, `export`, `persist`);
- purpose;
- fidelity requirements;
- explicit time-limited exceptions;
- relevant semantic judgments such as re-identification risk.

## Policy outcomes and treatments

A release decision selects a treatment (`KEEP`, `MASK`, `TOKENIZE`, `SYNTHETIC`, `GENERALIZE`, or `REMOVE`) only when the destination is authorized for the resulting representation. `BLOCK` is a terminal denial; `REQUIRE_REVIEW` holds the flow without releasing bytes until a separate, attributable approval produces a new decision. Neither is a content transformation. `REDACT` is informal language for irreversible masking/removal, not a distinct policy action. `KEEP` never means that unknown or unclassified content is implicitly approved.

Policy is deterministic after verified inputs are established. An absent/mismatched authenticated subject, tenant, purpose, actual sink, or required destination profile cannot be repaired with caller-supplied strings. Unknown/conflicting classifications, unsupported encodings, unavailable required checks, and failed transformations follow the destination's explicitly conservative behavior; protected external egress cannot fall back to plaintext. Semantic models may supply bounded input signals but do not execute the action or override deterministic secret evidence.

## Destination profile

Each external destination has security metadata, for example:

```yaml
provider: example-provider
residency: eu
retention: zero
training_use: disabled
enterprise_agreement: true
hosted_tools: true
hosted_mcp: false
approved_sensitivity:
  - INTERNAL
  - CONFIDENTIAL
```

Profiles are administrative facts bound to the actual destination by the enforcement point; neither a model nor a request body may assert a safer profile. A hosted semantic judge is itself an external destination with its own source-to-sink decision, even when its answer is used only in shadow mode.

## Exceptions

An exception is a first-class policy object, not a global bypass. It is narrow, purpose-bound, time-limited, attributable, auditable, and revocable. Example: allow exact software version and port for two hours in one project to one approved diagnostic provider while preserving host/customer cloaking.

## Bypass resistance

Managed deployments should prevent direct provider/network paths that circumvent the enforcement point. Coverage must be explicit: a browser extension may protect typed chat but cannot claim full agent protection for provider-side hosted tools it never sees.
