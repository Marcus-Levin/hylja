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

## Actions

- `KEEP`
- `MASK`
- `TOKENIZE`
- `SYNTHETIC`
- `GENERALIZE`
- `REMOVE`
- `BLOCK`
- `REQUIRE_REVIEW`

Policy is deterministic after its inputs are established. Semantic models may supply bounded input signals but do not execute the action.

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

Profiles are administrative facts and should not be inferred by a model at runtime.

## Exceptions

An exception is a first-class policy object, not a global bypass. It is narrow, purpose-bound, time-limited, attributable, auditable, and revocable. Example: allow exact software version and port for two hours in one project to one approved diagnostic provider while preserving host/customer cloaking.

## Bypass resistance

Managed deployments should prevent direct provider/network paths that circumvent the enforcement point. Coverage must be explicit: a browser extension may protect typed chat but cannot claim full agent protection for provider-side hosted tools it never sees.
