# Harness and provider integrations

The core must not be structured around OpenAI, Anthropic, Claude Code, Codex, or any single harness. Those are adapters.

## Harness strategies

| Surface | Preferred interception |
|---|---|
| Application we control | SDK/middleware or local gateway |
| CLI agent | launcher/wrapper + endpoint override + MCP/file/shell adapters |
| IDE agent | provider gateway plus supported tool/filesystem seams |
| Desktop app | supported plugin/custom endpoint/MCP first; proxy only when reliable |
| Web app we control | backend gateway |
| Third-party web chat | UI/browser protection is partial coverage only |
| MCP client | MCP proxy |
| Hosted MCP | Hylja-protected remote MCP endpoint |
| Agent-to-agent | handoff/result adapter |

## Coverage levels

1. UI protection - protects typed/pasted/uploaded content visible at the UI surface.
2. Model traffic protection - controls model requests and responses.
3. Tool/MCP protection - additionally controls arguments, tool results, resources, and remote action boundaries.
4. Full agent-runtime protection - controls supported model, tool, file, shell, memory, web, and agent handoff sinks with bypass resistance.

A deployment must state its coverage level rather than implying complete agent protection from a chat-only proxy.

## Provider adapters

Provider adapters translate provider-neutral model interactions into native streaming/messages/tool-call formats. They contain no privacy policy. The same classified interaction and authenticated policy context must yield the same privacy outcome across adapters when the actual destination profile is the same; different destination profiles may correctly produce different decisions. Unobservable hosted tools and opaque content cannot be counted as protected merely because the model gateway sees adjacent traffic.

## CLI V1 direction

A future `hylja run <harness>` can provision supported endpoint and MCP settings for one session, register a session policy context, and launch the harness. The launcher must bind that context to an authenticated subject and actual destination: CLI arguments or agent-generated identifiers are not authorization. This is a convenience around the enforcement architecture, not the security boundary by itself.
