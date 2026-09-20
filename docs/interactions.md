# Interaction model

Hylja normalizes agent traffic so privacy policy does not depend on a particular provider or harness.

## Event families

### Model
- `model.input`
- `model.output`

### Tool
- `tool.call`
- `tool.result`

### MCP
- `mcp.list`
- `mcp.resource`
- `mcp.prompt`
- `mcp.call`
- `mcp.result`

### Files
- `file.list`
- `file.read`
- `file.search`
- `file.write`
- `file.diff`

### Shell
- `shell.command`
- `shell.stdout`
- `shell.stderr`

### Skill
- `skill.load`
- `skill.resource`
- `skill.execute`

### Memory
- `memory.read`
- `memory.write`

### Web
- `web.request`
- `web.response`

### Agent
- `agent.handoff`
- `agent.result`

## Envelope

The envelope carries interaction identity, subject/harness, source, destination, operation, policy context, payload descriptors, provenance, and stream semantics. Raw payloads should remain ephemeral unless a specific component must process them.

## Bidirectional enforcement

Requests and responses are both enforcement boundaries. Tool results, shell stdout, file contents, MCP resources, and model output can introduce sensitive data or untrusted instructions into later contexts.

## Hosted-tool caveat

Provider-hosted tools or hosted MCP may execute outside a local gateway. Full protection then requires the remote tool/MCP endpoint itself to sit behind Hylja or the provider integration to expose an equivalent enforceable interception point. Coverage must be reported honestly.
