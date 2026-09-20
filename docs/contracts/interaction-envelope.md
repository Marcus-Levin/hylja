# Interaction envelope contract

Status: draft foundation contract.

All supported surfaces translate native traffic into a normalized interaction before privacy policy is evaluated.

```ts
export type InteractionOperation =
  | "model.input" | "model.output"
  | "tool.call" | "tool.result"
  | "mcp.list" | "mcp.resource" | "mcp.prompt" | "mcp.call" | "mcp.result"
  | "file.list" | "file.read" | "file.search" | "file.write" | "file.diff"
  | "shell.command" | "shell.stdout" | "shell.stderr"
  | "skill.load" | "skill.resource" | "skill.execute"
  | "memory.read" | "memory.write"
  | "web.request" | "web.response"
  | "agent.handoff" | "agent.result";

export interface InteractionEnvelope<T = unknown> {
  version: 1;
  id: string;
  occurredAt: string;
  operation: InteractionOperation;
  subject: {
    principalId: string;
    harness?: string;
    agent?: string;
    surface?: "cli" | "desktop" | "web" | "ide" | "sdk" | "service";
  };
  source: { kind: string; ref?: string; trustZone: string };
  destination: { kind: string; ref?: string; trustZone: string; profileId?: string };
  context: {
    tenantId: string;
    projectId?: string;
    sessionId?: string;
    purpose?: string;
  };
  payload: T;
  provenance: Array<{ kind: string; ref: string }>;
  stream?: { mode: "complete" | "stream"; sequence?: number };
}
```

The exact TypeScript may change when implemented, but adapters must not inject provider-specific policy semantics into this contract.
