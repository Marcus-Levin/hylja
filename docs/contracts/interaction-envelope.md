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
    sessionId: string;
    purpose: string;
  };
  payload: T;
  provenance: Array<{ kind: string; ref: string; authority: "authenticated" | "adapter-observed" | "untrusted" }>;
  representation?: { mediaType?: string; encodings?: string[] };
  stream?: { mode: "complete" | "stream"; id?: string; sequence?: number; final?: boolean; cancelled?: boolean };
}
```

The exact TypeScript may change when implemented; these fields describe a draft security contract, not a wire format. The principal and tenant must come from authenticated identity and tenant binding; purpose and session must be bound by the trusted caller/integration (including an assigned session for stateless calls). Source trust zone and the *effective* destination, profile, and trust zone must come from the intercepted boundary and observed routing, not from payload text or model/tool claims. An external protected release requires an identified sink and its applicable destination profile. Project, when present, must belong to the bound tenant.

Hylja records the origin and authority of each provenance claim; only authenticated or adapter-observed evidence may establish security context. Payload-supplied identity, purpose, session, destination, profile, trust-zone, or `CONTROL` claims remain untrusted data, even when they resemble Hylja metadata. Missing, unauthenticated, stale, or mismatched required bindings reject authorization and protected release rather than falling back to payload claims.

Representation descriptors identify observed media/encoding layers; transformations must retain a bounded relationship between decoded candidates and their original fields/spans so encodings cannot hide surviving originals. For streams, metadata must identify the stream, ordering, completion/cancellation, and inspection/holdback state before any protected segment is released; an undecided partial segment is not a release decision. Raw payloads and span maps remain ephemeral by default. Adapters must not inject provider-specific policy semantics into this contract.
