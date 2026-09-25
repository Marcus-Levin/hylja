# Interaction envelope contract

Status: draft foundation contract.

All supported surfaces translate native traffic into a normalized interaction before privacy policy is evaluated.

```ts
export type JsonValue = null | string | number | boolean | JsonValue[] | { [key: string]: JsonValue };
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

export interface InteractionEnvelope<T = JsonValue> {
  version: 1;
  id: string;             // core-generated UUIDv4
  occurredAt: string;     // canonical UTC ISO timestamp
  operation: InteractionOperation;
  subject: { principalId: string; workloadId?: string };
  source: { kind: string; ref: string; trustZone: string };
  destination: { kind: string; ref: string; trustZone: string; profileId: string };
  context: { tenantId: string; projectId?: string; sessionId: string; purpose: string };
  payload: T;
  provenance: Array<{
    kind: "identity" | "request" | "source" | "route";
    ref: string; issuedAt: string; expiresAt: string;
    authority: "authenticated" | "adapter-observed";
  }>;
  representation?: { mediaType?: string; encodings?: string[] };
  stream?: { mode: "complete" } | {
    mode: "stream"; id: string; sequence: number; final: boolean;
    cancelled: boolean; inspection: "unverified";
  };
  metadata?: { adapter: string; provider?: string; model?: string; correlationId?: string };
}
```

Version 1 payloads are limited to JSON data; unknown security fields, unversioned envelopes, unsupported operations, malformed representation descriptors, and unsupported stream states are rejected. References, trust zones and **the actual routed destination/profile** are required for every normalized crossing. Even a local sink must have a separately observed local profile; omitting it cannot silently create a permissive local default, and a later policy can still decide which profile permits what. The principal and tenant come from upstream authenticated identity and tenant binding; purpose and session come from the trusted request/session integration (including an assigned session for stateless calls). Workload identity is recorded when supplied by that integration. A project, when present, must be checked for membership in the bound tenant by the upstream authority, not inferred from a payload. Provider, model, adapter and opaque correlation details live only in non-authority `metadata`; they cannot select destination/profile, source trust, or policy.

`createInteractionEnvelope(draft, trustedContext, previous?)` copies those security fields from a **separate trusted adapter/broker argument**, not the draft. `parseInteractionEnvelope(json, trustedContext, previous?)` validates the wire fields against that independently supplied context. It requires exactly four matching, ordered evidence entries: authenticated identity and request binding, then adapter-observed source and actual route. The trusted context supplies each proof reference, canonical issue/expiry timestamps, principal/workload, tenant/project/session/purpose and source/route; proof issue time must be no older than five minutes and expiry no more than five minutes after issue. A wire timestamp must also be current within five minutes **and fall inside every proof's issue/expiry interval**. Only already-bound immutable objects can be serialized; parsing their JSON requires context again. Validation snapshots allowed data properties exactly once before using them; a changing JavaScript adapter object cannot change its operation or fragment flags after the check. This is congruence/freshness checking, **not** cryptographic verification of a proof, user authentication, project membership checking, destination discovery, or a capability to release data. The upstream integration must authenticate its context and observe the actual route, including redirects, before supplying it. Letting untrusted callers supply `trustedContext` defeats the boundary. Actual authenticated handoffs and pre-egress route/redirect denial are pending integration acceptance in [gateway #21](https://github.com/Marcus-Levin/hylja/issues/21) and [MCP #23](https://github.com/Marcus-Levin/hylja/issues/23), not satisfied by the plain context argument.

Payload-supplied identity, purpose, session, destination, profile, trust-zone, provenance or `CONTROL` claims remain untrusted data, even when they resemble Hylja metadata. Mismatches and missing/stale context reject the envelope rather than falling back to payload claims. Serialization and validation **never authorize USE, DISPLAY, EXPORT, protected release or uncloak**. No policy, broker, egress sentinel or transport enforcement is implemented by this envelope.

Representation descriptors identify declared media/encoding layers; they neither decode content nor assert that a payload was inspected. For streams, the first fragment has sequence zero and subsequent fragments require an already-bound previous fragment with contiguous order and matching operation, context, provenance, source, actual route/profile, metadata and representation. A final/cancelled fragment cannot be followed; `inspection: "unverified"` never authorizes any early release, including for a complete stream. A caller must retain/order prior fragments and rebind if transport routing changes. UTF-8 wire input/output is bounded to 1 MiB; JSON payload copying also has depth (32), node (100,000), object-key (10,000) and traversal-size limits, with oversized objects rejected before per-key descriptor inspection. Public errors are generic and never echo malformed wire, unknown fields, or adapter-thrown exceptions. Duplicate raw JSON keys are currently collapsed by the standard parser rather than rejected: later gateway/adapter integration must not forward the original raw wire as if it were the checked envelope; it must use normalized serialization and test differential-parser behavior before claiming a protected release boundary. Raw payloads remain ephemeral by default; adapters must not inject provider-specific policy semantics into this contract.
