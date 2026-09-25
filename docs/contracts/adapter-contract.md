# Adapter contract

Status: draft foundation contract.

Adapters translate between native surfaces and Hylja interactions; policy, authorization, and release remain core decisions. They declare coverage honestly.

An adapter must answer:

1. Which interaction operations and directions can it intercept, including request, result, and streaming segments?
2. Which payload parts (body, headers, metadata, nested/encoded fields, attachments) can it inspect and transform safely, and what opaque parts are unsupported?
3. Which provider-side/hosted actions or alternate egress routes bypass its interception?
4. Can it stop a protected flow on policy denial, `REQUIRE_REVIEW`, context/transform failure, or final egress-check failure before any denied or undecided bytes leave?
5. Can it preserve correlation/session and stream ordering/completion across request and result?

For each supported flow, the adapter must supply authenticated principal/tenant binding and trusted purpose/session context, and bind source trust and the *actual* routed sink/profile/trust zone from observed transport, including redirects. It must reject missing or mismatched security context rather than accept claims inside model, tool, or other untrusted content. A payload cannot create its own `CONTROL` authority.

Opaque or otherwise uninspectable content that is protected or may contain protected data on a supported external path must not pass through unchanged when safe handling cannot be established; stop it and report the coverage gap. Unsupported paths, including hosted actions outside interception, are declared as uncovered rather than described as protected. No adapter may bypass the core Policy Engine or required egress check for convenience.
