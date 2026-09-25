# Slice 3: OpenAI-compatible gateway proof

Status: draft.

## Goal

Expose one local OpenAI-compatible model gateway backed by the same interaction, policy, vault, and evaluation contracts.

## Required behavior

- request and response interception bound to authenticated caller/workload, tenant, session, purpose, and actual upstream destination; untrusted request headers/body or launcher flags cannot self-assert a safer profile;
- explicit supported content-type/operation matrix: unsupported attachments, binary/nested parts and unobservable hosted tools are denied for protected flows rather than silently forwarded; later multimodal work may expand that matrix;
- destination profiles bound by the gateway to actual network sinks, including redirects; deny missing, forged or mismatched context;
- tool-call arguments/results represented as interactions where the protocol exposes them; unobservable provider-side tool actions cannot be claimed as protected;
- outbound policy denial stops release before contacting upstream;
- streaming holdback defaults to no early plaintext for unknown/high-risk content and includes split credentials, interleaved tool arguments, finalization, cancellation, out-of-order chunks, buffer bounds and backpressure; deny or buffer until an inspectable unit is complete before the first protected byte;
- an independent egress sentinel verifies the exact serialized bytes immediately before external send, with no mutation after its check;
- inbound results are inspected conservatively at the first gateway milestone, without granting restoration from model-generated token text; full authorized entity-aware uncloak is a later dependent milestone;
- audit uses allowlisted opaque correlation IDs and excludes raw protected payloads, arbitrary metadata references, error contents, and streaming trace contents;
- limitations for hosted/provider-side tools and unsupported direct paths are explicit, and complete agent coverage is not claimed until bypass resistance is proved.

Acceptance captures actual upstream bytes for planted synthetic protected requests and split response/tool streams; denied or unsupported protected payloads send zero bytes. Forged subject/tenant/profile, redirect, chunk abort, sentinel outage and opaque-resource cases are negative tests. An exact-string fixture pass alone does not establish contextual re-identification safety for real customer traffic.
