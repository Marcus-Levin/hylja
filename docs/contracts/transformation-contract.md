# Transformation contract

Status: draft foundation contract.

For an authorized release treatment, a transformation receives the policy decision, canonical entity/candidate metadata, and a fidelity contract. It does not choose its own policy; BLOCK and REQUIRE_REVIEW do not invoke a release transformation.

Canonical policy decisions select authorized treatments KEEP, MASK, TOKENIZE, SYNTHETIC, GENERALIZE, or REMOVE, or select BLOCK or REQUIRE_REVIEW. `REDACT` is shorthand for irreversible `MASK`/`REMOVE`, not a separate decision. `BLOCK` is a terminal denial; `REQUIRE_REVIEW` holds the flow without release until separate attributable approval produces a new decision. Neither is a content transformation. `KEEP` requires an explicit policy release decision and the required final egress check.

Every permitted reversible transformation records a mapping reference, tenant/scope, version, and transformation metadata without placing originals into normal logs. Credentials/`SECRET` default to block or irreversible redaction, not reversible identity mappings.

For encoded or structured content, the transformer must relate each normalized candidate to its source field/span and bounded encoding layers, and ensure the released representation contains neither the original nor an untransformed encoded equivalent where policy forbids it. It must preserve required syntax/fidelity (including valid JSON/XML/YAML) or fail. A transformation failure, unsupported representation, or missing span mapping must never emit unchanged protected input as a fallback; protected release is denied unless a separately authorized safer transformation succeeds.

Streaming transformations must carry enough stream identity, ordering, completion/cancellation, and inspection/holdback metadata to prevent partial protected spans escaping before a release decision. Segments awaiting inspection remain held; a later finding cannot retract an already released protected span. This contract does not mandate a particular parser, encoding algorithm, buffer size, or wire schema.
