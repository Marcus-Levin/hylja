# Deployment models

Hylja should support several trust and sovereignty profiles without changing the core contracts.

## Local/workstation

Best for developer PoCs and CLI interception. When enabled in later slices, Mapping Vault and deterministic detection remain local; external semantic judgment is optional, separately policy-controlled egress, and receives only verified minimized context. The initial synthetic text proof has no production vault or bypass-resistance claim.

## Customer VPC / private cloud

Core services, database, policy, audit, and KMS integrations run in the customer's cloud boundary. External providers are reached only through controlled egress.

## On-premises

All core data-plane services run inside the enterprise network. Hosted semantic classification may be disabled or replaced by a local judge if policy forbids context leaving the environment.

## Air-gapped

No external model/judge dependency is assumed. Deterministic and local classifiers must provide a conservative mode. Evaluation and bundle updates are imported through an explicit signed process.

## SaaS

Possible for lower-sensitivity use cases, but the service must clearly document where raw candidates, semantic context, mapping ciphertext, and audit data are processed. Tenant isolation and key boundaries are central.

## Deployment invariants

- destination policy is independent of network topology;
- complete managed-egress coverage is claimed only after direct bypass paths are technically prevented and re-attested for each new adapter; earlier gateway deployments state narrower capabilities;
- tenant keys, mappings, blind indexes, caches, and synthetic identities are isolated from the first relevant stateful component, not deferred to enterprise hardening;
- unsupported opaque/binary or hosted-tool flows are denied for protected use or explicitly outside supported coverage, never quietly forwarded;
- deployment-specific capabilities and limitations are discoverable and auditable.
