# Deployment models

Hylja should support several trust and sovereignty profiles without changing the core contracts.

## Local/workstation

Best for developer PoCs and CLI interception. Mapping Vault and deterministic detection remain local; external semantic judgment is optional and receives minimized context.

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
- managed deployments can prevent direct egress that bypasses Hylja;
- tenant keys, mappings, blind indexes, caches, and synthetic identities are isolated;
- deployment-specific capabilities and limitations are discoverable and auditable.
