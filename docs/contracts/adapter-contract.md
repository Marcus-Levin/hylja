# Adapter contract

Status: draft foundation contract.

Adapters translate between native surfaces and Hylja interactions. They declare coverage honestly.

An adapter must answer:

1. Which interaction operations can it intercept?
2. Which request and result payloads can it transform safely?
3. Which provider-side/hosted actions bypass it?
4. Can it stop a protected flow when Hylja denies it?
5. Can it preserve correlation/session identity across request and result?

Unsupported coverage is a declared limitation, not a silent pass-through.
