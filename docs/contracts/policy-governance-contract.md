# Policy governance substrate contract

Status: draft foundation contract for issue #28. This documents the executable seam in
[`src/policy-governance.ts`](../../src/policy-governance.ts), **not** a production policy registry,
a distribution mechanism, an authentication service, an administrative server, an authorization
broker, a deployment, or an enforcement boundary. Implementation status belongs only in
[the plan](../plan.md#current-state).

## Scope and what this seam is not

The module is a bounded, offline, **NON-ENFORCING** substrate over synthetic data. It holds

- **versioned configuration snapshots** — a governance `revision`, a creation instant, an
  administrative purpose, and an independent content pin over the exact #4 bundle;
- **narrow exception objects** — bound to exactly one tenant, project, subject, purpose, semantic
  class, sensitivity, destination (profile plus exact sink reference), operation and configuration
  revision, with a mandatory expiry and an explicit revocation;
- a **bounded policy-diff simulation** — reporting the classes, sinks and operations a candidate
  configuration would newly expose, before any activation;
- **separate approval and audit hooks** — an approval and a #20 audit record are two independently
  supplied inputs, and a high-risk activation requires both.

There is deliberately **no** global or wildcard bypass, no cross-tenant reuse, no default allow, and
no semantic self-promotion: a semantic class is a *scope constraint* on what an exception may cover,
never a way to upgrade a class, a sensitivity or a treatment ceiling. There is also no provider API,
HTTP or admin surface, persistence, authentication service, key management, production registry or
distribution mechanism, real signing authority, vault or mapping lookup, transport, #13 treatment
semantics, #19 send path, deployment or managed-network enforcement. [#48](https://github.com/Marcus-Levin/hylja/issues/48)'s
administrative-plane reuse decision remains open; this is a separately reviewable bounded foundation
under the existing accepted scope, not product adoption.

## The accepted #4 foundation is preserved exactly

`decidePolicy` remains the only decision identity and `hylja.foundation` version `1` remains the
only supported policy schema. `createPolicyConfiguration` compares the candidate bundle's
`id`/`version` against `KNOWN_POLICY_BUNDLE` and refuses anything else with the typed
`CONFIGURATION_POLICY_VERSION_UNSUPPORTED`; it never extends `decidePolicy`'s wire allowlist, and
nothing here changes `src/policy.ts`.

Two version numbers are deliberately kept apart:

| concept | meaning | refusal when unsupported |
| --- | --- | --- |
| `policy.id` / `policy.version` | the accepted #4 decision identity | `CONFIGURATION_POLICY_VERSION_UNSUPPORTED` |
| `configVersion` | this module's own schema version | `CONFIGURATION_VERSION_UNSUPPORTED` |
| `revision` | a registry activation counter, not a version | bounded by `GOVERNANCE_LIMITS.revision` |

A governance `revision` is bookkeeping and is never comparable to, or substitutable for, a policy
version. The `digestPolicyBundle` content pin and the configuration commitment are separate values,
and the approval binds both.

## Versioning, staleness and forgery refusal

`digestPolicyConfiguration` is a SHA-256 commitment over the normalized revision, creation instant,
administrative purpose, policy identity and bundle content pin. `digestPolicyBundle` is reused
unchanged for the bundle content itself, and `digestClassification` is reused by the simulation. All
three are **unkeyed replay commitments, not credentials, signatures or authorization tokens**: only a
digest pinned independently by the trusted control plane is authoritative, and this module never
mints one — the value it compares against always arrives inside a separately supplied approval.

Content is re-derived from the bundle on **every** read, not only at issuance, because the snapshot
holds the caller's bundle object. A bundle mutated after issuance, or after an approval, is
`CONFIGURATION_CONTENT_CHANGED` and never reaches a comparison or a registry write. `pinnedDigest`,
when the control plane supplies one, must equal the recomputed configuration commitment, so a
substituted bundle or a substituted revision is refused before any revision comparison.

Staleness is a registry decision, in this order:

1. `REGISTRY_UNAVAILABLE` — the registry is not accepting writes;
2. `AUDIT_SCOPE_MISMATCH` — the audit hook is for another scope;
3. `CONFIGURATION_CONTENT_CHANGED` — the candidate or the active bundle no longer matches its pin;
4. `CONFIGURATION_ALREADY_ACTIVE` — the same revision and content are already active;
5. `CONFIGURATION_STALE` — the revision is not strictly newer than the active one.

## Narrow exceptions: what binds, and what can never be expressed

Every dimension is single-valued and **required**: `tenantId`, `projectId`, `principalId` (and the
optional `workloadId`), `purpose`, `semanticType`, `sensitivity`, `profileId`, `sinkRef`, `operation`,
`configRevision`, `issuedAt`, `expiresAt`, and the selected `treatment`. Consequences:

- there is no tenant-wide or project-wide form, because both identifiers are required;
- `*`, a URL, an email or free text cannot be planted in any field that is read verbatim — those
  fields are bounded opaque tokens, and a destination reference is one opaque token or absolute URI;
- an exception must expire: `expiresAt` must be strictly after `issuedAt` and within
  `GOVERNANCE_LIMITS.exceptionTtlMs` (24 h). An over-long window is `EXCEPTION_TTL_EXCEEDED` and an
  inverted window is `EXCEPTION_WINDOW_INVALID`, so a "temporary" exception cannot be minted as a
  permanent one;
- an exception naming `SECRET` or `CREDENTIAL_OR_SECRET` may only select `MASK` or `REMOVE`
  (`EXCEPTION_ABOVE_TREATMENT_CEILING`). This ceiling is applied for every exposure, which is
  strictly stricter than #4's exposure-conditional rule and therefore never relaxes it.

A registry refuses an exception minted for another tenant or project
(`EXCEPTION_SCOPE_MISMATCH`), so an exception cannot be filed in one tenant's registry and only turn
out to be unusable later; cross-tenant *use* was already closed at the evaluation layer, and this
closes the registry and audit-honesty side of it too.

Registration binds the exception to the **currently active** configuration revision. Activating a
newer revision therefore supersedes every older exception automatically
(`EXCEPTION_CONFIG_SUPERSEDED`) rather than leaving it live against a configuration nobody approved
it for. An identifier already present — including one that was revoked — is
`EXCEPTION_ALREADY_REGISTERED`: a revocation cannot be undone by re-registering.

The registry's exception list is capped by `GOVERNANCE_LIMITS.exceptions`, and the cap
(`EXCEPTION_CAPACITY`) gates **registration only**. It deliberately does not gate revocation: refusing
a revocation because the registry is full would strand a live exception, which is the fail-open
direction, so narrowing authority stays available at capacity.

### What an exception is *not*

`evaluatePolicyException` answers one question — does this live exception cover this exact request
tuple — and its `APPLICABLE` result carries `authority: 'NONE'`, `grantsTreatment: false` and
`requiresPolicyDecision: true`. It selects no treatment, transforms nothing, resolves no original,
grants no broker permission and authorizes no effect. The caller still runs #4
`decidePolicy`/`decideReviewedPolicy`, which independently refuses an unsafe treatment, an
unresolved or unknown classification, an unsupported policy identity, a substituted content pin and
every missing binding; a broker authorization is still required wherever one exists. The
simulation additionally re-observes the same seam (see below), and a committed case asserts that an
`APPLICABLE` exception leaves a held `SEND` decision held and an `UNRESOLVED` classification denied.

Refusal order is content, clock, revocation, expiry, scope, tuple, then configuration
supersession, and every refusal is a fixed code.

## Approval: a trusted integration obligation, not authentication here

An approval is a **structurally validated, separately supplied assertion** that a trusted integration
authenticated an approver and bound it to project membership. This module verifies congruence,
digests, windows and scope. It does **not** authenticate anyone, and a request string, a metadata
field or a model output can supply none of these facts. The synthetic host used by the tests is a
test double, never a human authentication service; the congruence digests are not credentials.

Every approval binds:

| field | binds |
| --- | --- |
| `scope` | the registry's exact tenant **and** project |
| `approver` | the identity the trusted integration claims to have authenticated |
| `purpose` | the administrative purpose of the target (configuration or exception) |
| `operation` | `DEPLOY` for a configuration activation, `UPDATE` for an exception change |
| `revision` | the target's governance revision |
| `targetDigest` | the **exact** target: a configuration commitment or an exception digest |
| `configDigest` | the configuration the approval was granted against: the currently active one, or `GOVERNANCE_ZERO_DIGEST` when the registry has never activated anything |
| `binding` | for an exception only: subject, class, sensitivity, destination and operation, which must equal the exception's own tuple |
| `validFrom` / `validUntil` | the window, capped by `GOVERNANCE_LIMITS.approvalTtlMs` (1 h) |

Missing, unsupported, forged, substituted, stale, expired, not-yet-valid, foreign-scope, wrong-purpose,
wrong-operation or oversized-window approvals all deny and leave the registry **exactly** as it was.
An approval granted against a configuration that has since been replaced cannot act on it. The
split between refusals is deliberate: a malformed **envelope** (missing or unknown key, hostile
getter, oversize container, planted free text, malformed digest, inverted window) is `INVALID_APPROVAL`,
while a well-formed envelope carrying a wrong or unbound claim is a governance decision with its own
code (`APPROVAL_MISMATCH`, `APPROVAL_MISSING`, `APPROVAL_TTL_EXCEEDED`, `APPROVAL_NOT_YET_VALID`,
`APPROVAL_EXPIRED`). Nothing is echoed in either case.

Two input classes behave differently on purpose. A forged *identity* for an object this module issued
— an unissued configuration or exception handed to an entry point — is a caller programming error and
throws `INVALID_CONFIGURATION` / `INVALID_EXCEPTION` loudly. Everything about untrusted input (the
approval, the audit hook, the clock, the binding, the registry object) is a fixed-code **denial**.

## Audit: #20's hook, not this module's

The audit hook supplies an #20 `AuditLedger`, an #20 `AuditTrustedContext` (scope, actor and the two
secret keys), the integrating deployment's declared bundle component versions, a correlation
reference and an occurrence instant.

Scope is checked **twice, and the first check is the one that prevents the write**.

**Before any append.** The hook's declared `scope`, the scope of the **ledger it carries** and the
scope of its **trusted context** must all name exactly the registry's tenant and project, and the
first mismatch is `AUDIT_SCOPE_MISMATCH` with `audit: { status: 'NOT_ATTEMPTED' }` — **nothing is
committed anywhere**. The declared field alone would be vacuous as a cross-tenant guard: #20 derives
an entry's scope from the **ledger**, so a hook that declares tenant A while carrying tenant B's
ledger and tenant B's trusted context satisfies every declared-scope comparison. The ledger's scope is
read through this module's existing bounded own-data-descriptor reader, reusing #20's exported
`AuditLedger` shape; no stream reader, entry validation or ledger core is reproduced here. A ledger
that is not an #20 ledger at all is `INVALID_AUDIT_HOOK`, also before any append. A stream carrying no
`projectId` is not congruent with a registry scoped to one, and an unreadable or unrecognised trusted
context is left to #20's own validation, which refuses it.

**After the append, before the registry write.** #20 returns the scope it committed under on the
receipt, and that receipt is re-validated against the registry scope. This is the binding on the
*result* rather than on a declaration, and it is kept as an independent second line: the pre-append
check is what prevents a foreign write, and this one refuses to act on a result that is not provably
in this registry's stream.

A mis-scoped hook is therefore a **pre-append refusal with no side effect at all** — the committed
regression asserts that the registry is unchanged *and* that the foreign ledger's `entries` length and
chain head are unchanged, for activation, for exception registration, and for revocation of a
genuinely live exception (whose `revokedAt` stays `null`).

`gateHighRiskEffect` is reused unchanged, so a sealed ledger, an unusable key or any other
non-committed append leaves the registry **unchanged** with `AUDIT_UNAVAILABLE` or
`AUDIT_EVIDENCE_INVALID` — never a partial promotion, and never a promotion without evidence in its
own scope. A recorded `ADMIN_APPLIED` is always followed by the write it describes, because
validation, approval and the audit gate all complete before the registry is touched. One consequence
is worth stating plainly: because a scope mismatch is refused **before** the append, a `DENIED`
outcome reporting `audit: { status: 'RECORDED' }` can only be an append that genuinely committed into
this registry's own stream, never into another tenant's.

Refusals decided **after** an append also append a best-effort `ADMIN_DENIED` record, and a denial
never depends on that record succeeding. A refusal decided **before** any append — a malformed
approval envelope, audit hook or clock, an unissued or unavailable registry — performs no append at all
and reports `audit: { status: 'NOT_ATTEMPTED', finding: 'NOT_ATTEMPTED' }` rather than one of #20's
codes, so an outcome never reports an audit result it did not observe.

## Simulation: a report, computed by the real seam

`simulatePolicyConfiguration` compares the active configuration with a candidate over a bounded probe
list (`profileId`, `semanticType`, `sensitivity`, `operation`, `sourceTrust`, optional `probeId`).
For each probe it **runs the real #4 seam twice** — once over the active bundle, once over the
candidate bundle — using a fixed, obviously synthetic, module-owned binding that is deliberately not
a tenant's live request context, and a **profile id alone is never treated as a destination**.

Each side is evaluated against the exact sink **its own** configuration declares for the probed
profile. When one side declares no profile at all it is evaluated against the sink the other side
declares, so #4 answers `PROFILE_MISMATCH`/`DENIED` — exactly what an integration would observe for a
request aimed at a destination that configuration does not declare. Skipping that side instead would
hide precisely the transitions #28 asks to be reported. A finding is therefore always an observed
`decidePolicy` outcome rather than a modelled guess, and the committed cases re-derive both sides
independently and compare.

Two independent conditions make a probe an exposure:

- **relaxation** — the candidate's release level exceeds the baseline's, where the level orders
  `DENIED` (0) below `HELD` (10) below a selected treatment (20 + its position in `REMOVE`…`KEEP`).
  Reported as `NEW_EXPOSURE`.
- **a newly exposed destination** — the candidate points the probed profile at an exact sink
  reference the baseline did not, whether because the profile is new or because it was rebound. It is
  reported as `SINK_REBOUND` when the level did not also rise and as `NEW_EXPOSURE` when it did;
  either way the destination itself is newly exposed even where both sides reach the same treatment.
  A candidate that is strictly **more restrictive** — a removed profile, a rebind that moves an external
trust zone into a local one, a lowered ceiling or a tightened rule — is `NARROWED` with reason
`NARROWED_DESTINATION_OR_TREATMENT`: reported rather than folded into `UNCHANGED`, and **never counted
as an exposure**. Only the external-to-local trust-zone direction counts as a narrowing rebind; an
unrecognised trust zone never produces one, so a host-altered bundle stays on the reporting side.

Both conditions feed the report: `newlyExposed.sinks` holds the **exact sink references** the
candidate newly exposes and `newlyExposed.profiles` the profile ids they are reached through, both
sorted and de-duplicated, alongside `newlyExposed.classes`, `newlyExposed.operations` and `count`.
Every finding carries `baselineSink` and `candidateSink` individually, so a rebound destination is
visible per probe. A profile that **neither** bundle declares is the only not-comparable case:
`UNAVAILABLE` with `PROFILE_UNAVAILABLE` and both sides `null`, never counted as a release.
`CREDENTIAL_OR_SECRET` is always `SECRET`, so a probe claiming otherwise is refused as ambiguous
rather than silently reported.

The simulation takes no approval, returns `activation: { state: 'UNAVAILABLE', effect:
'IGNORED_NO_AUTHORITY' }` and `authority: 'NONE'`, and repeats `GOVERNANCE_PROMOTION_GATES`. Its
result is **structurally unusable** as an activation or a registration input, because both accept
only objects this module issued; a committed case feeds the report back into both entry points and
asserts the typed refusal. With no active baseline, an altered bundle or an unreadable registry, it
reports `UNAVAILABLE` rather than comparing.

## The registry is a synthetic substrate

`createPolicyRegistry` produces one plain, inspectable, mutable object for exactly one
tenant/project: the active configuration, a bounded exception list, a cap and an `accepting` flag.
Anyone with host access can rewrite it, which is exactly why the configuration content pin and the
exception digest are re-verified on every read, and why an `accepting: false` registry refuses every
change. It offers no durability, replication, retention, administrative domain, distribution channel
or anchor of its own. A production registry, a production distribution path, an external checkpoint
authority, separation of duties and approval expiry/revocation in a real identity system are all
external obligations.

## Privacy and bounded, defensive reading

No raw original, policy-request content, free-text purpose, caller object or exception message
reaches an outcome, a simulation report, a refusal or an audit record; every refusal is a fixed code
from `GOVERNANCE_REASON_CODES`, and `PolicyGovernanceError` carries a code and a fixed message only.
Fields read verbatim are bounded opaque tokens, so an email, a URL, a host, a path or a pattern cannot
be planted in one. The residual limit is explicit and matches #20's: the registry **stores** the
bounded administrative tokens the trusted integration minted (identifier, purpose, sink reference),
so a protected original that is itself a legal token cannot be distinguished from an identifier —
minting privacy-safe values is an upstream obligation this module cannot discharge.

Every crossing value is read through one bounded `Reflect.ownKeys` snapshot with a key cap, own
**data** descriptors only, no getters, no inherited properties and no second enumeration, so a
time-varying Proxy can neither grow the inspected work set nor smuggle a value in. Arrays are refused
from a declared `length` read that is capped **before** the key set is enumerated, so an over-long
container costs O(1). Caps are applied before any sort, hash, parse or comparison: the probe count
before any `decidePolicy` call, the exception count before any scan, identifier and reference lengths
before any digest. A committed case asserts that a hostile `ownKeys` is invoked exactly once. These
bounds bound the work this module performs; they are not immunity from arbitrary host-level resource
exhaustion, and no such guarantee is claimed.

Timestamps must round-trip exactly (`new Date(ms).toISOString() === stamp`), so an imaginary date
such as `2026-02-31T00:00:00.000Z` — which `Date.parse` happily rolls forward — is a fixed
`INVALID_CLOCK` refusal rather than a silently different instant. `Date.now()` is never read: the
clock is an argument, so every expiry, window and supersession case is deterministic.

## Threat coverage and limits

Within the tested surface this addresses stale or forged policy versions, broad or cross-tenant
exception reuse (in use and in registration), an exception that outlives its purpose or its
configuration, a replayed or substituted approval, simulation treated as activation, a policy altered
after approval, a newly added or rebound destination sink going unreported, a high-risk activation
attempted while the audit is unavailable, and an activation or registration writing its evidence into
another tenant's audit stream. Its new surfaces are the governance
revision, the configuration content pin, the exception object and its registry, the approval
envelope, the audit hook, the probe list, the exact sink reference each side of a probe is evaluated
against, and the pre-append read of the carried ledger's and trusted context's own scopes.

Not proven here, and stated rather than implied: this seam is **not an enforcement boundary**. A pure
governance module that authenticates nothing and sends no bytes is evidence for a seam, not proof of
protected-egress safety. It does not authenticate approvers or verify project membership; it does
not distribute, deploy, cache or expire a policy in production; it does not enforce anything at a
sink; it does not transform content, broker an original or perform a final-byte egress check; and it
does not implement #13 treatment semantics or the #19 send path. The in-memory registry is host-
writable by anyone with process access, and the audit hook inherits #20's honest storage boundary
(confirmed commit in this array, not external durability). A mis-scoped audit hook is refused before any append (see *Audit* above) and therefore has no side
effect at all; what stays upstream is the trusted deployment's job of passing the ledger that belongs
to the registry being written. The configuration snapshot holds the caller's bundle object, so the
content pin is re-derived and the profiles are read as two separate steps: a host that rewrites the
bundle between them is the same host-writable boundary the registry already has, and is not detected
as a distinct attack. The simulation diffs two
configurations, not the traffic that will actually run: a decision that is correct for the probed
class, sensitivity, operation and profile says nothing about an unprobed combination, an actual
redirect, or a classification the probe did not compose, and the probe set is caller-supplied. Detector and classifier recall, actual
route observation, downstream transformation fidelity, held-out evaluation and any production
approval authority remain upstream obligations and are not discharged by the cases here.