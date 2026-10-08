# Decision 017: Independent public-marker lifetime owner draft

Status: PROPOSED. Not adopted. ISOLATED / NON-ENFORCING / PUBLIC_DRAFT_ONLY.
Independent human adoption is required before any private or accepted-runtime wiring.
This record grants no custody, CREATE, key, authentication, policy, provider or scoring authority.
Work tracking belongs to [#275](https://github.com/Marcus-Levin/hylja/issues/275), under
[#269](https://github.com/Marcus-Levin/hylja/issues/269); implemented behavior and durable
software limits belong only to [capabilities](../capabilities.md).

## Problem and concrete trace

The frozen method separates an outer reporting controller from a holder with strong request
and owner references. Its relevant trace is:

```text
GO accepted -> input attempt begins -> real end callback or child close absent
controller -> UNKNOWN -> local authority revoked / timers cleared / handles released
holder     -> retained request / owner / interval
```

Local release neither settles the attempted input nor proves holder or descendant termination.
A timer dispatched on the blocked owner's event loop is not independent preemption. Replacing
that timer, dropping references, reporting signal delivery, or observing only a parent PID
cannot close the private-copy envelope. The source record is evidence, not adopted authority:
the unreviewed F1 source findings and retained external baseline identified in the
[specification](../specs/f1-public-lifetime-owner-draft.md#source-basis).
No new native qualification follows from these historical reference identities.

## Proposed choice

Freeze only an abstract, capacity-one PUBLIC-marker model:

```text
reporting controller -- bounded commands --> lifetime owner
independent observation owner -----------> lifetime owner <-- holder / one input child
```

The lifetime owner acquires its immutable attempt and complete modeled envelope before GO.
It owns authority, the absolute deadline/high-water clock, sticky stops, effect counters and
terminal evidence. The reporting controller owns neither that clock nor the evidence store;
losing it cannot clear the owner's state. Observation ownership is separate from controller
commands. In a pure experiment these are nonserializable handles, not authenticated processes.
The exact shapes, transitions, terminal predicate, bounds and future counterexamples have
one home in the [draft specification](../specs/f1-public-lifetime-owner-draft.md).

This is a proposed topology change, not a new name for the old controller's revoked authority.
Controller loss stops effects; it does not authorize recovery, a fresh lease or reacquisition.
Owner/observer loss or unsupported facts latch UNKNOWN. Passive terminal observations may
record settlement after a stop, but cannot revive authority or turn UNKNOWN into success.
An attempted input retires only after the actual end callback AND actual child close; a
thrown end call manufactures neither. No signal/probe after UNKNOWN, exit, close, revocation
or expiry is permitted. The model exposes no signal/probe action at all.

## Why this boundary, and not more machinery

The necessary change is independent ownership of evidence and lifetime, before any effect.
A generic authority framework, arbitrary process/path selectors, caller callbacks, renewal,
retry and descendant discovery would add surfaces without supplying missing terminal facts.
They are excluded. Small public primitive bounds limit only this prototype's canonical input
and state; they do not restore any removed whole-arm model-request cap.

A pure `MODEL_COMPLETE` proves a predicate over synthetic events only. A future native
`COMPLETE` would require real independently owned callback, exit, close, reaping and full
owned-envelope absence observations under an explicitly supported failure model. No native
mechanism is selected here. In particular no cgroup, pidfd, container, privilege, independent
reaper, bounded scheduler or kernel recovery is assumed. Where those facts cannot be obtained,
private admission is refused as unsupported, not declared universally impossible or qualified
`F1_NOT_READY`.

## Consequences and gates

1. Freeze the public contract before separately admitted behavior tests. Require genuine
   behavioral RED then GREEN, generated isolation/order boundaries and adversarial cases.
2. A separately admitted public native method needs complete actually relied-on source/type
   inspection, provenance, finite controls and exact-head independent review. Abstract events
   and caller metadata cannot authenticate OS facts. No automatic native/private successor.
3. Human ownership adoption and separately admitted source, custody and effect gates remain
   prerequisites for any private work. A prose commit, AI review or public test does not satisfy them.
4. [Accepted012](012-synthetic-engineering-custody-preconditions.md) authorizes no key,
   custody or CREATE effect. [Accepted014](014-authenticated-local-request-evidence.md)
   accepts staged synthetic authentication direction, not this lifetime owner.
   Decisions 013/014, classification v1, policy and all existing runtime contracts stay unchanged.
5. [001](001-enforcement-core-not-advisory-filter.md),
   [003](003-semantic-judgment-does-not-own-effects.md),
   [004](004-brokered-vault-no-direct-mapping-api.md),
   [007](007-fail-closed-for-protected-egress.md),
   [008](008-minimize-raw-data-retention.md) and
   [009](009-secrets-are-not-synthetic-identities.md) remain unchanged: deterministic effects,
   fail-closed protected egress, broker-only purpose-bound resolution, USE != DISPLAY != EXPORT,
   short plaintext lifetimes and no reversible credential mappings by default.

No protected bytes, key generation/export, DER/CSR/issuer/OpenSSL operation, TLS, socket,
provider/model traffic, private or held-out data, erasure claim, production privacy claim,
authoritative evaluation or policy/adapter/authenticator import belongs to this proposal.
[Proposed016](016-synthetic-multi-asset-pilot-draft.md) stays separate and unadopted.
