# Transformation semantics draft: minimum safe representation for a task (#68)

Status: **proposed design for human review. Not accepted, not normative, not implemented.** Tracked by
[#68](https://github.com/Marcus-Levin/hylja/issues/68), with
[#66](https://github.com/Marcus-Levin/hylja/issues/66), the **proposed**
[decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md), the
[#65 taxonomy research](../research/issue-65-taxonomy-draft-p0.1.md) and the accepted
[decision 009](../decisions/009-secrets-are-not-synthetic-identities.md) as inputs. Implementation status
lives only in [capabilities.md](../capabilities.md). This document does **not** implement
[#13](https://github.com/Marcus-Levin/hylja/issues/13), does not accept decision 010 or the #66
multidimensional draft, changes no v1 classifier or policy rule, appoints no reviewer, and grants no
destination treatment. It is AI-authored and AI-reviewed only, which satisfies no human adoption gate.

Its vocabulary is the **existing draft vocabulary** in the
[information-model draft](information-model-draft.md) and its unwired executable
[`draft-2` model](../../src/information-model-draft.ts) (`EXACT`, `IDENTITY_SYNTHETIC`, `OPAQUE_TOKEN`,
`SEMANTIC_PLACEHOLDER`, `GENERALIZED`, `REMOVED`, `WITHHELD`, the fidelity predicates and
`[hylja:protected:KIND]` placeholders). This document adds **release-form requirements around** that
vocabulary: which form may be produced for which class, what each form must preserve, what it must never
carry, and what has to be bound to it. It does not rename or redefine the draft predicates.

## 1. Scope, and what is deliberately excluded

| In scope | Out of scope (and why) |
| --- | --- |
| Which released form may represent which kind of value, and what each form must preserve or never carry | Destination treatment selection: only the Policy Engine decides ([decision 003](../decisions/003-semantic-judgment-does-not-own-effects.md), [007](../decisions/007-fail-closed-for-protected-egress.md)) |
| The credential-presence semantics #68 asks for, without exposing or reversibly aliasing the value | #13 implementation: no transformer code, no new treatment meaning inside a transformer |
| Low-risk task-critical exact values (port `443`), hidden identity with retained role, repeated entity relations, subnet/topology generalization | Any production authenticator, KMS, vault, broker or transport interceptor: none exists, and this design cannot substitute for them |
| Placeholder typing rules that keep an agent from treating a marker as a usable secret | Any claim that a marker is a security token, capability or proof (see §7) |
| Trusted local USE without reveal as a **shape requirement** for future #17 | A USE grant: no broker exists, so nothing here authorizes using a credential |
| Typed transformation failure instead of original fallback | #43 comparative results: they cannot score before the human-approved #39 freeze (§12) |

The one-fact-one-home rule still applies: this file is the home of *transformation semantics*; release policy
belongs to [flow control](../flow-control.md) and the accepted [#4 policy seam](../../src/policy.ts); the
foundation behaviour a future implementation must not break is in the
[transformation contract](transformation-contract.md); evaluation rules belong to
[evaluation policy](../evaluation.md) and the [#5 seam](synthetic-evaluation-seam.md).

## 2. Release forms and the rules between them

`DERIVED_FACT` is **new in this draft**: the `draft-2` model has no representation for a derived fact,
because a fact about a protected value needs its own decision rather than riding along with a placeholder.

| Form | Intent | Reversible mapping required | Never used for | Obviously synthetic example |
| --- | --- | --- | --- | --- |
| `EXACT` | The exact value survives because this destination is authorized for it | No | A destination whose authorization is absent, implied or merely convenient | `"port": 443` |
| `IDENTITY_SYNTHETIC` | A consistent, entity-scoped stand-in that keeps referential structure | **Yes** — vault + broker, neither of which exists | Credentials, secrets, unresolved sensitivity ([decision 009](../decisions/009-secrets-are-not-synthetic-identities.md)) | `"server": "gw-17.plant.invalid"` |
| `OPAQUE_TOKEN` | A stable opaque reference with no meaning the task can read | **Yes** | Credentials, secrets, unresolved sensitivity | `"user": "[opaque:entity-7a3f]"` (shape only; the token grammar belongs to a reviewed #14/#13 decision) |
| `SEMANTIC_PLACEHOLDER` | A typed marker that states kind and presence only | **No**, and must never be given one | A value the task needs exactly; any case where emitting the *kind* itself is not separately permitted | `"apiKey": "[hylja:protected:API_KEY]"` |
| `DERIVED_FACT` | A locally computed, policy-approved fact about a value | No | Anything not separately approved for the **actual** destination | `"credentialPresent": true` |
| `GENERALIZED` | Reduced precision that keeps the task-relevant class | No | A value needing exact octets or exact identity | `"address": "192.0.2.0/24"` |
| `REMOVED` | The content is gone; existence is gone with it | No | Any value whose presence the task needs (§3) | field deleted |
| `WITHHELD` | No release at all (`BLOCK`/`REQUIRE_REVIEW`) | No | Anything that requires a non-release decision to become a release | interaction held, zero bytes |

Five rules govern combinations, and they are the substance of this draft:

- **R1 — one occurrence, one released form.** A single authorization yields exactly one form per
  occurrence. There is no hybrid output. In particular an `IDENTITY_SYNTHETIC` or `OPAQUE_TOKEN` value may
  never be combined with a `SEMANTIC_PLACEHOLDER`, a `DERIVED_FACT` or a partially masked original of the
  same occurrence.
- **R2 — no synthetic secret, ever.** Credentials and secrets never receive `IDENTITY_SYNTHETIC` or
  `OPAQUE_TOKEN`. A realistic fake credential is treated exactly like a real one for every purpose that
  matters: an agent may send it, a downstream service may accept it by accident, and the moment anyone
  builds the fake↔original table it is a secret-resolution channel. Decision 009 is accepted; this draft
  only states its consequence for transformation output.
- **R3 — a derived fact is a value, not a decoration.** Every `DERIVED_FACT` is separately classified and
  separately authorized for the actual destination. Emitting it because the placeholder was emitted is a
  policy bypass, because "the credential exists" and "the credential is well-formed" disclose different
  amounts.
- **R4 — the transformer narrows nothing and widens nothing.** If policy selected `IDENTITY_SYNTHETIC` and
  the generator fails, the result is `WITHHELD` or a typed failure (§10), never `EXACT`. If policy selected
  `GENERALIZED`, the transformer may choose a coarser class only if policy authorized that class.
- **R5 — a marker is not a token.** `[hylja:protected:API_KEY]` is text. It carries no authority, no
  mapping and no proof that anything was removed (§7).

## 3. Credential presence without exposing or aliasing the value

### 3.1 The states a task must be able to distinguish

`PRESENT` · `EMPTY` · `ABSENT` · `UNRESOLVED` (not parsed, opaque, unsupported format, or parse failure).

The #68 motivating failure is that `REMOVE` turns `PRESENT` into `ABSENT`: the downstream model concludes
no credential was supplied. Two symmetric errors must both be prevented:

- reporting `ABSENT` when a value was `PRESENT` (over-redaction changes the answer's meaning);
- reporting `ABSENT` when the field was **not parsed at all** (`UNRESOLVED`). An uninspected field is
  unknown, not empty, and never becomes a "no credential configured" statement.

`EMPTY` is a distinct state from `PRESENT` and from `ABSENT`, and it is usually derivable without reading
the value; exposing it is still a `DERIVED_FACT` under R3.

### 3.2 Structured form (JSON, YAML, TOML, INI, dotenv, connection strings)

The key stays in place and the placeholder becomes the value, so the container stays valid and existence
survives. Input and released representation, both synthetic:

```json
{
  "server": "gw-07.plant.invalid",
  "port": 443,
  "protocol": "https",
  "apiKey": "PLACEHOLDER_FOR_A_PLANTED_NON_LIVE_KEY"
}
```

```json
{
  "server": "gw-17.plant.invalid",
  "port": 443,
  "protocol": "https",
  "apiKey": "[hylja:protected:API_KEY]"
}
```

Dropping `apiKey`, or replacing it with `null`/`""`, is `REMOVED` and fails the `EXISTENCE` predicate in
the [information-model draft](information-model-draft.md#task-fidelity). A field whose value was never
parsed is `UNRESOLVED` and must not be serialized as `ABSENT`.

The same rule applies to the other structured forms; in YAML the key stays and the marker replaces the
value, so the document still parses and the key still names the credential:

```yaml
server: gw-17.plant.invalid
port: 443
apiKey: "[hylja:protected:API_KEY]"
```

Two encoding facts a transformer must respect rather than work around: a marker is re-encoded for the
syntax the parser found, so inside a URL it appears percent-encoded in the released bytes instead of
literally, and a marker that the found syntax cannot encode — an unquoted YAML plain scalar, for example —
fails closed with `UNENCODABLE_REPLACEMENT` rather than being emitted unencoded. Both are ordinary typed
outcomes of §10, and neither is a reason to relax the encoding.

### 3.3 Unstructured form (log lines, prose, scripts)

The span is replaced, not the sentence, so the surrounding grammar still says what happened:

```text
2026-09-19T08:14:33Z INFO user=demo.operator host=diag-node.example.invalid api_key=[hylja:protected:API_KEY]
```

Requirements: preserve the surrounding key/value or `key=` grammar and quoting; never rewrite the line into
a claim about the credential; never merge two occurrences; and if the credential span overlaps structure
that the parser over-covered (the known over-covering behavior of context detectors), return a typed
failure rather than guessing (§10).

**This form is not supported by any current mechanism, and this draft does not change that.** #7 parses log
text as fields only: `parseStructured(text, 'LOG')` returns `coverage: 'FIELDS_ONLY'`, and
`rewriteFieldValues` refuses anything whose parse is not `FULL`, so a log-line rewrite fails closed with
`SOURCE_NOT_COMPLETE` today. Building the unstructured form is therefore part of the #13 work this draft
feeds (and may need a #7 change), not something the structured path already provides. Until it exists, an
unstructured protected span has no released representation and the surrounding interaction stays held.

### 3.4 Derived facts: default off, individually approved

| Fact | v1 proposal | Rationale |
| --- | --- | --- |
| `credentialPresent` | Emitted with a placeholder **only if policy permits the fact for the actual destination** | It is the whole point of #68, so it should be available, but it is still a disclosure and it must be a decision, not a transformer default |
| `empty` | Off by default | Reveals a property of the value; enable only by explicit destination approval |
| `formatValid` | Off by default | Reveals issuer/format structure, which narrows guessing and can fingerprint a vendor |
| length, character-class entropy, keyed fingerprint | **Excluded from v1** | Length/fingerprint are derived secrets; a keyed fingerprint is still an offline guessing oracle for low-entropy values, exactly as decision 010 flags |
| expiry/rotation metadata | Only from a trusted source that already asserts it, never parsed out of the value | A fact about a secret's lifecycle is itself sensitive and belongs to a secret manager, not to a transformer |

Each enabled fact is a separate `DERIVED_FACT` with its own authorization (R3) and its own record in the
evidence of §11. The provisional "kind and presence only" choice in decision 010 stands; this draft does
not reopen it, and flags the reverse choice as a reviewer decision (§14).

### 3.5 What a downstream tool experiences

An agent that copies `[hylja:protected:API_KEY]` into a `curl` header gets an authentication failure. That
is the intended outcome and must be stated to the task owner rather than fixed by synthesizing a working
credential. The correct remedy is §8.

## 4. Low-risk task-critical exact values (`port` `443`)

`443` is task-critical for HTTPS diagnosis and is normally low-risk, so the contract must make `EXACT`
*representable* without letting usefulness decide anything:

- policy selects `KEEP`/`EXACT` per occurrence. A fidelity contract stating `EXACT_VALUE` is a cost input
  about restrictive treatments; it never selects `KEEP`, and the transformer never upgrades to `EXACT`
  because the task wants the number.
- `EXACT` is per occurrence, not per record: keeping `"port": 443` says nothing about `"apiKey"`.
- `GENERALIZED` must not collapse distinct ports into one class. `443` and `8443` must remain distinguishable
  whenever the task's diagnosis depends on the difference; a "high port" abstraction that maps both to the
  same value is a utility failure dressed up as restraint, not a safe generalization.
- Numbers, booleans, protocol names, units, field names and enum values are ordinary task content. A
  transformation must not infer sensitivity from a key's *name* alone; `port` is not a secret because
  `apiKey` is.
- `VALUE_SHAPE` is a distinct need: a synthetic host must stay a syntactically valid hostname in the right
  position (a URL host, not a log field), and a POSIX path must stay a POSIX path.
- Negative control for reviewers: the same payload must never cloak `443` while leaving a `SECRET` value
  exact, and must never generalize `443` while keeping a protected host exact.

## 5. Identity, role and relations for synthetic entities

- **Entity scope.** `IDENTITY_SYNTHETIC` is minted per canonical entity within an explicitly chosen scope
  (request, session, project, then tenant only when justified). The same entity gets the same stand-in inside
  that scope; two entities never collapse onto one stand-in.
- **Spelling is not identity.** The same string in two scopes does not imply one entity; two spellings of
  one entity must be reconciled by the canonical entity resolver before a single stand-in is minted.
- **Consistency across surfaces.** A host named in a log line and the same host inside a URL in the next
  line are one entity and one stand-in; a customer named in a JSON field and repeated in the note field is
  one customer. The existing D02/D05 oracle proposals already require this
  ([oracle draft](../research/issue-39-public-development-oracle-p0.1.json)); transformation must not be
  able to satisfy it by accident.
- **Role survives without identity.** A role such as "primary on-call", "database" or "gateway" is task
  content and may be retained as a task-authored attribute, but it is **not** derived from the original
  string by guessing, and it is not free: a rare role plus a rare attribute is itself a re-identification
  path ([#12](https://github.com/Marcus-Levin/hylja/issues/12)). Role retention therefore needs its own
  authorization: as authored task content it is a fidelity-contract attribute, and it becomes a
  `DERIVED_FACT` only when something computed it from the protected value — never a default of either. The
  accepted utility notes in [cloaking](../cloaking.md#fidelity-contracts) remain the starting point.
- **Repetition is evidence.** The number of distinct protected references to one entity in one task, and how
  rare each retained attribute is, feeds the re-identification signal; a design that keeps every reference
  consistent can still be over-revealing through combination.
- **Cross-scope resolution is a defect.** A stand-in minted under one tenant, project or session must never
  resolve under another, even when an exception policy exists.

## 6. Generalization: subnet and topology

`GENERALIZED` reduces precision while keeping the class the task reasons about. For addresses and networks
the retained properties are: address family and version, scope class (documentation, private, public), a
prefix/topology class that keeps "these hosts are on the same segment", and the position of the host in the
task's structure. The dropped properties are the exact octets or prefix length that pin one host or one site.

```json
{ "endpoint": "https://gw-17.plant.invalid", "peer": "198.18.7.17", "segment": "198.18.7.0/24" }
```

```json
{ "endpoint": "https://gw-31.plant.invalid", "peer": "198.18.7.31", "segment": "198.18.0.0/15" }
```

Constraints:

- **Shape beats coarseness inside a typed field.** If a field is an address, it stays an address: write a
  distinct documentation-range substitute there and express "same segment" as a separately authorized
  `DERIVED_FACT`, rather than putting a CIDR into a field the consumer reads as one host. A field whose
  declared type is already a network/prefix may be coarsened in place, and the coarsest class the task can
  tolerate is a policy decision, not a transformer choice.
- A generalized value is never presented as the exact value, and never as one that was measured.
- Distinctness is preserved: the D02 oracle requires a *distinct* documentation-range substitute, so
  generalizing two different hosts onto one address is a correctness failure, not a maximalist success.
- Substitution stays inside documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
  `198.18.0.0/15`) and `.invalid` names, so a released example can never be routed to.
- An over-coarse generalization that erases a task-relevant distinction (which segment, which role, which
  of two services) is scored as a utility failure, not a privacy win.
- A field whose declared type is a network or prefix may keep its **class**, and the example above coarsens
  the prefix for exactly that reason. Keeping an exact prefix is acceptable only where that prefix *is* the
  class the task needs, such as a documentation prefix in a prefix-typed field.
- Under-generalization is scored as a privacy failure: keeping a /32 that uniquely identifies one host,
  keeping a prefix that uniquely identifies one site, or keeping the last octet next to a rare role.

## 7. Placeholder typing: inert by construction, and never a security token

A placeholder is written into text that a model or an agent may execute. The grammar is therefore
constrained so that accidental execution cannot succeed and cannot be mistaken for a live secret:

- ASCII only, bounded length, and a fixed structure (`[hylja:protected:KIND]` with an uppercase kind token);
- no quotes, whitespace, newline, backslash, `$(`, backtick, `;`, `|`, `&`, `<`, `>`, path separators,
  leading `-`, scheme separator, or trailing punctuation that could concatenate into a longer token;
- not a plausible secret: not high-entropy, not a credential-shaped prefix, not a PEM header, not valid URI
  userinfo, not a resolvable DNS name, not a file path;
- valid inside every supported container: JSON string escaping, XML text and attribute context, YAML/TOML
  quoting, dotenv/shell assignment — the same obligation the
  [transformation contract](transformation-contract.md) already states for structured payloads. Where the
  found syntax cannot encode the marker, the rewrite fails closed (`UNENCODABLE_REPLACEMENT`, §3.2); the
  marker is never emitted unencoded to "make it fit".

Inbound handling is the mirror image: placeholder-shaped text arriving in *input* is untrusted content. It
is escaped or flagged, never read as Hylja-issued ([decision 010](../decisions/010-separate-information-dimensions-and-task-fidelity.md),
item 6). An agent that executes a placeholder fails closed, and no original is resolvable from it (R2).

The same grammar is already honoured in **two** live places, both by shape alone. The v1 credential detector
(`isReference` in [`src/secret-detectors.ts`](../../src/secret-detectors.ts)) treats a whole marker value as
a template reference and emits **no candidate** for it, and the #19 sentinel honours it again at pattern
level (§11). The detector is the consequential one, because with no candidate there is no `SECRET`
classification at all, so decision 009's credential ceiling and decision 010's `SECRET` floor never apply to
that value — the sentinel finding is downstream of the missing one. That is why the inbound rule and §13's
grammar review are live questions rather than theoretical ones.

Design consequence, which this draft states but does not implement: a marker-shaped value found in *input*
is an ordinary unclassified value and never a pre-cleared one, and a transformation may only emit a marker it
created and tracked itself in this request. Recognition in either direction is not evidence.

**Explicit non-claim.** A placeholder is text with a shape. It is not a security token, capability, receipt
or proof of removal; an attacker who knows the grammar gains nothing from it, and its presence proves
nothing about the original. Every claim in this document rests on deterministic policy plus the independent
post-serialization check (§11), never on the marker's spelling.

## 8. Trusted local USE without reveal (future #17)

Shape of the intended flow, all values synthetic:

```text
model (external)      : "Is the supplied API key accepted?"  -> carries only [hylja:protected:API_KEY]
trusted local effect  : uses the real credential from the real secret-management path
model (external)      <- {"credentialPresent": true, "authenticationResult": "401"}
```

Requirements this design places on #13 and #17 without implementing either:

- the original enters the trusted local operation and the boundary, never the model context;
- `USE` does not imply `DISPLAY`, and `DISPLAY` does not imply `EXPORT`
  ([security invariant 4](../security-model.md#security-invariants));
- the outcome is itself a value crossing back toward a sink: it gets its own inspection and authorization,
  and a status code is still data derived from a protected operation;
- resolution is purpose-, destination-, session- and tenant-bound through a broker; there is no bulk or
  direct mapping lookup ([decision 004](../decisions/004-brokered-vault-no-direct-mapping-api.md));
- a model request must never carry a value that only USE can produce; if a task states `EXACT_VALUE` for a
  credential, the draft's fidelity assessment returns `USE_WITHOUT_REVEAL`, which is a statement about the
  only acceptable remedy, not a grant.

Current status: **no broker, vault, key hierarchy or authenticator exists.** This section constrains a
future design; it authorizes nothing and proves no round trip.

## 9. Task fidelity never bypasses deterministic policy

- A fidelity contract states what the task needs. It may only raise the cost of a restrictive treatment
  inside decision 010's model. It never selects a treatment and never widens release.
- Every derived feature — presence, emptiness, validity, role, relation, generalized prefix, local effect
  outcome — is approved for the **actual destination** in its own right (R3). "The task needs it" is not
  approval.
- Untrusted content cannot supply authority: not the payload, not a model reply, not a fixture's own metadata
  (the public development fixtures say so themselves), not a launcher flag.
- Semantic judgment remains evidence. A judge that says "this value is fine" or "use `KEEP`" cannot produce
  either.
- A failure anywhere in the semantic or parse path leaves the release as restrictive as it was; utility is
  never the reason a protected value crosses.

## 10. Untrusted structure, unsupported formats and typed failure

A span may be rewritten only when the structure it sits in is trustworthy. Proposed typed outcomes
(names are illustrative and belong to #13's acceptance, not adopted here):

`TRANSFORM_UNTRUSTED_STRUCTURE` (malformed/opaque/ambiguous parse, duplicate keys, over-covered spans,
stale or overlapping locations) · `TRANSFORM_UNSUPPORTED_FORMAT` (representation outside declared coverage) ·
`TRANSFORM_GENERATOR_UNAVAILABLE` (synthetic generator or mapping service down) ·
`TRANSFORM_RESERIALIZATION_INVALID` (the rewritten document no longer parses as its own format) ·
`TRANSFORM_OUTPUT_NOT_VERIFIABLE` (the result cannot be tied back to checked bytes).

Those names are the transformer-level proposals. A parser refusal that already exists — #7's
`SOURCE_NOT_COMPLETE` when a source is not fully covered (§3.3) and `UNENCODABLE_REPLACEMENT` when the found
syntax cannot encode the replacement (§3.2) — is inherited as-is rather than renamed, so one refusal is
reported once with its own code instead of being translated into a second vocabulary.

For every one of them:

- **no original fallback**, never a partial success reported as success, and never a silent substitution of
  a less restrictive action;
- the only recovery is a separately authorized, verifiably safer **whole-payload** treatment (for example
  `MASK`/withhold of the entire protected interaction) that itself passed policy;
- an unparsed protected field stays `UNRESOLVED`; a streaming segment awaiting inspection stays held.

## 11. Binding and provenance a transformation must carry

Provenance uses opaque references only. No original, no reversible alias table, no raw payload, and no
free-text reason reaches an ordinary log, report or audit record.

| Binding | Proposed content | Why it exists |
| --- | --- | --- |
| Transformation contract | Contract id and version, `transformation-pack` version | A reviewed output shape is a versioned artifact ([evaluation](../evaluation.md#intelligence-bundle)) |
| Policy provenance | Policy id/version plus pinned content digest, and the selected per-occurrence treatment | [decision 005](../decisions/005-evaluation-precedes-authority.md); the transformer reports the decision it executed, never one it chose |
| Classification provenance | Digest of the composed classification actually consumed | Binds output to the exact evidence that justified it |
| Task-fidelity evidence | `taskRef`, contract version, contract digest, and the occurrence/entity refs it covers | A fidelity contract that does not bind to the request is not evidence about this request; a missing or mismatched binding **holds** the request ([third interview round](../research/issue-65-66-grill-working-notes-p0.1.md#third-interview-round-agreed-directions-and-q14-correction)) |
| Exact payload/source metadata | Interaction ref, representation id and serialization version, bounded field pointer, span unit and view id, per-occurrence released form, typed failure codes | Lets a reviewer or sentinel re-derive *which* bytes were produced from *which* source locations |
| Exact sink metadata | The **observed** destination/sink ref and profile, plus a digest of the exact serialized body **and** metadata that will cross | The independent check applies to those bytes and nothing after them |
| Sentinel provenance | Which independent check ran, on which digest, with which result | An unattested release is not a checked release |

Three limits are stated rather than designed around:

- **Two live components already recognise the placeholder grammar, and both do it by shape alone.** The v1
  credential detector ([#8](https://github.com/Marcus-Levin/hylja/issues/8), `isReference` in
  [`src/secret-detectors.ts`](../../src/secret-detectors.ts)) skips a credential-shaped value whose *whole*
  text is a marker, so it emits **no candidate** for it, and the #19 sentinel core
  ([#19](https://github.com/Marcus-Levin/hylja/issues/19)) exempts the same shape again, though not in every
  rule and not for one reason: `pattern.credential-assignment` exempts a whole marker because its
  `REFERENCE` set carries the marker alternative (and an unquoted one because that rule's not-a-value test
  starts with a bracket), and `pattern.authorization-credential` lets a marker through only incidentally,
  because its token character class cannot match a bracketed marker at all. The userinfo rule does **not**
  exempt it: `pattern.url-password` exempts a different reference set (`URL_PLACEHOLDER` — `${VAR}`, `{{x}}`,
  `<x>`, `$VAR`, `%s`) that carries no marker alternative, so a marker in URL userinfo is still flagged
  `BLOCK`. Where the shape is exempted, `[hylja:protected:KIND]` with an uppercase kind sits beside
  `${VAR}`, `{{x}}`, `<x>` and `***`. That is recognition, not authentication: nothing tracks which markers
  this request actually emitted, the kind is not validated against any allowed set, and no destination
  decision is consulted. The consequence is
  ordered, and the first step is the serious one: a marker-shaped credential value produces **no `SECRET`
  candidate**, so it is never classified `SECRET`, so decision 009's ceiling and decision 010 item 1's
  deterministic credential floor never constrain its representation at all; the sentinel exemption is the
  later, weaker effect. A forged marker with an arbitrary uppercase kind is currently indistinguishable
  from an issued one at the sites that exempt it (the `draft-2` model is equally permissive:
  `parseSemanticPlaceholder` accepts any uppercase kind). This document changes no code; the properties
  #8/#13 and #19 need — issuance tracking, kind validation, and marker-shaped text treated as a reference
  only where policy approved it, each with negative tests for forged markers — are the concrete input to
  §13 gates 4 and 5.
- **The sentinel is called by a harness, not by a production adapter.** The only caller today is the #104
  adapter-conformance harness, which runs `checkEgress` as a harness-owned pre-send control over controlled
  in-memory captures (see the [release-integrity contract](release-integrity-contract.md)). No production
  adapter calls it at a send point, so its presence in the tree is conformance evidence for synthetic
  adapters, not an enforced egress boundary.
- **This document invents no authenticator.** Who authenticates the principal, tenant, project, purpose and
  actual route is a trusted-integration obligation outside this draft; digests and fingerprints are replay
  commitments, not credentials, and a caller able to fabricate the bound context can fabricate the record.

## 12. Paired privacy/utility development scenarios

These are **proposals for #39/#5**, expressed as scenario pairs: a privacy assertion that must hold at the
exact serialized bytes, and a utility assertion whose expected answer is authored independently of any
candidate output. They reuse the existing [#5 seam](synthetic-evaluation-seam.md) — registration, an
independently authored planted oracle, controlled in-memory capture, task grading — and add **no second
framework**, no committed fixture and no score. Expectations here are placeholders for the humans who own
them; nothing here is a lock, an oracle label or a result.

| Id | Shape (synthetic) | Proposed released form | Privacy assertion | Utility assertion (independently authored) | Status |
| --- | --- | --- | --- | --- | --- |
| T1 | JSON config with a planted non-live key | `SEMANTIC_PLACEHOLDER` in place, key retained | No credential bytes in body or metadata; the *absent* key is still absent | Answer must state that a credential was supplied, not that none was | Proposed DEV case; oracle/treatment owner pending |
| T2 | Same config with the key field deleted upstream | `REMOVED`/absent | No credential bytes | The two answers must **differ**; a candidate that emits the same representation for both fails utility | Proposed DEV case |
| T3 | JSON config with `""` as the value | `SEMANTIC_PLACEHOLDER` (+ `empty` only if approved) | No credential bytes | Distinguishes empty from present only when policy approved that fact | Proposed; derived-fact policy pending |
| T4 | Unsupported/opaque fragment that cannot be parsed | `UNRESOLVED`, no value emitted | No original bytes, no claim of absence | The task answer must not assert "no credential configured" | Proposed DEV case |
| T5 | HTTPS config with `"port": 443` | `EXACT` | Port is not a protected value; a secret in the same payload still has zero bytes | Effective port semantics unchanged; `443` and `8443` stay distinguishable | Proposed DEV case, extends D02/D05 |
| T6 | Diagnostic log: host repeated in a log field and a URL | One `IDENTITY_SYNTHETIC` for both | Original hostname absent everywhere including metadata | The diagnosis keeps host-role and HTTPS/port semantics | Proposed; **needs #14 identity resolution and a vault** |
| T7 | Support note: one customer, one project, repeated references | Consistent `IDENTITY_SYNTHETIC` | Originals absent; identities not correlatable across scopes | Primary/backup relation and escalation order intact | Proposed; extends D01 |
| T8 | Two hosts on `192.0.2.0/24` | `GENERALIZED` per host + `DERIVED_FACT` same-segment | Exact octets absent | Topology ("same segment", distinct hosts) preserved | Proposed |
| T9 | Agent asked to "call the API with the key" | `USE_WITHOUT_REVEAL` shape | Original never in model context | Model reports the local outcome, not a fabricated success | **Untested until #15/#16/#17 exist** |
| T10 | Input containing literal `[hylja:protected:API_KEY]` text | Escaped/flagged, never trusted | No privilege gained by the shape | Task unaffected by spoofed marker text | Proposed adversarial DEV case |
| T11 | Placeholder pasted into a shell command by the agent | `SEMANTIC_PLACEHOLDER` | No original resolvable; nothing reconstructible | Command fails closed with a clear error | Proposed adversarial DEV case |
| T12 | Transformer failure: generator unavailable / invalid reserialization | `WITHHELD` + typed code | No original fallback bytes | No task answer claimed | Proposed; pairs with #13 acceptance |
| T13 | Attacker text made a credential value look like a marker, in input and in a released payload | Marker-shaped text is data, never an issued reference | Two layers, in order: **detection** — a marker-shaped credential value must not silently lose `SECRET` (#8/#13), and a forged uppercase kind must not be accepted as a reference any more than an issued one is unverified; **egress** — an issued marker and a forged one must not share one sentinel verdict for free (#19), per §11 | Task is unaffected by spoofed marker text | Proposed adversarial DEV case; depends on #8/#13 and #19 hardening decisions |

### 12.1 What evidence exists today, and what is required later

| Available now (public, unscored, development only) | Required later (not available, blocking comparison) |
| --- | --- |
| D01/D02/D05 public development fixtures and their independently reviewed oracle *proposals* | A frozen #39 v0 protocol: independently planted blind oracle, held-out split, scoring rules |
| The unwired, pure, property-tested `draft-2` model (fidelity assessment, placeholder grammar, oracle annotation schema) | Human acceptance of #65/#66 dimensions, decision 010, destination treatments and task answers |
| #7 structured parsers whose `rewriteFieldValues` round-trips JSON, DOTENV, INI, URL, connection strings and quoted YAML/TOML/XML | #13 implemented and run under the frozen protocol |
| #7 refusing a marker it cannot encode in the found syntax (plain YAML scalar → `UNENCODABLE_REPLACEMENT`) and refusing logs outright (`FIELDS_ONLY` → `SOURCE_NOT_COMPLETE`) — fail-closed, usable as typed-failure cases | A round-trip-safe **unstructured** rewrite for logs and prose; §3.3 has no mechanism today |
| The #5 seam's exact serialized body/metadata capture and planted-escape counting in a controlled local sink | A #19-equivalent sentinel at a real send point, with placeholder recognition |
| The non-enforcing sentinel's high-risk pattern set and #8's shape-only marker-reference exemption (§11), usable as negative-control design references | #14–#17 scoped identity, vault, keys and broker for any reversible or USE case |
| — | #8/#13 candidate generation and #19 recognition hardened with issuance tracking and kind validation, so a marker-shaped credential value cannot silently stop being `SECRET` (§11, T13) |
| — | [#43](https://github.com/Marcus-Levin/hylja/issues/43) engineering-fidelity and restoration comparisons, which #43 itself labels **predicted/untested** for Hylja's design until it is runnable under the frozen protocol |

Therefore: **#68 cannot be closed by local tests.** What local evidence can do is prove that the vocabulary is
consistent and testable; what it cannot do is establish that the semantics preserve utility, that a
destination may receive a placeholder or derived fact, or that anything is releasable. Any comparison
numbers that appear before the human-approved #39 freeze would be development observations, not results.

### 12.2 Wiring, not a new harness

If and when these scenarios are implemented, they belong in the existing seam: each case is registered with
`createDevelopmentEvaluation`, the oracle is authored independently of candidate output, the candidate is
handed a frozen candidate-facing view, and the release is graded from an evaluator-owned capture of the exact
serialized bytes. The evaluator mints ordinary report references, `untested` stays `untested`, and a missing
capture is never a zero-leak pass. A new expectation schema, a second scorer or an unblended scorer would
contradict [#39](https://github.com/Marcus-Levin/hylja/issues/39)'s "does not create a second evaluation
framework" constraint.

## 13. Proposed gates

Ordered, each fail-closed, none satisfied by this document:

1. **Human acceptance of decision 010 and the #66 dimensions** (or an explicit amendment). Until then the
   fidelity predicates, the `UNRESOLVED` ceiling and the placeholder grammar stay proposals.
2. **An independent application/task reviewer** validates the §12 utility assertions, especially T1–T5, from
   work experience — the same role split already requested in the
   [#65/#66 review handoff](../research/issue-65-66-independent-review-handoff-p0.1.md).
3. **A separate policy reviewer** decides, per destination, whether `SEMANTIC_PLACEHOLDER` and which
   `DERIVED_FACT`s may be released at all.
4. **A placeholder-grammar and spoofing review** of two live paths: inbound handling, execution inertness,
   whether placeholders need any per-request binding, and what the detector's existing shape-only marker
   exemption must require before a marker-shaped credential value is ever treated as a reference instead of
   a `SECRET` candidate (§11).
5. **A detection-and-egress review** with the same input: #8 candidate generation, #19 placeholder
   recognition, forged-marker rejection, issuance tracking and the exact-byte sentinel requirement of §11.
6. **Broker/vault readiness** (#14–#17) before any `IDENTITY_SYNTHETIC` or USE claim; the design says nothing
   about how those are built.
7. **#39 v0 freeze**, then [#43](https://github.com/Marcus-Levin/hylja/issues/43) measured evidence feeding
   back into these semantics before #13 is finalized, as #43 itself requires.

## 14. Open questions for the reviewers

1. Should `credentialPresent` be a policy default alongside the placeholder, or always an explicit
   per-destination decision?
2. May `empty`/`formatValid` ever be released for a `SECRET` occurrence, and to which destinations?
3. Does a low-risk exact value such as a port need an explicit policy rule, or is per-occurrence `KEEP` plus
   the negative control sufficient?
4. Where does host/customer **role** vocabulary live, who authors it, and what stops role retention from
   becoming a re-identification channel?
5. Under unresolved sensitivity, is the **current proposed position** the right ceiling — a typed
   placeholder only with independently established kind *and* destination-policy permission, otherwise a
   generic marker or withholding (decision 010 item 5, the working notes and the `draft-2`
   `SECRET_REPRESENTATIONS` ceiling) — or should it be tightened to forbid typed placeholders entirely
   there?
6. What is the smallest useful `GENERALIZED` vocabulary per class, and who sets the acceptable granularity?
7. Which of §11's bindings must be in the policy request digest, and which may live only in evidence?

## 15. Limits of this draft

It specifies no behavior any running component has. No test executes it, no transformer implements it, no
destination is permitted by it, and no task is proven solvable with these forms. The `draft-2` model it
refers to remains pure, unwired and **proposed**. It does not accept decision 010, the #66 multidimensional
model or the #65 taxonomy; it does not complete #13, #17 or #19; and it contains no comparative result from
#43, which cannot be scored before the human-approved #39 freeze. Its factual statements about current
behavior — that #7 refuses logs and refuses a marker a plain YAML scalar cannot encode, and that #19
exempts marker-shaped credential values by shape alone — were checked once with disposable bounded probes
at this commit and are deliberately **not** committed as repository tests: a test that only re-reads this
document would prove nothing, and the invariants themselves belong to #7/#13/#19 acceptance.
Examples are obviously synthetic, non-routable and carry no real credential, mapping or infrastructure value.
