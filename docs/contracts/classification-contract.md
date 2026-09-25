# Classification contract

Status: draft foundation contract.

A candidate can accumulate evidence from multiple detectors. Classification composition is separate from policy.

Required dimensions:

- semantic type/subtype;
- sensitivity;
- trust;
- provenance;
- reversible/not reversible;
- scope recommendation;
- detector evidence;
- semantic judgments with question-set/model identity where used.

A classifier returns evidence and judgments, including explicit `UNKNOWN`, conflict, abstention, and parser/classifier failure states; a failed parser is not evidence that a field contains no protected content. It does not return authorization such as "send externally".

Composition is deterministic and conservative: conflicting or incomplete evidence remains unresolved for policy, rather than becoming public/benign by default. An established `SECRET` or credential classification cannot be downgraded by a lower-confidence, absent, or contradictory semantic judgment; it remains non-reversible by default. An unknown or failed judgment cannot make protected egress less restrictive; policy selects an explicit safe fallback, review, or block.

Sensitivity and influence trust remain independent. Untrusted payload or model/tool text, even if formatted as a token, provenance entry, or `CONTROL` instruction, cannot promote itself to control-plane trust; authoritative origin comes from the bound interaction context, not semantic classification.

## Version 1 composition clarification

The pure composer receives **separate trusted-integration channels** for detector evidence, parser evidence, and semantic judgments, plus separately supplied source trust and interaction/source references. It does not parse an interaction payload as evidence or authenticate these arguments; the integration must enforce their origin and binding. The #2 envelope's congruence/freshness checks are not evidence of such integration authentication. A model-only `PUBLIC` judgment without detector evidence remains unresolved, not an authoritative absence of protected content.

Each valid record carries `version: 1`, a bounded evidence ID, `FOUND`/`ABSTAIN`/`FAILURE`, an input reference, a producer ID and version; semantic records additionally require question-set and model identity. Fields and input references must be privacy-safe identifiers, not raw originals. Invalid records become redacted `INVALID` evidence and leave the result unresolved; a parser failure, abstention, missing evidence/sensitivity, unknown or unsupported class/subtype, duplicate ID or conflicting claims likewise remains explicit. Composition sorts validated records so arrival order does not determine the result. It retains the highest claimed sensitivity and treats any recognized `CREDENTIAL_OR_SECRET` as `SECRET` even if a conflicting claim says `PUBLIC`; conflicts are still unresolved. An unresolved result is a conservative **input to later policy**, not a release decision.

`reversible` and `scope` are classification recommendations only. SECRET/credential or unresolved records default non-reversible and request-scoped; non-secret reversibility and broader scope require an unambiguous detector recommendation, never a semantic suggestion alone. No recommendation creates a mapping, grants USE/DISPLAY/EXPORT, selects KEEP, or permits egress.
