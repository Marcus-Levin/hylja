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
