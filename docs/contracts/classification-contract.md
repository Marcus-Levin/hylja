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

A classifier returns evidence and judgments. It does not return authorization such as "send externally".

Secret-like material defaults to non-reversible classification even when a semantic judge is unavailable.
