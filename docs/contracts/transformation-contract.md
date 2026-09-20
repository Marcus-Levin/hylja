# Transformation contract

Status: draft foundation contract.

A transformation receives an authorized policy action, canonical entity/candidate metadata, and a fidelity contract. It does not choose its own policy.

Required actions: KEEP, MASK, TOKENIZE, SYNTHETIC, GENERALIZE, REMOVE, BLOCK.

Every reversible transformation records a mapping reference, scope, version, and transformation metadata without placing originals into normal logs.

Structured transformers must preserve syntax by construction or return failure; they must not emit malformed JSON/XML/YAML as a successful transformation.
