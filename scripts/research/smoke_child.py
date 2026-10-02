#!/usr/bin/env python3
"""Presidio anonymizer runtime smoke, executed INSIDE the ephemeral bwrap sandbox.

This process runs from the freshly created, offline-installed virtualenv. It
imports the screened candidate artifact and exercises a small, fixed API surface
on obviously synthetic, non-routable in-memory values.

Untrusted boundary: this is the **untrusted** side. Its stdout/stderr are counted
and discarded by the driver, and its result file may contain only booleans,
range-checked integers and fixed codes -- never a version string, an entity-type
string, an exception class name or any other candidate-influenced text. The
driver re-derives the runtime versions itself from installed metadata.

The installed-tree check reports a **pair** of booleans, not one:
``installed_tree_check_completed`` says whether the comparison ran at all, and
``installed_tree_matches_screened_wheel`` is only meaningful when it is true. If
the check raises, the pair is ``false``/``false`` — not a verified mismatch —
and a consumer must read both, or ``false``/``true`` for a completed check that
found a difference.
"""

import hashlib
import json
import logging
import os
import sys
import zipfile

RESULT_PATH = "/tmp/result.json"
WORK_DIR = sys.argv[1] if len(sys.argv) > 1 else "/work"
CANDIDATE_WHEEL = "presidio_anonymizer-2.2.364-py3-none-any.whl"
MAX_RESULT_BYTES = 64 * 1024
MAX_COUNT = 1_000_000
EXPECTED_ENTITY = "PERSON"

# Obviously synthetic, non-routable planted value. It is a public source-fixture
# constant (tracked in this repository by design); the trial only ever placed it
# in this process' memory and in the sandbox' private tmpfs.
PLANTED = "Testcase Placeholder 0001"
TEMPLATE = "Contact {value} about the synthetic ticket 4242 at person.example.invalid."


def count(value):
    return int(value) if isinstance(value, int) and 0 <= int(value) <= MAX_COUNT else -1


result = {}
stage = "SMOKE_ERROR_AT_IMPORT"
try:
    logging.disable(logging.CRITICAL)

    import presidio_anonymizer
    from presidio_anonymizer import AnonymizerEngine, OperatorConfig, RecognizerResult

    stage = "SMOKE_ERROR_AT_SYMBOLS"
    result["api_symbols_importable"] = True
    result["declared_symbol_count"] = count(sum(
        1 for name in ("AnonymizerEngine", "DeanonymizeEngine", "OperatorConfig",
                       "PIIEntity", "RecognizerResult", "EngineResult")
        if hasattr(presidio_anonymizer, name)))

    stage = "SMOKE_ERROR_AT_ENGINE"
    text = TEMPLATE.format(value=PLANTED)
    start = text.index(PLANTED)
    # presidio-anonymizer 2.2.364 takes the entity type as a plain string; the
    # PIIEntity enum lives in presidio-analyzer, which this smoke does not
    # install (it would pull the NLP stack).
    finding = RecognizerResult(
        entity_type=EXPECTED_ENTITY, start=start, end=start + len(PLANTED), score=0.99
    )
    engine = AnonymizerEngine()
    result["engine_constructed"] = True

    stage = "SMOKE_ERROR_AT_OPERATOR"
    masked = engine.anonymize(
        text=text,
        analyzer_results=[finding],
        operators={"DEFAULT": OperatorConfig("mask", {
            "masking_char": "*", "chars_to_mask": 1000000, "from_end": False})},
    )
    out = masked.text
    result["mask_output_length"] = count(len(out))
    result["mask_output_differs_from_input"] = bool(out != text)
    result["mask_planted_value_absent_from_output"] = bool(PLANTED not in out)
    result["mask_engine_result_count"] = count(len(masked.items))
    result["mask_entity_type_is_expected_person"] = bool(
        masked.items and masked.items[0].entity_type == EXPECTED_ENTITY)

    # 2.2.364 hashes with a random per-entity salt unless the caller supplies
    # one, so only lengths and absence properties are recorded here.
    hashed = engine.anonymize(
        text=text,
        analyzer_results=[finding],
        operators={"DEFAULT": OperatorConfig("hash", {"hash_type": "sha256"})},
    )
    again = engine.anonymize(
        text=text,
        analyzer_results=[finding],
        operators={"DEFAULT": OperatorConfig("hash", {"hash_type": "sha256"})},
    )
    result["hash_output_length"] = count(len(hashed.text))
    result["hash_output_differs_from_input"] = bool(hashed.text != text)
    result["hash_planted_value_absent_from_output"] = bool(PLANTED not in hashed.text)
    result["hash_output_length_stable_across_calls"] = bool(
        len(again.text) == len(hashed.text))
    result["hash_outputs_differ_across_calls"] = bool(again.text != hashed.text)
    result["reversible_operators_exercised"] = False
    result["nlp_or_model_weights_downloaded"] = False
    stage = "SMOKE_COMPLETED"
except BaseException:  # noqa: BLE001
    # The exception class name is deliberately NOT reported: it is candidate- or
    # library-influenced text. Only the fixed stage code leaves this process.
    stage = stage if stage != "SMOKE_COMPLETED" else "SMOKE_ERROR_UNKNOWN"

result["smoke_code"] = stage

stage = "SMOKE_ERROR_AT_INSTALL_CHECK"
try:
    import presidio_anonymizer as _pkg

    pkg_dir = os.path.dirname(_pkg.__file__)
    wheel = os.path.join(WORK_DIR, "wheels", CANDIDATE_WHEEL)
    with zipfile.ZipFile(wheel) as archive:
        members = [n for n in archive.namelist() if not n.endswith("/")]
        mismatched = 0
        for name in members:
            if name.endswith(".dist-info/RECORD"):
                continue
            disk = os.path.join(pkg_dir, os.path.relpath(name, "presidio_anonymizer"))
            if not os.path.isfile(disk):
                mismatched += 1
                continue
            with open(disk, "rb") as handle:
                if hashlib.sha256(handle.read()).digest() != \
                        hashlib.sha256(archive.read(name)).digest():
                    mismatched += 1
        result["installed_member_count"] = count(len(members))
        result["installed_members_matching_screened_wheel"] = count(len(members) - mismatched)
        result["installed_tree_matches_screened_wheel"] = bool(mismatched == 0)
    result["installed_tree_check_completed"] = True
except BaseException:  # noqa: BLE001
    # The check did not complete, so the match boolean is not a comparison
    # result. installed_tree_check_completed=False is the disambiguator; the
    # pair (False, False) means "not verified", never "verified mismatch".
    result["installed_tree_matches_screened_wheel"] = False
    result["installed_tree_check_completed"] = False

payload = json.dumps(result)
if len(payload) > MAX_RESULT_BYTES:
    payload = json.dumps({"smoke_code": "SMOKE_ERROR_AT_INSTALL_CHECK"})
with open(RESULT_PATH, "w", encoding="utf-8") as handle:
    handle.write(payload)
sys.exit(0 if result.get("smoke_code") == "SMOKE_COMPLETED" else 1)
