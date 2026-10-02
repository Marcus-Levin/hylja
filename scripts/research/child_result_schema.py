#!/usr/bin/env python3
"""Fixed schema for the research sandbox's child result.

The child process in the smoke runs **untrusted candidate code**. Its result is
therefore accepted only through this module, and only in these forms:

* booleans (exact type ``bool``);
* integers inside a fixed range, with out-of-range values replaced by the
  sentinel ``OUT_OF_RANGE``;
* short strings **only** when they are one of this module's fixed codes;
* rejected entries are counted, never named.

That last list describes the values a **child** may supply. The error code
:func:`read_result` can return is a separate, **trusted-side** namespace: on a
failure to open the fixed result path it returns
``RESULT_READ_ERROR:<PythonExceptionTypeName>``, whose suffix is the class name
of the exception ``open()`` raised on this side of the boundary (e.g.
``FileNotFoundError``), never text the child wrote. The driver emits it as
``child_result_error_code``.

That is deliberately stricter than a key/type allowlist: an allowlist bounds
which *slots* exist, not what an attacker can *write into* them. Truncation is
not a boundary either, so no child-provided string is ever retained verbatim.
A submitted key name is looked up, never echoed. The driver's report can
therefore never carry candidate text, including exception class names the child
might raise: the only class-name suffix this module can emit is the trusted-side
``RESULT_READ_ERROR:`` one described above.

A validated child result is still a **self-report**: these observations are
advisory, are not enforcement evidence, and never grant authority.
"""

import json

MAX_FILE_BYTES = 64 * 1024
MAX_INT = 1_000_000
OUT_OF_RANGE = -1
UNRECOGNIZED_CODE = "UNRECOGNIZED_CODE"
MAX_LIST_ITEMS = 16

# The only strings that may appear in an accepted value.
ALLOWED_CODES = frozenset({
    "SMOKE_COMPLETED",
    "SMOKE_ERROR_AT_IMPORT",
    "SMOKE_ERROR_AT_SYMBOLS",
    "SMOKE_ERROR_AT_ENGINE",
    "SMOKE_ERROR_AT_OPERATOR",
    "SMOKE_ERROR_AT_INSTALL_CHECK",
    "SMOKE_ERROR_UNKNOWN",
    UNRECOGNIZED_CODE,
})

# key -> ("bool",) | ("int",) | ("code",)
ALLOWED_KEYS = {
    "smoke_code": ("code",),
    "api_symbols_importable": ("bool",),
    "declared_symbol_count": ("int",),
    "engine_constructed": ("bool",),
    "mask_output_length": ("int",),
    "mask_output_differs_from_input": ("bool",),
    "mask_planted_value_absent_from_output": ("bool",),
    "mask_engine_result_count": ("int",),
    "mask_entity_type_is_expected_person": ("bool",),
    "hash_output_length": ("int",),
    "hash_output_differs_from_input": ("bool",),
    "hash_planted_value_absent_from_output": ("bool",),
    "hash_output_length_stable_across_calls": ("bool",),
    "hash_outputs_differ_across_calls": ("bool",),
    "reversible_operators_exercised": ("bool",),
    "nlp_or_model_weights_downloaded": ("bool",),
    "installed_member_count": ("int",),
    "installed_members_matching_screened_wheel": ("int",),
    "installed_tree_matches_screened_wheel": ("bool",),
    "installed_tree_check_completed": ("bool",),
}

SHAPE_ERROR = "RESULT_NOT_AN_OBJECT"
READ_ERROR = "RESULT_READ_ERROR"
SIZE_ERROR = "RESULT_TOO_LARGE"


def _coerce(kind, value):
    if kind == "bool":
        return value if type(value) is bool else None
    if kind == "int":
        # Exact type: bool is a subclass of int and must not satisfy an int slot.
        if type(value) is not int:
            return None
        return value if 0 <= value <= MAX_INT else OUT_OF_RANGE
    if kind == "code":
        if type(value) is not str:
            return None
        return value if value in ALLOWED_CODES else UNRECOGNIZED_CODE
    return None


def sanitize(parsed):
    """Return ``(accepted_values, rejected_count)`` for a parsed child result."""
    if type(parsed) is not dict:
        return {}, 1
    accepted = {}
    rejected = 0
    for key, value in parsed.items():
        kind = ALLOWED_KEYS.get(key) if type(key) is str else None
        if kind is None:
            rejected += 1
            continue
        coerced = _coerce(kind[0], value)
        if coerced is None:
            rejected += 1
            continue
        accepted[key] = coerced
    return accepted, rejected


def read_result(path):
    """Read and sanitize a child result file.

    Returns ``(accepted, rejected_count, error_code_or_None)``. Never raises and
    never echoes a key name, a file path or any child byte. ``error_code`` is
    either a fixed code here or the trusted-side
    ``RESULT_READ_ERROR:<PythonExceptionTypeName>`` form documented above.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except Exception as exc:  # noqa: BLE001
        return {}, 0, "%s:%s" % (READ_ERROR, type(exc).__name__)
    if len(raw) > MAX_FILE_BYTES:
        return {}, 0, SIZE_ERROR
    try:
        parsed = json.loads(raw)
    except Exception:  # noqa: BLE001
        return {}, 0, "RESULT_NOT_JSON"
    accepted, rejected = sanitize(parsed)
    if not accepted and rejected == 1 and type(parsed) is not dict:
        return {}, rejected, SHAPE_ERROR
    return accepted, rejected, None
