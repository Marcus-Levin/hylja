#!/usr/bin/env python3
"""Trusted research driver: runs inside the sandbox, never handles candidate text.

Steps, in order: create a throwaway virtualenv, install the screened wheels
offline from the read-only bind, run the smoke child from that virtualenv, then
read the child's result through the fixed schema.

Two boundaries matter here:

* **Untrusted child execution** goes through :mod:`bounded_run`: child output is
  counted and discarded, a hard output ceiling and a wall-clock deadline are
  enforced, and every failure becomes a fixed code. ``RLIMIT_FSIZE`` in the
  sandbox bounds regular files but not pipes, so this step is what bounds them.
* **Untrusted child results** go through :mod:`child_result_schema`: booleans,
  range-checked integers and fixed codes only; rejected entries are counted, not
  named.

This module additionally derives the runtime version observations itself, on the
trusted side, by reading the installed distribution metadata with a strict
grammar and comparing it to the recorded pins. The child no longer supplies any
string at all.

    usage: trial_driver.py [work-dir]   (default /work, as seen inside the sandbox)
"""

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bounded_run  # noqa: E402
from child_result_schema import read_result  # noqa: E402

WORK_DIR = sys.argv[1] if len(sys.argv) > 1 else "/work"
RESULT_PATH = "/tmp/result.json"
SITE_DIR = "/tmp/venv/lib/python3.14/site-packages"
VENV_PYTHON = "/tmp/venv/bin/python"
DEFAULT_STEP_TIMEOUT = 120
OUTPUT_CAP = 64 * 1024
METADATA_HEAD_BYTES = 64 * 1024

# Recorded pins for this screen. These are trusted constants, so reporting them
# discloses nothing about the child.
EXPECTED_DISTRIBUTIONS = {
    "presidio-anonymizer": "2.2.364",
    "cryptography": "48.0.1",
}
VERSION_GRAMMAR = re.compile(r"^[0-9]{1,4}(\.[0-9]{1,4}){1,3}([A-Za-z0-9.+!_-]{0,16})$")
PYTHON_VERSION_GRAMMAR = re.compile(r"^[0-9]{1,2}\.[0-9]{1,2}$")


def step_timeout():
    """Bounded, validated per-step wall-clock limit from the environment."""
    raw = os.environ.get("HANDOFF_STEP_TIMEOUT_SECONDS", "")
    if not raw.isdigit():
        return DEFAULT_STEP_TIMEOUT
    return max(bounded_run.MIN_TIMEOUT, min(int(raw), bounded_run.MAX_TIMEOUT))


def _normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def installed_version_matches_pin(distribution, expected):
    """Read installed distribution metadata and compare it to a recorded pin.

    Trusted-side work: the installed metadata is located by its ``Name`` field
    (the offline installer unpacks wheels verbatim, so the directory spelling
    follows the wheel rather than the normalized name) and parsed here with a
    strict grammar, so no value from it is reported -- only the boolean.
    """
    try:
        entries = sorted(os.listdir(SITE_DIR)) if os.path.isdir(SITE_DIR) else []
    except OSError:
        return False
    for name in entries:
        if not name.endswith(".dist-info"):
            continue
        metadata = os.path.join(SITE_DIR, name, "METADATA")
        try:
            if not os.path.isfile(metadata) or os.path.getsize(metadata) > METADATA_HEAD_BYTES:
                continue
            with open(metadata, "rb") as handle:
                head = handle.read(METADATA_HEAD_BYTES).decode("utf-8", "replace")
        except OSError:
            continue
        declared_name = None
        observed_version = None
        for line in head.splitlines():
            if not line.strip():
                break
            lowered = line.lower()
            if declared_name is None and lowered.startswith("name:"):
                declared_name = line.split(":", 1)[1].strip()
            elif observed_version is None and lowered.startswith("version:"):
                observed_version = line.split(":", 1)[1].strip()
        if declared_name is None or observed_version is None:
            continue
        if _normalized(declared_name) != _normalized(distribution):
            continue
        return bool(VERSION_GRAMMAR.match(observed_version)) and observed_version == expected
    return False


def runtime_observations():
    """Trusted-side facts about the runtime this driver is executing in."""
    observations = {"python_version": "%d.%d" % sys.version_info[:2]}
    if not PYTHON_VERSION_GRAMMAR.match(observations["python_version"]):
        observations["python_version"] = "UNPARSEABLE"
    for distribution, expected in EXPECTED_DISTRIBUTIONS.items():
        observations["%s_version_matches_pin" % distribution.replace("-", "_")] = \
            installed_version_matches_pin(distribution, expected)
    return observations


def assemble_report(steps, child_result, rejected_count, runtime_observations):
    """Build the single JSON report. Contains only codes, counts and booleans."""
    report = {
        "steps": steps,
        "child_result": child_result,
        "rejected_key_count": int(rejected_count),
        "runtime_observations": runtime_observations,
        "candidate_result_is_advisory": True,
    }
    return report


def run_steps():
    steps = []
    timeout = step_timeout()
    steps.append(dict(
        step="venv_create",
        **bounded_run.run_bounded(
            ["/usr/bin/python3", "-m", "venv", "--without-pip", "/tmp/venv"],
            timeout=timeout, output_cap=OUTPUT_CAP)))
    if os.path.isdir(SITE_DIR) and os.path.exists(VENV_PYTHON):
        steps.append(dict(
            step="offline_install",
            **bounded_run.run_bounded(
                ["/usr/bin/python3", os.path.join(WORK_DIR, "install-wheels.py"),
                 os.path.join(WORK_DIR, "wheels"), SITE_DIR],
                timeout=timeout, output_cap=OUTPUT_CAP)))
        steps.append(dict(
            step="smoke_child",
            **bounded_run.run_bounded(
                [VENV_PYTHON, os.path.join(WORK_DIR, "smoke_child.py"), WORK_DIR],
                timeout=timeout, output_cap=OUTPUT_CAP)))
    else:
        steps.append({"step": "smoke_child", "outcome": "SPAWN_FAILED", "exit_code": -1,
                      "stdout_bytes": 0, "stderr_bytes": 0, "retained_bytes": 0,
                      "output_limit_exceeded": False})
    return steps


def main():
    # Steps first: the child's result only exists once the child has run.
    steps = run_steps()
    accepted, rejected, error = read_result(RESULT_PATH)
    report = assemble_report(
        steps=steps,
        child_result=accepted,
        rejected_count=rejected,
        runtime_observations=runtime_observations(),
    )
    if error:
        report["child_result_error_code"] = error
    json.dump(report, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        # A fixed code, never a traceback or a candidate byte.
        sys.stdout.write(json.dumps({"driver_error_code": "DRIVER_ERROR"}) + "\n")
        sys.exit(1)
