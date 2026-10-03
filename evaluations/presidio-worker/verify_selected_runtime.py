#!/usr/bin/env python3
"""Verify a selected Presidio analyzer runtime against its pin before execution is accepted.

Standard library only. It **imports nothing from the environment it verifies and executes no code
from it**: it reads the pinned manifest, the cached wheel files, the #46 screen report and the
candidate runtime's ``site-packages``, and prints one JSON line of counts and fixed codes. It never
prints a path, a file name, a file's content, an exception message or a stack trace, so its output is
safe to embed in a shared evaluation record. It reads only what it needs and keeps no file content:
every comparison is made on a digest.

Three independent questions are answered, because a digest-complete screen does not answer all of them:

1. **Name identity.** A pinned record is matched to a cached wheel by SHA-256, and that wheel's *own*
   ``METADATA`` name and version must equal the record's. A record whose name does not correspond to
   the artifact it names is an identity mismatch: it is reported and **excluded** from the selected
   set, not counted as covered. This is the check a digest-complete screen can still pass.
2. **Screen coverage.** Each selected artifact needs a record in the #46 screen report under its own
   normalized name, and that record must be ``OK``, not yanked, advisory-free and carry the same
   observed digest.
3. **Runtime identity.** Every file in the runtime's ``site-packages`` must be a byte-identical member
   of one selected wheel, the installed distribution set must equal the selected set, and there must be
   no ``.pth`` file and no byte-compiled entry. A ``.pth`` line beginning ``import `` is executed by
   ``site`` at interpreter startup, which is exactly how an artifact nobody selected can still run
   code on every process start. An entry that is neither a regular file nor a directory - a symlink
   above all - is counted and **refused**, never skipped, because Python follows a symlink when it
   imports: a skipped one would be an importable module this check cannot see.

The ``status`` this program reports is **derived** from its executed-subset checks rather than asserted,
and the comparison bridge re-derives it again from the checks it accepted and refuses a reply whose own
status disagrees with them. The status therefore never rests on any single string.

  usage: verify_selected_runtime.py <manifest.json> <wheel-dir> <screen-report.json> <site-packages-dir>
"""

import hashlib
import json
import os
import stat
import sys
import zipfile

PROTOCOL = "hylja.presidio.runtime-verification"
VERSION = 1

MAX_WHEELS = 4096
MAX_WHEEL_BYTES = 256 * 1024 * 1024
MAX_RUNTIME_FILES = 200_000
MAX_MEMBER_BYTES = 128 * 1024 * 1024
READ_CHUNK = 1024 * 1024

NAME_MISMATCH = "PINNED_RECORD_NAME_OR_VERSION_DOES_NOT_MATCH_THE_ARTIFACT"
DIGEST_ABSENT = "PINNED_DIGEST_NOT_IN_THE_WHEEL_DIRECTORY"
ARTIFACT_UNREADABLE = "ARTIFACT_UNREADABLE"
RECORD_SHAPE = "PINNED_RECORD_SHAPE"
SELF_UNIDENTIFIABLE = "ARTIFACT_OWNS_NO_SINGLE_TOP_LEVEL_DIST_INFO"
NON_REGULAR = "NON_REGULAR_RUNTIME_ENTRY"
ENTRY_UNREADABLE = "RUNTIME_ENTRY_UNREADABLE"
TOO_LARGE = "RUNTIME_FILE_TOO_LARGE_TO_COMPARE"
TRUNCATED = "RUNTIME_SCAN_TRUNCATED"
NOT_SELECTED = "RUNTIME_FILE_NOT_IN_SELECTED_WHEELS"
SELECTED_MISSING = "RUNTIME_SELECTED_FILE_MISSING"

# Every cause that can make `RUNTIME_FILE_PROVENANCE` fail, in the fixed order one code is reported.
# `ok: false` with `code: null` is not a state this program may emit: a check that reports a failure
# without naming it cannot be carried into a record, so the cause is lost and the reader is sent looking
# at the wrong thing. Every count below is reported in the detail regardless of which code is chosen.
PROVENANCE_CODES = ((NON_REGULAR, "nonRegularEntries"), (ENTRY_UNREADABLE, "entryUnreadable"),
                    (TOO_LARGE, "membersTooLargeToCompare"), (TRUNCATED, "truncated"),
                    (NOT_SELECTED, "filesNotFromSelectedWheels"), (SELECTED_MISSING, "missingSelectedFiles"))

# The checks that decide whether the **executed subset** is verified. Every one must pass; `ok` is
# computed from a counter in each case, so a check can never report `ok: true` beside a failure code.
EXECUTED_CHECKS = ("PINNED_DIGESTS_PRESENT", "SELECTED_ARTIFACTS_NAME_AND_SCREEN_VERIFIED",
                   "RUNTIME_FILE_PROVENANCE", "RUNTIME_DISTRIBUTION_SET", "RUNTIME_STARTUP_HOOKS",
                   "DECLARED_EXECUTED_SUBSET")
# The one check that is about the **pin** rather than about the executed subset. It is reported
# separately so a superseded full-stack claim stays visible as a non-ok check while the subset this run
# actually executed can still be verified.
PIN_CHECKS = ("PINNED_RECORDS_ALL_RESOLVED",)


def norm(value):
    """PEP 503-style normalization: the only name comparison performed anywhere here."""
    return str(value).lower().replace("-", "_").replace(".", "_")


def emit(status, checks, selected, excluded, screen, runtime, pins, reason=None):
    payload = {
        "protocol": PROTOCOL,
        "version": VERSION,
        "status": status,
        "checks": checks,
        "selectedArtifacts": selected,
        "excludedArtifactRecords": excluded,
        "screen": screen,
        "runtime": runtime,
        "pins": pins,
    }
    if reason is not None:
        payload["reason"] = reason
    sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
    raise SystemExit(0)


def refuse(reason, pins=None):
    """A refusal is a fixed code and nothing else.

    ``checks`` is deliberately **empty** on this path: the helper did not perform the verification, so
    there is no check to report, and a one-element pseudo-check named for readability would be
    indistinguishable from a real check to a reader that keys on the check list. The fixed cause travels
    as the reply's ``reason``, which is what a reader needs to know *why* nothing was verified.
    """
    emit("MISMATCH", [], 0, [], {}, {}, pins or {}, reason)


def digest_of(path, size):
    hasher = hashlib.sha256()
    read = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(READ_CHUNK)
                if not chunk:
                    break
                read += len(chunk)
                if read > size or read > MAX_WHEEL_BYTES:
                    return None, read
                hasher.update(chunk)
    except OSError:
        return None, read
    return hasher.hexdigest(), read


def own_metadata(names, reader):
    """A wheel's own top-level dist-info METADATA, read without unpacking anything else.

    A wheel may *vendor* other distributions' ``dist-info`` directories - setuptools 84.0.0 ships
    ``setuptools/_vendor/zipp-3.23.0.dist-info/METADATA`` among ten others - so only a top-level
    ``<dist-info>/METADATA`` describes the artifact itself. Reading a vendored one here would make
    this check agree with itself instead of with the wheel.
    """
    top = []
    for name in names:
        if "/" not in name:
            continue
        head, _, tail = name.partition("/")
        if tail == "METADATA" and head.endswith(".dist-info"):
            top.append(name)
    if len(top) != 1:
        return None
    fields = {}
    try:
        for line in reader(top[0]).decode("utf-8", "replace").split("\n")[:40]:
            key, sep, value = line.partition(": ")
            if sep and key not in fields:
                fields[key] = value
    except (OSError, KeyError, zipfile.BadZipFile):
        return None
    return fields.get("Name"), fields.get("Version")


def member_digests(path):
    """SHA-256 of every file member, keyed by archive name. No member content is retained."""
    digests = {}
    oversized = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.file_size > MAX_MEMBER_BYTES:
                    oversized += 1
                    continue
                hasher = hashlib.sha256()
                with archive.open(info) as member:
                    while True:
                        chunk = member.read(READ_CHUNK)
                        if not chunk:
                            break
                        hasher.update(chunk)
                digests[info.filename] = hasher.digest()
    except (OSError, zipfile.BadZipFile, RuntimeError):
        return None, 0, oversized + 1
    return digests, oversized, oversized


def inspect_artifact(record, wheels_by_digest):
    """Return the wheel path for a record whose name and version match the artifact, or a refusal."""
    path = wheels_by_digest.get(record.get("sha256"))
    if path is None:
        return None, {"name": record.get("name"), "version": record.get("version"),
                      "reason": DIGEST_ABSENT}
    try:
        with zipfile.ZipFile(path) as archive:
            own = own_metadata(archive.namelist(), archive.read)
            distributions = sorted({name.split("/", 1)[0] for name in archive.namelist()
                                    if name.split("/", 1)[0].endswith(".dist-info")})
    except (OSError, zipfile.BadZipFile):
        return None, {"name": record.get("name"), "version": record.get("version"),
                      "reason": ARTIFACT_UNREADABLE}
    if own is None or own[0] is None or len(distributions) != 1:
        return None, {"name": record.get("name"), "version": record.get("version"),
                      "reason": SELF_UNIDENTIFIABLE, "artifactOwnName": own[0] if own else None,
                      "artifactOwnVersion": own[1] if own else None}
    if norm(own[0]) != norm(record.get("name")) or own[1] != record.get("version"):
        return None, {"name": record.get("name"), "version": record.get("version"),
                      "reason": NAME_MISMATCH, "artifactOwnName": own[0],
                      "artifactOwnVersion": own[1]}
    return path, None


def file_digest(path, limit):
    """SHA-256 **digest bytes** in bounded chunks.

    Bounded on purpose: a whole-file ``read()`` would make this verifier's own memory depend on the
    largest file the candidate runtime happens to contain.
    """
    hasher = hashlib.sha256()
    read = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(READ_CHUNK)
                if not chunk:
                    break
                read += len(chunk)
                if read > limit:
                    return None, read
                hasher.update(chunk)
    except OSError:
        return None, read
    return hasher.digest(), read


def scan_runtime(site_packages):
    """Inventory the runtime: digests of installed files, distribution set, hooks, bytecode.

    A directory entry that is **neither a regular file nor a directory is counted and refused**, not
    skipped. Python follows a symlink when it imports, so a symlink into a file outside the verified
    runtime would otherwise be an importable module that `RUNTIME_FILE_PROVENANCE` never sees and the
    stated "every file is a byte-identical member of one selected wheel" would be silently untrue.
    """
    installed = {}
    distributions = set()
    pth_files = bytecode_files = 0
    non_regular = 0
    entry_unreadable = False
    truncated = False
    stack = [site_packages]
    while stack and not truncated:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            entry_unreadable = True
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    # A symlink, socket, FIFO or device: Python would import through it.
                    non_regular += 1
                    continue
                if not stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode):
                    non_regular += 1
                    continue
            except OSError:
                entry_unreadable = True
                continue
            relative = os.path.relpath(entry.path, site_packages).replace(os.sep, "/")
            if relative.endswith(".pth"):
                pth_files += 1
            if "__pycache__" in relative.split("/") or relative.endswith(".pyc"):
                bytecode_files += 1
            head = relative.split("/", 1)[0]
            if head.endswith(".dist-info"):
                distributions.add(norm(head[: -len(".dist-info")]))
            digest, _ = file_digest(entry.path, MAX_MEMBER_BYTES)
            if digest is None:
                entry_unreadable = True
                continue
            installed[relative] = digest
            if len(installed) > MAX_RUNTIME_FILES:
                truncated = True
                break
    return {"files": installed, "distributions": distributions, "pthFiles": pth_files,
            "bytecodeFiles": bytecode_files, "nonRegularEntries": non_regular,
            "entryUnreadable": entry_unreadable, "truncated": truncated}


def main(argv):
    args = [item for item in argv[1:] if not item.startswith("--")]
    if len(args) != 4:
        refuse("ARITY")
    manifest_path, wheel_directory, screen_path, site_packages = args
    if not os.path.isdir(site_packages):
        refuse("RUNTIME_SITE_PACKAGES_NOT_A_DIRECTORY")
    try:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        with open(screen_path, "r", encoding="utf-8") as handle:
            screen = json.load(handle)
    except (OSError, ValueError):
        refuse("MANIFEST_OR_SCREEN_UNREADABLE")
    if not isinstance(manifest, dict) or not isinstance(screen, list):
        refuse("MANIFEST_OR_SCREEN_SHAPE")
    records = manifest.get("artifacts")
    if not isinstance(records, list) or not records or len(records) > MAX_WHEELS:
        refuse("MANIFEST_ARTIFACT_RECORDS")

    wheels_by_digest = {}
    try:
        for entry in os.scandir(wheel_directory):
            if not entry.name.endswith(".whl"):
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            size = entry.stat(follow_symlinks=False).st_size
            if size > MAX_WHEEL_BYTES:
                continue
            digest, read = digest_of(entry.path, size)
            if digest is not None and read == size:
                wheels_by_digest[digest] = entry.path
    except OSError:
        refuse("WHEEL_DIRECTORY_UNREADABLE")

    screen_by_name = {}
    totals = {"records": 0, "ok": 0, "advisories": 0, "yanked": 0}
    for row in screen:
        if not isinstance(row, dict) or not isinstance(row.get("package_name"), str):
            continue
        screen_by_name[norm(row["package_name"])] = row
        totals["records"] += 1
        totals["ok"] += 1 if row.get("outcome") == "OK" else 0
        advisories = row.get("advisories")
        totals["advisories"] += len(advisories) if isinstance(advisories, list) else 0
        totals["yanked"] += 1 if row.get("yanked") is True else 0

    selected = []
    excluded = []
    selected_with_record = 0
    digests_present = 0
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("sha256"), str) \
                or not isinstance(record.get("name"), str):
            excluded.append({"name": None, "version": None, "reason": RECORD_SHAPE})
            continue
        if record["sha256"] in wheels_by_digest:
            digests_present += 1
        path, problem = inspect_artifact(record, wheels_by_digest)
        if problem is not None:
            excluded.append(problem)
            continue
        row = screen_by_name.get(norm(record["name"]))
        if (isinstance(row, dict) and row.get("outcome") == "OK" and row.get("yanked") is not True
                and not row.get("advisories") and row.get("observed_sha256") == record["sha256"]):
            selected_with_record += 1
        selected.append(path)

    runtime = scan_runtime(site_packages)
    expected = {}
    expected_distributions = set()
    oversized = 0
    for path in selected:
        digests, too_large, _ = member_digests(path)
        if digests is None:
            refuse("SELECTED_ARTIFACT_UNREADABLE")
        oversized += too_large
        expected.update(digests)
        try:
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    head = name.split("/", 1)[0]
                    if head.endswith(".dist-info"):
                        expected_distributions.add(norm(head[: -len(".dist-info")]))
        except (OSError, zipfile.BadZipFile):
            refuse("SELECTED_ARTIFACT_UNREADABLE")

    installed = runtime["files"]
    foreign = sum(1 for name, digest in installed.items() if expected.get(name) != digest)
    summary = {"distributions": len(runtime["distributions"]), "files": len(installed),
               "filesByteVerified": len(installed) - foreign,
               "filesNotFromSelectedWheels": foreign,
               "missingSelectedFiles": len(set(expected) - set(installed)),
               "membersTooLargeToCompare": oversized,
               "pthFiles": runtime["pthFiles"], "bytecodeFiles": runtime["bytecodeFiles"],
               "nonRegularEntries": runtime["nonRegularEntries"],
               "unexpectedDistributions": len(runtime["distributions"] - expected_distributions),
               "missingDistributions": len(expected_distributions - runtime["distributions"]),
               "truncated": runtime["truncated"], "entryUnreadable": runtime["entryUnreadable"]}

    declared = manifest.get("executionEnvironment")
    declared_subset = declared.get("selectedArtifacts") if isinstance(declared, dict) else None
    provenance_ok = (summary["filesNotFromSelectedWheels"] == 0 and summary["missingSelectedFiles"] == 0
                     and summary["membersTooLargeToCompare"] == 0 and not summary["truncated"]
                     and not summary["entryUnreadable"] and summary["nonRegularEntries"] == 0)
    provenance_code = None
    for code, counter in PROVENANCE_CODES:
        if summary[counter]:
            provenance_code = code
            break
    coverage_ok = len(selected) > 0 and selected_with_record == len(selected)
    checks = [
        {"check": "PINNED_DIGESTS_PRESENT", "ok": digests_present == len(records),
         "code": None if digests_present == len(records) else "DIGEST_NOT_CACHED",
         "detail": {"pinnedRecords": len(records), "digestsPresent": digests_present}},
        # One check for both halves of "is this artifact what the record says it is": every SELECTED
        # artifact's own wheel metadata matches its record's name and version, and every one has a
        # `#46` screen record under that same name. `ok` is computed from both counters, so it can never
        # report a pass beside a failure code.
        {"check": "SELECTED_ARTIFACTS_NAME_AND_SCREEN_VERIFIED", "ok": coverage_ok,
         "code": None if coverage_ok else "SCREEN_RECORD_MISSING_OR_STALE",
         "detail": {"selected": len(selected), "selectedWithScreenRecord": selected_with_record,
                    "excludedRecords": len(excluded)}},
        {"check": "RUNTIME_FILE_PROVENANCE", "ok": provenance_ok, "code": provenance_code,
         "detail": {"files": summary["files"], "byteVerified": summary["filesByteVerified"],
                    "foreign": summary["filesNotFromSelectedWheels"],
                    "missing": summary["missingSelectedFiles"],
                    "nonRegular": summary["nonRegularEntries"]}},
        {"check": "RUNTIME_DISTRIBUTION_SET",
         "ok": summary["unexpectedDistributions"] == 0 and summary["missingDistributions"] == 0,
         "code": None if summary["unexpectedDistributions"] == 0 else "RUNTIME_DISTRIBUTION_NOT_SELECTED",
         "detail": {"installed": summary["distributions"], "selected": len(expected_distributions)}},
        {"check": "RUNTIME_STARTUP_HOOKS",
         "ok": summary["pthFiles"] == 0 and summary["bytecodeFiles"] == 0,
         "code": None if summary["pthFiles"] == 0 else "RUNTIME_HAS_PTH_STARTUP_HOOK",
         "detail": {"pthFiles": summary["pthFiles"], "bytecodeFiles": summary["bytecodeFiles"]}},
        {"check": "DECLARED_EXECUTED_SUBSET",
         "ok": declared_subset is None or declared_subset == len(selected),
         "code": None if declared_subset is None or declared_subset == len(selected)
         else "DECLARED_SUBSET_DISAGREES_WITH_VERIFIED_SELECTION",
         "detail": {"declared": declared_subset, "verified": len(selected)}},
        # The one check that is about the PIN rather than about the executed subset. It is reported
        # separately so a superseded full-stack claim stays visible as a non-ok check while the
        # selected subset this run actually executed can still be read as verified.
        {"check": "PINNED_RECORDS_ALL_RESOLVED", "ok": not excluded,
         "code": excluded[0].get("reason") if excluded else None,
         "detail": {"pinnedRecords": len(records), "excluded": len(excluded)}},
    ]
    # The status is DERIVED from the executed-subset checks, never asserted: a check that fails makes
    # the subset unverified whatever the reply says about itself, and the only thing that keeps a
    # verified subset from being called `VERIFIED` is that at least one artifact was selected and every
    # one of them is name- and screen-verified.
    emitted = {item["check"] for item in checks}
    if emitted != set(EXECUTED_CHECKS) | set(PIN_CHECKS):
        # A check set this program did not assemble cannot be judged, and a name it does not recognise
        # is a bug here rather than something a caller can rely on.
        refuse("INTERNAL_CHECK_SET_MISMATCH")
    executed = [item for item in checks if item["check"] in EXECUTED_CHECKS]
    ok = all(item["ok"] for item in executed)
    status = "MISMATCH" if not ok else ("VERIFIED_WITH_EXCLUSIONS" if excluded else "VERIFIED")
    emit(status, checks, len(selected), excluded,
         dict(totals, selectedWithScreenRecord=selected_with_record), summary,
         {"manifestArtifactRecords": len(records), "digestsPresentInWheelDirectory": digests_present,
          "declaredExecutedSubset": declared_subset})


if __name__ == "__main__":
    main(sys.argv)