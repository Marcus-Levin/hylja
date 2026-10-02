#!/usr/bin/env python3
"""Host-side prescreen of downloaded PyPI wheels, for the #46 research screen.

Three things happen for each artifact, in this order:

1. the local bytes are read once, in bounded chunks, to compute size and
   SHA-256 -- nothing is unpacked yet;
2. the digest and size are compared against an **independently fetched**
   published record. A missing or mismatched pin is refused here, *before* any
   candidate archive is opened;
3. only then is the archive inspected, under fixed member-count, per-member
   size and metadata-expansion bounds.

Every failure is a fixed code. No file name, archive member name, request URL or
response body is echoed, because those are artifact-controlled text.

This is a **supply-chain hygiene screen**: bounded reads, published-digest
agreement and license/advisory observation. It is not, and must not be reported
as, cryptographic provenance verification -- that is a separate, signed check.

    usage: prescreen_pypi_artifacts.py <download-dir> <output-json>
"""

import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import zipfile

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_HTTP_BYTES = 20 * 1024 * 1024
HTTP_TIMEOUT = 45
MAX_MEMBERS = 2000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_COMPRESSION_RATIO = 200
METADATA_FIELD_LIMIT = 64
READ_CHUNK = 1024 * 1024

USER_AGENT = "hylja-46-prescreen-research/1.0"

# Strict grammars: a recorded value is either in one of these fixed domains or
# it is reported as unparseable. Nothing else is stored.
NAME_GRAMMAR = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
VERSION_GRAMMAR = re.compile(r"^[A-Za-z0-9.+!_-]{1,32}$")
LICENSE_GRAMMAR = re.compile(r"^[A-Za-z0-9 .(),;+*-]{1,128}$")
PYTHON_GRAMMAR = re.compile(r"^[A-Za-z0-9 .<>=!~,;]{1,64}$")

UNPARSEABLE = "UNPARSEABLE"


def outcome_record(outcome, **fields):
    record = {
        "outcome": outcome,
        "package_name": None,
        "version": None,
        "license_expression": None,
        "license_field": None,
        "requires_python": None,
        "has_native_code": None,
        "zip_members": None,
        "zip_entries": None,
    }
    record.update(fields)
    return record


def digest_and_size(path):
    """Bounded, streaming digest of local bytes. Returns (sha256, size) or (None, None)."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(READ_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_ARTIFACT_BYTES:
                return None, None
            digest.update(chunk)
    return digest.hexdigest(), size


def _field(head, key):
    lowered = key.lower() + ":"
    for line in head.splitlines():
        if not line.strip():
            break
        if line.lower().startswith(lowered):
            value = line.split(":", 1)[1].strip()
            return value or None
    return None


def _grammar(value, pattern):
    return value if value is not None and pattern.match(value) else None


def screen_local_artifact(path, expected_sha256, expected_size):
    """Screen one downloaded wheel against an independently fetched pin.

    ``expected_sha256``/``expected_size`` come from the index record, never from
    the artifact. The archive is opened only after both agree.
    """
    try:
        if os.path.getsize(path) > MAX_ARTIFACT_BYTES:
            return outcome_record("ARTIFACT_TOO_LARGE")
    except OSError:
        return outcome_record("ARTIFACT_UNREADABLE")

    if expected_sha256 is None:
        return outcome_record("EXPECTED_DIGEST_ABSENT")
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        return outcome_record("EXPECTED_DIGEST_MALFORMED")

    observed_sha256, observed_size = digest_and_size(path)
    if observed_sha256 is None:
        return outcome_record("ARTIFACT_TOO_LARGE")
    if observed_sha256 != expected_sha256:
        return outcome_record("ARTIFACT_DIGEST_MISMATCH",
                              observed_sha256=observed_sha256,
                              expected_sha256=expected_sha256)
    if expected_size is not None and observed_size != int(expected_size):
        return outcome_record("ARTIFACT_SIZE_MISMATCH",
                              observed_size=observed_size, expected_size=int(expected_size))

    try:
        archive = zipfile.ZipFile(path)
    except Exception:  # noqa: BLE001
        return outcome_record("ARCHIVE_UNREADABLE")
    with archive:
        try:
            infos = [info for info in archive.infolist() if not info.is_dir()]
        except Exception:  # noqa: BLE001
            return outcome_record("ARCHIVE_UNREADABLE")
        if len(infos) > MAX_MEMBERS:
            return outcome_record("MEMBER_COUNT_OUT_OF_BOUNDS")
        if any(info.file_size > MAX_MEMBER_BYTES for info in infos):
            return outcome_record("MEMBER_TOO_LARGE")

        metadata_info = None
        native = False
        for info in infos:
            if info.filename.endswith(".dist-info/METADATA"):
                metadata_info = info
            if info.filename.endswith((".so", ".pyd")):
                native = True
        if metadata_info is None:
            return outcome_record("METADATA_ABSENT")
        if metadata_info.file_size > MAX_METADATA_BYTES:
            return outcome_record("METADATA_TOO_LARGE")
        if metadata_info.compress_size > 0 and \
                metadata_info.file_size > metadata_info.compress_size * MAX_COMPRESSION_RATIO:
            return outcome_record("METADATA_COMPRESSION_RATIO_EXCEEDED")
        try:
            with archive.open(metadata_info) as member:
                raw = member.read(MAX_METADATA_BYTES + 1)
        except Exception:  # noqa: BLE001
            return outcome_record("METADATA_UNREADABLE")
        if len(raw) > MAX_METADATA_BYTES:
            return outcome_record("METADATA_TOO_LARGE")

    head = raw.decode("utf-8", "replace").splitlines()[:METADATA_FIELD_LIMIT]
    head_text = "\n".join(head)
    return outcome_record(
        "OK",
        observed_sha256=observed_sha256,
        observed_size=observed_size,
        zip_members=len(infos),
        zip_entries=len(archive.infolist()),
        has_native_code=bool(native),
        package_name=_grammar(_field(head_text, "name"), NAME_GRAMMAR),
        version=_grammar(_field(head_text, "version"), VERSION_GRAMMAR),
        license_expression=_grammar(_field(head_text, "license-expression"), LICENSE_GRAMMAR),
        license_field=_grammar(_field(head_text, "license"), LICENSE_GRAMMAR),
        requires_python=_grammar(_field(head_text, "requires-python"), PYTHON_GRAMMAR),
    )


def fetch_published_record(pkg, version, filename):
    """Fetch the index's own record for one exact file. Returns None on failure."""
    url = "https://pypi.org/pypi/%s/%s/json" % (urllib.parse.quote(pkg), urllib.parse.quote(version))
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            body = response.read(MAX_HTTP_BYTES + 1)
    except Exception:  # noqa: BLE001
        return None
    if len(body) > MAX_HTTP_BYTES:
        return None
    try:
        document = json.loads(body)
        for entry in document.get("urls", []):
            if entry.get("filename") == filename:
                return entry
    except Exception:  # noqa: BLE001
        return None
    return None


def query_osv(pkg, version):
    """Advisory query. Returns a fixed code or a list of advisory identifiers."""
    body = json.dumps({"package": {"name": pkg, "ecosystem": "PyPI"},
                       "version": version}).encode()
    try:
        request = urllib.request.Request(
            "https://api.osv.dev/v1/query", data=body, method="POST",
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            raw = response.read(MAX_HTTP_BYTES + 1)
    except Exception:  # noqa: BLE001
        return "OSV_QUERY_FAILED"
    if len(raw) > MAX_HTTP_BYTES:
        return "OSV_QUERY_FAILED"
    try:
        document = json.loads(raw) if raw.strip() else {}
    except Exception:  # noqa: BLE001
        return "OSV_QUERY_FAILED"
    ids = []
    for entry in document.get("vulns", []):
        identifier = entry.get("id")
        if isinstance(identifier, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", identifier):
            ids.append(identifier)
    return sorted(set(ids))


def split_filename(filename):
    """Return (package, version) parsed from a wheel file name, or (None, None)."""
    match = re.match(r"^([A-Za-z0-9._-]+?)-([^-]+)-[^-]+-[^-]+-[^-]+\.whl$", filename)
    if not match:
        return None, None
    return match.group(1), match.group(2)


def main(download_dir, output_path):
    records = []
    for filename in sorted(os.listdir(download_dir)):
        if not filename.endswith(".whl"):
            continue
        path = os.path.join(download_dir, filename)
        package, version = split_filename(filename)
        if package is None:
            records.append(outcome_record("FILENAME_UNPARSEABLE"))
            continue
        published = fetch_published_record(package.replace("_", "-"), version, filename)
        if published is None:
            records.append(outcome_record("PUBLISHED_RECORD_UNAVAILABLE",
                                          package_name=_grammar(package, NAME_GRAMMAR),
                                          version=_grammar(version, VERSION_GRAMMAR)))
            continue
        record = screen_local_artifact(path,
                                      published.get("digests", {}).get("sha256"),
                                      published.get("size"))
        record["package_name"] = record["package_name"] or _grammar(package, NAME_GRAMMAR)
        record["version"] = record["version"] or _grammar(version, VERSION_GRAMMAR)
        record["upload_time"] = _grammar(published.get("upload_time_iso_8601"),
                                         re.compile(r"^[0-9TZ:.\-]{10,40}$"))
        record["yanked"] = bool(published.get("yanked"))
        record["advisories"] = query_osv(record["package_name"], record["version"]) \
            if record["outcome"] == "OK" else "SKIPPED_UNVERIFIED_ARTIFACT"
        records.append(record)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(records, indent=1, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.stdout.write(json.dumps({"outcome": "USAGE"}) + "\n")
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
    sys.exit(0)
