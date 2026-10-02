#!/usr/bin/env python3
"""Host-side prescreen of downloaded PyPI wheels, for the #46 research screen.

Four things happen for each artifact, in this order:

1. the local bytes are read once, in bounded chunks, to compute size and
   SHA-256 -- nothing is unpacked yet, and an entry that is not an ordinary
   regular file is refused before a single byte is read, because opening one
   can wait for a writer that never arrives;
2. the digest and size are compared against an **independently fetched**
   published record. A missing or mismatched pin is refused here, *before* any
   candidate archive is opened;
3. only then is the archive inspected, under fixed member-count, per-member
   size and metadata-expansion bounds, and its distribution identity is read
   from **exactly one** root ``<distribution>-<version>.dist-info/METADATA``
   member. A vendored copy of another distribution's metadata lives *below* the
   outer package directory and describes that other distribution, so it can
   neither stand in for nor replace the outer one; a wheel with two root
   metadata members has two candidate identities and is refused rather than
   resolved by member order;
4. that declared identity is bound to the identity the **published record**
   publishes for the same version before anything is asked of an advisory
   service. The record, not the archive, says which distribution a file is; an
   archive member name is only ever a cross-check on what the metadata
   declares, never the source of a reported identity, and a file name
   contributes no identity to any record at all.

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
import stat
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

# How local artifact bytes are first touched. O_NONBLOCK is the whole point:
# opening a FIFO read-only otherwise waits for a writer, so a download entry
# that is not a regular file can park this screen forever instead of raising,
# and nothing here bounds that wait. O_CLOEXEC keeps the descriptor out of any
# child process. Neither flag is a tunable bound.
LOCAL_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)

USER_AGENT = "hylja-46-prescreen-research/1.0"

# Strict grammars: a recorded value is either in one of these fixed domains or
# it is reported as unparseable. Nothing else is stored.
NAME_GRAMMAR = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
VERSION_GRAMMAR = re.compile(r"^[A-Za-z0-9.+!_-]{1,32}$")
LICENSE_GRAMMAR = re.compile(r"^[A-Za-z0-9 .(),;+*-]{1,128}$")
PYTHON_GRAMMAR = re.compile(r"^[A-Za-z0-9 .<>=!~,;]{1,64}$")

# A distribution's own metadata is one member at the *root* of the wheel, named
# ``{distribution}-{version}.dist-info/METADATA``. Vendored copies of another
# distribution's metadata sit below the outer package directory, so the
# directory prefix is part of the identity's spelling and not decoration.
DIST_INFO_METADATA_SUFFIX = ".dist-info/METADATA"
DIST_INFO_SUFFIX = ".dist-info"

# PEP 503's separator run, folded to one hyphen. Applied only to compare two
# names that were each grammar-checked first.
NAME_SEPARATORS = re.compile(r"[-_.]+")

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


def is_ordinary_regular_file(path):
    """True when `path` is a regular file that can be read without waiting.

    This is a cheap *type* question, not a byte check: it opens the entry
    without blocking, asks the opened descriptor -- not the pathname, which a
    symlink or a replacement would misreport -- whether it is a regular file,
    and closes the descriptor again on every path. It reads no byte, keeps no
    descriptor and has no loop to poll, so it cannot itself hang, consume the
    artifact or run the process out of descriptors.

    A symlink is judged by its target. An entry that cannot be opened at all
    (no permission, gone, or a path that is not openable such as a socket)
    raises OSError inside and is reported as "not an ordinary regular file",
    which is the same refusal the caller already gave a failed stat.

    What this does not do is bind the later read to this descriptor: the digest
    is still read by reopening the path, and the archive is still opened by
    path again, so a trusted download directory that replaced the entry in
    between is a pre-existing research limit, not a property claimed here.
    """
    try:
        descriptor = os.open(path, LOCAL_READ_FLAGS)
    except OSError:
        return False
    try:
        return stat.S_ISREG(os.fstat(descriptor).st_mode)
    except OSError:
        return False
    finally:
        os.close(descriptor)


def digest_and_size(path):
    """Bounded, streaming digest of local bytes. Returns (sha256, size) or (None, None).

    Raises OSError if the path cannot be opened or read after it was stat'ed
    and its entry was accepted as a regular file; the caller turns that into a
    fixed code so the pathname-bearing exception never escapes into a report
    or a console.
    """
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


def _field_values(head, key):
    lowered = key.lower() + ":"
    values = []
    for line in head.splitlines():
        if not line.strip():
            break
        if line.lower().startswith(lowered):
            values.append(line.split(":", 1)[1].strip())
    return values


def _field(head, key):
    values = _field_values(head, key)
    return (values[0] or None) if values else None


def _grammar(value, pattern):
    return value if value is not None and pattern.match(value) else None


def normalize_distribution_name(name):
    """The PEP 503 normalized form of a distribution name, stdlib only.

    Deliberate and minimal, because this screen has no dependency to delegate
    it to: every run of ``-``, ``_`` and ``.`` collapses to one ``-`` and the
    name is lowercased, which is exactly what makes the escaped root directory
    name, an artifact's declared ``Name:`` and the index's project key one
    name. Nothing else is applied -- no version parsing, no further case folding
    -- and it is only ever used to *compare* two grammar-checked names, never to
    rewrite one into the record.
    """
    return NAME_SEPARATORS.sub("-", name).lower()


def root_dist_info_stem(member_name):
    """One member's root ``.dist-info`` directory name, or None.

    Only the root spelling is a candidate, and only that spelling is the outer
    distribution's own: ``a/b-1.0.dist-info/METADATA`` is a vendored copy
    belonging to whatever ``a`` bundles, and a member without a single directory
    level is not a wheel's own metadata whatever it is called.
    """
    if member_name.count("/") != 1 or not member_name.endswith(DIST_INFO_METADATA_SUFFIX):
        return None
    directory = member_name[:-len("/METADATA")]
    return directory[:-len(DIST_INFO_SUFFIX)] if directory.endswith(DIST_INFO_SUFFIX) else None


def dist_info_stem_identity(stem):
    """``(escaped name, version)`` from a ``{name}-{version}`` stem, or None.

    The stem is the archive's own spelling of the outer identity, and it is
    checked for agreement with the metadata rather than believed: a stem with no
    version cannot name a published version at all, so it yields None and the
    caller refuses rather than filling the gap from anywhere else.
    """
    name, separator, version = stem.rpartition("-")
    if not separator:
        return None
    escaped_name = _grammar(name, NAME_GRAMMAR)
    parsed_version = _grammar(version, VERSION_GRAMMAR)
    if escaped_name is None or parsed_version is None:
        return None
    return escaped_name, parsed_version


def declared_identity(head):
    """The one declared ``Name``/``Version`` pair in a metadata header, or None.

    A repeated field is not resolved by taking the first or the last: two
    ``Name:`` lines are an ambiguous declaration rather than a value, and an
    absent, repeated or out-of-grammar field yields None so the caller refuses.
    It is never completed from the file name or from any archive member name.
    """
    names = _field_values(head, "name")
    versions = _field_values(head, "version")
    if len(names) != 1 or len(versions) != 1:
        return None
    name = _grammar(names[0], NAME_GRAMMAR)
    version = _grammar(versions[0], VERSION_GRAMMAR)
    if name is None or version is None:
        return None
    return name, version


def screen_local_artifact(path, expected_sha256, expected_size, expected_name, expected_version):
    """Screen one downloaded wheel against an independently fetched record.

    ``expected_sha256``/``expected_size``/``expected_name``/``expected_version``
    all come from the published record, never from the artifact. The archive is
    opened only after the digest and size agree, and the artifact is only
    reported ``OK`` when its own declared identity agrees with both its root
    ``.dist-info`` directory and the published identity -- so an ``OK`` names a
    distribution that two independent sources agree on, not one an archive
    member claimed. All four are required: without a published identity there is
    nothing to bind to, and a screen that can succeed without one would report
    whatever the artifact itself said.
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

    # A download entry that is not an ordinary regular file -- a FIFO with no
    # writer, a directory, a device, an entry this process may not open -- is
    # refused here, before any byte is read. Opening such an entry can block
    # indefinitely rather than raise: a FIFO opened read-only waits for a
    # writer that may never come, and no timeout in this helper bounds that
    # wait. The refusal is the existing fixed code and nothing more: no path,
    # exception or message, no digest or size, no archive opened and no
    # advisory query.
    if not is_ordinary_regular_file(path):
        return outcome_record("ARTIFACT_UNREADABLE")

    try:
        observed_sha256, observed_size = digest_and_size(path)
    except OSError:
        # The path stat'ed but its bytes could not be opened or read: a
        # directory entry, a file this process may not read, or a read error
        # part way through. That is the same refusal as a failed stat, and it
        # is a refusal and nothing more -- the partial digest and size are
        # dropped, no path, exception or message is recorded, and no archive is
        # opened or member parsed for bytes that were never fully read.
        return outcome_record("ARTIFACT_UNREADABLE")
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

        # The candidate identity carriers, by shape and never by position: a
        # vendored ``.dist-info`` below a package directory is skipped, and a
        # second root candidate is ambiguous rather than a preference.
        roots = []
        native = False
        for info in infos:
            stem = root_dist_info_stem(info.filename)
            if stem is not None:
                roots.append((info, stem))
            if info.filename.endswith((".so", ".pyd")):
                native = True
        if not roots:
            return outcome_record("METADATA_ABSENT")
        if len(roots) > 1:
            return outcome_record("DIST_INFO_METADATA_AMBIGUOUS")
        metadata_info, stem = roots[0]
        stem_identity = dist_info_stem_identity(stem)
        if stem_identity is None:
            return outcome_record("DISTRIBUTION_IDENTITY_INVALID")

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
    identity = declared_identity(head_text)
    if identity is None:
        return outcome_record("DISTRIBUTION_IDENTITY_INVALID")
    name, version = identity

    # The archive's own spelling of the outer identity, checked against the
    # declared one: agreement is required, and the stem is never substituted for
    # it, so a metadata record claiming some other distribution is refused here.
    if (normalize_distribution_name(stem_identity[0]) != normalize_distribution_name(name)
            or stem_identity[1] != version):
        return outcome_record("DISTRIBUTION_IDENTITY_MISMATCH")

    # The independent binding. Without it this artifact is not screened as a
    # distribution, so it must not be reported as one and must never reach an
    # advisory query: the caller sees an unverified outcome, not a fallback name.
    if (_grammar(expected_name, NAME_GRAMMAR) is None
            or _grammar(expected_version, VERSION_GRAMMAR) is None
            or normalize_distribution_name(name) != normalize_distribution_name(expected_name)
            or version != expected_version):
        return outcome_record("DISTRIBUTION_IDENTITY_UNVERIFIED")

    return outcome_record(
        "OK",
        observed_sha256=observed_sha256,
        observed_size=observed_size,
        zip_members=len(infos),
        zip_entries=len(archive.infolist()),
        has_native_code=bool(native),
        package_name=name,
        version=version,
        license_expression=_grammar(_field(head_text, "license-expression"), LICENSE_GRAMMAR),
        license_field=_grammar(_field(head_text, "license"), LICENSE_GRAMMAR),
        requires_python=_grammar(_field(head_text, "requires-python"), PYTHON_GRAMMAR),
    )


def fetch_published_record(pkg, version, filename):
    """Fetch the index's own record for one exact file.

    Returns ``{"file": entry, "name": ..., "version": ..., "sha256": ..., "size": ...}``
    -- the exact file's entry plus the distribution identity the **index**
    publishes for that version and the pin to compare against -- or None on any
    failure. None covers a document that does not carry a usable published
    identity, that names no entry for this exact file, or whose byte count is
    not a byte count: the screen *compares* against the identity, the digest
    and the size, so a record that cannot supply them in the shapes it compares
    is not a record this helper can screen with. A digest that is not a string
    is not a refusal of the record but of the artifact, and becomes the absent
    pin the screen already has a fixed code for; an absent identity is never
    filled in from the download's own file name.
    """
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
        identity = document.get("info") or {}
        published_name = _grammar(identity.get("name"), NAME_GRAMMAR)
        published_version = _grammar(identity.get("version"), VERSION_GRAMMAR)
        entry = None
        for candidate in document.get("urls", []):
            if isinstance(candidate, dict) and candidate.get("filename") == filename:
                entry = candidate
        digests = entry.get("digests") if isinstance(entry.get("digests"), dict) else {}
        digest = digests.get("sha256")
        if not isinstance(digest, str):
            digest = None
        size = entry.get("size")
        if size is not None and type(size) is not int:  # noqa: E721 -- bool is not a byte count
            return None
    except Exception:  # noqa: BLE001
        return None
    if entry is None or published_name is None or published_version is None:
        return None
    return {"file": entry, "name": published_name, "version": published_version,
            "sha256": digest, "size": size}


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
    """Return (package, version) parsed from a wheel file name, or (None, None).

    Only used to ask the index for a record. The spelling is the wheel's own
    (escaped, per the wheel format) and is normalized by the caller; neither
    half ever becomes a reported identity.
    """
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
        file_name, file_version = split_filename(filename)
        if file_name is None:
            records.append(outcome_record("FILENAME_UNPARSEABLE"))
            continue
        # The file name says which index record to ask for -- normalized once,
        # deliberately -- and nothing more. It is not a recorded identity and is
        # never a fallback for one: an artifact whose own identity cannot be
        # read or verified reports no identity at all.
        requested_name = normalize_distribution_name(file_name)
        published = fetch_published_record(requested_name, file_version, filename)
        if published is None:
            records.append(outcome_record("PUBLISHED_RECORD_UNAVAILABLE"))
            continue
        record = screen_local_artifact(path, published["sha256"], published["size"],
                                       published["name"], published["version"])
        record["upload_time"] = _grammar(published["file"].get("upload_time_iso_8601"),
                                         re.compile(r"^[0-9TZ:.\-]{10,40}$"))
        record["yanked"] = bool(published["file"].get("yanked"))
        # The one request this helper makes that asks about something, and it
        # asks about the **published** identity, which the screen has already
        # bound the artifact to. A refused artifact is not put to it at all.
        record["advisories"] = query_osv(normalize_distribution_name(published["name"]),
                                         published["version"]) \
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
