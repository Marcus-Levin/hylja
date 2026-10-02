#!/usr/bin/env python3
"""Offline wheel installer used only inside the research sandbox.

This exists because some Linux Python builds ship no ``ensurepip`` wheels, so
``python -m venv`` cannot bootstrap pip without network access. It performs no
network access, imports nothing from an archive, and never executes archive
content: members are written as plain files and re-read to confirm their digest.

Path handling is deliberately strict. Absolute names, parent traversal, drive
letters, backslashes, ZIP symlink entries, oversized members and oversized
archives are **refused**, not normalised, and the destination of every member is
re-checked to be inside the target directory. Failures print one fixed code and
exit non-zero; nothing partial is reported as success.

    usage: install-wheels.py <wheel-dir> <target-dir>
"""

import hashlib
import json
import os
import stat
import sys
import zipfile

MAX_WHEELS = 8
MAX_MEMBERS = 2000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_WHEEL_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


def refuse(reason: str) -> "None":
    print(json.dumps({"install_error": reason}))
    sys.exit(3)


def safe_parts(name: str):
    """Return the member's path components, or None when the name is refused."""
    if not name or name.startswith("/") or name.startswith("\\"):
        return None
    if "\\" in name or ":" in name or "\x00" in name:
        return None
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    return parts


def install(wheel_dir: str, target: str) -> dict:
    try:
        wheels = sorted(n for n in os.listdir(wheel_dir) if n.endswith(".whl"))
    except OSError:
        refuse("WHEEL_DIR_UNREADABLE")
    if not wheels or len(wheels) > MAX_WHEELS:
        refuse("WHEEL_COUNT_OUT_OF_BOUNDS")
    target = os.path.realpath(target)
    os.makedirs(target, exist_ok=True)

    installed = {}
    total = 0
    for wheel in wheels:
        path = os.path.join(wheel_dir, wheel)
        if os.path.islink(path) or not os.path.isfile(path):
            refuse("WHEEL_NOT_A_REGULAR_FILE")
        if os.path.getsize(path) > MAX_WHEEL_BYTES:
            refuse("WHEEL_TOO_LARGE")
        try:
            archive = zipfile.ZipFile(path)
        except zipfile.BadZipFile:
            refuse("WHEEL_NOT_A_ZIP")
        with archive:
            members = [info for info in archive.infolist() if not info.is_dir()]
            if len(members) > MAX_MEMBERS:
                refuse("MEMBER_COUNT_OUT_OF_BOUNDS")
            for info in members:
                if stat.S_ISLNK(info.external_attr >> 16):
                    refuse("SYMLINK_MEMBER_REFUSED")
                parts = safe_parts(info.filename)
                if parts is None:
                    refuse("UNSAFE_MEMBER_NAME")
                if info.file_size > MAX_MEMBER_BYTES:
                    refuse("MEMBER_TOO_LARGE")
                destination = os.path.join(target, *parts)
                parent = os.path.realpath(os.path.dirname(destination))
                if parent != target and not parent.startswith(target + os.sep):
                    refuse("PATH_ESCAPE")
                data = archive.read(info)
                total += len(data)
                if total > MAX_TOTAL_BYTES:
                    refuse("TOTAL_SIZE_OUT_OF_BOUNDS")
                digest = hashlib.sha256(data).hexdigest()
                if os.path.isdir(destination) or (
                        os.path.exists(parent) and not os.path.isdir(parent)):
                    refuse("MEMBER_CONFLICTS_WITH_DIRECTORY")
                os.makedirs(parent, exist_ok=True)
                with open(destination, "wb") as handle:
                    handle.write(data)
                with open(destination, "rb") as handle:
                    if hashlib.sha256(handle.read()).hexdigest() != digest:
                        refuse("WRITE_VERIFY_FAILED")
                installed["/".join(parts)] = digest
    return {"installed_members": len(installed), "wheels": wheels}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        refuse("USAGE")
    try:
        summary = install(sys.argv[1], sys.argv[2])
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        # A fixed code, never an archive-provided message or traceback.
        refuse("INSTALL_ERROR")
    print(json.dumps(summary, sort_keys=True))
