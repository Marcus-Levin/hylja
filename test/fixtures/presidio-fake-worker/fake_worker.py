#!/usr/bin/env python3
"""Generated fake Presidio worker: conformance, adversarial and mutation scaffolding only.

Standard library only. It imports no third-party package, loads no model, opens no socket and reads
no environment variable. It exists so the #113 adapter's binding, span, privacy and resource bounds
can be exercised without installing, importing or executing any real candidate stack.

It is NOT a Presidio implementation. Its "detection" is a single configurable regular expression run
over the analysed text, reported in Python's own code-point offsets, so the adapter's
code-point -> UTF-16 conversion is exercised for real rather than against canned numbers.

Behaviour is chosen by a control file passed as the first argument. The control file is test data
belonging to the caller; nothing here grants it any authority over the adapter.

  usage: fake_worker.py <control.json>
  stdin : exactly one request line (JSON)
  stdout: exactly one reply line (JSON) in the modes that reply at all
  stderr: never parsed by the adapter; the crash modes write a planted value there on purpose
"""

import json
import os
import re
import sys
import time

PROTOCOL = "hylja.presidio.worker"
VERSION = 1
MAX_RESULTS = 256
# The transport must hand a worker this environment and nothing else: no inherited proxy, no
# PYTHONPATH, no user site, no token. A worker that sees anything else fails closed, so this
# assertion runs inside the worker rather than trusting the parent to have checked it.
#
# NODE_V8_COVERAGE is the one tolerated extra: Node's own coverage instrumentation rewrites
# child_process.spawn to propagate it, so `node --test --experimental-test-coverage` adds it even
# though the transport declares a fixed environment. It is a local path, carries no secret, and the
# trial's authoritative boundary is the sandbox's --clearenv, not this list. Anything else is a
# failure, which is what makes the check worth keeping.
EXPECTED_ENV = {
    "PATH", "LANG", "LC_ALL", "PYTHONHASHSEED", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE",
    "PYTHONUNBUFFERED", "TMPDIR", "HOME", "NODE_V8_COVERAGE",
}


def read_request():
    line = sys.stdin.buffer.readline()
    if not line:
        raise SystemExit(3)
    request = json.loads(line.decode("utf-8"))
    if not isinstance(request, dict) or request.get("protocol") != PROTOCOL:
        raise SystemExit(4)
    if request.get("version") != VERSION or request.get("offsetUnit") != "CODE_POINT":
        raise SystemExit(5)
    if not isinstance(request.get("text"), str):
        raise SystemExit(6)
    return request


def base_reply(request, control=None):
    control = control or {}
    return {
        "version": VERSION,
        "protocol": PROTOCOL,
        "requestId": request["requestId"],
        "inputRef": request["inputRef"],
        "tenantRef": request["tenantRef"],
        "projectRef": request["projectRef"],
        "representation": request["representation"],
        "textDigest": request["textDigest"],
        "offsetUnit": "CODE_POINT",
        "status": "OK",
        "results": [],
        "filtering": {
            "scoreThreshold": 0.0,
            "deduplicate": True,
            "allowListCount": 0,
            "allowListMatch": "NONE",
            "context": "UNAVAILABLE_NO_NLP",
            "decisionProcess": "NOT_REQUESTED",
        },
        # Modelled on the real worker: the reported identity comes from pinned metadata, not from a
        # string the process invents about itself, so the adapter's equality check has something real
        # to compare against.
        "runtime": {"version": control.get("runtimeVersion", "fake0"),
                    "language": control.get("language", "en"), "nerAvailable": False},
        "unsupported": [],
    }


def scan(request, control):
    """A single bounded regex scan reported in Python code-point offsets."""
    reply = base_reply(request, control)
    pattern = control.get("pattern", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    entity = control.get("entityType", "EMAIL_ADDRESS")
    score = float(control.get("score", 0.85))
    text = request["text"]
    try:
        matcher = re.compile(pattern)
    except re.error:
        raise SystemExit(7)
    found = list(matcher.finditer(text))[: max(0, int(control.get("maxResults", MAX_RESULTS)))]
    for found in found:
        # `match.start()`/`match.end()` are Python str indices, i.e. code points, end-exclusive.
        item = {"entityType": entity, "start": found.start(), "end": found.end(), "score": score}
        if control.get("seam"):
            item["seam"] = control["seam"]
        reply["results"].append(item)
    if control.get("status") is not None:
        reply["status"] = control["status"]
    if control.get("nerAvailable") is not None:
        reply["runtime"]["nerAvailable"] = bool(control["nerAvailable"])
    if control.get("filtering") is not None:
        reply["filtering"].update(control["filtering"])
    if control.get("unsupported") is not None:
        reply["unsupported"] = control["unsupported"]
    if control.get("override") is not None:
        reply.update(control["override"])
    if control.get("requireCleanEnv"):
        if set(os.environ) - EXPECTED_ENV:
            reply["status"] = "FAILURE"
    return reply


def main():
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        control = json.load(handle)
    mode = control.get("mode", "scan")
    request = read_request()

    if mode == "hang":
        time.sleep(float(control.get("seconds", 30)))
    elif mode == "hang_then_mark":
        # Sleep past the caller's deadline, then write the marker. A caller whose kill reaches the child
        # never observes the marker; a caller whose kill does not reach it always does, so the same mode
        # is both the regression and the positive control.
        time.sleep(float(control.get("seconds", 30)))
        with open(control["marker"], "w", encoding="utf-8") as handle:
            handle.write("reached\n")
        sys.stdout.write(json.dumps(scan(request, control)) + "\n")
        sys.stdout.flush()
    elif mode == "slow_reply":
        # Answers only after the sleep, so the *startup* deadline is what bounds this worker.
        time.sleep(float(control.get("seconds", 2)))
        sys.stdout.write(json.dumps(scan(request, control)) + "\n")
        sys.stdout.flush()
    elif mode == "reply_then_stall":
        # Writes its whole reply first and then stays alive, so the execution deadline - which starts on
        # the first stdout byte - is the one that has to fire.
        sys.stdout.write(json.dumps(scan(request, control)) + "\n")
        sys.stdout.flush()
        time.sleep(float(control.get("seconds", 30)))
    elif mode == "crash":
        sys.stderr.write(control.get("stderrText", "synthetic worker crash\n"))
        raise SystemExit(int(control.get("exitCode", 7)))
    elif mode == "raise":
        # The traceback carries the planted value and this file's path to stderr on purpose.
        raise RuntimeError(control.get("planted", "synthetic-planted-raise.invalid"))
    elif mode == "stdout_flood":
        sys.stdout.write("x" * int(control.get("bytes", 1 << 20)))
        sys.stdout.flush()
    elif mode == "stderr_flood":
        sys.stderr.write("y" * int(control.get("bytes", 1 << 20)))
        raise SystemExit(0)
    elif mode == "garbage":
        sys.stdout.write(control.get("payload", "{not json\n"))
        sys.stdout.flush()
        raise SystemExit(0)
    elif mode == "bad_utf8":
        # Bytes that are not valid UTF-8: the transport must refuse the decode, not resynchronise.
        sys.stdout.buffer.write(b"\xff\xfe\xfd\n")
        sys.stdout.buffer.flush()
        raise SystemExit(0)
    elif mode == "reply_then_crash":
        sys.stdout.write(json.dumps(scan(request, control)) + "\n")
        sys.stdout.flush()
        raise SystemExit(int(control.get("exitCode", 4)))
    elif mode == "no_newline":
        sys.stdout.write(json.dumps(scan(request, control)))
        sys.stdout.flush()
        raise SystemExit(0)
    elif mode == "two_lines":
        reply = json.dumps(scan(request, control))
        sys.stdout.write(reply + "\n" + reply + "\n")
        sys.stdout.flush()
        raise SystemExit(0)
    else:
        sys.stdout.write(json.dumps(scan(request, control)) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
