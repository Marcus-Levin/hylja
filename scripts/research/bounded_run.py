#!/usr/bin/env python3
"""Bounded, typed execution of an untrusted child process.

The research sandbox runs third-party candidate code in a child process. That
child's stdout/stderr are **untrusted bytes**: they must never be buffered
without limit, never reach a report, and never produce an unhandled exception
in the trusted driver.

This module therefore:

* **discards** child output entirely and records only byte counts, so no child
  byte is ever carried into a verdict (the smoke's evidence is the child's result
  *file*, not its streams). Each read materialises at most one transient 64 KiB
  chunk in a local before it is counted and dropped: nothing accumulates across
  reads, and because the ceiling is tested *after* a chunk is counted, a reported
  total may overshoot ``output_cap`` by at most one chunk. ``retained_bytes``
  means "carried into the verdict", not "never held in memory at all";
* enforces a hard per-step output ceiling and kills the child's whole process
  group when it is exceeded, yielding ``OUTPUT_LIMIT_EXCEEDED`` instead of a
  silently truncated "pass";
* enforces a wall-clock deadline, yielding ``STEP_TIMEOUT``;
* maps spawn failure, memory exhaustion and every other error to fixed codes,
  so a hung or hostile child can never raise through the driver or destroy an
  already-collected report.

Note on limits: the enclosing sandbox applies ``RLIMIT_FSIZE`` and friends, which
bound regular files and per-process address space but **not** pipes. This module
is what bounds the pipes.
"""

import os
import selectors
import signal
import subprocess
import time

OUTCOMES = frozenset({
    "COMPLETED",
    "NONZERO_EXIT",
    "OUTPUT_LIMIT_EXCEEDED",
    "STEP_TIMEOUT",
    "SPAWN_FAILED",
    "STEP_MEMORY_EXHAUSTED",
    "STEP_ERROR",
})

DEFAULT_TIMEOUT = 120
DEFAULT_OUTPUT_CAP = 64 * 1024
MIN_TIMEOUT = 1
MAX_TIMEOUT = 600
READ_CHUNK = 65536


def _kill_group(proc):
    for sender in (signal.SIGKILL,):
        try:
            os.killpg(os.getpgid(proc.pid), sender)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass


def run_bounded(args, timeout=DEFAULT_TIMEOUT, output_cap=DEFAULT_OUTPUT_CAP, env=None):
    """Run ``args`` with bounded, discarded output and return a fixed-shape verdict.

    The returned mapping contains only fixed outcome codes, booleans and integer
    counts. It never raises, and it never contains any child byte.
    """
    outcome = "COMPLETED"
    counts = {"stdout_bytes": 0, "stderr_bytes": 0}
    exit_code = -1
    deadline = time.monotonic() + max(MIN_TIMEOUT, min(int(timeout), MAX_TIMEOUT))
    cap = max(0, int(output_cap))

    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
    except MemoryError:
        return _verdict("STEP_MEMORY_EXHAUSTED", -1, 0, 0, False)
    except Exception:  # noqa: BLE001
        return _verdict("SPAWN_FAILED", -1, 0, 0, False)

    selector = selectors.DefaultSelector()
    try:
        selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
        open_streams = 2
        while open_streams:
            if time.monotonic() >= deadline:
                outcome = "STEP_TIMEOUT"
                _kill_group(proc)
                break
            for key, _mask in selector.select(timeout=0.5):
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), READ_CHUNK)
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(stream)
                    open_streams -= 1
                    continue
                # Counted and dropped: no accumulation across reads (see above).
                counts["%s_bytes" % key.data] += len(chunk)
                if cap and counts["stdout_bytes"] + counts["stderr_bytes"] > cap:
                    outcome = "OUTPUT_LIMIT_EXCEEDED"
                    _kill_group(proc)
                    break
            if outcome in ("OUTPUT_LIMIT_EXCEEDED", "STEP_TIMEOUT"):
                break
        try:
            exit_code = proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            _kill_group(proc)
            try:
                exit_code = proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                exit_code = -1
        if outcome == "COMPLETED" and exit_code != 0:
            outcome = "NONZERO_EXIT"
    except MemoryError:
        _kill_group(proc)
        outcome = "STEP_MEMORY_EXHAUSTED"
    except Exception:  # noqa: BLE001
        _kill_group(proc)
        outcome = "STEP_ERROR"
    finally:
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            selector.close()
        except Exception:  # noqa: BLE001
            pass

    limit_hit = outcome == "OUTPUT_LIMIT_EXCEEDED"
    return _verdict(outcome, exit_code, counts["stdout_bytes"], counts["stderr_bytes"],
                    limit_hit)


def _verdict(outcome, exit_code, stdout_bytes, stderr_bytes, limit_hit):
    return {
        "outcome": outcome,
        "exit_code": int(exit_code),
        "stdout_bytes": int(stdout_bytes),
        "stderr_bytes": int(stderr_bytes),
        "retained_bytes": 0,
        "output_limit_exceeded": bool(limit_hit),
    }
