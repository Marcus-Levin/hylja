#!/bin/bash
# Ephemeral, unprivileged, offline sandbox runner for the #46 research scripts.
#
#   usage: scripts/research/sandbox-run.sh --print <bind-dir> <python-script> [args...]
#          scripts/research/sandbox-run.sh          <bind-dir> <python-script> [args...]
#
#          HANDOFF_PYTHON=<path-inside-sandbox> selects the payload interpreter
#          (default /usr/bin/python3; the offline verification run points it at a
#          prescreened virtualenv holding the Sigstore reference implementation).
#
# Properties this enforces (see README.md): the user, PID, network, IPC, UTS and
# cgroup namespaces are unshared; the environment is cleared before anything is
# set; only the system runtime and the caller-supplied work directory are
# visible, both read-only; /tmp is a private tmpfs; resource bounds are applied
# before the payload starts; and a wall-clock limit is enforced outside.
#
# `--print` emits the exact argument vector instead of running it, so a reviewer
# (or selftest.py) can assert the isolation properties without executing
# anything. The script never runs a payload on the host. Do not weaken any flag
# to make a failing experiment pass; record the gap instead.
set -euo pipefail

PRINT_ONLY=0
if [ "${1:-}" = "--print" ]; then
  PRINT_ONLY=1
  shift
fi
if [ "$#" -lt 2 ]; then
  echo "usage: sandbox-run.sh [--print] <bind-dir> <python-script> [args...]" >&2
  exit 2
fi

BIND_DIR=$(cd "$1" && pwd)
SCRIPT=$2
shift 2

PAYLOAD_PYTHON=${HANDOFF_PYTHON:-/usr/bin/python3}
WALL_CLOCK_SECONDS=${HANDOFF_WALL_CLOCK_SECONDS:-300}
ADDRESS_SPACE_BYTES=${HANDOFF_ADDRESS_SPACE_BYTES:-2147483648}
CPU_SECONDS=${HANDOFF_CPU_SECONDS:-240}
# The payload interpreter is read from inside the sandbox image or the bound work
# directory only; a host path could escape the isolation entirely.
case "$PAYLOAD_PYTHON" in
  /work/*|/usr/bin/python3) ;;
  *) echo "HANDOFF_PYTHON must be /work/... or /usr/bin/python3" >&2; exit 2 ;;
esac

FILE_SIZE_BYTES=16777216
# RLIMIT_NPROC and RLIMIT_AS are **per real UID**, and RLIMIT_AS/RLIMIT_CPU are
# **per process**. They are not an aggregate bound: nothing here caps the sum
# across a process tree, and --unshare-cgroup only namespaces the hierarchy (it
# sets no memory.max/cpu.max/pids.max). The cap is therefore deliberately
# conservative for a one-process smoke, and the aggregate case is a stated
# runtime-execution gate in README.md rather than a claim made here.
PROCESSES=64
OPEN_FILES=1024

# bwrap 0.11 offers no --rlimit options, so this prelude applies the bounds
# inside the sandbox before the payload starts. Every limit here is per process
# (RLIMIT_NPROC is per real UID); see the note above. RLIMIT_FSIZE bounds regular
# files only -- pipes are bounded separately by bounded_run.py in the driver.
PRELUDE='
import os, resource, sys
for what, value in (
    (resource.RLIMIT_AS, int(os.environ["HANDOFF_AS"])),
    (resource.RLIMIT_CPU, int(os.environ["HANDOFF_CPU"])),
    (resource.RLIMIT_FSIZE, int(os.environ["HANDOFF_FSIZE"])),
    (resource.RLIMIT_NPROC, int(os.environ["HANDOFF_NPROC"])),
    (resource.RLIMIT_NOFILE, int(os.environ["HANDOFF_NOFILE"])),
    (resource.RLIMIT_CORE, 0),
):
    resource.setrlimit(what, (value, value))
script = os.environ["HANDOFF_SCRIPT"]
sys.argv = [script] + sys.argv[1:]
with open(script, encoding="utf-8") as handle:
    source = handle.read()
exec(compile(source, script, "exec"), {"__name__": "__main__", "__file__": script})
'

BWRAP=(
  bwrap
  --unshare-all
  --die-with-parent --new-session
  --clearenv
  --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind /lib64 /lib64
  --ro-bind "$BIND_DIR" /work
  --tmpfs /tmp --dev /dev --proc /proc
  --hostname prescreen --chdir /work
  --setenv PATH /usr/bin --setenv HOME /tmp --setenv LC_ALL C.UTF-8
  --setenv PYTHONDONTWRITEBYTECODE 1 --setenv PYTHONNOUSERSITE 1
  --setenv PYTHONHASHSEED 0
  --setenv HANDOFF_AS "$ADDRESS_SPACE_BYTES" --setenv HANDOFF_CPU "$CPU_SECONDS"
  --setenv HANDOFF_FSIZE "$FILE_SIZE_BYTES" --setenv HANDOFF_NPROC "$PROCESSES"
  --setenv HANDOFF_NOFILE "$OPEN_FILES"
  --setenv HANDOFF_SCRIPT "/work/$(basename "$SCRIPT")"
  "$PAYLOAD_PYTHON" -I -c "$PRELUDE"
)

if [ "$PRINT_ONLY" = "1" ]; then
  printf '%s\n' timeout --signal=KILL "$WALL_CLOCK_SECONDS" "${BWRAP[@]}"
  exit 0
fi

exec timeout --signal=KILL "$WALL_CLOCK_SECONDS" "${BWRAP[@]}"
