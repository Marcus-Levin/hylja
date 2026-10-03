#!/usr/bin/env python3
"""Deterministic self-tests for the research sandbox helpers.

These tests execute **no candidate code, download nothing, need no network and
need no sandbox**. They cover the parts of the helper that make the trial's
trust story true: the offline installer's refusal paths, the untrusted child
result schema, and the isolation properties the sandbox runner declares.

Run directly:  python3 scripts/research/selftest.py
It is not part of `npm test` or CI; it is run and reported separately.
"""

import builtins
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    path = os.path.join(HERE, name)
    spec = importlib.util.spec_from_file_location(name.replace("-", "_").replace(".py", ""), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


install_wheels = load("install-wheels.py")
schema = load("child_result_schema.py")

def try_load(name):
    """Load a helper module if it is importable without arguments."""
    try:
        return load(name)
    except Exception:  # noqa: BLE001
        return None


bounded_run = try_load("bounded_run.py")
prescreen = try_load("prescreen_pypi_artifacts.py")


def make_wheel(path, members, symlinks=()):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members:
            archive.writestr(name, data)
        for name in symlinks:
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "/etc/passwd")


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="prescreen-selftest-")
        os.chmod(self.tmp, 0o700)
        self.wheels = os.path.join(self.tmp, "wheels")
        self.target = os.path.join(self.tmp, "target")
        os.makedirs(self.wheels)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_install(self, args=None):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), self.assertRaises(SystemExit) as caught:
            install_wheels.install(*(args or (self.wheels, self.target)))
        self.assertEqual(caught.exception.code, 3)
        return json.loads(buffer.getvalue())["install_error"]

    def test_installs_verified_member(self):
        make_wheel(os.path.join(self.wheels, "a-1-py3-none-any.whl"),
                   [("pkg/__init__.py", b"synthetic\n")])
        summary = install_wheels.install(self.wheels, self.target)
        self.assertEqual(summary["installed_members"], 1)
        with open(os.path.join(self.target, "pkg", "__init__.py"), "rb") as handle:
            self.assertEqual(hashlib.sha256(handle.read()).hexdigest(),
                             hashlib.sha256(b"synthetic\n").hexdigest())

    def test_refuses_parent_traversal(self):
        make_wheel(os.path.join(self.wheels, "a-1-py3-none-any.whl"),
                   [("../escape.txt", b"x")])
        self.assertEqual(self.run_install(), "UNSAFE_MEMBER_NAME")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escape.txt")))

    def test_refuses_nested_parent_traversal(self):
        make_wheel(os.path.join(self.wheels, "a-1-py3-none-any.whl"),
                   [("pkg/../../escape.txt", b"x")])
        self.assertEqual(self.run_install(), "UNSAFE_MEMBER_NAME")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escape.txt")))

    def test_refuses_absolute_member(self):
        make_wheel(os.path.join(self.wheels, "a-1-py3-none-any.whl"), [("/abs.txt", b"x")])
        self.assertEqual(self.run_install(), "UNSAFE_MEMBER_NAME")

    def test_refuses_backslash_member(self):
        make_wheel(os.path.join(self.wheels, "a-1-py3-none-any.whl"), [("pkg\\evil.py", b"x")])
        self.assertEqual(self.run_install(), "UNSAFE_MEMBER_NAME")

    def test_refuses_symlink_member(self):
        make_wheel(os.path.join(self.wheels, "a-1-py3-none-any.whl"), [("pkg/link", b"")],
                   symlinks=["pkg/escape"])
        self.assertEqual(self.run_install(), "SYMLINK_MEMBER_REFUSED")

    def test_refuses_oversized_member_count(self):
        make_wheel(os.path.join(self.wheels, "a-1-py3-none-any.whl"),
                   [("pkg/%d.txt" % i, b"") for i in range(install_wheels.MAX_MEMBERS + 1)])
        self.assertEqual(self.run_install(), "MEMBER_COUNT_OUT_OF_BOUNDS")

    def test_refuses_oversized_member(self):
        original = install_wheels.MAX_MEMBER_BYTES
        install_wheels.MAX_MEMBER_BYTES = 1
        try:
            make_wheel(os.path.join(self.wheels, "a-1-py3-none-any.whl"),
                       [("pkg/big.txt", b"0123456789")])
            self.assertEqual(self.run_install(), "MEMBER_TOO_LARGE")
        finally:
            install_wheels.MAX_MEMBER_BYTES = original

    def test_refuses_non_zip_wheel(self):
        with open(os.path.join(self.wheels, "a-1-py3-none-any.whl"), "wb") as handle:
            handle.write(b"not a zip")
        self.assertEqual(self.run_install(), "WHEEL_NOT_A_ZIP")

    def test_refuses_empty_or_excess_wheel_count(self):
        self.assertEqual(self.run_install(), "WHEEL_COUNT_OUT_OF_BOUNDS")
        for i in range(install_wheels.MAX_WHEELS + 1):
            make_wheel(os.path.join(self.wheels, "p%d-1-py3-none-any.whl" % i), [("pkg/__init__.py", b"")])
        self.assertEqual(self.run_install(), "WHEEL_COUNT_OUT_OF_BOUNDS")

    def test_refuses_total_size_over_budget(self):
        original = install_wheels.MAX_TOTAL_BYTES
        install_wheels.MAX_TOTAL_BYTES = 4
        try:
            make_wheel(os.path.join(self.wheels, "a-1-py3-none-any.whl"),
                       [("pkg/one.txt", b"0123456789")])
            self.assertEqual(self.run_install(), "TOTAL_SIZE_OUT_OF_BOUNDS")
        finally:
            install_wheels.MAX_TOTAL_BYTES = original

    def test_refuses_member_that_conflicts_with_an_existing_directory(self):
        make_wheel(os.path.join(self.wheels, "a-1-py3-none-any.whl"),
                   [("pkg", b"file"), ("pkg/inner.py", b"x")])
        self.assertEqual(self.run_install(), "MEMBER_CONFLICTS_WITH_DIRECTORY")

    def test_refuses_symlinked_wheel(self):
        real = os.path.join(self.tmp, "real-1-py3-none-any.whl")
        make_wheel(real, [("pkg/__init__.py", b"")])
        os.symlink(real, os.path.join(self.wheels, "link-1-py3-none-any.whl"))
        self.assertEqual(self.run_install(), "WHEEL_NOT_A_REGULAR_FILE")


class ChildResultSchemaTest(unittest.TestCase):
    """Accepted values are booleans, range-checked integers or fixed codes only."""

    def test_accepts_known_keys_with_right_types(self):
        accepted, rejected = schema.sanitize({
            "smoke_code": "SMOKE_COMPLETED",
            "mask_output_length": 92,
            "mask_output_differs_from_input": True,
        })
        self.assertEqual(rejected, 0)
        self.assertEqual(accepted["mask_output_length"], 92)
        self.assertIs(accepted["mask_output_differs_from_input"], True)
        self.assertEqual(accepted["smoke_code"], "SMOKE_COMPLETED")

    def test_rejects_unknown_key_by_count_not_by_name(self):
        accepted, rejected = schema.sanitize({"smoke_code": "SMOKE_COMPLETED",
                                              "planted_value": "SYNTHETIC"})
        self.assertNotIn("planted_value", accepted)
        self.assertEqual(rejected, 1)

    def test_rejects_wrong_types_by_count(self):
        accepted, rejected = schema.sanitize({"mask_output_length": "92",
                                              "engine_constructed": "yes"})
        self.assertEqual(accepted, {})
        self.assertEqual(rejected, 2)

    def test_rejects_non_object(self):
        accepted, rejected = schema.sanitize(["not", "an", "object"])
        self.assertEqual(accepted, {})
        self.assertEqual(rejected, 1)

    def test_string_outside_the_fixed_code_set_is_replaced(self):
        accepted, _ = schema.sanitize({"smoke_code": "SYNTHETIC-PLANTED-9f3a"})
        self.assertEqual(accepted["smoke_code"], schema.UNRECOGNIZED_CODE)
        self.assertNotEqual(accepted["smoke_code"], "SYNTHETIC-PLANTED-9f3a")

    def test_no_list_valued_key_is_accepted(self):
        accepted, rejected = schema.sanitize({"declared_symbols_present": ["AnonymizerEngine"]})
        self.assertEqual(accepted, {})
        self.assertEqual(rejected, 1)

    def test_bool_never_satisfies_an_integer_key(self):
        # bool is a subclass of int in Python; exact type checks must still hold.
        accepted, rejected = schema.sanitize({"mask_output_length": True})
        self.assertEqual(accepted, {})
        self.assertEqual(rejected, 1)

    def test_int_never_satisfies_a_boolean_key(self):
        accepted, rejected = schema.sanitize({"engine_constructed": 1})
        self.assertEqual(accepted, {})
        self.assertEqual(rejected, 1)

    def test_accepted_values_are_only_bool_int_or_fixed_code(self):
        accepted, _ = schema.sanitize({"smoke_code": "SMOKE_COMPLETED",
                                       "mask_output_length": 92,
                                       "installed_tree_check_completed": True})
        for value in accepted.values():
            self.assertIn(type(value), (bool, int, str))
            if type(value) is str:
                self.assertIn(value, schema.ALLOWED_CODES)

    def test_read_result_reports_a_missing_file_without_raising(self):
        accepted, rejected, error = schema.read_result("/nonexistent/result.json")
        self.assertEqual(accepted, {})
        self.assertEqual(rejected, 0)
        self.assertTrue(error.startswith("RESULT_READ_ERROR"))

    def test_read_result_rejects_an_oversized_file(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as handle:
            handle.write(b'{"smoke_code": "' + b"A" * (schema.MAX_FILE_BYTES + 16) + b'"}')
            path = handle.name
        try:
            accepted, rejected, error = schema.read_result(path)
            self.assertEqual((accepted, rejected, error), ({}, 0, schema.SIZE_ERROR))
        finally:
            os.unlink(path)


class SandboxRunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="prescreen-sandbox-")
        os.chmod(cls.tmp, 0o700)
        cls.script = os.path.join(cls.tmp, "payload.py")
        with open(cls.script, "w", encoding="utf-8") as handle:
            handle.write("print('never runs in the print-only mode')\n")
        result = subprocess.run(["bash", os.path.join(HERE, "sandbox-run.sh"), "--print",
                                 cls.tmp, cls.script], stdout=subprocess.PIPE, check=True)
        cls.argv = result.stdout.decode().strip()
        # --print emits one argument per line; the resource-limit prelude is the
        # only multi-line argument and is always last.
        lines = cls.argv.splitlines()
        split = lines.index("-c")
        cls.argv_list = lines[:split] + ["-c", "\n".join(lines[split + 1:])]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_declares_full_namespace_unshare_and_clear_env(self):
        tokens = self.argv_list
        for flag in ("--unshare-all", "--clearenv", "--die-with-parent"):
            self.assertIn(flag, tokens)
        self.assertNotIn("--share-net", tokens)

    def test_binds_only_runtime_and_work_dir_read_only(self):
        tokens = self.argv_list
        binds = []
        for index, token in enumerate(tokens):
            if token == "--ro-bind":
                binds.append((tokens[index + 1], tokens[index + 2]))
        self.assertEqual(binds, [("/usr", "/usr"), ("/bin", "/bin"), ("/lib", "/lib"),
                                 ("/lib64", "/lib64"), (self.tmp, "/work")])
        for flag in ("--bind", "--dev-bind", "--ro-bind-try"):
            self.assertNotIn(flag, tokens)

    def test_private_tmp_and_bounded_resources(self):
        tokens = self.argv_list
        self.assertEqual(tokens[tokens.index("--tmpfs") + 1], "/tmp")
        self.assertIn("--proc", tokens)
        self.assertIn("RLIMIT_AS", self.argv)
        for key in ("HANDOFF_AS", "HANDOFF_CPU", "HANDOFF_FSIZE", "HANDOFF_NPROC",
                    "HANDOFF_NOFILE"):
            self.assertIn(key, tokens)
        self.assertIn("--signal=KILL", tokens)
        self.assertEqual(tokens[0], "timeout")

    def test_payload_interpreter_is_overridable_and_defaults_to_system_python(self):
        result = subprocess.run(["bash", os.path.join(HERE, "sandbox-run.sh"), "--print",
                                 self.tmp, self.script],
                                stdout=subprocess.PIPE, check=True,
                                env=dict(os.environ, HANDOFF_PYTHON="/work/venv/bin/python"))
        overridden = result.stdout.decode().split()
        self.assertEqual(overridden[overridden.index("-I") - 1], "/work/venv/bin/python")
        self.assertEqual(self.argv_list[self.argv_list.index("-I") - 1], "/usr/bin/python3")

    def test_print_only_does_not_execute_the_payload(self):
        self.assertNotIn("never runs in the print-only mode", self.argv_list)

    def test_refuses_a_payload_interpreter_outside_the_sandbox(self):
        result = subprocess.run(["bash", os.path.join(HERE, "sandbox-run.sh"),
                                 self.tmp, self.script, "--print"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=dict(os.environ, HANDOFF_PYTHON="/home/somebody/python3"))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"HANDOFF_PYTHON must be", result.stderr)

    def test_printed_command_is_the_executed_command_with_no_stray_arguments(self):
        # The prelude rewrites sys.argv to [script, *args], so the command must
        # end at the prelude: no positional payload argument of its own.
        self.assertEqual(self.argv_list[-2], "-c")
        self.assertTrue(self.argv_list[-1].rstrip().endswith(")"))
        self.assertNotIn(self.script, self.argv_list)

    def test_script_reaches_the_payload_only_through_the_bound_environment(self):
        self.assertEqual(self.argv_list[self.argv_list.index("HANDOFF_SCRIPT") + 1],
                         "/work/payload.py")



# --- Untrusted-output sentinels (root C1 / review B1) ----------------------

SENTINELS = [
    "SYNTHETIC-PLANTED-NOT-A-REAL-VALUE-9f3a",
    "Synthetic Exception Class Name 41",
    "Synthetic Entity Type 42",
]


class UntrustedOutputSentinelTest(unittest.TestCase):
    """No candidate-controlled text may survive anywhere in a reported result."""

    def hostile_result(self):
        return {
            "presidio_anonymizer_version": SENTINELS[0],
            "cryptography_version": SENTINELS[0],
            "python_version": SENTINELS[0],
            "mask_entity_type": SENTINELS[2],
            "installed_tree_check_error": SENTINELS[1],
            "smoke_code": SENTINELS[0],
            "declared_symbols_present": [SENTINELS[0], "AnonymizerEngine"],
            SENTINELS[0]: SENTINELS[1],
            "unrelated_key": SENTINELS[2],
            "mask_output_length": 92,
        }

    def test_no_sentinel_survives_sanitization(self):
        accepted, rejected = schema.sanitize(self.hostile_result())
        blob = json.dumps([accepted, rejected])
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, blob)

    def test_rejected_keys_are_a_count_not_candidate_names(self):
        accepted, rejected = schema.sanitize(self.hostile_result())
        self.assertIsInstance(rejected, int)
        self.assertGreaterEqual(rejected, 2)
        self.assertNotIsInstance(rejected, list)

    def test_unconstrained_codes_are_replaced_by_a_fixed_code(self):
        accepted, _ = schema.sanitize({"smoke_code": SENTINELS[0]})
        self.assertEqual(accepted.get("smoke_code"), schema.UNRECOGNIZED_CODE)

    def test_accepted_values_are_only_bool_int_or_fixed_code(self):
        accepted, _ = schema.sanitize(self.hostile_result())
        for value in accepted.values():
            if type(value) is str:
                self.assertIn(value, schema.ALLOWED_CODES)
            else:
                self.assertIn(type(value), (bool, int))

    def test_out_of_range_integers_are_not_recorded_verbatim(self):
        accepted, _ = schema.sanitize({"mask_output_length": 10 ** 12})
        self.assertEqual(accepted.get("mask_output_length"), schema.OUT_OF_RANGE)

    def test_report_assembly_keeps_no_candidate_text(self):
        driver = load("trial_driver.py")
        report = driver.assemble_report(
            steps=[{"step": "smoke_child", "outcome": "COMPLETED", "exit_code": 0,
                    "stdout_bytes": 0, "stderr_bytes": 0, "retained_bytes": 0,
                    "output_limit_exceeded": False}],
            child_result={"smoke_code": schema.UNRECOGNIZED_CODE},
            rejected_count=3,
            runtime_observations={"python_version": "3.14"},
        )
        blob = json.dumps(report)
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, blob)
        self.assertEqual(report["rejected_key_count"], 3)


# --- Bounded, typed child execution (root C2 / review B2) -----------------

CHILD = (
    "import json, os, sys, time\n"
    "mode = sys.argv[1]\n"
    "if mode == 'flood_stdout':\n"
    "    block = b'x' * 1024\n"
    "    for _ in range(8192):\n"
    "        sys.stdout.buffer.write(block)\n"
    "elif mode == 'flood_stderr':\n"
    "    block = b'y' * 1024\n"
    "    for _ in range(8192):\n"
    "        sys.stderr.buffer.write(block)\n"
    "elif mode == 'mixed_sentinel':\n"
    "    payload = os.environ['SENTINEL_PAYLOAD']\n"
    "    sys.stdout.write(payload)\n"
    "    sys.stderr.write(payload)\n"
    "    open('/tmp/bounded-run-sentinel-result.json', 'w').write(\n"
    "        json.dumps({'smoke_code': payload}))\n"
    "elif mode == 'hang':\n"
    "    time.sleep(30)\n"
    "elif mode == 'quiet':\n"
    "    pass\n"
)



class BoundedRunTest(unittest.TestCase):
    """Every step outcome is a fixed code and no child byte is carried into it."""

    def setUp(self):
        if bounded_run is None:
            self.fail("bounded_run.py must provide a bounded, typed child-execution path")
        self.tmp = tempfile.mkdtemp(prefix="prescreen-bounded-")
        os.chmod(self.tmp, 0o700)
        self.child = os.path.join(self.tmp, "child.py")
        with open(self.child, "w", encoding="utf-8") as handle:
            handle.write(CHILD)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        # The inert mixed-sentinel child writes one file outside the temp dir.
        try:
            os.unlink("/tmp/bounded-run-sentinel-result.json")
        except OSError:
            pass

    def run_child(self, mode, **kwargs):
        return bounded_run.run_bounded(
            [sys.executable, self.child, mode],
            timeout=kwargs.get("timeout", 30),
            output_cap=kwargs.get("output_cap", 64 * 1024),
            env=dict(os.environ, SENTINEL_PAYLOAD=SENTINELS[0]),
        )

    def test_quiet_child_completes(self):
        step = self.run_child("quiet")
        self.assertEqual(step["outcome"], "COMPLETED")
        self.assertEqual(step["retained_bytes"], 0)
        self.assertFalse(step["output_limit_exceeded"])

    def test_stdout_flood_is_stopped_with_a_fixed_code(self):
        step = self.run_child("flood_stdout")
        self.assertEqual(step["outcome"], "OUTPUT_LIMIT_EXCEEDED")
        self.assertTrue(step["output_limit_exceeded"])
        self.assertLessEqual(step["retained_bytes"], 64 * 1024)

    def test_stderr_flood_is_stopped_with_a_fixed_code(self):
        step = self.run_child("flood_stderr")
        self.assertEqual(step["outcome"], "OUTPUT_LIMIT_EXCEEDED")
        self.assertTrue(step["output_limit_exceeded"])

    def test_hang_yields_a_typed_timeout_not_an_exception(self):
        step = self.run_child("hang", timeout=1)
        self.assertEqual(step["outcome"], "STEP_TIMEOUT")

    def test_missing_executable_yields_a_typed_spawn_failure(self):
        step = bounded_run.run_bounded(
            [os.path.join(self.tmp, "does-not-exist")], timeout=5, output_cap=1024)
        self.assertEqual(step["outcome"], "SPAWN_FAILED")

    def test_step_verdict_carries_only_fixed_codes_and_counts(self):
        step = self.run_child("flood_stdout")
        for key, value in step.items():
            if key == "outcome":
                self.assertIn(value, bounded_run.OUTCOMES)
            else:
                self.assertIn(type(value), (bool, int))
                self.assertNotIsInstance(value, str)

    def test_child_bytes_are_discarded_not_reported(self):
        step = self.run_child("mixed_sentinel")
        blob = json.dumps(step)
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, blob)


# --- Host prescreen hardening (root C5) ----------------------------------

def synthetic_metadata(fields, body="A synthetic description."):
    """A wheel ``METADATA`` header block built from an ordered field list.

    The field order is the caller's, because one of the cases under test is
    that it must not matter; the description body sits after the blank line
    that ends the header block, so a body line that looks like a header cannot
    be read as one.
    """
    header = "\n".join("%s: %s" % (key, value) for key, value in fields)
    return header + "\n\n" + body + "\n"


PRESCREEN_GOOD_METADATA = synthetic_metadata([
    ("Metadata-Version", "2.1"),
    ("Name", "synthetic-sample"),
    ("Version", "1.0.0"),
    ("License-Expression", "MIT"),
    ("Requires-Python", ">=3.10"),
])

# The identity every offline case binds to, deliberately in the three
# spellings one distribution legitimately has: the root ``.dist-info`` directory
# spells the escaped form, ``METADATA`` spells the declared form and the
# published record spells the normalized one. They are one name, and a case
# that needs a *different* identity passes its own.
PUBLISHED_NAME = "synthetic-sample"
PUBLISHED_VERSION = "1.0.0"
ROOT_DIST_INFO = "synthetic_sample-1.0.0.dist-info"

# A vendored distribution's metadata lives below the outer distribution's own
# package directory, exactly as a real vendored wheel copies it.
def vendored_member(name=SENTINELS[0], version="9.9.9", license_expression="Apache-2.0"):
    return ("synthetic_sample/_vendor/%s-%s.dist-info/METADATA" % (name, version),
            synthetic_metadata([("Metadata-Version", "2.1"),
                                ("Name", name),
                                ("Version", version),
                                ("License-Expression", license_expression)]))


# --- Inert fixtures and one deadline for a download entry that is not a file --
#
# An unreadable artifact is refused by *returning*, so "it returns instead of
# waiting" is a claim a test has to be able to falsify; that is what the
# deadline below is for. Every fixture is created inside the suite's own
# temporary directory, holds at most a few obviously synthetic bytes, needs no
# privilege, touches no real user file, and is removed with that directory.

FIFO_PAYLOAD = b"SYNTHETIC-FIFO-PAYLOAD-NOT-A-WHEEL\n"

# Wall-clock ceiling for one call that must refuse rather than wait. Long
# enough that a loaded machine cannot trip it on four syscalls, short enough
# that a regression fails one case instead of stalling the suite. POSIX
# ``setitimer``, like the bwrap harness itself.
REFUSAL_DEADLINE_SECONDS = 5


class RefusalDeadlineExceeded(Exception):
    """Raised by ``wall_clock_deadline`` when a call outruns its deadline."""


@contextlib.contextmanager
def wall_clock_deadline(seconds):
    """Bound one in-process call to ``seconds`` of wall clock.

    ``SIGALRM`` interrupts a blocking ``open()`` in the calling process, so this
    needs no thread, no child process, no polling loop and leaves no orphan
    behind. The timer is cancelled and the previous handler restored in every
    case: returned, raised, or out of time.
    """

    def fire(_signum, _frame):
        raise RefusalDeadlineExceeded()

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def make_fifo(path):
    """An empty FIFO in the suite's temporary directory, with no writer attached.

    Opening one read-only waits for a writer to arrive, which is precisely the
    unbounded wait the screen has to refuse instead of entering.
    """
    os.mkfifo(path, 0o600)
    return path


def make_fed_fifo(path, payload=FIFO_PAYLOAD):
    """A FIFO whose inert payload is already buffered; returns the holder.

    The holder is opened ``O_RDWR``, which never blocks on a FIFO and keeps the
    bytes buffered, so a consumer really would take them away and the case can
    check afterwards that nothing did. The caller closes the holder.
    """
    os.mkfifo(path, 0o600)
    holder = os.open(path, os.O_RDWR)
    os.write(holder, payload)
    os.set_blocking(holder, False)
    return holder


def buffered_fifo_bytes(holder, size=4096):
    """Whatever is still buffered in a FIFO, without ever blocking on it."""
    try:
        return os.read(holder, size)
    except BlockingIOError:
        return b""


def make_socket_file(path):
    """Bind a local pathname socket at ``path``: a non-regular entry, no privilege.

    Closing the socket leaves the entry on disk, which is what this control
    wants: an entry that is not a regular file *and* cannot be opened at all.
    It is a local filesystem object, not a network endpoint.
    """
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(path)
    finally:
        server.close()
    return path


def open_descriptor_count():
    """How many descriptors this process currently holds, or ``None``.

    ``/proc/self/fd`` is Linux's only enumeration of a process's own
    descriptors, and this harness is Linux-only. Listing that directory is not
    reading any file's contents; a platform without it returns ``None`` so the
    caller skips the comparison instead of guessing at one.
    """
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return None


# --- Inert offline stand-ins for the prescreen helper's two I/O edges ------
#
# Each one replaces a single module reference on the loaded prescreen module
# and delegates to the stdlib, so nothing here opens a socket, executes
# candidate code, or reads outside a temporary directory. Each keeps a count
# only: no path, member name, request URL or response body is retained.


class ArchiveOpenCounter:
    """Stand-in for the helper's ``zipfile`` module reference.

    Counts every archive open the helper attempts and then delegates to the
    stdlib, so a refusal can be shown to happen *before* any ZIP work rather
    than only by the code it returns.
    """

    def __init__(self, real_module):
        self.opens = 0
        real_open = real_module.ZipFile

        def counting_open(*args, **kwargs):
            self.opens += 1
            return real_open(*args, **kwargs)

        self.ZipFile = counting_open


class RecordedResponse:
    """Minimal offline stand-in for an HTTP response.

    Serves one already-recorded byte body and nothing else: no status, headers,
    socket or timeout, so a stubbed request cannot reach a network.
    """

    def __init__(self, body):
        self._body = io.BytesIO(body)

    def read(self, size=-1):
        return self._body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        return False


class _StubRequestModule:
    """``urllib.request`` look-alike whose ``urlopen`` never delegates.

    Two things are recorded so a case can assert what the helper asked about
    rather than only how many requests it made: the URL of an index fetch and
    the distribution identity carried by an advisory query's own body. Both
    come from the synthetic fixture, neither reaches a report, and a body that
    is not JSON simply records nothing -- the malformed-response case relies on
    that.
    """

    def __init__(self, real_request_module, owner):
        self.Request = real_request_module.Request
        self._owner = owner

    def urlopen(self, request, *args, **kwargs):
        body = getattr(request, "data", None)
        if body is None:
            self._owner.fetches += 1
            self._owner.urls.append(getattr(request, "full_url", None))
        else:
            self._owner.queries += 1
            try:
                query = json.loads(body)
                package = query.get("package") or {}
            except Exception:  # noqa: BLE001 -- a body that is not JSON is the fixture
                query, package = {}, {}
            self._owner.advisory_queries.append((package.get("name"), query.get("version")))
        return self._owner.respond()


class _MISSING:
    """Sentinel type for "this module global did not exist"."""


@contextlib.contextmanager
def patched_module_global(module, name, value):
    """Replace one module global for the duration of a block, exactly restoring it.

    Python resolves a bare name to the module's globals before it reaches the
    builtins, so replacing ``open`` or a module reference here is enough to
    drive a branch the stdlib will not take for a synthetic fixture. A name the
    module never had is removed again rather than left shadowing a builtin, so
    "restored" is observable and not merely assumed.
    """
    original = getattr(module, name, _MISSING)
    setattr(module, name, value)
    try:
        yield value
    finally:
        if original is _MISSING:
            delattr(module, name)
        else:
            setattr(module, name, original)


def planted_read_error(path):
    """A synthetic unreadable-file error carrying a planted, obviously fake marker.

    The same error is used for a failing open and for a failing mid-read, so
    one planted marker covers both and one assertion proves neither reaches a
    record. The marker stands in for whatever a real host filesystem might put
    in an error string; no assertion below may let it, or the path, escape.
    """
    return PermissionError(errno.EACCES, "SYNTHETIC-PLANTED-READ-ERROR " + SENTINELS[0], path)


class LocalReadFailureOpen:
    """Stand-in for the helper's ``open`` that fails a local read on demand.

    Two failures are expressible, both strictly after a successful stat and
    both on temporary fixture paths:

    * ``unopenable`` -- ``open`` itself raises, which is what a file this
      process may not read does;
    * ``unreadable`` -- the handle yields one bounded chunk and the *next* read
      raises, so the artifact is partially consumed and the helper must still
      refuse it without recording a digest or a size.

    ``os.chmod`` is deliberately not used: a suite running as root reads a
    mode-000 file happily, so the refusal has to be injected at the one call the
    helper makes rather than depend on the suite's uid. Every other path --
    including the report file ``main()`` writes -- delegates to the stdlib. The
    stand-in retains counts only, never a path, a message or a byte.
    """

    def __init__(self, unopenable=(), unreadable=(), error=planted_read_error):
        self._real_open = builtins.open
        self._unopenable = {os.path.abspath(path) for path in unopenable}
        self._unreadable = {os.path.abspath(path) for path in unreadable}
        self._error = error
        self.refused_opens = 0
        self.reads = 0

    def __call__(self, path, *args, **kwargs):
        if os.path.abspath(path) in self._unopenable:
            self.refused_opens += 1
            raise self._error(path)
        handle = self._real_open(path, *args, **kwargs)
        if os.path.abspath(path) in self._unreadable:
            return _ReadFailingHandle(handle, path, self._error, self)
        return handle


class _ReadFailingHandle:
    """A handle that returns its first chunk and then raises a planted OSError.

    The first read succeeds on purpose: the artifact really has been partially
    consumed, so a refusal that still recorded a digest or a size would be a
    success-shaped partial outcome rather than a refusal.
    """

    def __init__(self, handle, path, error, owner):
        self._handle = handle
        self._path = path
        self._error = error
        self._owner = owner
        self._served = False

    def read(self, size):
        self._owner.reads += 1
        if self._served:
            raise self._error(self._path)
        self._served = True
        return self._handle.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self._handle.close()
        return False


class OfflineUrllibStub:
    """Stand-in for the helper's ``urllib`` module reference.

    ``parse`` and ``Request`` are the stdlib's own -- building a request object
    opens nothing -- while ``urlopen`` records one attempt and then either
    raises the configured error or replays the next recorded body. Index fetches
    and advisory queries are counted apart, because an index fetch is a request
    with no body and an advisory query is one with a body; that is what shows a
    refused artifact is never put to the advisory service.

    ``urls`` and ``advisory_queries`` retain, respectively, the fetched URL and
    the identity each advisory query asked about. Those are synthetic fixture
    strings held only in this test process so a case can assert *which*
    identity was used; they are never written to a report, and the stub does
    not keep a response body.
    """

    def __init__(self, real_urllib):
        self.parse = real_urllib.parse
        self.attempts = 0
        self.fetches = 0
        self.queries = 0
        self.urls = []
        self.advisory_queries = []
        self.bodies = []
        self.error = None
        self.request = _StubRequestModule(real_urllib.request, self)

    def respond(self):
        self.attempts += 1
        if self.error is not None:
            raise self.error
        return RecordedResponse(self.bodies.pop(0) if self.bodies else b"")


def corrupt_stored_member_crc(path, member):
    """Zero one stored member's recorded CRC-32, in place.

    The archive stays a structurally valid ZIP: only the recorded CRC no longer
    matches the member's bytes, which is the corruption the stdlib detects while
    reading that member. Exactly one member must be named, so a fixture that
    does not match fails loudly instead of silently doing nothing.
    """
    with open(path, "rb") as handle:
        raw = bytearray(handle.read())
    encoded = member.encode()
    patched = 0
    offset = 0
    while True:
        central = raw.find(b"PK\x01\x02", offset)
        if central < 0:
            break
        offset = central + 4
        name_length = struct.unpack("<H", raw[central + 28:central + 30])[0]
        if bytes(raw[central + 46:central + 46 + name_length]) != encoded:
            continue
        local = struct.unpack("<I", raw[central + 42:central + 46])[0]
        if bytes(raw[local:local + 4]) != b"PK\x03\x04":
            raise AssertionError("synthetic fixture: local file header not found")
        raw[central + 16:central + 20] = b"\x00\x00\x00\x00"
        raw[local + 14:local + 18] = b"\x00\x00\x00\x00"
        patched += 1
    if patched != 1:
        raise AssertionError("synthetic fixture: expected exactly one named member")
    with open(path, "wb") as handle:
        handle.write(bytes(raw))


class PrescreenHelperTest(unittest.TestCase):
    """The host-side screen refuses unverified bytes before touching a ZIP."""

    def setUp(self):
        if prescreen is None:
            self.fail("prescreen_pypi_artifacts.py must expose an importable offline screen")
        self.tmp = tempfile.mkdtemp(prefix="prescreen-host-")
        os.chmod(self.tmp, 0o700)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_wheel(self, name, members, compression=zipfile.ZIP_STORED):
        path = os.path.join(self.tmp, name)
        with zipfile.ZipFile(path, "w", compression=compression) as archive:
            for member, data in members:
                archive.writestr(member, data)
        return path

    def digest_of(self, path):
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()

    def screen_with_pin(self, path, expected_sha256=None, expected_size=None,
                        name=PUBLISHED_NAME, version=PUBLISHED_VERSION):
        """Screen one entry against the published pin and published identity.

        Both come from the independently fetched record and never from the
        fixture. The fixtures below declare ``PUBLISHED_NAME`` and
        ``PUBLISHED_VERSION`` in their root ``.dist-info`` directory *and* in
        their metadata, so an unexpected verdict is a disagreement rather than a
        fixture that never matched anything.
        """
        return prescreen.screen_local_artifact(path, expected_sha256, expected_size,
                                               name, version)

    def screen_promptly(self, path, expected_sha256, expected_size=None):
        """Screen one entry under a deadline, failing the case instead of waiting.

        The deadline covers this one call and is always disarmed again, so a
        screen that regressed into waiting costs ``REFUSAL_DEADLINE_SECONDS``
        of one case rather than the whole suite.
        """
        try:
            with wall_clock_deadline(REFUSAL_DEADLINE_SECONDS):
                return self.screen_with_pin(path, expected_sha256, expected_size)
        except RefusalDeadlineExceeded:
            self.fail("the screen waited on a non-regular entry instead of refusing it")

    def test_matching_pin_is_accepted_and_reads_its_own_metadata(self):
        path = self.write_wheel("ok-1.0-py3-none-any.whl", [
            ("ok/__init__.py", b"# synthetic\n"),
            (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "OK")
        self.assertEqual(record["package_name"], "synthetic-sample")
        self.assertEqual(record["license_expression"], "MIT")
        # File members and archive entries are both recorded, since the earlier
        # screen counted entries and the hardened helper counts files.
        self.assertEqual(record["zip_members"], 2)
        self.assertEqual(record["zip_entries"], 2)

    def test_missing_expected_digest_refuses_before_parsing(self):
        # A truncated archive: if the helper opened it, the failure would be a
        # ZIP error rather than the pin verdict.
        path = os.path.join(self.tmp, "broken-1.0-py3-none-any.whl")
        with open(path, "wb") as handle:
            handle.write(b"PK\x03\x04 truncated")
        record = self.screen_with_pin(path, None, None)
        self.assertEqual(record["outcome"], "EXPECTED_DIGEST_ABSENT")
        self.assertEqual(record["package_name"], None)

    def test_mismatched_expected_digest_refuses_before_parsing(self):
        path = os.path.join(self.tmp, "broken-1.0-py3-none-any.whl")
        with open(path, "wb") as handle:
            handle.write(b"PK\x03\x04 truncated")
        record = self.screen_with_pin(path, "0" * 64, None)
        self.assertEqual(record["outcome"], "ARTIFACT_DIGEST_MISMATCH")

    def test_mismatched_size_refuses_with_a_fixed_code(self):
        path = self.write_wheel("ok-1.0-py3-none-any.whl", [("ok/__init__.py", b"x")])
        record = self.screen_with_pin(path, self.digest_of(path), 1)
        self.assertEqual(record["outcome"], "ARTIFACT_SIZE_MISMATCH")

    def test_oversize_artifact_is_refused(self):
        path = os.path.join(self.tmp, "big-1.0-py3-none-any.whl")
        with open(path, "wb") as handle:
            handle.write(b"PK\x03\x04" + b"\x00" * 4096)
        original = prescreen.MAX_ARTIFACT_BYTES
        prescreen.MAX_ARTIFACT_BYTES = 128
        try:
            record = self.screen_with_pin(path, None, None)
            self.assertEqual(record["outcome"], "ARTIFACT_TOO_LARGE")
        finally:
            prescreen.MAX_ARTIFACT_BYTES = original

    def test_metadata_expansion_bomb_is_refused_with_a_fixed_code(self):
        path = self.write_wheel("bomb-1.0-py3-none-any.whl", [
            ("bomb/__init__.py", b"x"),
            ("bomb-1.0.dist-info/METADATA", b"A" * (prescreen.MAX_METADATA_BYTES + 1)),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "METADATA_TOO_LARGE")

    def test_member_count_bound_is_enforced(self):
        members = [("pkg/%d.py" % i, b"") for i in range(prescreen.MAX_MEMBERS + 1)]
        path = self.write_wheel("many-1.0-py3-none-any.whl", members)
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "MEMBER_COUNT_OUT_OF_BOUNDS")

    def test_malformed_archive_yields_a_fixed_code_not_an_exception(self):
        path = os.path.join(self.tmp, "bad-1.0-py3-none-any.whl")
        with open(path, "wb") as handle:
            handle.write(b"not a zip at all")
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "ARCHIVE_UNREADABLE")

    def test_missing_metadata_yields_a_fixed_code(self):
        path = self.write_wheel("nometa-1.0-py3-none-any.whl", [("nometa/__init__.py", b"x")])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "METADATA_ABSENT")

    # --- The outer distribution identity (vendored records) ----------------
    #
    # A wheel may carry another distribution's ``.dist-info`` **below its own
    # package directory**: that is what vendoring is, and a vendored record
    # describes the vendored distribution, not the wheel's owner. Selecting a
    # ``.dist-info/METADATA`` by "the last one in the member list" therefore
    # reports whatever archive entry happens to come last, which is why one
    # wheel of the recorded 51 was named after a package it only bundles.
    # Nothing below reads a *name* out of an archive entry and calls it truth:
    # the root ``.dist-info`` directory is only a cross-check on what the
    # metadata declares, and the declared identity is only believed once it
    # agrees with the independently fetched published record.

    def assert_refusal_echoes_nothing(self, record, *planted):
        """A refusal names its outcome and nothing else.

        The planted strings are the hostile identity and directory names the
        fixture carries, so this is what proves the refusal is a fixed code
        rather than a re-report of the artifact's own text.
        """
        self.assertIsInstance(record["outcome"], str)
        blob = json.dumps(record)
        for value in planted:
            self.assertNotIn(value, blob)
        self.assertNotIn(self.tmp, blob)
        for key, value in record.items():
            if key != "outcome":
                self.assertIsNone(value)

    def test_vendored_metadata_never_replaces_the_outer_identity(self):
        # The vendored record is written **last**: a selection that takes the
        # last `.dist-info/METADATA` in the member list reports the vendored
        # distribution's name, version and license here, which is the reported
        # defect exactly.
        path = self.write_wheel("vendored-1.0-py3-none-any.whl", [
            (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode()),
            ("synthetic_sample/__init__.py", b"# synthetic\n"),
            vendored_member(),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "OK")
        self.assertEqual(record["package_name"], PUBLISHED_NAME)
        self.assertEqual(record["version"], PUBLISHED_VERSION)
        self.assertEqual(record["license_expression"], "MIT")
        # Neither the vendored identity nor the vendored license may reach the
        # record in any spelling: the outer record is the only one read.
        blob = json.dumps(record)
        self.assertNotIn(SENTINELS[0], blob)
        self.assertNotIn("9.9.9", blob)
        self.assertNotIn("Apache-2.0", blob)
        self.assertNotIn("_vendor", blob)

    def test_the_outer_identity_is_selected_in_every_member_order(self):
        outer = (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode())
        vendored = vendored_member()
        filler = ("synthetic_sample/_vendor/__init__.py", b"# synthetic\n")
        seen = set()
        for label, members in (("outer first", [outer, filler, vendored]),
                               ("vendored first", [vendored, filler, outer]),
                               ("vendored last", [filler, vendored, outer]),
                               ("adjacent", [filler, outer, vendored])):
            with self.subTest(order=label):
                path = self.write_wheel("order-1.0-py3-none-any.whl", members)
                record = self.screen_with_pin(path, self.digest_of(path), None)
                seen.add((record["outcome"], record["package_name"], record["version"]))
                self.assertEqual(record["outcome"], "OK")
                self.assertEqual(record["package_name"], PUBLISHED_NAME)
                self.assertEqual(record["version"], PUBLISHED_VERSION)
                self.assertNotIn(SENTINELS[0], json.dumps(record))
        # One distinct result across four orders: the choice cannot be a
        # position in the member list.
        self.assertEqual(seen, {("OK", PUBLISHED_NAME, PUBLISHED_VERSION)})

    def test_two_root_metadata_members_are_refused_as_ambiguous(self):
        # Two root `.dist-info` directories name two distributions, and nothing
        # in the archive says which one this wheel *is*, so choosing either
        # would be a guess. This is a refusal, not a preference.
        path = self.write_wheel("two-roots-1.0-py3-none-any.whl", [
            (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode()),
            ("synthetic-other-2.0.dist-info/METADATA",
             synthetic_metadata([("Name", SENTINELS[0]), ("Version", "2.0")]).encode()),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "DIST_INFO_METADATA_AMBIGUOUS")
        self.assert_refusal_echoes_nothing(record, SENTINELS[0], "synthetic-other")

    def test_one_root_metadata_member_written_twice_is_refused_as_ambiguous(self):
        # A duplicated member name is an ordinary ZIP shape, not a trick: the
        # stdlib writes both entries and reports both, so "one member" is not
        # implied by one distinct name.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            path = self.write_wheel("duplicate-1.0-py3-none-any.whl", [
                (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode()),
                (ROOT_DIST_INFO + "/METADATA",
                 synthetic_metadata([("Name", SENTINELS[0]), ("Version", "1.0.0")]).encode()),
            ])
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(len(archive.infolist()), 2)
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "DIST_INFO_METADATA_AMBIGUOUS")
        self.assert_refusal_echoes_nothing(record, SENTINELS[0])

    def test_metadata_present_only_in_a_vendored_directory_is_refused_as_absent(self):
        # The same archive shape with no root metadata at all. A vendored
        # record cannot stand in for the outer distribution's own, so there is
        # no outer identity to report and the artifact has no metadata.
        path = self.write_wheel("nested-only-1.0-py3-none-any.whl", [
            ("synthetic_sample/__init__.py", b"# synthetic\n"),
            vendored_member(),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "METADATA_ABSENT")
        self.assert_refusal_echoes_nothing(record, SENTINELS[0], "9.9.9")

    def test_a_root_dist_info_name_that_disagrees_is_refused(self):
        path = self.write_wheel("root-name-1.0-py3-none-any.whl", [
            (ROOT_DIST_INFO + "/METADATA",
             synthetic_metadata([("Name", SENTINELS[0]), ("Version", PUBLISHED_VERSION)]).encode()),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "DISTRIBUTION_IDENTITY_MISMATCH")
        self.assert_refusal_echoes_nothing(record, SENTINELS[0])

    def test_a_root_dist_info_version_that_disagrees_is_refused(self):
        path = self.write_wheel("root-version-1.0-py3-none-any.whl", [
            (ROOT_DIST_INFO + "/METADATA",
             synthetic_metadata([("Name", PUBLISHED_NAME), ("Version", "9.9.9")]).encode()),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "DISTRIBUTION_IDENTITY_MISMATCH")
        self.assert_refusal_echoes_nothing(record, "9.9.9")

    def test_a_repeated_identity_field_is_refused_as_invalid(self):
        # Two `Name:` lines are an ambiguous declaration, not a value: neither
        # "first wins" nor "last wins" is a rule the archive or the index
        # states, and picking one would let a wheel claim whichever identity it
        # prefers.
        cases = (
            ("two different names", [("Name", PUBLISHED_NAME), ("Name", SENTINELS[0])]),
            ("two identical names", [("Name", PUBLISHED_NAME), ("Name", PUBLISHED_NAME)]),
            ("two versions", [("Name", PUBLISHED_NAME), ("Version", PUBLISHED_VERSION),
                              ("Version", "9.9.9")]),
        )
        for label, fields in cases:
            with self.subTest(fields=label):
                path = self.write_wheel("repeat-1.0-py3-none-any.whl", [
                    (ROOT_DIST_INFO + "/METADATA", synthetic_metadata(fields).encode()),
                ])
                record = self.screen_with_pin(path, self.digest_of(path), None)
                self.assertEqual(record["outcome"], "DISTRIBUTION_IDENTITY_INVALID")
                self.assert_refusal_echoes_nothing(record, SENTINELS[0], "9.9.9")

    def test_an_identity_field_outside_the_grammar_is_refused_as_invalid(self):
        # An identity that is not in a fixed grammar is not recorded, dropped
        # and replaced by the file name, or normalised into something else: it
        # is refused, because a screen that records a half-understood identity
        # and carries on has already lost the property being asked for.
        cases = (
            ("name with a space", [("Name", "synthetic sample"), ("Version", PUBLISHED_VERSION)]),
            ("name over the length bound", [("Name", "a" * 65), ("Version", PUBLISHED_VERSION)]),
            ("version with a space", [("Name", PUBLISHED_NAME), ("Version", "1.0.0 example")]),
            ("version over the length bound", [("Name", PUBLISHED_NAME), ("Version", "1" * 33)]),
        )
        for label, fields in cases:
            with self.subTest(fields=label):
                path = self.write_wheel("grammar-1.0-py3-none-any.whl", [
                    (ROOT_DIST_INFO + "/METADATA", synthetic_metadata(fields).encode()),
                ])
                record = self.screen_with_pin(path, self.digest_of(path), None)
                self.assertEqual(record["outcome"], "DISTRIBUTION_IDENTITY_INVALID")
                self.assert_refusal_echoes_nothing(record, "synthetic sample")

    def test_metadata_without_an_identity_field_is_refused_as_invalid(self):
        for label, fields in (("no name", [("Metadata-Version", "2.1"),
                                           ("Version", PUBLISHED_VERSION)]),
                              ("no version", [("Metadata-Version", "2.1"),
                                              ("Name", PUBLISHED_NAME)]),
                              ("neither", [("Metadata-Version", "2.1"),
                                           ("License-Expression", "MIT")])):
            with self.subTest(fields=label):
                path = self.write_wheel("no-identity-1.0-py3-none-any.whl", [
                    (ROOT_DIST_INFO + "/METADATA", synthetic_metadata(fields).encode()),
                ])
                record = self.screen_with_pin(path, self.digest_of(path), None)
                self.assertEqual(record["outcome"], "DISTRIBUTION_IDENTITY_INVALID")
                self.assert_refusal_echoes_nothing(record)

    def test_a_root_dist_info_stem_without_a_version_is_refused(self):
        # `{name}-{version}.dist-info` is the whole outer identity spelled by
        # the archive; a stem that carries no version cannot be bound to the
        # published one, so it is refused before the metadata is even read.
        path = self.write_wheel("no-version-1.0-py3-none-any.whl", [
            ("synthetic_sample.dist-info/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "DISTRIBUTION_IDENTITY_INVALID")
        self.assert_refusal_echoes_nothing(record, SENTINELS[0])

    def test_an_identity_the_published_record_does_not_agree_with_is_refused(self):
        # The published record, not the archive, says which distribution this
        # file is. An artifact whose own declared identity disagrees with it is
        # not screened as that distribution, and must not be put to an advisory
        # service under any identity.
        path = self.write_wheel("unverified-1.0-py3-none-any.whl", [
            (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        for label, name, version in (("other published name", "synthetic-other", PUBLISHED_VERSION),
                                     ("other published version", PUBLISHED_NAME, "9.9.9"),
                                     ("published name outside the grammar", "not a name",
                                      PUBLISHED_VERSION),
                                     ("published version outside the grammar", PUBLISHED_NAME,
                                      "not a version")):
            with self.subTest(published=label):
                record = prescreen.screen_local_artifact(path, self.digest_of(path), None,
                                                         name, version)
                self.assertEqual(record["outcome"], "DISTRIBUTION_IDENTITY_UNVERIFIED")
                self.assert_refusal_echoes_nothing(record, "synthetic-other", "9.9.9", name)
        # Control: the same wheel against the identity the published record
        # actually publishes, so the refusals above are the disagreement and
        # not the fixture.
        record = prescreen.screen_local_artifact(path, self.digest_of(path), None,
                                                 PUBLISHED_NAME, PUBLISHED_VERSION)
        self.assertEqual(record["outcome"], "OK")

    def test_one_distribution_spelled_three_ways_binds_as_one_identity(self):
        # Normalization is deliberate and minimal: runs of `-`, `_` and `.`
        # collapse to one `-` and the name is lowercased, which is what makes
        # the escaped root directory, the declared `Name:` and the published
        # project key one name. No dependency implements it, nothing else is
        # folded, and the artifact's own declared spelling is what is recorded.
        path = self.write_wheel("normalised-1.0-py3-none-any.whl", [
            (ROOT_DIST_INFO + "/METADATA",
             synthetic_metadata([("Name", "Synthetic.Sample"),
                                 ("Version", PUBLISHED_VERSION),
                                 ("License-Expression", "MIT")]).encode()),
        ])
        for label, name in (("published as declared", "Synthetic.Sample"),
                            ("published lowercased", PUBLISHED_NAME),
                            ("published hyphenated", "Synthetic-Sample")):
            with self.subTest(published=label):
                record = prescreen.screen_local_artifact(path, self.digest_of(path), None,
                                                         name, PUBLISHED_VERSION)
                self.assertEqual(record["outcome"], "OK")
                self.assertEqual(record["package_name"], "Synthetic.Sample")
                self.assertEqual(record["version"], PUBLISHED_VERSION)
        # A name that normalization keeps apart is still refused: collapsing
        # separators is not a licence to equate different names.
        record = prescreen.screen_local_artifact(path, self.digest_of(path), None,
                                                 "synthetic.sample.extra", PUBLISHED_VERSION)
        self.assertEqual(record["outcome"], "DISTRIBUTION_IDENTITY_UNVERIFIED")

    def test_metadata_field_order_and_description_do_not_change_the_record(self):
        # Field order is not a contract, and a description line that looks like
        # a header is not one: the header block ends at the first blank line.
        path = self.write_wheel("order-metadata-1.0-py3-none-any.whl", [
            (ROOT_DIST_INFO + "/METADATA", synthetic_metadata(
                [("License-Expression", "MIT"),
                 ("Version", PUBLISHED_VERSION),
                 ("Metadata-Version", "2.1"),
                 ("Requires-Python", ">=3.10"),
                 ("Name", PUBLISHED_NAME)],
                body="SYNTHETIC-PLANTED-BODY-9f3a\nName: %s\nVersion: 9.9.9\n" % SENTINELS[0]).encode()),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "OK")
        self.assertEqual(record["package_name"], PUBLISHED_NAME)
        self.assertEqual(record["version"], PUBLISHED_VERSION)
        self.assertEqual(record["license_expression"], "MIT")
        self.assertEqual(record["requires_python"], ">=3.10")
        blob = json.dumps(record)
        self.assertNotIn(SENTINELS[0], blob)
        self.assertNotIn("9f3a", blob)

    def test_a_wheel_without_any_dist_info_metadata_is_still_refused_as_absent(self):
        # Control on the selection: a member that merely ends in the metadata
        # suffix, without a root `.dist-info` directory of that name, is not a
        # candidate -- the suffix alone is not the identity's spelling.
        path = self.write_wheel("suffix-only-1.0-py3-none-any.whl", [
            ("synthetic_sample/METADATA", PRESCREEN_GOOD_METADATA.encode()),
            ("synthetic_sample-1.0.0.dist-info/RECORD", b"synthetic\n"),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "METADATA_ABSENT")
        self.assert_refusal_echoes_nothing(record, SENTINELS[0])

    def test_record_never_echoes_member_or_file_names(self):
        path = self.write_wheel("secretname-1.0-py3-none-any.whl", [
            ("pkg/__init__.py", b"x"),
            (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        record = self.screen_with_pin(path, self.digest_of(path), None)
        blob = json.dumps(record)
        self.assertNotIn("secretname-1.0-py3-none-any.whl", blob)
        self.assertNotIn("pkg/__init__.py", blob)

    def test_unreadable_artifact_yields_a_fixed_code_and_echoes_nothing(self):
        # A path that cannot be stat'ed at all: the refusal must name the
        # outcome and nothing else -- no path, no marker, no digest, no size.
        missing = os.path.join(self.tmp, "SYNTHETIC-PLANTED-ABSENT-9f3a.whl")
        record = self.screen_with_pin(missing, None, None)
        self.assertEqual(record["outcome"], "ARTIFACT_UNREADABLE")
        self.assertNotIn("9f3a", json.dumps(record))
        self.assertNotIn(self.tmp, json.dumps(record))
        for key, value in record.items():
            if key != "outcome":
                self.assertIsNone(value)

    def test_a_download_entry_that_stats_but_is_a_directory_is_refused_typed(self):
        # A path that stats cleanly and then cannot be read as a regular file
        # -- a directory named like a wheel inside a download directory. The
        # refusal names the outcome and nothing else: no path, no marker, no
        # digest, no size, and no archive is opened for bytes that were never
        # read. The entry is now refused by the non-regular-file check before
        # any byte is touched, so the outcome is the same fixed code.
        directory = os.path.join(self.tmp, "SYNTHETIC-PLANTED-DIRECTORY-9f3a")
        os.mkdir(directory)
        real_zipfile = prescreen.zipfile
        counter = ArchiveOpenCounter(real_zipfile)
        with patched_module_global(prescreen, "zipfile", counter):
            record = self.screen_with_pin(directory, "0" * 64, None)
        self.assertIs(prescreen.zipfile, real_zipfile)
        self.assertEqual(record["outcome"], "ARTIFACT_UNREADABLE")
        self.assertEqual(counter.opens, 0)
        blob = json.dumps(record)
        self.assertNotIn("9f3a", blob)
        self.assertNotIn(self.tmp, blob)
        for key, value in record.items():
            if key != "outcome":
                self.assertIsNone(value)

    def test_a_fifo_entry_with_no_writer_is_refused_without_waiting(self):
        # The unbounded wait this closes. A FIFO opened read-only blocks until
        # a writer appears, no timeout in the helper bounds that wait, and a
        # blocking open is not an exception, so `except OSError` never saw it:
        # before the non-regular-file check this call simply never returned.
        # The entry below has no writer at all, so the refusal has to be
        # prompt, typed, silent about the entry and spent on no archive.
        path = make_fifo(os.path.join(self.tmp, "SYNTHETIC-PLANTED-FIFO-9f3a.whl"))
        real_zipfile = prescreen.zipfile
        counter = ArchiveOpenCounter(real_zipfile)
        try:
            with patched_module_global(prescreen, "zipfile", counter):
                record = self.screen_promptly(path, "0" * 64, None)
        finally:
            self.assertIs(prescreen.zipfile, real_zipfile)
        self.assertEqual(record["outcome"], "ARTIFACT_UNREADABLE")
        self.assertEqual(counter.opens, 0)
        blob = json.dumps(record)
        self.assertNotIn("9f3a", blob)
        self.assertNotIn(self.tmp, blob)
        self.assertNotIn(SENTINELS[0], blob)
        for key, value in record.items():
            if key != "outcome":
                self.assertIsNone(value)

    def test_a_fifo_entry_is_refused_without_consuming_its_bytes(self):
        # A FIFO whose inert payload is already buffered, so a screen that
        # opened it and read would really take those bytes and reach a digest
        # verdict instead of a refusal. What is still in the pipe afterwards is
        # the measurement: the entry was refused without being consumed.
        path = os.path.join(self.tmp, "SYNTHETIC-PLANTED-FED-FIFO-9f3a.whl")
        holder = make_fed_fifo(path)
        try:
            real_zipfile = prescreen.zipfile
            counter = ArchiveOpenCounter(real_zipfile)
            try:
                with patched_module_global(prescreen, "zipfile", counter):
                    record = self.screen_promptly(path, "0" * 64, None)
            finally:
                buffered = buffered_fifo_bytes(holder)
        finally:
            os.close(holder)
        self.assertIs(prescreen.zipfile, real_zipfile)
        self.assertEqual(record["outcome"], "ARTIFACT_UNREADABLE")
        self.assertEqual(counter.opens, 0)
        self.assertEqual(buffered, FIFO_PAYLOAD)
        blob = json.dumps(record)
        self.assertNotIn("9f3a", blob)
        self.assertNotIn(self.tmp, blob)
        self.assertNotIn(SENTINELS[0], blob)
        for key, value in record.items():
            if key != "outcome":
                self.assertIsNone(value)

    def test_non_regular_entries_are_refused_and_leak_no_descriptor(self):
        # Controls for the same guard, one shape at a time, each repeated so a
        # single unclosed descriptor per refusal would show up: the check opens
        # an entry and closes it again on every path, so this process must hold
        # exactly as many descriptors afterwards as before.
        directory = os.path.join(self.tmp, "SYNTHETIC-PLANTED-DIR-9f3a.whl")
        os.mkdir(directory)
        socket_file = make_socket_file(os.path.join(self.tmp, "SYNTHETIC-PLANTED-SOCK-9f3a.whl"))
        # The platform's null device is the only character device reachable
        # without `mknod` and privilege, which this suite deliberately does not
        # take. It is opened read-only and closed, and no byte is ever read
        # from it; `mknod`-shaped control is out of reach here.
        character_device = "/dev/null"
        fifo = make_fifo(os.path.join(self.tmp, "SYNTHETIC-PLANTED-FIFO-9f3a-b.whl"))
        real_zipfile = prescreen.zipfile
        counter = ArchiveOpenCounter(real_zipfile)
        try:
            with patched_module_global(prescreen, "zipfile", counter):
                for label, entry in (("directory", directory),
                                     ("socket file", socket_file),
                                     ("character device", character_device),
                                     ("fifo", fifo)):
                    with self.subTest(entry=label):
                        before = open_descriptor_count()
                        for _ in range(8):
                            record = self.screen_promptly(entry, "0" * 64, None)
                            self.assertEqual(record["outcome"], "ARTIFACT_UNREADABLE")
                            self.assertEqual(counter.opens, 0)
                            self.assertNotIn(self.tmp, json.dumps(record))
                            for key, value in record.items():
                                if key != "outcome":
                                    self.assertIsNone(value)
                        after = open_descriptor_count()
                        if before is not None:
                            self.assertEqual(after, before)
        finally:
            self.assertIs(prescreen.zipfile, real_zipfile)

    def test_a_successful_stat_followed_by_an_unopenable_file_is_refused_typed(self):
        # Stat succeeds and open then fails, which is what a file this process
        # may not read does. The pin is deliberately wrong, so the refusal is
        # provably the read and not a digest verdict, and the real wheel bytes
        # are never parsed as an archive. The injected failure is at the digest
        # read, after the non-regular-file check has already accepted this
        # ordinary file, so the two edges stay separately covered.
        path = self.write_wheel("unopenable-1.0-py3-none-any.whl", [
            ("unopenable/__init__.py", b"# synthetic\n"),
            ("unopenable-1.0.dist-info/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        real_zipfile = prescreen.zipfile
        counter = ArchiveOpenCounter(real_zipfile)
        guard = LocalReadFailureOpen(unopenable=[path])
        with patched_module_global(prescreen, "zipfile", counter), \
                patched_module_global(prescreen, "open", guard):
            record = self.screen_with_pin(path, "0" * 64, None)
        self.assertIs(prescreen.zipfile, real_zipfile)
        self.assertFalse(hasattr(prescreen, "open"))
        self.assertEqual(guard.refused_opens, 1)
        self.assertEqual(record["outcome"], "ARTIFACT_UNREADABLE")
        self.assertEqual(counter.opens, 0)
        blob = json.dumps(record)
        self.assertNotIn(SENTINELS[0], blob)
        self.assertNotIn(path, blob)
        self.assertNotIn(self.tmp, blob)
        for key, value in record.items():
            if key != "outcome":
                self.assertIsNone(value)

    def test_a_read_error_after_partial_bytes_records_no_digest_or_size(self):
        # The pin here matches, so nothing but the read itself can refuse the
        # artifact. The fixture is deliberately larger than one READ_CHUNK and
        # the first chunk is really served, so this is the case where a
        # success-shaped partial outcome would be possible: no digest, no size
        # and no other field may survive, and no archive may be opened.
        path = self.write_wheel("partial-1.0-py3-none-any.whl", [
            ("partial/__init__.py", b"# synthetic\n"),
            ("partial/filler.bin", b"SYNTHETIC-FILLER-" * 100000),
            (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        self.assertGreater(os.path.getsize(path), prescreen.READ_CHUNK)
        real_zipfile = prescreen.zipfile
        counter = ArchiveOpenCounter(real_zipfile)
        guard = LocalReadFailureOpen(unreadable=[path])
        with patched_module_global(prescreen, "zipfile", counter), \
                patched_module_global(prescreen, "open", guard):
            record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertIs(prescreen.zipfile, real_zipfile)
        self.assertFalse(hasattr(prescreen, "open"))
        self.assertEqual(guard.reads, 2)
        self.assertEqual(record["outcome"], "ARTIFACT_UNREADABLE")
        self.assertEqual(counter.opens, 0)
        blob = json.dumps(record)
        self.assertNotIn(SENTINELS[0], blob)
        self.assertNotIn(path, blob)
        self.assertNotIn(self.tmp, blob)
        for key, value in record.items():
            if key != "outcome":
                self.assertIsNone(value)
        # The same wheel is screened normally once nothing fails its read, so
        # the refusals above are the injected failure and not the fixture.
        self.assertEqual(self.screen_with_pin(path, self.digest_of(path), None)["outcome"],
                         "OK")

    def test_malformed_expected_digest_is_refused_before_any_archive_open(self):
        # A real, bounded, well-formed wheel: if the pin-syntax check were
        # missing the helper would go on to open and parse this archive, so the
        # open counter below is what makes the ordering observable.
        path = self.write_wheel("pin-1.0-py3-none-any.whl", [
            ("pin/__init__.py", b"# synthetic\n"),
            (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        real_zipfile = prescreen.zipfile
        try:
            counter = ArchiveOpenCounter(real_zipfile)
            prescreen.zipfile = counter
            for label, pin in (("not hex", "not-a-digest"),
                               ("one digit short", "a" * 63),
                               ("uppercase hex", "A" * 64),
                               ("not a string", 4096)):
                with self.subTest(pin=label):
                    record = self.screen_with_pin(path, pin, None)
                    self.assertEqual(record["outcome"], "EXPECTED_DIGEST_MALFORMED")
            self.assertEqual(counter.opens, 0)

            # Control: the same counter does observe a genuine open, so the
            # zero above is a measurement and not a stub that never fires.
            control = ArchiveOpenCounter(real_zipfile)
            prescreen.zipfile = control
            record = self.screen_with_pin(path, self.digest_of(path), None)
            self.assertEqual(record["outcome"], "OK")
            self.assertEqual(control.opens, 1)
        finally:
            prescreen.zipfile = real_zipfile
        self.assertIs(prescreen.zipfile, real_zipfile)

    def test_maximum_individual_member_bound_is_enforced_and_restored(self):
        # Small fixture with a patched module threshold, the same technique as
        # the committed oversize-artifact case: the bound is read from the
        # module at call time, so no production threshold changes here.
        path = self.write_wheel("member-1.0-py3-none-any.whl", [
            ("member/__init__.py", b"# synthetic\n"),
            ("member/bulk.bin", b"SYNTHETIC-FILLER-" * 240),
            (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        original = prescreen.MAX_MEMBER_BYTES
        prescreen.MAX_MEMBER_BYTES = 512
        try:
            record = self.screen_with_pin(path, self.digest_of(path), None)
            self.assertEqual(record["outcome"], "MEMBER_TOO_LARGE")
            for key, value in record.items():
                if key not in ("outcome", "observed_sha256", "observed_size"):
                    self.assertIsNone(value)
        finally:
            prescreen.MAX_MEMBER_BYTES = original
        self.assertEqual(prescreen.MAX_MEMBER_BYTES, original)
        # The same wheel is accepted once the production bound is back.
        self.assertEqual(self.screen_with_pin(path, self.digest_of(path), None)["outcome"],
                         "OK")

    def test_metadata_compression_ratio_bound_refuses_deflated_metadata(self):
        # Real deflate, real ratio: one repeated byte well inside the metadata
        # size ceiling, so only the ratio bound can refuse this artifact.
        path = self.write_wheel("ratio-1.0-py3-none-any.whl", [
            ("ratio/__init__.py", b"# synthetic\n"),
            ("ratio-1.0.dist-info/METADATA", b"A" * (256 * 1024)),
        ], compression=zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo("ratio-1.0.dist-info/METADATA")
            self.assertLessEqual(info.file_size, prescreen.MAX_METADATA_BYTES)
            self.assertGreater(info.file_size, info.compress_size * prescreen.MAX_COMPRESSION_RATIO)
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "METADATA_COMPRESSION_RATIO_EXCEEDED")

        # Control: deflated metadata that stays inside the bound is accepted,
        # so the refusal above is the ratio and not "compressed at all".
        control = self.write_wheel("ratio-ok-1.0-py3-none-any.whl", [
            ("ratio_ok/__init__.py", b"# synthetic\n"),
            (ROOT_DIST_INFO + "/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ], compression=zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(control) as archive:
            info = archive.getinfo(ROOT_DIST_INFO + "/METADATA")
            self.assertLessEqual(info.file_size, info.compress_size * prescreen.MAX_COMPRESSION_RATIO)
        record = self.screen_with_pin(control, self.digest_of(control), None)
        self.assertEqual(record["outcome"], "OK")
        self.assertEqual(record["package_name"], "synthetic-sample")

    def test_corrupt_metadata_member_is_reported_as_unreadable(self):
        # A stored member whose recorded CRC no longer matches its bytes: the
        # archive is still structurally valid ZIP, so the only way the helper
        # can refuse this metadata is by failing to decode/read that member.
        path = self.write_wheel("crc-1.0-py3-none-any.whl", [
            ("crc/__init__.py", b"# synthetic\n"),
            ("crc-1.0.dist-info/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        corrupt_stored_member_crc(path, "crc-1.0.dist-info/METADATA")
        record = self.screen_with_pin(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "METADATA_UNREADABLE")
        blob = json.dumps(record)
        self.assertNotIn("crc-1.0.dist-info", blob)
        self.assertNotIn("crc-1.0-py3-none-any.whl", blob)
        for key, value in record.items():
            if key not in ("outcome", "observed_sha256", "observed_size"):
                self.assertIsNone(value)


class PrescreenMainOfflineTest(unittest.TestCase):
    """main()'s fixed codes, driven entirely by inert local stubs.

    The index fetch and the advisory query are the helper's only network paths.
    Both are replaced here by a stub that counts attempts and then raises or
    replays one already-recorded byte body: no socket is opened and every
    fixture is obviously synthetic. The stub retains only what a case has to
    assert -- the fetched URL and the identity each advisory query asked about
    -- and neither reaches a report. Nothing here says anything about how the
    live endpoints behave.
    """

    # One wheel, spelled the way a wheel's file name spells a distribution:
    # the escaped name, a hyphen, then the version.
    WHEEL_NAME = "synthetic_sample-1.0.0-py3-none-any.whl"

    def setUp(self):
        if prescreen is None:
            self.fail("prescreen_pypi_artifacts.py must expose an importable offline screen")
        self.tmp = tempfile.mkdtemp(prefix="prescreen-main-")
        os.chmod(self.tmp, 0o700)
        self.downloads = os.path.join(self.tmp, "downloads")
        self.output = os.path.join(self.tmp, "records.json")
        os.makedirs(self.downloads)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_wheel(self, name=None, with_metadata=True, metadata=PRESCREEN_GOOD_METADATA,
                    dist_info=ROOT_DIST_INFO, extra_members=()):
        """One obviously synthetic wheel in the download directory.

        Its root ``.dist-info`` directory, its ``METADATA`` and the published
        record the cases below replay all name the same distribution, in the
        three spellings one distribution legitimately has.
        """
        path = os.path.join(self.downloads, name or self.WHEEL_NAME)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("synthetic_sample/__init__.py", b"# synthetic\n")
            if with_metadata:
                archive.writestr(dist_info + "/METADATA", metadata.encode())
            for member, data in extra_members:
                archive.writestr(member, data)
        return path

    def digest_and_size(self, path):
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest(), os.path.getsize(path)

    def index_body(self, filename, sha256, size, name=PUBLISHED_NAME, version=PUBLISHED_VERSION,
                   publish_identity=True):
        """A recorded index document for one exact file; no live record.

        ``info`` is the distribution identity the **index** publishes for that
        version. It is what the artifact's own declared identity is bound to,
        so a case can withhold it, or publish a different one, without any
        network being involved.
        """
        document = {"urls": [{"filename": filename,
                              "digests": {"sha256": sha256},
                              "size": size}]}
        if publish_identity:
            document["info"] = {"name": name, "version": version}
        return json.dumps(document).encode()

    def run_main(self, stub):
        real_urllib = prescreen.urllib
        prescreen.urllib = stub
        try:
            prescreen.main(self.downloads, self.output)
        finally:
            prescreen.urllib = real_urllib
        records, _raw = self.read_output()
        return records

    @contextlib.contextmanager
    def private_case(self):
        """A download directory and report path of this sub-case's own.

        ``main()`` walks every wheel in the directory it is given, so a case
        that loops over several fixtures needs a directory per iteration to
        keep the records separate. The directory is created inside the suite's
        own temporary directory and goes away with it.
        """
        outer_downloads, outer_output = self.downloads, self.output
        case = tempfile.mkdtemp(prefix="prescreen-case-", dir=self.tmp)
        self.downloads = os.path.join(case, "downloads")
        self.output = os.path.join(case, "records.json")
        os.makedirs(self.downloads)
        try:
            yield
        finally:
            self.downloads, self.output = outer_downloads, outer_output

    def read_output(self):
        """The report file main() wrote, as records and as the exact bytes."""
        with open(self.output, "rb") as handle:
            raw = handle.read()
        return json.loads(raw.decode("utf-8")), raw

    def screened_batch(self, stub, unreadable=()):
        """Run main() offline with an archive-open counter and optional read failures.

        The counter and the ``open`` stand-in are removed again by the context
        manager, so the assertions below can also state that the module was
        restored exactly. Returns the parsed records, the raw report bytes and
        the counter.
        """
        counter = ArchiveOpenCounter(prescreen.zipfile)
        with patched_module_global(prescreen, "urllib", stub), \
                patched_module_global(prescreen, "zipfile", counter), \
                patched_module_global(prescreen, "open", LocalReadFailureOpen(unreadable=unreadable)):
            prescreen.main(self.downloads, self.output)
        records, raw = self.read_output()
        return records, raw, counter

    def test_unparseable_filename_is_refused_before_any_request(self):
        self.write_wheel("SYNTHETIC-PLANTED-BADNAME-9f3a.whl", with_metadata=False)
        stub = OfflineUrllibStub(prescreen.urllib)
        records = self.run_main(stub)
        self.assertEqual([record["outcome"] for record in records], ["FILENAME_UNPARSEABLE"])
        self.assertEqual(stub.attempts, 0)
        self.assertIsNone(records[0]["package_name"])
        self.assertNotIn("9f3a", json.dumps(records))

    def test_unavailable_published_record_is_recorded_when_the_request_fails(self):
        self.write_wheel()
        stub = OfflineUrllibStub(prescreen.urllib)
        stub.error = OSError("synthetic offline stub")
        records = self.run_main(stub)
        self.assertEqual([record["outcome"] for record in records],
                         ["PUBLISHED_RECORD_UNAVAILABLE"])
        # Exactly one attempted request, and the artifact was never screened.
        self.assertEqual(stub.attempts, 1)
        self.assertNotIn("advisories", records[0])

    def test_unverified_artifact_skips_the_advisory_query(self):
        path = self.write_wheel()
        stub = OfflineUrllibStub(prescreen.urllib)
        # A recorded index record that disagrees with the local bytes.
        stub.bodies.append(self.index_body(self.WHEEL_NAME, "0" * 64, 1))
        records = self.run_main(stub)
        self.assertEqual([record["outcome"] for record in records], ["ARTIFACT_DIGEST_MISMATCH"])
        self.assertEqual(records[0]["advisories"], "SKIPPED_UNVERIFIED_ARTIFACT")
        # The index request happened; the advisory query was never attempted.
        self.assertEqual(stub.attempts, 1)
        self.assertIsNotNone(path)

    def test_matching_record_with_a_malformed_advisory_response_is_a_fixed_code(self):
        path = self.write_wheel()
        sha256, size = self.digest_and_size(path)
        stub = OfflineUrllibStub(prescreen.urllib)
        stub.bodies.append(self.index_body(self.WHEEL_NAME, sha256, size))
        stub.bodies.append(b"{ not json")
        records = self.run_main(stub)
        self.assertEqual([record["outcome"] for record in records], ["OK"])
        self.assertEqual(records[0]["advisories"], "OSV_QUERY_FAILED")
        self.assertEqual(records[0]["package_name"], "synthetic-sample")
        self.assertEqual(stub.attempts, 2)

    # --- The identity an advisory query is allowed to be asked about --------
    #
    # The advisory service is the one request this helper makes that sends
    # something outward, and what it may be asked about is the identity of the
    # *distribution*, not whatever an archive member claimed. These cases pin
    # the boundary end to end through main(): which identity the query carries,
    # and that a refused identity costs no query at all.

    def test_vendored_metadata_never_drives_the_advisory_query(self):
        # The reported defect, driven through main(): the wheel carries a
        # vendored distribution's metadata, and the query must name the outer
        # distribution the index published, not the vendored one.
        path = self.write_wheel(extra_members=[vendored_member()])
        sha256, size = self.digest_and_size(path)
        stub = OfflineUrllibStub(prescreen.urllib)
        stub.bodies.append(self.index_body(self.WHEEL_NAME, sha256, size))
        stub.bodies.append(json.dumps({"vulns": []}).encode())
        records = self.run_main(stub)
        self.assertEqual([record["outcome"] for record in records], ["OK"])
        self.assertEqual(records[0]["package_name"], PUBLISHED_NAME)
        self.assertEqual(records[0]["version"], PUBLISHED_VERSION)
        self.assertEqual(records[0]["advisories"], [])
        self.assertEqual(stub.advisory_queries, [(PUBLISHED_NAME, PUBLISHED_VERSION)])
        self.assertEqual((stub.fetches, stub.queries), (1, 1))
        self.assertNotIn(SENTINELS[0], json.dumps(records))

    def test_an_identity_the_index_does_not_publish_is_never_queried(self):
        # The index record is the independent source of identity. If it names
        # another distribution, the artifact's own claim is unverified: the
        # record says so, and no advisory query is made for either name.
        for label, name, version in (("another distribution", "synthetic-other", PUBLISHED_VERSION),
                                     ("another version", PUBLISHED_NAME, "9.9.9")):
            with self.subTest(published=label), self.private_case():
                path = self.write_wheel()
                sha256, size = self.digest_and_size(path)
                stub = OfflineUrllibStub(prescreen.urllib)
                stub.bodies.append(self.index_body(self.WHEEL_NAME, sha256, size,
                                                   name=name, version=version))
                records = self.run_main(stub)
                self.assertEqual([record["outcome"] for record in records],
                                 ["DISTRIBUTION_IDENTITY_UNVERIFIED"])
                self.assertEqual(stub.queries, 0)
                self.assertEqual(stub.advisory_queries, [])
                self.assertEqual(records[0]["advisories"], "SKIPPED_UNVERIFIED_ARTIFACT")
                self.assertIsNone(records[0]["package_name"])
                self.assertIsNone(records[0]["version"])
                blob = json.dumps(records)
                self.assertNotIn("synthetic-other", blob)
                self.assertNotIn("9.9.9", blob)

    def test_a_published_record_without_an_identity_is_unavailable(self):
        # Nothing to bind to: a record that does not publish which
        # distribution this version is, cannot be used to verify one.
        path = self.write_wheel()
        sha256, size = self.digest_and_size(path)
        stub = OfflineUrllibStub(prescreen.urllib)
        stub.bodies.append(self.index_body(self.WHEEL_NAME, sha256, size, publish_identity=False))
        records = self.run_main(stub)
        self.assertEqual([record["outcome"] for record in records],
                         ["PUBLISHED_RECORD_UNAVAILABLE"])
        self.assertEqual(stub.queries, 0)
        self.assertNotIn("advisories", records[0])

    def test_a_published_record_that_cannot_be_screened_is_refused(self):
        # The screen compares against this record, so it needs an identity, a
        # digest and a byte count in the shapes it compares. Each shape below
        # is a typed refusal that spends one fetch, no archive and no query: a
        # pin that is not a digest becomes the absent pin, a byte count that is
        # not a byte count and an identity outside the grammar make the record
        # unusable.
        cases = (
            ("digest is not a string", {"sha256": 4096, "size": 10},
             "EXPECTED_DIGEST_ABSENT"),
            ("size is not an integer", {"sha256": "0" * 64, "size": "10"},
             "PUBLISHED_RECORD_UNAVAILABLE"),
            ("size is a boolean", {"sha256": "0" * 64, "size": True},
             "PUBLISHED_RECORD_UNAVAILABLE"),
            ("published name outside the grammar",
             {"sha256": "0" * 64, "size": 10, "name": "synthetic sample"},
             "PUBLISHED_RECORD_UNAVAILABLE"),
            ("published version outside the grammar",
             {"sha256": "0" * 64, "size": 10, "version": "not a version"},
             "PUBLISHED_RECORD_UNAVAILABLE"),
        )
        for label, pin, expected in cases:
            with self.subTest(published=label), self.private_case():
                path = self.write_wheel()
                stub = OfflineUrllibStub(prescreen.urllib)
                stub.bodies.append(self.index_body(self.WHEEL_NAME, **pin))
                records = self.run_main(stub)
                self.assertEqual([record["outcome"] for record in records], [expected])
                self.assertEqual((stub.fetches, stub.queries), (1, 0))
                self.assertIsNone(records[0]["package_name"])

    def test_a_refused_outer_identity_is_never_queried(self):
        # Ambiguous, absent or unbound outer identity: each is refused, and
        # none of them may turn into an advisory query under any identity.
        cases = (
            ("ambiguous", {"extra_members": [
                ("extra-1.0.dist-info/METADATA", PRESCREEN_GOOD_METADATA)]},
             "DIST_INFO_METADATA_AMBIGUOUS"),
            ("absent", {"with_metadata": False}, "METADATA_ABSENT"),
            ("vendored only", {"with_metadata": False, "extra_members": [vendored_member()]},
             "METADATA_ABSENT"),
            ("declared name disagrees", {"metadata": synthetic_metadata(
                [("Name", SENTINELS[0]), ("Version", PUBLISHED_VERSION)])},
             "DISTRIBUTION_IDENTITY_MISMATCH"),
            ("declared name outside the grammar", {"metadata": synthetic_metadata(
                [("Name", "synthetic sample"), ("Version", PUBLISHED_VERSION)])},
             "DISTRIBUTION_IDENTITY_INVALID"),
        )
        for label, wheel_arguments, expected in cases:
            with self.subTest(identity=label), self.private_case():
                path = self.write_wheel(**wheel_arguments)
                sha256, size = self.digest_and_size(path)
                stub = OfflineUrllibStub(prescreen.urllib)
                stub.bodies.append(self.index_body(self.WHEEL_NAME, sha256, size))
                records = self.run_main(stub)
                self.assertEqual([record["outcome"] for record in records], [expected])
                self.assertEqual(stub.queries, 0)
                self.assertEqual(stub.advisory_queries, [])
                self.assertEqual(records[0]["advisories"], "SKIPPED_UNVERIFIED_ARTIFACT")
                self.assertIsNone(records[0]["package_name"])
                self.assertNotIn(SENTINELS[0], json.dumps(records))

    def test_a_refused_identity_never_falls_back_to_the_file_name(self):
        # The file name is how the index record is *requested*; it is never
        # where a reported identity comes from. A wheel whose metadata declares
        # no usable name has no recorded identity at all, rather than the one
        # its file name happens to spell.
        path = self.write_wheel(metadata=synthetic_metadata(
            [("Metadata-Version", "2.1"), ("License-Expression", "MIT")]))
        sha256, size = self.digest_and_size(path)
        stub = OfflineUrllibStub(prescreen.urllib)
        stub.bodies.append(self.index_body(self.WHEEL_NAME, sha256, size))
        records = self.run_main(stub)
        self.assertEqual([record["outcome"] for record in records],
                         ["DISTRIBUTION_IDENTITY_INVALID"])
        self.assertIsNone(records[0]["package_name"])
        self.assertIsNone(records[0]["version"])
        # The request the file name drove is still made, and nothing else is.
        self.assertEqual(stub.fetches, 1)
        self.assertEqual(stub.queries, 0)

    def test_the_index_request_uses_the_normalized_distribution_name(self):
        # One deliberate normalization, applied once: the escaped wheel-name
        # spelling becomes the project key the index is asked about, so the
        # screen does not depend on which of the equivalent spellings a
        # downloader happened to use.
        path = self.write_wheel()
        sha256, size = self.digest_and_size(path)
        stub = OfflineUrllibStub(prescreen.urllib)
        stub.bodies.append(self.index_body(self.WHEEL_NAME, sha256, size))
        self.run_main(stub)
        self.assertEqual(stub.urls, ["https://pypi.org/pypi/synthetic-sample/1.0.0/json"])

    def test_a_batch_survives_an_entry_that_stats_but_is_a_directory(self):
        # main() walks one download directory, so a directory named like a wheel
        # reaches the screen. Before this correction the read raised out of
        # main(), so one such entry lost the whole batch's report file; now the
        # entry is a typed refusal and the verified item beside it is unchanged.
        # Records are in sorted() file-name order: "blocked" before "synthetic_sample".
        os.mkdir(os.path.join(self.downloads, "blocked-1.0-py3-none-any.whl"))
        path = self.write_wheel()
        sha256, size = self.digest_and_size(path)
        stub = OfflineUrllibStub(prescreen.urllib)
        stub.bodies.append(self.index_body("blocked-1.0-py3-none-any.whl", "0" * 64, 1))
        stub.bodies.append(self.index_body(self.WHEEL_NAME, sha256, size))
        stub.bodies.append(b"{ not json")
        records, raw, counter = self.screened_batch(stub)

        self.assertEqual([record["outcome"] for record in records],
                         ["ARTIFACT_UNREADABLE", "OK"])
        refused = records[0]
        # The refusal carries no digest, no size and no archive shape: the two
        # measured fields are absent rather than null, because nothing was
        # measured, and the advisory service is not asked about bytes that were
        # never read.
        self.assertNotIn("observed_sha256", refused)
        self.assertNotIn("observed_size", refused)
        self.assertIsNone(refused["zip_members"])
        self.assertIsNone(refused["zip_entries"])
        self.assertEqual(refused["advisories"], "SKIPPED_UNVERIFIED_ARTIFACT")
        # Only the verified wheel is opened as an archive and only it is put to
        # the advisory service; both entries are still fetched from the index.
        self.assertEqual(counter.opens, 1)
        self.assertEqual((stub.fetches, stub.queries, stub.attempts), (2, 1, 3))
        verified = records[1]
        self.assertEqual(verified["observed_sha256"], sha256)
        self.assertEqual(verified["package_name"], "synthetic-sample")
        self.assertEqual(verified["advisories"], "OSV_QUERY_FAILED")
        # The report holds neither a path, nor a file name, nor the class name
        # of the exception that used to escape.
        text = raw.decode("utf-8")
        self.assertNotIn(self.tmp, text)
        self.assertNotIn("blocked-1.0-py3-none-any.whl", text)
        self.assertNotIn("IsADirectoryError", text)
        self.assertNotIn(SENTINELS[0], text)

    def test_a_batch_survives_a_read_error_and_echoes_no_exception_text(self):
        # The same batch, with the failing entry an ordinary wheel whose bytes
        # stop mid-read. The planted error text is the strongest available check
        # that no exception string, path or file name reaches the report.
        broken = self.write_wheel("broken-1.0-py3-none-any.whl")
        path = self.write_wheel()
        sha256, size = self.digest_and_size(path)
        stub = OfflineUrllibStub(prescreen.urllib)
        stub.bodies.append(self.index_body("broken-1.0-py3-none-any.whl", "0" * 64, 1))
        stub.bodies.append(self.index_body(self.WHEEL_NAME, sha256, size))
        stub.bodies.append(b"{ not json")
        records, raw, counter = self.screened_batch(stub, unreadable=[broken])

        self.assertEqual([record["outcome"] for record in records],
                         ["ARTIFACT_UNREADABLE", "OK"])
        self.assertEqual(records[0]["advisories"], "SKIPPED_UNVERIFIED_ARTIFACT")
        self.assertEqual(records[1]["observed_sha256"], sha256)
        self.assertEqual(counter.opens, 1)
        self.assertEqual((stub.fetches, stub.queries, stub.attempts), (2, 1, 3))
        text = raw.decode("utf-8")
        self.assertNotIn(self.tmp, text)
        self.assertNotIn("broken-1.0-py3-none-any.whl", text)
        self.assertNotIn(SENTINELS[0], text)
        self.assertNotIn("PermissionError", text)

    def test_a_batch_survives_a_fifo_entry_and_keeps_the_verified_item(self):
        # The same batch with a *real* FIFO as the unreadable entry: main()
        # walks a download directory, so an entry named like a wheel that is a
        # FIFO used to park the whole walk in `open()` and the report file was
        # never written at all. Now it is a typed refusal under a deadline, the
        # verified wheel beside it is unchanged, and the FIFO is neither read
        # nor waited on.
        make_fifo(os.path.join(self.downloads, "blocked-1.0-py3-none-any.whl"))
        path = self.write_wheel()
        sha256, size = self.digest_and_size(path)
        stub = OfflineUrllibStub(prescreen.urllib)
        stub.bodies.append(self.index_body("blocked-1.0-py3-none-any.whl", "0" * 64, 1))
        stub.bodies.append(self.index_body(self.WHEEL_NAME, sha256, size))
        stub.bodies.append(b"{ not json")
        try:
            with wall_clock_deadline(REFUSAL_DEADLINE_SECONDS):
                records, raw, counter = self.screened_batch(stub)
        except RefusalDeadlineExceeded:
            self.fail("main() waited on a FIFO download entry instead of refusing it")

        self.assertEqual([record["outcome"] for record in records],
                         ["ARTIFACT_UNREADABLE", "OK"])
        refused = records[0]
        self.assertNotIn("observed_sha256", refused)
        self.assertNotIn("observed_size", refused)
        self.assertIsNone(refused["zip_members"])
        self.assertIsNone(refused["zip_entries"])
        self.assertEqual(refused["advisories"], "SKIPPED_UNVERIFIED_ARTIFACT")
        # The verified item is untouched and the FIFO cost no archive open and
        # no advisory query; both entries are still fetched from the index.
        self.assertEqual(records[1]["observed_sha256"], sha256)
        self.assertEqual(records[1]["observed_size"], size)
        self.assertEqual(records[1]["zip_members"], 2)
        self.assertEqual(records[1]["package_name"], "synthetic-sample")
        self.assertEqual(records[1]["advisories"], "OSV_QUERY_FAILED")
        self.assertEqual(counter.opens, 1)
        self.assertEqual((stub.fetches, stub.queries, stub.attempts), (2, 1, 3))
        text = raw.decode("utf-8")
        self.assertNotIn(self.tmp, text)
        self.assertNotIn("blocked-1.0-py3-none-any.whl", text)
        self.assertNotIn(SENTINELS[0], text)

    def test_cli_wrong_argument_count_prints_only_the_fixed_usage_line(self):
        result = subprocess.run([sys.executable,
                                 os.path.join(HERE, "prescreen_pypi_artifacts.py")],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout.decode(), '{"outcome": "USAGE"}\n')
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
