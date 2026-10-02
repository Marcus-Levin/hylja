#!/usr/bin/env python3
"""Deterministic self-tests for the research sandbox helpers.

These tests execute **no candidate code, download nothing, need no network and
need no sandbox**. They cover the parts of the helper that make the trial's
trust story true: the offline installer's refusal paths, the untrusted child
result schema, and the isolation properties the sandbox runner declares.

Run directly:  python3 scripts/research/selftest.py
It is not part of `npm test` or CI; it is run and reported separately.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
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

PRESCREEN_GOOD_METADATA = "\n".join([
    "Metadata-Version: 2.1",
    "Name: synthetic-sample",
    "Version: 1.0.0",
    "License-Expression: MIT",
    "Requires-Python: >=3.10",
    "",
    "A synthetic description.",
]) + "\n"


class PrescreenHelperTest(unittest.TestCase):
    """The host-side screen refuses unverified bytes before touching a ZIP."""

    def setUp(self):
        if prescreen is None:
            self.fail("prescreen_pypi_artifacts.py must expose an importable offline screen")
        self.tmp = tempfile.mkdtemp(prefix="prescreen-host-")
        os.chmod(self.tmp, 0o700)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_wheel(self, name, members):
        path = os.path.join(self.tmp, name)
        with zipfile.ZipFile(path, "w") as archive:
            for member, data in members:
                archive.writestr(member, data)
        return path

    def digest_of(self, path):
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()

    def test_matching_pin_is_accepted_and_reads_its_own_metadata(self):
        path = self.write_wheel("ok-1.0-py3-none-any.whl", [
            ("ok/__init__.py", b"# synthetic\n"),
            ("ok-1.0.dist-info/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        record = prescreen.screen_local_artifact(path, self.digest_of(path), None)
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
        record = prescreen.screen_local_artifact(path, None, None)
        self.assertEqual(record["outcome"], "EXPECTED_DIGEST_ABSENT")
        self.assertEqual(record["package_name"], None)

    def test_mismatched_expected_digest_refuses_before_parsing(self):
        path = os.path.join(self.tmp, "broken-1.0-py3-none-any.whl")
        with open(path, "wb") as handle:
            handle.write(b"PK\x03\x04 truncated")
        record = prescreen.screen_local_artifact(path, "0" * 64, None)
        self.assertEqual(record["outcome"], "ARTIFACT_DIGEST_MISMATCH")

    def test_mismatched_size_refuses_with_a_fixed_code(self):
        path = self.write_wheel("ok-1.0-py3-none-any.whl", [("ok/__init__.py", b"x")])
        record = prescreen.screen_local_artifact(path, self.digest_of(path), 1)
        self.assertEqual(record["outcome"], "ARTIFACT_SIZE_MISMATCH")

    def test_oversize_artifact_is_refused(self):
        path = os.path.join(self.tmp, "big-1.0-py3-none-any.whl")
        with open(path, "wb") as handle:
            handle.write(b"PK\x03\x04" + b"\x00" * 4096)
        original = prescreen.MAX_ARTIFACT_BYTES
        prescreen.MAX_ARTIFACT_BYTES = 128
        try:
            record = prescreen.screen_local_artifact(path, None, None)
            self.assertEqual(record["outcome"], "ARTIFACT_TOO_LARGE")
        finally:
            prescreen.MAX_ARTIFACT_BYTES = original

    def test_metadata_expansion_bomb_is_refused_with_a_fixed_code(self):
        path = self.write_wheel("bomb-1.0-py3-none-any.whl", [
            ("bomb/__init__.py", b"x"),
            ("bomb-1.0.dist-info/METADATA", b"A" * (prescreen.MAX_METADATA_BYTES + 1)),
        ])
        record = prescreen.screen_local_artifact(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "METADATA_TOO_LARGE")

    def test_member_count_bound_is_enforced(self):
        members = [("pkg/%d.py" % i, b"") for i in range(prescreen.MAX_MEMBERS + 1)]
        path = self.write_wheel("many-1.0-py3-none-any.whl", members)
        record = prescreen.screen_local_artifact(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "MEMBER_COUNT_OUT_OF_BOUNDS")

    def test_malformed_archive_yields_a_fixed_code_not_an_exception(self):
        path = os.path.join(self.tmp, "bad-1.0-py3-none-any.whl")
        with open(path, "wb") as handle:
            handle.write(b"not a zip at all")
        record = prescreen.screen_local_artifact(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "ARCHIVE_UNREADABLE")

    def test_missing_metadata_yields_a_fixed_code(self):
        path = self.write_wheel("nometa-1.0-py3-none-any.whl", [("nometa/__init__.py", b"x")])
        record = prescreen.screen_local_artifact(path, self.digest_of(path), None)
        self.assertEqual(record["outcome"], "METADATA_ABSENT")

    def test_record_never_echoes_member_or_file_names(self):
        path = self.write_wheel("secretname-1.0-py3-none-any.whl", [
            ("pkg/__init__.py", b"x"),
            ("secretname-1.0.dist-info/METADATA", PRESCREEN_GOOD_METADATA.encode()),
        ])
        record = prescreen.screen_local_artifact(path, self.digest_of(path), None)
        blob = json.dumps(record)
        self.assertNotIn("secretname-1.0-py3-none-any.whl", blob)
        self.assertNotIn("pkg/__init__.py", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
