"""Fail-closed readiness tests. Synthetic fixtures are not sandbox acceptance."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from infra.preflight import runtime


IMAGE = "sha256:" + "a" * 64
POLICY = {"approved_probe_images": [{"image_id": IMAGE, "purpose": "synthetic-preflight"}]}
GOOD_FIXTURE = """uid=65534
cap_eff=0000000000000000
no_new_privs=1
seccomp=2
root_readonly=1
interfaces=lo,
memory.max=134217728
pids.max=32
cpu.max=50000 100000
"""


def result(value="", exit_code=0):
    return {"stdout": json.dumps(value) if isinstance(value, dict) else value,
            "stderr": "", "exit_code": exit_code}


def inventory():
    return {
        "docker_version": result({"Client": {"Version": "test"}, "Server": {"Version": "test"}}),
        "docker_info": result({"OSType": "linux", "CgroupVersion": "2"}),
        "docker_endpoint": result('"unix:///var/run/docker.sock"'),
        "compose_version": result("test"),
    }


class ReadinessTests(unittest.TestCase):
    def test_inventory_never_establishes_an_arena_or_fixture_tier(self):
        report = runtime.assess(inventory(), POLICY)
        self.assertTrue(report["linux_engine_reachable"])
        self.assertFalse(report["synthetic_fixture_ready"])
        self.assertFalse(report["arena_ready"])
        self.assertIsNone(report["guarantee_tier_achieved"])
        self.assertEqual(report["controls"]["SECCOMP_FILTER_ACTIVE"]["state"], "UNTESTED")

    def test_every_required_fixture_observation_is_necessary(self):
        raw = inventory() | {"probe_image": IMAGE, "fixture": result(GOOD_FIXTURE)}
        self.assertTrue(runtime.assess(raw, POLICY)["synthetic_fixture_ready"])
        for line in GOOD_FIXTURE.splitlines():
            with self.subTest(missing=line):
                raw["fixture"] = result(GOOD_FIXTURE.replace(line + "\n", ""))
                self.assertFalse(runtime.assess(raw, POLICY)["synthetic_fixture_ready"])
        self.assertFalse(runtime.assess(raw, POLICY)["arena_ready"])

    def test_remote_context_cannot_be_disguised_by_local_host_override(self):
        raw = inventory() | {"probe_image": IMAGE, "fixture": result(GOOD_FIXTURE),
                             "docker_host_override": "unix:///var/run/docker.sock"}
        raw["docker_endpoint"] = result('"ssh://another-host"')
        self.assertFalse(runtime.assess(raw, POLICY)["synthetic_fixture_ready"])
        self.assertEqual(runtime.assess(raw, POLICY)["controls"]["LOCAL_DAEMON"]["state"], "UNAVAILABLE")

    def test_remote_host_override_is_rejected_even_with_local_context(self):
        raw = inventory() | {"docker_host_override": "tcp://127.0.0.1:2375"}
        self.assertEqual(runtime.assess(raw, POLICY)["controls"]["LOCAL_DAEMON"]["state"], "UNAVAILABLE")

    def test_daemon_failure_cannot_pass_from_partial_json(self):
        raw = inventory() | {"probe_image": IMAGE, "fixture": result(GOOD_FIXTURE)}
        raw["docker_info"]["exit_code"] = 1
        report = runtime.assess(raw, POLICY)
        self.assertFalse(report["linux_engine_reachable"])
        self.assertFalse(report["synthetic_fixture_ready"])

    def test_windows_daemon_cannot_be_claimed_as_linux(self):
        raw = inventory() | {"probe_image": IMAGE, "fixture": result(GOOD_FIXTURE)}
        raw["docker_info"] = result({"OSType": "windows"})
        self.assertFalse(runtime.assess(raw, POLICY)["synthetic_fixture_ready"])

    def test_unapproved_fixture_output_is_not_enforced_evidence(self):
        raw = inventory() | {"probe_image": IMAGE, "fixture": result(GOOD_FIXTURE)}
        report = runtime.assess(raw, {"approved_probe_images": []})
        self.assertFalse(report["synthetic_fixture_ready"])
        self.assertEqual(report["controls"]["NON_ROOT_UID"]["state"], "FAILED")

    def test_mutable_tags_and_unapproved_images_rejected_before_execution(self):
        for image in ("alpine:latest", IMAGE + ";echo unexpected", "sha256:" + "b" * 64):
            with self.subTest(image=image), patch.object(runtime, "collect") as collect:
                with patch.object(sys, "argv", ["preflight", "--output", "artifacts/preflight/uncreated.json", "--probe-image", image]):
                    self.assertEqual(runtime.main(), 1)
                collect.assert_not_called()

    def test_unapproved_image_cannot_trigger_docker_run_or_pull(self):
        with patch.object(runtime, "run_command", return_value=result()) as run:
            with self.assertRaises(ValueError):
                runtime.collect({"approved_probe_images": []}, IMAGE)
            self.assertFalse(any("run" in call.args[0] or "pull" in call.args[0] for call in run.call_args_list))

    def test_output_path_cannot_write_into_frontend_or_escape_project(self):
        for path in (runtime.ROOT / "frontend/preflight.json", runtime.ROOT / "../preflight.json"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                runtime.receipt_path(path)

    def test_existing_receipt_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipt.json"
            path.write_text("original", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                runtime.write_new(path, {"changed": True})
            self.assertEqual(path.read_text(), "original")

    def test_missing_binary_and_timeout_preserve_failure(self):
        with patch.object(subprocess, "run", side_effect=FileNotFoundError):
            missing = runtime.run_command(["missing-command"])
        self.assertIsNone(missing["exit_code"])
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired(["docker"], 1, output=b"partial")):
            timeout = runtime.run_command(["docker"], timeout=1)
        self.assertTrue(timeout["timed_out"])
        self.assertIsNone(timeout["exit_code"])
        self.assertEqual(timeout["stdout"], "partial")

    def test_wsl_redirected_utf16_output_is_readable(self):
        self.assertEqual(runtime.decode("docker-desktop Stopped 2".encode("utf-16-le")), "docker-desktop Stopped 2")


if __name__ == "__main__":
    unittest.main()
