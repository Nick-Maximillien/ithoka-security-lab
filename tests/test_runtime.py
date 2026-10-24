import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lab.foundation import LabError
from lab.runtime import (
    admit_experiment,
    release_experiment,
    request_maintenance,
    runtime_configure,
    runtime_start,
    runtime_status,
    runtime_stop,
    runtime_verify,
)


ROOT = Path(__file__).resolve().parents[1]


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        shutil.copytree(ROOT / "config", self.root / "config")
        for filename in ("windows-host.yaml", "dns.yaml", "proxies.yaml"):
            boundary = self.root / "config" / "networks" / "boundaries" / filename
            boundary.write_text(
                boundary.read_text(encoding="utf-8").replace("enabled: true", "enabled: false"),
                encoding="utf-8",
            )
        self.readiness = patch(
            "lab.runtime._network_readiness",
            return_value={
                "ready": True,
                "controls_applied": "not-verified",
                "effective_behavior": "not-verified",
                "runtime_acceptance": "not-run",
                "reason": None,
            },
        )
        self.readiness.start()
        self.addCleanup(self.readiness.stop)

    def tearDown(self):
        self.temporary.cleanup()

    def test_runtime_lifecycle_is_persistent_and_policy_aware(self):
        runtime_configure(self.root)
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch("lab.runtime.validate_network_setup", return_value={"ready": True}),
        ):
            runtime_start(self.root)
        status = runtime_status(self.root)
        self.assertEqual(status["status"], "RUNNING")
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch("lab.runtime.validate_network_setup", return_value={"ready": True}),
        ):
            verified = runtime_verify(self.root)
        self.assertFalse(verified["healthy"])
        self.assertEqual(verified["controls_applied"], "not-verified")
        self.assertEqual(verified["effective_behavior"], "not-verified")
        self.assertEqual(verified["runtime_acceptance"], "not-run")
        state = json.loads(
            (self.root / "state" / "runtime" / "runtime.json").read_text()
        )
        self.assertEqual(state["default_policy"]["profile"], "isolated")

    def test_unsupported_runtime_policy_is_reported_and_fails_closed(self):
        with self.assertRaisesRegex(
            LabError, "external_networks=runtime-acceptance-unavailable"
        ):
            runtime_start(self.root)
        self.assertEqual(runtime_status(self.root)["status"], "STOPPED")
        verified = runtime_verify(self.root)
        self.assertEqual(verified["policy_support"], "unsupported")
        self.assertEqual(verified["machine_prerequisites"], "not-ready")
        self.assertFalse(verified["healthy"])
        self.assertIn(
            "external_networks=runtime-acceptance-unavailable",
            verified["policy_error"],
        )

    def test_runtime_start_fails_closed_when_machine_preflight_fails(self):
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch(
                "lab.runtime.validate_network_setup",
                side_effect=LabError("cannot read privileged firewall rules"),
            ),
        ):
            with self.assertRaisesRegex(LabError, "privileged firewall rules"):
                runtime_start(self.root)
        self.assertEqual(runtime_status(self.root)["status"], "STOPPED")

    def test_runtime_start_refuses_without_verified_network_acceptance(self):
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch("lab.runtime.validate_network_setup", return_value={"ready": True}),
            patch("lab.runtime._network_readiness", return_value={
                "ready": False,
                "controls_applied": "verified",
                "effective_behavior": "not-verified",
                "runtime_acceptance": "not_configured",
                "reason": "project has no live acceptance evidence",
            }),
        ):
            with self.assertRaisesRegex(
                LabError, "runtime start refused.*no live acceptance evidence"
            ):
                runtime_start(self.root)
        self.assertEqual(runtime_status(self.root)["status"], "STOPPED")

    def test_running_runtime_revalidates_policy_before_idempotent_start(self):
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch("lab.runtime.validate_network_setup", return_value={"ready": True}),
        ):
            runtime_start(self.root)
        boundary = self.root / "config" / "networks" / "boundaries" / "windows-host.yaml"
        boundary.write_text(
            boundary.read_text(encoding="utf-8").replace("enabled: false", "enabled: true"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LabError, "windows_host=windows-firewall-required"):
            runtime_start(self.root)
        self.assertEqual(runtime_status(self.root)["status"], "RUNNING")

    def test_runtime_start_rejects_required_unsupported_boundaries(self):
        boundary = self.root / "config" / "networks" / "boundaries" / "windows-host.yaml"
        boundary.write_text(
            boundary.read_text(encoding="utf-8").replace("enabled: false", "enabled: true"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LabError, "windows_host=windows-firewall-required"):
            runtime_start(self.root)

    def test_active_experiment_blocks_runtime_stop_and_release_is_scoped(self):
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch("lab.runtime.validate_network_setup", return_value={"ready": True}),
        ):
            runtime_start(self.root)
            admitted = admit_experiment("brute-force", root=self.root, memory_mib=64)
        self.assertEqual(admitted["status"], "active")
        with self.assertRaisesRegex(LabError, "active owned resources"):
            runtime_stop(self.root)
        release_experiment("brute-force", self.root)
        runtime_stop(self.root)
        self.assertEqual(runtime_status(self.root)["status"], "STOPPED")

    def test_different_profile_names_are_not_themselves_conflicts(self):
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch("lab.runtime.validate_network_setup", return_value={"ready": True}),
        ):
            runtime_start(self.root)
            admit_experiment("isolated-run", "isolated", self.root, memory_mib=64)
            admitted = admit_experiment("maintenance-run", "maintenance", self.root, memory_mib=64)
        self.assertEqual(admitted["conflicts"], [])

    def test_default_profile_change_does_not_mutate_pinned_experiment(self):
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch("lab.runtime.validate_network_setup", return_value={"ready": True}),
        ):
            runtime_start(self.root)
            admitted = admit_experiment("pinned", "isolated", self.root)
        (self.root / "config" / "networks" / "active-profile").write_text(
            "maintenance\n", encoding="utf-8"
        )
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch("lab.runtime.validate_network_setup", return_value={"ready": True}),
        ):
            verified = runtime_verify(self.root)
        self.assertFalse(verified["healthy"])
        self.assertTrue(verified["configured_default_changed"])
        state = json.loads((self.root / "state" / "runtime" / "runtime.json").read_text())
        self.assertEqual(state["experiments"]["pinned"]["policy"], admitted["policy"])

    def test_capacity_conflict_is_rejected_without_mutating_existing_experiment(self):
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch("lab.runtime.validate_network_setup", return_value={"ready": True}),
        ):
            runtime_start(self.root)
            admit_experiment("a", root=self.root, memory_mib=400)
            with self.assertRaisesRegex(LabError, "capacity"):
                admit_experiment("b", root=self.root, memory_mib=200)
        state = json.loads((self.root / "state" / "runtime" / "runtime.json").read_text())
        self.assertNotIn("b", state["experiments"])
        self.assertEqual(state["experiments"]["a"]["status"], "active")

    def test_maintenance_is_recorded_as_explicit_rejection(self):
        result = request_maintenance("maintenance-1", "a", self.root, "registry.example")
        self.assertEqual(result["status"], "rejected")
        self.assertIn("unsupported", result["reason"])

    def test_stale_runtime_state_cannot_overwrite_newer_admission(self):
        with (
            patch("lab.runtime.validate_runtime_support"),
            patch("lab.runtime.validate_network_setup", return_value={"ready": True}),
        ):
            runtime_start(self.root)
        from lab import runtime as runtime_module
        first = runtime_module._load(self.root)
        second = runtime_module._load(self.root)
        first["events"].append({"action": "first"})
        runtime_module._save(self.root, first)
        second["events"].append({"action": "stale"})
        with self.assertRaisesRegex(LabError, "changed concurrently"):
            runtime_module._save(self.root, second)
