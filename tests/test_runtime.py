import json
import shutil
import tempfile
import unittest
from pathlib import Path

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

    def tearDown(self):
        self.temporary.cleanup()

    def test_runtime_lifecycle_is_persistent_and_policy_aware(self):
        runtime_configure(self.root)
        runtime_start(self.root)
        status = runtime_status(self.root)
        self.assertEqual(status["status"], "RUNNING")
        verified = runtime_verify(self.root)
        self.assertTrue(verified["healthy"])
        state = json.loads(
            (self.root / "state" / "runtime" / "runtime.json").read_text()
        )
        self.assertEqual(state["default_policy"]["profile"], "isolated")

    def test_active_experiment_blocks_runtime_stop_and_release_is_scoped(self):
        runtime_start(self.root)
        admitted = admit_experiment("brute-force", root=self.root, memory_mib=64)
        self.assertEqual(admitted["status"], "active")
        with self.assertRaisesRegex(LabError, "active owned resources"):
            runtime_stop(self.root)
        release_experiment("brute-force", self.root)
        runtime_stop(self.root)
        self.assertEqual(runtime_status(self.root)["status"], "STOPPED")

    def test_different_profile_names_are_not_themselves_conflicts(self):
        runtime_start(self.root)
        admit_experiment("isolated-run", "isolated", self.root, memory_mib=64)
        admitted = admit_experiment("maintenance-run", "maintenance", self.root, memory_mib=64)
        self.assertEqual(admitted["conflicts"], [])

    def test_default_profile_change_does_not_mutate_pinned_experiment(self):
        runtime_start(self.root)
        admitted = admit_experiment("pinned", "isolated", self.root)
        (self.root / "config" / "networks" / "active-profile").write_text(
            "maintenance\n", encoding="utf-8"
        )
        verified = runtime_verify(self.root)
        self.assertTrue(verified["healthy"])
        self.assertTrue(verified["configured_default_changed"])
        state = json.loads((self.root / "state" / "runtime" / "runtime.json").read_text())
        self.assertEqual(state["experiments"]["pinned"]["policy"], admitted["policy"])

    def test_capacity_conflict_is_rejected_without_mutating_existing_experiment(self):
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
        runtime_start(self.root)
        from lab import runtime as runtime_module
        first = runtime_module._load(self.root)
        second = runtime_module._load(self.root)
        first["events"].append({"action": "first"})
        runtime_module._save(self.root, first)
        second["events"].append({"action": "stale"})
        with self.assertRaisesRegex(LabError, "changed concurrently"):
            runtime_module._save(self.root, second)
