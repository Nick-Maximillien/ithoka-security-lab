import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[1]


class StaticPolicyTests(unittest.TestCase):
    def test_lab_has_no_preinstalled_investigations(self):
        experiments = ROOT / "experiments"
        self.assertFalse(experiments.exists())
        config = (ROOT / "config" / "lab.env.example").read_text()
        self.assertNotIn("LAB_EXPERIMENT", config)
        self.assertNotIn("LAB_NETWORK", config)

    def test_construction_entry_points_are_modular(self):
        for name in ("lab.py", "construction.py", "validation.py", "evidence.py"):
            self.assertTrue((ROOT / "lab" / name).exists(), name)
        self.assertTrue((ROOT / "scripts" / "preflight.sh").exists())

    def test_no_experiment_specific_runtime_branch_remains(self):
        for path in (ROOT / "lab").glob("*.py"):
            content = path.read_text()
            self.assertNotIn("EXP-0001", content)
            self.assertNotIn("EXP-0003", content)

    def test_emergency_stop_remains_scoped(self):
        content = (ROOT / "host" / "EmergencyStop.ps1").read_text()
        self.assertIn("StopLab", content)
        self.assertNotIn("--unregister", content)
