import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SHELL_SCRIPTS = (
    "lib.sh",
    "preflight.sh",
    "capture-start.sh",
    "capture-stop.sh",
    "gui.sh",
    "maintenance.sh",
    "incident.sh",
    "network-boundary.sh",
)


class ShellControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        shutil.copytree(ROOT / "scripts", self.root / "scripts")
        shutil.copytree(ROOT / "config", self.root / "config")
        shutil.copytree(ROOT / "lab", self.root / "lab")
        (self.root / "config" / "lab.env").write_text(
            (self.root / "config" / "lab.env.example").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        self.environment = os.environ.copy()
        for name in (
            "LAB_CONFIG_FILE",
            "LAB_RUN_ID",
            "MAINTENANCE_APPROVAL",
            "CAPTURE_APPROVAL",
        ):
            self.environment.pop(name, None)
        self.environment.update({
            "LAB_CONFIG_FILE": str(self.root / "config" / "lab.env"),
            "LAB_RUN_ID": "shell-test-run",
        })

    def tearDown(self):
        self.temporary.cleanup()

    def _run(self, script, *arguments, environment=None):
        return subprocess.run(
            ["bash", str(self.root / "scripts" / script), *arguments],
            cwd=self.root,
            env=environment or self.environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

    def test_every_controller_script_passes_bash_syntax_check(self):
        result = subprocess.run(
            ["bash", "-n", *[
                str(self.root / "scripts" / script)
                for script in SHELL_SCRIPTS
            ]],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_selected_missing_configuration_does_not_fall_back(self):
        environment = self.environment.copy()
        environment["LAB_CONFIG_FILE"] = str(self.root / "config" / "missing.env")
        result = self._run("incident.sh", "network", environment=environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("selected configuration is missing", result.stderr)

    def test_incident_record_is_created_once_and_associated_with_run(self):
        result = self._run("incident.sh", "network-outage")
        record = (
            self.root
            / "evidence-staging"
            / "shell-test-run"
            / "incident-network-outage.md"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        text = record.read_text(encoding="utf-8")
        self.assertIn("- Run: shell-test-run", text)
        self.assertIn("- Status: OPEN", text)
        self.assertIn("Do not mark containment as successful without evidence.", text)

        repeated = self._run("incident.sh", "network-outage")
        self.assertNotEqual(repeated.returncode, 0)
        self.assertIn("refusing to overwrite", repeated.stderr)

    def test_maintenance_record_matches_required_policy_fields_without_claiming_verification(self):
        environment = self.environment.copy()
        environment["MAINTENANCE_APPROVAL"] = "true"
        result = self._run(
            "maintenance.sh",
            "record",
            "sample-dependency",
            "package==1.2.3",
            "https://registry.invalid/sample",
            "sha256:operator-recorded-input",
            environment=environment,
        )
        record_path = self.root / "state" / "maintenance" / "dependencies.yaml"
        self.assertEqual(result.returncode, 0, result.stderr)
        record = yaml.safe_load(record_path.read_text(encoding="utf-8"))
        dependency = record["dependencies"][0]
        required = yaml.safe_load(
            (self.root / "config" / "maintenance-policy.yaml").read_text(
                encoding="utf-8"
            )
        )["maintenance"]["required_records"]
        self.assertTrue(set(required).issubset(dependency))
        self.assertEqual(dependency["dependency_reference"], "package==1.2.3")
        self.assertEqual(dependency["source_or_registry"], "https://registry.invalid/sample")
        self.assertEqual(dependency["verification_result"], "not-run")
        self.assertIn("no download", result.stdout)

    def test_maintenance_refuses_to_append_to_malformed_record(self):
        record_path = self.root / "state" / "maintenance" / "dependencies.yaml"
        record_path.parent.mkdir(parents=True)
        record_path.write_text("schema_version: 1\ndependencies: invalid\n", encoding="utf-8")
        original = record_path.read_bytes()
        environment = self.environment.copy()
        environment["MAINTENANCE_APPROVAL"] = "true"
        result = self._run(
            "maintenance.sh",
            "record",
            "sample-dependency",
            "package==1.2.3",
            "https://registry.invalid/sample",
            "sha256:input",
            environment=environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing dependency record is invalid", result.stderr)
        self.assertEqual(record_path.read_bytes(), original)

    def test_capture_requires_explicit_approval_and_stop_requires_recorded_state(self):
        result = self._run("capture-start.sh", "eth0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CAPTURE_APPROVAL=true", result.stderr)

        stopped = self._run("capture-stop.sh")
        self.assertNotEqual(stopped.returncode, 0)
        self.assertIn("capture PID/path state is missing", stopped.stderr)


if __name__ == "__main__":
    unittest.main()
