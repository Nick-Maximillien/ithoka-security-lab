import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lab import cli
from lab.foundation import LabError


class NetworkApplyCliTests(unittest.TestCase):
    def test_materials_command_reports_empty_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog_dir = root / "lab" / "catalog"
            catalog_dir.mkdir(parents=True)
            (catalog_dir / "materials.yaml").write_text(
                "schema_version: 1\nmaterials: []\n",
                encoding="utf-8",
            )
            output = io.StringIO()
            with patch.object(cli, "ROOT", root), redirect_stdout(output):
                result = cli.main(["materials"])
            self.assertEqual(result, 0)
            self.assertEqual(output.getvalue(), "No approved materials are registered.\n")

    def test_materials_json_command_lists_registered_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog_dir = root / "lab" / "catalog"
            catalog_dir.mkdir(parents=True)
            (catalog_dir / "materials.yaml").write_text(
                """schema_version: 1
materials:
  - id: approved-data
    version: v1
    kind: dataset
    availability: available
""",
                encoding="utf-8",
            )
            output = io.StringIO()
            with patch.object(cli, "ROOT", root), redirect_stdout(output):
                result = cli.main(["materials", "--json"])
            self.assertEqual(result, 0)
            self.assertEqual(
                json.loads(output.getvalue())["approved-data"]["kind"],
                "dataset",
            )

    def test_operator_docs_do_not_apply_before_network_creation(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        operations = (root / "docs" / "operations.md").read_text(encoding="utf-8")
        boundaries = (root / "docs" / "network-boundaries.md").read_text(encoding="utf-8")

        self.assertNotIn("python3 lab/lab.py networks apply", readme)
        self.assertNotIn("python3 lab/lab.py networks apply", operations)
        self.assertIn("requires the already-created, correctly labeled", boundaries)

    def test_network_preflight_is_a_separate_setup_command(self):
        output = io.StringIO()
        result_value = {
            "docker_context": "default",
            "default_networks_observed": ["bridge", "host", "none"],
            "firewall_backends": {"iptables": "legacy", "ip6tables": "legacy"},
            "firewall_rules_readable_as_root": True,
            "read_only": True,
        }
        with (
            patch.object(cli, "validate_network_setup", return_value=result_value),
            redirect_stdout(output),
        ):
            result = cli.main(["networks", "preflight"])

        self.assertEqual(result, 0)
        self.assertTrue(json.loads(output.getvalue())["ready"])

    def test_network_capabilities_separate_supported_and_unsupported_controls(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = cli.main(["networks", "capabilities"])
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        controls = report["controls"]
        self.assertEqual(controls["ipv4"]["status"], "supported")
        self.assertEqual(controls["external_networks"]["status"], "supported")
        self.assertEqual(controls["dns"]["status"], "unsupported")
        self.assertEqual(controls["proxies"]["status"], "unsupported")
        self.assertEqual(controls["windows_host"]["status"], "unsupported")

    def test_apply_without_constructed_network_gives_supported_sequence(self):
        error = io.StringIO()
        with (
            patch.object(cli, "resolve_project_network_policy", return_value={"profile": "isolated"}),
            patch.object(cli, "validate_runtime_support"),
            patch.object(cli, "validate_machine_configuration"),
            patch.object(
                cli,
                "inspect_owned_network",
                side_effect=LabError("expected exactly one owned project network; found 0"),
            ),
            patch("lab.cli.subprocess.run") as runner,
            redirect_stderr(error),
        ):
            result = cli.main([
                "networks", "apply", "sec-lab-i-local-study-01",
                "--profile", "isolated", "--authorize", "reviewed network policy",
            ])

        self.assertEqual(result, 1)
        message = error.getvalue()
        self.assertIn("networks apply does not create a Docker network", message)
        self.assertIn("networks preflight", message)
        self.assertIn("validate-investigation <specification.yaml>", message)
        self.assertIn("network_policy_supported: true", message)
        self.assertIn("construct-investigation <specification.yaml>", message)
        self.assertIn("--investigation-id local-study-01", message)
        self.assertIn("applies and verifies its boundary", message)
        runner.assert_not_called()

    def test_ambiguous_project_network_is_rejected_before_adapter_execution(self):
        error = io.StringIO()
        with (
            patch.object(cli, "resolve_project_network_policy", return_value={"profile": "isolated"}),
            patch.object(cli, "validate_runtime_support"),
            patch.object(cli, "validate_machine_configuration"),
            patch.object(
                cli, "inspect_owned_network",
                side_effect=LabError("expected exactly one owned project network; found 2"),
            ),
            patch("lab.cli.subprocess.run") as runner,
            redirect_stderr(error),
        ):
            result = cli.main([
                "networks", "apply", "sec-lab-i-local-study-01",
                "--profile", "isolated", "--authorize", "reviewed network policy",
            ])

        self.assertEqual(result, 1)
        self.assertIn("found 2", error.getvalue())
        runner.assert_not_called()

    def test_read_only_network_verify_reports_structural_verification_separately(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = io.StringIO()
            completed = type("Result", (), {
                "returncode": 0, "stdout": "verified\n", "stderr": "",
            })()
            with (
                patch.object(cli, "ROOT", root),
                patch.object(cli, "resolve_project_network_policy", return_value={"profile": "isolated"}),
                patch.object(cli, "validate_runtime_support"),
                patch.object(cli, "validate_machine_configuration"),
                patch("lab.cli.subprocess.run", return_value=completed) as runner,
                redirect_stdout(output),
            ):
                result = cli.main([
                    "networks", "verify", "sec-lab-i-study",
                    "--profile", "isolated",
                ])
            self.assertEqual(result, 1)
            report = json.loads(output.getvalue())
            self.assertEqual(report["firewall_rules"], "verified")
            self.assertEqual(report["effective_behavior"], "not-verified")
            self.assertEqual(report["runtime_acceptance"], "not-run")
            self.assertIn("live-acceptance", report["policy_readiness"])
            self.assertEqual(runner.call_args.args[0][2], "verify")

    def test_unsupported_network_plan_is_written_but_returns_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = io.StringIO()
            error = io.StringIO()
            plan = {
                "supported": False,
                "capability_error": "windows_host=windows-firewall-required",
            }
            with (
                patch.object(cli, "ROOT", root),
                patch.object(cli, "build_enforcement_plan", return_value=plan),
                redirect_stdout(output),
                redirect_stderr(error),
            ):
                result = cli.main([
                    "networks", "plan", "--profile", "isolated",
                    "--output", str(root / "state" / "isolated.json"),
                ])
            self.assertEqual(result, 1)
            self.assertTrue((root / "state" / "isolated.json").is_file())
            self.assertFalse(json.loads(output.getvalue())["supported"])
            self.assertIn("windows_host=windows-firewall-required", error.getvalue())


if __name__ == "__main__":
    unittest.main()
