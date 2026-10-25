import io
import json
import platform
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lab import cli
from lab.foundation import LabError
from lab.enforcement.models import EnforcementStatus
from lab.osapi.models import OSObservation


class NetworkApplyCliTests(unittest.TestCase):
    def test_os_inspection_cli_exposes_unknown_platform_observations(self):
        output = io.StringIO()
        report = {
            "schema": "ithoka.security-lab.os-observations.v1",
            "linux": {"firewall": {"status": "PASS"}},
            "docker": {"daemon": {"status": "UNKNOWN"}},
            "windows": {"firewall": {"status": "UNKNOWN"}},
            "wsl": {"boundary": {"status": "UNKNOWN"}},
        }
        with patch.object(
            cli.EnforcementCoordinator,
            "inspect_platforms",
            return_value=report,
        ), redirect_stdout(output):
            args = cli._parser().parse_args(["os", "inspect", "--project", "sec-lab-i-test"])
            result = cli._os_command(args)

        self.assertEqual(result, 1)
        self.assertEqual(
            json.loads(output.getvalue())["windows"]["firewall"]["status"],
            "UNKNOWN",
        )

    def test_docker_inspection_command_reports_structured_read_only_status(self):
        output = io.StringIO()
        report = {
            "status": "UNKNOWN",
            "project": "sec-lab-i-study",
            "read_only": True,
            "reason": "no containers",
            "findings": [],
        }
        with (
            patch.object(cli, "inspect_docker_project", return_value=report),
            redirect_stdout(output),
        ):
            args = cli._parser().parse_args([
                "networks",
                "inspect-docker",
                "sec-lab-i-study",
            ])
            result = cli._network_command(args)

        self.assertEqual(result, 1)
        emitted = json.loads(output.getvalue())
        self.assertEqual(
            emitted["docker_runtime_inspection"]["status"],
            "UNKNOWN",
        )
        self.assertTrue(emitted["docker_runtime_inspection"]["read_only"])

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
        with (
            patch.object(
                cli,
                "_host_prerequisite_status",
                return_value={"status": "PASS", "errors": []},
            ),
            redirect_stdout(output),
        ):
            result = cli.main(["networks", "preflight"])

        self.assertEqual(result, 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["preflight"]["status"], "FAIL")
        self.assertFalse(report["preflight"]["policy_supported"])
        self.assertEqual(report["preflight"]["host_prerequisites"], "PASS")

    def test_network_capabilities_separate_supported_and_unsupported_controls(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = cli.main(["networks", "capabilities"])
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        controls = report["controls"]
        self.assertEqual(controls["ipv4"]["status"], "adapter-declared-only")
        self.assertEqual(
            controls["external_networks"]["status"],
            "adapter-declared-only",
        )
        self.assertEqual(
            controls["external_networks"]["runtime_acceptance"],
            "not-run",
        )
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
                "_host_prerequisite_status",
                return_value={"status": "PASS", "errors": []},
            ),
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
        self.assertIn("apply command does not create Docker networks", message)
        self.assertIn("network preflight", message)
        self.assertIn("inspect the investigation plan", message)
        self.assertIn("construct-investigation", message)
        self.assertIn("policy verification and runtime acceptance", message)
        runner.assert_not_called()

    def test_ambiguous_project_network_is_rejected_before_adapter_execution(self):
        error = io.StringIO()
        with (
            patch.object(cli, "resolve_project_network_policy", return_value={"profile": "isolated"}),
            patch.object(cli, "validate_runtime_support"),
            patch.object(cli, "validate_machine_configuration"),
            patch.object(
                cli,
                "_host_prerequisite_status",
                return_value={"status": "PASS", "errors": []},
            ),
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
            policy_dir = root / "state" / "network-boundary"
            policy_dir.mkdir(parents=True)
            script_dir = root / "scripts"
            script_dir.mkdir()
            (script_dir / "network-boundary.sh").write_text(
                "# test fixture\n",
                encoding="utf-8",
            )
            project = "sec-lab-i-study"
            policy = cli.resolve_project_network_policy(
                Path(__file__).resolve().parents[1], project, "isolated"
            )
            (policy_dir / f"{project}-network-policy.json").write_text(
                cli.policy_json(policy),
                encoding="utf-8",
            )
            output = io.StringIO()
            completed = type("Result", (), {
                "returncode": 0, "stdout": "verified\n", "stderr": "",
            })()
            with (
                patch.object(cli, "ROOT", root),
                patch.object(cli, "POLICY_STATE_DIR", policy_dir),
                patch.object(cli, "resolve_project_network_policy", return_value=policy),
                patch.object(cli, "validate_runtime_support"),
                patch.object(cli, "validate_machine_configuration"),
                patch.object(
                    cli,
                    "_host_prerequisite_status",
                    return_value={"status": "PASS", "errors": []},
                ),
                patch.object(
                    cli,
                    "runtime_network_readiness",
                    return_value={
                        "ready": False,
                        "effective_behavior": "not-verified",
                        "runtime_acceptance": "not-run",
                    },
                ),
                patch(
                    "lab.osapi.actions.inspect_daemon",
                    return_value=OSObservation(
                        platform="docker",
                        subsystem="daemon",
                        operation="inspect",
                        target="default",
                        source="test fixture",
                        observed_utc="now",
                        status=EnforcementStatus.PASS,
                        values={
                            "selected_context": "default",
                            "endpoint": {"Host": "unix:///var/run/docker.sock"},
                            "daemon": {
                                "Name": platform.node(),
                                "OSType": "linux",
                            },
                        },
                    ),
                ),
                patch("lab.cli.subprocess.run", return_value=completed) as runner,
                redirect_stdout(output),
            ):
                result = cli.main([
                    "networks", "verify", project,
                    "--profile", "isolated",
                ])
            self.assertEqual(result, 1)
            report = json.loads(output.getvalue())
            self.assertEqual(
                report["structural_verification_output"], "verified"
            )
            self.assertEqual(
                report["enforcement"]["structural_verification"], "PASS"
            )
            self.assertEqual(
                report["acceptance_evidence"]["effective_behavior"],
                "not-verified",
            )
            self.assertEqual(
                report["acceptance_evidence"]["runtime_acceptance"],
                "not-run",
            )
            boundary_call = next(
                call for call in runner.call_args_list
                if call.args[0][0] == "bash"
            )
            self.assertEqual(boundary_call.args[0][2], "verify")

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
                patch.object(
                    cli,
                    "resolve_network_policy",
                    return_value={"profile": "isolated"},
                ),
                patch.object(
                    cli,
                    "_support_status",
                    return_value={"supported": False, "reason": "unsupported"},
                ),
                patch.object(
                    cli,
                    "_host_prerequisite_status",
                    return_value={"status": "PASS", "errors": []},
                ),
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
            self.assertFalse(
                json.loads(output.getvalue())["enforcement_plan"]["supported"]
            )
            self.assertIn(
                "windows_host=windows-firewall-required",
                json.loads(output.getvalue())["enforcement_plan"]["capability_error"],
            )


if __name__ == "__main__":
    unittest.main()
