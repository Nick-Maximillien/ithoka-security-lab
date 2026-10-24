import json
import shutil
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

import yaml

import lab
from lab.evidence import archive_evidence
from lab.foundation import LabError


ROOT = Path(__file__).resolve().parents[1]


class ConstructionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        shutil.copytree(ROOT / "config", self.root / "config")
        lab_env = self.root / "config" / "lab.env"
        lab_env.write_text(
            (self.root / "config" / "lab.env.example").read_text(encoding="utf-8")
            .replace("REQUIRE_RUNTIME_APPROVAL=false", "REQUIRE_RUNTIME_APPROVAL=true"),
            encoding="utf-8",
        )
        shutil.copytree(ROOT / "lab", self.root / "lab")
        shutil.copytree(ROOT / "scripts", self.root / "scripts")
        (self.root / "compose").mkdir()
        (self.root / "compose" / "research.yaml").write_text(
            """services:
  target:
    image: alpine:3.20
    command: ["sleep", "1"]
    user: lab
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 64m
    pids_limit: 16
    cpus: 0.5
    networks: [investigation]
networks:
  investigation:
    internal: true
""",
            encoding="utf-8",
        )
        self.spec = self.root / "investigation.yaml"
        self.spec.write_text(
            yaml.safe_dump({
                "schema_version": 1,
                "investigation": {"question": "Does the target remain available?"},
                "apparatus": {
                    "backend": "docker.compose",
                    "compose_file": "compose/research.yaml",
                    "network": {"logical_name": "investigation"},
                },
                "resources": [{"id": "compose", "kind": "docker.compose"}],
                "procedure": [{"id": "construct", "operation": "construct"}],
                "observations": {},
                "evaluation": {},
                "evidence": {},
                "safety": {"required_approvals": ["runtime"]},
                "resource_budget": {
                    "memory_mib": 64, "cpu_millicores": 500,
                    "pids": 16, "storage_mib": 128,
                },
            }, sort_keys=False),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_researcher_spec_validates_without_catalogued_experiment(self):
        specification = lab.validate_investigation(self.spec, self.root)
        self.assertEqual(specification["apparatus"]["backend"], "docker.compose")

    def test_plan_resolves_resources_and_records_integrity(self):
        plan = lab.build_construction_plan(self.spec, "investigation-one", self.root)
        self.assertEqual(plan["ownership"]["investigation"], "investigation-one")
        self.assertEqual(plan["resources"][0]["status"], "approved-lab-resource")
        self.assertEqual(len(plan["specification_sha256"]), 64)

    def test_unsupported_procedure_fails_closed(self):
        document = yaml.safe_load(self.spec.read_text(encoding="utf-8"))
        document["procedure"][0]["operation"] = "arbitrary_shell"
        self.spec.write_text(yaml.safe_dump(document), encoding="utf-8")
        with self.assertRaisesRegex(lab.LabError, "unsupported procedure"):
            lab.validate_investigation(self.spec, self.root)

    def test_plan_is_inspectable_json(self):
        output = self.root / "state" / "plan.json"
        lab.write_plan(self.spec, "investigation-two", output, self.root)
        plan = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(plan["backend"], "docker.compose")

    def test_workspace_lifecycle_preserves_selected_evidence(self):
        directory = lab.init_experiment("workspace-one", self.root)
        source = directory / "workspace" / "notes.txt"
        source.write_text("observed output\n", encoding="utf-8")
        manifest = lab.collect_evidence("workspace-one", [source], self.root)
        self.assertTrue(manifest.exists())
        lab.stop_experiment("workspace-one", self.root)
        lab.reset_experiment("workspace-one", self.root)
        lab.destroy_experiment("workspace-one", self.root)
        preserved = self.root / "evidence-staging" / "experiments" / "workspace-one"
        self.assertTrue((preserved / "notes.txt").exists())

    def test_tool_execution_is_bounded_and_records_output(self):
        lab.init_experiment("tool-one", self.root)

        class Result:
            returncode = 0
            stdout = "tool output\n"
            stderr = ""

        with patch("lab.workspace.subprocess.run", return_value=Result()) as runner:
            record = lab.execute_tool("tool-one", "approved/tool:1", ["sh", "-c", "echo tool"], self.root)
        command = runner.call_args.args[0]
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("--cap-drop", command)
        self.assertNotIn("--privileged", command)
        self.assertIn("tool output", record.read_text(encoding="utf-8"))

    def test_malformed_compose_network_fails_with_lab_error(self):
        compose = self.root / "compose" / "research.yaml"
        compose.write_text(compose.read_text(encoding="utf-8").replace(
            "  investigation:\n    internal: true", "  investigation: invalid"
        ), encoding="utf-8")
        with self.assertRaisesRegex(LabError, "must be a mapping"):
            lab.validate_investigation(self.spec, self.root)

    def test_ipv6_and_network_options_fail_closed(self):
        compose = self.root / "compose" / "research.yaml"
        original = compose.read_text(encoding="utf-8")
        for replacement, message in (
            ("    enable_ipv6: true\n", "conflicts with the selected deny policy"),
            ("    driver: overlay\n", "must use the bridge driver"),
            ("    name: shared-network\n", "unsupported options"),
        ):
            compose.write_text(original.replace("    internal: true\n", "    internal: true\n" + replacement),
                                encoding="utf-8")
            with self.assertRaisesRegex(LabError, message):
                lab.validate_investigation(self.spec, self.root)
        compose.write_text(original, encoding="utf-8")

    def test_network_boundary_is_applied_and_verified_before_start(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.dict("os.environ", {"REQUIRE_RUNTIME_APPROVAL": "true"}):
            plan = lab.construct_investigation(
                self.spec, "boundary-one", "reviewed", self.root, runner=runner
            )
        self.assertEqual(plan["status"], "constructed")
        actions = [command[2] for command in calls if command[:2] == ["bash", str(self.root / "scripts" / "network-boundary.sh")]]
        self.assertEqual(actions, ["apply", "verify"])
        create_index = next(index for index, command in enumerate(calls) if "create" in command)
        apply_index = next(index for index, command in enumerate(calls) if command[2:4] == ["apply", "sec-lab-i-boundary-one"])
        start_index = next(index for index, command in enumerate(calls) if command[-1:] == ["start"])
        self.assertLess(create_index, apply_index)
        self.assertLess(apply_index, start_index)

    def test_services_do_not_start_when_boundary_verification_fails(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if command[:2] == ["bash", str(self.root / "scripts" / "network-boundary.sh")] and command[2] == "verify":
                return SimpleNamespace(returncode=1, stdout="", stderr="rule missing")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.dict("os.environ", {"REQUIRE_RUNTIME_APPROVAL": "true"}):
            with self.assertRaisesRegex(LabError, "network-boundary verify failed"):
                lab.construct_investigation(
                    self.spec, "boundary-two", "reviewed", self.root, runner=runner
                )
        self.assertFalse(any(command[-1:] == ["start"] for command in calls))

    def test_malformed_open_section_fails_with_lab_error(self):
        document = yaml.safe_load(self.spec.read_text(encoding="utf-8"))
        document["observations"] = [{"unexpected": "list"}]
        self.spec.write_text(yaml.safe_dump(document), encoding="utf-8")
        with self.assertRaisesRegex(LabError, "observations must be a mapping"):
            lab.validate_investigation(self.spec, self.root)

    def test_construction_requires_global_runtime_approval(self):
        with patch.dict("os.environ", {"REQUIRE_RUNTIME_APPROVAL": "false"}):
            with self.assertRaisesRegex(LabError, "REQUIRE_RUNTIME_APPROVAL=true"):
                lab.construct_investigation(
                    self.spec, "investigation-one", "reviewed", self.root,
                    runner=lambda *args, **kwargs: None,
                )

    def test_archive_verifies_file_digests_after_copy(self):
        source = self.root / "evidence-staging" / "run-one"
        destination = self.root / "archives"
        source.mkdir(parents=True)
        destination.mkdir()
        (source / "result.txt").write_text("observed\n", encoding="utf-8")
        manifest = archive_evidence(source, destination, self.root)
        self.assertTrue(manifest.is_file())
        copied = destination / "run-one" / "result.txt"
        self.assertEqual(copied.read_text(encoding="utf-8"), "observed\n")
