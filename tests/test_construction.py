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
from lab.networks import policy_json, resolve_network_policy


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
                    "network_policy": {
                        "profile": "isolated",
                        "overrides": {
                            "windows_host": {"enabled": False},
                            "dns": {"enabled": False},
                            "proxies": {"enabled": False},
                        },
                    },
                },
                "resources": [],
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
        material_id = "alpine-runtime"
        image = "alpine:3.20"
        catalog_path = self.root / "lab" / "catalog" / "materials.yaml"
        catalog_path.write_text(yaml.safe_dump({
            "schema_version": 1,
            "materials": [{
                "id": material_id,
                "revision": "3.20.0",
                "kind": "container-image",
                "availability": "available",
                "image": image,
                "source": "operator-approved local image",
            }],
        }), encoding="utf-8")
        specification = yaml.safe_load(self.spec.read_text(encoding="utf-8"))
        specification["resources"] = [{
            "id": "runtime-image",
            "kind": "container-image",
            "material_id": material_id,
        }]
        self.spec.write_text(
            yaml.safe_dump(specification, sort_keys=False),
            encoding="utf-8",
        )
        plan = lab.build_construction_plan(self.spec, "investigation-one", self.root)
        self.assertEqual(plan["ownership"]["investigation"], "investigation-one")
        self.assertEqual(plan["resources"][0]["status"], "approved-material")
        self.assertEqual(plan["resources"][0]["material_id"], material_id)
        self.assertEqual(len(plan["specification_sha256"]), 64)
        self.assertFalse(plan["network_policy_supported"])
        self.assertIn(
            "external_networks=runtime-acceptance-unavailable",
            plan["network_policy_capability_error"],
        )

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

        (self.root / "lab" / "catalog" / "materials.yaml").write_text(
            yaml.safe_dump({
                "schema_version": 1,
                "materials": [{
                    "id": "approved-tool",
                    "revision": "1.0.0",
                    "kind": "container-image",
                    "availability": "available",
                    "image": "approved/tool:1",
                    "source": "unit test fixture",
                }],
            }),
            encoding="utf-8",
        )
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

    def test_host_mounts_docker_socket_privilege_and_capabilities_are_rejected(self):
        compose = self.root / "compose" / "research.yaml"
        original = yaml.safe_load(compose.read_text(encoding="utf-8"))
        unsafe_services = (
            ({"volumes": ["/tmp:/host"]}, "forbidden Compose options: volumes"),
            (
                {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]},
                "forbidden Compose options: volumes",
            ),
            ({"privileged": True}, "forbidden Compose options: privileged"),
            ({"cap_add": ["NET_ADMIN"]}, "forbidden Compose options: cap_add"),
        )
        for unsafe, message in unsafe_services:
            with self.subTest(unsafe=unsafe):
                document = yaml.safe_load(yaml.safe_dump(original))
                document["services"]["target"].update(unsafe)
                compose.write_text(yaml.safe_dump(document), encoding="utf-8")
                with self.assertRaisesRegex(LabError, message):
                    lab.validate_investigation(self.spec, self.root)
        compose.write_text(yaml.safe_dump(original), encoding="utf-8")

    def test_network_boundary_is_applied_and_verified_before_start(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            patch.dict("os.environ", {"REQUIRE_RUNTIME_APPROVAL": "true"}),
            patch("lab.construction.validate_runtime_support"),
        ):
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
        pinned = self.root / "state" / "runtime" / "sec-lab-i-boundary-one-network-policy.json"
        self.assertTrue(pinned.is_file())
        self.assertEqual(json.loads(pinned.read_text(encoding="utf-8"))["profile"], "isolated")

    def test_boundary_adapter_scopes_rules_and_saves_cleanup_identity_first(self):
        script = (self.root / "scripts" / "network-boundary.sh").read_text(
            encoding="utf-8"
        )
        apply_block = script.split("    apply)\n", 1)[1].split("    verify)\n", 1)[0]

        self.assertIn('--filter "label=com.docker.compose.project=$PROJECT"', script)
        self.assertIn('ensure_jump iptables FORWARD "$CHAIN4"', script)
        self.assertIn('ensure_jump ip6tables FORWARD "$CHAIN6"', script)
        self.assertIn('ensure_external_jump iptables "$EXT_CHAIN4"', script)
        self.assertIn('ensure_external_jump ip6tables "$EXT_CHAIN6"', script)
        self.assertIn('ensure_owned_chain iptables "$CHAIN4"', script)
        self.assertIn('ensure_owned_chain ip6tables "$CHAIN6"', script)
        self.assertLess(apply_block.index("printf 'PROJECT="), apply_block.index("apply_rules"))
        self.assertLess(apply_block.index("apply_rules"), apply_block.index("verify_rules"))
        self.assertNotIn("iptables -F", script)
        self.assertNotIn("ip6tables -F", script)
        self.assertNotIn("docker network create", script)

    def test_services_do_not_start_when_boundary_verification_fails(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if command[:2] == ["bash", str(self.root / "scripts" / "network-boundary.sh")] and command[2] == "verify":
                return SimpleNamespace(returncode=1, stdout="", stderr="rule missing")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            patch.dict("os.environ", {"REQUIRE_RUNTIME_APPROVAL": "true"}),
            patch("lab.construction.validate_runtime_support"),
        ):
            with self.assertRaisesRegex(LabError, "network-boundary verify failed"):
                lab.construct_investigation(
                    self.spec, "boundary-two", "reviewed", self.root, runner=runner
                )
        self.assertFalse(any(command[-1:] == ["start"] for command in calls))

    def test_services_do_not_start_when_boundary_application_fails(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if command[:2] == ["bash", str(self.root / "scripts" / "network-boundary.sh")] and command[2] == "apply":
                return SimpleNamespace(returncode=1, stdout="", stderr="unsupported policy")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            patch.dict("os.environ", {"REQUIRE_RUNTIME_APPROVAL": "true"}),
            patch("lab.construction.validate_runtime_support"),
        ):
            with self.assertRaisesRegex(LabError, "network-boundary apply failed"):
                lab.construct_investigation(
                    self.spec, "boundary-apply-failure", "reviewed", self.root, runner=runner
                )
        self.assertFalse(any(command[-1:] == ["start"] for command in calls))

    def test_unsupported_required_boundary_fails_before_compose_creation(self):
        document = yaml.safe_load(self.spec.read_text(encoding="utf-8"))
        document["apparatus"]["network_policy"]["overrides"]["windows_host"]["enabled"] = True
        self.spec.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        plan = lab.build_construction_plan(self.spec, "unsupported-boundary", self.root)
        self.assertFalse(plan["network_policy_supported"])
        self.assertIn("windows_host=windows-firewall-required", plan["network_policy_capability_error"])
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.dict("os.environ", {"REQUIRE_RUNTIME_APPROVAL": "true"}):
            with self.assertRaisesRegex(LabError, "windows_host=windows-firewall-required"):
                lab.construct_investigation(
                    self.spec, "unsupported-boundary", "reviewed", self.root, runner=runner
                )
        self.assertFalse(any("create" in command for command in calls))
        self.assertFalse(any(command[-1:] == ["start"] for command in calls))

    def test_disposal_refuses_project_resources_with_mismatched_ownership(self):
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if command[:3] == ["docker", "ps", "-aq"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[:4] == ["docker", "network", "ls", "-q"]:
                return SimpleNamespace(returncode=0, stdout="network-id\n", stderr="")
            if command[:3] == ["docker", "network", "inspect"]:
                return SimpleNamespace(returncode=0, stdout="security-lab|another-study", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with self.assertRaisesRegex(LabError, "not verified as owned"):
            lab.dispose_investigation(
                self.spec, "disposal-owner-check", self.root, runner=runner
            )
        self.assertFalse(any("down" in command for command in calls))
        self.assertFalse(any("network-boundary.sh" in " ".join(command) for command in calls))

    def test_disposal_removes_pinned_policy_only_after_owned_cleanup(self):
        project = "sec-lab-i-disposal-owner-check"
        pinned = self.root / "state" / "runtime" / f"{project}-network-policy.json"
        pinned.parent.mkdir(parents=True, exist_ok=True)
        pinned.write_text(
            policy_json(resolve_network_policy(self.root, "isolated", {
                "windows_host": {"enabled": False},
                "dns": {"enabled": False},
                "proxies": {"enabled": False},
            })),
            encoding="utf-8",
        )
        calls = []

        def runner(command, **kwargs):
            calls.append(command)
            if command[:3] == ["docker", "ps", "-aq"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[:4] == ["docker", "network", "ls", "-q"]:
                return SimpleNamespace(returncode=0, stdout="network-id\n", stderr="")
            if command[:3] == ["docker", "network", "inspect"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout="security-lab|disposal-owner-check",
                    stderr="",
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        lab.dispose_investigation(
            self.spec, "disposal-owner-check", self.root, runner=runner
        )
        self.assertFalse(pinned.exists())
        self.assertTrue(any(command[-2:] == ["down", "--remove-orphans"] for command in calls))

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
