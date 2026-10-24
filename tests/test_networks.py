import json
import shutil
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from lab.foundation import LabError
from lab.networks import (
    BOUNDARIES,
    list_network_profiles,
    resolve_network_policy,
    build_enforcement_plan,
    configure_machine,
    discover_network_inventory,
    inspect_owned_network,
    network_capabilities,
    resolve_project_network_policy,
    validate_firewall_chain_priority,
    validate_machine_configuration,
    validate_network_setup,
    validate_network_configuration,
    validate_runtime_support,
)


ROOT = Path(__file__).resolve().parents[1]


class NetworkPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        shutil.copytree(ROOT / "config", self.root / "config")
        shutil.copy(
            self.root / "config" / "networks" / "machine.yaml.example",
            self.root / "config" / "networks" / "machine.yaml",
        )
        machine = (self.root / "config" / "networks" / "machine.yaml").read_text()
        (self.root / "config" / "networks" / "machine.yaml").write_text(
            machine.replace("REPLACE_WITH_CONFIRMED_CONTEXT", "default"),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_profiles_resolve_independently(self):
        isolated = resolve_network_policy(self.root, "isolated")
        controlled = resolve_network_policy(self.root, "controlled-access")
        self.assertEqual(isolated["boundaries"]["ipv4"]["mode"], "deny")
        self.assertEqual(controlled["boundaries"]["ipv4"]["mode"], "restricted")
        self.assertEqual(isolated["boundaries"]["ipv6"]["mode"], "deny")
        self.assertEqual(controlled["boundaries"]["ipv6"]["mode"], "restricted")
        observation = resolve_network_policy(self.root, "observation")
        self.assertTrue(observation["boundaries"]["capture"]["enabled"])
        self.assertEqual(observation["boundaries"]["lab_ingress"]["mode"], "deny")

    def test_all_authoritative_boundary_files_and_profiles_validate(self):
        result = validate_network_configuration(self.root)
        self.assertEqual(result["boundaries"], list(BOUNDARIES))
        self.assertEqual(
            list_network_profiles(self.root),
            ["controlled-access", "isolated", "maintenance", "observation"],
        )

    def test_investigation_override_changes_effective_policy(self):
        policy = resolve_network_policy(self.root, "isolated", {
            "dns": {"mode": "restricted", "rules": [{
                "action": "allow", "protocol": "udp",
                "address": "192.0.2.53/32", "port": 53,
            }]}
        })
        self.assertEqual(policy["boundaries"]["dns"]["mode"], "restricted")
        self.assertEqual(policy["boundaries"]["dns"]["rules"][0]["port"], 53)
        self.assertEqual(policy["boundaries"]["ipv4"]["mode"], "deny")

    def test_invalid_policy_input_fails_closed(self):
        with self.assertRaisesRegex(LabError, "valid IP network"):
            resolve_network_policy(self.root, "isolated", {
                "dns": {"mode": "restricted", "rules": [{
                    "action": "allow", "address": "not-an-address",
                }]}
            })
        with self.assertRaisesRegex(LabError, "unsupported mode"):
            resolve_network_policy(self.root, "isolated", {
                "ipv4": {"mode": "permit"}
            })

    def test_active_profile_is_configuration(self):
        active = self.root / "config" / "networks" / "active-profile"
        active.write_text("controlled-access\n", encoding="utf-8")
        self.assertEqual(
            resolve_network_policy(self.root)["profile"], "controlled-access"
        )

    def test_editing_boundary_changes_effective_policy(self):
        boundary = self.root / "config" / "networks" / "boundaries" / "dns.yaml"
        text = boundary.read_text(encoding="utf-8").replace("mode: deny", "mode: restricted")
        boundary.write_text(text, encoding="utf-8")
        policy = resolve_network_policy(self.root, "isolated")
        self.assertEqual(policy["boundaries"]["dns"]["mode"], "restricted")

    def test_invalid_active_profile_fails_clearly(self):
        (self.root / "config" / "networks" / "active-profile").write_text(
            "not-a-profile\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(LabError, "does not exist"):
            resolve_network_policy(self.root)

    def test_controller_integrity_boundaries_cannot_be_disabled_by_policy(self):
        policy = resolve_network_policy(self.root, "isolated", {
            "filesystem": {"enabled": False},
        })
        with self.assertRaisesRegex(LabError, "controller-integrity"):
            validate_runtime_support(policy)

    def test_runtime_support_requires_both_deny_protocol_boundaries(self):
        for name in ("ipv4", "ipv6"):
            policy = resolve_network_policy(self.root, "isolated", {
                name: {"enabled": False},
            })
            with self.subTest(boundary=name):
                with self.assertRaisesRegex(LabError, f"{name}=required-deny"):
                    validate_runtime_support(policy)

    def test_runtime_support_rejects_unimplemented_custom_rules(self):
        policy = resolve_network_policy(self.root, "isolated", {
            "ipv4": {"rules": [{"action": "deny", "protocol": "tcp"}]},
        })
        with self.assertRaisesRegex(LabError, "ipv4=custom-rules"):
            validate_runtime_support(policy)

    def test_runtime_support_rejects_unimplemented_verification_requirements(self):
        policy = resolve_network_policy(self.root, "isolated", {
            "windows_host": {"enabled": False},
            "dns": {"enabled": False},
            "proxies": {"enabled": False},
            "external_networks": {"verification": ["forwarding_rules"]},
            "ipv4": {"verification": ["iptables", "manual_probe"]},
        })
        with self.assertRaisesRegex(LabError, "ipv4=unsupported-verification"):
            validate_runtime_support(policy)

    def test_runtime_support_rejects_windows_firewall_requirement(self):
        policy = resolve_network_policy(self.root, "isolated")
        with self.assertRaisesRegex(LabError, "windows_host=windows-firewall-required"):
            validate_runtime_support(policy)

    def test_runtime_support_rejects_unenforced_dns_and_proxy_boundaries(self):
        policy = resolve_network_policy(self.root, "isolated", {
            "windows_host": {"enabled": False},
        })
        with self.assertRaisesRegex(
            LabError,
            "dns=dedicated-enforcement-not-implemented.*proxies=dedicated-enforcement-not-implemented",
        ):
            validate_runtime_support(policy)

    def test_runtime_support_requires_live_external_acceptance_runner(self):
        policy = resolve_network_policy(self.root, "isolated", {
            "windows_host": {"enabled": False},
            "dns": {"enabled": False},
            "proxies": {"enabled": False},
        })
        with self.assertRaisesRegex(
            LabError, "external_networks=runtime-acceptance-unavailable"
        ):
            validate_runtime_support(policy)

    def test_capabilities_distinguish_enforcement_from_acceptance_and_limits(self):
        capabilities = network_capabilities()
        controls = capabilities["controls"]
        for name in ("ipv4", "ipv6", "lab_ingress", "lab_egress"):
            self.assertEqual(controls[name]["status"], "supported")
        for name in ("docker_networks", "filesystem", "resource_access"):
            self.assertEqual(controls[name]["status"], "supported")
        self.assertEqual(
            capabilities["enforcement_state"],
            "not-verified-until-project-apply-and-verify",
        )
        self.assertEqual(controls["external_networks"]["status"], "supported")
        self.assertEqual(controls["external_networks"]["acceptance"], "not-implemented")
        self.assertEqual(controls["external_networks"]["missing"], ["runtime_acceptance"])
        for name in ("windows_host", "dns", "proxies"):
            self.assertEqual(controls[name]["status"], "unsupported")
        self.assertEqual(capabilities["runtime_acceptance"], "not-run")

    def test_firewall_priority_accepts_owned_drops_and_rejects_conflicts(self):
        comments = ["ithoka-sec-lab-study-v4-input"]
        owned = (
            "-A INPUT -i br-study -m comment --comment "
            "ithoka-sec-lab-study-v4-input -j DROP"
        )
        validate_firewall_chain_priority("INPUT", owned, comments)
        with self.assertRaisesRegex(LabError, "unowned firewall rule precedes"):
            validate_firewall_chain_priority(
                "INPUT",
                "-A INPUT -i br-study -j ACCEPT\n" + owned,
                comments,
            )
        with self.assertRaisesRegex(LabError, "found 2"):
            validate_firewall_chain_priority(
                "INPUT", owned + "\n" + owned, comments
            )

    def test_firewall_owned_jump_must_precede_docker_and_other_host_rules(self):
        from lab.networks import (
            validate_firewall_jump_order,
            validate_firewall_jump_sequence,
        )

        jump = (
            "-A FORWARD -m comment --comment ithoka-sec-lab-study-v4-forward-jump "
            "-j SLB1234567894"
        )
        validate_firewall_jump_order(
            "FORWARD", jump, "SLB1234567894",
            "ithoka-sec-lab-study-v4-forward-jump",
        )
        with self.assertRaisesRegex(LabError, "not first"):
            validate_firewall_jump_order(
                "FORWARD",
                "-A FORWARD -j DOCKER-USER\n" + jump,
                "SLB1234567894",
                "ithoka-sec-lab-study-v4-forward-jump",
            )
        with self.assertRaisesRegex(LabError, "found 2"):
            validate_firewall_jump_order(
                "FORWARD", jump + "\n" + jump, "SLB1234567894",
                "ithoka-sec-lab-study-v4-forward-jump",
            )
        general = (
            "-A FORWARD -m comment --comment ithoka-sec-lab-study-v4-forward-jump "
            "-j SLB1234567894"
        )
        external = (
            "-A FORWARD -m comment --comment "
            "ithoka-sec-lab-study-external-v4-forward-jump -j SLX123456789E4"
        )
        expected_sequence = [
            ("SLX123456789E4", "ithoka-sec-lab-study-external-v4-forward-jump"),
            ("SLB1234567894", "ithoka-sec-lab-study-v4-forward-jump"),
        ]
        validate_firewall_jump_sequence(
            "FORWARD",
            external + "\n" + general,
            expected_sequence,
        )
        with self.assertRaisesRegex(LabError, "position 1"):
            validate_firewall_jump_sequence(
                "FORWARD", general + "\n" + external, expected_sequence
            )

    def test_runtime_support_rejects_capture_without_an_enforcement_adapter(self):
        policy = resolve_network_policy(self.root, "observation")
        with self.assertRaisesRegex(LabError, "capture=runtime-capture-not-implemented"):
            validate_runtime_support(policy)

    def test_machine_configuration_and_plan_are_explicit(self):
        config = validate_machine_configuration(self.root)
        self.assertEqual(config["operator_confirmed"]["approved_docker_context"], "default")
        plan = build_enforcement_plan(self.root, "isolated", config)
        self.assertFalse(plan["supported"])
        self.assertIn("windows_host=windows-firewall-required", plan["capability_error"])
        self.assertEqual(plan["apply_order"][-1], "verify")
        self.assertTrue(plan["read_only"])

    def test_machine_preflight_checks_context_defaults_and_root_firewall_reads(self):
        outputs = [
            "default",
            "bridge\nhost\nnone",
            "iptables v1.8.9 (legacy)",
            "",
            "ip6tables v1.8.9 (legacy)",
            "",
        ]
        commands = []

        def runner(command, **kwargs):
            commands.append(command)
            return type("Result", (), {
                "returncode": 0, "stdout": outputs.pop(0), "stderr": "",
            })()

        with (
            patch("lab.networks.shutil.which", return_value="/usr/bin/tool"),
            patch("lab.networks._run_inventory", return_value="default"),
        ):
            result = validate_network_setup(self.root, runner=runner)
        self.assertTrue(result["read_only"])
        self.assertEqual(result["scope"], "machine-prerequisites-only")
        self.assertTrue(result["ready"])
        self.assertEqual(result["policy_support"], "unsupported")
        self.assertIn("windows_host=windows-firewall-required", result["policy_capability_error"])
        self.assertEqual(result["firewall_backends"]["iptables"], "legacy")
        self.assertEqual(result["default_networks_observed"], ["bridge", "host", "none"])
        self.assertTrue(all(
            not any(token in command for token in ("-I", "-D", "-F", "create"))
            for command in commands
        ))

    def test_machine_preflight_fails_when_root_firewall_inspection_is_unavailable(self):
        def runner(command, **kwargs):
            if command[:3] == ["sudo", "-n", "iptables"]:
                return type("Result", (), {
                    "returncode": 1, "stdout": "", "stderr": "password required",
                })()
            return type("Result", (), {
                "returncode": 0,
                "stdout": "default" if command == ["docker", "context", "show"]
                else "bridge\nhost\nnone",
                "stderr": "",
            })()

        with (
            patch("lab.networks.shutil.which", return_value="/usr/bin/tool"),
            patch("lab.networks._run_inventory", return_value="default"),
        ):
            with self.assertRaisesRegex(LabError, "read privileged iptables version"):
                validate_network_setup(self.root, runner=runner)

    def test_discovery_is_read_only_and_reports_observations(self):
        inventory = discover_network_inventory()
        self.assertTrue(inventory["read_only"])
        self.assertIn("interfaces", inventory["observations"])
        self.assertIn("docker_context", inventory["availability"])

    def test_machine_configuration_can_be_created_without_confirming_values(self):
        destination = self.root / "config" / "networks" / "machine.yaml"
        destination.unlink()
        self.assertEqual(configure_machine(self.root), destination)
        self.assertIn("REPLACE_WITH_CONFIRMED_CONTEXT", destination.read_text())

    def test_machine_configuration_rejects_context_drift(self):
        config = self.root / "config" / "networks" / "machine.yaml"
        config.write_text(
            config.read_text(encoding="utf-8").replace("default", "wrong-context"),
            encoding="utf-8",
        )
        with patch("lab.networks._run_inventory", return_value="default"):
            with self.assertRaisesRegex(LabError, "does not match"):
                validate_machine_configuration(self.root)

    def test_owned_network_inspection_requires_constructed_network(self):
        empty = type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        with patch("lab.networks.subprocess.run", return_value=empty):
            with self.assertRaisesRegex(LabError, "found 0"):
                inspect_owned_network("sec-lab-i-local-study-01")

    def test_owned_network_inspection_rejects_ambiguous_projects(self):
        listing = type("Result", (), {
            "returncode": 0, "stdout": "network-one\nnetwork-two\n", "stderr": "",
        })()
        with patch("lab.networks.subprocess.run", return_value=listing) as runner:
            with self.assertRaisesRegex(LabError, "found 2"):
                inspect_owned_network("sec-lab-i-local-study-01")
        runner.assert_called_once()

    def test_owned_network_inspection_returns_docker_identity(self):
        network_id = "a" * 64
        listing = type("Result", (), {
            "returncode": 0, "stdout": f"{network_id}\n", "stderr": "",
        })()
        inspected = type("Result", (), {
            "returncode": 0,
            "stdout": json.dumps({
                "Name": "sec-lab-i-local-study-01_investigation",
                "Driver": "bridge",
                "Internal": True,
                "EnableIPv6": False,
                "Labels": {
                    "io.ithoka.security-lab.owner": "security-lab",
                    "io.ithoka.security-lab.investigation": "local-study-01",
                    "com.docker.compose.project": "sec-lab-i-local-study-01",
                },
                "IPAM": {"Config": [{"Subnet": "172.30.0.0/16"}]},
                "Containers": {},
                "Options": {"com.docker.network.bridge.name": "br-owned"},
            }),
            "stderr": "",
        })()
        with patch("lab.networks.subprocess.run", side_effect=[listing, inspected]):
            network = inspect_owned_network("sec-lab-i-local-study-01")
        self.assertEqual(network["network_id"], network_id)
        self.assertEqual(network["bridge"], "br-owned")

    def test_owned_network_inspection_resolves_bridge_from_ipam_gateway(self):
        network_id = "b" * 64
        listing = type("Result", (), {
            "returncode": 0, "stdout": f"{network_id}\n", "stderr": "",
        })()
        inspected = type("Result", (), {
            "returncode": 0,
            "stdout": json.dumps({
                "Name": "sec-lab-i-local-study-01_investigation",
                "Driver": "bridge",
                "Internal": True,
                "EnableIPv6": False,
                "Labels": {
                    "io.ithoka.security-lab.owner": "security-lab",
                    "io.ithoka.security-lab.investigation": "local-study-01",
                    "com.docker.compose.project": "sec-lab-i-local-study-01",
                },
                "IPAM": {"Config": [{
                    "Subnet": "172.30.0.0/16", "Gateway": "172.30.0.1",
                }]},
                "Containers": {},
                "Options": {},
            }),
            "stderr": "",
        })()
        interfaces = type("Result", (), {
            "returncode": 0,
            "stdout": json.dumps([{
                "ifname": "br-owned",
                "addr_info": [{"family": "inet", "local": "172.30.0.1"}],
            }]),
            "stderr": "",
        })()
        with patch(
            "lab.networks.subprocess.run",
            side_effect=[listing, inspected, interfaces],
        ) as runner:
            network = inspect_owned_network("sec-lab-i-local-study-01")
        self.assertEqual(network["bridge"], "br-owned")
        self.assertIn("--no-trunc", runner.call_args_list[0].args[0])

    def test_project_network_policy_uses_construction_pinned_overrides(self):
        policy = resolve_network_policy(self.root, "isolated", {
            "windows_host": {"enabled": False},
            "dns": {"enabled": False},
            "proxies": {"enabled": False},
        })
        pinned = self.root / "state" / "runtime" / "sec-lab-i-local-study-01-network-policy.json"
        pinned.parent.mkdir(parents=True)
        pinned.write_text(json.dumps(policy), encoding="utf-8")

        resolved = resolve_project_network_policy(
            self.root, "sec-lab-i-local-study-01", "isolated"
        )
        self.assertEqual(resolved, policy)
        with self.assertRaisesRegex(LabError, "does not match the project's pinned profile"):
            resolve_project_network_policy(
                self.root, "sec-lab-i-local-study-01", "maintenance"
            )
