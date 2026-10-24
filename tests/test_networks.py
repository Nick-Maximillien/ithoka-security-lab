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
    validate_machine_configuration,
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

    def test_machine_configuration_and_plan_are_explicit(self):
        config = validate_machine_configuration(self.root)
        self.assertEqual(config["operator_confirmed"]["approved_docker_context"], "default")
        plan = build_enforcement_plan(self.root, "isolated", config)
        self.assertTrue(plan["supported"])
        self.assertEqual(plan["apply_order"][-1], "verify")
        self.assertTrue(plan["read_only"])

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
