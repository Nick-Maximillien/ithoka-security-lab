import json
import hashlib
import platform
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lab.enforcement import (
    DockerAdapter,
    EnforcementCoordinator,
    EnforcementResult,
    EnforcementScope,
    EnforcementStatus,
    LinuxWslAdapter,
    WindowsHostAdapter,
)
from lab.foundation import LabError
from lab.osapi.models import OSObservation


PROJECT = "sec-lab-i-study"


class EnforcementContractTests(unittest.TestCase):
    @staticmethod
    def _local_docker_daemon():
        return OSObservation(
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
                "daemon": {"Name": platform.node(), "OSType": "linux"},
            },
        )

    def _firewall_observation(self, present=True):
        suffix = hashlib.sha256(PROJECT.encode("utf-8")).hexdigest()[:10]
        if present:
            values = {
                "ipv4": {
                    "chains": [
                        {"table": "filter", "name": f"SLB{suffix}4"},
                        {"table": "filter", "name": f"SLX{suffix}E4"},
                    ],
                    "rules": [
                        {"table": "filter", "source_chain": "INPUT",
                         "jump_target": f"SLB{suffix}4"},
                        {"table": "filter", "source_chain": "OUTPUT",
                         "jump_target": f"SLB{suffix}4"},
                        {"table": "filter", "source_chain": "FORWARD",
                         "jump_target": f"SLX{suffix}E4"},
                        {"table": "filter", "source_chain": "FORWARD",
                         "jump_target": f"SLB{suffix}4"},
                    ],
                },
                "ipv6": {
                    "chains": [
                        {"table": "filter", "name": f"SLB{suffix}6"},
                        {"table": "filter", "name": f"SLX{suffix}E6"},
                    ],
                    "rules": [
                        {"table": "filter", "source_chain": "INPUT",
                         "jump_target": f"SLB{suffix}6"},
                        {"table": "filter", "source_chain": "OUTPUT",
                         "jump_target": f"SLB{suffix}6"},
                        {"table": "filter", "source_chain": "FORWARD",
                         "jump_target": f"SLX{suffix}E6"},
                        {"table": "filter", "source_chain": "FORWARD",
                         "jump_target": f"SLB{suffix}6"},
                    ],
                },
            }
        else:
            values = {
                "ipv4": {"chains": [], "rules": []},
                "ipv6": {"chains": [], "rules": []},
            }
        return OSObservation(
            platform="linux",
            subsystem="firewall",
            operation="inspect",
            target="kernel firewall",
            source="iptables-save/ip6tables-save",
            observed_utc="2026-01-01T00:00:00+00:00",
            status=EnforcementStatus.PASS,
            values=values,
            parsed=True,
        )

    def test_docker_adapter_preserves_inspection_result_in_typed_contract(self):
        report = {
            "status": "PASS",
            "project": PROJECT,
            "read_only": True,
            "reason": "effective settings passed",
            "findings": [{"control": "network", "status": "PASS"}],
            "active_context": "default",
        }
        with patch("lab.networks.inspect_docker_project", return_value=report):
            result = DockerAdapter(Path(".")).inspect(PROJECT)

        self.assertIs(result.status, EnforcementStatus.PASS)
        self.assertEqual(result.scope.project, PROJECT)
        self.assertTrue(result.read_only)
        self.assertEqual(result.to_dict()["active_context"], "default")

    def test_coordinator_fails_closed_for_non_pass_mandatory_results(self):
        blocked = EnforcementResult(
            operation="verify",
            status=EnforcementStatus.UNKNOWN,
            scope=EnforcementScope("linux-wsl", "network-boundary"),
            read_only=True,
            reason="inspection unavailable",
        )
        with self.assertRaisesRegex(LabError, "UNKNOWN"):
            EnforcementCoordinator.require_pass([blocked], "startup")

    def test_linux_adapter_requires_approval_before_invoking_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = unittest.mock.Mock()
            adapter = LinuxWslAdapter(root, runner=runner)

            result = adapter.apply(
                PROJECT,
                root / "policy.json",
                approval_reference=None,
            )

        self.assertIs(result.status, EnforcementStatus.BLOCKED)
        runner.assert_not_called()

    def test_linux_apply_blocks_if_initial_kernel_rules_cannot_be_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "scripts" / "network-boundary.sh"
            script.parent.mkdir()
            script.write_text("# test fixture\n", encoding="utf-8")
            policy = root / "policy.json"
            policy.write_text("{}", encoding="utf-8")
            runner = unittest.mock.Mock()
            unreadable = OSObservation(
                platform="linux",
                subsystem="firewall",
                operation="inspect",
                target="kernel firewall",
                source="iptables-save",
                observed_utc="now",
                status=EnforcementStatus.UNKNOWN,
                errors=("permission denied",),
            )
            with patch(
                "lab.enforcement.linux.inspect_firewall",
                return_value=unreadable,
            ):
                result = LinuxWslAdapter(root, runner=runner).apply(
                    PROJECT,
                    policy,
                    approval_reference="approved",
                )

        self.assertIs(result.status, EnforcementStatus.UNKNOWN)
        runner.assert_not_called()

    def test_linux_apply_requires_separate_effective_state_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "scripts" / "network-boundary.sh"
            script.parent.mkdir()
            script.write_text("# test fixture\n", encoding="utf-8")
            policy = root / "policy.json"
            policy.write_text("{}", encoding="utf-8")
            calls = []

            def runner(command, **kwargs):
                calls.append((command, kwargs))
                return SimpleNamespace(returncode=0, stdout="verified", stderr="")

            with (
                patch(
                    "lab.osapi.actions.inspect_daemon",
                    return_value=self._local_docker_daemon(),
                ),
                patch(
                    "lab.enforcement.linux.inspect_firewall",
                    side_effect=[
                        self._firewall_observation(present=False),
                        self._firewall_observation(),
                        self._firewall_observation(),
                    ],
                ),
            ):
                result = LinuxWslAdapter(root, runner=runner).apply(
                    PROJECT,
                    policy,
                    approval_reference="approved change ticket",
                )

        self.assertIs(result.status, EnforcementStatus.PASS)
        self.assertEqual(
            [call[0][2] for call in calls if call[0][0] == "bash"],
            ["apply", "verify"],
        )
        self.assertTrue(all(call[1]["shell"] is False for call in calls))
        self.assertIn("approved change ticket", json.dumps(result.to_dict()))

    def test_linux_apply_failure_attempts_scoped_restoration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "scripts" / "network-boundary.sh"
            script.parent.mkdir()
            script.write_text("# test fixture\n", encoding="utf-8")
            policy = root / "policy.json"
            policy.write_text("{}", encoding="utf-8")
            responses = iter(
                (
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                    SimpleNamespace(returncode=1, stdout="", stderr="verify failed"),
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                )
            )
            calls = []

            def runner(command, **_kwargs):
                calls.append(command)
                return next(responses)

            with (
                patch(
                    "lab.osapi.actions.inspect_daemon",
                    return_value=self._local_docker_daemon(),
                ),
                patch(
                    "lab.enforcement.linux.inspect_firewall",
                    side_effect=[
                        self._firewall_observation(present=False),
                        self._firewall_observation(),
                        self._firewall_observation(),
                        self._firewall_observation(present=False),
                    ],
                ),
            ):
                result = LinuxWslAdapter(root, runner=runner).apply(
                    PROJECT,
                    policy,
                    approval_reference="approved change ticket",
                )

        self.assertIs(result.status, EnforcementStatus.FAIL)
        self.assertEqual(
            [command[2] for command in calls if command[0] == "bash"],
            ["apply", "verify", "remove"],
        )
        self.assertEqual(
            result.details["containment_restoration"]["status"],
            EnforcementStatus.PASS.value,
        )

    def test_linux_adapter_rejects_policy_outside_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            outside = Path(directory) / "policy.json"
            outside.write_text("{}", encoding="utf-8")
            result = LinuxWslAdapter(root).verify(PROJECT, outside)

        self.assertIs(result.status, EnforcementStatus.BLOCKED)

    def test_windows_inspection_is_observation_not_enforcement(self):
        runner = lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"Profiles": [], "Interfaces": []}),
            stderr="",
        )
        with patch("lab.osapi.command.shutil.which", return_value="/fake/pwsh"):
            result = WindowsHostAdapter(
                runner=runner,
                executable="/fake/pwsh",
            ).inspect()

        self.assertIs(result.status, EnforcementStatus.UNKNOWN)
        self.assertTrue(result.read_only)
        self.assertIs(
            WindowsHostAdapter(
                runner=runner,
                executable="powershell.exe",
            ).verify().status,
            EnforcementStatus.UNKNOWN,
        )
        self.assertIs(
            WindowsHostAdapter().apply().status,
            EnforcementStatus.BLOCKED,
        )


if __name__ == "__main__":
    unittest.main()
