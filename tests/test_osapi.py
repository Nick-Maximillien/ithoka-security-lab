import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lab.enforcement.models import EnforcementStatus
from lab.osapi.command import parse_json_execution, run_command
from lab.osapi.docker.containers import inspect_containers
from lab.osapi.linux.firewall import inspect_firewall, verify_rule_presence
from lab.osapi.linux.interfaces import inspect_interfaces
from lab.osapi.linux.routes import inspect_routes
from lab.osapi.linux.sockets import inspect_sockets
from lab.osapi.models import CommandExecution
from lab.osapi.windows._powershell import inspect_powershell


class OSAPICommandTests(unittest.TestCase):
    def test_executes_argv_without_shell_and_records_nonzero_stderr(self):
        captured = {}

        def runner(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return SimpleNamespace(returncode=7, stdout="", stderr="denied")

        with patch("lab.osapi.command.shutil.which", return_value="/bin/tool"):
            result = run_command(["tool", "arg"], runner=runner)

        self.assertEqual(result.status, EnforcementStatus.FAIL)
        self.assertEqual(result.stderr, "denied")
        self.assertEqual(result.reason, "command returned exit status 7")
        self.assertIs(captured["kwargs"]["shell"], False)
        self.assertEqual(captured["argv"], ["tool", "arg"])
        self.assertNotIn("denied", json.dumps(result.to_dict()))

    def test_missing_executable_is_unknown_without_invoking_runner(self):
        runner = unittest.mock.Mock()
        with patch("lab.osapi.command.shutil.which", return_value=None):
            result = run_command(["not-installed-osapi-tool"], runner=runner)

        self.assertEqual(result.status, EnforcementStatus.UNKNOWN)
        runner.assert_not_called()

    def test_timeout_is_reported(self):
        def runner(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(["tool"], 1, output="partial")

        with patch("lab.osapi.command.shutil.which", return_value="/bin/tool"):
            result = run_command(["tool"], runner=runner, timeout=1)

        self.assertEqual(result.status, EnforcementStatus.UNKNOWN)
        self.assertIn("timed out", result.reason)
        self.assertEqual(result.stdout, "partial")

    def test_malformed_json_is_not_treated_as_successful_parse(self):
        command = CommandExecution(
            command=("tool",),
            executable="tool",
            started_utc="now",
            finished_utc="now",
            returncode=0,
            stdout="{broken",
            stderr="",
            status=EnforcementStatus.PASS,
        )
        value, error = parse_json_execution(command)

        self.assertIsNone(value)
        self.assertIn("malformed JSON", error)


class LinuxOSAPITests(unittest.TestCase):
    def test_interface_json_is_parsed_into_address_state(self):
        payload = [{
            "ifname": "eth0",
            "ifindex": 2,
            "operstate": "UP",
            "link_type": "ether",
            "addr_info": [{
                "family": "inet6",
                "local": "2001:db8::1",
                "prefixlen": 64,
                "scope": "global",
            }],
        }]

        with (
            patch("lab.osapi.command.shutil.which", return_value="/sbin/ip"),
            patch(
                "lab.osapi.linux.interfaces.run_command",
                return_value=SimpleNamespace(
                    status=EnforcementStatus.PASS,
                    stdout=json.dumps(payload),
                    stderr="",
                    reason=None,
                    finished_utc="now",
                    to_dict=lambda: {},
                ),
            ),
        ):
            result = inspect_interfaces()

        self.assertEqual(result.status, EnforcementStatus.PASS)
        self.assertEqual(result.values[0]["addresses"][0]["family"], "inet6")

    def test_ipv4_route_success_ipv6_failure_is_unknown_not_empty_pass(self):
        executions = iter([
            SimpleNamespace(
                status=EnforcementStatus.PASS,
                stdout='[{"dst":"default","dev":"eth0"}]',
                stderr="",
                reason=None,
                finished_utc="v4",
                to_dict=lambda: {"finished_utc": "v4"},
            ),
            SimpleNamespace(
                status=EnforcementStatus.UNKNOWN,
                stdout="",
                stderr="",
                reason="ip6 command unavailable",
                finished_utc="v6",
                to_dict=lambda: {"finished_utc": "v6"},
            ),
        ])
        with patch("lab.osapi.linux.routes.run_command", side_effect=lambda *_a, **_k: next(executions)):
            result = inspect_routes()

        self.assertEqual(result.status, EnforcementStatus.UNKNOWN)
        self.assertIn("ipv4", result.values)
        self.assertNotIn("ipv6", result.values)

    def test_firewall_requires_both_ipv4_and_ipv6_observations(self):
        executions = iter([
            SimpleNamespace(status=EnforcementStatus.PASS, returncode=0,
                            executable="iptables-save",
                            stdout="*filter\nCOMMIT\n",
                            finished_utc="v4", to_dict=lambda: {}),
            SimpleNamespace(status=EnforcementStatus.UNKNOWN, returncode=None,
                            executable="ip6tables-save", stdout="",
                            reason="permission denied", finished_utc="v6",
                            to_dict=lambda: {}),
            SimpleNamespace(status=EnforcementStatus.UNKNOWN, returncode=None,
                            executable="nft", stdout="",
                            reason="missing nft", finished_utc="nft",
                            to_dict=lambda: {}),
        ])
        with patch("lab.osapi.linux.firewall.run_command", side_effect=lambda *_a, **_k: next(executions)):
            result = inspect_firewall()

        self.assertEqual(result.status, EnforcementStatus.UNKNOWN)
        self.assertIn("ipv4", result.values)
        self.assertNotIn("ipv6", result.values)

    def test_firewall_uses_noninteractive_privilege_only_after_permission_denial(self):
        executions = iter([
            SimpleNamespace(
                status=EnforcementStatus.FAIL,
                returncode=1,
                stderr="permission denied",
                stdout="",
                finished_utc="denied",
                reason="command returned exit status 1",
                to_dict=lambda: {},
            ),
            SimpleNamespace(
                status=EnforcementStatus.PASS,
                returncode=0,
                executable="iptables-save",
                stdout="*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
                stderr="",
                reason=None,
                finished_utc="sudo",
                to_dict=lambda: {},
            ),
            SimpleNamespace(
                status=EnforcementStatus.PASS,
                returncode=0,
                executable="ip6tables-save",
                stdout="*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
                stderr="",
                reason=None,
                finished_utc="v6",
                to_dict=lambda: {},
            ),
            SimpleNamespace(
                status=EnforcementStatus.UNKNOWN,
                returncode=None,
                executable="nft",
                stdout="",
                stderr="",
                reason="unavailable",
                finished_utc="nft",
                to_dict=lambda: {},
            ),
        ])
        commands = []

        def command(argv, **_kwargs):
            commands.append(argv)
            return next(executions)

        with patch("lab.osapi.linux.firewall.run_command", side_effect=command):
            result = inspect_firewall()

        self.assertEqual(result.status, EnforcementStatus.PASS)
        self.assertEqual(commands[0], ["iptables-save", "-c"])
        self.assertEqual(commands[1], ["sudo", "-n", "iptables-save", "-c"])

    def test_firewall_inspection_parses_chain_order_and_jump_target(self):
        executions = iter([
            SimpleNamespace(
                status=EnforcementStatus.PASS,
                returncode=0,
                executable="iptables-save",
                stdout=(
                    "*filter\n"
                    ":INPUT ACCEPT [4:50]\n"
                    ":LAB-CHAIN - [2:20]\n"
                    "[2:20] -A INPUT -j LAB-CHAIN\n"
                    "[1:10] -A LAB-CHAIN -o eth0 -j DROP\n"
                    "COMMIT\n"
                ),
                reason=None,
                finished_utc="v4",
                to_dict=lambda: {},
            ),
            SimpleNamespace(
                status=EnforcementStatus.PASS,
                returncode=0,
                executable="ip6tables-save",
                stdout="*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
                reason=None,
                finished_utc="v6",
                to_dict=lambda: {},
            ),
            SimpleNamespace(
                status=EnforcementStatus.UNKNOWN,
                returncode=None,
                executable="nft",
                stdout="",
                reason="not installed",
                finished_utc="nft",
                to_dict=lambda: {},
            ),
        ])
        with patch(
            "lab.osapi.linux.firewall.run_command",
            side_effect=lambda *_a, **_k: next(executions),
        ):
            result = inspect_firewall()

        self.assertEqual(result.status, EnforcementStatus.PASS)
        finding = verify_rule_presence(
            result,
            family="ipv4",
            chain="INPUT",
            expected="-j LAB-CHAIN",
        )
        self.assertEqual(finding.status, EnforcementStatus.PASS)
        self.assertEqual(result.values["ipv4"]["rules"][0]["jump_target"], "LAB-CHAIN")
        self.assertEqual(result.values["ipv4"]["rules"][1]["ordinal"], 2)

    def test_socket_command_error_is_not_interpreted_as_no_listeners(self):
        failure = SimpleNamespace(
            status=EnforcementStatus.BLOCKED,
            reason="permission denied",
            finished_utc="now",
            to_dict=lambda: {},
        )
        with patch("lab.osapi.linux.sockets.run_command", return_value=failure):
            result = inspect_sockets()

        self.assertEqual(result.status, EnforcementStatus.UNKNOWN)
        self.assertIsNone(result.values)
        self.assertIn("permission denied", result.errors[0])


class DockerOSAPITests(unittest.TestCase):
    def test_project_containers_use_daemon_inspect_and_redact_environment(self):
        raw = [{
            "Id": "a" * 64,
            "Name": "/service",
            "Image": "sha256:" + "b" * 64,
            "Config": {
                "Labels": {"com.docker.compose.project": "sec-lab-i-test"},
                "Env": ["SECRET_TOKEN=not-for-report"],
            },
            "HostConfig": {"NetworkMode": "lab", "PortBindings": {}},
            "State": {"Status": "running", "Running": True},
            "NetworkSettings": {"Networks": {"lab": {}}, "Ports": {}},
            "Mounts": [],
        }]

        def runner(argv, **_kwargs):
            if "ps" in argv:
                return SimpleNamespace(returncode=0, stdout="a" * 64, stderr="")
            if "inspect" in argv:
                return SimpleNamespace(returncode=0, stdout=json.dumps(raw), stderr="")
            raise AssertionError(argv)

        with patch("lab.osapi.command.shutil.which", return_value="/usr/bin/docker"):
            from lab.osapi.docker.containers import inspect_containers
            result = inspect_containers("sec-lab-i-test", "default", runner)

        self.assertEqual(result.status, EnforcementStatus.PASS)
        self.assertEqual(result.values[0]["state"], "running")
        self.assertNotIn("SECRET_TOKEN", json.dumps(result.to_dict()))

    def test_invalid_project_name_is_blocked_before_docker(self):
        runner = unittest.mock.Mock()
        result = inspect_containers("../other", "default", runner)

        self.assertEqual(result.status, EnforcementStatus.BLOCKED)
        runner.assert_not_called()


class WindowsOSAPITests(unittest.TestCase):
    def test_single_object_json_is_normalized_and_unknown_for_observation_only(self):
        runner = lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"Enabled":true}',
            stderr="",
        )
        with patch("lab.osapi.command.shutil.which", return_value="/fake/pwsh"):
            result = inspect_powershell(
                "firewall",
                "Get-NetFirewallProfile",
                runner=runner,
                executable="/fake/pwsh",
            )

        self.assertEqual(result.status, EnforcementStatus.PASS)
        self.assertEqual(result.values, [{"Enabled": True}])

    def test_malformed_powershell_output_is_unknown(self):
        runner = lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="not-json",
            stderr="",
        )
        with patch("lab.osapi.command.shutil.which", return_value="/fake/pwsh"):
            result = inspect_powershell(
                "interfaces",
                "Get-NetIPInterface",
                runner=runner,
                executable="/fake/pwsh",
            )

        self.assertEqual(result.status, EnforcementStatus.UNKNOWN)
        self.assertFalse(result.parsed)


if __name__ == "__main__":
    unittest.main()
