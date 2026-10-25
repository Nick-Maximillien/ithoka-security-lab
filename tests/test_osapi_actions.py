import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lab.enforcement.models import EnforcementStatus
from lab.osapi.actions import (
    OSActionRequest,
    OSActionExecutor,
    OSActionStatus,
)
from lab.osapi.models import OSObservation


class OSActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        (self.root / "scripts" / "network-boundary.sh").write_text(
            "# test fixture\n",
            encoding="utf-8",
        )
        self.policy = self.root / "policy.json"
        self.policy.write_text("{}", encoding="utf-8")

    @staticmethod
    def _local_daemon(context=None, **_kwargs):
        return OSObservation(
            platform="docker",
            subsystem="daemon",
            operation="inspect",
            target=context or "local",
            source="test fixture",
            observed_utc="now",
            status=EnforcementStatus.PASS,
            values={
                "selected_context": context or "local",
                "endpoint": {"Host": "unix:///var/run/docker.sock"},
                "daemon": {"Name": "test-host", "OSType": "linux"},
            },
        )

    def _request(self, **overrides):
        values = {
            "platform": "linux",
            "operation": "network-boundary.apply",
            "target": "sec-lab-i-test",
            "repository_root": self.root,
            "policy_file": self.policy,
        }
        values.update(overrides)
        return OSActionRequest(**values)

    def _run(self, request, runner):
        with (
            patch(
                "lab.osapi.command.shutil.which",
                side_effect=lambda name: f"/usr/bin/{name}",
            ),
        ):
            return OSActionExecutor(
                runner=runner,
                daemon_inspector=self._local_daemon,
                host_system="Linux",
                host_release="6.1-generic",
                host_name="test-host",
            ).execute(
                request,
            )

    def test_linux_boundary_dispatch_uses_fixed_argv_and_noninteractive_privilege(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout="applied", stderr="")

        result = self._run(self._request(), runner)

        self.assertIs(result.status, OSActionStatus.SUCCEEDED)
        self.assertTrue(result.elevation_required)
        self.assertTrue(result.elevation_obtained)
        self.assertTrue(result.execution_started)
        self.assertEqual(result.native_executable, "bash")
        self.assertEqual(calls[0][0], ["/usr/bin/sudo", "-n", "-v"])
        self.assertEqual(
            calls[1][0],
            [
                "bash",
                str(self.root / "scripts" / "network-boundary.sh"),
                "apply",
                "sec-lab-i-test",
                str(self.policy),
            ],
        )
        self.assertFalse(calls[1][1]["shell"])
        self.assertEqual(result.to_dict()["returncode"], 0)

    def test_remote_docker_target_is_rejected_before_elevation_or_script_execution(self):
        remote = OSObservation(
            platform="docker",
            subsystem="daemon",
            operation="inspect",
            target="remote",
            source="test fixture",
            observed_utc="now",
            status=EnforcementStatus.PASS,
            values={
                "selected_context": "remote",
                "endpoint": {"Host": "ssh://docker.example"},
                "daemon": {"Name": "other-host", "OSType": "linux"},
            },
        )
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            patch(
                "lab.osapi.command.shutil.which",
                side_effect=lambda name: f"/usr/bin/{name}",
            ),
        ):
            result = OSActionExecutor(
                runner=runner,
                daemon_inspector=lambda *_args, **_kwargs: remote,
                host_system="Linux",
                host_release="6.1-generic",
                host_name="test-host",
            ).execute(
                self._request(docker_context="remote"),
            )

        self.assertIs(result.status, OSActionStatus.UNSUPPORTED)
        self.assertFalse(result.execution_started)
        self.assertEqual(calls, [])

    def test_linux_firewall_action_rejects_docker_desktop_daemon(self):
        desktop = OSObservation(
            platform="docker",
            subsystem="daemon",
            operation="inspect",
            target="desktop-linux",
            source="test fixture",
            observed_utc="now",
            status=EnforcementStatus.PASS,
            values={
                "selected_context": "desktop-linux",
                "endpoint": {"Host": "unix:///var/run/docker.sock"},
                "daemon": {
                    "Name": "docker-desktop",
                    "OSType": "linux",
                    "OperatingSystem": "Docker Desktop",
                },
            },
        )
        calls = []
        with patch(
            "lab.osapi.command.shutil.which",
            side_effect=lambda name: f"/usr/bin/{name}",
        ):
            result = OSActionExecutor(
                runner=lambda argv, **_kwargs: calls.append(argv),
                daemon_inspector=lambda *_args, **_kwargs: desktop,
                host_system="Linux",
                host_release="6.1-generic",
                host_name="test-host",
            ).execute(
                self._request(
                    docker_context="desktop-linux",
                )
            )

        self.assertIs(result.status, OSActionStatus.UNSUPPORTED)
        self.assertEqual(
            result.target_details["daemon_kind"],
            "managed-docker-desktop",
        )
        self.assertEqual(calls, [])

    def test_missing_noninteractive_elevation_blocks_before_boundary_execution(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=1, stdout="", stderr="permission denied")

        result = self._run(self._request(), runner)

        self.assertIs(result.status, OSActionStatus.BLOCKED)
        self.assertFalse(result.elevation_obtained)
        self.assertFalse(result.execution_started)
        self.assertEqual(len(calls), 1)

    def test_boundary_operation_targets_current_wsl_distribution_explicitly(self):
        with patch(
            "lab.osapi.command.shutil.which",
            side_effect=lambda name: f"/usr/bin/{name}",
        ):
            result = OSActionExecutor(
                runner=lambda *_args, **_kwargs: SimpleNamespace(
                    returncode=0,
                    stdout="verified",
                    stderr="",
                ),
                daemon_inspector=self._local_daemon,
                host_system="Linux",
                host_release="5.15.90.1-microsoft-standard-WSL2",
                host_name="test-host",
                wsl_distribution="Ubuntu-22.04",
            ).execute(
                self._request(
                    platform="wsl",
                    operation="network-boundary.verify",
                )
            )

        self.assertIs(result.status, OSActionStatus.SUCCEEDED)
        self.assertEqual(
            result.target_details["wsl_distribution"],
            "Ubuntu-22.04",
        )

    def test_invalid_project_and_unregistered_platform_operations_never_execute(self):
        calls = []
        runner = lambda argv, **_kwargs: calls.append(argv)

        invalid = self._run(
            self._request(target="sec-lab-i-test; id"),
            runner,
        )
        unsupported = self._run(
            self._request(platform="windows"),
            runner,
        )

        self.assertIs(invalid.status, OSActionStatus.BLOCKED)
        self.assertIs(unsupported.status, OSActionStatus.UNSUPPORTED)
        self.assertEqual(calls, [])

    def test_timeout_and_nonzero_result_are_reported_without_success_fallback(self):
        def timeout_runner(argv, **_kwargs):
            if argv[0] == "bash":
                raise subprocess.TimeoutExpired(argv, 180)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        timed_out = self._run(self._request(), timeout_runner)
        self.assertIs(timed_out.status, OSActionStatus.TIMED_OUT)
        self.assertTrue(timed_out.execution_started)

        def failed_runner(argv, **_kwargs):
            if argv[0] == "bash":
                return SimpleNamespace(returncode=9, stdout="", stderr="script failed")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        failed = self._run(self._request(), failed_runner)
        self.assertIs(failed.status, OSActionStatus.FAILED)
        self.assertEqual(failed.returncode, 9)
        self.assertEqual(failed.stderr, "script failed")

    def test_missing_docker_target_is_reported_before_execution(self):
        unavailable = OSObservation(
            platform="docker",
            subsystem="daemon",
            operation="inspect",
            target="local",
            source="test fixture",
            observed_utc="now",
            status=EnforcementStatus.UNKNOWN,
            errors=("daemon unavailable",),
        )
        with (
            patch("lab.osapi.actions.shutil.which", return_value="/usr/bin/sudo"),
            patch("lab.osapi.command.shutil.which", return_value="/usr/bin/tool"),
        ):
            result = OSActionExecutor(
                runner=lambda *_args, **_kwargs: self.fail("must not execute"),
                daemon_inspector=lambda *_args, **_kwargs: unavailable,
                host_system="Linux",
                host_release="6.1-generic",
                host_name="test-host",
            ).execute(self._request())

        self.assertIs(result.status, OSActionStatus.TARGET_UNAVAILABLE)
        self.assertFalse(result.execution_started)

    def test_docker_network_mutation_requires_project_owned_resources(self):
        project = "sec-lab-i-test"
        container_id = "a" * 64
        network_id = "b" * 64
        labels = {
            "com.docker.compose.project": project,
            "io.ithoka.security-lab.owner": "security-lab",
            "io.ithoka.security-lab.investigation": "test",
        }
        containers = OSObservation(
            "docker", "containers", "inspect", project, "fixture", "now",
            EnforcementStatus.PASS,
            values=[{"id": container_id, "labels": labels}],
        )
        networks = OSObservation(
            "docker", "networks", "inspect", project, "fixture", "now",
            EnforcementStatus.PASS,
            values=[{"id": network_id, "labels": labels}],
        )
        daemon = OSObservation(
            "docker", "daemon", "inspect", "remote-lab", "fixture", "now",
            EnforcementStatus.PASS,
            values={
                "selected_context": "remote-lab",
                "endpoint": {"Host": "ssh://docker.example"},
                "daemon": {"Name": "remote-engine", "OSType": "linux"},
            },
        )
        calls = []

        def runner(argv, **_kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout="connected", stderr="")

        request = OSActionRequest(
            platform="docker",
            operation="docker.network.connect",
            target=project,
            docker_context="remote-lab",
            approval_reference="change-123",
            arguments={
                "container_id": container_id,
                "network_id": network_id,
            },
        )
        with patch(
            "lab.osapi.command.shutil.which",
            side_effect=lambda name: f"/usr/bin/{name}",
        ), patch(
            "lab.osapi.actions.inspect_containers",
            return_value=containers,
        ), patch(
            "lab.osapi.actions.inspect_networks",
            return_value=networks,
        ):
            result = OSActionExecutor(
                runner=runner,
                daemon_inspector=lambda *_args, **_kwargs: daemon,
            ).execute(request)

        self.assertIs(result.status, OSActionStatus.SUCCEEDED)
        self.assertEqual(
            calls,
            [[
                "docker",
                "--context",
                "remote-lab",
                "network",
                "connect",
                network_id,
                container_id,
            ]],
        )
        self.assertEqual(
            result.target_details["endpoint_locality"],
            "remote-ssh",
        )
        self.assertFalse(result.elevation_required)
        self.assertFalse(result.elevation_obtained)

    def test_docker_network_mutation_blocks_unowned_resources(self):
        project = "sec-lab-i-test"
        container_id = "a" * 64
        network_id = "b" * 64
        daemon = self._local_daemon()
        containers = OSObservation(
            "docker", "containers", "inspect", project, "fixture", "now",
            EnforcementStatus.PASS,
            values=[{"id": container_id, "labels": {}}],
        )
        networks = OSObservation(
            "docker", "networks", "inspect", project, "fixture", "now",
            EnforcementStatus.PASS,
            values=[{"id": network_id, "labels": {}}],
        )
        calls = []
        request = OSActionRequest(
            platform="docker",
            operation="docker.network.disconnect",
            target=project,
            docker_context="local",
            approval_reference="change-123",
            arguments={
                "container_id": container_id,
                "network_id": network_id,
            },
        )
        with (
            patch(
                "lab.osapi.command.shutil.which",
                side_effect=lambda name: f"/usr/bin/{name}",
            ),
            patch("lab.osapi.actions.inspect_containers", return_value=containers),
            patch("lab.osapi.actions.inspect_networks", return_value=networks),
        ):
            result = OSActionExecutor(
                runner=lambda argv, **_kwargs: calls.append(argv),
                daemon_inspector=lambda *_args, **_kwargs: daemon,
            ).execute(request)

        self.assertIs(result.status, OSActionStatus.BLOCKED)
        self.assertFalse(result.execution_started)
        self.assertEqual(calls, [])

    def test_docker_compose_lifecycle_uses_selected_context_and_fixed_operation(self):
        compose_file = self.root / "compose.yaml"
        compose_file.write_text("services: {}\n", encoding="utf-8")
        calls = []

        def runner(argv, **_kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout="created", stderr="")

        request = OSActionRequest(
            platform="docker",
            operation="docker.compose.create",
            target="sec-lab-i-test",
            repository_root=self.root,
            arguments={"compose_file": str(compose_file)},
        )
        with patch(
            "lab.osapi.command.shutil.which",
            side_effect=lambda name: f"/usr/bin/{name}",
        ):
            result = OSActionExecutor(
                runner=runner,
                daemon_inspector=self._local_daemon,
            ).execute(request)

        self.assertIs(result.status, OSActionStatus.SUCCEEDED)
        self.assertEqual(
            calls,
            [[
                "docker",
                "--context",
                "local",
                "compose",
                "--project-name",
                "sec-lab-i-test",
                "--file",
                str(compose_file),
                "create",
                "--no-build",
                "--pull",
                "never",
            ]],
        )


if __name__ == "__main__":
    unittest.main()
