import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lab.networks import inspect_docker_project


PROJECT = "sec-lab-i-study"
CONTAINER_ID = "a" * 64
NETWORK_NAME = f"{PROJECT}_lab"


def _container(**overrides):
    container = {
        "Id": CONTAINER_ID,
        "Image": "sha256:" + "c" * 64,
        "Name": f"/{PROJECT}-service-1",
        "Config": {
            "Image": "example/image:1",
            "User": "1000:1000",
            "Labels": {
                "io.ithoka.security-lab.owner": "security-lab",
                "io.ithoka.security-lab.investigation": "study",
                "com.docker.compose.project": PROJECT,
            },
            "Env": ["API_TOKEN=must-not-appear"],
        },
        "HostConfig": {
            "NetworkMode": NETWORK_NAME,
            "PortBindings": {},
            "Privileged": False,
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "Devices": [],
            "DeviceRequests": None,
            "ReadonlyRootfs": True,
            "Memory": 134217728,
            "NanoCpus": 500000000,
            "CpuQuota": 0,
            "CpuPeriod": 0,
            "PidsLimit": 64,
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {},
        },
        "State": {"Running": False, "Status": "created"},
        "NetworkSettings": {
            "Networks": {NETWORK_NAME: {}},
            "Ports": {},
        },
        "Mounts": [],
    }
    for key, value in overrides.items():
        container[key] = value
    return container


def _network():
    return {
        "network_id": "b" * 64,
        "name": NETWORK_NAME,
        "driver": "bridge",
        "internal": True,
        "enable_ipv6": False,
        "containers": {CONTAINER_ID: {"Name": "service-1"}},
        "bridge": "br-study",
    }


def _runner_for(container=None, context="default", endpoint="unix:///var/run/docker.sock"):
    inspected = _container() if container is None else container

    def runner(command, **_kwargs):
        if command == ["docker", "context", "show"]:
            return SimpleNamespace(returncode=0, stdout=context, stderr="")
        if command[:3] == ["docker", "context", "inspect"]:
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"Host": endpoint}),
                stderr="",
            )
        if "info" in command:
            return SimpleNamespace(
                returncode=0,
                stdout="daemon-id|engine|28.5.2|linux|x86_64",
                stderr="",
            )
        if "ps" in command:
            return SimpleNamespace(returncode=0, stdout=CONTAINER_ID, stderr="")
        if "inspect" in command:
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps([inspected]),
                stderr="",
            )
        raise AssertionError(f"unexpected Docker command: {command}")

    return runner


class DockerInspectionTests(unittest.TestCase):
    def test_effective_project_controls_pass_without_returning_container_env(self):
        with (
            patch(
                "lab.networks.validate_machine_configuration",
                return_value={
                    "operator_confirmed": {
                        "approved_docker_context": "default",
                    },
                },
            ),
            patch("lab.networks.inspect_owned_network", return_value=_network()),
        ):
            report = inspect_docker_project(
                PROJECT,
                Path("."),
                runner=_runner_for(),
            )

        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["read_only"])
        self.assertEqual(report["daemon"]["id"], "daemon-id")
        self.assertEqual(report["containers"][0]["network_attachments"], [NETWORK_NAME])
        self.assertNotIn("API_TOKEN=must-not-appear", json.dumps(report))
        self.assertTrue(all(item["status"] == "PASS" for item in report["findings"]))

    def test_remote_docker_endpoint_is_blocked_before_workload_inspection(self):
        with (
            patch(
                "lab.networks.validate_machine_configuration",
                return_value={
                    "operator_confirmed": {
                        "approved_docker_context": "default",
                    },
                },
            ),
            patch("lab.networks.inspect_owned_network") as inspect_network,
        ):
            report = inspect_docker_project(
                PROJECT,
                Path("."),
                runner=_runner_for(endpoint="ssh://docker.example"),
            )

        self.assertEqual(report["status"], "BLOCKED")
        self.assertEqual(report["endpoint_scheme"], "ssh")
        inspect_network.assert_not_called()

    def test_active_context_mismatch_is_blocked(self):
        with (
            patch(
                "lab.networks.validate_machine_configuration",
                return_value={
                    "operator_confirmed": {
                        "approved_docker_context": "approved",
                    },
                },
            ),
            patch("lab.networks.inspect_owned_network") as inspect_network,
        ):
            report = inspect_docker_project(
                PROJECT,
                Path("."),
                runner=_runner_for(context="unexpected"),
            )

        self.assertEqual(report["status"], "BLOCKED")
        inspect_network.assert_not_called()

    def test_privilege_mount_and_published_port_violations_fail(self):
        container = _container(
            HostConfig={
                **_container()["HostConfig"],
                "Privileged": True,
                "PortBindings": {"80/tcp": [{"HostPort": "8080"}]},
            },
            Mounts=[{
                "Type": "bind",
                "Source": "/home/user/data",
                "Destination": "/data",
            }],
            NetworkSettings={
                "Networks": {NETWORK_NAME: {}},
                "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
            },
        )
        with (
            patch(
                "lab.networks.validate_machine_configuration",
                return_value={
                    "operator_confirmed": {
                        "approved_docker_context": "default",
                    },
                },
            ),
            patch("lab.networks.inspect_owned_network", return_value=_network()),
        ):
            report = inspect_docker_project(
                PROJECT,
                Path("."),
                runner=_runner_for(container),
            )

        self.assertEqual(report["status"], "FAIL")
        failed_controls = {
            item["control"]
            for item in report["findings"]
            if item["status"] == "FAIL"
        }
        self.assertTrue({
            "privileged-mode",
            "published-ports",
            "host-filesystem-mounts",
        }.issubset(failed_controls))

    def test_named_user_is_unknown_when_non_root_cannot_be_proven(self):
        container = _container()
        container["Config"]["User"] = "lab"
        with (
            patch(
                "lab.networks.validate_machine_configuration",
                return_value={
                    "operator_confirmed": {
                        "approved_docker_context": "default",
                    },
                },
            ),
            patch("lab.networks.inspect_owned_network", return_value=_network()),
        ):
            report = inspect_docker_project(
                PROJECT,
                Path("."),
                runner=_runner_for(container),
            )

        self.assertEqual(report["status"], "UNKNOWN")
        finding = next(
            item for item in report["findings"]
            if item["control"] == "non-root-user"
        )
        self.assertEqual(finding["status"], "UNKNOWN")

    def test_unavailable_daemon_state_is_unknown(self):
        def runner(command, **_kwargs):
            if command == ["docker", "context", "show"]:
                return SimpleNamespace(returncode=0, stdout="default", stderr="")
            if command[:3] == ["docker", "context", "inspect"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps({"Host": "unix:///var/run/docker.sock"}),
                    stderr="",
                )
            return SimpleNamespace(returncode=1, stdout="", stderr="daemon unavailable")

        with patch(
            "lab.networks.validate_machine_configuration",
            return_value={
                "operator_confirmed": {
                    "approved_docker_context": "default",
                },
            },
        ):
            report = inspect_docker_project(PROJECT, Path("."), runner=runner)

        self.assertEqual(report["status"], "UNKNOWN")
        self.assertIn("daemon unavailable", report["reason"])


if __name__ == "__main__":
    unittest.main()
