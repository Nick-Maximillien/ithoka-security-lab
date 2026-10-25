"""Typed, allowlisted native actions for the existing lab lifecycle."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from ..enforcement.models import EnforcementStatus
from .command import run_command
from .docker.containers import inspect_containers
from .docker.daemon import inspect_daemon
from .docker.networks import inspect_networks
from .models import CommandExecution

_PROJECT_RE = re.compile(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}")
_BOUNDARY_ACTIONS = {
    "network-boundary.apply",
    "network-boundary.verify",
    "network-boundary.remove",
}
_DOCKER_ACTIONS = {
    "docker.network.connect",
    "docker.network.disconnect",
}
_DOCKER_COMPOSE_ACTIONS = {
    "docker.compose.create",
    "docker.compose.start",
    "docker.compose.stop",
    "docker.compose.down",
}
Runner = Callable[..., Any]
DaemonInspector = Callable[..., Any]


class OSActionStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    TARGET_UNAVAILABLE = "TARGET_UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    TIMED_OUT = "TIMED_OUT"


@dataclass(frozen=True)
class OSActionRequest:
    platform: str
    operation: str
    target: str
    repository_root: Path | None = None
    policy_file: Path | None = None
    docker_context: str | None = None
    approval_reference: str | None = None
    arguments: dict[str, str] | None = None


@dataclass(frozen=True)
class OSActionResult:
    operation: str
    platform: str
    target: str
    status: OSActionStatus
    approval_reference: str | None
    native_executable: str | None
    arguments: tuple[str, ...]
    elevation_required: bool
    elevation_obtained: bool
    execution_started: bool
    returncode: int | None
    stdout: str
    stderr: str
    reason: str | None = None
    target_details: dict[str, Any] | None = None
    preflight: CommandExecution | None = None
    execution: CommandExecution | None = None

    @property
    def passed(self) -> bool:
        return self.status is OSActionStatus.SUCCEEDED

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "platform": self.platform,
            "target": self.target,
            "status": self.status.value,
            "approval_reference": self.approval_reference,
            "native_executable": self.native_executable,
            "arguments": list(self.arguments),
            "elevation_required": self.elevation_required,
            "elevation_obtained": self.elevation_obtained,
            "execution_started": self.execution_started,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "reason": self.reason,
            "target_details": self.target_details,
            "preflight": self.preflight.to_dict() if self.preflight else None,
            "execution": self.execution.to_dict() if self.execution else None,
        }


class OSActionExecutor:
    """Execute only registered native operations; never accepts shell text."""

    def __init__(
        self,
        *,
        runner: Runner = subprocess.run,
        daemon_inspector: DaemonInspector | None = None,
        host_system: str | None = None,
        host_release: str | None = None,
        host_name: str | None = None,
        wsl_distribution: str | None = None,
    ) -> None:
        self.runner = runner
        self.daemon_inspector = daemon_inspector or inspect_daemon
        self.host_system = host_system or platform.system()
        self.host_release = host_release or platform.release()
        self.host_name = host_name or platform.node()
        self.wsl_distribution = (
            wsl_distribution
            if wsl_distribution is not None
            else os.environ.get("WSL_DISTRO_NAME")
        )

    def execute(
        self,
        request: OSActionRequest,
        *,
        environment: dict[str, str] | None = None,
    ) -> OSActionResult:
        if (
            request.platform == "docker"
            and request.operation in (_DOCKER_ACTIONS | _DOCKER_COMPOSE_ACTIONS)
        ):
            return self._execute_docker(request, environment)
        if request.operation not in _BOUNDARY_ACTIONS:
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason=f"native operation is not implemented: {request.operation}",
            )
        if request.platform not in {"linux", "wsl", "docker", "windows"}:
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason=f"unsupported target platform: {request.platform}",
            )
        if request.platform in {"docker", "windows"}:
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason=(
                    "this operation is implemented only for the current Linux "
                    "host or current WSL distribution"
                ),
            )
        if self.host_system != "Linux":
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason="Linux boundary script cannot execute on this host",
            )
        if request.platform == "wsl" and (
            not self.wsl_distribution
            or "microsoft" not in self.host_release.lower()
        ):
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="the requested current WSL distribution is not available",
            )
        if request.platform == "linux" and "microsoft" in self.host_release.lower():
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason="WSL host must be targeted explicitly as platform 'wsl'",
            )
        if not _PROJECT_RE.fullmatch(request.target):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="invalid owned project identifier",
            )
        try:
            if (
                not isinstance(request.repository_root, Path)
                or not isinstance(request.policy_file, Path)
            ):
                raise ValueError("repository root and policy file must be Paths")
            root = request.repository_root.resolve(strict=True)
            policy = request.policy_file.resolve(strict=True)
            script = root / "scripts" / "network-boundary.sh"
            if (
                not root.is_dir()
                or not policy.is_file()
                or request.repository_root.is_symlink()
                or request.policy_file.is_symlink()
                or not policy.is_relative_to(root)
                or not script.is_file()
                or script.is_symlink()
            ):
                raise ValueError("repository, policy, or script path is not trusted")
        except (OSError, RuntimeError, ValueError) as exc:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=f"invalid repository/policy target: {exc}",
            )

        inspection_environment = dict(
            os.environ if environment is None else environment
        )
        inspection_environment.pop("DOCKER_HOST", None)
        if request.docker_context:
            inspection_environment["DOCKER_CONTEXT"] = request.docker_context
        docker_report = self.daemon_inspector(
            request.docker_context,
            runner=self.runner,
            env=inspection_environment,
        )
        if docker_report.status is not EnforcementStatus.PASS:
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="Docker daemon/context could not be resolved safely",
                target_details={
                    "context": request.docker_context,
                    "errors": list(docker_report.errors),
                },
            )
        daemon_values = docker_report.values or {}
        endpoint = daemon_values.get("endpoint")
        daemon = daemon_values.get("daemon")
        if not isinstance(endpoint, dict) or not isinstance(daemon, dict):
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="Docker endpoint or daemon identity is incomplete",
            )
        endpoint_host = endpoint.get("Host")
        context_name = daemon_values.get("selected_context")
        daemon_name = daemon.get("Name")
        daemon_os = daemon.get("OperatingSystem")
        if (
            not isinstance(endpoint_host, str)
            or not endpoint_host.startswith("unix://")
            or not isinstance(context_name, str)
            or "desktop" in context_name.lower()
            or not isinstance(daemon_name, str)
            or daemon_name.lower() in {"docker-desktop", "desktop-linux"}
            or (
                isinstance(daemon_os, str)
                and "docker desktop" in daemon_os.lower()
            )
            or daemon_name.casefold() != self.host_name.casefold()
        ):
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason=(
                    "Linux firewall operations require a local Unix-socket "
                    "endpoint and a daemon name matching this host; remote and "
                    "Docker Desktop endpoints are not controlled by this host "
                    "firewall"
                ),
                target_details={
                    "context": context_name,
                    "endpoint_host": endpoint_host,
                    "daemon_name": daemon_name,
                    "daemon_operating_system": daemon_os,
                    "physical_daemon_host_verified": False,
                    "daemon_kind": self._docker_target_kind(
                        context_name,
                        endpoint_host,
                        daemon_name,
                        daemon_os,
                    ),
                    "host_name": self.host_name,
                },
            )

        sudo_path = shutil.which("sudo")
        if sudo_path is None:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="sudo is unavailable; non-interactive elevation is required",
                target_details={"context": context_name},
            )
        preflight = run_command(
            [sudo_path, "-n", "-v"],
            runner=self.runner,
            timeout=10,
            env=environment,
        )
        if preflight.status is not EnforcementStatus.PASS:
            if (
                preflight.status is EnforcementStatus.BLOCKED
                or preflight.returncode is not None
            ):
                status = OSActionStatus.BLOCKED
            elif "timed out" in (preflight.reason or ""):
                status = OSActionStatus.TIMED_OUT
            else:
                status = OSActionStatus.TARGET_UNAVAILABLE
            return self._result(
                request,
                status,
                reason=(
                    "non-interactive sudo authorization is unavailable for "
                    "firewall operations"
                ),
                target_details={"context": context_name},
                preflight=preflight,
            )

        child_environment = dict(os.environ if environment is None else environment)
        child_environment.pop("DOCKER_HOST", None)
        child_environment["DOCKER_CONTEXT"] = context_name
        command = (
            "bash",
            str(script),
            request.operation.rsplit(".", 1)[1],
            request.target,
            str(policy),
        )
        execution = run_command(
            command,
            runner=self.runner,
            timeout=180,
            cwd=root,
            env=child_environment,
        )
        if execution.status is EnforcementStatus.PASS:
            status = OSActionStatus.SUCCEEDED
        elif "timed out" in (execution.reason or ""):
            status = OSActionStatus.TIMED_OUT
        elif execution.returncode is None:
            status = OSActionStatus.TARGET_UNAVAILABLE
        else:
            status = OSActionStatus.FAILED
        return self._result(
            request,
            status,
            native_executable=execution.executable,
            arguments=execution.command[1:],
            elevation_obtained=True,
            execution_started=execution.returncode is not None
            or status is OSActionStatus.TIMED_OUT,
            returncode=execution.returncode,
            stdout=execution.stdout,
            stderr=execution.stderr,
            reason=execution.reason,
            target_details={
                "context": context_name,
                "endpoint_host": endpoint_host,
                "daemon_name": daemon_name,
                "daemon_operating_system": daemon_os,
                "physical_daemon_host_verified": False,
                "daemon_kind": self._docker_target_kind(
                    context_name,
                    endpoint_host,
                    daemon_name,
                    daemon_os,
                ),
                "host_name": self.host_name,
                "wsl_distribution": (
                    self.wsl_distribution
                    if request.platform == "wsl"
                    else None
                ),
            },
            preflight=preflight,
            execution=execution,
        )

    def _execute_docker(
        self,
        request: OSActionRequest,
        environment: dict[str, str] | None,
    ) -> OSActionResult:
        if request.operation in _DOCKER_COMPOSE_ACTIONS:
            return self._execute_docker_compose(request, environment)
        if not _PROJECT_RE.fullmatch(request.target):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="invalid owned project identifier",
            )
        arguments = request.arguments
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in arguments.items()
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="Docker action arguments must be a string mapping",
            )
        container_id = arguments.get("container_id")
        network_id = arguments.get("network_id")
        if (
            not isinstance(container_id, str)
            or not re.fullmatch(r"[0-9a-fA-F]{12,64}", container_id)
            or not isinstance(network_id, str)
            or not re.fullmatch(r"[0-9a-fA-F]{12,64}", network_id)
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="Docker connect/disconnect requires full container and network IDs",
            )
        if set(arguments) != {"container_id", "network_id"}:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="unsupported Docker action arguments",
            )
        if not request.docker_context:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="an explicit Docker context is required for mutation",
            )
        if (
            not isinstance(request.approval_reference, str)
            or not request.approval_reference.strip()
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="explicit operator approval reference is required",
            )
        inspection_environment = dict(
            os.environ if environment is None else environment
        )
        inspection_environment.pop("DOCKER_HOST", None)
        inspection_environment["DOCKER_CONTEXT"] = request.docker_context
        docker_report = self.daemon_inspector(
            request.docker_context,
            runner=self.runner,
            env=inspection_environment,
        )
        if docker_report.status is not EnforcementStatus.PASS:
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="selected Docker context is unavailable",
                target_details={"errors": list(docker_report.errors)},
            )
        selected_context = (docker_report.values or {}).get("selected_context")
        if selected_context != request.docker_context:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="selected Docker context identity did not match request",
            )
        containers = inspect_containers(
            request.target,
            request.docker_context,
            runner=self.runner,
            env=inspection_environment,
        )
        networks = inspect_networks(
            request.docker_context,
            request.target,
            runner=self.runner,
            env=inspection_environment,
        )
        if (
            containers.status is not EnforcementStatus.PASS
            or networks.status is not EnforcementStatus.PASS
        ):
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="owned Docker resources could not be inspected",
                target_details={
                    "container_status": containers.status.value,
                    "network_status": networks.status.value,
                    "container_errors": list(containers.errors),
                    "network_errors": list(networks.errors),
                },
            )
        project_suffix = request.target.removeprefix("sec-lab-i-")
        container = next(
            (
                item for item in containers.values or []
                if isinstance(item, dict) and item.get("id") == container_id
            ),
            None,
        )
        network = next(
            (
                item for item in networks.values or []
                if isinstance(item, dict) and item.get("id") == network_id
            ),
            None,
        )
        if not self._resource_is_owned(container, request.target, project_suffix):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="container is not verified as owned by this project",
            )
        if not self._resource_is_owned(network, request.target, project_suffix):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="network is not verified as owned by this project",
            )
        action = request.operation.rsplit(".", 1)[1]
        command = (
            "docker",
            "--context",
            request.docker_context,
            "network",
            action,
            network_id,
            container_id,
        )
        execution = run_command(
            command,
            runner=self.runner,
            timeout=60,
            env=inspection_environment,
        )
        if execution.status is EnforcementStatus.PASS:
            status = OSActionStatus.SUCCEEDED
        elif "timed out" in (execution.reason or ""):
            status = OSActionStatus.TIMED_OUT
        elif execution.returncode is None:
            status = OSActionStatus.TARGET_UNAVAILABLE
        else:
            status = OSActionStatus.FAILED
        endpoint = (docker_report.values or {}).get("endpoint")
        endpoint_host = endpoint.get("Host") if isinstance(endpoint, dict) else None
        if isinstance(endpoint_host, str):
            if endpoint_host.startswith("unix://"):
                locality = "local-unix-socket"
            elif endpoint_host.startswith("ssh://"):
                locality = "remote-ssh"
            elif endpoint_host.startswith(("tcp://", "http://", "https://")):
                locality = "remote-network"
            elif endpoint_host.startswith("npipe://"):
                locality = "windows-named-pipe"
            else:
                locality = "unclassified"
        else:
            locality = "unknown"
        return self._result(
            request,
            status,
            native_executable=execution.executable,
            arguments=execution.command[1:],
            execution_started=execution.returncode is not None
            or status is OSActionStatus.TIMED_OUT,
            returncode=execution.returncode,
            stdout=execution.stdout,
            stderr=execution.stderr,
            reason=execution.reason,
            target_details={
                "context": selected_context,
                "endpoint_host": endpoint_host,
                "endpoint_locality": locality,
                "daemon": (docker_report.values or {}).get("daemon"),
                "daemon_authorized": status is OSActionStatus.SUCCEEDED,
            },
            execution=execution,
        )

    def _execute_docker_compose(
        self,
        request: OSActionRequest,
        environment: dict[str, str] | None,
    ) -> OSActionResult:
        if not _PROJECT_RE.fullmatch(request.target):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="invalid owned project identifier",
            )
        arguments = request.arguments
        if (
            not isinstance(arguments, dict)
            or set(arguments) != {"compose_file"}
            or not isinstance(arguments.get("compose_file"), str)
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="Docker Compose operation requires one compose_file path",
            )
        if not isinstance(request.repository_root, Path):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="Docker Compose operation requires a repository root",
            )
        try:
            root = request.repository_root.resolve(strict=True)
            compose_file = Path(arguments["compose_file"]).resolve(strict=True)
            if (
                not root.is_dir()
                or request.repository_root.is_symlink()
                or not compose_file.is_file()
                or Path(arguments["compose_file"]).is_symlink()
                or not compose_file.is_relative_to(root)
            ):
                raise ValueError("Compose file must be a regular repository-owned file")
        except (OSError, RuntimeError, ValueError) as exc:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=f"invalid Compose target: {exc}",
            )
        inspection_environment = dict(
            os.environ if environment is None else environment
        )
        inspection_environment.pop("DOCKER_HOST", None)
        if request.docker_context:
            inspection_environment["DOCKER_CONTEXT"] = request.docker_context
        docker_report = self.daemon_inspector(
            request.docker_context,
            runner=self.runner,
            env=inspection_environment,
        )
        if docker_report.status is not EnforcementStatus.PASS:
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="selected Docker daemon/context is unavailable",
                target_details={"errors": list(docker_report.errors)},
            )
        values = docker_report.values or {}
        context = values.get("selected_context")
        endpoint = values.get("endpoint")
        daemon = values.get("daemon")
        if (
            not isinstance(context, str)
            or not isinstance(endpoint, dict)
            or not isinstance(daemon, dict)
        ):
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="Docker context endpoint or daemon identity is incomplete",
            )
        if request.docker_context and context != request.docker_context:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="selected Docker context identity did not match request",
            )
        action = request.operation.rsplit(".", 1)[1]
        command = [
            "docker",
            "--context",
            context,
            "compose",
            "--project-name",
            request.target,
            "--file",
            str(compose_file),
            action,
        ]
        if action == "create":
            command.extend(["--no-build", "--pull", "never"])
        elif action == "down":
            command.append("--remove-orphans")
        execution = run_command(
            command,
            runner=self.runner,
            timeout=180,
            cwd=root,
            env=inspection_environment,
        )
        if execution.status is EnforcementStatus.PASS:
            status = OSActionStatus.SUCCEEDED
        elif "timed out" in (execution.reason or ""):
            status = OSActionStatus.TIMED_OUT
        elif execution.returncode is None:
            status = OSActionStatus.TARGET_UNAVAILABLE
        else:
            status = OSActionStatus.FAILED
        endpoint_host = endpoint.get("Host")
        daemon_name = daemon.get("Name")
        daemon_os = daemon.get("OperatingSystem")
        return self._result(
            request,
            status,
            native_executable=execution.executable,
            arguments=execution.command[1:],
            execution_started=execution.returncode is not None
            or status is OSActionStatus.TIMED_OUT,
            returncode=execution.returncode,
            stdout=execution.stdout,
            stderr=execution.stderr,
            reason=execution.reason,
            target_details={
                "context": context,
                "endpoint_host": endpoint_host,
                "endpoint_locality": self._docker_target_kind(
                    context,
                    endpoint_host,
                    daemon_name,
                    daemon_os,
                ),
                "physical_daemon_host_verified": False,
                "daemon": daemon,
                "daemon_authorized": status is OSActionStatus.SUCCEEDED,
            },
            execution=execution,
        )

    @staticmethod
    def _resource_is_owned(
        resource: Any,
        project: str,
        project_suffix: str,
    ) -> bool:
        if not isinstance(resource, dict):
            return False
        labels = resource.get("labels")
        if not isinstance(labels, dict):
            return False
        return (
            labels.get("com.docker.compose.project") == project
            and labels.get("io.ithoka.security-lab.owner") == "security-lab"
            and labels.get("io.ithoka.security-lab.investigation")
            == project_suffix
        )

    @staticmethod
    def _docker_target_kind(
        context: Any,
        endpoint: Any,
        daemon_name: Any,
        operating_system: Any,
    ) -> str:
        text = " ".join(
            item for item in (context, daemon_name, operating_system)
            if isinstance(item, str)
        ).lower()
        if "docker desktop" in text or "desktop-linux" in text:
            return "managed-docker-desktop"
        if isinstance(endpoint, str) and endpoint.startswith("unix://"):
            return "local-unix-socket"
        if isinstance(endpoint, str) and endpoint.startswith(("ssh://", "tcp://")):
            return "remote"
        if isinstance(endpoint, str) and endpoint.startswith("npipe://"):
            return "windows-named-pipe"
        return "unclassified"

    @staticmethod
    def _result(
        request: OSActionRequest,
        status: OSActionStatus,
        *,
        native_executable: str | None = None,
        arguments: tuple[str, ...] = (),
        elevation_obtained: bool = False,
        execution_started: bool = False,
        returncode: int | None = None,
        stdout: str = "",
        stderr: str = "",
        reason: str | None = None,
        target_details: dict[str, Any] | None = None,
        preflight: CommandExecution | None = None,
        execution: CommandExecution | None = None,
    ) -> OSActionResult:
        return OSActionResult(
            operation=request.operation,
            platform=request.platform,
            target=request.target,
            status=status,
            approval_reference=request.approval_reference,
            native_executable=native_executable,
            arguments=arguments,
            elevation_required=request.platform in {"linux", "wsl"},
            elevation_obtained=elevation_obtained,
            execution_started=execution_started,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            reason=reason,
            target_details=target_details,
            preflight=preflight,
            execution=execution,
        )


def execute_os_action(
    request: OSActionRequest,
    *,
    runner: Runner = subprocess.run,
    environment: dict[str, str] | None = None,
    daemon_inspector: DaemonInspector | None = None,
) -> OSActionResult:
    """Execute one concrete registered action and return its native outcome."""
    return OSActionExecutor(
        runner=runner,
        daemon_inspector=daemon_inspector,
    ).execute(request, environment=environment)


def execute_network_boundary_action(
    action: str,
    project: str,
    policy_file: Path,
    repository_root: Path,
    *,
    runner: Runner | None = None,
    environment: dict[str, str] | None = None,
    docker_context: str | None = None,
    daemon_inspector: DaemonInspector | None = None,
) -> OSActionResult:
    """Run one existing boundary-script action for the current Linux target."""
    operation = f"network-boundary.{action}"
    if operation not in _BOUNDARY_ACTIONS:
        return OSActionResult(
            operation=operation,
            platform="linux",
            target=project,
            status=OSActionStatus.UNSUPPORTED,
            approval_reference=None,
            native_executable=None,
            arguments=(),
            elevation_required=True,
            elevation_obtained=False,
            execution_started=False,
            returncode=None,
            stdout="",
            stderr="",
            reason="unsupported network-boundary operation",
        )
    is_wsl = "microsoft" in platform.release().lower()
    request = OSActionRequest(
        platform="wsl" if is_wsl else "linux",
        operation=operation,
        target=project,
        repository_root=repository_root,
        policy_file=policy_file,
        docker_context=docker_context,
    )
    return OSActionExecutor(
        runner=runner or subprocess.run,
        daemon_inspector=daemon_inspector or inspect_daemon,
    ).execute(request, environment=environment)
