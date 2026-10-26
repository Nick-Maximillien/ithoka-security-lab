
"""Typed, allowlisted native actions for the Ithoka Security Lab.

This module dispatches structured operations to native enforcement mechanisms.
It never accepts arbitrary shell commands.

Docker observations belong to lab/osapi/docker.
Docker state changes belong to lab/enforcement/docker.
Linux/WSL network-boundary lifecycle is delegated to the installed
security-lab-firewall helper.

Command success is not proof of boundary enforcement. Effective enforcement
must be verified by a corresponding native adapter and runtime acceptance tests.
Missing adapters fail closed as UNSUPPORTED.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

from ..enforcement.models import EnforcementStatus
from ..enforcement.docker import DockerAdapter
from .command import run_command
from .docker.containers import inspect_containers
from .docker.daemon import inspect_daemon
from .docker.networks import inspect_networks
from .models import CommandExecution


_PROJECT_RE = re.compile(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}")
_PROFILE_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_BOUNDARY_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_RESOURCE_ID_RE = re.compile(r"[0-9a-fA-F]{12,64}")

_FIREWALL_HELPER = Path("/usr/local/sbin/security-lab-firewall")

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

_DOCKER_ENFORCEMENT_ACTIONS = {
    "docker.policy.apply",
}

BOUNDARY_NAMES = frozenset({
    "lab_ingress",
    "lab_egress",
    "windows_host",
    "external_networks",
    "dns",
    "proxies",
    "ipv4",
    "ipv6",
    "docker_networks",
    "filesystem",
    "capture",
    "resource_access",
})

PROFILE_NAMES = frozenset({
    "isolated",
    "controlled-access",
    "maintenance",
    "observation",
})

# The installed helper currently implements only these boundaries.
# This registry does not assert runtime acceptance.
LINUX_SCRIPT_BOUNDARIES = frozenset({
    "lab_ingress",
    "lab_egress",
    "external_networks",
    "ipv4",
    "ipv6",
})

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
        """Whether the requested action completed successfully.

        This is not a claim that the security boundary passed acceptance.
        """
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
    """Execute registered native operations with platform-aware validation."""

    def __init__(
        self,
        *,
        runner: Runner = subprocess.run,
        daemon_inspector: DaemonInspector | None = None,
        docker_adapter: DockerAdapter | None = None,
        host_system: str | None = None,
        host_release: str | None = None,
        host_name: str | None = None,
        wsl_distribution: str | None = None,
    ) -> None:
        self.runner = runner
        self.daemon_inspector = daemon_inspector or inspect_daemon
        self.docker_adapter = docker_adapter or DockerAdapter(runner=runner)
        self.host_system = host_system or platform.system()
        self.host_release = host_release or platform.release()
        self.host_name = host_name or platform.node()
        self.wsl_distribution = (
            wsl_distribution
            if wsl_distribution is not None
            else os.environ.get("WSL_DISTRO_NAME")
        )

    @property
    def is_wsl_host(self) -> bool:
        return (
            self.host_system == "Linux"
            and "microsoft" in self.host_release.lower()
        )

    def _environment(
        self,
        environment: dict[str, str] | None,
        *,
        docker_context: str | None = None,
    ) -> dict[str, str]:
        """Create a consistent child environment for this action."""
        result = dict(os.environ if environment is None else environment)

        # Context selection is explicit. Do not let an inherited DOCKER_HOST
        # silently redirect operations to a different daemon.
        result.pop("DOCKER_HOST", None)
        if docker_context:
            result["DOCKER_CONTEXT"] = docker_context
        return result

    def execute(
        self,
        request: OSActionRequest,
        *,
        environment: dict[str, str] | None = None,
    ) -> OSActionResult:
        """Dispatch one typed operation to its registered native adapter."""
        if request.platform not in {"linux", "wsl", "windows", "docker"}:
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason=f"unsupported target platform: {request.platform}",
            )

        if request.platform == "docker":
            if request.operation in _DOCKER_ENFORCEMENT_ACTIONS:
                return self._execute_docker_policy(request, environment)
            if request.operation in _DOCKER_ACTIONS:
                return self._execute_docker(request, environment)
            if request.operation in _DOCKER_COMPOSE_ACTIONS:
                return self._execute_docker_compose(request, environment)
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason=f"Docker operation is not implemented: {request.operation}",
            )

        if request.operation in _BOUNDARY_ACTIONS:
            return self._execute_network_boundary(request, environment)

        if request.operation.startswith("boundary."):
            return self._execute_boundary_operation(request, environment)

        if request.operation == "profile.apply":
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason=(
                    "profile.apply requires the policy resolver and a coordinator "
                    "that applies all required adapters and independently accepts "
                    "effective runtime behavior"
                ),
            )

        return self._result(
            request,
            OSActionStatus.UNSUPPORTED,
            reason=f"native operation is not implemented: {request.operation}",
        )

    # ------------------------------------------------------------------
    # Docker policy mutation
    # ------------------------------------------------------------------

    def _execute_docker_policy(
        self,
        request: OSActionRequest,
        environment: dict[str, str] | None,
    ) -> OSActionResult:
        """Delegate resolved policy mutation to the Docker enforcement adapter."""
        if request.platform != "docker":
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="Docker policy mutation requires platform='docker'",
            )

        if not _PROJECT_RE.fullmatch(request.target):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="invalid owned project identifier",
            )

        if not request.docker_context:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="an explicit Docker context is required for policy mutation",
            )

        if not isinstance(request.approval_reference, str) or not (
            request.approval_reference.strip()
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="policy mutation requires an approval reference",
            )

        args = request.arguments
        if not isinstance(args, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in args.items()
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="Docker policy arguments must be a string mapping",
            )

        allowed = {"policy_json", "approve_disruptive_changes"}
        if set(args) - allowed or "policy_json" not in args:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=(
                    "docker.policy.apply requires policy_json and accepts only "
                    "approve_disruptive_changes as an optional additional argument"
                ),
            )

        approval_value = args.get("approve_disruptive_changes", "false").lower()
        if approval_value not in {"true", "false"}:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="approve_disruptive_changes must be 'true' or 'false'",
            )

        try:
            policy = json.loads(args["policy_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=f"policy_json is invalid JSON: {exc}",
            )

        if not isinstance(policy, Mapping):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="policy_json must decode to an object",
            )

        env = self._environment(
            environment,
            docker_context=request.docker_context,
        )
        adapter = DockerAdapter(
            root=request.repository_root or Path("."),
            runner=self.runner,
            env=env,
        )

        result = adapter.apply(
            request.target,
            policy,
            context=request.docker_context,
            approve_disruptive_changes=(approval_value == "true"),
        )

        status_map = {
            EnforcementStatus.PASS: OSActionStatus.SUCCEEDED,
            EnforcementStatus.FAIL: OSActionStatus.FAILED,
            EnforcementStatus.UNKNOWN: OSActionStatus.FAILED,
            EnforcementStatus.BLOCKED: OSActionStatus.BLOCKED,
            EnforcementStatus.NOT_APPLICABLE: OSActionStatus.UNSUPPORTED,
        }
        status = status_map.get(result.status, OSActionStatus.FAILED)

        result_dict = result.to_dict()
        return self._result(
            request,
            status,
            native_executable="docker",
            arguments=(),
            execution_started=bool(result.outcomes),
            reason=result.reason,
            target_details={
                "enforcement_result": result_dict,
                "mutation_status": result.status.value,
                "runtime_acceptance_status": result.acceptance_status.value,
                "runtime_accepted": result.runtime_accepted,
                "fully_accepted": result.fully_accepted,
                "approval_reference": request.approval_reference,
                "enforcement_verified": result.runtime_accepted,
            },
            elevation_required=False,
            elevation_obtained=False,
        )

    # ------------------------------------------------------------------
    # Boundary-scoped dispatch
    # ------------------------------------------------------------------

    def _execute_boundary_operation(
        self,
        request: OSActionRequest,
        environment: dict[str, str] | None,
    ) -> OSActionResult:
        parts = request.operation.split(".")
        if len(parts) != 3 or parts[0] != "boundary":
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=(
                    "boundary operation must be "
                    "boundary.<boundary_name>.<apply|verify|remove>"
                ),
            )

        _, boundary, action = parts
        if (
            boundary not in BOUNDARY_NAMES
            or not _BOUNDARY_RE.fullmatch(boundary)
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=f"unknown boundary name: {boundary}",
            )

        if action not in {"apply", "verify", "remove"}:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=f"unsupported boundary action: {action}",
            )

        if not _PROJECT_RE.fullmatch(request.target):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="invalid owned project identifier",
            )

        args = request.arguments or {}
        if not isinstance(args, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in args.items()
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="boundary arguments must be a string mapping",
            )

        allowed_keys = {
            "profile",
            "policy_file",
            "interface",
            "capture_file",
        }
        if set(args) - allowed_keys:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="unsupported boundary action arguments",
            )

        profile = args.get("profile")
        if profile is not None and (
            profile not in PROFILE_NAMES
            or not _PROFILE_RE.fullmatch(profile)
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=f"unknown security profile: {profile}",
            )

        if request.platform in {"linux", "wsl"}:
            if request.platform == "wsl" and not self.is_wsl_host:
                return self._result(
                    request,
                    OSActionStatus.TARGET_UNAVAILABLE,
                    reason="the requested WSL target is not the current WSL host",
                )

            if request.platform == "linux" and self.is_wsl_host:
                return self._result(
                    request,
                    OSActionStatus.BLOCKED,
                    reason="this Linux host is WSL; target it explicitly as 'wsl'",
                )

            if boundary not in LINUX_SCRIPT_BOUNDARIES:
                return self._result(
                    request,
                    OSActionStatus.UNSUPPORTED,
                    reason=(
                        f"no registered native enforcement implementation "
                        f"exists for boundary '{boundary}' on {request.platform}"
                    ),
                    target_details={
                        "boundary": boundary,
                        "action": action,
                        "profile": profile,
                        "enforcement_verified": False,
                    },
                )

            return self._execute_network_boundary(
                OSActionRequest(
                    platform=request.platform,
                    operation=f"network-boundary.{action}",
                    target=request.target,
                    repository_root=request.repository_root,
                    policy_file=request.policy_file,
                    docker_context=request.docker_context,
                    approval_reference=request.approval_reference,
                    arguments=request.arguments,
                ),
                environment,
            )

        if request.platform == "windows":
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason=(
                    "no verified Windows boundary adapter is registered; "
                    "Windows host protection requires independent Windows-side "
                    "enforcement and runtime acceptance"
                ),
                target_details={
                    "boundary": boundary,
                    "action": action,
                    "enforcement_verified": False,
                },
            )

        return self._result(
            request,
            OSActionStatus.UNSUPPORTED,
            reason=(
                "Docker boundary enforcement must use docker.policy.apply "
                "with a resolved policy and the dedicated mutation adapter"
            ),
        )

    # ------------------------------------------------------------------
    # Installed Linux/WSL firewall-helper lifecycle
    # ------------------------------------------------------------------

    def _execute_network_boundary(
        self,
        request: OSActionRequest,
        environment: dict[str, str] | None,
    ) -> OSActionResult:
        if request.operation not in _BOUNDARY_ACTIONS:
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason="unsupported network-boundary operation",
            )

        if request.platform not in {"linux", "wsl"}:
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason="the Linux firewall helper only runs on Linux or WSL",
            )

        if self.host_system != "Linux":
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason="Linux firewall helper cannot execute on this host",
            )

        if request.platform == "wsl" and not self.is_wsl_host:
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="the current host is not WSL",
            )

        if request.platform == "linux" and self.is_wsl_host:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="WSL host must be targeted explicitly as platform 'wsl'",
            )

        if not _PROJECT_RE.fullmatch(request.target):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="invalid owned project identifier",
            )

        try:
            if not isinstance(request.policy_file, Path):
                raise ValueError("policy file must be a Path")

            policy_input = request.policy_file
            policy = policy_input.resolve(strict=True)

            if (
                policy_input.is_symlink()
                or not policy.is_file()
            ):
                raise ValueError("policy must be a regular file, not a symlink")

            helper = _FIREWALL_HELPER
            if (
                not helper.is_absolute()
                or helper.is_symlink()
                or not helper.is_file()
            ):
                raise ValueError(
                    f"installed firewall helper is missing or unsafe: {helper}"
                )

            helper_stat = helper.stat()
            if helper_stat.st_uid != 0 or helper_stat.st_mode & 0o022:
                raise ValueError(
                    "installed firewall helper must be root-owned and not "
                    "group/world writable"
                )

            policy_stat = policy.stat()
            if not policy_stat.st_mode & 0o444:
                raise ValueError("policy file is not readable")

        except (OSError, RuntimeError, ValueError) as exc:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=f"invalid firewall helper or policy target: {exc}",
            )

        child_environment = self._environment(
            environment,
            docker_context=request.docker_context,
        )

        docker_report = self.daemon_inspector(
            request.docker_context,
            runner=self.runner,
            env=child_environment,
        )

        if docker_report.status is not EnforcementStatus.PASS:
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="Docker daemon/context could not be resolved safely",
                target_details={
                    "context": request.docker_context,
                    "errors": list(docker_report.errors),
                    "enforcement_verified": False,
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
                    "Docker endpoint and a daemon name matching this host; "
                    "remote and Docker Desktop endpoints are outside this "
                    "host firewall's verified enforcement scope"
                ),
                target_details={
                    "context": context_name,
                    "endpoint_host": endpoint_host,
                    "daemon_name": daemon_name,
                    "daemon_operating_system": daemon_os,
                    "physical_daemon_host_verified": False,
                    "daemon_kind": self._docker_target_kind(
                        context_name, endpoint_host, daemon_name, daemon_os
                    ),
                    "host_name": self.host_name,
                    "enforcement_verified": False,
                },
            )

        sudo_path = shutil.which("sudo")
        if sudo_path is None:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="sudo is unavailable; non-interactive elevation is required",
            )

        preflight = run_command(
            [sudo_path, "-n", "-v"],
            runner=self.runner,
            timeout=10,
            env=child_environment,
        )

        if preflight.status is not EnforcementStatus.PASS:
            return self._result(
                request,
                self._status_from_execution(preflight),
                reason=(
                    "non-interactive sudo authorization is unavailable for "
                    "firewall operations"
                ),
                target_details={"context": context_name},
                preflight=preflight,
            )

        action = request.operation.rsplit(".", 1)[1]
        command = (
            sudo_path,
            "-n",
            str(helper),
            action,
            request.target,
            str(policy),
        )

        execution = run_command(
            command,
            runner=self.runner,
            timeout=180,
            env=child_environment,
        )
        status = self._status_from_execution(execution)

        return self._result(
            request,
            status,
            native_executable=execution.executable,
            arguments=execution.command[1:],
            elevation_required=True,
            elevation_obtained=(
                status is OSActionStatus.SUCCEEDED
                and preflight.status is EnforcementStatus.PASS
            ),
            execution_started=self._execution_started(execution),
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
                    context_name, endpoint_host, daemon_name, daemon_os
                ),
                "host_name": self.host_name,
                "wsl_distribution": (
                    self.wsl_distribution if request.platform == "wsl" else None
                ),
                "enforcement_verified": False,
                "runtime_acceptance_required": True,
                "helper": str(helper),
            },
            preflight=preflight,
            execution=execution,
        )

    # ------------------------------------------------------------------
    # Docker network mutations
    # ------------------------------------------------------------------

    def _execute_docker(
        self,
        request: OSActionRequest,
        environment: dict[str, str] | None,
    ) -> OSActionResult:
        """Handle direct network connect/disconnect only through ownership checks.

        These operations remain separate from policy application. A successful
        connection change is not proof that a boundary is enforced.
        """
        if request.operation not in _DOCKER_ACTIONS:
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason="unsupported Docker network operation",
            )

        if not _PROJECT_RE.fullmatch(request.target):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="invalid owned project identifier",
            )

        args = request.arguments
        if (
            not isinstance(args, dict)
            or any(not isinstance(k, str) or not isinstance(v, str)
                   for k, v in args.items())
            or set(args) != {"container_id", "network_id"}
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=(
                    "Docker network mutation requires only container_id "
                    "and network_id"
                ),
            )

        container_id = args["container_id"]
        network_id = args["network_id"]
        if (
            not _RESOURCE_ID_RE.fullmatch(container_id)
            or not _RESOURCE_ID_RE.fullmatch(network_id)
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="invalid Docker container or network ID",
            )

        if not request.docker_context:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="an explicit Docker context is required",
            )

        if not isinstance(request.approval_reference, str) or not (
            request.approval_reference.strip()
        ):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="explicit operator approval reference is required",
            )

        env = self._environment(
            environment,
            docker_context=request.docker_context,
        )
        daemon = self.daemon_inspector(
            request.docker_context,
            runner=self.runner,
            env=env,
        )
        if daemon.status is not EnforcementStatus.PASS:
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="selected Docker context is unavailable",
            )

        containers = inspect_containers(
            request.target,
            request.docker_context,
            runner=self.runner,
            env=env,
        )
        networks = inspect_networks(
            request.docker_context,
            project=request.target,
            runner=self.runner,
            env=env,
        )

        if (
            containers.status is not EnforcementStatus.PASS
            or networks.status is not EnforcementStatus.PASS
        ):
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="could not establish owned Docker resource inventory",
                target_details={
                    "container_status": containers.status.value,
                    "network_status": networks.status.value,
                    "container_errors": list(containers.errors),
                    "network_errors": list(networks.errors),
                },
            )

        container = next(
            (
                item for item in (containers.values or [])
                if isinstance(item, dict) and item.get("id") == container_id
            ),
            None,
        )
        network = next(
            (
                item for item in (networks.values or [])
                if isinstance(item, dict) and item.get("id") == network_id
            ),
            None,
        )

        if not self._project_label_matches(container, request.target):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="container ownership could not be established from labels",
            )
        if not self._project_label_matches(network, request.target):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="network ownership could not be established from labels",
            )

        action = request.operation.rsplit(".", 1)[1]
        command = [
            "docker",
            "--context", request.docker_context,
            "network", action,
            network_id,
            container_id,
        ]
        execution = run_command(
            command,
            runner=self.runner,
            timeout=60,
            env=env,
        )
        status = self._status_from_execution(execution)

        return self._result(
            request,
            status,
            native_executable=execution.executable,
            arguments=execution.command[1:],
            execution_started=self._execution_started(execution),
            returncode=execution.returncode,
            stdout=execution.stdout,
            stderr=execution.stderr,
            reason=execution.reason,
            target_details={
                "context": request.docker_context,
                "container_id": container_id,
                "network_id": network_id,
                "approval_reference": request.approval_reference,
                "enforcement_verified": False,
                "acceptance_required": True,
            },
            execution=execution,
            elevation_required=False,
        )

    # ------------------------------------------------------------------
    # Docker Compose lifecycle
    # ------------------------------------------------------------------

    def _execute_docker_compose(
        self,
        request: OSActionRequest,
        environment: dict[str, str] | None,
    ) -> OSActionResult:
        if request.operation not in _DOCKER_COMPOSE_ACTIONS:
            return self._result(
                request,
                OSActionStatus.UNSUPPORTED,
                reason="unsupported Docker Compose operation",
            )

        if not _PROJECT_RE.fullmatch(request.target):
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="invalid owned project identifier",
            )

        args = request.arguments
        if (
            not isinstance(args, dict)
            or set(args) != {"compose_file"}
            or not isinstance(args.get("compose_file"), str)
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
            root = self._trusted_repository_root(request.repository_root)
            compose_input = Path(args["compose_file"])
            compose_file = compose_input.resolve(strict=True)
            if (
                compose_input.is_symlink()
                or not compose_file.is_file()
                or not compose_file.is_relative_to(root)
            ):
                raise ValueError(
                    "Compose file must be a regular repository-owned file"
                )
        except (OSError, RuntimeError, ValueError) as exc:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason=f"invalid Compose target: {exc}",
            )

        if not request.docker_context:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="an explicit Docker context is required",
            )

        env = self._environment(
            environment,
            docker_context=request.docker_context,
        )
        report = self.daemon_inspector(
            request.docker_context,
            runner=self.runner,
            env=env,
        )
        if report.status is not EnforcementStatus.PASS:
            return self._result(
                request,
                OSActionStatus.TARGET_UNAVAILABLE,
                reason="selected Docker daemon/context is unavailable",
                target_details={"errors": list(report.errors)},
            )

        values = report.values or {}
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
        if context != request.docker_context:
            return self._result(
                request,
                OSActionStatus.BLOCKED,
                reason="selected Docker context identity did not match request",
            )

        action = request.operation.rsplit(".", 1)[1]
        command = [
            "docker",
            "--context", context,
            "compose",
            "--project-name", request.target,
            "--file", str(compose_file),
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
            env=env,
        )
        status = self._status_from_execution(execution)
        endpoint_host = endpoint.get("Host")

        return self._result(
            request,
            status,
            native_executable=execution.executable,
            arguments=execution.command[1:],
            execution_started=self._execution_started(execution),
            returncode=execution.returncode,
            stdout=execution.stdout,
            stderr=execution.stderr,
            reason=execution.reason,
            target_details={
                "context": context,
                "endpoint_host": endpoint_host,
                "daemon": daemon,
                "enforcement_verified": False,
                "acceptance_required": True,
            },
            execution=execution,
            elevation_required=False,
        )

    # ------------------------------------------------------------------
    # Validation and result helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _project_label_matches(resource: Any, project: str) -> bool:
        if not isinstance(resource, dict):
            return False
        labels = resource.get("labels")
        return (
            isinstance(labels, dict)
            and labels.get("com.docker.compose.project") == project
        )

    @staticmethod
    def _trusted_repository_root(path: Path | None) -> Path:
        if not isinstance(path, Path):
            raise ValueError("repository root must be a Path")
        root = path.resolve(strict=True)
        if not root.is_dir() or path.is_symlink():
            raise ValueError("repository root must be a real directory")
        return root

    @staticmethod
    def _endpoint_locality(endpoint: Any) -> str:
        if not isinstance(endpoint, str):
            return "unknown"
        if endpoint.startswith("unix://"):
            return "local-unix-socket"
        if endpoint.startswith("ssh://"):
            return "remote-ssh"
        if endpoint.startswith(("tcp://", "http://", "https://")):
            return "remote-network"
        if endpoint.startswith("npipe://"):
            return "windows-named-pipe"
        return "unclassified"

    @classmethod
    def _docker_target_kind(
        cls,
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
        return cls._endpoint_locality(endpoint)

    @staticmethod
    def _execution_started(execution: CommandExecution) -> bool:
        return execution.returncode is not None or execution.timed_out

    @staticmethod
    def _status_from_execution(
        execution: CommandExecution,
    ) -> OSActionStatus:
        if execution.timed_out:
            return OSActionStatus.TIMED_OUT
        if execution.status is EnforcementStatus.PASS:
            return OSActionStatus.SUCCEEDED
        if execution.status is EnforcementStatus.BLOCKED:
            return OSActionStatus.BLOCKED
        if execution.returncode is None:
            reason = (execution.reason or "").lower()
            if "unavailable" in reason or "cannot execute" in reason:
                return OSActionStatus.TARGET_UNAVAILABLE
            return OSActionStatus.FAILED
        return OSActionStatus.FAILED

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
        elevation_required: bool | None = None,
    ) -> OSActionResult:
        if elevation_required is None:
            elevation_required = request.platform in {
                "linux", "wsl", "windows",
            }

        return OSActionResult(
            operation=request.operation,
            platform=request.platform,
            target=request.target,
            status=status,
            approval_reference=request.approval_reference,
            native_executable=native_executable,
            arguments=arguments,
            elevation_required=elevation_required,
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
    docker_adapter: DockerAdapter | None = None,
) -> OSActionResult:
    """Execute one registered action and return its native outcome."""
    return OSActionExecutor(
        runner=runner,
        daemon_inspector=daemon_inspector,
        docker_adapter=docker_adapter,
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
    """Run a firewall-helper action for the current Linux/WSL target."""
    operation = f"network-boundary.{action}"
    is_wsl = (
        platform.system() == "Linux"
        and "microsoft" in platform.release().lower()
    )

    request = OSActionRequest(
        platform="wsl" if is_wsl else "linux",
        operation=operation,
        target=project,
        repository_root=repository_root,
        policy_file=policy_file,
        docker_context=docker_context,
    )

    if operation not in _BOUNDARY_ACTIONS:
        return OSActionExecutor._result(
            request,
            OSActionStatus.UNSUPPORTED,
            reason="unsupported network-boundary operation",
        )

    return OSActionExecutor(
        runner=runner or subprocess.run,
        daemon_inspector=daemon_inspector or inspect_daemon,
    ).execute(request, environment=environment)
