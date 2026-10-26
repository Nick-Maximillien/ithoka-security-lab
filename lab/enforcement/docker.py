
"""Docker mutation adapter.

Observations are delegated to lab/osapi/docker.
This module owns state-changing Docker commands, not inventory inspection.

Important:
- A successful Docker command is not runtime acceptance.
- Docker network containment changes topology and can disrupt service discovery.
- Container security settings such as privileged mode, capabilities, mounts,
  devices and namespaces generally cannot be safely repaired in place.
  Unsafe running containers are stopped and must be recreated compliantly.
- This adapter does not claim to enforce Windows Firewall, arbitrary host routes,
  all proxy/DNS paths, or packet-level isolation.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping

from .models import (
    AcceptanceStatus,
    EnforcementResult,
    EnforcementScope,
    EnforcementStatus,
    MutationOutcome,
)


_PROJECT_RE = re.compile(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}")
_CONTEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_CONTAINER_ID_RE = re.compile(r"[a-f0-9]{12,64}")
_NETWORK_ID_RE = re.compile(r"[a-f0-9]{12,64}")
_OWNER_LABEL = "io.ithoka.lab.owner"
_PURPOSE_LABEL = "io.ithoka.lab.purpose"
_INTERNAL_NETWORK_PURPOSE = "enforcement-internal"
_PROJECT_LABEL = "com.docker.compose.project"

_UNSUPPORTED_BOUNDARIES = {
    "lab_ingress",
    "lab_egress",
    "windows_host",
    "external_networks",
    "dns",
    "proxies",
    "ipv4",
    "ipv6",
    "filesystem",
    "capture",
}

_RESOURCE_ACCESS_BOUNDARY = "resource_access"
_DOCKER_NETWORK_BOUNDARY = "docker_networks"


def _valid_project(project: str) -> bool:
    return bool(_PROJECT_RE.fullmatch(project))


def _valid_context(context: str | None) -> bool:
    return context is None or bool(_CONTEXT_RE.fullmatch(context))


def _status_from_observation(observation: Any) -> EnforcementStatus:
    value = getattr(observation, "status", None)
    try:
        return EnforcementStatus(getattr(value, "value", value))
    except (ValueError, TypeError):
        return EnforcementStatus.UNKNOWN


def _values_from_observation(observation: Any) -> list[dict[str, Any]]:
    values = getattr(observation, "values", None)
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]


def _boundary_policy(
    policy: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Accept the resolved boundary mapping, not raw profile inheritance.

    Supported shapes:
        {"boundaries": {"docker_networks": {"enabled": True, "mode": "deny"}}}
        {"docker_networks": {"enabled": True, "mode": "deny"}}

    The policy resolver remains responsible for canonical definitions,
    profile overrides, investigation overrides and fixed safeguards.
    """
    raw = policy.get("boundaries", policy)
    if not isinstance(raw, Mapping):
        raise ValueError("Resolved policy must contain a boundary mapping")

    result: dict[str, dict[str, Any]] = {}
    for name, value in raw.items():
        if isinstance(name, str) and isinstance(value, Mapping):
            result[name] = dict(value)
    return result


def _enabled_deny(boundary: Mapping[str, Any]) -> bool:
    enabled = boundary.get("enabled", True)
    mode = str(boundary.get("mode", "")).strip().lower()
    return enabled is True and mode == "deny"


def _run(
    args: list[str],
    *,
    runner: Any,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one explicit Docker CLI operation without invoking a shell."""
    try:
        result = runner(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=dict(env) if env is not None else None,
        )
    except TypeError:
        # Support small injected test runners with a narrower signature.
        result = runner(args)

    if not hasattr(result, "returncode"):
        raise RuntimeError("Docker runner returned no process return code")
    return result


def _command_details(
    result: subprocess.CompletedProcess[str],
) -> dict[str, Any]:
    """Keep command output bounded and avoid returning environment contents."""
    stdout = str(getattr(result, "stdout", "") or "").strip()
    stderr = str(getattr(result, "stderr", "") or "").strip()
    return {
        "returncode": result.returncode,
        "stdout": stdout[-2000:],
        "stderr": stderr[-2000:],
    }


class DockerAdapter:
    """Apply supported Docker mutations to an owned Compose project."""

    def __init__(
        self,
        root: Path = Path("."),
        runner: Any = subprocess.run,
        inspector: Any | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.runner = runner
        # Retained for compatibility with earlier callers. This is not used
        # as an enforcement implementation or as a replacement OS API.
        self.inspector = inspector
        self.env = dict(env) if env is not None else None

    def _docker_args(self, context: str | None, *args: str) -> list[str]:
        if not _valid_context(context):
            raise ValueError("Invalid Docker context name")
        prefix = ["docker"]
        if context:
            prefix.extend(["--context", context])
        return prefix + list(args)

    def _result(
        self,
        *,
        project: str,
        context: str | None,
        status: EnforcementStatus,
        reason: str,
        outcomes: list[MutationOutcome] | None = None,
        findings: list[dict[str, Any]] | None = None,
        details: dict[str, Any] | None = None,
    ) -> EnforcementResult:
        return EnforcementResult(
            operation="apply",
            status=status,
            scope=EnforcementScope(
                platform="docker",
                adapter="docker-compose-mutation",
                project=project,
                docker_context=context,
            ),
            read_only=False,
            reason=reason,
            findings=tuple(findings or []),
            details={
                "mutation_applied": any(
                    item.changed for item in (outcomes or [])
                ),
                "runtime_acceptance_required": True,
                "acceptance_note": (
                    "Mutation success is not proof of effective isolation. "
                    "Run independent runtime acceptance tests."
                ),
                **(details or {}),
            },
            acceptance_status=AcceptanceStatus.NOT_RUN,
            outcomes=tuple(outcomes or []),
        )

    def _observe_project(
        self,
        project: str,
        context: str | None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
        """Read state through the existing OS API adapters."""
        from ..osapi.docker.containers import inspect_containers
        from ..osapi.docker.networks import inspect_networks

        containers_observation = inspect_containers(
            project,
            context or "default",
            runner=self.runner,
            env=self.env,
        )
        networks_observation = inspect_networks(
            context or "default",
            project=project,
            runner=self.runner,
            env=self.env,
        )

        errors: list[str] = []
        if _status_from_observation(containers_observation) is not EnforcementStatus.PASS:
            errors.append("Docker container observation failed")
        if _status_from_observation(networks_observation) is not EnforcementStatus.PASS:
            errors.append("Docker network observation failed")

        return (
            _values_from_observation(containers_observation),
            _values_from_observation(networks_observation),
            errors,
        )

    @staticmethod
    def _container_id(container: Mapping[str, Any]) -> str | None:
        value = container.get("id")
        if not isinstance(value, str):
            return None
        value = value.removeprefix("sha256:")
        return value if _CONTAINER_ID_RE.fullmatch(value) else None

    @staticmethod
    def _network_attachments(
        container: Mapping[str, Any],
    ) -> list[str]:
        network_data = container.get("network")
        if not isinstance(network_data, Mapping):
            return []

        networks = network_data.get("networks")
        if isinstance(networks, Mapping):
            return [
                name for name in networks
                if isinstance(name, str) and name
            ]

        if isinstance(networks, list):
            result: list[str] = []
            for item in networks:
                if isinstance(item, str) and item:
                    result.append(item)
                elif isinstance(item, Mapping):
                    name = item.get("name") or item.get("network")
                    if isinstance(name, str) and name:
                        result.append(name)
            return result

        return []

    @staticmethod
    def _is_internal(network: Mapping[str, Any]) -> bool:
        # Unknown is not equivalent to internal.
        return network.get("internal") is True

    @staticmethod
    def _resource_violations(
        container: Mapping[str, Any],
    ) -> list[str]:
        """Identify mandatory safeguards visible in the existing observation."""
        violations: list[str] = []
        security = container.get("security")
        if not isinstance(security, Mapping):
            return ["security configuration unavailable"]

        if security.get("privileged") is True:
            violations.append("privileged mode enabled")

        caps_drop = security.get("cap_drop")
        if not isinstance(caps_drop, list) or "ALL" not in {
            str(item).upper() for item in caps_drop
        }:
            violations.append("CAP_DROP ALL not confirmed")

        cap_add = security.get("cap_add")
        if cap_add not in (None, [], ()):
            violations.append("capability additions present")

        if security.get("no_new_privileges") is not True:
            violations.append("no-new-privileges not confirmed")

        if security.get("read_only_root") is not True:
            violations.append("read-only root filesystem not confirmed")

        if security.get("host_network") is True:
            violations.append("host network namespace requested")
        if security.get("host_pid") is True:
            violations.append("host PID namespace requested")
        if security.get("host_ipc") is True:
            violations.append("host IPC namespace requested")

        mounts = security.get("mounts")
        if isinstance(mounts, list):
            for mount in mounts:
                if not isinstance(mount, Mapping):
                    continue
                source = str(mount.get("source", "")).lower()
                target = str(mount.get("target", "")).lower()
                if source.endswith("/docker.sock") or target.endswith("/docker.sock"):
                    violations.append("Docker socket exposure")
                    break

        return violations

    def apply(
        self,
        project: str,
        policy: Mapping[str, Any],
        *,
        context: str | None = None,
        approve_disruptive_changes: bool = False,
    ) -> EnforcementResult:
        """Apply supported Docker mutations for a resolved boundary policy.

        This operation is intentionally conservative:
        - It never edits Compose files behind the caller's back.
        - It never silently claims unsupported boundaries are enforced.
        - It will not disconnect networks or stop containers without explicit
          approval because these actions can disrupt an investigation.
        - It does not claim runtime acceptance.
        """
        if not _valid_project(project):
            return self._result(
                project=str(project),
                context=context,
                status=EnforcementStatus.BLOCKED,
                reason="Project identifier is invalid; no mutation attempted",
            )

        if not _valid_context(context):
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.BLOCKED,
                reason="Docker context is invalid; no mutation attempted",
            )

        try:
            boundaries = _boundary_policy(policy)
        except (TypeError, ValueError) as exc:
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.BLOCKED,
                reason=f"Policy was not a resolved boundary mapping: {exc}",
            )

        requested = {
            name for name, boundary in boundaries.items()
            if boundary.get("enabled", True) is True
        }
        unsupported = sorted(
            name for name in requested
            if name in _UNSUPPORTED_BOUNDARIES
        )

        # A policy that explicitly enables a boundary we cannot enforce must
        # not be reported as successfully enforced.
        if unsupported:
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.BLOCKED,
                reason=(
                    "Docker adapter cannot independently enforce these "
                    "boundaries: " + ", ".join(unsupported)
                ),
                findings=[
                    {
                        "boundary": name,
                        "status": "UNSUPPORTED_BY_DOCKER_ADAPTER",
                    }
                    for name in unsupported
                ],
                details={
                    "unsupported_boundaries": unsupported,
                    "no_mutations_attempted": True,
                },
            )

        network_policy = boundaries.get(_DOCKER_NETWORK_BOUNDARY)
        resource_policy = boundaries.get(_RESOURCE_ACCESS_BOUNDARY)

        if not network_policy and not resource_policy:
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.NOT_APPLICABLE,
                reason="Policy requests no Docker mutation supported by this adapter",
            )

        if network_policy and not _enabled_deny(network_policy):
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.BLOCKED,
                reason=(
                    "docker_networks mode is not supported by this mutation "
                    "adapter unless explicitly enabled with mode='deny'; "
                    "restricted/allow modes fail closed"
                ),
                findings=[
                    {
                        "boundary": _DOCKER_NETWORK_BOUNDARY,
                        "requested_mode": network_policy.get("mode"),
                    }
                ],
            )

        if resource_policy and not _enabled_deny(resource_policy):
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.BLOCKED,
                reason=(
                    "resource_access must remain an enabled deny-mode "
                    "safeguard; it cannot be relaxed by a profile"
                ),
            )

        try:
            containers, networks, observation_errors = self._observe_project(
                project,
                context,
            )
        except Exception as exc:
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.FAIL,
                reason=f"Could not obtain required pre-mutation observations: {exc}",
            )

        if observation_errors:
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.FAIL,
                reason="Required Docker observations failed; no mutation attempted",
                findings=[{"error": error} for error in observation_errors],
            )

        invalid_containers = [
            container for container in containers
            if self._container_id(container) is None
        ]
        if invalid_containers:
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.FAIL,
                reason="Container observation included invalid or missing IDs",
            )

        outcomes: list[MutationOutcome] = []
        findings: list[dict[str, Any]] = []

        # Resource-access safeguards are not repairable through docker update.
        # Stop any violating running container only with explicit approval.
        if resource_policy:
            for container in containers:
                violations = self._resource_violations(container)
                if not violations:
                    continue

                container_id = self._container_id(container)
                running = container.get("running") is True
                findings.append({
                    "boundary": _RESOURCE_ACCESS_BOUNDARY,
                    "container": container.get("name"),
                    "container_id": container_id,
                    "violations": violations,
                    "action_required": (
                        "stop_then_recreate_with_compliant_configuration"
                        if running else
                        "recreate_with_compliant_configuration"
                    ),
                })

                if not running:
                    outcomes.append(MutationOutcome(
                        boundary=_RESOURCE_ACCESS_BOUNDARY,
                        action="reject_noncompliant_container",
                        resource=str(container_id),
                        status=EnforcementStatus.FAIL,
                        reason="Stopped container has noncompliant immutable configuration",
                        changed=False,
                        details={"violations": violations},
                    ))
                    continue

                if not approve_disruptive_changes:
                    outcomes.append(MutationOutcome(
                        boundary=_RESOURCE_ACCESS_BOUNDARY,
                        action="stop_container",
                        resource=str(container_id),
                        status=EnforcementStatus.BLOCKED,
                        reason="Stopping this container requires explicit approval",
                        changed=False,
                        details={"violations": violations},
                    ))
                    continue

                try:
                    result = _run(
                        self._docker_args(
                            context, "container", "stop", "--time", "5", container_id
                        ),
                        runner=self.runner,
                        env=self.env,
                    )
                    ok = result.returncode == 0
                    outcomes.append(MutationOutcome(
                        boundary=_RESOURCE_ACCESS_BOUNDARY,
                        action="stop_container",
                        resource=container_id,
                        status=(
                            EnforcementStatus.PASS
                            if ok else EnforcementStatus.FAIL
                        ),
                        reason=(
                            "Noncompliant container stopped"
                            if ok else "Docker failed to stop noncompliant container"
                        ),
                        changed=ok,
                        details=_command_details(result),
                    ))
                except Exception as exc:
                    outcomes.append(MutationOutcome(
                        boundary=_RESOURCE_ACCESS_BOUNDARY,
                        action="stop_container",
                        resource=container_id,
                        status=EnforcementStatus.FAIL,
                        reason=f"Container stop operation failed: {exc}",
                    ))

        # Network containment uses one project-owned internal bridge. It
        # disconnects project containers from other networks, which can alter
        # service discovery and intentionally removes other network paths.
        if network_policy:
            if not approve_disruptive_changes:
                return self._result(
                    project=project,
                    context=context,
                    status=EnforcementStatus.BLOCKED,
                    reason=(
                        "Applying Docker network containment changes container "
                        "connectivity; explicit disruptive-change approval is required"
                    ),
                    outcomes=outcomes,
                    findings=findings,
                    details={"no_network_mutations_attempted": True},
                )

            internal_network_name = f"{project}-enforced-internal"
            if len(internal_network_name) > 63:
                return self._result(
                    project=project,
                    context=context,
                    status=EnforcementStatus.BLOCKED,
                    reason="Derived internal network name exceeds the supported limit",
                    outcomes=outcomes,
                    findings=findings,
                )

            matching = [
                network for network in networks
                if network.get("name") == internal_network_name
            ]
            network_ready = bool(matching) and all(
                self._is_internal(network) for network in matching
            )

            if matching and not network_ready:
                return self._result(
                    project=project,
                    context=context,
                    status=EnforcementStatus.FAIL,
                    reason=(
                        "A network with the enforcement name already exists "
                        "but is not confirmed internal; refusing to reuse it"
                    ),
                    outcomes=outcomes,
                    findings=findings,
                )

            if not network_ready:
                try:
                    result = _run(
                        self._docker_args(
                            context,
                            "network", "create",
                            "--driver", "bridge",
                            "--internal",
                            "--label", f"{_OWNER_LABEL}={project}",
                            "--label", f"{_PURPOSE_LABEL}={_INTERNAL_NETWORK_PURPOSE}",
                            "--label", f"{_PROJECT_LABEL}={project}",
                            internal_network_name,
                        ),
                        runner=self.runner,
                        env=self.env,
                    )
                    ok = result.returncode == 0
                    created_id = str(result.stdout or "").strip()
                    if ok and not _NETWORK_ID_RE.fullmatch(created_id):
                        # A successful create must return an identifiable
                        # network before it can be used for further mutations.
                        outcomes.append(MutationOutcome(
                            boundary=_DOCKER_NETWORK_BOUNDARY,
                            action="create_internal_network",
                            resource=internal_network_name,
                            status=EnforcementStatus.FAIL,
                            reason="Docker did not return a valid network ID",
                            changed=True,
                            details=_command_details(result),
                        ))
                        return self._result(
                            project=project,
                            context=context,
                            status=EnforcementStatus.FAIL,
                            reason="Network creation returned an unusable identifier",
                            outcomes=outcomes,
                            findings=findings,
                        )

                    outcomes.append(MutationOutcome(
                        boundary=_DOCKER_NETWORK_BOUNDARY,
                        action="create_internal_network",
                        resource=internal_network_name,
                        status=(
                            EnforcementStatus.PASS
                            if ok else EnforcementStatus.FAIL
                        ),
                        reason=(
                            "Internal Docker network created"
                            if ok else "Docker failed to create internal network"
                        ),
                        changed=ok,
                        details=_command_details(result),
                    ))
                    if not ok:
                        return self._result(
                            project=project,
                            context=context,
                            status=EnforcementStatus.FAIL,
                            reason="Could not create internal Docker network",
                            outcomes=outcomes,
                            findings=findings,
                        )
                except Exception as exc:
                    outcomes.append(MutationOutcome(
                        boundary=_DOCKER_NETWORK_BOUNDARY,
                        action="create_internal_network",
                        resource=internal_network_name,
                        status=EnforcementStatus.FAIL,
                        reason=f"Network creation failed: {exc}",
                    ))
                    return self._result(
                        project=project,
                        context=context,
                        status=EnforcementStatus.FAIL,
                        reason="Could not create internal Docker network",
                        outcomes=outcomes,
                        findings=findings,
                    )

            # Attach first, then disconnect other networks. If a container
            # cannot be attached, do not proceed to disconnect its existing
            # network paths.
            for container in containers:
                container_id = self._container_id(container)
                if not container_id:
                    continue

                attachments = self._network_attachments(container)
                already_attached = internal_network_name in attachments

                if not already_attached:
                    try:
                        result = _run(
                            self._docker_args(
                                context,
                                "network", "connect",
                                "--alias", str(container.get("name") or container_id),
                                internal_network_name,
                                container_id,
                            ),
                            runner=self.runner,
                            env=self.env,
                        )
                        ok = result.returncode == 0
                        outcomes.append(MutationOutcome(
                            boundary=_DOCKER_NETWORK_BOUNDARY,
                            action="connect_internal_network",
                            resource=container_id,
                            status=(
                                EnforcementStatus.PASS
                                if ok else EnforcementStatus.FAIL
                            ),
                            reason=(
                                "Container attached to internal network"
                                if ok else "Docker failed to attach container"
                            ),
                            changed=ok,
                            details=_command_details(result),
                        ))
                        if not ok:
                            continue
                    except Exception as exc:
                        outcomes.append(MutationOutcome(
                            boundary=_DOCKER_NETWORK_BOUNDARY,
                            action="connect_internal_network",
                            resource=container_id,
                            status=EnforcementStatus.FAIL,
                            reason=f"Container attachment failed: {exc}",
                        ))
                        continue

                for network_name in attachments:
                    if network_name == internal_network_name:
                        continue

                    # Do not disconnect networks that the observations already
                    # confirm are internal; this adapter is only responsible
                    # for removing alternative network paths for this policy.
                    observed_network = next(
                        (
                            item for item in networks
                            if item.get("name") == network_name
                        ),
                        None,
                    )
                    if observed_network is not None and self._is_internal(observed_network):
                        continue

                    try:
                        result = _run(
                            self._docker_args(
                                context,
                                "network", "disconnect",
                                "--force",
                                network_name,
                                container_id,
                            ),
                            runner=self.runner,
                            env=self.env,
                        )
                        ok = result.returncode == 0
                        outcomes.append(MutationOutcome(
                            boundary=_DOCKER_NETWORK_BOUNDARY,
                            action="disconnect_alternative_network",
                            resource=f"{container_id}@{network_name}",
                            status=(
                                EnforcementStatus.PASS
                                if ok else EnforcementStatus.FAIL
                            ),
                            reason=(
                                "Alternative network attachment removed"
                                if ok else "Docker failed to remove network attachment"
                            ),
                            changed=ok,
                            details=_command_details(result),
                        ))
                    except Exception as exc:
                        outcomes.append(MutationOutcome(
                            boundary=_DOCKER_NETWORK_BOUNDARY,
                            action="disconnect_alternative_network",
                            resource=f"{container_id}@{network_name}",
                            status=EnforcementStatus.FAIL,
                            reason=f"Network disconnection failed: {exc}",
                        ))

        failed = [
            outcome for outcome in outcomes
            if outcome.status is not EnforcementStatus.PASS
            and outcome.status is not EnforcementStatus.NOT_APPLICABLE
        ]
        if failed:
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.FAIL,
                reason=(
                    f"{len(failed)} mandatory Docker mutation outcome(s) "
                    "did not pass"
                ),
                outcomes=outcomes,
                findings=findings,
            )

        # A resource-access policy cannot be passed just because no running
        # container needed stopping: every relevant container must have had
        # the required fields available and must satisfy the fixed safeguards.
        if resource_policy and findings:
            return self._result(
                project=project,
                context=context,
                status=EnforcementStatus.FAIL,
                reason=(
                    "Noncompliant container configuration remains; recreate "
                    "containers with mandatory safeguards before continuing"
                ),
                outcomes=outcomes,
                findings=findings,
            )

        return self._result(
            project=project,
            context=context,
            status=EnforcementStatus.PASS,
            reason="Requested supported Docker mutations completed",
            outcomes=outcomes,
            findings=findings,
            details={
                "supported_mutations": sorted({
                    outcome.action for outcome in outcomes
                    if outcome.status is EnforcementStatus.PASS
                }),
                "unsupported_runtime_claims": [
                    "packet-level ingress/egress acceptance",
                    "Windows Firewall enforcement",
                    "host and upstream route isolation",
                    "DNS and proxy bypass acceptance",
                    "filesystem isolation against all host access paths",
                ],
            },
        )

    def inspect_os_api(
        self,
        project: str | None = None,
        context: str | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Expose existing OS API observations without duplicating inspection."""
        from ..osapi import inspect_docker

        return {
            name: observation.to_dict()
            for name, observation in inspect_docker(project, context).items()
        }

    def inspect(self, project: str) -> EnforcementResult:
        """Deprecated compatibility shim; observations belong in lab/osapi."""
        return EnforcementResult(
            operation="inspect",
            status=EnforcementStatus.NOT_APPLICABLE,
            scope=EnforcementScope(
                platform="docker",
                adapter="docker-compose-mutation",
                project=project,
            ),
            read_only=True,
            reason=(
                "DockerAdapter is a mutation adapter. Use lab/osapi/docker "
                "for observations."
            ),
            details={"deprecated_api": True},
        )

    def verify(self, project: str) -> EnforcementResult:
        """Compatibility shim; verification must be an explicit acceptance run."""
        return EnforcementResult(
            operation="verify",
            status=EnforcementStatus.NOT_APPLICABLE,
            scope=EnforcementScope(
                platform="docker",
                adapter="docker-compose-mutation",
                project=project,
            ),
            read_only=True,
            reason=(
                "No runtime acceptance runner is wired to this adapter. "
                "Use a dedicated acceptance operation; inspection alone is insufficient."
            ),
            acceptance_status=AcceptanceStatus.NOT_RUN,
        )


def inspect_docker_project(
    project: str,
    root: Path = Path("."),
    runner: Any = subprocess.run,
) -> dict[str, Any]:
    """Legacy compatibility entry point.

    Kept temporarily so existing imports do not break. It no longer performs
    inspection through the mutation adapter.
    """
    return DockerAdapter(root=root, runner=runner).inspect(project).to_dict()
