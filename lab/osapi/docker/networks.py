
"""Read-only Docker daemon, network, container, and published-port inspection.

This module observes Docker configuration. It does not create, modify, or remove
Docker resources, install firewall rules, or claim that observed configuration
proves effective network or host isolation.

Project-scoped inspection uses the Docker Compose project label. A successful
inspection means the requested information was collected and parsed; it does
not mean any security boundary passed runtime acceptance.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation


_PROJECT_RE = re.compile(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}")
_CONTEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_RESOURCE_ID_RE = re.compile(r"[0-9a-fA-F]{12,64}")
_PROJECT_LABEL = "com.docker.compose.project"


def _options(
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build run_command options without changing the caller's environment."""
    result: dict[str, Any] = {}
    if runner is not None:
        result["runner"] = runner
    if env is not None:
        result["env"] = env
    return result


def _validate_scope(
    context: str,
    project: str | None,
) -> str | None:
    """Return a validation error, or None if the inspection scope is valid."""
    if not isinstance(context, str) or not _CONTEXT_RE.fullmatch(context):
        return "invalid Docker context identifier"

    if project is not None:
        if not isinstance(project, str) or not _PROJECT_RE.fullmatch(project):
            return "invalid lab project identifier"

    return None


def _observation(
    resource: str,
    operation: str,
    target: str,
    *,
    status: EnforcementStatus,
    timestamp: str = "",
    values: Any = None,
    execution: Any = None,
    parsed: bool = False,
    errors: tuple[str, ...] = (),
    coverage_limitations: tuple[str, ...] = (),
) -> OSObservation:
    """Create a consistent observation using the existing OSObservation model."""
    return OSObservation(
        "docker",
        resource,
        operation,
        target,
        "Docker Engine",
        timestamp,
        status,
        values=values,
        execution=execution,
        parsed=parsed,
        errors=errors,
        coverage_limitations=coverage_limitations,
    )


def _run(
    command: list[str],
    *,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> Any:
    """Execute an allowlisted, shell-free Docker CLI argument vector."""
    return run_command(command, **_options(runner=runner, env=env))


def _failure(
    resource: str,
    operation: str,
    target: str,
    execution: Any,
    message: str,
) -> OSObservation:
    """Report a failed or unavailable observation without implying enforcement."""
    reason = getattr(execution, "reason", None)
    detail = reason or message

    return _observation(
        resource,
        operation,
        target,
        status=EnforcementStatus.UNKNOWN,
        timestamp=getattr(execution, "finished_utc", ""),
        execution=execution,
        errors=(detail,),
        coverage_limitations=(
            "Inspection failure does not establish whether the requested "
            "Docker resources or security controls exist.",
        ),
    )


def _list_ids(
    *,
    context: str,
    resource: str,
    project: str | None,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> tuple[Any | None, list[str] | None, str | None]:
    """List full resource IDs and validate the CLI output."""
    prefix = ["docker", "--context", context]

    if resource == "networks":
        command = [*prefix, "network", "ls", "-q", "--no-trunc"]
    elif resource == "containers":
        command = [*prefix, "container", "ls", "-aq", "--no-trunc"]
    else:
        return None, None, f"unsupported Docker resource: {resource}"

    if project is not None:
        command.extend(
            ["--filter", f"label={_PROJECT_LABEL}={project}"]
        )

    execution = _run(command, runner=runner, env=env)

    if execution.status is not EnforcementStatus.PASS:
        return execution, None, (
            getattr(execution, "reason", None)
            or f"Docker {resource} listing failed"
        )

    identifiers = execution.stdout.split()

    if any(not _RESOURCE_ID_RE.fullmatch(item) for item in identifiers):
        return execution, None, f"Docker returned malformed {resource} ID"

    if len(identifiers) != len(set(identifiers)):
        return execution, None, f"Docker returned duplicate {resource} IDs"

    return execution, identifiers, None


def _inspect_json(
    *,
    context: str,
    resource: str,
    identifiers: list[str],
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> tuple[Any | None, list[dict[str, Any]] | None, str | None]:
    """Inspect validated IDs and parse Docker's JSON array."""
    if not identifiers:
        return None, [], None

    command = ["docker", "--context", context]

    if resource == "networks":
        command.extend(["network", "inspect", *identifiers])
    elif resource == "containers":
        command.extend(["container", "inspect", *identifiers])
    else:
        return None, None, f"unsupported Docker resource: {resource}"

    execution = _run(command, runner=runner, env=env)

    if execution.status is not EnforcementStatus.PASS:
        return execution, None, (
            getattr(execution, "reason", None)
            or f"Docker {resource} inspection failed"
        )

    try:
        result = json.loads(execution.stdout)

        if not isinstance(result, list):
            raise ValueError("Docker inspection result must be a JSON array")

        if len(result) != len(identifiers):
            raise ValueError(
                "Docker inspection result count does not match listed IDs"
            )

        if not all(isinstance(item, dict) for item in result):
            raise ValueError("Docker inspection entries must be objects")

        returned_ids = [item.get("Id") for item in result]
        if any(
            not isinstance(item, str)
            or not _RESOURCE_ID_RE.fullmatch(item)
            for item in returned_ids
        ):
            raise ValueError("Docker inspection returned a malformed resource ID")

        if set(returned_ids) != set(identifiers):
            raise ValueError(
                "Docker inspection IDs do not match the listed resource IDs"
            )

    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return execution, None, str(exc)

    return execution, result, None


def inspect_daemon(
    context: str = "default",
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> OSObservation:
    """Inspect Docker daemon availability, version, security options and storage.

    The selected Docker context is explicit. This function does not change
    contexts, start the daemon, or modify daemon configuration.
    """
    error = _validate_scope(context, None)
    if error:
        return _observation(
            "daemon",
            "inspect",
            context if isinstance(context, str) else "invalid",
            status=EnforcementStatus.BLOCKED,
            errors=(error,),
        )

    prefix = ["docker", "--context", context]

    version = _run(
        [*prefix, "version", "--format", "{{json .}}"],
        runner=runner,
        env=env,
    )
    if version.status is not EnforcementStatus.PASS:
        return _failure("daemon", "inspect", context, version,
                        "Docker version query failed")

    info = _run(
        [*prefix, "info", "--format", "{{json .}}"],
        runner=runner,
        env=env,
    )
    if info.status is not EnforcementStatus.PASS:
        return _failure("daemon", "inspect", context, info,
                        "Docker daemon information query failed")

    try:
        version_data = json.loads(version.stdout)
        info_data = json.loads(info.stdout)

        if not isinstance(version_data, dict):
            raise ValueError("Docker version result must be an object")
        if not isinstance(info_data, dict):
            raise ValueError("Docker info result must be an object")

        client = version_data.get("Client", {})
        server = version_data.get("Server", {})
        client_version = (
            client.get("Version") if isinstance(client, dict) else None
        )
        server_version = (
            server.get("Version") if isinstance(server, dict) else None
        )

        security_options = info_data.get("SecurityOptions", [])
        if not isinstance(security_options, list):
            raise ValueError("Docker SecurityOptions must be a list")

        values = [{
            "context": context,
            "client_version": client_version,
            "server_version": server_version,
            "server_api_version": (
                server.get("ApiVersion") if isinstance(server, dict) else None
            ),
            "operating_system": info_data.get("OperatingSystem"),
            "architecture": info_data.get("Architecture"),
            "kernel_version": info_data.get("KernelVersion"),
            "os_type": info_data.get("OSType"),
            "daemon_name": info_data.get("Name"),
            "driver": info_data.get("Driver"),
            "security_options": security_options,
            "live_restore_enabled": info_data.get("LiveRestoreEnabled"),
            "warnings": info_data.get("Warnings"),
        }]

    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return _observation(
            "daemon",
            "inspect",
            context,
            status=EnforcementStatus.UNKNOWN,
            timestamp=getattr(info, "finished_utc", ""),
            execution=info,
            parsed=False,
            errors=(str(exc),),
        )

    return _observation(
        "daemon",
        "inspect",
        context,
        status=EnforcementStatus.PASS,
        timestamp=getattr(info, "finished_utc", ""),
        values=values,
        execution=info,
        parsed=True,
        coverage_limitations=(
            "Daemon metadata does not prove that host permissions, firewall "
            "rules, or network isolation are effective.",
            "SecurityOptions describes reported daemon configuration; it is "
            "not a runtime acceptance test for container restrictions.",
        ),
    )


def inspect_networks(
    context: str,
    project: str | None = None,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> OSObservation:
    """Inspect Docker network IDs, drivers, endpoints, labels and IPAM."""
    error = _validate_scope(context, project)
    target = project or "all"

    if error:
        return _observation(
            "networks", "inspect", target,
            status=EnforcementStatus.BLOCKED,
            errors=(error,),
        )

    listing, identifiers, list_error = _list_ids(
        context=context,
        resource="networks",
        project=project,
        runner=runner,
        env=env,
    )

    if list_error:
        return _failure(
            "networks", "inspect", target, listing, list_error
        )

    assert identifiers is not None

    if not identifiers:
        return _observation(
            "networks", "inspect", target,
            status=EnforcementStatus.PASS,
            timestamp=getattr(listing, "finished_utc", ""),
            values=[],
            execution=listing,
            parsed=True,
            coverage_limitations=(
                "An empty network listing does not establish isolation.",
            ),
        )

    inspected, networks, inspect_error = _inspect_json(
        context=context,
        resource="networks",
        identifiers=identifiers,
        runner=runner,
        env=env,
    )

    if inspect_error:
        return _failure(
            "networks", "inspect", target, inspected, inspect_error
        )

    assert networks is not None

    values = []
    for network in networks:
        ipam = network.get("IPAM")
        if not isinstance(ipam, dict):
            ipam = {}

        containers = network.get("Containers")
        if containers is not None and not isinstance(containers, dict):
            return _observation(
                "networks", "inspect", target,
                status=EnforcementStatus.UNKNOWN,
                timestamp=getattr(inspected, "finished_utc", ""),
                execution=inspected,
                parsed=False,
                errors=("network Containers field must be an object or null",),
            )

        labels = network.get("Labels")
        options = network.get("Options")
        if labels is not None and not isinstance(labels, dict):
            return _observation(
                "networks", "inspect", target,
                status=EnforcementStatus.UNKNOWN,
                timestamp=getattr(inspected, "finished_utc", ""),
                execution=inspected,
                parsed=False,
                errors=("network Labels field must be an object or null",),
            )

        if options is not None and not isinstance(options, dict):
            return _observation(
                "networks", "inspect", target,
                status=EnforcementStatus.UNKNOWN,
                timestamp=getattr(inspected, "finished_utc", ""),
                execution=inspected,
                parsed=False,
                errors=("network Options field must be an object or null",),
            )

        values.append({
            "id": network.get("Id"),
            "name": network.get("Name"),
            "driver": network.get("Driver"),
            "scope": network.get("Scope"),
            "internal": network.get("Internal"),
            "enable_ipv6": network.get("EnableIPv6"),
            "attachable": network.get("Attachable"),
            "ingress": network.get("Ingress"),
            "labels": labels or {},
            "ipam": ipam.get("Config"),
            "ipam_driver": ipam.get("Driver"),
            "containers": containers or {},
            "options": options or {},
        })

    return _observation(
        "networks", "inspect", target,
        status=EnforcementStatus.PASS,
        timestamp=getattr(inspected, "finished_utc", ""),
        values=values,
        execution=inspected,
        parsed=True,
        coverage_limitations=(
            "Docker network metadata does not prove effective packet filtering.",
            "Network inspection does not prove isolation from the host, WSL, "
            "other interfaces, unrelated networks, VPNs, or upstream routes.",
            "The project label is a selection filter, not proof of ownership. "
            "Callers must separately validate resource ownership before acting.",
        ),
    )


def inspect_containers(
    context: str,
    project: str | None = None,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> OSObservation:
    """Inspect project containers and security-relevant effective configuration.

    Includes stopped containers so a stopped, weakened container is not omitted
    from the project inventory.
    """
    error = _validate_scope(context, project)
    target = project or "all"

    if error:
        return _observation(
            "containers", "inspect", target,
            status=EnforcementStatus.BLOCKED,
            errors=(error,),
        )

    listing, identifiers, list_error = _list_ids(
        context=context,
        resource="containers",
        project=project,
        runner=runner,
        env=env,
    )

    if list_error:
        return _failure(
            "containers", "inspect", target, listing, list_error
        )

    assert identifiers is not None

    if not identifiers:
        return _observation(
            "containers", "inspect", target,
            status=EnforcementStatus.PASS,
            timestamp=getattr(listing, "finished_utc", ""),
            values=[],
            execution=listing,
            parsed=True,
            coverage_limitations=(
                "An empty container listing does not prove that other Docker "
                "resources or host access paths are absent.",
            ),
        )

    inspected, containers, inspect_error = _inspect_json(
        context=context,
        resource="containers",
        identifiers=identifiers,
        runner=runner,
        env=env,
    )

    if inspect_error:
        return _failure(
            "containers", "inspect", target, inspected, inspect_error
        )

    assert containers is not None

    values = []

    for container in containers:
        config = container.get("Config")
        host_config = container.get("HostConfig")
        network_settings = container.get("NetworkSettings")

        if not isinstance(config, dict):
            config = {}
        if not isinstance(host_config, dict):
            host_config = {}
        if not isinstance(network_settings, dict):
            network_settings = {}

        state = container.get("State")
        if not isinstance(state, dict):
            state = {}

        mounts = container.get("Mounts")
        if not isinstance(mounts, list):
            mounts = []

        mount_values = []
        for mount in mounts:
            if not isinstance(mount, dict):
                return _observation(
                    "containers", "inspect", target,
                    status=EnforcementStatus.UNKNOWN,
                    timestamp=getattr(inspected, "finished_utc", ""),
                    execution=inspected,
                    parsed=False,
                    errors=("container Mounts entries must be objects",),
                )

            mount_values.append({
                "type": mount.get("Type"),
                "source": mount.get("Source"),
                "destination": mount.get("Destination"),
                "read_only": mount.get("RW") is False,
                "propagation": mount.get("Propagation"),
                "name": mount.get("Name"),
            })

        labels = config.get("Labels")
        if not isinstance(labels, dict):
            labels = {}

        networks = network_settings.get("Networks")
        if not isinstance(networks, dict):
            networks = {}

        network_values = {}
        for network_name, endpoint in networks.items():
            if not isinstance(endpoint, dict):
                continue
            network_values[network_name] = {
                "network_id": endpoint.get("NetworkID"),
                "endpoint_id": endpoint.get("EndpointID"),
                "ipv4_address": endpoint.get("IPAddress"),
                "ipv6_address": endpoint.get("GlobalIPv6Address"),
                "gateway": endpoint.get("Gateway"),
                "ipv6_gateway": endpoint.get("IPv6Gateway"),
            }

        ports = network_settings.get("Ports")
        if not isinstance(ports, dict):
            ports = {}

        values.append({
            "id": container.get("Id"),
            "name": container.get("Name"),
            "image": config.get("Image"),
            "created": container.get("Created"),
            "status": state.get("Status"),
            "running": state.get("Running"),
            "paused": state.get("Paused"),
            "restarting": state.get("Restarting"),
            "exit_code": state.get("ExitCode"),
            "labels": labels,
            "privileged": host_config.get("Privileged"),
            "cap_add": host_config.get("CapAdd"),
            "cap_drop": host_config.get("CapDrop"),
            "security_opt": host_config.get("SecurityOpt"),
            "user": config.get("User"),
            "read_only_rootfs": host_config.get("ReadonlyRootfs"),
            "network_mode": host_config.get("NetworkMode"),
            "pid_mode": host_config.get("PidMode"),
            "ipc_mode": host_config.get("IpcMode"),
            "uts_mode": host_config.get("UTSMode"),
            "devices": host_config.get("Devices"),
            "device_requests": host_config.get("DeviceRequests"),
            "privileged_host_paths": {
                "binds": host_config.get("Binds"),
                "volumes_from": host_config.get("VolumesFrom"),
            },
            "mounts": mount_values,
            "networks": network_values,
            "container_ports": ports,
            "restart_policy": host_config.get("RestartPolicy"),
            "security_profile": {
                "apparmor": host_config.get("AppArmorProfile"),
                "no_new_privileges": (
                    "no-new-privileges" in (host_config.get("SecurityOpt") or [])
                    if isinstance(host_config.get("SecurityOpt"), list)
                    else None
                ),
            },
        })

    return _observation(
        "containers", "inspect", target,
        status=EnforcementStatus.PASS,
        timestamp=getattr(inspected, "finished_utc", ""),
        values=values,
        execution=inspected,
        parsed=True,
        coverage_limitations=(
            "Container inspection reports Docker's configuration and state; "
            "it does not prove that the kernel enforces every restriction.",
            "Mount and device inspection does not prove that no equivalent "
            "host-access path exists outside the inspected container.",
            "This observation does not test prohibited syscalls, writes, "
            "network connections, or attempts to control the Docker daemon.",
        ),
    )


def inspect_ports(
    context: str,
    project: str | None = None,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> OSObservation:
    """Inspect configured container ports and host port bindings.

    Reports bindings from Docker container inspection, including stopped
    containers. It does not independently scan host listening sockets or prove
    that a published endpoint is reachable or unreachable.
    """
    error = _validate_scope(context, project)
    target = project or "all"

    if error:
        return _observation(
            "ports", "inspect", target,
            status=EnforcementStatus.BLOCKED,
            errors=(error,),
        )

    listing, identifiers, list_error = _list_ids(
        context=context,
        resource="containers",
        project=project,
        runner=runner,
        env=env,
    )

    if list_error:
        return _failure(
            "ports", "inspect", target, listing, list_error
        )

    assert identifiers is not None

    if not identifiers:
        return _observation(
            "ports", "inspect", target,
            status=EnforcementStatus.PASS,
            timestamp=getattr(listing, "finished_utc", ""),
            values=[],
            execution=listing,
            parsed=True,
            coverage_limitations=(
                "No project containers were found; this does not prove that "
                "the Docker host has no listening ports or other access paths.",
            ),
        )

    inspected, containers, inspect_error = _inspect_json(
        context=context,
        resource="containers",
        identifiers=identifiers,
        runner=runner,
        env=env,
    )

    if inspect_error:
        return _failure(
            "ports", "inspect", target, inspected, inspect_error
        )

    assert containers is not None

    values = []

    for container in containers:
        config = container.get("Config")
        host_config = container.get("HostConfig")
        network_settings = container.get("NetworkSettings")
        state = container.get("State")

        if not isinstance(config, dict):
            config = {}
        if not isinstance(host_config, dict):
            host_config = {}
        if not isinstance(network_settings, dict):
            network_settings = {}
        if not isinstance(state, dict):
            state = {}

        exposed = config.get("ExposedPorts")
        if not isinstance(exposed, dict):
            exposed = {}

        host_bindings = host_config.get("PortBindings")
        if not isinstance(host_bindings, dict):
            host_bindings = {}

        effective_ports = network_settings.get("Ports")
        if not isinstance(effective_ports, dict):
            effective_ports = {}

        port_keys = sorted(
            set(exposed) | set(host_bindings) | set(effective_ports)
        )

        bindings = []
        for port_key in port_keys:
            configured = host_bindings.get(port_key) or []
            effective = effective_ports.get(port_key)

            if not isinstance(configured, list):
                configured = []

            if effective is not None and not isinstance(effective, list):
                effective = []

            bindings.append({
                "container_port": port_key,
                "declared_exposed": port_key in exposed,
                "configured_host_bindings": [
                    {
                        "host_ip": item.get("HostIp"),
                        "host_port": item.get("HostPort"),
                    }
                    for item in configured
                    if isinstance(item, dict)
                ],
                "effective_bindings": [
                    {
                        "host_ip": item.get("HostIp"),
                        "host_port": item.get("HostPort"),
                    }
                    for item in (effective or [])
                    if isinstance(item, dict)
                ],
            })

        values.append({
            "container_id": container.get("Id"),
            "container_name": container.get("Name"),
            "running": state.get("Running"),
            "network_mode": host_config.get("NetworkMode"),
            "bindings": bindings,
            "network_ports": effective_ports,
        })

    return _observation(
        "ports", "inspect", target,
        status=EnforcementStatus.PASS,
        timestamp=getattr(inspected, "finished_utc", ""),
        values=values,
        execution=inspected,
        parsed=True,
        coverage_limitations=(
            "Docker port bindings are configuration evidence, not a live "
            "reachability test.",
            "Host networking, daemon proxying, host processes, WSL localhost "
            "forwarding, and other paths require separate inspection and tests.",
            "Runtime acceptance must test relevant host interfaces and both "
            "IPv4 and IPv6 where applicable.",
        ),
    )
