
"""Docker Compose project container state and effective configuration.

Read-only adapter for inspecting containers owned by a validated Compose
project. Reports daemon-observed runtime configuration for downstream
boundary enforcement and acceptance.

This module does not create, start, stop, remove, or modify containers.
Inspection results alone do not prove that a security boundary is effective.
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
_CONTAINER_ID_RE = re.compile(r"[0-9a-fA-F]{12,64}")

_COVERAGE_LIMITATIONS = (
    "Inspection is read-only and does not enforce container safeguards.",
    "Docker inspection does not prove that host-level or network boundaries work.",
    "Container environment variable values are intentionally omitted.",
    "A Compose project label is an ownership selector, not cryptographic proof of ownership.",
    "Containers created without the expected Compose project label are not included.",
    "Runtime reachability and actual packet filtering require separate acceptance tests.",
)


def _options(
    runner: Any,
    env: dict[str, str] | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if runner is not None:
        result["runner"] = runner
    if env is not None:
        result["env"] = env
    return result


def _failure(
    project: str,
    finished_utc: str,
    message: str,
    *,
    execution: Any = None,
    status: EnforcementStatus = EnforcementStatus.UNKNOWN,
    parsed: bool = False,
) -> OSObservation:
    return OSObservation(
        "docker",
        "containers",
        "inspect",
        project,
        "Docker Engine",
        finished_utc,
        status,
        execution=execution,
        parsed=parsed,
        errors=(message,),
        coverage_limitations=_COVERAGE_LIMITATIONS,
    )


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _string_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        return None
    return [item for item in value if isinstance(item, str)]


def _mount_summary(mounts: Any) -> list[dict[str, Any]] | None:
    """Summarize effective mounts without returning unrelated raw metadata."""
    if not isinstance(mounts, list):
        return None

    result: list[dict[str, Any]] = []
    for mount in mounts:
        if not isinstance(mount, dict):
            continue

        rw = mount.get("RW")
        result.append(
            {
                "type": mount.get("Type"),
                "source": mount.get("Source"),
                "destination": mount.get("Destination"),
                "read_write": rw if isinstance(rw, bool) else None,
                "read_only": (
                    not rw if isinstance(rw, bool) else None
                ),
                "propagation": mount.get("Propagation"),
                "name": mount.get("Name"),
                "driver": mount.get("Driver"),
            }
        )

    return result


def _port_summary(network_settings: dict[str, Any]) -> dict[str, Any]:
    """Return Docker-reported port bindings and exposed container ports."""
    ports = network_settings.get("Ports")
    if not isinstance(ports, dict):
        ports = {}

    normalized: dict[str, Any] = {}
    for container_port, bindings in ports.items():
        if not isinstance(container_port, str):
            continue

        if bindings is None:
            normalized[container_port] = None
            continue

        if not isinstance(bindings, list):
            normalized[container_port] = None
            continue

        normalized[container_port] = [
            {
                "host_ip": binding.get("HostIp"),
                "host_port": binding.get("HostPort"),
            }
            for binding in bindings
            if isinstance(binding, dict)
        ]

    return normalized


def _network_summary(network_settings: dict[str, Any]) -> dict[str, Any]:
    networks = network_settings.get("Networks")
    if not isinstance(networks, dict):
        return {
            "names": None,
            "attachments": None,
        }

    attachments: dict[str, Any] = {}
    for name, attachment in networks.items():
        if not isinstance(name, str) or not isinstance(attachment, dict):
            continue

        attachments[name] = {
            "network_id": attachment.get("NetworkID"),
            "endpoint_id": attachment.get("EndpointID"),
            "gateway": attachment.get("Gateway"),
            "ip_address": attachment.get("IPAddress"),
            "ip_prefix_len": attachment.get("IPPrefixLen"),
            "ipv6_gateway": attachment.get("IPv6Gateway"),
            "global_ipv6_address": attachment.get("GlobalIPv6Address"),
            "global_ipv6_prefix_len": attachment.get("GlobalIPv6PrefixLen"),
            "mac_address": attachment.get("MacAddress"),
        }

    return {
        "names": sorted(attachments),
        "attachments": attachments,
    }


def _security_summary(host: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Extract container settings relevant to resource-access and filesystem."""
    security_opt = _string_list(host.get("SecurityOpt"))
    cap_add = _string_list(host.get("CapAdd"))
    cap_drop = _string_list(host.get("CapDrop"))
    devices = host.get("Devices")
    device_requests = host.get("DeviceRequests")

    return {
        "privileged": host.get("Privileged"),
        "cap_add": cap_add,
        "cap_drop": cap_drop,
        "security_options": security_opt,
        "no_new_privileges_reported": (
            any(
                option.lower().startswith("no-new-privileges")
                for option in security_opt
            )
            if security_opt is not None
            else None
        ),
        "user": config.get("User"),
        "read_only_root_filesystem": host.get("ReadonlyRootfs"),
        "user_namespace_mode": host.get("UsernsMode"),
        "pid_mode": host.get("PidMode"),
        "ipc_mode": host.get("IpcMode"),
        "uts_mode": host.get("UTSMode"),
        "cgroupns_mode": host.get("CgroupnsMode"),
        "network_mode": host.get("NetworkMode"),
        "devices": devices if isinstance(devices, list) else None,
        "device_requests": (
            device_requests if isinstance(device_requests, list) else None
        ),
        "volumes_from": _string_list(host.get("VolumesFrom")),
        "init": host.get("Init"),
        "privileged_host_access_indicators": {
            "host_network": host.get("NetworkMode") == "host",
            "host_pid": host.get("PidMode") == "host",
            "host_ipc": host.get("IpcMode") == "host",
            "privileged": host.get("Privileged") is True,
            "docker_socket_or_host_mount_check_required": True,
        },
    }


def _container_summary(item: dict[str, Any]) -> dict[str, Any]:
    config = _dict(item.get("Config"))
    host = _dict(item.get("HostConfig"))
    state = _dict(item.get("State"))
    network_settings = _dict(item.get("NetworkSettings"))
    labels = config.get("Labels")
    if not isinstance(labels, dict):
        labels = {}

    mounts = _mount_summary(item.get("Mounts"))
    networks = _network_summary(network_settings)
    ports = _port_summary(network_settings)

    health = _dict(state.get("Health"))
    restart_policy = _dict(host.get("RestartPolicy"))

    return {
        "id": item.get("Id"),
        "name": item.get("Name"),
        "created": item.get("Created"),
        "image": item.get("Image"),
        "image_reference": config.get("Image"),
        "state": {
            "status": state.get("Status"),
            "running": state.get("Running"),
            "paused": state.get("Paused"),
            "restarting": state.get("Restarting"),
            "oom_killed": state.get("OOMKilled"),
            "dead": state.get("Dead"),
            "exit_code": state.get("ExitCode"),
            "error": state.get("Error"),
            "started_at": state.get("StartedAt"),
            "finished_at": state.get("FinishedAt"),
            "health": health.get("Status"),
        },
        "labels": labels,
        "compose": {
            "project": labels.get("com.docker.compose.project"),
            "service": labels.get("com.docker.compose.service"),
            "working_dir": labels.get("com.docker.compose.project.working_dir"),
            "config_files": labels.get("com.docker.compose.project.config_files"),
            "oneoff": labels.get("com.docker.compose.oneoff"),
            "container_number": labels.get("com.docker.compose.container-number"),
        },
        "runtime": {
            "path": item.get("Path"),
            "args": item.get("Args"),
            "restart_policy": {
                "name": restart_policy.get("Name"),
                "maximum_retry_count": restart_policy.get("MaximumRetryCount"),
            },
            "auto_remove": host.get("AutoRemove"),
            "network_mode": host.get("NetworkMode"),
        },
        "security": _security_summary(host, config),
        "filesystem": {
            "mounts": mounts,
            "mount_count": len(mounts) if mounts is not None else None,
            "binds": _string_list(host.get("Binds")),
            "tmpfs": host.get("Tmpfs"),
            "root_read_only": host.get("ReadonlyRootfs"),
        },
        "network": {
            "mode": host.get("NetworkMode"),
            "attachments": networks["attachments"],
            "network_names": networks["names"],
            "published_ports": ports,
            "exposed_ports": config.get("ExposedPorts"),
            "port_bindings_config": host.get("PortBindings"),
            "publish_all_ports": host.get("PublishAllPorts"),
            "dns_servers": host.get("Dns"),
            "dns_search": host.get("DnsSearch"),
            "dns_options": host.get("DnsOptions"),
            "extra_hosts": host.get("ExtraHosts"),
            "hostname": config.get("Hostname"),
        },
        "resources": {
            "memory_bytes": host.get("Memory"),
            "memory_swap_bytes": host.get("MemorySwap"),
            "memory_reservation_bytes": host.get("MemoryReservation"),
            "nano_cpus": host.get("NanoCpus"),
            "cpu_shares": host.get("CpuShares"),
            "cpu_quota": host.get("CpuQuota"),
            "cpu_period": host.get("CpuPeriod"),
            "cpuset_cpus": host.get("CpusetCpus"),
            "cpuset_mems": host.get("CpusetMems"),
            "pids_limit": host.get("PidsLimit"),
            "oom_kill_disable": host.get("OomKillDisable"),
            "ulimits": host.get("Ulimits"),
            "shm_size_bytes": host.get("ShmSize"),
        },
        "logging": host.get("LogConfig"),
        "process": {
            "user": config.get("User"),
            "working_directory": config.get("WorkingDir"),
            "entrypoint": config.get("Entrypoint"),
            "command": config.get("Cmd"),
            "tty": config.get("Tty"),
            "open_stdin": config.get("OpenStdin"),
            "stdin_once": config.get("StdinOnce"),
        },
        "environment": {
            "present": isinstance(config.get("Env"), list),
            "variable_names": (
                sorted(
                    {
                        entry.split("=", 1)[0]
                        for entry in config["Env"]
                        if isinstance(entry, str) and "=" in entry
                    }
                )
                if isinstance(config.get("Env"), list)
                else None
            ),
            "values_omitted": True,
        },
    }


def inspect_containers(
    project: str,
    context: str,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> OSObservation:
    """Inspect all containers returned by Docker for the specified project.

    Includes stopped containers because a stopped container can retain unsafe
    settings that become effective if it is restarted. The Compose project
    label is used as the selection filter; this function does not mutate
    resources or establish cryptographic ownership.
    """
    options = _options(runner, env)

    if not isinstance(project, str) or not _PROJECT_RE.fullmatch(project):
        return _failure(
            str(project),
            "",
            "invalid lab project identifier",
            status=EnforcementStatus.BLOCKED,
        )

    if not isinstance(context, str) or not _CONTEXT_RE.fullmatch(context):
        return _failure(
            project,
            "",
            "invalid Docker context identifier",
            status=EnforcementStatus.BLOCKED,
        )

    prefix = ["docker", "--context", context]

    listing = run_command(
        [
            *prefix,
            "ps",
            "-aq",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        **options,
    )

    if listing.status is not EnforcementStatus.PASS:
        return _failure(
            project,
            listing.finished_utc,
            listing.reason or "container listing failed",
            execution=listing,
        )

    identifiers = listing.stdout.split()

    if len(identifiers) != len(set(identifiers)):
        return _failure(
            project,
            listing.finished_utc,
            "Docker returned duplicate container identifiers",
            execution=listing,
        )

    if any(
        not isinstance(identifier, str)
        or not _CONTAINER_ID_RE.fullmatch(identifier)
        for identifier in identifiers
    ):
        return _failure(
            project,
            listing.finished_utc,
            "Docker returned malformed container ID",
            execution=listing,
        )

    if not identifiers:
        return OSObservation(
            "docker",
            "containers",
            "inspect",
            project,
            "Docker Engine",
            listing.finished_utc,
            EnforcementStatus.PASS,
            values=[],
            execution=listing,
            parsed=True,
            coverage_limitations=(
                "No containers currently carry this Compose project label.",
                *_COVERAGE_LIMITATIONS,
            ),
        )

    inspected = run_command(
        [*prefix, "container", "inspect", *identifiers],
        **options,
    )

    if inspected.status is not EnforcementStatus.PASS:
        return _failure(
            project,
            inspected.finished_utc,
            inspected.reason or "container inspect failed",
            execution=inspected,
        )

    try:
        data = json.loads(inspected.stdout)
        if not isinstance(data, list):
            raise ValueError("container inspection output must be a JSON array")
        if len(data) != len(identifiers):
            raise ValueError(
                "inspection result count does not match listed containers"
            )
        if not all(isinstance(item, dict) for item in data):
            raise ValueError("container inspection entries must be objects")
    except (ValueError, TypeError) as exc:
        return _failure(
            project,
            inspected.finished_utc,
            str(exc),
            execution=inspected,
            parsed=False,
        )

    expected_project_label = project
    summaries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for item in data:
        identifier = item.get("Id")
        if not isinstance(identifier, str) or not _CONTAINER_ID_RE.fullmatch(
            identifier
        ):
            return _failure(
                project,
                inspected.finished_utc,
                "container inspect returned a missing or malformed ID",
                execution=inspected,
                parsed=False,
            )

        if identifier in seen_ids:
            return _failure(
                project,
                inspected.finished_utc,
                "container inspect returned a duplicate ID",
                execution=inspected,
                parsed=False,
            )
        seen_ids.add(identifier)

        config = _dict(item.get("Config"))
        labels = _dict(config.get("Labels"))
        observed_project = labels.get("com.docker.compose.project")

        # Revalidate ownership after inspection. A listing filter is not a
        # substitute for validating each returned resource.
        if observed_project != expected_project_label:
            return _failure(
                project,
                inspected.finished_utc,
                "inspected container does not carry the expected Compose project label",
                execution=inspected,
                parsed=False,
            )

        summaries.append(_container_summary(item))

    listed_ids = set(identifiers)
    inspected_ids = seen_ids
    if listed_ids != inspected_ids:
        return _failure(
            project,
            inspected.finished_utc,
            "inspected container IDs do not match the listed IDs",
            execution=inspected,
            parsed=False,
        )

    return OSObservation(
        "docker",
        "containers",
        "inspect",
        project,
        "Docker Engine",
        inspected.finished_utc,
        EnforcementStatus.PASS,
        values=summaries,
        execution=inspected,
        parsed=True,
        coverage_limitations=_COVERAGE_LIMITATIONS,
    )
