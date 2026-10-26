
"""Read-only Docker daemon, context, runtime, and boundary-capability inspection.

This adapter gathers daemon-reported configuration relevant to the lab's
Docker boundary model. It does not mutate Docker resources, install firewall
rules, or prove network isolation.

A PASS means the required inspection commands completed and their outputs
were parsed. It does not mean the Docker daemon or host is secure.
"""

from __future__ import annotations

import re
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import parse_json_execution, run_command
from ..models import OSObservation


_CONTEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")

# These fields can expose credentials, local paths, or other sensitive
# connection details. The adapter reports a sanitized endpoint rather than
# assuming context metadata is safe to publish in evidence.
_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|token|secret|credential|authorization|"
    r"client.?key|private.?key|cert.?path|key.?path)",
    re.IGNORECASE,
)

_ENDPOINT_SECRET_RE = re.compile(
    r"(?i)(password|passwd|token|secret|authorization|"
    r"client_key|private_key)=([^,\s]+)"
)


def _run(
    argv: list[str],
    runner: Any = None,
    env: dict[str, str] | None = None,
):
    """Run a command through the shared shell-free command adapter."""
    options: dict[str, Any] = {}
    if runner is not None:
        options["runner"] = runner
    if env is not None:
        options["env"] = env
    return run_command(argv, **options)


def _sanitize(value: Any, key: str | None = None) -> Any:
    """Recursively sanitize metadata before storing it in observations."""
    if key and _SENSITIVE_KEY_RE.search(key):
        return "[REDACTED]"

    if isinstance(value, dict):
        return {
            str(child_key): _sanitize(child_value, str(child_key))
            for child_key, child_value in value.items()
        }

    if isinstance(value, list):
        return [_sanitize(item) for item in value]

    if isinstance(value, tuple):
        return [_sanitize(item) for item in value]

    if isinstance(value, str):
        return _ENDPOINT_SECRET_RE.sub(r"\1=[REDACTED]", value)

    return value


def _parse_json(result: Any, label: str) -> tuple[Any | None, str | None]:
    """Parse JSON command output and return a contextual error on failure."""
    if result.status is not EnforcementStatus.PASS:
        reason = result.reason or f"{label} command failed"
        return None, f"{label}: {reason}"

    parsed, error = parse_json_execution(result)
    if error:
        return None, f"{label}: {error}"

    if not isinstance(parsed, (dict, list)):
        return None, f"{label}: expected a JSON object or array"

    return parsed, None


def _object(value: Any) -> dict[str, Any] | None:
    """Return a JSON object when the value has the expected shape."""
    if isinstance(value, dict):
        return value

    # `docker context inspect` may represent its result as a one-item array.
    if isinstance(value, list) and len(value) == 1:
        if isinstance(value[0], dict):
            return value[0]

    return None


def _context_endpoint(context_data: Any) -> dict[str, Any] | None:
    """Extract Docker endpoint metadata from a context inspection result."""
    context_obj = _object(context_data)
    if context_obj is None:
        return None

    endpoints = context_obj.get("Endpoints")
    if not isinstance(endpoints, dict):
        return None

    endpoint = endpoints.get("docker")
    if not isinstance(endpoint, dict):
        return None

    return endpoint


def _security_summary(info: dict[str, Any]) -> dict[str, Any]:
    """Extract daemon-reported security and runtime configuration.

    These are observations, not assertions that the corresponding controls
    are effective or sufficient.
    """
    security_options = info.get("SecurityOptions")
    if not isinstance(security_options, list):
        security_options = None

    runtimes = info.get("Runtimes")
    if not isinstance(runtimes, dict):
        runtimes = None

    plugins = info.get("Plugins")
    if not isinstance(plugins, dict):
        plugins = None

    network_plugins = (
        plugins.get("Network") if isinstance(plugins, dict) else None
    )
    volume_plugins = (
        plugins.get("Volume") if isinstance(plugins, dict) else None
    )
    authorization_plugins = (
        plugins.get("Authorization") if isinstance(plugins, dict) else None

    )

    warnings = info.get("Warnings")
    if not isinstance(warnings, list):
        warnings = None

    return {
        # Daemon identity and implementation
        "daemon_id": info.get("ID"),
        "daemon_name": info.get("Name"),
        "server_version": info.get("ServerVersion"),
        "operating_system": info.get("OperatingSystem"),
        "os_type": info.get("OSType"),
        "architecture": info.get("Architecture"),
        "kernel_version": info.get("KernelVersion"),
        "build_time": info.get("BuildTime"),
        "experimental_build": info.get("ExperimentalBuild"),

        # Runtime and isolation-related configuration
        "security_options": security_options,
        "default_runtime": info.get("DefaultRuntime"),
        "available_runtimes": runtimes,
        "rootless_security_option_reported": any(
            "rootless" in str(option).lower()
            for option in (security_options or [])
        ),
        "user_namespace_security_option_reported": any(
            "userns" in str(option).lower()
            for option in (security_options or [])
        ),
        "live_restore_enabled": info.get("LiveRestoreEnabled"),
        "swarm": info.get("Swarm"),
        "containerd_commit": info.get("ContainerdCommit"),
        "runc_commit": info.get("RuncCommit"),
        "init_binary": info.get("InitBinary"),

        # Daemon resource and storage configuration
        "driver": info.get("Driver"),
        "driver_status": info.get("DriverStatus"),
        "docker_root_dir": info.get("DockerRootDir"),
        "storage_driver": info.get("Driver"),
        "storage_status": info.get("DriverStatus"),
        "logging_driver": info.get("LoggingDriver"),
        "cgroup_driver": info.get("CgroupDriver"),
        "cgroup_version": info.get("CgroupVersion"),
        "kernel_memory": info.get("KernelMemory"),
        "memory_limit_support_reported": info.get("MemoryLimit"),
        "swap_limit_support_reported": info.get("SwapLimit"),
        "oom_kill_disable_support_reported": info.get("OomKillDisable"),
        "cpu_cfs_quota_support_reported": info.get("CpuCfsQuota"),
        "cpu_shares_support_reported": info.get("CPUShares"),
        "pids_limit_support_reported": info.get("PidsLimit"),

        # Networking configuration and available plugins
        "network_plugins": network_plugins,
        "network_driver_names": info.get("NetworkDriverNames"),
        "bridge_network": info.get("Bridge"),
        "default_bridge_ip": info.get("DefaultBridge"),
        "default_address_pools": info.get("DefaultAddressPools"),
        "ipv4_forwarding_reported": info.get("IPv4Forwarding"),
        "bridge_nf_iptables_reported": info.get("BridgeNfIptables"),
        "bridge_nf_ip6tables_reported": info.get("BridgeNfIp6tables"),
        "ip_tables_enabled_reported": info.get("IPTables"),
        "ip6_tables_enabled_reported": info.get("IP6Tables"),
        "ip_masq_enabled_reported": info.get("IPMasq"),
        "userland_proxy_enabled_reported": info.get("UserlandProxy"),
        "experimental_networking": info.get("ExperimentalBuild"),

        # Other plugins and daemon-reported warnings
        "volume_plugins": volume_plugins,
        "authorization_plugins": authorization_plugins,
        "daemon_warnings": warnings,

        # Resource inventory: useful for planning, not resource enforcement.
        "containers_total": info.get("Containers"),
        "containers_running": info.get("ContainersRunning"),
        "containers_paused": info.get("ContainersPaused"),
        "containers_stopped": info.get("ContainersStopped"),
        "images": info.get("Images"),
        "cpu_count": info.get("NCPU"),
        "memory_bytes": info.get("MemTotal"),
    }


def _version_summary(version_data: Any) -> dict[str, Any] | None:
    """Extract client/server versions from `docker version` output."""
    version_obj = _object(version_data)
    if version_obj is None:
        return None

    result: dict[str, Any] = {}
    for side in ("Client", "Server"):
        details = version_obj.get(side)
        if not isinstance(details, dict):
            result[side.lower()] = None
            continue

        result[side.lower()] = {
            "version": details.get("Version"),
            "api_version": details.get("ApiVersion"),
            "minimum_api_version": details.get("MinAPIVersion"),
            "git_commit": details.get("GitCommit"),
            "go_version": details.get("GoVersion"),
            "os": details.get("Os"),
            "architecture": details.get("Arch"),
            "build_time": details.get("BuildTime"),
            "platform": details.get("Platform"),
        }

    return result


def inspect_daemon(
    context: str | None = None,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> OSObservation:
    """Inspect Docker context, client/server versions, and daemon configuration.

    Args:
        context:
            Optional Docker context name. When omitted, use the context
            reported by `docker context show`.
        runner:
            Optional injected command runner used by the shared run_command.
        env:
            Optional environment mapping passed to the shared command runner.

    Returns:
        OSObservation containing sanitized daemon evidence, errors, and
        explicit coverage limitations.

    Important:
        PASS means required observations were collected. It does not mean
        Docker boundaries have been enforced or accepted by runtime tests.
    """
    limitations = (
        "Docker daemon inspection is observational and does not install controls.",
        "Daemon-reported security options do not prove effective container isolation.",
        "Context endpoint metadata does not prove the physical host or trust boundary.",
        "This adapter does not inspect Windows Firewall or upstream network controls.",
        "This adapter does not prove IPv4 or IPv6 packet filtering or reachability.",
        "Daemon-wide inspection does not establish ownership of unrelated Docker resources.",
        "A successful Docker info response does not prove Docker socket access is restricted.",
        "Host listener exposure and endpoint reachability require separate OS-side checks.",
        "Daemon-reported network and firewall fields may be absent or backend-dependent.",
    )

    # Discover the active context first. This is separate from the selected
    # context because callers may explicitly inspect a non-active context.
    active_result = _run(
        ["docker", "context", "show"],
        runner=runner,
        env=env,
    )

    if active_result.status is not EnforcementStatus.PASS:
        return OSObservation(
            "docker",
            "daemon",
            "inspect",
            context or "active context",
            "Docker CLI",
            active_result.finished_utc,
            EnforcementStatus.UNKNOWN,
            execution=active_result,
            errors=(
                active_result.reason or "active Docker context unavailable",
            ),
            coverage_limitations=limitations,
        )

    active_context = active_result.stdout.strip()

    if not _CONTEXT_RE.fullmatch(active_context):
        return OSObservation(
            "docker",
            "daemon",
            "inspect",
            context or "active context",
            "Docker CLI",
            active_result.finished_utc,
            EnforcementStatus.BLOCKED,
            values={"active_context": active_context},
            errors=("Docker CLI returned an invalid active context name",),
            coverage_limitations=limitations,
        )

    selected_context = context if context is not None else active_context

    if not isinstance(selected_context, str) or not _CONTEXT_RE.fullmatch(
        selected_context
    ):
        return OSObservation(
            "docker",
            "daemon",
            "inspect",
            str(selected_context),
            "Docker CLI",
            active_result.finished_utc,
            EnforcementStatus.BLOCKED,
            values={"active_context": active_context},
            errors=("invalid Docker context identifier",),
            coverage_limitations=limitations,
        )

    prefix = ["docker", "--context", selected_context]

    # Use structured JSON output wherever supported. Keep the complete
    # sanitized context object so endpoint details and TLS configuration
    # can be observed without printing raw credentials.
    context_result = _run(
        [
            *prefix,
            "context",
            "inspect",
            selected_context,
            "--format",
            "{{json .}}",
        ],
        runner=runner,
        env=env,
    )

    version_result = _run(
        [
            *prefix,
            "version",
            "--format",
            "{{json .}}",
        ],
        runner=runner,
        env=env,
    )

    info_result = _run(
        [
            *prefix,
            "info",
            "--format",
            "{{json .}}",
        ],
        runner=runner,
        env=env,
    )

    # Compose is an optional capability for daemon inspection itself, but it
    # is important to the lab's intended disposable-apparatus workflow.
    compose_result = _run(
        [
            *prefix,
            "compose",
            "version",
            "--format",
            "json",
        ],
        runner=runner,
        env=env,
    )

    context_data, context_error = _parse_json(
        context_result,
        "Docker context inspection",
    )
    version_data, version_error = _parse_json(
        version_result,
        "Docker client/server version inspection",
    )
    info_data, info_error = _parse_json(
        info_result,
        "Docker daemon info inspection",
    )

    errors = [
        error
        for error in (context_error, version_error, info_error)
        if error
    ]

    context_obj = _object(context_data)
    version_summary = _version_summary(version_data)
    info_obj = _object(info_data)

    if context_data is not None and context_obj is None:
        errors.append("Docker context inspection did not return one object")

    if version_data is not None and version_summary is None:
        errors.append("Docker version inspection did not return one object")

    if info_data is not None and info_obj is None:
        errors.append("Docker info inspection did not return one object")

    endpoint = _context_endpoint(context_data)
    if context_data is not None and endpoint is None:
        errors.append("Docker context endpoint metadata is unavailable")

    if (
        version_summary is not None
        and version_summary.get("server") is None
    ):
        errors.append(
            "Docker server version is unavailable; the selected daemon "
            "may be unreachable or the CLI may not support this output"
        )

    daemon_summary = (
        _security_summary(info_obj)
        if info_obj is not None
        else None
    )

    # Optional Compose capability: record failure as a coverage gap instead
    # of pretending the daemon itself failed inspection.
    compose_version: str | None = None
    compose_details: Any = None
    compose_error: str | None = None

    if compose_result.status is EnforcementStatus.PASS:
        raw_compose = compose_result.stdout.strip()
        if raw_compose:
            try:
                # Compose releases differ in output shape. Preserve JSON
                # when valid; otherwise retain the short textual version.
                import json

                compose_details = json.loads(raw_compose)
                if isinstance(compose_details, dict):
                    compose_version = (
                        compose_details.get("version")
                        or compose_details.get("Version")
                    )
                elif isinstance(compose_details, str):
                    compose_version = compose_details
            except ValueError:
                compose_version = raw_compose
        else:
            compose_error = "Docker Compose returned empty version output"
    else:
        compose_error = (
            compose_result.reason or "Docker Compose plugin unavailable"
        )

    values = {
        "active_context": active_context,
        "selected_context": selected_context,
        "context_matches_active": selected_context == active_context,
        "context": _sanitize(context_obj),
        "endpoint": _sanitize(endpoint),
        "client_server_versions": _sanitize(version_summary),
        "daemon": _sanitize(daemon_summary),
        "compose": {
            "available": compose_result.status is EnforcementStatus.PASS
            and compose_version is not None,
            "version": compose_version,
            "details": _sanitize(compose_details),
            "error": compose_error,
        },
        "inspection_scope": {
            "daemon_metadata": info_obj is not None,
            "client_server_versions": version_summary is not None,
            "context_endpoint": endpoint is not None,
            "compose_capability": compose_version is not None,
        },
        "interpretation": {
            "observation_only": True,
            "enforcement_performed": False,
            "runtime_acceptance_performed": False,
            "physical_host_identity_verified": False,
            "network_isolation_verified": False,
            "windows_host_boundary_verified": False,
        },
    }

    # Missing Compose does not invalidate daemon inspection. The Compose
    # capability is reported separately so the orchestrator can refuse
    # operations that require it.
    status = (
        EnforcementStatus.PASS
        if not errors
        and info_obj is not None
        and version_summary is not None
        and endpoint is not None
        else EnforcementStatus.UNKNOWN
    )

    coverage = list(limitations)
    if compose_error:
        coverage.append(
            "Docker Compose capability could not be confirmed: "
            + compose_error
        )

    return OSObservation(
        "docker",
        "daemon",
        "inspect",
        selected_context,
        "Docker Engine via CLI",
        info_result.finished_utc,
        status,
        values=values,
        parsed=not errors,
        errors=tuple(errors),
        coverage_limitations=tuple(coverage),
    )
