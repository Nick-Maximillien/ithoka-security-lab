"""Read-only OS API and structured evidence used by the lab controller."""

from __future__ import annotations

import platform
from typing import Any

from .docker.containers import inspect_containers
from .docker.daemon import inspect_daemon
from .docker.networks import inspect_networks
from .docker.ports import inspect_published_ports
from .linux.firewall import inspect_firewall
from .linux.forwarding import inspect_forwarding
from .linux.interfaces import inspect_interfaces
from .linux.mounts import inspect_mounts
from .linux.processes import inspect_processes
from .linux.proxies import inspect_proxy_environment
from .linux.resolvers import inspect_resolvers
from .linux.routes import inspect_routes
from .linux.sockets import inspect_sockets
from .linux.sysctl import inspect_sysctl
from .models import OSObservation
from .actions import (
    OSActionExecutor,
    OSActionRequest,
    OSActionResult,
    OSActionStatus,
    execute_network_boundary_action,
    execute_os_action,
)
from .windows.firewall import inspect_firewall as inspect_windows_firewall
from .windows.interfaces import inspect_interfaces as inspect_windows_interfaces
from .windows.processes import inspect_processes as inspect_windows_processes
from .windows.routes import inspect_routes as inspect_windows_routes
from .windows.sockets import inspect_sockets as inspect_windows_sockets
from .wsl.boundary import inspect_boundary as inspect_wsl_boundary
from .wsl.networking import inspect_networking as inspect_wsl_networking
from .wsl.state import inspect_state as inspect_wsl_state


def inspect_linux() -> dict[str, OSObservation]:
    """Read Linux interfaces, routes, forwarding, firewall, sockets, processes."""
    return {
        "interfaces": inspect_interfaces(),
        "routes": inspect_routes(),
        "forwarding": inspect_forwarding(),
        "sysctl": inspect_sysctl(),
        "firewall": inspect_firewall(),
        "sockets": inspect_sockets(),
        "processes": inspect_processes(),
        "resolvers": inspect_resolvers(),
        "proxies": inspect_proxy_environment(),
        "mounts": inspect_mounts(),
    }


def inspect_windows() -> dict[str, OSObservation]:
    """Read Windows host state through native PowerShell networking cmdlets."""
    return {
        "interfaces": inspect_windows_interfaces(),
        "routes": inspect_windows_routes(),
        "firewall": inspect_windows_firewall(),
        "sockets": inspect_windows_sockets(),
        "processes": inspect_windows_processes(),
    }


def inspect_docker(
    project: str | None = None,
    context: str | None = None,
) -> dict[str, OSObservation]:
    """Read Docker daemon and optionally project resources."""
    daemon = inspect_daemon(context)
    if daemon.status.value != "PASS":
        return {"daemon": daemon}
    selected_context = context
    if selected_context is None and daemon.values:
        selected_context = daemon.values.get("active_context")
    result = {"daemon": daemon}
    if selected_context and project is not None:
        result.update({
            "containers": inspect_containers(project, selected_context),
            "networks": inspect_networks(selected_context, project),
            "ports": inspect_published_ports(project, selected_context),
        })
    return result


def inspect_platforms(
    *,
    project: str | None = None,
    context: str | None = None,
    docker_observations: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect current platform observations without changing host state."""
    linux = inspect_linux()
    windows = inspect_windows()
    linux_documents = {
        name: observation.to_dict()
        for name, observation in linux.items()
    }
    windows_documents = {
        name: observation.to_dict()
        for name, observation in windows.items()
    }
    return {
        "schema": "ithoka.security-lab.os-observations.v1",
        "observed_platform": platform.system().lower(),
        "read_only": True,
        "linux": linux_documents,
        "docker": {
            name: observation.to_dict()
            for name, observation in inspect_docker(project, context).items()
        } if docker_observations is None else docker_observations,
        "windows": windows_documents,
        "wsl": {
            name: observation.to_dict()
            for name, observation in {
                "state": inspect_wsl_state(),
                "networking": inspect_wsl_networking(
                    linux_observations=linux_documents,
                ),
                "boundary": inspect_wsl_boundary(
                    windows_observations=windows_documents,
                    linux_observations=linux_documents,
                ),
            }.items()
        },
    }
