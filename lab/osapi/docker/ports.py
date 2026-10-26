
"""Published Docker host port inspection.

Read-only inspection of published port bindings for containers belonging
to a validated Docker Compose project.

This adapter reports Docker's effective container port configuration. It
does not prove host reachability, firewall behavior, or external exposure.
"""

from __future__ import annotations

from typing import Any

from ...enforcement.models import EnforcementStatus
from ..models import OSObservation
from .containers import inspect_containers


_COVERAGE_LIMITATIONS = (
    "Port inspection is scoped to containers carrying the selected Compose project label.",
    "Docker port bindings do not prove that a host port is reachable.",
    "Host-wide listeners and ports exposed by processes outside this project are not inspected.",
    "Linux/WSL firewall rules, Windows Firewall, VPN paths, and upstream filtering are not verified.",
    "IPv4 and IPv6 reachability require separate runtime acceptance tests.",
)


def inspect_published_ports(
    project: str,
    context: str,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> OSObservation:
    """Inspect published ports for a Compose project without changing state."""
    containers = inspect_containers(
        project=project,
        context=context,
        runner=runner,
        env=env,
    )

    if containers.status is not EnforcementStatus.PASS:
        return OSObservation(
            "docker",
            "ports",
            "inspect",
            project,
            "Docker Engine",
            containers.observed_utc,
            containers.status,
            values=None,
            execution=containers.execution,
            parsed=containers.parsed,
            errors=containers.errors,
            coverage_limitations=tuple(
                dict.fromkeys(
                    (*containers.coverage_limitations, *_COVERAGE_LIMITATIONS)
                )
            ),
        )

    ports: list[dict[str, Any]] = []

    for container in containers.values or []:
        if not isinstance(container, dict):
            continue

        network = container.get("network")
        if not isinstance(network, dict):
            network = {}

        bindings = network.get("published_ports")
        if not isinstance(bindings, dict):
            # A missing or malformed binding map is not evidence of exposure.
            # Preserve the inspection limitation instead of inventing ports.
            bindings = {}

        published: list[dict[str, Any]] = []

        for container_port, host_bindings in bindings.items():
            if not isinstance(container_port, str):
                continue

            if host_bindings is None:
                # Docker may report an exposed container port without a
                # host-side binding. This is not itself a published host port.
                continue

            if not isinstance(host_bindings, list):
                continue

            for binding in host_bindings:
                if not isinstance(binding, dict):
                    continue

                host_port = binding.get("host_port")
                host_ip = binding.get("host_ip")

                # Docker inspect commonly represents an unpublished port
                # with no binding. Only include actual host-port values.
                if host_port is None or str(host_port).strip() == "":
                    continue

                published.append(
                    {
                        "container_port": container_port,
                        "host_ip": host_ip,
                        "host_port": str(host_port),
                    }
                )

        ports.append(
            {
                "container_id": container.get("id"),
                "container_name": container.get("name"),
                "container_state": (
                    container.get("state", {}).get("status")
                    if isinstance(container.get("state"), dict)
                    else None
                ),
                "network_mode": network.get("mode"),
                "published": published,
                "published_port_count": len(published),
            }
        )

    return OSObservation(
        "docker",
        "ports",
        "inspect",
        project,
        "Docker Engine",
        containers.observed_utc,
        EnforcementStatus.PASS,
        values=ports,
        execution=containers.execution,
        parsed=True,
        coverage_limitations=tuple(
            dict.fromkeys(
                (*containers.coverage_limitations, *_COVERAGE_LIMITATIONS)
            )
        ),
    )
