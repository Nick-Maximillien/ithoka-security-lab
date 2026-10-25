"""Published Docker host port inspection."""

from __future__ import annotations

from typing import Any

from ...enforcement.models import EnforcementStatus
from ..models import OSObservation
from .containers import inspect_containers


def inspect_published_ports(
    project: str,
    context: str,
    runner: Any = None,
) -> OSObservation:
    containers = inspect_containers(project, context, runner)
    if containers.status is not EnforcementStatus.PASS:
        return OSObservation(
            "docker", "ports", "inspect", project, "Docker Engine",
            containers.observed_utc, containers.status,
            values=None,
            parsed=containers.parsed,
            errors=containers.errors,
            coverage_limitations=containers.coverage_limitations,
        )
    ports = []
    for container in containers.values or []:
        bindings = container.get("published_ports")
        if isinstance(bindings, dict):
            ports.append({
                "container": container.get("name"),
                "bindings": bindings,
            })
    return OSObservation(
        "docker", "ports", "inspect", project, "Docker Engine",
        containers.observed_utc, EnforcementStatus.PASS,
        values=ports, parsed=True,
        coverage_limitations=("port observation is project-scoped; daemon-wide listeners are not included",),
    )
