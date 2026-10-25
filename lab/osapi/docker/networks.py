"""Docker network IDs, drivers, endpoint attachments, and IPAM details."""

from __future__ import annotations

import json
import re
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation

_PROJECT_RE = re.compile(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}")
_CONTEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def inspect_networks(
    context: str,
    project: str | None = None,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> OSObservation:
    options = {} if runner is None else {"runner": runner}
    if env is not None:
        options["env"] = env
    if project is not None and not _PROJECT_RE.fullmatch(project):
        return OSObservation(
            "docker", "networks", "inspect", project, "Docker Engine",
            "", EnforcementStatus.BLOCKED, errors=("invalid lab project identifier",)
        )
    if not isinstance(context, str) or not _CONTEXT_RE.fullmatch(context):
        return OSObservation(
            "docker", "networks", "inspect", project or "all",
            "Docker Engine", "", EnforcementStatus.BLOCKED,
            errors=("invalid Docker context identifier",)
        )
    prefix = ["docker", "--context", context]
    command = [*prefix, "network", "ls", "-q", "--no-trunc"]
    if project:
        command.extend(["--filter", f"label=com.docker.compose.project={project}"])
    listing = run_command(command, **options)
    if listing.status is not EnforcementStatus.PASS:
        return OSObservation(
            "docker", "networks", "inspect", project or "all",
            "Docker Engine", listing.finished_utc, EnforcementStatus.UNKNOWN,
            execution=listing, errors=(listing.reason or "network listing failed",)
        )
    identifiers = listing.stdout.split()
    if any(not re.fullmatch(r"[0-9a-fA-F]{12,64}", item) for item in identifiers):
        return OSObservation(
            "docker", "networks", "inspect", project or "all",
            "Docker Engine", listing.finished_utc, EnforcementStatus.UNKNOWN,
            execution=listing, errors=("Docker returned malformed network ID",)
        )
    if not identifiers:
        return OSObservation(
            "docker", "networks", "inspect", project or "all",
            "Docker Engine", listing.finished_utc, EnforcementStatus.PASS,
            values=[], execution=listing, parsed=True
        )
    inspected = run_command([*prefix, "network", "inspect", *identifiers], **options)
    if inspected.status is not EnforcementStatus.PASS:
        return OSObservation(
            "docker", "networks", "inspect", project or "all",
            "Docker Engine", inspected.finished_utc, EnforcementStatus.UNKNOWN,
            execution=inspected, errors=(inspected.reason or "network inspect failed",)
        )
    try:
        networks = json.loads(inspected.stdout)
        if not isinstance(networks, list) or len(networks) != len(identifiers):
            raise ValueError("network result count does not match listed networks")
        if not all(isinstance(network, dict) for network in networks):
            raise ValueError("network inspection entries must be objects")
    except (ValueError, TypeError) as exc:
        return OSObservation(
            "docker", "networks", "inspect", project or "all",
            "Docker Engine", inspected.finished_utc, EnforcementStatus.UNKNOWN,
            execution=inspected, parsed=False, errors=(str(exc),)
        )
    values = []
    for network in networks:
        ipam = network.get("IPAM") if isinstance(network.get("IPAM"), dict) else {}
        values.append({
            "id": network.get("Id"),
            "name": network.get("Name"),
            "driver": network.get("Driver"),
            "scope": network.get("Scope"),
            "internal": network.get("Internal"),
            "enable_ipv6": network.get("EnableIPv6"),
            "labels": network.get("Labels", {}),
            "ipam": ipam.get("Config"),
            "containers": network.get("Containers"),
            "options": network.get("Options"),
        })
    return OSObservation(
        "docker", "networks", "inspect", project or "all",
        "Docker Engine", inspected.finished_utc, EnforcementStatus.PASS,
        values=values, execution=inspected, parsed=True,
        coverage_limitations=(
            "Docker network configuration does not prove host/WSL isolation or packet behavior",
        ),
    )
