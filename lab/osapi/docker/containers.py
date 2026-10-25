"""Docker Compose project container state and effective configuration."""

from __future__ import annotations

import json
import re
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation

_PROJECT_RE = re.compile(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}")
_CONTEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def inspect_containers(
    project: str,
    context: str,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> OSObservation:
    options = {} if runner is None else {"runner": runner}
    if env is not None:
        options["env"] = env
    if not _PROJECT_RE.fullmatch(project):
        return OSObservation(
            "docker", "containers", "inspect", project, "Docker Engine",
            "", EnforcementStatus.BLOCKED, errors=("invalid lab project identifier",)
        )
    if not isinstance(context, str) or not _CONTEXT_RE.fullmatch(context):
        return OSObservation(
            "docker", "containers", "inspect", project, "Docker Engine",
            "", EnforcementStatus.BLOCKED, errors=("invalid Docker context identifier",)
        )
    prefix = ["docker", "--context", context]
    listing = run_command(
        [
            *prefix,
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        **options,
    )
    if listing.status is not EnforcementStatus.PASS:
        return OSObservation(
            "docker", "containers", "inspect", project, "Docker Engine",
            listing.finished_utc, EnforcementStatus.UNKNOWN,
            execution=listing, errors=(listing.reason or "container listing failed",)
        )
    identifiers = listing.stdout.split()
    if any(not re.fullmatch(r"[0-9a-fA-F]{12,64}", item) for item in identifiers):
        return OSObservation(
            "docker", "containers", "inspect", project, "Docker Engine",
            listing.finished_utc, EnforcementStatus.UNKNOWN,
            execution=listing, errors=("Docker returned malformed container ID",)
        )
    if not identifiers:
        return OSObservation(
            "docker", "containers", "inspect", project, "Docker Engine",
            listing.finished_utc, EnforcementStatus.PASS,
            values=[],
            execution=listing,
            parsed=True,
            coverage_limitations=("no containers currently carry this Compose project label",),
        )
    inspected = run_command([*prefix, "inspect", *identifiers], **options)
    if inspected.status is not EnforcementStatus.PASS:
        return OSObservation(
            "docker", "containers", "inspect", project, "Docker Engine",
            inspected.finished_utc, EnforcementStatus.UNKNOWN,
            execution=inspected, errors=(inspected.reason or "container inspect failed",)
        )
    try:
        data = json.loads(inspected.stdout)
        if not isinstance(data, list) or len(data) != len(identifiers):
            raise ValueError("inspection result count does not match listed containers")
        if not all(isinstance(item, dict) for item in data):
            raise ValueError("container inspection entries must be objects")
    except (ValueError, TypeError) as exc:
        return OSObservation(
            "docker", "containers", "inspect", project, "Docker Engine",
            inspected.finished_utc, EnforcementStatus.UNKNOWN,
            execution=inspected, parsed=False, errors=(str(exc),)
        )
    values = []
    for item in data:
        config = item.get("Config") if isinstance(item.get("Config"), dict) else {}
        host = item.get("HostConfig") if isinstance(item.get("HostConfig"), dict) else {}
        state = item.get("State") if isinstance(item.get("State"), dict) else {}
        network_settings = (
            item.get("NetworkSettings")
            if isinstance(item.get("NetworkSettings"), dict)
            else {}
        )
        network_map = network_settings.get("Networks")
        values.append({
            "id": item.get("Id"),
            "name": item.get("Name"),
            "image": item.get("Image"),
            "state": state.get("Status"),
            "running": state.get("Running"),
            "labels": config.get("Labels", {}),
            "network_mode": host.get("NetworkMode"),
            "networks": (
                sorted(network_map)
                if isinstance(network_map, dict)
                else None
            ),
            "host_config": host,
            "mounts": item.get("Mounts"),
            "published_ports": network_settings.get("Ports"),
        })
    return OSObservation(
        "docker", "containers", "inspect", project, "Docker Engine",
        inspected.finished_utc, EnforcementStatus.PASS,
        values=values, execution=inspected, parsed=True,
        coverage_limitations=("container environment values are intentionally omitted",),
    )
