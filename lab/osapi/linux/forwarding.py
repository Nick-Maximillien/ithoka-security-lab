"""Separate IPv4 and IPv6 forwarding observations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..models import OSObservation
from .sysctl import SYSCTL_PATHS, inspect_sysctl


def inspect_forwarding(paths: dict[str, Path] | None = None) -> OSObservation:
    selected = paths or {
        "ipv4": SYSCTL_PATHS["ipv4_forwarding"],
        "ipv6": SYSCTL_PATHS["ipv6_forwarding"],
    }
    observation = inspect_sysctl(selected)
    values = observation.values or {}
    return OSObservation(
        "linux",
        "forwarding",
        "inspect",
        "IPv4 and IPv6 forwarding",
        "procfs",
        observation.observed_utc,
        observation.status,
        values=values,
        parsed=observation.parsed,
        errors=observation.errors,
        coverage_limitations=(
            "forwarding status is not a complete test of alternate network paths",
        ),
    )
