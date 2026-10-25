"""Conservative Windows-to-WSL boundary assessment."""

from __future__ import annotations

from typing import Any

from ...enforcement.models import EnforcementStatus
from ..models import OSObservation
from ..windows.interfaces import inspect_interfaces as inspect_windows_interfaces
from ..windows.firewall import inspect_firewall as inspect_windows_firewall
from ..linux.interfaces import inspect_interfaces as inspect_linux_interfaces
from ..linux.routes import inspect_routes as inspect_linux_routes


def inspect_boundary(
    runner: Any = None,
    *,
    windows_observations: dict[str, Any] | None = None,
    linux_observations: dict[str, Any] | None = None,
) -> OSObservation:
    windows = windows_observations or {
        "interfaces": inspect_windows_interfaces(runner=runner).to_dict(),
        "firewall": inspect_windows_firewall(runner=runner).to_dict(),
    }
    linux = linux_observations or {
        "interfaces": inspect_linux_interfaces(runner=runner).to_dict(),
        "routes": inspect_linux_routes(runner=runner).to_dict(),
    }
    return OSObservation(
        "wsl",
        "boundary",
        "inspect",
        "Windows host <-> WSL guest",
        "Windows PowerShell and Linux iproute2",
        str(linux.get("routes", {}).get("observed_utc", "")),
        EnforcementStatus.UNKNOWN,
        values={
            "windows": windows,
            "linux": linux,
        },
        coverage_limitations=(
            "Separate host and guest observations do not prove cross-boundary isolation.",
            "A controlled, explicitly authorized bidirectional path test is required.",
        ),
    )
