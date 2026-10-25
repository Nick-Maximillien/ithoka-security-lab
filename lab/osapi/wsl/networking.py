"""Observe WSL networking mode and guest routes without changing settings."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation
from ..linux.forwarding import inspect_forwarding
from ..linux.interfaces import inspect_interfaces
from ..linux.routes import inspect_routes


def inspect_networking(
    runner: Any = None,
    linux_observations: dict[str, Any] | None = None,
) -> OSObservation:
    release = Path("/proc/sys/kernel/osrelease")
    try:
        is_wsl = "microsoft" in release.read_text(
            encoding="utf-8",
            errors="replace",
        ).lower()
    except OSError:
        is_wsl = False
    guest = linux_observations
    if is_wsl and guest is None:
        guest = {
            "interfaces": inspect_interfaces(runner).to_dict(),
            "routes": inspect_routes(runner).to_dict(),
            "forwarding": inspect_forwarding().to_dict(),
        }
    mode = None
    errors = []
    executable = shutil.which("wslinfo")
    if is_wsl and executable:
        options = {} if runner is None else {"runner": runner}
        result = run_command([executable, "--networking-mode"], **options)
        if result.status is EnforcementStatus.PASS:
            mode = result.stdout.strip()
        else:
            errors.append(result.reason or "WSL mode query failed")
    return OSObservation(
        "wsl",
        "networking",
        "inspect",
        "WSL networking paths",
        "guest iproute2/procfs and wslinfo",
        guest["routes"]["observed_utc"] if guest else "",
        EnforcementStatus.UNKNOWN,
        values={
            "is_wsl_guest": is_wsl,
            "networking_mode": mode,
            "guest_observations": guest,
        },
        errors=tuple(errors),
        coverage_limitations=(
            "Windows-side virtual interfaces and cross-boundary packet paths are not proven",
            "no active connectivity probe is performed by this read-only inspection",
        ),
    )
