"""Detect observable WSL state and distribution metadata."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation, utc_timestamp


def inspect_state(runner: Any = None) -> OSObservation:
    release = platform.release()
    kernel_release = ""
    try:
        kernel_release = Path("/proc/sys/kernel/osrelease").read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        pass
    is_wsl = "microsoft" in release.lower() or "microsoft" in kernel_release.lower()
    if is_wsl:
        data = {
            "environment": "wsl-guest",
            "kernel_release": release,
            "distribution": platform.platform(),
        }
        errors = []
        source = "kernel release and platform"
        executable = shutil.which("wslinfo")
        if executable:
            options = {} if runner is None else {"runner": runner}
            query = run_command([executable, "--networking-mode"], **options)
            data["networking_mode"] = (
                query.stdout.strip()
                if query.status is EnforcementStatus.PASS
                else None
            )
            if query.status is not EnforcementStatus.PASS:
                errors.append(query.reason or "wslinfo failed")
        else:
            data["networking_mode"] = None
        return OSObservation(
            "wsl",
            "state",
            "inspect",
            "current WSL guest",
            source,
            utc_timestamp(),
            EnforcementStatus.PASS,
            values=data,
            errors=tuple(errors),
            coverage_limitations=(
                "Windows host WSL configuration is not available from guest kernel state",
            ),
        )

    options = {} if runner is None else {"runner": runner}
    listing = run_command(["wsl.exe", "--list", "--verbose"], **options)
    if listing.status is not EnforcementStatus.PASS:
        return OSObservation(
            "wsl",
            "state",
            "inspect",
            "Windows WSL distributions",
            "wsl.exe",
            listing.finished_utc,
            EnforcementStatus.UNKNOWN,
            execution=listing,
            errors=(listing.reason or "WSL distribution inventory unavailable",),
        )
    status = run_command(["wsl.exe", "--status"], **options)
    return OSObservation(
        "wsl",
        "state",
        "inspect",
        "Windows WSL distributions",
        "wsl.exe",
        listing.finished_utc,
        EnforcementStatus.PASS,
        values={
            "distribution_list": listing.stdout,
            "wsl_status": (
                status.stdout
                if status.status is EnforcementStatus.PASS
                else None
            ),
        },
        execution=listing,
        errors=(
            (status.reason or "WSL status query failed",)
            if status.status is not EnforcementStatus.PASS
            else ()
        ),
        coverage_limitations=(
            "WSL output is retained as text because localization varies",
            "WSL configuration and networking mode may require Windows-side inspection",
        ),
    )
