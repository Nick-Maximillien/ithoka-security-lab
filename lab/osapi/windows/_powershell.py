"""Fixed-script PowerShell query support with robust JSON normalization."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation


def inspect_powershell(
    subsystem: str,
    script: str,
    *,
    runner: Any = subprocess.run,
    executable: str | None = None,
    coverage: tuple[str, ...] = (),
) -> OSObservation:
    powershell = executable or shutil.which("powershell.exe") or shutil.which("pwsh")
    if not powershell:
        return OSObservation(
            "windows",
            subsystem,
            "inspect",
            subsystem,
            "PowerShell cmdlets",
            "",
            EnforcementStatus.UNKNOWN,
            errors=("PowerShell executable is unavailable on this platform",),
            coverage_limitations=coverage,
        )
    execution = run_command(
        [
            powershell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference='Stop'; " + script,
        ],
        runner=runner,
        timeout=30,
    )
    if execution.status is not EnforcementStatus.PASS:
        return OSObservation(
            "windows",
            subsystem,
            "inspect",
            subsystem,
            "PowerShell cmdlets",
            execution.finished_utc,
            EnforcementStatus.UNKNOWN,
            execution=execution,
            errors=(execution.reason or "PowerShell query failed",),
            permission_limitations=("some fields may require an elevated PowerShell session",),
            coverage_limitations=coverage,
        )
    try:
        values = json.loads(execution.stdout)
    except (TypeError, ValueError) as exc:
        return OSObservation(
            "windows",
            subsystem,
            "inspect",
            subsystem,
            "PowerShell cmdlets",
            execution.finished_utc,
            EnforcementStatus.UNKNOWN,
            execution=execution,
            parsed=False,
            errors=(f"malformed PowerShell JSON: {exc}",),
            coverage_limitations=coverage,
        )
    if isinstance(values, dict):
        values = [values]
    if not isinstance(values, list):
        return OSObservation(
            "windows",
            subsystem,
            "inspect",
            subsystem,
            "PowerShell cmdlets",
            execution.finished_utc,
            EnforcementStatus.UNKNOWN,
            execution=execution,
            parsed=False,
            errors=("PowerShell JSON root must be an object or array",),
            coverage_limitations=coverage,
        )
    return OSObservation(
        "windows",
        subsystem,
        "inspect",
        subsystem,
        "PowerShell cmdlets",
        execution.finished_utc,
        EnforcementStatus.PASS,
        values=values,
        execution=execution,
        parsed=True,
        coverage_limitations=coverage,
    )
