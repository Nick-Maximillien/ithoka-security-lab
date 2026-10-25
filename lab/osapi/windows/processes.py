"""Windows process names for socket owner PIDs; command lines are excluded."""

from __future__ import annotations

import subprocess
from typing import Any

from ._powershell import inspect_powershell

_SCRIPT = (
    "Get-Process | Select-Object Id,ProcessName | ConvertTo-Json -Depth 3 -Compress"
)


def inspect_processes(
    runner: Any = subprocess.run,
    executable: str | None = None,
):
    return inspect_powershell(
        "processes",
        _SCRIPT,
        runner=runner,
        executable=executable,
        coverage=("process command lines are excluded to avoid disclosing secrets",),
    )
