"""Windows listening TCP and UDP endpoint inspection."""

from __future__ import annotations

import subprocess
from typing import Any

from ._powershell import inspect_powershell

_SCRIPT = (
    "$tcp=Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
    "Select-Object LocalAddress,LocalPort,OwningProcess,State; "
    "$udp=Get-NetUDPEndpoint -ErrorAction SilentlyContinue | "
    "Select-Object LocalAddress,LocalPort,OwningProcess; "
    "[PSCustomObject]@{TCP=@($tcp);UDP=@($udp)} | ConvertTo-Json -Depth 4 -Compress"
)


def inspect_sockets(
    runner: Any = subprocess.run,
    executable: str | None = None,
):
    return inspect_powershell(
        "sockets",
        _SCRIPT,
        runner=runner,
        executable=executable,
        coverage=("endpoint enumeration may be limited by Windows permissions",),
    )
