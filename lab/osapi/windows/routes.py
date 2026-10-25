"""Windows IPv4/IPv6 route inspection."""

from __future__ import annotations

import subprocess
from typing import Any

from ._powershell import inspect_powershell

_SCRIPT = (
    "$routes=Get-NetRoute | Select-Object InterfaceAlias,InterfaceIndex,"
    "AddressFamily,DestinationPrefix,NextHop,RouteMetric,Protocol,State; "
    "$routes | ConvertTo-Json -Depth 4 -Compress"
)


def inspect_routes(
    runner: Any = subprocess.run,
    executable: str | None = None,
):
    return inspect_powershell(
        "routes",
        _SCRIPT,
        runner=runner,
        executable=executable,
        coverage=("route inventory is not an active connectivity test",),
    )
