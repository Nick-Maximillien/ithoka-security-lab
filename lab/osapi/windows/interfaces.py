"""Windows IP interface and address inspection."""

from __future__ import annotations

import subprocess
from typing import Any

from ._powershell import inspect_powershell

_SCRIPT = (
    "$items=Get-NetIPInterface | Select-Object InterfaceAlias,InterfaceIndex,"
    "AddressFamily,ConnectionState,Forwarding,WeakHostSend,WeakHostReceive,"
    "NlMtu,InterfaceMetric; "
    "$addresses=Get-NetIPAddress | Select-Object InterfaceAlias,InterfaceIndex,"
    "AddressFamily,IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin,AddressState; "
    "$items | ForEach-Object { $x=$_; [PSCustomObject]@{Interface=$x;"
    "Addresses=@($addresses | Where-Object InterfaceIndex -eq $x.InterfaceIndex "
    "| Where-Object AddressFamily -eq $x.AddressFamily)} } "
    "| ConvertTo-Json -Depth 6 -Compress"
)


def inspect_interfaces(
    runner: Any = subprocess.run,
    executable: str | None = None,
):
    return inspect_powershell(
        "interfaces",
        _SCRIPT,
        runner=runner,
        executable=executable,
        coverage=("interface enumeration does not establish Windows firewall enforcement",),
    )
