"""Windows Defender Firewall profiles and enabled-rule inventory."""

from __future__ import annotations

import subprocess
from typing import Any

from ._powershell import inspect_powershell

_SCRIPT = (
    "$profiles=Get-NetFirewallProfile -PolicyStore ActiveStore | "
    "Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,"
    "AllowInboundRules,AllowLocalFirewallRules,PolicyStoreSourceType; "
    "$rules=Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True | "
    "Select-Object Name,DisplayName,Direction,Action,Profile,Enabled,"
    "PolicyStoreSourceType,PolicyStoreSource; "
    "[PSCustomObject]@{Profiles=@($profiles);EnabledRules=@($rules)} "
    "| ConvertTo-Json -Depth 5 -Compress"
)


def inspect_firewall(
    runner: Any = subprocess.run,
    executable: str | None = None,
):
    return inspect_powershell(
        "firewall",
        _SCRIPT,
        runner=runner,
        executable=executable,
        coverage=(
            "enabled rule filters/scopes are not expanded; default actions do not prove all rules harmless",
            "no lab-owned Windows rule verification or firewall mutation is implemented",
        ),
    )
