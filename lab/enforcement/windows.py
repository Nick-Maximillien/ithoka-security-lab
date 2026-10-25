"""Read-only Windows host inspection; no firewall mutation is implemented."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any

from .models import EnforcementResult, EnforcementScope, EnforcementStatus

class WindowsHostAdapter:
    """Observe Windows Firewall and interface state without changing either."""

    def __init__(
        self,
        runner: Any = subprocess.run,
        executable: str | None = None,
    ) -> None:
        self.runner = runner
        self.executable = executable or shutil.which("powershell.exe") or shutil.which("pwsh")

    def inspect(self) -> EnforcementResult:
        from ..osapi.windows.firewall import inspect_firewall
        from ..osapi.windows.interfaces import inspect_interfaces
        from ..osapi.windows.processes import inspect_processes
        from ..osapi.windows.routes import inspect_routes
        from ..osapi.windows.sockets import inspect_sockets

        scope = EnforcementScope(
            platform="windows",
            adapter="windows-read-only-os-api",
        )
        observers = {
            "firewall": inspect_firewall,
            "interfaces": inspect_interfaces,
            "routes": inspect_routes,
            "sockets": inspect_sockets,
            "processes": inspect_processes,
        }
        observed = {
            name: function(
                runner=self.runner,
                executable=self.executable,
            ).to_dict()
            for name, function in observers.items()
        }
        return EnforcementResult(
            operation="inspect",
            status=EnforcementStatus.UNKNOWN,
            scope=scope,
            read_only=True,
            reason=(
                "Windows firewall and interfaces were observed, but no approved "
                "Windows enforcement policy was independently verified"
            ),
            details={"observed": observed},
        )

    def apply(self, *_args: Any, **_kwargs: Any) -> EnforcementResult:
        return EnforcementResult(
            operation="apply",
            status=EnforcementStatus.BLOCKED,
            scope=EnforcementScope(platform="windows", adapter="powershell-read-only"),
            read_only=True,
            reason="Windows host enforcement is unsupported; no firewall changes were made",
        )

    def verify(self, *_args: Any, **_kwargs: Any) -> EnforcementResult:
        return EnforcementResult(
            operation="verify",
            status=EnforcementStatus.UNKNOWN,
            scope=EnforcementScope(platform="windows", adapter="powershell-read-only"),
            read_only=True,
            reason=(
                "Windows lab-owned firewall rules and behavioral controls "
                "cannot currently be verified"
            ),
        )

    def restore(self, *_args: Any, **_kwargs: Any) -> EnforcementResult:
        return EnforcementResult(
            operation="restore",
            status=EnforcementStatus.BLOCKED,
            scope=EnforcementScope(platform="windows", adapter="powershell-read-only"),
            read_only=True,
            reason="Windows host restoration is unsupported; no firewall changes were made",
        )
