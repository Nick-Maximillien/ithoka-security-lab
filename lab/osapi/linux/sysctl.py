"""Read Linux kernel networking settings from procfs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..models import OSObservation, utc_timestamp

SYSCTL_PATHS = {
    "ipv4_forwarding": Path("/proc/sys/net/ipv4/ip_forward"),
    "ipv6_forwarding": Path("/proc/sys/net/ipv6/conf/all/forwarding"),
    "ipv6_default_forwarding": Path("/proc/sys/net/ipv6/conf/default/forwarding"),
    "rp_filter": Path("/proc/sys/net/ipv4/conf/all/rp_filter"),
    "accept_redirects_ipv4": Path("/proc/sys/net/ipv4/conf/all/accept_redirects"),
    "accept_redirects_ipv6": Path("/proc/sys/net/ipv6/conf/all/accept_redirects"),
}


def inspect_sysctl(paths: dict[str, Path] | None = None) -> OSObservation:
    observed: dict[str, Any] = {}
    errors = []
    for name, path in (paths or SYSCTL_PATHS).items():
        try:
            raw = path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            observed[name] = {"status": "UNKNOWN", "reason": str(exc)}
            errors.append(f"{name}: {exc}")
            continue
        if raw not in {"0", "1"} and not raw.isdecimal():
            observed[name] = {"status": "UNKNOWN", "raw": raw}
            errors.append(f"{name}: unexpected kernel value")
            continue
        value = int(raw)
        observed[name] = {
            "status": "DISABLED" if value == 0 else "ENABLED",
            "value": value,
        }
    return OSObservation(
        "linux",
        "sysctl",
        "inspect",
        "network kernel parameters",
        "procfs",
        utc_timestamp(),
        EnforcementStatus.PASS if not errors else EnforcementStatus.UNKNOWN,
        values=observed,
        parsed=not errors,
        errors=tuple(errors),
        coverage_limitations=("kernel parameter values alone do not establish network isolation",),
    )
