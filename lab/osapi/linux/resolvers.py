"""Read resolver configuration without issuing DNS queries."""

from __future__ import annotations

from pathlib import Path

from ...enforcement.models import EnforcementStatus
from ..models import OSObservation, utc_timestamp


def inspect_resolvers(path: Path = Path("/etc/resolv.conf")) -> OSObservation:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return OSObservation(
            "linux",
            "dns",
            "inspect",
            str(path),
            "filesystem",
            utc_timestamp(),
            EnforcementStatus.UNKNOWN,
            errors=(f"resolver configuration could not be read: {exc}",),
            coverage_limitations=("resolver behavior and bypass paths were not tested",),
        )
    nameservers = []
    search_domains = []
    options = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        fields = line.split()
        if len(fields) > 1 and fields[0] == "nameserver":
            nameservers.append(fields[1])
        elif len(fields) > 1 and fields[0] in {"search", "domain"}:
            search_domains.extend(fields[1:])
        elif len(fields) > 1 and fields[0] == "options":
            options.extend(fields[1:])
    return OSObservation(
        "linux",
        "dns",
        "inspect",
        str(path),
        "filesystem",
        utc_timestamp(),
        EnforcementStatus.PASS,
        values={
            "is_symlink": path.is_symlink(),
            "nameservers": nameservers,
            "search_domains": search_domains,
            "options": options,
        },
        parsed=True,
        coverage_limitations=(
            "resolver configuration is not proof of effective DNS path or DNS isolation",
            "no DNS query or bypass test was run",
        ),
    )
