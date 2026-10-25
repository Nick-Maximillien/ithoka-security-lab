"""Linux interface and address inspection using iproute2 JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation


def inspect_interfaces(runner: Any = None) -> OSObservation:
    options = {} if runner is None else {"runner": runner}
    command = run_command(["ip", "-j", "-details", "address", "show"], **options)
    if command.status is not EnforcementStatus.PASS:
        return OSObservation(
            "linux",
            "interfaces",
            "inspect",
            "all",
            "iproute2",
            command.finished_utc,
            command.status,
            execution=command,
            errors=(command.reason or "ip address inspection failed",),
            coverage_limitations=("interface addresses and state unavailable",),
        )
    try:
        parsed = json.loads(command.stdout)
        if not isinstance(parsed, list) or any(not isinstance(item, dict) for item in parsed):
            raise ValueError("expected a JSON array of interfaces")
        values = []
        for interface in parsed:
            values.append({
                "name": interface.get("ifname"),
                "index": interface.get("ifindex"),
                "operstate": interface.get("operstate"),
                "flags": interface.get("flags", []),
                "link_type": interface.get("link_type"),
                "address": interface.get("address"),
                "mtu": interface.get("mtu"),
                "master": interface.get("master"),
                "addresses": [
                    {
                        "family": address.get("family"),
                        "local": address.get("local"),
                        "prefixlen": address.get("prefixlen"),
                        "scope": address.get("scope"),
                    }
                    for address in interface.get("addr_info", [])
                    if isinstance(address, dict)
                ],
            })
    except (ValueError, TypeError) as exc:
        return OSObservation(
            "linux",
            "interfaces",
            "inspect",
            "all",
            "iproute2",
            command.finished_utc,
            EnforcementStatus.UNKNOWN,
            execution=command,
            parsed=False,
            errors=(str(exc),),
        )
    return OSObservation(
        "linux",
        "interfaces",
        "inspect",
        "all",
        "iproute2",
        command.finished_utc,
        EnforcementStatus.PASS,
        values=values,
        execution=command,
        parsed=True,
        coverage_limitations=("observed interface state does not prove traffic isolation",),
    )
