"""IPv4 and IPv6 route-table inspection using iproute2 JSON."""

from __future__ import annotations

import json
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation


def inspect_routes(runner: Any = None) -> OSObservation:
    options = {} if runner is None else {"runner": runner}
    results = {}
    executions = []
    errors = []
    for family, args in (
        ("ipv4", ["ip", "-j", "-4", "route", "show", "table", "all"]),
        ("ipv6", ["ip", "-j", "-6", "route", "show", "table", "all"]),
    ):
        execution = run_command(args, **options)
        executions.append(execution.to_dict())
        if execution.status is not EnforcementStatus.PASS:
            errors.append(f"{family}: {execution.reason}")
            continue
        try:
            routes = json.loads(execution.stdout)
            if not isinstance(routes, list) or any(not isinstance(route, dict) for route in routes):
                raise ValueError("expected a JSON array of routes")
            results[family] = routes
        except (ValueError, TypeError) as exc:
            errors.append(f"{family}: malformed output: {exc}")
    status = EnforcementStatus.PASS if not errors else EnforcementStatus.UNKNOWN
    return OSObservation(
        "linux",
        "routes",
        "inspect",
        "IPv4 and IPv6 tables",
        "iproute2",
        executions[-1]["finished_utc"],
        status,
        values=results,
        parsed=not errors,
        errors=tuple(errors),
        coverage_limitations=("route observation is not a behavioral connectivity test",),
    )
