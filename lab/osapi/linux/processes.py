"""Process inventory without command-line arguments that may contain secrets."""

from __future__ import annotations

from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation


def inspect_processes(runner: Any = None) -> OSObservation:
    options = {} if runner is None else {"runner": runner}
    execution = run_command(["ps", "-eo", "pid=,comm="], **options)
    if execution.status is not EnforcementStatus.PASS:
        return OSObservation(
            "linux",
            "processes",
            "inspect",
            "process identifiers and executable names",
            "procps",
            execution.finished_utc,
            EnforcementStatus.UNKNOWN,
            execution=execution,
            errors=(execution.reason or "process inventory unavailable",),
        )
    processes = []
    errors = []
    for line in execution.stdout.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or not fields[0].isdigit():
            errors.append("unexpected ps output line")
            continue
        processes.append({"pid": int(fields[0]), "name": fields[1]})
    return OSObservation(
        "linux",
        "processes",
        "inspect",
        "process identifiers and executable names",
        "procps",
        execution.finished_utc,
        EnforcementStatus.PASS if not errors else EnforcementStatus.UNKNOWN,
        values=processes,
        execution=execution,
        parsed=not errors,
        errors=tuple(errors),
        coverage_limitations=("command-line arguments are omitted to avoid exposing secrets",),
    )
