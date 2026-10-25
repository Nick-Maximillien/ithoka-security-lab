"""Listening TCP/UDP socket inspection with explicit ownership limitations."""

from __future__ import annotations

from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation


def inspect_sockets(runner: Any = None) -> OSObservation:
    options = {} if runner is None else {"runner": runner}
    execution = run_command(["ss", "-H", "-lntu", "-p"], **options)
    if execution.status is not EnforcementStatus.PASS:
        return OSObservation(
            "linux",
            "sockets",
            "inspect",
            "listening TCP/UDP sockets",
            "ss",
            execution.finished_utc,
            EnforcementStatus.UNKNOWN,
            execution=execution,
            errors=(execution.reason or "socket listing unavailable",),
            permission_limitations=("process ownership may require elevated privileges",),
        )
    sockets = []
    for line in execution.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        sockets.append({
            "protocol": fields[0],
            "state": fields[1],
            "recv_queue": fields[2],
            "send_queue": fields[3],
            "local_address": fields[4],
            "peer_address": fields[5] if len(fields) > 5 else None,
            "process": " ".join(fields[6:]) if len(fields) > 6 else None,
        })
    return OSObservation(
        "linux",
        "sockets",
        "inspect",
        "listening TCP/UDP sockets",
        "ss",
        execution.finished_utc,
        EnforcementStatus.PASS,
        values=sockets,
        execution=execution,
        parsed=True,
        permission_limitations=(
            ("process-to-socket ownership may be incomplete without root",)
            if any(socket["process"] is None for socket in sockets)
            else ()
        ),
    )
