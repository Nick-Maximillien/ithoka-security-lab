"""Docker context and daemon identity inspection."""

from __future__ import annotations

import json
import re
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import parse_json_execution, run_command
from ..models import OSObservation

_CONTEXT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def inspect_daemon(
    context: str | None = None,
    runner: Any = None,
    env: dict[str, str] | None = None,
) -> OSObservation:
    options = {} if runner is None else {"runner": runner}
    if env is not None:
        options["env"] = env
    context_result = run_command(["docker", "context", "show"], **options)
    if context_result.status is not EnforcementStatus.PASS:
        return OSObservation(
            "docker",
            "daemon",
            "inspect",
            context or "active context",
            "Docker CLI",
            context_result.finished_utc,
            EnforcementStatus.UNKNOWN,
            execution=context_result,
            errors=(context_result.reason or "active context unavailable",),
        )
    active = context_result.stdout.strip()
    selected = context or active
    if not _CONTEXT_RE.fullmatch(selected):
        return OSObservation(
            "docker",
            "daemon",
            "inspect",
            selected,
            "Docker CLI",
            context_result.finished_utc,
            EnforcementStatus.BLOCKED,
            values={"active_context": active},
            errors=("invalid Docker context identifier",),
        )
    prefix = ["docker", "--context", selected]
    endpoint_cmd = run_command(
        [*prefix, "context", "inspect", selected, "--format", "{{json .Endpoints.docker}}"],
        **options,
    )
    info_cmd = run_command(
        [
            *prefix,
            "info",
            "--format",
            "{{json .}}",
        ],
        **options,
    )
    compose_cmd = run_command(
        [*prefix, "compose", "version", "--short"],
        **options,
    )
    endpoint, endpoint_error = parse_json_execution(endpoint_cmd)
    info, info_error = parse_json_execution(info_cmd)
    errors = [error for error in (endpoint_error, info_error) if error]
    if endpoint is not None and not isinstance(endpoint, dict):
        errors.append("Docker context endpoint output is not an object")
        endpoint = None
    if info is not None and not isinstance(info, dict):
        errors.append("Docker daemon info output is not an object")
        info = None
    values = {
        "active_context": active,
        "selected_context": selected,
        "context_matches_active": selected == active,
        "endpoint": endpoint,
        "daemon": (
            {
                key: info.get(key)
                for key in (
                    "ID",
                    "Name",
                    "ServerVersion",
                    "OSType",
                    "Architecture",
                    "OperatingSystem",
                )
            }
            if info
            else None
        ),
        "compose_version": (
            compose_cmd.stdout.strip()
            if compose_cmd.status is EnforcementStatus.PASS
            else None
        ),
        "locality_warning": (
            "Context endpoint scheme is an observation, not proof of physical host."
        ),
    }
    status = (
        EnforcementStatus.PASS
        if not errors and info is not None and endpoint is not None
        else EnforcementStatus.UNKNOWN
    )
    if compose_cmd.status is not EnforcementStatus.PASS:
        values["compose_version_error"] = compose_cmd.reason
    return OSObservation(
        "docker",
        "daemon",
        "inspect",
        selected,
        "Docker Engine via CLI",
        info_cmd.finished_utc,
        status,
        values=values,
        parsed=not errors,
        errors=tuple(errors),
        coverage_limitations=("Docker context does not establish Windows/WSL trust boundary",),
    )
