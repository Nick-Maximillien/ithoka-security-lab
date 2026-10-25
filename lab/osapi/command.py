"""Bounded, shell-free command execution for OS inspectors."""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from ..enforcement.models import EnforcementStatus
from .models import CommandExecution

Runner = Callable[..., Any]


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_command(
    argv: Sequence[str],
    *,
    runner: Runner = subprocess.run,
    timeout: float = 10,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> CommandExecution:
    """Run an executable as argv, retaining outcome and captured diagnostics."""
    command = tuple(str(part) for part in argv)
    started = _utc()
    if not command or not command[0]:
        return CommandExecution(
            command=command,
            executable="",
            started_utc=started,
            finished_utc=_utc(),
            returncode=None,
            stdout="",
            stderr="",
            status=EnforcementStatus.BLOCKED,
            reason="command must include an executable",
        )
    executable = command[0]
    if shutil.which(executable) is None and not Path(executable).is_file():
        return CommandExecution(
            command=command,
            executable=Path(executable).name,
            started_utc=started,
            finished_utc=_utc(),
            returncode=None,
            stdout="",
            stderr="",
            status=EnforcementStatus.UNKNOWN,
            reason=f"executable is unavailable: {Path(executable).name}",
        )
    try:
        completed = runner(
            list(command),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=env,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandExecution(
            command=command,
            executable=Path(executable).name,
            started_utc=started,
            finished_utc=_utc(),
            returncode=None,
            stdout=_text(exc.stdout),
            stderr=_text(exc.stderr),
            status=EnforcementStatus.UNKNOWN,
            reason=f"command timed out after {timeout:g} seconds",
        )
    except PermissionError as exc:
        return CommandExecution(
            command=command,
            executable=Path(executable).name,
            started_utc=started,
            finished_utc=_utc(),
            returncode=None,
            stdout="",
            stderr="",
            status=EnforcementStatus.BLOCKED,
            reason=f"permission denied executing {Path(executable).name}: {exc}",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandExecution(
            command=command,
            executable=Path(executable).name,
            started_utc=started,
            finished_utc=_utc(),
            returncode=None,
            stdout="",
            stderr="",
            status=EnforcementStatus.UNKNOWN,
            reason=f"cannot execute {Path(executable).name}: {exc}",
        )
    returncode = getattr(completed, "returncode", None)
    stdout = _text(getattr(completed, "stdout", ""))
    stderr = _text(getattr(completed, "stderr", ""))
    success = returncode == 0
    return CommandExecution(
        command=command,
        executable=Path(executable).name,
        started_utc=started,
        finished_utc=_utc(),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        status=EnforcementStatus.PASS if success else EnforcementStatus.FAIL,
        reason=None if success else f"command returned exit status {returncode}",
    )


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def parse_json_execution(execution: CommandExecution) -> tuple[Any, str | None]:
    """Parse command JSON and return either the parsed value or explicit error."""
    import json

    if execution.status is not EnforcementStatus.PASS:
        return None, execution.reason or "command did not succeed"
    try:
        return json.loads(execution.stdout), None
    except (TypeError, ValueError) as exc:
        return None, f"malformed JSON output: {exc}"
