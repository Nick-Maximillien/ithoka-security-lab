"""Bounded, shell-free command execution for OS inspectors and actions.

This module executes native commands and records their execution outcomes.
It does not determine whether a security boundary is effectively enforced.

Docker context selection, policy validation, mutation ordering, and post-action
acceptance verification belong to the calling OS API or enforcement adapter.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from ..enforcement.models import EnforcementStatus
from .models import (
    CommandExecution,
    OperationOutcome,
    PrivilegeOutcome,
    PrivilegeStatus,
)

Runner = Callable[..., Any]

_DEFAULT_TIMEOUT = 10.0
_MAX_TIMEOUT = 300.0
_REDACTED = "[REDACTED]"

_SENSITIVE_ENV_NAMES = frozenset(
    {
        "API_KEY",
        "ACCESS_TOKEN",
        "AUTH_TOKEN",
        "BEARER_TOKEN",
        "CLIENT_SECRET",
        "PASSWORD",
        "PASSWD",
        "PRIVATE_KEY",
        "SECRET",
    }
)


def _utc() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _text(value: Any) -> str:
    """Convert captured subprocess output to text safely."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def _duration_ms(started: float) -> int:
    """Return elapsed monotonic time in milliseconds."""
    return max(0, round((time.monotonic() - started) * 1000))


def _is_sensitive_env_name(name: str) -> bool:
    """Recognize common secret-bearing environment variable names."""
    normalized = name.upper()

    return (
        normalized in _SENSITIVE_ENV_NAMES
        or normalized.endswith(
            ("_TOKEN", "_SECRET", "_PASSWORD", "_PASSWD")
        )
        or normalized.endswith(("_API_KEY", "_PRIVATE_KEY"))
    )


def _redact_text(value: str, secrets: Sequence[str]) -> str:
    """Redact known secret values from captured text."""
    redacted = value

    for secret in sorted(
        (item for item in secrets if item),
        key=len,
        reverse=True,
    ):
        redacted = redacted.replace(secret, _REDACTED)

    return redacted


def _redact_argv(
    command: Sequence[str],
    *,
    sensitive_values: Sequence[str],
    sensitive_arguments: frozenset[int],
) -> tuple[str, ...]:
    """Redact selected argument positions and known secret values."""
    result: list[str] = []

    for index, argument in enumerate(command):
        if index in sensitive_arguments:
            result.append(_REDACTED)
        else:
            result.append(_redact_text(argument, sensitive_values))

    return tuple(result)


def _safe_executable_name(executable: str) -> str:
    """Return a display name without exposing the full executable path."""
    return Path(executable).name


def _status_for_outcome(outcome: OperationOutcome) -> EnforcementStatus:
    """Map execution outcomes to the shared status vocabulary.

    These statuses describe command execution only. They do not constitute
    proof that a security policy or boundary is effective.
    """
    if outcome is OperationOutcome.SUCCEEDED:
        return EnforcementStatus.PASS

    if outcome is OperationOutcome.FAILED:
        return EnforcementStatus.FAIL

    if outcome is OperationOutcome.BLOCKED:
        return EnforcementStatus.BLOCKED

    if outcome is OperationOutcome.NOT_STARTED:
        return EnforcementStatus.UNKNOWN

    return EnforcementStatus.UNKNOWN


def _result(
    *,
    command: tuple[str, ...],
    executable: str,
    started_utc: str,
    outcome: OperationOutcome,
    returncode: int | None = None,
    stdout: str = "",
    stderr: str = "",
    reason: str | None = None,
    timed_out: bool = False,
    duration_ms: int | None = None,
    privilege: PrivilegeOutcome | None = None,
) -> CommandExecution:
    """Build a consistent structured execution result."""
    return CommandExecution(
        command=command,
        executable=executable,
        started_utc=started_utc,
        finished_utc=_utc(),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        status=_status_for_outcome(outcome),
        reason=reason,
        timed_out=timed_out,
        duration_ms=duration_ms,
        privilege=privilege,
    )


def _prepare_environment(
    env: Mapping[str, str] | None,
    *,
    inherit_env: bool,
    sensitive_env_names: frozenset[str],
    sensitive_values: Sequence[str],
) -> tuple[dict[str, str], tuple[str, ...]]:
    """Build a child environment and identify values to redact from output."""
    if env is None:
        child_env = os.environ.copy() if inherit_env else {}
    elif inherit_env:
        child_env = os.environ.copy()
        child_env.update({str(key): str(value) for key, value in env.items()})
    else:
        child_env = {str(key): str(value) for key, value in env.items()}

    explicitly_sensitive = {name.upper() for name in sensitive_env_names}
    secret_values = list(sensitive_values)

    for name, value in child_env.items():
        if (
            name.upper() in explicitly_sensitive
            or _is_sensitive_env_name(name)
        ):
            if value:
                secret_values.append(str(value))

    # Remove duplicate values without changing their order. Empty values are
    # intentionally excluded so they cannot cause accidental broad replacement.
    unique_secrets = tuple(
        dict.fromkeys(value for value in secret_values if value)
    )

    return child_env, unique_secrets


def run_command(
    argv: Sequence[str],
    *,
    runner: Runner = subprocess.run,
    timeout: float = _DEFAULT_TIMEOUT,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    inherit_env: bool = True,
    privilege: PrivilegeOutcome | None = None,
    sensitive_values: Sequence[str] = (),
    sensitive_arguments: frozenset[int] = frozenset(),
    sensitive_env_names: frozenset[str] = frozenset(),
) -> CommandExecution:
    """Execute a bounded command without a shell.

    Environment behavior:
      - env=None, inherit_env=True: inherit the current process environment.
      - env=mapping, inherit_env=True: inherit and override selected variables.
      - env=mapping, inherit_env=False: use only the supplied environment.
      - env=None, inherit_env=False: use an empty environment.

    Privilege handling:
      - This function never adds sudo, runas, or another elevation wrapper.
      - The caller must establish authorization before invoking this function.
      - The optional privilege record describes the caller's privilege checks;
        it does not independently establish that elevation was obtained.

    Redaction:
      - Redaction applies to the recorded command and captured output, not to
        the actual arguments passed to the subprocess.
      - Use sensitive_arguments for argument positions that must be hidden.
      - Use sensitive_values for known secrets.
      - Sensitive environment values are also redacted from captured output.
      - This is output redaction, not a guarantee that a child process cannot
        disclose secrets through other channels.

    The returned status describes command execution only.
    A successful command is not proof that a boundary is effectively enforced.
    """
    started_monotonic = time.monotonic()
    started_utc = _utc()

    try:
        raw_command = tuple(str(part) for part in argv)
    except (TypeError, ValueError) as exc:
        return _result(
            command=(),
            executable="",
            started_utc=started_utc,
            outcome=OperationOutcome.BLOCKED,
            reason=f"invalid command arguments: {type(exc).__name__}",
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    if not raw_command or not raw_command[0].strip():
        return _result(
            command=raw_command,
            executable="",
            started_utc=started_utc,
            outcome=OperationOutcome.BLOCKED,
            reason="command must include an executable",
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    try:
        timeout_value = float(timeout)
    except (TypeError, ValueError, OverflowError):
        return _result(
            command=raw_command,
            executable=_safe_executable_name(raw_command[0]),
            started_utc=started_utc,
            outcome=OperationOutcome.BLOCKED,
            reason="timeout must be a finite positive number",
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    if (
        not math.isfinite(timeout_value)
        or not 0 < timeout_value <= _MAX_TIMEOUT
    ):
        return _result(
            command=raw_command,
            executable=_safe_executable_name(raw_command[0]),
            started_utc=started_utc,
            outcome=OperationOutcome.BLOCKED,
            reason=(
                "timeout must be greater than zero and at most "
                f"{_MAX_TIMEOUT:g} seconds"
            ),
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    executable = raw_command[0]
    executable_name = _safe_executable_name(executable)

    try:
        child_env, secret_values = _prepare_environment(
            env,
            inherit_env=inherit_env,
            sensitive_env_names=sensitive_env_names,
            sensitive_values=sensitive_values,
        )
    except (TypeError, ValueError) as exc:
        return _result(
            command=(),
            executable=executable_name,
            started_utc=started_utc,
            outcome=OperationOutcome.BLOCKED,
            reason=f"invalid environment configuration: {type(exc).__name__}",
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    safe_command = _redact_argv(
        raw_command,
        sensitive_values=secret_values,
        sensitive_arguments=sensitive_arguments,
    )

    # Resolve the executable before invoking the runner. Explicit executable
    # paths are allowed, but must refer to an existing regular file.
    if os.path.dirname(executable):
        try:
            available = Path(executable).is_file()
        except OSError:
            available = False
    else:
        available = (
            shutil.which(executable, path=child_env.get("PATH")) is not None
        )

    if not available:
        return _result(
            command=safe_command,
            executable=executable_name,
            started_utc=started_utc,
            outcome=OperationOutcome.TARGET_UNAVAILABLE,
            reason=f"executable is unavailable: {executable_name}",
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    try:
        completed = runner(
            list(raw_command),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_value,
            cwd=str(cwd) if cwd is not None else None,
            env=child_env,
            shell=False,
        )

    except subprocess.TimeoutExpired as exc:
        stdout = _redact_text(_text(exc.stdout), secret_values)
        stderr = _redact_text(_text(exc.stderr), secret_values)

        return _result(
            command=safe_command,
            executable=executable_name,
            started_utc=started_utc,
            outcome=OperationOutcome.TIMED_OUT,
            stdout=stdout,
            stderr=stderr,
            reason=f"command timed out after {timeout_value:g} seconds",
            timed_out=True,
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    except PermissionError:
        return _result(
            command=safe_command,
            executable=executable_name,
            started_utc=started_utc,
            outcome=OperationOutcome.BLOCKED,
            reason=f"permission denied executing {executable_name}",
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    except FileNotFoundError:
        return _result(
            command=safe_command,
            executable=executable_name,
            started_utc=started_utc,
            outcome=OperationOutcome.TARGET_UNAVAILABLE,
            reason=(
                "executable or working directory is unavailable: "
                f"{executable_name}"
            ),
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    except subprocess.SubprocessError as exc:
        return _result(
            command=safe_command,
            executable=executable_name,
            started_utc=started_utc,
            outcome=OperationOutcome.FAILED,
            reason=f"subprocess execution failed: {type(exc).__name__}",
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    except OSError as exc:
        # Do not persist exception text because it may contain environment-
        # specific paths or details that are not needed for classification.
        outcome = (
            OperationOutcome.BLOCKED
            if isinstance(exc, PermissionError)
            else OperationOutcome.FAILED
        )

        return _result(
            command=safe_command,
            executable=executable_name,
            started_utc=started_utc,
            outcome=outcome,
            reason=f"cannot execute {executable_name}: {type(exc).__name__}",
            duration_ms=_duration_ms(started_monotonic),
            privilege=privilege,
        )

    returncode = getattr(completed, "returncode", None)
    stdout = _redact_text(
        _text(getattr(completed, "stdout", "")),
        secret_values,
    )
    stderr = _redact_text(
        _text(getattr(completed, "stderr", "")),
        secret_values,
    )

    if returncode == 0:
        outcome = OperationOutcome.SUCCEEDED
        reason = None
    elif returncode is None:
        outcome = OperationOutcome.FAILED
        reason = "runner returned no exit status"
    else:
        outcome = OperationOutcome.FAILED
        reason = "command returned a non-zero exit status"

    return _result(
        command=safe_command,
        executable=executable_name,
        started_utc=started_utc,
        outcome=outcome,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        reason=reason,
        duration_ms=_duration_ms(started_monotonic),
        privilege=privilege,
    )


def parse_json_execution(
    execution: CommandExecution,
) -> tuple[Any, str | None]:
    """Parse successful command JSON without leaking parser diagnostics.

    A JSON parse succeeding establishes only that the output is valid JSON.
    It does not establish that the observed or enforced system state is safe.
    """
    if execution.status is not EnforcementStatus.PASS:
        return None, execution.reason or "command did not succeed"

    try:
        return json.loads(execution.stdout), None
    except (TypeError, ValueError):
        return None, "malformed JSON output"
