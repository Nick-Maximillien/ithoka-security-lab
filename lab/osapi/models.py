"""Structured operating-system observation and execution records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..enforcement.models import EnforcementStatus


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CommandExecution:
    command: tuple[str, ...]
    executable: str
    started_utc: str
    finished_utc: str
    returncode: int | None
    stdout: str
    stderr: str
    status: EnforcementStatus
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "command": list(self.command),
            "executable": self.executable,
            "started_utc": self.started_utc,
            "finished_utc": self.finished_utc,
            "returncode": self.returncode,
            "stdout_characters": len(self.stdout),
            "stderr_characters": len(self.stderr),
            "status": self.status.value,
            "reason": self.reason,
        }
        return result


@dataclass(frozen=True)
class VerificationFinding:
    name: str
    status: EnforcementStatus
    expected: str
    observed: Any
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        return result


@dataclass(frozen=True)
class OSObservation:
    platform: str
    subsystem: str
    operation: str
    target: str
    source: str
    observed_utc: str
    status: EnforcementStatus
    values: Any = None
    execution: CommandExecution | None = None
    parsed: bool | None = None
    findings: tuple[VerificationFinding, ...] = ()
    errors: tuple[str, ...] = ()
    permission_limitations: tuple[str, ...] = ()
    coverage_limitations: tuple[str, ...] = ()
    read_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "subsystem": self.subsystem,
            "operation": self.operation,
            "target": self.target,
            "source": self.source,
            "observed_utc": self.observed_utc,
            "status": self.status.value,
            "values": self.values,
            "execution": self.execution.to_dict() if self.execution else None,
            "parsed": self.parsed,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": list(self.errors),
            "permission_limitations": list(self.permission_limitations),
            "coverage_limitations": list(self.coverage_limitations),
            "read_only": self.read_only,
        }


@dataclass(frozen=True)
class EnforcementOperation:
    platform: str
    operation: str
    target: str
    status: EnforcementStatus
    occurred_utc: str = field(default_factory=utc_timestamp)
    approval_reference: str | None = None
    before: OSObservation | None = None
    after: OSObservation | None = None
    verification: OSObservation | None = None
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "operation": self.operation,
            "target": self.target,
            "status": self.status.value,
            "occurred_utc": self.occurred_utc,
            "approval_reference": self.approval_reference,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "verification": self.verification.to_dict() if self.verification else None,
            "errors": list(self.errors),
        }
