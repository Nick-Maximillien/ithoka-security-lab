"""Structured operating-system observation and execution records.

OS API records describe what was observed or attempted.
Enforcement records describe policy application and enforcement outcomes.

Shared status vocabulary comes from enforcement.models. Evidence collection
has its own status because collecting evidence is not itself an enforcement
judgment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ..enforcement.models import EnforcementStatus


def utc_timestamp() -> str:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


class PrivilegeStatus(str, Enum):
    """Record the outcome of a native operation's privilege requirements."""

    NOT_REQUIRED = "NOT_REQUIRED"
    NOT_CHECKED = "NOT_CHECKED"
    AVAILABLE = "AVAILABLE"
    OBTAINED = "OBTAINED"
    DENIED = "DENIED"
    UNAVAILABLE = "UNAVAILABLE"


class OperationOutcome(str, Enum):
    """Outcome of attempting a native operation."""

    NOT_STARTED = "NOT_STARTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    TARGET_UNAVAILABLE = "TARGET_UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    TIMED_OUT = "TIMED_OUT"


class EvidenceStatus(str, Enum):
    """Status of evidence collection and interpretation.

    This is deliberately distinct from EnforcementStatus. Evidence may be
    collected successfully without proving that a boundary is enforced.
    """

    NOT_TESTED = "NOT_TESTED"
    COLLECTED = "COLLECTED"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class TargetIdentity:
    """Describe the intended native target and available identity evidence."""

    platform: str
    target: str
    subsystem: str | None = None
    host_name: str | None = None
    distribution: str | None = None
    context: str | None = None
    endpoint: str | None = None
    resource_id: str | None = None
    identity_verified: bool = False
    verification_source: str | None = None
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "target": self.target,
            "subsystem": self.subsystem,
            "host_name": self.host_name,
            "distribution": self.distribution,
            "context": self.context,
            "endpoint": self.endpoint,
            "resource_id": self.resource_id,
            "identity_verified": self.identity_verified,
            "verification_source": self.verification_source,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class PrivilegeOutcome:
    """Record required, checked, and obtained privilege for an operation."""

    required: bool
    status: PrivilegeStatus = PrivilegeStatus.NOT_CHECKED
    mechanism: str | None = None
    identity: str | None = None
    checked_utc: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "required": self.required,
            "status": self.status.value,
            "mechanism": self.mechanism,
            "identity": self.identity,
            "checked_utc": self.checked_utc,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CommandExecution:
    """Record one native command execution without treating it as verification."""

    command: tuple[str, ...]
    executable: str
    started_utc: str
    finished_utc: str
    returncode: int | None
    stdout: str
    stderr: str
    status: EnforcementStatus
    reason: str | None = None
    timed_out: bool = False
    duration_ms: int | None = None
    privilege: PrivilegeOutcome | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "executable": self.executable,
            "started_utc": self.started_utc,
            "finished_utc": self.finished_utc,
            "returncode": self.returncode,
            "stdout_characters": len(self.stdout),
            "stderr_characters": len(self.stderr),
            "status": self.status.value,
            "reason": self.reason,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "privilege": self.privilege.to_dict() if self.privilege else None,
        }


@dataclass(frozen=True)
class VerificationFinding:
    """Represent one comparison between expected and observed state."""

    name: str
    status: EnforcementStatus
    expected: str
    observed: Any
    reason: str | None = None
    evidence_source: str | None = None
    observed_utc: str = field(default_factory=utc_timestamp)
    target: TargetIdentity | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "expected": self.expected,
            "observed": self.observed,
            "reason": self.reason,
            "evidence_source": self.evidence_source,
            "observed_utc": self.observed_utc,
            "target": self.target.to_dict() if self.target else None,
        }


@dataclass(frozen=True)
class VerificationEvidence:
    """Evidence collected to determine whether an expected state is present."""

    name: str
    source: str
    collected_utc: str = field(default_factory=utc_timestamp)
    target: TargetIdentity | None = None
    status: EvidenceStatus = EvidenceStatus.NOT_TESTED
    expected: Any = None
    observed: Any = None
    command: CommandExecution | None = None
    parsed: bool | None = None
    complete: bool = False
    limitations: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "collected_utc": self.collected_utc,
            "target": self.target.to_dict() if self.target else None,
            "status": self.status.value,
            "expected": self.expected,
            "observed": self.observed,
            "command": self.command.to_dict() if self.command else None,
            "parsed": self.parsed,
            "complete": self.complete,
            "limitations": list(self.limitations),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class OSObservation:
    """Represent a read-only observation of an OS or runtime target."""

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
    target_identity: TargetIdentity | None = None
    evidence: tuple[VerificationEvidence, ...] = ()

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
            "target_identity": (
                self.target_identity.to_dict() if self.target_identity else None
            ),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class EnforcementOperation:
    """Record an enforcement attempt and its independently observed outcomes.

    `status` is the enforcement judgment. `outcome` describes execution.
    A successful native command does not, by itself, establish PASS.
    """

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
    target_identity: TargetIdentity | None = None
    privilege: PrivilegeOutcome | None = None
    outcome: OperationOutcome | None = None
    native_executable: str | None = None
    arguments: tuple[str, ...] = ()
    returncode: int | None = None
    execution_started: bool = False
    evidence: tuple[VerificationEvidence, ...] = ()

    @property
    def passed(self) -> bool:
        """True only when enforcement verification explicitly reports PASS."""
        return self.status is EnforcementStatus.PASS

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
            "verification": (
                self.verification.to_dict() if self.verification else None
            ),
            "errors": list(self.errors),
            "target_identity": (
                self.target_identity.to_dict() if self.target_identity else None
            ),
            "privilege": self.privilege.to_dict() if self.privilege else None,
            "outcome": self.outcome.value if self.outcome else None,
            "native_executable": self.native_executable,
            "arguments": list(self.arguments),
            "returncode": self.returncode,
            "execution_started": self.execution_started,
            "evidence": [item.to_dict() for item in self.evidence],
        }