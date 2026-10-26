
"""Platform-neutral contracts for policy enforcement and runtime acceptance.

Enforcement adapters mutate platform state. OS API adapters observe that state.
A successful mutation is not equivalent to successful runtime acceptance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class EnforcementStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    BLOCKED = "BLOCKED"


class AcceptanceStatus(str, Enum):
    NOT_RUN = "NOT_RUN"
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class EnforcementScope:
    """The platform resources an operation is permitted to affect."""

    platform: str
    adapter: str
    project: str | None = None
    docker_context: str | None = None
    resource_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Mutation:
    """A requested state change, independent of any specific platform."""

    boundary: str
    action: str
    resource: str
    parameters: Mapping[str, Any] = field(default_factory=dict)
    mandatory: bool = True


@dataclass(frozen=True)
class MutationOutcome:
    """The observed result of one attempted state change."""

    boundary: str
    action: str
    resource: str
    status: EnforcementStatus
    reason: str
    changed: bool = False
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "boundary": self.boundary,
            "action": self.action,
            "resource": self.resource,
            "status": self.status.value,
            "reason": self.reason,
            "changed": self.changed,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class EnforcementResult:
    """Result of a mutation or an independent acceptance operation.

    `status` describes the operation that actually ran.
    `acceptance_status` records the independent runtime-acceptance state.
    A PASS mutation with NOT_RUN acceptance is not proof of effective isolation.
    """

    operation: str
    status: EnforcementStatus
    scope: EnforcementScope
    read_only: bool
    reason: str
    findings: tuple[dict[str, Any], ...] = ()
    details: dict[str, Any] = field(default_factory=dict)
    occurred_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    acceptance_status: AcceptanceStatus = AcceptanceStatus.NOT_RUN
    outcomes: tuple[MutationOutcome, ...] = ()

    @property
    def passed(self) -> bool:
        """Whether this operation passed—not whether isolation was proven."""
        return self.status is EnforcementStatus.PASS

    @property
    def runtime_accepted(self) -> bool:
        return self.acceptance_status is AcceptanceStatus.PASS

    @property
    def fully_accepted(self) -> bool:
        return (
            self.status is EnforcementStatus.PASS
            and self.acceptance_status is AcceptanceStatus.PASS
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.details,
            "project": self.scope.project,
            "operation": self.operation,
            "status": self.status.value,
            "scope": {
                "platform": self.scope.platform,
                "adapter": self.scope.adapter,
                "project": self.scope.project,
                "docker_context": self.scope.docker_context,
                "resource_ids": list(self.scope.resource_ids),
            },
            "read_only": self.read_only,
            "reason": self.reason,
            "findings": list(self.findings),
            "outcomes": [item.to_dict() for item in self.outcomes],
            "acceptance_status": self.acceptance_status.value,
            "runtime_accepted": self.runtime_accepted,
            "fully_accepted": self.fully_accepted,
            "occurred_utc": self.occurred_utc,
        }
