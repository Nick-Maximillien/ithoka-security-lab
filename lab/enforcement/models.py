"""Typed result contracts shared by enforcement adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EnforcementStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class EnforcementScope:
    platform: str
    adapter: str
    project: str | None = None
    docker_context: str | None = None


@dataclass(frozen=True)
class EnforcementResult:
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

    @property
    def passed(self) -> bool:
        return self.status is EnforcementStatus.PASS

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
            },
            "read_only": self.read_only,
            "reason": self.reason,
            "findings": list(self.findings),
            "occurred_utc": self.occurred_utc,
        }
