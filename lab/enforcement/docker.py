"""Docker inspection adapter backed by the existing project inspector."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from .models import EnforcementResult, EnforcementScope, EnforcementStatus


def _status(value: Any) -> EnforcementStatus:
    try:
        return EnforcementStatus(value)
    except ValueError:
        return EnforcementStatus.UNKNOWN


class DockerAdapter:
    """Run read-only effective-state checks for one owned Compose project."""

    def __init__(
        self,
        root: Path = Path("."),
        runner: Any = subprocess.run,
        inspector: Any | None = None,
    ) -> None:
        self.root = root
        self.runner = runner
        self.inspector = inspector

    def inspect(self, project: str) -> EnforcementResult:
        # Import lazily to retain networks.py as the policy/configuration owner.
        inspect_project = self.inspector
        if inspect_project is None:
            from ..networks import inspect_docker_project

            inspect_project = inspect_docker_project

        report = inspect_project(project, self.root, runner=self.runner)
        details = {
            key: value
            for key, value in report.items()
            if key not in {"status", "project", "read_only", "reason", "findings"}
        }
        return EnforcementResult(
            operation="inspect",
            status=_status(report.get("status")),
            scope=EnforcementScope(
                platform="docker",
                adapter="docker-compose",
                project=project,
                docker_context=report.get("active_context"),
            ),
            read_only=report.get("read_only") is True,
            reason=str(report.get("reason", "inspection returned no reason")),
            findings=tuple(
                finding
                for finding in report.get("findings", [])
                if isinstance(finding, dict)
            ),
            details=details,
        )

    def verify(self, project: str) -> EnforcementResult:
        """Independently re-inspect effective state; no cached result is used."""
        result = self.inspect(project)
        return EnforcementResult(
            operation="verify",
            status=result.status,
            scope=result.scope,
            read_only=True,
            reason=result.reason,
            findings=result.findings,
            details=result.details,
        )

    def inspect_os_api(
        self,
        project: str | None = None,
        context: str | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Return raw Docker Engine observations from the concrete OS API."""
        from ..osapi import inspect_docker

        return {
            name: observation.to_dict()
            for name, observation in inspect_docker(project, context).items()
        }


def inspect_docker_project(
    project: str,
    root: Path = Path("."),
    runner: Any = subprocess.run,
) -> dict[str, Any]:
    """Compatibility-shaped entry point for the existing CLI and lifecycle."""
    return DockerAdapter(root, runner).inspect(project).to_dict()
