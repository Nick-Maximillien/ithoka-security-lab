"""Lifecycle gate helpers for mandatory enforcement results."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from ..foundation import LabError
from .docker import DockerAdapter
from .linux import LinuxWslAdapter
from .models import EnforcementResult, EnforcementStatus


class EnforcementCoordinator:
    """Evaluate fresh adapter results before lifecycle transitions."""

    def __init__(
        self,
        root: Path = Path("."),
        docker_inspector: Any | None = None,
    ) -> None:
        self.docker = DockerAdapter(root, inspector=docker_inspector)

    def inspect_docker(self, project: str) -> EnforcementResult:
        return self.docker.inspect(project)

    def verify_linux_boundary(
        self,
        project: str,
        policy_file: Path,
        *,
        environment: dict[str, str] | None = None,
    ) -> EnforcementResult:
        return LinuxWslAdapter(
            self.docker.root,
            environment=environment,
        ).verify(project, policy_file)

    def inspect_platforms(
        self,
        *,
        project: str | None = None,
        context: str | None = None,
    ) -> dict[str, Any]:
        """Collect fresh, separate OS observations for every supported host."""
        from ..osapi import inspect_platforms

        docker_observations = self.docker.inspect_os_api(project, context)
        return inspect_platforms(
            project=project,
            context=context,
            docker_observations=docker_observations,
        )

    @staticmethod
    def require_pass(
        results: Iterable[EnforcementResult],
        transition: str,
    ) -> None:
        failures = [
            f"{result.scope.adapter}:{result.status.value} ({result.reason})"
            for result in results
            if result.status is not EnforcementStatus.PASS
        ]
        if failures:
            raise LabError(
                f"{transition} blocked by mandatory enforcement results: "
                + "; ".join(failures)
            )
