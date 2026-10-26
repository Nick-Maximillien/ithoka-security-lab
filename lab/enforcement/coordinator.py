
"""Coordinate platform enforcement and gate lifecycle transitions."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from ..foundation import LabError
from .docker import DockerAdapter
from .linux import LinuxWslAdapter
from .models import (
    AcceptanceStatus,
    EnforcementResult,
    EnforcementStatus,
)


class EnforcementCoordinator:
    """Dispatch mutations and require explicit results before lifecycle changes."""

    def __init__(
        self,
        root: Path = Path("."),
        docker_runner: Any = None,
        docker_inspector: Any | None = None,
    ) -> None:
        self.root = Path(root)
        kwargs: dict[str, Any] = {"root": self.root}
        if docker_runner is not None:
            kwargs["runner"] = docker_runner
        if docker_inspector is not None:
            kwargs["inspector"] = docker_inspector
        self.docker = DockerAdapter(**kwargs)

    def apply_docker_policy(
        self,
        project: str,
        policy: Mapping[str, Any],
        *,
        context: str | None = None,
        approve_disruptive_changes: bool = False,
    ) -> EnforcementResult:
        """Apply supported Docker mutations for an already-owned project.

        The policy must be resolved by the policy layer before it reaches this
        method. The adapter must not reinterpret profile inheritance or policy
        precedence independently.
        """
        return self.docker.apply(
            project,
            policy,
            context=context,
            approve_disruptive_changes=approve_disruptive_changes,
        )

    def verify_linux_boundary(
        self,
        project: str,
        policy_file: Path,
        *,
        environment: dict[str, str] | None = None,
    ) -> EnforcementResult:
        """Run the existing Linux/WSL policy verification path."""
        return LinuxWslAdapter(
            self.root,
            environment=environment,
        ).verify(project, policy_file)

    def inspect_platforms(
        self,
        *,
        project: str | None = None,
        context: str | None = None,
    ) -> dict[str, Any]:
        """Collect observations through the existing OS API layer."""
        from ..osapi import inspect_platforms

        docker_observations = self.docker.inspect_os_api(project, context)
        return inspect_platforms(
            project=project,
            context=context,
            docker_observations=docker_observations,
        )

    @staticmethod
    def require_mutations_pass(
        results: Iterable[EnforcementResult],
        transition: str,
    ) -> None:
        """Block a transition unless every required mutation operation passed."""
        failures = [
            f"{result.scope.adapter}:{result.status.value} ({result.reason})"
            for result in results
            if result.status is not EnforcementStatus.PASS
        ]
        if failures:
            raise LabError(
                f"{transition} blocked by failed enforcement mutations: "
                + "; ".join(failures)
            )

    @staticmethod
    def require_runtime_acceptance(
        results: Iterable[EnforcementResult],
        transition: str,
    ) -> None:
        """Block a transition unless independent acceptance explicitly passed."""
        failures: list[str] = []

        for result in results:
            if result.status is not EnforcementStatus.PASS:
                failures.append(
                    f"{result.scope.adapter}:mutation="
                    f"{result.status.value} ({result.reason})"
                )
            if result.acceptance_status is not AcceptanceStatus.PASS:
                failures.append(
                    f"{result.scope.adapter}:acceptance="
                    f"{result.acceptance_status.value}"
                )

        if failures:
            raise LabError(
                f"{transition} blocked by unaccepted enforcement: "
                + "; ".join(failures)
            )

    @staticmethod
    def require_pass(
        results: Iterable[EnforcementResult],
        transition: str,
    ) -> None:
        """Compatibility gate for callers using the original coordinator API.

        This checks operation status only. Use require_runtime_acceptance()
        whenever the lifecycle transition requires proof of effective behavior.
        """
        EnforcementCoordinator.require_mutations_pass(results, transition)
