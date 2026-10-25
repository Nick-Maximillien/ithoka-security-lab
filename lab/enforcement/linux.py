"""Scoped Linux/WSL network-boundary adapter."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from ..foundation import LabError, ensure_inside
from ..osapi.linux import (
    inspect_firewall,
    inspect_forwarding,
    inspect_interfaces,
    inspect_mounts,
    inspect_processes,
    inspect_proxy_environment,
    inspect_resolvers,
    inspect_routes,
    inspect_sockets,
    inspect_sysctl,
)
from ..osapi.models import OSObservation
from ..osapi.actions import OSActionStatus, execute_network_boundary_action
from .models import EnforcementResult, EnforcementScope, EnforcementStatus

_PROJECT_RE = re.compile(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}")
_ACTIONS = {"apply", "verify", "remove"}


def _verify_project_chains(
    observation: OSObservation,
    project: str,
    *,
    should_exist: bool,
) -> dict[str, Any]:
    if observation.status is not EnforcementStatus.PASS:
        return {
            "status": EnforcementStatus.UNKNOWN.value,
            "reason": "effective IPv4/IPv6 firewall state was not fully observed",
        }
    if not isinstance(observation.values, dict):
        return {
            "status": EnforcementStatus.UNKNOWN.value,
            "reason": "effective IPv4/IPv6 firewall state is malformed",
        }
    suffix = hashlib.sha256(project.encode("utf-8")).hexdigest()[:10]
    expected = {
        "ipv4": {
            f"SLB{suffix}4",
            f"SLX{suffix}E4",
        },
        "ipv6": {
            f"SLB{suffix}6",
            f"SLX{suffix}E6",
        },
    }
    results = {}
    for family, expected_chains in expected.items():
        state = observation.values.get(family)
        if not isinstance(state, dict):
            return {
                "status": EnforcementStatus.UNKNOWN.value,
                "reason": f"{family} firewall state is missing",
            }
        declarations = state.get("chains")
        rules = state.get("rules")
        if not isinstance(declarations, list) or not isinstance(rules, list):
            return {
                "status": EnforcementStatus.UNKNOWN.value,
                "reason": f"{family} chains or rules are malformed",
            }
        declared_names = {
            item.get("name")
            for item in declarations
            if isinstance(item, dict) and item.get("table") == "filter"
        }
        references = {
            item.get("jump_target")
            for item in rules
            if isinstance(item, dict) and item.get("table") == "filter"
        }
        present_chains = sorted(expected_chains & declared_names)
        present_refs = sorted(expected_chains & references)
        passed = (
            expected_chains <= declared_names
            and expected_chains <= references
            if should_exist
            else not expected_chains & declared_names
            and not expected_chains & references
        )
        results[family] = {
            "status": (
                EnforcementStatus.PASS.value
                if passed
                else EnforcementStatus.FAIL.value
            ),
            "expected_chains": sorted(expected_chains),
            "observed_chains": present_chains,
            "observed_jump_targets": present_refs,
        }
        if not passed:
            return {
                "status": EnforcementStatus.FAIL.value,
                "reason": f"{family} owned chain state did not match expectation",
                "families": results,
            }
    return {"status": EnforcementStatus.PASS.value, "families": results}


class LinuxWslAdapter:
    """Use the repository's owned-rule script; never accepts arbitrary argv."""

    def __init__(
        self,
        root: Path,
        runner: Any = subprocess.run,
        environment: dict[str, str] | None = None,
    ) -> None:
        self.root = root.resolve()
        self.runner = runner
        self.environment = environment or os.environ.copy()

    def inspect(self) -> EnforcementResult:
        observations = {
            "interfaces": inspect_interfaces(self.runner).to_dict(),
            "routes": inspect_routes(self.runner).to_dict(),
            "forwarding": inspect_forwarding().to_dict(),
            "sysctl": inspect_sysctl().to_dict(),
            "firewall": inspect_firewall(self.runner).to_dict(),
            "sockets": inspect_sockets(self.runner).to_dict(),
            "processes": inspect_processes(self.runner).to_dict(),
            "dns": inspect_resolvers().to_dict(),
            "proxies": inspect_proxy_environment().to_dict(),
            "mounts": inspect_mounts().to_dict(),
        }
        return EnforcementResult(
            operation="inspect",
            status=EnforcementStatus.UNKNOWN,
            scope=EnforcementScope(
                platform="linux-wsl",
                adapter="read-only-os-api",
            ),
            read_only=True,
            reason=(
                "Linux/WSL state was observed; project policy and packet behavior "
                "require separate verification; collection success is not enforcement"
            ),
            details={"inventory": observations},
        )

    def apply(
        self,
        project: str,
        policy_file: Path,
        approval_reference: str | None,
    ) -> EnforcementResult:
        applied = self._execute(
            "apply", project, policy_file, approval_reference
        )
        if applied.status is not EnforcementStatus.PASS:
            return applied
        verified = self._execute("verify", project, policy_file, None)
        restoration = None
        if verified.status is not EnforcementStatus.PASS:
            restoration = self._execute(
                "remove",
                project,
                policy_file,
                approval_reference,
            )
        return EnforcementResult(
            operation="apply",
            status=verified.status,
            scope=applied.scope,
            read_only=False,
            reason=(
                "apply completed and independent verification passed"
                if verified.status is EnforcementStatus.PASS
                else f"apply completed but independent verification was {verified.status.value}"
            ),
            findings=verified.findings,
            details={
                "approval_reference": approval_reference,
                "apply": applied.to_dict(),
                "verification": verified.to_dict(),
                "containment_restoration": (
                    restoration.to_dict() if restoration is not None else None
                ),
            },
        )

    def verify(self, project: str, policy_file: Path) -> EnforcementResult:
        return self._execute("verify", project, policy_file, None)

    def restore(
        self,
        project: str,
        policy_file: Path,
        approval_reference: str | None,
    ) -> EnforcementResult:
        return self._execute("remove", project, policy_file, approval_reference)

    def _execute(
        self,
        action: str,
        project: str,
        policy_file: Path,
        approval_reference: str | None,
    ) -> EnforcementResult:
        scope = EnforcementScope(
            platform="linux-wsl",
            adapter="network-boundary.sh",
            project=project,
        )
        if (
            action not in _ACTIONS
            or not isinstance(project, str)
            or not _PROJECT_RE.fullmatch(project)
        ):
            return EnforcementResult(
                operation=action,
                status=EnforcementStatus.BLOCKED,
                scope=scope,
                read_only=action == "verify",
                reason="unsupported action or invalid owned project identifier",
            )
        if action in {"apply", "remove"} and (
            not isinstance(approval_reference, str)
            or not approval_reference.strip()
        ):
            return EnforcementResult(
                operation=action,
                status=EnforcementStatus.BLOCKED,
                scope=scope,
                read_only=False,
                reason="explicit operator approval reference is required",
            )

        before_firewall = (
            inspect_firewall(self.runner).to_dict()
            if action in {"apply", "remove"}
            else None
        )
        try:
            policy = ensure_inside(
                self.root,
                policy_file,
                "pinned network policy",
            )
        except (LabError, OSError, ValueError) as exc:
            return EnforcementResult(
                operation=action,
                status=EnforcementStatus.BLOCKED,
                scope=scope,
                read_only=action == "verify",
                reason=f"policy path is outside the repository: {exc}",
            )
        if not policy.is_file() or policy.is_symlink():
            return EnforcementResult(
                operation=action,
                status=EnforcementStatus.BLOCKED,
                scope=scope,
                read_only=action == "verify",
                reason="pinned policy must be an existing regular non-symlink file",
            )

        script = self.root / "scripts" / "network-boundary.sh"
        if not script.is_file() or script.is_symlink():
            return EnforcementResult(
                operation=action,
                status=EnforcementStatus.UNKNOWN,
                scope=scope,
                read_only=action == "verify",
                reason="owned network-boundary adapter is unavailable",
            )
        if (
            action == "apply"
            and before_firewall is not None
            and before_firewall.get("status") != EnforcementStatus.PASS.value
        ):
            return EnforcementResult(
                operation=action,
                status=EnforcementStatus.UNKNOWN,
                scope=scope,
                read_only=True,
                reason=(
                    "cannot apply firewall controls until current IPv4 and IPv6 "
                    "kernel rulesets are independently readable"
                ),
                details={"before_firewall": before_firewall},
            )
        executed = execute_network_boundary_action(
            action,
            project,
            policy,
            self.root,
            runner=self.runner,
            environment=self.environment,
            docker_context=self.environment.get("DOCKER_CONTEXT"),
        )
        if executed.status is not OSActionStatus.SUCCEEDED:
            if executed.status in {
                OSActionStatus.FAILED,
                OSActionStatus.TIMED_OUT,
            }:
                execution_status = EnforcementStatus.FAIL
            elif executed.status in {
                OSActionStatus.BLOCKED,
                OSActionStatus.UNSUPPORTED,
            }:
                execution_status = EnforcementStatus.BLOCKED
            else:
                execution_status = EnforcementStatus.UNKNOWN
            return EnforcementResult(
                operation=action,
                status=execution_status,
                scope=scope,
                read_only=action == "verify",
                reason=executed.reason or "native boundary action failed",
                details={
                    "os_action": executed.to_dict(),
                    "before_firewall": before_firewall,
                },
            )

        after_firewall = inspect_firewall(self.runner)
        if after_firewall.status is not EnforcementStatus.PASS:
            return EnforcementResult(
                operation=action,
                status=EnforcementStatus.UNKNOWN,
                scope=scope,
                read_only=action == "verify",
                reason=(
                    "network-boundary command returned success but a fresh "
                    "kernel firewall observation was incomplete"
                ),
                details={
                    "os_action": executed.to_dict(),
                    "before_firewall": before_firewall,
                    "after_firewall": after_firewall.to_dict(),
                },
            )
        kernel_verification = _verify_project_chains(
            after_firewall,
            project,
            should_exist=action != "remove",
        )
        if kernel_verification["status"] != EnforcementStatus.PASS.value:
            return EnforcementResult(
                operation=action,
                status=EnforcementStatus(
                    kernel_verification["status"]
                ),
                scope=scope,
                read_only=action == "verify",
                reason=kernel_verification.get(
                    "reason",
                    "fresh kernel ruleset does not contain the expected owned chains",
                ),
                details={
                    "os_action": executed.to_dict(),
                    "before_firewall": before_firewall,
                    "after_firewall": after_firewall.to_dict(),
                    "kernel_verification": kernel_verification,
                },
            )

        # The shell adapter's apply/remove paths include structural checks of
        # the exact owned chains and persist their ownership state.
        return EnforcementResult(
            operation=action,
            status=EnforcementStatus.PASS,
            scope=scope,
            read_only=action == "verify",
            reason=f"owned network-boundary {action} completed",
            details={
                "os_action": executed.to_dict(),
                "approval_reference": approval_reference,
                "before_firewall": before_firewall,
                "after_firewall": after_firewall.to_dict(),
                "kernel_verification": kernel_verification,
            },
        )
