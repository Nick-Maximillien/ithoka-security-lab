#!/usr/bin/env python3
"""Security research lab CLI with consistent policy, enforcement, and acceptance status."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from .construction import (
    construct_investigation,
    dispose_investigation,
    validate_investigation,
    write_plan,
)
from .evidence import archive_evidence
from .foundation import (
    CAPABILITIES_FILE,
    LabError,
    ROOT,
    load_catalog,
    load_materials,
)
from .networks import (
    BOUNDARIES,
    list_network_profiles,
    network_policy_drift,
    network_capabilities,
    build_enforcement_plan,
    configure_machine,
    discover_network_inventory,
    inspect_owned_network,
    policy_json,
    resolve_project_network_policy,
    resolve_network_policy,
    select_network_profile,
    validate_network_setup,
    validate_machine_configuration,
    validate_runtime_support,
    validate_network_configuration,
)
from .workspace import (
    collect_evidence,
    destroy_experiment,
    enter_experiment,
    execute_tool,
    init_experiment,
    inspect_experiment,
    reset_experiment,
    stop_experiment,
)
from .runtime import (
    admit_experiment,
    request_maintenance,
    release_experiment,
    runtime_configure,
    runtime_inspect,
    runtime_doctor,
    runtime_recover,
    runtime_restart,
    runtime_start,
    runtime_status,
    runtime_stop,
    runtime_verify,
)

# Runtime's readiness check validates the pinned project policy and acceptance
# evidence. It is intentionally reused rather than reimplementing its schema.
from .runtime import _network_readiness as runtime_network_readiness


POLICY_STATUS_SCHEMA = "ithoka.security-lab.policy-status.v1"
NETWORK_BOUNDARY_SCRIPT = ROOT / "scripts" / "network-boundary.sh"
POLICY_STATE_DIR = ROOT / "state" / "network-boundary"


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str)


def _emit(value: Any) -> None:
    print(_json(value))


def _project_policy_path(project: str) -> Path:
    """Return the canonical location for a project's pinned network policy."""
    return POLICY_STATE_DIR / f"{project}-network-policy.json"


def _write_policy_atomically(path: Path, policy: dict[str, Any]) -> None:
    """Persist the exact policy used for enforcement without partial writes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(policy_json(policy), encoding="utf-8")
        temporary.replace(path)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _policy_definition_status(policy: dict[str, Any]) -> dict[str, Any]:
    """Describe intent only; this function does not claim enforcement."""
    boundaries = policy.get("boundaries", {})
    result: dict[str, Any] = {}

    for name in BOUNDARIES:
        definition = boundaries.get(name)
        if isinstance(definition, dict):
            result[name] = {
                "status": "DEFINED",
                "mode": definition.get("mode", "UNSPECIFIED"),
                "rules": definition,
            }
        else:
            result[name] = {
                "status": "INVALID_OR_MISSING",
                "mode": None,
                "rules": None,
            }

    return {
        "status": (
            "DEFINED"
            if all(item["status"] == "DEFINED" for item in result.values())
            else "INVALID"
        ),
        "profile": policy.get("profile"),
        "policy_identity": policy.get("provenance"),
        "boundaries": result,
    }


def _support_status(policy: dict[str, Any]) -> dict[str, Any]:
    """Report whether the selected policy is supported by known mechanisms."""
    try:
        validate_runtime_support(policy)
    except LabError as exc:
        return {
            "status": "UNSUPPORTED",
            "supported": False,
            "reason": str(exc),
        }

    return {
        "status": "SUPPORTED",
        "supported": True,
        "reason": None,
    }


def _host_prerequisite_status(
    profile: str | None = None,
) -> dict[str, Any]:
    """
    Discover and validate host prerequisites before policy activation.

    This is a preflight result, not proof that a policy has been enforced.
    """
    result: dict[str, Any] = {
        "status": "NOT_TESTED",
        "profile": profile,
        "machine_configuration": "NOT_TESTED",
        "network_setup": "NOT_TESTED",
        "capabilities": "NOT_TESTED",
        "inventory": "NOT_TESTED",
        "errors": [],
    }

    try:
        # Discovery is read-only. It must not be treated as enforcement.
        inventory = discover_network_inventory()
        result["inventory"] = "DISCOVERED"
        result["discovered_inventory"] = inventory
    except (LabError, OSError, ValueError) as exc:
        result["errors"].append(f"network inventory: {exc}")
        result["inventory"] = "FAILED"

    try:
        capabilities = network_capabilities()
        result["capabilities"] = "DISCOVERED"
        result["discovered_capabilities"] = capabilities
    except (LabError, OSError, ValueError) as exc:
        result["errors"].append(f"network capabilities: {exc}")
        result["capabilities"] = "FAILED"

    try:
        validate_machine_configuration(ROOT)
        result["machine_configuration"] = "VALID"
    except (LabError, OSError, ValueError) as exc:
        result["errors"].append(f"machine configuration: {exc}")
        result["machine_configuration"] = "FAILED"

    try:
        setup = validate_network_setup(ROOT)
        result["network_setup"] = "VALID"
        result["network_setup_details"] = setup
    except (LabError, OSError, ValueError) as exc:
        result["errors"].append(f"network setup: {exc}")
        result["network_setup"] = "FAILED"

    result["status"] = (
        "PASS" if not result["errors"] else "FAIL"
    )
    return result


def _read_runtime_acceptance(
    project: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """
    Ask the runtime to evaluate its pinned policy and acceptance evidence.

    Missing or stale acceptance evidence is not a pass. No evidence is
    generated here.
    """
    try:
        readiness = runtime_network_readiness(ROOT, policy)
    except (LabError, OSError, ValueError, KeyError, TypeError) as exc:
        return {
            "status": "FAIL",
            "ready": False,
            "project": project,
            "effective_behavior": "not-verified",
            "runtime_acceptance": "not-verified",
            "reason": str(exc),
        }

    if not isinstance(readiness, dict):
        return {
            "status": "FAIL",
            "ready": False,
            "project": project,
            "effective_behavior": "not-verified",
            "runtime_acceptance": "not-verified",
            "reason": "runtime readiness returned an invalid result",
        }

    ready = readiness.get("ready") is True
    effective = readiness.get("effective_behavior", "not-verified")
    acceptance = readiness.get("runtime_acceptance", "not-verified")

    return {
        "status": "PASS" if ready else "NOT_ACCEPTED",
        "ready": ready,
        "project": project,
        "controls_applied": readiness.get("controls_applied", "not-verified"),
        "effective_behavior": effective,
        "runtime_acceptance": acceptance,
        "reason": readiness.get(
            "reason",
            "runtime acceptance evidence is incomplete or unsuccessful",
        ),
    }


def _policy_status_report(
    policy: dict[str, Any],
    *,
    project: str | None = None,
    enforcement: str = "NOT_APPLIED",
    structural_verification: str = "NOT_TESTED",
    acceptance: dict[str, Any] | None = None,
    support: dict[str, Any] | None = None,
    host: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one consistent status envelope for all network operations."""
    support = support or _support_status(policy)
    definition = _policy_definition_status(policy)

    if acceptance is None:
        acceptance = {
            "status": "NOT_TESTED",
            "ready": False,
            "effective_behavior": "not-verified",
            "runtime_acceptance": "not-run",
            "reason": "no verified runtime acceptance evidence supplied",
        }

    if enforcement == "FAILED" or structural_verification == "FAILED":
        overall = "FAIL"
    elif not support.get("supported", False):
        overall = "UNSUPPORTED"
    elif acceptance.get("ready") is True and structural_verification == "PASS":
        overall = "PASS"
    elif enforcement == "APPLIED" and structural_verification == "PASS":
        overall = "PENDING_ACCEPTANCE"
    else:
        overall = "NOT_READY"

    return {
        "schema": POLICY_STATUS_SCHEMA,
        "overall_status": overall,
        "project": project,
        "profile": policy.get("profile"),
        "policy_identity": policy.get("provenance"),
        "policy_definition": definition,
        "enforcement": {
            "status": enforcement,
            "structural_verification": structural_verification,
            "support": support,
        },
        "acceptance_evidence": acceptance,
        "host_prerequisites": host or {
            "status": "NOT_TESTED",
            "reason": "host prerequisites were not checked by this operation",
        },
        "ready_for_workloads": (
            overall == "PASS"
            and support.get("supported", False)
            and acceptance.get("ready") is True
        ),
    }


def _run_boundary(
    action: str,
    project: str,
    policy_path: Path,
) -> subprocess.CompletedProcess[str]:
    """Run a boundary operation and preserve its diagnostic output."""
    if action not in {"apply", "verify", "remove"}:
        raise LabError(f"unsupported boundary action: {action}")

    if not NETWORK_BOUNDARY_SCRIPT.is_file():
        raise LabError(f"network boundary script is missing: {NETWORK_BOUNDARY_SCRIPT}")

    command = [
        "bash",
        str(NETWORK_BOUNDARY_SCRIPT),
        action,
        project,
        str(policy_path),
    ]
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _require_authorization(reason: str, operation: str) -> None:
    if not isinstance(reason, str) or not reason.strip():
        raise LabError(f"{operation} requires a non-empty authorization reason")


def _validate_selected_policy(
    profile: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Resolve policy and validate both support and host prerequisites."""
    policy = resolve_network_policy(ROOT, profile)
    support = _support_status(policy)

    if not support["supported"]:
        raise LabError(
            "network policy is unsupported; no enforcement or workload activation "
            f"is permitted: {support['reason']}"
        )

    host = _host_prerequisite_status(profile)
    if host["status"] != "PASS":
        raise LabError(
            "network policy prerequisites failed; profile cannot be activated: "
            + "; ".join(host["errors"])
        )

    return policy, support, host


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Security research lab control and construction"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    status = commands.add_parser("status")
    status.add_argument("--json", action="store_true")

    capabilities = commands.add_parser("capabilities")
    capabilities.add_argument("--json", action="store_true")

    materials = commands.add_parser(
        "materials",
        help="list explicitly approved research materials",
    )
    materials.add_argument("--json", action="store_true")

    networks = commands.add_parser(
        "networks",
        help="inspect and manage network policy, enforcement, and acceptance",
    )
    network_commands = networks.add_subparsers(
        dest="network_command",
        required=True,
    )

    network_commands.add_parser("profiles")

    select = network_commands.add_parser("select")
    select.add_argument("profile")

    show = network_commands.add_parser("show")
    show.add_argument("boundary", nargs="?")

    network_commands.add_parser("boundaries")
    network_commands.add_parser("validate")
    network_commands.add_parser("discover")

    configure = network_commands.add_parser("configure")
    configure.add_argument("--overwrite", action="store_true")

    network_commands.add_parser("validate-config")
    network_commands.add_parser(
        "preflight",
        help="read-only check of network prerequisites and host capabilities",
    )

    network_plan = network_commands.add_parser("plan")
    network_plan.add_argument("--profile")
    network_plan.add_argument("--output", type=Path, required=True)

    network_apply = network_commands.add_parser("apply")
    network_apply.add_argument("project")
    network_apply.add_argument("--profile")
    network_apply.add_argument("--authorize", required=True)

    network_verify = network_commands.add_parser("verify")
    network_verify.add_argument("project")
    network_verify.add_argument("--profile")

    network_remove = network_commands.add_parser("remove")
    network_remove.add_argument("project")
    network_remove.add_argument("--authorize", required=True)

    network_test = network_commands.add_parser("test")
    network_test.add_argument("project")
    network_test.add_argument("--profile")
    network_test.add_argument("--authorize", required=True)

    network_commands.add_parser("capabilities")

    drift = network_commands.add_parser("drift")
    drift.add_argument("project")

    maintenance = network_commands.add_parser("maintenance")
    maintenance_commands = maintenance.add_subparsers(
        dest="maintenance_command",
        required=True,
    )
    maintenance_commands.add_parser("status")
    maintenance_commands.add_parser("enter")
    maintenance_commands.add_parser("leave")

    runtime = commands.add_parser(
        "runtime",
        help="manage the persistent Lab Runtime",
    )
    runtime_commands = runtime.add_subparsers(
        dest="runtime_command",
        required=True,
    )

    for name in (
        "status",
        "configure",
        "start",
        "verify",
        "stop",
        "restart",
        "recover",
        "inspect",
        "doctor",
    ):
        runtime_commands.add_parser(name)

    admit = runtime_commands.add_parser("admit-experiment")
    admit.add_argument("experiment_id")
    admit.add_argument("--profile")
    admit.add_argument("--memory-mib", type=int, default=0)
    admit.add_argument("--cpu-millicores", type=int, default=0)
    admit.add_argument("--pids", type=int, default=0)

    release = runtime_commands.add_parser("release-experiment")
    release.add_argument("experiment_id")

    maintain = runtime_commands.add_parser("request-maintenance")
    maintain.add_argument("operation_id")
    maintain.add_argument("experiment_id")
    maintain.add_argument("--destination")

    validate = commands.add_parser("validate-investigation")
    validate.add_argument("specification", type=Path)

    plan = commands.add_parser("plan")
    plan.add_argument("specification", type=Path)
    plan.add_argument("--investigation-id", required=True)
    plan.add_argument("--output", type=Path, required=True)

    construct = commands.add_parser("construct-investigation")
    construct.add_argument("specification", type=Path)
    construct.add_argument("--investigation-id", required=True)
    construct.add_argument("--authorize", required=True)

    dispose = commands.add_parser("dispose-investigation")
    dispose.add_argument("specification", type=Path)
    dispose.add_argument("--investigation-id", required=True)

    archive = commands.add_parser("archive")
    archive.add_argument("evidence_directory", type=Path)
    archive.add_argument("--destination", type=Path)

    experiment = commands.add_parser(
        "experiment",
        help="manage a researcher-owned disposable workspace",
    )
    experiment_commands = experiment.add_subparsers(
        dest="experiment_command",
        required=True,
    )

    init = experiment_commands.add_parser("init")
    init.add_argument("experiment_id")

    enter = experiment_commands.add_parser("enter")
    enter.add_argument("experiment_id")

    inspect = experiment_commands.add_parser("inspect")
    inspect.add_argument("experiment_id")

    stop = experiment_commands.add_parser("stop")
    stop.add_argument("experiment_id")

    reset = experiment_commands.add_parser("reset")
    reset.add_argument("experiment_id")

    destroy = experiment_commands.add_parser("destroy")
    destroy.add_argument("experiment_id")

    collect = experiment_commands.add_parser("collect")
    collect.add_argument("experiment_id")
    collect.add_argument("paths", nargs="+", type=Path)

    execute = experiment_commands.add_parser("exec")
    execute.add_argument("experiment_id")
    execute.add_argument("--image", required=True)
    execute.add_argument("command", nargs="+")

    return parser


def _network_command(args: argparse.Namespace) -> int:
    command = args.network_command

    if command == "profiles":
        profiles = list_network_profiles(ROOT)
        rows: list[dict[str, Any]] = []

        for profile in profiles:
            try:
                policy = resolve_network_policy(ROOT, profile)
                support = _support_status(policy)
                definition = _policy_definition_status(policy)
                rows.append({
                    "profile": profile,
                    "policy_identity": policy.get("provenance"),
                    "policy_definition": definition["status"],
                    "enforcement_support": support["status"],
                    "capability_error": support["reason"],
                    "activation_status": (
                        "ELIGIBLE_FOR_PREFLIGHT"
                        if support["supported"]
                        else "BLOCKED_UNSUPPORTED"
                    ),
                    "acceptance_evidence": "NOT_EVALUATED",
                })
            except (LabError, OSError, ValueError) as exc:
                rows.append({
                    "profile": profile,
                    "policy_definition": "INVALID",
                    "enforcement_support": "NOT_TESTED",
                    "activation_status": "BLOCKED",
                    "reason": str(exc),
                    "acceptance_evidence": "NOT_EVALUATED",
                })

        _emit({
            "schema": POLICY_STATUS_SCHEMA,
            "profiles": rows,
            "note": (
                "Listing a profile does not apply enforcement or prove effective "
                "network behavior."
            ),
        })
        return 0 if all(
            row.get("policy_definition") == "DEFINED"
            and row.get("enforcement_support") == "SUPPORTED"
            for row in rows
        ) else 1

    if command == "select":
        # Resolve and validate the requested policy before changing active-profile.
        policy, support, host = _validate_selected_policy(args.profile)
        path = select_network_profile(ROOT, args.profile)

        _emit({
            "schema": POLICY_STATUS_SCHEMA,
            "overall_status": "SELECTED_NOT_ENFORCED",
            "active_profile": args.profile,
            "active_profile_file": str(path),
            "policy_identity": policy.get("provenance"),
            "policy_definition": _policy_definition_status(policy),
            "enforcement": {
                "status": "NOT_APPLIED",
                "support": support,
            },
            "acceptance_evidence": {
                "status": "NOT_TESTED",
                "effective_behavior": "not-verified",
                "runtime_acceptance": "not-run",
            },
            "host_prerequisites": host,
            "ready_for_workloads": False,
        })
        return 0

    if command == "boundaries":
        print("\n".join(BOUNDARIES))
        return 0

    if command == "show":
        policy = resolve_network_policy(ROOT)
        if args.boundary is not None:
            if args.boundary not in policy.get("boundaries", {}):
                raise LabError(f"unknown network boundary: {args.boundary}")
            _emit({
                "profile": policy.get("profile"),
                "policy_identity": policy.get("provenance"),
                "boundary": args.boundary,
                "policy_definition": policy["boundaries"][args.boundary],
                "enforcement_status": "NOT_EVALUATED",
                "acceptance_status": "NOT_EVALUATED",
            })
        else:
            _emit(_policy_status_report(policy))
        return 0

    if command == "validate":
        result = validate_network_configuration(ROOT)
        _emit({
            "schema": POLICY_STATUS_SCHEMA,
            "overall_status": "VALID" if result else "INVALID",
            "policy_definition": {
                "status": "VALIDATED",
                "profiles": result.get("profiles"),
                "boundaries": result.get("boundaries"),
            },
            "enforcement": "NOT_TESTED",
            "acceptance_evidence": "NOT_TESTED",
            "ready_for_workloads": False,
        })
        return 0

    if command == "capabilities":
        _emit(network_capabilities())
        return 0

    if command == "discover":
        _emit({
            "inventory_status": "DISCOVERED",
            "inventory": discover_network_inventory(),
            "enforcement": "NOT_TESTED",
            "acceptance_evidence": "NOT_TESTED",
        })
        return 0

    if command == "configure":
        path = configure_machine(ROOT, args.overwrite)
        _emit({
            "status": "TEMPLATE_WRITTEN",
            "path": str(path),
            "enforcement": "NOT_APPLIED",
            "acceptance_evidence": "NOT_TESTED",
            "note": "Writing a configuration template does not activate enforcement.",
        })
        return 0

    if command == "validate-config":
        config = validate_machine_configuration(ROOT)
        _emit({
            "status": "VALID",
            "approved_docker_context": config["operator_confirmed"][
                "approved_docker_context"
            ],
            "enforcement": "NOT_TESTED",
            "acceptance_evidence": "NOT_TESTED",
        })
        return 0

    if command == "preflight":
        policy = resolve_network_policy(ROOT)
        support = _support_status(policy)
        host = _host_prerequisite_status(policy.get("profile"))

        report = _policy_status_report(
            policy,
            support=support,
            host=host,
        )
        report["preflight"] = {
            "status": (
                "PASS"
                if support["supported"] and host["status"] == "PASS"
                else "FAIL"
            ),
            "policy_supported": support["supported"],
            "host_prerequisites": host["status"],
        }
        _emit(report)

        return 0 if (
            support["supported"]
            and host["status"] == "PASS"
        ) else 1

    if command == "plan":
        policy = resolve_network_policy(ROOT, args.profile)
        support = _support_status(policy)
        host = _host_prerequisite_status(policy.get("profile"))
        plan = build_enforcement_plan(ROOT, args.profile)

        destination = args.output.resolve()
        if ROOT.resolve() not in destination.parents:
            raise LabError("enforcement plan output must be inside the repository")

        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(plan, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        _emit({
            "schema": POLICY_STATUS_SCHEMA,
            "plan": str(destination),
            "profile": policy.get("profile"),
            "policy_identity": policy.get("provenance"),
            "policy_definition": _policy_definition_status(policy),
            "enforcement_plan": {
                "supported": plan.get("supported", False),
                "capability_error": plan.get("capability_error"),
                "details": plan,
            },
            "host_prerequisites": host,
            "acceptance_evidence": "NOT_TESTED",
            "ready_for_workloads": False,
        })

        return 0 if (
            plan.get("supported") is True
            and support["supported"]
            and host["status"] == "PASS"
        ) else 1

    if command in {"apply", "verify", "remove", "test"}:
        if command in {"apply", "remove", "test"}:
            _require_authorization(args.authorize, command)

        profile = getattr(args, "profile", None)
        policy = resolve_project_network_policy(ROOT, args.project, profile)
        support = _support_status(policy)
        policy_path = _project_policy_path(args.project)

        if command in {"apply", "test"}:
            if not support["supported"]:
                raise LabError(
                    "policy is unsupported; refusing the operation: "
                    f"{support['reason']}"
                )

        if command in {"apply", "verify", "test"}:
            host = _host_prerequisite_status(policy.get("profile"))
            if host["status"] != "PASS":
                raise LabError(
                    "host prerequisites failed; operation blocked: "
                    + "; ".join(host["errors"])
                )
        else:
            host = {
                "status": "NOT_REQUIRED_FOR_REMOVAL",
                "note": "Removal is cleanup, not policy activation.",
            }

        if command == "apply":
            # Apply requires an already existing network created by the
            # approved construction lifecycle. It does not create substitutes.
            try:
                owned_network = inspect_owned_network(args.project)
            except LabError as exc:
                investigation_id = args.project.removeprefix("sec-lab-i-")
                raise LabError(
                    f"cannot apply network boundary: {exc}. "
                    "The apply command does not create Docker networks. "
                    "Complete network preflight and inspect the investigation "
                    "plan, then use construct-investigation to create the owned "
                    "network and start workloads only after policy verification "
                    f"and runtime acceptance. Investigation identifier: {investigation_id}."
                ) from exc

            _write_policy_atomically(policy_path, policy)
            result = _run_boundary("apply", args.project, policy_path)

            if result.returncode != 0:
                report = _policy_status_report(
                    policy,
                    project=args.project,
                    enforcement="FAILED",
                    support=support,
                    host=host,
                )
                report["operation"] = "apply"
                report["authorization"] = args.authorize
                report["network"] = owned_network
                report["error"] = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "network boundary apply failed"
                )
                _emit(report)
                return 1

            report = _policy_status_report(
                policy,
                project=args.project,
                enforcement="APPLIED",
                structural_verification="NOT_TESTED",
                support=support,
                host=host,
            )
            report["operation"] = "apply"
            report["authorization"] = args.authorize
            report["network"] = owned_network
            report["command_output"] = result.stdout.strip()
            _emit(report)

            # Apply is not proof of effective behavior or acceptance.
            return 0

        if command == "verify":
            if not policy_path.is_file():
                raise LabError(
                    f"pinned policy is missing: {policy_path}; apply or construct "
                    "the intended project policy before verification"
                )

            # Verify against the pinned policy, not an unpersisted interpretation.
            pinned_text = policy_path.read_text(encoding="utf-8")
            if pinned_text != policy_json(policy):
                raise LabError(
                    "pinned policy differs from the requested policy; refusing "
                    "to verify against a mismatched policy identity"
                )

            result = _run_boundary("verify", args.project, policy_path)
            if result.returncode != 0:
                report = _policy_status_report(
                    policy,
                    project=args.project,
                    enforcement="APPLIED",
                    structural_verification="FAILED",
                    support=support,
                    host=host,
                )
                report["operation"] = "verify"
                report["error"] = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "network boundary verification failed"
                )
                _emit(report)
                return 1

            acceptance = _read_runtime_acceptance(args.project, policy)
            report = _policy_status_report(
                policy,
                project=args.project,
                enforcement="APPLIED",
                structural_verification="PASS",
                acceptance=acceptance,
                support=support,
                host=host,
            )
            report["operation"] = "verify"
            report["structural_verification_output"] = result.stdout.strip()
            _emit(report)

            # Structural verification alone must not report readiness.
            return 0 if report["ready_for_workloads"] else 1

        if command == "test":
            if not policy_path.is_file():
                raise LabError(
                    f"pinned policy is missing: {policy_path}; cannot evaluate "
                    "acceptance against an absent policy"
                )

            pinned_text = policy_path.read_text(encoding="utf-8")
            if pinned_text != policy_json(policy):
                raise LabError(
                    "pinned policy differs from the requested policy; acceptance "
                    "must use the exact project policy identity"
                )

            # The current CLI does not implement an independent live packet
            # test runner. Re-run structural verification and inspect the
            # existing runtime acceptance record, but never fabricate test PASS.
            result = _run_boundary("verify", args.project, policy_path)
            if result.returncode != 0:
                report = _policy_status_report(
                    policy,
                    project=args.project,
                    enforcement="APPLIED",
                    structural_verification="FAILED",
                    support=support,
                    host=host,
                )
                report["operation"] = "test"
                report["authorization"] = args.authorize
                report["live_connectivity_tests"] = "NOT_RUN"
                report["error"] = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "network boundary verification failed"
                )
                _emit(report)
                return 1

            acceptance = _read_runtime_acceptance(args.project, policy)
            report = _policy_status_report(
                policy,
                project=args.project,
                enforcement="APPLIED",
                structural_verification="PASS",
                acceptance=acceptance,
                support=support,
                host=host,
            )
            report["operation"] = "test"
            report["authorization"] = args.authorize
            report["live_connectivity_tests"] = (
                "PASS"
                if acceptance.get("ready") is True
                else "NOT_PROVEN"
            )
            report["note"] = (
                "This command does not generate acceptance evidence. "
                "A ready status requires the runtime's existing acceptance "
                "record to match this project's pinned policy."
            )
            _emit(report)
            return 0 if report["ready_for_workloads"] else 1

        if command == "remove":
            # Do not silently remove or alter another investigation's controls.
            owned_network = inspect_owned_network(args.project)

            if not policy_path.is_file():
                raise LabError(
                    f"cannot safely remove boundary without its pinned policy: "
                    f"{policy_path}"
                )

            result = _run_boundary("remove", args.project, policy_path)
            if result.returncode != 0:
                report = _policy_status_report(
                    policy,
                    project=args.project,
                    enforcement="FAILED",
                    support=support,
                    host=host,
                )
                report["operation"] = "remove"
                report["authorization"] = args.authorize
                report["network"] = owned_network
                report["error"] = (
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "network boundary removal failed"
                )
                _emit(report)
                return 1

            # Keep the policy record for audit/recovery. Removal must not erase
            # the only record of what was intended or applied.
            _emit({
                "schema": POLICY_STATUS_SCHEMA,
                "overall_status": "REMOVED",
                "operation": "remove",
                "project": args.project,
                "authorization": args.authorize,
                "policy_identity": policy.get("provenance"),
                "policy_definition": "RETAINED_FOR_AUDIT",
                "enforcement": "REMOVED",
                "acceptance_evidence": "HISTORICAL_NOT_CURRENT",
                "network": owned_network,
                "command_output": result.stdout.strip(),
                "ready_for_workloads": False,
            })
            return 0

    if command == "drift":
        policy = resolve_project_network_policy(ROOT, args.project)
        support = _support_status(policy)
        drift = network_policy_drift(ROOT, args.project)

        drift_detected = bool(
            drift.get("drift")
            or drift.get("drift_detected")
            or drift.get("status") in {"DRIFT", "DRIFTED", "FAIL"}
        )

        acceptance = _read_runtime_acceptance(args.project, policy)
        report = _policy_status_report(
            policy,
            project=args.project,
            enforcement="DRIFT" if drift_detected else "NOT_PROVEN",
            structural_verification="FAILED" if drift_detected else "NOT_TESTED",
            acceptance=acceptance,
            support=support,
        )
        report["operation"] = "drift"
        report["drift_report"] = drift
        report["drift_status"] = (
            "DRIFT_DETECTED" if drift_detected else "INSPECTION_RESULT_REQUIRES_REVIEW"
        )
        report["ready_for_workloads"] = False if drift_detected else report[
            "ready_for_workloads"
        ]
        _emit(report)
        return 1 if drift_detected or not support["supported"] else 0

    if command == "maintenance":
        if args.maintenance_command == "status":
            _emit({
                "status": "CLOSED",
                "supported": False,
                "policy_definition": "UNCHANGED",
                "enforcement": "NO_MAINTENANCE_POLICY_ACTIVE",
                "acceptance_evidence": "NOT_TESTED",
                "reason": (
                    "temporary maintenance enforcement and verified restoration "
                    "are not implemented"
                ),
            })
            return 0

        raise LabError(
            "maintenance lifecycle is unavailable: temporary policy application "
            "and verified restoration are not implemented"
        )

    raise LabError(f"unhandled network command: {command}")


def _runtime_command(args: argparse.Namespace) -> int:
    actions: dict[str, Callable[[Path], Any]] = {
        "status": runtime_status,
        "configure": runtime_configure,
        "start": runtime_start,
        "verify": runtime_verify,
        "stop": runtime_stop,
        "inspect": runtime_inspect,
        "restart": runtime_restart,
        "recover": runtime_recover,
        "doctor": runtime_doctor,
    }

    if args.runtime_command in actions:
        result = actions[args.runtime_command](ROOT)
        _emit(result)
        return 0

    if args.runtime_command == "admit-experiment":
        result = admit_experiment(
            args.experiment_id,
            args.profile,
            ROOT,
            args.memory_mib,
            args.cpu_millicores,
            args.pids,
        )
        _emit(result)
        return 0

    if args.runtime_command == "release-experiment":
        release_experiment(args.experiment_id, ROOT)
        _emit({
            "status": "RELEASED",
            "experiment_id": args.experiment_id,
            "policy_definition": "UNCHANGED",
            "enforcement": "RUNTIME_ADMISSION_RELEASED",
            "acceptance_evidence": "NOT_REEVALUATED",
        })
        return 0

    if args.runtime_command == "request-maintenance":
        _emit(request_maintenance(
            args.operation_id,
            args.experiment_id,
            ROOT,
            args.destination,
        ))
        return 0

    raise LabError(f"unhandled runtime command: {args.runtime_command}")


def _experiment_command(args: argparse.Namespace) -> int:
    if args.experiment_command == "init":
        directory = init_experiment(args.experiment_id, ROOT)
        print(f"PASS: experiment workspace initialized at {directory}")
    elif args.experiment_command == "enter":
        print(enter_experiment(args.experiment_id, ROOT))
    elif args.experiment_command == "inspect":
        _emit(inspect_experiment(args.experiment_id, ROOT))
    elif args.experiment_command == "stop":
        stop_experiment(args.experiment_id, ROOT)
        print(f"PASS: experiment {args.experiment_id} stopped")
    elif args.experiment_command == "reset":
        reset_experiment(args.experiment_id, ROOT)
        print(
            f"PASS: experiment {args.experiment_id} reset; "
            "preserved evidence retained"
        )
    elif args.experiment_command == "destroy":
        destroy_experiment(args.experiment_id, ROOT)
        print(
            f"PASS: experiment {args.experiment_id} destroyed; "
            "preserved evidence retained"
        )
    elif args.experiment_command == "collect":
        manifest = collect_evidence(args.experiment_id, args.paths, ROOT)
        print(f"PASS: evidence collected at {manifest}")
    elif args.experiment_command == "exec":
        record = execute_tool(
            args.experiment_id,
            args.image,
            args.command,
            ROOT,
        )
        print(f"PASS: bounded tool command recorded at {record}")
    else:
        raise LabError(
            f"unhandled experiment command: {args.experiment_command}"
        )

    return 0


def main(argv: list[str] | None = None) -> int:
    if os.name != "posix":
        print(
            "ERROR: run this controller from the intended Linux/WSL environment",
            file=sys.stderr,
        )
        return 2

    args = _parser().parse_args(argv)

    try:
        if args.command == "status":
            active_profile_path = ROOT / "config" / "networks" / "active-profile"
            active_profile = (
                active_profile_path.read_text(encoding="utf-8").strip()
                if active_profile_path.is_file()
                else None
            )

            try:
                policy = resolve_network_policy(ROOT)
                support = _support_status(policy)
                host = _host_prerequisite_status(policy.get("profile"))
                definition = _policy_definition_status(policy)
            except (LabError, OSError, ValueError) as exc:
                policy = None
                support = {
                    "status": "INVALID",
                    "supported": False,
                    "reason": str(exc),
                }
                host = {"status": "NOT_TESTED"}
                definition = {"status": "INVALID", "reason": str(exc)}

            status = {
                "schema": POLICY_STATUS_SCHEMA,
                "lab": "security-lab",
                "root": str(ROOT),
                "configuration": "INVESTIGATION_INDEPENDENT",
                "runtime_backend": "docker.compose",
                "active_profile": active_profile,
                "policy_definition": definition,
                "enforcement_support": support,
                "host_prerequisites": host,
                "enforcement": "NOT_INFERRED_FROM_STATIC_CONFIGURATION",
                "acceptance_evidence": "NOT_TESTED_BY_STATUS_COMMAND",
                "ready_for_workloads": False,
            }

            if args.json:
                _emit(status)
            else:
                print(
                    f"Policy definition: {definition['status']}\n"
                    f"Enforcement support: {support['status']}\n"
                    f"Host prerequisites: {host.get('status', 'NOT_TESTED')}\n"
                    "Effective behavior: NOT_VERIFIED\n"
                    "Runtime acceptance: NOT_TESTED\n"
                    "Workload readiness: NOT_READY"
                )

            return 0 if (
                support.get("supported") is True
                and host.get("status") == "PASS"
            ) else 1

        if args.command == "capabilities":
            value = load_catalog(CAPABILITIES_FILE, "capabilities")
            if args.json:
                _emit(value)
            else:
                print("\n".join(sorted(value)))
            return 0

        if args.command == "materials":
            value = load_materials(ROOT)
            if args.json:
                _emit(value)
            else:
                print("\n".join(sorted(value)))
                if not value:
                    print("No approved materials are registered.")
            return 0

        if args.command == "networks":
            return _network_command(args)

        if args.command == "runtime":
            return _runtime_command(args)

        if args.command == "validate-investigation":
            specification = validate_investigation(args.specification, ROOT)
            _emit({
                "status": "VALID",
                "backend": specification["apparatus"]["backend"],
                "policy_definition": "VALIDATED",
                "enforcement": "NOT_APPLIED",
                "acceptance_evidence": "NOT_TESTED",
                "ready_for_workloads": False,
            })
            return 0

        if args.command == "plan":
            output = write_plan(
                args.specification,
                args.investigation_id,
                args.output,
                ROOT,
            )
            plan = json.loads(output.read_text(encoding="utf-8"))

            report = {
                "plan": str(output),
                "policy_definition": (
                    "VALIDATED" if plan.get("network_policy") else "NOT_REPORTED"
                ),
                "network_policy_supported": plan.get(
                    "network_policy_supported",
                    False,
                ),
                "network_policy_capability_error": plan.get(
                    "network_policy_capability_error"
                ),
                "enforcement": "NOT_APPLIED",
                "acceptance_evidence": "NOT_TESTED",
                "ready_for_workloads": False,
            }
            _emit(report)

            if not plan.get("network_policy_supported", False):
                raise LabError(
                    "construction plan is unsupported; inspect "
                    f"{output}: {plan.get('network_policy_capability_error')}"
                )
            return 0

        if args.command == "construct-investigation":
            plan = construct_investigation(
                args.specification,
                args.investigation_id,
                args.authorize,
                ROOT,
            )
            _emit({
                "status": plan.get("status", "CONSTRUCTED"),
                "project": plan.get("project"),
                "policy_definition": "PINNED",
                "enforcement": plan.get("enforcement_status", "REQUIRES_RUNTIME_CHECK"),
                "acceptance_evidence": plan.get(
                    "acceptance_status",
                    "REQUIRES_RUNTIME_CHECK",
                ),
                "ready_for_workloads": plan.get(
                    "ready_for_workloads",
                    False,
                ),
                "construction_result": plan,
            })
            return 0

        if args.command == "dispose-investigation":
            dispose_investigation(
                args.specification,
                args.investigation_id,
                ROOT,
            )
            _emit({
                "status": "DISPOSED",
                "investigation_id": args.investigation_id,
                "policy_definition": "RETAINED_IF_REQUIRED_FOR_AUDIT",
                "enforcement": "DISPOSAL_REQUEST_COMPLETED",
                "acceptance_evidence": "HISTORICAL",
                "ready_for_workloads": False,
            })
            return 0

        if args.command == "archive":
            destination = archive_evidence(
                args.evidence_directory,
                args.destination,
                ROOT,
            )
            print(f"PASS: evidence hashed and verified at {destination}")
            return 0

        if args.command == "experiment":
            return _experiment_command(args)

        raise LabError(f"unhandled command: {args.command}")

    except (LabError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())