from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from .construction import (
    construct_investigation,
    dispose_investigation,
    validate_investigation,
    write_plan,
)
from .evidence import archive_evidence
from .foundation import CAPABILITIES_FILE, LabError, ROOT, load_catalog
from .networks import (
    BOUNDARIES,
    list_network_profiles,
    network_policy_drift,
    build_enforcement_plan,
    configure_machine,
    discover_network_inventory,
    inspect_owned_network,
    policy_json,
    resolve_network_policy,
    select_network_profile,
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Security research lab control and construction")
    commands = parser.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status")
    status.add_argument("--json", action="store_true")
    capabilities = commands.add_parser("capabilities")
    capabilities.add_argument("--json", action="store_true")
    networks = commands.add_parser("networks", help="inspect configurable network policies")
    network_commands = networks.add_subparsers(dest="network_command", required=True)
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
    maintenance_commands = maintenance.add_subparsers(dest="maintenance_command", required=True)
    maintenance_commands.add_parser("status")
    maintenance_commands.add_parser("enter")
    maintenance_commands.add_parser("leave")
    runtime = commands.add_parser("runtime", help="manage the persistent Lab Runtime")
    runtime_commands = runtime.add_subparsers(dest="runtime_command", required=True)
    for name in ("status", "configure", "start", "verify", "stop", "restart", "recover", "inspect", "doctor"):
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
    experiment = commands.add_parser("experiment", help="manage a researcher-owned disposable workspace")
    experiment_commands = experiment.add_subparsers(dest="experiment_command", required=True)
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


def main(argv: list[str] | None = None) -> int:
    if os.name != "posix":
        print("ERROR: run this controller from the intended Linux/WSL environment", file=sys.stderr)
        return 2
    args = _parser().parse_args(argv)
    try:
        if args.command == "status":
            status = {
                "lab": "security-lab",
                "root": str(ROOT),
                "configuration": "investigation-independent",
                "runtime_backend": "docker.compose",
                "static_configuration": "PASS",
                "runtime_readiness": "NOT_TESTED",
                "network_profile": (ROOT / "config" / "networks" / "active-profile").read_text(encoding="utf-8").strip(),
            }
            print(json.dumps(status, indent=2) if args.json else "NOT_TESTED: static lab configuration is available; runtime readiness requires preflight and acceptance checks")
        elif args.command == "capabilities":
            value = load_catalog(CAPABILITIES_FILE, "capabilities")
            print(json.dumps(value, indent=2, sort_keys=True) if args.json else "\n".join(sorted(value)))
        elif args.command == "networks":
            if args.network_command == "profiles":
                print("\n".join(list_network_profiles(ROOT)))
            elif args.network_command == "select":
                path = select_network_profile(ROOT, args.profile)
                print(f"PASS: active network profile set to {args.profile} ({path})")
            elif args.network_command == "boundaries":
                print("\n".join(BOUNDARIES))
            elif args.network_command in {"show", "validate"}:
                if args.network_command == "validate":
                    result = validate_network_configuration(ROOT)
                    print(json.dumps({"profiles": result["profiles"], "boundaries": result["boundaries"]}, indent=2))
                else:
                    policy = resolve_network_policy(ROOT)
                    if args.boundary is not None:
                        if args.boundary not in policy["boundaries"]:
                            raise LabError(f"unknown network boundary: {args.boundary}")
                        print(json.dumps(policy["boundaries"][args.boundary], indent=2, sort_keys=True))
                    else:
                        print(policy_json(policy), end="")
            elif args.network_command == "capabilities":
                print(json.dumps({
                    "linux-wsl": {
                        "ipv4": ["deny"],
                        "ipv6": ["deny"],
                        "windows_host": "unsupported",
                        "external_networks": "deny-only",
                    }
                }, indent=2, sort_keys=True))
            elif args.network_command == "discover":
                print(json.dumps(discover_network_inventory(), indent=2, sort_keys=True))
            elif args.network_command == "configure":
                path = configure_machine(ROOT, args.overwrite)
                print(f"PASS: machine configuration template written to {path}")
            elif args.network_command == "validate-config":
                config = validate_machine_configuration(ROOT)
                print(json.dumps({
                    "valid": True,
                    "approved_docker_context": config["operator_confirmed"]["approved_docker_context"],
                }, indent=2, sort_keys=True))
            elif args.network_command == "plan":
                plan = build_enforcement_plan(ROOT, args.profile)
                destination = args.output.resolve()
                if ROOT.resolve() not in destination.parents:
                    raise LabError("enforcement plan output must be inside the repository")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                print(json.dumps({
                    "plan": str(destination),
                    "supported": plan["supported"],
                    "capability_error": plan["capability_error"],
                }, indent=2, sort_keys=True))
            elif args.network_command in {"apply", "verify", "remove", "test"}:
                if not args.authorize.strip():
                    raise LabError(
                        f"network {args.network_command} requires a non-empty --authorize reason"
                    )
                profile = getattr(args, "profile", None)
                policy = resolve_network_policy(ROOT, profile)
                validate_runtime_support(policy)
                validate_machine_configuration(ROOT)
                policy_path = ROOT / "state" / "network-boundary" / f"{args.project}-network-policy.json"
                policy_path.parent.mkdir(parents=True, exist_ok=True)
                policy_path.write_text(policy_json(policy), encoding="utf-8")
                if args.network_command == "test":
                    verify_command = [
                        "bash", str(ROOT / "scripts" / "network-boundary.sh"),
                        "verify", args.project, str(policy_path),
                    ]
                    verified = subprocess.run(
                        verify_command, cwd=ROOT, text=True,
                        capture_output=True, check=False,
                    )
                    if verified.returncode != 0:
                        raise LabError(
                            verified.stderr.strip()
                            or verified.stdout.strip()
                            or "boundary verification failed"
                        )
                    result = {
                        "authorization": args.authorize,
                        "profile": policy["profile"],
                        "policy_identity": policy["provenance"],
                        "network": inspect_owned_network(args.project),
                        "boundary_verification": "passed",
                        "connectivity_tests": "not-run",
                        "reason": (
                            "The repository does not create disposable test workloads "
                            "or probe external targets automatically. Run controlled "
                            "workload-specific tests after reviewing this inventory."
                        ),
                    }
                    print(json.dumps(result, indent=2, sort_keys=True))
                    return 0
                action = "remove" if args.network_command == "remove" else args.network_command
                command = ["bash", str(ROOT / "scripts" / "network-boundary.sh"), action, args.project, str(policy_path)]
                result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
                if result.returncode != 0:
                    raise LabError(result.stderr.strip() or result.stdout.strip() or "network boundary operation failed")
                print(result.stdout, end="")
            elif args.network_command == "drift":
                print(json.dumps(network_policy_drift(ROOT, args.project), indent=2, sort_keys=True))
            elif args.network_command == "maintenance":
                if args.maintenance_command == "status":
                    print(json.dumps({
                        "status": "closed",
                        "supported": False,
                        "reason": "temporary maintenance enforcement and restoration are not implemented",
                    }, indent=2, sort_keys=True))
                else:
                    raise LabError(
                        "maintenance lifecycle is unavailable: temporary policy application "
                        "and verified restoration are not implemented"
                    )
        elif args.command == "runtime":
            actions = {
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
                print(json.dumps(actions[args.runtime_command](ROOT), indent=2, sort_keys=True))
            elif args.runtime_command == "admit-experiment":
                print(json.dumps(admit_experiment(
                    args.experiment_id, args.profile, ROOT, args.memory_mib,
                    args.cpu_millicores, args.pids,
                ), indent=2, sort_keys=True))
            elif args.runtime_command == "release-experiment":
                release_experiment(args.experiment_id, ROOT)
                print(f"PASS: experiment released: {args.experiment_id}")
            elif args.runtime_command == "request-maintenance":
                print(json.dumps(request_maintenance(
                    args.operation_id, args.experiment_id, ROOT, args.destination
                ), indent=2, sort_keys=True))
        elif args.command == "validate-investigation":
            specification = validate_investigation(args.specification, ROOT)
            print(f"PASS: investigation specification is valid ({specification['apparatus']['backend']})")
        elif args.command == "plan":
            output = write_plan(args.specification, args.investigation_id, args.output, ROOT)
            print(f"PASS: construction plan written to {output}")
        elif args.command == "construct-investigation":
            plan = construct_investigation(
                args.specification, args.investigation_id, args.authorize, ROOT
            )
            print(f"PASS: investigation constructed as {plan['project']}")
        elif args.command == "dispose-investigation":
            dispose_investigation(args.specification, args.investigation_id, ROOT)
            print(f"PASS: investigation {args.investigation_id} disposed")
        elif args.command == "archive":
            destination = archive_evidence(args.evidence_directory, args.destination, ROOT)
            print(f"PASS: evidence hashed and verified at {destination}")
        elif args.command == "experiment":
            if args.experiment_command == "init":
                directory = init_experiment(args.experiment_id, ROOT)
                print(f"PASS: experiment workspace initialized at {directory}")
            elif args.experiment_command == "enter":
                print(enter_experiment(args.experiment_id, ROOT))
            elif args.experiment_command == "inspect":
                print(json.dumps(inspect_experiment(args.experiment_id, ROOT), indent=2, sort_keys=True))
            elif args.experiment_command == "stop":
                stop_experiment(args.experiment_id, ROOT)
                print(f"PASS: experiment {args.experiment_id} stopped")
            elif args.experiment_command == "reset":
                reset_experiment(args.experiment_id, ROOT)
                print(f"PASS: experiment {args.experiment_id} reset; preserved evidence retained")
            elif args.experiment_command == "destroy":
                destroy_experiment(args.experiment_id, ROOT)
                print(f"PASS: experiment {args.experiment_id} destroyed; preserved evidence retained")
            elif args.experiment_command == "collect":
                manifest = collect_evidence(args.experiment_id, args.paths, ROOT)
                print(f"PASS: evidence collected at {manifest}")
            elif args.experiment_command == "exec":
                record = execute_tool(args.experiment_id, args.image, args.command, ROOT)
                print(f"PASS: bounded tool command recorded at {record}")
        return 0
    except (LabError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
