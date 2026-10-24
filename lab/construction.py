"""Generic researcher-defined investigation construction.

This module deliberately knows nothing about experiment names, service roles,
expected outputs, or registered procedures. The specification supplies the
apparatus and declarative procedure; the lab only validates and constrains it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import yaml
from pathlib import Path
from typing import Any

from .foundation import (
    CAPABILITIES_FILE,
    LabError,
    ROOT,
    ensure_inside,
    load_catalog,
    load_yaml,
    require_integer,
    require_list,
    require_mapping,
    require_open_mapping,
    require_text,
    reject_sensitive_fields,
    sha256_bytes,
    utc_now,
)
from .validation import validate_compose_document
from .networks import policy_json, resolve_network_policy, validate_runtime_support

def validate_investigation(path: Path, root: Path = ROOT) -> dict[str, Any]:
    source = ensure_inside(root, path, "investigation specification")
    specification = load_yaml(source)
    require_mapping(
        specification,
        "investigation",
        {
            "schema_version",
            "investigation",
            "apparatus",
            "resources",
            "procedure",
            "observations",
            "evaluation",
            "evidence",
            "safety",
            "resource_budget",
        },
    )
    if specification["schema_version"] != 1:
        raise LabError("unsupported investigation schema_version")
    investigation = require_mapping(
        specification["investigation"], "investigation.investigation",
        {"question"}, {"hypothesis", "objectives", "title"},
    )
    require_text(investigation["question"], "investigation.question")
    apparatus = require_mapping(
        specification["apparatus"], "investigation.apparatus",
        {"backend", "compose_file"}, {"network", "components", "relationships", "network_policy"},
    )
    if apparatus["backend"] != "docker.compose":
        raise LabError(f"unsupported construction backend: {apparatus['backend']}")
    network_policy = apparatus.get("network_policy", {})
    if not isinstance(network_policy, dict):
        raise LabError("investigation.apparatus.network_policy must be a mapping")
    unknown_policy_keys = set(network_policy) - {"profile", "overrides"}
    if unknown_policy_keys:
        raise LabError(
            "investigation.apparatus.network_policy contains unsupported keys: "
            + ", ".join(sorted(unknown_policy_keys))
        )
    if "overrides" in network_policy and not isinstance(network_policy["overrides"], dict):
        raise LabError("investigation.apparatus.network_policy.overrides must be a mapping")
    network = apparatus.get("network", {})
    if not isinstance(network, dict):
        raise LabError("investigation.apparatus.network must be a mapping")
    require_mapping(network, "investigation.apparatus.network", set(), {"logical_name"})
    compose_file = require_text(apparatus["compose_file"], "investigation.apparatus.compose_file")
    logical_name = network.get("logical_name", "lab")
    require_text(logical_name, "investigation.apparatus.network.logical_name")
    compose_path = ensure_inside(root, root / compose_file, "Compose definition")
    if not compose_path.is_file():
        raise LabError(f"Compose definition is missing: {compose_path}")
    compose = load_yaml(compose_path)
    effective_policy = resolve_network_policy(
        root,
        network_policy.get("profile"),
        network_policy.get("overrides"),
    )
    validate_compose_document(
        compose,
        {
            "apparatus": {
                "network": {
                    "mode": "internal",
                    "logical_name": logical_name,
                },
                "services": {},
            },
            "network_policy": effective_policy,
        },
    )
    resources = require_list(specification["resources"], "investigation.resources")
    for index, resource in enumerate(resources):
        require_mapping(resource, f"investigation.resources[{index}]", {"id", "kind"}, {"source", "digest", "authorization"})
        require_text(resource["id"], f"investigation.resources[{index}].id")
        require_text(resource["kind"], f"investigation.resources[{index}].kind")
    procedure = require_list(specification["procedure"], "investigation.procedure")
    for index, step in enumerate(procedure):
        require_mapping(step, f"investigation.procedure[{index}]", {"id", "operation"}, {"service", "arguments"})
        require_text(step["id"], f"investigation.procedure[{index}].id")
        if step["operation"] not in {"construct", "run_service", "collect_logs", "stop", "destroy"}:
            raise LabError(f"unsupported procedure operation: {step['operation']}")
    for field in ("observations", "evaluation", "evidence", "safety"):
        require_open_mapping(specification[field], f"investigation.{field}")
    budget = require_mapping(
        specification["resource_budget"], "investigation.resource_budget",
        {"memory_mib", "cpu_millicores", "pids", "storage_mib"},
    )
    for key, value in budget.items():
        require_integer(value, f"resource_budget.{key}", 1)
    capacity = load_yaml(root / "config" / "lab-capacity.yaml")
    require_mapping(
        capacity,
        "lab capacity",
        {"max_active_instances", "memory_mib", "cpu_millicores", "pids", "storage_mib", "max_duration_seconds"},
    )
    for key, value in capacity.items():
        require_integer(value, f"lab capacity.{key}", 1)
    for key in ("memory_mib", "cpu_millicores", "pids", "storage_mib"):
        if budget[key] > capacity[key]:
            raise LabError(f"resource_budget.{key} exceeds lab capacity ({capacity[key]})")
    reject_sensitive_fields(specification)
    return specification


def resolve_resources(specification: dict[str, Any], root: Path = ROOT) -> list[dict[str, Any]]:
    capabilities = load_catalog(root / "lab" / "catalog" / "capabilities.yaml", "capabilities")
    resolved: list[dict[str, Any]] = []
    for resource in specification["resources"]:
        capability = capabilities.get(resource["kind"])
        if capability is None:
            raise LabError(f"resource is not approved by the lab catalog: {resource['kind']}")
        if capability.get("availability") != "available":
            raise LabError(f"resource is not currently available: {resource['kind']}")
        resolved.append({
            "id": resource["id"],
            "kind": resource["kind"],
            "status": "approved-lab-resource",
            "revision": capability.get("revision"),
            "provenance": resource.get("source", "lab catalog"),
        })
    return resolved


def build_construction_plan(path: Path, investigation_id: str, root: Path = ROOT) -> dict[str, Any]:
    if not investigation_id or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", investigation_id):
        raise LabError("invalid investigation ID")
    specification = validate_investigation(path, root)
    resolved = resolve_resources(specification, root)
    source = ensure_inside(root, path, "investigation specification")
    return {
        "plan_version": 1,
        "investigation_id": investigation_id,
        "specification": str(source.relative_to(root)),
        "specification_sha256": sha256_bytes(source.read_bytes()),
        "backend": specification["apparatus"]["backend"],
        "resources": resolved,
        "procedure": specification["procedure"],
        "resource_budget": specification["resource_budget"],
        "authorization_required": specification["safety"].get("required_approvals", []),
        "network_policy": resolve_network_policy(
            root,
            specification["apparatus"].get("network_policy", {}).get("profile"),
            specification["apparatus"].get("network_policy", {}).get("overrides"),
        ),
        "ownership": {"lab": "security-lab", "investigation": investigation_id},
        "created_utc": utc_now(),
    }


def write_plan(path: Path, investigation_id: str, output: Path, root: Path = ROOT) -> Path:
    plan = build_construction_plan(path, investigation_id, root)
    destination = ensure_inside(root, output, "construction plan")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _runtime_gate_enabled(root: Path) -> bool:
    """Require both the persisted lab gate and an explicit per-shell opt-in."""
    config_path = root / "config" / "lab.env"
    configured = None
    try:
        for raw in config_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                if key.strip() == "REQUIRE_RUNTIME_APPROVAL":
                    configured = value.strip().strip("\"'")
    except OSError:
        return False
    return configured == "true" and os.environ.get("REQUIRE_RUNTIME_APPROVAL") == "true"


def _owned_compose_document(compose_file: Path, investigation_id: str) -> dict[str, Any]:
    """Add non-user-overridable ownership labels to a validated Compose document."""
    document = load_yaml(compose_file)
    owner = "io.ithoka.security-lab.owner"
    ident = "io.ithoka.security-lab.investigation"
    for service in document["services"].values():
        labels = service.get("labels", {})
        if isinstance(labels, list):
            converted = {}
            for item in labels:
                if isinstance(item, str) and "=" in item:
                    key, value = item.split("=", 1)
                    converted[key] = value
            labels = converted
        if not isinstance(labels, dict):
            raise LabError("Compose service labels must be a mapping or key=value list")
        if (owner in labels and labels[owner] != "security-lab") or (ident in labels and labels[ident] != investigation_id):
            raise LabError("Compose definition contains conflicting lab ownership labels")
        labels[owner] = "security-lab"
        labels[ident] = investigation_id
        service["labels"] = labels
    for network in document["networks"].values():
        labels = network.get("labels", {})
        if isinstance(labels, list):
            converted = {}
            for item in labels:
                if isinstance(item, str) and "=" in item:
                    key, value = item.split("=", 1)
                    converted[key] = value
            labels = converted
        if not isinstance(labels, dict):
            raise LabError("Compose network labels must be a mapping or key=value list")
        if (owner in labels and labels[owner] != "security-lab") or (ident in labels and labels[ident] != investigation_id):
            raise LabError("Compose definition contains conflicting lab ownership labels")
        labels[owner] = "security-lab"
        labels[ident] = investigation_id
        network["labels"] = labels
    return document


def _assert_project_absent(project: str, runner: Any, root: Path) -> None:
    """Never adopt or overwrite pre-existing resources under a project name."""
    for kind, command in (
        ("containers", ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"]),
        ("networks", ["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"]),
    ):
        result = runner(command, cwd=str(root), capture_output=True, text=True, check=False, timeout=20)
        if result.returncode != 0:
            raise LabError(f"cannot verify existing project {kind}: {result.stderr.strip()}")
        if result.stdout.strip():
            raise LabError(f"refusing to reuse existing Docker project resources ({kind}); inspect and resolve ownership explicitly")


def _assert_project_owned(project: str, investigation_id: str, runner: Any, root: Path) -> bool:
    """Verify all project containers and networks before disposal; return if any exist."""
    found = False
    queries = (
        ("containers", ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
         ["docker", "inspect", "--format", "{{ index .Config.Labels \"io.ithoka.security-lab.owner\" }}|{{ index .Config.Labels \"io.ithoka.security-lab.investigation\" }}"]),
        ("networks", ["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"],
         ["docker", "network", "inspect", "--format", "{{ index .Labels \"io.ithoka.security-lab.owner\" }}|{{ index .Labels \"io.ithoka.security-lab.investigation\" }}"]),
    )
    for kind, list_command, inspect_prefix in queries:
        listed = runner(list_command, cwd=str(root), capture_output=True, text=True, check=False, timeout=20)
        if listed.returncode != 0:
            raise LabError(f"cannot verify project {kind}: {listed.stderr.strip()}")
        ids = listed.stdout.split()
        found = found or bool(ids)
        for resource_id in ids:
            inspected = runner(inspect_prefix + [resource_id], cwd=str(root), capture_output=True, text=True, check=False, timeout=20)
            if inspected.returncode != 0 or inspected.stdout.strip() != f"security-lab|{investigation_id}":
                raise LabError(f"refusing disposal: {kind} resource {resource_id} is not verified as owned by this investigation")
    return found


def _boundary_command(action: str, project: str, policy_file: Path, root: Path) -> list[str]:
    script = root / "scripts" / "network-boundary.sh"
    if not script.is_file():
        raise LabError(f"network-boundary enforcement script is missing: {script}")
    return ["bash", str(script), action, project, str(policy_file)]


def _run_boundary(action: str, project: str, policy_file: Path, runner: Any, root: Path) -> None:
    result = runner(
        _boundary_command(action, project, policy_file, root),
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise LabError(f"network-boundary {action} failed: {result.stderr.strip()}")


def _record_boundary_failure(root: Path, project: str, message: str) -> None:
    record = root / "state" / "network-boundary" / "failures.log"
    record.parent.mkdir(parents=True, exist_ok=True)
    with record.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "project": project,
            "message": message,
            "recorded_utc": utc_now(),
        }, sort_keys=True) + "\n")


def construct_investigation(
    specification_path: Path,
    investigation_id: str,
    authorize: str,
    root: Path = ROOT,
    runner: Any = subprocess.run,
) -> dict[str, Any]:
    """Construct a uniquely owned Compose project without acquiring images."""
    if not authorize.strip():
        raise LabError("construction authorization rationale is required")
    if not investigation_id or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", investigation_id):
        raise LabError("invalid investigation ID")
    if not _runtime_gate_enabled(root):
        raise LabError("runtime construction requires REQUIRE_RUNTIME_APPROVAL=true in config/lab.env and the current shell")

    specification = validate_investigation(specification_path, root)
    plan = build_construction_plan(specification_path, investigation_id, root)
    validate_runtime_support(plan["network_policy"])
    compose_file = ensure_inside(root, root / specification["apparatus"]["compose_file"], "Compose definition")
    project = f"sec-lab-i-{investigation_id}"
    _assert_project_absent(project, runner, root)

    raw_compose = load_yaml(compose_file)
    validate_compose_document(raw_compose, {
        "apparatus": specification["apparatus"],
        "network_policy": plan["network_policy"],
    })
    # Images must already exist locally. This path never pulls or builds images.
    for service_name, service in raw_compose["services"].items():
        image = service["image"]
        inspected = runner(["docker", "image", "inspect", image], cwd=str(root), capture_output=True, text=True, check=False, timeout=20)
        if inspected.returncode != 0:
            raise LabError(f"image for service {service_name} is not available locally; acquisition requires the separate maintenance workflow: {image}")

    runtime_dir = root / "state" / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    runtime_file = None
    policy_file = root / "state" / "runtime" / f"{project}-network-policy.json"
    try:
        effective = _owned_compose_document(compose_file, investigation_id)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml", prefix=f"{project}-", dir=runtime_dir, delete=False) as stream:
            runtime_file = Path(stream.name)
            yaml.safe_dump(effective, stream, sort_keys=False)
        policy_file.write_text(policy_json(plan["network_policy"]), encoding="utf-8")
        create_command = [
            "docker", "compose", "--project-name", project, "--file", str(runtime_file),
            "create", "--no-build", "--pull", "never",
        ]
        result = runner(create_command, cwd=str(root), env={**os.environ, "LAB_OWNER": "security-lab"}, capture_output=True, text=True, check=False, timeout=120)
        if result.returncode != 0:
            raise LabError(f"construction failed; no image pull was attempted: {result.stderr.strip()}")
        boundary_started = False
        try:
            boundary_started = True
            _run_boundary("apply", project, policy_file, runner, root)
            _run_boundary("verify", project, policy_file, runner, root)
            start_command = [
                "docker", "compose", "--project-name", project, "--file", str(runtime_file),
                "start",
            ]
            started = runner(start_command, cwd=str(root), env={**os.environ, "LAB_OWNER": "security-lab"},
                             capture_output=True, text=True, check=False, timeout=120)
            if started.returncode != 0:
                raise LabError(f"construction startup failed: {started.stderr.strip()}")
        except (LabError, OSError, subprocess.SubprocessError):
            cleanup_errors: list[str] = []
            if boundary_started:
                try:
                    _run_boundary("remove", project, policy_file, runner, root)
                except LabError as cleanup_error:
                    cleanup_errors.append(str(cleanup_error))
            cleanup = runner(
                ["docker", "compose", "--project-name", project, "--file", str(runtime_file),
                 "down", "--remove-orphans"],
                cwd=str(root), env={**os.environ, "LAB_OWNER": "security-lab"},
                capture_output=True, text=True, check=False, timeout=120,
            )
            if cleanup.returncode != 0:
                cleanup_errors.append(f"project cleanup failed: {cleanup.stderr.strip()}")
            if cleanup_errors:
                message = f"construction failed; cleanup incomplete: {'; '.join(cleanup_errors)}"
                _record_boundary_failure(root, project, message)
                raise LabError(message)
            raise
        plan["authorization"] = authorize
        plan["status"] = "constructed"
        plan["project"] = project
        plan["provisioning_result"] = result.stdout.strip()
        plan["ownership_labels"] = {
            "io.ithoka.security-lab.owner": "security-lab",
            "io.ithoka.security-lab.investigation": investigation_id,
        }
        return plan
    finally:
        if runtime_file is not None:
            runtime_file.unlink(missing_ok=True)
        policy_file.unlink(missing_ok=True)


def dispose_investigation(
    specification_path: Path,
    investigation_id: str,
    root: Path = ROOT,
    runner: Any = subprocess.run,
) -> None:
    """Dispose only a project whose containers and network carry matching owner labels."""
    if not investigation_id or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", investigation_id):
        raise LabError("invalid investigation ID")
    specification = validate_investigation(specification_path, root)
    compose_file = ensure_inside(root, root / specification["apparatus"]["compose_file"], "Compose definition")
    project = f"sec-lab-i-{investigation_id}"
    found = _assert_project_owned(project, investigation_id, runner, root)
    if not found:
        return

    runtime_dir = root / "state" / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    runtime_file = None
    policy_file = root / "state" / "runtime" / f"{project}-network-policy.json"
    try:
        effective = _owned_compose_document(compose_file, investigation_id)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml", prefix=f"{project}-", dir=runtime_dir, delete=False) as stream:
            runtime_file = Path(stream.name)
            yaml.safe_dump(effective, stream, sort_keys=False)
        policy_file.write_text(policy_json(resolve_network_policy(
            root,
            specification["apparatus"].get("network_policy", {}).get("profile"),
            specification["apparatus"].get("network_policy", {}).get("overrides"),
        )), encoding="utf-8")
        try:
            _run_boundary("remove", project, policy_file, runner, root)
        except LabError as exc:
            _record_boundary_failure(root, project, str(exc))
            raise
        result = runner(
            ["docker", "compose", "--project-name", project, "--file", str(runtime_file), "down", "--remove-orphans"],
            cwd=str(root), env={**os.environ, "LAB_OWNER": "security-lab"}, capture_output=True, text=True, check=False, timeout=120,
        )
        if result.returncode != 0:
            raise LabError(f"disposal failed: {result.stderr.strip()}")
    finally:
        if runtime_file is not None:
            runtime_file.unlink(missing_ok=True)
        policy_file.unlink(missing_ok=True)


__all__ = [
    "build_construction_plan",
    "construct_investigation",
    "dispose_investigation",
    "resolve_resources",
    "validate_investigation",
    "write_plan",
]
