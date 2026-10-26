"""Construct and manage researcher-defined experiments inside the lab.

This module is the experiment-construction layer, not the lab-provisioning
layer. It operates against an already-running Lab Runtime and manages only
resources owned by the requested investigation.

Lifecycle:
    1. Validate the investigation and resolve its effective network policy.
    2. Confirm lab runtime readiness and reserve experiment runtime admission.
    3. Prepare uniquely owned experiment resources without starting workloads.
    4. Verify that the experiment's Docker network was created and is owned
       by the investigation.
    5. Apply the experiment's effective network policy.
    6. Verify enforcement controls.
    7. Execute fresh policy acceptance probes.
    8. Start workloads only after every mandatory gate passes.
    9. Record evidence for subsequent experiment inspection and disposal.

The lab infrastructure must already exist. This module does not provision
the lab, initialize its infrastructure, or claim ownership of shared lab
resources. Docker resources created here belong to an individual experiment.

Policy definition, enforcement, and acceptance evidence are independent.
Prepared resources and present firewall rules do not prove behavioral safety.
Unsupported mandatory boundaries and missing acceptance probes fail closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile

import yaml

from pathlib import Path
from typing import Any

from .foundation import (
    LabError,
    ROOT,
    ensure_inside,
    load_materials,
    load_yaml,
    require_integer,
    require_list,
    require_mapping,
    require_open_mapping,
    require_text,
    require_available_capability,
    require_available_image,
    reject_sensitive_fields,
    sha256_bytes,
    utc_now,
)
from .validation import validate_compose_document
from .networks import (
    inspect_docker_project,
    policy_json,
    resolve_network_policy,
    validate_runtime_support,
)
from .osapi.actions import (
    OSActionRequest,
    OSActionResult,
    OSActionStatus,
    execute_network_boundary_action,
    execute_os_action,
)

# Runtime's readiness helper performs fresh policy-bound acceptance execution.
# It is intentionally reused so construction and runtime share the same
# evidence contract rather than maintaining competing acceptance implementations.
from .runtime import (
    admit_experiment,
    release_experiment,
    runtime_status,
    _network_readiness,
)

INVESTIGATION_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
PROJECT_PREFIX = "sec-lab-i-"

OWNER_LABEL = "io.ithoka.security-lab.owner"
INVESTIGATION_LABEL = "io.ithoka.security-lab.investigation"

NETWORK_BOUNDARY_DIR = Path("state") / "network-boundary"
RUNTIME_DIR = Path("state") / "runtime"

PASS = "PASS"
FAIL = "FAIL"
NOT_TESTED = "NOT_TESTED"
ERROR = "ERROR"

LIFECYCLE = (
    "validate_policy",
    "admit_runtime",
    "prepare_resources",
    "verify_experiment_network",
    "apply_policy",
    "verify_enforcement",
    "execute_acceptance",
    "start_workloads",
    "verify_running_workloads",
)


def _project_name(investigation_id: str) -> str:
    if (
        not isinstance(investigation_id, str)
        or not INVESTIGATION_ID_RE.fullmatch(investigation_id)
    ):
        raise LabError("invalid investigation ID")
    return f"{PROJECT_PREFIX}{investigation_id}"


def _policy_identity(policy: dict[str, Any]) -> str:
    return hashlib.sha256(policy_json(policy).encode("utf-8")).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")

    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    except OSError as exc:
        raise LabError(
            f"cannot write construction evidence {path}: {exc}"
        ) from exc


def _run(
    command: list[str],
    runner: Any,
    root: Path,
    *,
    timeout: int = 30,
    env: dict[str, str] | None = None,
) -> Any:
    """Run a fixed argv command without shell interpretation."""
    try:
        result = runner(
            command,
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LabError(
            f"command could not execute ({command[0]}): {exc}"
        ) from exc

    if result.returncode != 0:
        detail = (
            (result.stderr or "").strip()
            or (result.stdout or "").strip()
        )
        raise LabError(
            f"command failed with exit code {result.returncode}: "
            f"{' '.join(command)}"
            + (f": {detail}" if detail else "")
        )

    return result


def _run_compose_action(
    action: str,
    project: str,
    compose_file: Path,
    root: Path,
    runner: Any,
) -> OSActionResult:
    """Execute a Compose operation scoped to one experiment project."""
    result = execute_os_action(
        OSActionRequest(
            platform="docker",
            operation=f"docker.compose.{action}",
            target=project,
            repository_root=root,
            arguments={"compose_file": str(compose_file)},
        ),
        runner=runner,
    )
    if result.status is not OSActionStatus.SUCCEEDED:
        raise LabError(
            f"Docker Compose {action} did not pass: "
            f"{result.reason or result.status.value}"
        )
    return result


def validate_investigation(
    path: Path,
    root: Path = ROOT,
) -> dict[str, Any]:
    source = ensure_inside(root, path, "investigation specification")
    if not source.is_file():
        raise LabError(f"investigation specification is missing: {source}")

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
        specification["investigation"],
        "investigation.investigation",
        {"question"},
        {"hypothesis", "objectives", "title"},
    )
    require_text(investigation["question"], "investigation.question")

    apparatus = require_mapping(
        specification["apparatus"],
        "investigation.apparatus",
        {"backend", "compose_file"},
        {"network", "components", "relationships", "network_policy"},
    )

    if apparatus["backend"] != "docker.compose":
        raise LabError(
            f"unsupported construction backend: {apparatus['backend']}"
        )
    require_available_capability(
        apparatus["backend"],
        "construct",
        root,
    )

    network_policy = apparatus.get("network_policy", {})
    if not isinstance(network_policy, dict):
        raise LabError(
            "investigation.apparatus.network_policy must be a mapping"
        )

    unknown_policy_keys = set(network_policy) - {"profile", "overrides"}
    if unknown_policy_keys:
        raise LabError(
            "investigation.apparatus.network_policy contains unsupported keys: "
            + ", ".join(sorted(unknown_policy_keys))
        )

    if "profile" in network_policy and network_policy["profile"] is not None:
        require_text(
            network_policy["profile"],
            "investigation.apparatus.network_policy.profile",
        )

    if "overrides" in network_policy and not isinstance(
        network_policy["overrides"], dict
    ):
        raise LabError(
            "investigation.apparatus.network_policy.overrides must be a mapping"
        )

    network = apparatus.get("network", {})
    if not isinstance(network, dict):
        raise LabError("investigation.apparatus.network must be a mapping")

    require_mapping(
        network,
        "investigation.apparatus.network",
        set(),
        {"logical_name"},
    )

    compose_file = require_text(
        apparatus["compose_file"],
        "investigation.apparatus.compose_file",
    )
    logical_name = network.get("logical_name", "lab")
    require_text(
        logical_name,
        "investigation.apparatus.network.logical_name",
    )

    compose_path = ensure_inside(
        root,
        root / compose_file,
        "Compose definition",
    )
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

    resources = require_list(
        specification["resources"],
        "investigation.resources",
    )
    seen_resource_ids: set[str] = set()

    for index, resource in enumerate(resources):
        label = f"investigation.resources[{index}]"
        require_mapping(
            resource,
            label,
            {"id", "kind"},
            {"source", "digest", "authorization", "material_id"},
        )
        resource_id = require_text(resource["id"], f"{label}.id")
        require_text(resource["kind"], f"{label}.kind")

        if resource_id in seen_resource_ids:
            raise LabError(
                f"duplicate investigation resource ID: {resource_id}"
            )
        seen_resource_ids.add(resource_id)

        for optional_text in ("source", "digest", "authorization"):
            if resource.get(optional_text) is not None:
                require_text(
                    resource[optional_text],
                    f"{label}.{optional_text}",
                )
        if "material_id" in resource:
            require_text(resource["material_id"], f"{label}.material_id")

    resolved_resources = resolve_resources(specification, root)
    _validate_registered_compose_images(compose, root)
    declared_images = {
        resource["material"]["image"]
        for resource in resolved_resources
        if resource.get("status") == "approved-material"
        and resource["material"]["kind"] == "container-image"
    }
    if declared_images:
        services = compose.get("services", {})
        compose_images = {
            service.get("image")
            for service in services.values()
            if isinstance(service, dict)
            and isinstance(service.get("image"), str)
        } if isinstance(services, dict) else set()
        unused_images = declared_images - compose_images
        if unused_images:
            raise LabError(
                "approved container-image material is not referenced by Compose: "
                + ", ".join(sorted(unused_images))
            )

    procedure = require_list(
        specification["procedure"],
        "investigation.procedure",
    )
    seen_step_ids: set[str] = set()

    allowed_operations = {
        "construct",
        "run_service",
        "collect_logs",
        "stop",
        "destroy",
    }

    for index, step in enumerate(procedure):
        label = f"investigation.procedure[{index}]"
        require_mapping(
            step,
            label,
            {"id", "operation"},
            {"service", "arguments"},
        )

        step_id = require_text(step["id"], f"{label}.id")
        if step_id in seen_step_ids:
            raise LabError(f"duplicate procedure step ID: {step_id}")
        seen_step_ids.add(step_id)

        if step["operation"] not in allowed_operations:
            raise LabError(
                f"unsupported procedure operation: {step['operation']}"
            )

        if "service" in step and step["service"] is not None:
            require_text(step["service"], f"{label}.service")

        if "arguments" in step and not isinstance(
            step["arguments"], (dict, list)
        ):
            raise LabError(
                f"{label}.arguments must be a mapping or list"
            )

    for field in ("observations", "evaluation", "evidence", "safety"):
        require_open_mapping(
            specification[field],
            f"investigation.{field}",
        )

    budget = require_mapping(
        specification["resource_budget"],
        "investigation.resource_budget",
        {"memory_mib", "cpu_millicores", "pids", "storage_mib"},
    )
    for key, value in budget.items():
        require_integer(value, f"resource_budget.{key}", 1)

    capacity = load_yaml(root / "config" / "lab-capacity.yaml")
    require_mapping(
        capacity,
        "lab capacity",
        {
            "max_active_instances",
            "memory_mib",
            "cpu_millicores",
            "pids",
            "storage_mib",
            "max_duration_seconds",
        },
    )
    for key, value in capacity.items():
        require_integer(value, f"lab capacity.{key}", 1)

    for key in ("memory_mib", "cpu_millicores", "pids", "storage_mib"):
        if budget[key] > capacity[key]:
            raise LabError(
                f"resource_budget.{key} exceeds lab capacity ({capacity[key]})"
            )

    reject_sensitive_fields(specification)
    return specification


def resolve_resources(
    specification: dict[str, Any],
    root: Path = ROOT,
) -> list[dict[str, Any]]:
    materials = load_materials(root)

    resolved: list[dict[str, Any]] = []
    for resource in specification["resources"]:
        material_id = resource.get("material_id")
        result = {
            "id": resource["id"],
            "kind": resource["kind"],
            "status": "declared-not-material-backed",
            "provenance": resource.get(
                "source",
                "investigation definition",
            ),
        }
        if material_id is None:
            resolved.append(result)
            continue

        material = materials.get(material_id)
        if material is None:
            raise LabError(f"material is not registered: {material_id}")
        if material["availability"] != "available":
            raise LabError(
                f"material is not currently available: {material_id}"
            )
        if resource["kind"] != material["kind"]:
            raise LabError(
                f"resource kind {resource['kind']} does not match material "
                f"{material_id} kind {material['kind']}"
            )
        if "digest" in resource and resource["digest"] != material.get("digest"):
            raise LabError(
                f"resource digest does not match material {material_id}"
            )

        result.update({
            "material_id": material_id,
            "status": "approved-material",
            "revision": material.get("revision", material.get("version")),
            "digest": material.get("digest"),
            "material": material,
        })
        resolved.append(result)

    return resolved


def build_construction_plan(
    path: Path,
    investigation_id: str,
    root: Path = ROOT,
) -> dict[str, Any]:
    project = _project_name(investigation_id)
    specification = validate_investigation(path, root)
    resolved = resolve_resources(specification, root)
    source = ensure_inside(root, path, "investigation specification")

    network_settings = specification["apparatus"].get("network_policy", {})
    network_policy = resolve_network_policy(
        root,
        network_settings.get("profile"),
        network_settings.get("overrides"),
    )

    network_support_error = None
    try:
        validate_runtime_support(network_policy)
    except LabError as exc:
        network_support_error = str(exc)

    identity = _policy_identity(network_policy)

    return {
        "plan_version": 2,
        "investigation_id": investigation_id,
        "project": project,
        "specification": str(source.relative_to(root)),
        "specification_sha256": sha256_bytes(source.read_bytes()),
        "backend": specification["apparatus"]["backend"],
        "resources": resolved,
        "procedure": specification["procedure"],
        "resource_budget": specification["resource_budget"],
        "authorization_required": specification["safety"].get(
            "required_approvals", []
        ),
        "network_policy": network_policy,
        "policy_definition": {
            "profile": network_policy["profile"],
            "identity": identity,
            "boundaries": network_policy.get("boundaries", {}),
        },
        "network_policy_supported": network_support_error is None,
        "network_policy_capability_error": network_support_error,
        "enforcement": {
            "status": NOT_TESTED,
            "reason": "enforcement has not yet been applied or verified",
        },
        "acceptance": {
            "status": NOT_TESTED,
            "reason": "acceptance probes have not yet executed",
        },
        "lifecycle_order": list(LIFECYCLE),
        "ownership": {
            "lab": "security-lab",
            "investigation": investigation_id,
            "project": project,
        },
        "created_utc": utc_now(),
    }


def write_plan(
    path: Path,
    investigation_id: str,
    output: Path,
    root: Path = ROOT,
) -> Path:
    plan = build_construction_plan(path, investigation_id, root)
    root_path = Path(root).resolve(strict=True)
    candidate = Path(output)
    if not candidate.is_absolute():
        candidate = root_path / candidate
    if candidate.is_symlink():
        raise LabError(
            f"construction plan destination must not be a symlink: {candidate}"
        )
    destination = candidate.resolve(strict=False)
    try:
        destination.relative_to(root_path)
    except ValueError as exc:
        raise LabError(
            f"construction plan must remain inside the repository: {output}"
        ) from exc
    if destination == root_path:
        raise LabError(
            "construction plan cannot replace the repository root"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    ensure_inside(
        root_path,
        destination.parent,
        "construction plan directory",
    )
    if destination.is_symlink():
        raise LabError(
            f"construction plan destination must not be a symlink: {destination}"
        )
    destination.write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def _runtime_gate_enabled(root: Path) -> bool:
    """Require persisted runtime approval and explicit shell opt-in."""
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

    return (
        configured == "true"
        and os.environ.get("REQUIRE_RUNTIME_APPROVAL") == "true"
    )


def _convert_labels(value: Any, context: str) -> dict[str, str]:
    if isinstance(value, list):
        converted: dict[str, str] = {}
        for item in value:
            if not isinstance(item, str) or "=" not in item:
                raise LabError(
                    f"{context} labels must be a mapping or key=value list"
                )
            key, label_value = item.split("=", 1)
            converted[key] = label_value
        return converted

    if isinstance(value, dict):
        converted = {}
        for key, label_value in value.items():
            if not isinstance(
                key,
                str,
            ) or not isinstance(label_value, (str, int, float, bool)):
                raise LabError(
                    f"{context} labels must contain scalar values"
                )
            converted[key] = str(label_value)
        return converted

    if value is None:
        return {}

    raise LabError(
        f"{context} labels must be a mapping or key=value list"
    )


def _owned_compose_document(
    compose_file: Path,
    investigation_id: str,
) -> dict[str, Any]:
    """Add experiment ownership labels to its services and networks.

    These labels identify experiment resources; they do not label or claim
    ownership of the shared lab runtime or other lab infrastructure.
    """
    document = load_yaml(compose_file)

    if not isinstance(document, dict):
        raise LabError("Compose definition must be a mapping")

    services = document.get("services")
    networks = document.get("networks")

    if not isinstance(services, dict) or not services:
        raise LabError(
            "Compose definition must declare at least one service"
        )
    if not isinstance(networks, dict) or not networks:
        raise LabError(
            "Compose definition must declare at least one explicit network"
        )

    for section_name, section in (
        ("service", services),
        ("network", networks),
    ):
        for name, item in section.items():
            if not isinstance(item, dict):
                raise LabError(
                    f"Compose {section_name} {name!r} must be a mapping"
                )

            labels = _convert_labels(
                item.get("labels", {}),
                f"Compose {section_name} {name!r}",
            )

            if (
                OWNER_LABEL in labels
                and labels[OWNER_LABEL] != "security-lab"
            ):
                raise LabError(
                    f"Compose {section_name} {name!r} has conflicting owner label"
                )

            if (
                INVESTIGATION_LABEL in labels
                and labels[INVESTIGATION_LABEL] != investigation_id
            ):
                raise LabError(
                    f"Compose {section_name} {name!r} has conflicting "
                    "investigation label"
                )

            labels[OWNER_LABEL] = "security-lab"
            labels[INVESTIGATION_LABEL] = investigation_id
            item["labels"] = labels

    return document


def _assert_project_absent(
    project: str,
    runner: Any,
    root: Path,
) -> None:
    """Never adopt or overwrite resources already bearing this Compose project."""
    queries = (
        (
            "containers",
            [
                "docker",
                "ps",
                "-aq",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
        ),
        (
            "networks",
            [
                "docker",
                "network",
                "ls",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
        ),
    )

    for kind, command in queries:
        result = _run(command, runner, root, timeout=20)
        if result.stdout.strip():
            raise LabError(
                "refusing to reuse existing Docker project resources "
                f"({kind}); inspect and resolve ownership explicitly"
            )


def _assert_project_owned(
    project: str,
    investigation_id: str,
    runner: Any,
    root: Path,
) -> bool:
    """Verify every project container and network before disposal."""
    found = False

    queries = (
        (
            "containers",
            [
                "docker",
                "ps",
                "-aq",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
            [
                "docker",
                "inspect",
                "--format",
                (
                    '{{ index .Config.Labels "io.ithoka.security-lab.owner" }}|'
                    '{{ index .Config.Labels "io.ithoka.security-lab.investigation" }}'
                ),
            ],
        ),
        (
            "networks",
            [
                "docker",
                "network",
                "ls",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
            [
                "docker",
                "network",
                "inspect",
                "--format",
                (
                    '{{ index .Labels "io.ithoka.security-lab.owner" }}|'
                    '{{ index .Labels "io.ithoka.security-lab.investigation" }}'
                ),
            ],
        ),
    )

    for kind, list_command, inspect_prefix in queries:
        listed = _run(list_command, runner, root, timeout=20)
        ids = listed.stdout.split()
        found = found or bool(ids)

        for resource_id in ids:
            inspected = _run(
                inspect_prefix + [resource_id],
                runner,
                root,
                timeout=20,
            )
            if inspected.stdout.strip() != (
                f"security-lab|{investigation_id}"
            ):
                raise LabError(
                    f"refusing disposal: {kind} resource {resource_id} "
                    "is not verified as owned by this investigation"
                )

    return found


def _verify_experiment_network(
    project: str,
    investigation_id: str,
    runner: Any,
    root: Path,
) -> dict[str, Any]:
    """Verify the network created for this experiment after Compose preparation.

    This verifies an experiment-owned resource within the existing lab. It
    neither creates nor provisions the lab infrastructure.

    The network must be discoverable under the expected Compose project and
    must carry the experiment ownership labels added to its Compose definition.
    A missing, duplicated, or incorrectly labelled network fails closed.
    """
    listed = _run(
        [
            "docker",
            "network",
            "ls",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={project}",
        ],
        runner,
        root,
        timeout=20,
    )

    network_ids = listed.stdout.split()

    if len(network_ids) != 1:
        raise LabError(
            "experiment resource preparation did not produce exactly one "
            "project-owned Docker network: "
            f"expected 1, found {len(network_ids)}"
        )

    network_id = network_ids[0]

    inspected = _run(
        [
            "docker",
            "network",
            "inspect",
            "--format",
            (
                '{{.Name}}|'
                '{{ index .Labels "com.docker.compose.project" }}|'
                '{{ index .Labels "io.ithoka.security-lab.owner" }}|'
                '{{ index .Labels "io.ithoka.security-lab.investigation" }}'
            ),
            network_id,
        ],
        runner,
        root,
        timeout=20,
    )

    fields = inspected.stdout.strip().split("|")
    if len(fields) != 4:
        raise LabError(
            "cannot verify the prepared experiment network's identity and ownership"
        )

    network_name, compose_project, owner, owner_investigation = fields

    if compose_project != project:
        raise LabError(
            "prepared Docker network has an unexpected Compose project label"
        )

    if owner != "security-lab" or owner_investigation != investigation_id:
        raise LabError(
            "prepared Docker network is not labelled as owned by this experiment"
        )

    return {
        "status": PASS,
        "project": project,
        "investigation_id": investigation_id,
        "network_id": network_id,
        "network_name": network_name,
        "ownership": {
            "compose_project": compose_project,
            OWNER_LABEL: owner,
            INVESTIGATION_LABEL: owner_investigation,
        },
        "verified_utc": utc_now(),
    }


def _run_boundary(
    action: str,
    project: str,
    policy_file: Path,
    runner: Any,
    root: Path,
) -> dict[str, Any]:
    result = execute_network_boundary_action(
        action,
        project,
        policy_file,
        root,
        runner=runner,
    )
    passed = result.status is OSActionStatus.SUCCEEDED
    command = (
        [result.native_executable, *result.arguments]
        if result.native_executable
        else []
    )
    return {
        "action": action,
        "status": (
            PASS
            if passed
            else FAIL
            if result.status in {
                OSActionStatus.FAILED,
                OSActionStatus.TIMED_OUT,
            }
            else ERROR
        ),
        "execution": result.to_dict(),
        "returncode": result.returncode,
        "reason": result.reason,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": command,
        "executed_utc": utc_now(),
    }


def _require_boundary_pass(result: dict[str, Any]) -> None:
    if result.get("status") != PASS:
        raise LabError(
            f"network-boundary {result.get('action')} did not pass: "
            f"{result.get('reason') or result.get('status')}"
        )


def _record_boundary_failure(
    root: Path,
    project: str,
    message: str,
    *,
    stage: str = "construction",
    status: str = FAIL,
) -> None:
    record = root / NETWORK_BOUNDARY_DIR / "failures.log"
    record.parent.mkdir(parents=True, exist_ok=True)

    with record.open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(
                {
                    "project": project,
                    "stage": stage,
                    "status": status,
                    "message": message,
                    "recorded_utc": utc_now(),
                },
                sort_keys=True,
            )
            + "\n"
        )


def _write_construction_evidence(
    root: Path,
    project: str,
    evidence: dict[str, Any],
) -> Path:
    path = root / NETWORK_BOUNDARY_DIR / f"{project}-construction.json"
    _write_json(path, evidence)
    return path


def _runtime_admit(
    investigation_id: str,
    policy: dict[str, Any],
    budget: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    """Reserve experiment resources through Runtime and reject policy drift.

    The Runtime admission API resolves a named profile but does not accept
    arbitrary per-investigation overrides. Construction proceeds only when
    the policy admitted by Runtime matches the effective experiment policy.
    """
    status = runtime_status(root)
    if status.get("status") != "RUNNING":
        raise LabError(
            "construction refused: the existing Lab Runtime must be RUNNING "
            "before experiment admission"
        )

    record = admit_experiment(
        experiment_id=investigation_id,
        profile=policy.get("profile"),
        root=root,
        memory_mib=budget["memory_mib"],
        cpu_millicores=budget["cpu_millicores"],
        pids=budget["pids"],
    )

    expected_identity = _policy_identity(policy)
    admitted_identity = record.get("policy_identity")

    if admitted_identity != expected_identity:
        try:
            release_experiment(investigation_id, root)
        except LabError as release_error:
            raise LabError(
                "runtime admission policy does not match experiment policy; "
                "resource release also failed and requires operator review: "
                f"{release_error}"
            ) from release_error

        raise LabError(
            "construction refused: Runtime admitted a different effective "
            "policy. Current runtime admission supports named profiles only; "
            "policy overrides must not bypass policy identity matching."
        )

    return record


def _prepare_compose_resources(
    project: str,
    runtime_file: Path,
    root: Path,
    runner: Any,
) -> dict[str, Any]:
    """Create this experiment's Compose resources without starting workloads."""
    result = _run_compose_action(
        "create",
        project,
        runtime_file,
        root,
        runner,
    )
    return {
        "status": PASS,
        "operation": "prepare_resources",
        "meaning": (
            "Experiment-owned Compose resources were created inside the "
            "existing lab; workloads have not been started"
        ),
        "stdout": result.stdout.strip(),
        "command": [result.native_executable, *result.arguments],
        "os_action": result.to_dict(),
        "completed_utc": utc_now(),
    }


def _verify_local_images(
    compose: dict[str, Any],
    runner: Any,
    root: Path,
) -> None:
    _validate_registered_compose_images(compose, root)
    materials = load_materials(root)
    services = compose.get("services")
    if not isinstance(services, dict) or not services:
        raise LabError("Compose definition must contain services")

    for service_name, service in services.items():
        if not isinstance(service, dict):
            raise LabError(
                f"Compose service {service_name!r} must be a mapping"
            )

        image = service.get("image")
        if not isinstance(image, str) or not image.strip():
            raise LabError(
                f"Compose service {service_name!r} must use an explicit local image"
            )

        registered_images = [
            material for material in materials.values()
            if material.get("image") == image
        ]
        if registered_images:
            require_available_image(image, root)

        _run(
            ["docker", "image", "inspect", image],
            runner,
            root,
            timeout=20,
        )


def _validate_registered_compose_images(
    compose: dict[str, Any],
    root: Path,
) -> None:
    materials = load_materials(root)
    registered_images = {
        material["image"]
        for material in materials.values()
        if material["kind"] == "container-image"
    }
    services = compose.get("services")
    if not isinstance(services, dict):
        return

    for service in services.values():
        if not isinstance(service, dict):
            continue
        image = service.get("image")
        if isinstance(image, str) and image in registered_images:
            require_available_image(image, root)


def _cleanup_failed_construction(
    *,
    project: str,
    investigation_id: str,
    runtime_file: Path | None,
    policy_file: Path,
    root: Path,
    runner: Any,
    boundary_apply_attempted: bool,
    admission_created: bool,
) -> list[str]:
    """Clean up this experiment conservatively without hiding failures."""
    errors: list[str] = []

    if runtime_file is not None:
        try:
            _run_compose_action(
                "stop",
                project,
                runtime_file,
                root,
                runner,
            )
        except LabError as exc:
            errors.append(f"workload stop failed: {exc}")

    if boundary_apply_attempted and policy_file.is_file():
        removal = _run_boundary(
            "remove",
            project,
            policy_file,
            runner,
            root,
        )
        if removal["status"] != PASS:
            errors.append(
                "boundary cleanup failed: "
                f"{removal.get('reason') or removal['status']}"
            )

    if runtime_file is not None:
        try:
            _run_compose_action(
                "down",
                project,
                runtime_file,
                root,
                runner,
            )
        except LabError as exc:
            errors.append(f"experiment resource cleanup failed: {exc}")

    if admission_created:
        try:
            release_experiment(investigation_id, root)
        except LabError as exc:
            errors.append(f"runtime admission release failed: {exc}")

    return errors


def construct_investigation(
    specification_path: Path,
    investigation_id: str,
    authorize: str,
    root: Path = ROOT,
    runner: Any = subprocess.run,
) -> dict[str, Any]:
    """Construct one experiment inside the existing Lab Runtime.

    This function does not construct the lab. It prepares and manages resources
    scoped to one investigation.

    Workloads are never started before policy application, enforcement
    verification, and acceptance all pass.
    """
    project = _project_name(investigation_id)

    if not isinstance(authorize, str) or not authorize.strip():
        raise LabError("construction authorization rationale is required")

    if not _runtime_gate_enabled(root):
        raise LabError(
            "experiment construction requires REQUIRE_RUNTIME_APPROVAL=true "
            "in config/lab.env and the current shell"
        )

    specification = validate_investigation(specification_path, root)
    plan = build_construction_plan(
        specification_path,
        investigation_id,
        root,
    )

    if not plan["network_policy_supported"]:
        raise LabError(
            "construction refused: mandatory network policy is unsupported: "
            f"{plan['network_policy_capability_error']}"
        )

    policy = plan["network_policy"]
    policy_identity = plan["policy_definition"]["identity"]
    budget = specification["resource_budget"]

    # Revalidate immediately before experiment side effects. This checks
    # policy support; it does not constitute enforcement evidence.
    validate_runtime_support(policy)

    compose_file = ensure_inside(
        root,
        root / specification["apparatus"]["compose_file"],
        "Compose definition",
    )
    raw_compose = load_yaml(compose_file)

    validate_compose_document(
        raw_compose,
        {
            "apparatus": specification["apparatus"],
            "network_policy": policy,
        },
    )

    _verify_local_images(raw_compose, runner, root)
    _assert_project_absent(project, runner, root)

    admission = _runtime_admit(
        investigation_id,
        policy,
        budget,
        root,
    )
    admission_created = True

    runtime_dir = root / RUNTIME_DIR
    runtime_dir.mkdir(parents=True, exist_ok=True)

    boundary_dir = root / NETWORK_BOUNDARY_DIR
    boundary_dir.mkdir(parents=True, exist_ok=True)

    runtime_file: Path | None = None
    policy_file = boundary_dir / f"{project}-network-policy.json"
    evidence_file = boundary_dir / f"{project}-construction.json"

    if policy_file.exists():
        try:
            existing = json.loads(
                policy_file.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            try:
                release_experiment(investigation_id, root)
            finally:
                raise LabError(
                    f"existing experiment policy evidence is unreadable: {policy_file}"
                ) from exc

        if _policy_identity(existing) != policy_identity:
            release_experiment(investigation_id, root)
            raise LabError(
                "refusing to overwrite existing experiment policy evidence "
                "with a different policy identity"
            )

        release_experiment(investigation_id, root)
        raise LabError(
            "experiment policy evidence already exists; inspect or dispose "
            "the previous experiment before reconstructing it"
        )

    evidence: dict[str, Any] = {
        "schema_version": 2,
        "project": project,
        "investigation_id": investigation_id,
        "status": "CONSTRUCTING",
        "policy_definition": {
            "profile": policy.get("profile"),
            "identity": policy_identity,
            "boundaries": policy.get("boundaries", {}),
        },
        "runtime_admission": {
            "status": PASS,
            "policy_identity": admission.get("policy_identity"),
            "decision_utc": admission.get("decision_utc"),
        },
        "lifecycle": {
            "order": list(LIFECYCLE),
            "completed": [],
        },
        "resource_preparation": {"status": NOT_TESTED},
        "experiment_network": {"status": NOT_TESTED},
        "enforcement": {"status": NOT_TESTED},
        "acceptance": {"status": NOT_TESTED},
        "workloads": {"status": NOT_TESTED},
        "created_utc": utc_now(),
    }

    boundary_apply_attempted = False
    preserve_policy_file = False

    try:
        _write_json(policy_file, policy)

        # Prepare only resources owned by this experiment. The lab runtime
        # must already be running; this operation does not provision the lab.
        effective_compose = _owned_compose_document(
            compose_file,
            investigation_id,
        )

        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".yaml",
            prefix=f"{project}-",
            dir=runtime_dir,
            delete=False,
        ) as stream:
            runtime_file = Path(stream.name)
            yaml.safe_dump(effective_compose, stream, sort_keys=False)

        evidence["resource_preparation"] = _prepare_compose_resources(
            project,
            runtime_file,
            root,
            runner,
        )
        evidence["lifecycle"]["completed"].append("prepare_resources")
        _write_construction_evidence(root, project, evidence)

        # Verify that resource preparation actually created the expected
        # experiment network before applying any experiment network policy.
        experiment_network = _verify_experiment_network(
            project,
            investigation_id,
            runner,
            root,
        )
        evidence["experiment_network"] = experiment_network
        evidence["lifecycle"]["completed"].append(
            "verify_experiment_network"
        )
        _write_construction_evidence(root, project, evidence)

        # Mark attempted before invoking the script because a failed command
        # may have partially changed controls.
        boundary_apply_attempted = True
        apply_result = _run_boundary(
            "apply",
            project,
            policy_file,
            runner,
            root,
        )
        evidence["enforcement"]["apply"] = apply_result
        _require_boundary_pass(apply_result)
        evidence["lifecycle"]["completed"].append("apply_policy")
        _write_construction_evidence(root, project, evidence)

        verify_result = _run_boundary(
            "verify",
            project,
            policy_file,
            runner,
            root,
        )
        evidence["enforcement"]["verification"] = verify_result
        _require_boundary_pass(verify_result)
        evidence["enforcement"]["status"] = PASS
        evidence["lifecycle"]["completed"].append("verify_enforcement")
        _write_construction_evidence(root, project, evidence)

        # Execute fresh acceptance probes for the pinned experiment policy.
        readiness = _network_readiness(root, policy)

        acceptance = readiness.get("acceptance", {})
        evidence["acceptance"] = acceptance

        if readiness.get("controls_applied") != PASS:
            evidence["enforcement"]["status"] = readiness.get(
                "controls_applied",
                FAIL,
            )
            evidence["enforcement"]["reason"] = readiness.get("reason")
            _write_construction_evidence(root, project, evidence)
            raise LabError(
                "construction refused: enforcement verification did not pass: "
                f"{readiness.get('reason') or readiness.get('controls_applied')}"
            )

        if (
            readiness.get("effective_behavior") != PASS
            or readiness.get("runtime_acceptance") != PASS
            or not readiness.get("ready", False)
        ):
            evidence["acceptance"]["status"] = readiness.get(
                "runtime_acceptance",
                NOT_TESTED,
            )
            evidence["acceptance"]["reason"] = readiness.get("reason")
            _write_construction_evidence(root, project, evidence)
            raise LabError(
                "construction refused: acceptance did not pass for every "
                "enabled boundary: "
                f"{readiness.get('reason') or readiness.get('runtime_acceptance')}"
            )

        evidence["acceptance"]["status"] = PASS
        evidence["lifecycle"]["completed"].append("execute_acceptance")
        _write_construction_evidence(root, project, evidence)

        # Recheck support before starting workloads. This does not replace
        # the enforcement and acceptance results above.
        validate_runtime_support(policy)

        started = _run_compose_action(
            "start",
            project,
            runtime_file,
            root,
            runner,
        )

        runtime_inspection = inspect_docker_project(
            project,
            root,
            runner=runner,
        )
        evidence["workloads"] = {
            "status": runtime_inspection.get("status", ERROR),
            "command": [started.native_executable, *started.arguments],
            "stdout": started.stdout.strip(),
            "os_action": started.to_dict(),
            "started_utc": utc_now(),
            "runtime_inspection": runtime_inspection,
        }
        if runtime_inspection.get("status") != PASS:
            evidence["workloads"]["reason"] = runtime_inspection.get(
                "reason",
                "post-start Docker runtime inspection did not pass",
            )
            _write_construction_evidence(root, project, evidence)
            raise LabError(
                "construction refused after workload start: Docker runtime "
                "inspection did not pass: "
                f"{evidence['workloads']['reason']}"
            )

        evidence["lifecycle"]["completed"].append("start_workloads")
        evidence["lifecycle"]["completed"].append("verify_running_workloads")
        evidence["status"] = "CONSTRUCTED"
        evidence["constructed_utc"] = utc_now()
        evidence["authorization"] = authorize
        evidence["specification_sha256"] = plan["specification_sha256"]
        evidence["policy_identity"] = policy_identity
        evidence["policy_file"] = str(policy_file.relative_to(root))
        evidence["acceptance_evidence_path"] = str(
            (boundary_dir / f"{project}-acceptance.json").relative_to(root)
        )
        evidence["ownership_labels"] = {
            OWNER_LABEL: "security-lab",
            INVESTIGATION_LABEL: investigation_id,
        }

        _write_construction_evidence(root, project, evidence)
        preserve_policy_file = True

        plan.update(
            {
                "status": "constructed",
                "authorization": authorize,
                "project": project,
                "policy_identity": policy_identity,
                "runtime_admission": admission,
                "resource_preparation": evidence["resource_preparation"],
                "experiment_network": evidence["experiment_network"],
                "enforcement": evidence["enforcement"],
                "acceptance": evidence["acceptance"],
                "workloads": evidence["workloads"],
                "lifecycle": evidence["lifecycle"],
                "construction_evidence_path": str(
                    evidence_file.relative_to(root)
                ),
                "acceptance_evidence_path": evidence[
                    "acceptance_evidence_path"
                ],
                "ownership_labels": evidence["ownership_labels"],
            }
        )
        return plan

    except Exception as exc:
        cleanup_errors = _cleanup_failed_construction(
            project=project,
            investigation_id=investigation_id,
            runtime_file=runtime_file,
            policy_file=policy_file,
            root=root,
            runner=runner,
            boundary_apply_attempted=boundary_apply_attempted,
            admission_created=admission_created,
        )

        evidence["status"] = "FAILED"
        evidence["failure"] = {
            "status": FAIL,
            "message": str(exc),
            "failed_utc": utc_now(),
        }
        evidence["cleanup"] = {
            "status": PASS if not cleanup_errors else FAIL,
            "errors": cleanup_errors,
        }

        if cleanup_errors:
            evidence["status"] = "RECOVERY_REQUIRED"
            _record_boundary_failure(
                root,
                project,
                f"{exc}; cleanup incomplete: {'; '.join(cleanup_errors)}",
                stage="construction_cleanup",
                status=FAIL,
            )

        try:
            _write_construction_evidence(root, project, evidence)
        except LabError:
            _record_boundary_failure(
                root,
                project,
                "could not persist experiment construction failure evidence",
                stage="evidence_persistence",
                status=ERROR,
            )

        if cleanup_errors:
            raise LabError(
                f"construction failed: {exc}; cleanup incomplete: "
                + "; ".join(cleanup_errors)
            ) from exc

        if isinstance(exc, LabError):
            raise

        raise LabError(f"construction failed: {exc}") from exc

    finally:
        if runtime_file is not None:
            runtime_file.unlink(missing_ok=True)

        if not preserve_policy_file:
            failure_record = evidence.get("cleanup", {})
            cleanup_failed = failure_record.get("status") == FAIL
            if not cleanup_failed:
                policy_file.unlink(missing_ok=True)


def dispose_investigation(
    specification_path: Path,
    investigation_id: str,
    root: Path = ROOT,
    runner: Any = subprocess.run,
) -> None:
    """Dispose only resources verified as belonging to this experiment."""
    project = _project_name(investigation_id)

    specification = validate_investigation(specification_path, root)
    compose_file = ensure_inside(
        root,
        root / specification["apparatus"]["compose_file"],
        "Compose definition",
    )

    found = _assert_project_owned(
        project,
        investigation_id,
        runner,
        root,
    )
    if not found:
        return

    runtime_dir = root / RUNTIME_DIR
    runtime_dir.mkdir(parents=True, exist_ok=True)

    boundary_dir = root / NETWORK_BOUNDARY_DIR
    policy_file = boundary_dir / f"{project}-network-policy.json"
    temporary_policy_file = not policy_file.is_file()
    runtime_file: Path | None = None

    try:
        effective = _owned_compose_document(
            compose_file,
            investigation_id,
        )

        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            suffix=".yaml",
            prefix=f"{project}-",
            dir=runtime_dir,
            delete=False,
        ) as stream:
            runtime_file = Path(stream.name)
            yaml.safe_dump(effective, stream, sort_keys=False)

        if temporary_policy_file:
            network_settings = specification["apparatus"].get(
                "network_policy",
                {},
            )
            policy = resolve_network_policy(
                root,
                network_settings.get("profile"),
                network_settings.get("overrides"),
            )
            _write_json(policy_file, policy)

        try:
            _run_compose_action(
                "stop",
                project,
                runtime_file,
                root,
                runner,
            )
        except LabError as exc:
            raise LabError(
                f"disposal refused: could not stop owned experiment workloads: {exc}"
            ) from exc

        removal = _run_boundary(
            "remove",
            project,
            policy_file,
            runner,
            root,
        )
        if removal["status"] != PASS:
            _record_boundary_failure(
                root,
                project,
                removal.get("reason") or "network boundary removal failed",
                stage="disposal_boundary_removal",
                status=FAIL,
            )
            raise LabError(
                "disposal refused: network boundary removal did not pass: "
                f"{removal.get('reason') or removal['status']}"
            )

        try:
            _run_compose_action(
                "down",
                project,
                runtime_file,
                root,
                runner,
            )
        except LabError as exc:
            raise LabError(
                f"disposal failed after boundary removal: {exc}"
            ) from exc

        policy_file.unlink(missing_ok=True)

        try:
            release_experiment(investigation_id, root)
        except LabError:
            _record_boundary_failure(
                root,
                project,
                "experiment disposed but runtime admission could not be released",
                stage="runtime_release",
                status=ERROR,
            )
            raise

    except LabError as exc:
        _record_boundary_failure(
            root,
            project,
            str(exc),
            stage="disposal",
            status=FAIL,
        )
        raise

    finally:
        if runtime_file is not None:
            runtime_file.unlink(missing_ok=True)

        if temporary_policy_file:
            policy_file.unlink(missing_ok=True)


__all__ = [
    "build_construction_plan",
    "construct_investigation",
    "dispose_investigation",
    "resolve_resources",
    "validate_investigation",
    "write_plan",
]