"""Researcher-defined apparatus construction and runtime admission.

Lifecycle:
    1. Validate the investigation and resolve its policy.
    2. Prepare bounded resources without starting workloads.
    3. Apply the network boundary policy.
    4. Verify enforcement and require independent acceptance evidence.
    5. Admit the investigation through the runtime.
    6. Start workloads only after every mandatory gate passes.

Policy definition, enforcement, and acceptance evidence are deliberately
represented as separate things. This module never creates a passing
acceptance record on behalf of the tests that must produce that evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .foundation import LabError, _memory_limit_mib, require_integer
from .networks import (
    policy_json,
    resolve_network_policy,
    validate_network_setup,
    validate_runtime_support,
)
from .runtime import (
    admit_experiment,
    release_experiment,
    runtime_status,
    _network_readiness,
)


INVESTIGATION_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
PROJECT_PREFIX = "sec-lab-i-"

POLICY_DIRECTORY = Path("state/network-boundary")
PLAN_DIRECTORY = Path("state/construction")

ALLOWED_BACKENDS = {"docker.compose"}
ALLOWED_OPERATIONS = {
    "construct",
    "run_service",
    "collect_logs",
    "stop",
    "destroy",
}
REQUIRED_INVESTIGATION_KEYS = {
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
}


def validate_compose_document(
    document: Any,
    definition: dict[str, Any],
) -> dict[str, Any]:
    """Reject Compose features that can escape the disposable lab."""
    if not isinstance(document, dict):
        raise LabError("Compose definition must be a mapping")

    allowed_top = {"services", "networks", "version", "name"}
    unknown_top = set(document) - allowed_top
    if unknown_top:
        raise LabError(
            "Compose top-level keys are not permitted: "
            + ", ".join(sorted(unknown_top))
        )

    services = document.get("services")
    networks = document.get("networks")
    if not isinstance(services, dict) or not services:
        raise LabError("Compose definition must declare services")
    if not isinstance(networks, dict) or not networks:
        raise LabError("Compose definition must declare networks")

    apparatus = definition.get("apparatus", {})
    network = apparatus.get("network", {}) if isinstance(apparatus, dict) else {}
    logical = (
        network.get("logical_name", "lab")
        if isinstance(network, dict)
        else "lab"
    )
    declared = networks.get(logical)
    if not isinstance(declared, dict):
        raise LabError(f"Compose network {logical} must be a mapping")
    if declared.get("internal") is not True or declared.get("external") is True:
        raise LabError(f"Compose network {logical} must be internal and non-external")
    if declared.get("driver", "bridge") != "bridge":
        raise LabError(f"Compose network {logical} must use the bridge driver")
    allowed_network_keys = {"internal", "enable_ipv6", "labels", "driver"}
    unknown_network_keys = set(declared) - allowed_network_keys
    if unknown_network_keys:
        raise LabError(
            f"Compose network {logical} has unsupported options: "
            + ", ".join(sorted(unknown_network_keys))
        )
    if set(networks) != {logical}:
        raise LabError("Compose must declare only the investigation internal network")
    if declared.get("name") or declared.get("external") or declared.get("attachable") is True:
        raise LabError(
            f"Compose network {logical}: custom/external network control is forbidden"
        )

    policy = definition.get("network_policy", {})
    boundaries = policy.get("boundaries", {}) if isinstance(policy, dict) else {}
    ipv6_policy = boundaries.get("ipv6", {}) if isinstance(boundaries, dict) else {}
    if (
        declared.get("enable_ipv6") is True
        and ipv6_policy.get("mode", "deny") == "deny"
    ):
        raise LabError(
            f"Compose network {logical}: enable_ipv6 conflicts with the selected deny policy"
        )

    forbidden = {
        "build", "volumes", "volumes_from", "ports", "network_mode",
        "privileged", "cap_add", "devices", "device_cgroup_rules", "pid",
        "ipc", "uts", "cgroup", "cgroup_parent", "userns_mode", "runtime",
        "sysctls", "extra_hosts", "host_ipc", "host_pid", "secrets",
        "configs", "env_file", "credential_spec", "external_links", "links",
        "mac_address", "use_api_socket", "provider", "develop", "extends",
        "post_start", "pre_stop", "container_name", "group_add",
    }
    proxy_keys = {
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
    }
    for name, service in services.items():
        if not isinstance(service, dict):
            raise LabError(f"Compose service {name} must be a mapping")
        present = forbidden.intersection(service)
        if present:
            raise LabError(
                f"{name}: forbidden Compose options: "
                + ", ".join(sorted(present))
            )

        dns_policy = boundaries.get("dns", {}) if isinstance(boundaries, dict) else {}
        proxy_policy = boundaries.get("proxies", {}) if isinstance(boundaries, dict) else {}
        if (
            dns_policy.get("mode") == "deny"
            and any(key in service for key in ("dns", "dns_search", "dns_opt"))
        ):
            raise LabError(
                f"{name}: DNS configuration conflicts with the selected deny policy"
            )

        environment = service.get("environment", {})
        if isinstance(environment, dict):
            environment_keys = set(environment)
        elif isinstance(environment, list) and all(
            isinstance(item, str) for item in environment
        ):
            environment_keys = {
                item.split("=", 1)[0] for item in environment
            }
        elif "environment" in service:
            raise LabError(f"{name}.environment must be a mapping or list of strings")
        else:
            environment_keys = set()
        if proxy_policy.get("mode") == "deny" and proxy_keys.intersection(environment_keys):
            raise LabError(
                f"{name}: proxy environment conflicts with the selected deny policy"
            )

        image = service.get("image")
        if not isinstance(image, str) or not image.strip():
            raise LabError(
                f"{name}: an explicit pre-acquired image is required; build is forbidden"
            )
        if service.get("pull_policy") not in (None, "never"):
            raise LabError(f"{name}: pull_policy must be absent or 'never'")
        cap_drop = service.get("cap_drop", [])
        if not isinstance(cap_drop, list) or "ALL" not in cap_drop:
            raise LabError(f"{name}: cap_drop must be a list containing ALL")
        security_opt = service.get("security_opt", [])
        if (
            not isinstance(security_opt, list)
            or "no-new-privileges:true" not in security_opt
        ):
            raise LabError(f"{name}: no-new-privileges is required")
        if any(
            "unconfined" in str(option).lower()
            or "label=disable" in str(option).lower()
            for option in security_opt
        ):
            raise LabError(f"{name}: unconfined security profiles are forbidden")
        user = service.get("user")
        if service.get("read_only") is not True or user in (None, "root", 0):
            raise LabError(
                f"{name}: read-only root and explicit non-root user are required"
            )
        if isinstance(user, str) and re.match(r"^(?:0|root)(?::0)?$", user.strip()):
            raise LabError(f"{name}: root execution is forbidden")
        _memory_limit_mib(service.get("mem_limit"), f"{name}.mem_limit")
        require_integer(service.get("pids_limit"), f"{name}.pids_limit", 1)
        cpus = service.get("cpus")
        if type(cpus) not in (int, float) or cpus <= 0:
            raise LabError(f"{name}.cpus must be a positive CPU limit")
        if service.get("deploy") is not None:
            raise LabError(
                f"{name}: deploy overrides are not permitted; "
                "use explicit bounded service limits"
            )
        if service.get("restart") not in (None, "no"):
            raise LabError(f"{name}: automatic restart policies are forbidden")

        attachments = service.get("networks", [])
        if not isinstance(attachments, (list, dict)):
            raise LabError(f"{name}.networks must be a list or mapping")
        if set(attachments) != {logical}:
            raise LabError(
                f"{name}: service must attach only to the declared internal network"
            )
        if service.get("tmpfs"):
            entries = service["tmpfs"]
            if isinstance(entries, str):
                values = [entries]
            elif isinstance(entries, list):
                values = entries
            else:
                raise LabError(f"{name}.tmpfs must be a string or list")
            for entry in values:
                text = str(entry)
                if not re.search(
                    r"(?:^|[:;,])size=[1-9][0-9]*[kKmMgG]?(?:[,;]|$)",
                    text,
                ):
                    raise LabError(
                        f"{name}: each tmpfs mount must have an explicit size limit"
                    )

    return document


__all__ = ["validate_compose_document"]

# These are the boundary dimensions understood by the policy system.
# They are not a claim that every host/runtime adapter can enforce every
# dimension. validate_runtime_support() is authoritative for that decision.
REQUIRED_BOUNDARIES = {
    "lab_ingress",
    "lab_egress",
    "windows_host",
    "external_networks",
    "dns",
    "proxies",
    "ipv4",
    "ipv6",
    "docker_networks",
    "filesystem",
    "capture",
    "resource_access",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_yaml(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except OSError as exc:
        raise LabError(f"Cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise LabError(f"Invalid YAML in {path}: {exc}") from exc


def _write_json(path: Path, value: Any) -> None:
    """Write JSON atomically, without leaving a partial policy or plan."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise LabError(f"Cannot write {path}: {exc}") from exc


def _policy_identity(policy: dict[str, Any]) -> str:
    """Stable identity for the resolved policy definition."""
    return hashlib.sha256(policy_json(policy).encode("utf-8")).hexdigest()


def _project_name(investigation_id: str) -> str:
    if not isinstance(investigation_id, str) or not INVESTIGATION_ID_RE.fullmatch(
        investigation_id
    ):
        raise LabError(
            "investigation_id must be 1–32 lowercase letters, digits, or hyphens "
            "and must start with a letter or digit"
        )
    return f"{PROJECT_PREFIX}{investigation_id}"


def _load_mapping(path: Path, label: str) -> dict[str, Any]:
    value = _read_yaml(path)
    if not isinstance(value, dict):
        raise LabError(f"{label} must be a YAML mapping: {path}")
    return value


def _inside_root(path: Path, root: Path, label: str) -> Path:
    """Resolve a researcher-supplied path and prevent path traversal."""
    try:
        resolved_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise LabError(f"{label} must resolve to an existing path inside {root}") from exc
    return resolved


def _load_investigation(path: Path, root: Path) -> tuple[dict[str, Any], Path]:
    root = root.resolve()
    path = path if path.is_absolute() else root / path
    resolved_path = _inside_root(path, root, "Investigation definition")
    definition = _load_mapping(resolved_path, "Investigation definition")

    missing = REQUIRED_INVESTIGATION_KEYS - set(definition)
    if missing:
        raise LabError(
            "Investigation definition is missing required keys: "
            + ", ".join(sorted(missing))
        )

    unknown = set(definition) - REQUIRED_INVESTIGATION_KEYS
    if unknown:
        raise LabError(
            "Unsupported investigation keys: " + ", ".join(sorted(unknown))
        )

    if definition.get("schema_version") != 1:
        raise LabError("Only investigation schema_version 1 is supported")

    investigation = definition.get("investigation")
    if not isinstance(investigation, dict):
        raise LabError("investigation must be a mapping")

    backend = investigation.get("backend")
    if backend not in ALLOWED_BACKENDS:
        raise LabError(
            f"Unsupported investigation backend {backend!r}; "
            f"allowed: {', '.join(sorted(ALLOWED_BACKENDS))}"
        )

    apparatus = definition.get("apparatus")
    if not isinstance(apparatus, dict):
        raise LabError("apparatus must be a mapping")

    if apparatus.get("backend", backend) != "docker.compose":
        raise LabError("apparatus.backend must be docker.compose")

    compose_relative = apparatus.get("compose_file")
    if not isinstance(compose_relative, str) or not compose_relative.strip():
        raise LabError("apparatus.compose_file must be a non-empty path")

    compose_path = Path(compose_relative)
    if not compose_path.is_absolute():
        compose_path = resolved_path.parent / compose_path
    compose_path = _inside_root(compose_path, root, "Compose file")

    for key in ("resources", "procedure", "observations", "evaluation", "evidence", "safety"):
        if not isinstance(definition.get(key), (dict, list)):
            raise LabError(f"{key} must be a mapping or list")

    if not isinstance(definition.get("resource_budget"), dict):
        raise LabError("resource_budget must be a mapping")

    return definition, compose_path


def validate_investigation(
    path: str | Path,
    root: str | Path,
) -> dict[str, Any]:
    """Validate the investigation document, policy, Compose apparatus, and budget."""
    root_path = Path(root).resolve()
    definition, compose_path = _load_investigation(Path(path), root_path)

    apparatus = definition["apparatus"]
    network = apparatus.get("network", {})
    if not isinstance(network, dict):
        raise LabError("apparatus.network must be a mapping")

    policy_spec = apparatus.get("network_policy", {})
    if not isinstance(policy_spec, dict):
        raise LabError("apparatus.network_policy must be a mapping")

    unknown_policy_keys = set(policy_spec) - {"profile", "overrides"}
    if unknown_policy_keys:
        raise LabError(
            "Unsupported apparatus.network_policy keys: "
            + ", ".join(sorted(unknown_policy_keys))
        )

    profile = policy_spec.get("profile")
    overrides = policy_spec.get("overrides")
    if overrides is not None and not isinstance(overrides, dict):
        raise LabError("apparatus.network_policy.overrides must be a mapping")

    policy = resolve_network_policy(
        root_path,
        profile=profile,
        overrides=overrides,
    )

    boundaries = policy.get("boundaries")
    if not isinstance(boundaries, dict):
        raise LabError("Resolved network policy must contain a boundaries mapping")

    missing_boundaries = REQUIRED_BOUNDARIES - set(boundaries)
    if missing_boundaries:
        raise LabError(
            "Resolved policy is missing required boundary definitions: "
            + ", ".join(sorted(missing_boundaries))
        )

    # Reject malformed definitions here. Actual support and enforcement are
    # checked separately before the runtime is admitted or workloads are started.
    for boundary_name, boundary in boundaries.items():
        if not isinstance(boundary, dict):
            raise LabError(f"Policy boundary {boundary_name!r} must be a mapping")
        mode = boundary.get("mode")
        if not isinstance(mode, str) or not mode.strip():
            raise LabError(f"Policy boundary {boundary_name!r} needs an explicit mode")

    compose_document = _read_yaml(compose_path)
    if not isinstance(compose_document, dict):
        raise LabError("Compose definition must be a mapping")

    # The validator rejects alternate networks, host networking, published
    # ports, host mounts, unexpected interfaces, prohibited options, and
    # unapproved DNS/proxy overrides. It also enforces service hardening and
    # explicit bounded resource limits.
    definition_for_validation = dict(definition)
    definition_for_validation["network_policy"] = policy
    validate_compose_document(compose_document, definition_for_validation)

    resources = definition.get("resources")
    if not isinstance(resources, dict):
        raise LabError("resources must be a mapping")

    budget = definition["resource_budget"]
    for key in ("memory_mib", "cpu_millicores", "pids"):
        value = budget.get(key)
        if type(value) is not int or value < 0:
            raise LabError(f"resource_budget.{key} must be a non-negative integer")

    # The capability catalog is part of the lab's declared resource contract.
    capability_path = root_path / "lab" / "catalog" / "capabilities.yaml"
    capabilities = _load_mapping(capability_path, "Capability catalog")
    available = capabilities.get("resources", capabilities.get("capabilities", {}))
    if not isinstance(available, dict):
        raise LabError("Capability catalog must define a resources/capabilities mapping")

    requested_kinds = resources.get("kinds", [])
    if not isinstance(requested_kinds, list) or any(
        not isinstance(item, str) or not item.strip() for item in requested_kinds
    ):
        raise LabError("resources.kinds must be a list of non-empty strings")

    for kind in requested_kinds:
        entry = available.get(kind)
        if not isinstance(entry, dict):
            raise LabError(f"Requested resource kind is not catalogued: {kind}")
        if entry.get("available") is not True:
            raise LabError(f"Requested resource kind is not available: {kind}")

    procedure = definition["procedure"]
    operations = procedure if isinstance(procedure, list) else procedure.get("steps", [])
    if not isinstance(operations, list):
        raise LabError("procedure.steps must be a list")

    for index, operation in enumerate(operations):
        if not isinstance(operation, dict):
            raise LabError(f"procedure step {index} must be a mapping")
        name = operation.get("operation")
        if name not in ALLOWED_OPERATIONS:
            raise LabError(
                f"procedure step {index} has unsupported operation {name!r}"
            )

    # Sensitive host-control fields are not part of the researcher interface.
    serialized = json.dumps(definition, sort_keys=True).lower()
    prohibited_tokens = (
        "sudo_password",
        "host_firewall_command",
        "windows_firewall_command",
        "host_network_namespace",
        "docker_socket",
        "privileged_host",
    )
    for token in prohibited_tokens:
        if token in serialized:
            raise LabError(f"Investigation definition contains prohibited field: {token}")

    return {
        "definition": definition,
        "definition_path": str(Path(path).resolve()),
        "compose_path": str(compose_path),
        "policy": policy,
        "policy_identity": _policy_identity(policy),
        "resources": resources,
        "resource_budget": budget,
    }


def resolve_resources(
    definition: dict[str, Any],
    root: str | Path,
) -> dict[str, Any]:
    """Resolve the requested resource kinds against the local capability catalog."""
    root_path = Path(root).resolve()
    catalog_path = root_path / "lab" / "catalog" / "capabilities.yaml"
    catalog = _load_mapping(catalog_path, "Capability catalog")
    available = catalog.get("resources", catalog.get("capabilities", {}))
    if not isinstance(available, dict):
        raise LabError("Capability catalog must define a resources/capabilities mapping")

    requested = definition.get("resources", {})
    if not isinstance(requested, dict):
        raise LabError("resources must be a mapping")

    kinds = requested.get("kinds", [])
    if not isinstance(kinds, list):
        raise LabError("resources.kinds must be a list")

    resolved: dict[str, Any] = {}
    for kind in kinds:
        entry = available.get(kind)
        if not isinstance(entry, dict) or entry.get("available") is not True:
            raise LabError(f"Resource unavailable or unrecognised: {kind}")
        resolved[kind] = entry

    return resolved


def _policy_layers(
    policy: dict[str, Any],
    *,
    enforcement_state: str,
    acceptance_state: str,
    reason: str | None = None,
) -> dict[str, Any]:
    """Report definition, enforcement, and evidence without conflating them."""
    result: dict[str, Any] = {
        "policy_identity": _policy_identity(policy),
        "policy_definition": {},
        "enforcement": {
            "state": enforcement_state,
            "reason": reason,
        },
        "acceptance_evidence": {
            "state": acceptance_state,
            "source": "independent network-boundary acceptance record",
        },
    }

    for name, definition in sorted(policy.get("boundaries", {}).items()):
        result["policy_definition"][name] = {
            "mode": definition.get("mode"),
            "definition_state": "VALIDATED",
            # Do not infer per-boundary behavior from a policy file or a
            # policy-wide verifier result. Only granular test results can do so.
            "enforcement_state": enforcement_state,
            "acceptance_state": acceptance_state,
        }

    return result


def build_construction_plan(
    path: str | Path,
    investigation_id: str,
    root: str | Path,
) -> dict[str, Any]:
    """Build a plan only; this function does not create or start workloads."""
    project = _project_name(investigation_id)
    validated = validate_investigation(path, root)
    resources = resolve_resources(validated["definition"], root)

    policy = validated["policy"]
    try:
        support = validate_runtime_support(policy)
    except Exception as exc:
        layers = _policy_layers(
            policy,
            enforcement_state="UNSUPPORTED",
            acceptance_state="NOT_TESTED",
            reason=str(exc),
        )
        raise LabError(
            "Fail-closed: the selected policy cannot be enforced by this runtime. "
            + json.dumps(layers, sort_keys=True)
        ) from exc

    plan = {
        "schema_version": 1,
        "created_at": _utc_now(),
        "investigation_id": investigation_id,
        "project": project,
        "definition_path": validated["definition_path"],
        "compose_path": validated["compose_path"],
        "policy": policy,
        "policy_identity": validated["policy_identity"],
        "policy_layers": _policy_layers(
            policy,
            enforcement_state="NOT_APPLIED",
            acceptance_state="NOT_TESTED",
        ),
        "resources": resources,
        "resource_budget": validated["resource_budget"],
        "runtime_support": support,
        "lifecycle": [
            "validate",
            "prepare_resources",
            "apply_policy",
            "verify_enforcement",
            "require_acceptance_evidence",
            "admit_runtime",
            "start_workloads",
        ],
        "workloads_started": False,
    }
    return plan


def write_plan(
    plan: dict[str, Any],
    investigation_id: str,
    root: str | Path,
) -> Path:
    """Persist a construction plan for auditability."""
    _project_name(investigation_id)
    destination = Path(root).resolve() / PLAN_DIRECTORY / f"{investigation_id}.json"
    _write_json(destination, plan)
    return destination


def _runtime_gate_enabled(root: Path) -> bool:
    """Require explicit opt-in in both lab.env and the current process."""
    env_path = root / "config" / "lab.env"
    if not env_path.is_file():
        return False

    configured = False
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == "REQUIRE_RUNTIME_APPROVAL":
            configured = value.strip().strip("'\"").lower() == "true"

    return configured and os.environ.get("REQUIRE_RUNTIME_APPROVAL", "").lower() == "true"


def _run(
    command: list[str],
    *,
    root: Path,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=root,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LabError(f"Command could not be completed: {command[0]}: {exc}") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise LabError(
            f"Command failed ({result.returncode}): {' '.join(command)}"
            + (f"\n{detail}" if detail else "")
        )
    return result


def _docker_json(command: list[str], root: Path) -> Any:
    result = _run(command, root=root)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise LabError(f"Docker returned invalid JSON for: {' '.join(command)}") from exc


def _assert_project_absent(project: str, root: Path) -> None:
    """Do not adopt or overwrite pre-existing project containers or networks."""
    containers = _docker_json(
        ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{json .}}"],
        root,
    )
    if isinstance(containers, list) and containers:
        raise LabError(f"Refusing to reuse existing containers for project {project}")

    networks = _docker_json(
        ["docker", "network", "ls", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{json .}}"],
        root,
    )
    if isinstance(networks, list) and networks:
        raise LabError(f"Refusing to reuse existing networks for project {project}")

    # Docker's --format output may be newline-delimited JSON objects, depending
    # on version. Use a separate ID query as the authoritative existence check.
    for kind in ("container", "network"):
        result = _run(
            [
                "docker",
                kind,
                "ls",
                "-a",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--quiet",
            ],
            root=root,
        )
        if result.stdout.strip():
            raise LabError(f"Refusing to reuse existing {kind}s for project {project}")


def _owned_compose_document(
    compose_file: Path,
    investigation_id: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Add mandatory ownership labels to an already validated Compose document."""
    document = _read_yaml(compose_file)
    if not isinstance(document, dict):
        raise LabError("Compose definition must be a mapping")

    services = document.get("services")
    networks = document.get("networks")
    if not isinstance(services, dict) or not isinstance(networks, dict):
        raise LabError("Compose definition must declare services and networks")

    owner_label = "io.ithoka.security-lab.owner"
    investigation_label = "io.ithoka.security-lab.investigation"
    policy_label = "io.ithoka.security-lab.policy-identity"
    mandatory = {
        owner_label: "security-lab",
        investigation_label: investigation_id,
        policy_label: _policy_identity(policy),
    }

    for name, service in services.items():
        if not isinstance(service, dict):
            raise LabError(f"Compose service {name} must be a mapping")
        labels = service.get("labels", {})
        if isinstance(labels, list):
            converted: dict[str, str] = {}
            for item in labels:
                if not isinstance(item, str) or "=" not in item:
                    raise LabError(f"{name}.labels entries must be KEY=VALUE strings")
                key, value = item.split("=", 1)
                converted[key] = value
            labels = converted
        if not isinstance(labels, dict):
            raise LabError(f"{name}.labels must be a mapping or KEY=VALUE list")
        labels = dict(labels)
        for key, value in mandatory.items():
            if key in labels and str(labels[key]) != value:
                raise LabError(f"{name}: conflicting mandatory ownership label {key}")
            labels[key] = value
        service["labels"] = labels

    for name, network in networks.items():
        if not isinstance(network, dict):
            raise LabError(f"Compose network {name} must be a mapping")
        labels = network.get("labels", {})
        if isinstance(labels, list):
            converted = {}
            for item in labels:
                if not isinstance(item, str) or "=" not in item:
                    raise LabError(f"{name}.labels entries must be KEY=VALUE strings")
                key, value = item.split("=", 1)
                converted[key] = value
            labels = converted
        if not isinstance(labels, dict):
            raise LabError(f"{name}.labels must be a mapping or KEY=VALUE list")
        labels = dict(labels)
        for key, value in mandatory.items():
            if key in labels and str(labels[key]) != value:
                raise LabError(f"{name}: conflicting mandatory ownership label {key}")
            labels[key] = value
        network["labels"] = labels

    return document


def _run_boundary(
    action: str,
    project: str,
    policy_path: Path,
    root: Path,
) -> subprocess.CompletedProcess[str]:
    from .osapi.actions import OSActionStatus, execute_network_boundary_action

    if action not in {"apply", "verify", "remove"}:
        raise LabError(f"Unsupported network boundary action: {action}")
    result = execute_network_boundary_action(
        action,
        project,
        policy_path,
        root,
    )
    completed = subprocess.CompletedProcess(
        args=(
            [result.native_executable, *result.arguments]
            if result.native_executable
            else []
        ),
        returncode=result.returncode if result.returncode is not None else 1,
        stdout=result.stdout,
        stderr=result.stderr or (result.reason or ""),
    )
    completed.os_action = result.to_dict()
    if result.status is not OSActionStatus.SUCCEEDED:
        raise LabError(
            f"network-boundary {action} did not pass: "
            f"{result.reason or result.status.value}"
        )
    return completed


def _record_boundary_failure(
    project: str,
    reason: str,
    root: Path,
) -> None:
    """Record a failure as a failure, never as acceptance evidence."""
    destination = root / POLICY_DIRECTORY / f"{project}-construction-failure.json"
    _write_json(
        destination,
        {
            "project": project,
            "recorded_at": _utc_now(),
            "state": "FAILED_CLOSED",
            "reason": reason,
        },
    )


def _require_acceptance(
    root: Path,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Ask the runtime's verifier to validate pinned policy and live evidence."""
    readiness = _network_readiness(root, policy)
    if not isinstance(readiness, dict):
        raise LabError("Runtime returned an invalid network-readiness result")

    if readiness.get("controls_applied") is not True:
        raise LabError(
            "Fail-closed: the runtime has not verified that mandatory controls are applied"
        )
    if readiness.get("effective_behavior") != "passed":
        raise LabError(
            "Fail-closed: effective network behavior has not passed acceptance tests"
        )
    if readiness.get("runtime_acceptance") != "passed":
        raise LabError(
            "Fail-closed: runtime acceptance evidence is missing or has not passed"
        )
    return readiness


def _assert_runtime_policy_match(
    policy: dict[str, Any],
    profile: str | None,
    root: Path,
) -> None:
    """Prevent runtime admission under a different policy than the apparatus uses."""
    runtime_policy = resolve_network_policy(root, profile=profile)
    if policy_json(runtime_policy) != policy_json(policy):
        raise LabError(
            "Fail-closed: the investigation policy differs from the runtime admission "
            "profile. Runtime admission does not accept arbitrary policy overrides; "
            "select a matching approved profile before constructing this apparatus."
        )


def construct_investigation(
    path: str | Path,
    investigation_id: str,
    root: str | Path,
    *,
    authorization_rationale: str,
    runner: Any = None,
) -> dict[str, Any]:
    """Prepare, enforce, verify, admit, then start one investigation."""
    del runner  # Retained for API compatibility; commands use the controlled runner.
    root_path = Path(root).resolve()
    project = _project_name(investigation_id)

    if not isinstance(authorization_rationale, str) or not authorization_rationale.strip():
        raise LabError("A non-empty authorization_rationale is required")

    if not _runtime_gate_enabled(root_path):
        raise LabError(
            "Runtime approval is disabled. REQUIRE_RUNTIME_APPROVAL=true must be "
            "set in config/lab.env and in the current process."
        )

    # Stage 1: validate and resolve definitions; no workload is started.
    plan = build_construction_plan(path, investigation_id, root_path)
    validated = validate_investigation(path, root_path)
    definition = validated["definition"]
    policy = validated["policy"]
    compose_path = Path(validated["compose_path"])

    # Check the lab's setup declarations, but do not interpret a valid setup file
    # as proof that controls are enforced.
    validate_network_setup(root_path)
    validate_runtime_support(policy)

    status = runtime_status(root_path)
    if not isinstance(status, dict) or status.get("state") != "RUNNING":
        raise LabError("Fail-closed: runtime must be RUNNING before construction")

    policy_directory = root_path / POLICY_DIRECTORY
    policy_directory.mkdir(parents=True, exist_ok=True)
    policy_path = policy_directory / f"{project}-network-policy.json"

    # The runtime reads this exact policy directory. Pin the fully resolved policy
    # before preparing the apparatus so that apply/verify/acceptance share identity.
    _write_json(policy_path, policy)

    temp_path: Path | None = None
    admitted = False
    workloads_started = False
    boundary_attempted = False
    compose_created = False

    try:
        _assert_project_absent(project, root_path)

        # Validate again after resolution and before passing the generated file to
        # Compose. The source file remains unchanged.
        document = _owned_compose_document(compose_path, investigation_id, policy)
        definition_for_validation = dict(definition)
        definition_for_validation["network_policy"] = policy
        validate_compose_document(document, definition_for_validation)

        # No image pulls or builds are allowed during construction.
        for service_name, service in document["services"].items():
            image = service.get("image")
            if not isinstance(image, str) or not image.strip():
                raise LabError(f"{service_name}: an explicit local image is required")
            _run(["docker", "image", "inspect", image], root=root_path)

        # Stage 2: prepare resources without starting workloads.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".compose.yaml",
            prefix=f"{project}-",
            dir=root_path,
            delete=False,
        ) as handle:
            yaml.safe_dump(document, handle, sort_keys=False)
            temp_path = Path(handle.name)

        _run(
            [
                "docker",
                "compose",
                "--project-name",
                project,
                "-f",
                str(temp_path),
                "create",
                "--no-build",
                "--pull",
                "never",
            ],
            root=root_path,
            timeout=240,
        )
        compose_created = True

        # Stage 3: apply the policy. A failed apply blocks every later stage.
        boundary_attempted = True
        _run_boundary("apply", project, policy_path, root_path)

        # Stage 4: verify the enforcement controller, then require independent,
        # identity-matched effective-behavior and runtime-acceptance evidence.
        _run_boundary("verify", project, policy_path, root_path)
        readiness = _require_acceptance(root_path, policy)

        # The runtime's admission API accepts a profile, not arbitrary overrides.
        # Refuse admission unless its profile resolves to exactly the same policy.
        policy_spec = definition.get("apparatus", {}).get("network_policy", {})
        profile = policy_spec.get("profile") if isinstance(policy_spec, dict) else None
        _assert_runtime_policy_match(policy, profile, root_path)

        # Stage 5: reserve runtime resources only after enforcement and acceptance.
        budget = definition.get("resource_budget", {})
        admit_experiment(
            investigation_id,
            profile=profile,
            root=root_path,
            memory_mib=budget.get("memory_mib", 0),
            cpu_millicores=budget.get("cpu_millicores", 0),
            pids=budget.get("pids", 0),
        )
        admitted = True

        # Recheck immediately before start. This narrows the gap between acceptance
        # and workload start and ensures a missing/changed evidence record blocks start.
        _run_boundary("verify", project, policy_path, root_path)
        readiness = _require_acceptance(root_path, policy)

        # Stage 6: this is the first operation that starts the researcher workload.
        _run(
            [
                "docker",
                "compose",
                "--project-name",
                project,
                "-f",
                str(temp_path),
                "start",
            ],
            root=root_path,
            timeout=180,
        )
        workloads_started = True

        plan["state"] = "constructed"
        plan["constructed_at"] = _utc_now()
        plan["authorization_rationale"] = authorization_rationale.strip()
        plan["runtime_admitted"] = True
        plan["workloads_started"] = True
        plan["network_readiness"] = readiness
        plan["policy_layers"] = _policy_layers(
            policy,
            enforcement_state="VERIFIED_BY_CONTROLLER",
            acceptance_state="POLICY_WIDE_ACCEPTANCE_PASSED",
        )
        plan["policy_layers"]["note"] = (
            "Policy-wide acceptance is not per-boundary proof. Individual boundary "
            "acceptance remains NOT_TESTED unless the acceptance artifact supplies "
            "explicit, identity-matched results for each boundary."
        )
        plan["policy_path"] = str(policy_path)
        plan["policy_identity"] = _policy_identity(policy)
        write_plan(plan, investigation_id, root_path)
        return plan

    except Exception as exc:
        # Fail closed: do not leave a running workload after a mandatory gate fails.
        cleanup_errors: list[str] = []

        if workloads_started or compose_created:
            try:
                if temp_path is not None and temp_path.exists():
                    _run(
                        [
                            "docker",
                            "compose",
                            "--project-name",
                            project,
                            "-f",
                            str(temp_path),
                            "stop",
                        ],
                        root=root_path,
                        timeout=120,
                    )
            except Exception as cleanup_exc:
                cleanup_errors.append(f"stop: {cleanup_exc}")

        if boundary_attempted:
            try:
                _run_boundary("remove", project, policy_path, root_path)
            except Exception as cleanup_exc:
                cleanup_errors.append(f"boundary removal: {cleanup_exc}")

        if compose_created and temp_path is not None and temp_path.exists():
            try:
                _run(
                    [
                        "docker",
                        "compose",
                        "--project-name",
                        project,
                        "-f",
                        str(temp_path),
                        "down",
                        "--remove-orphans",
                    ],
                    root=root_path,
                    timeout=180,
                )
            except Exception as cleanup_exc:
                cleanup_errors.append(f"compose cleanup: {cleanup_exc}")

        if admitted:
            try:
                release_experiment(investigation_id, root=root_path)
            except Exception as cleanup_exc:
                cleanup_errors.append(f"runtime release: {cleanup_exc}")

        reason = str(exc)
        if cleanup_errors:
            reason += " | Cleanup failures: " + "; ".join(cleanup_errors)

        try:
            _record_boundary_failure(project, reason, root_path)
        except Exception:
            # The original failure remains authoritative; do not replace it with
            # a secondary audit-write failure.
            pass

        raise LabError(
            f"Investigation construction failed closed: {reason}"
        ) from exc

    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def dispose_investigation(
    path: str | Path,
    investigation_id: str,
    root: str | Path,
) -> dict[str, Any]:
    """Stop and remove only a correctly labelled investigation owned by this lab."""
    root_path = Path(root).resolve()
    project = _project_name(investigation_id)
    validated = validate_investigation(path, root_path)
    policy = validated["policy"]
    policy_path = root_path / POLICY_DIRECTORY / f"{project}-network-policy.json"

    if not policy_path.is_file():
        raise LabError(
            f"Cannot safely dispose {project}: its pinned network policy is missing"
        )

    pinned_policy = _read_yaml(policy_path)
    if not isinstance(pinned_policy, dict):
        # The policy is JSON, which is also valid YAML; this checks its structure.
        raise LabError(f"Pinned network policy is invalid: {policy_path}")

    if policy_json(pinned_policy) != policy_json(policy):
        raise LabError(
            "Refusing disposal: supplied investigation policy differs from the "
            "policy pinned to this project"
        )

    # Validate every discovered container/network label before removing resources.
    # Never take ownership of resources solely because their names match.
    from .networks import inspect_owned_network

    inspect_owned_network(project)

    compose_path = Path(validated["compose_path"])
    document = _owned_compose_document(compose_path, investigation_id, policy)
    temp_path: Path | None = None
    errors: list[str] = []

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".compose.yaml",
            prefix=f"{project}-dispose-",
            dir=root_path,
            delete=False,
        ) as handle:
            yaml.safe_dump(document, handle, sort_keys=False)
            temp_path = Path(handle.name)

        try:
            _run_boundary("remove", project, policy_path, root_path)
        except Exception as exc:
            errors.append(f"boundary removal: {exc}")

        try:
            _run(
                [
                    "docker",
                    "compose",
                    "--project-name",
                    project,
                    "-f",
                    str(temp_path),
                    "down",
                    "--remove-orphans",
                ],
                root=root_path,
                timeout=180,
            )
        except Exception as exc:
            errors.append(f"Compose disposal: {exc}")

        try:
            release_experiment(investigation_id, root=root_path)
        except Exception as exc:
            errors.append(f"runtime release: {exc}")

        if errors:
            raise LabError(
                "Disposal incomplete; manual review is required: " + "; ".join(errors)
            )

        # Preserve the pinned policy and acceptance artifacts for audit. They are
        # evidence of what was applied and tested, not temporary scratch files.
        result = {
            "state": "disposed",
            "investigation_id": investigation_id,
            "project": project,
            "disposed_at": _utc_now(),
            "policy_identity": _policy_identity(policy),
            "policy_artifacts_preserved": True,
        }
        _write_json(
            root_path / PLAN_DIRECTORY / f"{investigation_id}-disposal.json",
            result,
        )
        return result

    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


__all__ = [
    "build_construction_plan",
    "construct_investigation",
    "dispose_investigation",
    "resolve_resources",
    "validate_investigation",
    "write_plan",
]