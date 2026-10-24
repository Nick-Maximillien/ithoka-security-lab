#!/usr/bin/env python3
"""Foundation primitives and fail-closed preflight for the constrained lab.

Responsibilities:
- Safe YAML loading and reusable schema/parameter validation.
- Repository path containment and sensitive-field rejection.
- Catalog validation and resource-limit parsing.
- Read-only discovery of host and lab capabilities.
- Pre-activation validation of policy prerequisites and enforcement mappings.
- Separate validation of independently generated acceptance evidence.

This module does not configure host controls, activate policies, or manufacture
acceptance evidence. Enforcement and acceptance are handled by their respective
runtime and network-boundary layers.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
CAPACITY_FILE = ROOT / "config" / "lab-capacity.yaml"
CAPABILITIES_FILE = ROOT / "lab" / "catalog" / "capabilities.yaml"
MATERIALS_FILE = ROOT / "lab" / "catalog" / "materials.yaml"

ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
EXPERIMENT_PATTERN = re.compile(r"^EXP-[0-9]{4}-[a-z0-9-]+$")
REVISION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

SECRET_PATTERN = re.compile(
    r"(?i)(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|token|api[\_-]?key)\s*[:=])"
)

# All policy dimensions known to the current lab architecture.
# This is a list of dimensions, not a claim that the host can enforce them.
POLICY_BOUNDARIES = {
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

# Each boundary must be associated with an actual, named enforcement mechanism
# before a strict profile can be approved for activation. These are semantic
# categories, not claims that a particular binary implements the control.
ENFORCEMENT_CONTROL_TYPES = {
    "firewall",
    "host_firewall",
    "docker_network",
    "dns_control",
    "proxy_control",
    "address_family_control",
    "filesystem_control",
    "packet_capture",
    "resource_limits",
    "host_access_control",
}

# Tools are recorded as observations only. Tool presence does not prove that a
# policy has been installed, that a rule is effective, or that a bypass is absent.
TOOL_NAMES = (
    "docker",
    "docker-compose",
    "wsl",
    "bash",
    "ip",
    "iptables",
    "ip6tables",
    "nft",
    "ufw",
    "firewall-cmd",
    "powershell",
    "pwsh",
    "tcpdump",
    "tshark",
    "wireshark",
    "curl",
    "python",
    "python3",
)

# Mapping from a policy boundary to capability observations relevant to it.
# "observed" means the host has a possible supporting tool or API; the network
# adapter must still verify whether that mechanism is usable and effective.
BOUNDARY_CAPABILITY_HINTS = {
    "lab_ingress": ("linux_firewall_tool", "docker_available"),
    "lab_egress": ("linux_firewall_tool", "docker_available"),
    "windows_host": ("windows_host_firewall_api",),
    "external_networks": ("linux_firewall_tool", "docker_available"),
    "dns": ("dns_enforcement_adapter",),
    "proxies": ("proxy_enforcement_adapter",),
    "ipv4": ("ipv4_firewall_tool",),
    "ipv6": ("ipv6_firewall_tool",),
    "docker_networks": ("docker_available",),
    "filesystem": ("docker_available",),
    "capture": ("packet_capture_tool",),
    "resource_access": ("docker_available",),
}


class LabError(Exception):
    """An expected validation, policy, or lifecycle error."""


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise LabError("YAML mapping keys must be hashable") from exc

        if duplicate:
            raise LabError(f"duplicate YAML key: {key}")

        mapping[key] = loader.construct_object(value_node, deep=deep)

    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def utc_now() -> str:
    """Return an offset-aware UTC timestamp."""
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    """Return a SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def sha256_json(value: Any) -> str:
    """Return a stable SHA-256 digest for JSON-compatible data."""
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LabError(f"value cannot be represented as stable JSON: {exc}") from exc

    return sha256_bytes(encoded)


def load_yaml(path: Path) -> Any:
    """Load YAML with duplicate-key rejection and safe constructors."""
    try:
        with path.open("r", encoding="utf-8") as stream:
            return yaml.load(stream, Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError, LabError) as exc:
        raise LabError(f"cannot read YAML {path}: {exc}") from exc


def ensure_inside(root: Path, path: Path, description: str) -> Path:
    """Resolve a path and require it to be a descendant of the repository root."""
    try:
        root_resolved = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LabError(f"{description} cannot be resolved: {path}: {exc}") from exc

    if resolved == root_resolved or root_resolved not in resolved.parents:
        raise LabError(
            f"{description} must resolve inside the repository and not be the root itself: {path}"
        )

    return resolved


def require_mapping(
    value: Any,
    label: str,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    """Require a string-keyed mapping with an explicit schema."""
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise LabError(f"{label} must be a mapping with string keys")

    optional = optional or set()
    missing = required - value.keys()
    unknown = value.keys() - required - optional

    if missing:
        raise LabError(
            f"{label} is missing required keys: {', '.join(sorted(missing))}"
        )
    if unknown:
        raise LabError(
            f"{label} contains unsupported keys: {', '.join(sorted(unknown))}"
        )

    return value


def require_open_mapping(value: Any, label: str) -> dict[str, Any]:
    """Require a string-keyed mapping without constraining its key set."""
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise LabError(f"{label} must be a mapping with string keys")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    """Require a list."""
    if not isinstance(value, list):
        raise LabError(f"{label} must be a list")
    return value


def require_text(value: Any, label: str) -> str:
    """Require a non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise LabError(f"{label} must be a non-empty string")
    return value


def require_integer(value: Any, label: str, minimum: int = 0) -> int:
    """Require an integer, explicitly excluding bool."""
    if type(value) is not int or value < minimum:
        raise LabError(f"{label} must be an integer >= {minimum}")
    return value


def _memory_limit_mib(value: Any, label: str) -> int:
    """Parse a positive byte count or unit-suffixed memory limit into MiB."""
    if type(value) is int:
        byte_count = value
    elif isinstance(value, str):
        match = re.fullmatch(
            r"([0-9]+)([kmgt]?i?b?)?",
            value.strip(),
            re.IGNORECASE,
        )
        if not match:
            raise LabError(f"{label} has an unsupported memory limit format")

        amount = int(match.group(1))
        unit = (match.group(2) or "").lower().rstrip("b")
        multiplier = {
            "": 1,
            "k": 1024,
            "ki": 1024,
            "m": 1024**2,
            "mi": 1024**2,
            "g": 1024**3,
            "gi": 1024**3,
            "t": 1024**4,
            "ti": 1024**4,
        }.get(unit)

        if multiplier is None:
            raise LabError(f"{label} has an unsupported memory unit")

        byte_count = amount * multiplier
    else:
        raise LabError(f"{label} must declare a memory limit")

    if byte_count <= 0:
        raise LabError(f"{label} must be positive")

    return (byte_count + 1024**2 - 1) // 1024**2


def reject_sensitive_fields(value: Any, path: str = "definition") -> None:
    """Reject secret-bearing fields and secret-like values in research records."""
    if isinstance(value, dict):
        for key, child in value.items():
            if re.search(
                r"(?i)(password|passwd|secret|token|private[\_-]?key|credential)",
                str(key),
            ):
                raise LabError(
                    f"{path} contains a prohibited sensitive field name: {key}"
                )
            reject_sensitive_fields(child, f"{path}.{key}")

    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive_fields(child, f"{path}[{index}]")

    elif isinstance(value, str) and SECRET_PATTERN.search(value):
        raise LabError(
            f"{path} resembles a secret; remove it from the scientific record"
        )


def load_catalog(path: Path, key: str) -> dict[str, dict[str, Any]]:
    """Load a versioned list catalog and reject duplicate identifiers."""
    if key not in {"capabilities", "materials"}:
        raise LabError(f"unsupported catalog collection: {key}")

    document = load_yaml(path)
    require_mapping(document, str(path), {"schema_version", key})

    if document["schema_version"] != 1:
        raise LabError(f"unsupported catalog schema_version in {path}")

    entries = require_list(document[key], f"{path}:{key}")
    catalog: dict[str, dict[str, Any]] = {}

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise LabError(f"{path}:{key}[{index}] must be a mapping")

        identifier = require_text(
            entry.get("id"),
            f"{path}:{key}[{index}].id",
        )
        if identifier in catalog:
            raise LabError(f"duplicate catalog identifier: {identifier}")

        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", identifier):
            raise LabError(f"{path}:{key}[{index}].id has an invalid format")

        catalog[identifier] = entry

    if key == "capabilities":
        for identifier, capability in catalog.items():
            label = f"capabilities.{identifier}"
            require_mapping(
                capability,
                label,
                {
                    "id",
                    "revision",
                    "adapter",
                    "availability",
                    "operations",
                    "permissions",
                    "validation",
                },
            )
            if capability["id"] != identifier:
                raise LabError(f"{label}.id does not match its catalog identifier")
            require_text(capability["revision"], f"{label}.revision")
            if not REVISION_PATTERN.fullmatch(capability["revision"]):
                raise LabError(f"{label}.revision must be semantic versioning")
            require_text(capability["adapter"], f"{label}.adapter")
            if capability["availability"] not in {"available", "unavailable"}:
                raise LabError(f"{label}.availability is invalid")
            require_text(capability["validation"], f"{label}.validation")
            for field in ("operations", "permissions"):
                values = require_list(capability[field], f"{label}.{field}")
                if not values or any(
                    not isinstance(value, str) or not value.strip()
                    for value in values
                ):
                    raise LabError(f"{label}.{field} must contain non-empty strings")
                if len(values) != len(set(values)):
                    raise LabError(f"{label}.{field} contains duplicate entries")

    return catalog


def load_materials(root: Path = ROOT) -> dict[str, dict[str, Any]]:
    """Load and validate the approved-material registry."""
    materials = load_catalog(
        root / "lab" / "catalog" / "materials.yaml",
        "materials",
    )

    for material_id, material in materials.items():
        label = f"materials.{material_id}"
        require_mapping(
            material,
            label,
            {"id", "kind", "availability"},
            {"revision", "version", "image", "digest", "source"},
        )
        if material["id"] != material_id:
            raise LabError(f"{label}.id does not match its catalog identifier")
        require_text(material["kind"], f"{label}.kind")
        if material["availability"] not in {"available", "unavailable"}:
            raise LabError(f"{label}.availability is invalid")
        if ("revision" in material) == ("version" in material):
            raise LabError(f"{label} must declare exactly one of revision or version")
        version = require_text(
            material.get("revision", material.get("version")),
            f"{label}.revision or version",
        )
        if not version.strip():
            raise LabError(f"{label}.revision or version must not be empty")
        if "image" in material:
            require_text(material["image"], f"{label}.image")
            if material["kind"] != "container-image":
                raise LabError(
                    f"{label}.image is only valid for container-image materials"
                )
        if material["kind"] == "container-image" and "image" not in material:
            raise LabError(f"{label}.image is required for container-image materials")
        if "digest" in material:
            digest = require_text(material["digest"], f"{label}.digest")
            if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
                raise LabError(f"{label}.digest must be a SHA-256 digest")
        if "source" in material:
            require_text(material["source"], f"{label}.source")

    return materials


def require_available_capability(
    capability_id: str,
    operation: str,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Require an available capability that explicitly supports an operation."""
    capabilities = load_catalog(
        root / "lab" / "catalog" / "capabilities.yaml",
        "capabilities",
    )
    capability = capabilities.get(capability_id)
    if capability is None:
        raise LabError(f"capability is not registered: {capability_id}")
    if capability["availability"] != "available":
        raise LabError(f"capability is not currently available: {capability_id}")
    if operation not in capability["operations"]:
        raise LabError(
            f"capability {capability_id} does not support operation {operation}"
        )
    return capability


def require_available_image(
    image: str,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Resolve an exact image reference against approved materials."""
    materials = load_materials(root)

    matches = [
        material
        for material in materials.values()
        if material.get("image") == image
    ]
    if not matches:
        raise LabError(
            f"container image is not registered in the materials catalog: {image}"
        )
    if len(matches) != 1:
        raise LabError(f"container image has ambiguous material registrations: {image}")
    if matches[0]["availability"] != "available":
        raise LabError(f"container image material is unavailable: {image}")
    return matches[0]


def _validate_parameter_value(value: Any, spec: Any, label: str) -> None:
    """Validate a value against a typed parameter specification."""
    require_mapping(
        spec,
        label,
        {"type"},
        {"minimum", "maximum", "min_items", "max_items"},
    )
    kind = spec["type"]

    for bound in ("minimum", "maximum"):
        if bound in spec and (
            type(spec[bound]) not in (int, float)
            or not math.isfinite(spec[bound])
        ):
            raise LabError(f"{label}.{bound} must be a finite number")

    if (
        "minimum" in spec
        and "maximum" in spec
        and spec["minimum"] > spec["maximum"]
    ):
        raise LabError(f"{label} has minimum greater than maximum")

    for bound in ("min_items", "max_items"):
        if bound in spec:
            require_integer(spec[bound], f"{label}.{bound}", 0)

    if spec.get("min_items", 1) > spec.get("max_items", 1000):
        raise LabError(f"{label} has min_items greater than max_items")

    valid_types = {
        "number": lambda item: (
            type(item) in (int, float) and math.isfinite(item)
        ),
        "integer": lambda item: type(item) is int,
        "string": lambda item: isinstance(item, str),
        "boolean": lambda item: type(item) is bool,
    }

    if kind == "number_list":
        if not isinstance(value, list) or not value:
            raise LabError(f"{label} must be a non-empty number list")
        if any(
            type(item) not in (int, float) or not math.isfinite(item)
            for item in value
        ):
            raise LabError(f"{label} must contain only finite numbers")
        if (
            len(value) < spec.get("min_items", 1)
            or len(value) > spec.get("max_items", 1000)
        ):
            raise LabError(f"{label} length is outside its permitted range")
        return

    if kind not in valid_types:
        raise LabError(f"{label} declares unsupported type {kind!r}")

    if not valid_types[kind](value):
        raise LabError(f"{label} must have type {kind}")

    if kind in ("number", "integer"):
        if "minimum" in spec and value < spec["minimum"]:
            raise LabError(
                f"{label} is below its minimum {spec['minimum']}"
            )
        if "maximum" in spec and value > spec["maximum"]:
            raise LabError(
                f"{label} is above its maximum {spec['maximum']}"
            )


def _run_probe(
    command: list[str],
    *,
    timeout: int = 3,
) -> dict[str, Any]:
    """Run a bounded, read-only host inspection command."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "available": True,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip()[:12000],
            "stderr": completed.stderr.strip()[:4000],
        }
    except FileNotFoundError:
        return {"available": False, "reason": "executable_not_found"}
    except subprocess.TimeoutExpired:
        return {"available": True, "reason": "probe_timed_out"}
    except OSError as exc:
        return {"available": False, "reason": str(exc)}


def _is_wsl() -> bool:
    """Detect WSL using environment/kernel indicators, without modifying state."""
    if os.environ.get("WSL_INTEROP") or os.environ.get("WSL_DISTRO_NAME"):
        return True

    try:
        release = platform.release().lower()
        version = Path("/proc/version").read_text(
            encoding="utf-8",
            errors="replace",
        ).lower()
    except OSError:
        return "microsoft" in platform.release().lower()

    return "microsoft" in release or "microsoft" in version


def _linux_tool_observations() -> dict[str, bool]:
    """Record whether likely Linux control tools are installed."""
    return {
        "iptables": shutil.which("iptables") is not None,
        "ip6tables": shutil.which("ip6tables") is not None,
        "nft": shutil.which("nft") is not None,
        "ufw": shutil.which("ufw") is not None,
        "firewall-cmd": shutil.which("firewall-cmd") is not None,
        "ip": shutil.which("ip") is not None,
        "tcpdump": shutil.which("tcpdump") is not None,
        "tshark": shutil.which("tshark") is not None,
    }


def _discover_interfaces() -> dict[str, Any]:
    """Inspect interfaces and routes where standard read-only tools exist."""
    result: dict[str, Any] = {"interfaces": None, "routes_v4": None, "routes_v6": None}

    if shutil.which("ip"):
        result["interfaces"] = _run_probe(["ip", "-brief", "address"])
        result["routes_v4"] = _run_probe(["ip", "-4", "route", "show"])
        result["routes_v6"] = _run_probe(["ip", "-6", "route", "show"])

    return result


def _discover_virtualization() -> dict[str, Any]:
    """Report observable virtualization signals; never change firmware settings."""
    facts: dict[str, Any] = {
        "wsl_detected": _is_wsl(),
        "container_environment_hint": (
            Path("/.dockerenv").exists()
            or Path("/run/.containerenv").exists()
        ),
        "linux_virtualization_flags": None,
    }

    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        try:
            contents = cpuinfo.read_text(
                encoding="utf-8",
                errors="replace",
            ).lower()
            facts["linux_virtualization_flags"] = {
                "vmx": bool(re.search(r"\bvmx\b", contents)),
                "svm": bool(re.search(r"\bsvm\b", contents)),
            }
        except OSError:
            facts["linux_virtualization_flags"] = None

    if os.name == "nt":
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if powershell:
            # Read-only CIM query. A failure remains an unknown, not "supported".
            facts["windows_computer_system"] = _run_probe(
                [
                    powershell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    (
                        "Get-CimInstance Win32_ComputerSystem | "
                        "Select-Object Manufacturer,Model,HypervisorPresent | "
                        "ConvertTo-Json -Compress"
                    ),
                ],
                timeout=6,
            )

    return facts


def discover_host_capabilities(
    root: str | Path | None = None,
) -> dict[str, Any]:
    """Discover host/lab prerequisites without enabling or changing controls.

    The returned object is an observation snapshot, not proof of enforcement.
    Call validate_policy_prerequisites() before allowing profile activation.
    """
    root_path = Path(root).resolve() if root is not None else ROOT
    tools = {name: shutil.which(name) for name in TOOL_NAMES}
    platform_name = platform.system().lower()
    is_linux = platform_name == "linux"
    is_windows = platform_name == "windows"
    wsl = _is_wsl()

    docker_version = None
    if tools.get("docker"):
        docker_version = _run_probe(["docker", "version", "--format", "{{json .}}"])

    docker_info = None
    if tools.get("docker"):
        docker_info = _run_probe(
            [
                "docker",
                "info",
                "--format",
                "{{json .}}",
            ],
            timeout=8,
        )

    firewall_tools = _linux_tool_observations() if is_linux else {}
    network_observations = _discover_interfaces() if is_linux else {}

    capabilities: dict[str, Any] = {
        "schema_version": 1,
        "discovered_at": utc_now(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "is_windows": is_windows,
            "is_linux": is_linux,
            "is_wsl": wsl,
            "hostname": socket.gethostname(),
        },
        "tools": tools,
        "docker": {
            "executable_found": bool(tools.get("docker")),
            "version_probe": docker_version,
            "info_probe": docker_info,
        },
        "linux_firewall_tools": firewall_tools,
        "network_observations": network_observations,
        "virtualization": _discover_virtualization(),
        "lab_files": {
            "root_exists": root_path.is_dir(),
            "capacity_file_exists": (root_path / "config" / "lab-capacity.yaml").is_file(),
            "capabilities_file_exists": (
                root_path / "lab" / "catalog" / "capabilities.yaml"
            ).is_file(),
            "materials_file_exists": (
                root_path / "lab" / "catalog" / "materials.yaml"
            ).is_file(),
        },
    }

    # These fields are deliberately conservative. An installed binary does not
    # prove an adapter can use it or that its rules have the required semantics.
    has_firewall_tool = any(firewall_tools.values())
    capabilities["observed_capabilities"] = {
        "docker_available": bool(tools.get("docker")),
        "linux_firewall_tool": has_firewall_tool,
        "ipv4_firewall_tool": bool(
            firewall_tools.get("iptables") or firewall_tools.get("nft")
        ),
        "ipv6_firewall_tool": bool(
            firewall_tools.get("ip6tables") or firewall_tools.get("nft")
        ),
        "packet_capture_tool": bool(
            tools.get("tcpdump") or tools.get("tshark")
        ),
        # These controls require an explicit implementation/adapter declaration.
        # They must never be inferred from the presence of a generic executable.
        "windows_host_firewall_api": False,
        "dns_enforcement_adapter": False,
        "proxy_enforcement_adapter": False,
    }

    return capabilities


def _load_host_capability_declaration(
    root: Path,
) -> dict[str, Any]:
    """Load optional operator-maintained capability declarations.

    This file can declare that an enforcement adapter exists. It cannot replace
    runtime verification or acceptance testing.
    """
    path = root / "config" / "host-capabilities.yaml"
    if not path.is_file():
        return {
            "declared": False,
            "path": str(path),
            "adapters": {},
            "reason": "host-capabilities.yaml is absent",
        }

    document = load_yaml(path)
    require_mapping(
        document,
        str(path),
        {"schema_version", "adapters"},
        {"description"},
    )

    if document["schema_version"] != 1:
        raise LabError(f"unsupported schema_version in {path}")

    adapters = require_mapping(
        document["adapters"],
        f"{path}:adapters",
        set(),
        set(BOUNDARY_CAPABILITY_HINTS),
    )

    for boundary, adapter in adapters.items():
        if not isinstance(adapter, dict):
            raise LabError(f"{path}:adapters.{boundary} must be a mapping")

        require_mapping(
            adapter,
            f"{path}:adapters.{boundary}",
            {"control", "implementation", "available"},
            {"notes"},
        )

        if adapter["control"] not in ENFORCEMENT_CONTROL_TYPES:
            raise LabError(
                f"{path}:adapters.{boundary}.control must be one of "
                + ", ".join(sorted(ENFORCEMENT_CONTROL_TYPES))
            )
        require_text(
            adapter["implementation"],
            f"{path}:adapters.{boundary}.implementation",
        )
        if type(adapter["available"]) is not bool:
            raise LabError(
                f"{path}:adapters.{boundary}.available must be a boolean"
            )

    return {
        "declared": True,
        "path": str(path),
        "adapters": adapters,
    }


def _validate_policy_definition(policy: Any) -> dict[str, Any]:
    """Validate the policy definition independently from enforcement/evidence."""
    if not isinstance(policy, dict):
        raise LabError("policy must be a mapping")

    boundaries = policy.get("boundaries")
    if not isinstance(boundaries, dict):
        raise LabError("policy must contain a boundaries mapping")

    missing = POLICY_BOUNDARIES - set(boundaries)
    if missing:
        raise LabError(
            "policy is missing required boundaries: "
            + ", ".join(sorted(missing))
        )

    normalized: dict[str, Any] = {}
    for name in sorted(POLICY_BOUNDARIES):
        definition = boundaries[name]
        if not isinstance(definition, dict):
            raise LabError(f"policy boundary {name} must be a mapping")

        mode = definition.get("mode")
        if not isinstance(mode, str) or not mode.strip():
            raise LabError(f"policy boundary {name} needs an explicit mode")

        normalized[name] = {
            "mode": mode.strip().lower(),
            "definition_state": "VALIDATED",
        }

    return {
        "state": "VALIDATED",
        "identity": sha256_json(policy),
        "boundaries": normalized,
    }


def validate_policy_prerequisites(
    policy: dict[str, Any],
    root: str | Path | None = None,
    host_capabilities: dict[str, Any] | None = None,
    *,
    require_enforcement_declarations: bool = True,
) -> dict[str, Any]:
    """Preflight policy prerequisites before activating a profile.

    This function:
    - validates the declared policy definition;
    - discovers host capabilities if no snapshot is supplied;
    - checks that each required boundary has an available enforcement adapter;
    - checks basic prerequisites for the named control;
    - reports acceptance as NOT_TESTED until independent tests exist.

    It does not install controls or claim that traffic is blocked. The network
    adapter must still apply controls, verify them, and consume acceptance
    evidence before workloads are admitted.
    """
    root_path = Path(root).resolve() if root is not None else ROOT
    definition_report = _validate_policy_definition(policy)
    discovered = (
        host_capabilities
        if host_capabilities is not None
        else discover_host_capabilities(root_path)
    )

    if not isinstance(discovered, dict):
        raise LabError("host_capabilities must be a mapping")

    observed = discovered.get("observed_capabilities", {})
    if not isinstance(observed, dict):
        raise LabError("host capability snapshot has no valid observed_capabilities")

    declarations = _load_host_capability_declaration(root_path)
    declared_adapters = declarations.get("adapters", {})

    per_boundary: dict[str, Any] = {}
    failures: list[str] = []

    for boundary_name in sorted(POLICY_BOUNDARIES):
        boundary_policy = policy["boundaries"][boundary_name]
        mode = str(boundary_policy["mode"]).strip().lower()

        # Modes are policy vocabulary, not firewall commands. "allow" or "deny"
        # states intent only; the adapter owns the translation to enforcement.
        adapter_declaration = declared_adapters.get(boundary_name)
        hints = BOUNDARY_CAPABILITY_HINTS.get(boundary_name, ())
        missing_observations = [
            capability
            for capability in hints
            if observed.get(capability) is not True
        ]

        if adapter_declaration is None:
            adapter_state = "UNDECLARED"
            adapter_name = None
            control_type = None
            adapter_available = False
        else:
            adapter_state = (
                "DECLARED_AVAILABLE"
                if adapter_declaration.get("available") is True
                else "DECLARED_UNAVAILABLE"
            )
            adapter_name = adapter_declaration.get("implementation")
            control_type = adapter_declaration.get("control")
            adapter_available = adapter_declaration.get("available") is True

        # A declared adapter does not magically create missing host prerequisites.
        # The declared adapter must still have its relevant observed prerequisites.
        # Special host-specific controls remain unsupported unless an operator has
        # supplied an explicit adapter declaration and the required runtime checks.
        if missing_observations:
            state = "MISSING_HOST_PREREQUISITE"
            reason = (
                "missing observed prerequisite(s): "
                + ", ".join(missing_observations)
            )
        elif require_enforcement_declarations and not adapter_available:
            state = "ENFORCEMENT_UNDECLARED_OR_UNAVAILABLE"
            reason = (
                "no available operator-declared enforcement adapter for this boundary"
            )
        elif adapter_available:
            state = "PREREQUISITES_PRESENT"
            reason = (
                "declared adapter and observed prerequisites are present; "
                "effective enforcement is not yet verified"
            )
        else:
            state = "OBSERVATION_ONLY"
            reason = (
                "host tools were observed, but no enforcement adapter was approved"
            )

        per_boundary[boundary_name] = {
            "policy_definition": {
                "mode": mode,
                "state": "VALIDATED",
            },
            "enforcement": {
                "state": state,
                "adapter": adapter_name,
                "control": control_type,
                "reason": reason,
            },
            "acceptance_evidence": {
                "state": "NOT_TESTED",
                "reason": "acceptance tests have not been evaluated by this preflight",
            },
        }

        if require_enforcement_declarations and state != "PREREQUISITES_PRESENT":
            failures.append(f"{boundary_name}: {reason}")

    report = {
        "schema_version": 1,
        "checked_at": utc_now(),
        "policy_identity": definition_report["identity"],
        "policy_definition": definition_report,
        "host_capabilities": discovered,
        "adapter_declarations": declarations,
        "boundaries": per_boundary,
        "activation": {
            "allowed": not failures,
            "state": "PREREQUISITES_VALIDATED" if not failures else "BLOCKED",
            "failures": failures,
        },
        "acceptance_evidence": {
            "state": "NOT_TESTED",
            "note": (
                "This is a pre-activation report. It is not acceptance evidence "
                "and must not be used to authorize workload startup."
            ),
        },
    }

    return report


def require_policy_prerequisites(
    policy: dict[str, Any],
    root: str | Path | None = None,
    host_capabilities: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fail closed if required policy prerequisites are missing."""
    report = validate_policy_prerequisites(
        policy,
        root=root,
        host_capabilities=host_capabilities,
        require_enforcement_declarations=True,
    )
    if report["activation"]["allowed"] is not True:
        reasons = report["activation"]["failures"]
        raise LabError(
            "Policy profile activation blocked by failed prerequisites: "
            + "; ".join(reasons)
        )
    return report


def validate_acceptance_evidence(
    evidence: Any,
    *,
    expected_policy_identity: str,
    required_boundaries: set[str] | None = None,
) -> dict[str, Any]:
    """Validate independent acceptance evidence after enforcement has been applied.

    Expected evidence structure:

        {
          "schema_version": 1,
          "policy_identity": "<sha256 of resolved policy>",
          "effective_behavior": "passed",
          "runtime_acceptance": "passed",
          "boundaries": {
            "lab_ingress": {"state": "passed", "tests": [...]},
            ...
          }
        }

    Each boundary must have explicit tests. A missing test result is NOT_TESTED,
    never PASS. The test runner, not this validator, must create the evidence.
    """
    if not isinstance(evidence, dict):
        raise LabError("acceptance evidence must be a mapping")

    require_mapping(
        evidence,
        "acceptance evidence",
        {
            "schema_version",
            "policy_identity",
            "effective_behavior",
            "runtime_acceptance",
            "boundaries",
        },
        {"created_at", "test_run_id", "producer", "notes"},
    )

    if evidence["schema_version"] != 1:
        raise LabError("unsupported acceptance evidence schema_version")

    if evidence["policy_identity"] != expected_policy_identity:
        raise LabError(
            "acceptance evidence policy_identity does not match the active policy"
        )

    if evidence["effective_behavior"] != "passed":
        raise LabError("effective network behavior acceptance has not passed")

    if evidence["runtime_acceptance"] != "passed":
        raise LabError("runtime acceptance has not passed")

    boundaries = evidence["boundaries"]
    if not isinstance(boundaries, dict):
        raise LabError("acceptance evidence boundaries must be a mapping")

    required = required_boundaries or POLICY_BOUNDARIES
    missing = required - set(boundaries)
    if missing:
        raise LabError(
            "acceptance evidence is missing boundary results: "
            + ", ".join(sorted(missing))
        )

    boundary_report: dict[str, Any] = {}
    failures: list[str] = []

    for boundary_name in sorted(required):
        result = boundaries[boundary_name]
        if not isinstance(result, dict):
            raise LabError(
                f"acceptance evidence boundary {boundary_name} must be a mapping"
            )

        state = result.get("state")
        tests = result.get("tests")
        if not isinstance(tests, list) or not tests:
            boundary_report[boundary_name] = {
                "state": "NOT_TESTED",
                "tests": [],
            }
            failures.append(f"{boundary_name}: no explicit acceptance tests")
            continue

        normalized_tests: list[dict[str, Any]] = []
        for index, test in enumerate(tests):
            if not isinstance(test, dict):
                raise LabError(
                    f"{boundary_name}.tests[{index}] must be a mapping"
                )
            require_mapping(
                test,
                f"{boundary_name}.tests[{index}]",
                {"test_id", "expected", "observed", "state"},
                {"details", "timestamp"},
            )
            require_text(
                test["test_id"],
                f"{boundary_name}.tests[{index}].test_id",
            )

            if test["expected"] not in ("allow", "deny", "reachable", "unreachable"):
                raise LabError(
                    f"{boundary_name}.tests[{index}].expected has unsupported value"
                )
            if test["observed"] not in (
                "allow",
                "deny",
                "reachable",
                "unreachable",
                "error",
                "unknown",
            ):
                raise LabError(
                    f"{boundary_name}.tests[{index}].observed has unsupported value"
                )
            if test["state"] not in ("passed", "failed", "not_tested"):
                raise LabError(
                    f"{boundary_name}.tests[{index}].state has unsupported value"
                )

            normalized_tests.append(test)

        test_failures = [
            test["test_id"]
            for test in normalized_tests
            if test["state"] != "passed"
        ]

        if state != "passed" or test_failures:
            boundary_report[boundary_name] = {
                "state": "failed" if state == "failed" or test_failures else "NOT_TESTED",
                "tests": normalized_tests,
            }
            failures.append(
                f"{boundary_name}: boundary or test results have not all passed"
            )
        else:
            boundary_report[boundary_name] = {
                "state": "passed",
                "tests": normalized_tests,
            }

    return {
        "schema_version": 1,
        "policy_identity": expected_policy_identity,
        "state": "passed" if not failures else "failed",
        "boundaries": boundary_report,
        "failures": failures,
        "evidence_digest": sha256_json(evidence),
    }


def require_acceptance_evidence(
    evidence: Any,
    *,
    expected_policy_identity: str,
    required_boundaries: set[str] | None = None,
) -> dict[str, Any]:
    """Fail closed unless independent acceptance evidence passes all boundaries."""
    report = validate_acceptance_evidence(
        evidence,
        expected_policy_identity=expected_policy_identity,
        required_boundaries=required_boundaries,
    )
    if report["state"] != "passed":
        raise LabError(
            "Policy acceptance failed closed: "
            + "; ".join(report["failures"])
        )
    return report


__all__ = [
    "LabError",
    "UniqueKeyLoader",
    "ROOT",
    "CAPACITY_FILE",
    "CAPABILITIES_FILE",
    "MATERIALS_FILE",
    "ID_PATTERN",
    "EXPERIMENT_PATTERN",
    "REVISION_PATTERN",
    "POLICY_BOUNDARIES",
    "ENFORCEMENT_CONTROL_TYPES",
    "BOUNDARY_CAPABILITY_HINTS",
    "utc_now",
    "sha256_bytes",
    "sha256_json",
    "load_yaml",
    "ensure_inside",
    "require_mapping",
    "require_open_mapping",
    "require_list",
    "require_text",
    "require_integer",
    "_memory_limit_mib",
    "reject_sensitive_fields",
    "load_catalog",
    "_validate_parameter_value",
    "discover_host_capabilities",
    "validate_policy_prerequisites",
    "require_policy_prerequisites",
    "validate_acceptance_evidence",
    "require_acceptance_evidence",
]