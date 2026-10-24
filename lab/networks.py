"""Configuration-driven network boundary policy resolution."""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import shutil
import subprocess
import platform
import datetime as dt
from pathlib import Path
from typing import Any

from .foundation import LabError, load_yaml, require_mapping, require_text, sha256_bytes

MODES = {"allow", "deny", "restricted", "monitor"}
BOUNDARIES = (
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
)
BOUNDARY_KEYS = {
    "enabled", "mode", "direction", "scope", "rules", "exceptions",
    "verification", "description", "reason",
    "adapter",
}
BOUNDARY_FILE_NAMES = {
    "lab_ingress": "lab-ingress.yaml",
    "lab_egress": "lab-egress.yaml",
    "windows_host": "windows-host.yaml",
    "external_networks": "external-networks.yaml",
    "dns": "dns.yaml",
    "proxies": "proxies.yaml",
    "ipv4": "ipv4.yaml",
    "ipv6": "ipv6.yaml",
    "docker_networks": "docker-networks.yaml",
    "filesystem": "filesystem.yaml",
    "capture": "capture.yaml",
    "resource_access": "resource-access.yaml",
}
DIRECTIONS = {"inbound", "outbound", "bidirectional", "not_applicable"}
MACHINE_CONFIG = "config/networks/machine.yaml"


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _validate_rule(rule: Any, label: str) -> None:
    if not isinstance(rule, dict):
        raise LabError(f"{label} must be a mapping")
    allowed = {"action", "protocol", "address", "port", "interface", "resource", "destination"}
    unknown = set(rule) - allowed
    if unknown:
        raise LabError(f"{label} has unsupported fields: {', '.join(sorted(unknown))}")
    if rule.get("action") not in {"allow", "deny", "log"}:
        raise LabError(f"{label}.action must be allow, deny, or log")
    if "protocol" in rule and rule["protocol"] not in {"tcp", "udp", "icmp", "icmpv6", "any"}:
        raise LabError(f"{label}.protocol is unsupported")
    for key in ("address", "destination"):
        if key in rule:
            try:
                ipaddress.ip_network(str(rule[key]), strict=False)
            except ValueError as exc:
                raise LabError(f"{label}.{key} is not a valid IP network") from exc
    if "port" in rule:
        ports = rule["port"] if isinstance(rule["port"], list) else [rule["port"]]
        if not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            raise LabError(f"{label}.port must contain integers from 1 through 65535")


def validate_policy(policy: Any, label: str = "network policy") -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise LabError(f"{label} must be a mapping")
    require_mapping(
        policy,
        label,
        {"version", "profile", "boundaries"},
        {"provenance", "enforcement", "requested_capabilities"},
    )
    if policy["version"] != 1:
        raise LabError(f"{label}.version is unsupported")
    require_text(policy["profile"], f"{label}.profile")
    boundaries = policy["boundaries"]
    if not isinstance(boundaries, dict):
        raise LabError(f"{label}.boundaries must be a mapping")
    unknown = set(boundaries) - set(BOUNDARIES)
    if unknown:
        raise LabError(f"{label} has unsupported boundaries: {', '.join(sorted(unknown))}")
    if set(boundaries) != set(BOUNDARIES):
        missing = set(BOUNDARIES) - set(boundaries)
        raise LabError(f"{label} is missing boundaries: {', '.join(sorted(missing))}")
    for name, boundary in boundaries.items():
        if not isinstance(boundary, dict):
            raise LabError(f"{label}.boundaries.{name} must be a mapping")
        unknown_keys = set(boundary) - BOUNDARY_KEYS
        if unknown_keys:
            raise LabError(
                f"{label}.boundaries.{name} has unsupported fields: "
                f"{', '.join(sorted(unknown_keys))}"
            )
        if type(boundary.get("enabled")) is not bool:
            raise LabError(f"{label}.boundaries.{name}.enabled must be boolean")
        if boundary.get("mode") not in MODES:
            raise LabError(f"{label}.boundaries.{name} has unsupported mode")
        if boundary.get("direction") not in DIRECTIONS:
            raise LabError(f"{label}.boundaries.{name}.direction is unsupported")
        for key in ("rules", "exceptions", "verification"):
            if not isinstance(boundary.get(key), list):
                raise LabError(f"{label}.boundaries.{name}.{key} must be a list")
        for index, rule in enumerate(boundary["rules"]):
            _validate_rule(rule, f"{label}.boundaries.{name}.rules[{index}]")
        for index, rule in enumerate(boundary["exceptions"]):
            _validate_rule(rule, f"{label}.boundaries.{name}.exceptions[{index}]")
    return policy


def _profile_path(root: Path, profile: str) -> Path:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", profile):
        raise LabError("invalid network profile name")
    path = root / "config" / "networks" / "profiles" / f"{profile}.yaml"
    if not path.is_file():
        raise LabError(f"network profile does not exist: {profile}")
    return path


def _load_boundaries(root: Path) -> dict[str, dict[str, Any]]:
    result = {}
    directory = root / "config" / "networks" / "boundaries"
    for name, filename in BOUNDARY_FILE_NAMES.items():
        path = directory / filename
        if not path.is_file():
            raise LabError(f"network boundary configuration is missing: {path}")
        document = load_yaml(path)
        if not isinstance(document, dict):
            raise LabError(f"network boundary configuration must be a mapping: {path}")
        require_mapping(document, str(path), {"version", "boundary", "settings"})
        if document["version"] != 1 or document["boundary"] != name:
            raise LabError(f"{path} has an unsupported version or boundary identifier")
        result[name] = document["settings"]
    return result


def _resolve_profile(
    boundary_defaults: dict[str, dict[str, Any]],
    profile_document: dict[str, Any],
    profile: str,
) -> dict[str, Any]:
    require_mapping(profile_document, f"network profile {profile}", {"version", "profile", "boundaries"})
    if profile_document["version"] != 1 or profile_document["profile"] != profile:
        raise LabError(f"network profile {profile} has an invalid identity or version")
    selections = profile_document["boundaries"]
    if not isinstance(selections, dict) or set(selections) != set(BOUNDARIES):
        raise LabError(f"network profile {profile} must select every boundary")
    resolved = {}
    for name in BOUNDARIES:
        selection = selections[name]
        if not isinstance(selection, dict):
            raise LabError(f"network profile {profile}.{name} must be a mapping")
        if selection.get("source") != BOUNDARY_FILE_NAMES[name]:
            raise LabError(f"network profile {profile}.{name} references the wrong boundary source")
        overrides = selection.get("overrides", {})
        if not isinstance(overrides, dict):
            raise LabError(f"network profile {profile}.{name}.overrides must be a mapping")
        resolved[name] = _merge(boundary_defaults[name], overrides)
    return {"version": 1, "profile": profile, "boundaries": resolved}


def resolve_network_policy(
    root: Path,
    profile: str | None = None,
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selected = profile
    if selected is None:
        active = root / "config" / "networks" / "active-profile"
        try:
            selected = active.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise LabError(f"cannot read active network profile: {active}") from exc
    if not selected:
        raise LabError("active network profile is empty")
    boundary_defaults = _load_boundaries(root)
    base = _resolve_profile(boundary_defaults, load_yaml(_profile_path(root, selected)), selected)
    resolved = validate_policy(base, f"network profile {selected}")
    if overrides is not None:
        if not isinstance(overrides, dict):
            raise LabError("network policy overrides must be a mapping")
        resolved = _merge(resolved, {"boundaries": overrides})
    resolved["profile"] = selected
    resolved["provenance"] = {
        "profile_file": sha256_bytes(_profile_path(root, selected).read_bytes()),
        "boundary_files": {
            name: sha256_bytes((root / "config" / "networks" / "boundaries" / filename).read_bytes())
            for name, filename in BOUNDARY_FILE_NAMES.items()
        },
    }
    resolved["enforcement"] = {
        "adapters": sorted({
            boundary.get("adapter")
            for boundary in resolved["boundaries"].values()
            if boundary.get("adapter")
        }),
        "scopes": {
            name: boundary.get("scope")
            for name, boundary in resolved["boundaries"].items()
        },
        "verification_requirements": {
            name: boundary["verification"]
            for name, boundary in resolved["boundaries"].items()
            if boundary["enabled"]
        },
    }
    resolved["requested_capabilities"] = sorted({
        f"{name}:{boundary['mode']}"
        for name, boundary in resolved["boundaries"].items()
        if boundary["enabled"]
    })
    return validate_policy(resolved, "effective network policy")


def policy_json(policy: dict[str, Any]) -> str:
    return json.dumps(policy, indent=2, sort_keys=True) + "\n"


def list_network_profiles(root: Path) -> list[str]:
    directory = root / "config" / "networks" / "profiles"
    canonical = {"isolated", "observation", "controlled-access", "maintenance"}
    profiles = sorted(path.stem for path in directory.glob("*.yaml") if path.stem in canonical)
    if not profiles:
        raise LabError(f"no network profiles found: {directory}")
    return profiles


def validate_network_configuration(root: Path) -> dict[str, Any]:
    profiles = list_network_profiles(root)
    expected = ["controlled-access", "isolated", "maintenance", "observation"]
    if profiles != expected:
        raise LabError(f"network profiles must be exactly: {', '.join(expected)}")
    resolved = {profile: resolve_network_policy(root, profile) for profile in profiles}
    return {"profiles": profiles, "boundaries": list(BOUNDARIES), "resolved": resolved}


def validate_runtime_support(policy: dict[str, Any]) -> None:
    unsupported = []
    for name, boundary in policy["boundaries"].items():
        if name in {"filesystem", "resource_access", "docker_networks"} and (
            not boundary["enabled"] or boundary["mode"] != "deny"
        ):
            unsupported.append(f"{name}=controller-integrity")
            continue
        if not boundary["enabled"]:
            continue
        if name in {"ipv4", "ipv6", "lab_ingress", "lab_egress", "external_networks", "windows_host"}:
            if boundary["mode"] != "deny":
                unsupported.append(f"{name}={boundary['mode']}")
        elif name == "capture":
            if boundary["mode"] != "monitor":
                unsupported.append(f"{name}={boundary['mode']}")
            elif not (shutil.which("tcpdump") or shutil.which("tshark")):
                unsupported.append("capture_tool=tcpdump-or-tshark")
        elif name in {"dns", "proxies"} and boundary["mode"] != "deny":
            unsupported.append(f"{name}={boundary['mode']}")
    if unsupported:
        raise LabError(
            "selected network policy is not supported for construction by the "
            f"Linux/WSL adapter: {', '.join(unsupported)}"
        )


def _run_inventory(command: list[str], timeout: int = 10) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=timeout
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable: {exc}"
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit {result.returncode}"
        return f"unavailable: {detail}"
    return result.stdout.strip()


def discover_network_inventory() -> dict[str, Any]:
    """Return read-only observations from the current Linux/WSL environment."""
    commands = {
        "interfaces": ["ip", "-details", "address", "show"],
        "routes": ["ip", "route", "show"],
        "routes_ipv6": ["ip", "-6", "route", "show"],
        "resolvers": ["cat", "/etc/resolv.conf"],
        "docker_version": ["docker", "version", "--format", "{{.Server.Version}}"],
        "docker_context": ["docker", "context", "show"],
        "docker_networks": ["docker", "network", "ls"],
        "docker_network_details": ["docker", "network", "ls", "--format", "{{.ID}} {{.Name}} {{.Driver}} {{.Scope}}"],
        "compose_version": ["docker", "compose", "version"],
        "iptables_version": ["iptables", "--version"],
        "ip6tables_version": ["ip6tables", "--version"],
        "nftables_version": ["nft", "--version"],
        "iptables_rules": ["iptables", "-S"],
        "ip6tables_rules": ["ip6tables", "-S"],
        "nftables_rules": ["nft", "list", "ruleset"],
    }
    availability = {
        name: shutil.which(command[0]) is not None
        for name, command in commands.items()
    }
    observations = {
        name: _run_inventory(command) if availability[name] else "unavailable: command not found"
        for name, command in commands.items()
    }
    return {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "wsl_indicators": {
            "is_wsl": "microsoft" in platform.release().lower()
            or "microsoft" in observations["resolvers"].lower(),
            "kernel_release": platform.release(),
        },
        "availability": availability,
        "observations": observations,
        "read_only": True,
    }


def validate_machine_configuration(root: Path = Path(".")) -> dict[str, Any]:
    path = root / MACHINE_CONFIG
    if not path.is_file():
        raise LabError(
            f"machine network configuration is missing: {path}; "
            "run networks discover, then review this file"
        )
    document = load_yaml(path)
    require_mapping(
        document,
        str(path),
        {"version", "operator_confirmed"},
        {"discovered", "derived", "unsupported"},
    )
    if document["version"] != 1:
        raise LabError(f"{path}.version is unsupported")
    confirmed = document["operator_confirmed"]
    require_mapping(
        confirmed,
        f"{path}.operator_confirmed",
        {"approved_docker_context"},
        {"approved_interfaces", "approved_networks"},
    )
    if (
        not isinstance(confirmed["approved_docker_context"], str)
        or not confirmed["approved_docker_context"].strip()
        or confirmed["approved_docker_context"].startswith("REPLACE_")
    ):
        raise LabError(f"{path}.operator_confirmed.approved_docker_context must be non-empty")
    for key in ("approved_interfaces", "approved_networks"):
        if key in confirmed and not isinstance(confirmed[key], list):
            raise LabError(f"{path}.operator_confirmed.{key} must be a list")
    current_context = _run_inventory(["docker", "context", "show"])
    if not current_context.startswith("unavailable:"):
        if current_context != confirmed["approved_docker_context"]:
            raise LabError(
                f"{path}.operator_confirmed.approved_docker_context does not match "
                f"the current Docker context ({current_context})"
            )
    return document


def configure_machine(root: Path = Path("."), overwrite: bool = False) -> Path:
    destination = root / MACHINE_CONFIG
    if destination.exists() and not overwrite:
        raise LabError(f"machine network configuration already exists: {destination}")
    example = root / "config" / "networks" / "machine.yaml.example"
    if not example.is_file():
        raise LabError(f"machine network configuration template is missing: {example}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    return destination


def inspect_owned_network(project: str) -> dict[str, Any]:
    if not re.fullmatch(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}", project):
        raise LabError("invalid investigation project")
    result = subprocess.run(
        [
            "docker", "network", "ls", "-q",
            "--filter", f"label=com.docker.compose.project={project}",
        ],
        capture_output=True, text=True, check=False, timeout=20,
    )
    if result.returncode != 0:
        raise LabError(f"cannot enumerate project network: {result.stderr.strip()}")
    ids = result.stdout.split()
    if len(ids) != 1:
        raise LabError(f"expected exactly one owned project network; found {len(ids)}")
    network_id = ids[0]
    inspected = subprocess.run(
        [
            "docker", "network", "inspect", network_id,
            "--format",
            "{{json .}}",
        ],
        capture_output=True, text=True, check=False, timeout=20,
    )
    if inspected.returncode != 0:
        raise LabError(f"cannot inspect project network: {inspected.stderr.strip()}")
    try:
        data = json.loads(inspected.stdout)
    except ValueError as exc:
        raise LabError("Docker returned invalid network inspection JSON") from exc
    labels = data.get("Labels", {})
    if labels.get("io.ithoka.security-lab.owner") != "security-lab":
        raise LabError("project network is not owned by security-lab")
    if labels.get("io.ithoka.security-lab.investigation") != project.removeprefix("sec-lab-i-"):
        raise LabError("project network ownership does not match the investigation")
    return {
        "network_id": network_id,
        "name": data.get("Name"),
        "driver": data.get("Driver"),
        "internal": data.get("Internal"),
        "enable_ipv6": data.get("EnableIPv6"),
        "labels": labels,
        "ipam": data.get("IPAM", {}),
        "containers": data.get("Containers", {}),
        "bridge": data.get("Options", {}).get("com.docker.network.bridge.name"),
        "observed_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }


def build_enforcement_plan(
    root: Path = Path("."),
    profile: str | None = None,
    machine_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy = resolve_network_policy(root, profile)
    support_error = None
    try:
        validate_runtime_support(policy)
    except LabError as exc:
        support_error = str(exc)
    machine = machine_config or validate_machine_configuration(root)
    operations = []
    for name, boundary in policy["boundaries"].items():
        operations.append({
            "boundary": name,
            "enabled": boundary["enabled"],
            "mode": boundary["mode"],
            "scope": boundary.get("scope"),
            "adapter": boundary.get("adapter"),
            "verification": boundary["verification"],
            "rules": boundary["rules"],
            "exceptions": boundary["exceptions"],
        })
    return {
        "plan_version": 1,
        "profile": policy["profile"],
        "policy": policy,
        "policy_identity": sha256_bytes(policy_json(policy).encode("utf-8")),
        "machine_configuration": machine,
        "operations": operations,
        "supported": support_error is None,
        "capability_error": support_error,
        "apply_order": ["resolve_scope", "apply", "inspect", "verify"],
        "read_only": True,
    }


def select_network_profile(root: Path, profile: str) -> Path:
    if profile not in list_network_profiles(root):
        raise LabError(f"unsupported network profile: {profile}")
    destination = root / "config" / "networks" / "active-profile"
    destination.write_text(profile + "\n", encoding="utf-8")
    return destination


def network_policy_drift(root: Path, project: str) -> dict[str, Any]:
    if not re.fullmatch(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}", project):
        raise LabError("invalid investigation project")
    runtime_file = root / "state" / "runtime" / f"{project}-network-policy.json"
    if not runtime_file.is_file():
        raise LabError(f"no pinned policy exists for project: {project}")
    try:
        pinned = json.loads(runtime_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LabError(f"cannot read pinned policy: {runtime_file}") from exc
    current = resolve_network_policy(root)
    return {
        "project": project,
        "drifted": pinned != current,
        "pinned_profile": pinned.get("profile"),
        "active_profile": current.get("profile"),
        "pinned_provenance": pinned.get("provenance"),
        "active_provenance": current.get("provenance"),
    }


__all__ = [
    "BOUNDARIES",
    "MACHINE_CONFIG",
    "build_enforcement_plan",
    "configure_machine",
    "discover_network_inventory",
    "inspect_owned_network",
    "list_network_profiles",
    "policy_json",
    "network_policy_drift",
    "resolve_network_policy",
    "select_network_profile",
    "validate_machine_configuration",
    "validate_network_configuration",
    "validate_runtime_support",
    "validate_policy",
]
