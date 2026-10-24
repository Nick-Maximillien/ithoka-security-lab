"""Configuration-driven network boundary policy resolution.

Design contract
---------------
1. Policy definition describes what is permitted and forbidden.
2. Enforcement capability describes which adapter can enforce each requirement.
3. Acceptance evidence records observed results; configuration validity is not
   enforcement, and enforcement-rule presence is not runtime acceptance.

This module is deliberately conservative. It does not perform firewall mutations.
"""

from __future__ import annotations

import copy
import datetime as dt
import ipaddress
import json
import platform
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .foundation import (
    LabError,
    load_yaml,
    require_mapping,
    require_text,
    sha256_bytes,
)

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
    "enabled",
    "mode",
    "direction",
    "scope",
    "rules",
    "exceptions",
    "verification",
    "description",
    "reason",
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

DIRECTIONS = {
    "inbound",
    "outbound",
    "bidirectional",
    "not_applicable",
}

MACHINE_CONFIG = "config/networks/machine.yaml"

CANONICAL_PROFILES = {
    "isolated",
    "observation",
    "controlled-access",
    "maintenance",
}

# These are declared requirements, not claims that controls are implemented.
REQUIRED_BOUNDARY_CONTROLS = {
    "ipv4": {
        "adapter": "linux-wsl",
        "verification": {"iptables"},
    },
    "ipv6": {
        "adapter": "linux-wsl",
        "verification": {"ip6tables"},
    },
    "lab_ingress": {
        "adapter": "linux-wsl",
        "verification": {"iptables", "ip6tables"},
    },
    "lab_egress": {
        "adapter": "linux-wsl",
        "verification": {"iptables", "ip6tables"},
    },
    "external_networks": {
        "adapter": "linux-wsl",
        "verification": {"forwarding_rules", "runtime_acceptance"},
    },
}

# No implementation in this module proves these controls at runtime.
UNIMPLEMENTED_BOUNDARIES = {
    "windows_host": (
        "Windows-host enforcement requires a Windows-side control adapter "
        "and host-level acceptance evidence."
    ),
    "dns": (
        "DNS enforcement requires resolver-path control, bypass prevention, "
        "and runtime DNS acceptance tests."
    ),
    "proxies": (
        "Proxy enforcement requires declared endpoint policy, bypass prevention, "
        "and runtime traffic acceptance tests."
    ),
    "capture": (
        "Runtime capture activation, integrity checks, and evidence collection "
        "are not implemented by this policy resolver."
    ),
}

# These controls may be validated by other layers, but this module alone does
# not establish that their runtime restrictions cannot be bypassed.
CONFIGURATION_VALIDATED_BOUNDARIES = {
    "docker_networks",
    "filesystem",
    "resource_access",
}


def _merge(
    base: dict[str, Any],
    override: dict[str, Any],
) -> dict[str, Any]:
    """Deep-merge dictionaries without mutating either input."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _validate_rule(rule: Any, label: str) -> None:
    """Validate a declarative rule without implying that it is enforced."""
    if not isinstance(rule, dict):
        raise LabError(f"{label} must be a mapping")

    allowed = {
        "action",
        "protocol",
        "address",
        "port",
        "interface",
        "resource",
        "destination",
    }
    unknown = set(rule) - allowed
    if unknown:
        raise LabError(
            f"{label} has unsupported fields: {', '.join(sorted(unknown))}"
        )

    if rule.get("action") not in {"allow", "deny", "log"}:
        raise LabError(f"{label}.action must be allow, deny, or log")

    if "protocol" in rule and rule["protocol"] not in {
        "tcp",
        "udp",
        "icmp",
        "icmpv6",
        "any",
    }:
        raise LabError(f"{label}.protocol is unsupported")

    for key in ("address", "destination"):
        if key in rule:
            try:
                ipaddress.ip_network(str(rule[key]), strict=False)
            except ValueError as exc:
                raise LabError(
                    f"{label}.{key} is not a valid IP network"
                ) from exc

    if "port" in rule:
        ports = rule["port"]
        ports = ports if isinstance(ports, list) else [ports]
        if not ports or any(
            type(port) is not int or not 1 <= port <= 65535
            for port in ports
        ):
            raise LabError(
                f"{label}.port must contain integers from 1 through 65535"
            )

    for key in ("interface", "resource"):
        if key in rule and (
            not isinstance(rule[key], str) or not rule[key].strip()
        ):
            raise LabError(f"{label}.{key} must be non-empty text")


def validate_policy(
    policy: Any,
    label: str = "network policy",
) -> dict[str, Any]:
    """Validate policy structure and semantics, not runtime enforcement."""
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

    if policy["profile"] not in CANONICAL_PROFILES:
        raise LabError(
            f"{label}.profile is not a canonical profile: {policy['profile']}"
        )

    boundaries = policy["boundaries"]
    if not isinstance(boundaries, dict):
        raise LabError(f"{label}.boundaries must be a mapping")

    unknown = set(boundaries) - set(BOUNDARIES)
    if unknown:
        raise LabError(
            f"{label} has unsupported boundaries: {', '.join(sorted(unknown))}"
        )

    missing = set(BOUNDARIES) - set(boundaries)
    if missing:
        raise LabError(
            f"{label} is missing boundaries: {', '.join(sorted(missing))}"
        )

    for name, boundary in boundaries.items():
        boundary_label = f"{label}.boundaries.{name}"

        if not isinstance(boundary, dict):
            raise LabError(f"{boundary_label} must be a mapping")

        unknown_keys = set(boundary) - BOUNDARY_KEYS
        if unknown_keys:
            raise LabError(
                f"{boundary_label} has unsupported fields: "
                f"{', '.join(sorted(unknown_keys))}"
            )

        if type(boundary.get("enabled")) is not bool:
            raise LabError(f"{boundary_label}.enabled must be boolean")

        if boundary.get("mode") not in MODES:
            raise LabError(f"{boundary_label}.mode is unsupported")

        if boundary.get("direction") not in DIRECTIONS:
            raise LabError(f"{boundary_label}.direction is unsupported")

        for key in ("rules", "exceptions", "verification"):
            if not isinstance(boundary.get(key), list):
                raise LabError(f"{boundary_label}.{key} must be a list")

        for key in ("scope", "adapter", "description", "reason"):
            if key in boundary and boundary[key] is not None:
                if not isinstance(boundary[key], str):
                    raise LabError(f"{boundary_label}.{key} must be text")

        for index, rule in enumerate(boundary["rules"]):
            _validate_rule(rule, f"{boundary_label}.rules[{index}]")

        for index, rule in enumerate(boundary["exceptions"]):
            _validate_rule(rule, f"{boundary_label}.exceptions[{index}]")

        for index, requirement in enumerate(boundary["verification"]):
            if not isinstance(requirement, str) or not requirement.strip():
                raise LabError(
                    f"{boundary_label}.verification[{index}] must be non-empty text"
                )

        # Exceptions must not silently bypass a deny-only boundary.
        if boundary["enabled"] and boundary["mode"] == "deny":
            if any(rule["action"] == "allow" for rule in boundary["rules"]):
                raise LabError(
                    f"{boundary_label} uses mode=deny but contains an allow rule"
                )

            if any(rule["action"] == "allow" for rule in boundary["exceptions"]):
                raise LabError(
                    f"{boundary_label} uses mode=deny but contains an allow exception"
                )

    return policy


def _profile_path(root: Path, profile: str) -> Path:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", profile):
        raise LabError("invalid network profile name")

    if profile not in CANONICAL_PROFILES:
        raise LabError(f"unsupported network profile: {profile}")

    path = root / "config" / "networks" / "profiles" / f"{profile}.yaml"
    if not path.is_file():
        raise LabError(f"network profile does not exist: {profile}")
    return path


def _load_boundaries(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    directory = root / "config" / "networks" / "boundaries"

    for name, filename in BOUNDARY_FILE_NAMES.items():
        path = directory / filename
        if not path.is_file():
            raise LabError(
                f"network boundary configuration is missing: {path}"
            )

        document = load_yaml(path)
        if not isinstance(document, dict):
            raise LabError(
                f"network boundary configuration must be a mapping: {path}"
            )

        require_mapping(document, str(path), {"version", "boundary", "settings"})

        if document["version"] != 1 or document["boundary"] != name:
            raise LabError(
                f"{path} has an unsupported version or boundary identifier"
            )

        if not isinstance(document["settings"], dict):
            raise LabError(f"{path}.settings must be a mapping")

        result[name] = document["settings"]

    return result


def _resolve_profile(
    boundary_defaults: dict[str, dict[str, Any]],
    profile_document: dict[str, Any],
    profile: str,
) -> dict[str, Any]:
    require_mapping(
        profile_document,
        f"network profile {profile}",
        {"version", "profile", "boundaries"},
    )

    if (
        profile_document["version"] != 1
        or profile_document["profile"] != profile
    ):
        raise LabError(
            f"network profile {profile} has an invalid identity or version"
        )

    selections = profile_document["boundaries"]
    if not isinstance(selections, dict) or set(selections) != set(BOUNDARIES):
        raise LabError(
            f"network profile {profile} must select every boundary"
        )

    resolved: dict[str, dict[str, Any]] = {}

    for name in BOUNDARIES:
        selection = selections[name]
        if not isinstance(selection, dict):
            raise LabError(f"network profile {profile}.{name} must be a mapping")

        if selection.get("source") != BOUNDARY_FILE_NAMES[name]:
            raise LabError(
                f"network profile {profile}.{name} references "
                "the wrong boundary source"
            )

        overrides = selection.get("overrides", {})
        if not isinstance(overrides, dict):
            raise LabError(
                f"network profile {profile}.{name}.overrides must be a mapping"
            )

        resolved[name] = _merge(boundary_defaults[name], overrides)

    return {
        "version": 1,
        "profile": profile,
        "boundaries": resolved,
    }


def resolve_network_policy(
    root: Path,
    profile: str | None = None,
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve profile plus boundary defaults and return provenance hashes."""
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
    profile_file = _profile_path(root, selected)
    base = _resolve_profile(
        boundary_defaults,
        load_yaml(profile_file),
        selected,
    )
    resolved = validate_policy(base, f"network profile {selected}")

    if overrides is not None:
        if not isinstance(overrides, dict):
            raise LabError("network policy overrides must be a mapping")

        unknown = set(overrides) - set(BOUNDARIES)
        if unknown:
            raise LabError(
                "network policy overrides contain unknown boundaries: "
                + ", ".join(sorted(unknown))
            )

        for name, override in overrides.items():
            if not isinstance(override, dict):
                raise LabError(
                    f"network policy override for {name} must be a mapping"
                )

        resolved = _merge(resolved, {"boundaries": overrides})
        validate_policy(resolved, "effective network policy")

    resolved["profile"] = selected
    resolved["provenance"] = {
        "profile_file": sha256_bytes(profile_file.read_bytes()),
        "boundary_files": {
            name: sha256_bytes(
                (root / "config" / "networks" / "boundaries" / filename)
                .read_bytes()
            )
            for name, filename in BOUNDARY_FILE_NAMES.items()
        },
    }

    resolved["enforcement"] = {
        "adapters": sorted({
            boundary["adapter"]
            for boundary in resolved["boundaries"].values()
            if boundary.get("enabled") and boundary.get("adapter")
        }),
        "scopes": {
            name: boundary.get("scope")
            for name, boundary in resolved["boundaries"].items()
        },
        "verification_requirements": {
            name: list(boundary["verification"])
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
    profiles = sorted(
        path.stem
        for path in directory.glob("*.yaml")
        if path.stem in CANONICAL_PROFILES
    )

    if set(profiles) != CANONICAL_PROFILES:
        missing = CANONICAL_PROFILES - set(profiles)
        raise LabError(
            f"network profile set is incomplete; missing: {', '.join(sorted(missing))}"
        )

    return profiles


def validate_network_configuration(root: Path) -> dict[str, Any]:
    """Validate all four canonical profiles and their resolved policies."""
    profiles = list_network_profiles(root)
    expected = sorted(CANONICAL_PROFILES)

    if profiles != expected:
        raise LabError(
            f"network profiles must be exactly: {', '.join(expected)}"
        )

    resolved = {
        profile: resolve_network_policy(root, profile)
        for profile in profiles
    }

    return {
        "profiles": profiles,
        "boundaries": list(BOUNDARIES),
        "resolved": resolved,
        "configuration_valid": True,
        "runtime_enforcement_verified": False,
        "runtime_acceptance": "not-run",
    }


def _boundary_capability(
    name: str,
    boundary: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate support claims conservatively for one boundary."""
    if not boundary["enabled"]:
        return {
            "status": "not-required",
            "reason": "Boundary is disabled by the selected policy.",
            "enforcement_verified": False,
            "acceptance": "not-run",
        }

    if name in UNIMPLEMENTED_BOUNDARIES:
        return {
            "status": "unsupported",
            "reason": UNIMPLEMENTED_BOUNDARIES[name],
            "enforcement_verified": False,
            "acceptance": "not-run",
        }

    if name in CONFIGURATION_VALIDATED_BOUNDARIES:
        return {
            "status": "configuration-validation-only",
            "reason": (
                "This module does not prove runtime enforcement. "
                "The relevant controller must validate configuration and "
                "separate runtime acceptance tests must pass."
            ),
            "enforcement_verified": False,
            "acceptance": "not-run",
        }

    requirement = REQUIRED_BOUNDARY_CONTROLS.get(name)
    if requirement is None:
        return {
            "status": "unsupported",
            "reason": "No enforcement adapter is registered for this boundary.",
            "enforcement_verified": False,
            "acceptance": "not-run",
        }

    problems: list[str] = []

    if boundary["mode"] != "deny":
        problems.append("required mode is deny")

    if boundary.get("adapter") != requirement["adapter"]:
        problems.append(
            f"required adapter is {requirement['adapter']}"
        )

    if set(boundary["verification"]) != requirement["verification"]:
        problems.append(
            "verification requirements do not match the registered adapter contract"
        )

    if boundary["rules"] or boundary["exceptions"]:
        problems.append(
            "custom rules and exceptions have no registered rule compiler"
        )

    if not boundary.get("scope"):
        problems.append("enforcement scope is unspecified")

    if name == "external_networks":
        problems.append(
            "runtime acceptance is mandatory and has not been implemented "
            "by this module"
        )

    if problems:
        return {
            "status": "unsupported",
            "reason": "; ".join(problems),
            "enforcement_verified": False,
            "acceptance": "not-run",
        }

    return {
        "status": "adapter-declared-only",
        "reason": (
            "The policy matches the declared adapter contract, but this module "
            "has not verified installed rules or packet behaviour."
        ),
        "enforcement_verified": False,
        "acceptance": "not-run",
    }


def validate_runtime_support(policy: dict[str, Any]) -> None:
    """Raise unless every enabled boundary has a declared supported path.

    This function is intentionally not a runtime PASS check. Even when it
    returns normally, actual enforcement and traffic acceptance remain separate.
    """
    validate_policy(policy)
    unsupported = []

    for name, boundary in policy["boundaries"].items():
        capability = _boundary_capability(name, boundary)
        if capability["status"] in {"unsupported"}:
            unsupported.append(f"{name}={capability['reason']}")

    if unsupported:
        raise LabError(
            "selected network policy cannot be established by the registered "
            "enforcement adapters: " + " | ".join(unsupported)
        )


def network_capabilities() -> dict[str, Any]:
    """Describe known implementation state without claiming runtime proof."""
    controls: dict[str, Any] = {}

    for name in BOUNDARIES:
        if name in REQUIRED_BOUNDARY_CONTROLS:
            requirement = REQUIRED_BOUNDARY_CONTROLS[name]
            controls[name] = {
                "status": "adapter-declared-only",
                "adapter": requirement["adapter"],
                "modes": ["deny"],
                "required_verification": sorted(requirement["verification"]),
                "enforcement_state": "not-verified",
                "runtime_acceptance": "not-run",
            }
        elif name in CONFIGURATION_VALIDATED_BOUNDARIES:
            controls[name] = {
                "status": "configuration-validation-only",
                "enforcement_state": "not-verified",
                "runtime_acceptance": "not-run",
            }
        elif name in UNIMPLEMENTED_BOUNDARIES:
            controls[name] = {
                "status": "unsupported",
                "reason": UNIMPLEMENTED_BOUNDARIES[name],
                "enforcement_state": "not-implemented",
                "runtime_acceptance": "not-run",
            }
        else:
            controls[name] = {
                "status": "unsupported",
                "reason": "No enforcement implementation is registered.",
                "enforcement_state": "not-implemented",
                "runtime_acceptance": "not-run",
            }

    return {
        "adapter": "linux-wsl",
        "controls": controls,
        "machine_state": "not-verified",
        "runtime_acceptance": "not-run",
        "overall_status": "not-verified",
        "pass_rule": (
            "PASS requires required controls verified at their enforcement "
            "points and all mandatory runtime acceptance tests passed."
        ),
    }


def validate_firewall_jump_order(
    chain: str,
    rules_output: str,
    owned_chain: str,
    jump_comment: str,
) -> None:
    """Require exactly one owned jump, as the first effective built-in rule."""
    rules = []

    for line in rules_output.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            raise LabError(f"cannot parse {chain} firewall rules: {exc}") from exc

        if len(tokens) >= 3 and tokens[:2] == ["-A", chain]:
            rules.append(tokens)

    matches = [
        index
        for index, rule in enumerate(rules)
        if "-j" in rule
        and rule.index("-j") + 1 < len(rule)
        and rule[rule.index("-j") + 1] == owned_chain
        and "--comment" in rule
        and rule.index("--comment") + 1 < len(rule)
        and rule[rule.index("--comment") + 1] == jump_comment
    ]

    if len(matches) != 1:
        raise LabError(
            f"expected exactly one owned jump to {owned_chain} in {chain}; "
            f"found {len(matches)}"
        )

    if matches[0] != 0:
        raise LabError(
            f"owned enforcement jump is not first in {chain}; "
            "effective order is ambiguous"
        )


def validate_firewall_jump_sequence(
    chain: str,
    rules_output: str,
    expected_jumps: list[tuple[str, str]],
) -> None:
    """Require owned jumps to occupy the specified initial rule positions."""
    rules = []

    for line in rules_output.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            raise LabError(f"cannot parse {chain} firewall rules: {exc}") from exc

        if len(tokens) >= 3 and tokens[:2] == ["-A", chain]:
            rules.append(tokens)

    for index, (owned_chain, jump_comment) in enumerate(expected_jumps):
        matches = [
            position
            for position, rule in enumerate(rules)
            if "-j" in rule
            and rule.index("-j") + 1 < len(rule)
            and rule[rule.index("-j") + 1] == owned_chain
            and "--comment" in rule
            and rule.index("--comment") + 1 < len(rule)
            and rule[rule.index("--comment") + 1] == jump_comment
        ]

        if len(matches) != 1:
            raise LabError(
                f"expected exactly one owned jump to {owned_chain} in {chain}; "
                f"found {len(matches)}"
            )

        if matches[0] != index:
            raise LabError(
                f"owned jump to {owned_chain} is not at position {index + 1} "
                f"in {chain}; effective order is ambiguous"
            )


def validate_firewall_chain_priority(
    chain: str,
    rules_output: str,
    expected_comments: list[str],
) -> None:
    """Reject unowned rules preceding each required project DROP rule."""
    rules = []

    for line in rules_output.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError as exc:
            raise LabError(f"cannot parse {chain} firewall rules: {exc}") from exc

        if len(tokens) >= 3 and tokens[:2] == ["-A", chain]:
            rules.append(tokens)

    positions: dict[str, list[int]] = {}
    for index, rule in enumerate(rules):
        if "--comment" in rule:
            marker = rule.index("--comment")
            if marker + 1 < len(rule):
                positions.setdefault(rule[marker + 1], []).append(index)

    for comment in expected_comments:
        found = positions.get(comment, [])

        if len(found) != 1:
            raise LabError(
                f"expected exactly one installed rule {comment}; found {len(found)}"
            )

        for prior in rules[:found[0]]:
            prior_comment = None
            if "--comment" in prior:
                marker = prior.index("--comment")
                if marker + 1 < len(prior):
                    prior_comment = prior[marker + 1]

            if not prior_comment or not prior_comment.startswith(
                "ithoka-sec-lab-"
            ):
                raise LabError(
                    f"unowned firewall rule precedes {comment} in {chain}; "
                    "effective enforcement is ambiguous"
                )


def validate_network_setup(
    root: Path,
    runner: Any = subprocess.run,
) -> dict[str, Any]:
    """Check read-only machine prerequisites independently of experiments."""
    machine = validate_machine_configuration(root)

    for command in ("docker", "sudo", "iptables", "ip6tables"):
        if shutil.which(command) is None:
            raise LabError(f"network setup requires command in PATH: {command}")

    def run_checked(command: list[str], label: str) -> str:
        try:
            result = runner(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LabError(f"network setup could not {label}: {exc}") from exc

        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit {result.returncode}"
            raise LabError(f"network setup could not {label}: {detail}")

        return result.stdout.strip()

    context = run_checked(["docker", "context", "show"], "read Docker context")
    approved_context = machine["operator_confirmed"]["approved_docker_context"]

    if context != approved_context:
        raise LabError(
            "network setup Docker context does not match the operator-approved "
            f"context ({context})"
        )

    network_names = set(
        run_checked(
            ["docker", "network", "ls", "--format", "{{.Name}}"],
            "enumerate Docker networks",
        ).splitlines()
    )

    missing_defaults = {"bridge", "host", "none"} - network_names
    if missing_defaults:
        raise LabError(
            "network setup did not find the default Docker networks: "
            + ", ".join(sorted(missing_defaults))
        )

    backends = {}
    for command in ("iptables", "ip6tables"):
        version = run_checked(
            ["sudo", "-n", command, "--version"],
            f"read privileged {command} version",
        )

        match = re.search(r"\((legacy|nf_tables)\)$", version)
        if match is None:
            raise LabError(
                f"network setup cannot identify the {command} backend: {version}"
            )

        run_checked(
            ["sudo", "-n", command, "-S"],
            f"read privileged {command} rules",
        )
        backends[command] = match.group(1)

    if backends["iptables"] != backends["ip6tables"]:
        raise LabError(
            "network setup requires compatible IPv4 and IPv6 firewall backends; "
            f"found {backends['iptables']} and {backends['ip6tables']}"
        )

    selected_policy = resolve_network_policy(root)
    policy_error = None

    try:
        validate_runtime_support(selected_policy)
    except LabError as exc:
        policy_error = str(exc)

    return {
        "scope": "machine-prerequisites-only",
        "ready": True,
        "docker_context": context,
        "default_networks_observed": ["bridge", "host", "none"],
        "firewall_backends": backends,
        "firewall_rules_readable_as_root": True,
        "selected_profile": selected_policy["profile"],
        "policy_support": "declared-supported" if policy_error is None else "unsupported",
        "policy_capability_error": policy_error,
        "enforcement_verified": False,
        "runtime_acceptance": "not-run",
        "read_only": True,
    }


def _run_inventory(command: list[str], timeout: int = 10) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
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
        "docker_version": [
            "docker", "version", "--format", "{{.Server.Version}}"
        ],
        "docker_context": ["docker", "context", "show"],
        "docker_networks": ["docker", "network", "ls"],
        "docker_network_details": [
            "docker", "network", "ls", "--format",
            "{{.ID}} {{.Name}} {{.Driver}} {{.Scope}}",
        ],
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
        name: (
            _run_inventory(command)
            if availability[name]
            else "unavailable: command not found"
        )
        for name, command in commands.items()
    }

    release = platform.release()
    resolver_output = observations["resolvers"]

    return {
        "platform": {
            "system": platform.system(),
            "release": release,
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "wsl_indicators": {
            "is_wsl": (
                "microsoft" in release.lower()
                or "microsoft" in resolver_output.lower()
            ),
            "kernel_release": release,
        },
        "availability": availability,
        "observations": observations,
        "read_only": True,
        "enforcement_verified": False,
        "runtime_acceptance": "not-run",
    }


def validate_machine_configuration(
    root: Path = Path("."),
) -> dict[str, Any]:
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

    context = confirmed["approved_docker_context"]
    if (
        not isinstance(context, str)
        or not context.strip()
        or context.startswith("REPLACE_")
    ):
        raise LabError(
            f"{path}.operator_confirmed.approved_docker_context must be non-empty"
        )

    for key in ("approved_interfaces", "approved_networks"):
        if key in confirmed:
            if not isinstance(confirmed[key], list):
                raise LabError(f"{path}.operator_confirmed.{key} must be a list")
            if any(
                not isinstance(item, str) or not item.strip()
                for item in confirmed[key]
            ):
                raise LabError(
                    f"{path}.operator_confirmed.{key} must contain non-empty strings"
                )

    current_context = _run_inventory(["docker", "context", "show"])
    if current_context.startswith("unavailable:"):
        raise LabError(
            f"cannot determine the current Docker context: {current_context}"
        )

    if current_context != context:
        raise LabError(
            f"{path}.operator_confirmed.approved_docker_context does not match "
            f"the current Docker context ({current_context})"
        )

    return document


def configure_machine(
    root: Path = Path("."),
    overwrite: bool = False,
) -> Path:
    """Copy the machine template; never overwrite existing config by default."""
    destination = root / MACHINE_CONFIG

    if destination.exists() and not overwrite:
        raise LabError(f"machine network configuration already exists: {destination}")

    example = root / "config" / "networks" / "machine.yaml.example"
    if not example.is_file():
        raise LabError(f"machine network configuration template is missing: {example}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        example.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return destination


def inspect_owned_network(project: str) -> dict[str, Any]:
    """Inspect one investigation's owned internal bridge without modifying it."""
    if not re.fullmatch(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}", project):
        raise LabError("invalid investigation project")

    try:
        result = subprocess.run(
            [
                "docker", "network", "ls", "-q", "--no-trunc",
                "--filter", f"label=com.docker.compose.project={project}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LabError(f"cannot enumerate project network: {exc}") from exc

    if result.returncode != 0:
        raise LabError(f"cannot enumerate project network: {result.stderr.strip()}")

    ids = result.stdout.split()
    if len(ids) != 1:
        raise LabError(f"expected exactly one owned project network; found {len(ids)}")

    network_id = ids[0]
    if not re.fullmatch(r"[0-9a-f]{64}", network_id):
        raise LabError("Docker returned a malformed full project network ID")

    try:
        inspected = subprocess.run(
            [
                "docker", "network", "inspect", network_id,
                "--format", "{{json .}}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LabError(f"cannot inspect project network: {exc}") from exc

    if inspected.returncode != 0:
        raise LabError(f"cannot inspect project network: {inspected.stderr.strip()}")

    try:
        data = json.loads(inspected.stdout)
    except ValueError as exc:
        raise LabError("Docker returned invalid network inspection JSON") from exc

    if not isinstance(data, dict):
        raise LabError("Docker returned an invalid project network inspection")

    labels = data.get("Labels")
    if not isinstance(labels, dict):
        raise LabError("project network ownership labels are missing")

    if labels.get("io.ithoka.security-lab.owner") != "security-lab":
        raise LabError("project network is not owned by security-lab")

    if labels.get("io.ithoka.security-lab.investigation") != project.removeprefix(
        "sec-lab-i-"
    ):
        raise LabError("project network ownership does not match the investigation")

    if labels.get("com.docker.compose.project") != project:
        raise LabError(
            "project network is missing its matching Compose project label"
        )

    if data.get("Internal") is not True or data.get("Driver") != "bridge":
        raise LabError("project network is not an internal bridge")

    network_name = data.get("Name")
    if not isinstance(network_name, str) or not network_name:
        raise LabError("project network name is missing")

    if network_name in {"bridge", "host", "none"}:
        raise LabError("refusing to enforce a default Docker network")

    options = data.get("Options")
    if not isinstance(options, dict):
        options = {}

    bridge = options.get("com.docker.network.bridge.name")

    if not isinstance(bridge, str) or not bridge:
        ipam = data.get("IPAM")
        configs = ipam.get("Config") if isinstance(ipam, dict) else None

        if not isinstance(configs, list):
            raise LabError("project network IPAM configuration is missing")

        try:
            gateways = {
                str(ipaddress.ip_address(config["Gateway"]))
                for config in configs
                if isinstance(config, dict) and config.get("Gateway")
            }
        except ValueError as exc:
            raise LabError("project network has an invalid IPAM gateway") from exc

        if not gateways:
            raise LabError("project network has no resolvable Docker IPAM gateway")

        try:
            interfaces = subprocess.run(
                ["ip", "-j", "address", "show"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LabError(f"cannot resolve project bridge interface: {exc}") from exc

        if interfaces.returncode != 0:
            raise LabError(
                "cannot resolve project bridge interface: "
                + (interfaces.stderr.strip() or f"exit {interfaces.returncode}")
            )

        try:
            interface_data = json.loads(interfaces.stdout)
        except ValueError as exc:
            raise LabError("ip returned invalid interface inspection JSON") from exc

        if not isinstance(interface_data, list):
            raise LabError("ip returned invalid interface inspection JSON")

        matches = [
            interface.get("ifname")
            for interface in interface_data
            if isinstance(interface, dict)
            and gateways.issubset({
                address.get("local")
                for address in interface.get("addr_info", [])
                if isinstance(address, dict) and address.get("family") == "inet"
            })
        ]

        if len(matches) != 1 or not isinstance(matches[0], str):
            raise LabError(
                "expected exactly one bridge matching Docker IPAM gateways; "
                f"found {len(matches)}"
            )

        bridge = matches[0]

    return {
        "network_id": network_id,
        "name": network_name,
        "driver": data.get("Driver"),
        "internal": data.get("Internal"),
        "enable_ipv6": data.get("EnableIPv6"),
        "labels": labels,
        "ipam": data.get("IPAM", {}),
        "containers": data.get("Containers", {}),
        "bridge": bridge,
        "observed_utc": dt.datetime.now(dt.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "enforcement_verified": False,
        "runtime_acceptance": "not-run",
    }


def build_enforcement_plan(
    root: Path = Path("."),
    profile: str | None = None,
    machine_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a read-only plan; never describe the plan as applied enforcement."""
    policy = resolve_network_policy(root, profile)
    capability_report = {
        name: _boundary_capability(name, boundary)
        for name, boundary in policy["boundaries"].items()
    }

    unsupported = {
        name: capability["reason"]
        for name, capability in capability_report.items()
        if capability["status"] == "unsupported"
    }

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
            "capability": capability_report[name],
        })

    return {
        "plan_version": 2,
        "profile": policy["profile"],
        "policy": policy,
        "policy_identity": sha256_bytes(policy_json(policy).encode("utf-8")),
        "machine_configuration": machine,
        "operations": operations,
        "supported": not unsupported,
        "capability_error": unsupported or None,
        "apply_order": [
            "resolve_scope",
            "validate_capabilities",
            "apply_controls",
            "inspect_installed_controls",
            "verify_rule_state",
            "run_runtime_acceptance",
            "record_evidence",
        ],
        "enforcement_state": "not-applied",
        "runtime_acceptance": "not-run",
        "read_only": True,
    }


def select_network_profile(root: Path, profile: str) -> Path:
    """Select one known profile. This does not apply or verify its controls."""
    if profile not in list_network_profiles(root):
        raise LabError(f"unsupported network profile: {profile}")

    destination = root / "config" / "networks" / "active-profile"
    destination.write_text(profile + "\n", encoding="utf-8")
    return destination


def resolve_project_network_policy(
    root: Path,
    project: str,
    profile: str | None = None,
) -> dict[str, Any]:
    if not re.fullmatch(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}", project):
        raise LabError("invalid investigation project")

    pinned_path = root / "state" / "runtime" / f"{project}-network-policy.json"

    if not pinned_path.is_file():
        return resolve_network_policy(root, profile)

    try:
        pinned = json.loads(pinned_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LabError(
            f"cannot read pinned project network policy: {pinned_path}"
        ) from exc

    validate_policy(pinned, "pinned project network policy")

    if profile is not None and pinned["profile"] != profile:
        raise LabError(
            f"requested profile {profile} does not match the project's pinned "
            f"profile ({pinned['profile']})"
        )

    return pinned


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

    validate_policy(pinned, "pinned project network policy")
    current = resolve_network_policy(root)

    return {
        "project": project,
        "drifted": pinned != current,
        "pinned_profile": pinned.get("profile"),
        "active_profile": current.get("profile"),
        "pinned_provenance": pinned.get("provenance"),
        "active_provenance": current.get("provenance"),
        "enforcement_verified": False,
        "runtime_acceptance": "not-run",
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
    "network_capabilities",
    "resolve_project_network_policy",
    "resolve_network_policy",
    "select_network_profile",
    "validate_machine_configuration",
    "validate_network_setup",
    "validate_firewall_chain_priority",
    "validate_firewall_jump_order",
    "validate_firewall_jump_sequence",
    "validate_network_configuration",
    "validate_runtime_support",
    "validate_policy",
]