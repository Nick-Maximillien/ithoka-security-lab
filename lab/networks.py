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
import os
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

FIXED_DENY_BOUNDARIES = {
    "ipv4",
    "ipv6",
    "filesystem",
    "resource_access",
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

UNIMPLEMENTED_BOUNDARY_CODES = {
    "windows_host": "windows-firewall-required",
    "dns": "dedicated-enforcement-not-implemented",
    "proxies": "dedicated-enforcement-not-implemented",
    "capture": "runtime-capture-not-implemented",
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

        required_boundary_keys = {
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
        missing_keys = required_boundary_keys - boundary.keys()
        if missing_keys:
            raise LabError(
                f"{boundary_label} is missing required fields: "
                + ", ".join(sorted(missing_keys))
            )

        unknown_keys = set(boundary) - BOUNDARY_KEYS
        if unknown_keys:
            raise LabError(
                f"{boundary_label} has unsupported fields: "
                f"{', '.join(sorted(unknown_keys))}"
            )

        if type(boundary.get("enabled")) is not bool:
            raise LabError(f"{boundary_label}.enabled must be boolean")

        if boundary.get("mode") not in MODES:
            raise LabError(
                f"{boundary_label} has unsupported mode: {boundary.get('mode')!r}"
            )

        if boundary.get("direction") not in DIRECTIONS:
            raise LabError(f"{boundary_label}.direction is unsupported")

        for key in ("rules", "exceptions", "verification"):
            if not isinstance(boundary.get(key), list):
                raise LabError(f"{boundary_label}.{key} must be a list")

        for key in ("scope", "adapter", "description", "reason"):
            require_text(boundary[key], f"{boundary_label}.{key}")

        for index, rule in enumerate(boundary["rules"]):
            _validate_rule(rule, f"{boundary_label}.rules[{index}]")

        for index, rule in enumerate(boundary["exceptions"]):
            _validate_rule(rule, f"{boundary_label}.exceptions[{index}]")

        for index, requirement in enumerate(boundary["verification"]):
            if not isinstance(requirement, str) or not requirement.strip():
                raise LabError(
                    f"{boundary_label}.verification[{index}] must be non-empty text"
                )
        if len(boundary["verification"]) != len(set(boundary["verification"])):
            raise LabError(f"{boundary_label}.verification contains duplicates")

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

    path = root / "config" / "networks" / "profiles" / f"{profile}.yaml"
    if not path.is_file():
        raise LabError(f"network profile does not exist: {profile}")
    if profile not in CANONICAL_PROFILES:
        raise LabError(f"unsupported network profile: {profile}")
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
        require_mapping(
            selection,
            f"network profile {profile}.{name}",
            {"source", "overrides"},
        )

        if selection.get("source") != BOUNDARY_FILE_NAMES[name]:
            raise LabError(
                f"network profile {profile}.{name} references "
                "the wrong boundary source"
            )

        overrides = selection["overrides"]
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
    if name in FIXED_DENY_BOUNDARIES and (
        not boundary["enabled"] or boundary["mode"] != "deny"
    ):
        if name in {"filesystem", "resource_access"}:
            reason = (
                "controller-integrity: safeguards require this boundary "
                "to remain enabled in deny mode"
            )
        else:
            reason = "required-deny"
        return {
            "status": "unsupported",
            "reason": reason,
            "enforcement_verified": False,
            "acceptance": "not-run",
        }

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
            "reason": (
                f"{UNIMPLEMENTED_BOUNDARY_CODES[name]}: "
                f"{UNIMPLEMENTED_BOUNDARIES[name]}"
            ),
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
        problems.append("required-deny")

    if boundary.get("adapter") != requirement["adapter"]:
        problems.append(
            f"required adapter is {requirement['adapter']}"
        )

    verification = set(boundary["verification"])
    missing_verification = requirement["verification"] - verification
    unsupported_verification = (
        verification - requirement["verification"] - {"runtime_acceptance"}
    )
    if missing_verification or unsupported_verification:
        problems.append(
            "unsupported-verification requirements: "
            f"missing={sorted(missing_verification)}, "
            f"unsupported={sorted(unsupported_verification)}"
        )

    if boundary["rules"] or boundary["exceptions"]:
        problems.append(
            "custom-rules have no registered rule compiler"
        )

    if not boundary.get("scope"):
        problems.append("enforcement scope is unspecified")

    if name == "external_networks":
        problems.append(
            "runtime-acceptance-unavailable: runtime acceptance is mandatory "
            "and has not been implemented "
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
    from .osapi.docker.daemon import inspect_daemon
    from .osapi.docker.networks import inspect_networks
    from .osapi.linux.firewall import inspect_firewall
    from .osapi.linux.forwarding import inspect_forwarding
    from .osapi.linux.interfaces import inspect_interfaces
    from .osapi.linux.mounts import inspect_mounts
    from .osapi.linux.proxies import inspect_proxy_environment
    from .osapi.linux.resolvers import inspect_resolvers
    from .osapi.linux.routes import inspect_routes
    from .osapi.linux.sysctl import inspect_sysctl
    interface_report = inspect_interfaces()
    route_report = inspect_routes()
    forwarding_report = inspect_forwarding()
    sysctl_report = inspect_sysctl()
    firewall_report = inspect_firewall()
    resolver_report = inspect_resolvers()
    proxy_report = inspect_proxy_environment()
    mounts_report = inspect_mounts()
    daemon_report = inspect_daemon()
    docker_context = (
        daemon_report.values.get("active_context")
        if isinstance(daemon_report.values, dict)
        else None
    )
    docker_network_report = (
        inspect_networks(docker_context)
        if isinstance(docker_context, str)
        else None
    )
    docker_network_document = (
        docker_network_report.to_dict()
        if docker_network_report is not None
        else {
            "status": "UNKNOWN",
            "reason": "Docker context could not be observed",
            "values": None,
        }
    )
    def family_routes(family: str) -> list[dict[str, Any]]:
        routes = route_report.values or {}
        value = routes.get(family, [])
        return value if isinstance(value, list) else []

    def family_interfaces(family: str) -> list[dict[str, Any]]:
        wanted = "inet6" if family == "ipv6" else "inet"
        return [
            {
                "name": interface.get("name"),
                "operstate": interface.get("operstate"),
                "addresses": [
                    address
                    for address in interface.get("addresses", [])
                    if address.get("family") == wanted
                ],
            }
            for interface in interface_report.values or []
            if any(
                address.get("family") == wanted
                for address in interface.get("addresses", [])
            )
        ]

    def forward_value(key: str) -> str:
        record = (forwarding_report.values or {}).get(key)
        if isinstance(record, dict) and "value" in record:
            return str(record["value"])
        return "unavailable"

    observations: dict[str, Any] = {
        "interfaces": interface_report.to_dict(),
        "interfaces_ipv6": family_interfaces("ipv6"),
        "routes": family_routes("ipv4"),
        "routes_ipv6": family_routes("ipv6"),
        "ipv4_forwarding": forward_value("ipv4"),
        "ipv6_forwarding": forward_value("ipv6"),
        "resolvers": resolver_report.to_dict(),
        "docker_version": (
            daemon_report.values.get("daemon", {}).get("ServerVersion")
            if isinstance(daemon_report.values, dict)
            and isinstance(daemon_report.values.get("daemon"), dict)
            else "unavailable"
        ),
        "docker_context": docker_context or "unavailable",
        "docker_networks": docker_network_document,
        "docker_network_details": (
            docker_network_report.values if docker_network_report else None
        ),
        "compose_version": (
            daemon_report.values.get("compose_version")
            if isinstance(daemon_report.values, dict)
            else None
        ),
        "iptables_version": (
            firewall_report.values.get("ipv4", {}).get("version", "unavailable")
            if isinstance(firewall_report.values, dict)
            else "unavailable"
        ),
        "ip6tables_version": (
            firewall_report.values.get("ipv6", {}).get("version", "unavailable")
            if isinstance(firewall_report.values, dict)
            else "unavailable"
        ),
        "nftables_version": (
            "observed"
            if isinstance(firewall_report.values, dict)
            and firewall_report.values.get("nftables")
            else "unavailable"
        ),
        "iptables_rules": firewall_report.values,
        "ip6tables_rules": firewall_report.values,
        "sysctl": sysctl_report.to_dict(),
        "mounts": mounts_report.to_dict(),
        "proxy_environment": proxy_report.to_dict(),
    }
    availability = {
        "interfaces": interface_report.status.value == "PASS",
        "interfaces_ipv6": interface_report.status.value == "PASS",
        "routes": route_report.status.value == "PASS",
        "routes_ipv6": route_report.status.value == "PASS",
        "ipv4_forwarding": forward_value("ipv4") != "unavailable",
        "ipv6_forwarding": forward_value("ipv6") != "unavailable",
        "resolvers": resolver_report.status.value == "PASS",
        "docker_version": daemon_report.status.value == "PASS",
        "docker_context": docker_context is not None,
        "docker_networks": docker_network_report is not None
        and docker_network_report.status.value == "PASS",
        "docker_network_details": docker_network_report is not None
        and docker_network_report.status.value == "PASS",
        "compose_version": isinstance(daemon_report.values, dict)
        and daemon_report.values.get("compose_version") is not None,
        "iptables_version": isinstance(firewall_report.values, dict)
        and "ipv4" in firewall_report.values,
        "ip6tables_version": isinstance(firewall_report.values, dict)
        and "ipv6" in firewall_report.values,
        "nftables_version": isinstance(firewall_report.values, dict)
        and "nftables" in firewall_report.values,
        "iptables_rules": isinstance(firewall_report.values, dict)
        and "ipv4" in firewall_report.values,
        "ip6tables_rules": isinstance(firewall_report.values, dict)
        and "ipv6" in firewall_report.values,
    }

    release = platform.release()

    return {
        "platform": {
            "system": platform.system(),
            "release": release,
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "wsl_indicators": {
            "is_wsl": "microsoft" in release.lower(),
            "kernel_release": release,
        },
        "availability": availability,
        "observations": observations,
        "proxy_environment": {
            "configured_variable_names": (
                (proxy_report.values or {}).get("configured_variable_names", [])
            ),
            "values_redacted": True,
        },
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


def inspect_owned_network(
    project: str,
    docker_context: str | None = None,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Inspect one investigation's owned internal bridge without modifying it."""
    if not re.fullmatch(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}", project):
        raise LabError("invalid investigation project")

    docker = ["docker"]
    if docker_context is not None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", docker_context):
            raise LabError("invalid Docker context name")
        docker.extend(["--context", docker_context])
    if runner is None:
        runner = subprocess.run

    try:
        result = runner(
            docker + [
                "network", "ls", "-q", "--no-trunc",
                "--filter", f"label=com.docker.compose.project={project}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
            shell=False,
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
        inspected = runner(
            docker + [
                "network", "inspect", network_id,
                "--format", "{{json .}}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
            shell=False,
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
            interfaces = runner(
                ["ip", "-j", "address", "show"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
                shell=False,
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


def inspect_docker_project(
    project: str,
    root: Path = Path("."),
    runner: Any = subprocess.run,
) -> dict[str, Any]:
    """Inspect effective Docker controls for one owned project without mutation."""
    if not re.fullmatch(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}", project):
        raise LabError("invalid investigation project")

    def report(status: str, reason: str, **details: Any) -> dict[str, Any]:
        return {
            "status": status,
            "project": project,
            "read_only": True,
            "reason": reason,
            "findings": [],
            **details,
        }

    def run(command: list[str], label: str) -> str:
        try:
            completed = runner(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise LabError(f"cannot {label}: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip() or f"exit {completed.returncode}"
            raise LabError(f"cannot {label}: {detail}")
        return completed.stdout.strip()

    try:
        machine_document = load_yaml(root / MACHINE_CONFIG)
        if not isinstance(machine_document, dict):
            raise LabError("machine network configuration must be a mapping")
        confirmed = machine_document.get("operator_confirmed")
        if not isinstance(confirmed, dict):
            raise LabError("machine operator-confirmed settings are missing")
        approved_context = confirmed.get("approved_docker_context")
        if (
            not isinstance(approved_context, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", approved_context)
        ):
            raise LabError("approved Docker context name is invalid")
        active_context = run(["docker", "context", "show"], "read Docker context")
    except (LabError, KeyError, TypeError) as exc:
        return report("UNKNOWN", f"Docker context inspection is incomplete: {exc}")

    if active_context != approved_context:
        return report(
            "BLOCKED",
            "active Docker context does not match the operator-approved context",
            active_context=active_context,
            approved_context=approved_context,
        )

    try:
        validate_machine_configuration(root)
    except LabError as exc:
        return report(
            "UNKNOWN",
            f"operator-approved Docker context could not be validated: {exc}",
            active_context=active_context,
            approved_context=approved_context,
        )

    try:
        endpoint_text = run(
            [
                "docker", "context", "inspect", active_context,
                "--format", "{{json .Endpoints.docker}}",
            ],
            "inspect Docker context endpoint",
        )
        endpoint = json.loads(endpoint_text)
        if not isinstance(endpoint, dict) or not isinstance(endpoint.get("Host"), str):
            raise ValueError("context endpoint has no Docker Host")
    except (LabError, ValueError, TypeError) as exc:
        return report("UNKNOWN", f"Docker context endpoint is unavailable: {exc}")

    endpoint_scheme = endpoint["Host"].partition("://")[0].lower()
    if endpoint_scheme not in {"unix", "npipe"}:
        if endpoint_scheme in {"ssh", "tcp", "http", "https"}:
            return report(
                "BLOCKED",
                "remote Docker endpoints are not approved for lab workloads",
                active_context=active_context,
                endpoint_scheme=endpoint_scheme,
            )
        return report(
            "UNKNOWN",
            "Docker endpoint locality cannot be determined",
            active_context=active_context,
            endpoint_scheme=endpoint_scheme or "unknown",
        )

    docker = ["docker", "--context", active_context]
    try:
        daemon_text = run(
            [
                *docker,
                "info",
                "--format",
                "{{.ID}}|{{.Name}}|{{.ServerVersion}}|{{.OSType}}|{{.Architecture}}",
            ],
            "inspect Docker daemon identity",
        )
        daemon_fields = daemon_text.split("|")
        if len(daemon_fields) != 5 or any(not value for value in daemon_fields):
            raise ValueError("Docker daemon identity is incomplete")
        if daemon_fields[3].lower() != "linux":
            return report(
                "BLOCKED",
                "the lab's Linux/WSL Docker adapter does not support this daemon OS",
                active_context=active_context,
                endpoint_scheme=endpoint_scheme,
                daemon_os=daemon_fields[3],
            )

        network = inspect_owned_network(
            project,
            active_context,
            runner=runner,
        )
        container_listing = run(
            [
                *docker,
                "ps",
                "-aq",
                "--filter",
                f"label=com.docker.compose.project={project}",
            ],
            "enumerate project containers",
        )
        container_ids = container_listing.split()
        if not container_ids:
            return report(
                "UNKNOWN",
                "no Compose project containers are available for inspection",
                active_context=active_context,
                approved_context=approved_context,
                endpoint_scheme=endpoint_scheme,
                daemon={
                    "id": daemon_fields[0],
                    "name": daemon_fields[1],
                    "server_version": daemon_fields[2],
                    "os_type": daemon_fields[3],
                    "architecture": daemon_fields[4],
                },
                network={
                    "id": network["network_id"],
                    "name": network["name"],
                    "endpoint_count": len(network.get("containers", {})),
                },
            )
        if any(
            not re.fullmatch(r"[0-9a-fA-F]{12,64}", value)
            for value in container_ids
        ):
            raise ValueError("Docker returned a malformed container ID")

        inspected_text = run(
            [*docker, "inspect", *container_ids],
            "inspect project containers",
        )
        containers = json.loads(inspected_text)
        if (
            not isinstance(containers, list)
            or len(containers) != len(container_ids)
            or not all(isinstance(item, dict) for item in containers)
        ):
            raise ValueError("Docker returned an incomplete container inspection")
    except (LabError, ValueError, TypeError) as exc:
        return report(
            "UNKNOWN",
            f"project runtime inspection is incomplete: {exc}",
            active_context=active_context,
            endpoint_scheme=endpoint_scheme,
        )

    findings: list[dict[str, Any]] = []

    def check(name: str, passed: bool | None, observed: Any, expected: str) -> None:
        findings.append({
            "control": name,
            "status": (
                "PASS" if passed is True
                else "FAIL" if passed is False
                else "UNKNOWN"
            ),
            "observed": observed,
            "expected": expected,
        })

    network_name = network["name"]
    expected_investigation = project.removeprefix("sec-lab-i-")
    endpoints = network.get("containers", {})
    endpoint_ids = (
        {str(value).lower() for value in endpoints}
        if isinstance(endpoints, dict)
        else set()
    )
    inspected_ids = {
        str(item.get("Id", "")).lower()
        for item in containers
        if isinstance(item.get("Id"), str)
    }
    check(
        "network-endpoints-owned",
        (
            {value[:12] for value in endpoint_ids}
            == {value[:12] for value in inspected_ids}
            if isinstance(endpoints, dict)
            else None
        ),
        {
            "attached": sorted(value[:12] for value in endpoint_ids),
            "project_containers": sorted(value[:12] for value in inspected_ids),
        },
        "every project container is attached to the owned network and no foreign endpoint is attached",
    )
    check(
        "internal-bridge",
        network.get("internal") is True and network.get("driver") == "bridge",
        {"internal": network.get("internal"), "driver": network.get("driver")},
        "internal bridge network",
    )
    check(
        "ipv6-disabled",
        (
            network.get("enable_ipv6") is False
            if "enable_ipv6" in network
            else None
        ),
        network.get("enable_ipv6"),
        "IPv6 disabled on the project bridge",
    )

    summaries: list[dict[str, Any]] = []
    for container in containers:
        container_id = container.get("Id")
        config = container.get("Config")
        host = container.get("HostConfig")
        state = container.get("State")
        settings = container.get("NetworkSettings")
        if (
            not isinstance(container_id, str)
            or not all(isinstance(value, dict) for value in (config, host, state, settings))
        ):
            check(
                "container-inspection-complete",
                None,
                container_id[:12] if isinstance(container_id, str) else None,
                "container identity, Config, HostConfig, State, and NetworkSettings",
            )
            continue

        labels = config.get("Labels")
        labels = labels if isinstance(labels, dict) else {}
        check(
            "container-ownership",
            labels.get("io.ithoka.security-lab.owner") == "security-lab"
            and labels.get("io.ithoka.security-lab.investigation") == expected_investigation
            and labels.get("com.docker.compose.project") == project,
            {
                "container_id": container_id[:12],
                "owner": labels.get("io.ithoka.security-lab.owner"),
                "investigation": labels.get("io.ithoka.security-lab.investigation"),
                "compose_project": labels.get("com.docker.compose.project"),
            },
            "matching lab owner, investigation, and Compose project labels",
        )
        image_id = container.get("Image")
        check(
            "image-identity",
            (
                bool(re.fullmatch(r"sha256:[0-9a-fA-F]{64}", image_id))
                if isinstance(image_id, str)
                else None
            ),
            image_id,
            "resolved image content ID in sha256 form",
        )

        actual_networks = settings.get("Networks")
        attached_networks = (
            sorted(actual_networks) if isinstance(actual_networks, dict) else None
        )
        check(
            "network-attachments",
            attached_networks == [network_name],
            attached_networks,
            f"only the owned internal network {network_name}",
        )
        check(
            "host-network-mode",
            (
                host.get("NetworkMode") != "host"
                if isinstance(host.get("NetworkMode"), str)
                else None
            ),
            host.get("NetworkMode"),
            "not host network mode",
        )

        port_bindings = host.get("PortBindings")
        effective_ports = settings.get("Ports")

        def valid_port_map(value: Any, require_host_port: bool = False) -> bool:
            return value is None or (
                isinstance(value, dict)
                and all(
                    bindings is None
                    or (
                        isinstance(bindings, list)
                        and all(
                            isinstance(binding, dict)
                            and (
                                not require_host_port
                                or isinstance(binding.get("HostPort"), str)
                            )
                            for binding in bindings
                        )
                    )
                    for bindings in value.values()
                )
            )

        bound_ports = (
            [
                binding
                for values in port_bindings.values()
                if isinstance(values, list)
                for binding in values
            ]
            if isinstance(port_bindings, dict)
            else []
        )
        mapped_ports = (
            [
                binding
                for values in effective_ports.values()
                if isinstance(values, list)
                for binding in values
                if isinstance(binding, dict) and binding.get("HostPort")
            ]
            if isinstance(effective_ports, dict)
            else []
        )
        published_port_count = max(len(bound_ports), len(mapped_ports))
        port_maps_valid = (
            "PortBindings" in host
            and "Ports" in settings
            and valid_port_map(port_bindings)
            and valid_port_map(effective_ports, require_host_port=True)
        )
        check(
            "published-ports",
            not bound_ports and not mapped_ports if port_maps_valid else None,
            published_port_count,
            "no published host ports",
        )

        mounts = container.get("Mounts")
        mounts_valid = isinstance(mounts, list) and all(
            isinstance(mount, dict) for mount in mounts
        )
        check(
            "mount-inspection",
            mounts_valid if isinstance(mounts, list) else None,
            len(mounts) if isinstance(mounts, list) else None,
            "valid mount inspection list",
        )
        if not isinstance(mounts, list):
            mounts = []
        bind_mounts = [
            {
                "source": str(mount.get("Source", "")),
                "target": str(mount.get("Destination", "")),
            }
            for mount in mounts
            if isinstance(mount, dict) and mount.get("Type") == "bind"
        ]
        socket_mounts = [
            str(mount.get("Destination") or mount.get("Source") or "")
            for mount in mounts
            if isinstance(mount, dict)
            and (
                "docker.sock" in str(mount.get("Source", "")).lower()
                or "docker.sock" in str(mount.get("Destination", "")).lower()
            )
        ]
        check(
            "host-filesystem-mounts",
            not bind_mounts if mounts_valid else None,
            bind_mounts,
            "no host bind mounts",
        )
        check(
            "docker-socket-mounts",
            not socket_mounts if mounts_valid else None,
            socket_mounts,
            "no Docker socket mounts",
        )
        privileged = host.get("Privileged")
        check(
            "privileged-mode",
            privileged is False if isinstance(privileged, bool) else None,
            privileged,
            "Privileged=false",
        )
        cap_add = host.get("CapAdd")
        check(
            "capabilities",
            not cap_add if "CapAdd" in host and isinstance(cap_add, (list, type(None))) else None,
            cap_add or [] if isinstance(cap_add, (list, type(None))) else cap_add,
            "no added Linux capabilities",
        )
        cap_drop = host.get("CapDrop")
        check(
            "capabilities-dropped",
            (
                any(str(value).upper() == "ALL" for value in cap_drop)
                if isinstance(cap_drop, list)
                else None
            ),
            cap_drop,
            "all default Linux capabilities dropped",
        )
        devices = host.get("Devices")
        device_requests = host.get("DeviceRequests")
        check(
            "device-access",
            (
                not devices and not device_requests
                if "Devices" in host
                and "DeviceRequests" in host
                and isinstance(devices, (list, type(None)))
                and isinstance(device_requests, (list, type(None)))
                else None
            ),
            {"devices": devices or [], "device_requests": device_requests or []},
            "no host devices or device requests",
        )

        user = config.get("User")
        uid = user.split(":", 1)[0] if isinstance(user, str) else user
        if type(uid) is int:
            non_root = uid != 0
        elif isinstance(uid, str):
            normalized_uid = uid.strip().lower()
            if normalized_uid in {"", "0", "root"}:
                non_root = False
            elif normalized_uid.isdecimal():
                non_root = int(normalized_uid) != 0
            else:
                non_root = None
        else:
            non_root = None
        if "User" not in config:
            non_root = None
        check("non-root-user", non_root, user, "explicit non-root user")
        check(
            "read-only-root-filesystem",
            (
                host.get("ReadonlyRootfs") is True
                if isinstance(host.get("ReadonlyRootfs"), bool)
                else None
            ),
            host.get("ReadonlyRootfs"),
            "ReadonlyRootfs=true",
        )
        tmpfs = host.get("Tmpfs")
        if tmpfs is None:
            tmpfs_valid = True if "Tmpfs" in host else None
            tmpfs_count = 0
        elif isinstance(tmpfs, dict):
            tmpfs_count = len(tmpfs)
            tmpfs_valid = all(
                isinstance(path, str)
                and isinstance(options, str)
                and re.search(
                    r"(?:^|,)size=[1-9][0-9]*(?:[kKmMgG])?(?:,|$)",
                    options,
                )
                for path, options in tmpfs.items()
            )
        else:
            tmpfs_count = None
            tmpfs_valid = None
        check(
            "tmpfs-size-limits",
            tmpfs_valid,
            tmpfs_count,
            "each writable tmpfs has a positive explicit size limit",
        )

        memory = host.get("Memory")
        nano_cpus = host.get("NanoCpus")
        cpu_quota = host.get("CpuQuota")
        cpu_period = host.get("CpuPeriod")
        pids_limit = host.get("PidsLimit")
        check(
            "memory-limit",
            memory > 0 if type(memory) is int else None,
            memory,
            "positive memory limit in bytes",
        )
        check(
            "cpu-limit",
            (
                (type(nano_cpus) is int and nano_cpus > 0)
                or (
                    type(cpu_quota) is int
                    and cpu_quota > 0
                    and type(cpu_period) is int
                    and cpu_period > 0
                )
                if all(
                    key in host
                    for key in ("NanoCpus", "CpuQuota", "CpuPeriod")
                )
                else None
            ),
            {
                "nano_cpus": nano_cpus,
                "cpu_quota": cpu_quota,
                "cpu_period": cpu_period,
            },
            "positive NanoCpus or CPU quota and period",
        )
        check(
            "pid-limit",
            pids_limit > 0 if type(pids_limit) is int else None,
            pids_limit,
            "positive PidsLimit",
        )
        security_options = host.get("SecurityOpt")
        security_options_available = isinstance(security_options, list)
        security_options = security_options if security_options_available else []
        no_new_privileges = any(
            str(value).lower() in {"no-new-privileges", "no-new-privileges:true"}
            for value in security_options
        )
        check(
            "no-new-privileges",
            no_new_privileges if security_options_available else None,
            security_options,
            "no-new-privileges enabled",
        )

        summaries.append({
            "id": container_id[:12],
            "name": str(container.get("Name", "")).lstrip("/"),
            "image": config.get("Image"),
            "image_id": image_id,
            "running": state.get("Running"),
            "status": state.get("Status"),
            "network_mode": host.get("NetworkMode"),
            "network_attachments": attached_networks,
            "published_port_count": published_port_count,
            "mount_count": len(mounts),
            "tmpfs_count": tmpfs_count,
            "tmpfs": (
                [
                    {"target": path, "options": options}
                    for path, options in tmpfs.items()
                ]
                if isinstance(tmpfs, dict)
                else None
            ),
        })

    statuses = {item["status"] for item in findings}
    if "FAIL" in statuses:
        overall = "FAIL"
        reason = "one or more effective Docker runtime controls failed"
    elif "UNKNOWN" in statuses:
        overall = "UNKNOWN"
        reason = "one or more effective Docker runtime controls could not be verified"
    else:
        overall = "PASS"
        reason = "effective project Docker settings satisfy the inspected constraints"

    return report(
        overall,
        reason,
        active_context=active_context,
        approved_context=approved_context,
        endpoint_scheme=endpoint_scheme,
        locality_note=(
            "A local-socket endpoint does not establish the physical host or "
            "the Windows/WSL boundary."
        ),
        daemon={
            "id": daemon_fields[0],
            "name": daemon_fields[1],
            "server_version": daemon_fields[2],
            "os_type": daemon_fields[3],
            "architecture": daemon_fields[4],
        },
        network={
            "id": network["network_id"],
            "name": network_name,
            "network_id": network["network_id"],
            "network_name": network_name,
            "bridge": network.get("bridge"),
            "driver": network.get("driver"),
            "internal": network.get("internal"),
            "enable_ipv6": network.get("enable_ipv6"),
            "endpoint_count": len(endpoints),
        },
        containers=summaries,
        findings=findings,
    )


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
    "inspect_docker_project",
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