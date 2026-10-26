
"""Read effective Linux firewall tables and backend information."""

from __future__ import annotations

import re
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation, VerificationFinding


_CHAIN = re.compile(r"^:([^\s]+)\s+([^\s]+)\s+\[(\d+):(\d+)\]$")
_COUNTERS = re.compile(r"^\[(\d+):(\d+)\]\s+(.*)$")
_BACKEND = re.compile(r"iptables-save\s+(v[0-9][^\s)]*)")


def _jump_target(rule: str) -> str | None:
    """Return a rule's explicit jump or goto target, if present."""
    fields = rule.split()

    for flag in ("-j", "--jump", "-g", "--goto"):
        try:
            index = fields.index(flag)
        except ValueError:
            continue

        if index + 1 < len(fields):
            return fields[index + 1]

    return None


def _parse_iptables_save(text: str) -> dict[str, Any]:
    """Parse iptables-save output into the common observation schema."""
    table: str | None = None
    chains: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    ordinals: dict[str, int] = {}

    for line in text.splitlines():
        if line.startswith("*"):
            if len(line) == 1:
                raise ValueError("malformed table declaration")
            table = line[1:]
            continue

        if line == "COMMIT":
            if table is None:
                raise ValueError("COMMIT encountered outside a table")
            table = None
            continue

        if table is None:
            # Headers and comments outside a table are valid.
            continue

        if line.startswith(":"):
            match = _CHAIN.fullmatch(line)
            if not match:
                raise ValueError(f"malformed chain declaration: {line}")

            chains.append(
                {
                    "table": table,
                    "name": match.group(1),
                    "policy": match.group(2),
                    "packets": int(match.group(3)),
                    "bytes": int(match.group(4)),
                }
            )
            continue

        packets: int | None = None
        byte_count: int | None = None
        rule_text = line

        if line.startswith("["):
            match = _COUNTERS.fullmatch(line)
            if not match:
                raise ValueError(f"malformed rule counter: {line}")

            packets = int(match.group(1))
            byte_count = int(match.group(2))
            rule_text = match.group(3)

            if not rule_text.startswith("-A "):
                raise ValueError(f"counter entry is not a rule: {line}")

        if rule_text.startswith("-A "):
            fields = rule_text.split()
            if len(fields) < 2:
                raise ValueError(f"malformed rule specification: {line}")

            ordinals[table] = ordinals.get(table, 0) + 1

            rules.append(
                {
                    "table": table,
                    "ordinal": ordinals[table],
                    "packets": packets,
                    "bytes": byte_count,
                    "specification": rule_text,
                    "source_chain": fields[1],
                    "jump_target": _jump_target(rule_text),
                }
            )

    if table is not None:
        raise ValueError(f"table {table!r} is missing COMMIT")

    return {"chains": chains, "rules": rules}


def _run_firewall_command(
    command: list[str],
    *,
    options: dict[str, Any],
) -> Any:
    """Run a read-only firewall command, retrying with noninteractive sudo
    only when the original command failed due to insufficient privileges.
    """
    execution = run_command(command, **options)

    if (
        execution.status is not EnforcementStatus.PASS
        and execution.returncode is not None
        and any(
            hint in execution.stderr.lower()
            for hint in ("permission denied", "operation not permitted")
        )
    ):
        execution = run_command(["sudo", "-n", *command], **options)

    return execution


def inspect_firewall(runner: Any = None) -> OSObservation:
    """Observe IPv4 and IPv6 iptables rules and supplementary nftables state.

    The IPv4 and IPv6 compatibility rulesets are required for PASS because
    the enforcement adapter verifies its owned chains through those entries.
    nftables output is supplementary and cannot replace either observation.
    """
    options = {} if runner is None else {"runner": runner}

    results: dict[str, Any] = {}
    errors: list[str] = []
    required_errors: list[str] = []
    executions: list[dict[str, Any]] = []
    observed_utc = ""

    commands = (
        ("ipv4", ["iptables-save", "-c"]),
        ("ipv6", ["ip6tables-save", "-c"]),
        ("nftables", ["nft", "list", "ruleset"]),
    )

    for family, command in commands:
        execution = _run_firewall_command(command, options=options)
        observed_utc = execution.finished_utc
        executions.append(execution.to_dict())

        if execution.status is not EnforcementStatus.PASS:
            reason = execution.reason or "command failed"
            errors.append(f"{family}: {reason}")

            if family in {"ipv4", "ipv6"}:
                required_errors.append(f"{family}: {reason}")

            continue

        if family == "nftables":
            results[family] = {
                "executable": execution.executable,
                "ruleset": execution.stdout,
            }
            continue

        try:
            lines = execution.stdout.splitlines()
            header = lines[0] if lines else ""
            version_match = _BACKEND.search(header)

            parsed = _parse_iptables_save(execution.stdout)

            results[family] = {
                "executable": execution.executable,
                "version": (
                    version_match.group(1) if version_match else None
                ),
                "backend": (
                    "nf_tables"
                    if "nf_tables" in header
                    else "legacy_or_unspecified"
                ),
                **parsed,
            }
        except ValueError as exc:
            message = f"{family}: {exc}"
            errors.append(message)
            required_errors.append(message)

    required_families_present = (
        isinstance(results.get("ipv4"), dict)
        and isinstance(results.get("ipv6"), dict)
        and not required_errors
    )

    status = (
        EnforcementStatus.PASS
        if required_families_present
        else EnforcementStatus.UNKNOWN
    )

    return OSObservation(
        "linux",
        "firewall",
        "inspect",
        "kernel firewall rulesets",
        "iptables-save/ip6tables-save/nft",
        observed_utc,
        status,
        values={
            **results,
            "command_executions": executions,
        },
        parsed=required_families_present,
        errors=tuple(errors),
        permission_limitations=(
            (
                "root privileges may be required to read complete IPv4/IPv6 "
                "firewall rulesets"
            ,)
            if required_errors
            else ()
        ),
        coverage_limitations=(
            "ruleset visibility is structural evidence, not packet-level acceptance",
            "nft and compatibility backends may expose overlapping rule state",
            "nftables output is supplementary and does not replace IPv4/IPv6 observations",
        ),
    )


def verify_rule_presence(
    observation: OSObservation,
    *,
    family: str,
    chain: str,
    expected: str,
) -> VerificationFinding:
    """Verify that a rule containing the expected specification exists."""
    if observation.status is not EnforcementStatus.PASS:
        return VerificationFinding(
            "firewall-rule-presence",
            EnforcementStatus.UNKNOWN,
            expected,
            None,
            "firewall state was not completely observed",
        )

    values = observation.values
    family_state = values.get(family) if isinstance(values, dict) else None
    rules = (
        family_state.get("rules")
        if isinstance(family_state, dict)
        else None
    )

    if not isinstance(rules, list):
        return VerificationFinding(
            "firewall-rule-presence",
            EnforcementStatus.UNKNOWN,
            expected,
            None,
            f"{family} firewall rules are unavailable",
        )

    matching = [
        rule
        for rule in rules
        if isinstance(rule, dict)
        and rule.get("table") == "filter"
        and rule.get("source_chain") == chain
    ]

    passed = any(
        expected in rule.get("specification", "")
        for rule in matching
        if isinstance(rule.get("specification"), str)
    )

    return VerificationFinding(
        "firewall-rule-presence",
        EnforcementStatus.PASS if passed else EnforcementStatus.FAIL,
        expected,
        matching,
        (
            None
            if passed
            else "required rule was not observed in the effective filter ruleset"
        ),
    )


def verify_jump_order(
    observation: OSObservation,
    *,
    family: str,
    builtin_chain: str,
    owned_chain: str,
) -> VerificationFinding:
    """Verify that the first filter-table rule in a built-in chain jumps
    to the expected owned chain.
    """
    expected = f"{owned_chain} is first in {builtin_chain}"

    if observation.status is not EnforcementStatus.PASS:
        return VerificationFinding(
            "firewall-jump-order",
            EnforcementStatus.UNKNOWN,
            expected,
            None,
            "firewall state was not completely observed",
        )

    values = observation.values
    family_state = values.get(family) if isinstance(values, dict) else None
    rules = (
        family_state.get("rules")
        if isinstance(family_state, dict)
        else None
    )

    if not isinstance(rules, list):
        return VerificationFinding(
            "firewall-jump-order",
            EnforcementStatus.UNKNOWN,
            expected,
            None,
            f"{family} firewall rules are unavailable",
        )

    chain_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict)
        and rule.get("table") == "filter"
        and rule.get("source_chain") == builtin_chain
    ]

    first_rule = chain_rules[0] if chain_rules else None
    first_target = (
        first_rule.get("jump_target")
        if isinstance(first_rule, dict)
        else None
    )
    passed = first_target == owned_chain

    return VerificationFinding(
        "firewall-jump-order",
        EnforcementStatus.PASS if passed else EnforcementStatus.FAIL,
        expected,
        {
            "first_rule": first_rule,
            "builtin_rule_count": len(chain_rules),
        },
        (
            None
            if passed
            else "the owned firewall jump is absent or not first"
        ),
    )
