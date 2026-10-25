"""Read effective Linux firewall tables and backend information."""

from __future__ import annotations

import re
from typing import Any

from ...enforcement.models import EnforcementStatus
from ..command import run_command
from ..models import OSObservation, VerificationFinding

_CHAIN = re.compile(r"^:([^\s]+)\s+([^\s]+)\s+\[(\d+):(\d+)\]$")
_COUNTERS = re.compile(r"^\[(\d+):(\d+)\]\s+(.*)$")


def _parse_iptables_save(text: str) -> dict[str, Any]:
    table = None
    chains = []
    rules = []
    for line in text.splitlines():
        if line.startswith("*"):
            table = line[1:]
        elif line == "COMMIT":
            table = None
        elif table and line.startswith(":"):
            match = _CHAIN.fullmatch(line)
            if not match:
                raise ValueError(f"malformed chain declaration: {line}")
            chains.append({
                "table": table,
                "name": match.group(1),
                "policy": match.group(2),
                "packets": int(match.group(3)),
                "bytes": int(match.group(4)),
            })
        elif table and line.startswith("["):
            match = _COUNTERS.fullmatch(line)
            if not match:
                raise ValueError(f"malformed rule counter: {line}")
            rule_text = match.group(3)
            rules.append({
                "table": table,
                "ordinal": sum(1 for rule in rules if rule["table"] == table) + 1,
                "packets": int(match.group(1)),
                "bytes": int(match.group(2)),
                "specification": rule_text,
                "source_chain": (
                    rule_text.split()[1]
                    if rule_text.startswith("-A ") and len(rule_text.split()) > 1
                    else None
                ),
                "jump_target": _jump_target(rule_text),
            })
        elif table and line.startswith("-A "):
            rule_text = line
            rules.append({
                "table": table,
                "ordinal": sum(1 for rule in rules if rule["table"] == table) + 1,
                "packets": None,
                "bytes": None,
                "specification": rule_text,
                "source_chain": (
                    rule_text.split()[1] if len(rule_text.split()) > 1 else None
                ),
                "jump_target": _jump_target(rule_text),
            })
    return {"chains": chains, "rules": rules}


def _jump_target(rule: str) -> str | None:
    fields = rule.split()
    for flag in ("-j", "--jump", "-g", "--goto"):
        if flag in fields:
            index = fields.index(flag)
            if index + 1 < len(fields):
                return fields[index + 1]
    return None


def inspect_firewall(runner: Any = None) -> OSObservation:
    options = {} if runner is None else {"runner": runner}
    results = {}
    errors = []
    required_errors = []
    executions = []
    observed_utc = ""
    for family, command in (
        ("ipv4", ["iptables-save", "-c"]),
        ("ipv6", ["ip6tables-save", "-c"]),
        ("nftables", ["nft", "list", "ruleset"]),
    ):
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
        observed_utc = execution.finished_utc
        executions.append(execution.to_dict())
        if execution.status is EnforcementStatus.PASS:
            if family == "nftables":
                results[family] = {
                    "executable": execution.executable,
                    "ruleset": execution.stdout,
                }
            else:
                try:
                    version_match = re.search(
                        r"iptables-save\s+(v[0-9][^\s)]*)",
                        execution.stdout.splitlines()[0]
                        if execution.stdout.splitlines()
                        else "",
                    )
                    results[family] = {
                        "executable": execution.executable,
                        "version": version_match.group(1) if version_match else None,
                        "backend": (
                            "nf_tables"
                            if "nf_tables" in execution.stdout
                            else "legacy_or_unspecified"
                        ),
                        **_parse_iptables_save(execution.stdout),
                    }
                except ValueError as exc:
                    errors.append(f"{family}: {exc}")
                    if family in {"ipv4", "ipv6"}:
                        required_errors.append(f"{family}: {exc}")
        else:
            errors.append(f"{family}: {execution.reason}")
            if family in {"ipv4", "ipv6"}:
                required_errors.append(f"{family}: {execution.reason}")
    if (
        "ipv4" not in results
        or "ipv6" not in results
        or required_errors
    ):
        status = EnforcementStatus.UNKNOWN
    else:
        status = EnforcementStatus.PASS
    return OSObservation(
        "linux",
        "firewall",
        "inspect",
        "kernel firewall rulesets",
        "iptables-save/ip6tables-save/nft",
        observed_utc,
        status,
        values={**results, "command_executions": executions},
        parsed=not required_errors and "ipv4" in results and "ipv6" in results,
        errors=tuple(errors),
        permission_limitations=(
            ("root privileges may be required to read complete rulesets",)
            if errors
            else ()
        ),
        coverage_limitations=(
            "ruleset visibility is structural evidence, not packet-level acceptance",
            "nft and compatibility backends may expose overlapping rule state",
        ),
    )


def verify_rule_presence(
    observation: OSObservation,
    *,
    family: str,
    chain: str,
    expected: str,
) -> VerificationFinding:
    if observation.status is not EnforcementStatus.PASS:
        return VerificationFinding(
            "firewall-rule-presence",
            EnforcementStatus.UNKNOWN,
            expected,
            None,
            "firewall state was not completely observed",
        )
    family_state = (observation.values or {}).get(family)
    rules = family_state.get("rules") if isinstance(family_state, dict) else None
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
        if isinstance(rule, dict) and rule.get("source_chain") == chain
    ]
    passed = any(expected in rule.get("specification", "") for rule in matching)
    return VerificationFinding(
        "firewall-rule-presence",
        EnforcementStatus.PASS if passed else EnforcementStatus.FAIL,
        expected,
        matching,
        None if passed else "required rule was not observed in effective ruleset",
    )


def verify_jump_order(
    observation: OSObservation,
    *,
    family: str,
    builtin_chain: str,
    owned_chain: str,
) -> VerificationFinding:
    if observation.status is not EnforcementStatus.PASS:
        return VerificationFinding(
            "firewall-jump-order",
            EnforcementStatus.UNKNOWN,
            f"{owned_chain} is first in {builtin_chain}",
            None,
            "firewall state was not completely observed",
        )
    family_state = (observation.values or {}).get(family)
    rules = family_state.get("rules") if isinstance(family_state, dict) else None
    if not isinstance(rules, list):
        return VerificationFinding(
            "firewall-jump-order",
            EnforcementStatus.UNKNOWN,
            f"{owned_chain} is first in {builtin_chain}",
            None,
            f"{family} firewall rules are unavailable",
        )
    chain_rules = [
        rule for rule in rules
        if isinstance(rule, dict)
        and rule.get("table") == "filter"
        and rule.get("source_chain") == builtin_chain
    ]
    first_target = (
        chain_rules[0].get("jump_target")
        if chain_rules
        else None
    )
    passed = first_target == owned_chain
    return VerificationFinding(
        "firewall-jump-order",
        EnforcementStatus.PASS if passed else EnforcementStatus.FAIL,
        f"{owned_chain} is first in {builtin_chain}",
        {
            "first_rule": chain_rules[0] if chain_rules else None,
            "builtin_rule_count": len(chain_rules),
        },
        None if passed else "the owned firewall jump is absent or not first",
    )
