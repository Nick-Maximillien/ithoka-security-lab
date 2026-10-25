#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATE_DIR="$ROOT/state/network-boundary"

OWNER="security-lab"
PROJECT_RE='^sec-lab-i-[a-z0-9][a-z0-9-]{0,31}$'

# This adapter enforces only the explicitly supported Linux/WSL boundaries.
# All other boundaries are checked and rejected if enabled.
SUPPORTED_BOUNDARIES=(
    lab_ingress
    lab_egress
    external_networks
    ipv4
    ipv6
)

UNSUPPORTED_BOUNDARIES=(
    windows_host
    dns
    proxies
    capture
)

CONFIGURATION_VALIDATED_BOUNDARIES=(
    docker_networks
    filesystem
    resource_access
)

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 ||
        fail "required command not found: $1"
}

root_cmd() {
    sudo -n "$@"
}

[[ $# -eq 3 ]] ||
    fail "usage: $0 {apply|verify|remove} sec-lab-i-<investigation-id> policy.json"

ACTION="$1"
PROJECT="$2"
POLICY_FILE="$3"

[[ "$PROJECT" =~ $PROJECT_RE ]] ||
    fail "invalid project name: $PROJECT"

[[ -f "$POLICY_FILE" && ! -L "$POLICY_FILE" ]] ||
    fail "policy file must be an existing regular, non-symlink file"

case "$ACTION" in
    apply|verify|remove) ;;
    *) fail "unsupported action: $ACTION" ;;
esac

need docker
need sudo
need iptables
need ip6tables
need sha256sum
need python3
need ip
need grep
need sed
need cut

STATE_DIR="$ROOT/state/network-boundary"
state_file="$STATE_DIR/$PROJECT.env"

comment_base="ithoka-sec-lab-${PROJECT}"
project_suffix="$(printf '%s' "$PROJECT" | sha256sum | cut -c1-10)"

CHAIN4="SLB${project_suffix}4"
CHAIN6="SLB${project_suffix}6"
EXT_CHAIN4="SLX${project_suffix}E4"
EXT_CHAIN6="SLX${project_suffix}E6"

POLICY_SHA256="$(sha256sum "$POLICY_FILE" | cut -d ' ' -f 1)"

# Values populated by network_details or load_saved_state.
NETWORK_ID=""
BRIDGE=""
SUBNETS=""
PROJECT_SAVED=""
STATE_POLICY_SHA256=""

# ---------------------------------------------------------------------------
# Policy parsing and validation
#
# The policy definition is not enforcement evidence.
# This script validates the definition, applies supported controls, and
# verifies the installed firewall rules. Independent runtime acceptance
# evidence is produced and checked elsewhere.
# ---------------------------------------------------------------------------

policy_value() {
    local boundary="$1"
    local key="$2"

    python3 - "$POLICY_FILE" "$boundary" "$key" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        policy = json.load(stream)

    value = policy["boundaries"][sys.argv[2]][sys.argv[3]]

    if isinstance(value, bool):
        print("true" if value else "false")
    elif isinstance(value, (str, int, float)):
        print(value)
    else:
        print(json.dumps(value, sort_keys=True))
except (OSError, ValueError, KeyError, TypeError) as exc:
    print(f"invalid policy field: {exc}", file=sys.stderr)
    raise SystemExit(2)
PY
}

policy_has_verification() {
    python3 - "$POLICY_FILE" "$1" "$2" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        policy = json.load(stream)

    verification = policy["boundaries"][sys.argv[2]]["verification"]
    if not isinstance(verification, list):
        raise ValueError("verification must be a list")

    raise SystemExit(0 if sys.argv[3] in verification else 1)
except (OSError, ValueError, KeyError, TypeError) as exc:
    print(f"invalid verification policy: {exc}", file=sys.stderr)
    raise SystemExit(2)
PY
}

policy_verification_is() {
    python3 - "$POLICY_FILE" "$1" "${@:2}" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        policy = json.load(stream)

    actual = policy["boundaries"][sys.argv[2]]["verification"]
    if not isinstance(actual, list) or not all(
        isinstance(item, str) for item in actual
    ):
        raise ValueError("verification must be a list of strings")

    raise SystemExit(0 if set(actual) == set(sys.argv[3:]) else 1)
except (OSError, ValueError, KeyError, TypeError) as exc:
    print(f"invalid verification policy: {exc}", file=sys.stderr)
    raise SystemExit(2)
PY
}

validate_policy_document() {
    python3 - "$POLICY_FILE" <<'PY'
import json
import sys

SUPPORTED = {
    "lab_ingress",
    "lab_egress",
    "external_networks",
    "ipv4",
    "ipv6",
}

UNSUPPORTED = {
    "windows_host",
    "dns",
    "proxies",
    "capture",
}

CONFIGURATION_VALIDATED = {
    "docker_networks",
    "filesystem",
    "resource_access",
}

EXPECTED = SUPPORTED | UNSUPPORTED | CONFIGURATION_VALIDATED

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        policy = json.load(stream)

    if not isinstance(policy, dict):
        raise ValueError("policy root must be an object")

    boundaries = policy.get("boundaries")
    if not isinstance(boundaries, dict):
        raise ValueError("policy.boundaries must be an object")

    missing = EXPECTED - set(boundaries)
    if missing:
        raise ValueError(
            "policy is missing required boundaries: "
            + ", ".join(sorted(missing))
        )

    for name in sorted(EXPECTED):
        boundary = boundaries[name]

        if not isinstance(boundary, dict):
            raise ValueError(f"{name} must be an object")

        enabled = boundary.get("enabled")
        if not isinstance(enabled, bool):
            raise ValueError(f"{name}.enabled must be a boolean")

        for field in ("mode", "scope", "adapter", "rules", "exceptions",
                      "verification"):
            if field not in boundary:
                raise ValueError(f"{name}.{field} is missing")

        if not isinstance(boundary["mode"], str):
            raise ValueError(f"{name}.mode must be a string")
        if not isinstance(boundary["scope"], str):
            raise ValueError(f"{name}.scope must be a string")
        if not isinstance(boundary["adapter"], str):
            raise ValueError(f"{name}.adapter must be a string")
        if not isinstance(boundary["rules"], list):
            raise ValueError(f"{name}.rules must be a list")
        if not isinstance(boundary["exceptions"], list):
            raise ValueError(f"{name}.exceptions must be a list")
        if not isinstance(boundary["verification"], list):
            raise ValueError(f"{name}.verification must be a list")

        if not all(isinstance(item, str) for item in boundary["verification"]):
            raise ValueError(f"{name}.verification must contain strings")

    enabled_unsupported = sorted(
        name for name in UNSUPPORTED if boundaries[name]["enabled"]
    )
    if enabled_unsupported:
        raise ValueError(
            "enabled boundaries are unsupported by the Linux/WSL adapter: "
            + ", ".join(enabled_unsupported)
        )

    for name in CONFIGURATION_VALIDATED:
        boundary = boundaries[name]
        if boundary["enabled"] and boundary["mode"] != "deny":
            raise ValueError(f"{name} must remain in deny mode")
        if boundary["enabled"] and boundary["adapter"] != "docker-compose":
            raise ValueError(f"{name} requires adapter=docker-compose")

    # This adapter intentionally implements a strict deny-only profile.
    for name in SUPPORTED:
        boundary = boundaries[name]

        if not boundary["enabled"]:
            raise ValueError(
                f"{name} must be enabled for this enforcement adapter"
            )
        if boundary["mode"] != "deny":
            raise ValueError(
                f"{name} must use mode=deny; got {boundary['mode']!r}"
            )
        if boundary["adapter"] != "linux-wsl":
            raise ValueError(
                f"{name} requires adapter=linux-wsl; "
                f"got {boundary['adapter']!r}"
            )
        if boundary["rules"] != []:
            raise ValueError(
                f"{name} custom rules are not supported by this adapter"
            )
        if boundary["exceptions"] != []:
            raise ValueError(
                f"{name} exceptions are not supported by this adapter"
            )

    expected_scopes = {
        "ipv4": "investigation-bridge",
        "ipv6": "investigation-bridge",
        "lab_ingress": "investigation-network",
        "lab_egress": "investigation-network",
        "external_networks": "lan-internet-vpn",
    }

    expected_verification = {
        "ipv4": {"iptables"},
        "ipv6": {"ip6tables"},
        "lab_ingress": {"iptables", "ip6tables"},
        "lab_egress": {"iptables", "ip6tables"},
        "external_networks": {"forwarding_rules", "runtime_acceptance"},
    }

    for name, scope in expected_scopes.items():
        actual = boundaries[name]["scope"]
        if actual != scope:
            raise ValueError(
                f"{name}.scope must be {scope!r}; got {actual!r}"
            )

    for name, expected in expected_verification.items():
        actual = boundaries[name]["verification"]
        actual_set = set(actual)
        unsupported = actual_set - expected - {"runtime_acceptance"}
        if (
            not expected.issubset(actual_set)
            or unsupported
            or len(actual) != len(actual_set)
        ):
            raise ValueError(
                f"{name}.verification does not match the adapter contract: "
                f"required={sorted(expected)!r}, got={actual!r}"
            )

    print("Policy schema: VALID")
    print("Supported policy boundaries: " + ", ".join(sorted(SUPPORTED)))
    print("Unsupported boundaries: disabled")

except (OSError, ValueError, KeyError, TypeError) as exc:
    print(f"FAIL: invalid or unsupported network policy: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
}

require_supported_policy() {
    validate_policy_document >/dev/null ||
        fail "policy definition is invalid or requests unsupported enforcement"
}

# ---------------------------------------------------------------------------
# Privileged firewall prerequisites
# ---------------------------------------------------------------------------

check_firewall_prerequisites() {
    local v4_version v6_version v4_backend v6_backend

    v4_version="$(root_cmd iptables --version)" ||
        fail "cannot read privileged iptables version"

    v6_version="$(root_cmd ip6tables --version)" ||
        fail "cannot read privileged ip6tables version"

    [[ "$v4_version" =~ \((legacy|nf_tables)\)$ ]] ||
        fail "cannot identify iptables backend: $v4_version"
    v4_backend="${BASH_REMATCH[1]}"

    [[ "$v6_version" =~ \((legacy|nf_tables)\)$ ]] ||
        fail "cannot identify ip6tables backend: $v6_version"
    v6_backend="${BASH_REMATCH[1]}"

    [[ "$v4_backend" == "$v6_backend" ]] ||
        fail "IPv4 and IPv6 firewall backends differ: $v4_backend and $v6_backend"

    root_cmd iptables -S >/dev/null ||
        fail "cannot read privileged IPv4 firewall rules"

    root_cmd ip6tables -S >/dev/null ||
        fail "cannot read privileged IPv6 firewall rules"

    root_cmd iptables -m comment -h >/dev/null 2>&1 ||
        fail "iptables comment matching is unavailable"

    root_cmd ip6tables -m comment -h >/dev/null 2>&1 ||
        fail "ip6tables comment matching is unavailable"
}

# ---------------------------------------------------------------------------
# Firewall jump-order validation
# ---------------------------------------------------------------------------

check_jump_order() {
    local tool="$1"
    local builtin="$2"
    local chain="$3"
    local comment="$4"
    local rules

    rules="$(root_cmd "$tool" -S "$builtin")" ||
        return 1

    FIREWALL_RULES="$rules" PYTHONPATH="$ROOT" python3 -c '
import os
import sys
from lab.foundation import LabError
from lab.networks import validate_firewall_jump_order

try:
    validate_firewall_jump_order(
        sys.argv[1],
        os.environ["FIREWALL_RULES"],
        sys.argv[2],
        sys.argv[3],
    )
except LabError as exc:
    print(exc, file=sys.stderr)
    raise SystemExit(1)
' "$builtin" "$chain" "$comment"
}

check_jump_sequence() {
    local tool="$1"
    local builtin="$2"
    local rules

    shift 2
    rules="$(root_cmd "$tool" -S "$builtin")" ||
        return 1

    FIREWALL_RULES="$rules" PYTHONPATH="$ROOT" python3 -c '
import os
import sys
from lab.foundation import LabError
from lab.networks import validate_firewall_jump_sequence

chain = sys.argv[1]
arguments = sys.argv[2:]

if len(arguments) == 0 or len(arguments) % 2:
    raise SystemExit("expected chain/comment pairs")

try:
    validate_firewall_jump_sequence(
        chain,
        os.environ["FIREWALL_RULES"],
        list(zip(arguments[0::2], arguments[1::2])),
    )
except LabError as exc:
    print(exc, file=sys.stderr)
    raise SystemExit(1)
' "$builtin" "$@"
}

# ---------------------------------------------------------------------------
# Docker network discovery and ownership
# ---------------------------------------------------------------------------

network_details() {
    local ids count detail network_name bridge gateways

    ids="$(docker network ls -q --no-trunc \
        --filter "label=com.docker.compose.project=$PROJECT")" ||
        fail "cannot enumerate networks for $PROJECT"

    count="$(printf '%s\n' "$ids" |
        sed '/^[[:space:]]*$/d' |
        wc -l |
        tr -d ' ')"

    [[ "$count" == 1 ]] ||
        fail "expected exactly one project network; found $count"

    NETWORK_ID="$(printf '%s\n' "$ids" | sed -n '1p')"

    detail="$(docker network inspect --format \
        '{{.Internal}}|{{.Driver}}|{{index .Labels "com.docker.compose.project"}}|{{index .Labels "io.ithoka.security-lab.owner"}}|{{index .Labels "io.ithoka.security-lab.investigation"}}' \
        "$NETWORK_ID")" ||
        fail "cannot inspect project network"

    [[ "$detail" == "true|bridge|$PROJECT|$OWNER|${PROJECT#sec-lab-i-}" ]] ||
        fail "network is not an owned internal bridge (actual: $detail)"

    [[ "$NETWORK_ID" =~ ^[0-9a-f]{64}$ ]] ||
        fail "Docker returned a malformed full network ID"

    network_name="$(docker network inspect --format '{{.Name}}' "$NETWORK_ID")" ||
        fail "cannot inspect project network name"

    [[ "$network_name" != bridge &&
       "$network_name" != host &&
       "$network_name" != none ]] ||
        fail "refusing to enforce a default Docker network"

    bridge="$(docker network inspect --format \
        '{{index .Options "com.docker.network.bridge.name"}}' "$NETWORK_ID")" ||
        fail "cannot inspect Docker bridge options"

    if [[ -z "$bridge" || "$bridge" == "<no value>" ]]; then
        gateways="$(docker network inspect --format '{{json .IPAM.Config}}' "$NETWORK_ID")" ||
            fail "cannot inspect project network gateways"

        bridge="$(ip -j address show | python3 -c '
import ipaddress
import json
import sys

try:
    configs = json.loads(sys.argv[1])
    interfaces = json.load(sys.stdin)

    gateways = {
        str(ipaddress.ip_address(item["Gateway"]))
        for item in configs
        if isinstance(item, dict) and item.get("Gateway")
    }

    if not gateways:
        raise ValueError("project network has no resolvable IPAM gateway")

    matches = []
    for interface in interfaces:
        addresses = {
            address["local"]
            for address in interface.get("addr_info", [])
            if address.get("family") == "inet"
        }
        if gateways.issubset(addresses):
            matches.append(interface["ifname"])

    if len(matches) != 1:
        raise ValueError(
            f"expected one bridge matching Docker IPAM gateways; found {len(matches)}"
        )

    print(matches[0])
except (ValueError, KeyError, TypeError, OSError) as exc:
    print(exc, file=sys.stderr)
    raise SystemExit(1)
' "$gateways")" ||
            fail "cannot resolve Docker bridge from inspected IPAM gateways"
    fi

    [[ "$bridge" =~ ^[A-Za-z0-9_.:-]+$ && -n "$bridge" ]] ||
        fail "Docker did not report an approved bridge name"

    [[ "$bridge" != docker0 ]] ||
        fail "refusing to enforce the default Docker bridge interface"

    BRIDGE="$bridge"

    [[ -d "/sys/class/net/$BRIDGE/bridge" ]] ||
        fail "expected Linux bridge interface is absent: $BRIDGE"

    SUBNETS="$(docker network inspect --format \
        '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$NETWORK_ID")" ||
        fail "cannot resolve Docker network subnets"

    [[ -n "$SUBNETS" ]] ||
        fail "owned Docker network has no resolved subnet"
}

# ---------------------------------------------------------------------------
# State persistence
#
# The file is data, never sourced as shell code.
# It binds the firewall state to project, network, bridge, subnets and policy.
# ---------------------------------------------------------------------------

load_saved_state() {
    [[ -f "$state_file" && ! -L "$state_file" ]] ||
        fail "boundary state file is missing or is a symlink: $state_file"

    local parsed
    parsed="$(python3 - "$state_file" <<'PY'
import re
import sys

required = {"PROJECT", "NETWORK_ID", "BRIDGE", "SUBNETS", "POLICY_SHA256"}
values = {}

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        for raw in stream:
            line = raw.rstrip("\n")
            if not line:
                continue
            if "=" not in line:
                raise ValueError("malformed state line")
            key, value = line.split("=", 1)
            if key not in required:
                raise ValueError(f"unknown state key: {key}")
            if key in values:
                raise ValueError(f"duplicate state key: {key}")
            values[key] = value

    if set(values) != required:
        raise ValueError("state file has missing or unexpected fields")

    if not re.fullmatch(r"sec-lab-i-[a-z0-9][a-z0-9-]{0,31}", values["PROJECT"]):
        raise ValueError("invalid saved project name")
    if not re.fullmatch(r"[0-9a-f]{64}", values["NETWORK_ID"]):
        raise ValueError("malformed saved network ID")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", values["BRIDGE"]):
        raise ValueError("malformed saved bridge")
    if not values["SUBNETS"]:
        raise ValueError("saved subnets are missing")
    if not re.fullmatch(r"[0-9a-f]{64}", values["POLICY_SHA256"]):
        raise ValueError("malformed saved policy hash")

    for key in ("PROJECT", "NETWORK_ID", "BRIDGE", "SUBNETS", "POLICY_SHA256"):
        print(f"{key}={values[key]}")
except (OSError, ValueError) as exc:
    print(f"invalid boundary state: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
)" || fail "cannot parse saved boundary state"

    PROJECT_SAVED="$(printf '%s\n' "$parsed" | sed -n 's/^PROJECT=//p')"
    NETWORK_ID="$(printf '%s\n' "$parsed" | sed -n 's/^NETWORK_ID=//p')"
    BRIDGE="$(printf '%s\n' "$parsed" | sed -n 's/^BRIDGE=//p')"
    SUBNETS="$(printf '%s\n' "$parsed" | sed -n 's/^SUBNETS=//p')"
    STATE_POLICY_SHA256="$(printf '%s\n' "$parsed" | sed -n 's/^POLICY_SHA256=//p')"

    [[ "$PROJECT_SAVED" == "$PROJECT" ]] ||
        fail "boundary state belongs to another project"

    [[ "$STATE_POLICY_SHA256" == "$POLICY_SHA256" ]] ||
        fail "policy hash differs from the policy pinned at apply time"
}

save_state() {
    local tmp

    mkdir -p -- "$STATE_DIR"
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] ||
        fail "boundary state directory must not be a symlink"

    tmp="$(mktemp "$STATE_DIR/.${PROJECT}.env.XXXXXX")" ||
        fail "cannot create temporary boundary state"

    if ! printf 'PROJECT=%s\nNETWORK_ID=%s\nBRIDGE=%s\nSUBNETS=%s\nPOLICY_SHA256=%s\n' \
        "$PROJECT" "$NETWORK_ID" "$BRIDGE" "$SUBNETS" "$POLICY_SHA256" > "$tmp"; then
        rm -f -- "$tmp"
        fail "cannot write boundary state"
    fi

    chmod 600 "$tmp" ||
        fail "cannot secure temporary boundary state"

    mv -f -- "$tmp" "$state_file" ||
        fail "cannot commit boundary state"
}

check_current_identity_matches_state() {
    local current_network_id="$NETWORK_ID"
    local current_bridge="$BRIDGE"
    local current_subnets="$SUBNETS"

    load_saved_state

    [[ "$current_network_id" == "$NETWORK_ID" ]] ||
        fail "project network identity changed"

    [[ "$current_bridge" == "$BRIDGE" ]] ||
        fail "project bridge identity changed"

    [[ "$current_subnets" == "$SUBNETS" ]] ||
        fail "project subnet identity changed"
}

# ---------------------------------------------------------------------------
# General owned chains: block host and forwarded paths involving the bridge.
# ---------------------------------------------------------------------------

ensure_owned_chain() {
    local tool="$1" chain="$2" in_comment="$3" out_comment="$4" bridge="$5"
    local rules line

    if ! root_cmd "$tool" -S "$chain" >/dev/null 2>&1; then
        root_cmd "$tool" -N "$chain" ||
            fail "could not create owned chain $chain"
    fi

    rules="$(root_cmd "$tool" -S "$chain")" ||
        fail "cannot inspect owned chain $chain"

    while IFS= read -r line; do
        [[ -z "$line" ||
           "$line" == "-N $chain" ||
           "$line" == "-A $chain -i $bridge -m comment --comment $in_comment -j DROP" ||
           "$line" == "-A $chain -o $bridge -m comment --comment $out_comment -j DROP" ||
           "$line" == "-A $chain -m comment --comment ${comment_base}-return -j RETURN" ]] ||
            fail "owned chain $chain contains an unknown rule; refusing mutation"
    done <<< "$rules"

    root_cmd "$tool" -C "$chain" \
        -i "$bridge" -m comment --comment "$in_comment" -j DROP >/dev/null 2>&1 ||
        root_cmd "$tool" -A "$chain" \
            -i "$bridge" -m comment --comment "$in_comment" -j DROP ||
        fail "could not add bridge ingress drop to $chain"

    root_cmd "$tool" -C "$chain" \
        -o "$bridge" -m comment --comment "$out_comment" -j DROP >/dev/null 2>&1 ||
        root_cmd "$tool" -A "$chain" \
            -o "$bridge" -m comment --comment "$out_comment" -j DROP ||
        fail "could not add bridge egress drop to $chain"

    root_cmd "$tool" -C "$chain" \
        -m comment --comment "${comment_base}-return" -j RETURN >/dev/null 2>&1 ||
        root_cmd "$tool" -A "$chain" \
            -m comment --comment "${comment_base}-return" -j RETURN ||
        fail "could not add return rule to $chain"
}

ensure_jump() {
    local tool="$1" builtin="$2" chain="$3" comment="$4"

    if ! root_cmd "$tool" -C "$builtin" \
        -m comment --comment "$comment" -j "$chain" >/dev/null 2>&1; then
        root_cmd "$tool" -I "$builtin" 1 \
            -m comment --comment "$comment" -j "$chain" ||
            fail "could not install owned jump in $builtin"
    fi
}

# ---------------------------------------------------------------------------
# External-network isolation: block forwarding into and out of the lab bridge.
# ---------------------------------------------------------------------------

ensure_external_chain() {
    local tool="$1" chain="$2" bridge="$3"
    local in_comment="$4" out_comment="$5" return_comment="$6"
    local rules line

    if ! root_cmd "$tool" -S "$chain" >/dev/null 2>&1; then
        root_cmd "$tool" -N "$chain" ||
            fail "could not create external-boundary chain $chain"
    fi

    rules="$(root_cmd "$tool" -S "$chain")" ||
        fail "cannot inspect external-boundary chain $chain"

    while IFS= read -r line; do
        [[ -z "$line" ||
           "$line" == "-N $chain" ||
           "$line" == "-A $chain -i $bridge ! -o $bridge -m comment --comment $in_comment -j DROP" ||
           "$line" == "-A $chain ! -i $bridge -o $bridge -m comment --comment $out_comment -j DROP" ||
           "$line" == "-A $chain -m comment --comment $return_comment -j RETURN" ]] ||
            fail "external-boundary chain $chain contains an unknown rule; refusing mutation"
    done <<< "$rules"

    root_cmd "$tool" -C "$chain" \
        -i "$bridge" ! -o "$bridge" \
        -m comment --comment "$in_comment" -j DROP >/dev/null 2>&1 ||
        root_cmd "$tool" -A "$chain" \
            -i "$bridge" ! -o "$bridge" \
            -m comment --comment "$in_comment" -j DROP ||
        fail "could not add outbound external-traffic drop to $chain"

    root_cmd "$tool" -C "$chain" \
        ! -i "$bridge" -o "$bridge" \
        -m comment --comment "$out_comment" -j DROP >/dev/null 2>&1 ||
        root_cmd "$tool" -A "$chain" \
            ! -i "$bridge" -o "$bridge" \
            -m comment --comment "$out_comment" -j DROP ||
        fail "could not add inbound external-traffic drop to $chain"

    root_cmd "$tool" -C "$chain" \
        -m comment --comment "$return_comment" -j RETURN >/dev/null 2>&1 ||
        root_cmd "$tool" -A "$chain" \
            -m comment --comment "$return_comment" -j RETURN ||
        fail "could not add return rule to $chain"
}

ensure_external_jump() {
    local tool="$1" chain="$2" comment="$3"
    local rules line exact

    exact="-A FORWARD -m comment --comment $comment -j $chain"
    rules="$(root_cmd "$tool" -S FORWARD)" ||
        fail "cannot inspect $tool FORWARD rules"

    while IFS= read -r line; do
        if [[ "$line" == "-A FORWARD "* &&
              "$line" == *"-j $chain"* &&
              "$line" != "$exact" ]]; then
            fail "unexpected FORWARD reference to $chain; refusing mutation"
        fi
    done <<< "$rules"

    if ! root_cmd "$tool" -C FORWARD \
        -m comment --comment "$comment" -j "$chain" >/dev/null 2>&1; then
        root_cmd "$tool" -I FORWARD 1 \
            -m comment --comment "$comment" -j "$chain" ||
            fail "could not install external-boundary jump in FORWARD"
    fi
}

apply_external_rules() {
    ensure_external_chain iptables "$EXT_CHAIN4" "$BRIDGE" \
        "${comment_base}-external-v4-out" \
        "${comment_base}-external-v4-in" \
        "${comment_base}-external-v4-return"

    ensure_external_jump iptables "$EXT_CHAIN4" \
        "${comment_base}-external-v4-forward-jump"

    ensure_external_chain ip6tables "$EXT_CHAIN6" "$BRIDGE" \
        "${comment_base}-external-v6-out" \
        "${comment_base}-external-v6-in" \
        "${comment_base}-external-v6-return"

    ensure_external_jump ip6tables "$EXT_CHAIN6" \
        "${comment_base}-external-v6-forward-jump"
}

verify_external_chain() {
    local tool="$1" chain="$2" bridge="$3"
    local in_comment="$4" out_comment="$5" return_comment="$6"
    local rules expected

    rules="$(root_cmd "$tool" -S "$chain")" ||
        fail "external-boundary chain $chain is missing"

    expected="$(printf '%s\n' \
        "-N $chain" \
        "-A $chain -i $bridge ! -o $bridge -m comment --comment $in_comment -j DROP" \
        "-A $chain ! -i $bridge -o $bridge -m comment --comment $out_comment -j DROP" \
        "-A $chain -m comment --comment $return_comment -j RETURN")"

    [[ "$rules" == "$expected" ]] ||
        fail "$tool external-boundary chain $chain has missing, duplicate, or unexpected rules"
}

verify_external_rules() {
    verify_external_chain iptables "$EXT_CHAIN4" "$BRIDGE" \
        "${comment_base}-external-v4-out" \
        "${comment_base}-external-v4-in" \
        "${comment_base}-external-v4-return"

    check_jump_order iptables FORWARD "$EXT_CHAIN4" \
        "${comment_base}-external-v4-forward-jump" ||
        fail "IPv4 external-boundary FORWARD jump is missing, duplicated, or incorrectly ordered"

    verify_external_chain ip6tables "$EXT_CHAIN6" "$BRIDGE" \
        "${comment_base}-external-v6-out" \
        "${comment_base}-external-v6-in" \
        "${comment_base}-external-v6-return"

    check_jump_order ip6tables FORWARD "$EXT_CHAIN6" \
        "${comment_base}-external-v6-forward-jump" ||
        fail "IPv6 external-boundary FORWARD jump is missing, duplicated, or incorrectly ordered"
}

# ---------------------------------------------------------------------------
# Apply and verify supported IPv4/IPv6 rules
# ---------------------------------------------------------------------------

apply_rules() {
    ensure_owned_chain iptables "$CHAIN4" \
        "${comment_base}-v4-in" \
        "${comment_base}-v4-out" \
        "$BRIDGE"

    ensure_jump iptables INPUT "$CHAIN4" \
        "${comment_base}-v4-input-jump"
    ensure_jump iptables OUTPUT "$CHAIN4" \
        "${comment_base}-v4-output-jump"
    ensure_jump iptables FORWARD "$CHAIN4" \
        "${comment_base}-v4-forward-jump"

    ensure_owned_chain ip6tables "$CHAIN6" \
        "${comment_base}-v6-in" \
        "${comment_base}-v6-out" \
        "$BRIDGE"

    ensure_jump ip6tables INPUT "$CHAIN6" \
        "${comment_base}-v6-input-jump"
    ensure_jump ip6tables OUTPUT "$CHAIN6" \
        "${comment_base}-v6-output-jump"
    ensure_jump ip6tables FORWARD "$CHAIN6" \
        "${comment_base}-v6-forward-jump"

    # The external forwarding jump must precede the general bridge jump.
    apply_external_rules
}

verify_general_chain() {
    local tool="$1" chain="$2" bridge="$3"
    local family="$4" rules expected

    rules="$(root_cmd "$tool" -S "$chain")" ||
        fail "$family owned enforcement chain is missing"

    expected="$(printf '%s\n' \
        "-N $chain" \
        "-A $chain -i $bridge -m comment --comment ${comment_base}-${family}-in -j DROP" \
        "-A $chain -o $bridge -m comment --comment ${comment_base}-${family}-out -j DROP" \
        "-A $chain -m comment --comment ${comment_base}-return -j RETURN")"

    [[ "$rules" == "$expected" ]] ||
        fail "$family owned chain has missing, duplicate, or unexpected rules"
}

verify_rules() {
    verify_general_chain iptables "$CHAIN4" "$BRIDGE" v4

    check_jump_order iptables INPUT "$CHAIN4" \
        "${comment_base}-v4-input-jump" ||
        fail "IPv4 INPUT enforcement order is ambiguous"

    check_jump_order iptables OUTPUT "$CHAIN4" \
        "${comment_base}-v4-output-jump" ||
        fail "IPv4 OUTPUT enforcement order is ambiguous"

    check_jump_sequence iptables FORWARD \
        "$EXT_CHAIN4" "${comment_base}-external-v4-forward-jump" \
        "$CHAIN4" "${comment_base}-v4-forward-jump" ||
        fail "IPv4 FORWARD enforcement order is ambiguous"

    verify_general_chain ip6tables "$CHAIN6" "$BRIDGE" v6

    check_jump_order ip6tables INPUT "$CHAIN6" \
        "${comment_base}-v6-input-jump" ||
        fail "IPv6 INPUT enforcement order is ambiguous"

    check_jump_order ip6tables OUTPUT "$CHAIN6" \
        "${comment_base}-v6-output-jump" ||
        fail "IPv6 OUTPUT enforcement order is ambiguous"

    check_jump_sequence ip6tables FORWARD \
        "$EXT_CHAIN6" "${comment_base}-external-v6-forward-jump" \
        "$CHAIN6" "${comment_base}-v6-forward-jump" ||
        fail "IPv6 FORWARD enforcement order is ambiguous"

    verify_external_rules
}

# ---------------------------------------------------------------------------
# Conservative cleanup
#
# Validate all owned chains and references before deleting any of them.
# Unknown rules or unowned references cause cleanup to stop.
# ---------------------------------------------------------------------------

validate_general_chain_for_removal() {
    local tool="$1" chain="$2" bridge="$3" family="$4"
    local rules line

    if ! root_cmd "$tool" -S "$chain" >/dev/null 2>&1; then
        return 0
    fi

    rules="$(root_cmd "$tool" -S "$chain")" ||
        fail "cannot inspect owned chain $chain"

    while IFS= read -r line; do
        [[ -z "$line" ||
           "$line" == "-N $chain" ||
           "$line" == "-A $chain -i $bridge -m comment --comment ${comment_base}-${family}-in -j DROP" ||
           "$line" == "-A $chain -o $bridge -m comment --comment ${comment_base}-${family}-out -j DROP" ||
           "$line" == "-A $chain -m comment --comment ${comment_base}-return -j RETURN" ]] ||
            fail "owned chain $chain contains an unknown rule; refusing cleanup"
    done <<< "$rules"
}

validate_external_chain_for_removal() {
    local tool="$1" chain="$2" bridge="$3"
    local in_comment="$4" out_comment="$5" return_comment="$6"
    local rules line

    if ! root_cmd "$tool" -S "$chain" >/dev/null 2>&1; then
        return 0
    fi

    rules="$(root_cmd "$tool" -S "$chain")" ||
        fail "cannot inspect external-boundary chain $chain"

    while IFS= read -r line; do
        [[ -z "$line" ||
           "$line" == "-N $chain" ||
           "$line" == "-A $chain -i $bridge ! -o $bridge -m comment --comment $in_comment -j DROP" ||
           "$line" == "-A $chain ! -i $bridge -o $bridge -m comment --comment $out_comment -j DROP" ||
           "$line" == "-A $chain -m comment --comment $return_comment -j RETURN" ]] ||
            fail "external-boundary chain $chain contains an unknown rule; refusing cleanup"
    done <<< "$rules"
}

remove_exact_jump() {
    local tool="$1" builtin="$2" chain="$3" comment="$4"
    local rules line exact

    rules="$(root_cmd "$tool" -S "$builtin")" ||
        fail "cannot inspect $tool $builtin rules"

    exact="-A $builtin -m comment --comment $comment -j $chain"

    while IFS= read -r line; do
        if [[ "$line" == "-A $builtin "* &&
              "$line" == *"-j $chain"* &&
              "$line" != "$exact" ]]; then
            fail "unexpected reference to owned chain $chain in $builtin"
        fi
    done <<< "$rules"

    while root_cmd "$tool" -C "$builtin" \
        -m comment --comment "$comment" -j "$chain" >/dev/null 2>&1; do
        root_cmd "$tool" -D "$builtin" \
            -m comment --comment "$comment" -j "$chain" ||
            fail "could not remove owned jump $comment"
    done
}

remove_general_rules() {
    local tool="$1" chain="$2" family="$3"
    local builtin comment

    for builtin in INPUT OUTPUT FORWARD; do
        case "$builtin" in
            INPUT) comment="${comment_base}-${family}-input-jump" ;;
            OUTPUT) comment="${comment_base}-${family}-output-jump" ;;
            FORWARD) comment="${comment_base}-${family}-forward-jump" ;;
        esac

        remove_exact_jump "$tool" "$builtin" "$chain" "$comment"
    done

    if root_cmd "$tool" -S "$chain" >/dev/null 2>&1; then
        root_cmd "$tool" -D "$chain" \
            -i "$BRIDGE" \
            -m comment --comment "${comment_base}-${family}-in" \
            -j DROP ||
            fail "could not remove owned ingress rule from $chain"

        root_cmd "$tool" -D "$chain" \
            -o "$BRIDGE" \
            -m comment --comment "${comment_base}-${family}-out" \
            -j DROP ||
            fail "could not remove owned egress rule from $chain"

        root_cmd "$tool" -D "$chain" \
            -m comment --comment "${comment_base}-return" \
            -j RETURN ||
            fail "could not remove owned return rule from $chain"

        root_cmd "$tool" -X "$chain" ||
            fail "could not remove owned chain $chain"
    fi
}

remove_external_rules() {
    local tool chain family

    for family in v4 v6; do
        if [[ "$family" == v4 ]]; then
            tool=iptables
            chain="$EXT_CHAIN4"
        else
            tool=ip6tables
            chain="$EXT_CHAIN6"
        fi

        remove_exact_jump "$tool" FORWARD "$chain" \
            "${comment_base}-external-${family}-forward-jump"

        if root_cmd "$tool" -S "$chain" >/dev/null 2>&1; then
            root_cmd "$tool" -D "$chain" \
                -i "$BRIDGE" ! -o "$BRIDGE" \
                -m comment --comment "${comment_base}-external-${family}-out" \
                -j DROP ||
                fail "could not remove external outbound rule from $chain"

            root_cmd "$tool" -D "$chain" \
                ! -i "$BRIDGE" -o "$BRIDGE" \
                -m comment --comment "${comment_base}-external-${family}-in" \
                -j DROP ||
                fail "could not remove external inbound rule from $chain"

            root_cmd "$tool" -D "$chain" \
                -m comment --comment "${comment_base}-external-${family}-return" \
                -j RETURN ||
                fail "could not remove external return rule from $chain"

            root_cmd "$tool" -X "$chain" ||
                fail "could not remove external-boundary chain $chain"
        fi
    done
}

verify_project_rules_removed() {
    local tool rules chain

    for tool in iptables ip6tables; do
        rules="$(root_cmd "$tool" -S)" ||
            fail "cannot verify cleanup in $tool"

        if grep -Fq -- "$comment_base-" <<< "$rules"; then
            fail "project-owned or unexpected tagged rules remain in $tool"
        fi
    done

    for tool in iptables ip6tables; do
        for chain in "$CHAIN4" "$CHAIN6" "$EXT_CHAIN4" "$EXT_CHAIN6"; do
            if root_cmd "$tool" -S "$chain" >/dev/null 2>&1; then
                fail "project-owned firewall chain remains after cleanup: $tool/$chain"
            fi
        done
    done
}

# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

case "$ACTION" in
    apply)
        require_supported_policy
        check_firewall_prerequisites

        if [[ -e "$state_file" || -L "$state_file" ]]; then
            load_saved_state
            SAVED_NETWORK_ID="$NETWORK_ID"
            SAVED_BRIDGE="$BRIDGE"
            SAVED_SUBNETS="$SUBNETS"
        fi

        network_details

        if [[ -n "${SAVED_NETWORK_ID:-}" ]]; then
            [[ "$NETWORK_ID" == "$SAVED_NETWORK_ID" &&
               "$BRIDGE" == "$SAVED_BRIDGE" &&
               "$SUBNETS" == "$SAVED_SUBNETS" ]] ||
                fail "refusing to replace boundary state for a different project network"
        fi

        save_state
        apply_rules
        verify_rules

        printf 'POLICY_DEFINITION=VALIDATED\n'
        printf 'ENFORCEMENT=APPLIED_AND_VERIFIED\n'
        printf 'RUNTIME_ACCEPTANCE=NOT_TESTED\n'
        printf 'POLICY_SHA256=%s\n' "$POLICY_SHA256"
        printf 'PROJECT=%s\nNETWORK_ID=%s\nBRIDGE=%s\n' \
            "$PROJECT" "$NETWORK_ID" "$BRIDGE"
        ;;

    verify)
        require_supported_policy
        check_firewall_prerequisites

        load_saved_state
        SAVED_NETWORK_ID="$NETWORK_ID"
        SAVED_BRIDGE="$BRIDGE"
        SAVED_SUBNETS="$SUBNETS"

        network_details

        [[ "$NETWORK_ID" == "$SAVED_NETWORK_ID" ]] ||
            fail "project network identity changed"

        [[ "$BRIDGE" == "$SAVED_BRIDGE" ]] ||
            fail "project bridge identity changed"

        [[ "$SUBNETS" == "$SAVED_SUBNETS" ]] ||
            fail "project subnet identity changed"

        # Reload to compare the saved policy hash after network discovery.
        load_saved_state
        verify_rules

        printf 'POLICY_DEFINITION=VALIDATED\n'
        printf 'ENFORCEMENT=VERIFIED\n'
        printf 'RUNTIME_ACCEPTANCE=NOT_TESTED\n'
        printf 'POLICY_SHA256=%s\n' "$POLICY_SHA256"
        printf 'PROJECT=%s\nNETWORK_ID=%s\nBRIDGE=%s\n' \
            "$PROJECT" "$NETWORK_ID" "$BRIDGE"
        ;;

    remove)
        check_firewall_prerequisites
        load_saved_state

        SAVED_NETWORK_ID="$NETWORK_ID"
        SAVED_BRIDGE="$BRIDGE"
        SAVED_SUBNETS="$SUBNETS"

        network_details

        [[ "$NETWORK_ID" == "$SAVED_NETWORK_ID" ]] ||
            fail "refusing cleanup after project network identity changed"

        [[ "$BRIDGE" == "$SAVED_BRIDGE" ]] ||
            fail "refusing cleanup after project bridge identity changed"

        [[ "$SUBNETS" == "$SAVED_SUBNETS" ]] ||
            fail "refusing cleanup after project subnet identity changed"

        # Validate every owned chain before mutating any firewall rules.
        validate_general_chain_for_removal \
            iptables "$CHAIN4" "$BRIDGE" v4
        validate_general_chain_for_removal \
            ip6tables "$CHAIN6" "$BRIDGE" v6

        validate_external_chain_for_removal \
            iptables "$EXT_CHAIN4" "$BRIDGE" \
            "${comment_base}-external-v4-out" \
            "${comment_base}-external-v4-in" \
            "${comment_base}-external-v4-return"

        validate_external_chain_for_removal \
            ip6tables "$EXT_CHAIN6" "$BRIDGE" \
            "${comment_base}-external-v6-out" \
            "${comment_base}-external-v6-in" \
            "${comment_base}-external-v6-return"

        remove_external_rules
        remove_general_rules iptables "$CHAIN4" v4
        remove_general_rules ip6tables "$CHAIN6" v6
        verify_project_rules_removed

        rm -f -- "$state_file" ||
            fail "firewall rules removed but boundary state could not be deleted"

        printf 'POLICY_DEFINITION=NOT_APPLICABLE\n'
        printf 'ENFORCEMENT=REMOVED_AND_VERIFIED\n'
        printf 'RUNTIME_ACCEPTANCE=NOT_TESTED\n'
        printf 'PROJECT=%s\n' "$PROJECT"
        ;;
esac