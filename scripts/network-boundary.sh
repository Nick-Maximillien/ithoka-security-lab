#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
STATE_DIR="$ROOT/state/network-boundary"
OWNER="security-lab"
PROJECT_RE='^sec-lab-i-[a-z0-9][a-z0-9-]{0,31}$'

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }
root_cmd() { sudo "$@"; }

[[ $# -eq 3 ]] || fail "usage: $0 {apply|verify|remove} sec-lab-i-<investigation-id> policy.json"
ACTION="$1"
PROJECT="$2"
POLICY_FILE="$3"
[[ "$PROJECT" =~ $PROJECT_RE ]] || fail "invalid project name: $PROJECT"
[[ -f "$POLICY_FILE" ]] || fail "network policy file is missing: $POLICY_FILE"
case "$ACTION" in
    apply|verify|remove) : ;;
    *) fail "unsupported action: $ACTION" ;;
esac

need docker
need sudo
need iptables
need ip6tables

state_file="$STATE_DIR/$PROJECT.env"
comment_base="ithoka-sec-lab-${PROJECT}"

policy_value() {
    local boundary="$1" key="$2"
    python3 - "$POLICY_FILE" "$boundary" "$key" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    policy = json.load(stream)
value = policy["boundaries"][sys.argv[2]][sys.argv[3]]
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

require_supported_protocol_policy() {
    local boundary="$1"
    [[ "$(policy_value "$boundary" enabled)" == "true" ]] || return 0
    [[ "$(policy_value "$boundary" mode)" == "deny" ]] ||
        fail "$boundary policy is not supported by the Linux/WSL adapter; requested mode: $(policy_value "$boundary" mode)"
}

rule_present() {
    local tool="$1" chain="$2" comment="$3"
    shift 3
    root_cmd "$tool" -C "$chain" "$@" -m comment --comment "$comment" -j DROP >/dev/null 2>&1
}

ensure_rule() {
    local tool="$1" chain="$2" comment="$3"
    shift 3
    if ! rule_present "$tool" "$chain" "$comment" "$@"; then
        root_cmd "$tool" -I "$chain" 1 "$@" -m comment --comment "$comment" -j DROP
    fi
}

remove_rule() {
    local tool="$1" chain="$2" comment="$3"
    shift 3
    if rule_present "$tool" "$chain" "$comment" "$@"; then
        root_cmd "$tool" -D "$chain" "$@" -m comment --comment "$comment" -j DROP
    fi
}

network_details() {
    local ids count detail bridge
    ids="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT")" ||
        fail "cannot enumerate networks for $PROJECT"
    count="$(printf '%s\n' "$ids" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
    [[ "$count" == 1 ]] || fail "expected exactly one project network; found $count"
    NETWORK_ID="$(printf '%s\n' "$ids" | sed -n '1p')"
    detail="$(docker network inspect --format '{{.Internal}}|{{.EnableIPv6}}|{{.Driver}}|{{index .Labels "io.ithoka.security-lab.owner"}}|{{index .Labels "io.ithoka.security-lab.investigation"}}' "$NETWORK_ID")" ||
        fail "cannot inspect project network"
    [[ "$detail" == true\|*\|bridge\|"$OWNER"\|"${PROJECT#sec-lab-i-}" ]] ||
        fail "network is not an owned internal bridge (actual: $detail)"
    bridge="$(docker network inspect --format '{{index .Options "com.docker.network.bridge.name"}}' "$NETWORK_ID")" ||
        fail "cannot resolve the Docker bridge name"
    [[ "$bridge" =~ ^[A-Za-z0-9_.:-]+$ && -n "$bridge" ]] ||
        fail "Docker did not report an approved bridge name"
    BRIDGE="$bridge"
    [[ -d "/sys/class/net/$BRIDGE" ]] || fail "expected bridge interface is absent: $BRIDGE"
    SUBNETS="$(docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$NETWORK_ID")" ||
        fail "cannot resolve Docker network subnets"
    [[ -n "$SUBNETS" ]] || fail "owned Docker network has no resolved subnet"
}

load_saved_state() {
    [[ -f "$state_file" ]] || fail "boundary state file missing: $state_file"
    PROJECT_SAVED=""
    NETWORK_ID=""
    BRIDGE=""
    # The file is generated below from trusted values; do not source it.
    PROJECT_SAVED="$(sed -n 's/^PROJECT=//p' "$state_file")"
    NETWORK_ID="$(sed -n 's/^NETWORK_ID=//p' "$state_file")"
    BRIDGE="$(sed -n 's/^BRIDGE=//p' "$state_file")"
    [[ "$PROJECT_SAVED" == "$PROJECT" ]] || fail "boundary state belongs to another project"
    [[ "$NETWORK_ID" =~ ^[0-9a-f]{64}$ ]] || fail "saved network ID is malformed"
    [[ "$BRIDGE" =~ ^[A-Za-z0-9_.:-]+$ ]] || fail "saved bridge is malformed"
    [[ -n "$SUBNETS" ]] || fail "saved network subnets are missing"
}

apply_rules() {
    local b="$BRIDGE"
    if [[ "$(policy_value ipv4 enabled)" == "true" ]]; then
        ensure_rule iptables INPUT "${comment_base}-v4-input" -i "$b"
        ensure_rule iptables OUTPUT "${comment_base}-v4-output" -o "$b"
        ensure_rule iptables FORWARD "${comment_base}-v4-forward" -i "$b" ! -o "$b"
    fi
    if [[ "$(policy_value ipv6 enabled)" == "true" ]]; then
        ensure_rule ip6tables INPUT "${comment_base}-v6-input" -i "$b"
        ensure_rule ip6tables OUTPUT "${comment_base}-v6-output" -o "$b"
        ensure_rule ip6tables FORWARD "${comment_base}-v6-forward" -i "$b" ! -o "$b"
    fi
}

verify_rules() {
    local b="$BRIDGE"
    if [[ "$(policy_value ipv4 enabled)" == "true" ]]; then
        rule_present iptables INPUT "${comment_base}-v4-input" -i "$b" || fail "IPv4 host ingress rule is not installed"
        rule_present iptables OUTPUT "${comment_base}-v4-output" -o "$b" || fail "IPv4 host egress rule is not installed"
        rule_present iptables FORWARD "${comment_base}-v4-forward" -i "$b" ! -o "$b" || fail "IPv4 forwarding rule is not installed"
    fi
    if [[ "$(policy_value ipv6 enabled)" == "true" ]]; then
        rule_present ip6tables INPUT "${comment_base}-v6-input" -i "$b" || fail "IPv6 host ingress rule is not installed"
        rule_present ip6tables OUTPUT "${comment_base}-v6-output" -o "$b" || fail "IPv6 host egress rule is not installed"
        rule_present ip6tables FORWARD "${comment_base}-v6-forward" -i "$b" ! -o "$b" || fail "IPv6 forwarding rule is not installed"
    fi
}

remove_rules() {
    local b="$BRIDGE"
    remove_rule iptables INPUT "${comment_base}-v4-input" -i "$b"
    remove_rule iptables OUTPUT "${comment_base}-v4-output" -o "$b"
    remove_rule iptables FORWARD "${comment_base}-v4-forward" -i "$b" ! -o "$b"
    remove_rule ip6tables INPUT "${comment_base}-v6-input" -i "$b"
    remove_rule ip6tables OUTPUT "${comment_base}-v6-output" -o "$b"
    remove_rule ip6tables FORWARD "${comment_base}-v6-forward" -i "$b" ! -o "$b"
}

case "$ACTION" in
    apply)
        require_supported_protocol_policy ipv4
        require_supported_protocol_policy ipv6
        network_details
        mkdir -p "$STATE_DIR"
        printf 'PROJECT=%s\nNETWORK_ID=%s\nBRIDGE=%s\nSUBNETS=%s\n' "$PROJECT" "$NETWORK_ID" "$BRIDGE" "$SUBNETS" > "$state_file"
        apply_rules
        verify_rules
        ;;
    verify)
        require_supported_protocol_policy ipv4
        require_supported_protocol_policy ipv6
        load_saved_state
        network_details
        [[ "$NETWORK_ID" == "$(sed -n 's/^NETWORK_ID=//p' "$state_file")" ]] ||
            fail "project network identity changed"
        [[ "$BRIDGE" == "$(sed -n 's/^BRIDGE=//p' "$state_file")" ]] ||
            fail "project bridge identity changed"
        verify_rules
        ;;
    remove)
        load_saved_state
        network_details
        [[ "$NETWORK_ID" == "$(sed -n 's/^NETWORK_ID=//p' "$state_file")" ]] ||
            fail "refusing cleanup after project network identity changed"
        remove_rules
        rm -f -- "$state_file"
        ;;
esac
