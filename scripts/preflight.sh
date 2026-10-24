
#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

LAB_ACTION=preflight

require_lab_config
info "project=$LAB_PROJECT"

mkdir -p "$STATE_PATH"

INVENTORY="$STATE_PATH/preflight-inventory.txt"
CAPABILITIES="$STATE_PATH/capabilities.json"
NETWORK_POLICY="$STATE_PATH/network-policy-validation.txt"

# Record host and Docker context before evaluating runtime readiness.
# This inventory is diagnostic evidence, not proof of isolation.
{
    printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'working_directory=%s\n' "$ROOT_DIR"

    printf '\nkernel=\n'
    uname -a

    printf '\nos=\n'
    cat /etc/os-release

    printf '\ncpu_count=%s\n' \
        "$(nproc 2>/dev/null || printf UNKNOWN)"

    printf '\nmemory=\n'
    free -h 2>/dev/null || printf 'status=UNKNOWN free-unavailable\n'

    printf '\ndisk=\n'
    df -hT "$ROOT_DIR"

    printf '\ndocker_context=\n'
    docker context show

    printf '\ndocker_info=\n'
    docker info --format \
        'server={{.ServerVersion}} driver={{.Driver}}'
} > "$INVENTORY" 2>&1 || {
    die "Host/Docker inventory failed; inspect $INVENTORY"
}

info "host inventory recorded=$INVENTORY"

# Existing project status and Docker checks.
python3 "$ROOT_DIR/lab/lab.py" status
require_docker_client
check_active_run
require_compose

# Verify that the canonical configuration files exist.
# Do not silently fall back to duplicate policy/capacity files.
required_files=(
    "$ROOT_DIR/config/lab-capacity.yaml"
    "$ROOT_DIR/config/policy/scientific-lab.yaml"
    "$ROOT_DIR/config/maintenance-policy.yaml"
    "$ROOT_DIR/lab/catalog/capabilities.yaml"
)

for file in "${required_files[@]}"; do
    [[ -f "$file" ]] || die "Required configuration missing: $file"
done

# Record the effective capabilities catalog output.
python3 "$ROOT_DIR/lab/lab.py" capabilities --json \
    > "$CAPABILITIES" || {
        die "Capability catalog validation failed; inspect $CAPABILITIES"
    }

# Validate network policy definitions.
# This does not establish that host, LAN, Internet, DNS, VPN, or IPv6
# traffic is blocked at runtime.
if python3 "$ROOT_DIR/lab/lab.py" networks validate \
    > "$NETWORK_POLICY" 2>&1; then
    info "network policy definitions validated"
else
    die "Network policy validation failed; inspect $NETWORK_POLICY"
fi

# Warn if the repository filesystem has less than 5 GiB available.
available_kb="$(df -Pk "$ROOT_DIR" | awk 'NR==2 {print $4}')"

[[ "$available_kb" =~ ^[0-9]+$ ]] ||
    die "Unable to determine available repository filesystem space"

if (( available_kb < 5242880 )); then
    warn "less than 5 GiB available; review storage before runtime"
fi

info "preflight passed"
info "policy definitions validated; runtime isolation and external paths remain separately unverified"

result PASS "preflight completed"
log_event "preflight pass project=$LAB_PROJECT"
