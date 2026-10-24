#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; source "$SCRIPT_DIR/lib.sh"
LAB_ACTION=preflight
require_lab_config; info "project=$LAB_PROJECT"
python3 "$ROOT_DIR/lab/lab.py" status
require_docker_client
check_active_run
mkdir -p "$STATE_PATH"
{
	printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	printf 'working_directory=%s\n' "$ROOT_DIR"
	printf 'kernel=\n'; uname -a
	printf 'os=\n'; cat /etc/os-release
	printf 'cpu_count=%s\n' "$(nproc 2>/dev/null || printf UNKNOWN)"
	printf 'memory=\n'; free -h 2>/dev/null || printf 'status=UNKNOWN free-unavailable\n'
	printf 'disk=\n'; df -hT "$ROOT_DIR"
	printf 'docker_context=\n'; docker context show
	printf 'docker_info=\n'; docker info --format 'server={{.ServerVersion}} driver={{.Driver}}'
} > "$STATE_PATH/preflight-inventory.txt" || die "Docker or host readiness inventory failed; see $STATE_PATH/preflight-inventory.txt"
require_compose
python3 "$ROOT_DIR/lab/lab.py" capabilities --json > "$STATE_PATH/capabilities.json"
python3 "$ROOT_DIR/lab/lab.py" networks validate > "$STATE_PATH/network-policy-validation.json"
available_kb="$(df -Pk "$ROOT_DIR" | awk 'NR==2 {print $4}')"
(( available_kb >= 5242880 )) || warn "less than 5 GiB available at repository filesystem; review before runtime"
info "preflight passed; host network topology and external paths remain separately unverified"
result PASS "preflight completed"
log_event "preflight pass project=$LAB_PROJECT"