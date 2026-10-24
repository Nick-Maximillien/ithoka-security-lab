#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; source "$SCRIPT_DIR/lib.sh"
LAB_ACTION=maintenance
require_lab_config
command="${1:-status}"
maintenance_dir="$ROOT_DIR/state/maintenance"
record="$maintenance_dir/dependencies.yaml"
case "$command" in
  status)
    [[ -f "$record" ]] && cat "$record" || result NOT_TESTED "no dependency acquisition record exists"
    ;;
  check)
    require_docker_client; docker info >/dev/null 2>&1 || { result BLOCKED "Docker daemon is unavailable; image availability cannot be determined"; exit 2; }
    require_compose
    result NOT_TESTED "resource availability is resolved from each submitted investigation plan"
    ;;
  record)
    [[ "${MAINTENANCE_APPROVAL:-false}" == "true" ]] || die "set MAINTENANCE_APPROVAL=true after defining the approved acquisition"
    [[ $# -ge 4 ]] || die "usage: maintenance.sh record NAME REFERENCE DIGEST_OR_BUILD_INPUT"
    name="$2"; reference="$3"; identity="$4"
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ && "$reference" != *$'\n'* && "$identity" != *$'\n'* ]] || die "unsafe dependency record"
    mkdir -p "$maintenance_dir"
    printf '%s\n' "- name: $name" "  reference: $reference" "  identity: $identity" "  acquired_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)" "  verification: operator-recorded" >> "$record"
    result PASS "dependency record added; no download was performed"
    ;;
  close)
    [[ -f "$record" ]] || die "cannot close maintenance without a dependency record"
    printf 'closed_utc=%s\nstatus=closed-isolated-profile\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$maintenance_dir/closure.txt"
    result PASS "maintenance path recorded as closed; no host network changes were made"
    ;;
  *) die "usage: maintenance.sh status|check|record NAME REFERENCE DIGEST_OR_BUILD_INPUT|close" ;;
esac
log_event "maintenance command=$command"