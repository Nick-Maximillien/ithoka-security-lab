#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; source "$SCRIPT_DIR/lib.sh"
LAB_ACTION=incident
require_lab_config
kind="${1:-unknown}"
[[ "$kind" =~ ^[A-Za-z0-9._-]+$ ]] || die "unsafe incident type"
mkdir -p "$EVIDENCE_PATH/$RUN_ID"
file="$EVIDENCE_PATH/$RUN_ID/incident-$kind.md"
cat > "$file" <<EOF
# Incident: $kind

Run: $RUN_ID
Project: $LAB_PROJECT
Recorded UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Status: OPEN

## Operator notes

Record observed condition, containment action, residual resources, evidence references, and recovery decision here.
EOF
result PASS "incident record created: $file"
log_event "incident created type=$kind file=$file"