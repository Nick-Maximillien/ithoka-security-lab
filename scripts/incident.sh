```bash
#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

LAB_ACTION=incident

require_lab_config

kind="${1:-unknown}"

[[ "$kind" =~ ^[A-Za-z0-9._-]{1,64}$ ]] ||
  die "unsafe incident type; use 1–64 letters, digits, dots, underscores, or hyphens"

umask 077

mkdir -p "$RUN_EVIDENCE"

file="$RUN_EVIDENCE/incident-$kind.md"

[[ ! -e "$file" ]] ||
  die "incident record already exists; refusing to overwrite: $file"

recorded_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "$file" <<EOF
# Incident: $kind

- Run: $RUN_ID
- Project: $LAB_PROJECT
- Recorded UTC: $recorded_utc
- Status: OPEN

## Observed condition

Record what was observed, when it occurred, and how it was detected.
Distinguish direct observations from assumptions.

## Immediate containment

Record the actions taken, the operator who performed them, and their
observed results. Do not mark containment as successful without evidence.

## Residual resources

Record remaining containers, processes, network connections, capture
processes, temporary files, and other resources requiring investigation.

## Evidence references

List relevant paths, capture files, metadata, logs, and verification
outputs. Preserve original evidence; document any transformations.

## Recovery decision

Record the decision, rationale, required verification, and authorization
before resuming laboratory activity.

## Follow-up

Record unresolved questions, corrective actions, and the evidence needed
to close the incident.
EOF

result PASS "incident record created: $file"

log_event "incident created type=$kind file=$file"
```