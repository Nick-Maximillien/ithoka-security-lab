#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; source "$SCRIPT_DIR/lib.sh"
LAB_ACTION=capture-stop
require_lab_config
pid_file="$RUN_STATE/capture.pid"
[[ -f "$pid_file" ]] || die "no capture is recorded for run $RUN_ID"
pid="$(cat "$pid_file")"
[[ "$pid" =~ ^[0-9]+$ ]] || die "invalid capture pid state"
command_name="$(ps -p "$pid" -o comm= 2>/dev/null | tr -d ' ')"
if [[ "$command_name" != tcpdump && "$command_name" != tshark ]]; then
  die "recorded pid is not a capture process"
fi
capture_path="$(cat "$RUN_STATE/capture.path" 2>/dev/null || true)"
metadata="${capture_path}.metadata"
expected_interface="$(awk -F= '$1 == "interface" {print $2; exit}' "$metadata" 2>/dev/null || true)"
process_args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
[[ -n "$expected_interface" && "$process_args" == *"$expected_interface"* ]] || die "recorded capture process does not match the recorded interface; refusing to stop it"
kill "$pid" 2>/dev/null || warn "capture process was already absent; final state is uncertain"
sleep 1
if kill -0 "$pid" 2>/dev/null; then
  result FAIL "capture process remains running: $pid"
  exit 1
fi
path="$capture_path"
[[ -f "$path" ]] || { result UNKNOWN "capture file is absent: $path"; exit 2; }
size="$(stat -c '%s' "$path" 2>/dev/null || printf 'unknown')"
printf 'stopped_utc=%s\nsize_bytes=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$size" >> "$path.metadata"
rm -f "$pid_file" "$RUN_STATE/capture.path"
result PASS "capture stopped and metadata recorded: $path"
log_event "capture stopped path=$path"