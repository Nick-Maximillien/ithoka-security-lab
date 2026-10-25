#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

LAB_ACTION=capture-stop

require_lab_config

pid_file="$RUN_STATE/capture.pid"
path_file="$RUN_STATE/capture.path"

[[ -f "$pid_file" && ! -L "$pid_file" &&
   -f "$path_file" && ! -L "$path_file" ]] ||
  die "capture PID/path state is missing for run $RUN_ID; investigate before modifying state"

pid="$(<"$pid_file")"
capture_path="$(<"$path_file")"

[[ "$pid" =~ ^[0-9]+$ ]] ||
  die "invalid capture PID state"

capture_directory="$(realpath -e -- "$RUN_EVIDENCE/packet-captures")" ||
  die "capture evidence directory cannot be resolved"
resolved_capture_path="$(realpath -m -- "$capture_path")" ||
  die "recorded capture path cannot be resolved"

[[ -n "$capture_path" &&
   "$resolved_capture_path" == "$capture_path" &&
   "$resolved_capture_path" == "$capture_directory/"* ]] ||
  die "recorded capture path is outside the expected evidence directory"

metadata="$capture_path.metadata"

[[ -f "$metadata" && ! -L "$metadata" ]] ||
  die "capture metadata is missing: $metadata"

expected_run="$(awk -F= '$1 == "run_id" {print $2; exit}' "$metadata")"
expected_interface="$(awk -F= '$1 == "interface" {print $2; exit}' "$metadata")"
expected_tool="$(awk -F= '$1 == "tool" {print $2; exit}' "$metadata")"

[[ "$expected_run" == "$RUN_ID" ]] ||
  die "capture metadata run ID does not match the current run"

[[ "$expected_interface" =~ ^[A-Za-z0-9_.:-]+$ ]] ||
  die "invalid interface in capture metadata"

[[ "$expected_tool" == tcpdump || "$expected_tool" == tshark ]] ||
  die "invalid capture tool in metadata"

if ! kill -0 "$pid" 2>/dev/null; then
  result UNKNOWN \
    "recorded capture process is absent; finalization is uncertain, state retained for investigation"
  exit 2
fi

command_name="$(ps -p "$pid" -o comm= 2>/dev/null | tr -d ' ')"
process_args="$(ps -p "$pid" -o args= 2>/dev/null || true)"

[[ "$command_name" == "$expected_tool" ]] ||
  die "recorded PID is not the expected capture tool; refusing to signal it"

[[ "$process_args" == *"$capture_path"* &&
   "$process_args" == *"-i $expected_interface"* ]] ||
  die "recorded process arguments do not match capture metadata; refusing to stop it"

# Request orderly shutdown so the capture tool can finalize its output.
kill -TERM "$pid" ||
  die "unable to signal capture process; state retained"

stopped=false

for _ in 1 2 3 4 5; do
  sleep 1

  if ! kill -0 "$pid" 2>/dev/null; then
    stopped=true
    break
  fi

  current_state="$(ps -p "$pid" -o stat= 2>/dev/null | tr -d ' ')"

  # A zombie has exited but has not yet been reaped by its parent.
  if [[ "$current_state" == Z* ]]; then
    stopped=true
    break
  fi
done

if [[ "$stopped" != true ]]; then
  result FAIL \
    "capture process remains present after termination request: pid=$pid; state retained"
  exit 1
fi

if [[ ! -f "$capture_path" ]]; then
  result UNKNOWN \
    "capture process stopped but the expected output file is absent: $capture_path"
  exit 2
fi

size="$(stat -c '%s' "$capture_path" 2>/dev/null || true)"

[[ "$size" =~ ^[0-9]+$ ]] ||
  size=unknown

{
  printf 'stopped_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'size_bytes=%s\n' "$size"
  printf 'capture_status=stop-request-completed\n'
} >> "$metadata"

# Preserve the capture file and metadata. Clear only active-process state.
rm -f -- "$pid_file" "$path_file"

result PASS \
  "capture process stopped; output retained at $capture_path"

log_event "capture stopped path=$capture_path pid=$pid size_bytes=$size"