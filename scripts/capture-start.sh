```bash
#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

LAB_ACTION=capture-start

require_lab_config
check_active_run

[[ "${CAPTURE_APPROVAL:-false}" == "true" ]] ||
  die "set CAPTURE_APPROVAL=true after reviewing the capture interface, capture point, data sensitivity, and privilege requirements"

interface="${1:-${CAPTURE_INTERFACE:-}}"

[[ -n "$interface" && "$interface" =~ ^[A-Za-z0-9_.:-]+$ ]] ||
  die "a specific valid capture interface is required"

tool="${CAPTURE_TOOL:-}"

if [[ -z "$tool" ]]; then
  if command -v tcpdump >/dev/null 2>&1; then
    tool=tcpdump
  elif command -v tshark >/dev/null 2>&1; then
    tool=tshark
  fi
fi

case "$tool" in
  tcpdump|tshark)
    command -v "$tool" >/dev/null 2>&1 ||
      die "configured capture tool is unavailable: $tool"
    ;;
  *)
    die "supported capture tool (tcpdump or tshark) is unavailable"
    ;;
esac

# Capture data may contain sensitive network information.
umask 077

mkdir -p "$RUN_EVIDENCE/packet-captures" "$RUN_STATE"

pid_file="$RUN_STATE/capture.pid"
path_file="$RUN_STATE/capture.path"

if [[ -f "$pid_file" || -f "$path_file" ]]; then
  [[ -f "$pid_file" && -f "$path_file" ]] ||
    die "incomplete capture state exists; investigate before starting another capture"

  old_pid="$(<"$pid_file")"
  old_path="$(<"$path_file")"

  if [[ "$old_pid" =~ ^[0-9]+$ ]] &&
     kill -0 "$old_pid" 2>/dev/null; then
    old_command="$(ps -p "$old_pid" -o comm= 2>/dev/null | tr -d ' ')"
    old_args="$(ps -p "$old_pid" -o args= 2>/dev/null || true)"

    if [[ "$old_command" == tcpdump || "$old_command" == tshark ]]; then
      [[ "$old_args" == *"$old_path"* ]] ||
        die "capture PID exists but its command does not match recorded state; investigate manually"

      die "capture already running for run $RUN_ID: pid=$old_pid"
    fi

    die "recorded PID is active but is not a recognized capture process; investigate manually"
  fi

  # A dead or invalid PID does not prove the previous capture closed cleanly.
  die "stale capture state exists; inspect the previous process, file, and metadata before clearing it"
fi

case "$tool" in
  tcpdump) extension=pcap ;;
  tshark) extension=pcapng ;;
esac

capture="$RUN_EVIDENCE/packet-captures/$interface-$RUN_ID.$extension"
metadata="$capture.metadata"

[[ ! -e "$capture" && ! -e "$metadata" ]] ||
  die "capture output already exists; refusing to overwrite evidence"

started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
  printf 'run_id=%s\n' "$RUN_ID"
  printf 'interface=%s\n' "$interface"
  printf 'tool=%s\n' "$tool"
  printf 'started_utc=%s\n' "$started_utc"
  printf 'visibility=selected-interface-only\n'
  printf 'capture_status=starting\n'
} > "$metadata"

case "$tool" in
  tcpdump)
    tcpdump -i "$interface" -s 0 \
      -C 100 -W 1 \
      -w "$capture" >/dev/null 2>&1 &
    ;;
  tshark)
    tshark -i "$interface" \
      -b filesize:102400 \
      -w "$capture" >/dev/null 2>&1 &
    ;;
esac

capture_pid="$!"

# Allow the process to initialize, then confirm it remains alive.
sleep 1

if ! kill -0 "$capture_pid" 2>/dev/null; then
  {
    printf 'capture_status=startup-failed\n'
    printf 'startup_failure_utc=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >> "$metadata"

  die "capture process exited during startup; inspect $metadata"
fi

process_name="$(ps -p "$capture_pid" -o comm= 2>/dev/null | tr -d ' ')"
process_args="$(ps -p "$capture_pid" -o args= 2>/dev/null || true)"

[[ "$process_name" == "$tool" ]] ||
  die "started process identity does not match configured capture tool"

[[ "$process_args" == *"$capture"* &&
   "$process_args" == *"-i $interface"* ]] ||
  die "started process arguments do not match the requested capture"

# Publish state only after basic process verification.
printf '%s\n' "$capture" > "$path_file"
printf '%s\n' "$capture_pid" > "$pid_file"

{
  printf 'pid=%s\n' "$capture_pid"
  printf 'capture_status=running\n'
} >> "$metadata"

result PASS \
  "capture process started pid=$capture_pid interface=$interface tool=$tool"

log_event "capture started interface=$interface tool=$tool path=$capture pid=$capture_pid"
```