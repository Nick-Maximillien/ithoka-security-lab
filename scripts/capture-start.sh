#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; source "$SCRIPT_DIR/lib.sh"
LAB_ACTION=capture-start
require_lab_config
[[ "${CAPTURE_APPROVAL:-false}" == "true" ]] || die "set CAPTURE_APPROVAL=true after reviewing capture point and privilege requirements"
interface="${1:-${CAPTURE_INTERFACE:-}}"
[[ "$interface" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "a specific capture interface is required"
tool="${CAPTURE_TOOL:-}"
if [[ -z "$tool" ]]; then
  command -v tcpdump >/dev/null 2>&1 && tool=tcpdump || true
  if [[ -z "$tool" ]]; then command -v tshark >/dev/null 2>&1 && tool=tshark || true; fi
fi
[[ "$tool" == tcpdump || "$tool" == tshark ]] || die "supported capture tool (tcpdump or tshark) is unavailable"
mkdir -p "$RUN_EVIDENCE/packet-captures" "$RUN_STATE"
if [[ -f "$RUN_STATE/capture.pid" ]]; then
  old_pid="$(cat "$RUN_STATE/capture.pid")"
  if [[ "$old_pid" =~ ^[0-9]+$ ]] && kill -0 "$old_pid" 2>/dev/null; then
    old_command="$(ps -p "$old_pid" -o comm= 2>/dev/null | tr -d ' ')"
    [[ "$old_command" == tcpdump || "$old_command" == tshark ]] && die "capture already running for run $RUN_ID: pid=$old_pid"
  fi
  rm -f "$RUN_STATE/capture.pid" "$RUN_STATE/capture.path"
fi
capture="$RUN_EVIDENCE/packet-captures/$interface-$RUN_ID.pcapng"
printf 'run_id=%s\ninterface=%s\ntool=%s\nstarted_utc=%s\nvisibility=selected-interface-only\n' "$RUN_ID" "$interface" "$tool" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$capture.metadata"
if [[ "$tool" == tcpdump ]]; then
  tcpdump -i "$interface" -s 0 -C 100 -W 1 -w "$capture" >/dev/null 2>&1 &
else
  tshark -i "$interface" -b filesize:102400 -w "$capture" >/dev/null 2>&1 &
fi
capture_pid="$!"
sleep 1
kill -0 "$capture_pid" 2>/dev/null || die "capture process exited during startup"
printf '%s\n' "$capture_pid" > "$RUN_STATE/capture.pid"
printf '%s\n' "$capture" > "$RUN_STATE/capture.path"
printf 'pid=%s\n' "$capture_pid" >> "$capture.metadata"
result PASS "capture started pid=$capture_pid interface=$interface tool=$tool"
log_event "capture started interface=$interface tool=$tool path=$capture"