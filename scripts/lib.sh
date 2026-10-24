#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${LAB_CONFIG_FILE:-$ROOT_DIR/config/lab.env}"
if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
else
  source "$ROOT_DIR/config/lab.env.example"
fi

: "${LAB_PROJECT:?LAB_PROJECT is required}"
: "${EVIDENCE_STAGING:?EVIDENCE_STAGING is required}"
EVIDENCE_PATH="$ROOT_DIR/$EVIDENCE_STAGING"
LOG_FILE="$ROOT_DIR/logs/controller.log"
STATE_PATH="$ROOT_DIR/state"
if [[ -n "${LAB_RUN_ID:-}" ]]; then
  RUN_ID="$LAB_RUN_ID"
elif [[ -f "$STATE_PATH/active-run" ]]; then
  active_candidate="$(<"$STATE_PATH/active-run")"
  RUN_ID="$active_candidate"
else
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
RUN_STATE="$STATE_PATH/$RUN_ID"
RUN_EVIDENCE="$EVIDENCE_PATH/$RUN_ID"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf 'INFO: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
result() { printf '%s: %s\n' "$1" "$2"; }
log_event() { mkdir -p "$(dirname "$LOG_FILE")"; printf '%s action=%s project=%s investigation=%s run=%s %s\n' "$(date -Is)" "${LAB_ACTION:-unknown}" "$LAB_PROJECT" "${LAB_INVESTIGATION_ID:-none}" "$RUN_ID" "$*" >> "$LOG_FILE"; }
require_identifier() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || die "unsafe identifier: $1"
}

require_lab_config() {
  [[ "$LAB_PROJECT" == sec-lab-docker ]] || die "unexpected project; refusing to target $LAB_PROJECT"
  require_identifier "$LAB_PROJECT"
  [[ "$EVIDENCE_PATH" == "$ROOT_DIR"/* ]] || die "evidence staging must remain inside the repository"
  [[ "$STATE_PATH" == "$ROOT_DIR"/* ]] || die "state must remain inside the repository"
}

require_docker_client() { command -v docker >/dev/null || die "docker command is unavailable; install it separately and rerun preflight"; }
require_compose() { docker compose version >/dev/null 2>&1 || die "Docker Compose is unavailable or daemon/client probing failed"; }

check_active_run() {
  [[ -f "$STATE_PATH/active-run" ]] || return 0
  local active status
  active="$(<"$STATE_PATH/active-run")"
  [[ "$active" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$ ]] || die "invalid active-run state"
  [[ "$active" == "$RUN_ID" ]] && return 0
  status="$(cat "$STATE_PATH/$active/status" 2>/dev/null || true)"
  case "$status" in
    RUNNING|STARTING|RESETTING|CONTAINING) die "active run $active has non-terminal status $status" ;;
  esac
}
