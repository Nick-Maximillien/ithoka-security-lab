#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONFIG_FILE="${LAB_CONFIG_FILE:-$ROOT_DIR/config/lab.env}"
EXAMPLE_CONFIG="$ROOT_DIR/config/lab.env.example"
_CAPTURE_APPROVAL_WAS_SET="${CAPTURE_APPROVAL+x}"
_CAPTURE_APPROVAL_OVERRIDE="${CAPTURE_APPROVAL-}"
_MAINTENANCE_APPROVAL_WAS_SET="${MAINTENANCE_APPROVAL+x}"
_MAINTENANCE_APPROVAL_OVERRIDE="${MAINTENANCE_APPROVAL-}"

if [[ -n "${LAB_CONFIG_FILE:-}" ]]; then
  [[ -f "$CONFIG_FILE" ]] || {
    printf 'ERROR: selected configuration is missing: %s\n' "$CONFIG_FILE" >&2
    exit 1
  }
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
elif [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
elif [[ -f "$EXAMPLE_CONFIG" ]]; then
  # shellcheck disable=SC1090
  source "$EXAMPLE_CONFIG"
else
  printf 'ERROR: configuration missing: %s\n' "$CONFIG_FILE" >&2
  exit 1
fi

if [[ "$_CAPTURE_APPROVAL_WAS_SET" == "x" ]]; then
  CAPTURE_APPROVAL="$_CAPTURE_APPROVAL_OVERRIDE"
fi
if [[ "$_MAINTENANCE_APPROVAL_WAS_SET" == "x" ]]; then
  MAINTENANCE_APPROVAL="$_MAINTENANCE_APPROVAL_OVERRIDE"
fi

: "${LAB_PROJECT:?LAB_PROJECT is required}"
: "${EVIDENCE_STAGING:?EVIDENCE_STAGING is required}"

STATE_PATH="$ROOT_DIR/state"
LOG_FILE="$ROOT_DIR/logs/controller.log"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

info() {
  printf 'INFO: %s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

result() {
  printf '%s: %s\n' "$1" "$2"
}

require_identifier() {
  local value="${1:-}"

  [[ "$value" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] ||
    die "unsafe identifier: $value"
}

require_run_identifier() {
  local value="${1:-}"

  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$ ]] ||
    die "unsafe run identifier: $value"
}

# Resolve and validate repository-relative paths without creating them.
# Reject absolute paths, traversal components, and paths resolving outside
# the repository. This is a configuration guard, not a symlink-proof
# filesystem sandbox.
resolve_repo_path() {
  local relative_path="$1"
  local resolved

  [[ -n "$relative_path" ]] ||
    die "repository-relative path must not be empty"

  [[ "$relative_path" != /* ]] ||
    die "absolute paths are not allowed: $relative_path"

  case "/$relative_path/" in
    *"/../"*)
      die "path traversal is not allowed: $relative_path"
      ;;
  esac

  resolved="$(realpath -m -- "$ROOT_DIR/$relative_path")" ||
    die "unable to resolve path: $relative_path"

  [[ "$resolved" == "$ROOT_DIR/"* ]] ||
    die "path must remain inside the repository: $relative_path"

  printf '%s\n' "$resolved"
}

EVIDENCE_PATH="$(resolve_repo_path "$EVIDENCE_STAGING")"

if [[ -n "${LAB_RUN_ID:-}" ]]; then
  RUN_ID="$LAB_RUN_ID"
elif [[ -f "$STATE_PATH/active-run" ]]; then
  RUN_ID="$(<"$STATE_PATH/active-run")"
else
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi

require_run_identifier "$RUN_ID"

RUN_STATE="$STATE_PATH/$RUN_ID"
RUN_EVIDENCE="$EVIDENCE_PATH/$RUN_ID"

log_event() {
  local timestamp

  timestamp="$(date -Is)"

  mkdir -p "$(dirname "$LOG_FILE")"

  printf '%s action=%s project=%s investigation=%s run=%s %s\n' \
    "$timestamp" \
    "${LAB_ACTION:-unknown}" \
    "$LAB_PROJECT" \
    "${LAB_INVESTIGATION_ID:-none}" \
    "$RUN_ID" \
    "$*" >> "$LOG_FILE"
}

require_lab_config() {
  [[ "$LAB_PROJECT" == "sec-lab-docker" ]] ||
    die "unexpected project; refusing to target $LAB_PROJECT"

  require_identifier "$LAB_PROJECT"

  [[ "$EVIDENCE_PATH" == "$ROOT_DIR/"* ]] ||
    die "evidence staging must remain inside the repository"

  [[ "$STATE_PATH" == "$ROOT_DIR/"* ]] ||
    die "state must remain inside the repository"

  [[ "$RUN_STATE" == "$STATE_PATH/"* ]] ||
    die "run state must remain inside the state directory"

  [[ "$RUN_EVIDENCE" == "$EVIDENCE_PATH/"* ]] ||
    die "run evidence must remain inside evidence staging"

  require_run_identifier "$RUN_ID"
}

require_docker_client() {
  command -v docker >/dev/null 2>&1 ||
    die "docker command is unavailable; install it separately and rerun preflight"
}

require_compose() {
  require_docker_client

  docker compose version >/dev/null 2>&1 ||
    die "Docker Compose plugin is unavailable or cannot be queried"
}

check_active_run() {
  local active status status_file

  [[ -f "$STATE_PATH/active-run" ]] || return 0

  active="$(<"$STATE_PATH/active-run")"
  require_run_identifier "$active"

  if [[ "$active" == "$RUN_ID" ]]; then
    return 0
  fi

  status_file="$STATE_PATH/$active/status"

  if [[ ! -f "$status_file" ]]; then
    die "active run $active has no readable status; refusing to assume it is terminal"
  fi

  status="$(<"$status_file")"

  case "$status" in
    RUNNING|STARTING|RESETTING|CONTAINING)
      die "active run $active has non-terminal status $status"
      ;;
    STOPPED|COMPLETED|FAILED|DESTROYED|CANCELLED)
      info "previous run $active has terminal status $status"
      ;;
    *)
      die "active run $active has unknown or unsupported status: $status"
      ;;
  esac
}