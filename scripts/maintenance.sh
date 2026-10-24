```bash
#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

LAB_ACTION=maintenance

require_lab_config

command="${1:-status}"

maintenance_dir="$ROOT_DIR/state/maintenance"
record="$maintenance_dir/dependencies.yaml"
closure_record="$maintenance_dir/closure.txt"
maintenance_policy="$ROOT_DIR/config/maintenance-policy.yaml"

case "$command" in
  status)
    if [[ -f "$record" ]]; then
      cat "$record"
    else
      result NOT_TESTED "no dependency acquisition record exists"
    fi

    if [[ -f "$closure_record" ]]; then
      printf '\n'
      cat "$closure_record"
    fi
    ;;

  check)
    # Maintenance policy must exist before any acquisition workflow.
    [[ -f "$maintenance_policy" ]] ||
      die "maintenance policy missing: $maintenance_policy"

    require_docker_client

    docker info >/dev/null 2>&1 || {
      result BLOCKED "Docker daemon unavailable; image availability cannot be determined"
      exit 2
    }

    require_compose

    # This is a readiness check, not a dependency pull or network grant.
    result NOT_TESTED \
      "Docker and Compose are available; dependency-specific availability and acquisition approval remain unresolved"
    ;;

  record)
    [[ "${MAINTENANCE_APPROVAL:-false}" == "true" ]] ||
      die "set MAINTENANCE_APPROVAL=true only after defining and approving the acquisition"

    [[ -f "$maintenance_policy" ]] ||
      die "maintenance policy missing: $maintenance_policy"

    [[ $# -eq 4 ]] ||
      die "usage: maintenance.sh record NAME REFERENCE DIGEST_OR_BUILD_INPUT"

    name="$2"
    reference="$3"
    identity="$4"

    # Restrict the name for safe use in the record.
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] ||
      die "invalid dependency name"

    # Reject empty values and control characters that could corrupt YAML.
    for value in "$reference" "$identity"; do
      [[ -n "$value" ]] || die "dependency reference and identity must not be empty"
      [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] ||
        die "dependency fields must not contain line breaks"
    done

    # Quote YAML scalar values safely, including colons, quotes and
    # characters that could otherwise alter the record's structure.
    yaml_quote() {
      local value="$1"
      value="${value//\\/\\\\}"
      value="${value//\"/\\\"}"
      printf '"%s"' "$value"
    }

    mkdir -p "$maintenance_dir"

    # Do not append to a closure-marked maintenance record.
    if [[ -f "$closure_record" ]]; then
      die "maintenance is marked closed; reopen through an explicit operator-controlled workflow before recording another acquisition"
    fi

    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Create a valid YAML sequence on first use; append one entry thereafter.
    if [[ ! -f "$record" ]]; then
      printf '%s\n' 'schema_version: 1' 'dependencies:' > "$record"
    fi

    {
      printf '  - name: "%s"\n' "$name"
      printf '    reference: %s\n' "$(yaml_quote "$reference")"
      printf '    digest_or_build_input: %s\n' "$(yaml_quote "$identity")"
      printf '    acquired_utc: "%s"\n' "$timestamp"
      printf '    verification_result: "operator-recorded"\n'
    } >> "$record"

    result PASS \
      "dependency acquisition metadata recorded; no download, digest verification, or network change was performed"
    ;;

  close)
    [[ -f "$maintenance_policy" ]] ||
      die "maintenance policy missing: $maintenance_policy"

    mkdir -p "$maintenance_dir"

    # Require a record so closure is not confused with a verified,
    # completed dependency-acquisition workflow.
    [[ -f "$record" ]] ||
      die "cannot close maintenance without a dependency record"

    # Record the checks that an operator must verify. This script does
    # not claim that the checks have been executed or passed.
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    {
      printf 'closed_utc=%s\n' "$timestamp"
      printf 'status=closure-recorded\n'
      printf 'isolated_compose_validation=requires_verification\n'
      printf 'external_network_attachments=requires_verification\n'
      printf 'published_ports=requires_verification\n'
      printf 'host_and_upstream_network_isolation=not_verified_by_this_script\n'
    } > "$closure_record"

    result NOT_TESTED \
      "closure recorded; complete the isolation checks and verify the effective runtime state independently"
    ;;

  *)
    die "usage: maintenance.sh status|check|record NAME REFERENCE DIGEST_OR_BUILD_INPUT|close"
    ;;
esac

log_event "maintenance command=$command"
```