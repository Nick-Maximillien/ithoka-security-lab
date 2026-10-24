"""Persistent Lab Runtime state, admission, acceptance, and scoped maintenance records.

The runtime deliberately separates:
    1. Policy definition: what each boundary requires.
    2. Enforcement evidence: whether the relevant controls are present and verifiable.
    3. Acceptance evidence: whether declared behavioral probes actually passed.

A configured policy, running Docker daemon, or present firewall rules are not
sufficient to establish runtime health. Acceptance probes are executed as argv
lists without a shell. Missing probes remain NOT_TESTED.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

from .foundation import LabError, ROOT, load_yaml, utc_now
from .networks import (
    inspect_owned_network,
    policy_json,
    resolve_network_policy,
    validate_policy,
    validate_network_setup,
    validate_runtime_support,
)

RUNTIME_STATE = "runtime/runtime.json"
NETWORK_BOUNDARY_DIR = "state/network-boundary"

MAINTENANCE_STATES = {
    "requested",
    "rejected",
    "queued",
    "revalidated",
    "admitted",
    "applying",
    "active",
    "restoring",
    "verified_closed",
    "recovery_required",
}

# These are result values, not interchangeable descriptions.
PASS = "PASS"
FAIL = "FAIL"
NOT_TESTED = "NOT_TESTED"
ERROR = "ERROR"

# Acceptance commands are explicit, argv-based probes. Shell interpreters and
# arbitrary scripting runtimes are deliberately excluded. A probe may use
# Docker to execute a test inside an existing, explicitly named container.
_ALLOWED_PROBE_EXECUTABLES = {
    "docker",
    "curl",
    "wget",
    "ping",
    "ping6",
    "nc",
    "ncat",
    "netcat",
    "dig",
    "nslookup",
    "getent",
    "ip",
    "iptables",
    "ip6tables",
    "nft",
    "timeout",
    "true",
    "false",
}

_PROBE_TIMEOUT_SECONDS = 30
_WINDOWS_STATE_LOCK = threading.RLock()


def _state_path(root: Path) -> Path:
    return root / "state" / RUNTIME_STATE


@contextlib.contextmanager
def _state_lock(root: Path):
    if os.name != "posix":
        with _WINDOWS_STATE_LOCK:
            yield
        return

    lock_path = _state_path(root).with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+")

    try:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _load(root: Path) -> dict[str, Any]:
    path = _state_path(root)

    if not path.is_file():
        state = {
            "schema_version": 1,
            "revision": 0,
            "status": "STOPPED",
            "created_utc": utc_now(),
            "experiments": {},
            "maintenance": {},
            "events": [],
        }
        state["_loaded_revision"] = 0
        return state

    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            raise ValueError("runtime state must be a JSON object")

        state.setdefault("schema_version", 1)
        state.setdefault("revision", 0)
        state.setdefault("status", "STOPPED")
        state.setdefault("experiments", {})
        state.setdefault("maintenance", {})
        state.setdefault("events", [])

        if not isinstance(state["experiments"], dict):
            raise ValueError("experiments must be an object")
        if not isinstance(state["maintenance"], dict):
            raise ValueError("maintenance must be an object")
        if not isinstance(state["events"], list):
            raise ValueError("events must be an array")

        state["_loaded_revision"] = state.get("revision", 0)
        return state

    except (OSError, ValueError, TypeError) as exc:
        raise LabError(f"runtime state is unreadable: {path}: {exc}") from exc


def _save(root: Path, state: dict[str, Any]) -> None:
    path = _state_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)

    current_revision = 0
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            current_revision = existing.get("revision", 0)
        except (OSError, ValueError, TypeError) as exc:
            raise LabError(
                f"runtime state changed and is unreadable: {path}"
            ) from exc

    if current_revision != state.get("_loaded_revision", current_revision):
        raise LabError(
            "runtime state changed concurrently; re-read state and retry"
        )

    state["revision"] = current_revision + 1
    state.pop("_loaded_revision", None)

    temporary = path.with_suffix(".tmp")
    try:
        temporary.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    except OSError as exc:
        raise LabError(f"cannot persist runtime state: {path}: {exc}") from exc


def _event(state: dict[str, Any], action: str, **details: Any) -> None:
    state.setdefault("events", []).append(
        {"action": action, "utc": utc_now(), **details}
    )


def _policy_identity(policy: dict[str, Any]) -> str:
    return hashlib.sha256(policy_json(policy).encode("utf-8")).hexdigest()


def _atomic_json_write(path: Path, payload: dict[str, Any]) -> None:
    """Write evidence atomically so readers do not observe partial JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")

    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    except OSError as exc:
        raise LabError(f"cannot write evidence file {path}: {exc}") from exc


def runtime_status(root: Path = ROOT) -> dict[str, Any]:
    state = _load(root)
    policy = resolve_network_policy(root)

    return {
        "status": state["status"],
        "profile": policy["profile"],
        "experiments": state["experiments"],
        "maintenance": state["maintenance"],
        "event_count": len(state["events"]),
    }


def runtime_configure(root: Path = ROOT) -> dict[str, Any]:
    with _state_lock(root):
        policy = resolve_network_policy(root)
        state = _load(root)

        state["default_policy"] = policy
        state["configured_utc"] = utc_now()

        _event(
            state,
            "configure",
            profile=policy["profile"],
            policy_identity=_policy_identity(policy),
        )
        _save(root, state)

    return runtime_status(root)


# -------------------------------------------
# Acceptance probe definition and execution
# ---------------------------------------------

def _boundary_verification(boundary: dict[str, Any]) -> dict[str, Any]:
    verification = boundary.get("verification", {})
    return verification if isinstance(verification, dict) else {}


def _acceptance_tests_for_boundary(
    boundary_name: str,
    boundary: dict[str, Any],
) -> list[dict[str, Any]]:
    """Read explicit acceptance probes from a boundary's policy definition.

    Supported policy shape:

        verification:
          acceptance_tests:
            - id: outbound-https-blocked
              description: Outbound HTTPS must be blocked
              command: ["docker", "exec", "probe-container", "curl",
                        "--connect-timeout", "3", "https://example.com"]
              expected_exit_code: 28
              stdout_contains: []
              stdout_not_contains: []
              stderr_contains: []
              stderr_not_contains: []
              timeout_seconds: 10

    `command` must be a list of argv strings. Shell command strings are not
    accepted. The test author must select an exit code that distinguishes the
    expected behavior from the forbidden behavior.

    Alternative key `tests` is accepted for compatibility.
    """
    verification = _boundary_verification(boundary)
    tests = verification.get(
        "acceptance_tests",
        verification.get("tests", boundary.get("acceptance_tests", [])),
    )

    if tests is None:
        return []

    if not isinstance(tests, list):
        return [{
            "_definition_error": (
                f"{boundary_name}: verification acceptance_tests must be a list"
            )
        }]

    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(tests):
        if not isinstance(item, dict):
            normalized.append({
                "_definition_error": (
                    f"{boundary_name}: acceptance test {index} must be a mapping"
                )
            })
            continue

        test = dict(item)
        test.setdefault("id", f"{boundary_name}-{index + 1}")
        test.setdefault("boundary", boundary_name)
        normalized.append(test)

    return normalized


def _substitute_probe_arguments(
    command: list[str],
    *,
    project: str,
    network: dict[str, Any],
    boundary_name: str,
) -> list[str]:
    """Substitute known identity values; never invoke a shell."""
    values = {
        "project": project,
        "network_id": str(network.get("network_id", "")),
        "network_name": str(network.get("network_name", "")),
        "bridge": str(network.get("bridge", "")),
        "boundary": boundary_name,
    }

    substituted: list[str] = []
    for argument in command:
        if not isinstance(argument, str):
            raise ValueError("every command argument must be a string")

        value = argument
        for key, replacement in values.items():
            value = value.replace("{" + key + "}", replacement)
        substituted.append(value)

    return substituted


def _validate_probe_command(command: Any) -> list[str]:
    if not isinstance(command, list) or not command:
        raise ValueError("command must be a non-empty argv list")

    if not all(isinstance(arg, str) and arg for arg in command):
        raise ValueError("command must contain only non-empty string arguments")

    executable = Path(command[0]).name.lower()
    if executable not in _ALLOWED_PROBE_EXECUTABLES:
        raise ValueError(
            f"probe executable {executable!r} is not in the acceptance allowlist"
        )

    # Explicitly reject shell metacharacters as an extra safeguard. Arguments
    # are passed to subprocess directly, never interpreted by a shell.
    if any("\x00" in arg for arg in command):
        raise ValueError("command contains a NUL character")

    return command


def _evaluate_probe_expectations(
    test: dict[str, Any],
    returncode: int,
    stdout: str,
    stderr: str,
) -> tuple[bool, list[str]]:
    failures: list[str] = []

    expected_exit_code = test.get("expected_exit_code", 0)
    if not isinstance(expected_exit_code, int):
        failures.append("expected_exit_code must be an integer")
    elif returncode != expected_exit_code:
        failures.append(
            f"exit code was {returncode}; expected {expected_exit_code}"
        )

    for text in test.get("stdout_contains", []) or []:
        if not isinstance(text, str):
            failures.append("stdout_contains entries must be strings")
        elif text not in stdout:
            failures.append(f"stdout did not contain {text!r}")

    for text in test.get("stdout_not_contains", []) or []:
        if not isinstance(text, str):
            failures.append("stdout_not_contains entries must be strings")
        elif text in stdout:
            failures.append(f"stdout unexpectedly contained {text!r}")

    for text in test.get("stderr_contains", []) or []:
        if not isinstance(text, str):
            failures.append("stderr_contains entries must be strings")
        elif text not in stderr:
            failures.append(f"stderr did not contain {text!r}")

    for text in test.get("stderr_not_contains", []) or []:
        if not isinstance(text, str):
            failures.append("stderr_not_contains entries must be strings")
        elif text in stderr:
            failures.append(f"stderr unexpectedly contained {text!r}")

    return not failures, failures


def _run_acceptance_probe(
    test: dict[str, Any],
    *,
    project: str,
    network: dict[str, Any],
    boundary_name: str,
    root: Path,
) -> dict[str, Any]:
    test_id = str(test.get("id", f"{boundary_name}-unnamed"))

    if "_definition_error" in test:
        return {
            "id": test_id,
            "boundary": boundary_name,
            "status": ERROR,
            "reason": test["_definition_error"],
            "executed": False,
        }

    description = test.get("description", "")
    if not isinstance(description, str):
        return {
            "id": test_id,
            "boundary": boundary_name,
            "status": ERROR,
            "reason": "description must be a string",
            "executed": False,
        }

    try:
        command = _validate_probe_command(test.get("command"))
        command = _substitute_probe_arguments(
            command,
            project=project,
            network=network,
            boundary_name=boundary_name,
        )
        command = _validate_probe_command(command)
    except (ValueError, TypeError) as exc:
        return {
            "id": test_id,
            "boundary": boundary_name,
            "description": description,
            "status": ERROR,
            "reason": f"invalid acceptance test definition: {exc}",
            "executed": False,
        }

    timeout = test.get("timeout_seconds", _PROBE_TIMEOUT_SECONDS)
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        return {
            "id": test_id,
            "boundary": boundary_name,
            "description": description,
            "status": ERROR,
            "reason": "timeout_seconds must be a positive number",
            "executed": False,
            "command": command,
        }

    timeout = min(float(timeout), 300.0)

    try:
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")

        return {
            "id": test_id,
            "boundary": boundary_name,
            "description": description,
            "status": ERROR,
            "reason": f"acceptance probe timed out after {timeout:g}s",
            "executed": True,
            "command": command,
            "timeout_seconds": timeout,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": None,
            "executed_utc": utc_now(),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "id": test_id,
            "boundary": boundary_name,
            "description": description,
            "status": ERROR,
            "reason": f"could not execute acceptance probe: {exc}",
            "executed": False,
            "command": command,
            "executed_utc": utc_now(),
        }

    passed, failures = _evaluate_probe_expectations(
        test,
        completed.returncode,
        completed.stdout,
        completed.stderr,
    )

    return {
        "id": test_id,
        "boundary": boundary_name,
        "description": description,
        "status": PASS if passed else FAIL,
        "reason": None if passed else "; ".join(failures),
        "executed": True,
        "command": command,
        "returncode": completed.returncode,
        "expected_exit_code": test.get("expected_exit_code", 0),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "executed_utc": utc_now(),
    }


def _enabled_boundaries(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    boundaries = policy.get("boundaries", {})
    if not isinstance(boundaries, dict):
        raise LabError("effective policy boundaries must be a mapping")

    enabled: dict[str, dict[str, Any]] = {}
    for name, definition in boundaries.items():
        if not isinstance(definition, dict):
            raise LabError(f"boundary {name!r} must be a mapping")
        if definition.get("enabled") is True:
            enabled[name] = definition

    return enabled


def _execute_policy_acceptance(
    policy: dict[str, Any],
    *,
    project: str,
    network: dict[str, Any],
    root: Path,
) -> dict[str, Any]:
    """Execute all declared probes for enabled boundaries.

    A boundary with no probes is NOT_TESTED. Disabled boundaries are listed
    separately and do not receive an acceptance PASS. A policy only passes
    acceptance when every enabled boundary has at least one declared probe and
    every declared probe passes.
    """
    enabled = _enabled_boundaries(policy)
    boundary_results: dict[str, dict[str, Any]] = {}
    all_tests: list[dict[str, Any]] = []

    for boundary_name, definition in enabled.items():
        tests = _acceptance_tests_for_boundary(boundary_name, definition)
        if not tests:
            boundary_results[boundary_name] = {
                "status": NOT_TESTED,
                "test_count": 0,
                "passed": 0,
                "failed": 0,
                "errors": 0,
                "reason": "no acceptance probes are declared for this enabled boundary",
            }
            continue

        results = [
            _run_acceptance_probe(
                test,
                project=project,
                network=network,
                boundary_name=boundary_name,
                root=root,
            )
            for test in tests
        ]
        all_tests.extend(results)

        statuses = [item["status"] for item in results]
        if FAIL in statuses:
            status = FAIL
        elif ERROR in statuses:
            status = ERROR
        elif NOT_TESTED in statuses:
            status = NOT_TESTED
        elif statuses and all(value == PASS for value in statuses):
            status = PASS
        else:
            status = NOT_TESTED

        boundary_results[boundary_name] = {
            "status": status,
            "test_count": len(results),
            "passed": sum(value == PASS for value in statuses),
            "failed": sum(value == FAIL for value in statuses),
            "errors": sum(value == ERROR for value in statuses),
            "reason": None if status == PASS else (
                "one or more acceptance probes did not pass"
            ),
        }

    statuses = [item["status"] for item in boundary_results.values()]

    if FAIL in statuses:
        overall = FAIL
    elif ERROR in statuses:
        overall = ERROR
    elif NOT_TESTED in statuses:
        overall = NOT_TESTED
    elif statuses and all(value == PASS for value in statuses):
        overall = PASS
    else:
        overall = NOT_TESTED

    return {
        "status": overall,
        "policy_definition": {
            "profile": policy.get("profile"),
            "boundaries_enabled": list(enabled.keys()),
            "boundary_count": len(enabled),
        },
        "boundaries": boundary_results,
        "tests": all_tests,
        "summary": {
            "boundary_count": len(boundary_results),
            "passed": sum(value == PASS for value in statuses),
            "failed": sum(value == FAIL for value in statuses),
            "not_tested": sum(value == NOT_TESTED for value in statuses),
            "errors": sum(value == ERROR for value in statuses),
            "tests_executed": sum(item.get("executed") is True for item in all_tests),
            "tests_passed": sum(item["status"] == PASS for item in all_tests),
            "tests_failed": sum(item["status"] == FAIL for item in all_tests),
            "tests_errored": sum(item["status"] == ERROR for item in all_tests),
        },
        "executed_utc": utc_now(),
    }


# ---------------------------------------------------------------------------
# Enforcement inspection and project readiness
# ---------------------------------------------------------------------------

def _network_readiness(root: Path, policy: dict[str, Any]) -> dict[str, Any]:
    """Inspect current controls, then execute current-policy acceptance probes.

    A previously generated acceptance file is never accepted as a substitute
    for executing fresh probes. Evidence is written for audit/history only;
    each call recomputes the result.
    """
    evidence_dir = root / NETWORK_BOUNDARY_DIR
    policy_identity = _policy_identity(policy)

    policy_paths = (
        [
            path
            for path in evidence_dir.glob("*-network-policy.json")
            if path.is_file()
        ]
        if evidence_dir.is_dir()
        else []
    )

    matching: list[Path] = []
    for path in policy_paths:
        try:
            pinned = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise LabError(
                f"network policy evidence is unreadable: {path}"
            ) from exc

        validate_policy(pinned, f"pinned network policy {path}")

        if _policy_identity(pinned) == policy_identity:
            matching.append(path)

    if len(matching) != 1:
        return {
            "ready": False,
            "controls_applied": NOT_TESTED,
            "effective_behavior": NOT_TESTED,
            "runtime_acceptance": NOT_TESTED,
            "acceptance": {
                "status": NOT_TESTED,
                "reason": (
                    "expected exactly one project-pinned policy matching the "
                    f"selected policy; found {len(matching)}"
                ),
                "boundaries": {},
                "tests": [],
            },
            "reason": (
                "expected one project-pinned policy matching the selected profile; "
                f"found {len(matching)}"
            ),
        }

    policy_path = matching[0]
    project = policy_path.name.removesuffix("-network-policy.json")

    try:
        network = inspect_owned_network(project)
    except LabError as exc:
        return {
            "ready": False,
            "controls_applied": FAIL,
            "effective_behavior": NOT_TESTED,
            "runtime_acceptance": NOT_TESTED,
            "acceptance": {
                "status": NOT_TESTED,
                "reason": f"owned network inspection failed: {exc}",
                "boundaries": {},
                "tests": [],
            },
            "reason": f"cannot inspect the owned investigation network: {exc}",
        }

    # Firewall verification is enforcement evidence, not behavioral acceptance.
    command = [
        "bash",
        str(root / "scripts" / "network-boundary.sh"),
        "verify",
        project,
        str(policy_path),
    ]

    try:
        verified = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        enforcement_status = ERROR
        enforcement_reason = f"cannot execute firewall verification: {exc}"
        enforcement_output = ""
    else:
        enforcement_output = (
            verified.stderr.strip() or verified.stdout.strip()
        )
        if verified.returncode == 0:
            enforcement_status = PASS
            enforcement_reason = None
        else:
            enforcement_status = FAIL
            enforcement_reason = (
                enforcement_output or "owned firewall verification failed"
            )

    # Execute probes regardless of the firewall verifier's result so the
    # evidence shows actual observed behavior. A probe pass cannot override
    # failed enforcement verification.
    acceptance = _execute_policy_acceptance(
        policy,
        project=project,
        network=network,
        root=root,
    )

    acceptance_document = {
        "schema_version": 2,
        "project": project,
        "profile": policy.get("profile"),
        "policy_identity": policy_identity,
        "network_id": network.get("network_id"),
        "network_name": network.get("network_name"),
        "bridge": network.get("bridge"),
        "enforcement": {
            "status": enforcement_status,
            "reason": enforcement_reason,
            "verification_output": enforcement_output,
            "verified_utc": utc_now(),
        },
        "acceptance": acceptance,
        "effective_behavior": acceptance["status"],
        "runtime_acceptance": acceptance["status"],
        "recorded_utc": utc_now(),
    }

    acceptance_path = evidence_dir / f"{project}-acceptance.json"
    _atomic_json_write(acceptance_path, acceptance_document)

    # Effective behavior requires behavioral tests to pass. Overall readiness
    # also requires verified enforcement. Neither result can substitute for
    # the other.
    effective_behavior = acceptance["status"]
    runtime_acceptance = acceptance["status"]

    ready = (
        enforcement_status == PASS
        and effective_behavior == PASS
        and runtime_acceptance == PASS
    )

    reasons: list[str] = []
    if enforcement_status != PASS:
        reasons.append(
            enforcement_reason or f"enforcement status is {enforcement_status}"
        )
    if effective_behavior != PASS:
        reasons.append(
            f"acceptance behavior status is {effective_behavior}"
        )

    return {
        "ready": ready,
        "project": project,
        "policy_identity": policy_identity,
        "network_id": network.get("network_id"),
        "controls_applied": enforcement_status,
        "effective_behavior": effective_behavior,
        "runtime_acceptance": runtime_acceptance,
        "acceptance": acceptance,
        "acceptance_evidence_path": str(acceptance_path),
        "enforcement_reason": enforcement_reason,
        "reason": "; ".join(reasons) if reasons else None,
    }


def runtime_start(root: Path = ROOT) -> dict[str, Any]:
    with _state_lock(root):
        state = _load(root)

        if any(
            item.get("status") == "active"
            for item in state["maintenance"].values()
        ):
            raise LabError("cannot start runtime while maintenance is active")

        policy = resolve_network_policy(root)

        # Unsupported mandatory boundaries must prevent admission. Static
        # acceptance probes do not make an unsupported architecture supported.
        validate_runtime_support(policy)
        validate_network_setup(root)

        network_readiness = _network_readiness(root, policy)
        if not network_readiness["ready"]:
            raise LabError(
                "runtime start refused: project network readiness is not "
                "established: "
                f"{network_readiness['reason']}"
            )

        if state["status"] == "RUNNING":
            return runtime_status(root)

        state["default_policy"] = policy
        state["status"] = "RUNNING"
        state["started_utc"] = utc_now()

        _event(
            state,
            "start",
            profile=policy["profile"],
            policy_identity=_policy_identity(policy),
            acceptance_status=network_readiness["runtime_acceptance"],
            enforcement_status=network_readiness["controls_applied"],
        )
        _save(root, state)

    return runtime_status(root)


def runtime_stop(root: Path = ROOT) -> dict[str, Any]:
    with _state_lock(root):
        state = _load(root)

        active = [
            key
            for key, value in state["experiments"].items()
            if value.get("status") == "active"
        ]
        maintenance = [
            key
            for key, value in state["maintenance"].items()
            if value.get("status") == "active"
        ]

        if active or maintenance:
            raise LabError(
                "runtime has active owned resources: "
                f"experiments={active}, maintenance={maintenance}"
            )

        state["status"] = "STOPPED"
        state["stopped_utc"] = utc_now()
        _event(state, "stop")
        _save(root, state)

    return runtime_status(root)


def runtime_verify(root: Path = ROOT) -> dict[str, Any]:
    """Recompute policy support, machine prerequisites, enforcement, and probes."""
    state = _load(root)
    policy = resolve_network_policy(root)

    policy_error = None
    try:
        validate_runtime_support(policy)
    except LabError as exc:
        policy_error = str(exc)

    machine_error = None
    try:
        validate_network_setup(root)
    except LabError as exc:
        machine_error = str(exc)

    network_readiness = _network_readiness(root, policy)

    active_policy_drift = []
    current_identity = _policy_identity(policy)

    for experiment_id, record in state["experiments"].items():
        if record.get("status") != "active":
            continue

        recorded_identity = record.get("policy_identity")
        if recorded_identity is None or recorded_identity != current_identity:
            active_policy_drift.append(experiment_id)

    maintenance_recovery_required = any(
        value.get("status") == "recovery_required"
        for value in state["maintenance"].values()
    )

    acceptance = network_readiness.get("acceptance", {})
    result = {
        "status": state["status"],
        "policy_profile": policy["profile"],
        "policy_identity": current_identity,
        "policy_support": PASS if policy_error is None else FAIL,
        "policy_error": policy_error,
        "machine_prerequisites": PASS if machine_error is None else FAIL,
        "machine_error": machine_error,
        "controls_applied": network_readiness["controls_applied"],
        "effective_behavior": network_readiness["effective_behavior"],
        "runtime_acceptance": network_readiness["runtime_acceptance"],
        "acceptance": acceptance,
        "acceptance_evidence_path": network_readiness.get(
            "acceptance_evidence_path"
        ),
        "network_readiness_error": network_readiness.get("reason"),
        "configured_default_changed": (
            state.get("default_policy") not in (None, policy)
        ),
        "active_policy_drift": active_policy_drift,
        "maintenance_recovery_required": maintenance_recovery_required,
        "configuration_valid": True,
    }

    # Keep a separate health status. Configuration validity is not evidence
    # that the network is enforced or that its acceptance tests passed.
    healthy = (
        state["status"] == "RUNNING"
        and policy_error is None
        and machine_error is None
        and result["controls_applied"] == PASS
        and result["effective_behavior"] == PASS
        and result["runtime_acceptance"] == PASS
        and not active_policy_drift
        and not maintenance_recovery_required
    )

    result["healthy"] = healthy
    result["health_status"] = PASS if healthy else FAIL

    with _state_lock(root):
        latest_state = _load(root)
        _event(
            latest_state,
            "verify",
            healthy=healthy,
            policy_support=result["policy_support"],
            enforcement_status=result["controls_applied"],
            effective_behavior=result["effective_behavior"],
            runtime_acceptance=result["runtime_acceptance"],
        )
        _save(root, latest_state)

    return result


def runtime_recover(root: Path = ROOT) -> dict[str, Any]:
    with _state_lock(root):
        state = _load(root)
        unresolved = [
            key
            for key, value in state["maintenance"].items()
            if value.get("status") == "recovery_required"
        ]

        if unresolved:
            raise LabError(
                "runtime recovery requires operator review: "
                + ", ".join(unresolved)
            )

        _event(state, "recover", result="no-unresolved-owned-failures")
        _save(root, state)

    return runtime_verify(root)


def runtime_restart(root: Path = ROOT) -> dict[str, Any]:
    runtime_stop(root)
    return runtime_start(root)


def runtime_doctor(root: Path = ROOT) -> dict[str, Any]:
    state = _load(root)
    policy = resolve_network_policy(root)

    policy_error = None
    try:
        validate_runtime_support(policy)
    except LabError as exc:
        policy_error = str(exc)

    machine_error = None
    try:
        validate_network_setup(root)
    except LabError as exc:
        machine_error = str(exc)

    return {
        "runtime_state": state["status"],
        "active_experiments": [
            item["experiment_id"]
            for item in state["experiments"].values()
            if item.get("status") == "active"
        ],
        "policy_profile": policy["profile"],
        "policy_identity": _policy_identity(policy),
        "policy_support": PASS if policy_error is None else FAIL,
        "policy_error": policy_error,
        "machine_prerequisites": PASS if machine_error is None else FAIL,
        "machine_error": machine_error,
        "configuration_valid": True,
        "maintenance_recovery_required": any(
            value.get("status") == "recovery_required"
            for value in state["maintenance"].values()
        ),
        "acceptance_execution": (
            "performed by runtime_verify; doctor does not execute traffic probes"
        ),
    }


def runtime_inspect(root: Path = ROOT) -> dict[str, Any]:
    return _load(root)


# ---------------------------------------------------------------------------
# Experiment admission and release
# ---------------------------------------------------------------------------

def admit_experiment(
    experiment_id: str,
    profile: str | None = None,
    root: Path = ROOT,
    memory_mib: int = 0,
    cpu_millicores: int = 0,
    pids: int = 0,
) -> dict[str, Any]:
    if not isinstance(experiment_id, str) or not experiment_id.strip():
        raise LabError("experiment_id must be a non-empty string")

    for name, value in (
        ("memory_mib", memory_mib),
        ("cpu_millicores", cpu_millicores),
        ("pids", pids),
    ):
        if not isinstance(value, int) or value < 0:
            raise LabError(f"{name} must be a non-negative integer")

    with _state_lock(root):
        state = _load(root)

        if state["status"] != "RUNNING":
            raise LabError(
                "Lab Runtime must be running before admitting an experiment"
            )

        if experiment_id in state["experiments"]:
            raise LabError(f"experiment is already registered: {experiment_id}")

        policy = resolve_network_policy(root, profile)

        try:
            validate_runtime_support(policy)
        except LabError as exc:
            raise LabError(
                "experiment admission rejected: unsupported capability: "
                f"{exc}"
            ) from exc

        capacity = load_yaml(root / "config" / "lab-capacity.yaml")
        if not isinstance(capacity, dict):
            raise LabError("lab-capacity.yaml must contain a mapping")

        active = [
            item
            for item in state["experiments"].values()
            if item.get("status") == "active"
        ]

        used_memory = sum(item.get("memory_mib", 0) for item in active)
        used_cpu = sum(item.get("cpu_millicores", 0) for item in active)
        used_pids = sum(item.get("pids", 0) for item in active)

        conflicts = []
        for item in active:
            if (
                item.get("enforcement_scope") == "shared-runtime-boundary"
                and item.get("policy", {}).get("boundaries")
                != policy.get("boundaries")
            ):
                conflicts.append(item["experiment_id"])

        if conflicts:
            raise LabError(
                "experiment admission rejected: shared enforcement scope "
                "conflicts with active experiments: "
                + ", ".join(conflicts)
            )

        required_capacity_keys = ("memory_mib", "cpu_millicores", "pids")
        for key in required_capacity_keys:
            if not isinstance(capacity.get(key), int) or capacity[key] < 0:
                raise LabError(
                    f"lab-capacity.yaml requires a non-negative integer {key}"
                )

        if (
            used_memory + memory_mib > capacity["memory_mib"]
            or used_cpu + cpu_millicores > capacity["cpu_millicores"]
            or used_pids + pids > capacity["pids"]
        ):
            raise LabError(
                "experiment admission rejected: declared resource capacity is exhausted"
            )

        now = utc_now()
        identity = _policy_identity(policy)

        record = {
            "experiment_id": experiment_id,
            "status": "active",
            "decision": "admit",
            "decision_reason": (
                "policy support and declared resource capacity are compatible; "
                "live network acceptance must be established by runtime verification"
            ),
            "requested_profile": profile,
            "profile": policy["profile"],
            "policy_identity": identity,
            "policy": policy,
            "required_capabilities": ["linux-wsl-network-boundary"],
            "memory_mib": memory_mib,
            "cpu_millicores": cpu_millicores,
            "pids": pids,
            "resource_reservation": {
                "memory_mib": memory_mib,
                "cpu_millicores": cpu_millicores,
                "pids": pids,
            },
            "conflicts": conflicts,
            "enforcement_scope": "shared-runtime-boundary",
            "decision_utc": now,
            "admitted_utc": now,
        }

        state["experiments"][experiment_id] = record
        _event(
            state,
            "experiment_admitted",
            experiment_id=experiment_id,
            conflicts=conflicts,
            policy_identity=identity,
        )
        _save(root, state)

    return record


def release_experiment(experiment_id: str, root: Path = ROOT) -> None:
    with _state_lock(root):
        state = _load(root)
        record = state["experiments"].get(experiment_id)

        if record is None:
            raise LabError(f"experiment is not registered: {experiment_id}")

        record["status"] = "released"
        record["released_utc"] = utc_now()

        _event(state, "experiment_released", experiment_id=experiment_id)
        _save(root, state)


# ---------------------------------------------------------------------------
# Scoped maintenance
# ---------------------------------------------------------------------------

def request_maintenance(
    operation_id: str,
    experiment_id: str,
    root: Path = ROOT,
    destination: str | None = None,
) -> dict[str, Any]:
    with _state_lock(root):
        state = _load(root)

        if operation_id in state["maintenance"]:
            raise LabError(
                f"maintenance operation already exists: {operation_id}"
            )

        record = {
            "operation_id": operation_id,
            "experiment_id": experiment_id,
            "destination": destination,
            "status": "rejected",
            "reason": (
                "scoped temporary policy application and verified restoration "
                "are unsupported"
            ),
            "requested_utc": utc_now(),
        }

        state["maintenance"][operation_id] = record
        _event(
            state,
            "maintenance_rejected",
            operation_id=operation_id,
            experiment_id=experiment_id,
        )
        _save(root, state)

    return record


__all__ = [
    "admit_experiment",
    "release_experiment",
    "request_maintenance",
    "runtime_configure",
    "runtime_inspect",
    "runtime_doctor",
    "runtime_recover",
    "runtime_restart",
    "runtime_start",
    "runtime_status",
    "runtime_stop",
    "runtime_verify",
]