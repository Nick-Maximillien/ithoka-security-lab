"""Persistent Lab Runtime state, admission, and scoped maintenance records."""

from __future__ import annotations

import json
import hashlib
import os
import contextlib
import threading
from pathlib import Path
from typing import Any

from .foundation import LabError, ROOT, load_yaml, utc_now
from .networks import policy_json, resolve_network_policy, validate_runtime_support

RUNTIME_STATE = "runtime/runtime.json"
MAINTENANCE_STATES = {
    "requested", "rejected", "queued", "revalidated", "admitted",
    "applying", "active", "restoring", "verified_closed", "recovery_required",
}
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
        state["_loaded_revision"] = state.get("revision", 0)
        return state
    except (OSError, ValueError) as exc:
        raise LabError(f"runtime state is unreadable: {path}") from exc


def _save(root: Path, state: dict[str, Any]) -> None:
    path = _state_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    current_revision = 0
    if path.is_file():
        try:
            current_revision = json.loads(path.read_text(encoding="utf-8")).get("revision", 0)
        except (OSError, ValueError) as exc:
            raise LabError(f"runtime state changed and is unreadable: {path}") from exc
    if current_revision != state.get("_loaded_revision", current_revision):
        raise LabError("runtime state changed concurrently; re-read state and retry")
    state["revision"] = current_revision + 1
    state.pop("_loaded_revision", None)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _event(state: dict[str, Any], action: str, **details: Any) -> None:
    state["events"].append({"action": action, "utc": utc_now(), **details})


def runtime_status(root: Path = ROOT) -> dict[str, Any]:
    state = _load(root)
    return {
        "status": state["status"],
        "profile": resolve_network_policy(root)["profile"],
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
        _event(state, "configure", profile=policy["profile"])
        _save(root, state)
    return runtime_status(root)


def runtime_start(root: Path = ROOT) -> dict[str, Any]:
    with _state_lock(root):
        state = _load(root)
        if state["status"] == "RUNNING":
            return runtime_status(root)
        if any(item.get("status") == "active" for item in state["maintenance"].values()):
            raise LabError("cannot start runtime while maintenance is active")
        policy = resolve_network_policy(root)
        validate_runtime_support(policy)
        state["default_policy"] = policy
        state["status"] = "RUNNING"
        state["started_utc"] = utc_now()
        _event(state, "start", profile=policy["profile"])
        _save(root, state)
    return runtime_status(root)


def runtime_stop(root: Path = ROOT) -> dict[str, Any]:
    with _state_lock(root):
        state = _load(root)
        active = [key for key, value in state["experiments"].items() if value.get("status") == "active"]
        maintenance = [key for key, value in state["maintenance"].items() if value.get("status") == "active"]
        if active or maintenance:
            raise LabError(f"runtime has active owned resources: experiments={active}, maintenance={maintenance}")
        state["status"] = "STOPPED"
        state["stopped_utc"] = utc_now()
        _event(state, "stop")
        _save(root, state)
    return runtime_status(root)


def runtime_verify(root: Path = ROOT) -> dict[str, Any]:
    state = _load(root)
    policy = resolve_network_policy(root)
    active_policy_drift = []
    for experiment_id, record in state["experiments"].items():
        if record.get("status") == "active" and record.get("policy") is None:
            active_policy_drift.append(experiment_id)
    result = {
        "status": state["status"],
        "policy_profile": policy["profile"],
        "configured_default_changed": state.get("default_policy") not in (None, policy),
        "active_policy_drift": active_policy_drift,
        "maintenance_recovery_required": any(
            value.get("status") == "recovery_required"
            for value in state["maintenance"].values()
        ),
    }
    result["configuration_valid"] = True
    result["healthy"] = (
        state["status"] in {"RUNNING", "STOPPED"}
        and not result["active_policy_drift"]
        and not result["maintenance_recovery_required"]
    )
    _event(state, "verify", healthy=result["healthy"])
    _save(root, state)
    return result


def runtime_recover(root: Path = ROOT) -> dict[str, Any]:
    state = _load(root)
    unresolved = [
        key for key, value in state["maintenance"].items()
        if value.get("status") == "recovery_required"
    ]
    if unresolved:
        raise LabError(f"runtime recovery requires operator review: {', '.join(unresolved)}")
    _event(state, "recover", result="no-unresolved-owned-failures")
    _save(root, state)
    return runtime_verify(root)


def runtime_restart(root: Path = ROOT) -> dict[str, Any]:
    runtime_stop(root)
    return runtime_start(root)


def runtime_doctor(root: Path = ROOT) -> dict[str, Any]:
    state = _load(root)
    policy = resolve_network_policy(root)
    return {
        "runtime_state": state["status"],
        "active_experiments": [
            item["experiment_id"] for item in state["experiments"].values()
            if item.get("status") == "active"
        ],
        "policy_profile": policy["profile"],
        "configuration_valid": True,
        "maintenance_recovery_required": any(
            value.get("status") == "recovery_required"
            for value in state["maintenance"].values()
        ),
    }

def runtime_inspect(root: Path = ROOT) -> dict[str, Any]:
    return _load(root)


def admit_experiment(
    experiment_id: str,
    profile: str | None = None,
    root: Path = ROOT,
    memory_mib: int = 0,
    cpu_millicores: int = 0,
    pids: int = 0,
) -> dict[str, Any]:
    with _state_lock(root):
        state = _load(root)
        if state["status"] != "RUNNING":
            raise LabError("Lab Runtime must be running before admitting an experiment")
        if experiment_id in state["experiments"]:
            raise LabError(f"experiment is already registered: {experiment_id}")
        policy = resolve_network_policy(root, profile)
        try:
            validate_runtime_support(policy)
        except LabError as exc:
            raise LabError(f"experiment admission rejected: unsupported capability: {exc}") from exc
        capacity = load_yaml(root / "config" / "lab-capacity.yaml")
        active = [item for item in state["experiments"].values() if item.get("status") == "active"]
        used_memory = sum(item.get("memory_mib", 0) for item in active)
        used_cpu = sum(item.get("cpu_millicores", 0) for item in active)
        used_pids = sum(item.get("pids", 0) for item in active)
        conflicts = []
        for item in active:
            if item.get("enforcement_scope") == "shared-runtime-boundary" and item.get("policy", {}).get("boundaries") != policy.get("boundaries"):
                conflicts.append(item["experiment_id"])
        if conflicts:
            raise LabError(
                "experiment admission rejected: shared enforcement scope conflicts "
                f"with active experiments: {', '.join(conflicts)}"
            )
        if used_memory + memory_mib > capacity["memory_mib"] or used_cpu + cpu_millicores > capacity["cpu_millicores"] or used_pids + pids > capacity["pids"]:
            raise LabError("experiment admission rejected: declared resource capacity is exhausted")
        record = {
            "experiment_id": experiment_id,
            "status": "active",
            "decision": "admit",
            "decision_reason": "effective policy and declared resources are compatible",
            "requested_profile": profile,
            "profile": policy["profile"],
            "policy_identity": hashlib.sha256(policy_json(policy).encode("utf-8")).hexdigest(),
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
            "decision_utc": utc_now(),
            "admitted_utc": utc_now(),
        }
        state["experiments"][experiment_id] = record
        _event(state, "experiment_admitted", experiment_id=experiment_id, conflicts=conflicts)
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


def request_maintenance(
    operation_id: str,
    experiment_id: str,
    root: Path = ROOT,
    destination: str | None = None,
) -> dict[str, Any]:
    with _state_lock(root):
        state = _load(root)
        if operation_id in state["maintenance"]:
            raise LabError(f"maintenance operation already exists: {operation_id}")
        record = {
        "operation_id": operation_id,
        "experiment_id": experiment_id,
        "destination": destination,
        "status": "rejected",
        "reason": "scoped temporary policy application and verified restoration are unsupported",
        "requested_utc": utc_now(),
        }
        state["maintenance"][operation_id] = record
        _event(state, "maintenance_rejected", operation_id=operation_id, experiment_id=experiment_id)
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
