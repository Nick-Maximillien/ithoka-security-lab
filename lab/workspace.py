"""Command-driven, disposable researcher workspaces.

Workspace state is descriptive, not runtime authorization.

The runtime/network-boundary layer remains responsible for admitting
experiments and verifying policy enforcement and runtime acceptance.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any, Callable

from .foundation import (
    ID_PATTERN,
    LabError,
    ROOT,
    ensure_inside,
    sha256_bytes,
    utc_now,
    require_available_image,
)


OWNER = "security-lab"
WORKSPACE_STATUSES = {"READY", "RUNNING", "STOPPED"}
TOOL_TIMEOUT_SECONDS = 120
TOOL_MEMORY = "128m"
TOOL_PIDS_LIMIT = "64"
TOOL_CPUS = "0.5"
TOOL_USER = "1000:1000"
TOOL_TMPFS = "/tmp:rw,noexec,nosuid,size=64m"


def _root_path(root: Path) -> Path:
    """Return the canonical project root."""
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise LabError(f"project root cannot be resolved: {root}") from exc

    if not resolved.is_dir():
        raise LabError(f"project root is not a directory: {resolved}")

    return resolved


def _workspace(root: Path, experiment_id: str) -> Path:
    """Resolve an experiment directory without permitting path traversal."""
    if not isinstance(experiment_id, str) or not ID_PATTERN.fullmatch(experiment_id):
        raise LabError(
            "experiment ID must contain only lowercase letters, digits, and hyphens"
        )

    root = _root_path(root)
    candidate = root / "state" / "experiments" / experiment_id

    directory = ensure_inside(
        root,
        candidate,
        "experiment workspace",
    )

    if directory.is_symlink():
        raise LabError("experiment workspace must not be a symlink")

    return directory


def _required_directory(directory: Path, description: str) -> Path:
    """Require an existing, real directory rather than a symlink."""
    if directory.is_symlink():
        raise LabError(f"{description} must not be a symlink: {directory}")

    if not directory.is_dir():
        raise LabError(f"{description} is missing or is not a directory: {directory}")

    return directory


def _read_json(path: Path, description: str) -> dict[str, Any]:
    """Read a JSON object and reject malformed or unexpected top-level data."""
    if path.is_symlink() or not path.is_file():
        raise LabError(f"{description} is missing or is not a regular file: {path}")

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LabError(f"cannot read {description}: {exc}") from exc

    if not isinstance(value, dict):
        raise LabError(f"{description} must contain a JSON object")

    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    """Write JSON to a new temporary file and atomically replace the destination."""
    if path.is_symlink():
        raise LabError(f"refusing to write through a symlink: {path}")

    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")

    try:
        temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    except (OSError, TypeError, ValueError) as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise LabError(f"cannot write {path}: {exc}") from exc


def _write_metadata(directory: Path, metadata: dict[str, Any]) -> None:
    _required_directory(directory, "experiment directory")
    _write_json(directory / "experiment.json", metadata)


def _validate_metadata(
    experiment_id: str,
    directory: Path,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Validate persisted identity and status before trusting metadata."""
    if metadata.get("experiment_id") != experiment_id:
        raise LabError("experiment metadata identity does not match its directory")

    if metadata.get("owner") != OWNER:
        raise LabError("experiment metadata has an unexpected owner")

    status = metadata.get("status")
    if status not in WORKSPACE_STATUSES:
        raise LabError(f"experiment has an unsupported status: {status!r}")

    for key in ("workspace", "evidence", "mutable_state"):
        value = metadata.get(key)
        if not isinstance(value, str) or not value:
            raise LabError(f"experiment metadata field {key!r} is invalid")

        resolved = ensure_inside(
            _root_path(ROOT if directory == _workspace(ROOT, experiment_id) else directory.parents[2]),
            Path(value),
            f"experiment metadata {key}",
        )

        if key == "workspace" and resolved != directory / "workspace":
            raise LabError("workspace metadata path does not match the experiment directory")

        if key == "evidence" and resolved != directory / "evidence":
            raise LabError("evidence metadata path does not match the experiment directory")

    return metadata


def _inspect(
    experiment_id: str,
    root: Path,
) -> tuple[Path, dict[str, Any]]:
    directory = _workspace(root, experiment_id)
    _required_directory(directory, "experiment directory")

    metadata = _read_json(
        directory / "experiment.json",
        "experiment metadata",
    )

    if metadata.get("experiment_id") != experiment_id:
        raise LabError("experiment metadata identity does not match its directory")

    if metadata.get("owner") != OWNER:
        raise LabError("experiment metadata has an unexpected owner")

    if metadata.get("status") not in WORKSPACE_STATUSES:
        raise LabError(
            f"experiment has an unsupported status: {metadata.get('status')!r}"
        )

    for name in ("workspace", "evidence", "records"):
        _required_directory(directory / name, f"experiment {name} directory")

    return directory, metadata


def init_experiment(experiment_id: str, root: Path = ROOT) -> Path:
    """Create a new disposable workspace and its evidence directories."""
    root = _root_path(root)
    directory = _workspace(root, experiment_id)

    if directory.exists() or directory.is_symlink():
        raise LabError(f"experiment already exists: {experiment_id}")

    parent = directory.parent
    parent.mkdir(parents=True, exist_ok=True)

    # Do not follow a symlinked state/experiments parent.
    if parent.is_symlink():
        raise LabError("experiment parent directory must not be a symlink")

    try:
        directory.mkdir()
        (directory / "workspace").mkdir()
        (directory / "evidence").mkdir()
        (directory / "records").mkdir()

        metadata = {
            "experiment_id": experiment_id,
            "owner": OWNER,
            "status": "READY",
            "created_utc": utc_now(),
            "workspace": str((directory / "workspace").relative_to(root)),
            "evidence": str((directory / "evidence").relative_to(root)),
            "records": str((directory / "records").relative_to(root)),
            "mutable_state": str((directory / "workspace").relative_to(root)),
            "resource_scope": f"{OWNER}/{experiment_id}",
            "runtime_admission": "NOT_ESTABLISHED",
            "network_enforcement": "NOT_ESTABLISHED",
            "runtime_acceptance": "NOT_ESTABLISHED",
        }

        _write_metadata(directory, metadata)

    except Exception:
        # Roll back only this newly created directory. Do not delete a
        # pre-existing experiment or any path outside the new directory.
        if directory.exists() and not directory.is_symlink():
            shutil.rmtree(directory, ignore_errors=True)
        raise

    return directory


def inspect_experiment(
    experiment_id: str,
    root: Path = ROOT,
) -> dict[str, Any]:
    """Return validated experiment metadata."""
    _, metadata = _inspect(experiment_id, root)
    return metadata


def enter_experiment(
    experiment_id: str,
    root: Path = ROOT,
) -> Path:
    """Return the workspace path after validating experiment identity."""
    directory, _ = _inspect(experiment_id, root)
    return _required_directory(directory / "workspace", "experiment workspace")


def stop_experiment(
    experiment_id: str,
    root: Path = ROOT,
) -> None:
    """Mark a workspace stopped.

    This updates workspace metadata only. It does not stop Docker containers
    or prove that runtime resources have been released.
    """
    directory, metadata = _inspect(experiment_id, root)

    if metadata["status"] == "STOPPED":
        return

    metadata["status"] = "STOPPED"
    metadata["stopped_utc"] = utc_now()
    _write_metadata(directory, metadata)


def reset_experiment(
    experiment_id: str,
    root: Path = ROOT,
) -> None:
    """Reset mutable workspace contents without deleting evidence or records."""
    directory, metadata = _inspect(experiment_id, root)

    if metadata["status"] == "RUNNING":
        raise LabError("running experiment must be stopped before reset")

    workspace = _required_directory(
        directory / "workspace",
        "experiment workspace",
    )

    # Build a replacement before swapping it in, so a failed mkdir does not
    # silently leave the workspace deleted.
    replacement = directory / f".workspace-reset-{uuid.uuid4().hex}"

    try:
        replacement.mkdir()
        shutil.rmtree(workspace)
        replacement.rename(workspace)
    except OSError as exc:
        if replacement.exists() and not replacement.is_symlink():
            shutil.rmtree(replacement, ignore_errors=True)
        raise LabError(f"could not reset experiment workspace: {exc}") from exc

    metadata["status"] = "READY"
    metadata["reset_utc"] = utc_now()
    metadata["runtime_admission"] = "NOT_ESTABLISHED"
    metadata["network_enforcement"] = "NOT_ESTABLISHED"
    metadata["runtime_acceptance"] = "NOT_ESTABLISHED"
    _write_metadata(directory, metadata)


def _preservation_destination(root: Path, experiment_id: str) -> Path:
    destination = root / "evidence-staging" / "experiments" / experiment_id
    destination = ensure_inside(
        root,
        destination,
        "preserved experiment evidence",
    )

    if destination.is_symlink():
        raise LabError("preserved evidence destination must not be a symlink")

    return destination


def destroy_experiment(
    experiment_id: str,
    root: Path = ROOT,
) -> None:
    """Destroy a stopped workspace only after preserving its evidence and records."""
    root = _root_path(root)
    directory, metadata = _inspect(experiment_id, root)

    if metadata["status"] == "RUNNING":
        raise LabError("running experiment must be stopped before destruction")

    evidence = _required_directory(directory / "evidence", "experiment evidence")
    records = _required_directory(directory / "records", "experiment records")

    # Preserve the complete evidence and records trees. Command records can
    # contain diagnostic information even when no evidence files were collected.
    has_preservable_data = (
        any(evidence.iterdir())
        or any(records.iterdir())
    )

    preserved = _preservation_destination(root, experiment_id)

    if has_preservable_data:
        if preserved.exists():
            raise LabError(
                f"preserved evidence destination already exists: {preserved}"
            )

        preserved.parent.mkdir(parents=True, exist_ok=True)

        if preserved.parent.is_symlink():
            raise LabError("evidence-staging parent must not be a symlink")

        temporary = preserved.parent / f".{experiment_id}-{uuid.uuid4().hex}.tmp"

        try:
            temporary.mkdir()
            shutil.copytree(evidence, temporary / "evidence")
            shutil.copytree(records, temporary / "records")

            # Copy the experiment metadata for traceability.
            shutil.copy2(directory / "experiment.json", temporary / "experiment.json")

            # Verify every copied regular file by content hash before committing.
            _verify_copied_tree(evidence, temporary / "evidence")
            _verify_copied_tree(records, temporary / "records")

            (temporary / "preservation.json").write_text(
                json.dumps(
                    {
                        "experiment_id": experiment_id,
                        "preserved_utc": utc_now(),
                        "owner": OWNER,
                        "evidence_preserved": True,
                        "records_preserved": True,
                    },
                    indent=2,
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )

            temporary.rename(preserved)

        except Exception:
            if temporary.exists() and not temporary.is_symlink():
                shutil.rmtree(temporary, ignore_errors=True)
            raise

    # If evidence/records exist, they are now preserved at the destination.
    # The workspace directory is deleted only after preservation succeeds.
    try:
        shutil.rmtree(directory)
    except OSError as exc:
        raise LabError(
            "evidence preservation completed, but workspace deletion failed: "
            f"{exc}"
        ) from exc


def _verify_copied_tree(source: Path, destination: Path) -> None:
    """Verify copied regular files using relative paths and SHA-256 hashes."""
    source_files = {
        item.relative_to(source): item
        for item in source.rglob("*")
        if item.is_file() and not item.is_symlink()
    }

    destination_files = {
        item.relative_to(destination): item
        for item in destination.rglob("*")
        if item.is_file() and not item.is_symlink()
    }

    if set(source_files) != set(destination_files):
        raise LabError("preserved tree verification failed: file list differs")

    for relative, source_file in source_files.items():
        destination_file = destination_files[relative]

        if sha256_bytes(source_file.read_bytes()) != sha256_bytes(
            destination_file.read_bytes()
        ):
            raise LabError(
                f"preserved tree verification failed for {relative}"
            )


def collect_evidence(
    experiment_id: str,
    paths: list[Path],
    root: Path = ROOT,
) -> Path:
    """Copy evidence files into an experiment and write an integrity manifest."""
    root = _root_path(root)
    directory, _ = _inspect(experiment_id, root)

    evidence = _required_directory(directory / "evidence", "experiment evidence")
    entries: list[dict[str, Any]] = []
    seen_destinations: set[str] = set()

    for source in paths:
        resolved = ensure_inside(root, source, "evidence source")

        if resolved.is_symlink() or not resolved.is_file():
            raise LabError(f"evidence source is not a regular file: {resolved}")

        if resolved.name == "manifest.json":
            raise LabError("manifest.json is reserved for the evidence manifest")

        if resolved.name in seen_destinations:
            raise LabError(
                f"multiple evidence sources have the same filename: {resolved.name}"
            )
        seen_destinations.add(resolved.name)

        destination = evidence / resolved.name

        if destination.exists() or destination.is_symlink():
            raise LabError(f"refusing to overwrite evidence: {destination}")

        try:
            shutil.copy2(resolved, destination)
        except OSError as exc:
            raise LabError(f"could not copy evidence file {resolved}: {exc}") from exc

        copied_bytes = destination.read_bytes()
        entries.append(
            {
                "source": str(resolved.relative_to(root)),
                "path": str(destination.relative_to(root)),
                "sha256": sha256_bytes(copied_bytes),
                "size": len(copied_bytes),
            }
        )

    manifest_path = evidence / "manifest.json"

    if manifest_path.exists() or manifest_path.is_symlink():
        raise LabError(
            "evidence manifest already exists; refusing to overwrite it"
        )

    manifest = {
        "experiment_id": experiment_id,
        "owner": OWNER,
        "collected_utc": utc_now(),
        "files": entries,
    }

    _write_json(manifest_path, manifest)
    return manifest_path


def _validate_tool_arguments(image: str, command: list[str]) -> None:
    if not isinstance(image, str) or not image.strip():
        raise LabError("a Docker image is required")

    if not isinstance(command, list) or not command:
        raise LabError("a non-empty command list is required")

    if any(not isinstance(value, str) for value in command):
        raise LabError("every command argument must be a string")

    values = [image, *command]

    if any("\x00" in value for value in values):
        raise LabError("tool image and command must not contain NUL bytes")

    if any(not value for value in command):
        raise LabError("empty command arguments are not allowed")

    # Require a named image reference, not a flag that could alter Docker CLI
    # behavior. Digests are allowed; image approval remains the responsibility
    # of the catalog/policy validation layer.
    if image.startswith("-"):
        raise LabError("Docker image reference must not begin with '-'")

    if image.startswith("/") or image.startswith("."):
        raise LabError("local filesystem paths are not valid approved image references")


def _tool_command(image: str, command: list[str]) -> list[str]:
    """Build a fixed, non-interactive Docker invocation."""
    return [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--tmpfs",
        TOOL_TMPFS,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        TOOL_MEMORY,
        "--pids-limit",
        TOOL_PIDS_LIMIT,
        "--cpus",
        TOOL_CPUS,
        "--user",
        TOOL_USER,
        "--",
        image,
        *command,
    ]



def execute_tool(
    experiment_id: str,
    image: str,
    command: list[str],
    root: Path = ROOT,
    runner: Any = None,
) -> Path:
    """Run one bounded, network-disabled Docker tool command.

    The tool has no host mounts and cannot access workspace files directly.
    Its output is recorded under the experiment's records directory.

    This function does not establish runtime admission or network-policy
    acceptance. Those checks must be completed by the runtime layer before
    experiments are considered authorized.
    """
    root = _root_path(root)
    require_available_image(image, root)
    
    _validate_tool_arguments(image, command)

    directory, metadata = _inspect(experiment_id, root)

    if metadata["status"] == "STOPPED":
        raise LabError("stopped experiment must be reset or reinitialized before execution")

    workspace = _required_directory(
        directory / "workspace",
        "experiment workspace",
    )
    records = _required_directory(
        directory / "records",
        "experiment records",
    )

    if runner is None:
        runner = subprocess.run

    record = records / f"command-{uuid.uuid4().hex}.json"
    created_utc = utc_now()
    argv = _tool_command(image, command)

    record_data: dict[str, Any] = {
        "experiment_id": experiment_id,
        "owner": OWNER,
        "image": image,
        "command": command,
        "created_utc": created_utc,
        "network": "none",
        "host_mounts": False,
        "read_only_root": True,
        "capabilities": "ALL_DROPPED",
        "no_new_privileges": True,
        "memory_limit": TOOL_MEMORY,
        "pids_limit": TOOL_PIDS_LIMIT,
        "cpu_limit": TOOL_CPUS,
        "user": TOOL_USER,
        "pull_policy": "never",
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "execution_status": "NOT_COMPLETED",
    }

    try:
        result = runner(
            argv,
            cwd=str(workspace),
            capture_output=True,
            text=True,
            check=False,
            timeout=TOOL_TIMEOUT_SECONDS,
        )

        record_data.update(
            {
                "returncode": result.returncode,
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
                "execution_status": (
                    "SUCCEEDED" if result.returncode == 0 else "FAILED"
                ),
            }
        )

    except subprocess.TimeoutExpired as exc:
        record_data.update(
            {
                "execution_status": "TIMED_OUT",
                "stdout": _decode_output(exc.stdout),
                "stderr": _decode_output(exc.stderr),
                "error": f"command exceeded {TOOL_TIMEOUT_SECONDS} seconds",
            }
        )
        _write_json(record, record_data)
        raise LabError(f"tool command timed out; output preserved at {record}") from exc

    except OSError as exc:
        record_data.update(
            {
                "execution_status": "LAUNCH_FAILED",
                "error": str(exc),
            }
        )
        _write_json(record, record_data)
        raise LabError(f"could not launch Docker tool; output preserved at {record}") from exc

    _write_json(record, record_data)

    if record_data["execution_status"] != "SUCCEEDED":
        raise LabError(f"tool command failed; output preserved at {record}")

    return record


def _decode_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


__all__ = [
    "collect_evidence",
    "destroy_experiment",
    "execute_tool",
    "enter_experiment",
    "init_experiment",
    "inspect_experiment",
    "reset_experiment",
    "stop_experiment",
]