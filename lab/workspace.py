"""Command-driven, disposable researcher workspaces."""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

from .foundation import ID_PATTERN, LabError, ROOT, ensure_inside, sha256_bytes, utc_now


def _workspace(root: Path, experiment_id: str) -> Path:
    if not ID_PATTERN.fullmatch(experiment_id):
        raise LabError("experiment ID must contain only lowercase letters, digits, and hyphens")
    return ensure_inside(root, root / "state" / "experiments" / experiment_id, "experiment workspace")


def _write_metadata(directory: Path, metadata: dict[str, Any]) -> None:
    (directory / "experiment.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def init_experiment(experiment_id: str, root: Path = ROOT) -> Path:
    directory = _workspace(root, experiment_id)
    if directory.exists():
        raise LabError(f"experiment already exists: {experiment_id}")
    directory.mkdir(parents=True)
    (directory / "workspace").mkdir()
    (directory / "evidence").mkdir()
    (directory / "records").mkdir()
    metadata = {
        "experiment_id": experiment_id,
        "owner": "security-lab",
        "status": "READY",
        "created_utc": utc_now(),
        "workspace": str((directory / "workspace").relative_to(root)),
        "evidence": str((directory / "evidence").relative_to(root)),
        "mutable_state": str((directory / "workspace").relative_to(root)),
        "resource_scope": f"security-lab/{experiment_id}",
    }
    _write_metadata(directory, metadata)
    return directory


def inspect_experiment(experiment_id: str, root: Path = ROOT) -> dict[str, Any]:
    directory = _workspace(root, experiment_id)
    metadata_path = directory / "experiment.json"
    if not metadata_path.is_file():
        raise LabError(f"experiment is not initialized: {experiment_id}")
    return json.loads(metadata_path.read_text(encoding="utf-8"))


def enter_experiment(experiment_id: str, root: Path = ROOT) -> Path:
    inspect_experiment(experiment_id, root)
    return _workspace(root, experiment_id) / "workspace"


def stop_experiment(experiment_id: str, root: Path = ROOT) -> None:
    directory = _workspace(root, experiment_id)
    metadata = inspect_experiment(experiment_id, root)
    metadata["status"] = "STOPPED"
    metadata["stopped_utc"] = utc_now()
    _write_metadata(directory, metadata)


def reset_experiment(experiment_id: str, root: Path = ROOT) -> None:
    directory = _workspace(root, experiment_id)
    metadata = inspect_experiment(experiment_id, root)
    workspace = directory / "workspace"
    shutil.rmtree(workspace)
    workspace.mkdir()
    metadata["status"] = "READY"
    metadata["reset_utc"] = utc_now()
    _write_metadata(directory, metadata)


def destroy_experiment(experiment_id: str, root: Path = ROOT) -> None:
    directory = _workspace(root, experiment_id)
    metadata = inspect_experiment(experiment_id, root)
    if metadata["status"] == "RUNNING":
        raise LabError("running experiment must be stopped before destruction")
    evidence = directory / "evidence"
    preserved = ensure_inside(root, root / "evidence-staging" / "experiments" / experiment_id, "preserved evidence")
    preserved.parent.mkdir(parents=True, exist_ok=True)
    if evidence.exists() and any(evidence.iterdir()):
        if preserved.exists():
            raise LabError(f"preserved evidence destination already exists: {preserved}")
        shutil.copytree(evidence, preserved)
    shutil.rmtree(directory)


def collect_evidence(
    experiment_id: str, paths: list[Path], root: Path = ROOT
) -> Path:
    directory = _workspace(root, experiment_id)
    inspect_experiment(experiment_id, root)
    evidence = directory / "evidence"
    entries: list[dict[str, Any]] = []
    for source in paths:
        resolved = ensure_inside(root, source, "evidence source")
        if not resolved.is_file():
            raise LabError(f"evidence source is not a file: {resolved}")
        destination = evidence / resolved.name
        if destination.exists():
            raise LabError(f"refusing to overwrite evidence: {destination}")
        shutil.copy2(resolved, destination)
        entries.append({
            "source": str(resolved.relative_to(root)),
            "path": str(destination.relative_to(root)),
            "sha256": sha256_bytes(destination.read_bytes()),
            "size": destination.stat().st_size,
        })
    manifest = {"experiment_id": experiment_id, "collected_utc": utc_now(), "files": entries}
    (evidence / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return evidence / "manifest.json"


def execute_tool(
    experiment_id: str,
    image: str,
    command: list[str],
    root: Path = ROOT,
    runner: Any = None,
) -> Path:
    """Run one bounded tool command without host mounts or network access."""
    if not image or not command:
        raise LabError("an image and command are required")
    directory = _workspace(root, experiment_id)
    metadata = inspect_experiment(experiment_id, root)
    if metadata["status"] == "STOPPED":
        raise LabError("stopped experiment must be started before tool execution")
    if any("\x00" in value for value in [image, *command]):
        raise LabError("tool image and command must not contain NUL bytes")
    if runner is None:
        runner = subprocess.run
    result = runner(
        [
            "docker", "run", "--rm", "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--memory", "128m", "--pids-limit", "64", "--cpus", "0.5",
            "--user", "1000:1000", image, *command,
        ],
        cwd=str(directory / "workspace"),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    record = directory / "records" / f"command-{uuid.uuid4().hex}.json"
    record.write_text(
        json.dumps({
            "experiment_id": experiment_id,
            "image": image,
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "network": "none",
            "host_mounts": False,
            "created_utc": utc_now(),
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise LabError(f"tool command failed; output preserved at {record}")
    return record


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
