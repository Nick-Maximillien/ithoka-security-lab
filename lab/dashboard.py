"""Read models and action wrappers for the optional local dashboard.

This module contains no Docker or subprocess access. All mutating operations
delegate to the existing control-plane modules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .construction import (
    construct_investigation,
    dispose_investigation,
    validate_investigation,
    write_plan,
)
from .evidence import archive_evidence
from .foundation import CAPABILITIES_FILE, LabError, ROOT, ensure_inside, load_catalog
from .workspace import (
    collect_evidence,
    destroy_experiment,
    init_experiment,
    inspect_experiment,
    reset_experiment,
    stop_experiment,
)


def lab_overview(root: Path = ROOT) -> dict[str, Any]:
    preflight = root / "state" / "preflight-inventory.txt"
    return {
        "lab": "security-lab",
        "root": str(root),
        "configuration": "investigation-independent",
        "backend": "docker.compose",
        "capabilities": sorted(load_catalog(CAPABILITIES_FILE, "capabilities")),
        "preflight_recorded": preflight.is_file(),
        "preflight_inventory": preflight.read_text(encoding="utf-8") if preflight.is_file() else None,
    }


def list_experiments(root: Path = ROOT) -> list[dict[str, Any]]:
    directory = root / "state" / "experiments"
    if not directory.is_dir():
        return []
    results = []
    for metadata_path in sorted(directory.glob("*/experiment.json")):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        metadata["metadata_path"] = str(metadata_path.relative_to(root))
        results.append(metadata)
    return results


def experiment_records(experiment_id: str, root: Path = ROOT) -> list[dict[str, Any]]:
    inspect_experiment(experiment_id, root)
    records_dir = root / "state" / "experiments" / experiment_id / "records"
    records = []
    for record_path in sorted(records_dir.glob("*.json")):
        try:
            records.append(json.loads(record_path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError):
            records.append({"record": record_path.name, "status": "unreadable"})
    return records


def validate_and_plan(specification: Path, experiment_id: str, root: Path = ROOT) -> Path:
    validate_investigation(specification, root)
    output = root / "state" / "plans" / f"{experiment_id}.json"
    return write_plan(specification, experiment_id, output, root)


def construct(specification: Path, experiment_id: str, authorization: str, root: Path = ROOT) -> dict[str, Any]:
    return construct_investigation(specification, experiment_id, authorization, root)


def dispose(specification: Path, experiment_id: str, root: Path = ROOT) -> None:
    dispose_investigation(specification, experiment_id, root)


__all__ = [
    "archive_evidence",
    "collect_evidence",
    "construct",
    "destroy_experiment",
    "dispose",
    "experiment_records",
    "init_experiment",
    "inspect_experiment",
    "lab_overview",
    "list_experiments",
    "reset_experiment",
    "stop_experiment",
    "validate_and_plan",
]
