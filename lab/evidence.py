"""Evidence integrity and controlled export for disposable investigations."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from .foundation import LabError, ROOT, ensure_inside, utc_now


def _manifest_for(directory: Path) -> dict:
    entries = []
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        if path.name == "evidence-manifest.json":
            continue
        entries.append({
            "path": str(path.relative_to(directory)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        })
    return entries


def _verify_manifest(directory: Path, manifest: dict) -> None:
    if manifest.get("files") != _manifest_for(directory):
        raise LabError(f"evidence integrity verification failed: {directory}")


def archive_evidence(
    evidence_directory: Path, destination: Path | None = None, root: Path = ROOT
) -> Path:
    source = ensure_inside(root, evidence_directory, "evidence directory")
    if not source.is_dir():
        raise LabError(f"evidence directory does not exist: {source}")
    entries = _manifest_for(source)
    manifest = {"created_utc": utc_now(), "files": entries}
    manifest_path = source / "evidence-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if destination is None:
        return manifest_path
    target_root = ensure_inside(root, destination, "archive destination")
    if not target_root.is_dir():
        raise LabError("archive destination must already exist")
    target = target_root / source.name
    if target.exists():
        raise LabError(f"refusing to overwrite archive: {target}")
    try:
        shutil.copytree(source, target)
        copied = json.loads((target / "evidence-manifest.json").read_text(encoding="utf-8"))
        if copied != manifest:
            raise LabError("copied evidence manifest does not match source")
        _verify_manifest(target, copied)
    except (OSError, json.JSONDecodeError, LabError):
        if target.exists():
            shutil.rmtree(target)
        raise
    return target / "evidence-manifest.json"


__all__ = ["archive_evidence"]
