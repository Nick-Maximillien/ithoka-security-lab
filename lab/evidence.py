"""Evidence integrity and controlled export for disposable investigations.

This module establishes file-integrity evidence only. A valid manifest does
not establish that runtime isolation, network controls, or experiment
acceptance criteria passed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from .foundation import LabError, ROOT, ensure_inside, utc_now


MANIFEST_NAME = "evidence-manifest.json"


def _reject_symlinks(directory: Path) -> None:
    """Reject symlinks anywhere in the evidence tree."""
    if directory.is_symlink():
        raise LabError(f"symlink is not permitted: {directory}")

    for path in directory.rglob("*"):
        if path.is_symlink():
            raise LabError(f"symlink is not permitted in evidence: {path}")


def _manifest_for(directory: Path) -> list[dict]:
    """Build a deterministic inventory of evidence files."""
    _reject_symlinks(directory)

    entries: list[dict] = []

    for path in sorted(
        item for item in directory.rglob("*") if item.is_file()
    ):
        if path.name == MANIFEST_NAME:
            continue

        content = path.read_bytes()
        entries.append(
            {
                "path": path.relative_to(directory).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )

    return entries


def _read_manifest(directory: Path) -> dict:
    """Read and structurally validate the evidence manifest."""
    manifest_path = directory / MANIFEST_NAME

    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise LabError(f"evidence manifest is missing: {manifest_path}")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LabError(f"cannot read evidence manifest: {manifest_path}") from exc

    if not isinstance(manifest, dict):
        raise LabError(f"invalid evidence manifest: {manifest_path}")

    if not isinstance(manifest.get("created_utc"), str):
        raise LabError(f"manifest has no valid created_utc: {manifest_path}")

    files = manifest.get("files")
    if not isinstance(files, list):
        raise LabError(f"manifest has no valid files list: {manifest_path}")

    for entry in files:
        if not isinstance(entry, dict):
            raise LabError(f"invalid file entry in manifest: {manifest_path}")

        relative_path = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size")

        if (
            not isinstance(relative_path, str)
            or not relative_path
            or Path(relative_path).is_absolute()
            or ".." in Path(relative_path).parts
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise LabError(f"invalid file entry in manifest: {manifest_path}")

    return manifest


def _verify_manifest(directory: Path, manifest: dict) -> None:
    """Verify that the current evidence tree matches its manifest."""
    _reject_symlinks(directory)

    expected = manifest.get("files")
    actual = _manifest_for(directory)

    if expected != actual:
        raise LabError(f"evidence integrity verification failed: {directory}")


def archive_evidence(
    evidence_directory: Path,
    destination: Path | None = None,
    root: Path = ROOT,
) -> Path:
    """Create an evidence manifest and optionally export a verified copy.

    If destination is omitted, return the manifest path in the source evidence
    directory. If destination is supplied, it must be an existing directory
    inside root. The archive is created as destination/<evidence-dir-name>.

    Existing manifests and archive destinations are never overwritten.
    """
    source = ensure_inside(root, evidence_directory, "evidence directory")

    if not source.is_dir():
        raise LabError(f"evidence directory does not exist: {source}")

    _reject_symlinks(source)

    manifest_path = source / MANIFEST_NAME
    if manifest_path.exists() or manifest_path.is_symlink():
        raise LabError(
            f"refusing to overwrite existing evidence manifest: {manifest_path}"
        )

    entries = _manifest_for(source)
    manifest = {
        "created_utc": utc_now(),
        "files": entries,
    }

    # If the caller only needs a local manifest, create it without exporting.
    if destination is None:
        try:
            with manifest_path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        except FileExistsError as exc:
            raise LabError(
                f"refusing to overwrite existing evidence manifest: {manifest_path}"
            ) from exc

        _verify_manifest(source, manifest)
        return manifest_path

    target_root = ensure_inside(root, destination, "archive destination")

    if not target_root.is_dir():
        raise LabError("archive destination must already exist")

    _reject_symlinks(target_root)

    target = target_root / source.name

    # Refuse both existing paths and dangling symlinks.
    if target.exists() or target.is_symlink():
        raise LabError(f"refusing to overwrite archive: {target}")

    # Stage the export under the destination filesystem. Publish only after
    # the source manifest and copied tree have both passed verification.
    temporary: Path | None = None

    try:
        with manifest_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

        _verify_manifest(source, manifest)

        with tempfile.TemporaryDirectory(
            prefix=".evidence-export-",
            dir=target_root,
        ) as staging_name:
            staging_directory = Path(staging_name)
            temporary = staging_directory / source.name

            shutil.copytree(source, temporary, symlinks=True)

            _reject_symlinks(temporary)

            copied_manifest = _read_manifest(temporary)
            if copied_manifest != manifest:
                raise LabError("copied evidence manifest does not match source")

            _verify_manifest(temporary, copied_manifest)

            # Recheck immediately before publication.
            if target.exists() or target.is_symlink():
                raise LabError(f"refusing to overwrite archive: {target}")

            temporary.rename(target)

    except (OSError, shutil.Error, json.JSONDecodeError) as exc:
        if target.exists() and target.is_dir():
            shutil.rmtree(target, ignore_errors=True)

        # The manifest belongs to this operation, so remove it if export
        # failed. Preserve all original evidence files.
        if manifest_path.exists() and not manifest_path.is_symlink():
            manifest_path.unlink(missing_ok=True)

        raise LabError(f"evidence export failed: {exc}") from exc
    except LabError:
        if target.exists() and target.is_dir():
            shutil.rmtree(target, ignore_errors=True)

        if manifest_path.exists() and not manifest_path.is_symlink():
            manifest_path.unlink(missing_ok=True)

        raise

    return target / MANIFEST_NAME


__all__ = ["archive_evidence"]