"""Read Linux mount table for filesystem exposure context."""

from __future__ import annotations

from pathlib import Path

from ...enforcement.models import EnforcementStatus
from ..models import OSObservation, utc_timestamp


def _unescape(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def inspect_mounts(path: Path = Path("/proc/self/mountinfo")) -> OSObservation:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return OSObservation(
            "linux",
            "filesystem",
            "inspect",
            str(path),
            "procfs",
            utc_timestamp(),
            EnforcementStatus.UNKNOWN,
            errors=(f"mount table could not be read: {exc}",),
        )
    mounts = []
    for number, line in enumerate(lines, 1):
        fields = line.split()
        try:
            separator = fields.index("-")
            if separator < 6 or len(fields) <= separator + 2:
                raise ValueError
        except (ValueError, IndexError):
            return OSObservation(
                "linux",
                "filesystem",
                "inspect",
                str(path),
                "procfs",
                utc_timestamp(),
                EnforcementStatus.UNKNOWN,
                values=mounts,
                parsed=False,
                errors=(f"malformed mountinfo line {number}",),
            )
        mounts.append({
            "mount_id": fields[0],
            "parent_id": fields[1],
            "device": fields[2],
            "root": _unescape(fields[3]),
            "mountpoint": _unescape(fields[4]),
            "mount_options": fields[5].split(","),
            "filesystem": fields[separator + 1],
            "source": _unescape(fields[separator + 2]),
            "super_options": fields[separator + 3].split(",")
            if len(fields) > separator + 3
            else [],
        })
    return OSObservation(
        "linux",
        "filesystem",
        "inspect",
        str(path),
        "procfs",
        utc_timestamp(),
        EnforcementStatus.PASS,
        values=mounts,
        parsed=True,
        coverage_limitations=(
            "mount inventory is not an access-control test for any particular path",
        ),
    )
