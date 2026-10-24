#!/usr/bin/env python3
"""Scientific experiment definition and run controller for the constrained lab."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Callable

import yaml

if os.name == "nt":
    import msvcrt
else:
    import fcntl


ROOT = Path(__file__).resolve().parents[1]
CAPACITY_FILE = ROOT / "config" / "lab-capacity.yaml"
CAPABILITIES_FILE = ROOT / "lab" / "catalog" / "capabilities.yaml"
MATERIALS_FILE = ROOT / "lab" / "catalog" / "materials.yaml"
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
EXPERIMENT_PATTERN = re.compile(r"^EXP-[0-9]{4}-[a-z0-9-]+$")
REVISION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SECRET_PATTERN = re.compile(
    r"(?i)(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=])"
)


class LabError(Exception):
    """An expected validation, policy, or lifecycle error."""


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise LabError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_yaml(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return yaml.load(stream, Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError, LabError) as exc:
        raise LabError(f"cannot read YAML {path}: {exc}") from exc


def ensure_inside(root: Path, path: Path, description: str) -> Path:
    root_resolved = root.resolve()
    resolved = path.resolve()
    if resolved == root_resolved or root_resolved not in resolved.parents:
        raise LabError(f"{description} must resolve inside the repository: {path}")
    return resolved


def require_mapping(value: Any, label: str, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise LabError(f"{label} must be a mapping with string keys")
    optional = optional or set()
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise LabError(f"{label} is missing required keys: {', '.join(sorted(missing))}")
    if unknown:
        raise LabError(f"{label} contains unsupported keys: {', '.join(sorted(unknown))}")
    return value


def require_open_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise LabError(f"{label} must be a mapping with string keys")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise LabError(f"{label} must be a list")
    return value


def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LabError(f"{label} must be a non-empty string")
    return value


def require_integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise LabError(f"{label} must be an integer >= {minimum}")
    return value


def _memory_limit_mib(value: Any, label: str) -> int:
    if type(value) is int:
        byte_count = value
    elif isinstance(value, str):
        match = re.fullmatch(r"([0-9]+)([kmgt]?i?b?)?", value.strip(), re.IGNORECASE)
        if not match:
            raise LabError(f"{label} has an unsupported memory limit format")
        amount = int(match.group(1))
        unit = (match.group(2) or "").lower().rstrip("b")
        multiplier = {"": 1, "k": 1024, "ki": 1024, "m": 1024**2, "mi": 1024**2,
                      "g": 1024**3, "gi": 1024**3, "t": 1024**4, "ti": 1024**4}.get(unit)
        if multiplier is None:
            raise LabError(f"{label} has an unsupported memory unit")
        byte_count = amount * multiplier
    else:
        raise LabError(f"{label} must declare a memory limit")
    if byte_count <= 0:
        raise LabError(f"{label} must be positive")
    return (byte_count + 1024**2 - 1) // 1024**2


def reject_sensitive_fields(value: Any, path: str = "definition") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if re.search(r"(?i)(password|passwd|secret|token|private[_-]?key|credential)", str(key)):
                raise LabError(f"{path} contains a prohibited sensitive field name: {key}")
            reject_sensitive_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive_fields(child, f"{path}[{index}]")
    elif isinstance(value, str) and SECRET_PATTERN.search(value):
        raise LabError(f"{path} resembles a secret; remove it from the scientific record")


def load_catalog(path: Path, key: str) -> dict[str, dict[str, Any]]:
    document = load_yaml(path)
    require_mapping(document, str(path), {"schema_version", key})
    if document["schema_version"] != 1:
        raise LabError(f"unsupported catalog schema_version in {path}")
    entries = require_list(document[key], f"{path}:{key}")
    catalog: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise LabError(f"{path}:{key}[{index}] must be a mapping")
        identifier = require_text(entry.get("id"), f"{path}:{key}[{index}].id")
        if identifier in catalog:
            raise LabError(f"duplicate catalog identifier: {identifier}")
        catalog[identifier] = entry
    return catalog


def _validate_parameter_value(value: Any, spec: Any, label: str) -> None:
    require_mapping(spec, label, {"type"}, {"minimum", "maximum", "min_items", "max_items"})
    kind = spec["type"]
    for bound in ("minimum", "maximum"):
        if bound in spec and (type(spec[bound]) not in (int, float) or not math.isfinite(spec[bound])):
            raise LabError(f"{label}.{bound} must be a finite number")
    if "minimum" in spec and "maximum" in spec and spec["minimum"] > spec["maximum"]:
        raise LabError(f"{label} has minimum greater than maximum")
    for bound in ("min_items", "max_items"):
        if bound in spec:
            require_integer(spec[bound], f"{label}.{bound}", 0)
    if spec.get("min_items", 1) > spec.get("max_items", 1000):
        raise LabError(f"{label} has min_items greater than max_items")
    valid_types = {
        "number": lambda item: type(item) in (int, float) and math.isfinite(item),
        "integer": lambda item: type(item) is int,
        "string": lambda item: isinstance(item, str),
        "boolean": lambda item: type(item) is bool,
    }
    if kind == "number_list":
        if not isinstance(value, list) or not value:
            raise LabError(f"{label} must be a non-empty number list")
        if any(type(item) not in (int, float) or not math.isfinite(item) for item in value):
            raise LabError(f"{label} must contain only finite numbers")
        if len(value) < spec.get("min_items", 1) or len(value) > spec.get("max_items", 1000):
            raise LabError(f"{label} length is outside its permitted range")
        return
    if kind not in valid_types or not valid_types[kind](value):
        raise LabError(f"{label} must have type {kind}")
    if kind in ("number", "integer"):
        if "minimum" in spec and value < spec["minimum"]:
            raise LabError(f"{label} is below its minimum {spec['minimum']}")
        if "maximum" in spec and value > spec["maximum"]:
            raise LabError(f"{label} is above its maximum {spec['maximum']}")


__all__ = [name for name in globals() if not name.startswith("__")]
