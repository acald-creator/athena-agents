"""Load and normalize target TOML documents for the OPAR CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file. Uses tomllib (3.11+) or tomli as fallback."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    with open(path, "rb") as f:
        return tomllib.load(f)


def normalize_target_document(raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten ``[target]`` or legacy flat target docs plus optional sections."""
    target_table = raw.get("target")
    if isinstance(target_table, dict):
        merged: dict[str, Any] = dict(target_table)
    elif "host" in raw or "port" in raw:
        merged = dict(raw)
    else:
        merged = dict(raw)

    if "target_id" in merged and "id" not in merged:
        merged["id"] = merged["target_id"]

    for key in ("scenario", "api", "attack_vectors", "labels"):
        if key in raw and key not in merged:
            merged[key] = raw[key]

    return merged


def load_target_document(path: Path) -> dict[str, Any]:
    """Load ``targets/<name>.toml`` and return a normalized target document."""
    return normalize_target_document(load_toml(path))
