"""Allowlist verification for the Athena agent orchestrator.

Provides integrity-checked loading of target allowlists and target matching.
The allowlist is a JSON file containing approved targets. Before each execution
cycle, the orchestrator verifies the file's SHA-256 hash against an expected
value, rejecting execution if verification fails.

Requirements: 4.2, 4.3, 11.1, 11.2
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


class AllowlistError(Exception):
    """Raised when allowlist loading or verification fails."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass
class AllowlistEntry:
    """A single approved target entry in the allowlist."""

    host: str
    port_range: tuple[int, int]
    protocol: str
    label: str  # e.g., "juice-shop-lab"


def verify_allowlist(path: Path, expected_hash: str) -> list[AllowlistEntry]:
    """Load and verify allowlist integrity.

    Reads the allowlist JSON file, computes its SHA-256 hash, and compares
    against the expected hash. On success, parses the JSON into a list of
    AllowlistEntry objects.

    Args:
        path: Path to the allowlist JSON file.
        expected_hash: Expected SHA-256 hex digest of the file contents.

    Returns:
        List of AllowlistEntry objects parsed from the file.

    Raises:
        AllowlistError: If the file is missing, unreadable, has an invalid
            format, or fails hash verification.
    """
    # Read file bytes
    try:
        file_bytes = path.read_bytes()
    except FileNotFoundError:
        raise AllowlistError(f"Allowlist file not found: {path}")
    except OSError as exc:
        raise AllowlistError(f"Unable to read allowlist file: {exc}")

    # Compute and verify SHA-256 hash
    computed_hash = hashlib.sha256(file_bytes).hexdigest()
    if computed_hash != expected_hash:
        raise AllowlistError(
            f"Allowlist integrity check failed: expected hash {expected_hash}, "
            f"got {computed_hash}"
        )

    # Parse JSON
    try:
        data = json.loads(file_bytes)
    except (json.JSONDecodeError, ValueError) as exc:
        raise AllowlistError(f"Invalid JSON in allowlist file: {exc}")

    if not isinstance(data, list):
        raise AllowlistError("Allowlist must be a JSON array of entries")

    # Convert to AllowlistEntry objects
    entries: list[AllowlistEntry] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise AllowlistError(f"Allowlist entry {i} is not a JSON object")
        try:
            port_range = item["port_range"]
            entry = AllowlistEntry(
                host=item["host"],
                port_range=(int(port_range[0]), int(port_range[1])),
                protocol=item["protocol"],
                label=item["label"],
            )
            entries.append(entry)
        except (KeyError, TypeError, IndexError) as exc:
            raise AllowlistError(
                f"Allowlist entry {i} has invalid or missing fields: {exc}"
            )

    return entries


def is_target_allowed(
    target: str, port: int, allowlist: list[AllowlistEntry]
) -> bool:
    """Check if a target:port combination is allowed by the allowlist.

    Args:
        target: Hostname or IP address of the target.
        port: Port number to check.
        allowlist: List of verified AllowlistEntry objects.

    Returns:
        True if the target:port matches any entry in the allowlist,
        False otherwise.
    """
    for entry in allowlist:
        if entry.host == target:
            start, end = entry.port_range
            if start <= port <= end:
                return True
    return False
