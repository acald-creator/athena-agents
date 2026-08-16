"""Audit trail logging for the Agent Orchestrator.

Provides append-only, JSON Lines audit logging for all executed actions.
Each entry records an ISO-8601 UTC timestamp, target, action type, tool ID,
and completion status (success/failure).

Requirements: 11.8
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO


@dataclass
class AuditTrailEntry:
    """A single audit trail log entry.

    Attributes:
        timestamp: ISO 8601 UTC timestamp (e.g., "2024-01-15T10:30:00.000Z").
        target: Target host identifier the action was directed at.
        action_type: Type of action executed (e.g., "scan", "fuzz", "craft").
        tool_id: Identifier of the tool used from the Tool Registry.
        status: Completion status - either "success" or "failure".
        detail: Optional additional detail about the action or failure reason.
    """

    timestamp: str
    target: str
    action_type: str
    tool_id: str
    status: str
    detail: str | None = None

    def __post_init__(self) -> None:
        """Validate status field is either 'success' or 'failure'."""
        if self.status not in ("success", "failure"):
            raise ValueError(f"status must be 'success' or 'failure', got: {self.status!r}")


class AuditTrail:
    """Append-only audit trail writer.

    Writes audit trail entries as JSON Lines (one JSON object per line).
    Supports writing to a file path (from constructor or ATHENA_AUDIT_PATH
    environment variable) or to stdout if no path is configured.

    Usage:
        # File-based audit trail
        with AuditTrail(path="/var/log/athena/audit.jsonl") as trail:
            trail.log_action(target="juice-shop", tool_id="port-scanner",
                            action_type="scan", success=True)

        # Stdout-based (default when no path configured)
        with AuditTrail() as trail:
            trail.log(entry)

    Parameters
    ----------
    path : str | Path | None
        File path for the audit trail. If None, falls back to the
        ATHENA_AUDIT_PATH environment variable. If that is also unset,
        writes to stdout.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        resolved_path = path or os.environ.get("ATHENA_AUDIT_PATH")
        self._file_path: Path | None = Path(resolved_path) if resolved_path else None
        self._file_handle: IO[str] | None = None
        self._owns_handle: bool = False

    def __enter__(self) -> AuditTrail:
        """Open the audit trail for writing."""
        if self._file_path is not None:
            # Ensure parent directory exists
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            # Open in append mode for append-only semantics
            self._file_handle = open(self._file_path, "a", encoding="utf-8")
            self._owns_handle = True
        else:
            self._file_handle = sys.stdout
            self._owns_handle = False
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Close the audit trail file handle if we own it."""
        if self._owns_handle and self._file_handle is not None:
            self._file_handle.close()
            self._file_handle = None

    def _get_output(self) -> IO[str]:
        """Get the output stream, opening lazily if not in context manager."""
        if self._file_handle is not None:
            return self._file_handle
        # Lazy open if used outside context manager
        if self._file_path is not None:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(self._file_path, "a", encoding="utf-8")
            self._owns_handle = True
            return self._file_handle
        return sys.stdout

    def log(self, entry: AuditTrailEntry) -> None:
        """Serialize an audit trail entry as a JSON line and append to output.

        Args:
            entry: The AuditTrailEntry to log.
        """
        output = self._get_output()
        record = asdict(entry)
        # Remove None detail field to keep output clean
        if record["detail"] is None:
            del record["detail"]
        line = json.dumps(record, separators=(",", ":"))
        output.write(line + "\n")
        output.flush()

    def log_action(
        self,
        target: str,
        tool_id: str,
        action_type: str,
        success: bool,
        detail: str | None = None,
    ) -> None:
        """Convenience method to log an action with auto-generated timestamp.

        Args:
            target: Target host identifier.
            tool_id: Tool identifier from the Tool Registry.
            action_type: Type of action executed.
            success: Whether the action succeeded.
            detail: Optional additional detail.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        status = "success" if success else "failure"
        entry = AuditTrailEntry(
            timestamp=timestamp,
            target=target,
            action_type=action_type,
            tool_id=tool_id,
            status=status,
            detail=detail,
        )
        self.log(entry)

    def close(self) -> None:
        """Explicitly close the audit trail output, if file-backed."""
        if self._owns_handle and self._file_handle is not None:
            self._file_handle.close()
            self._file_handle = None
            self._owns_handle = False
