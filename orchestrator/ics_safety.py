"""ICS safety controls for the Athena orchestrator.

Provides safe-range validation, ICS target configuration loading, and
capability gating for Modbus TCP and CAN Bus operations.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]


class IcsConfigError(Exception):
    """Raised when an ICS target configuration is invalid or cannot be loaded."""


@dataclass
class SafeRange:
    """A configured safe range for a specific Modbus register address.

    Defines the minimum and maximum values that may be written to a particular
    register. Writes outside this boundary are rejected before transmission.
    """

    register_address: int
    min_value: int
    max_value: int


@dataclass
class IcsTargetConfig:
    """Configuration for an ICS target environment.

    Loaded from a TOML file in config/targets/. Defines connection parameters,
    rate limits, safe ranges, and required capabilities for the target.
    """

    target_id: str
    host: str
    port: int
    protocol: str  # "modbus-tcp" | "canbus"
    ics_rate_limit: int = 10
    safe_ranges: list[SafeRange] = field(default_factory=list)
    capabilities_required: list[str] = field(default_factory=list)


def load_ics_target_config(path: Path) -> IcsTargetConfig:
    """Load and validate an ICS target TOML configuration file.

    Parameters
    ----------
    path : Path
        Path to the TOML configuration file.

    Returns
    -------
    IcsTargetConfig
        Parsed and validated target configuration.

    Raises
    ------
    IcsConfigError
        If the file cannot be read, parsed, or is missing required fields.
    """
    if not path.exists():
        raise IcsConfigError(f"target config file not found: {path}")

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        raise IcsConfigError(f"failed to parse target config '{path}': {e}") from e

    target = data.get("target")
    if target is None:
        raise IcsConfigError(f"missing [target] section in '{path}'")

    # Required fields
    required_fields = ["id", "host", "port", "protocol"]
    for field_name in required_fields:
        if field_name not in target:
            raise IcsConfigError(
                f"missing required field 'target.{field_name}' in '{path}'"
            )

    protocol = target["protocol"]
    valid_protocols = ("modbus-tcp", "canbus")
    if protocol not in valid_protocols:
        raise IcsConfigError(
            f"invalid protocol '{protocol}' in '{path}'; "
            f"must be one of {valid_protocols}"
        )

    # Parse safe ranges
    safe_ranges: list[SafeRange] = []
    raw_ranges = target.get("safe_ranges", {})
    if isinstance(raw_ranges, dict):
        for addr_str, bounds in raw_ranges.items():
            try:
                address = int(addr_str)
            except (ValueError, TypeError) as e:
                raise IcsConfigError(
                    f"invalid safe_range address '{addr_str}' in '{path}': {e}"
                ) from e

            if not isinstance(bounds, (list, tuple)) or len(bounds) != 2:
                raise IcsConfigError(
                    f"safe_range for address {address} must be [min, max] in '{path}'"
                )

            safe_ranges.append(
                SafeRange(
                    register_address=address,
                    min_value=int(bounds[0]),
                    max_value=int(bounds[1]),
                )
            )

    # Parse capabilities
    capabilities: list[str] = []
    if protocol == "modbus-tcp":
        capabilities = ["ICS_WRITE"]
    elif protocol == "canbus":
        capabilities = ["CAN_INJECT"]

    # Allow override from config
    caps_from_config = target.get("capabilities_required")
    if caps_from_config is not None:
        capabilities = list(caps_from_config)

    return IcsTargetConfig(
        target_id=target["id"],
        host=target.get("host", ""),
        port=target.get("port", 0),
        protocol=protocol,
        ics_rate_limit=target.get("ics_rate_limit", 10),
        safe_ranges=safe_ranges,
        capabilities_required=capabilities,
    )


def validate_write_against_safe_range(
    address: int, value: int, safe_ranges: list[SafeRange]
) -> tuple[bool, str | None]:
    """Check if a write value is within the safe range for a given address.

    If a safe range is defined for the given address, the value must be within
    [min_value, max_value] (inclusive). If no safe range is defined for the
    address, the write is allowed.

    Parameters
    ----------
    address : int
        The register address being written to.
    value : int
        The value to be written.
    safe_ranges : list[SafeRange]
        The configured safe ranges for the target.

    Returns
    -------
    tuple[bool, str | None]
        (True, None) if the write is allowed.
        (False, error_message) if the write violates a safe range.
    """
    for sr in safe_ranges:
        if sr.register_address == address:
            if value < sr.min_value or value > sr.max_value:
                return (
                    False,
                    f"safety boundary violation: value {value} at address {address} "
                    f"is outside safe range [{sr.min_value}, {sr.max_value}]",
                )
            return (True, None)

    # No safe range defined for this address — allow
    return (True, None)
