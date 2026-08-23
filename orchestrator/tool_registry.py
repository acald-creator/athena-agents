"""Tool Registry loader and validator.

Provides configuration-driven tool discovery and invocation validation.
Tools are declared in a TOML file (config/tool-registry.toml) with argument
schemas, invocation types, and capability requirements.

Requirements: 6.1, 6.2, 6.3, 6.5, 6.8
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, field_validator

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


class ToolRegistryError(Exception):
    """Raised when the tool registry file cannot be loaded or fails validation."""


class ToolValidationError(Exception):
    """Raised when tool arguments fail validation against declared schema."""


class ToolArg(BaseModel):
    """Schema definition for a single tool argument."""

    type: Literal["string", "integer", "object"]
    required: bool = True
    default: Any = None
    min: int | None = None
    max: int | None = None
    enum: list[str] | None = None


class ToolEntry(BaseModel):
    """A single tool definition in the registry."""

    executable: str | None = None
    module: str | None = None
    invocation: Literal["subprocess", "in-process"]
    required_capabilities: list[str] = []
    description: str = ""
    args: dict[str, ToolArg] = {}

    @field_validator("executable", mode="before")
    @classmethod
    def expand_env_vars(cls, v: str | None) -> str | None:
        """Expand environment variables in executable paths (e.g., ${ATHENA_BIN_DIR})."""
        if v is None:
            return v
        return _expand_env_vars(v)


def _expand_env_vars(value: str) -> str:
    """Replace ${VAR_NAME} patterns with environment variable values.

    If the environment variable is not set, the placeholder is left as-is.
    """

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))

    return re.sub(r"\$\{([^}]+)\}", _replace, value)


class ToolRegistry:
    """Configuration-driven catalog of offensive tools.

    Loads tool definitions from a TOML file and validates tool arguments
    at invocation time against declared schemas.
    """

    def __init__(self, tools: dict[str, ToolEntry]) -> None:
        self._tools = tools

    @classmethod
    def load(cls, path: Path) -> ToolRegistry:
        """Load and validate tool registry from a TOML file.

        Args:
            path: Path to the tool-registry.toml file.

        Returns:
            A validated ToolRegistry instance.

        Raises:
            ToolRegistryError: If the file is missing, unreadable, or invalid.
        """
        if not path.exists():
            raise ToolRegistryError(f"Tool registry file not found: {path}")

        try:
            content = path.read_bytes()
        except OSError as e:
            raise ToolRegistryError(f"Cannot read tool registry file: {path}: {e}") from e

        try:
            data = tomllib.loads(content.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
            raise ToolRegistryError(f"Invalid TOML in tool registry: {path}: {e}") from e

        tools_section = data.get("tools")
        if tools_section is None:
            raise ToolRegistryError(
                f"Tool registry missing [tools] section: {path}"
            )

        if not isinstance(tools_section, dict):
            raise ToolRegistryError(
                f"Tool registry [tools] section must be a table: {path}"
            )

        tools: dict[str, ToolEntry] = {}
        for tool_id, tool_data in tools_section.items():
            try:
                tools[tool_id] = ToolEntry.model_validate(tool_data)
            except Exception as e:
                raise ToolRegistryError(
                    f"Invalid tool entry '{tool_id}' in {path}: {e}"
                ) from e

        return cls(tools)

    def get_tool(self, tool_id: str) -> ToolEntry | None:
        """Look up a tool by its identifier.

        Args:
            tool_id: The unique tool identifier.

        Returns:
            The ToolEntry if found, otherwise None.
        """
        return self._tools.get(tool_id)

    def list_tools(self) -> list[str]:
        """Return all registered tool identifiers."""
        return list(self._tools.keys())

    def apply_defaults(self, tool_id: str, args: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of args with declared defaults filled in.

        Raises
        ------
        ToolRegistryError
            If the tool is not found in the registry.
        """
        tool = self._tools.get(tool_id)
        if tool is None:
            raise ToolRegistryError(f"Tool not found in registry: {tool_id}")

        merged = dict(args)
        for arg_name, arg_schema in tool.args.items():
            if arg_name not in merged and arg_schema.default is not None:
                merged[arg_name] = arg_schema.default
        return merged

    def validate_arguments(self, tool_id: str, args: dict[str, Any]) -> None:
        """Validate arguments against a tool's declared schema.

        Args:
            tool_id: The tool identifier.
            args: The arguments to validate.

        Raises:
            ToolValidationError: If validation fails (missing required arg,
                type mismatch, out of range, invalid enum value).
            ToolRegistryError: If the tool is not found in the registry.
        """
        tool = self._tools.get(tool_id)
        if tool is None:
            raise ToolRegistryError(f"Tool not found in registry: {tool_id}")

        for arg_name, arg_schema in tool.args.items():
            if arg_name not in args:
                if arg_schema.required:
                    raise ToolValidationError(
                        f"Missing required argument '{arg_name}' for tool '{tool_id}'"
                    )
                # Optional arg not provided — skip further checks
                continue

            value = args[arg_name]
            self._validate_arg_value(tool_id, arg_name, value, arg_schema)

    @staticmethod
    def _validate_arg_value(
        tool_id: str, arg_name: str, value: Any, schema: ToolArg
    ) -> None:
        """Validate a single argument value against its schema."""
        # Type checking
        expected_type = schema.type
        if expected_type == "string":
            if not isinstance(value, str):
                raise ToolValidationError(
                    f"Argument '{arg_name}' for tool '{tool_id}' must be a string, "
                    f"got {type(value).__name__}"
                )
        elif expected_type == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                raise ToolValidationError(
                    f"Argument '{arg_name}' for tool '{tool_id}' must be an integer, "
                    f"got {type(value).__name__}"
                )
        elif expected_type == "object":
            if not isinstance(value, dict):
                raise ToolValidationError(
                    f"Argument '{arg_name}' for tool '{tool_id}' must be an object (dict), "
                    f"got {type(value).__name__}"
                )

        # Range checking (integers only)
        if expected_type == "integer" and isinstance(value, int) and not isinstance(value, bool):
            if schema.min is not None and value < schema.min:
                raise ToolValidationError(
                    f"Argument '{arg_name}' for tool '{tool_id}' value {value} "
                    f"is below minimum {schema.min}"
                )
            if schema.max is not None and value > schema.max:
                raise ToolValidationError(
                    f"Argument '{arg_name}' for tool '{tool_id}' value {value} "
                    f"exceeds maximum {schema.max}"
                )

        # Enum checking (strings only)
        if expected_type == "string" and schema.enum is not None:
            if value not in schema.enum:
                raise ToolValidationError(
                    f"Argument '{arg_name}' for tool '{tool_id}' value '{value}' "
                    f"not in allowed values: {schema.enum}"
                )
