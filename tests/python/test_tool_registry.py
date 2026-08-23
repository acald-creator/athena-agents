"""Tests for orchestrator.tool_registry module.

Validates: Requirements 6.1, 6.2, 6.3, 6.5, 6.8
"""

from __future__ import annotations

import os
from pathlib import Path
from textwrap import dedent

import pytest

from orchestrator.tool_registry import (
    ToolArg,
    ToolEntry,
    ToolRegistry,
    ToolRegistryError,
    ToolValidationError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def valid_toml(tmp_path: Path) -> Path:
    """Create a valid tool-registry TOML file."""
    content = dedent("""\
        [tools.port-scanner]
        executable = "/usr/local/bin/athena-scanner"
        invocation = "subprocess"
        required_capabilities = []
        description = "Async TCP port scanner"

        [tools.port-scanner.args]
        target = { type = "string", required = true }
        start_port = { type = "integer", required = true, min = 1, max = 65535 }
        end_port = { type = "integer", required = true, min = 1, max = 65535 }
        concurrency = { type = "integer", required = false, default = 1024, min = 1, max = 65535 }

        [tools.scapy-craft]
        module = "orchestrator.tools.scapy_craft"
        invocation = "in-process"
        required_capabilities = ["NET_RAW"]
        description = "Scapy packet crafter"

        [tools.scapy-craft.args]
        packet_spec = { type = "object", required = true }
    """)
    path = tmp_path / "tool-registry.toml"
    path.write_text(content)
    return path


@pytest.fixture()
def registry(valid_toml: Path) -> ToolRegistry:
    """Load a ToolRegistry from the valid fixture."""
    return ToolRegistry.load(valid_toml)


# ---------------------------------------------------------------------------
# Loading tests
# ---------------------------------------------------------------------------


class TestToolRegistryLoading:
    """Test registry loading and validation."""

    def test_load_valid_file(self, valid_toml: Path) -> None:
        """Load a valid TOML file successfully."""
        reg = ToolRegistry.load(valid_toml)
        assert "port-scanner" in reg.list_tools()
        assert "scapy-craft" in reg.list_tools()

    def test_missing_file_raises_error(self, tmp_path: Path) -> None:
        """Missing file raises ToolRegistryError."""
        missing = tmp_path / "nonexistent.toml"
        with pytest.raises(ToolRegistryError, match="not found"):
            ToolRegistry.load(missing)

    def test_invalid_toml_raises_error(self, tmp_path: Path) -> None:
        """Invalid TOML syntax raises ToolRegistryError."""
        bad_toml = tmp_path / "bad.toml"
        bad_toml.write_text("[tools.broken\nthis is not valid toml {{{")
        with pytest.raises(ToolRegistryError, match="Invalid TOML"):
            ToolRegistry.load(bad_toml)

    def test_missing_tools_section_raises_error(self, tmp_path: Path) -> None:
        """TOML without [tools] section raises ToolRegistryError."""
        no_tools = tmp_path / "no-tools.toml"
        no_tools.write_text('[meta]\nversion = "1.0"\n')
        with pytest.raises(ToolRegistryError, match="missing \\[tools\\] section"):
            ToolRegistry.load(no_tools)

    def test_invalid_tool_entry_raises_error(self, tmp_path: Path) -> None:
        """Invalid tool entry (bad invocation type) raises ToolRegistryError."""
        bad_entry = tmp_path / "bad-entry.toml"
        bad_entry.write_text(dedent("""\
            [tools.broken]
            executable = "/bin/false"
            invocation = "magic"
            [tools.broken.args]
        """))
        with pytest.raises(ToolRegistryError, match="Invalid tool entry 'broken'"):
            ToolRegistry.load(bad_entry)


# ---------------------------------------------------------------------------
# Lookup tests
# ---------------------------------------------------------------------------


class TestToolLookup:
    """Test tool retrieval by ID."""

    def test_get_existing_tool(self, registry: ToolRegistry) -> None:
        """Look up a tool that exists."""
        tool = registry.get_tool("port-scanner")
        assert tool is not None
        assert tool.invocation == "subprocess"
        assert tool.executable == "/usr/local/bin/athena-scanner"

    def test_get_nonexistent_tool_returns_none(self, registry: ToolRegistry) -> None:
        """Look up a tool that doesn't exist returns None."""
        assert registry.get_tool("does-not-exist") is None

    def test_list_tools_returns_all_ids(self, registry: ToolRegistry) -> None:
        """list_tools returns all registered tool IDs."""
        tools = registry.list_tools()
        assert sorted(tools) == ["port-scanner", "scapy-craft"]

    def test_in_process_tool_has_module(self, registry: ToolRegistry) -> None:
        """In-process tools have module field set."""
        tool = registry.get_tool("scapy-craft")
        assert tool is not None
        assert tool.module == "orchestrator.tools.scapy_craft"
        assert tool.invocation == "in-process"

    def test_subprocess_tool_has_executable(self, registry: ToolRegistry) -> None:
        """Subprocess tools have executable field set."""
        tool = registry.get_tool("port-scanner")
        assert tool is not None
        assert tool.executable is not None


# ---------------------------------------------------------------------------
# Argument validation tests
# ---------------------------------------------------------------------------


class TestArgumentValidation:
    """Test argument validation against declared schemas."""

    def test_valid_arguments_pass(self, registry: ToolRegistry) -> None:
        """Valid arguments pass validation without error."""
        registry.validate_arguments("port-scanner", {
            "target": "192.168.1.1",
            "start_port": 1,
            "end_port": 1024,
            "concurrency": 512,
        })

    def test_missing_required_arg_raises_error(self, registry: ToolRegistry) -> None:
        """Missing required argument raises ToolValidationError."""
        with pytest.raises(ToolValidationError, match="Missing required argument 'target'"):
            registry.validate_arguments("port-scanner", {
                "start_port": 1,
                "end_port": 1024,
            })

    def test_type_mismatch_string_raises_error(self, registry: ToolRegistry) -> None:
        """Passing integer where string expected raises ToolValidationError."""
        with pytest.raises(ToolValidationError, match="must be a string"):
            registry.validate_arguments("port-scanner", {
                "target": 12345,  # should be string
                "start_port": 1,
                "end_port": 1024,
            })

    def test_type_mismatch_integer_raises_error(self, registry: ToolRegistry) -> None:
        """Passing string where integer expected raises ToolValidationError."""
        with pytest.raises(ToolValidationError, match="must be an integer"):
            registry.validate_arguments("port-scanner", {
                "target": "192.168.1.1",
                "start_port": "not-a-number",
                "end_port": 1024,
            })

    def test_type_mismatch_object_raises_error(self, registry: ToolRegistry) -> None:
        """Passing string where object expected raises ToolValidationError."""
        with pytest.raises(ToolValidationError, match="must be an object"):
            registry.validate_arguments("scapy-craft", {
                "packet_spec": "not-an-object",
            })

    def test_value_below_min_raises_error(self, registry: ToolRegistry) -> None:
        """Integer below declared min raises ToolValidationError."""
        with pytest.raises(ToolValidationError, match="below minimum"):
            registry.validate_arguments("port-scanner", {
                "target": "192.168.1.1",
                "start_port": 0,  # min is 1
                "end_port": 1024,
            })

    def test_value_above_max_raises_error(self, registry: ToolRegistry) -> None:
        """Integer above declared max raises ToolValidationError."""
        with pytest.raises(ToolValidationError, match="exceeds maximum"):
            registry.validate_arguments("port-scanner", {
                "target": "192.168.1.1",
                "start_port": 1,
                "end_port": 100000,  # max is 65535
            })

    def test_optional_arg_can_be_omitted(self, registry: ToolRegistry) -> None:
        """Optional arguments can be omitted without error."""
        registry.validate_arguments("port-scanner", {
            "target": "192.168.1.1",
            "start_port": 1,
            "end_port": 1024,
            # concurrency is optional, omitted
        })

    def test_validate_unknown_tool_raises_registry_error(self, registry: ToolRegistry) -> None:
        """Validating args for an unknown tool raises ToolRegistryError."""
        with pytest.raises(ToolRegistryError, match="Tool not found"):
            registry.validate_arguments("ghost-tool", {"x": 1})

    def test_apply_defaults_fills_optional_values(self, registry: ToolRegistry) -> None:
        """apply_defaults copies declared defaults without mutating the input."""
        original = {"target": "192.168.1.1", "start_port": 1, "end_port": 1024}
        merged = registry.apply_defaults("port-scanner", original)
        assert merged["concurrency"] == 1024
        assert "concurrency" not in original

    def test_apply_defaults_does_not_overwrite_provided(self, registry: ToolRegistry) -> None:
        """An explicit value wins over the schema default."""
        merged = registry.apply_defaults(
            "port-scanner",
            {"target": "192.168.1.1", "start_port": 1, "end_port": 1024, "concurrency": 8},
        )
        assert merged["concurrency"] == 8


# ---------------------------------------------------------------------------
# Environment variable expansion tests
# ---------------------------------------------------------------------------


class TestEnvVarExpansion:
    """Test ${VAR} expansion in executable paths."""

    def test_env_var_expansion(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables in executable paths are expanded."""
        monkeypatch.setenv("ATHENA_BIN_DIR", "/opt/athena/bin")
        content = dedent("""\
            [tools.scanner]
            executable = "${ATHENA_BIN_DIR}/athena-scanner"
            invocation = "subprocess"
            [tools.scanner.args]
            target = { type = "string", required = true }
        """)
        path = tmp_path / "registry.toml"
        path.write_text(content)

        reg = ToolRegistry.load(path)
        tool = reg.get_tool("scanner")
        assert tool is not None
        assert tool.executable == "/opt/athena/bin/athena-scanner"

    def test_unset_env_var_left_as_is(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unset environment variables are left as their ${VAR} placeholder."""
        monkeypatch.delenv("ATHENA_BIN_DIR", raising=False)
        content = dedent("""\
            [tools.scanner]
            executable = "${ATHENA_BIN_DIR}/athena-scanner"
            invocation = "subprocess"
            [tools.scanner.args]
            target = { type = "string", required = true }
        """)
        path = tmp_path / "registry.toml"
        path.write_text(content)

        reg = ToolRegistry.load(path)
        tool = reg.get_tool("scanner")
        assert tool is not None
        assert tool.executable == "${ATHENA_BIN_DIR}/athena-scanner"


# ---------------------------------------------------------------------------
# Enum validation tests
# ---------------------------------------------------------------------------


class TestEnumValidation:
    """Test enum constraint validation on string arguments."""

    def test_valid_enum_value_passes(self, tmp_path: Path) -> None:
        """A value matching an enum entry passes validation."""
        content = dedent("""\
            [tools.fuzzer]
            executable = "/usr/bin/fuzzer"
            invocation = "subprocess"
            [tools.fuzzer.args]
            protocol = { type = "string", required = true, enum = ["http", "tcp", "dns"] }
        """)
        path = tmp_path / "registry.toml"
        path.write_text(content)
        reg = ToolRegistry.load(path)

        # Should not raise
        reg.validate_arguments("fuzzer", {"protocol": "http"})

    def test_invalid_enum_value_raises_error(self, tmp_path: Path) -> None:
        """A value not in the enum list raises ToolValidationError."""
        content = dedent("""\
            [tools.fuzzer]
            executable = "/usr/bin/fuzzer"
            invocation = "subprocess"
            [tools.fuzzer.args]
            protocol = { type = "string", required = true, enum = ["http", "tcp", "dns"] }
        """)
        path = tmp_path / "registry.toml"
        path.write_text(content)
        reg = ToolRegistry.load(path)

        with pytest.raises(ToolValidationError, match="not in allowed values"):
            reg.validate_arguments("fuzzer", {"protocol": "ftp"})


# ---------------------------------------------------------------------------
# Integration test with real config file
# ---------------------------------------------------------------------------


class TestRealConfig:
    """Test loading the actual config/tool-registry.toml file."""

    def test_load_project_config(self) -> None:
        """The project's config/tool-registry.toml loads successfully."""
        config_path = Path(__file__).resolve().parents[2] / "config" / "tool-registry.toml"
        if not config_path.exists():
            pytest.skip("config/tool-registry.toml not present")

        reg = ToolRegistry.load(config_path)
        tools = reg.list_tools()
        assert "port-scanner" in tools
        assert "protocol-fuzzer" in tools
        assert "packet-crafter" in tools
        assert "nmap-scan" in tools
        assert "http-request" in tools
        assert "scapy-craft" in tools
