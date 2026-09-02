"""Tests for traffic labeling and metadata.

Validates that the TrafficLabeler produces correct HTTP headers and
environment variables for SOC pipeline filtering.

Requirements: 10.2, 10.4
"""

from orchestrator.traffic_labeling import TrafficLabeler


class TestTrafficLabelerHTTPHeaders:
    """Tests for get_http_headers method."""

    def test_returns_dict(self):
        """get_http_headers should return a dictionary."""
        labeler = TrafficLabeler()
        result = labeler.get_http_headers("scenario-123")
        assert isinstance(result, dict)

    def test_includes_scenario_id_header(self):
        """Headers must include X-Athena-Scenario-Id with the scenario_id value."""
        labeler = TrafficLabeler()
        headers = labeler.get_http_headers("abc-def-456", label="night-quire")
        assert "X-Athena-Scenario-Id" in headers
        assert headers["X-Athena-Scenario-Id"] == "abc-def-456"

    def test_includes_scenario_label_header(self):
        labeler = TrafficLabeler()
        headers = labeler.get_http_headers("abc-def-456", label="night-quire")
        assert headers["X-Athena-Scenario"] == "night-quire"

    def test_includes_run_id_when_provided(self):
        labeler = TrafficLabeler()
        headers = labeler.get_http_headers(
            "abc-def-456", label="night-quire", run_id="run-1"
        )
        assert headers["X-Athena-Run-ID"] == "run-1"

    def test_scenario_id_header_matches_input(self):
        """The X-Athena-Scenario-Id header value must match the scenario_id argument."""
        labeler = TrafficLabeler()
        scenario_id = "550e8400-e29b-41d4-a716-446655440000"
        headers = labeler.get_http_headers(scenario_id)
        assert headers["X-Athena-Scenario-Id"] == scenario_id
        assert headers["X-Athena-Scenario"] == scenario_id

    def test_empty_scenario_id(self):
        """An empty scenario_id should still produce a header with empty value."""
        labeler = TrafficLabeler()
        headers = labeler.get_http_headers("")
        assert headers["X-Athena-Scenario-Id"] == ""
        assert headers["X-Athena-Scenario"] == ""

    def test_uuid_format_scenario_id(self):
        """UUID-formatted scenario IDs should be returned verbatim."""
        labeler = TrafficLabeler()
        uuid_id = "123e4567-e89b-12d3-a456-426614174000"
        headers = labeler.get_http_headers(uuid_id)
        assert headers["X-Athena-Scenario-Id"] == uuid_id


class TestTrafficLabelerEnvVars:
    """Tests for get_env_vars method."""

    def test_returns_dict(self):
        """get_env_vars should return a dictionary."""
        labeler = TrafficLabeler()
        result = labeler.get_env_vars("scenario-123", "test-label")
        assert isinstance(result, dict)

    def test_includes_scenario_id_env(self):
        """Env vars must include ATHENA_SCENARIO_ID."""
        labeler = TrafficLabeler()
        env_vars = labeler.get_env_vars("scenario-789", "my-label")
        assert "ATHENA_SCENARIO_ID" in env_vars
        assert env_vars["ATHENA_SCENARIO_ID"] == "scenario-789"

    def test_includes_scenario_label_env(self):
        """Env vars must include ATHENA_SCENARIO_LABEL."""
        labeler = TrafficLabeler()
        env_vars = labeler.get_env_vars("scenario-789", "sqli-juice-shop")
        assert "ATHENA_SCENARIO_LABEL" in env_vars
        assert env_vars["ATHENA_SCENARIO_LABEL"] == "sqli-juice-shop"

    def test_env_vars_match_inputs(self):
        """Environment variable values must match the provided arguments."""
        labeler = TrafficLabeler()
        scenario_id = "550e8400-e29b-41d4-a716-446655440000"
        label = "xss-dvwa-reflected"
        env_vars = labeler.get_env_vars(scenario_id, label)
        assert env_vars["ATHENA_SCENARIO_ID"] == scenario_id
        assert env_vars["ATHENA_SCENARIO_LABEL"] == label

    def test_empty_label(self):
        """An empty label should still produce the ATHENA_SCENARIO_LABEL env var."""
        labeler = TrafficLabeler()
        env_vars = labeler.get_env_vars("scenario-123", "")
        assert env_vars["ATHENA_SCENARIO_LABEL"] == ""

    def test_empty_scenario_id(self):
        """An empty scenario_id should still produce the ATHENA_SCENARIO_ID env var."""
        labeler = TrafficLabeler()
        env_vars = labeler.get_env_vars("", "some-label")
        assert env_vars["ATHENA_SCENARIO_ID"] == ""


class TestTrafficLabelerConsistency:
    """Tests for consistency between headers and env vars."""

    def test_scenario_id_consistent_across_methods(self):
        """The scenario_id should appear in both headers and env vars."""
        labeler = TrafficLabeler()
        scenario_id = "consistent-test-id"
        headers = labeler.get_http_headers(scenario_id, label="test-label")
        env_vars = labeler.get_env_vars(scenario_id, "test-label", run_id="run-42")
        assert headers["X-Athena-Scenario-Id"] == env_vars["ATHENA_SCENARIO_ID"]
        assert headers["X-Athena-Scenario"] == env_vars["ATHENA_SCENARIO_LABEL"]
        assert env_vars["ATHENA_RUN_ID"] == "run-42"

    def test_multiple_calls_same_result(self):
        """Calling the same method multiple times with same input returns same result."""
        labeler = TrafficLabeler()
        headers1 = labeler.get_http_headers("repeat-test")
        headers2 = labeler.get_http_headers("repeat-test")
        assert headers1 == headers2

    def test_different_scenarios_different_headers(self):
        """Different scenario IDs produce different header values."""
        labeler = TrafficLabeler()
        headers1 = labeler.get_http_headers("scenario-a")
        headers2 = labeler.get_http_headers("scenario-b")
        assert headers1["X-Athena-Scenario-Id"] != headers2["X-Athena-Scenario-Id"]
