"""Traffic labeling and metadata for SOC pipeline filtering.

Provides the TrafficLabeler class that manages scenario labels for
HTTP-based attack traffic and tool invocation environments. This enables
SOC dashboards to filter training traffic from real alerts by label value.

Requirements: 10.2, 10.4
"""

from __future__ import annotations


class TrafficLabeler:
    """Manages scenario labels for traffic identification and SOC filtering.

    Produces HTTP headers and environment variables that label Athena-generated
    traffic so that SOC dashboards can distinguish training/simulation traffic
    from real alerts.

    HTTP headers (aligned with core-nexus ai-inference / gateway):
    - ``X-Athena-Scenario``: human-readable scenario label (SOC filter)
    - ``X-Athena-Scenario-Id``: unique scenario run identifier
    - ``X-Athena-Run-ID``: OPAR run identifier

    Environment variables (tool subprocesses):
    - ``ATHENA_SCENARIO_ID``, ``ATHENA_SCENARIO_LABEL``, ``ATHENA_RUN_ID``
    """

    SCENARIO_HEADER = "X-Athena-Scenario"
    SCENARIO_ID_HEADER = "X-Athena-Scenario-Id"
    RUN_ID_HEADER = "X-Athena-Run-ID"

    SCENARIO_ID_ENV = "ATHENA_SCENARIO_ID"
    SCENARIO_LABEL_ENV = "ATHENA_SCENARIO_LABEL"
    RUN_ID_ENV = "ATHENA_RUN_ID"

    def get_http_headers(
        self,
        scenario_id: str,
        *,
        label: str = "",
        run_id: str = "",
    ) -> dict[str, str]:
        """Return HTTP headers for labeled attack traffic."""
        scenario_label = label or scenario_id
        headers = {
            self.SCENARIO_ID_HEADER: scenario_id,
            self.SCENARIO_HEADER: scenario_label,
        }
        if run_id:
            headers[self.RUN_ID_HEADER] = run_id
        return headers

    def get_env_vars(
        self,
        scenario_id: str,
        label: str,
        *,
        run_id: str = "",
    ) -> dict[str, str]:
        """Return environment variables for tool invocations."""
        env = {
            self.SCENARIO_ID_ENV: scenario_id,
            self.SCENARIO_LABEL_ENV: label,
        }
        if run_id:
            env[self.RUN_ID_ENV] = run_id
        return env
