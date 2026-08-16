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

    The labeler provides two outputs:
    - HTTP headers (for HTTP-based attack tools): includes `X-Athena-Scenario-Id`
    - Environment variables (for tool invocations): includes `ATHENA_SCENARIO_ID`
      and `ATHENA_SCENARIO_LABEL`

    Example usage::

        labeler = TrafficLabeler()
        headers = labeler.get_http_headers("scenario-abc-123")
        env_vars = labeler.get_env_vars("scenario-abc-123", "sqli-juice-shop")

    """

    #: Header name used to tag HTTP-based attack traffic with the scenario ID.
    SCENARIO_ID_HEADER = "X-Athena-Scenario-Id"

    #: Environment variable name for the scenario ID passed to tool invocations.
    SCENARIO_ID_ENV = "ATHENA_SCENARIO_ID"

    #: Environment variable name for the scenario label passed to tool invocations.
    SCENARIO_LABEL_ENV = "ATHENA_SCENARIO_LABEL"

    def get_http_headers(self, scenario_id: str) -> dict[str, str]:
        """Return HTTP headers to attach to HTTP-based attack traffic.

        These headers allow SOC sensors and dashboards to identify which
        scenario generated a given piece of network traffic.

        Args:
            scenario_id: The unique identifier of the running scenario.

        Returns:
            A dictionary of header name to header value. Currently includes
            the ``X-Athena-Scenario-Id`` header.
        """
        return {
            self.SCENARIO_ID_HEADER: scenario_id,
        }

    def get_env_vars(self, scenario_id: str, label: str) -> dict[str, str]:
        """Return environment variables to set for tool invocations.

        These environment variables are injected into the subprocess or
        in-process tool environment so that any downstream telemetry or
        logging can carry the scenario context.

        Args:
            scenario_id: The unique identifier of the running scenario.
            label: A descriptive label for the scenario (e.g., "sqli-juice-shop",
                "xss-dvwa"). Used by SOC dashboards to filter training traffic.

        Returns:
            A dictionary of environment variable name to value. Includes
            ``ATHENA_SCENARIO_ID`` and ``ATHENA_SCENARIO_LABEL``.
        """
        return {
            self.SCENARIO_ID_ENV: scenario_id,
            self.SCENARIO_LABEL_ENV: label,
        }
