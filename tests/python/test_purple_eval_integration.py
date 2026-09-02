"""Tests for eval triage adapter and http-post-probe safety gates."""

from __future__ import annotations

import importlib.util

import pytest

from eval.triage_adapter import triage_to_prediction


def test_triage_to_prediction_extracts_scenario_and_technique():
    pred = triage_to_prediction(
        {
            "scenario_id": "uuid-1",
            "technique": "T1190",
            "timestamp": "2024-01-15T10:01:00.000Z",
            "score": 0.9,
            "model_name": "nexus-triage-baseline",
            "model_version": "1.1.0",
        }
    )
    assert pred is not None
    assert pred.scenario_id == "uuid-1"
    assert pred.technique == "T1190"


def test_triage_to_prediction_skips_incomplete():
    assert triage_to_prediction({"score": 0.5}) is None


@pytest.mark.skipif(importlib.util.find_spec("httpx") is None, reason="httpx not installed")
def test_post_probe_rejects_unknown_path():
    from orchestrator.allowlist import AllowlistEntry
    from orchestrator.tools.http_post_probe import HttpProbeError, resolve_post_url

    allowlist = [AllowlistEntry(host="127.0.0.1", port_range=(8090, 8090), protocol="http", label="nq")]
    with pytest.raises(HttpProbeError, match="allowlist"):
        resolve_post_url(
            {
                "target": "127.0.0.1",
                "port": 8090,
                "path": "/api/v1/admin/delete-all",
                "body": {"email": "a@b.c", "password": "x"},
            },
            "127.0.0.1",
            8090,
            allowlist,
        )


@pytest.mark.skipif(importlib.util.find_spec("httpx") is None, reason="httpx not installed")
def test_post_probe_accepts_login_path():
    from orchestrator.allowlist import AllowlistEntry
    from orchestrator.tools.http_post_probe import resolve_post_url

    allowlist = [AllowlistEntry(host="127.0.0.1", port_range=(8090, 8090), protocol="http", label="nq")]
    url, host, port, path, body = resolve_post_url(
        {
            "target": "127.0.0.1",
            "port": 8090,
            "path": "/api/v1/auth/login",
            "body": {"email": "reader@nightquire.com", "password": "readerpass"},
        },
        "127.0.0.1",
        8090,
        allowlist,
    )
    assert host == "127.0.0.1"
    assert path.startswith("/api/v1/auth/login")
    assert body["email"] == "reader@nightquire.com"
