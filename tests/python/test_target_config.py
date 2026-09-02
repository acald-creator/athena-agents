"""Tests for target TOML normalization."""

from pathlib import Path

from orchestrator.target_config import load_target_document, normalize_target_document


def test_normalize_nested_target_table():
    raw = {
        "target": {"host": "127.0.0.1", "port": 8090, "id": "night-quire"},
        "scenario": {"max_actions": 8},
        "api": {"public_endpoints": ["GET /health"]},
    }
    doc = normalize_target_document(raw)
    assert doc["host"] == "127.0.0.1"
    assert doc["port"] == 8090
    assert doc["scenario"]["max_actions"] == 8
    assert doc["api"]["public_endpoints"] == ["GET /health"]


def test_normalize_legacy_flat_target():
    raw = {
        "target_id": "novel-directory",
        "host": "127.0.0.1",
        "port": 8090,
        "scenario": {"max_actions": 100},
    }
    doc = normalize_target_document(raw)
    assert doc["id"] == "novel-directory"
    assert doc["host"] == "127.0.0.1"
    assert doc["port"] == 8090


def test_load_night_quire_target_file():
    path = Path(__file__).resolve().parents[2] / "config" / "targets" / "night-quire.toml"
    doc = load_target_document(path)
    assert doc["host"] == "127.0.0.1"
    assert doc["port"] == 8090
    assert doc["scenario"]["max_actions"] == 8
