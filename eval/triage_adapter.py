"""Map ai-inference triage payloads to eval PredictionRecord instances."""

from __future__ import annotations

from typing import Any

from eval.harness import PredictionRecord


def triage_to_prediction(record: dict[str, Any]) -> PredictionRecord | None:
    """Best-effort conversion of a persisted triage result to a prediction."""
    meta = record.get("feature_meta") if isinstance(record.get("feature_meta"), dict) else {}
    scenario_id = (
        record.get("scenario_id")
        or record.get("athena_scenario")
        or meta.get("scenario_id")
        or meta.get("athena_scenario")
    )
    technique = record.get("technique") or meta.get("technique")
    timestamp = record.get("timestamp") or record.get("saved_at")
    if not scenario_id or not technique or not timestamp:
        return None
    saved_at = record.get("saved_at")
    if isinstance(saved_at, (int, float)) and not str(timestamp).endswith("Z"):
        from datetime import datetime, timezone

        timestamp = datetime.fromtimestamp(float(saved_at), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"
    return PredictionRecord(
        scenario_id=str(scenario_id),
        technique=str(technique),
        timestamp=str(timestamp),
        model_name=str(record.get("model_name") or "nexus-triage-baseline"),
        model_version=str(record.get("model_version") or "unknown"),
        confidence=float(record.get("score") or record.get("confidenceScore") or 0.0),
    )


def load_predictions_jsonl(path: str) -> list[PredictionRecord]:
    """Load predictions from a JSONL export of triage records."""
    import json
    from pathlib import Path

    out: list[PredictionRecord] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        data = json.loads(line)
        if not isinstance(data, dict):
            continue
        pred = triage_to_prediction(data)
        if pred is not None:
            out.append(pred)
    return out
