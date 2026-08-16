"""Eval Harness - Report generation and filtering.

Produces structured JSON evaluation reports with:
- Model metadata (name, version, time window)
- Total counts (ground-truth, predictions)
- Per-technique and aggregate metrics
- Skipped records with reasons
- Warning field for empty inputs
- Duplicates excluded count

Supports filtering by scenario_id, technique, or payload_family
as inclusive predicates before metric computation.

Requirements: 8.2, 8.5, 8.6, 8.8, 8.9
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from eval.harness import (
    PredictionRecord,
    TechniqueMetrics,
    compute_metrics,
    match_records,
)
from orchestrator.interfaces import GroundTruthRecord


@dataclass
class SkippedRecord:
    """A record excluded from evaluation due to missing required fields."""

    record_type: str  # "ground_truth" or "prediction"
    reason: str
    partial_data: dict


@dataclass
class EvalReport:
    """Structured evaluation report for purple-team metrics."""

    model_name: str
    model_version: str
    time_window_seconds: int
    total_ground_truth: int
    total_predictions: int
    per_technique: list[TechniqueMetrics]
    aggregate_precision: float
    aggregate_recall: float
    aggregate_f1: float
    skipped_records: list[SkippedRecord] = field(default_factory=list)
    warning: str | None = None
    duplicates_excluded: int = 0

    def to_dict(self) -> dict:
        """Convert the report to a plain dictionary."""
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "time_window_seconds": self.time_window_seconds,
            "total_ground_truth": self.total_ground_truth,
            "total_predictions": self.total_predictions,
            "per_technique": [
                {
                    "technique": m.technique,
                    "true_positives": m.true_positives,
                    "false_positives": m.false_positives,
                    "false_negatives": m.false_negatives,
                    "precision": m.precision,
                    "recall": m.recall,
                    "f1": m.f1,
                }
                for m in self.per_technique
            ],
            "aggregate_precision": self.aggregate_precision,
            "aggregate_recall": self.aggregate_recall,
            "aggregate_f1": self.aggregate_f1,
            "skipped_records": [
                {
                    "record_type": s.record_type,
                    "reason": s.reason,
                    "partial_data": s.partial_data,
                }
                for s in self.skipped_records
            ],
            "warning": self.warning,
            "duplicates_excluded": self.duplicates_excluded,
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Serialize the report to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


def _validate_gt_record(record: GroundTruthRecord) -> str | None:
    """Validate a ground-truth record has required fields.

    Returns None if valid, or a reason string if the record should be skipped.
    """
    missing = []
    if not getattr(record, "scenario_id", None):
        missing.append("scenario_id")
    if not getattr(record, "technique", None) and getattr(record, "technique", "") is not None:
        # technique can be None (valid per spec), but if it's an empty string that's missing
        if getattr(record, "technique", None) == "":
            missing.append("technique")
    if not getattr(record, "timestamp", None):
        missing.append("timestamp")

    if missing:
        return f"missing required field(s): {', '.join(missing)}"
    return None


def _validate_prediction_record(record: PredictionRecord) -> str | None:
    """Validate a prediction record has required fields.

    Returns None if valid, or a reason string if the record should be skipped.
    """
    missing = []
    if not getattr(record, "scenario_id", None):
        missing.append("scenario_id")
    if not getattr(record, "technique", None):
        missing.append("technique")
    if not getattr(record, "timestamp", None):
        missing.append("timestamp")

    if missing:
        return f"missing required field(s): {', '.join(missing)}"
    return None


def _gt_to_partial_data(record: GroundTruthRecord) -> dict:
    """Extract partial data from a ground-truth record for the skipped_records entry."""
    return {
        "scenario_id": getattr(record, "scenario_id", None),
        "technique": getattr(record, "technique", None),
        "timestamp": getattr(record, "timestamp", None),
        "target": getattr(record, "target", None),
        "payload_family": getattr(record, "payload_family", None),
    }


def _pred_to_partial_data(record: PredictionRecord) -> dict:
    """Extract partial data from a prediction record for the skipped_records entry."""
    return {
        "scenario_id": getattr(record, "scenario_id", None),
        "technique": getattr(record, "technique", None),
        "timestamp": getattr(record, "timestamp", None),
        "model_name": getattr(record, "model_name", None),
        "model_version": getattr(record, "model_version", None),
    }


def generate_report(
    ground_truth: list[GroundTruthRecord],
    predictions: list[PredictionRecord],
    model_name: str,
    model_version: str,
    time_window_seconds: int = 300,
    scenario_filter: str | None = None,
    technique_filter: str | None = None,
    payload_family_filter: str | None = None,
) -> EvalReport:
    """Generate a structured evaluation report.

    Validates records, applies optional filters, computes metrics, and produces
    a complete EvalReport.

    Args:
        ground_truth: List of ground-truth records from Athena agent.
        predictions: List of prediction records from AI-SOC Inference Engine.
        model_name: Name of the AI model being evaluated.
        model_version: Version of the AI model being evaluated.
        time_window_seconds: Maximum timestamp difference for matching (default 300s).
        scenario_filter: If set, include only records with this scenario_id.
        technique_filter: If set, include only records with this technique.
        payload_family_filter: If set, include only GT records with this payload_family.

    Returns:
        A complete EvalReport with metrics, skipped records, and warnings.
    """
    skipped_records: list[SkippedRecord] = []

    # Step 1: Validate ground-truth records
    valid_gt: list[GroundTruthRecord] = []
    for record in ground_truth:
        reason = _validate_gt_record(record)
        if reason:
            skipped_records.append(
                SkippedRecord(
                    record_type="ground_truth",
                    reason=reason,
                    partial_data=_gt_to_partial_data(record),
                )
            )
        else:
            valid_gt.append(record)

    # Step 2: Validate prediction records
    valid_preds: list[PredictionRecord] = []
    for record in predictions:
        reason = _validate_prediction_record(record)
        if reason:
            skipped_records.append(
                SkippedRecord(
                    record_type="prediction",
                    reason=reason,
                    partial_data=_pred_to_partial_data(record),
                )
            )
        else:
            valid_preds.append(record)

    # Step 3: Apply filters (inclusive predicates)
    if scenario_filter is not None:
        valid_gt = [r for r in valid_gt if r.scenario_id == scenario_filter]
        valid_preds = [p for p in valid_preds if p.scenario_id == scenario_filter]

    if technique_filter is not None:
        valid_gt = [r for r in valid_gt if r.technique == technique_filter]
        valid_preds = [p for p in valid_preds if p.technique == technique_filter]

    if payload_family_filter is not None:
        valid_gt = [r for r in valid_gt if r.payload_family == payload_family_filter]
        # Predictions don't have payload_family, so we don't filter them here
        # (they match by scenario_id + technique in the harness)

    # Step 4: Check for empty inputs and set warning
    warning: str | None = None
    if len(valid_gt) == 0 and len(valid_preds) == 0:
        warning = "Both ground-truth and prediction input sets are empty"
    elif len(valid_gt) == 0:
        warning = "Ground-truth input set is empty"
    elif len(valid_preds) == 0:
        warning = "Prediction input set is empty"

    # Step 5: Compute matching and metrics
    if warning is not None:
        # If either input is empty, all metrics = 0
        match_result = match_records(valid_gt, valid_preds, time_window_seconds)
        per_technique, agg_precision, agg_recall, agg_f1 = compute_metrics(match_result)
        duplicates_excluded = match_result.duplicates_excluded
    else:
        match_result = match_records(valid_gt, valid_preds, time_window_seconds)
        per_technique, agg_precision, agg_recall, agg_f1 = compute_metrics(match_result)
        duplicates_excluded = match_result.duplicates_excluded

    return EvalReport(
        model_name=model_name,
        model_version=model_version,
        time_window_seconds=time_window_seconds,
        total_ground_truth=len(valid_gt),
        total_predictions=len(valid_preds),
        per_technique=per_technique,
        aggregate_precision=agg_precision,
        aggregate_recall=agg_recall,
        aggregate_f1=agg_f1,
        skipped_records=skipped_records,
        warning=warning,
        duplicates_excluded=duplicates_excluded,
    )
