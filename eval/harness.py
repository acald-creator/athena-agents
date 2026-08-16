"""Eval Harness - Matching algorithm and metrics computation.

Implements ground-truth to prediction matching for purple-team metrics:
- Record matching by scenario_id + technique within a configurable time window
- One-to-one matching (earliest prediction wins)
- Per-technique and aggregate (micro-averaged) precision, recall, F1

Requirements: 8.1, 8.3, 8.4, 8.7
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PredictionRecord:
    """A prediction from the AI-SOC Inference Engine."""

    scenario_id: str
    technique: str
    timestamp: str  # ISO 8601 UTC
    model_name: str
    model_version: str
    confidence: float | None = None


@dataclass
class MatchedPair:
    """A ground-truth record matched to a prediction (true positive)."""

    ground_truth: object  # GroundTruthRecord
    prediction: PredictionRecord


@dataclass
class MatchResult:
    """Result of matching ground-truth records to predictions."""

    true_positives: list[MatchedPair] = field(default_factory=list)
    false_negatives: list[object] = field(default_factory=list)  # Unmatched GT
    false_positives: list[PredictionRecord] = field(default_factory=list)  # Unmatched predictions
    duplicates_excluded: int = 0


@dataclass
class TechniqueMetrics:
    """Per-technique precision, recall, and F1 metrics."""

    technique: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float


def _parse_timestamp(ts: str) -> datetime:
    """Parse an ISO 8601 timestamp string to a datetime object.

    Handles both 'Z' suffix and '+00:00' timezone formats.
    """
    # Handle 'Z' suffix by replacing with +00:00
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def match_records(
    ground_truth: list,
    predictions: list[PredictionRecord],
    time_window_seconds: int = 300,
) -> MatchResult:
    """Match ground-truth records to predictions.

    Algorithm:
    1. Sort both lists by timestamp
    2. For each ground-truth record, find predictions where:
       - scenario_id matches AND technique matches
       - |prediction.timestamp - gt.timestamp| <= time_window_seconds
    3. If multiple predictions match, take the earliest (first within window)
    4. Mark that prediction as consumed (one-to-one matching)
    5. Unmatched ground-truth = false negatives
    6. Unmatched predictions = false positives
    7. Matched pairs = true positives

    Args:
        ground_truth: List of GroundTruthRecord instances.
        predictions: List of PredictionRecord instances.
        time_window_seconds: Maximum absolute timestamp difference for a match.
            Must be between 1 and 86400 (inclusive). Defaults to 300.

    Returns:
        A MatchResult containing true positives, false negatives,
        false positives, and count of duplicates excluded.

    Raises:
        ValueError: If time_window_seconds is outside the valid range [1, 86400].
    """
    if time_window_seconds < 1 or time_window_seconds > 86400:
        raise ValueError(
            f"time_window_seconds must be between 1 and 86400, got {time_window_seconds}"
        )

    result = MatchResult()

    if not ground_truth or not predictions:
        # If either list is empty, all GT are FN and all predictions are FP
        result.false_negatives = list(ground_truth)
        result.false_positives = list(predictions)
        return result

    # Sort both by timestamp
    sorted_gt = sorted(ground_truth, key=lambda r: _parse_timestamp(r.timestamp))
    sorted_preds = sorted(predictions, key=lambda r: _parse_timestamp(r.timestamp))

    # Track which predictions have been consumed
    consumed_predictions: set[int] = set()

    for gt_record in sorted_gt:
        gt_time = _parse_timestamp(gt_record.timestamp)
        gt_technique = gt_record.technique

        # Find matching predictions: same scenario_id + technique within time window
        best_match_idx: int | None = None
        best_match_time: datetime | None = None

        for pred_idx, pred in enumerate(sorted_preds):
            if pred_idx in consumed_predictions:
                continue

            # Check scenario_id and technique match
            if pred.scenario_id != gt_record.scenario_id:
                continue
            if pred.technique != gt_technique:
                continue

            # Check time window
            pred_time = _parse_timestamp(pred.timestamp)
            time_diff = abs((pred_time - gt_time).total_seconds())
            if time_diff > time_window_seconds:
                continue

            # If multiple match, take the earliest prediction
            if best_match_idx is None or pred_time < best_match_time:
                best_match_idx = pred_idx
                best_match_time = pred_time

        if best_match_idx is not None:
            # True positive: matched pair
            result.true_positives.append(
                MatchedPair(
                    ground_truth=gt_record,
                    prediction=sorted_preds[best_match_idx],
                )
            )
            consumed_predictions.add(best_match_idx)
        else:
            # False negative: no matching prediction
            result.false_negatives.append(gt_record)

    # Count duplicates: predictions that matched a GT record's criteria
    # but were excluded because an earlier one was chosen
    # We count how many unconsumed predictions *could* have matched consumed GT
    duplicates = 0
    for pred_idx, pred in enumerate(sorted_preds):
        if pred_idx in consumed_predictions:
            continue
        # Check if this prediction could have matched any GT that already has a match
        pred_time = _parse_timestamp(pred.timestamp)
        for tp in result.true_positives:
            gt_record = tp.ground_truth
            gt_time = _parse_timestamp(gt_record.timestamp)
            if (
                pred.scenario_id == gt_record.scenario_id
                and pred.technique == gt_record.technique
                and abs((pred_time - gt_time).total_seconds()) <= time_window_seconds
            ):
                duplicates += 1
                break

    result.duplicates_excluded = duplicates

    # False positives: unconsumed predictions that aren't duplicates
    for pred_idx, pred in enumerate(sorted_preds):
        if pred_idx not in consumed_predictions:
            result.false_positives.append(pred)

    return result


def _compute_precision(tp: int, fp: int) -> float:
    """Compute precision = TP / (TP + FP), or 0 when denominator is 0."""
    denom = tp + fp
    return tp / denom if denom > 0 else 0.0


def _compute_recall(tp: int, fn: int) -> float:
    """Compute recall = TP / (TP + FN), or 0 when denominator is 0."""
    denom = tp + fn
    return tp / denom if denom > 0 else 0.0


def _compute_f1(precision: float, recall: float) -> float:
    """Compute F1 = 2 * P * R / (P + R), or 0 when denominator is 0."""
    denom = precision + recall
    return 2 * precision * recall / denom if denom > 0 else 0.0


def compute_metrics(
    match_result: MatchResult,
) -> tuple[list[TechniqueMetrics], float, float, float]:
    """Compute per-technique and aggregate micro-averaged metrics.

    For each technique encountered in the match result:
    - Count TP, FP, FN
    - Compute precision, recall, F1

    Aggregate metrics use micro-averaging:
    - Sum all TPs, FPs, FNs across techniques
    - Compute precision, recall, F1 from the sums

    Args:
        match_result: The result of match_records().

    Returns:
        A tuple of:
        - List of per-technique TechniqueMetrics
        - Aggregate micro-averaged precision
        - Aggregate micro-averaged recall
        - Aggregate micro-averaged F1
    """
    # Collect per-technique counts
    technique_tp: dict[str, int] = {}
    technique_fp: dict[str, int] = {}
    technique_fn: dict[str, int] = {}

    # Count TPs per technique
    for tp_pair in match_result.true_positives:
        technique = tp_pair.prediction.technique
        technique_tp[technique] = technique_tp.get(technique, 0) + 1

    # Count FPs per technique
    for fp_pred in match_result.false_positives:
        technique = fp_pred.technique
        technique_fp[technique] = technique_fp.get(technique, 0) + 1

    # Count FNs per technique
    for fn_gt in match_result.false_negatives:
        technique = fn_gt.technique
        # Handle None technique
        tech_key = technique if technique is not None else "__none__"
        technique_fn[tech_key] = technique_fn.get(tech_key, 0) + 1

    # Gather all techniques
    all_techniques = set(technique_tp.keys()) | set(technique_fp.keys()) | set(technique_fn.keys())

    per_technique: list[TechniqueMetrics] = []
    for technique in sorted(all_techniques):
        tp = technique_tp.get(technique, 0)
        fp = technique_fp.get(technique, 0)
        fn = technique_fn.get(technique, 0)
        precision = _compute_precision(tp, fp)
        recall = _compute_recall(tp, fn)
        f1 = _compute_f1(precision, recall)
        per_technique.append(
            TechniqueMetrics(
                technique=technique,
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                precision=precision,
                recall=recall,
                f1=f1,
            )
        )

    # Aggregate micro-averaged metrics
    total_tp = sum(technique_tp.values())
    total_fp = sum(technique_fp.values())
    total_fn = sum(technique_fn.values())

    agg_precision = _compute_precision(total_tp, total_fp)
    agg_recall = _compute_recall(total_tp, total_fn)
    agg_f1 = _compute_f1(agg_precision, agg_recall)

    return per_technique, agg_precision, agg_recall, agg_f1
