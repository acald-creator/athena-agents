"""Tests for eval harness matching algorithm and metrics computation.

Covers:
- Exact match (GT + prediction with same scenario_id + technique within window) -> TP
- No matching prediction -> FN
- Prediction without matching GT -> FP
- Multiple predictions for one GT -> earliest is TP, others excluded as duplicates
- Time window filtering (out of window -> no match)
- Per-technique metrics computed correctly
- Aggregate micro-averaged metrics
- Empty inputs return all zeros
"""

from __future__ import annotations

import pytest

from eval.harness import (
    MatchResult,
    PredictionRecord,
    TechniqueMetrics,
    compute_metrics,
    match_records,
)
from orchestrator.interfaces import GroundTruthLabel, GroundTruthRecord


def _make_gt(
    scenario_id: str = "scenario-1",
    technique: str | None = "T1046",
    timestamp: str = "2024-01-15T10:00:00+00:00",
) -> GroundTruthRecord:
    """Create a GroundTruthRecord for testing."""
    return GroundTruthRecord(
        scenario_id=scenario_id,
        run_id="run-1",
        timestamp=timestamp,
        target="juice-shop.lab.local",
        payload_family="recon",
        technique=technique,
        expected_result="port discovery",
        safety_boundary="lab-network",
        label=GroundTruthLabel.MALICIOUS,
        artifact_reference="/tmp/artifacts/1.json",
    )


def _make_pred(
    scenario_id: str = "scenario-1",
    technique: str = "T1046",
    timestamp: str = "2024-01-15T10:01:00+00:00",
    model_name: str = "soc-model",
    model_version: str = "1.0.0",
    confidence: float | None = 0.95,
) -> PredictionRecord:
    """Create a PredictionRecord for testing."""
    return PredictionRecord(
        scenario_id=scenario_id,
        technique=technique,
        timestamp=timestamp,
        model_name=model_name,
        model_version=model_version,
        confidence=confidence,
    )


class TestMatchRecordsExactMatch:
    """Test exact matching: GT and prediction with same scenario_id + technique within window."""

    def test_single_exact_match_is_true_positive(self):
        gt = [_make_gt()]
        preds = [_make_pred()]

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 1
        assert len(result.false_negatives) == 0
        assert len(result.false_positives) == 0
        assert result.true_positives[0].ground_truth == gt[0]
        assert result.true_positives[0].prediction == preds[0]

    def test_match_with_z_suffix_timestamps(self):
        gt = [_make_gt(timestamp="2024-01-15T10:00:00Z")]
        preds = [_make_pred(timestamp="2024-01-15T10:01:00Z")]

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 1
        assert len(result.false_negatives) == 0
        assert len(result.false_positives) == 0

    def test_match_at_boundary_of_time_window(self):
        """Prediction exactly at the time window boundary should match."""
        gt = [_make_gt(timestamp="2024-01-15T10:00:00+00:00")]
        # Exactly 300 seconds later
        preds = [_make_pred(timestamp="2024-01-15T10:05:00+00:00")]

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 1


class TestMatchRecordsFalseNegative:
    """Test no matching prediction -> FN."""

    def test_gt_without_any_prediction(self):
        gt = [_make_gt()]
        preds: list[PredictionRecord] = []

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 1
        assert result.false_negatives[0] == gt[0]

    def test_gt_with_mismatched_scenario_id(self):
        gt = [_make_gt(scenario_id="scenario-1")]
        preds = [_make_pred(scenario_id="scenario-2")]

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 1
        assert len(result.false_positives) == 1

    def test_gt_with_mismatched_technique(self):
        gt = [_make_gt(technique="T1046")]
        preds = [_make_pred(technique="T1059")]

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 1
        assert len(result.false_positives) == 1


class TestMatchRecordsFalsePositive:
    """Test prediction without matching GT -> FP."""

    def test_prediction_without_gt(self):
        gt: list = []
        preds = [_make_pred()]

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 0
        assert len(result.false_positives) == 1
        assert result.false_positives[0] == preds[0]

    def test_extra_predictions_beyond_gt(self):
        gt = [_make_gt()]
        preds = [
            _make_pred(timestamp="2024-01-15T10:01:00+00:00"),
            _make_pred(scenario_id="scenario-999", timestamp="2024-01-15T10:02:00+00:00"),
        ]

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 1
        assert len(result.false_positives) == 1
        assert result.false_positives[0].scenario_id == "scenario-999"


class TestMatchRecordsDuplicates:
    """Test multiple predictions for one GT -> earliest is TP, others are duplicates."""

    def test_earliest_prediction_wins(self):
        gt = [_make_gt(timestamp="2024-01-15T10:00:00+00:00")]
        preds = [
            _make_pred(timestamp="2024-01-15T10:03:00+00:00"),  # Later
            _make_pred(timestamp="2024-01-15T10:01:00+00:00"),  # Earlier — should win
            _make_pred(timestamp="2024-01-15T10:02:00+00:00"),  # Middle
        ]

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 1
        # The earliest prediction (10:01:00) should be the match
        assert result.true_positives[0].prediction.timestamp == "2024-01-15T10:01:00+00:00"
        # The other two should be in false_positives (one as duplicate)
        assert result.duplicates_excluded >= 1

    def test_duplicates_counted_correctly(self):
        gt = [_make_gt(timestamp="2024-01-15T10:00:00+00:00")]
        # Three predictions match the same GT, only earliest should be TP
        preds = [
            _make_pred(timestamp="2024-01-15T10:00:30+00:00"),  # Earliest — wins
            _make_pred(timestamp="2024-01-15T10:01:00+00:00"),  # Duplicate
            _make_pred(timestamp="2024-01-15T10:02:00+00:00"),  # Duplicate
        ]

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 1
        assert result.duplicates_excluded == 2
        # The two non-matched predictions appear in false_positives list
        assert len(result.false_positives) == 2


class TestMatchRecordsTimeWindow:
    """Test time window filtering (out of window -> no match)."""

    def test_prediction_outside_window_not_matched(self):
        gt = [_make_gt(timestamp="2024-01-15T10:00:00+00:00")]
        # 301 seconds later — just outside default 300s window
        preds = [_make_pred(timestamp="2024-01-15T10:05:01+00:00")]

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 1
        assert len(result.false_positives) == 1

    def test_prediction_before_gt_within_window(self):
        """Prediction before GT within window should match (absolute difference)."""
        gt = [_make_gt(timestamp="2024-01-15T10:05:00+00:00")]
        preds = [_make_pred(timestamp="2024-01-15T10:02:00+00:00")]  # 3 min before

        result = match_records(gt, preds, time_window_seconds=300)

        assert len(result.true_positives) == 1

    def test_custom_time_window_narrow(self):
        gt = [_make_gt(timestamp="2024-01-15T10:00:00+00:00")]
        # 61 seconds later
        preds = [_make_pred(timestamp="2024-01-15T10:01:01+00:00")]

        # With a 60-second window, this should NOT match
        result = match_records(gt, preds, time_window_seconds=60)

        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 1

    def test_custom_time_window_wide(self):
        gt = [_make_gt(timestamp="2024-01-15T10:00:00+00:00")]
        # 1 hour later
        preds = [_make_pred(timestamp="2024-01-15T11:00:00+00:00")]

        # With a 3600-second (1 hour) window, this should match
        result = match_records(gt, preds, time_window_seconds=3600)

        assert len(result.true_positives) == 1

    def test_invalid_time_window_below_minimum(self):
        with pytest.raises(ValueError, match="time_window_seconds must be between 1 and 86400"):
            match_records([], [], time_window_seconds=0)

    def test_invalid_time_window_above_maximum(self):
        with pytest.raises(ValueError, match="time_window_seconds must be between 1 and 86400"):
            match_records([], [], time_window_seconds=86401)


class TestComputeMetricsPerTechnique:
    """Test per-technique metrics computation."""

    def test_single_technique_all_tp(self):
        gt = [
            _make_gt(technique="T1046", timestamp="2024-01-15T10:00:00+00:00"),
            _make_gt(technique="T1046", timestamp="2024-01-15T10:10:00+00:00", scenario_id="s2"),
        ]
        preds = [
            _make_pred(technique="T1046", timestamp="2024-01-15T10:01:00+00:00"),
            _make_pred(
                technique="T1046", timestamp="2024-01-15T10:11:00+00:00", scenario_id="s2"
            ),
        ]

        result = match_records(gt, preds, time_window_seconds=300)
        per_technique, _, _, _ = compute_metrics(result)

        assert len(per_technique) == 1
        t1046 = per_technique[0]
        assert t1046.technique == "T1046"
        assert t1046.true_positives == 2
        assert t1046.false_positives == 0
        assert t1046.false_negatives == 0
        assert t1046.precision == 1.0
        assert t1046.recall == 1.0
        assert t1046.f1 == 1.0

    def test_multiple_techniques(self):
        gt = [
            _make_gt(technique="T1046", scenario_id="s1", timestamp="2024-01-15T10:00:00+00:00"),
            _make_gt(technique="T1059", scenario_id="s2", timestamp="2024-01-15T10:05:00+00:00"),
        ]
        preds = [
            _make_pred(technique="T1046", scenario_id="s1", timestamp="2024-01-15T10:01:00+00:00"),
            # No prediction for T1059 -> FN
        ]

        result = match_records(gt, preds, time_window_seconds=300)
        per_technique, _, _, _ = compute_metrics(result)

        # Should have metrics for both techniques
        techniques = {m.technique: m for m in per_technique}
        assert "T1046" in techniques
        assert "T1059" in techniques

        assert techniques["T1046"].true_positives == 1
        assert techniques["T1046"].precision == 1.0
        assert techniques["T1046"].recall == 1.0

        assert techniques["T1059"].true_positives == 0
        assert techniques["T1059"].false_negatives == 1
        assert techniques["T1059"].precision == 0.0
        assert techniques["T1059"].recall == 0.0
        assert techniques["T1059"].f1 == 0.0

    def test_technique_with_mixed_tp_fp_fn(self):
        # 2 GT for T1046, 3 predictions for T1046 (one matches, two don't match any GT)
        gt = [
            _make_gt(technique="T1046", scenario_id="s1", timestamp="2024-01-15T10:00:00+00:00"),
            _make_gt(technique="T1046", scenario_id="s2", timestamp="2024-01-15T10:10:00+00:00"),
        ]
        preds = [
            _make_pred(
                technique="T1046", scenario_id="s1", timestamp="2024-01-15T10:01:00+00:00"
            ),
            # This matches s2 - but wrong scenario_id -> FP
            _make_pred(
                technique="T1046", scenario_id="s3", timestamp="2024-01-15T10:11:00+00:00"
            ),
        ]

        result = match_records(gt, preds, time_window_seconds=300)
        per_technique, _, _, _ = compute_metrics(result)

        techniques = {m.technique: m for m in per_technique}
        t1046 = techniques["T1046"]
        # 1 TP (s1 matched), 1 FN (s2 unmatched), 1 FP (s3 prediction)
        assert t1046.true_positives == 1
        assert t1046.false_negatives == 1
        assert t1046.false_positives == 1
        assert t1046.precision == pytest.approx(0.5)
        assert t1046.recall == pytest.approx(0.5)
        # F1 = 2 * 0.5 * 0.5 / (0.5 + 0.5) = 0.5
        assert t1046.f1 == pytest.approx(0.5)


class TestComputeMetricsAggregate:
    """Test aggregate micro-averaged metrics."""

    def test_micro_average_across_techniques(self):
        # T1046: 2 TP, 0 FP, 0 FN -> P=1.0, R=1.0
        # T1059: 0 TP, 1 FP, 1 FN -> P=0.0, R=0.0
        gt = [
            _make_gt(technique="T1046", scenario_id="s1", timestamp="2024-01-15T10:00:00+00:00"),
            _make_gt(technique="T1046", scenario_id="s2", timestamp="2024-01-15T10:05:00+00:00"),
            _make_gt(technique="T1059", scenario_id="s3", timestamp="2024-01-15T10:10:00+00:00"),
        ]
        preds = [
            _make_pred(
                technique="T1046", scenario_id="s1", timestamp="2024-01-15T10:01:00+00:00"
            ),
            _make_pred(
                technique="T1046", scenario_id="s2", timestamp="2024-01-15T10:06:00+00:00"
            ),
            # Prediction for T1059 but wrong scenario_id
            _make_pred(
                technique="T1059", scenario_id="s4", timestamp="2024-01-15T10:11:00+00:00"
            ),
        ]

        result = match_records(gt, preds, time_window_seconds=300)
        _, agg_p, agg_r, agg_f1 = compute_metrics(result)

        # Micro-averaged: total TP=2, total FP=1, total FN=1
        # Precision = 2/(2+1) = 2/3
        # Recall = 2/(2+1) = 2/3
        # F1 = 2 * (2/3) * (2/3) / (2/3 + 2/3) = 2/3
        assert agg_p == pytest.approx(2 / 3)
        assert agg_r == pytest.approx(2 / 3)
        assert agg_f1 == pytest.approx(2 / 3)

    def test_perfect_score(self):
        gt = [_make_gt()]
        preds = [_make_pred()]

        result = match_records(gt, preds, time_window_seconds=300)
        _, agg_p, agg_r, agg_f1 = compute_metrics(result)

        assert agg_p == 1.0
        assert agg_r == 1.0
        assert agg_f1 == 1.0


class TestEmptyInputs:
    """Test empty inputs return all zeros."""

    def test_empty_gt_and_empty_predictions(self):
        result = match_records([], [], time_window_seconds=300)
        per_technique, agg_p, agg_r, agg_f1 = compute_metrics(result)

        assert per_technique == []
        assert agg_p == 0.0
        assert agg_r == 0.0
        assert agg_f1 == 0.0

    def test_empty_gt_with_predictions(self):
        preds = [_make_pred()]
        result = match_records([], preds, time_window_seconds=300)

        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 0
        assert len(result.false_positives) == 1

        per_technique, agg_p, agg_r, agg_f1 = compute_metrics(result)
        # With 0 TP, 1 FP: precision = 0/1 = 0, recall = 0/0 = 0, F1 = 0
        assert agg_p == 0.0
        assert agg_r == 0.0
        assert agg_f1 == 0.0

    def test_gt_with_empty_predictions(self):
        gt = [_make_gt()]
        result = match_records(gt, [], time_window_seconds=300)

        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 1
        assert len(result.false_positives) == 0

        per_technique, agg_p, agg_r, agg_f1 = compute_metrics(result)
        # With 0 TP, 0 FP, 1 FN: precision = 0/0 = 0, recall = 0/1 = 0, F1 = 0
        assert agg_p == 0.0
        assert agg_r == 0.0
        assert agg_f1 == 0.0


class TestMatchRecordsOneToOne:
    """Test one-to-one matching: each prediction can only match one GT."""

    def test_one_prediction_cannot_match_two_gt(self):
        """With 2 GT records and 1 prediction that matches both,
        only one GT gets matched (the first processed GT gets the prediction)."""
        gt = [
            _make_gt(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:00:00+00:00"),
            _make_gt(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:00:30+00:00"),
        ]
        preds = [
            _make_pred(
                scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:00:15+00:00"
            ),
        ]

        result = match_records(gt, preds, time_window_seconds=300)

        # Only one TP possible since there's only one prediction
        assert len(result.true_positives) == 1
        assert len(result.false_negatives) == 1
