"""Tests for eval harness report generation and filtering.

Covers:
- Full report generation with valid data
- Filtering by scenario_id, technique, payload_family
- Missing required fields → skipped_records
- Empty inputs produce warning
- Report JSON output matches expected schema
"""

from __future__ import annotations

import json

import pytest

from eval.harness import PredictionRecord, TechniqueMetrics
from eval.report import EvalReport, SkippedRecord, generate_report
from orchestrator.interfaces import GroundTruthLabel, GroundTruthRecord


def _make_gt(
    scenario_id: str = "scenario-1",
    technique: str | None = "T1046",
    timestamp: str = "2024-01-15T10:00:00+00:00",
    payload_family: str = "recon",
) -> GroundTruthRecord:
    """Create a GroundTruthRecord for testing."""
    return GroundTruthRecord(
        scenario_id=scenario_id,
        run_id="run-1",
        timestamp=timestamp,
        target="juice-shop.lab.local",
        payload_family=payload_family,
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


class TestFullReportGeneration:
    """Test full report generation with valid data."""

    def test_report_with_matching_records(self):
        gt = [
            _make_gt(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:00:00+00:00"),
            _make_gt(scenario_id="s2", technique="T1059", timestamp="2024-01-15T10:05:00+00:00"),
        ]
        preds = [
            _make_pred(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:01:00+00:00"),
            _make_pred(scenario_id="s2", technique="T1059", timestamp="2024-01-15T10:06:00+00:00"),
        ]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
            time_window_seconds=300,
        )

        assert report.model_name == "soc-model"
        assert report.model_version == "1.0.0"
        assert report.time_window_seconds == 300
        assert report.total_ground_truth == 2
        assert report.total_predictions == 2
        assert report.aggregate_precision == 1.0
        assert report.aggregate_recall == 1.0
        assert report.aggregate_f1 == 1.0
        assert report.warning is None
        assert report.skipped_records == []
        assert report.duplicates_excluded == 0
        assert len(report.per_technique) == 2

    def test_report_with_partial_matches(self):
        gt = [
            _make_gt(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:00:00+00:00"),
            _make_gt(scenario_id="s2", technique="T1059", timestamp="2024-01-15T10:05:00+00:00"),
        ]
        preds = [
            _make_pred(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:01:00+00:00"),
            # No prediction for s2/T1059
        ]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
        )

        assert report.total_ground_truth == 2
        assert report.total_predictions == 1
        assert report.aggregate_precision == 1.0  # 1 TP, 0 FP
        assert report.aggregate_recall == pytest.approx(0.5)  # 1 TP, 1 FN
        assert report.warning is None

    def test_report_with_duplicates(self):
        gt = [_make_gt(timestamp="2024-01-15T10:00:00+00:00")]
        preds = [
            _make_pred(timestamp="2024-01-15T10:00:30+00:00"),
            _make_pred(timestamp="2024-01-15T10:01:00+00:00"),
            _make_pred(timestamp="2024-01-15T10:02:00+00:00"),
        ]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
        )

        assert report.total_ground_truth == 1
        assert report.total_predictions == 3
        assert report.duplicates_excluded == 2


class TestFilterByScenarioId:
    """Test filtering by scenario_id."""

    def test_scenario_filter_includes_matching_records(self):
        gt = [
            _make_gt(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:00:00+00:00"),
            _make_gt(scenario_id="s2", technique="T1059", timestamp="2024-01-15T10:05:00+00:00"),
        ]
        preds = [
            _make_pred(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:01:00+00:00"),
            _make_pred(scenario_id="s2", technique="T1059", timestamp="2024-01-15T10:06:00+00:00"),
        ]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
            scenario_filter="s1",
        )

        assert report.total_ground_truth == 1
        assert report.total_predictions == 1
        assert report.aggregate_precision == 1.0
        assert report.aggregate_recall == 1.0

    def test_scenario_filter_no_match_produces_warning(self):
        gt = [_make_gt(scenario_id="s1")]
        preds = [_make_pred(scenario_id="s1")]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
            scenario_filter="nonexistent",
        )

        assert report.total_ground_truth == 0
        assert report.total_predictions == 0
        assert report.warning is not None


class TestFilterByTechnique:
    """Test filtering by technique."""

    def test_technique_filter_includes_matching_records(self):
        gt = [
            _make_gt(
                scenario_id="s1",
                technique="T1046",
                timestamp="2024-01-15T10:00:00+00:00",
            ),
            _make_gt(
                scenario_id="s2",
                technique="T1059",
                timestamp="2024-01-15T10:05:00+00:00",
            ),
        ]
        preds = [
            _make_pred(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:01:00+00:00"),
            _make_pred(scenario_id="s2", technique="T1059", timestamp="2024-01-15T10:06:00+00:00"),
        ]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
            technique_filter="T1046",
        )

        assert report.total_ground_truth == 1
        assert report.total_predictions == 1
        assert len(report.per_technique) == 1
        assert report.per_technique[0].technique == "T1046"

    def test_technique_filter_excludes_non_matching(self):
        gt = [_make_gt(technique="T1046")]
        preds = [_make_pred(technique="T1046")]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
            technique_filter="T9999",
        )

        assert report.total_ground_truth == 0
        assert report.total_predictions == 0
        assert report.warning is not None


class TestFilterByPayloadFamily:
    """Test filtering by payload_family."""

    def test_payload_family_filter_includes_matching_gt(self):
        gt = [
            _make_gt(
                scenario_id="s1",
                payload_family="recon",
                timestamp="2024-01-15T10:00:00+00:00",
            ),
            _make_gt(
                scenario_id="s2",
                payload_family="sqli",
                timestamp="2024-01-15T10:05:00+00:00",
            ),
        ]
        preds = [
            _make_pred(scenario_id="s1", timestamp="2024-01-15T10:01:00+00:00"),
            _make_pred(scenario_id="s2", timestamp="2024-01-15T10:06:00+00:00"),
        ]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
            payload_family_filter="recon",
        )

        # Only s1 GT passes filter; both predictions still present
        assert report.total_ground_truth == 1
        assert report.total_predictions == 2

    def test_payload_family_filter_no_match(self):
        gt = [_make_gt(payload_family="recon")]
        preds = [_make_pred()]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
            payload_family_filter="xss",
        )

        # GT filtered out, predictions remain
        assert report.total_ground_truth == 0
        assert report.warning is not None


class TestMissingRequiredFields:
    """Test records with missing required fields → skipped_records."""

    def test_gt_missing_scenario_id_is_skipped(self):
        gt_valid = _make_gt(scenario_id="s1", timestamp="2024-01-15T10:00:00+00:00")
        gt_invalid = GroundTruthRecord(
            scenario_id="",  # Empty = missing
            run_id="run-1",
            timestamp="2024-01-15T10:05:00+00:00",
            target="target",
            payload_family="recon",
            technique="T1046",
            expected_result="test",
            safety_boundary="lab",
            label=GroundTruthLabel.MALICIOUS,
            artifact_reference="/tmp/a",
        )
        preds = [_make_pred(scenario_id="s1", timestamp="2024-01-15T10:01:00+00:00")]

        report = generate_report(
            ground_truth=[gt_valid, gt_invalid],
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
        )

        assert report.total_ground_truth == 1  # Only valid GT counted
        assert len(report.skipped_records) == 1
        assert report.skipped_records[0].record_type == "ground_truth"
        assert "scenario_id" in report.skipped_records[0].reason

    def test_gt_missing_timestamp_is_skipped(self):
        gt_invalid = GroundTruthRecord(
            scenario_id="s1",
            run_id="run-1",
            timestamp="",  # Empty = missing
            target="target",
            payload_family="recon",
            technique="T1046",
            expected_result="test",
            safety_boundary="lab",
            label=GroundTruthLabel.MALICIOUS,
            artifact_reference="/tmp/a",
        )

        report = generate_report(
            ground_truth=[gt_invalid],
            predictions=[],
            model_name="soc-model",
            model_version="1.0.0",
        )

        assert len(report.skipped_records) == 1
        assert "timestamp" in report.skipped_records[0].reason

    def test_prediction_missing_technique_is_skipped(self):
        pred_invalid = PredictionRecord(
            scenario_id="s1",
            technique="",  # Empty = missing
            timestamp="2024-01-15T10:01:00+00:00",
            model_name="soc-model",
            model_version="1.0.0",
        )
        gt = [_make_gt(timestamp="2024-01-15T10:00:00+00:00")]

        report = generate_report(
            ground_truth=gt,
            predictions=[pred_invalid],
            model_name="soc-model",
            model_version="1.0.0",
        )

        assert len(report.skipped_records) == 1
        assert report.skipped_records[0].record_type == "prediction"
        assert "technique" in report.skipped_records[0].reason
        # GT with no valid predictions → warning
        assert report.warning is not None

    def test_prediction_missing_scenario_id_is_skipped(self):
        pred_invalid = PredictionRecord(
            scenario_id="",  # Empty = missing
            technique="T1046",
            timestamp="2024-01-15T10:01:00+00:00",
            model_name="soc-model",
            model_version="1.0.0",
        )

        report = generate_report(
            ground_truth=[_make_gt(timestamp="2024-01-15T10:00:00+00:00")],
            predictions=[pred_invalid],
            model_name="soc-model",
            model_version="1.0.0",
        )

        assert len(report.skipped_records) == 1
        assert report.skipped_records[0].record_type == "prediction"
        assert "scenario_id" in report.skipped_records[0].reason

    def test_multiple_invalid_records_all_skipped(self):
        gt_invalid = GroundTruthRecord(
            scenario_id="",
            run_id="run-1",
            timestamp="2024-01-15T10:00:00+00:00",
            target="target",
            payload_family="recon",
            technique="T1046",
            expected_result="test",
            safety_boundary="lab",
            label=GroundTruthLabel.MALICIOUS,
            artifact_reference="/tmp/a",
        )
        pred_invalid = PredictionRecord(
            scenario_id="",
            technique="T1046",
            timestamp="2024-01-15T10:01:00+00:00",
            model_name="soc-model",
            model_version="1.0.0",
        )

        report = generate_report(
            ground_truth=[gt_invalid],
            predictions=[pred_invalid],
            model_name="soc-model",
            model_version="1.0.0",
        )

        assert len(report.skipped_records) == 2
        assert report.warning is not None  # Both sets empty after skipping

    def test_skipped_records_contain_partial_data(self):
        gt_invalid = GroundTruthRecord(
            scenario_id="",
            run_id="run-1",
            timestamp="2024-01-15T10:00:00+00:00",
            target="juice-shop",
            payload_family="sqli",
            technique="T1046",
            expected_result="test",
            safety_boundary="lab",
            label=GroundTruthLabel.MALICIOUS,
            artifact_reference="/tmp/a",
        )

        report = generate_report(
            ground_truth=[gt_invalid],
            predictions=[],
            model_name="soc-model",
            model_version="1.0.0",
        )

        skipped = report.skipped_records[0]
        assert skipped.partial_data["timestamp"] == "2024-01-15T10:00:00+00:00"
        assert skipped.partial_data["technique"] == "T1046"
        assert skipped.partial_data["payload_family"] == "sqli"


class TestEmptyInputsWarning:
    """Test empty inputs produce warning with all metrics = 0."""

    def test_both_empty(self):
        report = generate_report(
            ground_truth=[],
            predictions=[],
            model_name="soc-model",
            model_version="1.0.0",
        )

        assert report.total_ground_truth == 0
        assert report.total_predictions == 0
        assert report.aggregate_precision == 0.0
        assert report.aggregate_recall == 0.0
        assert report.aggregate_f1 == 0.0
        assert report.warning is not None
        assert "empty" in report.warning.lower()

    def test_empty_gt_with_predictions(self):
        preds = [_make_pred()]

        report = generate_report(
            ground_truth=[],
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
        )

        assert report.total_ground_truth == 0
        assert report.total_predictions == 1
        assert report.aggregate_precision == 0.0
        assert report.aggregate_recall == 0.0
        assert report.aggregate_f1 == 0.0
        assert report.warning is not None
        assert "ground-truth" in report.warning.lower()

    def test_gt_with_empty_predictions(self):
        gt = [_make_gt()]

        report = generate_report(
            ground_truth=gt,
            predictions=[],
            model_name="soc-model",
            model_version="1.0.0",
        )

        assert report.total_ground_truth == 1
        assert report.total_predictions == 0
        assert report.aggregate_precision == 0.0
        assert report.aggregate_recall == 0.0
        assert report.aggregate_f1 == 0.0
        assert report.warning is not None
        assert "prediction" in report.warning.lower()


class TestReportJsonOutput:
    """Test report JSON output matches expected schema."""

    def test_to_dict_structure(self):
        gt = [_make_gt(timestamp="2024-01-15T10:00:00+00:00")]
        preds = [_make_pred(timestamp="2024-01-15T10:01:00+00:00")]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
            time_window_seconds=300,
        )

        d = report.to_dict()

        # Required top-level fields
        assert d["model_name"] == "soc-model"
        assert d["model_version"] == "1.0.0"
        assert d["time_window_seconds"] == 300
        assert d["total_ground_truth"] == 1
        assert d["total_predictions"] == 1
        assert isinstance(d["per_technique"], list)
        assert isinstance(d["aggregate_precision"], float)
        assert isinstance(d["aggregate_recall"], float)
        assert isinstance(d["aggregate_f1"], float)
        assert isinstance(d["skipped_records"], list)
        assert "warning" in d
        assert "duplicates_excluded" in d

    def test_to_json_is_valid_json(self):
        report = generate_report(
            ground_truth=[_make_gt(timestamp="2024-01-15T10:00:00+00:00")],
            predictions=[_make_pred(timestamp="2024-01-15T10:01:00+00:00")],
            model_name="soc-model",
            model_version="1.0.0",
        )

        json_str = report.to_json()
        parsed = json.loads(json_str)

        assert parsed["model_name"] == "soc-model"
        assert parsed["model_version"] == "1.0.0"

    def test_to_json_per_technique_structure(self):
        gt = [_make_gt(timestamp="2024-01-15T10:00:00+00:00")]
        preds = [_make_pred(timestamp="2024-01-15T10:01:00+00:00")]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
        )

        json_str = report.to_json()
        parsed = json.loads(json_str)

        assert len(parsed["per_technique"]) == 1
        technique_entry = parsed["per_technique"][0]
        assert "technique" in technique_entry
        assert "true_positives" in technique_entry
        assert "false_positives" in technique_entry
        assert "false_negatives" in technique_entry
        assert "precision" in technique_entry
        assert "recall" in technique_entry
        assert "f1" in technique_entry

    def test_to_json_skipped_records_structure(self):
        gt_invalid = GroundTruthRecord(
            scenario_id="",
            run_id="run-1",
            timestamp="2024-01-15T10:00:00+00:00",
            target="target",
            payload_family="recon",
            technique="T1046",
            expected_result="test",
            safety_boundary="lab",
            label=GroundTruthLabel.MALICIOUS,
            artifact_reference="/tmp/a",
        )

        report = generate_report(
            ground_truth=[gt_invalid],
            predictions=[],
            model_name="soc-model",
            model_version="1.0.0",
        )

        json_str = report.to_json()
        parsed = json.loads(json_str)

        assert len(parsed["skipped_records"]) == 1
        skipped = parsed["skipped_records"][0]
        assert "record_type" in skipped
        assert "reason" in skipped
        assert "partial_data" in skipped

    def test_to_dict_roundtrip_no_data_loss(self):
        """to_dict() followed by manual inspection shows all fields preserved."""
        gt = [
            _make_gt(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:00:00+00:00"),
        ]
        preds = [
            _make_pred(scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:01:00+00:00"),
        ]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="test-model",
            model_version="2.5.0",
            time_window_seconds=600,
        )

        d = report.to_dict()

        assert d["model_name"] == report.model_name
        assert d["model_version"] == report.model_version
        assert d["time_window_seconds"] == report.time_window_seconds
        assert d["total_ground_truth"] == report.total_ground_truth
        assert d["total_predictions"] == report.total_predictions
        assert d["aggregate_precision"] == report.aggregate_precision
        assert d["aggregate_recall"] == report.aggregate_recall
        assert d["aggregate_f1"] == report.aggregate_f1
        assert d["duplicates_excluded"] == report.duplicates_excluded
        assert d["warning"] == report.warning


class TestCombinedFilters:
    """Test combining multiple filters."""

    def test_scenario_and_technique_filter_combined(self):
        gt = [
            _make_gt(
                scenario_id="s1",
                technique="T1046",
                timestamp="2024-01-15T10:00:00+00:00",
            ),
            _make_gt(
                scenario_id="s1",
                technique="T1059",
                timestamp="2024-01-15T10:05:00+00:00",
            ),
            _make_gt(
                scenario_id="s2",
                technique="T1046",
                timestamp="2024-01-15T10:10:00+00:00",
            ),
        ]
        preds = [
            _make_pred(
                scenario_id="s1", technique="T1046", timestamp="2024-01-15T10:01:00+00:00"
            ),
            _make_pred(
                scenario_id="s1", technique="T1059", timestamp="2024-01-15T10:06:00+00:00"
            ),
            _make_pred(
                scenario_id="s2", technique="T1046", timestamp="2024-01-15T10:11:00+00:00"
            ),
        ]

        report = generate_report(
            ground_truth=gt,
            predictions=preds,
            model_name="soc-model",
            model_version="1.0.0",
            scenario_filter="s1",
            technique_filter="T1046",
        )

        # Only s1 + T1046 should pass both filters
        assert report.total_ground_truth == 1
        assert report.total_predictions == 1
        assert report.aggregate_precision == 1.0
        assert report.aggregate_recall == 1.0
