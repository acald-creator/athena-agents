"""CLI: correlate ground-truth JSONL with ai-inference triage predictions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

from eval.report import generate_report
from eval.triage_adapter import load_predictions_jsonl, triage_to_prediction
from orchestrator.ground_truth import deserialize_record


def load_ground_truth(path: Path) -> list:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(deserialize_record(line))
    return records


def fetch_predictions(base_url: str, limit: int) -> list:
    url = base_url.rstrip("/") + "/v1/triage/recent"
    response = httpx.get(url, params={"limit": limit}, timeout=30.0)
    response.raise_for_status()
    body = response.json()
    items = body.get("results") if isinstance(body, dict) else body
    if not isinstance(items, list):
        return []
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        pred = triage_to_prediction(item)
        if pred is not None:
            out.append(pred)
    return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="purple-eval",
        description="Purple-team eval: match Athena ground-truth JSONL to SOC triage predictions",
    )
    parser.add_argument(
        "--gt",
        default=None,
        help="Ground-truth JSONL path (default: ATHENA_GT_OUTPUT env or stdin path required)",
    )
    parser.add_argument(
        "--inference-url",
        default=None,
        help="ai-inference base URL (default: ATHENA_INFERENCE_URL or http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--predictions-jsonl",
        default=None,
        help="Optional offline triage JSONL instead of live inference fetch",
    )
    parser.add_argument("--limit", type=int, default=500, help="Max triage records to fetch")
    parser.add_argument("--time-window", type=int, default=300, help="Match window in seconds")
    parser.add_argument("--scenario", default=None, help="Filter to scenario_id")
    parser.add_argument("--technique", default=None, help="Filter to MITRE technique")
    parser.add_argument("--output", default="-", help="Report path or '-' for stdout")
    return parser.parse_args()


def main() -> int:
    import os

    args = parse_args()
    gt_path = Path(args.gt or os.environ.get("ATHENA_GT_OUTPUT", ""))
    if not gt_path.is_file():
        print(f"ground-truth file not found: {gt_path}", file=sys.stderr)
        return 2

    ground_truth = load_ground_truth(gt_path)
    if args.predictions_jsonl:
        predictions = load_predictions_jsonl(args.predictions_jsonl)
        model_name = "offline-export"
        model_version = "jsonl"
    else:
        inference_url = (
            args.inference_url
            or os.environ.get("ATHENA_INFERENCE_URL")
            or "http://127.0.0.1:8000"
        )
        try:
            predictions = fetch_predictions(inference_url, args.limit)
        except httpx.HTTPError as exc:
            print(f"failed to fetch triage predictions: {exc}", file=sys.stderr)
            return 1
        model_name = "nexus-triage-baseline"
        model_version = predictions[0].model_version if predictions else "unknown"

    report = generate_report(
        ground_truth=ground_truth,
        predictions=predictions,
        model_name=model_name,
        model_version=model_version,
        time_window_seconds=args.time_window,
        scenario_filter=args.scenario,
        technique_filter=args.technique,
    )
    text = report.to_json()
    if args.output == "-":
        print(text)
    else:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
