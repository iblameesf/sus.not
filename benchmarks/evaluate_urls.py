"""Offline synthetic URL benchmark. Run: python -m benchmarks.evaluate_urls."""

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.main import AnalyzeURLRequest, analyze_url

DATASET_PATH = Path(__file__).with_name("url_cases.json")
RESULTS_PATH = Path(__file__).with_name("results") / "url_evaluation.json"
WARNING_THRESHOLD = 60


class URLCase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1)
    url: str
    expected_label: Literal["benign", "suspicious"]
    rationale: str = Field(min_length=1)

    @field_validator("id", "rationale")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Must not be blank")
        return value

    @field_validator("url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        return AnalyzeURLRequest(url=value).url


def load_cases(path: Path = DATASET_PATH) -> list[URLCase]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or len(raw) < 30:
        raise ValueError("Dataset must be a list with at least 30 cases")
    cases = [URLCase.model_validate(case) for case in raw]
    if len({case.id for case in cases}) != len(cases):
        raise ValueError("Case IDs must be unique")
    return cases


def calculate_metrics(*, tp: int, tn: int, fp: int, fn: int) -> dict:
    if any(type(count) is not int or count < 0 for count in (tp, tn, fp, fn)):
        raise ValueError("Confusion counts must be nonnegative integers")

    def divide(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0

    return {
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": divide(tp, tp + fp),
        "recall": divide(tp, tp + fn),
        "f1_score": divide(2 * tp, 2 * tp + fp + fn),
        "accuracy": divide(tp + tn, tp + tn + fp + fn),
    }


def evaluate_cases(cases: list[URLCase]) -> dict:
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    rows = []
    for case in cases:
        result = analyze_url(AnalyzeURLRequest(url=case.url))
        predicted = "suspicious" if result.sus_score >= WARNING_THRESHOLD else "benign"
        positive = case.expected_label == "suspicious"
        outcome = ("tp" if positive else "fp") if predicted == "suspicious" else ("fn" if positive else "tn")
        counts[outcome] += 1
        rows.append({
            **case.model_dump(),
            "sus_score": result.sus_score,
            "risk_level": result.risk_level,
            "indicators": result.indicators,
            "predicted_label": predicted,
            "outcome": outcome,
        })
    # Hash normalized validated data, not formatting, for stable dataset identity.
    canonical = json.dumps([case.model_dump() for case in cases], sort_keys=True, ensure_ascii=True)
    return {
        "evaluation_version": "1",
        "dataset_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "warning_threshold": WARNING_THRESHOLD,
        "dataset_size": len(cases),
        "label_caveat": "Synthetic scenario labels, not verified fraud or real-world accuracy.",
        "metrics": calculate_metrics(**counts),
        "cases": rows,
        "misclassified_cases": [row for row in rows if row["outcome"] in {"fp", "fn"}],
    }


def serialize_report(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def print_report(report: dict) -> None:
    metrics = report["metrics"]
    print(f"Synthetic URL evaluation: {report['dataset_size']} cases; warning threshold >= {WARNING_THRESHOLD}")
    print("Actual \\ Predicted       suspicious    benign")
    print(f"suspicious (TP / FN)     {metrics['true_positives']:10d} {metrics['false_negatives']:9d}")
    print(f"benign     (FP / TN)     {metrics['false_positives']:10d} {metrics['true_negatives']:9d}")
    for name in ("precision", "recall", "f1_score", "accuracy"):
        print(f"{name}: {metrics[name]:.4f}")
    print("Misclassified cases:")
    for row in report["misclassified_cases"]:
        print(f"  {row['id']} [{row['outcome'].upper()}] score={row['sus_score']} {row['url']}")
        print(f"    {row['rationale']}")
    if not report["misclassified_cases"]:
        print("  None")
    print(report["label_caveat"])


def main() -> None:
    report = evaluate_cases(load_cases())
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(serialize_report(report), encoding="utf-8")
    print_report(report)
    print(f"Saved: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
