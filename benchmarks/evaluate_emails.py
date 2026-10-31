"""Reproducible offline deterministic email slice; NOT an end-to-end AI benchmark."""

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from backend.email_evidence import correlate, email_advisory, metadata_evidence, url_evidence
from backend.email_parser import EmailInvestigationRequest, parse_email
from backend.main import AnalyzeURLRequest, analyze_url
from backend.orchestration import validate_url_output

DATASET_PATH = Path(__file__).with_name("email_cases.json")
RESULTS_PATH = Path(__file__).with_name("results") / "email_evaluation.json"


class EmailCase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str
    label: Literal["benign", "suspicious", "ambiguous"]
    category: Literal["baseline", "false_positive_candidate", "false_negative_candidate"]
    rationale: str
    input: EmailInvestigationRequest
    expected_advisory: Literal["continue_with_caution", "review_before_proceeding", "show_warning"]


def load_cases(path: Path = DATASET_PATH) -> list[EmailCase]:
    cases = [EmailCase.model_validate(value) for value in json.loads(path.read_text(encoding="utf-8"))]
    if not cases or len({case.id for case in cases}) != len(cases):
        raise ValueError("Unique, nonempty case IDs required")
    return cases


def evaluate_cases(cases: list[EmailCase]) -> dict:
    rows = []
    for case in cases:
        parsed = parse_email(case.input)
        records = metadata_evidence(parsed)
        assessments = []
        for item in parsed.urls:
            result = analyze_url(AnalyzeURLRequest(url=item.value))
            assessment = validate_url_output({
                "sus_score": result.sus_score, "risk_level": result.risk_level,
                "indicators": result.indicators, "explanation": result.message,
            }, item.value)
            url_evidence(records, assessment, item.url_id)
            assessments.append({"url_id": item.url_id, "sus_score": assessment.sus_score,
                                "indicators": assessment.indicators})
        correlations = correlate(records)
        # Offline scope intentionally excludes AI; it is not marked as a runtime tool failure.
        decision = email_advisory(records, correlations, incomplete=bool(parsed.errors))
        rows.append({
            "id": case.id, "label": case.label, "category": case.category, "rationale": case.rationale,
            "expected_advisory": case.expected_advisory, "actual_advisory": decision.action,
            "policy_regression_pass": decision.action == case.expected_advisory,
            "evidence_types": [e.evidence_type for e in records],
            "correlation_rules": [c.rule_id for c in correlations], "url_assessments": assessments,
            "errors": parsed.errors,
        })
    canonical = json.dumps([case.model_dump() for case in cases], sort_keys=True, ensure_ascii=True)
    return {
        "evaluation_version": "email-1", "policy_version": "email-1",
        "dataset_sha256": hashlib.sha256(canonical.encode()).hexdigest(), "dataset_size": len(cases),
        "scope": "Offline parser, metadata, existing URL analyzer, evidence correlation and email advisory policy only.",
        "mcp_status": "not_run; actual SDK transport is covered by integration tests",
        "ai_status": "not_run; no fabricated Qwen findings or end-to-end AI accuracy",
        "label_caveat": "Synthetic scenario labels, not verified fraud or real-world accuracy. Expected advisories are regression targets, not ground truth safety.",
        "policy_regressions_passed": sum(row["policy_regression_pass"] for row in rows),
        "benign_flagged_for_review_or_warning": [row["id"] for row in rows if row["label"] == "benign" and row["actual_advisory"] != "continue_with_caution"],
        "suspicious_without_deterministic_indicators": [row["id"] for row in rows if row["label"] == "suspicious" and row["actual_advisory"] == "continue_with_caution"],
        "cases": rows,
    }


def main():
    report = evaluate_cases(load_cases())
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Offline synthetic email slice: {report['dataset_size']} cases")
    print(f"Policy regression matches: {report['policy_regressions_passed']}/{report['dataset_size']}")
    print(report["ai_status"])
    print(report["label_caveat"])
    print(f"Saved: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
