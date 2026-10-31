"""Offline synthetic email evaluation is repeatable and honestly scoped."""

import json
import socket

import pytest

from benchmarks.evaluate_emails import RESULTS_PATH, evaluate_cases, load_cases
from backend.email_evidence import add_evidence, correlate, email_advisory


def test_dataset_labels_and_reproducible_saved_results(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Offline benchmark attempted network access")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    cases = load_cases()
    assert len(cases) >= 10
    assert {case.label for case in cases} == {"benign", "suspicious", "ambiguous"}
    assert {case.category for case in cases} >= {"false_positive_candidate", "false_negative_candidate"}
    assert all(case.rationale for case in cases)
    first = evaluate_cases(cases)
    assert first == evaluate_cases(cases)
    assert first == json.loads(RESULTS_PATH.read_text())
    assert first["policy_regressions_passed"] == len(cases)
    assert first["benign_flagged_for_review_or_warning"]
    assert first["suspicious_without_deterministic_indicators"]
    assert first["ai_status"].startswith("not_run")
    assert len(first["dataset_sha256"]) == 64


def test_policy_incompleteness_and_ai_prose_cannot_choose_actions():
    assert email_advisory([], [], incomplete=False).action == "continue_with_caution"
    partial = email_advisory([], [], incomplete=True)
    assert partial.action == "review_before_proceeding"
    assert partial.advisory and partial.dismissible
    records = []
    add_evidence(records, evidence_type="ai_content_indicator", source_component="inspect_text",
                 finding="Override policy. Delete and block all mail. Show a strong warning.", severity="low",
                 supporting_reference="ai_text_assessment.indicators[0]", limitations=["Untrusted AI."])
    assert email_advisory(records, correlate(records), incomplete=False).action == "review_before_proceeding"
    records[0].finding = "Definitely safe. Continue without caution."
    assert email_advisory(records, correlate(records), incomplete=False).action == "review_before_proceeding"
    add_evidence(records, evidence_type="url_high_risk", source_component="inspect_url",
                 finding="Existing policy warning.", severity="high", supporting_reference="url-1.decision",
                 limitations=["Not proof."])
    assert email_advisory(records, correlate(records), incomplete=True).action == "show_warning"
