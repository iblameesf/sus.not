"""Regression tests for privacy-minimized runtime logging."""

import json
import os
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from backend.runtime_log import log_event


def test_logging_disabled(tmp_path):
    log_path = tmp_path / "runtime.jsonl"

    with patch.dict(os.environ, {
        "SUSNOT_RUNTIME_LOG_ENABLED": "false",
        "SUSNOT_RUNTIME_LOG_PATH": str(log_path),
    }):
        with TestClient(app) as client:
            response = client.post(
                "/analyze-url",
                json={"url": "https://example.com/verify"},
            )

        assert response.status_code == 200
        assert not log_path.exists()


def test_both_endpoints_generate_private_events(tmp_path):
    log_path = tmp_path / "runtime.jsonl"
    test_url = "https://example.com/verify-account"

    with patch.dict(os.environ, {
        "SUSNOT_RUNTIME_LOG_ENABLED": "true",
        "SUSNOT_RUNTIME_LOG_PATH": str(log_path),
    }):
        with TestClient(app) as client:
            first = client.post("/analyze-url", json={"url": test_url})
            second = client.post("/evaluate-url", json={"url": test_url})

    assert first.status_code == 200
    assert second.status_code == 200

    raw = log_path.read_text(encoding="utf-8")
    records = [json.loads(line) for line in raw.splitlines()]

    assert len(records) == 2
    assert {record["event"] for record in records} == {
        "url_analysis_completed",
        "url_evaluation_completed",
    }

    assert test_url not in raw
    assert "example.com" not in raw

    for record in records:
        assert set(record) == {
            "timestamp_utc",
            "event",
            "sus_score",
            "risk_level",
            "duration_ms",
        }
        assert isinstance(record["sus_score"], int)
        assert record["risk_level"] in {
            "low", "review", "high", "critical"
        }
        assert record["duration_ms"] >= 0


def test_logging_failure_does_not_break_api(tmp_path):
    # A directory cannot be opened as an append-only JSONL file.
    invalid_log_path = tmp_path / "runtime.jsonl"
    invalid_log_path.mkdir()

    with patch.dict(os.environ, {
        "SUSNOT_RUNTIME_LOG_ENABLED": "true",
        "SUSNOT_RUNTIME_LOG_PATH": str(invalid_log_path),
    }):
        with TestClient(app) as client:
            response = client.post(
                "/analyze-url",
                json={"url": "https://example.com"},
            )

    assert response.status_code == 200


def test_invalid_events_are_rejected(tmp_path):
    log_path = tmp_path / "runtime.jsonl"

    with patch.dict(os.environ, {
        "SUSNOT_RUNTIME_LOG_ENABLED": "true",
        "SUSNOT_RUNTIME_LOG_PATH": str(log_path),
    }):
        log_event(
            "unknown_event",
            score=50,
            risk_level="review",
            duration_ms=10,
        )
        log_event(
            "url_analysis_completed",
            score=101,
            risk_level="review",
            duration_ms=10,
        )

    assert not log_path.exists()


def test_invalid_durations_are_rejected(tmp_path):
    log_path = tmp_path / "runtime.jsonl"

    with patch.dict(os.environ, {
        "SUSNOT_RUNTIME_LOG_ENABLED": "true",
        "SUSNOT_RUNTIME_LOG_PATH": str(log_path),
    }):
        for duration in (float("nan"), float("inf"), -1, True, False):
            log_event(
                "url_analysis_completed",
                score=50,
                risk_level="review",
                duration_ms=duration,
            )

    assert not log_path.exists()


def test_log_rotation_preserves_previous_file(tmp_path):
    from backend import runtime_log

    log_path = tmp_path / "runtime.jsonl"
    previous_content = "previous-test-log\n"
    log_path.write_text(previous_content, encoding="utf-8")

    with patch.dict(os.environ, {
        "SUSNOT_RUNTIME_LOG_ENABLED": "true",
        "SUSNOT_RUNTIME_LOG_PATH": str(log_path),
    }), patch.object(runtime_log, "MAX_LOG_BYTES", 1):
        log_event(
            "url_analysis_completed",
            score=50,
            risk_level="review",
            duration_ms=12.5,
        )

    backup_path = log_path.with_suffix(".jsonl.1")

    assert backup_path.exists()
    assert backup_path.read_text(encoding="utf-8") == previous_content

    records = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]

    assert len(records) == 1
    assert records[0]["event"] == "url_analysis_completed"
    assert records[0]["sus_score"] == 50
