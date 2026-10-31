import ipaddress
import json
import socket
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
import pytest
from pydantic import ValidationError

from benchmarks import evaluate_urls as evaluation


def test_dataset_schema_size_labels_and_reserved_hosts():
    cases = evaluation.load_cases()
    assert len(cases) >= 30
    assert {case.expected_label for case in cases} == {"benign", "suspicious"}
    assert len({case.id for case in cases}) == len(cases)
    assert len({case.url for case in cases}) == len(cases)
    for case in cases:
        assert set(case.model_dump()) == {"id", "url", "expected_label", "rationale"}
        host = urlsplit(case.url).hostname.rstrip(".")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            assert host in {"example.com", "example.net", "example.org"} or host.endswith(
                (".example", ".example.com", ".example.net", ".example.org")
            )
        else:
            networks = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
            assert any(address in ipaddress.ip_network(network) for network in networks)
        if case.expected_label == "suspicious":
            assert "Synthetic scenario" in case.rationale
            assert "Not verified fraud" in case.rationale or "not verified fraud" in case.rationale


@pytest.mark.parametrize("updates", [
    {"expected_label": "fraud"}, {"expected_label": True}, {"expected_label": None},
    {"id": " "}, {"rationale": ""}, {"rationale": 123},
    {"url": "file:///etc/passwd"}, {"extra": "unsupported"},
])
def test_invalid_case_schema(updates):
    raw = evaluation.load_cases()[0].model_dump()
    with pytest.raises(ValidationError):
        evaluation.URLCase.model_validate({**raw, **updates})


def test_missing_fields_rejected():
    raw = evaluation.load_cases()[0].model_dump()
    for field in raw:
        with pytest.raises(ValidationError):
            evaluation.URLCase.model_validate({key: value for key, value in raw.items() if key != field})


@pytest.mark.parametrize("mutation", ["too_small", "duplicate_id", "not_a_list"])
def test_dataset_collection_validation(tmp_path, mutation):
    raw = [case.model_dump() for case in evaluation.load_cases()]
    if mutation == "too_small":
        raw = raw[:29]
    elif mutation == "duplicate_id":
        raw[1]["id"] = raw[0]["id"]
    else:
        raw = {"cases": raw}
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError):
        evaluation.load_cases(path)


def test_metric_calculations():
    metrics = evaluation.calculate_metrics(tp=3, tn=5, fp=1, fn=2)
    assert metrics == {
        "true_positives": 3, "true_negatives": 5,
        "false_positives": 1, "false_negatives": 2,
        "precision": 0.75, "recall": 0.6, "f1_score": 2 / 3, "accuracy": 8 / 11,
    }


@pytest.mark.parametrize("counts,expected", [
    ((0, 0, 0, 0), (0, 0, 0, 0)),
    ((0, 5, 0, 0), (0, 0, 0, 1)),
    ((0, 0, 0, 5), (0, 0, 0, 0)),
    ((0, 0, 5, 0), (0, 0, 0, 0)),
    ((5, 0, 0, 0), (1, 1, 1, 1)),
])
def test_zero_denominators_and_perfect_predictions(counts, expected):
    result = evaluation.calculate_metrics(**dict(zip(("tp", "tn", "fp", "fn"), counts)))
    assert tuple(result[key] for key in ("precision", "recall", "f1_score", "accuracy")) == expected


@pytest.mark.parametrize("count", [-1, True, 1.5, "1", None])
def test_invalid_confusion_counts(count):
    with pytest.raises(ValueError):
        evaluation.calculate_metrics(tp=count, tn=0, fp=0, fn=0)


def test_warning_threshold_is_inclusive(monkeypatch):
    cases = evaluation.load_cases()[:2]
    scores = iter([59, 60])
    monkeypatch.setattr(evaluation, "analyze_url", lambda request: SimpleNamespace(
        sus_score=next(scores), risk_level="high", indicators=[],
    ))
    report = evaluation.evaluate_cases(cases)
    assert report["warning_threshold"] == 60
    assert [row["predicted_label"] for row in report["cases"]] == ["benign", "suspicious"]


def test_reproducibility_saved_artifact_and_no_network(monkeypatch, tmp_path, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("Offline evaluation attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(httpx.Client, "request", forbidden)
    monkeypatch.setattr(httpx.AsyncClient, "request", forbidden)
    cases = evaluation.load_cases()
    first = evaluation.serialize_report(evaluation.evaluate_cases(cases))
    assert evaluation.serialize_report(evaluation.evaluate_cases(cases)) == first
    assert evaluation.RESULTS_PATH.read_text(encoding="utf-8") == first
    output = tmp_path / "results" / "url_evaluation.json"
    monkeypatch.setattr(evaluation, "RESULTS_PATH", output)
    evaluation.main()
    assert output.read_text(encoding="utf-8") == first
    evaluation.main()
    assert output.read_text(encoding="utf-8") == first
    console = capsys.readouterr().out
    assert "Actual \\ Predicted" in console
    report = json.loads(first)
    assert report["metrics"] == evaluation.calculate_metrics(tp=4, tn=14, fp=2, fn=12)
    mistakes = [row for row in report["cases"] if row["expected_label"] != row["predicted_label"]]
    assert report["misclassified_cases"] == mistakes
    assert {row["outcome"] for row in mistakes} == {"fp", "fn"}
    for row in mistakes:
        assert row["id"] in console
