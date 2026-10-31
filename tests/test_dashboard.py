import json
from uuid import uuid4

import httpx
import pytest
from streamlit.testing.v1 import AppTest

from dashboard.data import (
    API, OLLAMA, ROOT, BENCHMARK_PATH, DashboardClient, DataError,
    confusion_matrix, history_rows, load_benchmark, qwen_available,
)

ID = str(uuid4())
RECORD = {
    "investigation_id": ID, "timestamp_utc": "2026-01-01T00:00:00+00:00",
    "investigation_type": "URL", "sus_score": 70, "risk_level": "high",
    "indicators": ["IP address used instead of a domain (+30)"],
    "recommended_action": "show_warning", "policy_version": "1",
    "analysis_status": "completed", "redacted_url": "https://[redacted]",
}
URL_RESULT = {
    "url": "https://example.com", "sus_score": 0, "risk_level": "low",
    "indicators": [], "message": "Experimental heuristic.",
}
DECISION = {
    "sus_score": 0, "risk_level": "low", "recommended_action": "continue_with_caution",
    "explanation": "Verify independently.", "policy_version": "1",
}
TEXT = {
    "indicators": ["Possible urgency"], "explanation": "Potential pressure.",
    "recommendation": "Verify independently.", "uncertainty": "Not proof of fraud.",
}


def client_for(payload, status=200):
    return DashboardClient(httpx.MockTransport(lambda request: httpx.Response(status, json=payload)))


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadTimeout])
def test_unavailable_backend_is_sanitized(error, caplog):
    def fail(request):
        raise error("secret raw text password", request=request)
    with DashboardClient(httpx.MockTransport(fail)) as client:
        with pytest.raises(DataError) as caught:
            client.health()
    assert "secret" not in str(caught.value)
    assert "password" not in caplog.text


@pytest.mark.parametrize("status", [302, 404, 422, 500, 503, 504])
def test_http_failures_do_not_expose_body(status):
    with client_for({"detail": "secret text api_key=abc"}, status) as client:
        with pytest.raises(DataError) as caught:
            client.analyze_text("secret text")
        assert "secret" not in str(caught.value)
        assert "abc" not in str(caught.value)


@pytest.mark.parametrize("payload", [None, [], {}, {"status": "ok"}, {"status": "bad", "service": "SUS.NOT"}])
def test_invalid_health(payload):
    with client_for(payload) as client, pytest.raises(DataError):
        client.health()


def test_non_json_response():
    with DashboardClient(httpx.MockTransport(lambda request: httpx.Response(200, text="not json"))) as client:
        with pytest.raises(DataError):
            client.health()


@pytest.mark.parametrize("method,payload", [
    ("health", {"status": "ok", "service": "SUS.NOT"}),
    ("history_status", {"enabled": False}),
    ("models", {"models": [{"name": "qwen3.5:4b-q4_K_M"}]}),
])
def test_valid_status_contracts(method, payload):
    with client_for(payload) as client:
        result = getattr(client, method)()
        assert result is not None
        if method == "models":
            assert qwen_available(result)


def test_missing_model_is_not_available():
    with client_for({"models": []}) as client:
        assert not qwen_available(client.models())


@pytest.mark.parametrize("method,payload", [
    ("analyze_url", URL_RESULT), ("evaluate_url", DECISION), ("analyze_text", TEXT),
])
def test_analysis_valid_and_invalid_contracts(method, payload):
    with client_for(payload) as client:
        assert getattr(client, method)("input").model_dump() == payload
    with client_for({}) as client, pytest.raises(DataError):
        getattr(client, method)("input")
    invalid = dict(payload)
    invalid["sus_score" if method != "analyze_text" else "indicators"] = "secret"
    with client_for(invalid) as client, pytest.raises(DataError):
        getattr(client, method)("input")


def test_only_localhost_no_automatic_recording_or_redirects(monkeypatch):
    requests = []
    def handle(request):
        requests.append(request)
        payloads = {
            "/health": {"status": "ok", "service": "SUS.NOT"},
            "/api/tags": {"models": []}, "/analyze-url": URL_RESULT,
            "/evaluate-url": DECISION, "/analyze-text": TEXT,
        }
        return httpx.Response(200, json=payloads[request.url.path])
    monkeypatch.setenv("HTTP_PROXY", "http://external.invalid")
    with DashboardClient(httpx.MockTransport(handle)) as client:
        assert not client._client.follow_redirects
        assert not client._client.trust_env
        client.health()
        client.models()
        client.analyze_url("https://external.invalid")
        client.evaluate_url("https://external.invalid")
        client.analyze_text("private")
        assert all("x-susnot-record-history" not in r.headers for r in requests)
        client.evaluate_url("https://external.invalid", record=True)
        client.analyze_text("private", record=True)
    assert all(str(r.url).startswith((API + "/", OLLAMA + "/")) for r in requests)
    assert requests[-1].headers["x-susnot-record-history"] == "true"
    assert requests[-2].headers["x-susnot-record-history"] == "true"


def test_history_empty_and_minimized_projection():
    with client_for({"items": [], "total": 0, "limit": 20, "offset": 0}) as client:
        assert history_rows(client.history()) == []
    extra = {**RECORD, "url": "https://secret", "text": "secret", "redacted_url": "https://secret"}
    with client_for({"items": [extra], "total": 1, "limit": 20, "offset": 0}) as client:
        rows = history_rows(client.history())
        assert rows[0]["investigation_id"] == ID
        assert "secret" not in json.dumps(rows)
    with client_for(extra) as client:
        record = client.investigation(ID)
        assert "secret" not in record.model_dump_json()


@pytest.mark.parametrize("limit,offset", [(0, 0), (101, 0), (20, -1), ("20", 0), (True, 0)])
def test_invalid_pagination(limit, offset):
    with client_for({}) as client, pytest.raises(DataError):
        client.history(limit=limit, offset=offset)


def test_pagination_requests_and_inconsistent_pages():
    def handle(request):
        assert dict(request.url.params) == {"limit": "10", "offset": "10"}
        return httpx.Response(200, json={"items": [RECORD], "total": 11, "limit": 10, "offset": 10})
    with DashboardClient(httpx.MockTransport(handle)) as client:
        assert client.history(limit=10, offset=10).total == 11
    with client_for({"items": [], "total": 0, "limit": 10, "offset": 0}) as client:
        with pytest.raises(DataError):
            client.history()


@pytest.mark.parametrize("identifier", ["bad", "../health", "' OR 1=1 --"])
def test_invalid_investigation_id(identifier):
    with client_for(RECORD) as client, pytest.raises(DataError):
        client.investigation(identifier)


def test_invalid_history_response():
    for record in ({**RECORD, "timestamp_utc": "2026-01-01"}, {**RECORD, "sus_score": 101}):
        with client_for(record) as client, pytest.raises(DataError):
            client.investigation(ID)


def test_benchmark_loads_saved_values_and_matrix():
    raw = json.loads(BENCHMARK_PATH.read_text())
    result = load_benchmark()
    assert result.dataset_size == raw["dataset_size"]
    assert result.warning_threshold == raw["warning_threshold"]
    assert result.metrics.model_dump() == raw["metrics"]
    matrix = confusion_matrix(result)
    assert matrix[0]["Predicted suspicious"] == raw["metrics"]["true_positives"]
    assert matrix[0]["Predicted benign"] == raw["metrics"]["false_negatives"]
    assert matrix[1]["Predicted suspicious"] == raw["metrics"]["false_positives"]
    assert matrix[1]["Predicted benign"] == raw["metrics"]["true_negatives"]


@pytest.mark.parametrize("contents", ["{", "{}", '{"dataset_size": "secret"}'])
def test_invalid_and_missing_benchmark(tmp_path, contents):
    path = tmp_path / "results.json"
    with pytest.raises(DataError):
        load_benchmark(path)
    path.write_text(contents)
    with pytest.raises(DataError):
        load_benchmark(path)


def test_benchmark_rejects_inconsistent_counts(tmp_path):
    raw = json.loads(BENCHMARK_PATH.read_text())
    raw["dataset_size"] += 1
    path = tmp_path / "results.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(DataError):
        load_benchmark(path)


def test_history_status_is_backend_sourced(monkeypatch):
    from backend.main import app
    from fastapi.testclient import TestClient
    with TestClient(app) as client:
        monkeypatch.delenv("SUSNOT_HISTORY_ENABLED", raising=False)
        assert client.get("/history-status").json() == {"enabled": False}
        monkeypatch.setenv("SUSNOT_HISTORY_ENABLED", "true")
        assert client.get("/history-status").json() == {"enabled": True}


def test_streamlit_sections_render_with_backend_unavailable(monkeypatch):
    def fail(*args, **kwargs):
        raise DataError("Local service unavailable.")
    monkeypatch.setattr(DashboardClient, "health", fail)
    monkeypatch.setattr(DashboardClient, "models", fail)
    monkeypatch.setattr(DashboardClient, "history_status", fail)
    at = AppTest.from_file(ROOT / "dashboard/app.py", default_timeout=15).run()
    assert not at.exception
    assert any("Unavailable" in item.value for item in at.error)
    for section in ["URL Investigator", "AI Text Investigator", "Investigation History", "Benchmarks", "Project Evidence"]:
        at.sidebar.radio[0].set_value(section).run()
        assert not at.exception


def test_streamlit_url_submission_uses_both_endpoints(monkeypatch):
    from dashboard.data import HistoryStatus
    from backend.main import AnalyzeURLResponse
    from backend.decision_policy import URLDecision
    calls = []
    monkeypatch.setattr(DashboardClient, "health", lambda self: None)
    monkeypatch.setattr(DashboardClient, "models", lambda self: (_ for _ in ()).throw(DataError("Unavailable")))
    monkeypatch.setattr(DashboardClient, "history_status", lambda self: HistoryStatus(enabled=True))
    monkeypatch.setattr(DashboardClient, "history", lambda self, **kw: (_ for _ in ()).throw(DataError("Unavailable")))
    def analyze(self, url):
        calls.append(("analyze", url))
        return AnalyzeURLResponse(**URL_RESULT)
    def evaluate(self, url, *, record=False):
        calls.append(("evaluate", record))
        return URLDecision(**DECISION)
    monkeypatch.setattr(DashboardClient, "analyze_url", analyze)
    monkeypatch.setattr(DashboardClient, "evaluate_url", evaluate)
    at = AppTest.from_file(ROOT / "dashboard/app.py").run()
    at.sidebar.radio[0].set_value("URL Investigator").run()
    at.text_input[0].set_value("https://example.com")
    next(button for button in at.button if button.label == "Analyze URL").click().run()
    assert not at.exception
    assert calls == [("analyze", "https://example.com"), ("evaluate", False)]


def test_streamlit_text_and_history_flows(monkeypatch):
    from dashboard.data import HistoryStatus, Page, Record
    from backend.text_investigator import AnalyzeTextResponse
    calls = []
    monkeypatch.setattr(DashboardClient, "health", lambda self: None)
    monkeypatch.setattr(DashboardClient, "models", lambda self: (_ for _ in ()).throw(DataError("Unavailable")))
    monkeypatch.setattr(DashboardClient, "history_status", lambda self: HistoryStatus(enabled=True))
    def page(self, *, limit=20, offset=0):
        return Page.model_validate_json(json.dumps({"items": [RECORD], "total": 1, "limit": limit, "offset": offset}))
    monkeypatch.setattr(DashboardClient, "history", page)
    monkeypatch.setattr(DashboardClient, "investigation", lambda self, identifier: Record.model_validate_json(json.dumps(RECORD)))
    def analyze(self, text, *, record=False):
        calls.append((text, record))
        return AnalyzeTextResponse(**TEXT)
    monkeypatch.setattr(DashboardClient, "analyze_text", analyze)
    at = AppTest.from_file(ROOT / "dashboard/app.py", default_timeout=15).run()
    at.sidebar.radio[0].set_value("AI Text Investigator").run()
    assert not at.checkbox[0].value
    at.checkbox[0].check()
    at.text_area[0].set_value("Private test message")
    next(button for button in at.button if button.label == "Analyze text").click().run()
    assert not at.exception
    assert calls == [("Private test message", True)]
    assert any(item.value == TEXT["uncertainty"] for item in at.text)
    at.sidebar.radio[0].set_value("Investigation History").run()
    assert not at.exception
    assert len(at.dataframe) == 1
    next(button for button in at.button if button.label == "Load details").click().run()
    assert not at.exception
    assert ID in at.json[0].value


def test_streamlit_disabled_and_empty_history(monkeypatch):
    from dashboard.data import HistoryStatus, Page
    enabled = {"value": False}
    monkeypatch.setattr(DashboardClient, "health", lambda self: None)
    monkeypatch.setattr(DashboardClient, "models", lambda self: (_ for _ in ()).throw(DataError("Unavailable")))
    monkeypatch.setattr(DashboardClient, "history_status", lambda self: HistoryStatus(enabled=enabled["value"]))
    monkeypatch.setattr(DashboardClient, "history", lambda self, **kw: Page(items=[], total=0, limit=20, offset=0))
    at = AppTest.from_file(ROOT / "dashboard/app.py").run()
    assert any("disabled" in item.value for item in at.info)
    at.sidebar.radio[0].set_value("Investigation History").run()
    assert any("disabled" in item.value for item in at.info)
    enabled["value"] = True
    at.run()
    assert not at.exception
    assert any("History is empty" in item.value for item in at.info)
