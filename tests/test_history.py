import json
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.history import HistoryStore, redact_url
from backend.main import app
from backend.text_investigator import get_ollama_client

CONSENT = {"X-SUSNOT-Record-History": "true"}


@pytest.fixture
def history(tmp_path, monkeypatch):
    path = tmp_path / "history.sqlite3"
    monkeypatch.setenv("SUSNOT_HISTORY_ENABLED", "true")
    monkeypatch.setenv("SUSNOT_HISTORY_DB", str(path))
    return HistoryStore(path)


def test_initialize_create_retrieve_and_pagination(history):
    history.initialize()
    history.initialize()
    assert history.list()["total"] == 0
    records = [history.create(investigation_type="URL", sus_score=i) for i in range(4)]
    for record in records:
        assert history.get(record["investigation_id"]) == record
        assert record["timestamp_utc"].endswith("+00:00")
    page = history.list(limit=2, offset=1)
    assert page["total"] == 4
    assert page["items"] == list(reversed(records))[1:3]
    assert history.list(offset=20)["items"] == []
    assert history.get(str(uuid4())) is None


def test_parameterized_sql(history):
    injection = "'); DROP TABLE investigations; --"
    record = history.create(investigation_type="text", indicators=[injection])
    assert history.get(record["investigation_id"])["indicators"] == [injection]
    assert history.get("' OR 1=1 --") is None
    assert history.list()["total"] == 1


@pytest.mark.parametrize("url", [
    "https://user:password@example.com:8443/private/token?api_key=secret#fragment",
    "https://secret-subdomain.example.com/path%2Fsecret",
    "https://[::1]:1234/secret", "https://example.com/",
])
def test_url_redaction(url):
    assert redact_url(url) == "https://[redacted]"


def test_disabled_by_default(history, monkeypatch):
    monkeypatch.delenv("SUSNOT_HISTORY_ENABLED")
    with TestClient(app) as client:
        assert client.post("/analyze-url", json={"url": "https://example.com"}, headers=CONSENT).status_code == 200
        assert client.get("/investigations").json()["total"] == 0
        assert client.get(f"/investigations/{uuid4()}").status_code == 404
    assert not history.path.exists()


def test_enabled_still_requires_request_consent(history):
    with TestClient(app) as client:
        for endpoint in ("/analyze-url", "/evaluate-url"):
            assert client.post(endpoint, json={"url": "https://example.com"}).status_code == 200
    assert not history.path.exists()  # Includes Guardian's existing requests.


def test_url_endpoint_compatibility_and_history(history):
    url = "https://user:password@127.0.0.1/verify/private?api_key=secret#fragment"
    with TestClient(app) as client:
        for endpoint in ("/analyze-url", "/evaluate-url"):
            before = client.post(endpoint, json={"url": url}).json()
            after = client.post(endpoint, json={"url": url}, headers=CONSENT).json()
            assert after == before
        page = client.get("/investigations", params={"limit": 1, "offset": 0}).json()
        assert page["total"] == 2
        record = page["items"][0]
        assert record["recommended_action"] == after["recommended_action"]
        assert record["policy_version"] == "1"
        assert client.get(f"/investigations/{record['investigation_id']}").json() == record
        assert client.get(f"/investigations/{uuid4()}").status_code == 404
        assert client.get("/investigations/not-an-id").status_code == 422
        assert client.get("/investigations/' OR 1=1 --").status_code == 422
    data = history.path.read_bytes()
    for secret in (b"password", b"api_key", b"fragment", b"127.0.0.1", b"private"):
        assert secret not in data


@pytest.mark.parametrize("params", [
    {"limit": 0}, {"limit": -1}, {"limit": 101}, {"limit": "x"},
    {"offset": -1}, {"offset": "x"}, {"limit": "1.5"},
])
def test_invalid_pagination(history, params):
    with TestClient(app) as client:
        assert client.get("/investigations", params=params).status_code == 422
    assert not history.path.exists()


def test_text_prose_is_never_stored_and_failure_is_recorded(history, caplog):
    secret = "PRIVATE MESSAGE api_key=secret password=hunter2"
    assessment = {
        "indicators": [secret], "explanation": secret,
        "recommendation": secret, "uncertainty": secret,
    }
    state = {"fail": False}

    async def override():
        def respond(request):
            if state["fail"]:
                return httpx.Response(500, text=secret)
            return httpx.Response(200, json={"done": True, "message": {
                "role": "assistant", "content": json.dumps(assessment),
            }})
        async with httpx.AsyncClient(base_url="http://127.0.0.1:11434",
                                     transport=httpx.MockTransport(respond)) as client:
            yield client

    app.dependency_overrides[get_ollama_client] = override
    try:
        with TestClient(app) as client:
            before = client.post("/analyze-text", json={"text": secret}).json()
            after = client.post("/analyze-text", json={"text": secret}, headers=CONSENT).json()
            assert after == before
            state["fail"] = True
            assert client.post("/analyze-text", json={"text": secret}, headers=CONSENT).status_code == 502
        records = history.list()["items"]
        assert len(records) == 2
        assert records[0]["analysis_status"] == "failed"
        assert records[1]["indicators"] == ["model_reported_indicators"]
        assert records[1]["sus_score"] is None
        assert secret.encode() not in history.path.read_bytes()
        assert secret not in caplog.text
    finally:
        app.dependency_overrides.pop(get_ollama_client, None)


def test_unavailable_history_preserves_analysis(history):
    history.path.mkdir()
    with TestClient(app) as client:
        assert client.post("/analyze-url", json={"url": "https://example.com"}, headers=CONSENT).status_code == 200
        assert client.get("/investigations").status_code == 503
        assert client.get(f"/investigations/{uuid4()}").status_code == 503
