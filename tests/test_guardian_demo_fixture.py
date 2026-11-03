"""Controlled demo never activates in production defaults."""
from fastapi.testclient import TestClient
from backend.main import app


def test_demo_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SUSNOT_DEMO_MODE", raising=False)
    with TestClient(app) as client:
        data = client.post("/analyze-url", json={"url": "http://127.0.0.1:8765"}).json()
    assert data["sus_score"] == 30
    assert all("DEMO" not in x for x in data["indicators"])


def test_demo_enabled_for_exact_loopback_origin(monkeypatch):
    monkeypatch.setenv("SUSNOT_DEMO_MODE", "1")
    with TestClient(app) as client:
        data = client.post("/analyze-url", json={"url": "http://127.0.0.1:8765"}).json()
    assert data["sus_score"] == 70
    assert data["risk_level"] == "high"
    assert "SYNTHETIC DEMO" in data["indicators"][0]


def test_demo_does_not_change_other_urls(monkeypatch):
    monkeypatch.setenv("SUSNOT_DEMO_MODE", "1")
    with TestClient(app) as client:
        for url in ("http://127.0.0.1:8766", "https://example.com", "http://localhost:8765"):
            data = client.post("/analyze-url", json={"url": url}).json()
            assert all("DEMO" not in x for x in data["indicators"])
