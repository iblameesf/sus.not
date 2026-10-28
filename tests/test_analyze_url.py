import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize(
    "url, score, risk_level, indicators",
    [
        ("https://example.com/login", 0, "low", []),
        (
            "http://192.0.2.1/login",
            30,
            "review",
            ["IP address used instead of a domain (+30)"],
        ),
        (
            "https://[2001:db8::1]/login",
            30,
            "review",
            ["IP address used instead of a domain (+30)"],
        ),
        (
            "https://user@example.com/login",
            25,
            "low",
            ["@ character in URL authority (+25)"],
        ),
        (
            "https://@example.com/login",
            25,
            "low",
            ["@ character in URL authority (+25)"],
        ),
        (
            "https://example.com/verify",
            15,
            "low",
            ["Path contains verify or urgent (+15)"],
        ),
        (
            "https://example.com/URGENT/verify",
            15,
            "low",
            ["Path contains verify or urgent (+15)"],
        ),
        # These indicators must not match query strings or fragments.
        ("https://example.com/login?next=@urgent#verify", 0, "low", []),
        (
            "https://user@192.0.2.1/verify",
            70,
            "high",
            [
                "IP address used instead of a domain (+30)",
                "@ character in URL authority (+25)",
                "Path contains verify or urgent (+15)",
            ],
        ),
    ],
)
def test_analyze_url(client, url, score, risk_level, indicators):
    response = client.post("/analyze-url", json={"url": url})

    assert response.status_code == 200
    result = response.json()
    assert set(result) == {"url", "sus_score", "risk_level", "indicators", "message"}
    assert result["url"] == url
    assert result["sus_score"] == score
    assert 0 <= result["sus_score"] <= 100
    assert result["risk_level"] == risk_level
    assert result["indicators"] == indicators
    assert "heuristic, not a probability of fraud" in result["message"]
    assert "URL was not visited" in result["message"]


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "https://",
        "https:///example.com",
        "https://example.com:invalid",
        "https://example.com:99999",
        "https://[invalid]/",
        "https://exa mple.com",
        "https://example.com/\nverify",
        "https://example.com\\login",
        "ftp://example.com/file",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "//example.com/login",
    ],
)
def test_reject_invalid_or_unsupported_url(client, url):
    response = client.post("/analyze-url", json={"url": url})

    assert response.status_code == 422


@pytest.mark.parametrize("payload", [{}, {"url": None}, {"url": 123}])
def test_url_is_required_and_must_be_a_string(client, payload):
    response = client.post("/analyze-url", json=payload)

    assert response.status_code == 422
