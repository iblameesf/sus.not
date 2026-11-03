import pytest

from backend.hostname_risk import assess_hostname


@pytest.mark.parametrize(
    "origin, expected_score",
    [
        ("https://example.com", 0),
        ("https://university-scholarship.example", 0),
        ("https://student-login.example", 0),
        ("https://xn--example.com", 20),
        ("https://a.b.c.d.example.com", 15),
        ("https://" + "a" * 55 + ".example.com", 15),
        ("https://" + "a" * 55 + ".b.c.d.example.com", 30),
    ],
)
def test_hostname_risk(origin, expected_score):
    score, indicators = assess_hostname(origin)

    assert score == expected_score
    assert isinstance(indicators, list)
    assert all(isinstance(item, str) for item in indicators)
