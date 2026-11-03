"""Conservative, deterministic hostname risk assessment for SUS.NOT Guardian."""

from urllib.parse import urlsplit


def assess_hostname(origin: str) -> tuple[int, list[str]]:
    """Return a preliminary risk score and explainable indicators."""
    hostname = (urlsplit(origin).hostname or "").lower().rstrip(".")
    if not hostname:
        return 0, []

    score = 0
    indicators = []

    labels = hostname.split(".")

    if any(label.startswith("xn--") for label in labels):
        score += 20
        indicators.append("Internationalized hostname requires additional verification (+20)")

    if len(labels) >= 5:
        score += 15
        indicators.append("Unusually deep hostname structure (+15)")

    if len(hostname) > 60:
        score += 15
        indicators.append("Long hostname requires additional verification (+15)")

    return min(score, 100), indicators
