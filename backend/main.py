from ipaddress import ip_address
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI
from pydantic import BaseModel, Field, HttpUrl, field_validator

from backend.text_investigator import router as text_investigator_router

app = FastAPI(title="SUS.NOT API")
app.include_router(text_investigator_router)


class AnalyzeURLRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        # Reject malformed input rather than silently repairing or stripping it.
        if any(character.isspace() or ord(character) < 32 for character in value):
            raise ValueError("URL must not contain whitespace or control characters")
        if "\\" in value:
            raise ValueError("URL must not contain backslashes")

        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL must be an absolute HTTP or HTTPS URL with a host")

        # Pydantic validates URL syntax, including host and port validity.
        HttpUrl(value)
        # Keep the original text so authority characters such as @ are preserved.
        return value


class AnalyzeURLResponse(BaseModel):
    url: str
    sus_score: int = Field(ge=0, le=100)
    risk_level: Literal["low", "review", "high", "critical"]
    indicators: list[str]
    message: str


@app.post("/analyze-url", response_model=AnalyzeURLResponse)
def analyze_url(request: AnalyzeURLRequest) -> AnalyzeURLResponse:
    # urlsplit only parses text; it makes no network requests.
    parsed = urlsplit(request.url)
    score = 0
    indicators = []

    try:
        ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        score += 30
        indicators.append("IP address used instead of a domain (+30)")

    if "@" in parsed.netloc:
        score += 25
        indicators.append("@ character in URL authority (+25)")

    if any(word in parsed.path.lower() for word in ("verify", "urgent")):
        score += 15
        indicators.append("Path contains verify or urgent (+15)")

    score = min(score, 100)
    if score < 30:
        risk_level = "low"
    elif score < 60:
        risk_level = "review"
    elif score < 80:
        risk_level = "high"
    else:
        risk_level = "critical"

    return AnalyzeURLResponse(
        url=request.url,
        sus_score=score,
        risk_level=risk_level,
        indicators=indicators,
        message=(
            "The experimental SUS Score is a heuristic, not a probability of fraud. "
            "A low score does not guarantee safety. The URL was not visited."
        ),
    )


@app.get("/health")
def health():
    return {"status": "ok", "service": "SUS.NOT"}
