import os
from time import perf_counter
from contextlib import asynccontextmanager
from ipaddress import ip_address
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Header
from pydantic import BaseModel, Field, HttpUrl, field_validator

from backend.decision_policy import URLDecision, evaluate_url_result
from backend.runtime_log import log_event
from backend.text_investigator import router as text_investigator_router
from backend.history import record_history, redact_url, router as history_router
from backend.orchestration import router as orchestration_router
from backend.email_guardian import router as email_guardian_router
from backend.gmail_security import GmailControl, GmailControlMiddleware, router as gmail_security_router
from backend.gmail_routes import router as gmail_routes

@asynccontextmanager
async def lifespan(application):
    try:
        yield
    finally:
        configured = getattr(application.state, "gmail_service", None)
        if configured:
            configured.close()


app = FastAPI(title="SUS.NOT API", lifespan=lifespan)
app.state.gmail_service = None  # Trusted DesktopClient configuration only; no public bootstrap.
app.state.gmail_control = GmailControl()
app.add_middleware(GmailControlMiddleware, control=app.state.gmail_control)
app.include_router(text_investigator_router)
app.include_router(history_router)
app.include_router(orchestration_router)
app.include_router(email_guardian_router)
app.include_router(gmail_security_router)
app.include_router(gmail_routes)


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


@app.post("/analyze-url", response_model=AnalyzeURLResponse)
def investigate_url(
    request: AnalyzeURLRequest,
    x_susnot_record_history: str | None = Header(default=None),
) -> AnalyzeURLResponse:
    started = perf_counter()
    result = analyze_url(request)
    # Explicitly enabled, loopback-only synthetic fixture for end-to-end Chrome UI testing.
    # Never enabled by default and never represents a real phishing verdict.
    if (os.environ.get("SUSNOT_DEMO_MODE") == "1"
            and request.url == "http://127.0.0.1:8765"):
        result = AnalyzeURLResponse(
            url=request.url, sus_score=70, risk_level="high",
            indicators=["SYNTHETIC DEMO FIXTURE: controlled warning-pipeline validation (+70)"],
            message="Synthetic demonstration only; not a phishing assessment. URL was not visited.",
        )
    record_history(
        x_susnot_record_history, investigation_type="URL",
        redacted_url=redact_url(request.url), sus_score=result.sus_score,
        risk_level=result.risk_level, indicators=result.indicators,
    )
    log_event(
        'url_analysis_completed',
        score=result.sus_score,
        risk_level=result.risk_level,
        duration_ms=(perf_counter() - started) * 1000,
    )
    return result


@app.post("/evaluate-url", response_model=URLDecision)
def evaluate_url(
    request: AnalyzeURLRequest,
    x_susnot_record_history: str | None = Header(default=None),
) -> URLDecision:
    started = perf_counter()
    result = analyze_url(request)
    decision = evaluate_url_result(result)
    record_history(
        x_susnot_record_history, investigation_type="URL",
        redacted_url=redact_url(request.url), sus_score=decision.sus_score,
        risk_level=decision.risk_level, indicators=result.indicators,
        recommended_action=decision.recommended_action, policy_version=decision.policy_version,
    )
    log_event(
        'url_evaluation_completed',
        score=decision.sus_score,
        risk_level=decision.risk_level,
        duration_ms=(perf_counter() - started) * 1000,
    )
    return decision


@app.get("/health")
def health():
    return {"status": "ok", "service": "SUS.NOT"}
