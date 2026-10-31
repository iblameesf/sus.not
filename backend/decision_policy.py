"""Advisory URL decision policy; no AI input or action execution."""

from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

if TYPE_CHECKING:
    from backend.main import AnalyzeURLResponse

POLICY_VERSION = "1"
Score = Annotated[int, Field(strict=True, ge=0, le=100)]
_score_validator = TypeAdapter(Score)


class URLDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sus_score: Score
    risk_level: Literal["low", "review", "high", "critical"]
    recommended_action: Literal[
        "continue_with_caution", "review_before_proceeding", "show_warning", "strong_warning"
    ]
    explanation: str
    policy_version: Literal["1"] = POLICY_VERSION


def evaluate_url_result(result: "AnalyzeURLResponse") -> URLDecision:
    """Apply v1 to a validated, trusted URL analyzer result, never to AI findings.

    Revalidate the score without coercion, even if a caller bypassed the analyzer's
    model validation. Integers only, matching the existing analyzer's score domain.
    All other result fields are ignored: prose cannot override the decision.
    """
    score = _score_validator.validate_python(result.sus_score)
    if score < 30:
        risk, action = "low", "continue_with_caution"
        advice = "Continue with caution; a low score does not guarantee safety."
    elif score < 60:
        risk, action = "review", "review_before_proceeding"
        advice = "Review the URL and independently verify the context before proceeding."
    elif score < 80:
        risk, action = "high", "show_warning"
        advice = "Show an advisory, dismissible warning and encourage independent verification."
    else:
        risk, action = "critical", "strong_warning"
        advice = "Show a strong advisory, dismissible warning and urge independent verification."

    return URLDecision(
        sus_score=score,
        risk_level=risk,
        recommended_action=action,
        explanation=(
            f"{advice} The SUS Score is experimental and does not represent a calibrated "
            "fraud probability. All warnings are advisory and dismissible. "
            "This policy does not block websites or mark emails as spam."
        ),
        policy_version=POLICY_VERSION,
    )
