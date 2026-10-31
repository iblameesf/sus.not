"""Application-controlled MCP investigations; model prose never dispatches actions."""

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import PaginatedRequestParams
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from backend.decision_policy import URLDecision, evaluate_url_result
from backend.history import record_history, redact_url
from backend.text_investigator import AnalyzeTextRequest, AnalyzeTextResponse

ALLOWED_TOOLS = frozenset({"inspect_url", "inspect_text"})
CONNECTION_TIMEOUT_SECONDS = 10
TOOL_TIMEOUT_SECONDS = 95  # Allows the existing 90-second local model deadline.
URL_UNCERTAINTY = (
    "The experimental SUS Score is a heuristic, not a probability of fraud. "
    "A low score does not guarantee safety. The URL was not visited."
)


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str | None = None
    text: str | None = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        if value is not None:
            # Local import keeps the existing API contracts in their original module.
            from backend.main import AnalyzeURLRequest
            return AnalyzeURLRequest(url=value).url
        return value

    @field_validator("text")
    @classmethod
    def validate_text(cls, value: str | None) -> str | None:
        return AnalyzeTextRequest(text=value).text if value is not None else None

    @model_validator(mode="after")
    def require_input(self):
        if self.url is None and self.text is None:
            raise ValueError("Provide at least one of url or text")
        return self


class URLAssessment(BaseModel):
    """Original URL inspection and the separate, code-owned policy decision."""

    sus_score: int
    risk_level: str
    indicators: list[str]
    explanation: str
    decision: URLDecision


class ToolFailure(BaseModel):
    tool: Literal["inspect_url", "inspect_text"]
    code: Literal["tool_error", "tool_timeout", "invalid_tool_output"]
    message: str


class InvestigationReport(BaseModel):
    investigation_id: str
    url_assessment: URLAssessment | None = None
    ai_text_assessment: AnalyzeTextResponse | None = None
    recommended_action: str | None = None
    uncertainty: list[str]
    tools_used: list[Literal["inspect_url", "inspect_text"]]
    policy_version: str | None = None
    errors: list[ToolFailure]


@asynccontextmanager
async def mcp_connection():
    # Executable, module and cwd are application-owned, never taken from inputs.
    # Do not forward ambient environment secrets to the child process.
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "backend.mcp_server"],
        cwd=str(Path(__file__).resolve().parents[1]),
        env={"PYTHONPATH": str(Path(__file__).resolve().parents[1])},
    )
    # MCP stderr may contain tool exception details; never relay it into API logs.
    with open(os.devnull, "w") as error_log:
        async with stdio_client(params, errlog=error_log) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                yield session


async def discover_tools(session) -> set[str]:
    """Discover names, without granting authority to advertised extra tools."""
    names = set()
    cursor = None
    # Bound pagination even if a broken server repeats its cursor.
    for _ in range(10):
        page = await session.list_tools(params=PaginatedRequestParams(cursor=cursor) if cursor else None)
        names.update(tool.name for tool in page.tools)
        cursor = page.next_cursor
        if cursor is None:
            return names & ALLOWED_TOOLS
    raise ValueError("Invalid tool discovery pagination")


async def invoke_tool(session, discovered: set[str], name: str, arguments: dict):
    """Only application-allowlisted, discovered tools with validated arguments."""
    if name not in ALLOWED_TOOLS:
        raise ValueError("Unauthorized tool")
    if name not in discovered:
        raise ValueError("Required tool unavailable")
    if name == "inspect_url":
        from backend.main import AnalyzeURLRequest
        arguments = AnalyzeURLRequest.model_validate(arguments, extra="forbid").model_dump()
    else:
        arguments = AnalyzeTextRequest.model_validate(arguments).model_dump()
    async with asyncio.timeout(TOOL_TIMEOUT_SECONDS):
        return await session.call_tool(name, arguments)


def validate_url_output(data: dict, url: str) -> URLAssessment:
    from backend.main import AnalyzeURLResponse

    if not isinstance(data, dict) or set(data) != {"sus_score", "risk_level", "indicators", "explanation"}:
        raise ValueError("Invalid URL tool output")
    result = AnalyzeURLResponse.model_validate(
        {"url": url, "message": data["explanation"],
         **{key: data[key] for key in ("sus_score", "risk_level", "indicators")}},
        strict=True,
    )
    decision = evaluate_url_result(result)
    # Reject inconsistent output, rather than allowing prose/risk labels to change policy.
    if result.risk_level != decision.risk_level:
        raise ValueError("Inconsistent URL risk level")
    return URLAssessment(**data, decision=decision)


async def investigate(request: InvestigationRequest, consent: str | None = None) -> InvestigationReport:
    """Run a fixed workflow over an actual SDK session, without storing raw input."""
    report = InvestigationReport(
        investigation_id=str(uuid4()), uncertainty=[], tools_used=[], errors=[],
    )
    planned = []
    if request.url is not None:
        planned.append(("inspect_url", {"url": request.url}))
    if request.text is not None:
        planned.append(("inspect_text", {"text": request.text}))

    try:
        # Bound startup, discovery, tools and shutdown together as well as each call.
        async with asyncio.timeout(CONNECTION_TIMEOUT_SECONDS + len(planned) * TOOL_TIMEOUT_SECONDS):
            async with mcp_connection() as session:
                async with asyncio.timeout(CONNECTION_TIMEOUT_SECONDS):
                    await session.initialize()
                    discovered = await discover_tools(session)
                for name, arguments in planned:
                    try:
                        if name not in discovered:
                            raise ValueError("Required tool unavailable")
                        report.tools_used.append(name)
                        result = await invoke_tool(session, discovered, name, arguments)
                    except TimeoutError:
                        report.errors.append(ToolFailure(
                            tool=name, code="tool_timeout", message="Investigation tool timed out. Retry later.",
                        ))
                        continue
                    except Exception:
                        report.errors.append(ToolFailure(
                            tool=name, code="tool_error", message="Required investigation tool is unavailable.",
                        ))
                        continue
                    if result.is_error:
                        report.errors.append(ToolFailure(
                            tool=name, code="tool_error",
                            message=("Local text investigation failed. Check Ollama/model availability and retry."
                                     if name == "inspect_text" else "URL investigation tool failed."),
                        ))
                        continue
                    try:
                        # Do not interpret prose, fall back to text JSON, or execute returned instructions.
                        if name == "inspect_url":
                            report.url_assessment = validate_url_output(result.structured_content, request.url)
                        else:
                            report.ai_text_assessment = AnalyzeTextResponse.model_validate(
                                result.structured_content,
                            )
                    except (ValidationError, ValueError, TypeError):
                        report.errors.append(ToolFailure(
                            tool=name, code="invalid_tool_output",
                            message="Investigation tool returned an invalid structured assessment.",
                        ))
    except TimeoutError:
        raise HTTPException(504, "MCP investigation timed out. Please retry.") from None
    except Exception:
        raise HTTPException(503, "Local MCP server is unavailable. Please retry.") from None

    if report.url_assessment is not None:
        assessment = report.url_assessment
        report.recommended_action = assessment.decision.recommended_action
        report.policy_version = assessment.decision.policy_version
        report.uncertainty.append(URL_UNCERTAINTY)
        record_history(
            consent, investigation_type="URL", redacted_url=redact_url(request.url),
            sus_score=assessment.sus_score, risk_level=assessment.risk_level,
            # Do not persist tool prose, which could quote sensitive input.
            indicators=[], recommended_action=report.recommended_action,
            policy_version=report.policy_version,
        )
    elif request.url is not None:
        record_history(consent, investigation_type="URL", analysis_status="failed")
    if report.ai_text_assessment is not None:
        assessment = report.ai_text_assessment
        report.uncertainty.append(assessment.uncertainty)
        record_history(
            consent, investigation_type="text",
            indicators=["model_reported_indicators"] if assessment.indicators else [],
        )
    elif request.text is not None:
        record_history(consent, investigation_type="text", analysis_status="failed")
    if report.errors:
        report.uncertainty.append("One or more investigations failed; missing assessments imply no safety conclusion.")
    return report


router = APIRouter()


@router.post("/investigate", response_model=InvestigationReport)
async def investigate_endpoint(
    request: InvestigationRequest,
    x_susnot_record_history: str | None = Header(default=None),
) -> InvestigationReport:
    return await investigate(request, x_susnot_record_history)
