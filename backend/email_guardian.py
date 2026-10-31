"""Local evidence-driven email investigations through application-controlled MCP."""

import asyncio
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ValidationError

from backend import orchestration as mcp
from backend.email_evidence import (
    Correlation, EmailAdvisory, Evidence, add_evidence, correlate, email_advisory, metadata_evidence, url_evidence,
)
from backend.email_parser import EmailInvestigationRequest, EmailParseError, StructuredEmail, parse_email
from backend.email_privacy import EmailRedactor
from backend.history import record_history, redact_url
from backend.text_investigator import AnalyzeTextResponse

MAX_REQUEST_BYTES = 512 * 1024
URL_TIMEOUT_SECONDS = 5
EMAIL_TIMEOUT_SECONDS = 165
LIMITATIONS = [
    "Email headers are unverified claims. SPF, DKIM, and DMARC were not verified.",
    "URLs and remote images were not fetched. Attachments and nested forwarded messages were not analyzed.",
    "URL heuristics and AI findings can be wrong. No email fraud probability is computed.",
    "Metadata, URLs, addresses and recognizable credentials are redacted in this response; source is not retained.",
]


class EmailError(BaseModel):
    code: str
    component: str
    supporting_reference: str
    message: str = "This check was incomplete or failed; no safety conclusion can be drawn from missing evidence."


class EmailURLAssessment(BaseModel):
    url_id: str
    url: str  # scheme only; credentials, host, path, query and fragment are omitted
    supporting_references: list[str]
    assessment: mcp.URLAssessment | None = None


class EmailReport(BaseModel):
    investigation_id: str
    status: Literal["completed", "partial"]
    parsed_metadata: dict
    url_assessments: list[EmailURLAssessment]
    ai_text_assessment: AnalyzeTextResponse | None = None
    evidence: list[Evidence]
    correlation_findings: list[Correlation]
    recommended_advisory_action: EmailAdvisory
    uncertainty: list[str]
    tools_used: list[Literal["inspect_url", "inspect_text"]]
    errors: list[EmailError]
    privacy_redactions_applied: bool = False


def private_assessment(assessment: AnalyzeTextResponse, redactor: EmailRedactor) -> AnalyzeTextResponse:
    # Bound again after replacement, since redaction markers can expand short values.
    return AnalyzeTextResponse(
        indicators=[redactor.scrub(value)[:300] for value in assessment.indicators],
        explanation=redactor.scrub(assessment.explanation)[:1500],
        recommendation=redactor.scrub(assessment.recommendation)[:1500],
        uncertainty=redactor.scrub(assessment.uncertainty)[:1000],
    )


async def investigate_email(request: EmailInvestigationRequest | bytes, consent: str | None = None,
                            *, blocked_literals: tuple[str, ...] = ()) -> EmailReport:
    """Reusable engine: parse -> inspect -> correlate -> advise. No mailbox actions."""
    parsed = parse_email(request)
    # Trusted Gmail coordinator may block its own credential literals in decoded
    # evidence before any MCP call; this parameter is not accepted over HTTP.
    if blocked_literals:
        from urllib.parse import unquote
        source = unquote("\n".join([*parsed.headers.values(), parsed.text, *(item.value for item in parsed.urls)]))
        if any(value and value in source for value in blocked_literals):
            raise EmailParseError("credential_content_blocked")
    redactor = EmailRedactor(parsed)
    evidence = metadata_evidence(parsed)
    errors = [EmailError(code=code, component="email_parser", supporting_reference=ref) for code, ref in parsed.errors]
    urls = [EmailURLAssessment(url_id=item.url_id, url=redact_url(item.value), supporting_references=item.references)
            for item in parsed.urls]
    ai = None
    tools_used = []
    redactions = False
    subject = parsed.headers.get("Subject", "")
    content = (f"Subject: {subject}\n\n" if subject else "") + parsed.text
    plan = [("inspect_url", {"url": item.value}, item.url_id) for item in parsed.urls]
    if content.strip():
        # Qwen needs linguistic evidence, not addresses, credential-bearing URLs or secrets.
        # Keep this within the existing text-tool contract after marker expansion.
        safe_content = redactor.scrub(content)
        redactions |= safe_content != content
        content = safe_content
        if len(content) > 5000:
            errors.append(EmailError(code="text_truncated", component="email_parser", supporting_reference="body.text"))
        plan.append(("inspect_text", {"text": content[:5000]}, "body.text"))
    else:
        errors.append(EmailError(code="no_text", component="email_parser", supporting_reference="body.text"))

    if plan:
        try:
            async with asyncio.timeout(EMAIL_TIMEOUT_SECONDS):
                async with mcp.mcp_connection() as session:
                    async with asyncio.timeout(mcp.CONNECTION_TIMEOUT_SECONDS):
                        await session.initialize()
                        discovered = await mcp.discover_tools(session)
                    for name, arguments, reference in plan:
                        try:
                            if name not in discovered:
                                raise ValueError("Required tool unavailable")
                            if name not in tools_used:
                                tools_used.append(name)
                            async with asyncio.timeout(URL_TIMEOUT_SECONDS if name == "inspect_url" else mcp.TOOL_TIMEOUT_SECONDS):
                                result = await mcp.invoke_tool(session, discovered, name, arguments)
                            if result.is_error:
                                errors.append(EmailError(code="tool_error", component=name, supporting_reference=reference))
                                continue
                        except TimeoutError:
                            errors.append(EmailError(code="tool_timeout", component=name, supporting_reference=reference))
                            continue
                        except Exception:
                            errors.append(EmailError(code="tool_unavailable", component=name, supporting_reference=reference))
                            continue
                        try:
                            if name == "inspect_url":
                                assessment = mcp.validate_url_output(result.structured_content, arguments["url"])
                                safe = assessment.model_copy(update={
                                    "indicators": [redactor.scrub(value) for value in assessment.indicators],
                                    "explanation": redactor.scrub(assessment.explanation),
                                })
                                redactions |= assessment != safe
                                next(item for item in urls if item.url_id == reference).assessment = safe
                                url_evidence(evidence, safe, reference)
                            else:
                                original = AnalyzeTextResponse.model_validate(result.structured_content)
                                ai = private_assessment(original, redactor)
                                redactions |= original != ai
                                for index, finding in enumerate(ai.indicators):
                                    add_evidence(evidence, evidence_type="ai_content_indicator", source_component=name,
                                                 finding=finding, severity="low",
                                                 supporting_reference=f"ai_text_assessment.indicators[{index}]",
                                                 limitations=["Unverified model finding; may reflect prompt injection or hallucination."])
                        except (ValueError, TypeError, ValidationError):
                            errors.append(EmailError(code="invalid_tool_output", component=name, supporting_reference=reference))
        except Exception:
            # Includes transport lifecycle exception groups; keep already collected results.
            errors.append(EmailError(code="mcp_unavailable_or_timeout", component="mcp", supporting_reference="investigation"))
    correlations = correlate(evidence)
    advisory = email_advisory(evidence, correlations, incomplete=bool(errors))
    uncertainty = list(LIMITATIONS)
    if ai:
        uncertainty.append(ai.uncertainty)
    if errors:
        uncertainty.append("Investigation is partial. Omitted, truncated, invalid or failed checks do not establish safety.")
    # Compatible with existing SQLite/dashboard contracts: one text-type marker,
    # no email content, evidence prose, URLs, addresses, subject or model text.
    record_history(consent, investigation_type="text", indicators=["email_guardian"],
                   recommended_action=advisory.action, policy_version=advisory.policy_version,
                   analysis_status="failed" if errors else "completed")
    return EmailReport(
        investigation_id=str(uuid4()), status="partial" if errors else "completed",
        parsed_metadata=parsed.metadata, url_assessments=urls, ai_text_assessment=ai,
        evidence=evidence, correlation_findings=correlations, recommended_advisory_action=advisory,
        uncertainty=uncertainty, tools_used=tools_used, errors=errors,
        privacy_redactions_applied=redactions,
    )


async def read_email_request(request: Request) -> EmailInvestigationRequest:
    # Stream-limit JSON before parsing. Do not return Pydantic errors that echo inputs.
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > MAX_REQUEST_BYTES:
            raise HTTPException(413, "Email request exceeds the size limit.")
        data.extend(chunk)
    try:
        return EmailInvestigationRequest.model_validate_json(data)
    except (ValidationError, ValueError):
        raise HTTPException(422, "Provide either raw_email or structured email fields within the documented limits.") from None


router = APIRouter()


@router.post("/investigate-email", response_model=EmailReport, openapi_extra={
    "requestBody": {"required": True, "content": {"application/json": {"schema": {
        "type": "object", "additionalProperties": False,
        "properties": {"raw_email": {"type": "string", "maxLength": 131072},
                       "email": StructuredEmail.model_json_schema()},
        "oneOf": [{"required": ["raw_email"], "not": {"required": ["email"]}},
                  {"required": ["email"], "not": {"required": ["raw_email"]}}],
    }}}},
})
async def investigate_email_endpoint(
    request: EmailInvestigationRequest = Depends(read_email_request),
    x_susnot_record_history: str | None = Header(default=None),
) -> EmailReport:
    try:
        return await investigate_email(request, x_susnot_record_history)
    except EmailParseError as error:
        raise HTTPException(error.status, {"code": error.code, "message": str(error)}) from None
