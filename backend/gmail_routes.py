"""Authenticated Gmail control routes. Configuration/capability bootstrap stay private."""

from dataclasses import asdict
import re
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from backend.gmail_connector import ConnectorError
from backend.gmail_google import GmailError
from backend.gmail_selections import SelectionError
from backend.gmail_state import AuthorizationError

router = APIRouter(prefix="/gmail", tags=["Gmail read-only"])


class ExplicitConsent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    consent: Literal[True]

    @field_validator("consent", mode="before")
    @classmethod
    def explicit_consent(cls, value):
        if value is not True:
            raise ValueError("Explicit consent required")
        return value


class Consent(ExplicitConsent):
    remember: bool = False


class Selected(ExplicitConsent):
    references: list[Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$")]] = Field(min_length=1, max_length=5)


def service(request):
    configured = getattr(request.app.state, "gmail_service", None)
    if configured is None:
        raise HTTPException(503, {"code": "gmail_not_configured"})
    return configured


async def body(request, schema):
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > 4096:
            raise HTTPException(413, {"code": "gmail_request_limit"})
        content.extend(chunk)
    try:
        return schema.model_validate_json(content)
    except ValueError:
        raise HTTPException(422, {"code": "invalid_gmail_request"}) from None


async def operation(awaitable):
    try:
        return await awaitable
    except (GmailError, ConnectorError) as error:
        raise HTTPException(error.status, {"code": error.code}) from None
    except SelectionError:
        raise HTTPException(409, {"code": "invalid_or_consumed_selection"}) from None
    except AuthorizationError:
        raise HTTPException(401, {"code": "gmail_authorization_required"}) from None
    except Exception:
        raise HTTPException(502, {"code": "gmail_operation_failed"}) from None


@router.post("/oauth/start")
async def start(request: Request):
    configured = service(request)
    values = await body(request, Consent)
    return await operation(configured.begin(request.state.gmail_session, consent=values.consent, remember=values.remember))


@router.get("/account")
async def account(request: Request):
    configured = service(request)
    async def fetch():
        connection = configured._connection(request.state.gmail_session)
        await configured.access(connection)
        identity = await configured.connector(request.state.gmail_session).authorized_account()
        if any(value in identity.address for value in connection.literals):
            raise GmailError("credential_content_blocked")
        return {"address": identity.address, "source": "gmail_profile"}
    return await operation(fetch())


@router.get("/messages")
async def messages(request: Request):
    configured = service(request)
    query = request.query_params
    try:
        if any(key not in {"limit", "page_token"} or len(query.getlist(key)) != 1 for key in query):
            raise ValueError()
        limit = int(query.get("limit", "20"))
        if not 1 <= limit <= 20:
            raise ValueError()
    except ValueError:
        raise HTTPException(422, {"code": "invalid_gmail_request"}) from None
    page = await operation(configured.connector(request.state.gmail_session).list_metadata(limit=limit, page_token=query.get("page_token")))
    # Picker headers are user-requested transient metadata, not trusted HTML. Redact
    # recognizable credentials/addresses, plus the application's own credential literals.
    from backend.email_parser import ParsedEmail
    from backend.email_privacy import EmailRedactor
    source = "\n".join(value for item in page.messages for value in (item.sender, item.subject, item.date))
    redactor = EmailRedactor(ParsedEmail({}, None, None, source, [], [], [], {}))
    connection = configured._connection(request.state.gmail_session)
    output = asdict(page)
    if output["next_page_token"] and any(value in output["next_page_token"] for value in connection.literals):
        raise HTTPException(502, {"code": "invalid_gmail_response"})
    literals = re.compile("|".join(re.escape(value) for value in sorted(connection.literals, key=len, reverse=True)))
    for item in output["messages"]:
        for field in ("sender", "subject", "date"):
            value = redactor.scrub(item[field])
            item[field] = literals.sub("[credential redacted]", value)[:2048]
    return output


@router.post("/investigate")
async def investigate(request: Request):
    configured = service(request)
    values = await body(request, Selected)
    return await operation(configured.investigate(request.state.gmail_session, values.references,
                           consent=values.consent, history_consent=request.headers.get("x-susnot-record-history")))


@router.post("/disconnect")
async def disconnect(request: Request):
    return await operation(service(request).disconnect(request.state.gmail_session))
