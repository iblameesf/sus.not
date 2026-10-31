"""Fixed-destination, bounded Google protocol transport. No browser or AI calls."""

import asyncio
import base64
import json
import re

import httpx

from backend.email_parser import MAX_EMAIL_BYTES, MAX_PARTS, MAX_DEPTH
from backend.gmail_connector import gmail_endpoint, GOOGLE_TOKEN_ENDPOINT, GOOGLE_REVOCATION_ENDPOINT
from backend.gmail_selections import valid_message_id, MAX_PAGE_SIZE
from backend.gmail_tokens import GMAIL_READONLY_SCOPE, OAuthCredentials


class GmailError(RuntimeError):
    def __init__(self, code="google_unavailable", status=502):
        self.code, self.status = code, status
        super().__init__("Gmail operation failed; no safety conclusion is available from this failure.")


def token_response(data, *, now, previous=None):
    """Google, not email/model content, supplies these protocol fields."""
    if not isinstance(data, dict) or not isinstance(data.get("token_type"), str) or data["token_type"].lower() != "bearer":
        raise GmailError("invalid_token_response")
    expires = data.get("expires_in")
    if type(expires) is not int or not 0 < expires <= 86400:
        raise GmailError("invalid_token_response")
    scope = data.get("scope", GMAIL_READONLY_SCOPE if previous else None)
    if scope != GMAIL_READONLY_SCOPE:
        raise GmailError("invalid_scope")
    access, refresh = data.get("access_token"), data.get("refresh_token")
    for value in (access, refresh):
        if value is not None and (not isinstance(value, str) or not 0 < len(value) <= 8192
                                  or any(ord(c) < 33 or ord(c) > 126 for c in value)):
            raise GmailError("invalid_token_response")
    if not access:
        raise GmailError("invalid_token_response")
    return OAuthCredentials(access_token=access,
                            refresh_token=refresh or (previous.refresh_token if previous else None),
                            expires_at=float(now + expires))


def _skeleton_fields(depth=0):
    fields = "mimeType,filename,headers,body(size,attachmentId)"
    # An extra level exposes overflow instead of silently dropping deeper parts.
    return fields + (",parts(" + _skeleton_fields(depth + 1) + ")" if depth <= MAX_DEPTH else ",parts(mimeType)")


def validate_skeleton(data, message_id):
    """Reject attachment-bearing messages BEFORE requesting raw MIME bytes."""
    if not isinstance(data, dict) or data.get("id") != message_id or not isinstance(data.get("payload"), dict):
        raise GmailError("invalid_gmail_response")
    size = data.get("sizeEstimate")
    if type(size) is not int or not 0 < size <= MAX_EMAIL_BYTES:
        raise GmailError("message_size_limit", 413)
    count = 0
    def visit(part, depth):
        nonlocal count
        count += 1
        if not isinstance(part, dict) or depth > MAX_DEPTH or count > MAX_PARTS:
            raise GmailError("mime_limit", 413)
        mime = part.get("mimeType")
        headers, body = part.get("headers", []), part.get("body", {})
        if not isinstance(headers, list) or len(headers) > 50 or not isinstance(body, dict):
            raise GmailError("invalid_gmail_response")
        if part.get("filename") or body.get("attachmentId"):
            raise GmailError("attachments_unsupported", 422)
        for header in headers:
            if (not isinstance(header, dict) or not isinstance(header.get("name"), str)
                    or not isinstance(header.get("value"), str) or len(header["value"]) > 2048):
                raise GmailError("invalid_gmail_response")
            if header["name"].lower() == "content-disposition" and header["value"].lower().split(";", 1)[0].strip() == "attachment":
                raise GmailError("attachments_unsupported", 422)
        parts = part.get("parts", [])
        if not isinstance(parts, list):
            raise GmailError("invalid_gmail_response")
        if isinstance(mime, str) and mime.startswith("multipart/") and parts:
            for child in parts:
                visit(child, depth + 1)
        elif mime not in {"text/plain", "text/html"} or parts:
            raise GmailError("unsupported_mime", 422)
    visit(data["payload"], 0)


class GoogleAPI:
    def __init__(self, *, transport=None):
        # Injection is for trusted tests, never request fields or model output.
        self._transport = transport

    async def _request(self, method, url, *, access=None, params=None, data=None, cap=24576):
        allowed = {GOOGLE_TOKEN_ENDPOINT: "POST", GOOGLE_REVOCATION_ENDPOINT: "POST",
                   gmail_endpoint("profile"): "GET", gmail_endpoint("list"): "GET"}
        if url not in allowed:
            prefix = gmail_endpoint("list") + "/"
            if not url.startswith(prefix) or not valid_message_id(url[len(prefix):]):
                raise GmailError("invalid_destination")
            allowed[url] = "GET"
        if allowed[url] != method:
            raise GmailError("invalid_destination")
        try:
            async with asyncio.timeout(15):
                async with httpx.AsyncClient(transport=self._transport, trust_env=False, follow_redirects=False,
                                             timeout=httpx.Timeout(10, connect=3)) as client:
                    headers = {"Authorization": "Bearer " + access} if access else {}
                    async with client.stream(method, url, headers=headers, params=params, data=data) as response:
                        content = bytearray()
                        async for chunk in response.aiter_bytes(chunk_size=4096):
                            if len(content) + len(chunk) > cap:
                                raise GmailError("google_response_limit", 413)
                            content.extend(chunk)
                        if response.status_code == 200 and url == GOOGLE_REVOCATION_ENDPOINT:
                            return {}
                        # Protocol status remains authoritative even for empty/HTML errors.
                        if response.status_code == 429:
                            raise GmailError("google_rate_limit", 429)
                        if response.status_code == 401:
                            raise GmailError("access_expired", 401)
                        try:
                            result = json.loads(content)
                        except (ValueError, UnicodeError):
                            raise GmailError("invalid_gmail_response") from None
                        error_body = result.get("error") if isinstance(result, dict) else None
                        reasons = error_body.get("errors", []) if isinstance(error_body, dict) else []
                        if (response.status_code == 403 and isinstance(reasons, list)
                            and any(item.get("reason") in {"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"}
                                    for item in reasons if isinstance(item, dict))):
                            raise GmailError("google_rate_limit", 429)
                        if response.status_code == 400 and isinstance(result, dict) and result.get("error") == "invalid_grant":
                            raise GmailError("authorization_revoked", 401)
                        if response.status_code != 200 or not isinstance(result, dict):
                            raise GmailError("google_rejected_request", 502)
                        return result
        except (httpx.TimeoutException, TimeoutError):
            raise GmailError("google_timeout", 504) from None
        except httpx.RequestError:
            raise GmailError("google_unavailable", 503) from None

    async def exchange(self, form):
        return await self._request("POST", GOOGLE_TOKEN_ENDPOINT, data=form)

    async def revoke(self, token):
        await self._request("POST", GOOGLE_REVOCATION_ENDPOINT, data={"token": token})

    async def profile(self, access):
        result = await self._request("GET", gmail_endpoint("profile"), access=access,
                                     params={"fields": "emailAddress"}, cap=4096)
        address = result.get("emailAddress")
        if not isinstance(address, str) or not re.fullmatch(r"[^\s@]{1,64}@[^\s@]{1,189}", address):
            raise GmailError("invalid_account_identity")
        return address.casefold()

    async def list_ids(self, access, limit, page_token):
        params = {"maxResults": limit, "fields": "messages(id),nextPageToken", "includeSpamTrash": "false"}
        if page_token is not None:
            params["pageToken"] = page_token
        result = await self._request("GET", gmail_endpoint("list"), access=access, params=params, cap=16384)
        messages = result.get("messages", [])
        if not isinstance(messages, list) or len(messages) > min(limit, MAX_PAGE_SIZE):
            raise GmailError("invalid_gmail_response")
        ids = [item.get("id") if isinstance(item, dict) else None for item in messages]
        if not all(valid_message_id(value) for value in ids) or len(set(ids)) != len(ids):
            raise GmailError("invalid_gmail_response")
        return ids, result.get("nextPageToken")

    async def metadata(self, access, message_id):
        return await self._request("GET", gmail_endpoint("get", message_id=message_id), access=access, cap=16384,
                                   params={"format": "metadata", "metadataHeaders": ["From", "Subject", "Date"],
                                           "fields": "id,payload(headers)"})

    async def raw(self, access, message_id, *, check=lambda: None):
        check()
        endpoint = gmail_endpoint("get", message_id=message_id)
        skeleton = await self._request("GET", endpoint, access=access, cap=65536,
                                       params={"format": "full", "fields": "id,sizeEstimate,payload(" + _skeleton_fields() + ")"})
        validate_skeleton(skeleton, message_id)
        check()  # Never fetch content after disconnection/expiry during MIME preflight.
        result = await self._request("GET", endpoint, access=access, cap=180000,
                                     params={"format": "raw", "fields": "id,raw"})
        check()
        raw = result.get("raw")
        if (result.get("id") != message_id or not isinstance(raw, str) or len(raw) > 174764
                or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", raw)):
            raise GmailError("invalid_gmail_response")
        try:
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
        except ValueError:
            raise GmailError("invalid_gmail_response") from None
        if not 0 < len(decoded) <= MAX_EMAIL_BYTES:
            raise GmailError("message_size_limit", 413)
        return decoded
