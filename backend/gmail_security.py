"""Isolated Gmail control plane; OAuth uses a separate PKCE loopback receiver."""

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_address
import secrets
from threading import RLock
import time
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse
from starlette._utils import get_route_path

from backend.gmail_selections import SelectionRegistry
from backend.gmail_state import AuthorizationMachine


@dataclass(frozen=True, repr=False)
class ControlCredentials:
    session_id: UUID
    bearer: str
    csrf: str


@dataclass(repr=False)
class _Session:
    session_id: UUID
    bearer_digest: bytes
    csrf_digest: bytes
    expires_at: float
    authorization: AuthorizationMachine
    cleanup: object = None


class GmailControl:
    """Capabilities may only be issued by a trusted future desktop launcher/IPC."""

    def __init__(self, *, clock=time.monotonic):
        self._clock = clock
        self._sessions = {}
        self._lock = RLock()
        self.selections = SelectionRegistry(clock=clock)

    def _invalidate(self, session):
        session.authorization.invalidate()
        self.selections.invalidate_session(session.session_id)
        if session.cleanup:
            session.cleanup()
            session.cleanup = None

    def _purge(self):
        for key, value in list(self._sessions.items()):
            if value.expires_at <= self._clock():
                self._invalidate(value)
                del self._sessions[key]

    def issue_session(self) -> ControlCredentials:
        # Not exposed over HTTP; never print or automatically write these secrets.
        with self._lock:
            self._purge()
            if len(self._sessions) >= 16:
                raise RuntimeError("Local control session limit reached.")
            credentials = ControlCredentials(uuid4(), secrets.token_urlsafe(32), secrets.token_urlsafe(32))
            deadline = self._clock() + 1800
            record = _Session(credentials.session_id, sha256(credentials.bearer.encode()).digest(),
                              sha256(credentials.csrf.encode()).digest(), deadline,
                              AuthorizationMachine(clock=self._clock, valid_until=deadline))
            self._sessions[record.bearer_digest] = record
            return credentials

    def authenticate(self, bearer: str, csrf: str | None = None, *, mutation=False) -> _Session | None:
        if len(bearer) != 43 or not bearer.isascii():
            return None
        with self._lock:
            self._purge()
            record = self._sessions.get(sha256(bearer.encode()).digest())
            if record is None:
                return None
            if mutation and (csrf is None or len(csrf) != 43 or not csrf.isascii() or not secrets.compare_digest(
                record.csrf_digest, sha256(csrf.encode()).digest(),
            )):
                return None
            return record

    def close(self, session: _Session) -> None:
        with self._lock:
            self._sessions.pop(session.bearer_digest, None)
            self._invalidate(session)


class GmailControlMiddleware:
    """Protect the entire /gmail prefix, including unknown routes and preflights."""

    def __init__(self, app, *, control: GmailControl, origin="http://127.0.0.1:8000"):
        # Server-owned configuration only. Origin is deliberately not inferred from Host.
        if origin not in {"http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"}:
            raise ValueError("Unsupported local control origin")
        self.app, self.control, self.origin = app, control, origin
        self.host = origin.removeprefix("http://")

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        if not (scope.get("path", "").startswith("/gmail") or get_route_path(scope).startswith("/gmail")):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return

        async def reject(status):
            await JSONResponse({"detail": "Gmail control request denied."}, status_code=status,
                               headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})(scope, receive, send)

        try:
            local = ip_address(scope["client"][0]).is_loopback
        except (ValueError, TypeError, KeyError, IndexError):
            local = False
        # Duplicate critical headers are ambiguous; never pick the first/last one.
        headers = {}
        critical = {b"host", b"origin", b"authorization", b"x-susnot-csrf", b"sec-fetch-site"}
        for key, value in scope["headers"]:
            key = key.lower()
            if key in critical and key in headers:
                await reject(400)
                return
            headers[key] = value
        if (not local or scope.get("scheme") != "http" or headers.get(b"host") != self.host.encode()
                or any(key == b"forwarded" or key.startswith(b"x-forwarded-") for key in headers)):
            await reject(403)
            return
        if (b"origin" in headers and headers[b"origin"] != self.origin.encode()) or (
            b"sec-fetch-site" in headers and headers[b"sec-fetch-site"] != b"same-origin"
        ):
            await reject(403)
            return
        # No CORS grants or cookie auth. Cross-origin preflight is never approved.
        if scope["method"] == "OPTIONS":
            await reject(403)
            return
        authorization = headers.get(b"authorization", b"")
        if not authorization.startswith(b"Bearer "):
            await reject(401)
            return
        try:
            session = self.control.authenticate(
                authorization[7:].decode("ascii"), headers.get(b"x-susnot-csrf", b"").decode("ascii"),
                mutation=scope["method"] not in {"GET", "HEAD"},
            )
        except UnicodeError:
            session = None
        if session is None:
            await reject(401)
            return
        scope.setdefault("state", {})["gmail_session"] = session

        async def private_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = [(key, value) for key, value in message.get("headers", [])
                                      if key.lower() not in {b"cache-control", b"access-control-allow-origin", b"access-control-allow-credentials"}]
                message["headers"].extend([(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")])
            await send(message)
        await self.app(scope, receive, private_send)


router = APIRouter(prefix="/gmail", tags=["Gmail foundation"])


@router.get("/status")
def status(request: Request):
    session = request.state.gmail_session
    enabled = getattr(request.app.state, "gmail_service", None) is not None
    result = {"state": session.authorization.state.value, "oauth_enabled": enabled, "connector_enabled": enabled}
    if enabled:
        connection = request.app.state.gmail_service._connections.get(session.session_id)
        result["last_error"] = connection.last_error if connection else None
    return result


@router.post("/session/close")
async def close_session(request: Request):
    # Ends the local capability only. This is NOT Google grant revocation.
    request.app.state.gmail_control.close(request.state.gmail_session)
    return {"closed": True, "google_revocation_performed": False}
