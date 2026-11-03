"""Desktop PKCE and token lifecycle coordinator; inert until trusted configuration."""

import asyncio
import base64
from dataclasses import dataclass, field
from hashlib import sha256
import re
import secrets
import time
from urllib.parse import parse_qs, urlencode
from uuid import UUID, uuid4

from pydantic import SecretStr

from backend.gmail_callback import LoopbackCallback, valid_loopback_redirect
from backend.gmail_google import GoogleAPI, GmailError, token_response
from backend.gmail_tokens import (
    CredentialStoreError, GMAIL_READONLY_SCOPE,
    MacOSKeychainStore,
)
from backend.gmail_state import AuthorizationError

AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"


@dataclass(frozen=True, repr=False)
class DesktopClient:
    client_id: str
    client_secret: SecretStr
    redirect_uris: tuple[str, ...] = ()

    @classmethod
    def from_google_config(cls, data):
        """Parse an already-loaded Desktop/installed config; never read files or log it."""
        from backend.gmail_connector import GOOGLE_TOKEN_ENDPOINT
        try:
            installed = data["installed"]
            if ("web" in data or installed["auth_uri"] not in {AUTHORIZATION_ENDPOINT, "https://accounts.google.com/o/oauth2/auth"}
                    or installed["token_uri"] != GOOGLE_TOKEN_ENDPOINT):
                raise ValueError()
            redirects = installed.get("redirect_uris", [])
            if not isinstance(redirects, list):
                raise ValueError()
            return cls(installed["client_id"], SecretStr(installed["client_secret"]), tuple(redirects))
        except (KeyError, TypeError, ValueError):
            raise ValueError("Use the Google Desktop application (installed) configuration.") from None

    def __post_init__(self):
        if (not isinstance(self.client_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,240}\.apps\.googleusercontent\.com", self.client_id)
                or not isinstance(self.client_secret, SecretStr) or not isinstance(self.client_secret.get_secret_value(), str)
                or not 0 < len(self.client_secret.get_secret_value()) <= 1024
                or not isinstance(self.redirect_uris, tuple) or len(self.redirect_uris) > 8
                or not all(valid_loopback_redirect(uri) for uri in self.redirect_uris)):
            raise ValueError("A Google Desktop application configuration is required.")


@dataclass(repr=False)
class Pending:
    state_digest: bytes
    verifier: str
    challenge: str
    redirect_uri: str
    expires_at: float
    listener: object
    timer: object = None

    def close(self):
        self.listener.close()
        if self.timer:
            self.timer.cancel()


@dataclass(repr=False)
class Connection:
    session: object
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    credentials: object = None
    account_id: object = None
    address: str | None = None
    remember: bool = False
    pending: Pending | None = None
    last_error: str | None = None
    literals: set = field(default_factory=set)


class GmailService:
    def __init__(self, client: DesktopClient, control, *, api=None, store=None,
                 callback_factory=LoopbackCallback, clock=time.monotonic, wall_clock=time.time):
        self.client, self.control = client, control
        self.api, self.store = api or GoogleAPI(), store or MacOSKeychainStore()
        self.callback_factory, self.clock, self.wall_clock = callback_factory, clock, wall_clock
        self._connections = {}
        self._worker = asyncio.Lock()

    def _connection(self, session):
        session.authorization.ensure_live()
        if session.session_id not in self._connections:
            conn = Connection(session)
            conn.literals.add(self.client.client_secret.get_secret_value())
            self._connections[session.session_id] = conn
            session.cleanup = lambda: self.drop(session)
        return self._connections[session.session_id]

    def drop(self, session):
        conn = self._connections.pop(session.session_id, None)
        if conn:
            if conn.pending:
                conn.pending.close()
                conn.pending = None
            conn.credentials = None
            conn.literals.clear()
        # Remembered Keychain entries deliberately survive local capability closure.

    def close(self):
        for conn in list(self._connections.values()):
            self.control.close(conn.session)

    async def restore(self, session, account_id):
        """Trusted launcher-only explicit restore of a known Keychain binding; not HTTP."""
        conn = self._connection(session)
        async with conn.lock:
            if not isinstance(account_id, UUID) or session.authorization.state != "disconnected" or conn.credentials:
                raise GmailError("invalid_restore", 409)
            session.authorization.transition("authorization_pending")
            conn.account_id, conn.remember = account_id, True
            try:
                credentials = self.store.load(account_id)
                if credentials is None or credentials.account_identity is None:
                    raise GmailError("reauthorization_required", 401)
                expected_address = credentials.account_identity.get_secret_value()
                renewed = False
                if credentials.expires_at <= self.wall_clock() + 30:
                    if credentials.refresh_token is None:
                        raise GmailError("reauthorization_required", 401)
                    credentials = token_response(await self.api.exchange({
                        "grant_type": "refresh_token", "refresh_token": credentials.refresh_token.get_secret_value(),
                        "client_id": self.client.client_id, "client_secret": self.client.client_secret.get_secret_value(),
                    }), now=self.wall_clock(), previous=credentials)
                    renewed = True
                session.authorization.ensure_live()
                if session.authorization.state != "authorization_pending":
                    raise GmailError("authorization_expired", 401)
                address = await self.api.profile(credentials.access_token.get_secret_value())
                if address != expected_address:
                    raise GmailError("account_mismatch", 401)
                credentials = credentials.model_copy(update={"account_identity": SecretStr(address)})
                session.authorization.ensure_live()
                self._remember_literals(conn, credentials)
                if renewed:
                    self.store.save(account_id, credentials)
                session.authorization.transition("connected", account_id=account_id)
                conn.credentials, conn.address = credentials, address
            except Exception as error:
                if session.authorization.state == "authorization_pending":
                    session.authorization.transition("error")
                if isinstance(error, GmailError):
                    raise
                raise GmailError("credential_storage_unavailable", 503) from None

    def _expire(self, conn, pending):
        if conn.pending is pending:
            pending.close()
            conn.pending = None
            conn.last_error = "authorization_expired"
            if conn.session.authorization.state == "authorization_pending":
                try:
                    conn.session.authorization.ensure_live()
                except AuthorizationError:
                    return  # Idle control expiry is expected, not an unhandled timer error.
                conn.session.authorization.transition("error")

    async def begin(self, session, *, consent: bool, remember: bool):
        if consent is not True or type(remember) is not bool:
            raise GmailError("consent_required", 422)
        conn = self._connection(session)
        async with conn.lock:
            if (session.authorization.state not in {"disconnected", "revoked", "error"} or conn.credentials is not None
                    or (conn.remember and conn.account_id is not None)):
                raise GmailError("disconnect_before_authorizing", 409)
            session.authorization.transition("authorization_pending")
            conn.last_error = None
            listener = self.callback_factory()
            try:
                uri = await listener.open(lambda redirect, query: self.complete(session, redirect, query))
                if session.authorization.state != "authorization_pending" or self._connections.get(session.session_id) is not conn:
                    raise GmailError("authorization_expired", 401)
                if not valid_loopback_redirect(uri, require_port=True):
                    raise GmailError("invalid_redirect_uri")
                state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
                challenge = base64.urlsafe_b64encode(sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                pending = Pending(sha256(state.encode()).digest(), verifier, challenge, uri, self.clock() + 300, listener)
                conn.pending, conn.remember = pending, remember
                pending.timer = asyncio.get_running_loop().call_later(300, self._expire, conn, pending)
                return {"authorization_url": AUTHORIZATION_ENDPOINT + "?" + urlencode({
                    "client_id": self.client.client_id, "redirect_uri": uri, "response_type": "code",
                    "scope": GMAIL_READONLY_SCOPE, "state": state, "code_challenge": challenge,
                    "code_challenge_method": "S256", "access_type": "offline" if remember else "online",
                    **({"prompt": "consent"} if remember else {}),
                }), "expires_in": 300, "permission_notice": (
                    "Gmail read-only permission is mailbox-wide, not limited by Google to selected messages. "
                    "SUS.NOT enforces explicit selection, uses local AI, and does not modify email."
                )}
            except Exception:
                listener.close()
                if session.authorization.state == "authorization_pending":
                    session.authorization.transition("error")
                raise GmailError("authorization_start_failed", 503) from None

    async def complete(self, session, redirect_uri, query):
        conn = self._connections.get(session.session_id)
        if conn is None:
            raise GmailError("invalid_callback", 400)
        async with conn.lock:
            pending = conn.pending
            try:
                params = parse_qs(query, keep_blank_values=True, strict_parsing=True, max_num_fields=10)
                state = params.get("state", [None])
                if (pending is None or redirect_uri != pending.redirect_uri or len(query) > 8192
                        or any(key not in {"state", "code", "error", "error_description", "error_uri", "scope", "authuser", "prompt", "hd", "iss"} for key in params)
                        or ("iss" in params and params["iss"] != ["https://accounts.google.com"])
                        or any(len(values) != 1 for values in params.values()) or len(state) != 1
                        or not isinstance(state[0], str) or len(state[0]) != 43
                        or not secrets.compare_digest(sha256(state[0].encode()).digest(), pending.state_digest)):
                    raise ValueError()
            except (ValueError, TypeError):
                raise GmailError("invalid_callback", 400) from None
            # Consume once, before code exchange; a failure requires a new explicit flow.
            conn.pending = None
            pending.close()
            account_id = uuid4()
            saved, credentials = False, None
            try:
                session.authorization.ensure_live()
                if self.clock() >= pending.expires_at or session.authorization.state != "authorization_pending":
                    raise GmailError("authorization_expired", 401)
                challenge = base64.urlsafe_b64encode(sha256(pending.verifier.encode()).digest()).rstrip(b"=").decode()
                if not re.fullmatch(r"[A-Za-z0-9_-]{86}", pending.verifier) or not secrets.compare_digest(challenge, pending.challenge):
                    raise GmailError("invalid_pkce", 400)
                if "error" in params:
                    raise GmailError("authorization_denied", 401)
                code = params.get("code", [None])[0]
                if not isinstance(code, str) or not 0 < len(code) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in code):
                    raise GmailError("invalid_callback", 400)
                result = await self.api.exchange({
                    "grant_type": "authorization_code", "client_id": self.client.client_id,
                    "client_secret": self.client.client_secret.get_secret_value(), "code": code,
                    "code_verifier": pending.verifier, "redirect_uri": pending.redirect_uri,
                })
                credentials = token_response(result, now=self.wall_clock())
                if conn.remember and credentials.refresh_token is None:
                    raise GmailError("refresh_token_missing")
                session.authorization.ensure_live()
                if session.authorization.state != "authorization_pending":
                    raise GmailError("authorization_expired", 401)
                address = await self.api.profile(credentials.access_token.get_secret_value())
                session.authorization.ensure_live()
                if session.authorization.state != "authorization_pending":
                    raise GmailError("authorization_expired", 401)
                credentials = credentials.model_copy(update={"account_identity": SecretStr(address)})
                self._remember_literals(conn, credentials)
                if conn.remember:
                    conn.account_id = account_id  # Keep an opaque cleanup handle if storage fails midway.
                    saved = True
                    self.store.save(account_id, credentials)
                session.authorization.transition("connected", account_id=account_id)
                conn.credentials, conn.address, conn.account_id = credentials, address, account_id
            except Exception as error:
                conn.last_error = error.code if isinstance(error, GmailError) else (
                    "authorization_expired" if isinstance(error, AuthorizationError) else "credential_storage_unavailable")
                if credentials is not None:
                    try:
                        await self.api.revoke((credentials.refresh_token or credentials.access_token).get_secret_value())
                    except Exception:
                        pass  # Failed setup never grants local access; remote cleanup is best effort.
                if saved:
                    try:
                        self.store.delete(account_id)
                        conn.account_id = None
                    except CredentialStoreError:
                        pass
                if session.authorization.state == "authorization_pending":
                    session.authorization.transition("error")
                if isinstance(error, GmailError):
                    raise
                if isinstance(error, AuthorizationError):
                    raise GmailError("authorization_expired", 401) from None
                raise GmailError("credential_storage_unavailable" if isinstance(error, CredentialStoreError)
                                 else "authorization_failed", 503) from None

    @staticmethod
    def _remember_literals(conn, credentials):
        if len(conn.literals) > 60:
            raise GmailError("reauthorization_required", 401)
        conn.literals.add(credentials.access_token.get_secret_value())
        if credentials.refresh_token:
            conn.literals.add(credentials.refresh_token.get_secret_value())

    async def access(self, conn, *, force=False):
        async with conn.lock:
            conn.session.authorization.ensure_live()
            credentials = conn.credentials
            state = conn.session.authorization.state
            if credentials is None or state not in {"connected", "expired"}:
                raise GmailError("not_connected", 401)
            if not force and state == "connected" and credentials.expires_at > self.wall_clock() + 30:
                with conn.session.authorization.connected_context(conn.session.session_id):
                    return credentials.access_token.get_secret_value()
            if state == "connected" and (force or credentials.expires_at <= self.wall_clock()):
                conn.session.authorization.transition("expired")
            if not credentials.refresh_token:
                raise GmailError("reauthorization_required", 401)
            try:
                result = await self.api.exchange({
                    "grant_type": "refresh_token", "refresh_token": credentials.refresh_token.get_secret_value(),
                    "client_id": self.client.client_id, "client_secret": self.client.client_secret.get_secret_value(),
                })
                renewed = token_response(result, now=self.wall_clock(), previous=credentials)
                conn.session.authorization.ensure_live()
                if conn.session.authorization.state not in {"connected", "expired"}:
                    raise GmailError("authorization_expired", 401)
                address = await self.api.profile(renewed.access_token.get_secret_value())
                if address != conn.address:
                    raise GmailError("account_mismatch", 401)
                conn.session.authorization.ensure_live()
                if conn.session.authorization.state not in {"connected", "expired"}:
                    raise GmailError("authorization_expired", 401)
                renewed = renewed.model_copy(update={"account_identity": SecretStr(address)})
                self._remember_literals(conn, renewed)
                conn.credentials = renewed  # Keep rotated credentials for explicit revocation even if persistence fails.
                if conn.remember:
                    self.store.save(conn.account_id, renewed)
                if conn.session.authorization.state == "expired":
                    conn.session.authorization.transition("connected", account_id=conn.account_id)
                with conn.session.authorization.connected_context(conn.session.session_id):
                    conn.last_error = None
                    return renewed.access_token.get_secret_value()
            except Exception as error:
                conn.last_error = error.code if isinstance(error, GmailError) else "credential_storage_unavailable"
                if isinstance(error, GmailError) and error.code == "authorization_revoked":
                    if conn.session.authorization.state in {"connected", "expired"}:
                        conn.session.authorization.transition("revoked")
                    conn.credentials = None
                    if conn.remember:
                        try:
                            self.store.delete(conn.account_id)
                        except CredentialStoreError:
                            raise GmailError("credential_storage_unavailable", 503) from None
                elif isinstance(error, CredentialStoreError) or (isinstance(error, GmailError) and error.code in {
                    "account_mismatch", "invalid_scope", "invalid_token_response", "reauthorization_required",
                }):
                    if conn.session.authorization.state in {"connected", "expired"}:
                        conn.session.authorization.transition("error")
                if isinstance(error, GmailError):
                    raise
                raise GmailError("credential_storage_unavailable", 503) from None

    async def call(self, conn, operation, *args):
        access = await self.access(conn)
        with conn.session.authorization.connected_context(conn.session.session_id) as context:
            pass
        try:
            return await operation(access, *args)
        except GmailError as error:
            if error.code != "access_expired":
                raise
        # A single coordinated refresh/retry, never an unbounded retry loop.
        async with conn.lock:
            changed = conn.credentials and conn.credentials.access_token.get_secret_value() != access
        if not changed:
            await self.access(conn, force=True)
        access = await self.access(conn)
        with conn.session.authorization.connected_context(conn.session.session_id) as current:
            if current != context:
                raise GmailError("authorization_changed_reselect", 409)
        return await operation(access, *args)

    async def disconnect(self, session):
        conn = self._connection(session)
        session.authorization.disconnect()
        self.control.selections.invalidate_session(session.session_id)

        if conn.pending:
            conn.pending.close()
            conn.pending = None

        errors = []
        revoked = False
        removed = True

        if conn.credentials:
            token = conn.credentials.refresh_token or conn.credentials.access_token
            try:
                await self.api.revoke(token.get_secret_value())
                revoked = True
            except GmailError:
                errors.append("revocation_unconfirmed")

        if conn.remember and conn.account_id:
            try:
                self.store.delete(conn.account_id)
                if self.store.load(conn.account_id) is not None:
                    raise CredentialStoreError()
            except CredentialStoreError:
                removed = False
                errors.append("credential_storage_unavailable")

        conn.credentials = None

        if removed:
            conn.remember = False
            conn.account_id, conn.address = None, None

        return {
            "disconnected": True,
            "google_revocation_performed": revoked,
            "credentials_removed": removed,
            "errors": errors,
        }

    def connector(self, session):
        from backend.gmail_connector import GoogleGmailConnector
        conn = self._connection(session)
        return GoogleGmailConnector(session.session_id, session.authorization, self.control.selections, service=self, connection=conn)

    async def investigate(self, session, references, *, consent, history_consent=None):
        from backend.email_guardian import investigate_email
        from backend.email_parser import EmailParseError
        from backend.gmail_connector import ConnectorError
        from backend.text_investigator import ASSESSMENT_LIMITATION
        if consent is not True:
            raise GmailError("consent_required", 422)
        conn = self._connection(session)
        await self.access(conn)  # Expired/changed generations require relisting, not silent rebinding.
        leases = self.control.selections.claim(session.session_id, session.authorization, references)
        connector = self.connector(session)
        results = []
        private_literals = set(conn.literals)
        async with self._worker:  # One local investigation at a time across accounts.
            for index, lease in enumerate(leases):
                try:
                    message = await connector.retrieve_selected(lease)
                    context = connector._context()
                    private_literals.update(conn.literals)
                    report = await investigate_email(message.content, history_consent, blocked_literals=tuple(private_literals))
                    private_literals.update(conn.literals)
                    if connector._context() != context:
                        raise GmailError("authorization_expired", 401)
                    results.append({"selection_index": index, "status": report.status, "report": report.model_dump()})
                except Exception as error:
                    code = error.code if isinstance(error, (GmailError, EmailParseError, ConnectorError)) else "selected_investigation_failed"
                    results.append({"selection_index": index, "status": "failed", "error": code,
                                    "recommended_advisory_action": "review_before_proceeding"})
        # Guard only model-owned prose. A credential coincidentally equal to an
        # action/version must not rewrite deterministic policy, evidence IDs or scores.
        # One pass avoids repeatedly expanding replacement markers for short literals.
        # Never compile an empty alternative: it matches every position.
        # Ignore empty credential literals while preserving redaction.
        protected_literals = [
            value for value in private_literals
            if isinstance(value, str) and value
        ]
        pattern = (
            re.compile("|".join(
                re.escape(value)
                for value in sorted(protected_literals, key=len, reverse=True)
            ))
            if protected_literals else None
        )
        def scrub(value, limit):
            return (pattern.sub("[credential redacted]", value) if pattern else value)[:limit]
        for item in results:
            report = item.get("report")
            if not report or not report["ai_text_assessment"]:
                continue
            ai = report["ai_text_assessment"]
            original_assessment = ai.copy()
            original_uncertainty = ai["uncertainty"]
            ai["indicators"] = [scrub(value, 300) for value in ai["indicators"]]
            for name in ("explanation", "recommendation"):
                ai[name] = scrub(ai[name], 1500)
            if pattern is not None and pattern.search(original_uncertainty):
                prefix = original_uncertainty.removesuffix(ASSESSMENT_LIMITATION).rstrip()
                ai["uncertainty"] = scrub(prefix, 1000 - len(ASSESSMENT_LIMITATION) - 2) + "\n\n" + ASSESSMENT_LIMITATION
            if ai != original_assessment:
                report["privacy_redactions_applied"] = True
            report["uncertainty"] = [ai["uncertainty"] if value == original_uncertainty else value for value in report["uncertainty"]]
            for evidence in report["evidence"]:
                if evidence["source_component"] == "inspect_text":
                    evidence["finding"] = scrub(evidence["finding"], 300)
        return {"status": "completed" if all(item["status"] == "completed" for item in results) else "partial",
                "results": results}
