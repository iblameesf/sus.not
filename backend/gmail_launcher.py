"""Explicit terminal launcher; private in-process ASGI, no browser bootstrap/server."""

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import parse_qs, urlsplit
from uuid import UUID
import webbrowser

import httpx

from backend.gmail_oauth import AUTHORIZATION_ENDPOINT, DesktopClient, GmailService
from backend.gmail_callback import valid_loopback_redirect
from backend.gmail_state import AuthorizationState

ORIGIN = "http://127.0.0.1:8000"
OPERATIONS = {
    "status": ("GET", "/gmail/status"), "identity": ("GET", "/gmail/account"),
    "authorize": ("POST", "/gmail/oauth/start"),
    "list": ("GET", "/gmail/messages"), "investigate": ("POST", "/gmail/investigate"),
    "disconnect": ("POST", "/gmail/disconnect"),
}


class LauncherError(RuntimeError):
    def __init__(self):
        super().__init__("Local operation rejected or failed. Check consent/session state and the verification guide.")


def load_desktop_client(path: str) -> DesktopClient:
    """Later operator-supplied config only: private regular file outside the repo."""
    try:
        candidate = Path(path).expanduser().resolve(strict=True)
        root = Path(__file__).resolve().parents[1]
        if candidate.is_relative_to(root) or Path(path).expanduser().is_symlink():
            raise LauncherError()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        descriptor = os.open(candidate, flags)
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                    or info.st_nlink != 1 or not 0 < info.st_size <= 16384):
                raise LauncherError()
            payload = source.read(16385)
            if len(payload) > 16384:
                raise LauncherError()
        return DesktopClient.from_google_config(json.loads(payload))
    except Exception:
        raise LauncherError() from None


class TrustedLauncher:
    """Trusted Python entry, not an HTTP API. No capabilities are handed to browsers."""

    def __init__(self, app, *, confirmed: bool, browser_opener=webbrowser.open):
        if confirmed is not True:
            raise LauncherError()
        self._app, self._opener = app, browser_opener
        self._client = self._credentials = self._session = None
        self._references, self._next_page = (), None
        self._last_result = self._report_context = None

    async def __aenter__(self):
        if self._client is not None:
            raise LauncherError()
        control = self._app.state.gmail_control
        self._credentials = control.issue_session()
        self._session = control.authenticate(self._credentials.bearer)
        try:
            self._client = httpx.AsyncClient(
                transport=httpx.ASGITransport(app=self._app, client=("127.0.0.1", 0)),
                base_url=ORIGIN, follow_redirects=False, trust_env=False,
            )
            return self
        except Exception:
            await self.close()
            raise LauncherError() from None

    async def __aexit__(self, *exc):
        await self.close()

    async def close(self):
        try:
            if self._session:
                self._app.state.gmail_control.close(self._session)
        finally:
            if self._client:
                await self._client.aclose()
            self._client = self._credentials = self._session = None
            self._references, self._next_page = (), None
            self._last_result = self._report_context = None

    async def _request(self, operation, *, payload=None, params=None, record_history=False):
        if self._client is None or self._credentials is None or operation not in OPERATIONS:
            raise LauncherError()
        method, path = OPERATIONS[operation]
        headers = {"Authorization": "Bearer " + self._credentials.bearer,
                   "X-SUSNOT-CSRF": self._credentials.csrf, "Origin": ORIGIN,
                   "Sec-Fetch-Site": "same-origin"}
        if record_history:
            headers["X-SUSNOT-Record-History"] = "true"
        try:
            async with asyncio.timeout(900):
                response = await self._client.request(method, path, headers=headers, json=payload, params=params)
            if response.status_code != 200:
                raise LauncherError()
            value = response.json()
            if not isinstance(value, dict):
                raise LauncherError()
            return value
        except Exception:
            raise LauncherError() from None

    async def status(self):
        result = await self._request("status")
        if (result.get("state") not in AuthorizationState._value2member_map_
                or type(result.get("oauth_enabled")) is not bool or type(result.get("connector_enabled")) is not bool):
            raise LauncherError()
        return {key: result[key] for key in ("state", "oauth_enabled", "connector_enabled")}

    async def identity(self, *, consent: bool):
        if consent is not True:
            raise LauncherError()
        result = await self._request("identity")
        address = result.get("address")
        if (result.get("source") != "gmail_profile" or not isinstance(address, str) or len(address) > 254
                or not re.fullmatch(r"[^\s@]{1,64}@[^\s@]{1,189}", address)):
            raise LauncherError()
        return {"address": address, "source": "gmail_profile"}

    async def evidence(self, *, consent: bool):
        if consent is not True or self._last_result is None:
            raise LauncherError()
        try:
            await self.status()  # Retain the middleware capability/expiry boundary for views.
            with self._session.authorization.connected_context(self._session.session_id) as current:
                if current != self._report_context:
                    raise LauncherError()
            return self._last_result
        except Exception:
            self._last_result = self._report_context = None
            raise LauncherError() from None

    async def authorize(self, *, consent: bool, remember=False):
        if consent is not True or type(remember) is not bool:
            raise LauncherError()
        self._last_result = self._report_context = None
        result = await self._request("authorize", payload={"consent": True, "remember": remember})
        try:
            uri = result["authorization_url"]
            parsed, fixed = urlsplit(uri), urlsplit(AUTHORIZATION_ENDPOINT)
            query = parse_qs(parsed.query, strict_parsing=True, max_num_fields=10)
            required = {"client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method", "access_type"}
            if (len(uri) > 4096 or (parsed.scheme, parsed.netloc, parsed.path) != (fixed.scheme, fixed.netloc, fixed.path)
                    or parsed.fragment or not required <= query.keys() or query.keys() - required - {"prompt"}
                    or any(len(values) != 1 for values in query.values())):
                raise LauncherError()
            from backend.gmail_tokens import GMAIL_READONLY_SCOPE
            configured = self._app.state.gmail_service
            if (query["client_id"] != [configured.client.client_id] or query["scope"] != [GMAIL_READONLY_SCOPE]
                    or query["response_type"] != ["code"] or query["code_challenge_method"] != ["S256"]
                    or query["access_type"] != ["offline" if remember else "online"]
                    or query.get("prompt") != (["consent"] if remember else None)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{43}", query["state"][0])
                    or not re.fullmatch(r"[A-Za-z0-9_-]{43}", query["code_challenge"][0])
                    or not valid_loopback_redirect(query["redirect_uri"][0], require_port=True)
                    or self._credentials.bearer in uri or self._credentials.csrf in uri):
                raise LauncherError()
            if await asyncio.to_thread(self._opener, uri) is not True:
                raise LauncherError()
            return {"browser_opened": True, "expires_in": 300}
        except Exception:
            # Fail closed, including unexpected/malicious browser destinations.
            self._app.state.gmail_control.close(self._session)
            raise LauncherError() from None

    async def list_messages(self, *, consent: bool, next_page=False):
        if consent is not True or type(next_page) is not bool or (next_page and self._next_page is None):
            raise LauncherError()
        params = {"limit": 20}
        if next_page:
            params["page_token"] = self._next_page
        self._references = ()
        result = await self._request("list", params=params)
        messages, token = result.get("messages"), result.get("next_page_token")
        if (not isinstance(messages, list) or len(messages) > 20
                or (token is not None and (not isinstance(token, str) or not 0 < len(token) <= 256))):
            raise LauncherError()
        references, display = [], []
        for index, item in enumerate(messages, 1):
            if (not isinstance(item, dict) or not isinstance(item.get("reference"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{43}", item["reference"])
                    or not all(isinstance(item.get(field), str) and len(item[field]) <= 2048 for field in ("sender", "subject", "date"))):
                raise LauncherError()
            references.append(item["reference"])
            display.append({"index": index, **{key: item[key] for key in ("sender", "subject", "date")}})
        if len(set(references)) != len(references):
            raise LauncherError()
        self._references, self._next_page = tuple(references), token
        return display

    async def investigate(self, indices: list[int], *, consent: bool, record_history=False):
        if (consent is not True or type(record_history) is not bool or not isinstance(indices, list)
                or not 1 <= len(indices) <= 5 or not all(type(index) is int and 1 <= index <= len(self._references) for index in indices)
                or len(set(indices)) != len(indices)):
            raise LauncherError()
        references = [self._references[index - 1] for index in indices]
        self._last_result = self._report_context = None
        try:
            result = await self._request("investigate", payload={"consent": True, "references": references}, record_history=record_history)
            with self._session.authorization.connected_context(self._session.session_id) as context:
                self._last_result, self._report_context = result, context
            return result
        finally:
            self._references = ()  # No implicit retry or stale terminal selection reuse.

    async def disconnect(self, *, consent: bool):
        if consent is not True:
            raise LauncherError()
        self._references, self._next_page = (), None
        self._last_result = self._report_context = None
        result = await self._request("disconnect")
        return {key: result.get(key) is True for key in ("disconnected", "google_revocation_performed", "credentials_removed")}


def summary(result):
    """Terminal output excludes raw/model prose, subjects, message IDs and references."""
    actions = {"continue_with_caution", "review_before_proceeding", "show_warning"}
    output = []
    for index, item in enumerate(result.get("results", [])[:5], 1):
        report = item.get("report") or {}
        advisory = report.get("recommended_advisory_action", {})
        try:
            identifier = str(UUID(report.get("investigation_id")))
        except (ValueError, TypeError, AttributeError):
            identifier = None
        output.append({"selection_index": index, "status": item.get("status") if item.get("status") in {"completed", "partial", "failed"} else "failed",
                       "investigation_id": identifier,
                       "action": advisory.get("action") if advisory.get("action") in actions else "review_before_proceeding",
                       "policy_version": "email-1" if advisory.get("policy_version") == "email-1" else None,
                       "evidence_count": len(report.get("evidence", [])), "error_count": len(report.get("errors", [])) + int("error" in item)})
    return {"results": output}


async def terminal_line(prompt):
    """macOS/Unix TTY input without blocking callback/timer processing or a read thread."""
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    descriptor = sys.stdin.fileno()
    print(prompt, end="", flush=True)
    def ready():
        if future.done():
            return
        try:
            line = sys.stdin.readline(4097)
            if not line:
                future.set_exception(EOFError())
            elif len(line) > 4096:
                future.set_exception(LauncherError())
            else:
                future.set_result(line.rstrip("\r\n"))
        except Exception:
            future.set_exception(LauncherError())
    loop.add_reader(descriptor, ready)
    try:
        return await future
    finally:
        loop.remove_reader(descriptor)


async def interactive(app, *, ask=None, emit=print, browser_opener=webbrowser.open):
    async def question(prompt):
        return await terminal_line(prompt) if ask is None else await asyncio.to_thread(ask, prompt)
    async with app.router.lifespan_context(app), TrustedLauncher(app, confirmed=True, browser_opener=browser_opener) as launcher:
        emit("Commands: status, identity, authorize, list, more, investigate, evidence, disconnect, quit. No automatic collection.")
        while True:
            try:
                command = (await question("sus.not> ")).strip().lower()
                if command in {"quit", "q", "exit"}:
                    return
                if command == "status":
                    emit(json.dumps(await launcher.status(), ensure_ascii=True))
                elif command == "identity":
                    if await question("Type IDENTITY to read/display the authorized Gmail profile address: ") == "IDENTITY":
                        emit(json.dumps(await launcher.identity(consent=True), ensure_ascii=True))
                elif command == "evidence":
                    if await question("Findings may contain private information. Type EVIDENCE to display the latest in-memory report: ") == "EVIDENCE":
                        emit(json.dumps(await launcher.evidence(consent=True), ensure_ascii=True, indent=2))
                elif command == "authorize":
                    emit("Google read-only permission is mailbox-wide. SUS.NOT enforces selection; AI remains local.")
                    if await question("Type AUTHORIZE to open Google in the system browser: ") != "AUTHORIZE":
                        continue
                    remember = await question("Type REMEMBER to persist credentials in macOS Keychain; Enter for session-only: ") == "REMEMBER"
                    await launcher.authorize(consent=True, remember=remember)
                    emit("Browser opened. Complete authorization there, then request status. No messages are loaded automatically.")
                elif command in {"list", "more"}:
                    for item in await launcher.list_messages(consent=True, next_page=command == "more"):
                        emit(json.dumps(item, ensure_ascii=True))  # Escape ANSI/control/bidi text.
                elif command == "investigate":
                    indices = [int(value.strip()) for value in (await question("Choose up to five current page indices, comma-separated: ")).split(",")]
                    if await question("Type INVESTIGATE to fetch and locally analyze only these selections: ") != "INVESTIGATE":
                        continue
                    record = await question("Type RECORD to opt into minimized history (also requires server enablement); Enter for none: ") == "RECORD"
                    emit(json.dumps(summary(await launcher.investigate(indices, consent=True, record_history=record)), ensure_ascii=True))
                elif command == "disconnect":
                    if await question("Type DISCONNECT to revoke and remove this connection's credentials: ") == "DISCONNECT":
                        emit(json.dumps(await launcher.disconnect(consent=True)))
                else:
                    emit("Choose a listed command.")
            except (LauncherError, ValueError):
                emit("Operation rejected or failed. Check authorization/consent; reload selections if needed. No safety conclusion is implied.")
            except (EOFError, KeyboardInterrupt):
                return


def main(argv=None):
    parser = argparse.ArgumentParser(description="Explicit trusted local terminal; no HTTP bootstrap or automatic OAuth.")
    parser.add_argument("--client-config", metavar="PRIVATE_PATH", help="Future operator-supplied Desktop config outside the repository; does not start OAuth")
    args = parser.parse_args(argv)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Interactive local terminal required; no session was issued.", file=sys.stderr)
        return 2
    try:
        if input("Type START to create a private, expiring local control session (no OAuth/messages yet): ") != "START":
            return 0
        from backend.main import app
        if args.client_config:
            client = load_desktop_client(args.client_config)
            app.state.gmail_service = GmailService(client, app.state.gmail_control)
        # CLI-only logging policy; existing server/dashboard processes are untouched.
        for name in ("httpx", "httpcore"):
            logging.getLogger(name).setLevel(logging.WARNING)
        asyncio.run(interactive(app))
        return 0
    except (LauncherError, EOFError, KeyboardInterrupt):
        print("Launcher closed or configuration unavailable. No plaintext fallback; see the local verification guide.")
        return 1
    except Exception:
        print("Launcher failed closed; see the local verification guide.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
