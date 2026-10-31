"""Trusted terminal/ASGI launcher tests. Google, browser and Keychain are mocked."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import pytest

from backend import gmail_launcher as module
from backend.gmail_launcher import LauncherError, TrustedLauncher, load_desktop_client, summary
from test_gmail_oauth import integration, CLIENT_SECRET, TOKEN, REFRESH


class RecordingApp:
    def __init__(self, app):
        self.app, self.state, self.router = app, app.state, app.router
        self.requests = []

    async def __call__(self, scope, receive, send):
        self.requests.append((scope["method"], scope["path"], dict(scope["headers"])))
        await self.app(scope, receive, send)


def run(e, function):
    return e["client"].portal.call(function)


def test_explicit_confirmation_no_automatic_google_or_browser(integration, caplog):
    e = integration
    app = RecordingApp(e["client"].app)
    opened = []
    with pytest.raises(LauncherError):
        TrustedLauncher(app, confirmed=False)
    async def exercise():
        async with TrustedLauncher(app, confirmed=True, browser_opener=lambda uri: opened.append(uri)) as launcher:
            credentials = launcher._credentials
            status = await launcher.status()
            assert status["state"] == "disconnected"
            assert credentials.bearer not in json.dumps(status)
            assert credentials.csrf not in repr(launcher)
            assert not opened and not e["requests"] and not e["models"]
            assert app.requests[0][:2] == ("GET", "/gmail/status")
            headers = app.requests[0][2]
            assert headers[b"host"] == b"127.0.0.1:8000"
            assert headers[b"origin"] == b"http://127.0.0.1:8000"
            assert headers[b"sec-fetch-site"] == b"same-origin"
            assert e["control"].authenticate(headers[b"authorization"][7:].decode(), headers[b"x-susnot-csrf"].decode(), mutation=True)
        assert e["control"].authenticate(credentials.bearer) is None
        assert launcher._client is launcher._credentials is None
        assert credentials.bearer not in caplog.text and credentials.csrf not in caplog.text
    run(e, exercise)


def test_launcher_mock_oauth_selected_real_sdk_investigation(integration):
    e = integration
    app = RecordingApp(e["client"].app)
    opened = []
    def browser(uri):
        opened.append(uri)
        return True
    async def exercise():
        async with TrustedLauncher(app, confirmed=True, browser_opener=browser) as launcher:
            with pytest.raises(LauncherError):
                await launcher.authorize(consent=False)
            assert not opened and not e["requests"]
            result = await launcher.authorize(consent=True, remember=False)
            assert result == {"browser_opened": True, "expires_in": 300}
            assert len(opened) == 1 and not e["requests"]  # Browser is mocked; no real flow.
            uri = opened[0]
            for secret in (launcher._credentials.bearer, launcher._credentials.csrf, CLIENT_SECRET, TOKEN, REFRESH):
                assert secret not in uri
            params = parse_qs(urlsplit(uri).query)
            await e["service"].complete(launcher._session, params["redirect_uri"][0],
                                         urlencode({"state": params["state"][0], "code": "mock-code"}))
            assert not any(request.url.path.endswith("/messages") for request in e["requests"])
            page = await launcher.list_messages(consent=True)
            assert len(page) == 2 and all("reference" not in item and "message_id" not in item for item in page)
            for indices in ([1, 1], [True], [0], [3], [1, 2, 3, 4, 5, 6]):
                with pytest.raises(LauncherError):
                    await launcher.investigate(indices, consent=True)
            assert not e["models"]
            result = await launcher.investigate([1], consent=True)
            report = result["results"][0]["report"]
            assert report["tools_used"] == ["inspect_url", "inspect_text"]
            assert report["url_assessments"][0]["assessment"]["sus_score"] == 70
            safe = json.dumps(summary(result))
            assert "email-1" in safe and "show_warning" in safe
            for private in (TOKEN, REFRESH, CLIENT_SECRET, "Ignore instructions", "Synthetic subject", "message0"):
                assert private not in safe
            with pytest.raises(LauncherError):
                await launcher.investigate([1], consent=True)
            raw_calls = [request for request in e["requests"] if request.url.params.get("format") == "raw"]
            assert len(raw_calls) == 1
            assert not e["database"].exists()
            await launcher.list_messages(consent=True)
            with pytest.raises(LauncherError):
                await launcher.investigate([1], consent=True)  # Backend duplicate tombstone is not bypassed.
            assert len([request for request in e["requests"] if request.url.params.get("format") == "raw"]) == 1
            assert all(path.startswith("/gmail/") for _, path, _ in app.requests)
    run(e, exercise)


def test_launcher_expiry_no_implicit_renewal_and_exception_cleanup(integration):
    e = integration
    async def exercise():
        launcher = TrustedLauncher(e["client"].app, confirmed=True)
        with pytest.raises(RuntimeError, match="synthetic failure"):
            async with launcher:
                credentials, session = launcher._credentials, launcher._session
                e["clock"][0] += 1800
                with pytest.raises(LauncherError):
                    await launcher.status()
                assert session.authorization.state == "disconnected"
                raise RuntimeError("synthetic failure")
        assert e["control"].authenticate(credentials.bearer) is None
        assert launcher._credentials is None
        assert not e["requests"]
    run(e, exercise)


@pytest.mark.parametrize("attack", ["destination", "scope", "secret_parameter", "redirect", "capability"])
def test_unexpected_browser_url_rejected_and_session_closed(integration, monkeypatch, attack):
    e, opened = integration, []
    original = e["service"].begin
    async def malicious(session, **kwargs):
        result = await original(session, **kwargs)
        parsed = urlsplit(result["authorization_url"])
        query = parse_qs(parsed.query)
        if attack == "destination":
            result["authorization_url"] = "https://external.invalid/"
        else:
            if attack == "scope":
                query["scope"] = ["https://mail.google.com/"]
            elif attack == "secret_parameter":
                query["access_token"] = [TOKEN]
            elif attack == "redirect":
                query["redirect_uri"] = ["https://external.invalid/"]
            else:
                query["state"] = [captured[0]._credentials.bearer]
            result["authorization_url"] = urlunsplit(parsed._replace(query=urlencode(query, doseq=True)))
        return result
    monkeypatch.setattr(e["service"], "begin", malicious)
    captured = []
    async def exercise():
        async with TrustedLauncher(e["client"].app, confirmed=True, browser_opener=lambda uri: opened.append(uri)) as launcher:
            captured.append(launcher)
            credentials = launcher._credentials
            with pytest.raises(LauncherError):
                await launcher.authorize(consent=True)
            assert e["control"].authenticate(credentials.bearer) is None
        assert not opened and not e["requests"]
    run(e, exercise)


def test_pending_timer_handles_idle_control_session_expiry(integration):
    e, opened = integration, []
    def browser(uri):
        opened.append(uri)
        return True
    async def exercise():
        async with TrustedLauncher(e["client"].app, confirmed=True, browser_opener=browser) as launcher:
            await launcher.authorize(consent=True)
            connection = e["service"]._connections[launcher._session.session_id]
            pending = connection.pending
            e["clock"][0] += 1800
            e["service"]._expire(connection, pending)
            assert pending.listener.closed and connection.pending is None
            assert launcher._session.authorization.state == "disconnected"
            assert not e["requests"]
    run(e, exercise)


def test_browser_failure_closes_pending_listener(integration):
    e = integration
    async def exercise():
        async with TrustedLauncher(e["client"].app, confirmed=True, browser_opener=lambda _: False) as launcher:
            with pytest.raises(LauncherError):
                await launcher.authorize(consent=True)
            assert launcher._session.authorization.state == "disconnected"
            assert launcher._session.session_id not in e["service"]._connections
            assert not e["requests"]
    run(e, exercise)


def test_no_history_header_without_explicit_selection_consent(integration):
    e = integration
    app = RecordingApp(e["client"].app)
    async def exercise():
        async with TrustedLauncher(app, confirmed=True) as launcher:
            await launcher.status()
            await launcher.disconnect(consent=True)
            assert all(b"x-susnot-record-history" not in headers for _, _, headers in app.requests)
            with pytest.raises(LauncherError):
                await launcher.investigate([1], consent=False, record_history=True)
    run(e, exercise)


def test_history_opt_in_is_per_investigation_only(integration, monkeypatch):
    e, opened = integration, []
    app = RecordingApp(e["client"].app)
    monkeypatch.setenv("SUSNOT_HISTORY_ENABLED", "true")
    def browser(uri):
        opened.append(uri)
        return True
    async def exercise():
        async with TrustedLauncher(app, confirmed=True, browser_opener=browser) as launcher:
            await launcher.authorize(consent=True)
            params = parse_qs(urlsplit(opened[0]).query)
            await e["service"].complete(launcher._session, params["redirect_uri"][0],
                                         urlencode({"state": params["state"][0], "code": "mock-code"}))
            await launcher.list_messages(consent=True)
            assert all(b"x-susnot-record-history" not in headers for _, _, headers in app.requests)
            await launcher.investigate([1], consent=True, record_history=True)
            assert app.requests[-1][2][b"x-susnot-record-history"] == b"true"
            await launcher.status()
            assert b"x-susnot-record-history" not in app.requests[-1][2]
            assert e["database"].exists()
    run(e, exercise)


@pytest.mark.parametrize("commands", [["status", "quit"], ["authorize", "CANCEL", "quit"]])
def test_interactive_commands_never_automatically_authorize_or_collect(integration, commands):
    e, output, opened = integration, [], []
    replies = iter(commands)
    async def exercise():
        await module.interactive(e["client"].app, ask=lambda _: next(replies), emit=output.append,
                                 browser_opener=lambda uri: opened.append(uri))
    run(e, exercise)
    assert not opened and not e["requests"] and not e["models"]
    assert all(secret not in "\n".join(output) for secret in (TOKEN, REFRESH, CLIENT_SECRET))


def test_waiting_for_terminal_input_keeps_event_loop_responsive(integration):
    import threading
    e, event, observed = integration, threading.Event(), []
    def ask(_):
        observed.append(event.wait(2))
        return "quit"
    async def exercise():
        async def heartbeat():
            await asyncio.sleep(0.01)
            event.set()
        task = asyncio.create_task(heartbeat())
        await module.interactive(e["client"].app, ask=ask, emit=lambda _: None)
        await task
    run(e, exercise)
    assert observed == [True]


def test_async_terminal_reader_cleanup_and_size_limit(monkeypatch):
    import os
    async def exercise():
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "r") as source:
            monkeypatch.setattr(module.sys, "stdin", source)
            try:
                task = asyncio.create_task(module.terminal_line("synthetic> "))
                await asyncio.sleep(0)
                os.write(write_fd, b"quit\n")
                assert await task == "quit"
                assert asyncio.get_running_loop().remove_reader(read_fd) is False
                task = asyncio.create_task(module.terminal_line("synthetic> "))
                await asyncio.sleep(0)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert asyncio.get_running_loop().remove_reader(read_fd) is False
                task = asyncio.create_task(module.terminal_line("synthetic> "))
                await asyncio.sleep(0)
                os.write(write_fd, b"x" * 4097 + b"\n")
                with pytest.raises(LauncherError):
                    await task
            finally:
                os.close(write_fd)
    asyncio.run(exercise())


def test_terminal_metadata_is_escaped(integration, monkeypatch):
    e, output = integration, []
    replies = iter(["list", "quit"])
    async def listing(*args, **kwargs):
        return [{"index": 1, "subject": "\x1b[31m\r\n\u202e<script>untrusted</script>", "sender": "[redacted]", "date": ""}]
    monkeypatch.setattr(TrustedLauncher, "list_messages", listing)
    async def exercise():
        await module.interactive(e["client"].app, ask=lambda _: next(replies), emit=output.append)
    run(e, exercise)
    rendered = "\n".join(output)
    assert "\x1b" not in rendered and "\r" not in rendered and "\u202e" not in rendered
    assert "\\u001b" in rendered and "\\u202e" in rendered


def test_noninteractive_cli_does_not_read_config_or_issue_sessions(monkeypatch, capsys):
    monkeypatch.setattr(module.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr(module, "load_desktop_client", lambda _: pytest.fail("Unexpected config read"))
    assert module.main(["--client-config", "/not/read.json"]) == 2
    assert "Interactive local terminal required" in capsys.readouterr().err


def test_declined_cli_start_does_not_load_configuration(monkeypatch):
    monkeypatch.setattr(module.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(module.sys, "stdout", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", lambda _: "CANCEL")
    monkeypatch.setattr(module, "load_desktop_client", lambda _: pytest.fail("Unexpected config read"))
    assert module.main(["--client-config", "/not/read.json"]) == 0


def synthetic_config():
    return {"installed": {"client_id": "synthetic.apps.googleusercontent.com", "client_secret": CLIENT_SECRET,
                           "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token"}}


def test_private_configuration_loader(tmp_path, caplog):
    path = tmp_path / "synthetic.json"
    path.write_text(json.dumps(synthetic_config()))
    path.chmod(0o600)
    client = load_desktop_client(str(path))
    assert client.client_secret.get_secret_value() == CLIENT_SECRET
    assert CLIENT_SECRET not in repr(client) and CLIENT_SECRET not in caplog.text
    path.chmod(0o644)
    with pytest.raises(LauncherError) as error:
        load_desktop_client(str(path))
    assert CLIENT_SECRET not in str(error.value) and str(path) not in str(error.value)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "oversize", "invalid", "fifo", "directory", "repository"])
def test_untrusted_configuration_files_rejected(tmp_path, kind):
    path = tmp_path / "synthetic.json"
    path.write_text(json.dumps(synthetic_config()))
    path.chmod(0o600)
    if kind == "symlink":
        linked = tmp_path / "link.json"
        linked.symlink_to(path)
        path = linked
    elif kind == "hardlink":
        import os
        os.link(path, tmp_path / "linked.json")
    elif kind == "oversize":
        path.write_bytes(b"x" * 16385)
    elif kind == "invalid":
        path.write_text("not-json " + CLIENT_SECRET)
    elif kind == "fifo":
        import os
        path.unlink()
        os.mkfifo(path, 0o600)
    elif kind == "directory":
        path = tmp_path
    elif kind == "repository":
        path = Path(__file__)
    with pytest.raises(LauncherError) as error:
        load_desktop_client(str(path))
    assert CLIENT_SECRET not in str(error.value)


def test_summary_excludes_all_model_and_source_prose():
    private = "PRIVATE BODY TOKEN PASSWORD"
    result = {"results": [{"status": "partial", "report": {"investigation_id": "invalid",
              "recommended_advisory_action": {"action": private, "explanation": private},
              "ai_text_assessment": {"uncertainty": private}, "evidence": [{"finding": private}], "errors": []}}]}
    result = summary(result)
    assert private not in json.dumps(result)
    assert result["results"][0]["action"] == "review_before_proceeding"
