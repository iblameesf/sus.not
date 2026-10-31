"""Local readiness uses fake config/Keychain; no OAuth, provider or model calls."""

import asyncio
from copy import deepcopy
import json
import socket
from uuid import uuid4

from fastapi import FastAPI
import pytest

from backend import gmail_readiness as checks, gmail_oauth, gmail_google
from backend.gmail_callback import LoopbackCallback, valid_loopback_redirect
from backend.gmail_routes import router as api_routes
from backend.gmail_security import GmailControl, GmailControlMiddleware, router as control_routes
from backend.gmail_tokens import CredentialStoreError, SERVICE, VERIFICATION_SERVICE
from test_gmail_tokens import FakeKeychain
from test_gmail_oauth import integration, authorize

SECRET = "SYNTHETIC-READINESS-SECRET"


def config_data():
    return {"installed": {"client_id": "synthetic-readiness.apps.googleusercontent.com", "client_secret": SECRET,
                           "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token",
                           "project_id": "not-a-real-project", "redirect_uris": ["http://localhost"]}}


@pytest.fixture
def local(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail("Readiness attempted network/authorization")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(LoopbackCallback, "open", forbidden)
    monkeypatch.setattr(gmail_oauth.GmailService, "begin", forbidden)
    monkeypatch.setattr(gmail_oauth.GmailService, "restore", forbidden)
    for method in ("exchange", "revoke", "profile", "list_ids", "metadata", "raw"):
        monkeypatch.setattr(gmail_google.GoogleAPI, method, forbidden)
    monkeypatch.setattr(checks.text_investigator, "get_ollama_client", forbidden)
    monkeypatch.setattr(checks.orchestration, "mcp_connection", forbidden)
    path = tmp_path / "synthetic-desktop.json"
    path.write_text(json.dumps(config_data()))
    path.chmod(0o600)
    app = FastAPI()
    app.state.gmail_control, app.state.gmail_service = GmailControl(), None
    app.add_middleware(GmailControlMiddleware, control=app.state.gmail_control)
    app.include_router(control_routes)
    app.include_router(api_routes)
    backend = FakeKeychain()
    def factory(*, service):
        assert service == VERIFICATION_SERVICE
        return backend
    return path, app, backend, factory


def report(local, **kwargs):
    path, app, _, factory = local
    return asyncio.run(checks.readiness(str(path), app=app, backend_factory=factory, **kwargs))


def test_local_readiness_pass_with_synthetic_verification_no_external_calls(local, caplog):
    result = report(local, verify_keychain=True)
    assert result["status"] == "local_checks_passed"
    assert result["blocking_reasons"] == []
    assert result["checks"]["runtime_readonly_scope"] == "passed"
    assert result["checks"]["trusted_launcher_and_fastapi_security"] == "passed_inprocess_probes"
    assert result["checks"]["declared_redirects"] == "compatible_loopback_roots"
    assert result["keychain_verification"]["cleanup"] == "confirmed_absent"
    assert not local[2].items
    assert not local[1].state.gmail_control._sessions
    assert result["google_cloud_verified"] is False
    assert result["authorization_started"] is False
    assert result["callback_listener_opened"] is False
    assert result["gmail_requests_performed"] is False
    assert "google_audience_and_test_user" in result["unverified_prerequisites"]
    assert SECRET not in json.dumps(result) and SECRET not in caplog.text
    assert str(local[0]) not in json.dumps(result)
    assert "synthetic-readiness.apps.googleusercontent.com" not in json.dumps(result)


def test_read_only_default_does_not_claim_write_readiness(local):
    result = report(local)
    assert result["status"] == "needs_local_verification"
    assert result["checks"]["keychain"] == "read_available_write_unverified"
    assert not local[2].items
    assert result["keychain_verification"]["writes_performed"] is False


def test_missing_configuration_never_scans_or_discovers_credentials(local, monkeypatch):
    _, app, _, factory = local
    monkeypatch.setattr(checks, "load_desktop_client", lambda _: pytest.fail("Implicit config read"))
    result = asyncio.run(checks.readiness(app=app, backend_factory=factory))
    assert result["status"] == "blocked"
    assert result["checks"]["client_configuration"] == "missing"
    assert result["blocking_reasons"] == ["supply_private_desktop_client_config_path"]


@pytest.mark.parametrize("change", ["web", "missing_id", "bad_id", "bad_secret", "wrong_auth", "wrong_token", "remote_redirect", "fixed_path", "bad_redirect_type"])
def test_invalid_desktop_configuration_is_blocked_without_echo(local, change):
    path = local[0]
    data = deepcopy(config_data())
    fields = data["installed"]
    if change == "web":
        data = {"web": fields}
    elif change == "missing_id":
        del fields["client_id"]
    elif change == "bad_id":
        fields["client_id"] = SECRET
    elif change == "bad_secret":
        fields["client_secret"] = None
    elif change == "wrong_auth":
        fields["auth_uri"] = "https://untrusted.invalid/auth"
    elif change == "wrong_token":
        fields["token_uri"] = "https://untrusted.invalid/token"
    elif change == "remote_redirect":
        fields["redirect_uris"] = ["https://untrusted.invalid/" ]
    elif change == "fixed_path":
        fields["redirect_uris"] = ["http://localhost/arbitrary-path"]
    else:
        fields["redirect_uris"] = "http://localhost"
    path.write_text(json.dumps(data))
    result = report(local)
    assert result["status"] == "blocked"
    assert result["checks"]["client_configuration"] == "invalid_or_unreadable"
    assert SECRET not in json.dumps(result)


def test_missing_declared_redirects_uses_runtime_policy_not_fabricated_registration(local):
    data = config_data()
    del data["installed"]["redirect_uris"]
    local[0].write_text(json.dumps(data))
    result = report(local, verify_keychain=True)
    assert result["status"] == "local_checks_passed"
    assert result["checks"]["declared_redirects"] == "not_declared_runtime_strategy_checked"
    assert result["google_cloud_verified"] is False


@pytest.mark.parametrize("uri,declared,runtime", [
    ("http://localhost", True, False), ("http://127.0.0.1/", True, False), ("http://[::1]/", True, False),
    ("http://127.0.0.1:54321/", True, True), ("https://127.0.0.1:54321/", False, False),
    ("http://127.0.0.1:54321/oauth/callback/random", False, False),
    ("http://user:secret@127.0.0.1/", False, False), ("http://127.0.0.1:99999/", False, False),
    ("http://@127.0.0.1:54321/", False, False), ("http://:@127.0.0.1:54321/", False, False),
    ("http://127.0.0.1/?secret=value", False, False), ("http://127.0.0.1/#fragment", False, False),
    ("http://127.0.0.1:54321/\n", False, False), (" http://localhost", False, False),
])
def test_loopback_compatibility(uri, declared, runtime):
    assert valid_loopback_redirect(uri) is declared
    assert valid_loopback_redirect(uri, require_port=True) is runtime


@pytest.mark.parametrize("target", ["oauth", "tokens", "google"])
def test_scope_drift_is_blocked(local, monkeypatch, target):
    module = {"oauth": checks.gmail_oauth, "tokens": checks.gmail_tokens, "google": checks.gmail_google}[target]
    monkeypatch.setattr(module, "GMAIL_READONLY_SCOPE", "https://www.googleapis.com/auth/gmail.modify")
    result = report(local)
    assert "runtime_scope_must_be_exactly_gmail_readonly" in result["blocking_reasons"]


def test_private_file_permissions_reused(local):
    local[0].chmod(0o644)
    result = report(local)
    assert result["checks"]["client_configuration"] == "invalid_or_unreadable"


def test_guardrail_drift_and_missing_middleware_are_blocked(local, monkeypatch):
    monkeypatch.setattr(checks.orchestration, "ALLOWED_TOOLS", frozenset({"inspect_text", "shell"}))
    monkeypatch.setattr(checks.text_investigator, "OLLAMA_BASE_URL", "https://external.invalid")
    app = local[1]
    app.user_middleware.clear()
    result = report(local)
    assert "restore_local_ai_and_tool_allowlist" in result["blocking_reasons"]
    assert "fix_launcher_or_control_plane_security" in result["blocking_reasons"]


def test_outer_cors_grants_fail_readiness(local):
    from fastapi.middleware.cors import CORSMiddleware
    local[1].add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    result = report(local)
    assert "fix_launcher_or_control_plane_security" in result["blocking_reasons"]


def test_readiness_does_not_invalidate_other_sessions(local):
    app = local[1]
    credentials = app.state.gmail_control.issue_session()
    session = app.state.gmail_control.authenticate(credentials.bearer)
    session.authorization.transition("authorization_pending")
    session.authorization.transition("connected", account_id=uuid4())  # Synthetic state only.
    result = report(local)
    assert result["checks"]["trusted_launcher_and_fastapi_security"] == "passed_inprocess_probes"
    assert app.state.gmail_control.authenticate(credentials.bearer) is session
    assert session.authorization.state == "connected"
    app.state.gmail_control.close(session)


def test_keychain_failure_or_unconfirmed_cleanup_blocks(local):
    def failed_factory(**kwargs):
        raise CredentialStoreError(-25308)
    path, app, backend, _ = local
    result = asyncio.run(checks.readiness(str(path), app=app, backend_factory=failed_factory))
    assert result["checks"]["keychain"] == "failed"
    assert result["keychain_verification"]["os_status"] == -25308
    backend.delete = lambda _: None  # Simulate failed deletion without an OS exception.
    result = report(local, verify_keychain=True)
    assert result["status"] == "blocked"
    assert result["keychain_verification"]["cleanup"] == "unconfirmed_manual_cleanup_required"
    backend.items.clear()


def test_keychain_production_namespace_never_read(local):
    local[2]._service = SERVICE
    local[2].get = lambda _: pytest.fail("Production namespace read")
    result = report(local)
    assert result["checks"]["keychain"] == "failed"
    assert result["keychain_verification"]["code"] == "wrong_keychain_namespace"


def test_cli_safe_output_and_exit_codes(local, monkeypatch, capsys):
    async def checking(path, verify_keychain):
        return await checks.readiness_original(path, verify_keychain=verify_keychain, app=local[1], backend_factory=local[3])
    monkeypatch.setattr(checks, "readiness_original", checks.readiness, raising=False)
    monkeypatch.setattr(checks, "readiness", checking)
    assert checks.main([]) == 1
    assert checks.main(["--client-config", str(local[0])]) == 2
    assert checks.main(["--client-config", str(local[0]), "--verify-keychain"]) == 0
    output = capsys.readouterr().out
    assert SECRET not in output and str(local[0]) not in output


def test_identity_is_explicit_and_evidence_is_in_memory(integration):
    from backend.gmail_launcher import TrustedLauncher
    e, opened = integration, []
    def browser(uri):
        opened.append(uri)
        return True
    async def exercise():
        async with TrustedLauncher(e["client"].app, confirmed=True, browser_opener=browser) as launcher:
            await launcher.authorize(consent=True)
            from urllib.parse import parse_qs, urlencode, urlsplit
            params = parse_qs(urlsplit(opened[0]).query)
            await e["service"].complete(launcher._session, params["redirect_uri"][0],
                                       urlencode({"state": params["state"][0], "code": "synthetic-code"}))
            from backend.gmail_launcher import LauncherError
            with pytest.raises(LauncherError):
                await launcher.identity(consent=False)
            before = len(e["requests"])
            identity = await launcher.identity(consent=True)
            assert identity == {"address": "authorized@example.com", "source": "gmail_profile"}
            assert len(e["requests"]) == before + 1
            assert not any(r.url.path.endswith("/messages") for r in e["requests"])
            await launcher.list_messages(consent=True)
            await launcher.investigate([1], consent=True)
            before = len(e["requests"])
            with pytest.raises(LauncherError):
                await launcher.evidence(consent=False)
            evidence = await launcher.evidence(consent=True)
            assert evidence["results"][0]["report"]["evidence"]
            assert len(e["requests"]) == before  # Cached report view does not fetch Gmail.
            await launcher.disconnect(consent=True)
            assert launcher._last_result is None
            with pytest.raises(LauncherError):
                await launcher.evidence(consent=True)
        assert launcher._last_result is launcher._report_context is None
    e["client"].portal.call(exercise)


def test_identity_endpoint_is_protected_and_does_not_authorize(integration):
    e = integration
    assert e["client"].get("/gmail/account").status_code == 401
    assert e["client"].get("/gmail/account", headers={**e["headers"], "Origin": "https://untrusted.invalid"}).status_code == 403
    assert e["client"].get("/gmail/account", headers=e["headers"]).status_code == 401
    assert not e["requests"]


def test_cached_evidence_expires_with_control_session(integration):
    from backend.gmail_launcher import TrustedLauncher, LauncherError
    from urllib.parse import parse_qs, urlencode, urlsplit
    e, opened = integration, []
    def browser(uri):
        opened.append(uri)
        return True
    async def exercise():
        async with TrustedLauncher(e["client"].app, confirmed=True, browser_opener=browser) as launcher:
            await launcher.authorize(consent=True)
            query = parse_qs(urlsplit(opened[0]).query)
            await e["service"].complete(launcher._session, query["redirect_uri"][0], urlencode({"state": query["state"][0], "code": "synthetic-code"}))
            await launcher.list_messages(consent=True)
            await launcher.investigate([1], consent=True)
            e["clock"][0] += 1800
            with pytest.raises(LauncherError):
                await launcher.evidence(consent=True)
            assert launcher._last_result is launcher._report_context is None
    e["client"].portal.call(exercise)


def test_disconnect_detects_unsuccessful_keychain_deletion(integration):
    e = integration
    authorize(e, remember=True)
    e["backend"].delete = lambda _: None
    response = e["client"].post("/gmail/disconnect", headers=e["headers"])
    assert response.json()["disconnected"] is True
    assert response.json()["credentials_removed"] is False
    assert "credential_storage_unavailable" in response.json()["errors"]
    e["backend"].items.clear()  # Only a synthetic mock backend exists.
