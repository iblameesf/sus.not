"""Offline/local Gmail readiness checks. Never starts OAuth or calls Google/Ollama."""

import argparse
import asyncio
import json
from uuid import uuid4

import httpx

from backend import gmail_oauth, gmail_google, gmail_tokens, orchestration, text_investigator
from backend.gmail_callback import LoopbackCallback, valid_loopback_redirect
from backend.gmail_launcher import TrustedLauncher, load_desktop_client, ORIGIN
from backend.gmail_security import GmailControl, GmailControlMiddleware
from backend.gmail_keychain_verify import verify_backend
from backend.gmail_tokens import CredentialStoreError, VERIFICATION_SERVICE, _SecurityFramework

EXPECTED_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def keychain_check(*, full=False, backend_factory=_SecurityFramework):
    """Only a fresh synthetic verification-namespace item, never production tokens."""
    try:
        backend = backend_factory(service=VERIFICATION_SERVICE)
        if getattr(backend, "_service", VERIFICATION_SERVICE) != VERIFICATION_SERVICE:
            return "failed", {"code": "wrong_keychain_namespace"}
        if full:
            report = verify_backend(backend)
            return ("passed" if report["success"] else "failed"), report
        store = gmail_tokens.MacOSKeychainStore(backend, service=VERIFICATION_SERVICE)
        if store.load(uuid4()) is not None:
            return "failed", {"code": "unexpected_verification_item"}
        return "read_available_write_unverified", {"writes_performed": False, "production_credentials_read": False}
    except Exception as error:
        return "failed", {"code": "keychain_unavailable",
                          "os_status": error.os_status if isinstance(error, CredentialStoreError) else None}


async def control_check(app):
    """Exercise actual middleware with a disposable in-process session; no lifecycle shutdown."""
    control = getattr(app.state, "gmail_control", None)
    if not isinstance(control, GmailControl) or not any(
        entry.cls is GmailControlMiddleware and entry.kwargs.get("control") is control for entry in app.user_middleware
    ):
        return False
    try:
        async with TrustedLauncher(app, confirmed=True, browser_opener=lambda _: False) as launcher:
            status = await launcher.status()
            if status["state"] != "disconnected":
                return False
            credentials = launcher._credentials
            headers = {"Authorization": "Bearer " + credentials.bearer, "X-SUSNOT-CSRF": credentials.csrf}
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 0), raise_app_exceptions=False),
                                         base_url=ORIGIN, trust_env=False, follow_redirects=False) as client:
                cases = [
                    ("GET", "/gmail/status", {}, 401),
                    ("GET", "/gmail/status", {"Authorization": "Bearer " + "x" * 43}, 401),
                    ("GET", "/gmail/status", {**headers, "Origin": "https://untrusted.invalid"}, 403),
                    ("GET", "/gmail/status", {**headers, "Host": "untrusted.invalid:8000"}, 403),
                    ("OPTIONS", "/gmail/status", {"Origin": "https://untrusted.invalid", "Access-Control-Request-Method": "POST",
                                                    "Access-Control-Request-Headers": "authorization,x-susnot-csrf"}, 403),
                    ("GET", "/gmail/status", {**headers, "X-Forwarded-For": "127.0.0.1"}, 403),
                    ("POST", "/gmail/session/close", {"Authorization": headers["Authorization"]}, 401),
                ]
                for method, path, values, expected in cases:
                    response = await client.request(method, path, headers=values)
                    if (response.status_code != expected or response.headers.get("cache-control") != "no-store"
                            or "access-control-allow-origin" in response.headers):
                        return False
                closed = await client.post("/gmail/session/close", headers=headers)
                if closed.status_code != 200 or closed.json().get("closed") is not True:
                    return False
                if (await client.get("/gmail/status", headers=headers)).status_code != 401:
                    return False
        return True
    except Exception:
        return False


async def readiness(config_path=None, *, verify_keychain=False, app=None, backend_factory=_SecurityFramework):
    if app is None:
        from backend.main import app
    checks, blocking, unverified = {}, [], [
        "google_project_and_gmail_api_enabled", "google_audience_and_test_user",
        "google_data_access_scope", "google_desktop_client_registration",
        "real_browser_google_callback_interoperability", "ollama_running_and_model_installed",
        "live_test_requires_separate_explicit_approval",
    ]
    client = None
    if config_path is None:
        checks["client_configuration"] = "missing"
        blocking.append("supply_private_desktop_client_config_path")
    else:
        try:
            client = load_desktop_client(config_path)
            checks["client_configuration"] = "passed"
        except Exception:
            checks["client_configuration"] = "invalid_or_unreadable"
            blocking.append("fix_private_desktop_client_configuration")
    checks["client_id_and_installed_type"] = "passed_local_shape_only" if client else "not_checked"
    checks["declared_redirects"] = ("compatible_loopback_roots" if client and client.redirect_uris else
                                    "not_declared_runtime_strategy_checked" if client else "not_checked")
    scope_ok = (gmail_tokens.GMAIL_READONLY_SCOPE == gmail_oauth.GMAIL_READONLY_SCOPE == gmail_google.GMAIL_READONLY_SCOPE == EXPECTED_SCOPE
                and gmail_tokens.OAuthCredentials.model_fields["scopes"].default == (EXPECTED_SCOPE,))
    checks["runtime_readonly_scope"] = "passed" if scope_ok else "failed"
    if not scope_ok:
        blocking.append("runtime_scope_must_be_exactly_gmail_readonly")
    # Inspect the callback strategy without opening a socket or creating a transaction.
    redirect_ok = (LoopbackCallback().path == "/"
                   and valid_loopback_redirect("http://127.0.0.1:54321/", require_port=True)
                   and not valid_loopback_redirect("https://untrusted.invalid/", require_port=True))
    checks["runtime_redirect_strategy"] = "passed_root_loopback_dynamic_port" if redirect_ok else "failed"
    if not redirect_ok:
        blocking.append("fix_desktop_loopback_strategy")
    guards_ok = (orchestration.ALLOWED_TOOLS == frozenset({"inspect_url", "inspect_text"})
                 and text_investigator.OLLAMA_BASE_URL == "http://127.0.0.1:11434")
    checks["local_ai_and_mcp_allowlist"] = "passed_static_configuration" if guards_ok else "failed"
    if not guards_ok:
        blocking.append("restore_local_ai_and_tool_allowlist")
    try:
        security = await control_check(app)
    except Exception:
        security = False
    checks["trusted_launcher_and_fastapi_security"] = "passed_inprocess_probes" if security else "failed"
    if not security:
        blocking.append("fix_launcher_or_control_plane_security")
    keychain_status, keychain_report = keychain_check(full=verify_keychain, backend_factory=backend_factory)
    checks["keychain"] = keychain_status
    if keychain_status == "failed":
        blocking.append("keychain_access_or_cleanup_failed")
    elif keychain_status != "passed":
        unverified.append("keychain_write_update_delete_use_verify_keychain_option")
    status = "blocked" if blocking else "local_checks_passed" if keychain_status == "passed" else "needs_local_verification"
    return {"status": status, "checks": checks, "blocking_reasons": blocking, "unverified_prerequisites": unverified,
            "required_scope": EXPECTED_SCOPE, "keychain_verification": keychain_report,
            "google_cloud_verified": False, "authorization_started": False,
            "gmail_requests_performed": False, "callback_listener_opened": False,
            "note": "Local checks are not proof of Google configuration or permission to start a live test."}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local-only readiness; no OAuth, browser, Gmail or model requests.")
    parser.add_argument("--client-config", metavar="PRIVATE_PATH", help="Existing operator-owned Desktop JSON outside the repository; never displayed")
    parser.add_argument("--verify-keychain", action="store_true", help="Explicitly allow isolated synthetic Keychain CRUD and cleanup; default is read-only probe")
    args = parser.parse_args(argv)
    try:
        report = asyncio.run(readiness(args.client_config, verify_keychain=args.verify_keychain))
        print(json.dumps(report, sort_keys=True))
        return {"local_checks_passed": 0, "blocked": 1, "needs_local_verification": 2}[report["status"]]
    except Exception:
        print(json.dumps({"status": "blocked", "code": "local_readiness_check_failed", "authorization_started": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
