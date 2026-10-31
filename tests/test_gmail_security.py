"""Isolated control-plane tests: no OAuth, real credentials, or Gmail calls."""

from concurrent.futures import ThreadPoolExecutor
import itertools
import secrets
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from backend.gmail_security import GmailControl, GmailControlMiddleware, router
from backend.gmail_selections import SelectionError, SelectionRegistry
from backend.gmail_state import AuthorizationError, AuthorizationMachine, AuthorizationState, TRANSITIONS
from backend.main import app as existing_app


@pytest.fixture
def protected():
    clock = [100.0]
    control = GmailControl(clock=lambda: clock[0])
    app = FastAPI()
    app.state.gmail_control = control
    app.add_middleware(GmailControlMiddleware, control=control)
    app.include_router(router)
    credentials = control.issue_session()  # Trusted in-process bootstrap ONLY.
    headers = {"Authorization": "Bearer " + credentials.bearer, "X-SUSNOT-CSRF": credentials.csrf}
    with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as client:
        yield client, control, credentials, headers, clock


def test_default_deny_and_valid_status(protected):
    client, _, credentials, headers, _ = protected
    assert client.get("/gmail/status").status_code == 401
    assert client.get("/gmail/status", headers={"Authorization": "Bearer " + secrets.token_urlsafe(32)}).status_code == 401
    response = client.get("/gmail/status", headers=headers)
    assert response.json() == {"state": "disconnected", "oauth_enabled": False, "connector_enabled": False}
    assert response.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in response.headers
    assert credentials.bearer not in response.text
    assert credentials.csrf not in response.text
    assert credentials.bearer not in repr(credentials)


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://127.0.0.1:8501", "http://localhost:8000"])
def test_cross_origin_even_with_valid_capabilities(protected, origin):
    client, _, _, headers, _ = protected
    for method, path in [("GET", "/gmail/status"), ("POST", "/gmail/session/close")]:
        response = client.request(method, path, headers={**headers, "Origin": origin})
        assert response.status_code == 403
        assert "access-control-allow-origin" not in response.headers


def test_same_origin_non_browser_and_csrf(protected):
    client, _, credentials, headers, _ = protected
    assert client.get("/gmail/status", headers={**headers, "Origin": "http://127.0.0.1:8000", "Sec-Fetch-Site": "same-origin"}).status_code == 200
    assert client.post("/gmail/session/close", headers={"Authorization": headers["Authorization"]}).status_code == 401
    assert client.post("/gmail/session/close", headers={**headers, "X-SUSNOT-CSRF": "wrong"}).status_code == 401
    assert client.post("/gmail/session/close", headers={"Cookie": f"bearer={credentials.bearer}; csrf={credentials.csrf}"}).status_code == 401
    response = client.post("/gmail/session/close", headers=headers)
    assert response.json() == {"closed": True, "google_revocation_performed": False}
    assert client.get("/gmail/status", headers=headers).status_code == 401


@pytest.mark.parametrize("site", ["cross-site", "same-site", "none"])
def test_browser_fetch_metadata_rejected(protected, site):
    client, _, _, headers, _ = protected
    assert client.get("/gmail/status", headers={**headers, "Sec-Fetch-Site": site}).status_code == 403


@pytest.mark.parametrize("host", ["evil.example:8000", "127.0.0.1.evil.example:8000", "127.0.0.1:9999", "localhost:8000", "127.0.0.1:8000@evil.example"])
def test_host_rebinding_and_other_ports_rejected(protected, host):
    client, _, _, headers, _ = protected
    assert client.get("/gmail/status", headers={**headers, "Host": host}).status_code == 403


def test_remote_peer_and_websocket_rejected(protected):
    client, _, _, headers, _ = protected
    with TestClient(client.app, base_url="http://127.0.0.1:8000", client=("192.0.2.1", 50000)) as remote:
        assert remote.get("/gmail/status", headers=headers).status_code == 403
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/gmail/status", headers=headers):
            pytest.fail("Unexpected Gmail websocket")


def test_preflight_unknown_prefix_and_duplicate_headers(protected):
    client, _, _, headers, _ = protected
    assert client.options("/gmail/status", headers={**headers, "Access-Control-Request-Method": "GET"}).status_code == 403
    assert client.get("/gmail/future-operation").status_code == 401
    assert client.get("/%67mail/status").status_code == 401
    assert client.post("/gmail/authorize", headers=headers).status_code == 404
    for name, value in [("Host", "127.0.0.1:8000"), ("Origin", "http://127.0.0.1:8000"),
                        ("Authorization", headers["Authorization"]), ("X-SUSNOT-CSRF", headers["X-SUSNOT-CSRF"])]:
        raw = [(key, val) for key, val in headers.items() if key.lower() != name.lower()]
        raw += [(name, value), (name, value)]
        assert client.get("/gmail/status", headers=raw).status_code == 400


def test_mounted_root_path_and_forwarded_headers_cannot_bypass_guard(protected):
    client, _, _, headers, _ = protected
    parent = FastAPI()
    parent.mount("/mounted", client.app)
    with TestClient(parent, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 50000)) as mounted:
        assert mounted.get("/mounted/gmail/status").status_code == 401
        assert mounted.get("/mounted/gmail/status", headers=headers).status_code == 200
    for forwarded in ({"X-Forwarded-For": "127.0.0.1"}, {"Forwarded": "for=127.0.0.1"}):
        assert client.get("/gmail/status", headers={**headers, **forwarded}).status_code == 403


def test_session_expiry_bounds_and_privacy(protected, tmp_path, monkeypatch, caplog):
    client, control, credentials, headers, clock = protected
    database = tmp_path / "history.sqlite3"
    monkeypatch.setenv("SUSNOT_HISTORY_ENABLED", "true")
    monkeypatch.setenv("SUSNOT_HISTORY_DB", str(database))
    response = client.get("/gmail/status", headers={**headers, "X-SUSNOT-Record-History": "true"})
    assert response.status_code == 200
    assert not database.exists()
    assert credentials.bearer not in caplog.text and credentials.csrf not in caplog.text
    clock[0] += 1800
    assert client.get("/gmail/status", headers=headers).status_code == 401
    for _ in range(16):
        control.issue_session()
    with pytest.raises(RuntimeError, match="limit"):
        control.issue_session()


def test_close_invalidates_authorization_and_selections(protected):
    client, control, credentials, headers, _ = protected
    session = control.authenticate(credentials.bearer)
    session.authorization.transition("authorization_pending")
    session.authorization.transition("connected", account_id=uuid4())
    ref = control.selections.issue(credentials.session_id, session.authorization, ["message1"])
    assert client.post("/gmail/session/close", headers=headers).status_code == 200
    assert session.authorization.state == "disconnected"
    with pytest.raises(AuthorizationError):
        session.authorization.transition("authorization_pending")
    with pytest.raises(AuthorizationError):
        control.selections.claim(credentials.session_id, session.authorization, ref)


def test_expired_control_session_blocks_internal_operations_before_next_http_request(protected):
    _, control, credentials, _, clock = protected
    session = control.authenticate(credentials.bearer)
    session.authorization.transition("authorization_pending")
    session.authorization.transition("connected", account_id=uuid4())
    clock[0] += 1799
    references = control.selections.issue(credentials.session_id, session.authorization, ["message1"])
    clock[0] += 1  # Selection itself is still fresh; the control session is not.
    with pytest.raises(AuthorizationError):
        control.selections.claim(credentials.session_id, session.authorization, references)
    assert session.authorization.state == "disconnected"


def test_existing_endpoint_compatibility():
    # Existing non-Gmail routes retain their contracts and client access behavior.
    with TestClient(existing_app) as client:
        assert client.get("/health").json() == {"status": "ok", "service": "SUS.NOT"}
        assert client.get("/gmail/status").status_code == 403  # TestClient isn't a loopback peer by default.
        result = client.post("/analyze-url", json={"url": "https://user@192.0.2.1/verify"})
        assert result.status_code == 200 and result.json()["sus_score"] == 70
        assert client.post("/evaluate-url", json={"url": "https://example.com"}).json()["recommended_action"] == "continue_with_caution"


def machine_in(state):
    machine, account = AuthorizationMachine(), uuid4()
    if state != "disconnected":
        machine.transition("authorization_pending")
    if state in {"connected", "expired", "revoked"}:
        machine.transition("connected", account_id=account)
    if state in {"expired", "revoked", "error"}:
        machine.transition(state)
    return machine, account


@pytest.mark.parametrize("source,target", list(itertools.product(AuthorizationState, repeat=2)))
def test_authorization_transition_matrix(source, target):
    machine, account = machine_in(source)
    if target in TRANSITIONS[source]:
        machine.transition(target, **({"account_id": account} if target == "connected" else {}))
        assert machine.state == target
    else:
        with pytest.raises(AuthorizationError):
            machine.transition(target, **({"account_id": account} if target == "connected" else {}))
        assert machine.state == source


def test_connected_requires_valid_identity_and_no_account_switch_on_refresh():
    machine, account = machine_in("authorization_pending")
    for invalid in (None, "email@example.com"):
        with pytest.raises(AuthorizationError):
            machine.transition("connected", account_id=invalid)
    machine.transition("connected", account_id=account)
    machine.transition("expired")
    with pytest.raises(AuthorizationError):
        machine.transition("connected", account_id=uuid4())
    machine.transition("connected", account_id=account)
    with pytest.raises(AuthorizationError):
        machine.transition("execute_shell")
    with pytest.raises(AuthorizationError):
        machine.transition("expired", account_id=account)


@pytest.fixture
def selections():
    clock = [100.0]
    registry = SelectionRegistry(clock=lambda: clock[0])
    machine, account = machine_in("connected")
    return registry, machine, account, uuid4(), clock


def test_forged_expired_cross_account_and_session_selections(selections):
    registry, machine, _, session, clock = selections
    references = registry.issue(session, machine, ["message1", "message2"])
    with pytest.raises(SelectionError):
        registry.claim(session, machine, [secrets.token_urlsafe(32)])
    with pytest.raises(SelectionError):
        registry.claim(session, machine, [references[0][:-1] + "!"])
    other_machine, _ = machine_in("connected")
    with pytest.raises(SelectionError):
        registry.claim(session, other_machine, [references[0]])
    with pytest.raises(SelectionError):
        registry.claim(uuid4(), machine, [references[0]])
    clock[0] += 600
    with pytest.raises(SelectionError):
        registry.claim(session, machine, references)


def test_atomic_claim_duplicate_id_new_handle_and_auth_generation(selections):
    registry, machine, account, session, _ = selections
    first = registry.issue(session, machine, ["message1", "message2"])
    duplicate = registry.issue(session, machine, ["message1"])
    with pytest.raises(SelectionError):
        registry.claim(session, machine, [first[0], duplicate[0]])
    with pytest.raises(SelectionError):
        registry.claim(session, machine, [first[0], secrets.token_urlsafe(32)])
    lease = registry.claim(session, machine, [first[0]])[0]  # Failed batches reserved nothing.
    for refs in ([first[0]], duplicate):
        with pytest.raises(SelectionError):
            registry.claim(session, machine, refs)
    machine.transition("expired")
    machine.transition("connected", account_id=account)
    with pytest.raises(SelectionError):
        registry.claim(session, machine, [first[1]])
    renewed = registry.issue(session, machine, ["message1"])
    with pytest.raises(SelectionError):
        registry.claim(session, machine, renewed)
    with pytest.raises(SelectionError):
        registry.resolve(session, machine, lease)


def test_concurrent_claim_only_one_wins(selections):
    registry, machine, _, session, _ = selections
    refs = registry.issue(session, machine, ["message1"])
    def claim():
        try:
            registry.claim(session, machine, refs)
            return True
        except SelectionError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _: claim(), range(8))) == 1


def test_bounded_batches_registry_and_single_use_leases(selections):
    registry, machine, _, session, clock = selections
    for ids in ([], ["a"] * 2, ["x"] * 21, ["https://evil.example"], ["../message"], [None]):
        with pytest.raises(SelectionError):
            registry.issue(session, machine, ids)
    refs = registry.issue(session, machine, [f"id{i}" for i in range(6)])
    for batch in ([], refs, [refs[0], refs[0]], [None]):
        with pytest.raises(SelectionError):
            registry.claim(session, machine, batch)
    leases = registry.claim(session, machine, refs[:5])
    with pytest.raises(SelectionError):
        registry.claim(session, machine, [refs[5]])  # At most five outstanding jobs too.
    assert registry.resolve(session, machine, leases[0]) == "id0"
    with pytest.raises(SelectionError):
        registry.resolve(session, machine, leases[0])
    registry.finish(session, machine, leases[0], "completed")
    with pytest.raises(SelectionError):
        registry.validate_running(session, machine, leases[0])
    clock[0] += 300
    with pytest.raises(SelectionError):
        registry.resolve(session, machine, leases[1])
    assert "id0" not in repr(leases[0])
    for index in range(12):
        registry.issue(session, machine, [f"page{index}_{i}" for i in range(20)])
    with pytest.raises(SelectionError):
        registry.issue(session, machine, [f"over{i}" for i in range(20)])


def test_nonconnected_states_cannot_issue_selection():
    for state in AuthorizationState:
        if state == "connected":
            continue
        machine, _ = machine_in(state)
        with pytest.raises(AuthorizationError):
            SelectionRegistry().issue(uuid4(), machine, ["message1"])
