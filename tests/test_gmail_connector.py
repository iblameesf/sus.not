"""Read-only connector contract tested only with synthetic, network-free hooks."""

import asyncio
import socket
from uuid import uuid4

import pytest

from backend.gmail_connector import (
    AccountIdentity, ConnectorError, GMAIL_BASE, GmailConnector, MessageMetadata, MetadataPage,
    RawMessage, gmail_endpoint, GOOGLE_TOKEN_ENDPOINT, GOOGLE_REVOCATION_ENDPOINT,
)
from backend.gmail_selections import SelectionRegistry
from backend.gmail_state import AuthorizationMachine


class FakeConnector(GmailConnector):
    def __init__(self, *args, account, **kwargs):
        super().__init__(*args, **kwargs)
        self.account = account
        self.calls = []
        self.mode = "ok"

    async def _authorized_account(self):
        self.calls.append("profile")
        return AccountIdentity(self.account, "synthetic@example.com")

    async def _list_metadata(self, *, limit, page_token):
        self.calls.append("list")
        if self.mode == "switch_account":
            self._authorization.disconnect()
            self._authorization.transition("authorization_pending")
            self._authorization.transition("connected", account_id=uuid4())
        count = limit + 1 if self.mode == "oversized_page" else 2
        return MetadataPage(tuple(MessageMetadata(f"message{i}", "Synthetic sender", "Synthetic subject", "2025") for i in range(count)))

    async def _retrieve_message(self, message_id):
        self.calls.append("get")
        if self.mode == "revoke_during_fetch":
            self._authorization.transition("revoked")
        if self.mode == "oversized_message":
            return RawMessage(message_id, b"x" * 131073)
        if self.mode == "wrong_message":
            return RawMessage("different", b"synthetic body")
        return RawMessage(message_id, b"From: synthetic@example.com\n\nSynthetic body")

    async def _revoke(self):
        assert self._authorization.state == "disconnected"
        self.calls.append("revoke")
        if self.mode == "revoke_error":
            raise RuntimeError("mock-refresh-SECRET private email")


@pytest.fixture
def connector(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Foundation attempted a network request")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    session, account = uuid4(), uuid4()
    authorization = AuthorizationMachine()
    authorization.transition("authorization_pending")
    authorization.transition("connected", account_id=account)
    registry = SelectionRegistry()
    connector = FakeConnector(session, authorization, registry, account=account)
    return connector, authorization, registry, session


def test_account_bounded_listing_then_explicit_retrieval(connector):
    connector, authorization, registry, session = connector
    assert asyncio.run(connector.authorized_account()).account_id == connector.account
    page = asyncio.run(connector.list_metadata(limit=2))
    assert len(page.messages) == 2
    assert connector.calls == ["profile", "list"]  # Listing fetched no bodies.
    assert not hasattr(page.messages[0], "message_id")
    lease = registry.claim(session, authorization, [page.messages[0].reference])[0]
    message = asyncio.run(connector.retrieve_selected(lease))
    assert message.message_id == "message0"
    assert "Synthetic body" not in repr(message)
    with pytest.raises(ConnectorError):
        asyncio.run(connector.retrieve_selected(lease))
    assert connector.calls.count("get") == 1
    assert not hasattr(connector, "send_message") and not hasattr(connector, "modify_message")


@pytest.mark.parametrize("limit", [0, -1, 21, True, "20"])
def test_invalid_listing_bounds_before_hook(connector, limit):
    connector, _, _, _ = connector
    with pytest.raises(ConnectorError):
        asyncio.run(connector.list_metadata(limit=limit))
    assert connector.calls == []


@pytest.mark.parametrize("mode", ["oversized_page", "switch_account"])
def test_invalid_listing_result_and_context_switch(connector, mode):
    connector, _, _, _ = connector
    connector.mode = mode
    with pytest.raises(ConnectorError):
        asyncio.run(connector.list_metadata(limit=2))


@pytest.mark.parametrize("mode", ["oversized_message", "wrong_message", "revoke_during_fetch"])
def test_fetch_failures_are_sanitized_and_cannot_duplicate(connector, mode, caplog):
    connector, authorization, registry, session = connector
    page = asyncio.run(connector.list_metadata(limit=2))
    lease = registry.claim(session, authorization, [page.messages[0].reference])[0]
    connector.mode = mode
    with pytest.raises(ConnectorError) as error:
        asyncio.run(connector.retrieve_selected(lease))
    assert "Synthetic body" not in str(error.value)
    assert "Synthetic body" not in caplog.text
    with pytest.raises(ConnectorError):
        asyncio.run(connector.retrieve_selected(lease))
    assert connector.calls.count("get") == 1


def test_identity_mismatch_and_disconnect_failure_stops_access(connector, caplog):
    connector, authorization, _, _ = connector
    connector.account = uuid4()
    with pytest.raises(ConnectorError):
        asyncio.run(connector.authorized_account())
    connector.mode = "revoke_error"
    with pytest.raises(ConnectorError) as error:
        asyncio.run(connector.disconnect_and_revoke())
    assert authorization.state == "disconnected"
    assert "SECRET" not in str(error.value) and "SECRET" not in caplog.text
    with pytest.raises(ConnectorError):
        asyncio.run(connector.list_metadata())


def test_fixed_read_only_endpoints_and_no_arbitrary_destinations():
    assert gmail_endpoint("profile") == GMAIL_BASE + "/profile"
    assert gmail_endpoint("list") == GMAIL_BASE + "/messages"
    assert gmail_endpoint("get", message_id="message123") == GMAIL_BASE + "/messages/message123"
    assert GOOGLE_TOKEN_ENDPOINT == "https://oauth2.googleapis.com/token"
    assert GOOGLE_REVOCATION_ENDPOINT == "https://oauth2.googleapis.com/revoke"
    for operation, message_id in [("https://evil.example", None), ("delete", "message123"),
                                   ("get", "../profile"), ("get", "https://evil.example"),
                                   ("get", "message1?access_token=SECRET"), ("list", "message123")]:
        with pytest.raises(ConnectorError) as error:
            gmail_endpoint(operation, message_id=message_id)
        assert "SECRET" not in str(error.value)
    with pytest.raises(TypeError):
        GmailConnector(uuid4(), AuthorizationMachine(), SelectionRegistry())  # No real implementation.
