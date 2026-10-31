"""Credential tests use fake in-memory Keychain backends, never the real Keychain."""

import json
import subprocess
from uuid import uuid4

import pytest

from backend import gmail_tokens as tokens


class FakeKeychain:
    def __init__(self):
        self.items = {}
        self.fail = False

    def put(self, account, value):
        if self.fail:
            raise OSError("mock-access-SECRET mock-refresh-SECRET")
        self.items[account] = value

    def get(self, account):
        if self.fail:
            raise OSError("mock-access-SECRET mock-refresh-SECRET")
        return self.items.get(account)

    def delete(self, account):
        if self.fail:
            raise OSError("mock-access-SECRET mock-refresh-SECRET")
        self.items.pop(account, None)


@pytest.fixture
def credentials():
    return tokens.OAuthCredentials(access_token="mock-access-SECRET", refresh_token="mock-refresh-SECRET",
                                   expires_at=2000000000.0)


def test_keychain_round_trip_update_delete_and_account_isolation(credentials, monkeypatch, tmp_path, caplog):
    def forbidden(*args, **kwargs):
        pytest.fail("Token was passed to a subprocess")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setenv("SUSNOT_HISTORY_ENABLED", "true")
    monkeypatch.setenv("SUSNOT_HISTORY_DB", str(tmp_path / "history.sqlite3"))
    backend = FakeKeychain()
    store = tokens.MacOSKeychainStore(backend)
    first, other = uuid4(), uuid4()
    assert store.load(first) is None
    store.save(first, credentials)
    loaded = store.load(first)
    assert loaded.access_token.get_secret_value() == "mock-access-SECRET"
    assert loaded.refresh_token.get_secret_value() == "mock-refresh-SECRET"
    assert loaded.scopes == (tokens.GMAIL_READONLY_SCOPE,)
    assert store.load(other) is None
    assert list(backend.items) == [str(first)]
    store.save(first, credentials.model_copy(update={"refresh_token": None}))
    assert store.load(first).refresh_token is None
    assert "mock-access-SECRET" not in repr(credentials)
    assert "mock-access-SECRET" not in credentials.model_dump_json()
    assert "SECRET" not in caplog.text
    assert not list(tmp_path.iterdir())
    store.delete(first)
    store.delete(first)  # Missing item deletion is idempotent.
    assert store.load(first) is None


@pytest.mark.parametrize("operation", ["save", "load", "delete"])
def test_storage_failure_sanitized_no_fallback(operation, credentials, caplog, tmp_path):
    backend = FakeKeychain()
    backend.fail = True
    store, account = tokens.MacOSKeychainStore(backend), uuid4()
    with pytest.raises(tokens.CredentialStoreError) as error:
        getattr(store, operation)(account, *([credentials] if operation == "save" else []))
    assert "SECRET" not in str(error.value)
    assert "SECRET" not in caplog.text
    assert not list(tmp_path.iterdir())
    assert not backend.items


@pytest.mark.parametrize("payload", [b"not-json mock-access-SECRET", b"x" * (tokens.MAX_CREDENTIAL_BYTES + 1),
    json.dumps({"access_token": "mock-access-SECRET", "expires_at": 1, "scopes": ["https://mail.google.com/"]}).encode(),
    json.dumps({"access_token": "mock-access-SECRET", "expires_at": 1, "extra": "mock-refresh-SECRET"}).encode()])
def test_corrupt_or_overbroad_stored_credentials_are_rejected(payload):
    backend, account = FakeKeychain(), uuid4()
    backend.items[str(account)] = payload
    with pytest.raises(tokens.CredentialStoreError) as error:
        tokens.MacOSKeychainStore(backend).load(account)
    assert "SECRET" not in str(error.value)


def test_unsupported_platform_and_native_loader_failure(credentials, monkeypatch):
    monkeypatch.setattr(tokens.sys, "platform", "not-macos")
    with pytest.raises(tokens.CredentialStoreError):
        tokens.MacOSKeychainStore().save(uuid4(), credentials)
    monkeypatch.setattr(tokens.sys, "platform", "darwin")
    def unavailable(*args):
        raise OSError("mock-access-SECRET")
    monkeypatch.setattr(tokens.C, "CDLL", unavailable)
    with pytest.raises(tokens.CredentialStoreError) as error:
        tokens.MacOSKeychainStore().load(uuid4())
    assert "SECRET" not in str(error.value)


def test_invalid_account_and_bypassed_model_validation(credentials):
    backend = FakeKeychain()
    store = tokens.MacOSKeychainStore(backend)
    with pytest.raises(tokens.CredentialStoreError):
        store.save("private@example.com", credentials)
    unsafe = credentials.model_copy(update={"scopes": ("https://mail.google.com/",)})
    with pytest.raises(tokens.CredentialStoreError):
        store.save(uuid4(), unsafe)
    assert not backend.items
