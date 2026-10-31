"""Mocked verifier checks; normal pytest never writes the native macOS Keychain."""

import json
from uuid import uuid4

import pytest

from backend import gmail_keychain_verify as verifier
from backend.gmail_tokens import CredentialStoreError, MacOSKeychainStore, OAuthCredentials, SERVICE, VERIFICATION_SERVICE
from test_gmail_tokens import FakeKeychain


def test_verifier_round_trip_error_recovery_and_cleanup(caplog):
    backend = FakeKeychain()
    report = verifier.verify_backend(backend)
    assert report["success"] is True
    assert all(value is True for value in report["checks"].values())
    assert report["cleanup"] == "confirmed_absent"
    assert not backend.items
    assert "SUSNOT-SYNTHETIC-ACCESS" not in json.dumps(report)
    assert "SUSNOT-SYNTHETIC" not in caplog.text


def test_partial_write_failure_still_cleans_up_and_preserves_safe_status():
    class PartialWrite(FakeKeychain):
        def put(self, account, value):
            super().put(account, value)
            raise CredentialStoreError(-25308)
    backend = PartialWrite()
    report = verifier.verify_backend(backend)
    assert report["success"] is False
    assert report["errors"][0]["os_status"] == -25308
    assert report["cleanup"] == "confirmed_absent"
    assert not backend.items


def test_failure_before_writing_does_not_delete_unknown_item():
    class Denied(FakeKeychain):
        def get(self, account):
            raise CredentialStoreError(-25308)
        def delete(self, account):
            pytest.fail("No write was attempted; nothing owned to delete")
    report = verifier.verify_backend(Denied())
    assert report["success"] is False
    assert report["checks"]["write_read"] == "not_run"
    assert report["cleanup"] == "not_needed_no_write"
    assert report["errors"][0]["os_status"] == -25308


def test_failed_cleanup_never_claims_success():
    class DeleteDenied(FakeKeychain):
        def delete(self, account):
            raise CredentialStoreError(-25308)
    backend = DeleteDenied()
    report = verifier.verify_backend(backend)
    assert report["success"] is False
    assert report["cleanup"] == "unconfirmed_manual_cleanup_required"
    assert any(error["stage"] == "cleanup" for error in report["errors"])
    assert backend.items
    backend.items.clear()  # Synthetic mock memory only, no native item exists.


def test_existing_synthetic_item_not_overwritten_or_deleted():
    backend, account = FakeKeychain(), uuid4()
    store = MacOSKeychainStore(backend, service=VERIFICATION_SERVICE)
    credentials = OAuthCredentials(access_token="synthetic-existing", expires_at=2000000000.0)
    store.save(account, credentials)
    original = dict(backend.items)
    report = verifier.verify_backend(backend, account_id=account)
    assert report["success"] is False and report["cleanup"] == "not_needed_no_write"
    assert backend.items == original


def test_production_namespace_rejected_before_access():
    backend = FakeKeychain()
    backend._service = SERVICE
    backend.get = lambda _: pytest.fail("Production service accessed")
    report = verifier.verify_backend(backend)
    assert report["success"] is False
    assert report["errors"][0]["code"] == "production_namespace_rejected"
    with pytest.raises(CredentialStoreError):
        MacOSKeychainStore(service="unrelated.service")


def test_native_cli_requires_explicit_flag_and_does_not_print_secrets(monkeypatch, capsys):
    factories = []
    def fake(*, service):
        factories.append(service)
        return FakeKeychain()
    monkeypatch.setattr(verifier, "_SecurityFramework", fake)
    assert verifier.main([]) == 2
    assert not factories
    capsys.readouterr()
    assert verifier.main(["--run-native"]) == 0
    assert factories == [VERIFICATION_SERVICE]
    output = capsys.readouterr().out
    assert '"success": true' in output
    assert "SUSNOT-SYNTHETIC-ACCESS" not in output and "SUSNOT-SYNTHETIC-REFRESH" not in output


def test_native_initialization_failure_is_sanitized(monkeypatch, capsys):
    def unavailable(**kwargs):
        raise OSError("SYNTHETIC-SECRET")
    monkeypatch.setattr(verifier, "_SecurityFramework", unavailable)
    assert verifier.main(["--run-native"]) == 1
    output = capsys.readouterr().out
    assert "SYNTHETIC-SECRET" not in output
    assert "native_keychain_unavailable" in output
