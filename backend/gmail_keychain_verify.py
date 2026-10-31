"""Opt-in native Keychain verification with isolated synthetic data; no OAuth/network."""

import argparse
import json
import time
from uuid import UUID, uuid4

from backend.gmail_tokens import (
    CredentialStoreError, MacOSKeychainStore, OAuthCredentials,
    VERIFICATION_SERVICE, _SecurityFramework,
)


class VerificationFailed(Exception):
    pass


def verify_backend(backend, *, account_id: UUID | None = None) -> dict:
    """Test one fresh item, never inspect production credentials or print values."""
    account_id = account_id or uuid4()
    checks = dict.fromkeys(("missing_read", "write_read", "update_read", "invalid_data_rejected",
                            "recovery_read", "delete_read", "missing_delete"), "not_run")
    report = {"service": VERIFICATION_SERVICE, "account_id": str(account_id), "checks": checks,
              "cleanup": "not_needed_no_write", "success": False, "errors": []}
    if getattr(backend, "_service", VERIFICATION_SERVICE) != VERIFICATION_SERVICE:
        report["errors"].append({"stage": "namespace", "code": "production_namespace_rejected"})
        return report
    store = MacOSKeychainStore(backend, service=VERIFICATION_SERVICE)
    synthetic = OAuthCredentials(access_token="SUSNOT-SYNTHETIC-ACCESS-" + uuid4().hex,
                                 refresh_token="SUSNOT-SYNTHETIC-REFRESH-" + uuid4().hex,
                                 account_identity="synthetic@example.invalid", expires_at=float(time.time() + 3600))
    updated = synthetic.model_copy(update={"expires_at": synthetic.expires_at + 3600})
    # Update all credential values, not just metadata; keep them out of output/argv.
    updated = OAuthCredentials(access_token="SUSNOT-SYNTHETIC-UPDATED-" + uuid4().hex,
                               refresh_token="SUSNOT-SYNTHETIC-ROTATED-" + uuid4().hex,
                               account_identity="synthetic@example.invalid", expires_at=updated.expires_at)
    write_attempted, stage = False, "missing_read"
    try:
        if store.load(account_id) is not None:
            raise VerificationFailed()  # Do not overwrite/delete a pre-existing item.
        checks[stage] = True
        stage, write_attempted = "write_read", True
        store.save(account_id, synthetic)
        if store.load(account_id) != synthetic:
            raise VerificationFailed()
        checks[stage] = True
        stage = "update_read"
        store.save(account_id, updated)
        if store.load(account_id) != updated:
            raise VerificationFailed()
        checks[stage] = True
        stage = "invalid_data_rejected"
        backend.put(str(account_id), b"synthetic-invalid-json")
        try:
            store.load(account_id)
        except CredentialStoreError as error:
            if error.os_status is not None:
                raise
        else:
            raise VerificationFailed()
        checks[stage] = True
        stage = "recovery_read"
        store.save(account_id, updated)
        if store.load(account_id) != updated:
            raise VerificationFailed()
        checks[stage] = True
        stage = "delete_read"
        store.delete(account_id)
        if store.load(account_id) is not None:
            raise VerificationFailed()
        checks[stage] = True
        stage = "missing_delete"
        store.delete(account_id)
        checks[stage] = True
    except (Exception, KeyboardInterrupt) as error:
        checks[stage] = False
        report["errors"].append({"stage": stage, "code": "interrupted" if isinstance(error, KeyboardInterrupt) else "verification_failed",
                                 "os_status": error.os_status if isinstance(error, CredentialStoreError) else None})
    finally:
        if write_attempted:
            try:
                store.delete(account_id)
                if store.load(account_id) is not None:
                    raise VerificationFailed()
                report["cleanup"] = "confirmed_absent"
            except (Exception, KeyboardInterrupt) as error:
                report["cleanup"] = "unconfirmed_manual_cleanup_required"
                report["errors"].append({"stage": "cleanup", "code": "cleanup_failed",
                                         "os_status": error.os_status if isinstance(error, CredentialStoreError) else None})
    report["success"] = all(value is True for value in checks.values()) and report["cleanup"] == "confirmed_absent"
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Isolated synthetic macOS Keychain check. No Google access.")
    parser.add_argument("--run-native", action="store_true", help="Explicitly allow synthetic Keychain write/read/update/delete")
    args = parser.parse_args(argv)
    if not args.run_native:
        parser.print_help()
        return 2
    account_id = uuid4()
    # Locator is non-sensitive cleanup metadata, never a credential value.
    print(json.dumps({"service": VERIFICATION_SERVICE, "account_id": str(account_id), "mode": "synthetic_native_only"}), flush=True)
    try:
        backend = _SecurityFramework(service=VERIFICATION_SERVICE)
    except Exception:
        print(json.dumps({"success": False, "error": "native_keychain_unavailable", "cleanup": "not_needed_no_write"}))
        return 1
    report = verify_backend(backend, account_id=account_id)
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
