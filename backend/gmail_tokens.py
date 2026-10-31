"""Mockable credential store backed by macOS Security.framework, never token files."""

from contextlib import contextmanager
import ctypes as C
import json
import sys
from threading import RLock
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SERVICE = "SUS.NOT.Gmail.OAuth"
VERIFICATION_SERVICE = "SUS.NOT.Gmail.LocalVerification"
MAX_CREDENTIAL_BYTES = 24576


class OAuthCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True, revalidate_instances="always")

    access_token: SecretStr = Field(min_length=1, max_length=8192)
    refresh_token: SecretStr | None = Field(default=None, min_length=1, max_length=8192)
    expires_at: float = Field(gt=0, allow_inf_nan=False)
    account_identity: SecretStr | None = Field(default=None, min_length=3, max_length=254)
    scopes: tuple[str, ...] = (GMAIL_READONLY_SCOPE,)

    @field_validator("scopes")
    @classmethod
    def read_only(cls, value):
        if value != (GMAIL_READONLY_SCOPE,):
            raise ValueError("Only the planned read-only scope is permitted")
        return value


class CredentialStoreError(RuntimeError):
    def __init__(self, os_status: int | None = None):
        self.os_status = os_status if type(os_status) is int else None
        super().__init__("Secure credential storage is unavailable or invalid.")


class CredentialStore(Protocol):
    def save(self, account_id: UUID, credentials: OAuthCredentials) -> None: ...
    def load(self, account_id: UUID) -> OAuthCredentials | None: ...
    def delete(self, account_id: UUID) -> None: ...


class KeychainBackend(Protocol):
    def put(self, account: str, value: bytes) -> None: ...
    def get(self, account: str) -> bytes | None: ...
    def delete(self, account: str) -> None: ...


class MacOSKeychainStore:
    def __init__(self, backend: KeychainBackend | None = None, *, service: str = SERVICE):
        if service not in {SERVICE, VERIFICATION_SERVICE}:
            raise CredentialStoreError()
        self._service = service
        self._backend = backend
        self._lock = RLock()

    def _native(self):
        if self._backend is None:
            self._backend = _SecurityFramework(service=self._service)
        return self._backend

    @staticmethod
    def _account(account_id):
        if not isinstance(account_id, UUID):
            raise CredentialStoreError()
        return str(account_id)  # App-owned opaque binding, not an email address.

    def save(self, account_id: UUID, credentials: OAuthCredentials) -> None:
        try:
            account = self._account(account_id)
            if not isinstance(credentials, OAuthCredentials):
                raise CredentialStoreError()
            credentials = OAuthCredentials.model_validate(credentials)
            payload = json.dumps({
                "access_token": credentials.access_token.get_secret_value(),
                "refresh_token": credentials.refresh_token.get_secret_value() if credentials.refresh_token else None,
                "expires_at": credentials.expires_at, "scopes": list(credentials.scopes),
                "account_identity": credentials.account_identity.get_secret_value() if credentials.account_identity else None,
            }).encode("utf-8")
            if len(payload) > MAX_CREDENTIAL_BYTES:
                raise CredentialStoreError()
            with self._lock:
                self._native().put(account, payload)
        except Exception as error:
            raise CredentialStoreError(error.os_status if isinstance(error, CredentialStoreError) else None) from None

    def load(self, account_id: UUID) -> OAuthCredentials | None:
        try:
            account = self._account(account_id)
            with self._lock:
                payload = self._native().get(account)
            if payload is None:
                return None
            if not isinstance(payload, bytes) or len(payload) > MAX_CREDENTIAL_BYTES:
                raise CredentialStoreError()
            return OAuthCredentials.model_validate_json(payload)
        except Exception as error:
            raise CredentialStoreError(error.os_status if isinstance(error, CredentialStoreError) else None) from None

    def delete(self, account_id: UUID) -> None:
        try:
            account = self._account(account_id)
            with self._lock:
                self._native().delete(account)
        except Exception as error:
            raise CredentialStoreError(error.os_status if isinstance(error, CredentialStoreError) else None) from None


class _SecurityFramework:
    """Native generic-password items. No subprocess arguments, shell or disk fallback.

    Loaded lazily: importing the app never opens Keychain. Authentication UI is
    prohibited; locked/denied stores fail closed instead of prompting or falling back.
    """

    def __init__(self, *, service: str = SERVICE):
        if service not in {SERVICE, VERIFICATION_SERVICE}:
            raise CredentialStoreError()
        self._service = service
        if sys.platform != "darwin":
            raise CredentialStoreError()
        self.cf = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.sec = C.CDLL("/System/Library/Frameworks/Security.framework/Security")
        signatures = {
            "CFStringCreateWithCString": ([C.c_void_p, C.c_char_p, C.c_uint32], C.c_void_p),
            "CFDataCreate": ([C.c_void_p, C.c_char_p, C.c_long], C.c_void_p),
            "CFDictionaryCreateMutable": ([C.c_void_p, C.c_long, C.c_void_p, C.c_void_p], C.c_void_p),
            "CFDictionarySetValue": ([C.c_void_p, C.c_void_p, C.c_void_p], None),
            "CFDataGetLength": ([C.c_void_p], C.c_long),
            "CFDataGetBytePtr": ([C.c_void_p], C.c_void_p),
            "CFGetTypeID": ([C.c_void_p], C.c_ulong),
            "CFDataGetTypeID": ([], C.c_ulong),
            "CFRelease": ([C.c_void_p], None),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.cf, name)
            function.argtypes, function.restype = arguments, result
        for name, arguments in {
            "SecItemAdd": [C.c_void_p, C.POINTER(C.c_void_p)],
            "SecItemCopyMatching": [C.c_void_p, C.POINTER(C.c_void_p)],
            "SecItemUpdate": [C.c_void_p, C.c_void_p], "SecItemDelete": [C.c_void_p],
        }.items():
            function = getattr(self.sec, name)
            function.argtypes, function.restype = arguments, C.c_int32

    def _constant(self, name):
        return C.c_void_p.in_dll(self.sec, name).value

    @contextmanager
    def _dictionary(self, account=None, *, data=None, read=False, attributes=False):
        keys = C.addressof(C.c_byte.in_dll(self.cf, "kCFTypeDictionaryKeyCallBacks"))
        values = C.addressof(C.c_byte.in_dll(self.cf, "kCFTypeDictionaryValueCallBacks"))
        dictionary = self.cf.CFDictionaryCreateMutable(None, 0, keys, values)
        if not dictionary:
            raise CredentialStoreError()
        allocated = []
        try:
            def add(key, value):
                self.cf.CFDictionarySetValue(dictionary, self._constant(key), value)

            def string(value):
                result = self.cf.CFStringCreateWithCString(None, value.encode("utf-8"), 0x08000100)
                if not result:
                    raise CredentialStoreError()
                allocated.append(result)
                return result

            if not attributes:
                add("kSecClass", self._constant("kSecClassGenericPassword"))
                add("kSecAttrService", string(self._service))
                add("kSecAttrAccount", string(account))
                add("kSecUseAuthenticationUI", self._constant("kSecUseAuthenticationUIFail"))
            if data is not None:
                value = self.cf.CFDataCreate(None, data, len(data))
                if not value:
                    raise CredentialStoreError()
                allocated.append(value)
                add("kSecValueData", value)
            if read:
                add("kSecReturnData", C.c_void_p.in_dll(self.cf, "kCFBooleanTrue").value)
                add("kSecMatchLimit", self._constant("kSecMatchLimitOne"))
            yield dictionary
        finally:
            self.cf.CFRelease(dictionary)
            for value in allocated:
                self.cf.CFRelease(value)

    def put(self, account, value):
        with self._dictionary(account) as query, self._dictionary(data=value, attributes=True) as attributes:
            status = self.sec.SecItemUpdate(query, attributes)
            if status == -25300:  # errSecItemNotFound
                with self._dictionary(account, data=value) as item:
                    status = self.sec.SecItemAdd(item, None)
                if status == -25299:  # Another writer created it; update the same item.
                    status = self.sec.SecItemUpdate(query, attributes)
            if status != 0:
                raise CredentialStoreError(status)

    def get(self, account):
        with self._dictionary(account, read=True) as query:
            result = C.c_void_p()
            status = self.sec.SecItemCopyMatching(query, C.byref(result))
            try:
                if status == -25300:
                    return None
                if status != 0:
                    raise CredentialStoreError(status)
                if not result.value or self.cf.CFGetTypeID(result) != self.cf.CFDataGetTypeID():
                    raise CredentialStoreError()
                length = self.cf.CFDataGetLength(result)
                if not 0 < length <= MAX_CREDENTIAL_BYTES:
                    raise CredentialStoreError()
                return C.string_at(self.cf.CFDataGetBytePtr(result), length)
            finally:
                if result.value:
                    self.cf.CFRelease(result)

    def delete(self, account):
        with self._dictionary(account) as query:
            status = self.sec.SecItemDelete(query)
            if status not in {0, -25300}:
                raise CredentialStoreError(status)
