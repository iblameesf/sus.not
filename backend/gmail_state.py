"""Authorization lifecycle only; no OAuth, credentials, or network operations."""

from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
import time
from uuid import UUID


class AuthorizationState(StrEnum):
    DISCONNECTED = "disconnected"
    AUTHORIZATION_PENDING = "authorization_pending"
    CONNECTED = "connected"
    EXPIRED = "expired"
    REVOKED = "revoked"
    ERROR = "error"


class AuthorizationError(ValueError):
    def __init__(self):
        super().__init__("Authorization operation is not permitted in the current state.")


TRANSITIONS = {
    AuthorizationState.DISCONNECTED: frozenset({"authorization_pending"}),
    AuthorizationState.AUTHORIZATION_PENDING: frozenset({"connected", "disconnected", "error"}),
    AuthorizationState.CONNECTED: frozenset({"expired", "revoked", "disconnected", "error"}),
    AuthorizationState.EXPIRED: frozenset({"connected", "authorization_pending", "revoked", "disconnected", "error"}),
    AuthorizationState.REVOKED: frozenset({"authorization_pending", "disconnected"}),
    AuthorizationState.ERROR: frozenset({"authorization_pending", "disconnected", "revoked"}),
}


@dataclass(frozen=True, repr=False)
class AccountContext:
    session_id: UUID
    account_id: UUID
    generation: int


class AuthorizationMachine:
    def __init__(self, *, clock=time.monotonic, valid_until: float | None = None):
        self._clock, self._valid_until, self._closed = clock, valid_until, False
        self._state = AuthorizationState.DISCONNECTED
        self._account_id = None
        self._generation = 0
        self._lock = RLock()

    @property
    def state(self) -> AuthorizationState:
        with self._lock:
            return self._state

    def transition(self, target: AuthorizationState, *, account_id: UUID | None = None) -> None:
        with self._lock:
            try:
                target = AuthorizationState(target)
            except (ValueError, TypeError):
                raise AuthorizationError() from None
            if target != AuthorizationState.DISCONNECTED and (
                self._closed or (self._valid_until is not None and self._clock() >= self._valid_until)
            ):
                raise AuthorizationError()
            if target not in TRANSITIONS[self._state]:
                raise AuthorizationError()
            if target == AuthorizationState.CONNECTED:
                if not isinstance(account_id, UUID):
                    raise AuthorizationError()
                if self._state == AuthorizationState.EXPIRED and account_id != self._account_id:
                    raise AuthorizationError()
            elif account_id is not None:
                raise AuthorizationError()
            self._account_id = account_id if target == AuthorizationState.CONNECTED else (
                self._account_id if target == AuthorizationState.EXPIRED else None
            )
            self._state = target
            # Every lifecycle change invalidates previously issued selections/leases.
            self._generation += 1

    def disconnect(self) -> None:
        """Idempotent local shutdown; unlike transition(), permits already-disconnected."""
        with self._lock:
            if self._state != AuthorizationState.DISCONNECTED:
                self.transition(AuthorizationState.DISCONNECTED)

    def invalidate(self) -> None:
        """Permanently close an expired/closed control session's authorization context."""
        with self._lock:
            self.disconnect()
            self._closed = True

    def ensure_live(self) -> None:
        """Check the control-session lifetime even during pending OAuth/refresh."""
        with self._lock:
            if self._valid_until is not None and self._clock() >= self._valid_until:
                self.invalidate()
            if self._closed:
                raise AuthorizationError()

    @contextmanager
    def connected_context(self, session_id: UUID):
        # Held across registry operations so transitions cannot race a claim.
        with self._lock:
            self.ensure_live()
            if self._state != AuthorizationState.CONNECTED or not isinstance(session_id, UUID):
                raise AuthorizationError()
            yield AccountContext(session_id, self._account_id, self._generation)
