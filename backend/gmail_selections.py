"""Ephemeral, account/session-bound selections with atomic, bounded single claims."""

from dataclasses import dataclass
from hashlib import sha256
import re
import secrets
from threading import RLock
import time
from uuid import UUID

from backend.gmail_state import AccountContext, AuthorizationMachine

MAX_PAGE_SIZE = 20
MAX_BATCH_SIZE = 5
MAX_ACTIVE_JOBS = 5
MAX_REGISTRY_SIZE = 256
MESSAGE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
REFERENCE = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class SelectionError(ValueError):
    def __init__(self):
        super().__init__("Selection is invalid, expired, already claimed, or exceeds processing limits.")


def valid_message_id(value: str) -> bool:
    return isinstance(value, str) and MESSAGE_ID.fullmatch(value) is not None


def digest(reference: str) -> bytes:
    if not isinstance(reference, str) or REFERENCE.fullmatch(reference) is None:
        raise SelectionError()
    return sha256(reference.encode("ascii")).digest()


@dataclass(repr=False)
class _Selection:
    context: AccountContext
    message_id: str
    expires_at: float


@dataclass(repr=False)
class _Job:
    context: AccountContext
    message_id: str
    expires_at: float
    state: str = "claimed"


@dataclass(frozen=True, repr=False)
class SelectionLease:
    reference: str


class SelectionRegistry:
    def __init__(self, *, clock=time.monotonic):
        self._clock = clock
        self._selections = {}
        self._jobs = {}
        self._claimed = set()
        self._lock = RLock()

    @staticmethod
    def _key(context, message_id):
        return (context.session_id, context.account_id, message_id)

    def _purge(self):
        now = self._clock()
        self._selections = {key: value for key, value in self._selections.items() if value.expires_at > now}
        # Do not evict claimed-job tombstones: that would permit duplicate processing.

    def issue(self, session_id: UUID, authorization: AuthorizationMachine, message_ids: list[str]) -> list[str]:
        """Trusted connector calls this for IDs actually returned by a bounded listing."""
        if (not isinstance(message_ids, list) or not 1 <= len(message_ids) <= MAX_PAGE_SIZE
                or not all(valid_message_id(value) for value in message_ids)
                or len(set(message_ids)) != len(message_ids)):
            raise SelectionError()
        with authorization.connected_context(session_id) as context, self._lock:
            self._purge()
            if len(self._selections) + len(message_ids) > MAX_REGISTRY_SIZE:
                raise SelectionError()
            references = []
            for message_id in message_ids:
                reference = secrets.token_urlsafe(32)
                self._selections[digest(reference)] = _Selection(context, message_id, self._clock() + 600)
                references.append(reference)
            return references

    def claim(self, session_id: UUID, authorization: AuthorizationMachine, references: list[str]) -> list[SelectionLease]:
        if (not isinstance(references, list) or not 1 <= len(references) <= MAX_BATCH_SIZE
                or not all(isinstance(value, str) for value in references)
                or len(set(references)) != len(references)):
            raise SelectionError()
        hashes = [digest(reference) for reference in references]
        with authorization.connected_context(session_id) as context, self._lock:
            self._purge()
            selections = [self._selections.get(key) for key in hashes]
            if any(value is None or value.context != context for value in selections):
                raise SelectionError()
            keys = [self._key(context, value.message_id) for value in selections]
            if len(set(keys)) != len(keys) or any(key in self._claimed for key in keys):
                raise SelectionError()
            active = sum(job.state in {"claimed", "running"} and job.expires_at > self._clock()
                         for job in self._jobs.values())
            if len(self._jobs) + len(keys) > MAX_REGISTRY_SIZE or active + len(keys) > MAX_ACTIVE_JOBS:
                raise SelectionError()
            # Validate the whole batch first; no partial reservations on rejection.
            leases = []
            for key, selection, selection_hash in zip(keys, selections, hashes):
                reference = secrets.token_urlsafe(32)
                self._jobs[digest(reference)] = _Job(context, selection.message_id, self._clock() + 300)
                self._claimed.add(key)
                del self._selections[selection_hash]
                leases.append(SelectionLease(reference))
            return leases

    def resolve(self, session_id: UUID, authorization: AuthorizationMachine, lease: SelectionLease) -> str:
        if not isinstance(lease, SelectionLease):
            raise SelectionError()
        with authorization.connected_context(session_id) as context, self._lock:
            job = self._jobs.get(digest(lease.reference))
            if job is None or job.context != context or job.state != "claimed" or job.expires_at <= self._clock():
                raise SelectionError()
            # Consume before retrieval: the same lease cannot initiate two fetches.
            job.state = "running"
            return job.message_id

    def validate_running(self, session_id: UUID, authorization: AuthorizationMachine, lease: SelectionLease) -> None:
        if not isinstance(lease, SelectionLease):
            raise SelectionError()
        with authorization.connected_context(session_id) as context, self._lock:
            job = self._jobs.get(digest(lease.reference))
            if job is None or job.context != context or job.state != "running" or job.expires_at <= self._clock():
                raise SelectionError()

    def finish(self, session_id: UUID, authorization: AuthorizationMachine, lease: SelectionLease, state: str) -> None:
        if state not in {"completed", "failed", "cancelled"}:
            raise SelectionError()
        with authorization.connected_context(session_id), self._lock:
            self.validate_running(session_id, authorization, lease)
            self._jobs[digest(lease.reference)].state = state

    def invalidate_session(self, session_id: UUID) -> None:
        with self._lock:
            self._selections = {key: value for key, value in self._selections.items() if value.context.session_id != session_id}
            self._jobs = {key: value for key, value in self._jobs.items() if value.context.session_id != session_id}
            self._claimed = {key for key in self._claimed if key[0] != session_id}
