"""Read-only connector contracts, endpoint plans and selected-message Google adapter."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import UUID

from backend.email_parser import MAX_EMAIL_BYTES
from backend.gmail_selections import MAX_PAGE_SIZE, SelectionLease, SelectionRegistry, valid_message_id
from backend.gmail_state import AuthorizationMachine

GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_REVOCATION_ENDPOINT = "https://oauth2.googleapis.com/revoke"


class ConnectorError(RuntimeError):
    def __init__(self, code="connector_failed", status=502):
        self.code, self.status = code, status
        super().__init__("Read-only Gmail operation could not be completed.")


def gmail_endpoint(operation: str, *, message_id: str | None = None) -> str:
    """Application-owned operations only; never accepts a URL or arbitrary API path."""
    if operation == "profile" and message_id is None:
        return GMAIL_BASE + "/profile"
    if operation == "list" and message_id is None:
        return GMAIL_BASE + "/messages"
    if operation == "get" and valid_message_id(message_id):
        return GMAIL_BASE + "/messages/" + message_id
    if operation == "modify" and valid_message_id(message_id):
        return GMAIL_BASE + "/messages/" + message_id + "/modify"
    raise ConnectorError()


def valid_page_token(value):
    return value is None or (isinstance(value, str) and 0 < len(value) <= 256 and all(32 < ord(c) < 127 for c in value))


@dataclass(frozen=True, repr=False)
class AccountIdentity:
    account_id: UUID  # Local opaque binding established by future verified authorization.
    address: str


@dataclass(frozen=True, repr=False)
class MessageMetadata:
    message_id: str
    sender: str
    subject: str
    date: str

    def __post_init__(self):
        if not valid_message_id(self.message_id) or not all(
            isinstance(value, str) and len(value) <= 2048 for value in (self.sender, self.subject, self.date)
        ):
            raise ConnectorError()


@dataclass(frozen=True, repr=False)
class MetadataPage:
    messages: tuple[MessageMetadata, ...]
    next_page_token: str | None = None


@dataclass(frozen=True, repr=False)
class SelectableMessage:
    reference: str
    sender: str
    subject: str
    date: str


@dataclass(frozen=True, repr=False)
class SelectablePage:
    messages: tuple[SelectableMessage, ...]
    next_page_token: str | None


@dataclass(frozen=True, repr=False)
class RawMessage:
    message_id: str
    content: bytes

    def __post_init__(self):
        if not valid_message_id(self.message_id) or not isinstance(self.content, bytes) or not 0 < len(self.content) <= MAX_EMAIL_BYTES:
            raise ConnectorError()


class GmailConnector(ABC):
    """Template enforces bounded listing, explicit selection and lifecycle checks.

    Network hooks must use gmail_endpoint(), TLS, bounded streaming, no
    redirects/proxies, no cloud AI, and no attachment or modification operations.
    GoogleGmailConnector below supplies hooks only after trusted OAuth configuration.
    """

    def __init__(self, session_id: UUID, authorization: AuthorizationMachine, selections: SelectionRegistry):
        self._session_id, self._authorization, self._selections = session_id, authorization, selections

    def _context(self):
        with self._authorization.connected_context(self._session_id) as context:
            return context

    async def authorized_account(self) -> AccountIdentity:
        try:
            context = self._context()
            identity = await self._authorized_account()
            if (self._context() != context or not isinstance(identity, AccountIdentity)
                    or identity.account_id != context.account_id or not isinstance(identity.address, str)
                    or not 0 < len(identity.address) <= 254):
                raise ConnectorError()
            return identity
        except Exception as error:
            if isinstance(error, ConnectorError):
                raise
            raise ConnectorError() from None

    async def list_metadata(self, *, limit: int = MAX_PAGE_SIZE, page_token: str | None = None) -> SelectablePage:
        try:
            if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE or not valid_page_token(page_token):
                raise ConnectorError()
            context = self._context()
            page = await self._list_metadata(limit=limit, page_token=page_token)
            if (self._context() != context or not isinstance(page, MetadataPage)
                    or not isinstance(page.messages, tuple) or len(page.messages) > limit
                    or not valid_page_token(page.next_page_token)
                    or not all(isinstance(item, MessageMetadata) for item in page.messages)):
                raise ConnectorError()
            with self._authorization.connected_context(self._session_id) as current:
                if current != context:
                    raise ConnectorError()
                references = self._selections.issue(self._session_id, self._authorization,
                                                     [item.message_id for item in page.messages]) if page.messages else []
                return SelectablePage(tuple(SelectableMessage(ref, item.sender, item.subject, item.date)
                                            for ref, item in zip(references, page.messages)), page.next_page_token)
        except Exception as error:
            if isinstance(error, ConnectorError):
                raise
            raise ConnectorError() from None

    async def retrieve_selected(self, lease: SelectionLease) -> RawMessage:
        try:
            message_id = self._selections.resolve(self._session_id, self._authorization, lease)
            message = await self._retrieve_message(message_id)
            self._selections.validate_running(self._session_id, self._authorization, lease)
            if not isinstance(message, RawMessage) or message.message_id != message_id:
                raise ConnectorError()
            self._selections.finish(self._session_id, self._authorization, lease, "completed")
            return message
        except Exception as error:
            # Failed/expired claims remain consumed; no hidden network retries or duplicate fetches.
            if isinstance(error, ConnectorError):
                raise
            raise ConnectorError() from None

    async def disconnect_and_revoke(self) -> None:
        # Shut down local access before an awaited remote revocation hook.
        self._authorization.disconnect()
        self._selections.invalidate_session(self._session_id)
        try:
            await self._revoke()
        except Exception:
            # A future UI must distinguish local disconnection from remote revocation failure.
            raise ConnectorError() from None


    @abstractmethod
    async def _authorized_account(self) -> AccountIdentity: ...

    @abstractmethod
    async def _list_metadata(self, *, limit: int, page_token: str | None) -> MetadataPage: ...

    @abstractmethod
    async def _retrieve_message(self, message_id: str) -> RawMessage: ...

    @abstractmethod
    async def _revoke(self) -> None: ...



class GoogleGmailConnector(GmailConnector):
    """Only code-owned Google operations; content retrieval requires a claimed lease."""

    def __init__(self, *args, service, connection):
        super().__init__(*args)
        self.service, self.connection = service, connection

    async def _call(self, operation, *args):
        from backend.gmail_google import GmailError
        try:
            return await self.service.call(self.connection, operation, *args)
        except GmailError as error:
            raise ConnectorError(error.code, error.status) from None

    async def list_metadata(self, **kwargs):
        # Refresh before the base wrapper snapshots a generation for new selections.
        await self._call_access()
        return await super().list_metadata(**kwargs)

    async def _call_access(self):
        from backend.gmail_google import GmailError
        try:
            return await self.service.access(self.connection)
        except GmailError as error:
            raise ConnectorError(error.code, error.status) from None

    async def _authorized_account(self):
        address = await self._call(self.service.api.profile)
        if address != self.connection.address:
            self._authorization.transition("error")
            raise ConnectorError("account_mismatch", 401)
        return AccountIdentity(self.connection.account_id, address)

    async def _list_metadata(self, *, limit, page_token):
        import asyncio
        try:
            async with asyncio.timeout(45):
                ids, next_page = await self._call(self.service.api.list_ids, limit, page_token)
                messages = []
                for message_id in ids:
                    result = await self._call(self.service.api.metadata, message_id)
                    payload = result.get("payload")
                    if result.get("id") != message_id or not isinstance(payload, dict):
                        raise ConnectorError("invalid_gmail_response")
                    headers = payload.get("headers", [])
                    if not isinstance(headers, list) or len(headers) > 50:
                        raise ConnectorError("invalid_gmail_response")
                    fields = {}
                    for header in headers:
                        if not isinstance(header, dict) or not isinstance(header.get("name"), str) or not isinstance(header.get("value"), str):
                            raise ConnectorError("invalid_gmail_response")
                        name, value = header["name"].lower(), header["value"]
                        if name not in {"from", "subject", "date"} or name in fields or len(value) > 2048:
                            raise ConnectorError("invalid_gmail_response")
                        fields[name] = value
                    messages.append(MessageMetadata(message_id, fields.get("from", ""), fields.get("subject", ""), fields.get("date", "")))
                return MetadataPage(tuple(messages), next_page)
        except TimeoutError:
            raise ConnectorError("google_timeout", 504) from None

    async def _retrieve_message(self, message_id):
        context = self._context()
        def check():
            if self._context() != context:
                raise ConnectorError("authorization_changed_reselect", 409)
        async def selected_raw(access, selected_id):
            return await self.service.api.raw(access, selected_id, check=check)
        return RawMessage(message_id, await self._call(selected_raw, message_id))

    async def _revoke(self):
        # Service performs token revocation plus local Keychain removal, even on failure.
        result = await self.service.disconnect(self.connection.session)
        if result["errors"]:
            raise ConnectorError("revocation_or_storage_failure")
