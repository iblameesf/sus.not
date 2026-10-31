"""Temporary desktop OAuth loopback receiver; separate from protected /gmail routes."""

import asyncio
from ipaddress import ip_address
from urllib.parse import urlsplit

from backend.gmail_google import GmailError


def valid_loopback_redirect(uri, *, require_port=False):
    """Google Desktop loopback form; runtime callback is IPv4 with an owned port."""
    if (not isinstance(uri, str) or len(uri) > 2048
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c == "\\" for c in uri)):
        return False
    try:
        parsed = urlsplit(uri)
        return (parsed.scheme == "http" and parsed.hostname in (
                    {"127.0.0.1"} if require_port else {"127.0.0.1", "localhost", "::1"})
                and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment
                and parsed.path in ({"/"} if require_port else {"", "/"})
                and (parsed.port is None or 0 < parsed.port <= 65535)
                and (not require_port or parsed.port is not None))
    except ValueError:
        return False


class LoopbackCallback:
    def __init__(self):
        self.server = None
        self.uri = None
        self.path = "/"  # Documented Desktop loopback form; state + PKCE bind the transaction.
        self._active = False

    async def open(self, handler):
        self.handler = handler
        self.loop = asyncio.get_running_loop()
        self.server = await asyncio.start_server(self._receive, "127.0.0.1", 0, limit=8192, backlog=1)
        port = self.server.sockets[0].getsockname()[1]
        self.uri = f"http://127.0.0.1:{port}{self.path}"
        return self.uri

    def close(self):
        if self.server:
            if self.loop.is_running():
                self.loop.call_soon_threadsafe(self.server.close)
            else:
                self.server.close()

    async def _receive(self, reader, writer):
        active = False
        status, text = 400, "Authorization could not be completed. Return to SUS.NOT."
        try:
            if self._active or not ip_address(writer.get_extra_info("peername")[0]).is_loopback:
                raise GmailError("invalid_callback")
            self._active = active = True
            async with asyncio.timeout(5):
                request = await reader.readuntil(b"\r\n\r\n")
            if len(request) > 8192:
                raise GmailError("invalid_callback")
            lines = request.decode("ascii").split("\r\n")
            method, target, version = lines[0].split(" ")
            headers = {}
            for line in lines[1:]:
                if not line:
                    continue
                key, value = line.split(":", 1)
                key = key.lower()
                if key in headers:
                    raise GmailError("invalid_callback")
                headers[key] = value.strip()
            parsed = urlsplit(target)
            if (method != "GET" or version not in {"HTTP/1.0", "HTTP/1.1"} or parsed.scheme or parsed.netloc
                    or parsed.path != self.path or parsed.fragment
                    or headers.get("host") != urlsplit(self.uri).netloc
                    or "transfer-encoding" in headers or headers.get("content-length", "0") != "0"):
                raise GmailError("invalid_callback")
            await self.handler(self.uri, parsed.query)
            status, text = 200, "Authorization completed. Return to SUS.NOT."
        except Exception:
            # No URLs, codes, state, upstream bodies or exceptions enter logs/responses.
            pass
        finally:
            if active:
                self._active = False
            body = text.encode("ascii")
            writer.write((f"HTTP/1.1 {status} {'OK' if status == 200 else 'Bad Request'}\r\n"
                          f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                          "Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n"
                          "X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n").encode() + body)
            try:
                await writer.drain()
            except (ConnectionError, OSError):
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
