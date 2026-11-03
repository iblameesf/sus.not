"""Private, local Gmail bridge for the SUS.NOT Streamlit dashboard.

The browser never receives Gmail control credentials. This bridge is intended
for a trusted, localhost-only dashboard, not a publicly hosted Streamlit app.
"""

import asyncio
import threading
from concurrent.futures import Future

from backend.gmail_launcher import TrustedLauncher, load_desktop_client
from backend.gmail_oauth import GmailService


class GmailBridge:
    """Owns one trusted Gmail launcher and its dedicated event loop."""

    def __init__(self, client_config: str):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="susnot-gmail-bridge",
            daemon=True,
        )
        self._closed = False
        self._expiry_timer = None
        self._thread.start()

        try:
            self._submit(self._initialize(client_config))
            self._expiry_timer = threading.Timer(
                1800,
                self.close,
            )
            self._expiry_timer.daemon = True
            self._expiry_timer.start()
        except Exception:
            self.close()
            raise

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _submit(self, coroutine):
        if self._closed:
            coroutine.close()
            raise RuntimeError("Gmail bridge is closed")

        future: Future = asyncio.run_coroutine_threadsafe(
            coroutine, self._loop
        )
        return future.result(timeout=120)

    async def _initialize(self, client_config):
        from backend.main import app
        from backend.gmail_security import GmailControl

        # Create a separate application/control plane for this bridge.
        # Never configure the process-global backend.main.app directly.
        from fastapi import FastAPI
        from backend.gmail_routes import router as gmail_routes
        from backend.gmail_security import (
            GmailControlMiddleware,
            router as gmail_security_router,
        )

        self._app = FastAPI()
        self._app.state.gmail_control = GmailControl()
        self._app.state.gmail_service = GmailService(
            load_desktop_client(client_config),
            self._app.state.gmail_control,
        )
        self._app.add_middleware(
            GmailControlMiddleware,
            control=self._app.state.gmail_control,
        )
        self._app.include_router(gmail_security_router)
        self._app.include_router(gmail_routes)

        self._lifespan = self._app.router.lifespan_context(self._app)
        await self._lifespan.__aenter__()

        self._launcher = TrustedLauncher(
            self._app,
            confirmed=True,
        )
        await self._launcher.__aenter__()

    def status(self):
        return self._submit(self._launcher.status())

    def identity(self):
        return self._submit(self._launcher.identity(consent=True))

    def authorize(self, remember=False):
        return self._submit(
            self._launcher.authorize(
                consent=True,
                remember=remember,
            )
        )




    def list_messages(self, next_page=False):
        return self._submit(
            self._launcher.list_messages(
                consent=True,
                next_page=next_page,
            )
        )

    def investigate(self, indices, record_history=False):
        return self._submit(
            self._launcher.investigate(
                indices,
                consent=True,
                record_history=record_history,
            )
        )

    def evidence(self):
        return self._submit(
            self._launcher.evidence(consent=True)
        )


    def disconnect(self):
        return self._submit(
            self._launcher.disconnect(consent=True)
        )

    def close(self):
        if self._closed:
            return

        self._closed = True

        timer = self._expiry_timer
        if timer is not None:
            timer.cancel()

        async def shutdown():
            launcher = getattr(self, "_launcher", None)
            if launcher is not None:
                await launcher.__aexit__(None, None, None)

            lifespan = getattr(self, "_lifespan", None)
            if lifespan is not None:
                await lifespan.__aexit__(None, None, None)

        try:
            future = asyncio.run_coroutine_threadsafe(
                shutdown(), self._loop
            )
            future.result(timeout=15)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)
