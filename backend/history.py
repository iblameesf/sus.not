"""Opt-in, local, privacy-minimized investigation metadata (stdlib SQLite)."""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query

DEFAULT_DATABASE = Path(__file__).resolve().parents[1] / "data" / "investigations.sqlite3"


def history_enabled() -> bool:
    return os.environ.get("SUSNOT_HISTORY_ENABLED", "").lower() == "true"


def redact_url(url: str) -> str:
    """Retain only the scheme: even hostnames can contain private identifiers."""
    scheme = urlsplit(url).scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Expected an HTTP(S) URL")
    return f"{scheme}://[redacted]"


class HistoryStore:
    def __init__(self, path: str | Path):
        # A filesystem path, not a SQLite URI or remote database service.
        self.path = Path(path)

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    investigation_id TEXT PRIMARY KEY,
                    timestamp_utc TEXT NOT NULL,
                    investigation_type TEXT NOT NULL CHECK (investigation_type IN ('URL', 'text')),
                    redacted_url TEXT,
                    sus_score INTEGER,
                    risk_level TEXT,
                    indicators TEXT NOT NULL,
                    recommended_action TEXT,
                    policy_version TEXT,
                    analysis_status TEXT NOT NULL CHECK (analysis_status IN ('completed', 'failed'))
                )
            """)
            connection.execute("""CREATE INDEX IF NOT EXISTS investigations_timestamp
                ON investigations(timestamp_utc DESC, investigation_id DESC)""")

    def create(self, *, investigation_type: str, redacted_url: str | None = None,
               sus_score: int | None = None, risk_level: str | None = None,
               indicators: list[str] | None = None, recommended_action: str | None = None,
               policy_version: str | None = None, analysis_status: str = "completed") -> dict:
        record = {
            "investigation_id": str(uuid4()),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "investigation_type": investigation_type,
            "redacted_url": redacted_url,
            "sus_score": sus_score,
            "risk_level": risk_level,
            "indicators": indicators or [],
            "recommended_action": recommended_action,
            "policy_version": policy_version,
            "analysis_status": analysis_status,
        }
        values = {**record, "indicators": json.dumps(record["indicators"])}
        self.initialize()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("""INSERT INTO investigations VALUES (
                :investigation_id, :timestamp_utc, :investigation_type, :redacted_url,
                :sus_score, :risk_level, :indicators, :recommended_action,
                :policy_version, :analysis_status
            )""", values)
        return record

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict:
        record = dict(row)
        record["indicators"] = json.loads(record["indicators"])
        return record

    def get(self, investigation_id: str) -> dict | None:
        self.initialize()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM investigations WHERE investigation_id = ?", (investigation_id,)
            ).fetchone()
        return self._decode(row) if row else None

    def list(self, *, limit: int = 20, offset: int = 0) -> dict:
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("Invalid pagination")
        self.initialize()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.row_factory = sqlite3.Row
            # Keep count and page in the same read transaction.
            connection.execute("BEGIN")
            total = connection.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
            rows = connection.execute("""SELECT * FROM investigations
                ORDER BY timestamp_utc DESC, investigation_id DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        return {"items": [self._decode(row) for row in rows], "total": total,
                "limit": limit, "offset": offset}


def configured_store() -> HistoryStore:
    return HistoryStore(os.environ.get("SUSNOT_HISTORY_DB", str(DEFAULT_DATABASE)))


def record_history(consent: str | None, **metadata) -> None:
    if not history_enabled() or consent != "true":
        return
    try:
        configured_store().create(**metadata)
    except (OSError, sqlite3.Error):
        # Optional persistence must not break analysis or expose input/error details.
        pass


router = APIRouter()


@router.get("/history-status")
def get_history_status():
    """Expose enablement only, never database paths or configuration secrets."""
    return {"enabled": history_enabled()}


@router.get("/investigations")
def list_investigations(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)):
    if not history_enabled():
        return {"items": [], "total": 0, "limit": limit, "offset": offset}
    try:
        return configured_store().list(limit=limit, offset=offset)
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "Local history is unavailable.") from None


@router.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: UUID):
    if not history_enabled():
        raise HTTPException(404, "Investigation not found.")
    try:
        record = configured_store().get(str(investigation_id))
    except (OSError, sqlite3.Error):
        raise HTTPException(503, "Local history is unavailable.") from None
    if record is None:
        raise HTTPException(404, "Investigation not found.")
    return record
