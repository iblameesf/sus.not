
"""Optional, privacy-minimized local runtime event logging."""

import json
import math

import os

import threading

from datetime import datetime, timezone

from pathlib import Path

DEFAULT_LOG_PATH = Path(__file__).resolve().parents[1] / "data" / "runtime.jsonl"

MAX_LOG_BYTES = 2_000_000

_LOCK = threading.Lock()

ALLOWED_EVENTS = {

    "url_analysis_completed",

    "url_evaluation_completed",

}

ALLOWED_RISKS = {"low", "review", "high", "critical"}

def log_event(

    event: str,

    *,

    score: int,

    risk_level: str,

    duration_ms: float,

) -> None:

    """Write an allowlisted event without URLs or personal content."""

    if os.environ.get("SUSNOT_RUNTIME_LOG_ENABLED", "").lower() != "true":

        return

    if event not in ALLOWED_EVENTS:

        return

    if type(score) is not int or not 0 <= score <= 100:

        return

    if risk_level not in ALLOWED_RISKS:

        return

    if (type(duration_ms) not in (int, float)
            or not math.isfinite(duration_ms)
            or duration_ms < 0):

        return

    record = {

        "timestamp_utc": datetime.now(timezone.utc).isoformat(),

        "event": event,

        "sus_score": score,

        "risk_level": risk_level,

        "duration_ms": round(duration_ms, 2),

    }

    try:

        path = Path(os.environ.get("SUSNOT_RUNTIME_LOG_PATH", str(DEFAULT_LOG_PATH)))

        with _LOCK:

            path.parent.mkdir(parents=True, exist_ok=True)

            if path.exists() and path.stat().st_size >= MAX_LOG_BYTES:

                backup = path.with_suffix(".jsonl.1")

                path.replace(backup)

            with path.open("a", encoding="utf-8") as handle:

                handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    except (OSError, ValueError):

        # Logging must never interrupt the security assessment.

        return
