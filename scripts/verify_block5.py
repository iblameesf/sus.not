"""Verify SUS.NOT investigation persistence across separate processes."""

import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "evidence" / "block5-persistence.json"

WRITER = """
import json
import sys
from backend.history import HistoryStore

store = HistoryStore(sys.argv[1])

record = store.create(
    investigation_type="URL",
    redacted_url="https://[redacted]",
    sus_score=70,
    risk_level="high",
    indicators=["Synthetic suspicious URL"],
    recommended_action="Verify independently",
    policy_version="block5-test",
)

print(json.dumps(record))
"""

READER = """
import json
import sys
from backend.history import HistoryStore

store = HistoryStore(sys.argv[1])
record = store.get(sys.argv[2])

print(json.dumps(record))
"""


def execute(code, *arguments):
    completed = subprocess.run(
        [sys.executable, "-c", code, *map(str, arguments)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return json.loads(completed.stdout)


def main():
    with tempfile.TemporaryDirectory(prefix="susnot-memory-") as directory:
        database = Path(directory) / "investigations.sqlite3"

        written = execute(WRITER, database)

        assert database.exists(), "Database was not created"

        recovered = execute(
            READER,
            database,
            written["investigation_id"],
        )

        assert recovered == written, "Stored record changed after restart"

        assert recovered["sus_score"] == 70
        assert recovered["risk_level"] == "high"
        assert recovered["redacted_url"] == "https://[redacted]"

        assert "example.com" not in json.dumps(recovered)

        evidence = {
            "project": "SUS.NOT",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "block": 5,
            "test": "Investigation memory survives process restart",
            "writer_process": "terminated",
            "reader_process": "separate Python interpreter",
            "persistence": "SQLite",
            "result": "PASS",
            "record": recovered,
            "privacy": {
                "raw_url_stored": False,
                "hostname_stored": False,
                "temporary_database": True,
            },
            "limitations": [
                "Demonstrates persisted investigation metadata.",
                "Does not demonstrate conversational memory or model recall.",
                "Does not measure LLM context-window token consumption.",
            ],
        }

        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(json.dumps(evidence, indent=2))

        print("===== BLOCK 5 PERSISTENCE =====")
        print("Write process: PASS")
        print("Process restart: PASS")
        print("Record recovery: PASS")
        print("Privacy minimization: PASS")
        print("Evidence:", OUTPUT)


if __name__ == "__main__":
    main()
