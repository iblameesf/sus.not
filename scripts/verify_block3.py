"""Verify Block 3: Code-enforced restrictions."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "blocks3-4-verification.json"

TEST_FILES = [
    "tests/test_mcp_server.py",
    "tests/test_guardian_demo_fixture.py",
]


def main():
    print("===== BLOCK 3 VERIFICATION =====")

    assert EVIDENCE.is_file(), "Historical evidence file missing"

    data = json.loads(EVIDENCE.read_text())
    assert data["project"] == "SUS.NOT"

    recorded = data["checks"]["block3_guardrails"]

    assert recorded["return_code"] == 0, (
        "Historical guardrail tests did not pass"
    )

    print("Historical test evidence: PASS")
    print("Running targeted restriction tests...")

    result = subprocess.run(
        [sys.executable, "-m", "pytest", *TEST_FILES, "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    if result.stdout:
        print(result.stdout.strip())

    if result.stderr:
        print(result.stderr.strip())

    assert result.returncode == 0, (
        f"Targeted tests failed with exit code {result.returncode}"
    )

    print("Targeted tests: PASS")
    print("BLOCK 3: PASS (targeted tests executed successfully)")
    print(
        "Limitation: These tests verify their implemented assertions, "
        "not every possible security restriction."
    )


if __name__ == "__main__":
    main()
