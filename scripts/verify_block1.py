"""Verify Block 1: Qwen-selected custom tool execution."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "qwen-tool-call.json"


def main():
    assert EVIDENCE.is_file(), "Block 1 evidence file missing"

    data = json.loads(EVIDENCE.read_text())

    assert data["project"] == "SUS.NOT"
    assert data["model"] == "qwen3.5:4b-q4_K_M"
    assert data["tool"] == "inspect_url"

    events = data["events"]

    selection = next(
        event for event in events
        if event["operation"] == "model_tool_selection"
    )

    invocation = next(
        event for event in events
        if event["operation"] == "mcp_tool_invocation"
    )

    tool_call = next(
        call for call in selection["tool_calls"]
        if call["function"]["name"] == "inspect_url"
    )

    selected_arguments = tool_call["function"]["arguments"]
    executed_arguments = invocation["arguments"]

    assert selected_arguments == executed_arguments, (
        "Selected tool arguments differ from executed arguments"
    )

    result = invocation["result"]

    assert isinstance(result["sus_score"], (int, float))
    assert 0 <= result["sus_score"] <= 100
    assert result["risk_level"] in {"low", "medium", "high"}
    assert isinstance(result["indicators"], list)
    assert isinstance(result["explanation"], str)

    print("===== BLOCK 1 VERIFICATION =====")
    print("Qwen model identification: PASS")
    print("Model-selected tool: PASS")
    print("Tool arguments match invocation: PASS")
    print("Recorded tool result structure: PASS")
    print("BLOCK 1: PASS (recorded evidence validated)")
    print("Note: This does not rerun Qwen.")


if __name__ == "__main__":
    main()
