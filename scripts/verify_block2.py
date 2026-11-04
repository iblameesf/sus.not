"""Verify Block 2: Recorded MCP client/server execution evidence."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "mcp-live-trace.json"


def main():
    assert EVIDENCE.is_file(), "MCP evidence file missing"

    data = json.loads(EVIDENCE.read_text())

    assert data["project"] == "SUS.NOT"
    assert data["transport"] == "stdio"
    assert data["server"] == "backend.mcp_server"
    assert data["model_used"] is False

    events = data["events"]

    initialization = next(
        event for event in events
        if event["operation"] == "initialize"
    )

    assert initialization["server_name"] == "SUS.NOT"
    assert initialization["protocol_version"]

    listing = next(
        event for event in events
        if event["operation"] == "tools/list"
    )

    tools = {tool["name"]: tool for tool in listing["tools"]}

    assert "inspect_url" in tools
    assert "inspect_text" in tools

    url_schema = tools["inspect_url"]["input_schema"]
    assert "url" in url_schema["required"]
    assert url_schema["properties"]["url"]["type"] == "string"

    calls = [
        event for event in events
        if event["operation"] == "tools/call"
        and event["tool"] == "inspect_url"
    ]

    successful = next(
        call for call in calls
        if call["is_error"] is False
    )

    assert successful["arguments"]["url"] == (
        "https://user@192.0.2.1/verify"
    )

    response = successful["response"]

    assert response["sus_score"] == 70
    assert response["risk_level"] == "high"
    assert isinstance(response["indicators"], list)
    assert len(response["indicators"]) > 0
    assert isinstance(response["explanation"], str)

    rejected = next(
        call for call in calls
        if call["arguments"]["url"] == "file:///etc/passwd"
    )

    assert rejected["is_error"] is True
    assert isinstance(rejected["response"], list)
    assert any(
        "Invalid URL" in message
        for message in rejected["response"]
    )

    print("===== BLOCK 2 VERIFICATION =====")
    print("MCP transport and server identity: PASS")
    print("MCP initialization: PASS")
    print("MCP tool discovery: PASS")
    print("inspect_url input schema: PASS")
    print("Recorded successful tool invocation: PASS")
    print("Recorded invalid URL rejection: PASS")
    print("BLOCK 2: PASS (recorded MCP evidence validated)")
    print("Note: This does not start a new MCP server.")


if __name__ == "__main__":
    main()
