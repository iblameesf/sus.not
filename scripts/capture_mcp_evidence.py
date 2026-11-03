"""Capture real MCP protocol evidence from the SUS.NOT server."""

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "evidence" / "mcp-live-trace.json"


async def main():
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "backend.mcp_server"],
        cwd=str(ROOT),
    )

    trace = {
        "project": "SUS.NOT",
        "evidence_type": "Real MCP subprocess invocation",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "transport": "stdio",
        "server": "backend.mcp_server",
        "model_used": False,
        "events": [],
    }

    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:

            initialization = await session.initialize()

            trace["events"].append({
                "operation": "initialize",
                "server_name": initialization.server_info.name,
                "protocol_version": initialization.protocol_version,
            })

            tools = (await session.list_tools()).tools

            trace["events"].append({
                "operation": "tools/list",
                "tools": [
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.input_schema,
                    }
                    for tool in tools
                ],
            })

            valid_url = "https://user@192.0.2.1/verify"

            valid = await session.call_tool(
                "inspect_url",
                {"url": valid_url},
            )

            trace["events"].append({
                "operation": "tools/call",
                "tool": "inspect_url",
                "arguments": {"url": valid_url},
                "is_error": valid.is_error,
                "response": valid.structured_content,
            })

            invalid_url = "file:///etc/passwd"

            invalid = await session.call_tool(
                "inspect_url",
                {"url": invalid_url},
            )

            trace["events"].append({
                "operation": "tools/call",
                "tool": "inspect_url",
                "arguments": {"url": invalid_url},
                "is_error": invalid.is_error,
                "response": [
                    getattr(item, "text", str(item))
                    for item in invalid.content
                ],
            })

    assert not valid.is_error, "Valid MCP call failed"
    assert valid.structured_content["sus_score"] == 70
    assert valid.structured_content["risk_level"] == "high"
    assert invalid.is_error, "Unsafe URL was not rejected"

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    OUTPUT.write_text(
        json.dumps(trace, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n===== SUS.NOT MCP EVIDENCE =====")
    print("Server initialization: PASS")
    print("Tool discovery: PASS")
    print("Valid URL invocation: PASS")
    print("HIGH-risk score: 70/100")
    print("Invalid URL rejection: PASS")
    print(f"\nEvidence saved: {OUTPUT}")


if __name__ == "__main__":
    asyncio.run(main())
