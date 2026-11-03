"""SUS.NOT: local Qwen agent with an enforced MCP tool boundary."""

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


ROOT = Path(__file__).resolve().parents[1]
MODEL = "qwen3.5:4b-q4_K_M"
OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
OUTPUT = ROOT / "evidence" / "qwen-tool-call.json"

TEST_URL = "https://user@192.0.2.1/verify"

TOOL = {
    "type": "function",
    "function": {
        "name": "inspect_url",
        "description": (
            "Inspect a URL using SUS.NOT's deterministic security "
            "analysis. Use this tool when asked to assess a URL."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The complete URL to investigate",
                }
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    },
}


async def main():
    trace = {
        "project": "SUS.NOT",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model": MODEL,
        "tool": "inspect_url",
        "events": [],
    }

    payload = {
        "model": MODEL,
        "stream": False,
        "options": {"num_ctx": 8192, "temperature": 0},
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity investigation assistant. "
                    "For URL investigations, call inspect_url. "
                    "Do not guess risk scores. "
                    "The tool provides the authoritative result."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Investigate this URL using your tool: {TEST_URL}"
                ),
            },
        ],
        "tools": [TOOL],
    }

    print("1. Asking local Qwen to select a tool...")

    async with httpx.AsyncClient(
        timeout=180,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = await client.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        model_response = response.json()

    message = model_response.get("message", {})
    calls = message.get("tool_calls") or []

    trace["events"].append({
        "operation": "model_tool_selection",
        "tool_calls": calls,
    })

    if len(calls) != 1:
        raise RuntimeError(
            f"Expected exactly one model tool call; received {len(calls)}."
        )

    function = calls[0].get("function", {})

    if function.get("name") != "inspect_url":
        raise RuntimeError("Model selected an unauthorized tool.")

    arguments = function.get("arguments", {})

    if isinstance(arguments, str):
        arguments = json.loads(arguments)

    if not isinstance(arguments, dict):
        raise RuntimeError("Invalid tool arguments.")

    if set(arguments) != {"url"}:
        raise RuntimeError("Unexpected tool arguments.")

    if arguments["url"] != TEST_URL:
        raise RuntimeError("Model altered the investigation URL.")

    print("2. Qwen selected inspect_url.")
    print("3. Starting the actual SUS.NOT MCP server...")

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "backend.mcp_server"],
        cwd=str(ROOT),
    )

    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()

            available = {
                tool.name
                for tool in (await session.list_tools()).tools
            }

            if "inspect_url" not in available:
                raise RuntimeError("MCP tool is unavailable.")

            result = await session.call_tool(
                "inspect_url",
                arguments,
            )

    if result.is_error:
        raise RuntimeError("MCP tool returned an error.")

    assessment = result.structured_content

    if not isinstance(assessment, dict):
        raise RuntimeError("MCP tool returned invalid structured data.")

    if assessment.get("sus_score") != 70:
        raise RuntimeError("Unexpected investigation score.")

    trace["events"].append({
        "operation": "mcp_tool_invocation",
        "arguments": arguments,
        "result": assessment,
    })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    OUTPUT.write_text(
        json.dumps(trace, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("4. MCP tool invocation successful.")
    print("5. Evidence saved.")

    print("\n===== SUS.NOT AGENT RESULT =====")
    print("Model:", MODEL)
    print("Selected tool:", function["name"])
    print("SUS Score:", assessment["sus_score"])
    print("Risk level:", assessment["risk_level"])
    print("Evidence:", OUTPUT)


if __name__ == "__main__":
    asyncio.run(main())
