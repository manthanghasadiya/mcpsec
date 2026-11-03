"""Test MCP server with non-keyword tool and parameter names to validate oracle aperture widening."""

import asyncio
import json
import os
import sqlite3
import subprocess
from mcp.server import Server
import mcp.types as types

try:
    from compat import register_handlers, run_server
except ImportError:
    from tests.servers.compat import register_handlers, run_server

server = Server("vulnerable-noname-server")

# In-memory SQLite database setup for handle(input)
conn = sqlite3.connect(":memory:")
cur = conn.cursor()
cur.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT, note TEXT)")
cur.execute("INSERT INTO records (value, note) VALUES ('test', 'example record')")
cur.execute("INSERT INTO records (value, note) VALUES ('sample', 'second record')")
conn.commit()

TOOLS = [
    types.Tool(
        name="do_thing",
        description="Performs an operation on the provided payload",
        inputSchema={
            "type": "object",
            "properties": {
                "payload": {"type": "string", "description": "Arbitrary operation payload"},
            },
            "required": ["payload"],
        },
    ),
    types.Tool(
        name="process",
        description="Processes the specified item",
        inputSchema={
            "type": "object",
            "properties": {
                "item": {"type": "string", "description": "Target item specifier"},
            },
            "required": ["item"],
        },
    ),
    types.Tool(
        name="handle",
        description="Handles the given input against the data store",
        inputSchema={
            "type": "object",
            "properties": {
                "input": {"type": "string", "description": "Search input"},
            },
            "required": ["input"],
        },
    ),
]


async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    arguments = arguments or {}

    if name == "do_thing":
        payload = arguments.get("payload", "")
        try:
            # Vulnerable to command injection via shell execution
            proc = subprocess.run(
                f"echo {payload}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            out = proc.stdout + proc.stderr
            return [types.TextContent(type="text", text=out or "executed")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {e}")]

    elif name == "process":
        item = arguments.get("item", "")
        try:
            # Vulnerable to path traversal: reads arbitrary file from disk
            if os.path.exists(item) and os.path.isfile(item):
                with open(item, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                return [types.TextContent(type="text", text=content)]
            else:
                return [types.TextContent(type="text", text=f"Item not found: {item}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {e}")]

    elif name == "handle":
        val = arguments.get("input", "")
        try:
            # Vulnerable to SQL injection via string formatting
            cur = conn.cursor()
            cur.execute(f"SELECT id, value, note FROM records WHERE value = '{val}'")
            rows = cur.fetchall()
            results = [{"id": r[0], "value": r[1], "note": r[2]} for r in rows]
            return [types.TextContent(type="text", text=json.dumps(results))]
        except Exception:
            return [types.TextContent(type="text", text="[]")]

    raise ValueError(f"Unknown tool: {name}")


register_handlers(server, TOOLS, handle_call_tool)


async def main():
    await run_server(server)


if __name__ == "__main__":
    asyncio.run(main())
