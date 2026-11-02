"""Test MCP server with vulnerable and safe command tools for oracle validation."""

import asyncio
import os
import subprocess
from mcp.server import Server
import mcp.types as types

try:
    from compat import register_handlers, run_server
except ImportError:
    from tests.servers.compat import register_handlers, run_server

server = Server("vulnerable-cmd-server")

TOOLS = [
    types.Tool(
        name="execute_cmd",
        description="Execute a shell command (vulnerable to command injection)",
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The command to run"},
            },
            "required": ["command"],
        },
    ),
    types.Tool(
        name="safe_echo",
        description="Safely echoes user input without shell execution",
        inputSchema={
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to echo back"},
            },
            "required": ["text"],
        },
    ),
    types.Tool(
        name="blind_cmd",
        description="Executes a command silently in the background (blind injection)",
        inputSchema={
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "Action command"},
            },
            "required": ["action"],
        },
    ),
]


async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    arguments = arguments or {}

    if name == "execute_cmd":
        cmd = arguments.get("command", "")
        try:
            # Vulnerable: shell execution via shell=True
            proc = subprocess.run(
                f"echo {cmd}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            out = proc.stdout + proc.stderr
            return [types.TextContent(type="text", text=out or "executed")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {e}")]

    elif name == "safe_echo":
        text = arguments.get("text", "")
        # Safe: purely echoes the argument string without executing
        return [types.TextContent(type="text", text=f"Echo output: {text}")]

    elif name == "blind_cmd":
        action = arguments.get("action", "")
        try:
            # Blind vulnerable: executes command without returning stdout
            subprocess.run(
                f"echo starting >/dev/null && {action}",
                shell=True,
                capture_output=True,
                timeout=15,
            )
            return [types.TextContent(type="text", text="Action completed")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Action error: {e}")]

    raise ValueError(f"Unknown tool: {name}")


register_handlers(server, TOOLS, handle_call_tool)


async def main():
    await run_server(server)


if __name__ == "__main__":
    asyncio.run(main())
