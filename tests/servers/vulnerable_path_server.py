"""Test MCP server with vulnerable, reflection, and safe file reading tools for path traversal oracle validation."""

import asyncio
import os
import tempfile
from mcp.server import Server
import mcp.types as types

try:
    from compat import register_handlers, run_server
except ImportError:
    from tests.servers.compat import register_handlers, run_server

server = Server("vulnerable-path-server")

SAFE_BASE_DIR = os.path.realpath(os.path.join(tempfile.gettempdir(), "mcpsec_safe_base"))
os.makedirs(SAFE_BASE_DIR, exist_ok=True)
SAFE_FILE_PATH = os.path.join(SAFE_BASE_DIR, "safe.txt")
with open(SAFE_FILE_PATH, "w", encoding="utf-8") as f:
    f.write("safe content")

TOOLS = [
    types.Tool(
        name="read_file",
        description="Read file contents from an arbitrary path (vulnerable to path traversal)",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path of file to read"},
            },
            "required": ["path"],
        },
    ),
    types.Tool(
        name="reflect_path",
        description="Echoes the path string without reading from disk",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to echo"},
            },
            "required": ["path"],
        },
    ),
    types.Tool(
        name="safe_read",
        description="Safely reads file within allowlisted directory only",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to read"},
            },
            "required": ["path"],
        },
    ),
]


async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    arguments = arguments or {}

    if name == "read_file":
        path = arguments.get("path", "")
        if path.startswith("file://"):
            path = path[7:]
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(4096)
                return [types.TextContent(type="text", text=content)]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error reading file: {e}")]

    elif name == "reflect_path":
        path = arguments.get("path", "")
        # Purely returns the path string without touching the file system
        return [types.TextContent(type="text", text=f"Echo path: {path}")]

    elif name == "safe_read":
        path = arguments.get("path", "")
        if path.startswith("file://"):
            path = path[7:]
        # Normalize slashes for cross-platform containment check
        norm_path = path.replace("\\", "/")
        if os.path.isabs(path) and not path.startswith(SAFE_BASE_DIR):
            return [
                types.TextContent(
                    type="text",
                    text=f"Error: Access denied. Path outside allowed directory: {path}",
                )
            ]
        resolved = os.path.realpath(os.path.join(SAFE_BASE_DIR, norm_path.lstrip("/")))
        if not (resolved == SAFE_BASE_DIR or resolved.startswith(SAFE_BASE_DIR + os.sep)):
            return [
                types.TextContent(
                    type="text",
                    text=f"Error: Access denied. Path outside allowed directory: {path}",
                )
            ]
        try:
            with open(resolved, "r", encoding="utf-8", errors="replace") as f:
                return [types.TextContent(type="text", text=f.read(4096))]
        except Exception:
            return [
                types.TextContent(
                    type="text",
                    text=f"Error: Access denied. Cannot read file: {path}",
                )
            ]

    raise ValueError(f"Unknown tool: {name}")


register_handlers(server, TOOLS, handle_call_tool)


async def main():
    await run_server(server)


if __name__ == "__main__":
    asyncio.run(main())
