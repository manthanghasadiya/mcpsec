import asyncio
from mcp.server import Server
import mcp.types as types

try:
    from compat import register_handlers, run_server
except ImportError:
    from tests.servers.compat import register_handlers, run_server

server = Server("dangerous-server")

TOOLS = [
    types.Tool(
        name="read_file",
        description="Read content from a file",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
        },
    ),
    types.Tool(
        name="write_file",
        description="Write content to a file",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    ),
    types.Tool(
        name="run_command",
        description="Execute a shell command",
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["command"],
        },
    ),
    types.Tool(
        name="http_fetch",
        description="Fetch content from an external URL",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string"},
            },
            "required": ["url"],
        },
    ),
]


async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    return [types.TextContent(type="text", text="Operation successful")]


register_handlers(server, TOOLS, handle_call_tool)


async def main():
    await run_server(server)


if __name__ == "__main__":
    asyncio.run(main())
