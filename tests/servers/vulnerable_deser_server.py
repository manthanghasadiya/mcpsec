"""Test MCP server with vulnerable, safe, and reflecting YAML tools."""

import asyncio
import yaml
from mcp.server import Server
import mcp.types as types

try:
    from compat import register_handlers, run_server
except ImportError:
    from tests.servers.compat import register_handlers, run_server

server = Server("vulnerable-deser-server")

TOOLS = [
    types.Tool(
        name="load_config",
        description="Load YAML configuration (vulnerable: uses UnsafeLoader)",
        inputSchema={
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "YAML configuration string"},
            },
            "required": ["data"],
        },
    ),
    types.Tool(
        name="safe_load_config",
        description="Safely parse YAML configuration using safe_load",
        inputSchema={
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "YAML configuration string"},
            },
            "required": ["data"],
        },
    ),
    types.Tool(
        name="reflect_config",
        description="Echoes the configuration string without YAML parsing",
        inputSchema={
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Configuration string to echo"},
            },
            "required": ["data"],
        },
    ),
]


async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    arguments = arguments or {}

    if name == "load_config":
        data = arguments.get("data", "")
        try:
            # Vulnerable: constructs python objects, triggering sleep
            parsed = yaml.load(data, Loader=yaml.UnsafeLoader)
            return [types.TextContent(type="text", text=f"Config loaded: {type(parsed).__name__}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error loading config: {e}")]

    elif name == "safe_load_config":
        data = arguments.get("data", "")
        try:
            # Safe: refuses python object tags, raises ConstructorError
            parsed = yaml.safe_load(data)
            return [types.TextContent(type="text", text=f"Config loaded: {type(parsed).__name__}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Safe load rejected: {type(e).__name__}: {e}")]

    elif name == "reflect_config":
        data = arguments.get("data", "")
        return [types.TextContent(type="text", text=f"Echo config: {data}")]

    raise ValueError(f"Unknown tool: {name}")


register_handlers(server, TOOLS, handle_call_tool)


async def main():
    await run_server(server)


if __name__ == "__main__":
    asyncio.run(main())
