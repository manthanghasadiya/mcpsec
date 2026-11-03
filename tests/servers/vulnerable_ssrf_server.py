"""Test MCP server with vulnerable and safe URL fetching tools for SSRF oracle validation."""

import asyncio
import urllib.parse
import urllib.request
from mcp.server import Server
import mcp.types as types

try:
    from compat import register_handlers, run_server
except ImportError:
    from tests.servers.compat import register_handlers, run_server

server = Server("vulnerable-ssrf-server")

TOOLS = [
    types.Tool(
        name="fetch_url",
        description="Fetch content from an arbitrary URL (vulnerable to SSRF)",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to fetch", "format": "uri"},
            },
            "required": ["url"],
        },
    ),
    types.Tool(
        name="reflect_url",
        description="Echoes the URL string back without making any network request",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to reflect", "format": "uri"},
            },
            "required": ["url"],
        },
    ),
    types.Tool(
        name="safe_fetch",
        description="Safely fetches from allowlisted hosts only",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL to fetch", "format": "uri"},
            },
            "required": ["url"],
        },
    ),
]


async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    arguments = arguments or {}

    if name == "fetch_url":
        url = arguments.get("url", "")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mcpsec-test-fetcher"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                content = resp.read(512)
                return [
                    types.TextContent(
                        type="text",
                        text=f"Fetched successfully: status={resp.status}, length={len(content)}",
                    )
                ]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Fetch error: {e}")]

    elif name == "reflect_url":
        url = arguments.get("url", "")
        # Purely returns the URL string without making any network request
        return [types.TextContent(type="text", text=f"Reflected URL: {url}")]

    elif name == "safe_fetch":
        url = arguments.get("url", "")
        parsed = urllib.parse.urlparse(url)
        allowed_hosts = ("api.example.com", "public.example.com")
        if parsed.hostname not in allowed_hosts:
            return [
                types.TextContent(
                    type="text",
                    text=f"Error: Host '{parsed.hostname}' is not in allowlist",
                )
            ]
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mcpsec-safe-fetcher"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return [types.TextContent(type="text", text=f"Safe fetch status={resp.status}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Fetch error: {e}")]

    raise ValueError(f"Unknown tool: {name}")


register_handlers(server, TOOLS, handle_call_tool)


async def main():
    await run_server(server)


if __name__ == "__main__":
    asyncio.run(main())
