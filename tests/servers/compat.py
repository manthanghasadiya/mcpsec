"""Dual-version MCP SDK compatibility helpers (mcp >= 1.0.0 and 2.x).

The 2026-07-28 SDK (2.x) replaced the decorator API (@server.list_tools,
@server.call_tool) with explicit handler registration (add_request_handler)
and removed InitializationOptions/get_capabilities in favor of
create_initialization_options. These helpers let test servers run on both.
"""

import mcp.types as types


def is_modern_sdk(server) -> bool:
    """True when running against the 2026-07-28 SDK (2.x)."""
    return hasattr(server, "add_request_handler")


def register_handlers(server, tools: list[types.Tool], call_impl) -> None:
    """Register tools/list and tools/call handlers across SDK versions.

    Args:
        server: mcp.server.Server instance.
        tools: List of types.Tool to advertise.
        call_impl: async callable (name: str, arguments: dict) -> list[types.TextContent].
    """
    if is_modern_sdk(server):
        async def handle_list(ctx, params: types.PaginatedRequestParams):
            return types.ListToolsResult(
                tools=tools,
                ttlMs=0,
                cacheScope="private",
                resultType="complete",
            )

        async def handle_call(ctx, params: types.CallToolRequestParams):
            result = await call_impl(params.name, params.arguments or {})
            return types.CallToolResult(
                content=result,
                resultType="complete",
            )

        server.add_request_handler("tools/list", types.PaginatedRequestParams, handle_list)
        server.add_request_handler("tools/call", types.CallToolRequestParams, handle_call)
    else:
        @server.list_tools()
        async def handle_list():
            return tools

        @server.call_tool()
        async def handle_call(name: str, arguments: dict | None):
            return await call_impl(name, arguments or {})


async def run_server(server) -> None:
    """Run a server over stdio with version-appropriate initialization options."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        if is_modern_sdk(server):
            options = server.create_initialization_options()
        else:
            from mcp.server import NotificationOptions
            from mcp.server.models import InitializationOptions

            options = InitializationOptions(
                server_name=server.name,
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            )
        await server.run(read_stream, write_stream, options)
