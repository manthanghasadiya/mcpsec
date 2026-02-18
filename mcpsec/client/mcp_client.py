"""
MCP client — connects to MCP servers via stdio or HTTP, enumerates tools/resources/prompts.
"""

from __future__ import annotations

import asyncio
import json
import shlex
from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from mcpsec.models import (
    PromptInfo,
    ResourceInfo,
    ServerProfile,
    ToolInfo,
    TransportType,
)
from mcpsec.ui import console


class MCPSecClient:
    """Client that connects to an MCP server and enumerates its attack surface."""

    def __init__(self):
        self.session: ClientSession | None = None
        self._exit_stack = AsyncExitStack()
        self._profile: ServerProfile | None = None

    async def connect_stdio(self, command: str, args: list[str] | None = None, env: dict | None = None) -> ServerProfile:
        """Connect to an MCP server via stdio transport."""
        if not args:
            # Parse command string into command + args
            parts = shlex.split(command)
            command = parts[0]
            args = parts[1:] if len(parts) > 1 else []

        server_params = StdioServerParameters(
            command=command,
            args=args,
            env=env,
        )

        stdio_transport = await self._exit_stack.enter_async_context(
            stdio_client(server_params)
        )
        read_stream, write_stream = stdio_transport
        self.session = await self._exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await self.session.initialize()
        return await self._enumerate()

    async def connect_http(self, url: str, headers: dict | None = None) -> ServerProfile:
        """Connect to an MCP server via streamable HTTP transport."""
        http_transport = await self._exit_stack.enter_async_context(
            streamablehttp_client(url=url, headers=headers)
        )
        read_stream, write_stream = http_transport[0], http_transport[1]
        self.session = await self._exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await self.session.initialize()
        return await self._enumerate()

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """Call a tool on the connected MCP server. Returns the raw result."""
        if not self.session:
            raise RuntimeError("Not connected to any MCP server")
        try:
            result = await self.session.call_tool(tool_name, arguments)
            return result
        except Exception as e:
            return {"error": str(e)}

    async def _enumerate(self) -> ServerProfile:
        """Enumerate all tools, resources, and prompts from the server."""
        if not self.session:
            raise RuntimeError("Not connected")

        profile = ServerProfile()

        # ── Enumerate Tools ──────────────────────────────────────────────
        try:
            tools_result = await self.session.list_tools()
            for tool in tools_result.tools:
                params = {}
                raw_schema = {}
                if tool.inputSchema and "properties" in tool.inputSchema:
                    raw_schema = tool.inputSchema
                    for param_name, param_def in tool.inputSchema["properties"].items():
                        param_type = param_def.get("type", "any")
                        params[param_name] = param_type

                annotations = {}
                if hasattr(tool, "annotations") and tool.annotations:
                    ann = tool.annotations
                    if hasattr(ann, "model_dump"):
                        annotations = ann.model_dump(exclude_none=True)
                    elif isinstance(ann, dict):
                        annotations = ann

                profile.tools.append(ToolInfo(
                    name=tool.name,
                    description=tool.description or "",
                    parameters=params,
                    annotations=annotations,
                    raw_schema=raw_schema,
                ))
        except Exception as e:
            console.print(f"  [warning]⚠ Failed to enumerate tools: {e}[/warning]")

        # ── Enumerate Resources ──────────────────────────────────────────
        try:
            resources_result = await self.session.list_resources()
            for res in resources_result.resources:
                profile.resources.append(ResourceInfo(
                    uri=str(res.uri),
                    name=res.name or "",
                    description=res.description or "",
                    mime_type=res.mimeType or "",
                ))
        except Exception:
            pass  # Resources are optional

        # ── Enumerate Prompts ────────────────────────────────────────────
        try:
            prompts_result = await self.session.list_prompts()
            for prompt in prompts_result.prompts:
                args = []
                if prompt.arguments:
                    for arg in prompt.arguments:
                        args.append({
                            "name": arg.name,
                            "description": arg.description or "",
                            "required": arg.required if hasattr(arg, "required") else False,
                        })
                profile.prompts.append(PromptInfo(
                    name=prompt.name,
                    description=prompt.description or "",
                    arguments=args,
                ))
        except Exception:
            pass  # Prompts are optional

        self._profile = profile
        return profile

    @property
    def profile(self) -> ServerProfile | None:
        return self._profile

    async def close(self):
        """Clean up connections."""
        await self._exit_stack.aclose()
