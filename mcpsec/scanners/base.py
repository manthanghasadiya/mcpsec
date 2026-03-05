"""
Base scanner interface — all scanners inherit from this.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile


class BaseScanner(ABC):
    """Abstract base class for all mcpsec scanners."""

    name: str = "base"
    description: str = "Base scanner"

    @abstractmethod
    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]:
        """
        Run the scanner against a server profile.

        Args:
            profile: The enumerated server profile (tools, resources, prompts)
            client: Optional live MCP client for dynamic testing

        Returns:
            List of findings
        """
        ...

    def __repr__(self) -> str:
        return f"<Scanner:{self.name}>"

    def _get_dummy_args(
        self, tool: ServerProfile.ToolInfo, target_param: str, payload: Any
    ) -> dict[str, Any]:
        """
        Generate a dictionary of arguments for a tool call, including the target payload
        and dummy values for all other required parameters to satisfy schema validation.
        """
        args = {target_param: payload}

        schema = tool.raw_schema
        if "inputSchema" in schema:
            schema = schema["inputSchema"]

        required = schema.get("required", [])
        props = schema.get("properties", {})

        for req_param in required:
            if req_param == target_param:
                continue

            # Provide a dummy value based on type
            p_def = props.get(req_param, {})
            p_type = p_def.get("type", "string")

            if p_type == "string":
                # Handle enums
                if "enum" in p_def and p_def["enum"]:
                    args[req_param] = p_def["enum"][0]
                else:
                    args[req_param] = "mcpsec_test"
            elif p_type == "integer" or p_type == "number":
                args[req_param] = 1
            elif p_type == "boolean":
                args[req_param] = False
            elif p_type == "object":
                args[req_param] = {}
            elif p_type == "array":
                args[req_param] = []

        return args
