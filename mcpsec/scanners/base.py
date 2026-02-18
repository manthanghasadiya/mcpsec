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
    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
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
