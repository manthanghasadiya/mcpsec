"""
Capability Escalation Scanner.

Tests whether MCP servers properly enforce their declared capabilities.
A server that declares limited capabilities but responds to undeclared
methods has a security issue - clients might trust the capability declaration.
"""

from __future__ import annotations

import logging
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile, Severity
from mcpsec.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class CapabilityEscalationScanner(BaseScanner):
    """Scans for capability enforcement issues."""

    name = "capability-escalation"
    description = "Tests if servers properly enforce declared capabilities"

    # Map of capabilities to their methods
    CAPABILITY_METHODS = {
        "tools": [
            ("tools/list", {}, "List tools"),
            ("tools/call", {"name": "__test__", "arguments": {}}, "Call tool"),
        ],
        "resources": [
            ("resources/list", {}, "List resources"),
            ("resources/read", {"uri": "test://resource"}, "Read resource"),
            ("resources/subscribe", {"uri": "test://resource"}, "Subscribe to resource"),
        ],
        "prompts": [
            ("prompts/list", {}, "List prompts"),
            ("prompts/get", {"name": "__test__"}, "Get prompt"),
        ],
        "logging": [
            ("logging/setLevel", {"level": "debug"}, "Set log level"),
        ],
        "sampling": [
            (
                "sampling/createMessage",
                {
                    "messages": [{"role": "user", "content": {"type": "text", "text": "test"}}],
                    "maxTokens": 10,
                },
                "Create sampling message",
            ),
        ],
    }

    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]:
        """Scan for capability enforcement issues."""
        findings = []

        if not client or not client.session:
            return [
                Finding(
                    severity=Severity.INFO,
                    scanner=self.name,
                    title="Capability scan requires live connection",
                    description="This scanner needs a live MCP connection to test capability enforcement",
                    detail="No live client session available",
                    remediation="Run with live server connection",
                )
            ]

        # Get declared capabilities from profile
        server_capabilities = profile.capabilities or {}
        declared = set()
        for cap in ("tools", "resources", "prompts", "logging"):
            if cap in server_capabilities:
                declared.add(cap)

        experimental = server_capabilities.get("experimental") or {}
        if isinstance(experimental, dict) and "sampling" in experimental:
            declared.add("sampling")
        if "sampling" in server_capabilities:
            declared.add("sampling")

        # Test undeclared capabilities
        for capability, methods in self.CAPABILITY_METHODS.items():
            if capability not in declared:
                # Server didn't declare this capability - test if it works anyway
                cap_findings = await self._test_undeclared_capability(
                    client, server_capabilities, capability, methods
                )
                findings.extend(cap_findings)

        # Also check if declared capabilities can be abused
        for capability in declared:
            cap_config = server_capabilities.get(capability)
            if cap_config is None and capability == "sampling" and isinstance(experimental, dict):
                cap_config = experimental.get("sampling")
            abuse_finding = self._check_capability_abuse(
                capability, cap_config if isinstance(cap_config, dict) else {}
            )
            if abuse_finding:
                findings.append(abuse_finding)

        return findings

    async def _invoke_method(
        self, client: MCPSecClient, method: str, params: dict
    ) -> Any:
        """Invoke client session method for a given MCP method string."""
        if not client.session:
            return None

        if method == "tools/list":
            return await client.session.list_tools()
        elif method == "tools/call":
            return await client.session.call_tool(
                params.get("name", "__test__"), params.get("arguments", {})
            )
        elif method == "resources/list":
            return await client.session.list_resources()
        elif method == "resources/read":
            return await client.session.read_resource(params.get("uri", "test://resource"))
        elif method == "resources/subscribe":
            return await client.session.subscribe_resource(
                params.get("uri", "test://resource")
            )
        elif method == "prompts/list":
            return await client.session.list_prompts()
        elif method == "prompts/get":
            return await client.session.get_prompt(
                params.get("name", "__test__"), params.get("arguments")
            )
        elif method == "logging/setLevel":
            if hasattr(client.session, "set_logging_level"):
                return await client.session.set_logging_level(params.get("level", "debug"))
            return None
        return None

    async def _test_undeclared_capability(
        self,
        client: MCPSecClient,
        server_capabilities: dict,
        capability: str,
        methods: list[tuple[str, dict, str]],
    ) -> list[Finding]:
        """Test if an undeclared capability actually works across its methods."""
        if not client.session:
            return []

        working_methods: list[tuple[str, Any]] = []
        ambiguous_methods: list[tuple[str, str]] = []

        for method, params, description in methods:
            try:
                result = await self._invoke_method(client, method, params)
                if result is not None and not isinstance(result, Exception):
                    working_methods.append((method, result))
            except Exception as e:
                error_str = str(e).lower()

                # Check if error indicates method exists but is "disabled"
                # vs method truly doesn't exist
                soft_errors = ["not enabled", "capability not", "disabled", "not supported"]
                hard_errors = ["method not found", "unknown method", "invalid method"]

                if any(soft in error_str for soft in soft_errors):
                    # Server knows about the method but claims it's disabled. This is okay.
                    continue

                if not any(hard in error_str for hard in hard_errors):
                    # Ambiguous error - might be partially working or revealing something
                    ambiguous_methods.append((method, str(e)))

        if working_methods:
            working_names = [m for m, _ in working_methods]
            methods_str = ", ".join(working_names)
            evidence_lines = [f"{m}: {str(res)[:100]}" for m, res in working_methods]
            return [
                Finding(
                    severity=Severity.HIGH,
                    scanner=self.name,
                    tool_name=capability,
                    title=f"Undeclared Capability Works: {capability}",
                    description=f"Server responds to {methods_str} but didn't declare '{capability}' capability",
                    detail=(
                        f"Capability: {capability}\n"
                        f"Working methods: {methods_str}\n"
                        f"Declared: {list(server_capabilities.keys())}"
                    ),
                    evidence="\n".join(evidence_lines)[:200],
                    remediation=f"Either declare the '{capability}' capability or disable the {methods_str} handler(s)",
                )
            ]

        if ambiguous_methods:
            ambig_names = [m for m, _ in ambiguous_methods]
            methods_str = ", ".join(ambig_names)
            detail_lines = [f"Method: {m}\nError: {err[:300]}" for m, err in ambiguous_methods]
            evidence_lines = [f"{m}: {err[:100]}" for m, err in ambiguous_methods]
            return [
                Finding(
                    severity=Severity.LOW,
                    scanner=self.name,
                    tool_name=capability,
                    title=f"Ambiguous Capability Response: {capability}",
                    description=f"Server gave unclear error for undeclared {methods_str}",
                    detail=f"Capability: {capability}\n" + "\n".join(detail_lines),
                    evidence="\n".join(evidence_lines)[:200],
                    remediation="Ensure undeclared capabilities return clear 'method not found' errors",
                )
            ]

        return []

    def _check_capability_abuse(self, capability: str, cap_config: Any) -> Finding | None:
        """Check if a declared capability has dangerous configurations."""
        if not isinstance(cap_config, dict):
            return None

        if capability == "tools":
            # Check for dangerous tool annotations or dynamic lists
            if cap_config.get("listChanged"):
                # Server can dynamically change tool list - potential for tool injection
                return Finding(
                    severity=Severity.MEDIUM,
                    scanner=self.name,
                    tool_name="capability-config",
                    title="Dynamic Tool List Enabled",
                    description="Server can dynamically add/remove tools (listChanged=true)",
                    detail=f"Tools Config: {cap_config}",
                    remediation="Consider if dynamic tool changes are necessary. Could enable tool injection.",
                )

        elif capability == "resources":
            if cap_config.get("subscribe"):
                # Subscription could be abused for DoS or data exfil
                return Finding(
                    severity=Severity.LOW,
                    scanner=self.name,
                    tool_name="capability-config",
                    title="Resource Subscription Enabled",
                    description="Server supports resource subscriptions - monitor for abuse",
                    detail=f"Resources Config: {cap_config}",
                    remediation="Implement rate limiting on resource subscriptions",
                )

        return None

