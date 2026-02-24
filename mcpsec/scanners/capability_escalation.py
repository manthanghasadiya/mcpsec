"""
Capability Escalation Scanner.

Tests whether MCP servers properly enforce their declared capabilities.
A server that declares limited capabilities but responds to undeclared
methods has a security issue - clients might trust the capability declaration.
"""

from __future__ import annotations

import logging
from typing import Any

from mcpsec.models import Finding, Severity, ServerProfile
from mcpsec.scanners.base import BaseScanner
from mcpsec.client.mcp_client import MCPSecClient

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
            ("sampling/createMessage", {
                "messages": [{"role": "user", "content": {"type": "text", "text": "test"}}],
                "maxTokens": 10
            }, "Create sampling message"),
        ],
    }
    
    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
        """Scan for capability enforcement issues."""
        findings = []
        
        if not client or not client.session:
            return [Finding(
                severity=Severity.INFO,
                scanner=self.name,
                title="Capability scan requires live connection",
                description="This scanner needs a live MCP connection to test capability enforcement",
                detail="No live client session available",
                remediation="Run with live server connection"
            )]
        
        # Get declared capabilities from profile
        server_capabilities = profile.capabilities
        declared = set()
        if server_capabilities.get("tools"):
            declared.add("tools")
        if server_capabilities.get("resources"):
            declared.add("resources")
        if server_capabilities.get("prompts"):
            declared.add("prompts")
        if server_capabilities.get("logging"):
            declared.add("logging")
        if server_capabilities.get("experimental", {}).get("sampling"):
            declared.add("sampling")
        
        # Test undeclared capabilities
        for capability, methods in self.CAPABILITY_METHODS.items():
            if capability not in declared:
                # Server didn't declare this capability - test if it works anyway
                for method, params, description in methods:
                    finding = await self._test_undeclared_capability(
                        client, server_capabilities, capability, method, params, description
                    )
                    if finding:
                        findings.append(finding)
        
        # Also check if declared capabilities can be abused
        for capability in declared:
            abuse_finding = self._check_capability_abuse(capability, server_capabilities.get(capability, {}))
            if abuse_finding:
                findings.append(abuse_finding)
        
        return findings
    
    async def _test_undeclared_capability(
        self, 
        client: MCPSecClient,
        server_capabilities: dict,
        capability: str, 
        method: str, 
        params: dict,
        description: str
    ) -> Finding | None:
        """Test if an undeclared capability actually works."""
        if not client.session:
            return None

        try:
            # Try to call the method via the low-level session request
            result = await client.session.send_request(method, params)
            
            # If we got a successful response (not None and not an exception), that's a problem
            if result is not None and not isinstance(result, Exception):
                return Finding(
                    severity=Severity.HIGH,
                    scanner=self.name,
                    tool_name=method,
                    title=f"Undeclared Capability Works: {capability}",
                    description=f"Server responds to {method} but didn't declare '{capability}' capability",
                    detail=f"Capability: {capability}\nDeclared: {list(server_capabilities.keys())}",
                    evidence=str(result)[:200],
                    remediation=f"Either declare the '{capability}' capability or disable the {method} handler"
                )
        except Exception as e:
            error_str = str(e).lower()
            
            # Check if error indicates method exists but is "disabled"
            # vs method truly doesn't exist
            soft_errors = ["not enabled", "capability not", "disabled", "not supported"]
            hard_errors = ["method not found", "unknown method", "invalid method"]
            
            if any(soft in error_str for soft in soft_errors):
                # Server knows about the method but claims it's disabled. This is okay.
                return None
            
            if not any(hard in error_str for hard in hard_errors):
                # Ambiguous error - might be partially working or revealing something
                return Finding(
                    severity=Severity.LOW,
                    scanner=self.name,
                    tool_name=method,
                    title=f"Ambiguous Capability Response: {capability}",
                    description=f"Server gave unclear error for undeclared {method}",
                    detail=f"Method: {method}\nError: {error_str[:300]}",
                    evidence=error_str[:200],
                    remediation="Ensure undeclared capabilities return clear 'method not found' errors"
                )
        
        return None
    
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
                    remediation="Consider if dynamic tool changes are necessary. Could enable tool injection."
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
                    remediation="Implement rate limiting on resource subscriptions"
                )
        
        return None
