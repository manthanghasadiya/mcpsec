"""
SSRF Scanner — detects Server-Side Request Forgery vulnerabilities in MCP tools.
"""

from __future__ import annotations

import logging
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, Severity, ServerProfile, ToolInfo
from mcpsec.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Parameters that typically represent URLs or remote targets
URL_PARAM_KEYWORDS = [
    "url", "uri", "endpoint", "target", "webhook", "callback", "link", 
    "src", "source", "host", "hostname", "address"
]

# SSRF payloads targeting internal services and metadata
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",        # AWS/OpenStack Metadata
    "http://169.254.169.254/computeMetadata/v1/",     # Google Cloud Metadata
    "http://127.0.0.1:22/",                            # Local SSH
    "http://localhost:22/",                            # Local SSH
    "http://127.0.0.1:6379/",                          # Local Redis
    "http://localhost:80/",                            # Local HTTP
]

# Indicators of successful SSRF or internal service access
SUCCESS_INDICATORS = [
    "ami-id", "instance-id", "iam/security-credentials", # AWS indicators
    "Metadata-Flavor: Google",                            # GCP indicator
    "SSH-2.0-",                                           # SSH banner
    "redis_version",                                      # Redis indicator
    "PONG",                                               # Redis indicator
    "root:x:",                                            # file:// etc/passwd if supported
]

class SSRFScanner(BaseScanner):
    """Scans for SSRF vulnerabilities by sending payloads targeting internal infrastructure."""

    name = "ssrf"
    description = "Detect Server-Side Request Forgery in URL-related tool parameters"

    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        for tool in profile.tools:
            # Find parameters that look like URLs
            url_params = [
                param_name for param_name in tool.parameters 
                if any(keyword in param_name.lower() for keyword in URL_PARAM_KEYWORDS)
            ]

            if not url_params:
                continue

            for param_name in url_params:
                for payload in SSRF_PAYLOADS:
                    try:
                        result = await client.call_tool(tool.name, {param_name: payload})
                        
                        # Extract text response
                        response_text = ""
                        if hasattr(result, 'content'):
                            for block in result.content:
                                if hasattr(block, 'text'):
                                    response_text += block.text
                        
                        is_error = getattr(result, 'isError', False)

                        # Check if any success indicator is in the response
                        evidence = ""
                        for indicator in SUCCESS_INDICATORS:
                            if indicator.lower() in response_text.lower():
                                evidence = f"Matched internal service indicator: '{indicator}'"
                                break
                        
                        if evidence:
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                scanner=self.name,
                                tool_name=tool.name,
                                title=f"SSRF detected in parameter '{param_name}'",
                                description=(
                                    f"Tool '{tool.name}' appears vulnerable to Server-Side Request Forgery (SSRF) "
                                    f"via the '{param_name}' parameter. Sending a payload targeting internal "
                                    f"services or metadata endpoints returned sensitive indicators."
                                ),
                                detail=f"Payload sent: {payload}\nResponse snippet: {response_text[:200]}",
                                evidence=evidence,
                                remediation=(
                                    "Implement an allowlist of permitted domains and IP addresses. "
                                    "Disable support for non-HTTP protocols (e.g., file://, gopher://). "
                                    "Use a dedicated egress proxy to restrict outbound access. "
                                    "Avoid passing raw user input to HTTP clients."
                                ),
                                cwe="CWE-918",
                            ))
                            break # Found a vulnerability for this parameter
                            
                    except Exception as e:
                        logger.error(f"Error calling tool {tool.name} with payload {payload}: {e}")

        return findings
