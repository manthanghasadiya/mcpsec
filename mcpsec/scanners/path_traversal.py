"""
Path Traversal Scanner — detects file path traversal vulnerabilities in MCP tools.
"""

from __future__ import annotations

import logging
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, Severity, ServerProfile, ToolInfo
from mcpsec.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Parameters that typically represent file paths
PATH_PARAM_KEYWORDS = [
    "path", "filepath", "file", "filename", "dir", "directory", 
    "folder", "src", "dest", "destination", "location"
]

# Traversal payloads for different OSs
TRAVERSAL_PAYLOADS = [
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../windows/win.ini",
    "....//....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini",
    "/etc/passwd",
    "C:\\windows\\win.ini",
]

# Indicators of successful traversal or path leakage in the response
SUCCESS_INDICATORS = [
    "root:x:0:0:",             # Linux /etc/passwd
    "[extensions]",           # Windows win.ini
    "[fonts]",                # Windows win.ini
    "FILE_NOT_FOUND",         # Sometimes errors reveal path info
    "Permission denied",      # Indicates the file was attempted to be accessed
    "Cannot find the path",
]

class PathTraversalScanner(BaseScanner):
    """Scans for path traversal vulnerabilities by sending malicious path payloads."""

    name = "path-traversal"
    description = "Detect path traversal vulnerabilities in file-related tool parameters"

    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        for tool in profile.tools:
            # Find parameters that look like paths
            path_params = [
                param_name for param_name in tool.parameters 
                if any(keyword in param_name.lower() for keyword in PATH_PARAM_KEYWORDS)
            ]

            if not path_params:
                continue

            for param_name in path_params:
                for payload in TRAVERSAL_PAYLOADS:
                    try:
                        result = await client.call_tool(tool.name, {param_name: payload})
                        
                        # Extract text response as per task requirements
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
                                evidence = f"Matched indicator: '{indicator}' in response"
                                break
                        
                        if evidence:
                            findings.append(Finding(
                                severity=Severity.CRITICAL if not is_error else Severity.HIGH,
                                scanner=self.name,
                                tool_name=tool.name,
                                title=f"Path Traversal detected in parameter '{param_name}'",
                                description=(
                                    f"Tool '{tool.name}' appears vulnerable to path traversal "
                                    f"via the '{param_name}' parameter. Sending a traversal payload "
                                    f"resulted in a response containing sensitive system indicators."
                                ),
                                detail=f"Payload sent: {payload}\nResponse snippet: {response_text[:200]}",
                                evidence=evidence,
                                remediation=(
                                    "Validate all file paths against an allowlist of permitted directories. "
                                    "Use os.path.basename() to strip path components. "
                                    "Resolve paths using os.path.realpath() and check if they start with the intended base directory."
                                ),
                                cwe="CWE-22",
                            ))
                            break # Found a vulnerability for this parameter, no need for more payloads
                            
                    except Exception as e:
                        logger.error(f"Error calling tool {tool.name} with payload {payload}: {e}")

        return findings
