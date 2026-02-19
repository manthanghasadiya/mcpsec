"""
Command Injection Scanner — detects arbitrary command execution vulnerabilities in MCP tools.
"""

from __future__ import annotations

import logging
import getpass
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, Severity, ServerProfile, ToolInfo
from mcpsec.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Parameters that typically represent shell commands or targets
COMMAND_PARAM_KEYWORDS = [
    "command", "target", "host", "cmd", "query", "input", "args", "arguments",
    "script", "exec", "run", "payload"
]

# Injection payloads for different shell environments
INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "$(id)",
    "`id`",
    "& id",
    "; whoami",
    "| whoami",
    "& whoami",
    "; echo MCPSEC_INJECTED",
    "| echo MCPSEC_INJECTED",
    "& echo MCPSEC_INJECTED",
]

# Indicators of successful command execution
SUCCESS_INDICATORS = [
    "uid=",                  # Linux id output
    "gid=",                  # Linux id output
    getpass.getuser(),       # Current username (from whoami)
    "MCPSEC_INJECTED",       # Evidence from echo
]

class CommandInjectionScanner(BaseScanner):
    """Scans for command injection vulnerabilities by sending shell-escape payloads."""

    name = "command-injection"
    description = "Detect command injection vulnerabilities in shell-related tool parameters"

    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        for tool in profile.tools:
            # Find parameters that look like they might be passed to a shell
            cmd_params = [
                param_name for param_name in tool.parameters 
                if any(keyword in param_name.lower() for keyword in COMMAND_PARAM_KEYWORDS)
            ]

            if not cmd_params:
                continue

            for param_name in cmd_params:
                for payload in INJECTION_PAYLOADS:
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
                                evidence = f"Matched indicator: '{indicator}' in response"
                                break
                        
                        if evidence:
                            findings.append(Finding(
                                severity=Severity.CRITICAL,
                                scanner=self.name,
                                tool_name=tool.name,
                                title=f"Command Injection detected in parameter '{param_name}'",
                                description=(
                                    f"Tool '{tool.name}' appears vulnerable to command injection "
                                    f"via the '{param_name}' parameter. Sending a shell injection payload "
                                    f"resulted in command execution output."
                                ),
                                detail=f"Payload sent: {payload}\nResponse snippet: {response_text[:200]}",
                                evidence=evidence,
                                remediation=(
                                    "Avoid passing user input directly to shell commands. "
                                    "Use APIs that support argument arrays instead of string interpolation "
                                    "(e.g., subprocess.run(['ls', path]) instead of shell=False). "
                                    "Strictly validate and sanitize all input against an allowlist."
                                ),
                                cwe="CWE-78",
                            ))
                            break # Found a vulnerability for this parameter
                            
                    except Exception as e:
                        logger.error(f"Error calling tool {tool.name} with payload {payload}: {e}")

        return findings
