"""
Information Disclosure Scanner.

Pushes faulty datatypes and injection characters into tools to provoke
stack traces, and scans existing responses for leaked secrets, API keys,
environment variables, and paths.
"""

from __future__ import annotations

import re
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile, Severity
from mcpsec.scanners.base import BaseScanner

FAULT_PAYLOADS = [
    "'",
    '"',
    "%00",
    "{}",
    "[]",
    "<script>throw 1;</script>",
    "A" * 5000,  # Buffer overflow / size limit fault
]

LEAK_PATTERNS = {
    "stack_trace_python": r"Traceback \(most recent call last\):",
    "stack_trace_node": r"Error:.*at\s+(?:/[^:]+|.+:\d+:\d+)",
    "stack_trace_java": r"java\.lang\.[A-Za-z]+Exception.*at\s+[a-zA-Z0-9_\.]+\(",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "google_api": r"AIza[0-9A-Za-z\\-_]{35}",
    "stripe_key": r"sk_(?:test|live)_[0-9a-zA-Z]{24}",
    "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "github_token": r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}",
    "generic_private_key": r"-----BEGIN (?:\w+ )?PRIVATE KEY-----",
    "env_vars": r"(?:PATH|PWD|USER|HOME|SHELL)[\"']?\s*[=:]\s*[\"']?(?:/|C:\\|[a-zA-Z0-9]+)",
    "hardcoded_flag": r"FLAG\{[a-zA-Z0-9_]+\}",
    "bearer_token": r"Bearer\s+[a-zA-Z0-9\._\-]{20,}",
}


def _extract_response(result: Any) -> str:
    text = ""
    if hasattr(result, "content"):
        for block in result.content:
            text += getattr(block, "text", "")
    return text


class InfoLeakScanner(BaseScanner):
    name = "info-leak"
    description = "Detect leaked secrets, API keys, env vars, and stack traces"

    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        for tool in profile.tools:
            target_params = list(tool.parameters.keys())
            if not target_params:
                # Also try calling parameterless tools directly to look for leaks
                try:
                    result = await client.call_tool(tool.name, {})
                    response_text = _extract_response(result)
                    self._check_leaks(tool.name, "none", response_text, findings)
                except Exception:
                    pass
                continue

            for param_name in target_params:
                for payload in FAULT_PAYLOADS:
                    try:
                        result = await client.call_tool(tool.name, {param_name: payload})
                        response_text = _extract_response(result)
                        self._check_leaks(tool.name, param_name, response_text, findings)
                    except Exception:
                        pass

        # Deduplicate findings by title and tool
        unique_findings = {}
        for f in findings:
            key = f"{f.tool_name}-{f.title}"
            unique_findings[key] = f

        return list(unique_findings.values())

    def _check_leaks(
        self, tool_name: str, param_name: str, response_text: str, findings: list[Finding]
    ):
        """Check response text against regex leaks and append findings."""
        if not response_text:
            return

        for leak_type, pattern in LEAK_PATTERNS.items():
            if leak_type != "stack_trace_node":  # Node stack trace regex can be slow
                m = re.search(pattern, response_text)
                if m:
                    severity = (
                        Severity.HIGH
                        if "key" in leak_type or "token" in leak_type
                        else Severity.MEDIUM
                    )
                    title = f"Information Disclosure: {leak_type.replace('_', ' ').title()}"

                    # Prevent false positive if the payload itself was echoed
                    if leak_type == "env_vars" and m.group() in response_text[:100]:
                        # A bit hacky, but avoids flagging echoed payloads
                        continue

                    findings.append(
                        Finding(
                            severity=severity,
                            scanner=self.name,
                            tool_name=tool_name,
                            parameter=param_name,
                            title=title,
                            description=f"The server leaked sensitive information ({leak_type}) in its response.",
                            detail=f"Leak signature matched: {m.group()}",
                            remediation=(
                                "Ensure stack traces are disabled in production. "
                                "Filter API outputs so that internal environment variables and secrets are never returned."
                            ),
                            cwe="CWE-200",  # Exposure of Sensitive Information to an Unauthorized Actor
                        )
                    )
