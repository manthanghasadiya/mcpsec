"""
Code Execution Scanner — detects arbitrary code execution vulnerabilities in MCP tools.
Specifically targets eval(), exec(), and compile() sinks.
"""

import logging
import re
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile, Severity
from mcpsec.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

RELEVANT_KEYWORDS = [
    "eval",
    "expression",
    "code",
    "transform",
    "calculate",
    "formula",
    "logic",
    "script",
    "compute",
    "math",
    "process",
    "data",
]

PAYLOADS = [
    "7*7",
    "__import__('os').system('id')",
    "__import__('os').popen('id').read()",
    "int('49')",
    "[ ().__class__.__base__.__subclasses__()[i] for i in range(len(().__class__.__base__.__subclasses__())) ]",
    "getattr(__import__('os'), 'system')('id')",
    'eval(\'__import__("os").system("id")\')',
    "__import__('subprocess').check_output(['id'])",
]

SUCCESS_INDICATORS = {
    "math": [r"\b49\b"],
    "system": [
        r"uid=\d+",
        r"gid=\d+",
        r"groups=\d+",
        r"NT AUTHORITY",
        r"BUILTIN",
        r"<class '",
        r"__main__",
    ],
}


class CodeExecutionScanner(BaseScanner):
    name = "code-execution"
    description = "Detect arbitrary code execution via eval(), exec(), or logic-based injection"

    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        for tool in profile.tools:
            # Check if tool is relevant for code execution
            combined = f"{tool.name} {tool.description}".lower()
            is_relevant = any(kw in combined for kw in RELEVANT_KEYWORDS)

            if not is_relevant:
                continue

            # Identify candidate parameters
            params = []
            schema = tool.raw_schema
            if "inputSchema" in schema:
                schema = schema["inputSchema"]

            props = schema.get("properties", {})
            for p_name, p_def in props.items():
                if p_def.get("type") == "string":
                    params.append(p_name)

            if not params:
                params = list(tool.parameters.keys())

            for param in params:
                found_vuln = False
                for payload in PAYLOADS:
                    if found_vuln:
                        break
                    try:
                        call_args = self._get_dummy_args(tool, param, payload)
                        result = await client.call_tool(tool.name, call_args)
                        text = self._extract_text(result)

                        # Check for success indicators
                        evidence = ""
                        confidence = ""

                        # Math check (7*7 = 49)
                        if "49" in text and "7*7" not in text:
                            evidence = "Mathematical expression '7*7' evaluated to '49'"
                            confidence = "CONFIRMED"

                        # System command output
                        for pattern in SUCCESS_INDICATORS["system"]:
                            if re.search(pattern, text, re.IGNORECASE):
                                evidence = f"Code execution output detected: {re.search(pattern, text).group()}"
                                confidence = "CONFIRMED"
                                break

                        if evidence:
                            findings.append(
                                Finding(
                                    severity=Severity.CRITICAL,
                                    scanner=self.name,
                                    tool_name=tool.name,
                                    parameter=param,
                                    title=f"Code Execution in '{param}' [{confidence}]",
                                    description=f"Tool '{tool.name}' appears to evaluate the '{param}' parameter as code.",
                                    detail=f"Payload: {payload}\nResponse: {text[:300]}",
                                    evidence=evidence,
                                    confidence=confidence.lower(),
                                    remediation="Never use eval(), exec(), or compile() on user input. Use safe alternatives or strict allowlists.",
                                    cwe="CWE-94",
                                )
                            )
                            found_vuln = True
                    except Exception as e:
                        logger.debug(f"Error testing {tool.name}/{param}: {e}")
        return findings

    def _extract_text(self, result: Any) -> str:
        text = ""
        if hasattr(result, "content"):
            for block in result.content:
                if hasattr(block, "text"):
                    text += block.text
        return text
