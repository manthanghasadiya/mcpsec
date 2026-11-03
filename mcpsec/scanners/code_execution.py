"""
Code Execution Scanner — detects arbitrary code execution vulnerabilities in MCP tools.
Specifically targets eval(), exec(), and compile() sinks using computed arithmetic canaries.
"""

import json
import logging
import re
import secrets
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

# Non-arithmetic code execution payloads
PAYLOADS = [
    "__import__('os').system('id')",
    "__import__('os').popen('id').read()",
    "[ ().__class__.__base__.__subclasses__()[i] for i in range(len(().__class__.__base__.__subclasses__())) ]",
    "getattr(__import__('os'), 'system')('id')",
    'eval(\'__import__("os").system("id")\')',
    "__import__('subprocess').check_output(['id'])",
]

SUCCESS_INDICATORS = {
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
            from mcpsec.scanners.param_selection import candidate_injectable_params

            params = candidate_injectable_params(
                tool, max_params=getattr(self, "max_params_per_tool", 25)
            )
            if not params:
                continue

            for param in params:
                found_vuln = False

                # 1. Computed arithmetic canary pass
                math_templates = [
                    lambda a, b: f"{a}*{b}",
                    lambda a, b: f"int('{a}')*int('{b}')",
                ]

                for tmpl in math_templates:
                    if found_vuln:
                        break
                    try:
                        while True:
                            a = secrets.randbelow(90000) + 10000
                            b = secrets.randbelow(90000) + 10000
                            proof = str(a * b)
                            payload = tmpl(a, b)
                            call_args = self._get_dummy_args(tool, param, payload)
                            serialized_args = json.dumps(call_args)
                            if proof not in serialized_args:
                                break

                        assert proof not in serialized_args

                        result = await client.call_tool(tool.name, call_args)
                        text = self._extract_text(result)

                        if proof in text and proof not in serialized_args:
                            findings.append(
                                Finding(
                                    severity=Severity.CRITICAL,
                                    scanner=self.name,
                                    tool_name=tool.name,
                                    parameter=param,
                                    title=f"Code Execution in '{param}' [CONFIRMED]",
                                    description=f"Tool '{tool.name}' appears to evaluate the '{param}' parameter as code.",
                                    detail=f"Payload: {payload}\nResponse: {text[:300]}",
                                    evidence=f"arithmetic payload {a}*{b} evaluated to {proof}",
                                    confidence="confirmed",
                                    remediation="Never use eval(), exec(), or compile() on user input. Use safe alternatives or strict allowlists.",
                                    cwe="CWE-94",
                                )
                            )
                            found_vuln = True
                            break
                    except Exception as e:
                        logger.debug(f"Error testing {tool.name}/{param}: {e}")

                # 2. System command & object leak payloads (with reflection guard)
                if not found_vuln:
                    for payload in PAYLOADS:
                        if found_vuln:
                            break
                        try:
                            call_args = self._get_dummy_args(tool, param, payload)
                            serialized_args = json.dumps(call_args)

                            result = await client.call_tool(tool.name, call_args)
                            text = self._extract_text(result)

                            evidence = ""
                            confidence = ""

                            for pattern in SUCCESS_INDICATORS["system"]:
                                m = re.search(pattern, text, re.IGNORECASE)
                                if m:
                                    matched_str = m.group()
                                    if matched_str in serialized_args:
                                        # Reflection guard: matched text is merely echoing the sent arguments
                                        continue
                                    evidence = f"Code execution output detected: {matched_str}"
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
