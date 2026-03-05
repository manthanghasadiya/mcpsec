"""
Template Injection Scanner — detects Server-Side Template Injection (SSTI) and format string vulnerabilities.
Targets Python format strings, Jinja2, Mako, etc.
"""

import logging
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile, Severity
from mcpsec.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

RELEVANT_KEYWORDS = [
    "template",
    "format",
    "report",
    "render",
    "generate",
    "string",
    "text",
    "content",
    "summary",
    "style",
    "params",
    "metadata",
]

# Combination of format string and template engine payloads
PAYLOADS = [
    "{7*7}",
    "{{7*7}}",
    "#{7*7}",
    "${7*7}",
    "<%= 7*7 %>",
    "{self}",
    "{__class__}",
    "{{self.__class__}}",
    "{{config}}",
    "{{request}}",
    "{0.__class__}",
    "{{[].__class__.__base__.__subclasses__()}}",
]


class TemplateInjectionScanner(BaseScanner):
    name = "template-injection"
    description = "Detect Server-Side Template Injection (SSTI) and format string vulnerabilities"

    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        for tool in profile.tools:
            # Scoping: tools that generate or format text
            combined = f"{tool.name} {tool.description}".lower()
            is_relevant = any(kw in combined for kw in RELEVANT_KEYWORDS)

            if not is_relevant:
                continue

            params = []
            schema = tool.raw_schema
            if "inputSchema" in schema:
                schema = schema["inputSchema"]

            props = schema.get("properties", {})
            for p_name, p_def in props.items():
                if p_def.get("type") == "string":
                    params.append(p_name)
                elif p_def.get("type") == "object":
                    # For format strings, often nested in an object
                    params.append(p_name)

            if not params:
                params = list(tool.parameters.keys())

            for param in params:
                found_vuln = False
                for payload in PAYLOADS:
                    if found_vuln:
                        break
                    try:
                        # Use _get_dummy_args to satisfy other required params
                        call_args = self._get_dummy_args(tool, param, payload)

                        # maintain specific logic for object-type params if still needed
                        if tool.parameters.get(param) == "object":
                            # If it's the target param and it was already set by dummy_args,
                            # we override it with the more specific SSTI payload structure
                            call_args[param] = {
                                "value": payload,
                                "name": payload,
                                "text": payload,
                                "date": payload,
                            }

                        result = await client.call_tool(tool.name, call_args)
                        text = self._extract_text(result)

                        evidence = ""
                        confidence = ""

                        # 1. Math evaluation (49)
                        if "49" in text and "7*7" not in text:
                            evidence = f"Template payload '{payload}' evaluated to '49'"
                            confidence = "CONFIRMED"

                        # 2. Python class references
                        elif "<class '" in text or "__main__" in text:
                            evidence = (
                                f"Template payload '{payload}' leaked internal class information"
                            )
                            confidence = "CONFIRMED"

                        # 3. Object-based leaks
                        elif "{'accessKeyId'" in text or "'DATABASE_URL'" in text:
                            evidence = f"Template payload '{payload}' leaked configuration data"
                            confidence = "CONFIRMED"

                        if evidence:
                            findings.append(
                                Finding(
                                    severity=Severity.HIGH,
                                    scanner=self.name,
                                    tool_name=tool.name,
                                    parameter=param,
                                    title=f"Template Injection in '{param}' [{confidence}]",
                                    description=f"Tool '{tool.name}' is vulnerable to template injection via '{param}'.",
                                    detail=f"Payload: {payload}\nResponse: {text[:300]}",
                                    evidence=evidence,
                                    confidence=confidence.lower(),
                                    remediation="Avoid passing untrusted input directly into template engines or format strings. Use parameterized templates.",
                                    cwe="CWE-1336",
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
