"""
Template Injection Scanner — detects Server-Side Template Injection (SSTI) and format string vulnerabilities.
Targets Python format strings, Jinja2, Mako, etc. using computed arithmetic canaries.
"""

import json
import logging
import secrets
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

# Non-arithmetic template payloads (object inspection & environment leaks)
PAYLOADS = [
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
            from mcpsec.scanners.param_selection import candidate_injectable_params

            params = candidate_injectable_params(
                tool, max_params=getattr(self, "max_params_per_tool", 25)
            )
            if not params:
                continue

            for param in params:
                found_vuln = False

                # 1. Computed arithmetic canary pass across template wrappers
                canary_templates = [
                    lambda a, b: "{" + f"{a}*{b}" + "}",
                    lambda a, b: "{{" + f"{a}*{b}" + "}}",
                    lambda a, b: "#{" + f"{a}*{b}" + "}",
                    lambda a, b: "${" + f"{a}*{b}" + "}",
                    lambda a, b: "<%= " + f"{a}*{b}" + " %>",
                ]

                for tmpl in canary_templates:
                    if found_vuln:
                        break
                    try:
                        while True:
                            a = secrets.randbelow(90000) + 10000
                            b = secrets.randbelow(90000) + 10000
                            proof = str(a * b)
                            payload = tmpl(a, b)
                            call_args = self._get_dummy_args(tool, param, payload)
                            if tool.parameters.get(param) == "object":
                                call_args[param] = {
                                    "value": payload,
                                    "name": payload,
                                    "text": payload,
                                    "date": payload,
                                }
                            serialized_args = json.dumps(call_args)
                            if proof not in serialized_args:
                                break

                        assert proof not in serialized_args

                        result = await client.call_tool(tool.name, call_args)
                        text = self._extract_text(result)

                        if proof in text and proof not in serialized_args:
                            findings.append(
                                self.create_finding(
                                    severity=Severity.HIGH,
                                    tool_name=tool.name,
                                    parameter=param,
                                    title=f"Template Injection in '{param}'",
                                    description=f"Tool '{tool.name}' is vulnerable to template injection via '{param}'.",
                                    detail=f"Payload: {payload}\nResponse: {text[:300]}",
                                    evidence=f"Template payload '{payload}' evaluated to '{proof}'",
                                    confidence="confirmed",
                                    remediation="Avoid passing untrusted input directly into template engines or format strings. Use parameterized templates.",
                                    cwe="CWE-1336",
                                )
                            )
                            found_vuln = True
                            break
                    except Exception as e:
                        logger.debug(f"Error testing {tool.name}/{param}: {e}")

                # 2. Object & internal leak payloads (with reflection guard)
                if not found_vuln:
                    for payload in PAYLOADS:
                        if found_vuln:
                            break
                        try:
                            call_args = self._get_dummy_args(tool, param, payload)
                            if tool.parameters.get(param) == "object":
                                call_args[param] = {
                                    "value": payload,
                                    "name": payload,
                                    "text": payload,
                                    "date": payload,
                                }
                            serialized_args = json.dumps(call_args)

                            result = await client.call_tool(tool.name, call_args)
                            text = self._extract_text(result)

                            evidence = ""
                            confidence = ""

                            # Python class references (with reflection guard)
                            if "<class '" in text:
                                if "<class '" not in serialized_args:
                                    evidence = f"Template payload '{payload}' leaked internal class information"
                                    confidence = "confirmed"
                            elif "__main__" in text:
                                if "__main__" not in serialized_args:
                                    evidence = f"Template payload '{payload}' leaked module reference"
                                    confidence = "suspected"

                            # Object-based leaks (with reflection guard)
                            elif "{'accessKeyId'" in text or "'DATABASE_URL'" in text:
                                if (
                                    "{'accessKeyId'" not in serialized_args
                                    and "'DATABASE_URL'" not in serialized_args
                                ):
                                    evidence = f"Template payload '{payload}' leaked configuration data"
                                    confidence = "suspected"

                            if evidence:
                                findings.append(
                                    self.create_finding(
                                        severity=Severity.HIGH,
                                        tool_name=tool.name,
                                        parameter=param,
                                        title=f"Template Injection in '{param}'",
                                        description=f"Tool '{tool.name}' is vulnerable to template injection via '{param}'.",
                                        detail=f"Payload: {payload}\nResponse: {text[:300]}",
                                        evidence=evidence,
                                        confidence=confidence,
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
