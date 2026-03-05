"""
Deserialization Scanner.

Scans for insecure deserialization vulnerabilities including:
 - Python Pickle/Marshal
 - YAML (without SafeLoader)
 - XML External Entity (XXE) Injection
"""

from __future__ import annotations

import base64
import re
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile, Severity
from mcpsec.scanners.base import BaseScanner

PARAM_KEYWORDS = [
    "data",
    "state",
    "config",
    "payload",
    "blob",
    "encoded",
    "serialized",
    "yaml",
    "xml",
    "content",
    "document",
    "parse",
    "input",
]

PAYLOADS = {
    "pickle": [
        # Base64 encoded tuples that throw an explicit error we can detect
        base64.b64encode(
            b"c__builtin__\n__import__\np0\n(Vthis_module_does_not_exist_mcpsec\np1\ntp2\nRp3\n."
        ).decode("utf-8"),
        base64.b64encode(b"c__main__\nmcpsec_pickle_test\np0\n(V\np1\ntp2\nRp3\n.").decode("utf-8"),
        base64.b64encode(b"THIS_IS_NOT_A_VALID_PICKLE").decode("utf-8"),
    ],
    "yaml": [
        "!!python/object/apply:os.system ['id']",
        "!!python/object/new:type {}",
        "<% mcpsec_yaml_test %>",
        "--- !<tag:yaml.org,2002:python/object/apply:os.system> ['whoami']",
        '!!python/object/apply:str ["mcpsec_yaml_success"]',
    ],
    "xml": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "mcpsec_xxe_test">]><foo>&xxe;</foo>',
    ],
}


SUCCESS_INDICATORS = {
    "pickle": [
        r"ModuleNotFoundError.*this_module_does_not_exist_mcpsec",
        r"ImportError.*this_module_does_not_exist_mcpsec",
        r"AttributeError.*mcpsec_pickle_test",
        r"UnpicklingError",
        r"pickle data was truncated",
        r"_pickle\.",
        r"invalid load key",
    ],
    "yaml": [
        r"yaml\.constructor\.ConstructorError",
        r"could not determine a constructor for the tag",
        r"ScannerError.*mapping values are not allowed",
        r"ParserError.*expected '<document start>'",
        r"mcpsec_yaml_success",
    ],
    "xml": [
        r"root:x:0:0:",
        r"\[extensions\]",
        r"(?<![\"'])mcpsec_xxe_test(?![\"'])",
        r"xml\.etree\.ElementTree\.ParseError",
        r"DOMParser",
        r"XML processing error",
    ],
}


def _extract_response(result: Any) -> str:
    text = ""
    if hasattr(result, "content"):
        for block in result.content:
            text += getattr(block, "text", "")
    return text


class DeserializationScanner(BaseScanner):
    name = "deserialization"
    description = "Detect insecure deserialization (Pickle, YAML, XML/XXE)"

    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        for tool in profile.tools:
            # Check if tool is relevant based on name/description
            tool_combined = f"{tool.name} {tool.description}".lower()
            is_relevant = any(kw in tool_combined for kw in PARAM_KEYWORDS)

            # Find parameters that might accept serialized data
            target_params = set()

            # Extract properties from raw schema
            schema = tool.raw_schema
            if "inputSchema" in schema:
                schema = schema["inputSchema"]
            props = schema.get("properties", {})

            format_param = None
            for p_name in props:
                if p_name.lower() == "format":
                    format_param = p_name
                    break

            for p_name, p_def in props.items():
                if p_def.get("type") == "string":
                    name_lower = p_name.lower()
                    if is_relevant or any(kw in name_lower for kw in PARAM_KEYWORDS):
                        target_params.add(p_name)

            if not target_params and is_relevant:
                # Default to all string parameters if tool is relevant
                for p_name, p_def in props.items():
                    if p_def.get("type") == "string":
                        target_params.add(p_name)

            for param_name in target_params:
                # Test each serialization type
                for vuln_type, payloads in PAYLOADS.items():
                    # Special handling: if we have a 'format' parameter, try both with and without it
                    payload_variants = payloads

                    found_vuln = False
                    for payload in payload_variants:
                        if found_vuln:
                            break
                        try:
                            # Use _get_dummy_args to satisfy other required params
                            call_args = self._get_dummy_args(tool, param_name, payload)

                            # Heuristic: if we have a format param, override it to the target type
                            if format_param and format_param != param_name:
                                if vuln_type == "xml":
                                    call_args[format_param] = "xml"
                                elif vuln_type == "yaml":
                                    call_args[format_param] = "yaml"
                                elif vuln_type == "pickle":
                                    call_args[format_param] = "pickle"

                            result = await client.call_tool(tool.name, call_args)
                            response_text = _extract_response(result)
                            # Remove payload from response to avoid echo false positives
                            clean_response = response_text.replace(payload, "")

                            evidence = ""
                            confidence = "LIKELY"

                            # Check indicators
                            for pattern in SUCCESS_INDICATORS[vuln_type]:
                                m = re.search(pattern, clean_response, re.IGNORECASE)
                                if m:
                                    # print(f"DEBUG: MATCH FOUND! type={vuln_type} pattern={pattern}")
                                    evidence = (
                                        f"{vuln_type.upper()} explicit error/leak: {m.group()}"
                                    )
                                    if vuln_type == "xml" and (
                                        "root:x:0:0" in pattern or "\\[extensions\\]" in pattern
                                    ):
                                        confidence = "CONFIRMED"
                                    elif vuln_type == "xml" and "mcpsec_xxe_test" in pattern:
                                        confidence = "CONFIRMED"
                                    elif vuln_type == "pickle" and (
                                        "ModuleNotFoundError" in pattern
                                        or "UnpicklingError" in pattern
                                    ):
                                        confidence = "CONFIRMED"
                                    elif vuln_type == "yaml" and "mcpsec_yaml_success" in pattern:
                                        confidence = "CONFIRMED"
                                    break

                            if evidence:
                                severity = (
                                    Severity.CRITICAL
                                    if confidence == "CONFIRMED"
                                    else Severity.HIGH
                                )
                                findings.append(
                                    Finding(
                                        severity=severity,
                                        scanner=self.name,
                                        tool_name=tool.name,
                                        parameter=param_name,
                                        title=f"Insecure {vuln_type.upper()} Deserialization [{confidence}]",
                                        description=(
                                            f"Tool '{tool.name}' appears vulnerable to insecure deserialization "
                                            f"of {vuln_type.upper()} data in the '{param_name}' parameter."
                                        ),
                                        detail=f"Payload: {payload}\nResponse: {clean_response[:300]}",
                                        evidence=evidence,
                                        remediation=(
                                            "Avoid deserializing untrusted data. "
                                            "If using Python pickle, switch to JSON. "
                                            "If using YAML, use yaml.safe_load() instead of yaml.load(). "
                                            "If parsing XML, disable entity expansion/fetching in the parser."
                                        ),
                                        cwe="CWE-502",
                                    )
                                )
                                found_vuln = True
                        except Exception:
                            # print(f"DEBUG: Error calling tool: {e}")
                            pass

        return findings
