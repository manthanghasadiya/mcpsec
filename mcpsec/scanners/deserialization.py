"""
Deserialization Scanner.

Scans for insecure deserialization vulnerabilities including:
 - Python Pickle/Marshal
 - YAML (without SafeLoader)
 - XML External Entity (XXE) Injection
"""

from __future__ import annotations

import base64
import logging
import re
import time
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile, Severity
from mcpsec.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

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
        base64.b64encode(
            b"c__builtin__\n__import__\np0\n(Vthis_module_does_not_exist_mcpsec\np1\ntp2\nRp3\n."
        ).decode("utf-8"),
        base64.b64encode(b"c__main__\nmcpsec_pickle_test\np0\n(V\np1\ntp2\nRp3\n.").decode("utf-8"),
    ],
    "xml": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><foo>&xxe;</foo>',
    ],
}

# Only genuine side-effect evidence: actual leaked file content or module import errors.
# Parse errors (ConstructorError, UnpicklingError, ParseError, truncated data) are NOT effects.
SUCCESS_INDICATORS = {
    "pickle": [
        r"ModuleNotFoundError.*this_module_does_not_exist_mcpsec",
        r"ImportError.*this_module_does_not_exist_mcpsec",
        r"AttributeError.*mcpsec_pickle_test",
    ],
    "xml": [
        r"root:x:0:0:",
        r"\[extensions\]",
        r"\[boot loader\]",
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
            from mcpsec.scanners.param_selection import candidate_injectable_params

            target_params = candidate_injectable_params(
                tool, max_params=getattr(self, "max_params_per_tool", 25)
            )
            if not target_params:
                continue

            # Extract properties from raw schema to detect format param if present
            schema = tool.raw_schema
            if "inputSchema" in schema:
                schema = schema["inputSchema"]
            props = schema.get("properties", {}) if isinstance(schema, dict) else {}

            format_param = None
            for p_name in props:
                if p_name.lower() == "format":
                    format_param = p_name
                    break

            for param_name in target_params:
                # Measure baseline latency for time-based oracle confirmation
                baseline_times = []
                for _ in range(3):
                    t0 = time.monotonic()
                    try:
                        dummy_args = self._get_dummy_args(tool, param_name, "test")
                        await client.call_tool(tool.name, dummy_args)
                    except Exception as e:
                        logger.debug(f"Exception measuring baseline: {e}")
                    baseline_times.append(time.monotonic() - t0)

                from mcpsec.scanners.response_classifier import measure_baseline_latency

                baseline_ms = measure_baseline_latency(baseline_times) * 1000.0

                async def call_fn(t_name: str, args: dict[str, Any]) -> tuple[str, float]:
                    start = time.monotonic()
                    try:
                        res = await client.call_tool(t_name, args)
                        elapsed = time.monotonic() - start
                        text = _extract_response(res)
                        return text, elapsed
                    except Exception as e:
                        elapsed = time.monotonic() - start
                        return f"[ERROR: {str(e)}]", elapsed

                base_args = self._get_dummy_args(tool, param_name, "test")
                if format_param and format_param != param_name:
                    base_args[format_param] = "yaml"

                from mcpsec.scanners.oracles import confirm_deserialization

                collector = getattr(self, "collector", None)
                oracle_res = await confirm_deserialization(
                    call_fn=call_fn,
                    tool_name=tool.name,
                    param_name=param_name,
                    base_args=base_args,
                    collector=collector,
                    baseline_latency_ms=baseline_ms,
                )

                if oracle_res.confirmed:
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            scanner=self.name,
                            tool_name=tool.name,
                            parameter=param_name,
                            title=f"Insecure Deserialization in '{param_name}' [CONFIRMED]",
                            description=(
                                f"Tool '{tool.name}' is vulnerable to insecure deserialization "
                                f"via the '{param_name}' parameter."
                            ),
                            detail=f"Payload: {oracle_res.payload}\nEvidence: {oracle_res.evidence}",
                            evidence=oracle_res.evidence,
                            remediation=(
                                "Avoid deserializing untrusted data. "
                                "If using Python pickle, switch to JSON. "
                                "If using YAML, use yaml.safe_load() instead of yaml.load(). "
                                "If parsing XML, disable entity expansion/fetching in the parser."
                            ),
                            cwe="CWE-502",
                        )
                    )
                    continue

                # Secondary checks: XML entity file leaks or pickle module imports (reflection-guarded)
                for vuln_type in ["xml", "pickle"]:
                    payloads = PAYLOADS.get(vuln_type, [])
                    found_sec = False
                    for payload in payloads:
                        if found_sec:
                            break
                        try:
                            call_args = self._get_dummy_args(tool, param_name, payload)
                            if format_param and format_param != param_name:
                                call_args[format_param] = vuln_type

                            result = await client.call_tool(tool.name, call_args)
                            response_text = _extract_response(result)

                            # Reflection guard: ignore if response merely echoes payload
                            payload_str = str(payload)
                            if not response_text or response_text.strip() == payload_str.strip():
                                continue
                            clean_response = response_text.replace(payload_str, "")
                            if not clean_response.strip():
                                continue

                            evidence = ""
                            for pattern in SUCCESS_INDICATORS.get(vuln_type, []):
                                m = re.search(pattern, clean_response, re.IGNORECASE)
                                if m:
                                    if payload_str and re.search(pattern, payload_str, re.IGNORECASE):
                                        continue
                                    evidence = f"{vuln_type.upper()} confirmed effect: {m.group()}"
                                    break

                            if evidence:
                                findings.append(
                                    Finding(
                                        severity=Severity.CRITICAL,
                                        scanner=self.name,
                                        tool_name=tool.name,
                                        parameter=param_name,
                                        title=f"Insecure {vuln_type.upper()} Deserialization [CONFIRMED]",
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
                                found_sec = True
                        except Exception:
                            pass

        return findings


