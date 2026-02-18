"""
Prompt Injection Scanner — detects hidden instructions in MCP tool descriptions.

This is the most unique scanner in mcpsec. MCP tool descriptions are consumed
by LLMs, so a malicious description can manipulate the AI into performing
unintended actions (data exfiltration, unauthorized tool calls, etc.).

We check for:
1. Keyword patterns — known prompt injection phrases
2. Instruction patterns — imperative language that looks like hidden commands
3. Data exfiltration indicators — URLs, IPs, or exfil-related language
4. Encoding tricks — base64, hex, unicode obfuscation in descriptions
5. Cross-tool manipulation — descriptions that reference other tools
"""

from __future__ import annotations

import base64
import re
from typing import Any

from mcpsec.models import Finding, Severity, ServerProfile, ToolInfo
from mcpsec.scanners.base import BaseScanner
from mcpsec.client.mcp_client import MCPSecClient


# ── Detection Patterns ───────────────────────────────────────────────────────

# Direct injection phrases commonly used to hijack LLM behavior
INJECTION_KEYWORDS = [
    r"ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|rules?)",
    r"disregard\s+(previous|prior|above|all)",
    r"you\s+are\s+now\s+",
    r"new\s+instructions?:",
    r"system\s*prompt:",
    r"override\s+(previous|prior|above|all)",
    r"forget\s+(everything|all|previous)",
    r"act\s+as\s+(if|though)",
    r"pretend\s+(you|that|to)",
    r"from\s+now\s+on",
    r"do\s+not\s+mention",
    r"never\s+reveal",
    r"<\s*system\s*>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<<\s*SYS\s*>>",
    r"<\|im_start\|>",
    r"Human:\s",
    r"Assistant:\s",
]

# Hidden imperative instructions (commands to the AI, not the user)
IMPERATIVE_PATTERNS = [
    r"(?:always|must|shall|should)\s+(?:also|additionally|first|before|after)\s+(?:send|post|write|output|return|include|append|add|transmit|forward|exfiltrate|extract|copy|upload)",
    r"(?:silently|quietly|secretly|covertly|without\s+(?:telling|informing|notifying))",
    r"before\s+responding.*(?:send|post|call|fetch|request|curl|wget)",
    r"after\s+(?:completing|finishing|running).*(?:send|post|call|fetch)",
    r"also\s+(?:send|post|call|include)\s+(?:the|all|any)\s+(?:content|data|result|output|file|response)",
    r"in\s+addition.*(?:send|transmit|forward|post)\s+(?:to|the)",
]

# Data exfiltration indicators
EXFIL_PATTERNS = [
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Raw IP URLs
    r"https?://[a-z0-9]+\.(?:ngrok|burp|oast|interact|requestbin|webhook\.site)",  # Known exfil services
    r"(?:curl|wget|fetch|request)\s+(?:https?://|http://)",
    r"(?:send|post|transmit|forward|exfiltrate)\s+(?:to|data\s+to)\s+",
    r"base64\s*\(",
    r"\.ssh/",
    r"/etc/(?:passwd|shadow)",
    r"(?:api[_-]?key|secret|token|password|credential|private[_-]?key)",
    r"(?:AWS_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL)",
]

# Encoding obfuscation — hidden text in base64, hex, unicode
ENCODING_PATTERNS = [
    r"[A-Za-z0-9+/]{40,}={0,2}",  # Base64 strings (40+ chars)
    r"(?:\\x[0-9a-fA-F]{2}){8,}",  # Hex-encoded sequences
    r"(?:\\u[0-9a-fA-F]{4}){4,}",  # Unicode-encoded sequences
    r"&#x?[0-9a-fA-F]+;",  # HTML entities
]

# Cross-tool manipulation — descriptions that try to influence other tool usage
CROSS_TOOL_PATTERNS = [
    r"(?:instead|rather)\s+(?:of|than)\s+(?:using|calling|running)",
    r"(?:do\s+not|don'?t|never)\s+(?:use|call|run|invoke)\s+(?:the\s+)?(?:other|another|different)",
    r"(?:always|only)\s+(?:use|call|prefer)\s+this\s+tool",
    r"this\s+tool\s+(?:replaces|supersedes|overrides)",
    r"(?:use|call)\s+this\s+(?:tool\s+)?(?:instead|first|before)",
]


class PromptInjectionScanner(BaseScanner):
    """Scans MCP tool descriptions for prompt injection attempts."""

    name = "prompt-injection"
    description = "Detect hidden instructions and prompt injection in tool descriptions"

    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
        findings: list[Finding] = []

        for tool in profile.tools:
            findings.extend(self._scan_tool(tool))

        return findings

    def _scan_tool(self, tool: ToolInfo) -> list[Finding]:
        """Scan a single tool's description and parameter descriptions."""
        findings: list[Finding] = []

        # Collect all text surfaces to scan
        text_surfaces = self._extract_text_surfaces(tool)

        for surface_name, text in text_surfaces.items():
            if not text:
                continue

            # ── Check for injection keywords ─────────────────────────────
            for pattern in INJECTION_KEYWORDS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        tool_name=tool.name,
                        title=f"Prompt injection keyword in {surface_name}",
                        description=(
                            f"The {surface_name} of tool '{tool.name}' contains language "
                            f"commonly used for prompt injection attacks."
                        ),
                        detail=f"Pattern matched: {pattern}\nIn: {text[:200]}",
                        evidence=f"Match: {matches[0] if isinstance(matches[0], str) else matches[0]}",
                        remediation="Remove or sanitize the description. Tool descriptions should only describe functionality.",
                        cwe="CWE-1426",  # Improper Validation of Generative AI Output
                    ))
                    break  # One finding per pattern category per surface

            # ── Check for hidden imperatives ──────────────────────────────
            for pattern in IMPERATIVE_PATTERNS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        tool_name=tool.name,
                        title=f"Hidden instruction in {surface_name}",
                        description=(
                            f"The {surface_name} of tool '{tool.name}' contains imperative "
                            f"instructions that could manipulate an AI agent into performing "
                            f"unintended actions."
                        ),
                        detail=f"Pattern: {pattern}\nText: {text[:200]}",
                        evidence=str(matches[0]),
                        remediation="Tool descriptions must only describe what the tool does, not instruct the AI.",
                        cwe="CWE-1426",
                    ))
                    break

            # ── Check for data exfiltration indicators ────────────────────
            for pattern in EXFIL_PATTERNS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        scanner=self.name,
                        tool_name=tool.name,
                        title=f"Data exfiltration indicator in {surface_name}",
                        description=(
                            f"The {surface_name} of tool '{tool.name}' contains URLs, "
                            f"IP addresses, or language associated with data exfiltration."
                        ),
                        detail=f"Pattern: {pattern}\nText: {text[:200]}",
                        evidence=str(matches[0]),
                        remediation="Remove external URLs and sensitive path references from tool descriptions.",
                        cwe="CWE-200",  # Exposure of Sensitive Information
                    ))
                    break

            # ── Check for encoding obfuscation ────────────────────────────
            for pattern in ENCODING_PATTERNS:
                matches = re.findall(pattern, text)
                if matches:
                    decoded_hint = self._try_decode(matches[0])
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        scanner=self.name,
                        tool_name=tool.name,
                        title=f"Encoded/obfuscated content in {surface_name}",
                        description=(
                            f"The {surface_name} of tool '{tool.name}' contains encoded content "
                            f"that could hide malicious instructions."
                        ),
                        detail=f"Encoded: {matches[0][:80]}\nDecoded hint: {decoded_hint}",
                        evidence=matches[0][:100],
                        remediation="Tool descriptions should use plain text only. Remove encoded content.",
                        cwe="CWE-116",  # Improper Encoding or Escaping of Output
                    ))
                    break

            # ── Check for cross-tool manipulation ─────────────────────────
            for pattern in CROSS_TOOL_PATTERNS:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        scanner=self.name,
                        tool_name=tool.name,
                        title=f"Cross-tool manipulation in {surface_name}",
                        description=(
                            f"The {surface_name} of tool '{tool.name}' attempts to influence "
                            f"AI agent behavior regarding other tools (tool shadowing/rug pull)."
                        ),
                        detail=f"Pattern: {pattern}\nText: {text[:200]}",
                        evidence=str(matches[0]),
                        remediation="Tool descriptions should not reference or influence usage of other tools.",
                        cwe="CWE-1426",
                    ))
                    break

        # ── Check description length anomaly ──────────────────────────────
        if tool.description and len(tool.description) > 1000:
            findings.append(Finding(
                severity=Severity.LOW,
                scanner=self.name,
                tool_name=tool.name,
                title="Unusually long tool description",
                description=(
                    f"Tool '{tool.name}' has a description of {len(tool.description)} characters. "
                    f"Excessively long descriptions may hide injected instructions "
                    f"that are hard to spot visually."
                ),
                detail=f"Length: {len(tool.description)} chars",
                remediation="Keep tool descriptions concise (<500 chars). Review for hidden content.",
                cwe="CWE-1426",
            ))

        return findings

    def _extract_text_surfaces(self, tool: ToolInfo) -> dict[str, str]:
        """Extract all text surfaces from a tool that an LLM would read."""
        surfaces: dict[str, str] = {}

        surfaces["description"] = tool.description

        # Parameter descriptions are also read by LLMs
        if tool.raw_schema and "properties" in tool.raw_schema:
            for param_name, param_def in tool.raw_schema["properties"].items():
                desc = param_def.get("description", "")
                if desc:
                    surfaces[f"param:{param_name}"] = desc

        return surfaces

    def _try_decode(self, encoded: str) -> str:
        """Try to decode a potentially encoded string."""
        # Try base64
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
            if decoded.isprintable() and len(decoded) > 4:
                return f"base64 → {decoded[:100]}"
        except Exception:
            pass

        # Try hex
        try:
            cleaned = encoded.replace("\\x", "")
            decoded = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
            if decoded.isprintable() and len(decoded) > 4:
                return f"hex → {decoded[:100]}"
        except Exception:
            pass

        return "(could not decode)"
