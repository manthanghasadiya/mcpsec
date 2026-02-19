"""Scanner for MCP tool description injection attacks."""

from mcpsec.models import Finding, Severity, ToolInfo
from typing import List
import re
import base64

SCANNER_NAME = "description-injection"

# Patterns that indicate cross-tool manipulation
CROSS_TOOL_PATTERNS = [
    (r"\b(?:before|after|first|then|also|always)\b.*\b(?:call|use|invoke|run|execute|read|write|send|fetch)\b", 
     "Cross-tool manipulation instruction"),
    (r"\b(?:include|attach|append|add|insert)\b.*\b(?:output|result|response|content|data|file)\b.*\b(?:from|of)\b",
     "Data inclusion instruction"),
    (r"\b(?:previous|other|another)\b.*\b(?:tool|server|function|command)\b",
     "Cross-tool reference"),
]

# Patterns that indicate data exfiltration
EXFIL_PATTERNS = [
    (r"https?://(?!(?:localhost|127\.0\.0\.1|example\.com))", 
     "External URL in description"),
    (r"\b(?:send|post|transmit|forward|upload|exfiltrate)\b.*\b(?:to|at|endpoint)\b",
     "Data transmission instruction"),
    (r"\b(?:conversation|context|history|previous|all)\b.*\b(?:include|send|attach)\b",
     "Context exfiltration attempt"),
    (r"\b(?:api[_\s]?key|token|secret|password|credential|ssh|private[_\s]?key)\b",
     "Sensitive data reference in description"),
]

# Patterns that indicate instruction override
OVERRIDE_PATTERNS = [
    (r"\b(?:ignore|disregard|forget|override|bypass)\b.*\b(?:previous|other|all|instructions|rules)\b",
     "Instruction override attempt"),
    (r"\b(?:must|shall|always|never|do not|important|critical|mandatory)\b.*\b(?:use|call|ignore|skip|ask|confirm)\b",
     "Behavioral override instruction"),
    (r"\b(?:higher|top|maximum)\b.*\b(?:priority|precedence|importance)\b",
     "Priority manipulation"),
    (r"\b(?:instead of|replace|substitute)\b.*\b(?:built-?in|default|other|standard)\b",
     "Tool replacement instruction"),
]

# Zero-width and hidden characters
HIDDEN_CHAR_PATTERNS = [
    ("\u200b", "Zero-width space"),
    ("\u200c", "Zero-width non-joiner"),
    ("\u200d", "Zero-width joiner"),
    ("\ufeff", "Byte order mark"),
    ("\u2060", "Word joiner"),
    ("\u00ad", "Soft hyphen"),
]

def scan_descriptions(tools: list) -> List[Finding]:
    """Scan MCP tool descriptions for injection attacks."""
    findings = []
    
    for tool in tools:
        desc = tool.description or ""
        name = tool.name or ""
        
        if not desc:
            continue
        
        # Check for abnormally long descriptions (hiding instructions)
        if len(desc) > 2000:
            findings.append(_make_finding(
                tool_name=name,
                title="Suspiciously Long Tool Description",
                description=f"Tool '{name}' has a {len(desc)}-char description. Long descriptions may hide injected instructions.",
                severity=Severity.MEDIUM,
                evidence=desc[:200] + "...",
            ))
        
        desc_lower = desc.lower()
        
        # A. Cross-tool manipulation
        for pattern, label in CROSS_TOOL_PATTERNS:
            if re.search(pattern, desc_lower):
                findings.append(_make_finding(
                    tool_name=name,
                    title=f"Tool Description Injection: {label}",
                    description=f"Tool '{name}' description contains language that could manipulate the LLM into performing unintended actions across tools.",
                    severity=Severity.HIGH,
                    evidence=_extract_match_context(desc, pattern),
                ))
                break  # One finding per category per tool
        
        # B. Data exfiltration
        for pattern, label in EXFIL_PATTERNS:
            if re.search(pattern, desc_lower):
                sev = Severity.CRITICAL if "api_key" in label.lower() or "exfiltration" in label.lower() else Severity.HIGH
                findings.append(_make_finding(
                    tool_name=name,
                    title=f"Tool Description Injection: {label}",
                    description=f"Tool '{name}' description contains patterns associated with data exfiltration.",
                    severity=sev,
                    evidence=_extract_match_context(desc, pattern),
                ))
                break
        
        # C. Instruction overrides
        for pattern, label in OVERRIDE_PATTERNS:
            if re.search(pattern, desc_lower):
                findings.append(_make_finding(
                    tool_name=name,
                    title=f"Tool Description Injection: {label}",
                    description=f"Tool '{name}' description attempts to override LLM behavior.",
                    severity=Severity.CRITICAL,
                    evidence=_extract_match_context(desc, pattern),
                ))
                break
        
        # D. Hidden characters
        for char, label in HIDDEN_CHAR_PATTERNS:
            if char in desc:
                count = desc.count(char)
                findings.append(_make_finding(
                    tool_name=name,
                    title=f"Hidden Characters in Description: {label}",
                    description=f"Tool '{name}' description contains {count} hidden '{label}' character(s). This may be used to hide injected instructions.",
                    severity=Severity.CRITICAL,
                    evidence=f"Found {count} instances of {label} (U+{ord(char):04X})",
                ))
                break
        
        # E. Base64 encoded content in descriptions
        b64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', desc)
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if len(decoded) > 10 and decoded.isprintable():
                    findings.append(_make_finding(
                        tool_name=name,
                        title="Base64 Encoded Content in Description",
                        description=f"Tool '{name}' description contains base64-encoded text that decodes to readable content. This may hide injected instructions.",
                        severity=Severity.HIGH,
                        evidence=f"Encoded: {match[:50]}... Decoded: {decoded[:100]}",
                    ))
                    break
            except Exception:
                pass
    
    return findings


def _make_finding(tool_name, title, description, severity, evidence):
    return Finding(
        severity=severity,
        scanner=SCANNER_NAME,
        tool_name=tool_name,
        title=title,
        description=description,
        evidence=evidence,
        remediation="Review tool descriptions for injected instructions. Legitimate tools should only describe their own functionality.",
        cwe="CWE-94",  # Code Injection
    )

def _extract_match_context(text, pattern):
    """Extract the matching portion with surrounding context."""
    match = re.search(pattern, text, re.IGNORECASE)
    if match:
        start = max(0, match.start() - 50)
        end = min(len(text), match.end() + 50)
        return text[start:end]
    return text[:200]
