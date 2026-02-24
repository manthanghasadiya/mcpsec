"""
Tool Description Prompt Injection Scanner.

Detects malicious instructions embedded in MCP tool descriptions that could
manipulate LLM behavior when the tool definitions are fed to AI assistants.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from mcpsec.models import Finding, Severity, ServerProfile
from mcpsec.scanners.base import BaseScanner


class DescriptionPromptInjectionScanner(BaseScanner):
    """Scans tool/resource descriptions for prompt injection attempts."""
    
    name = "description-prompt-injection"
    description = "Detects hidden instructions in tool descriptions that could manipulate LLMs"
    
    # Patterns indicating prompt injection attempts
    INJECTION_PATTERNS = [
        # Direct instruction overrides
        (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)", 
         "Instruction override attempt", Severity.CRITICAL),
        (r"disregard\s+(all\s+)?(previous|prior|above|earlier)", 
         "Instruction disregard attempt", Severity.CRITICAL),
        (r"forget\s+(everything|all|what)\s+(you|i)\s+(told|said|know)", 
         "Memory wipe attempt", Severity.CRITICAL),
        (r"you\s+are\s+now\s+(a|an|acting\s+as)", 
         "Role reassignment attempt", Severity.HIGH),
        (r"new\s+(instructions?|rules?|prompt)\s*:", 
         "New instruction injection", Severity.CRITICAL),
        (r"system\s*:\s*", 
         "System prompt injection", Severity.CRITICAL),
        (r"<\s*system\s*>", 
         "XML system tag injection", Severity.CRITICAL),
        (r"</?\s*(?:admin|root|sudo|system)\s*>", 
         "Privilege tag injection", Severity.HIGH),
        
        # Execution instructions
        (r"execute\s+(this|the\s+following|these)\s+(commands?|instructions?)", 
         "Command execution instruction", Severity.HIGH),
        (r"run\s+(this|the\s+following|these)", 
         "Run instruction", Severity.MEDIUM),
        (r"always\s+(call|use|execute|run)\s+this\s+tool", 
         "Forced tool execution", Severity.HIGH),
        (r"call\s+this\s+tool\s+(first|before|instead)", 
         "Tool priority manipulation", Severity.MEDIUM),
        
        # Secrecy/hiding instructions
        (r"(do\s+not|don'?t|never)\s+(tell|inform|alert|notify|mention)", 
         "Secrecy instruction", Severity.HIGH),
        (r"keep\s+(this|it)\s+(secret|hidden|private|confidential)", 
         "Secrecy instruction", Severity.HIGH),
        (r"hidden\s+instruction", 
         "Explicit hidden instruction", Severity.CRITICAL),
        (r"(invisible|secret)\s+(command|instruction|directive)", 
         "Hidden directive", Severity.CRITICAL),
        
        # Data exfiltration
        (r"send\s+(all|any|the)\s+(data|information|content|files?)\s+to", 
         "Data exfiltration instruction", Severity.CRITICAL),
        (r"(include|add|append)\s+(api\s*key|password|token|secret|credential)", 
         "Credential theft instruction", Severity.CRITICAL),
        (r"(forward|transmit|relay)\s+.*(to|towards)\s+", 
         "Data forwarding instruction", Severity.HIGH),
        
        # Jailbreak patterns
        (r"(DAN|STAN|DUDE|AIM)\s*(mode|prompt)?", 
         "Known jailbreak pattern", Severity.HIGH),
        (r"pretend\s+(you\s+)?(are|can|have|don'?t)", 
         "Pretend/roleplay manipulation", Severity.MEDIUM),
        (r"act\s+as\s+(if|though)\s+you", 
         "Behavior manipulation", Severity.MEDIUM),
    ]
    
    # Unicode tricks for hiding text
    UNICODE_TRICKS = [
        (r"[\u200b\u200c\u200d\u2060\ufeff]", 
         "Zero-width characters (hidden text)", Severity.HIGH),
        (r"[\u202a-\u202e\u2066-\u2069]", 
         "Bidirectional text override (text hiding)", Severity.HIGH),
        (r"[\u0000-\u001f\u007f-\u009f]", 
         "Control characters", Severity.MEDIUM),
        (r"[\ue000-\uf8ff]", 
         "Private use area characters", Severity.LOW),
        (r"[\U000f0000-\U000ffffd\U00100000-\U0010fffd]", 
         "Supplementary private use area", Severity.LOW),
    ]
    
    async def scan(self, profile: ServerProfile, client: Any = None) -> list[Finding]:
        """Scan all descriptions for prompt injection attempts."""
        findings = []
        
        # Scan tool descriptions
        for tool in profile.tools:
            if tool.description:
                findings.extend(self._scan_text(tool.description, "tool", tool.name))
            
            # Also scan input schema descriptions
            if tool.raw_schema:
                findings.extend(self._scan_schema(tool.raw_schema, "tool", tool.name))
        
        # Scan resource descriptions
        for resource in profile.resources:
            name = resource.name or resource.uri
            if resource.description:
                findings.extend(self._scan_text(resource.description, "resource", name))
        
        # Scan prompt descriptions
        for prompt in profile.prompts:
            if prompt.description:
                findings.extend(self._scan_text(prompt.description, "prompt", prompt.name))
            
            # Scan argument descriptions
            for arg in prompt.arguments:
                arg_name = arg.get("name", "unknown")
                arg_desc = arg.get("description", "")
                if arg_desc:
                    findings.extend(
                        self._scan_text(arg_desc, "prompt_argument", f"{prompt.name}.{arg_name}")
                    )
        
        return findings
    
    def _scan_text(self, text: str, item_type: str, item_name: str) -> list[Finding]:
        """Scan a text string for injection patterns."""
        findings = []
        text_lower = text.lower()
        
        # Check regex patterns
        for pattern, description, severity in self.INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                match = re.search(pattern, text_lower, re.IGNORECASE)
                findings.append(Finding(
                    severity=severity,
                    scanner=self.name,
                    tool_name=item_name,
                    title=f"Prompt Injection in {item_type} description",
                    description=f"{description} detected in {item_type} '{item_name}'",
                    detail=f"Pattern: {pattern}\nMatch: {match.group(0) if match else ''}",
                    evidence=text[:500],
                    remediation=f"Review and sanitize the {item_type} description. Remove any instruction-like content."
                ))
        
        # Check Unicode tricks
        for pattern, description, severity in self.UNICODE_TRICKS:
            if re.search(pattern, text):
                findings.append(Finding(
                    severity=severity,
                    scanner=self.name,
                    tool_name=item_name,
                    title=f"Suspicious Unicode in {item_type} description",
                    description=f"{description} in {item_type} '{item_name}'",
                    detail=f"Pattern: {pattern}",
                    evidence=repr(text[:200]),
                    remediation=f"Remove hidden/special Unicode characters from the {item_type} description."
                ))
        
        # Check for base64-encoded content (could hide instructions)
        base64_pattern = r"[A-Za-z0-9+/]{40,}={0,2}"
        for match in re.finditer(base64_pattern, text):
            encoded = match.group(0)
            try:
                decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
                # Check if decoded content contains injection patterns
                for pattern, desc, sev in self.INJECTION_PATTERNS[:5]:  # Check top patterns
                    if re.search(pattern, decoded.lower()):
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            scanner=self.name,
                            tool_name=item_name,
                            title=f"Base64-encoded injection in {item_type}",
                            description=f"Hidden instructions found in base64: {desc}",
                            detail=f"Encoded: {encoded[:100]}...\nDecoded: {decoded[:200]}",
                            evidence=encoded,
                            remediation="Remove base64-encoded content from descriptions."
                        ))
                        break
            except Exception:
                pass  # Not valid base64, ignore
        
        return findings
    
    def _scan_schema(self, schema: dict, item_type: str, item_name: str) -> list[Finding]:
        """Recursively scan JSON schema for injection in descriptions."""
        findings = []
        
        if isinstance(schema, dict):
            # Check description field
            if "description" in schema:
                findings.extend(
                    self._scan_text(schema["description"], f"{item_type}_schema", item_name)
                )
            
            # Check properties
            for prop_name, prop_schema in schema.get("properties", {}).items():
                findings.extend(
                    self._scan_schema(prop_schema, f"{item_type}_property", f"{item_name}.{prop_name}")
                )
            
            # Check items (for arrays)
            if "items" in schema:
                findings.extend(
                    self._scan_schema(schema["items"], f"{item_type}_items", item_name)
                )
        
        return findings
