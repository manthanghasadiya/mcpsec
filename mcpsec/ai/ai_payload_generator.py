"""AI payload generator — creates targeted exploits per MCP tool."""

import json
import re
from typing import List, Dict, Any
from mcpsec.ai.llm_client import LLMClient

PAYLOAD_SYSTEM_PROMPT = """You are a penetration tester generating exploit payloads 
for MCP server tools. Given a tool's name, description, and parameters, generate
targeted attack payloads that a human pentester would try.

Generate payloads for these categories:
1. Command injection (OS-specific: Linux AND Windows)
2. Path traversal (with bypass techniques: double encoding, null bytes, ../ variations)
3. SQL injection (if the tool touches databases)
4. SSRF (if the tool makes network requests)
5. Prompt injection (if the tool processes text that an LLM sees)
6. Logic bugs (negative values, empty strings, extremely long inputs, type confusion)
7. Authentication bypass (if tool has auth-related parameters)

For EACH payload, explain what it tests and what a successful exploit looks like.

Respond ONLY with JSON array:
[
  {
    "parameter": "name of the parameter to inject into",
    "payload": "the actual payload string",
    "category": "command-injection" | "path-traversal" | "sqli" | "ssrf" | "prompt-injection" | "logic" | "auth-bypass",
    "description": "What this tests",
    "success_indicator": "What to look for in the response to confirm exploitation"
  }
]

Generate 10-20 payloads per tool. Be creative. Think like a real attacker.
Include bypass techniques (WAF evasion, encoding tricks, filter bypasses).
Do NOT generate generic payloads. Every payload should be tailored to THIS tool."""


class AIPayloadGenerator:
    """Generates custom exploit payloads per MCP tool using LLM."""
    
    def __init__(self):
        self.client = LLMClient()
    
    @property
    def available(self) -> bool:
        return self.client.available
    
    async def generate_payloads(self, tool_info: Dict[str, Any]) -> List[Dict]:
        """Generate targeted payloads for a specific MCP tool."""
        if not self.available:
            return []
        
        prompt = f"""Generate targeted security test payloads for this MCP tool:

Tool name: {tool_info.get('name', 'unknown')}
Description: {tool_info.get('description', 'No description')}
Parameters: {json.dumps(tool_info.get('parameters', {}), indent=2)}

Consider the tool's purpose and generate payloads that:
1. Are specific to what this tool does (not generic)
2. Include bypass techniques for common input filters
3. Test both Linux and Windows attack vectors
4. Include encoding/obfuscation variants
5. Test edge cases the developer probably didn't think of

Respond ONLY with JSON array."""
        
        response = await self.client.chat(PAYLOAD_SYSTEM_PROMPT, prompt)
        if not response:
            from mcpsec.ui import console
            console.print(f"  [dim]    ⚠ AI returned empty response for {tool_info.get('name')}[/dim]")
            return []
        
        parsed = self._parse_payloads(response)
        if not parsed:
            from mcpsec.ui import console
            console.print(f"  [dim]    ⚠ Failed to parse AI response for {tool_info.get('name')} (Length: {len(response)})[/dim]")
            # console.print(f"  [dim]    Raw: {response[:100]}...[/dim]")
        
        return parsed
    
    def _parse_payloads(self, response: str) -> List[Dict]:
        """Parse LLM payload response with robust extraction."""
        cleaned = response.strip()
        
        # Strip markdown fences (```json ... ```)
        cleaned = re.sub(r"^```(?:json)?\s*\n?", "", cleaned)
        cleaned = re.sub(r"\n?\s*```\s*$", "", cleaned)
        
        # Try direct parse first
        try:
            items = json.loads(cleaned)
            if isinstance(items, list):
                return [i for i in items if isinstance(i, dict) and "payload" in i]
        except json.JSONDecodeError:
            pass
        
        # Try to find JSON array in the response
        # Handle case where LLM wraps response in explanation text
        bracket_start = cleaned.find("[")
        bracket_end = cleaned.rfind("]")
        
        if bracket_start != -1 and bracket_end != -1 and bracket_end > bracket_start:
            json_str = cleaned[bracket_start:bracket_end + 1]
            try:
                items = json.loads(json_str)
                if isinstance(items, list):
                    return [i for i in items if isinstance(i, dict) and "payload" in i]
            except json.JSONDecodeError:
                pass
        
        # Last resort: try to find individual JSON objects
        # Some LLMs return one object per line
        items = []
        for match in re.finditer(r'\{[^{}]+\}', cleaned):
            try:
                obj = json.loads(match.group())
                if isinstance(obj, dict) and "payload" in obj:
                    items.append(obj)
            except json.JSONDecodeError:
                continue
        
        return items
