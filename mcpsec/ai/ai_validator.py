"""AI finding validator — triages and ranks findings like a senior pentester."""

import json
import re
from typing import List
from mcpsec.models import Finding, Severity
from mcpsec.ai.llm_client import LLMClient

VALIDATOR_SYSTEM_PROMPT = """You are a senior penetration tester reviewing automated 
scanner findings. Your job is to triage findings and remove false positives.

For each finding, assess:
1. Is the vulnerability REAL or a false positive?
2. Is it actually EXPLOITABLE in practice?
3. What is the real-world IMPACT?
4. How would an attacker chain this with other findings?

Rules:
- A finding is FALSE POSITIVE if:
  - The code is commented out
  - The input is sanitized/validated before the sink
  - The value is hardcoded (not user-controlled)
  - The sink is in test/example code that doesn't run in production
  - The "dangerous" function is used safely (e.g., spawn with array args)

- A finding is LOW RISK if:
  - Exploitation requires unlikely conditions
  - The tool is clearly designed to do dangerous things (e.g., a shell MCP server)
  - The impact is limited (e.g., reading non-sensitive files only)

IMPORTANT: These findings come from a security scanner that has 
CONFIRMED exploitation. If a finding says "CONFIRMED" or includes 
actual response data showing successful exploitation (e.g., file 
contents from path traversal, username from whoami, database records 
from SQL injection), it IS a real vulnerability regardless of whether 
it was found by an automated tool. Automated scanners finding real 
bugs does not make the bugs less real.

Do NOT dismiss findings just because they were found by a scanner.
Judge the EVIDENCE: did the payload produce output proving exploitation?
If yes → REAL. If the response just echoes the payload back → LOW_RISK.

Respond with JSON array of validated findings:
[
  {
    "index": original_finding_index,
    "verdict": "REAL" | "FALSE_POSITIVE" | "LOW_RISK",
    "confidence": "high" | "medium" | "low",
    "reasoning": "One sentence explaining your assessment",
    "exploit_scenario": "If REAL: brief description of how attacker exploits this"
  }
]"""


class AIValidator:
    """Reviews and triages scanner findings using LLM."""
    
    def __init__(self):
        self.client = LLMClient()
    
    @property
    def available(self) -> bool:
        return self.client.available
    
    async def validate_findings(self, findings: List[Finding], 
                                 source_code: str = "") -> List[Finding]:
        """Review findings and filter false positives."""
        if not self.available or not findings:
            return findings
        
        # Only validate CRITICAL and HIGH findings (not worth AI cost on LOW)
        serious = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        low = [f for f in findings if f.severity not in (Severity.CRITICAL, Severity.HIGH)]
        
        if not serious:
            return findings
        
        from rich.console import Console
        console = Console()
        
        # Build finding descriptions for the LLM
        finding_descriptions = []
        for i, f in enumerate(serious):
            desc = (
                f"[{i}] {f.severity.name} - {f.title}\n"
                f"    Scanner: {f.scanner}\n"
                f"    Tool: {getattr(f, 'tool', 'N/A')}\n"
                f"    Parameter: {getattr(f, 'parameter', 'N/A')}\n"
                f"    File: {f.file_path or 'N/A'} Line: {f.line_number or 'N/A'}\n"
                f"    Code: {f.code_snippet[:200] if f.code_snippet else 'N/A'}\n"
                f"    Description: {f.description[:500] if f.description else 'N/A'}\n"
                f"    Flow: {f.taint_flow or 'N/A'}\n"
            )
            finding_descriptions.append(desc)
        
        prompt = f"""Review these {len(serious)} security findings from an MCP server scan.

{"Source code context:" if source_code else ""}
{source_code[:8000] if source_code else "No source code available."}

Findings to review:
{chr(10).join(finding_descriptions)}

For each finding, determine: REAL, FALSE_POSITIVE, or LOW_RISK.
Respond ONLY with JSON array."""
        
        response = await self.client.chat(VALIDATOR_SYSTEM_PROMPT, prompt)
        if not response:
            return findings  # If AI fails, return all findings unmodified
        
        verdicts = self._parse_verdicts(response)
        
        if not verdicts:
            console.print("    [yellow]⚠ AI Validator returned no parseable verdicts.[/yellow]")
            return findings
        
        console.print(f"    [cyan]✔ AI validated {len(verdicts)} findings[/cyan]")
        validated = []
        for i, f in enumerate(serious):
            verdict = verdicts.get(i, {"verdict": "REAL"})
            if verdict.get("verdict") == "FALSE_POSITIVE":
                continue  # Remove false positive
            # Add AI reasoning to finding description
            if verdict.get("exploit_scenario"):
                reason = verdict.get("reasoning", "")
                console.print(f"    [dim]  [{i}] {serious[i].title}: {verdict.get('verdict')} - {reason[:60]}...[/dim]")
                f.description = (
                    f"{f.description}\n"
                    f"AI Assessment: {reason}\n"
                    f"Exploit: {verdict.get('exploit_scenario', '')}"
                )
            else:
                console.print(f"    [dim]  [{i}] {serious[i].title}: {verdict.get('verdict')}[/dim]")
            validated.append(f)
        
        return validated + low
    
    def _parse_verdicts(self, response: str) -> dict:
        """Parse validator response into verdict dict keyed by index."""
        cleaned = response.strip()
        cleaned = re.sub(r"^```(?:json)?\s*\n?", "", cleaned)
        cleaned = re.sub(r"\n?\s*```\s*$", "", cleaned)
        
        items = []
        parsed = False
        
        # Try direct parse
        try:
            items = json.loads(cleaned)
            parsed = True
        except json.JSONDecodeError:
            pass
            
        # Try finding array brackets
        if not parsed:
            bracket_start = cleaned.find("[")
            bracket_end = cleaned.rfind("]")
            if bracket_start != -1 and bracket_end != -1 and bracket_end > bracket_start:
                try:
                    items = json.loads(cleaned[bracket_start:bracket_end + 1])
                    parsed = True
                except json.JSONDecodeError:
                    pass
        
        # Try finding individual objects
        if not parsed:
            temp_items = []
            for match in re.finditer(r'\{[^{}]+\}', cleaned):
                try:
                    obj = json.loads(match.group())
                    if isinstance(obj, dict):
                        temp_items.append(obj)
                except json.JSONDecodeError:
                    continue
            if temp_items:
                items = temp_items
                parsed = True
        
        if not isinstance(items, list):
            return {}
        
        return {
            item.get("index", -1): item
            for item in items
            if isinstance(item, dict)
        }
