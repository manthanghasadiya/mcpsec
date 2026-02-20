"""AI finding validator — triages and ranks findings like a senior pentester."""

import json
import re
from typing import List
from mcpsec.models import Finding, Severity
from mcpsec.ai.llm_client import LLMClient

VALIDATOR_SYSTEM_PROMPT = """You are a senior penetration tester reviewing automated 
scanner findings. Your primary goal is to prioritize findings, NOT to dismiss them.

The findings you are reviewing come from Semgrep, which uses AST (Abstract Syntax Tree) 
analysis. This means they are syntactically correct and represent real code patterns.

INSTRUCTIONS:
1. TRUST THE SCANNER. Assume the finding is REAL unless you have specific evidence otherwise.
2. ONLY dismiss a finding as FALSE POSITIVE if:
   - The code is inside a comment or string literal (and not executable)
   - The value is hardcoded constant (e.g., exec("ls"))
   - The code is clearly inside a test file or example script
   - The input is explicitly sanitized immediately before use (e.g., parseInt(input))

3. DO NOT dismiss findings because:
   - "It might be safe" (If unclear, mark as LOW RISK, not False Positive)
   - "It requires user interaction" (That's still a vulnerability)
   - "It's a CLI tool" (Command injection is still valid in CLI tools)

4. CLASSIFICATION:
   - REAL: Valid vulnerability.
   - LOW_RISK: Valid but difficult to exploit or low impact.
   - FALSE_POSITIVE: Technically impossible to exploit (dead code, hardcoded, etc).

Respond with JSON array:
[
  {
    "index": 0,
    "verdict": "REAL" | "LOW_RISK" | "FALSE_POSITIVE",
    "reasoning": "Brief explanation",
    "exploit_scenario": "How to exploit (if REAL)"
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
        
        # Only validate CRITICAL and HIGH findings
        serious = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        low = [f for f in findings if f.severity not in (Severity.CRITICAL, Severity.HIGH)]
        
        if not serious:
            return findings
        
        from rich.console import Console
        console = Console()
        
        # Build finding descriptions
        finding_descriptions = []
        for i, f in enumerate(serious):
            desc = (
                f"[{i}] {f.severity.name} - {f.title}\n"
                f"    Tool: {getattr(f, 'tool', 'N/A')}\n"
                f"    File: {f.file_path}:{f.line_number}\n"
                f"    Code: {f.code_snippet[:300] if f.code_snippet else 'N/A'}\n"
                f"    Flow: {f.taint_flow or 'N/A'}\n"
            )
            finding_descriptions.append(desc)
        
        prompt = f"""Review these {len(serious)} Semgrep findings.
        
{"Source context:" if source_code else ""}
{source_code[:5000] if source_code else ""}

Findings:
{chr(10).join(finding_descriptions)}

Respond ONLY with JSON array."""
        
        response = await self.client.chat(VALIDATOR_SYSTEM_PROMPT, prompt)
        if not response:
            return findings
        
        verdicts = self._parse_verdicts(response)
        
        if not verdicts:
            console.print("    [yellow]⚠ AI Validator returned no parseable verdicts.[/yellow]")
            return findings
        
        console.print(f"    [cyan]✔ AI validated {len(verdicts)} findings[/cyan]")
        validated = []
        
        for i, f in enumerate(serious):
            verdict = verdicts.get(i, {"verdict": "REAL"})
            status = verdict.get("verdict", "REAL").upper()
            
            if status == "FALSE_POSITIVE":
                # console.print(f"    [dim]  [{i}] {f.title}: Dismissed ({verdict.get('reasoning')})[/dim]")
                continue
                
            # Update finding with AI details
            if verdict.get("reasoning"):
                f.description = f"{f.description}\n\n🤖 AI Assessment ({status}): {verdict['reasoning']}"
            
            if status == "LOW_RISK":
                f.severity = Severity.LOW
                
            validated.append(f)
            
        # WARNING: If AI removed EVERYTHING, that's suspicious
        if len(serious) > 0 and len(validated) == 0:
            console.print("\n    [bold red]⚠ AI Validator dismissed ALL findings. This might be a mistake.[/bold red]")
            console.print("    [yellow]Run without --ai to see raw scanner results.[/yellow]\n")
            
        return validated + low
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
