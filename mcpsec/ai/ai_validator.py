"""AI finding validator — triages and ranks findings like a senior pentester."""

import json
import re
from typing import List
from mcpsec.models import Finding, Severity
from mcpsec.ai.llm_client import LLMClient

VALIDATOR_SYSTEM_PROMPT = """You are a security finding validator. You receive findings from a 
static analysis tool (Semgrep) and must assess each one.

IMPORTANT RULES:
1. Semgrep findings are AST-based and HIGH CONFIDENCE. They matched 
   actual code patterns, not string grep. DO NOT dismiss them lightly.
2. Mark as REAL if:
   - User input flows to a dangerous function (exec, query, eval)
   - No sanitization is visible between source and sink
   - The finding is in application code (not test/example files)
3. Mark as FALSE_POSITIVE only if you can identify a SPECIFIC reason:
   - The value is hardcoded (not from user input)
   - There IS sanitization between source and sink
   - The code is commented out or unreachable
   - The file is explicitly a test fixture or documentation
4. Mark as BY_DESIGN if:
   - The tool/server is explicitly designed to execute commands
   - The README says "execute commands" or "shell access"
5. When in doubt, mark as REAL. False negatives are worse than 
   false positives in security scanning.
6. NEVER dismiss a finding just because it "looks like scanner output"
   or "appears to be automated testing."

For each finding, respond with EXACTLY this JSON format:
[
  {
    "index": 0,
    "verdict": "REAL" | "FALSE_POSITIVE" | "BY_DESIGN",
    "reason": "one line explanation"
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
                reason = verdict.get("reason", verdict.get("reasoning", ""))
                console.print(f"    [dim]  [{i}] {f.title}: Dismissed ({reason})[/dim]")
                continue
                
            # Update finding with AI details
            reason = verdict.get("reason", verdict.get("reasoning", ""))
            if reason:
                f.description = f"{f.description}\n\n🤖 AI Assessment ({status}): {reason}"
            
            if status == "BY_DESIGN":
                f.severity = Severity.LOW
                
            validated.append(f)
        
        # SAFEGUARD: If AI removed EVERYTHING, keep all originals
        if len(serious) > 0 and len(validated) == 0:
            console.print("\n    [bold red]⚠ AI Validator dismissed ALL findings — keeping originals.[/bold red]")
            return serious + low
            
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
