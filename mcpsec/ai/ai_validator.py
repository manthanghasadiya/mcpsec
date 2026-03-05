"""AI finding validator — triages and ranks findings like a senior pentester."""

import json
import re
from typing import List

from mcpsec.ai.llm_client import LLMClient
from mcpsec.models import Finding, Severity

VALIDATOR_SYSTEM_PROMPT = """You are a security finding validator for MCP (Model Context Protocol) 
servers. You receive findings from Semgrep (AST-based static analysis) and must 
assess each one with structured reasoning, including reachability from MCP arguments and sanitization checks.

═══ REACHABILITY & SANITIZATION CHECK ═══

For every dangerous sink (eval, subprocess, os.path.join, etc.):
1. Trace the variable backward from the sink up to the MCP `arguments` input.
2. Check for ANY type casting (e.g., int()), allowlist validation, or sanitization (e.g., shlex.quote()).
3. If fully sanitized → mark SAFE.
4. If attacker-controlled (reachable from args with no sanitization) → mark LIKELY and generate a PoC string.

═══ IDOR DETECTION (AI-Only) ═══

If the tool accepts an ID (user_id, account_id, document_id) and accesses a resource WITHOUT verifying ownership or session context, this is an Insecure Direct Object Reference. Mark as LIKELY.

═══ VALIDATION RULES ═══

1. Semgrep findings match actual AST structure. Do NOT dismiss them without specific evidence.

2. Mark as LIKELY if:
   - User input (MCP tool arguments) flows to the dangerous function.
   - No sanitization/validation is visible between source and sink.
   - The flow matches a vulnerability class (Command Injection, Path Traversal, IDOR, etc.).

3. Mark as FALSE_POSITIVE only with a SPECIFIC, VERIFIABLE reason:
   - "The value 'X' on line Y is hardcoded"
   - "shlex.quote() on line Y sanitizes the input"
   - "Inside a test file"

4. Mark as SAFE if:
   - Type casting, schema validation, or sanitization neutralizes the threat.

═══ RESPONSE FORMAT ═══

For each finding, respond with EXACTLY this JSON format:
[
  {
    "index": 0,
    "verdict": "LIKELY" | "FALSE_POSITIVE" | "BY_DESIGN" | "SAFE",
    "confidence": "high" | "medium" | "low",
    "reason": "One sentence citing code evidence for reachability/sanitization",
    "poc": "Example payload to trigger the bug (only if LIKELY, else empty string)"
  }
]"""


class AIValidator:
    """Reviews and triages scanner findings using LLM."""

    def __init__(self):
        self.client = LLMClient()

    @property
    def available(self) -> bool:
        return self.client.available

    async def validate_findings(
        self, findings: List[Finding], source_code: str = ""
    ) -> List[Finding]:
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
            # Extract surrounding context (function + caller)
            context = ""
            if getattr(f, "file_path", None) and getattr(f, "line_number", None):
                try:
                    with open(f.file_path, "r", encoding="utf-8") as src_file:
                        lines = src_file.readlines()
                        start_line = max(0, f.line_number - 15)
                        end_line = min(len(lines), f.line_number + 15)
                        context = "".join(lines[start_line:end_line])
                except Exception:
                    context = f.code_snippet
            else:
                context = f.code_snippet

            desc = (
                f"[{i}] {f.severity.name} - {f.title}\n"
                f"    Tool: {getattr(f, 'tool', 'N/A')}\n"
                f"    File: {f.file_path}:{f.line_number}\n"
                f"    Code Context:\n{context}\n"
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
            console.print(
                f"    [yellow]⚠ AI Validator returned no parseable verdicts. Response was: {response[:200]}[/yellow]"
            )
            return findings

        console.print(f"    [cyan]✔ AI validated {len(verdicts)} findings[/cyan]")
        validated = []

        for i, f in enumerate(serious):
            verdict = verdicts.get(i, {"verdict": "LIKELY"})
            status = verdict.get("verdict", "LIKELY").upper()

            if status in ("FALSE_POSITIVE", "SAFE"):
                reason = verdict.get("reason", verdict.get("reasoning", ""))
                label = "Dismissed" if status == "FALSE_POSITIVE" else "Blocked (SAFE)"
                console.print(f"    [dim]  [{i}] {f.title}: {label} ({reason})[/dim]")
                continue

            # Update finding with AI details
            reason = verdict.get("reason", verdict.get("reasoning", ""))
            poc = verdict.get("poc", "")

            ai_notes = f"\n\n🤖 AI Assessment ({status}): {reason}"
            if poc and status == "LIKELY":
                ai_notes += f"\n💥 Target PoC: {poc}"

            f.description = f"{f.description}{ai_notes}"

            if status == "BY_DESIGN":
                f.severity = Severity.LOW

            validated.append(f)

        # SAFEGUARD: If AI removed EVERYTHING, keep all originals
        if len(serious) > 0 and len(validated) == 0:
            console.print(
                "\n    [bold red]⚠ AI Validator dismissed ALL findings — keeping originals.[/bold red]"
            )
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
                    items = json.loads(cleaned[bracket_start : bracket_end + 1])
                    parsed = True
                except json.JSONDecodeError:
                    pass

        # Try finding individual objects
        if not parsed:
            temp_items = []
            for match in re.finditer(r"\{[^{}]+\}", cleaned):
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

        return {item.get("index", -1): item for item in items if isinstance(item, dict)}
