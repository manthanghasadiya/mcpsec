"""
LLM-powered reachability analysis.

Determines if user input can reach detected sinks.
"""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import json
import re

from mcpsec.ai.llm_client import LLMClient
from mcpsec.static.patterns.base import SinkMatch
from mcpsec.static.framework.detector import FrameworkInfo
from mcpsec.models import Finding, Severity


REACHABILITY_PROMPT_V2 = """You are analyzing MCP server code for vulnerabilities.

## SINK DETECTED
- File: {file_path}
- Line: {line_number}
- Type: {vuln_type}
- Code: `{code_line}`

## FULL FILE CONTEXT
```{language}
{full_file}
```

## FRAMEWORK: {framework}

## INSTRUCTIONS
1. Find MCP tool entry points (handlers, decorators, tool registrations)
2. Trace data flow from tool parameters to the sink
3. Check for sanitizers that would block exploitation
4. Generate a PoC payload if exploitable

## RESPOND WITH JSON:
{{
    "reachable": true/false,
    "confidence": "high/medium/low",
    "source_tool": "tool name",
    "source_param": "param name",
    "taint_flow": ["Step 1...", "Step 2...", "Step 3..."],
    "sanitized": true/false,
    "exploitable": true/false,
    "poc_payload": {{"tool": "name", "args": {{"param": "payload"}}}},
    "explanation": "Summary"
}}
"""


@dataclass
class ReachabilityResult:
    """Result of reachability analysis."""
    sink: SinkMatch
    reachable: bool
    confidence: str
    source_param: Optional[str]
    flow: str
    sanitized: bool
    exploitable: bool
    poc_suggestion: Optional[str]
    explanation: str


class ReachabilityAnalyzer:
    """
    Uses LLM to determine if sinks are reachable from MCP input.
    Falls back to heuristics when LLM is unavailable.
    """

    def __init__(self):
        self.client = LLMClient()

    @property
    def available(self) -> bool:
        return self.client.available

    async def analyze_sinks(
        self,
        sinks: list[SinkMatch],
        framework_info: FrameworkInfo,
        project_path: Path,
    ) -> list[Finding]:
        """
        Analyze sinks for reachability.
        Returns validated findings.
        """
        if not self.available:
            return self._heuristic_analysis(sinks, framework_info)

        findings = []
        for sink in sinks:
            result = await self._analyze_sink_v2(sink, framework_info, project_path)
            if result.reachable and result.exploitable:
                finding = self._create_finding(sink, result)
                findings.append(finding)

        return findings

    async def _analyze_sink_v2(
        self,
        sink: SinkMatch,
        framework_info: FrameworkInfo,
        project_path: Path,
    ) -> ReachabilityResult:
        # Read full file (truncate if >50K chars)
        file_path = Path(sink.file_path)
        try:
            full_file = file_path.read_text(encoding="utf-8")[:50000]
        except Exception:
            full_file = sink.context

        # Use improved prompt
        prompt = REACHABILITY_PROMPT_V2.format(
            file_path=sink.file_path,
            line_number=sink.line_number,
            vuln_type=sink.pattern.vuln_type.value,
            code_line=sink.code_line,
            language=framework_info.language.value,
            full_file=full_file,
            framework=framework_info.framework.value,
        )

        response = await self.client.chat(
            system="Respond with valid JSON only.",
            user=prompt,
        )

        return self._parse_response(sink, response)

    def _parse_response(self, sink: SinkMatch, response: Optional[str]) -> ReachabilityResult:
        """Parse LLM JSON response into ReachabilityResult."""
        default = ReachabilityResult(
            sink=sink,
            reachable=False,
            confidence="low",
            source_param=None,
            flow="",
            sanitized=False,
            exploitable=False,
            poc_suggestion=None,
            explanation="Analysis inconclusive",
        )

        if not response:
            return default

        # Clean and parse JSON
        cleaned = response.strip()
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            # Try to extract first JSON object
            m = re.search(r"\{[^{}]+\}", cleaned, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group())
                except Exception:
                    return default
            else:
                return default

        return ReachabilityResult(
            sink=sink,
            reachable=bool(data.get("reachable", False)),
            confidence=str(data.get("confidence", "low")),
            source_param=data.get("source_param"),
            flow=str(data.get("flow", "")),
            sanitized=bool(data.get("sanitized", False)),
            exploitable=bool(data.get("exploitable", False)),
            poc_suggestion=data.get("poc_suggestion"),
            explanation=str(data.get("explanation", "")),
        )

    def _create_finding(
        self,
        sink: SinkMatch,
        result: ReachabilityResult,
    ) -> Finding:
        """Convert a ReachabilityResult to a Finding."""
        description = result.explanation
        if result.flow:
            description += f"\n\nData flow: {result.flow}"
        if result.poc_suggestion:
            description += f"\n\nPoC: {result.poc_suggestion}"

        return Finding(
            severity=sink.pattern.severity,
            scanner="mcpsec-audit-reachability",
            title=f"{sink.pattern.vuln_type.value}: {sink.pattern.function_name}",
            description=description,
            file_path=sink.file_path,
            line_number=sink.line_number,
            code_snippet=sink.context,
            taint_source=result.source_param or "unknown",
            taint_sink=sink.pattern.function_name,
            taint_flow=result.flow,
            confidence=result.confidence,
            remediation=sink.pattern.remediation,
            cwe=sink.pattern.cwe,
        )

    def _heuristic_analysis(
        self,
        sinks: list[SinkMatch],
        framework_info: FrameworkInfo,
    ) -> list[Finding]:
        """
        Fallback heuristic analysis without LLM.
        Only reports HIGH-confidence sinks when LLM is unavailable.
        """
        findings = []

        for sink in sinks:
            if sink.pattern.confidence.value == "low":
                continue

            findings.append(Finding(
                severity=sink.pattern.severity,
                scanner="mcpsec-audit-heuristic",
                title=f"Potential {sink.pattern.vuln_type.value}: {sink.pattern.function_name}",
                description=(
                    f"Dangerous sink detected. Manual verification required.\n\n"
                    f"{sink.pattern.description}"
                ),
                file_path=sink.file_path,
                line_number=sink.line_number,
                code_snippet=sink.short_context,
                confidence="medium",
                remediation=sink.pattern.remediation,
                cwe=sink.pattern.cwe,
            ))

        return findings
