"""AI taint analysis — reads code like a pentester, not a regex engine."""

import json
import re
from pathlib import Path
from typing import List

from mcpsec.ai.llm_client import LLMClient
from mcpsec.models import Finding, Severity

TAINT_SYSTEM_PROMPT = """You are an expert MCP (Model Context Protocol) security auditor performing 
taint analysis. You trace data flows from user-controlled MCP tool parameters 
to dangerous sinks to find exploitable vulnerabilities.

═══ DATA FLOW TRACING ═══

Trace through ALL of these patterns:
- Direct variable assignment and string interpolation/concatenation
- Function call chains across files (service classes, helpers, utilities)
- Async/await chains, callbacks, Promise .then() chains
- Object destructuring: const { path, query } = args
- Array methods: .map(), .forEach(), .reduce(), .filter()
- Template literals: `SELECT * FROM ${table}`
- Property access chains: args.config.database.query

═══ VULNERABILITY CLASSES ═══

CRITICAL — Remote Code Execution:
  • Shell injection: exec(userInput), os.system(cmd), subprocess with shell=True
  • Code injection: eval(expr), exec(code), new Function(code), vm.runInNewContext
  • Deserialization: pickle.loads(data), yaml.load(data) without SafeLoader
  • MRO traversal: eval() sandbox without __class__/__mro__ blocking
  • SQLi to RCE: cursor.execute(f"...{userInput}...") on DB with file/exec ops

HIGH — Data Breach:
  • Path traversal: open(userPath) without realpath+containment check
  • SQL injection: string formatting in queries (f-string, %, .format, +)
  • SSRF: requests.get(userURL) without URL allowlist validation

MEDIUM — Logic/Auth Flaws:
  • IDOR: tool fetches resource by user-provided ID without ownership check
  • Indirect injection: tool writes user data to storage read by LLM later

═══ SANITIZERS (SAFE if present on tainted variable) ═══

These neutralize the taint:
  • parseInt(), Number(), parseFloat(), int(), float() — type casting
  • shlex.quote(), shlex.split() — shell escaping
  • path.basename(), path.normalize() + startsWith check — path safety
  • encodeURIComponent(), encodeURI() — URL encoding
  • Parameterized queries (?, $1, %s with tuple) — SQL safety
  • Schema validation (zod, joi, yup, pydantic) — input validation
  • Allowlist/enum checks — explicit value restriction

═══ FALSE POSITIVE RULES ═══

Do NOT report if:
  1. Value is hardcoded/constant (not from user input)
  2. Variable comes from config file or environment, not MCP arguments
  3. Sanitizer exists between source and sink
  4. Code is commented out, in a test file, or unreachable
  5. The function is a library/framework internal, not application code

═══ RESPONSE FORMAT ═══

Respond ONLY with a JSON array. No markdown fences. No explanation outside JSON.

[
  {
    "severity": "CRITICAL" | "HIGH" | "MEDIUM",
    "title": "Brief vulnerability title",
    "source": "MCP tool parameter name (e.g., 'path', 'query', 'url')",
    "sink": "Dangerous function call (e.g., 'subprocess.run()', 'cursor.execute()')",
    "flow": "Step-by-step trace: args.path → userPath → os.path.join(base, userPath) → open(joined)",
    "line": line_number_of_sink,
    "confidence": "high" | "medium",
    "explanation": "One sentence: what an attacker controls, and what they can do"
  }
]

If NO vulnerabilities found, respond: []"""


class AITaintAnalyzer:
    """Uses LLM to find complex taint flows regex can't catch."""

    def __init__(self):
        self.client = LLMClient()

    @property
    def available(self) -> bool:
        return self.client.available

    async def analyze_project(self, project_path: Path) -> List[Finding]:
        if not self.available:
            return []

        findings = []
        tool_files = self._find_tool_files(project_path)

        for file_path in tool_files:
            file_findings = await self._analyze_file(file_path, project_path)
            findings.extend(file_findings)

        return findings

    def _find_tool_files(self, project_path: Path) -> List[Path]:
        """Find files with MCP tool registrations."""
        tool_patterns = [
            r"server\.tool\(",
            r"setRequestHandler\(",
            r"CallToolRequest",
            r"@mcp\.tool",
            r"@server\.tool",
            r"tools/call",
            r"registerTool\(",
            r"list_tools",
        ]

        tool_files = []
        for ext in ["*.ts", "*.js", "*.mjs", "*.py"]:
            for fp in project_path.rglob(ext):
                path_str = str(fp)
                if any(
                    s in path_str
                    for s in [
                        "node_modules",
                        "dist",
                        "build",
                        ".git",
                        "__pycache__",
                        ".test.",
                        ".spec.",
                        "__tests__",
                        "docs",
                        "examples",
                    ]
                ):
                    continue
                try:
                    content = fp.read_text(encoding="utf-8", errors="ignore")
                    if any(re.search(p, content) for p in tool_patterns):
                        tool_files.append(fp)
                except Exception:
                    continue

        return tool_files

    async def _analyze_file(self, file_path: Path, project_root: Path) -> List[Finding]:
        """Analyze a single file. Includes imports/helpers for context."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        # Build context: include imported local files for cross-file analysis
        context = self._build_context(file_path, project_root, content)

        # Truncate if needed
        if len(context) > 15000:
            context = context[:15000] + "\n\n// ... (truncated)"

        prompt = f"""Analyze this MCP server code for security vulnerabilities.

Primary file: {file_path.name}
{context}

Find ALL flows where MCP tool parameters reach dangerous sinks without sanitization.
Include cross-file flows through imported functions.
Respond ONLY with JSON array."""

        response = await self.client.chat(TAINT_SYSTEM_PROMPT, prompt)
        if not response:
            return []

        return self._parse_response(response, str(file_path))

    def _build_context(self, file_path: Path, project_root: Path, content: str) -> str:
        """Include imported file contents for cross-file analysis."""
        context = f"=== {file_path.name} ===\n```\n{content}\n```\n"

        # Find local imports
        import_patterns = [
            r"from\s+['\"]\.\.?/([^'\"]+)['\"]",  # JS/TS relative imports
            r"require\(['\"]\.\.?/([^'\"]+)['\"]\)",
            r"from\s+\.(\w+)\s+import",  # Python relative imports
        ]

        imported_files = set()
        for pattern in import_patterns:
            for match in re.finditer(pattern, content):
                imported_files.add(match.group(1))

        # Resolve and include imported files
        for imp in list(imported_files)[:5]:  # Max 5 imported files
            # Try common extensions
            for ext in ["", ".ts", ".js", ".py"]:
                candidate = file_path.parent / f"{imp}{ext}"
                if candidate.exists():
                    try:
                        imp_content = candidate.read_text(encoding="utf-8", errors="ignore")
                        # Only include first 3000 chars per import
                        if len(imp_content) > 3000:
                            imp_content = imp_content[:3000] + "\n// truncated"
                        context += (
                            f"\n=== {candidate.name} (imported) ===\n```\n{imp_content}\n```\n"
                        )
                    except Exception:
                        pass
                    break

        return context

    def _parse_response(self, response: str, file_path: str) -> List[Finding]:
        """Parse LLM JSON response into Finding objects using robust extraction."""
        cleaned = response.strip()

        # Strip markdown fences
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
            return []

        findings = []
        for item in items:
            if not isinstance(item, dict):
                continue

            sev = Severity.CRITICAL if item.get("severity") == "CRITICAL" else Severity.HIGH

            findings.append(
                Finding(
                    severity=sev,
                    scanner="ai-taint-analysis",
                    title=f"AI: {item.get('title', 'Vulnerability')}",
                    description=item.get("explanation", ""),
                    file_path=file_path,
                    line_number=item.get("line", 0),
                    code_snippet="",
                    remediation="Validate and sanitize MCP tool parameters before dangerous operations.",
                    taint_source=item.get("source", ""),
                    taint_sink=item.get("sink", ""),
                    taint_flow=item.get("flow", ""),
                )
            )

        return findings
