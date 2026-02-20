"""
Static analyzer for Python files using AST and regex (Simplified fallback).
"""

import ast
import re
from pathlib import Path
from typing import List, Dict, Any

from mcpsec.models import Finding, Severity

# File extensions
PY_EXTENSIONS = {".py", ".pyw"}

class Pattern:
    def __init__(self, name, regex, description, severity, remediation, cwe):
        self.name = name
        self.regex = re.compile(regex, re.MULTILINE)
        self.description = description
        self.severity = severity
        self.remediation = remediation
        self.cwe = cwe

# Minimal fallback patterns (mostly covered by Semgrep now)
FALLBACK_PATTERNS = [
    Pattern(
        "Hardcoded API Key",
        r"(?i)(api_key|access_token|secret_key|private_key)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]",
        "Hardcoded API key detected.",
        Severity.CRITICAL,
        "Use environment variables.",
        "CWE-798"
    ),
    Pattern(
        "Unsafe Deserialization",
        r"pickle\.(?:load|loads)\(",
        "Unsafe deserialization detected.",
        Severity.CRITICAL,
        "Avoid pickle on untrusted data.",
        "CWE-502"
    )
]

class DangerousCallVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def visit_Call(self, node: ast.Call):
        # Check for subprocess.run with shell=True
        if self._is_subprocess_shell(node):
            self.findings.append({
                "line": node.lineno,
                "msg": "subprocess call with shell=True",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-78",
                "remediation": "Set shell=False and pass args as list."
            })
        
        # Check for eval/exec
        elif self._is_builtin(node, "eval") or self._is_builtin(node, "exec"):
             self.findings.append({
                "line": node.lineno,
                "msg": "Dynamic code execution (eval/exec)",
                "severity": Severity.CRITICAL,
                "cwe": "CWE-95",
                "remediation": "Avoid dynamic execution of code."
            })
            
        self.generic_visit(node)

    def _is_subprocess_shell(self, node: ast.Call) -> bool:
        if not isinstance(node.func, ast.Attribute):
            return False
        if not isinstance(node.func.value, ast.Name):
            return False

        if node.func.value.id == 'subprocess':
            method = node.func.attr
            if method in ('run', 'call', 'Popen', 'check_output'):
                for kw in node.keywords:
                    # kw.value must be a Constant (True/False)
                    if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        return True
        return False

    def _is_builtin(self, node: ast.Call, func: str) -> bool:
        if isinstance(node.func, ast.Name) and node.func.id == func:
            return True
        return False


def scan_py_file(file_path: Path) -> List[Finding]:
    """
    Scan a single Python file for dangerous patterns using AST and regex.
    """
    findings = []
    
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    
    lines = content.splitlines()

    # 1. AST Analysis
    try:
        tree = ast.parse(content, filename=str(file_path))
        visitor = DangerousCallVisitor()
        visitor.visit(tree)
        
        for f in visitor.findings:
            line_no = int(f["line"])
            snippet = _get_context(lines, line_no - 1)
            findings.append(Finding(
                severity=f["severity"],
                scanner="static-analysis-py-ast",
                title=str(f.get("msg")),
                description=str(f["msg"]),
                detail=f"AST Analysis found dangerous pattern in {file_path.name}:{line_no}",
                evidence=lines[line_no-1].strip() if 0 <= line_no-1 < len(lines) else "",
                remediation=str(f["remediation"]),
                cwe=str(f["cwe"]),
                file_path=str(file_path),
                line_number=line_no,
                code_snippet=snippet
            ))

    except SyntaxError:
        pass

    # 2. Regex Fallback
    for pattern in FALLBACK_PATTERNS:
        for match in pattern.regex.finditer(content):
            start_index = match.start()
            line_number = content.count("\n", 0, start_index) + 1
            
            # Simple dedup: if AST found finding on matching line
            if any(f.line_number == line_number for f in findings):
                continue

            snippet = _get_context(lines, line_number - 1)
            findings.append(Finding(
                severity=pattern.severity,
                scanner="static-analysis-py-regex",
                title=pattern.name,
                description=pattern.description,
                detail=f"Regex matched pattern in {file_path.name}:{line_number}",
                evidence=match.group(0),
                remediation=pattern.remediation,
                cwe=pattern.cwe,
                file_path=str(file_path),
                line_number=line_number,
                code_snippet=snippet
            ))

    return findings

def _get_context(lines: List[str], line_idx: int, context: int = 2) -> str:
    start = max(0, line_idx - context)
    end = min(len(lines), line_idx + context + 1)
    return "\n".join(lines[start:end])
