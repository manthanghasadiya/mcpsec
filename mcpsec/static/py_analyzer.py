"""
Static analyzer for Python files using AST and regex.
"""

import ast
from pathlib import Path
from typing import List, Any

from mcpsec.models import Finding, Severity
from mcpsec.static.patterns import PY_PATTERNS, COMMON_PATTERNS

# File extensions
PY_EXTENSIONS = {".py", ".pyw"}

class DangerousCallVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def visit_Call(self, node: ast.Call):
        # Check for subprocess.run with shell=True
        if self._is_subprocess_shell(node):
            self.findings.append({
                "line": node.lineno,
                "msg": "subprocess call with shell=True",
                "severity": "critical",
                "cwe": "CWE-78",
                "remediation": "Set shell=False and pass args as list."
            })
        
        # Check for os.system
        elif self._is_call_to(node, "os", "system"):
            self.findings.append({
                "line": node.lineno,
                "msg": "os.system text execution",
                "severity": "critical",
                "cwe": "CWE-78",
                "remediation": "Use subprocess.run with shell=False."
            })

        # Check for os.popen
        elif self._is_call_to(node, "os", "popen"):
             self.findings.append({
                "line": node.lineno,
                "msg": "os.popen text execution",
                "severity": "critical",
                "cwe": "CWE-78",
                "remediation": "Use subprocess.run with shell=False."
            })

        # Check for eval/exec
        elif self._is_builtin(node, "eval") or self._is_builtin(node, "exec"):
             self.findings.append({
                "line": node.lineno,
                "msg": "Dynamic code execution (eval/exec)",
                "severity": "critical",
                "cwe": "CWE-95",
                "remediation": "Avoid dynamic execution of code."
            })
            
        self.generic_visit(node)

    def _is_subprocess_shell(self, node: ast.Call) -> bool:
        # Check if it's subprocess.<something>
        if not isinstance(node.func, ast.Attribute):
            return False
        
        # Check if value is a Name node (e.g. subprocess.run)
        if not isinstance(node.func.value, ast.Name):
            return False

        if node.func.value.id == 'subprocess':
            method = node.func.attr
            if method in ('run', 'call', 'Popen', 'check_output'):
                # Check keywords for shell=True
                for kw in node.keywords:
                    # kw.value must be a Constant (True/False)
                    if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        return True
        return False

    def _is_call_to(self, node: ast.Call, module: str, func: str) -> bool:
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == module:
                if node.func.attr == func:
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
            line_no = int(f["line"])  # Ensure line_no is int
            snippet = _get_context_str(lines, line_no - 1)
            findings.append(Finding(
                severity=Severity(str(f["severity"])), # Ensure string for Enum
                scanner="static-analysis-py-ast",
                title=str(f.get("title", f["msg"])),
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
        # Fallback to pure regex if AST parsing fails
        pass

    # 2. Regex Analysis (Fallback & Common Patterns)
    # Combine common patterns. AST covers specific function calls well, 
    # but regex catches SQLi in strings, open() calls, etc.
    
    # We filter out patterns that AST likely covered to avoid dupes?
    # Actually, let's run all relevant patterns. Deduplication logic is complex,
    # but for now we can just rely on regex for things AST visitor didn't explicitly look for 
    # OR run regex as a backup.
    
    # Let's run COMMON_PATTERNS (SQL, Path Traversal) via Regex
    # And specifically PY_PATTERNS which might catch things AST missed (like weird imports)
    
    all_patterns = PY_PATTERNS + COMMON_PATTERNS
    
    for pattern in all_patterns:
        # Optimization: Don't run regex for things clearly caught by AST if found?
        # No, simpler to run all regexes. Overlap is acceptable for MVP.
        
        for match in pattern.regex.finditer(content):
            start_index = match.start()
            line_number = content.count("\n", 0, start_index) + 1
            
            # De-duplicate with AST findings on the same line?
            # If we already have a finding on this line from AST, maybe skip "Command Injection" types?
            # But "SQL Injection" wouldn't be in AST findings.
            
            # Simple check: if we have an AST finding on this line, only add if it's a different category
            already_found = any(f.line_number == line_number for f in findings)
            
            # If it's a common pattern (SQL, Path) or if AST didn't find anything on this line
            # We add it.
            if not already_found or pattern in COMMON_PATTERNS:
                 matched_text = match.group(0)
                 snippet = _get_context_str(lines, line_number - 1)
                 
                 findings.append(Finding(
                    severity=Severity(pattern.severity),
                    scanner="static-analysis-py-regex",
                    title=pattern.name,
                    description=pattern.description,
                    detail=f"Regex matched pattern in {file_path.name}:{line_number}",
                    evidence=matched_text,
                    remediation=pattern.remediation,
                    cwe=pattern.cwe,
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=snippet
                ))

    return findings

def _get_context_str(lines: List[str], line_idx: int, context: int = 2) -> str:
    """Get lines around a specific index as a string."""
    start = max(0, line_idx - context)
    end = min(len(lines), line_idx + context + 1)
    return "\n".join(lines[start:end])
