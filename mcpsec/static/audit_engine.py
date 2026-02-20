"""
Orchestrates the static analysis process.
"""

import asyncio
from pathlib import Path
from typing import List

from mcpsec.models import Finding
from mcpsec.static.source_fetcher import fetch_source, cleanup_temp
# from mcpsec.static.js_analyzer import scan_js_file, JS_EXTENSIONS
JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
from mcpsec.static.py_analyzer import scan_py_file, PY_EXTENSIONS
from mcpsec.ui import console, print_section

async def run_audit(
    npm: str | None = None,
    github: str | None = None,
    path: str | None = None
) -> tuple[List[Finding], str | None]:
    """
    Run the static audit.
    """
    
    # 1. Fetch Source
    source_path = await fetch_source(npm, github, path)
    if not source_path:
        return [], None
    
    console.print(f"  [success]Source code available at: {source_path}[/success]")
    console.print("  Scanning files with Semgrep...")
    
    findings = []
    
    try:
        # Step 1: Semgrep analysis (AST-based taint tracking)
        from mcpsec.static.semgrep_engine import run_semgrep
        findings.extend(run_semgrep(Path(source_path)))
        
        # Step 2: Python AST checks (supplementary)
        # We keep py_analyzer as it has some specific python pattern matching
        # that complements Semgrep rules.
        root = Path(source_path)
        files = [root] if root.is_file() else root.rglob("*")
        
        for file_path in files:
            if not file_path.is_file():
                continue
            
            # Skip hidden/node_modules/venv
            if any(part.startswith(".") for part in file_path.parts) or \
               "node_modules" in file_path.parts or \
               "venv" in file_path.parts or \
               "__pycache__" in file_path.parts:
                continue
            
            if _is_excluded(file_path):
                continue
                
            # Scan Python ONLY (Semgrep handles JS/TS fully now)
            if file_path.suffix.lower() in PY_EXTENSIONS:
                try:
                    from mcpsec.static.py_analyzer import scan_py_file
                    findings.extend(scan_py_file(file_path))
                except Exception:
                    pass

        # Step 3: Apply "By Design" heuristics
        findings = _apply_design_heuristics(findings, Path(source_path))

    except Exception as e:
        console.print(f"  [danger]Error during scan: {e}[/danger]")
    finally:
        # Cleanup if it was a temp download
        # If user provided --path, do NOT cleanup
        if npm or github:
            cleanup_temp(source_path)

    # Sort findings by severity
    findings.sort(key=lambda x: _severity_rank(x.severity), reverse=True)
    
    return findings, source_path


def _apply_design_heuristics(findings: List[Finding], source_path: Path) -> List[Finding]:
    """Detect if project is a 'by design' shell tool and adjust severity."""
    is_shell_tool = False
    
    # Check package.json
    pkg_json = source_path / "package.json"
    if pkg_json.exists():
        try:
            content = pkg_json.read_text(encoding="utf-8", errors="ignore").lower()
            if any(kw in content for kw in ["command", "shell", "exec", "terminal", "desktop commander", "run command"]):
                is_shell_tool = True
        except Exception:
            pass
    
    # Check README
    if not is_shell_tool:
        for readme in ["README.md", "readme.md", "README.rst"]:
            readme_path = source_path / readme
            if readme_path.exists():
                try:
                    content = readme_path.read_text(encoding="utf-8", errors="ignore").lower()
                    if any(kw in content for kw in ["execute commands", "run shell", "command execution", "terminal access", "shell access", "run arbitrary"]):
                        is_shell_tool = True
                        break
                except Exception:
                    pass
    
    if is_shell_tool:
        for f in findings:
            if "command" in f.title.lower() or "exec" in f.title.lower():
                from mcpsec.models import Severity
                # Only downgrade if it's currently generic command injection
                # Don't downgrade definitive issues if we can distinguish them, 
                # but for now, widespread exec use in a shell tool is likely intended.
                f.severity = Severity.INFO
                f.description += (
                    "\n\nNote: This project appears to be designed for "
                    "command execution. This finding may be expected behavior."
                )
    
    return findings


def _is_excluded(path: Path) -> bool:
    """Check if file should be excluded from audit (tests, build dirs)."""
    name = path.name.lower()
    parts = [p.lower() for p in path.parts]
    
    # 1. Directory Exclusions
    excluded_dirs = {"tests", "__tests__", "test", "build", "dist", "out", "coverage"}
    if any(d in parts for d in excluded_dirs):
        return True
        
    # 2. File Pattern Exclusions
    if name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js", ".test.jsx", ".test.tsx")):
        return True
    
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
        
    return False


def _severity_rank(severity: str) -> int:
    ranks = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0
    }
    s = str(severity).lower()
    return ranks.get(s, 0)

def _filter_false_positives(findings: List[Finding]) -> List[Finding]:
    """Filter out known false positives."""
    import re
    filtered = []
    for f in findings:
        code = f.code_snippet or ""
        
        # 1. Generic assignment target check (for both regex and taint scanners)
        # Scan title or description for the variable name
        var_match = re.search(r"'(.*?)'", f.description)
        if var_match:
            var_name = var_match.group(1)
            if _is_assignment_target(var_name, code):
                continue

        # 2. RegExp.exec() false positive for regex scanner
        if f.title == "Command Injection (Variable Argument)":
             if re.search(r"\w+\.exec\s*\(", code):
                 continue
                 
        filtered.append(f)
    return filtered

def _is_assignment_target(var_name: str, line: str) -> bool:
    """Check if variable is being assigned FROM the sink (not flowing INTO it)."""
    import re
    patterns = [
        rf"(?:const|let|var)\s+{re.escape(var_name)}\s*=",
        rf"{re.escape(var_name)}\s*=\s*(?:await\s+)?(?:spawn|exec|execAsync|execSync|subprocess|os\.system|os\.popen)",
    ]
    return any(re.search(p, line) for p in patterns)

def _is_excluded(path: Path) -> bool:
    """Check if file should be excluded from audit (tests, build dirs)."""
    name = path.name.lower()
    parts = [p.lower() for p in path.parts]
    
    # 1. Directory Exclusions
    excluded_dirs = {"tests", "__tests__", "test", "build", "dist", "out", "coverage"}
    if any(d in parts for d in excluded_dirs):
        return True
        
    # 2. File Pattern Exclusions
    if name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js", ".test.jsx", ".test.tsx")):
        return True
    
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
        
    # 3. Exclude analyzer definition files (they contain the patterns!)
    if name in ("patterns.py", "py_analyzer.py", "taint_analyzer.py"):
        return True

    return False

def _severity_rank(severity: str) -> int:
    ranks = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0
    }
    # Handle both string and Enum if mixed
    s = str(severity).lower()
    return ranks.get(s, 0)
