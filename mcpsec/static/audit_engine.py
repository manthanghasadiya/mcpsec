"""
Orchestrates the static analysis process.
"""

import asyncio
from pathlib import Path
from typing import List

from mcpsec.models import Finding
from mcpsec.static.source_fetcher import fetch_source, cleanup_temp
from mcpsec.static.js_analyzer import scan_js_file, JS_EXTENSIONS
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
    console.print("  Scanning files...")
    
    findings = []
    
    try:
        # Walk directory or single file
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
            
            # Phase 3.1: Exclude tests and build artifacts
            if _is_excluded(file_path):
                continue

            ext = file_path.suffix.lower()
            
            file_findings = []
            taint_findings = []

            # Phase 5: Scan for secrets (ALL file types)
            try:
                from mcpsec.scanners.secrets_exposure import scan_secrets
                file_findings.extend(scan_secrets(file_path))
            except Exception:
                pass

            # Scan JS/TS
            if ext in JS_EXTENSIONS:
                file_findings.extend(scan_js_file(file_path))
                try:
                    from mcpsec.static.taint_analyzer import scan_taint
                    taint_findings.extend(scan_taint(file_path))
                except Exception:
                    pass
            
            # Scan Python
            elif ext in PY_EXTENSIONS:
                file_findings.extend(scan_py_file(file_path))
                try:
                    from mcpsec.static.taint_analyzer import scan_taint
                    taint_findings.extend(scan_taint(file_path))
                except Exception:
                    pass

            # Deduplicate findings on same line
            if taint_findings:
                # 1. Deduplicate multiple taint findings on same line for same source
                seen_taint = set()
                dedup_taint = []
                for f in taint_findings:
                    # Keep only the first finding for a given (line, source)
                    key = (f.line_number, f.taint_source)
                    if key not in seen_taint:
                        dedup_taint.append(f)
                        seen_taint.add(key)
                taint_findings = dedup_taint

                # 2. Taint findings take precedence over regex findings, but keep secrets
                taint_lines = {f.line_number for f in taint_findings}
                file_findings = [
                    f for f in file_findings 
                    if f.line_number not in taint_lines or f.scanner == "secrets-exposure"
                ]
                file_findings.extend(taint_findings)

            findings.extend(file_findings)

        # Phase 4.2: Cross-file taint analysis
        try:
            from mcpsec.static.taint_analyzer import scan_taint_cross_file
            cross_file_findings = scan_taint_cross_file(root)
            if cross_file_findings:
                # Deduplicate against existing findings on same lines
                existing_lines = {(f.file_path, f.line_number) for f in findings}
                for cf in cross_file_findings:
                    if (cf.file_path, cf.line_number) not in existing_lines:
                        findings.append(cf)
        except Exception:
            # Don't crash if cross-file analysis fails
            pass

    except Exception as e:
        console.print(f"  [danger]Error during scan: {e}[/danger]")
    finally:
        # Cleanup if it was a temp download
        # If user provided --path, do NOT cleanup
        if npm or github:
            cleanup_temp(source_path)

    # Filter out known false positives
    findings = _filter_false_positives(findings)

    # Sort findings by severity
    findings.sort(key=lambda x: _severity_rank(x.severity), reverse=True)
    
    return findings, source_path

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
