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
) -> List[Finding]:
    """
    Run the static audit.
    """
    
    # 1. Fetch Source
    source_path = await fetch_source(npm, github, path)
    if not source_path:
        return []
    
    console.print(f"  [success]Source code available at: {source_path}[/success]")
    console.print("  Scanning files...")
    
    findings = []
    
    try:
        # Walk directory
        root = Path(source_path)
        for file_path in root.rglob("*"):
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

            # Deduplicate: Taint findings take precedence over regex findings on same line
            if taint_findings:
                taint_lines = {f.line_number for f in taint_findings}
                file_findings = [f for f in file_findings if f.line_number not in taint_lines]
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

    # Filter out known false positives (e.g. RegExp.exec flagged by regex scanner)
    findings = _filter_false_positives(findings)

    # Sort findings by severity
    findings.sort(key=lambda x: _severity_rank(x.severity), reverse=True)
    
    return findings

def _filter_false_positives(findings: List[Finding]) -> List[Finding]:
    """Filter out known false positives from regex scanner."""
    import re
    filtered = []
    for f in findings:
        # Regex scanner flags RegExp.exec() as Command Injection
        if f.title == "Command Injection (Variable Argument)" and f.code_snippet:
             # Check for variable.exec( - likely RegExp
             if re.search(r"\w+\.exec\s*\(", f.code_snippet):
                 continue
        filtered.append(f)
    return filtered

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
