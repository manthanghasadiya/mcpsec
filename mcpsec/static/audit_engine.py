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
            
            # Scan JS/TS
            if ext in JS_EXTENSIONS:
                findings.extend(scan_js_file(file_path))
            
            # Scan Python
            elif ext in PY_EXTENSIONS:
                findings.extend(scan_py_file(file_path))

    except Exception as e:
        console.print(f"  [danger]Error during scan: {e}[/danger]")
    finally:
        # Cleanup if it was a temp download
        # If user provided --path, do NOT cleanup
        if npm or github:
            cleanup_temp(source_path)

    # Sort findings by severity
    findings.sort(key=lambda x: _severity_rank(x.severity), reverse=True)
    
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
        
    # 3. Exclude analyzer definition files (they contain the patterns!)
    if name in ("patterns.py", "py_analyzer.py"):
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
