"""
Semgrep-powered static analysis engine.
Replaces regex-based taint analyzer with proper AST analysis.
"""
import subprocess
import json
import shutil
from pathlib import Path
from typing import List
from mcpsec.models import Finding, Severity

# Path to our custom MCP rules
RULES_DIR = Path(__file__).parent.parent / "rules"

SEVERITY_MAP = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,  
    "INFO": Severity.MEDIUM,
}

def run_semgrep(source_path: Path) -> List[Finding]:
    """Run Semgrep with MCP-specific rules against source code."""
    
    semgrep_cmd = shutil.which("semgrep")
    if not semgrep_cmd:
        # Semgrep not installed — fall back gracefully
        return []
    
    try:
        # Ensure rules directory exists
        if not RULES_DIR.exists():
            return []
            
        cmd = [
            semgrep_cmd,
            "--config", str(RULES_DIR),
            "--json",
            "--no-git-ignore",
            "--timeout", "30",
            "--max-target-bytes", "1000000",
            str(source_path),
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        
        if result.returncode not in (0, 1):  # 1 = findings found
            return []
        
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
            
        findings = []
        
        for r in data.get("results", []):
            extra = r.get("extra", {})
            metadata = extra.get("metadata", {})
            
            # Map Semgrep severity to our model
            semgrep_sev = extra.get("severity", "ERROR")
            severity = SEVERITY_MAP.get(semgrep_sev, Severity.MEDIUM)
            
            # Extract line content
            lines = extra.get("lines", "").strip()
            
            findings.append(Finding(
                severity=severity,
                scanner="semgrep-mcp",
                title=r.get("check_id", "Unknown").replace("mcpsec.rules.", ""),
                description=extra.get("message", ""),
                file_path=r.get("path", ""),
                line_number=r.get("start", {}).get("line", 0),
                code_snippet=lines,
                cwe=metadata.get("cwe", ""),
                confidence=metadata.get("confidence", "MEDIUM").lower(),
                remediation=f"Fix: {metadata.get('category', 'unknown')} vulnerability",
                detail=f"Rule ID: {r.get('check_id')}\nCategory: {metadata.get('category')}"
            ))
        
        return findings
        
    except (subprocess.TimeoutExpired, Exception):
        return []
