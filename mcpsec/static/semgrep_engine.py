"""
Semgrep-powered static analysis engine.
Replaces regex-based taint analyzer with proper AST analysis.
"""
import subprocess
import json
import shutil
from pathlib import Path
from typing import List, Tuple
from mcpsec.models import Finding, Severity

# Path to our custom MCP rules
RULES_DIR = Path(__file__).parent.parent / "rules"

SEVERITY_MAP = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,  
    "INFO": Severity.MEDIUM,
}

# ============================================================
# EXCLUSION PATTERNS — Filter false positives from results
# ============================================================

# Directories that contain test/demo/build code (not production MCP servers)
EXCLUDED_DIRS = {
    # Test directories
    "tests", "__tests__", "test", "testing", "spec", "__mocks__",
    # Build/output directories  
    "build", "dist", "out", "coverage", ".nyc_output",
    # CI/CD and scripts
    "scripts", "ci", ".github", ".gitlab",
    # Documentation
    "docs", "doc", "documentation",
    # Demo/example code
    "examples", "example", "demo", "demos", "samples", "sample",
    # Dependencies (should already be excluded but belt-and-suspenders)
    "node_modules", "vendor", ".venv", "venv", "__pycache__",
}

# File patterns that indicate test/spec files
EXCLUDED_FILE_PATTERNS = (
    ".test.", ".spec.", "_test.", "_spec.",
    ".test-", ".spec-", "_test-", "_spec-",
    "test_", "spec_",
)

# Specific folders in the official MCP servers repo that are demo code
EXCLUDED_SPECIAL_PATHS = {
    "everything",  # The "everything" demo server in modelcontextprotocol/servers
}


def _should_exclude_path(file_path: str) -> bool:
    """
    Check if a file path should be excluded from results.
    
    Returns True for:
    - Test files (*.test.ts, *.spec.ts, test_*.py, etc.)
    - Files in test/demo/script directories
    - Build output and dependencies
    """
    # Normalize path separators
    path_lower = file_path.lower().replace("\\", "/")
    parts = path_lower.split("/")
    
    # 1. Check directory exclusions
    for part in parts:
        if part in EXCLUDED_DIRS:
            return True
        if part in EXCLUDED_SPECIAL_PATHS:
            return True
    
    # 2. Check file pattern exclusions
    filename = parts[-1] if parts else ""
    for pattern in EXCLUDED_FILE_PATTERNS:
        if pattern in filename:
            return True
    
    # 3. Exclude type definition files (no runtime code)
    if filename.endswith(".d.ts"):
        return True
    
    # 4. Exclude config files
    config_patterns = (
        "vite.config.", "webpack.config.", "rollup.config.",
        "jest.config.", "tsconfig.", "babel.config.",
        "eslint", "prettier", ".eslintrc", ".prettierrc",
    )
    for pattern in config_patterns:
        if pattern in filename:
            return True
    
    return False


def _categorize_finding(file_path: str) -> str:
    """
    Categorize a finding by its source type.
    Returns: 'production', 'test', 'demo', 'script', 'config'
    """
    path_lower = file_path.lower().replace("\\", "/")
    parts = path_lower.split("/")
    
    # Test files
    test_indicators = {"tests", "__tests__", "test", "spec", "__mocks__"}
    if any(p in test_indicators for p in parts):
        return "test"
    
    filename = parts[-1] if parts else ""
    if any(p in filename for p in EXCLUDED_FILE_PATTERNS):
        return "test"
    
    # Demo/example code
    demo_indicators = {"examples", "example", "demo", "demos", "samples", "everything"}
    if any(p in demo_indicators for p in parts):
        return "demo"
    
    # Scripts
    if "scripts" in parts or "ci" in parts:
        return "script"
    
    # Config
    if any(p in filename for p in ("config.", ".config.", "rc.", ".rc")):
        return "config"
    
    return "production"


def run_semgrep(source_path: Path, include_tests: bool = False) -> List[Finding]:
    """
    Run Semgrep with MCP-specific rules against source code.
    
    Args:
        source_path: Path to source code directory
        include_tests: If True, include findings from test files (default: False)
    
    Returns:
        List of Finding objects
    """
    
    semgrep_cmd = shutil.which("semgrep")
    if not semgrep_cmd:
        # Semgrep not installed — fall back gracefully
        return []
    
    try:
        # Ensure rules directory exists
        if not RULES_DIR.exists():
            return []
        
        # Build Semgrep command with exclusions
        cmd = [
            semgrep_cmd,
            "--config", str(RULES_DIR),
            "--json",
            "--no-git-ignore",
            "--timeout", "30",
            "--max-target-bytes", "1000000",
        ]
        
        # Add directory exclusions to Semgrep command
        # This is more efficient than post-filtering
        for excluded_dir in EXCLUDED_DIRS:
            cmd.extend(["--exclude", f"**/{excluded_dir}/**"])
        
        # Add file pattern exclusions
        cmd.extend([
            "--exclude", "**/*.test.*",
            "--exclude", "**/*.spec.*",
            "--exclude", "**/*_test.*",
            "--exclude", "**/*_spec.*",
            "--exclude", "**/test_*",
            "--exclude", "**/*.d.ts",
        ])
        
        cmd.append(str(source_path))
        
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
        excluded_count = 0
        
        for r in data.get("results", []):
            file_path = r.get("path", "")
            
            # Post-filter: double-check exclusions (belt-and-suspenders)
            # Semgrep's --exclude might miss some patterns
            if not include_tests and _should_exclude_path(file_path):
                excluded_count += 1
                continue
            
            extra = r.get("extra", {})
            metadata = extra.get("metadata", {})
            
            # Map Semgrep severity to our model
            semgrep_sev = extra.get("severity", "ERROR")
            severity = SEVERITY_MAP.get(semgrep_sev, Severity.MEDIUM)
            
            # Extract line content
            lines = extra.get("lines", "").strip()
            
            # Get the rule ID and clean it up
            rule_id = r.get("check_id", "Unknown")
            # Remove common prefixes for cleaner display
            for prefix in ("mcpsec.rules.", "Documents.Code.Projects.mcpsec."):
                if rule_id.startswith(prefix):
                    rule_id = rule_id[len(prefix):]
            
            findings.append(Finding(
                severity=severity,
                scanner="semgrep-mcp",
                title=rule_id,
                description=extra.get("message", ""),
                file_path=file_path,
                line_number=r.get("start", {}).get("line", 0),
                code_snippet=lines,
                cwe=str(metadata.get("cwe") or ""),
                confidence=str(metadata.get("confidence") or "MEDIUM").lower(),
                remediation=f"Fix: {metadata.get('category') or 'unknown'} vulnerability",
                detail=f"Rule ID: {r.get('check_id')}\nCategory: {metadata.get('category')}"
            ))
        
        # Log excluded count for debugging
        if excluded_count > 0:
            # This will be visible in debug mode
            import logging
            logging.debug(f"Excluded {excluded_count} findings from test/demo/script files")
        
        return findings
        
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


def run_semgrep_with_categories(source_path: Path) -> Tuple[List[Finding], dict]:
    """
    Run Semgrep and categorize findings by source type.
    
    Returns:
        Tuple of (production_findings, category_counts)
        category_counts = {'test': N, 'demo': N, 'script': N, 'config': N}
    """
    semgrep_cmd = shutil.which("semgrep")
    if not semgrep_cmd or not RULES_DIR.exists():
        return [], {}
    
    try:
        # Run WITHOUT exclusions to get full picture
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
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120,
        )
        
        if result.returncode not in (0, 1):
            return [], {}
        
        data = json.loads(result.stdout)
        
        production_findings = []
        category_counts = {"test": 0, "demo": 0, "script": 0, "config": 0}
        
        for r in data.get("results", []):
            file_path = r.get("path", "")
            category = _categorize_finding(file_path)
            
            if category != "production":
                category_counts[category] = category_counts.get(category, 0) + 1
                continue
            
            # Build Finding object (same as run_semgrep)
            extra = r.get("extra", {})
            metadata = extra.get("metadata", {})
            semgrep_sev = extra.get("severity", "ERROR")
            severity = SEVERITY_MAP.get(semgrep_sev, Severity.MEDIUM)
            
            rule_id = r.get("check_id", "Unknown")
            for prefix in ("mcpsec.rules.", "Documents.Code.Projects.mcpsec."):
                if rule_id.startswith(prefix):
                    rule_id = rule_id[len(prefix):]
            
            production_findings.append(Finding(
                severity=severity,
                scanner="semgrep-mcp",
                title=rule_id,
                description=extra.get("message", ""),
                file_path=file_path,
                line_number=r.get("start", {}).get("line", 0),
                code_snippet=extra.get("lines", "").strip(),
                cwe=str(metadata.get("cwe") or ""),
                confidence=str(metadata.get("confidence") or "MEDIUM").lower(),
                remediation=f"Fix: {metadata.get('category') or 'unknown'} vulnerability",
                detail=f"Rule ID: {r.get('check_id')}\nCategory: {metadata.get('category')}"
            ))
        
        return production_findings, category_counts
        
    except Exception:
        return [], {}
