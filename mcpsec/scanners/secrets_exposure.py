"""Scanner for secrets exposure in MCP server source code."""

import re
from pathlib import Path
from mcpsec.models import Finding, Severity

SCANNER_NAME = "secrets-exposure"

# Patterns for secrets in source code
SECRET_PATTERNS = [
    # Hardcoded secrets
    (r"""(?:api[_-]?key|apikey|secret|token|password|passwd|auth)\s*[:=]\s*['"][A-Za-z0-9+/=_\-]{16,}['"]""",
     "Hardcoded Secret", Severity.CRITICAL),
    
    # AWS keys
    (r"""AKIA[0-9A-Z]{16}""", "AWS Access Key", Severity.CRITICAL),
    
    # GitHub tokens  
    (r"""gh[ps]_[A-Za-z0-9_]{36,}""", "GitHub Token", Severity.CRITICAL),
    
    # process.env exposure (returning env vars to tool caller)
    (r"""(?:return|content|text|result).*process\.env""",
     "Environment Variable Exposure", Severity.HIGH),
    
    # Reading .env files
    (r"""(?:readFile|readFileSync|open)\s*\(.*\.env""",
     "Reading .env File", Severity.MEDIUM),
     
    # Private key patterns
    (r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----""",
     "Private Key in Source", Severity.CRITICAL),
]

def scan_secrets(file_path: Path) -> list:
    """Scan a source file for exposed secrets."""
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    
    lines = content.splitlines()
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip comments
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
            continue
            
        for pattern, label, severity in SECRET_PATTERNS:
            if re.search(pattern, stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity=severity,
                    scanner=SCANNER_NAME,
                    title=f"Secrets Exposure: {label}",
                    description=f"Potential secret or credential exposure detected.",
                    evidence=stripped[:200],
                    file_path=str(file_path),
                    line_number=i + 1,
                    remediation="Use environment variables and never expose secrets in tool responses.",
                ))
                break  # One finding per line
    
    return findings
