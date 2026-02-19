"""
Static analyzer for JavaScript/TypeScript files.
"""

from pathlib import Path
from typing import List

from mcpsec.models import Finding, Severity
from mcpsec.static.patterns import JS_PATTERNS, COMMON_PATTERNS

# File extensions to scan
JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}

def scan_js_file(file_path: Path) -> List[Finding]:
    """
    Scan a single JS/TS file for dangerous patterns.
    """
    findings = []
    
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        # If we can't read it, skip it
        return []

    lines = content.splitlines()

    # Combine all patterns relevant for JS
    all_patterns = JS_PATTERNS + COMMON_PATTERNS

    for pattern in all_patterns:
        # Regex search on the whole content is often faster and allows multiline matching
        # However, for reporting, we need line numbers.
        # Simple approach: Iterate lines for simple patterns, or use finditer on content.
        
        # Using finditer on content to support multiline regexes if needed
        for match in pattern.regex.finditer(content):
            start_index = match.start()
            
            # simple line number calculation
            line_number = content.count("\n", 0, start_index) + 1
            matched_text = match.group(0)
            
            # Extract snippet (a few lines of context)
            snippet_lines = _get_context(lines, line_number - 1)
            snippet = "\n".join(snippet_lines)

            findings.append(Finding(
                severity=Severity(pattern.severity),
                scanner="static-analysis-js",
                title=pattern.name,
                description=pattern.description,
                detail=f"Matched pattern in {file_path.name}:{line_number}\n\nMatch: {matched_text[:100]}...",
                evidence=matched_text,
                remediation=pattern.remediation,
                cwe=pattern.cwe,
                file_path=str(file_path),
                line_number=line_number,
                code_snippet=snippet
            ))

    return findings

def _get_context(lines: List[str], line_idx: int, context: int = 2) -> List[str]:
    """Get lines around a specific index."""
    start = max(0, line_idx - context)
    end = min(len(lines), line_idx + context + 1)
    return lines[start:end]
