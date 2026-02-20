"""
Legacy Taint Analyzer (simplified).
Kept only as a fallback or for specific Python logic that Semgrep might miss.
"""
from pathlib import Path
from typing import List
from mcpsec.models import Finding

class TaintAnalyzer:
    def scan_file(self, file_path: Path) -> List[Finding]:
        return []

def scan_taint(file_path: Path) -> List[Finding]:
    return []

def scan_taint_cross_file(source_dir: Path) -> List[Finding]:
    return []
