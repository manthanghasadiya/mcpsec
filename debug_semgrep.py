from pathlib import Path
import shutil
import sys
from mcpsec.static.semgrep_engine import run_semgrep

path = Path("temp_kanban")
print(f"Scanning {path.absolute()}")
semgrep_path = shutil.which("semgrep")
print(f"Semgrep path: {semgrep_path}")

if not semgrep_path:
    print("Semgrep not found!")
else:
    findings = run_semgrep(path)
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"- {f.title}: {f.file_path}")
