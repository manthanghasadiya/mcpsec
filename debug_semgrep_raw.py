import subprocess
import shutil
from pathlib import Path

semgrep_cmd = shutil.which("semgrep")
RULES_DIR = Path("mcpsec/rules")
source_path = Path("temp_kanban")

print(f"Testing rules in {RULES_DIR}...")

for rule_file in RULES_DIR.glob("*.yml"):
    print(f"\nTesting {rule_file.name}...")
    cmd = [
        semgrep_cmd,
        "--config", str(rule_file),
        "--no-git-ignore",
        str(source_path),
    ]
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"FAILED (Code {result.returncode})")
        print(result.stderr[:500])  # Print first 500 chars of stderr
    else:
        print("OK")
