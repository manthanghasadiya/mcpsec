import shutil
import sys

print(f"Platform: {sys.platform}")
resolved = shutil.which("npx")
print(f"shutil.which('npx'): {resolved}")

resolved_cmd = shutil.which("npx.cmd")
print(f"shutil.which('npx.cmd'): {resolved_cmd}")
