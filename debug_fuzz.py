
import sys
import traceback
from mcpsec.fuzzer.fuzz_engine import FuzzEngine

try:
    print("Starting debug run...")
    engine = FuzzEngine("python tests/vuln_test_server.py", 0.5)
    print("Engine created.")
    summary = engine.run()
    print("Run complete.")
    print(summary)
except Exception:
    traceback.print_exc()
