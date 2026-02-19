import subprocess
import time
import sys
import threading
import json

def run_test():
    print("Starting server (newline test)...")
    cmd = [sys.executable, "-u", "tests/vuln_test_server.py"]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    def read_stderr():
        for line in proc.stderr:
            print(f"[stderr] {line.decode().strip()}")
            
    t = threading.Thread(target=read_stderr, daemon=True)
    t.start()
    
    msg = {
        "jsonrpc": "2.0", 
        "method": "initialize", 
        "id": 1, 
        "params": {
            "protocolVersion": "2024-11-05", 
            "capabilities": {}, 
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    }
    payload = json.dumps(msg).encode("utf-8")
    # TRY: Use \n instead of \r\n
    header = f"Content-Length: {len(payload)}\n\n".encode("utf-8")
    
    print("Writing to stdin immediately with \\n...")
    proc.stdin.write(header + payload)
    proc.stdin.flush()
    
    print("Reading response...")
    time.sleep(1) # wait a bit
    proc.terminate()

if __name__ == "__main__":
    run_test()
