import subprocess
import time
import sys
import threading

def run_test():
    print("Starting server...")
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
    
    print("Sleeping 2 seconds...")
    time.sleep(2.0)
    
    print("Sending initialize...")
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
    import json
    payload = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(payload)}\r\n\r\n".encode("utf-8")
    
    proc.stdin.write(header + payload)
    proc.stdin.flush()
    
    print("Reading response...")
    # Read header
    header_data = b""
    while b"\r\n\r\n" not in header_data:
        chunk = proc.stdout.read(1)
        if not chunk:
            print("EOF reading header")
            break
        header_data += chunk
        
    print(f"Header: {header_data.decode()}")
    
    # Check length
    length = 0
    for line in header_data.decode().splitlines():
        if line.lower().startswith("content-length:"):
            length = int(line.split(":")[1])
            
    if length > 0:
        body = proc.stdout.read(length)
        print(f"Body: {body.decode()}")
        
    proc.terminate()

if __name__ == "__main__":
    run_test()
