import sys
import time
import json

def run():
    # Simulate slow startup
    time.sleep(5)
    
    # Read initialize
    # Simple manual MCP server
    # Read headers
    content_length = 0
    while True:
        line = sys.stdin.readline()
        if not line:
            return
        if line.strip().lower().startswith("content-length:"):
            content_length = int(line.split(":")[1].strip())
        if line.strip() == "":
            break
            
    if content_length > 0:
        body = sys.stdin.read(content_length)
        # Parse?
        pass
        
    # Send response
    resp = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "slow_server", "version": "1.0"}
        }
    }
    msg = json.dumps(resp)
    
    sys.stdout.write(f"Content-Length: {len(msg)}\r\n\r\n{msg}")
    sys.stdout.flush()
    
    # Read initialized notification
    # ...

if __name__ == "__main__":
    run()
