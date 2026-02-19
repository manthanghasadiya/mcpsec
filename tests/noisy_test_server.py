import sys
import json
import logging
import time

# Configure logging to stderr
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
log = logging.getLogger("noisy_server")

def main():
    if sys.platform == "win32":
        import msvcrt
        import os
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    
    # POLLUTION: Write some garbage to stdout that doesn't end with \r\n
    stdout.write(b"Installing dependencies...\n")
    stdout.write(b"Still loading...\n")
    stdout.flush()
    # time.sleep(0.1) 

    while True:
        try:
            # Read header
            line = stdin.readline()
            if not line:
                break
            
            line = line.strip()
            if not line:
                continue
                
            if line.startswith(b"Content-Length:"):
                length = int(line.split(b":")[1].strip())
                stdin.readline()
                body = stdin.read(length)
                
                request = json.loads(body)
                
                # Handle initialize
                if request.get("method") == "initialize":
                     response = {
                         "jsonrpc": "2.0",
                         "id": request.get("id"),
                         "result": {
                             "protocolVersion": "2024-11-05",
                             "capabilities": {},
                             "serverInfo": {"name": "noisy-server", "version": "1.0"}
                         }
                     }
                     send_response(stdout, response)
                else:
                     pass
                     
        except Exception as e:
            log.error(f"Error: {e}")
            break

def send_response(stdout, msg):
    data = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(data)}\r\n\r\n".encode("ascii")
    # Write header and body
    stdout.write(header + data)
    stdout.flush()

if __name__ == "__main__":
    main()
