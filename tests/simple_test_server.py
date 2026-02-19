import sys
import json
import logging

# Configure logging to stderr
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
log = logging.getLogger("simple_server")

def main():
    log.info("Simple MCP Server starting...")
    if sys.platform == "win32":
        import msvcrt
        import os
        # Ensure binary mode for stdin/stdout on Windows
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    
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
                # Read empty line
                stdin.readline()
                # Read body
                body = stdin.read(length)
                log.info(f"Received: {body}")
                
                try:
                    request = json.loads(body)
                except json.JSONDecodeError:
                    log.error("Invalid JSON")
                    continue
                
                # Handle initialize
                if request.get("method") == "initialize":
                     response = {
                         "jsonrpc": "2.0",
                         "id": request.get("id"),
                         "result": {
                             "protocolVersion": "2024-11-05",
                             "capabilities": {},
                             "serverInfo": {"name": "simple-server", "version": "1.0"}
                         }
                     }
                     send_response(stdout, response)
                     log.info("Sent initialize response")
                
                elif request.get("method") == "ping":
                     response = {"jsonrpc": "2.0", "id": request.get("id"), "result": {}}
                     send_response(stdout, response)
                
                else:
                     # Echo or error
                     pass
                     
        except Exception as e:
            log.error(f"Error: {e}")
            break

def send_response(stdout, msg):
    data = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(data)}\r\n\r\n".encode("ascii")
    stdout.write(header + data)
    stdout.flush()

if __name__ == "__main__":
    main()
