import json
import sys
import os

DEBUG_FILE = "server_mcp_debug.log"
if os.path.exists(DEBUG_FILE):
    os.remove(DEBUG_FILE)

def debug_log(msg):
    with open(DEBUG_FILE, "a") as f:
        f.write(f"{msg}\n")

def read_json():
    header = b""
    while True:
        line = sys.stdin.buffer.readline()
        if not line: 
            debug_log("[READ] No line received (EOF)")
            return None
        debug_log(f"[READ] Line: {repr(line)}")
        if line.strip() == b"": 
            debug_log("[READ] End of headers")
            break
        header += line
    
    # Try to find Content-Length
    cl = 0
    for h in header.decode().split("\n"):
        if h.lower().startswith("content-length:"):
            try:
                cl = int(h.split(":")[1].strip())
            except: pass
    
    if cl > 0:
        body = sys.stdin.buffer.read(cl)
        debug_log(f"[READ] Body ({cl} bytes): {repr(body)}")
        return json.loads(body)
    
    # Fallback: if header itself is JSON (no content-length)
    try:
        if header.strip().startswith(b"{"):
            return json.loads(header)
    except: pass
    
    return None

def write_json(obj):
    body = json.dumps(obj).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode()
    debug_log(f"[WRITE] {repr(header + body)}")
    sys.stdout.buffer.write(header)
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()

def main():
    debug_log("=== Server Started ===")
    
    # Basic MCP initialization
    req = read_json()
    if not req: 
        debug_log("FAILED: No initial request")
        return
    
    # Send initialize response
    write_json({
        "jsonrpc": "2.0",
        "id": req.get("id"),
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {"name": "stateful-test", "version": "1.0.0"}
        }
    })

    # Wait for initialized notification
    read_json()

    # State
    valid_refs = ["e21", "e35"]
    
    while True:
        req = read_json()
        if not req: 
            debug_log("Exiting: No more requests")
            break
        
        try:
            method = req.get("method")
            params = req.get("params", {})
            req_id = req.get("id")
            
            if method == "tools/list":
                write_json({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {
                                "name": "get_snapshot",
                                "description": "Returns a DOM snapshot with element refs.",
                                "inputSchema": {"type": "object", "properties": {}}
                            },
                            {
                                "name": "click_element",
                                "description": "Clicks an element by its ref ID.",
                                "inputSchema": {
                                    "type": "object", 
                                    "properties": {
                                        "ref": {"type": "string", "description": "Element reference from snapshot"},
                                        "label": {"type": "string", "description": "Button label"}
                                    },
                                    "required": ["ref"]
                                }
                            }
                        ]
                    }
                })
            
            elif method == "tools/call":
                tool_name = params.get("name")
                args = params.get("arguments", {})
                
                if tool_name == "get_snapshot":
                    write_json({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": "Found button: [Click Me] (ref=e21), [Submit] (ref=e35)"}]
                        }
                    })
                
                elif tool_name == "click_element":
                    ref = args.get("ref")
                    label = args.get("label", "")
                    
                    if ref not in valid_refs:
                        write_json({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32000, "message": f"Invalid ref: {ref}"}
                        })
                    else:
                        # VULNERABILITY: If label contains a command injection payload, "execute" it
                        if ";" in label or "|" in label or "`" in label:
                             write_json({
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [{"type": "text", "text": f"uid=0(root) gid=0(root) groups=0(root) Executing: {label}"}]
                                }
                            })
                        else:
                            write_json({
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": {
                                    "content": [{"type": "text", "text": f"Clicked element {ref}"}]
                                }
                            })
        except Exception as e:
            debug_log(f"ERROR: {str(e)}")
            break

if __name__ == "__main__":
    main()
