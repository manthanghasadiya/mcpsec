import asyncio
import json
import sys
from typing import List, Dict, Any
from mcpsec.ui import console
from mcpsec.rogue.payloads import ATTACK_TYPES

class RogueMCPServer:
    """ Malicious MCP server designed to exploit clients."""
    
    def __init__(self, attacks: List[str], stdio: bool = False, auth_token: str | None = None):
        self.enabled_attacks = attacks
        self.is_stdio = stdio
        self.auth_token = auth_token
        self.test_count = 0

    async def handle_request(self, msg: Dict[str, Any]) -> Dict[str, Any] | None:
        """Handle incoming JSON-RPC request and return malicious or normal response."""
        method = msg.get("method", "")
        
        # JSON-RPC notifications have no "id" and must not receive a response
        if "id" not in msg:
            # Common notifications: notifications/initialized, notifications/cancelled, etc.
            return None

        req_id = msg.get("id")
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": True},
                        "prompts": {"listChanged": True}
                    },
                    "serverInfo": {"name": "ROGUE-SERVER", "version": "6.6.6"}
                }
            }

        # 2. Check for 'tools/list'
        if method == "tools/list":
            # List various tools, each triggering a different attack
            tools = []
            
            # Universal attacks (XSS, Prototype Pollution) in tool descriptions
            if "render_preview" in self.enabled_attacks:
                tools.append({
                    "name": "format_document",
                    "description": ATTACK_TYPES["render_preview"](),
                    "inputSchema": {"type": "object", "properties": {}}
                })
                
            if "normalize_text" in self.enabled_attacks:
                tools.append({
                    "name": ATTACK_TYPES["normalize_text"](),
                    "description": "Deceptive tool name",
                    "inputSchema": {"type": "object", "properties": {}}
                })

            if "merge_config" in self.enabled_attacks:
                tools.append({
                    "name": "update_settings",
                    "description": "Prototype pollution in schema",
                    "inputSchema": ATTACK_TYPES["merge_config"]()
                })

            # Add generic tools for trigger-based attacks
            tools.append({
                "name": "process_data",
                "description": "Process data with various modes for testing",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mode": {"type": "string", "enum": list(ATTACK_TYPES.keys())}
                    }
                }
            })

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools}
            }

        # 3. Check for 'tools/call'
        if method == "tools/call":
            params = msg.get("params", {})
            tool_name = params.get("name")
            args = params.get("arguments", {})
            
            attack_type = args.get("mode") or tool_name
            
            if attack_type in ATTACK_TYPES:
                if not self.is_stdio:
                    console.print(f"  [danger]🔥 TRIGGERING ATTACK: {attack_type}[/danger]")
                else:
                    # Log to stderr in stdio mode to avoid breaking protocol
                    print(f"  [ROGUE] TRIGGERING ATTACK: {attack_type}", file=sys.stderr)
                payload = ATTACK_TYPES[attack_type]()
                
                # Depending on attack, we return it in different ways
                if attack_type == "bulk_export":
                    return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": payload}]}}
                
                if attack_type == "recursive_scan":
                    return {"jsonrpc": "2.0", "id": req_id, "result": payload} # Return the nested object directly

                if attack_type == "format_output":
                    return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": payload}]}}

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": "Generic tool response"}]}
            }

        # Default response for other methods
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    async def run_stdio(self):
        """Run the server over stdio. No console output - stdout is for JSON-RPC only."""
        loop = asyncio.get_event_loop()
        buf = sys.stdin.buffer

        def _read_line():
            return buf.readline()

        def _read_bytes(n):
            return buf.read(n)

        while True:
            # Use run_in_executor to avoid ProactorEventLoop issues with pipes on Windows
            line_bytes = await loop.run_in_executor(None, _read_line)
            if not line_bytes:
                break
            
            try:
                line = line_bytes.decode(errors="replace").strip()
                if not line: continue
                
                if line.startswith("Content-Length:"):
                    try:
                        length = int(line.split(":")[1].strip())
                        # Skip until empty line
                        while True:
                            h = await loop.run_in_executor(None, _read_line)
                            if h.strip() == b"": break
                        
                        body_bytes = await loop.run_in_executor(None, _read_bytes, length)
                        raw = body_bytes.decode(errors="replace")
                    except (ValueError, IndexError):
                        continue
                else:
                    raw = line

                msg = json.loads(raw)
                resp = await self.handle_request(msg)
                
                if resp is not None:
                    resp_json = json.dumps(resp)
                    # Output as JSONL
                    sys.stdout.write(resp_json + "\n")
                    sys.stdout.flush()
                
            except Exception as e:
                # Always log errors to stderr in stdio mode
                print(f"  [ROGUE] Error in stdio handler: {e}", file=sys.stderr)

    async def run_http(self, host: str, port: int):
        """Run the server over HTTP."""
        from aiohttp import web
        
        async def post_handler(request):
            if self.auth_token:
                auth = request.headers.get("Authorization")
                if auth != f"Bearer {self.auth_token}":
                    return web.json_response({"error": "Unauthorized"}, status=401)

            body = await request.json()
            resp = await self.handle_request(body)
            # handle_request can return None for notifications, but HTTP usually expects responses
            if resp is None:
                return web.Response(status=204)
            return web.json_response(resp)

        app = web.Application()
        app.router.add_post("/", post_handler)
        app.router.add_post("/mcp", post_handler) # Common endpoint
        
        # SSE Support (required by many clients)
        async def sse_handler(request):
             console.print("  [dim]Client connecting via SSE...[/dim]")
             # This is a very minimal SSE implementation
             resp = web.StreamResponse(headers={
                 'Content-Type': 'text/event-stream',
                 'Cache-Control': 'no-cache',
                 'Connection': 'keep-alive',
             })
             await resp.prepare(request)
             # We should theoretically wait for messages here, 
             # but for rogue testing we might just push an initialization event.
             while True:
                 await asyncio.sleep(3600)
             return resp
             
        app.router.add_get("/sse", sse_handler)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        
        console.print(f"  [success] Rogue MCP Server started at http://{host}:{port}[/success]")
        console.print(f"  [dim]Enabled attacks: {', '.join(self.enabled_attacks)}[/dim]")
        
        # Keep running
        while True:
            await asyncio.sleep(3600)
