"""Generate protocol-level violations that test MCP spec compliance."""

import json
from .base import FuzzCase

def _frame(message: dict, framing: str = "clrf") -> bytes:
    body = json.dumps(message).encode("utf-8")
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body

def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases = []
    
    # 1. Wrong JSON-RPC version
    cases.append(FuzzCase(
        name="wrong_jsonrpc_version",
        generator="protocol_violation",
        payload=_frame({"jsonrpc": "1.0", "method": "tools/list", "id": 1}, framing),
        description="JSON-RPC version 1.0 instead of 2.0",
        expected_behavior="Server rejects with invalid request error (-32600)"
    ))
    
    # 2. Missing jsonrpc field
    cases.append(FuzzCase(
        name="missing_jsonrpc",
        generator="protocol_violation",
        payload=_frame({"method": "tools/list", "id": 1}, framing),
        description="Missing 'jsonrpc' field",
        expected_behavior="Server rejects with invalid request"
    ))
    
    # 3. Call tools/list BEFORE initialize
    cases.append(FuzzCase(
        name="tools_before_init",
        generator="protocol_violation",
        payload=_frame({"jsonrpc": "2.0", "method": "tools/list", "id": 1}, framing),
        description="Calling tools/list before initialize handshake",
        expected_behavior="Server rejects — must initialize first"
    ))
    
    # 4. Double initialize
    init_msg = {
        "jsonrpc": "2.0", "method": "initialize", "id": 1,
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "mcpsec-fuzzer", "version": "0.1.0"}
        }
    }
    cases.append(FuzzCase(
        name="double_initialize",
        generator="protocol_violation",
        payload=_frame(init_msg, framing),  # Second init
        description="Sending initialize twice",
        expected_behavior="Server rejects second initialize"
    ))
    
    # 5. Unknown method
    cases.append(FuzzCase(
        name="unknown_method",
        generator="protocol_violation",
        payload=_frame({"jsonrpc": "2.0", "method": "hacker/pwn", "id": 1}, framing),
        description="Calling non-existent method",
        expected_behavior="Server returns method not found (-32601)"
    ))
    
    # 6. tools/call with non-existent tool
    cases.append(FuzzCase(
        name="call_nonexistent_tool",
        generator="protocol_violation",
        payload=_frame({
            "jsonrpc": "2.0", "method": "tools/call", "id": 2,
            "params": {"name": "nonexistent_tool_12345", "arguments": {}}
        }, framing),
        description="Calling tool that doesn't exist",
        expected_behavior="Server returns tool not found error"
    ))
    
    # 7. Integer overflow in id
    cases.append(FuzzCase(
        name="id_integer_overflow",
        generator="protocol_violation",
        payload=_frame({"jsonrpc": "2.0", "method": "tools/list", "id": 99999999999999999999}, framing),
        description="Very large integer as request ID",
        expected_behavior="Server handles or rejects gracefully"
    ))
    
    # 8. Negative id
    cases.append(FuzzCase(
        name="negative_id",
        generator="protocol_violation",
        payload=_frame({"jsonrpc": "2.0", "method": "tools/list", "id": -1}, framing),
        description="Negative request ID",
        expected_behavior="Server handles or rejects"
    ))
    
    # 9. String id (valid per JSON-RPC but unusual)
    cases.append(FuzzCase(
        name="string_id",
        generator="protocol_violation",
        payload=_frame({"jsonrpc": "2.0", "method": "tools/list", "id": "test-string-id"}, framing),
        description="String request ID instead of integer",
        expected_behavior="Server accepts (valid per JSON-RPC 2.0)"
    ))
    
    # 10. Null id (notification — should not get response)
    # Notifications are tricky in fuzzer because we wait for response.
    # But for a notification, we effectively just timeout unless server sends something back (error?) or we use async read.
    # StdioFuzzer expects a response.
    # We might expect a TIMEOUT here as "correct behavior".
    cases.append(FuzzCase(
        name="null_id_notification",
        generator="protocol_violation",
        payload=_frame({"jsonrpc": "2.0", "method": "tools/list"}, framing),
        description="Request without id (notification style)",
        expected_behavior="Server does not respond (notification)"
    ))
    
    # 11. Empty params
    cases.append(FuzzCase(
        name="empty_params_on_call",
        generator="protocol_violation",
        payload=_frame({
            "jsonrpc": "2.0", "method": "tools/call", "id": 1,
            "params": {}
        }, framing),
        description="tools/call with empty params (missing name)",
        expected_behavior="Server returns invalid params (-32602)"
    ))
    
    # 12. Extra unexpected fields
    cases.append(FuzzCase(
        name="extra_fields",
        generator="protocol_violation",
        payload=_frame({
            "jsonrpc": "2.0", "method": "tools/list", "id": 1,
            "hacker": "was_here", "extra": {"nested": True}
        }, framing),
        description="Extra unknown fields in request",
        expected_behavior="Server ignores extra fields"
    ))
    
    return cases
