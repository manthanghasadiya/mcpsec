"""Session/lifecycle attack payloads — test MCP protocol state machine."""

import json
from .base import FuzzCase

def _frame(body: bytes, framing: str = "clrf") -> bytes:
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases = []

    # 1. tools/call BEFORE initialize
    cases.append(FuzzCase(
        name="pre_init_tool_call",
        generator="session_attacks",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "test", "arguments": {}}
        }).encode(), framing),
        description="Send tools/call before initialize",
        expected_behavior="Server rejects with error or returns initRequired",
    ))

    # 2. Wrong protocol version
    cases.append(FuzzCase(
        name="wrong_protocol_version",
        generator="session_attacks",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "9999.0.0",
                "capabilities": {},
                "clientInfo": {"name": "fuzz", "version": "1.0"},
            },
        }).encode(), framing),
        description="Initialize with unsupported protocolVersion",
        expected_behavior="Server rejects or negotiates down",
    ))

    # 3. Empty clientInfo
    cases.append(FuzzCase(
        name="empty_client_info",
        generator="session_attacks",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {},
            },
        }).encode(), framing),
        description="Initialize with empty clientInfo (missing name/version)",
        expected_behavior="Server rejects or handles gracefully",
    ))

    # 4. Null capabilities
    cases.append(FuzzCase(
        name="null_capabilities",
        generator="session_attacks",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": None,
                "clientInfo": {"name": "fuzz", "version": "1.0"},
            },
        }).encode(), framing),
        description="Initialize with null capabilities",
        expected_behavior="Server handles gracefully",
    ))

    # 5. Double initialized notification
    init_notify = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
    cases.append(FuzzCase(
        name="double_initialized",
        generator="session_attacks",
        payload=_frame(init_notify, framing) + _frame(init_notify, framing),
        description="Send initialized notification twice",
        expected_behavior="Server ignores duplicate or handles gracefully",
    ))

    # 6. Monotonically decreasing IDs
    payloads = b""
    for req_id in [10, 9, 8, 7, 6]:
        payloads += _frame(json.dumps({
            "jsonrpc": "2.0", "id": req_id,
            "method": "tools/list",
        }).encode(), framing)
    cases.append(FuzzCase(
        name="decreasing_ids",
        generator="session_attacks",
        payload=payloads,
        description="Send requests with monotonically decreasing IDs",
        expected_behavior="Server processes all regardless of ID order",
    ))

    # 7. Duplicate request ID
    dup = json.dumps({"jsonrpc": "2.0", "id": 42, "method": "tools/list"}).encode()
    cases.append(FuzzCase(
        name="duplicate_request_id",
        generator="session_attacks",
        payload=_frame(dup, framing) + _frame(dup, framing),
        description="Send two requests with same ID",
        expected_behavior="Server rejects duplicate or responds to both",
    ))

    # 8. Rapid initialize flood (resource exhaustion)
    flood = b""
    for i in range(50):
        flood += _frame(json.dumps({
            "jsonrpc": "2.0", "id": i + 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "flood", "version": "1.0"},
            },
        }).encode(), framing)
    cases.append(FuzzCase(
        name="rapid_init_flood",
        generator="session_attacks",
        payload=flood,
        description="Send 50 rapid initialize requests",
        expected_behavior="Server handles without crash or resource leak",
    ))

    # 9. Notification with ID field (protocol violation)
    cases.append(FuzzCase(
        name="notification_with_id",
        generator="session_attacks",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0",
            "id": 999,  # Notifications MUST NOT have id
            "method": "notifications/initialized",
        }).encode(), framing),
        description="Notification with id field (protocol violation)",
        expected_behavior="Server rejects or ignores the id field",
    ))

    # 10. Response object instead of request
    cases.append(FuzzCase(
        name="send_response_object",
        generator="session_attacks",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []},
        }).encode(), framing),
        description="Send a response object instead of a request",
        expected_behavior="Server ignores or returns error",
    ))

    # 11. Batch JSON-RPC array (not in MCP spec)
    cases.append(FuzzCase(
        name="batch_jsonrpc_array",
        generator="session_attacks",
        payload=_frame(json.dumps([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "resources/list"},
        ]).encode(), framing),
        description="Send batch JSON-RPC array (not in MCP spec)",
        expected_behavior="Server rejects batch or processes individually",
    ))

    # 12. Interleaved valid and invalid messages
    inter = b""
    inter += _frame(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode(), framing)
    inter += _frame(b"GARBAGE NOT JSON", framing)
    inter += _frame(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).encode(), framing)
    cases.append(FuzzCase(
        name="interleaved_valid_invalid",
        generator="session_attacks",
        payload=inter,
        description="Interleave valid and invalid messages",
        expected_behavior="Server recovers and processes valid messages after invalid",
    ))

    # 13. Request with huge progressToken in _meta
    cases.append(FuzzCase(
        name="huge_progress_token",
        generator="session_attacks",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/list",
            "params": {"_meta": {"progressToken": "A" * 100000}},
        }).encode(), framing),
        description="Request with 100KB progressToken in _meta",
        expected_behavior="Server handles without crash",
    ))

    # 14. Method with extra path segments
    cases.append(FuzzCase(
        name="extra_path_segments",
        generator="session_attacks",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call/../../etc/passwd",
        }).encode(), framing),
        description="Method with path traversal segments",
        expected_behavior="Server rejects unknown method",
    ))

    # 15. Initialize with extra unknown fields 
    cases.append(FuzzCase(
        name="extra_init_fields",
        generator="session_attacks",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "fuzz", "version": "1.0"},
                "__proto__": {"admin": True},
                "constructor": {"prototype": {"isAdmin": True}},
            },
        }).encode(), framing),
        description="Initialize with prototype pollution fields",
        expected_behavior="Server ignores unknown fields",
    ))

    return cases
