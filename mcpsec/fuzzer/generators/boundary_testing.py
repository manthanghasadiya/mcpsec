"""Test boundary conditions — oversized payloads, empty fields, limits."""

import json
from .base import FuzzCase

def _frame(message: dict) -> bytes:
    body = json.dumps(message).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body

def generate() -> list[FuzzCase]:
    cases = []
    
    # 1. Empty method string
    cases.append(FuzzCase(
        name="empty_method",
        generator="boundary",
        payload=_frame({"jsonrpc": "2.0", "method": "", "id": 1}),
        description="Empty string as method name",
        expected_behavior="Server returns method not found"
    ))
    
    # 2. Very long method name (64KB)
    cases.append(FuzzCase(
        name="long_method_64k",
        generator="boundary",
        payload=_frame({"jsonrpc": "2.0", "method": "A" * 65536, "id": 1}),
        description="64KB method name",
        expected_behavior="Server rejects or handles gracefully"
    ))
    
    # 3. Very long tool name in tools/call
    cases.append(FuzzCase(
        name="long_tool_name",
        generator="boundary",
        payload=_frame({
            "jsonrpc": "2.0", "method": "tools/call", "id": 1,
            "params": {"name": "X" * 100000, "arguments": {}}
        }),
        description="100KB tool name in tools/call",
        expected_behavior="Server rejects oversized tool name"
    ))
    
    # 4. Thousands of arguments
    many_args = {f"arg_{i}": f"value_{i}" for i in range(10000)}
    cases.append(FuzzCase(
        name="10k_arguments",
        generator="boundary",
        payload=_frame({
            "jsonrpc": "2.0", "method": "tools/call", "id": 1,
            "params": {"name": "test_tool", "arguments": many_args}
        }),
        description="10,000 arguments in tool call",
        expected_behavior="Server handles or rejects gracefully"
    ))
    
    # 5. Argument value is 10MB string
    cases.append(FuzzCase(
        name="10mb_argument_value",
        generator="boundary",
        payload=_frame({
            "jsonrpc": "2.0", "method": "tools/call", "id": 1,
            "params": {"name": "test_tool", "arguments": {"data": "X" * 10_000_000}}
        }),
        description="10MB string as argument value",
        expected_behavior="Server rejects or imposes size limits"
    ))
    
    # 6. ID = 0 (edge case)
    cases.append(FuzzCase(
        name="id_zero",
        generator="boundary",
        payload=_frame({"jsonrpc": "2.0", "method": "tools/list", "id": 0}),
        description="Request ID = 0",
        expected_behavior="Server accepts (0 is valid)"
    ))
    
    # 7. Unicode method name
    cases.append(FuzzCase(
        name="unicode_method",
        generator="boundary",
        payload=_frame({"jsonrpc": "2.0", "method": "工具/列表", "id": 1}),
        description="Chinese characters as method name",
        expected_behavior="Server returns method not found"
    ))
    
    # 8. Rapid-fire 100 requests
    msgs = b""
    for i in range(100):
        msgs += _frame({"jsonrpc": "2.0", "method": "tools/list", "id": i})
    cases.append(FuzzCase(
        name="rapid_fire_100",
        generator="boundary",
        payload=msgs,
        description="100 rapid sequential requests",
        expected_behavior="Server handles all without crash"
    ))
    
    return cases
