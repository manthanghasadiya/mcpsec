"""Resource exhaustion test cases — stress test server limits."""

import json
from .base import FuzzCase

def _frame(body: bytes, framing: str = "clrf") -> bytes:
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases = []

    # 1. Rapid tools/list flood (100 requests)
    flood = b""
    for i in range(100):
        flood += _frame(json.dumps({
            "jsonrpc": "2.0", "id": i + 1, "method": "tools/list",
        }).encode(), framing)
    cases.append(FuzzCase(
        name="rapid_tools_list_flood",
        generator="resource_exhaustion",
        payload=flood,
        description="100 rapid tools/list requests",
        expected_behavior="Server handles all without crash or excessive memory",
    ))

    # 2. Large argument value (1MB)
    big_val = "A" * (1024 * 1024)
    cases.append(FuzzCase(
        name="1mb_argument",
        generator="resource_exhaustion",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "test", "arguments": {"data": big_val}},
        }).encode(), framing),
        description="1MB string argument value",
        expected_behavior="Server rejects oversized payload or handles gracefully",
    ))

    # 3. Deeply nested JSON (500 levels)
    nested = {"a": None}
    current = nested
    for _ in range(500):
        current["a"] = {"a": None}
        current = current["a"]
    cases.append(FuzzCase(
        name="deep_nested_json_500",
        generator="resource_exhaustion",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "test", "arguments": nested},
        }).encode(), framing),
        description="Deeply nested JSON (500 levels)",
        expected_behavior="Server rejects or handles without stack overflow",
    ))

    # 4. Many keys (10,000 keys in arguments)
    many_keys = {f"key_{i}": f"val_{i}" for i in range(10000)}
    cases.append(FuzzCase(
        name="many_keys_10k",
        generator="resource_exhaustion",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "test", "arguments": many_keys},
        }).encode(), framing),
        description="10,000 keys in arguments object",
        expected_behavior="Server handles without excessive CPU usage",
    ))

    # 5. Concurrent tool calls (50)
    concurrent = b""
    for i in range(50):
        concurrent += _frame(json.dumps({
            "jsonrpc": "2.0", "id": i + 100,
            "method": "tools/call",
            "params": {"name": "test", "arguments": {"idx": i}},
        }).encode(), framing)
    cases.append(FuzzCase(
        name="concurrent_tool_calls_50",
        generator="resource_exhaustion",
        payload=concurrent,
        description="50 concurrent tool calls",
        expected_behavior="Server handles concurrency without deadlock",
    ))

    # 6. Empty params (null)
    cases.append(FuzzCase(
        name="null_params",
        generator="resource_exhaustion",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": None,
        }).encode(), framing),
        description="tools/call with null params",
        expected_behavior="Server returns error about missing params",
    ))

    # 7. Large array argument
    big_arr = list(range(50000))
    cases.append(FuzzCase(
        name="large_array_argument",
        generator="resource_exhaustion",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "test", "arguments": {"items": big_arr}},
        }).encode(), framing),
        description="Array with 50,000 elements as argument",
        expected_behavior="Server rejects or handles gracefully",
    ))

    # 8. Repeated same method (resources/list)
    rl_flood = b""
    for i in range(100):
        rl_flood += _frame(json.dumps({
            "jsonrpc": "2.0", "id": i + 200, "method": "resources/list",
        }).encode(), framing)
    cases.append(FuzzCase(
        name="rapid_resources_list_flood",
        generator="resource_exhaustion",
        payload=rl_flood,
        description="100 rapid resources/list requests",
        expected_behavior="Server handles without resource leak",
    ))

    # 9. Long method name
    cases.append(FuzzCase(
        name="long_method_name",
        generator="resource_exhaustion",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "A" * 100000,
        }).encode(), framing),
        description="100KB method name",
        expected_behavior="Server returns method not found error",
    ))

    # 10. Integer overflow in ID
    cases.append(FuzzCase(
        name="integer_overflow_id",
        generator="resource_exhaustion",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 2**63,
            "method": "tools/list",
        }).encode(), framing),
        description="Request ID at 2^63 (integer overflow test)",
        expected_behavior="Server handles large ID without overflow",
    ))

    # 11. Negative ID
    cases.append(FuzzCase(
        name="negative_id",
        generator="resource_exhaustion",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": -1,
            "method": "tools/list",
        }).encode(), framing),
        description="Negative request ID",
        expected_behavior="Server handles or rejects negative ID",
    ))

    # 12. Float ID
    cases.append(FuzzCase(
        name="float_id",
        generator="resource_exhaustion",
        payload=_frame(json.dumps({
            "jsonrpc": "2.0", "id": 3.14159,
            "method": "tools/list",
        }).encode(), framing),
        description="Floating-point request ID",
        expected_behavior="Server handles or rejects float ID",
    ))

    return cases
