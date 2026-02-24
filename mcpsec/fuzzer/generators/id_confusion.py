"""
JSON-RPC ID Confusion Fuzzer for MCP.

Tests what happens with:
1. Duplicate IDs
2. Negative IDs
3. Float IDs (spec says integer or string)
4. Huge IDs (integer overflow)
5. Type confusion (arrays, objects as IDs)
6. Null IDs (notification vs request confusion)
"""

import math
from typing import Any

# Generator metadata
GENERATOR_NAME = "id_confusion"
GENERATOR_DESCRIPTION = "Tests JSON-RPC message ID edge cases and type confusion"
CATEGORY = "protocol"
INTENSITY_LEVELS = {
    "low": 15,
    "medium": 35,
    "high": 60,
    "insane": 60
}


def generate(intensity: str = "medium") -> list[dict[str, Any]]:
    """Generate ID confusion test cases."""
    cases = []
    max_cases = INTENSITY_LEVELS.get(intensity, 35)
    
    # Base request template
    base_method = "tools/list"
    base_params = {}
    
    # ===========================================
    # Category 1: Numeric ID Edge Cases
    # ===========================================
    numeric_ids = [
        ("zero", 0, "ID of zero"),
        ("negative_one", -1, "Negative ID"),
        ("negative_large", -999999999, "Large negative ID"),
        ("max_int32", 2147483647, "Max 32-bit signed int"),
        ("max_int32_plus1", 2147483648, "Max 32-bit signed + 1 (overflow)"),
        ("min_int32", -2147483648, "Min 32-bit signed int"),
        ("min_int32_minus1", -2147483649, "Min 32-bit signed - 1 (underflow)"),
        ("max_int64", 9223372036854775807, "Max 64-bit signed int"),
        ("max_int64_plus1", 9223372036854775808, "Max 64-bit signed + 1"),
        ("max_uint64", 18446744073709551615, "Max 64-bit unsigned int"),
        ("huge_int", 10**100, "Astronomically large integer"),
    ]
    
    for name, id_val, desc in numeric_ids:
        cases.append({
            "name": f"id_numeric_{name}",
            "description": desc,
            "payload": {"jsonrpc": "2.0", "id": id_val, "method": base_method, "params": base_params},
            "expects_error": False,
            "crash_indicates_bug": True,
        })
    
    # ===========================================
    # Category 2: Float IDs (technically valid JSON-RPC but edge case)
    # ===========================================
    float_ids = [
        ("positive_float", 1.5, "Positive float ID"),
        ("negative_float", -1.5, "Negative float ID"),
        ("tiny_float", 0.0000001, "Very small float"),
        ("large_float", 1e308, "Large float near max"),
        ("negative_zero", -0.0, "Negative zero"),
        # Note: infinity and NaN can't be represented in standard JSON
        # but some parsers might accept them
    ]
    
    for name, id_val, desc in float_ids:
        cases.append({
            "name": f"id_float_{name}",
            "description": desc,
            "payload": {"jsonrpc": "2.0", "id": id_val, "method": base_method, "params": base_params},
            "expects_error": False,
            "crash_indicates_bug": True,
        })
    
    # ===========================================
    # Category 3: String IDs (valid per JSON-RPC 2.0)
    # ===========================================
    string_ids = [
        ("empty_string", "", "Empty string ID"),
        ("simple_string", "abc", "Simple string ID"),
        ("numeric_string", "123", "Numeric string ID"),
        ("uuid", "550e8400-e29b-41d4-a716-446655440000", "UUID string ID"),
        ("special_chars", "id-with-special!@#$%", "Special characters in ID"),
        ("unicode", "id_\u4e2d\u6587_test", "Unicode characters in ID"),
        ("null_byte", "id\x00hidden", "Null byte in string ID"),
        ("newline", "id\nwith\nnewlines", "Newlines in ID"),
        ("long_string", "A" * 10000, "Very long string ID"),
        ("whitespace", "   ", "Whitespace-only ID"),
        ("json_injection", '{"nested": "json"}', "JSON string as ID"),
    ]
    
    for name, id_val, desc in string_ids:
        cases.append({
            "name": f"id_string_{name}",
            "description": desc,
            "payload": {"jsonrpc": "2.0", "id": id_val, "method": base_method, "params": base_params},
            "expects_error": False,
            "crash_indicates_bug": True,
        })
    
    # ===========================================
    # Category 4: Type Confusion
    # ===========================================
    type_confusion_ids = [
        ("null", None, "Null ID (ambiguous: notification or request?)"),
        ("boolean_true", True, "Boolean true as ID"),
        ("boolean_false", False, "Boolean false as ID"),
        ("empty_array", [], "Empty array as ID"),
        ("array_with_int", [1], "Array containing int as ID"),
        ("nested_array", [[1, 2], [3, 4]], "Nested array as ID"),
        ("empty_object", {}, "Empty object as ID"),
        ("object_with_id", {"id": 1}, "Object with 'id' field as ID"),
        ("array_of_ids", [1, 2, 3], "Multiple IDs in array"),
    ]
    
    for name, id_val, desc in type_confusion_ids:
        cases.append({
            "name": f"id_type_{name}",
            "description": desc,
            "payload": {"jsonrpc": "2.0", "id": id_val, "method": base_method, "params": base_params},
            "expects_error": True,  # Invalid ID types should error
            "crash_indicates_bug": True,
        })
    
    # ===========================================
    # Category 5: ID Collision/Reuse
    # ===========================================
    # These are sent as sequences
    cases.append({
        "name": "id_duplicate_sequential",
        "description": "Send two requests with same ID sequentially",
        "payload": {"jsonrpc": "2.0", "id": 1, "method": base_method, "params": base_params},
        "repeat": 2,
        "crash_indicates_bug": True,
    })
    
    cases.append({
        "name": "id_reuse_after_response",
        "description": "Reuse ID immediately after receiving response",
        "payload": {"jsonrpc": "2.0", "id": 42, "method": base_method, "params": base_params},
        "repeat": 3,
        "delay_between": 0.1,
        "crash_indicates_bug": True,
    })
    
    # ===========================================
    # Category 6: Missing ID (Notification vs Request)
    # ===========================================
    # Request without ID = notification, but expecting response is confusing
    cases.append({
        "name": "missing_id_tools_list",
        "description": "tools/list without ID (treated as notification, but expects result)",
        "payload": {"jsonrpc": "2.0", "method": "tools/list", "params": {}},
        "expects_error": False,  # Notifications don't get responses
        "crash_indicates_bug": True,
    })
    
    cases.append({
        "name": "missing_id_tools_call",
        "description": "tools/call without ID (notification for a method that needs response)",
        "payload": {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "test", "arguments": {}}},
        "expects_error": False,
        "crash_indicates_bug": True,
    })
    
    # ===========================================
    # Category 7: ID in Notifications (Invalid)
    # ===========================================
    notification_with_ids = [
        ("initialized", "notifications/initialized", {}),
        ("cancelled", "notifications/cancelled", {"requestId": 1}),
        ("progress", "notifications/progress", {"progressToken": "tok", "progress": 50}),
    ]
    
    for name, method, params in notification_with_ids:
        cases.append({
            "name": f"notification_with_id_{name}",
            "description": f"{method} notification incorrectly includes ID",
            "payload": {"jsonrpc": "2.0", "id": 999, "method": method, "params": params},
            "expects_error": True,
            "crash_indicates_bug": True,
        })
    
    # Limit to intensity level
    return cases[:max_cases]
